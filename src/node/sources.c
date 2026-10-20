/* The server list's external channels (security.md 7.5, roadmap phase 2
 * item 2): when no server of the list has been reachable for 10 minutes,
 * or the list has expired, ask the channels the list names, in parallel:
 * DoH (RFC 8484 GET) for TXT records holding the seed list, at public DoH
 * services reached by IP; HTTPS static files holding the full list. None of
 * them needs to be trusted: a list counts only when its signature checks
 * and its serial is newer (node_server_list_update). Rounds back off from 1
 * minute to 1 hour, with jitter. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/dns.h"
#include "npf/http.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"

#define SRC_AFTER_MS    (10 * 60 * 1000)    /* no server reachable this long */
#define SRC_FIRST_MS    (60 * 1000)
#define SRC_MAX_MS      (60 * 60 * 1000)
#define SRC_BODY_MAX    (128 * 1024)

/* public DoH services, reached by IP (no name resolution needed) */
static const struct { const char *ip, *host; } k_doh[] = {
    {"223.5.5.5", "dns.alidns.com"},        /* Aliyun */
    {"1.12.12.12", "doh.pub"},              /* Tencent */
    {"1.1.1.1", "cloudflare-dns.com"},
    {"8.8.8.8", "dns.google"},
};

typedef struct src_req {
    npf_node *n;
    npf_http *h;
    int       slot;
    char      via[400];
} src_req;

/* the DoH services in use: the public ones, or "IP:PORT=HOST,..." (tests) */
static int doh_list(const npf_node *n, struct sockaddr_storage *addr, char host[][128], int max)
{
    int k = 0;
    if (n->cfg.doh_servers && *n->cfg.doh_servers) {
        char buf[512], *t, *save;
        snprintf(buf, sizeof buf, "%s", n->cfg.doh_servers);
        for (t = strtok_r(buf, ",", &save); t && k < max; t = strtok_r(NULL, ",", &save)) {
            char *eq = strchr(t, '=');
            if (!eq)
                continue;
            *eq = 0;
            if (npf_addr_parse(t, &addr[k]) == 0) {
                snprintf(host[k], 128, "%s", eq + 1);
                k++;
            }
        }
        return k;
    }
    for (; k < (int)(sizeof k_doh / sizeof k_doh[0]) && k < max; k++) {
        char spec[64];
        snprintf(spec, sizeof spec, "%s:443", k_doh[k].ip);
        npf_addr_parse(spec, &addr[k]);
        snprintf(host[k], 128, "%s", k_doh[k].host);
    }
    return k;
}

static void src_reconnect_now(npf_node *n)
{
    node_reconnect_now(n);
}

/* a body that is the blob, or its Base64url text */
static int try_blob(npf_node *n, const uint8_t *b, size_t len, const char *via)
{
    uint8_t *dec;
    long dl;
    int r;
    if (node_server_list_update(n, b, len, via))
        return 1;
    while (len && (b[len - 1] == '\n' || b[len - 1] == '\r' || b[len - 1] == ' '))
        len--;
    if (!(dec = malloc(SRC_BODY_MAX)))
        return 0;
    dl = len < (size_t)SRC_BODY_MAX * 4 / 3 ? npf_b64url_decode((const char *)b, len, dec, SRC_BODY_MAX) : -1;
    r = dl > 0 && node_server_list_update(n, dec, (size_t)dl, via);
    free(dec);
    return r;
}

static void req_done(src_req *r)
{
    npf_node *n = r->n;
    n->src_req[r->slot] = NULL;
    n->nsrc_req--;
    free(r);
}

static void got_txt(const uint8_t *txt, size_t len, void *arg)
{
    src_req *r = arg;
    if (try_blob(r->n, txt, len, r->via))
        src_reconnect_now(r->n);
}

static void doh_done(int status, const uint8_t *body, size_t len, const char *err, void *arg)
{
    src_req *r = arg;
    if (status == 200) {
        if (npf_dns_txt_answers(body, len, got_txt, r) <= 0)
            npf_logd("server list: %s: no TXT answer", r->via);
    } else {
        npf_logd("server list: %s: %s", r->via, status < 0 ? err : "HTTP error");
    }
    req_done(r);
}

static void https_done(int status, const uint8_t *body, size_t len, const char *err, void *arg)
{
    src_req *r = arg;
    if (status == 200) {
        if (try_blob(r->n, body, len, r->via))
            src_reconnect_now(r->n);
    } else {
        npf_logd("server list: %s: %s (%d)", r->via, status < 0 ? err : "HTTP error", status);
    }
    req_done(r);
}

static src_req *new_req(npf_node *n, const char *via)
{
    int i;
    src_req *r;
    for (i = 0; i < (int)(sizeof n->src_req / sizeof n->src_req[0]); i++)
        if (!n->src_req[i])
            break;
    if (i == (int)(sizeof n->src_req / sizeof n->src_req[0]) || !(r = calloc(1, sizeof *r)))
        return NULL;
    r->n = n;
    r->slot = i;
    snprintf(r->via, sizeof r->via, "%s", via);
    return r;
}

static void start_round(npf_node *n, const char *why)
{
    struct sockaddr_storage addr[8];
    char host[8][128];
    int nd = doh_list(n, addr, host, 8), i, k, started = 0;
    const npf_list_meta *m = &n->sl_meta;
    for (i = 0; i < m->nhttps; i++) {
        src_req *r = new_req(n, m->https[i]);
        if (!r)
            break;
        r->h = npf_http_get(n->loop, m->https[i], NULL, "application/octet-stream", SRC_BODY_MAX, 15000, https_done, r);
        if (r->h) {
            n->src_req[r->slot] = r;
            n->nsrc_req++;
            started++;
        } else {
            free(r);
        }
    }
    for (i = 0; i < m->ndoh && nd > 0; i++) {
        uint8_t q[300];
        char q64[420], url[1200];
        int ql = npf_dns_txt_query(m->doh[i], (uint16_t)npf_rand_range(0, 65535), q, sizeof q);
        int first = (int)npf_rand_range(0, (size_t)nd - 1);
        if (ql < 0)
            continue;
        q64[npf_b64url_encode(q, (size_t)ql, q64)] = 0;
        for (k = 0; k < (nd > 1 ? 2 : 1); k++) {     /* two services in random order */
            int d = (first + k) % nd;
            char via[400];
            src_req *r;
            snprintf(url, sizeof url, "https://%.127s/dns-query?dns=%.419s", host[d], q64);
            snprintf(via, sizeof via, "DoH %.127s (%.127s)", m->doh[i], host[d]);
            if (!(r = new_req(n, via)))
                break;
            r->h = npf_http_get(n->loop, url, &addr[d], "application/dns-message", 65536, 15000, doh_done, r);
            if (r->h) {
                n->src_req[r->slot] = r;
                n->nsrc_req++;
                started++;
            } else {
                free(r);
            }
        }
    }
    if (started)
        npf_log("server list: %s; asking the external channels (%d requests)", why, started);
}

void node_sources_check(npf_node *n)
{
    int64_t now = npf_mono_ms(), after = SRC_AFTER_MS;
    int expired, stuck, d;
    char why[96];
    const char *e = getenv("NPF_TEST_SOURCES_AFTER_MS");
    if (e)
        after = atoll(e);
    if (n->online || n->nsrc_req > 0 || now < n->src_next || (!n->sl_meta.ndoh && !n->sl_meta.nhttps))
        return;
    expired = n->sl_meta.expires && npf_unix_ms() / 1000 > n->sl_meta.expires;
    stuck = n->unreachable_since && now - n->unreachable_since >= after;
    if (!expired && !stuck)
        return;
    if (stuck)
        snprintf(why, sizeof why, "no server reachable for %lld s", (long long)((now - n->unreachable_since) / 1000));
    else
        snprintf(why, sizeof why, "the list has expired");
    n->src_backoff = n->src_backoff ? (n->src_backoff * 2 > SRC_MAX_MS ? SRC_MAX_MS : n->src_backoff * 2) : SRC_FIRST_MS;
    d = n->src_backoff * 3 / 4 + (int)npf_rand_range(0, (size_t)n->src_backoff / 2);
    n->src_next = now + d;
    start_round(n, why);
}

void node_sources_stop(npf_node *n)
{
    int i;
    for (i = 0; i < (int)(sizeof n->src_req / sizeof n->src_req[0]); i++)
        if (n->src_req[i]) {
            src_req *r = n->src_req[i];
            npf_http_cancel(r->h);          /* its callback does not run */
            free(r);
            n->src_req[i] = NULL;
        }
    n->nsrc_req = 0;
}

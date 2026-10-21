#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "npf/candidates.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"

/* ---- addresses ---- */

int npf_addr_parse(const char *s, struct sockaddr_storage *out)
{
    char host[64];
    const char *colon;
    long port;
    char *end;
    memset(out, 0, sizeof *out);
    if (*s == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':' || (size_t)(rb - s - 1) >= sizeof host)
            return -1;
        memcpy(host, s + 1, (size_t)(rb - s - 1));
        host[rb - s - 1] = 0;
        colon = rb + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon || (size_t)(colon - s) >= sizeof host)
            return -1;
        memcpy(host, s, (size_t)(colon - s));
        host[colon - s] = 0;
    }
    port = strtol(colon + 1, &end, 10);
    if (*end || port < 0 || port > 65535)
        return -1;
    if (strchr(host, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)port);
        return inet_pton(AF_INET6, host, &a->sin6_addr) == 1 ? 0 : -1;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)port);
        return inet_pton(AF_INET, host, &a->sin_addr) == 1 ? 0 : -1;
    }
}

const char *npf_addr_str(const struct sockaddr_storage *a, char *b, size_t n)
{
    char ip[INET6_ADDRSTRLEN];
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)a;
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
        snprintf(b, n, "[%s]:%u", ip, ntohs(s6->sin6_port));
    } else if (a->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)a;
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
        snprintf(b, n, "%s:%u", ip, ntohs(s4->sin_port));
    } else {
        snprintf(b, n, "-");
    }
    return b;
}

/* ---- server list ---- */

static int serverlist_parse(const char *json, size_t len, npf_server_entry *out, int max, int64_t *serial,
                            npf_jtok *tok)
{
    npf_json j;
    int arr, i, n = 0;
    if (npf_json_parse(&j, json, len, tok, NPF_JSON_MAX_TOKENS) < 0 || tok[0].type != NPF_JT_OBJECT)
        return -1;
    if (npf_json_get_int(&j, 0, "serial", 0, INT64_MAX, serial) < 0)
        return -1;
    arr = npf_json_get(&j, 0, "servers");
    if (arr < 0 || tok[arr].type != NPF_JT_ARRAY)
        return -1;
    for (i = 0; i < tok[arr].size && n < max; i++) {
        int s = npf_json_item(&j, arr, i), ws, k;
        int64_t v;
        npf_server_entry *e = &out[n];
        memset(e, 0, sizeof *e);
        if (npf_json_get_int(&j, s, "id", 0, 1 << 30, &v) < 0)
            continue;
        e->id = (int)v;
        e->prio = npf_json_get_int(&j, s, "prio", 0, 1000, &v) == 0 ? (int)v : 1;
        e->weight = npf_json_get_int(&j, s, "weight", 0, 1000, &v) == 0 ? (int)v : 1;
        e->cdn = npf_json_eq(&j, npf_json_get(&j, s, "kind"), "cdn");
        if (npf_json_get_b64(&j, s, "dh_pub", e->dh_pub, 32) != 32)
            continue;
        ws = npf_json_get(&j, s, "ws");
        for (k = 0; ws >= 0 && k < tok[ws].size && e->nws < 2; k++)
            if (npf_json_str(&j, npf_json_item(&j, ws, k), e->ws[e->nws], sizeof e->ws[0]) > 0)
                e->nws++;
        if (!e->nws)
            continue;
        {
            int rb = 0;
            if (npf_json_bool(&j, npf_json_get(&j, s, "relay"), &rb) == 0)
                e->relay = rb;
        }
        n++;
    }
    return n;
}

/* the token arrays are per call: instances on other threads parse at the same time */
int npf_serverlist_parse(const char *json, size_t len, npf_server_entry *out, int max, int64_t *serial)
{
    npf_jtok *tok = malloc(NPF_JSON_MAX_TOKENS * sizeof *tok);
    int r = tok ? serverlist_parse(json, len, out, max, serial, tok) : -1;
    free(tok);
    return r;
}

static void serverlist_meta(const char *json, size_t len, npf_list_meta *m, npf_jtok *tok);

void npf_serverlist_meta(const char *json, size_t len, npf_list_meta *m)
{
    npf_jtok *tok = malloc(NPF_JSON_MAX_TOKENS * sizeof *tok);
    if (!tok) {
        memset(m, 0, sizeof *m);
        m->full = 1;
        return;
    }
    serverlist_meta(json, len, m, tok);
    free(tok);
}

static void serverlist_meta(const char *json, size_t len, npf_list_meta *m, npf_jtok *tok)
{
    npf_json j;
    int src, arr, k;
    int64_t v;
    memset(m, 0, sizeof *m);
    m->full = 1;
    if (npf_json_parse(&j, json, len, tok, NPF_JSON_MAX_TOKENS) < 0 || tok[0].type != NPF_JT_OBJECT)
        return;
    if (npf_json_get_int(&j, 0, "expires", 0, INT64_MAX, &v) == 0)
        m->expires = v;
    if (npf_json_bool(&j, npf_json_get(&j, 0, "full"), &m->full) < 0)
        m->full = 1;
    src = npf_json_get(&j, 0, "sources");
    if (src < 0 || tok[src].type != NPF_JT_OBJECT)
        return;
    arr = npf_json_get(&j, src, "doh");
    for (k = 0; arr >= 0 && k < tok[arr].size && m->ndoh < NPF_SOURCES_MAX; k++)
        if (npf_json_str(&j, npf_json_item(&j, arr, k), m->doh[m->ndoh], sizeof m->doh[0]) > 0)
            m->ndoh++;
    arr = npf_json_get(&j, src, "https");
    for (k = 0; arr >= 0 && k < tok[arr].size && m->nhttps < NPF_SOURCES_MAX; k++)
        if (npf_json_str(&j, npf_json_item(&j, arr, k), m->https[m->nhttps], sizeof m->https[0]) > 0
            && strncmp(m->https[m->nhttps], "https://", 8) == 0)
            m->nhttps++;
}

static int load_list_file(npf_node *n, const char *path, int64_t *serial, npf_server_entry *tmp, int *count,
                          npf_list_meta *meta)
{
    char *blob;
    long len = npf_file_read(path, &blob);
    const uint8_t *pl;
    size_t plen;
    int r = -1;
    if (len < 0)
        return -1;
    if (npf_serverlist_verify((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, (uint8_t *)blob, (size_t)len,
                              &pl, &plen) == 0) {
        int c = npf_serverlist_parse((const char *)pl, plen, tmp, NPF_MAX_SERVERS, serial);
        if (c > 0) {
            *count = c;
            npf_serverlist_meta((const char *)pl, plen, meta);
            r = 0;
        }
    }
    free(blob);
    return r;
}

/* *dst: count entries of src (room for one at least); 0, -1 out of memory */
static int servers_set(npf_server_entry **dst, const npf_server_entry *src, int count)
{
    npf_server_entry *e = realloc(*dst, (size_t)(count > 0 ? count : 1) * sizeof *e);
    if (!e)
        return -1;
    if (count > 0)
        memcpy(e, src, (size_t)count * sizeof *e);
    *dst = e;
    return 0;
}

/* the newer of the built-in and the saved list (security.md 7.5) */
static void load_server_list(npf_node *n)
{
    /* scratch on the heap, per call (instances on other threads load theirs at the same time) */
    struct lists {
        npf_server_entry a[NPF_MAX_SERVERS], b[NPF_MAX_SERVERS];
        npf_list_meta    ma, mb;
    } *l = calloc(1, sizeof *l);
    int64_t sa = -1, sb = -1;
    int ca = 0, cb = 0;
    if (!l)
        return;
    if (n->cfg.serverlist_builtin)
        load_list_file(n, n->cfg.serverlist_builtin, &sa, l->a, &ca, &l->ma);
    if (n->cfg.serverlist_saved)
        load_list_file(n, n->cfg.serverlist_saved, &sb, l->b, &cb, &l->mb);
    if (ca && (!cb || sa >= sb)) {
        if (servers_set(&n->servers, l->a, ca) < 0)
            ca = 0;
        n->nservers = ca;
        n->sl_serial = n->sl_full_serial = sa;
        n->sl_meta = l->ma;
    } else if (cb) {
        if (servers_set(&n->servers, l->b, cb) < 0)
            cb = 0;
        n->nservers = cb;
        n->sl_serial = n->sl_full_serial = sb;
        n->sl_meta = l->mb;
    }
    free(l);
    n->nlist = servers_set(&n->list, n->servers, n->nservers) == 0 ? n->nservers : 0;
    if (n->cfg.server_url) {    /* test override: a single server outside any list */
        npf_server_entry *e;
        if (!n->servers && servers_set(&n->servers, NULL, 0) < 0)
            return;
        e = &n->servers[0];
        memset(e, 0, sizeof *e);
        snprintf(e->ws[0], sizeof e->ws[0], "%s", n->cfg.server_url);
        e->nws = 1;
        memcpy(e->dh_pub, n->cfg.server_pub, 32);
        e->relay = 1;
        if (n->nservers == 0)
            n->nservers = 1;
        else {  /* keep the probe addresses of the list's first entry */
            n->nservers = 1;
        }
    }
}

/* a server_list blob (login, push, or an external channel named by via):
 * verify, compare serial, adopt, save a full list. A seed list (full =
 * false, from DNS) is used but not saved: the full list on disk stays
 * (security.md 7.5). Returns 1 when adopted. */
static int list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via, npf_server_entry *tmp);

int node_server_list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via)
{
    npf_server_entry *tmp = malloc(NPF_MAX_SERVERS * sizeof *tmp);
    int r = tmp ? list_update(n, blob, len, via, tmp) : 0;
    free(tmp);
    return r;
}

static int list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via, npf_server_entry *tmp)
{
    npf_list_meta meta;
    const uint8_t *pl;
    size_t plen;
    int64_t serial;
    int c;
    if (npf_serverlist_verify((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, blob, len, &pl, &plen) < 0) {
        npf_logw("server list%s%s: signature check failed, ignored", via ? " from " : "", via ? via : "");
        return 0;
    }
    c = npf_serverlist_parse((const char *)pl, plen, tmp, NPF_MAX_SERVERS, &serial);
    if (c <= 0 || serial <= n->sl_serial)
        return 0;
    npf_serverlist_meta((const char *)pl, plen, &meta);
    if (meta.full) {
        if (n->cfg.serverlist_saved && npf_file_write(n->cfg.serverlist_saved, blob, len, 0644) < 0)
            npf_logw("server list: cannot save %s: %s", n->cfg.serverlist_saved, strerror(errno));
        n->sl_full_serial = serial;
    }
    if (!meta.ndoh && !meta.nhttps) {   /* a seed list need not name the channels: keep the known ones */
        memcpy(meta.doh, n->sl_meta.doh, sizeof meta.doh);
        meta.ndoh = n->sl_meta.ndoh;
        memcpy(meta.https, n->sl_meta.https, sizeof meta.https);
        meta.nhttps = n->sl_meta.nhttps;
    }
    n->sl_meta = meta;
    if (servers_set(&n->list, tmp, c) < 0 || (!n->cfg.server_url && servers_set(&n->servers, tmp, c) < 0)) {
        npf_loge("server list: out of memory");
        n->nlist = n->nlist < c ? n->nlist : c;
        return 0;
    }
    n->nlist = c;
    if (!n->cfg.server_url) {
        n->nservers = c;
        n->cur_server = -1;
    }
    n->sl_serial = serial;
    npf_log("server list: serial %lld, %d servers%s%s%s", (long long)serial, c, meta.full ? "" : " (seed list)",
            via ? " from " : "", via ? via : "");
    return 1;
}

#define SERVER_DEGRADE_MS (3600 * 1000)

/* a connection attempt to this entry failed; three in a row deprioritise it for an hour */
static void server_failed(npf_server_entry *e, int weight)
{
    e->fails += weight;
    if (e->fails >= 3)
        e->degraded_until = npf_mono_ms() + SERVER_DEGRADE_MS;
}

static int degraded(const npf_server_entry *e)
{
    if (e->fails >= 3 && npf_mono_ms() < e->degraded_until)
        return 1;
    return 0;
}

static int eff_prio(const npf_server_entry *e)
{
    return e->prio + (degraded(e) ? 100 : 0);
}

/* choose by prio, then weight; recently failing entries sort behind the rest */
static int pick_server(npf_node *n)
{
    int best_prio = 1 << 30, i, total = 0, r;
    if (n->nservers == 0)
        return -1;
    for (i = 0; i < n->nservers; i++) {
        if (!degraded(&n->servers[i]) && n->servers[i].fails >= 3)
            n->servers[i].fails = 0;        /* the hour is over: a fresh start */
        if (eff_prio(&n->servers[i]) < best_prio)
            best_prio = eff_prio(&n->servers[i]);
    }
    for (i = 0; i < n->nservers; i++)
        if (eff_prio(&n->servers[i]) == best_prio)
            total += n->servers[i].weight > 0 ? n->servers[i].weight : 1;
    r = (int)npf_rand_range(0, (size_t)(total - 1));
    for (i = 0; i < n->nservers; i++) {
        if (eff_prio(&n->servers[i]) != best_prio)
            continue;
        r -= n->servers[i].weight > 0 ? n->servers[i].weight : 1;
        if (r < 0)
            return i;
    }
    return 0;
}

/* ---- signaling ---- */

int64_t npf_node_time(const npf_node *n)
{
    return npf_unix_ms() + n->clock_offset_ms;
}

static int send_env(npf_node *n, const char *type, const char *id, const char *reply_to, const char *status,
                    const char *error, const char *data_json)
{
    char *buf;
    npf_jw w;
    int len, r;
    if (!n->sig || !(buf = malloc(NPF_JSON_MAX_SIZE)))
        return -1;
    npf_jw_init(&w, buf, NPF_JSON_MAX_SIZE);
    npf_jw_obj(&w);
    npf_jw_kint(&w, "v", 1);
    npf_jw_kstr(&w, "type", type);
    if (id) npf_jw_kstr(&w, "id", id);
    if (reply_to) npf_jw_kstr(&w, "reply_to", reply_to);
    if (status) npf_jw_kstr(&w, "status", status);
    if (error) npf_jw_kstr(&w, "error", error);
    npf_jw_key(&w, "data");
    if (data_json)
        npf_jw_raw(&w, data_json, strlen(data_json));
    else
        npf_jw_raw(&w, "{}", 2);
    npf_jw_end(&w);
    len = npf_jw_finish(&w);
    if (len < 0) {
        free(buf);
        return -1;
    }
    /* the envelope only, never data: it carries passwords, codes, keys (R10) */
    npf_logt("sig > %s%s%s%s%s%s%s%s%s, %d bytes", type, id ? " id=" : "", id ? id : "", reply_to ? " reply_to=" : "",
             reply_to ? reply_to : "", status ? " " : "", status ? status : "", error ? " " : "", error ? error : "", len);
    r = npf_sig_send(n->sig, buf, (size_t)len);
    npf_wipe(buf, (size_t)len);
    free(buf);
    return r;
}

int npf_node_send(npf_node *n, const char *type, int request, const char *data_json)
{
    char id[16];
    if (!request)
        return send_env(n, type, NULL, NULL, NULL, NULL, data_json) < 0 ? -1 : 0;
    n->req_seq++;
    snprintf(id, sizeof id, "r%d", n->req_seq);
    return send_env(n, type, id, NULL, NULL, NULL, data_json) < 0 ? -1 : n->req_seq;
}

#define SIG_REPLY_MS 10000      /* a request sent: something from the server within, else a ping asks */
#define SIG_PONG_MS  10000      /* a ping sent: its pong (or anything) within */
static void sig_expect(npf_node *n, int ms, int probed);   /* the watch on the signaling, below */

int npf_node_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg)
{
    int i, id;
    for (i = 0; i < 16; i++)
        if (!n->pending[i].fn)
            break;
    if (i == 16)
        return -1;
    id = npf_node_send(n, type, 1, data_json);
    if (id < 0)
        return -1;
    n->pending[i].id = id;
    n->pending[i].fn = fn;
    n->pending[i].arg = arg;
    sig_expect(n, SIG_REPLY_MS, 0);     /* a connection that took it and carries nothing: found */
    return 0;
}

/* ---- call_end reports ---- */

static void ends_flush(npf_node *n);

static void end_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    npf_end_report *e = arg;
    (void)ok;
    e->state = j ? 0 : 1;               /* answered: done; connection lost: again after the next login */
    if (j)
        ends_flush(n);                  /* a request slot is free again */
}

static void ends_flush(npf_node *n)
{
    char data[160];
    int i;
    if (!n->online)
        return;
    for (i = 0; i < NPF_ENDS_MAX; i++) {
        npf_end_report *e = &n->ends[i];
        if (e->state != 1)
            continue;
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"reason\":\"%s\",\"ago_ms\":%lld}", e->call_id, e->reason,
                 (long long)(npf_mono_ms() - e->at_ms));
        if (npf_node_request(n, "call_end", data, end_reply, e) < 0)
            return;                     /* no request slot: on the next answer */
        e->state = 2;
    }
}

void npf_node_call_end(npf_node *n, const char *call_id, const char *reason)
{
    npf_end_report *e = NULL;
    int i;
    for (i = 0; i < NPF_ENDS_MAX && !e; i++)
        if (n->ends[i].state == 0)
            e = &n->ends[i];
    for (i = 0; i < NPF_ENDS_MAX && !e; i++)      /* full: the oldest waiting one goes */
        if (n->ends[i].state == 1 && (!e || n->ends[i].at_ms < e->at_ms))
            e = &n->ends[i];
    if (!e)
        return;
    snprintf(e->call_id, sizeof e->call_id, "%s", call_id);
    snprintf(e->reason, sizeof e->reason, "%s", reason);
    e->at_ms = npf_mono_ms();
    e->state = 1;
    if (!n->online)
        npf_log("call %s: ended (%s), the platform is told after the next login", call_id, reason);
    ends_flush(n);
}

void npf_node_cancel_requests(npf_node *n, void *arg)
{
    int i;
    for (i = 0; i < 16; i++)
        if (n->pending[i].fn && n->pending[i].arg == arg)
            n->pending[i].fn = NULL;
}

static void fail_pending(npf_node *n)
{
    int i;
    for (i = 0; i < 16; i++) {
        npf_reply_fn fn = n->pending[i].fn;
        if (fn) {
            n->pending[i].fn = NULL;
            fn(n, NULL, 0, n->pending[i].arg);
        }
    }
}

int npf_node_reply(npf_node *n, const char *type, const char *reply_to, const char *status,
                   const char *error, const char *data_json)
{
    return send_env(n, type, NULL, reply_to, status, error, data_json);
}

static void connect_server(npf_node *n);
static void race_drop(npf_node *n);
static void idle_watch(npf_node *n);

/* a new list from an external channel: drop the attempt in progress (to
 * the old list's servers) and connect again at once */
void node_reconnect_now(npf_node *n)
{
    if (n->online)
        return;
    race_drop(n);
    if (n->sig)
        npf_sig_close(n->sig);
    n->sig = NULL;
    if (n->t_reconnect)
        npf_timer_cancel(n->loop, n->t_reconnect);
    n->t_reconnect = NULL;
    if (n->t_login)
        npf_timer_cancel(n->loop, n->t_login);
    n->t_login = NULL;
    n->backoff_ms = 0;
    connect_server(n);
}

static void reconnect_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_reconnect = NULL;
    connect_server(n);
}

static void schedule_reconnect(npf_node *n)
{
    int d;
    if (!n->unreachable_since)
        n->unreachable_since = npf_mono_ms();   /* no server since now (sources.c counts from it) */
    node_sources_check(n);
    if (n->t_reconnect)
        return;
    /* exponential backoff with jitter, 1 s .. 60 s (security.md 7.3) */
    d = n->backoff_ms ? n->backoff_ms : 1000;
    n->backoff_ms = d * 2 > 60000 ? 60000 : d * 2;
    d = d / 2 + (int)npf_rand_range(0, (size_t)d / 2);
    n->t_reconnect = npf_timer_add(n->loop, d, reconnect_cb, n);
}

#define SIG_LOGIN_MS 20000         /* connect, TLS, upgrade, Noise and login together */

static void sig_down(npf_sig *s, const char *why, void *arg);

/* drop a connection that makes no progress: nothing else would notice (a
 * stalled TCP/TLS/handshake, or a server that went silent behind a NAT),
 * and the node stayed offline for an hour (Mac, 2026-10-06) */
static void race_drop(npf_node *n)
{
    if (n->race)
        npf_sig_close(n->race);
    n->race = NULL;
}

static void sig_abort(npf_node *n, const char *why)
{
    npf_sig *s = n->sig;
    race_drop(n);
    npf_logw("signaling: %s, reconnecting", why);
    sig_down(s, why, n);            /* n->sig = NULL, reconnect scheduled */
    npf_sig_close(s);
}

static void login_deadline(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_login = NULL;
    if (n->sig && !n->online)
        sig_abort(n, "no login within 20 s");
}

/* A connection can look up and carry nothing (a VPN's tunnel after the
 * system slept: the server's messages lost for a minute and more, calls to
 * this node timing out meanwhile; 2026-10-20). Something from the server is
 * due after each ping and each request: none in time, a ping asks; none to
 * that either, the connection is dropped and made again. */

static void expect_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_expect = NULL;
    if (!n->sig || !n->online || npf_sig_last_rx(n->sig) >= n->expect_since)
        return;                     /* heard from it */
    if (!n->expect_probed) {
        n->expect_probed = 1;
        n->expect_since = npf_mono_ms();
        npf_sig_ping(n->sig);
        n->t_expect = npf_timer_add(n->loop, SIG_PONG_MS, expect_cb, n);
        return;
    }
    sig_abort(n, "the server stopped answering");
}

/* something from the server is due within ms; probed: a ping is out for it.
 * One watch at a time (the one running is the older) */
static void sig_expect(npf_node *n, int ms, int probed)
{
    if (!n->sig || !n->online || n->t_expect)
        return;
    n->expect_since = npf_mono_ms();
    n->expect_probed = probed;
    n->t_expect = npf_timer_add(n->loop, ms, expect_cb, n);
}

static void expect_stop(npf_node *n)
{
    if (n->t_expect)
        npf_timer_cancel(n->loop, n->t_expect);
    n->t_expect = NULL;
}

void node_sig_probe(npf_node *n)
{
    if (!n->sig || !n->online || n->t_expect)
        return;
    npf_sig_ping(n->sig);
    sig_expect(n, SIG_PONG_MS, 1);
}

static void ping_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int ivl = (n->ping_s > 0 ? n->ping_s : 25) * 1000;
    (void)loop;
    n->t_ping = NULL;
    if (!n->sig)
        return;
    /* the server answers each ping (pong) and sends its own: three
     * intervals without a frame mean the connection is gone */
    if (npf_mono_ms() - npf_sig_last_rx(n->sig) > 3 * (int64_t)ivl) {
        sig_abort(n, "the server went silent");
        return;
    }
    npf_sig_ping(n->sig);
    sig_expect(n, SIG_PONG_MS, 1);      /* its pong in time, else the connection goes */
    n->t_ping = npf_timer_add(n->loop, (n->ping_s > 0 ? n->ping_s : 25) * 1000, ping_cb, n);
}

static void send_login(npf_node *n)
{
    char data[4096], num[24];
    npf_jw w;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    if (n->cfg.callable) {
        npf_jw_kstr(&w, "role", "node");
        snprintf(num, sizeof num, "%llu", (unsigned long long)n->cfg.number);
        npf_jw_kstr(&w, "number", num);
        if (n->cert_len)
            npf_jw_kb64(&w, "cert", n->cert, n->cert_len);
        if (n->account_cert_len)
            npf_jw_kb64(&w, "account_cert", n->account_cert, n->account_cert_len);
    } else if (n->cfg.hosted_service) {
        npf_jw_kstr(&w, "role", "hosted");          /* npf-hosted itself (its key: hosted_keys) */
    } else {
        npf_jw_kstr(&w, "role", "client");
        if (n->account_cert_len)
            npf_jw_kb64(&w, "cert", n->account_cert, n->account_cert_len);
    }
    if (n->cfg.callable && n->cfg.model) npf_jw_kstr(&w, "model", n->cfg.model);
    if (n->cfg.callable && n->cfg.fw) npf_jw_kstr(&w, "fw", n->cfg.fw);
    if (n->cfg.app_name) {
        npf_jw_key(&w, "app");
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "name", n->cfg.app_name);
        npf_jw_kstr(&w, "ver", n->cfg.app_ver);
        npf_jw_end(&w);
    }
    /* the full list's serial: after a seed list from DNS the server still
     * sends the full one */
    npf_jw_kint(&w, "sl_serial", n->sl_full_serial ? n->sl_full_serial : n->sl_serial);
    if (!n->cfg.no_host_report) {
        /* the platform's connection record: OS, machine, interfaces (report_host = 0: none) */
        npf_host_info h;
        int i;
        npf_host_info_get(&h);
        npf_jw_key(&w, "host");
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "os", h.os);
        npf_jw_kstr(&w, "arch", h.arch);
        npf_jw_kstr(&w, "hostname", h.hostname);
        npf_jw_kstr(&w, "machine_id", h.machine_id);
        npf_jw_key(&w, "macs");
        npf_jw_arr(&w);
        for (i = 0; i < h.nmacs; i++)
            npf_jw_str(&w, h.macs[i]);
        npf_jw_end(&w);
        npf_jw_end(&w);
    }
    npf_jw_end(&w);
    n->login_sent_ms = npf_mono_ms();
    if (npf_jw_finish(&w) < 0 || npf_node_send(n, "login", 1, data) < 0)
        npf_logw("login: send failed");
}

/* ---- one key per model: enrol (security.md 5.2) ---- */

/* what an enrolment refusal's reason means (signaling.md "enroll") */
static const char *enroll_why(const char *err, const char *reason)
{
    static const struct { const char *r, *text; } t[] = {
        {"bad_chain", "the model credential is not one NPF's vendors signed"},
        {"bad_sig", "the enrolment's signatures are wrong"},
        {"unregistered", "the model is not registered on the platform (the vendor registers it)"},
        {"unbound", "this model credential was never given to the platform (the vendor binds it)"},
        {"revoked", "the model is disabled or this model credential revoked"},
        {"expired", "the model's registration has ended"},
        {"whitelist", "this serial number is not on the model's whitelist"},
        {"quota", "the model has all the devices it may have"},
        {"rate", "the model has had all its enrolments this hour"},
        {"clone", "a device with this serial number is online with other keys"},
        {"conflict", "this serial number belongs to another device (its owner releases it)"},
        {"wait", "the old identity was online moments ago"},
        {"disabled", "this device's number is disabled on the platform"},
    };
    size_t i;
    for (i = 0; reason[0] && i < sizeof t / sizeof t[0]; i++)
        if (strcmp(reason, t[i].r) == 0)
            return t[i].text;
    return strcmp(err, "rate_limited") == 0 ? "over the model's quota or rate, or the old identity was online moments ago"
           : strcmp(err, "conflict") == 0   ? "this serial number belongs to another device (the owner releases it)"
           : strcmp(err, "forbidden") == 0  ? "revoked credential, serial not on the whitelist, or the old identity is online"
                                            : "no reason given";
}

static void enroll_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    char num[24], err[32] = "no reply", reason[24] = "";
    int d, cl;
    (void)arg;
    if (!j)
        return;                             /* the connection went: enrol again on the next one */
    d = npf_json_get(j, 0, "data");
    if (!ok || npf_json_get_str(j, d, "number", num, sizeof num) <= 0
        || (cl = npf_json_get_b64(j, d, "cert", n->cert, sizeof n->cert)) <= 0) {
        npf_json_get_str(j, 0, "error", err, sizeof err);
        npf_json_get_str(j, 0, "message", reason, sizeof reason);
        npf_loge("enrol: refused (%s%s%s): %s", err, reason[0] ? ", " : "", reason, enroll_why(err, reason));
        if (n->backoff_ms < 10000)
            n->backoff_ms = 10000;          /* enrol again later, not every second */
        n->enroll_state = NPF_ENROLL_REFUSED;
        snprintf(n->enroll_error, sizeof n->enroll_error, "%s", err);
        snprintf(n->enroll_reason, sizeof n->enroll_reason, "%s", reason);
        n->enroll_at_unix_ms = npf_unix_ms();
        if (n->hooks.on_enroll_failed)
            n->hooks.on_enroll_failed(n, err, reason, n->backoff_ms / 1000, n->hook_arg);
        sig_abort(n, "enrolment refused");
        return;
    }
    n->enroll_state = NPF_ENROLL_DONE;
    n->enroll_error[0] = n->enroll_reason[0] = 0;
    n->enroll_at_unix_ms = npf_unix_ms();
    n->cert_len = (size_t)cl;
    n->cfg.number = strtoull(num, NULL, 10);
    n->cfg.callable = 1;
    npf_log("enrol: number %.3s %.3s %.3s", num, num + 3, num + 6);
    if (n->hooks.on_enrolled)
        n->hooks.on_enrolled(n, n->cfg.number, n->hook_arg);
    send_login(n);                          /* on the same connection */
}

static void send_enroll(npf_node *n)
{
    const npf_enroll_req *e = n->cfg.enroll;
    uint8_t msg[64 + 1 + 64 + 32 + 32], sv[64], sd[64];   /* h is the 64-byte BLAKE2b handshake hash */
    size_t sl = strlen(e->serial), ml;
    char data[3072];
    int i;
    npf_jw w;
    if (sl == 0 || sl > 64) {
        npf_loge("enrol: no serial number (serial / serial_file)");
        return;
    }
    memcpy(msg, npf_sig_hash(n->sig), 64);
    msg[64] = (uint8_t)sl;
    memcpy(msg + 65, e->serial, sl);
    memcpy(msg + 65 + sl, e->hw_fp, 32);
    memcpy(msg + 97 + sl, n->id.sign_pub, 32);
    ml = 129 + sl;
    npf_sign2(sv, e->model_sk, "npf-enroll-v1", 13, msg, ml);
    npf_sign2(sd, n->id.sign_sk, "npf-enroll-v1", 13, msg, ml);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kb64(&w, "model_chain", e->model_chain, e->model_chain_len);
    npf_jw_kstr(&w, "serial", e->serial);
    npf_jw_key(&w, "hw");
    npf_jw_arr(&w);
    for (i = 0; i < e->nhw; i++) {
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "k", e->hw_kind[i]);
        npf_jw_kb64(&w, "h", e->hw_hash[i], 16);
        npf_jw_end(&w);
    }
    npf_jw_end(&w);
    npf_jw_kb64(&w, "sign_pub", n->id.sign_pub, 32);
    npf_jw_kb64(&w, "sig_v", sv, 64);
    npf_jw_kb64(&w, "sig_d", sd, 64);
    if (n->cfg.model) npf_jw_kstr(&w, "model", n->cfg.model);
    if (n->cfg.fw) npf_jw_kstr(&w, "fw", n->cfg.fw);
    npf_jw_end(&w);
    {
        char kinds[8 * 17] = "";
        size_t o = 0;
        for (i = 0; i < e->nhw && o < sizeof kinds; i++)
            o += (size_t)snprintf(kinds + o, sizeof kinds - o, "%s%s", i ? ", " : "", e->hw_kind[i]);
        npf_log("enrol: serial %s with the model credential, hardware items: %s", e->serial, kinds);
    }
    if (npf_jw_finish(&w) < 0 || npf_node_request(n, "enroll", data, enroll_reply, NULL) < 0) {
        npf_logw("enrol: send failed");
        return;
    }
    if (n->enroll_state != NPF_ENROLL_REFUSED)
        n->enroll_state = NPF_ENROLL_SENT;  /* a refusal stays until the next answer */
}

static void parse_daykeys(const npf_json *j, int arr, npf_daykey out[2])
{
    int i;
    memset(out, 0, 2 * sizeof *out);
    for (i = 0; arr >= 0 && i < j->tok[arr].size && i < 2; i++) {
        int it = npf_json_item(j, arr, i);
        int64_t d;
        if (npf_json_get_int(j, it, "day", 0, INT32_MAX, &d) == 0
            && npf_json_get_b64(j, it, "key", out[i].key, 32) == 32)
            out[i].day = d;
    }
}

const uint8_t *node_day_key(const npf_node *n, const npf_daykey keys[2])
{
    int64_t day = npf_node_time(n) / 86400000;
    int i;
    for (i = 0; i < 2; i++)
        if (keys[i].day == day)
            return keys[i].key;
    return keys[0].day ? keys[0].key : NULL;
}

/* the address probes the server names (login, "keys", "probe"): E1, E2 on
 * one probe server, E3 on another; none: no probe there. Returns 1 when
 * they changed */
static int node_apply_probe(npf_node *n, const npf_json *j, int d)
{
    struct sockaddr_in old[3];
    int pr = npf_json_get(j, d, "probe"), k, nold = n->nprobe_ep;
    memcpy(old, n->probe_ep, sizeof old);
    memset(n->probe_ep, 0, sizeof n->probe_ep);
    n->nprobe_ep = 0;
    for (k = 0; pr >= 0 && j->tok[pr].type == NPF_JT_ARRAY && k < j->tok[pr].size && n->nprobe_ep < 3; k++) {
        char a[64];
        struct sockaddr_storage ss;
        if (npf_json_str(j, npf_json_item(j, pr, k), a, sizeof a) > 0 && npf_addr_parse(a, &ss) == 0
            && ss.ss_family == AF_INET)
            memcpy(&n->probe_ep[n->nprobe_ep++], &ss, sizeof(struct sockaddr_in));
    }
    return n->nprobe_ep != nold || memcmp(old, n->probe_ep, sizeof old) != 0;
}

/* other probes while online (another server came or went): measured again */
static void probe_changed(npf_node *n)
{
    if (n->online && n->udp_fd >= 0 && !n->probe)
        node_nat_refresh(n);
}

void node_apply_keys(npf_node *n, const npf_json *j, int d)
{
    uint8_t t[64];
    if (npf_json_get_b64(j, d, "ticket", t, sizeof t) == 28)
        memcpy(n->ticket, t, 28);
    parse_daykeys(j, npf_json_get(j, d, "probe_keys"), n->probe_keys);
    parse_daykeys(j, npf_json_get(j, d, "relay_keys"), n->relay_keys);
}

/* a renewed account (client) certificate from welcome: keep it and tell the program */
static void node_accept_account_cert(npf_node *n, const uint8_t *blob, size_t bl)
{
    npf_cert inter, leaf;
    if (bl > sizeof n->account_cert
        || npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, blob, bl, &inter, &leaf,
                                npf_node_time(n) / 1000) < 0
        || leaf.type != NPF_CERT_CLIENT || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
        npf_log("login: received account certificate does not verify, ignored");
        return;
    }
    memcpy(n->account_cert, blob, bl);
    n->account_cert_len = bl;
    npf_log("login: account certificate renewed (expires in %lld days)",
            (long long)(leaf.not_after - npf_node_time(n) / 1000) / 86400);
    if (n->on_account_cert)
        n->on_account_cert(n, n->on_account_cert_arg);
}

static void handle_welcome(npf_node *n, const npf_json *j, int d)
{
    int64_t t, v;
    char buf[64];
    uint8_t *blob = malloc(65536);      /* per call: other instances' threads */
    const size_t blob_cap = 65536;
    int bl;
    if (!blob)
        return;
    if (npf_json_get_int(j, d, "time", 0, INT64_MAX, &t) == 0) {
        /* welcome.time was read half a round trip ago (punch start_at needs this) */
        int64_t rtt = npf_mono_ms() - n->login_sent_ms;
        n->clock_offset_ms = t + (rtt > 0 && rtt < 10000 ? rtt / 2 : 0) - npf_unix_ms();
    }
    if (npf_json_get_int(j, d, "server_id", 0, 1 << 30, &v) == 0)
        n->server_id = (int)v;
    if (npf_json_get_str(j, d, "client_id", buf, sizeof buf) > 0)
        n->client_id = strtoull(buf, NULL, 10);
    n->account_id = npf_json_get_str(j, d, "account_id", buf, sizeof buf) > 0 ? strtoull(buf, NULL, 10) : 0;
    if (!n->account_id && n->account_cert_len) {
        /* the platform no longer accepts our account session */
        npf_logw("login: account session expired or revoked, log in again");
        n->account_cert_len = 0;
        if (n->on_account_lost)
            n->on_account_lost(n, n->hook_arg);
    }
    if (npf_json_get_int(j, d, "ping_s", 5, 3600, &v) == 0)
        n->ping_s = (int)v;
    node_apply_keys(n, j, d);
    node_apply_probe(n, j, d);          /* measured below (node_nat_login) */
    /* a (re)issued certificate: a node's own certificate in "cert"; the
     * account (client) certificate in "account_cert" for nodes, in "cert" for
     * pure clients (signaling.md "welcome") */
    bl = npf_json_get_b64(j, d, "cert", blob, blob_cap);
    if (bl > 0 && (size_t)bl <= sizeof n->cert) {
        npf_cert inter, leaf;
        if (npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, blob, (size_t)bl,
                                 &inter, &leaf, npf_node_time(n) / 1000) < 0
            || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
            npf_log("login: received certificate does not verify, ignored");
        } else if (n->cfg.callable && leaf.type == NPF_CERT_NODE) {
            memcpy(n->cert, blob, (size_t)bl);
            n->cert_len = (size_t)bl;
            npf_log("login: certificate issued (expires in %lld days)",
                    (long long)(leaf.not_after - npf_node_time(n) / 1000) / 86400);
            if (n->on_cert)
                n->on_cert(n, n->on_cert_arg);
        } else if (!n->cfg.callable && leaf.type == NPF_CERT_CLIENT) {
            node_accept_account_cert(n, blob, (size_t)bl);
        } else {
            npf_logw("login: certificate of the wrong type, ignored");
        }
    }
    bl = npf_json_get_b64(j, d, "account_cert", blob, blob_cap);
    if (bl > 0 && (size_t)bl <= sizeof n->account_cert)
        node_accept_account_cert(n, blob, (size_t)bl);
    bl = npf_json_get_b64(j, d, "server_list", blob, blob_cap);
    if (bl > 0)
        node_server_list_update(n, blob, (size_t)bl, NULL);
    free(blob);
    n->online = 1;
    n->logins++;
    n->last_login_unix_ms = npf_unix_ms();
    n->unreachable_since = 0;
    n->src_backoff = 0;
    n->src_next = 0;
    if (n->t_login) {
        npf_timer_cancel(n->loop, n->t_login);
        n->t_login = NULL;
    }
    n->backoff_ms = 0;
    if (n->cur_server >= 0)
        n->servers[n->cur_server].fails = 0;
    npf_log("login: online at server %d (clock offset %lld ms)", n->server_id, (long long)n->clock_offset_ms);
    if (n->t_ping)
        npf_timer_cancel(n->loop, n->t_ping);
    n->t_ping = npf_timer_add(n->loop, (n->ping_s > 0 ? n->ping_s : 25) * 1000, ping_cb, n);
    ends_flush(n);                      /* call ends from while signaling was down */
    idle_watch(n);
    node_nat_login(n);                  /* calls hooks.on_login, at once or after the first probe */
}

/* the first access point to finish the Noise handshake stays, the other one
 * is closed before it logs in (security.md 7.5) */
static void sig_ready(npf_sig *s, void *arg)
{
    npf_node *n = arg;
    if (s == n->race) {
        npf_log("signaling: server %d %s answered first", n->servers[n->race_server].id, "(second access point)");
        if (n->sig)
            npf_sig_close(n->sig);
        n->sig = s;
        n->cur_server = n->race_server;
        n->race = NULL;
    } else if (s != n->sig) {
        return;
    } else {
        race_drop(n);
    }
    if (n->cfg.enroll && !n->cfg.number)
        send_enroll(n);                     /* the first message instead of login (security.md 5.2) */
    else
        send_login(n);
}

static void sig_msg(npf_sig *s, const npf_json *j, void *arg)
{
    npf_node *n = arg;
    int d = npf_json_get(j, 0, "data");
    int reply = npf_json_get(j, 0, "reply_to") >= 0;
    char type[32];
    (void)s;
    if (npf_json_get_str(j, 0, "type", type, sizeof type) < 0 || d < 0 || j->tok[d].type != NPF_JT_OBJECT)
        return;
    if (npf_log_on(NPF_LOG_TRACE)) {     /* the envelope only (R10) */
        char id[24] = "", rt[24] = "", st[16] = "", er[32] = "";
        npf_json_get_str(j, 0, "id", id, sizeof id);
        npf_json_get_str(j, 0, "reply_to", rt, sizeof rt);
        npf_json_get_str(j, 0, "status", st, sizeof st);
        npf_json_get_str(j, 0, "error", er, sizeof er);
        npf_logt("sig < %s%s%s%s%s%s%s%s%s, %zu bytes", type, id[0] ? " id=" : "", id, rt[0] ? " reply_to=" : "", rt,
                 st[0] ? " " : "", st, er[0] ? " " : "", er, (size_t)j->len);
    }
    if (reply) {
        char rt[24];
        int i;
        if (npf_json_get_str(j, 0, "reply_to", rt, sizeof rt) > 0 && rt[0] == 'r') {
            int id = atoi(rt + 1);
            for (i = 0; i < 16; i++) {
                if (n->pending[i].fn && n->pending[i].id == id) {
                    npf_reply_fn fn = n->pending[i].fn;
                    n->pending[i].fn = NULL;
                    fn(n, j, npf_json_eq(j, npf_json_get(j, 0, "status"), "ok"), n->pending[i].arg);
                    return;
                }
            }
        }
    }
    if (strcmp(type, "login") == 0 && reply) {
        if (npf_json_eq(j, npf_json_get(j, 0, "status"), "ok")) {
            handle_welcome(n, j, d);
        } else {
            char err[32] = "";
            npf_json_get_str(j, 0, "error", err, sizeof err);
            npf_logw("login: rejected (%s)", err);
            if (n->cur_server >= 0)
                server_failed(&n->servers[n->cur_server], 3);
            n->sig = NULL;
            npf_sig_close(s);
            schedule_reconnect(n);
        }
        return;
    }
    if (strcmp(type, "server_list") == 0) {
        uint8_t *blob = malloc(65536);
        int bl = blob ? npf_json_get_b64(j, d, "blob", blob, 65536) : -1;
        if (bl > 0)
            node_server_list_update(n, blob, (size_t)bl, NULL);
        free(blob);
        return;
    }
    if (strcmp(type, "probe") == 0) {
        if (node_apply_probe(n, j, d))
            probe_changed(n);
        return;
    }
    if (strcmp(type, "replaced") == 0) {    /* the server closes this connection next */
        n->replaced = 1;
        return;
    }
    if (strcmp(type, "keys") == 0) {
        node_apply_keys(n, j, d);
        if (node_apply_probe(n, j, d))
            probe_changed(n);
        return;
    }
    if (strcmp(type, "redirect") == 0) {
        int64_t sid;
        int i;
        if (npf_json_get_int(j, d, "server_id", 0, 1 << 30, &sid) < 0)
            return;
        for (i = 0; i < n->nservers; i++)
            if (n->servers[i].id == sid)
                break;
        if (i == n->nservers)
            return;     /* not in the signed list: ignore */
        npf_log("redirect to server %lld", (long long)sid);
        n->cur_server = i;
        n->sig = NULL;
        npf_sig_close(s);
        n->online = 0;
        n->backoff_ms = 1000;
        schedule_reconnect(n);
        return;
    }
    node_dispatch(n, type, j, d);
}

static void sig_down(npf_sig *s, const char *why, void *arg)
{
    npf_node *n = arg;
    int was_online = n->online && n->sig == s;
    if (s == n->race) {             /* the second access point failed: the first one goes on */
        npf_log("signaling: second access point server %d failed (%s)", n->servers[n->race_server].id, why);
        server_failed(&n->servers[n->race_server], 1);
        n->race = NULL;
        return;
    }
    if (n->sig != s)
        return;
    if (n->race && !n->online) {    /* the first failed while the second still tries */
        npf_log("signaling: server %d failed (%s), waiting for the second access point", n->cur_server >= 0 ?
                n->servers[n->cur_server].id : -1, why);
        if (n->cur_server >= 0)
            server_failed(&n->servers[n->cur_server], 1);
        n->sig = n->race;
        n->cur_server = n->race_server;
        n->race = NULL;
        return;
    }
    if (!n->online && npf_net_bypass_active()) {
        /* no login this time: the next attempt the other way (around a VPN, or
         * on the default route for servers reachable through the VPN only) */
        n->sig_via_vpn = !n->sig_via_vpn;
        npf_log("signaling: the next attempt %s", n->sig_via_vpn ? "on the default route (through the VPN)"
                                                                : "around the VPN");
    }
    n->sig = NULL;
    n->online = 0;
    if (n->t_ping) {
        npf_timer_cancel(n->loop, n->t_ping);
        n->t_ping = NULL;
    }
    expect_stop(n);
    if (n->replaced) {
        /* not the server's fault: the same identity logged in again elsewhere
         * (another process with these files, a copy of them on another host).
         * Taking it back at once would push that one off in turn, both every
         * second; back off instead, and say why */
        int up = n->last_login_unix_ms && npf_unix_ms() - n->last_login_unix_ms > 120000;
        n->replaced = 0;
        n->replaced_backoff_ms = up || !n->replaced_backoff_ms ? 10000
                                 : n->replaced_backoff_ms * 2 > 300000 ? 300000 : n->replaced_backoff_ms * 2;
        n->backoff_ms = n->replaced_backoff_ms;
        npf_logw("signaling: this identity logged in elsewhere (another npf with the same files?): "
                 "logging in again in %d s", n->replaced_backoff_ms / 1000);
    } else if (n->cur_server >= 0)
        server_failed(&n->servers[n->cur_server], 1);
    npf_log("signaling: disconnected (%s)", why);
    fail_pending(n);
    node_sig_lost(n);
    schedule_reconnect(n);
    if (was_online && n->hooks.on_offline)
        n->hooks.on_offline(n, why, n->hook_arg);
}

static void connect_server(npf_node *n)
{
    static const npf_sig_cbs cbs = {sig_ready, sig_msg, sig_down};
    npf_server_entry *e;
    int i;
    if (n->sig)
        return;
    if (n->cur_server < 0 || n->servers[n->cur_server].fails >= 3)
        n->cur_server = pick_server(n);
    if (n->cur_server < 0) {
        npf_log("signaling: no usable server in the list");
        schedule_reconnect(n);
        return;
    }
    e = &n->servers[n->cur_server];
    i = e->fails % (e->nws ? e->nws : 1);
    npf_log("signaling: connecting to server %d %s", e->id, e->ws[i]);
    /* around a VPN like the UDP sockets (connect_mode p2p: a tunnel that
     * stalls after the system slept took the signaling with it, 2026-10-20);
     * through it the next time when going around did not log in */
    n->sig = npf_sig_open(n->loop, e->ws[i], e->dh_pub, &n->id, "npf-ws-v1", &cbs, n, !n->sig_via_vpn);
    if (!n->sig) {
        server_failed(e, 1);
        npf_logw("signaling: cannot connect to %s", e->ws[i]);
        schedule_reconnect(n);
        return;
    }
    {   /* and a second access point at the same time: the server's next URL
         * (a domain and an IP), else another server of the same priority */
        int r = -1, u = 0, k, total = 0;
        if (e->nws > 1) {
            r = n->cur_server;
            u = (i + 1) % e->nws;
        } else {
            for (k = 0; k < n->nservers; k++)
                if (k != n->cur_server && eff_prio(&n->servers[k]) == eff_prio(e) && n->servers[k].nws > 0)
                    total += n->servers[k].weight > 0 ? n->servers[k].weight : 1;
            if (total > 0) {
                int x = (int)npf_rand_range(0, (size_t)(total - 1));
                for (k = 0; k < n->nservers && r < 0; k++) {
                    if (k == n->cur_server || eff_prio(&n->servers[k]) != eff_prio(e) || n->servers[k].nws == 0)
                        continue;
                    x -= n->servers[k].weight > 0 ? n->servers[k].weight : 1;
                    if (x < 0)
                        r = k;
                }
                if (r >= 0)
                    u = n->servers[r].fails % n->servers[r].nws;
            }
        }
        if (r >= 0) {
            npf_server_entry *f = &n->servers[r];
            npf_log("signaling: and to server %d %s", f->id, f->ws[u]);
            n->race = npf_sig_open(n->loop, f->ws[u], f->dh_pub, &n->id, "npf-ws-v1", &cbs, n, !n->sig_via_vpn);
            n->race_server = r;
        }
    }
    if (n->t_login)
        npf_timer_cancel(n->loop, n->t_login);
    n->t_login = npf_timer_add(n->loop, SIG_LOGIN_MS, login_deadline, n);
}

/* ---- UDP ---- */

void npf_node_start(npf_node *n);
static void udp_failed(npf_node *n, int fd, const char *why);

static void udp_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r < 0) {
            int se = 0;
            socklen_t sl = sizeof se;
            if (!npf_sock_again() && npf_sock_broken())
                udp_failed(n, fd, npf_sock_strerror());
            else if ((ev & NPF_EV_ERROR) && getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&se, &sl) == 0
                     && npf_sock_broken_code(se))
                udp_failed(n, fd, npf_sock_strerror_code(se));
            break;
        }
        node_udp_input(n, fd, buf, (size_t)r, &from);
    }
}

static int open_udp(npf_node *n)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int fd = npf_udp_socket(AF_INET, 0);
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)n->cfg.udp_port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || getsockname(fd, (struct sockaddr *)&a, &al) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    {
        /* AnLiu bursts at its pacing rate; a small receive buffer drops whole
         * flights while the loop is busy. The kernel caps this at rmem_max. */
        int sz = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    }
    n->udp_fd = fd;
    n->udp_port = ntohs(a.sin_port);
    return npf_loop_add(n->loop, fd, NPF_EV_READ, udp_cb, n);
}

/* the IPv6 main socket (nat-traversal.md 7.1 S0): v6 only, the IPv4 port when
 * it is free; none when the host has no IPv6 (not an error) */
static void open_udp6(npf_node *n)
{
    struct sockaddr_in6 a;
    socklen_t al = sizeof a;
    int fd = npf_udp_socket(AF_INET6, 0), one = 1, k;
    if (fd < 0)
        return;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&one, sizeof one);
    for (k = 0; k < 2; k++) {
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(k == 0 ? n->udp_port : 0);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0)
            break;
    }
    if (k == 2 || getsockname(fd, (struct sockaddr *)&a, &al) < 0 || npf_loop_add(n->loop, fd, NPF_EV_READ, udp_cb, n) < 0) {
        npf_sock_close(fd);
        return;
    }
    {
        int sz = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof sz);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof sz);
    }
    n->udp6_fd = fd;
    n->udp6_port = ntohs(a.sin6_port);
}

int npf_node_init(npf_node *n, npf_loop *loop, const npf_node_cfg *cfg, const npf_identity *id,
                  const npf_node_hooks *hooks, void *arg)
{
    memset(n, 0, sizeof *n);
    n->started_unix_ms = npf_unix_ms();
    n->started_mono_ms = npf_mono_ms();
    n->loop = loop;
    n->cfg = *cfg;
    n->id = *id;
    if (hooks)
        n->hooks = *hooks;
    n->hook_arg = arg;
    n->cur_server = -1;
    n->udp_fd = -1;
    n->udp6_fd = -1;
    {
        const char *v = getenv("NPF_TEST_DROP_P2P");
        n->test_cut_ms = v ? atoll(v) : -1;
        n->test_cut_port = v && strchr(v, ':') ? atoi(strchr(v, ':') + 1) : 0;
    }
    n->punch_lead_ms = cfg->punch_lead_ms >= 0 ? cfg->punch_lead_ms : npf_firewall_lead_ms();
    {   /* four S3 hard sides at full size at once (256 each) when the descriptors allow */
        long lim = npf_fd_limit(4096);
        n->punch_budget = lim / 2 >= 1024 ? 1024 : lim / 2 < 64 ? 64 : (int)(lim / 2);
    }
    if (n->punch_lead_ms > 0)
        npf_log("node: punching starts %d ms early (%s)", n->punch_lead_ms,
                cfg->punch_lead_ms >= 0 ? "punch_lead_ms" : "the application firewall drops unsolicited UDP");
    if (!cfg->offline)
        load_server_list(n);
    if (n->nservers == 0 && !cfg->offline) {
        npf_log("node: no server list (built-in %s, saved %s)", cfg->serverlist_builtin ? cfg->serverlist_builtin : "-",
                cfg->serverlist_saved ? cfg->serverlist_saved : "-");
        return -1;
    }
    if (cfg->udp_on_demand)
        return 0;                       /* the sockets when a session needs them */
    if (open_udp(n) < 0) {
        npf_loge("node: cannot open UDP socket: %s", npf_sock_strerror());
        return -1;
    }
    if (!cfg->offline)
        open_udp6(n);
    return 0;
}

/* ---- UDP on demand (cfg.udp_on_demand: hosted clients) ---- */

static void udp_new_port(npf_node *n);

int npf_node_udp_open(npf_node *n)
{
    if (!n->cfg.udp_on_demand || n->udp_fd >= 0)
        return 0;
    if (open_udp(n) < 0) {
        npf_loge("udp: cannot open the socket: %s", npf_sock_strerror());
        if (n->udp_fd >= 0)
            npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
        return -1;
    }
    if (!n->cfg.offline)
        open_udp6(n);
    udp_new_port(n);
    return 0;
}

/* a new main socket (another port): the address the last probe found is not
 * this socket's, unless the operator says it is public and that probe agreed */
static void udp_new_port(npf_node *n)
{
    if (n->cfg.udp_public && n->nat_valid && n->nat_udp && n->nat_kept_port) {
        n->srflx.sin_port = htons(n->udp_port);
        n->pred_port = 0;
        node_nat_regather(n);
        npf_log("udp: open (port %u), public as configured", n->udp_port);
    } else {
        /* the NAT measured before (a full probe): this socket's mapping only */
        n->nat_quick = n->nat_udp && n->nat.allocation != NPF_ALLOC_UNKNOWN;
        n->nat_valid = 0;
        npf_log("udp: open (port %u), %s", n->udp_port,
                n->nat_quick ? "its mapping to be measured (the NAT's port allocation is known)"
                             : "its NAT profile to be measured");
    }
}

int npf_node_udp_ready(npf_node *n)
{
    if (!n->cfg.udp_on_demand)
        return 1;
    if (n->udp_fd < 0 && npf_node_udp_open(n) < 0)
        return 1;                       /* none: the session goes without (the WS relay) */
    if (n->nat_valid)
        return 1;
    if (!n->probe)
        node_nat_refresh(n);
    if (!n->probe)
        return 1;                       /* no probe servers: as without one (local tests) */
    n->udp_waiters = 1;
    return 0;
}

static void udp_close(npf_node *n)
{
    if (n->udp_fd < 0)
        return;
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    n->udp_waiters = 0;
    npf_loop_del(n->loop, n->udp_fd);
    npf_sock_close(n->udp_fd);
    n->udp_fd = -1;
    if (n->udp6_fd >= 0) {
        npf_loop_del(n->loop, n->udp6_fd);
        npf_sock_close(n->udp6_fd);
        n->udp6_fd = -1;
    }
    npf_log("udp: closed until a session needs it");
}

/* ---- signaling on demand (cfg.sig_idle_ms: hosted clients) ---- */

#define SIG_IDLE_TICK_MS 1000

static void wake_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_wake = NULL;
    npf_node_wake(n, "periodic refresh");
}

/* nothing needs the connection: no call, no request waiting for its
 * reply, no call end to report, and the application agrees */
static int node_busy(npf_node *n)
{
    int i;
    if (n->calls)
        return 1;
    for (i = 0; i < (int)(sizeof n->pending / sizeof n->pending[0]); i++)
        if (n->pending[i].fn)
            return 1;
    for (i = 0; i < NPF_ENDS_MAX; i++)
        if (n->ends[i].state)
            return 1;
    return n->hooks.busy && n->hooks.busy(n, n->hook_arg);
}

static void idle_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t now = npf_mono_ms();
    n->t_idle = NULL;
    if (!n->online || n->dormant)
        return;
    if (node_busy(n))
        n->busy_at = now;
    if (now - n->busy_at < n->cfg.sig_idle_ms) {
        n->t_idle = npf_timer_add(loop, SIG_IDLE_TICK_MS, idle_cb, n);
        return;
    }
    npf_log("signaling: not needed for %d s: disconnecting until it is", n->cfg.sig_idle_ms / 1000);
    race_drop(n);
    if (n->sig)
        npf_sig_close(n->sig);
    n->sig = NULL;
    n->online = 0;
    n->dormant = 1;
    n->sleeps++;
    if (n->cfg.udp_on_demand && !n->calls)
        udp_close(n);
    if (n->t_ping)
        npf_timer_cancel(loop, n->t_ping);
    n->t_ping = NULL;
    expect_stop(n);
    fail_pending(n);
    if (n->cfg.sig_wake_ms > 0)
        n->t_wake = npf_timer_add(loop, n->cfg.sig_wake_ms, wake_cb, n);
}

/* logged in: on demand, watch for the time nothing needs the connection */
static void idle_watch(npf_node *n)
{
    if (n->cfg.sig_idle_ms <= 0 || n->t_idle)
        return;
    n->busy_at = npf_mono_ms();
    n->t_idle = npf_timer_add(n->loop, SIG_IDLE_TICK_MS, idle_cb, n);
}

int npf_node_wake(npf_node *n, const char *why)
{
    if (!n->dormant)
        return 0;
    n->dormant = 0;
    if (n->t_wake)
        npf_timer_cancel(n->loop, n->t_wake);
    n->t_wake = NULL;
    npf_log("signaling: connecting (%s)", why);
    n->backoff_ms = 0;
    connect_server(n);
    return 1;
}

/* ---- the network watch ----
 * libnpf mends its connections by itself when the process was suspended (an
 * iOS app in the background, a laptop's sleep) or the network changed (Wi-Fi
 * to mobile data): the application does nothing. A timer tick that comes
 * late on a clock that counts sleep tells a suspension; the interfaces'
 * addresses tell another network. Either way the signaling connection is
 * pinged at once (dropped when it does not answer), the NAT measured again,
 * the direct paths checked both ways, and the peers waiting to reconnect try
 * now. A main socket that failed (iOS reclaims a suspended app's sockets) is
 * reopened; the calls on it end and their peers reconnect. */

#define WATCH_TICK_MS    2000
#define WATCH_LATE_MS    10000          /* a tick this late: the process was suspended */
#define NETCHECK_MS      8000           /* the signaling must answer a check's ping this soon */
#define UDP_REOPEN_RETRY_MS 5000

static void node_net_check(npf_node *n, const char *why);

/* a digest of the interfaces' addresses: IPv4, and the /64 prefix of global
 * IPv6 ones (temporary addresses change within it every day); in any order */
static uint32_t addrs_digest(void)
{
    npf_ifaddr a[32];
    int k, cnt = npf_if_list(a, 32);
    uint32_t sum = 0, nused = 0;
    for (k = 0; k < cnt; k++) {
        uint32_t h = 2166136261u;
        int i, len;
        if (a[k].loopback)
            continue;
        if (a[k].family == AF_INET6) {
            if ((a[k].addr[0] & 0xe0) != 0x20)  /* 2000::/3 only */
                continue;
            len = 8;
        } else {
            len = 4;
        }
        h = (h ^ (uint32_t)a[k].family) * 16777619u;
        for (i = 0; i < len; i++)
            h = (h ^ a[k].addr[i]) * 16777619u;
        sum += h;
        nused++;
    }
    return (sum ^ (nused * 2654435761u)) | 1;   /* never 0 ("not yet") */
}

/* the zero-length datagram to the discard port of the loopback: a socket
 * that has failed says so (an unconnected UDP socket hears no ICMP) */
static int udp_alive(int fd, int family)
{
    struct sockaddr_storage to;
    memset(&to, 0, sizeof to);
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&to;
        a->sin6_family = AF_INET6;
        a->sin6_addr.s6_addr[15] = 1;
        a->sin6_port = htons(9);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&to;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(0x7f000001);
        a->sin_port = htons(9);
    }
    if (sendto(fd, "", 0, 0, (struct sockaddr *)&to,
               family == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6) : (socklen_t)sizeof(struct sockaddr_in)) >= 0)
        return 1;
    return npf_sock_again() || !npf_sock_broken();
}

static void udp_reopen_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int old4 = n->udp_fd, old6 = n->udp6_fd;
    uint16_t was = n->udp_port;
    (void)loop;
    n->t_udp_reopen = NULL;
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    if (old4 >= 0)
        npf_node_calls_lost_fd(n, old4, "udp_socket_failed");
    if (old6 >= 0)
        npf_node_calls_lost_fd(n, old6, "udp_socket_failed");
    if (old4 >= 0) {
        npf_loop_del(n->loop, old4);
        npf_sock_close(old4);
    }
    if (old6 >= 0) {
        npf_loop_del(n->loop, old6);
        npf_sock_close(old6);
    }
    n->udp_fd = n->udp6_fd = -1;
    n->udp_waiters = 0;
    if (n->cfg.udp_on_demand) {             /* the next session opens them */
        npf_log("udp: closed until a session needs it");
        return;
    }
    if (open_udp(n) < 0) {
        npf_loge("udp: cannot open the socket again: %s; trying again in %d s", npf_sock_strerror(),
                 UDP_REOPEN_RETRY_MS / 1000);
        if (n->udp_fd >= 0)
            npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
        n->t_udp_reopen = npf_timer_add(n->loop, UDP_REOPEN_RETRY_MS, udp_reopen_cb, n);
        return;
    }
    if (!n->cfg.offline)
        open_udp6(n);
    udp_new_port(n);
    if (n->udp_port != was && !n->cfg.offline)
        node_portmap_restart(n);
    node_net_check(n, "the UDP socket was reopened");
}

/* a main socket failed: out of the loop now (no busy loop on its error),
 * reopened right after this callback */
static void udp_failed(npf_node *n, int fd, const char *why)
{
    npf_loop_del(n->loop, fd);
    if (n->t_udp_reopen)
        return;
    npf_logw("udp: the %s socket failed (%s), reopening", fd == n->udp6_fd ? "IPv6" : "IPv4", why);
    n->t_udp_reopen = npf_timer_add(n->loop, 0, udp_reopen_cb, n);
}

void npf_node_set_secure(npf_node *n, int on)
{
    if (n->cfg.secure == (on != 0))
        return;
    n->cfg.secure = on != 0;
    npf_udp_hook_on(!on);
    npf_log("connect_mode %s: %s", on ? "secure" : "p2p",
            on ? "relays only, no address to the peers, a VPN kept" : "direct paths first, around a VPN");
    npf_node_report_nat(n);
    npf_node_udp_reset(n, "connect_mode changed");  /* the sessions open again under it */
}

void npf_node_udp_reset(npf_node *n, const char *why)
{
    if (n->t_udp_reopen || (n->udp_fd < 0 && n->udp6_fd < 0))
        return;
    npf_log("udp: opening the sockets again (%s)", why);
    if (n->udp_fd >= 0)
        npf_loop_del(n->loop, n->udp_fd);
    if (n->udp6_fd >= 0)
        npf_loop_del(n->loop, n->udp6_fd);
    n->t_udp_reopen = npf_timer_add(n->loop, 0, udp_reopen_cb, n);
}

static void netcheck_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_netcheck = NULL;
    if (n->sig && n->online && npf_sig_last_rx(n->sig) < n->netcheck_ms) {
        n->backoff_ms = 0;
        sig_abort(n, "no answer after a network change");
    }
}

static void node_net_check(npf_node *n, const char *why)
{
    n->netchecks++;
    npf_log("network: %s: checking the connections", why);
    if (n->udp_fd >= 0 && !n->t_udp_reopen && !udp_alive(n->udp_fd, AF_INET)) {
        udp_failed(n, n->udp_fd, npf_sock_strerror());
        return;                             /* the reopen checks again */
    }
    if (n->udp6_fd >= 0 && !n->t_udp_reopen && !udp_alive(n->udp6_fd, AF_INET6)) {
        udp_failed(n, n->udp6_fd, npf_sock_strerror());
        return;
    }
    if (!n->cfg.offline && !n->dormant) {
        if (n->sig && n->online) {
            n->netcheck_ms = npf_mono_ms();
            npf_sig_ping(n->sig);
            if (n->t_netcheck)
                npf_timer_cancel(n->loop, n->t_netcheck);
            n->t_netcheck = npf_timer_add(n->loop, NETCHECK_MS, netcheck_cb, n);
            if (n->udp_fd >= 0) {           /* the mapping (perhaps a new NAT) */
                n->nat_quick = n->nat_udp && n->nat.allocation != NPF_ALLOC_UNKNOWN;
                node_nat_refresh(n);
            }
        } else {
            node_reconnect_now(n);
        }
    }
    npf_node_check_paths(n, why);
    n->repunch_on_nat = 1;                  /* with the new NAT's candidates (nat.c) */
    if (n->hooks.on_net_change)
        n->hooks.on_net_change(n, why, n->hook_arg);
}

static void watch_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t now = npf_boot_ms(), late = now - n->watch_boot_ms - WATCH_TICK_MS;
    uint32_t d = addrs_digest();
    char why[64];
    n->t_watch = npf_timer_add(loop, WATCH_TICK_MS, watch_cb, n);
    n->watch_boot_ms = now;
#ifndef _WIN32
    {   /* tests: NPF_TEST_UDP_FAIL=FILE: when FILE appears, the IPv4 socket
         * fails as a reclaimed one does (every call on it: ENOTSOCK) */
        const char *f = getenv("NPF_TEST_UDP_FAIL");
        int z;
        if (f && n->udp_fd >= 0 && remove(f) == 0 && (z = open("/dev/null", O_RDONLY)) >= 0) {
            npf_logw("test: the UDP socket fails now");
            dup2(z, n->udp_fd);
            close(z);
        }
    }
#endif
    /* a failed socket may never wake the loop (epoll forgets a descriptor
     * that is gone): asked every tick, one empty datagram each */
    if (!n->t_udp_reopen && ((n->udp_fd >= 0 && !udp_alive(n->udp_fd, AF_INET))
                             || (n->udp6_fd >= 0 && !udp_alive(n->udp6_fd, AF_INET6)))) {
        n->watch_addrs = d;
        udp_failed(n, n->udp_fd >= 0 && !udp_alive(n->udp_fd, AF_INET) ? n->udp_fd : n->udp6_fd,
                   npf_sock_strerror());
        return;                             /* the reopen checks the connections */
    }
    if (late >= WATCH_LATE_MS) {
        snprintf(why, sizeof why, "suspended for %lld s", (long long)(late / 1000));
        n->watch_addrs = d;
        node_net_check(n, why);
    } else if (d != n->watch_addrs) {
        int first = n->watch_addrs == 0;
        n->watch_addrs = d;
        if (!first)
            node_net_check(n, "the addresses changed");
    }
}

static void watch_start(npf_node *n)
{
    if (n->cfg.udp_on_demand)
        return;                             /* hosted clients: servers, many instances */
    n->watch_boot_ms = npf_boot_ms();
    n->watch_addrs = addrs_digest();
    n->t_watch = npf_timer_add(n->loop, WATCH_TICK_MS, watch_cb, n);
}

void npf_node_start(npf_node *n)
{
    watch_start(n);
    if (!n->cfg.offline) {
        node_portmap_start(n);
        connect_server(n);
    }
}

void npf_node_stop(npf_node *n)
{
    node_portmap_stop(n);
    node_calls_free(n);
    node_sources_stop(n);
    race_drop(n);
    if (n->sig)
        npf_sig_close(n->sig);
    n->sig = NULL;
    fail_pending(n);                        /* requests still waiting learn there is no reply (their memory goes) */
    if (n->t_reconnect)
        npf_timer_cancel(n->loop, n->t_reconnect);
    if (n->t_ping)
        npf_timer_cancel(n->loop, n->t_ping);
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    if (n->t_login)
        npf_timer_cancel(n->loop, n->t_login);
    n->t_reconnect = n->t_ping = n->t_login = NULL;
    if (n->t_idle)
        npf_timer_cancel(n->loop, n->t_idle);
    if (n->t_wake)
        npf_timer_cancel(n->loop, n->t_wake);
    n->t_idle = n->t_wake = NULL;
    n->dormant = 0;
    if (n->t_watch)
        npf_timer_cancel(n->loop, n->t_watch);
    if (n->t_netcheck)
        npf_timer_cancel(n->loop, n->t_netcheck);
    if (n->t_udp_reopen)
        npf_timer_cancel(n->loop, n->t_udp_reopen);
    if (n->t_nat_retry)
        npf_timer_cancel(n->loop, n->t_nat_retry);
    if (n->t_punch_gap)
        npf_timer_cancel(n->loop, n->t_punch_gap);
    n->t_punch_gap = NULL;
    n->t_watch = n->t_netcheck = n->t_udp_reopen = n->t_nat_retry = NULL;
    if (n->udp_fd >= 0) {
        npf_loop_del(n->loop, n->udp_fd);
        npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
    }
    if (n->udp6_fd >= 0) {
        npf_loop_del(n->loop, n->udp6_fd);
        npf_sock_close(n->udp6_fd);
        n->udp6_fd = -1;
    }
    free(n->servers);
    free(n->list);
    n->servers = n->list = NULL;
    n->nservers = n->nlist = 0;
    n->cur_server = -1;
}

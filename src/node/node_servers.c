/* Signed server lists and access-point selection. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"

/* ---- server list ---- */

/* the token arrays are per call: instances on other threads parse at the same time */
int npf_serverlist_parse(const char *json, size_t len, npf_server_entry *out, int64_t *serial, npf_list_meta *meta)
{
    npf_jtok *tok = malloc(NPF_JSON_MAX_TOKENS * sizeof *tok);
    m_list *l = malloc(sizeof *l);
    npf_json j;
    char err[96];
    int i, k, n = -1;
    if (tok && l && npf_json_parse(&j, json, len, tok, NPF_JSON_MAX_TOKENS) == 0) {
        if (npf_msg_parse(&m_list_d, &j, 0, l, err, sizeof err) < 0)
            npf_logw("server list: refused (%s)", err);
        else
            n = l->nservers;
    }
    for (i = 0; i < n; i++) {
        const m_server *s = &l->servers[i];
        npf_server_entry *e = &out[i];
        memset(e, 0, sizeof *e);
        e->id = (int)s->id;
        e->prio = (int)s->prio;
        e->weight = (int)s->weight;
        memcpy(e->ws, s->ws, sizeof e->ws);
        e->nws = s->nws;
        for (k = 0; k < s->nudp; k++)          /* IPv4 (F_V4): a sockaddr_in each */
            memcpy(&e->udp[k], &s->udp[k], sizeof e->udp[k]);
        e->nudp = s->nudp;
        memcpy(e->dh_pub, s->dh_pub, 32);
    }
    if (n >= 0) {
        *serial = l->serial;
        memset(meta, 0, sizeof *meta);
        meta->expires = l->expires;
        meta->full = l->full;
        memcpy(meta->doh, l->sources.doh, sizeof meta->doh);
        meta->ndoh = l->sources.ndoh;
        for (i = 0; i < l->sources.nhttps; i++)
            if (strncmp(l->sources.https[i], "https://", 8) == 0)
                memcpy(meta->https[meta->nhttps++], l->sources.https[i], sizeof meta->https[0]);
    }
    free(tok);
    free(l);
    return n;
}

/* a signed list's servers in tmp: their count (0: none usable), -1 when
 * the signature does not verify */
static int list_read(const npf_node *n, const uint8_t *blob, size_t len, npf_server_entry *tmp, int64_t *serial,
                     npf_list_meta *meta)
{
    const uint8_t *pl;
    size_t plen;
    int c;
    if (npf_signed_verify((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, NPF_PERM_SERVERLIST, blob, len, &pl,
                          &plen) < 0)
        return -1;
    c = npf_serverlist_parse((const char *)pl, plen, tmp, serial, meta);
    return c > 0 ? c : 0;
}

static int load_list_file(const npf_node *n, const char *path, int64_t *serial, npf_server_entry *tmp,
                          npf_list_meta *meta)
{
    char *blob;
    long len = npf_file_read(path, &blob);
    int c;
    if (len < 0)
        return 0;
    c = list_read(n, (const uint8_t *)blob, (size_t)len, tmp, serial, meta);
    free(blob);
    return c > 0 ? c : 0;
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
void node_servers_load(npf_node *n)
{
    /* scratch on the heap, per call (instances on other threads load theirs at the same time) */
    struct lists {
        npf_server_entry e[2][NPF_MAX_SERVERS];
        npf_list_meta    m[2];
    } *l = calloc(1, sizeof *l);
    int64_t s[2] = {-1, -1};
    int c[2] = {0, 0}, k;
    if (!l)
        return;
    if (n->cfg.serverlist_builtin)
        c[0] = load_list_file(n, n->cfg.serverlist_builtin, &s[0], l->e[0], &l->m[0]);
    if (n->cfg.serverlist_saved)
        c[1] = load_list_file(n, n->cfg.serverlist_saved, &s[1], l->e[1], &l->m[1]);
    k = c[0] && (!c[1] || s[0] >= s[1]) ? 0 : 1;
    if (c[k]) {
        n->nservers = servers_set(&n->servers, l->e[k], c[k]) < 0 ? 0 : c[k];
        n->sl_serial = n->sl_full_serial = s[k];
        n->sl_meta = l->m[k];
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
        n->nservers = 1;
    }
}

/* a server_list blob (login, push, or an external channel named by via):
 * verify, compare serial, adopt, save a full list. A seed list (full =
 * false, from DNS) is used but not saved: the full list on disk stays
 * (security.md 7.5). Returns 1 when adopted. */
int node_server_list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via)
{
    npf_server_entry *tmp = malloc(NPF_MAX_SERVERS * sizeof *tmp);
    npf_list_meta meta;
    int64_t serial;
    int c, r = 0;
    if (!tmp)
        return 0;
    if ((c = list_read(n, blob, len, tmp, &serial, &meta)) < 0)
        npf_logw("server list%s%s: signature check failed, ignored", via ? " from " : "", via ? via : "");
    /* newer than the list in use; a full list also replaces a seed list of
     * its own publish (the same serial: it was refused, and every login
     * then brought it again for nothing while the node kept the seed's few
     * servers) */
    if (c <= 0 || (meta.full ? serial <= n->sl_full_serial || serial < n->sl_serial : serial <= n->sl_serial))
        goto out;
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
        goto out;
    }
    n->nlist = c;
    if (!n->cfg.server_url) {
        n->nservers = c;
        n->cur_server = -1;
    }
    n->sl_serial = serial;
    npf_log("server list: serial %lld, %d servers%s%s%s", (long long)serial, c, meta.full ? "" : " (seed list)",
            via ? " from " : "", via ? via : "");
    r = 1;
out:
    free(tmp);
    return r;
}

#define SERVER_DEGRADE_MS (3600 * 1000)

/* a connection attempt to this entry failed; three in a row deprioritise it for an hour */
void node_server_failed(npf_server_entry *e, int weight)
{
    e->fails += weight;
    if (e->fails >= 3)
        e->degraded_until = npf_mono_ms() + SERVER_DEGRADE_MS;
}

static int degraded(const npf_server_entry *e)
{
    return e->fails >= 3 && npf_mono_ms() < e->degraded_until;
}

int node_eff_prio(const npf_server_entry *e)
{
    return e->prio + (degraded(e) ? 100 : 0);
}

/* entry i's weight in a pick of the entries of priority prio but skip (0: not one of them) */
static int pick_weight(const npf_node *n, int i, int prio, int skip)
{
    const npf_server_entry *e = &n->servers[i];
    if (i == skip || node_eff_prio(e) != prio || !e->nws)
        return 0;
    return e->weight > 0 ? e->weight : 1;
}

int node_server_pick(npf_node *n, int prio, int skip)
{
    int i, total = 0, r;
    if (prio < 0) {                         /* the best: recently failing entries sort behind the rest */
        prio = 1 << 30;
        for (i = 0; i < n->nservers; i++) {
            if (!degraded(&n->servers[i]) && n->servers[i].fails >= 3)
                n->servers[i].fails = 0;    /* the hour is over: a fresh start */
            if (node_eff_prio(&n->servers[i]) < prio)
                prio = node_eff_prio(&n->servers[i]);
        }
    }
    for (i = 0; i < n->nservers; i++)
        total += pick_weight(n, i, prio, skip);
    if (!total)
        return -1;
    r = (int)npf_rand_range(0, (size_t)(total - 1));
    for (i = 0; i < n->nservers; i++)
        if ((r -= pick_weight(n, i, prio, skip)) < 0)
            return i;
    return -1;
}

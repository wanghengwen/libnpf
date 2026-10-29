/* libnpf: the operations of npf.h's objects, each a public function that
 * runs on the instance's thread (npf_api_op): the peers in ops_peer.c, the
 * forwards in ops_forward.c, the resources in ops_resource.c, a device's
 * pairing in ops_pairing.c; here the structures' defaults, what the
 * operations share, the records in local.json, this node and its sessions.
 * The library has no command syntax for peers and forwards: the program's
 * command line (npf's modules) has its own over these same functions. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "npf/module.h"

/* ---- the structures' defaults ---- */

/* the defaults d into the application's s of size bytes (its sizeof): what
 * both builds know, zeros past this build's structure, size first */
static void init_sized(void *s, size_t size, const void *d, size_t dsize)
{
    if (!s || size < sizeof(size_t))
        return;
    put_out(s, size, d, dsize);
    memcpy(s, &size, sizeof size);
}

#define DEFAULTS(T, ...)                                                                                             \
    void T##_init_size(T *s, size_t size)                                                                            \
    {                                                                                                                \
        T d = {0, __VA_ARGS__};                                                                                      \
        init_sized(s, size, &d, sizeof d);                                                                           \
    }

DEFAULTS(npf_options, .log_level = -1)
DEFAULTS(npf_callbacks, .user = NULL)
DEFAULTS(npf_setup, .punch_lead_ms = -1)
DEFAULTS(npf_peer_opt, .target = NPF_TARGET_NUMBER)
DEFAULTS(npf_forward_opt, .kind = NPF_FWD_LOCAL)
DEFAULTS(npf_resource, .type = NPF_RES_TCP)
DEFAULTS(npf_media_opt, .prio = 1, .max_age_ms = 500, .fec = -1)

/* ---- what the operations share ---- */

int op_fail(op_arg *x, int rc, const char *fmt, ...)
{
    va_list ap;
    if (x && x->err && x->errcap) {
        va_start(ap, fmt);
        vsnprintf(x->err, x->errcap, fmt, ap);
        va_end(ap);
    }
    return rc;
}

int op_get(npf_t *n, int (*fn)(npf_t *n, void *arg), uint32_t id, void *out, size_t size)
{
    op_arg x = {.id = id, .out = out, .size = size};
    return out ? npf_api_op(n, fn, &x) : NPF_EINVAL;
}

int op_list(npf_t *n, int (*fn)(npf_t *n, void *arg), uint32_t id, void *out, size_t size, size_t cap,
            size_t *count)
{
    op_arg x = {.id = id, .out = out, .size = size, .cap = cap, .count = count};
    int rc;
    if (!count || (cap && !out))
        return NPF_EINVAL;
    *count = 0;
    rc = npf_api_op(n, fn, &x);
    return rc != NPF_OK ? rc : *count > cap ? NPF_ETOOBIG : NPF_OK;
}

const char *npf_source_name(int tag)
{
    return tag == NPF_PERSIST ? "saved" : tag == NPF_PLATFORM ? "platform" : "temporary";
}

/* ---- the records in local.json ---- */

/* forward i of p as a record: 0, 1 when it is not one to save, -1 none */
static int lfwd_of(const npf_peer *p, int i, npf_lfwd *lf)
{
    npf_fwd_state st;
    if (npf_peer_forward_state(p, i, &st) < 0)
        return -1;
    memset(lf, 0, sizeof *lf);
    lf->opt = st.opt;
    lf->udp = st.udp;
    if (st.opt == 'L' || st.opt == 'D' || st.opt == 'R') {
        snprintf(lf->bind, sizeof lf->bind, "%s", st.bind);
        lf->port = st.port;
        snprintf(lf->host, sizeof lf->host, "%s", st.host);
        lf->hostport = st.hostport;
    } else {
        snprintf(lf->spec, sizeof lf->spec, "%s", st.spec);
    }
    return st.perm && !st.ext ? 0 : 1;
}

int npf_ops_record(npf_t *n, npf_peer *p, int save, const char *psk_file)
{
    npf_ldev *d = npf_local_dev(&n->lc, npf_peer_name(p), save);
    int i;
    if (no_saved_objects(n))
        return NPF_OK;                      /* the application keeps its own */
    if (!d)
        return save ? NPF_EBUSY : NPF_OK;
    d->save = save;
    d->on_demand = save && npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND;
    d->idle_ms = save ? npf_peer_idle_asked(p) : 0;   /* NPF_PEER_OPT_IDLE_MS: kept for on demand */
    npf_local_fwd_clear(d);
    if (!save) {
        d->psk_file[0] = d->psk[0] = 0;
    } else {
        if (psk_file) {
            snprintf(d->psk_file, sizeof d->psk_file, "%s", psk_file);
            d->psk[0] = 0;
        } else if (!d->psk_file[0] && !d->psk[0] && npf_peer_psk(p)) {
            d->psk[npf_b64url_encode(npf_peer_psk(p), 32, d->psk)] = 0;  /* a direct peer: its key */
        }
        for (i = 0; i < npf_peer_nfwd(p); i++) {
            npf_lfwd lf;
            if (lfwd_of(p, i, &lf) == 0)
                npf_local_fwd_add(d, &lf);
        }
    }
    npf_mods_fwds_saved(n, d);
    return saved_rc(n);
}

int npf_ops_record_fwd(npf_t *n, npf_peer *p, int i, int add)
{
    npf_ldev *d = npf_local_dev(&n->lc, npf_peer_name(p), 0);
    npf_lfwd lf;
    if (no_saved_objects(n) || !d || !d->save || lfwd_of(p, i, &lf) < 0)
        return NPF_OK;
    if (add)
        npf_local_fwd_add(d, &lf);
    else
        npf_local_fwd_del(d, &lf);
    npf_mods_fwds_saved(n, d);
    return saved_rc(n);
}

/* "HOST:PORT" or "[V6]:PORT" into its parts; -1 without a port 1..65535 */
int npf_hostport_split(const char *s, char *host, size_t cap, uint16_t *port)
{
    const char *colon = strrchr(s, ':');
    char *end;
    long p;
    if (!colon || (s[0] == '[' && (colon < s + 2 || colon[-1] != ']')))
        return -1;
    p = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end || p < 1 || p > 65535)
        return -1;
    if (s[0] == '[')
        snprintf(host, cap, "%.*s", (int)(colon - s - 2), s + 1);
    else
        snprintf(host, cap, "%.*s", (int)(colon - s), s);
    *port = (uint16_t)p;
    return 0;
}

/* a record's forwards onto its peer brought back (one that does not make
 * a forward is left out, with a warning) */
static void restore_fwds(npf_peer *p, const npf_ldev *d)
{
    char e[300];
    int k, r;
    for (k = 0; k < d->nfwd; k++) {
        const npf_lfwd *lf = &d->fwd[k];
        if (lf->opt == 'L' || lf->opt == 'D' || lf->opt == 'R') {
            npf_fwd_new fn;
            memset(&fn, 0, sizeof fn);
            fn.opt = lf->opt;
            fn.udp = lf->udp;
            fn.bind = lf->bind[0] ? lf->bind : NULL;
            fn.port = lf->port;
            fn.host = lf->host;
            fn.hostport = lf->hostport;
            r = npf_peer_forward_add_parts(p, &fn, 1, 0, e, sizeof e);
        } else {
            r = npf_peer_forward_add_kind(p, lf->opt, lf->spec, 1, e, sizeof e);
        }
        if (r < 0)
            npf_logw("local.json: %s: a forward left out: %s", d->target, e);
    }
}

void npf_ops_restore(npf_t *n)
{
    int i;
    for (i = 0; i < n->lc.ndev; i++) {
        npf_ldev *d = &n->lc.dev[i];
        npf_peer_new pn;
        npf_peer *p;
        char host[300], path[1600], e[300];
        uint8_t psk[32];
        int code;
        if (!d->save || npf_peers_find(n->peers, d->target))
            continue;
        memset(&pn, 0, sizeof pn);
        memset(psk, 0, sizeof psk);
        if (!(pn.number = npf_number_parse(d->target))) {      /* a direct peer, with its key */
            if (npf_hostport_split(d->target, host, sizeof host, &pn.port) < 0)
                continue;
            pn.host = host;
            if (d->psk_file[0] && npf_path_is_abs(d->psk_file))
                snprintf(path, sizeof path, "%s", d->psk_file);
            else if (d->psk_file[0])
                snprintf(path, sizeof path, "%s/%s", n->data_dir, d->psk_file);
            if (npf_direct_psk(d->psk[0] ? d->psk : NULL, d->psk_file[0] ? path : NULL, psk) < 0) {
                npf_logw("local.json: %s: no key to connect with: left out", d->target);
                continue;
            }
            pn.psk = psk;
        }
        pn.connect = d->on_demand ? NPF_CONNECT_ON_DEMAND : NPF_CONNECT_KEEP;
        pn.idle_ms = d->idle_ms;
        p = npf_peers_create(n->peers, &pn, e, sizeof e, &code);
        npf_wipe(psk, sizeof psk);
        if (!p) {
            npf_logw("local.json: %s: %s: left out", d->target, e);
            continue;
        }
        npf_peer_set_tag(p, NPF_PERSIST);
        restore_fwds(p, d);
    }
}

/* ---- this node, sessions, the network, saving ---- */

static int node_get_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_node_info i;
    struct sockaddr_storage ss;
    char a[80];
    memset(&i, 0, sizeof i);
    i.number = n->has_number ? n->number : 0;
    i.role = n->role;
    i.online = n->node.online;
    i.server = n->node.online ? n->node.server_id : 0;
    i.account_id = n->node.account_id;
    i.enrolling = n->model_dev && !n->has_number;
    i.nat = n->node.nat_valid ? n->node.nat.mapping : NPF_NAT_UNKNOWN;
    i.nat_filtering = n->node.nat_valid ? n->node.nat.filtering : NPF_NAT_UNKNOWN;
    if (n->node.nat_valid && n->node.nat_udp) {
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &n->node.srflx, sizeof n->node.srflx);
        snprintf(i.public_addr, sizeof i.public_addr, "%s", npf_addr_str(&ss, a, sizeof a));
    }
    i.udp_port = n->node.udp_port;
    i.started = n->started_unix;
    i.peers = n->peers ? npf_peers_count(n->peers) : 0;
    i.sessions = n->nsess;
    i.unsaved = n->lc.unsaved;
    put_out(x->out, x->size, &i, sizeof i);
    return NPF_OK;
}

int npf_node_get_size(npf_t *n, npf_node_info *out, size_t size)
{
    return op_get(n, node_get_run, 0, out, size);
}

static int session_get_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_session_info i;
    npf_call_info ci;
    int k;
    for (k = 0; k < n->nsess && n->sess[k].id != x->id; k++)
        ;
    if (k == n->nsess)
        return NPF_ENOENT;
    npf_call_info_get(n->sess[k].call, &ci);
    memset(&i, 0, sizeof i);
    i.peer = peer_of(n, n->sess[k].peer) ? n->sess[k].peer : 0;     /* 0: removed since (or none) */
    i.number = ci.number;
    i.outgoing = ci.caller;
    i.path = ci.path_code;
    snprintf(i.call_id, sizeof i.call_id, "%s", ci.id);
    put_out(x->out, x->size, &i, sizeof i);
    return NPF_OK;
}

int npf_session_get_size(npf_t *n, uint32_t session, npf_session_info *out, size_t size)
{
    return op_get(n, session_get_run, session, out, size);
}

static int session_list_run(npf_t *n, void *arg)
{
    int k;
    for (k = 0; k < n->nsess; k++)
        list_put(arg, &n->sess[k].id, sizeof n->sess[k].id);
    return NPF_OK;
}

int npf_session_list(npf_t *n, uint32_t *sessions, size_t cap, size_t *count)
{
    return op_list(n, session_list_run, 0, sessions, sizeof *sessions, cap, count);
}

/* npf_network_changed and the command netcheck (an app: the network under a
 * VPN changed, npf_host). The peers try again once the sockets are open
 * again (on_net_change after the reopen's check): tried before, their
 * new sessions ended with the old socket (udp_socket_failed); at once
 * when nothing reopens */
void npf_net_changed(npf_t *n)
{
    if (npf_node_udp_reset(&n->node, "the network changed") < 0 && n->peers)
        npf_peers_net_changed(n->peers);
}

static int net_changed_run(npf_t *n, void *arg)
{
    (void)arg;
    if (!n->started)
        return NPF_ESTATE;
    npf_net_changed(n);
    return NPF_OK;
}

int npf_network_changed(npf_t *n)
{
    return npf_api_op(n, net_changed_run, NULL);
}

static int save_run(npf_t *n, void *arg)
{
    (void)arg;
    return saved_rc(n);
}

int npf_save(npf_t *n)
{
    return npf_api_op(n, save_run, NULL);
}

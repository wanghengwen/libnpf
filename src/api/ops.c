/* libnpf: the operations of npf.h's objects (peers, forwards, resources, a
 * device's pairing, this node's state), each a public function that runs on
 * the instance's thread (npf_api_op). The command line (cmd_peers.c,
 * publish.c, nodes.c) parses its words and goes through the same layer
 * below it: the peers' structured primitives (npf/peers.h) and the records
 * in local.json (npf_ops_record). The library has no command syntax for
 * peers and forwards: the application has its own over these. What a peer
 * may do depends on where it comes from: the application's (made, or
 * brought back from local.json) or the platform's (NPF_PLATFORM). Here the
 * structures' defaults, the records and this node; the peers in ops_peer.c,
 * the forwards in ops_forward.c, the resources in ops_resource.c, a
 * device's pairing in ops_pairing.c; what they share in ops_internal.h. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"
#include "npf/resources.h"
#include "ops_internal.h"

/* ---- the structures' defaults ---- */

void npf_peer_opt_init_size(npf_peer_opt *o, size_t size)
{
    npf_peer_opt d;
    memset(&d, 0, sizeof d);
    d.target = NPF_TARGET_NUMBER;
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_peer_info_init_size(npf_peer_info *o, size_t size)
{
    npf_peer_info d;
    memset(&d, 0, sizeof d);
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_forward_opt_init_size(npf_forward_opt *o, size_t size)
{
    npf_forward_opt d;
    memset(&d, 0, sizeof d);
    d.kind = NPF_FWD_LOCAL;
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_forward_info_init_size(npf_forward_info *o, size_t size)
{
    npf_forward_info d;
    memset(&d, 0, sizeof d);
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_resource_init_size(npf_resource *r, size_t size)
{
    npf_resource d;
    memset(&d, 0, sizeof d);
    d.type = NPF_RES_TCP;
    npf_init_sized(r, size, &d, sizeof d);
}

void npf_node_info_init_size(npf_node_info *o, size_t size)
{
    npf_node_info d;
    memset(&d, 0, sizeof d);
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_session_info_init_size(npf_session_info *o, size_t size)
{
    npf_session_info d;
    memset(&d, 0, sizeof d);
    npf_init_sized(o, size, &d, sizeof d);
}


/* ---- peers: where they come from ---- */

uint32_t npf_ops_flags(const npf_t *n, const npf_peer *p)
{
    (void)n;
    switch (npf_peer_tag(p)) {
    case PEER_SAVED: return NPF_PERSIST;
    case PEER_PLATFORM: return NPF_PLATFORM;
    default: return 0;
    }
}


/* forward i of p as a record */
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
    return st.perm && !st.ext ? 0 : 1;      /* 1: not one to save */
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
            d->psk[npf_b64url_encode(npf_peer_psk(p), 32, d->psk)] = 0;  /* saved later (PERSIST): its key */
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


/* ---- this node, sessions, the network, saving ---- */

static int node_get_run(npf_t *n, void *arg)
{
    npf_node_info i;
    struct sockaddr_storage ss;
    char a[80];
    memset(&i, 0, sizeof i);
    i.size = sizeof i;
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
    return copy_out(arg, &i, sizeof i) < 0 ? NPF_EINVAL : NPF_OK;
}

int npf_node_get(npf_t *n, npf_node_info *out)
{
    if (!out)
        return NPF_EINVAL;
    return npf_api_op(n, node_get_run, out);
}

int npf_path_code(const char *path)
{
    if (!path)
        return 0;
    if (strcmp(path, "direct") == 0 || strcmp(path, "p2p") == 0)
        return NPF_PATH_DIRECT;
    if (strncmp(path, "relay", 5) == 0)
        return NPF_PATH_UDP_RELAY;
    if (strcmp(path, "ws relay") == 0)
        return NPF_PATH_WS_RELAY;
    return 0;
}

static int session_get_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    npf_session_info i;
    npf_call_info ci;
    int k;
    for (k = 0; k < n->nsess && n->sess[k].id != x->id; k++)
        ;
    if (k == n->nsess)
        return NPF_ENOENT;
    npf_call_info_get(n->sess[k].call, &ci);
    memset(&i, 0, sizeof i);
    i.size = sizeof i;
    i.peer = n->sess[k].peer && peer_of(n, n->sess[k].peer) ? n->sess[k].peer : 0;
    i.number = ci.number;
    i.outgoing = ci.caller;
    i.path = npf_path_code(ci.path);
    snprintf(i.call_id, sizeof i.call_id, "%s", ci.id);
    return copy_out(x->out, &i, sizeof i) < 0 ? NPF_EINVAL : NPF_OK;
}

int npf_session_get(npf_t *n, uint32_t session, npf_session_info *out)
{
    pid_arg x = {.id = session, .out = out};
    if (!out)
        return NPF_EINVAL;
    return npf_api_op(n, session_get_run, &x);
}

static int session_list_run(npf_t *n, void *arg)
{
    list_arg *x = arg;
    int k;
    for (k = 0; k < n->nsess; k++)
        list_put(x, n->sess[k].id);
    return list_rc(*x->count, x->cap);
}

int npf_session_list(npf_t *n, uint32_t *sessions, size_t cap, size_t *count)
{
    list_arg x = {.ids = sessions, .cap = cap, .count = count};
    if (!count || (cap && !sessions))
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, session_list_run, &x);
}

static int net_changed_run(npf_t *n, void *arg)
{
    (void)arg;
    if (!n->started)
        return NPF_ESTATE;
    npf_node_udp_reset(&n->node, "the network changed");
    if (n->peers)
        npf_peers_net_changed(n->peers);
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

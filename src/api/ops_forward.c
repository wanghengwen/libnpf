/* libnpf: the operations on forwards (npf_forward_create and the rest):
 * made on a peer, listed, read, removed, their context. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "api_internal.h"

/* -R: where the peer listens, an address of its (loopback by default; any
 * other needs lan: in its reverse resource, the peer decides) */
static const char *remote_bind(const char *h)
{
    unsigned char b[16];
    if (!h || !*h || strcmp(h, "localhost") == 0)
        return "127.0.0.1";
    if (strcmp(h, "*") == 0)
        return "0.0.0.0";
    if (inet_pton(AF_INET, h, b) == 1 || inet_pton(AF_INET6, h, b) == 1)
        return h;
    return NULL;
}

static int fwd_create_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    const npf_forward_opt *o = x->in;
    npf_peer *p = peer_of(n, x->id);
    int persist = (o->flags & NPF_PERSIST) != 0, i, rc = NPF_OK;
    npf_fwd_new fn;
    npf_fwd_state st;
    if (!p)
        return NPF_ENOENT;
    if (npf_peer_tag(p) == NPF_PLATFORM)
        return NPF_EREADONLY;
    if (o->flags & ~NPF_PERSIST || o->kind < NPF_FWD_LOCAL || o->kind > NPF_FWD_REMOTE
        || (o->proto != NPF_PROTO_TCP && o->proto != NPF_PROTO_UDP)
        || (o->proto == NPF_PROTO_UDP && o->kind == NPF_FWD_SOCKS))
        return op_fail(x, NPF_EINVAL, "bad kind, protocol or flags (UDP: LOCAL and REMOTE)");
    if (persist && npf_peer_tag(p) != NPF_PERSIST)
        return op_fail(x, NPF_EINVAL, "a saved forward needs a saved peer");
    if (persist && no_saved_objects(n))
        return op_fail(x, NPF_EUNAVAIL, "forwards are not saved here (NPF_OPT_NO_SAVED_OBJECTS)");
    if (o->kind != NPF_FWD_SOCKS && (!o->target.host || !*o->target.host || !o->target.port))
        return op_fail(x, NPF_EINVAL, "the target needs a host and a port");
    if (o->kind == NPF_FWD_REMOTE && npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND)
        return op_fail(x, NPF_EINVAL, "an on-demand node cannot have a reverse forward");
    memset(&fn, 0, sizeof fn);
    fn.opt = o->kind == NPF_FWD_LOCAL ? 'L' : o->kind == NPF_FWD_SOCKS ? 'D' : 'R';
    fn.udp = o->proto == NPF_PROTO_UDP;
    if (o->kind != NPF_FWD_REMOTE)
        fn.bind = o->listen.host && *o->listen.host ? o->listen.host : "127.0.0.1";
    else if (!(fn.bind = remote_bind(o->listen.host)))
        return op_fail(x, NPF_EINVAL, "a remote forward listens on an address of the peer (an IP address)");
    fn.port = o->listen.port;
    if (o->kind != NPF_FWD_SOCKS) {
        fn.host = o->target.host;
        fn.hostport = o->target.port;
    }
    i = npf_peer_forward_add_parts(p, &fn, persist, 0, x->err, x->errcap);
    if (i < 0)
        return i == -1 ? NPF_EINVAL : i == -2 ? NPF_EBUSY : NPF_EFAIL;
    /* what is known at once: the port here taken, the address not ours */
    if (npf_peer_forward_state(p, i, &st) == 0 && st.state == NPF_FWD_FAILED
        && (st.why_code == NPF_FWD_WHY_PORT_IN_USE || st.why_code == NPF_FWD_WHY_BIND)) {
        op_fail(x, NPF_EFAIL, "%s", st.why);
        npf_peer_forward_del_at(p, i);
        return NPF_EFAIL;
    }
    npf_peer_forward_set_ctx(p, i, o->ctx);
    if (persist)
        rc = npf_ops_record_fwd(n, p, i, 1);
    *(uint32_t *)x->out = (uint32_t)npf_peer_forward_id(p, i);
    return rc;
}

int npf_forward_create(npf_t *n, uint32_t peer, const npf_forward_opt *o, uint32_t *fwd, char *err, size_t errcap)
{
    npf_forward_opt opt;
    uint32_t id = 0;
    op_arg x = {.id = peer, .in = &opt, .out = &id, .err = err, .errcap = errcap};
    int rc;
    err_clear(err, errcap);
    npf_forward_opt_init(&opt);
    if (take_in(&opt, sizeof opt, o, SIZE_TO(npf_forward_opt, ctx)) < 0)
        rc = op_fail(&x, NPF_EINVAL, "options not initialised (npf_forward_opt_init)");
    else
        rc = npf_api_op(n, fwd_create_run, &x);
    if (fwd)
        *fwd = id;
    return rc;
}

/* forward id: its peer and index there, NULL none */
static npf_peer *fwd_of(npf_t *n, uint32_t id, int *i, npf_fwd_state *st)
{
    npf_peer *p = npf_peers_fwd_find(n->peers, (int)id, i);
    return p && npf_peer_forward_state(p, *i, st) == 0 ? p : NULL;
}

static int fwd_remove_run(npf_t *n, void *arg)
{
    npf_fwd_state st;
    int i, rc = NPF_OK;
    npf_peer *p = fwd_of(n, *(uint32_t *)arg, &i, &st);
    if (!p)
        return NPF_ENOENT;
    if (npf_peer_tag(p) == NPF_PLATFORM || st.ext)
        return NPF_EREADONLY;
    if (st.perm && npf_peer_tag(p) == NPF_PERSIST)
        rc = npf_ops_record_fwd(n, p, i, 0);
    npf_peer_forward_del_at(p, i);
    return rc;
}

int npf_forward_remove(npf_t *n, uint32_t fwd)
{
    return npf_api_op(n, fwd_remove_run, &fwd);
}

static int fwd_list_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_peer *p;
    int k;
    if (x->id && !peer_of(n, x->id))
        return NPF_ENOENT;
    for (p = npf_peers_first(n->peers); p; p = npf_peer_next(p)) {
        if (x->id && npf_peer_id(p) != x->id)
            continue;
        for (k = 0; k < npf_peer_nfwd(p); k++) {
            uint32_t id = (uint32_t)npf_peer_forward_id(p, k);
            if (id)
                list_put(x, &id, sizeof id);
        }
    }
    return NPF_OK;
}

int npf_forward_list(npf_t *n, uint32_t peer, uint32_t *fwds, size_t cap, size_t *count)
{
    return op_list(n, fwd_list_run, peer, fwds, sizeof *fwds, cap, count);
}

static int fwd_get_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_fwd_state st;
    npf_forward_info fi;
    int i;
    npf_peer *p = fwd_of(n, x->id, &i, &st);
    if (!p)
        return NPF_ENOENT;
    memset(&fi, 0, sizeof fi);
    fi.peer = npf_peer_id(p);
    fi.kind = st.opt == 'L' ? NPF_FWD_LOCAL : st.opt == 'D' ? NPF_FWD_SOCKS : st.opt == 'R' ? NPF_FWD_REMOTE : 0;
    fi.proto = st.udp ? NPF_PROTO_UDP : NPF_PROTO_TCP;
    fi.flags = (st.perm ? NPF_PERSIST : 0) | (npf_peer_tag(p) == NPF_PLATFORM || st.ext ? NPF_PLATFORM : 0);
    fi.saved = (fi.flags & NPF_PERSIST) && !n->lc.unsaved;
    snprintf(fi.listen_host, sizeof fi.listen_host, "%s", st.bind);
    fi.listen_port = (uint16_t)st.lport;
    snprintf(fi.target_host, sizeof fi.target_host, "%s", st.host);
    fi.target_port = (uint16_t)st.hostport;
    fi.state = st.state;
    fi.why_code = st.why_code;
    snprintf(fi.why, sizeof fi.why, "%s", st.why);
    fi.conns = st.conns;
    fi.refused = st.refused;
    snprintf(fi.refused_why, sizeof fi.refused_why, "%s", st.refused_why);
    fi.ctx = st.ctx;
    put_out(x->out, x->size, &fi, sizeof fi);
    return NPF_OK;
}

int npf_forward_get_size(npf_t *n, uint32_t fwd, npf_forward_info *out, size_t size)
{
    return op_get(n, fwd_get_run, fwd, out, size);
}

static int fwd_setopt_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    int i;
    npf_peer *p = npf_peers_fwd_find(n->peers, (int)x->id, &i);
    if (!p)
        return NPF_ENOENT;
    npf_peer_forward_set_ctx(p, i, (void *)x->in);
    return NPF_OK;
}

int npf_forward_setopt(npf_t *n, uint32_t fwd, int opt, const void *val, size_t len)
{
    op_arg x = {.id = fwd, .in = val};
    if (opt != NPF_FWD_OPT_CTX || len != 0)
        return NPF_EINVAL;
    return npf_api_op(n, fwd_setopt_run, &x);
}

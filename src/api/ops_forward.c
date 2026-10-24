/* libnpf: the operations on forwards (npf_forward_create and the rest):
 * made on a peer, listed, read, removed, their context. */
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
#include "ops_internal.h"
/* ---- forwards ---- */

typedef struct fc_arg {
    uint32_t        peer;
    npf_forward_opt o;
    uint32_t       *id;
    char           *err;
    size_t          errcap;
} fc_arg;

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
    fc_arg *x = arg;
    npf_forward_opt *o = &x->o;
    npf_peer *p = peer_of(n, x->peer);
    npf_fwd_new fn;
    npf_fwd_state st;
    uint32_t f;
    int persist = (o->flags & NPF_PERSIST) != 0, i, rc = NPF_OK;
    if (!p)
        return NPF_ENOENT;
    f = npf_ops_flags(n, p);
    if (f & NPF_PLATFORM)
        return NPF_EREADONLY;
    if (o->flags & ~NPF_PERSIST || o->kind < NPF_FWD_LOCAL || o->kind > NPF_FWD_REMOTE
        || (o->proto != NPF_PROTO_TCP && o->proto != NPF_PROTO_UDP)
        || (o->proto == NPF_PROTO_UDP && o->kind == NPF_FWD_SOCKS)) {
        err_set(x->err, x->errcap, "%s", "bad kind, protocol or flags (UDP: LOCAL and REMOTE)");
        return NPF_EINVAL;
    }
    if (persist && !(f & NPF_PERSIST)) {
        err_set(x->err, x->errcap, "%s", "a saved forward needs a saved peer");
        return NPF_EINVAL;
    }
    if (persist && no_saved_objects(n)) {
        err_set(x->err, x->errcap, "%s", "forwards are not saved here (NPF_OPT_NO_SAVED_OBJECTS)");
        return NPF_EUNAVAIL;
    }
    if (o->kind != NPF_FWD_SOCKS && (!o->target.host || !*o->target.host || !o->target.port)) {
        err_set(x->err, x->errcap, "%s", "the target needs a host and a port");
        return NPF_EINVAL;
    }
    if (o->kind == NPF_FWD_REMOTE && npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND) {
        err_set(x->err, x->errcap, "%s", "an on-demand node cannot have a reverse forward");
        return NPF_EINVAL;
    }
    memset(&fn, 0, sizeof fn);
    fn.opt = o->kind == NPF_FWD_LOCAL ? 'L' : o->kind == NPF_FWD_SOCKS ? 'D' : 'R';
    fn.udp = o->proto == NPF_PROTO_UDP;
    if (o->kind == NPF_FWD_REMOTE) {
        if (!(fn.bind = remote_bind(o->listen.host))) {
            err_set(x->err, x->errcap, "%s", "a remote forward listens on an address of the peer (an IP address)");
            return NPF_EINVAL;
        }
    } else {
        fn.bind = o->listen.host && *o->listen.host ? o->listen.host : "127.0.0.1";
    }
    fn.port = o->listen.port;
    fn.host = o->kind == NPF_FWD_SOCKS ? NULL : o->target.host;
    fn.hostport = o->kind == NPF_FWD_SOCKS ? 0 : o->target.port;
    i = npf_peer_forward_add_parts(p, &fn, persist, 0, x->err, x->errcap);
    if (i < 0)
        return i == -1 ? NPF_EINVAL : i == -2 ? NPF_EBUSY : NPF_EFAIL;
    /* what is known at once: the port here taken, the address not ours */
    if (npf_peer_forward_state(p, i, &st) == 0 && st.state == NPF_FWD_FAILED
        && (st.why_code == NPF_FWD_WHY_PORT_IN_USE || st.why_code == NPF_FWD_WHY_BIND)) {
        err_set(x->err, x->errcap, "%s", st.why);
        npf_peer_forward_del_at(p, i);
        return NPF_EFAIL;
    }
    npf_peer_forward_set_ctx(p, i, o->ctx);
    if (persist)
        rc = npf_ops_record_fwd(n, p, i, 1);
    *x->id = (uint32_t)npf_peer_forward_id(p, i);
    return rc;
}

int npf_forward_create(npf_t *n, uint32_t peer, const npf_forward_opt *o, uint32_t *fwd, char *err, size_t errcap)
{
    fc_arg x;
    uint32_t dummy;
    if (err && errcap)
        err[0] = 0;
    memset(&x, 0, sizeof x);
    x.peer = peer;
    x.id = fwd ? fwd : &dummy;
    *x.id = 0;
    npf_forward_opt_init(&x.o);
    if (copy_in(&x.o, sizeof x.o, o, offsetof(npf_forward_opt, ctx) + sizeof o->ctx) < 0) {
        err_set(err, errcap, "%s", "options not initialised (npf_forward_opt_init)");
        return NPF_EINVAL;
    }
    x.err = err;
    x.errcap = errcap;
    return npf_api_op(n, fwd_create_run, &x);
}

static int fwd_remove_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int i, rc = NPF_OK;
    npf_peer *p = n->peers ? npf_peers_fwd_find(n->peers, (int)x->id, &i) : NULL;
    npf_fwd_state st;
    uint32_t f;
    if (!p || npf_peer_forward_state(p, i, &st) < 0)
        return NPF_ENOENT;
    f = npf_ops_flags(n, p);
    if ((f & NPF_PLATFORM) || npf_peer_forward_ext(p, i))
        return NPF_EREADONLY;
    if (st.perm && (f & NPF_PERSIST))
        rc = npf_ops_record_fwd(n, p, i, 0);
    npf_peer_forward_del_at(p, i);
    return rc;
}

int npf_forward_remove(npf_t *n, uint32_t fwd)
{
    pid_arg x = {.id = fwd};
    return npf_api_op(n, fwd_remove_run, &x);
}

static int fwd_list_run(npf_t *n, void *arg)
{
    list_arg *x = arg;
    npf_peer *p;
    int k;
    if (x->of && !peer_of(n, x->of))
        return NPF_ENOENT;
    for (p = n->peers ? npf_peers_first(n->peers) : NULL; p; p = npf_peer_next(p)) {
        if (x->of && npf_peer_id(p) != x->of)
            continue;
        for (k = 0; k < npf_peer_nfwd(p); k++)
            if (npf_peer_forward_id(p, k))
                list_put(x, (uint32_t)npf_peer_forward_id(p, k));
    }
    return list_rc(*x->count, x->cap);
}

int npf_forward_list(npf_t *n, uint32_t peer, uint32_t *fwds, size_t cap, size_t *count)
{
    list_arg x = {.of = peer, .ids = fwds, .cap = cap, .count = count};
    if (!count || (cap && !fwds))
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, fwd_list_run, &x);
}

static int fwd_get_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int i;
    npf_peer *p = n->peers ? npf_peers_fwd_find(n->peers, (int)x->id, &i) : NULL;
    npf_fwd_state st;
    npf_forward_info fi;
    uint32_t f;
    if (!p || npf_peer_forward_state(p, i, &st) < 0)
        return NPF_ENOENT;
    f = npf_ops_flags(n, p);
    memset(&fi, 0, sizeof fi);
    fi.size = sizeof fi;
    fi.peer = npf_peer_id(p);
    fi.kind = st.opt == 'L' ? NPF_FWD_LOCAL : st.opt == 'D' ? NPF_FWD_SOCKS : st.opt == 'R' ? NPF_FWD_REMOTE : 0;
    fi.proto = st.udp ? NPF_PROTO_UDP : NPF_PROTO_TCP;
    fi.flags = (st.perm ? NPF_PERSIST : 0) | (f & NPF_PLATFORM || st.ext ? NPF_PLATFORM : 0);
    fi.saved = (fi.flags & NPF_PERSIST) && !n->lc.unsaved;
    snprintf(fi.listen_host, sizeof fi.listen_host, "%s", st.bind);
    fi.listen_port = (uint16_t)(st.lport ? st.lport : 0);
    snprintf(fi.target_host, sizeof fi.target_host, "%s", st.host);
    fi.target_port = (uint16_t)st.hostport;
    fi.state = st.state;
    fi.why_code = st.why_code;
    snprintf(fi.why, sizeof fi.why, "%s", st.why);
    fi.conns = st.conns;
    fi.refused = st.refused;
    snprintf(fi.refused_why, sizeof fi.refused_why, "%s", st.refused_why);
    fi.ctx = st.ctx;
    return copy_out(x->out, &fi, sizeof fi) < 0 ? NPF_EINVAL : NPF_OK;
}

int npf_forward_get(npf_t *n, uint32_t fwd, npf_forward_info *out)
{
    pid_arg x = {.id = fwd, .out = out};
    if (!out)
        return NPF_EINVAL;
    return npf_api_op(n, fwd_get_run, &x);
}

static int fwd_setopt_run(npf_t *n, void *arg)
{
    so_arg *x = arg;
    int i;
    npf_peer *p = n->peers ? npf_peers_fwd_find(n->peers, (int)x->id, &i) : NULL;
    if (!p)
        return NPF_ENOENT;
    npf_peer_forward_set_ctx(p, i, x->ctx);
    return NPF_OK;
}

int npf_forward_setopt(npf_t *n, uint32_t fwd, int opt, const void *val, size_t len)
{
    so_arg x;
    if (opt != NPF_FWD_OPT_CTX || len != 0)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.id = fwd;
    x.opt = opt;
    x.ctx = (void *)val;
    return npf_api_op(n, fwd_setopt_run, &x);
}

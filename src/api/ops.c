/* libnpf: the operations of npf.h's objects (peers, forwards, resources, a
 * device's pairing, this node's state), each a public function that runs on
 * the instance's thread (npf_api_op). The command line (cmd_peers.c,
 * publish.c, nodes.c) parses its words and goes through the same layer
 * below it: the peers' structured primitives (npf/peers.h) and the records
 * in local.json (npf_ops_record). The library has no command syntax for
 * peers and forwards: the application has its own over these. What a peer
 * may do depends on where it comes from: the application's (made, or
 * brought back from local.json) or the platform's (NPF_PLATFORM). */
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

/* the application's structure into ours: what both know (size first) */
static int copy_in(void *dst, size_t dsize, const void *src, size_t min)
{
    size_t size;
    if (!src)
        return -1;
    memcpy(&size, src, sizeof size);
    if (size < min)
        return -1;
    memcpy(dst, src, size < dsize ? size : dsize);
    memcpy(dst, &dsize, sizeof dsize);
    return 0;
}

/* ours into the application's (its size kept, the rest of ours left out) */
static int copy_out(void *dst, const void *src, size_t ssize)
{
    size_t size;
    if (!dst)
        return -1;
    memcpy(&size, dst, sizeof size);
    if (size < sizeof size)
        return -1;
    memcpy(dst, src, size < ssize ? size : ssize);
    if (size > ssize)
        memset((char *)dst + ssize, 0, size - ssize);
    memcpy(dst, &size, sizeof size);
    return 0;
}

/* a list of structures with the caller's element size: element i at i * elem */
static void put_elem(void *out, size_t elem, size_t i, const void *src, size_t ssize)
{
    char *d = (char *)out + i * elem;
    memset(d, 0, elem);
    memcpy(d, src, elem < ssize ? elem : ssize);
    memcpy(d, &elem, sizeof elem);
}

static void err_set(char *err, size_t errcap, const char *fmt, const char *s)
{
    if (err && errcap)
        snprintf(err, errcap, fmt, s ? s : "");
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

static int no_saved_objects(const npf_t *n)
{
    return (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS) != 0;
}

static int saved_rc(npf_t *n)
{
    return npf_local_save(&n->lc) < 0 ? NPF_ESAVE : NPF_OK;
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

/* the direct key of a peer made from parts, for its record */
static void record_psk(npf_t *n, npf_peer *p, const uint8_t psk[32])
{
    npf_ldev *d = npf_local_dev(&n->lc, npf_peer_name(p), 0);
    if (d && !no_saved_objects(n) && psk) {
        d->psk[npf_b64url_encode(psk, 32, d->psk)] = 0;
        d->psk_file[0] = 0;
    }
}

/* ---- peers ---- */

typedef struct pc_arg {
    npf_peer_opt o;
    uint32_t    *id;
    char        *err;
    size_t       errcap;
} pc_arg;

static int name_ok(npf_t *n, npf_peer *self, const char *name, const char *target, char *err, size_t errcap)
{
    npf_ldev *other;
    npf_peer *q;
    if (!*name)
        return NPF_OK;
    if (!npf_name_valid(name)) {
        err_set(err, errcap, "%s: a name is 1 to 32 letters, digits, '.', '_', '-', not only digits", name);
        return NPF_EINVAL;
    }
    if ((other = npf_local_by_name(&n->lc, name)) && strcmp(other->target, target) != 0) {
        err_set(err, errcap, "the name %s is another peer's", name);
        return NPF_EEXIST;
    }
    for (q = npf_peers_first(n->peers); q; q = npf_peer_next(q))
        if (q != self && strcmp(npf_peer_label(q), name) == 0) {
            err_set(err, errcap, "the name %s is another peer's", name);
            return NPF_EEXIST;
        }
    return NPF_OK;
}

/* the names of p: in local.json (unless the application keeps its objects), and of this run */
static int names_put(npf_t *n, npf_peer *p, const char *name, const char *nick)
{
    npf_ldev *d;
    int rc = NPF_OK;
    if (name)
        npf_peer_set_label(p, name);
    if (nick)
        npf_peer_set_nick_here(p, nick);
    if (no_saved_objects(n))
        return NPF_OK;
    if (!(d = npf_local_dev(&n->lc, npf_peer_name(p), 1)))
        return NPF_EBUSY;
    if (name)
        snprintf(d->name, sizeof d->name, "%s", name);
    if (nick) {
        snprintf(d->nick, sizeof d->nick, "%s", nick);
        npf_peer_set_nick_here(p, NULL);
    }
    rc = saved_rc(n);
    if (nick)
        npf_mods_nick_set(n, npf_peer_name(p), nick);     /* the platform's alias too (a module) */
    return rc;
}

static int peer_create_run(npf_t *n, void *arg)
{
    pc_arg *x = arg;
    npf_peer_opt *o = &x->o;
    npf_peer_new pn;
    npf_peer *p;
    char target[320];
    int code, rc = NPF_OK, persist = (o->flags & NPF_PERSIST) != 0;
#ifdef NPF_NO_PEERS
    err_set(x->err, x->errcap, "%s", "sessions to other nodes are not in this build (NPF_PEERS=OFF)");
    return NPF_EUNAVAIL;
#endif
    if (!n->peers || (n->role == NPF_ROLE_DIRECT && o->target == NPF_TARGET_NUMBER)) {
        err_set(x->err, x->errcap, "%s", n->peers ? "no platform here (NPF_ROLE_DIRECT)" : "no peers in this build");
        return NPF_EUNAVAIL;
    }
    if ((o->target != NPF_TARGET_NUMBER && o->target != NPF_TARGET_DIRECT) || (o->flags & ~NPF_PERSIST)
        || o->connect < NPF_CONNECT_KEEP || o->connect > NPF_CONNECT_ON_DEMAND || o->idle_ms < 0) {
        err_set(x->err, x->errcap, "%s", "bad target, connect or flags");
        return NPF_EINVAL;
    }
    if (o->connect == NPF_CONNECT_ONCE && persist) {
        err_set(x->err, x->errcap, "%s", "a one-off peer is not saved (NPF_CONNECT_ONCE with NPF_PERSIST)");
        return NPF_EINVAL;
    }
    if (o->connect == NPF_CONNECT_ON_DEMAND && !persist) {
        err_set(x->err, x->errcap, "%s", "on demand is for saved peers (NPF_CONNECT_ON_DEMAND needs NPF_PERSIST)");
        return NPF_EINVAL;
    }
    if (persist && no_saved_objects(n)) {
        err_set(x->err, x->errcap, "%s", "peers are not saved here (NPF_OPT_NO_SAVED_OBJECTS)");
        return NPF_EUNAVAIL;
    }
    if (o->target == NPF_TARGET_NUMBER) {
        char num[24];
        snprintf(num, sizeof num, "%llu", (unsigned long long)o->number);
        if (!npf_number_parse(num)) {
            err_set(x->err, x->errcap, "%s: not a number (9 digits with a check digit)", num);
            return NPF_EINVAL;
        }
    } else if (!o->host || !*o->host || !o->port || !o->psk) {
        err_set(x->err, x->errcap, "%s", "a direct peer needs a host, a port and its key");
        return NPF_EINVAL;
    }
    if ((o->password && (strlen(o->password) > NPF_PASSWORD_MAX || !*o->password))
        || (o->name && strlen(o->name) > NPF_NAME_MAX) || (o->nick && !npf_nick_valid(o->nick))) {
        err_set(x->err, x->errcap, "%s", "the password, name or nick is too long or not valid");
        return NPF_EINVAL;
    }
    if (npf_peer_target_name(o->target == NPF_TARGET_NUMBER ? o->number : 0, o->host, o->port, target,
                             sizeof target) < 0) {
        err_set(x->err, x->errcap, "%s", "bad target");
        return NPF_EINVAL;
    }
    if ((p = npf_peers_find(n->peers, target))) {
        *x->id = npf_peer_id(p);
        err_set(x->err, x->errcap, "%s is a peer already", target);
        return NPF_EEXIST;
    }
    if (o->name && (rc = name_ok(n, NULL, o->name, target, x->err, x->errcap)) != NPF_OK)
        return rc;
    if (persist && !npf_local_dev(&n->lc, target, 0) && n->lc.ndev >= NPF_PEERS_SAVED_MAX) {
        err_set(x->err, x->errcap, "%s", "local.json holds as many peers as it may");
        return NPF_EBUSY;
    }
    memset(&pn, 0, sizeof pn);
    pn.number = o->target == NPF_TARGET_NUMBER ? o->number : 0;
    pn.host = o->target == NPF_TARGET_DIRECT ? o->host : NULL;
    pn.port = o->port;
    pn.psk = o->target == NPF_TARGET_DIRECT ? o->psk : NULL;
    pn.password = o->password;
    pn.connect = o->connect;
    pn.idle_ms = o->idle_ms;
    if (!(p = npf_peers_create(n->peers, &pn, x->err, x->errcap, &code)))
        return code == 1 ? NPF_EINVAL : code == 2 ? NPF_EEXIST : NPF_EFAIL;
    npf_peer_set_tag(p, persist ? PEER_SAVED : PEER_TEMP);
    npf_peer_ctx_put(p, o->ctx);
    if (o->name || o->nick)
        rc = names_put(n, p, o->name, o->nick);
    if (persist) {
        int r = npf_ops_record(n, p, 1, NULL);
        if (o->target == NPF_TARGET_DIRECT) {
            record_psk(n, p, o->psk);
            r = saved_rc(n);
        }
        if (r != NPF_OK)
            rc = r;
    }
    *x->id = npf_peer_id(p);
    npf_log("peer %s added%s", npf_peer_shown(p), persist ? " and saved" : "");
    npf_start_peers(n);
    return rc == NPF_EBUSY ? NPF_ESAVE : rc;
}

int npf_peer_create(npf_t *n, const npf_peer_opt *o, uint32_t *peer, char *err, size_t errcap)
{
    pc_arg x;
    uint32_t dummy;
    if (err && errcap)
        err[0] = 0;
    memset(&x, 0, sizeof x);
    x.id = peer ? peer : &dummy;
    *x.id = 0;
    npf_peer_opt_init(&x.o);
    if (copy_in(&x.o, sizeof x.o, o, offsetof(npf_peer_opt, ctx) + sizeof o->ctx) < 0) {
        err_set(err, errcap, "%s", "options not initialised (npf_peer_opt_init)");
        return NPF_EINVAL;
    }
    x.err = err;
    x.errcap = errcap;
    return npf_api_op(n, peer_create_run, &x);
}

typedef struct pid_arg {
    uint32_t    id;
    int         flags;
    const char *a, *b;
    void       *ctx;
    void       *out;
    char       *err;
    size_t      errcap;
} pid_arg;

static npf_peer *peer_of(npf_t *n, uint32_t id)
{
    return n->peers ? npf_peers_by_id(n->peers, id) : NULL;
}

static int peer_remove_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    uint32_t f;
    int rc = NPF_OK, pm;
    if (!p)
        return NPF_ENOENT;
    f = npf_ops_flags(n, p);
    if (f & NPF_PLATFORM)
        return NPF_EREADONLY;               /* the platform's mappings: removed there */
    pm = npf_mods_peer_removing(n, p);      /* its platform mappings: back after (a module's) */
    if (f & NPF_PERSIST)
        rc = npf_ops_record(n, p, 0, NULL);
    npf_log("peer %s removed", npf_peer_shown(p));
    npf_peers_remove(n->peers, p);
    if (pm)
        npf_mods_peer_removed(n);
    return rc;
}

int npf_peer_remove_id(npf_t *n, uint32_t peer)
{
    pid_arg x = {peer, 0, NULL, NULL, NULL, NULL, NULL, 0};
    return npf_api_op(n, peer_remove_run, &x);
}

static int peer_find_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    npf_peer *p = n->peers ? npf_peers_find(n->peers, x->a) : NULL;
    if (!p)
        return NPF_ENOENT;
    *(uint32_t *)x->out = npf_peer_id(p);
    return NPF_OK;
}

int npf_peer_find(npf_t *n, const char *target_or_name, uint32_t *peer)
{
    pid_arg x = {0, 0, target_or_name, NULL, NULL, peer, NULL, 0};
    if (!target_or_name || !peer)
        return NPF_EINVAL;
    *peer = 0;
    return npf_api_op(n, peer_find_run, &x);
}

typedef struct list_arg {
    uint32_t  of;
    uint32_t *ids;
    size_t    cap, *count;
} list_arg;

static void list_put(list_arg *x, uint32_t id)
{
    if (*x->count < x->cap)
        x->ids[*x->count] = id;
    (*x->count)++;
}

static int peer_list_run(npf_t *n, void *arg)
{
    list_arg *x = arg;
    npf_peer *p;
    for (p = n->peers ? npf_peers_first(n->peers) : NULL; p; p = npf_peer_next(p))
        list_put(x, npf_peer_id(p));
    return *x->count > x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_peer_list(npf_t *n, uint32_t *peers, size_t cap, size_t *count)
{
    list_arg x = {0, peers, cap, count};
    if (!count || (cap && !peers))
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, peer_list_run, &x);
}

static int peer_get_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    npf_peer_info i;
    npf_call *c;
    const char *h, *nick;
    uint16_t port;
    int k;
    if (!p)
        return NPF_ENOENT;
    memset(&i, 0, sizeof i);
    i.size = sizeof i;
    if (npf_peer_direct_target(p, &h, &port) == 0) {
        i.target = NPF_TARGET_DIRECT;
        snprintf(i.host, sizeof i.host, "%s", h);
        i.port = port;
    } else {
        i.target = NPF_TARGET_NUMBER;
        i.number = npf_peer_number(p);
    }
    snprintf(i.name, sizeof i.name, "%s", npf_peer_label(p));
    nick = npf_peer_nick(p);
    snprintf(i.nick, sizeof i.nick, "%s", nick ? nick : "");
    i.connect = npf_peer_connect_mode(p);
    i.flags = (int)npf_ops_flags(n, p);
    i.saved = (i.flags & NPF_PERSIST) && !n->lc.unsaved;
    i.state = npf_peer_state(p, &i.needs, &i.retry_in_ms);
    if (npf_peer_last_why(p)[0] && i.state != NPF_PEER_CONNECTED && strcmp(npf_peer_last_why(p), "starting") != 0)
        i.end_reason = npf_end_code(npf_peer_last_why(p), strcmp(npf_peer_last_why(p), "idle") == 0);
    snprintf(i.why, sizeof i.why, "%s", i.state == NPF_PEER_CONNECTED ? "" : npf_peer_last_why(p));
    c = npf_peer_call(p);
    i.session = c && npf_call_state(c) == NPF_CALL_ESTABLISHED ? npf_session_of(n, c) : 0;
    for (k = 0; k < npf_peer_nfwd(p); k++) {
        npf_fwd_state st;
        if (npf_peer_forward_state(p, k, &st) == 0)
            i.nforwards++;
    }
    i.ctx = npf_peer_ctx(p);
    return copy_out(x->out, &i, sizeof i) < 0 ? NPF_EINVAL : NPF_OK;
}

int npf_peer_get(npf_t *n, uint32_t peer, npf_peer_info *out)
{
    pid_arg x = {peer, 0, NULL, NULL, NULL, out, NULL, 0};
    if (!out)
        return NPF_EINVAL;
    return npf_api_op(n, peer_get_run, &x);
}

static int peer_connect_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    if (!p)
        return NPF_ENOENT;
    if (npf_ops_flags(n, p) & NPF_PLATFORM)
        return NPF_EREADONLY;               /* its module keeps its session */
    if (!n->started)
        return NPF_ESTATE;
    npf_peer_wake_now(p);
    return NPF_OK;
}

int npf_peer_connect_now(npf_t *n, uint32_t peer)
{
    pid_arg x = {peer, 0, NULL, NULL, NULL, NULL, NULL, 0};
    return npf_api_op(n, peer_connect_run, &x);
}

/* ---- npf_peer_setopt ---- */

typedef struct so_arg {
    uint32_t    id;
    int         opt;
    int         iv;                 /* an int option's value */
    const char *sv;                 /* a string option's */
    void       *ctx;
} so_arg;

/* NPF_PEER_OPT_CONNECT: KEEP connects now, ON_DEMAND needs NPF_PERSIST and no
 * remote forward, ONCE ends with the current session (not for a persisted peer) */
static int opt_connect(npf_t *n, npf_peer *p, uint32_t f, int mode)
{
    npf_fwd_state st;
    int k;
    if ((mode != NPF_CONNECT_KEEP && mode != NPF_CONNECT_ONCE && mode != NPF_CONNECT_ON_DEMAND)
        || (mode == NPF_CONNECT_ONCE && (f & NPF_PERSIST)))
        return NPF_EINVAL;
    if (mode == NPF_CONNECT_ON_DEMAND) {
        if (!(f & NPF_PERSIST))
            return NPF_EINVAL;              /* on demand is for saved peers */
        for (k = 0; k < npf_peer_nfwd(p); k++)
            if (npf_peer_forward_state(p, k, &st) == 0 && st.opt == 'R')
                return NPF_EINVAL;          /* the other side may use a -R at any time */
    }
    if (mode == npf_peer_connect_mode(p))
        return NPF_OK;
    npf_peer_connect_put(p, mode, npf_peer_idle_asked(p), n->started);
    return (f & NPF_PERSIST) ? npf_ops_record(n, p, 1, NULL) : NPF_OK;
}

/* NPF_PEER_OPT_PERSIST: on, saved now with its forwards; off, not brought
 * back at the next start (its pinned key, names and the rest stay) */
static int opt_persist(npf_t *n, npf_peer *p, uint32_t f, int on)
{
    int k;
    if (on != 0 && on != 1)
        return NPF_EINVAL;
    if (on && npf_peer_connect_mode(p) == NPF_CONNECT_ONCE)
        return NPF_EINVAL;
    if (!on && npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND)
        return NPF_EINVAL;                  /* on demand is for saved peers */
    if (on && no_saved_objects(n))
        return NPF_EUNAVAIL;
    if (!on && no_saved_objects(n))
        return NPF_OK;
    if (on == !!(f & NPF_PERSIST))
        return NPF_OK;
    npf_peer_set_tag(p, on ? PEER_SAVED : PEER_TEMP);
    for (k = 0; k < npf_peer_nfwd(p); k++)
        if (!npf_peer_forward_ext(p, k))
            npf_peer_forward_perm_set(p, k, on);
    return npf_ops_record(n, p, on, NULL);
}

static int peer_setopt_run(npf_t *n, void *arg)
{
    so_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    uint32_t f;
    int rc;
    if (!p)
        return NPF_ENOENT;
    f = npf_ops_flags(n, p);
    if ((f & NPF_PLATFORM)
        && (x->opt == NPF_PEER_OPT_CONNECT || x->opt == NPF_PEER_OPT_IDLE_MS || x->opt == NPF_PEER_OPT_PERSIST))
        return NPF_EREADONLY;               /* its module keeps it */
    switch (x->opt) {
    case NPF_PEER_OPT_CONNECT:
        return opt_connect(n, p, f, x->iv);
    case NPF_PEER_OPT_IDLE_MS:
        if (x->iv == npf_peer_idle_asked(p))
            return NPF_OK;
        npf_peer_idle_put(p, x->iv);
        return (f & NPF_PERSIST) ? npf_ops_record(n, p, 1, NULL) : NPF_OK;
    case NPF_PEER_OPT_PERSIST:
        return opt_persist(n, p, f, x->iv);
    case NPF_PEER_OPT_NAME:
        if (*x->sv && (rc = name_ok(n, p, x->sv, npf_peer_name(p), NULL, 0)) != NPF_OK)
            return rc;
        return names_put(n, p, x->sv, NULL);
    case NPF_PEER_OPT_NICK:
        if (*x->sv && !npf_nick_valid(x->sv))
            return NPF_EINVAL;
        return names_put(n, p, NULL, x->sv);
    case NPF_PEER_OPT_CTX:
        npf_peer_ctx_put(p, x->ctx);
        return NPF_OK;
    case NPF_PEER_OPT_PASSWORD:             /* not paired yet, or refused: tried at once, not kept */
        if ((f & NPF_PLATFORM) || npf_peer_number(p) == 0)
            return NPF_EINVAL;              /* let in through the account / a direct peer has its key */
        return npf_peer_password_try(p, x->sv) < 0 ? NPF_EINVAL : NPF_OK;
    }
    return NPF_EINVAL;
}

/* the value as the option takes it: an int (len sizeof(int)), a string
 * (NUL-terminated, len 0, at most max bytes), or the pointer itself (CTX) */
static int opt_value(int opt, const void *val, size_t len, so_arg *x)
{
    size_t max;
    switch (opt) {
    case NPF_PEER_OPT_CONNECT:
    case NPF_PEER_OPT_IDLE_MS:
    case NPF_PEER_OPT_PERSIST:
        if (!val || len != sizeof(int))
            return -1;
        memcpy(&x->iv, val, sizeof(int));
        return opt == NPF_PEER_OPT_IDLE_MS && (x->iv < 0 || x->iv > 86400000) ? -1 : 0;
    case NPF_PEER_OPT_NAME:
    case NPF_PEER_OPT_NICK:
    case NPF_PEER_OPT_PASSWORD:
        max = opt == NPF_PEER_OPT_NAME ? NPF_NAME_MAX : opt == NPF_PEER_OPT_NICK ? NPF_NICK_MAX : NPF_PASSWORD_MAX;
        if (!val || len != 0 || strlen(val) > max || (opt == NPF_PEER_OPT_PASSWORD && !*(const char *)val))
            return -1;
        x->sv = val;
        return 0;
    case NPF_PEER_OPT_CTX:
        if (len != 0)
            return -1;
        x->ctx = (void *)val;
        return 0;
    }
    return -1;
}

int npf_peer_setopt(npf_t *n, uint32_t peer, int opt, const void *val, size_t len)
{
    so_arg x;
    memset(&x, 0, sizeof x);
    x.id = peer;
    x.opt = opt;
    if (opt_value(opt, val, len, &x) < 0)
        return NPF_EINVAL;
    return npf_api_op(n, peer_setopt_run, &x);
}

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
    pid_arg x = {fwd, 0, NULL, NULL, NULL, NULL, NULL, 0};
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
    return *x->count > x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_forward_list(npf_t *n, uint32_t peer, uint32_t *fwds, size_t cap, size_t *count)
{
    list_arg x = {peer, fwds, cap, count};
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
    pid_arg x = {fwd, 0, NULL, NULL, NULL, out, NULL, 0};
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

/* ---- resources ---- */

typedef struct rp_arg {
    npf_resource r;
    char        *err;
    size_t       errcap;
} rp_arg;

static const char *res_type_name(int t)
{
    switch (t) {
    case NPF_RES_TCP: return "tcp";
    case NPF_RES_UDP: return "udp";
    case NPF_RES_NET: return "net";
    case NPF_RES_SOCKS: return "socks";
    case NPF_RES_REVERSE: return "reverse";
    default: return NULL;
    }
}

static int res_type_code(const char *t)
{
    static const char *const names[] = {"", "tcp", "udp", "net", "socks", "reverse"};
    int i;
    for (i = 1; i < 6; i++)
        if (strcmp(names[i], t) == 0)
            return i;
    return 0;
}

static int res_put_run(npf_t *n, void *arg)
{
    rp_arg *x = arg;
    npf_resource *u = &x->r;
    npf_res r;
    const char *type = res_type_name(u->type);
    /* udp: one service (service.host), or "*" / networks as a rule */
    int service = u->type == NPF_RES_TCP || (u->type == NPF_RES_UDP && !(u->rule && *u->rule && !u->service.host)), l;
    memset(&r, 0, sizeof r);
    if (!type || !u->name || !*u->name || strlen(u->name) >= sizeof r.name || (u->flags & ~NPF_PERSIST)
        || (u->svc && strlen(u->svc) >= sizeof r.svc) || (u->desc && strlen(u->desc) >= sizeof r.desc)
        || (u->path && strlen(u->path) >= sizeof r.path)) {
        err_set(x->err, x->errcap, "%s", "bad type or flags, or a name, service, path or description too long");
        return NPF_EINVAL;
    }
    snprintf(r.type, sizeof r.type, "%s", type);
    snprintf(r.name, sizeof r.name, "%s", u->name);
    if (u->svc)
        snprintf(r.svc, sizeof r.svc, "%s", u->svc);
    if (u->desc)
        snprintf(r.desc, sizeof r.desc, "%s", u->desc);
    if (service) {
        const char *h = u->service.host;
        if (!h || !*h || !u->service.port) {
            err_set(x->err, x->errcap, "%s", "a service needs an address and a port");
            return NPF_EINVAL;
        }
        l = strchr(h, ':') ? snprintf(r.target, sizeof r.target, "[%s]:%u", h, (unsigned)u->service.port)
                           : snprintf(r.target, sizeof r.target, "%s:%u", h, (unsigned)u->service.port);
        if (l < 0 || (size_t)l >= sizeof r.target) {
            err_set(x->err, x->errcap, "%s", "the service's address is too long");
            return NPF_EINVAL;
        }
        if (u->path && *u->path && strcmp(u->path, "/") != 0)
            snprintf(r.path, sizeof r.path, "%s", u->path);
    } else {
        if (!u->rule || !*u->rule || strlen(u->rule) > 63) {
            err_set(x->err, x->errcap, "%s", "a rule of 1 to 63 bytes is needed");
            return NPF_EINVAL;
        }
        snprintf(r.target, sizeof r.target, "%s", u->rule);
    }
    if (npf_res_check(&r, x->err, x->errcap) < 0)
        return NPF_EINVAL;
    r.persist = (u->flags & NPF_PERSIST) != 0;
    return npf_pub_put(n, &r, x->err, x->errcap);
}

int npf_resource_put(npf_t *n, const npf_resource *r, char *err, size_t errcap)
{
    rp_arg x;
    if (err && errcap)
        err[0] = 0;
    memset(&x, 0, sizeof x);
    npf_resource_init(&x.r);
    if (copy_in(&x.r, sizeof x.r, r, offsetof(npf_resource, flags) + sizeof r->flags) < 0) {
        err_set(err, errcap, "%s", "not initialised (npf_resource_init)");
        return NPF_EINVAL;
    }
    x.err = err;
    x.errcap = errcap;
    return npf_api_op(n, res_put_run, &x);
}

static int res_remove_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    char err[200];
    return npf_pub_remove(n, x->a, err, sizeof err);
}

int npf_resource_remove(npf_t *n, const char *name)
{
    pid_arg x = {0, 0, name, NULL, NULL, NULL, NULL, 0};
    if (!name || !*name)
        return NPF_EINVAL;
    return npf_api_op(n, res_remove_run, &x);
}

typedef struct rl_arg {
    uint32_t           peer;
    npf_resource_info *out;
    size_t             elem, cap, *count;
} rl_arg;

static void res_info(const npf_res *r, int saved, npf_resource_info *i)
{
    memset(i, 0, sizeof *i);
    i->size = sizeof *i;
    i->type = res_type_code(r->type);
    i->flags = (r->persist ? NPF_PERSIST : 0) | (r->fixed ? NPF_FIXED : 0);
    i->saved = r->persist && saved;
    snprintf(i->name, sizeof i->name, "%s", r->name);
    snprintf(i->svc, sizeof i->svc, "%s", r->svc);
    if (npf_res_is_service(r)) {
        const char *colon = strrchr(r->target, ':');
        if (colon) {
            if (r->target[0] == '[')
                snprintf(i->host, sizeof i->host, "%.*s", (int)(colon - r->target - 2), r->target + 1);
            else
                snprintf(i->host, sizeof i->host, "%.*s", (int)(colon - r->target), r->target);
            i->port = (uint16_t)atoi(colon + 1);
        }
    } else {
        snprintf(i->rule, sizeof i->rule, "%s", r->target);
    }
    snprintf(i->path, sizeof i->path, "%s", r->path);
    snprintf(i->desc, sizeof i->desc, "%s", r->desc);
}

static int res_list_run(npf_t *n, void *arg)
{
    rl_arg *x = arg;
    npf_resource_info i;
    int k;
    if (!x->peer) {
        for (k = 0; k < n->nres; k++) {
            if (*x->count < x->cap) {
                res_info(&n->res[k], !n->lc.unsaved, &i);
                put_elem(x->out, x->elem, *x->count, &i, sizeof i);
            }
            (*x->count)++;
        }
    } else {
        npf_peer *p = peer_of(n, x->peer);
        const char *json;
        npf_jtok *tok;
        npf_res *r;
        npf_json j;
        char e[160];
        int m = -1;
        if (!p)
            return NPF_ENOENT;
        if (!(json = npf_peer_resources(p)))
            return NPF_OK;
        tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
        r = malloc(NPF_RES_MAX * sizeof *r);
        if (tok && r && npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) == 0)
            m = npf_res_parse(&j, 0, r, NPF_RES_MAX, e, sizeof e);
        for (k = 0; k < m; k++) {
            if (*x->count < x->cap) {
                r[k].persist = 0;
                res_info(&r[k], 0, &i);
                i.flags = 0;
                put_elem(x->out, x->elem, *x->count, &i, sizeof i);
            }
            (*x->count)++;
        }
        free(tok);
        free(r);
    }
    return *x->count > x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_resource_list_size(npf_t *n, uint32_t peer, npf_resource_info *out, size_t elem_size, size_t cap,
                           size_t *count)
{
    rl_arg x = {peer, out, elem_size, cap, count};
    if (!count || (cap && !out) || elem_size < offsetof(npf_resource_info, desc) + sizeof out->desc)
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, res_list_run, &x);
}

/* ---- a device's pairing ---- */

static int callee_rc(int r)
{
    return r == 0 ? NPF_OK : r == -2 ? NPF_ESAVE : NPF_EINVAL;
}

static int pw_get_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    if (strlen(n->callee->password) >= (size_t)x->flags)
        return NPF_ETOOBIG;
    snprintf(x->out, (size_t)x->flags, "%s", n->callee->password);
    return NPF_OK;
}

int npf_pairing_password_get(npf_t *n, char *out, size_t cap)
{
    pid_arg x = {0, (int)cap, NULL, NULL, NULL, out, NULL, 0};
    if (!out || !cap || cap > 1 << 20)
        return NPF_EINVAL;
    out[0] = 0;
    return npf_api_op(n, pw_get_run, &x);
}

static int pw_set_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int r;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    r = npf_callee_password_set(n->callee, x->a);
    if (r == -1)
        err_set(x->err, x->errcap, "%s", "the password needs 8 to 127 bytes");
    else if (r == -2)
        err_set(x->err, x->errcap, "%s", "in effect, but the device's state could not be written");
    return callee_rc(r);
}

int npf_pairing_password_set(npf_t *n, const char *password, char *err, size_t errcap)
{
    pid_arg x = {0, 0, password, NULL, NULL, NULL, err, errcap};
    if (err && errcap)
        err[0] = 0;
    if (!password)
        return NPF_EINVAL;
    return npf_api_op(n, pw_set_run, &x);
}

typedef struct pl_arg {
    npf_pairing *out;
    size_t       elem, cap, *count;
} pl_arg;

static int pairing_list_run(npf_t *n, void *arg)
{
    pl_arg *x = arg;
    npf_pairing pr;
    int k;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    for (k = 0; k < n->callee->npaired; k++) {
        if (*x->count < x->cap) {
            memset(&pr, 0, sizeof pr);
            pr.size = sizeof pr;
            memcpy(pr.key, n->callee->paired[k].pub, 32);
            pr.since = n->callee->paired[k].added;
            put_elem(x->out, x->elem, *x->count, &pr, sizeof pr);
        }
        (*x->count)++;
    }
    return *x->count > x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_pairing_list_size(npf_t *n, npf_pairing *out, size_t elem_size, size_t cap, size_t *count)
{
    pl_arg x = {out, elem_size, cap, count};
    if (!count || (cap && !out) || elem_size < sizeof(npf_pairing))
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, pairing_list_run, &x);
}

static int unpair_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int r;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    r = npf_callee_unpair_key(n->callee, x->out);
    return r == -1 ? NPF_ENOENT : callee_rc(r);
}

int npf_pairing_remove(npf_t *n, const uint8_t key[32])
{
    pid_arg x = {0, 0, NULL, NULL, NULL, (void *)key, NULL, 0};
    return npf_api_op(n, unpair_run, &x);
}

static int owner_reset_run(npf_t *n, void *arg)
{
    (void)arg;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    return callee_rc(npf_callee_owner_reset(n->callee));
}

int npf_owner_reset(npf_t *n)
{
    return npf_api_op(n, owner_reset_run, NULL);
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
    pid_arg x = {session, 0, NULL, NULL, NULL, out, NULL, 0};
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
    return *x->count > x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_session_list(npf_t *n, uint32_t *sessions, size_t cap, size_t *count)
{
    list_arg x = {0, sessions, cap, count};
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

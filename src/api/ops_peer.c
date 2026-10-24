/* libnpf: the operations on peers (npf_peer_create and the rest of npf.h's
 * peer functions): made, found, listed, removed, their options. */
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
/* ---- peers ---- */

/* the direct key of a peer made from parts, for its record */
static void record_psk(npf_t *n, npf_peer *p, const uint8_t psk[32])
{
    npf_ldev *d = npf_local_dev(&n->lc, npf_peer_name(p), 0);
    if (d && !no_saved_objects(n) && psk) {
        d->psk[npf_b64url_encode(psk, 32, d->psk)] = 0;
        d->psk_file[0] = 0;
    }
}

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
    npf_start_peer(n, p);
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
    pid_arg x = {.id = peer};
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
    pid_arg x = {.a = target_or_name, .out = peer};
    if (!target_or_name || !peer)
        return NPF_EINVAL;
    *peer = 0;
    return npf_api_op(n, peer_find_run, &x);
}
static int peer_list_run(npf_t *n, void *arg)
{
    list_arg *x = arg;
    npf_peer *p;
    for (p = n->peers ? npf_peers_first(n->peers) : NULL; p; p = npf_peer_next(p))
        list_put(x, npf_peer_id(p));
    return list_rc(*x->count, x->cap);
}

int npf_peer_list(npf_t *n, uint32_t *peers, size_t cap, size_t *count)
{
    list_arg x = {.ids = peers, .cap = cap, .count = count};
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
    const char *nick;
    uint16_t port;
    int k;
    if (!p)
        return NPF_ENOENT;
    memset(&i, 0, sizeof i);
    i.size = sizeof i;
    if (npf_peer_direct_target(p, i.host, sizeof i.host, &port) == 0) {
        i.target = NPF_TARGET_DIRECT;
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
    pid_arg x = {.id = peer, .out = out};
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
    pid_arg x = {.id = peer};
    return npf_api_op(n, peer_connect_run, &x);
}
/* ---- npf_peer_setopt ---- */

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

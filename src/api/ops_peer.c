/* libnpf: the operations on peers (npf_peer_create and the rest of npf.h's
 * peer functions): made, found, listed, removed, their options. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"

/* name is free for target: a valid name, not another peer's here or in
 * local.json (x NULL: no reason wanted) */
static int name_ok(npf_t *n, npf_peer *self, const char *name, const char *target, op_arg *x)
{
    npf_ldev *other;
    npf_peer *q;
    if (!*name)
        return NPF_OK;
    if (!npf_name_valid(name))
        return op_fail(x, NPF_EINVAL, "%s: a name is 1 to 32 letters, digits, '.', '_', '-', not only digits", name);
    if ((other = npf_local_by_name(&n->lc, name)) && strcmp(other->target, target) != 0)
        return op_fail(x, NPF_EEXIST, "the name %s is another peer's", name);
    for (q = npf_peers_first(n->peers); q; q = npf_peer_next(q))
        if (q != self && strcmp(npf_peer_label(q), name) == 0)
            return op_fail(x, NPF_EEXIST, "the name %s is another peer's", name);
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
    if (!no_saved_objects(n)) {
        if (!(d = npf_local_dev(&n->lc, npf_peer_name(p), 1)))
            return NPF_EBUSY;
        if (name)
            snprintf(d->name, sizeof d->name, "%s", name);
        if (nick) {
            snprintf(d->nick, sizeof d->nick, "%s", nick);
            npf_peer_set_nick_here(p, NULL);
        }
        rc = saved_rc(n);
    }
    if (nick)
        npf_mods_nick_set(n, npf_peer_name(p), nick);     /* the platform's alias too (a module) */
    return rc;
}

static int peer_create_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    const npf_peer_opt *o = x->in;
    int persist = (o->flags & NPF_PERSIST) != 0, code, rc = NPF_OK;
    npf_peer_new pn;
    npf_peer *p;
    char target[320];
#ifdef NPF_NO_PEERS
    return op_fail(x, NPF_EUNAVAIL, "sessions to other nodes are not in this build (NPF_PEERS=OFF)");
#endif
    if (n->role == NPF_ROLE_DIRECT && o->target == NPF_TARGET_NUMBER)
        return op_fail(x, NPF_EUNAVAIL, "no platform here (NPF_ROLE_DIRECT)");
    if ((o->target != NPF_TARGET_NUMBER && o->target != NPF_TARGET_DIRECT) || (o->flags & ~NPF_PERSIST)
        || o->connect < NPF_CONNECT_KEEP || o->connect > NPF_CONNECT_ON_DEMAND || o->idle_ms < 0)
        return op_fail(x, NPF_EINVAL, "bad target, connect or flags");
    if (o->connect == NPF_CONNECT_ONCE && persist)
        return op_fail(x, NPF_EINVAL, "a one-off peer is not saved (NPF_CONNECT_ONCE with NPF_PERSIST)");
    if (o->connect == NPF_CONNECT_ON_DEMAND && !persist)
        return op_fail(x, NPF_EINVAL, "on demand is for saved peers (NPF_CONNECT_ON_DEMAND needs NPF_PERSIST)");
    if (persist && no_saved_objects(n))
        return op_fail(x, NPF_EUNAVAIL, "peers are not saved here (NPF_OPT_NO_SAVED_OBJECTS)");
    if (o->target == NPF_TARGET_NUMBER) {
        char num[24];
        snprintf(num, sizeof num, "%llu", (unsigned long long)o->number);
        if (!npf_number_parse(num))
            return op_fail(x, NPF_EINVAL, "%s: not a number (9 digits with a check digit)", num);
    } else if (!o->host || !*o->host || !o->port || !o->psk) {
        return op_fail(x, NPF_EINVAL, "a direct peer needs a host, a port and its key");
    }
    if ((o->password && (strlen(o->password) > NPF_PASSWORD_MAX || !*o->password))
        || (o->name && strlen(o->name) > NPF_NAME_MAX) || (o->nick && !npf_nick_valid(o->nick)))
        return op_fail(x, NPF_EINVAL, "the password, name or nick is too long or not valid");
    if (npf_peer_target_name(o->target == NPF_TARGET_NUMBER ? o->number : 0, o->host, o->port, target,
                             sizeof target) < 0)
        return op_fail(x, NPF_EINVAL, "bad target");
    if ((p = npf_peers_find(n->peers, target))) {
        *(uint32_t *)x->out = npf_peer_id(p);
        return op_fail(x, NPF_EEXIST, "%s is a peer already", target);
    }
    if (o->name && (rc = name_ok(n, NULL, o->name, target, x)) != NPF_OK)
        return rc;
    if (persist && !npf_local_dev(&n->lc, target, 0) && n->lc.ndev >= NPF_PEERS_SAVED_MAX)
        return op_fail(x, NPF_EBUSY, "local.json holds as many peers as it may");
    memset(&pn, 0, sizeof pn);
    if (o->target == NPF_TARGET_NUMBER) {
        pn.number = o->number;
    } else {
        pn.host = o->host;
        pn.psk = o->psk;
    }
    pn.port = o->port;
    pn.password = o->password;
    pn.connect = o->connect;
    pn.idle_ms = o->idle_ms;
    if (!(p = npf_peers_create(n->peers, &pn, x->err, x->errcap, &code)))
        return code == 1 ? NPF_EINVAL : code == 2 ? NPF_EEXIST : NPF_EFAIL;
    npf_peer_set_tag(p, persist ? NPF_PERSIST : 0);
    npf_peer_ctx_put(p, o->ctx);
    if (o->name || o->nick)
        rc = names_put(n, p, o->name, o->nick);
    if (persist) {
        int r = npf_ops_record(n, p, 1, NULL);
        npf_ldev *d = npf_local_dev(&n->lc, npf_peer_name(p), 0);
        if (d && pn.psk) {                  /* a direct peer: this key, not one an old record had */
            npf_b64url_encode(o->psk, 32, d->psk);
            d->psk_file[0] = 0;
            r = saved_rc(n);
        }
        if (r != NPF_OK)
            rc = r;
    }
    *(uint32_t *)x->out = npf_peer_id(p);
    npf_log("peer %s added%s", npf_peer_shown(p), persist ? " and saved" : "");
    if (n->started)
        npf_peer_start(p);                  /* else the run starts it */
    return rc == NPF_EBUSY ? NPF_ESAVE : rc;
}

int npf_peer_create(npf_t *n, const npf_peer_opt *o, uint32_t *peer, char *err, size_t errcap)
{
    npf_peer_opt opt;
    op_arg x = {.out = peer, .err = err, .errcap = errcap};
    npf_peer_opt_init(&opt);
    return op_take(n, peer_create_run, &x, &opt, sizeof opt, o, SIZE_TO(npf_peer_opt, ctx), "npf_peer_opt_init");
}

static int peer_remove_run(npf_t *n, void *arg)
{
    npf_peer *p = peer_of(n, *(uint32_t *)arg);
    int rc = NPF_OK, again;
    if (!p)
        return NPF_ENOENT;
    if (npf_peer_tag(p) == NPF_PLATFORM)
        return NPF_EREADONLY;               /* the platform's mappings: removed there */
    again = npf_mods_peer_removing(n, p);   /* its platform mappings: back after (a module's) */
    if (npf_peer_tag(p) == NPF_PERSIST)
        rc = npf_ops_record(n, p, 0, NULL);
    npf_log("peer %s removed", npf_peer_shown(p));
    npf_peers_remove(n->peers, p);
    if (again)
        npf_mods_peer_removed(n);
    return rc;
}

int npf_peer_remove(npf_t *n, uint32_t peer)
{
    return npf_api_op(n, peer_remove_run, &peer);
}

static int peer_find_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_peer *p = n->peers ? npf_peers_find(n->peers, x->in) : NULL;
    if (!p)
        return NPF_ENOENT;
    *(uint32_t *)x->out = npf_peer_id(p);
    return NPF_OK;
}

int npf_peer_find(npf_t *n, const char *target_or_name, uint32_t *peer)
{
    op_arg x = {.in = target_or_name, .out = peer};
    if (!target_or_name || !peer)
        return NPF_EINVAL;
    *peer = 0;
    return npf_api_op(n, peer_find_run, &x);
}

static int peer_list_run(npf_t *n, void *arg)
{
    npf_peer *p;
    for (p = n->peers ? npf_peers_first(n->peers) : NULL; p; p = npf_peer_next(p)) {
        uint32_t id = npf_peer_id(p);
        list_put(arg, &id, sizeof id);
    }
    return NPF_OK;
}

int npf_peer_list(npf_t *n, uint32_t *peers, size_t cap, size_t *count)
{
    return op_list(n, peer_list_run, 0, peers, sizeof *peers, cap, count);
}

/* why a session ended, as an NPF_END_* code */
static int end_code(const char *why)
{
    static const struct { const char *why; int code; } map[] = {
        {"transport_lost", NPF_END_LOST}, {"timeout", NPF_END_LOST},
        {"auth_failed", NPF_END_REFUSED}, {"unauthorized", NPF_END_REFUSED}, {"wrong_password", NPF_END_REFUSED},
        {"not_paired", NPF_END_REFUSED}, {"pairing_lost", NPF_END_REFUSED}, {"no_account", NPF_END_REFUSED},
        {"revoked", NPF_END_REFUSED}, {"forbidden", NPF_END_REFUSED}, {"busy", NPF_END_REFUSED},
        {"no_path", NPF_END_UNREACHABLE}, {"unreachable", NPF_END_UNREACHABLE}, {"offline", NPF_END_UNREACHABLE},
        {"quota", NPF_END_PLATFORM}, {"secure_plan", NPF_END_PLATFORM}, {"plan_limit", NPF_END_PLATFORM},
        {"idle", NPF_END_LOCAL},
    };
    size_t i;
    if (!*why || strcmp(why, "closed") == 0)
        return NPF_END_PEER;
    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i].why, why) == 0)
            return map[i].code;
    return NPF_END_OTHER;
}

static int peer_get_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    const char *why;
    npf_peer_info i;
    npf_call *c;
    int k;
    if (!p)
        return NPF_ENOENT;
    memset(&i, 0, sizeof i);
    if (npf_peer_direct_target(p, i.host, sizeof i.host, &i.port) == 0) {
        i.target = NPF_TARGET_DIRECT;
    } else {
        i.target = NPF_TARGET_NUMBER;
        i.number = npf_peer_number(p);
    }
    snprintf(i.name, sizeof i.name, "%s", npf_peer_label(p));
    snprintf(i.nick, sizeof i.nick, "%s", npf_peer_nick(p));
    i.connect = npf_peer_connect_mode(p);
    i.flags = npf_peer_tag(p);
    i.saved = i.flags == NPF_PERSIST && !n->lc.unsaved;
    i.state = npf_peer_state(p, &i.needs, &i.retry_in_ms);
    why = npf_peer_last_why(p);
    if (i.state != NPF_PEER_CONNECTED) {
        if (*why)
            i.end_reason = end_code(why);
        snprintf(i.why, sizeof i.why, "%s", why);
    }
    c = npf_peer_call(p);
    i.session = c && npf_call_state(c) == NPF_CALL_ESTABLISHED ? npf_session_of(n, c) : 0;
    for (k = 0; k < npf_peer_nfwd(p); k++) {
        npf_fwd_state st;
        if (npf_peer_forward_state(p, k, &st) == 0)
            i.nforwards++;
    }
    i.ctx = npf_peer_ctx(p);
    put_out(x->out, x->size, &i, sizeof i);
    return NPF_OK;
}

int npf_peer_get_size(npf_t *n, uint32_t peer, npf_peer_info *out, size_t size)
{
    return op_get(n, peer_get_run, peer, out, size);
}

static int peer_connect_run(npf_t *n, void *arg)
{
    npf_peer *p = peer_of(n, *(uint32_t *)arg);
    if (!p)
        return NPF_ENOENT;
    if (npf_peer_tag(p) == NPF_PLATFORM)
        return NPF_EREADONLY;               /* its module keeps its session */
    if (!n->started)
        return NPF_ESTATE;
    npf_peer_wake_now(p);
    return NPF_OK;
}

int npf_peer_connect_now(npf_t *n, uint32_t peer)
{
    return npf_api_op(n, peer_connect_run, &peer);
}

/* ---- npf_peer_setopt ---- */

/* an option and its value: an int, a string, or the context */
typedef struct so_arg {
    uint32_t    id;
    int         opt, iv;
    const char *sv;
    void       *ctx;
} so_arg;

/* NPF_PEER_OPT_CONNECT: KEEP connects now, ON_DEMAND needs NPF_PERSIST and no
 * remote forward, ONCE ends with the current session (not for a persisted peer) */
static int opt_connect(npf_t *n, npf_peer *p, int mode)
{
    int saved = npf_peer_tag(p) == NPF_PERSIST, k;
    npf_fwd_state st;
    if ((mode != NPF_CONNECT_KEEP && mode != NPF_CONNECT_ONCE && mode != NPF_CONNECT_ON_DEMAND)
        || (mode == NPF_CONNECT_ONCE && saved) || (mode == NPF_CONNECT_ON_DEMAND && !saved))
        return NPF_EINVAL;                  /* on demand is for saved peers */
    for (k = 0; mode == NPF_CONNECT_ON_DEMAND && k < npf_peer_nfwd(p); k++)
        if (npf_peer_forward_state(p, k, &st) == 0 && st.opt == 'R')
            return NPF_EINVAL;              /* the other side may use a -R at any time */
    if (mode == npf_peer_connect_mode(p))
        return NPF_OK;
    npf_peer_connect_put(p, mode, npf_peer_idle_asked(p), n->started);
    return saved ? npf_ops_record(n, p, 1, NULL) : NPF_OK;
}

/* NPF_PEER_OPT_PERSIST: on, saved now with its forwards; off, not brought
 * back at the next start (its pinned key, names and the rest stay) */
static int opt_persist(npf_t *n, npf_peer *p, int on)
{
    int k;
    if ((on != 0 && on != 1) || (on && npf_peer_connect_mode(p) == NPF_CONNECT_ONCE)
        || (!on && npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND))
        return NPF_EINVAL;                  /* on demand is for saved peers */
    if (no_saved_objects(n))
        return on ? NPF_EUNAVAIL : NPF_OK;
    if (on == (npf_peer_tag(p) == NPF_PERSIST))
        return NPF_OK;
    npf_peer_set_tag(p, on ? NPF_PERSIST : 0);
    for (k = 0; k < npf_peer_nfwd(p); k++)
        if (!npf_peer_forward_ext(p, k))
            npf_peer_forward_perm_set(p, k, on);
    return npf_ops_record(n, p, on, NULL);
}

static int peer_setopt_run(npf_t *n, void *arg)
{
    so_arg *x = arg;
    npf_peer *p = peer_of(n, x->id);
    int rc;
    if (!p)
        return NPF_ENOENT;
    if (npf_peer_tag(p) == NPF_PLATFORM
        && (x->opt == NPF_PEER_OPT_CONNECT || x->opt == NPF_PEER_OPT_IDLE_MS || x->opt == NPF_PEER_OPT_PERSIST))
        return NPF_EREADONLY;               /* its module keeps it */
    switch (x->opt) {
    case NPF_PEER_OPT_CONNECT:
        return opt_connect(n, p, x->iv);
    case NPF_PEER_OPT_IDLE_MS:
        if (x->iv == npf_peer_idle_asked(p))
            return NPF_OK;
        npf_peer_idle_put(p, x->iv);
        return npf_peer_tag(p) == NPF_PERSIST ? npf_ops_record(n, p, 1, NULL) : NPF_OK;
    case NPF_PEER_OPT_PERSIST:
        return opt_persist(n, p, x->iv);
    case NPF_PEER_OPT_NAME:
        if ((rc = name_ok(n, p, x->sv, npf_peer_name(p), NULL)) != NPF_OK)
            return rc;
        return names_put(n, p, x->sv, NULL);
    case NPF_PEER_OPT_NICK:
        if (*x->sv && !npf_nick_valid(x->sv))
            return NPF_EINVAL;
        return names_put(n, p, NULL, x->sv);
    case NPF_PEER_OPT_CTX:
        npf_peer_ctx_put(p, x->ctx);
        return NPF_OK;
    default:                                /* NPF_PEER_OPT_PASSWORD: tried at once, not kept */
        if (npf_peer_tag(p) == NPF_PLATFORM || npf_peer_number(p) == 0)
            return NPF_EINVAL;              /* let in through the account / a direct peer has its key */
        return npf_peer_password_try(p, x->sv) < 0 ? NPF_EINVAL : NPF_OK;
    }
}

/* the value as the option takes it: an int (len sizeof(int)), a string
 * (NUL-terminated, len 0, at most max bytes), or the pointer itself (CTX) */
static int opt_value(so_arg *x, const void *val, size_t len)
{
    size_t max;
    switch (x->opt) {
    case NPF_PEER_OPT_CONNECT:
    case NPF_PEER_OPT_IDLE_MS:
    case NPF_PEER_OPT_PERSIST:
        if (!val || len != sizeof(int))
            return -1;
        memcpy(&x->iv, val, sizeof(int));
        return x->opt == NPF_PEER_OPT_IDLE_MS && (x->iv < 0 || x->iv > 86400000) ? -1 : 0;
    case NPF_PEER_OPT_NAME:
    case NPF_PEER_OPT_NICK:
    case NPF_PEER_OPT_PASSWORD:
        max = x->opt == NPF_PEER_OPT_NAME ? NPF_NAME_MAX : x->opt == NPF_PEER_OPT_NICK ? NPF_NICK_MAX : NPF_PASSWORD_MAX;
        if (!val || len != 0 || strlen(val) > max || (x->opt == NPF_PEER_OPT_PASSWORD && !*(const char *)val))
            return -1;
        x->sv = val;
        return 0;
    case NPF_PEER_OPT_CTX:
        x->ctx = (void *)val;
        return len == 0 ? 0 : -1;
    }
    return -1;
}

int npf_peer_setopt(npf_t *n, uint32_t peer, int opt, const void *val, size_t len)
{
    so_arg x = {.id = peer, .opt = opt};
    if (opt_value(&x, val, len) < 0)
        return NPF_EINVAL;
    return npf_api_op(n, peer_setopt_run, &x);
}

/* Peer objects, outgoing sessions, authentication and reconnection. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf.h"
#include "npf/platform.h"
#include "npf/resolve.h"
#include "npf/text.h"
#include "npf/why.h"

#include "peers_internal.h"

/* Reconnecting without a storm: delays double from 1 s up to the cap, each
 * with +-25 % jitter (peers that lost the same server do not come back in
 * step); a session must stay up STABLE_MS before the delay starts again from
 * 1 s (a session that drops at once does not loop every second); at login
 * the peers start spread over up to 2 s. Port mappings retry the same way,
 * each on its own. */
#define BACKOFF_MAX_MS     120000
#define STABLE_MS          60000
#define LOGIN_SPREAD_MS    2000
#define IDLE_DEFAULT_MS    300000   /* on demand, no idle time asked for nor set for all */
/* A pairing session that sent CPace's message 3 and never came up is a
 * guess at the password that the platform, playing the callee, can check
 * offline, however it ends (security.md 9.2): after PAKE_TRIES of them the
 * password is wiped and the peer needs it again. 2: one retry covers a
 * session lost after message 3 (a relay or a punch that failed then), and
 * each one more would give a platform one more guess per password given */
#define PAKE_TRIES         2
/* A callee with remote access off refuses each try; retried, a burst of
 * tries from one source then meets the platform's limit on callers it has
 * not paired with, which answers "unavailable" (security.md 8.3: it tells a
 * stranger nothing). Within OFF_KEEP_MS (the limit's window) of the
 * callee's own remote_access_off, an unavailable keeps that reason: the
 * user sees why, not the limit */
#define OFF_KEEP_MS        120000

/* target's local.json record (made when create), NULL: none */
static npf_ldev *dev_of(const npf_peers *ps, const char *target, int create)
{
    return ps->lc ? npf_local_dev(ps->lc, target, create) : NULL;
}

/* ---- known callee keys: the pinned public keys, in local.json ---- */

static int known_get(const npf_peers *ps, uint64_t number, uint8_t pub[32])
{
    char t[24];
    npf_ldev *d;
    snprintf(t, sizeof t, "%llu", (unsigned long long)number);
    if (!(d = dev_of(ps, t, 0)) || !d->has_key)
        return 0;
    memcpy(pub, d->key, 32);
    return 1;
}

/* ---- the peer's one timer (architecture.md 3.9) ---- */

static void peer_free_now(npf_peer *p);

static void peer_timer(npf_loop *loop, void *arg)
{
    npf_peer *p = arg;
    (void)loop;
    if (p->st == PS_REMOVED) {              /* the turn after npf_peers_remove */
        peer_free_now(p);
        return;
    }
    peer_tick(p, npf_mono_ms());
    peers_at(p, peer_due(p));
}

void peers_at(npf_peer *p, int64_t at)
{
    int64_t d = at - npf_mono_ms();
    if (at == INT64_MAX || (npf_timer_pending(&p->t_due) && at >= p->due_at))
        return;
    p->due_at = at;
    npf_timer_set(p->ps->n->loop, &p->t_due, d);
}

static int64_t earliest(int64_t d, int64_t at)
{
    return at && at < d ? at : d;
}

int64_t peer_due(const npf_peer *p)
{
    int64_t d = earliest(INT64_MAX, p->demand_at);
    int i;
    if (p->st == PS_REMOVED)
        return 0;
    for (i = 0; i < p->nfwd; i++)
        d = earliest(earliest(d, p->fwds[i]->accept_at), p->fwds[i]->st == FS_RETRY ? p->fwds[i]->retry_at : 0);
    return earliest(d, peer_waits(p) ? p->retry_at : 0);
}

/* (a removal on the way leaves nothing due: peer_drop) */
void peer_tick(npf_peer *p, int64_t now)
{
    if (peer_waits(p) && p->retry_at <= now)
        peers_kick(p);
    peers_demand_tick(p, now);
    peers_forwards_tick(p, now);
}

/* ---- sessions ---- */

/* the peer gives up (it stays, ended, until removed or tried again) */
static void finish(npf_peer *p, const char *why)
{
    if (p->st >= PS_ENDED)
        return;
    p->st = PS_ENDED;
    peers_demand_drop(p, why);
    if (why != p->last_why)                 /* finish(p, p->last_why): no copy onto itself */
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
    if (p->ps->cbs.done)
        p->ps->cbs.done(p, why, p->ps->arg);
}

/* an ended peer tries again, as it was made */
static void unfinish(npf_peer *p)
{
    if (p->st == PS_ENDED)
        p->st = PS_IDLE, p->backoff = 0;
}

int peers_kick(npf_peer *p)
{
    if (peer_waits(p))
        p->st = PS_IDLE;                    /* now, not at retry_at */
    peers_start_call(p);
    return p->st == PS_REMOVED ? -1 : 0;
}

void npf_peers_retry_now(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->st == PS_ENDED && !p->direct     /* a need an account session may meet */
            && (strcmp(p->last_why, "no_account") == 0 || strcmp(p->last_why, "not_paired") == 0)) {
            npf_log("%s: an account session: trying again", p->name);
            unfinish(p);
            peers_start_call(p);
        } else if (peer_waits(p) && !p->idle_ms) {
            npf_log("%s: retrying now", p->name);
            peers_kick(p);
        }
    }
}

/* reconnect later, or report the peer ended */
static void again(npf_peer *p, const char *why)
{
    int d;
    if (p->idle_ms) {                       /* on demand: the next connection tries again */
        peers_demand_drop(p, why);
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
        return;
    }
    if (p->connect == NPF_CONNECT_ONCE) {
        finish(p, why);
        return;
    }
    if (p->st != PS_IDLE)
        return;
    d = npf_backoff(&p->backoff, 1000, BACKOFF_MAX_MS);
    snprintf(p->last_why, sizeof p->last_why, "%s", why);
    p->st = PS_RETRY;
    p->retry_at = npf_mono_ms() + d;
    npf_log("%s: reconnecting in %d s", p->name, (d + 999) / 1000);
    peers_at(p, p->retry_at);
}

/* the session started (c), or not (reconnecting later) */
static void session(npf_peer *p, npf_call *c)
{
    p->call = c;
    p->st = c ? PS_CALL : PS_IDLE;
    if (!c)
        again(p, "error");
}

/* why it cannot connect without a password: a refused one stays the reason
 * (the console says the password was wrong) until another is given */
static const char *unpaired_why(const npf_peer *p)
{
    return npf_why_needs(p->last_why) & NPF_NEED_PASSWORD_WRONG ? p->last_why : "not_paired";
}

static void grant_got(npf_node *n, const npf_env *e, int ok, void *arg)
{
    npf_peer *p = arg;
    uint8_t chain[1024], grant[512];
    int cl, gl;
    if (p->st != PS_ASKING)
        return;
    p->st = PS_IDLE;
    if (!ok) {
        const char *err = e && e->error[0] ? e->error : "no reply";
        if (strcmp(err, "unavailable") == 0) {  /* the account neither owns it nor was given it */
            p->by_account = 0;
            npf_logw("%s: not paired yet, and the account has no access to it: give its password (-p)", p->name);
            finish(p, unpaired_why(p));     /* a password tries again */
        } else {
            npf_logw("%s: the account's grant refused (%s)", p->name, err);
            again(p, err);
        }
        return;
    }
    cl = npf_json_get_b64(e->j, e->data, "cert", chain, sizeof chain);
    gl = npf_json_get_b64(e->j, e->data, "grant", grant, sizeof grant);
    if (cl <= 0 || gl <= 0) {
        session(p, NULL);
        return;
    }
    p->by_account = 1;
    p->call_pinned = 0;
    session(p, npf_call_start_grant(n, p->number, chain, (size_t)cl, grant, (size_t)gl));
}

static void grant_updated(npf_call *c, const npf_env *e, int ok, void *arg)
{
    npf_peer *p = arg;
    (void)c;
    if (ok) {
        npf_log("%s: the device took the new target list", p->name);
        return;
    }
    npf_logw("%s: grant_update refused (%s): the session starts again", p->name, e && e->error[0] ? e->error : "no reply");
    if (p->call)
        npf_call_end(p->call, "closed");    /* the next session brings the new grant */
}

static void grant_renewed(npf_node *n, const npf_env *e, int ok, void *arg)
{
    npf_peer *p = arg;
    uint8_t grant[512];
    char data[NPF_B64_LEN(512) + 32], g64[NPF_B64_LEN(512) + 1];
    int gl;
    (void)n;
    p->renewing = 0;
    if (!p->call || npf_call_state(p->call) != NPF_CALL_ESTABLISHED)
        return;                             /* a new session gets a new grant anyway */
    gl = ok ? npf_json_get_b64(e->j, e->data, "grant", grant, sizeof grant) : -1;
    if (gl <= 0) {
        npf_logw("%s: no new grant: the session ends (no target left?)", p->name);
        npf_call_end(p->call, "closed");
        return;
    }
    g64[npf_b64url_encode(grant, (size_t)gl, g64)] = 0;
    snprintf(data, sizeof data, "{\"grant\":\"%s\"}", g64);
    if (npf_call_ctl_request(p->call, "grant_update", data, grant_updated, p) < 0)
        npf_call_end(p->call, "closed");
}

void npf_peer_grant_update(npf_peer *p)
{
    npf_node *n = p->ps->n;
    char data[64];
    if (!n->cfg.hosted_exec || !p->call || p->renewing || npf_call_state(p->call) != NPF_CALL_ESTABLISHED)
        return;
    snprintf(data, sizeof data, "{\"callee\":\"%llu\"}", (unsigned long long)p->number);
    if (npf_node_request(n, "grant_get", data, grant_renewed, p) == 0)
        p->renewing = 1;
}

/* a direct peer's name, looked up off the loop thread: its IPv4 address,
 * else an IPv6 one when the node has an IPv6 socket */
static void direct_resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens,
                            int na, void *arg)
{
    npf_peer *p = arg;
    const struct sockaddr_storage *to = NULL;
    int i;
    (void)r;
    (void)lens;
    p->rs = NULL;
    p->st = PS_IDLE;
    for (i = 0; !err && i < na; i++)
        if (addrs[i].ss_family == AF_INET) {
            to = &addrs[i];
            break;
        } else if (!to && addrs[i].ss_family == AF_INET6 && p->ps->n->udp6_fd >= 0) {
            to = &addrs[i];
        }
    if (!to) {
        npf_logw("%s: cannot resolve the name%s", p->name, err ? "" : " to an address this node can reach");
        again(p, "unreachable");
        return;
    }
    session(p, npf_direct_connect(p->ps->n, to, p->psk));
}

static void direct_start(npf_peer *p)
{
    char host[256];
    uint16_t port;
    if (p->to.ss_family) {
        session(p, npf_direct_connect(p->ps->n, &p->to, p->psk));
        return;
    }
    if (npf_hostport(p->name, host, sizeof host, &port) < 0
        || !(p->rs = npf_resolve_start(p->ps->n->loop, host, port, SOCK_DGRAM, direct_resolved, p))) {
        again(p, "error");
        return;
    }
    p->st = PS_ASKING;
}

void peers_start_call(npf_peer *p)
{
    npf_node *n = p->ps->n;
    uint8_t pub[32];
    int pinned;
    if (p->st != PS_IDLE)
        return;
    if (p->direct) {
        direct_start(p);
        return;
    }
    if (!n->online) {
        if (p->npend || p->nuq) {           /* signaling on demand: a connection waits */
            npf_node_udp_open(n);           /* UDP on demand: meanwhile */
            npf_node_wake(n, "a connection to a public port");
        }
        return;                             /* the next login starts it */
    }
    if (!npf_node_udp_ready(n))
        return;                             /* UDP on demand: on_udp_ready starts it */
    /* a hosted client always comes with a grant: the device never pairs it */
    pinned = !n->cfg.hosted_exec && known_get(p->ps, p->number, pub);
    if (pinned && p->pin_refused && !p->password[0]) {
        /* paired by password: never the account's grant instead (security.md 9.6) */
        finish(p, "pairing_lost");          /* a new password tries again */
        return;
    }
    if (!pinned && !p->password[0]) {
        if (n->account_id) {
            char data[64];
            snprintf(data, sizeof data, "{\"callee\":\"%llu\"}", (unsigned long long)p->number);
            if (npf_node_request(n, "grant_get", data, grant_got, p) == 0)
                p->st = PS_ASKING;
            else
                again(p, "error");
            return;
        }
        if (p->by_account)
            npf_logw("%s: the account is logged out (its session expired or was revoked): log in again", p->name);
        else
            npf_log("%s: not paired yet: give its password (-p)", p->name);
        finish(p, p->by_account ? "no_account" : unpaired_why(p));  /* a password or an account session tries again */
        return;
    }
    p->call_pinned = pinned && !p->password[0];
    session(p, npf_call_start(n, p->number, p->call_pinned ? NULL : p->password, pinned ? pub : NULL));
}

/* ---- names people give peers (local.json) ---- */

int npf_peers_name_set(npf_peers *ps, const char *name, const char *target, char *err, size_t errcap)
{
    npf_ldev *d, *other;
    npf_peer *p;
    if (!ps->lc) {
        snprintf(err, errcap, "no local.json to keep names in");
        return -1;
    }
    if (*name && !npf_name_valid(name)) {
        snprintf(err, errcap, "%s: a name is letters, digits, '.', '_', '-' (at most 32), not only digits", name);
        return -1;
    }
    if (*name && (other = npf_local_by_name(ps->lc, name)) && strcmp(other->target, target) != 0) {
        snprintf(err, errcap, "the name %s is %s's already", name, other->target);
        return -1;
    }
    if (!(d = npf_local_dev(ps->lc, target, 1))) {
        snprintf(err, errcap, "too many devices in %s", ps->lc->path);
        return -1;
    }
    snprintf(d->name, sizeof d->name, "%s", name);
    if (npf_local_save(ps->lc) < 0) {
        snprintf(err, errcap, "cannot write %s", ps->lc->path);
        return -1;
    }
    for (p = ps->list; p; p = p->next)
        if (strcmp(p->name, target) == 0)
            snprintf(p->label, sizeof p->label, "%s", name);
    return 0;
}

const char *npf_peers_resolve(const npf_peers *ps, const char *word, char *buf, size_t cap)
{
    npf_ldev *d;
    if (ps->lc && npf_name_valid(word) && (d = npf_local_by_name(ps->lc, word))) {
        snprintf(buf, cap, "%s", d->target);
        return buf;
    }
    return word;
}

const char *npf_peer_nick(const npf_peer *p)
{
    npf_ldev *d;
    if (p->has_nick_here)
        return p->nick_here;                /* this run's (the application keeps its objects) */
    return (d = dev_of(p->ps, p->name, 0)) ? d->nick : "";
}

const char *npf_peer_resources(const npf_peer *p)
{
    npf_ldev *d;
    if (p->resources)
        return p->resources;
    return (d = dev_of(p->ps, p->name, 0)) ? d->resources : NULL;
}

int npf_peer_resources_same(const npf_peer *p, const char *json)
{
    return p->resources && strcmp(p->resources, json) == 0;
}

const char *npf_peer_remote_name(const npf_peer *p)
{
    npf_ldev *d;
    if (p->has_remote_name)
        return p->remote_name;
    return (d = dev_of(p->ps, p->name, 0)) ? d->remote_name : "";
}

const char *npf_peer_role(const npf_peer *p)
{
    return p->role;
}

void npf_peer_role_set(npf_peer *p, const char *role)
{
    snprintf(p->role, sizeof p->role, "%s", strcmp(role, "admin") == 0 || strcmp(role, "member") == 0 ? role : "");
}

#define SAVE_GAP_MS 30000       /* local.json for the peers' lists: once in this long at most */

static void save_later(npf_loop *loop, void *arg)
{
    npf_peers *ps = arg;
    (void)loop;
    ps->t_save = NULL;
    ps->saved_at = npf_mono_ms();
    npf_local_save(ps->lc);
}

/* a peer sending one list after another (its session's control units)
 * costs one write of local.json every SAVE_GAP_MS, not one per list */
static int save_soon(npf_peers *ps)
{
    int64_t now = npf_mono_ms();
    if (ps->t_save)
        return 0;
    if (!ps->saved_at || now - ps->saved_at >= SAVE_GAP_MS) {
        ps->saved_at = now;
        return npf_local_save(ps->lc);
    }
    ps->t_save = npf_timer_add(ps->n->loop, ps->saved_at + SAVE_GAP_MS - now, save_later, ps);
    return 0;
}

int npf_peer_resources_set(npf_peer *p, const char *json)
{
    npf_ldev *d = dev_of(p->ps, p->name, 0);
    char *s = strdup(json);
    if (!s)
        return -1;
    free(p->resources);
    p->resources = s;
    /* its local.json record keeps the last one (shown while it is away);
     * a peer without a record gets none for it */
    if (d && !p->ps->no_cache && (!d->resources || strcmp(d->resources, json) != 0)) {
        char *k = strdup(json);
        if (!k)
            return -1;
        free(d->resources);
        d->resources = k;
        return save_soon(p->ps);
    }
    return 0;
}

int npf_peer_remote_name_set(npf_peer *p, const char *name)
{
    npf_ldev *d = dev_of(p->ps, p->name, 0);
    char v[NPF_PEER_NAME_MAX + 1];
    int same;
    snprintf(v, sizeof v, "%s", name);     /* longer: cut, then cut at a character */
    if (npf_text_display(v, NPF_PEER_NAME_MAX) < 0)
        v[0] = 0;
    same = p->has_remote_name && strcmp(p->remote_name, v) == 0;
    snprintf(p->remote_name, sizeof p->remote_name, "%s", v);
    p->has_remote_name = 1;
    if (d && !p->ps->no_cache && strcmp(d->remote_name, v) != 0) {
        snprintf(d->remote_name, sizeof d->remote_name, "%s", v);
        if (save_soon(p->ps) < 0)
            return -1;
    }
    return !same;
}

npf_peers *npf_peers_new(npf_node *n, npf_local *lc, const npf_peers_cbs *cbs, void *arg)
{
    npf_peers *ps = calloc(1, sizeof *ps);
    if (!ps)
        return NULL;
    ps->n = n;
    ps->lc = lc;
    if (cbs)
        ps->cbs = *cbs;
    ps->arg = arg;
    return ps;
}

/* removed: the session ends without the done callback, the listeners close */
static void peer_drop(npf_peer *p)
{
    npf_call *c = p->call;
    if (p->st == PS_ASKING || p->renewing)
        npf_node_cancel_requests(p->ps->n, p);
    p->st = PS_REMOVED;                     /* no done callback, nothing starts again */
    p->call = NULL;                         /* the state callback does not find it */
    p->renewing = 0;
    npf_resolve_cancel(p->rs);
    p->rs = NULL;
    p->demand_at = 0;
    peers_demand_drop(p, "closed");
    if (c)
        npf_call_end(c, "closed");
    peers_listeners_close(p);
}

/* what is left of a removed peer (off the gone list): anything a callback
 * started on it after the removal goes too */
static void peer_free_now(npf_peer *p)
{
    npf_peer **pp;
    int i;
    for (pp = &p->ps->gone; *pp; pp = &(*pp)->gone_next)
        if (*pp == p) {
            *pp = p->gone_next;
            break;
        }
    peer_drop(p);                           /* its waiting queues emptied and freed too */
    npf_timer_cancel(p->ps->n->loop, &p->t_due);
    for (i = 0; i < p->nfwd; i++) {
        free(p->fwds[i]->acl);
        npf_wipe_free(p->fwds[i], sizeof *p->fwds[i]);
    }
    free(p->resources);
    npf_wipe_free(p, sizeof *p);
}

/* the session ends (peer_drop); freed on the next turn, never at once: the
 * application may remove a peer from any callback (npf.h), its own done and
 * forward events too, and the code that called out still holds the peer and
 * its forwards (accept_cb, demand_wait, the loops over the forwards and the
 * peers). That code stops at PS_REMOVED; a removed peer tells nothing more
 * (fwd_changed, finish) and its stale next still leads through the list */
void npf_peers_remove(npf_peers *ps, npf_peer *p)
{
    npf_peer **pp;
    int k;
    if (p->st == PS_REMOVED)
        return;                             /* again, from a callback of its removal */
    for (k = 0; k < ps->nconns; k++)       /* its open connections end later, without it */
        if (ps->conns[k].p == p)
            ps->conns[k].p = NULL;
    for (pp = &ps->list; *pp; pp = &(*pp)->next)
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    if (p->call)
        peers_subs_call_gone(ps, p->call);
    peer_drop(p);
    p->gone_next = ps->gone;
    ps->gone = p;
    peers_at(p, 0);                         /* no timer (no memory): freed with the peers */
}

/* HOST:PORT in its canonical form ("" when it is not one) */
static void canon_target(const char *word, char *out, size_t cap)
{
    char host[300];
    uint16_t port;
    if (npf_hostport(word, host, sizeof host, &port) < 0 || npf_peer_target_name(0, host, port, out, cap) < 0)
        out[0] = 0;
}

npf_peer *npf_peers_find(const npf_peers *ps, const char *name)
{
    npf_peer *p;
    uint64_t num = npf_number_parse(name);
    char canon[320];
    canon_target(name, canon, sizeof canon);
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (strcmp(p->name, name) == 0 || (num && p->number == num) || (canon[0] && strcmp(p->name, canon) == 0)
            || (p->label[0] && strcmp(p->label, name) == 0))
            return p;
    return NULL;
}

npf_peer *npf_peers_first(const npf_peers *ps) { return ps ? ps->list : NULL; }
npf_peer *npf_peer_next(const npf_peer *p) { return p->next; }
void      npf_peer_set_tag(npf_peer *p, int tag) { p->tag = tag; }
int       npf_peer_tag(const npf_peer *p) { return p->tag; }

/* the text of npf_peer_state, for people (the web console matches it) */
const char *npf_peer_status(const npf_peer *p, char *buf, size_t cap)
{
    int ms;
    switch (npf_peer_state(p, NULL, &ms)) {
    case NPF_PEER_CONNECTED: snprintf(buf, cap, "connected"); break;
    case NPF_PEER_CONNECTING: snprintf(buf, cap, "connecting"); break;
    case NPF_PEER_IDLE: snprintf(buf, cap, "on demand"); break;   /* a connection (or node wake) starts the session */
    case NPF_PEER_RETRY: snprintf(buf, cap, "retry in %d s (%s)", (ms + 999) / 1000, p->last_why); break;
    case NPF_PEER_ENDED: snprintf(buf, cap, "ended (%s)", p->last_why); break;
    default: snprintf(buf, cap, "waiting for the server"); break;
    }
    return buf;
}

void npf_peers_free(npf_peers *ps)
{
    npf_peer *p;
    if (!ps)
        return;
    /* unlink first: ending a call reports its state, and the callback walks
     * the list (several peers end one after another) */
    while ((p = ps->list) != NULL) {
        ps->list = p->next;
        peer_free_now(p);
    }
    while (ps->gone)
        peer_free_now(ps->gone);
    {   /* the sessions still being freed must not call back into us */
        npf_call *c;
        for (c = npf_node_calls(ps->n); c; c = npf_call_next(c))
            npf_call_on_sublink_done(c, NULL, NULL);
    }
    npf_timer_cancel(ps->n->loop, ps->t_idle);
    if (ps->t_save) {                   /* what waited to be written goes now */
        npf_timer_cancel(ps->n->loop, ps->t_save);
        npf_local_save(ps->lc);
    }
    peers_http_free(ps);
    peers_conns_free(ps);
    free(ps->subs);
    free(ps);
}

int npf_peer_target_name(uint64_t number, const char *host, uint16_t port, char *out, size_t cap)
{
    char h[256], a[64];
    unsigned char bin[16];
    size_t i;
    int n;
    if (number) {
        n = snprintf(out, cap, "%llu", (unsigned long long)number);
        return n < 0 || (size_t)n >= cap ? -1 : 0;
    }
    if (!host || !*host || !port || strlen(host) >= sizeof h || strchr(host, ' '))
        return -1;
    for (i = 0; host[i]; i++)
        h[i] = (char)((host[i] >= 'A' && host[i] <= 'Z') ? host[i] - 'A' + 'a' : host[i]);
    h[i] = 0;
    if (inet_pton(AF_INET, h, bin) == 1 && inet_ntop(AF_INET, bin, a, sizeof a))
        n = snprintf(out, cap, "%s:%u", a, (unsigned)port);
    else if (inet_pton(AF_INET6, h, bin) == 1 && inet_ntop(AF_INET6, bin, a, sizeof a))
        n = snprintf(out, cap, "[%s]:%u", a, (unsigned)port);
    else if (strchr(h, ':'))
        return -1;
    else
        n = snprintf(out, cap, "%s:%u", h, (unsigned)port);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}

npf_peer *npf_peers_create(npf_peers *ps, const npf_peer_new *pn, char *err, size_t errcap, int *code)
{
    npf_peer *p, **pp;
    npf_ldev *d;
    char name[320];
    int dummy;
    if (!code)
        code = &dummy;
    *code = 1;
    if (npf_peer_target_name(pn->number, pn->host, pn->port, name, sizeof name) < 0 || strlen(name) >= sizeof p->name) {
        snprintf(err, errcap, "peer: a number, or a host and a port");
        return NULL;
    }
    if (pn->number && pn->number == ps->n->cfg.number) {
        snprintf(err, errcap, "%llu is this computer's own number: it cannot connect to itself",
                 (unsigned long long)pn->number);
        return NULL;
    }
    if (pn->password && strlen(pn->password) >= sizeof p->password) {
        snprintf(err, errcap, "peer %s: the password is too long", name);
        return NULL;
    }
    if (!pn->number && !pn->psk) {
        snprintf(err, errcap, "peer %s: a direct peer needs its pre-shared key", name);
        return NULL;
    }
    if (npf_peers_find(ps, name)) {
        *code = 2;
        snprintf(err, errcap, "%s is a peer already", name);
        return NULL;
    }
    *code = 3;
    if (!(p = calloc(1, sizeof *p))) {
        snprintf(err, errcap, "no memory");
        return NULL;
    }
    p->ps = ps;
    npf_timer_init(&p->t_due, peer_timer, p);
    memcpy(p->name, name, strlen(name) + 1);        /* it fits: checked above */
    p->number = pn->number;
    if (!pn->number) {
        p->direct = 1;
        if (npf_addr_parse(name, &p->to) < 0)
            memset(&p->to, 0, sizeof p->to);   /* a name: looked up when a session starts */
        memcpy(p->psk, pn->psk, 32);
    }
    if (pn->password)
        snprintf(p->password, sizeof p->password, "%s", pn->password);
    p->connect = pn->connect;
    npf_peer_idle_put(p, pn->idle_ms);
    if ((d = dev_of(ps, p->name, 0)))
        snprintf(p->label, sizeof p->label, "%s", d->name);
    p->id = ++ps->peer_seq;
    for (pp = &ps->list; *pp; pp = &(*pp)->next)
        ;
    *pp = p;
    if (p->idle_ms)
        peers_forwards_start(p);            /* on demand: listening, a connection starts the session */
    return p;
}

int npf_peers_count(const npf_peers *ps)
{
    const npf_peer *p;
    int n = 0;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        n++;
    return n;
}

void npf_peers_start(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (p->direct && p->st != PS_REMOVED)
            npf_peer_start(p);
}

void npf_peer_start(npf_peer *p)
{
    int online = p->ps->n->online;          /* offline: the login starts it (a direct peer needs none) */
    if (p->direct || (online && !p->idle_ms))
        peers_start_call(p);                /* (not while waiting to retry) */
    else if (online && !p->listening)
        peers_forwards_start(p);            /* on demand: listening; a connection starts the session */
}

void npf_peers_on_login(npf_peers *ps)
{
    npf_peer *p;
    int waiting = 0;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        waiting += !p->idle_ms && !p->direct && p->st == PS_IDLE;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->st == PS_REMOVED)
            continue;                       /* in a callback of the peer before it */
        if (p->idle_ms) {                   /* on demand: listening; a connection starts the session */
            if (!p->listening)
                peers_forwards_start(p);
            if (p->npend || p->nuq)
                peers_start_call(p);
            continue;
        }
        if (p->direct || p->st != PS_IDLE)
            continue;
        if (waiting > 1 && !ps->n->th.no_spread) {
            /* many peers: spread the calls (and their punching); tests that
             * need concurrent punches turn it off (NPF_TEST_NO_SPREAD) */
            p->st = PS_START;
            p->retry_at = npf_mono_ms() + (int64_t)npf_rand_range(0, LOGIN_SPREAD_MS);
            peers_at(p, p->retry_at);
        } else {
            peers_start_call(p);
        }
    }
}

int npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why)
{
    npf_peer *p;
    int k;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (p->call == c)
            break;
    if (!p)
        return 0;
    if (st == NPF_CALL_CONNECTING && npf_call_auth(c) == NPF_AUTH_PAKE)
        p->pake_tries++;                /* message 3 went (call_on_accepted) */
    if (st == NPF_CALL_ESTABLISHED) {
        npf_log("%s: connected (%s)", p->name, npf_call_path_label(c));
        p->up_since = npf_mono_ms();
        p->off_at = 0;
        peers_forwards_start(p);        /* a mapping that fails retries on its own */
        if (p->st == PS_REMOVED)
            return 1;                   /* in a forward event */
        peers_ready(p);                 /* the connections that waited for it, now or once it can take them */
        for (k = 0; k < p->ps->nkinds; k++)     /* and those of the modules' forwards */
            if (p->ps->kinds[k].k->kick)
                p->ps->kinds[k].k->kick(p->ps->kinds[k].arg);
        if (p->idle_ms)
            peers_demand_timer(p);
        if (p->ps->cbs.up)
            p->ps->cbs.up(p, c, p->ps->arg);
    } else if (st == NPF_CALL_CLOSED) {
        int64_t now = npf_mono_ms();
        npf_log("%s: session closed (%s)", p->name, why ? why : "");
        if (why && strcmp(why, "remote_access_off") == 0)
            p->off_at = now;
        else if (why && strcmp(why, "unavailable") == 0 && p->off_at && now - p->off_at < OFF_KEEP_MS)
            why = "remote_access_off";      /* the device's reason, not the limit's (OFF_KEEP_MS) */
        p->call = NULL;
        p->st = PS_IDLE;
        peers_subs_call_gone(p->ps, c);
        if (why && strcmp(why, "auth_failed") == 0 && p->password[0] && !p->up_since) {
            /* the device refused the password or the share code's secret (the
             * same auth_failed on the wire: the share code is ours to know):
             * not tried again (each try counts against it there, security.md
             * 8.3); the user gives it anew */
            int share = npf_share_parse(p->password, NULL, NULL) == 0;
            npf_logw(share ? "%s: the share code's secret is wrong: check the code, or ask for a new one"
                           : "%s: the password was not accepted: give it again (-p)", p->name);
            npf_wipe(p->password, sizeof p->password);
            why = share ? "wrong_share_code" : "wrong_password";
        }
        if (why && strcmp(why, "unauthorized") == 0 && npf_share_parse(p->password, NULL, NULL) == 0) {
            /* a share code the device does not know (used up, expired or deleted): never again */
            npf_logw("%s: the share code is used up, expired or deleted there: ask for a new one", p->name);
            npf_wipe(p->password, sizeof p->password);
            why = "wrong_share_code";
        }
        if (why && strcmp(why, "unauthorized") == 0 && p->call_pinned) {
            /* the device does not know the pairing any more (reset or
             * reinstalled: new keys, or the pairing revoked): trying again
             * never helps, and the account's grant does not replace a
             * password pairing (security.md 9.6): the user pairs anew */
            npf_logw("%s: the device no longer accepts this computer's pairing (reset, reinstalled, "
                     "or the pairing revoked): pair again with its password (-p)", p->name);
            p->pin_refused = 1;
            why = "pairing_lost";
        }
        if (p->password[0] && !p->up_since && p->pake_tries >= PAKE_TRIES) {
            npf_logw("%s: the pairing did not complete in %d tries: give the password or share code again (-p)",
                     p->name, p->pake_tries);
            npf_wipe(p->password, sizeof p->password);
            why = "not_paired";
        }
        p->call_pinned = 0;
        peers_forwards_session_gone(p);
        if (p->st == PS_REMOVED)
            return 1;
        if (p->up_since && npf_mono_ms() - p->up_since >= STABLE_MS)
            p->backoff = 0;             /* it was up long enough: start from 1 s again */
        p->up_since = 0;
        if (npf_why_needs(why) & NPF_NEED_PASSWORD) {
            finish(p, why);                 /* a new password tries again */
            return 1;
        }
        /* on demand: no reconnecting; the connections that waited for this
         * session go, a new connection starts the next one (again) */
        again(p, why ? why : "closed");
    }
    return 1;
}

void npf_peers_on_paired(npf_peers *ps, uint64_t number, const uint8_t pub[32])
{
    npf_peer *p;
    npf_ldev *d;
    char t[24];
    if (!ps)
        return;
    snprintf(t, sizeof t, "%llu", (unsigned long long)number);
    if ((d = dev_of(ps, t, 1))) {
        if (d->has_key && memcmp(d->key, pub, 32) != 0)
            npf_log("note: the key of %llu changed; the new key replaces the pinned one", (unsigned long long)number);
        memcpy(d->key, pub, 32);
        d->has_key = 1;
        if (npf_local_save(ps->lc) < 0)
            npf_loge("cannot write %s", ps->lc->path);
    }
    npf_log("paired with %llu; later connections need no password", (unsigned long long)number);
    for (p = ps->list; p; p = p->next)
        if (p->number == number) {
            npf_wipe(p->password, sizeof p->password);    /* IK from now on */
            p->pin_refused = 0;
        }
}

npf_call   *npf_peer_call(const npf_peer *p) { return p->call; }
uint64_t    npf_peer_number(const npf_peer *p) { return p->number; }
const char *npf_peer_name(const npf_peer *p) { return p->name; }
const char *npf_peer_label(const npf_peer *p) { return p->label; }
const char *npf_peer_shown(const npf_peer *p) { return p->label[0] ? p->label : p->name; }
int         npf_peer_nfwd(const npf_peer *p) { return p->nfwd; }
uint32_t    npf_peer_id(const npf_peer *p) { return p->id; }
void       *npf_peer_ctx(const npf_peer *p) { return p->ctx; }
void        npf_peer_ctx_put(npf_peer *p, void *ctx) { p->ctx = ctx; }
int         npf_peer_connect_mode(const npf_peer *p) { return p->connect; }
int         npf_peer_idle_asked(const npf_peer *p) { return p->idle_req; }
const char *npf_peer_last_why(const npf_peer *p) { return p->last_why; }

npf_peer *npf_peers_by_id(const npf_peers *ps, uint32_t id)
{
    npf_peer *p;
    for (p = ps && id ? ps->list : NULL; p; p = p->next)
        if (p->id == id)
            return p;
    return NULL;
}

/* into the caller's buffer: instances run on threads of their own (a
 * static one was shared by all) */
int npf_peer_direct_target(const npf_peer *p, char *host, size_t cap, uint16_t *port)
{
    return p->direct ? npf_hostport(p->name, host, cap, port) : -1;     /* (its name is canonical: HOST:PORT) */
}

void npf_peer_set_nick_here(npf_peer *p, const char *nick)
{
    p->has_nick_here = nick != NULL;
    snprintf(p->nick_here, sizeof p->nick_here, "%s", nick ? nick : "");
}

void npf_peer_set_label(npf_peer *p, const char *name)
{
    snprintf(p->label, sizeof p->label, "%s", name ? name : "");
}

int npf_peer_needs(const npf_peer *p)
{
    return p->call || p->password[0] ? 0 : npf_why_needs(p->last_why);
}

int npf_peer_state(const npf_peer *p, int *needs, int *retry_in_ms)
{
    int nd = npf_peer_needs(p), st;
    if (retry_in_ms)
        *retry_in_ms = 0;
    if (p->st == PS_CALL && npf_call_state(p->call) == NPF_CALL_ESTABLISHED)
        st = NPF_PEER_CONNECTED;
    else if (p->st == PS_CALL || p->st == PS_ASKING)
        st = NPF_PEER_CONNECTING;
    else if (p->st >= PS_ENDED)
        st = NPF_PEER_ENDED;
    else if (p->idle_ms)
        st = NPF_PEER_IDLE;
    else if (p->st == PS_RETRY) {
        int64_t ms = p->retry_at - npf_mono_ms();
        st = NPF_PEER_RETRY;
        if (retry_in_ms)
            *retry_in_ms = ms > 0 ? (int)ms : 0;
    } else
        st = NPF_PEER_WAITING;              /* PS_IDLE, PS_START: for the login, or spread after it */
    if (needs)
        *needs = st == NPF_PEER_CONNECTED || st == NPF_PEER_CONNECTING ? 0 : nd;
    return st;
}

void npf_peer_connect_put(npf_peer *p, int connect, int idle_ms, int running)
{
    int busy = p->st == PS_CALL || p->st == PS_ASKING;
    p->connect = connect;
    p->idle_ms = 0;                         /* idle_req stays: the time asked for on demand */
    if (connect == NPF_CONNECT_ON_DEMAND) {
        npf_peer_idle_put(p, idle_ms);
        p->idle_since = 0;                  /* the idle time runs from now */
        /* no reconnecting: a connection starts the next one */
        if (peer_waits(p))
            p->st = PS_IDLE;
        if (!p->listening)
            peers_forwards_start(p);        /* listening now, the session when a connection comes */
        if (p->call)
            peers_demand_timer(p);
    } else if (connect == NPF_CONNECT_KEEP) {
        unfinish(p);
        if (running)
            peers_start_call(p);            /* no session: one now (a direct one too), not while waiting to retry */
    } else if (!busy) {                     /* ONCE, no session to end first: ended now (a retry too) */
        finish(p, p->last_why[0] ? p->last_why : "local");
    }
}

const uint8_t *npf_peer_psk(const npf_peer *p) { return p->direct ? p->psk : NULL; }

void npf_peer_idle_put(npf_peer *p, int idle_ms)
{
    p->idle_req = idle_ms > 0 ? idle_ms : 0;
    if (p->connect == NPF_CONNECT_ON_DEMAND)    /* else used once it is on demand */
        p->idle_ms = p->idle_req ? p->idle_req : p->ps->default_idle_ms ? p->ps->default_idle_ms : IDLE_DEFAULT_MS;
}

void npf_peers_set_idle(npf_peers *ps, int idle_ms)
{
    npf_peer *p;
    if (!ps)
        return;
    ps->default_idle_ms = idle_ms > 0 ? idle_ms : 0;
    for (p = ps->list; p; p = p->next)
        npf_peer_idle_put(p, p->idle_req);  /* those on demand without a time of their own: the new default */
}

int npf_peers_idle(const npf_peers *ps) { return ps ? ps->default_idle_ms : 0; }
void npf_peers_no_cache(npf_peers *ps) { ps->no_cache = 1; }

int npf_peer_password_try(npf_peer *p, const char *password)
{
    if (!password[0] || strlen(password) >= sizeof p->password)
        return -1;
    snprintf(p->password, sizeof p->password, "%s", password);
    p->pake_tries = 0;
    if (npf_why_needs(p->last_why))
        p->last_why[0] = 0;
    npf_log("%s: password given", p->name);
    npf_peer_wake_now(p);
    return 0;
}

void npf_peer_wake_now(npf_peer *p)
{
    if (p->st != PS_ENDED && !peer_waits(p) && !(p->st == PS_IDLE && p->idle_ms))
        return;
    npf_log("%s: %s", p->name, p->st == PS_ENDED ? "trying again" : p->idle_ms ? "woken: starting the session" : "retrying now");
    unfinish(p);
    peers_kick(p);
}

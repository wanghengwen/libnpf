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

/* ---- sessions ---- */

/* the peer gives up (it stays, finished, until removed or tried again) */
static void finish(npf_peer *p, const char *why)
{
    if (p->finished)
        return;
    p->finished = 1;
    peers_demand_drop(p, why);
    if (why != p->last_why)                 /* finish(p, p->last_why): no copy onto itself */
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
    if (p->ps->cbs.done)
        p->ps->cbs.done(p, why, p->ps->arg);
}

/* a finished peer tries again, as it was made */
static void unfinish(npf_peer *p)
{
    p->finished = 0;
    p->backoff = 0;
}

static void retry_cb(npf_loop *loop, void *arg)
{
    npf_peer *p = arg;
    (void)loop;
    p->t_retry = NULL;
    peers_start_call(p);
}

int peers_kick(npf_peer *p)
{
    npf_timer_stop(p->ps->n->loop, &p->t_retry);
    peers_start_call(p);
    return p->removed ? -1 : 0;
}

void npf_peers_retry_now(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->removed || p->call || p->waiting)
            continue;
        if (!p->direct && p->finished   /* a need an account session may meet */
            && (strcmp(p->last_why, "no_account") == 0 || strcmp(p->last_why, "not_paired") == 0)) {
            npf_log("%s: an account session: trying again", p->name);
            unfinish(p);
            peers_start_call(p);
        } else if (p->t_retry && !p->idle_ms && !p->finished) {
            npf_log("%s: retrying now", p->name);
            peers_kick(p);
        }
    }
}

/* reconnect later, or report the peer finished */
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
    if (p->t_retry)
        return;
    d = npf_backoff(&p->backoff, 1000, BACKOFF_MAX_MS);
    snprintf(p->last_why, sizeof p->last_why, "%s", why);
    p->retry_at = npf_mono_ms() + d;
    npf_log("%s: reconnecting in %d s", p->name, (d + 999) / 1000);
    p->t_retry = npf_timer_add(p->ps->n->loop, d, retry_cb, p);
}

/* why it cannot connect without a password: a refused one stays the reason
 * (the console says the password was wrong) until another is given */
static const char *unpaired_why(const npf_peer *p)
{
    return strcmp(p->last_why, "wrong_password") == 0 ? "wrong_password" : "not_paired";
}

static void grant_got(npf_node *n, const npf_env *e, int ok, void *arg)
{
    npf_peer *p = arg;
    uint8_t chain[1024], grant[512];
    int cl, gl;
    p->waiting = 0;
    if (p->finished || p->call)
        return;
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
    if (cl > 0 && gl > 0) {
        p->by_account = 1;
        p->call_pinned = 0;
        p->call = npf_call_start_grant(n, p->number, chain, (size_t)cl, grant, (size_t)gl);
    }
    if (!p->call)
        again(p, "error");
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

static void direct_connect(npf_peer *p, const struct sockaddr_storage *to)
{
    if (!(p->call = npf_direct_connect(p->ps->n, to, p->psk)))
        again(p, "error");
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
    p->waiting = 0;
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
    direct_connect(p, to);
}

static void direct_start(npf_peer *p)
{
    char host[256];
    uint16_t port;
    if (p->to.ss_family) {
        direct_connect(p, &p->to);
        return;
    }
    if (npf_hostport(p->name, host, sizeof host, &port) < 0
        || !(p->rs = npf_resolve_start(p->ps->n->loop, host, port, SOCK_DGRAM, direct_resolved, p))) {
        again(p, "error");
        return;
    }
    p->waiting = 1;
}

void peers_start_call(npf_peer *p)
{
    npf_node *n = p->ps->n;
    uint8_t pub[32];
    int pinned;
    if (p->call || p->waiting || p->finished)
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
            if (npf_node_request(n, "grant_get", data, grant_got, p) == 0) {
                p->waiting = 1;
            } else {
                again(p, "error");
            }
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
    p->call = npf_call_start(n, p->number, pinned && !p->password[0] ? NULL : p->password, pinned ? pub : NULL);
    if (!p->call)
        again(p, "error");
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

/* end the session without the done callback and close the listeners */
static void peer_drop(npf_peer *p)
{
    npf_call *c = p->call;
    p->finished = 1;                        /* no done callback */
    p->call = NULL;                         /* the state callback does not find it */
    npf_timer_stop(p->ps->n->loop, &p->t_retry);
    if (p->rs)
        npf_resolve_cancel(p->rs);
    p->rs = NULL;
    if (p->waiting || p->renewing)
        npf_node_cancel_requests(p->ps->n, p);
    p->waiting = p->renewing = 0;
    npf_timer_stop(p->ps->n->loop, &p->t_demand);
    npf_timer_stop(p->ps->n->loop, &p->t_ready);
    peers_demand_drop(p, "closed");
    if (c)
        npf_call_end(c, "closed");
    peers_listeners_close(p);
}

/* what is left of a removed peer: anything a callback started on it after
 * the removal goes too */
static void peer_free_now(npf_peer *p)
{
    int i;
    npf_timer_stop(p->ps->n->loop, &p->t_free);
    peer_drop(p);                           /* its waiting queues emptied and freed too */
    for (i = 0; i < p->nfwd; i++) {
        npf_timer_cancel(p->ps->n->loop, p->fwds[i]->t_accept);
        free(p->fwds[i]->acl);
        npf_wipe_free(p->fwds[i], sizeof *p->fwds[i]);
    }
    free(p->resources);
    npf_wipe_free(p, sizeof *p);
}

static void peer_free_later(npf_loop *loop, void *arg)
{
    npf_peer *p = arg, **pp;
    (void)loop;
    p->t_free = NULL;
    for (pp = &p->ps->gone; *pp; pp = &(*pp)->gone_next)
        if (*pp == p) {
            *pp = p->gone_next;
            break;
        }
    peer_free_now(p);
}

/* the session ends (peer_drop); freed on the next turn, never at once: the
 * application may remove a peer from any callback (npf.h), its own done and
 * forward events too, and the code that called out still holds the peer and
 * its forwards (accept_cb, demand_wait, the loops over the forwards and the
 * peers). That code stops at p->removed; a removed peer tells nothing more
 * (fwd_changed, finish) and its stale next still leads through the list */
void npf_peers_remove(npf_peers *ps, npf_peer *p)
{
    npf_peer **pp;
    int k;
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
    p->removed = 1;
    p->gone_next = ps->gone;
    ps->gone = p;
    p->t_free = npf_timer_add(ps->n->loop, 0, peer_free_later, p);    /* none (no memory): with the peers */
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
    while ((p = ps->gone) != NULL) {
        ps->gone = p->gone_next;
        peer_free_now(p);
    }
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
    free(ps->conns);
    free(ps->ips);
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
        if (p->direct && !p->removed)
            npf_peer_start(p);
}

void npf_peer_start(npf_peer *p)
{
    int online = p->ps->n->online;          /* offline: the login starts it (a direct peer needs none) */
    if (p->direct || (online && !p->idle_ms)) {
        if (!p->t_retry)
            peers_start_call(p);
    } else if (online && !p->listening) {
        peers_forwards_start(p);            /* on demand: listening; a connection starts the session */
    }
}

void npf_peers_on_login(npf_peers *ps)
{
    npf_peer *p;
    int waiting = 0;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        waiting += !p->idle_ms && !p->direct && !p->t_retry && !p->call && !p->waiting && !p->finished;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->removed)
            continue;                       /* in a callback of the peer before it */
        if (p->idle_ms) {                   /* on demand: listening; a connection starts the session */
            if (!p->listening)
                peers_forwards_start(p);
            if ((p->npend || p->nuq) && !p->call && !p->waiting)
                peers_start_call(p);
            continue;
        }
        if (p->direct || p->t_retry)
            continue;
        if (waiting > 1 && !p->call && !p->waiting && !p->finished && !ps->n->th.no_spread) {
            /* many peers: spread the calls (and their punching); tests that
             * need concurrent punches turn it off (NPF_TEST_NO_SPREAD) */
            int d = (int)npf_rand_range(0, LOGIN_SPREAD_MS);
            snprintf(p->last_why, sizeof p->last_why, "starting");
            p->retry_at = npf_mono_ms() + d;
            p->t_retry = npf_timer_add(ps->n->loop, d, retry_cb, p);
        } else {
            peers_start_call(p);
        }
    }
}

int npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (p->call == c)
            break;
    if (!p)
        return 0;
    if (st == NPF_CALL_ESTABLISHED) {
        npf_log("%s: connected (%s)", p->name, npf_call_path_label(c));
        p->up_since = npf_mono_ms();
        peers_forwards_start(p);        /* a mapping that fails retries on its own */
        if (p->removed)
            return 1;                   /* in a forward event */
        peers_ready(p);                 /* the connections that waited for it, now or once it can take them */
        {                               /* and those of the modules' forwards */
            int k;
            for (k = 0; k < p->ps->nkinds; k++)
                if (p->ps->kinds[k].k->kick)
                    p->ps->kinds[k].k->kick(p->ps->kinds[k].arg);
        }
        if (p->idle_ms)
            peers_demand_timer(p);
        if (p->ps->cbs.up)
            p->ps->cbs.up(p, c, p->ps->arg);
    } else if (st == NPF_CALL_CLOSED) {
        npf_log("%s: session closed (%s)", p->name, why ? why : "");
        p->call = NULL;
        peers_subs_call_gone(p->ps, c);
        if (why && strcmp(why, "auth_failed") == 0 && p->password[0] && !p->up_since) {
            /* the device refused the password: not tried again (each try counts
             * against it there, security.md 8.3); the user gives it anew */
            npf_logw("%s: the password was not accepted: give it again (-p)", p->name);
            npf_wipe(p->password, sizeof p->password);
            why = "wrong_password";
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
        p->call_pinned = 0;
        peers_forwards_session_gone(p);
        if (p->removed)
            return 1;
        if (p->up_since && npf_mono_ms() - p->up_since >= STABLE_MS)
            p->backoff = 0;             /* it was up long enough: start from 1 s again */
        p->up_since = 0;
        if (strcmp(why ? why : "", "wrong_password") == 0 || strcmp(why ? why : "", "pairing_lost") == 0) {
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

/* what a session that ended for why waits for: NPF_NEED_*, 0 nothing */
static int why_needs(const char *why)
{
    return strcmp(why, "not_paired") == 0       ? NPF_NEED_PASSWORD
           : strcmp(why, "wrong_password") == 0 ? NPF_NEED_PASSWORD | NPF_NEED_PASSWORD_WRONG
           : strcmp(why, "pairing_lost") == 0   ? NPF_NEED_PASSWORD | NPF_NEED_PAIRING_LOST
           : strcmp(why, "no_account") == 0     ? NPF_NEED_ACCOUNT
                                                : 0;
}

int npf_peer_needs(const npf_peer *p)
{
    return p->call || p->password[0] ? 0 : why_needs(p->last_why);
}

int npf_peer_state(const npf_peer *p, int *needs, int *retry_in_ms)
{
    int nd = npf_peer_needs(p), st;
    if (retry_in_ms)
        *retry_in_ms = 0;
    if (p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED)
        st = NPF_PEER_CONNECTED;
    else if (p->call || p->waiting)
        st = NPF_PEER_CONNECTING;
    else if (p->finished)
        st = NPF_PEER_ENDED;
    else if (p->idle_ms)
        st = NPF_PEER_IDLE;
    else if (p->t_retry && strcmp(p->last_why, "starting") != 0) {
        int64_t ms = p->retry_at - npf_mono_ms();
        st = NPF_PEER_RETRY;
        if (retry_in_ms)
            *retry_in_ms = ms > 0 ? (int)ms : 0;
    } else
        st = NPF_PEER_WAITING;
    if (needs)
        *needs = st == NPF_PEER_CONNECTED || st == NPF_PEER_CONNECTING ? 0 : nd;
    return st;
}

void npf_peer_connect_put(npf_peer *p, int connect, int idle_ms, int running)
{
    int busy = p->call || p->waiting;
    p->connect = connect;
    p->idle_ms = 0;                         /* idle_req stays: the time asked for on demand */
    if (connect == NPF_CONNECT_ON_DEMAND) {
        npf_peer_idle_put(p, idle_ms);
        p->idle_since = 0;                  /* the idle time runs from now */
        /* no reconnecting: a connection starts the next one */
        npf_timer_stop(p->ps->n->loop, &p->t_retry);
        if (!p->listening)
            peers_forwards_start(p);        /* listening now, the session when a connection comes */
        if (p->call)
            peers_demand_timer(p);
    } else if (connect == NPF_CONNECT_KEEP) {
        if (p->finished)
            unfinish(p);
        if (running && !busy && !p->t_retry)
            peers_start_call(p);            /* no session: one now (a direct one too) */
    } else if (!busy) {                     /* ONCE, no session to end first: ended now */
        npf_timer_stop(p->ps->n->loop, &p->t_retry);
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
    if (why_needs(p->last_why))
        p->last_why[0] = 0;
    npf_log("%s: password given", p->name);
    npf_peer_wake_now(p);
    return 0;
}

void npf_peer_wake_now(npf_peer *p)
{
    if (p->call || p->waiting || (!p->finished && !p->idle_ms && !p->t_retry))
        return;
    npf_log("%s: %s", p->name, p->finished ? "trying again" : p->idle_ms ? "woken: starting the session" : "retrying now");
    if (p->finished)
        unfinish(p);
    peers_kick(p);
}

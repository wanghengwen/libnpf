/* The node's spare allocation on the relay of the server it is logged in to
 * (home-binding.md v0.5, 9, 16.1): an ordinary relay allocation no call has
 * yet, asked for after welcome (home_open) and bound from the main socket
 * with the binder of the calls' allocations (relay_bind.c), so the mapping
 * the relay sees is the one punching and calls use. The keepalive is the
 * relay's: after T of silence from the node it pings, the node answers at
 * once (an outbound datagram: it keeps the mapping whatever the NAT does
 * with inbound ones); the relay learns T. The node only binds, answers,
 * tells whether its main socket sent elsewhere meanwhile, and watches:
 * nothing from the relay by its last datagram + T + the relay's tries + a
 * margin, and it binds again. A call takes the spare as its allocation,
 * bound already (node_home_adopt); the platform sends the next one
 * (relay_spare), and one every hour (a fresh hint and key). The spare
 * outlives the signaling connection (U6): a login to the same server takes
 * it back (resume). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/platform.h"
#include "npf/siv.h"

#include "home.h"
#include "node_internal.h"

#define HOME_DOG_MARGIN  5000       /* the watchdog's margin past T and the relay's tries */
#define HOME_TIME_WINDOW 60000      /* a ping's srv_time_ms within this of the node's server time */
#define HOME_NEXT_MS     30000      /* taken by a call: home_open if no relay_spare came by then */
#define HOME_PREV_MS     30000      /* relay_spare{taken} before the call's relay: the taken one kept this long */

enum { H_OFF, H_OPENING, H_BINDING, H_BOUND, H_LOST, H_BACKOFF, H_TAKEN };
static const char *const k_state[] = {"off", "opening", "binding", "bound", "lost", "binding", "taken"};

struct npf_home {
    npf_node     *n;
    int           state;
    int           has;                      /* a spare (r) */
    int           server;                   /* the server it is on */
    relay_c       r;                        /* the spare and its binding (relay_bind.c) */
    relay_c       prev;                     /* the one a call took, while the call's relay may still come */
    int           has_prev, prev_bound;
    int64_t       prev_at;
    struct sockaddr_in R;                   /* where the relay sees us */
    int           haveR;
    int64_t       last_rx;                  /* npf_mono_ms: the last datagram from the relay */
    int64_t       ping_mark;                /* the last ping answered (or the binding): "elsewhere since" */
    int64_t       srv_seen;                 /* srv_time_ms of the newest ping taken */
    int           t_s, learn;               /* the relay's T and learning */
    int64_t       rtt;
    int           newnet;                   /* tell the relay the network changed, until it answers */
    int           backoff;
    int           opening;                  /* a home_open waits for its answer */
    npf_timer    *t_dog, *t_retry;
    int64_t       bound_ms, since;          /* mono, Unix s: bound first */
    uint64_t      keepalives, moved, drops, taken; /* pings answered, R changes, watchdog rebinds, calls */
    npf_udp_watch w;
    int           watch_fd;
};

static void bind_start(struct npf_home *h, int from_lost);
static void home_open_send(struct npf_home *h);

static void tstop(npf_loop *l, npf_timer **t)
{
    if (*t)
        npf_timer_cancel(l, *t);
    *t = NULL;
}

static const char *addr4(const struct sockaddr_in *a, char *b, size_t n)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, a, sizeof *a);
    return npf_addr_str(&ss, b, n);
}

static const struct sockaddr_in *cur4(const struct npf_home *h)
{
    return (const struct sockaddr_in *)&h->r.addr[h->r.cur];
}

static int same4(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

const char *home_learn_str(int learn)
{
    return learn == RELAY_LEARNED ? "learned" : learn == RELAY_UNSTABLE ? "unstable" : "learning";
}

/* may this node have a spare (9.1): a UDP socket of its own, an account or a node's identity */
static int home_allowed(const npf_node *n)
{
    return !n->cfg.home_off && !n->cfg.offline && !n->cfg.udp_on_demand && !n->cfg.hosted_service
           && !n->cfg.hosted_exec && n->udp_fd >= 0 && (n->cfg.callable || n->account_id) && !getenv("NPF_NO_HOME");
}

/* the main socket's sends watched (again, after a reopen) toward the relay
 * in use: what may keep the mapping the relay sees, by the NAT's mapping */
static void watch_sync(struct npf_home *h)
{
    npf_node *n = h->n;
    if (h->watch_fd != n->udp_fd) {
        npf_udp_watch_on(h->watch_fd, NULL);
        npf_udp_watch_on(n->udp_fd, &h->w);
        h->watch_fd = n->udp_fd;
    }
    if (h->r.naddr) {
        h->w.relay_ip = cur4(h)->sin_addr.s_addr;
        h->w.relay_port = cur4(h)->sin_port;
    }
    /* EIM (or not known): anything else keeps it; ADM: the relay's IP; APDM: nothing else */
    h->w.mode = !n->nat_valid || !n->nat_udp ? NPF_WATCH_ANY
                : n->nat.mapping == NPF_MAP_APDM ? NPF_WATCH_NONE
                : n->nat.mapping == NPF_MAP_ADM  ? NPF_WATCH_IP
                                                 : NPF_WATCH_ANY;
}

/* a RELAY_BIND; flags RELAY_F_PONG: the answer to ping_id */
static void bind_send(struct npf_home *h, int flags, uint32_t ping_id)
{
    npf_node *n = h->n;
    uint8_t wire[256];
    char a[64];
    int len;
    if (n->udp_fd < 0 || !h->has
        || (n->test_block_relay && call_relay_blocked(n, npf_addr_str(&h->r.addr[h->r.cur], a, sizeof a))))
        return;
    watch_sync(h);
    if (h->newnet)
        flags |= RELAY_F_NEWNET;
    if ((len = relay_bind_pack(&h->r, n, flags, ping_id, wire)) > 0)
        (void)npf_udp_send(n->udp_fd, wire, (size_t)len, cur4(h));
}

/* ---- the watchdog ---- */

static void dog_timer(npf_loop *loop, void *arg);

/* nothing from the relay by this: bind again */
static int64_t dog_deadline(const struct npf_home *h)
{
    int64_t last = h->r.last_tx > h->last_rx ? h->r.last_tx : h->last_rx;
    return last + (int64_t)(h->t_s > 0 ? h->t_s : 25) * 1000 + HOME_RETRY_MS + HOME_DOG_MARGIN;
}

static void dog_arm(struct npf_home *h, int64_t now)
{
    int64_t d = dog_deadline(h) - now;
    tstop(h->n->loop, &h->t_dog);
    h->t_dog = npf_timer_add(h->n->loop, d > 0 ? d : 0, dog_timer, h);
}

/* 1: it bound again */
static int dog_check(struct npf_home *h, int64_t now)
{
    if (h->state != H_BOUND)
        return 0;
    if (now < dog_deadline(h)) {            /* the node sent since: later */
        dog_arm(h, now);
        return 0;
    }
    h->drops++;
    npf_log("home: nothing from the relay for %lld s (its interval %d s): binding again",
            (long long)(now - (h->last_rx > h->bound_ms ? h->last_rx : h->bound_ms)) / 1000, h->t_s);
    bind_start(h, 1);
    return 1;
}

static void dog_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_dog = NULL;
    dog_check(h, npf_mono_ms());
}

/* ---- binding (data-channel.md 9.2): every address in turn, 700 ms apart, 3 each ---- */

static void retry_timer(npf_loop *loop, void *arg);

static void bind_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    static const int again_s[] = {5, 20, 60, 180};
    (void)loop;
    h->r.t_bind = NULL;
    if (h->state != H_BINDING && h->state != H_LOST)
        return;
    if (relay_bind_next(&h->r) < 0) {
        h->r.cur = h->r.tries = 0;
        npf_log("home: the relay does not answer: binding again in %d s", again_s[h->backoff]);
        if (h->state == H_LOST && h->n->online)
            home_open_send(h);              /* does the server still have it (resume)? a new one if not */
        h->state = H_BACKOFF;
        h->t_retry = npf_timer_add(h->n->loop, again_s[h->backoff] * 1000, retry_timer, h);
        if (h->backoff < 3)
            h->backoff++;
        return;
    }
    bind_send(h, 0, 0);
    h->r.t_bind = npf_timer_add(h->n->loop, RELAY_BIND_MS, bind_timer, h);
}

static void retry_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_retry = NULL;
    if (h->state == H_BACKOFF && h->has)
        bind_start(h, 0);
    else if ((h->state == H_OFF || h->state == H_TAKEN) && h->n->online)
        home_open_send(h);
}

static void bind_start(struct npf_home *h, int from_lost)
{
    npf_loop *l = h->n->loop;
    tstop(l, &h->r.t_bind);
    tstop(l, &h->t_dog);
    h->state = from_lost ? H_LOST : H_BINDING;
    h->r.bound = 0;
    h->r.cur = h->r.tries = 0;
    bind_send(h, 0, 0);
    h->r.t_bind = npf_timer_add(l, RELAY_BIND_MS, bind_timer, h);
}

/* ---- the platform ---- */

/* a spare (home_open, relay_spare): bound from the first of the relay's addresses */
static void home_take(struct npf_home *h, const uint8_t id[8], const uint8_t key[32],
                      const struct sockaddr_storage *addr, int naddr)
{
    npf_loop *l = h->n->loop;
    tstop(l, &h->t_dog);
    tstop(l, &h->t_retry);
    relay_bind_take(&h->r, h->n, id, key, addr, naddr);
    h->r.active = 1;
    h->has = 1;
    h->server = h->n->server_id;
    h->backoff = 0;
    h->srv_seen = 0;
    h->bound_ms = 0;
    bind_start(h, 0);
}

/* a spare's relay object (signaling.md "relay"): 0, or -1 no use */
static int spare_parse(const npf_json *j, int r, uint8_t id[8], uint8_t key[32], struct sockaddr_storage *addr,
                       int *naddr)
{
    int arr = npf_json_get(j, r, "udp"), i;
    char mode[8] = "";
    *naddr = 0;
    npf_json_get_str(j, r, "mode", mode, sizeof mode);
    if (strcmp(mode, "udp") != 0 || npf_json_get_b64(j, r, "relay_id", id, 8) != 8
        || npf_json_get_b64(j, r, "alloc_key", key, 32) != 32)
        return -1;
    for (i = 0; arr >= 0 && i < j->tok[arr].size && *naddr < 4; i++) {
        char a[80];
        if (npf_json_str(j, npf_json_item(j, arr, i), a, sizeof a) > 0 && npf_addr_parse(a, &addr[*naddr]) == 0
            && addr[*naddr].ss_family == AF_INET)
            (*naddr)++;
    }
    return *naddr ? 0 : -1;
}

/* the relay object at j[r] taken as the spare; 0, or -1 */
static int spare_take(struct npf_home *h, const npf_json *j, int r)
{
    uint8_t id[8], key[32];
    struct sockaddr_storage addr[4];
    int naddr, ok = spare_parse(j, r, id, key, addr, &naddr);
    if (ok == 0)
        home_take(h, id, key, addr, naddr);
    npf_wipe(key, sizeof key);
    return ok;
}

static void open_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    struct npf_home *h = arg;
    uint8_t id[8];
    int resumed = 0, d;
    char err[32] = "";
    h->opening = 0;
    if (!j)
        return;                             /* the connection went: the next login asks again */
    if (!ok) {
        npf_json_get_str(j, 0, "error", err, sizeof err);
        npf_log("home: home_open refused (%s)%s", err, h->has ? ": the spare kept" : "");
        if (!h->has) {
            h->state = H_OFF;
            tstop(n->loop, &h->t_retry);
            h->t_retry = npf_timer_add(n->loop, strcmp(err, "rate_limited") == 0 ? 60000 : 300000, retry_timer, h);
        }
        return;
    }
    d = npf_json_get(j, 0, "data");
    npf_json_bool(j, npf_json_get(j, d, "resumed"), &resumed);
    if (resumed) {
        if (h->has && npf_json_get_b64(j, d, "relay_id", id, 8) == 8 && memcmp(id, h->r.relay_id, 8) == 0) {
            npf_log("home: spare resumed (server %d)", n->server_id);
            h->server = n->server_id;
            if (h->state == H_BACKOFF) {
                tstop(n->loop, &h->t_retry);
                bind_start(h, 0);
            }
        }
        return;
    }
    if (spare_take(h, j, npf_json_get(j, d, "relay")) == 0)
        npf_logd("home: a spare allocation (server %d)", n->server_id);
}

static void home_open_send(struct npf_home *h)
{
    npf_node *n = h->n;
    char data[64] = "{}";
    if (h->opening || !n->online)
        return;
    if (h->has && h->server == n->server_id) {
        char b[16];
        npf_b64url_encode(h->r.relay_id, 8, b);
        b[11] = 0;
        snprintf(data, sizeof data, "{\"resume\":\"%s\"}", b);
    } else if (!h->has) {
        h->state = H_OPENING;
    }
    if (npf_node_request(n, "home_open", data, open_reply, h) == 0)
        h->opening = 1;
}

static struct npf_home *home_new(npf_node *n)
{
    struct npf_home *h = n->home;
    if (h || !(h = calloc(1, sizeof *h)))
        return h;
    h->n = n;
    h->watch_fd = -1;
    n->home = h;
    return h;
}

int node_home_test_take(npf_node *n, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_in *relay)
{
    struct npf_home *h = home_new(n);
    struct sockaddr_storage ss;
    if (!h)
        return -1;
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, relay, sizeof *relay);
    home_take(h, id, key, &ss, 1);
    return 0;
}

int node_home_state(const npf_node *n)
{
    return n->home ? n->home->state : 0;
}

int node_home_test_dog(npf_node *n, int64_t now_ms)
{
    return n->home ? dog_check(n->home, now_ms) : 0;
}

void node_home_login(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!home_allowed(n)) {
        if (h && n->cfg.home_off)
            node_home_stop(n);
        return;
    }
    if (!(h = home_new(n)))
        return;
    if (h->has && h->server != n->server_id) {
        /* another server now: its spare is no use here, a new one; the old
         * one idles out there */
        npf_log("home: on server %d now: a new spare there (the one on server %d left)", n->server_id, h->server);
        tstop(n->loop, &h->t_dog);
        tstop(n->loop, &h->r.t_bind);
        h->has = 0;
        h->state = H_OFF;
    }
    tstop(n->loop, &h->t_retry);
    home_open_send(h);
}

void node_home_sig_lost(npf_node *n)
{
    if (n->home)
        n->home->opening = 0;
}

void node_home_net_change(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || !h->has)
        return;
    h->newnet = 1;                          /* another network: the relay learns again */
    if (h->state == H_BOUND) {
        bind_send(h, 0, 0);                 /* at once: a new address binds within a round trip */
        dog_arm(h, npf_mono_ms());
    } else if (h->state == H_BACKOFF || h->state == H_LOST) {
        tstop(n->loop, &h->t_retry);
        bind_start(h, h->state == H_LOST);
    }
}

/* the spare given up here (closed, taken, replaced): no more of its timers */
static void spare_drop(struct npf_home *h, int state)
{
    npf_loop *l = h->n->loop;
    tstop(l, &h->t_dog);
    tstop(l, &h->r.t_bind);
    tstop(l, &h->t_retry);
    h->has = 0;
    h->r.active = h->r.bound = 0;
    h->state = state;
}

void node_home_close(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || !h->has)
        return;
    if (n->online) {                        /* best effort: else it idles out (330 s at most) */
        char data[48], b[16];
        npf_b64url_encode(h->r.relay_id, 8, b);
        b[11] = 0;
        snprintf(data, sizeof data, "{\"relay_id\":\"%s\"}", b);
        npf_node_send(n, "home_close", 0, data);
    }
    spare_drop(h, H_OFF);
}

void node_home_stop(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h)
        return;
    node_home_close(n);
    tstop(n->loop, &h->t_retry);
    npf_node_cancel_requests(n, h);
    npf_udp_watch_on(h->watch_fd, NULL);
    npf_wipe(&h->r, sizeof h->r);
    npf_wipe(&h->prev, sizeof h->prev);
    free(h);
    n->home = NULL;
}

/* src's binding (the cookie, kseq, the address in use) into the call's dst */
static void binding_give(relay_c *dst, const relay_c *src, int bound)
{
    npf_timer *t = dst->t_bind;
    int64_t expires = dst->expires;
    uint32_t seq = dst->seq;
    char mode[8];
    memcpy(mode, dst->mode, sizeof mode);
    *dst = *src;
    dst->bound = bound;
    dst->t_bind = t;
    dst->expires = expires;
    dst->seq = seq;
    memcpy(dst->mode, mode, sizeof mode);
}

int node_home_adopt(npf_node *n, const uint8_t id[8], relay_c *dst)
{
    struct npf_home *h = n->home;
    if (!h)
        return 0;
    if (h->has_prev && memcmp(id, h->prev.relay_id, 8) == 0 && npf_mono_ms() - h->prev_at < HOME_PREV_MS) {
        /* its replacement came first (relay_spare{taken}): the one taken kept for this */
        binding_give(dst, &h->prev, h->prev_bound);
        h->has_prev = 0;
        npf_wipe(&h->prev, sizeof h->prev);
        h->taken++;
        return 1;
    }
    if (!h->has || memcmp(id, h->r.relay_id, 8) != 0)
        return 0;
    binding_give(dst, &h->r, h->state == H_BOUND);
    h->taken++;
    npf_logd("home: the spare taken by a call: the next one from the platform");
    spare_drop(h, H_TAKEN);
    h->t_retry = npf_timer_add(n->loop, HOME_NEXT_MS, retry_timer, h);
    return 1;
}

void node_home_spare(npf_node *n, const npf_json *j, int d)
{
    struct npf_home *h = n->home;
    char why[16] = "";
    if (!h)                                 /* sent only to a node that asked for a spare */
        return;
    npf_json_get_str(j, d, "why", why, sizeof why);
    if (strcmp(why, "taken") == 0 && h->has) {
        /* the one a call took, its relay (the reply, incoming) still to
         * come: kept for node_home_adopt, its timers the new one's */
        h->prev = h->r;
        h->prev.t_bind = NULL;
        h->prev_bound = h->state == H_BOUND;
        h->prev_at = npf_mono_ms();
        h->has_prev = 1;
    }
    if (spare_take(h, j, npf_json_get(j, d, "relay")) == 0)
        npf_log("home: another spare allocation (%s)", why[0] ? why : "?");
}

/* ---- what comes from the relay ---- */

/* the address the relay sees (R): a change is told (P2 takes it up as the srflx) */
static void r_seen(struct npf_home *h, const struct sockaddr_in *a)
{
    char x[64], y[64];
    if (h->haveR && !same4(a, &h->R)) {
        npf_log("home: the relay sees %s now (was %s)", addr4(a, x, sizeof x), addr4(&h->R, y, sizeof y));
        h->moved++;
    }
    h->R = *a;
    h->haveR = 1;
}

/* the relay's interval and learning, said when they change */
static void learn_seen(struct npf_home *h, int t_s, int learn)
{
    if (t_s < 1 || t_s > 600)
        return;
    if (t_s != h->t_s || learn != h->learn)
        npf_log("home: the relay pings after %d s of silence (%s)", t_s, home_learn_str(learn));
    h->t_s = t_s;
    h->learn = learn;
}

/* a RELAY_BIND_ACK of ours (relay_bind_ack): R; bound now, or a challenge answered */
static void ack_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    npf_node *n = h->n;
    relay_ack a;
    int64_t now = npf_mono_ms();
    char x[64], y[64];
    if (!relay_bind_ack(&h->r, n, plain, pl, &a) || a.rtt < 0)
        return;                             /* not an answer to one of ours (a replay, a stale one) */
    h->rtt = a.rtt;
    h->last_rx = now;
    r_seen(h, &a.addr);
    if (a.state != RELAY_ACK_BOUND) {
        /* a challenge: this address is not the spare's (yet); its cookie at once */
        if (relay_bind_echo_due(&h->r))
            bind_send(h, 0, 0);
        return;
    }
    /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that binds, as a call's (call_relay.c) */
    if (getenv("NPF_TEST_DROP_BIND_ACK"))
        return;
    h->newnet = 0;
    learn_seen(h, a.t_s, a.learn);
    if (h->state != H_BOUND) {
        int first = !h->bound_ms;
        tstop(n->loop, &h->r.t_bind);
        h->state = H_BOUND;
        h->r.bound = 1;
        h->bound_ms = now;
        h->ping_mark = now;
        h->backoff = 0;
        watch_sync(h);
        if (first) {
            h->since = npf_unix_ms() / 1000;
            npf_log("home: spare bound via %s (%s), the relay pings after %d s of silence",
                    addr4(cur4(h), x, sizeof x), addr4(&h->R, y, sizeof y), h->t_s);
        } else {
            npf_log("home: spare bound again via %s (%s)", addr4(cur4(h), x, sizeof x), addr4(&h->R, y, sizeof y));
        }
    }
    dog_arm(h, now);
}

/* a RELAY_PING: answered at once (that is the keepalive) */
static void ping_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    size_t blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    relay_ping p;
    int64_t now = npf_mono_ms(), d;
    int flags = RELAY_F_PONG;
    if (pl < NPF_PKT_HDR_SIZE || NPF_PKT_HDR_SIZE + blen > pl
        || relay_ping_parse(plain + NPF_PKT_HDR_SIZE, blen, &p) < 0)
        return;
    /* newer than any taken, of about now: a replayed one is not answered */
    d = p.srv_ms - npf_node_time(h->n);
    if (p.srv_ms <= h->srv_seen || d > HOME_TIME_WINDOW || d < -HOME_TIME_WINDOW)
        return;
    h->srv_seen = p.srv_ms;
    h->last_rx = now;
    r_seen(h, &p.addr);
    learn_seen(h, p.t_s, p.learn);
    watch_sync(h);
    if (h->w.other > h->ping_mark)
        flags |= RELAY_F_OTHER;             /* this silence says nothing of the mapping alone */
    h->ping_mark = now;
    h->keepalives++;
    bind_send(h, flags, p.ping_id);
    if (h->state == H_BOUND)
        dog_arm(h, now);
}

int node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    struct npf_home *h = n->home;
    uint8_t plain[2048];
    int pl;
    if (!h || !h->has || fd != n->udp_fd || from->ss_family != AF_INET || len < 12 + 20)
        return 0;
    if ((pl = relay_bind_open(&h->r, buf, len, from, plain)) <= 0)
        return pl == 0;
    if (plain[0] == PKT_RELAY_BIND_ACK)
        ack_in(h, plain, (size_t)pl);
    else if (plain[0] == PKT_RELAY_PING)
        ping_in(h, plain, (size_t)pl);
    return 1;
}

/* ---- what it says ---- */

size_t npf_node_home_json(npf_node *n, char *buf, size_t cap)
{
    struct npf_home *h = n->home;
    npf_jw w;
    char a[64];
    int r;
    if (!h)
        return 0;
    npf_jw_init(&w, buf, cap);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "state", k_state[h->state]);
    if (h->has) {
        npf_jw_kint(&w, "server", h->server);
        npf_jw_kstr(&w, "relay", addr4(cur4(h), a, sizeof a));
    }
    if (h->haveR)
        npf_jw_kstr(&w, "addr", addr4(&h->R, a, sizeof a));
    npf_jw_kint(&w, "iv_s", h->t_s);
    npf_jw_kstr(&w, "learn", home_learn_str(h->learn));
    npf_jw_kint(&w, "last_ping_ms", h->keepalives ? npf_mono_ms() - h->ping_mark : -1);
    npf_jw_kint(&w, "rtt_ms", h->rtt);
    npf_jw_kint(&w, "moved", (int64_t)h->moved);
    npf_jw_kint(&w, "drops", (int64_t)h->drops);
    npf_jw_kint(&w, "keepalives", (int64_t)h->keepalives);
    npf_jw_kint(&w, "taken", (int64_t)h->taken);
    npf_jw_kint(&w, "since", h->since);
    npf_jw_end(&w);
    r = npf_jw_finish(&w);
    return r > 0 ? (size_t)r : 0;
}

void npf_node_home_text(npf_node *n, char *buf, size_t cap)
{
    struct npf_home *h = n->home;
    char a[64];
    buf[0] = 0;
    if (!h)
        return;
    if (h->state != H_BOUND) {
        snprintf(buf, cap, "%s", k_state[h->state]);
        return;
    }
    snprintf(buf, cap, "spare bound via %s, the relay pings after %d s of silence (%s)", addr4(cur4(h), a, sizeof a),
             h->t_s, home_learn_str(h->learn));
}

/* The persistent binding on the relay of the server the node is logged in
 * to (home-binding.md v0.4, 9, 16.1): home_open after welcome, HOME_BIND
 * from the main socket (the mapping the relay sees is the one punching
 * uses). The keepalive is the relay's: after T of silence from the node it
 * pings, the node answers at once (an outbound datagram: it keeps the
 * mapping whatever the NAT does with inbound ones); the relay learns T. The
 * node only binds, answers, tells whether its main socket sent elsewhere
 * meanwhile, and watches: nothing from the relay by its last datagram + T +
 * the relay's tries + a margin, and it binds again. The binding outlives
 * the signaling connection (U6): a login to the same server takes it back
 * (resume). The calls keep their per-call allocations for now (P1). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/natprobe.h"
#include "npf/platform.h"
#include "npf/siv.h"

#include "home.h"
#include "node_internal.h"

#define HOME_SENT        8          /* the last HOME_BINDs whose HOME_ACK is taken */
#define HOME_ACK_AGE_MS  10000
#define HOME_BIND_MS     700        /* binding: a HOME_BIND every 700 ms, 3 to an address */
#define HOME_BIND_TRIES  3
#define HOME_DOG_MARGIN  5000       /* the watchdog's margin past T and the relay's tries */
#define HOME_TIME_WINDOW 60000      /* a ping's srv_time_ms within this of the node's server time */

enum { H_OFF, H_OPENING, H_BINDING, H_BOUND, H_LOST, H_BACKOFF };
static const char *const k_state[] = {"off", "opening", "binding", "bound", "lost", "binding"};

struct npf_home {
    npf_node     *n;
    int           state;
    int           has;                      /* a binding (id, key) */
    int           server;                   /* the server it is on */
    uint8_t       id[8];
    npf_siv_keys  keys;
    struct sockaddr_in relay[4];
    int           nrelay, cur, tries;
    uint64_t      kseq;
    struct {
        uint8_t  txid[NPF_TXID_SIZE];
        uint32_t ts;
        uint64_t kseq;
        int64_t  at;
    } sent[HOME_SENT];
    int           nsent;
    uint8_t       cookie[8];
    int64_t       echo_ms;                  /* the last challenge answered */
    struct sockaddr_in R;                   /* where the relay sees us */
    int           haveR;
    int64_t       last_tx, last_rx;         /* npf_mono_ms: the last datagram to / from the relay */
    int64_t       ping_mark;                /* the last ping answered (or the binding): "elsewhere since" */
    int64_t       srv_seen;                 /* srv_time_ms of the newest ping taken */
    int           t_s, learn;               /* the relay's T and learning */
    int64_t       rtt;
    int           newnet;                   /* tell the relay the network changed, until it answers */
    int           backoff;
    int           opening;                  /* a home_open waits for its answer */
    npf_timer    *t_dog, *t_bind, *t_retry;
    int64_t       bound_ms, since;          /* mono, Unix s: bound first */
    uint64_t      keepalives, moved, drops; /* pings answered, R changes, watchdog rebinds (this binding) */
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

static int same4(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

/* ---- the packets ---- */

static void st64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

void home_bind_body(uint8_t out[HOME_BIND_BODY], const uint8_t cookie[8], uint64_t kseq, int flags, uint32_t ping_id)
{
    memcpy(out, cookie, 8);
    st64(out + 8, kseq);
    out[16] = (uint8_t)flags;
    npf_le32(out + 17, ping_id);
}

/* family(1) | port(2) | addr(4): IPv4 only; the bytes after it, or NULL */
static const uint8_t *addr_parse(const uint8_t *b, size_t len, struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    if (len < 7 || b[0] != 4)
        return NULL;
    a->sin_family = AF_INET;
    a->sin_port = htons((uint16_t)(b[1] | b[2] << 8));
    memcpy(&a->sin_addr, b + 3, 4);
    return b + 7;
}

int home_ack_parse(const uint8_t *b, size_t len, home_ack *a)
{
    const uint8_t *p;
    memset(a, 0, sizeof *a);
    if (!(p = addr_parse(b, len, &a->addr)) || len < 7 + 8 + 1 + 8 + 8 + 1 + 3)
        return -1;
    a->srv_ms = (int64_t)npf_rd64(p);
    a->state = p[8];
    memcpy(a->cookie, p + 9, 8);
    a->kseq = npf_rd64(p + 17);
    a->flags = p[25];
    a->t_s = p[26] | p[27] << 8;
    a->learn = p[28];
    return 0;
}

int home_ping_parse(const uint8_t *b, size_t len, home_ping *q)
{
    const uint8_t *p;
    memset(q, 0, sizeof *q);
    if (!(p = addr_parse(b, len, &q->addr)) || len < 7 + 8 + 4 + 2 + 1 + 1)
        return -1;
    q->srv_ms = (int64_t)npf_rd64(p);
    q->ping_id = npf_rd32(p + 8);
    q->t_s = p[12] | p[13] << 8;
    q->learn = p[14];
    q->try_n = p[15];
    return 0;
}

const char *home_learn_str(int learn)
{
    return learn == HOME_LEARNED ? "learned" : learn == HOME_UNSTABLE ? "unstable" : "learning";
}

/* may this node bind (9.1): a UDP socket of its own, an account or a node's identity */
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
    if (h->nrelay) {
        h->w.relay_ip = h->relay[h->cur].sin_addr.s_addr;
        h->w.relay_port = h->relay[h->cur].sin_port;
    }
    /* EIM (or not known): anything else keeps it; ADM: the relay's IP; APDM: nothing else */
    h->w.mode = !n->nat_valid || !n->nat_udp ? NPF_WATCH_ANY
                : n->nat.mapping == NPF_MAP_APDM ? NPF_WATCH_NONE
                : n->nat.mapping == NPF_MAP_ADM  ? NPF_WATCH_IP
                                                 : NPF_WATCH_ANY;
}

/* ---- sending ---- */

/* a HOME_BIND; flags HOME_F_PONG: the answer to ping_id (shorter: not padded to 96) */
static void bind_send(struct npf_home *h, int flags, uint32_t ping_id)
{
    npf_node *n = h->n;
    uint8_t wire[256], body[HOME_BIND_BODY], txid[NPF_TXID_SIZE];
    size_t len = flags & HOME_F_PONG ? npf_rand_range(72, NPF_BIND_REQ_MIN)
                                     : npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
    uint32_t ts = (uint32_t)npf_node_time(n);
    int k = h->nsent++ % HOME_SENT, r;
    if (n->udp_fd < 0 || !h->has || !h->nrelay)
        return;
    watch_sync(h);
    if (h->newnet)
        flags |= HOME_F_NEWNET;
    npf_random(txid, sizeof txid);
    h->kseq++;
    memcpy(h->sent[k].txid, txid, sizeof txid);
    h->sent[k].ts = ts;
    h->sent[k].kseq = h->kseq;
    h->sent[k].at = h->last_tx = npf_mono_ms();
    home_bind_body(body, h->cookie, h->kseq, flags, ping_id);
    memcpy(wire, h->id, 4);
    r = npf_pkt_seal(&h->keys, NPF_DIR_REQ, PKT_HOME_BIND, txid, ts, body, sizeof body, len - 4, wire + 4);
    if (r > 0)
        (void)npf_udp_send(n->udp_fd, wire, (size_t)r + 4, &h->relay[h->cur]);
}

/* ---- the watchdog ---- */

static void dog_timer(npf_loop *loop, void *arg);

/* nothing from the relay by this: bind again */
static int64_t dog_deadline(const struct npf_home *h)
{
    int64_t last = h->last_tx > h->last_rx ? h->last_tx : h->last_rx;
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

/* ---- binding (9.2): every address in turn, 700 ms apart, 3 each ---- */

static void retry_timer(npf_loop *loop, void *arg);

static void bind_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    static const int again_s[] = {5, 20, 60, 180};
    (void)loop;
    h->t_bind = NULL;
    if (h->state != H_BINDING && h->state != H_LOST)
        return;
    if (++h->tries > HOME_BIND_TRIES) {
        h->tries = 0;
        if (++h->cur >= h->nrelay) {
            h->cur = 0;
            npf_log("home: the relay does not answer: binding again in %d s", again_s[h->backoff]);
            if (h->state == H_LOST && h->n->online)
                home_open_send(h);          /* does the server still have it (resume)? a new one if not */
            h->state = H_BACKOFF;
            h->t_retry = npf_timer_add(h->n->loop, again_s[h->backoff] * 1000, retry_timer, h);
            if (h->backoff < 3)
                h->backoff++;
            return;
        }
    }
    bind_send(h, 0, 0);
    h->t_bind = npf_timer_add(h->n->loop, HOME_BIND_MS, bind_timer, h);
}

static void retry_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_retry = NULL;
    if (h->state == H_BACKOFF && h->has)
        bind_start(h, 0);
    else if (h->state == H_OFF && h->n->online)
        home_open_send(h);
}

static void bind_start(struct npf_home *h, int from_lost)
{
    npf_loop *l = h->n->loop;
    tstop(l, &h->t_bind);
    tstop(l, &h->t_dog);
    h->state = from_lost ? H_LOST : H_BINDING;
    h->cur = 0;
    h->tries = 0;
    bind_send(h, 0, 0);
    h->t_bind = npf_timer_add(l, HOME_BIND_MS, bind_timer, h);
}

/* ---- the platform ---- */

/* a new binding: bound from the first of the relay's addresses */
static void home_take(struct npf_home *h, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_in *addr,
                      int naddr)
{
    npf_loop *l = h->n->loop;
    tstop(l, &h->t_dog);
    tstop(l, &h->t_retry);
    memcpy(h->id, id, 8);
    npf_siv_derive(&h->keys, key, LABEL_HOME);
    memcpy(h->relay, addr, (size_t)naddr * sizeof addr[0]);
    h->nrelay = naddr;
    h->has = 1;
    h->server = h->n->server_id;
    h->kseq = 0;
    h->nsent = 0;
    memset(h->sent, 0, sizeof h->sent);
    memset(h->cookie, 0, sizeof h->cookie);
    h->backoff = 0;
    h->srv_seen = 0;
    h->t_s = 0;
    h->learn = HOME_LEARNING;
    h->bound_ms = 0;
    h->keepalives = h->moved = h->drops = 0;
    h->newnet = 0;                          /* a new binding learns from the start anyway */
    bind_start(h, 0);
}

static void open_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    struct npf_home *h = arg;
    uint8_t id[8], key[32];
    int resumed = 0, arr, i, naddr = 0, d;
    struct sockaddr_in addr[4];
    char err[32] = "";
    h->opening = 0;
    if (!j)
        return;                             /* the connection went: the next login asks again */
    if (!ok) {
        npf_json_get_str(j, 0, "error", err, sizeof err);
        npf_log("home: home_open refused (%s)%s", err, h->has ? ": the binding kept" : "");
        if (!h->has) {
            h->state = H_OFF;
            tstop(n->loop, &h->t_retry);
            h->t_retry = npf_timer_add(n->loop, strcmp(err, "rate_limited") == 0 ? 60000 : 300000, retry_timer, h);
        }
        return;
    }
    d = npf_json_get(j, 0, "data");
    npf_json_bool(j, npf_json_get(j, d, "resumed"), &resumed);
    if (npf_json_get_b64(j, d, "bind_id", id, 8) != 8)
        return;
    arr = npf_json_get(j, d, "udp");
    for (i = 0; arr >= 0 && i < j->tok[arr].size && naddr < 4; i++) {
        char a[80];
        struct sockaddr_storage ss;
        if (npf_json_str(j, npf_json_item(j, arr, i), a, sizeof a) > 0 && npf_addr_parse(a, &ss) == 0
            && ss.ss_family == AF_INET)
            memcpy(&addr[naddr++], &ss, sizeof addr[0]);
    }
    if (resumed && h->has && memcmp(id, h->id, 8) == 0) {
        npf_log("home: binding resumed (server %d)", n->server_id);
        h->server = n->server_id;
        if (h->state == H_BACKOFF) {
            tstop(n->loop, &h->t_retry);
            bind_start(h, 0);
        }
        return;
    }
    if (resumed || npf_json_get_b64(j, d, "bind_key", key, 32) != 32 || !naddr)
        return;
    home_take(h, id, key, addr, naddr);
    npf_wipe(key, sizeof key);
}

static void home_open_send(struct npf_home *h)
{
    npf_node *n = h->n;
    char data[64] = "{}";
    if (h->opening || !n->online)
        return;
    if (h->has && h->server == n->server_id) {
        char b[16];
        npf_b64url_encode(h->id, 8, b);
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
    if (!h)
        return -1;
    home_take(h, id, key, relay, 1);
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
        /* another server now: its binding is no use (no session on it,
         * P1), a new one here; the old one idles out there */
        npf_log("home: on server %d now: a new binding there (the one on server %d left)", n->server_id, h->server);
        tstop(n->loop, &h->t_dog);
        tstop(n->loop, &h->t_bind);
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

void node_home_close(npf_node *n)
{
    struct npf_home *h = n->home;
    npf_loop *l = n->loop;
    if (!h || !h->has)
        return;
    if (n->online) {                        /* best effort: else it idles out (330 s at most) */
        char data[48], b[16];
        npf_b64url_encode(h->id, 8, b);
        b[11] = 0;
        snprintf(data, sizeof data, "{\"bind_id\":\"%s\"}", b);
        npf_node_send(n, "home_close", 0, data);
    }
    tstop(l, &h->t_dog);
    tstop(l, &h->t_bind);
    tstop(l, &h->t_retry);
    h->has = 0;
    h->state = H_OFF;
}

void node_home_stop(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h)
        return;
    node_home_close(n);
    npf_node_cancel_requests(n, h);
    npf_udp_watch_on(h->watch_fd, NULL);
    npf_wipe(&h->keys, sizeof h->keys);
    free(h);
    n->home = NULL;
}

void node_home_rekey(npf_node *n, const npf_json *j, int d)
{
    struct npf_home *h = n->home;
    uint8_t id[8], nid[8], key[32];
    if (!h || !h->has || npf_json_get_b64(j, d, "bind_id", id, 8) != 8 || memcmp(id, h->id, 8) != 0
        || npf_json_get_b64(j, d, "new_id", nid, 8) != 8 || npf_json_get_b64(j, d, "bind_key", key, 32) != 32)
        return;
    memcpy(h->id, nid, 8);
    npf_siv_derive(&h->keys, key, LABEL_HOME);
    npf_wipe(key, sizeof key);
    npf_logd("home: new hint and key");
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

/* a HOME_ACK of ours: R, the cookie; bound now, or a challenge answered */
static void ack_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    npf_node *n = h->n;
    const uint8_t *txid = plain + 4;
    uint32_t ts = npf_rd32(plain + 4 + NPF_TXID_SIZE);
    size_t blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    home_ack a;
    int i, k = -1;
    int64_t now = npf_mono_ms();
    char x[64], y[64];
    if (NPF_PKT_HDR_SIZE + blen > pl || home_ack_parse(plain + NPF_PKT_HDR_SIZE, blen, &a) < 0)
        return;
    for (i = 0; i < HOME_SENT; i++)
        if (h->sent[i].at && now - h->sent[i].at <= HOME_ACK_AGE_MS && h->sent[i].ts == ts
            && h->sent[i].kseq == a.kseq && npf_ct_eq(h->sent[i].txid, txid, NPF_TXID_SIZE) == 0) {
            k = i;
            break;
        }
    if (k < 0)
        return;                             /* not an answer to one of ours (a replay, a stale one) */
    h->rtt = now - h->sent[k].at;
    h->sent[k].at = 0;
    h->last_rx = now;
    memcpy(h->cookie, a.cookie, 8);
    r_seen(h, &a.addr);
    if (a.state != 1) {
        /* a challenge: this address is not the binding's (yet); its cookie at once */
        if (now - h->echo_ms >= 200) {
            h->echo_ms = now;
            bind_send(h, 0, 0);
        }
        return;
    }
    h->newnet = 0;
    learn_seen(h, a.t_s, a.learn);
    if (h->state != H_BOUND) {
        int first = !h->bound_ms;
        tstop(n->loop, &h->t_bind);
        h->state = H_BOUND;
        h->bound_ms = now;
        h->ping_mark = now;
        h->backoff = 0;
        watch_sync(h);
        if (first) {
            h->since = npf_unix_ms() / 1000;
            npf_log("home: bound via %s (%s), the relay pings after %d s of silence", addr4(&h->relay[h->cur], x,
                    sizeof x), addr4(&h->R, y, sizeof y), h->t_s);
        } else {
            npf_log("home: bound again via %s (%s)", addr4(&h->relay[h->cur], x, sizeof x), addr4(&h->R, y, sizeof y));
        }
    }
    dog_arm(h, now);
}

/* a HOME_PING: answered at once (that is the keepalive) */
static void ping_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    size_t blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    home_ping p;
    int64_t now = npf_mono_ms(), d;
    int flags = HOME_F_PONG;
    if (NPF_PKT_HDR_SIZE + blen > pl || home_ping_parse(plain + NPF_PKT_HDR_SIZE, blen, &p) < 0 || !h->has)
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
        flags |= HOME_F_OTHER;              /* this silence says nothing of the mapping alone */
    h->ping_mark = now;
    h->keepalives++;
    bind_send(h, flags, p.ping_id);
    if (h->state == H_BOUND)
        dog_arm(h, now);
}

int node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    struct npf_home *h = n->home;
    uint8_t plain[512];
    int i, pl;
    if (!h || !h->has || fd != n->udp_fd || from->ss_family != AF_INET || len > sizeof plain || len < 12 + 20)
        return 0;
    for (i = 0; i < h->nrelay && !same4((const struct sockaddr_in *)from, &h->relay[i]); i++)
        ;
    if (i == h->nrelay)
        return 0;
    if ((pl = npf_siv_open(&h->keys, NPF_DIR_RESP, buf, len, plain)) < NPF_PKT_HDR_SIZE)
        return 0;
    if (i != h->cur) {
        if (h->state == H_BOUND)
            return 1;                       /* an address given up on, late */
        h->cur = i;
    }
    if (plain[0] == PKT_HOME_ACK)
        ack_in(h, plain, (size_t)pl);
    else if (plain[0] == PKT_HOME_PING)
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
        if (h->nrelay)
            npf_jw_kstr(&w, "relay", addr4(&h->relay[h->cur], a, sizeof a));
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
    snprintf(buf, cap, "bound via %s, the relay pings after %d s of silence (%s)", addr4(&h->relay[h->cur], a, sizeof a),
             h->t_s, home_learn_str(h->learn));
}

/* The persistent binding on the relay of the server the node is logged in
 * to (home-binding.md 9, 16.1): home_open after welcome, HOME_BIND from the
 * main socket (the mapping the relay sees is the one punching uses), kept
 * alive at the interval the learner found for this network, measured with
 * the relay's echo (HOME_PING) while the main socket is quiet enough (5.4).
 * The binding outlives the signaling connection (U6): a login to the same
 * server takes it back (resume). The calls keep their per-call allocations
 * for now (P1): nothing here touches a call. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#define HOME_RESP_MS     1500       /* a keepalive's answer waited for this long, then it goes again */
#define HOME_LOST_AFTER  3          /* keepalives unanswered: the binding is lost */
#define HOME_BIND_MS     700        /* binding: a HOME_BIND every 700 ms, 3 to an address */
#define HOME_BIND_TRIES  3
#define HOME_ECHO_WAIT   3000       /* the echo waited for T + this */
#define HOME_VERDICT_MS  10000      /* a move once learned: the signaling's fate waited for this long */
#define HOME_MOVED_KEEP  16

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
    int64_t       last_ack, rtt, bound_ms;
    int           unanswered;
    int64_t       last_tx;                  /* the last HOME_BIND sent */
    int           move_seen;                /* an answer showed another address, not taken up yet */
    int           backoff;
    int           opening;                  /* a home_open waits for its answer */
    npf_timer    *t_ka, *t_resp, *t_bind, *t_retry, *t_verdict;
    /* the step being measured: 1 its keepalive went, the echo awaited;
     * 2 none came, the keepalive that tells went */
    int           measuring;
    hl_step       step;
    int           step_k;                   /* its keepalive's sent[] slot (the pings echo its txid) */
    int           step_resent;
    int64_t       step_at;
    int           step_cls;
    struct sockaddr_in step_R;              /* R when the step began */
    npf_udp_watch w;
    int           watch_fd;
    hl_state      L;
    uint64_t      net;
    int           net_known, net_check;
    int64_t       sig_lost_ms, net_event_ms;
    int64_t       moved[HOME_MOVED_KEEP];   /* Unix s of the moves seen */
    int           nmoved;
    int64_t       moved_ms;                 /* a move once learned waits for its verdict */
    uint32_t      moved_ip;
    int           moved_track;
    uint64_t      keepalives;
};

static void home_next(struct npf_home *h, int due);
static void bind_start(struct npf_home *h, int from_lost);
static void home_open_send(struct npf_home *h);

static void tstop(npf_loop *l, npf_timer **t)
{
    if (*t)
        npf_timer_cancel(l, *t);
    *t = NULL;
}

static int64_t now_s(void) { return npf_unix_ms() / 1000; }

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

static const char *net_hex(const struct npf_home *h, char *b, size_t n)
{
    snprintf(b, n, "%08llx", (unsigned long long)(h->net >> 32));
    return b;
}

/* may this node bind (9.1): a UDP socket of its own, an account or a node's identity */
static int home_allowed(const npf_node *n)
{
    return !n->cfg.home_off && !n->cfg.offline && !n->cfg.udp_on_demand && !n->cfg.hosted_service
           && !n->cfg.hosted_exec && n->udp_fd >= 0 && (n->cfg.callable || n->account_id) && !getenv("NPF_NO_HOME");
}

/* the main socket's sends counted (again, after a reopen) toward the relay in use */
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
}

/* the track the main socket is on: an EIM one sending elsewhere within the
 * last 15 s is busy; the others have one track */
static int track_now(const struct npf_home *h)
{
    int64_t now = npf_mono_ms(), last = h->w.last_other > h->w.last_relay_ip ? h->w.last_other : h->w.last_relay_ip;
    if (h->L.map == NPF_MAP_ADM || h->L.map == NPF_MAP_APDM)
        return HL_QUIET;
    return last && now - last <= HL_BUSY_GAP_MS + 1000 ? HL_BUSY : HL_QUIET;   /* as hl_classify */
}

static int iv_now(const struct npf_home *h) { return hl_iv(&h->L, track_now(h)); }

/* ---- what the learning keeps and tells ---- */

static int persist_eq(const hl_state *a, const hl_state *b)
{
    return a->map == b->map && memcmp(a->tr, b->tr, sizeof a->tr) == 0 && a->refresh == b->refresh
           && a->preserve == b->preserve && a->per_flow == b->per_flow && a->mapped == b->mapped
           && memcmp(a->drops, b->drops, sizeof a->drops) == 0;
}

/* the learning changed: home.json, the platform (nat.home) */
static void learn_changed(struct npf_home *h, const hl_state *was)
{
    if (persist_eq(was, &h->L))
        return;
    if (h->net_known && h->n->cfg.home_store && home_store_save(h->n->cfg.home_store, h->net, &h->L, now_s()) < 0)
        npf_logd("home: %s not written", h->n->cfg.home_store);
    npf_node_report_nat(h->n);
}

/* the network the node is on (5.7): its record, or learning from the start */
static void net_switch(struct npf_home *h)
{
    npf_node *n = h->n;
    char k[24];
    int64_t used = 0;
    uint64_t key = home_net_now(h->R.sin_addr.s_addr, 0);
    int map = n->nat_valid && n->nat_udp ? n->nat.mapping : NPF_MAP_UNKNOWN;
    h->net_check = 0;
    if (h->net_known && key == h->net)
        return;
    h->net = key;
    h->net_known = 1;
    hl_init(&h->L, map, n->cfg.home_iv_max > 0 ? n->cfg.home_iv_max : 150, n->cfg.home_learn_off);
    if (n->cfg.home_store && home_store_load(n->cfg.home_store, key, &h->L, &used) == 0 && !n->cfg.home_learn_off) {
        const hl_track *q = &h->L.tr[HL_QUIET];
        char when[32] = "?";
        time_t t = (time_t)q->learned_at;
        struct tm tm;
#ifdef _WIN32
        if (q->learned_at && gmtime_s(&tm, &t) == 0)
#else
        if (q->learned_at && gmtime_r(&t, &tm))
#endif
            strftime(when, sizeof when, "%Y-%m-%d", &tm);
        if (map != NPF_MAP_UNKNOWN && h->L.map != map && h->L.map != NPF_MAP_UNKNOWN) {
            npf_log("home: network %s: the record says %s, the NAT is %s now: learning again", net_hex(h, k, sizeof k),
                    npf_nat_mapping_str(h->L.map), npf_nat_mapping_str(map));
            hl_init(&h->L, map, h->L.iv_max, 0);
        } else {
            int i;
            if (map != NPF_MAP_UNKNOWN)
                h->L.map = map;
            for (i = 0; i < 2; i++)         /* an old record: confirmed from its t_ok upward now */
                if (h->L.tr[i].phase == HL_LEARNED && now_s() - h->L.tr[i].learned_at > HL_STALE_S)
                    h->L.tr[i].up_at = 0;
            npf_log("home: interval %d s from the record of network %s (measured %s)", hl_iv(&h->L, HL_QUIET),
                    net_hex(h, k, sizeof k), when);
        }
    } else {
        npf_log("home: network %s: not measured yet, interval %d s", net_hex(h, k, sizeof k), hl_iv(&h->L, HL_QUIET));
    }
    {   /* the gateway maps the main socket's port, and that is what the relay sees (5.6) */
        struct sockaddr_storage pm;
        if (node_portmap_cand(n, &pm) && pm.ss_family == AF_INET && same4((struct sockaddr_in *)&pm, &h->R))
            hl_mapped(&h->L, now_s());
    }
}

/* the NAT profile came after the binding: the learning goes by its mapping */
static void map_sync(struct npf_home *h)
{
    npf_node *n = h->n;
    if (!n->nat_valid || !n->nat_udp || h->L.map == n->nat.mapping)
        return;
    if (h->L.map != NPF_MAP_UNKNOWN) {
        char k[24];
        hl_state was = h->L;
        npf_log("home: network %s: the NAT is %s now (was %s): learning again", net_hex(h, k, sizeof k),
                npf_nat_mapping_str(n->nat.mapping), npf_nat_mapping_str(h->L.map));
        hl_init(&h->L, n->nat.mapping, h->L.iv_max, h->L.off);
        learn_changed(h, &was);
        return;
    }
    h->L.map = n->nat.mapping;
}

static void moved_note(struct npf_home *h)
{
    memmove(h->moved, h->moved + 1, sizeof h->moved - sizeof h->moved[0]);
    h->moved[HOME_MOVED_KEEP - 1] = now_s();
    if (h->nmoved < HOME_MOVED_KEEP)
        h->nmoved++;
}

static int moved_24h(const struct npf_home *h)
{
    int i, c = 0;
    for (i = 0; i < HOME_MOVED_KEEP; i++)
        if (h->moved[i] && now_s() - h->moved[i] < 86400)
            c++;
    return c;
}

/* ---- sending ---- */

/* a HOME_BIND: probe_s the step's wait (0: a plain keepalive) */
static void bind_send(struct npf_home *h, int probe_s, int flags)
{
    npf_node *n = h->n;
    uint8_t wire[256], body[HOME_BIND_BODY], txid[NPF_TXID_SIZE];
    size_t len = flags & HOME_F_INBOUND ? HOME_INBOUND_LEN
                 : probe_s ? npf_rand_range(HOME_PROBE_LEN, NPF_BIND_REQ_MAX) : npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
    uint32_t ts = (uint32_t)npf_node_time(n);
    int k = h->nsent++ % HOME_SENT, r, iv = iv_now(h);
    if (n->udp_fd < 0 || !h->has || !h->nrelay)
        return;
    watch_sync(h);
    if (probe_s && iv < probe_s + 5)
        iv = probe_s + 5;                   /* the relay keeps the binding past the wait */
    npf_random(txid, sizeof txid);
    h->kseq++;
    memcpy(h->sent[k].txid, txid, sizeof txid);
    h->sent[k].ts = ts;
    h->sent[k].kseq = h->kseq;
    h->sent[k].at = npf_mono_ms();
    h->last_tx = h->sent[k].at;
    home_bind_body(body, h->cookie, h->kseq, iv, probe_s, flags);
    memcpy(wire, h->id, 4);
    r = npf_pkt_seal(&h->keys, NPF_DIR_REQ, PKT_HOME_BIND, txid, ts, body, sizeof body, len - 4, wire + 4);
    if (r > 0)
        (void)npf_udp_send(n->udp_fd, wire, (size_t)r + 4, &h->relay[h->cur]);
    if (probe_s) {
        h->step_k = k;
        h->step_at = h->sent[k].at;
        npf_udp_watch_mark(&h->w, h->step_at);
    }
}

static void resp_timer(npf_loop *loop, void *arg);
static void ka_timer(npf_loop *loop, void *arg);

/* a keepalive while bound: its answer awaited */
static void ka_send(struct npf_home *h, int probe_s, int flags)
{
    bind_send(h, probe_s, flags);
    tstop(h->n->loop, &h->t_resp);
    h->t_resp = npf_timer_add(h->n->loop, HOME_RESP_MS, resp_timer, h);
}

/* the step's end: what the learner makes of it, then (go_on) on with the next */
static void step_done(struct npf_home *h, int outcome, int go_on)
{
    npf_node *n = h->n;
    hl_state was = h->L;
    hl_step st = h->step;
    int cls = h->step_cls;
    char k[24], a[64], b[64];
    int iv;
    h->measuring = 0;
    tstop(n->loop, &h->t_ka);
    if (outcome != HL_VOID && cls < 0)
        outcome = HL_VOID;
    hl_done(&h->L, &st, outcome, cls, now_s(), npf_mono_ms());
    iv = hl_iv(&h->L, cls == HL_BUSY ? HL_BUSY : HL_QUIET);
    net_hex(h, k, sizeof k);
    if (st.inbound && outcome != HL_VOID) {
        npf_log("home: inbound datagrams %s the mapping (network %s)",
                h->L.refresh == HL_REFRESH_BOTH ? "refresh" : "do not refresh", k);
    } else if (outcome == HL_OK) {
        npf_log("home: the mapping lives %d s at least (%s)", st.T, cls == HL_BUSY ? "busy" : "quiet");
    } else if (outcome == HL_EXPIRED) {
        npf_log("home: the mapping expired within %d s (%s -> %s): interval %d s (network %s)", st.T,
                addr4(&h->step_R, a, sizeof a), addr4(&h->R, b, sizeof b), iv, k);
    } else if (outcome == HL_NOECHO) {
        if (h->L.tr[cls == HL_BUSY ? HL_BUSY : HL_QUIET].doubt == st.T)
            npf_log("home: no echo after %d s (port kept: expired and made again, or lost): trying %d s once more",
                    st.T, st.T);
        else
            npf_log("home: no echo after %d s again: the mapping expired (its port kept): interval %d s (network %s)",
                    st.T, iv, k);
    } else {
        npf_logd("home: the %d s step is void (the socket was not quiet, or the binding or the network changed)",
                 st.T);
    }
    if (h->L.per_flow && !was.per_flow)
        npf_log("home: busy: the mapping expired within %d s although the socket sent meanwhile (a per-flow NAT)",
                st.T);
    learn_changed(h, &was);
    if (go_on)
        home_next(h, 1);                    /* the next step at once (or a keepalive) */
}

/* a track learned now: said once */
static void say_learned(struct npf_home *h, const hl_state *was)
{
    char k[24];
    int i;
    for (i = 0; i < 2; i++)
        if (was->tr[i].phase != HL_LEARNED && h->L.tr[i].phase == HL_LEARNED)
            npf_log("home: learned on network %s: interval %d s (%s%s)", net_hex(h, k, sizeof k), hl_iv(&h->L, i),
                    i == HL_BUSY ? "busy" : "quiet", h->L.tr[i].unstable ? ", unstable" : "");
}

/* until the next look at the keepalive: the interval after the last
 * HOME_BIND, looked at again by the quiet interval at least (5.4: a busy
 * socket gone quiet keeps the mapping by the quiet one from its last
 * keepalive on) */
static int64_t ka_wait(const struct npf_home *h)
{
    int64_t due = h->last_tx + (int64_t)iv_now(h) * 1000 - npf_mono_ms(),
            look = (int64_t)hl_iv(&h->L, HL_QUIET) * 1000;
    if (due < 0)
        due = 0;
    return due < look ? due : look;
}

/* due: a HOME_BIND now, a step of the learning when one is due, else a
 * plain keepalive; then (and without due) the next look at it */
static void home_next(struct npf_home *h, int due)
{
    npf_node *n = h->n;
    hl_step st;
    hl_state was;
    tstop(n->loop, &h->t_ka);
    if (h->state != H_BOUND)
        return;
    map_sync(h);
    was = h->L;
    /* no step while the NAT is probed (its datagrams to the probe servers
     * would spoil it, the profile tells which rules it goes by) */
    if (due && h->net_known && !n->probe && !n->mapcheck && hl_next(&h->L, track_now(h), now_s(), npf_mono_ms(), &st)) {
        say_learned(h, &was);
        learn_changed(h, &was);
        h->measuring = 1;
        h->step = st;
        h->step_resent = 0;
        h->step_R = h->R;
        npf_logd("home: measuring %d s (%s%s)", st.T, st.track == HL_BUSY ? "busy" : "quiet",
                 st.inbound ? ", inbound test" : "");
        ka_send(h, st.T, st.inbound ? HOME_F_INBOUND : 0);
        h->t_ka = npf_timer_add(n->loop, (int64_t)st.T * 1000 + HOME_ECHO_WAIT, ka_timer, h);
        return;
    }
    say_learned(h, &was);
    learn_changed(h, &was);
    if (due)
        ka_send(h, 0, 0);
    h->t_ka = npf_timer_add(n->loop, ka_wait(h), ka_timer, h);
}

/* the interval is over (a plain keepalive due), or the step's echo did not come */
static void ka_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_ka = NULL;
    if (h->state != H_BOUND)
        return;
    if (h->measuring == 1) {
        /* no echo by T + 3 s: what the main socket did meanwhile, then a
         * keepalive tells whether the mapping moved */
        h->step_cls = hl_classify(h->L.map, &h->w, h->step_at, npf_mono_ms());
        h->measuring = 2;
        ka_send(h, 0, 0);
        return;
    }
    if (h->measuring == 2)
        return;                             /* the telling keepalive's answer is awaited (resp_timer) */
    if (npf_mono_ms() - h->last_tx < (int64_t)iv_now(h) * 1000 - 500) {
        h->t_ka = npf_timer_add(h->n->loop, ka_wait(h), ka_timer, h);   /* busy still: later */
        return;
    }
    home_next(h, 1);                        /* a step now, or the keepalive */
}

/* a keepalive unanswered: again, then the binding is lost */
static void resp_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_resp = NULL;
    if (h->state != H_BOUND)
        return;
    if (++h->unanswered >= HOME_LOST_AFTER) {
        npf_log("home: no answer to %d keepalives: binding again", HOME_LOST_AFTER);
        if (h->measuring)
            step_done(h, HL_VOID, 0);
        tstop(h->n->loop, &h->t_ka);
        bind_start(h, 1);
        return;
    }
    if (h->measuring == 1) {                /* the step's keepalive again: the wait starts over */
        h->step_resent++;
        ka_send(h, h->step.T, h->step.inbound ? HOME_F_INBOUND : 0);
        tstop(h->n->loop, &h->t_ka);
        h->t_ka = npf_timer_add(h->n->loop, (int64_t)h->step.T * 1000 + HOME_ECHO_WAIT, ka_timer, h);
        return;
    }
    ka_send(h, 0, 0);
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
            if (h->state == H_LOST && h->n->online) {
                npf_log("home: the relay does not answer: a new binding");
                h->has = 0;
                home_open_send(h);
                return;
            }
            npf_log("home: the relay does not answer: binding again in %d s", again_s[h->backoff]);
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
    tstop(l, &h->t_resp);
    tstop(l, &h->t_ka);
    h->state = from_lost ? H_LOST : H_BINDING;
    h->cur = 0;
    h->tries = 0;
    h->unanswered = 0;
    bind_send(h, 0, 0);
    h->t_bind = npf_timer_add(l, HOME_BIND_MS, bind_timer, h);
}

/* ---- the platform ---- */

/* a new binding: bound from the first of the relay's addresses */
static void home_take(struct npf_home *h, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_in *addr,
                      int naddr)
{
    tstop(h->n->loop, &h->t_ka);
    tstop(h->n->loop, &h->t_resp);
    tstop(h->n->loop, &h->t_retry);
    tstop(h->n->loop, &h->t_verdict);
    if (h->measuring) {
        h->measuring = 0;
        hl_done(&h->L, &h->step, HL_VOID, h->step_cls, now_s(), npf_mono_ms());
    }
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
    h->moved_ms = 0;
    bind_start(h, 0);
}

static void open_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    struct npf_home *h = arg;
    uint8_t id[8], key[32];
    int resumed = 0, arr, i, naddr = 0;
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
    {
        int d = npf_json_get(j, 0, "data");
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
    }
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
    h->step_cls = -1;
    hl_init(&h->L, NPF_MAP_UNKNOWN, n->cfg.home_iv_max > 0 ? n->cfg.home_iv_max : 150, n->cfg.home_learn_off);
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

void node_home_test_due(npf_node *n)
{
    if (n->home)
        home_next(n->home, 1);
}

int node_home_state(const npf_node *n, int *measuring_s)
{
    const struct npf_home *h = n->home;
    if (measuring_s)
        *measuring_s = h && h->measuring ? h->step.T : 0;
    return h ? h->state : 0;
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
        tstop(n->loop, &h->t_ka);
        tstop(n->loop, &h->t_resp);
        tstop(n->loop, &h->t_bind);
        if (h->measuring) {
            h->measuring = 0;
            hl_done(&h->L, &h->step, HL_VOID, -1, now_s(), npf_mono_ms());
        }
        h->has = 0;
        h->state = H_OFF;
    }
    tstop(n->loop, &h->t_retry);
    home_open_send(h);
}

void node_home_sig_lost(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h)
        return;
    h->sig_lost_ms = npf_mono_ms();
    h->opening = 0;
    if (h->measuring)                       /* a NAT restart takes the signaling too: no verdict */
        step_done(h, HL_VOID, 1);
}

void node_home_net_change(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || !h->has)
        return;
    h->net_event_ms = npf_mono_ms();
    h->net_check = 1;
    if (h->state == H_BOUND) {
        if (h->measuring) {
            h->measuring = 0;
            hl_done(&h->L, &h->step, HL_VOID, -1, now_s(), npf_mono_ms());
        }
        tstop(n->loop, &h->t_ka);
        ka_send(h, 0, 0);                   /* at once: a new address binds within a round trip */
        h->t_ka = npf_timer_add(n->loop, (int64_t)iv_now(h) * 1000, ka_timer, h);
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
    tstop(l, &h->t_ka);
    tstop(l, &h->t_resp);
    tstop(l, &h->t_bind);
    tstop(l, &h->t_retry);
    tstop(l, &h->t_verdict);
    h->has = 0;
    h->measuring = 0;
    h->state = H_OFF;
}

void node_home_stop(npf_node *n)
{
    struct npf_home *h = n->home;
    npf_loop *l = n->loop;
    if (!h)
        return;
    node_home_close(n);
    npf_node_cancel_requests(n, h);
    npf_udp_watch_on(h->watch_fd, NULL);
    tstop(l, &h->t_ka);
    tstop(l, &h->t_resp);
    tstop(l, &h->t_bind);
    tstop(l, &h->t_retry);
    tstop(l, &h->t_verdict);
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

/* a move once learned (5.7): with the signaling's fate in view, a network
 * event or the interval too long */
static void verdict_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    hl_state was = h->L;
    int64_t span = (int64_t)iv_now(h) * 1000 + 10000;
    int network, r;
    char k[24];
    (void)loop;
    h->t_verdict = NULL;
    network = (h->sig_lost_ms && h->sig_lost_ms >= h->moved_ms - span)
              || (h->net_event_ms && h->net_event_ms >= h->moved_ms - span - 20000)
              || h->moved_ip != h->R.sin_addr.s_addr;
    r = hl_moved(&h->L, h->moved_track, network, now_s());
    h->moved_ms = 0;
    net_hex(h, k, sizeof k);
    if (network)
        npf_log("home: the mapping moved with a network event (the signaling dropped, another public IP or a network "
                "change): the interval stays");
    else if (r == 2)
        npf_log("home: the third expiry within 24 h on network %s: learning again", k);
    else if (r == 1)
        npf_log("home: the mapping expired within the interval: %d s from now on (network %s)", iv_now(h), k);
    learn_changed(h, &was);
    if (r == 2)
        home_next(h, 0);
}

/* a HOME_ACK of ours: R, the cookie; bound now, or a challenge answered */
static void ack_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    npf_node *n = h->n;
    const uint8_t *txid = plain + 4;
    uint32_t ts = npf_rd32(plain + 4 + NPF_TXID_SIZE);
    size_t blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    home_ack a;
    int i, k = -1, moved, was_step;
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
    h->last_ack = now;
    h->unanswered = 0;
    tstop(n->loop, &h->t_resp);
    memcpy(h->cookie, a.cookie, 8);
    moved = h->haveR && !same4(&a.addr, &h->R);
    if (moved) {
        npf_log("home: the relay sees %s now (was %s)", addr4(&a.addr, x, sizeof x), addr4(&h->R, y, sizeof y));
        moved_note(h);
        h->move_seen = 1;
        if (h->R.sin_addr.s_addr != a.addr.sin_addr.s_addr)
            h->net_check = 1;
    }
    h->R = a.addr;
    h->haveR = 1;
    was_step = h->measuring && k == h->step_k;
    if (a.state != 1) {
        /* a challenge: this address is not the binding's (yet); its cookie at once */
        if (h->measuring == 2) {            /* the telling keepalive came from elsewhere: it expired */
            step_done(h, HL_EXPIRED, 0);    /* on once the new address is bound */
            h->move_seen = 0;
        } else if (h->measuring == 1 && was_step) {
            step_done(h, HL_VOID, 0);
            h->move_seen = 0;
        }
        if (now - h->echo_ms >= 200) {
            h->echo_ms = now;
            if (h->state == H_BOUND)
                ka_send(h, 0, 0);
            else
                bind_send(h, 0, 0);
        }
        return;
    }
    if (h->state != H_BOUND) {
        int first = !h->bound_ms;
        tstop(n->loop, &h->t_bind);
        h->state = H_BOUND;
        h->bound_ms = now;
        h->backoff = 0;
        watch_sync(h);
        if (h->net_check || !h->net_known)
            net_switch(h);
        if (first) {
            char k2[24];
            npf_log("home: bound via %s (%s), interval %d s (network %s)", addr4(&h->relay[h->cur], x, sizeof x),
                    addr4(&h->R, y, sizeof y), iv_now(h), net_hex(h, k2, sizeof k2));
        } else {
            npf_log("home: bound again via %s (%s)", addr4(&h->relay[h->cur], x, sizeof x), addr4(&h->R, y, sizeof y));
        }
        h->keepalives++;
        home_next(h, 0);
        return;
    }
    h->keepalives++;
    if (h->net_check)
        net_switch(h);
    if (h->measuring == 1 && was_step) {
        if (!(a.flags & HOME_A_PROBE_SET))
            step_done(h, HL_VOID, 1);       /* the relay set no echo (too short, not the bound address) */
        return;                             /* the echo is awaited (ka_timer) */
    }
    if (h->measuring == 2) {
        h->move_seen = 0;
        step_done(h, moved ? HL_EXPIRED : HL_NOECHO, 1);
        return;
    }
    if (h->measuring)
        return;
    if (h->move_seen && !h->moved_ms && h->L.tr[track_now(h)].phase == HL_LEARNED) {
        /* once learned, a move between keepalives: expired within the
         * interval, or a NAT restart: the signaling (asked now) tells */
        h->moved_ms = now;
        h->moved_ip = h->step_R.sin_addr.s_addr ? h->step_R.sin_addr.s_addr : a.addr.sin_addr.s_addr;
        h->moved_track = track_now(h);
        if (n->online)
            node_sig_probe(n);
        tstop(n->loop, &h->t_verdict);
        h->t_verdict = npf_timer_add(n->loop, HOME_VERDICT_MS, verdict_timer, h);
    }
    if (!h->move_seen)
        h->step_R = h->R;
    h->move_seen = 0;
    home_next(h, 0);
}

/* a HOME_PING: the step's echo */
static void ping_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    const uint8_t *txid = plain + 4;
    uint32_t ts = npf_rd32(plain + 4 + NPF_TXID_SIZE);
    size_t blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    int64_t srv;
    int probe, nn;
    if (h->measuring != 1 || NPF_PKT_HDR_SIZE + blen > pl
        || home_ping_parse(plain + NPF_PKT_HDR_SIZE, blen, &srv, &probe, &nn) < 0 || probe != h->step.T
        || h->sent[h->step_k].ts != ts || npf_ct_eq(h->sent[h->step_k].txid, txid, NPF_TXID_SIZE) != 0)
        return;
    if (nn == 0)
        return;                             /* the inbound test's halfway ping */
    h->step_cls = hl_classify(h->L.map, &h->w, h->step_at, npf_mono_ms());
    step_done(h, HL_OK, 1);
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

int node_home_reports(const npf_node *n)
{
    return n->home && n->home->net_known;
}

void node_home_write_nat(npf_node *n, npf_jw *w)
{
    struct npf_home *h = n->home;
    const hl_state *L;
    char k[24];
    if (!h || !h->net_known)
        return;
    L = &h->L;
    npf_jw_key(w, "home");
    npf_jw_obj(w);
    npf_jw_kstr(w, "map", npf_nat_mapping_str(L->map));
    npf_jw_kint(w, "iv_quiet", hl_iv(L, HL_QUIET));
    npf_jw_kint(w, "iv_busy", hl_iv(L, HL_BUSY));
    if (L->tr[HL_QUIET].t_ok)
        npf_jw_kint(w, "t_ok", L->tr[HL_QUIET].t_ok);
    if (L->tr[HL_QUIET].t_fail)
        npf_jw_kint(w, "t_fail", L->tr[HL_QUIET].t_fail);
    if (L->refresh != HL_REFRESH_NONE)
        npf_jw_kstr(w, "refresh", hl_refresh_str(L->refresh));
    if (L->preserve >= 0)
        npf_jw_kbool(w, "preserve", L->preserve);
    if (L->per_flow)
        npf_jw_kbool(w, "per_flow", 1);
    if (L->tr[HL_QUIET].unstable)
        npf_jw_kbool(w, "unstable", 1);
    npf_jw_kint(w, "moved_24h", moved_24h(h));
    npf_jw_kint(w, "drops_24h", hl_drops_24h(L, now_s()));
    snprintf(k, sizeof k, "%016llx", (unsigned long long)h->net);
    npf_jw_kstr(w, "net", k);
    npf_jw_end(w);
}

static void track_json(npf_jw *w, const char *k, const hl_state *L, int t)
{
    npf_jw_key(w, k);
    npf_jw_obj(w);
    npf_jw_kstr(w, "state", hl_phase_str(L->tr[t].phase));
    npf_jw_kint(w, "iv", hl_iv(L, t));
    if (L->tr[t].t_ok)
        npf_jw_kint(w, "t_ok", L->tr[t].t_ok);
    if (L->tr[t].t_fail)
        npf_jw_kint(w, "t_fail", L->tr[t].t_fail);
    npf_jw_end(w);
}

size_t npf_node_home_json(npf_node *n, char *buf, size_t cap)
{
    struct npf_home *h = n->home;
    npf_jw w;
    char a[64], k[24];
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
    npf_jw_kint(&w, "iv_s", iv_now(h));
    npf_jw_kstr(&w, "track", track_now(h) == HL_BUSY && h->L.map != NPF_MAP_APDM && h->L.map != NPF_MAP_ADM ? "busy"
                                                                                                      : "quiet");
    if (h->net_known) {
        const hl_state *L = &h->L;
        npf_jw_kstr(&w, "net", net_hex(h, k, sizeof k));
        npf_jw_key(&w, "learn");
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "state", L->off ? "off" : h->measuring ? "measuring" : hl_phase_str(L->tr[HL_QUIET].phase));
        if (h->measuring)
            npf_jw_kint(&w, "step_s", h->step.T);
        npf_jw_kstr(&w, "map", npf_nat_mapping_str(L->map));
        track_json(&w, "quiet", L, HL_QUIET);
        if (L->map == NPF_MAP_EIM || L->map == NPF_MAP_UNKNOWN)
            track_json(&w, "busy", L, HL_BUSY);
        npf_jw_kstr(&w, "refresh", L->refresh == HL_REFRESH_NONE ? "unknown" : hl_refresh_str(L->refresh));
        if (L->preserve >= 0)
            npf_jw_kbool(&w, "preserve", L->preserve);
        npf_jw_kbool(&w, "per_flow", L->per_flow);
        if (L->mapped)
            npf_jw_kbool(&w, "mapped", 1);
        if (L->tr[HL_QUIET].learned_at)
            npf_jw_kint(&w, "at", L->tr[HL_QUIET].learned_at);
        npf_jw_end(&w);
    }
    npf_jw_kint(&w, "last_ack_ms", h->last_ack ? npf_mono_ms() - h->last_ack : -1);
    npf_jw_kint(&w, "rtt_ms", h->rtt);
    npf_jw_kint(&w, "moved_24h", moved_24h(h));
    npf_jw_kint(&w, "drops_24h", hl_drops_24h(&h->L, now_s()));
    npf_jw_kint(&w, "keepalives", (int64_t)h->keepalives);
    npf_jw_kint(&w, "chans", 0);
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
    snprintf(buf, cap, "bound via %s, interval %d s%s%s", addr4(&h->relay[h->cur], a, sizeof a), iv_now(h),
             h->measuring ? ", measuring" : h->L.tr[HL_QUIET].phase == HL_LEARNED ? " (learned)" : "",
             h->L.tr[HL_QUIET].unstable ? ", unstable" : "");
}

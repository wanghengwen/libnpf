/* The node's spare allocation (home-binding.md v0.5, 9, 16.1): a relay
 * allocation no call has yet, asked for after welcome (home_open), bound
 * from the main socket with the calls' binder (relay_bind.c). The relay
 * pings after T of silence, the node answers at once and watches (nothing
 * from the relay by its last datagram + T + the relay's tries + a margin:
 * bind again). A call takes it bound (node_home_adopt), relay_spare brings
 * the next; it outlives the signaling connection (resume, U6). */
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

#define HOME_RETRY_MS    4500       /* the relay's tries of a ping: 3, 1.5 s apart */
#define HOME_DOG_MARGIN  5000       /* the watchdog's margin past T and the relay's tries */
#define HOME_TIME_WINDOW 60000      /* a ping's srv_time_ms within this of the node's server time */
#define HOME_NEXT_MS     30000      /* taken by a call: home_open if no relay_spare came by then */

/* The spare's states (architecture.md 3.4): with no spare OFF, OPENING,
 * TAKEN; with one its binder's (binding, lost: probing, bound, backoff:
 * given up). One deadline each (home_due) or an event awaited */
enum { H_OFF, H_OPENING, H_TAKEN };
static const char *const k_state[] = {"off", "opening", "taken", "binding", "lost", "bound", "backoff"};
#define H_STATE(h) ((h)->r.state ? 2 + (h)->r.state : (h)->state)

struct npf_home {
    npf_node     *n;
    int           state;                    /* no spare (r.state RB_NONE): H_* */
    int           server;                   /* the server it is on */
    relay_c       r;                        /* the spare and its binding (relay_bind.c) */
    struct sockaddr_storage R;              /* where the relay sees us */
    int64_t       last_rx;                  /* npf_mono_ms: the last datagram from the relay */
    int64_t       ping_mark;                /* the last ping answered (or the binding): "elsewhere since" */
    int64_t       srv_seen;                 /* srv_time_ms of the newest ping taken */
    int           t_s, learn;               /* the relay's T and learning */
    int64_t       rtt;
    int           newnet;                   /* tell the relay the network changed, until it answers */
    int           backoff;                  /* given up since last bound: BACKOFF's step; bound, the NAT measured again */
    int           opening;                  /* a home_open waits for its answer */
    int64_t       at;                       /* BACKOFF: bound again; OFF (refused), TAKEN: home_open (mono ms; 0 none) */
    npf_timer    *t_due;                    /* the one timer, at home_due */
    int64_t       bound_ms, since;          /* mono, Unix s: bound first */
    uint64_t      keepalives, moved, drops, taken; /* pings answered, R changes, watchdog rebinds, calls */
    npf_udp_watch w;
    int           watch_fd;
};

static void home_open_send(struct npf_home *h);
static void home_arm(struct npf_home *h);

#define CUR(h) (&(h)->r.addr[(h)->r.cur])     /* the relay's address in use */

static const char *learn_str(int learn)
{
    return learn == RELAY_LEARNED ? "learned" : learn == RELAY_UNSTABLE ? "unstable" : "learning";
}

/* may this node have a spare (9.1): a UDP socket of its own, an account or a
 * node's identity; not in tests without UDP (NPF_NO_UDP) or spares (NPF_NO_HOME) */
static int home_allowed(const npf_node *n)
{
    return !n->cfg.home_off && !n->cfg.offline && !n->cfg.udp_on_demand && !n->cfg.hosted_service
           && !n->cfg.hosted_exec && n->udp_fd >= 0 && (n->cfg.callable || n->account_id) && !n->test_no_udp
           && !getenv("NPF_NO_HOME");
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
    if (h->r.naddr) {           /* the binds' address (a probe from the one in use tries the others) */
        const struct sockaddr_in *a = (const void *)RELAY_BIND_DST(&h->r);
        h->w.relay_ip = a->sin_addr.s_addr;
        h->w.relay_port = a->sin_port;
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
    int len;
    if (n->udp_fd < 0 || !h->r.state || call_relay_addr_blocked(n, RELAY_BIND_DST(&h->r)))
        return;
    watch_sync(h);
    if (h->newnet)
        flags |= RELAY_F_NEWNET;
    if ((len = relay_bind_pack(&h->r, n, flags, ping_id, wire)) > 0)
        (void)npf_udp_send(n->udp_fd, wire, (size_t)len, RELAY_BIND_DST(&h->r));
}

/* ---- the spare's deadline ---- */

/* bound: nothing from the relay by this, bind again */
static int64_t dog_deadline(const struct npf_home *h)
{
    int64_t last = h->r.last_tx > h->last_rx ? h->r.last_tx : h->last_rx;
    return last + (int64_t)(h->t_s > 0 ? h->t_s : 25) * 1000 + HOME_RETRY_MS + HOME_DOG_MARGIN;
}

static int64_t home_due(const struct npf_home *h)
{
    int64_t at = h->r.state == RB_BOUND                               ? dog_deadline(h)
                 : h->r.state == RB_BINDING || h->r.state == RB_PROBING ? h->r.at
                                                                       : h->at;
    return at ? at : INT64_MAX;
}

/* a binding run from now (relay_bind_begin; probe: the watchdog's, from the
 * address in use, then the others in order, architecture.md Q2) */
static void bind_start(struct npf_home *h, int probe, int64_t now)
{
    h->at = 0;
    relay_bind_begin(&h->r, probe, now);
    bind_send(h, 0, 0);
}

/* every address tried: again later, sooner first. Each time the platform
 * is asked whether the spare is still there (home_open resume: kept, or a
 * new one): the relay reclaims a spare it does not hear from (at most
 * 330 s), and binding the old one again never ends (measured: a node's UDP
 * dropped 91 s, its spare resumed once while still dropped, then bound in
 * vain every 180 s for over an hour; the calls' allocations bound at once) */
static void gave_up(struct npf_home *h, int64_t now)
{
    static const int again_s[] = {5, 20, 60, 180};
    int s = again_s[h->backoff < 3 ? h->backoff : 3];
    h->backoff++;
    h->at = now + s * 1000;
    npf_log("home: the relay does not answer: binding again in %d s", s);
    if (h->n->online)
        home_open_send(h);                  /* does the server still have it (resume)? a new one if not */
}

/* what is due at now (architecture.md 3.4) */
static void home_tick(struct npf_home *h, int64_t now)
{
    int k;
    if (now < home_due(h))
        return;
    if (h->r.state == RB_BOUND) {
        h->drops++;
        npf_log("home: nothing from the relay for %lld s (its interval %d s): binding again",
                (long long)(now - (h->last_rx > h->bound_ms ? h->last_rx : h->bound_ms)) / 1000, h->t_s);
        bind_start(h, 1, now);
    } else if (h->r.state == RB_BINDING || h->r.state == RB_PROBING) {
        if ((k = relay_bind_tick(&h->r, now, 0)) < 0)
            gave_up(h, now);
        else if (k > 0)
            bind_send(h, 0, 0);
    } else {
        h->at = 0;
        if (h->r.state == RB_GAVE_UP)
            bind_start(h, 0, now);
        else if (h->n->online)
            home_open_send(h);              /* OFF after a refusal, TAKEN with no relay_spare */
    }
}

static void home_timer(npf_loop *loop, void *arg)
{
    struct npf_home *h = arg;
    (void)loop;
    h->t_due = NULL;
    home_tick(h, npf_mono_ms());
    home_arm(h);
}

/* the one timer at the deadline, after each event */
static void home_arm(struct npf_home *h)
{
    int64_t at = home_due(h), now = npf_mono_ms();
    npf_timer_stop(h->n->loop, &h->t_due);
    if (at != INT64_MAX)
        h->t_due = npf_timer_add(h->n->loop, at > now ? at - now : 0, home_timer, h);
}

/* ---- the platform ---- */

/* a relay allocation as the spare (home_open, relay_spare), bound from the
 * first of its addresses (after a loss: the NAT measured again once bound);
 * 0, or -1 */
static int spare_take(struct npf_home *h, const m_relay *r)
{
    if (!r->nudp || strcmp(r->mode, "udp") != 0)
        return -1;
    relay_bind_take(&h->r, h->n, r->relay_id, r->alloc_key, r->udp, r->nudp);
    h->at = 0;
    h->server = h->n->server_id;
    h->srv_seen = 0;
    h->bound_ms = 0;
    bind_send(h, 0, 0);
    home_arm(h);
    return 0;
}

/* {"key": "<relay_id>"} */
static const char *id_json(const struct npf_home *h, const char *key, char *out, size_t cap)
{
    char b[16];
    npf_b64url_encode(h->r.relay_id, 8, b);
    b[11] = 0;
    snprintf(out, cap, "{\"%s\":\"%s\"}", key, b);
    return out;
}

static void open_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    struct npf_home *h = arg;
    m_env e;
    m_home_open m;
    char err[96];
    h->opening = 0;
    if (!j || node_env(j, &e) < 0)
        return;                             /* the connection went: the next login asks again */
    if (!ok) {
        npf_log("home: home_open refused (%s)%s", e.error, h->r.state ? ": the spare kept" : "");
        if (!h->r.state) {
            h->state = H_OFF;
            h->at = npf_mono_ms() + (strcmp(e.error, "rate_limited") == 0 ? 60000 : 300000);
            home_arm(h);
        }
        return;
    }
    if (npf_msg_parse(&m_home_open_d, j, e.data, &m, err, sizeof err) < 0)
        npf_logw("home: home_open's reply refused (%s)", err);
    else if (m.resumed && h->r.state && m.relay_id_len && memcmp(m.relay_id, h->r.relay_id, 8) == 0) {
        npf_log("home: spare resumed (server %d)", n->server_id);
        h->server = n->server_id;           /* backing off: bound again at its deadline (D11) */
    } else if (!m.resumed && spare_take(h, &m.relay) == 0)
        npf_logd("home: a spare allocation (server %d)", n->server_id);
    npf_msg_wipe(&m_home_open_d, &m);
}

static void home_open_send(struct npf_home *h)
{
    npf_node *n = h->n;
    char data[64] = "{}";
    if (h->opening || !n->online)
        return;
    if (h->r.state && h->server == n->server_id)
        id_json(h, "resume", data, sizeof data);
    else if (!h->r.state)
        h->state = H_OPENING;
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

/* the spare given up here (closed, taken, replaced): state from now, its deadline at */
static void spare_drop(struct npf_home *h, int state, int64_t at)
{
    h->r.state = RB_NONE;
    h->state = state;
    h->at = at;
    home_arm(h);
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
    if (h->r.state && h->server != n->server_id) {
        /* another server now: its spare is no use here, a new one; the old
         * one idles out there */
        npf_log("home: on server %d now: a new spare there (the one on server %d left)", n->server_id, h->server);
        spare_drop(h, H_OFF, 0);
    }
    /* a spare backing off keeps its deadline: the reply to the resume may
     * never come, or home_open is refused with the spare kept (open_reply),
     * and it would back off for good */
    if (h->r.state != RB_GAVE_UP)
        h->at = 0;
    home_open_send(h);
    home_arm(h);
}

/* A spare backing off after the relay stopped answering waits up to 180 s
 * for its next try; once UDP is seen to work again it asks at once: the
 * platform resumes it (still there) or opens a new one (reclaimed) */
void node_home_udp_ok(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || h->r.state != RB_GAVE_UP || !n->online || h->opening)
        return;
    npf_log("home: UDP works again: binding the spare at once, asking whether it is still there");
    bind_start(h, 0, npf_mono_ms());        /* still there: it binds; reclaimed: the reply brings a new one */
    home_open_send(h);
    home_arm(h);
}

void node_home_net_change(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || !h->r.state)
        return;
    h->newnet = 1;                          /* another network: the relay learns again */
    if (h->r.state == RB_BOUND)
        bind_send(h, 0, 0);                 /* at once: a new address binds within a round trip */
    else if (h->r.state == RB_GAVE_UP || h->r.state == RB_PROBING)
        bind_start(h, h->r.state == RB_PROBING, npf_mono_ms());
    home_arm(h);
}

void node_home_close(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h || !h->r.state)
        return;
    if (n->online) {                        /* best effort: else it idles out (330 s at most) */
        char data[48];
        npf_node_send(n, "home_close", 0, id_json(h, "relay_id", data, sizeof data));
    }
    spare_drop(h, H_OFF, 0);
}

void node_home_stop(npf_node *n)
{
    struct npf_home *h = n->home;
    if (!h)
        return;
    node_home_close(n);
    npf_timer_stop(n->loop, &h->t_due);
    npf_node_cancel_requests(n, h);
    npf_udp_watch_on(h->watch_fd, NULL);
    npf_wipe(&h->r, sizeof h->r);
    free(h);
    n->home = NULL;
}

int node_home_adopt(npf_node *n, const uint8_t id[8], relay_c *dst)
{
    struct npf_home *h = n->home;
    if (!h || !h->r.state || memcmp(id, h->r.relay_id, 8) != 0)
        return 0;
    *dst = h->r;                            /* its binding: the cookie, kseq, the address in use, bound or not */
    h->taken++;
    npf_logd("home: the spare taken by a call: the next one from the platform");
    spare_drop(h, H_TAKEN, npf_mono_ms() + HOME_NEXT_MS);
    return 1;
}

void node_on_relay_spare(npf_node *n, const m_env *e, const void *msg)
{
    const m_relay_spare *m = msg;
    (void)e;
    if (n->home && spare_take(n->home, &m->relay) == 0)  /* sent only to a node that asked for a spare */
        npf_log("home: another spare allocation (%s)", m->why[0] ? m->why : "?");   /* taken: after the call's relay */
}

/* ---- what comes from the relay ---- */

/* the address the relay sees (R): logged and counted; the platform takes it
 * as this side's srflx itself (home-binding.md 6, U7 reversed) */
static void r_seen(struct npf_home *h, const struct sockaddr_storage *a)
{
    char x[64], y[64];
    if (h->R.ss_family && !npf_addr_eq(a, &h->R)) {
        npf_log("home: the relay sees %s now (was %s)", npf_addr_str(a, x, sizeof x), npf_addr_str(&h->R, y, sizeof y));
        h->moved++;
    }
    h->R = *a;
}

/* the relay's interval and learning, said when they change */
static void learn_seen(struct npf_home *h, int t_s, int learn)
{
    if (t_s < 1 || t_s > 600)
        return;
    if (t_s != h->t_s || learn != h->learn)
        npf_log("home: the relay pings after %d s of silence (%s)", t_s, learn_str(learn));
    h->t_s = t_s;
    h->learn = learn;
}

/* bound (a BIND_ACK "bound"): the watchdog counts from now on */
static void spare_bound(struct npf_home *h, int64_t now)
{
    npf_node *n = h->n;
    char x[64], y[64];
    if (!relay_bind_up(&h->r, now, 0))
        return;
    h->ping_mark = now;
    watch_sync(h);
    if (!h->bound_ms)
        h->since = npf_unix_ms() / 1000;
    npf_log("home: spare bound %svia %s (%s), the relay pings after %d s of silence", h->bound_ms ? "again " : "",
            npf_addr_str(CUR(h), x, sizeof x), npf_addr_str(&h->R, y, sizeof y), h->t_s);
    h->bound_ms = now;
    if (h->backoff) {
        /* UDP is back after the relay stopped answering: the NAT may have
         * mapped the socket anew meanwhile (its mappings expired), and the
         * srflx measured before would send the peers' probes to a port no
         * longer ours (measured: every round of the next calls failed until
         * the process restarted) */
        h->backoff = 0;
        if (!n->probe && n->udp_fd >= 0 && (!n->nat_ok_ms || now - n->nat_ok_ms > 10000)) {
            npf_log("home: the relay answers again: measuring the NAT again");
            node_nat_refresh(n);
        }
    }
}

/* a RELAY_BIND_ACK of ours (relay_bind_ack): R; bound now, or a challenge answered */
static void ack_in(struct npf_home *h, const uint8_t *plain, size_t pl)
{
    relay_ack a;
    int64_t now = npf_mono_ms();
    int k = relay_bind_ack(&h->r, h->n, plain, pl, &a);
    if (!k || a.rtt < 0)
        return;                             /* not an answer to one of ours (a replay, a stale one) */
    h->rtt = a.rtt;
    h->last_rx = now;
    r_seen(h, &a.addr);
    if (a.state != RELAY_ACK_BOUND) {
        if (k == 2)                         /* a challenge: this address is not the spare's (yet) */
            bind_send(h, 0, 0);
        return;
    }
    /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that binds, as a call's (path_udp.c) */
    if (h->n->th.drop_bind_ack)
        return;
    h->newnet = 0;
    learn_seen(h, a.t_s, a.learn);
    spare_bound(h, now);
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
}

int node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    struct npf_home *h = n->home;
    uint8_t plain[2048];
    int pl;
    if (!h || !h->r.state || fd != n->udp_fd || from->ss_family != AF_INET || len < 12 + 20)
        return 0;
    if ((pl = relay_bind_open(&h->r, buf, len, from, plain)) <= 0)
        return pl == 0;
    if (plain[0] == PKT_RELAY_BIND_ACK)
        ack_in(h, plain, (size_t)pl);
    else if (plain[0] == PKT_RELAY_PING)
        ping_in(h, plain, (size_t)pl);
    home_arm(h);
    return 1;
}

/* ---- what it says ---- */

int npf_node_home_status(npf_node *n, npf_out *w)
{
    struct npf_home *h = n->home;
    char a[64] = "", r[64];
    if (!h)
        return 0;
    if (h->r.state)
        npf_addr_str(CUR(h), a, sizeof a);
    npf_out_jobj(w);
    npf_out_kstr(w, "state", k_state[H_STATE(h)]);
    if (h->r.state) {
        npf_out_kint(w, "server", h->server);
        npf_out_kstr(w, "relay", a);
    }
    if (h->R.ss_family)
        npf_out_kstr(w, "addr", npf_addr_str(&h->R, r, sizeof r));
    npf_out_kint(w, "iv_s", h->t_s);
    npf_out_kstr(w, "learn", learn_str(h->learn));
    npf_out_kint(w, "last_ping_ms", h->keepalives ? npf_mono_ms() - h->ping_mark : -1);
    npf_out_kint(w, "rtt_ms", h->rtt);
    npf_out_kint(w, "moved", (int64_t)h->moved);
    npf_out_kint(w, "drops", (int64_t)h->drops);
    npf_out_kint(w, "keepalives", (int64_t)h->keepalives);
    npf_out_kint(w, "taken", (int64_t)h->taken);
    npf_out_kint(w, "since", h->since);
    npf_out_jend(w);
    return 1;
}

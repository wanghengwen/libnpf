/* Event-driven hole punching on npf_loop (nat-traversal.md 7, 10). */
#define _DEFAULT_SOURCE
#include "npf/log.h"
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/platform.h"
#include "npf/punch.h"

#define S1_FAST_MS   2000
#define S1_FAST_IVL    50
#define S1_SLOW_IVL   200
#define S3_RESEND_MS 1000
#define NOM_GRACE_MS  200   /* a higher-priority pair still probed: waited for this long at most */
#define NOM_IVL_MS    200
#define S1_QUIET_MS  3000   /* S1: nothing at all from the peer this long after the start, */
#define CAND_QUIET_MS 2000  /* nor since a candidate joined: the round ends (nat-traversal.md 9) */
#define S2B_QUIET_MS 2200   /* S2B: nothing this long after the last pass (two resends) */
#define S2_DESTS     (4 * 256 + 1)  /* S2's easy side: the ports around the measured one */
#define S3_EASY_LEAD  150
#define TICK_MS        10
#define TRIG_MAX       64   /* triggered checks per punch */
#define SPRAY_BURST    32   /* probes of a spray in one tick at most */
#define SPRAY_LAG_MS   50   /* a spray behind by more (the loop stalled) catches up no further */
#define SEEN_MAX      128   /* packets of the peer remembered (their txids): a replay is dropped */
#define TRIG_GAP_MS   500   /* at most one per source this often */
#define S2B_MAX       512   /* S2B: destinations of a round (window x passes) */
#define S2B_PASS_MS   300   /* between two passes */
#define S2B_RESEND_MS 1000  /* the destinations sent so far, again (their mappings exist: no new ones) */

/* a source of a triggered check: an IPv4 or IPv6 address, not 128 bytes */
typedef union trig_addr {
    struct sockaddr     sa;
    struct sockaddr_in  in4;
    struct sockaddr_in6 in6;
} trig_addr;

typedef struct psock {
    int     fd;
    int     owned;
    int64_t next_send;
} psock;

struct npf_punch {
    npf_loop       *loop;
    npf_punch_cfg   cfg;
    npf_siv_keys    kp, kn;
    psock          *socks;          /* nsock of capsock: 1, 2 (S2B), or 1 + S3 hard's own */
    int             nsock, capsock;
    int64_t         start, deadline, spray_next, nom_next, validated_at;
    int             sprayed, nom_sent, have_valid, win_sock, finished;
    int             win_fd;         /* the socket the winning path uses (socks[win_sock] or fd6) */
    struct { trig_addr a; int sock; int64_t at; } trig[TRIG_MAX];
    int             ntrig;
    struct sockaddr_storage winner;
    /* S2B */
    npf_siv_keys    kprobe;
    uint8_t         btx[NPF_TXID_SIZE];
    int             bsent, pass;
    int64_t         bnext, pass_next, resend_next;
    uint16_t        own_port, peer_port;
    uint16_t        dests[S2B_MAX];
    int             ndests;
    int64_t         last_pass;      /* S2B: when the last pass went out */
    /* S2's easy side: the ports after the hard side's measured one, in order */
    uint16_t        mdest[S2_DESTS];
    int             nmdest, mdest_at;
    int             got_any;        /* a packet of the peer's came (an early report, 9, waits for nothing) */
    int             quiet_said;     /* cfg.quiet was called */
    int64_t         cand_at;        /* a candidate joined then */
    int             win_prio;       /* the winner's priority (10.1) */
    int64_t         nom_at;         /* the controlling side's NOMINATE is due then */
    int             nv6;            /* IPv6 peers: probed alongside in every strategy */
    uint8_t        *sent_to;        /* S3 easy: the peer's IPv4 ports probed (S2's targets after the
                                     * measured port skip them), 8 KB */
    npf_punch_result res;
    uint8_t         seen_tx[SEEN_MAX][NPF_TXID_SIZE]; /* the last SEEN_MAX authenticated packets' txids */
    int             seen_at;
    npf_timer       tick;           /* embedded (npf/loop.h) */
    int64_t         tick_due;
    npf_punch_done_fn done;
    void           *arg;
    int             depth;          /* input / tick / sock_cb: free deferred while > 0 */
    int             free_me;
};

/* the bodies: session_id(8), then PROBE: sock(2); PROBE_ACK: its PROBE's
 * sock(2) | family(1) | port(2) | addr(4 or 16), where that came from;
 * NOMINATE, NOMINATE_ACK: nothing more */
static size_t sid_body(uint8_t *b, uint64_t sid)
{
    npf_le64(b, sid);
    return 8;
}

static size_t ack_body(uint8_t *b, uint64_t sid, uint16_t idx, const struct sockaddr_storage *seen)
{
    int v6 = seen->ss_family == AF_INET6;
    size_t alen = v6 ? 16 : 4;
    sid_body(b, sid);
    npf_le16(b + 8, idx);
    b[10] = v6 ? 6 : 4;
    npf_le16(b + 11, npf_addr_port(seen));
    memcpy(b + 13, v6 ? (const void *)&((const struct sockaddr_in6 *)seen)->sin6_addr
                      : (const void *)&((const struct sockaddr_in *)seen)->sin_addr, alen);
    return 13 + alen;
}

/* the sizes (6.5): random in [PKT_MIN, PKT_MAX], a reply no longer than
 * what it answers (no amplification: max); PKT_MIN fits an IPv6 PROBE_ACK */
#define PKT_MIN 72
#define PKT_MAX 256

static void send_pkt(int fd, const npf_siv_keys *keys, int dir, int type, const uint8_t *body, size_t blen,
                     size_t max, const struct sockaddr_storage *to)
{
    uint8_t wire[PKT_MAX], txid[NPF_TXID_SIZE];
    size_t len = npf_rand_range(PKT_MIN, (uint32_t)max);
    int n;
    npf_random(txid, sizeof(txid));
    n = npf_pkt_seal(keys, dir, type, txid, (uint32_t)npf_mono_ms(), body, blen, len, wire);
    if (n > 0)
        (void)npf_udp_send(fd, wire, (size_t)n, to);
}

/* a random port of [lo, hi] (lo > hi: the range wraps past 65535), not below 1024 */
static uint16_t rand_port(uint16_t lo, uint16_t hi)
{
    uint32_t span = (uint32_t)(uint16_t)(hi - lo) + 1;
    int i;
    for (i = 0; i < 64; i++) {
        uint16_t port = (uint16_t)(lo + npf_rand_range(0, span - 1));
        if (port >= 1024)
            return port;
    }
    return (uint16_t)npf_rand_range(1024, 65535);
}

static void probe(npf_punch *p, int sock, const struct sockaddr_storage *to)
{
    uint8_t b[16];
    size_t n = sid_body(b, p->cfg.plan.session_id);
    int fd = p->socks[sock].fd;
    if (sock == 0 && to->ss_family == AF_INET6) {     /* S0: IPv6 peers from the IPv6 socket */
        if (p->cfg.fd6 < 0)
            return;
        fd = p->cfg.fd6;
    }
    npf_le16(b + n, (uint16_t)sock);
    send_pkt(fd, &p->kp, p->cfg.plan.role, NPF_PKT_PROBE, b, n + 2, PKT_MAX, to);
    if (to->ss_family == AF_INET && p->sent_to) {
        uint16_t port = npf_addr_port(to);
        p->sent_to[port >> 3] |= (uint8_t)(1u << (port & 7));
    }
    if (sock == 0 && p->res.probes_sent < p->cfg.npeers && npf_log_on(NPF_LOG_TRACE)) {
        char a[64];     /* the first round, in candidate order */
        npf_logt("punch: PROBE -> %s", npf_addr_str(to, a, sizeof a));
    }
    p->res.probes_sent++;
}

/* the spray (S3 easy) sent to the peer's IPv4 port in this round */
static int probed(const npf_punch *p, uint16_t port)
{
    return p->sent_to && (p->sent_to[port >> 3] & (1u << (port & 7))) != 0;
}

static int same_ip(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    return a->ss_family == AF_INET
               ? ((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr
               : memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr, 16) == 0;
}

/* a's IP is the peer's: a candidate's, its NAT's public one (the spray's
 * target), the easy side's srflx (an S3 hard side's target) */
static int peer_ip(const npf_punch *p, const struct sockaddr_storage *a)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int i;
    if (a->ss_family == AF_INET && pl->peer_ip4.s_addr
        && pl->peer_ip4.s_addr == ((const struct sockaddr_in *)a)->sin_addr.s_addr)
        return 1;
    for (i = 0; i < p->cfg.npeers && !same_ip(a, &p->cfg.peers[i]); i++)
        ;
    return i < p->cfg.npeers || same_ip(a, &pl->peer_srflx);
}

/* A triggered check (ICE): a PROBE that came in shows a path from the peer
 * to this socket; probing back at once lets this side validate it too. In S3
 * the easy side's sprayed probe to a port often arrives before the hard
 * side's mapping exists and is lost, while the hard side's probes from that
 * mapping get through later (the easy side sent there): without probing back
 * the caller never sees a PROBE_ACK and cannot nominate (a Mac -> a host
 * behind a cloud NAT gateway, 2026-10-07: 6 probes in, none of its own
 * answered, the round failed). Only to an IP of the peer's (any port: a
 * mapping not known yet): a spoofed source gets its PROBE_ACK, nothing more. */
static void triggered(npf_punch *p, int sock, const struct sockaddr_storage *from)
{
    int64_t now = npf_mono_ms();
    int i;
    if (p->have_valid || p->finished || !peer_ip(p, from))
        return;
    for (i = 0; i < p->ntrig; i++)
        if (p->trig[i].sock == sock && npf_addr_eq(&p->trig[i].a, from)) {
            if (now - p->trig[i].at < TRIG_GAP_MS)
                return;
            p->trig[i].at = now;
            probe(p, sock, from);
            return;
        }
    if (p->ntrig == TRIG_MAX)
        return;
    memcpy(&p->trig[p->ntrig].a, from, npf_addr_len(from));
    p->trig[p->ntrig].sock = sock;
    p->trig[p->ntrig].at = now;
    p->ntrig++;
    if (npf_log_on(NPF_LOG_TRACE)) {
        char a[64];
        npf_logt("punch: triggered PROBE -> %s (sock %d)", npf_addr_str(from, a, sizeof a), sock);
    }
    probe(p, sock, from);
}

static void finish(npf_punch *p, int ok)
{
    int i, fd = -1;
    if (p->finished || p->free_me)
        return;                     /* free_me: the owner has dropped it */
    p->finished = 1;
    p->res.ok = ok;
    p->res.elapsed_ms = (int)(npf_mono_ms() - p->start);
    npf_timer_cancel(p->loop, &p->tick);
    if (ok) {
        struct sockaddr_storage la;
        socklen_t ll = sizeof la;
        fd = p->win_fd;
        p->res.peer = p->winner;
        p->res.peer_len = npf_addr_len(&p->winner);
        p->res.sock_idx = p->win_sock;
        if (getsockname(fd, (struct sockaddr *)&la, &ll) == 0)
            p->res.local_port = npf_addr_port(&la);
    }
    /* the sockets of our own that lost are closed; the winner goes to the
     * owner, which registers it again */
    for (i = 0; i < p->nsock; i++) {
        psock *s = &p->socks[i];
        if (!s->owned)
            continue;
        npf_loop_del(p->loop, s->fd);
        if (ok && i == p->win_sock) {
            s->owned = 0;
        } else {
            npf_sock_close(s->fd);
            s->fd = -1;
        }
    }
    /* late PROBE / NOMINATE are answered on the winning path only (its
     * socket, or fd6) */
    if (ok) {
        p->socks[0] = p->socks[p->win_sock];
        p->socks[0].fd = p->win_fd;
        p->win_sock = 0;
    }
    p->nsock = ok;
    p->done(p, &p->res, fd, p->arg);
}

static void schedule(npf_punch *p);

/* the peer's public IP at port, in to (the caller's: punches of
 * instances on other threads do not share one) */
static const struct sockaddr_storage *peer_at(npf_punch *p, uint16_t port, struct sockaddr_storage *to)
{
    npf_addr_set(to, AF_INET, &p->cfg.plan.peer_ip4, port);
    return to;
}

/* S2B's passes; S3 easy's interval between two sprayed probes */
static int s2b_passes(const npf_punch_plan *pl)
{
    return pl->passes > 0 ? pl->passes : 4;
}

static int64_t spray_ivl(const npf_punch_plan *pl)
{
    return pl->pps > 1000 ? 1 : pl->pps > 0 ? 1000 / pl->pps : 5;
}

/* S2B: a BIND_REQ from the fresh socket to a probe server (E1: its mapping;
 * E2: the caller's spacer, one more mapping) */
static void s2b_bind_to(npf_punch *p, const struct sockaddr_in *to, const uint8_t txid[NPF_TXID_SIZE])
{
    npf_bind_req_send(p->socks[1].fd, to, &p->kprobe, NPF_PKT_BIND_REQ, txid, p->cfg.clock_offset_ms, p->cfg.ticket,
                      NPF_TICKET_SIZE);
}

/* S2B: the caller's spacer before pass r: one more mapping of the fresh
 * socket's, so a destination it has not sent to yet (an APDM NAT gives a
 * known one the mapping it has): E2, then E2's next ports (nothing listens
 * there, nothing comes back) */
static void s2b_spacer(npf_punch *p, int r)
{
    struct sockaddr_in to = p->cfg.probe_ep[1];
    uint8_t txid[NPF_TXID_SIZE];
    unsigned port = ntohs(to.sin_port);
    to.sin_port = htons((uint16_t)(port + r <= 65535 ? port + r : port - r));
    npf_random(txid, sizeof txid);
    s2b_bind_to(p, &to, txid);
}

/* S2B, one pass: the next window of the ports the peer's NAT gives after its
 * fresh mapping, the caller in ascending order, the callee in descending
 * order. The caller's k-th new mapping meets the callee's m-th when
 * k - m = (the callee's ports taken by others meanwhile) and k + m + 1 =
 * W - (the caller's): a solution for every pair of shifts that adds up to
 * less than W when the two add up to an odd number. The caller's spacer
 * before every pass (one more mapping of its own, a new destination each
 * time) turns the parity every pass: a round misses only when the others
 * took an odd number of ports before every pass (7.6). Once the spacers
 * went before odd passes only and both to E2, so the second one took no
 * new mapping: a round missed whenever the others took an odd number
 * between the first two passes and none after, about 15 % of the rounds
 * at 2 ports a second */
static void s2b_pass(npf_punch *p)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int w = pl->window > 0 ? pl->window : 32, k;
    int up = pl->role == NPF_PUNCH_CONTROLLING;
    struct sockaddr_storage pa;
    if (up)
        s2b_spacer(p, p->pass);
    for (k = 0; k < w && p->ndests < S2B_MAX; k++) {
        int n = up ? p->pass * w + k + 1 : p->pass * w + w - k;
        long port = (long)p->peer_port + (long)n * pl->peer_delta;
        if (port < 1024 || port > 65535)
            continue;
        p->dests[p->ndests++] = (uint16_t)port;
        probe(p, 1, peer_at(p, (uint16_t)port, &pa));
    }
}

/* S2B's fresh socket, S2's first new one: its mapping not known yet (a
 * BIND_REQ to E1 again, four at most) */
static int bind_pending(const npf_punch *p)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    return p->nsock > 1 && !p->own_port && p->bsent < 4
           && (pl->strategy == NPF_PUNCH_S2B || (pl->measure && pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD));
}

static void bind_retry(npf_punch *p, int64_t now)
{
    static const int next_ms[] = {200, 400, 800, 1600};
    if (bind_pending(p) && now >= p->bnext) {
        s2b_bind_to(p, &p->cfg.probe_ep[0], p->btx);
        p->bnext = now + next_ms[p->bsent++];
    }
}

static void s2b_tick(npf_punch *p, int64_t now)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    struct sockaddr_storage pa;
    int i;
    if (!p->own_port || !p->peer_port || !pl->peer_ip4.s_addr)
        return;                     /* no public IP of the peer's to send to: nothing (H-1) */
    if (p->pass < s2b_passes(pl) && now >= p->pass_next) {
        s2b_pass(p);
        p->pass++;
        p->last_pass = now;
        p->pass_next = now + S2B_PASS_MS;
        if (!p->resend_next)
            p->resend_next = now + S2B_RESEND_MS;
    }
    if (p->resend_next && now >= p->resend_next) {
        for (i = 0; i < p->ndests; i++)
            probe(p, 1, peer_at(p, p->dests[i], &pa));
        p->resend_next = now + S2B_RESEND_MS;
    }
}

/* S2B: the fresh socket's BIND_RESP from E1 (1: it was one) */
static int s2b_input(npf_punch *p, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    const struct sockaddr_in *f = (const struct sockaddr_in *)from;
    uint8_t plain[NPF_PKT_MAX];
    npf_pkt pkt;
    npf_bind_resp resp;
    int ep;
    if (from->ss_family != AF_INET || len > NPF_PKT_MAX)
        return 0;
    for (ep = 0; ep < 2; ep++)
        if (f->sin_addr.s_addr == p->cfg.probe_ep[ep].sin_addr.s_addr && f->sin_port == p->cfg.probe_ep[ep].sin_port)
            break;
    if (ep == 2)
        return 0;
    if (ep == 0 && !p->own_port && npf_pkt_open(&p->kprobe, NPF_DIR_RESP, buf, len, plain, &pkt) == 0
        && memcmp(pkt.txid, p->btx, NPF_TXID_SIZE) == 0 && npf_bind_resp_parse(&pkt, &resp) == 0
        && resp.mapped.ss_family == AF_INET) {
        p->own_port = npf_addr_port(&resp.mapped);
        npf_log("punch: %s: the fresh socket's mapping is port %u", p->cfg.plan.strategy == NPF_PUNCH_S2B ? "S2B" : "S2",
                p->own_port);
        if (p->cfg.info)
            p->cfg.info(p, p->own_port, p->arg);
        if (p->peer_port) {
            p->pass_next = npf_mono_ms();
            schedule(p);
        }
    }
    return 1;
}

/* S2's easy side: the ports the hard side's new sockets take after its
 * measured mapping q0, as a sequential NAT gives them (q0 + k·δ: those after
 * it first, then the few before: sockets that sent before the measurement),
 * the spray's targets before every port */
static void s2_dests(npf_punch *p, uint16_t q0)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int n = pl->peer_n, d = pl->peer_delta ? pl->peer_delta : 1, k;
    p->nmdest = p->mdest_at = 0;
    for (k = 1; k <= 3 * n && p->nmdest < S2_DESTS; k++) {
        long port = (long)q0 + (long)k * d;
        if (port >= 1024 && port <= 65535)
            p->mdest[p->nmdest++] = (uint16_t)port;
    }
    for (k = 0; k >= -n && p->nmdest < S2_DESTS; k--) {
        long port = (long)q0 + (long)k * d;
        if (port >= 1024 && port <= 65535)
            p->mdest[p->nmdest++] = (uint16_t)port;
    }
}

void npf_punch_peer_port(npf_punch *p, uint16_t port)
{
    const npf_punch_plan *pl;
    if (!p || p->finished || p->peer_port)
        return;
    pl = &p->cfg.plan;
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY && pl->peer_n > 0) {
        p->peer_port = port;
        s2_dests(p, port);
        npf_log("punch: S2: the peer's sockets take the ports after %u: %d of them sprayed first, then every port",
                port, p->nmdest);
        schedule(p);
        return;
    }
    if (pl->strategy != NPF_PUNCH_S2B)
        return;
    p->peer_port = port;
    npf_log("punch: S2B: the peer's fresh mapping is port %u", port);
    p->pass_next = npf_mono_ms();
    schedule(p);
}

/* the priority of the pair to a (10.1): a peer candidate's, else (a
 * mapping the spray found, a triggered check's source) the lowest */
static int peer_prio(const npf_punch *p, const struct sockaddr_storage *a)
{
    int i;
    for (i = 0; i < p->cfg.npeers; i++)
        if (npf_addr_eq(a, &p->cfg.peers[i]))
            return p->cfg.prio[i] ? p->cfg.prio[i] : 1;
    return 1;
}

/* a pair of a higher priority than prio is still probed (not validated) */
static int higher_pending(const npf_punch *p, int prio)
{
    int i;
    for (i = 0; i < p->cfg.npeers; i++)
        if (p->cfg.prio[i] > prio && (p->cfg.peers[i].ss_family == AF_INET || p->cfg.fd6 >= 0))
            return 1;
    return 0;
}

int npf_punch_add_peer(npf_punch *p, const struct sockaddr_storage *a, int srflx)
{
    int i, added = 0;
    char t[64];
    if (!p || p->finished || (a->ss_family != AF_INET && a->ss_family != AF_INET6))
        return 0;
    if (srflx && a->ss_family == AF_INET && p->cfg.plan.strategy == NPF_PUNCH_S3 && p->cfg.plan.side == NPF_PUNCH_HARD
        && !npf_addr_eq(a, &p->cfg.plan.peer_srflx)) {
        p->cfg.plan.peer_srflx = *a;    /* the hard side's sockets: at the easy side's new mapping */
        p->cfg.plan.peer_srflx_len = sizeof(struct sockaddr_in);
        for (i = 1; i < p->nsock; i++)
            p->socks[i].next_send = npf_mono_ms() + (i - 1) % 50;  /* spread, as the first burst */
        added = 1;
    }
    for (i = 0; i < p->cfg.npeers && !npf_addr_eq(a, &p->cfg.peers[i]); i++)
        ;
    if (i == p->cfg.npeers && p->cfg.npeers < NPF_PUNCH_MAX_PEERS) {
        p->cfg.prio[p->cfg.npeers] = srflx ? 1 : a->ss_family == AF_INET6 ? 4 : 1;
        p->cfg.peers[p->cfg.npeers++] = *a;
        p->nv6 += a->ss_family == AF_INET6;
        p->socks[0].next_send = npf_mono_ms();  /* probed at once, then with the others */
        p->cand_at = npf_mono_ms();             /* an S1 round does not end early just after */
        added = 1;
    }
    if (added) {
        npf_log("punch: the peer's new candidate %s joins the round", npf_addr_str(a, t, sizeof t));
        schedule(p);
    }
    return added;
}

/* when the round ends for want of anything from the peer (INT64_MAX: not
 * by this): S1 3 s after its start and 2 s after a new candidate, S2B 2.2 s
 * after its last pass; never once something came (an S3 waits for its
 * spray: its timeout is the spray's length, the platform's) */
static int64_t quiet_end(const npf_punch *p)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int64_t t;
    if (p->got_any || p->quiet_said || !p->cfg.quiet || p->cfg.test_deaf)
        return INT64_MAX;
    if (pl->strategy == NPF_PUNCH_S1) {
        t = p->start + S1_QUIET_MS;
        return p->cand_at + CAND_QUIET_MS > t ? p->cand_at + CAND_QUIET_MS : t;
    }
    if (pl->strategy == NPF_PUNCH_S2B && p->last_pass && p->pass >= s2b_passes(pl))
        return p->last_pass + S2B_QUIET_MS;
    return INT64_MAX;
}

/* the main socket probes all the peer's candidates: S1, S3's easy side,
 * S3's hard side without sockets of its own (the node's budget is held by
 * other punches) */
static int probes_all(const npf_punch *p)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    return pl->strategy == NPF_PUNCH_S1
           || (pl->strategy == NPF_PUNCH_S3 && (pl->side == NPF_PUNCH_EASY || p->nsock == 1));
}

/* otherwise the IPv6 peers, from the main path's IPv6 socket: both with
 * global IPv6, probed in every strategy (7.1: a firewall may block it,
 * IPv4 goes on) */
static int v6_alongside(const npf_punch *p)
{
    return p->nv6 && p->cfg.fd6 >= 0 && !probes_all(p);
}

void npf_punch_stop(npf_punch *p)
{
    if (!p || p->finished)
        return;
    npf_log("punch: the peer let the round go: it ends");
    finish(p, 0);
}

static void punch_destroy(npf_punch *p)
{
    int i;
    npf_timer_cancel(p->loop, &p->tick);
    for (i = 0; i < p->nsock; i++) {
        if (p->socks[i].owned && p->socks[i].fd >= 0) {
            npf_loop_del(p->loop, p->socks[i].fd);
            npf_sock_close(p->socks[i].fd);
        }
    }
    free(p->socks);
    free(p->sent_to);
    npf_wipe_free(p, sizeof *p);        /* punch_key, nominate_key, SIV keys */
}

static void leave(npf_punch *p)
{
    if (--p->depth == 0 && p->free_me)
        punch_destroy(p);
}

static void tick_cb(npf_loop *loop, void *arg)
{
    struct sockaddr_storage pa;
    int burst;
    npf_punch *p = arg;
    const npf_punch_plan *pl = &p->cfg.plan;
    int64_t now = npf_mono_ms();
    int i, k;
    (void)loop;
    p->depth++;
    if (now >= p->deadline) {
        finish(p, 0);
        leave(p);
        return;
    }
    if (now >= quiet_end(p)) {
        /* nothing at all came from the peer by now (S1: within 3 s of the
         * start, 2 s of a new candidate; S2B: 2.2 s after the last pass):
         * the owner hears it (the platform plans the next round sooner), the
         * round goes on to its timeout: the peer may have started late (S1
         * starts on receipt; a plan over a loaded link came seconds later),
         * its probes are answered and it may nominate (nat-traversal.md 9) */
        npf_log("punch: nothing from the peer in %d ms: told early, the round goes on to its end", (int)(now - p->start));
        p->quiet_said = 1;
        p->res.elapsed_ms = (int)(now - p->start);
        p->cfg.quiet(p, &p->res, p->arg);
        if (p->finished || p->free_me) {
            leave(p);
            return;                 /* the owner ended it or let it go */
        }
    }
    if ((probes_all(p) || v6_alongside(p)) && now >= p->socks[0].next_send) {
        int all = probes_all(p);
        for (k = 0; k < p->cfg.npeers; k++)
            if (all || p->cfg.peers[k].ss_family == AF_INET6)
                probe(p, 0, &p->cfg.peers[k]);
        p->socks[0].next_send = now + (now - p->start < S1_FAST_MS ? S1_FAST_IVL : S1_SLOW_IVL);
    }
    bind_retry(p, now);
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD) {
        for (i = 1; i < p->nsock; i++) {
            if (now >= p->socks[i].next_send) {
                probe(p, i, &pl->peer_srflx);
                p->socks[i].next_send = now + S3_RESEND_MS;
            }
        }
    }
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY) {
        int64_t ivl = spray_ivl(pl);
        uint16_t lo = pl->range_lo ? pl->range_lo : 1024;
        uint16_t hi = pl->range_hi ? pl->range_hi : 65535;
        if (p->spray_next < now - SPRAY_LAG_MS)
            p->spray_next = now - SPRAY_LAG_MS;     /* after a stall: not everything that came due at once */
        for (burst = 0; burst < SPRAY_BURST && p->sprayed < pl->m_total && pl->peer_ip4.s_addr && now >= p->spray_next;
             burst++) {
            uint16_t port = rand_port(lo, hi);
            if (p->peer_port) {         /* S2, the hard side's port measured: the ports after it, then all */
                while (p->mdest_at < p->nmdest && probed(p, p->mdest[p->mdest_at]))
                    p->mdest_at++;
                port = p->mdest_at < p->nmdest ? p->mdest[p->mdest_at++] : rand_port(1024, 65535);
            }
            probe(p, 0, peer_at(p, port, &pa));
            p->sprayed++;
            p->spray_next += ivl;
        }
    }
    if (pl->strategy == NPF_PUNCH_S2B && p->nsock > 1)
        s2b_tick(p, now);
    if (pl->role == NPF_PUNCH_CONTROLLING && p->have_valid) {
        uint8_t b[8];
        if ((!p->nom_sent && now >= p->nom_at) || (p->nom_sent && now >= p->nom_next)) {
            send_pkt(p->win_fd, &p->kn, pl->role, NPF_PKT_NOMINATE, b, sid_body(b, pl->session_id), PKT_MAX,
                     &p->winner);
            p->nom_sent = 1;
            p->nom_next = now + NOM_IVL_MS;
        }
    }
    schedule(p);
    leave(p);
}

/* a spray due at t: when its interval is below a tick, it goes in batches
 * a tick apart (SPRAY_BURST at most each), not a wake-up a probe */
static int64_t spray_due(int64_t t, int64_t ivl, int64_t now)
{
    if (t < now - SPRAY_LAG_MS)
        t = now - SPRAY_LAG_MS;
    if (ivl < TICK_MS && t < now + TICK_MS)
        t = now + TICK_MS;
    return t;
}

/* when tick_cb next has something to do: the same conditions as there */
static int64_t next_due(const npf_punch *p, int64_t now)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int64_t due = p->deadline;
    int i;
#define DUE(t) do { int64_t t_ = (t); if (t_ < due) due = t_; } while (0)
    if (probes_all(p) || v6_alongside(p))
        DUE(p->socks[0].next_send);
    if (bind_pending(p))
        DUE(p->bnext);
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD)
        for (i = 1; i < p->nsock; i++)
            DUE(p->socks[i].next_send);
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY && p->sprayed < pl->m_total && pl->peer_ip4.s_addr)
        DUE(spray_due(p->spray_next, spray_ivl(pl), now));
    if (pl->strategy == NPF_PUNCH_S2B && p->nsock > 1 && p->own_port && p->peer_port && pl->peer_ip4.s_addr) {
        if (p->pass < s2b_passes(pl))
            DUE(p->pass_next);
        if (p->resend_next)
            DUE(p->resend_next);
    }
    if (pl->role == NPF_PUNCH_CONTROLLING && p->have_valid)
        DUE(p->nom_sent ? p->nom_next : p->nom_at);
    DUE(quiet_end(p));
#undef DUE
    return due;
}

/* the tick at the next thing to do, not every TICK_MS: a punch of S1 wakes
 * the loop 20 times a second, then 5, not 100.
 * After a change that brings something forward (a path validated, S2B's
 * ports known) too */
static void schedule(npf_punch *p)
{
    int64_t now = npf_mono_ms(), due;
    if (p->finished)
        return;
    due = next_due(p, now);
    if (npf_timer_pending(&p->tick) && p->tick_due <= due)
        return;
    p->tick_due = due;
    npf_timer_set(p->loop, &p->tick, due - now);
}

/* 1 when this packet (its random txid) was taken before: someone on the
 * path sending a copy (from an address of their choosing) gets no answer
 * and no say in the path; otherwise it is remembered */
static int replayed(npf_punch *p, const uint8_t txid[NPF_TXID_SIZE])
{
    int i;
    for (i = 0; i < SEEN_MAX; i++)
        if (memcmp(p->seen_tx[i], txid, NPF_TXID_SIZE) == 0)
            return 1;
    memcpy(p->seen_tx[p->seen_at], txid, NPF_TXID_SIZE);
    p->seen_at = (p->seen_at + 1) % SEEN_MAX;
    return 0;
}

static void set_winner(npf_punch *p, int sock, int fd, const struct sockaddr_storage *from)
{
    p->winner = *from;
    p->win_sock = sock;
    p->win_fd = fd;
}

static int handle(npf_punch *p, int sock, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int peer_dir = 1 - pl->role;
    uint8_t plain[NPF_PKT_MAX];
    npf_pkt pkt;
    if (len < PKT_MIN || len > PKT_MAX)  /* send_pkt's sizes (within NPF_PKT_MAX, plain's) */
        return 0;
    /* security.md 11.1 inbound: a source this side would never probe
     * (loopback, multicast, the platform's own endpoints, ...) gets no ACK,
     * no triggered probe, no say in the path; its txid is not taken */
    if (p->cfg.from_ok && !p->cfg.from_ok(p, from, p->arg))
        return 0;
    if (npf_pkt_open(&p->kp, peer_dir, buf, len, plain, &pkt) == 0
        && (pkt.type == NPF_PKT_PROBE || pkt.type == NPF_PKT_PROBE_ACK)
        && pkt.body_len >= 10 && npf_rd64(pkt.body) == pl->session_id) {
        if (p->cfg.test_deaf || replayed(p, pkt.txid))
            return 1;
        p->got_any = 1;
        if (from->ss_family == AF_INET) {      /* 7.8: what the peer's NAT showed */
            uint16_t port = npf_addr_port(from);
            int i;
            for (i = 0; i < p->res.nseen && p->res.seen[i] != port; i++)
                ;
            if (i == p->res.nseen && p->res.nseen < (int)(sizeof p->res.seen / sizeof p->res.seen[0]))
                p->res.seen[p->res.nseen++] = port;
        }
        if (pkt.type == NPF_PKT_PROBE) {
            uint8_t b[40];
            p->res.probes_recv++;
            if (p->res.probes_recv <= 3 && npf_log_on(NPF_LOG_TRACE)) {
                char a[64];
                npf_logt("punch: PROBE from %s (sock %d, %d ms) -> PROBE_ACK", npf_addr_str(from, a, sizeof a), sock,
                         (int)(npf_mono_ms() - p->start));
            }
            send_pkt(fd, &p->kp, pl->role, NPF_PKT_PROBE_ACK, b, ack_body(b, pl->session_id, npf_rd16(pkt.body + 8), from),
                     len, from);
            triggered(p, sock, from);
        } else {
            p->res.acks_recv++;
            if (p->have_valid && !p->finished && !p->nom_sent && peer_prio(p, from) > p->win_prio) {
                /* a pair of a higher priority came up in the grace: it is the one */
                set_winner(p, sock, fd, from);
                p->win_prio = peer_prio(p, from);
                if (!higher_pending(p, p->win_prio))
                    p->nom_at = npf_mono_ms();
                schedule(p);
            }
            if (!p->have_valid && !p->finished) {
                p->have_valid = 1;
                set_winner(p, sock, fd, from);
                p->validated_at = npf_mono_ms();
                /* NOMINATE at once (10.1), unless a pair of a higher priority
                 * (an IPv6, a mapped, a LAN one) is still probed: up to 200 ms for it */
                p->win_prio = peer_prio(p, from);
                p->nom_at = p->validated_at + (higher_pending(p, p->win_prio) ? NOM_GRACE_MS : 0);
                schedule(p);                /* the NOMINATE's time */
                if (npf_log_on(NPF_LOG_TRACE)) {
                    char a[64];
                    npf_logt("punch: path validated via %s (sock %d, %d ms)", npf_addr_str(from, a, sizeof a), sock,
                             (int)(npf_mono_ms() - p->start));
                }
            }
        }
        return 1;
    }
    if (npf_pkt_open(&p->kn, peer_dir, buf, len, plain, &pkt) == 0
        && pkt.body_len >= 8 && npf_rd64(pkt.body) == pl->session_id) {
        if (replayed(p, pkt.txid))
            return 1;
        p->got_any = 1;
        if (pkt.type == NPF_PKT_NOMINATE && pl->role == NPF_PUNCH_CONTROLLED) {
            uint8_t b[8];
            send_pkt(fd, &p->kn, pl->role, NPF_PKT_NOMINATE_ACK, b, sid_body(b, pl->session_id), len, from);
            if (!p->finished) {
                set_winner(p, sock, fd, from);
                finish(p, 1);
            }
        } else if (pkt.type == NPF_PKT_NOMINATE_ACK && pl->role == NPF_PUNCH_CONTROLLING && p->nom_sent
                   && npf_addr_eq(from, &p->winner)) {     /* from where the NOMINATE went only */
            if (!p->finished) {
                p->res.rtt_ms = (int)(npf_mono_ms() - (p->nom_next - NOM_IVL_MS));
                if (p->res.rtt_ms < 0)
                    p->res.rtt_ms = 0;
                finish(p, 1);
            }
        }
        return 1;
    }
    return 0;
}

static void sock_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_punch *p = arg;
    int i, k;
    (void)loop;
    (void)ev;
    for (i = 1; i < p->nsock; i++)
        if (p->socks[i].fd == fd)
            break;
    if (i >= p->nsock)
        return;
    p->depth++;
    for (k = 0; k < 64; k++) {          /* a bounded batch (level-triggered) */
        uint8_t buf[512];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (!((p->cfg.plan.strategy == NPF_PUNCH_S2B || (p->cfg.plan.measure && i == 1))
              && s2b_input(p, buf, (size_t)r, &from)))
            handle(p, i, fd, buf, (size_t)r, &from);
        if (p->finished || p->free_me)
            break;  /* the socket table changed, or the owner let it go (freed in leave) */
    }
    leave(p);
}

/* a fresh UDP socket of the round's own (S2B's, S3 hard's), on any port and
 * read by sock_cb; 0, or -1 when there is none */
static int own_socket(npf_punch *p, int64_t first_send)
{
    struct sockaddr_in a;
    int fd = npf_udp_socket(AF_INET, 0, p->cfg.bypass);
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || npf_loop_add(p->loop, fd, NPF_EV_READ, sock_cb, p) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    p->socks[p->nsock].fd = fd;
    p->socks[p->nsock].owned = 1;
    p->socks[p->nsock].next_send = first_send;
    p->nsock++;
    return 0;
}

npf_punch *npf_punch_new(npf_loop *loop, const npf_punch_cfg *cfg, int primary_fd,
                         npf_punch_done_fn done, void *arg)
{
    npf_punch *p = calloc(1, sizeof *p);
    int i, hard = cfg->plan.strategy == NPF_PUNCH_S3 && cfg->plan.side == NPF_PUNCH_HARD;
    int spray = cfg->plan.strategy == NPF_PUNCH_S3 && !hard;
    if (!p)
        return NULL;
    /* the sockets it needs: the main one, a fresh one (S2B), S3 hard's own */
    p->capsock = hard ? 1 + (cfg->plan.n_sockets < NPF_PUNCH_MAX_SOCKETS - 1 ? (cfg->plan.n_sockets > 0 ? cfg->plan.n_sockets : 0)
                                                                            : NPF_PUNCH_MAX_SOCKETS - 1)
                      : 2;
    if (!(p->socks = calloc((size_t)p->capsock, sizeof *p->socks)) || (spray && !(p->sent_to = calloc(1, 65536 / 8)))) {
        free(p->socks);
        free(p);
        return NULL;
    }
    p->loop = loop;
    npf_timer_init(&p->tick, tick_cb, p);
    p->cfg = *cfg;
    p->done = done;
    p->arg = arg;
    p->res.sock_idx = -1;
    p->res.rtt_ms = -1;
    npf_siv_derive(&p->kp, cfg->plan.punch_key, NPF_SIV_LABEL_PUNCH);
    npf_siv_derive(&p->kn, cfg->plan.nominate_key, NPF_SIV_LABEL_NOMIN);
    p->start = npf_mono_ms();
    p->deadline = p->start + (cfg->plan.timeout_ms > 0 ? cfg->plan.timeout_ms : 8000);
    p->socks[0].fd = primary_fd;
    p->socks[0].next_send = p->start;
    p->nsock = 1;
    p->cand_at = p->start;
    for (i = 0; i < p->cfg.npeers; i++)
        p->nv6 += p->cfg.peers[i].ss_family == AF_INET6;
    if (cfg->plan.measure && hard) {    /* S2: the first new socket measures its mapping */
        npf_siv_derive(&p->kprobe, cfg->probe_key, NPF_SIV_LABEL_PROBE);
        npf_random(p->btx, sizeof p->btx);
        p->bnext = p->start;
    }
    if (cfg->plan.strategy == NPF_PUNCH_S3 && cfg->plan.side == NPF_PUNCH_EASY)
        p->spray_next = p->start + S3_EASY_LEAD;
    if (cfg->plan.strategy == NPF_PUNCH_S2B) {
        own_socket(p, 0);               /* one fresh socket: its mappings are the round's own */
        npf_siv_derive(&p->kprobe, cfg->probe_key, NPF_SIV_LABEL_PROBE);
        npf_random(p->btx, sizeof p->btx);
        p->bnext = p->start;
        p->spray_next = p->start;
    }
    if (hard)       /* S3 hard's own sockets, the first burst spread */
        for (i = 0; i < p->capsock - 1 && i < cfg->plan.n_sockets && own_socket(p, p->start + i % 50) == 0; i++)
            ;
    schedule(p);
    return p;
}

int npf_punch_input(npf_punch *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    int r;
    if (!p || p->nsock == 0 || (fd != p->socks[0].fd && (p->cfg.fd6 < 0 || fd != p->cfg.fd6)))
        return 0;
    p->depth++;
    r = handle(p, 0, fd, buf, len, from);
    leave(p);
    return r;
}

int64_t npf_punch_ends_at(const npf_punch *p)
{
    return p->deadline;
}

int npf_punch_finished(const npf_punch *p)
{
    return p->finished;
}

void npf_punch_free(npf_punch *p)
{
    if (!p)
        return;
    if (p->depth > 0) {
        p->free_me = 1;             /* sock_cb / input / tick still on the stack */
        return;
    }
    punch_destroy(p);
}

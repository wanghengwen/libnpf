/* Calls: the punching rounds the platform sends (nat-traversal.md 7): their
 * hard-side sockets, the direct path a round finds, and what the node tells
 * the platform (results, its profile's changes). When a round comes, with
 * which plan, after which wait: the platform's alone (signaling.md
 * "punch_result 与重试") */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* ---- punching ---- */

#define HARD_PUNCHES_MAX 1           /* a caller's hard-side punches at once; a round for more: busy */
#define PRESSURE_KEEP_MS (10 * 60 * 1000)   /* a sign of port pressure counts this long */
#define PRESSURE_SEEN_MS 60000      /* a check unanswered this soon after a hard-side punch: a sign */

/* what the platform plans the next rounds with: whether the NAT showed it is
 * short of ports lately (call_port_pressure) and when the last hard-side
 * punch ended; tests: NPF_TEST_PUNCH_GAP_MS (a gap of that length, a test
 * platform only), NPF_TEST_REPUNCH_MS (its backoff) */
static void write_pressure(const npf_call *c, npf_out *w)
{
    const npf_node *n = c->n;
    int64_t now = npf_mono_ms();
    if ((n->port_pressure && now - n->port_pressure < PRESSURE_KEEP_MS) || n->th.punch_gap_ms) {
        npf_out_kbool(w, "pressure", 1);
        npf_out_kint(w, "hard_ago_ms", n->hard_punch_end ? now - n->hard_punch_end : -1);
    }
    if (n->th.punch_gap_ms)
        npf_out_kint(w, "test_gap_ms", n->th.punch_gap_ms);
    if (n->th.repunch_ms)
        npf_out_kint(w, "test_backoff_ms", n->th.repunch_ms);
}

/* no punching in this session: connect_mode secure on either side (relays
 * only, neither side's address goes to the other), or tests (NPF_NO_P2P) */
int call_no_p2p(const npf_call *c)
{
    return c->secure || c->n->th.no_p2p;
}

/* the platform hears what changed for the call's rounds (punch_update):
 * why "network" (the NAT measured again after a network change),
 * "profile" (the node's first profile: a call made before had no
 * candidates), "path_lost" (the direct path given up); with this side's profile and
 * candidates. The platform decides whether and when a round comes; a moved
 * mapping it sees itself (its relay, the spare's address) */
void call_punch_report(npf_call *c, const char *why)
{
    npf_out w = {0};
    if (call_over(c) || call_has_p2p(c) || call_has_ws(c) || c->direct || call_no_p2p(c) || !call_accepted(c))
        return;
    npf_out_jobj(&w);
    npf_out_kstr(&w, "call_id", c->call_id_s);
    npf_out_kstr(&w, "why", why);
    npf_node_write_nat(c->n, &w);
    npf_node_write_cands(c->n, &w);
    npf_out_jend(&w);
    if (!w.failed) {
        npf_logd("call %s: punch_update (%s)", c->call_id_s, why);
        npf_node_send(c->n, "punch_update", 0, w.p);
    }
    npf_out_free(&w);
}

/* a punch_result (signaling.md): its head, the round's counts, the end */
static void result_begin(const npf_call *c, npf_out *w, int ok)
{
    npf_out_jobj(w);
    npf_out_kstr(w, "call_id", c->call_id_s);
    npf_out_kint(w, "round", c->punch_round);
    npf_out_kbool(w, "ok", ok);
}

static void result_counts(npf_out *w, const npf_punch_result *res)
{
    npf_out_kint(w, "elapsed_ms", res->elapsed_ms);
    npf_out_kint(w, "probes_sent", res->probes_sent);
    npf_out_kint(w, "probes_recv", res->probes_recv);
}

static void result_send(npf_call *c, npf_out *w)
{
    npf_out_jend(w);
    if (!w->failed)
        npf_node_send(c->n, "punch_result", 0, w->p);
    npf_out_free(w);
}

/* a punch gave its sockets (the NAT's ports) back: the relays that could
 * not bind meanwhile try again, once no other one holds them */
static void socks_back(npf_call *c)
{
    npf_call *o;
    if (!c->punch_socks)
        return;
    c->punch_socks = 0;
    c->n->hard_punch_end = npf_mono_ms();
    if (call_hard_punches(c->n, NULL))
        return;
    for (o = c->n->calls; o; o = o->next)
        if (o->pm.wait == PM_IN_PORTS)
            pm_check(o);                /* bound again (pm_decide) */
}

/* the round's punch ended (p NULL: one that could not run): its result;
 * LINGER, its punch freed at once after a failure, 10 s on after a success
 * (it answers the peer's late probes) */
void call_punch_done(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    npf_call *c = arg;
    char a[64], la[64];
    struct sockaddr_storage ls;
    socklen_t ll = sizeof ls;
    npf_out w = {0};
    (void)p;
    socks_back(c);                  /* finish() closed the extra sockets */
    result_begin(c, &w, res->ok);
    if (res->ok) {
        getsockname(fd, (struct sockaddr *)&ls, &ll);
        npf_out_jkey(&w, "path");
        npf_out_jobj(&w);
        npf_out_kstr(&w, "local", npf_addr_str(&ls, la, sizeof la));
        npf_out_kstr(&w, "peer", npf_addr_str(&res->peer, a, sizeof a));
        npf_out_jend(&w);
    }
    result_counts(&w, res);
    npf_out_kint(&w, "rtt_ms", res->rtt_ms);
    if (res->nseen > 0) {           /* the peer's NAT as this round showed it (nat-traversal.md 7.8) */
        int i;
        npf_out_jkey(&w, "seen");
        npf_out_jarr(&w);
        for (i = 0; i < res->nseen; i++)
            npf_out_jint(&w, res->seen[i]);
        npf_out_jend(&w);
    }
    write_pressure(c, &w);
    result_send(c, &w);
    if (!res->ok) {
        npf_logw("call %s: punching failed after %d ms (%d probes sent, %d received)", c->call_id_s,
                res->elapsed_ms, res->probes_sent, res->probes_recv);
        call_punch_to(c, PN_LINGER, npf_mono_ms());     /* freed after this callback */
        pm_check(c);                /* the UDP relay unreachable meanwhile: the next step */
        return;                     /* the platform plans what comes next */
    }
    npf_log("call %s: direct path %s (%d ms)", c->call_id_s, npf_addr_str(&res->peer, a, sizeof a),
            res->elapsed_ms);
    path_direct_up(c, fd, &res->peer);
    call_punch_to(c, PN_LINGER, npf_mono_ms() + PUNCH_LINGER_MS);
    call_path_up(c);
}

/* S3 hard side: the sockets one punch may open. All calls share a node budget
 * (punch_sockets; by default 1024, four full punches, or half the descriptor
 * limit): concurrent hard-side punches would otherwise multiply the
 * descriptors and the CGNAT ports (nat-traversal.md 8). The start time is
 * agreed with the peer, so a punch is not queued: it gets what is left, down
 * to none (then it probes from the main socket, like S1); a caller's round
 * with too few is let go (busy) and the platform sends it again later. Measured behind
 * a cloud NAT gateway (APDM, random ports) with the old budget of 256: three
 * concurrent calls, the first punch took all sockets, the others sent
 * nothing. */
int npf_node_punch_budget(const npf_node *n)
{
    return n->cfg.punch_sockets > 0 ? n->cfg.punch_sockets : n->punch_budget;
}

/* hard-side punches running now (another than c; the sockets: punch_socks
 * of a running punch only) */
int call_hard_punches(const npf_node *n, const npf_call *c)
{
    const npf_call *o;
    int k = 0;
    for (o = n->calls; o; o = o->next)
        k += o != c && o->punch_socks > 0;
    return k;
}

static int punch_sockets_grant(npf_call *c, int want)
{
    npf_call *o;
    int left = npf_node_punch_budget(c->n);
    for (o = c->n->calls; o; o = o->next)
        if (o != c)
            left -= o->punch_socks;
    if (left < 0)
        left = 0;
    return want < left ? want : left;
}

/* a sign that the NAT is short of ports: the UDP relay or the NAT probe
 * got no answer while a hard-side punch held them or just after (a carrier
 * NAT's quota: nothing new maps then). The platform hears it with the next
 * results (write_pressure) and keeps the caller's hard-side rounds apart */
void call_port_pressure(npf_node *n, const char *what)
{
    int64_t now = npf_mono_ms();
    if (!call_hard_punches(n, NULL) && !(n->hard_punch_end && now - n->hard_punch_end < PRESSURE_SEEN_MS))
        return;
    if (!n->port_pressure || now - n->port_pressure > PRESSURE_KEEP_MS)
        npf_log("punch: %s around a hard-side punch: the NAT may be short of ports (told to the platform)", what);
    n->port_pressure = now;
}

/* punching's one transition (architecture.md 3.2): the state and its
 * deadline (SCHEDULED, LINGER); a punch only in RUNNING and LINGER, of the
 * last round planned: a peer's port or candidate goes to its own round */
void call_punch_to(npf_call *c, int st, int64_t at)
{
    if (st != PN_RUNNING && st != PN_LINGER) {
        npf_punch_free(c->punch);
        c->punch = NULL;
        socks_back(c);              /* a running hard-side one's sockets */
    }
    c->punch_st = st;
    c->punch_at = at;
    if (at)
        call_at(c, at);
}

/* S2B: this side's fresh mapping, to the peer (punch_info, nat-traversal.md 7.6) */
static void punch_info_send(npf_punch *p, uint16_t port, void *arg)
{
    npf_call *c = arg;
    npf_out w = {0};
    (void)p;
    npf_out_jobj(&w);
    npf_out_kstr(&w, "call_id", c->call_id_s);
    npf_out_kint(&w, "round", c->punch_round);
    npf_out_kint(&w, "port", port);
    npf_out_jend(&w);
    if (!w.failed)
        npf_node_send(c->n, "punch_info", 0, w.p);
    npf_out_free(&w);
}

/* an IPv4 address the node may send probes to (security.md H-1, under the
 * platform's own check): not unspecified, 0/8, loopback (but with a test
 * platform on this host, test_one_host), link-local, multicast, reserved or
 * the broadcast */
static int peer_ip4_ok(const npf_node *n, struct in_addr ip)
{
    uint32_t a = ntohl(ip.s_addr);
    if ((a >> 24) == 127)
        return n->cfg.test_one_host;
    return (a >> 24) != 0 && (a >> 16) != 0xa9fe && (a >> 28) < 0xe;
}

/* one of the platform's addresses this node knows (its probes, the call's
 * relays): ip only (port 0), or ip:port */
static int platform_addr(const npf_call *c, struct in_addr ip, uint16_t port)
{
    int i;
    for (i = 0; i < c->n->nprobe_ep && i < 3; i++)
        if (c->n->probe_ep[i].sin_addr.s_addr == ip.s_addr && (!port || ntohs(c->n->probe_ep[i].sin_port) == port))
            return 1;
    for (i = 0; i < c->pu.r.naddr && i < 4; i++) {
        const struct sockaddr_in *r = (const struct sockaddr_in *)&c->pu.r.addr[i];
        if (r->sin_family == AF_INET && r->sin_addr.s_addr == ip.s_addr && (!port || ntohs(r->sin_port) == port))
            return 1;
    }
    return 0;
}

/* a peer candidate the node may probe: an IPv4 one as above and not one of
 * the platform's endpoints; an IPv6 one not unspecified, loopback (but on
 * one host), link-local, multicast or v4-mapped */
static int peer_addr_ok(const npf_call *c, const struct sockaddr_storage *a)
{
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *v = (const struct sockaddr_in *)a;
        return v->sin_port != 0 && peer_ip4_ok(c->n, v->sin_addr) && !platform_addr(c, v->sin_addr, ntohs(v->sin_port));
    }
    if (a->ss_family == AF_INET6) {
        const struct in6_addr *v = &((const struct sockaddr_in6 *)a)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(v))
            return c->n->cfg.test_one_host;
        return ((const struct sockaddr_in6 *)a)->sin6_port != 0 && !IN6_IS_ADDR_UNSPECIFIED(v)
               && !IN6_IS_ADDR_LINKLOCAL(v) && !IN6_IS_ADDR_MULTICAST(v) && !IN6_IS_ADDR_V4MAPPED(v);
    }
    return 0;
}

/* a peer candidate a module says is no use here (npf_node.skip_cand: one
 * this host would send into a virtual interface of its own), or one this
 * node never sends to (peer_addr_ok) */
static int cand_skipped(const npf_call *c, const struct sockaddr_storage *to, const char *shown)
{
    if (!peer_addr_ok(c, to)) {
        npf_logw("call %s: the peer's candidate %s is not an address to send to: dropped", c->call_id_s, shown);
        return 1;
    }
    return c->n->skip_cand && c->n->skip_cand(c->n->skip_cand_arg, to, shown, c->call_id_s);
}

/* the peer's new srflx (the platform's: its spare's mapping toward the relay
 * moved, signaling.md punch_info): into the round running, else kept for the next */
static void peer_cand(npf_call *c, const m_cand *k)
{
    char a[80];
    if (call_over(c) || call_has_p2p(c) || call_has_ws(c) || call_no_p2p(c) || strcmp(k->t, "srflx") != 0
        || k->a.ss_family != AF_INET || cand_skipped(c, &k->a, npf_addr_str(&k->a, a, sizeof a)))
        return;
    if (c->tcand.ss_family && npf_addr_eq(&k->a, &c->tcand))
        return;
    c->tcand = k->a;
    npf_log("call %s: the peer's new srflx %s", c->call_id_s, a);
    if (c->punch_st == PN_RUNNING)
        npf_punch_add_peer(c->punch, &k->a, 1);
}

/* S2B: the peer's fresh mapping; its new srflx (cand) */
void call_on_punch_info(npf_call *c, const void *msg)
{
    const m_punch_info *m = msg;
    if (m->cand.a.ss_family) {
        peer_cand(c, &m->cand);
        return;
    }
    if (m->round != c->punch_round)
        return;                     /* another round's: not this one's (an old one ended at the new punch_start) */
    if (m->stop) {
        /* the caller let this round go (its hard-side punches one at a
         * time): no spray into nothing for the round's time */
        if (c->punch_st == PN_SCHEDULED || c->punch_st == PN_WAIT_KEYS) {
            call_punch_to(c, PN_NONE, 0);
            npf_log("call %s: punch round %lld let go by the peer: not started", c->call_id_s, (long long)m->round);
        } else if (c->punch_st == PN_RUNNING && !npf_punch_finished(c->punch))
            npf_punch_stop(c->punch);
        return;
    }
    if (!m->port)
        return;
    if (c->punch_st == PN_RUNNING)
        npf_punch_peer_port(c->punch, (uint16_t)m->port);
    else if (c->punch_st == PN_SCHEDULED || c->punch_st == PN_WAIT_KEYS)
        c->punch_port = (uint16_t)m->port;  /* the punch starts later (its time, the keys) */
}

/* nothing from the peer yet where it would have come (punch_ev.c, the
 * round goes on to its timeout for a late peer): the platform hears of the
 * failure now, a round planned otherwise comes sooner (signaling.md
 * punch_result early). Not while the UDP relay is unreachable and this punch
 * decides the WS relay (pm_decide, at its real end): a late peer's direct
 * path keeps the session off the WS relay, which cannot go direct */
static void punch_quiet(npf_punch *p, const npf_punch_result *res, void *arg)
{
    npf_call *c = arg;
    npf_out w = {0};
    (void)p;
    if (c->pm.wait == PM_IN_PUNCH)
        return;
    result_begin(c, &w, 0);
    npf_out_kbool(&w, "early", 1);
    result_counts(&w, res);
    result_send(c, &w);
}

/* this round let go (the caller's hard-side punches one at a time): the
 * platform tells the peer to end its part and sends the round again when
 * the punch holding the sockets ends (ends_in_ms, signaling.md punch_result
 * busy); not a failed round */
static void punch_busy(npf_call *c)
{
    int64_t now = npf_mono_ms(), ends = 0;
    const npf_call *o;
    npf_out w = {0};
    for (o = c->n->calls; o; o = o->next)
        if (o != c && o->punch_socks > 0 && npf_punch_ends_at(o->punch) - now > ends)
            ends = npf_punch_ends_at(o->punch) - now;
    result_begin(c, &w, 0);
    npf_out_kbool(&w, "busy", 1);
    npf_out_kint(&w, "ends_in_ms", ends);
    write_pressure(c, &w);
    result_send(c, &w);
}

/* S2's hard side, S2B: the first need probe servers measure this side's
 * fresh mapping (sent to the peer: punch_info_send); 0: fewer known */
static int punch_probes(npf_call *c, int need)
{
    const uint8_t *pk = node_day_key(c->n, c->n->probe_keys);
    int i;
    if (c->n->nprobe_ep < need || !pk)
        return 0;
    for (i = 0; i < need; i++)
        c->pcfg->probe_ep[i] = c->n->probe_ep[i];
    memcpy(c->pcfg->probe_key, pk, 32);
    memcpy(c->pcfg->ticket, c->n->ticket, sizeof c->pcfg->ticket);
    c->pcfg->clock_offset_ms = c->n->clock_offset_ms;
    c->pcfg->info = punch_info_send;
    return 1;
}

void call_punch_go(npf_call *c)
{
    if (!c->keys_ready) {
        call_punch_to(c, PN_WAIT_KEYS, 0);  /* NOMINATE needs the E2E key (nat-traversal.md 10.1) */
        return;
    }
    memcpy(c->pcfg->plan.nominate_key, c->nominate_key, 32);
    if (c->pcfg->plan.strategy == NPF_PUNCH_S3 && c->pcfg->plan.side == NPF_PUNCH_HARD) {
        int want = c->pcfg->plan.n_sockets, budget = npf_node_punch_budget(c->n);
        int full = want < budget ? want : budget;      /* the most it could get with nothing else running */
        c->pcfg->plan.n_sockets = punch_sockets_grant(c, want);
        if (c->caller && (c->pcfg->plan.n_sockets < full / 2 || call_hard_punches(c->n, c) >= HARD_PUNCHES_MAX)) {
            /* too few to hit anything (the phone on an APDM CGNAT at a start,
             * eight sessions at once: the last four had none, 0 replies), or
             * enough punches at once (five of them: the carrier NAT dropped the
             * relay binds too): this round is let go (busy), the platform sends
             * it again when the other punch ends; it does not count */
            if (c->pcfg->plan.n_sockets < full / 2)
                npf_log("call %s: punch round %d: %d of %d hard-side sockets free: busy until another punch ends",
                        c->call_id_s, c->punch_round, c->pcfg->plan.n_sockets, want);
            else
                npf_log("call %s: punch round %d: another hard-side punch holds the NAT's ports: waiting for it to end",
                        c->call_id_s, c->punch_round);
            punch_busy(c);          /* the peer's part ends now: no spray into nothing */
            call_punch_to(c, PN_NONE, 0);   /* the round comes again */
            return;
        }
        if (c->pcfg->plan.n_sockets < want)
            npf_log("call %s: punch round %d: %d of %d hard-side sockets (other punches hold the rest)",
                    c->call_id_s, c->punch_round, c->pcfg->plan.n_sockets, want);
    }
    c->pcfg->fd6 = c->n->udp6_fd;
    c->pcfg->test_deaf = c->n->th.punch_fail_ms != 0;
    c->pcfg->quiet = punch_quiet;
    if (c->pcfg->plan.measure && !punch_probes(c, 1))  /* S2's hard side: its first new socket's mapping, from E1 */
        c->pcfg->plan.measure = 0;      /* the easy side sprays the predicted ports */
    if (c->pcfg->plan.strategy == NPF_PUNCH_S2B && !punch_probes(c, 2)) {
        npf_punch_result res;
        npf_logw("call %s: punch round %d S2B: no probe servers to measure the fresh mapping with", c->call_id_s,
                 c->punch_round);
        memset(&res, 0, sizeof res);    /* a failed round: reported, and the next one asked for */
        call_punch_done(NULL, &res, -1, c);
        return;
    }
    if (!(c->punch = npf_punch_new(c->n->loop, c->pcfg, c->n->udp_fd, call_punch_done, c))) {
        call_punch_to(c, PN_IDLE, 0);
        return;
    }
    c->punch_socks = c->pcfg->plan.n_sockets;
    call_punch_to(c, PN_RUNNING, 0);
    /* the peer's new srflx, when the plan was made before it came (later
     * ones have the peer's fresh candidates): the hard side's sockets aim at
     * it; the peer's port of this round, come before it started */
    if (c->tcand.ss_family)
        npf_punch_add_peer(c->punch, &c->tcand, 1);
    if (c->punch_port)
        npf_punch_peer_port(c->punch, c->punch_port);
}

/* the call's tick (call_tick, punch_at): a round's start, a punch's linger over */
void call_punch_tick(npf_call *c)
{
    if (c->punch_st == PN_SCHEDULED)
        call_punch_go(c);
    else if (c->punch_st == PN_LINGER)
        call_punch_to(c, PN_IDLE, 0);
}

/* Behind a firewall that blocks a flow whose first packet is an unsolicited
 * inbound one: open the flows to the peer's candidates at once, before the
 * punch. The punch itself waits for the E2E keys, and a callee that pairs
 * with a password (three handshake messages, the last one from the caller)
 * gets them after the start time: the peer's first probes would arrive
 * first and the flow stay blocked (a Mac callee <-> a Linux caller, 5 of
 * 5). One byte, twice: nothing the peer reads (a node drops it silently).
 * Only once the keys are there: the platform plans a pairing's rounds after
 * its handshake checked out (handshake_done), and a call the handshake has
 * not admitted gets nothing */
static void firewall_open(npf_call *c)
{
    static const uint8_t one[1] = {0};
    int i, k;
    if (!c->pcfg || !c->keys_ready)
        return;                     /* nothing to anyone the handshake has not admitted */
    for (k = 0; k < 2; k++)
        for (i = 0; i < c->pcfg->npeers; i++)
            if (c->pcfg->peers[i].ss_family == AF_INET || c->n->udp6_fd >= 0)
                npf_udp_send(c->pcfg->peers[i].ss_family == AF_INET6 ? c->n->udp6_fd : c->n->udp_fd, one, 1,
                             &c->pcfg->peers[i]);
    npf_logd("call %s: firewall: flows to %d peer candidates opened before the punch", c->call_id_s, c->pcfg->npeers);
}

void call_on_punch_start(npf_call *c, const void *msg)
{
    const m_punch_start *m = msg;
    const char *strat = m->strategy[0] ? m->strategy : "S1";
    npf_punch_plan *pl;
    int64_t v, start_at;
    int i;
    if (!c->caller)
        call_accept(c);
    if (call_has_p2p(c) || call_has_ws(c))       /* a WS relay session cannot move to a direct path */
        return;
    if (call_no_p2p(c)) {                /* secure, or tests: the session stays on the relay */
        npf_log("call %s: punching disabled (%s)", c->call_id_s, c->secure ? "connect_mode secure" : "NPF_NO_P2P");
        return;
    }
    /* an old or repeated round changes nothing (it wiped the plan of the
     * round waiting for its start time: that one then probed no one) */
    if (m->round <= c->punch_round)
        return;
    /* the platform plans PUNCH_ROUNDS_MAX counted rounds and some let go;
     * far more is not ours to spray (a platform using the device to flood
     * addresses) */
    if (m->round > 4 * PUNCH_ROUNDS_MAX) {
        npf_logw("call %s: punch round %lld refused (more rounds than the platform plans)", c->call_id_s,
                 (long long)m->round);
        return;
    }
    c->punch_round = (int)m->round;
    call_punch_to(c, PN_NONE, 0);               /* the last round's punch ends: this one replaces it */
    c->punch_port = 0;
    if (!c->pcfg && !(c->pcfg = malloc(sizeof *c->pcfg)))
        return;
    memset(c->pcfg, 0, sizeof *c->pcfg);
    pl = &c->pcfg->plan;
    if (strcmp(m->skip, "no_strategy") == 0) {
        /* both NATs hard, nothing that can work between them (nat-traversal.md
         * 7.1): no round, none comes until the platform hears of a network
         * change (punch_update) */
        npf_log("call %s: punch round %d: both NATs are hard, no strategy works between them: the session stays on the relay",
                c->call_id_s, c->punch_round);
        call_punch_to(c, PN_IDLE, 0);
        pm_check(c);
        return;
    }
    if (!m->punch_id_len || !m->punch_key_len)
        return;
    memcpy(pl->punch_key, m->punch_key, 32);
    pl->session_id = npf_rd64(m->punch_id);
    pl->role = c->caller ? NPF_PUNCH_CONTROLLING : NPF_PUNCH_CONTROLLED;
    pl->family = AF_INET;
    /* S2 (sequential allocation) is S3 over the predicted ports: the range says
     * which; S4 is S3 with a hard sprayer (its main socket sprays, the other
     * side's fresh sockets catch); S2B is its own (two sequential NATs) */
    pl->strategy = strcmp(strat, "S3") == 0 || strcmp(strat, "S2") == 0 || strcmp(strat, "S4") == 0
                       ? NPF_PUNCH_S3 : strcmp(strat, "S2B") == 0 ? NPF_PUNCH_S2B : NPF_PUNCH_S1;
    pl->side = strcmp(m->side, "hard") == 0 ? NPF_PUNCH_HARD : NPF_PUNCH_EASY;
    for (i = 0; i < m->peer.ncand && c->pcfg->npeers < NPF_PUNCH_MAX_PEERS; i++) {
        const m_cand *k = &m->peer.cand[i];
        char a[80];
        if ((k->a.ss_family != AF_INET && (k->a.ss_family != AF_INET6 || c->n->udp6_fd < 0))
            || cand_skipped(c, &k->a, npf_addr_str(&k->a, a, sizeof a)))
            continue;
        c->pcfg->peers[c->pcfg->npeers] = k->a;
        if (!pl->peer_srflx_len && strcmp(k->t, "srflx") == 0) {
            pl->peer_srflx = k->a;
            pl->peer_srflx_len = sizeof(struct sockaddr_in);
        }
        /* the pairs' priority (nat-traversal.md 10.1): nominated first */
        c->pcfg->prio[c->pcfg->npeers++] = strcmp(k->t, "host6") == 0 ? 4 : strcmp(k->t, "mapped") == 0 ? 3
                                           : strcmp(k->t, "host4") == 0 ? 2 : 1;
    }
    /* the peer's public IPv4 the sprays aim at: as a candidate, and not one
     * of the platform's IPs (whatever the port). Said once a call, when the
     * plan sprays: a WARN when the address is none to send to at all, INFO
     * when it is the platform's (a peer on a server's host: nothing wrong) */
    if (inet_pton(AF_INET, m->peer.pub_ip, &pl->peer_ip4) == 1
        && (!peer_ip4_ok(c->n, pl->peer_ip4) || platform_addr(c, pl->peer_ip4, 0))) {
        int sprays = (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY) || pl->strategy == NPF_PUNCH_S2B;
        if (sprays && !c->spray_refused_said) {
            c->spray_refused_said = 1;
            if (peer_ip4_ok(c->n, pl->peer_ip4))
                npf_log("call %s: the peer's public IP %s is the platform's: none sprayed at it", c->call_id_s,
                        m->peer.pub_ip);
            else
                npf_logw("call %s: the peer's public IP %s is not an address to spray: none sprayed", c->call_id_s,
                         m->peer.pub_ip);
        }
        pl->peer_ip4.s_addr = 0;
    }
    if (m->nrange == 2) {
        pl->range_lo = (uint16_t)m->range[0];
        pl->range_hi = (uint16_t)m->range[1];
    }
    pl->m_total = (int)m->m_total;
    pl->pps = (int)m->pps;
    pl->n_sockets = (int)m->n_sockets;
    pl->timeout_ms = (int)m->timeout_ms;
    pl->own_delta = (int)m->delta;
    pl->peer_delta = (int)m->peer_delta;
    pl->window = (int)m->window;
    pl->passes = (int)m->passes;
    /* S2 (nat-traversal.md 7.3): the hard side measures its port, the easy
     * side sprays after it (the hard side's step and sockets) */
    pl->measure = strcmp(strat, "S2") == 0 && pl->side == NPF_PUNCH_HARD;
    pl->peer_n = strcmp(strat, "S2") == 0 && pl->side == NPF_PUNCH_EASY ? (int)m->peer_n : 0;
    if (c->n->th.punch_fail_ms)         /* tests: every round fails, after this */
        pl->timeout_ms = (int)c->n->th.punch_fail_ms;
    if (c->n->th.s3_hard) {             /* tests: this side opens N sockets (the node budget) */
        pl->strategy = NPF_PUNCH_S3;
        pl->side = NPF_PUNCH_HARD;
        pl->n_sockets = (int)c->n->th.s3_hard;
    }
    start_at = m->start_at >= 0 ? m->start_at : npf_node_time(c->n);
    npf_log("call %s: punch round %d %s %s, %d peer candidates, start in %lld ms", c->call_id_s, c->punch_round, strat,
            pl->side == NPF_PUNCH_HARD ? "hard" : "easy", c->pcfg->npeers, (long long)(start_at - npf_node_time(c->n)));
    /* a host whose firewall blocks a flow that starts with an unsolicited
     * inbound packet (macOS application firewall) sends its first probes
     * before the peer's can arrive; the peer drops what comes before its own
     * start (npf_firewall_lead_ms) */
    if (c->n->punch_lead_ms > 0 && !(pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD))
        firewall_open(c);
    v = start_at - npf_node_time(c->n) - c->n->punch_lead_ms;
    v += c->n->th.punch_delay_ms;       /* tests: this side starts late (a slow plan, as over a loaded link) */
    call_punch_to(c, PN_SCHEDULED, npf_mono_ms() + (v > 0 ? v : 0));
}
/* the NAT measured again: after a network change (npf_node_network,
 * network), or a probe that may bring candidates the calls lacked (profile):
 * each call's platform hears it (punch_update) and decides */
void node_calls_punch_report(npf_node *n, const char *why)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next)
        call_punch_report(c, why);
}

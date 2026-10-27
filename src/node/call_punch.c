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
static void write_pressure(const npf_call *c, npf_jw *w)
{
    const npf_node *n = c->n;
    int64_t now = npf_mono_ms();
    const char *t;
    if ((n->port_pressure && now - n->port_pressure < PRESSURE_KEEP_MS) || getenv("NPF_TEST_PUNCH_GAP_MS")) {
        npf_jw_kbool(w, "pressure", 1);
        npf_jw_kint(w, "hard_ago_ms", n->hard_punch_end ? now - n->hard_punch_end : -1);
    }
    if ((t = getenv("NPF_TEST_PUNCH_GAP_MS")) != NULL)
        npf_jw_kint(w, "test_gap_ms", atoll(t));
    if ((t = getenv("NPF_TEST_REPUNCH_MS")) != NULL)
        npf_jw_kint(w, "test_backoff_ms", atoll(t));
}

/* the platform hears what changed for the call's rounds (punch_update):
 * why "network" (the NAT measured again after a network change), "profile"
 * (measured again: candidates may have come), "path_lost" (the direct path
 * given up); with this side's profile and candidates. The platform decides
 * whether and when a round comes */
void call_punch_report(npf_call *c, const char *why)
{
    char data[4096];
    npf_jw w;
    if (c->ended || c->ws_mode || c->direct || call_no_p2p(c) || !c->accepted)
        return;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kstr(&w, "why", why);
    npf_node_write_nat(c->n, &w);
    npf_node_write_cands(c->n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0) {
        npf_logd("call %s: punch_update (%s)", c->call_id_s, why);
        npf_node_send(c->n, "punch_update", 0, data);
    }
}

static void linger_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_linger = NULL;
    npf_punch_free(c->punch);
    c->punch = NULL;
}
static void punch_done(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    npf_call *c = arg;
    char data[768], a[64], la[64];
    struct sockaddr_storage ls;
    socklen_t ll = sizeof ls;
    npf_jw w;
    (void)p;
    {
        int had = c->punch_socks > 0;
        c->punch_socks = 0;          /* finish() closed the extra sockets */
        if (had)
            call_punch_sockets_back(c->n);
    }
    c->punched = 1;
    call_ws_wait_end(c, res->ok);        /* the UDP relay was unreachable: a failed punch leaves the WS relay */
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kint(&w, "round", c->punch_of);
    npf_jw_kbool(&w, "ok", res->ok);
    if (res->ok) {
        getsockname(fd, (struct sockaddr *)&ls, &ll);
        npf_jw_key(&w, "path");
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "local", npf_addr_str(&ls, la, sizeof la));
        npf_jw_kstr(&w, "peer", npf_addr_str(&res->peer, a, sizeof a));
        npf_jw_end(&w);
    }
    npf_jw_kint(&w, "elapsed_ms", res->elapsed_ms);
    npf_jw_kint(&w, "probes_sent", res->probes_sent);
    npf_jw_kint(&w, "probes_recv", res->probes_recv);
    npf_jw_kint(&w, "rtt_ms", res->rtt_ms);
    if (res->nseen > 0) {           /* the peer's NAT as this round showed it (nat-traversal.md 7.8) */
        int i;
        npf_jw_key(&w, "seen");
        npf_jw_arr(&w);
        for (i = 0; i < res->nseen; i++)
            npf_jw_int(&w, res->seen[i]);
        npf_jw_end(&w);
    }
    write_pressure(c, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_send(c->n, "punch_result", 0, data);
    if (!res->ok) {
        npf_logw("call %s: punching failed after %d ms (%d probes sent, %d received)", c->call_id_s,
                res->elapsed_ms, res->probes_sent, res->probes_recv);
        c->t_linger = npf_timer_add(c->n->loop, 0, linger_done, c);
        return;                     /* the platform plans what comes next */
    }
    npf_log("call %s: direct path %s (%d ms)", c->call_id_s, npf_addr_str(&res->peer, a, sizeof a),
            res->elapsed_ms);
    c->p2p = 1;
    c->p2p_fd = fd;
    c->p2p_addr = res->peer;
    c->p2p_rx_ms = npf_mono_ms();
    c->p2p_since = c->p2p_rx_ms;
    if (fd != c->n->udp_fd && fd != c->n->udp6_fd) {
        c->p2p_owned = 1;
        npf_loop_add(c->n->loop, fd, NPF_EV_READ, call_p2p_input_cb, c);
    }
    c->t_linger = npf_timer_add(c->n->loop, PUNCH_LINGER_MS, linger_done, c);
    if (c->relay.active && !c->t_standby)
        c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
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

/* hard-side punches running now (another than c) */
int call_hard_punches(const npf_call *c)
{
    const npf_call *o;
    int k = 0;
    for (o = c->n->calls; o; o = o->next)
        if (o != c && o->punch && o->punch_socks > 0)
            k++;
    return k;
}

static int punch_sockets_grant(npf_call *c, int want)
{
    npf_call *o;
    int left = npf_node_punch_budget(c->n);
    for (o = c->n->calls; o; o = o->next)
        if (o != c && o->punch)
            left -= o->punch_socks;
    if (left < 0)
        left = 0;
    return want < left ? want : left;
}

/* a sign that the NAT is short of ports: the UDP relay or a mapping check
 * got no answer while a hard-side punch held them or just after (a carrier
 * NAT's quota: nothing new maps then). The platform hears it with the next
 * results (write_pressure) and keeps the caller's hard-side rounds apart */
void call_port_pressure(npf_node *n, const char *what)
{
    int64_t now = npf_mono_ms();
    const npf_call *o;
    int punching = 0;
    for (o = n->calls; o; o = o->next)
        punching |= o->punch && o->punch_socks > 0;
    if (!punching && !(n->hard_punch_end && now - n->hard_punch_end < PRESSURE_SEEN_MS))
        return;
    if (!n->port_pressure || now - n->port_pressure > PRESSURE_KEEP_MS)
        npf_log("punch: %s around a hard-side punch: the NAT may be short of ports (told to the platform)", what);
    n->port_pressure = now;
}

/* a punch gave its sockets (the NAT's ports) back: the relays that could
 * not bind meanwhile try again */
void call_punch_sockets_back(npf_node *n)
{
    npf_call *o;
    n->hard_punch_end = npf_mono_ms();
    for (o = n->calls; o; o = o->next)
        if (o->punch && o->punch_socks > 0)
            return;                     /* another one still holds them */
    for (o = n->calls; o; o = o->next)
        if (o->relay_waits_ports && !o->ended && !o->relay.bound && !o->ws_mode) {
            o->relay_waits_ports = 0;
            npf_log("call %s: the punch gave the NAT's ports back: trying the UDP relay again", o->call_id_s);
            call_relay_rebind(o);
        }
}

/* S2B: this side's fresh mapping, to the peer (punch_info, nat-traversal.md 7.6) */
static void punch_info_send(npf_punch *p, uint16_t port, void *arg)
{
    npf_call *c = arg;
    char data[160];
    npf_jw w;
    (void)p;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kint(&w, "round", c->punch_round);
    npf_jw_kint(&w, "port", port);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_send(c->n, "punch_info", 0, data);
}

static int cand_skipped(const npf_call *c, const struct sockaddr_storage *to, const char *shown);

/* this side's new srflx (the call-time check, nat.c) to the peer: a
 * candidate trickled into the call (nat-traversal.md 4.5) */
void call_cand_send(npf_call *c)
{
    char data[256], a[64];
    struct sockaddr_storage ss;
    npf_jw w;
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, &c->n->srflx, sizeof c->n->srflx);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kint(&w, "round", c->punch_round);
    npf_jw_key(&w, "cand");
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "t", "srflx");
    npf_jw_kstr(&w, "a", npf_addr_str(&ss, a, sizeof a));
    npf_jw_end(&w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) <= 0)
        return;
    npf_log("call %s: the new srflx %s to the peer", c->call_id_s, a);
    npf_node_send(c->n, "punch_info", 0, data);    /* the platform may start a round for it */
}

/* tests: NPF_TEST_PUNCH_INFO_EXTRA="addr,...": forged srflx candidates
 * sent to the peer once the call is accepted (the platform must drop them) */
void call_test_punch_info(npf_call *c)
{
    char buf[256], data[256], *tok, *save;
    npf_jw w;
    if (!getenv("NPF_TEST_PUNCH_INFO_EXTRA"))
        return;
    snprintf(buf, sizeof buf, "%s", getenv("NPF_TEST_PUNCH_INFO_EXTRA"));
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        npf_jw_init(&w, data, sizeof data);
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "call_id", c->call_id_s);
        npf_jw_kint(&w, "round", c->punch_round);
        npf_jw_key(&w, "cand");
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "t", "srflx");
        npf_jw_kstr(&w, "a", tok);
        npf_jw_end(&w);
        npf_jw_end(&w);
        if (npf_jw_finish(&w) > 0)
            npf_node_send(c->n, "punch_info", 0, data);
    }
}

void node_calls_srflx_changed(npf_node *n)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next) {
        if (c->ended || c->p2p || c->ws_mode || c->direct || call_no_p2p(c))
            continue;
        if (c->caller && c->state == NPF_CALL_CALLING)
            c->cand_later = 1;      /* the platform passes punch_info on once the call is accepted */
        else
            call_cand_send(c);
    }
}

/* the peer's new srflx: into the round running, else kept for the next */
static void peer_cand(npf_call *c, const npf_json *j, int o)
{
    char a[80];
    struct sockaddr_storage ss;
    if (c->ended || c->p2p || c->ws_mode || call_no_p2p(c))
        return;
    memset(&ss, 0, sizeof ss);
    if (!npf_json_eq(j, npf_json_get(j, o, "t"), "srflx") || npf_json_get_str(j, o, "a", a, sizeof a) <= 0
        || npf_addr_parse(a, &ss) != 0 || ss.ss_family != AF_INET || cand_skipped(c, &ss, a))
        return;
    if (c->tcand.ss_family && call_same_addr(&ss, &c->tcand))
        return;
    c->tcand = ss;
    npf_log("call %s: the peer's new srflx %s", c->call_id_s, a);
    if (c->punch && !npf_punch_finished(c->punch))
        npf_punch_add_peer(c->punch, &ss, 1);
}

/* S2B: the peer's fresh mapping; its new srflx (cand) */
void call_handle_punch_info(npf_call *c, const npf_json *j, int d)
{
    int64_t round, port;
    int stop = 0;
    int cand = npf_json_get(j, d, "cand");
    if (npf_json_get_int(j, d, "round", 0, 1000, &round) < 0)
        return;
    if (cand >= 0) {
        peer_cand(c, j, cand);
        return;
    }
    if (npf_json_bool(j, npf_json_get(j, d, "stop"), &stop) == 0 && stop) {
        /* the caller let this round go (its hard-side punches one at a
         * time): no spray into nothing for the round's time */
        if (round == c->punch_round && c->t_punch) {
            timer_stop(c->n->loop, &c->t_punch);
            npf_log("call %s: punch round %lld let go by the peer: not started", c->call_id_s, (long long)round);
        } else if (round == c->punch_round && c->punch_of == c->punch_round && c->punch && !npf_punch_finished(c->punch))
            npf_punch_stop(c->punch);
        return;
    }
    if (round < 1 || npf_json_get_int(j, d, "port", 1024, 65535, &port) < 0)
        return;
    if (round < c->punch_round)
        return;
    if (round == c->punch_round && c->punch)
        npf_punch_peer_port(c->punch, (uint16_t)port);
    else {                          /* the punch starts later (its time, the keys, its plan) */
        c->info_port = (uint16_t)port;
        c->info_round = (int)round;
    }
}

/* nothing from the peer yet where it would have come (punch_ev.c, the
 * round goes on to its timeout for a late peer): the platform hears of the
 * failure now, a round planned otherwise comes sooner (signaling.md
 * punch_result early). Not while the UDP relay is unreachable and this punch
 * decides the WS relay (call_ws_wait_end at its real end): a late peer's
 * direct path keeps the session off the WS relay, which cannot go direct */
static void punch_quiet(npf_punch *p, const npf_punch_result *res, void *arg)
{
    npf_call *c = arg;
    char data[256];
    npf_jw w;
    (void)p;
    if (c->t_ws_wait || c->ended || c->p2p)
        return;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kint(&w, "round", c->punch_of);
    npf_jw_kbool(&w, "ok", 0);
    npf_jw_kbool(&w, "early", 1);
    npf_jw_kint(&w, "elapsed_ms", res->elapsed_ms);
    npf_jw_kint(&w, "probes_sent", res->probes_sent);
    npf_jw_kint(&w, "probes_recv", res->probes_recv);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_send(c->n, "punch_result", 0, data);
}

/* this round let go (the caller's hard-side punches one at a time): the
 * platform tells the peer to end its part and sends the round again when
 * the punch holding the sockets ends (ends_in_ms, signaling.md punch_result
 * busy); not a failed round */
static void punch_busy(npf_call *c)
{
    char data[256];
    int64_t now = npf_mono_ms(), ends = 0;
    const npf_call *o;
    npf_jw w;
    for (o = c->n->calls; o; o = o->next)
        if (o != c && o->punch && o->punch_socks > 0 && !npf_punch_finished(o->punch)
            && npf_punch_ends_at(o->punch) - now > ends)
            ends = npf_punch_ends_at(o->punch) - now;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kint(&w, "round", c->punch_round);
    npf_jw_kbool(&w, "ok", 0);
    npf_jw_kbool(&w, "busy", 1);
    npf_jw_kint(&w, "ends_in_ms", ends);
    write_pressure(c, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_send(c->n, "punch_result", 0, data);
}

void call_start_punch_now(npf_call *c)
{
    if (!c->pcfg)
        return;                     /* no round came (punch_start makes it) */
    if (!c->keys_ready) {
        c->punch_wait_keys = 1;   /* NOMINATE needs the E2E key (nat-traversal.md 10.1) */
        return;
    }
    memcpy(c->pcfg->plan.nominate_key, c->nominate_key, 32);
    if (c->punch) {                 /* the last round's, lingering or still running */
        int had = c->punch_socks > 0;
        timer_stop(c->n->loop, &c->t_linger);
        npf_punch_free(c->punch);
        c->punch = NULL;
        c->punch_socks = 0;
        if (had)                    /* a running hard-side one: the calls waiting for its sockets */
            call_punch_sockets_back(c->n);
    }
    c->punch_socks = 0;
    c->punch_of = c->punch_round;
    if (c->pcfg->plan.strategy == NPF_PUNCH_S3 && c->pcfg->plan.side == NPF_PUNCH_HARD) {
        int want = c->pcfg->plan.n_sockets, budget = npf_node_punch_budget(c->n);
        int full = want < budget ? want : budget;      /* the most it could get with nothing else running */
        c->pcfg->plan.n_sockets = punch_sockets_grant(c, want);
        if (c->caller && (c->pcfg->plan.n_sockets < full / 2 || call_hard_punches(c) >= HARD_PUNCHES_MAX)) {
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
            c->punched = 1;
            punch_busy(c);          /* the peer's part ends now: no spray into nothing */
            return;
        }
        if (c->pcfg->plan.n_sockets < want)
            npf_log("call %s: punch round %d: %d of %d hard-side sockets (other punches hold the rest)",
                    c->call_id_s, c->punch_round, c->pcfg->plan.n_sockets, want);
    }
    if (c->tcand.ss_family) {       /* the peer's new srflx: among this round's candidates */
        npf_punch_plan *pl = &c->pcfg->plan;
        int i;
        for (i = 0; i < c->pcfg->npeers && !call_same_addr(&c->tcand, &c->pcfg->peers[i]); i++)
            ;
        /* not in the plan: made before it came (later ones have the peer's
         * fresh candidates); the hard side's sockets aim at it then */
        if (i == c->pcfg->npeers && pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD) {
            pl->peer_srflx = c->tcand;
            pl->peer_srflx_len = sizeof(struct sockaddr_in);
        }
        if (i == c->pcfg->npeers && c->pcfg->npeers < NPF_PUNCH_MAX_PEERS) {
            c->pcfg->prio[c->pcfg->npeers] = 1;
            c->pcfg->peers[c->pcfg->npeers++] = c->tcand;
        }
    }
    c->pcfg->fd6 = c->n->udp6_fd;
    c->pcfg->test_deaf = getenv("NPF_TEST_PUNCH_FAIL") != NULL;
    c->pcfg->quiet = punch_quiet;
    if (c->pcfg->plan.measure) {        /* S2's hard side: its first new socket's mapping, from E1 */
        const uint8_t *pk = node_day_key(c->n, c->n->probe_keys);
        if (c->n->nprobe_ep < 1 || !pk) {
            c->pcfg->plan.measure = 0;  /* the easy side sprays the predicted ports */
        } else {
            c->pcfg->probe_ep[0] = c->n->probe_ep[0];
            memcpy(c->pcfg->probe_key, pk, 32);
            memcpy(c->pcfg->ticket, c->n->ticket, sizeof c->pcfg->ticket);
            c->pcfg->clock_offset_ms = c->n->clock_offset_ms;
            c->pcfg->info = punch_info_send;
        }
    }
    if (c->pcfg->plan.strategy == NPF_PUNCH_S2B) {
        const uint8_t *pk = node_day_key(c->n, c->n->probe_keys);
        if (c->n->nprobe_ep < 2 || !pk) {
            npf_punch_result res;
            npf_logw("call %s: punch round %d S2B: no probe servers to measure the fresh mapping with",
                     c->call_id_s, c->punch_round);
            memset(&res, 0, sizeof res);    /* a failed round: reported, and the next one asked for */
            punch_done(NULL, &res, -1, c);
            return;
        }
        c->pcfg->probe_ep[0] = c->n->probe_ep[0];
        c->pcfg->probe_ep[1] = c->n->probe_ep[1];
        memcpy(c->pcfg->probe_key, pk, 32);
        memcpy(c->pcfg->ticket, c->n->ticket, sizeof c->pcfg->ticket);
        c->pcfg->clock_offset_ms = c->n->clock_offset_ms;
        c->pcfg->info = punch_info_send;
    }
    c->punch = npf_punch_new(c->n->loop, c->pcfg, c->n->udp_fd, punch_done, c);
    if (c->punch)
        c->punch_socks = c->pcfg->plan.n_sockets;
    if (c->punch && c->info_port && c->info_round == c->punch_round)
        npf_punch_peer_port(c->punch, c->info_port);
}

static void punch_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_punch = NULL;
    if (!c->p2p && !c->ended)       /* the last round's punch may have gone direct meanwhile */
        call_start_punch_now(c);
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
                call_udp_send(c, c->pcfg->peers[i].ss_family == AF_INET6 ? c->n->udp6_fd : c->n->udp_fd,
                         &c->pcfg->peers[i], one, 1);
    npf_logd("call %s: firewall: flows to %d peer candidates opened before the punch", c->call_id_s, c->pcfg->npeers);
}


/* a test platform on this host (test_one_host = 1, tests only): loopback
 * is this host's network */
static int lab_loopback(const npf_node *n)
{
    return n->cfg.test_one_host;
}

/* an IPv4 address the node may send probes to (security.md H-1, under the
 * platform's own check): not unspecified, 0/8, loopback (but in tests on one host),
 * link-local, multicast, reserved or the broadcast */
static int peer_ip4_ok(const npf_node *n, struct in_addr ip)
{
    uint32_t a = ntohl(ip.s_addr);
    if ((a >> 24) == 127)
        return lab_loopback(n);
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
    for (i = 0; i < c->relay.naddr && i < 4; i++) {
        const struct sockaddr_in *r = (const struct sockaddr_in *)&c->relay.addr[i];
        if (r->sin_family == AF_INET && r->sin_addr.s_addr == ip.s_addr && (!port || ntohs(r->sin_port) == port))
            return 1;
    }
    return 0;
}

/* a peer candidate the node may probe: an IPv4 one as above and not one of
 * the platform's endpoints; an IPv6 one not unspecified, loopback (but on
 * one host), link-local, multicast or v4-mapped */
int call_peer_addr_ok(const npf_call *c, const struct sockaddr_storage *a)
{
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *v = (const struct sockaddr_in *)a;
        return v->sin_port != 0 && peer_ip4_ok(c->n, v->sin_addr) && !platform_addr(c, v->sin_addr, ntohs(v->sin_port));
    }
    if (a->ss_family == AF_INET6) {
        const struct in6_addr *v = &((const struct sockaddr_in6 *)a)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(v))
            return lab_loopback(c->n);
        return ((const struct sockaddr_in6 *)a)->sin6_port != 0 && !IN6_IS_ADDR_UNSPECIFIED(v)
               && !IN6_IS_ADDR_LINKLOCAL(v) && !IN6_IS_ADDR_MULTICAST(v) && !IN6_IS_ADDR_V4MAPPED(v);
    }
    return 0;
}

/* an IPv4 address that may be sent to at all (peer_ip4_ok) */
int call_peer_ip4_usable(const npf_node *n, struct in_addr ip)
{
    return ip.s_addr != 0 && peer_ip4_ok(n, ip);
}

/* the peer's public IPv4 the sprays aim at: as a candidate, and not one of
 * the platform's IPs (whatever the port) */
int call_peer_spray_ok(const npf_call *c, struct in_addr ip)
{
    return ip.s_addr != 0 && peer_ip4_ok(c->n, ip) && !platform_addr(c, ip, 0);
}

/* a peer candidate a module says is no use here (npf_node.skip_cand: one
 * this host would send into a virtual interface of its own), or one this
 * node never sends to (call_peer_addr_ok) */
static int cand_skipped(const npf_call *c, const struct sockaddr_storage *to, const char *shown)
{
    if (!call_peer_addr_ok(c, to)) {
        npf_logw("call %s: the peer's candidate %s is not an address to send to: dropped", c->call_id_s, shown);
        return 1;
    }
    return c->n->skip_cand && c->n->skip_cand(c->n->skip_cand_arg, to, shown, c->call_id_s);
}

void call_handle_punch_start(npf_call *c, const npf_json *j, int d)
{
    npf_punch_plan *pl;
    int peer = npf_json_get(j, d, "peer"), arr, i;
    int64_t v, start_at;
    uint8_t pid[8];
    char s[64], strat[8] = "S1";
    if (!c->caller)
        call_accept_seen(c);
    if (c->p2p || c->ws_mode)       /* a WS relay session cannot move to a direct path */
        return;
    if (call_no_p2p(c)) {                /* secure, or tests: the session stays on the relay */
        npf_log("call %s: punching disabled (%s)", c->call_id_s, c->secure ? "connect_mode secure" : "NPF_NO_P2P");
        return;
    }
    /* an old or repeated round changes nothing (it wiped the plan of the
     * round waiting for its start time: that one then probed no one) */
    if (npf_json_get_int(j, d, "round", 1, 1000, &v) < 0 || v <= c->punch_round)
        return;
    /* the platform plans PUNCH_ROUNDS_MAX counted rounds and some let go;
     * far more is not ours to spray (a platform using the device to flood
     * addresses) */
    if (v > 4 * PUNCH_ROUNDS_MAX) {
        npf_logw("call %s: punch round %lld refused (more rounds than the platform plans)", c->call_id_s, (long long)v);
        return;
    }
    c->punch_round = (int)v;
    if (c->t_punch) {               /* the last round's start: this one replaces it */
        npf_timer_cancel(c->n->loop, c->t_punch);
        c->t_punch = NULL;
    }
    c->punch_wait_keys = 0;
    if (!c->pcfg && !(c->pcfg = calloc(1, sizeof *c->pcfg)))
        return;
    memset(c->pcfg, 0, sizeof *c->pcfg);
    pl = &c->pcfg->plan;
    if (npf_json_get(j, d, "skip") >= 0 && !npf_json_eq(j, npf_json_get(j, d, "skip"), "no_strategy")) {
        npf_log("call %s: punch round %d skipped", c->call_id_s, c->punch_round);
        return;
    }
    if (npf_json_eq(j, npf_json_get(j, d, "skip"), "no_strategy")) {
        /* both NATs hard, nothing that can work between them (nat-traversal.md
         * 7.1): no round, none comes until the platform hears of a network
         * change (punch_update) */
        npf_log("call %s: punch round %d: both NATs are hard, no strategy works between them: the session stays on the relay",
                c->call_id_s, c->punch_round);
        c->punched = 1;
        call_ws_wait_end(c, 0);
        return;
    }
    if (npf_json_get_b64(j, d, "punch_id", pid, 8) != 8 || npf_json_get_b64(j, d, "punch_key", pl->punch_key, 32) != 32)
        return;
    pl->session_id = npf_rd64(pid);
    pl->role = c->caller ? NPF_PUNCH_CONTROLLING : NPF_PUNCH_CONTROLLED;
    pl->family = AF_INET;
    npf_json_get_str(j, d, "strategy", strat, sizeof strat);
    /* S2 (sequential allocation) is S3 over the predicted ports: the range says
     * which; S4 is S3 with a hard sprayer (its main socket sprays, the other
     * side's fresh sockets catch); S2B is its own (two sequential NATs) */
    pl->strategy = strcmp(strat, "S3") == 0 || strcmp(strat, "S2") == 0 || strcmp(strat, "S4") == 0
                       ? NPF_PUNCH_S3 : strcmp(strat, "S2B") == 0 ? NPF_PUNCH_S2B : NPF_PUNCH_S1;
    pl->side = npf_json_eq(j, npf_json_get(j, d, "side"), "hard") ? NPF_PUNCH_HARD : NPF_PUNCH_EASY;
    arr = npf_json_get(j, peer, "cand");
    for (i = 0; arr >= 0 && i < j->tok[arr].size && c->pcfg->npeers < NPF_PUNCH_MAX_PEERS; i++) {
        char a[80];
        if (npf_json_get_str(j, npf_json_item(j, arr, i), "a", a, sizeof a) > 0
            && npf_addr_parse(a, &c->pcfg->peers[c->pcfg->npeers]) == 0
            && (c->pcfg->peers[c->pcfg->npeers].ss_family == AF_INET
                || (c->pcfg->peers[c->pcfg->npeers].ss_family == AF_INET6 && c->n->udp6_fd >= 0))
            && !cand_skipped(c, &c->pcfg->peers[c->pcfg->npeers], a)) {
            int t = npf_json_get(j, npf_json_item(j, arr, i), "t");
            if (!pl->peer_srflx_len && npf_json_eq(j, t, "srflx")) {
                pl->peer_srflx = c->pcfg->peers[c->pcfg->npeers];
                pl->peer_srflx_len = sizeof(struct sockaddr_in);
            }
            /* the pairs' priority (nat-traversal.md 10.1): nominated first */
            c->pcfg->prio[c->pcfg->npeers] = npf_json_eq(j, t, "host6") ? 4 : npf_json_eq(j, t, "mapped") ? 3
                                             : npf_json_eq(j, t, "host4") ? 2 : 1;
            c->pcfg->npeers++;
        }
    }
    if (npf_json_get_str(j, peer, "pub_ip", s, sizeof s) > 0 && inet_pton(AF_INET, s, &pl->peer_ip4) == 1
        && !call_peer_spray_ok(c, pl->peer_ip4)) {
        /* said once a call, when the plan sprays: a WARN when the address
         * is none to send to at all, INFO when it is the platform's (a peer
         * on a server's host: nothing wrong) */
        int sprays = (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY) || pl->strategy == NPF_PUNCH_S2B;
        if (sprays && !c->spray_refused_said) {
            c->spray_refused_said = 1;
            if (call_peer_ip4_usable(c->n, pl->peer_ip4))
                npf_log("call %s: the peer's public IP %s is the platform's: none sprayed at it", c->call_id_s, s);
            else
                npf_logw("call %s: the peer's public IP %s is not an address to spray: none sprayed", c->call_id_s, s);
        }
        pl->peer_ip4.s_addr = 0;
    }
    arr = npf_json_get(j, d, "range");
    if (arr >= 0 && j->tok[arr].size == 2) {
        int64_t lo, hi;
        if (npf_json_int(j, npf_json_item(j, arr, 0), 1, 65535, &lo) == 0
            && npf_json_int(j, npf_json_item(j, arr, 1), 1, 65535, &hi) == 0) {
            pl->range_lo = (uint16_t)lo;
            pl->range_hi = (uint16_t)hi;
        }
    }
    pl->m_total = npf_json_get_int(j, d, "m_total", 0, 4000, &v) == 0 ? (int)v : 1024;
    pl->pps = npf_json_get_int(j, d, "pps", 1, 1000, &v) == 0 ? (int)v : 200;
    pl->n_sockets = npf_json_get_int(j, d, "n_sockets", 0, 256, &v) == 0 ? (int)v : 0;
    pl->timeout_ms = npf_json_get_int(j, d, "timeout_ms", 1000, 600000, &v) == 0 ? (int)v : 8000;
    pl->own_delta = npf_json_get_int(j, d, "delta", -64, 64, &v) == 0 ? (int)v : 0;
    pl->peer_delta = npf_json_get_int(j, d, "peer_delta", -64, 64, &v) == 0 ? (int)v : 0;
    pl->window = npf_json_get_int(j, d, "window", 1, 128, &v) == 0 ? (int)v : 32;
    pl->passes = npf_json_get_int(j, d, "passes", 1, 8, &v) == 0 ? (int)v : 4;
    /* S2 (nat-traversal.md 7.3): the hard side measures its port, the easy
     * side sprays after it (the hard side's step and sockets) */
    pl->measure = strcmp(strat, "S2") == 0 && pl->side == NPF_PUNCH_HARD;
    pl->peer_n = strcmp(strat, "S2") == 0 && pl->side == NPF_PUNCH_EASY
                 && npf_json_get_int(j, d, "peer_n", 1, 256, &v) == 0 ? (int)v : 0;
    if (c->info_round != c->punch_round)
        c->info_port = 0;
    if (getenv("NPF_TEST_PUNCH_FAIL"))  /* tests: NPF_TEST_PUNCH_FAIL=ms: every round fails, after ms */
        pl->timeout_ms = atoi(getenv("NPF_TEST_PUNCH_FAIL"));
    if (getenv("NPF_TEST_S3_HARD")) {   /* tests: this side opens N sockets (the node budget) */
        pl->strategy = NPF_PUNCH_S3;
        pl->side = NPF_PUNCH_HARD;
        pl->n_sockets = atoi(getenv("NPF_TEST_S3_HARD"));
    }
    if (npf_json_get_int(j, d, "start_at", 0, INT64_MAX, &start_at) < 0)
        start_at = npf_node_time(c->n);
    npf_log("call %s: punch round %d %s %s, %d peer candidates, start in %lld ms", c->call_id_s,
                c->punch_round, strat,
                pl->side == NPF_PUNCH_HARD ? "hard" : "easy", c->pcfg->npeers,
                (long long)(start_at - npf_node_time(c->n)));
    if (c->t_punch)
        npf_timer_cancel(c->n->loop, c->t_punch);
    /* a host whose firewall blocks a flow that starts with an unsolicited
     * inbound packet (macOS application firewall) sends its first probes
     * before the peer's can arrive; the peer drops what comes before its own
     * start (npf_firewall_lead_ms) */
    if (c->n->punch_lead_ms > 0 && !(pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD))
        firewall_open(c);
    v = start_at - npf_node_time(c->n) - c->n->punch_lead_ms;
    if (getenv("NPF_TEST_PUNCH_DELAY"))     /* tests: this side starts late (a slow plan, as over a loaded link) */
        v += atoi(getenv("NPF_TEST_PUNCH_DELAY"));
    c->t_punch = npf_timer_add(c->n->loop, v > 0 ? v : 0, punch_timer, c);
}
/* the NAT measured again: after a network change (npf_node_network,
 * network), or a probe that may bring candidates the calls lacked (profile):
 * each call's platform hears it (punch_update) and decides */
void node_calls_punch_report(npf_node *n, const char *why)
{
    npf_call *c;
    if (getenv("NPF_NO_P2P"))
        return;
    for (c = n->calls; c; c = c->next)
        if (!c->p2p && !c->secure)
            call_punch_report(c, why);
}

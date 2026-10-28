/* The path manager (path.h, architecture.md 2.4): which of a session's
 * paths AnLiu's datagrams go on, the name of the one in use, the paths'
 * health by one set of rules; then the decisions between the paths a
 * session makes today (architecture.md 3.6 to come): the platform's relay
 * allocations, the relay's standby, the way to the WS relay when the UDP
 * relay cannot be reached. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

/* The health rules' times per kind (path.h pm_rules; nat-traversal.md
 * 10.3, data-channel.md 3). The direct path: silent 3 s (2 RTO) with data
 * in flight, 20 s without (the peer's AnLiu sends a keepalive every 15 s),
 * a PATH_CHECK every 500 ms, lost 10 s after. The UDP relay: the same
 * silences (20 s idle: the relay's 10 s was below AnLiu's keepalive and
 * bound it again every 10-15 s, architecture.md D3); its probe is a bind,
 * its address in use first (relay_bind_probe), its verdict every address
 * tried. The WS relay: TCP's own retransmission with data in flight; 30 s
 * without any frame (its ping every 25 s, the peer's keepalives) is a
 * half-open connection: connected again, DEAD after 5 that do not pair
 * (path_ws.c). */
const pm_rules pm_rules_of[PK_N] = {
    [PK_DIRECT]    = {3000, 20000, 500, 10000},
    [PK_UDP_RELAY] = {3000, 20000, 0, 0},
    [PK_WS_RELAY]  = {0, 30000, 0, 0},
};

static int64_t max64(int64_t a, int64_t b)
{
    return a > b ? a : b;
}

/* the roles from the paths in use and their health (path.h npf_pm); a
 * direct path given up carries nothing */
static void pm_route(npf_pm *m)
{
    npf_path *d = m->p[PK_DIRECT], *u = m->p[PK_UDP_RELAY], *w = m->p[PK_WS_RELAY];
    int k;
    if (d && d->health == PH_DEAD)
        d = NULL;
    for (k = 0; k < PK_N; k++)
        if (m->p[k])
            m->p[k]->role = PR_IDLE;
    m->primary = w ? w : d ? d : u;
    m->second = NULL;
    if (!w && d && u) {
        if (d->health == PH_SUSPECT)
            m->second = u;
        u->role = m->second ? PR_SECOND : PR_STANDBY;
    }
    if (m->primary)
        m->primary->role = PR_PRIMARY;
}

void pm_add(npf_pm *m, npf_path *p)
{
    m->p[p->kind] = p;
    pm_route(m);
}

void pm_del(npf_pm *m, npf_path *p)
{
    if (m->p[p->kind] != p)
        return;
    m->p[p->kind] = NULL;
    p->role = PR_IDLE;
    pm_route(m);
}

void pm_health(npf_pm *m, npf_path *p, int health)
{
    p->health = (uint8_t)health;
    if (m->p[p->kind] == p)
        pm_route(m);
}

void pm_suspect(npf_pm *m, npf_path *p, int64_t now)
{
    p->suspect_at = now;
    p->probe_at = now;
    p->probe_until = 0;
    pm_health(m, p, PH_SUSPECT);
}

void pm_probe(npf_pm *m, npf_path *p, int64_t now, int64_t window)
{
    (void)m;
    p->probe_at = now;
    p->probe_until = now + window;
}

int pm_rt(npf_pm *m, npf_path *p, int64_t now)
{
    p->rt_ok = now;
    p->probe_until = 0;
    if (p->health == PH_UP)
        return 0;
    p->busy_since = 0;
    pm_health(m, p, PH_UP);
    return 1;
}

void pm_dead(npf_pm *m, npf_path *p)
{
    pm_health(m, p, PH_DEAD);
}

int64_t pm_tick(npf_pm *m, int64_t now, uint32_t inflight, int rto)
{
    int64_t due = INT64_MAX;
    int k;
    for (k = 0; k < PK_N; k++) {
        npf_path *p = m->p[k];
        const pm_rules *r = &pm_rules_of[k];
        if (!p)
            continue;
        if (p->health == PH_UP && p->probe_until) {
            /* probed with no doubt (pm_probe): until a round trip or the window's end */
            if (now >= p->probe_until || !r->t_probe) {
                p->probe_until = 0;
            } else {
                if (now >= p->probe_at) {
                    p->probe_at = now + r->t_probe;
                    p->ops->probe(p);
                    if (m->p[k] != p || p->health != PH_UP)
                        continue;
                }
                due = due < p->probe_at ? due : p->probe_at;
                due = due < p->probe_until ? due : p->probe_until;
            }
        }
        if (p->health == PH_UP) {
            int64_t from, quiet;
            if (!pm_relied(m, p)) {
                p->busy_since = 0;
                continue;
            }
            /* silence counts from the later of the last datagram heard and
             * the moment data went in flight: after an idle spell the first
             * new request must not look like a path quiet all along. With
             * nothing in flight (a sender waiting for its peer's credit, an
             * idle session) a peer that is there still sends AnLiu's
             * keepalive every 15 s (measured: all of a node's UDP dropped
             * mid-download, the sender idle on credit) */
            if (inflight && r->t_busy) {
                if (!p->busy_since)
                    p->busy_since = now;
                quiet = max64(r->t_busy, 2 * (int64_t)rto);
                from = max64(p->last_rx, p->busy_since);
            } else {
                p->busy_since = 0;
                quiet = r->t_idle;
                from = max64(p->last_rx, p->since);
            }
            if (now - from < quiet) {
                due = due < from + quiet ? due : from + quiet;
                continue;
            }
            pm_suspect(m, p, now);
            p->ops->suspect(p, quiet);
            if (m->p[k] != p || p->health != PH_SUSPECT)
                continue;                   /* gone, or proven already */
        }
        if (p->health != PH_SUSPECT)
            continue;
        if (r->t_verdict && now - p->suspect_at >= r->t_verdict) {
            pm_dead(m, p);
            p->ops->dead(p);
            continue;
        }
        if (r->t_probe && now >= p->probe_at) {
            p->probe_at = now + r->t_probe;
            p->ops->probe(p);
            if (m->p[k] != p || p->health != PH_SUSPECT)
                continue;
        }
        if (r->t_probe && p->probe_at < due)
            due = p->probe_at;
        if (r->t_verdict && p->suspect_at + r->t_verdict < due)
            due = p->suspect_at + r->t_verdict;
    }
    return due;
}

const char *pm_name(const npf_pm *m)
{
    if (m->fixed)
        return "direct";
    return m->primary ? m->primary->ops->name(m->primary) : "none";
}

const char *pm_label(const npf_pm *m)
{
    if (m->fixed)
        return "Direct";
    if (!m->primary)
        return "none";
    return m->primary->kind == PK_DIRECT ? "P2P" : "Relayed";
}

/* npf.h's NPF_PATH_DIRECT, _UDP_RELAY, _WS_RELAY are 1 + the kind (test_path.c) */
int pm_code(const npf_pm *m)
{
    if (m->fixed)
        return 1 + PK_DIRECT;
    return m->primary ? 1 + m->primary->kind : 0;
}

/* a new call's paths: none in use */
void call_paths_init(npf_call *c)
{
    c->pd.p.ops = &path_direct_ops;
    c->pd.p.kind = PK_DIRECT;
    c->pd.fd = -1;
    c->pu.p.ops = &path_udp_ops;
    c->pu.p.kind = PK_UDP_RELAY;
    c->pw.p.ops = &path_ws_ops;
    c->pw.p.kind = PK_WS_RELAY;
}


/* ---- the session's paths' health ---- */

static void pm_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pm.t_check = NULL;
    pm_check(c);
}

/* The health rules now (pm_tick) for a session with its AnLiu connection:
 * from AnLiu's timer, the manager's own (at the next thing due: a probe, a
 * verdict, a silence long enough; earlier only when it moved earlier, as
 * AnLiu's timer, call_transport.c:anl_after_input) and the events that
 * change a path's health. Nothing on the hot path: a datagram only writes
 * its path's last_rx. */
void pm_check(npf_call *c)
{
    anl_stats st;
    int64_t now, due;
    int k, busy = 0;
    if (c->ended || !c->anl)
        return;
    /* AnLiu's stats only for a path whose rules look at the data in
     * flight (the WS relay's do not) */
    for (k = 0; k < PK_N; k++)
        busy |= c->pm.p[k] && c->pm.p[k]->health == PH_UP && pm_rules_of[k].t_busy && pm_relied(&c->pm, c->pm.p[k]);
    memset(&st, 0, sizeof st);
    if (busy && anl_get_stats(c->anl, &st) < 0)
        return;
    now = npf_mono_ms();
    if (call_has_ws(c))
        path_ws_heard(c);
    due = pm_tick(&c->pm, now, st.inflight, (int)st.rto);
    if (c->ended || due == INT64_MAX || (c->pm.t_check && c->pm.check_at <= due))
        return;
    npf_timer_stop(c->n->loop, &c->pm.t_check);
    c->pm.check_at = due;
    c->pm.t_check = npf_timer_add(c->n->loop, due > now ? due - now : 0, pm_timer, c);
}


/* ---- the session's decisions between its paths ---- */

/* the direct path up (or alive again): the UDP relay stands by for
 * RELAY_STANDBY_MS, then goes (call_standby_done) */
void pm_standby_start(npf_call *c)
{
    if (call_has_relay(c) && !c->pu.t_standby)
        c->pu.t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
}

#define STANDBY_CHECK_MS 10000      /* the direct path's check before the relay goes: its echo within this */

/* the direct path held for 30 s: stop using the relay; the caller tells the
 * platform to free both allocations (data-channel.md 3) */
void call_standby_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    char data[96];
    (void)loop;
    c->pu.t_standby = NULL;
    if (!call_has_p2p(c) || !call_has_relay(c))
        return;
    if (c->pd.p.health == PH_SUSPECT) {   /* not while the direct path is in doubt */
        if (!c->pd.standby_check)
            c->pu.t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
        return;
    }
    if (c->pd.p.rt_ok < c->pd.p.since) {
        /* the punch proved only that the peer's datagrams reach us (a path
         * cut one way still passes it): a path check answered over the direct
         * path first, else the session would lose the relay it still needs.
         * A probe, not a doubt (it was: the data on both paths meanwhile and,
         * with no echo in 10 s, the direct path given up): no echo, the relay
         * stands by on and the check comes again; a path dead one way goes
         * silent in the peer's direction and the health rules find it */
        if (!c->pd.standby_check) {
            c->pd.standby_check = 1;
            path_direct_check(c);
            pm_probe(&c->pm, &c->pd.p, npf_mono_ms(), STANDBY_CHECK_MS);
            pm_check(c);
            c->pu.t_standby = npf_timer_add(c->n->loop, STANDBY_CHECK_MS, call_standby_done, c);
            return;
        }
        c->pd.standby_check = 0;
        npf_log("call %s: no echo over the direct path in %d s: the relay stands by %d s more", c->call_id_s,
                STANDBY_CHECK_MS / 1000, RELAY_STANDBY_MS / 1000);
        c->pu.t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
        return;
    }
    path_udp_off(c);
    c->pu.r.bound = 0;
    npf_timer_stop(c->n->loop, &c->pu.r.t_bind);
    if (c->caller) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        npf_node_send(c->n, "relay_release", 0, data);
    }
    npf_log("call %s: relay released", c->call_id_s);
}

/* the platform's relay allocation (the reply to the call, incoming,
 * call_accepted, relay_switch): the UDP relay's (path_udp_setup) or the WS
 * relay's (call_ws_setup) */
void call_relay_setup(npf_call *c, const npf_json *j, int d)
{
    int r = npf_json_get(j, d, "relay"), naddr;
    char mode[8];
    uint8_t id[8], key[32];
    struct sockaddr_storage addr[4];
    if (r < 0 || j->tok[r].type != NPF_JT_OBJECT || (naddr = relay_obj_parse(j, r, mode, id, key, addr)) < 0)
        return;
    if (strcmp(mode, "ws") == 0) {
        if (call_has_ws(c) && (c->pw.wsr || c->pw.fail_wait) && memcmp(id, c->pu.r.relay_id, 8) == 0)
            return;                 /* the one in use, sent again (both sides asked; the reply to the
                                     * call, then call_accepted): its sublinks stay */
        call_relay_take(c, id, key, NULL, 0);
        if (call_ws_setup(c, j, r) < 0)
            call_ws_failed(c, "cannot connect");
        return;
    }
    if (strcmp(mode, "udp") != 0 || !naddr)
        return;
    /* from the WS relay back to UDP (udp_back): the same AnLiu connection,
     * a datagram carrier again; punching rounds come again too */
    call_ws_leave(c);
    path_udp_setup(c, id, key, addr, naddr);
}

/* the WS relay for this call (relay_switch{mode:"ws"}); the platform moves both sides */
void call_ask_ws_relay(npf_call *c)
{
    char data[128];
    npf_timer_stop(c->n->loop, &c->pm.t_ws_wait);
    if (call_has_ws(c))                 /* on it already */
        return;
    npf_log("call %s: asking for the WS relay", c->call_id_s);
    snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"ws\"}", c->call_id_s);
    npf_node_send(c->n, "relay_switch", 0, data);
    call_relay_asked(c);
    /* UDP believed to work: measured again, so that when it fails the profile
     * says so and the probe's retries see it come back (udp_back brings the
     * session back to UDP) */
    if (c->n->nat_valid && c->n->nat_udp && !c->n->probe && c->n->udp_fd >= 0)
        node_nat_refresh(c->n);
}

/* may a relay_switch go out: none is waiting for its allocation, or the last
 * one is RELAY_ASK_AGAIN_MS old. The platform drops some without a word (the
 * call not accepted yet, no token left, refused before the session is up, no
 * relay to give): a session asked once only never had a relay again */
int call_relay_ask_ok(const npf_call *c)
{
    return !c->pm.asked_ms || npf_mono_ms() - c->pm.asked_ms >= RELAY_ASK_AGAIN_MS;
}

void call_relay_asked(npf_call *c)
{
    int64_t now = npf_mono_ms();
    c->pm.asked_ms = now ? now : 1;
}

static void ws_wait_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pm.t_ws_wait = NULL;
    c->pu.waits_ports = 0;
    if (!call_has_p2p(c) && !c->pu.r.bound) {
        npf_log("call %s: no direct path within %d s", c->call_id_s, WS_WAIT_MS / 1000);
        call_ask_ws_relay(c);
    }
}

/* every address of the UDP relay tried (relay_bind_run) */
void call_relay_gave_up(void *arg)
{
    npf_call *c = arg;
    if (c->caller && c->state == NPF_CALL_CALLING) {
        /* bound from the reply to the call, before the callee accepted:
         * the platform takes no relay_switch yet. The accept brings the
         * same allocation, which binds it again from its first address
         * (call_relay_setup), the usual way on from there */
        npf_log("call %s: UDP relay unreachable before the accept: binding it again then", c->call_id_s);
    } else if (call_has_p2p(c)) {
        /* in doubt (SUSPECT): the verdict decides (lost: the WS relay,
         * path_direct.c:direct_lost); no punching on the WS relay */
        npf_log("call %s: UDP relay unreachable; the direct path carries the session%s", c->call_id_s,
                c->pd.p.health == PH_SUSPECT ? " while it is checked" : "");
    } else if (!c->pu.ports_waited && call_hard_punches(c) > 0) {
        /* a hard-side punch holds hundreds of the NAT's ports: a carrier
         * NAT with a quota of them (the phone's APDM CGNAT, about 500) then
         * maps nothing new, the relay included. Measured: every relay bind
         * failed while two punches ran, the next one after them bound at
         * once. Again when they end (call_punch_sockets_back), WS_WAIT_MS at most */
        npf_log("call %s: UDP relay unreachable while a punch holds the NAT's ports: trying again when it ends",
                c->call_id_s);
        c->pu.ports_waited = 1;
        c->pu.waits_ports = 1;
        call_port_pressure(c->n, "the UDP relay unreachable");
        if (!c->pm.t_ws_wait)
            c->pm.t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
    } else if (!c->punched && !call_no_p2p(c)) {
        /* a WS relay session gets no punching rounds (they come back
         * only with UDP): let the first punch round decide.
         * Measured: a Linux node's UDP relay unreachable 2 s before the
         * punch plan arrived, the direct path up 6 s later, the session
         * stuck on the WS relay at 14 KB/s */
        npf_log("call %s: UDP relay unreachable; waiting for the punch before asking for the WS relay",
                c->call_id_s);
        if (!c->pm.t_ws_wait)
            c->pm.t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
    } else {
        npf_log("call %s: UDP relay unreachable", c->call_id_s);
        call_ask_ws_relay(c);
    }
}

/* a round that did not go direct (failed, or none planned) while the UDP
 * relay was unreachable: the UDP relay once more, then the WS relay */
void call_ws_wait_end(npf_call *c, int ok)
{
    if (!c->pm.t_ws_wait)
        return;
    npf_timer_stop(c->n->loop, &c->pm.t_ws_wait);
    if (!ok && !c->pu.r.bound && c->pu.r.t_bind) {
        /* the UDP relay is being bound again (the punch gave the NAT's ports
         * back): its answer first; when it gives up, relay_bind_timer asks
         * for the WS relay (asked here at once, a bind about to succeed was
         * replaced: the phone's sessions, measured) */
        npf_log("call %s: the UDP relay is being bound: its answer before the WS relay", c->call_id_s);
        return;
    }
    if (!ok && !c->pu.retried && !c->pu.r.bound && !c->pu.r.t_bind) {
        /* once more first: a WS relay session gets no punching rounds, and
         * the UDP relay may have been lost to a passing storm (the phone at a
         * start, five punches at once: its binds went unanswered for 5 s) */
        npf_log("call %s: trying the UDP relay once more before the WS relay", c->call_id_s);
        c->pu.retried = 1;
        call_relay_rebind(c);
    } else if (!ok) {
        call_ask_ws_relay(c);
    }
}

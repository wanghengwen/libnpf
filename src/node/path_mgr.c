/* The path manager (path.h, architecture.md 2.4): which of a session's
 * paths AnLiu's datagrams go on, and the name of the one in use; then the
 * decisions between the paths a session makes today (architecture.md 3.6
 * to come): the platform's relay allocations, the relay's standby, the way
 * to the WS relay when the UDP relay cannot be reached. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

/* the roles from the paths in use and their health (path.h npf_pm) */
static void pm_route(npf_pm *m)
{
    npf_path *d = m->p[PK_DIRECT], *u = m->p[PK_UDP_RELAY], *w = m->p[PK_WS_RELAY];
    int k;
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


/* ---- the session's decisions between its paths ---- */

/* the direct path up (or alive again): the UDP relay stands by for
 * RELAY_STANDBY_MS, then goes (call_standby_done) */
void pm_standby_start(npf_call *c)
{
    if (call_has_relay(c) && !c->pu.t_standby)
        c->pu.t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
}

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
    if (c->pd.suspect) {   /* not while the direct path is in doubt */
        if (!c->pd.standby_check)
            c->pu.t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
        return;
    }
    if (c->pd.echo_ms < c->pd.p.since) {
        /* the punch proved only that the peer's datagrams reach us (a path
         * cut one way still passes it): a path check answered over the direct
         * path first, else the session would lose the relay it still needs */
        c->pd.standby_check = 1;
        path_direct_suspect(c, npf_mono_ms());
        path_direct_check(c);
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
        /* in doubt (p2p_suspect): the verdict decides (lost: the WS
         * relay, check_p2p); no punching on the WS relay */
        npf_log("call %s: UDP relay unreachable; the direct path carries the session%s", c->call_id_s,
                c->pd.suspect ? " while it is checked" : "");
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

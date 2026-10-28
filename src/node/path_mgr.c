/* The path manager (path.h, architecture.md 2.4, 3.6): which of a session's
 * paths AnLiu's datagrams go on, the name of the one in use, the paths'
 * health by one set of rules, the decisions between them (what to wait for,
 * what the session needs of the platform: pm_decide), and the session's
 * side of them: the platform's relay allocations, the relay's standby, the
 * requests and their deadlines (call_need). */
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
 * its address in use first (path_udp.c:bind_run), its verdict every address
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

static int pm_wait(npf_pm *m, unsigned wait, int64_t at, int r)
{
    m->wait = wait;
    m->act_at = at;
    return r;
}

/* What the session needs (path.h), by architecture.md 3.6, from its paths'
 * health and the inputs; each decision once, at the event or the time
 * (act_at) that makes it. The WS relay given up: one elsewhere (the caller
 * asks); UDP working: the UDP relay when UDP came back or udp_again after
 * (Q4), straight back when that does not bind. No UDP relay: one while the
 * direct path is in doubt, once asked until it comes. The direct path up:
 * the relay stands by PM_STANDBY_MS, then goes once a round trip over the
 * direct path is proven (a punch proves one way only: a probe first). It
 * lost: dropped, path_lost unless the UDP relay is dead too. The UDP relay
 * dead (every address tried): beside a doubt, bound once more; alone, after
 * the accept: the ports a hard-side punch holds, then the round under way
 * awaited (PM_WAIT_MS at most), bound once more, the WS relay; each loss
 * afresh (Q7: once a call before), a bind under way awaited first (D4) */
int pm_decide(npf_pm *m, unsigned in, int64_t now)
{
    npf_path *d = m->p[PK_DIRECT], *u = m->p[PK_UDP_RELAY], *w = m->p[PK_WS_RELAY];
    unsigned k;
    if (u && u->health == PH_UP)
        m->tried = 0;
    if (m->fixed)
        return PM_NONE;
    if (w) {
        if (w->health == PH_DEAD)
            return pm_wait(m, 0, 0, (in & (PM_IN_CALLER | PM_IN_HOLD)) == PM_IN_CALLER ? PM_NEED_WS_ELSEWHERE : PM_NONE);
        if (!(in & PM_IN_UDP) || !(in & (PM_IN_UP | PM_IN_UDP_BACK)))
            return pm_wait(m, 0, 0, PM_NONE);
        if (!(in & PM_IN_UDP_BACK) && now - w->since < m->udp_again)
            return pm_wait(m, 0, w->since + m->udp_again, PM_NONE);
        m->tried = PM_IN_PORTS | PM_IN_PUNCH | PM_T_RETRY;
        return pm_wait(m, 0, 0, PM_NEED_UDP_BACK);
    }
    if (in & PM_IN_NOUDP)
        return pm_wait(m, 0, 0, PM_NEED_WS);
    if (d && d->health == PH_DEAD)
        return pm_wait(m, 0, 0, u && u->health == PH_DEAD ? PM_DROP : PM_NEED_PATH_LOST);
    if (!u)
        return pm_wait(m, 0, 0, (d ? d->health == PH_SUSPECT : m->need == PM_NEED_UDP) ? PM_NEED_UDP : PM_NONE);
    if (d && d->health == PH_UP) {
        if (m->wait != PM_W_STANDBY && m->wait != PM_W_PROBE)
            return pm_wait(m, PM_W_STANDBY, now + PM_STANDBY_MS, PM_NONE);
        if (d->rt_ok >= d->since && (m->wait == PM_W_PROBE || now >= m->act_at))
            return pm_wait(m, 0, 0, PM_NEED_RELEASE);
        if (now < m->act_at)
            return PM_NONE;
        if (m->wait == PM_W_PROBE)
            return pm_wait(m, PM_W_STANDBY, now + PM_STANDBY_MS, PM_STANDBY_ON);
        pm_probe(m, d, now, PM_PROBE_MS);
        return pm_wait(m, PM_W_PROBE, now + PM_PROBE_MS, PM_PROBE);
    }
    if (u->health != PH_DEAD || in & PM_IN_HOLD || (d && m->tried & PM_T_RETRY))
        return pm_wait(m, 0, 0, PM_NONE);
    if (m->wait && in & m->wait && now < m->act_at)
        return PM_NONE;
    k = m->wait == PM_IN_PORTS && !(in & PM_IN_PORTS);
    pm_wait(m, 0, 0, PM_NONE);
    if (k)
        return PM_REBIND;
    if (m->need == PM_NEED_WS)
        return PM_NEED_WS;
    if (!d && (k = in & (PM_IN_PORTS | PM_IN_PUNCH) & ~m->tried) != 0) {
        k = k & PM_IN_PORTS ? PM_IN_PORTS : PM_IN_PUNCH;
        m->tried |= k;
        return pm_wait(m, k, now + PM_WAIT_MS, k == PM_IN_PORTS ? PM_WAIT_PORTS : PM_WAIT_PUNCH);
    }
    if (m->tried & PM_T_RETRY)
        return PM_NEED_WS;
    m->tried |= PM_T_RETRY;
    return PM_RETRY;
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
    c->pm.udp_again = c->n->th.udp_again_ms > 0 ? c->n->th.udp_again_ms : PM_UDP_AGAIN_MS;
}


/* ---- the session's paths' health ---- */

/* The health rules now (pm_tick) for a session with its AnLiu connection,
 * then the decisions (pm_decide, call_need): from the call's tick (each
 * one while it has an AnLiu connection, else at check_at: the next thing
 * due, a probe, a verdict, a silence long enough, a wait's end, a
 * request's deadline) and the events that change a path's health or an
 * input. Nothing on the hot path: a datagram only writes its path's
 * last_rx. */
void pm_check(npf_call *c)
{
    static const char *const act[] = {
        "the UDP relay unreachable while a punch holds the NAT's ports: trying again when it ends",
        "the UDP relay unreachable: waiting for the punch before asking for the WS relay",
        "trying the UDP relay once more before the WS relay",
        "the punch gave the NAT's ports back: trying the UDP relay again", "",
        "no echo over the direct path in 10 s: the relay stands by 30 s more", ""};
    npf_node *n = c->n;
    npf_pm *m = &c->pm;
    anl_stats st;
    int64_t now = npf_mono_ms(), due = INT64_MAX;
    int k, busy = 0, r;
    unsigned in;
    if (call_over(c))
        return;
    /* AnLiu's stats only for a path whose rules look at the data in
     * flight (the WS relay's do not) */
    for (k = 0; k < PK_N; k++)
        busy |= m->p[k] && m->p[k]->health == PH_UP && pm_rules_of[k].t_busy && pm_relied(m, m->p[k]);
    memset(&st, 0, sizeof st);
    if (c->anl && (!busy || anl_get_stats(c->anl, &st) == 0)) {
        if (call_has_ws(c))
            path_ws_heard(c);
        due = pm_tick(m, now, st.inflight, (int)st.rto);
    }
    in = (c->caller ? PM_IN_CALLER : 0) | (c->caller && c->st == CS_CALLING ? PM_IN_HOLD : 0)
         | (call_up(c) ? PM_IN_UP : 0) | (!call_no_p2p(c) && c->punch_st < PN_LINGER ? PM_IN_PUNCH : 0)
         | (n->nat_valid && n->nat_udp && !n->test_no_udp ? PM_IN_UDP : 0)
         | (n->udp_back_ms > c->pw.p.since ? PM_IN_UDP_BACK : 0) | (n->test_no_udp && c->keys_ready ? PM_IN_NOUDP : 0)
         | (call_has_relay(c) && c->pu.p.health == PH_DEAD && call_hard_punches(n, c) > 0 ? PM_IN_PORTS : 0);
    if (call_over(c))
        return;
    r = pm_decide(m, in, now);
    if (r >= PM_WAIT_PORTS && *act[r - PM_WAIT_PORTS])
        npf_log("call %s: %s", c->call_id_s, act[r - PM_WAIT_PORTS]);
    if (r == PM_PROBE)
        path_direct_check(c);           /* a new nonce: only an echo of these counts */
    if (r == PM_DROP || r == PM_NEED_PATH_LOST) {
        call_p2p_drop(c);
        anl_flush(c->anl);
    }
    if (r == PM_PROBE || r == PM_DROP || r == PM_NEED_PATH_LOST)
        due = now;                      /* the probe, the next decision: at once */
    call_need(c, r < PM_WAIT_PORTS ? r : PM_NONE, now);
    if (r == PM_WAIT_PORTS)
        call_port_pressure(n, "the UDP relay unreachable");
    else if (r == PM_RETRY || r == PM_REBIND)
        call_relay_rebind(c);
    if (m->act_at && m->act_at < due)
        due = m->act_at;
    if (m->need && m->ask_at < due)
        due = m->ask_at;
    m->check_at = due;
    call_at(c, due);
}


/* ---- the session's side of the decisions ---- */

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
        if (call_has_ws(c) && (c->pw.wsr || c->pw.p.health == PH_DEAD) && memcmp(id, c->pw.id, 8) == 0)
            return;                 /* the one in use, sent again (both sides asked; the reply to the
                                     * call, then call_accepted): its sublinks stay */
        memcpy(c->pw.id, id, 8);    /* (the UDP relay's binder keeps its own allocation) */
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

/* What the session needs of the platform (architecture.md 2.4), each time
 * the manager says so (pm_decide): its message, sent again 10 s later, 30 s
 * after and every 30 s on while it holds with no allocation (the platform
 * drops some without a word: asked once, a session stayed without a relay),
 * within the switch quota (a burst of 6, then one in 30 s: signaling.md
 * "中转方式的选择"); path_lost and the release once */
void call_need(npf_call *c, int need, int64_t now)
{
    static const char *const what[] = {"", "a UDP relay", "the WS relay", "one on our own server", "the UDP relay"};
    static const char *const how[] = {"", "\"mode\":\"udp\"", "\"mode\":\"ws\"", "\"unreachable\":true",
                                      "\"mode\":\"udp\""};
    npf_pm *m = &c->pm;
    char data[1024];
    npf_jw w;
    if (need == PM_NEED_PATH_LOST) {    /* once: no answer to wait for (a round, or none) */
        call_punch_report(c, "path_lost");
        return;
    }
    if (need == PM_NEED_RELEASE) {      /* once: only the caller frees both allocations (data-channel.md 3) */
        path_udp_off(c);
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        if (c->caller)
            npf_node_send(c->n, "relay_release", 0, data);
        npf_log("call %s: relay released", c->call_id_s);
        return;
    }
    if (need != m->need) {
        m->need = need;
        m->asks = 0;
        m->ask_at = now;
    }
    if (!need || now < m->ask_at)
        return;
    if (m->asks)
        npf_log("call %s: no allocation %d s after asking for %s: asking again", c->call_id_s,
                m->asks == 1 ? RELAY_ASK_AGAIN_MS / 1000 : RELAY_ASK_LATER_MS / 1000, what[need]);
    else
        npf_log("call %s: %sasking for %s", c->call_id_s,
                need == PM_NEED_UDP_BACK ? "UDP works: " : need == PM_NEED_WS_ELSEWHERE ? "relay unreachable, " : "",
                what[need]);
    m->ask_at = now + (m->asks++ ? RELAY_ASK_LATER_MS : RELAY_ASK_AGAIN_MS);
    if (need == PM_NEED_UDP_BACK) {
        npf_jw_init(&w, data, sizeof data);
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "call_id", c->call_id_s);
        npf_jw_kstr(&w, "why", "udp_back");
        npf_node_write_nat(c->n, &w);
        npf_jw_end(&w);
        if (npf_jw_finish(&w) > 0)
            npf_node_send(c->n, "punch_update", 0, data);
    }
    snprintf(data, sizeof data, "{\"call_id\":\"%s\",%s}", c->call_id_s, how[need]);
    npf_node_send(c->n, "relay_switch", 0, data);
    /* UDP believed to work: measured again, so that when it fails the
     * profile says so and the probe's retries see it come back (udp_back) */
    if (need == PM_NEED_WS && m->asks == 1 && c->n->nat_valid && c->n->nat_udp && !c->n->probe && c->n->udp_fd >= 0)
        node_nat_refresh(c->n);
}

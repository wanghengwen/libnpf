/* The path manager (path.h, architecture.md 2.4): which of a session's
 * paths AnLiu's datagrams go on, and the name of the one in use; then the
 * decisions between the paths a session makes today (the relay's standby,
 * architecture.md 3.6 to come). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "call_internal.h"

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
}


/* ---- the session's decisions between its paths ---- */

/* the direct path up (or alive again): the UDP relay stands by for
 * RELAY_STANDBY_MS, then goes (call_standby_done) */
void pm_standby_start(npf_call *c)
{
    if (c->relay.active && !c->t_standby)
        c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
}

/* the direct path held for 30 s: stop using the relay; the caller tells the
 * platform to free both allocations (data-channel.md 3) */
void call_standby_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    char data[96];
    (void)loop;
    c->t_standby = NULL;
    if (!call_has_p2p(c) || !c->relay.active)
        return;
    if (c->pd.suspect) {   /* not while the direct path is in doubt */
        if (!c->pd.standby_check)
            c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
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
    c->relay.active = 0;
    c->relay.bound = 0;
    npf_timer_stop(c->n->loop, &c->relay.t_bind);
    if (c->caller) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        npf_node_send(c->n, "relay_release", 0, data);
    }
    npf_log("call %s: relay released", c->call_id_s);
}

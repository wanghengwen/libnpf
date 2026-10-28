/* The path manager (path.h, architecture.md 2.4): which of a session's
 * paths AnLiu's datagrams go on, and the name of the one in use. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <string.h>

#include "npf.h"
#include "path.h"

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

int pm_code(const npf_pm *m)
{
    static const int code[PK_N] = {NPF_PATH_DIRECT, NPF_PATH_UDP_RELAY, NPF_PATH_WS_RELAY};
    if (m->fixed)
        return NPF_PATH_DIRECT;
    return m->primary ? code[m->primary->kind] : 0;
}

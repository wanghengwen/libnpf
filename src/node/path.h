/* A session's paths (architecture.md 2.3, 2.4): the direct path
 * (path_direct.c), the UDP relay (path_udp.c) and the WS relay (path_ws.c),
 * each an npf_path, and the path manager (path_mgr.c), the one place that
 * says where AnLiu's datagrams go (pm_send) and names the path in use
 * (npf_call_path). So far the manager only sends and names: each path's
 * health checks and the decisions on the relays are still their own. */
#ifndef NPF_PATH_H
#define NPF_PATH_H

#include "npf/sys.h"
#include <stddef.h>
#include <stdint.h>

enum { PK_DIRECT, PK_UDP_RELAY, PK_WS_RELAY, PK_N };     /* kinds, by rank: direct > UDP relay > WS relay */
enum { PH_UP, PH_SUSPECT };                              /* health (so far only the direct path's doubt) */
enum { PR_IDLE, PR_PRIMARY, PR_SECOND, PR_STANDBY };     /* the role the manager gives a path */

typedef struct npf_path npf_path;

typedef struct npf_path_ops {
    /* one AnLiu datagram on the path; the hot path: no allocation, no lookup
     * (tx: Windows' headers make send a macro) */
    void        (*tx)(npf_path *p, const uint8_t *dgram, size_t len);
    /* its precise name for status and logs (npf_call_path) */
    const char *(*name)(const npf_path *p);
} npf_path_ops;

struct npf_path {
    const npf_path_ops *ops;
    uint8_t  kind, health, role;
    int64_t  since;                 /* up since (monotonic ms) */
    int64_t  last_rx;               /* the peer last heard on it (monotonic ms; the UDP relay: its answers too) */
    int64_t  busy_since;            /* the session relies on it with data in flight since (ms); 0 no */
};

/* The manager: the paths in use, by kind, and where pm_send sends. A WS
 * relay is exclusive (data-channel.md 3: UDP gave out); else the direct
 * path is the primary one with the UDP relay standing by, or the second one
 * while the direct path is in doubt (each datagram on both, AnLiu drops the
 * duplicates); else the UDP relay, bound or not (the relay forwards what our
 * key seals from an address it has not bound yet) */
typedef struct npf_pm {
    npf_path *p[PK_N];              /* NULL: none of that kind */
    npf_path *primary, *second;     /* pm_route's choice */
    int       fixed;                /* a direct connection's (no platform): a fixed direct path */
} npf_pm;

/* a path in use from now on (once of each kind), or no longer; its health:
 * each changes the choice */
void pm_add(npf_pm *m, npf_path *p);
void pm_del(npf_pm *m, npf_path *p);
void pm_health(npf_pm *m, npf_path *p, int health);

static inline int pm_has(const npf_pm *m, int kind)
{
    return m->p[kind] != NULL;
}

static inline void pm_send(const npf_pm *m, const uint8_t *dgram, size_t len)
{
    if (m->primary)
        m->primary->ops->tx(m->primary, dgram, len);
    if (m->second)
        m->second->ops->tx(m->second, dgram, len);
}

/* the path in use: precisely ("p2p", "relay (binding)", "ws relay", "direct",
 * "none"), as people see it ("P2P", "Relayed", "Direct", "none"), as npf.h's
 * NPF_PATH_* (0 none) */
const char *pm_name(const npf_pm *m);
const char *pm_label(const npf_pm *m);
int pm_code(const npf_pm *m);

#endif

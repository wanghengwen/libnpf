/* A session's paths (architecture.md 2.3, 2.4): the direct path
 * (path_direct.c), the UDP relay (path_udp.c), the WS relay (path_ws.c), and
 * the manager (path_mgr.c): where AnLiu's datagrams go (pm_send), the name
 * of the path in use, the health rules (pm_tick), the decisions (pm_decide). */
#ifndef NPF_PATH_H
#define NPF_PATH_H

#include "npf/sys.h"
#include <stddef.h>
#include <stdint.h>

#include "npf/loop.h"
#include "npf/siv.h"
#include "npf/wsrelay.h"
#include "relay_bind.h"

enum { PK_DIRECT, PK_UDP_RELAY, PK_WS_RELAY, PK_N };     /* kinds, by rank: direct > UDP relay > WS relay */
/* health: NEW not proven yet (a UDP relay binding, a WS relay not paired),
 * UP, SUSPECT (silent while relied on: probed), DEAD (the verdict) */
enum { PH_NEW, PH_UP, PH_SUSPECT, PH_DEAD };
enum { PR_IDLE, PR_PRIMARY, PR_SECOND, PR_STANDBY };     /* the role the manager gives a path */

typedef struct npf_path npf_path;

/* tx: one AnLiu datagram, the hot path: no allocation, no lookup (Windows'
 * headers make send a macro). The health rules' events (pm_tick), the path
 * SUSPECT or DEAD already: silent for quiet ms while relied on (busy_since
 * set: with data in flight), a probe due, the verdict's time up; NULL for a
 * kind whose rules have no such time (pm_rules) */
typedef struct npf_path_ops {
    void (*tx)(npf_path *p, const uint8_t *dgram, size_t len);
    void (*suspect)(npf_path *p, int64_t quiet);
    void (*probe)(npf_path *p);
    void (*dead)(npf_path *p);
} npf_path_ops;

struct npf_path {                   /* the times: monotonic ms */
    const npf_path_ops *ops;
    uint8_t  kind, health, role;
    int64_t  since;                 /* up since */
    int64_t  last_rx;               /* the peer last heard on it (the UDP relay: its answers too; the WS relay: any frame) */
    int64_t  busy_since;            /* relied on with data in flight since; 0 no */
    int64_t  rt_ok;                 /* the last round trip proven (an echo, a BIND_ACK, the pairing) */
    int64_t  suspect_at;            /* SUSPECT since */
    int64_t  probe_at;              /* the next probe: SUSPECT, or probed while UP */
    int64_t  probe_until;           /* UP, probed (pm_probe) until then; 0 not */
};

/* The health rules (architecture.md 2.4), their times per kind (ms,
 * pm_rules_of): UP and relied on (pm_relied), a path goes SUSPECT when
 * silent for max(t_busy, 2 RTO) with data in flight, for t_idle without;
 * SUSPECT, it is probed every t_probe, a round trip (pm_rt) brings it UP,
 * t_verdict after it is DEAD. 0: no such rule (t_busy: t_idle with data in
 * flight too; t_probe, t_verdict: the path probes and decides on its own) */
typedef struct pm_rules {
    int t_busy, t_idle, t_probe, t_verdict;
} pm_rules;

extern const pm_rules pm_rules_of[PK_N];

/* the direct path (path_direct.c) */
typedef struct path_direct {
    npf_path p;
    int      fd;                    /* the main socket, or an S3 one the punch handed over (owned); -1 none */
    int      owned;
    struct sockaddr_storage addr;   /* the peer */
    npf_siv_keys keys;              /* PATH_CHECK / PATH_ECHO, from the E2E keys */
    int      keys_ready;
    uint64_t nonce;                 /* of the checks in flight (a new one each time it is in doubt) */
} path_direct;

/* the UDP relay (path_udp.c): its health is its binder's state (relay_bind.h):
 * NEW binding, UP bound, SUSPECT probing, DEAD given up */
typedef struct path_udp {
    npf_path p;
    relay_c  r;
} path_udp;

/* the WS relay (path_ws.c): a connection to the allocation's relay; p.since: the allocation came */
typedef struct path_ws {
    npf_path p;
    npf_wsr *wsr;                   /* the relay connection, NULL none (lost: connected again) */
    char     url[256];              /* the allocation's relay, for a connection lost after pairing */
    uint8_t  pub[32], id[8];        /* ... its key, the allocation's id */
    npf_timer *t_flush;             /* the datagrams queued this turn of the loop go out in one write */
    int64_t  re_at;                 /* connected again after a loss; a connection made again: paired by then */
    int      paired_once;           /* it worked at least once */
    int      fails;                 /* connections made again in a row that did not pair (5: DEAD) */
} path_ws;

/* The manager (architecture.md 2.4): the paths in use by kind and where
 * pm_send sends: the WS relay alone; else the direct path, the UDP relay
 * standing by, or second (each datagram on both) while the direct path is
 * in doubt; else the UDP relay, bound or not */
typedef struct npf_pm {
    npf_path *p[PK_N];              /* NULL: none of that kind */
    npf_path *primary, *second;     /* pm_route's choice */
    int       fixed;                /* a direct connection's fixed direct path: no health rules */
    int64_t   check_at;             /* pm_check again */
    /* pm_decide's: the steps this loss of the UDP relay has had (PM_IN_PORTS,
     * PM_IN_PUNCH, PM_T_RETRY), the wait act_at ends (PM_IN_PORTS,
     * PM_IN_PUNCH, PM_W_STANDBY, PM_W_PROBE; on the WS relay: UDP tried
     * again), UDP tried again this long after the WS relay came */
    unsigned  tried, wait;
    int64_t   act_at, udp_again;
    int       need, asks;           /* call_need: asked of the platform, how many times, */
    int64_t   ask_at;               /* ... again then */
} npf_pm;

/* pm_decide (architecture.md 3.6): its inputs (the caller; before the
 * accept; established; a punching round may still come; a hard-side punch
 * holds the NAT's ports; UDP works; UDP came back since the WS relay did;
 * tests: no UDP), its answer: what to ask the platform for, or to do now */
enum { PM_IN_CALLER = 1, PM_IN_HOLD = 2, PM_IN_UP = 4, PM_IN_PUNCH = 8, PM_IN_PORTS = 16, PM_IN_UDP = 32,
       PM_IN_UDP_BACK = 64, PM_IN_NOUDP = 128, PM_T_RETRY = 256, PM_W_STANDBY = 512, PM_W_PROBE = 1024 };
enum { PM_NONE, PM_NEED_UDP, PM_NEED_WS, PM_NEED_WS_ELSEWHERE, PM_NEED_UDP_BACK, PM_NEED_PATH_LOST, PM_NEED_RELEASE,
       PM_WAIT_PORTS, PM_WAIT_PUNCH, PM_RETRY, PM_REBIND, PM_PROBE, PM_STANDBY_ON, PM_DROP };
#define PM_WAIT_MS      15000       /* the UDP relay unreachable: a wait (the punch, the ports) at most this */
#define PM_UDP_AGAIN_MS 300000      /* on the WS relay while UDP works: the UDP relay tried again after this */
#define PM_STANDBY_MS   30000       /* the relay standing by after the direct path came up, then released */
#define PM_PROBE_MS     10000       /* ... once the direct path's check had an echo within this */
int pm_decide(npf_pm *m, unsigned in, int64_t now);

/* a path in use from now on (one of each kind), or no longer, its health: each changes the roles */
void pm_add(npf_pm *m, npf_path *p);
void pm_del(npf_pm *m, npf_path *p);
void pm_health(npf_pm *m, npf_path *p, int health);

/* the health rules' transitions (a path's own verdict: pm_health DEAD):
 * SUSPECT from now (the rules, or a reason of the path's own); probed while
 * UP for window ms (no doubt: the standby's check); a round trip proven: 1
 * when it brought the path UP. pm_tick: the rules at now, the next time
 * anything is due (INT64_MAX none) */
void pm_suspect(npf_pm *m, npf_path *p, int64_t now);
void pm_probe(npf_path *p, int64_t now, int64_t window);
int  pm_rt(npf_pm *m, npf_path *p, int64_t now);
int64_t pm_tick(npf_pm *m, int64_t now, uint32_t inflight, int rto);

/* the session relies on p: the health rules apply to it */
static inline int pm_relied(const npf_pm *m, const npf_path *p)
{
    return !m->fixed && (p->role == PR_PRIMARY || p->role == PR_SECOND);
}

static inline void pm_send(const npf_pm *m, const uint8_t *dgram, size_t len)
{
    if (m->primary)
        m->primary->ops->tx(m->primary, dgram, len);
    if (m->second)
        m->second->ops->tx(m->second, dgram, len);
}

/* the path in use: precisely ("p2p", "relay", "relay (binding)", "ws
 * relay", "direct", "none"), as people see it ("P2P", "Relayed", "Direct",
 * "none"), as npf.h's NPF_PATH_* (0 none) */
const char *pm_name(const npf_pm *m);
const char *pm_label(const npf_pm *m);
int pm_code(const npf_pm *m);

extern const npf_path_ops path_direct_ops, path_udp_ops, path_ws_ops;

#endif

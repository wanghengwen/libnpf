/* A session's paths (architecture.md 2.3, 2.4): the direct path
 * (path_direct.c), the UDP relay (path_udp.c) and the WS relay (path_ws.c),
 * each an npf_path, and the path manager (path_mgr.c), the one place that
 * says where AnLiu's datagrams go (pm_send), names the path in use
 * (npf_call_path) and keeps the paths' health by one set of rules
 * (pm_tick, pm_rules_of). The decisions on the relays (which to ask the
 * platform for, and when) are still the session's own (path_mgr.c). */
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

typedef struct npf_path_ops {
    /* one AnLiu datagram on the path; the hot path: no allocation, no lookup
     * (tx: Windows' headers make send a macro) */
    void        (*tx)(npf_path *p, const uint8_t *dgram, size_t len);
    /* its precise name for status and logs (npf_call_path) */
    const char *(*name)(const npf_path *p);
    /* the health rules' events (pm_tick), the path SUSPECT or DEAD already:
     * silent for quiet ms while relied on (busy_since set: with data in
     * flight), its probing begins; a probe due (kinds whose rules probe on a
     * period); the verdict's time is up (kinds whose rules give one by time) */
    void        (*suspect)(npf_path *p, int64_t quiet);
    void        (*probe)(npf_path *p);
    void        (*dead)(npf_path *p);
} npf_path_ops;

struct npf_path {
    const npf_path_ops *ops;
    uint8_t  kind, health, role;
    int64_t  since;                 /* up since (monotonic ms) */
    int64_t  last_rx;               /* the peer last heard on it (monotonic ms; the UDP relay: its answers too;
                                     * the WS relay: any frame, npf_wsr_last_rx) */
    int64_t  busy_since;            /* the session relies on it with data in flight since (ms); 0 no */
    int64_t  rt_ok;                 /* the last round trip proven (an echo, a BIND_ACK, the pairing; ms) */
    int64_t  suspect_at;            /* SUSPECT since (ms) */
    int64_t  probe_at;              /* SUSPECT: the next probe (kinds whose rules probe on a period) */
};

/* The health rules, one set for every kind (architecture.md 2.4), the times
 * (ms) per kind (pm_rules_of). A path relied on (the primary one, or the
 * second while the primary is in doubt; not a direct connection's fixed
 * one) and UP goes SUSPECT when silent: with data in flight, for
 * max(t_busy, 2 RTO) since the later of its last datagram and the data
 * going in flight; with none, for t_idle since the later of its last
 * datagram and its start. SUSPECT, it is probed every t_probe; a round
 * trip proven (pm_rt) brings it UP; t_verdict after the suspicion it is
 * DEAD. A zero: no such rule by time (t_busy: the idle rule with data in
 * flight too; t_probe, t_verdict: the path probes and decides on its own,
 * pm_dead) */
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
    int      standby_check;         /* the check before the relay goes: echo -> release */
} path_direct;

/* the UDP relay (path_udp.c); p.last_rx: the relay last answered (a
 * BIND_ACK, the peer's data through it) */
typedef struct path_udp {
    npf_path p;
    relay_c  r;                     /* the binder (relay_bind.h): the allocation; also the WS relay's id and key;
                                     * r.bound: UP (NEW binding, SUSPECT probing, DEAD every address tried) */
    npf_timer *t_standby;           /* the direct path up: the relay goes after RELAY_STANDBY_MS */
    int      retried;               /* tried again once after a failed punch, before the WS relay */
    int      waits_ports;           /* unreachable while punches held the NAT's ports: again when they end */
    int      ports_waited;          /* that wait was had (once) */
} path_udp;

/* the WS relay (path_ws.c): a connection to the relay of the allocation
 * (its id and key: the UDP relay's binder, call_relay_take) */
typedef struct path_ws {
    npf_path p;
    npf_wsr *wsr;                   /* the relay connection, NULL none (lost: connected again) */
    char     url[256];              /* the allocation's relay, for a connection lost after pairing */
    uint8_t  pub[32];
    npf_timer *t_flush;             /* the datagrams queued this turn of the loop go out in one write */
    npf_timer *t_re;                /* connected again after a loss; a connection made again: paired by then */
    int      paired_once;           /* it worked at least once */
    int      fails;                 /* connections made again in a row that did not pair (5: DEAD) */
    int      fail_wait;             /* caller: it failed before the accept: asked about after it */
} path_ws;

/* The manager: the paths in use, by kind, and where pm_send sends. A WS
 * relay is exclusive (data-channel.md 3: UDP gave out); else the direct
 * path is the primary one with the UDP relay standing by, or the second one
 * while the direct path is in doubt (each datagram on both, AnLiu drops the
 * duplicates); else the UDP relay, bound or not (the relay forwards what our
 * key seals from an address it has not bound yet) */
typedef struct npf_pm {
    npf_path *p[PK_N];              /* NULL: none of that kind */
    npf_path *primary, *second;     /* pm_route's choice */
    int       fixed;                /* a direct connection's (no platform): a fixed direct path, no health rules */
    npf_timer *t_check;             /* the health rules again (pm_check), at check_at */
    int64_t   check_at;
    /* the session's requests and waits (path_mgr.c) */
    int64_t   asked_ms;             /* relay_switch sent at (monotonic ms), waiting for a new allocation; 0 none */
    npf_timer *t_ws_wait;           /* UDP relay unreachable: waiting for the punch first */
} npf_pm;

/* a path in use from now on (once of each kind), or no longer; its health:
 * each changes the choice */
void pm_add(npf_pm *m, npf_path *p);
void pm_del(npf_pm *m, npf_path *p);
void pm_health(npf_pm *m, npf_path *p, int health);

/* the health rules' transitions: SUSPECT from now (the rules, or a reason
 * of the path's own: a connection lost, a network change, the standby's
 * check), its probes due from now; a round trip proven: 1 when it brought
 * the path UP (it was not); the path's own verdict */
void pm_suspect(npf_pm *m, npf_path *p, int64_t now);
int  pm_rt(npf_pm *m, npf_path *p, int64_t now);
void pm_dead(npf_pm *m, npf_path *p);
/* the rules applied at now, the session's data in flight and RTO given
 * (the path's ops told of what they find): the next time anything is due,
 * INT64_MAX nothing */
int64_t pm_tick(npf_pm *m, int64_t now, uint32_t inflight, int rto);

static inline int pm_has(const npf_pm *m, int kind)
{
    return m->p[kind] != NULL;
}

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

/* the path in use: precisely ("p2p", "relay (binding)", "ws relay", "direct",
 * "none"), as people see it ("P2P", "Relayed", "Direct", "none"), as npf.h's
 * NPF_PATH_* (0 none) */
const char *pm_name(const npf_pm *m);
const char *pm_label(const npf_pm *m);
int pm_code(const npf_pm *m);

extern const npf_path_ops path_direct_ops, path_udp_ops, path_ws_ops;

#endif

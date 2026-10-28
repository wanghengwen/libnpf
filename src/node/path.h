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

#include "npf/loop.h"
#include "npf/siv.h"
#include "npf/wsrelay.h"
#include "relay_bind.h"

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

/* the direct path (path_direct.c) */
typedef struct path_direct {
    npf_path p;
    int      fd;                    /* the main socket, or an S3 one the punch handed over (owned); -1 none */
    int      owned;
    struct sockaddr_storage addr;   /* the peer */
    int64_t  suspect;               /* in doubt since (ms), 0 no (path_direct_suspect: the health with it) */
    npf_siv_keys keys;              /* PATH_CHECK / PATH_ECHO, from the E2E keys */
    int      keys_ready;
    uint64_t nonce;                 /* of the checks in flight */
    int64_t  echo_ms;               /* the last matching echo (ms) */
    int      standby_check;         /* the check before the relay goes: echo -> release */
    npf_timer *t_check;
} path_direct;

/* the UDP relay (path_udp.c); p.last_rx: the relay last answered (a
 * BIND_ACK, the peer's data through it) */
typedef struct path_udp {
    npf_path p;
    relay_c  r;                     /* the binder (relay_bind.h): the allocation; also the WS relay's id and key */
    npf_timer *t_check;             /* call_check_relay again while the session relies on it */
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
    npf_timer *t_re;                /* connected again after a loss */
    int      paired_once;           /* it worked at least once */
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
    int       fixed;                /* a direct connection's (no platform): a fixed direct path */
    /* the session's requests and waits (path_mgr.c) */
    int64_t   asked_ms;             /* relay_switch sent at (monotonic ms), waiting for a new allocation; 0 none */
    npf_timer *t_ws_wait;           /* UDP relay unreachable: waiting for the punch first */
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

extern const npf_path_ops path_direct_ops, path_udp_ops, path_ws_ops;

#endif

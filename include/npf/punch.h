/* UDP hole punching (nat-traversal.md 7, 10), event-driven on an npf_loop.
 * Internal to libnpf: the node runs the rounds the platform plans; it is in
 * include/npf for the npf-punch tool, which runs one round on a loop of its own.
 *
 *   S0/S1  both sides reachable (EIM mapping or global IPv6): the main socket
 *          probes every peer candidate and answers the peer's probes.
 *   S3     one easy (EIM) side, one hard side: the hard side opens n_sockets
 *          sockets aimed at the easy side's srflx, the easy side sprays
 *          m_total probes over the hard side's public IPv4 (S4 runs as S3).
 *          With measure / peer_n (S2) the hard side measures its first new
 *          socket's mapping and the easy side sprays the ports after it first.
 *   S2B    two sequential NATs: each side measures a fresh socket's mapping,
 *          learns the peer's (npf_punch_peer_port) and probes the ports the
 *          peer's NAT gives next, the controlling side ascending, the other
 *          descending.
 * S3 and S2B are IPv4 only. IPv6 peer candidates are probed from cfg.fd6 in
 * every strategy.
 *
 * PROBE / PROBE_ACK are sealed with punch_key (label NPF-PUNCH-v1), NOMINATE /
 * NOMINATE_ACK with nominate_key (NPF-NOMIN-v1); the key direction is the
 * role. A packet must carry the plan's session_id; a replayed one (its txid
 * among the last 128 taken) gets no answer. The controlling side (the caller
 * of the session) sends NOMINATE; easy / hard is independent of the role. */
#ifndef NPF_PUNCH_H
#define NPF_PUNCH_H

#include <stdint.h>
#include "npf/sys.h"

#define NPF_PKT_PROBE         3
#define NPF_PKT_PROBE_ACK     4
#define NPF_PKT_NOMINATE      5
#define NPF_PKT_NOMINATE_ACK  6

enum { NPF_PUNCH_CONTROLLING = 0, NPF_PUNCH_CONTROLLED = 1 };
enum { NPF_PUNCH_S1 = 1, NPF_PUNCH_S3 = 3, NPF_PUNCH_S2B = 20 };
enum { NPF_PUNCH_EASY = 0, NPF_PUNCH_HARD = 1 };

#define NPF_PUNCH_MAX_SOCKETS 512       /* the main socket and S3 hard's own */

typedef struct npf_punch_plan {
    int      role;                  /* NPF_PUNCH_CONTROLLING / CONTROLLED */
    int      strategy;              /* NPF_PUNCH_S1 / S3 / S2B */
    int      side;                  /* NPF_PUNCH_EASY / HARD (S3) */
    uint64_t session_id;
    uint8_t  punch_key[32];
    uint8_t  nominate_key[32];
    struct sockaddr_storage peer_srflx;  /* S3 hard: where its sockets send (the easy side's srflx) */
    socklen_t peer_srflx_len;
    struct in_addr peer_ip4;        /* S3 easy, S2B: the peer's public IPv4; 0: nothing sprayed */
    uint16_t range_lo, range_hi;    /* S3 easy: ports sprayed, 0 = 1024 / 65535; lo > hi wraps past 65535;
                                       ports below 1024 never */
    int      n_sockets;             /* S3 hard: sockets of its own (at most NPF_PUNCH_MAX_SOCKETS - 1) */
    int      m_total;               /* S3 easy: probes sprayed */
    int      pps;                   /* S3 easy: probes a second; 0: 200 */
    int      timeout_ms;            /* the round's length; 0: 8000 */
    int      peer_delta;            /* the peer's NAT's step (S2B; S2's easy side: the hard side's, 0: 1) */
    int      window, passes;        /* S2B: ports a pass (0: 32), passes (0: 4) */
    int      measure;               /* S3 hard (S2): measure the first new socket's mapping (needs probe_ep[0]) */
    int      peer_n;                /* S3 easy (S2): the hard side's socket count; 0: not S2 */
} npf_punch_plan;

typedef struct npf_punch_result {
    int      ok;
    int      sock_idx;              /* the winner's socket: 0 the main one (or fd6), else S3 / S2B's own; -1 none */
    struct sockaddr_storage peer;   /* the winning path's peer address */
    socklen_t peer_len;
    uint16_t local_port;            /* the winning socket's */
    int      elapsed_ms;
    int      probes_sent;
    int      probes_recv;
    int      acks_recv;
    int      rtt_ms;                /* NOMINATE round trip (controlling side), else -1 */
    uint16_t seen[16];              /* source ports of the peer's IPv4 PROBE / PROBE_ACK (its NAT's mappings
                                       toward this side, nat-traversal.md 7.8), nseen of them */
    int      nseen;
} npf_punch_result;

#include "npf/loop.h"

#define NPF_PUNCH_MAX_PEERS 16

typedef struct npf_punch npf_punch;
typedef void (*npf_punch_done_fn)(npf_punch *p, const npf_punch_result *res, int fd, void *arg);

typedef struct npf_punch_cfg {
    npf_punch_plan plan;
    struct sockaddr_storage peers[NPF_PUNCH_MAX_PEERS];   /* the peer's candidates (IPv4 or IPv6) */
    int      npeers;
    uint8_t  prio[NPF_PUNCH_MAX_PEERS]; /* their priority (10.1): host6 4, mapped 3, host4 2, else 1; 0: 1 */
    int      fd6;                   /* the node's IPv6 socket for IPv6 peers, -1: none */
    int      test_deaf;             /* tests: the peer's PROBE / PROBE_ACK are dropped */
    int      bypass;                /* its own sockets go around a VPN (npf_udp_socket) */
    /* S2B, S2's hard side: probe servers E1 (the fresh socket's mapping) and
     * E2 (S2B's controlling side: one more mapping before each pass), with
     * their key, ticket and clock offset; info gets the measured port (for
     * the peer: punch_info), optional */
    struct sockaddr_in probe_ep[2];
    uint8_t  probe_key[32];
    uint8_t  ticket[28];
    int64_t  clock_offset_ms;
    void   (*info)(npf_punch *p, uint16_t port, void *arg);
    /* Nothing came from the peer by when it should have (S1: 3 s after the
     * start and 2 s after a new candidate; S2B: 2.2 s after the last pass).
     * Called at most once; the round goes on to its timeout. NULL: none */
    void   (*quiet)(npf_punch *p, const npf_punch_result *res, void *arg);
    /* 1 when a datagram's source may be answered or win the path (security.md
     * 11.1 inbound half: the same policy as outbound candidates); a datagram
     * from another is not the round's (npf_punch_input: 0). NULL: any
     * (tests, npf-punch) */
    int    (*from_ok)(npf_punch *p, const struct sockaddr_storage *from, void *arg);
} npf_punch_cfg;

/* Starts a round on loop with primary_fd as the main socket (the caller's;
 * it passes that socket's datagrams in with npf_punch_input). cfg is copied.
 * S3 hard and S2B open sockets of their own, read on loop. NULL: no memory.
 * done runs once on the loop's thread, never from npf_punch_new: ok with the
 * winning socket fd (the main one, fd6, or one of the round's own: that one
 * is then the caller's and off the loop), or failed (fd -1) at the timeout or
 * npf_punch_stop. The round's other sockets are closed before done. done,
 * info and quiet may call npf_punch_free (deferred while an input or tick
 * callback of this punch is on the stack); no callback of the round's
 * comes after it. */
npf_punch *npf_punch_new(npf_loop *loop, const npf_punch_cfg *cfg, int primary_fd,
                         npf_punch_done_fn done, void *arg);
/* A datagram that came on the main socket or fd6: 1 when it is a punch
 * packet of this round (taken; done may run in it), 0 otherwise. After a
 * success it still answers the peer's late PROBE / NOMINATE that come on the
 * winning socket or fd6; after a failure it takes nothing. */
int  npf_punch_input(npf_punch *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* Frees the round and closes the sockets of its own it still holds (not the
 * winner). NULL is fine. The owner keeps a finished round for some seconds
 * so that late packets are answered. */
void npf_punch_free(npf_punch *p);
int  npf_punch_finished(const npf_punch *p);
/* S2B: the peer's measured fresh mapping; S2's easy side: the hard side's
 * measured port. Only the first one counts; ignored after the end. */
void npf_punch_peer_port(npf_punch *p, uint16_t port);
/* The peer gave the round up: it ends now, failed (done runs). */
void npf_punch_stop(npf_punch *p);
/* A peer candidate that came after the start (its mapping changed, a
 * trickled candidate), probed from now on. srflx: it is the peer's
 * server-reflexive address; on the S3 hard side the round's sockets aim at
 * it from now on. 1 when added (or the hard side's target changed); 0 when
 * the round is over, the address is not IPv4 / IPv6, it is there already or
 * NPF_PUNCH_MAX_PEERS are. */
int  npf_punch_add_peer(npf_punch *p, const struct sockaddr_storage *a, int srflx);

/* the round's timeout, monotonic ms */
int64_t npf_punch_ends_at(const npf_punch *p);

#endif

/* UDP hole punching (nat-traversal.md 7, 10).
 *
 *   S0/S1 simultaneous open — both sides reachable with a fixed mapping (EIM)
 *                             or a global IPv6 address; one socket each, both
 *                             spray the peer and reply to inbound PROBEs.
 *   S3   birthday brute force — one EIM side (easy), one hard side; the hard
 *                             side opens N sockets to the easy srflx and the
 *                             easy side sprays M PROBEs over the hard public IP.
 *                             S4 (a hard sprayer, the other side's filter lets
 *                             in any port of an IP it sent to) runs as S3.
 *   S2B  two sequential NATs — each side measures a fresh socket's mapping,
 *                             learns the peer's (npf_punch_peer_port) and sends
 *                             to the ports the peer's NAT gives next, the
 *                             caller ascending, the callee descending.
 *   S5   slow birthday       — two small port blocks: both sides send from one
 *                             fresh socket to random ports of the peer's block,
 *                             a few a second, for minutes.
 *
 * S1/S0 work over IPv4 or IPv6 (plan.family). S3 is IPv4 only (it depends on
 * NAT port behaviour; IPv6 has no NAT, so S1/S0 covers it).
 *
 * PROBE/PROBE_ACK use punch_key (label NPF-PUNCH-v1), NOMINATE/NOMINATE_ACK use
 * nominate_key (NPF-NOMIN-v1); the key direction is the role.
 *
 * Synchronous (poll). The event-loop API of the design doc comes later. */
#ifndef NPF_PUNCH_H
#define NPF_PUNCH_H

#include <stdint.h>
#include "npf/sys.h"

#define NPF_PKT_PROBE         3
#define NPF_PKT_PROBE_ACK     4
#define NPF_PKT_NOMINATE      5
#define NPF_PKT_NOMINATE_ACK  6

enum { NPF_PUNCH_CONTROLLING = 0, NPF_PUNCH_CONTROLLED = 1 };
enum { NPF_PUNCH_S1 = 1, NPF_PUNCH_S3 = 3, NPF_PUNCH_S2B = 20, NPF_PUNCH_S5 = 5 };
enum { NPF_PUNCH_EASY = 0, NPF_PUNCH_HARD = 1 };

#define NPF_PUNCH_MAX_SOCKETS 512

typedef struct npf_punch_plan {
    int      role;                  /* NPF_PUNCH_CONTROLLING / CONTROLLED */
    int      strategy;              /* NPF_PUNCH_S1 / S3 */
    int      side;                  /* NPF_PUNCH_EASY / HARD */
    int      family;                /* AF_INET / AF_INET6 (S1/S0); S3 is AF_INET */
    uint64_t session_id;
    uint8_t  punch_key[32];
    uint8_t  nominate_key[32];
    struct sockaddr_storage peer_srflx;  /* peer address to send to (S1/S0; S3 hard -> easy srflx) */
    socklen_t peer_srflx_len;
    struct in_addr peer_ip4;        /* S3 easy: hard side public IPv4 to spray */
    uint16_t range_lo, range_hi;    /* spray port range; 0,0 = [1024,65535]; lo > hi: it wraps past 65535 */
    int      n_sockets;             /* S3 hard socket count */
    int      m_total;               /* S3 easy spray count */
    int      pps;                   /* S3 easy spray rate; S5 both sides */
    int      timeout_ms;
    /* S2B (nat-traversal.md 7.6) */
    int      own_delta, peer_delta; /* the NATs' allocation steps */
    int      window, passes;        /* probes a pass, passes */
} npf_punch_plan;

typedef struct npf_punch_result {
    int      ok;
    int      sock_idx;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    uint16_t local_port;
    int      elapsed_ms;
    int      probes_sent;
    int      probes_recv;
    int      acks_recv;
    int      rtt_ms;                /* NOMINATE round trip (controlling), else -1 */
    /* what the round showed of the peer's NAT, for the rounds after it
     * (nat-traversal.md 7.8): the source ports of its probes (its mappings
     * toward this side), and probes from ports this side never sent to (this
     * side's filter lets in other ports of an IP it sent to) */
    uint16_t seen[16];
    int      nseen;
    int      unsolicited;
} npf_punch_result;

/* ---- event-driven punching (used by the node) ----
 *
 * S1/S0: PROBE every peer candidate from the primary socket. S3: as above,
 * easy side sprays the hard side's public IP, hard side opens n_sockets
 * sockets aimed at the easy side's srflx. The caller of the call is always the
 * controlling side and sends NOMINATE (nat-traversal.md 10.1); easy/hard is
 * independent of the role. */
#include "npf/loop.h"

#define NPF_PUNCH_MAX_PEERS 16

typedef struct npf_punch npf_punch;
typedef void (*npf_punch_done_fn)(npf_punch *p, const npf_punch_result *res, int fd, void *arg);

typedef struct npf_punch_cfg {
    npf_punch_plan plan;            /* peer_srflx unused: peers[] below */
    struct sockaddr_storage peers[NPF_PUNCH_MAX_PEERS];
    int      npeers;
    int      fd6;                   /* the node's IPv6 socket (S0: IPv6 peers are probed from it), -1: none */
    int      test_deaf;             /* tests: the peer's probes are dropped, so the round fails */
    /* S2B: the probe servers' E1 (the fresh socket's mapping) and E2 (the
     * caller's spacer), their key and ticket; info tells the owner the
     * fresh mapping's port (it goes to the peer: punch_info) */
    struct sockaddr_in probe_ep[2];
    uint8_t  probe_key[32];
    uint8_t  ticket[28];
    int64_t  clock_offset_ms;
    void   (*info)(npf_punch *p, uint16_t port, void *arg);
} npf_punch_cfg;

/* done is called once: ok with the winning fd (primary or an S3 socket, which
 * then belongs to the caller), or failed at timeout. */
npf_punch *npf_punch_new(npf_loop *loop, const npf_punch_cfg *cfg, int primary_fd,
                         npf_punch_done_fn done, void *arg);
/* datagram on the primary socket or fd6: 1 if it was a punch packet of this session */
int  npf_punch_input(npf_punch *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* After done the session keeps answering late PROBE / NOMINATE until freed;
 * the owner frees it some seconds later. Owned S3 sockets except the winner
 * are closed at done. */
void npf_punch_free(npf_punch *p);
int  npf_punch_finished(const npf_punch *p);
/* S2B: the peer's fresh mapping (its punch_info) */
void npf_punch_peer_port(npf_punch *p, uint16_t port);

/* primary_fd: an already-open, already-bound UDP socket (family == plan.family)
 * for S1/S0 and the S3 easy side; ignored for the S3 hard side (it opens its
 * own). Returns 0 if a path was nominated, -1 on timeout. Built with
 * NPF_TOOLS_API only (the npf-punch tool; a node uses npf_punch_new). */
int npf_punch_run(const npf_punch_plan *plan, int primary_fd, npf_punch_result *res);

#endif

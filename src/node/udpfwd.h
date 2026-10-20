/* UDP forwarding of a session (data-channel.md 15).
 *
 *   - A flow is what one local source address sends to one forward (UDP has
 *     no connections: told apart by the source, as a NAT does): the caller's
 *     -L .../udp (odd numbers) or the callee's listener of a -R .../udp
 *     (even numbers); never reusing a number in the session.
 *   - On AnLiu (direct path, UDP relay) every flow shares one semi-reliable
 *     stream (tag NPF_TAG_UDP) the caller opens (at its first datagram, or
 *     before it asks for a -R .../udp):
 *       frame = flow(4) | flags(1) | [tlen(1) | host | port(2)] | [lid(4)] | payload
 *     flags bit 0: the -L target follows (caller), bit 1: the -R listener's
 *     id (callee); added until the other side said OK, so a lost first frame
 *     still opens the flow. The caller sends a -R flow to the target it
 *     registered for that listener (npf_udpf_rev_add), nothing else.
 *   - On the WS relay the same frames go in records of channel 3, dropped
 *     (not queued) while the connection is backlogged.
 *   - UDP units on the control channel: op(1) | flow(4) [| reason(1)],
 *     OK=1 (callee: the flow is open), CLOSE=2 (either side: it is over).
 *   - The callee opens a flow only to a target its "udp" resources cover
 *     (npf_policy_udp_allowed), with a socket of its own connected to the
 *     target; flows idle for NPF_UDP_IDLE_MS end on either side. */
#ifndef NPF_UDPFWD_H
#define NPF_UDPFWD_H

#include <stddef.h>
#include <stdint.h>

#include "anliu.h"
#include "npf/loop.h"
#include "npf/sys.h"
#include "npf/tunnel.h"

#define NPF_TAG_UDP          2      /* the AnLiu tag of the UDP stream */
#define NPF_UDP_PAYLOAD_MAX  65000  /* a datagram (a WS record holds a frame whole) */
#define NPF_UDP_IDLE_MS      60000
#define NPF_UDP_MAX_AGE_MS   200    /* AnLiu retries a frame this long (2 RTT + 100 ms, at least this), then drops it */
#define NPF_UDP_MAX_AGE_HI   1000   /* ... and at most this */
#define NPF_UDP_FLOWS_FWD    256    /* caller: flows of one forward (the least recent goes) */
#define NPF_UDP_FLOWS        1024   /* flows of a session on either side */
#define NPF_UDP_ONE_SEG      1150   /* larger datagrams go in more than one AnLiu segment (MTU 1200) */

enum { NPF_UDP_OK = 1, NPF_UDP_CLOSE = 2 };
enum { NPF_UDP_R_CLOSED = 1, NPF_UDP_R_REFUSED = 2, NPF_UDP_R_LIMIT = 3, NPF_UDP_R_FAILED = 4 };

typedef struct npf_udpf npf_udpf;

typedef struct npf_udpf_io {
    /* a UDP unit to the peer (the tunnel's control channel); 0 or -1 */
    int    (*unit)(void *arg, const uint8_t *buf, size_t len);
    /* WS relay: one record of channel 3; 0 or -1 */
    int    (*ws_write)(void *arg, const uint8_t *buf, size_t len);
    /* WS relay: bytes waiting in the connection */
    size_t (*ws_backlog)(void *arg);
    /* AnLiu: frames were queued, flush soon */
    void   (*kick)(void *arg);
    /* callee: may this session have UDP flows at all (a hosted client's may not)? */
    int    (*allowed)(void *arg);
} npf_udpf_io;

typedef struct npf_udpf_stats {
    int      flows;
    uint64_t dgrams_out, dgrams_in;     /* sent to / received from the peer */
    uint64_t bytes_out, bytes_in;
    uint64_t dropped;                   /* not sent (WS backlog, AnLiu refused, no flow) */
    uint64_t split;                     /* sent in more than one AnLiu segment */
    uint64_t refused;                   /* flows the callee refused (caller) / refused here (callee) */
} npf_udpf_stats;

/* anl NULL: the WS relay; policy: the callee's (NULL refuses every flow) */
npf_udpf *npf_udpf_new(npf_loop *loop, anl_t *anl, int caller, npf_policy *policy, const npf_udpf_io *io, void *arg);
/* the session ended: flows and sockets go, nothing is sent */
void npf_udpf_free(npf_udpf *u);

/* AnLiu, callee: the accept callback for the caller's UDP stream; 0 takes it */
int  npf_udpf_accept(npf_udpf *u, anl_stream_t *s, anl_stream_opt *opt);
int  npf_udpf_is_stream(const npf_udpf *u, const anl_stream_t *s);
/* the stream is readable */
void npf_udpf_drain(npf_udpf *u, anl_stream_t *s);
/* a UDP unit / a WS record of channel 3 from the peer */
void npf_udpf_unit_input(npf_udpf *u, const uint8_t *buf, size_t len);
void npf_udpf_ws_input(npf_udpf *u, const uint8_t *buf, size_t len);

/* caller: a datagram from src arrived on the forward's socket lfd, for
 * host:port on the other side; replies go out on lfd to src. 0, or -1
 * when it was dropped */
int  npf_udpf_send(npf_udpf *u, int lfd, const struct sockaddr_storage *src, socklen_t srclen, const char *host,
                   uint16_t port, const uint8_t *buf, size_t len);
/* caller: a datagram of a virtual flow (a module's kind of forward,
 * npf_fwd_kind, whose local ends are not sockets) for host:port: key (the local end's flow) tells the flows apart, the
 * replies go to deliver(key, ...). 0, or -1 when it was dropped */
typedef void (*npf_udpf_deliver)(void *key, const uint8_t *buf, size_t len);
int  npf_udpf_send_v(npf_udpf *u, void *key, npf_udpf_deliver deliver, const char *host, uint16_t port,
                     const uint8_t *buf, size_t len);
/* the local end's flow goes: its flow ends (deliver is not called again) */
void npf_udpf_forget_v(npf_udpf *u, const void *key);
/* callee: a datagram from src on the -R .../udp listener lfd (listen id lid) */
int  npf_udpf_send_rev(npf_udpf *u, int lfd, const struct sockaddr_storage *src, socklen_t srclen, uint32_t lid,
                       const uint8_t *buf, size_t len);
/* the forward's / listener's socket closes: its flows end */
void npf_udpf_forget_fd(npf_udpf *u, int lfd);
/* caller: open the stream now (the callee of a -R .../udp sends on it) */
void npf_udpf_prepare(npf_udpf *u);
/* caller: the target of the -R .../udp mapping lid (the callee's listen id);
 * 0, -1. rev_del ends its flows too */
int  npf_udpf_rev_add(npf_udpf *u, uint32_t lid, const char *host, uint16_t port);
void npf_udpf_rev_del(npf_udpf *u, uint32_t lid);

void npf_udpf_get_stats(const npf_udpf *u, npf_udpf_stats *out);

#endif

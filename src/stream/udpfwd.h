/* UDP forwarding of a session (data-channel.md 15): the caller's -L .../udp
 * flows (odd numbers) and the callee's -R .../udp listeners' (even), told
 * apart by the source address, all on one semi-reliable AnLiu stream
 * (tag NPF_TAG_UDP) the caller opens:
 *   frame = flow(4) | flags(1) | [tlen(1) | host | port(2)] | [lid(4)] | payload
 * and UDP units (OK, CLOSE) on the control channel. */
#ifndef NPF_UDPFWD_H
#define NPF_UDPFWD_H

#include <stddef.h>
#include <stdint.h>

#include "anliu.h"
#include "npf/loop.h"
#include "npf/sys.h"
#include "npf/tunnel.h"

#define NPF_TAG_UDP          2      /* the AnLiu tag of the UDP stream */
#define NPF_UDP_PAYLOAD_MAX  65000  /* a datagram */
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
    /* AnLiu: frames were queued, flush soon */
    void   (*kick)(void *arg);
    /* callee: may this session have UDP flows at all (a hosted client's may not)? */
    int    (*allowed)(void *arg);
    /* caller: the target of the -R .../udp mapping lid (the callee's listen
     * id), NULL: none */
    const char *(*rev)(void *arg, uint32_t lid, uint16_t *port);
} npf_udpf_io;

typedef struct npf_udpf_stats {
    int      flows;
    uint64_t dgrams_out, dgrams_in;     /* sent to / received from the peer */
    uint64_t bytes_out, bytes_in;
    uint64_t dropped;                   /* not sent (AnLiu refused, no flow) */
    uint64_t split;                     /* sent in more than one AnLiu segment */
    uint64_t refused;                   /* flows the callee refused (caller) / refused here (callee) */
} npf_udpf_stats;

/* policy: the callee's (NULL refuses every flow); idle_ms: a flow's idle
 * time, 0 NPF_UDP_IDLE_MS (tests: NPF_TEST_UDP_IDLE_MS) */
npf_udpf *npf_udpf_new(npf_loop *loop, anl_t *anl, int caller, npf_policy *policy, const npf_udpf_io *io, void *arg,
                       int idle_ms);
/* the shares the sockets of the peer's flows count in, with the tunnels'
 * sublinks (npf_tunnel_set_shared): a flow over subs_max is refused */
void npf_udpf_set_shared(npf_udpf *u, npf_tunnel_shared *node, npf_tunnel_shared *key);
/* the session ended: flows and sockets go, nothing is sent */
void npf_udpf_free(npf_udpf *u);

/* AnLiu, callee: the accept callback for the caller's UDP stream; 0 takes it.
 * srtt (ms, 0 unknown): the connection's, read before the input (AnLiu
 * allows no anl_get_stats from the accept callback) */
int  npf_udpf_accept(npf_udpf *u, anl_stream_t *s, anl_stream_opt *opt, int srtt);
int  npf_udpf_is_stream(const npf_udpf *u, const anl_stream_t *s);
/* the stream is readable */
void npf_udpf_drain(npf_udpf *u, anl_stream_t *s);
/* a UDP unit from the peer; a frame of the UDP stream (npf_udpf_drain's, tests') */
void npf_udpf_unit_input(npf_udpf *u, const uint8_t *buf, size_t len);
void npf_udpf_frame_in(npf_udpf *u, const uint8_t *buf, size_t len);

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
/* caller: the -R .../udp mapping lid ended: its flows end */
void npf_udpf_rev_del(npf_udpf *u, uint32_t lid);

void npf_udpf_get_stats(const npf_udpf *u, npf_udpf_stats *out);

#endif

/* WS relay client connection (data-channel.md 10): it carries the session's
 * AnLiu datagrams (sealed by AnLiu itself), one binary message each; this
 * module only moves them. The allocation's bind, sealed with its alloc_key,
 * comes from the caller (relay_bind.c). */
#ifndef NPF_WSRELAY_H
#define NPF_WSRELAY_H

#include <stddef.h>
#include <stdint.h>

#include "npf/loop.h"

/* the message types; a control message from the relay is one event byte */
enum { NPF_WSR_CTL = 0, NPF_WSR_ANL = 3 };
enum { NPF_WSR_PAIRED = 1, NPF_WSR_PAIRED_UDP = 2, NPF_WSR_PEER_GONE = 3 };
#define NPF_WSR_BIND_MAX 255        /* the bind after the type byte */

typedef struct npf_wsr npf_wsr;

typedef struct npf_wsr_cbs {
    /* both sides bound; peer_udp: the other side is on a UDP allocation of
     * the relay (PAIRED_UDP), so the datagrams cross UDP too */
    void (*paired)(npf_wsr *r, int peer_udp, void *arg);
    void (*datagram)(npf_wsr *r, const uint8_t *d, size_t len, void *arg);
    /* r == NULL: the connection is gone and freed; otherwise the peer left */
    void (*gone)(npf_wsr *r, const char *why, void *arg);
} npf_wsr_cbs;

/* bind (len bytes, NPF_WSR_BIND_MAX at most): the first message's, sent
 * once the WebSocket is open */
npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t *bind, size_t len, const npf_wsr_cbs *cbs,
                      void *arg);
/* an AnLiu datagram queued (once paired): -1 not paired or no memory; the
 * queue goes out at npf_wsr_flush */
int    npf_wsr_queue(npf_wsr *r, const uint8_t *d, size_t len);
int    npf_wsr_flush(npf_wsr *r);
size_t npf_wsr_pending(const npf_wsr *r);
int    npf_wsr_paired(const npf_wsr *r);
/* the last frame from the relay, any (its pongs, the peer's datagrams;
 * monotonic ms), 0 none yet */
int64_t npf_wsr_last_rx(const npf_wsr *r);
void   npf_wsr_close(npf_wsr *r);

#endif

/* WS relay client connection (data-channel.md 10): it carries the session's
 * AnLiu datagrams (sealed by AnLiu itself), one binary message each; this
 * module only moves them. */
#ifndef NPF_WSRELAY_H
#define NPF_WSRELAY_H

#include <stddef.h>
#include <stdint.h>

#include "npf/crypto.h"
#include "npf/loop.h"

enum { NPF_WSR_CTL = 0, NPF_WSR_ANL = 3 };

typedef struct npf_wsr npf_wsr;

typedef struct npf_wsr_cbs {
    /* both sides bound; peer_udp: the other side is on a UDP allocation of
     * the relay (relay_paired "peer": "udp"), so the datagrams cross UDP too */
    void (*paired)(npf_wsr *r, int peer_udp, void *arg);
    void (*datagram)(npf_wsr *r, const uint8_t *d, size_t len, void *arg);
    /* r == NULL: the connection is gone and freed; otherwise the peer left */
    void (*gone)(npf_wsr *r, const char *why, void *arg);
} npf_wsr_cbs;

npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t server_pub[32], const npf_identity *id,
                      const uint8_t relay_id[8], const npf_wsr_cbs *cbs, void *arg);
/* an AnLiu datagram queued (once paired): -1 not paired or no memory; the
 * queue goes out at npf_wsr_flush */
int    npf_wsr_queue(npf_wsr *r, const uint8_t *d, size_t len);
int    npf_wsr_flush(npf_wsr *r);
size_t npf_wsr_pending(const npf_wsr *r);
int    npf_wsr_paired(const npf_wsr *r);
void   npf_wsr_close(npf_wsr *r);

#endif

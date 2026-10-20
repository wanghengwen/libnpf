/* WS relay client connection (data-channel.md 10). The records it carries
 * are sealed by the call with k_ws; this module only moves them. */
#ifndef NPF_WSRELAY_H
#define NPF_WSRELAY_H

#include <stddef.h>
#include <stdint.h>

#include "npf/crypto.h"
#include "npf/loop.h"

enum { NPF_WSR_CTL = 0, NPF_WSR_START = 1, NPF_WSR_RECORD = 2 };

typedef struct npf_wsr npf_wsr;

typedef struct npf_wsr_cbs {
    void (*paired)(npf_wsr *r, void *arg);                       /* both sides bound */
    void (*start)(npf_wsr *r, const uint8_t salt[16], void *arg);
    void (*record)(npf_wsr *r, const uint8_t *rec, size_t len, void *arg);
    /* r == NULL: the connection is gone and freed; otherwise the peer left */
    void (*gone)(npf_wsr *r, const char *why, void *arg);
    void (*drained)(npf_wsr *r, void *arg);                      /* send queue empty */
} npf_wsr_cbs;

npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t server_pub[32], const npf_identity *id,
                      const uint8_t relay_id[8], const npf_wsr_cbs *cbs, void *arg);
int    npf_wsr_send(npf_wsr *r, int type, const uint8_t *p, size_t len);
size_t npf_wsr_pending(const npf_wsr *r);
int    npf_wsr_paired(const npf_wsr *r);
void   npf_wsr_close(npf_wsr *r);

#endif

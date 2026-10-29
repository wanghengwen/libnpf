/* The signaling connection's two backends (npf/sig.h): WebSocket (sig.c)
 * and UDP (sigudp.c, signaling-udp.md). Private to src/proto. */
#ifndef NPF_SIG_INT_H
#define NPF_SIG_INT_H

#include "npf/noise.h"
#include "npf/sig.h"
#include "npf/ws.h"

struct sigudp;

struct npf_sig {
    npf_sig_cbs  cbs;
    void        *arg;
    uint8_t      hash[64];
    int64_t      last_tx;               /* monotonic ms of our last message or ping, 0 = none */
    int          ready;
    /* WebSocket */
    npf_ws      *ws;
    npf_noise_hs hs;
    npf_noise_cs tx, rx;
    /* UDP: the session, NULL on WebSocket */
    struct sigudp *udp;
};

/* a whole message received (plaintext JSON) to on_msg: NULL when handed
 * over (s may be gone then), else why not (s untouched) */
const char *sig_json(npf_sig *s, const uint8_t *plain, size_t len);

#ifdef NPF_SIG_UDP
int         sigudp_send(npf_sig *s, const char *json, size_t len);
int         sigudp_ping(npf_sig *s);
int64_t     sigudp_last_rx(const npf_sig *s);
int         sigudp_rtt(const npf_sig *s);
const char *sigudp_diag(const npf_sig *s, char *buf, size_t cap);
void        sigudp_close(npf_sig *s);        /* frees s (later, inside one of its callbacks) */
#endif

#endif

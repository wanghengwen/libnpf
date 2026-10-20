/* Signaling channel: WebSocket + Noise_XK (initiator) + JSON messages
 * (security.md 7.2, signaling.md "接入与服务器列表").
 *
 *   ws open -> XK msg1 -> msg2 -> msg3 -> transport; every later WebSocket
 *   binary message is one Noise transport message carrying one JSON object.
 *
 * Reconnection, server selection and login live in the node (node.c). */
#ifndef NPF_SIG_H
#define NPF_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/loop.h"

typedef struct npf_sig npf_sig;

typedef struct npf_sig_cbs {
    void (*on_ready)(npf_sig *s, void *arg);                     /* handshake done */
    void (*on_msg)(npf_sig *s, const npf_json *j, void *arg);    /* token 0 = root object */
    void (*on_down)(npf_sig *s, const char *why, void *arg);     /* handle freed after return; do not close it here */
} npf_sig_cbs;

/* outside_vpn: the connection goes around a VPN like the node's UDP sockets
 * (connect_mode p2p; npf_ws_connect_ext) */
npf_sig *npf_sig_open(npf_loop *loop, const char *url, const uint8_t server_pub[32],
                      const npf_identity *id, const char *prologue, const npf_sig_cbs *cbs, void *arg,
                      int outside_vpn);
int  npf_sig_send(npf_sig *s, const char *json, size_t len);
void npf_sig_close(npf_sig *s);
int  npf_sig_ping(npf_sig *s);
/* monotonic ms of the last frame from the server, 0 = none yet */
int64_t npf_sig_last_rx(const npf_sig *s);
/* Noise handshake hash (binds enrollment signatures to this connection) */
const uint8_t *npf_sig_hash(const npf_sig *s);

#endif

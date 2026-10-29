/* Signaling channel: Noise_XK (initiator) + JSON messages (security.md
 * 7.2, signaling.md "接入与服务器列表") over one of two carriers:
 *
 *   WebSocket  ws open -> XK msg1 -> msg2 -> msg3 -> transport; every later
 *              WebSocket binary message is one Noise transport message
 *              carrying one JSON object (prologue "npf-ws-v1")
 *   UDP        the handshake in sealed datagrams, then explicitly counted
 *              AEAD packets with a small reliable layer (signaling-udp.md
 *              3-6, prologue "npf-sigudp-v1"); its datagrams go out through
 *              the caller's send function (the node's main socket) and come
 *              in through npf_sig_input. Not in builds with NPF_SIG_UDP off
 *              (npf_sig_open_udp: NULL there)
 *
 * Reconnection, server selection and login live in the node (node.c). */
#ifndef NPF_SIG_H
#define NPF_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/loop.h"
#include "npf/sys.h"

typedef struct npf_sig npf_sig;

typedef struct npf_sig_cbs {
    void (*on_ready)(npf_sig *s, void *arg);                     /* handshake done */
    void (*on_msg)(npf_sig *s, const npf_json *j, void *arg);    /* token 0 = root object */
    void (*on_down)(npf_sig *s, const char *why, void *arg);     /* handle freed after return; do not close it here */
} npf_sig_cbs;

/* outside_vpn: the connection goes around a VPN like the node's UDP sockets
 * (connect_mode p2p; npf_ws_connect) */
npf_sig *npf_sig_open(npf_loop *loop, const char *url, const uint8_t server_pub[32],
                      const npf_identity *id, const npf_sig_cbs *cbs, void *arg, int outside_vpn);
int  npf_sig_send(npf_sig *s, const char *json, size_t len);
void npf_sig_close(npf_sig *s);
/* UDP: an empty segment, none while segments are in flight (their acks answer) */
int  npf_sig_ping(npf_sig *s);
/* UDP: sends one datagram to (the server); its result is not looked at
 * (a lost datagram is retransmitted) */
typedef int (*npf_sig_send_fn)(const void *pkt, size_t len, const struct sockaddr_in *to, void *arg);

/* the server's cookie (signaling-udp.md 3.3), kept by the caller for the
 * next attempts to this address: read and written by the session */
typedef struct npf_sig_cookie {
    struct sockaddr_in to;
    int64_t            until;           /* monotonic ms, 0 none */
    uint8_t            c[16];
} npf_sig_cookie;

/* A UDP session to server (IPv4) whose Noise static key is server_pub; its
 * first datagram goes out before this returns; cookie may be NULL. NULL on
 * no memory (or NPF_SIG_UDP off). on_down's why: "udp: no answer" (no
 * handshake in 7.5 s), "closed: REASON" (the server's CLOSE), ... */
npf_sig *npf_sig_open_udp(npf_loop *loop, npf_sig_send_fn send, const struct sockaddr_in *server,
                          const uint8_t server_pub[32], const npf_identity *id, npf_sig_cookie *cookie,
                          const npf_sig_cbs *cbs, void *arg);
/* A datagram that came in on the socket send writes to: 1 when it is this
 * UDP session's (from the server's address; taken, valid or not), 0 when
 * not (another sender, or a WebSocket connection). Callbacks may run in it. */
int  npf_sig_input(npf_sig *s, const struct sockaddr_storage *from, const uint8_t *buf, size_t len);
/* "udp" or "ws" */
const char *npf_sig_via(const npf_sig *s);
/* UDP: the smoothed round trip in ms; 0 none yet, and on WebSocket */
int  npf_sig_rtt(const npf_sig *s);
/* monotonic ms of the last frame from the server (UDP: authenticated
 * datagram, handshake answers too), 0 = none yet */
int64_t npf_sig_last_rx(const npf_sig *s);
/* monotonic ms of our last message or ping sent (UDP: datagram), 0 = none yet */
int64_t npf_sig_last_tx(const npf_sig *s);
/* its queues, ours and the kernel's, for a log line when it stalls (npf_ws_diag) */
const char *npf_sig_diag(const npf_sig *s, char *buf, size_t cap);
/* Noise handshake hash (binds enrollment signatures to this connection) */
const uint8_t *npf_sig_hash(const npf_sig *s);

#endif

/* Minimal WebSocket client (RFC 6455) over TCP or TLS, driven by npf_loop.
 *
 * wss:// uses mbedTLS without certificate verification (security.md 7.1, D5):
 * TLS is camouflage, authentication is the Noise handshake inside. ws:// is
 * accepted for tests. Hostname resolution is synchronous (getaddrinfo). */
#ifndef NPF_WS_H
#define NPF_WS_H

#include <stddef.h>
#include <stdint.h>

#include "npf/loop.h"

#define NPF_WS_MAX_MESSAGE (128 * 1024)

typedef struct npf_ws npf_ws;

typedef struct npf_ws_cbs {
    void (*on_open)(npf_ws *ws, void *arg);
    void (*on_message)(npf_ws *ws, const uint8_t *data, size_t len, int binary, void *arg);
    /* after on_close the handle is freed; code 0 = transport failure */
    void (*on_close)(npf_ws *ws, int code, const char *why, void *arg);
    /* optional: everything queued has been written to the socket */
    void (*on_drain)(npf_ws *ws, void *arg);
} npf_ws_cbs;

npf_ws *npf_ws_connect(npf_loop *loop, const char *url, const npf_ws_cbs *cbs, void *arg);
/* the same; outside_vpn: the socket goes around a VPN like the node's UDP ones
 * (npf_net_bypass: connect_mode p2p only) */
npf_ws *npf_ws_connect_ext(npf_loop *loop, const char *url, const npf_ws_cbs *cbs, void *arg, int outside_vpn);

int  npf_ws_send(npf_ws *ws, const void *data, size_t len, int binary);
int  npf_ws_ping(npf_ws *ws);
/* bytes queued but not yet written to the socket */
size_t npf_ws_pending(const npf_ws *ws);
/* close without callback; frees the handle */
void npf_ws_free(npf_ws *ws);
/* monotonic ms of the last frame received (pongs included), 0 = none yet */
int64_t npf_ws_last_rx(const npf_ws *ws);

/* split "wss://host:port/path"; returns 0 or -1 */
int npf_url_parse(const char *url, int *tls, char *host, size_t hcap, int *port, char *path, size_t pcap);

#endif

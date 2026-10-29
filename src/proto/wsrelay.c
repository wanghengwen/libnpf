/* WS relay connection (data-channel.md 10.1): a WebSocket whose first
 * message is the allocation's bind, then type-prefixed binary messages:
 * 0 control (the relay's event byte), 3 ANL (an AnLiu datagram). */
#include <stdlib.h>
#include <string.h>

#include "npf/ws.h"
#include "npf/wsrelay.h"

struct npf_wsr {
    npf_loop    *loop;
    npf_ws      *ws;
    npf_wsr_cbs  cbs;
    void        *arg;
    uint8_t      bind[1 + NPF_WSR_BIND_MAX];
    size_t       blen;
    int          paired;
    npf_timer   *t_ping;
};

static void wsr_down(npf_wsr *r, const char *why)
{
    npf_wsr_cbs cbs = r->cbs;
    void *arg = r->arg;
    npf_wsr_close(r);
    if (cbs.gone)
        cbs.gone(NULL, why, arg);
}

static void ping_cb(npf_loop *loop, void *arg)
{
    npf_wsr *r = arg;
    npf_ws_ping(r->ws);
    r->t_ping = npf_timer_add(loop, 25000, ping_cb, r);
}

static void ws_open(npf_ws *ws, void *arg)
{
    npf_wsr *r = arg;
    if (npf_ws_send(ws, r->bind, r->blen, 1) < 0) {
        wsr_down(r, "send failed");
        return;
    }
    r->t_ping = npf_timer_add(r->loop, 25000, ping_cb, r);
}

/* A datagram (paired or not: AnLiu authenticates it), or an event; anything
 * else ends the connection. The events are not authenticated: only the
 * TLS peer can send them, and one not the relay (TLS is not verified) may
 * as well drop everything (security.md 10) */
static void ws_msg(npf_ws *ws, const uint8_t *d, size_t len, int binary, void *arg)
{
    npf_wsr *r = arg;
    int ev = binary && len == 2 && d[0] == NPF_WSR_CTL ? d[1] : 0;
    (void)ws;
    if (binary && len && d[0] == NPF_WSR_ANL) {
        if (len > 1 && r->cbs.datagram)
            r->cbs.datagram(r, d + 1, len - 1, r->arg);
    } else if (ev == NPF_WSR_PAIRED || ev == NPF_WSR_PAIRED_UDP) {
        r->paired = 1;
        if (r->cbs.paired)
            r->cbs.paired(r, ev == NPF_WSR_PAIRED_UDP, r->arg);
    } else if (ev == NPF_WSR_PEER_GONE) {
        if (r->cbs.gone)
            r->cbs.gone(r, "peer gone", r->arg);
    } else {
        wsr_down(r, "bad message");
    }
}

static void ws_closed(npf_ws *ws, int code, const char *why, void *arg)
{
    npf_wsr *r = arg;
    (void)ws;
    (void)code;
    r->ws = NULL;           /* freed by the ws layer */
    wsr_down(r, why && *why ? why : "connection closed");
}

npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t *bind, size_t len, const npf_wsr_cbs *cbs,
                      void *arg)
{
    static const npf_ws_cbs wcb = {ws_open, ws_msg, ws_closed, NULL};
    npf_wsr *r;
    if (len > NPF_WSR_BIND_MAX || !(r = calloc(1, sizeof *r)))
        return NULL;
    r->loop = loop;
    r->cbs = *cbs;
    r->arg = arg;
    r->bind[0] = NPF_WSR_CTL;
    memcpy(r->bind + 1, bind, len);
    r->blen = len + 1;
    if (!(r->ws = npf_ws_connect(loop, url, &wcb, r, 0))) {
        free(r);
        return NULL;
    }
    return r;
}

int npf_wsr_queue(npf_wsr *r, const uint8_t *d, size_t len)
{
    static const uint8_t t = NPF_WSR_ANL;
    if (!r->paired)
        return -1;
    return npf_ws_queue2(r->ws, &t, 1, d, len);
}

int npf_wsr_flush(npf_wsr *r)
{
    return npf_ws_flush(r->ws);
}

size_t npf_wsr_pending(const npf_wsr *r)
{
    return npf_ws_pending(r->ws);
}

int npf_wsr_paired(const npf_wsr *r)
{
    return r->paired;
}

int64_t npf_wsr_last_rx(const npf_wsr *r)
{
    return npf_ws_last_rx(r->ws);
}

void npf_wsr_close(npf_wsr *r)
{
    if (!r)
        return;
    npf_timer_cancel(r->loop, r->t_ping);
    npf_ws_free(r->ws);
    free(r);
}

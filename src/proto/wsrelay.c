/* WS relay connection (data-channel.md 10.1): WebSocket + Noise_XK
 * (prologue "npf-relay-v1"), relay_bind, then type-prefixed binary messages:
 * 0 control (Noise ciphertext of JSON), 1 START (salt), 2 RECORD. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/noise.h"
#include "npf/wsrelay.h"
#include "npf/ws.h"

struct npf_wsr {
    npf_loop    *loop;
    npf_ws      *ws;
    npf_wsr_cbs  cbs;
    void        *arg;
    npf_noise_hs hs;
    npf_noise_cs tx, rx;
    uint8_t      relay_id[8];
    int          ready;             /* Noise done */
    int          bound, paired;
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

static int send_ctl(npf_wsr *r, const char *json)
{
    uint8_t buf[1024];
    size_t l = strlen(json);
    int n;
    if (l + 1 + 16 > sizeof buf)
        return -1;
    buf[0] = NPF_WSR_CTL;
    n = npf_noise_encrypt(&r->tx, NULL, 0, (const uint8_t *)json, l, buf + 1);
    if (n < 0)
        return -1;
    return npf_ws_send(r->ws, buf, (size_t)n + 1, 1);
}

static void ping_cb(npf_loop *loop, void *arg)
{
    npf_wsr *r = arg;
    r->t_ping = NULL;
    if (r->ws)
        npf_ws_ping(r->ws);
    r->t_ping = npf_timer_add(loop, 25000, ping_cb, r);
}

static void on_open(npf_ws *ws, void *arg)
{
    npf_wsr *r = arg;
    uint8_t m[64];
    int n = npf_noise_write(&r->hs, NULL, 0, m, sizeof m);
    if (n < 0 || npf_ws_send(ws, m, (size_t)n, 1) < 0)
        wsr_down(r, "noise write failed");
}

static void on_msg(npf_ws *ws, const uint8_t *data, size_t len, int binary, void *arg)
{
    npf_wsr *r = arg;
    (void)ws;
    if (!binary) {
        wsr_down(r, "text frame");
        return;
    }
    if (!r->ready) {
        uint8_t m[128], p[64], b[64];
        char bind[128];
        int n;
        if (npf_noise_read(&r->hs, data, len, p, sizeof p) < 0) {
            wsr_down(r, "relay server authentication failed");
            return;
        }
        n = npf_noise_write(&r->hs, NULL, 0, m, sizeof m);
        if (n < 0 || npf_noise_split(&r->hs, &r->tx, &r->rx, NULL, NULL, NULL) < 0
            || npf_ws_send(r->ws, m, (size_t)n, 1) < 0) {
            wsr_down(r, "noise handshake failed");
            return;
        }
        r->ready = 1;
        npf_b64url_encode(r->relay_id, 8, (char *)b);
        snprintf(bind, sizeof bind, "{\"v\":1,\"type\":\"relay_bind\",\"data\":{\"relay_id\":\"%s\"}}", (char *)b);
        if (send_ctl(r, bind) < 0) {
            wsr_down(r, "send failed");
            return;
        }
        r->t_ping = npf_timer_add(r->loop, 25000, ping_cb, r);
        return;
    }
    if (len < 1)
        return;
    switch (data[0]) {
    case NPF_WSR_CTL: {
        char plain[1024];
        int n;
        if (len - 1 > sizeof plain + 16 || (n = npf_noise_decrypt(&r->rx, NULL, 0, data + 1, len - 1, (uint8_t *)plain)) < 0) {
            wsr_down(r, "control decrypt failed");
            return;
        }
        plain[n < (int)sizeof plain ? n : (int)sizeof plain - 1] = 0;
        if (strstr(plain, "\"relay_bound\"")) {
            r->bound = 1;
        } else if (strstr(plain, "\"relay_paired\"")) {
            r->paired = 1;
            if (r->cbs.paired)
                r->cbs.paired(r, r->arg);
        } else if (strstr(plain, "\"relay_peer_gone\"")) {
            npf_wsr_cbs cbs = r->cbs;
            r->paired = 0;
            if (cbs.gone)
                cbs.gone(r, "peer gone", r->arg);
        } else if (strstr(plain, "\"relay_error\"")) {
            wsr_down(r, "relay refused the binding");
        }
        return;
    }
    case NPF_WSR_START:
        if (len == 17 && r->cbs.start)
            r->cbs.start(r, data + 1, r->arg);
        return;
    case NPF_WSR_RECORD:
        if (r->cbs.record)
            r->cbs.record(r, data + 1, len - 1, r->arg);
        return;
    }
}

static void on_drain(npf_ws *ws, void *arg)
{
    npf_wsr *r = arg;
    (void)ws;
    if (r->cbs.drained)
        r->cbs.drained(r, r->arg);
}

static void on_close(npf_ws *ws, int code, const char *why, void *arg)
{
    npf_wsr *r = arg;
    (void)ws;
    (void)code;
    r->ws = NULL;
    wsr_down(r, why && *why ? why : "relay connection closed");
}

npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t server_pub[32], const npf_identity *id,
                      const uint8_t relay_id[8], const npf_wsr_cbs *cbs, void *arg)
{
    static const npf_ws_cbs wcb = {on_open, on_msg, on_close, on_drain};
    npf_wsr *r = calloc(1, sizeof *r);
    if (!r)
        return NULL;
    r->loop = loop;
    r->cbs = *cbs;
    r->arg = arg;
    memcpy(r->relay_id, relay_id, 8);
    if (npf_noise_init(&r->hs, NPF_NOISE_XK, 1, "npf-relay-v1", 12, id->dh_sk, server_pub, NULL) < 0) {
        free(r);
        return NULL;
    }
    r->ws = npf_ws_connect(loop, url, &wcb, r);
    if (!r->ws) {
        free(r);
        return NULL;
    }
    return r;
}

int npf_wsr_send(npf_wsr *r, int type, const uint8_t *p, size_t len)
{
    uint8_t *buf;
    int rc;
    if (!r->ws || !r->paired)
        return -1;
    buf = malloc(len + 1);
    if (!buf)
        return -1;
    buf[0] = (uint8_t)type;
    memcpy(buf + 1, p, len);
    rc = npf_ws_send(r->ws, buf, len + 1, 1);
    free(buf);
    return rc;
}

size_t npf_wsr_pending(const npf_wsr *r)
{
    return r->ws ? npf_ws_pending(r->ws) : 0;
}

int npf_wsr_paired(const npf_wsr *r)
{
    return r->paired;
}

void npf_wsr_close(npf_wsr *r)
{
    if (!r)
        return;
    if (r->t_ping)
        npf_timer_cancel(r->loop, r->t_ping);
    if (r->ws)
        npf_ws_free(r->ws);
    npf_wipe(r, sizeof *r);
    free(r);
}

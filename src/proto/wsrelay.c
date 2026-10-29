/* WS relay connection (data-channel.md 10.1): WebSocket + Noise_XK
 * (prologue "npf-relay-v1"), relay_bind, then type-prefixed binary messages:
 * 0 control (Noise ciphertext of JSON), 3 ANL (an AnLiu datagram). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/sig.h"
#include "npf/wsrelay.h"

struct npf_wsr {
    npf_loop    *loop;
    npf_sig     *s;                 /* the WebSocket and Noise_XK, as signaling's */
    npf_wsr_cbs  cbs;
    void        *arg;
    uint8_t      relay_id[8];
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

static void ping_cb(npf_loop *loop, void *arg)
{
    npf_wsr *r = arg;
    npf_sig_ping(r->s);
    r->t_ping = npf_timer_add(loop, 25000, ping_cb, r);
}

static void on_ready(npf_sig *s, void *arg)
{
    npf_wsr *r = arg;
    char b[16], bind[96];
    b[npf_b64url_encode(r->relay_id, 8, b)] = 0;
    snprintf(bind, sizeof bind, "{\"v\":1,\"type\":\"relay_bind\",\"data\":{\"relay_id\":\"%s\"}}", b);
    if (npf_sig_send(s, bind, strlen(bind)) < 0) {
        wsr_down(r, "send failed");
        return;
    }
    r->t_ping = npf_timer_add(r->loop, 25000, ping_cb, r);
}

/* a control message, by its type (not a word found anywhere in it: an
 * error's text naming another type) */
static void on_ctl(npf_sig *s, const npf_json *j, void *arg)
{
    npf_wsr *r = arg;
    char type[24] = "";
    (void)s;
    npf_json_get_str(j, 0, "type", type, sizeof type);
    if (strcmp(type, "relay_bound") == 0) {
        r->bound = 1;
    } else if (strcmp(type, "relay_paired") == 0) {
        r->paired = 1;
        if (r->cbs.paired)
            r->cbs.paired(r, npf_json_eq(j, npf_json_get(j, npf_json_get(j, 0, "data"), "peer"), "udp"), r->arg);
    } else if (strcmp(type, "relay_peer_gone") == 0) {
        r->paired = 0;
        if (r->cbs.gone)
            r->cbs.gone(r, "peer gone", r->arg);
    } else if (strcmp(type, "relay_error") == 0) {
        wsr_down(r, "relay refused the binding");
    }
}

static void on_raw(npf_sig *s, const uint8_t *d, size_t len, void *arg)
{
    npf_wsr *r = arg;
    (void)s;
    if (len && d[0] == NPF_WSR_ANL && r->paired && r->cbs.datagram)
        r->cbs.datagram(r, d + 1, len - 1, r->arg);
}

static void on_down(npf_sig *s, const char *why, void *arg)
{
    npf_wsr *r = arg;
    (void)s;
    r->s = NULL;                        /* freed by sig.c after this */
    wsr_down(r, why);
}

npf_wsr *npf_wsr_open(npf_loop *loop, const char *url, const uint8_t server_pub[32], const npf_identity *id,
                      const uint8_t relay_id[8], const npf_wsr_cbs *cbs, void *arg)
{
    static const npf_sig_cbs scb = {on_ready, on_ctl, on_down, on_raw};
    npf_wsr *r = calloc(1, sizeof *r);
    if (!r)
        return NULL;
    r->loop = loop;
    r->cbs = *cbs;
    r->arg = arg;
    memcpy(r->relay_id, relay_id, 8);
    if (!(r->s = npf_sig_open(loop, url, server_pub, id, "npf-relay-v1", &scb, r, 0))) {
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
    return npf_ws_queue2(npf_sig_ws(r->s), &t, 1, d, len);
}

int npf_wsr_flush(npf_wsr *r)
{
    return npf_ws_flush(npf_sig_ws(r->s));
}

size_t npf_wsr_pending(const npf_wsr *r)
{
    return npf_ws_pending(npf_sig_ws(r->s));
}

int npf_wsr_paired(const npf_wsr *r)
{
    return r->paired;
}

int64_t npf_wsr_last_rx(const npf_wsr *r)
{
    return npf_sig_last_rx(r->s);
}

void npf_wsr_close(npf_wsr *r)
{
    if (!r)
        return;
    npf_timer_cancel(r->loop, r->t_ping);
    npf_sig_close(r->s);
    free(r);
}

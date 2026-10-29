/* The signaling connection (npf/sig.h) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"

#include "sig_int.h"

/* on_down runs first (the handle is still valid, but must not be closed
 * there), then the handle is freed */
static void sig_down(npf_sig *s, const char *why)
{
    npf_ws_free(s->ws);
    s->ws = NULL;
    if (s->cbs.on_down)
        s->cbs.on_down(s, why, s->arg);
    npf_sig_close(s);
}

const char *sig_json(npf_sig *s, const uint8_t *plain, size_t len)
{
    /* a token takes two characters at least ("1,") */
    size_t ntok = len / 2 + 2 < NPF_JSON_MAX_TOKENS ? len / 2 + 2 : NPF_JSON_MAX_TOKENS;
    npf_jtok *tok = malloc(ntok * sizeof *tok);
    npf_json j;
    if (!tok)
        return "no memory";
    if (npf_json_parse(&j, (const char *)plain, len, tok, (int)ntok) < 0 || tok[0].type != NPF_JT_OBJECT) {
        free(tok);
        return "bad json";
    }
    s->cbs.on_msg(s, &j, s->arg);
    free(tok);
    return NULL;
}

/* Noise_XK as the initiator: the first message once the WebSocket is open */
static void ws_open(npf_ws *ws, void *arg)
{
    npf_sig *s = arg;
    uint8_t m[64];
    int n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
    if (n < 0 || npf_ws_send(ws, m, (size_t)n, 1) < 0)
        sig_down(s, "noise write failed");
}

/* Every WebSocket message is a binary one: the Noise handshake message or
 * a transport ciphertext as it is (signaling.md); a text message ends the
 * connection */
static void ws_msg(npf_ws *ws, const uint8_t *data, size_t len, int binary, void *arg)
{
    npf_sig *s = arg;
    (void)ws;
    if (!binary) {
        sig_down(s, "text frame");
        return;
    }
    if (len > NPF_JSON_MAX_SIZE + NPF_AEAD_TAG_SIZE) {     /* the handshake's are smaller still */
        sig_down(s, "message too large");
        return;
    }
    if (!s->ready) {                    /* the server's answer, our last message */
        uint8_t m[128], p[64];
        int n;
        if (npf_noise_read(&s->hs, data, len, p, sizeof p) < 0) {
            sig_down(s, "server authentication failed");
            return;
        }
        n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
        if (n < 0 || npf_noise_split(&s->hs, &s->tx, &s->rx, NULL, NULL, s->hash) < 0
            || npf_ws_send(s->ws, m, (size_t)n, 1) < 0) {
            sig_down(s, "noise handshake failed");
            return;
        }
        s->ready = 1;
        if (s->cbs.on_ready)
            s->cbs.on_ready(s, s->arg);
        return;
    }
    {
        uint8_t *plain = malloc(len + 1);
        int n = -1;
        const char *bad = NULL;
        if (!plain)
            bad = "no memory";
        else if ((n = npf_noise_decrypt(&s->rx, NULL, 0, data, len, plain)) < 0)
            bad = "decrypt failed";
        else
            bad = sig_json(s, plain, (size_t)n);    /* s may be gone when NULL */
        if (bad)
            sig_down(s, bad);
        if (plain && n > 0)
            npf_wipe(plain, (size_t)n);
        free(plain);
    }
}

static void ws_closed(npf_ws *ws, int code, const char *why, void *arg)
{
    npf_sig *s = arg;
    (void)ws;
    (void)code;
    s->ws = NULL;           /* freed by the ws layer */
    sig_down(s, why && *why ? why : "connection closed");
}

npf_sig *npf_sig_open(npf_loop *loop, const char *url, const uint8_t server_pub[32],
                      const npf_identity *id, const npf_sig_cbs *cbs, void *arg, int outside_vpn)
{
    static const npf_ws_cbs wcb = {ws_open, ws_msg, ws_closed, NULL};
    static const char prologue[] = "npf-ws-v1";
    npf_sig *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    s->cbs = *cbs;
    s->arg = arg;
    if (npf_noise_init(&s->hs, NPF_NOISE_XK, 1, prologue, sizeof prologue - 1, id->dh_sk, server_pub, NULL) < 0
        || !(s->ws = npf_ws_connect(loop, url, &wcb, s, outside_vpn))) {
        npf_sig_close(s);               /* the handshake state holds our key */
        return NULL;
    }
    return s;
}

int npf_sig_send(npf_sig *s, const char *json, size_t len)
{
    uint8_t *out;               /* up to NPF_JSON_MAX_SIZE: not on the stack (malloc) */
    int n, r = -1;
#ifdef NPF_SIG_UDP
    if (s->udp)
        return sigudp_send(s, json, len);
#endif
    if (!s->ready || !s->ws || len > NPF_JSON_MAX_SIZE || !(out = malloc(len + 64)))
        return -1;
    n = npf_noise_encrypt(&s->tx, NULL, 0, (const uint8_t *)json, len, out);
    if (n >= 0)
        r = npf_ws_send(s->ws, out, (size_t)n, 1);
    free(out);
    if (r == 0)
        s->last_tx = npf_mono_ms();
    return r;
}

int npf_sig_ping(npf_sig *s)
{
    int r;
#ifdef NPF_SIG_UDP
    if (s->udp)
        return sigudp_ping(s);
#endif
    r = s->ws ? npf_ws_ping(s->ws) : -1;
    if (r == 0)
        s->last_tx = npf_mono_ms();
    return r;
}

int64_t npf_sig_last_tx(const npf_sig *s)
{
    return s->last_tx;
}

int64_t npf_sig_last_rx(const npf_sig *s)
{
#ifdef NPF_SIG_UDP
    if (s->udp)
        return sigudp_last_rx(s);
#endif
    return s->ws ? npf_ws_last_rx(s->ws) : 0;
}

const char *npf_sig_diag(const npf_sig *s, char *buf, size_t cap)
{
#ifdef NPF_SIG_UDP
    if (s && s->udp)
        return sigudp_diag(s, buf, cap);
#endif
    if (s && s->ws)
        return npf_ws_diag(s->ws, buf, cap);
    snprintf(buf, cap, "no connection");
    return buf;
}

const uint8_t *npf_sig_hash(const npf_sig *s)
{
    return s->hash;
}

const char *npf_sig_via(const npf_sig *s)
{
    return s->udp ? "udp" : "ws";
}

int npf_sig_rtt(const npf_sig *s)
{
#ifdef NPF_SIG_UDP
    if (s->udp)
        return sigudp_rtt(s);
#endif
    (void)s;
    return 0;                   /* WebSocket: not measured */
}

#ifndef NPF_SIG_UDP     /* built without UDP signaling (NPF_SIG_UDP=OFF): WebSocket only */
npf_sig *npf_sig_open_udp(npf_loop *loop, npf_sig_send_fn send, const struct sockaddr_in *server,
                          const uint8_t server_pub[32], const npf_identity *id, npf_sig_cookie *cookie,
                          const npf_sig_cbs *cbs, void *arg)
{
    (void)loop, (void)send, (void)server, (void)server_pub, (void)id, (void)cookie, (void)cbs, (void)arg;
    return NULL;
}

int npf_sig_input(npf_sig *s, const struct sockaddr_storage *from, const uint8_t *buf, size_t len)
{
    (void)s, (void)from, (void)buf, (void)len;
    return 0;
}
#endif

void npf_sig_close(npf_sig *s)
{
    if (!s)
        return;
#ifdef NPF_SIG_UDP
    if (s->udp) {
        sigudp_close(s);
        return;
    }
#endif
    npf_ws_free(s->ws);
    npf_wipe(s, sizeof *s);
    free(s);
}

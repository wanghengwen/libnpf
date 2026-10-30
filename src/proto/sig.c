/* The signaling connection (npf/sig.h): what both carriers share, then the
 * WebSocket carrier */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"

#include "sig_int.h"

/* ---- both carriers ---- */

static void sig_free(npf_sig *s)
{
    s->ops->release(s);
    npf_wipe_free(s, sizeof *s);        /* the handshake and the keys */
}

void sig_enter(npf_sig *s)
{
    s->depth++;
}

void sig_leave(npf_sig *s)
{
    if (--s->depth == 0 && s->dead)
        sig_free(s);
}

void sig_down(npf_sig *s, npf_sig_down code, const char *why)
{
    if (s->dead)
        return;
    s->dead = 1;
    sig_enter(s);
    if (s->cbs.on_down)
        s->cbs.on_down(s, code, why, s->arg);
    sig_leave(s);
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

int npf_sig_send(npf_sig *s, const char *json, size_t len)
{
    return s->dead || !s->ready || len > NPF_JSON_MAX_SIZE ? -1 : s->ops->send_json(s, json, len);
}

int npf_sig_ping(npf_sig *s)
{
    return s->dead || !s->ready ? -1 : s->ops->ping(s);
}

int npf_sig_input(npf_sig *s, const struct sockaddr_storage *from, const uint8_t *buf, size_t len)
{
    return s && s->ops->input ? s->ops->input(s, from, buf, len) : 0;
}

void npf_sig_close(npf_sig *s)
{
    if (!s)
        return;
    if (!s->dead) {
        s->dead = 1;
        if (s->ops->bye)
            s->ops->bye(s);
    }
    if (!s->depth)
        sig_free(s);
}

const char *npf_sig_via(const npf_sig *s) { return s->ops->via; }
int npf_sig_rtt(const npf_sig *s) { return s->ops->rtt(s); }
int64_t npf_sig_last_rx(const npf_sig *s) { return s->ops->last_rx(s); }
int64_t npf_sig_last_tx(const npf_sig *s) { return s->last_tx; }
const uint8_t *npf_sig_hash(const npf_sig *s) { return s->hash; }

const char *npf_sig_diag(const npf_sig *s, char *buf, size_t cap)
{
    if (!s || !s->ops->diag(s, buf, cap))
        snprintf(buf, cap, "no connection");
    return buf;
}

/* ---- the WebSocket carrier ---- */

/* Noise_XK as the initiator: the first message once the WebSocket is open */
static void ws_open(npf_ws *ws, void *arg)
{
    npf_sig *s = arg;
    uint8_t m[64];
    int n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
    if (n < 0 || npf_ws_send(ws, m, (size_t)n, 1) < 0)
        sig_down(s, NPF_SIG_DOWN_ERROR, "noise write failed");
}

/* the server's answer, then our last message: ready */
static const char *ws_finish(npf_sig *s, const uint8_t *data, size_t len)
{
    uint8_t m[128], p[64];
    int n;
    if (npf_noise_read(&s->hs, data, len, p, sizeof p) < 0)
        return "server authentication failed";
    n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
    if (n < 0 || npf_noise_split(&s->hs, &s->tx, &s->rx, NULL, NULL, s->hash) < 0
        || npf_ws_send(s->ws, m, (size_t)n, 1) < 0)
        return "noise handshake failed";
    s->ready = 1;
    if (s->cbs.on_ready)
        s->cbs.on_ready(s, s->arg);
    return NULL;
}

/* Every WebSocket message is a binary one: the Noise handshake message or
 * a transport ciphertext as it is (signaling.md); a text message ends the
 * connection */
static void ws_msg(npf_ws *ws, const uint8_t *data, size_t len, int binary, void *arg)
{
    npf_sig *s = arg;
    uint8_t *plain = NULL;
    const char *bad;
    int n;
    (void)ws;
    sig_enter(s);
    if (!binary)
        bad = "text frame";
    else if (len > NPF_JSON_MAX_SIZE + NPF_AEAD_TAG_SIZE)     /* the handshake's are smaller still */
        bad = "message too large";
    else if (!s->ready)
        bad = ws_finish(s, data, len);
    else if (!(plain = malloc(len + 1)))
        bad = "no memory";
    else if ((n = npf_noise_decrypt(&s->rx, NULL, 0, data, len, plain)) < 0)
        bad = "decrypt failed";
    else
        bad = sig_json(s, plain, (size_t)n);
    if (bad)
        sig_down(s, NPF_SIG_DOWN_ERROR, bad);
    npf_wipe_free(plain, len + 1);
    sig_leave(s);
}

static void ws_closed(npf_ws *ws, int code, const char *why, void *arg)
{
    npf_sig *s = arg;
    (void)ws;
    (void)code;
    s->ws = NULL;           /* freed by the ws layer */
    sig_down(s, NPF_SIG_DOWN_ERROR, why && *why ? why : "connection closed");
}

static int ws_send(npf_sig *s, const char *json, size_t len)
{
    uint8_t *out = malloc(len + 64);    /* up to NPF_JSON_MAX_SIZE: not on the stack */
    int n, r = -1;
    if (!out)
        return -1;
    n = npf_noise_encrypt(&s->tx, NULL, 0, (const uint8_t *)json, len, out);
    if (n >= 0)
        r = npf_ws_send(s->ws, out, (size_t)n, 1);
    free(out);
    if (r == 0)
        s->last_tx = npf_mono_ms();
    return r;
}

static int ws_ping(npf_sig *s)
{
    int r = npf_ws_ping(s->ws);
    if (r == 0)
        s->last_tx = npf_mono_ms();
    return r;
}

static int64_t ws_last_rx(const npf_sig *s) { return s->ws ? npf_ws_last_rx(s->ws) : 0; }
static int ws_rtt(const npf_sig *s) { (void)s; return 0; }      /* not measured */
static void ws_free(npf_sig *s) { npf_ws_free(s->ws); }

static const char *ws_diag(const npf_sig *s, char *buf, size_t cap)
{
    return s->ws ? npf_ws_diag(s->ws, buf, cap) : NULL;
}

npf_sig *npf_sig_open(npf_loop *loop, const char *url, const uint8_t server_pub[32],
                      const npf_identity *id, const npf_sig_cbs *cbs, void *arg, int outside_vpn)
{
    static const sig_ops ops = {"ws", ws_send, ws_ping, ws_last_rx, ws_rtt, ws_diag, NULL, NULL, ws_free};
    static const npf_ws_cbs wcb = {ws_open, ws_msg, ws_closed, NULL};
    static const char prologue[] = "npf-ws-v1";
    npf_sig *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    s->ops = &ops;
    s->cbs = *cbs;
    s->arg = arg;
    if (npf_noise_init(&s->hs, NPF_NOISE_XK, 1, prologue, sizeof prologue - 1, id->dh_sk, server_pub, NULL) < 0
        || !(s->ws = npf_ws_connect(loop, url, &wcb, s, outside_vpn))) {
        npf_sig_close(s);               /* the handshake state holds our key */
        return NULL;
    }
    return s;
}

#include <stdlib.h>
#include <string.h>

#include "npf/noise.h"
#include "npf/sig.h"
#include "npf/ws.h"

struct npf_sig {
    npf_loop    *loop;
    npf_ws      *ws;
    npf_sig_cbs  cbs;
    void        *arg;
    npf_noise_hs hs;
    npf_noise_cs tx, rx;
    uint8_t      hash[64];
    int          ready;
    int          closing;
};

/* on_down runs first (the handle is still valid, but must not be closed
 * there), then the handle is freed */
static void sig_down(npf_sig *s, const char *why)
{
    if (s->ws)
        npf_ws_free(s->ws);
    s->ws = NULL;
    if (s->cbs.on_down)
        s->cbs.on_down(s, why, s->arg);
    npf_wipe(s, sizeof *s);
    free(s);
}

/* A WebSocket message is a binary message: the Noise handshake message or
 * transport ciphertext as it is (signaling.md). Received, a text message
 * with the same in Base64url is taken too (servers before 2026-10-22). */
static int send_msg(npf_ws *ws, const uint8_t *m, size_t n)
{
    if (n > NPF_JSON_MAX_SIZE + 64)
        return -1;
    return npf_ws_send(ws, m, n, 1);
}

static void ws_open(npf_ws *ws, void *arg)
{
    npf_sig *s = arg;
    uint8_t m[64];
    int n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
    if (n < 0 || send_msg(ws, m, (size_t)n) < 0)
        sig_down(s, "noise write failed");
}

static void ws_msg(npf_ws *ws, const uint8_t *msg, size_t mlen, int binary, void *arg)
{
    npf_sig *s = arg;
    uint8_t *raw = NULL;                /* a text message's bytes, per message: no state shared
                                           between instances */
    const uint8_t *data = msg;
    size_t len = mlen;
    (void)ws;
    if (!binary) {                      /* Base64url text: a server before 2026-10-22 */
        size_t rcap = mlen / 4 * 3 + 3; /* each its size, not the largest's (96 KB a message
                                           left holes in the heap of many instances) */
        int dl;
        if (rcap > NPF_JSON_MAX_SIZE + 64)
            rcap = NPF_JSON_MAX_SIZE + 64;
        if (!(raw = malloc(rcap))) {
            sig_down(s, "no memory");
            return;
        }
        dl = npf_b64url_decode((const char *)msg, mlen, raw, rcap);
        if (dl < 0) {
            free(raw);
            sig_down(s, "bad base64url");
            return;
        }
        data = raw;
        len = (size_t)dl;
    } else if (len > NPF_JSON_MAX_SIZE + 64) {
        sig_down(s, "message too large");
        return;
    }
    if (!s->ready) {
        uint8_t m[128], p[64];
        int n;
        if (npf_noise_read(&s->hs, data, len, p, sizeof p) < 0) {
            free(raw);
            sig_down(s, "server authentication failed");
            return;
        }
        free(raw);
        n = npf_noise_write(&s->hs, NULL, 0, m, sizeof m);
        if (n < 0 || npf_noise_split(&s->hs, &s->tx, &s->rx, NULL, NULL, s->hash) < 0
            || send_msg(s->ws, m, (size_t)n) < 0) {
            sig_down(s, "noise handshake failed");
            return;
        }
        s->ready = 1;
        if (s->cbs.on_ready)
            s->cbs.on_ready(s, s->arg);
        return;
    }
    {
        /* a token takes two characters at least ("1,") */
        size_t ntok = len / 2 + 2 < NPF_JSON_MAX_TOKENS ? len / 2 + 2 : NPF_JSON_MAX_TOKENS;
        uint8_t *plain = malloc(len + 1);
        npf_jtok *tok = malloc(ntok * sizeof *tok);
        npf_json j;
        int n = -1;
        const char *bad = NULL;
        if (!plain || !tok)
            bad = "no memory";
        else if (len > NPF_JSON_MAX_SIZE + NPF_AEAD_TAG_SIZE)
            bad = "message too large";
        else if ((n = npf_noise_decrypt(&s->rx, NULL, 0, data, len, plain)) < 0)
            bad = "decrypt failed";
        else if (npf_json_parse(&j, (const char *)plain, (size_t)n, tok, (int)ntok) < 0
                 || tok[0].type != NPF_JT_OBJECT)
            bad = "bad json";
        free(raw);
        if (bad)
            sig_down(s, bad);
        else
            s->cbs.on_msg(s, &j, s->arg);       /* s may be gone after this */
        if (plain && n > 0)
            npf_wipe(plain, (size_t)n);
        free(plain);
        free(tok);
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
                      const npf_identity *id, const char *prologue, const npf_sig_cbs *cbs, void *arg,
                      int outside_vpn)
{
    static const npf_ws_cbs wcb = {ws_open, ws_msg, ws_closed, NULL};
    npf_sig *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    s->loop = loop;
    s->cbs = *cbs;
    s->arg = arg;
    if (npf_noise_init(&s->hs, NPF_NOISE_XK, 1, prologue, strlen(prologue), id->dh_sk, server_pub, NULL) < 0) {
        free(s);
        return NULL;
    }
    s->ws = npf_ws_connect_ext(loop, url, &wcb, s, outside_vpn);
    if (!s->ws) {
        npf_wipe(s, sizeof *s);
        free(s);
        return NULL;
    }
    return s;
}

int npf_sig_send(npf_sig *s, const char *json, size_t len)
{
    uint8_t *out;               /* not on the stack (sys.h, npf_scratch) */
    int n, r = -1;
    if (!s->ready || !s->ws || len > NPF_JSON_MAX_SIZE || !(out = malloc(len + 64)))
        return -1;
    n = npf_noise_encrypt(&s->tx, NULL, 0, (const uint8_t *)json, len, out);
    if (n >= 0)
        r = send_msg(s->ws, out, (size_t)n);
    free(out);
    return r;
}

int npf_sig_ping(npf_sig *s)
{
    return s->ws ? npf_ws_ping(s->ws) : -1;
}

int64_t npf_sig_last_rx(const npf_sig *s)
{
    return s->ws ? npf_ws_last_rx(s->ws) : 0;
}

const uint8_t *npf_sig_hash(const npf_sig *s)
{
    return s->hash;
}

void npf_sig_close(npf_sig *s)
{
    if (!s)
        return;
    if (s->ws)
        npf_ws_free(s->ws);
    npf_wipe(s, sizeof *s);
    free(s);
}

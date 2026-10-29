/* WebSocket client (npf/ws.h) on npf_tcp (tcp.c). */
#ifndef _WIN32
#define _GNU_SOURCE         /* struct addrinfo (resolve.h) */
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/out.h"
#include "npf/platform.h"
#include "npf/tcp.h"
#include "npf/ws.h"

enum { ST_CONNECTING, ST_UPGRADE, ST_OPEN, ST_DEAD };     /* ST_CONNECTING: npf_tcp (TLS too) */

typedef struct buf {
    uint8_t *p;
    size_t   len, cap;
} buf;

struct npf_ws {
    npf_loop  *loop;
    npf_ws_cbs cbs;
    void      *arg;
    npf_tcp    tcp;
    int        state;
    char       host[256];
    char       path[512];
    char       key[32];             /* Sec-WebSocket-Key (base64) */
    buf        out, in;
    buf        frag;                /* fragmented message being assembled */
    int        frag_active;
    int        frag_binary;
    int        busy;                /* inside on_io: defer the free */
    int        drained;             /* out went empty during this on_io */
    int        freed;
    int64_t    last_rx;             /* monotonic ms of the last complete frame (any opcode) */
};

static void real_free(npf_ws *ws);

/* ---- small helpers ---- */

/* at least n bytes free after len */
static int buf_room(buf *b, size_t n)
{
    return n > SIZE_MAX - b->len ? -1 : npf_grow(&b->p, &b->cap, b->len + n, 1, 4096);
}

static int buf_put(buf *b, const void *p, size_t n)
{
    if (buf_room(b, n))
        return -1;
    if (n)
        memcpy(b->p + b->len, p, n);
    b->len += n;
    return 0;
}

static void buf_consume(buf *b, size_t n)
{
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
    if (b->len == 0 && b->cap > 65536) {    /* a burst's room is not kept for the connection's life */
        free(b->p);
        b->p = NULL;
        b->cap = 0;
    }
}

static void buf_free(buf *b)
{
    free(b->p);
    memset(b, 0, sizeof *b);
}

/* SHA-1, only for Sec-WebSocket-Accept */
static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t blk[64];
    size_t total = ((len + 8) / 64 + 1) * 64, off;
    int i;
    for (off = 0; off < total; off += 64) {
        uint32_t w[80], a, b, c, d, e;
        for (i = 0; i < 64; i++) {
            size_t k = off + (size_t)i;
            if (k < len) blk[i] = msg[k];
            else if (k == len) blk[i] = 0x80;
            else if (k >= total - 8) blk[i] = (uint8_t)(((uint64_t)len * 8) >> (8 * (total - 1 - k)));
            else blk[i] = 0;
        }
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) | ((uint32_t)blk[4 * i + 2] << 8) | blk[4 * i + 3];
        for (i = 16; i < 80; i++)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
        for (i = 0; i < 80; i++) {
            uint32_t f, k, tmp;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            tmp = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}

/* ---- I/O ---- */

/* Resolution and connect timers can fail outside on_io too. Hold the
 * handle across on_close, which is allowed to call npf_ws_free itself. */
static void ws_fail(npf_ws *ws, int code, const char *why)
{
    if (ws->state == ST_DEAD)
        return;
    ws->state = ST_DEAD;
    ws->busy++;
    if (ws->cbs.on_close)
        ws->cbs.on_close(ws, code, why, ws->arg);
    npf_ws_free(ws);
    if (--ws->busy == 0)
        real_free(ws);
}

/* -1: the write failed; the socket is watched for writing still, so the
 * loop reports it (not from inside a caller's send) */
static int flush_out(npf_ws *ws)
{
    size_t off = 0;                     /* moved down once, not at each TLS record (16 KB of a 1 MB queue) */
    int r = 0;
    if (ws->out.len)
        ws->drained = 1;                /* reported (if still empty) when on_io returns */
    while (off < ws->out.len) {
        ssize_t w = npf_tcp_write(&ws->tcp, ws->out.p + off, ws->out.len - off);
        if (w == NPF_TLS_WANT_WRITE || w == NPF_TLS_WANT_READ)
            break;
        if (w <= 0) {
            r = -1;
            break;
        }
        off += (size_t)w;
    }
    buf_consume(&ws->out, off);
    npf_loop_mod(ws->loop, ws->tcp.fd, NPF_EV_READ | (ws->out.len > 0 ? NPF_EV_WRITE : 0));
    return r;
}

/* one frame of head (hlen bytes) and then data: put together here, masked
 * in place, no copy of its own by the caller */
static int send_frame2(npf_ws *ws, int opcode, const void *head, size_t hlen, const void *data, size_t dlen)
{
    uint8_t h[14], mask[4];
    size_t hl = 2, i, start, len;
    if (hlen > NPF_WS_MAX_MESSAGE || dlen > NPF_WS_MAX_MESSAGE - hlen)
        return -1;
    len = hlen + dlen;
    h[0] = (uint8_t)(0x80 | opcode);
    if (len < 126) {
        h[1] = (uint8_t)(0x80 | len);
    } else if (len < 65536) {
        h[1] = 0x80 | 126;
        h[2] = (uint8_t)(len >> 8);
        h[3] = (uint8_t)len;
        hl = 4;
    } else {
        h[1] = 0x80 | 127;
        for (i = 0; i < 8; i++)
            h[2 + i] = (uint8_t)((uint64_t)len >> (56 - 8 * i));
        hl = 10;
    }
    npf_random(mask, 4);
    memcpy(h + hl, mask, 4);
    hl += 4;
    /* Reserve the entire frame before changing out: an allocation failure
     * must not leave an orphan header in front of the next message. */
    if (buf_room(&ws->out, hl + len))
        return -1;
    buf_put(&ws->out, h, hl);
    start = ws->out.len;
    if (buf_put(&ws->out, head, hlen) || buf_put(&ws->out, data, dlen))
        return -1;
    for (i = 0; i < len; i++)
        ws->out.p[start + i] ^= mask[i & 3];
    return 0;
}

static int send_frame(npf_ws *ws, int opcode, const void *data, size_t len)
{
    return send_frame2(ws, opcode, data, len, NULL, 0);
}

/* 0, or -1 with ws failed (and maybe freed) */
static int start_upgrade(npf_ws *ws)
{
    char req[1024];
    uint8_t k[16];
    int n;
    const char *fmt = strchr(ws->host, ':') ? "[%s]" : "%s";
    char hostfield[300];
    npf_random(k, 16);
    npf_b64std_encode(k, 16, ws->key);
    snprintf(hostfield, sizeof hostfield, fmt, ws->host);
    n = snprintf(req, sizeof req,
                 "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
                 "User-Agent: Mozilla/5.0\r\n\r\n",
                 ws->path, hostfield, ws->key);
    if (n < 0 || (size_t)n >= sizeof req) {   /* not with the URL limits (npf_url_parse) */
        ws_fail(ws, 0, "request too large");
        return -1;
    }
    ws->state = ST_UPGRADE;
    if (buf_put(&ws->out, req, (size_t)n) < 0) {
        ws_fail(ws, 0, "no memory");
        return -1;
    }
    return 0;
}

/* memmem / strcasestr are GNU extensions */
static char *find_mem(const void *h, size_t hl, const char *n, size_t nl)
{
    const char *p = h;
    size_t i;
    for (i = 0; i + nl <= hl; i++)
        if (memcmp(p + i, n, nl) == 0)
            return (char *)p + i;
    return NULL;
}

static char *find_nocase(const char *h, const char *n)
{
    size_t nl = strlen(n), i;
    for (; *h; h++) {
        for (i = 0; i < nl && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i]); i++)
            ;
        if (i == nl)
            return (char *)h;
    }
    return NULL;
}

/* the HTTP response to the upgrade: 1 done, 0 need more, -1 refused */
static int parse_upgrade(npf_ws *ws)
{
    char *end, *line, expect[64], *acc;
    uint8_t digest[20];
    char kg[128];
    size_t hlen;
    end = find_mem(ws->in.p, ws->in.len, "\r\n\r\n", 4);
    if (!end)
        return ws->in.len > 8192 ? -1 : 0;
    hlen = (size_t)(end - (char *)ws->in.p) + 4;
    if (hlen > 8192)
        return -1;
    end[2] = 0;
    line = (char *)ws->in.p;
    if (strncmp(line, "HTTP/1.1 101", 12) != 0)
        return -1;
    snprintf(kg, sizeof kg, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws->key);
    sha1((const uint8_t *)kg, strlen(kg), digest);
    npf_b64std_encode(digest, 20, expect);
    acc = find_nocase(line, "\r\nSec-WebSocket-Accept:");
    if (!acc)
        return -1;
    acc += 23;
    while (*acc == ' ')
        acc++;
    if (strncmp(acc, expect, strlen(expect)) != 0)
        return -1;
    buf_consume(&ws->in, hlen);
    ws->state = ST_OPEN;
    return 1;
}

#define PONG_ROOM 65536     /* pongs only while the peer reads: a ping flood does not grow out */

/* the frames from in.p + *off on, *off moved past each one taken; returns
 * -1 to fail the connection, -2 if the handle was freed by a callback */
static int parse_frames_at(npf_ws *ws, size_t *off)
{
    while (ws->in.len - *off >= 2) {
        uint8_t *p = ws->in.p + *off;
        size_t avail = ws->in.len - *off;
        int fin = p[0] & 0x80, op = p[0] & 0x0f;
        uint64_t len = p[1] & 0x7f;
        size_t hl = 2;
        if (p[1] & 0x80)
            return -1;                  /* servers must not mask */
        if (p[0] & 0x70)
            return -1;
        if (len == 126) {
            if (avail < 4) return 0;
            len = ((uint64_t)p[2] << 8) | p[3];
            hl = 4;
        } else if (len == 127) {
            int i;
            if (avail < 10) return 0;
            len = 0;
            for (i = 0; i < 8; i++) len = (len << 8) | p[2 + i];
            hl = 10;
        }
        if (len > NPF_WS_MAX_MESSAGE || ((op & 8) && (!fin || len > 125)))
            return -1;
        if (avail < hl + len)
            return 0;
        p += hl;
        ws->last_rx = npf_mono_ms();    /* pongs too: the peer is alive */
        switch (op) {
        case 0x0: case 0x1: case 0x2:
            if (op != 0) {
                if (ws->frag_active)
                    return -1;
                ws->frag_binary = op == 2;
                ws->frag_active = !fin;
            } else if (!ws->frag_active) {
                return -1;
            }
            if (fin && op != 0) {
                ws->cbs.on_message(ws, p, (size_t)len, ws->frag_binary, ws->arg);
            } else {
                if (ws->frag.len + len > NPF_WS_MAX_MESSAGE || buf_put(&ws->frag, p, (size_t)len))
                    return -1;
                if (fin) {
                    ws->cbs.on_message(ws, ws->frag.p, ws->frag.len, ws->frag_binary, ws->arg);
                    if (ws->state != ST_DEAD) {
                        buf_consume(&ws->frag, ws->frag.len);
                        ws->frag_active = 0;
                    }
                }
            }
            if (ws->state == ST_DEAD)
                return -2;
            break;
        case 0x8: {
            char why[128] = "";
            int code = len >= 2 ? (p[0] << 8) | p[1] : 1005;
            if (len == 1)
                return -1;
            if (len > 2) {
                size_t l = (size_t)len - 2 < sizeof why - 1 ? (size_t)len - 2 : sizeof why - 1;
                size_t i;
                memcpy(why, p + 2, l);
                why[l] = 0;
                for (i = 0; i < l; i++)     /* it goes into the log: no control characters */
                    if ((unsigned char)why[i] < 0x20 || why[i] == 0x7f)
                        why[i] = '?';
            }
            ws_fail(ws, code, why);
            return -2;
        }
        case 0x9:
            /* RFC 6455 5.5.3: answering only the latest ping is enough */
            if (ws->out.len <= PONG_ROOM && send_frame(ws, 0xA, p, (size_t)len))
                return -1;
            break;
        case 0xA:
            break;
        default:
            return -1;
        }
        *off += hl + (size_t)len;
    }
    return 0;
}

/* in is moved down once for all the frames taken, not at each (a buffer of
 * tiny frames made that quadratic) */
static int parse_frames(npf_ws *ws)
{
    size_t off = 0;
    int r = parse_frames_at(ws, &off);
    if (r != -2 && off)
        buf_consume(&ws->in, off);
    return r;
}

static void on_io_inner(npf_ws *ws, unsigned ev);

static void on_io(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_ws *ws = arg;
    (void)loop;
    (void)fd;
    ws->busy++;
    ws->drained = 0;
    on_io_inner(ws, ev);
    if (ws->drained && ws->out.len == 0 && ws->state == ST_OPEN && ws->cbs.on_drain)
        ws->cbs.on_drain(ws, ws->arg);
    ws->busy--;
    if (ws->freed && !ws->busy)
        real_free(ws);
}

static void on_io_inner(npf_ws *ws, unsigned ev)
{
    if (ws->state == ST_CONNECTING && (npf_tcp_step(&ws->tcp, ev) <= 0 || start_upgrade(ws) < 0))
        return;
    if (flush_out(ws) < 0) {
        ws_fail(ws, 0, "write failed");
        return;
    }
    for (;;) {
        ssize_t r;
        if (buf_room(&ws->in, 4096)) {      /* read straight into it: no buffer on the stack */
            ws_fail(ws, 0, "out of memory");
            return;
        }
        r = npf_tcp_read(&ws->tcp, ws->in.p + ws->in.len, ws->in.cap - ws->in.len);
        if (r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE)
            break;
        if (r <= 0) {
            ws_fail(ws, 0, r == 0 ? "connection closed" : "read failed");
            return;
        }
        ws->in.len += (size_t)r;
        if (ws->state == ST_UPGRADE) {
            int u = parse_upgrade(ws);
            if (u < 0) {
                ws_fail(ws, 0, "websocket upgrade rejected");
                return;
            }
            if (u == 1) {
                ws->cbs.on_open(ws, ws->arg);
                if (ws->state == ST_DEAD)
                    return;
            }
        }
        if (ws->state == ST_OPEN) {
            int pr = parse_frames(ws);
            if (pr == -2)
                return;
            if (pr < 0) {
                ws_fail(ws, 1002, "protocol error");
                return;
            }
        }
    }
    if (flush_out(ws) < 0)
        ws_fail(ws, 0, "write failed");
}

static void ws_tcp_failed(void *arg, const char *why)
{
    ws_fail(arg, 0, why);
}

npf_ws *npf_ws_connect(npf_loop *loop, const char *url, const npf_ws_cbs *cbs, void *arg, int outside_vpn)
{
    npf_ws *ws = calloc(1, sizeof *ws);
    if (!ws)
        return NULL;
    ws->loop = loop;
    ws->cbs = *cbs;
    ws->arg = arg;
    npf_tcp_init(&ws->tcp, loop, ws->host, on_io, ws_tcp_failed, ws);
    ws->tcp.outside_vpn = outside_vpn;
    if (npf_url_parse(url, &ws->tcp.use_tls, ws->host, sizeof ws->host, &ws->tcp.port, ws->path, sizeof ws->path) < 0
        || (ws->tcp.use_tls && !npf_tls_available()) || npf_tcp_start(&ws->tcp, NULL) < 0) {
        npf_tcp_close(&ws->tcp);
        free(ws);
        return NULL;
    }
    return ws;
}

int64_t npf_ws_last_rx(const npf_ws *ws)
{
    return ws->last_rx;
}

int npf_ws_send(npf_ws *ws, const void *data, size_t len, int binary)
{
    return ws->state != ST_OPEN || send_frame(ws, binary ? 2 : 1, data, len) || flush_out(ws) < 0 ? -1 : 0;
}

int npf_ws_queue2(npf_ws *ws, const void *head, size_t hlen, const void *data, size_t len)
{
    return ws->state != ST_OPEN || send_frame2(ws, 2, head, hlen, data, len) ? -1 : 0;
}

int npf_ws_flush(npf_ws *ws)
{
    return ws->state != ST_OPEN || flush_out(ws) < 0 ? -1 : 0;
}

int npf_ws_ping(npf_ws *ws)
{
    return ws->state != ST_OPEN || send_frame(ws, 9, NULL, 0) || flush_out(ws) < 0 ? -1 : 0;
}

size_t npf_ws_pending(const npf_ws *ws)
{
    return ws->out.len;
}

const char *npf_ws_diag(const npf_ws *ws, char *buf, size_t cap)
{
    char k[200];
    snprintf(buf, cap, "%zu B queued here, %s", ws->out.len,
             ws->tcp.fd >= 0 ? npf_sock_tcp_diag(ws->tcp.fd, k, sizeof k) : "no socket");
    return buf;
}

void npf_ws_free(npf_ws *ws)
{
    if (!ws || ws->freed)
        return;
    ws->state = ST_DEAD;
    ws->freed = 1;
    if (!ws->busy)
        real_free(ws);
}

static void real_free(npf_ws *ws)
{
    npf_tcp_close(&ws->tcp);
    buf_free(&ws->out);
    buf_free(&ws->in);
    buf_free(&ws->frag);
    free(ws);
}

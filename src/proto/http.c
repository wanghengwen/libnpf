/* Minimal asynchronous HTTP(S) GET (npf/http.h). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include "npf/sys.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "npf/http.h"
#include "npf/platform.h"
#include "npf/tcp.h"
#include "npf/ws.h"                 /* npf_url_parse */

enum { H_CONNECTING, H_SEND, H_READ };     /* H_CONNECTING: npf_tcp (TLS too) */

struct npf_http {
    npf_loop    *loop;
    int          state;
    npf_tcp      tcp;
    npf_timer   *t;
    char         host[256];
    char         req[1024];
    size_t       req_len, req_off;
    uint8_t     *in;
    size_t       in_len, in_cap, max;
    /* the head (h_head) */
    size_t       body_off;
    int          status, chunked, have_length;
    size_t       length;
    npf_http_fn  fn;
    void        *arg;
};

static void h_free(npf_http *h)
{
    if (h->t)
        npf_timer_cancel(h->loop, h->t);
    npf_tcp_close(&h->tcp);
    free(h->in);
    free(h);
}

static void h_done(npf_http *h, int status, const uint8_t *body, size_t len, const char *err)
{
    npf_http_fn fn = h->fn;
    void *arg = h->arg;
    h->fn = NULL;
    fn(status, body, len, err, arg);
}

static void h_fail(npf_http *h, const char *err)
{
    h_done(h, -1, NULL, 0, err);
    h_free(h);
}

/* decode a chunked body in place; -1 when malformed or incomplete */
static long chunk_body(uint8_t *b, size_t n, int decode)
{
    size_t r = 0, w = 0;
    for (;;) {
        size_t sz = 0, digits = 0;
        const uint8_t *crlf = NULL;
        size_t i;
        for (i = r; i + 1 < n; i++)
            if (b[i] == '\r' && b[i + 1] == '\n') {
                crlf = b + i;
                break;
            }
        if (!crlf)
            return -1;
        for (i = r; b + i < crlf; i++) {
            unsigned ch = b[i], v;
            if (ch >= '0' && ch <= '9') v = ch - '0';
            else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
            else break;
            if (sz > (SIZE_MAX - v) / 16)
                return -1;
            sz = sz * 16 + v;
            digits++;
        }
        if (!digits || (b + i < crlf && b[i] != ';'))
            return -1;
        r = (size_t)(crlf - b) + 2;
        if (sz == 0) {
            /* The trailer section ends with an empty line. */
            for (;;) {
                for (i = r; i + 1 < n && !(b[i] == '\r' && b[i + 1] == '\n'); i++)
                    ;
                if (i + 1 >= n)
                    return -1;
                if (i == r)
                    return (long)w;
                if (!memchr(b + r, ':', i - r))
                    return -1;
                r = i + 2;
            }
        }
        if (n - r < 2 || sz > n - r - 2 || b[r + sz] != '\r' || b[r + sz + 1] != '\n')
            return -1;
        if (decode)
            memmove(b + w, b + r, sz);
        w += sz;
        r += sz + 2;
    }
}

/* the status line and the headers, for the end of the body and for the
 * response alike: 1 (the fields above set), 0 not all in yet, -1 malformed */
static int h_head(npf_http *h)
{
    char *s = (char *)h->in, *end, *line;
    h->chunked = h->have_length = 0;
    h->length = 0;
    if (!s || !(end = strstr(s, "\r\n\r\n")))
        return 0;
    if (h->in_len < 12 || (h->status = npf_http_status(s)) < 0)
        return -1;
    for (line = strstr(s, "\r\n") + 2; line < end; line = strstr(line, "\r\n") + 2) {
        char *eol = strstr(line, "\r\n");
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            char *v = strstr(line + 18, "chunked");
            h->chunked = v && v < eol;
        } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *p = line + 15;
            size_t value = 0;
            while (p < eol && (*p == ' ' || *p == '\t')) p++;
            if (p == eol || *p < '0' || *p > '9') return -1;
            while (p < eol && *p >= '0' && *p <= '9') {
                unsigned digit = (unsigned)(*p++ - '0');
                if (value > (SIZE_MAX - digit) / 10) return -1;
                value = value * 10 + digit;
            }
            while (p < eol && (*p == ' ' || *p == '\t')) p++;
            if (p != eol || (h->have_length && h->length != value)) return -1;
            h->length = value;
            h->have_length = 1;
        }
    }
    h->body_off = (size_t)(end + 4 - s);
    return 1;
}

/* A framed response ends independently of the TLS connection. In particular,
 * some HTTP servers close TCP without sending TLS close_notify afterwards.
 * A malformed head ends it too (h_response fails it). */
static int h_body_complete(npf_http *h)
{
    int r = h_head(h);
    size_t blen;
    if (r <= 0)
        return r < 0;
    blen = h->in_len - h->body_off;
    return h->chunked ? chunk_body(h->in + h->body_off, blen, 0) >= 0 : h->have_length && blen >= h->length;
}

/* the whole response is in: status line, headers, body */
static void h_response(npf_http *h)
{
    uint8_t *body;
    size_t blen;
    if (h_head(h) <= 0) {
        h_fail(h, "bad response");
        return;
    }
    body = h->in + h->body_off;
    blen = h->in_len - h->body_off;
    if (h->chunked) {
        long n = chunk_body(body, blen, 1);
        if (n < 0) {
            h_fail(h, "bad chunked body");
            return;
        }
        blen = (size_t)n;
    } else if (h->have_length && h->length < blen) {
        blen = h->length;
    } else if (h->have_length && h->length > blen) {
        h_fail(h, "body cut short");
        return;
    }
    if (blen > h->max) {
        h_fail(h, "response too large");
        return;
    }
    h_done(h, h->status, body, blen, NULL);
    h_free(h);
}

static void h_io(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_http *h = arg;
    (void)loop;
    (void)fd;
    if (h->state == H_CONNECTING) {
        if (npf_tcp_step(&h->tcp, ev) <= 0)
            return;
        h->state = H_SEND;
    }
    if (h->state == H_SEND) {
        while (h->req_off < h->req_len) {
            ssize_t w = npf_tcp_write(&h->tcp, h->req + h->req_off, h->req_len - h->req_off);
            if (w == NPF_TLS_WANT_WRITE || w == NPF_TLS_WANT_READ) {
                npf_loop_mod(h->loop, h->tcp.fd, NPF_EV_READ | NPF_EV_WRITE);
                return;
            }
            if (w <= 0) {
                h_fail(h, "write failed");
                return;
            }
            h->req_off += (size_t)w;
        }
        h->state = H_READ;
        npf_loop_mod(h->loop, h->tcp.fd, NPF_EV_READ);
    }
    for (;;) {
        ssize_t r;
        if (h->in_len + 4096 + 1 > h->in_cap) {
            size_t cap = h->in_cap ? h->in_cap * 2 : 16384;
            uint8_t *p;
            if (h->in_len > h->max + 16384) {
                h_fail(h, "response too large");
                return;
            }
            if (!(p = realloc(h->in, cap))) {
                h_fail(h, "no memory");
                return;
            }
            h->in = p;
            h->in_cap = cap;
        }
        r = npf_tcp_read(&h->tcp, h->in + h->in_len, h->in_cap - h->in_len - 1);
        if (r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE)
            return;
        if (r < 0) {
            h_fail(h, "read failed");
            return;
        }
        if (r == 0) {               /* Connection: close: the response is complete */
            h->in[h->in_len] = 0;
            h_response(h);
            return;
        }
        h->in_len += (size_t)r;
        h->in[h->in_len] = 0;
        if (h->in_len > h->max + 16384) {   /* max of body, headers within 16 KB: not twice that */
            h_fail(h, "response too large");
            return;
        }
        if (h_body_complete(h)) {
            h_response(h);
            return;
        }
    }
}

static void h_timeout(npf_loop *loop, void *arg)
{
    npf_http *h = arg;
    (void)loop;
    h->t = NULL;
    h_fail(h, "timeout");
}

static void h_tcp_failed(void *arg, const char *why)
{
    h_fail(arg, why);
}

npf_http *npf_http_get(npf_loop *loop, const char *url, const struct sockaddr_storage *addr, const char *accept,
                       size_t max, int timeout_ms, npf_http_fn fn, void *arg)
{
    npf_http *h = calloc(1, sizeof *h);
    char path[700];
    int n;
    if (!h)
        return NULL;
    h->loop = loop;
    h->fn = fn;
    h->arg = arg;
    h->max = max;
    npf_tcp_init(&h->tcp, loop, h->host, h_io, h_tcp_failed, h);
    if (npf_url_parse(url, &h->tcp.use_tls, h->host, sizeof h->host, &h->tcp.port, path, sizeof path) < 0
        || (h->tcp.use_tls && !npf_tls_available())) {
        free(h);
        return NULL;
    }
    n = snprintf(h->req, sizeof h->req,
                 "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: npf\r\nAccept: %s\r\nConnection: close\r\n\r\n", path,
                 h->host, accept ? accept : "*/*");
    if (n < 0 || n >= (int)sizeof h->req) {
        free(h);
        return NULL;
    }
    h->req_len = (size_t)n;
    h->t = npf_timer_add(loop, timeout_ms > 0 ? timeout_ms : 15000, h_timeout, h);
    if (!h->t || npf_tcp_start(&h->tcp, addr) < 0) {
        h->fn = NULL;
        h_free(h);
        return NULL;
    }
    return h;
}

void npf_http_cancel(npf_http *h)
{
    /* Completion already owns the final free while fn is running. */
    if (h && h->fn)
        h_free(h);
}

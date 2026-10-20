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
#include "npf/resolve.h"
#include "npf/tls.h"
#include "npf/ws.h"                 /* npf_url_parse */

enum { H_RESOLVING, H_CONNECTING, H_TLS, H_SEND, H_READ };

struct npf_http {
    npf_loop    *loop;
    int          state;
    int          fd;
    int          use_tls;
    npf_tls     *tls;
    npf_resolve *resolve;
    npf_timer   *t, *t_connect;
    struct sockaddr_storage cand[NPF_RESOLVE_MAX];
    socklen_t cand_len[NPF_RESOLVE_MAX];
    int ncand, icand;
    char         host[256];
    int          port;
    char         req[1024];
    size_t       req_len, req_off;
    uint8_t     *in;
    size_t       in_len, in_cap, max;
    npf_http_fn  fn;
    void        *arg;
};

static int h_next(npf_http *h);

static void h_free(npf_http *h)
{
    if (h->t)
        npf_timer_cancel(h->loop, h->t);
    if (h->t_connect)
        npf_timer_cancel(h->loop, h->t_connect);
    npf_resolve_cancel(h->resolve);
    if (h->tls)
        npf_tls_free(h->tls);
    if (h->fd >= 0) {
        npf_loop_del(h->loop, h->fd);
        npf_sock_close(h->fd);
    }
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

static long dechunk(uint8_t *b, size_t n)
{
    return chunk_body(b, n, 1);
}

/* A framed response ends independently of the TLS connection. In particular,
 * some HTTP servers close TCP without sending TLS close_notify afterwards. */
static int h_body_complete(npf_http *h)
{
    char *s = (char *)h->in, *end = strstr(s, "\r\n\r\n"), *line;
    size_t length = 0, blen;
    int have_length = 0, chunked = 0;
    uint8_t *body;
    if (!end)
        return 0;
    for (line = strstr(s, "\r\n") + 2; line < end; line = strstr(line, "\r\n") + 2) {
        char *eol = strstr(line, "\r\n");
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            char *v = strstr(line + 18, "chunked");
            chunked = v && v < eol;
        } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *p = line + 15;
            size_t value = 0;
            while (p < eol && (*p == ' ' || *p == '\t')) p++;
            if (p == eol || *p < '0' || *p > '9') return 0;
            while (p < eol && *p >= '0' && *p <= '9') {
                unsigned digit = (unsigned)(*p++ - '0');
                if (value > (SIZE_MAX - digit) / 10) return 0;
                value = value * 10 + digit;
            }
            while (p < eol && (*p == ' ' || *p == '\t')) p++;
            if (p != eol || (have_length && length != value)) return 0;
            length = value;
            have_length = 1;
        }
    }
    body = (uint8_t *)end + 4;
    blen = h->in_len - (size_t)(body - h->in);
    return chunked ? chunk_body(body, blen, 0) >= 0 : have_length && blen >= length;
}

/* the whole response is in: status line, headers, body */
static void h_response(npf_http *h)
{
    char *s = (char *)h->in, *hdr_end, *line;
    int status = 0, chunked = 0;
    long clen = -1;
    uint8_t *body;
    size_t blen;
    if (h->in_len < 12 || (status = npf_http_status(s)) < 0) {
        h_fail(h, "bad response");
        return;
    }
    hdr_end = strstr(s, "\r\n\r\n");
    if (!hdr_end) {
        h_fail(h, "bad response");
        return;
    }
    for (line = strstr(s, "\r\n") + 2; line < hdr_end; line = strstr(line, "\r\n") + 2) {
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 && strstr(line, "chunked") && strstr(line, "chunked") < strstr(line, "\r\n"))
            chunked = 1;
        else if (strncasecmp(line, "Content-Length:", 15) == 0)
            clen = strtol(line + 15, NULL, 10);
    }
    body = (uint8_t *)hdr_end + 4;
    blen = h->in_len - (size_t)(body - h->in);
    if (chunked) {
        long n = dechunk(body, blen);
        if (n < 0) {
            h_fail(h, "bad chunked body");
            return;
        }
        blen = (size_t)n;
    } else if (clen >= 0 && (size_t)clen < blen) {
        blen = (size_t)clen;
    } else if (clen >= 0 && (size_t)clen > blen) {
        h_fail(h, "body cut short");
        return;
    }
    h_done(h, status, body, blen, NULL);
    h_free(h);
}

static ssize_t h_write(npf_http *h, const void *p, size_t n)
{
    ssize_t r;
    if (h->tls)
        return npf_tls_write(h->tls, p, n);
    r = send(h->fd, p, n, MSG_NOSIGNAL);
    return r < 0 && npf_sock_again() ? NPF_TLS_WANT_WRITE : r;
}

static ssize_t h_read(npf_http *h, void *p, size_t n)
{
    ssize_t r;
    if (h->tls)
        return npf_tls_read(h->tls, p, n);
    r = recv(h->fd, p, n, 0);
    return r < 0 && npf_sock_again() ? NPF_TLS_WANT_READ : r;
}

static void h_io(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_http *h = arg;
    (void)loop;
    (void)fd;
    if (h->state == H_CONNECTING) {
        int err = 0;
        socklen_t el = sizeof err;
        getsockopt(h->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
        if (err) {
            if (h_next(h) < 0)
                h_fail(h, "cannot connect to any server address");
            return;
        }
        /* a refused connect is POLLHUP alone on macOS (no POLLERR): any event
         * checks SO_ERROR above; without an error the socket must be writable */
        if (!(ev & NPF_EV_WRITE))
            return;
        npf_timer_cancel(h->loop, h->t_connect);
        h->t_connect = NULL;
        h->state = h->use_tls ? H_TLS : H_SEND;
    }
    if (h->state == H_TLS) {
        int r = npf_tls_handshake(h->tls);
        if (r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE) {
            npf_loop_mod(h->loop, h->fd, r == NPF_TLS_WANT_WRITE ? NPF_EV_READ | NPF_EV_WRITE : NPF_EV_READ);
            return;
        }
        if (r < 0) {
            h_fail(h, "tls handshake failed");
            return;
        }
        h->state = H_SEND;
    }
    if (h->state == H_SEND) {
        while (h->req_off < h->req_len) {
            ssize_t w = h_write(h, h->req + h->req_off, h->req_len - h->req_off);
            if (w == NPF_TLS_WANT_WRITE || w == NPF_TLS_WANT_READ) {
                npf_loop_mod(h->loop, h->fd, NPF_EV_READ | NPF_EV_WRITE);
                return;
            }
            if (w <= 0) {
                h_fail(h, "write failed");
                return;
            }
            h->req_off += (size_t)w;
        }
        h->state = H_READ;
        npf_loop_mod(h->loop, h->fd, NPF_EV_READ);
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
        r = h_read(h, h->in + h->in_len, h->in_cap - h->in_len - 1);
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

static int h_connect(npf_http *h, const struct sockaddr_storage *a, socklen_t al)
{
    int fd = npf_socket(a->ss_family, SOCK_STREAM, 0, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)a, al) < 0 && !npf_sock_inprogress()) {
        npf_sock_close(fd);
        return -1;
    }
    h->fd = fd;
    if (h->use_tls && !(h->tls = npf_tls_new(fd, h->host)))
        return -1;
    h->state = H_CONNECTING;
    return npf_loop_add(h->loop, fd, NPF_EV_READ | NPF_EV_WRITE, h_io, h);
}

static void h_connect_timeout(npf_loop *loop, void *arg)
{
    npf_http *h = arg;
    (void)loop;
    h->t_connect = NULL;
    if (h_next(h) < 0)
        h_fail(h, "connect timeout");
}

static int h_next(npf_http *h)
{
    if (h->t_connect)
        npf_timer_cancel(h->loop, h->t_connect);
    h->t_connect = NULL;
    for (;;) {
        if (h->tls)
            npf_tls_free(h->tls);
        h->tls = NULL;
        if (h->fd >= 0) {
            npf_loop_del(h->loop, h->fd);
            npf_sock_close(h->fd);
        }
        h->fd = -1;
        if (h->icand == h->ncand)
            return -1;
        h->icand++;
        if (h_connect(h, &h->cand[h->icand - 1], h->cand_len[h->icand - 1]) == 0)
            break;
    }
    h->t_connect = npf_timer_add(h->loop, h->icand < h->ncand ? 1000 : 5000, h_connect_timeout, h);
    return h->t_connect ? 0 : -1;
}

static void h_resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens, int n,
                       void *arg)
{
    npf_http *h = arg;
    (void)r;
    h->resolve = NULL;
    if (err || n < 1 || n > NPF_RESOLVE_MAX) {
        h_fail(h, "cannot resolve");
        return;
    }
    memcpy(h->cand, addrs, (size_t)n * sizeof *addrs);
    memcpy(h->cand_len, lens, (size_t)n * sizeof *lens);
    h->ncand = n;
    if (h_next(h) < 0)
        h_fail(h, "cannot connect");
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
    h->fd = -1;
    h->fn = fn;
    h->arg = arg;
    h->max = max;
    if (npf_url_parse(url, &h->use_tls, h->host, sizeof h->host, &h->port, path, sizeof path) < 0
        || (h->use_tls && !npf_tls_available())) {
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
    if (addr) {
        struct sockaddr_storage a = *addr;
        socklen_t al = a.ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        h->cand[0] = a;
        h->cand_len[0] = al;
        h->ncand = 1;
        if (h_next(h) < 0) {
            h->fn = NULL;
            h_free(h);
            return NULL;
        }
        return h;
    }
    h->state = H_RESOLVING;
    h->resolve = npf_resolve_start(loop, h->host, (uint16_t)h->port, SOCK_STREAM, h_resolved, h);
    if (!h->resolve) {
        h->fn = NULL;
        h_free(h);
        return NULL;
    }
    return h;
}

void npf_http_cancel(npf_http *h)
{
    if (h)
        h_free(h);
}

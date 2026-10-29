/* The TCP connection, with TLS or without, of a WebSocket (ws.c) and of an
 * HTTP request (http.c), and the URLs they are given (npf/tcp.h). */
#ifndef _WIN32
#define _GNU_SOURCE         /* struct addrinfo (resolve.h) */
#endif
#include <stdlib.h>
#include <string.h>

#include "npf/tcp.h"

int npf_url_parse(const char *url, int *tls, char *host, size_t hcap, int *port, char *path, size_t pcap)
{
    const char *p, *h, *he, *ps;
    size_t hl;
    /* These components are copied into HTTP request lines and headers. */
    for (p = url; *p; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p == 0x7f)
            return -1;
    if (strncmp(url, "wss://", 6) == 0) { *tls = 1; p = url + 6; *port = 443; }
    else if (strncmp(url, "ws://", 5) == 0) { *tls = 0; p = url + 5; *port = 80; }
    else if (strncmp(url, "https://", 8) == 0) { *tls = 1; p = url + 8; *port = 443; }   /* npf_http */
    else if (strncmp(url, "http://", 7) == 0) { *tls = 0; p = url + 7; *port = 80; }
    else return -1;
    ps = strchr(p, '/');
    if (!ps)
        ps = p + strlen(p);
    if (*p == '[') {
        h = p + 1;
        he = memchr(h, ']', (size_t)(ps - h));
        if (!he)
            return -1;
        p = he + 1;
    } else {
        h = p;
        he = memchr(p, ':', (size_t)(ps - p));
        if (!he)
            he = ps;
        p = he;
    }
    if (p < ps && *p == ':') {
        char *end;
        long v = strtol(p + 1, &end, 10);
        if (end != ps || v <= 0 || v > 65535)
            return -1;
        *port = (int)v;
    } else if (p != ps) {
        return -1;
    }
    hl = (size_t)(he - h);
    if (hl == 0 || hl >= hcap)
        return -1;
    memcpy(host, h, hl);
    host[hl] = 0;
    if (strlen(*ps ? ps : "/") >= pcap)
        return -1;
    strcpy(path, *ps ? ps : "/");
    return 0;
}

enum { TCP_RESOLVING, TCP_CONNECTING, TCP_TLS, TCP_READY };

/* the socket (and TLS) of the address tried */
static void tcp_drop(npf_tcp *c)
{
    if (c->tls)
        npf_tls_free(c->tls);
    c->tls = NULL;
    if (c->fd >= 0) {
        npf_loop_del(c->loop, c->fd);
        npf_sock_close(c->fd);
    }
    c->fd = -1;
}

static int tcp_next(npf_tcp *c);

/* Try every address, including after asynchronous errors. A blackholed
 * address gets one second before the next; the final address gets five. */
static void tcp_timeout(npf_loop *loop, void *arg)
{
    npf_tcp *c = arg;
    (void)loop;
    c->t = NULL;
    if (tcp_next(c) < 0)
        c->fail(c->arg, "connect timeout");
}

static int tcp_next(npf_tcp *c)
{
    int fd = -1, one = 1;
    if (c->t)
        npf_timer_cancel(c->loop, c->t);
    c->t = NULL;
    tcp_drop(c);
    while (c->icand < c->ncand) {
        int i = c->icand++;
        fd = npf_socket(c->cand[i].ss_family, SOCK_STREAM, 0, 0);
        if (fd < 0)
            continue;
        if (c->outside_vpn)
            npf_net_bypass(fd, c->cand[i].ss_family);    /* it could not: the default route */
        if (connect(fd, (const struct sockaddr *)&c->cand[i], c->cand_len[i]) == 0 || npf_sock_inprogress())
            break;
        npf_sock_close(fd);
        fd = -1;
    }
    if (fd < 0)
        return -1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    c->fd = fd;
    if (c->use_tls && !(c->tls = npf_tls_new(fd, c->host)))
        return -1;
    c->state = TCP_CONNECTING;
    if (npf_loop_add(c->loop, fd, NPF_EV_READ | NPF_EV_WRITE, c->io, c->arg) < 0)
        return -1;
    c->t = npf_timer_add(c->loop, c->icand < c->ncand ? 1000 : 5000, tcp_timeout, c);
    return c->t ? 0 : -1;
}

/* the host's name looked up off the loop thread: a reconnect of the
 * signaling no longer stalls the sessions while DNS is slow (review R8) */
static void tcp_resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens, int n,
                         void *arg)
{
    npf_tcp *c = arg;
    (void)r;
    c->resolve = NULL;
    if (err || n < 1 || n > NPF_RESOLVE_MAX) {
        c->fail(c->arg, "cannot resolve the server name");
        return;
    }
    memcpy(c->cand, addrs, (size_t)n * sizeof *addrs);
    memcpy(c->cand_len, lens, (size_t)n * sizeof *lens);
    c->ncand = n;
    if (tcp_next(c) < 0)
        c->fail(c->arg, "cannot connect");
}

void npf_tcp_init(npf_tcp *c, npf_loop *loop, const char *host, npf_io_fn io,
                  void (*fail)(void *arg, const char *why), void *arg)
{
    memset(c, 0, sizeof *c);
    c->loop = loop;
    c->host = host;
    c->io = io;
    c->fail = fail;
    c->arg = arg;
    c->fd = -1;
}

int npf_tcp_start(npf_tcp *c, const struct sockaddr_storage *addr)
{
    struct sockaddr_storage *a = &c->cand[0];
    memset(a, 0, sizeof *a);
    if (addr) {
        *a = *addr;
    } else if (inet_pton(AF_INET, c->host, &((struct sockaddr_in *)a)->sin_addr) == 1) {
        a->ss_family = AF_INET;
        ((struct sockaddr_in *)a)->sin_port = htons((uint16_t)c->port);
    } else if (inet_pton(AF_INET6, c->host, &((struct sockaddr_in6 *)a)->sin6_addr) == 1) {
        a->ss_family = AF_INET6;
        ((struct sockaddr_in6 *)a)->sin6_port = htons((uint16_t)c->port);
    } else {
        c->state = TCP_RESOLVING;
        c->resolve = npf_resolve_start(c->loop, c->host, (uint16_t)c->port, SOCK_STREAM, tcp_resolved, c);
        return c->resolve ? 0 : -1;
    }
    c->cand_len[0] = a->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    c->ncand = 1;
    return tcp_next(c);
}

int npf_tcp_step(npf_tcp *c, unsigned events)
{
    if (c->state == TCP_CONNECTING) {
        int err = 0;
        socklen_t el = sizeof err;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) {
            if (tcp_next(c) == 0)
                return 0;
            c->fail(c->arg, "cannot connect to any server address");
            return -1;
        }
        /* a refused connect is POLLHUP alone on macOS (no POLLERR): any event
         * checks SO_ERROR above; without an error the socket must be writable */
        if (!(events & NPF_EV_WRITE))
            return 0;
        npf_timer_cancel(c->loop, c->t);
        c->t = NULL;
        c->state = c->tls ? TCP_TLS : TCP_READY;
    }
    if (c->state == TCP_TLS) {
        int r = npf_tls_handshake(c->tls);
        if (r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE) {
            npf_loop_mod(c->loop, c->fd, NPF_EV_READ | (r == NPF_TLS_WANT_WRITE ? NPF_EV_WRITE : 0));
            return 0;
        }
        if (r < 0) {
            c->fail(c->arg, "tls handshake failed");
            return -1;
        }
        c->state = TCP_READY;
    }
    return c->state == TCP_READY;
}

ssize_t npf_tcp_read(npf_tcp *c, void *p, size_t n)
{
    ssize_t r;
    if (c->tls)
        return npf_tls_read(c->tls, p, n);
    r = recv(c->fd, p, n, 0);
    if (r < 0)
        return npf_sock_again() ? NPF_TLS_WANT_READ : -1;
    return r;
}

ssize_t npf_tcp_write(npf_tcp *c, const void *p, size_t n)
{
    ssize_t r;
    if (c->tls)
        return npf_tls_write(c->tls, p, n);
    r = send(c->fd, p, n, MSG_NOSIGNAL);
    if (r < 0)
        return npf_sock_again() ? NPF_TLS_WANT_WRITE : -1;
    return r;
}

void npf_tcp_close(npf_tcp *c)
{
    if (c->t)
        npf_timer_cancel(c->loop, c->t);
    c->t = NULL;
    npf_resolve_cancel(c->resolve);
    c->resolve = NULL;
    tcp_drop(c);
}

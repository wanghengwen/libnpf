/* Two tunnels joined in memory: hello, SOCKS5 CONNECT through the callee to a
 * local TCP server, 3 MB with flow control, FIN, and a policy denial; a
 * request with data after it in one frame, the greeting deadline, Happy
 * Eyeballs over a name's addresses. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/crypto.h"
#include "npf/loop.h"
#include "npf/platform.h"
#include "npf/tunnel.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

#define TOTAL (3 * 1024 * 1024)

typedef struct end {
    npf_tunnel *t;
    struct end *peer;
    uint8_t    *q;              /* control bytes on their way to the peer */
    size_t      len, cap;
    uint8_t    *dq;             /* data messages on their way: len(4) | message */
    size_t      dlen, dcap;
    int         ready;
} end;

static npf_loop *loop;
static end A, B;
static npf_timer *t_pump;

static void pump(npf_loop *l, void *arg);

static int io_write_ctrl(void *arg, const uint8_t *buf, size_t len)
{
    end *e = arg;
    if (e->len + len > e->cap) {
        e->cap = (e->len + len) * 2;
        e->q = realloc(e->q, e->cap);
    }
    memcpy(e->q + e->len, buf, len);
    e->len += len;
    if (!t_pump)
        t_pump = npf_timer_add(loop, 0, pump, NULL);
    return 0;
}

static int io_write_data(void *arg, const uint8_t *msg, size_t len)
{
    end *e = arg;
    if (e->dlen + 4 + len > e->dcap) {
        e->dcap = (e->dlen + 4 + len) * 2;
        e->dq = realloc(e->dq, e->dcap);
    }
    npf_le32(e->dq + e->dlen, (uint32_t)len);
    memcpy(e->dq + e->dlen + 4, msg, len);
    e->dlen += 4 + len;
    if (!t_pump)
        t_pump = npf_timer_add(loop, 0, pump, NULL);
    return 0;
}

static size_t io_backlog(void *arg)
{
    return ((end *)arg)->dlen;
}

static void io_ready(void *arg)
{
    ((end *)arg)->ready = 1;
}

static int fails_expected;

static void io_broken(void *arg, const char *why)
{
    (void)arg;
    if (fails_expected)
        return;
    fprintf(stderr, "tunnel broken: %s\n", why);
    fails++;
}

/* deliver like the transport: control first (stream 0's priority), in
 * pieces that may split units; then up to 64 KiB of whole data messages */
static void pump(npf_loop *l, void *arg)
{
    end *e[2] = {&A, &B};
    int i;
    (void)l;
    (void)arg;
    t_pump = NULL;
    for (i = 0; i < 2; i++) {
        size_t n = e[i]->len < 5 ? e[i]->len : e[i]->len / 2 + 1, off = 0;
        if (!e[i]->t || !e[i]->peer->t) {   /* freed by a test: what was on its way goes */
            e[i]->len = e[i]->dlen = 0;
            continue;
        }
        if (n) {
            npf_tunnel_input_ctrl(e[i]->peer->t, e[i]->q, n);
            if (e[i]->len > n)
                memmove(e[i]->q, e[i]->q + n, e[i]->len - n);
            e[i]->len -= n;
        }
        while (off + 4 <= e[i]->dlen && off < 65536) {
            size_t m = npf_rd32(e[i]->dq + off);
            npf_tunnel_input_data(e[i]->peer->t, e[i]->dq + off + 4, m);
            off += 4 + m;
        }
        if (e[i]->dlen > off)
            memmove(e[i]->dq, e[i]->dq + off, e[i]->dlen - off);
        e[i]->dlen -= off;
        npf_tunnel_kick(e[i]->t);
    }
    if ((A.len || B.len || A.dlen || B.dlen) && !t_pump)
        t_pump = npf_timer_add(loop, 0, pump, NULL);
}

/* target server: sends TOTAL bytes of a pattern, then closes */
typedef struct target {
    int lfd, fd;
    size_t sent;
} target;

static void target_io(npf_loop *l, int fd, unsigned ev, void *arg)
{
    target *t = arg;
    (void)ev;
    while (t->sent < TOTAL) {
        uint8_t buf[16384];
        size_t i, n = TOTAL - t->sent < sizeof buf ? TOTAL - t->sent : sizeof buf;
        ssize_t w;
        for (i = 0; i < n; i++)
            buf[i] = (uint8_t)((t->sent + i) * 7);
        w = send(fd, buf, n, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w <= 0)
            return;
        t->sent += (size_t)w;
    }
    npf_loop_del(l, fd);
    close(fd);
}

static void target_accept(npf_loop *l, int lfd, unsigned ev, void *arg)
{
    target *t = arg;
    (void)ev;
    t->fd = npf_accept(lfd);
    if (t->fd >= 0)
        npf_loop_add(l, t->fd, NPF_EV_WRITE, target_io, t);
}

static int app_read(int fd, uint8_t *pattern_ok, size_t *got, int *eof)
{
    for (;;) {
        uint8_t buf[65536];
        ssize_t r = recv(fd, buf, sizeof buf, MSG_DONTWAIT), i;
        if (r == 0) {
            *eof = 1;
            return 0;
        }
        if (r < 0)
            return errno == EAGAIN ? 0 : -1;
        for (i = 0; i < r; i++)
            if (buf[i] != (uint8_t)((*got + (size_t)i) * 7))
                *pattern_ok = 0;
        *got += (size_t)r;
    }
}

/* read exactly n bytes from the application's end, running the loop */
static int app_take(npf_loop *loop, int fd, uint8_t *out, size_t n)
{
    size_t got = 0;
    int64_t until = npf_mono_ms() + 5000;
    while (got < n && npf_mono_ms() < until) {
        ssize_t r = recv(fd, out + got, n - got, MSG_DONTWAIT);
        if (r > 0)
            got += (size_t)r;
        else if (r == 0)
            return -1;
        else
            npf_loop_once(loop, 5);
    }
    return got == n ? 0 : -1;
}

/* -D: the application speaks SOCKS5 itself; split: greeting, then the
 * request after the method reply (as curl does) */
static int socks_app(npf_loop *loop, npf_tunnel *t, uint16_t port, int split)
{
    int sp[2], eof = 0;
    uint8_t rep[10], ok = 1, req[13] = {5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 0};
    size_t got = 0;
    int64_t until;
    req[11] = (uint8_t)(port >> 8);
    req[12] = (uint8_t)port;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    if (npf_tunnel_open(t, sp[0], 1, NULL, 0) < 0)
        return -1;
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
    if (split) {
        if (send(sp[1], req, 3, 0) != 3 || app_take(loop, sp[1], rep, 2) < 0 || rep[0] != 5 || rep[1] != 0
            || send(sp[1], req + 3, 10, 0) != 10)
            return -1;
    } else if (send(sp[1], req, 13, 0) != 13 || app_take(loop, sp[1], rep, 2) < 0 || rep[0] != 5 || rep[1] != 0) {
        return -1;
    }
    if (app_take(loop, sp[1], rep, 10) < 0 || rep[0] != 5 || rep[1] != 0)
        return -1;                      /* the CONNECT reply, once: the server's method reply was dropped */
    until = npf_mono_ms() + 10000;
    while (!eof && npf_mono_ms() < until) {
        npf_loop_once(loop, 5);
        if (app_read(sp[1], &ok, &got, &eof) < 0)
            break;
    }
    close(sp[1]);
    return got == TOTAL && ok && eof ? 0 : -1;
}

/* the callee's check of a hosted grant's targets: this port is not one */
static uint16_t refused_port;
static int io_target_ok(void *arg, const char *host, uint16_t port)
{
    (void)arg;
    return !(port == refused_port && strcmp(host, "127.0.0.1") == 0);
}

/* the caller's sublinks that ended: how many, the last one's id and bytes */
static int done_n;
static uint32_t done_id;
static npf_sublink_stats done_st;
static char done_end[32];
static npf_tunnel **free_in_done;   /* the callback frees this tunnel (the session ends in it) */
static void io_sublink_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    (void)arg;
    if (free_in_done) {
        npf_tunnel_free(*free_in_done);
        *free_in_done = NULL;
    }
    done_n++;
    done_id = id;
    done_st = *st;
    snprintf(done_end, sizeof done_end, "%s", st->end);
}

/* a virtual local end (npf_tunnel_open_v, as the TUN's lwIP connections):
 * it reads "hello" (said 0; the test target does not read: 1 skips it) and
 * then its end; it takes at most 3000 bytes a write and
 * then has no room until room_tick gives some again (as lwIP's sent
 * callback does) */
typedef struct vend {
    npf_tunnel *t;
    uint32_t    sid;
    size_t      got;
    uint8_t     ok;
    int         said, room, shut, closed, reset, writes;
} vend;

static ssize_t v_read(void *arg, uint8_t *buf, size_t cap)
{
    vend *v = arg;
    if (v->said == 0 && cap >= 5) {
        memcpy(buf, "hello", 5);
        v->said = 1;
        return 5;
    }
    v->said = 2;
    return 0;
}

static ssize_t v_write(void *arg, const uint8_t *buf, size_t len)
{
    vend *v = arg;
    size_t i, n = len < 3000 ? len : 3000;
    if (!v->room)
        return 0;
    for (i = 0; i < n; i++)
        if (buf[i] != (uint8_t)((v->got + i) * 7))
            v->ok = 0;
    v->got += n;
    v->room = 0;
    v->writes++;
    return (ssize_t)n;
}

static unsigned v_ready(void *arg)
{
    vend *v = arg;
    return (v->said < 2 ? NPF_EV_READ : 0) | (v->room ? NPF_EV_WRITE : 0);
}

static void v_shutdown(void *arg)
{
    ((vend *)arg)->shut = 1;
}

static void v_closed(void *arg, int reset)
{
    vend *v = arg;
    v->closed++;
    v->reset = reset;
}

static void room_tick(npf_loop *l, void *arg)
{
    vend *v = arg;
    (void)l;
    if (!v->room && !v->closed) {
        v->room = 1;
        npf_tunnel_vkick(v->t, v->sid);
    }
}

static const npf_vend_io k_vend = {v_read, v_write, v_ready, v_shutdown, v_closed};

/* a virtual end that sends SEND_TOTAL pattern bytes (a POST); its owner
 * then closes it at once (npf_tunnel_vclose, not a reset) */
#define SEND_TOTAL 200000                /* within the first window: all of it queued at once */
typedef struct vsend {
    size_t sent;
    int    closed;
} vsend;

static ssize_t vs_read(void *arg, uint8_t *buf, size_t cap)
{
    vsend *v = arg;
    size_t i, n = SEND_TOTAL - v->sent < cap ? SEND_TOTAL - v->sent : cap;
    if (n == 0)
        return -1;                      /* nothing now */
    for (i = 0; i < n; i++)
        buf[i] = (uint8_t)((v->sent + i) * 7);
    v->sent += n;
    return (ssize_t)n;
}
static ssize_t vs_write(void *arg, const uint8_t *buf, size_t len) { (void)arg; (void)buf; return (ssize_t)len; }
static unsigned vs_ready(void *arg) { return ((vsend *)arg)->sent < SEND_TOTAL ? NPF_EV_READ | NPF_EV_WRITE : NPF_EV_WRITE; }
static void vs_shutdown(void *arg) { (void)arg; }
static void vs_closed(void *arg, int reset) { (void)reset; ((vsend *)arg)->closed++; }
static const npf_vend_io k_vsend = {vs_read, vs_write, vs_ready, vs_shutdown, vs_closed};

/* a target that only reads: the bytes and whether they are the pattern */
typedef struct sink {
    int    lfd, fd;
    size_t got;
    uint8_t ok;
} sink;

static void sink_io(npf_loop *l, int fd, unsigned ev, void *arg)
{
    sink *k = arg;
    uint8_t buf[4096];
    ssize_t r, i;
    (void)ev;
    while ((r = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0) {
        for (i = 0; i < r; i++)
            if (buf[i] != (uint8_t)((k->got + (size_t)i) * 7))
                k->ok = 0;
        k->got += (size_t)r;
    }
    if (r == 0) {
        npf_loop_del(l, fd);
        close(fd);
        k->fd = -1;
    }
}

static void sink_accept(npf_loop *l, int lfd, unsigned ev, void *arg)
{
    sink *k = arg;
    (void)ev;
    k->fd = npf_accept(lfd);
    if (k->fd >= 0)
        npf_loop_add(l, k->fd, NPF_EV_READ, sink_io, k);
}

static int listen_lo(int backlog, uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int fd = npf_socket(AF_INET, SOCK_STREAM, 0, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(fd, backlog) < 0
        || getsockname(fd, (struct sockaddr *)&a, &al) < 0)
        return -1;
    *port = ntohs(a.sin_port);
    return fd;
}

/* the test resolver: "he.test" is a port that never answers, then the target */
static uint16_t he_dead, he_live;
static int he_resolve(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens, int max)
{
    int i;
    uint16_t ports[2] = {he_dead, he_live};
    (void)port;
    if (strcmp(host, "he.test") != 0 || max < 2)
        return -1;
    for (i = 0; i < 2; i++) {
        struct sockaddr_in *a = (struct sockaddr_in *)&out[i];
        memset(&out[i], 0, sizeof out[i]);
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(ports[i]);
        lens[i] = sizeof *a;
    }
    return 2;
}

static void v6(struct sockaddr_storage *a, int tag)
{
    memset(a, 0, sizeof *a);
    ((struct sockaddr_in6 *)a)->sin6_family = AF_INET6;
    ((struct sockaddr_in6 *)a)->sin6_port = htons((uint16_t)tag);
}

static void v4(struct sockaddr_storage *a, int tag)
{
    memset(a, 0, sizeof *a);
    ((struct sockaddr_in *)a)->sin_family = AF_INET;
    ((struct sockaddr_in *)a)->sin_port = htons((uint16_t)tag);
}

static int tag_of(const struct sockaddr_storage *a)
{
    return ntohs(a->ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)a)->sin6_port
                                          : ((const struct sockaddr_in *)a)->sin_port);
}

int test_tunnel(void)
{
    static const npf_tunnel_io io = {io_write_ctrl, io_write_data, io_backlog, io_ready, NULL, io_broken, NULL, NULL,
                                     io_sublink_done};
    static const npf_tunnel_io io_b = {io_write_ctrl, io_write_data, io_backlog, io_ready, NULL, io_broken, NULL,
                                       io_target_ok, NULL};
    int sid;
    npf_policy pol;
    target tg;
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int sp[2], sp2[2], eof = 0, i;
    uint8_t ok = 1;
    size_t got = 0;
    int64_t until;

    loop = npf_loop_new();
    memset(&pol, 0, sizeof pol);
    npf_policy_add(&pol, "lan");           /* the host and its LAN (a resource) */
    npf_policy_refresh(&pol);
    memset(&A, 0, sizeof A);
    memset(&B, 0, sizeof B);
    A.peer = &B;
    B.peer = &A;
    A.t = npf_tunnel_new(loop, 1, &io, &A, NULL);
    B.t = npf_tunnel_new(loop, 0, &io_b, &B, &pol);
    npf_tunnel_start(B.t);              /* the callee says hello first */
    for (i = 0; i < 50 && !(A.ready && B.ready); i++)
        npf_loop_once(loop, 5);
    CHECK(A.ready && B.ready, "hello exchange");

    memset(&tg, 0, sizeof tg);
    tg.lfd = npf_socket(AF_INET, SOCK_STREAM, 0, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(tg.lfd, (struct sockaddr *)&a, sizeof a);
    listen(tg.lfd, 4);
    getsockname(tg.lfd, (struct sockaddr *)&a, &al);
    npf_loop_add(loop, tg.lfd, NPF_EV_READ, target_accept, &tg);

    /* port mapping style sublink: the tunnel speaks SOCKS5 for the application */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    sid = npf_tunnel_open(A.t, sp[0], 0, "127.0.0.1", ntohs(a.sin_port));
    CHECK(sid > 0, "open sublink (id %d)", sid);
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
    until = npf_mono_ms() + 10000;
    while (!eof && npf_mono_ms() < until) {
        npf_loop_once(loop, 5);
        if (app_read(sp[1], &ok, &got, &eof) < 0)
            break;
    }
    CHECK(got == TOTAL && ok, "3 MB through the tunnel (got %zu, pattern %d)", got, ok);
    CHECK(eof, "FIN from the target reached the application");
    close(sp[1]);
    for (i = 0; i < 40; i++)
        npf_loop_once(loop, 5);
    CHECK(npf_tunnel_count(A.t) == 0 && npf_tunnel_count(B.t) == 0, "sublinks released (%d, %d)",
          npf_tunnel_count(A.t), npf_tunnel_count(B.t));
    CHECK(done_n == 1 && done_id == (uint32_t)sid && done_st.out == TOTAL, "sublink_done: %d, id %u, %llu bytes written",
          done_n, done_id, (unsigned long long)done_st.out);
    CHECK(done_st.connect_ms >= 0 && done_st.first_byte_ms >= done_st.connect_ms && strcmp(done_end, "peer_closed") == 0,
          "sublink_done: target reached in %d ms, first byte at %d ms, ended %s", done_st.connect_ms,
          done_st.first_byte_ms, done_end);

    /* -D: the greeting answered here, the request after it or pipelined */
    tg.sent = 0;
    CHECK(socks_app(loop, A.t, ntohs(a.sin_port), 1) == 0, "-D: greeting answered locally, then the request");
    tg.sent = 0;
    CHECK(socks_app(loop, A.t, ntohs(a.sin_port), 0) == 0, "-D: greeting and request in one write");
    for (i = 0; i < 40; i++)
        npf_loop_once(loop, 5);

    /* a name target: resolved off the loop thread, then connected like an address */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    fcntl(sp2[1], F_SETFL, O_NONBLOCK);
    tg.sent = 0;
    CHECK(npf_tunnel_open(A.t, sp2[0], 0, "localhost", ntohs(a.sin_port)) > 0, "open sublink by name");
    eof = 0;
    got = 0;
    ok = 1;
    until = npf_mono_ms() + 10000;
    while (!eof && npf_mono_ms() < until) {
        npf_loop_once(loop, 5);
        if (app_read(sp2[1], &ok, &got, &eof) < 0)
            break;
    }
    CHECK(got == TOTAL && ok && eof, "3 MB through a resolved name (got %zu)", got);
    close(sp2[1]);
    for (i = 0; i < 40; i++)
        npf_loop_once(loop, 5);

    /* "nc -z" through a name: the application connects and closes at once,
     * the FIN comes while the name resolves; both ends release the sublink
     * (the callee freed its own quietly, the caller's waited for good) */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    tg.sent = 0;
    CHECK(npf_tunnel_open(A.t, sp2[0], 0, "localhost", ntohs(a.sin_port)) > 0, "open a sublink by name to close it");
    close(sp2[1]);
    until = npf_mono_ms() + 5000;
    while ((npf_tunnel_count(A.t) || npf_tunnel_count(B.t)) && npf_mono_ms() < until)
        npf_loop_once(loop, 5);
    CHECK(npf_tunnel_count(A.t) == 0 && npf_tunnel_count(B.t) == 0, "closed while resolving: released (%d, %d)",
          npf_tunnel_count(A.t), npf_tunnel_count(B.t));

    /* a public target is refused by the default policy (D22): the application sees a close */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    fcntl(sp2[1], F_SETFL, O_NONBLOCK);
    npf_tunnel_open(A.t, sp2[0], 0, "1.1.1.1", 80);
    eof = 0;
    got = 0;
    until = npf_mono_ms() + 3000;
    while (!eof && npf_mono_ms() < until) {
        npf_loop_once(loop, 5);
        ok = 1;
        app_read(sp2[1], &ok, &got, &eof);
    }
    CHECK(eof && got == 0, "public target refused");
    close(sp2[1]);
    for (i = 0; i < 40; i++)
        npf_loop_once(loop, 5);

    /* a target the callee's target_ok refuses (a hosted grant without it) */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    fcntl(sp2[1], F_SETFL, O_NONBLOCK);
    refused_port = ntohs(a.sin_port);
    tg.sent = 0;
    npf_tunnel_open(A.t, sp2[0], 0, "127.0.0.1", refused_port);
    eof = 0;
    got = 0;
    until = npf_mono_ms() + 3000;
    while (!eof && npf_mono_ms() < until) {
        npf_loop_once(loop, 5);
        ok = 1;
        app_read(sp2[1], &ok, &got, &eof);
    }
    CHECK(eof && got == 0, "a target not in the hosted grant refused");
    refused_port = 0;
    close(sp2[1]);
    for (i = 0; i < 40; i++)
        npf_loop_once(loop, 5);
    CHECK(strcmp(done_end, "target_refused") == 0 && done_st.connect_ms < 0 && done_st.first_byte_ms < 0,
          "sublink_done of the refused target: ended %s (the policy: target_refused) (target reached %d ms)", done_end, done_st.connect_ms);

    /* a rate group: 3 MB at 2 MB/s (1 s of burst) takes about a second */
    {
        int64_t t0 = npf_mono_ms(), el;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
        fcntl(sp2[1], F_SETFL, O_NONBLOCK);
        tg.sent = 0;
        CHECK(npf_tunnel_open_rated(A.t, sp2[0], 0, "127.0.0.1", ntohs(a.sin_port), 7, 2u << 20) > 0, "open rated");
        eof = 0;
        got = 0;
        ok = 1;
        until = npf_mono_ms() + 10000;
        while (!eof && npf_mono_ms() < until) {
            npf_loop_once(loop, 5);
            if (app_read(sp2[1], &ok, &got, &eof) < 0)
                break;
        }
        el = npf_mono_ms() - t0;
        CHECK(got == TOTAL && ok && eof && el >= 400 && el < 3000, "3 MB at 2 MB/s in %lld ms (got %zu)",
              (long long)el, got);
        close(sp2[1]);
        for (i = 0; i < 40; i++)
            npf_loop_once(loop, 5);
    }

    /* a virtual local end: 3 MB written to it in pieces as room comes, its
     * end (FIN), the peer's FIN to it, then closed (not reset) */
    {
        vend v;
        memset(&v, 0, sizeof v);
        v.ok = 1;
        v.room = 1;
        v.said = 1;                     /* the target closes with unread bytes as RST */
        v.t = A.t;
        tg.sent = 0;
        sid = npf_tunnel_open_v(A.t, &k_vend, &v, "127.0.0.1", ntohs(a.sin_port));
        CHECK(sid > 0, "open a virtual sublink (id %d)", sid);
        v.sid = (uint32_t)sid;
        until = npf_mono_ms() + 15000;
        while (!v.closed && npf_mono_ms() < until) {
            npf_timer_add(loop, 0, room_tick, &v);
            npf_loop_once(loop, 1);
        }
        CHECK(v.got == TOTAL && v.ok && v.shut && v.closed == 1 && !v.reset && v.said == 2,
              "virtual end: 3 MB in %d writes (got %zu, pattern %d), its FIN, the peer's, closed once without reset "
              "(%d, %d, %d; ended %s)", v.writes, v.got, v.ok, v.shut, v.closed, v.reset, done_end);
        CHECK(strcmp(done_end, "peer_closed") == 0 || strcmp(done_end, "local_closed") == 0,
              "virtual end: sublink_done says %s", done_end);
        for (i = 0; i < 40; i++)
            npf_loop_once(loop, 5);
        CHECK(npf_tunnel_count(A.t) == 0 && npf_tunnel_count(B.t) == 0, "virtual: sublinks released (%d, %d)",
              npf_tunnel_count(A.t), npf_tunnel_count(B.t));

        /* a refused target: closed with reset */
        memset(&v, 0, sizeof v);
        v.ok = 1;
        v.t = A.t;
        v.said = 2;                     /* nothing to say: no FIN either */
        sid = npf_tunnel_open_v(A.t, &k_vend, &v, "1.1.1.1", 80);
        v.sid = (uint32_t)sid;
        until = npf_mono_ms() + 3000;
        while (!v.closed && npf_mono_ms() < until)
            npf_loop_once(loop, 5);
        CHECK(sid > 0 && v.closed == 1 && v.reset, "virtual end, refused target: closed with reset (%d, %d)", v.closed,
              v.reset);

        /* the local end goes by itself mid-transfer: the peer's side is reset, closed is not called */
        memset(&v, 0, sizeof v);
        v.ok = 1;
        v.t = A.t;
        v.room = 1;
        v.said = 1;
        tg.sent = 0;
        sid = npf_tunnel_open_v(A.t, &k_vend, &v, "127.0.0.1", ntohs(a.sin_port));
        v.sid = (uint32_t)sid;
        until = npf_mono_ms() + 5000;
        while (v.got < 100000 && npf_mono_ms() < until) {
            npf_timer_add(loop, 0, room_tick, &v);
            npf_loop_once(loop, 1);
        }
        npf_tunnel_vclose(A.t, v.sid, 1);
        for (i = 0; i < 60; i++)
            npf_loop_once(loop, 5);
        CHECK(v.got >= 100000 && v.closed == 0 && npf_tunnel_count(A.t) == 0 && npf_tunnel_count(B.t) == 0,
              "virtual end gone by itself: both sides released, closed not called (%d; %d, %d)", v.closed,
              npf_tunnel_count(A.t), npf_tunnel_count(B.t));
    }

    /* a virtual end closed by its owner right after its last bytes went to
     * the transport: they arrive, then the close (a RESET on the control
     * lane overtook them) */
    {
        sink k;
        vsend vs;
        uint16_t kp;
        memset(&k, 0, sizeof k);
        memset(&vs, 0, sizeof vs);
        k.ok = 1;
        k.fd = -1;
        k.lfd = listen_lo(4, &kp);
        npf_loop_add(loop, k.lfd, NPF_EV_READ, sink_accept, &k);
        sid = npf_tunnel_open_v(A.t, &k_vsend, &vs, "127.0.0.1", kp);
        CHECK(sid > 0, "a sending virtual end");
        until = npf_mono_ms() + 5000;
        while (vs.sent < SEND_TOTAL && npf_mono_ms() < until)
            npf_loop_once(loop, 1);
        npf_tunnel_vclose(A.t, (uint32_t)sid, 0);
        until = npf_mono_ms() + 5000;
        while ((k.got < SEND_TOTAL || k.fd >= 0 || npf_tunnel_count(A.t) || npf_tunnel_count(B.t))
               && npf_mono_ms() < until)
            npf_loop_once(loop, 5);
        CHECK(k.got == SEND_TOTAL && k.ok && k.fd < 0 && vs.closed == 0 && npf_tunnel_count(A.t) == 0
                  && npf_tunnel_count(B.t) == 0,
              "closed after its last bytes: all of them, then the target's EOF (%zu of %d; %d, %d)", k.got,
              SEND_TOTAL, npf_tunnel_count(A.t), npf_tunnel_count(B.t));
        npf_loop_del(loop, k.lfd);
        close(k.lfd);
    }

    /* the order of a name's addresses: the families in turns */
    {
        struct sockaddr_storage a[5];
        socklen_t l[5] = {0};
        v6(&a[0], 1), v6(&a[1], 2), v4(&a[2], 3), v4(&a[3], 4), v6(&a[4], 5);
        npf_he_order(a, l, 5);
        CHECK(tag_of(&a[0]) == 1 && tag_of(&a[1]) == 3 && tag_of(&a[2]) == 2 && tag_of(&a[3]) == 4
                  && tag_of(&a[4]) == 5, "v6 v6 v4 v4 v6 tried as v6 v4 v6 v4 v6");
        v4(&a[0], 1), v6(&a[1], 2), v6(&a[2], 3);
        npf_he_order(a, l, 3);
        CHECK(tag_of(&a[0]) == 1 && tag_of(&a[1]) == 2 && tag_of(&a[2]) == 3, "v4 v6 v6 kept");
    }

#ifdef __linux__
    /* Happy Eyeballs: the name's first address never answers (a listener
     * whose queue is full drops the SYN), the second is the target: reached
     * after the delay, not after the 10 s deadline */
    {
        int dead, filler, el;
        int64_t t0;
        dead = listen_lo(0, &he_dead);
        filler = npf_socket(AF_INET, SOCK_STREAM, 0, 0);
        {
            struct sockaddr_in d;
            memset(&d, 0, sizeof d);
            d.sin_family = AF_INET;
            d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            d.sin_port = htons(he_dead);
            connect(filler, (struct sockaddr *)&d, sizeof d);   /* fills the queue (backlog 0) */
        }
        {
            fd_set w;                   /* its handshake done: it is in the queue */
            struct timeval tv = {2, 0};
            FD_ZERO(&w);
            FD_SET(filler, &w);
            select(filler + 1, NULL, &w, NULL, &tv);
        }

        he_live = ntohs(a.sin_port);
        npf_tunnel_test_resolve = he_resolve;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
        fcntl(sp2[1], F_SETFL, O_NONBLOCK);
        tg.sent = 0;
        t0 = npf_mono_ms();
        CHECK(npf_tunnel_open(A.t, sp2[0], 0, "he.test", 1) > 0, "open a sublink to he.test");
        eof = 0;
        got = 0;
        ok = 1;
        until = npf_mono_ms() + 9000;
        while (!got && npf_mono_ms() < until) {
            npf_loop_once(loop, 5);
            if (app_read(sp2[1], &ok, &got, &eof) < 0)
                break;
        }
        el = (int)(npf_mono_ms() - t0);
        CHECK(got > 0 && el >= 200 && el < 3000, "Happy Eyeballs: the second address after %d ms (got %zu)", el, got);
        close(sp2[1]);
        npf_tunnel_test_resolve = NULL;
        for (i = 0; i < 40; i++)
            npf_loop_once(loop, 5);
        close(filler);
        close(dead);
    }
#endif

    /* frames put straight into the callee from here on (ids above the
     * caller's: the caller's later sublinks would look late to it) */
    /* a request with data pipelined after it in one frame, together over the
     * 600-byte parse buffer: the data waits for the connection, then goes */
    {
        sink k;
        uint16_t kp;
        uint8_t msg[4 + 13 + 2000];
        int before = npf_tunnel_count(B.t);
        memset(&k, 0, sizeof k);
        k.ok = 1;
        k.fd = -1;
        k.lfd = listen_lo(4, &kp);
        npf_loop_add(loop, k.lfd, NPF_EV_READ, sink_accept, &k);
        npf_le32(msg, 2001);
        memcpy(msg + 4, (const uint8_t[]){5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1}, 11);
        msg[15] = (uint8_t)(kp >> 8);
        msg[16] = (uint8_t)kp;
        for (i = 0; i < 2000; i++)
            msg[17 + i] = (uint8_t)(i * 7);
        CHECK(npf_tunnel_input_data(B.t, msg, sizeof msg) == 0, "request and 2000 bytes in one frame: taken");
        until = npf_mono_ms() + 3000;
        while (k.got < 2000 && npf_mono_ms() < until)
            npf_loop_once(loop, 5);
        CHECK(k.got == 2000 && k.ok && npf_tunnel_count(B.t) == before + 1,
              "the data after the request reached the target (%zu bytes, pattern %d)", k.got, k.ok);
        npf_le32(msg, 2001);
        npf_tunnel_input_data(B.t, msg, 4);     /* its FIN */
        for (i = 0; i < 20; i++)
            npf_loop_once(loop, 5);
        npf_loop_del(loop, k.lfd);
        close(k.lfd);
        if (k.fd >= 0) {
            npf_loop_del(loop, k.fd);
            close(k.fd);
        }
    }

    /* a greeting that never completes: the sublink goes after the deadline */
    {
        uint8_t msg[4 + 2];
        int before = npf_tunnel_count(B.t);
        int64_t t0;
        npf_tunnel_greet_ms = 150;
        npf_le32(msg, 2003);
        msg[4] = 5;
        msg[5] = 2;                         /* two methods announced, none sent */
        CHECK(npf_tunnel_input_data(B.t, msg, sizeof msg) == 0 && npf_tunnel_count(B.t) == before + 1,
              "a half greeting opens a sublink");
        t0 = npf_mono_ms();
        while (npf_tunnel_count(B.t) > before && npf_mono_ms() - t0 < 2000)
            npf_loop_once(loop, 5);
        CHECK(npf_tunnel_count(B.t) == before && npf_mono_ms() - t0 >= 100,
              "released after the greeting deadline (%lld ms)", (long long)(npf_mono_ms() - t0));
        npf_tunnel_greet_ms = 10000;
    }

    /* first data out of id order (-D takes the id at accept, sends after the
     * greeting): the smaller id still opens; a RESET that overtakes the data
     * of an id below the largest keeps it closed too */
    {
        uint8_t msg[4 + 3] = {0, 0, 0, 0, 5, 1, 0}, rst[3 + 5] = {NPF_CU_RESET, 5, 0};
        uint32_t ids[] = {3003, 3001}, k;
        int before = npf_tunnel_count(B.t);
        for (k = 0; k < 2; k++) {
            npf_le32(msg, ids[k]);
            npf_tunnel_input_data(B.t, msg, sizeof msg);
        }
        CHECK(npf_tunnel_count(B.t) == before + 2, "a smaller id's first data after a larger one's opens it (%d)",
              npf_tunnel_count(B.t) - before);
        npf_le32(rst + 3, 3007);
        rst[7] = NPF_RST_LOCAL;
        npf_tunnel_input_data(B.t, (npf_le32(msg, 3009), msg), sizeof msg);
        npf_tunnel_input_ctrl(B.t, rst, sizeof rst);
        npf_tunnel_input_data(B.t, (npf_le32(msg, 3007), msg), sizeof msg);
        npf_tunnel_input_data(B.t, (npf_le32(msg, 3001), msg), sizeof msg);   /* seen: no second sublink */
        CHECK(npf_tunnel_count(B.t) == before + 3, "reset below the largest, then its data: closed (%d)",
              npf_tunnel_count(B.t) - before);
        for (k = 3001; k <= 3009; k += 2) {               /* the ones opened here go */
            npf_le32(rst + 3, k);
            npf_tunnel_input_ctrl(B.t, rst, sizeof rst);
        }
        CHECK(npf_tunnel_count(B.t) == before, "released by their resets (%d)", npf_tunnel_count(B.t) - before);
    }

    /* as many sublinks as the limit from the peer, the largest id first (all
     * below it within the ids remembered): all open; one more is refused */
    {
        uint8_t msg[4 + 2] = {0, 0, 0, 0, 5, 1}, rst[3 + 5] = {NPF_CU_RESET, 5, 0};  /* half a greeting */
        int before = npf_tunnel_count(B.t), k, room = NPF_MAX_SUBLINKS - before;
        const uint32_t base = 5001;
        for (k = room - 1; k >= 0; k--) {
            npf_le32(msg, base + 2 * (uint32_t)k);
            npf_tunnel_input_data(B.t, msg, sizeof msg);
        }
        CHECK(npf_tunnel_count(B.t) == NPF_MAX_SUBLINKS, "%d sublinks open in any order (%d)", NPF_MAX_SUBLINKS,
              npf_tunnel_count(B.t));
        npf_le32(msg, base + 2 * (uint32_t)room);
        npf_tunnel_input_data(B.t, msg, sizeof msg);
        CHECK(npf_tunnel_count(B.t) == NPF_MAX_SUBLINKS, "one more refused (%d)", npf_tunnel_count(B.t));
        rst[7] = NPF_RST_LOCAL;
        for (k = 0; k < room; k++) {
            npf_le32(rst + 3, base + 2 * (uint32_t)k);
            npf_tunnel_input_ctrl(B.t, rst, sizeof rst);
        }
        CHECK(npf_tunnel_count(B.t) == before, "all released (%d)", npf_tunnel_count(B.t) - before);
    }

    /* a RESET on the control lane can overtake the sublink's first data: the
     * late data must not open it (ids are never reused) */
    {
        uint8_t rst[3 + 5] = {NPF_CU_RESET, 5, 0}, msg[4 + 3] = {0, 0, 0, 0, 5, 1, 0};
        int before = npf_tunnel_count(B.t);
        npf_le32(rst + 3, 1001);
        rst[7] = NPF_RST_LOCAL;
        npf_le32(msg, 1001);
        CHECK(npf_tunnel_input_ctrl(B.t, rst, sizeof rst) == 0 && npf_tunnel_input_data(B.t, msg, sizeof msg) == 0
              && npf_tunnel_count(B.t) == before, "RESET before the first data: the sublink stays closed");
        /* a malformed data message breaks the tunnel */
        fails_expected = 1;
        CHECK(npf_tunnel_input_data(B.t, msg, 3) < 0, "a data message shorter than its header");
        fails_expected = 0;
    }

    /* a control unit cut by the stream's reads: byte by byte, then one
     * whole and the next one's head in one read; each still acts once */
    {
        uint8_t rst[3 + 5] = {NPF_CU_RESET, 5, 0}, two[2 * (3 + 5)];
        int sp3[2], sp4[2], id1, id2, before = npf_tunnel_count(A.t);
        size_t k;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp3);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp4);
        id1 = npf_tunnel_open(A.t, sp3[0], 0, "127.0.0.1", 9);
        id2 = npf_tunnel_open(A.t, sp4[0], 0, "127.0.0.1", 9);
        CHECK(id1 > 0 && id2 > 0 && npf_tunnel_count(A.t) == before + 2, "two sublinks to reset");
        npf_le32(rst + 3, (uint32_t)id1);
        rst[7] = NPF_RST_LOCAL;
        for (k = 0; k < sizeof rst; k++)
            CHECK(npf_tunnel_input_ctrl(A.t, rst + k, 1) == 0, "a byte of a unit");
        CHECK(npf_tunnel_count(A.t) == before + 1, "a RESET fed byte by byte reset its sublink (%d)",
              npf_tunnel_count(A.t) - before);
        memcpy(two, rst, sizeof rst);           /* the same id again: nothing to do */
        memcpy(two + sizeof rst, rst, sizeof rst);
        npf_le32(two + sizeof rst + 3, (uint32_t)id2);
        CHECK(npf_tunnel_input_ctrl(A.t, two, sizeof rst + 2) == 0 && npf_tunnel_count(A.t) == before + 1,
              "a whole unit and the next one's head: the head waits");
        CHECK(npf_tunnel_input_ctrl(A.t, two + sizeof rst + 2, sizeof rst - 2) == 0
              && npf_tunnel_count(A.t) == before, "its rest: the second sublink reset (%d)", npf_tunnel_count(A.t) - before);
        close(sp3[1]);
        close(sp4[1]);
    }

    /* a callback that frees the tunnel (sublink_done, inside the peer's
     * RESET): the tunnel goes at the end of that input, nothing in it used
     * after (ASan) */
    {
        uint8_t rst[3 + 5] = {NPF_CU_RESET, 5, 0};
        int sp3[2], id;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp3);
        id = npf_tunnel_open(A.t, sp3[0], 0, "127.0.0.1", 9);
        CHECK(id > 0, "a sublink to reset");
        npf_le32(rst + 3, (uint32_t)id);
        rst[7] = NPF_RST_LOCAL;
        free_in_done = &A.t;
        CHECK(npf_tunnel_input_ctrl(A.t, rst, sizeof rst) < 0 && A.t == NULL,
              "freed from its own callback: gone once the input returns");
        free_in_done = NULL;
        close(sp3[1]);
    }

    /* the same from a timer (review 2026-10-24): a local SOCKS greeting
     * that never comes; at its deadline sublink_done frees the tunnel, which
     * goes when the timer is done with it (ASan: no use after free) */
    {
        end C, D;
        int sp4[2], k;
        int64_t t0;
        memset(&C, 0, sizeof C);
        memset(&D, 0, sizeof D);
        C.peer = &D;                        /* not pumped: the hellos are passed here */
        D.peer = &C;
        C.t = npf_tunnel_new(loop, 1, &io, &C, NULL);
        D.t = npf_tunnel_new(loop, 0, &io_b, &D, &pol);
        npf_tunnel_start(D.t);
        for (k = 0; k < 4; k++) {
            if (D.len) {
                npf_tunnel_input_ctrl(C.t, D.q, D.len);
                D.len = 0;
            }
            if (C.len) {
                npf_tunnel_input_ctrl(D.t, C.q, C.len);
                C.len = 0;
            }
        }
        /* the caller key's share (review 2026-10-24): one peer sublink
         * allowed there, the second refused though the node has room */
        {
            npf_tunnel_shared node_sh = {0, 1000, 0, (int64_t)1 << 40}, key_sh = {0, 1, 0, (int64_t)1 << 40};
            int sa[2], sb[2], before = npf_tunnel_count(D.t);
            size_t off;
            npf_tunnel_set_shared(D.t, &node_sh, &key_sh);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sa);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sb);
            CHECK(npf_tunnel_open(C.t, sa[0], 0, "127.0.0.1", 9) > 0 && npf_tunnel_open(C.t, sb[0], 0, "127.0.0.1", 9) > 0,
                  "two sublinks opened toward the callee");
            for (off = 0; off + 4 <= C.dlen;) {
                size_t m = npf_rd32(C.dq + off);
                npf_tunnel_input_data(D.t, C.dq + off + 4, m);
                off += 4 + m;
            }
            C.dlen = 0;
            CHECK(npf_tunnel_count(D.t) == before + 1 && key_sh.subs == 1 && node_sh.subs == 1,
                  "the key's share takes one, refuses the other (%d open, key %d, node %d)",
                  npf_tunnel_count(D.t) - before, key_sh.subs, node_sh.subs);
            npf_tunnel_free(D.t);                       /* its sublinks go: the shares count down */
            D.t = NULL;
            CHECK(key_sh.subs == 0 && key_sh.rx == 0 && node_sh.subs == 0 && node_sh.rx == 0,
                  "the shares back to zero when the tunnel goes");
            close(sa[1]);
            close(sb[1]);
        }
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp4);
        npf_tunnel_greet_ms = 0;
        CHECK(C.t && npf_tunnel_open(C.t, sp4[0], 1, NULL, 0) >= 0, "a local SOCKS sublink waiting for its greeting");
        free_in_done = &C.t;
        t0 = npf_mono_ms();
        while (C.t && npf_mono_ms() - t0 < 2000)
            npf_loop_once(loop, 5);
        CHECK(C.t == NULL, "freed from its own callback at the greeting deadline");
        free_in_done = NULL;
        npf_tunnel_greet_ms = 10000;
        npf_tunnel_free(C.t);
        npf_tunnel_free(D.t);
        free(C.q);
        free(C.dq);
        free(D.q);
        free(D.dq);
        close(sp4[1]);
    }

    npf_tunnel_free(A.t);
    npf_tunnel_free(B.t);
    npf_loop_del(loop, tg.lfd);
    close(tg.lfd);
    npf_loop_free(loop);
    free(A.q);
    free(B.q);
    free(A.dq);
    free(B.dq);
    return fails;
}

/* Two tunnels joined in memory: hello, SOCKS5 CONNECT through the callee to a
 * local TCP server, 3 MB with flow control, FIN, and a policy denial. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
static void io_sublink_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    (void)arg;
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

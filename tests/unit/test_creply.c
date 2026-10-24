/* The caller side's reading of the server's SOCKS5 replies (the method
 * reply, then the CONNECT reply), fed here frame by frame as the peer would
 * send them: whole, or a byte a frame, with the application's data in the
 * same frame. A port mapping keeps them from the application; -D gives it
 * the CONNECT reply as it is, a failure too. Each byte is credited back
 * once. A refusal, a bad reply and a reply cut short end the sublink with
 * the right reason; a failure reply the application cannot take yet waits
 * in the queue across the FIN. */
#define _GNU_SOURCE
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
#include "../../src/tunnel/tunnel_internal.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

typedef struct pipe_ {
    uint8_t q[8192];            /* control bytes for the other tunnel (the hellos) */
    size_t  len;
} pipe_;

static pipe_ PC, PD;
static int ndone;
static char done_end[32];

static int w_ctrl(void *arg, const uint8_t *buf, size_t len)
{
    pipe_ *p = arg;
    if (p->len + len <= sizeof p->q) {
        memcpy(p->q + p->len, buf, len);
        p->len += len;
    }
    return 0;
}
static int w_data(void *arg, const uint8_t *m, size_t len) { (void)arg; (void)m; (void)len; return 0; }
static size_t backlog(void *arg) { (void)arg; return 0; }
static void ready(void *arg) { (void)arg; }
static void broken(void *arg, const char *why) { (void)arg; (void)why; }
static void sub_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    (void)arg;
    (void)id;
    ndone++;
    snprintf(done_end, sizeof done_end, "%s", st->end ? st->end : "");
}

static const npf_tunnel_io io_c = {w_ctrl, w_data, backlog, ready, NULL, broken, NULL, NULL, sub_done};
static const npf_tunnel_io io_d = {w_ctrl, w_data, backlog, ready, NULL, broken, NULL, NULL, NULL};

static npf_loop *loop;
static npf_tunnel *C;           /* the caller's tunnel, its peer played here */

static sublink *sub_of(uint32_t id)
{
    int i;
    for (i = 0; C && i < C->nsubs; i++)
        if (C->ids[i] == id)
            return C->subs[i];
    return NULL;
}

/* one DATA frame of sublink id; len 0: its FIN */
static void frame(uint32_t id, const uint8_t *p, size_t len)
{
    uint8_t m[NPF_DATA_HDR + 512];
    npf_le32(m, id);
    memcpy(m + NPF_DATA_HDR, p, len);
    npf_tunnel_input_data(C, m, NPF_DATA_HDR + len);
}

static void spin(int n)
{
    while (n-- > 0)
        npf_loop_once(loop, 2);
}

/* what the application reads by now */
static size_t app_read(int fd, uint8_t *out, size_t cap)
{
    size_t got = 0;
    int k;
    for (k = 0; k < 20 && got < cap; k++) {
        ssize_t r = recv(fd, out + got, cap - got, MSG_DONTWAIT);
        if (r > 0)
            got += (size_t)r;
        else
            spin(1);
    }
    return got;
}

/* a sublink on C with its application end: a port mapping (dyn 0), or
 * -D (dyn 1: the application's greeting and request answered locally) */
static uint32_t open_sub(int dyn, int *app)
{
    int sp[2], id;
    uint8_t mr[2];
    static const uint8_t req[] = {5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80};
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
    id = dyn ? npf_tunnel_open(C, sp[0], 1, NULL, 0) : npf_tunnel_open(C, sp[0], 0, "127.0.0.1", 80);
    *app = sp[1];
    if (id <= 0)
        return 0;
    if (dyn) {
        if (send(sp[1], req, sizeof req, 0) != (ssize_t)sizeof req || app_read(sp[1], mr, 2) != 2 || mr[1] != 0)
            return 0;
    }
    return (uint32_t)id;
}

/* the replies of an address type (1, 3 "host", 4) and REP; returns their length */
static size_t replies(uint8_t *b, int atyp, uint8_t rep)
{
    size_t n = 0, i;
    b[n++] = 5;
    b[n++] = 0;
    b[n++] = 5;
    b[n++] = rep;
    b[n++] = 0;
    b[n++] = (uint8_t)atyp;
    if (atyp == 3) {
        b[n++] = 4;
        memcpy(b + n, "host", 4);
        n += 4;
    } else {
        for (i = 0; i < (atyp == 1 ? 4u : 16u); i++)
            b[n++] = (uint8_t)(i + 1);
    }
    b[n++] = 0x1f;
    b[n++] = 0x90;
    return n;
}

/* a success, whole or a byte a frame, application data after it (in the
 * last frame of the reply): the application gets the data (and -D the
 * CONNECT reply before it); every byte credited once */
static void ok_case(int dyn, int atyp, int bytewise)
{
    uint8_t in[64], got[64];
    size_t rl = replies(in, atyp, 0), total, k, n;
    int app;
    uint32_t id = open_sub(dyn, &app);
    sublink *s = sub_of(id);
    memcpy(in + rl, "DATA", 4);
    total = rl + 4;
    CHECK(id && s && s->state == SL_CLIENT_WAIT, "dyn %d atyp %d: waiting for the replies", dyn, atyp);
    if (!s)
        return;
    if (bytewise) {
        for (k = 0; k + 1 < rl; k++)
            frame(id, in + k, 1);
        frame(id, in + rl - 1, 5);      /* the reply's last byte with the data */
    } else {
        frame(id, in, total);
    }
    n = app_read(app, got, sizeof got);
    s = sub_of(id);
    if (dyn)
        CHECK(n == total - 2 && memcmp(got, in + 2, n) == 0, "dyn atyp %d bytewise %d: reply and data (%zu)", atyp,
              bytewise, n);
    else
        CHECK(n == 4 && memcmp(got, "DATA", 4) == 0, "map atyp %d bytewise %d: data only (%zu)", atyp, bytewise, n);
    CHECK(s && s->state == SL_OPEN && s->wq.len == 0 && s->rx_freed == total && s->t_ok,
          "dyn %d atyp %d bytewise %d: open, %u of %zu credited", dyn, atyp, bytewise, s ? s->rx_freed : 0, total);
    if (s)
        tunnel_sub_reset(s, NPF_RST_LOCAL);
    close(app);
}

/* a failure or a bad reply a byte a frame: a mapping resets at once; -D
 * hands a failure on and waits for the peer's end */
static void fail_case(int dyn, const uint8_t *in, size_t len, const char *want, int gone)
{
    uint8_t got[64];
    size_t k, n;
    int app, before = ndone;
    uint32_t id = open_sub(dyn, &app);
    done_end[0] = 0;
    for (k = 0; k < len && sub_of(id); k++)
        frame(id, in + k, 1);
    CHECK((sub_of(id) == NULL) == gone, "dyn %d %s: %s", dyn, want, gone ? "reset" : "kept for the peer's end");
    if (!gone) {
        n = app_read(app, got, sizeof got);
        CHECK(n == len - 2 && memcmp(got, in + 2, n) == 0, "dyn %s: the failure reply handed on (%zu)", want, n);
        frame(id, NULL, 0);             /* the peer's FIN */
        close(app);
        spin(5);
    }
    CHECK(ndone == before + 1 && strcmp(done_end, want) == 0, "dyn %d: ended %s (%s)", dyn, want, done_end);
    if (sub_of(id))
        tunnel_sub_reset(sub_of(id), NPF_RST_LOCAL);
    if (gone)
        close(app);
}

int test_creply(void)
{
    npf_tunnel *D;
    uint8_t r[64];
    size_t rl;
    int k, a;

    loop = npf_loop_new();
    C = npf_tunnel_new(loop, 1, &io_c, &PC, NULL);
    D = npf_tunnel_new(loop, 0, &io_d, &PD, NULL);
    npf_tunnel_start(D);
    for (k = 0; k < 4; k++) {           /* the hellos */
        if (PD.len) {
            npf_tunnel_input_ctrl(C, PD.q, PD.len);
            PD.len = 0;
        }
        if (PC.len) {
            npf_tunnel_input_ctrl(D, PC.q, PC.len);
            PC.len = 0;
        }
    }
    npf_tunnel_free(D);                 /* its part is played here from now on */
    CHECK(npf_tunnel_is_ready(C), "caller tunnel ready");

    for (a = 1; a <= 4; a++) {
        if (a == 2)
            continue;
        ok_case(0, a, 0);
        ok_case(0, a, 1);
        ok_case(1, a, 0);
        ok_case(1, a, 1);
    }

    rl = replies(r, 1, 2);              /* REP 2: the other side's policy */
    fail_case(0, r, rl, "target_refused", 1);
    fail_case(1, r, rl, "target_refused", 0);
    rl = replies(r, 1, 5);              /* REP 5: refused by the target */
    fail_case(0, r, rl, "target_failed", 1);
    fail_case(1, r, rl, "target_failed", 0);
    rl = replies(r, 1, 0);
    r[4] = 1;                           /* RSV not 0 */
    fail_case(0, r, rl, "target_failed", 1);
    fail_case(1, r, rl, "target_failed", 1);
    r[4] = 0;
    r[5] = 2;                           /* no such ATYP */
    fail_case(1, r, rl, "target_failed", 1);
    r[5] = 1;
    r[2] = 4;                           /* not SOCKS5 */
    fail_case(0, r, rl, "target_failed", 1);
    r[2] = 5;
    r[1] = 0xff;                        /* no acceptable method */
    fail_case(1, r, rl, "target_failed", 1);
    r[1] = 0;

    /* a reply cut short by the peer's FIN: the target was not reached */
    {
        int app, before = ndone;
        uint32_t id = open_sub(0, &app);
        frame(id, r, 5);
        frame(id, NULL, 0);
        close(app);
        spin(5);
        CHECK(ndone == before + 1 && strcmp(done_end, "target_failed") == 0, "cut short: %s", done_end);
    }

    /* -D: a failure reply the application cannot take yet is queued, the
     * FIN comes after it; the reply goes out whole once there is room,
     * credited once, then the end */
    {
        int app, before = ndone, sndbuf = 4096;
        uint8_t junk[1024], got[64];
        size_t filled = 0, drained = 0, n;
        uint32_t id = open_sub(1, &app);
        sublink *s = sub_of(id);
        if (s) {
            setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
            memset(junk, 'j', sizeof junk);
            for (;;) {                  /* the application's socket full */
                ssize_t w = send(s->fd, junk, sizeof junk, MSG_DONTWAIT);
                if (w <= 0)
                    break;
                filled += (size_t)w;
            }
            rl = replies(r, 1, 5);
            frame(id, r, rl);
            frame(id, NULL, 0);
            s = sub_of(id);
            CHECK(s && s->wq.len == rl - 2 && s->peer_fin && !s->shut_wr, "queued before the FIN (%zu)",
                  s ? s->wq.len : 0);
            while (drained < filled) {
                ssize_t g = recv(app, junk, sizeof junk < filled - drained ? sizeof junk : filled - drained,
                                 MSG_DONTWAIT);
                if (g > 0)
                    drained += (size_t)g;
                else
                    spin(1);
            }
            n = app_read(app, got, sizeof got);
            CHECK(n == rl - 2 && memcmp(got, r + 2, n) == 0, "the whole failure reply after the queue (%zu)", n);
            s = sub_of(id);
            CHECK(s && s->wq.len == 0 && s->shut_wr && s->rx_freed == rl, "written, shut, %u of %zu credited",
                  s ? s->rx_freed : 0, rl);
            CHECK(recv(app, got, 1, MSG_DONTWAIT) == 0, "then the end");
            close(app);
            spin(5);
            CHECK(ndone == before + 1 && strcmp(done_end, "target_failed") == 0, "ended target_failed (%s)",
                  done_end);
        } else {
            CHECK(0, "-D sublink for the queue case");
        }
    }

    npf_tunnel_free(C);
    npf_loop_free(loop);
    return fails;
}

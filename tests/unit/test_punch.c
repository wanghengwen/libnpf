/* Event-driven punching on one machine: a triggered check lets the caller
 * validate a path it could not probe itself (punch_ev.c). */
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf/loop.h"
#include "npf/platform.h"
#include "npf/punch.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

typedef struct side {
    int        fd;
    npf_punch *p;
    int        done, ok;
} side;

static int last_probes_recv;
static void done_cb(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    side *s = arg;
    (void)p;
    (void)fd;
    s->done = 1;
    s->ok = res->ok;
    last_probes_recv = res->probes_recv;
}

static void rx_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    side *s = arg;
    (void)loop;
    (void)ev;
    for (;;) {
        uint8_t buf[512];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        npf_punch_input(s->p, fd, buf, (size_t)r, &from);
    }
}

static int udp_bound(struct sockaddr_storage *addr)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (struct sockaddr *)&a, sizeof a);
    getsockname(fd, (struct sockaddr *)&a, &al);
    memset(addr, 0, sizeof *addr);
    memcpy(addr, &a, sizeof a);
    return fd;
}

int test_punch(void)
{
    npf_loop *loop = npf_loop_new();
    side a = {0}, b = {0};
    struct sockaddr_storage aa, ba, nowhere;
    npf_punch_cfg ca, cb;
    int64_t until;
    int dead = udp_bound(&nowhere);     /* a port nobody reads: the caller's only candidate */
    a.fd = udp_bound(&aa);
    b.fd = udp_bound(&ba);
    memset(&ca, 0, sizeof ca);
    ca.plan.role = NPF_PUNCH_CONTROLLING;
    ca.plan.strategy = NPF_PUNCH_S1;
    ca.plan.family = AF_INET;
    ca.plan.session_id = 42;
    memset(ca.plan.punch_key, 7, 32);
    memset(ca.plan.nominate_key, 9, 32);
    ca.plan.timeout_ms = 3000;
    ca.fd6 = -1;
    cb = ca;
    cb.plan.role = NPF_PUNCH_CONTROLLED;
    ca.peers[0] = nowhere;              /* the caller cannot reach the callee by itself */
    ca.npeers = 1;
    cb.peers[0] = aa;                   /* the callee reaches the caller */
    cb.npeers = 1;
    npf_loop_add(loop, a.fd, NPF_EV_READ, rx_cb, &a);
    npf_loop_add(loop, b.fd, NPF_EV_READ, rx_cb, &b);
    a.p = npf_punch_new(loop, &ca, a.fd, done_cb, &a);
    b.p = npf_punch_new(loop, &cb, b.fd, done_cb, &b);
    until = npf_mono_ms() + 4000;
    while ((!a.done || !b.done) && npf_mono_ms() < until)
        npf_loop_once(loop, 10);
    CHECK(a.done && a.ok && b.done && b.ok,
          "triggered check: the caller validates the path the callee opened (caller %d/%d, callee %d/%d)", a.done,
          a.ok, b.done, b.ok);
    npf_loop_del(loop, a.fd);
    npf_loop_del(loop, b.fd);
    npf_punch_free(a.p);
    npf_punch_free(b.p);

    /* a PROBE copied by someone on the path and sent again, from an address
     * of their choosing: taken once, the copy gets no answer */
    {
        side c = {0}, d = {0};
        struct sockaddr_storage tapa, spoof;
        int tap = udp_bound(&tapa), sp = udp_bound(&spoof), k;
        uint8_t pkt[512];
        ssize_t n = -1;
        ca.peers[0] = tapa;
        ca.plan.timeout_ms = 600;
        cb.plan.timeout_ms = 600;
        c.p = npf_punch_new(loop, &ca, a.fd, done_cb, &c);
        for (k = 0; k < 50 && n <= 0; k++) {
            npf_loop_once(loop, 10);
            n = recv(tap, pkt, sizeof pkt, MSG_DONTWAIT);
        }
        CHECK(n > 0, "a PROBE captured");
        d.p = npf_punch_new(loop, &cb, b.fd, done_cb, &d);
        if (n > 0) {
            npf_punch_input(d.p, b.fd, pkt, (size_t)n, &spoof);
            npf_punch_input(d.p, b.fd, pkt, (size_t)n, &spoof);
            npf_punch_input(d.p, b.fd, pkt, (size_t)n, &tapa);
        }
        until = npf_mono_ms() + 2000;
        while (!d.done && npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(d.done && last_probes_recv == 1, "the copies dropped (%d PROBEs taken)", last_probes_recv);
        npf_punch_free(c.p);
        npf_punch_free(d.p);
        npf_sock_close(tap);
        npf_sock_close(sp);
    }
    npf_sock_close(a.fd);
    npf_sock_close(b.fd);
    npf_sock_close(dead);
    npf_loop_free(loop);
    return fails;
}

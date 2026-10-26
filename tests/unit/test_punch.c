/* Event-driven punching on one machine: a triggered check lets the caller
 * validate a path it could not probe itself; a candidate trickled into a
 * running round (npf_punch_add_peer) is probed with the others (punch_ev.c). */
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/loop.h"
#include "npf/natprobe.h"
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
    int        done, ok, ms;
} side;

static int last_probes_recv;
static void done_cb(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    side *s = arg;
    (void)p;
    (void)fd;
    s->done = 1;
    s->ok = res->ok;
    s->ms = res->elapsed_ms;
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

/* the call-time mapping check (nat.c node_nat_check): E1 alone, no
 * allocation or filtering test, on the main socket the node reads */
typedef struct check_st {
    npf_natprobe *p;
    int done, ok;
    struct sockaddr_in mapped;
    int64_t at;
} check_st;

static void check_cb(int ok, const npf_natprobe_result *res, void *arg)
{
    check_st *c = arg;
    c->done = 1;
    c->ok = ok;
    c->mapped = res->mapped[0];
    c->at = npf_mono_ms();
}

static void check_rx(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    check_st *c = arg;
    (void)loop;
    (void)ev;
    for (;;) {
        uint8_t buf[NPF_PKT_MAX];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (c->p)
            npf_natprobe_input(c->p, fd, buf, (size_t)r, &from);
    }
}

static int check_mapping(npf_loop *loop, int main_fd, const struct sockaddr_storage *e1a, int e1, int answer,
                         check_st *c)
{
    npf_natprobe_cfg cfg;
    uint8_t key[32];
    npf_siv_keys keys;
    int64_t t0 = npf_mono_ms(), until = t0 + 4000;
    int asked = 0;
    memset(key, 5, sizeof key);
    npf_siv_derive(&keys, key, NPF_SIV_LABEL_PROBE);
    npf_natprobe_cfg_init(&cfg);
    memcpy(&cfg.ep[0], e1a, sizeof cfg.ep[0]);
    cfg.n_ep = 1;
    memcpy(cfg.probe_key, key, 32);
    cfg.alloc_sockets = 0;
    cfg.filter_test = 0;
    cfg.main_fd = main_fd;
    memset(c, 0, sizeof *c);
    npf_loop_add(loop, main_fd, NPF_EV_READ, check_rx, c);
    c->p = npf_natprobe_start(loop, &cfg, check_cb, c);
    while (c->p && !c->done && npf_mono_ms() < until) {
        uint8_t buf[NPF_PKT_MAX], plain[NPF_PKT_MAX], body[15], wire[NPF_PKT_MAX];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        npf_pkt pkt;
        ssize_t r;
        npf_loop_once(loop, 10);
        r = recvfrom(e1, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0 || npf_pkt_open(&keys, NPF_DIR_REQ, buf, (size_t)r, plain, &pkt) < 0)
            continue;
        asked++;
        if (!answer)
            continue;
        body[0] = 4;                    /* the mapping as E1 sees it: 198.51.100.7:40001 */
        body[1] = (uint8_t)(40001 & 255);
        body[2] = (uint8_t)(40001 >> 8);
        body[3] = 198; body[4] = 51; body[5] = 100; body[6] = 7;
        memset(body + 7, 0, 8);
        if (npf_pkt_seal(&keys, NPF_DIR_RESP, NPF_PKT_BIND_RESP, pkt.txid, pkt.ts_ms, body, sizeof body, 80, wire) > 0)
            sendto(e1, wire, 80, 0, (struct sockaddr *)&from, fl);
    }
    npf_loop_del(loop, main_fd);
    if (!c->done)
        npf_natprobe_cancel(c->p);
    c->p = NULL;
    c->at -= t0;
    return asked;
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
    {
        struct sockaddr_storage e1a;
        int e1 = udp_bound(&e1a), asked;
        check_st c;
        asked = check_mapping(loop, a.fd, &e1a, e1, 1, &c);
        CHECK(c.done && c.ok && asked == 1 && ntohs(c.mapped.sin_port) == 40001 && c.at < 1000,
              "mapping check: E1's answer ends it (done %d ok %d, %d requests, port %u, %lld ms)", c.done, c.ok, asked,
              ntohs(c.mapped.sin_port), (long long)c.at);
        asked = check_mapping(loop, a.fd, &e1a, e1, 0, &c);
        CHECK(c.done && !c.ok && asked == 4 && c.at >= 2000 && c.at < 3000,
              "mapping check: no answer, given up (done %d ok %d, %d requests, %lld ms)", c.done, c.ok, asked,
              (long long)c.at);
        npf_sock_close(e1);
    }
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
    /* both sides start with the other's old srflx only (an expired mapping:
     * nobody reads there); the new one comes while the round runs, as the
     * punch_info "cand" brings it, and the round goes direct with it */
    {
        side e = {0}, f = {0};
        ca.peers[0] = nowhere;
        cb.peers[0] = nowhere;
        ca.plan.timeout_ms = cb.plan.timeout_ms = 3000;
        ca.plan.session_id = cb.plan.session_id = 43;  /* not the probes of the rounds above, still queued */
        npf_loop_add(loop, a.fd, NPF_EV_READ, rx_cb, &e);
        npf_loop_add(loop, b.fd, NPF_EV_READ, rx_cb, &f);
        e.p = npf_punch_new(loop, &ca, a.fd, done_cb, &e);
        f.p = npf_punch_new(loop, &cb, b.fd, done_cb, &f);
        until = npf_mono_ms() + 300;
        while (npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(!e.done && !f.done, "nothing direct with the old addresses");
        CHECK(npf_punch_add_peer(e.p, &ba, 1) == 1 && npf_punch_add_peer(f.p, &aa, 1) == 1, "the new srflx added");
        CHECK(npf_punch_add_peer(e.p, &ba, 1) == 0 && npf_punch_add_peer(e.p, &nowhere, 0) == 0, "a candidate there already: no");
        until = npf_mono_ms() + 3000;
        while ((!e.done || !f.done) && npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(e.done && e.ok && f.done && f.ok, "the trickled candidates make the path (caller %d/%d, callee %d/%d)",
              e.done, e.ok, f.done, f.ok);
        CHECK(npf_punch_add_peer(e.p, &nowhere, 1) == 0, "a finished round takes none");
        npf_loop_del(loop, a.fd);
        npf_loop_del(loop, b.fd);
        npf_punch_free(e.p);
        npf_punch_free(f.p);
    }
    /* nominated at once when no pair of a higher priority is still probed
     * (no 200 ms grace), else up to 200 ms for it (nat-traversal.md 10.1) */
    {
        side e = {0}, f = {0};
        ca.peers[0] = ba;
        cb.peers[0] = aa;
        ca.npeers = cb.npeers = 1;
        ca.prio[0] = cb.prio[0] = 1;
        ca.plan.session_id = cb.plan.session_id = 44;
        npf_loop_add(loop, a.fd, NPF_EV_READ, rx_cb, &e);
        npf_loop_add(loop, b.fd, NPF_EV_READ, rx_cb, &f);
        e.p = npf_punch_new(loop, &ca, a.fd, done_cb, &e);
        f.p = npf_punch_new(loop, &cb, b.fd, done_cb, &f);
        until = npf_mono_ms() + 2000;
        while ((!e.done || !f.done) && npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(e.ok && f.ok && e.ms < 150, "no higher pair: nominated at once (%d %d, %d ms)", e.ok, f.ok, e.ms);
        npf_punch_free(e.p);
        npf_punch_free(f.p);
        memset(&e, 0, sizeof e);
        memset(&f, 0, sizeof f);
        ca.peers[1] = nowhere;              /* a LAN candidate (host4) that does not answer */
        ca.prio[1] = 2;
        ca.npeers = 2;
        ca.plan.session_id = cb.plan.session_id = 45;
        e.p = npf_punch_new(loop, &ca, a.fd, done_cb, &e);
        f.p = npf_punch_new(loop, &cb, b.fd, done_cb, &f);
        until = npf_mono_ms() + 2000;
        while ((!e.done || !f.done) && npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(e.ok && f.ok && e.ms >= 200 && e.ms < 400, "a higher pair still probed: waited for it (%d %d, %d ms)", e.ok,
              f.ok, e.ms);
        npf_loop_del(loop, a.fd);
        npf_loop_del(loop, b.fd);
        npf_punch_free(e.p);
        npf_punch_free(f.p);
        ca.npeers = 1;
        ca.prio[0] = ca.prio[1] = cb.prio[0] = 0;
    }
    /* S1: nothing at all from the peer within 3 s: the round ends then, not
     * at its timeout (nat-traversal.md 9) */
    {
        side e = {0};
        ca.peers[0] = nowhere;
        ca.plan.timeout_ms = 8000;
        ca.plan.session_id = 46;
        npf_loop_add(loop, a.fd, NPF_EV_READ, rx_cb, &e);
        e.p = npf_punch_new(loop, &ca, a.fd, done_cb, &e);
        until = npf_mono_ms() + 5000;
        while (!e.done && npf_mono_ms() < until)
            npf_loop_once(loop, 10);
        CHECK(e.done && !e.ok && e.ms >= 2900 && e.ms < 3500, "S1 with nothing from the peer: ended after %d ms (done %d)",
              e.ms, e.done);
        npf_loop_del(loop, a.fd);
        npf_punch_free(e.p);
    }
    /* S2's easy side: told the hard side's measured port q0, it sprays q0 + 1,
     * q0 + 2, ... first (the ports its new sockets take), not at random */
    {
        side e = {0};
        struct sockaddr_storage ta;
        int t = udp_bound(&ta), got = 0, k;
        uint8_t buf[512];
        npf_punch_cfg cs = ca;
        cs.plan.strategy = NPF_PUNCH_S3;
        cs.plan.side = NPF_PUNCH_EASY;
        cs.plan.m_total = 2000;
        cs.plan.pps = 200;
        cs.plan.peer_n = 8;
        cs.plan.peer_delta = 1;
        cs.plan.timeout_ms = 3000;
        cs.plan.peer_ip4.s_addr = htonl(INADDR_LOOPBACK);
        cs.plan.session_id = 47;
        e.p = npf_punch_new(loop, &cs, a.fd, done_cb, &e);
        npf_punch_peer_port(e.p, (uint16_t)(ntohs(((struct sockaddr_in *)&ta)->sin_port) - 1));
        for (k = 0; k < 30 && !got; k++) {
            npf_loop_once(loop, 10);
            got = recv(t, buf, sizeof buf, MSG_DONTWAIT) > 0;
        }
        CHECK(got, "S2: the port after the measured one not sprayed first");
        npf_punch_free(e.p);
        npf_sock_close(t);
    }
    npf_sock_close(a.fd);
    npf_sock_close(b.fd);
    npf_sock_close(dead);
    npf_loop_free(loop);
    return fails;
}

/* Event-driven punching on one machine: a triggered check lets the caller
 * validate a path it could not probe itself; a candidate trickled into a
 * running round (npf_punch_add_peer) is probed with the others (punch_ev.c). */
#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/natprobe.h"
#include "npf/platform.h"
#include "npf/punch.h"
#include "npf/sys.h"
#include "test.h"

typedef struct side {
    int        fd;
    npf_punch *p;
    int        done, ok, ms;
    struct sockaddr_storage peer;
    int        late;                /* the round's callbacks after the owner let it go */
} side;

static int last_probes_recv;
static int quiet_ms = -1;           /* when cfg.quiet was called (the round's ms), -1: not */
static void quiet_cb(npf_punch *p, const npf_punch_result *res, void *arg)
{
    (void)p;
    (void)arg;
    quiet_ms = res->elapsed_ms;
}
static void done_cb(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    side *s = arg;
    (void)p;
    (void)fd;
    s->late += !s->p;
    s->done = 1;
    s->ok = res->ok;
    s->ms = res->elapsed_ms;
    s->peer = res->peer;
    last_probes_recv = res->probes_recv;
}

/* the punch inbound filter of these tests: anything but 127.0.0.3 */
static int from_ok_cb(void *arg, const struct sockaddr_storage *from)
{
    side *s = arg;
    s->late += !s->p;
    return ((const struct sockaddr_in *)from)->sin_addr.s_addr != htonl(0x7f000003);
}

/* a controlling side's packet of type for round sid, sealed with key under
 * label (a fresh txid), in out; its length */
static size_t sealed(const uint8_t key[32], const char *label, int type, uint64_t sid, uint8_t out[128])
{
    npf_siv_keys k;
    uint8_t tx[NPF_TXID_SIZE], body[10] = {0};
    npf_siv_derive(&k, key, label);
    npf_random(tx, sizeof tx);
    npf_le64(body, sid);
    return (size_t)npf_pkt_seal(&k, NPF_PUNCH_CONTROLLING, type, tx, 0, body, type == NPF_PKT_NOMINATE ? 8 : 10,
                                96, out);
}

/* an owner that lets the round go from quiet or info (the free deferred:
 * tick_cb / sock_cb is on the stack); nothing of it is called after that */
static void let_go(npf_punch *p, void *arg)
{
    side *s = arg;
    npf_punch_free(p);
    s->p = NULL;
}
static void quiet_go(npf_punch *p, const npf_punch_result *res, void *arg)
{
    (void)res;
    let_go(p, arg);
}
static void info_go(npf_punch *p, uint16_t port, void *arg)
{
    (void)port;
    let_go(p, arg);
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

/* a round from cfg on s's socket, heard there */
static void start(npf_loop *loop, side *s, int fd, const npf_punch_cfg *cfg)
{
    memset(s, 0, sizeof *s);
    s->fd = fd;
    npf_loop_add(loop, fd, NPF_EV_READ, rx_cb, s);
    s->p = npf_punch_new(loop, cfg, fd, done_cb, s);
}

static void stop(npf_loop *loop, side *s)
{
    npf_loop_del(loop, s->fd);
    npf_punch_free(s->p);
}

int test_punch(void)
{
    npf_loop *loop = npf_loop_new();
    side a, b, e, f, g;
    struct sockaddr_storage aa, ba, ga, nowhere;
    npf_punch_cfg ca, cb;
    int dead = lo_socket(SOCK_DGRAM, 0, &nowhere, sizeof nowhere);  /* nobody reads it: the caller's only candidate */
    int fa = lo_socket(SOCK_DGRAM, 0, &aa, sizeof aa), fb = lo_socket(SOCK_DGRAM, 0, &ba, sizeof ba);
    int fg = lo_socket(SOCK_DGRAM, 0, &ga, sizeof ga);
    memset(&ca, 0, sizeof ca);
    ca.plan.role = NPF_PUNCH_CONTROLLING;
    ca.plan.strategy = NPF_PUNCH_S1;
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
    start(loop, &a, fa, &ca);
    start(loop, &b, fb, &cb);
    LOOP_UNTIL(loop, a.done && b.done, 4000);
    CHECK(a.done && a.ok && b.done && b.ok,
          "triggered check: the caller validates the path the callee opened (caller %d/%d, callee %d/%d)", a.done,
          a.ok, b.done, b.ok);
    stop(loop, &a);
    stop(loop, &b);

    /* a PROBE copied by someone on the path and sent again, from an address
     * of their choosing: taken once, the copy gets no answer */
    {
        struct sockaddr_storage tapa, spoof;
        int tap = lo_socket(SOCK_DGRAM, 0, &tapa, sizeof tapa), sp = lo_socket(SOCK_DGRAM, 0, &spoof, sizeof spoof);
        uint8_t pkt[512];
        ssize_t n = -1;
        ca.peers[0] = tapa;
        ca.plan.timeout_ms = 600;
        cb.plan.timeout_ms = 600;
        memset(&e, 0, sizeof e);
        memset(&f, 0, sizeof f);
        e.p = npf_punch_new(loop, &ca, fa, done_cb, &e);
        LOOP_UNTIL(loop, (n = recv(tap, pkt, sizeof pkt, MSG_DONTWAIT)) > 0, 500);
        CHECK(n > 0, "a PROBE captured");
        f.p = npf_punch_new(loop, &cb, fb, done_cb, &f);
        if (n > 0) {
            npf_punch_input(f.p, fb, pkt, (size_t)n, &spoof);
            npf_punch_input(f.p, fb, pkt, (size_t)n, &spoof);
            npf_punch_input(f.p, fb, pkt, (size_t)n, &tapa);
        }
        LOOP_UNTIL(loop, f.done, 2000);
        CHECK(f.done && last_probes_recv == 1, "the copies dropped (%d PROBEs taken)", last_probes_recv);
        npf_punch_free(e.p);
        npf_punch_free(f.p);
        close(tap);
        close(sp);
    }
    /* both sides start with the other's old srflx only (an expired mapping:
     * nobody reads there); the new one comes while the round runs, as the
     * punch_info "cand" brings it, and the round goes direct with it */
    ca.peers[0] = nowhere;
    cb.peers[0] = nowhere;
    ca.plan.timeout_ms = cb.plan.timeout_ms = 3000;
    ca.plan.session_id = cb.plan.session_id = 43;   /* not the probes of the rounds above, still queued */
    start(loop, &e, fa, &ca);
    start(loop, &f, fb, &cb);
    LOOP_UNTIL(loop, 0, 300);
    CHECK(!e.done && !f.done, "nothing direct with the old addresses");
    CHECK(npf_punch_add_peer(e.p, &ba, 1) == 1 && npf_punch_add_peer(f.p, &aa, 1) == 1, "the new srflx added");
    CHECK(npf_punch_add_peer(e.p, &ba, 1) == 0 && npf_punch_add_peer(e.p, &nowhere, 0) == 0, "a candidate there already: no");
    LOOP_UNTIL(loop, e.done && f.done, 3000);
    CHECK(e.done && e.ok && f.done && f.ok, "the trickled candidates make the path (caller %d/%d, callee %d/%d)",
          e.done, e.ok, f.done, f.ok);
    CHECK(npf_punch_add_peer(e.p, &nowhere, 1) == 0, "a finished round takes none");
    stop(loop, &e);
    stop(loop, &f);
    /* nominated at once when no pair of a higher priority is still probed
     * (no 200 ms grace), else up to 200 ms for it (nat-traversal.md 10.1) */
    ca.peers[0] = ba;
    cb.peers[0] = aa;
    ca.npeers = cb.npeers = 1;
    ca.prio[0] = cb.prio[0] = 1;
    ca.plan.session_id = cb.plan.session_id = 44;
    start(loop, &e, fa, &ca);
    start(loop, &f, fb, &cb);
    LOOP_UNTIL(loop, e.done && f.done, 2000);
    CHECK(e.ok && f.ok && e.ms < 150, "no higher pair: nominated at once (%d %d, %d ms)", e.ok, f.ok, e.ms);
    stop(loop, &e);
    stop(loop, &f);
    ca.peers[1] = nowhere;                  /* a LAN candidate (host4) that does not answer */
    ca.prio[1] = 2;
    ca.npeers = 2;
    ca.plan.session_id = cb.plan.session_id = 45;
    start(loop, &e, fa, &ca);
    start(loop, &f, fb, &cb);
    LOOP_UNTIL(loop, e.done && f.done, 2000);
    CHECK(e.ok && f.ok && e.ms >= 200 && e.ms < 400, "a higher pair still probed: waited for it (%d %d, %d ms)", e.ok,
          f.ok, e.ms);
    stop(loop, &e);
    stop(loop, &f);
    ca.npeers = 1;
    ca.prio[0] = ca.prio[1] = cb.prio[0] = 0;
    /* S1: nothing at all from the peer within 3 s: the owner hears it then
     * (it tells the platform), the round goes on to its timeout; a peer that
     * starts only then (S1 starts on receipt: its plan came late) still gets
     * the path (nat-traversal.md 9) */
    ca.peers[0] = ba;
    cb.peers[0] = aa;
    ca.npeers = cb.npeers = 1;
    ca.plan.timeout_ms = cb.plan.timeout_ms = 8000;
    ca.plan.session_id = cb.plan.session_id = 46;
    ca.quiet = quiet_cb;
    start(loop, &e, fa, &ca);
    {
        npf_punch_cfg cq = ca;          /* alongside: an owner that lets its round go then */
        cq.peers[0] = nowhere;
        cq.plan.session_id = 50;
        cq.quiet = quiet_go;
        start(loop, &g, fg, &cq);
    }
    LOOP_UNTIL(loop, quiet_ms >= 0 && !g.p, 4000);
    CHECK(!e.done && quiet_ms >= 2900 && quiet_ms < 3500, "S1 with nothing from the peer: told after %d ms, done %d",
          quiet_ms, e.done);
    CHECK(!g.p, "the round let go in quiet");
    npf_loop_del(loop, fg);
    start(loop, &f, fb, &cb);               /* the peer, 3 s late */
    LOOP_UNTIL(loop, e.done && f.done, 3000);
    CHECK(e.done && e.ok && f.done && f.ok, "a peer 3 s late: direct all the same (%d %d)", e.ok, f.ok);
    CHECK(!g.done && !g.late, "let go in quiet: nothing of it after that (%d %d)", g.done, g.late);
    stop(loop, &e);
    stop(loop, &f);
    ca.quiet = NULL;
    ca.peers[0] = nowhere;
    /* S2's easy side: told the hard side's measured port q0, it sprays q0 + 1,
     * q0 + 2, ... first (the ports its new sockets take), not at random */
    {
        struct sockaddr_storage ta;
        int t = lo_socket(SOCK_DGRAM, 0, &ta, sizeof ta), got = 0;
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
        memset(&e, 0, sizeof e);
        e.p = npf_punch_new(loop, &cs, fa, done_cb, &e);
        npf_punch_peer_port(e.p, (uint16_t)(ntohs(((struct sockaddr_in *)&ta)->sin_port) - 1));
        LOOP_UNTIL(loop, (got = recv(t, buf, sizeof buf, MSG_DONTWAIT) > 0), 300);
        CHECK(got, "S2: the port after the measured one not sprayed first");
        npf_punch_free(e.p);
        close(t);
    }
    /* NOMINATE (nat-traversal.md 10.1) is the controlling side's pick: the
     * controlled one takes it before a path of its own is validated, and from
     * another IP than the one it validated (another exit, a pooled NAT), not
     * from a source from_ok refuses */
    {
        struct sockaddr_storage other = aa, bad = aa;
        uint8_t pkt[128];
        size_t n;
        npf_punch_cfg cn = cb;
        cn.peers[0] = nowhere;
        cn.npeers = 1;
        cn.from_ok = from_ok_cb;
        cn.plan.session_id = 48;
        ((struct sockaddr_in *)&other)->sin_addr.s_addr = htonl(0x7f000002);
        ((struct sockaddr_in *)&bad)->sin_addr.s_addr = htonl(0x7f000003);
        memset(&f, 0, sizeof f);
        f.p = npf_punch_new(loop, &cn, fb, done_cb, &f);
        n = sealed(cn.plan.nominate_key, NPF_SIV_LABEL_NOMIN, NPF_PKT_NOMINATE, 48, pkt);
        npf_punch_input(f.p, fb, pkt, n, &bad);
        CHECK(!f.done, "a NOMINATE from a source from_ok refuses: dropped");
        n = sealed(cn.plan.nominate_key, NPF_SIV_LABEL_NOMIN, NPF_PKT_NOMINATE, 48, pkt);
        npf_punch_input(f.p, fb, pkt, n, &aa);
        CHECK(f.done && f.ok && npf_addr_eq(&f.peer, &aa), "a NOMINATE before any validated path: taken (%d %d)",
              f.done, f.ok);
        npf_punch_free(f.p);
        cn.plan.session_id = 49;
        memset(&f, 0, sizeof f);
        f.p = npf_punch_new(loop, &cn, fb, done_cb, &f);
        n = sealed(cn.plan.punch_key, NPF_SIV_LABEL_PUNCH, NPF_PKT_PROBE_ACK, 49, pkt);
        npf_punch_input(f.p, fb, pkt, n, &aa);          /* the path via aa validated */
        n = sealed(cn.plan.nominate_key, NPF_SIV_LABEL_NOMIN, NPF_PKT_NOMINATE, 49, pkt);
        npf_punch_input(f.p, fb, pkt, n, &other);
        CHECK(f.done && f.ok && npf_addr_eq(&f.peer, &other), "a NOMINATE from another IP: the path switches there (%d %d)",
              f.done, f.ok);
        npf_punch_free(f.p);
    }
    /* an owner that lets an S2B round go in info (its fresh socket's mapping
     * from E1) while a PROBE waits behind the BIND_RESP: the rest is not read
     * and nothing of the owner's is called again */
    {
        struct sockaddr_storage e1a, ta, fresh;
        socklen_t fl = sizeof fresh;
        int e1 = lo_socket(SOCK_DGRAM, 0, &e1a, sizeof e1a), t = lo_socket(SOCK_DGRAM, 0, &ta, sizeof ta);
        uint8_t pkt[NPF_PKT_MAX], plain[NPF_PKT_MAX], body[15];
        ssize_t n = -1;
        npf_siv_keys kq;
        npf_pkt req;
        npf_punch_cfg cs = cb;
        cs.plan.strategy = NPF_PUNCH_S2B;
        cs.plan.session_id = 51;
        cs.peers[0] = nowhere;
        cs.npeers = 1;
        cs.from_ok = from_ok_cb;
        cs.info = info_go;
        memcpy(&cs.probe_ep[0], &e1a, sizeof cs.probe_ep[0]);
        memset(cs.probe_key, 5, sizeof cs.probe_key);
        npf_siv_derive(&kq, cs.probe_key, NPF_SIV_LABEL_PROBE);
        memset(&g, 0, sizeof g);
        g.p = npf_punch_new(loop, &cs, fg, done_cb, &g);
        LOOP_UNTIL(loop, (n = recvfrom(e1, pkt, sizeof pkt, MSG_DONTWAIT, (struct sockaddr *)&fresh, &fl)) > 0, 500);
        CHECK(n > 0 && npf_pkt_open(&kq, NPF_DIR_REQ, pkt, (size_t)n, plain, &req) == 0, "S2B: a BIND_REQ to E1");
        body[0] = 4;
        npf_le16(body + 1, npf_addr_port(&fresh));
        memcpy(body + 3, &((struct sockaddr_in *)&fresh)->sin_addr, 4);
        npf_le64(body + 7, 0);
        n = npf_pkt_seal(&kq, NPF_DIR_RESP, NPF_PKT_BIND_RESP, req.txid, 0, body, sizeof body, NPF_BIND_RESP_MIN, pkt);
        sendto(e1, pkt, (size_t)n, 0, (struct sockaddr *)&fresh, sizeof(struct sockaddr_in));
        n = (ssize_t)sealed(cs.plan.punch_key, NPF_SIV_LABEL_PUNCH, NPF_PKT_PROBE, 51, pkt);
        sendto(t, pkt, (size_t)n, 0, (struct sockaddr *)&fresh, sizeof(struct sockaddr_in));
        LOOP_UNTIL(loop, !g.p, 500);
        LOOP_UNTIL(loop, 0, 50);
        CHECK(!g.p && !g.done && !g.late, "let go in info: nothing of it after that (%d %d %d)", !g.p, g.done, g.late);
        close(e1);
        close(t);
    }
    close(fa);
    close(fb);
    close(dead);
    close(fg);
    npf_loop_free(loop);
    return fails;
}

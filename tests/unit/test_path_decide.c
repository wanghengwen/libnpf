/* The path manager's decisions (path.h pm_decide, architecture.md 3.6),
 * one row of the table at a time, on a fake clock and paths with no
 * sockets behind them: what the session needs of the platform, what it
 * waits for and when it binds the UDP relay again. Each loss of the UDP
 * relay gets the waits and the retry again (Q7, they were once a call);
 * the wait for the punch is over with the round, and a bind under way is
 * awaited first (D4); a session on the WS relay while UDP works tries the
 * UDP relay after udp_again (Q4), and an allocation from that which does
 * not bind goes straight back. The relay standing by beside the direct
 * path goes after 30 s once a round trip over the direct path is proven,
 * a probe of 10 s first when none was. (The requests' deadlines:
 * test_call.c.) */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "path.h"
#include "test.h"

static npf_path p[PK_N];
static npf_pm m;

#define D (1 << PK_DIRECT)
#define U (1 << PK_UDP_RELAY)
#define W (1 << PK_WS_RELAY)

/* the paths of kinds, each of the health given; the manager as new */
static void start(int kinds, int health)
{
    int k;
    memset(&m, 0, sizeof m);
    memset(p, 0, sizeof p);
    m.udp_again = PM_UDP_AGAIN_MS;
    for (k = 0; k < PK_N; k++) {
        p[k].kind = (uint8_t)k;
        if (kinds & 1 << k) {
            p[k].health = (uint8_t)health;
            pm_add(&m, &p[k]);
        }
    }
}

/* the decision at now, with need the request the call keeps (call_need) */
static int decide(unsigned in, int64_t now)
{
    int r = pm_decide(&m, in, now);
    m.need = r <= PM_NEED_UDP_BACK ? r : PM_NONE;
    return r;
}

static void health(int kind, int h)
{
    pm_health(&m, &p[kind], h);
}

/* the direct path carries the session */
static void direct(void)
{
    /* in doubt, the relay released after the standby: one asked for, and
     * once asked, until it comes (also after the direct path is lost) */
    start(D, PH_UP);
    CHECK(decide(0, 0) == PM_NONE, "the direct path up: a need");
    health(PK_DIRECT, PH_SUSPECT);
    CHECK(decide(0, 1000) == PM_NEED_UDP, "in doubt with no relay: no UDP relay asked for");
    pm_del(&m, &p[PK_DIRECT]);
    CHECK(decide(0, 2000) == PM_NEED_UDP, "lost with no relay: the request dropped");
    start(D, PH_SUSPECT);
    CHECK(decide(0, 0) == PM_NEED_UDP, "in doubt");
    health(PK_DIRECT, PH_UP);
    CHECK(decide(0, 100) == PM_NONE, "back: still asking");
    /* a relay that never bound (DEAD) beside it: bound once more in the
     * doubt, nothing while the direct path is up or the relay binding */
    start(D | U, PH_UP);
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(0, 0) == PM_NONE, "a dead relay standing by: acted on");
    health(PK_DIRECT, PH_SUSPECT);
    CHECK(decide(0, 100) == PM_RETRY, "in doubt, the relay never bound: not bound again");
    health(PK_UDP_RELAY, PH_NEW);
    CHECK(decide(0, 200) == PM_NONE, "binding: acted on");
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(0, 3000) == PM_NONE, "bound again twice in one doubt");
    /* the direct path lost too (dropped): the waits (the punch is over:
     * it made the direct path) and the retry had: the WS relay */
    pm_del(&m, &p[PK_DIRECT]);
    CHECK(decide(PM_IN_CALLER, 10000) == PM_NEED_WS, "no path left: not the WS relay");
}

/* the relay standing by: 30 s, then a probe of the direct path when no
 * round trip proved it yet; its echo lets the relay go at once, none
 * leaves it standing by 30 s more; a doubt ends the standby, a proven one
 * after it needs no probe */
static void standby(void)
{
    start(D | U, PH_UP);
    p[PK_DIRECT].since = 1000;
    CHECK(decide(0, 1000) == PM_NONE && m.wait == PM_W_STANDBY && m.act_at == 1000 + PM_STANDBY_MS, "no standby");
    CHECK(decide(0, 1000 + PM_STANDBY_MS - 1) == PM_NONE, "the standby short");
    CHECK(decide(0, 1000 + PM_STANDBY_MS) == PM_PROBE && p[PK_DIRECT].probe_until == 1000 + PM_STANDBY_MS + PM_PROBE_MS,
          "released with no round trip proven, or no probe");
    CHECK(decide(0, 1000 + PM_STANDBY_MS + PM_PROBE_MS) == PM_STANDBY_ON
          && m.act_at == 1000 + 2 * PM_STANDBY_MS + PM_PROBE_MS, "no echo: released, or not on");
    CHECK(decide(0, 1000 + 2 * PM_STANDBY_MS + PM_PROBE_MS) == PM_PROBE, "the probe not again");
    pm_rt(&m, &p[PK_DIRECT], 80000);
    CHECK(decide(0, 80000) == PM_NEED_RELEASE && !m.wait, "the echo: the relay kept");
    start(D | U, PH_UP);
    p[PK_DIRECT].since = 1000;
    decide(0, 1000);
    health(PK_DIRECT, PH_SUSPECT);
    CHECK(decide(0, 5000) == PM_NONE && !m.wait, "the standby on in a doubt");
    pm_rt(&m, &p[PK_DIRECT], 6000);
    CHECK(decide(0, 6000) == PM_NONE && m.act_at == 6000 + PM_STANDBY_MS, "the standby not again after the doubt");
    CHECK(decide(0, 6000 + PM_STANDBY_MS) == PM_NEED_RELEASE, "a probe after a proven doubt");
    /* the direct path lost: dropped, the platform told (path_lost); not
     * when the UDP relay did not bind either (the WS relay next) */
    start(D | U, PH_UP);
    health(PK_DIRECT, PH_DEAD);
    CHECK(decide(0, 0) == PM_NEED_PATH_LOST, "lost: no path_lost");
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(0, 0) == PM_DROP, "lost beside a dead relay: path_lost");
}

/* the UDP relay unreachable, no direct path: the waits, the retry, the WS
 * relay, in that order */
static void udp_lost(void)
{
    /* the caller before the accept: nothing (the accept binds it again) */
    start(U, PH_DEAD);
    CHECK(decide(PM_IN_CALLER | PM_IN_HOLD | PM_IN_PORTS | PM_IN_PUNCH, 0) == PM_NONE && !m.tried,
          "before the accept: acted on");
    /* a punch holds the NAT's ports: their end awaited, PM_WAIT_MS at most;
     * back: bound again at once */
    CHECK(decide(PM_IN_PORTS | PM_IN_PUNCH, 1000) == PM_WAIT_PORTS && m.act_at == 1000 + PM_WAIT_MS,
          "the ports held: no wait");
    CHECK(decide(PM_IN_PORTS | PM_IN_PUNCH, 2000) == PM_NONE, "waiting for the ports: acted on");
    CHECK(decide(PM_IN_PUNCH, 3000) == PM_REBIND && !m.act_at, "the ports back: not bound again");
    health(PK_UDP_RELAY, PH_NEW);
    CHECK(decide(PM_IN_PUNCH, 4000) == PM_NONE, "binding: acted on");
    /* that bind fails too: a round under way, its result awaited */
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(PM_IN_PUNCH, 6000) == PM_WAIT_PUNCH && m.wait == PM_IN_PUNCH, "the round not awaited");
    CHECK(decide(PM_IN_PUNCH | PM_IN_PORTS, 7000) == PM_NONE, "waiting for the round: acted on");
    /* the round failed: once more, then the WS relay */
    CHECK(decide(0, 8000) == PM_RETRY, "after the round: not bound once more");
    health(PK_UDP_RELAY, PH_NEW);
    CHECK(decide(0, 9000) == PM_NONE, "the retry binding: acted on");
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(0, 12000) == PM_NEED_WS, "everything tried: not the WS relay");
    /* asked: no new wait (ports held by now) */
    CHECK(decide(PM_IN_PORTS | PM_IN_PUNCH, 13000) == PM_NEED_WS, "asked, then a wait");

    /* the waits end at their time: the ports still held after 15 s */
    start(U, PH_DEAD);
    CHECK(decide(PM_IN_PORTS, 0) == PM_WAIT_PORTS, "the ports held");
    CHECK(decide(PM_IN_PORTS, PM_WAIT_MS - 1) == PM_NONE, "waited less");
    CHECK(decide(PM_IN_PORTS, PM_WAIT_MS) == PM_RETRY, "the ports' wait never ends");
    /* no round coming within 15 s */
    start(U, PH_DEAD);
    CHECK(decide(PM_IN_PUNCH, 0) == PM_WAIT_PUNCH, "the round");
    CHECK(decide(PM_IN_PUNCH, PM_WAIT_MS) == PM_RETRY, "the round's wait never ends");
    /* no punching (secure, NPF_NO_P2P, the round over), no ports held: once more, then WS */
    start(U, PH_DEAD);
    CHECK(decide(0, 0) == PM_RETRY, "no once more");
    CHECK(decide(0, 1) == PM_NEED_WS, "not the WS relay after once more");
}

/* Q7: bound again (UP), a later loss has every wait and the retry again
 * (after udp_back, say: it used to go to the WS relay at once) */
static void each_loss(void)
{
    int k;
    start(U, PH_DEAD);
    for (k = 0; k < 2; k++) {
        int64_t t = k * 100000;
        CHECK(decide(PM_IN_PORTS | PM_IN_PUNCH, t) == PM_WAIT_PORTS, "loss %d: no wait for the ports", k + 1);
        CHECK(decide(PM_IN_PUNCH, t + 1000) == PM_REBIND, "loss %d: not bound again with the ports", k + 1);
        health(PK_UDP_RELAY, PH_DEAD);
        CHECK(decide(PM_IN_PUNCH, t + 4000) == PM_WAIT_PUNCH, "loss %d: no wait for the round", k + 1);
        CHECK(decide(0, t + 5000) == PM_RETRY, "loss %d: not bound once more", k + 1);
        health(PK_UDP_RELAY, PH_UP);    /* bound: the session on it again */
        CHECK(decide(0, t + 6000) == PM_NONE && !m.tried, "loss %d: the waits kept after the bind", k + 1);
        health(PK_UDP_RELAY, PH_DEAD);
    }
}

/* the WS relay: given up there, elsewhere (the caller asks, once
 * accepted); UDP again when it came back or after udp_again (Q4) */
static void ws(void)
{
    start(W, PH_NEW);
    CHECK(decide(PM_IN_CALLER | PM_IN_UDP | PM_IN_UP, 0) == PM_NONE, "connecting: a need");
    health(PK_WS_RELAY, PH_DEAD);
    CHECK(decide(PM_IN_CALLER | PM_IN_HOLD, 0) == PM_NONE, "given up before the accept: asked");
    CHECK(decide(PM_IN_CALLER, 0) == PM_NEED_WS_ELSEWHERE, "given up: the caller does not ask elsewhere");
    CHECK(decide(0, 0) == PM_NONE, "given up: the callee asks");
    /* paired at 1 s (its allocation then), UDP works: tried after udp_again */
    start(W, PH_UP);
    p[PK_WS_RELAY].since = 1000;
    CHECK(decide(PM_IN_UDP | PM_IN_UP, 2000) == PM_NONE && m.act_at == 1000 + PM_UDP_AGAIN_MS, "Q4 not due at 5 min");
    CHECK(decide(PM_IN_UDP | PM_IN_UP, 1000 + PM_UDP_AGAIN_MS) == PM_NEED_UDP_BACK, "Q4: UDP not tried after 5 min");
    CHECK(decide(PM_IN_UP, 1000 + PM_UDP_AGAIN_MS) == PM_NONE, "UDP tried with no UDP");
    CHECK(decide(PM_IN_UDP, 1000 + PM_UDP_AGAIN_MS) == PM_NONE, "UDP tried before the session is up");
    /* UDP came back since the WS relay did (udp_back): at once */
    CHECK(decide(PM_IN_UDP | PM_IN_UDP_BACK, 3000) == PM_NEED_UDP_BACK, "udp_back: UDP not asked for");
    /* the UDP allocation (the WS relay gone) does not bind: straight back */
    pm_del(&m, &p[PK_WS_RELAY]);
    p[PK_UDP_RELAY].health = PH_NEW;
    pm_add(&m, &p[PK_UDP_RELAY]);
    CHECK(decide(PM_IN_PUNCH | PM_IN_UDP, 4000) == PM_NONE, "binding the try: a need");
    health(PK_UDP_RELAY, PH_DEAD);
    CHECK(decide(PM_IN_PUNCH | PM_IN_PORTS | PM_IN_UDP, 7000) == PM_NEED_WS, "the try not bound: no straight way back");
    /* tests: no UDP (NPF_TEST_WS_FILE): the WS relay, from any path */
    start(D | U, PH_UP);
    CHECK(decide(PM_IN_NOUDP, 0) == PM_NEED_WS, "no UDP: not the WS relay");
    /* a direct connection's fixed path: nothing ever */
    start(D, PH_SUSPECT);
    m.fixed = 1;
    CHECK(decide(PM_IN_NOUDP, 0) == PM_NONE, "a fixed path asks");
}

int test_path_decide(void)
{
    direct();
    standby();
    udp_lost();
    each_loss();
    ws();
    return fails;
}

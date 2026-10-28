/* The paths' health (path.h pm_tick, architecture.md 2.4), one rule per
 * check, on a fake clock and fake paths that count what the rules tell
 * them: for each kind, silence with data in flight and without, the
 * probes while in doubt, a round trip bringing a path back, the verdict;
 * which paths the rules apply to (relied on: the primary one, the second
 * while the primary is in doubt; not one standing by, not a direct
 * connection's fixed one, not one not proven yet); a probe with no doubt
 * (the hot standby's check). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "path.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

typedef struct fake {
    npf_path p;
    int      suspects, probes, deads;
    int64_t  quiet;                 /* the last suspect's */
    int      busy;                  /* ... with data in flight */
} fake;

static fake f[PK_N];
static npf_pm m;

static void fake_tx(npf_path *p, const uint8_t *d, size_t len)
{
    (void)p, (void)d, (void)len;
}

static void fake_suspect(npf_path *p, int64_t quiet)
{
    fake *x = (fake *)(void *)p;
    x->suspects++;
    x->quiet = quiet;
    x->busy = p->busy_since != 0;
}

static void fake_probe(npf_path *p)
{
    ((fake *)(void *)p)->probes++;
}

static void fake_dead(npf_path *p)
{
    ((fake *)(void *)p)->deads++;
}

static const npf_path_ops fake_ops = {fake_tx, fake_suspect, fake_probe, fake_dead};

/* every path new and gone, the manager empty; the kinds given UP from t0 */
static void start(int kinds, int64_t t0)
{
    int k;
    memset(&m, 0, sizeof m);
    memset(f, 0, sizeof f);
    for (k = 0; k < PK_N; k++) {
        f[k].p.ops = &fake_ops;
        f[k].p.kind = (uint8_t)k;
        if (kinds & 1 << k) {
            f[k].p.health = PH_UP;
            f[k].p.since = f[k].p.last_rx = t0;
            pm_add(&m, &f[k].p);
        }
    }
}

#define D (1 << PK_DIRECT)
#define U (1 << PK_UDP_RELAY)
#define W (1 << PK_WS_RELAY)

/* silent with data in flight: max(3 s, 2 RTO) from the later of the last
 * datagram and the data going in flight; with none: 20 s (direct, UDP) or
 * 30 s (WS) from the later of the last datagram and the start */
static void silence(int kind)
{
    fake *x = &f[kind];
    int64_t due;
    int idle = kind == PK_WS_RELAY ? 30000 : 20000;

    /* idle: just before the threshold nothing, the due time is the threshold */
    start(1 << kind, 1000);
    due = pm_tick(&m, 1000 + idle - 1, 0, 200);
    CHECK(x->suspects == 0 && x->p.health == PH_UP && due == 1000 + idle, "kind %d: idle, %lld", kind, (long long)due);
    due = pm_tick(&m, 1000 + idle, 0, 200);
    CHECK(x->suspects == 1 && x->p.health == PH_SUSPECT && x->quiet == idle && !x->busy && x->p.suspect_at == 1000 + idle,
          "kind %d: silent %d ms idle: %d suspects, health %d", kind, idle, x->suspects, x->p.health);
    /* a datagram heard counts: the idle silence from it */
    start(1 << kind, 1000);
    x->p.last_rx = 15000;
    CHECK(pm_tick(&m, 1000 + idle, 0, 200) == 15000 + idle && x->suspects == 0, "kind %d: heard at 15 s", kind);

    /* data in flight from 50 s, nothing heard since 1 s */
    start(1 << kind, 1000);
    due = pm_tick(&m, 50000, 4, 200);
    if (kind == PK_WS_RELAY) {
        /* the WS relay: TCP's own retransmission; only the 30 s silence */
        CHECK(x->suspects == 1 && x->quiet == 30000, "WS relay in flight: the 30 s silence (%d)", x->suspects);
        start(1 << kind, 1000);
        x->p.last_rx = 40000;
        due = pm_tick(&m, 50000, 4, 200);
        CHECK(x->suspects == 0 && due == 70000, "WS relay in flight 10 s: %lld", (long long)due);
        return;
    }
    CHECK(x->suspects == 0 && x->p.busy_since == 50000 && due == 53000, "kind %d: in flight from now: %lld", kind,
          (long long)due);
    CHECK(pm_tick(&m, 52999, 4, 200) == 53000 && x->suspects == 0, "kind %d: in flight 2999 ms", kind);
    pm_tick(&m, 53000, 4, 200);
    CHECK(x->suspects == 1 && x->busy && x->quiet == 3000, "kind %d: in flight 3 s, nothing heard", kind);
    /* a datagram heard in flight: from it */
    start(1 << kind, 1000);
    pm_tick(&m, 50000, 4, 200);
    x->p.last_rx = 51000;
    CHECK(pm_tick(&m, 53000, 4, 200) == 54000 && x->suspects == 0, "kind %d: heard in flight", kind);
    /* 2 RTO above 3 s */
    start(1 << kind, 1000);
    pm_tick(&m, 50000, 4, 2500);
    CHECK(pm_tick(&m, 54999, 4, 2500) == 55000 && x->suspects == 0, "kind %d: 2 RTO 5 s", kind);
    pm_tick(&m, 55000, 4, 2500);
    CHECK(x->suspects == 1 && x->quiet == 5000, "kind %d: in flight 2 RTO", kind);
    /* the data acknowledged: in flight no longer, idle from the last datagram */
    start(1 << kind, 1000);
    pm_tick(&m, 50000, 4, 200);
    pm_tick(&m, 51000, 0, 200);
    CHECK(x->p.busy_since == 0, "kind %d: in flight still", kind);
}

/* in doubt: the direct path probed every 500 ms, lost 10 s after; the
 * relays probe and decide on their own (no probe, no verdict by time) */
static void doubt(int kind)
{
    fake *x = &f[kind];
    int64_t t, due;
    start(1 << kind, 0);
    pm_tick(&m, 40000, 0, 200);
    CHECK(x->p.health == PH_SUSPECT, "kind %d: not in doubt", kind);
    if (kind == PK_DIRECT) {
        CHECK(x->probes == 1 && x->p.probe_at == 40500, "the direct path: a check at once (%d)", x->probes);
        CHECK(pm_tick(&m, 40499, 0, 200) == 40500 && x->probes == 1, "a check before 500 ms");
        for (t = 40500; t < 50000; t += 500)
            pm_tick(&m, t, 0, 200);
        CHECK(x->probes == 20 && x->deads == 0 && x->p.health == PH_SUSPECT, "the direct path: %d checks in 10 s",
              x->probes);
        due = pm_tick(&m, 49999, 0, 200);
        CHECK(due == 50000, "the verdict at 10 s (%lld)", (long long)due);
        pm_tick(&m, 50000, 0, 200);
        CHECK(x->deads == 1 && x->p.health == PH_DEAD && x->probes == 20, "the direct path not lost at 10 s");
        CHECK(pm_tick(&m, 60000, 0, 200) == INT64_MAX && x->deads == 1, "lost twice");
        return;
    }
    for (t = 40000; t < 400000; t += 1000)
        CHECK(pm_tick(&m, t, 0, 200) == INT64_MAX, "kind %d: a due time in doubt", kind);
    CHECK(x->probes == 0 && x->deads == 0 && x->p.health == PH_SUSPECT, "kind %d: probed (%d) or lost (%d) by time",
          kind, x->probes, x->deads);
    pm_dead(&m, &x->p);                 /* its own verdict (every address tried, reconnects failed) */
    CHECK(x->p.health == PH_DEAD && pm_tick(&m, 500000, 0, 200) == INT64_MAX && x->deads == 0, "kind %d: DEAD", kind);
}

/* a round trip proven brings a path in doubt back; its silence from then */
static void back(int kind)
{
    fake *x = &f[kind];
    start(1 << kind, 0);
    pm_tick(&m, 40000, 0, 200);
    CHECK(pm_rt(&m, &x->p, 41000) == 1 && x->p.health == PH_UP && x->p.rt_ok == 41000, "kind %d: not back", kind);
    CHECK(pm_rt(&m, &x->p, 41001) == 0 && x->p.rt_ok == 41001, "kind %d: back twice", kind);
    x->p.last_rx = 41000;
    CHECK(pm_tick(&m, 42000, 0, 200) == 41000 + (kind == PK_WS_RELAY ? 30000 : 20000) && x->suspects == 1,
          "kind %d: in doubt again at once", kind);
}

/* whom the rules apply to: the direct path and the UDP relay second while
 * it is in doubt (each datagram on both), the relay standing by not */
static void relied(void)
{
    fake *d = &f[PK_DIRECT], *u = &f[PK_UDP_RELAY];
    start(D | U, 0);
    CHECK(u->p.role == PR_STANDBY && !pm_relied(&m, &u->p) && pm_relied(&m, &d->p), "roles with a direct path");
    d->p.last_rx = 1000000;             /* the direct path heard all along */
    CHECK(pm_tick(&m, 500000, 4, 200) == 1003000 && u->suspects == 0 && u->p.busy_since == 0,
          "the relay standing by checked");
    /* the direct path in doubt: the relay second, relied on (silent 20 s: in doubt in the same tick) */
    d->p.last_rx = 0;
    pm_tick(&m, 1000000, 0, 200);
    CHECK(d->suspects == 1 && m.second == &u->p && u->p.role == PR_SECOND && u->suspects == 1,
          "the relay second while the direct path is in doubt (%d)", u->suspects);
    /* the direct path lost: the relay primary */
    start(D | U, 0);
    u->p.last_rx = 1009000;
    pm_tick(&m, 1000000, 0, 200);
    pm_tick(&m, 1010000, 0, 200);
    CHECK(d->p.health == PH_DEAD && m.primary == &u->p && !m.second && u->suspects == 0,
          "the relay after the direct path's verdict");
    pm_del(&m, &d->p);
    CHECK(m.primary == &u->p && pm_relied(&m, &u->p), "the relay alone");

    /* a direct connection's fixed path: no rules */
    start(D, 0);
    m.fixed = 1;
    CHECK(pm_tick(&m, 500000, 0, 200) == INT64_MAX && d->suspects == 0, "a fixed path checked");
    /* a path not proven yet (a UDP relay binding, a WS relay not paired): no rules */
    start(0, 0);
    pm_add(&m, &f[PK_UDP_RELAY].p);
    CHECK(f[PK_UDP_RELAY].p.health == PH_NEW && pm_tick(&m, 500000, 4, 200) == INT64_MAX
          && f[PK_UDP_RELAY].suspects == 0, "a new path checked");
    CHECK(pm_rt(&m, &f[PK_UDP_RELAY].p, 500000) == 1 && f[PK_UDP_RELAY].p.health == PH_UP, "a new path proven");
    /* the WS relay exclusive: the others not relied on */
    start(D | U | W, 0);
    CHECK(pm_relied(&m, &f[PK_WS_RELAY].p) && !pm_relied(&m, &d->p) && !pm_relied(&m, &u->p), "roles on WS");
    pm_tick(&m, 25000, 0, 200);
    CHECK(d->suspects == 0 && u->suspects == 0 && f[PK_WS_RELAY].suspects == 0, "checked beside the WS relay");
}

/* probed with no doubt (the standby's check, pm_probe): the direct path's
 * checks every 500 ms for the window, nothing else (the relay stands by, no
 * verdict); a round trip ends them */
static void probed(void)
{
    fake *d = &f[PK_DIRECT], *u = &f[PK_UDP_RELAY];
    int64_t t;
    start(D | U, 0);
    d->p.last_rx = 1000000;
    pm_probe(&d->p, 1000, 10000);
    CHECK(pm_tick(&m, 1000, 0, 200) == 1500 && d->probes == 1, "the first check (%d)", d->probes);
    for (t = 1500; t < 11000; t += 500)
        pm_tick(&m, t, 0, 200);
    CHECK(d->probes == 20 && d->p.health == PH_UP && u->p.role == PR_STANDBY && !m.second && d->suspects == 0,
          "probed: %d checks, health %d, relay role %d", d->probes, d->p.health, u->p.role);
    pm_tick(&m, 11000, 0, 200);
    CHECK(d->probes == 20 && d->p.probe_until == 0 && d->deads == 0, "checks after the window (%d)", d->probes);
    pm_probe(&d->p, 20000, 10000);
    pm_tick(&m, 20000, 0, 200);
    CHECK(pm_rt(&m, &d->p, 20100) == 0 && d->p.probe_until == 0 && d->p.rt_ok == 20100, "the echo");
    pm_tick(&m, 21000, 0, 200);
    CHECK(d->probes == 21, "checks after the echo (%d)", d->probes);
}

int test_path_health(void)
{
    int k;
    fails = 0;
    CHECK(pm_rules_of[PK_DIRECT].t_idle == 20000 && pm_rules_of[PK_UDP_RELAY].t_idle == 20000,
          "the idle silence of the direct path and the UDP relay (Q3)");
    for (k = 0; k < PK_N; k++) {
        silence(k);
        doubt(k);
        back(k);
    }
    relied();
    probed();
    return fails;
}

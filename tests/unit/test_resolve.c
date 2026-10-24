/* The resolver's lifetimes and budget (review R2, R7): a lookup still running
 * when its loop is freed, a result posted but not delivered when the loop
 * goes, cancel-and-restart that must not pile up work, the request limit.
 * ASan / LSan report what these get wrong. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>

#include "npf/loop.h"
#include "npf/platform.h"
#include "npf/resolve.h"
#include "npf/crypto.h"
#include "../../src/node/udpfwd.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* shared with the workers: atomics (ThreadSanitizer) */
static int g_hold;                  /* the fake DNS answers only when 0 */
static int g_calls;
#define HOLD(v)  __atomic_store_n(&g_hold, (v), __ATOMIC_SEQ_CST)
#define CALLS()  __atomic_load_n(&g_calls, __ATOMIC_SEQ_CST)
static int g_delivered;

static int slow_gai(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    (void)service;
    (void)hints;
    if (strcmp(node, "own.example") == 0) {     /* a DNS server that answers this one */
        *res = NULL;
        return EAI_NONAME;
    }
    __atomic_fetch_add(&g_calls, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&g_hold, __ATOMIC_SEQ_CST))
        npf_sleep_ms(2);
    *res = NULL;
    return EAI_NONAME;
}

static int g_units;
static int unit_sink(void *arg, const uint8_t *buf, size_t len)
{
    (void)arg;
    (void)len;
    g_units += buf[0] == 2;         /* NPF_UDP_CLOSE */
    return 0;
}

static void got(npf_resolve *r, int err, const struct sockaddr_storage *a, const socklen_t *l, int n, void *arg)
{
    (void)r;
    (void)err;
    (void)a;
    (void)l;
    (void)n;
    (void)arg;
    g_delivered++;
}

/* until the pool has nothing queued or running (workers done), at most 5 s */
static int drained(void)
{
    int i;
    for (i = 0; i < 2500 && npf_resolve_active() > 0; i++)
        npf_sleep_ms(2);
    return npf_resolve_active() == 0;
}

int test_resolve(void)
{
    npf_resolve_gai_fn saved = npf_resolve_gai;
    npf_loop *l;
    npf_resolve *r[RESOLVE_CAPACITY + 8];
    int i, n;
    npf_resolve_gai = slow_gai;

    /* 1. the lookup runs on while the loop is cancelled and freed: the
     * worker must not post to the freed loop (it did: heap-use-after-free) */
    HOLD(1);
    l = npf_loop_new();
    r[0] = npf_resolve_start(l, "slow.example", 80, SOCK_STREAM, got, NULL);
    CHECK(r[0] != NULL, "start");
    npf_resolve_cancel(r[0]);
    npf_loop_free(l);
    HOLD(0);
    CHECK(drained(), "the worker finished after the loop was freed");

    /* 2. answered and posted, the loop freed before it ran: released, not leaked */
    l = npf_loop_new();
    g_delivered = 0;
    r[0] = npf_resolve_start(l, "fast.example", 80, SOCK_STREAM, got, NULL);
    CHECK(r[0] != NULL && drained(), "answered");
    npf_loop_free(l);               /* the posted result is dropped here */
    CHECK(g_delivered == 0, "no callback after the loop was freed");

    /* 3. delivered normally */
    l = npf_loop_new();
    r[0] = npf_resolve_start(l, "fast.example", 80, SOCK_STREAM, got, NULL);
    for (i = 0; i < 500 && g_delivered == 0; i++)
        npf_loop_once(l, 10);
    CHECK(g_delivered == 1, "delivered once (%d)", g_delivered);

    /* 4. the budget, against a dead DNS server. (a) lookups nobody cancels:
     * the pool takes RESOLVE_CAPACITY and refuses the rest, RESOLVE_WORKERS
     * run at once. (b) cancel and start again, over and over: a cancelled
     * lookup that already runs keeps its place until the system returns, a
     * queued one costs nothing; the pool never holds more than its capacity
     * and never runs more than its workers. */
    HOLD(1);
    __atomic_store_n(&g_calls, 0, __ATOMIC_SEQ_CST);
    for (n = 0, i = 0; i < RESOLVE_CAPACITY + 8; i++) {
        r[i] = npf_resolve_start(l, "dead.example", 80, SOCK_STREAM, got, NULL);
        n += r[i] != NULL;
    }
    CHECK(n == RESOLVE_CAPACITY, "%d of %d lookups accepted, want %d", n, RESOLVE_CAPACITY + 8, RESOLVE_CAPACITY);
    npf_sleep_ms(50);
    CHECK(CALLS() <= RESOLVE_WORKERS, "at most %d lookups run at once (%d)", RESOLVE_WORKERS, CALLS());
    for (i = 0; i < RESOLVE_CAPACITY + 8; i++)
        npf_resolve_cancel(r[i]);
    for (n = 0, i = 0; i < 2000; i++) {
        npf_resolve *x = npf_resolve_start(l, "dead.example", 80, SOCK_STREAM, got, NULL);
        npf_resolve_cancel(x);
        if (npf_resolve_active() > RESOLVE_CAPACITY)
            n++;
    }
    CHECK(n == 0, "the pool went over its capacity %d times", n);
    CHECK(CALLS() <= RESOLVE_WORKERS, "still at most %d lookups at once (%d)", RESOLVE_WORKERS, CALLS());
    CHECK(npf_resolve_active() >= RESOLVE_WORKERS, "running cancelled lookups still count (%d)", npf_resolve_active());
    HOLD(0);
    CHECK(drained(), "the pool drains once DNS answers");
    CHECK(g_delivered == 1, "no callback for cancelled lookups (%d)", g_delivered);
    CHECK(npf_resolve_start(l, "fast.example", 80, SOCK_STREAM, got, NULL) != NULL, "room again afterwards");
    CHECK(drained(), "drained");
    npf_loop_free(l);

    /* 5. the peers' lookups against a dead DNS server: they get their share
     * (RESOLVE_PEER_CAPACITY requests, RESOLVE_PEER_WORKERS threads) and
     * the node's own lookup is answered meanwhile */
    l = npf_loop_new();
    HOLD(1);
    __atomic_store_n(&g_calls, 0, __ATOMIC_SEQ_CST);
    g_delivered = 0;
    for (n = 0, i = 0; i < RESOLVE_CAPACITY; i++) {
        r[i] = npf_resolve_start_peer(l, "dead.example", 80, SOCK_STREAM, got, NULL);
        n += r[i] != NULL;
    }
    CHECK(n == RESOLVE_PEER_CAPACITY && npf_resolve_active_peer() == RESOLVE_PEER_CAPACITY,
          "%d peers' lookups accepted, want %d", n, RESOLVE_PEER_CAPACITY);
    npf_sleep_ms(50);
    CHECK(CALLS() == RESOLVE_PEER_WORKERS, "the peers' lookups run on %d threads (%d)", RESOLVE_PEER_WORKERS, CALLS());
    CHECK(npf_resolve_start(l, "own.example", 80, SOCK_STREAM, got, NULL) != NULL, "the node's own lookup has room");
    for (i = 0; i < 300 && g_delivered == 0; i++)
        npf_loop_once(l, 10);
    CHECK(g_delivered == 1, "the node's own lookup answered while the peers' wait (%d)", g_delivered);
    for (i = 0; i < RESOLVE_CAPACITY; i++)
        npf_resolve_cancel(r[i]);
    HOLD(0);
    CHECK(drained() && npf_resolve_active_peer() == 0, "the peers' share drains");
    npf_loop_free(l);

    /* 5a. one session's UDP flows to names (review 2026-10-24): at most
     * UDP_RESOLVING_MAX (2) of its lookups at once, the rest refused at
     * once: one session cannot take the peers' share from the others */
    {
        npf_policy pol;
        npf_udpf_io uio;
        npf_udpf *u;
        uint8_t fr[64];
        char name[32];
        memset(&pol, 0, sizeof pol);
        memset(&uio, 0, sizeof uio);
        uio.unit = unit_sink;
        l = npf_loop_new();
        u = npf_udpf_new(l, NULL, 0, &pol, &uio, NULL);     /* callee, on the WS relay */
        HOLD(1);
        g_units = 0;
        for (i = 0; i < 10; i++) {
            size_t tl = (size_t)snprintf(name, sizeof name, "dead%d.example", i);
            npf_le32(fr, (uint32_t)(2 * i + 1));            /* the caller's flows are odd */
            fr[4] = 1;                                      /* the target follows */
            fr[5] = (uint8_t)tl;
            memcpy(fr + 6, name, tl);
            npf_le16(fr + 6 + tl, 53);
            fr[8 + tl] = 'x';
            npf_udpf_ws_input(u, fr, 9 + tl);
        }
        CHECK(npf_resolve_active_peer() == 2, "one session's UDP flows hold 2 lookups (%d)", npf_resolve_active_peer());
        CHECK(g_units == 8, "the other 8 flows refused at once (%d)", g_units);
        npf_udpf_free(u);                                   /* cancels its lookups */
        HOLD(0);
        CHECK(drained() && npf_resolve_active_peer() == 0, "its lookups gone with the session");
        npf_loop_free(l);
    }

    /* 6. many loops created and freed while lookups run */
    HOLD(1);
    for (i = 0; i < 20; i++) {
        l = npf_loop_new();
        npf_resolve_start(l, "slow.example", 80, SOCK_STREAM, got, NULL);
        npf_loop_free(l);
    }
    HOLD(0);
    CHECK(drained(), "loops freed with lookups running");
    npf_resolve_gai = saved;
    return fails;
}

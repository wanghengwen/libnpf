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

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static volatile int g_hold;         /* the fake DNS answers only when 0 */
static volatile int g_calls;
static int g_delivered;

static int slow_gai(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    (void)node;
    (void)service;
    (void)hints;
    g_calls++;
    while (g_hold)
        npf_sleep_ms(2);
    *res = NULL;
    return EAI_NONAME;
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
    g_hold = 1;
    l = npf_loop_new();
    r[0] = npf_resolve_start(l, "slow.example", 80, SOCK_STREAM, got, NULL);
    CHECK(r[0] != NULL, "start");
    npf_resolve_cancel(r[0]);
    npf_loop_free(l);
    g_hold = 0;
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
    g_hold = 1;
    g_calls = 0;
    for (n = 0, i = 0; i < RESOLVE_CAPACITY + 8; i++) {
        r[i] = npf_resolve_start(l, "dead.example", 80, SOCK_STREAM, got, NULL);
        n += r[i] != NULL;
    }
    CHECK(n == RESOLVE_CAPACITY, "%d of %d lookups accepted, want %d", n, RESOLVE_CAPACITY + 8, RESOLVE_CAPACITY);
    npf_sleep_ms(50);
    CHECK(g_calls <= RESOLVE_WORKERS, "at most %d lookups run at once (%d)", RESOLVE_WORKERS, g_calls);
    for (i = 0; i < RESOLVE_CAPACITY + 8; i++)
        npf_resolve_cancel(r[i]);
    for (n = 0, i = 0; i < 2000; i++) {
        npf_resolve *x = npf_resolve_start(l, "dead.example", 80, SOCK_STREAM, got, NULL);
        npf_resolve_cancel(x);
        if (npf_resolve_active() > RESOLVE_CAPACITY)
            n++;
    }
    CHECK(n == 0, "the pool went over its capacity %d times", n);
    CHECK(g_calls <= RESOLVE_WORKERS, "still at most %d lookups at once (%d)", RESOLVE_WORKERS, g_calls);
    CHECK(npf_resolve_active() >= RESOLVE_WORKERS, "running cancelled lookups still count (%d)", npf_resolve_active());
    g_hold = 0;
    CHECK(drained(), "the pool drains once DNS answers");
    CHECK(g_delivered == 1, "no callback for cancelled lookups (%d)", g_delivered);
    CHECK(npf_resolve_start(l, "fast.example", 80, SOCK_STREAM, got, NULL) != NULL, "room again afterwards");
    CHECK(drained(), "drained");
    npf_loop_free(l);

    /* 5. many loops created and freed while lookups run */
    g_hold = 1;
    for (i = 0; i < 20; i++) {
        l = npf_loop_new();
        npf_resolve_start(l, "slow.example", 80, SOCK_STREAM, got, NULL);
        npf_loop_free(l);
    }
    g_hold = 0;
    CHECK(drained(), "loops freed with lookups running");
    npf_resolve_gai = saved;
    return fails;
}

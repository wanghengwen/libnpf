/* Event loop timers (binary min-heap): firing order by due time, then by the
 * order added; cancel from anywhere, including a timer cancelling itself or
 * another one from its callback, and adding timers from a callback. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/loop.h"
#include "npf/platform.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

#define NT 300

static struct {
    npf_timer *t[NT];
    int        delay[NT];
    int64_t    due_lo[NT], due_hi[NT];  /* the due time lies in [lo, hi]: the loop reads the clock itself */
    int        fired[NT];
    int        cancelled[NT];
    int        order[NT + 8];
    int        nfired;
    npf_loop  *loop;
} T;

static void fire(npf_loop *l, void *arg)
{
    int i = (int)(long)arg;
    (void)l;
    T.fired[i]++;
    T.order[T.nfired++] = i;
    T.t[i] = NULL;
    npf_timer_cancel(l, T.t[i]);    /* NULL: nothing */
    if (i % 7 == 0 && i + 1 < NT && T.t[i + 1]) {   /* cancel a later one */
        npf_timer_cancel(l, T.t[i + 1]);
        T.t[i + 1] = NULL;
        T.cancelled[i + 1] = 1;
    }
}

static npf_timer *self;
static int self_fired, added_fired;

static void added(npf_loop *l, void *arg)
{
    (void)arg;
    added_fired++;
    npf_loop_stop(l);
}

static void cancels_itself(npf_loop *l, void *arg)
{
    (void)arg;
    self_fired++;
    npf_timer_cancel(l, self);      /* firing: a no-op, freed after return */
    self = NULL;
    npf_timer_add(l, 5, added, NULL);
}

int test_loop(void)
{
    int i, prev = -1, ok = 1;
    T.loop = npf_loop_new();
    srand(7);
    for (i = 0; i < NT; i++) {
        int64_t before;
        T.delay[i] = rand() % 8 * 5;            /* many equal due times */
        before = npf_mono_ms();
        T.t[i] = npf_timer_add(T.loop, T.delay[i], fire, (void *)(long)i);
        T.due_lo[i] = before + T.delay[i];
        T.due_hi[i] = npf_mono_ms() + T.delay[i];
    }
    for (i = 3; i < NT; i += 10) {              /* cancel some up front */
        npf_timer_cancel(T.loop, T.t[i]);
        T.t[i] = NULL;
        T.cancelled[i] = 1;
    }
    self = npf_timer_add(T.loop, 60, cancels_itself, NULL);
    npf_loop_run(T.loop);
    for (i = 0; i < NT; i++)
        CHECK(T.fired[i] == !T.cancelled[i], "timer %d fired %d times (cancelled %d)", i, T.fired[i], T.cancelled[i]);
    /* the order of the real due times: delays are relative to the clock at
     * each add, so a pause while adding moves later timers' due times (T2).
     * A violation is only one that holds for any due time in the ranges: k
     * fired after prev although surely due earlier, or due at the same
     * millisecond and added earlier. */
    for (i = 0; i < T.nfired; i++) {
        int k = T.order[i];
        if (prev >= 0 && k < NT && prev < NT
            && (T.due_hi[k] < T.due_lo[prev]
                || (T.due_lo[k] == T.due_hi[k] && T.due_lo[prev] == T.due_hi[prev] && T.due_lo[k] == T.due_lo[prev]
                    && k < prev)))
            ok = 0;
        prev = k;
    }
    CHECK(ok, "timers fire by due time, then in the order added");
    CHECK(T.nfired > NT / 2, "most timers fired (%d)", T.nfired);
    CHECK(self_fired == 1 && added_fired == 1, "self-cancel and add from a callback");
    /* timers left pending are freed with the loop */
    npf_timer_add(T.loop, 100000, fire, (void *)0L);
    npf_loop_free(T.loop);
    return fails;
}

/* Event loop timers (binary min-heap): firing order by due time, then by the
 * order added; cancel from anywhere, including a timer cancelling itself or
 * another one from its callback, and adding timers from a callback; a
 * descriptor the queue takes in part (kqueue) leaves nothing in it;
 * embedded timers moved within the heap, set again from their own callback. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/log.h"
#include "npf/loop.h"
#include "npf/platform.h"
#include "../../src/platform/loop_int.h"    /* the loop's queue (epfd) */
#include "test.h"
#if !defined(__linux__) && !defined(_WIN32)
#include <sys/event.h>
#endif

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

/* a timer that arms itself again at once: one firing per turn of the loop,
 * the sockets looked at in between (it used to keep the loop in its timers) */
static int rearm_n;
static void rearm(npf_loop *l, void *arg)
{
    (void)arg;
    if (++rearm_n < 1000)
        npf_timer_add(l, 0, rearm, NULL);
}

/* within one poll's batch, a callback closes another socket and a new one
 * gets its number: that one's handler does not get the old one's events */
static int sp_y[2], sp_new[2], new_called, x_called;
static void new_cb(npf_loop *l, int fd, unsigned ev, void *arg) { (void)l; (void)fd; (void)ev; (void)arg; new_called++; }
static void y_cb(npf_loop *l, int fd, unsigned ev, void *arg) { (void)l; (void)fd; (void)ev; (void)arg; }
static void x_cb(npf_loop *l, int fd, unsigned ev, void *arg)
{
    char b[8];
    (void)ev;
    (void)arg;
    x_called++;
    (void)!recv(fd, b, sizeof b, 0);
    npf_loop_del(l, sp_y[0]);
    close(sp_y[0]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp_new);   /* the lowest free number: the one just closed */
    npf_loop_add(l, sp_new[0], NPF_EV_READ, new_cb, NULL);
}

static void test_reuse(void)
{
    npf_loop *l = npf_loop_new();
    int sp_x[2], reused;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp_x);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp_y);
    npf_loop_add(l, sp_x[0], NPF_EV_READ, x_cb, NULL);    /* before y in the poll set */
    npf_loop_add(l, sp_y[0], NPF_EV_READ, y_cb, NULL);
    (void)!send(sp_x[1], "x", 1, 0);
    (void)!send(sp_y[1], "y", 1, 0);                      /* y readable in the same batch */
    npf_loop_once(l, 100);
    reused = sp_new[0] == sp_y[0];
    CHECK(x_called == 1, "x read");
    CHECK(new_called == 0, "the new socket (number %s) got no stale event", reused ? "reused" : "not reused");
    npf_loop_once(l, 0);
    CHECK(new_called == 0, "nothing to read on it later either");
    npf_loop_del(l, sp_new[0]);
    npf_loop_del(l, sp_x[0]);
    close(sp_x[0]);
    close(sp_x[1]);
    close(sp_y[1]);
    close(sp_new[0]);
    close(sp_new[1]);

    npf_timer_add(l, 0, rearm, NULL);
    npf_loop_once(l, 0);
    CHECK(rearm_n == 1, "a timer armed again at once waits for the next turn (%d)", rearm_n);
    npf_loop_once(l, 0);
    CHECK(rearm_n == 2, "and fires then (%d)", rearm_n);
    rearm_n = 1000;
    npf_loop_free(l);
}

/* embedded timers (npf_timer_init / npf_timer_set): no allocation, moved
 * within the heap, set again from their own callback, in the same order as
 * npf_timer_add's */
typedef struct emb {
    npf_timer t;
    int       fired, again;
    int       seq;              /* the order it fired in */
} emb;
static int emb_n;
static void emb_cb(npf_loop *l, void *arg)
{
    emb *e = arg;
    e->fired++;
    e->seq = ++emb_n;
    CHECK(!npf_timer_pending(&e->t), "not pending while it fires");
    if (e->again && e->again--)
        npf_timer_set(l, &e->t, 0);            /* from its own callback: the next turn */
}
static void emb_alloc_cb(npf_loop *l, void *arg)
{
    (void)l;
    *(int *)arg = ++emb_n;
}

static void test_embedded(void)
{
    npf_loop *l = npf_loop_new();
    emb a, b, c, *z = calloc(1, sizeof *z);
    int i, alloc_seq = 0;
    npf_timer_init(&a.t, emb_cb, &a);
    npf_timer_init(&b.t, emb_cb, &b);
    npf_timer_init(&c.t, emb_cb, &c);
    a.fired = b.fired = c.fired = 0;
    a.again = b.again = c.again = 0;
    CHECK(!npf_timer_pending(&z->t), "a zeroed one is not pending");
    npf_timer_cancel(l, &z->t);                 /* nothing to do */
    npf_timer_cancel(l, &a.t);                  /* initialised, never set: nothing to do */
    CHECK(npf_timer_set(l, &a.t, 100000) == 0 && npf_timer_pending(&a.t), "set: pending");
    npf_timer_set(l, &b.t, 100000);
    npf_timer_set(l, &c.t, 100000);
    for (i = 0; i < 50; i++) {                  /* moved many times: one heap entry each */
        npf_timer_set(l, &a.t, 100000 + i);
        npf_timer_set(l, &b.t, 50000 - i);
    }
    npf_timer_set(l, &a.t, 0);                  /* moved earlier */
    npf_timer_add(l, 0, emb_alloc_cb, &alloc_seq);     /* due with a, set after it */
    npf_timer_set(l, &c.t, 0);                  /* also due with a: set after both */
    npf_timer_cancel(l, &b.t);
    CHECK(!npf_timer_pending(&b.t), "cancelled: not pending");
    npf_loop_once(l, 0);
    CHECK(a.fired == 1 && c.fired == 1 && b.fired == 0, "moved earlier ones fired, the cancelled one not");
    CHECK(a.seq == 1 && alloc_seq == 2 && c.seq == 3, "in the order set, with npf_timer_add's (%d %d %d)",
          a.seq, alloc_seq, c.seq);
    a.again = 2;
    npf_timer_set(l, &a.t, 0);
    npf_loop_once(l, 0);
    CHECK(a.fired == 2 && npf_timer_pending(&a.t), "set again from its callback: pending");
    npf_loop_once(l, 0);
    npf_loop_once(l, 0);
    CHECK(a.fired == 4 && !npf_timer_pending(&a.t), "one firing per turn, then done (%d)", a.fired);
    npf_timer_set(l, &b.t, 100000);             /* left pending: the loop does not free it */
    npf_timer_set(l, &z->t, 100000);
    npf_timer_cancel(l, &z->t);
    free(z);                                    /* the owner goes once it is cancelled */
    npf_loop_free(l);
    CHECK(!npf_timer_pending(&b.t), "not pending once its loop is freed");
}

/* a standalone loop's callbacks run in the thread's log context (the
 * instance's level, hook, ring): not the process's (it lost its debug lines) */
static int ctx_timer_debug = -1, ctx_fd_debug = -1;
static void ctx_timer(npf_loop *l, void *arg) { (void)l; (void)arg; ctx_timer_debug = npf_log_on(NPF_LOG_DEBUG); }
static void ctx_fd(npf_loop *l, int fd, unsigned ev, void *arg)
{
    char b[4];
    (void)l; (void)ev; (void)arg;
    (void)!recv(fd, b, sizeof b, 0);
    ctx_fd_debug = npf_log_on(NPF_LOG_DEBUG);
}

static void test_logctx(void)
{
    npf_loop *l = npf_loop_new();
    npf_log_ctx ctx, *prev;
    int sp[2], was = npf_log_get_level();
    memset(&ctx, 0, sizeof ctx);
    ctx.level = NPF_LOG_DEBUG;
    npf_log_set_level(NPF_LOG_INFO);        /* the process: info */
    prev = npf_log_ctx_swap(&ctx);          /* this thread's instance: debug */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    npf_loop_add(l, sp[0], NPF_EV_READ, ctx_fd, NULL);
    (void)!send(sp[1], "x", 1, 0);
    npf_timer_add(l, 0, ctx_timer, NULL);
    npf_loop_once(l, 100);
    npf_loop_once(l, 0);
    CHECK(ctx_fd_debug == 1 && ctx_timer_debug == 1, "callbacks in the thread's log context (fd %d, timer %d)",
          ctx_fd_debug, ctx_timer_debug);
    npf_log_ctx_swap(prev);
    npf_log_set_level(was);
    npf_loop_del(l, sp[0]);
    close(sp[0]);
    close(sp[1]);
    npf_loop_free(l);
}

/* a descriptor the queue does not take is refused, not left silent; a
 * freed entry is taken again by the next socket and both still fire */
static int slot_hits[3];
static void slot_cb(npf_loop *l, int fd, unsigned ev, void *arg)
{
    char b[8];
    (void)l;
    (void)ev;
    slot_hits[(int)(long)arg]++;
    while (recv(fd, b, sizeof b, MSG_DONTWAIT) > 0)
        ;
}

static void test_slots(void)
{
    npf_loop *l = npf_loop_new();
    int sp[3][2], i;
    for (i = 0; i < 3; i++)
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp[i]) == 0, "socketpair");
#ifdef __linux__
    {   /* epoll takes no regular file */
        char path[] = "/tmp/npf-loop-XXXXXX";
        int f = mkstemp(path);
        CHECK(f >= 0 && npf_loop_add(l, f, NPF_EV_READ, slot_cb, (void *)0L) < 0, "a regular file refused");
        CHECK(npf_loop_add(l, sp[0][0], NPF_EV_READ, slot_cb, (void *)0L) == 0, "and nothing left of it");
        npf_loop_del(l, sp[0][0]);
        if (f >= 0) {
            close(f);
            unlink(path);
        }
    }
#elif !defined(_WIN32)
    {   /* kqueue: a kqueue takes a read filter but no write filter; the read
         * one is not left behind pointing at the registration freed */
        int k = kqueue();
        struct kevent del;
        CHECK(k >= 0 && npf_loop_add(l, k, NPF_EV_READ | NPF_EV_WRITE, slot_cb, (void *)0L) < 0, "a kqueue for writing refused");
        EV_SET(&del, k, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        CHECK(kevent(l->epfd, &del, 1, NULL, 0, NULL) < 0, "and nothing left of it in the queue");
        close(k);
    }
#endif
    for (i = 0; i < 3; i++)
        CHECK(npf_loop_add(l, sp[i][0], NPF_EV_READ, slot_cb, (void *)(long)i) == 0, "add %d", i);
    npf_loop_del(l, sp[0][0]);
    npf_loop_del(l, sp[1][0]);
    CHECK(npf_loop_add(l, sp[1][0], NPF_EV_READ, slot_cb, (void *)1L) == 0, "a freed entry taken again");
    CHECK(npf_loop_add(l, sp[0][0], NPF_EV_READ, slot_cb, (void *)0L) == 0, "and the next one");
    for (i = 0; i < 3; i++)
        CHECK(send(sp[i][1], "x", 1, 0) == 1, "send");
    for (i = 0; i < 5 && (!slot_hits[0] || !slot_hits[1] || !slot_hits[2]); i++)
        npf_loop_once(l, 50);
    CHECK(slot_hits[0] && slot_hits[1] && slot_hits[2], "each fires (%d %d %d)", slot_hits[0], slot_hits[1],
          slot_hits[2]);
    npf_loop_free(l);
    for (i = 0; i < 3; i++) {
        close(sp[i][0]);
        close(sp[i][1]);
    }
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
    test_reuse();
    test_embedded();
    test_logctx();
    test_slots();
    return fails;
}

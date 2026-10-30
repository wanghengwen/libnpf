/* The single-threaded event loop (epoll, kqueue or WSAPoll) with timers and
 * calls posted from other threads. Internal to libnpf; in include/npf
 * because npf's app (control socket, web server, service), modules (TUN)
 * and tools run on an instance's loop.
 *
 * Only the loop's thread may call these functions, except where a comment
 * says otherwise. Callbacks run on that thread and must not block. */
#ifndef NPF_LOOP_H
#define NPF_LOOP_H

#include <stddef.h>
#include <stdint.h>

#define NPF_EV_READ  1u
#define NPF_EV_WRITE 2u
#define NPF_EV_ERROR 4u

typedef struct npf_loop npf_loop;
typedef struct npf_timer npf_timer;

typedef void (*npf_io_fn)(npf_loop *loop, int fd, unsigned events, void *arg);
typedef void (*npf_timer_fn)(npf_loop *loop, void *arg);

/* A timer: npf_timer_add's (allocated, one-shot), or embedded in its owner
 * (npf_timer_init / npf_timer_set: no allocation, set again any number of
 * times). The fields are the loop's. */
struct npf_timer {
    int64_t      due;
    uint64_t     seq;           /* equal due: in the order set */
    npf_timer_fn fn;
    void        *arg;
    int          pos;           /* 1 + its index in the loop's heap; 0 not pending (also while it fires) */
    int          owned;         /* npf_timer_add's: freed once it fired or was cancelled */
};

npf_loop *npf_loop_new(void);                  /* NULL on failure */
void      npf_loop_free(npf_loop *loop);

/* Watches fd for NPF_EV_READ / NPF_EV_WRITE; an error comes as
 * NPF_EV_ERROR | NPF_EV_READ, a hang-up as READ. One handler per fd: -1
 * when fd has one already, or on error. npf_loop_del before closing fd. */
int  npf_loop_add(npf_loop *loop, int fd, unsigned events, npf_io_fn fn, void *arg);
int  npf_loop_mod(npf_loop *loop, int fd, unsigned events);
void npf_loop_del(npf_loop *loop, int fd);

/* A one-shot timer: fn runs once, delay_ms from now (a negative delay is 0).
 * Timers due together run in the order they were added; one added by a
 * timer's callback runs no earlier than the next round. The handle is valid
 * until fn returns or the timer is cancelled; NULL when out of memory. */
npf_timer *npf_timer_add(npf_loop *loop, int64_t delay_ms, npf_timer_fn fn, void *arg);
/* Cancels a pending timer (npf_timer_add's is freed). t may be NULL, the
 * timer whose callback is running, or an embedded one not pending (then
 * nothing happens). */
void       npf_timer_cancel(npf_loop *loop, npf_timer *t);
/* Cancels *t (if set) and clears it. */
static inline void npf_timer_stop(npf_loop *loop, npf_timer **t)
{
    npf_timer_cancel(loop, *t);
    *t = NULL;
}

/* An embedded timer, for one its owner sets again and again (a session's,
 * a connection's): init once (a zeroed one is not pending either), then
 * npf_timer_set and npf_timer_cancel as often as needed, also from its own
 * callback; cancel it before the owner goes. set (re)schedules it delay_ms
 * from now, moved within the heap when pending: 0, or -1 when out of memory
 * (it is then not pending). The same ordering as npf_timer_add's. */
void npf_timer_init(npf_timer *t, npf_timer_fn fn, void *arg);
int  npf_timer_set(npf_loop *loop, npf_timer *t, int64_t delay_ms);
static inline int npf_timer_pending(const npf_timer *t) { return t->pos != 0; }

/* Runs the loop until npf_loop_stop. npf_loop_stop may be called from any
 * thread or a signal handler, also before npf_loop_run; it stays stopped. */
void npf_loop_run(npf_loop *loop);
void npf_loop_stop(npf_loop *loop);

/* Wakes the loop. Any thread; async-signal-safe. The loop then runs the
 * wake hook (one per loop, set by npf_loop_on_wake) on its thread; the hook
 * finds out why from flags of its own. */
void npf_loop_wake(npf_loop *loop);
void npf_loop_on_wake(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);

/* Runs fn(loop, arg) on the loop's thread soon, in posting order. Any
 * thread. 0, or -1 when out of memory (fn will not run). When the loop is
 * freed first, fn never runs; npf_loop_post_drop runs drop(arg) instead
 * (on the freeing thread). */
int  npf_loop_post(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);
int  npf_loop_post_drop(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void (*drop)(void *arg), void *arg);
/* fn(loop, arg) runs first in npf_loop_free, so that a component can stop
 * its worker threads before the loop goes. At most 4: 0, or -1. */
int  npf_loop_on_free(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);

/* One round: waits up to max_ms (-1: until something happens), then runs
 * what is ready. For tests and for the end of a run. */
void npf_loop_once(npf_loop *loop, int max_ms);

/* ---- a shared runtime: child loops run by a host loop's thread ----
 *
 * A child has its own sockets, timers and posted calls; waking it wakes the
 * host. npf_loop_attach (any thread; 0, or -1 when out of memory or not a
 * child) hands it to the host's thread, which calls start(child, arg) and
 * from then on runs the child with its own, under the child's log context
 * (npf_loop_set_logctx). After npf_loop_stop(child) the host calls
 * end(child, arg): it returns how many ms to go on before end is called
 * again, or -1. Then the child is detached and done(child, arg) runs, the
 * host's last use of it: it may be freed from then on. If the host has no
 * room, done runs at once without start or end. npf_loop_run and
 * npf_loop_once are not for children. */
struct npf_log_ctx;
typedef struct npf_child_fns {
    void (*start)(npf_loop *child, void *arg);
    int  (*end)(npf_loop *child, void *arg);
    void (*done)(npf_loop *child, void *arg);
} npf_child_fns;

npf_loop *npf_loop_new_child(npf_loop *host);
void npf_loop_set_logctx(npf_loop *child, struct npf_log_ctx *ctx);
int  npf_loop_attach(npf_loop *child, const npf_child_fns *fns, void *arg);

/* npf_mono_ms cached by the loop, refreshed each time it wakes. */
int64_t npf_loop_now(const npf_loop *loop);

#endif

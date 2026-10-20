/* Single-threaded event loop: poll for sockets, a binary min-heap for
 * timers. Everything in the node runs on one loop; callbacks must not block. */
#ifndef NPF_LOOP_H
#define NPF_LOOP_H

#include <stdint.h>

#define NPF_EV_READ  1u
#define NPF_EV_WRITE 2u
#define NPF_EV_ERROR 4u

typedef struct npf_loop npf_loop;
typedef struct npf_timer npf_timer;

typedef void (*npf_io_fn)(npf_loop *loop, int fd, unsigned events, void *arg);
typedef void (*npf_timer_fn)(npf_loop *loop, void *arg);

npf_loop *npf_loop_new(void);
void      npf_loop_free(npf_loop *loop);

/* register fd for events; one handler per fd */
int  npf_loop_add(npf_loop *loop, int fd, unsigned events, npf_io_fn fn, void *arg);
int  npf_loop_mod(npf_loop *loop, int fd, unsigned events);
void npf_loop_del(npf_loop *loop, int fd);

/* one-shot timer; returns a handle valid until it fires or is cancelled */
npf_timer *npf_timer_add(npf_loop *loop, int64_t delay_ms, npf_timer_fn fn, void *arg);
void       npf_timer_cancel(npf_loop *loop, npf_timer *t);

/* Run until npf_loop_stop(). */
void npf_loop_run(npf_loop *loop);
void npf_loop_stop(npf_loop *loop);

/* Wake the loop from a signal handler or another thread (async-signal-safe);
 * the wake hook, if set, then runs on the loop thread. The loop itself keeps
 * no state about why it was woken: the hook checks the flags it owns. */
void npf_loop_wake(npf_loop *loop);
void npf_loop_on_wake(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);

/* Run fn(loop, arg) on the loop thread as soon as it wakes: the way a worker
 * thread (resolver) hands its result back. Thread-safe; 0 or -1 (no memory). */
int  npf_loop_post(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);
/* the same, with drop(arg) run instead of fn when the loop is freed first */
int  npf_loop_post_drop(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void (*drop)(void *arg), void *arg);
/* fn(loop, arg) runs first thing in npf_loop_free (at most 4 hooks): a
 * component whose worker threads post to the loop stops them there.
 * 0 or -1 (no room) */
int  npf_loop_on_free(npf_loop *loop, void (*fn)(npf_loop *loop, void *arg), void *arg);

/* run one iteration waiting at most max_ms; for tests and embedding */
void npf_loop_once(npf_loop *loop, int max_ms);

/* ---- a shared runtime: child loops run by a host loop's thread ----
 *
 * A child has its own sockets, timers and posted calls, and no wake
 * descriptor: waking it wakes the host. npf_loop_attach (any thread) hands it
 * to the host's thread, which then dispatches it with the host's own, under
 * its log context (the instance's lines go to the instance). On
 * npf_loop_stop(child) the host calls end(child, arg) there: it returns how
 * long the child goes on being dispatched before end is called again, or -1;
 * then the child is detached and done(child, arg) runs, the last the host
 * does with it (anyone may free it from then on). npf_loop_run and
 * npf_loop_once are not for children. */
struct npf_log_ctx;
typedef struct npf_child_fns {
    void (*start)(npf_loop *child, void *arg);
    int  (*end)(npf_loop *child, void *arg);
    void (*done)(npf_loop *child, void *arg);
} npf_child_fns;

npf_loop *npf_loop_new_child(npf_loop *host);
void npf_loop_set_logctx(npf_loop *child, struct npf_log_ctx *ctx);
int  npf_loop_attach(npf_loop *child, const npf_child_fns *fns, void *arg);  /* 0 or -1 (no memory) */

int64_t npf_loop_now(const npf_loop *loop);     /* cached monotonic ms */

#endif

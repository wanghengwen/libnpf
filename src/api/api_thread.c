/* libnpf: the library thread. An instance's own or a shared runtime's
 * (npf_runtime), how a call from another thread reaches it and waits
 * (sync_call), the start, the run, the stop and the destroy. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include "npf/atomic.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "npf/platform.h"
#include "api_internal.h"

/* this thread is a shared runtime's: it never waits for another thread's
 * loop (two such waits, each for the other's thread, are a deadlock; a
 * wait stalls every instance of this thread) */
static NPF_THREAD_LOCAL int on_runtime;

int npf_api_init(npf_t *n)
{
    n->sync = calloc(1, sizeof *n->sync);
    if (!n->sync)
        return -1;
    if (npf_mutex_init(&n->sync->mu)) {
        free(n->sync);
        return -1;
    }
    if (npf_cond_init(&n->sync->cv)) {
        npf_mutex_free(&n->sync->mu);
        free(n->sync);
        return -1;
    }
    return 0;
}

void npf_api_fini(npf_t *n)
{
    npf_cond_free(&n->sync->cv);
    npf_mutex_free(&n->sync->mu);
    free(n->sync);
}

int api_enter(npf_t *n)
{
    int ok;
    if (!n)
        return 0;
    npf_atomic_add(&n->sync->calls, 1);
    LOCK();
    ok = !n->sync->destroying;
    if (!ok) {
        npf_atomic_add(&n->sync->calls, -1);
        WAKE();
    }
    UNLOCK();
    return ok;
}

void api_leave(npf_t *n)
{
    LOCK();
    npf_atomic_add(&n->sync->calls, -1);
    WAKE();
    UNLOCK();
}

/* fn on the caller's thread with a reference held (npf_start, npf_run, npf_stop) */
static int guarded(npf_t *n, int (*fn)(npf_t *n))
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = fn(n);
    api_leave(n);
    return r;
}

/* a call posted to the loop; the caller waits for it. It is on the heap: a
 * caller that gives up (the run ended first) leaves it to the loop. */
typedef struct job {
    npf_t *n;
    int  (*fn)(npf_t *n, void *arg);
    void  *arg;
    int    rc, done, cancelled;
} job;

static void job_run(npf_loop *loop, void *arg)
{
    job *j = arg;
    npf_t *n = j->n;
    int skip;
    (void)loop;
    LOCK();
    skip = j->cancelled;
    UNLOCK();
    if (skip) {
        free(j);
        return;
    }
    if (!j->n->ended)
        j->rc = j->fn(j->n, j->arg);
    else
        j->cancelled = -1;                  /* tell the caller it did not run */
    LOCK();
    j->done = 1;
    WAKE();
    UNLOCK();
}

static void job_drop(void *arg)
{
    job *j = arg;
    npf_t *n = j->n;
    LOCK();
    if (j->cancelled > 0) {
        UNLOCK();
        free(j);
        return;
    }
    j->cancelled = -1;
    j->done = 1;
    WAKE();
    UNLOCK();
}

void npf_api_lock(npf_t *n)
{
    LOCK();
}

void npf_api_unlock(npf_t *n)
{
    UNLOCK();
}

/* Who executes a call. Running: the loop thread (others post to it). Not
 * running (before the start, after the end): the caller itself, one at a
 * time per instance; a call from inside one (a callback) goes on at once. */
enum { EXEC_POST, EXEC_HERE, EXEC_TURN };

static int exec_mode(npf_t *n)
{
    unsigned long me = self_tid();
    int r;
    LOCK();
    if (n->running) {
        r = n->loop_tid == me ? EXEC_HERE : EXEC_POST;
    } else if (n->exec_busy && n->exec_owner == me) {
        r = EXEC_HERE;
    } else {
        while (n->exec_busy && !n->running)
            WAIT();
        if (n->running) {
            r = n->loop_tid == me ? EXEC_HERE : EXEC_POST;
        } else {
            n->exec_busy = 1;
            n->exec_owner = me;
            r = EXEC_TURN;
        }
    }
    UNLOCK();
    return r;
}

static void turn_end(npf_t *n)
{
    LOCK();
    n->exec_busy = 0;
    n->exec_owner = 0;
    WAKE();
    UNLOCK();
}

int sync_call(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg)
{
    job *j;
    int r, mode = exec_mode(n);
    if (mode != EXEC_POST) {
        npf_log_ctx *prev;
        if (n->ended) {
            r = NPF_ESTATE;
        } else {
            prev = npf_log_ctx_swap(&n->logctx);    /* its lines go to this instance */
            r = fn(n, arg);
            npf_log_ctx_swap(prev);
        }
        if (mode == EXEC_TURN)
            turn_end(n);
        return r;
    }
    if (on_runtime) {
        npf_loge("a call from a shared runtime's thread for an instance on another thread: refused (NPF_ESTATE)");
        return NPF_ESTATE;
    }
    if (!(j = calloc(1, sizeof *j)))
        return NPF_ENOMEM;
    j->n = n;
    j->fn = fn;
    j->arg = arg;
    if (npf_loop_post_drop(n->loop, job_run, job_drop, j) < 0) {
        free(j);
        return NPF_ENOMEM;
    }
    LOCK();
    while (!j->done && n->running)
        WAIT();
    if (!j->done) {                         /* the loop is gone and will not run it */
        j->cancelled = 1;
        UNLOCK();
        return NPF_ESTATE;
    }
    r = j->cancelled < 0 ? NPF_ESTATE : j->rc;
    UNLOCK();
    free(j);
    return r;
}

int npf_api_op(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = sync_call(n, fn, arg);
    api_leave(n);
    return r;
}

static void loop_main(npf_t *n)
{
    npf_log_ctx *prev = npf_log_ctx_swap(&n->logctx);
    LOCK();
    n->loop_tid = self_tid();
    UNLOCK();
    npf_engine_run(n);
    npf_scratch_trim();                     /* this thread's (sys.h) */
    LOCK();
    n->running = 0;
    n->loop_tid = 0;
    WAKE();
    UNLOCK();
    npf_log_ctx_swap(prev);
}

#ifdef _WIN32
static DWORD WINAPI thread_main(LPVOID arg)
{
    loop_main(arg);
    return 0;
}
#else
static void *thread_main(void *arg)
{
    loop_main(arg);
    return NULL;
}
#endif

/* started and running, once, after the calls in progress, on the loop
 * thread tid (0: npf_start's own, which sets it) */
static int begin_run(npf_t *n, unsigned long tid)
{
    LOCK();
    while (n->exec_busy && n->exec_owner != self_tid())
        WAIT();
    if (n->started || n->stopping || n->exec_busy) {
        UNLOCK();
        return NPF_ESTATE;
    }
    n->started = 1;
    n->running = 1;                         /* calls from now on go through the loop */
    n->loop_tid = tid;
    UNLOCK();
    return NPF_OK;
}

/* ---- a shared runtime (npf.h): threads, each running a host loop with the
 * instances' loops as its children; an instance stays on one ---- */

typedef struct rt_thread {
    npf_loop *host;
    void     *th;
    unsigned long tid;                  /* set before up */
    int       up;                       /* atomic: the thread runs, tid is set */
    int       count;                    /* instances created on it, not destroyed yet */
} rt_thread;

struct npf_runtime {
    int        nthreads;
    rt_thread *t;
    npf_mutex  mu;
};

#define RT_LOCK(rt)   npf_mutex_lock(&(rt)->mu)
#define RT_UNLOCK(rt) npf_mutex_unlock(&(rt)->mu)

static void rt_main(rt_thread *t)
{
    on_runtime = 1;
    t->tid = self_tid();
    npf_atomic_set(&t->up, 1);
    npf_loop_run(t->host);
    npf_scratch_trim();                     /* this thread's (sys.h) */
}

#ifdef _WIN32
static DWORD WINAPI rt_thread_main(LPVOID arg)
{
    rt_main(arg);
    return 0;
}
#else
static void *rt_thread_main(void *arg)
{
    rt_main(arg);
    return NULL;
}
#endif

static void *thread_new(int rt, void *arg);
static void thread_join(void *th);

static int cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long c = sysconf(_SC_NPROCESSORS_ONLN);
    return c > 0 ? (int)c : 1;
#endif
}

npf_runtime *npf_runtime_new(int threads)
{
    npf_runtime *rt = calloc(1, sizeof *rt);
    int i;
    if (!rt)
        return NULL;
    rt->nthreads = threads > 0 ? threads : cpu_count();
    if (!(rt->t = calloc((size_t)rt->nthreads, sizeof *rt->t))) {
        free(rt);
        return NULL;
    }
    if (npf_mutex_init(&rt->mu)) {
        free(rt->t);
        free(rt);
        return NULL;
    }
    for (i = 0; i < rt->nthreads; i++) {
        rt_thread *t = &rt->t[i];
        if (!(t->host = npf_loop_new()) || !(t->th = thread_new(1, t))) {
            npf_loop_free(t->host);
            t->host = NULL;
            rt->nthreads = i;
            npf_runtime_free(rt);
            return NULL;
        }
    }
    for (i = 0; i < rt->nthreads; i++)      /* the threads' ids: their instances' calls run there directly */
        while (!npf_atomic_get(&rt->t[i].up))
            npf_sleep_ms(1);
    return rt;
}

int npf_runtime_free(npf_runtime *rt)
{
    int i, busy = 0;
    if (!rt)
        return NPF_OK;
    RT_LOCK(rt);
    for (i = 0; i < rt->nthreads; i++)
        busy += rt->t[i].count;
    RT_UNLOCK(rt);
    if (busy)
        return NPF_ESTATE;
    for (i = 0; i < rt->nthreads; i++) {
        npf_loop_stop(rt->t[i].host);
        thread_join(rt->t[i].th);
        npf_loop_free(rt->t[i].host);
    }
    npf_mutex_free(&rt->mu);
    free(rt->t);
    free(rt);
    return NPF_OK;
}

/* npf_create: a loop on the thread with the fewest instances */
npf_loop *npf_runtime_child(npf_runtime *rt, int *slot)
{
    npf_loop *l;
    int i, best = 0;
    RT_LOCK(rt);
    for (i = 1; i < rt->nthreads; i++)
        if (rt->t[i].count < rt->t[best].count)
            best = i;
    l = npf_loop_new_child(rt->t[best].host);
    if (l)
        rt->t[best].count++;
    RT_UNLOCK(rt);
    *slot = best;
    return l;
}

void npf_runtime_leave(npf_runtime *rt, int slot)
{
    RT_LOCK(rt);
    rt->t[slot].count--;
    RT_UNLOCK(rt);
}

static void rt_start(npf_loop *loop, void *arg)
{
    npf_t *n = arg;
    (void)loop;
    npf_engine_begin(n);
}

static int rt_end(npf_loop *loop, void *arg)
{
    (void)loop;
    return npf_engine_end_step(arg);
}

static void rt_done(npf_loop *loop, void *arg)
{
    npf_t *n = arg;
    (void)loop;
    LOCK();
    n->running = 0;
    n->loop_tid = 0;
    WAKE();
    UNLOCK();                               /* n may be gone from here on */
}

static const npf_child_fns rt_fns = {rt_start, rt_end, rt_done};

static int start_on_runtime(npf_t *n)
{
    if (begin_run(n, n->rt->t[n->rt_slot].tid) != NPF_OK)
        return NPF_ESTATE;
    if (npf_loop_attach(n->loop, &rt_fns, n) < 0) {
        LOCK();
        n->running = 0;
        n->started = 0;
        n->loop_tid = 0;
        WAKE();
        UNLOCK();
        return NPF_ENOMEM;
    }
    return NPF_OK;
}

/* a library thread: an instance's own (rt 0) or a runtime's */
static void *thread_new(int rt, void *arg)
{
#ifdef _WIN32
    return CreateThread(NULL, 0, rt ? rt_thread_main : thread_main, arg, 0, NULL);
#else
    pthread_t *t = malloc(sizeof *t);
    pthread_attr_t a;
    /* an explicit stack: musl's default is 128 KB, and a frame of the
     * loop's deepest path (AnLiu input, the tunnel, a control reply) takes
     * more than half of that; only what is used becomes memory */
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, 1 << 20);
    if (t && pthread_create(t, &a, rt ? rt_thread_main : thread_main, arg) != 0) {
        free(t);
        t = NULL;
    }
    pthread_attr_destroy(&a);
    return t;
#endif
}

static void thread_join(void *th)
{
#ifdef _WIN32
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
#else
    pthread_join(*(pthread_t *)th, NULL);
    free(th);
#endif
}

static int start_run(npf_t *n)
{
    void *th = NULL;
    if (n->rt)
        return start_on_runtime(n);
    if (begin_run(n, 0) != NPF_OK)
        return NPF_ESTATE;
    th = thread_new(0, n);
    LOCK();
    n->thread = th;
    if (!th) {
        n->running = 0;
        n->started = 0;
        WAKE();
    }
    UNLOCK();
    return th ? NPF_OK : NPF_EFAIL;
}

static int run_run(npf_t *n)
{
    if (n->rt || begin_run(n, self_tid()) != NPF_OK)
        return NPF_ESTATE;
    loop_main(n);
    return NPF_OK;
}

static int stop_run(npf_t *n)
{
    LOCK();
    n->stopping = 1;
    /* Atomic stop + wake: no allocation and no lost stop under memory pressure. */
    npf_loop_stop(n->loop);
    UNLOCK();
    return NPF_OK;
}

void npf_destroy(npf_t *n)
{
    void *th;
    if (!n)
        return;
    LOCK();
    if (on_runtime || (n->running && n->loop_tid == self_tid()) || (n->exec_busy && n->exec_owner == self_tid())) {
        UNLOCK();
        npf_loge("npf_destroy from a callback (of this instance, or on a shared runtime): refused");
        return;
    }
    n->sync->destroying = 1;
    n->stopping = 1;
    npf_loop_stop(n->loop);
    while (npf_atomic_get(&n->sync->calls) || n->running || n->exec_busy)
        WAIT();
    th = n->thread;
    n->thread = NULL;
    UNLOCK();
    if (th)
        thread_join(th);
    npf_engine_free(n);
}

void npf_free(void *p)
{
    free(p);
}

int npf_start(npf_t *n) { return guarded(n, start_run); }
int npf_run(npf_t *n) { return guarded(n, run_run); }
void npf_stop(npf_t *n) { guarded(n, stop_run); }

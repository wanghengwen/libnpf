/* libnpf: the public functions of npf.h. Each one runs on the library thread:
 * at once when called there (callbacks) or before npf_start / npf_run;
 * otherwise posted to the loop while the caller waits for the result
 * (npf_media_send only queues a copy). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "npf/platform.h"
#include "npf_int.h"
#include "npf/module.h"

/* ---- threads ---- */

struct npf_api_sync {
#ifdef _WIN32
    CRITICAL_SECTION mu;
    CONDITION_VARIABLE cv;
#else
    pthread_mutex_t mu;
    pthread_cond_t cv;
#endif
    unsigned calls;
    int destroying;
};

#ifdef _WIN32
#define LOCK()   EnterCriticalSection(&n->sync->mu)
#define UNLOCK() LeaveCriticalSection(&n->sync->mu)
#define WAIT()   SleepConditionVariableCS(&n->sync->cv, &n->sync->mu, INFINITE)
#define WAKE()   WakeAllConditionVariable(&n->sync->cv)
static unsigned long self_tid(void) { return (unsigned long)GetCurrentThreadId(); }
#else
#define LOCK()   pthread_mutex_lock(&n->sync->mu)
#define UNLOCK() pthread_mutex_unlock(&n->sync->mu)
#define WAIT()   pthread_cond_wait(&n->sync->cv, &n->sync->mu)
#define WAKE()   pthread_cond_broadcast(&n->sync->cv)
static unsigned long self_tid(void) { return (unsigned long)pthread_self(); }
#endif

int npf_api_init(npf_t *n)
{
    n->sync = calloc(1, sizeof *n->sync);
    if (!n->sync)
        return -1;
#ifdef _WIN32
    InitializeCriticalSection(&n->sync->mu);
    InitializeConditionVariable(&n->sync->cv);
#else
    if (pthread_mutex_init(&n->sync->mu, NULL)) {
        free(n->sync);
        return -1;
    }
    if (pthread_cond_init(&n->sync->cv, NULL)) {
        pthread_mutex_destroy(&n->sync->mu);
        free(n->sync);
        return -1;
    }
#endif
    return 0;
}

void npf_api_fini(npf_t *n)
{
#ifdef _WIN32
    DeleteCriticalSection(&n->sync->mu);
#else
    pthread_cond_destroy(&n->sync->cv);
    pthread_mutex_destroy(&n->sync->mu);
#endif
    free(n->sync);
}

/* Public entry points hold a reference through preparation, posting and
 * completion. The owner prevents new calls from starting once destroy begins. */
static int api_enter(npf_t *n)
{
    int ok;
    if (!n)
        return 0;
    __atomic_add_fetch(&n->sync->calls, 1, __ATOMIC_SEQ_CST);
    LOCK();
    ok = !n->sync->destroying;
    if (!ok) {
        __atomic_sub_fetch(&n->sync->calls, 1, __ATOMIC_SEQ_CST);
        WAKE();
    }
    UNLOCK();
    return ok;
}

static void api_leave(npf_t *n)
{
    LOCK();
    __atomic_sub_fetch(&n->sync->calls, 1, __ATOMIC_SEQ_CST);
    WAKE();
    UNLOCK();
}

/* a call posted to the loop; the caller waits for it. It is on the heap: a
 * caller that gives up (the run ended first) leaves it to the loop. */
typedef struct job {
    npf_t *n;
    void (*fn)(npf_t *n, void *arg);
    void  *arg;
    int    done, cancelled;
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
        j->fn(j->n, j->arg);
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

/* run fn for the instance and wait for it: 0, or NPF_ESTATE when it did not
 * run (the run has ended) */
static int sync_call(npf_t *n, void (*fn)(npf_t *n, void *arg), void *arg)
{
    job *j;
    int r, mode = exec_mode(n);
    if (mode != EXEC_POST) {
        npf_log_ctx *prev;
        if (n->ended) {
            r = NPF_ESTATE;
        } else {
            prev = npf_log_ctx_swap(&n->logctx);    /* its lines go to this instance */
            fn(n, arg);
            npf_log_ctx_swap(prev);
            r = 0;
        }
        if (mode == EXEC_TURN)
            turn_end(n);
        return r;
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
    r = j->cancelled < 0 ? NPF_ESTATE : 0;
    UNLOCK();
    free(j);
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

/* started and running, once, after the calls in progress; the caller's
 * thread is the loop's when it runs it (npf_run) */
static int begin_run(npf_t *n, int here)
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
    n->loop_tid = here ? self_tid() : 0;    /* npf_start: the thread sets it */
    UNLOCK();
    return NPF_OK;
}

/* ---- a shared runtime (npf.h): threads, each running a host loop with the
 * instances' loops as its children; an instance stays on one ---- */

typedef struct rt_thread {
    npf_loop *host;
    void     *th;
    unsigned long tid;
    int       count;                    /* instances created on it, not destroyed yet */
} rt_thread;

struct npf_runtime {
    int        nthreads;
    rt_thread *t;
#ifdef _WIN32
    CRITICAL_SECTION mu;
#else
    pthread_mutex_t mu;
#endif
};

#ifdef _WIN32
#define RT_LOCK(rt)   EnterCriticalSection(&(rt)->mu)
#define RT_UNLOCK(rt) LeaveCriticalSection(&(rt)->mu)
#else
#define RT_LOCK(rt)   pthread_mutex_lock(&(rt)->mu)
#define RT_UNLOCK(rt) pthread_mutex_unlock(&(rt)->mu)
#endif

static void rt_main(rt_thread *t)
{
    __atomic_store_n(&t->tid, self_tid(), __ATOMIC_RELEASE);
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
#ifdef _WIN32
    InitializeCriticalSection(&rt->mu);
#else
    pthread_mutex_init(&rt->mu, NULL);
#endif
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
        while (!__atomic_load_n(&rt->t[i].tid, __ATOMIC_ACQUIRE))
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
#ifdef _WIN32
    DeleteCriticalSection(&rt->mu);
#else
    pthread_mutex_destroy(&rt->mu);
#endif
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
    if (begin_run(n, 0) != NPF_OK)
        return NPF_ESTATE;
    LOCK();
    n->loop_tid = n->rt->t[n->rt_slot].tid;
    UNLOCK();
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

static int npf_start_impl(npf_t *n)
{
    void *th = NULL;
    if (n && n->rt)
        return start_on_runtime(n);
    if (!n || begin_run(n, 0) != NPF_OK)
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

static int npf_run_impl(npf_t *n)
{
    if (!n || n->rt || begin_run(n, 1) != NPF_OK)
        return NPF_ESTATE;
    loop_main(n);
    return NPF_OK;
}

static void stop_impl(npf_t *n)
{
    LOCK();
    n->stopping = 1;
    /* Atomic stop + wake: no allocation and no lost stop under memory pressure. */
    npf_loop_stop(n->loop);
    UNLOCK();
}

void npf_destroy(npf_t *n)
{
    void *th;
    if (!n)
        return;
    LOCK();
    if ((n->running && n->loop_tid == self_tid()) || (n->exec_busy && n->exec_owner == self_tid())) {
        UNLOCK();
        npf_loge("npf_destroy from a callback of the same instance: refused");
        return;
    }
    n->sync->destroying = 1;
    n->stopping = 1;
    npf_loop_stop(n->loop);
    while (__atomic_load_n(&n->sync->calls, __ATOMIC_SEQ_CST) || n->running || n->exec_busy)
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

/* ---- queries ---- */

typedef struct q_arg {
    int     what, max;
    npf_out o;
} q_arg;

static void q_run(npf_t *n, void *arg)
{
    q_arg *q = arg;
    if (q->what == 0) {
        npf_cmd_status_json(n, &q->o);
    } else if (q->what == 1) {
        npf_cmd_config_json(n, &q->o);
    } else if (q->what == 2) {
        char *buf = malloc((size_t)q->max + 1);
        if (buf) {
            size_t len = npf_log_recent(buf, (size_t)q->max + 1);
            npf_out_printf(&q->o, "{\"lines\":");
            npf_out_json_str(&q->o, buf, len);
            npf_out_printf(&q->o, "}\n");
            free(buf);
        }
    } else if (q->what == 3) {
        npf_cmd_sessions_json(n, &q->o);
    } else if (n->peers) {
        npf_peers_public_json(n->peers, q->what == 5, &q->o);
    } else {
        npf_out_printf(&q->o, "{\"open\":0,\"closing\":false,\"mappings\":[]}");
    }
}

static char *query(npf_t *n, int what, int max)
{
    q_arg q;
    memset(&q, 0, sizeof q);
    q.what = what;
    q.max = max > 0 ? max : 16384;
    if (!n)
        return NULL;
    if (sync_call(n, q_run, &q) < 0 || q.o.failed) {
        npf_out_free(&q.o);
        return NULL;
    }
    return q.o.p;                           /* npf_out text: malloc'd, freed by npf_free */
}

static char *npf_status_json_impl(npf_t *n) { return query(n, 0, 0); }
static char *npf_config_json_impl(npf_t *n) { return query(n, 1, 0); }
static char *npf_log_json_impl(npf_t *n, int max) { return query(n, 2, max); }
static char *npf_sessions_json_impl(npf_t *n) { return query(n, 3, 0); }
static char *npf_public_json_impl(npf_t *n, int close) { return query(n, close ? 5 : 4, 0); }

/* ---- settings, peers, forwards ---- */

typedef struct a_arg {
    int         what, flags, rc, live, code;     /* code: an NPF_E* answer of its own */
    const char *a, *b, *c, *d;
    int         argc;
    char      **argv;
    char        *out;
    size_t       cap;
    npf_out      o;
} a_arg;

static int split_words(char *line, char **argv, int max)
{
    int argc = 0;
    char *t, *save;
    for (t = strtok_r(line, " \t", &save); t && argc < max; t = strtok_r(NULL, " \t", &save))
        argv[argc++] = t;
    return argc;
}

static void a_run(npf_t *n, void *arg)
{
    a_arg *x = arg;
    switch (x->what) {
    case 0: {                               /* config_get */
        char buf[600];
        int l;
        if (!npf_conf_known(x->a) && !npf_mod_key_known(x->a)) {
            x->code = NPF_ENOENT;
            break;
        }
        l = snprintf(x->out, x->cap, "%s", npf_cmd_is_secret(x->a) ? "(hidden)" : npf_cmd_get(n, x->a, buf, sizeof buf));
        x->code = l < 0 || (size_t)l >= x->cap ? NPF_ETOOBIG : NPF_OK;
        break;
    }
    case 6:                                 /* peer_add_argv */
        x->rc = npf_cmd_peer_add(n, x->argc, x->argv, x->flags, &x->o);
        break;
    case 1:                                 /* config_set: 1 when it applies at the next start */
        x->rc = npf_cmd_set(n, x->a, x->b, x->flags, &x->o);
        if (x->rc == 0 && !npf_cmd_is_settable(x->a))
            x->live = 1;
        break;
    case 2: {                               /* peer_add */
        char line[1024], *argv[64];
        int argc;
        snprintf(line, sizeof line, "%s", x->a);
        argc = split_words(line, argv, 64);
        x->rc = npf_cmd_peer_add(n, argc, argv, x->flags, &x->o);
        break;
    }
    case 3:                                 /* peer_remove */
        x->rc = npf_cmd_peer_remove(n, x->a, x->flags, &x->o);
        break;
    default: {                              /* forward add / del */
        char *argv[5] = {(char *)x->a, x->what == 4 ? "add" : "del", (char *)x->b, (char *)x->c, "--save"};
        x->rc = npf_cmd_forward(n, x->what == 4 && x->flags ? 5 : 4, argv, &x->o);
        break;
    }
    }
}

static int action(npf_t *n, a_arg *x, char *err, size_t errcap)
{
    if (!n)
        return NPF_EINVAL;
    if (sync_call(n, a_run, x) < 0)
        return NPF_ESTATE;
    if (x->o.failed) {
        npf_out_free(&x->o);
        return NPF_ENOMEM;
    }
    if (x->code)
        return x->code;
    if (x->rc && err && errcap)
        snprintf(err, errcap, "%s", x->o.p ? x->o.p : "failed");
    npf_out_free(&x->o);
    return x->rc == 0 ? x->live : x->rc == 2 ? NPF_EINVAL : NPF_EFAIL;
}

static int npf_config_get_impl(npf_t *n, const char *key, char *out, size_t cap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!key || !out || !cap)
        return NPF_EINVAL;
    x.what = 0;
    x.a = key;
    x.out = out;
    x.cap = cap;
    return action(n, &x, NULL, 0);
}

static int npf_config_set_impl(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!key || !value)
        return NPF_EINVAL;
    x.what = 1;
    x.a = key;
    x.b = value;
    x.flags = save;
    return action(n, &x, err, errcap);
}

static int npf_peer_add_argv_impl(npf_t *n, int argc, const char *const *argv, int flags, char *err, size_t errcap)
{
    a_arg x;
    char **w;
    int i, r = NPF_ENOMEM;
    if (argc < 1 || argc > 256 || !argv)
        return NPF_EINVAL;
    if (!(w = calloc((size_t)argc + 1, sizeof *w)))
        return NPF_ENOMEM;
    for (i = 0; i < argc; i++)
        if (!argv[i] || !(w[i] = strdup(argv[i])))
            break;
    if (i == argc) {
        char **work = malloc(((size_t)argc + 1) * sizeof *work);    /* the command may rearrange it */
        if (work) {
            memcpy(work, w, ((size_t)argc + 1) * sizeof *work);
            memset(&x, 0, sizeof x);
            x.what = 6;
            x.argc = argc;
            x.argv = work;
            x.flags = flags;
            r = action(n, &x, err, errcap);
            free(work);
        }
    } else if (!argv[i]) {
        r = NPF_EINVAL;
    }
    for (i = 0; i < argc; i++) {
        if (w[i])
            npf_wipe(w[i], strlen(w[i]));   /* a password */
        free(w[i]);
    }
    free(w);
    return r;
}

static int npf_peer_add_impl(npf_t *n, const char *spec, int flags, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!spec)
        return NPF_EINVAL;
    x.what = 2;
    x.a = spec;
    x.flags = flags;
    return action(n, &x, err, errcap);
}

static int npf_peer_remove_impl(npf_t *n, const char *name, int unsave, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!name)
        return NPF_EINVAL;
    x.what = 3;
    x.a = name;
    x.flags = unsave;
    return action(n, &x, err, errcap);
}

static int npf_forward_add_impl(npf_t *n, const char *peer, const char *opt, const char *spec, int save, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!peer || !opt || !spec)
        return NPF_EINVAL;
    x.what = 4;
    x.a = peer;
    x.b = opt;
    x.c = spec;
    x.flags = save;
    return action(n, &x, err, errcap);
}

static int npf_forward_del_impl(npf_t *n, const char *peer, const char *opt, const char *spec, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!peer || !opt || !spec)
        return NPF_EINVAL;
    x.what = 5;
    x.a = peer;
    x.b = opt;
    x.c = spec;
    return action(n, &x, err, errcap);
}

/* ---- commands and platform requests ---- */

typedef struct c_arg {
    int          argc;
    char       **argv;
    npf_text_cb  cb;
    void        *user;
    int          rc;
} c_arg;

static void c_run(npf_t *n, void *arg)
{
    c_arg *x = arg;
    npf_out o = {0};
    int r = npf_cmd_run(n, x->argc, x->argv, &o, x->cb, x->user);
    if (r >= 0 && x->cb)
        x->cb(x->user, o.failed ? 1 : r, o.failed ? "no memory" : o.p ? o.p : "");
    npf_out_free(&o);
    x->rc = NPF_OK;
}

static int npf_command_impl(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user)
{
    c_arg x;
    char **own, **work;
    int i, ok = 1;
    if (!n || argc < 1 || !argv)
        return NPF_EINVAL;
    /* own: the copies, freed here; work: what the command gets, which it may
     * rearrange (connect drops its options in place) */
    own = calloc((size_t)argc + 1, sizeof *own);
    work = calloc((size_t)argc + 1, sizeof *work);
    for (i = 0; own && work && i < argc; i++)
        if (!(own[i] = strdup(argv[i] ? argv[i] : "")))
            break;
    if (!own || !work || i < argc) {
        ok = 0;
    } else {
        memcpy(work, own, (size_t)argc * sizeof *work);
        x.argc = argc;
        x.argv = work;
        x.cb = cb;
        x.user = user;
        x.rc = NPF_EFAIL;
        if (sync_call(n, c_run, &x) < 0)
            x.rc = NPF_ESTATE;
    }
    for (i = 0; own && i < argc; i++) {
        if (own[i])
            npf_wipe(own[i], strlen(own[i]));      /* passwords */
        free(own[i]);
    }
    free(own);
    free(work);
    return ok ? x.rc : NPF_ENOMEM;
}

typedef struct r_arg {
    const char  *type, *data;
    int          proof, rc;
    npf_reply_cb cb;
    void        *user;
    npf_out      err;
} r_arg;

static void r_run(npf_t *n, void *arg)
{
    r_arg *x = arg;
    x->rc = npf_plat_request(n, x->type, x->data, x->proof, x->cb, x->user, &x->err);
}

static int npf_request_impl(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb, void *user)
{
    r_arg x;
    if (!n || !type)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.type = type;
    x.data = data_json;
    x.proof = key_proof;
    x.cb = cb;
    x.user = user;
    if (sync_call(n, r_run, &x) < 0)
        x.rc = NPF_ESTATE;
    if (x.rc != NPF_OK && x.err.p)
        npf_log("npf_request %s: %s", type, x.err.p);
    npf_out_free(&x.err);
    return x.rc;
}

/* ---- sessions: application data and media ---- */

typedef struct s_arg {
    uint32_t    id;
    const void *buf;
    size_t      len;
    int         rc, flags;
    const npf_media_opt *mo;
    npf_media_stats *st;
} s_arg;

static void send_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_call *call = npf_session_call(n, x->id);
    if (!call) {
        x->rc = NPF_ENOENT;
        return;
    }
    x->rc = npf_call_app_send(call, x->buf, x->len) == 0 ? NPF_OK : NPF_ESTATE;
}

static int npf_session_send_impl(npf_t *n, uint32_t session, const void *buf, size_t len)
{
    s_arg x;
    if (!n || (!buf && len))
        return NPF_EINVAL;
    if (len > 16384)
        return NPF_ETOOBIG;
    memset(&x, 0, sizeof x);
    x.id = session;
    x.buf = buf;
    x.len = len;
    if (sync_call(n, send_run, &x) < 0)
        return NPF_ESTATE;
    return x.rc;
}

void npf_media_opt_default(npf_media_opt *o)
{
    memset(o, 0, sizeof *o);
    o->size = sizeof *o;
    o->prio = 1;
    o->max_age_ms = 500;
    o->fec = -1;
    o->rcv_deadline_ms = -1;
}

typedef struct m_open {
    uint32_t session, media;
    const npf_media_opt *o;
    int err;
} m_open;

static void open_run(npf_t *n, void *arg)
{
    m_open *x = arg;
    npf_call *call = npf_session_call(n, x->session);
    npf_call_media_opt co;
    uint32_t lid;
    int e = 0;
    if (!call) {
        x->err = NPF_ENOENT;
        return;
    }
    if (n->nmed >= NPF_MAX_MEDIA) {
        x->err = NPF_EBUSY;
        return;
    }
    co.tag = x->o->tag;
    co.prio = x->o->prio < 0 || x->o->prio > 3 ? 1 : x->o->prio;
    co.max_age_ms = x->o->max_age_ms;
    co.drop_until_key = x->o->drop_until_key;
    co.fec = x->o->fec;
    co.fec_ratio = x->o->fec_ratio;
    co.latency_rtt = x->o->latency_rtt;
    co.rcv_deadline_ms = x->o->rcv_deadline_ms;
    co.rcv_drop_until_key = x->o->rcv_drop_until_key;
    if (!(lid = npf_call_media_open(call, &co, &e))) {
        x->err = e ? e : NPF_ESTATE;
        return;
    }
    if (!(x->media = npf_media_add(n, x->session, call, lid))) {
        npf_call_media_close(call, lid);
        x->err = NPF_ENOMEM;
    }
}

static uint32_t npf_media_open_impl(npf_t *n, uint32_t session, const npf_media_opt *o, int *err)
{
    m_open x;
    npf_media_opt opt;
    int e;
    if (!err)
        err = &e;
    npf_media_opt_default(&opt);
    if (o) {                                /* what the application's build has, defaults for the rest */
        if (o->size < offsetof(npf_media_opt, rcv_drop_until_key) + sizeof o->rcv_drop_until_key) {
            *err = NPF_EINVAL;
            return 0;
        }
        memcpy(&opt, o, o->size < sizeof opt ? o->size : sizeof opt);
        opt.size = sizeof opt;
    }
    o = &opt;
    if (!n) {
        *err = NPF_EINVAL;
        return 0;
    }
    if (o->tag < 0 || o->tag > 999) {
        *err = NPF_EINVAL;
        return 0;
    }
    memset(&x, 0, sizeof x);
    x.session = session;
    x.o = o;
    if (sync_call(n, open_run, &x) < 0)
        x.err = NPF_ESTATE;
    *err = x.media ? NPF_OK : x.err;
    return x.media;
}

typedef struct m_frame {
    npf_t   *n;
    uint32_t media;
    int      flags;
    int64_t  t;                     /* npf_media_send: max_age counts from here */
    size_t   len;
    uint8_t  data[];
} m_frame;

static int frame_send(npf_t *n, uint32_t media, int flags, const void *d, size_t len, int64_t t)
{
    npf_med *m = n->ended ? NULL : npf_media_find(n, media);
    if (!m)
        return n->ended ? NPF_ESTATE : NPF_ENOENT;
    return npf_call_media_send(m->call, m->lid, flags & NPF_FRAME_KEY, d, len, t);
}

static void frame_run(npf_loop *loop, void *arg)
{
    m_frame *f = arg;
    npf_t *n = f->n;
    (void)loop;
    LOCK();
    f->n->send_queued -= f->len;
    f->n->send_jobs--;
    UNLOCK();
    frame_send(f->n, f->media, f->flags, f->data, f->len, f->t);
    free(f);
}

static void frame_drop(void *arg)
{
    m_frame *f = arg;
    npf_t *n = f->n;
    LOCK();
    f->n->send_queued -= f->len;
    f->n->send_jobs--;
    UNLOCK();
    free(f);
}

/* Frames from other threads wait for the library's thread with a budget:
 * over NPF_MEDIA_SEND_QUEUE bytes the send is refused (NPF_EBUSY) and the
 * application decides (skip to the next key frame, lower the rate). The
 * number is checked on every thread alike; what goes wrong later (the
 * stream ended meanwhile) only drops the frame. */
static int npf_media_send_impl(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    m_frame *f;
    npf_med *m;
    int here, rc = NPF_OK;
    int64_t t = npf_mono_ms();
    if (!n || !frame || !len)
        return NPF_EINVAL;
    if (len > NPF_MEDIA_FRAME_MAX)
        return NPF_ETOOBIG;
    LOCK();
    here = !n->running || n->loop_tid == self_tid();
    if (n->ended)
        rc = NPF_ESTATE;
    else if (!(m = npf_media_find(n, media)))
        rc = NPF_ENOENT;
    else if (len > m->frame_max)
        rc = NPF_ETOOBIG;
    else if (!here && (n->send_queued + len > NPF_MEDIA_SEND_QUEUE || n->send_jobs >= 4096))
        rc = NPF_EBUSY;
    else if (!here) {
        n->send_queued += len;
        n->send_jobs++;
    }
    UNLOCK();
    if (rc != NPF_OK)
        return rc;
    if (here) {                             /* a callback (or not running): at once, no copy */
        rc = exec_mode(n);
        if (rc == EXEC_POST)                /* it started meanwhile */
            return NPF_EBUSY;
        {
            npf_log_ctx *prev = npf_log_ctx_swap(&n->logctx);
            int r = frame_send(n, media, flags, frame, len, t);
            npf_log_ctx_swap(prev);
            if (rc == EXEC_TURN)
                turn_end(n);
            return r;
        }
    }
    if (!(f = malloc(sizeof *f + len))) {
        LOCK();
        n->send_queued -= len;
        n->send_jobs--;
        UNLOCK();
        return NPF_ENOMEM;
    }
    f->n = n;
    f->media = media;
    f->flags = flags;
    f->t = t;
    f->len = len;
    memcpy(f->data, frame, len);
    if (npf_loop_post_drop(n->loop, frame_run, frame_drop, f) < 0) {
        frame_drop(f);
        return NPF_ENOMEM;
    }
    return NPF_OK;
}

static void stats_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    npf_call_media_stats cs;
    if (!m) {
        x->rc = NPF_ENOENT;
        return;
    }
    if ((x->rc = npf_call_media_get_stats(m->call, m->lid, &cs)) < 0)
        return;
    x->st->target_rate = cs.target_rate;
    x->st->srtt_ms = cs.srtt_ms;
    x->st->min_rtt_ms = cs.min_rtt_ms;
    x->st->frames_dropped = cs.frames_dropped;
    x->st->frames_skipped = cs.frames_skipped;
    x->st->fec_recovered = cs.fec_recovered;
    x->st->peer_frame_delay_avg_ms = cs.peer_frame_delay_avg_ms;
    x->st->peer_frame_delay_max_ms = cs.peer_frame_delay_max_ms;
    x->st->peer_jitter_ms = cs.peer_jitter_ms;
    x->st->capacity_short = cs.capacity_short;
    x->rc = NPF_OK;
}

static int npf_media_stats_get_impl(npf_t *n, uint32_t media, npf_media_stats *out)
{
    s_arg x;
    npf_media_stats st;
    size_t size;
    if (!n || !out || out->size < offsetof(npf_media_stats, capacity_short) + sizeof out->capacity_short)
        return NPF_EINVAL;                  /* the caller sets out->size */
    size = out->size < sizeof st ? out->size : sizeof st;
    memset(&x, 0, sizeof x);
    memset(&st, 0, sizeof st);
    x.id = media;
    x.st = &st;
    if (sync_call(n, stats_run, &x) < 0)
        return NPF_ESTATE;
    st.size = size;
    memcpy(out, &st, size);
    return x.rc;
}

static void close_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    if (!m) {
        x->rc = NPF_ENOENT;
        return;
    }
    x->rc = npf_call_media_close(m->call, m->lid);
    if (x->rc == NPF_OK)
        npf_media_forget(n, x->id);
}

static int npf_media_close_impl(npf_t *n, uint32_t media)
{
    s_arg x;
    if (!n)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.id = media;
    if (sync_call(n, close_run, &x) < 0)
        return NPF_ESTATE;
    return x.rc;
}

/* ---- public entry points: lifetime guards ---- */

int npf_start(npf_t *n)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_start_impl(n);
    api_leave(n);
    return r;
}

int npf_run(npf_t *n)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_run_impl(n);
    api_leave(n);
    return r;
}

char *npf_status_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_status_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_config_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_config_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_log_json(npf_t *n, int max)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_log_json_impl(n, max);
    api_leave(n);
    return r;
}

char *npf_sessions_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_sessions_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_public_json(npf_t *n, int close)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_public_json_impl(n, close);
    api_leave(n);
    return r;
}

int npf_config_get(npf_t *n, const char *key, char *out, size_t cap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_config_get_impl(n, key, out, cap);
    api_leave(n);
    return r;
}

int npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_config_set_impl(n, key, value, save, err, errcap);
    api_leave(n);
    return r;
}

int npf_peer_add_argv(npf_t *n, int argc, const char *const *argv, int flags, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_peer_add_argv_impl(n, argc, argv, flags, err, errcap);
    api_leave(n);
    return r;
}

int npf_peer_add(npf_t *n, const char *spec, int flags, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_peer_add_impl(n, spec, flags, err, errcap);
    api_leave(n);
    return r;
}

int npf_peer_remove(npf_t *n, const char *name, int unsave, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_peer_remove_impl(n, name, unsave, err, errcap);
    api_leave(n);
    return r;
}

int npf_forward_add(npf_t *n, const char *peer, const char *opt, const char *spec, int save, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_forward_add_impl(n, peer, opt, spec, save, err, errcap);
    api_leave(n);
    return r;
}

int npf_forward_del(npf_t *n, const char *peer, const char *opt, const char *spec, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_forward_del_impl(n, peer, opt, spec, err, errcap);
    api_leave(n);
    return r;
}

int npf_command(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_command_impl(n, argc, argv, cb, user);
    api_leave(n);
    return r;
}

int npf_request(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb, void *user)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_request_impl(n, type, data_json, key_proof, cb, user);
    api_leave(n);
    return r;
}

int npf_session_send(npf_t *n, uint32_t session, const void *buf, size_t len)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_session_send_impl(n, session, buf, len);
    api_leave(n);
    return r;
}

uint32_t npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, int *err)
{
    uint32_t r;
    if (!api_enter(n)) { if (err) *err = NPF_ESTATE; return 0; }
    r = npf_media_open_impl(n, session, o, err);
    api_leave(n);
    return r;
}

int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_send_impl(n, media, flags, frame, len);
    api_leave(n);
    return r;
}

int npf_media_stats_get(npf_t *n, uint32_t media, npf_media_stats *out)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_stats_get_impl(n, media, out);
    api_leave(n);
    return r;
}

int npf_media_close(npf_t *n, uint32_t media)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_close_impl(n, media);
    api_leave(n);
    return r;
}

void npf_stop(npf_t *n)
{
    if (!api_enter(n))
        return;
    stop_impl(n);
    api_leave(n);
}

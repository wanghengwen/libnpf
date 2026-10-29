/* Event loop: epoll on Linux, kqueue on macOS, iOS and the BSDs, WSAPoll on
 * Windows; timers in a binary min-heap. A shared runtime's host loop runs
 * its children's sockets and timers with its own (in its one queue). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/loop.h"
#include "npf/out.h"
#include "npf/platform.h"
#include "npf/sys.h"

/* a callback that holds the loop SLOW_CB_MS or more is logged, with its
 * address and npf_loop_new's (the offset between them names it: nm, addr2line):
 * nothing else runs meanwhile, timers come late (a ping, a watch) */
#define SLOW_CB_MS 1000
#define TIMED(fnp, call) do {                                                                       \
        uintptr_t fn_ = (uintptr_t)(fnp);                                                          \
        int64_t t0_ = npf_mono_ms(), d_;                                                            \
        call;                                                                                       \
        if ((d_ = npf_mono_ms() - t0_) >= SLOW_CB_MS)                                               \
            npf_logw("loop: a callback held the loop %lld ms (%#lx; npf_loop_new %#lx)", (long long)d_, \
                     (unsigned long)fn_, (unsigned long)(uintptr_t)npf_loop_new);                   \
    } while (0)

#ifdef _WIN32
typedef CRITICAL_SECTION npf_mutex;
#define npf_mutex_init(m)   InitializeCriticalSection(m)
#define npf_mutex_free(m)   DeleteCriticalSection(m)
#define npf_mutex_lock(m)   EnterCriticalSection(m)
#define npf_mutex_unlock(m) LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t npf_mutex;
#define npf_mutex_init(m)   pthread_mutex_init((m), NULL)
#define npf_mutex_free(m)   pthread_mutex_destroy(m)
#define npf_mutex_lock(m)   pthread_mutex_lock(m)
#define npf_mutex_unlock(m) pthread_mutex_unlock(m)
#endif

/* The sockets: a queue (NPF_EVQ) everywhere but Windows, epoll on Linux
 * (2.6.27 and later: epoll_create1, eventfd flags), kqueue on macOS, iOS and
 * the BSDs: a wake-up costs what is ready, not what is watched (a node with a
 * thousand sublinks). WSAPoll on Windows, which has neither (IOCP is another
 * model). The wake: an eventfd on Linux, a loopback UDP socket elsewhere
 * (send: safe in a signal handler). */
#if defined(__linux__)
#define NPF_EVQ 1
#define NPF_EVQ_EPOLL 1
#define NPF_EVENTFD 1
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <mmsystem.h>
#else
#define NPF_EVQ 1
#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#endif

/* a socket in a runtime host's queue: the event's pointer; dead once
 * removed (an event of the same batch may still name it), freed after it */
typedef struct ep_reg {
    npf_loop *l;
    int       fd, dead;
    unsigned  kev;              /* kqueue: the filters registered (NPF_EV_READ / NPF_EV_WRITE) */
    struct ep_reg *next;
} ep_reg;

typedef struct handler {
    npf_io_fn fn;
    void     *arg;
    int       active;
    int       fd;
    unsigned  events;
    unsigned  gen;              /* its registration (npf_loop_add): a pfd entry taken from another is stale */
    ep_reg   *reg;              /* in the host's queue (NPF_EVQ) */
} handler;

struct npf_timer {
    int64_t    due;
    uint64_t   seq;             /* equal due: in the order added */
    npf_timer_fn fn;
    void      *arg;
    int        idx;             /* in the heap; -1 while firing */
};

typedef struct posted {
    void (*fn)(npf_loop *l, void *arg);
    void (*drop)(void *arg);        /* the loop is freed before fn ran: release arg */
    void *arg;
    struct posted *next;
} posted;

#define FREE_HOOKS 4

struct npf_loop {
    handler   *h;               /* the nh entries (idx: fd -> entry) */
    int        nh;
    size_t     cap;
    int        hfree;           /* no free entry in h below this one */
    npf_timer **heap;           /* timers: min-heap by (due, seq) */
    int        nheap;
    size_t     capheap;
    uint64_t   tseq;
    int64_t    now;
    volatile int stop;
    volatile int woken;
    void     (*wake_fn)(npf_loop *l, void *arg);
    void      *wake_arg;
    int        wake_fd;         /* Linux: eventfd; elsewhere: loopback UDP socket */
    npf_mutex  post_mu;         /* guards the posted list (other threads append) */
    posted    *post_head, *post_tail;
    struct { void (*fn)(npf_loop *l, void *arg); void *arg; } free_hook[FREE_HOOKS];
    int        nfree_hook;
    unsigned   gen;
    int       *idx;             /* fd -> index into h, plus one; open addressing */
    int        idx_cap;         /* power of two */
    int        idx_tomb;        /* deleted slots still occupying the table */
    /* a shared runtime (loop.h): the host's children, or a child's host */
    npf_loop **kids;
    int        nkids;
    size_t     capkids;
    npf_loop  *host;
    npf_child_fns cf;
    void      *carg;
    npf_log_ctx *logctx;
    int        ending;          /* child: stopped, end() steps under way */
    int64_t    end_due;
    int        attached;        /* child: run by the host now */
#ifdef NPF_EVQ
    int        epfd;            /* its queue: its sockets and its children's; -1: a child */
    ep_reg    *grave;           /* host: removed registrations, freed after the batch */
#else
    WSAPOLLFD *pfd;
    unsigned  *pgen;            /* pfd entry -> the registration it was taken from */
    int       *own;             /* pfd entry -> its loop's child (-1: the host's own) */
    size_t     npfd;            /* pfd, pgen and own have room for this many */
#endif
};

#ifdef NPF_EVQ
/* ---- the queue: epoll or kqueue behind one set of calls ---- */

static int evq_new(void)
{
#ifdef NPF_EVQ_EPOLL
    return epoll_create1(EPOLL_CLOEXEC);
#else
    int q = kqueue();
    if (q >= 0)
        fcntl(q, F_SETFD, FD_CLOEXEC);
    return q;
#endif
}

/* the wake descriptor in q: an event with no registration (NULL) */
static int evq_wake(int q, int fd)
{
#ifdef NPF_EVQ_EPOLL
    struct epoll_event e;
    memset(&e, 0, sizeof e);
    e.events = EPOLLIN;
    return epoll_ctl(q, EPOLL_CTL_ADD, fd, &e);
#else
    struct kevent k;
    EV_SET(&k, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    return kevent(q, &k, 1, NULL, 0, NULL);
#endif
}

/* r watched in q for want (NPF_EV_READ / NPF_EV_WRITE); add: new in q */
static int evq_set(int q, ep_reg *r, unsigned want, int add)
{
#ifdef NPF_EVQ_EPOLL
    struct epoll_event e;
    memset(&e, 0, sizeof e);
    e.events = ((want & NPF_EV_READ) ? EPOLLIN : 0) | ((want & NPF_EV_WRITE) ? EPOLLOUT : 0);
    e.data.ptr = r;
    return epoll_ctl(q, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, r->fd, &e);
#else
    /* a filter each way: what changed added or deleted */
    struct kevent k[2];
    int n = 0;
    (void)add;
    want &= NPF_EV_READ | NPF_EV_WRITE;
    if ((want ^ r->kev) & NPF_EV_READ)
        EV_SET(&k[n++], r->fd, EVFILT_READ, (want & NPF_EV_READ) ? EV_ADD : EV_DELETE, 0, 0, r);
    if ((want ^ r->kev) & NPF_EV_WRITE)
        EV_SET(&k[n++], r->fd, EVFILT_WRITE, (want & NPF_EV_WRITE) ? EV_ADD : EV_DELETE, 0, 0, r);
    if (n && kevent(q, k, n, NULL, 0, NULL) < 0)
        return -1;
    r->kev = want;
    return 0;
#endif
}

static void evq_remove(int q, ep_reg *r)
{
#ifdef NPF_EVQ_EPOLL
    epoll_ctl(q, EPOLL_CTL_DEL, r->fd, NULL);
#else
    (void)evq_set(q, r, 0, 0);          /* (a socket already closed left by itself) */
#endif
}

typedef struct evq_ev {
    ep_reg  *r;                         /* NULL: the wake */
    unsigned ev;                        /* NPF_EV_* */
} evq_ev;

#define EVQ_BATCH 256

/* the ready ones, at most EVQ_BATCH, waiting up to ms (-1: no limit) */
static int evq_wait(int q, evq_ev *out, int ms)
{
    int n, i;
#ifdef NPF_EVQ_EPOLL
    struct epoll_event ev[EVQ_BATCH];
    n = epoll_wait(q, ev, EVQ_BATCH, ms);
    for (i = 0; i < n; i++) {
        uint32_t x = ev[i].events;
        unsigned e = 0;
        if (x & (EPOLLIN | EPOLLHUP)) e |= NPF_EV_READ;
        if (x & EPOLLOUT) e |= NPF_EV_WRITE;
        if (x & EPOLLERR) e |= NPF_EV_ERROR | NPF_EV_READ;
        out[i].r = ev[i].data.ptr;
        out[i].ev = e;
    }
#else
    struct kevent ev[EVQ_BATCH];
    struct timespec ts, *tp = NULL;
    if (ms >= 0) {
        ts.tv_sec = ms / 1000;
        ts.tv_nsec = (long)(ms % 1000) * 1000000L;
        tp = &ts;
    }
    n = kevent(q, NULL, 0, ev, EVQ_BATCH, tp);
    for (i = 0; i < n; i++) {
        unsigned e = ev[i].filter == EVFILT_WRITE ? NPF_EV_WRITE : NPF_EV_READ;
        if (ev[i].flags & EV_EOF)
            e |= NPF_EV_READ;           /* as poll's POLLHUP: the read sees the end */
        if (ev[i].flags & EV_ERROR)
            e |= NPF_EV_ERROR | NPF_EV_READ;
        out[i].r = ev[i].udata;
        out[i].ev = e;
    }
#endif
    return n < 0 ? 0 : n;               /* EINTR: none this time */
}

/* the queue a loop's sockets go into: its own, or its host's while attached */
static int ep_fd(const npf_loop *l)
{
    if (l->host)
        return l->attached ? l->host->epfd : -1;
    return l->epfd;
}

/* -1: the queue does not take it (no memory, a descriptor it cannot watch) */
static int ep_add(npf_loop *l, handler *h)
{
    int ep = ep_fd(l);
    ep_reg *r;
    if (ep < 0 || h->reg)
        return 0;                       /* a child not attached: when it is */
    if (!(r = calloc(1, sizeof *r)))
        return -1;
    r->l = l;
    r->fd = h->fd;
    if (evq_set(ep, r, h->events, 1) < 0) {
        npf_loge("loop: descriptor %d not watched: %s", h->fd, strerror(errno));
        free(r);
        return -1;
    }
    h->reg = r;
    return 0;
}

static void ep_mod(npf_loop *l, handler *h)
{
    int ep = ep_fd(l);
    if (ep >= 0 && h->reg)
        (void)evq_set(ep, h->reg, h->events, 0);
}

static void ep_del(npf_loop *l, handler *h)
{
    npf_loop *host = l->host ? l->host : l;
    int ep = ep_fd(l);
    if (!h->reg)
        return;
    if (ep >= 0)
        evq_remove(ep, h->reg);
    h->reg->dead = 1;
    h->reg->next = host->grave;
    host->grave = h->reg;
    h->reg = NULL;
}

/* a child's sockets into its host's queue (attached) or out of it */
static void ep_all(npf_loop *l, int add)
{
    int i;
    for (i = 0; i < l->nh; i++)
        if (l->h[i].active) {
            if (add)
                (void)ep_add(l, &l->h[i]);
            else
                ep_del(l, &l->h[i]);
        }
}

static void free_grave(npf_loop *l)
{
    while (l->grave) {
        ep_reg *r = l->grave;
        l->grave = r->next;
        free(r);
    }
}
#else
#define ep_add(l, h) 0
#define ep_mod(l, h) ((void)0)
#define ep_del(l, h) ((void)0)
#define ep_all(l, add) ((void)0)
#define free_grave(l) ((void)0)
#endif

/* the log context a loop's work runs in: a runtime child's, its instance's
 * (npf_loop_set_logctx); a loop without one keeps the thread's (a
 * standalone instance's thread set it itself: its level, hook and ring).
 * Returns what to put back */
static npf_log_ctx *ctx_enter(const npf_loop *c)
{
    npf_log_ctx *prev = npf_log_ctx_swap(c->logctx);
    if (!c->logctx)
        npf_log_ctx_swap(prev);         /* none of its own: the thread's stays */
    return prev;
}

#define POSTED_BATCH 256            /* then sockets and timers get their turn */

static void run_posted(npf_loop *l)
{
    int done = 0;
    for (;;) {
        posted *p;
        if (done++ == POSTED_BATCH) {
            npf_mutex_lock(&l->post_mu);
            p = l->post_head;
            npf_mutex_unlock(&l->post_mu);
            if (p)
                npf_loop_wake(l);           /* the rest on the next round */
            return;
        }
        npf_mutex_lock(&l->post_mu);
        p = l->post_head;
        if (p) {
            l->post_head = p->next;
            if (!l->post_head)
                l->post_tail = NULL;
        }
        npf_mutex_unlock(&l->post_mu);
        if (!p)
            return;
        TIMED(p->fn, p->fn(l, p->arg));
        free(p);
    }
}

static void run_wake_hook(npf_loop *l)
{
    /* other threads and signal handlers set it: an atomic exchange */
    if (__atomic_exchange_n(&l->woken, 0, __ATOMIC_ACQ_REL)) {
        if (l->wake_fn)
            l->wake_fn(l, l->wake_arg);
    }
    run_posted(l);
}

int npf_loop_post(npf_loop *l, void (*fn)(npf_loop *l, void *arg), void *arg)
{
    return npf_loop_post_drop(l, fn, NULL, arg);
}

int npf_loop_post_drop(npf_loop *l, void (*fn)(npf_loop *l, void *arg), void (*drop)(void *arg), void *arg)
{
    posted *p = calloc(1, sizeof *p);
    if (!p)
        return -1;
    p->fn = fn;
    p->drop = drop;
    p->arg = arg;
    npf_mutex_lock(&l->post_mu);
    if (l->post_tail)
        l->post_tail->next = p;
    else
        l->post_head = p;
    l->post_tail = p;
    npf_mutex_unlock(&l->post_mu);
    npf_loop_wake(l);
    return 0;
}

static void free_posted(npf_loop *l)
{
    posted *p, *n;
    npf_mutex_lock(&l->post_mu);
    p = l->post_head;
    l->post_head = l->post_tail = NULL;
    npf_mutex_unlock(&l->post_mu);
    for (; p; p = n) {
        n = p->next;
        if (p->drop)
            p->drop(p->arg);
        free(p);
    }
}

int npf_loop_on_free(npf_loop *l, void (*fn)(npf_loop *l, void *arg), void *arg)
{
    if (l->nfree_hook >= FREE_HOOKS)
        return -1;
    l->free_hook[l->nfree_hook].fn = fn;
    l->free_hook[l->nfree_hook].arg = arg;
    l->nfree_hook++;
    return 0;
}

void npf_loop_on_wake(npf_loop *l, void (*fn)(npf_loop *l, void *arg), void *arg)
{
    l->wake_fn = fn;
    l->wake_arg = arg;
}

/* ---- timer heap: every session has several timers (AnLiu, keepalive,
 * standby ...) and the AnLiu one is rescheduled on each datagram ---- */

static int t_before(const npf_timer *a, const npf_timer *b)
{
    return a->due < b->due || (a->due == b->due && a->seq < b->seq);
}

static void heap_set(npf_loop *l, int i, npf_timer *t)
{
    l->heap[i] = t;
    t->idx = i;
}

static void heap_up(npf_loop *l, int i)
{
    npf_timer *t = l->heap[i];
    while (i > 0 && t_before(t, l->heap[(i - 1) / 2])) {
        heap_set(l, i, l->heap[(i - 1) / 2]);
        i = (i - 1) / 2;
    }
    heap_set(l, i, t);
}

static void heap_down(npf_loop *l, int i)
{
    npf_timer *t = l->heap[i];
    for (;;) {
        int c = 2 * i + 1;
        if (c >= l->nheap)
            break;
        if (c + 1 < l->nheap && t_before(l->heap[c + 1], l->heap[c]))
            c++;
        if (!t_before(l->heap[c], t))
            break;
        heap_set(l, i, l->heap[c]);
        i = c;
    }
    heap_set(l, i, t);
}

static void heap_remove(npf_loop *l, npf_timer *t)
{
    int i = t->idx;
    npf_timer *last = l->heap[--l->nheap];
    t->idx = -1;
    if (i == l->nheap)
        return;
    heap_set(l, i, last);
    heap_up(l, i);
    heap_down(l, last->idx);
}

static void fire_timers(npf_loop *l)
{
    /* a callback may add or cancel timers; one it adds (even due at once:
     * one that arms itself again with 0 ms) waits for the next turn, after
     * the sockets were looked at */
    uint64_t end = l->tseq;
    while (l->nheap > 0) {
        npf_timer *t = l->heap[0];
        if (t->due > npf_mono_ms() || t->seq >= end)
            break;
        heap_remove(l, t);
        TIMED(t->fn, t->fn(l, t->arg));
        free(t);
    }
}

/* the wait (ms, -1 none) shortened to what comes due at due (INT64_MAX: nothing) */
static int wait_until(int wait, int64_t due, int64_t now)
{
    int64_t d;
    if (due == INT64_MAX)
        return wait;
    d = due - now;
    if (d < 0)
        d = 0;
    if (d > INT_MAX)
        d = INT_MAX;
    return wait < 0 || d < wait ? (int)d : wait;
}

npf_loop *npf_loop_new(void)
{
    npf_loop *l;
    if (npf_sys_init() < 0)
        return NULL;
    l = calloc(1, sizeof *l);
    if (!l)
        return NULL;
#ifdef NPF_EVENTFD
    l->wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (l->wake_fd < 0) {
        free(l);
        return NULL;
    }
#else
    {
    struct sockaddr_in wa;
    socklen_t al = sizeof wa;
    l->wake_fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
    memset(&wa, 0, sizeof wa);
    wa.sin_family = AF_INET;
    wa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (l->wake_fd < 0 || bind(l->wake_fd, (struct sockaddr *)&wa, sizeof wa) < 0
        || getsockname(l->wake_fd, (struct sockaddr *)&wa, &al) < 0
        /* connected to itself: datagrams from other local processes are dropped */
        || connect(l->wake_fd, (struct sockaddr *)&wa, sizeof wa) < 0) {
        npf_sock_close(l->wake_fd);
        free(l);
        return NULL;
    }
    }
#endif
#ifdef NPF_EVQ
    if ((l->epfd = evq_new()) < 0 || evq_wake(l->epfd, l->wake_fd) < 0) {
        npf_loge("loop: no event queue: %s", strerror(errno));
        if (l->epfd >= 0)
            close(l->epfd);
        npf_sock_close(l->wake_fd);
        free(l);
        return NULL;
    }
#else
    timeBeginPeriod(1);             /* 1 ms timer resolution: AnLiu pacing and RTT */
#endif
    npf_mutex_init(&l->post_mu);
    l->now = npf_mono_ms();
    return l;
}

void npf_loop_free(npf_loop *l)
{
    int i;
    if (!l)
        return;
    /* first: the hooks stop other threads from posting */
    for (i = 0; i < l->nfree_hook; i++)
        l->free_hook[i].fn(l, l->free_hook[i].arg);
    l->nfree_hook = 0;
    for (i = 0; i < l->nheap; i++)
        free(l->heap[i]);
    free(l->heap);
    free_posted(l);
    npf_mutex_free(&l->post_mu);
    for (i = 0; i < l->nh; i++)
        free(l->h[i].reg);              /* (a child is detached by now: out of the queue) */
    free_grave(l);
    if (!l->host) {
        npf_sock_close(l->wake_fd);
#ifdef NPF_EVQ
        close(l->epfd);
#else
        timeEndPeriod(1);
#endif
    }
#ifndef NPF_EVQ
    free(l->pfd);
    free(l->pgen);
    free(l->own);
#endif
    free(l->h);
    free(l->idx);
    free(l->kids);
    free(l);
}

npf_loop *npf_loop_new_child(npf_loop *host)
{
    npf_loop *l = calloc(1, sizeof *l);
    if (!l)
        return NULL;
    l->host = host;
    l->wake_fd = -1;
#ifdef NPF_EVQ
    l->epfd = -1;
#endif
    npf_mutex_init(&l->post_mu);
    l->now = npf_mono_ms();
    return l;
}

void npf_loop_set_logctx(npf_loop *l, npf_log_ctx *ctx)
{
    l->logctx = ctx;
}

static void attach_run(npf_loop *h, void *arg)
{
    npf_loop *c = arg;
    npf_log_ctx *prev;
    if (npf_grow(&h->kids, &h->capkids, (size_t)h->nkids + 1, sizeof *h->kids, 16) < 0) {
        c->cf.done(c, c->carg);         /* the child cannot run: it ends at once */
        return;
    }
    h->kids[h->nkids++] = c;
    c->attached = 1;
    ep_all(c, 1);
    c->now = npf_mono_ms();
    prev = ctx_enter(c);
    c->cf.start(c, c->carg);
    npf_log_ctx_swap(prev);
    npf_loop_wake(c);                   /* what was posted to it before */
}

int npf_loop_attach(npf_loop *c, const npf_child_fns *fns, void *arg)
{
    if (!c->host)
        return -1;
    c->cf = *fns;
    c->carg = arg;
    return npf_loop_post(c->host, attach_run, c);
}

/* fd -> handler index: open addressing on the fd value (sockets are small
 * integers on POSIX, arbitrary handles on Windows); -1 marks a free slot
 * and the table never fills beyond half */
static unsigned idx_hash(int fd, int cap)
{
    unsigned x = (unsigned)fd * 2654435761u;
    return (x ^ (x >> 15)) & (unsigned)(cap - 1);
}

static int idx_find(const npf_loop *l, int fd)
{
    unsigned k;
    if (!l->idx_cap)
        return -1;
    for (k = idx_hash(fd, l->idx_cap);; k = (k + 1) & (unsigned)(l->idx_cap - 1)) {
        int v = l->idx[k];
        if (v == 0)
            return -1;
        if (v > 0 && l->h[v - 1].active && l->h[v - 1].fd == fd)
            return v - 1;
    }
}

static void idx_put(npf_loop *l, int fd, int i)
{
    unsigned k;
    for (k = idx_hash(fd, l->idx_cap); l->idx[k] > 0; k = (k + 1) & (unsigned)(l->idx_cap - 1))
        ;
    l->idx[k] = i + 1;
}

/* rebuild without tombstones, at a capacity keeping the table under a quarter full */
static int idx_rebuild(npf_loop *l)
{
    int cap = 128, i, *old = l->idx;
    int *nidx;
    while ((l->nh + 1) * 4 > cap)
        cap *= 2;
    nidx = calloc((size_t)cap, sizeof *nidx);
    if (!nidx)
        return -1;
    l->idx = nidx;
    l->idx_cap = cap;
    l->idx_tomb = 0;
    for (i = 0; i < l->nh; i++)
        if (l->h[i].active)
            idx_put(l, l->h[i].fd, i);
    free(old);
    return 0;
}

static void idx_del(npf_loop *l, int fd)
{
    unsigned k;
    if (!l->idx_cap)
        return;
    for (k = idx_hash(fd, l->idx_cap); l->idx[k] != 0; k = (k + 1) & (unsigned)(l->idx_cap - 1)) {
        int v = l->idx[k];
        if (v > 0 && l->h[v - 1].fd == fd) {
            l->idx[k] = -1;         /* tombstone: lookups walk past it */
            l->idx_tomb++;
            return;
        }
    }
}

static handler *find_h(npf_loop *l, int fd)
{
    int i = idx_find(l, fd);
    return i >= 0 ? &l->h[i] : NULL;
}

int npf_loop_add(npf_loop *l, int fd, unsigned events, npf_io_fn fn, void *arg)
{
    handler *h;
    int i;
    if (fd < 0 || find_h(l, fd))
        return -1;
    for (i = l->hfree < l->nh ? l->hfree : l->nh; i < l->nh && l->h[i].active; i++)
        ;
    if (i == l->nh) {
        if (npf_grow(&l->h, &l->cap, (size_t)l->nh + 1, sizeof *l->h, 64) < 0)
            return -1;
        memset(&l->h[l->nh], 0, sizeof l->h[0]);
        l->nh++;
    }
    /* live entries and tombstones together stay under half the table, so a
     * miss always reaches an empty slot */
    if ((l->nh + l->idx_tomb + 1) * 2 > l->idx_cap) {
        if (idx_rebuild(l) < 0) {
            if (i == l->nh - 1)
                l->nh--;
            return -1;
        }
    }
    h = &l->h[i];
    h->fd = fd;
    h->events = events;
    h->fn = fn;
    h->arg = arg;
    h->active = 1;
    h->gen = ++l->gen;
    h->reg = NULL;
    idx_put(l, fd, i);
    l->hfree = i + 1;
    if (ep_add(l, h) < 0) {             /* it would never be called: the caller hears it */
        npf_loop_del(l, fd);
        return -1;
    }
    return 0;
}

int npf_loop_mod(npf_loop *l, int fd, unsigned events)
{
    handler *h = find_h(l, fd);
    if (!h)
        return -1;
    if (h->events == events)
        return 0;                       /* nothing to tell the queue (a system call each) */
    h->events = events;
    ep_mod(l, h);
    return 0;
}

void npf_loop_del(npf_loop *l, int fd)
{
    handler *h = find_h(l, fd);
    if (!h)
        return;
    ep_del(l, h);
    idx_del(l, fd);
    h->active = 0;
    h->fn = NULL;
    if (h - l->h < l->hfree)
        l->hfree = (int)(h - l->h);
    while (l->nh > 0 && !l->h[l->nh - 1].active)
        l->nh--;
}

/* ---- one round: the host's own sockets and timers, and those of its
 * children (a shared runtime's), in one wait ---- */

static void wake_drain(npf_loop *l)
{
#ifdef NPF_EVENTFD
    uint64_t v;
    while (read(l->wake_fd, &v, sizeof v) > 0)
        ;
#else
    char b[16];
    while (recv(l->wake_fd, b, sizeof b, 0) > 0)
        ;
#endif
}

/* h of loop c (the host's own or a child's) is ready */
static void dispatch(npf_loop *l, npf_loop *c, handler *h, unsigned ev)
{
    npf_log_ctx *prev;
    c->now = l->now;
    prev = ctx_enter(c);
    TIMED(h->fn, h->fn(c, h->fd, ev, h->arg));
    npf_log_ctx_swap(prev);
}

#ifdef NPF_EVQ
static void wait_io(npf_loop *l, int wait)
{
    evq_ev ev[EVQ_BATCH];
    int i, n = evq_wait(l->epfd, ev, wait);
    l->now = npf_mono_ms();
    for (i = 0; i < n; i++) {
        ep_reg *r = ev[i].r;
        handler *h;
        if (!r) {
            wake_drain(l);
            continue;
        }
        if (r->dead)
            continue;                   /* removed by an earlier callback of this batch */
        h = find_h(r->l, r->fd);
        if (h && h->fn && h->reg == r)  /* not its fd closed and reused: another registration */
            dispatch(l, r->l, h, ev[i].ev);
    }
}
#else
/* pfd and its parallel arrays (pgen, own) for need entries */
static int pfd_room(npf_loop *l, size_t need)
{
    size_t c1 = l->npfd, c2 = l->npfd;     /* the same capacity for each */
    if (npf_grow(&l->pfd, &c1, need, sizeof *l->pfd, 64) < 0 || npf_grow(&l->pgen, &c2, need, sizeof *l->pgen, 64) < 0)
        return -1;
    return npf_grow(&l->own, &l->npfd, need, sizeof *l->own, 64);
}

static void wait_io(npf_loop *l, int wait)
{
    int i, k, n = 0, total = l->nh + 1;
    for (k = 0; k < l->nkids; k++)
        total += l->kids[k]->nh;
    if (pfd_room(l, (size_t)total) < 0)
        return;
    l->pfd[n].fd = l->wake_fd;
    l->pfd[n].events = POLLRDNORM;
    l->pfd[n].revents = 0;
    l->own[n++] = -1;
    for (k = -1; k < l->nkids; k++) {
        npf_loop *c = k < 0 ? l : l->kids[k];
        for (i = 0; i < c->nh; i++) {
            if (!c->h[i].active)
                continue;
            l->pfd[n].fd = c->h[i].fd;
            l->pfd[n].events = (short)(((c->h[i].events & NPF_EV_READ) ? POLLRDNORM : 0)
                                       | ((c->h[i].events & NPF_EV_WRITE) ? POLLWRNORM : 0));
            l->pfd[n].revents = 0;
            l->pgen[n] = c->h[i].gen;
            l->own[n++] = k;
        }
    }
    if (WSAPoll(l->pfd, (ULONG)n, wait) <= 0)
        return;
    l->now = npf_mono_ms();
    if (l->pfd[0].revents)
        wake_drain(l);
    for (i = 1; i < n; i++) {
        short r = l->pfd[i].revents;
        unsigned e = 0;
        npf_loop *c = l->own[i] < 0 ? l : l->kids[l->own[i]];
        handler *h;
        if (!r)
            continue;
        if (r & (POLLRDNORM | POLLHUP)) e |= NPF_EV_READ;
        if (r & POLLWRNORM) e |= NPF_EV_WRITE;
        if (r & (POLLERR | POLLNVAL)) e |= NPF_EV_ERROR | NPF_EV_READ;
        /* the handler may have been removed or replaced by an earlier
         * callback, or its fd closed and reused meanwhile */
        h = find_h(c, (int)l->pfd[i].fd);
        if (h && h->fn && h->gen == l->pgen[i])
            dispatch(l, c, h, e);
    }
}
#endif

static int64_t child_due(npf_loop *c)
{
    int64_t d = c->nheap > 0 ? c->heap[0]->due : INT64_MAX;
    if (__atomic_load_n(&c->woken, __ATOMIC_ACQUIRE) || (__atomic_load_n(&c->stop, __ATOMIC_ACQUIRE) && !c->ending))
        return 0;
    if (c->ending && c->end_due < d)
        d = c->end_due;
    return d;
}

/* each child: a few loads unless it has work */
static void run_kids(npf_loop *l)
{
    int k;
    for (k = 0; k < l->nkids; k++) {
        npf_loop *c = l->kids[k];
        int woken = __atomic_load_n(&c->woken, __ATOMIC_ACQUIRE);
        int timers = c->nheap > 0 && c->heap[0]->due <= l->now;
        int stop = __atomic_load_n(&c->stop, __ATOMIC_ACQUIRE);
        npf_log_ctx *prev;
        if (!woken && !timers && !stop)
            continue;
        c->now = l->now;
        prev = ctx_enter(c);
        if (woken)
            run_wake_hook(c);
        if (timers)
            fire_timers(c);
        if (stop && !c->ending) {
            c->ending = 1;
            c->end_due = l->now;
        }
        if (c->ending && c->end_due <= npf_mono_ms()) {
            int ms = c->cf.end(c, c->carg);
            if (ms < 0) {
                npf_log_ctx_swap(prev);
                ep_all(c, 0);           /* its sockets out of the queue: they may be closed and reused */
                c->attached = 0;
                l->kids[k] = l->kids[--l->nkids];
                k--;
                c->cf.done(c, c->carg);     /* the last use of c here */
                continue;
            }
            c->end_due = npf_mono_ms() + ms;
        }
        npf_log_ctx_swap(prev);
    }
}

void npf_loop_once(npf_loop *l, int max_ms)
{
    int k, wait;
    l->now = npf_mono_ms();
    wait = wait_until(max_ms, l->nheap > 0 ? l->heap[0]->due : INT64_MAX, l->now);
    for (k = 0; k < l->nkids; k++)
        wait = wait_until(wait, child_due(l->kids[k]), l->now);
    wait_io(l, wait);
    l->now = npf_mono_ms();
    run_wake_hook(l);                   /* attaches among them */
    fire_timers(l);
    run_kids(l);
    free_grave(l);                      /* no event of this batch names them any more */
}

/* may run on another thread (console / service control handler) or in a
 * signal handler; write() and send() are async-signal-safe */
void npf_loop_wake(npf_loop *l)
{
    __atomic_store_n(&l->woken, 1, __ATOMIC_RELEASE);
    if (l->host) {
        npf_loop_wake(l->host);
        return;
    }
#ifdef NPF_EVENTFD
    {
        uint64_t one = 1;
        ssize_t r = write(l->wake_fd, &one, sizeof one);
        (void)r;
    }
#else
    send(l->wake_fd, "x", 1, 0);        /* connected (npf_loop_new) */
#endif
}

void npf_loop_stop(npf_loop *l)
{
    __atomic_store_n(&l->stop, 1, __ATOMIC_RELEASE);
    npf_loop_wake(l);
}

npf_timer *npf_timer_add(npf_loop *l, int64_t delay_ms, npf_timer_fn fn, void *arg)
{
    npf_timer *t;
    int64_t now;
    if (npf_grow(&l->heap, &l->capheap, (size_t)l->nheap + 1, sizeof *l->heap, 64) < 0)
        return NULL;
    t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    now = npf_mono_ms();
    if (delay_ms < 0)
        delay_ms = 0;
    t->due = delay_ms > INT64_MAX - now ? INT64_MAX : now + delay_ms;
    t->seq = l->tseq++;
    t->fn = fn;
    t->arg = arg;
    heap_set(l, l->nheap++, t);
    heap_up(l, t->idx);
    return t;
}

/* t must be pending, or firing (its own callback cancels it: nothing to do) */
void npf_timer_cancel(npf_loop *l, npf_timer *t)
{
    if (!t || t->idx < 0)
        return;
    heap_remove(l, t);
    free(t);
}

/* a stop requested before run (an early service stop) is kept */
void npf_loop_run(npf_loop *l)
{
    while (!__atomic_load_n(&l->stop, __ATOMIC_ACQUIRE)) {
        run_wake_hook(l);           /* a signal that arrived during a callback */
        npf_loop_once(l, -1);
    }
}

int64_t npf_loop_now(const npf_loop *l)
{
    return l->now;
}

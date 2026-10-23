/* Event loop: poll everywhere (WSAPoll on Windows): no epoll descriptor per
 * loop; timers in a binary min-heap. A shared runtime's host loop runs its
 * children's sockets and timers with its own (on Linux in one epoll). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/loop.h"
#include "npf/platform.h"
#include "npf/sys.h"
#include <stdint.h>

/* a callback that holds the loop SLOW_CB_MS or more is logged, with its
 * address and npf_loop_new's (the offset between them names it: nm, addr2line):
 * nothing else runs meanwhile, timers come late (a ping, a watch) */
#define SLOW_CB_MS 1000
#define TIMED(fnp, call) do {                                                                       \
        int64_t t0_ = npf_mono_ms(), d_;                                                            \
        call;                                                                                       \
        if ((d_ = npf_mono_ms() - t0_) >= SLOW_CB_MS)                                               \
            npf_logw("loop: a callback held the loop %lld ms (%#lx; npf_loop_new %#lx)", (long long)d_, \
                     (unsigned long)(uintptr_t)(fnp), (unsigned long)(uintptr_t)npf_loop_new);      \
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

/* poll(2) everywhere (no epoll: one descriptor less per loop, and the loops
 * watch a few dozen at most); the wake: an eventfd on Linux, a loopback UDP
 * socket elsewhere */
#if defined(__linux__)
#define NPF_EVENTFD 1
#define NPF_EPOLL 1                 /* the host of a shared runtime: its children's sockets in one epoll */
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
typedef struct pollfd npf_pollfd;
#define NPF_POLL(f, n, ms) poll((f), (nfds_t)(n), (ms))
#define NPF_POLL_IN  POLLIN
#define NPF_POLL_OUT POLLOUT
#elif defined(_WIN32)
#include <mmsystem.h>
typedef WSAPOLLFD npf_pollfd;
#define NPF_POLL(f, n, ms) WSAPoll((f), (ULONG)(n), (ms))
#define NPF_POLL_IN  POLLRDNORM
#define NPF_POLL_OUT POLLWRNORM
#else
typedef struct pollfd npf_pollfd;
#define NPF_POLL(f, n, ms) poll((f), (nfds_t)(n), (ms))
#define NPF_POLL_IN  POLLIN
#define NPF_POLL_OUT POLLOUT
#endif

/* a socket in a runtime host's epoll: the event's pointer; dead once
 * removed (an event of the same batch may still name it), freed after it */
typedef struct ep_reg {
    npf_loop *l;
    int       fd, dead;
    struct ep_reg *next;
} ep_reg;

typedef struct handler {
    npf_io_fn fn;
    void     *arg;
    int       active;
    int       fd;
    unsigned  events;
    ep_reg   *reg;              /* in the host's epoll (NPF_EPOLL) */
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
    npf_timer **heap;           /* timers: min-heap by (due, seq) */
    int        nheap, capheap;
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
    int        cap;
#ifndef NPF_EVENTFD
    struct sockaddr_in wake_addr;
#endif
    npf_pollfd *pfd;
    int        npfd;
    int       *idx;             /* fd -> index into h, plus one; open addressing */
    int        idx_cap;         /* power of two */
    int        idx_tomb;        /* deleted slots still occupying the table */
    /* a shared runtime (loop.h): the host's children, or a child's host */
    npf_loop **kids;
    int        nkids, capkids;
    int       *own;             /* host: pfd entry -> its child (-1: the host's own) */
    npf_loop  *host;
    npf_child_fns cf;
    void      *carg;
    npf_log_ctx *logctx;
    int        ending;          /* child: stopped, end() steps under way */
    int64_t    end_due;
    int        attached;        /* child: run by the host now */
    int        epfd;            /* host (NPF_EPOLL): its children's sockets and its own; -1: poll */
    ep_reg    *grave;           /* host: removed registrations, freed after the batch */
};

#ifdef NPF_EPOLL
/* the epoll a loop's sockets go into: a host's own, or its host's while attached */
static int ep_fd(const npf_loop *l)
{
    if (l->host)
        return l->attached ? l->host->epfd : -1;
    return l->epfd;
}

static uint32_t ep_events(unsigned ev)
{
    return ((ev & NPF_EV_READ) ? EPOLLIN : 0) | ((ev & NPF_EV_WRITE) ? EPOLLOUT : 0);
}

static void ep_add(npf_loop *l, handler *h)
{
    int ep = ep_fd(l);
    struct epoll_event e;
    ep_reg *r;
    if (ep < 0 || h->reg || !(r = calloc(1, sizeof *r)))
        return;
    r->l = l;
    r->fd = h->fd;
    memset(&e, 0, sizeof e);
    e.events = ep_events(h->events);
    e.data.ptr = r;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, h->fd, &e) < 0) {
        npf_loge("loop: descriptor %d not watched: %s", h->fd, strerror(errno));
        free(r);
        return;
    }
    h->reg = r;
}

static void ep_mod(npf_loop *l, handler *h)
{
    int ep = ep_fd(l);
    struct epoll_event e;
    if (ep < 0 || !h->reg)
        return;
    memset(&e, 0, sizeof e);
    e.events = ep_events(h->events);
    e.data.ptr = h->reg;
    epoll_ctl(ep, EPOLL_CTL_MOD, h->fd, &e);
}

static void ep_del(npf_loop *l, handler *h)
{
    npf_loop *host = l->host ? l->host : l;
    int ep = ep_fd(l);
    if (!h->reg)
        return;
    if (ep >= 0)
        epoll_ctl(ep, EPOLL_CTL_DEL, h->fd, NULL);
    h->reg->dead = 1;
    h->reg->next = host->grave;
    host->grave = h->reg;
    h->reg = NULL;
}

static void ep_all(npf_loop *l, int add)
{
    int i;
    for (i = 0; i < l->nh; i++)
        if (l->h[i].active) {
            if (add)
                ep_add(l, &l->h[i]);
            else
                ep_del(l, &l->h[i]);
        }
}
#else
#define ep_add(l, h) ((void)0)
#define ep_mod(l, h) ((void)0)
#define ep_del(l, h) ((void)0)
#endif

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

/* first in npf_loop_free: the hooks stop other threads from posting */
static void run_free_hooks(npf_loop *l)
{
    int i;
    for (i = 0; i < l->nfree_hook; i++)
        l->free_hook[i].fn(l, l->free_hook[i].arg);
    l->nfree_hook = 0;
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
    /* a callback may add or cancel timers */
    while (l->nheap > 0) {
        npf_timer *t = l->heap[0];
        if (t->due > npf_mono_ms())
            break;
        heap_remove(l, t);
        TIMED(t->fn, t->fn(l, t->arg));
        free(t);
    }
}

static int next_wait(npf_loop *l, int max_ms)
{
    int wait = max_ms;
    l->now = npf_mono_ms();
    if (l->nheap > 0) {
        int64_t d = l->heap[0]->due - l->now;
        if (d < 0) d = 0;
        if (wait < 0 || d < wait) wait = (int)d;
    }
    return wait;
}

static void free_timers(npf_loop *l)
{
    int i;
    for (i = 0; i < l->nheap; i++)
        free(l->heap[i]);
    free(l->heap);
    l->heap = NULL;
    l->nheap = l->capheap = 0;
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
    socklen_t al = sizeof(struct sockaddr_in);
    l->wake_fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
    memset(&l->wake_addr, 0, sizeof l->wake_addr);
    l->wake_addr.sin_family = AF_INET;
    l->wake_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (l->wake_fd < 0 || bind(l->wake_fd, (struct sockaddr *)&l->wake_addr, sizeof l->wake_addr) < 0
        || getsockname(l->wake_fd, (struct sockaddr *)&l->wake_addr, &al) < 0) {
        npf_sock_close(l->wake_fd);
        free(l);
        return NULL;
    }
    }
#endif
#ifdef _WIN32
    timeBeginPeriod(1);             /* 1 ms timer resolution: AnLiu pacing and RTT */
#endif
    npf_mutex_init(&l->post_mu);
    l->now = npf_mono_ms();
    l->epfd = -1;
    return l;
}

void npf_loop_free(npf_loop *l)
{
    if (!l)
        return;
    run_free_hooks(l);
    free_timers(l);
    free_posted(l);
    npf_mutex_free(&l->post_mu);
    if (!l->host) {
        npf_sock_close(l->wake_fd);
#ifdef _WIN32
        timeEndPeriod(1);
#endif
    }
    {
        int i;
        for (i = 0; i < l->nh; i++)
            free(l->h[i].reg);          /* (a child is detached by now: out of the epoll) */
    }
    while (l->grave) {
        ep_reg *r = l->grave;
        l->grave = r->next;
        free(r);
    }
#ifdef NPF_EPOLL
    if (l->epfd >= 0)
        close(l->epfd);
#endif
    free(l->h);
    free(l->pfd);
    free(l->idx);
    free(l->kids);
    free(l->own);
    free(l);
}

npf_loop *npf_loop_new_child(npf_loop *host)
{
    npf_loop *l = calloc(1, sizeof *l);
    if (!l)
        return NULL;
    l->host = host;
    l->wake_fd = -1;
    l->epfd = -1;
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
    if (h->nkids == h->capkids) {
        int cap = h->capkids ? 2 * h->capkids : 16;
        npf_loop **k = realloc(h->kids, (size_t)cap * sizeof *k);
        if (!k) {                       /* the child cannot run: it ends at once */
            c->cf.done(c, c->carg);
            return;
        }
        h->kids = k;
        h->capkids = cap;
    }
    h->kids[h->nkids++] = c;
#ifdef NPF_EPOLL
    if (h->epfd < 0 && (h->epfd = epoll_create1(EPOLL_CLOEXEC)) >= 0) {
        struct epoll_event e;           /* the wake: data NULL */
        memset(&e, 0, sizeof e);
        e.events = EPOLLIN;
        if (epoll_ctl(h->epfd, EPOLL_CTL_ADD, h->wake_fd, &e) < 0) {
            close(h->epfd);
            h->epfd = -1;
        } else {
            ep_all(h, 1);
        }
    }
#endif
    c->attached = 1;
#ifdef NPF_EPOLL
    ep_all(c, 1);
#endif
    c->now = npf_mono_ms();
    prev = npf_log_ctx_swap(c->logctx);
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
    for (i = 0; i < l->nh && l->h[i].active; i++)
        ;
    if (i == l->nh) {
        if (l->nh == l->cap) {
            int n = l->cap ? l->cap * 2 : 64;
            handler *nh = realloc(l->h, (size_t)n * sizeof *nh);
            if (!nh)
                return -1;
            l->h = nh;
            l->cap = n;
        }
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
    h->reg = NULL;
    idx_put(l, fd, i);
    ep_add(l, h);
    return 0;
}

int npf_loop_mod(npf_loop *l, int fd, unsigned events)
{
    handler *h = find_h(l, fd);
    if (!h)
        return -1;
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
    while (l->nh > 0 && !l->h[l->nh - 1].active)
        l->nh--;
}

/* ---- the host of a shared runtime: its own sockets and timers, and its
 * children's, in one poll ---- */

static int64_t child_due(npf_loop *c)
{
    int64_t d = c->nheap > 0 ? c->heap[0]->due : INT64_MAX;
    if (__atomic_load_n(&c->woken, __ATOMIC_ACQUIRE) || (__atomic_load_n(&c->stop, __ATOMIC_ACQUIRE) && !c->ending))
        return 0;
    if (c->ending && c->end_due < d)
        d = c->end_due;
    return d;
}

static void host_once(npf_loop *l, int max_ms)
{
    int i, k, n, total = l->nh + 1, nkids = l->nkids, wait = next_wait(l, max_ms);
    npf_log_ctx *prev;
    for (k = 0; k < nkids; k++) {
        int64_t d = child_due(l->kids[k]) - l->now;
        if (d < 0)
            d = 0;
        if (wait < 0 || d < wait)
            wait = (int)d;
        total += l->kids[k]->nh;
    }
#ifdef NPF_EPOLL
    if (l->epfd >= 0) {                 /* the cost of a wake-up does not grow with the children */
        struct epoll_event ev[256];
        int ne = epoll_wait(l->epfd, ev, 256, wait);
        l->now = npf_mono_ms();
        for (i = 0; i < ne; i++) {
            ep_reg *r = ev[i].data.ptr;
            uint32_t x = ev[i].events;
            unsigned e = 0;
            npf_loop *c;
            handler *h;
            if (!r) {                   /* the wake */
                uint64_t v;
                while (read(l->wake_fd, &v, sizeof v) > 0)
                    ;
                continue;
            }
            if (r->dead)
                continue;               /* removed by an earlier callback of this batch */
            if (x & (EPOLLIN | EPOLLHUP)) e |= NPF_EV_READ;
            if (x & EPOLLOUT) e |= NPF_EV_WRITE;
            if (x & EPOLLERR) e |= NPF_EV_ERROR | NPF_EV_READ;
            c = r->l;
            h = find_h(c, r->fd);
            if (!h || !h->fn || h->reg != r)
                continue;
            c->now = l->now;
            prev = npf_log_ctx_swap(c->logctx);
            TIMED(h->fn, h->fn(c, h->fd, e, h->arg));
            npf_log_ctx_swap(prev);
        }
        goto after;
    }
#endif
    if (l->npfd < total || !l->own) {   /* own: as long as pfd */
        int cap = l->npfd < total ? total + 64 : l->npfd;
        npf_pollfd *p = realloc(l->pfd, (size_t)cap * sizeof *p);
        int *o;
        if (p)
            l->pfd = p;
        o = p ? realloc(l->own, (size_t)cap * sizeof *o) : NULL;
        if (!o)
            return;
        l->own = o;
        l->npfd = cap;
    }
    n = 0;
    l->pfd[n].fd = l->wake_fd;
    l->pfd[n].events = NPF_POLL_IN;
    l->pfd[n].revents = 0;
    l->own[n++] = -1;
    for (k = -1; k < nkids; k++) {
        npf_loop *c = k < 0 ? l : l->kids[k];
        for (i = 0; i < c->nh; i++) {
            if (!c->h[i].active)
                continue;
            l->pfd[n].fd = c->h[i].fd;
            l->pfd[n].events = (short)(((c->h[i].events & NPF_EV_READ) ? NPF_POLL_IN : 0)
                                       | ((c->h[i].events & NPF_EV_WRITE) ? NPF_POLL_OUT : 0));
            l->pfd[n].revents = 0;
            l->own[n++] = k;
        }
    }
    if (NPF_POLL(l->pfd, n, wait) > 0) {
        l->now = npf_mono_ms();
        if (l->pfd[0].revents) {
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
        for (i = 1; i < n; i++) {
            short r = l->pfd[i].revents;
            unsigned e = 0;
            npf_loop *c;
            handler *h;
            if (!r)
                continue;
            if (r & (NPF_POLL_IN | POLLHUP)) e |= NPF_EV_READ;
            if (r & NPF_POLL_OUT) e |= NPF_EV_WRITE;
            if (r & (POLLERR | POLLNVAL)) e |= NPF_EV_ERROR | NPF_EV_READ;
            c = l->own[i] < 0 ? l : l->kids[l->own[i]];
            /* the handler may have been removed or replaced by an earlier callback */
            h = find_h(c, (int)l->pfd[i].fd);
            if (!h || !h->fn)
                continue;
            c->now = l->now;
            prev = npf_log_ctx_swap(c->logctx);
            TIMED(h->fn, h->fn(c, h->fd, e, h->arg));
            npf_log_ctx_swap(prev);
        }
    }
#ifdef NPF_EPOLL
after:
#endif
    l->now = npf_mono_ms();
    run_wake_hook(l);                   /* attaches among them */
    fire_timers(l);
    for (k = 0; k < l->nkids; k++) {    /* each child: a few loads unless it has work */
        npf_loop *c = l->kids[k];
        int woken = __atomic_load_n(&c->woken, __ATOMIC_ACQUIRE);
        int timers = c->nheap > 0 && c->heap[0]->due <= l->now;
        int stop = __atomic_load_n(&c->stop, __ATOMIC_ACQUIRE);
        if (!woken && !timers && !stop)
            continue;
        c->now = l->now;
        prev = npf_log_ctx_swap(c->logctx);
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
#ifdef NPF_EPOLL
                ep_all(c, 0);           /* its sockets out of the epoll: they may be closed and reused */
#endif
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
    while (l->grave) {                  /* no event of this batch names them any more */
        ep_reg *r = l->grave;
        l->grave = r->next;
        free(r);
    }
}

void npf_loop_once(npf_loop *l, int max_ms)
{
    int i, n, wait;
    if (l->nkids > 0) {
        host_once(l, max_ms);
        return;
    }
    wait = next_wait(l, max_ms);
    if (l->npfd < l->nh + 1) {
        npf_pollfd *p = realloc(l->pfd, (size_t)(l->nh + 64) * sizeof *p);
        if (!p)
            return;
        l->pfd = p;
        l->npfd = l->nh + 64;
    }
    n = 0;
    l->pfd[n].fd = l->wake_fd;
    l->pfd[n].events = NPF_POLL_IN;
    l->pfd[n].revents = 0;
    n++;
    for (i = 0; i < l->nh; i++) {
        if (!l->h[i].active)
            continue;
        l->pfd[n].fd = l->h[i].fd;
        l->pfd[n].events = (short)(((l->h[i].events & NPF_EV_READ) ? NPF_POLL_IN : 0)
                                   | ((l->h[i].events & NPF_EV_WRITE) ? NPF_POLL_OUT : 0));
        l->pfd[n].revents = 0;
        n++;
    }
    if (NPF_POLL(l->pfd, n, wait) > 0) {
        l->now = npf_mono_ms();
        if (l->pfd[0].revents) {
#ifdef NPF_EVENTFD
            uint64_t v;
            while (read(l->wake_fd, &v, sizeof v) > 0)
                ;
#else
            char b[16];
            while (recv(l->wake_fd, b, sizeof b, 0) > 0)
                ;
#endif
            run_wake_hook(l);
        }
        for (i = 1; i < n; i++) {
            short r = l->pfd[i].revents;
            unsigned e = 0;
            handler *h;
            if (!r)
                continue;
            if (r & (NPF_POLL_IN | POLLHUP)) e |= NPF_EV_READ;
            if (r & NPF_POLL_OUT) e |= NPF_EV_WRITE;
            if (r & (POLLERR | POLLNVAL)) e |= NPF_EV_ERROR | NPF_EV_READ;
            /* the handler may have been removed or replaced by an earlier callback */
            h = find_h(l, (int)l->pfd[i].fd);
            if (h && h->fn)
                TIMED(h->fn, h->fn(l, h->fd, e, h->arg));
        }
    }
    l->now = npf_mono_ms();
    fire_timers(l);
}

/* may run on another thread (console / service control handler) or in a
 * signal handler; write() and sendto() are async-signal-safe */
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
    sendto(l->wake_fd, "x", 1, 0, (struct sockaddr *)&l->wake_addr, sizeof l->wake_addr);
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
    if (l->nheap == l->capheap) {
        int cap = l->capheap ? 2 * l->capheap : 64;
        npf_timer **h = realloc(l->heap, (size_t)cap * sizeof *h);
        if (!h)
            return NULL;
        l->heap = h;
        l->capheap = cap;
    }
    t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->due = npf_mono_ms() + (delay_ms < 0 ? 0 : delay_ms);
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

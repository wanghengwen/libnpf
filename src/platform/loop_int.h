/* Inside the event loop (npf/loop.h): the loop itself (loop.c) and a
 * shared runtime's children (loop_child.c) share this. */
#ifndef NPF_LOOP_INT_H
#define NPF_LOOP_INT_H

#include <stdint.h>

#include "npf/lock.h"
#include "npf/log.h"
#include "npf/loop.h"
#include "npf/sys.h"

/* The sockets: a queue (NPF_EVQ) everywhere but Windows, epoll on Linux
 * (2.6.27 and later: epoll_create1, eventfd flags), kqueue on macOS, iOS and
 * the BSDs: a wake-up costs what is ready, not what is watched (a node with a
 * thousand sublinks). WSAPoll on Windows, which has neither (IOCP is another
 * model). The wake: an eventfd on Linux, a loopback UDP socket elsewhere
 * (send: safe in a signal handler). */
#ifndef _WIN32
#define NPF_EVQ 1
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

#define FREE_HOOKS 4

struct npf_loop {
    /* ---- every loop: its sockets, timers, wake hook and posted calls ---- */
    handler   *h;               /* the nh entries (idx: fd -> entry) */
    int        nh;
    size_t     cap;
    int        hfree;           /* no free entry in h below this one */
    unsigned   gen;
    int       *idx;             /* fd -> index into h, plus one; open addressing */
    int        idx_cap;         /* power of two */
    int        idx_tomb;        /* deleted slots still occupying the table */
    npf_timer **heap;           /* timers: min-heap by (due, seq) */
    int        nheap;
    size_t     capheap;
    uint64_t   tseq;
    int64_t    now;
    volatile int stop;
    volatile int woken;
    void     (*wake_fn)(npf_loop *l, void *arg);
    void      *wake_arg;
    npf_mutex  post_mu;         /* guards the posted list (other threads append) */
    struct posted *post_head, *post_tail;
    struct { void (*fn)(npf_loop *l, void *arg); void *arg; } free_hook[FREE_HOOKS];
    int        nfree_hook;
    /* ---- host only (a loop of its own): the wait, and the children it runs ---- */
    int        wake_fd;         /* Linux: eventfd; elsewhere: loopback UDP socket; -1: a child */
    npf_loop **kids;
    int        nkids;
    size_t     capkids;
#ifdef NPF_EVQ
    int        epfd;            /* its queue: its sockets and its children's; -1: a child */
    ep_reg    *grave;           /* removed registrations, freed after the batch */
#else
    /* ---- host only, Windows: WSAPoll's arrays, rebuilt each round ---- */
    WSAPOLLFD *pfd;
    unsigned  *pgen;            /* pfd entry -> the registration it was taken from */
    int       *own;             /* pfd entry -> its loop's child (-1: the host's own) */
    size_t     npfd;            /* pfd, pgen and own have room for this many */
#endif
    /* ---- child only (loop_child.c): its host and the attach protocol ---- */
    npf_loop  *host;
    npf_child_fns cf;
    void      *carg;
    npf_log_ctx *logctx;        /* its instance's (npf_loop_set_logctx) */
    int        attached;        /* run by the host now */
    int        ending;          /* stopped, end() steps under way */
    int64_t    end_due;
};

/* loop.c: what a woken loop runs (its wake hook, its posted calls), its
 * timers that are due, and (NPF_EVQ) a child's sockets put into its host's
 * queue or taken out (WSAPoll: the host polls its children's each round) */
void loop_run_woken(npf_loop *l);
void loop_fire_timers(npf_loop *l);
#ifdef NPF_EVQ
void loop_ep_all(npf_loop *l, int add);
#else
#define loop_ep_all(l, add) ((void)0)
#endif

/* the log context a loop's work runs in: a runtime child's, its instance's
 * (npf_loop_set_logctx); a loop without one keeps the thread's (a
 * standalone instance's thread set it itself: its level, hook and ring).
 * Returns what to put back */
static inline npf_log_ctx *loop_ctx_enter(const npf_loop *c)
{
    npf_log_ctx *prev = npf_log_ctx_swap(c->logctx);
    if (!c->logctx)
        npf_log_ctx_swap(prev);         /* none of its own: the thread's stays */
    return prev;
}

/* loop_child.c: when child c needs the host next (INT64_MAX: nothing
 * pending), and each attached child's round */
int64_t loop_child_due(npf_loop *c);
void loop_run_kids(npf_loop *l);

#endif

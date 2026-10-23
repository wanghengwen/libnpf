/* Asynchronous getaddrinfo (npf/resolve.h): a small pool of worker threads
 * with a bounded queue, delivering through npf_loop_post.
 *
 * Lifetimes. Each loop has a hub, the place its results go; the hub lives
 * while the loop or a request needs it (reference count). npf_loop_free runs
 * the hub's free hook, which marks the hub dead under the pool lock, so a
 * worker that finishes later frees its request instead of posting to a freed
 * loop. Results posted but not yet delivered when the loop goes are released
 * by the post's drop function. A request is freed exactly once: by its
 * worker (cancelled, or the loop gone), by deliver, or by drop.
 *
 * Budget. getaddrinfo cannot be interrupted: a dead DNS server keeps a
 * worker busy until the system gives up. At most RESOLVE_WORKERS run at
 * once and RESOLVE_CAPACITY requests are queued or running; a cancelled
 * request counts until its worker is done with it, so cancelling and
 * starting again cannot pile up work. Beyond that npf_resolve_start fails.
 * The peers' lookups wait in a queue of their own, run on at most
 * RESOLVE_PEER_WORKERS of the threads and hold at most RESOLVE_PEER_CAPACITY
 * of the room; a worker takes the node's own first. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/resolve.h"

#ifdef _WIN32
#include <windows.h>
static SRWLOCK g_mu = SRWLOCK_INIT;
static CONDITION_VARIABLE g_cv = CONDITION_VARIABLE_INIT;
#define LOCK()   AcquireSRWLockExclusive(&g_mu)
#define UNLOCK() ReleaseSRWLockExclusive(&g_mu)
#define WAIT()   SleepConditionVariableSRW(&g_cv, &g_mu, INFINITE, 0)
#define SIGNAL() WakeConditionVariable(&g_cv)
#else
#include <pthread.h>
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
#define LOCK()   pthread_mutex_lock(&g_mu)
#define UNLOCK() pthread_mutex_unlock(&g_mu)
#define WAIT()   pthread_cond_wait(&g_cv, &g_mu)
#define SIGNAL() pthread_cond_signal(&g_cv)
#endif

npf_resolve_gai_fn npf_resolve_gai = getaddrinfo;

typedef struct hub {
    npf_loop   *loop;               /* NULL once the loop is freed */
    int         refs;               /* the hub list (while the loop lives) + requests */
    struct hub *next;
} hub;

struct npf_resolve {
    hub        *h;
    char        host[256];
    uint16_t    port;
    int         socktype;
    npf_resolve_fn fn;
    void       *arg;
    int         cancelled;          /* under the lock */
    int         peer;               /* a peer asked for it */
    int         err;
    int         n;
    struct sockaddr_storage addrs[NPF_RESOLVE_MAX];
    socklen_t   lens[NPF_RESOLVE_MAX];
    struct npf_resolve *next;       /* queue */
};

/* everything below is under the lock */
static struct {
    npf_resolve *head, *tail;       /* waiting for a worker: the node's own */
    npf_resolve *phead, *ptail;     /* and the peers' */
    int          active;            /* queued + running */
    int          pactive, prunning; /* the peers' of them; running now */
    int          workers;           /* threads started (they stay) */
    int          idle;              /* workers waiting for work */
    hub         *hubs;
} P;

static void hub_unref(hub *h)
{
    if (--h->refs == 0)
        free(h);
}

/* npf_loop_free: no more posts to this loop */
static void loop_gone(npf_loop *loop, void *arg)
{
    hub *h = arg, **pp;
    (void)loop;
    LOCK();
    h->loop = NULL;
    for (pp = &P.hubs; *pp; pp = &(*pp)->next)
        if (*pp == h) {
            *pp = h->next;
            break;
        }
    hub_unref(h);                   /* the list's reference */
    UNLOCK();
}

static hub *hub_of(npf_loop *loop)
{
    hub *h;
    for (h = P.hubs; h; h = h->next)
        if (h->loop == loop)
            return h;
    h = calloc(1, sizeof *h);
    if (!h)
        return NULL;
    if (npf_loop_on_free(loop, loop_gone, h) < 0) {
        free(h);
        return NULL;
    }
    h->loop = loop;
    h->refs = 1;
    h->next = P.hubs;
    P.hubs = h;
    return h;
}

/* on the loop thread */
static void deliver(npf_loop *loop, void *arg)
{
    npf_resolve *r = arg;
    int cancelled;
    (void)loop;
    LOCK();
    cancelled = r->cancelled;
    hub_unref(r->h);
    UNLOCK();
    if (!cancelled)
        r->fn(r, r->err, r->addrs, r->lens, r->n, r->arg);
    free(r);
}

/* the loop was freed with this result still queued */
static void drop(void *arg)
{
    npf_resolve *r = arg;
    LOCK();
    hub_unref(r->h);
    UNLOCK();
    free(r);
}

static void work(npf_resolve *r)
{
    struct addrinfo hints, *res = NULL, *ai;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = r->socktype;
    snprintf(ps, sizeof ps, "%u", (unsigned)r->port);
    r->err = npf_resolve_gai(r->host, ps, &hints, &res);
    if (r->err == 0) {
        for (ai = res; ai && r->n < NPF_RESOLVE_MAX; ai = ai->ai_next) {
            if (ai->ai_addrlen > sizeof r->addrs[0])
                continue;
            memcpy(&r->addrs[r->n], ai->ai_addr, ai->ai_addrlen);
            r->lens[r->n++] = ai->ai_addrlen;
        }
        if (res)
            freeaddrinfo(res);
        if (r->n == 0)
            r->err = EAI_NONAME;
    }
}

static void worker(void)
{
    for (;;) {
        npf_resolve *r;
        int skip;
        LOCK();
        while (!P.head && !(P.phead && P.prunning < RESOLVE_PEER_WORKERS)) {
            P.idle++;
            WAIT();
            P.idle--;
        }
        if (P.head) {                   /* the node's own first */
            r = P.head;
            P.head = r->next;
            if (!P.head)
                P.tail = NULL;
        } else {
            r = P.phead;
            P.phead = r->next;
            if (!P.phead)
                P.ptail = NULL;
            P.prunning++;
        }
        skip = r->cancelled || !r->h->loop;
        UNLOCK();
        if (!skip)
            work(r);
        LOCK();
        P.active--;
        if (r->peer) {
            P.pactive--;
            P.prunning--;
            if (P.phead)
                SIGNAL();               /* a waiting peers' lookup may run now */
        }
        /* posted under the lock: the loop cannot be freed in between */
        if (r->cancelled || !r->h->loop || npf_loop_post_drop(r->h->loop, deliver, drop, r) < 0) {
            hub_unref(r->h);
            free(r);
        }
        UNLOCK();
    }
}

#ifdef _WIN32
static DWORD WINAPI thread_main(LPVOID p)
{
    (void)p;
    worker();
    return 0;
}

static int spawn(void)
{
    HANDLE h = CreateThread(NULL, 0, thread_main, NULL, 0, NULL);
    if (!h)
        return -1;
    CloseHandle(h);
    return 0;
}
#else
static void *thread_main(void *p)
{
    (void)p;
    worker();
    return NULL;
}

static int spawn(void)
{
    pthread_t t;
    pthread_attr_t a;
    int e;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&a, 256 << 10);    /* not musl's 128 KB default */
    e = pthread_create(&t, &a, thread_main, NULL);
    pthread_attr_destroy(&a);
    return e ? -1 : 0;
}
#endif

static npf_resolve *start(npf_loop *loop, const char *host, uint16_t port, int socktype, npf_resolve_fn fn,
                          void *arg, int peer)
{
    npf_resolve *r;
    hub *h;
    if (strlen(host) >= sizeof r->host)
        return NULL;
    r = calloc(1, sizeof *r);
    if (!r)
        return NULL;
    strcpy(r->host, host);
    r->port = port;
    r->socktype = socktype;
    r->fn = fn;
    r->arg = arg;
    r->peer = peer;
    LOCK();
    if (P.active >= RESOLVE_CAPACITY || (peer && P.pactive >= RESOLVE_PEER_CAPACITY) || !(h = hub_of(loop))) {
        UNLOCK();
        free(r);
        return NULL;                /* busy: the caller fails this lookup */
    }
    if (P.idle == 0 && P.workers < RESOLVE_WORKERS) {
        if (spawn() == 0)
            P.workers++;
        else if (P.workers == 0) {
            UNLOCK();
            free(r);
            return NULL;
        }
    }
    h->refs++;
    r->h = h;
    if (peer) {
        if (P.ptail)
            P.ptail->next = r;
        else
            P.phead = r;
        P.ptail = r;
        P.pactive++;
    } else {
        if (P.tail)
            P.tail->next = r;
        else
            P.head = r;
        P.tail = r;
    }
    P.active++;
    SIGNAL();
    UNLOCK();
    return r;
}

npf_resolve *npf_resolve_start(npf_loop *loop, const char *host, uint16_t port, int socktype, npf_resolve_fn fn,
                               void *arg)
{
    return start(loop, host, port, socktype, fn, arg, 0);
}

npf_resolve *npf_resolve_start_peer(npf_loop *loop, const char *host, uint16_t port, int socktype, npf_resolve_fn fn,
                                    void *arg)
{
    return start(loop, host, port, socktype, fn, arg, 1);
}

void npf_resolve_cancel(npf_resolve *r)
{
    if (!r)
        return;
    LOCK();
    r->cancelled = 1;
    UNLOCK();
}

int npf_resolve_active(void)
{
    int n;
    LOCK();
    n = P.active;
    UNLOCK();
    return n;
}

int npf_resolve_active_peer(void)
{
    int n;
    LOCK();
    n = P.pactive;
    UNLOCK();
    return n;
}

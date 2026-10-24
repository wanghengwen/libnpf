/* The router's port mapping for the node's main socket (nat-traversal.md 5):
 * PCP, else NAT-PMP, at the default gateway. A mapping is a "mapped"
 * candidate, as good as a public address: the platform then plans S1 instead
 * of birthday punching for this side. The request blocks for up to a few
 * seconds when the gateway does not answer, so it runs on a thread of its
 * own; the result comes back through npf_loop_post. Renewed before the lease
 * ends (1 hour, 10 minutes ahead), tried again every 30 minutes when there
 * is none, removed when the node stops. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/node.h"
#include "npf/platform.h"
#include "npf/portmap.h"

#include "node_internal.h"

#define PM_LEASE_S   3600
#define PM_RENEW_S    600            /* ahead of the end of the lease */
#define PM_RETRY_MS  (30 * 60 * 1000)
#define PM_MIN_S      120            /* a gateway's lease as it is used: renewed no more often than every minute, */
#define PM_MAX_S    86400            /* and at least once a day */

/* A request runs on a thread of its own and may outlive the node: the node
 * forgets it (cancelled, under pm_mu) when it stops; the thread then frees
 * the job instead of posting it, or (posted already) pm_deliver does. Only
 * a job not cancelled touches the node or its loop */
typedef struct pm_job {
    npf_node   *n;
    uint16_t    port;
    uint32_t    lifetime;
    int         ok;
    int         cancelled;          /* under pm_mu */
    npf_portmap res;
} pm_job;

#ifdef _WIN32
static SRWLOCK pm_mu = SRWLOCK_INIT;
#define PM_LOCK()   AcquireSRWLockExclusive(&pm_mu)
#define PM_UNLOCK() ReleaseSRWLockExclusive(&pm_mu)
#else
static pthread_mutex_t pm_mu = PTHREAD_MUTEX_INITIALIZER;
#define PM_LOCK()   pthread_mutex_lock(&pm_mu)
#define PM_UNLOCK() pthread_mutex_unlock(&pm_mu)
#endif

static void pm_timer(npf_loop *loop, void *arg);

/* a public address: a mapping on a router behind another NAT (CGNAT,
 * double NAT) gives nothing */
static int public_ip4(const uint8_t *a)
{
    return !(a[0] == 10 || a[0] == 127 || a[0] == 0 || (a[0] == 172 && (a[1] & 0xf0) == 16)
             || (a[0] == 192 && a[1] == 168) || (a[0] == 100 && (a[1] & 0xc0) == 64) || (a[0] == 169 && a[1] == 254));
}

static void pm_deliver(npf_loop *loop, void *arg)
{
    pm_job *j = arg;
    npf_node *n;
    int64_t next = PM_RETRY_MS;
    int cancelled;
    (void)loop;
    PM_LOCK();
    cancelled = j->cancelled;
    PM_UNLOCK();
    if (cancelled) {                        /* the node stopped meanwhile: it may be gone */
        free(j);
        return;
    }
    n = j->n;
    n->pm_job = NULL;
    if (j->ok && j->res.ext_family == 4 && (public_ip4(j->res.external_ip) || getenv("NPF_TEST_PORTMAP_GW"))) {
        int had = n->pm_ok;
        if (j->res.lifetime < PM_MIN_S)
            j->res.lifetime = PM_MIN_S;
        if (j->res.lifetime > PM_MAX_S)
            j->res.lifetime = PM_MAX_S;
        n->pm = j->res;
        n->pm_ok = 1;
        if (!had)
            npf_log("portmap: %s mapping %u.%u.%u.%u:%u -> UDP port %u for %u s", npf_portmap_method_str(j->res.method),
                    j->res.external_ip[0], j->res.external_ip[1], j->res.external_ip[2], j->res.external_ip[3],
                    j->res.external_port, j->res.internal_port, j->res.lifetime);
        next = (int64_t)(j->res.lifetime > 2 * PM_RENEW_S ? j->res.lifetime - PM_RENEW_S : j->res.lifetime / 2) * 1000;
        if (!had)
            node_nat_regather(n);           /* the "mapped" candidate */
    } else {
        if (j->ok)
            npf_logd("portmap: the router's external address is not public (another NAT behind it): not used");
        else if (!n->pm_tried)
            npf_log("portmap: no PCP / NAT-PMP answer from the gateway");
        if (n->pm_ok) {
            n->pm_ok = 0;
            node_nat_regather(n);
        }
    }
    n->pm_tried = 1;
    if (!n->t_pm)
        n->t_pm = npf_timer_add(n->loop, next > 1000 ? next : 1000, pm_timer, n);
    free(j);
}

static void pm_work(pm_job *j)
{
    j->ok = npf_portmap_request(j->port, j->lifetime, &j->res) == 0;
    PM_LOCK();                              /* the node (and its loop) still there while not cancelled */
    if (j->cancelled || npf_loop_post_drop(j->n->loop, pm_deliver, free, j) < 0) {
        PM_UNLOCK();
        free(j);
        return;
    }
    PM_UNLOCK();
}

/* the node no longer waits for its request (stop, restart) */
static void pm_forget(npf_node *n)
{
    if (!n->pm_job)
        return;
    PM_LOCK();
    ((pm_job *)n->pm_job)->cancelled = 1;
    PM_UNLOCK();
    n->pm_job = NULL;
}

#ifdef _WIN32
static DWORD WINAPI pm_thread(LPVOID arg)
{
    pm_work(arg);
    return 0;
}

static int spawn(pm_job *j)
{
    HANDLE h = CreateThread(NULL, 0, pm_thread, j, 0, NULL);
    if (!h)
        return -1;
    CloseHandle(h);
    return 0;
}
#else
static void *pm_thread(void *arg)
{
    pm_work(arg);
    return NULL;
}

static int spawn(pm_job *j)
{
    pthread_t t;
    pthread_attr_t a;
    int e;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&a, 256 << 10);    /* not musl's 128 KB default */
    e = pthread_create(&t, &a, pm_thread, j);
    pthread_attr_destroy(&a);
    return e ? -1 : 0;
}
#endif

static void pm_request(npf_node *n)
{
    pm_job *j;
    if (n->pm_job || n->udp_fd < 0 || !(j = calloc(1, sizeof *j)))
        return;
    j->n = n;
    j->port = n->udp_port;
    j->lifetime = PM_LEASE_S;
    n->pm_job = j;
    if (spawn(j) < 0) {
        n->pm_job = NULL;
        free(j);
    }
}

static void pm_timer(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_pm = NULL;
    pm_request(n);
}

void node_portmap_start(npf_node *n)
{
    if (n->cfg.offline || n->cfg.no_portmap)
        return;
    pm_request(n);
}

void node_portmap_stop(npf_node *n)
{
    if (n->t_pm)
        npf_timer_cancel(n->loop, n->t_pm);
    n->t_pm = NULL;
    pm_forget(n);                           /* a running request's answer is dropped */
    if (n->pm_ok) {                         /* one short try: a gateway gone silent does not hold up the stop */
        npf_portmap_remove(n->udp_port, n->pm.method);
        n->pm_ok = 0;
    }
}

void node_portmap_restart(npf_node *n)
{
    if (n->t_pm)
        npf_timer_cancel(n->loop, n->t_pm);
    n->t_pm = NULL;
    pm_forget(n);
    n->pm_ok = 0;
    node_portmap_start(n);
}

int node_portmap_cand(const npf_node *n, struct sockaddr_storage *out)
{
    struct sockaddr_in *a = (struct sockaddr_in *)out;
    if (!n->pm_ok)
        return 0;
    memset(out, 0, sizeof *out);
    a->sin_family = AF_INET;
    memcpy(&a->sin_addr, n->pm.external_ip, 4);
    a->sin_port = htons(n->pm.external_port);
    return 1;
}

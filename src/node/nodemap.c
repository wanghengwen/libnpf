/* The router's port mapping for the node's main socket (nat-traversal.md 5):
 * PCP, else NAT-PMP, at the default gateway. A mapping is a "mapped"
 * candidate, as good as a public address: the platform then plans S1 instead
 * of birthday punching for this side. The request blocks for up to a few
 * seconds when the gateway does not answer, so it runs on a thread of its
 * own; the result comes back through npf_loop_post. Renewed before the lease
 * ends (1 hour, 10 minutes ahead), tried again every 30 minutes when there
 * is none, removed when the node stops, asked for again on another network.
 *
 * UPnP IGD (NPF_UPNP) is only detected, never used for a mapping: at the
 * start and on another network, on a thread as well. What the gateway did
 * goes to the platform with the NAT profile ("pm", npf_node_write_nat), for
 * the platform's statistics: would a UPnP mapping help? */
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
#include "npf/upnp.h"

#include "node_internal.h"

#define PM_LEASE_S   3600
#define PM_RENEW_S    600            /* ahead of the end of the lease */
#define PM_RETRY_MS  (30 * 60 * 1000)
#define PM_MIN_S      120            /* a gateway's lease as it is used: renewed no more often than every minute, */
#define PM_MAX_S    86400            /* and at least once a day */

/* what the gateway did (n->pm_gw, the "pm" object's gw) */
enum { PM_GW_UNKNOWN = 0, PM_GW_MAP, PM_GW_PRIVATE, PM_GW_NONE, PM_GW_NOGW };
/* the UPnP detection (n->upnp): not yet, no gateway, then npf_upnp_detect + 2 */
enum { UPNP_UNKNOWN = 0, UPNP_NOGW, UPNP_NONE, UPNP_PRESENT, UPNP_ADDR };

/* A request runs on a thread of its own and may outlive the node: the node
 * forgets it (cancelled, under pm_mu) when it stops; the thread then frees
 * the job instead of posting it, or (posted already) pm_deliver does. Only
 * a job not cancelled touches the node or its loop */
typedef struct pm_job {
    npf_node   *n;
    int         upnp;               /* a UPnP detection, not a PCP / NAT-PMP request */
    uint16_t    port;
    uint32_t    lifetime;
    int         ret;                /* npf_portmap_request, npf_upnp_detect */
    int         cancelled;          /* under pm_mu */
    npf_portmap res;
    uint8_t     ip[4];              /* UPnP: the WAN address */
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
static void upnp_start(npf_node *n);
static void upnp_deliver(npf_node *n, pm_job *j);

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
    int cancelled, was_gw, was_m;
    (void)loop;
    PM_LOCK();
    cancelled = j->cancelled;
    PM_UNLOCK();
    if (cancelled) {                        /* the node stopped meanwhile: it may be gone */
        free(j);
        return;
    }
    n = j->n;
    if (j->upnp) {
        upnp_deliver(n, j);
        free(j);
        return;
    }
    n->pm_job = NULL;
    was_gw = n->pm_gw;
    was_m = n->pm_m;
    if (j->ret == 0 && j->res.ext_family == 4 && (public_ip4(j->res.external_ip) || getenv("NPF_TEST_PORTMAP_GW"))) {
        int had = n->pm_ok;
        if (j->res.lifetime < PM_MIN_S)
            j->res.lifetime = PM_MIN_S;
        if (j->res.lifetime > PM_MAX_S)
            j->res.lifetime = PM_MAX_S;
        n->pm = j->res;
        n->pm_ok = 1;
        n->pm_gw = PM_GW_MAP;
        n->pm_m = j->res.method;
        if (!had)
            npf_log("portmap: %s mapping %u.%u.%u.%u:%u -> UDP port %u for %u s", npf_portmap_method_str(j->res.method),
                    j->res.external_ip[0], j->res.external_ip[1], j->res.external_ip[2], j->res.external_ip[3],
                    j->res.external_port, j->res.internal_port, j->res.lifetime);
        next = (int64_t)(j->res.lifetime > 2 * PM_RENEW_S ? j->res.lifetime - PM_RENEW_S : j->res.lifetime / 2) * 1000;
        if (!had)
            node_nat_regather(n);           /* the "mapped" candidate */
    } else {
        n->pm_gw = j->ret == 0 ? PM_GW_PRIVATE : j->ret == -2 ? PM_GW_NOGW : PM_GW_NONE;
        n->pm_m = j->ret == 0 ? j->res.method : 0;
        if (j->ret == 0)
            npf_logd("portmap: the router's external address is not public (another NAT behind it): not used");
        else if (!n->pm_tried && j->ret == -2)
            npf_log("portmap: no default IPv4 gateway");
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
    if (n->pm_gw != was_gw || n->pm_m != was_m)
        npf_node_report_nat(n);             /* the platform's statistics */
}

static void pm_work(pm_job *j)
{
#ifdef NPF_UPNP
    if (j->upnp)
        j->ret = npf_upnp_detect(j->ip);
    else
#endif
        j->ret = npf_portmap_request(j->port, j->lifetime, &j->res);
    PM_LOCK();                              /* the node (and its loop) still there while not cancelled */
    if (j->cancelled || npf_loop_post_drop(j->n->loop, pm_deliver, free, j) < 0) {
        PM_UNLOCK();
        free(j);
        return;
    }
    PM_UNLOCK();
}

/* the node no longer waits for its request (stop, restart) */
static void pm_forget(void **job)
{
    if (!*job)
        return;
    PM_LOCK();
    ((pm_job *)*job)->cancelled = 1;
    PM_UNLOCK();
    *job = NULL;
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

static void job_start(npf_node *n, void **slot, int upnp)
{
    pm_job *j;
    if (*slot || !(j = calloc(1, sizeof *j)))
        return;
    j->n = n;
    j->upnp = upnp;
    j->port = n->udp_port;
    j->lifetime = PM_LEASE_S;
    *slot = j;
    if (spawn(j) < 0) {
        *slot = NULL;
        free(j);
    }
}

static void pm_request(npf_node *n)
{
    if (n->udp_fd >= 0)
        job_start(n, &n->pm_job, 0);
}

static int upnp_off(const npf_node *n)
{
#ifdef NPF_UPNP
    return n->cfg.offline || n->cfg.no_portmap || n->cfg.no_upnp;
#else
    (void)n;
    return 1;
#endif
}

static void upnp_start(npf_node *n)
{
    if (!upnp_off(n))
        job_start(n, &n->upnp_job, 1);
}

static void upnp_deliver(npf_node *n, pm_job *j)
{
    int was = n->upnp;
    uint8_t was_ip[4];
    char a[INET_ADDRSTRLEN];
    memcpy(was_ip, n->upnp_ip, 4);
    n->upnp_job = NULL;
    n->upnp = j->ret < 0 ? UPNP_NOGW : j->ret + UPNP_NONE;
    memcpy(n->upnp_ip, j->ip, 4);
    if (n->upnp == UPNP_ADDR)
        npf_log("upnp: an IGD at the gateway, WAN address %s%s (detected only: no mapping)",
                inet_ntop(AF_INET, n->upnp_ip, a, sizeof a), public_ip4(n->upnp_ip) ? "" : ", not public");
    else
        npf_log("upnp: %s", n->upnp == UPNP_PRESENT ? "an IGD at the gateway, its WAN address not learned"
                            : n->upnp == UPNP_NONE  ? "no IGD at the gateway" : "no default IPv4 gateway");
    if (n->upnp != was || memcmp(was_ip, n->upnp_ip, 4) != 0)
        npf_node_report_nat(n);
}

static void pm_timer(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_pm = NULL;
    pm_request(n);
    if (n->upnp == UPNP_NOGW)               /* perhaps one now */
        upnp_start(n);
}

void node_portmap_start(npf_node *n)
{
    if (n->cfg.offline || n->cfg.no_portmap)
        return;
    n->pm_net = npf_portmap_net();
    pm_request(n);
    upnp_start(n);
}

void node_portmap_stop(npf_node *n)
{
    if (n->t_pm)
        npf_timer_cancel(n->loop, n->t_pm);
    n->t_pm = NULL;
    pm_forget(&n->pm_job);                  /* a running request's answer is dropped */
    pm_forget(&n->upnp_job);
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
    pm_forget(&n->pm_job);
    n->pm_ok = 0;
    n->pm_gw = PM_GW_UNKNOWN;
    n->pm_m = 0;
    if (!n->cfg.offline && !n->cfg.no_portmap)
        pm_request(n);
}

void node_portmap_net_change(npf_node *n)
{
    uint64_t net;
    if (n->cfg.offline || n->cfg.no_portmap || (net = npf_portmap_net()) == n->pm_net)
        return;                             /* the same gateway, the same address toward it */
    npf_logd("portmap: another network: the router's mapping asked for again, UPnP detected again");
    n->pm_net = net;
    node_portmap_restart(n);
    pm_forget(&n->upnp_job);
    n->upnp = UPNP_UNKNOWN;
    upnp_start(n);
}

/* the "pm" object of the nat profile: enums only (no address: secure mode too) */
void node_portmap_write(const npf_node *n, npf_jw *w)
{
    static const char *const gws[] = {NULL, "map", "private", "none", "nogw"};
    static const char *const ups[] = {NULL, "nogw", "none", "present"};
    const char *up = upnp_off(n) ? "off" : n->upnp < UPNP_ADDR ? ups[n->upnp]
                     : !public_ip4(n->upnp_ip) && !getenv("NPF_TEST_UPNP_GW") ? "private"
                     : n->nat_valid && n->nat_udp && memcmp(&n->pub_ip, n->upnp_ip, 4) != 0 ? "other" : "public";
    npf_jw_key(w, "pm");
    npf_jw_obj(w);
    if (n->cfg.offline || n->cfg.no_portmap) {
        npf_jw_kstr(w, "gw", "off");
    } else {
        if (n->pm_m)
            npf_jw_kstr(w, "m", n->pm_m == NPF_PORTMAP_PCP ? "pcp" : "natpmp");
        if (gws[n->pm_gw])
            npf_jw_kstr(w, "gw", gws[n->pm_gw]);
    }
    if (up)
        npf_jw_kstr(w, "upnp", up);
    npf_jw_end(w);
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

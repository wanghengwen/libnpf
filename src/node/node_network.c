/* UDP sockets, recovery and network-change monitoring. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "npf/candidates.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"

static void udp_new_port(npf_node *n);
static void udp_failed(npf_node *n, int fd, const char *why);
static void node_net_check(npf_node *n, const char *why);

/* ---- UDP ---- */


static void udp_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_node *n = arg;
    int k;
    (void)loop;
    /* a bounded batch: the loop is level-triggered, the rest is read on the
     * next turn after the timers (a flood does not starve them) */
    for (k = 0; k < 256; k++) {
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r < 0) {
            int se = 0;
            socklen_t sl = sizeof se;
            if (!npf_sock_again() && npf_sock_broken())
                udp_failed(n, fd, npf_sock_strerror());
            else if ((ev & NPF_EV_ERROR) && getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&se, &sl) == 0
                     && npf_sock_broken_code(se))
                udp_failed(n, fd, npf_sock_strerror_code(se));
            break;
        }
        node_udp_input(n, fd, buf, (size_t)r, &from);
    }
}

int node_udp_open4(npf_node *n)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int fd = npf_udp_socket(AF_INET, 0);
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)n->cfg.udp_port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || getsockname(fd, (struct sockaddr *)&a, &al) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    {
        /* AnLiu bursts at its pacing rate; a small receive buffer drops whole
         * flights while the loop is busy. The kernel caps this at rmem_max. */
        int sz = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    }
    n->udp_fd = fd;
    n->udp_port = ntohs(a.sin_port);
    return npf_loop_add(n->loop, fd, NPF_EV_READ, udp_cb, n);
}

/* the IPv6 main socket (nat-traversal.md 7.1 S0): v6 only, the IPv4 port when
 * it is free; none when the host has no IPv6 (not an error) */
void node_udp_open6(npf_node *n)
{
    struct sockaddr_in6 a;
    socklen_t al = sizeof a;
    int fd = npf_udp_socket(AF_INET6, 0), one = 1, k;
    if (fd < 0)
        return;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&one, sizeof one);
    for (k = 0; k < 2; k++) {
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(k == 0 ? n->udp_port : 0);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0)
            break;
    }
    if (k == 2 || getsockname(fd, (struct sockaddr *)&a, &al) < 0 || npf_loop_add(n->loop, fd, NPF_EV_READ, udp_cb, n) < 0) {
        npf_sock_close(fd);
        return;
    }
    {
        int sz = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof sz);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof sz);
    }
    n->udp6_fd = fd;
    n->udp6_port = ntohs(a.sin6_port);
}

/* ---- UDP on demand (cfg.udp_on_demand: hosted clients) ---- */


int npf_node_udp_open(npf_node *n)
{
    if (!n->cfg.udp_on_demand || n->udp_fd >= 0)
        return 0;
    if (node_udp_open4(n) < 0) {
        npf_loge("udp: cannot open the socket: %s", npf_sock_strerror());
        if (n->udp_fd >= 0)
            npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
        return -1;
    }
    if (!n->cfg.offline)
        node_udp_open6(n);
    udp_new_port(n);
    return 0;
}

/* a new main socket (another port): the address the last probe found is not
 * this socket's, unless the operator says it is public and that probe agreed */
static void udp_new_port(npf_node *n)
{
    if (n->cfg.udp_public && n->nat_valid && n->nat_udp && n->nat_kept_port) {
        n->srflx.sin_port = htons(n->udp_port);
        n->pred_port = 0;
        node_nat_regather(n);
        npf_log("udp: open (port %u), public as configured", n->udp_port);
    } else {
        /* the NAT measured before (a full probe): this socket's mapping only */
        n->nat_quick = n->nat_udp && n->nat.allocation != NPF_ALLOC_UNKNOWN;
        n->nat_valid = 0;
        npf_log("udp: open (port %u), %s", n->udp_port,
                n->nat_quick ? "its mapping to be measured (the NAT's port allocation is known)"
                             : "its NAT profile to be measured");
    }
}

int npf_node_udp_ready(npf_node *n)
{
    if (!n->cfg.udp_on_demand)
        return 1;
    if (n->udp_fd < 0 && npf_node_udp_open(n) < 0)
        return 1;                       /* none: the session goes without (the WS relay) */
    if (n->nat_valid)
        return 1;
    if (!n->probe)
        node_nat_refresh(n);
    if (!n->probe)
        return 1;                       /* no probe servers: as without one (local tests) */
    n->udp_waiters = 1;
    return 0;
}

void node_udp_close_idle(npf_node *n)
{
    if (n->udp_fd < 0 || n->udp_waiters)
        return;                             /* sessions wait for its profile: they need it */
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    n->udp_waiters = 0;
    npf_loop_del(n->loop, n->udp_fd);
    npf_sock_close(n->udp_fd);
    n->udp_fd = -1;
    if (n->udp6_fd >= 0) {
        npf_loop_del(n->loop, n->udp6_fd);
        npf_sock_close(n->udp6_fd);
        n->udp6_fd = -1;
    }
    npf_log("udp: closed until a session needs it");
}

/* ---- the network watch ----
 * libnpf mends its connections by itself when the process was suspended (an
 * iOS app in the background, a laptop's sleep) or the network changed (Wi-Fi
 * to mobile data): the application does nothing. A timer tick that comes
 * late on a clock that counts sleep tells a suspension; the interfaces'
 * addresses tell another network. Either way the signaling connection is
 * pinged at once (dropped when it does not answer), the NAT measured again,
 * the direct paths checked both ways, and the peers waiting to reconnect try
 * now. A main socket that failed (iOS reclaims a suspended app's sockets) is
 * reopened; the calls on it end and their peers reconnect. */

#define WATCH_TICK_MS    2000
#define WATCH_LATE_MS    10000          /* a tick this late: the process was suspended */
#define NETCHECK_MS      8000           /* the signaling must answer a check's ping this soon */
#define UDP_REOPEN_RETRY_MS 5000


/* a digest of the interfaces' addresses: IPv4, and the /64 prefix of global
 * IPv6 ones (temporary addresses change within it every day); in any order */
static uint32_t addrs_digest(void)
{
    npf_ifaddr a[32];
    int k, cnt = npf_if_list(a, 32);
    uint32_t sum = 0, nused = 0;
    for (k = 0; k < cnt; k++) {
        uint32_t h = 2166136261u;
        int i, len;
        if (a[k].loopback)
            continue;
        if (a[k].family == AF_INET6) {
            if ((a[k].addr[0] & 0xe0) != 0x20)  /* 2000::/3 only */
                continue;
            len = 8;
        } else {
            len = 4;
        }
        h = (h ^ (uint32_t)a[k].family) * 16777619u;
        for (i = 0; i < len; i++)
            h = (h ^ a[k].addr[i]) * 16777619u;
        sum += h;
        nused++;
    }
    return (sum ^ (nused * 2654435761u)) | 1;   /* never 0 ("not yet") */
}

/* the zero-length datagram to the discard port of the loopback: a socket
 * that has failed says so (an unconnected UDP socket hears no ICMP) */
static int udp_alive(int fd, int family)
{
    struct sockaddr_storage to;
    memset(&to, 0, sizeof to);
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&to;
        a->sin6_family = AF_INET6;
        a->sin6_addr.s6_addr[15] = 1;
        a->sin6_port = htons(9);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&to;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(0x7f000001);
        a->sin_port = htons(9);
    }
    if (sendto(fd, "", 0, 0, (struct sockaddr *)&to,
               family == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6) : (socklen_t)sizeof(struct sockaddr_in)) >= 0)
        return 1;
    return npf_sock_again() || !npf_sock_broken();
}

static void udp_reopen_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int old4 = n->udp_fd, old6 = n->udp6_fd, waiters = n->udp_waiters;
    uint16_t was = n->udp_port;
    (void)loop;
    n->t_udp_reopen = NULL;
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    if (old4 >= 0)
        npf_node_calls_lost_fd(n, old4, "udp_socket_failed");
    if (old6 >= 0)
        npf_node_calls_lost_fd(n, old6, "udp_socket_failed");
    if (old4 >= 0) {
        npf_loop_del(n->loop, old4);
        npf_sock_close(old4);
    }
    if (old6 >= 0) {
        npf_loop_del(n->loop, old6);
        npf_sock_close(old6);
    }
    n->udp_fd = n->udp6_fd = -1;
    n->udp_waiters = 0;
    if (n->cfg.udp_on_demand) {             /* the next session opens them */
        if (!waiters) {
            npf_log("udp: closed until a session needs it");
            return;
        }
        /* sessions waited for the profile: open and measure again now, they
         * start when it is there (they were left waiting for good) */
        if (npf_node_udp_ready(n) && n->on_udp_ready)
            n->on_udp_ready(n, n->hook_arg);
        return;
    }
    if (node_udp_open4(n) < 0) {
        npf_loge("udp: cannot open the socket again: %s; trying again in %d s", npf_sock_strerror(),
                 UDP_REOPEN_RETRY_MS / 1000);
        if (n->udp_fd >= 0)
            npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
        n->t_udp_reopen = npf_timer_add(n->loop, UDP_REOPEN_RETRY_MS, udp_reopen_cb, n);
        return;
    }
    if (!n->cfg.offline)
        node_udp_open6(n);
    udp_new_port(n);
    if (n->udp_port != was && !n->cfg.offline)
        node_portmap_restart(n);
    node_net_check(n, "the UDP socket was reopened");
}

/* a main socket failed: out of the loop now (no busy loop on its error),
 * reopened right after this callback */
static void udp_failed(npf_node *n, int fd, const char *why)
{
    npf_loop_del(n->loop, fd);
    if (n->t_udp_reopen)
        return;
    npf_logw("udp: the %s socket failed (%s), reopening", fd == n->udp6_fd ? "IPv6" : "IPv4", why);
    n->t_udp_reopen = npf_timer_add(n->loop, 0, udp_reopen_cb, n);
}

void npf_node_set_secure(npf_node *n, int on)
{
    if (n->cfg.secure == (on != 0))
        return;
    n->cfg.secure = on != 0;
    npf_udp_hook_on(!on);
    npf_log("connect_mode %s: %s", on ? "secure" : "p2p",
            on ? "relays only, no address to the peers, a VPN kept" : "direct paths first, around a VPN");
    npf_node_report_nat(n);
    npf_node_udp_reset(n, "connect_mode changed");  /* the sessions open again under it */
}

void npf_node_udp_reset(npf_node *n, const char *why)
{
    if (n->t_udp_reopen || (n->udp_fd < 0 && n->udp6_fd < 0))
        return;
    npf_log("udp: opening the sockets again (%s)", why);
    if (n->udp_fd >= 0)
        npf_loop_del(n->loop, n->udp_fd);
    if (n->udp6_fd >= 0)
        npf_loop_del(n->loop, n->udp6_fd);
    n->t_udp_reopen = npf_timer_add(n->loop, 0, udp_reopen_cb, n);
}

static void netcheck_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_netcheck = NULL;
    if (n->sig && n->online && npf_sig_last_rx(n->sig) < n->netcheck_ms) {
        n->backoff_ms = 0;
        node_sig_abort(n, "no answer after a network change");
    }
}

static void node_net_check(npf_node *n, const char *why)
{
    n->netchecks++;
    npf_log("network: %s: checking the connections", why);
    if (n->udp_fd >= 0 && !n->t_udp_reopen && !udp_alive(n->udp_fd, AF_INET)) {
        udp_failed(n, n->udp_fd, npf_sock_strerror());
        return;                             /* the reopen checks again */
    }
    if (n->udp6_fd >= 0 && !n->t_udp_reopen && !udp_alive(n->udp6_fd, AF_INET6)) {
        udp_failed(n, n->udp6_fd, npf_sock_strerror());
        return;
    }
    if (!n->cfg.offline && !n->dormant) {
        if (n->sig && n->online) {
            n->netcheck_ms = npf_mono_ms();
            npf_sig_ping(n->sig);
            if (n->t_netcheck)
                npf_timer_cancel(n->loop, n->t_netcheck);
            n->t_netcheck = npf_timer_add(n->loop, NETCHECK_MS, netcheck_cb, n);
            if (n->udp_fd >= 0) {           /* the mapping (perhaps a new NAT) */
                n->nat_quick = n->nat_udp && n->nat.allocation != NPF_ALLOC_UNKNOWN;
                node_nat_refresh(n);
            }
        } else {
            node_reconnect_now(n);
        }
    }
    npf_node_check_paths(n, why);
    n->repunch_on_nat = 1;                  /* with the new NAT's candidates (nat.c) */
    if (n->hooks.on_net_change)
        n->hooks.on_net_change(n, why, n->hook_arg);
}

static void watch_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t now = npf_boot_ms(), late = now - n->watch_boot_ms - WATCH_TICK_MS;
    uint32_t d = addrs_digest();
    char why[64];
    n->t_watch = npf_timer_add(loop, WATCH_TICK_MS, watch_cb, n);
    n->watch_boot_ms = now;
#ifndef _WIN32
    {   /* tests: NPF_TEST_UDP_FAIL=FILE: when FILE appears, the IPv4 socket
         * fails as a reclaimed one does (every call on it: ENOTSOCK) */
        const char *f = getenv("NPF_TEST_UDP_FAIL");
        int z;
        if (f && n->udp_fd >= 0 && remove(f) == 0 && (z = open("/dev/null", O_RDONLY)) >= 0) {
            npf_logw("test: the UDP socket fails now");
            dup2(z, n->udp_fd);
            close(z);
        }
    }
#endif
    /* a failed socket may never wake the loop (epoll forgets a descriptor
     * that is gone): asked every tick, one empty datagram each */
    if (!n->t_udp_reopen) {
        int dead = n->udp_fd >= 0 && !udp_alive(n->udp_fd, AF_INET)      ? n->udp_fd
                   : n->udp6_fd >= 0 && !udp_alive(n->udp6_fd, AF_INET6) ? n->udp6_fd
                                                                          : -1;
        if (dead >= 0) {                    /* each checked once; the error of the one that failed */
            n->watch_addrs = d;
            udp_failed(n, dead, npf_sock_strerror());
            return;                         /* the reopen checks the connections */
        }
    }
    if (late >= WATCH_LATE_MS) {
        snprintf(why, sizeof why, "suspended for %lld s", (long long)(late / 1000));
        n->watch_addrs = d;
        node_net_check(n, why);
    } else if (d != n->watch_addrs) {
        int first = n->watch_addrs == 0;
        n->watch_addrs = d;
        if (!first)
            node_net_check(n, "the addresses changed");
    }
}

void node_watch_start(npf_node *n)
{
    if (n->cfg.udp_on_demand)
        return;                             /* hosted clients: servers, many instances */
    n->watch_boot_ms = npf_boot_ms();
    n->watch_addrs = addrs_digest();
    n->t_watch = npf_timer_add(n->loop, WATCH_TICK_MS, watch_cb, n);
}

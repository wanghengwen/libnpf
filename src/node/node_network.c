/* UDP sockets, recovery and network-change monitoring. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"
#include "home.h"

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

/* a main socket of family fam bound to port (0: any; IPv6: v6 only), on the
 * loop: the fd and its port in *bound, or -1 */
static int udp_open(npf_node *n, int fam, uint16_t port, uint16_t *bound)
{
    struct sockaddr_storage a;
    socklen_t al = sizeof a;
    int fd = npf_udp_socket(fam, 0), one = 1, sz = 4 << 20;
    if (fd < 0)
        return -1;
    if (fam == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&one, sizeof one);
    memset(&a, 0, sizeof a);
    a.ss_family = fam == AF_INET6 ? AF_INET6 : AF_INET;
    if (fam == AF_INET6)
        ((struct sockaddr_in6 *)&a)->sin6_port = htons(port);
    else
        ((struct sockaddr_in *)&a)->sin_port = htons(port);
    /* AnLiu bursts at its pacing rate; a small receive buffer drops whole
     * flights while the loop is busy. The kernel caps this at rmem_max. */
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof sz);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof sz);
    if (bind(fd, (struct sockaddr *)&a, npf_addr_len(&a)) < 0
        || getsockname(fd, (struct sockaddr *)&a, &al) < 0 || npf_loop_add(n->loop, fd, NPF_EV_READ, udp_cb, n) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    *bound = npf_addr_port(&a);
    return fd;
}

int node_udp_open(npf_node *n)
{
    if ((n->udp_fd = udp_open(n, AF_INET, (uint16_t)n->cfg.udp_port, &n->udp_port)) < 0)
        return -1;
    /* the IPv6 main socket (nat-traversal.md 7.1 S0): the IPv4 port when it
     * is free; none when the host has no IPv6 (not an error) */
    if (!n->cfg.offline && (n->udp6_fd = udp_open(n, AF_INET6, n->udp_port, &n->udp6_port)) < 0)
        n->udp6_fd = udp_open(n, AF_INET6, 0, &n->udp6_port);
    return 0;
}

void node_udp_close(npf_node *n)
{
    if (n->udp_fd >= 0) {
        npf_loop_del(n->loop, n->udp_fd);
        npf_sock_close(n->udp_fd);
    }
    if (n->udp6_fd >= 0) {
        npf_loop_del(n->loop, n->udp6_fd);
        npf_sock_close(n->udp6_fd);
    }
    n->udp_fd = n->udp6_fd = -1;
}

/* ---- UDP on demand (cfg.udp_on_demand: hosted clients) ---- */

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

int npf_node_udp_open(npf_node *n)
{
    if (!n->cfg.udp_on_demand || n->udp_fd >= 0)
        return 0;
    if (node_udp_open(n) < 0) {
        npf_loge("udp: cannot open the socket: %s", npf_sock_strerror());
        return -1;
    }
    udp_new_port(n);
    return 0;
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
    node_udp_close(n);
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
    npf_addr_parse(family == AF_INET6 ? "[::1]:9" : "127.0.0.1:9", &to);
    if (sendto(fd, "", 0, 0, (struct sockaddr *)&to, npf_addr_len(&to)) >= 0)
        return 1;
    return npf_sock_again() || !npf_sock_broken();
}

/* a main socket that failed (udp_alive), the IPv4 one first; -1 none */
static int udp_dead(const npf_node *n)
{
    return n->udp_fd >= 0 && !udp_alive(n->udp_fd, AF_INET)      ? n->udp_fd
           : n->udp6_fd >= 0 && !udp_alive(n->udp6_fd, AF_INET6) ? n->udp6_fd
                                                                  : -1;
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
    node_udp_close(n);
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
    if (node_udp_open(n) < 0) {
        npf_loge("udp: cannot open the socket again: %s; trying again in %d s", npf_sock_strerror(),
                 UDP_REOPEN_RETRY_MS / 1000);
        n->t_udp_reopen = npf_timer_add(n->loop, UDP_REOPEN_RETRY_MS, udp_reopen_cb, n);
        return;
    }
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

int npf_node_udp_reset(npf_node *n, const char *why)
{
    if (n->t_udp_reopen)
        return n->cfg.udp_on_demand ? -1 : 0;
    if (n->udp_fd < 0 && n->udp6_fd < 0)
        return -1;
    npf_log("udp: opening the sockets again (%s)", why);
    if (n->udp_fd >= 0)
        npf_loop_del(n->loop, n->udp_fd);
    if (n->udp6_fd >= 0)
        npf_loop_del(n->loop, n->udp6_fd);
    n->t_udp_reopen = npf_timer_add(n->loop, 0, udp_reopen_cb, n);
    return n->cfg.udp_on_demand ? -1 : 0;
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
    int fd;
    npf_log("network: %s: checking the connections", why);
    if (!n->t_udp_reopen && (fd = udp_dead(n)) >= 0) {
        udp_failed(n, fd, npf_sock_strerror());
        return;                             /* the reopen checks again */
    }
    if (!n->cfg.offline && !n->dormant) {
        if (n->sig && n->online) {
            n->netcheck_ms = npf_mono_ms();
            npf_sig_ping(n->sig);
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
    node_home_net_change(n);                /* the spare follows a new address at once */
    n->repunch_on_nat = 1;                  /* with the new NAT's candidates (nat.c) */
    node_portmap_net_change(n);             /* another router: its mapping */
    if (n->hooks.on_net_change)
        n->hooks.on_net_change(n, why, n->hook_arg);
}

static void watch_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t now = npf_boot_ms(), late = now - n->watch_boot_ms - WATCH_TICK_MS;
    uint32_t d = addrs_digest();
    char why[64];
    int dead;
    n->t_watch = npf_timer_add(loop, WATCH_TICK_MS, watch_cb, n);
    n->watch_boot_ms = now;
#ifndef _WIN32
    {   /* tests: NPF_TEST_UDP_FAIL=FILE: when FILE appears, the IPv4 socket
         * fails as a reclaimed one does (every call on it: ENOTSOCK) */
        const char *f = n->th.udp_fail;
        int z;
        if (f && n->udp_fd >= 0 && remove(f) == 0 && (z = open("/dev/null", O_RDONLY)) >= 0) {
            npf_logw("test: the UDP socket fails now");
            dup2(z, n->udp_fd);
            close(z);
        }
        /* tests: NPF_TEST_WS_FILE=FILE: while FILE exists the node has no
         * UDP (its profile says so, its sessions move to the WS relay); when
         * it goes, UDP works again (the sessions go back, udp_back) */
        if ((f = n->th.ws_file) != NULL && (z = access(f, F_OK) == 0) != n->th.no_udp) {
            n->th.no_udp = z;
            npf_logw("test: UDP %s", z ? "gone" : "back");
            npf_node_report_nat(n);         /* as a probe's new profile would */
            if (!z)
                n->udp_back_ms = npf_mono_ms();
            npf_node_calls_decide(n);
        }
    }
#endif
    /* a failed socket may never wake the loop (epoll forgets a descriptor
     * that is gone): asked every tick, one empty datagram each */
    if (!n->t_udp_reopen && (dead = udp_dead(n)) >= 0) {   /* the error of the one that failed */
        n->watch_addrs = d;
        udp_failed(n, dead, npf_sock_strerror());
        return;                             /* the reopen checks the connections */
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

/* The system layer (npf/sys.h) on POSIX: Linux, macOS, iOS, Android, the
 * BSDs. The portable rest is in sys.c. */
#define _GNU_SOURCE
#include "npf/text.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "npf/sys.h"

#ifdef __linux__
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#ifndef SIOCOUTQ                        /* linux/sockios.h, absent with musl */
#define SIOCOUTQ TIOCOUTQ
#endif
#ifndef SIOCOUTQNSD
#define SIOCOUTQNSD 0x894B
#endif
#endif

#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#if !TARGET_OS_IPHONE                       /* not in the iOS SDK */
#include <net/route.h>
#endif
#include <sys/sysctl.h>
#endif

int npf_sys_init(void)
{
    return 0;
}

int npf_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    return fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ? -1 : 0;
}

#ifdef SOCK_NONBLOCK

int npf_socket(int family, int type, int proto, int blocking)
{
    return socket(family, type | SOCK_CLOEXEC | (blocking ? 0 : SOCK_NONBLOCK), proto);
}

int npf_accept(int lfd)
{
    return accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

#else /* macOS / BSD without the socket type flags */

static int setup_fd(int fd, int blocking)
{
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    {
        int one = 1;                /* there is no MSG_NOSIGNAL */
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    }
#endif
    if (!blocking && npf_set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int npf_socket(int family, int type, int proto, int blocking)
{
    return setup_fd(socket(family, type, proto), blocking);
}

int npf_accept(int lfd)
{
    return setup_fd(accept(lfd, NULL, NULL), 0);
}

#endif

void npf_sock_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

void npf_sock_listen_opts(int fd, int type)
{
    int one = 1;
    if (fd >= 0 && type == SOCK_STREAM)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
}

int npf_sock_err(void)
{
    return errno;
}

const char *npf_sock_strerror_code(int err)
{
    return strerror(err);
}

static int masklen(const struct sockaddr *m)
{
    const uint8_t *b;
    int len, i, n = 0;
    if (!m)
        return -1;
    if (m->sa_family == AF_INET) {
        b = (const uint8_t *)&((const struct sockaddr_in *)m)->sin_addr;
        len = 4;
    } else if (m->sa_family == AF_INET6) {
        b = (const uint8_t *)&((const struct sockaddr_in6 *)m)->sin6_addr;
        len = 16;
    } else {
        return -1;
    }
    for (i = 0; i < len; i++) {
        uint8_t v = b[i];
        while (v & 0x80) {
            n++;
            v = (uint8_t)(v << 1);
        }
        if (b[i] != 0xff)
            break;
    }
    return n;
}

int npf_if_list(npf_ifaddr *out, int max)
{
    struct ifaddrs *ifa, *p;
    int n = 0;
    if (max <= 0 || getifaddrs(&ifa) < 0)
        return 0;
    for (p = ifa; p && n < max; p = p->ifa_next) {
        if (!p->ifa_addr || !(p->ifa_flags & IFF_UP))
            continue;
        if (p->ifa_addr->sa_family == AF_INET)
            memcpy(out[n].addr, &((struct sockaddr_in *)p->ifa_addr)->sin_addr, 4);
        else if (p->ifa_addr->sa_family == AF_INET6)
            memcpy(out[n].addr, &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr, 16);
        else
            continue;
        out[n].family = p->ifa_addr->sa_family;
        out[n].prefix = masklen(p->ifa_netmask);
        out[n].loopback = (p->ifa_flags & IFF_LOOPBACK) != 0;
        n++;
    }
    freeifaddrs(ifa);
    return n;
}

#if defined(__APPLE__)

/* the application firewall's global state; an ad-hoc-signed program is not in
 * its list, and --getappblocked wrongly reports it permitted, so only the
 * global switch counts (measured 2026-10-06: an unsolicited first datagram
 * blocks the flow both ways for tens of seconds) */
int npf_firewall_lead_ms(void)
{
#if TARGET_OS_IPHONE
    return 0;                               /* iOS has no application firewall, nor popen */
#else
    char line[256];
    int on = 0;
    FILE *f = popen("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null", "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f))
        if (strstr(line, "State = 1") || strstr(line, "State = 2"))
            on = 1;
    pclose(f);
    return on ? 300 : 0;
#endif
}

#if TARGET_OS_IPHONE
/* iOS: no routing table for apps; no router port mapping on a phone */
int npf_default_gw4(uint32_t *gw)
{
    (void)gw;
    return -1;
}
#else
/* the routing table through sysctl: the default route's RTA_GATEWAY */
int npf_default_gw4(uint32_t *gw)
{
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
    size_t len = 0;
    char *buf, *p;
    int r = -1;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0 || len == 0)
        return -1;
    buf = malloc(len);
    if (!buf)
        return -1;
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        free(buf);
        return -1;
    }
    for (p = buf; p + sizeof(struct rt_msghdr) <= buf + len && r < 0;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)p;
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        struct sockaddr_in *dst = NULL, *gwa = NULL;
        int i;
        if (rtm->rtm_msglen == 0)
            break;
        for (i = 0; i < RTAX_MAX; i++) {
            if (!(rtm->rtm_addrs & (1 << i)))
                continue;
            if (i == RTAX_DST && sa->sa_family == AF_INET)
                dst = (struct sockaddr_in *)sa;
            if (i == RTAX_GATEWAY && sa->sa_family == AF_INET)
                gwa = (struct sockaddr_in *)sa;
            /* sockaddrs are padded to 4 bytes; a zero length still takes 4 */
            sa = (struct sockaddr *)((char *)sa + (sa->sa_len ? ((sa->sa_len + 3) & ~3) : 4));
        }
        if (dst && gwa && dst->sin_addr.s_addr == 0 && gwa->sin_addr.s_addr != 0) {
            *gw = gwa->sin_addr.s_addr;
            r = 0;
        }
        p += rtm->rtm_msglen;
    }
    free(buf);
    return r;
}
#endif

#elif defined(__linux__) && !defined(__ANDROID__)

int npf_firewall_lead_ms(void)
{
    return 0;
}

int npf_default_gw4(uint32_t *gw)
{
    FILE *f = fopen("/proc/net/route", "r");
    char line[256];
    if (!f)
        return -1;
    if (!fgets(line, sizeof line, f)) {             /* header */
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char iface[64];
        const char *p = line;
        unsigned long dest, gwaddr, flags;
        if (npf_text_word(&p, iface, sizeof iface) == 0 && npf_text_hex(&p, &dest) == 0
            && npf_text_hex(&p, &gwaddr) == 0 && npf_text_hex(&p, &flags) == 0
            && dest == 0 && (flags & 0x2)) {        /* default route, RTF_GATEWAY */
            fclose(f);
            *gw = (uint32_t)gwaddr;                 /* already network order */
            return gwaddr ? 0 : -1;
        }
    }
    fclose(f);
    return -1;
}

#else

/* elsewhere, Android among them: apps cannot read the routing table (no
 * router port mapping on a phone, as on iOS) */
int npf_firewall_lead_ms(void)
{
    return 0;
}

int npf_default_gw4(uint32_t *gw)
{
    (void)gw;
    return -1;
}

#endif

int npf_file_private(const char *path)
{
    return chmod(path, 0600);
}

int npf_file_too_open(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & 077) != 0;
}

int npf_path_is_abs(const char *p)
{
    return p[0] == '/';
}

int npf_abspath(const char *p, char *out, size_t cap)
{
    char cwd[1024];
    if (npf_path_is_abs(p))
        return snprintf(out, cap, "%s", p) < (int)cap ? 0 : -1;
    if (!getcwd(cwd, sizeof cwd))
        return -1;
    return snprintf(out, cap, "%s/%s", cwd, p) < (int)cap ? 0 : -1;
}

/* A TCP connection's kernel side, for a log line when it stalls: the bytes
 * not yet acked and not yet sent, retransmissions, RTT and RTO (Linux; "-"
 * elsewhere). Bytes stuck here with retransmissions: the path; none while
 * the peer heard nothing: ours. */
const char *npf_sock_tcp_diag(int fd, char *buf, size_t cap)
{
#ifdef __linux__
    struct tcp_info ti;
    socklen_t tl = sizeof ti;
    int outq = -1, unsent = -1;
    ioctl(fd, SIOCOUTQ, &outq);
    ioctl(fd, SIOCOUTQNSD, &unsent);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0) {
        snprintf(buf, cap, "kernel send queue %d B (%d unsent), %u segments unacked, %u retransmits now (%u total), "
                 "rtt %u ms, rto %u ms", outq, unsent, ti.tcpi_unacked, ti.tcpi_retransmits, ti.tcpi_total_retrans,
                 ti.tcpi_rtt / 1000, ti.tcpi_rto / 1000);
        return buf;
    }
#endif
    (void)fd;
    snprintf(buf, cap, "-");
    return buf;
}

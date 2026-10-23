/* Portable system layer (npf/sys.h): POSIX and Windows. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "npf/log.h"
#include "npf/platform.h"
#include "npf/sys.h"

#ifdef _WIN32
#include <direct.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <sddl.h>
#include <aclapi.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET _WSAIOW(IOC_VENDOR, 15)
#endif

int npf_sys_init(void)
{
    WSADATA wd;
    /* reference counted and thread-safe: every node calls it */
    return WSAStartup(MAKEWORD(2, 2), &wd) != 0 ? -1 : 0;
}

int npf_set_nonblock(int fd)
{
    u_long on = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &on) == 0 ? 0 : -1;
}

int npf_socket(int family, int type, int proto, int blocking)
{
    SOCKET s;
    npf_sys_init();
    s = WSASocketW(family, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET)
        return -1;
    if (type == SOCK_DGRAM) {
        /* an ICMP port unreachable must not fail the next recvfrom() (punching sends to dead ports) */
        BOOL off = FALSE;
        DWORD ret;
        WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
        WSAIoctl(s, SIO_UDP_NETRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
    }
    if (!blocking && npf_set_nonblock((int)s) < 0) {
        closesocket(s);
        return -1;
    }
    return (int)s;
}

int npf_accept(int lfd)
{
    SOCKET s = accept((SOCKET)lfd, NULL, NULL);
    if (s == INVALID_SOCKET)
        return -1;
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    if (npf_set_nonblock((int)s) < 0) {
        closesocket(s);
        return -1;
    }
    return (int)s;
}

void npf_sock_close(int fd)
{
    if (fd >= 0)
        closesocket((SOCKET)fd);
}

void npf_sock_listen_opts(int fd, int type)
{
    BOOL one = TRUE;
    (void)type;
    if (fd >= 0)
        setsockopt((SOCKET)fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one);
}

int npf_sock_again(void)
{
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
}

int npf_sock_in_use(void)
{
    int e = WSAGetLastError();
    return e == WSAEADDRINUSE || e == WSAEACCES;
}

int npf_sock_broken_code(int e)
{
    return e == WSAENOTSOCK || e == WSAEBADF || e == WSAENOTCONN || e == WSAESHUTDOWN || e == WSAENETDOWN;
}

int npf_sock_broken(void)
{
    return npf_sock_broken_code(WSAGetLastError());
}

int npf_sock_inprogress(void)
{
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
}

const char *npf_sock_strerror(void)
{
    return npf_sock_strerror_code(WSAGetLastError());
}

const char *npf_sock_strerror_code(int e)
{
    static NPF_THREAD_LOCAL char buf[160];
    /* English, like the rest of the log; the localized text would arrive in the ANSI code page */
    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)e,
                        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof buf, NULL))
        snprintf(buf, sizeof buf, "error %d", e);
    else
        buf[strcspn(buf, "\r\n")] = 0;
    return buf;
}

int npf_if_list(npf_ifaddr *out, int max)
{
    ULONG len = 16384;
    IP_ADAPTER_ADDRESSES *aa = NULL, *a;
    int n = 0, tries;
    for (tries = 0; tries < 3; tries++) {
        ULONG r;
        aa = malloc(len);
        if (!aa)
            return 0;
        r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                 NULL, aa, &len);
        if (r == NO_ERROR)
            break;
        free(aa);
        aa = NULL;
        if (r != ERROR_BUFFER_OVERFLOW)
            return 0;
    }
    for (a = aa; a && n < max; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        if (a->OperStatus != IfOperStatusUp)
            continue;
        for (u = a->FirstUnicastAddress; u && n < max; u = u->Next) {
            struct sockaddr *sa = u->Address.lpSockaddr;
            if (sa->sa_family == AF_INET)
                memcpy(out[n].addr, &((struct sockaddr_in *)sa)->sin_addr, 4);
            else if (sa->sa_family == AF_INET6)
                memcpy(out[n].addr, &((struct sockaddr_in6 *)sa)->sin6_addr, 16);
            else
                continue;
            out[n].family = sa->sa_family;
            out[n].prefix = u->OnLinkPrefixLength;
            out[n].loopback = a->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            n++;
        }
    }
    free(aa);
    return n;
}

/* Windows Defender Firewall lets replies to our own traffic in; whether an
 * early unsolicited packet poisons the flow has not been measured: on time */
int npf_firewall_lead_ms(void)
{
    return 0;
}

int npf_default_gw4(uint32_t *gw)
{
    MIB_IPFORWARDROW row;
    if (GetBestRoute(inet_addr("8.8.8.8"), 0, &row) != NO_ERROR || row.dwForwardNextHop == 0)
        return -1;
    *gw = row.dwForwardNextHop;             /* network order */
    return 0;
}

int npf_mkdir(const char *path)
{
    if (_mkdir(path) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

int npf_file_private(const char *path)
{
    /* SYSTEM, Administrators and the file's owner; inherited entries removed */
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD r;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",
                                                              SDDL_REVISION_1, &sd, NULL))
        return -1;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
        LocalFree(sd);
        return -1;
    }
    r = SetNamedSecurityInfoA((char *)path, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl,
                              NULL);
    LocalFree(sd);
    return r == ERROR_SUCCESS ? 0 : -1;
}

int npf_file_too_open(const char *path)
{
    (void)path;
    return 0;
}

int npf_path_is_abs(const char *p)
{
    return (p[0] && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || (p[0] == '\\' && p[1] == '\\');
}

int npf_abspath(const char *p, char *out, size_t cap)
{
    DWORD r = GetFullPathNameA(p, (DWORD)cap, out, NULL);
    return r > 0 && r < cap ? 0 : -1;
}

#else /* POSIX */

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

int npf_sock_again(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

int npf_sock_in_use(void)
{
    return errno == EADDRINUSE || errno == EACCES;
}

int npf_sock_broken_code(int e)
{
    /* a defunct socket (XNU: a suspended app's, reclaimed) fails with
     * ENOTCONN or EBADF; EPIPE and ECONNABORTED after a shutdown */
    return e == EBADF || e == ENOTSOCK || e == ENOTCONN || e == EPIPE || e == ECONNABORTED || e == ENETDOWN;
}

int npf_sock_broken(void)
{
    return npf_sock_broken_code(errno);
}

int npf_sock_inprogress(void)
{
    return errno == EINPROGRESS;
}

const char *npf_sock_strerror(void)
{
    return strerror(errno);
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

int npf_mkdir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

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

#endif

int npf_mkdir_p(const char *path)
{
    char buf[1024];
    size_t i, n = strlen(path);
    if (n == 0 || n >= sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] == '/' || buf[i] == '\\') {
            char c = buf[i];
            if (buf[i - 1] == ':')          /* "C:\" */
                continue;
            buf[i] = 0;
            npf_mkdir(buf);
            buf[i] = c;
        }
    }
    return npf_mkdir(buf);
}

/* ---- scratch buffers (sys.h) ---- */

#define SCRATCH_KEEP 4

typedef struct {
    void *p;
    size_t cap;
    int busy;
} scratch_slot;

static NPF_THREAD_LOCAL scratch_slot t_scratch[SCRATCH_KEEP];

void *npf_scratch(size_t n)
{
    scratch_slot *s = t_scratch, *empty = NULL, *small = NULL;
    int i;
    for (i = 0; i < SCRATCH_KEEP; i++) {
        if (s[i].busy)
            continue;
        if (s[i].p && s[i].cap >= n) {
            s[i].busy = 1;
            return s[i].p;
        }
        if (!s[i].p && !empty)
            empty = &s[i];
        else if (s[i].p && !small)
            small = &s[i];
    }
    if (!empty && small) {          /* too small: replaced by a bigger one */
        free(small->p);
        small->p = NULL;
        empty = small;
    }
    if (!empty)
        return malloc(n);           /* nested deeper than SCRATCH_KEEP: not kept */
    if (!(empty->p = malloc(n)))
        return NULL;
    empty->cap = n;
    empty->busy = 1;
    return empty->p;
}

void npf_scratch_done(void *p)
{
    int i;
    if (!p)
        return;
    for (i = 0; i < SCRATCH_KEEP; i++)
        if (t_scratch[i].p == p) {
            t_scratch[i].busy = 0;
            return;
        }
    free(p);
}

void npf_scratch_trim(void)
{
    int i;
    for (i = 0; i < SCRATCH_KEEP; i++)
        if (t_scratch[i].p && !t_scratch[i].busy) {
            free(t_scratch[i].p);
            t_scratch[i].p = NULL;
            t_scratch[i].cap = 0;
        }
}

/* ---- UDP sends (sys.h) ---- */

#define SEND_ERR_QUIET_MS 60000

/* the last reported failure of this thread: the same error again within a
 * minute is only counted */
typedef struct {
    int      err;
    int64_t  at;
    unsigned more;
} send_err;

static NPF_THREAD_LOCAL send_err t_send_err;

static int dst_len(const struct sockaddr *to)
{
    return to->sa_family == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
}

static void dst_txt(const struct sockaddr *to, char *out, size_t cap)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    unsigned port;
    if (to->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)to)->sin6_addr, ip, sizeof ip);
        port = ntohs(((const struct sockaddr_in6 *)to)->sin6_port);
    } else {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)to)->sin_addr, ip, sizeof ip);
        port = ntohs(((const struct sockaddr_in *)to)->sin_port);
    }
    snprintf(out, cap, "%s:%u", ip, port);
}

/* 1 when this one is only counted */
static int quiet(send_err *e, int err, int64_t now)
{
    if (err == e->err && now - e->at < SEND_ERR_QUIET_MS) {
        e->more++;
        return 1;
    }
    return 0;
}

static void report(send_err *e, int level, int err, int64_t now, const struct sockaddr *to, const char *hint)
{
    char d[80];
    dst_txt(to, d, sizeof d);
    if (e->more)
        npf_log_at(level, __FILE__, __LINE__,
                   "udp: sending to %s failed: %s%s (and %u more failures of this kind in the last minute)", d,
                   npf_sock_strerror_code(err), hint, e->more);
    else
        npf_log_at(level, __FILE__, __LINE__, "udp: sending to %s failed: %s%s", d, npf_sock_strerror_code(err),
                   hint);
    e->err = err;
    e->at = now;
    e->more = 0;
}

#ifdef __APPLE__
static NPF_THREAD_LOCAL send_err t_lan_err;

/* a private IPv4 destination on a subnet of one of our interfaces */
static int on_local_subnet(const struct sockaddr *to)
{
    npf_ifaddr ifs[32];
    uint32_t a;
    int n, i;
    if (to->sa_family != AF_INET)
        return 0;
    a = ntohl(((const struct sockaddr_in *)to)->sin_addr.s_addr);
    if ((a >> 24) != 10 && (a >> 20) != 0xac1 && (a >> 16) != 0xc0a8 && (a >> 16) != 0xa9fe)
        return 0;                   /* 10/8, 172.16/12, 192.168/16, 169.254/16 */
    n = npf_if_list(ifs, 32);
    for (i = 0; i < n; i++) {
        uint32_t b, m;
        if (ifs[i].family != AF_INET || ifs[i].loopback || ifs[i].prefix <= 0 || ifs[i].prefix > 32)
            continue;
        b = (uint32_t)ifs[i].addr[0] << 24 | (uint32_t)ifs[i].addr[1] << 16 | (uint32_t)ifs[i].addr[2] << 8
            | ifs[i].addr[3];
        m = ifs[i].prefix == 32 ? 0xffffffffu : ~(0xffffffffu >> ifs[i].prefix);
        if ((a & m) == (b & m))
            return 1;
    }
    return 0;
}
#endif

static void send_failed(const struct sockaddr *to, int err)
{
    int64_t now = npf_mono_ms();
    int level = NPF_LOG_WARN;
#ifdef __APPLE__
    /* macOS's local network privacy: a program without the permission (one
     * started over SSH, say) gets "No route to host" for every address of
     * the local network, while the internet works */
    if (err == EHOSTUNREACH && on_local_subnet(to)) {
        if (!quiet(&t_lan_err, err, now))
            report(&t_lan_err, NPF_LOG_WARN, err, now, to,
                   "; macOS blocks the local network for this program: allow npf under System Settings > "
                   "Privacy & Security > Local Network, or run it as a launchd daemon");
        return;
    }
#endif
#ifdef _WIN32
    if (err == WSAENETUNREACH || err == WSAEHOSTUNREACH || err == WSAEADDRNOTAVAIL || err == WSAEAFNOSUPPORT)
        level = NPF_LOG_DEBUG;
#else
    /* punching tries every candidate of the peer: some are not routable
     * from here (another family, a LAN that is not ours, a host gone) */
    if (err == ENETUNREACH || err == EHOSTUNREACH || err == EADDRNOTAVAIL || err == EAFNOSUPPORT)
        level = NPF_LOG_DEBUG;
#ifdef EHOSTDOWN
    if (err == EHOSTDOWN)           /* macOS: no ARP answer on the LAN (not the privacy block) */
        level = NPF_LOG_DEBUG;
#endif
#endif
    if (!quiet(&t_send_err, err, now))
        report(&t_send_err, level, err, now, to, "");
}

#ifdef _WIN32
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif
/* 127.0.0.0/8, ::1, or ::ffff:127.x */
static int is_loopback(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return (ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr) >> 24) == 127;
    if (sa->sa_family == AF_INET6) {
        const unsigned char *a = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
        static const unsigned char one[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        return memcmp(a, one, 16) == 0 || (memcmp(a, mapped, 12) == 0 && a[12] == 127);
    }
    return 0;
}

/* A socket taken around a VPN (npf_vpn_bypass: IP_UNICAST_IF) sends every
 * datagram out on the physical interface, so one to this computer's
 * loopback (a direct peer on 127.0.0.1) never arrives: that one goes without
 * it, the socket's interface put back right after. IP_UNICAST_IF acts on
 * sending only: the answers come in as before. */
static int sendto_loopback(int fd, const void *buf, size_t len, const struct sockaddr *sa)
{
    int v6 = sa->sa_family == AF_INET6, lvl = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
    int opt = v6 ? IPV6_UNICAST_IF : IP_UNICAST_IF, cl = (int)sizeof(DWORD), r, err;
    DWORD cur = 0, none = 0;
    if (getsockopt((SOCKET)fd, lvl, opt, (char *)&cur, &cl) != 0 || cur == 0
        || setsockopt((SOCKET)fd, lvl, opt, (const char *)&none, sizeof none) != 0)
        return sendto(fd, buf, len, MSG_DONTWAIT, sa, dst_len(sa));
    r = sendto(fd, buf, len, MSG_DONTWAIT, sa, dst_len(sa));
    err = WSAGetLastError();
    setsockopt((SOCKET)fd, lvl, opt, (const char *)&cur, sizeof cur);
    WSASetLastError(err);
    return r;
}
#endif

int npf_udp_send(int fd, const void *buf, size_t len, const void *to)
{
    const struct sockaddr *sa = to;
    int err;
#ifdef _WIN32
    if (npf_udp_hook_is_on() && is_loopback(sa)) {
        if (sendto_loopback(fd, buf, len, sa) >= 0)
            return 0;
    } else
#endif
    if (sendto(fd, buf, len, MSG_DONTWAIT, sa, dst_len(sa)) >= 0)
        return 0;
#ifdef _WIN32
    err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAEINTR)
        return -1;
#else
    err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == ENOBUFS)
        return -1;                  /* a full queue: the datagram is lost, nothing to tell */
#endif
    send_failed(sa, err);
    return -1;
}

/* ---- the node's UDP sockets (sys.h) ---- */

static npf_udp_hook_fn g_udp_hook;
static void *g_udp_hook_arg;
static int g_udp_hook_on = 1;
static int g_udp_hook_failed;               /* the last one failed: said once until one works */

void npf_udp_hook_set(npf_udp_hook_fn fn, void *arg)
{
    __atomic_store_n(&g_udp_hook_arg, arg, __ATOMIC_RELEASE);
    __atomic_store_n(&g_udp_hook, fn, __ATOMIC_RELEASE);
}

void npf_udp_hook_on(int on)
{
    __atomic_store_n(&g_udp_hook_on, on != 0, __ATOMIC_RELAXED);
}

int npf_udp_hook_is_on(void)
{
    return __atomic_load_n(&g_udp_hook_on, __ATOMIC_RELAXED);
}

int npf_net_bypass(int fd, int family)
{
    npf_udp_hook_fn fn = __atomic_load_n(&g_udp_hook, __ATOMIC_ACQUIRE);
    if (fd < 0 || !npf_udp_hook_is_on())
        return 0;
    if (!fn)
        fn = npf_vpn_bypass;
    return fn(fd, family, __atomic_load_n(&g_udp_hook_arg, __ATOMIC_ACQUIRE));
}

int npf_net_bypass_active(void)
{
    return npf_udp_hook_is_on() && (__atomic_load_n(&g_udp_hook, __ATOMIC_ACQUIRE) != NULL || npf_vpn_in_way());
}

int npf_udp_socket(int family, int blocking)
{
    int fd = npf_socket(family, SOCK_DGRAM, 0, blocking), r;
    if (fd < 0 || !npf_udp_hook_is_on())
        return fd;
    r = npf_net_bypass(fd, family);
    if (r < 0 && !__atomic_exchange_n(&g_udp_hook_failed, 1, __ATOMIC_RELAXED))
        npf_logw("udp: the socket stays on the default route (the platform could not bind it: %d)", r);
    else if (r >= 0)
        __atomic_store_n(&g_udp_hook_failed, 0, __ATOMIC_RELAXED);
    return fd;
}

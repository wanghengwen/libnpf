/* The portable part of the system layer (npf/sys.h): socket errors and
 * addresses, scratch buffers, UDP sends and the node's socket hook;
 * sys_posix.c and sys_win.c hold what differs. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "npf/atomic.h"
#include "npf/crypto.h"
#include "npf/lock.h"
#include "npf/log.h"
#include "npf/platform.h"
#include "npf/sys.h"

#ifdef _WIN32
#include <direct.h>
#endif

static int npf_mkdir(const char *path)
{
#ifdef _WIN32
    wchar_t w[1024];
    int r = npf_wpath(path, w, 1024) < 0 ? -1 : _wmkdir(w);
#else
    int r = mkdir(path, 0700);
#endif
    return r == 0 || errno == EEXIST ? 0 : -1;
}

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

/* ---- socket errors (sys.h); a plain E... code that Winsock never
 * returns (EPIPE, ENFILE, ENOMEM) is harmless in the lists on Windows ---- */

int npf_sock_again(void)
{
    int e = npf_sock_err();
    return e == NPF_SE(WOULDBLOCK) || e == NPF_SE(INTR) || e == EAGAIN;
}

int npf_sock_in_use(void)
{
    int e = npf_sock_err();
    return e == NPF_SE(ADDRINUSE) || e == NPF_SE(ACCES);
}

int npf_sock_inprogress(void)
{
    int e = npf_sock_err();
#ifdef _WIN32
    if (e == WSAEWOULDBLOCK)            /* Winsock's non-blocking connect() */
        return 1;
#endif
    return e == NPF_SE(INPROGRESS);
}

int npf_sock_broken_code(int e)
{
    /* a defunct socket (XNU: a suspended app's, reclaimed) fails with
     * ENOTCONN or EBADF; EPIPE, ECONNABORTED, ESHUTDOWN after a shutdown */
    return e == NPF_SE(BADF) || e == NPF_SE(NOTSOCK) || e == NPF_SE(NOTCONN) || e == NPF_SE(NETDOWN)
           || e == NPF_SE(SHUTDOWN) || e == NPF_SE(CONNABORTED) || e == EPIPE;
}

int npf_sock_broken(void)
{
    return npf_sock_broken_code(npf_sock_err());
}

int npf_sock_starved(void)
{
    int e = npf_sock_err();
    return e == NPF_SE(MFILE) || e == NPF_SE(NOBUFS) || e == ENFILE || e == ENOMEM;
}

const char *npf_sock_strerror(void)
{
    return npf_sock_strerror_code(npf_sock_err());
}

/* ---- socket addresses (sys.h) ---- */

socklen_t npf_addr_len(const void *sa)
{
    return ((const struct sockaddr *)sa)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                                : sizeof(struct sockaddr_in);
}

uint16_t npf_addr_port(const void *sa)
{
    const struct sockaddr *a = sa;
    return ntohs(a->sa_family == AF_INET6 ? ((const struct sockaddr_in6 *)sa)->sin6_port
                                          : ((const struct sockaddr_in *)sa)->sin_port);
}

int npf_addr_eq(const void *a, const void *b)
{
    int f = ((const struct sockaddr *)a)->sa_family;
    if (f != ((const struct sockaddr *)b)->sa_family || npf_addr_port(a) != npf_addr_port(b))
        return 0;
    if (f == AF_INET6)
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr, 16) == 0;
    return f == AF_INET
           && ((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr;
}

const char *npf_addr_str(const void *sa, char *buf, size_t cap)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    int f = ((const struct sockaddr *)sa)->sa_family;
    if (f != AF_INET && f != AF_INET6) {
        snprintf(buf, cap, "-");
        return buf;
    }
    inet_ntop(f, f == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)sa)->sin6_addr
                               : (const void *)&((const struct sockaddr_in *)sa)->sin_addr, ip, sizeof ip);
    snprintf(buf, cap, f == AF_INET6 ? "[%s]:%u" : "%s:%u", ip, npf_addr_port(sa));
    return buf;
}

void npf_addr_set(struct sockaddr_storage *out, int family, const void *ip, uint16_t port)
{
    memset(out, 0, sizeof *out);
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        memcpy(&a->sin6_addr, ip, 16);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        memcpy(&a->sin_addr, ip, 4);
    }
}

int npf_addr_ip(const char *host, uint16_t port, struct sockaddr_storage *out)
{
    uint8_t b[16];
    int f = inet_pton(AF_INET, host, b) == 1 ? AF_INET : inet_pton(AF_INET6, host, b) == 1 ? AF_INET6 : 0;
    if (!f) {
        memset(out, 0, sizeof *out);
        return -1;
    }
    npf_addr_set(out, f, b, port);
    return 0;
}

const char *npf_path_sep(const char *p)
{
    const char *s = strrchr(p, '/');
#ifdef _WIN32
    const char *b = strrchr(p, '\\');
    if (!s || b > s)
        s = b;
#endif
    return s;
}

void npf_dirname(const char *p, char *out, size_t cap)
{
    const char *s = npf_path_sep(p);
    if (s)
        snprintf(out, cap, "%.*s", (int)(s - p), p);
    else
        snprintf(out, cap, ".");
}

int npf_addr_parse(const char *s, struct sockaddr_storage *out)
{
    char host[64];
    uint16_t port;
    memset(out, 0, sizeof *out);
    return npf_hostport(s, host, sizeof host, &port) < 0 ? -1 : npf_addr_ip(host, port, out);
}

int npf_if_has(int family, const void *addr)
{
    npf_ifaddr ifs[64];
    int i, n = npf_if_list(ifs, 64);
    for (i = 0; i < n; i++)
        if (ifs[i].family == family && memcmp(ifs[i].addr, addr, family == AF_INET ? 4 : 16) == 0)
            return 1;
    return 0;
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
    char d[80], more[80] = "";
    npf_addr_str(to, d, sizeof d);
    if (e->more)
        snprintf(more, sizeof more, " (and %u more failures of this kind in the last minute)", e->more);
    npf_log_at(level, __FILE__, __LINE__, "udp: sending to %s failed: %s%s%s", d, npf_sock_strerror_code(err), hint,
               more);
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
        b = npf_rdbe32(ifs[i].addr);
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
    if (err == EHOSTUNREACH) {
        if (quiet(&t_lan_err, err, now))
            return;                     /* told a moment ago: no interface list for each datagram */
        if (on_local_subnet(to)) {
            report(&t_lan_err, NPF_LOG_WARN, err, now, to,
                   "; macOS blocks the local network for this program: allow npf under System Settings > "
                   "Privacy & Security > Local Network, or run it as a launchd daemon");
            return;
        }
    }
#endif
    /* punching tries every candidate of the peer: some are not routable
     * from here (another family, a LAN that is not ours, a host gone;
     * EHOSTDOWN, macOS: no ARP answer on the LAN, not the privacy block) */
    if (err == NPF_SE(NETUNREACH) || err == NPF_SE(HOSTUNREACH) || err == NPF_SE(ADDRNOTAVAIL)
        || err == NPF_SE(AFNOSUPPORT) || err == NPF_SE(HOSTDOWN))
        level = NPF_LOG_DEBUG;
    if (!quiet(&t_send_err, err, now))
        report(&t_send_err, level, err, now, to, "");
}

#ifdef _WIN32
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
        return sendto(fd, buf, len, MSG_DONTWAIT, sa, npf_addr_len(sa));
    r = sendto(fd, buf, len, MSG_DONTWAIT, sa, npf_addr_len(sa));
    err = WSAGetLastError();
    setsockopt((SOCKET)fd, lvl, opt, (const char *)&cur, sizeof cur);
    WSASetLastError(err);
    return r;
}
#endif

/* ---- the main sockets' sends (npf_udp_watch) ---- */

static NPF_THREAD_LOCAL npf_udp_watch *t_watch;

void npf_udp_watch_on(npf_udp_watch *w, int fd)
{
    npf_udp_watch **p = &t_watch;
    if (w->fd >= 0) {
        while (*p && *p != w)
            p = &(*p)->next;
        if (!*p) {                          /* on another thread's list: neither one touched */
            npf_loge("udp: a send watch (fd %d) moved on a thread not its own", w->fd);
            return;
        }
        *p = w->next;
    }
    w->fd = fd;
    if (fd >= 0) {
        w->next = t_watch;
        t_watch = w;
    }
}

static void udp_watch_note(npf_udp_watch *w, const struct sockaddr *sa)
{
    const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
    int to_ip = sa->sa_family == AF_INET && w->relay_ip && a->sin_addr.s_addr == w->relay_ip;
    if (to_ip && a->sin_port == w->relay_port)
        return;                             /* the relay itself */
    if (w->mode == NPF_WATCH_ANY || (w->mode == NPF_WATCH_IP && to_ip))
        w->other = npf_mono_ms();
}

int npf_udp_send(int fd, const void *buf, size_t len, const void *to)
{
    const struct sockaddr *sa = to;
    int err;
    npf_udp_watch *w;
    for (w = t_watch; w; w = w->next)
        if (w->fd == fd)
            udp_watch_note(w, sa);
#ifdef _WIN32
    if (is_loopback(sa)) {
        if (sendto_loopback(fd, buf, len, sa) >= 0)
            return 0;
    } else
#endif
    if (sendto(fd, buf, len, MSG_DONTWAIT, sa, npf_addr_len(sa)) >= 0)
        return 0;
    err = npf_sock_err();
    if (npf_sock_again() || err == NPF_SE(NOBUFS))
        return -1;                  /* a full queue: the datagram is lost, nothing to tell */
    send_failed(sa, err);
    return -1;
}

/* ---- the node's UDP sockets (sys.h) ---- */

static npf_mutex g_udp_hook_mu = NPF_MUTEX_INIT;   /* the hook and its arg, set together */
static npf_udp_hook_fn g_udp_hook;
static void *g_udp_hook_arg;
static int g_udp_hook_failed;               /* atomic: the last one failed, said once until one works */

void npf_udp_hook_set(npf_udp_hook_fn fn, void *arg)
{
    npf_mutex_lock(&g_udp_hook_mu);
    g_udp_hook = fn;
    g_udp_hook_arg = arg;
    npf_mutex_unlock(&g_udp_hook_mu);
}

static npf_udp_hook_fn udp_hook(void **arg)
{
    npf_udp_hook_fn fn;
    npf_mutex_lock(&g_udp_hook_mu);
    fn = g_udp_hook;
    *arg = g_udp_hook_arg;
    npf_mutex_unlock(&g_udp_hook_mu);
    return fn;
}

int npf_net_bypass(int fd, int family)
{
    void *arg;
    npf_udp_hook_fn fn = udp_hook(&arg);
    if (fd < 0)
        return 0;
    return (fn ? fn : npf_vpn_bypass)(fd, family, arg);
}

int npf_net_bypass_active(void)
{
    void *arg;
    return udp_hook(&arg) != NULL || npf_vpn_in_way();
}

int npf_udp_socket(int family, int blocking, int bypass)
{
    int fd = npf_socket(family, SOCK_DGRAM, 0, blocking), r;
    if (fd < 0 || !bypass)
        return fd;
    r = npf_net_bypass(fd, family);
    if (r < 0 && !npf_atomic_swap(&g_udp_hook_failed, 1))
        npf_logw("udp: the socket stays on the default route (the platform could not bind it: %d)", r);
    else if (r >= 0)
        npf_atomic_set(&g_udp_hook_failed, 0);
    return fd;
}

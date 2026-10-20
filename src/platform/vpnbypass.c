/* The built-in UDP hook (npf/sys.h npf_udp_socket) where the application set
 * none (desktops, iOS; the Android app binds through its own): when a VPN
 * has the default route, the node's UDP sockets (and its signaling's TCP,
 * node.c) go out on the physical
 * interface under it (connect_mode p2p), so punching meets this host's own
 * NAT and a peer on the same LAN. Windows: IP_UNICAST_IF; macOS and iOS:
 * IP_BOUND_IF; Linux: SO_BINDTODEVICE (needs CAP_NET_RAW: else the socket
 * stays on the default route). The choice is looked at again every few
 * seconds, so a VPN going up or down is followed by the sockets opened next. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/platform.h"
#include "npf/sys.h"

#ifdef _WIN32
#include <iphlpapi.h>
#include <wchar.h>
#include <wctype.h>
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define RECHECK_MS 3000

typedef struct {
    int      vpn;               /* a VPN has the default route */
    unsigned idx4, idx6;        /* the interface to bind to (0: none) */
    char     name[64];          /* its name, and the VPN's */
    char     vpn_name[64];
} choice;

static choice g_ch;
static int64_t g_at = -RECHECK_MS;
static int g_lock;
static char g_said[160];

int npf_if_tunnel_name(const char *n)
{
    static const char *const pre[] = {"utun", "tun", "tap", "wg", "ppp", "ipsec", "tailscale", "zt", "nordlynx",
                                      "gpd", "cloudflarewarp", "vpn", "wintun", "wireguard", "clash", "mihomo",
                                      "singbox", "sing-box", "meta", NULL};
    int i;
    char l[64];
    size_t k;
    for (k = 0; n[k] && k + 1 < sizeof l; k++)
        l[k] = (char)(n[k] >= 'A' && n[k] <= 'Z' ? n[k] + 32 : n[k]);
    l[k] = 0;
    for (i = 0; pre[i]; i++)
        if (strncmp(l, pre[i], strlen(pre[i])) == 0)
            return 1;
    return 0;
}

/* the source address the system picks toward the internet (no packet sent) */
static int default_src(struct in_addr *out)
{
    struct sockaddr_in to, me;
    socklen_t ml = sizeof me;
    int fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 1), r;
    if (fd < 0)
        return -1;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    to.sin_addr.s_addr = htonl(0x01010101);    /* 1.1.1.1 */
    r = connect(fd, (struct sockaddr *)&to, sizeof to) == 0 && getsockname(fd, (struct sockaddr *)&me, &ml) == 0 ? 0 : -1;
    npf_sock_close(fd);
    if (r == 0)
        *out = me.sin_addr;
    return r;
}

#ifdef _WIN32

static int wcontains(const wchar_t *s, const wchar_t *sub)
{
    wchar_t l[256];
    size_t k;
    if (!s)
        return 0;
    for (k = 0; s[k] && k + 1 < sizeof l / sizeof l[0]; k++)
        l[k] = (wchar_t)towlower(s[k]);
    l[k] = 0;
    return wcsstr(l, sub) != NULL;
}

static int win_tunnel(const IP_ADAPTER_ADDRESSES *a)
{
    return a->IfType == IF_TYPE_PROP_VIRTUAL || a->IfType == IF_TYPE_TUNNEL || a->IfType == IF_TYPE_PPP
        || wcontains(a->Description, L"wintun") || wcontains(a->Description, L"tap-") || wcontains(a->Description, L"wireguard")
        || wcontains(a->Description, L"tun") || wcontains(a->Description, L"vpn");
}

static int has_v4(const IP_ADAPTER_ADDRESSES *a, const struct in_addr *want)
{
    const IP_ADAPTER_UNICAST_ADDRESS *u;
    for (u = a->FirstUnicastAddress; u; u = u->Next)
        if (u->Address.lpSockaddr->sa_family == AF_INET
            && (!want || ((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr == want->s_addr))
            return 1;
    return 0;
}

static void pick(choice *c)
{
    ULONG len = 32768;
    IP_ADAPTER_ADDRESSES *aa = NULL, *a, *def = NULL, *best = NULL;
    struct in_addr src;
    int tries, best_virtual = 1;
    memset(c, 0, sizeof *c);
    if (default_src(&src) < 0)
        return;
    for (tries = 0; tries < 3; tries++) {
        ULONG r;
        aa = malloc(len);
        if (!aa)
            return;
        r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                 | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &len);
        if (r == NO_ERROR)
            break;
        free(aa);
        aa = NULL;
        if (r != ERROR_BUFFER_OVERFLOW)
            return;
    }
    for (a = aa; a; a = a->Next)
        if (a->OperStatus == IfOperStatusUp && has_v4(a, &src))
            def = a;
    if (def && win_tunnel(def)) {
        c->vpn = 1;
        WideCharToMultiByte(CP_UTF8, 0, def->FriendlyName, -1, c->vpn_name, sizeof c->vpn_name, NULL, NULL);
        for (a = aa; a; a = a->Next) {
            int virt;
            if (a == def || a->OperStatus != IfOperStatusUp || win_tunnel(a) || !a->FirstGatewayAddress || !has_v4(a, NULL)
                || (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211))
                continue;
            virt = wcontains(a->Description, L"virtual") || wcontains(a->Description, L"hyper-v");
            if (!best || (best_virtual && !virt) || (best_virtual == virt && a->Ipv4Metric < best->Ipv4Metric)) {
                best = a;
                best_virtual = virt;
            }
        }
        if (best) {
            c->idx4 = best->IfIndex;
            c->idx6 = best->Ipv6IfIndex;
            WideCharToMultiByte(CP_UTF8, 0, best->FriendlyName, -1, c->name, sizeof c->name, NULL, NULL);
        }
    }
    free(aa);
}

static int bind_to(int fd, int family, const choice *c)
{
    if (family == AF_INET6) {
        DWORD v = c->idx6;
        return v && setsockopt((SOCKET)fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&v, sizeof v) == 0 ? 0 : -1;
    }
    {
        DWORD v = htonl(c->idx4);          /* IPv4: in network order */
        return c->idx4 && setsockopt((SOCKET)fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&v, sizeof v) == 0 ? 0 : -1;
    }
}

#else /* POSIX */

#ifdef __linux__
/* a device of its own (not a bridge, a tunnel, a veth...) */
static int linux_physical(const char *n)
{
    char p[128];
    snprintf(p, sizeof p, "/sys/class/net/%s/device", n);
    return access(p, F_OK) == 0;
}

/* a default route through it in the main table */
static int linux_default_via(const char *n)
{
    char line[256], ifn[64];
    unsigned long dst;
    int ok = 0;
    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return 0;
    while (!ok && fgets(line, sizeof line, f)) {
        const char *p = line;
        if (npf_text_word(&p, ifn, sizeof ifn) == 0 && npf_text_hex(&p, &dst) == 0 && dst == 0 && strcmp(ifn, n) == 0)
            ok = 1;
    }
    fclose(f);
    return ok;
}
#endif

/* how good an interface is to go out on: 0 not at all */
static int rank(const char *n)
{
    if (npf_if_tunnel_name(n) || strncmp(n, "lo", 2) == 0)
        return 0;
#ifdef __linux__
    if (!linux_default_via(n))
        return 0;
    return linux_physical(n) ? 3 : 1;
#elif defined(__APPLE__)
    if (strcmp(n, "en0") == 0)
        return 4;                       /* Wi-Fi on phones, the first port on Macs */
    if (strncmp(n, "en", 2) == 0)
        return 3;
    if (strncmp(n, "pdp_ip", 6) == 0)
        return 2;                       /* iOS: cellular */
    return 0;
#else
    return 1;
#endif
}

static void pick(choice *c)
{
    struct ifaddrs *ifa, *i;
    struct in_addr src;
    const char *def = NULL, *best = NULL;
    int br = 0;
    memset(c, 0, sizeof *c);
    if (default_src(&src) < 0 || getifaddrs(&ifa) < 0)
        return;
    for (i = ifa; i; i = i->ifa_next)
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET
            && ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr == src.s_addr)
            def = i->ifa_name;
    if (def && npf_if_tunnel_name(def)) {
        c->vpn = 1;
        snprintf(c->vpn_name, sizeof c->vpn_name, "%s", def);
        for (i = ifa; i; i = i->ifa_next) {
            uint32_t a;
            int r;
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET || !(i->ifa_flags & IFF_UP)
                || !(i->ifa_flags & IFF_RUNNING) || (i->ifa_flags & IFF_LOOPBACK) || strcmp(i->ifa_name, def) == 0)
                continue;
            a = ntohl(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
            if ((a >> 16) == 0xA9FE)    /* 169.254/16: no way out */
                continue;
            r = rank(i->ifa_name);
            if (r > br) {
                br = r;
                best = i->ifa_name;
            }
        }
        if (best) {
            snprintf(c->name, sizeof c->name, "%s", best);
            c->idx4 = c->idx6 = if_nametoindex(best);
        }
    }
    freeifaddrs(ifa);
}

static int bind_to(int fd, int family, const choice *c)
{
    if (!c->idx4)
        return -1;
#if defined(__APPLE__)
    {
        unsigned v = c->idx4;
        if (family == AF_INET6)
            return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &v, sizeof v) == 0 ? 0 : -1;
        return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &v, sizeof v) == 0 ? 0 : -1;
    }
#elif defined(__linux__)
    (void)family;
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, c->name, (socklen_t)strlen(c->name) + 1) == 0 ? 0 : -1;
#else
    (void)fd;
    (void)family;
    return -1;
#endif
}

#endif

int npf_vpn_bypass(int fd, int family, void *arg)
{
    choice c;
    int64_t now = npf_mono_ms();
    char said[160];
    (void)arg;
    while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE))
        ;
    if (now - g_at >= RECHECK_MS) {
        pick(&g_ch);
        g_at = now;
        if (!g_ch.vpn)
            snprintf(said, sizeof said, "-");
        else
            snprintf(said, sizeof said, "%s>%s", g_ch.vpn_name, g_ch.name);
        if (strcmp(said, g_said) != 0) {
            if (g_ch.vpn && g_ch.name[0])
                npf_log("udp: a VPN (%s) has the default route: the UDP sockets and the signaling go out on %s (connect_mode p2p)",
                        g_ch.vpn_name, g_ch.name);
            else if (g_ch.vpn)
                npf_log("udp: a VPN (%s) has the default route and no other network is up: the UDP sockets go through it",
                        g_ch.vpn_name);
            else if (g_said[0] && strcmp(g_said, "-") != 0)
                npf_log("udp: no VPN in the way any more");
            snprintf(g_said, sizeof g_said, "%s", said);
        }
    }
    c = g_ch;
    __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE);
    if (!c.vpn)
        return 0;                       /* nothing to go around */
    return bind_to(fd, family, &c) == 0 ? 0 : -1;
}

int npf_vpn_in_way(void)
{
    int r;
    while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE))
        ;
    r = g_ch.vpn && g_ch.name[0];
    __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE);
    return r;
}

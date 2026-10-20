#include "npf/sys.h"
#include <string.h>

#include "npf/candidates.h"

static int is_global_v6(const struct in6_addr *a)
{
    if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_SITELOCAL(a)
        || IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_UNSPECIFIED(a))
        return 0;
    if ((a->s6_addr[0] & 0xfe) == 0xfc)     /* fc00::/7 unique-local */
        return 0;
    return 1;
}

int npf_gather_host6(struct in6_addr *out, int max)
{
    npf_ifaddr ifs[64];
    int i, k = npf_if_list(ifs, 64), n = 0;
    for (i = 0; i < k && n < max; i++) {
        struct in6_addr a;
        if (ifs[i].family != AF_INET6 || ifs[i].loopback)
            continue;
        memcpy(&a, ifs[i].addr, 16);
        if (is_global_v6(&a))
            out[n++] = a;
    }
    return n;
}

int npf_gather_host4(struct in_addr *out, int max)
{
    npf_ifaddr ifs[64];
    int i, k = npf_if_list(ifs, 64), n = 0;
    for (i = 0; i < k && n < max; i++) {
        uint32_t h;
        /* nothing on a loopback interface is reachable from outside; WSL puts
         * its host alias 10.255.255.254 on lo, where it is not even usable */
        if (ifs[i].family != AF_INET || ifs[i].loopback)
            continue;
        h = ((uint32_t)ifs[i].addr[0] << 24) | ((uint32_t)ifs[i].addr[1] << 16) | ((uint32_t)ifs[i].addr[2] << 8)
            | ifs[i].addr[3];
        if ((h >> 24) == 127)               /* 127.0.0.0/8 loopback */
            continue;
        if ((h & 0xffff0000u) == 0xa9fe0000u)  /* 169.254/16 link-local */
            continue;
        memcpy(&out[n++], ifs[i].addr, 4);
    }
    return n;
}

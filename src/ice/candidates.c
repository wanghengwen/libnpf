#include "npf/sys.h"
#include <string.h>

#include "npf/candidates.h"

/* reachable from elsewhere: nothing on a loopback interface (WSL puts its
 * host alias 10.255.255.254 on lo, where it is not even usable), no
 * loopback, link-local, multicast or unique-local (fc00::/7) address */
static int usable(const npf_ifaddr *f)
{
    const uint8_t *a = f->addr;
    struct in6_addr a6;
    if (f->loopback)
        return 0;
    if (f->family == AF_INET)
        return a[0] != 127 && !(a[0] == 169 && a[1] == 254);
    memcpy(&a6, a, 16);
    return !IN6_IS_ADDR_LOOPBACK(&a6) && !IN6_IS_ADDR_LINKLOCAL(&a6) && !IN6_IS_ADDR_SITELOCAL(&a6)
        && !IN6_IS_ADDR_MULTICAST(&a6) && !IN6_IS_ADDR_UNSPECIFIED(&a6) && (a[0] & 0xfe) != 0xfc;
}

int npf_gather_host(int family, void *out, int max)
{
    npf_ifaddr ifs[64];
    size_t len = family == AF_INET ? 4 : 16;
    int i, k = npf_if_list(ifs, 64), n = 0;
    for (i = 0; i < k && n < max; i++)
        if (ifs[i].family == family && usable(&ifs[i]))
            memcpy((uint8_t *)out + len * (size_t)n++, ifs[i].addr, len);
    return n;
}

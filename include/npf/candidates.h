/* Local address candidates (nat-traversal.md 5): host4 and host6.
 * srflx/pred come from the probe; mapped from portmap; these are the
 * directly-usable local addresses to advertise to the peer. */
#ifndef NPF_CANDIDATES_H
#define NPF_CANDIDATES_H

#include "npf/sys.h"

/* This host's addresses of a family (AF_INET: struct in_addr out[max],
 * AF_INET6: struct in6_addr), none loopback or link-local; IPv6 global only
 * (no fc00::/7). Returns the count. host6 is the highest-priority candidate:
 * usually only a firewall pinhole (handled like S1) is needed, no NAT; host4
 * (private or public) serves peers behind the same NAT (same srflx IP). */
int npf_gather_host(int family, void *out, int max);

#endif

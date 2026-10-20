/* Local address candidates (nat-traversal.md 5): host4 and host6.
 * srflx/pred come from the probe; mapped from portmap; these are the
 * directly-usable local addresses to advertise to the peer. */
#ifndef NPF_CANDIDATES_H
#define NPF_CANDIDATES_H

#include "npf/sys.h"

/* Global (routable) IPv6 addresses of this host: excludes loopback,
 * link-local (fe80::/10) and unique-local (fc00::/7). Writes up to `max`,
 * returns the count. host6 is the highest-priority candidate: usually only a
 * firewall pinhole (handled like S1) is needed, no NAT. */
int npf_gather_host6(struct in6_addr *out, int max);

/* Non-loopback IPv4 addresses (private or public). Useful when both peers sit
 * behind the same NAT (same srflx IP) and can reach each other directly. */
int npf_gather_host4(struct in_addr *out, int max);

#endif

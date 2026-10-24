/* Port mapping via PCP (RFC 6887) and NAT-PMP (RFC 6886) — nat-traversal.md 5.
 *
 * Both talk UDP to the default gateway on port 5351. We try PCP first (newer,
 * returns the external IP directly, supports IPv6) and fall back to NAT-PMP.
 * On success the router forwards its external_ip:external_port to this host's
 * internal_port — a `mapped` candidate, as good as a public address.
 *
 * UPnP IGD is intentionally not supported. */
#ifndef NPF_PORTMAP_H
#define NPF_PORTMAP_H

#include <stdint.h>
#include "npf/sys.h"

#define NPF_PORTMAP_PORT   5351

enum { NPF_PORTMAP_NONE = 0, NPF_PORTMAP_PCP, NPF_PORTMAP_NATPMP };

typedef struct npf_portmap {
    int      method;            /* NPF_PORTMAP_PCP / NATPMP */
    uint16_t internal_port;
    uint16_t external_port;
    int      ext_family;        /* 4 or 6 */
    uint8_t  external_ip[16];   /* network order; first 4 bytes used when ext_family==4 */
    uint32_t lifetime;          /* granted, seconds */
    uint32_t epoch;             /* server epoch (for restart detection) */
} npf_portmap;

/* Build/parse one PCP MAP request/response (UDP proto). Exposed for the KATs. */
int  npf_pcp_build_map(uint8_t out[60], const uint8_t nonce[12], const struct in_addr *client,
                       uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime);
int  npf_pcp_parse_map(const uint8_t *in, size_t len, const uint8_t nonce[12], npf_portmap *res);

/* Build/parse one NAT-PMP UDP MAP request/response. */
int  npf_natpmp_build_map(uint8_t out[12], uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime);
int  npf_natpmp_parse_map(const uint8_t *in, size_t len, npf_portmap *res);

/* Default IPv4 gateway (npf_default_gw4). Returns 0 / -1. */
int  npf_portmap_gateway_v4(struct in_addr *gw);

/* Full attempt: discover gateway, try PCP then NAT-PMP for a UDP mapping of
 * `internal_port`. Returns 0 on success (res filled), -1 otherwise. */
int  npf_portmap_request(uint16_t internal_port, uint32_t lifetime, npf_portmap *res);

/* The mapping of internal_port removed with the method that made it: one
 * try of 250 ms (a stopping node does not wait out a gateway gone silent;
 * an unremoved mapping ends with its lease). 0 / -1. */
int  npf_portmap_remove(uint16_t internal_port, int method);

const char *npf_portmap_method_str(int method);

#endif

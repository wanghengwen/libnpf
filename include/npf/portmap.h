/* Router port mapping with PCP (RFC 6887), else NAT-PMP (RFC 6886), over UDP
 * to the default IPv4 gateway's port 5351 (nat-traversal.md 5; no UPnP IGD).
 * A mapping makes the router forward external_ip:external_port to this
 * host's internal_port: a "mapped" candidate. Internal to libnpf (the node
 * keeps its UDP port mapped); in include/npf for the npf-portmap tool. */
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
    uint8_t  external_ip[16];   /* network order, the first 4 bytes for IPv4; NAT-PMP: zeros when the
                                   gateway did not tell it */
    uint32_t lifetime;          /* granted, seconds */
    uint32_t epoch;             /* the gateway's epoch (it restarted when it goes back) */
} npf_portmap;

/* One UDP MAP request / its response, for the known-answer tests. build
 * returns the length (60, 12); parse 0 for a success response (PCP: the
 * same nonce, UDP), -1 otherwise. NAT-PMP's parse leaves external_ip zero. */
int  npf_pcp_build_map(uint8_t out[60], const uint8_t nonce[12], const struct in_addr *client,
                       uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime);
int  npf_pcp_parse_map(const uint8_t *in, size_t len, const uint8_t nonce[12], npf_portmap *res);
int  npf_natpmp_build_map(uint8_t out[12], uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime);
int  npf_natpmp_parse_map(const uint8_t *in, size_t len, npf_portmap *res);

/* at, in the three below: a gateway "IP:PORT" (IPv4) to use instead of the
 * default route's (tests), or NULL; bypass: the socket goes around a VPN
 * (npf_udp_socket). */

/* Maps UDP internal_port (the same external port asked for), PCP first,
 * then NAT-PMP, 4 tries each (250 ms doubling). Blocks up to ~7.5 s: the
 * node calls it on a thread of its own. Only a success reply for
 * internal_port with an external port counts. 0 with res filled, -2 without
 * a gateway, -1 without an answer. */
int  npf_portmap_request(const char *at, int bypass, uint16_t internal_port, uint32_t lifetime, npf_portmap *res);

/* Removes the mapping of internal_port with the method that made it: one
 * try, blocking up to 250 ms (an unremoved mapping ends with its lifetime).
 * 0, or -1. */
int  npf_portmap_remove(const char *at, int bypass, uint16_t internal_port, int method);

/* The network the gateway is on, to notice a change: the gateway's IPv4
 * address << 32 | this host's address toward it (both network order; 0 when
 * unknown). No packet is sent. 0 without a gateway. */
uint64_t npf_portmap_net(const char *at, int bypass);

/* "none", "PCP", "NAT-PMP" (static; out of range: "none") */
const char *npf_portmap_method_str(int method);

#endif

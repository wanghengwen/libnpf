/* UPnP IGD detection (nat-traversal.md 5.1): is the default gateway an
 * Internet Gateway Device, and what is its WAN address? Detection only,
 * for the statistics (would a UPnP mapping help?): no mapping is ever
 * made, changed or deleted on the router.
 *
 * SSDP M-SEARCH (multicast and unicast to the gateway) for the IGD v1/v2
 * and its WANIPConnection / WANPPPConnection services; answers only from
 * the default gateway's address; the device description fetched from the
 * gateway only (its LOCATION, URLBase and controlURL must name the
 * gateway's IP: never another host); one SOAP GetExternalIPAddress. Bounded
 * sizes, a few seconds for each step. Blocking: run it on a worker thread. */
#ifndef NPF_UPNP_H
#define NPF_UPNP_H

#include <stddef.h>
#include <stdint.h>

#define NPF_UPNP_SSDP_PORT 1900
#define NPF_UPNP_PATH_MAX  256

/* what npf_upnp_detect found */
enum { NPF_UPNP_NONE = 0,       /* no IGD answered at the gateway */
       NPF_UPNP_PRESENT,        /* an IGD answered, its WAN address not learned */
       NPF_UPNP_ADDR };         /* and its WAN address */

/* a URL at the gateway: port and path ("/...", printable, no spaces) */
typedef struct npf_upnp_url {
    uint16_t port;
    char     path[NPF_UPNP_PATH_MAX];
} npf_upnp_url;

/* The parsers, exposed for the unit tests. gw is the gateway's IPv4
 * address (network order); 0 / -1. */
/* an SSDP answer of an IGD (or its WAN connection service): its LOCATION */
int npf_upnp_parse_ssdp(const char *buf, size_t len, uint32_t gw, npf_upnp_url *loc);
/* an HTTP response with status 200: its body (chunked bodies decoded in place) */
int npf_upnp_parse_http(char *buf, size_t len, const char **body, size_t *blen);
/* the device description: the control URL and the service type of its
 * WANIPConnection / WANPPPConnection number nth (0: the first; loc: where
 * the description came from) */
int npf_upnp_parse_desc(const char *xml, size_t len, uint32_t gw, const npf_upnp_url *loc, npf_upnp_url *ctl,
                        char *st, size_t stcap, int nth);
/* the SOAP answer to GetExternalIPAddress: an IPv4 address (not 0.0.0.0) */
int npf_upnp_parse_extip(const char *body, size_t len, uint8_t ip[4]);

/* The detection at the default gateway (tests: NPF_TEST_UPNP_GW=IP:PORT, a
 * stand-in answering SSDP there, unicast only). NPF_UPNP_*, ip set with
 * NPF_UPNP_ADDR; -1 without a default IPv4 gateway. Up to about 12 s. */
int npf_upnp_detect(uint8_t ip[4]);

#endif

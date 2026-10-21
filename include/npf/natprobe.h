/* NAT detection against self-hosted probe servers (nat-traversal.md 4).
 *
 * E1 = IP_A:P1, E2 = IP_A:P2, E3 = IP_B:P1. One socket asks all three for its
 * mapped address (mapping behaviour), then K fresh sockets ask E1 (port
 * allocation), then E2 and E3 are asked to answer the first of those (F, which
 * sent to E1 only) from where they are (filtering behaviour). IPv4 only.
 * npf_natprobe_run is synchronous (poll: the npf-natprobe tool);
 * npf_natprobe_start runs on the event loop (the node). */
#ifndef NPF_NATPROBE_H
#define NPF_NATPROBE_H

#include <stdint.h>
#include "npf/sys.h"

#include "npf/bind.h"
#include "npf/loop.h"

enum { NPF_MAP_UNKNOWN = 0, NPF_MAP_EIM, NPF_MAP_ADM, NPF_MAP_APDM };
enum { NPF_ALLOC_UNKNOWN = 0, NPF_ALLOC_PRESERVE, NPF_ALLOC_SEQUENTIAL, NPF_ALLOC_BLOCK, NPF_ALLOC_RANDOM };
/* who may send in on a mapping: anyone, the IPs it sent to, the IP:ports it sent to */
enum { NPF_FILT_UNKNOWN = 0, NPF_FILT_EIF, NPF_FILT_ADF, NPF_FILT_APDF };

typedef struct npf_nat_profile {
    uint8_t  mapping;           /* NPF_MAP_* */
    uint8_t  allocation;        /* NPF_ALLOC_* */
    uint8_t  filtering;         /* NPF_FILT_* (ADF without an E3: EIF or ADF) */
    int16_t  seq_delta;         /* step of sequential allocation */
    uint16_t block_lo, block_hi;/* smallest observed port range; lo > hi when it wraps past 65535 */
    uint8_t  open;              /* public address on a local interface, no NAT */
    uint8_t  ip_varies;         /* E3 saw another public IP: non-paired pooling, hard side, no S3 */
    uint8_t  has_ipv6;          /* global IPv6 address (not probed yet) */
    uint8_t  upnp, pcp;         /* port mapping protocols (not probed yet) */
    uint32_t measured_at;       /* Unix seconds */
} npf_nat_profile;

#define NPF_NATPROBE_MAX_ALLOC 32

typedef struct npf_natprobe_cfg {
    struct sockaddr_in ep[3];   /* E1, E2, E3 */
    int      n_ep;              /* 2 (single server: no ADM detection) or 3 */
    uint8_t  probe_key[NPF_SIV_KEY_SIZE];
    uint8_t  ticket[NPF_TICKET_SIZE];
    int64_t  clock_offset_ms;   /* server clock - local clock, from the signaling server */
    int      alloc_sockets;     /* K fresh sockets for the allocation test; 0 = skip */
    int      filter_test;       /* after it, the filtering test (default 1; needs E2) */
    int      main_fd;           /* >= 0: probe the mapping of this (AnLiu) socket; -1: a fresh one */
} npf_natprobe_cfg;

typedef struct npf_natprobe_result {
    npf_nat_profile profile;
    uint16_t local_port;                    /* the main socket */
    int      got[3];                        /* answered */
    struct sockaddr_in mapped[3];           /* M1, M2, M3 */
    int      rtt_ms[3];
    int      tries[3];                      /* requests sent */
    int      alloc_n;
    int      alloc_got[NPF_NATPROBE_MAX_ALLOC];
    uint16_t alloc_local[NPF_NATPROBE_MAX_ALLOC];
    uint16_t alloc_mapped[NPF_NATPROBE_MAX_ALLOC];
    int      filter_acked[2];                /* E2, E3 got the bounce request */
    int      filter_got[2];                  /* their answers reached F */
    int      have_offset;
    int64_t  srv_offset_ms;                 /* E1 clock - local clock */
} npf_natprobe_result;

void npf_natprobe_cfg_init(npf_natprobe_cfg *cfg);

/* Run the whole detection (about 2-3 s worst case). Returns 0, or -1 if E1
 * did not answer at all (no profile). */
int npf_natprobe_run(const npf_natprobe_cfg *cfg, npf_natprobe_result *res);

/* Event-driven (the node): the same detection on the loop, nothing blocks.
 * cfg->main_fd is required; the caller passes the main socket's datagrams
 * to npf_natprobe_input (it takes those from the probe servers, 1). fn runs
 * once, ok 1 with a profile or 0 (E1 never answered), and the probe is gone
 * afterwards. npf_natprobe_cancel drops a running one (fn does not run). */
typedef struct npf_natprobe npf_natprobe;
typedef void (*npf_natprobe_fn)(int ok, const npf_natprobe_result *res, void *arg);
npf_natprobe *npf_natprobe_start(npf_loop *loop, const npf_natprobe_cfg *cfg, npf_natprobe_fn fn, void *arg);
int  npf_natprobe_input(npf_natprobe *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void npf_natprobe_cancel(npf_natprobe *p);

const char *npf_nat_mapping_str(int mapping);
const char *npf_nat_alloc_str(int allocation);
const char *npf_nat_filter_str(int filtering);

#endif

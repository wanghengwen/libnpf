/* NAT detection against the platform's probe servers (nat-traversal.md 4).
 * Internal to libnpf: the node probes on its loop. It is in include/npf for
 * npf's basic module (the NAT names in npf status) and the npf-natprobe and
 * npf-punch tools (npf_natprobe_run).
 *
 * E1 = IP_A:P1, E2 = IP_A:P2, E3 = IP_B:P1. The main socket asks each for its
 * mapped address (mapping), then K fresh sockets ask E1 (port allocation),
 * then E2 and E3 are asked to send to the first of those, F, which has sent
 * to E1 only (filtering). IPv4 only. Each phase ends when all its requests
 * are answered or after 2.2 s. */
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
    uint8_t  mapping;           /* NPF_MAP_*; UNKNOWN: E2 silent, or M1 = M2 and E3 silent */
    uint8_t  allocation;        /* NPF_ALLOC_* */
    uint8_t  filtering;         /* NPF_FILT_* (without E3: ADF stands for EIF or ADF) */
    int16_t  seq_delta;         /* SEQUENTIAL: the smallest step */
    uint16_t block_lo, block_hi;/* BLOCK / RANDOM: the smallest port range holding the samples; lo > hi wraps
                                   past 65535 */
    uint8_t  open;              /* the mapped address is a local interface's, the port unchanged: no NAT */
    uint8_t  ip_varies;         /* E3 saw another public IP than E1 (non-paired pooling: no S3) */
    uint32_t measured_at;       /* Unix seconds */
} npf_nat_profile;

#define NPF_NATPROBE_MAX_ALLOC 32

typedef struct npf_natprobe_cfg {
    struct sockaddr_in ep[3];   /* E1, E2, E3 */
    int      n_ep;              /* 1..3; without E3 no ADM is told apart, without E2 no filtering test */
    uint8_t  probe_key[NPF_SIV_KEY_SIZE];
    uint8_t  ticket[NPF_TICKET_SIZE];
    int64_t  clock_offset_ms;   /* server clock - local clock, from the signaling server */
    int      alloc_sockets;     /* K (default 8, at most NPF_NATPROBE_MAX_ALLOC); 0: no allocation nor
                                   filtering test */
    int      filter_test;       /* default 1 */
    int      main_fd;           /* the socket whose mapping is probed; -1 (default): npf_natprobe_run makes one */
    int      bypass;            /* its own sockets go around a VPN (npf_udp_socket); default 1 */
} npf_natprobe_cfg;

typedef struct npf_natprobe_result {
    npf_nat_profile profile;
    uint16_t local_port;                    /* the main socket's */
    int      got[3];                        /* E1..E3 answered */
    struct sockaddr_in mapped[3];           /* M1, M2, M3 */
    int      rtt_ms[3];
    int      tries[3];                      /* requests sent */
    int      alloc_n;
    int      alloc_got[NPF_NATPROBE_MAX_ALLOC];
    uint16_t alloc_local[NPF_NATPROBE_MAX_ALLOC];
    uint16_t alloc_mapped[NPF_NATPROBE_MAX_ALLOC];
    int      alloc_doubt;                   /* BLOCK / RANDOM, but sequential with one sample left out */
    int      filter_acked[2];               /* E2, E3 answered the request to send to F */
    int      filter_got[2];                 /* what they sent reached F */
    int      have_offset;
    int64_t  srv_offset_ms;                 /* E1 clock - local clock */
} npf_natprobe_result;

/* the defaults: alloc_sockets 8, filter_test 1, main_fd -1, the rest 0 */
void npf_natprobe_cfg_init(npf_natprobe_cfg *cfg);
/* Sets profile.allocation, seq_delta, block_lo / hi and alloc_doubt from
 * the alloc_* samples (fewer than 3 answered: UNKNOWN); the block's range
 * holds M1 and M2 too (got, mapped). */
void npf_natprobe_classify_alloc(npf_natprobe_result *res);

/* The whole detection on a loop of its own; blocks, about 7 s at most.
 * main_fd -1: a fresh socket. 0 with res filled, -1 when E1 never answered
 * (or no loop or socket). Built with NPF_TOOLS_API only (the tools). */
int npf_natprobe_run(const npf_natprobe_cfg *cfg, npf_natprobe_result *res);

/* The detection on loop, nothing blocks; cfg is copied and cfg->main_fd
 * (the caller's, never closed here) is required. The caller hands the main
 * socket's datagrams to npf_natprobe_input: 1 when it took one (it came from
 * a probe server's endpoint), 0 when it is the caller's. fn runs once on the
 * loop's thread, from a timer or npf_natprobe_input, never from
 * npf_natprobe_start: ok 1 with a profile, 0 when E1 never answered. The
 * probe is freed before fn runs. npf_natprobe_start: NULL when n_ep < 1,
 * main_fd is not a socket, or no memory. npf_natprobe_cancel frees a
 * running probe without fn (NULL is fine); not after fn. */
typedef struct npf_natprobe npf_natprobe;
typedef void (*npf_natprobe_fn)(int ok, const npf_natprobe_result *res, void *arg);
npf_natprobe *npf_natprobe_start(npf_loop *loop, const npf_natprobe_cfg *cfg, npf_natprobe_fn fn, void *arg);
int  npf_natprobe_input(npf_natprobe *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void npf_natprobe_cancel(npf_natprobe *p);

/* "UNKNOWN", "EIM", ... (static strings; out of range: "UNKNOWN") */
const char *npf_nat_mapping_str(int mapping);
const char *npf_nat_alloc_str(int allocation);
const char *npf_nat_filter_str(int filtering);

#endif

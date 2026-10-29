/* Test hooks (architecture.md 6): the test switches, environment variables
 * read once per node (npf_node_init: npf_th_read), only from the process's
 * own environment, never from a message; a node with any on says so in one
 * warning. Unset or empty: 0 / NULL; a number switch is off unless > 0.
 * One line each: the field, the variable, what it does (where). */
#ifndef NPF_TESTHOOKS_H
#define NPF_TESTHOOKS_H

#include <stdint.h>

#define NPF_TEST_HOOKS(N, S) \
    N(no_udp,           "NPF_NO_UDP")                /* no UDP: the WS relay, no spare (nat.c, path_mgr.c, home.c) */ \
    N(no_p2p,           "NPF_NO_P2P")                /* no punching, the relays only (call_punch.c) */ \
    N(no_home,          "NPF_NO_HOME")               /* no spare allocation (home.c) */ \
    N(drop_p2p_ms,      "NPF_TEST_DROP_P2P")         /* the direct path cut this long after up (path_direct.c) */ \
    N(drop_p2p_port,    "NPF_TEST_DROP_P2P_PORT")    /* ... only the one to the peer on this port */ \
    S(block_relay,      "NPF_TEST_BLOCK_RELAY")      /* "addr,url,...": these relays unreachable (path_udp.c) */ \
    N(drop_bind_ack,    "NPF_TEST_DROP_BIND_ACK")    /* the BIND_ACKs that bind lost (path_udp.c, home.c) */ \
    S(udp_fail,         "NPF_TEST_UDP_FAIL")         /* FILE: when it appears, IPv4 socket fails (node_network.c) */ \
    S(ws_file,          "NPF_TEST_WS_FILE")          /* FILE: no UDP while it exists: sets no_udp (node_network.c) */ \
    N(punch_fail_ms,    "NPF_TEST_PUNCH_FAIL")       /* every round fails, after this (call_punch.c) */ \
    N(punch_delay_ms,   "NPF_TEST_PUNCH_DELAY")      /* this side starts its rounds late (call_punch.c) */ \
    N(s3_hard,          "NPF_TEST_S3_HARD")          /* this side S3's hard side, this many sockets (call_punch.c) */ \
    N(punch_gap_ms,     "NPF_TEST_PUNCH_GAP_MS")     /* pressure reported, a test platform's gap (call_punch.c) */ \
    N(repunch_ms,       "NPF_TEST_REPUNCH_MS")       /* a test platform's backoff between rounds (call_punch.c) */ \
    N(no_spread,        "NPF_TEST_NO_SPREAD")        /* the calls after login not spread out (peers.c) */ \
    S(pub_ip,           "NPF_TEST_PUB_IP")           /* a forged public IP in the profile (nat.c) */ \
    S(cands_extra,      "NPF_TEST_CANDS_EXTRA")      /* "t=addr,...": forged candidates (nat.c) */ \
    N(cands_late_ms,    "NPF_TEST_CANDS_LATE")       /* no candidates this long after the first offer (nat.c) */ \
    S(host6,            "NPF_TEST_HOST6")            /* "addr,...": global IPv6 ones, no IPv4 candidates (nat.c) */ \
    S(portmap_gw,       "NPF_TEST_PORTMAP_GW")       /* "IP:PORT": a stand-in port mapping gateway (nodemap.c) */ \
    N(sources_after_ms, "NPF_TEST_SOURCES_AFTER_MS") /* outside channels asked this long unreachable (sources.c) */ \
    N(upgrade_retry_ms, "NPF_TEST_UPGRADE_RETRY_MS") /* reconnecting while an upgrade is required (node_signal.c) */ \
    N(udp_idle_ms,      "NPF_TEST_UDP_IDLE_MS")      /* a UDP flow's idle time (call_transport.c) */ \
    N(udp_again_ms,     "NPF_TEST_UDP_AGAIN_MS")     /* on the WS relay, UDP working: UDP again after (path_mgr.c) */

typedef struct npf_test_hooks {
#define TH_N(f, name) int64_t f;
#define TH_S(f, name) const char *f;
    NPF_TEST_HOOKS(TH_N, TH_S)
#undef TH_N
#undef TH_S
} npf_test_hooks;

void npf_th_read(npf_test_hooks *t);

#endif

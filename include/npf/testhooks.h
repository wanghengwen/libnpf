/* Test hooks (architecture.md 6): the environment's test switches, read
 * once per node (npf_node_init), never per datagram or per call. So far the
 * paths'; the others still read their own variables. */
#ifndef NPF_TESTHOOKS_H
#define NPF_TESTHOOKS_H

#include <stdint.h>

typedef struct npf_test_hooks {
    int         no_p2p;             /* NPF_NO_P2P: no punching, sessions on the relays only */
    int         drop_bind_ack;      /* NPF_TEST_DROP_BIND_ACK: lose the BIND_ACKs that confirm a binding */
    int64_t     drop_p2p_ms;        /* NPF_TEST_DROP_P2P=ms[:port]: the direct path cut this long after it came up; -1 off */
    int         drop_p2p_port;      /* ... only the one to the peer on this port; 0 every one */
    const char *block_relay;        /* NPF_TEST_BLOCK_RELAY="addr,url,...": these relay endpoints unreachable; NULL none */
    int64_t     udp_again_ms;       /* NPF_TEST_UDP_AGAIN_MS: on the WS relay while UDP works, UDP tried after this; 0 5 min */
} npf_test_hooks;

void npf_th_read(npf_test_hooks *t);

#endif

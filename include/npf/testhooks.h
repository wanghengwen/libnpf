/* Test hooks (architecture.md 6): the environment's test switches, read
 * once per process on first use and only read after that: none is looked up
 * per datagram or per call. Not for programs: integration tests and natlab
 * set them. So far the paths' (DROP_P2P, BLOCK_RELAY, DROP_BIND_ACK,
 * NO_P2P); the others still read their own variables. */
#ifndef NPF_TESTHOOKS_H
#define NPF_TESTHOOKS_H

#include <stdint.h>

typedef struct npf_test_hooks {
    int         no_p2p;             /* NPF_NO_P2P: no punching, sessions on the relays only */
    int         drop_bind_ack;      /* NPF_TEST_DROP_BIND_ACK: lose the BIND_ACKs that confirm a binding */
    int64_t     drop_p2p_ms;        /* NPF_TEST_DROP_P2P=ms[:port]: the direct path cut this long after it came up; -1 off */
    int         drop_p2p_port;      /* ... only the one to the peer on this port; 0 every one */
    const char *block_relay;        /* NPF_TEST_BLOCK_RELAY="addr,url,...": these relay endpoints unreachable; NULL none */
} npf_test_hooks;

const npf_test_hooks *npf_th(void);

#endif

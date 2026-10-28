/* Test hooks (npf/testhooks.h) */
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "npf/testhooks.h"

void npf_th_read(npf_test_hooks *t)
{
    const char *v = getenv("NPF_TEST_DROP_P2P");
    memset(t, 0, sizeof *t);
    t->no_p2p = getenv("NPF_NO_P2P") != NULL;
    t->drop_bind_ack = getenv("NPF_TEST_DROP_BIND_ACK") != NULL;
    t->drop_p2p_ms = v ? atoll(v) : -1;
    t->drop_p2p_port = v && strchr(v, ':') ? atoi(strchr(v, ':') + 1) : 0;
    t->block_relay = getenv("NPF_TEST_BLOCK_RELAY");
    t->udp_again_ms = (v = getenv("NPF_TEST_UDP_AGAIN_MS")) ? atoll(v) : 0;
}

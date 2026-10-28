/* Test hooks (npf/testhooks.h): read once, the first caller fills them in
 * while any other thread waits, then everyone reads the same copy. */
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "npf/testhooks.h"

static npf_test_hooks g_th;
static int g_state;                 /* 0 not read, 1 being read, 2 ready */

static void th_read(npf_test_hooks *t)
{
    const char *v = getenv("NPF_TEST_DROP_P2P");
    memset(t, 0, sizeof *t);
    t->no_p2p = getenv("NPF_NO_P2P") != NULL;
    t->drop_bind_ack = getenv("NPF_TEST_DROP_BIND_ACK") != NULL;
    t->drop_p2p_ms = v ? atoll(v) : -1;
    t->drop_p2p_port = v && strchr(v, ':') ? atoi(strchr(v, ':') + 1) : 0;
    t->block_relay = getenv("NPF_TEST_BLOCK_RELAY");
}

const npf_test_hooks *npf_th(void)
{
    int s = __atomic_load_n(&g_state, __ATOMIC_ACQUIRE), none = 0;
    if (s == 2)
        return &g_th;
    if (__atomic_compare_exchange_n(&g_state, &none, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        th_read(&g_th);
        __atomic_store_n(&g_state, 2, __ATOMIC_RELEASE);
        return &g_th;
    }
    while (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != 2)
        ;                           /* a few getenv calls on another thread */
    return &g_th;
}

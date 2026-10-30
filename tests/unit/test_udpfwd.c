/* UDP forwarding's flow ids (data-channel.md 15): this side's ids go round
 * the 32 bits, skipping 0 and the ids still in use. The test includes
 * udpfwd.c (the counter is not in the library's interface). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "../../src/stream/udpfwd.c"
#include "test.h"

static int g_units;                 /* CLOSEs sent: none, no flow gives way */

static int unit_rec(void *arg, const uint8_t *buf, size_t len)
{
    (void)arg;
    (void)buf;
    (void)len;
    g_units++;
    return 0;
}

static void no_kick(void *arg) { (void)arg; }

/* a new out flow of u from 127.0.0.1:port (the caller's -L on fd 7, the
 * callee's -R listener 1 on fd 7): its id */
static uint32_t open_out(npf_udpf *u, uint16_t port)
{
    struct sockaddr_storage ss;
    struct sockaddr_in *a = (struct sockaddr_in *)&ss;
    uflow *f;
    memset(&ss, 0, sizeof ss);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a->sin_port = htons(port);
    if (u->caller)
        npf_udpf_send(u, 7, &ss, sizeof *a, "127.0.0.1", 9, (const uint8_t *)"x", 1);
    else
        npf_udpf_send_rev(u, 7, &ss, sizeof *a, 1, (const uint8_t *)"x", 1);
    f = find_src(u, 7, &ss);
    return f ? f->id : 0;
}

int test_udpfwd(void)
{
    npf_udpf_io uio = {unit_rec, no_kick, NULL, NULL};
    npf_loop *l = npf_loop_new();
    anl_config cfg;
    anl_t *w;
    npf_udpf *u;
    uint32_t id[4];

    /* 1. the caller (frames on a real AnLiu connection): 1, then from the
     * top round to 1, which is in use, and on to 3 */
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    w = anl_create(77, &cfg, NULL);
    u = npf_udpf_new(l, w, 1, NULL, &uio, NULL, 0);
    g_units = 0;
    id[0] = open_out(u, 1000);
    u->next_id = UINT32_MAX - 4;
    id[1] = open_out(u, 1001);
    id[2] = open_out(u, 1002);
    id[3] = open_out(u, 1003);
    CHECK(id[0] == 1 && id[1] == UINT32_MAX - 2 && id[2] == UINT32_MAX && id[3] == 3,
          "caller's ids %u %x %x %u", id[0], id[1], id[2], id[3]);
    CHECK(u->nflows == 4 && g_units == 0 && u->st.dgrams_out == 4, "four flows, all sent, none closed (%d, %d)",
          u->nflows, g_units);
    npf_udpf_free(u);
    anl_release(w);

    /* 2. the callee (no stream: the frames are dropped, the flows made):
     * 2, then round past 0 and 2 (in use) to 4 */
    u = npf_udpf_new(l, NULL, 0, NULL, &uio, NULL, 0);
    id[0] = open_out(u, 1000);
    u->next_id = UINT32_MAX - 3;
    id[1] = open_out(u, 1001);
    id[2] = open_out(u, 1002);
    CHECK(id[0] == 2 && id[1] == UINT32_MAX - 1 && id[2] == 4, "callee's ids %u %x %u", id[0], id[1], id[2]);
    CHECK(u->nflows == 3 && g_units == 0, "three flows, none closed");
    npf_udpf_free(u);

    npf_loop_free(l);
    return fails;
}

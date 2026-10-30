/* UDP forwarding (data-channel.md 15). UT-43: this side's flow ids go round
 * the 32 bits, skipping 0 and the ids still in use. UT-47: a CLOSE's reason
 * is counted (sent or received) as what happened. The test includes
 * udpfwd.c (the counter is not in the library's interface). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "../../src/stream/udpfwd.c"
#include "test.h"

static int g_units;                 /* units sent */
static uint8_t g_last[6];           /* the last of them */
static npf_loop *g_stop;            /* a CLOSE stops it */

static int unit_rec(void *arg, const uint8_t *buf, size_t len)
{
    memcpy(g_last, buf, len < sizeof g_last ? len : sizeof g_last);
    g_units++;
    (void)arg;
    if (g_stop && buf[0] == NPF_UDP_CLOSE)
        npf_loop_stop(g_stop);
    return 0;
}

static int no_name(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    (void)node;
    (void)service;
    (void)hints;
    *res = NULL;
    return EAI_NONAME;
}

/* the caller's -R .../udp mappings: 1 to 127.0.0.1:9, 2 to a name */
static const char *rev_of(void *arg, uint32_t lid, uint16_t *port)
{
    (void)arg;
    *port = 9;
    return lid == 1 ? "127.0.0.1" : lid == 2 ? "nowhere.invalid" : NULL;
}

static void stop_at(npf_loop *l, void *arg)
{
    *(npf_timer **)arg = NULL;
    npf_loop_stop(l);
}

/* the callee's first frame of flow id through the caller's mapping lid */
static void rev_frame(npf_udpf *u, uint32_t id, uint32_t lid)
{
    uint8_t b[10];
    npf_le32(b, id);
    b[4] = F_LID;
    npf_le32(b + 5, lid);
    b[9] = 'x';
    npf_udpf_frame_in(u, b, sizeof b);
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

/* UT-47 */
static void test_close_reasons(npf_loop *l)
{
    npf_udpf_io uio = {unit_rec, no_kick, NULL, rev_of};
    npf_resolve_gai_fn saved = npf_resolve_gai;
    anl_config cfg;
    anl_t *w;
    npf_udpf *u;
    npf_timer *t;
    uint8_t b[6];
    int r;

    /* 1. the callee's CLOSEs for the caller's flows: each reason in its own
     * count, an unknown one as a failure, an idle one not at all */
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    w = anl_create(78, &cfg, NULL);
    u = npf_udpf_new(l, w, 1, NULL, &uio, NULL, 0);
    for (r = NPF_UDP_R_CLOSED; r <= NPF_UDP_R_N; r++) {
        uint32_t id = open_out(u, (uint16_t)(2000 + r));
        b[0] = NPF_UDP_CLOSE;
        npf_le32(b + 1, id);
        b[5] = (uint8_t)(r == NPF_UDP_R_N ? 9 : r);
        npf_udpf_unit_input(u, b, sizeof b);
    }
    CHECK(u->nflows == 0 && u->st.ends[NPF_UDP_R_CLOSED] == 0 && u->st.ends[NPF_UDP_R_REFUSED] == 1
          && u->st.ends[NPF_UDP_R_LIMIT] == 1 && u->st.ends[NPF_UDP_R_FAILED] == 2 && u->st.ends[NPF_UDP_R_TARGET] == 1,
          "received CLOSEs counted by reason (%d flows; %llu %llu %llu %llu)", u->nflows,
          (unsigned long long)u->st.ends[2], (unsigned long long)u->st.ends[3], (unsigned long long)u->st.ends[4],
          (unsigned long long)u->st.ends[5]);
    npf_udpf_free(u);
    anl_release(w);

    /* 2. the caller's own CLOSEs for the callee's -R flows: not a mapping
     * (refused), a mapping to an address (opened), to a name that does
     * not resolve (the target failed, not this side) */
    npf_resolve_gai = no_name;
    u = npf_udpf_new(l, NULL, 1, NULL, &uio, NULL, 0);
    g_units = 0;
    rev_frame(u, 2, 7);
    CHECK(g_last[0] == NPF_UDP_CLOSE && g_last[5] == NPF_UDP_R_REFUSED && u->st.ends[NPF_UDP_R_REFUSED] == 1,
          "no such mapping: refused");
    rev_frame(u, 4, 1);
    CHECK(g_last[0] == NPF_UDP_OK && u->nflows == 1, "a mapping to an address: OK");
    rev_frame(u, 6, 2);
    t = npf_timer_add(l, 5000, stop_at, &t);
    g_stop = l;
    npf_loop_run(l);
    g_stop = NULL;
    npf_timer_cancel(l, t);
    CHECK(g_last[0] == NPF_UDP_CLOSE && g_last[5] == NPF_UDP_R_TARGET && u->st.ends[NPF_UDP_R_TARGET] == 1
          && u->st.ends[NPF_UDP_R_FAILED] == 0 && u->nflows == 1 && u->nresolving == 0,
          "a name that does not resolve: the target failed (reason %d)", g_last[5]);
    npf_udpf_free(u);
    npf_resolve_gai = saved;
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

    test_close_reasons(l);
    npf_loop_free(l);
    return fails;
}

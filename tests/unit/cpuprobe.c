/* The CPU a session costs: a listener on one loop, a direct session from a
 * caller on another, a TCP sublink carrying N MB through the callee to a
 * sink; the loops' CPU time counted per side; then the idle cost of S
 * sessions over a few seconds. Not a test: npf_cpuprobe [MB] [sessions]. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "npf/crypto.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/tunnel.h"
#include "call_internal.h"

typedef struct side { npf_node node; int established, closed; npf_call *last; } side;
static void on_state(npf_node *n, npf_call *c, int st, const char *why, void *arg)
{
    side *s = arg; (void)n; (void)why;
    s->last = c;
    if (st == NPF_CALL_ESTABLISHED) s->established++;
    if (st == NPF_CALL_CLOSED) s->closed++;
}
static int init_side(side *s, npf_loop *loop)
{
    npf_node_cfg cfg; npf_identity id; uint8_t seed[32];
    npf_node_hooks hooks = {NULL, on_state, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    memset(s, 0, sizeof *s); memset(&cfg, 0, sizeof cfg); cfg.offline = 1;
    npf_random(seed, 32); npf_identity_from_seed(&id, seed);
    return npf_node_init(&s->node, loop, &cfg, &id, &hooks, s);
}

static double cpu_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}
static double cpu[2];                   /* ms: callee, caller */
static long iters[2], early[2];         /* turns, and turns the loop left before its timeout (work came) */
static int swap;                        /* NPF_PROBE_SWAP: the caller's loop first (an order artefact?) */
static void one(npf_loop *l, int side, int ms)
{
    double t0 = cpu_ms();
    int64_t w0 = npf_mono_ms();
    npf_loop_once(l, ms);
    cpu[side] += cpu_ms() - t0;
    iters[side]++;
    early[side] += npf_mono_ms() - w0 < ms - 1;
}
static void turn(npf_loop *lc, npf_loop *la, int ms)
{
    one(swap ? la : lc, swap ? 1 : 0, ms);
    one(swap ? lc : la, swap ? 0 : 1, ms);
}

/* the sink: a TCP listener read by a thread, the bytes counted */
static int sink_fd;
static volatile long sink_got;
static void *sink_main(void *arg)
{
    int c = accept(sink_fd, NULL, NULL);
    static char buf[1 << 16];
    (void)arg;
    for (;;) {
        ssize_t r = read(c, buf, sizeof buf);
        if (r <= 0) break;
        sink_got += r;
    }
    close(c);
    return NULL;
}
/* the source: a thread writing total bytes into the caller's end of the sublink */
static long src_total;
static void *src_main(void *arg)
{
    int fd = *(int *)arg;
    static char buf[1 << 16];
    long left = src_total;
    memset(buf, 'x', sizeof buf);
    while (left > 0) {
        ssize_t w = write(fd, buf, left < (long)sizeof buf ? (size_t)left : sizeof buf);
        if (w <= 0) break;
        left -= w;
    }
    shutdown(fd, SHUT_WR);
    return NULL;
}

int main(int argc, char **argv)
{
    long mb = argc > 1 ? atol(argv[1]) : 64;
    int S = argc > 2 ? atoi(argv[2]) : 16, i, sp[2], port;
    npf_loop *lc = npf_loop_new(), *la = npf_loop_new();
    static side L, A;
    npf_policy pol; npf_direct *dl; uint8_t psk[32]; char spec[64], k[44];
    struct sockaddr_storage to; struct sockaddr_in sa; socklen_t sl = sizeof sa;
    pthread_t th_sink, th_src;
    int64_t w0; double c0, c1;
    swap = getenv("NPF_PROBE_SWAP") != NULL;
    init_side(&L, lc); init_side(&A, la);
    memset(&pol, 0, sizeof pol); npf_policy_add(&pol, "lan"); npf_policy_refresh(&pol);
    npf_direct_genpsk(k); npf_direct_psk(k, NULL, psk);
    snprintf(spec, sizeof spec, "127.0.0.1:%d", 20000 + (int)npf_rand_range(0, 20000));
    dl = npf_direct_listen(&L.node, spec, psk, &pol);
    npf_direct_resolve(spec, &to);
    /* the sink */
    sink_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sink_fd, (struct sockaddr *)&sa, sizeof sa); getsockname(sink_fd, (struct sockaddr *)&sa, &sl); listen(sink_fd, 4);
    port = ntohs(sa.sin_port);
    pthread_create(&th_sink, NULL, sink_main, NULL);
    /* one session, one sublink to the sink */
    {
        npf_call *ca = npf_direct_connect(&A.node, &to, psk);
        int64_t until = npf_mono_ms() + 5000;
        while ((A.established < 1 || L.established < 1) && npf_mono_ms() < until) turn(lc, la, 2);
        while (!npf_call_ready(ca) && npf_mono_ms() < until) turn(lc, la, 2);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        if (npf_call_open(ca, sp[0], 0, "127.0.0.1", (uint16_t)port) < 0) { fprintf(stderr, "open failed\n"); return 1; }
    }
    src_total = mb << 20;
    cpu[0] = cpu[1] = 0; iters[0] = iters[1] = 0;
    w0 = npf_mono_ms();
    pthread_create(&th_src, NULL, src_main, &sp[1]);
    while (sink_got < src_total && npf_mono_ms() - w0 < 120000) turn(lc, la, 1);
    {
        double wall = (npf_mono_ms() - w0) / 1e3;
        printf("transfer %ld MB through the tunnel: %.1f s wall, %.0f MB/s\n", mb, wall, mb / wall);
        printf("  callee loop: %.0f ms CPU (%.1f ms/MB, %ld loop turns)\n", cpu[0], cpu[0] / mb, iters[0]);
        printf("  caller loop: %.0f ms CPU (%.1f ms/MB, %ld loop turns)\n", cpu[1], cpu[1] / mb, iters[1]);
    }
    pthread_join(th_src, NULL);
    /* S more sessions, then idle */
    for (i = 1; i < S; i++) {
        int64_t until = npf_mono_ms() + 5000;
        npf_direct_connect(&A.node, &to, psk);
        while (L.established < i + 1 && npf_mono_ms() < until) turn(lc, la, 2);
    }
    cpu[0] = cpu[1] = 0; iters[0] = iters[1] = 0; early[0] = early[1] = 0;
    w0 = npf_mono_ms(); c0 = cpu_ms();
    while (npf_mono_ms() - w0 < 10000) turn(lc, la, 50);
    c1 = cpu_ms();
    printf("idle, %d sessions, 10 s: callee %.1f ms CPU (%ld wakes), caller %.1f ms CPU (%ld wakes); %ld turns, whole thread %.1f ms\n",
           S, cpu[0], early[0], cpu[1], early[1], iters[0], c1 - c0);
    npf_direct_close(dl); npf_node_stop(&L.node); npf_node_stop(&A.node);
    return 0;
}

/* The heap of a callee per session: a listener on one loop, N direct
 * initiators on another, the heap counted per side through malloc wrappers
 * (glibc). Not a test: npf_memprobe [N] prints the bytes per session and the
 * live blocks by size and allocation site (addr2line -e npf_memprobe ADDR). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <execinfo.h>

#include "npf/crypto.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/tunnel.h"
#include "call_internal.h"
#include "tunnel_internal.h"

extern void *__libc_malloc(size_t), *__libc_calloc(size_t, size_t), *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
/* the wrappers must be the whole process's (libc's own calls included):
 * seen from outside although the build hides symbols */
#define WRAP __attribute__((visibility("default")))

static int tag = 2, busy;                     /* 0 callee, 1 caller, 2 other */
static long live[3], peak[3], blocks[3];
typedef struct hdr { size_t size; int tag; int pad; void *site[4]; } hdr;   /* 48 bytes */
#define HSZ 48
#define MAXLIVE 200000
static hdr *lives[MAXLIVE];
static int nlive;

static void account(hdr *h) {
    live[h->tag] += (long)h->size; blocks[h->tag]++;
    if (live[h->tag] > peak[h->tag]) peak[h->tag] = live[h->tag];
    if (nlive < MAXLIVE) lives[nlive++] = h;
}
static void unaccount(hdr *h) {
    int i;
    live[h->tag] -= (long)h->size; blocks[h->tag]--;
    for (i = nlive - 1; i >= 0; i--) if (lives[i] == h) { lives[i] = lives[--nlive]; break; }
}
WRAP void *malloc(size_t n) {
    hdr *h = __libc_malloc(n + HSZ);
    if (!h) return NULL;
    h->size = n; h->tag = tag;
    memset(h->site, 0, sizeof h->site);
    if (tag == 0 && !busy) { busy = 1; backtrace(h->site, 4); busy = 0; }
    account(h);
    return (char *)h + HSZ;
}
WRAP void *calloc(size_t c, size_t n) {
    void *p = malloc(c * n);
    if (p) memset(p, 0, c * n);
    return p;
}
WRAP void free(void *p) {
    hdr *h;
    if (!p) return;
    h = (hdr *)((char *)p - HSZ);
    unaccount(h);
    __libc_free(h);
}
WRAP void *realloc(void *p, size_t n) {
    hdr *h, *q;
    if (!p) return malloc(n);
    h = (hdr *)((char *)p - HSZ);
    unaccount(h);
    q = __libc_realloc(h, n + HSZ);
    if (!q) { account(h); return NULL; }
    q->size = n; q->tag = tag;
    if (tag == 0 && !busy) { busy = 1; backtrace(q->site, 4); busy = 0; }
    account(q);
    return (char *)q + HSZ;
}

typedef struct side { npf_node node; int established, closed; } side;
static void on_state(npf_node *n, npf_call *c, int st, const char *why, void *arg)
{
    side *s = arg; (void)n; (void)c; (void)why;
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
static void spin(npf_loop *lc, npf_loop *la, int *flag, int want, int ms)
{
    int64_t until = npf_mono_ms() + ms;
    while (*flag < want && npf_mono_ms() < until) {
        tag = 0; npf_loop_once(lc, 2);
        tag = 1; npf_loop_once(la, 2);
        tag = 2;
    }
}
static void dump_callee_sites(const char *when)
{
    /* live callee blocks grouped by (size, site[2]) */
    struct { size_t size; void *site; long n; } g[512]; int ng = 0, i, j;
    for (i = 0; i < nlive; i++) {
        hdr *h = lives[i];
        if (h->tag != 0) continue;
        for (j = 0; j < ng; j++) if (g[j].size == h->size && g[j].site == h->site[2]) break;
        if (j == ng && ng < 512) { g[ng].size = h->size; g[ng].site = h->site[2]; g[ng].n = 0; ng++; }
        if (j < ng) g[j].n++;
    }
    printf("-- callee live blocks %s (size x count = bytes, caller of the allocating function):\n", when);
    for (i = 0; i < ng; i++) {
        char **sym = backtrace_symbols(&g[i].site, 1);
        if (g[i].size * g[i].n >= 1024)
            printf("  %7zu x %4ld = %8ld  %s\n", g[i].size, g[i].n, (long)g[i].size * g[i].n, sym ? sym[0] : "?");
        free(sym);
    }
}

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 8, i;
    npf_loop *lc, *la;
    static side L, A;
    npf_policy pol; npf_direct *dl; uint8_t psk[32]; char spec[64], k[44];
    struct sockaddr_storage to; long base, after;
    printf("sizeof: npf_call %zu  npf_tunnel %zu  sublink %zu  relay_c %zu  noise_hs %zu  cpace %zu  node %zu  policy %zu  punch_cfg %zu  sockaddr_storage %zu\n",
           sizeof(npf_call), sizeof(npf_tunnel), sizeof(sublink), sizeof(relay_c), sizeof(npf_noise_hs), sizeof(npf_cpace),
           sizeof(npf_node), sizeof(npf_policy), sizeof(npf_punch_cfg), sizeof(struct sockaddr_storage));
    tag = 0; lc = npf_loop_new(); init_side(&L, lc);
    tag = 1; la = npf_loop_new(); init_side(&A, la);
    tag = 0;
    memset(&pol, 0, sizeof pol); npf_policy_add(&pol, "lan"); npf_policy_refresh(&pol);
    npf_direct_genpsk(k); npf_direct_psk(k, NULL, psk);
    snprintf(spec, sizeof spec, "127.0.0.1:%d", 20000 + (int)npf_rand_range(0, 20000));
    dl = npf_direct_listen(&L.node, spec, psk, &pol);
    npf_direct_resolve(spec, &to);
    tag = 2;
    base = live[0];
    printf("callee baseline (node + listener): %ld bytes in %ld blocks\n", base, blocks[0]);
    for (i = 0; i < N; i++) {
        long before = live[0];
        tag = 1; npf_direct_connect(&A.node, &to, psk); tag = 2;
        spin(lc, la, &L.established, i + 1, 5000);
        spin(lc, la, &A.established, i + 1, 2000);
        printf("session %2d established: callee +%ld bytes (live %ld, peak %ld)\n", i + 1, live[0] - before, live[0], peak[0]);
    }
    /* idle a second: timers and keepalives, nothing else */
    { int64_t until = npf_mono_ms() + 1500; int z = 0; while (npf_mono_ms() < until) spin(lc, la, &z, 1, 50); }
    after = live[0];
    printf("callee with %d sessions: %ld bytes live, %ld blocks, peak %ld; per session %ld\n", N, after, blocks[0], peak[0], (after - base) / N);
    dump_callee_sites("with sessions");
    { struct mallinfo2 m = mallinfo2(); printf("process heap (mallinfo2): arena %zu in use %zu\n", m.arena, m.uordblks); }
    tag = 0; npf_direct_close(dl); npf_node_stop(&L.node); tag = 1; npf_node_stop(&A.node); tag = 2;
    return 0;
}

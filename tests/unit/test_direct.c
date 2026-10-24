/* Direct connections (data-channel.md 13): two offline nodes on one loop, a
 * listener with a pre-shared key, an initiator with the right key becomes a
 * session, one with the wrong key gets no answer and creates no session; the
 * initiator's close reaches the listener. Also the loop's wake hook. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "npf/crypto.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/tunnel.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

typedef struct side {
    npf_node node;
    int established, closed, connecting;
    npf_call *last;
    char why[32];               /* copied: the string is only valid during the callback */
} side;

static void on_state(npf_node *n, npf_call *c, int st, const char *why, void *arg)
{
    side *s = arg;
    (void)n;
    s->last = c;
    if (st == NPF_CALL_CONNECTING) s->connecting++;
    if (st == NPF_CALL_ESTABLISHED) s->established++;
    if (st == NPF_CALL_CLOSED) { s->closed++; snprintf(s->why, sizeof s->why, "%s", why ? why : ""); }
}

static int woken;
static void on_wake(npf_loop *l, void *arg) { (void)l; (void)arg; woken++; }

static int init_side(side *s, npf_loop *loop)
{
    npf_node_cfg cfg;
    npf_node_hooks hooks = {NULL, on_state, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    npf_identity id;
    uint8_t seed[32];
    memset(s, 0, sizeof *s);
    memset(&cfg, 0, sizeof cfg);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    return npf_node_init(&s->node, loop, &cfg, &id, &hooks, s);
}

static void run_until(npf_loop *loop, int *flag, int want, int ms)
{
    int64_t until = npf_mono_ms() + ms;
    while (*flag < want && npf_mono_ms() < until)
        npf_loop_once(loop, 10);
}

int test_direct(void)
{
    npf_loop *loop = npf_loop_new();
    static side L, A, B;
    npf_policy pol;
    npf_direct *dl;
    uint8_t psk[32], wrong[32];
    char spec[64], k[44];
    struct sockaddr_storage to;
    npf_call *ca, *cb;
    int port;

    CHECK(loop != NULL, "loop");
    /* the wake hook runs on the loop after npf_loop_wake() */
    npf_loop_on_wake(loop, on_wake, NULL);
    npf_loop_wake(loop);
    npf_loop_once(loop, 10);
    CHECK(woken == 1, "wake hook ran %d times", woken);
    npf_loop_once(loop, 10);
    CHECK(woken == 1, "wake hook not repeated");

    CHECK(init_side(&L, loop) == 0 && init_side(&A, loop) == 0 && init_side(&B, loop) == 0, "nodes");
    memset(&pol, 0, sizeof pol);
    npf_policy_add(&pol, "lan");           /* the host and its LAN (a resource) */
    npf_policy_refresh(&pol);

    npf_direct_genpsk(k);
    CHECK(strlen(k) == 43 && npf_direct_psk(k, NULL, psk) == 0, "genpsk round trip");
    CHECK(npf_direct_psk("short", NULL, wrong) < 0, "bad key text refused");
    npf_random(wrong, 32);

    /* the listener's port: the main socket's port of L is free for a second socket? no: pick 20000 + random */
    port = 20000 + (int)npf_rand_range(0, 20000);
    snprintf(spec, sizeof spec, "127.0.0.1:%d", port);
    dl = npf_direct_listen(&L.node, spec, psk, &pol);
    CHECK(dl != NULL, "listen on %s", spec);
    if (!dl)
        return fails;

    /* right key: a session on both sides */
    CHECK(npf_direct_resolve(spec, &to) == 0, "resolve");
    ca = npf_direct_connect(&A.node, &to, psk);
    CHECK(ca != NULL, "connect");
    run_until(loop, &A.established, 1, 3000);
    run_until(loop, &L.established, 1, 1000);
    CHECK(A.established == 1 && L.established == 1, "established (A %d, L %d)", A.established, L.established);
    CHECK(ca && strcmp(npf_call_path(ca), "direct") == 0, "path is direct");
    CHECK(npf_call_auth(ca) == NPF_AUTH_DIRECT, "auth is direct");

    /* wrong key: silence, no session on the listener */
    cb = npf_direct_connect(&B.node, &to, wrong);
    CHECK(cb != NULL, "connect with the wrong key starts");
    run_until(loop, &L.connecting, 2, 1500);
    CHECK(L.connecting == 1 && L.established == 1, "wrong key created no session (%d)", L.connecting);
    CHECK(B.established == 0 && B.closed == 0, "initiator still retrying");

    /* the initiator closes: the listener sees the close; a reason goes as a
     * code (a-z 0-9 _), never as JSON of its own */
    npf_call_end(ca, "bye\"},\"x\":\"1");
    run_until(loop, &L.closed, 1, 3000);
    CHECK(A.closed == 1 && L.closed == 1 && strcmp(L.why, "byex1") == 0 && strcmp(A.why, "byex1") == 0,
          "close propagated (%d/%d %s/%s)", A.closed, L.closed, A.why, L.why);

    /* the wrong-key initiator gives up by itself after its retries (~14 s): end it here instead */
    npf_call_end(cb, "closed");
    npf_loop_once(loop, 10);

    /* a grant call refused before anything starts: no grant, an empty or too
     * long one, a chain that does not verify (no roots here) */
    {
        static uint8_t g[600], chain[64];
        npf_call *before = A.node.calls;
        memset(g, 1, sizeof g);
        CHECK(npf_call_start_grant(&A.node, 123, chain, sizeof chain, NULL, 16) == NULL, "no grant refused");
        CHECK(npf_call_start_grant(&A.node, 123, chain, sizeof chain, g, 0) == NULL, "empty grant refused");
        CHECK(npf_call_start_grant(&A.node, 123, chain, sizeof chain, g, 513) == NULL, "long grant refused");
        CHECK(npf_call_start_grant(&A.node, 123, chain, sizeof chain, g, 64) == NULL, "bad chain refused");
        CHECK(A.node.calls == before, "no call made");
    }

    npf_direct_close(dl);
    npf_node_stop(&L.node);
    npf_node_stop(&A.node);
    npf_node_stop(&B.node);
    npf_loop_free(loop);
    return fails;
}

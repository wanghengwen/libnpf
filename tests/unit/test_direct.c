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
#include "npf/json.h"
#include "call_internal.h"
#include "../../src/tunnel/tunnel_internal.h"
#include "test.h"

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
    static const npf_node_hooks hooks = {.on_call_state = on_state};
    memset(s, 0, sizeof *s);
    return offline_node(&s->node, loop, &hooks, s);
}

/* the session moves to the WS relay: the AnLiu connection stays (its
 * carrier changes), and with it the requests awaiting a reply and the
 * sublinks */
typedef struct move_rec {
    int fails, sub_done, sub_closed;
} move_rec;

static void move_ctl(npf_call *c, const npf_env *e, int ok, void *arg)
{
    move_rec *r = arg;
    (void)c;
    (void)e;
    r->fails += !ok;
}

static void move_sub_done(npf_call *c, uint32_t sid, const npf_sublink_stats *st, void *arg)
{
    move_rec *r = arg;
    (void)c;
    (void)sid;
    (void)st;
    r->sub_done++;
}

static move_rec *vrec;
static ssize_t v_read(void *a, uint8_t *b, size_t cap) { (void)a; (void)b; (void)cap; return -1; }
static ssize_t v_write(void *a, const uint8_t *b, size_t n) { (void)a; (void)b; return (ssize_t)n; }
static unsigned v_ready(void *a) { (void)a; return 0; }
static void v_shutdown(void *a) { (void)a; }
static void v_closed(void *a, int rst) { (void)a; (void)rst; vrec->sub_closed++; }
static const npf_vend_io vio = {v_read, v_write, v_ready, v_shutdown, v_closed};

static int ws_move(npf_call *c)
{
    m_relay r;
    memset(&r, 0, sizeof r);
    snprintf(r.ws, sizeof r.ws, "wss://127.0.0.1:9/r");
    return call_ws_setup(c, &r);
}

static void test_tunnel_move(npf_loop *loop, const struct sockaddr_storage *to, const uint8_t psk[32], side *L)
{
    static side A2;
    move_rec r1;
    npf_call *c;
    int want = L->established;

    memset(&r1, 0, sizeof r1);
    CHECK(init_side(&A2, loop) == 0, "a node for the move");
    /* the relay's URL blocked: the move connects nowhere */
    A2.node.th.block_relay = "wss://127.0.0.1:9/r";
    A2.node.cfg.server_url = "wss://127.0.0.1:9/";
    c = npf_direct_connect(&A2.node, to, psk);
    LOOP_UNTIL(loop, A2.established >= 1, 3000);
    LOOP_UNTIL(loop, L->established >= want + 1, 1000);
    CHECK(c && A2.established == 1 && c->tun && npf_tunnel_is_ready(c->tun), "second session up");
    if (c && A2.established == 1) {
        vrec = &r1;
        npf_call_on_sublink_done(c, move_sub_done, &r1);
        CHECK(npf_tunnel_open_v(c->tun, &vio, NULL, "127.0.0.1", 9) > 0, "a virtual sublink");
        CHECK(npf_call_ctl_request(c, "one", NULL, move_ctl, &r1) == 0, "a request");
        CHECK(ws_move(c) == -1, "the blocked relay: no connection");
        CHECK(r1.fails == 0 && r1.sub_done == 0 && r1.sub_closed == 0, "the request and the sublink stay (%d/%d/%d)",
              r1.fails, r1.sub_done, r1.sub_closed);
        CHECK(c->tun && c->anl && c->stream && call_has_ws(c) && !call_has_p2p(c) && !call_over(c),
              "the AnLiu connection stays, on the WS relay's carrier");
        npf_call_end(c, "closed");
        CHECK(r1.fails == 1, "the request fails with the session's end");
        npf_loop_once(loop, 10);
    }
    npf_node_stop(&A2.node);
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
    LOOP_UNTIL(loop, A.established >= 1, 3000);
    LOOP_UNTIL(loop, L.established >= 1, 1000);
    CHECK(A.established == 1 && L.established == 1, "established (A %d, L %d)", A.established, L.established);
    CHECK(ca && strcmp(npf_call_path(ca), "direct") == 0, "path is direct");
    CHECK(npf_call_auth(ca) == NPF_AUTH_DIRECT, "auth is direct");

    /* wrong key: silence, no session on the listener */
    cb = npf_direct_connect(&B.node, &to, wrong);
    CHECK(cb != NULL, "connect with the wrong key starts");
    LOOP_UNTIL(loop, L.connecting >= 2, 1500);
    CHECK(L.connecting == 1 && L.established == 1, "wrong key created no session (%d)", L.connecting);
    CHECK(B.established == 0 && B.closed == 0, "initiator still retrying");

    /* the initiator closes: the listener sees the close; a reason goes as a
     * code (a-z 0-9 _), never as JSON of its own */
    npf_call_end(ca, "bye\"},\"x\":\"1");
    LOOP_UNTIL(loop, L.closed >= 1, 3000);
    CHECK(A.closed == 1 && L.closed == 1 && strcmp(L.why, "byex1") == 0 && strcmp(A.why, "byex1") == 0,
          "close propagated (%d/%d %s/%s)", A.closed, L.closed, A.why, L.why);

    /* the wrong-key initiator gives up by itself after its retries (~14 s): end it here instead */
    npf_call_end(cb, "closed");
    npf_loop_once(loop, 10);

    test_tunnel_move(loop, &to, psk, &L);

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

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

/* the tunnel replaced (the session moves to the WS relay): its requests
 * fail at once, once each; a request made from a failure finds no tunnel;
 * a sublink's end sees none either; a failure that ends the session stops
 * the move */
typedef struct move_rec {
    int fails, again_ok, end_it;
    int sub_done, sub_closed, saw_tun;
    int made_transport;
} move_rec;

static void move_ctl(npf_call *c, const npf_json *j, int ok, void *arg)
{
    move_rec *r = arg;
    (void)j;
    r->fails += !ok;
    if (npf_call_ctl_request(c, "again", NULL, move_ctl, r) == 0)
        r->again_ok++;
    if (r->end_it)
        npf_call_end(c, "closed");
}

static void move_sub_done(npf_call *c, uint32_t sid, const npf_sublink_stats *st, void *arg)
{
    move_rec *r = arg;
    (void)sid;
    (void)st;
    r->sub_done++;
    r->saw_tun += c->tun != NULL;
    r->made_transport += call_media_of(c) != NULL || call_udp_of(c) != NULL;
}

static move_rec *vrec;
static npf_call *vcall;
static ssize_t v_read(void *a, uint8_t *b, size_t cap) { (void)a; (void)b; (void)cap; return -1; }
static ssize_t v_write(void *a, const uint8_t *b, size_t n) { (void)a; (void)b; return (ssize_t)n; }
static unsigned v_ready(void *a) { (void)a; return 0; }
static void v_shutdown(void *a) { (void)a; }
static void v_closed(void *a, int rst) { (void)a; (void)rst; vrec->sub_closed++; vrec->saw_tun += vcall->tun != NULL; }
static const npf_vend_io vio = {v_read, v_write, v_ready, v_shutdown, v_closed};

static int ws_move(npf_call *c)
{
    static const char js[] = "{\"ws\":{\"url\":\"wss://127.0.0.1:9/r\",\"server_id\":0}}";
    npf_jtok tok[16];
    npf_json j;
    if (npf_json_parse(&j, js, sizeof js - 1, tok, 16) < 0)
        return -2;
    return call_ws_setup(c, &j, 0);
}

static void test_tunnel_move(npf_loop *loop, const struct sockaddr_storage *to, const uint8_t psk[32], side *L)
{
    static side A2, A3;
    move_rec r1, r2;
    npf_call *c;
    int want = L->established;

    memset(&r1, 0, sizeof r1);
    memset(&r2, 0, sizeof r2);
    CHECK(init_side(&A2, loop) == 0 && init_side(&A3, loop) == 0, "nodes for the move");
    /* the relay's URL blocked: the move stops before connecting anywhere */
    A2.node.test_block_relay = A3.node.test_block_relay = "wss://127.0.0.1:9/r";
    A2.node.cfg.server_url = A3.node.cfg.server_url = "wss://127.0.0.1:9/";

    c = npf_direct_connect(&A2.node, to, psk);
    run_until(loop, &A2.established, 1, 3000);
    run_until(loop, &L->established, want + 1, 1000);
    CHECK(c && A2.established == 1 && c->tun && npf_tunnel_is_ready(c->tun), "second session up");
    if (c && A2.established == 1) {
        vrec = &r1;
        vcall = c;
        npf_call_on_sublink_done(c, move_sub_done, &r1);
        CHECK(npf_tunnel_open_v(c->tun, &vio, NULL, "127.0.0.1", 9) > 0, "a virtual sublink");
        CHECK(npf_call_ctl_request(c, "one", NULL, move_ctl, &r1) == 0
              && npf_call_ctl_request(c, "two", NULL, move_ctl, &r1) == 0, "two requests");
        CHECK(ws_move(c) == -1, "move stops at the blocked relay");
        CHECK(r1.fails == 2, "each request failed once (%d)", r1.fails);
        CHECK(r1.again_ok == 0, "no request from a failure (%d)", r1.again_ok);
        CHECK(r1.sub_done == 1 && r1.sub_closed == 1, "sublink ended (%d/%d)", r1.sub_done, r1.sub_closed);
        CHECK(r1.saw_tun == 0, "the ends saw no tunnel (%d)", r1.saw_tun);
        CHECK(r1.made_transport == 0, "end callbacks cannot create adapters on the retiring transport");
        CHECK(!c->tun && !c->anl && !c->stream && c->ws_mode && !c->ended, "transport gone, session on");
        /* the -R mappings in use go on in the tunnel the WS relay brings */
        call_crev_add(c, 7, "127.0.0.1", 8080, 0);
        call_crev_add(c, 9, "127.0.0.1", 5353, 1);
        c->tun = call_tunnel_new(c);
        CHECK(c->tun && c->tun->nrev == 1 && c->tun->rev[0]->id == 7 && c->tun->rev[0]->port == 8080,
              "a new tunnel has the TCP -R mapping");
        npf_call_end(c, "closed");
        npf_loop_once(loop, 10);
    }

    want = L->established;
    c = npf_direct_connect(&A3.node, to, psk);
    run_until(loop, &A3.established, 1, 3000);
    run_until(loop, &L->established, want + 1, 1000);
    CHECK(c && A3.established == 1, "third session up");
    if (c && A3.established == 1) {
        r2.end_it = 1;
        CHECK(npf_call_ctl_request(c, "one", NULL, move_ctl, &r2) == 0, "a request");
        CHECK(ws_move(c) == -1, "move stops");
        CHECK(r2.fails == 1 && c->ended && !c->ws_mode && !c->wsr, "ended in the failure: no WS relay (%d)",
              r2.fails);
        npf_loop_once(loop, 10);
    }
    npf_node_stop(&A2.node);
    npf_node_stop(&A3.node);
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

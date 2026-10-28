/* A call's state against the platform's messages, on an offline node (what
 * it would send to the platform read from its log):
 * - a callee established through the relay before its first punch_start
 *   (the time limit gone with the peer's hello) takes that punch_start as
 *   the accept: the platform then hears of its rounds (punch_update
 *   path_lost); it did not, every punch_update of the callee was dropped;
 * - a relay_switch the platform dropped without a word is asked again after
 *   RELAY_ASK_AGAIN_MS, not before (it was asked once only);
 * - the peer's punch_info port of a round goes to the punch of that round:
 *   with the next round planned while the last one still runs, it is kept
 *   for the next one (it went to the old punch, the new one never had it);
 * - a session moving to the WS relay ends its running punch and gives its
 *   hard-side sockets back (the punch ran on and could make the WS session
 *   "direct");
 * - a WS relay lost after it worked is connected again; after 5 connections
 *   in a row that did not pair it is given up (DEAD) and the caller asks
 *   for a relay elsewhere, the callee waits (architecture.md Q5; it was
 *   connected again every 2 s for good). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "npf/json.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/punch.h"
#include "call_internal.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* the lines logged while a check runs */
static char seen[8192];
static size_t seen_len;

static void log_hook(void *user, int level, const char *line)
{
    size_t l = strlen(line);
    (void)user, (void)level;
    if (seen_len + l + 2 < sizeof seen) {
        memcpy(seen + seen_len, line, l);
        seen_len += l;
        seen[seen_len++] = '\n';
        seen[seen_len] = 0;
    }
}

static void seen_clear(void)
{
    seen_len = 0;
    seen[0] = 0;
}

/* the platform's message (its data) to the call: j holds it */
static int msg(npf_json *j, npf_jtok *tok, int ntok, char *buf, size_t cap, const char *json)
{
    snprintf(buf, cap, "%s", json);
    return npf_json_parse(j, buf, strlen(buf), tok, ntok);
}

static void callee_accept_after_relay(npf_node *n)
{
    npf_call *c = call_new(n, 0);
    npf_jtok tok[32];
    npf_json j;
    char buf[256];
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "accept-test");
    /* established through the relay: the peer's hello ends the time limit */
    c->peer_hello = 1;
    call_set_state(c, NPF_CALL_ESTABLISHED, "relay");
    CHECK(!c->t_timeout && !c->accepted, "established, the time limit gone");
    /* the first punch_start (a round planned later): the accept */
    CHECK(msg(&j, tok, 32, buf, sizeof buf, "{\"call_id\":\"accept-test\"}") == 0, "punch_start JSON");
    call_handle_punch_start(c, &j, 0);
    CHECK(c->accepted, "a punch_start after the time limit is not taken as the accept");
    CHECK(!c->t_timeout, "the time limit armed again on an established call");
    /* the direct path lost later: the platform hears it */
    seen_clear();
    call_punch_report(c, "path_lost");
    CHECK(strstr(seen, "call accept-test: punch_update (path_lost)") != NULL,
          "the callee's punch_update dropped: %s", seen);
    npf_call_end(c, "test");
}

static int count(const char *s, const char *what)
{
    int k = 0;
    for (; (s = strstr(s, what)) != NULL; s++)
        k++;
    return k;
}

static void relay_asked_again(npf_node *n)
{
    npf_call *c = call_new(n, 1);
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "ask-test");
    c->state = NPF_CALL_CONNECTING;
    pm_add(&c->pm, &c->pw.p);           /* the session on the WS relay */
    seen_clear();
    call_ws_failed(c, "test");          /* the WS relay never worked: a relay on our own server */
    call_ws_failed(c, "test");          /* again at once: still waiting for the first */
    CHECK(count(seen, "asking for one on our own server") == 1, "asked %d times at once: %s",
          count(seen, "asking for one on our own server"), seen);
    c->pm.asked_ms -= RELAY_ASK_AGAIN_MS;    /* no allocation came: the platform dropped it */
    call_ws_failed(c, "test");
    CHECK(count(seen, "asking for one on our own server") == 2, "not asked again: %s", seen);
    npf_call_end(c, "test");
}

static void punch_done_cb(npf_punch *p, const npf_punch_result *res, int fd, void *arg)
{
    (void)p, (void)res, (void)fd, (void)arg;
}

/* a running S1 punch from fd (on loopback) to a port nobody reads */
static npf_punch *punch_running(npf_loop *loop, int fd, int *dead)
{
    npf_punch_cfg cfg;
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *dead = socket(AF_INET, SOCK_DGRAM, 0);
    if (*dead < 0 || bind(*dead, (struct sockaddr *)&a, sizeof a) < 0 || getsockname(*dead, (struct sockaddr *)&a, &al) < 0)
        return NULL;
    memset(&cfg, 0, sizeof cfg);
    cfg.plan.role = NPF_PUNCH_CONTROLLING;
    cfg.plan.strategy = NPF_PUNCH_S1;
    cfg.plan.family = AF_INET;
    cfg.plan.session_id = 7;
    cfg.plan.timeout_ms = 10000;
    cfg.fd6 = -1;
    memcpy(&cfg.peers[0], &a, sizeof a);
    cfg.npeers = 1;
    return npf_punch_new(loop, &cfg, fd, punch_done_cb, NULL);
}

static void punch_info_round(npf_node *n)
{
    npf_call *c = call_new(n, 1);
    npf_jtok tok[32];
    npf_json j;
    char buf[256];
    int dead = -1;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "info-test");
    c->punch = punch_running(n->loop, n->udp_fd, &dead);
    CHECK(c->punch && !npf_punch_finished(c->punch), "a running punch");
    c->punch_of = 1;                    /* round 1 still running here */
    c->punch_round = 2;                 /* round 2 planned (its start time to come) */
    CHECK(msg(&j, tok, 32, buf, sizeof buf, "{\"call_id\":\"info-test\",\"round\":2,\"port\":40001}") == 0,
          "punch_info JSON");
    call_handle_punch_info(c, &j, 0);
    CHECK(c->info_port == 40001 && c->info_round == 2, "round 2's port not kept for its punch (%u, round %d)",
          (unsigned)c->info_port, c->info_round);
    npf_call_end(c, "test");
    if (dead >= 0)
        close(dead);
}

static void ws_leaves_punch(npf_node *n)
{
    npf_call *c = call_new(n, 1);
    int dead = -1;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "leave-test");
    c->punch = punch_running(n->loop, n->udp_fd, &dead);
    CHECK(c->punch && !npf_punch_finished(c->punch), "a running punch");
    c->punch_of = c->punch_round = 1;
    c->punch_socks = 4;                 /* as an S3 hard side's */
    n->hard_punch_end = 0;
    call_relay_leave(c);
    CHECK(!c->punch && !c->punch_socks, "the punch runs on after the move to the WS relay");
    CHECK(n->hard_punch_end > 0, "its sockets not given back");
    npf_call_end(c, "test");
    if (dead >= 0)
        close(dead);
}

/* the WS relay lost after pairing: SUSPECT, connected again; 5 that fail: DEAD */
static void ws_gives_up(npf_node *n, int caller)
{
    static npf_test_hooks th;
    const npf_test_hooks *old = n->th;
    npf_call *c = call_new(n, caller);
    int k;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "ws-test-%d", caller);
    c->state = NPF_CALL_ESTABLISHED;
    th = *old;
    th.block_relay = "wss://blocked.test/relay";    /* every connection fails at once */
    n->th = &th;
    snprintf(c->pw.url, sizeof c->pw.url, "wss://blocked.test/relay");
    pm_add(&c->pm, &c->pw.p);
    c->pw.paired_once = 1;
    pm_rt(&c->pm, &c->pw.p, npf_mono_ms());
    seen_clear();
    call_ws_failed(c, "relay connection closed");   /* lost: in doubt, connected again in 2 s */
    CHECK(c->pw.p.health == PH_SUSPECT && c->pw.t_re && c->pw.fails == 0, "a WS relay lost: health %d, fails %d",
          c->pw.p.health, c->pw.fails);
    for (k = 1; k < 5; k++) {
        call_ws_failed(c, "cannot connect");
        CHECK(c->pw.p.health == PH_SUSPECT && c->pw.fails == k && c->pw.t_re, "reconnect %d failed: health %d",
              k, c->pw.p.health);
    }
    CHECK(!strstr(seen, "giving it up") && !strstr(seen, "relay_switch"), "given up before 5: %s", seen);
    call_ws_failed(c, "cannot connect");
    CHECK(c->pw.p.health == PH_DEAD && !c->pw.t_re && !c->pw.wsr, "5 failed: health %d", c->pw.p.health);
    CHECK(strstr(seen, "never paired: giving it up") != NULL, "not given up: %s", seen);
    CHECK(caller ? strstr(seen, "asking for one on our own server") != NULL
                 : strstr(seen, "asking for one") == NULL && strstr(seen, "waiting for the platform") != NULL,
          "%s: %s", caller ? "the caller did not ask elsewhere" : "the callee asked", seen);
    seen_clear();
    call_ws_failed(c, "cannot connect");            /* given up: nothing more */
    CHECK(!c->pw.t_re && !strstr(seen, "asking"), "after the verdict: %s", seen);
    n->th = old;
    npf_call_end(c, "test");
}

int test_call(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    npf_log_ctx lc, *old;
    uint8_t seed[32];

    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    memset(&lc, 0, sizeof lc);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    CHECK(loop && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return fails;
    lc.hook = log_hook;
    lc.level = NPF_LOG_DEBUG;
    old = npf_log_ctx_swap(&lc);

    callee_accept_after_relay(&node);
    relay_asked_again(&node);
    punch_info_round(&node);
    ws_leaves_punch(&node);
    ws_gives_up(&node, 1);
    ws_gives_up(&node, 0);

    npf_log_ctx_swap(old);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

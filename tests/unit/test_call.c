/* A call's state against the platform's messages, on an offline node (what
 * it would send to the platform read from its log):
 * - a callee established through the relay before its first punch_start
 *   (the time limit gone with the peer's hello) takes that punch_start as
 *   the accept: the platform then hears of its rounds (punch_update
 *   path_lost); it did not, every punch_update of the callee was dropped;
 * - a relay_switch the platform dropped without a word is asked again after
 *   RELAY_ASK_AGAIN_MS, not before (it was asked once only). */
#include <stdio.h>
#include <string.h>

#include "npf/json.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/platform.h"
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
    seen_clear();
    call_ws_failed(c, "test");          /* the WS relay never worked: a relay on our own server */
    call_ws_failed(c, "test");          /* again at once: still waiting for the first */
    CHECK(count(seen, "asking for one on our own server") == 1, "asked %d times at once: %s",
          count(seen, "asking for one on our own server"), seen);
    c->relay_asked_ms -= RELAY_ASK_AGAIN_MS;    /* no allocation came: the platform dropped it */
    call_ws_failed(c, "test");
    CHECK(count(seen, "asking for one on our own server") == 2, "not asked again: %s", seen);
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

    npf_log_ctx_swap(old);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

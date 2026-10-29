/* A call's state against the platform's messages, on an offline node (what
 * it would send to the platform read from its log; the call's and its
 * punching's state machines row by row: test_call_state.c):
 * - a request the platform dropped without a word is sent again 10 s after
 *   it, 30 s after that and every 30 s on, not between; a need that holds
 *   no longer is not (architecture.md Q1; it was sent once only);
 * - the UDP relay unreachable: a punching round waited for only when one
 *   is coming, not before the first punch_start (architecture.md 3.6);
 * - a WS relay lost after it worked is connected again; after 5 connections
 *   in a row that did not pair it is given up (DEAD) and the caller asks
 *   for a relay elsewhere, the callee waits (architecture.md Q5; it was
 *   connected again every 2 s for good);
 * - the call's one timer (architecture.md 4): a call not ended always has
 *   a deadline and its timer is never later than the earliest one, in
 *   each phase (the time limit, the session's AnLiu, a UDP relay binding,
 *   a WS relay connected again); a deadline moved earlier moves the timer,
 *   one moved later or gone leaves it early and the tick finds nothing due
 *   then, an ended call has none. */
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

static int count(const char *s, const char *what)
{
    int k = 0;
    for (; (s = strstr(s, what)) != NULL; s++)
        k++;
    return k;
}

static void relay_asked_again(npf_node *n)
{
    static const int64_t at[] = {9999, 10000, 39999, 40000, 69999, 70000, 100000};
    static const int sends[] = {1, 2, 2, 3, 3, 4, 5};
    npf_call *c = call_new(n, 1);
    int64_t t0 = 1000000;
    size_t i;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "ask-test");
    c->st = CS_CONNECTING;
    pm_add(&c->pm, &c->pw.p);           /* the session on the WS relay */
    seen_clear();
    call_ws_failed(c, "test");          /* the WS relay never worked: a relay on our own server */
    call_ws_failed(c, "test");          /* again at once: given up already */
    CHECK(c->pw.p.health == PH_DEAD && count(seen, "asking for one on our own server") == 1, "asked %d times at once: %s",
          count(seen, "asking for one on our own server"), seen);
    call_need(c, PM_NONE, t0);
    seen_clear();
    call_need(c, PM_NEED_WS_ELSEWHERE, t0);
    for (i = 0; i < sizeof at / sizeof at[0]; i++) {
        call_need(c, PM_NEED_WS_ELSEWHERE, t0 + at[i]);
        CHECK(count(seen, "asking for one on our own server") == sends[i],
              "at %lld ms: sent %d times, not %d: %s", (long long)at[i], count(seen, "asking for one on our own server"),
              sends[i], seen);
    }
    CHECK(count(seen, "asking again") == 4, "the resends not logged once each: %s", seen);
    call_need(c, PM_NONE, t0 + 100001);         /* an allocation came, or the need is gone */
    call_need(c, PM_NONE, t0 + 200000);
    CHECK(count(seen, "asking for one on our own server") == 5, "sent with no need: %s", seen);
    npf_call_end(c, "test");
}

/* the UDP relay unreachable on an established session: it waits up to 15 s
 * for a punching round only when one is coming (scheduled, running, or
 * planned and let go); before the first punch_start none may come: tried
 * once more, then the WS relay at once (architecture.md 3.6; it waited
 * 15 s for a round that never came) */
static void relay_dead_punch(npf_node *n, int round)
{
    npf_call *c = call_new(n, 1);
    int nat_valid = n->nat_valid, nat_udp = n->nat_udp;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "punch-wait-%d", round);
    c->st = CS_UP;
    n->nat_valid = n->nat_udp = 1;
    pm_add(&c->pm, &c->pu.p);
    if (round) {                        /* a round scheduled a minute from now */
        c->punch_round = 1;
        call_punch_to(c, PN_SCHEDULED, npf_mono_ms() + 60000);
    }
    seen_clear();
    pm_health(&c->pm, &c->pu.p, PH_DEAD);
    pm_check(c);
    if (round) {
        CHECK(strstr(seen, "waiting for the punch before asking for the WS relay") && !strstr(seen, ": asking for"),
              "a round scheduled: not waited for: %s", seen);
        call_punch_to(c, PN_NONE, 0);   /* let go by the peer: it comes again, still waited for */
        seen_clear();
        pm_check(c);
        CHECK(!strstr(seen, ": asking for"), "a round let go: not waited for: %s", seen);
    } else {
        CHECK(strstr(seen, "trying the UDP relay once more") && !strstr(seen, "waiting for the punch"),
              "no round yet: waited for one: %s", seen);
        seen_clear();
        pm_health(&c->pm, &c->pu.p, PH_DEAD);   /* the second try fails too */
        pm_check(c);
        CHECK(strstr(seen, ": asking for the WS relay") != NULL, "no round yet: the WS relay not asked for: %s", seen);
    }
    n->nat_valid = nat_valid;
    n->nat_udp = nat_udp;
    npf_call_end(c, "test");
}

/* the WS relay lost after pairing: SUSPECT, connected again; 5 that fail: DEAD */
static void ws_gives_up(npf_node *n, int caller)
{
    npf_test_hooks old = n->th;
    npf_call *c = call_new(n, caller);
    int k;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "ws-test-%d", caller);
    c->st = CS_UP;
    n->th.block_relay = "wss://blocked.test/relay";    /* every connection fails at once */
    snprintf(c->pw.url, sizeof c->pw.url, "wss://blocked.test/relay");
    pm_add(&c->pm, &c->pw.p);
    c->pw.paired_once = 1;
    pm_rt(&c->pm, &c->pw.p, npf_mono_ms());
    seen_clear();
    call_ws_failed(c, "relay connection closed");   /* lost: in doubt, connected again in 2 s */
    CHECK(c->pw.p.health == PH_SUSPECT && c->pw.re_at && c->pw.fails == 0, "a WS relay lost: health %d, fails %d",
          c->pw.p.health, c->pw.fails);
    for (k = 1; k < 5; k++) {
        call_ws_failed(c, "cannot connect");
        CHECK(c->pw.p.health == PH_SUSPECT && c->pw.fails == k && c->pw.re_at, "reconnect %d failed: health %d",
              k, c->pw.p.health);
    }
    CHECK(!strstr(seen, "giving it up") && !strstr(seen, "relay_switch"), "given up before 5: %s", seen);
    call_ws_failed(c, "cannot connect");
    CHECK(c->pw.p.health == PH_DEAD && !c->pw.re_at && !c->pw.wsr, "5 failed: health %d", c->pw.p.health);
    CHECK(strstr(seen, "never paired: giving it up") != NULL, "not given up: %s", seen);
    CHECK(caller ? strstr(seen, "asking for one on our own server") != NULL
                 : strstr(seen, "asking for one") == NULL && strstr(seen, "waiting for the platform") != NULL,
          "%s: %s", caller ? "the caller did not ask elsewhere" : "the callee asked", seen);
    seen_clear();
    call_ws_failed(c, "cannot connect");            /* given up: nothing more */
    CHECK(!c->pw.re_at && !strstr(seen, "asking"), "after the verdict: %s", seen);
    n->th = old;
    npf_call_end(c, "test");
}

/* a call not ended has a deadline, its timer no later than the earliest one */
static int armed(const npf_call *c)
{
    int64_t d = call_due(c, npf_mono_ms());
    return d < INT64_MAX && c->t_due && c->due_at <= d;
}

/* the loop run until at, or until *flag (NULL none) is at least want */
static void run_until(npf_loop *l, int64_t at, const int *flag, int want)
{
    while (npf_mono_ms() <= at && !(flag && *flag >= want))
        npf_loop_once(l, 5);
}

static void deadline_invariant(npf_node *n, int caller)
{
    static const uint8_t rid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t key[32] = {9};
    struct sockaddr_storage ra;
    npf_call *c = call_new(n, caller);
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "due-test-%d", caller);
    CHECK(armed(c) && c->due_at == c->limit_at, "a new call: its time limit");
    c->st = CS_CONNECTING;
    npf_random(c->k12, sizeof c->k12);
    CHECK(call_start_transport(c) == 0 && armed(c), "the session made");
    call_set_state(c, CS_UP, "test");
    CHECK(!c->limit_at && armed(c), "established: no time limit, AnLiu's deadline");
    npf_addr_parse("127.0.0.1:9", &ra);
    path_udp_setup(c, rid, key, &ra, 1);
    CHECK(c->pu.r.at && armed(c), "a UDP relay binding");
    run_until(n->loop, npf_mono_ms() + 5000, &c->pu.r.tries, 2);
    CHECK(c->pu.r.tries == 2 && armed(c), "binding: %d binds again", c->pu.r.tries);
    path_udp_off(c);
    pm_add(&c->pm, &c->pw.p);
    c->pw.paired_once = 1;
    pm_rt(&c->pm, &c->pw.p, npf_mono_ms());
    call_ws_failed(c, "relay connection closed");
    CHECK(c->pw.re_at && armed(c), "a WS relay to connect again");
    npf_call_end(c, "test");
    CHECK(!c->t_due, "an ended call's timer");
}

static void deadline_moves(npf_node *n)
{
    npf_call *c = call_new(n, 1);
    int64_t t;
    CHECK(c != NULL, "call");
    if (!c)
        return;
    snprintf(c->call_id_s, sizeof c->call_id_s, "move-test");
    call_punch_to(c, PN_LINGER, npf_mono_ms() + 20);    /* earlier than the time limit */
    CHECK(c->due_at == c->punch_at, "a deadline earlier: the timer not moved");
    run_until(n->loop, c->punch_at, NULL, 0);
    CHECK(!c->punch_at && c->punch_st == PN_IDLE && c->due_at == c->limit_at,
          "the linger done: the timer at %lld, not the limit's", (long long)(c->due_at - c->limit_at));
    t = c->limit_at = npf_mono_ms() + 20;
    call_at(c, c->limit_at);
    c->st = CS_CALLING;
    call_accept(c);                             /* the limit later: 25 s from now */
    CHECK(c->due_at == t && c->limit_at > t + 20000, "a deadline later: the timer moved at once");
    run_until(n->loop, t, NULL, 0);
    CHECK(!call_over(c) && c->due_at == c->limit_at, "the tick before the limit: %s, the timer %lld ms early",
          call_over(c) ? "ended" : "not ended", (long long)(c->limit_at - c->due_at));
    npf_call_end(c, "test");
}

/* offline, the call_end reports wait; all slots taken, a new one takes the
 * oldest waiting one's (it took the first slot's, whatever its age) */
static void ends_full(npf_node *n)
{
    int i, oldest = 5;
    for (i = 0; i < NPF_ENDS_MAX; i++)
        npf_node_call_end(n, "c", "test", 0);
    for (i = 0; i < NPF_ENDS_MAX; i++)
        n->ends[i].at_ms = 1000 + (i == oldest ? 0 : i + 1);
    npf_node_call_end(n, "new", "test", 0);
    CHECK(strcmp(n->ends[oldest].call_id, "new") == 0 && strcmp(n->ends[0].call_id, "c") == 0,
          "call_end reports full: the oldest waiting one replaced");
    memset(n->ends, 0, sizeof n->ends);
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

    relay_asked_again(&node);
    relay_dead_punch(&node, 0);
    relay_dead_punch(&node, 1);
    ws_gives_up(&node, 1);
    ws_gives_up(&node, 0);
    deadline_invariant(&node, 1);
    deadline_invariant(&node, 0);
    deadline_moves(&node);
    ends_full(&node);

    npf_log_ctx_swap(old);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

/* The call's and its punching's state machines (architecture.md 3.1, 3.2),
 * row by row on an offline node: the platform's messages as JSON, the
 * deadlines on a clock the test moves (call_tick at a given time), no
 * socket of the test's own (a running S1 punch has no peer to send to). What
 * goes to the platform is read from the node's end reports and the log.
 * - the call: a caller's CALLING, the call reply, call_accepted (the time
 *   limit from then on), call_rejected and a signaling loss (no call_end); a
 *   callee's answer (not accepted yet: its punch_update dropped), its first
 *   punch_start (accepted, the limit from then on; the next one changes
 *   nothing), its call_established (accepted too, Q6: a callee established
 *   through the relay with no punch_start tells the platform of its rounds;
 *   10-27 (1)); a caller's own hello (established, the limit kept) and the
 *   peer's (the limit gone); the limit's end; the ends (call_end and the
 *   record's side) and the free on the next turn;
 * - punching: punch_start (SCHEDULED at its start), skip (IDLE: no direct
 *   path to wait for), the start without keys (WAIT_KEYS) and with them
 *   (RUNNING), the peer letting a round go before it started (NONE), a port
 *   for a round before it started (kept) and running (its punch's), a new
 *   punch_start while a round runs (the old punch ends: a port of the old
 *   round goes nowhere, one of the new round to the new punch; 10-27 (4)),
 *   success (LINGER 10 s, then IDLE; the direct path used only after an
 *   echo of its check from the punched address), failure (LINGER at once), the move to
 *   the WS relay (NONE: rounds again on UDP) and the call's end (IDLE), the
 *   hard-side sockets back, a
 *   caller's round while another hard-side punch runs (busy: NONE, the
 *   round comes again). After each row: a deadline in SCHEDULED and LINGER
 *   only, the call's timer no later, a punch in RUNNING and LINGER only;
 * - the platform's upgrade offer: its download page kept only as an https URL;
 * - remote_access off: incoming sessions end (this node's own stay), and an
 *   incoming call is refused before the callee is asked anything. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/noise.h"
#include "npf/platform.h"
#include "call_internal.h"
#include "node_internal.h"
#include "test.h"

static char states[64];             /* the public states the hook heard, as digits */

static void state_hook(npf_node *n, npf_call *c, int st, const char *why, void *arg)
{
    size_t l = strlen(states);
    (void)n, (void)c, (void)why, (void)arg;
    if (l + 1 < sizeof states) {
        states[l] = (char)('0' + st);
        states[l + 1] = 0;
    }
}

static void clear(void)
{
    log_clear();
    states[0] = 0;
}

static npf_json j;
static npf_jtok tok[64];
static char jbuf[1024];

/* the platform's message of this type to n: fmt is the rest of the object */
static void sig(npf_node *n, const char *type, const char *fmt, const char *id, long long a)
{
    char f[900];
    snprintf(f, sizeof f, fmt, id, a);
    snprintf(jbuf, sizeof jbuf, "{\"v\":1,\"type\":\"%s\",%s", type, f + 1);
    if (npf_json_parse(&j, jbuf, strlen(jbuf), tok, 64) == 0)
        node_msg(n, &j);
}

static npf_call *new_call(npf_node *n, int caller, int st)
{
    npf_call *c = call_new(n, caller);
    if (c) {
        npf_random(c->call_id, 16);
        npf_b64url_encode(c->call_id, 16, c->call_id_s);
        c->st = st;
    }
    return c;
}

/* the call_end report for c (NULL: none) */
static const npf_end_report *end_of(const npf_node *n, const npf_call *c)
{
    int i;
    for (i = 0; i < NPF_ENDS_MAX; i++)
        if (n->ends[i].state && strcmp(n->ends[i].call_id, c->call_id_s) == 0)
            return &n->ends[i];
    return NULL;
}

static int freed(const npf_node *n, const npf_call *c)
{
    const npf_call *x;
    for (x = n->calls; x; x = x->next)
        if (x == c)
            return 0;
    return 1;
}

static void call_rows(npf_node *n)
{
    npf_call *c, *d;
    int64_t t0;

    /* caller: CALLING, the reply, call_accepted */
    clear();
    c = new_call(n, 1, CS_CALLING);
    CHECK(c && npf_call_state(c) == NPF_CALL_CALLING && c->limit_at && !call_accepted(c), "a caller's call");
    if (!c)
        return;
    t0 = c->limit_at;
    c->call_req = 7;
    sig(n, "call", "{\"reply_to\":\"r7\",\"status\":\"ok\",\"data\":{\"x\":\"%s%lld\"}}", "", 0);
    CHECK(c->st == CS_CALLING && c->limit_at == t0, "the call's reply: CALLING, the limit kept");
    call_accept(c);
    CHECK(c->st == CS_CONNECTING && call_accepted(c) && c->limit_at >= npf_mono_ms() + 24000
          && strcmp(states, "2") == 0, "call_accepted: CONNECTING, the limit from now (%s)", states);
    call_set_state(c, CS_HALF, NULL);       /* our hello */
    CHECK(npf_call_state(c) == NPF_CALL_ESTABLISHED && c->limit_at && c->up_ms, "our hello: established, the limit kept");
    call_set_state(c, CS_CONNECTING, NULL);
    CHECK(c->st == CS_HALF, "a state went back");
    call_set_state(c, CS_UP, NULL);         /* the peer's hello */
    CHECK(c->st == CS_UP && !c->limit_at && strcmp(states, "23") == 0 && !strstr(logged, "call_established"),
          "the peer's hello: UP, no limit, nothing to the platform (%s)", states);
    node_sig_lost(n);
    CHECK(!call_over(c), "an established call ended with the signaling");
    clear();
    npf_call_end(c, "bye now");
    CHECK(call_over(c) && npf_call_state(c) == NPF_CALL_CLOSED && strcmp(states, "4") == 0 && end_of(n, c)
          && !end_of(n, c)->peer && strcmp(end_of(n, c)->reason, "byenow") == 0 && c->t_free && !npf_timer_pending(&c->t_due),
          "a local end: CLOSED, call_end (ours), the free next");
    npf_loop_once(n->loop, 0);
    CHECK(freed(n, c), "not freed on the next turn");

    /* call_rejected, a signaling loss before the call is up: no call_end */
    c = new_call(n, 1, CS_CALLING);
    d = new_call(n, 1, CS_CONNECTING);
    if (!c || !d)
        return;
    clear();
    sig(n, "call_rejected", "{\"data\":{\"call_id\":\"%s\",\"error\":\"busy%lld\"}}", c->call_id_s, 0);
    CHECK(call_over(c) && !end_of(n, c) && strcmp(states, "4") == 0, "call_rejected: closed quietly");
    node_sig_lost(n);
    CHECK(call_over(d) && !end_of(n, d), "the signaling lost while connecting: closed quietly");

    /* the time limit's end; the peer's close (the record names the peer) */
    c = new_call(n, 1, CS_CONNECTING);
    d = new_call(n, 0, CS_UP);
    if (!c || !d)
        return;
    call_tick(c, c->limit_at - 1);
    CHECK(!call_over(c), "ended before its limit");
    call_tick(c, c->limit_at);
    CHECK(call_over(c) && end_of(n, c) && strcmp(end_of(n, c)->reason, "timeout") == 0, "the limit: no timeout");
    call_close(d, "closed", CALL_END_PEER);
    CHECK(call_over(d) && end_of(n, d) && end_of(n, d)->peer, "the peer's close: the record not the peer's");
    npf_loop_once(n->loop, 0);

    /* callee: answered, not accepted; its first punch_start; established */
    clear();
    c = new_call(n, 0, CS_ANSWERED);
    if (!c)
        return;
    t0 = c->limit_at;
    call_punch_report(c, "network");
    CHECK(npf_call_state(c) == NPF_CALL_CONNECTING && !call_accepted(c) && !strstr(logged, "punch_update"),
          "a callee not accepted told the platform: %s", logged);
    sig(n, "punch_start", "{\"data\":{\"call_id\":\"%s\",\"round\":%lld}}", c->call_id_s, 1);
    CHECK(c->st == CS_CONNECTING && call_accepted(c) && c->limit_at >= t0 && !states[0],
          "the first punch_start: accepted, the limit from now (%s)", states);
    t0 = c->limit_at;
    sig(n, "punch_start", "{\"data\":{\"call_id\":\"%s\",\"round\":%lld}}", c->call_id_s, 1);
    CHECK(c->limit_at == t0, "a second punch_start moved the limit");
    call_set_state(c, CS_UP, NULL);
    CHECK(!c->limit_at && strstr(logged, "call_established") && strcmp(states, "3") == 0, "UP: call_established not sent");
    npf_call_end(c, "test");

    /* Q6 (10-27 (1)): established through the relay, no punch_start yet */
    clear();
    c = new_call(n, 0, CS_ANSWERED);
    if (!c)
        return;
    call_set_state(c, CS_UP, NULL);
    CHECK(call_accepted(c) && strstr(logged, "call_established"), "call_established: not accepted");
    call_punch_report(c, "path_lost");
    CHECK(strstr(logged, "punch_update (path_lost)") != NULL, "the callee's punch_update dropped: %s", logged);
    call_accept(c);
    CHECK(!c->limit_at, "an accept after UP armed the limit again");
    npf_call_end(c, "test");
    npf_loop_once(n->loop, 0);
}

/* ---- punching ---- */

static char pid[16], pkey[48];

/* a call's punching invariants (architecture.md 4): a deadline in
 * SCHEDULED and LINGER only, the call's timer no later; a punch in RUNNING
 * and LINGER only (RUNNING: always) */
static int pn_ok(const npf_call *c)
{
    int st = c->punch_st, dl = st == PN_SCHEDULED || st == PN_LINGER;
    return dl == (c->punch_at != 0) && (!c->punch_at || (npf_timer_pending(&c->t_due) && c->due_at <= c->punch_at))
           && (st == PN_RUNNING || st == PN_LINGER || !c->punch) && (st != PN_RUNNING || c->punch);
}

static void punch_start(npf_call *c, int round, const char *extra)
{
    char f[512];
    snprintf(f, sizeof f,
             "{\"data\":{\"call_id\":\"%%s\",\"round\":%%lld,\"punch_id\":\"%s\",\"punch_key\":\"%s\",\"peer\":{}%s}}",
             pid, pkey, extra);
    sig(c->n, "punch_start", f, c->call_id_s, round);
}

static void punch_info(npf_call *c, int round, const char *what)
{
    char f[256];
    snprintf(f, sizeof f, "{\"data\":{\"call_id\":\"%%s\",\"round\":%%lld,%s}}", what);
    sig(c->n, "punch_info", f, c->call_id_s, round);
}

static void keys(npf_call *c)
{
    c->keys_ready = 1;
    npf_random(c->nominate_key, 32);
}

/* the peer's PATH_ECHO of nonce, from addr, on the main socket */
static void echo(npf_node *n, npf_call *c, uint64_t nonce, const char *addr)
{
    uint8_t b[PATH_PKT_LEN];
    struct sockaddr_storage a;
    b[NPF_SIV_TAG_SIZE] = 11;               /* PKT_PATH_ECHO */
    b[NPF_SIV_TAG_SIZE + 1] = 0;
    npf_le64(b + NPF_SIV_TAG_SIZE + 2, nonce);
    npf_siv_seal(&c->pd.keys, c->caller ? 1 : 0, b, 10);
    npf_addr_parse(addr, &a);
    node_udp_input(n, n->udp_fd, b, sizeof b, &a);
}

static void punch_rows(npf_node *n)
{
    npf_punch_result res;
    npf_call *c = new_call(n, 1, CS_CONNECTING), *o;
    int64_t at;
    uint64_t nonce;
    if (!c)
        return;
    clear();
    CHECK(c->punch_st == PN_NONE && pn_ok(c), "a new call's punching");
    punch_start(c, 1, "");
    CHECK(c->punch_st == PN_SCHEDULED && c->punch_round == 1 && pn_ok(c), "punch_start: %d", c->punch_st);
    punch_info(c, 1, "\"port\":40001");
    CHECK(c->punch_port == 40001, "its port before the start not kept");
    call_tick(c, c->punch_at);              /* no keys */
    CHECK(c->punch_st == PN_WAIT_KEYS && pn_ok(c), "the start without keys: %d", c->punch_st);
    punch_info(c, 1, "\"stop\":true");
    CHECK(c->punch_st == PN_NONE && pn_ok(c) && strstr(logged, "let go by the peer"), "let go: %d", c->punch_st);

    punch_start(c, 2, "");
    CHECK(c->punch_st == PN_SCHEDULED && !c->punch_port && pn_ok(c), "round 2: %d", c->punch_st);
    call_tick(c, c->punch_at);
    keys(c);
    call_punch_go(c);                       /* the keys came (call_start_transport) */
    CHECK(c->punch_st == PN_RUNNING && c->punch && pn_ok(c), "with the keys: %d", c->punch_st);
    punch_info(c, 2, "\"port\":40002");
    CHECK(c->punch_st == PN_RUNNING && !c->punch_port, "a running round's port kept for later");

    /* 10-27 (4): a new round while one runs */
    punch_start(c, 3, "");
    CHECK(c->punch_st == PN_SCHEDULED && !c->punch && pn_ok(c), "round 3 while 2 ran: %d", c->punch_st);
    punch_info(c, 2, "\"port\":40003");
    CHECK(!c->punch_port, "round 2's port taken for round 3");
    punch_info(c, 3, "\"port\":40004");
    CHECK(c->punch_port == 40004, "round 3's port not kept");
    punch_info(c, 4, "\"port\":40005");
    CHECK(c->punch_port == 40004, "a later round's port taken");
    call_tick(c, c->punch_at);
    CHECK(c->punch_st == PN_RUNNING && c->punch && pn_ok(c), "round 3 started: %d", c->punch_st);

    /* failure: LINGER at once, then IDLE (no direct path to wait for) */
    punch_info(c, 3, "\"stop\":true");      /* the peer let it go while it ran: it fails */
    CHECK(c->punch_st == PN_LINGER && c->punch_at && pn_ok(c), "a failure: %d", c->punch_st);
    call_tick(c, c->punch_at);
    CHECK(c->punch_st == PN_IDLE && !c->punch && pn_ok(c), "after the failure: %d", c->punch_st);

    /* success: LINGER 10 s, the direct path; then IDLE */
    punch_start(c, 4, "");
    call_tick(c, c->punch_at);
    CHECK(c->punch_st == PN_RUNNING, "round 4: %d", c->punch_st);
    memset(&res, 0, sizeof res);
    res.ok = 1;
    npf_addr_parse("127.0.0.1:9", &res.peer);
    at = npf_mono_ms();
    call_punch_done(c->punch, &res, n->udp_fd, c);
    CHECK(c->punch_st == PN_LINGER && c->punch && call_has_p2p(c) && c->punch_at >= at + PUNCH_LINGER_MS && pn_ok(c),
          "a success: %d", c->punch_st);
    CHECK(c->pd.p.health == PH_NEW && c->pm.primary != &c->pd.p, "the punched path used before an echo");
    nonce = c->pd.nonce;
    echo(n, c, nonce, "127.0.0.2:9");
    echo(n, c, nonce + 1, "127.0.0.1:9");
    CHECK(c->pd.p.health == PH_NEW && c->pm.primary != &c->pd.p, "an echo from elsewhere or of another check taken");
    echo(n, c, nonce, "127.0.0.1:9");
    CHECK(c->pd.p.health == PH_UP && c->pm.primary == &c->pd.p && c->pd.nonce != nonce
          && strstr(logged, "direct path proven"), "the echo from the punched address: the path used");
    punch_start(c, 5, "");
    CHECK(c->punch_st == PN_LINGER && c->punch_round == 4, "a punch_start on a direct path taken");
    call_tick(c, c->punch_at - 1);
    CHECK(c->punch_st == PN_LINGER && c->punch, "the linger ended early");
    call_tick(c, c->punch_at);
    CHECK(c->punch_st == PN_IDLE && !c->punch && pn_ok(c), "the linger over: %d", c->punch_st);
    call_p2p_drop(c);

    /* skip: IDLE; then the move to the WS relay from SCHEDULED */
    punch_start(c, 5, ",\"skip\":\"no_strategy\"");
    CHECK(c->punch_st == PN_IDLE && pn_ok(c), "no_strategy: %d", c->punch_st);
    punch_start(c, 6, "");
    call_punch_to(c, PN_NONE, 0);           /* the WS relay (call_ws_setup) */
    CHECK(c->punch_st == PN_NONE && !c->punch_at && pn_ok(c), "the WS relay while scheduled: %d", c->punch_st);

    /* busy: a caller's hard-side round while another hard-side punch runs */
    o = new_call(n, 0, CS_CONNECTING);
    if (!o)
        return;
    keys(o);
    punch_start(o, 1, "");
    call_tick(o, o->punch_at);
    o->punch_socks = 4;                     /* as an S3 hard side's */
    CHECK(o->punch_st == PN_RUNNING && call_hard_punches(n, c) == 1, "another hard-side punch");
    punch_start(c, 7, ",\"strategy\":\"S3\",\"side\":\"hard\",\"n_sockets\":8");
    call_tick(c, c->punch_at);
    CHECK(c->punch_st == PN_NONE && !c->punch && pn_ok(c) && strstr(logged, "punch round 7"), "busy: %d", c->punch_st);

    /* the move to the WS relay and the call's end while running: IDLE, the sockets back */
    n->hard_punch_end = 0;
    call_punch_to(o, PN_NONE, 0);           /* the WS relay */
    CHECK(o->punch_st == PN_NONE && !o->punch && !o->punch_socks && n->hard_punch_end, "the WS relay while running");
    punch_start(o, 2, "");
    call_tick(o, o->punch_at);
    CHECK(o->punch_st == PN_RUNNING, "round 2: %d", o->punch_st);
    npf_call_end(o, "test");
    CHECK(o->punch_st == PN_IDLE && !o->punch, "the call's end: the punch runs on");
    npf_call_end(c, "test");
    npf_loop_once(n->loop, 0);
}

static void upgrade_rows(npf_node *n)
{
    clear();
    sig(n, "upgrade", "{\"data\":{\"latest\":\"%s\",\"url\":\"javascript:alert(1)\"}}", "9.9.9", 0);
    CHECK(strcmp(n->upgrade.latest, "9.9.9") == 0 && !n->upgrade.url[0] && strstr(logged, "not an https URL"),
          "an upgrade's download page not https: dropped (%s)", n->upgrade.url);
    sig(n, "upgrade", "{\"data\":{\"latest\":\"%s\",\"url\":\"https://example.com/dl\"}}", "9.9.9", 0);
    CHECK(strcmp(n->upgrade.url, "https://example.com/dl") == 0, "an https download page: kept (%s)", n->upgrade.url);
}

static int locked_asked;
static int stub_locked(npf_node *n, void *arg)
{
    (void)n, (void)arg;
    locked_asked++;
    return 1;
}

/* the platform's incoming pairing call: a caller's message 1 of XXpsk3
 * (its prologue: npf-pair-v1, the call id, the callee's number); the
 * callee is then asked whether pairing is locked */
static void incoming_pairing(npf_node *n)
{
    npf_noise_hs h;
    uint8_t r[32], pro[48], m1[96];
    char id[32], hs[160], cp[48];
    int ml;
    npf_random(r, 16);
    npf_b64url_encode(r, 16, id);
    memcpy(pro, "npf-pair-v1", 11);
    memcpy(pro + 11, r, 16);
    npf_le64(pro + 27, n->cfg.number);
    npf_random(r, 32);
    if (npf_noise_init(&h, NPF_NOISE_XXPSK3, 1, pro, 35, r, NULL, NULL) < 0
        || (ml = npf_noise_write(&h, NULL, 0, m1, sizeof m1)) < 0)
        return;
    npf_b64url_encode(m1, (size_t)ml, hs);
    npf_random(r, 32);
    npf_b64url_encode(r, 32, cp);
    snprintf(jbuf, sizeof jbuf, "{\"v\":1,\"type\":\"incoming\",\"id\":\"p9\",\"data\":{\"call_id\":\"%s\","
             "\"auth\":\"pake\",\"hs\":\"%s\",\"cpace\":\"%s\"}}", id, hs, cp);
    if (npf_json_parse(&j, jbuf, strlen(jbuf), tok, 64) == 0)
        node_msg(n, &j);
}

static void remote_rows(npf_node *n)
{
    static const npf_callee_ops ops = {.locked = stub_locked};
    npf_call *in, *out;
    clear();
    in = new_call(n, 0, CS_UP);
    out = new_call(n, 1, CS_UP);
    if (!in || !out)
        return;
    n->cfg.remote_off = 1;
    npf_node_end_incoming(n, "remote_access_off");
    CHECK(call_over(in) && end_of(n, in) && strcmp(end_of(n, in)->reason, "remote_access_off") == 0 && !call_over(out),
          "remote access off: the incoming session ends (remote_access_off), this node's own stays");
    npf_call_end(out, "bye");
    npf_loop_once(n->loop, 0);
    n->callee = &ops;
    locked_asked = 0;
    incoming_pairing(n);
    CHECK(locked_asked == 0 && !n->calls, "remote access off: an incoming pairing asked the callee (%d)", locked_asked);
    n->cfg.remote_off = 0;
    incoming_pairing(n);
    CHECK(locked_asked == 1 && !n->calls, "remote access on: the callee is asked (%d)", locked_asked);
    n->callee = NULL;
}

int test_call_state(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_hooks hooks;
    npf_log_ctx lc, *old;
    uint8_t b[32];

    memset(&hooks, 0, sizeof hooks);
    hooks.on_call_state = state_hook;
    CHECK(offline_node(&node, loop, &hooks, NULL) == 0, "set-up");
    if (fails)
        return fails;
    npf_random(b, 32);
    npf_b64url_encode(b, 8, pid);
    npf_b64url_encode(b, 32, pkey);
    old = log_capture(&lc);

    call_rows(&node);
    punch_rows(&node);
    upgrade_rows(&node);
    remote_rows(&node);

    npf_log_ctx_swap(old);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

/* Calls: a session's state, timer and end, the signaling messages
 * dispatched to it, the node's sessions as a whole (their datagrams, their
 * ends). The handshake in call_handshake.c, punching in call_punch.c; the
 * session's transport, and what the library asks of it, in
 * call_transport.c, its paths in path_*.c (path.h) (signaling.md
 * "呼叫与端到端连接", data-channel.md, security.md 9). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/why.h"

#include "call_internal.h"
#include "../node/home.h"

#define CALL_LIMIT_MS      25000  /* to be established, from the start and again from the accept */

int npf_call_auth(const npf_call *c) { return c->auth; }

/* ---- state (architecture.md 3.1) ---- */

static const int call_pub[] = {0, NPF_CALL_CALLING, NPF_CALL_CONNECTING, NPF_CALL_CONNECTING, NPF_CALL_ESTABLISHED,
                               NPF_CALL_ESTABLISHED, NPF_CALL_CLOSED};

int npf_call_state(const npf_call *c) { return call_pub[c->st]; }

void call_tell(const npf_call *c, const char *type)
{
    char data[64];
    snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
    npf_node_send(c->n, type, 0, data);
}

/* the call's transition, forward only; the hooks hear NPF_CALL_* when it
 * changes. UP (the peer's hello) ends the time limit, and a callee tells
 * the platform: the E2E handshake held, relay_switch allocates freely from
 * then on (Q6, security review M-2) */
void call_set_state(npf_call *c, int st, const char *why)
{
    int was = npf_call_state(c);
    if (st <= c->st)
        return;
    c->st = st;
    if (st == CS_UP)
        c->limit_at = 0;
    if (call_pub[st] != was && call_pub[st] == NPF_CALL_ESTABLISHED)
        c->up_ms = npf_mono_ms();
    if (call_pub[st] != was && c->n->hooks.on_call_state)
        c->n->hooks.on_call_state(c->n, c, call_pub[st], why, c->n->hook_arg);
    if (st == CS_UP && !c->caller && !c->direct && !call_over(c)) {
        npf_logd("call %s: call_established", c->call_id_s);
        call_tell(c, "call_established");
    }
}

/* ---- the call's one timer (architecture.md 4) ---- */

static void call_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->ticking = 1;
    call_tick(c, npf_mono_ms());
    c->ticking = 0;
    call_at(c, call_due(c, npf_mono_ms()));
}

void call_arm(npf_call *c, int64_t at)
{
    if (call_over(c) || c->ticking || at == INT64_MAX)
        return;
    c->due_at = at;
    npf_timer_set(c->n->loop, &c->t_due, at - npf_mono_ms());
}

int64_t call_due(const npf_call *c, int64_t now)
{
    const int64_t at[] = {c->limit_at, c->punch_at, c->direct_at, c->pm.check_at, c->pu.r.at, c->pw.re_at};
    int64_t d = tr_due(c, now);
    size_t i;
    for (i = 0; i < sizeof at / sizeof at[0]; i++)
        if (at[i] && at[i] < d)
            d = at[i];
    return d;
}

static int due(int64_t at, int64_t now)
{
    return at && at <= now;
}

/* the parts in order (architecture.md 4); none after the call ended */
void call_tick(npf_call *c, int64_t now)
{
    if (c->anl)
        tr_tick(c, now);
    if (!call_over(c) && due(c->pu.r.at, now))
        path_udp_tick(c);
    if (!call_over(c) && due(c->pw.re_at, now))
        path_ws_tick(c);
    if (!call_over(c) && (c->anl || due(c->pm.check_at, now)))
        pm_check(c);
    if (!call_over(c) && due(c->punch_at, now))
        call_punch_tick(c);
    if (!call_over(c) && due(c->direct_at, now))
        call_direct_tick(c);
    if (!call_over(c) && due(c->limit_at, now)) {
        c->limit_at = 0;
        npf_logw("call %s: timed out", c->call_id_s);
        if (c->caller)
            node_sig_probe(c->n);           /* the platform may have stopped hearing us */
        npf_call_end(c, "timeout");
    }
}

/* the platform's accept (a caller's call_accepted, a callee's first
 * punch_start): the time to be established counted from now (a late accept
 * still gets all of it); a callee UP before is accepted already (Q6) */
void call_accept(npf_call *c)
{
    if (c->st != CS_CALLING && c->st != CS_ANSWERED)
        return;
    call_set_state(c, CS_CONNECTING, NULL);
    c->limit_at = npf_mono_ms() + CALL_LIMIT_MS;
}

npf_call *call_new(npf_node *n, int caller)
{
    npf_call *c = calloc(1, sizeof *c);
    if (!c)
        return NULL;
    if (!(c->hs = calloc(1, sizeof *c->hs))) {
        free(c);
        return NULL;
    }
    c->n = n;
    c->caller = caller;
    npf_timer_init(&c->t_due, call_timer, c);
    npf_timer_init(&c->pw.t_flush, path_ws_flush_timer, c);
    c->secure = n->cfg.secure;
    if (caller)
        n->calls_out++;
    else
        n->calls_in++;
    call_paths_init(c);
    c->next = n->calls;
    n->calls = c;
    c->limit_at = npf_mono_ms() + CALL_LIMIT_MS;
    call_at(c, c->limit_at);
    return c;
}

void call_free(npf_call *c)
{
    npf_node *n = c->n;
    npf_call **pp;
    /* not ended yet when the node stops or a start fails: what its
     * resources' ends call back cannot end it again (a free_later on
     * freed memory) */
    c->st = CS_CLOSED;
    for (pp = &n->calls; *pp; pp = &(*pp)->next)
        if (*pp == c) {
            *pp = c->next;
            break;
        }
    if (n->relay_hit == c)
        n->relay_hit = NULL;
    npf_timer_cancel(n->loop, &c->t_due);
    npf_timer_stop(n->loop, &c->t_free);    /* freed now (the node stops): not again */
    call_ws_leave_conn(c);
    call_punch_to(c, PN_IDLE, 0);
    call_rev_close_all(c);
    call_relay_early_free(c);
    tr_free(c);
    free(c->targets);
    call_hs_free(c);
    npf_wipe_free(c->pcfg, sizeof *c->pcfg);    /* punch_key, nominate_key */
    c->pcfg = NULL;
    call_p2p_drop(c);
    npf_wipe_free(c, sizeof *c);
    if (!n->calls)
        npf_scratch_trim();             /* the last session's buffers (sys.h) */
}

void call_hs_free(npf_call *c)
{
    npf_wipe_free(c->hs, sizeof *c->hs);
    c->hs = NULL;
}

/* defer the free: npf_call_end may run inside callbacks of this call */
static void free_later(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_free = NULL;
    call_free(c);
}

void npf_call_end(npf_call *c, const char *why)
{
    call_close(c, why, CALL_END_LOCAL);
}

/* CLOSED first (what the ends and the hooks call back finds the call
 * ended), then the words to the platform and the peer (how); the requests
 * waiting get no reply, punching and the timer end, the free on the next turn */
void call_close(npf_call *c, const char *why, int how)
{
    char rc[24];
    const char *reason = how == CALL_END_QUIET ? why : npf_why_wire(why, rc);
    if (call_over(c))
        return;
    c->st = CS_CLOSED;
    /* the platform first: the side that ends is the one its record names
     * (the close below reaches the peer over the WS relay at once, and the
     * peer's own call_end might come first otherwise) */
    if (!c->direct && how != CALL_END_QUIET)
        npf_node_call_end(c->n, c->call_id_s, reason, how == CALL_END_PEER);
    if (how != CALL_END_QUIET)
        tr_close(c, reason);
    if (c->n->hooks.on_call_state)
        c->n->hooks.on_call_state(c->n, c, NPF_CALL_CLOSED, reason, c->n->hook_arg);
    call_ctl_fail_all(c);                   /* after CLOSED: the peers know the session is gone */
    call_punch_to(c, PN_IDLE, 0);
    npf_timer_cancel(c->n->loop, &c->t_due);
    if (!c->t_free)
        c->t_free = npf_timer_add(c->n->loop, 0, free_later, c);
}

void npf_call_info_get(const npf_call *c, npf_call_info *i)
{
    memset(i, 0, sizeof *i);
    snprintf(i->id, sizeof i->id, "%s", c->call_id_s);
    i->caller = c->caller;
    i->direct = c->direct;
    i->state = npf_call_state(c);
    i->number = c->caller ? c->number : c->caller_number;     /* the other side's */
    memcpy(i->peer_pub, c->peer_pub, 32);
    i->path = npf_call_path(c);
    i->path_code = pm_code(&c->pm);
    if (call_has_p2p(c)) {
        i->p2p_addr = c->pd.addr;
        i->has_p2p_addr = 1;
    }
    i->up_s = c->up_ms ? (npf_mono_ms() - c->up_ms) / 1000 : -1;
    i->app = c->caller ? "" : c->caller_app;
    i->hosted = !c->caller && (c->caller_hosted || c->hosted_grant);
    tr_info(c, i);
}

npf_call *npf_node_calls(npf_node *n) { return n->calls; }
npf_call *npf_call_next(const npf_call *c) { return c->next; }

/* the path the session sends on (path_mgr.c), named */
const char *npf_call_path(const npf_call *c) { return pm_name(&c->pm); }
const char *npf_call_path_label(const npf_call *c) { return pm_label(&c->pm); }

void npf_node_end_callers(npf_node *n, int (*drop)(const npf_caller *who, void *arg), void *arg)
{
    npf_call *x;
    npf_caller w;
    for (x = n->calls; x; x = x->next) {
        if (x->caller || x->direct || call_over(x) || !x->keys_ready)
            continue;
        w.pub = x->peer_pub;
        w.auth = x->auth;
        w.grant_account = x->grant_account;
        w.grant_issued = x->grant_issued;
        if (drop(&w, arg)) {
            npf_log("call %s: the caller is no longer admitted", x->call_id_s);
            npf_call_end(x, "revoked");
        }
    }
}

/* ---- the platform's messages (msgs.c) ---- */

/* the callee's profile and candidates, before the platform's next round */
void node_on_punch_request(npf_node *n, const m_env *e, const void *m)
{
    npf_out w = {0};
    (void)m;
    if (!e->id[0])
        return;
    npf_out_jobj(&w);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_out_jend(&w);
    if (!w.failed)
        npf_node_reply(n, e->type, e->id, "ok", NULL, w.p);
    npf_out_free(&w);
}

void node_on_revoke(npf_node *n, const m_env *e, const void *msg)
{
    const m_revoke *m = msg;
    uint64_t acct = strtoull(m->account_id, NULL, 10);
    npf_call *x;
    if (n->callee && n->callee->revoke)
        n->callee->revoke(n, acct, m->before, m->owner, n->callee_arg);
    /* sessions admitted by this account's grants end now */
    for (x = n->calls; x; x = x->next)
        if (!x->caller && !call_over(x) && x->auth == AUTH_GRANT && x->grant_account == acct) {
            npf_log("call %s: revoked", x->call_id_s);
            npf_call_end(x, "revoked");
        }
    if (e->id[0])
        npf_node_reply(n, e->type, e->id, "ok", NULL, NULL);
}

void node_on_bind_committed(npf_node *n, const m_env *e, const void *msg)
{
    const m_bind_committed *m = msg;
    (void)e;
    if (n->callee && n->callee->bind_committed)
        n->callee->bind_committed(n, strtoull(m->account_id, NULL, 10), m->operation_id, n->callee_arg);
}

/* the reply to our call request: the call is taken, and it brings our
 * relay, bound now while the callee is reached (call_accepted brings it
 * again); or the platform refused it */
void node_on_call(npf_node *n, const m_env *e, const void *msg)
{
    const m_call_reply *m = msg;
    npf_call *x;
    for (x = n->calls; x; x = x->next) {
        char id[24];
        snprintf(id, sizeof id, "r%d", x->call_req);
        if (!x->caller || call_over(x) || strcmp(id, e->reply_to) != 0)
            continue;
        if (strcmp(e->status, "ok") != 0) {
            npf_logw("call %s: rejected by the platform (%s)", x->call_id_s, e->error);
            call_close(x, e->error, CALL_END_QUIET);
        } else if (x->st == CS_CALLING && m->relay.mode[0]) {
            call_relay_setup(x, &m->relay);
        }
        return;
    }
}

/* what the platform's refusal or end of a call means to its caller */
static void call_why_hint(const char *why)
{
    if (strcmp(why, "no_path") == 0)
        npf_log("no direct path (UDP unusable here, or punching gave up) and only callers logged in to an "
                "account get a relay: log in to an account, or check that UDP is not blocked");
    else if (strcmp(why, "secure_plan") == 0)
        npf_log("connect_mode secure on one side: relays only, which takes a caller's account with a paid plan "
                "(set connect_mode p2p allows direct paths)");
    else if (strcmp(why, "quota") == 0)
        npf_log("this month's traffic of the account is used up: no relay, and no direct path either, "
                "until next month or a larger plan");
}

void call_on_rejected(npf_call *c, const void *msg)
{
    const m_call_rejected *m = msg;
    if (!c->caller)
        return;
    npf_logw("call %s: rejected (%s)", c->call_id_s, m->error);
    call_why_hint(m->error);
    call_close(c, m->error, CALL_END_QUIET);
}

void call_on_relay_switch(npf_call *c, const void *msg)
{
    const m_relay_switch *m = msg;
    if (m->relay.mode[0])
        call_relay_setup(c, &m->relay);
}

void call_on_ended(npf_call *c, const void *msg)
{
    const m_call_ended *m = msg;
    const char *r = m->reason[0] ? m->reason : "closed";
    npf_log("call %s: ended by the peer or the platform (%s)", c->call_id_s, r);
    if (c->caller)
        call_why_hint(r);   /* the platform ends a call no path can carry (quota, no_path) */
    call_close(c, r, CALL_END_QUIET);
}

void node_sig_lost(npf_node *n)
{
    npf_call *c, *next;
    /* calls still being set up cannot finish without signaling; established ones go on */
    for (c = n->calls; c; c = next) {
        next = c->next;
        if (!call_up(c))
            call_close(c, "signaling lost", CALL_END_QUIET);
    }
}

void node_calls_relogin(npf_node *n)
{
    npf_call *c;
    int64_t now = npf_mono_ms();
    for (c = n->calls; c; c = c->next) {
        if (call_over(c) || !call_up(c))
            continue;
        if (c->pm.need) {               /* an allocation asked for: again now, its 10 s from here */
            c->pm.asks = 0;
            c->pm.ask_at = now;
            call_need(c, c->pm.need, now);
        }
        if (c->st == CS_UP && !c->caller && !c->direct)
            call_tell(c, "call_established");      /* idempotent at the platform */
    }
}

/* a call (not over) that is up, or (up 0) still being set up */
static int calls_in(const npf_node *n, int up)
{
    const npf_call *c;
    for (c = n->calls; c; c = c->next)
        if (!call_over(c) && !call_up(c) == !up)
            return 1;
    return 0;
}

int node_calls_setting_up(const npf_node *n) { return calls_in(n, 0); }
int node_calls_up(const npf_node *n) { return calls_in(n, 1); }

int node_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    npf_call *c;
    uint32_t conv;
    int matched = 0;
    if (node_sig_udp_input(n, fd, buf, len, from))
        return 1;                   /* the signaling server's (by its address, signaling-udp.md 3.1) */
    if (n->probe && npf_natprobe_input(n->probe, fd, buf, len, from))
        return 1;                   /* a probe server's answer to the running NAT probe */
    /* AnLiu first, the bulk of the traffic: the datagram names its connection
     * (conv, masked but not encrypted, DESIGN 3.4); anl_input then
     * authenticates it. A node keeps many sessions at once (many-to-many), and
     * conv is only 32 bits derived from each session's keys: when two sessions
     * share a conv, the one whose keys authenticate the datagram takes it.
     * Anything else (relay, punching) reads as some random conv, which almost
     * never belongs to a call and then fails authentication. */
    if (len <= 65535 && anl_peek_conv((const char *)buf, (int)len, &conv) == ANL_OK) {    /* a datagram: int is enough */
        npf_call *next;
        for (c = n->conv_tab[CONV_SLOT(conv)]; c; c = next) {
            int on_p2p;
            next = c->conv_next;
            if (call_over(c) || c->conv != conv)
                continue;
            matched = 1;
            on_p2p = call_has_p2p(c) && npf_addr_eq(from, &c->pd.addr);
            if (on_p2p && call_p2p_cut(c))
                return 1;
            if (call_anl_feed(c, buf, len) == 0) {
                if (on_p2p && !call_over(c))
                    c->pd.p.last_rx = npf_mono_ms();
                return 1;
            }
        }
    }
    if (len == PATH_PKT_LEN)
        for (c = n->calls; c; c = c->next)
            if (!call_over(c) && call_has_p2p(c) && fd == c->pd.fd && npf_addr_eq(from, &c->pd.addr) && call_path_input(c, buf, len))
                return 1;
    /* a direct listener's answer (Noise message 2) to a connection being
     * made: after the sessions already up with that listener, whose every
     * datagram would else be tried as one (a Noise read is a DH: 16 idle
     * sessions' keepalives cost one each while a 17th connected) */
    for (c = n->calls; c; c = c->next)
        if (!call_over(c) && c->direct && c->caller && !c->keys_ready && fd == c->pd.fd
            && npf_addr_eq(from, &c->pd.addr) && call_direct_reply(c, buf, len, from))
            return 1;
    /* relayed data (data-channel.md 9.2): its hint names the allocation,
     * no session's keys are tried */
    if (node_relay_data_input(n, buf, len, from))
        return 1;
    /* the relays' control packets (RELAY_BIND_ACK; they carry no hint): the
     * sessions on the relay they come from, each tried until one's keys
     * open it; the last one first. A few a minute */
    if ((c = n->relay_hit) && !call_over(c) && call_relay_input(c, buf, len, from))
        return 1;
    for (c = n->calls; c; c = c->next)
        if (c != n->relay_hit && !call_over(c) && call_relay_input(c, buf, len, from)) {
            n->relay_hit = c;
            return 1;
        }
    /* the spare allocation's pings and BIND_ACKs (home.c): after
     * the calls' relayed data, the bulk of what comes from the relay */
    if (node_home_input(n, fd, buf, len, from))
        return 1;
    for (c = n->calls; c; c = c->next)
        if (c->punch && npf_punch_input(c->punch, fd, buf, len, from))
            return 1;
    /* a datagram whose conv matches some call is consumed: a forged one is
     * dropped silently */
    return matched;
}

/* shutting down: every session, accepted or started here, gets an orderly
 * end (close in the tunnel, call_end to the platform) so the other side does
 * not wait for AnLiu's idle timeout; run the loop briefly afterwards to send */
void npf_node_end_calls(npf_node *n, const char *reason)
{
    npf_call *c;
    node_home_close(n);             /* and the spare: home_close goes out with the ends */
    for (c = n->calls; c; c = c->next)
        if (!call_over(c))
            npf_call_end(c, reason);
}

void npf_node_calls_lost_fd(npf_node *n, int fd, const char *reason)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next) {
        int on_it = c->pd.fd == fd && !c->pd.owned;
        if (on_it)
            call_p2p_drop(c);
        /* platform sessions use the IPv4 socket for the relay too */
        if (!call_over(c) && (on_it || (!c->direct && fd == n->udp_fd)))
            npf_call_end(c, reason);
    }
}

void npf_node_check_paths(npf_node *n, const char *why)
{
    npf_call *c;
    char w[96];
    snprintf(w, sizeof w, "%s: checking the direct path", why);
    for (c = n->calls; c; c = c->next)
        if (!call_over(c) && call_has_p2p(c) && !c->direct && c->anl && c->pd.p.health != PH_SUSPECT)
            call_p2p_suspect_start(c, w);
}

/* the node's UDP changed (udp_back_ms; tests: NPF_TEST_WS_FILE): each
 * session decides again (pm_decide, data-channel.md 3) */
void npf_node_calls_decide(npf_node *n)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next)
        pm_check(c);
}

void node_calls_free(npf_node *n)
{
    while (n->calls)
        call_free(n->calls);
}

/* Calls: a session's state and end, the signaling messages dispatched to
 * it, the node's sessions as a whole (their datagrams, their ends, what the
 * library asks of them). The handshake in call_handshake.c, the transport
 * in call_transport.c, the paths in path_*.c (path.h), punching in
 * call_punch.c (signaling.md "呼叫与端到端连接", data-channel.md, security.md 9). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

#define CALL_LIMIT_MS      25000  /* to be established, from the start and again from the accept */

/* ---- helpers ---- */

int npf_call_auth(const npf_call *c) { return c->auth; }

/* ---- state (architecture.md 3.1) ---- */

static const int call_pub[] = {0, NPF_CALL_CALLING, NPF_CALL_CONNECTING, NPF_CALL_CONNECTING, NPF_CALL_ESTABLISHED,
                               NPF_CALL_ESTABLISHED, NPF_CALL_CLOSED};

int npf_call_state(const npf_call *c) { return call_pub[c->st]; }

/* the call's transition, forward only; the hooks hear NPF_CALL_* when it
 * changes. UP (the peer's hello) ends the time limit, and a callee tells
 * the platform: the E2E handshake held, relay_switch allocates freely from
 * then on (Q6, security review M-2) */
void call_set_state(npf_call *c, int st, const char *why)
{
    int was = npf_call_state(c);
    char data[64];
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
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        npf_node_send(c->n, "call_established", 0, data);
    }
}

/* ---- the call's one timer (architecture.md 4) ---- */

static void call_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_due = NULL;
    c->ticking = 1;
    call_tick(c, npf_mono_ms());
    c->ticking = 0;
    call_at(c, call_due(c, npf_mono_ms()));
}

void call_arm(npf_call *c, int64_t at)
{
    if (call_over(c) || c->ticking || at == INT64_MAX)
        return;
    npf_timer_stop(c->n->loop, &c->t_due);
    c->due_at = at;
    c->t_due = npf_timer_add(c->n->loop, at - npf_mono_ms(), call_timer, c);
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

/* the session's data transport goes: its tunnel, UDP forwarding and media
 * (before the AnLiu connection whose streams they use). Each is taken off
 * the call before it is freed: the tunnel's sublinks end with callbacks
 * (sublink_done, a virtual end's closed), which must not find it still
 * there. It sends nothing and fails no control request: its callers do */
static void call_data_free(npf_call *c)
{
    npf_tunnel *t = c->tun;
    npf_udpf *u = c->udp;
    npf_media *m = c->media;
    c->tun = NULL;
    c->udp = NULL;
    c->media = NULL;
    npf_udpf_free(u);
    npf_media_free(m);
    npf_tunnel_free(t);
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
    npf_timer_stop(n->loop, &c->t_due);
    npf_timer_stop(n->loop, &c->t_free);    /* freed now (the node stops): not again */
    call_ws_leave_conn(c);
    call_punch_to(c, PN_IDLE, 0);
    call_rev_close_all(c);
    call_relay_early_free(c);
    call_data_free(c);
    if (c->kshare)
        c->kshare->calls--;                 /* its counts went with the tunnel (or go when it does) */
    free(c->targets);
    call_hs_free(c);
    free(c->pcfg);
    call_anl_drop(c);
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

/* a reason as the peer and the platform get it (the server keeps the same
 * characters): a-z 0-9 _, at most an end report's 23; "closed" when none is
 * left. A peer's close carries its own, printed into JSON from here on */
static const char *reason_code(const char *r, char out[24])
{
    size_t k = 0;
    for (; r && *r && k < 23; r++)
        if ((*r >= 'a' && *r <= 'z') || (*r >= '0' && *r <= '9') || *r == '_')
            out[k++] = *r;
    out[k] = 0;
    return k ? out : "closed";
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
    const char *reason = how == CALL_END_QUIET ? why : reason_code(why, rc);
    if (call_over(c))
        return;
    c->st = CS_CLOSED;
    /* the platform first: the side that ends is the one its record names
     * (the close below reaches the peer over the WS relay at once, and the
     * peer's own call_end might come first otherwise) */
    if (!c->direct && how != CALL_END_QUIET)
        npf_node_call_end(c->n, c->call_id_s, reason, how == CALL_END_PEER);
    if (how != CALL_END_QUIET && c->tun && npf_tunnel_is_ready(c->tun)) {
        char m[96];
        int len = snprintf(m, sizeof m, "{\"v\":1,\"type\":\"close\",\"data\":{\"reason\":\"%s\"}}", reason);
        npf_tunnel_control(c->tun, m, (size_t)len);
        if (c->anl) {
            anl_update(c->anl, (uint32_t)npf_mono_ms());
            anl_flush(c->anl);
        }
        if (call_has_ws(c) && c->pw.wsr)
            npf_wsr_flush(c->pw.wsr);          /* now: the relay connection goes with the call */
    }
    if (c->n->hooks.on_call_state)
        c->n->hooks.on_call_state(c->n, c, NPF_CALL_CLOSED, reason, c->n->hook_arg);
    call_ctl_fail_all(c);                   /* after CLOSED: the peers know the session is gone */
    call_punch_to(c, PN_IDLE, 0);
    npf_timer_stop(c->n->loop, &c->t_due);
    if (!c->t_free)
        c->t_free = npf_timer_add(c->n->loop, 0, free_later, c);
}

void npf_call_info_get(const npf_call *c, npf_call_info *i)
{
    anl_stats st;
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
    i->tx_bytes = c->tx_bytes;
    i->rx_bytes = c->rx_bytes;
    i->srtt_ms = -1;
    if (c->anl && anl_get_stats(c->anl, &st) == 0) {
        i->srtt_ms = (int)st.srtt;
        i->retrans = st.retrans;
    }
    i->sublinks = c->tun ? npf_tunnel_count(c->tun) : 0;
    {
        npf_udpf_stats us;
        npf_udpf_get_stats(c->udp, &us);
        i->udp_flows = us.flows;
        i->udp_out = us.dgrams_out;
        i->udp_in = us.dgrams_in;
        i->udp_dropped = us.dropped;
        i->udp_split = us.split;
    }
}

npf_call *npf_node_calls(npf_node *n) { return n->calls; }
npf_call *npf_call_next(const npf_call *c) { return c->next; }

/* the path the session sends on (path_mgr.c), named */
const char *npf_call_path(const npf_call *c) { return pm_name(&c->pm); }
const char *npf_call_path_label(const npf_call *c) { return pm_label(&c->pm); }

int npf_call_open(npf_call *c, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                  uint32_t rate)
{
    if (call_over(c) || !c->tun || !npf_tunnel_is_ready(c->tun))
        return -1;
    return npf_tunnel_open_rated(c->tun, fd, passthrough, host, port, group, rate);
}

void npf_call_on_sublink_done(npf_call *c, npf_sublink_fn fn, void *arg)
{
    c->sub_done = fn;
    c->sub_arg = arg;
}

int npf_call_group_count(const npf_call *c, uint32_t group)
{
    return c->tun ? npf_tunnel_group_count(c->tun, group) : 0;
}

int npf_call_group_reset(npf_call *c, uint32_t group, const char *why)
{
    return c->tun ? npf_tunnel_group_reset(c->tun, group, why) : 0;
}

int npf_call_sub_bytes(npf_call *c, uint32_t sid, uint64_t *in, uint64_t *out)
{
    return c->tun ? npf_tunnel_sub_bytes(c->tun, sid, in, out) : -1;
}

int npf_call_sub_reset(npf_call *c, uint32_t sid, const char *why)
{
    return c->tun ? npf_tunnel_sub_reset(c->tun, sid, why) : -1;
}

void npf_call_usage_take(npf_call *c, uint64_t *tx, uint64_t *rx)
{
    uint64_t in = 0, out = 0;
    if (c->tun)
        npf_tunnel_local_bytes(c->tun, &in, &out);
    *tx = in > c->rep_tx ? in - c->rep_tx : 0;
    *rx = out > c->rep_rx ? out - c->rep_rx : 0;
    c->rep_tx = in > c->rep_tx ? in : c->rep_tx;
    c->rep_rx = out > c->rep_rx ? out : c->rep_rx;
}

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

void call_on_rejected(npf_call *c, const void *msg)
{
    const m_call_rejected *m = msg;
    if (!c->caller)
        return;
    npf_logw("call %s: rejected (%s)", c->call_id_s, m->error);
    if (strcmp(m->error, "no_path") == 0)
        npf_log("UDP is unusable here and only callers logged in to an account get a relay: "
                "log in to an account, or check that UDP is not blocked");
    else if (strcmp(m->error, "secure_plan") == 0)
        npf_log("connect_mode secure on one side: relays only, which takes a caller's account with a paid plan "
                "(set connect_mode p2p allows direct paths)");
    else if (strcmp(m->error, "quota") == 0)
        npf_log("this month's traffic of the account is used up: no relay, and no direct path either, "
                "until next month or a larger plan");
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
    npf_log("call %s: ended by the peer (%s)", c->call_id_s, r);
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

int node_calls_setting_up(const npf_node *n)
{
    const npf_call *c;
    for (c = n->calls; c; c = c->next)
        if (!call_up(c) && !call_over(c))
            return 1;
    return 0;
}

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

void npf_node_dump(npf_node *n)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next) {
        anl_stats st;
        fprintf(stderr, "%lld call %s caller=%d state=%d path=%s\n", (long long)npf_mono_ms(), c->call_id_s, c->caller,
                npf_call_state(c), npf_call_path(c));
        if (c->anl && anl_get_stats(c->anl, &st) == 0) {
            anl_stream_stats ss;
            memset(&ss, 0, sizeof ss);
            if (c->stream)
                anl_stream_get_stats(c->stream, &ss);
            fprintf(stderr, "  anl: waitsnd=%d state=%d srtt=%u rto=%u min_rtt=%u cwnd=%u inflight=%u pace=%u bw=%u cc=%d "
                    "retrans=%u tx=%llu rx=%llu authfail=%llu stale=%llu rcv_bytes=%u t_due=%p | stream state=%d "
                    "rmt_wnd=%u backlog=%u\n",
                    c->stream ? anl_stream_waitsnd(c->stream) : -1, anl_state(c->anl), st.srtt, st.rto, st.min_rtt, st.cwnd,
                    st.inflight, st.pace_rate, st.bw_estimate, st.cc_state, st.retrans, (unsigned long long)st.tx_datagrams,
                    (unsigned long long)st.rx_datagrams, (unsigned long long)st.rx_auth_fail,
                    (unsigned long long)st.rx_stale, st.rcv_bytes, (void *)c->t_due, ss.state, ss.rmt_wnd,
                    ss.backlog_bytes);
        }
        if (c->tun)
            npf_tunnel_dump(c->tun);
    }
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

/* ---- UDP forwards: the caller's side (peers.c) ---- */

int npf_call_udp_send(npf_call *c, int lfd, const struct sockaddr_storage *src, socklen_t srclen, const char *host,
                      uint16_t port, const uint8_t *buf, size_t len)
{
    npf_udpf *u;
    if (!call_up(c) || !c->caller || !(u = call_udp_of(c)))
        return -1;
    return npf_udpf_send(u, lfd, src, srclen, host, port, buf, len);
}

void npf_call_udp_forget(npf_call *c, int lfd)
{
    npf_udpf_forget_fd(c->udp, lfd);
}

int npf_call_ready(const npf_call *c)
{
    return c && call_up(c) && c->tun && npf_tunnel_is_ready(c->tun);
}

int npf_call_open_v(npf_call *c, const npf_vend_io *v, void *varg, const char *host, uint16_t port,
                    npf_tunnel **tun)
{
    if (!npf_call_ready(c) || !c->caller)
        return -1;
    *tun = c->tun;
    return npf_tunnel_open_v(c->tun, v, varg, host, port);
}

int npf_call_udp_send_v(npf_call *c, void *key, void (*deliver)(void *key, const uint8_t *buf, size_t len),
                        const char *host, uint16_t port, const uint8_t *buf, size_t len)
{
    npf_udpf *u;
    if (!call_up(c) || !c->caller || !(u = call_udp_of(c)))
        return -1;
    return npf_udpf_send_v(u, key, deliver, host, port, buf, len);
}

void npf_node_udp_forget_v(npf_node *n, const void *key)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next)
        npf_udpf_forget_v(c->udp, key);
}

/* ---- libnpf: application data and media streams ---- */

int npf_call_app_send(npf_call *c, const void *buf, size_t len)
{
    if (call_over(c) || !c->tun || len > NPF_CTRL_MAX)
        return -1;
    return npf_tunnel_unit_send(c->tun, NPF_CU_APP, buf, len);
}

uint32_t npf_call_media_open(npf_call *c, const npf_call_media_opt *o, int *err)
{
    npf_media *m;
    if (!call_up(c) || !(m = call_media_of(c))) {
        *err = NPF_CALL_ESTATE;
        return 0;
    }
    return npf_media_open_stream(m, o, err);
}

int npf_call_media_send(npf_call *c, uint32_t media, int flags, const void *buf, size_t len, int64_t t_submit)
{
    int r;
    if (call_over(c) || !c->media)
        return call_over(c) ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    r = npf_media_send_frame(c->media, media, flags, buf, len, t_submit);
    if (r == 0)
        c->tx_bytes += len;
    return r;
}

int npf_call_media_get_stats(npf_call *c, uint32_t media, npf_call_media_stats *out)
{
    if (call_over(c) || !c->media)
        return call_over(c) ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    return npf_media_stream_stats(c->media, media, out);
}

int npf_call_media_close(npf_call *c, uint32_t media)
{
    if (call_over(c) || !c->media)
        return call_over(c) ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    return npf_media_close_stream(c->media, media);
}

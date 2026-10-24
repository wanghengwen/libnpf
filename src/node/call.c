/* Calls: a session's state and end, the signaling messages dispatched to
 * it, the node's sessions as a whole (their datagrams, their ends, what the
 * library asks of them). The handshake in call_handshake.c, the transport
 * in call_transport.c, the direct path's check in call_path.c, punching in
 * call_punch.c, the relays in call_relay.c and call_ws.c (signaling.md
 * "呼叫与端到端连接", data-channel.md, security.md 9). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define CALL_TIMEOUT_MS    15000

/* ---- helpers ---- */

void call_b64_of(const uint8_t *b, size_t n, char *out)
{
    npf_b64url_encode(b, n, out);
}

npf_call *call_find(npf_node *n, const npf_json *j, int d)
{
    uint8_t id[16];
    npf_call *c;
    if (npf_json_get_b64(j, d, "call_id", id, sizeof id) != 16)
        return NULL;
    for (c = n->calls; c; c = c->next)
        if (memcmp(c->call_id, id, 16) == 0)
            return c;
    return NULL;
}

int call_udp_send(npf_call *c, int fd, const struct sockaddr_storage *to, const uint8_t *buf, size_t len)
{
    (void)c;
    return npf_udp_send(fd, buf, len, to);
}

/* tests: NPF_TEST_BLOCK_RELAY="addr,url,..." makes these relay endpoints unreachable */
int call_relay_blocked(const npf_node *n, const char *what)
{
    const char *v = n->test_block_relay;
    return v && *what && strstr(v, what) != NULL;
}

int call_relay_addr_blocked(const npf_call *c)
{
    char a[64];
    return c->n->test_block_relay
           && call_relay_blocked(c->n, npf_addr_str(&c->relay.addr[c->relay.cur], a, sizeof a));
}


int npf_call_auth(const npf_call *c) { return c->auth; }
uint64_t npf_call_grant_account(const npf_call *c) { return c->grant_account; }


/* the session moves to the WS relay: the UDP relay (binding, waiting) and
 * the direct path (its check, a punch about to start) have nothing left to
 * do, and their timers would ask for the WS relay again (the platform then
 * sends the allocation again: its sublinks reset) */
void call_relay_leave(npf_call *c)
{
    npf_loop *l = c->n->loop;
    timer_stop(l, &c->relay.t_bind);
    c->relay.bound = 0;
    c->relay_waits_ports = 0;
    timer_stop(l, &c->t_ws_wait);
    timer_stop(l, &c->t_pcheck);
    c->p2p_suspect = 0;
    c->standby_check = 0;
    timer_stop(l, &c->t_punch);
    c->punch_wait_keys = 0;
}


/* ---- state ---- */

void call_set_state(npf_call *c, int st, const char *why)
{
    if (c->state == st)
        return;
    c->state = st;
    if (st == NPF_CALL_ESTABLISHED)
        c->up_ms = npf_mono_ms();
    if (st == NPF_CALL_ESTABLISHED && c->t_timeout) {
        npf_timer_cancel(c->n->loop, c->t_timeout);
        c->t_timeout = NULL;
    }
    if (c->n->hooks.on_call_state)
        c->n->hooks.on_call_state(c->n, c, st, why, c->n->hook_arg);
}

static void timeout_cb(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_timeout = NULL;
    npf_logw("call %s: timed out", c->call_id_s);
    if (c->caller)
        node_sig_probe(c->n);           /* the platform may have stopped hearing us */
    npf_call_end(c, "timeout");
}

/* the call accepted on the platform (the caller: call_accepted; the callee:
 * its first punch_start): the time to be established counts from now, so an
 * accept that came late (the callee's answer slow on its way, up to the
 * platform's 20 s, signaling.md) still gets all of it */
void call_accept_seen(npf_call *c)
{
    if (c->accepted || !c->t_timeout)
        return;
    c->accepted = 1;
    npf_timer_cancel(c->n->loop, c->t_timeout);
    c->t_timeout = npf_timer_add(c->n->loop, CALL_TIMEOUT_MS + 10000, timeout_cb, c);
}

npf_call *call_new(npf_node *n, int caller)
{
    npf_call *c = calloc(1, sizeof *c);
    if (!c)
        return NULL;
    c->n = n;
    c->caller = caller;
    c->secure = n->cfg.secure;
    if (caller)
        n->calls_out++;
    else
        n->calls_in++;
    c->p2p_fd = -1;
    c->next = n->calls;
    n->calls = c;
    c->t_timeout = npf_timer_add(n->loop, CALL_TIMEOUT_MS + 10000, timeout_cb, c);
    return c;
}

/* an ended call does nothing more: what its timers would start (a punch, a
 * relay bind or switch, a path check, a retry, a probe of the signaling) is
 * no one's now. Not t_wsflush: it sends the close over the WS relay */
static void call_timers_stop(npf_call *c)
{
    npf_timer **t[] = {&c->t_anl, &c->t_timeout, &c->t_punch, &c->t_ws_wait, &c->t_pcheck, &c->t_repunch,
                       &c->t_standby, &c->t_direct, &c->relay.t_bind};
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (*t[i])
            npf_timer_cancel(c->n->loop, *t[i]);
        *t[i] = NULL;
    }
}

/* the session's data transport goes: its tunnel, UDP forwarding and media
 * (before the AnLiu connection whose streams they use). Each is taken off
 * the call before it is freed: the tunnel's sublinks end with callbacks
 * (sublink_done, a virtual end's closed), which must not find it still
 * there. It sends nothing and fails no control request: its callers do */
void call_data_free(npf_call *c)
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

/* the AnLiu connection goes (after call_data_free), with its data stream,
 * its conv's entry and the datagrams waiting for it. Not its timer
 * (t_anl): call_timers_stop */
void call_anl_drop(npf_call *c)
{
    anl_t *a = c->anl;
    if (a) {
        call_conv_unlink(c);
        c->anl = NULL;
        c->stream = NULL;
        anl_release(a);                 /* releases the stream handles too */
    }
    c->stream = NULL;
    call_dpend_free(c);
}

void call_free(npf_call *c)
{
    npf_node *n = c->n;
    npf_call **pp;
    /* not ended yet when the node stops or a start fails: what its
     * resources' ends call back cannot end it again (a free_later on
     * freed memory) */
    c->ended = 1;
    for (pp = &n->calls; *pp; pp = &(*pp)->next)
        if (*pp == c) {
            *pp = c->next;
            break;
        }
    if (n->relay_hit == c)
        n->relay_hit = NULL;
    call_timers_stop(c);
    if (c->t_linger) npf_timer_cancel(n->loop, c->t_linger);
    if (c->t_wsflush) npf_timer_cancel(n->loop, c->t_wsflush);
    if (c->t_free) npf_timer_cancel(n->loop, c->t_free);     /* freed now (the node stops): not again */
    c->t_linger = c->t_wsflush = c->t_free = NULL;
    if (c->wsr) npf_wsr_close(c->wsr);
    c->wsr = NULL;
    free(c->ws_out);
    free(c->ws_in);
    c->ws_out = c->ws_in = NULL;
    if (c->punch) {
        npf_punch_free(c->punch);
        c->punch = NULL;
        if (c->punch_socks > 0) {
            c->punch_socks = 0;
            call_punch_sockets_back(c->n);
        }
    }
    call_rev_close_all(c);
    call_data_free(c);
    if (c->kshare)
        c->kshare->calls--;                 /* its counts went with the tunnel (or go when it does) */
    free(c->targets);
    call_anl_drop(c);
    if (c->p2p_owned && c->p2p_fd >= 0) {
        npf_loop_del(n->loop, c->p2p_fd);
        npf_sock_close(c->p2p_fd);
    }
    npf_wipe(c, sizeof *c);
    free(c);
    if (!n->calls)
        npf_scratch_trim();             /* the last session's buffers (sys.h) */
}

/* defer the free: npf_call_end may run inside callbacks of this call */
static void free_later(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_free = NULL;
    call_free(c);
}

/* the end of a call, after its CLOSED: the requests waiting for replies get
 * none, its timers stop, it is freed on the next turn of the loop (once) */
static void call_ended(npf_call *c)
{
    call_ctl_fail_all(c);                   /* after CLOSED: the peers know the session is gone */
    call_timers_stop(c);
    if (!c->t_free)
        c->t_free = npf_timer_add(c->n->loop, 0, free_later, c);
}

/* a call that ends without a word to the peer or the platform (they told
 * us, or the platform refused it, or the signaling went before it was up) */
static void call_close_quiet(npf_call *c, const char *why)
{
    if (c->ended)
        return;
    c->ended = 1;
    call_set_state(c, NPF_CALL_CLOSED, why);
    call_ended(c);
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
    char rc[24];
    const char *reason;
    if (c->ended)
        return;
    c->ended = 1;
    reason = reason_code(why, rc);
    if (c->tun && npf_tunnel_is_ready(c->tun)) {
        char m[96];
        int len = snprintf(m, sizeof m, "{\"v\":1,\"type\":\"close\",\"data\":{\"reason\":\"%s\"}}", reason);
        npf_tunnel_control(c->tun, m, (size_t)len);
        if (c->anl) {
            anl_update(c->anl, (uint32_t)npf_mono_ms());
            anl_flush(c->anl);
        }
    }
    if (!c->direct)
        npf_node_call_end(c->n, c->call_id_s, reason);
    call_set_state(c, NPF_CALL_CLOSED, reason);
    call_ended(c);
}

int npf_call_state(const npf_call *c) { return c->state; }

void npf_call_info_get(const npf_call *c, npf_call_info *i)
{
    anl_stats st;
    memset(i, 0, sizeof *i);
    snprintf(i->id, sizeof i->id, "%s", c->call_id_s);
    i->caller = c->caller;
    i->direct = c->direct;
    i->state = c->state;
    i->number = c->caller ? c->number : c->caller_number;     /* the other side's */
    memcpy(i->peer_pub, c->peer_pub, 32);
    i->path = npf_call_path(c);
    if (c->p2p) {
        i->p2p_addr = c->p2p_addr;
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
uint64_t npf_call_peer(const npf_call *c) { return c->number; }

const char *npf_call_path(const npf_call *c)
{
    if (c->direct)
        return "direct";
    if (c->ws_mode)
        return "ws relay";
    if (c->p2p)
        return "p2p";
    if (c->relay.active)
        return c->relay.bound ? "relay" : "relay (binding)";
    return "none";
}

const char *npf_call_path_label(const npf_call *c)
{
    if (c->direct)
        return "Direct";
    if (c->p2p && !c->ws_mode)
        return "P2P";
    if (c->ws_mode || c->relay.active)
        return "Relayed";
    return "none";
}

int npf_call_open(npf_call *c, int fd, int passthrough, const char *host, uint16_t port)
{
    return npf_call_open_rated(c, fd, passthrough, host, port, 0, 0);
}

int npf_call_open_rated(npf_call *c, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                        uint32_t rate)
{
    if (c->ended || !c->tun || !npf_tunnel_is_ready(c->tun))
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
        if (x->caller || x->direct || x->ended || !x->keys_ready)
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

static void handle_punch_request(npf_node *n, const npf_json *j, int d)
{
    char req[24], data[2048];
    npf_jw w;
    (void)d;
    if (npf_json_get_str(j, 0, "id", req, sizeof req) < 0)
        return;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_reply(n, "punch_request", req, "ok", NULL, data);
}

/* ---- dispatch ---- */

void node_dispatch(npf_node *n, const char *type, const npf_json *j, int d)
{
    npf_call *c;
    if (strcmp(type, "incoming") == 0) {
        call_handle_incoming(n, j, d);
        return;
    }
    if (strcmp(type, "punch_request") == 0 && npf_json_get(j, 0, "id") >= 0) {
        handle_punch_request(n, j, d);
        return;
    }
    if (strcmp(type, "revoke") == 0) {
        char a[32], req[24];
        int64_t before = 0;
        int owner = 0;
        uint64_t acct;
        npf_call *x;
        if (npf_json_get_str(j, d, "account_id", a, sizeof a) <= 0
            || npf_json_get_int(j, d, "before", 0, INT64_MAX, &before) < 0)
            return;
        npf_json_bool(j, npf_json_get(j, d, "owner"), &owner);
        acct = strtoull(a, NULL, 10);
        if (n->callee && n->callee->revoke)
            n->callee->revoke(n, acct, before, owner, n->callee_arg);
        /* sessions admitted by this account's grants end now */
        for (x = n->calls; x; x = x->next)
            if (!x->caller && !x->ended && x->auth == AUTH_GRANT && x->grant_account == acct) {
                npf_log("call %s: revoked", x->call_id_s);
                npf_call_end(x, "revoked");
            }
        if (npf_json_get_str(j, 0, "id", req, sizeof req) > 0)
            npf_node_reply(n, "revoke", req, "ok", NULL, NULL);
        return;
    }
    if (strcmp(type, "bind_committed") == 0) {
        char a[32];
        uint8_t op[16];
        if (npf_json_get_str(j, d, "account_id", a, sizeof a) > 0 && npf_json_get_b64(j, d, "operation_id", op, 16) == 16
            && n->callee && n->callee->bind_committed)
            n->callee->bind_committed(n, strtoull(a, NULL, 10), op, n->callee_arg);
        return;
    }
    if (strcmp(type, "call") == 0) {      /* reply to our call request */
        char rt[24], err[32] = "";
        npf_call *x;
        if (npf_json_get_str(j, 0, "reply_to", rt, sizeof rt) < 0)
            return;
        if (npf_json_eq(j, npf_json_get(j, 0, "status"), "ok"))
            return;
        npf_json_get_str(j, 0, "error", err, sizeof err);
        for (x = n->calls; x; x = x->next) {
            char id[24];
            snprintf(id, sizeof id, "r%d", x->call_req);
            if (x->caller && strcmp(id, rt) == 0) {
                npf_logw("call %s: rejected by the platform (%s)", x->call_id_s, err);
                call_close_quiet(x, err);
                return;
            }
        }
        return;
    }
    if (npf_json_get(j, d, "call_id") < 0) {
        if (n->hooks.on_event && npf_json_get(j, 0, "reply_to") < 0)
            n->hooks.on_event(n, type, j, d, n->hook_arg);  /* mappings_changed, devices_changed ... */
        return;
    }
    c = call_find(n, j, d);
    if (!c || c->ended)
        return;
    if (strcmp(type, "call_accepted") == 0 && c->caller && c->state == NPF_CALL_CALLING) {
        call_accept_seen(c);
        call_caller_accepted(c, j, d);
    } else if (strcmp(type, "call_rejected") == 0 && c->caller) {
        char err[32] = "";
        npf_json_get_str(j, d, "error", err, sizeof err);
        npf_logw("call %s: rejected (%s)", c->call_id_s, err);
        if (strcmp(err, "no_path") == 0)
            npf_log("UDP is unusable here and only callers logged in to an account get a relay: "
                    "log in to an account, or check that UDP is not blocked");
        else if (strcmp(err, "secure_plan") == 0)
            npf_log("connect_mode secure on one side: relays only, which takes a caller's account with a paid plan "
                    "(set connect_mode p2p allows direct paths)");
        else if (strcmp(err, "quota") == 0)
            npf_log("this month's traffic of the account is used up: no relay, and no direct path either, "
                    "until next month or a larger plan");
        call_close_quiet(c, err);
    } else if (strcmp(type, "handshake") == 0) {
        call_handle_handshake(c, j, d);
    } else if (strcmp(type, "punch_start") == 0) {
        call_handle_punch_start(c, j, d);
    } else if (strcmp(type, "punch_info") == 0) {
        call_handle_punch_info(c, j, d);
    } else if (strcmp(type, "relay_switch") == 0) {
        if (npf_json_get(j, d, "relay") >= 0)
            call_relay_setup(c, j, d);
    } else if (strcmp(type, "call_ended") == 0) {
        char r[32] = "closed";
        npf_json_get_str(j, d, "reason", r, sizeof r);
        npf_log("call %s: ended by the peer (%s)", c->call_id_s, r);
        call_close_quiet(c, r);
    }
}

void node_sig_lost(npf_node *n)
{
    npf_call *c, *next;
    /* calls still being set up cannot finish without signaling; established ones go on */
    for (c = n->calls; c; c = next) {
        next = c->next;
        if (c->state != NPF_CALL_ESTABLISHED)
            call_close_quiet(c, "signaling lost");
    }
}


int node_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    npf_call *c;
    uint32_t conv;
    int matched = 0;
    if (n->probe && npf_natprobe_input(n->probe, fd, buf, len, from))
        return 1;                   /* a probe server's answer to the running NAT probe */
    for (c = n->calls; c; c = c->next)
        if (!c->ended && c->direct && c->caller && !c->keys_ready && fd == n->udp_fd
            && call_same_addr(from, &c->p2p_addr) && call_direct_reply(c, buf, len, from))
            return 1;
    /* AnLiu first, the bulk of the traffic: the datagram names its connection
     * (conv, masked but not encrypted, DESIGN 3.4); anl_input then
     * authenticates it. A node keeps many sessions at once (many-to-many), and
     * conv is only 32 bits derived from each session's keys: when two sessions
     * share a conv, the one whose keys authenticate the datagram takes it.
     * Anything else (relay, punching) reads as some random conv, which almost
     * never belongs to a call and then fails authentication. */
    if (anl_peek_conv((const char *)buf, (long)len, &conv) == ANL_OK) {
        npf_call *next;
        for (c = n->conv_tab[CONV_SLOT(conv)]; c; c = next) {
            int on_p2p;
            next = c->conv_next;
            if (c->ended || c->conv != conv)
                continue;
            matched = 1;
            on_p2p = c->p2p && call_same_addr(from, &c->p2p_addr);
            if (on_p2p && call_p2p_cut(c))
                return 1;
            if (call_anl_feed(c, buf, len) == 0) {
                if (on_p2p && !c->ended)
                    c->p2p_rx_ms = npf_mono_ms();
                return 1;
            }
        }
    }
    if (len == PATH_PKT_LEN)
        for (c = n->calls; c; c = c->next)
            if (!c->ended && c->p2p && fd == c->p2p_fd && call_same_addr(from, &c->p2p_addr) && call_path_input(c, buf, len))
                return 1;
    /* relayed: every session on one relay server comes from its address,
     * each tried until one's keys open it; the last one first */
    if ((c = n->relay_hit) && !c->ended && call_relay_input(c, buf, len, from))
        return 1;
    for (c = n->calls; c; c = c->next)
        if (c != n->relay_hit && !c->ended && call_relay_input(c, buf, len, from)) {
            n->relay_hit = c;
            return 1;
        }
    for (c = n->calls; c; c = c->next)
        if (!c->ended && c->punch && npf_punch_input(c->punch, fd, buf, len, from))
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
                c->state, npf_call_path(c));
        if (c->anl && anl_get_stats(c->anl, &st) == 0) {
            anl_stream_stats ss;
            memset(&ss, 0, sizeof ss);
            if (c->stream)
                anl_stream_get_stats(c->stream, &ss);
            fprintf(stderr, "  anl: waitsnd=%d state=%d srtt=%u rto=%u min_rtt=%u cwnd=%u inflight=%u pace=%u bw=%u cc=%d "
                    "retrans=%u tx=%llu rx=%llu authfail=%llu stale=%llu rcv_bytes=%u t_anl=%p | stream state=%d "
                    "rmt_wnd=%u backlog=%u\n",
                    c->stream ? anl_stream_waitsnd(c->stream) : -1, anl_state(c->anl), st.srtt, st.rto, st.min_rtt, st.cwnd,
                    st.inflight, st.pace_rate, st.bw_estimate, st.cc_state, st.retrans, (unsigned long long)st.tx_datagrams,
                    (unsigned long long)st.rx_datagrams, (unsigned long long)st.rx_auth_fail,
                    (unsigned long long)st.rx_stale, st.rcv_bytes, (void *)c->t_anl, ss.state, ss.rmt_wnd,
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
    for (c = n->calls; c; c = c->next)
        if (!c->ended)
            npf_call_end(c, reason);
}

void npf_node_calls_lost_fd(npf_node *n, int fd, const char *reason)
{
    npf_call *c;
    for (c = n->calls; c; c = c->next) {
        int on_it = c->p2p_fd == fd && !c->p2p_owned;
        if (on_it) {
            c->p2p = 0;
            c->p2p_fd = -1;
        }
        /* platform sessions use the IPv4 socket for the relay too */
        if (!c->ended && (on_it || (!c->direct && fd == n->udp_fd)))
            npf_call_end(c, reason);
    }
}

void npf_node_check_paths(npf_node *n, const char *why)
{
    npf_call *c;
    char w[96];
    snprintf(w, sizeof w, "%s: checking the direct path", why);
    for (c = n->calls; c; c = c->next)
        if (!c->ended && c->p2p && !c->direct && c->anl && !c->p2p_suspect)
            call_p2p_suspect_start(c, w);
}


void npf_node_ws_calls_udp_back(npf_node *n)
{
    npf_call *c;
    if (getenv("NPF_NO_UDP"))
        return;
    for (c = n->calls; c; c = c->next) {
        if (c->ended || !c->caller || !c->ws_mode || c->secure)
            continue;
        npf_log("call %s: UDP works again: leaving the WS relay (the session starts again)", c->call_id_s);
        npf_call_end(c, "udp_back");
    }
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
    if (c->ended || c->state != NPF_CALL_ESTABLISHED || !c->caller || !(u = call_udp_of(c)))
        return -1;
    return npf_udpf_send(u, lfd, src, srclen, host, port, buf, len);
}

void npf_call_udp_forget(npf_call *c, int lfd)
{
    npf_udpf_forget_fd(c->udp, lfd);
}

int npf_call_ready(const npf_call *c)
{
    return c && !c->ended && c->state == NPF_CALL_ESTABLISHED && c->tun && npf_tunnel_is_ready(c->tun);
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
    if (c->ended || c->state != NPF_CALL_ESTABLISHED || !c->caller || !(u = call_udp_of(c)))
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
    if (c->ended || !c->tun || len > NPF_CTRL_MAX)
        return -1;
    return npf_tunnel_unit_send(c->tun, NPF_CU_APP, buf, len);
}

uint32_t npf_call_media_open(npf_call *c, const npf_call_media_opt *o, int *err)
{
    npf_media *m;
    if (c->ended || c->state != NPF_CALL_ESTABLISHED || !(m = call_media_of(c))) {
        *err = NPF_CALL_ESTATE;
        return 0;
    }
    return npf_media_open_stream(m, o, err);
}

int npf_call_media_send(npf_call *c, uint32_t media, int flags, const void *buf, size_t len, int64_t t_submit)
{
    int r;
    if (c->ended || !c->media)
        return c->ended ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    r = npf_media_send_frame(c->media, media, flags, buf, len, t_submit);
    if (r == 0)
        c->tx_bytes += len;
    return r;
}

int npf_call_media_get_stats(npf_call *c, uint32_t media, npf_call_media_stats *out)
{
    if (c->ended || !c->media)
        return c->ended ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    return npf_media_stream_stats(c->media, media, out);
}

int npf_call_media_close(npf_call *c, uint32_t media)
{
    if (c->ended || !c->media)
        return c->ended ? NPF_CALL_ESTATE : NPF_CALL_ENOENT;
    return npf_media_close_stream(c->media, media);
}

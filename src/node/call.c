/* Calls: end-to-end handshake over signaling, AnLiu connection, UDP relay,
 * punching and the tunnel (signaling.md "呼叫与端到端连接", data-channel.md,
 * security.md 9). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define NPF_TAG_TUNNEL     1
#define ANL_MTU            1200
#define CALL_TIMEOUT_MS    15000
#define P2P_SILENT_MS      3000      /* nat-traversal.md 10.3; at least 2 x RTO */
#define P2P_DUAL_MS        10000     /* suspected path: send on both paths this long */
#define PKT_PATH_CHECK     10         /* direct path check (both directions work?) */
#define PKT_PATH_ECHO      11
#define LABEL_PATH         "NPF-PCHECK-1"
#define PATH_CHECK_MS      500
#define PATH_PKT_LEN       (NPF_SIV_TAG_SIZE + 10)
#define MAX_CALLS_DEFAULT  32        /* concurrent sessions a callee accepts (signaling.md "incoming": busy; R46) */



static void grant_update(npf_call *c, const npf_json *j);

/* callee: what a grant admits; a hosted grant: its targets only */
static int set_targets(npf_call *c, const npf_grant *g)
{
    uint8_t *t = NULL;
    c->grant_issued = g->issued;
    if (g->kind != NPF_GRANT_HOSTED)
        return 0;
    if (g->tlen && !(t = malloc(g->tlen)))
        return -1;
    if (g->tlen)
        memcpy(t, g->targets, g->tlen);
    free(c->targets);
    c->targets = t;
    c->tlen = g->tlen;
    c->hosted_grant = 1;
    return 0;
}

/* a data message waiting for the stream (callee, data-channel.md 4) */
typedef struct dmsg {
    struct dmsg *next;
    size_t       len;
    uint8_t      d[];
} dmsg;

void call_dpend_free(npf_call *c)
{
    while (c->dpend) {
        dmsg *m = c->dpend;
        c->dpend = m->next;
        free(m);
    }
    c->dpend_tail = &c->dpend;
    c->dpend_bytes = 0;
}
static void check_p2p(npf_call *c);
static void anl_schedule(npf_call *c);

/* ---- helpers ---- */


void call_b64_of(const uint8_t *b, size_t n, char *out)
{
    npf_b64url_encode(b, n, out);
}

static npf_call *find_call(npf_node *n, const npf_json *j, int d)
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

static void prologue(const npf_call *c, uint8_t *out, size_t *len)
{
    const char *pre = c->auth == AUTH_PAKE ? "npf-pair-v1" : "npf-conn-v1";
    size_t l = strlen(pre);
    memcpy(out, pre, l);
    memcpy(out + l, c->call_id, 16);
    npf_le64(out + l + 16, c->number);
    *len = l + 24;
}

static void sid_of(const npf_call *c, uint8_t sid[24])
{
    memcpy(sid, c->call_id, 16);
    npf_le64(sid + 16, c->number);
}

static void parse_cands(npf_call *c, const npf_json *j, int d)
{
    int arr = npf_json_get(j, d, "cand"), i;
    c->npeer_cand = 0;
    for (i = 0; arr >= 0 && i < j->tok[arr].size && c->npeer_cand < NPF_PUNCH_MAX_PEERS; i++) {
        char a[80];
        int it = npf_json_item(j, arr, i);
        if (npf_json_get_str(j, it, "a", a, sizeof a) > 0
            && npf_addr_parse(a, &c->peer_cand[c->npeer_cand]) == 0
            && c->peer_cand[c->npeer_cand].ss_family == AF_INET)   /* the main socket is IPv4 */
            c->npeer_cand++;
    }
}

/* ---- AnLiu ---- */

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

static void relay_send_data(npf_call *c, const uint8_t *dgram, size_t len)
{
    uint8_t buf[2048];
    uint8_t *p = buf + NPF_SIV_TAG_SIZE;
    if (len + 6 + NPF_SIV_TAG_SIZE > sizeof buf)
        return;
    if (call_relay_addr_blocked(c))
        return;
    p[0] = PKT_RELAY_DATA;
    p[1] = 0;
    npf_le32(p + 2, c->relay.seq++);
    memcpy(p + 6, dgram, len);
    npf_siv_seal(&c->relay.keys, 0, buf, len + 6);
    call_udp_send(c, c->n->udp_fd, &c->relay.addr[c->relay.cur], buf, len + 6 + NPF_SIV_TAG_SIZE);
}

/* tests: NPF_TEST_DROP_P2P=ms[:port] cuts the direct path that long after it
 * came up; with a port only the path to the peer on that port (many-to-many) */
static int p2p_cut(const npf_call *c)
{
    int64_t cut = c->n->test_cut_ms;
    int port = c->n->test_cut_port;
    if (cut < 0 || !c->p2p || npf_mono_ms() - c->p2p_since <= cut)
        return 0;
    return !port || ntohs(c->p2p_addr.ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)&c->p2p_addr)->sin6_port
                                                             : ((const struct sockaddr_in *)&c->p2p_addr)->sin_port) == port;
}

static int anl_out(char *buf, int len, anl_t *w, void *user)
{
    npf_call *c = user;
    (void)w;
    if (c->p2p && !p2p_cut(c))
        call_udp_send(c, c->p2p_fd, &c->p2p_addr, (const uint8_t *)buf, (size_t)len);
    /* the relay carries the data when there is no direct path, and as a second
     * copy while the direct path is suspected (AnLiu drops the duplicates) */
    if ((!c->p2p || c->p2p_suspect) && c->relay.active)
        relay_send_data(c, (const uint8_t *)buf, (size_t)len);
    return 0;
}

static int anl_accept(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    npf_call *c = user;
    (void)w;
    /* the caller's UDP stream (udpfwd.h) */
    if (anl_stream_tag(s) == NPF_TAG_UDP) {
        npf_udpf *u = c->caller ? NULL : call_udp_of(c);
        return u ? npf_udpf_accept(u, s, opt) : -1;
    }
    /* a media stream of the peer (libnpf, media.h) */
    if ((anl_stream_tag(s) & ~NPF_MEDIA_TAG_RDK) >= NPF_TAG_MEDIA) {
        npf_media *m = call_media_of(c);
        return m ? npf_media_accept(m, s, opt) : -1;
    }
    /* the callee takes the caller's data stream (data-channel.md 4): one,
     * reliable, messages; both send on it */
    if (c->caller || c->stream || anl_stream_tag(s) != NPF_TAG_TUNNEL || opt->mode != ANL_RELIABLE || opt->stream)
        return -1;
    if (opt->rcv_wnd > NPF_ANL_DATA_WND) {  /* what it would make this end hold (media.h) */
        npf_logw("call %s: the peer's data stream refused: receive window %d > %d", c->call_id_s, opt->rcv_wnd,
                 NPF_ANL_DATA_WND);
        return -1;
    }
    c->stream = s;
    while (c->dpend) {                      /* what waited for it (sent from the next flush on) */
        dmsg *m = c->dpend;
        c->dpend = m->next;
        anl_stream_send(s, (const char *)m->d, (int)m->len);
        free(m);
    }
    c->dpend_tail = &c->dpend;
    c->dpend_bytes = 0;
    return 0;
}


/* WS relay: both channels in one byte stream of records,
 * unit = channel(1) | len(2) | content (data-channel.md 10.2) */
static int ws_mux(npf_call *c, int ch, const uint8_t *buf, size_t len)
{
    if (!c->ws_tx_ready || len > 65535)
        return -1;
    if (c->ws_out_len + 3 + len > c->ws_out_cap) {
        size_t cap = c->ws_out_cap ? c->ws_out_cap : 65536;
        uint8_t *q;
        while (cap < c->ws_out_len + 3 + len)
            cap *= 2;
        q = realloc(c->ws_out, cap);
        if (!q)
            return -1;
        c->ws_out = q;
        c->ws_out_cap = cap;
    }
    c->ws_out[c->ws_out_len] = (uint8_t)ch;
    npf_le16(c->ws_out + c->ws_out_len + 1, (uint16_t)len);
    memcpy(c->ws_out + c->ws_out_len + 3, buf, len);
    c->ws_out_len += 3 + len;
    c->ws_out_total += 3 + len;
    if (!c->t_wsflush)
        c->t_wsflush = npf_timer_add(c->n->loop, 0, call_ws_flush_timer, c);
    return 0;
}

static void anl_kick(npf_call *c)
{
    if (!c->flush_pending) {
        c->flush_pending = 1;
        timer_stop(c->n->loop, &c->t_anl);
        anl_schedule(c);
    }
}

/* control units: AnLiu's default stream 0 (strict priority over the data) */
static int tun_write_ctrl(void *arg, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    c->tx_bytes += len;
    if (c->ws_mode)
        return ws_mux(c, 0, buf, len);
    if (!c->anl || anl_stream_send(anl_default_stream(c->anl), (const char *)buf, (int)len) < 0)
        return -1;
    anl_kick(c);
    return 0;
}

/* data messages: the data stream. The callee may have something to send
 * before the caller's stream reached it (its STREAM_OPEN is retried when
 * lost): that waits here, the tunnel sees it as backlog */
static int tun_write_data(void *arg, const uint8_t *msg, size_t len)
{
    npf_call *c = arg;
    c->tx_bytes += len;
    if (c->ws_mode)
        return ws_mux(c, 1, msg, len);
    if (!c->stream && !c->caller && c->anl) {
        dmsg *m = malloc(sizeof *m + len);
        if (!m)
            return -1;
        m->next = NULL;
        m->len = len;
        memcpy(m->d, msg, len);
        if (!c->dpend_tail)
            c->dpend_tail = &c->dpend;
        *c->dpend_tail = m;
        c->dpend_tail = &m->next;
        c->dpend_bytes += len;
        return 0;
    }
    if (!c->stream || anl_stream_send(c->stream, (const char *)msg, (int)len) < 0)
        return -1;
    anl_kick(c);
    return 0;
}

/* bytes on their way over the WS relay: not sealed yet, and in its queue */
static size_t ws_queued(const npf_call *c)
{
    return c->ws_out_len + (c->wsr ? npf_wsr_pending(c->wsr) : 0);
}

static size_t tun_backlog(void *arg)
{
    npf_call *c = arg;
    if (c->ws_mode) {
        size_t b = ws_queued(c);
        /* media streams open: the forwards keep 1/8 of the usual backlog and
         * wait while frames do (data-channel.md 14) */
        if (npf_media_count(c->media))
            b = (b + npf_media_ws_queued(c->media)) * 8;
        return b;
    }
    return (c->stream ? (size_t)anl_stream_waitsnd(c->stream) * ANL_MTU : 0) + c->dpend_bytes;
}

static void tun_ready(void *arg)
{
    npf_call *c = arg;
    if (c->caller && c->auth == AUTH_PAKE && c->n->hooks.on_paired)
        c->n->hooks.on_paired(c->n, c->number, c->peer_pub, c->n->hook_arg);
    call_set_state(c, NPF_CALL_ESTABLISHED, NULL);
}


static void tun_control(void *arg, const npf_json *j)
{
    npf_call *c = arg;
    char type[32], rt[24];
    int i;
    if (npf_json_get_str(j, 0, "type", type, sizeof type) <= 0)
        return;
    if (npf_json_get_str(j, 0, "reply_to", rt, sizeof rt) > 0) {
        int id = atoi(rt + 1);
        for (i = 0; i < NPF_CALL_CTL_MAX; i++) {
            if (c->ctl[i].fn && c->ctl[i].id == id) {
                npf_ctl_fn fn = c->ctl[i].fn;
                c->ctl[i].fn = NULL;
                fn(c, j, npf_json_eq(j, npf_json_get(j, 0, "status"), "ok"), c->ctl[i].arg);
                return;
            }
        }
        return;
    }
    if (strcmp(type, "close") == 0) {
        char r[32] = "closed";
        npf_json_get_str(j, npf_json_get(j, 0, "data"), "reason", r, sizeof r);
        npf_log("call %s: peer closed the session (%s)", c->call_id_s, r);
        npf_call_end(c, r);
        return;
    }
    if (!c->caller && (strcmp(type, "reverse_listen") == 0 || strcmp(type, "reverse_close") == 0)) {
        call_reverse_request(c, type, j);
        return;
    }
    if (c->caller && strcmp(type, "reverse_closed") == 0) {
        int64_t id;
        if (npf_json_get_int(j, npf_json_get(j, 0, "data"), "listen_id", 1, UINT32_MAX, &id) == 0) {
            if (c->tun)
                npf_tunnel_rev_del(c->tun, (uint32_t)id);
            npf_udpf_rev_del(c->udp, (uint32_t)id);
        }
        return;
    }
    if (!c->caller && strcmp(type, "grant_update") == 0) {
        grant_update(c, j);
        return;
    }
    if (c->caller && strcmp(type, "resources") == 0) {
        if (c->n->hooks.on_resources)
            c->n->hooks.on_resources(c->n, c, j, npf_json_get(j, 0, "data"), c->n->hook_arg);
        return;
    }
    /* requests for the program (bind_approve ...) on the callee */
    if (!c->caller && c->n->callee && c->n->callee->control)
        c->n->callee->control(c->n, c, j, c->n->callee_arg);
    else if (npf_json_get(j, 0, "id") >= 0)
        npf_call_ctl_reply(c, type, j, "error", "unsupported_type", NULL);
}

/* the requests still awaiting a reply get none (the session ended, or its
 * tunnel was replaced): each callback once, with j NULL and ok 0 */
void call_ctl_fail_all(npf_call *c)
{
    int i;
    for (i = 0; i < NPF_CALL_CTL_MAX; i++)
        if (c->ctl[i].fn) {
            npf_ctl_fn fn = c->ctl[i].fn;
            c->ctl[i].fn = NULL;
            fn(c, NULL, 0, c->ctl[i].arg);
        }
}

int npf_call_ctl_request(npf_call *c, const char *type, const char *data_json, npf_ctl_fn fn, void *arg)
{
    char *buf;
    int i, n, r;
    for (i = 0; i < NPF_CALL_CTL_MAX; i++)
        if (!c->ctl[i].fn)
            break;
    if (i == NPF_CALL_CTL_MAX || c->ended || !c->tun || !npf_tunnel_is_ready(c->tun) || !(buf = npf_scratch(NPF_CTRL_MAX)))
        return -1;
    c->ctl_seq++;
    n = snprintf(buf, NPF_CTRL_MAX, "{\"v\":1,\"type\":\"%s\",\"id\":\"c%d\",\"data\":%s}", type, c->ctl_seq,
                 data_json ? data_json : "{}");
    r = n < 0 || n >= NPF_CTRL_MAX || npf_tunnel_control(c->tun, buf, (size_t)n) < 0 ? -1 : 0;
    npf_scratch_done(buf);
    if (r < 0)
        return -1;
    c->ctl[i].id = c->ctl_seq;
    c->ctl[i].fn = fn;
    c->ctl[i].arg = arg;
    return 0;
}

int npf_call_ctl_event(npf_call *c, const char *type, const char *data_json)
{
    char *buf;
    int n, r;
    if (c->ended || !c->tun || !npf_tunnel_is_ready(c->tun) || !(buf = npf_scratch(NPF_CTRL_MAX)))
        return -1;
    n = snprintf(buf, NPF_CTRL_MAX, "{\"v\":1,\"type\":\"%s\",\"data\":%s}", type, data_json ? data_json : "{}");
    r = n < 0 || n >= NPF_CTRL_MAX || npf_tunnel_control(c->tun, buf, (size_t)n) < 0 ? -1 : 0;
    npf_scratch_done(buf);
    return r;
}

int npf_call_ctl_reply(npf_call *c, const char *type, const npf_json *req, const char *status, const char *error,
                       const char *data_json)
{
    char *buf, id[24];
    int n, r;
    if (npf_json_get_str(req, 0, "id", id, sizeof id) <= 0 || !c->tun || !(buf = npf_scratch(NPF_CTRL_MAX)))
        return -1;
    n = snprintf(buf, NPF_CTRL_MAX, "{\"v\":1,\"type\":\"%s\",\"reply_to\":\"%s\",\"status\":\"%s\"%s%s%s,\"data\":%s}",
                 type, id, status, error ? ",\"error\":\"" : "", error ? error : "", error ? "\"" : "",
                 data_json ? data_json : "{}");
    r = n < 0 || n >= NPF_CTRL_MAX ? -1 : npf_tunnel_control(c->tun, buf, (size_t)n);
    npf_scratch_done(buf);
    return r;
}

/* the target policy of this session's tunnel: a callee's, the published
 * resources; a caller's, none (its -R reaches what it registered, 7.1) */
struct npf_policy *call_policy(npf_call *c)
{
    if (c->caller)
        return NULL;
    return c->policy ? c->policy : c->n->callee ? c->n->callee->policy : NULL;
}


int npf_call_auth(const npf_call *c) { return c->auth; }
uint64_t npf_call_grant_account(const npf_call *c) { return c->grant_account; }

static void tun_broken(void *arg, const char *why)
{
    npf_call *c = arg;
    npf_log("call %s: tunnel %s", c->call_id_s, why);
    npf_call_end(c, "error");
}

static void anl_drain_with(npf_call *c, char *buf, size_t cap);

static void anl_drain(npf_call *c)
{
    char *buf;
    if (!c->anl)
        return;
    if (c->media && npf_media_poll(c->media) < 0)  /* the peer's new media streams: taken or not */
        return;
    if (!(buf = npf_scratch(65536)))
        return;
    anl_drain_with(c, buf, 65536);
    npf_scratch_done(buf);
}

static void anl_drain_with(npf_call *c, char *buf, size_t cap)
{
    anl_stream_t *rd[64];                   /* every stream at once (8: the rest waited for the next datagram) */
    int n, i;
    n = anl_readable(c->anl, rd, 64);
    for (i = 0; i < n && i < 64; i++) {
        int ctrl = rd[i] == anl_default_stream(c->anl);
        if (!ctrl && rd[i] != c->stream) {
            if (npf_udpf_is_stream(c->udp, rd[i])) {
                npf_udpf_drain(c->udp, rd[i]);
                if (c->ended)
                    return;
            } else if (npf_media_is_stream(c->media, rd[i])) {
                if (npf_media_drain(c->media, rd[i]) < 0 || c->ended)
                    return;
            } else if (anl_stream_peeksize(rd[i]) == ANL_ECLOSED) {
                anl_stream_close(rd[i]);
            }
            continue;
        }
        for (;;) {
            int r = anl_stream_recv(rd[i], buf, cap);   /* data stream: one message */
            if (r > 0) {
                c->rx_bytes += (uint64_t)r;
                if (!c->tun)
                    continue;
                if (ctrl ? npf_tunnel_input_ctrl(c->tun, (uint8_t *)buf, (size_t)r) < 0
                         : npf_tunnel_input_data(c->tun, (uint8_t *)buf, (size_t)r) < 0)
                    return;
                if (c->ended)               /* the peer's close: nothing more goes to the tunnel */
                    return;
                continue;
            }
            if (r == ANL_ECLOSED && rd[i] == c->stream) {
                npf_log("call %s: tunnel stream closed", c->call_id_s);
                npf_call_end(c, "closed");
                return;
            }
            break;
        }
    }
    if (c->tun)
        npf_tunnel_kick(c->tun);
}

static void auth_fail_check(npf_call *c);

static void anl_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_anl = NULL;
    if (!c->anl)
        return;
    anl_update(c->anl, (uint32_t)npf_mono_ms());
    if (c->flush_pending) {
        c->flush_pending = 0;
        anl_flush(c->anl);
    }
    if (anl_state(c->anl) < 0) {
        npf_logw("call %s: connection dead", c->call_id_s);
        npf_call_end(c, "transport_lost");
        return;
    }
    auth_fail_check(c);
    anl_drain(c);
    if (c->ended)
        return;
    check_p2p(c);
    anl_schedule(c);
}

static void anl_schedule(npf_call *c)
{
    uint32_t now, next;
    int64_t d;
    if (!c->anl || c->t_anl)
        return;
    now = (uint32_t)npf_mono_ms();
    next = c->flush_pending ? now : anl_check(c->anl, now);
    d = (int32_t)(next - now);
    if (d < 0)
        d = 0;
    c->anl_due = npf_mono_ms() + d;
    c->t_anl = npf_timer_add(c->n->loop, d, anl_timer, c);
}

static void anl_after_input(npf_call *c);

/* one datagram for this call's connection; 0 when it was authentic */
/* n->conv_tab: AnLiu datagrams find their call by conv without a scan */
#define CONV_SLOT(conv) (((conv) ^ ((conv) >> 8) ^ ((conv) >> 16) ^ ((conv) >> 24)) & 255)

static void conv_link(npf_call *c)
{
    npf_call **slot = &c->n->conv_tab[CONV_SLOT(c->conv)];
    c->conv_next = *slot;
    *slot = c;
}

void call_conv_unlink(npf_call *c)
{
    npf_call **pp;
    for (pp = &c->n->conv_tab[CONV_SLOT(c->conv)]; *pp; pp = &(*pp)->conv_next)
        if (*pp == c) {
            *pp = c->conv_next;
            c->conv_next = NULL;
            return;
        }
}

/* datagrams that named this session's conv and failed authentication: a
 * datagram of another session sharing the conv now and then (two sessions'
 * convs collide one time in 2^32 per pair), else forged or replayed ones.
 * The conv goes in the clear (masked): someone on the path can send them,
 * and each costs a decryption; they never touch the session (no reply, no
 * state: AnLiu SECURITY_AUDIT.md 3). Told at most once a minute. */
#define AUTH_FAIL_WARN     100
#define AUTH_FAIL_EVERY_MS 60000

static void auth_fail_check(npf_call *c)
{
    anl_stats st;
    int64_t now = npf_mono_ms();
    if (!c->anl || anl_get_stats(c->anl, &st) < 0 || st.rx_auth_fail < c->auth_fail_seen + AUTH_FAIL_WARN
        || (c->auth_fail_at && now - c->auth_fail_at < AUTH_FAIL_EVERY_MS))
        return;
    npf_logw("call %s: %llu datagram(s) with this session's conv failed authentication (forged or replayed: dropped)",
             c->call_id_s, (unsigned long long)(st.rx_auth_fail - c->auth_fail_seen));
    c->auth_fail_seen = st.rx_auth_fail;
    c->auth_fail_at = now;
}

int call_anl_feed(npf_call *c, const uint8_t *buf, size_t len)
{
    int r;
    if (!c->anl)
        return -1;
    anl_update(c->anl, (uint32_t)npf_mono_ms());
    r = anl_input(c->anl, (const char *)buf, (long)len);
    if (r < 0)
        return r;
    anl_after_input(c);
    return 0;
}

/* after a datagram: the timer moved only when AnLiu wants to be called
 * sooner than it fires (it was made again for every datagram) */
static void anl_after_input(npf_call *c)
{
    anl_drain(c);
    if (c->ended)
        return;
    if (c->t_anl) {
        int64_t now = npf_mono_ms();
        uint32_t n32 = (uint32_t)now, next = c->flush_pending ? n32 : anl_check(c->anl, n32);
        int32_t d = (int32_t)(next - n32);
        if (c->anl_due <= now + (d > 0 ? d : 0))
            return;                         /* it comes first and schedules the next one */
        npf_timer_cancel(c->n->loop, c->t_anl);
        c->t_anl = NULL;
    }
    anl_schedule(c);
}

/* the same callbacks serve the AnLiu and the WS relay transport: tun_write
 * and tun_backlog look at c->ws_mode */
/* ---- libnpf media streams (media.h) ---- */

static int m_unit(void *arg, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    return c->tun ? npf_tunnel_unit_send(c->tun, NPF_CU_MEDIA, buf, len) : -1;
}

static int m_ws_write(void *arg, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    c->tx_bytes += len;
    return ws_mux(c, 2, buf, len);
}

static void m_ws_backlog(void *arg, size_t *pending, uint64_t *total)
{
    npf_call *c = arg;
    *pending = ws_queued(c);
    *total = c->ws_out_total;
}

static void m_kick(void *arg)
{
    anl_kick(arg);
}

static int m_open(void *arg, uint32_t id, int tag)
{
    npf_call *c = arg;
    return c->n->hooks.on_media_open && c->n->hooks.on_media_open(c->n, c, id, tag, c->n->hook_arg);
}

static void m_frame(void *arg, uint32_t id, const uint8_t *buf, size_t len, uint32_t fno, int flags, uint32_t lost)
{
    npf_call *c = arg;
    c->rx_bytes += len;
    if (c->n->hooks.on_media_frame)
        c->n->hooks.on_media_frame(c->n, c, id, buf, len, fno, flags, lost, c->n->hook_arg);
}

static void m_closed(void *arg, uint32_t id)
{
    npf_call *c = arg;
    if (c->n->hooks.on_media_closed)
        c->n->hooks.on_media_closed(c->n, c, id, c->n->hook_arg);
}

static int m_ended(void *arg)
{
    return ((npf_call *)arg)->ended;
}

static const npf_media_io media_io = {m_unit, m_ws_write, m_ws_backlog, m_kick, m_open, m_frame, m_closed, m_ended};

/* the session's media streams, made on first use on its transport */
npf_media *call_media_of(npf_call *c)
{
    if (!c->media && !c->ended && (c->ws_mode || c->anl))
        c->media = npf_media_new(c->n->loop, c->ws_mode ? NULL : c->anl, !c->caller, &media_io, c);
    return c->media;
}

/* ---- UDP forwards (udpfwd.h) ---- */

static int u_unit(void *arg, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    return c->tun ? npf_tunnel_unit_send(c->tun, NPF_CU_UDP, buf, len) : -1;
}

static int u_ws_write(void *arg, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    c->tx_bytes += len;
    return ws_mux(c, 3, buf, len);
}

static size_t u_ws_backlog(void *arg)
{
    return ws_queued(arg);
}

/* a hosted client (a public mapping) has no UDP flows (data-channel.md 15) */
static int u_allowed(void *arg)
{
    return !((npf_call *)arg)->hosted_grant;
}

static const npf_udpf_io udp_io = {u_unit, u_ws_write, u_ws_backlog, m_kick, u_allowed};

npf_udpf *call_udp_of(npf_call *c)
{
    if (!c->udp && !c->ended && (c->ws_mode || c->anl))
        c->udp = npf_udpf_new(c->n->loop, c->ws_mode ? NULL : c->anl, c->caller, call_policy(c), &udp_io, c);
    return c->udp;
}

static void tun_unit(void *arg, int type, const uint8_t *buf, size_t len)
{
    npf_call *c = arg;
    if (type == NPF_CU_UDP) {
        npf_udpf *u = call_udp_of(c);
        if (u)
            npf_udpf_unit_input(u, buf, len);
        return;
    }
    if (type == NPF_CU_APP && c->n->hooks.on_app_data) {
        c->n->hooks.on_app_data(c->n, c, buf, len, c->n->hook_arg);
    } else if (type == NPF_CU_MEDIA) {
        npf_media *m = call_media_of(c);
        if (m)
            npf_media_unit_input(m, buf, len);
    }
}

/* grant_update{grant}: a hosted client's new target list (signaling.md
 * "隧道内控制消息"): the same caller key and account, issued later */
static void grant_update(npf_call *c, const npf_json *j)
{
    npf_node *n = c->n;
    uint8_t g[512];
    npf_grant gr;
    uint64_t acct = 0;
    int gl = npf_json_get_b64(j, npf_json_get(j, 0, "data"), "grant", g, sizeof g);
    if (c->auth != AUTH_GRANT || !c->hosted_grant || gl <= 0 || !n->callee || !n->callee->grant_check
        || n->callee->grant_check(n, g, (size_t)gl, c->peer_pub, &acct, &gr, n->callee_arg) < 0
        || gr.kind != NPF_GRANT_HOSTED || acct != c->grant_account || gr.issued < c->grant_issued) {
        npf_call_ctl_reply(c, "grant_update", j, "error", "forbidden", NULL);
        return;
    }
    if (set_targets(c, &gr) < 0) {
        npf_call_ctl_reply(c, "grant_update", j, "error", "internal_error", NULL);
        return;
    }
    npf_log("call %s: platform public mapping: target list updated", c->call_id_s);
    npf_call_ctl_reply(c, "grant_update", j, "ok", NULL, NULL);
}

/* a hosted client opens the targets of its grant only (security.md 8.4) */
static int tun_target_ok(void *arg, const char *host, uint16_t port)
{
    npf_call *c = arg;
    npf_grant g;
    if (!c->hosted_grant)
        return 1;
    memset(&g, 0, sizeof g);
    g.targets = c->targets;
    g.tlen = c->tlen;
    if (npf_grant_target_allowed(&g, host, port))
        return 1;
    npf_logw("call %s: platform public mapping: %s:%u is not one of its targets, refused", c->call_id_s, host, port);
    return 0;
}

static void tun_sublink_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    npf_call *c = arg;
    if (c->sub_done)
        c->sub_done(c, id, st, c->sub_arg);
}

static const npf_tunnel_io tun_io = {tun_write_ctrl, tun_write_data, tun_backlog, tun_ready, tun_control, tun_broken,
                                     tun_unit, tun_target_ok, tun_sublink_done};
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

/* the session's tunnel (call_start_transport, ws_reset), NULL: no memory */
npf_tunnel *call_tunnel_new(npf_call *c)
{
    npf_tunnel *t = npf_tunnel_new(c->n->loop, c->caller, &tun_io, c, call_policy(c));
    if (t && c->n->budget)
        npf_tunnel_set_budget(t, c->n->budget);   /* a hosted client: its quota */
    return t;
}


/* keys from k1 | k2 (security.md 9.5) and the AnLiu connection */
int call_start_transport(npf_call *c)
{
    anl_config cfg;
    uint8_t psk[32], cv[32];
    npf_kdf(psk, c->k12, 64, "npf anliu psk v1", 16);
    npf_kdf(cv, c->k12, 64, "npf anliu conv v1", 17);
    npf_kdf(c->nominate_key, c->k12, 64, "npf nominate v1", 15);
    {
        uint8_t pk[32];
        npf_kdf(pk, c->k12, 64, "npf path v1", 11);
        npf_siv_derive(&c->path_keys, pk, LABEL_PATH);
        npf_wipe(pk, sizeof pk);
        c->path_ready = 1;
    }
    c->conv = npf_rd32(cv);
    if (c->conv == 0)
        c->conv = 1;
    c->keys_ready = 1;
    if (c->ws_mode) {   /* the tunnel starts with the START exchange */
        if (c->ws_has_pending && c->wsr) {      /* the START came on this relay connection */
            c->ws_has_pending = 0;
            call_wsr_start(c->wsr, c->ws_pending_salt, c);
        } else if (c->caller && c->wsr && npf_wsr_paired(c->wsr)) {
            call_wsr_paired(c->wsr, c);
        }
        return 0;
    }
    anl_config_default(&cfg, c->caller ? ANL_ROLE_CLIENT : ANL_ROLE_SERVER);
    memcpy(cfg.psk, psk, 32);
    cfg.mtu = ANL_MTU;
    cfg.default_rcv_wnd = NPF_ANL_CTRL_WND;
    cfg.keepalive_ms = 15000;
    cfg.idle_timeout_ms = 60000;
    {
        /* tests: NPF_TEST_PACE=bytes/s caps AnLiu's pacing (a BBR-overestimate diagnostic) */
        const char *v = getenv("NPF_TEST_PACE");
        if (v)
            cfg.pace_rate = atoi(v);
    }
    npf_wipe(psk, 32);
    c->anl = anl_create(c->conv, &cfg, c);
    if (!c->anl)
        return -1;
    conv_link(c);
    anl_setoutput(c->anl, anl_out);
    anl_set_accept(c->anl, anl_accept);
    anl_update(c->anl, (uint32_t)npf_mono_ms());
    c->tun = call_tunnel_new(c);
    if (!c->tun)
        return -1;
    if (c->caller) {
        /* one data stream, both directions: the caller opens it, the callee
         * takes it in the accept callback (its STREAM_OPEN goes at once,
         * before any data); control goes on the default stream 0 */
        anl_stream_opt opt;
        int err = 0;
        anl_stream_opt_default(&opt, ANL_RELIABLE);
        opt.rcv_wnd = NPF_ANL_DATA_WND;     /* what the callee takes (media.h) */
        opt.tag = NPF_TAG_TUNNEL;
        opt.stream = 0;                     /* messages: the data header needs no length */
        opt.prio = 2;
        c->stream = anl_stream_open(c->anl, &opt, &err);
        if (!c->stream)
            return -1;
    }
    /* hello waits for a path: sent into nothing it would sit out an RTO */
    if (!c->caller && (c->p2p || c->relay.bound))
        npf_tunnel_start(c->tun);
    anl_schedule(c);
    if (c->punch_wait_keys) {
        c->punch_wait_keys = 0;
        call_start_punch_now(c);
    }
    return 0;
}

static int finish_handshake(npf_call *c)
{
    uint8_t k1[32], k2[32];
    const uint8_t *rs = npf_noise_remote_static(&c->hs);
    if (!rs || npf_noise_split(&c->hs, NULL, NULL, k1, k2, NULL) < 0)
        return -1;
    memcpy(c->peer_pub, rs, 32);
    memcpy(c->k12, k1, 32);
    memcpy(c->k12 + 32, k2, 32);
    npf_wipe(k1, 32);
    npf_wipe(k2, 32);
    if (c->password[0])
        npf_wipe(c->password, sizeof c->password);
    return call_start_transport(c);
}

/* a path (relay bound or direct) became usable */
void call_path_up(npf_call *c)
{
    if (!c->anl)
        return;
    if (!c->caller && c->tun && !npf_tunnel_is_ready(c->tun))
        npf_tunnel_start(c->tun);
    anl_update(c->anl, (uint32_t)npf_mono_ms());
    anl_flush(c->anl);
    timer_stop(c->n->loop, &c->t_anl);
    anl_schedule(c);
}



/* no punching in this session: connect_mode secure on either side (relays
 * only, neither side's address goes to the other), or tests (NPF_NO_P2P) */
int call_no_p2p(const npf_call *c)
{
    return c->secure || getenv("NPF_NO_P2P") != NULL;
}



/* nat-traversal.md 10.3: unacknowledged data and nothing heard on the direct
 * path for 3 s while the relay is bound -> back to the relay, punch again later */
/* nat-traversal.md 10.3. A long queue on a loaded uplink can hold packets for
 * seconds, so silence alone does not prove the direct path dead: with
 * unacknowledged data and nothing heard for max(3 s, 2 RTO), send on both
 * paths (asking for a relay if it was released); give the direct path up
 * only if it stays silent for another 10 s. */
/* ---- direct path check ----
 * Hearing the peer on the direct path does not prove that it hears us: with
 * a path that died one way (a firewall, a cut in a test) the peer's
 * datagrams still arrive while ours are lost, and the path was taken back
 * and the session lost (mesh.sh, 2026-10-06). While the path is suspect,
 * PATH_CHECK{nonce} goes out on it every 500 ms; the peer answers each on
 * the direct path with PATH_ECHO{nonce}. Only a matching echo, a round
 * trip over the path, brings it back. The packets are SIV-sealed with a
 * key of the session and the sender's direction: nobody else can make one,
 * and a reflected check is no echo. */
static void path_send(npf_call *c, int type, uint64_t nonce)
{
    uint8_t buf[PATH_PKT_LEN], *p = buf + NPF_SIV_TAG_SIZE;
    if (!c->path_ready || !c->p2p || p2p_cut(c))
        return;
    p[0] = (uint8_t)type;
    p[1] = 0;
    npf_le64(p + 2, nonce);
    npf_siv_seal(&c->path_keys, c->caller ? 0 : 1, buf, 10);
    call_udp_send(c, c->p2p_fd, &c->p2p_addr, buf, sizeof buf);
}

/* 1 when the datagram was a path check or echo of this call */
static int path_input(npf_call *c, const uint8_t *buf, size_t len)
{
    uint8_t plain[16];
    if (!c->path_ready || len != PATH_PKT_LEN || npf_siv_open(&c->path_keys, c->caller ? 1 : 0, buf, len, plain) < 0)
        return 0;
    if (plain[0] == PKT_PATH_CHECK)
        path_send(c, PKT_PATH_ECHO, npf_rd64(plain + 2));
    else if (plain[0] == PKT_PATH_ECHO && c->p2p_suspect && npf_rd64(plain + 2) == c->path_nonce)
        c->path_echo_ms = npf_mono_ms();
    return 1;
}

static void check_p2p(npf_call *c);

static void path_check_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_pcheck = NULL;
    if (!c->p2p_suspect || c->ended)
        return;
    check_p2p(c);                           /* an echo, or the time is up (an idle session's AnLiu timer is far) */
    if (!c->p2p_suspect || c->ended)
        return;
    path_send(c, PKT_PATH_CHECK, c->path_nonce);
    c->t_pcheck = npf_timer_add(c->n->loop, PATH_CHECK_MS, path_check_timer, c);
}

static void p2p_suspect_start(npf_call *c, const char *why);

/* nat-traversal.md 10.3 */
static void check_p2p(npf_call *c)
{
    anl_stats st;
    int64_t now = npf_mono_ms(), quiet;
    if (!c->p2p || c->direct || !c->anl || anl_get_stats(c->anl, &st) < 0)
        return;
    if (c->p2p_suspect) {
        if (c->path_echo_ms > c->p2p_suspect) {
            c->p2p_suspect = 0;
            if (c->standby_check) {         /* both ways: now the relay may go */
                c->standby_check = 0;
                call_standby_done(c->n->loop, c);
                return;
            }
            npf_log("call %s: direct path alive again (checked both ways)", c->call_id_s);
            if (c->relay.active && !c->t_standby)
                c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
            return;
        }
        if (now - c->p2p_suspect < P2P_DUAL_MS)
            return;
        npf_logw("call %s: direct path lost, staying on the relay", c->call_id_s);
        c->p2p_suspect = 0;
        c->standby_check = 0;
        c->p2p = 0;
        if (c->p2p_owned) {
            npf_loop_del(c->n->loop, c->p2p_fd);
            npf_sock_close(c->p2p_fd);
            c->p2p_owned = 0;
        }
        c->p2p_fd = -1;
        anl_flush(c->anl);
        if (c->relay.active && !c->relay.bound && !c->relay.t_bind) {
            /* the UDP relay did not bind either (binding still: it asks for
             * the WS relay itself when it gives up) */
            npf_logw("call %s: no UDP relay bound: the WS relay", c->call_id_s);
            call_ask_ws_relay(c);
            return;
        }
        if (!c->relay.active && c->caller && !call_no_p2p(c)) {
            /* no relay to fall back on (an anonymous caller, D6): the only way
             * out is a new round now, before AnLiu's idle timeout ends the session */
            timer_stop(c->n->loop, &c->t_repunch);
            c->repunch_waiting = 0;
            c->punch_retries = 0;
            if (c->punch_requests < PUNCH_ROUNDS_MAX - 1)
                call_repunch_timer(c->n->loop, c);
            else
                npf_logw("call %s: %d punching rounds, no more", c->call_id_s, PUNCH_ROUNDS_MAX);
        } else {
            call_schedule_repunch(c);
        }
        return;
    }
    /* silence counts from the later of the last datagram heard and the moment
     * data went in flight: after an idle spell the first new request must not
     * look like a path that has been quiet all along */
    if (st.inflight == 0) {
        c->p2p_busy_since = 0;
        return;
    }
    if (!c->p2p_busy_since)
        c->p2p_busy_since = now;
    quiet = 2 * (int64_t)st.rto > P2P_SILENT_MS ? 2 * (int64_t)st.rto : P2P_SILENT_MS;
    if (now - (c->p2p_rx_ms > c->p2p_busy_since ? c->p2p_rx_ms : c->p2p_busy_since) < quiet)
        return;
    {
        char why[64];
        snprintf(why, sizeof why, "direct path silent for %lld ms", (long long)quiet);
        p2p_suspect_start(c, why);
    }
}

/* the direct path is in doubt: checked both ways (PATH_CHECK), the data on
 * the relay too meanwhile (asked for when it was released) */
static void p2p_suspect_start(npf_call *c, const char *why)
{
    c->p2p_suspect = npf_mono_ms();
    npf_random(&c->path_nonce, sizeof c->path_nonce);
    if (!c->t_pcheck)
        path_check_timer(c->n->loop, c);
    timer_stop(c->n->loop, &c->t_standby);
    if (c->relay.active) {
        npf_log("call %s: %s, sending on the relay too", c->call_id_s, why);
        if (!c->relay.bound && !c->relay.t_bind) {
            /* it never bound (the direct path carried the session): bound
             * now, or the session had nothing left when the path went */
            npf_log("call %s: the UDP relay never bound: binding it again", c->call_id_s);
            call_relay_rebind(c);
        }
    } else if (!c->relay_asked) {
        /* the relay was released after the standby: ask for a new allocation */
        char data[96];
        npf_log("call %s: %s, asking for a relay", c->call_id_s, why);
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"udp\"}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        c->relay_asked = 1;
    }
    anl_flush(c->anl);
}

/* the direct path held for 30 s: stop using the relay; the caller tells the
 * platform to free both allocations (data-channel.md 3) */
void call_standby_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    char data[96];
    (void)loop;
    c->t_standby = NULL;
    if (!c->p2p || !c->relay.active)
        return;
    if (c->p2p_suspect) {   /* not while the direct path is in doubt */
        if (!c->standby_check)
            c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
        return;
    }
    if (c->path_echo_ms < c->p2p_since) {
        /* the punch proved only that the peer's datagrams reach us (a path
         * cut one way still passes it): a path check answered over the direct
         * path first, else the session would lose the relay it still needs */
        c->standby_check = 1;
        c->p2p_suspect = npf_mono_ms();
        npf_random(&c->path_nonce, sizeof c->path_nonce);
        if (!c->t_pcheck)
            path_check_timer(c->n->loop, c);
        return;
    }
    c->relay.active = 0;
    c->relay.bound = 0;
    timer_stop(c->n->loop, &c->relay.t_bind);
    if (c->caller) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        npf_node_send(c->n, "relay_release", 0, data);
    }
    npf_log("call %s: relay released", c->call_id_s);
}


void call_p2p_input_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    (void)ev;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (c->punch && npf_punch_input(c->punch, fd, buf, (size_t)r, &from))
            continue;
        if (path_input(c, buf, (size_t)r))
            continue;
        if (call_anl_feed(c, buf, (size_t)r) == 0 && !c->ended)
            c->p2p_rx_ms = npf_mono_ms();
        if (c->ended)
            return;
    }
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

void call_free(npf_call *c)
{
    npf_node *n = c->n;
    npf_call **pp;
    for (pp = &n->calls; *pp; pp = &(*pp)->next)
        if (*pp == c) {
            *pp = c->next;
            break;
        }
    if (n->relay_hit == c)
        n->relay_hit = NULL;
    if (c->t_anl) npf_timer_cancel(n->loop, c->t_anl);
    if (c->t_timeout) npf_timer_cancel(n->loop, c->t_timeout);
    if (c->t_punch) npf_timer_cancel(n->loop, c->t_punch);
    if (c->t_linger) npf_timer_cancel(n->loop, c->t_linger);
    if (c->t_ws_wait) npf_timer_cancel(n->loop, c->t_ws_wait);
    if (c->t_repunch) npf_timer_cancel(n->loop, c->t_repunch);
    if (c->t_direct) npf_timer_cancel(n->loop, c->t_direct);
    if (c->t_standby) npf_timer_cancel(n->loop, c->t_standby);
    if (c->t_pcheck) npf_timer_cancel(n->loop, c->t_pcheck);
    if (c->relay.t_bind) npf_timer_cancel(n->loop, c->relay.t_bind);
    if (c->t_wsflush) npf_timer_cancel(n->loop, c->t_wsflush);
    if (c->t_free) npf_timer_cancel(n->loop, c->t_free);     /* freed now (the node stops): not again */
    if (c->wsr) npf_wsr_close(c->wsr);
    free(c->ws_out);
    free(c->ws_in);
    if (c->punch) {
        npf_punch_free(c->punch);
        if (c->punch_socks > 0) {
            c->punch_socks = 0;
            call_punch_sockets_back(c->n);
        }
    }
    call_rev_close_all(c);
    if (c->tun) npf_tunnel_free(c->tun);
    free(c->targets);
    call_dpend_free(c);
    npf_media_free(c->media);
    npf_udpf_free(c->udp);
    if (c->anl) {
        call_conv_unlink(c);
        anl_release(c->anl);            /* releases the stream handles too */
    }
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

/* ---- caller ---- */

npf_call *npf_call_start_grant(npf_node *n, uint64_t number, const uint8_t *chain, size_t chain_len,
                               const uint8_t *grant, size_t grant_len)
{
    npf_cert inter, leaf;
    npf_call *c;
    if (grant_len > sizeof c->grant
        || npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, chain, chain_len, &inter, &leaf,
                                npf_node_time(n) / 1000) < 0
        || leaf.type != NPF_CERT_NODE || leaf.subject != number) {
        npf_log("call: the platform's certificate for %llu does not verify", (unsigned long long)number);
        return NULL;
    }
    /* IK with the certified key; the grant goes with the call (security.md 8.2) */
    n->pending_grant = grant;
    n->pending_grant_len = grant_len;
    c = npf_call_start(n, number, NULL, leaf.dh_pub);
    n->pending_grant = NULL;
    return c;
}

npf_call *npf_call_start(npf_node *n, uint64_t number, const char *password, const uint8_t pinned[32])
{
    char data[4096];
    npf_call *c;
    uint8_t pro[64], msg[256], cmsg[32], sid[24];
    size_t pl;
    int len;
    char num[24], hs[NPF_B64_LEN(256)];
    npf_jw w;
    if (!n->online)
        return NULL;
    c = call_new(n, 1);
    if (!c)
        return NULL;
    c->number = number;
    npf_random(c->call_id, 16);
    call_b64_of(c->call_id, 16, c->call_id_s);
    c->auth = password ? AUTH_PAKE : n->pending_grant ? AUTH_GRANT : AUTH_IK;
    if (n->pending_grant) {
        memcpy(c->grant, n->pending_grant, n->pending_grant_len);
        c->grant_len = n->pending_grant_len;
    }
    prologue(c, pro, &pl);
    if (password) {
        snprintf(c->password, sizeof c->password, "%s", password);
        sid_of(c, sid);
        if (npf_cpace_start(&c->cp, c->password, strlen(c->password), sid, sizeof sid, cmsg) < 0
            || npf_noise_init(&c->hs, NPF_NOISE_XXPSK3, 1, pro, pl, n->id.dh_sk, NULL, NULL) < 0)
            goto fail;
    } else {
        memcpy(c->pinned, pinned, 32);
        if (npf_noise_init(&c->hs, NPF_NOISE_IK, 1, pro, pl, n->id.dh_sk, pinned, NULL) < 0)
            goto fail;
    }
    len = npf_noise_write(&c->hs, NULL, 0, msg, sizeof msg);
    if (len < 0)
        goto fail;
    call_b64_of(msg, (size_t)len, hs);
    snprintf(num, sizeof num, "%llu", (unsigned long long)number);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kstr(&w, "callee", num);
    npf_jw_kstr(&w, "auth", c->auth == AUTH_PAKE ? "pake" : c->auth == AUTH_GRANT ? "grant" : "ik");
    npf_jw_kstr(&w, "hs", hs);
    if (c->auth == AUTH_GRANT)
        npf_jw_kb64(&w, "grant", c->grant, c->grant_len);
    if (password)
        npf_jw_kb64(&w, "cpace", cmsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) < 0)
        goto fail;
    c->call_req = npf_node_send(n, "call", 1, data);
    if (c->call_req < 0)
        goto fail;
    c->state = NPF_CALL_CALLING;
    npf_log("call %s: calling %llu (%s)", c->call_id_s, (unsigned long long)number,
            c->auth == AUTH_PAKE ? "pairing" : c->auth == AUTH_GRANT ? "the account's grant" : "paired");
    return c;
fail:
    call_free(c);
    return NULL;
}

/* incoming / call_accepted: "secure" when the session is to stay on relays
 * (connect_mode secure here or on the other side) */
static void secure_of(npf_call *c, const npf_json *j, int d)
{
    int v = 0;
    if (npf_json_bool(j, npf_json_get(j, d, "secure"), &v) == 0 && v && !c->secure) {
        c->secure = 1;
        npf_log("call %s: secure: relays only, no direct path", c->call_id_s);
    }
}

static void caller_accepted(npf_call *c, const npf_json *j, int d)
{
    uint8_t msg[512], out[256], peer_y[32], isk[32], p[64];
    int ml, ol;
    ml = npf_json_get_b64(j, d, "hs", msg, sizeof msg);
    if (ml < 0)
        goto fail;
    parse_cands(c, j, d);
    secure_of(c, j, d);
    if (c->auth == AUTH_PAKE) {
        char data[1024];
        if (npf_json_get_b64(j, d, "cpace", peer_y, 32) != 32 || npf_cpace_finish(&c->cp, peer_y, 1, isk) < 0)
            goto fail;
        npf_noise_set_psk(&c->hs, isk);
        npf_wipe(isk, 32);
        if (npf_noise_read(&c->hs, msg, (size_t)ml, p, sizeof p) < 0)
            goto fail;
        ol = npf_noise_write(&c->hs, NULL, 0, out, sizeof out);
        if (ol < 0)
            goto fail;
        {
            char b[NPF_B64_LEN(256)];
            call_b64_of(out, (size_t)ol, b);
            snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"step\":3,\"msg\":\"%s\"}", c->call_id_s, b);
        }
        npf_node_send(c->n, "handshake", 0, data);
    } else {
        if (npf_noise_read(&c->hs, msg, (size_t)ml, p, sizeof p) < 0)
            goto fail;
    }
    if (finish_handshake(c) < 0)
        goto fail;
    call_set_state(c, NPF_CALL_CONNECTING, NULL);
    call_relay_setup(c, j, d);
    return;
fail:
    npf_logw("call %s: handshake with the callee failed", c->call_id_s);
    npf_call_end(c, "auth_failed");
}

/* ---- callee ---- */

static void callee_reply_error(npf_node *n, const char *req, const char *err)
{
    npf_node_reply(n, "incoming", req, "error", err, NULL);
}

/* an incoming pairing (CPace, then Noise XXpsk3 with its key): the answer
 * in out (*ol bytes), the CPace message in ymsg; NULL, or the error to reply */
static const char *incoming_pake(npf_call *c, const npf_json *j, int d, const uint8_t *msg, int ml, uint8_t *out,
                                 size_t outcap, int *ol, uint8_t ymsg[32])
{
    npf_node *n = c->n;
    const char *pw = n->callee->password ? n->callee->password(n, n->callee_arg) : NULL;
    int64_t lock = n->callee->locked_until ? n->callee->locked_until(n, n->callee_arg) : 0;
    uint8_t p[64], pro[64], sid[24], isk[32], peer_y[32];
    size_t pl;
    int ok;
    c->auth = AUTH_PAKE;
    if (lock > npf_node_time(n) / 1000)
        return "locked";
    if (!pw || !*pw || npf_json_get_b64(j, d, "cpace", peer_y, 32) != 32)
        return "unauthorized";
    prologue(c, pro, &pl);
    sid_of(c, sid);
    ok = npf_cpace_start(&c->cp, pw, strlen(pw), sid, sizeof sid, ymsg) >= 0
         && npf_cpace_finish(&c->cp, peer_y, 0, isk) >= 0
         && npf_noise_init(&c->hs, NPF_NOISE_XXPSK3, 0, pro, pl, n->id.dh_sk, NULL, isk) >= 0
         && npf_noise_read(&c->hs, msg, (size_t)ml, p, sizeof p) >= 0
         && (*ol = npf_noise_write(&c->hs, NULL, 0, out, outcap)) >= 0;
    npf_wipe(isk, 32);
    return ok ? NULL : "unauthorized";
}

/* an incoming session of a paired caller (Noise IK) or of a grant: the
 * callee gate (security.md 8.3): the caller's key is authorized, or hosted
 * trust with a valid grant bound to that key; the answer in out (*ol bytes) */
static const char *incoming_ik(npf_call *c, const npf_json *j, int d, const uint8_t *msg, int ml, uint8_t *out,
                               size_t outcap, int *ol)
{
    npf_node *n = c->n;
    uint8_t p[64], pro[64];
    size_t pl;
    prologue(c, pro, &pl);
    if (npf_noise_init(&c->hs, NPF_NOISE_IK, 0, pro, pl, n->id.dh_sk, NULL, NULL) < 0
        || npf_noise_read(&c->hs, msg, (size_t)ml, p, sizeof p) < 0)
        return "unauthorized";
    if (c->auth == AUTH_IK) {
        if (!n->callee->authorized || !n->callee->authorized(n, npf_noise_remote_static(&c->hs), n->callee_arg))
            return "unauthorized";
    } else {
        uint8_t g[512];
        npf_grant gr;
        int gl = npf_json_get_b64(j, d, "grant", g, sizeof g);
        if (gl <= 0 || !n->callee->grant_check
            || n->callee->grant_check(n, g, (size_t)gl, npf_noise_remote_static(&c->hs), &c->grant_account, &gr,
                                      n->callee_arg) < 0
            || set_targets(c, &gr) < 0)
            return "unauthorized";
    }
    *ol = npf_noise_write(&c->hs, NULL, 0, out, outcap);
    if (*ol < 0 || finish_handshake(c) < 0)
        return "unauthorized";
    return NULL;
}

static void handle_incoming(npf_node *n, const npf_json *j, int d)
{
    char data[4096];
    char req[24], auth[8], hs_b[NPF_B64_LEN(512)];
    uint8_t msg[512], out[512], ymsg[32];
    const char *err;
    int ml, ol = -1;
    npf_call *c;
    npf_jw w;
    if (npf_json_get_str(j, 0, "id", req, sizeof req) < 0)
        return;
    if (!n->callee) {
        callee_reply_error(n, req, "unauthorized");
        return;
    }
    if (find_call(n, j, d)) {
        callee_reply_error(n, req, "conflict");
        return;
    }
    /* concurrent sessions (signaling.md "incoming": busy); direct sessions
     * have their own limit on the listener */
    {
        int sessions = 0, max = n->cfg.max_calls > 0 ? n->cfg.max_calls : MAX_CALLS_DEFAULT;
        for (c = n->calls; c; c = c->next)
            if (!c->caller && !c->direct && !c->ended)
                sessions++;
        if (sessions >= max) {
            npf_logw("call: %d sessions already, refusing a new one (busy)", sessions);
            callee_reply_error(n, req, "busy");
            return;
        }
    }
    c = call_new(n, 0);
    if (!c)
        return;
    snprintf(c->req_id, sizeof c->req_id, "%s", req);
    c->number = n->cfg.number;
    {
        int who = npf_json_get(j, d, "caller");
        char id[24];
        if (who >= 0 && npf_json_eq(j, npf_json_get(j, who, "kind"), "node")
            && npf_json_get_str(j, who, "id", id, sizeof id) > 0)
            c->caller_number = strtoull(id, NULL, 10);
        if (who >= 0) {
            int a = npf_json_get(j, who, "app");
            char an[40] = "", av[40] = "";
            if (a >= 0 && npf_json_get_str(j, a, "name", an, sizeof an) > 0
                && npf_json_get_str(j, a, "ver", av, sizeof av) > 0)
                snprintf(c->caller_app, sizeof c->caller_app, "%.32s %.32s", an, av);   /* each 1..32 (signaling.md) */
            npf_json_bool(j, npf_json_get(j, who, "hosted"), &c->caller_hosted);
        }
    }
    if (npf_json_get_b64(j, d, "call_id", c->call_id, 16) != 16
        || npf_json_get_str(j, d, "auth", auth, sizeof auth) < 0
        || (ml = npf_json_get_b64(j, d, "hs", msg, sizeof msg)) < 0) {
        callee_reply_error(n, req, "bad_request");
        call_free(c);
        return;
    }
    call_b64_of(c->call_id, 16, c->call_id_s);
    parse_cands(c, j, d);
    secure_of(c, j, d);
    if (strcmp(auth, "pake") == 0) {
        err = incoming_pake(c, j, d, msg, ml, out, sizeof out, &ol, ymsg);
    } else if (strcmp(auth, "ik") == 0 || strcmp(auth, "grant") == 0) {
        c->auth = strcmp(auth, "ik") == 0 ? AUTH_IK : AUTH_GRANT;
        err = incoming_ik(c, j, d, msg, ml, out, sizeof out, &ol);
    } else {
        err = "unauthorized";
    }
    if (err) {
        callee_reply_error(n, req, err);
        call_free(c);
        return;
    }
    call_b64_of(out, (size_t)ol, hs_b);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "hs", hs_b);
    if (c->auth == AUTH_PAKE)
        npf_jw_kb64(&w, "cpace", ymsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) < 0) {
        call_free(c);
        return;
    }
    npf_node_reply(n, "incoming", req, "ok", NULL, data);
    c->state = NPF_CALL_CONNECTING;
    npf_log("call %s: incoming %s call accepted", c->call_id_s, c->auth == AUTH_PAKE ? "pairing" : "paired");
    call_relay_setup(c, j, d);
}

static void handle_handshake(npf_call *c, const npf_json *j, int d)
{
    uint8_t msg[512], p[64];
    int ml;
    int64_t step;
    if (c->caller || c->auth != AUTH_PAKE || c->keys_ready)
        return;
    if (npf_json_get_int(j, d, "step", 3, 3, &step) < 0 || (ml = npf_json_get_b64(j, d, "msg", msg, sizeof msg)) < 0)
        return;
    if (npf_noise_read(&c->hs, msg, (size_t)ml, p, sizeof p) < 0) {
        /* wrong password: count it (security.md 8.3) */
        npf_logw("call %s: pairing failed (wrong password)", c->call_id_s);
        if (c->n->callee->pair_failed)
            c->n->callee->pair_failed(c->n, c->n->callee_arg);
        npf_call_end(c, "auth_failed");
        return;
    }
    if (finish_handshake(c) < 0) {
        npf_call_end(c, "error");
        return;
    }
    /* msg 3 depends on our fresh ephemeral key: not a replay, the caller knows the password */
    if (c->n->callee->paired)
        c->n->callee->paired(c->n, c->peer_pub, c->n->callee_arg);
    npf_log("call %s: paired", c->call_id_s);
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
        handle_incoming(n, j, d);
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
    c = find_call(n, j, d);
    if (!c || c->ended)
        return;
    if (strcmp(type, "call_accepted") == 0 && c->caller && c->state == NPF_CALL_CALLING) {
        call_accept_seen(c);
        caller_accepted(c, j, d);
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
        handle_handshake(c, j, d);
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
            if (on_p2p && p2p_cut(c))
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
            if (!c->ended && c->p2p && fd == c->p2p_fd && call_same_addr(from, &c->p2p_addr) && path_input(c, buf, len))
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
            p2p_suspect_start(c, w);
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

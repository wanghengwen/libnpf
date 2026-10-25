/* Calls: the data transport of a session. The AnLiu connection (its
 * callbacks, timer and drain, the conv table), the WS relay's record mux,
 * the tunnel's callbacks (npf_tunnel_io) and the control messages in it,
 * the media and UDP forward adapters, the caller key shares and the tunnel
 * made for a session (data-channel.md, security.md 9.5). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define NPF_TAG_TUNNEL     1
#define ANL_MTU            1200
#define ANL_MSG_MAX        (NPF_DATA_HDR + NPF_FRAME_MAX)   /* the largest message on either stream (a data message) */

static void grant_update(npf_call *c, const npf_json *j);
static void anl_schedule(npf_call *c);

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
/* ---- AnLiu ---- */
static int anl_out(char *buf, int len, anl_t *w, void *user)
{
    npf_call *c = user;
    (void)w;
    if (c->p2p && !call_p2p_cut(c))
        call_udp_send(c, c->p2p_fd, &c->p2p_addr, (const uint8_t *)buf, (size_t)len);
    /* the relay carries the data when there is no direct path, and as a second
     * copy while the direct path is suspected (AnLiu drops the duplicates) */
    if ((!c->p2p || c->p2p_suspect) && c->relay.active)
        call_relay_send_data(c, (const uint8_t *)buf, (size_t)len);
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
        size_t cap = c->ws_out_cap ? c->ws_out_cap : 16384;
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
    if (!c->ended)
        call_set_state(c, NPF_CALL_ESTABLISHED, NULL);
}

/* Only ids emitted by ctl_request match a pending request. atoi accepted
 * arbitrary prefixes / suffixes and overflowing numbers from the peer. */
static int ctl_id(const char *s)
{
    int id = 0;
    if (*s++ != 'c' || *s < '1' || *s > '9')
        return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || id > (INT_MAX - (*s - '0')) / 10)
            return -1;
        id = id * 10 + (*s - '0');
    }
    return id;
}

static void tun_control(void *arg, const npf_json *j)
{
    npf_call *c = arg;
    char type[32], rt[24];
    int i;
    if (npf_json_get_str(j, 0, "type", type, sizeof type) <= 0)
        return;
    if (npf_json_get_str(j, 0, "reply_to", rt, sizeof rt) > 0) {
        int id = ctl_id(rt);
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
            call_crev_del(c, (uint32_t)id);
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

static int ctl_send(npf_call *c, const char *type, const char *id_key, const char *id,
                    const char *status, const char *error, const char *data_json)
{
    char *buf;
    npf_jw w;
    int n, r;
    if (!c->tun || !(buf = npf_scratch(NPF_CTRL_MAX)))
        return -1;
    npf_jw_init(&w, buf, NPF_CTRL_MAX);
    npf_jw_obj(&w);
    npf_jw_kint(&w, "v", 1);
    npf_jw_kstr(&w, "type", type);
    if (id_key)
        npf_jw_kstr(&w, id_key, id);
    if (status)
        npf_jw_kstr(&w, "status", status);
    if (error)
        npf_jw_kstr(&w, "error", error);
    npf_jw_key(&w, "data");
    npf_jw_raw(&w, data_json ? data_json : "{}", data_json ? strlen(data_json) : 2);
    npf_jw_end(&w);
    n = npf_jw_finish(&w);
    r = n < 0 ? -1 : npf_tunnel_control(c->tun, buf, (size_t)n);
    npf_scratch_done(buf);
    return r;
}

int npf_call_ctl_request(npf_call *c, const char *type, const char *data_json, npf_ctl_fn fn, void *arg)
{
    char id[24];
    int i, k, seq;
    if (!fn || c->ended || !c->tun || !npf_tunnel_is_ready(c->tun))
        return -1;
    for (i = 0; i < NPF_CALL_CTL_MAX && c->ctl[i].fn; i++)
        ;
    if (i == NPF_CALL_CTL_MAX)
        return -1;
    do {
        c->ctl_seq = c->ctl_seq == INT_MAX ? 1 : c->ctl_seq + 1;
        for (k = 0; k < NPF_CALL_CTL_MAX; k++)
            if (c->ctl[k].fn && c->ctl[k].id == c->ctl_seq)
                break;
    } while (k != NPF_CALL_CTL_MAX);
    seq = c->ctl_seq;
    snprintf(id, sizeof id, "c%d", seq);
    c->ctl[i].id = seq;
    c->ctl[i].fn = fn;
    c->ctl[i].arg = arg;
    if (ctl_send(c, type, "id", id, NULL, NULL, data_json) < 0) {
        if (c->ctl[i].id == seq)
            c->ctl[i].fn = NULL;
        return -1;
    }
    return 0;
}

int npf_call_ctl_event(npf_call *c, const char *type, const char *data_json)
{
    if (c->ended || !c->tun || !npf_tunnel_is_ready(c->tun))
        return -1;
    return ctl_send(c, type, NULL, NULL, NULL, NULL, data_json);
}

int npf_call_ctl_reply(npf_call *c, const char *type, const npf_json *req, const char *status, const char *error,
                       const char *data_json)
{
    char id[24];
    if (npf_json_get_str(req, 0, "id", id, sizeof id) <= 0)
        return -1;
    return ctl_send(c, type, "reply_to", id, status, error, data_json);
}
/* the target policy of this session's tunnel: a callee's, the published
 * resources; a caller's, none (its -R reaches what it registered, 7.1) */
struct npf_policy *call_policy(npf_call *c)
{
    if (c->caller)
        return NULL;
    return c->policy ? c->policy : c->n->callee ? c->n->callee->policy : NULL;
}
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
    if (!(buf = npf_scratch(ANL_MSG_MAX)))     /* kept by the thread between uses (sys.h): no larger than needed */
        return;
    anl_drain_with(c, buf, ANL_MSG_MAX);
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
            if (r == ANL_EBUFSIZE) {        /* larger than any message of the protocol: it would never be read */
                npf_logw("call %s: a message of the peer's over %d bytes: the session ends", c->call_id_s, (int)cap);
                npf_call_end(c, "error");
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
    call_check_p2p(c);
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
    if (!c->media && !c->ended && c->tun && (c->ws_mode || c->anl))
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
    if (!c->udp && !c->ended && c->tun && (c->ws_mode || c->anl)) {
        c->udp = npf_udpf_new(c->n->loop, c->ws_mode ? NULL : c->anl, c->caller, call_policy(c), &udp_io, c);
        if (c->udp) {
            npf_udpf_set_shared(c->udp, &c->n->tun_shared, c->kshare ? &c->kshare->sh : NULL);
            call_crev_restore(c, NULL, c->udp);
        }
    }
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
    if (call_set_targets(c, &gr) < 0) {
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
static npf_key_share *key_share(npf_node *n, const uint8_t pub[32])
{
    npf_key_share *e, *idle = NULL, **ns;
    int i;
    for (i = 0; i < n->nkshares; i++) {
        e = n->kshares[i];
        if (memcmp(e->pub, pub, 32) == 0)
            return e;
        if (!idle && !e->calls && !e->sh.subs && !e->sh.rx)
            idle = e;
    }
    if (!(e = idle)) {
        if (!(e = calloc(1, sizeof *e)))
            return NULL;
        if (!(ns = realloc(n->kshares, (size_t)(n->nkshares + 1) * sizeof *ns))) {
            free(e);
            return NULL;
        }
        n->kshares = ns;
        n->kshares[n->nkshares++] = e;
    }
    memset(e, 0, sizeof *e);
    memcpy(e->pub, pub, 32);
    e->sh.subs_max = n->tun_shared.subs_max / 2;
    e->sh.rx_max = n->tun_shared.rx_max / 2;
    return e;
}

void call_key_shares_free(npf_node *n)
{
    int i, k = 0;
    for (i = 0; i < n->nkshares; i++)
        if (n->kshares[i]->calls || n->kshares[i]->sh.subs || n->kshares[i]->sh.rx)
            n->kshares[k++] = n->kshares[i];    /* a tunnel still going: kept, not freed under it */
        else
            free(n->kshares[i]);
    n->nkshares = k;
    if (!k) {
        free(n->kshares);
        n->kshares = NULL;
    }
}

/* the session's tunnel (call_start_transport, ws_reset), NULL: no memory;
 * a callee's counts in the node's limits and its caller key's */
npf_tunnel *call_tunnel_new(npf_call *c)
{
    npf_tunnel *t = npf_tunnel_new(c->n->loop, c->caller, &tun_io, c, call_policy(c));
    static const uint8_t zero[32];
    if (!t)
        return NULL;
    if (c->n->budget)
        npf_tunnel_set_budget(t, c->n->budget);   /* a hosted client: its quota */
    if (!c->caller && !c->direct && !c->kshare && memcmp(c->peer_pub, zero, 32) != 0
        && (c->kshare = key_share(c->n, c->peer_pub)))
        c->kshare->calls++;
    npf_tunnel_set_shared(t, &c->n->tun_shared, c->kshare ? &c->kshare->sh : NULL);
    call_crev_restore(c, t, NULL);          /* a new tunnel of the session: its -R mappings go on */
    return t;
}


/* keys from k1 | k2 (security.md 9.5) and the AnLiu connection */
int call_start_transport(npf_call *c)
{
    anl_config cfg;
    uint8_t psk[32], cv[32];
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
    npf_wipe(cv, sizeof cv);
    if (c->conv == 0)
        c->conv = 1;
    c->keys_ready = 1;
    call_hs_free(c);                        /* nothing of the handshake is needed from here on */
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
    npf_kdf(psk, c->k12, 64, "npf anliu psk v1", 16);
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
    npf_wipe(&cfg, sizeof cfg);
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

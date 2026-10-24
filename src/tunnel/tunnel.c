/* libnpf: the tunnel (data-channel.md): frames, flow control, the sublinks
 * and their local ends; the SOCKS5 side and connecting in tunnel_socks.c,
 * the rate limits in tunnel_rate.c, the virtual local ends in tunnel_virt.c */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "tunnel_internal.h"

#define BACKLOG_PAUSE  (1024 * 1024)    /* transport bytes queued before local reads pause */

/* ---- helpers ---- */

void npf_tunnel_dump(const npf_tunnel *t);

int tunnel_wb_put(wbuf *b, const void *p, size_t n)
{
    /* the tail full: the room written out at the front taken back when it is
     * as much as what stays (a byte moved for a byte written out at most;
     * at each full tail a local end that reads slowly had about three); else
     * the buffer grows, to twice what it holds at most (that, the window) */
    if (b->off && b->off + b->len + n > b->cap && b->off >= b->len) {
        memmove(b->p, b->p + b->off, b->len);
        b->off = 0;
    }
    if (b->off + b->len + n > b->cap) {
        size_t c = b->cap ? b->cap : 16384;
        uint8_t *q;
        while (c < b->off + b->len + n)
            c *= 2;
        q = realloc(b->p, c);
        if (!q)
            return -1;
        b->p = q;
        b->cap = c;
    }
    memcpy(b->p + b->off + b->len, p, n);
    b->len += n;
    return 0;
}

/* the first n bytes were written */
static void wb_take(wbuf *b, size_t n)
{
    b->off += n;
    b->len -= n;
    if (!b->len)
        b->off = 0;
}

/* a control unit on the control channel */
static int send_ctrl(npf_tunnel *t, int type, const void *body, size_t len)
{
    uint8_t small[64], *buf = small;    /* bigger ones not on the stack (sys.h, npf_scratch) */
    int r;
    if (t->dead || len > NPF_CTRL_MAX)
        return -1;
    if (NPF_CU_HDR + len > sizeof small && !(buf = npf_scratch(NPF_CU_HDR + len)))
        return -1;
    buf[0] = (uint8_t)type;
    npf_le16(buf + 1, (uint16_t)len);
    if (len)
        memcpy(buf + NPF_CU_HDR, body, len);
    r = t->io.write_ctrl(t->arg, buf, NPF_CU_HDR + len);
    if (buf != small)
        npf_scratch_done(buf);
    return r;
}

/* a DATA message: m has NPF_DATA_HDR bytes free, then the payload */
static int send_data(npf_tunnel *t, uint32_t id, uint8_t *m, size_t len)
{
    if (t->dead || len > NPF_FRAME_MAX)
        return -1;
    npf_le32(m, id);
    return t->io.write_data(t->arg, m, NPF_DATA_HDR + len);
}

/* DATA and FIN travel as data messages, WINDOW and RESET as control units */
int tunnel_send_frame(npf_tunnel *t, uint32_t id, int type, const void *payload, size_t len)
{
    uint8_t b[NPF_DATA_HDR + 9];
    if (t->dead)
        return -1;
    npf_le32(b, id);
    switch (type) {
    case FR_DATA: {
        uint8_t small[64], *m = small;
        int r;
        if (len > NPF_FRAME_MAX)
            return -1;
        if (NPF_DATA_HDR + len > sizeof small && !(m = npf_scratch(NPF_DATA_HDR + len)))
            return -1;
        memcpy(m + NPF_DATA_HDR, payload, len);
        r = send_data(t, id, m, len);
        if (m != small)
            npf_scratch_done(m);
        return r;
    }
    case FR_FIN:
        return t->io.write_data(t->arg, b, NPF_DATA_HDR);
    case FR_WINDOW:
        memcpy(b + 4, payload, 4);
        return send_ctrl(t, NPF_CU_WINDOW, b, 8);
    default:
        b[4] = *(const uint8_t *)payload;
        return send_ctrl(t, NPF_CU_RESET, b, 5);
    }
}

static void send_reset(npf_tunnel *t, uint32_t id, int reason)
{
    uint8_t r = (uint8_t)reason;
    tunnel_send_frame(t, id, FR_RESET, &r, 1);
}

sublink *tunnel_find(npf_tunnel *t, uint32_t id)
{
    int i;
    if (t->last < t->nsubs && t->ids[t->last] == id)
        return t->subs[t->last];        /* frames come in runs of one sublink's */
    for (i = 0; i < t->nsubs; i++)
        if (t->ids[i] == id) {
            t->last = i;
            return t->subs[i];
        }
    return NULL;
}

static void rx_add(npf_tunnel *t, int64_t d);
void tunnel_update_ev(sublink *s);

void tunnel_update_ev(sublink *s)
{
    npf_tunnel *t = s->t;
    unsigned ev = 0;
    if (s->fd < 0 && !s->v)
        return;
    if (s->state == SL_LOCAL_GREETING) {
        ev = NPF_EV_READ;
    } else if (s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) {
        if (!s->local_eof && s->tx_credit > 0 && !t->paused && tunnel_rate_allow(s, 1, 1))
            ev |= NPF_EV_READ;
        if (s->wq.len && tunnel_rate_allow(s, 0, 1))
            ev |= NPF_EV_WRITE;
    }
    if (s->v) {                     /* no socket: virt_poll asks the local end */
        s->ev = ev;
        if (ev & s->v->ready(s->varg))
            tunnel_virt_arm(t);
        return;
    }
    if (ev != s->ev) {
        if (s->ev == 0 && ev)
            npf_loop_add(t->loop, s->fd, ev, tunnel_io_cb, s);
        else if (ev == 0)
            npf_loop_del(t->loop, s->fd);
        else
            npf_loop_mod(t->loop, s->fd, ev);
        s->ev = ev;
    }
}

void tunnel_sub_free(sublink *s, int rst)
{
    npf_tunnel *t = s->t;
    int i;
    if (!s->server && t->io.sublink_done) {    /* one we opened (npf_tunnel_open) ends (reverse: a server one) */
        npf_sublink_stats st;
        st.in = s->in;
        st.out = s->out;
        st.connect_ms = s->t_ok ? (int)(s->t_ok - s->t_open) : -1;
        st.first_byte_ms = s->t_first ? (int)(s->t_first - s->t_open) : -1;
        st.end = s->end ? s->end : !rst && s->fin_first == 2 ? "peer_closed" : !rst ? "local_closed" : "local_reset";
        t->io.sublink_done(t->arg, s->id, &st);
    }
    rx_add(t, -(int64_t)s->rx_window);
    for (i = 0; s->shared && i < 2; i++)
        if (t->shared[i])
            t->shared[i]->subs--;
    for (i = 0; i < t->nsubs; i++)
        if (t->subs[i] == s) {          /* the last one takes its place */
            t->nsubs--;
            t->subs[i] = t->subs[t->nsubs];
            t->ids[i] = t->ids[t->nsubs];
            break;
        }
    if (s->t_connect)
        npf_timer_cancel(t->loop, s->t_connect);
    if (s->t_greet)
        npf_timer_cancel(t->loop, s->t_greet);
    if (s->t_he)
        npf_timer_cancel(t->loop, s->t_he);
    if (s->t_gone)
        npf_timer_cancel(t->loop, s->t_gone);
    if (s->vgone)
        t->ngone--;
    for (i = 0; i < s->ncfd; i++) {
        npf_loop_del(t->loop, s->cfd[i]);
        npf_sock_close(s->cfd[i]);
    }
    npf_resolve_cancel(s->resolve);
    free(s->cand);
    if (s->v) {
        const npf_vend_io *v = s->v;
        s->v = NULL;
        v->closed(s->varg, rst);
    }
    if (s->fd >= 0) {
        if (s->ev)
            npf_loop_del(t->loop, s->fd);
        if (rst) {
            struct linger l = {1, 0};   /* abortive close: the application sees RST */
            setsockopt(s->fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
        }
        npf_sock_close(s->fd);
    }
    free(s->wq.p);
    free(s);
}

void tunnel_sub_reset(sublink *s, int reason)
{
    send_reset(s->t, s->id, reason);
    tunnel_sub_free(s, 1);
}

/* release once both directions are finished */
/* both sides ended and all written: the sublink goes; 1 when it went */
static int maybe_done(sublink *s)
{
    if (!(s->local_eof && s->peer_fin && s->wq.len == 0 && s->shut_wr))
        return 0;
    tunnel_sub_free(s, 0);
    return 1;
}

/* room in the node's and the caller key's limits (npf_tunnel_shared) for
 * window bytes more, and with sub for one more peer's sublink */
static int shared_room(const npf_tunnel *t, int sub, int64_t window)
{
    int i;
    for (i = 0; i < 2; i++) {
        const npf_tunnel_shared *sh = t->shared[i];
        if (sh && ((sub && sh->subs >= sh->subs_max) || sh->rx + window > sh->rx_max))
            return 0;
    }
    return 1;
}

/* receive window granted: this tunnel's, and its node's over all tunnels */
static void rx_add(npf_tunnel *t, int64_t d)
{
    int i;
    t->rx_total += d;
    for (i = 0; i < 2; i++)
        if (t->shared[i])
            t->shared[i]->rx += d;
}

static sublink *sub_new(npf_tunnel *t, uint32_t id, int fd, int server)
{
    sublink *s;
    if (t->nsubs == t->cap) {
        int c = t->cap ? t->cap * 2 : 16;
        sublink **ns = realloc(t->subs, (size_t)c * sizeof *ns);
        uint32_t *ni;
        if (!ns)
            return NULL;
        t->subs = ns;
        if (!(ni = realloc(t->ids, (size_t)c * sizeof *ni)))
            return NULL;
        t->ids = ni;
        t->cap = c;
    }
    if (!(s = calloc(1, sizeof *s)))
        return NULL;
    s->t = t;
    s->id = id;
    s->fd = fd;
    s->server = server;
    s->tx_credit = t->peer_window;
    s->rx_window = NPF_INIT_WINDOW;
    rx_add(t, s->rx_window);
    if (server && (t->shared[0] || t->shared[1])) {
        int i;
        s->shared = 1;
        for (i = 0; i < 2; i++)
            if (t->shared[i])
                t->shared[i]->subs++;
    }
    t->subs[t->nsubs] = s;
    t->ids[t->nsubs] = id;
    t->nsubs++;
    return s;
}

/* Data written to the local socket frees receive window. The window grows
 * while the local side keeps up (nothing left queued when a quarter of the
 * window has been consumed), doubling up to NPF_MAX_WINDOW: one sublink's
 * throughput is about window / RTT (data-channel.md 6). */
void tunnel_credit_back(sublink *s, size_t n)
{
    s->rx_freed += (uint32_t)n;
    if (s->rx_freed >= s->rx_window / 4) {
        uint8_t inc[4];
        uint32_t grant = s->rx_freed;
        if (s->wq.len == 0 && s->rx_window < NPF_MAX_WINDOW && s->t->rx_total + s->rx_window <= NPF_RX_BUDGET
            && shared_room(s->t, 0, s->rx_window)) {
            grant += s->rx_window;          /* the extra half becomes permanent window */
            rx_add(s->t, s->rx_window);
            s->rx_window *= 2;
        }
        npf_le32(inc, grant);
        tunnel_send_frame(s->t, s->id, FR_WINDOW, inc, 4);
        s->rx_freed = 0;
    }
}

/* one write to the local end: the bytes it took, 0 none now (full, or the
 * rate group's share used up: the window holds the peer), -1 an error */
static ssize_t local_write(sublink *s, const uint8_t *p, size_t len)
{
    size_t n;
    ssize_t w;
    if (!s->v && s->fd < 0)
        return (ssize_t)len;            /* its virtual end closed (npf_tunnel_vclose): nobody reads it */
    n = tunnel_rate_allow(s, 0, len);
    if (n == 0)
        return 0;
    if (s->v) {
        if ((w = s->v->write(s->varg, p, n)) < 0)
            return -1;
    } else if ((w = send(s->fd, p, n, MSG_NOSIGNAL | MSG_DONTWAIT)) < 0) {
        return npf_sock_again() ? 0 : -1;
    }
    if (w > 0) {
        tunnel_rate_take(s, 0, (size_t)w);
        s->t->local_out += (uint64_t)w;
        if (!s->out)
            s->t_first = npf_mono_ms();
        s->out += (uint64_t)w;
    }
    return w;
}

int tunnel_flush_local(sublink *s)
{
    while (s->wq.len) {
        ssize_t w = local_write(s, s->wq.p + s->wq.off, s->wq.len);
        if (w < 0)
            return -1;
        if (w == 0)
            break;
        wb_take(&s->wq, (size_t)w);
        tunnel_credit_back(s, (size_t)w);
    }
    if (s->wq.len == 0 && s->peer_fin && !s->shut_wr) {
        if (s->v)
            s->v->shutdown(s->varg);
        else if (s->fd >= 0)
            shutdown(s->fd, SHUT_WR);
        s->shut_wr = 1;
    }
    return 0;
}

/* ---- frames from the peer ---- */

static int handle_control_with(npf_tunnel *t, const uint8_t *p, size_t n, npf_jtok *tok);

static int handle_control(npf_tunnel *t, const uint8_t *p, size_t n)
{
    npf_jtok *tok = npf_scratch(512 * sizeof *tok);     /* 8 KB: not on the stack */
    int r;
    if (!tok)
        return -1;
    r = handle_control_with(t, p, n, tok);
    npf_scratch_done(tok);
    return r;
}

static int handle_control_with(npf_tunnel *t, const uint8_t *p, size_t n, npf_jtok *tok)
{
    npf_json j;
    char type[32];
    if (npf_json_parse(&j, (const char *)p, n, tok, 512) < 0 || tok[0].type != NPF_JT_OBJECT
        || npf_json_get_str(&j, 0, "type", type, sizeof type) < 0)
        return -1;
    if (strcmp(type, "hello") == 0) {
        int d = npf_json_get(&j, 0, "data");
        int64_t w = NPF_INIT_WINDOW, m = NPF_MAX_SUBLINKS;
        if (t->hello_recv)
            return -1;
        npf_json_get_int(&j, d, "init_window", 4096, 16 << 20, &w);
        npf_json_get_int(&j, d, "max_sublinks", 1, 4096, &m);
        t->peer_window = (uint32_t)w;
        t->peer_max = (int)m;
        t->hello_recv = 1;
        if (t->caller && !t->hello_sent)
            npf_tunnel_start(t);        /* calls ready */
        else if (t->hello_sent && t->io.ready)
            t->io.ready(t->arg);
        return 0;
    }
    if (t->io.control)
        t->io.control(t->arg, &j);
    return 0;
}

#define SEEN_BITS NPF_MAX_SUBLINKS        /* ids remembered below the largest: as many as may be open */
#define SEEN_WORDS (SEEN_BITS / 64)

/* the window of the peer's ids below the largest, moved n ids on (bit k
 * becomes bit k + n) */
static void seen_shift(uint64_t w[SEEN_WORDS], uint32_t n)
{
    int i, q = (int)(n / 64), r = (int)(n % 64);
    if (n >= SEEN_BITS) {
        memset(w, 0, SEEN_WORDS * sizeof w[0]);
        return;
    }
    for (i = SEEN_WORDS - 1; i >= 0; i--) {
        uint64_t hi = i - q >= 0 ? w[i - q] : 0, lo = i - q - 1 >= 0 ? w[i - q - 1] : 0;
        w[i] = r ? (hi << r) | (lo >> (64 - r)) : hi;
    }
}

/* an id the peer opens (or resets before its first data) seen now: 1 when it
 * is new, 0 when seen already or too old (a released sublink's late frame).
 * Not just the largest: a sublink's first data may come after a later one's
 * (-D takes its id at accept, its first frame after the application's
 * greeting), and a RESET on the control lane after a later id's data */
static int peer_id_new(npf_tunnel *t, uint32_t id)
{
    uint32_t k;
    if (id > t->peer_max_seen) {
        if (t->peer_max_seen) {
            k = (id - t->peer_max_seen) / 2;        /* the old largest: bit k - 1 */
            seen_shift(t->peer_seen, k);
            if (k - 1 < SEEN_BITS)
                t->peer_seen[(k - 1) / 64] |= 1ULL << ((k - 1) % 64);
        }
        t->peer_max_seen = id;
        return 1;
    }
    if (id == t->peer_max_seen || (k = (t->peer_max_seen - id) / 2 - 1) >= SEEN_BITS
        || (t->peer_seen[k / 64] >> (k % 64) & 1))
        return 0;
    t->peer_seen[k / 64] |= 1ULL << (k % 64);
    return 1;
}

/* a DATA frame of the sublink: into the SOCKS parse while it greets, the
 * server's replies while it waits for them, else to the local end (what it
 * cannot take now queued); a protocol error resets it */
static void data_in(sublink *s, const uint8_t *p, size_t n)
{
    /* the peer may not exceed the window we granted: everything received
     * and not yet given back (buffered, or consumed but not yet in a WINDOW) */
    if (n == 0 || s->peer_fin || s->wq.len + (s->server ? s->sl : 0) + s->rx_freed + n > s->rx_window) {
        tunnel_sub_reset(s, NPF_RST_PROTOCOL);
        return;
    }
    if (s->gone)
        return;   /* its local end closed: dropped, no credit back (the peer's window runs out) */
    if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
        /* into the parse buffer what fits (a greeting and a request are
         * 519 bytes at most); data pipelined after the request, in this
         * frame or later ones, is queued until the target is connected */
        size_t take = n < sizeof s->sb - s->sl ? n : sizeof s->sb - s->sl;
        memcpy(s->sb + s->sl, p, take);
        s->sl += take;
        if (tunnel_socks_parse(s) < 0)
            return;           /* released */
        if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
            if (s->sl == sizeof s->sb)      /* full and still no request: not SOCKS5 */
                tunnel_sub_reset(s, NPF_RST_PROTOCOL);
            return;
        }
        if (take < n && tunnel_wb_put(&s->wq, p + take, n - take) < 0)
            tunnel_sub_reset(s, NPF_RST_LIMIT);
        return;
    }
    if (s->state == SL_CLIENT_WAIT) {
        size_t drop;
        int r = tunnel_client_reply(s, p, n, &drop);
        if (r < 0) {
            if (!s->end)
                s->end = "target_failed";   /* the other side could not reach the target */
            tunnel_sub_reset(s, r == -2 ? NPF_RST_PROTOCOL : NPF_RST_LOCAL);
            return;
        }
        tunnel_credit_back(s, drop);    /* the replies' own bytes: the rest is credited as written */
        p += drop;
        n -= drop;
        if (n == 0) {
            tunnel_update_ev(s);
            return;
        }
    }
    if ((s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) && s->wq.len == 0) {
        /* nothing queued: straight from the frame to the local end, only
         * what it cannot take now is queued (one copy less) */
        size_t done = 0;
        while (done < n) {
            ssize_t w = local_write(s, p + done, n - done);
            if (w < 0) {
                tunnel_sub_reset(s, NPF_RST_LOCAL);
                return;
            }
            if (w == 0)
                break;
            done += (size_t)w;
        }
        if (done < n && tunnel_wb_put(&s->wq, p + done, n - done) < 0) {
            tunnel_sub_reset(s, NPF_RST_LIMIT);
            return;
        }
        if (done)
            tunnel_credit_back(s, done); /* after queueing the rest: the window grows only if all went */
        tunnel_update_ev(s);
        return;
    }
    if (tunnel_wb_put(&s->wq, p, n) < 0) {
        tunnel_sub_reset(s, NPF_RST_LIMIT);
        return;
    }
    if ((s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) && tunnel_flush_local(s) < 0) {
        tunnel_sub_reset(s, NPF_RST_LOCAL);
        return;
    }
    tunnel_update_ev(s);
}

static int handle_frame(npf_tunnel *t, uint32_t id, int type, const uint8_t *p, size_t n)
{
    sublink *s;
    if (id == 0)
        return -1;                  /* not a sublink */
    /* the channels are independent: a sublink's first data can come before
     * the peer's hello, but never before ours (the callee starts first, the
     * caller opens sublinks only after it) */
    if (!t->hello_sent)
        return -1;
    s = tunnel_find(t, id);
    if (!s) {
        int peer_opened = t->caller ? (id % 2 == 0) : (id % 2 == 1);
        if (type == FR_RESET && peer_opened) {
            /* reset on the fast lane before its first data arrived: that
             * data is late now (ids are never reused) */
            peer_id_new(t, id);
            return 0;
        }
        if (type != FR_DATA)
            return 0;               /* late frame of a released sublink */
        if (!peer_opened || !peer_id_new(t, id))
            return 0;
        if (t->caller && t->nrev == 0) {
            send_reset(t, id, NPF_RST_PROTOCOL);   /* no reverse mapping registered */
            return 0;
        }
        if (t->nsubs >= NPF_MAX_SUBLINKS
            || !shared_room(t, 1, NPF_INIT_WINDOW)) {
            send_reset(t, id, NPF_RST_LIMIT);   /* this session's, or the node's over all sessions */
            return 0;
        }
        s = sub_new(t, id, -1, 1);
        if (!s)
            return -1;
        s->state = SL_SOCKS_GREETING;
        tunnel_greet_wait(s);
    }
    switch (type) {
    case FR_DATA:
        data_in(s, p, n);
        return 0;
    case FR_FIN:
        if (!s->local_eof && !s->fin_first)
            s->fin_first = 2;
        s->peer_fin = 1;
        if (s->state == SL_CLIENT_WAIT && !s->end)
            s->end = "target_failed";       /* the replies cut short: the target was not reached */
        if (s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) {
            if (tunnel_flush_local(s) < 0) {
                tunnel_sub_reset(s, NPF_RST_LOCAL);
                return 0;
            }
            tunnel_update_ev(s);
            maybe_done(s);
        } else if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
            /* closed before its request was complete: refused, and the peer
             * told (freed quietly, its end waited for replies for good) */
            tunnel_sub_reset(s, NPF_RST_PROTOCOL);
        }
        /* resolving or connecting: kept, the target's write side is shut
         * once connected (nc -z through a name: both ends then end) */
        return 0;
    case FR_RESET:
        if (!s->end)                        /* (a refusal seen in a reply stays the reason) */
            s->end = s->state == SL_CLIENT_WAIT ? "target_failed" : "peer_reset";
        tunnel_sub_free(s, 1);
        return 0;
    case FR_WINDOW:
        if (n != 4)
            goto proto;
        s->tx_credit += npf_rd32(p);
        tunnel_update_ev(s);
        return 0;
    default:
        return 0;                   /* unknown types are skipped */
    }
proto:
    tunnel_sub_reset(s, NPF_RST_PROTOCOL);
    return 0;
}

static int broken(npf_tunnel *t, const char *why)
{
    t->dead = 1;
    if (t->io.broken)
        t->io.broken(t->arg, why);
    return -1;
}

static int input_data(npf_tunnel *t, const uint8_t *msg, size_t len)
{
    if (len < NPF_DATA_HDR || len > NPF_DATA_HDR + NPF_FRAME_MAX)
        return broken(t, "bad data message");
    if (handle_frame(t, npf_rd32(msg), len == NPF_DATA_HDR ? FR_FIN : FR_DATA, msg + NPF_DATA_HDR,
                     len - NPF_DATA_HDR) < 0)
        return broken(t, "protocol error");
    return 0;
}

int npf_tunnel_input_data(npf_tunnel *t, const uint8_t *msg, size_t len)
{
    int r;
    if (t->dead)
        return -1;
    t->depth++;
    r = input_data(t, msg, len);
    return tunnel_leave(t) ? -1 : r;
}

static int handle_unit(npf_tunnel *t, int type, const uint8_t *p, size_t n)
{
    switch (type) {
    case NPF_CU_JSON:
        return handle_control(t, p, n);
    case NPF_CU_WINDOW:
        return n == 8 ? handle_frame(t, npf_rd32(p), FR_WINDOW, p + 4, 4) : -1;
    case NPF_CU_RESET:
        return n == 5 ? handle_frame(t, npf_rd32(p), FR_RESET, p + 4, 1) : -1;
    case NPF_CU_APP:
    case NPF_CU_MEDIA:
    case NPF_CU_UDP:
        if (t->io.unit)
            t->io.unit(t->arg, type, p, n);
        return 0;
    default:
        return 0;                   /* unknown units are skipped */
    }
}

static int input_ctrl(npf_tunnel *t, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    if (t->rl + len > t->rcap) {
        size_t c = t->rcap ? t->rcap : 65536;
        uint8_t *q;
        while (c < t->rl + len)
            c *= 2;
        q = realloc(t->rb, c);
        if (!q)
            return -1;
        t->rb = q;
        t->rcap = c;
    }
    memcpy(t->rb + t->rl, buf, len);
    t->rl += len;
    while (t->rl - off >= NPF_CU_HDR) {
        uint8_t *h = t->rb + off;
        size_t n = npf_rd16(h + 1);
        if (n > NPF_CTRL_MAX)
            return broken(t, "oversized control unit");
        if (t->rl - off < NPF_CU_HDR + n)
            break;
        if (handle_unit(t, h[0], h + NPF_CU_HDR, n) < 0)
            return broken(t, "protocol error");
        if (t->dead)
            return -1;
        off += NPF_CU_HDR + n;
    }
    if (off) {
        memmove(t->rb, t->rb + off, t->rl - off);
        t->rl -= off;
    }
    return 0;
}

int npf_tunnel_input_ctrl(npf_tunnel *t, const uint8_t *buf, size_t len)
{
    int r;
    if (t->dead)
        return -1;
    t->depth++;
    r = input_ctrl(t, buf, len);
    return tunnel_leave(t) ? -1 : r;
}

/* ---- local sockets ---- */

/* -D: the application's SOCKS5 greeting is answered here at once ("no
 * authentication"); the server gets a greeting of its own with what the
 * application sends next (its request), pipelined, and its method reply is
 * dropped when it comes. The application's request goes after one round
 * trip to the peer instead of two (data-channel.md 7). */
static void local_greeting(sublink *s)
{
    uint8_t g[3] = {5, 1, 0};
    size_t need, i;
    int ok = 0;
    ssize_t r = recv(s->fd, s->sb + s->sl, sizeof s->sb - s->sl, MSG_DONTWAIT);
    if (r <= 0) {
        if (r < 0 && npf_sock_again())
            return;
        tunnel_sub_free(s, 0);              /* gone before its greeting: nothing went to the peer */
        return;
    }
    s->sl += (size_t)r;
    if (s->sl < 2)
        return;
    if (s->sb[0] != 5) {
        tunnel_sub_free(s, 1);
        return;
    }
    need = 2 + (size_t)s->sb[1];
    if (s->sl < need)
        return;
    for (i = 2; i < need; i++)
        if (s->sb[i] == 0)
            ok = 1;
    if (send(s->fd, ok ? "\x05\x00" : "\x05\xff", 2, MSG_NOSIGNAL | MSG_DONTWAIT) != 2 || !ok) {
        tunnel_sub_free(s, 0);              /* no method we offer: the application closes */
        return;
    }
    /* the server's greeting, then whatever the application already sent */
    if (tunnel_send_frame(s->t, s->id, FR_DATA, g, 3) < 0)
        return;
    s->tx_credit -= 3;
    if (s->sl > need) {
        if (tunnel_send_frame(s->t, s->id, FR_DATA, s->sb + need, s->sl - need) < 0)
            return;
        s->tx_credit -= (int64_t)(s->sl - need);
    }
    s->sl = 0;
    s->fwd_rep = 1;                     /* the server's replies: its CONNECT reply is the application's */
    s->state = SL_CLIENT_WAIT;
    tunnel_greet_done(s);
    tunnel_update_ev(s);
}

static void io_cb_in(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    int was_paused = t->paused;
    (void)loop;
    (void)fd;
    if (ev & NPF_EV_WRITE) {
        if (tunnel_flush_local(s) < 0) {
            tunnel_sub_reset(s, NPF_RST_LOCAL);
            return;
        }
        if (maybe_done(s))
            return;
    }
    if (s->state == SL_LOCAL_GREETING) {
        local_greeting(s);                  /* may release s */
        return;
    }
    if ((ev & NPF_EV_READ) && !s->local_eof && s->tx_credit > 0 && !t->paused) {
        size_t want = tunnel_rate_allow(s, 1, s->tx_credit < NPF_FRAME_MAX ? (size_t)s->tx_credit : NPF_FRAME_MAX);
        uint8_t *m = want ? npf_scratch(NPF_DATA_HDR + NPF_FRAME_MAX) : NULL;    /* received in place */
        ssize_t r = !m ? -1 : s->v ? s->v->read(s->varg, m + NPF_DATA_HDR, want)
                                   : recv(s->fd, m + NPF_DATA_HDR, want, MSG_DONTWAIT);
        if (want == 0) {
            tunnel_update_ev(s);        /* the rate group's share is used up */
            return;
        }
        if (!m)
            return;
        if (r > 0) {
            tunnel_rate_take(s, 1, (size_t)r);
            t->local_in += (uint64_t)r;
            s->in += (uint64_t)r;
        }
        if (r > 0) {
            int w = send_data(t, s->id, m, (size_t)r);
            npf_scratch_done(m);
            if (w < 0) {                /* the bytes read are lost: the stream cannot go on */
                if (!s->end)
                    s->end = "session_ended";   /* the transport is broken: the session goes */
                tunnel_sub_reset(s, NPF_RST_TRANSPORT);
                return;
            }
            s->tx_credit -= r;
            if (t->io.backlog(t->arg) > BACKLOG_PAUSE)
                t->paused = 1;
        } else if (r == 0) {
            npf_scratch_done(m);
            if (!s->peer_fin && !s->fin_first)
                s->fin_first = 1;
            s->local_eof = 1;
            tunnel_send_frame(t, s->id, FR_FIN, NULL, 0);
            if (maybe_done(s))
                return;
        } else {
            int again = s->v || npf_sock_again();     /* a virtual end: -1 is "none now" */
            npf_scratch_done(m);
            if (!again) {
                tunnel_sub_reset(s, NPF_RST_LOCAL);
                return;
            }
        }
    }
    if (t->paused && !was_paused) {     /* paused just now: no sublink reads (once, not at each event) */
        int i;
        for (i = 0; i < t->nsubs; i++)
            tunnel_update_ev(t->subs[i]);
    } else {
        tunnel_update_ev(s);
    }
}

/* a local socket's event: the transport's write may free the tunnel */
void tunnel_io_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_tunnel *t = ((sublink *)arg)->t;
    t->depth++;
    io_cb_in(loop, fd, ev, arg);
    tunnel_leave(t);
}

void npf_tunnel_kick(npf_tunnel *t)
{
    int i;
    if (!t->paused || t->io.backlog(t->arg) > BACKLOG_PAUSE / 2)
        return;
    t->paused = 0;
    for (i = 0; i < t->nsubs; i++)
        tunnel_update_ev(t->subs[i]);
}

/* ---- public ---- */

npf_tunnel *npf_tunnel_new(npf_loop *loop, int caller, const npf_tunnel_io *io, void *arg, npf_policy *policy)
{
    npf_tunnel *t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->loop = loop;
    t->caller = caller;
    t->io = *io;
    t->arg = arg;
    t->policy = policy;
    t->next_id = caller ? 1 : 2;
    t->peer_window = NPF_INIT_WINDOW;
    return t;
}

void npf_tunnel_set_budget(npf_tunnel *t, npf_budget *b)
{
    t->budget = b;
}

void npf_tunnel_set_shared(npf_tunnel *t, npf_tunnel_shared *node, npf_tunnel_shared *key)
{
    t->shared[0] = node;
    t->shared[1] = key;
}

void npf_tunnel_local_bytes(const npf_tunnel *t, uint64_t *in, uint64_t *out)
{
    *in = t->local_in;
    *out = t->local_out;
}


int npf_tunnel_sub_bytes(npf_tunnel *t, uint32_t id, uint64_t *in, uint64_t *out)
{
    sublink *s = tunnel_find(t, id);
    if (!s)
        return -1;
    *in = s->in;
    *out = s->out;
    return 0;
}

int npf_tunnel_sub_reset(npf_tunnel *t, uint32_t id, const char *why)
{
    sublink *s = tunnel_find(t, id);
    if (!s)
        return -1;
    t->depth++;                             /* sublink_done may free the tunnel */
    s->end = why;
    tunnel_sub_reset(s, NPF_RST_LOCAL);
    tunnel_leave(t);
    return 0;
}

/* the tunnel's memory, once nothing runs on it any more */
static void tunnel_release(npf_tunnel *t)
{
    free(t->subs);
    free(t->ids);
    free(t->rb);
    free(t);
}

/* the sublinks, then the tunnel; a free asked for by one of the callbacks
 * this calls (closed, sublink_done) changes nothing */
static void tunnel_destroy(npf_tunnel *t)
{
    t->depth++;
    if (t->t_rate)
        npf_timer_cancel(t->loop, t->t_rate);
    t->t_rate = NULL;
    if (t->t_virt)
        npf_timer_cancel(t->loop, t->t_virt);
    t->t_virt = NULL;
    t->dead = 1;
    while (t->nsubs) {
        sublink *s = t->subs[t->nsubs - 1];
        if (!s->end)
            s->end = "session_ended";
        tunnel_sub_free(s, 1);
    }
    tunnel_release(t);
}

/* the end of a call into the tunnel that may have called out: 1 when the
 * tunnel was freed meanwhile (it is gone now) */
int tunnel_leave(npf_tunnel *t)
{
    if (--t->depth || !t->free_later)
        return 0;
    tunnel_destroy(t);
    return 1;
}

/* from inside one of our calls (a transport's write, a local end's call, a
 * sublink_done), the end of that call frees it: the sublinks the call still
 * uses stay till then; nothing more goes to the transport from now on */
void npf_tunnel_free(npf_tunnel *t)
{
    if (!t)
        return;
    t->dead = 1;
    if (t->depth) {
        t->free_later = 1;
        return;
    }
    tunnel_destroy(t);
}


int npf_tunnel_control(npf_tunnel *t, const char *json, size_t len)
{
    return send_ctrl(t, NPF_CU_JSON, json, len);
}

int npf_tunnel_unit_send(npf_tunnel *t, int type, const void *buf, size_t len)
{
    if (!npf_tunnel_is_ready(t) || (type != NPF_CU_APP && type != NPF_CU_MEDIA && type != NPF_CU_UDP))
        return -1;
    return send_ctrl(t, type, buf, len);
}

void npf_tunnel_start(npf_tunnel *t)
{
    char buf[160];
    int n = snprintf(buf, sizeof buf,
                     "{\"v\":2,\"type\":\"hello\",\"data\":{\"init_window\":%d,\"max_sublinks\":%d%s}}",
                     NPF_INIT_WINDOW, NPF_MAX_SUBLINKS, t->caller ? "" : ",\"socks\":[\"connect\"]");
    if (t->hello_sent)
        return;
    t->hello_sent = 1;
    npf_tunnel_control(t, buf, (size_t)n);
    if (t->hello_recv && t->io.ready)
        t->io.ready(t->arg);
}

int npf_tunnel_is_ready(const npf_tunnel *t)
{
    return t->hello_sent && t->hello_recv && !t->dead;
}

void npf_tunnel_dump(const npf_tunnel *t)
{
    int i;
    fprintf(stderr, "  tunnel: caller=%d subs=%d paused=%d backlog=%zu peer_window=%u rbuf=%zu\n", t->caller,
            t->nsubs, t->paused, t->io.backlog(t->arg), t->peer_window, t->rl);
    for (i = 0; i < t->nsubs; i++) {
        const sublink *s = t->subs[i];
        fprintf(stderr, "    sub %u fd=%d state=%d credit=%lld rx_freed=%u wq=%zu sl=%zu eof=%d fin=%d shut=%d ev=%u\n",
                s->id, s->fd, s->state, (long long)s->tx_credit, s->rx_freed, s->wq.len, s->sl, s->local_eof,
                s->peer_fin, s->shut_wr, s->ev);
    }
}

int npf_tunnel_rev_add(npf_tunnel *t, uint32_t listen_id, const char *host, uint16_t port)
{
    if (t->nrev >= NPF_MAX_REVERSE || strlen(host) >= sizeof t->rev[0].host)
        return -1;
    t->rev[t->nrev].id = listen_id;
    strcpy(t->rev[t->nrev].host, host);
    t->rev[t->nrev].port = port;
    t->nrev++;
    return 0;
}

void npf_tunnel_rev_del(npf_tunnel *t, uint32_t listen_id)
{
    int i;
    for (i = 0; i < t->nrev; i++)
        if (t->rev[i].id == listen_id) {
            t->rev[i] = t->rev[--t->nrev];
            return;
        }
}

int npf_tunnel_count(const npf_tunnel *t)
{
    return t->nsubs;
}

int npf_tunnel_open(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port)
{
    return npf_tunnel_open_rated(t, fd, passthrough, host, port, 0, 0);
}

static int open_sub(npf_tunnel *t, int fd, const npf_vend_io *v, void *varg, int passthrough, const char *host,
                    uint16_t port, uint32_t group, uint32_t rate);

int npf_tunnel_open_rated(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                          uint32_t rate)
{
    return open_sub(t, fd, NULL, NULL, passthrough, host, port, group, rate);
}

int npf_tunnel_open_v(npf_tunnel *t, const npf_vend_io *v, void *varg, const char *host, uint16_t port)
{
    return open_sub(t, -1, v, varg, 0, host, port, 0, 0);
}

/* a port mapping's greeting and CONNECT, pipelined; -1 for a host that
 * cannot be one */
static int socks_request(const char *host, uint16_t port, uint8_t req[300], size_t *len)
{
    size_t hl = strlen(host), n = 0;
    struct in_addr a4;
    struct in6_addr a6;
    req[n++] = 5; req[n++] = 1; req[n++] = 0;          /* greeting: no authentication */
    req[n++] = 5; req[n++] = 1; req[n++] = 0;          /* CONNECT, pipelined */
    if (inet_pton(AF_INET, host, &a4) == 1) {
        req[n++] = 1;
        memcpy(req + n, &a4, 4);
        n += 4;
    } else if (inet_pton(AF_INET6, host, &a6) == 1) {
        req[n++] = 4;
        memcpy(req + n, &a6, 16);
        n += 16;
    } else {
        if (hl == 0 || hl > 255)
            return -1;
        req[n++] = 3;
        req[n++] = (uint8_t)hl;
        memcpy(req + n, host, hl);
        n += hl;
    }
    req[n++] = (uint8_t)(port >> 8);
    req[n++] = (uint8_t)port;
    *len = n;
    return 0;
}

static int open_sub(npf_tunnel *t, int fd, const npf_vend_io *v, void *varg, int passthrough, const char *host,
                    uint16_t port, uint32_t group, uint32_t rate)
{
    sublink *s;
    rgroup *g = NULL;
    uint8_t req[300];
    size_t rl = 0;
    int i;
    if (!npf_tunnel_is_ready(t) || t->nsubs >= t->peer_max || t->next_id > 0x7ffffff0u)
        return -1;
    /* checked first: on -1 the caller keeps its local end (a bad host freed
     * the sublink, closing the fd the caller then closed again) */
    if (!passthrough && socks_request(host, port, req, &rl) < 0)
        return -1;
    if (group) {                            /* rate 0: counted (npf_tunnel_group_count), not limited */
        for (i = 0; i < t->nrg && !g; i++)
            if (t->rg[i].id == group)
                g = &t->rg[i];
        for (i = 0; i < t->nrg && !g; i++)
            if (!t->rg[i].id)
                g = &t->rg[i];              /* a place a closed group left */
        if (!g) {
            if (t->nrg == NPF_RATE_GROUPS)
                return -1;
            g = &t->rg[t->nrg++];
        }
        if (!g->id) {
            g->id = group;
            g->up = g->down = rate;
            g->at_ms = npf_mono_ms();
        }
        g->rate = rate;                 /* the mapping's current rate */
    }
    if (fd >= 0) {
        int one = 1;
        npf_set_nonblock(fd);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    s = sub_new(t, t->next_id, fd, 0);
    if (!s)
        return -1;
    s->rg = g;
    s->v = v;
    s->varg = varg;
    s->t_open = npf_mono_ms();
    t->next_id += 2;
    if (passthrough) {
        s->state = SL_LOCAL_GREETING;       /* -D: a SOCKS5 application */
        tunnel_greet_wait(s);
    } else {
        tunnel_send_frame(t, s->id, FR_DATA, req, rl);
        s->tx_credit -= (int64_t)rl;
        s->state = SL_CLIENT_WAIT;
    }
    tunnel_update_ev(s);
    return (int)s->id;
}

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
#include "npf/resolve.h"
#include "npf/tunnel.h"

#define BACKLOG_PAUSE  (1024 * 1024)    /* transport bytes queued before local reads pause */
#define SOCKS_BUF      600
#define CONNECT_MS     10000
#define HE_DELAY_MS    250      /* Happy Eyeballs (RFC 8305): the next address after this long without an answer */
#define GREET_MS       10000    /* a peer-opened sublink's SOCKS greeting and request, at most this long */
#define RESOLVING_MAX  16       /* lookups of one tunnel at once: one peer cannot take the whole resolver */

enum {
    SL_SOCKS_GREETING,      /* server: waiting for the greeting */
    SL_SOCKS_REQUEST,       /* server: waiting for the request */
    SL_RESOLVING,           /* server: the target name is being resolved (worker thread) */
    SL_CONNECTING,          /* server: connecting to the target */
    SL_OPEN,
    SL_CLIENT_WAIT,         /* client (port mapping): waiting for the two replies */
    SL_LOCAL_GREETING,      /* client (-D): the local application's greeting, answered here */
};

/* bytes for the local end: p[off .. off+len) (written from the front
 * without moving the rest; moved down only when the space runs out) */
typedef struct wbuf {
    uint8_t *p;
    size_t   off, len, cap;
} wbuf;

/* a rate group: token buckets (1 s of burst) for each direction */
typedef struct rgroup {
    uint32_t id, rate;
    int64_t  up, down;          /* tokens: bytes we may read from / write to the local sockets */
    int64_t  at_ms;             /* last refill */
} rgroup;

typedef struct sublink {
    npf_tunnel *t;
    uint32_t id;
    int      fd;
    int      state;
    int      server;            /* we run the SOCKS5 server for this sublink */
    uint8_t  sb[SOCKS_BUF];     /* SOCKS bytes being parsed / replies being stripped */
    size_t   sl;
    size_t   strip;             /* client: reply bytes still to strip (0 = unknown yet) */
    int      skip_method;       /* client (-D): bytes of the server's method reply still to drop */
    int      socks_rep;         /* client (-D): its CONNECT reply not seen yet (REP 2: the policy) */
    int64_t  tx_credit;         /* DATA bytes we may still send */
    uint32_t rx_freed;          /* written locally since the last WINDOW */
    uint32_t rx_window;
    wbuf     wq;                /* to be written to the local socket */
    int      local_eof;         /* local read side ended, FIN sent */
    int      peer_fin;          /* FIN received */
    int      shut_wr;           /* local write side shut down */
    unsigned ev;                /* registered events */
    int      reverse;           /* caller side of a reverse mapping: target checked against rev[] */
    npf_timer *t_connect;
    npf_timer *t_greet;         /* the SOCKS greeting and request still to come (GREET_MS) */
    npf_timer *t_he;            /* SL_CONNECTING: the next address's turn (HE_DELAY_MS) */
    int      cfd[NPF_RESOLVE_MAX];  /* SL_CONNECTING: the attempts under way (the winner becomes fd) */
    int      ncfd;
    int      last_err;          /* SL_CONNECTING: the last attempt's error */
    struct rgroup *rg;          /* its rate group, NULL: none */
    uint64_t in, out;           /* read from / written to its local socket */
    npf_resolve *resolve;       /* SL_RESOLVING: the pending lookup */
    struct sockaddr_storage *cand;  /* SL_CONNECTING: a name's addresses still to try (malloc) */
    socklen_t clen[NPF_RESOLVE_MAX];
    int      ncand, icand;
    /* opened here: for its record (npf_sublink_stats) */
    int64_t  t_open, t_ok, t_first;     /* mono ms: opened, CONNECT reply, first byte to the local socket */
    int      fin_first;                 /* 1: the local side closed first, 2: the peer */
    const char *end;                    /* why it ended, when not by FIN (npf_sublink_stats.end) */
    const npf_vend_io *v;               /* a virtual local end (npf_tunnel_open_v), fd -1; NULL: none */
    void    *varg;
} sublink;

struct npf_tunnel {
    npf_loop   *loop;
    int         caller;
    npf_tunnel_io io;
    void       *arg;
    npf_policy *policy;
    /* the sublinks: ids[i] is subs[i]'s, looked up by a scan of ids (a few
     * hundred at most: one cache line per 16), the last one found first */
    sublink   **subs;
    uint32_t   *ids;
    int         nsubs, cap, last;
    uint32_t    next_id;
    uint32_t    peer_max_seen;  /* largest peer-opened id */
    uint8_t    *rb;             /* frame reassembly */
    size_t      rl, rcap;
    int         hello_sent, hello_recv;
    uint32_t    peer_window;
    int         peer_max;
    int         paused;
    int         dead;
    rgroup      rg[NPF_RATE_GROUPS];
    int         nrg;
    npf_budget *budget;         /* NULL: none */
    uint64_t    local_in, local_out;    /* read from / written to the local sockets */
    npf_timer  *t_rate;         /* a group ran dry: look again soon */
    /* caller: targets registered for reverse mapping (data-channel.md 7.1) */
    struct { uint32_t id; char host[256]; uint16_t port; } rev[NPF_MAX_REVERSE];
    int         nrev;
    npf_timer  *t_virt;         /* virtual local ends to look at (virt_poll) */
    int         in_poll;        /* virt_poll runs: npf_tunnel_free waits for its end */
    int         free_later;
};

/* ---- helpers ---- */

void npf_tunnel_dump(const npf_tunnel *t);

static int wb_put(wbuf *b, const void *p, size_t n)
{
    if (b->off && b->off + b->len + n > b->cap) {
        memmove(b->p, b->p + b->off, b->len);   /* the room written out at the front, once */
        b->off = 0;
    }
    if (b->len + n > b->cap) {
        size_t c = b->cap ? b->cap : 16384;
        uint8_t *q;
        while (c < b->len + n)
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

enum { FR_DATA = 1, FR_FIN = 2, FR_RESET = 3, FR_WINDOW = 4 };   /* what handle_frame acts on */

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
static int send_frame(npf_tunnel *t, uint32_t id, int type, const void *payload, size_t len)
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
    send_frame(t, id, FR_RESET, &r, 1);
}

static sublink *find(npf_tunnel *t, uint32_t id)
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

static void io_cb(npf_loop *loop, int fd, unsigned ev, void *arg);
static void update_ev(sublink *s);

#define RATE_TICK_MS 50

static void rg_refill(rgroup *g)
{
    int64_t now = npf_mono_ms(), add;
    if (now <= g->at_ms)
        return;
    add = (now - g->at_ms) * (int64_t)g->rate / 1000;
    if (add <= 0)
        return;
    g->at_ms = now;
    g->up = g->up + add > (int64_t)g->rate ? (int64_t)g->rate : g->up + add;
    g->down = g->down + add > (int64_t)g->rate ? (int64_t)g->rate : g->down + add;
}

static void rate_tick(npf_loop *loop, void *arg)
{
    npf_tunnel *t = arg;
    int i;
    (void)loop;
    t->t_rate = NULL;
    for (i = 0; i < t->nrg; i++)
        rg_refill(&t->rg[i]);
    for (i = 0; i < t->nsubs; i++)
        if (t->subs[i]->rg || t->budget)
            update_ev(t->subs[i]);
}

/* a group ran dry: its sublinks wait for the next tick */
static void rate_wait(npf_tunnel *t)
{
    if (!t->t_rate)
        t->t_rate = npf_timer_add(t->loop, RATE_TICK_MS, rate_tick, t);
}

/* the budget's slow bucket (none left): one second of burst */
static void budget_refill(npf_budget *b)
{
    int64_t now = npf_mono_ms();
    if (b->at_ms == 0 || b->tokens > b->slow) {
        b->tokens = b->slow;
        b->at_ms = now;
    }
    b->tokens += (double)(now - b->at_ms) * b->slow / 1000;
    if (b->tokens > b->slow)
        b->tokens = b->slow;
    b->at_ms = now;
}

/* bytes the sublink may move now (up: local -> tunnel), at most want */
static size_t rate_allow(sublink *s, int up, size_t want)
{
    npf_budget *b = s->t->budget;
    if (s->rg && s->rg->rate) {
        int64_t *tok;
        rg_refill(s->rg);
        tok = up ? &s->rg->up : &s->rg->down;
        if (*tok <= 0) {
            rate_wait(s->t);
            return 0;
        }
        if ((int64_t)want > *tok)
            want = (size_t)*tok;
    }
    if (b && b->left <= 0) {                /* the quota is used up: the slow speed */
        budget_refill(b);
        if (b->tokens < 1) {
            rate_wait(s->t);
            return 0;
        }
        if ((double)want > b->tokens)
            want = (size_t)b->tokens;
    } else if (b && (int64_t)want > b->left) {
        want = (size_t)b->left;
    }
    return want;
}

static void rate_take(sublink *s, int up, size_t n)
{
    npf_budget *b = s->t->budget;
    if (s->rg && s->rg->rate)
        *(up ? &s->rg->up : &s->rg->down) -= (int64_t)n;
    if (b) {
        if (b->idle && b->wake) {
            b->idle = 0;
            b->wake(b->wake_arg);
        }
        if (b->left > 0)
            b->left -= (int64_t)n;
        else
            b->tokens -= (double)n;
    }
}

static void virt_arm(npf_tunnel *t);

static void update_ev(sublink *s)
{
    npf_tunnel *t = s->t;
    unsigned ev = 0;
    if (s->fd < 0 && !s->v)
        return;
    if (s->state == SL_LOCAL_GREETING) {
        ev = NPF_EV_READ;
    } else if (s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) {
        if (!s->local_eof && s->tx_credit > 0 && !t->paused && rate_allow(s, 1, 1))
            ev |= NPF_EV_READ;
        if (s->wq.len && rate_allow(s, 0, 1))
            ev |= NPF_EV_WRITE;
    }
    if (s->v) {                     /* no socket: virt_poll asks the local end */
        s->ev = ev;
        if (ev & s->v->ready(s->varg))
            virt_arm(t);
        return;
    }
    if (ev != s->ev) {
        if (s->ev == 0 && ev)
            npf_loop_add(t->loop, s->fd, ev, io_cb, s);
        else if (ev == 0)
            npf_loop_del(t->loop, s->fd);
        else
            npf_loop_mod(t->loop, s->fd, ev);
        s->ev = ev;
    }
}

static void sub_free(sublink *s, int rst)
{
    npf_tunnel *t = s->t;
    int i;
    if (!s->server && !s->reverse && t->io.sublink_done) { /* one we opened (npf_tunnel_open) ends */
        npf_sublink_stats st;
        st.in = s->in;
        st.out = s->out;
        st.connect_ms = s->t_ok ? (int)(s->t_ok - s->t_open) : -1;
        st.first_byte_ms = s->t_first ? (int)(s->t_first - s->t_open) : -1;
        st.end = s->end ? s->end : !rst && s->fin_first == 2 ? "peer_closed" : !rst ? "local_closed" : "local_reset";
        t->io.sublink_done(t->arg, s->id, &st);
    }
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

static void sub_reset(sublink *s, int reason)
{
    send_reset(s->t, s->id, reason);
    sub_free(s, 1);
}

/* release once both directions are finished */
static void maybe_done(sublink *s)
{
    if (s->local_eof && s->peer_fin && s->wq.len == 0 && s->shut_wr)
        sub_free(s, 0);
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
    t->subs[t->nsubs] = s;
    t->ids[t->nsubs] = id;
    t->nsubs++;
    return s;
}

/* Data written to the local socket frees receive window. The window grows
 * while the local side keeps up (nothing left queued when a quarter of the
 * window has been consumed), doubling up to NPF_MAX_WINDOW: one sublink's
 * throughput is about window / RTT (data-channel.md 6). */
static void credit_back(sublink *s, size_t n)
{
    s->rx_freed += (uint32_t)n;
    if (s->rx_freed >= s->rx_window / 4) {
        uint8_t inc[4];
        uint32_t grant = s->rx_freed;
        if (s->wq.len == 0 && s->rx_window < NPF_MAX_WINDOW) {
            grant += s->rx_window;          /* the extra half becomes permanent window */
            s->rx_window *= 2;
        }
        npf_le32(inc, grant);
        send_frame(s->t, s->id, FR_WINDOW, inc, 4);
        s->rx_freed = 0;
    }
}

/* one write to the local end: the bytes it took, 0 none now (full, or the
 * rate group's share used up: the window holds the peer), -1 an error */
static ssize_t local_write(sublink *s, const uint8_t *p, size_t len)
{
    size_t n = rate_allow(s, 0, len);
    ssize_t w;
    if (n == 0)
        return 0;
    if (s->v) {
        if ((w = s->v->write(s->varg, p, n)) < 0)
            return -1;
    } else if ((w = send(s->fd, p, n, MSG_NOSIGNAL | MSG_DONTWAIT)) < 0) {
        return npf_sock_again() ? 0 : -1;
    }
    if (w > 0) {
        rate_take(s, 0, (size_t)w);
        s->t->local_out += (uint64_t)w;
        if (!s->out)
            s->t_first = npf_mono_ms();
        s->out += (uint64_t)w;
    }
    return w;
}

static int flush_local(sublink *s)
{
    while (s->wq.len) {
        ssize_t w = local_write(s, s->wq.p + s->wq.off, s->wq.len);
        if (w < 0)
            return -1;
        if (w == 0)
            break;
        wb_take(&s->wq, (size_t)w);
        credit_back(s, (size_t)w);
    }
    if (s->wq.len == 0 && s->peer_fin && !s->shut_wr) {
        if (s->v)
            s->v->shutdown(s->varg);
        else
            shutdown(s->fd, SHUT_WR);
        s->shut_wr = 1;
    }
    return 0;
}

/* ---- SOCKS5 server side (data-channel.md 7) ---- */

static void socks_reply(sublink *s, uint8_t rep)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};    /* BND = 0.0.0.0:0 */
    send_frame(s->t, s->id, FR_DATA, r, sizeof r);
    s->tx_credit -= sizeof r;
}

static void socks_fail(sublink *s, uint8_t rep)
{
    socks_reply(s, rep);
    send_frame(s->t, s->id, FR_FIN, NULL, 0);
    sub_free(s, 0);
}

static void connect_timeout(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    (void)loop;
    s->t_connect = NULL;
    socks_fail(s, 6);
}

static int map_errno(int e)
{
    switch (e) {
    case ECONNREFUSED: return 5;
    case ENETUNREACH: return 3;
    case EHOSTUNREACH: return 4;
    case ETIMEDOUT: return 6;
    default: return 1;
    }
}

int npf_tunnel_he_ms = HE_DELAY_MS;
int npf_tunnel_greet_ms = GREET_MS;
int (*npf_tunnel_test_resolve)(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens,
                               int max);

/* RFC 8305 4: the families taken in turns, the first address's first, each
 * family's own order kept */
void npf_he_order(struct sockaddr_storage *a, socklen_t *l, int n)
{
    struct sockaddr_storage ta[NPF_RESOLVE_MAX];
    socklen_t tl[NPF_RESOLVE_MAX];
    int used[NPF_RESOLVE_MAX] = {0}, k = 0, fam;
    if (n < 3 || n > NPF_RESOLVE_MAX)
        return;                         /* two: already in turns, or one family */
    fam = a[0].ss_family;
    while (k < n) {
        int i, found = 0;
        for (i = 0; i < n; i++)         /* the next unused of fam, else of any */
            if (!used[i] && a[i].ss_family == fam) {
                found = 1;
                break;
            }
        if (!found)
            for (i = 0; i < n && used[i]; i++)
                ;
        used[i] = 1;
        ta[k] = a[i];
        tl[k++] = l[i];
        fam = fam == AF_INET6 ? AF_INET : AF_INET6;
    }
    memcpy(a, ta, (size_t)n * sizeof *a);
    memcpy(l, tl, (size_t)n * sizeof *l);
}

static void conn_cb(npf_loop *loop, int fd, unsigned ev, void *arg);
static int connect_next(sublink *s);

static void he_timer(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    (void)loop;
    s->t_he = NULL;
    connect_next(s);                    /* no answer yet: the next address too */
}

/* start the next address's attempt (Happy Eyeballs: the others keep going);
 * the one after it follows in HE_DELAY_MS, or at once when this one fails.
 * Returns -1 when the sublink was released (nothing left to try). */
static int connect_next(sublink *s)
{
    while (s->icand < s->ncand) {
        int i = s->icand++, fd, one = 1;
        fd = npf_socket(s->cand[i].ss_family, SOCK_STREAM, 0, 0);
        if (fd < 0) {
            s->last_err = errno;
            continue;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, (const struct sockaddr *)&s->cand[i], s->clen[i]) < 0 && !npf_sock_inprogress()) {
            s->last_err = errno;
            npf_sock_close(fd);
            continue;
        }
        s->cfd[s->ncfd++] = fd;
        npf_loop_add(s->t->loop, fd, NPF_EV_WRITE, conn_cb, s);
        if (s->icand < s->ncand && !s->t_he)
            s->t_he = npf_timer_add(s->t->loop, npf_tunnel_he_ms, he_timer, s);
        return 0;
    }
    if (s->ncfd)
        return 0;                       /* the ones under way may still answer */
    socks_fail(s, (uint8_t)map_errno(s->last_err));
    return -1;
}

/* an attempt answered: connected (the others closed, the sublink open) or
 * failed (the next address at once, or the end when none is left) */
static void conn_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    sublink *s = arg;
    int err = 0, i, k;
    socklen_t el = sizeof err;
    (void)ev;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &el);
    for (k = 0; k < s->ncfd && s->cfd[k] != fd; k++)
        ;
    if (k == s->ncfd)
        return;
    npf_loop_del(loop, fd);
    s->cfd[k] = s->cfd[--s->ncfd];
    if (err) {
        npf_sock_close(fd);
        s->last_err = err;
        if (s->t_he) {                  /* its turn is now */
            npf_timer_cancel(loop, s->t_he);
            s->t_he = NULL;
        }
        connect_next(s);
        return;
    }
    for (i = 0; i < s->ncfd; i++) {     /* the winner: the slower ones go */
        npf_loop_del(loop, s->cfd[i]);
        npf_sock_close(s->cfd[i]);
    }
    s->ncfd = 0;
    if (s->t_he) {
        npf_timer_cancel(loop, s->t_he);
        s->t_he = NULL;
    }
    if (s->t_connect) {
        npf_timer_cancel(loop, s->t_connect);
        s->t_connect = NULL;
    }
    free(s->cand);
    s->cand = NULL;
    s->ncand = s->icand = 0;
    s->fd = fd;
    s->ev = 0;
    socks_reply(s, 0);
    s->state = SL_OPEN;
    if (flush_local(s) < 0) {
        sub_reset(s, NPF_RST_LOCAL);
        return;
    }
    update_ev(s);
}

/* check the policy for every address, then connect to them (Happy Eyeballs).
 * Returns -1 when the sublink was released. */
static int socks_connect_addrs(sublink *s, const struct sockaddr_storage *cand, const socklen_t *clen, int nc)
{
    int i;
    /* every resolved address must pass: a name must not smuggle in a denied
     * target. Not a reverse sublink's: the caller's own -R named it */
    for (i = 0; i < nc && !s->reverse; i++) {
        if (!npf_policy_allowed(s->t->policy, (const struct sockaddr *)&cand[i])) {
            socks_fail(s, 2);
            return -1;
        }
    }
    /* this host's control interface (the web console): never, whoever asks
     * (a resource that covers it, a -R naming it) */
    for (i = 0; i < nc; i++) {
        if (npf_guard_blocked((const struct sockaddr *)&cand[i])) {
            char a[64];
            npf_logw("tunnel: %s is this computer's control interface (the web console): not forwarded",
                     npf_addr_str(&cand[i], a, sizeof a));
            socks_fail(s, 2);
            return -1;
        }
    }
    if (nc == 0) {
        socks_fail(s, 4);
        return -1;
    }
    if (nc > NPF_RESOLVE_MAX)
        nc = NPF_RESOLVE_MAX;
    if (!(s->cand = malloc((size_t)nc * sizeof *cand))) {
        socks_fail(s, 1);
        return -1;
    }
    memcpy(s->cand, cand, (size_t)nc * sizeof *cand);
    memcpy(s->clen, clen, (size_t)nc * sizeof *clen);
    npf_he_order(s->cand, s->clen, nc);
    s->ncand = nc;
    s->icand = 0;
    s->state = SL_CONNECTING;
    if (!s->t_connect)                  /* a name: the deadline runs since the lookup began */
        s->t_connect = npf_timer_add(s->t->loop, CONNECT_MS, connect_timeout, s);
    return connect_next(s);
}

/* the worker thread's answer for a domain-name target */
static void resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens, int n,
                     void *arg)
{
    sublink *s = arg;
    (void)r;
    s->resolve = NULL;
    if (err != 0) {
        socks_fail(s, 4);           /* host unreachable: the name did not resolve */
        return;
    }
    socks_connect_addrs(s, addrs, lens, n);
}

/* literal addresses connect at once; names are resolved off the loop thread.
 * Returns -1 when the sublink was released. */
static int socks_connect(sublink *s, int atyp, const uint8_t *addr, size_t alen, uint16_t port)
{
    struct sockaddr_storage cand;
    socklen_t clen;
    if (s->t->io.target_ok && !s->reverse) {
        char h[256];
        if (atyp == 1)
            inet_ntop(AF_INET, addr, h, sizeof h);
        else if (atyp == 4)
            inet_ntop(AF_INET6, addr, h, sizeof h);
        else
            memcpy(h, addr, alen), h[alen] = 0;
        if (!s->t->io.target_ok(s->t->arg, h, port)) {
            socks_fail(s, 2);
            return -1;
        }
    }
    memset(&cand, 0, sizeof cand);
    if (atyp == 1) {
        struct sockaddr_in *a = (struct sockaddr_in *)&cand;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, addr, 4);
        a->sin_port = htons(port);
        clen = sizeof *a;
    } else if (atyp == 4) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&cand;
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, addr, 16);
        a->sin6_port = htons(port);
        clen = sizeof *a;
    } else {
        char host[256];
        memcpy(host, addr, alen);
        host[alen] = 0;
        if (npf_tunnel_test_resolve) {     /* tests: the addresses of their choosing, at once */
            struct sockaddr_storage ta[NPF_RESOLVE_MAX];
            socklen_t tl[NPF_RESOLVE_MAX];
            int tn = npf_tunnel_test_resolve(host, port, ta, tl, NPF_RESOLVE_MAX);
            if (tn >= 0)
                return socks_connect_addrs(s, ta, tl, tn);
        }
        {
            int i, busy = 0;
            for (i = 0; i < s->t->nsubs; i++)
                busy += s->t->subs[i]->state == SL_RESOLVING;
            if (busy >= RESOLVING_MAX) {
                socks_fail(s, 1);
                return -1;
            }
        }
        s->state = SL_RESOLVING;
        s->resolve = npf_resolve_start(s->t->loop, host, port, SOCK_STREAM, resolved, s);
        if (!s->resolve) {
            socks_fail(s, 1);       /* the resolver's budget is used up (or no memory) */
            return -1;
        }
        /* one deadline for the lookup and the connection: a lookup that
         * never returns fails the sublink after CONNECT_MS (the worker is
         * released by the system, the request's callback is cancelled) */
        s->t_connect = npf_timer_add(s->t->loop, CONNECT_MS, connect_timeout, s);
        return 0;
    }
    return socks_connect_addrs(s, &cand, &clen, 1);
}

/* the greeting and request did not come in time: a peer's sublink is reset
 * (it holds one of the session's sublinks), a local application's (-D) closed
 * (nothing went to the peer yet) */
static void greet_timeout(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    (void)loop;
    s->t_greet = NULL;
    if (s->state == SL_LOCAL_GREETING) {
        s->end = "greeting_timeout";
        sub_free(s, 1);
    } else if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
        sub_reset(s, NPF_RST_PROTOCOL);
    }
}

static void greet_wait(sublink *s)
{
    s->t_greet = npf_timer_add(s->t->loop, npf_tunnel_greet_ms, greet_timeout, s);
}

static void greet_done(sublink *s)
{
    if (s->t_greet) {
        npf_timer_cancel(s->t->loop, s->t_greet);
        s->t_greet = NULL;
    }
}

/* parse what the client sent so far; returns -1 if the sublink was freed */
static int socks_parse(sublink *s)
{
    if (s->state == SL_SOCKS_GREETING) {
        size_t n;
        int ok = 0;
        if (s->sl < 2)
            return 0;
        if (s->sb[0] != 5) {
            sub_reset(s, NPF_RST_PROTOCOL);
            return -1;
        }
        n = 2 + (size_t)s->sb[1];
        if (s->sl < n)
            return 0;
        {
            size_t i;
            for (i = 2; i < n; i++)
                if (s->sb[i] == 0)
                    ok = 1;
        }
        if (!ok) {
            uint8_t r[2] = {5, 0xff};
            send_frame(s->t, s->id, FR_DATA, r, 2);
            send_frame(s->t, s->id, FR_FIN, NULL, 0);
            sub_free(s, 0);
            return -1;
        }
        {
            uint8_t r[2] = {5, 0};
            send_frame(s->t, s->id, FR_DATA, r, 2);
            s->tx_credit -= 2;
        }
        credit_back(s, n);
        memmove(s->sb, s->sb + n, s->sl - n);
        s->sl -= n;
        s->state = SL_SOCKS_REQUEST;
    }
    if (s->state == SL_SOCKS_REQUEST) {
        size_t need, alen;
        int atyp;
        uint16_t port;
        if (s->sl < 5)
            return 0;
        if (s->sb[0] != 5 || s->sb[2] != 0) {
            sub_reset(s, NPF_RST_PROTOCOL);
            return -1;
        }
        atyp = s->sb[3];
        if (atyp == 1) alen = 4;
        else if (atyp == 4) alen = 16;
        else if (atyp == 3) alen = s->sb[4];
        else {
            socks_fail(s, 8);
            return -1;
        }
        need = 4 + (atyp == 3 ? 1 : 0) + alen + 2;
        if (s->sl < need)
            return 0;
        if (s->sb[1] != 1) {        /* only CONNECT (C5) */
            socks_fail(s, 7);
            return -1;
        }
        if (atyp == 3 && alen == 0) {
            socks_fail(s, 4);
            return -1;
        }
        port = (uint16_t)((s->sb[need - 2] << 8) | s->sb[need - 1]);
        {
            uint8_t addr[256];
            memcpy(addr, s->sb + 4 + (atyp == 3 ? 1 : 0), alen);
            /* pipelined data after the request waits in wq until connected */
            if (s->sl > need && wb_put(&s->wq, s->sb + need, s->sl - need) < 0) {
                sub_reset(s, NPF_RST_LIMIT);
                return -1;
            }
            s->sl = 0;
            credit_back(s, need);
            greet_done(s);
            if (s->t->caller) {
                /* reverse sublink: only a target this caller registered (7.1) */
                char host[256];
                int i, ok = 0;
                if (atyp == 1) inet_ntop(AF_INET, addr, host, sizeof host);
                else if (atyp == 4) inet_ntop(AF_INET6, addr, host, sizeof host);
                else { memcpy(host, addr, alen); host[alen] = 0; }
                for (i = 0; i < s->t->nrev; i++)
                    if (s->t->rev[i].port == port && strcmp(s->t->rev[i].host, host) == 0)
                        ok = 1;
                if (!ok) {
                    socks_fail(s, 2);
                    return -1;
                }
                s->reverse = 1;
            }
            return socks_connect(s, atyp, addr, alen, port);
        }
    }
    return 0;
}

/* client side (port mapping): strip "05 00" and the CONNECT reply */
static int client_strip(sublink *s, const uint8_t *p, size_t n, size_t *used)
{
    size_t take;
    *used = 0;
    while (s->state == SL_CLIENT_WAIT && *used < n) {
        size_t need;
        take = n - *used;
        if (take > sizeof s->sb - s->sl)
            take = sizeof s->sb - s->sl;
        memcpy(s->sb + s->sl, p + *used, take);
        s->sl += take;
        *used += take;
        if (s->sl < 2)
            continue;
        if (s->sb[0] != 5 || s->sb[1] != 0)
            return -1;              /* method refused */
        if (s->sl < 2 + 5)
            continue;
        if (s->sb[3] != 0) {
            s->end = s->sb[3] == 2 ? "target_refused" : "target_failed";   /* 2: the other side's policy */
            return -1;              /* REP != 0: connection failed */
        }
        need = 2 + 4 + (s->sb[5] == 1 ? 4 : s->sb[5] == 4 ? 16 : 1 + (size_t)s->sb[6]) + 2;
        if (s->sl < need)
            continue;
        /* bytes after the replies belong to the application */
        if (s->sl > need) {
            size_t extra = s->sl - need;
            *used -= extra;
        }
        s->state = SL_OPEN;
        s->t_ok = npf_mono_ms();
        s->sl = 0;
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
    s = find(t, id);
    if (!s) {
        int peer_opened = t->caller ? (id % 2 == 0) : (id % 2 == 1);
        if (type == FR_RESET && peer_opened && id > t->peer_max_seen) {
            /* reset on the fast lane before its first data arrived: that
             * data is late now (ids are never reused) */
            t->peer_max_seen = id;
            return 0;
        }
        if (type != FR_DATA)
            return 0;               /* late frame of a released sublink */
        if (!peer_opened || id <= t->peer_max_seen)
            return 0;
        t->peer_max_seen = id;
        if (t->caller && t->nrev == 0) {
            send_reset(t, id, NPF_RST_PROTOCOL);   /* no reverse mapping registered */
            return 0;
        }
        if (t->nsubs >= NPF_MAX_SUBLINKS) {
            send_reset(t, id, NPF_RST_LIMIT);
            return 0;
        }
        s = sub_new(t, id, -1, 1);
        if (!s)
            return -1;
        s->state = SL_SOCKS_GREETING;
        greet_wait(s);
    }
    switch (type) {
    case FR_DATA:
        if (n == 0 || s->peer_fin)
            goto proto;
        /* the peer may not exceed the window we granted: everything received
         * and not yet given back (buffered, or consumed but not yet in a WINDOW) */
        if (s->wq.len + s->sl + s->rx_freed + n > s->rx_window)
            goto proto;
        if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
            /* into the parse buffer what fits (a greeting and a request are
             * 519 bytes at most); data pipelined after the request, in this
             * frame or later ones, is queued until the target is connected */
            size_t take = n < sizeof s->sb - s->sl ? n : sizeof s->sb - s->sl;
            memcpy(s->sb + s->sl, p, take);
            s->sl += take;
            if (socks_parse(s) < 0)
                return 0;           /* released */
            if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
                if (s->sl == sizeof s->sb)
                    goto proto;     /* full and still no request: not SOCKS5 */
                return 0;
            }
            if (take < n && wb_put(&s->wq, p + take, n - take) < 0) {
                sub_reset(s, NPF_RST_LIMIT);
                return 0;
            }
            return 0;
        }
        if (s->state == SL_CLIENT_WAIT) {
            size_t used;
            if (client_strip(s, p, n, &used) < 0) {
                if (!s->end)
                    s->end = "target_failed";   /* the other side could not reach the target */
                sub_reset(s, NPF_RST_LOCAL);
                return 0;
            }
            credit_back(s, used);
            p += used;
            n -= used;
            if (n == 0) {
                update_ev(s);
                return 0;
            }
        }
        if (s->skip_method) {               /* -D: the server's "05 00", answered here already */
            size_t k = 0;
            while (k < n && s->skip_method) {
                if (p[k] != (s->skip_method == 2 ? 5 : 0)) {
                    sub_reset(s, NPF_RST_PROTOCOL);
                    return 0;
                }
                k++;
                s->skip_method--;
            }
            credit_back(s, k);
            p += k;
            n -= k;
            if (n == 0)
                return 0;
        }
        if (s->socks_rep && !s->skip_method) {     /* -D: the CONNECT reply goes to the application as it is */
            if (p[0] == 5 && n >= 2 && p[1] == 2)
                s->end = "target_refused";      /* not a resource the other side published */
            if (n >= 2)
                s->socks_rep = 0;
        }
        if (s->state == SL_OPEN && s->wq.len == 0) {
            /* nothing queued: straight from the frame to the local end, only
             * what it cannot take now is queued (one copy less) */
            size_t done = 0;
            while (done < n) {
                ssize_t w = local_write(s, p + done, n - done);
                if (w < 0) {
                    sub_reset(s, NPF_RST_LOCAL);
                    return 0;
                }
                if (w == 0)
                    break;
                done += (size_t)w;
            }
            if (done < n && wb_put(&s->wq, p + done, n - done) < 0) {
                sub_reset(s, NPF_RST_LIMIT);
                return 0;
            }
            if (done)
                credit_back(s, done);       /* after queueing the rest: the window grows only if all went */
            update_ev(s);
            return 0;
        }
        if (wb_put(&s->wq, p, n) < 0) {
            sub_reset(s, NPF_RST_LIMIT);
            return 0;
        }
        if (s->state == SL_OPEN && flush_local(s) < 0) {
            sub_reset(s, NPF_RST_LOCAL);
            return 0;
        }
        update_ev(s);
        return 0;
    case FR_FIN:
        if (!s->local_eof && !s->fin_first)
            s->fin_first = 2;
        s->peer_fin = 1;
        if (s->state == SL_OPEN || s->state == SL_CLIENT_WAIT) {
            if (flush_local(s) < 0) {
                sub_reset(s, NPF_RST_LOCAL);
                return 0;
            }
            update_ev(s);
            maybe_done(s);
        } else if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST || s->state == SL_RESOLVING) {
            sub_free(s, 0);
        }
        return 0;
    case FR_RESET:
        if (!s->end)                        /* (a refusal seen in a reply stays the reason) */
            s->end = s->state == SL_CLIENT_WAIT ? "target_failed" : "peer_reset";
        sub_free(s, 1);
        return 0;
    case FR_WINDOW:
        if (n != 4)
            goto proto;
        s->tx_credit += npf_rd32(p);
        update_ev(s);
        return 0;
    default:
        return 0;                   /* unknown types are skipped */
    }
proto:
    sub_reset(s, NPF_RST_PROTOCOL);
    return 0;
}

static int broken(npf_tunnel *t, const char *why)
{
    t->dead = 1;
    if (t->io.broken)
        t->io.broken(t->arg, why);
    return -1;
}

int npf_tunnel_input_data(npf_tunnel *t, const uint8_t *msg, size_t len)
{
    if (t->dead)
        return -1;
    if (len < NPF_DATA_HDR || len > NPF_DATA_HDR + NPF_FRAME_MAX)
        return broken(t, "bad data message");
    if (handle_frame(t, npf_rd32(msg), len == NPF_DATA_HDR ? FR_FIN : FR_DATA, msg + NPF_DATA_HDR,
                     len - NPF_DATA_HDR) < 0)
        return broken(t, "protocol error");
    return 0;
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

int npf_tunnel_input_ctrl(npf_tunnel *t, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    if (t->dead)
        return -1;
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
        sub_free(s, 0);                     /* gone before its greeting: nothing went to the peer */
        return;
    }
    s->sl += (size_t)r;
    if (s->sl < 2)
        return;
    if (s->sb[0] != 5) {
        sub_free(s, 1);
        return;
    }
    need = 2 + (size_t)s->sb[1];
    if (s->sl < need)
        return;
    for (i = 2; i < need; i++)
        if (s->sb[i] == 0)
            ok = 1;
    if (send(s->fd, ok ? "\x05\x00" : "\x05\xff", 2, MSG_NOSIGNAL | MSG_DONTWAIT) != 2 || !ok) {
        sub_free(s, 0);                     /* no method we offer: the application closes */
        return;
    }
    /* the server's greeting, then whatever the application already sent */
    if (send_frame(s->t, s->id, FR_DATA, g, 3) < 0)
        return;
    s->tx_credit -= 3;
    if (s->sl > need) {
        if (send_frame(s->t, s->id, FR_DATA, s->sb + need, s->sl - need) < 0)
            return;
        s->tx_credit -= (int64_t)(s->sl - need);
    }
    s->sl = 0;
    s->skip_method = 2;
    s->socks_rep = 1;
    s->state = SL_OPEN;
    greet_done(s);
    update_ev(s);
}

static void io_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    uint32_t id = s->id;            /* s may be released below; ids are never reused */
    (void)loop;
    (void)fd;
    if (ev & NPF_EV_WRITE) {
        if (flush_local(s) < 0) {
            sub_reset(s, NPF_RST_LOCAL);
            return;
        }
        maybe_done(s);
        if (!find(t, id))
            return;
    }
    if (s->state == SL_LOCAL_GREETING) {
        local_greeting(s);                  /* may release s */
        return;
    }
    if ((ev & NPF_EV_READ) && !s->local_eof && s->tx_credit > 0 && !t->paused) {
        size_t want = rate_allow(s, 1, s->tx_credit < NPF_FRAME_MAX ? (size_t)s->tx_credit : NPF_FRAME_MAX);
        uint8_t *m = want ? npf_scratch(NPF_DATA_HDR + NPF_FRAME_MAX) : NULL;    /* received in place */
        ssize_t r = !m ? -1 : s->v ? s->v->read(s->varg, m + NPF_DATA_HDR, want)
                                   : recv(s->fd, m + NPF_DATA_HDR, want, MSG_DONTWAIT);
        if (want == 0) {
            update_ev(s);               /* the rate group's share is used up */
            return;
        }
        if (!m)
            return;
        if (r > 0) {
            rate_take(s, 1, (size_t)r);
            t->local_in += (uint64_t)r;
            s->in += (uint64_t)r;
        }
        if (r > 0) {
            int w = send_data(t, s->id, m, (size_t)r);
            npf_scratch_done(m);
            if (w < 0)
                return;
            s->tx_credit -= r;
            if (t->io.backlog(t->arg) > BACKLOG_PAUSE)
                t->paused = 1;
        } else if (r == 0) {
            npf_scratch_done(m);
            if (!s->peer_fin && !s->fin_first)
                s->fin_first = 1;
            s->local_eof = 1;
            send_frame(t, s->id, FR_FIN, NULL, 0);
            maybe_done(s);
            if (!find(t, id))
                return;
        } else {
            int again = s->v || npf_sock_again();     /* a virtual end: -1 is "none now" */
            npf_scratch_done(m);
            if (!again) {
                sub_reset(s, NPF_RST_LOCAL);
                return;
            }
        }
    }
    if (t->paused) {
        int i;
        for (i = 0; i < t->nsubs; i++)
            update_ev(t->subs[i]);
    } else {
        update_ev(s);
    }
}

void npf_tunnel_kick(npf_tunnel *t)
{
    int i;
    if (!t->paused || t->io.backlog(t->arg) > BACKLOG_PAUSE / 2)
        return;
    t->paused = 0;
    for (i = 0; i < t->nsubs; i++)
        update_ev(t->subs[i]);
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

void npf_tunnel_local_bytes(const npf_tunnel *t, uint64_t *in, uint64_t *out)
{
    *in = t->local_in;
    *out = t->local_out;
}

int npf_tunnel_group_count(const npf_tunnel *t, uint32_t group)
{
    int i, n = 0;
    for (i = 0; i < t->nsubs; i++)
        n += t->subs[i]->rg && t->subs[i]->rg->id == group;
    return n;
}

int npf_tunnel_group_reset(npf_tunnel *t, uint32_t group, const char *why)
{
    int i, n = 0;
    for (i = t->nsubs - 1; i >= 0; i--) {   /* from the end: a released one's place takes one seen already */
        sublink *s = t->subs[i];
        if (s->rg && s->rg->id == group) {
            s->end = why;
            sub_reset(s, NPF_RST_LOCAL);
            n++;
        }
    }
    return n;
}

void npf_tunnel_free(npf_tunnel *t)
{
    if (!t)
        return;
    if (t->t_rate)
        npf_timer_cancel(t->loop, t->t_rate);
    t->t_rate = NULL;
    if (t->t_virt)
        npf_timer_cancel(t->loop, t->t_virt);
    t->t_virt = NULL;
    t->dead = 1;                        /* nothing more goes to the transport */
    while (t->nsubs) {
        sublink *s = t->subs[t->nsubs - 1];
        if (!s->end)
            s->end = "session_ended";
        sub_free(s, 1);
    }
    if (t->in_poll) {                   /* a local end's call ended the session: virt_poll frees it */
        t->free_later = 1;
        return;
    }
    free(t->subs);
    free(t->ids);
    free(t->rb);
    free(t);
}

/* ---- virtual local ends (npf_tunnel_open_v) ---- */

#define VIRT_ROUNDS 64                  /* passes of one poll (a pass reads a frame per sublink) */

static void virt_poll(npf_loop *loop, void *arg)
{
    npf_tunnel *t = arg;
    int round, busy = 1;
    (void)loop;
    t->t_virt = NULL;
    t->in_poll = 1;
    for (round = 0; round < VIRT_ROUNDS && busy && !t->free_later; round++) {
        int i;
        busy = 0;
        /* from the end: io_cb releases s at most, never another, and the
         * last one (seen already) takes its place */
        for (i = t->nsubs - 1; i >= 0 && !t->free_later; i--) {
            sublink *s;
            unsigned ev;
            if (i >= t->nsubs)
                continue;
            s = t->subs[i];
            if (!s->v || !(ev = s->ev & s->v->ready(s->varg)))
                continue;
            busy = 1;
            io_cb(t->loop, -1, ev, s);
        }
    }
    t->in_poll = 0;
    if (t->free_later) {
        free(t->subs);
        free(t->ids);
        free(t->rb);
        free(t);
        return;
    }
    if (busy)
        virt_arm(t);                    /* more next time: other work goes first */
}

static void virt_arm(npf_tunnel *t)
{
    if (!t->t_virt && !t->in_poll && !t->dead)
        t->t_virt = npf_timer_add(t->loop, 0, virt_poll, t);
}

void npf_tunnel_vkick(npf_tunnel *t, uint32_t id)
{
    (void)id;
    virt_arm(t);
}

void npf_tunnel_vclose(npf_tunnel *t, uint32_t id, int reset)
{
    sublink *s = find(t, id);
    if (!s || !s->v)
        return;
    s->v = NULL;                        /* gone: not called again */
    if (reset) {
        if (!s->end)
            s->end = "local_reset";
        sub_reset(s, NPF_RST_LOCAL);
        return;
    }
    if (!s->local_eof) {                /* as if FIN came and the rest could not be written */
        s->local_eof = 1;
        if (!s->fin_first)
            s->fin_first = 1;
        send_frame(t, s->id, FR_FIN, NULL, 0);
    }
    if (!s->peer_fin || s->wq.len) {
        sub_reset(s, NPF_RST_LOCAL);
        return;
    }
    sub_free(s, 0);
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

static int open_sub(npf_tunnel *t, int fd, const npf_vend_io *v, void *varg, int passthrough, const char *host,
                    uint16_t port, uint32_t group, uint32_t rate)
{
    sublink *s;
    rgroup *g = NULL;
    int i;
    if (!npf_tunnel_is_ready(t) || t->nsubs >= t->peer_max || t->next_id > 0x7ffffff0u)
        return -1;
    if (group) {                            /* rate 0: counted (npf_tunnel_group_count), not limited */
        for (i = 0; i < t->nrg && !g; i++)
            if (t->rg[i].id == group)
                g = &t->rg[i];
        if (!g) {
            if (t->nrg == NPF_RATE_GROUPS)
                return -1;
            g = &t->rg[t->nrg++];
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
        greet_wait(s);
    } else {
        uint8_t req[300];
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
            if (hl == 0 || hl > 255) {
                s->v = NULL;            /* the caller keeps its local end */
                sub_free(s, 1);
                return -1;
            }
            req[n++] = 3;
            req[n++] = (uint8_t)hl;
            memcpy(req + n, host, hl);
            n += hl;
        }
        req[n++] = (uint8_t)(port >> 8);
        req[n++] = (uint8_t)port;
        send_frame(t, s->id, FR_DATA, req, n);
        s->tx_credit -= (int64_t)n;
        s->state = SL_CLIENT_WAIT;
    }
    update_ev(s);
    return (int)s->id;
}

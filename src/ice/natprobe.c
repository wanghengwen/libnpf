/* NAT detection (npf/natprobe.h): transactions with the probe servers,
 * driven on the event loop; the tools' synchronous run drives the same on
 * a loop of its own. */
#define _DEFAULT_SOURCE
#include "npf/log.h"
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/natprobe.h"
#include "npf/platform.h"

/* retransmission schedule (4.2): send at 0, 200, 600, 1400 ms, give up at 2200 ms */
static const int k_send_at[] = { 0, 200, 600, 1400 };
#define TX_SENDS     4
#define TX_GIVEUP_MS 2200
#define ALLOC_SPREAD_MS 200     /* the K allocation requests are spread over 200 ms */
#define FILTER_WAIT_MS  600     /* a bounce comes with the server's acknowledgement: so long after it at most */

typedef struct tx {
    int      fd;
    struct sockaddr_in dst;
    uint8_t  txid[NPF_TXID_SIZE];
    int64_t  start;             /* monotonic ms */
    int      sent;
    int      done;
    int      type;              /* NPF_PKT_BIND_REQ or NPF_PKT_BOUNCE_REQ */
    uint8_t  extra[24];         /* BOUNCE_REQ: the target and its txid, after the ticket */
    size_t   extra_len;
    int      listen;            /* sends nothing: waits for the answer a bounce request asked for */
    int      pair;              /* a bounce request: its listening transaction (sent again until
                                   that is answered); a listening one: its request; else -1 */
    int64_t  acked_at;          /* when it was answered */
    /* result */
    struct sockaddr_in mapped;
    int      rtt_ms;
    int64_t  srv_offset_ms;
} tx;

static uint32_t wire_ts(int64_t offset)
{
    return (uint32_t)(npf_unix_ms() + offset);
}

static void tx_send(const npf_natprobe_cfg *cfg, const npf_siv_keys *keys, tx *t)
{
    uint8_t body[NPF_TICKET_SIZE + sizeof t->extra];
    int n;
    memcpy(body, cfg->ticket, NPF_TICKET_SIZE);
    memcpy(body + NPF_TICKET_SIZE, t->extra, t->extra_len);
    n = npf_bind_req_send(t->fd, &t->dst, keys, t->type, t->txid, cfg->clock_offset_ms, body,
                          NPF_TICKET_SIZE + t->extra_len);
    t->sent++;
    if (npf_log_on(NPF_LOG_TRACE)) {
        char a[64];
        npf_logt("natprobe: fd %d -> %s %s #%d (%d bytes)", t->fd, npf_addr_str(&t->dst, a, sizeof(a)),
                 t->type == NPF_PKT_BOUNCE_REQ ? "BOUNCE_REQ" : "BIND_REQ", t->sent, n);
    }
}

static int tx_input(const npf_natprobe_cfg *cfg, const npf_siv_keys *keys, tx *txs, int n,
                    int fd, const uint8_t *buf, size_t len, const struct sockaddr_in *from)
{
    uint8_t plain[NPF_PKT_MAX];
    npf_pkt pkt;
    npf_bind_resp resp;
    char a[64];
    int i;

    if (npf_pkt_open(keys, NPF_DIR_RESP, buf, len, plain, &pkt) < 0 || npf_bind_resp_parse(&pkt, &resp) < 0) {
        if (npf_log_on(NPF_LOG_TRACE))
            npf_logt("natprobe: fd %d <- %s %zu bytes: not a valid BIND_RESP", fd, npf_addr_str(from, a, sizeof(a)), len);
        return 0;
    }
    for (i = 0; i < n; i++) {
        tx *t = &txs[i];
        if (t->done || t->fd != fd || memcmp(t->txid, pkt.txid, NPF_TXID_SIZE) != 0)
            continue;
        if (!npf_addr_eq(from, &t->dst) || resp.family != 4)
            continue;                   /* the server answers from the endpoint we asked */
        t->done = 1;
        t->acked_at = npf_mono_ms();
        memset(&t->mapped, 0, sizeof(t->mapped));
        t->mapped.sin_family = AF_INET;
        memcpy(&t->mapped.sin_addr, resp.addr, 4);
        t->mapped.sin_port = htons(resp.port);
        /* the response echoes the ts_ms of the request it answers (no retransmission ambiguity) */
        t->rtt_ms = (int)(uint32_t)(wire_ts(cfg->clock_offset_ms) - pkt.ts_ms);
        t->srv_offset_ms = (int64_t)resp.srv_time_ms - (npf_unix_ms() - t->rtt_ms / 2);
        if (npf_log_on(NPF_LOG_TRACE)) {
            char m[64];
            npf_logt("natprobe: fd %d <- %s BIND_RESP mapped %s rtt %d ms", fd,
                    npf_addr_str(from, a, sizeof(a)), npf_addr_str(&t->mapped, m, sizeof(m)), t->rtt_ms);
        }
        return 1;
    }
    if (npf_log_on(NPF_LOG_TRACE))
        npf_logt("natprobe: fd %d <- %s stray BIND_RESP", fd, npf_addr_str(from, a, sizeof(a)));
    return 1;
}

/* send what is due; 1 while a transaction is open (wake: when to come back).
 * A bounce request is sent again until the answer it asked for came (the
 * server's acknowledgement may come back while that answer is lost) */
static int tx_step(const npf_natprobe_cfg *cfg, const npf_siv_keys *keys, tx *txs, int n, int64_t now, int64_t *wake)
{
    int i, pending = 0;
    *wake = -1;
    for (i = 0; i < n; i++) {
        tx *t = &txs[i];
        int64_t due;
        if (t->done && (t->pair < 0 || txs[t->pair].done))
            continue;
        if (now - t->start >= TX_GIVEUP_MS
            || (t->listen && txs[t->pair].done > 0 && now - txs[t->pair].acked_at >= FILTER_WAIT_MS)) {
            if (!t->done)
                t->done = -1;
            continue;
        }
        pending = 1;
        while (!t->listen && t->sent < TX_SENDS && now - t->start >= k_send_at[t->sent])
            tx_send(cfg, keys, t);
        due = !t->listen && t->sent < TX_SENDS ? t->start + k_send_at[t->sent] : t->start + TX_GIVEUP_MS;
        if (t->listen && txs[t->pair].done > 0 && txs[t->pair].acked_at + FILTER_WAIT_MS < due)
            due = txs[t->pair].acked_at + FILTER_WAIT_MS;
        if (*wake < 0 || due < *wake)
            *wake = due;
    }
    return pending;
}

/* a fresh non-blocking UDP socket on any port: its port in *local_port */
static int udp_socket(uint16_t *local_port)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int fd = npf_udp_socket(AF_INET, 0);
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || getsockname(fd, (struct sockaddr *)&a, &alen) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    *local_port = ntohs(a.sin_port);
    return fd;
}

static void tx_init(tx *t, int fd, const struct sockaddr_in *dst, int64_t start)
{
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    t->dst = *dst;
    t->start = start;
    t->type = NPF_PKT_BIND_REQ;
    t->pair = -1;
    npf_random(t->txid, sizeof(t->txid));
}

/* The filtering test (4.2): F, a socket that has sent to E1 only, and its
 * mapping mF. From the main socket (which has sent to E2 and E3 already) E2
 * and E3 are asked to answer mF; listening transactions on F wait for those
 * answers. Layout: E2 request, E2 listen, E3 request, E3 listen. Returns the
 * count (0: no test). */
static int filter_txs(const npf_natprobe_cfg *cfg, tx *txs, int main_fd, int f_fd,
                      const struct sockaddr_in *mf, int n_ep, int64_t now)
{
    int e, n = 0;
    if (!cfg->filter_test || n_ep < 2 || f_fd < 0)
        return 0;
    for (e = 1; e < n_ep && e <= 2; e++) {
        tx *req = &txs[n], *lis = &txs[n + 1];
        tx_init(lis, f_fd, &cfg->ep[e], now);
        lis->listen = 1;
        lis->pair = n;
        tx_init(req, main_fd, &cfg->ep[e], now);
        req->type = NPF_PKT_BOUNCE_REQ;
        req->pair = n + 1;
        req->extra[0] = 4;
        req->extra[1] = (uint8_t)ntohs(mf->sin_port);
        req->extra[2] = (uint8_t)(ntohs(mf->sin_port) >> 8);
        memcpy(req->extra + 3, &mf->sin_addr, 4);
        memcpy(req->extra + 7, lis->txid, NPF_TXID_SIZE);
        req->extra_len = 7 + NPF_TXID_SIZE;
        n += 2;
    }
    return n;
}

/* which answers reached F: from E3 (another IP) -> anyone may send in; from
 * E2 only (the same IP, another port) -> the IPs it sent to; none while the
 * server got the requests -> the IP:ports it sent to */
static void decide_filter(npf_natprobe_result *res, const tx *txs, int n)
{
    int i;
    for (i = 0; i + 1 < n; i += 2) {
        res->filter_acked[i / 2] = txs[i].done > 0;
        res->filter_got[i / 2] = txs[i + 1].done > 0;
    }
    if (res->filter_got[1])
        res->profile.filtering = NPF_FILT_EIF;
    else if (res->filter_got[0])
        res->profile.filtering = NPF_FILT_ADF;
    else if (res->filter_acked[0] || res->filter_acked[1])
        res->profile.filtering = NPF_FILT_APDF;
    else
        res->profile.filtering = NPF_FILT_UNKNOWN;
}

static int is_local_ipv4(const struct in_addr *ip)
{
    npf_ifaddr ifs[64];
    int i, n = npf_if_list(ifs, 64);
    for (i = 0; i < n; i++)
        if (ifs[i].family == AF_INET && memcmp(ifs[i].addr, &ip->s_addr, 4) == 0)
            return 1;
    return 0;
}

/* port allocation from K (local, mapped) samples, 4.2 */
void npf_natprobe_classify_alloc(npf_natprobe_result *res)
{
    uint16_t p[NPF_NATPROBE_MAX_ALLOC];
    int n = 0, i, preserve = 1, best = 0, best_cnt = 0;
    uint16_t lo = 0xffff, hi = 0;

    for (i = 0; i < res->alloc_n; i++) {
        if (!res->alloc_got[i])
            continue;
        if (res->alloc_mapped[i] != res->alloc_local[i])
            preserve = 0;
        p[n++] = res->alloc_mapped[i];
    }
    if (n < 3) {
        res->profile.allocation = NPF_ALLOC_UNKNOWN;
        return;
    }
    if (preserve) {
        res->profile.allocation = NPF_ALLOC_PRESERVE;
        return;
    }
    /* sequential: the ports go up in small steps, all of them (but one, of
     * five and more: the range wrapping at its end); the step the smallest.
     * Other traffic behind the same NAT takes ports in between (a busy NAT:
     * deltas 2 4 3 for a step of 1), so not "the same delta" each time: that
     * read a busy sequential NAT as a block. A block's or random allocation
     * goes down as often as up */
    for (i = 0; i + 1 < n; i++) {
        int d = (int16_t)(uint16_t)(p[i + 1] - p[i]);
        if (d >= 1 && d <= 64) {
            best_cnt++;
            if (!best || d < best)
                best = d;
        }
    }
    if (n - 1 >= 2 && best_cnt >= (n - 1 >= 5 ? n - 2 : n - 1) && best > 0 && best <= 16) {
        res->profile.allocation = NPF_ALLOC_SEQUENTIAL;
        res->profile.seq_delta = (int16_t)best;
        return;
    }
    /* smallest circular range holding every sample: the complement of the
     * largest gap (a port block may wrap from 65535 back to 1024) */
    {
        int j, gap_best = -1, gap_at = 0;
        uint16_t sorted[NPF_NATPROBE_MAX_ALLOC], tmp;
        memcpy(sorted, p, (size_t)n * sizeof(p[0]));
        for (i = 1; i < n; i++)
            for (j = i; j > 0 && sorted[j - 1] > sorted[j]; j--) {
                tmp = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = tmp;
            }
        for (i = 0; i < n; i++) {
            int gap = (uint16_t)(sorted[(i + 1) % n] - sorted[i]);
            if (gap > gap_best) {
                gap_best = gap;
                gap_at = i;
            }
        }
        lo = sorted[(gap_at + 1) % n];
        hi = sorted[gap_at];
    }
    res->profile.block_lo = lo;
    res->profile.block_hi = hi;     /* lo > hi: the range wraps around */
    res->profile.allocation = (uint16_t)(hi - lo) < 4096 ? NPF_ALLOC_BLOCK : NPF_ALLOC_RANDOM;
}

/* phase 1 results and the 4.2 decision table; -1 when E1 did not answer */
static int decide_mapping(npf_natprobe_result *res, const tx *txs, int n_ep)
{
    int i;
    for (i = 0; i < n_ep; i++) {
        res->got[i] = txs[i].done > 0;
        res->tries[i] = txs[i].sent;
        if (res->got[i]) {
            res->mapped[i] = txs[i].mapped;
            res->rtt_ms[i] = txs[i].rtt_ms;
        }
    }
    if (!res->got[0])
        return -1;
    res->have_offset = 1;
    res->srv_offset_ms = txs[0].srv_offset_ms;
    res->profile.open = is_local_ipv4(&res->mapped[0].sin_addr)
                        && ntohs(res->mapped[0].sin_port) == res->local_port;
    if (n_ep >= 2 && res->got[1] && !npf_addr_eq(&res->mapped[0], &res->mapped[1]))
        res->profile.mapping = NPF_MAP_APDM;
    else if (n_ep >= 3 && res->got[1] && res->got[2]) {
        if (res->mapped[2].sin_addr.s_addr != res->mapped[0].sin_addr.s_addr) {
            res->profile.ip_varies = 1;
            res->profile.mapping = NPF_MAP_ADM;
        } else if (npf_addr_eq(&res->mapped[0], &res->mapped[2]))
            res->profile.mapping = NPF_MAP_EIM;
        else
            res->profile.mapping = NPF_MAP_ADM;
    } else
        res->profile.mapping = NPF_MAP_UNKNOWN;
    return 0;
}

/* phase 2 results: the allocation behaviour; the index of the first socket
 * answered (F for the filtering test), -1 if none */
static int collect_alloc(npf_natprobe_result *res, const tx *txs, int n)
{
    int i, f = -1;
    res->alloc_n = n;
    for (i = 0; i < n; i++) {
        res->alloc_got[i] = txs[i].done > 0;
        if (res->alloc_got[i]) {
            res->alloc_mapped[i] = ntohs(txs[i].mapped.sin_port);
            if (f < 0)
                f = i;
        }
    }
    npf_natprobe_classify_alloc(res);
    return f;
}

static void finish_profile(npf_natprobe_result *res)
{
    if (res->profile.allocation == NPF_ALLOC_UNKNOWN && ntohs(res->mapped[0].sin_port) == res->local_port)
        res->profile.allocation = NPF_ALLOC_PRESERVE;
    res->profile.measured_at = (uint32_t)(npf_unix_ms() / 1000);
}

void npf_natprobe_cfg_init(npf_natprobe_cfg *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->alloc_sockets = 8;
    cfg->filter_test = 1;
    cfg->main_fd = -1;
}

/* ---- event-driven (roadmap 1.1, review R8) ----
 * The same two phases on the event loop: the transactions are pumped by a
 * timer, the main socket's datagrams come in through npf_natprobe_input
 * (the node's own dispatch hands over what comes from a probe server, so
 * no session datagram is read here), the K allocation sockets are the
 * probe's own loop handlers. Nothing blocks. */

struct npf_natprobe {
    npf_loop        *loop;
    npf_natprobe_cfg cfg;
    npf_siv_keys     keys;
    npf_natprobe_fn  fn;
    void            *arg;
    int              phase;     /* 1 mapping (main socket), 2 allocation, 3 filtering (F) */
    int              ffd;       /* phase 3: F, the allocation socket kept */
    int              n_ep;
    tx               txs[NPF_NATPROBE_MAX_ALLOC];
    int              ntx;
    npf_timer       *t;
    npf_natprobe_result res;
};

static void ev_pump(npf_natprobe *p);

/* the allocation sockets (phase 2) closed, all but keep */
static void drop_alloc(npf_natprobe *p, int keep)
{
    int i;
    for (i = 0; i < p->ntx; i++)
        if (p->txs[i].fd != keep) {
            npf_loop_del(p->loop, p->txs[i].fd);
            npf_sock_close(p->txs[i].fd);
        }
}

static void ev_finish(npf_natprobe *p, int ok)
{
    npf_natprobe_fn fn = p->fn;
    void *arg = p->arg;
    npf_natprobe_result res = p->res;
    npf_natprobe_cancel(p);         /* sockets, timer, memory */
    fn(ok, &res, arg);
}

static void ev_tick(npf_loop *loop, void *arg)
{
    npf_natprobe *p = arg;
    (void)loop;
    p->t = NULL;
    ev_pump(p);
}

static void ev_alloc_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_natprobe *p = arg;
    int k;
    (void)loop;
    (void)ev;
    for (k = 0; k < 64; k++) {          /* a bounded batch (level-triggered) */
        uint8_t buf[NPF_PKT_MAX];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t r = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
        if (r <= 0)
            break;
        if (from.sin_family == AF_INET)
            tx_input(&p->cfg, &p->keys, p->txs, p->ntx, fd, buf, (size_t)r, &from);
    }
    npf_timer_stop(p->loop, &p->t);
    ev_pump(p);
}

/* send what is due; when every transaction of the phase is over, go on */
static void ev_pump(npf_natprobe *p)
{
    int64_t now = npf_mono_ms(), wake;
    int i, k;
    if (tx_step(&p->cfg, &p->keys, p->txs, p->ntx, now, &wake)) {
        p->t = npf_timer_add(p->loop, wake > now ? wake - now : 0, ev_tick, p);
        return;
    }
    if (p->phase == 1) {
        if (decide_mapping(&p->res, p->txs, p->n_ep) < 0) {
            ev_finish(p, 0);
            return;
        }
        k = p->cfg.alloc_sockets < NPF_NATPROBE_MAX_ALLOC ? p->cfg.alloc_sockets : NPF_NATPROBE_MAX_ALLOC;
        p->phase = 2;
        p->ntx = 0;
        now = npf_mono_ms();
        for (i = 0; i < k; i++) {
            uint16_t lp;
            int s = udp_socket(&lp);
            if (s < 0)
                break;
            if (npf_loop_add(p->loop, s, NPF_EV_READ, ev_alloc_cb, p) < 0) {
                npf_sock_close(s);
                break;
            }
            p->res.alloc_local[p->ntx] = lp;
            tx_init(&p->txs[p->ntx], s, &p->cfg.ep[0], now + (int64_t)i * ALLOC_SPREAD_MS / k);
            p->ntx++;
        }
        if (p->ntx > 0) {
            ev_pump(p);
            return;
        }
    } else if (p->phase == 2) {
        int f = collect_alloc(&p->res, p->txs, p->ntx);
        struct sockaddr_in mf;
        memset(&mf, 0, sizeof mf);
        if (f >= 0) {
            p->ffd = p->txs[f].fd;
            mf = p->txs[f].mapped;
        }
        drop_alloc(p, p->ffd);
        p->phase = 3;
        p->ntx = filter_txs(&p->cfg, p->txs, p->cfg.main_fd, p->ffd, &mf, p->n_ep, npf_mono_ms());
        if (p->ntx > 0) {
            ev_pump(p);
            return;
        }
    } else {
        decide_filter(&p->res, p->txs, p->ntx);
    }
    finish_profile(&p->res);
    ev_finish(p, 1);
}

npf_natprobe *npf_natprobe_start(npf_loop *loop, const npf_natprobe_cfg *cfg, npf_natprobe_fn fn, void *arg)
{
    npf_natprobe *p;
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int i;
    if (cfg->n_ep < 1 || cfg->main_fd < 0 || getsockname(cfg->main_fd, (struct sockaddr *)&a, &alen) < 0)
        return NULL;
    p = calloc(1, sizeof *p);
    if (!p)
        return NULL;
    p->loop = loop;
    p->cfg = *cfg;
    p->fn = fn;
    p->arg = arg;
    p->n_ep = cfg->n_ep < 3 ? cfg->n_ep : 3;
    p->res.local_port = ntohs(a.sin_port);
    npf_siv_derive(&p->keys, cfg->probe_key, NPF_SIV_LABEL_PROBE);
    p->phase = 1;
    p->ffd = -1;
    p->ntx = p->n_ep;
    for (i = 0; i < p->n_ep; i++)
        tx_init(&p->txs[i], cfg->main_fd, &cfg->ep[i], npf_mono_ms());
    ev_pump(p);
    return p;
}

int npf_natprobe_input(npf_natprobe *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    const struct sockaddr_in *f = (const struct sockaddr_in *)from;
    int i, ours = 0;
    if (!p || (p->phase != 1 && p->phase != 3) || fd != p->cfg.main_fd || from->ss_family != AF_INET)
        return 0;
    if (len > NPF_PKT_MAX)
        return 0;                   /* never a probe server's: and tx_input opens into NPF_PKT_MAX bytes */
    for (i = 0; i < p->n_ep && !ours; i++)
        ours = npf_addr_eq(f, &p->cfg.ep[i]);
    if (!ours)
        return 0;                   /* not from a probe server: the node's */
    tx_input(&p->cfg, &p->keys, p->txs, p->ntx, fd, buf, len, f);
    npf_timer_stop(p->loop, &p->t);
    ev_pump(p);                     /* may finish the probe: p is gone then */
    return 1;
}

void npf_natprobe_cancel(npf_natprobe *p)
{
    if (!p)
        return;
    npf_timer_cancel(p->loop, p->t);
    if (p->phase == 2)
        drop_alloc(p, -1);
    if (p->phase == 3 && p->ffd >= 0) {
        npf_loop_del(p->loop, p->ffd);
        npf_sock_close(p->ffd);
    }
    free(p);
}

#ifdef NPF_TOOLS_API   /* the tools' (CMake NPF_TOOLS_API): a node uses npf_natprobe_start */
typedef struct run {
    npf_natprobe        *p;
    npf_natprobe_result *res;
    int                  done, ok;
} run;

static void run_done(int ok, const npf_natprobe_result *res, void *arg)
{
    run *r = arg;
    *r->res = *res;
    r->ok = ok;
    r->done = 1;
}

/* the main socket's datagrams: one each time (it may be the caller's
 * blocking socket) */
static void run_input(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    run *r = arg;
    uint8_t buf[NPF_PKT_MAX];
    struct sockaddr_storage from;
    socklen_t flen = sizeof from;
    ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
    (void)loop;
    (void)ev;
    if (n > 0 && !r->done)
        npf_natprobe_input(r->p, fd, buf, (size_t)n, &from);
}

int npf_natprobe_run(const npf_natprobe_cfg *cfg, npf_natprobe_result *res)
{
    npf_natprobe_cfg c = *cfg;
    npf_loop *loop = npf_loop_new();
    run r;
    int own = -1;
    uint16_t lp;
    memset(res, 0, sizeof(*res));
    memset(&r, 0, sizeof r);
    r.res = res;
    if (!loop)
        return -1;
    if (c.main_fd < 0)
        c.main_fd = own = udp_socket(&lp);
    if (c.main_fd >= 0 && npf_loop_add(loop, c.main_fd, NPF_EV_READ, run_input, &r) == 0) {
        if ((r.p = npf_natprobe_start(loop, &c, run_done, &r)) != NULL)
            while (!r.done)
                npf_loop_once(loop, 100);
        npf_loop_del(loop, c.main_fd);
    }
    npf_sock_close(own);
    npf_loop_free(loop);
    return r.ok ? 0 : -1;
}
#endif

const char *npf_nat_mapping_str(int mapping)
{
    switch (mapping) {
    case NPF_MAP_EIM:  return "EIM";
    case NPF_MAP_ADM:  return "ADM";
    case NPF_MAP_APDM: return "APDM";
    default:           return "UNKNOWN";
    }
}

const char *npf_nat_filter_str(int filtering)
{
    switch (filtering) {
    case NPF_FILT_EIF:  return "EIF";
    case NPF_FILT_ADF:  return "ADF";
    case NPF_FILT_APDF: return "APDF";
    default:            return "UNKNOWN";
    }
}

const char *npf_nat_alloc_str(int allocation)
{
    switch (allocation) {
    case NPF_ALLOC_PRESERVE:   return "PRESERVE";
    case NPF_ALLOC_SEQUENTIAL: return "SEQUENTIAL";
    case NPF_ALLOC_BLOCK:      return "BLOCK";
    case NPF_ALLOC_RANDOM:     return "RANDOM";
    default:                   return "UNKNOWN";
    }
}

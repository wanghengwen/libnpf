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

typedef struct tx {
    int      fd;
    struct sockaddr_in dst;
    uint8_t  txid[NPF_TXID_SIZE];
    int64_t  start;             /* monotonic ms */
    int      sent;
    int      done;
    /* result */
    struct sockaddr_in mapped;
    int      rtt_ms;
    int64_t  srv_offset_ms;
} tx;

static uint32_t wire_ts(int64_t offset)
{
    return (uint32_t)(npf_unix_ms() + offset);
}

static const char *fmt_addr(const struct sockaddr_in *a, char *buf, size_t n)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
    snprintf(buf, n, "%s:%u", ip, ntohs(a->sin_port));
    return buf;
}

static void tx_send(const npf_natprobe_cfg *cfg, const npf_siv_keys *keys, tx *t)
{
    uint8_t wire[NPF_PKT_MAX];
    size_t len = npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
    int n = npf_pkt_seal(keys, NPF_DIR_REQ, NPF_PKT_BIND_REQ, t->txid, wire_ts(cfg->clock_offset_ms),
                         cfg->ticket, NPF_TICKET_SIZE, len, wire);
    if (n > 0)
        (void)npf_udp_send(t->fd, wire, (size_t)n, &t->dst);
    t->sent++;
    if (npf_log_on(NPF_LOG_TRACE)) {
        char a[64];
        npf_logt("natprobe: fd %d -> %s BIND_REQ #%d (%zu bytes)", t->fd, fmt_addr(&t->dst, a, sizeof(a)), t->sent, len);
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
            npf_logt("natprobe: fd %d <- %s %zu bytes: not a valid BIND_RESP", fd, fmt_addr(from, a, sizeof(a)), len);
        return 0;
    }
    for (i = 0; i < n; i++) {
        tx *t = &txs[i];
        if (t->done || t->fd != fd || memcmp(t->txid, pkt.txid, NPF_TXID_SIZE) != 0)
            continue;
        /* the server answers from the endpoint we asked */
        if (from->sin_addr.s_addr != t->dst.sin_addr.s_addr || from->sin_port != t->dst.sin_port)
            continue;
        if (resp.family != 4)
            continue;
        t->done = 1;
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
                    fmt_addr(from, a, sizeof(a)), fmt_addr(&t->mapped, m, sizeof(m)), t->rtt_ms);
        }
        return 1;
    }
    if (npf_log_on(NPF_LOG_TRACE))
        npf_logt("natprobe: fd %d <- %s stray BIND_RESP", fd, fmt_addr(from, a, sizeof(a)));
    return 1;
}

/* drive a set of transactions until all are answered or have given up */
static void tx_run(const npf_natprobe_cfg *cfg, const npf_siv_keys *keys, tx *txs, int n)
{
    struct pollfd pfd[1 + NPF_NATPROBE_MAX_ALLOC];
    int nfd = 0, i, j;

    for (i = 0; i < n; i++) {
        for (j = 0; j < nfd && (int)pfd[j].fd != txs[i].fd; j++)
            ;
        if (j == nfd) {
            pfd[nfd].fd = txs[i].fd;
            pfd[nfd].events = POLLIN;
            nfd++;
        }
    }
    for (;;) {
        int64_t now = npf_mono_ms(), wake = -1;
        int pending = 0;
        for (i = 0; i < n; i++) {
            tx *t = &txs[i];
            int64_t due;
            if (t->done)
                continue;
            if (now - t->start >= TX_GIVEUP_MS) {
                t->done = -1;
                continue;
            }
            pending = 1;
            while (t->sent < TX_SENDS && now - t->start >= k_send_at[t->sent])
                tx_send(cfg, keys, t);
            due = t->sent < TX_SENDS ? t->start + k_send_at[t->sent] : t->start + TX_GIVEUP_MS;
            if (wake < 0 || due < wake)
                wake = due;
        }
        if (!pending)
            return;
        if (poll(pfd, (nfds_t)nfd, (int)(wake > now ? wake - now : 0)) <= 0)
            continue;
        for (j = 0; j < nfd; j++) {
            uint8_t buf[NPF_PKT_MAX];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t r;
            if (!(pfd[j].revents & POLLIN))
                continue;
            r = recvfrom(pfd[j].fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (r > 0 && from.sin_family == AF_INET)
                tx_input(cfg, keys, txs, n, pfd[j].fd, buf, (size_t)r, &from);
        }
    }
}

/* blocking for the probe run with poll(); not for the event loop's: there
 * ev_alloc_cb reads until nothing is left, and MSG_DONTWAIT is 0 on Windows */
static int udp_socket(uint16_t *local_port, int blocking)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int fd = npf_udp_socket(AF_INET, blocking);
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
    npf_random(t->txid, sizeof(t->txid));
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

static int same_ep(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

/* port allocation from K (local, mapped) samples, 4.2 */
static void classify_alloc(npf_natprobe_result *res)
{
    uint16_t p[NPF_NATPROBE_MAX_ALLOC];
    int n = 0, i, preserve = 1, best = 0, best_cnt = 0, ok = 1;
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
    /* sequential: deltas small and positive, the most common one is the step
     * (other traffic behind the same NAT may take a port now and then) */
    for (i = 0; i + 1 < n; i++) {
        int d = (int16_t)(uint16_t)(p[i + 1] - p[i]), j, cnt = 0;
        if (d <= 0 || d > 64)
            ok = 0;
        for (j = 0; j + 1 < n; j++)
            if ((int16_t)(uint16_t)(p[j + 1] - p[j]) == d)
                cnt++;
        if (cnt > best_cnt) {
            best_cnt = cnt;
            best = d;
        }
    }
    if (ok && best > 0 && best <= 16 && best_cnt * 2 >= n - 1) {
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
    if (n_ep >= 2 && res->got[1] && !same_ep(&res->mapped[0], &res->mapped[1]))
        res->profile.mapping = NPF_MAP_APDM;
    else if (n_ep >= 3 && res->got[1] && res->got[2]) {
        if (res->mapped[2].sin_addr.s_addr != res->mapped[0].sin_addr.s_addr) {
            res->profile.ip_varies = 1;
            res->profile.mapping = NPF_MAP_ADM;
        } else if (same_ep(&res->mapped[0], &res->mapped[2]))
            res->profile.mapping = NPF_MAP_EIM;
        else
            res->profile.mapping = NPF_MAP_ADM;
    } else
        res->profile.mapping = NPF_MAP_UNKNOWN;
    return 0;
}

/* phase 2 results: the allocation behaviour */
static void collect_alloc(npf_natprobe_result *res, const tx *txs, int n)
{
    int i;
    res->alloc_n = n;
    for (i = 0; i < n; i++) {
        res->alloc_got[i] = txs[i].done > 0;
        if (res->alloc_got[i])
            res->alloc_mapped[i] = ntohs(txs[i].mapped.sin_port);
    }
    classify_alloc(res);
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
    cfg->main_fd = -1;
}

int npf_natprobe_run(const npf_natprobe_cfg *cfg, npf_natprobe_result *res)
{
    npf_siv_keys keys;
    tx txs[NPF_NATPROBE_MAX_ALLOC];
    int fd, i, k, n_ep = cfg->n_ep < 3 ? cfg->n_ep : 3;
    int64_t now;

    memset(res, 0, sizeof(*res));
    if (n_ep < 1)
        return -1;
    npf_siv_derive(&keys, cfg->probe_key, NPF_SIV_LABEL_PROBE);

    /* 1. mapping behaviour: one socket, E1/E2/E3 in parallel */
    if (cfg->main_fd >= 0) {
        struct sockaddr_in a;
        socklen_t alen = sizeof(a);
        fd = cfg->main_fd;
        if (getsockname(fd, (struct sockaddr *)&a, &alen) < 0)
            return -1;
        res->local_port = ntohs(a.sin_port);
    } else {
        fd = udp_socket(&res->local_port, 1);
        if (fd < 0)
            return -1;
    }
    now = npf_mono_ms();
    for (i = 0; i < n_ep; i++)
        tx_init(&txs[i], fd, &cfg->ep[i], now);
    tx_run(cfg, &keys, txs, n_ep);
    if (fd != cfg->main_fd)
        npf_sock_close(fd);
    if (decide_mapping(res, txs, n_ep) < 0)
        return -1;

    /* 2. port allocation: K fresh sockets to E1, spread over 200 ms */
    k = cfg->alloc_sockets < NPF_NATPROBE_MAX_ALLOC ? cfg->alloc_sockets : NPF_NATPROBE_MAX_ALLOC;
    if (k > 0) {
        int n = 0;
        now = npf_mono_ms();
        for (i = 0; i < k; i++) {
            uint16_t lp;
            int s = udp_socket(&lp, 1);
            if (s < 0)
                break;
            res->alloc_local[n] = lp;
            tx_init(&txs[n], s, &cfg->ep[0], now + (int64_t)i * ALLOC_SPREAD_MS / k);
            n++;
        }
        tx_run(cfg, &keys, txs, n);
        collect_alloc(res, txs, n);
        for (i = 0; i < n; i++)
            npf_sock_close(txs[i].fd);
    }
    finish_profile(res);
    return 0;
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
    int              phase;     /* 1 mapping (main socket), 2 allocation */
    int              n_ep;
    tx               txs[NPF_NATPROBE_MAX_ALLOC];
    int              ntx;
    npf_timer       *t;
    npf_natprobe_result res;
};

static void ev_pump(npf_natprobe *p);

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
    (void)loop;
    (void)ev;
    for (;;) {
        uint8_t buf[NPF_PKT_MAX];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t r = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
        if (r <= 0)
            break;
        if (from.sin_family == AF_INET)
            tx_input(&p->cfg, &p->keys, p->txs, p->ntx, fd, buf, (size_t)r, &from);
    }
    if (p->t)
        npf_timer_cancel(p->loop, p->t);
    p->t = NULL;
    ev_pump(p);
}

/* send what is due; when every transaction of the phase is over, go on */
static void ev_pump(npf_natprobe *p)
{
    int64_t now = npf_mono_ms(), wake = -1;
    int i, k, pending = 0;
    for (i = 0; i < p->ntx; i++) {
        tx *t = &p->txs[i];
        int64_t due;
        if (t->done)
            continue;
        if (now - t->start >= TX_GIVEUP_MS) {
            t->done = -1;
            continue;
        }
        pending = 1;
        while (t->sent < TX_SENDS && now - t->start >= k_send_at[t->sent])
            tx_send(&p->cfg, &p->keys, t);
        due = t->sent < TX_SENDS ? t->start + k_send_at[t->sent] : t->start + TX_GIVEUP_MS;
        if (wake < 0 || due < wake)
            wake = due;
    }
    if (pending) {
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
            int s = udp_socket(&lp, 0);
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
    } else {
        collect_alloc(&p->res, p->txs, p->ntx);
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
    if (!p || p->phase != 1 || fd != p->cfg.main_fd || from->ss_family != AF_INET)
        return 0;
    for (i = 0; i < p->n_ep && !ours; i++)
        ours = same_ep(f, &p->cfg.ep[i]);
    if (!ours)
        return 0;                   /* not from a probe server: the node's */
    tx_input(&p->cfg, &p->keys, p->txs, p->ntx, fd, buf, len, f);
    if (p->t)
        npf_timer_cancel(p->loop, p->t);
    p->t = NULL;
    ev_pump(p);                     /* may finish the probe: p is gone then */
    return 1;
}

void npf_natprobe_cancel(npf_natprobe *p)
{
    int i;
    if (!p)
        return;
    if (p->t)
        npf_timer_cancel(p->loop, p->t);
    if (p->phase == 2)
        for (i = 0; i < p->ntx; i++) {
            npf_loop_del(p->loop, p->txs[i].fd);
            npf_sock_close(p->txs[i].fd);
        }
    free(p);
}

const char *npf_nat_mapping_str(int mapping)
{
    switch (mapping) {
    case NPF_MAP_EIM:  return "EIM";
    case NPF_MAP_ADM:  return "ADM";
    case NPF_MAP_APDM: return "APDM";
    default:           return "UNKNOWN";
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

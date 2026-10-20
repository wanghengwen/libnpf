/* Event-driven hole punching on npf_loop (nat-traversal.md 7, 10). */
#define _DEFAULT_SOURCE
#include "npf/log.h"
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/platform.h"
#include "npf/punch.h"

#define S1_FAST_MS   2000
#define S1_FAST_IVL    50
#define S1_SLOW_IVL   200
#define S3_RESEND_MS 1000
#define NOM_GRACE_MS  200
#define NOM_IVL_MS    200
#define S3_EASY_LEAD  150
#define TICK_MS        10
#define TRIG_MAX       64   /* triggered checks per punch */
#define TRIG_GAP_MS   500   /* at most one per source this often */

typedef struct psock {
    int     fd;
    int     owned;
    int64_t next_send;
} psock;

struct npf_punch {
    npf_loop       *loop;
    npf_punch_cfg   cfg;
    npf_siv_keys    kp, kn;
    psock           socks[NPF_PUNCH_MAX_SOCKETS];
    int             nsock;
    int64_t         start, deadline, spray_next, nom_next, validated_at;
    int             sprayed, nom_sent, have_valid, win_sock, finished;
    int             win_fd;         /* the socket the winning path uses (socks[win_sock] or fd6) */
    struct { struct sockaddr_storage a; int sock; int64_t at; } trig[TRIG_MAX];
    int             ntrig;
    struct sockaddr_storage winner;
    npf_punch_result res;
    npf_timer      *tick;
    npf_punch_done_fn done;
    void           *arg;
};

static void st16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t ld16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static socklen_t ss_len(const struct sockaddr_storage *a)
{
    return a->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
}

static uint16_t ss_port(const struct sockaddr_storage *a)
{
    return ntohs(a->ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)a)->sin6_port
                                          : ((const struct sockaddr_in *)a)->sin_port);
}

static size_t sid_body(uint8_t *b, uint64_t sid)
{
    int i;
    for (i = 0; i < 8; i++)
        b[i] = (uint8_t)(sid >> (8 * i));
    return 8;
}

static uint64_t body_sid(const uint8_t *b)
{
    uint64_t s = 0;
    int i;
    for (i = 7; i >= 0; i--)
        s = (s << 8) | b[i];
    return s;
}

static size_t ack_body(uint8_t *b, uint64_t sid, uint16_t idx, const struct sockaddr_storage *seen)
{
    size_t n = sid_body(b, sid);
    st16(b + n, idx);
    n += 2;
    if (seen->ss_family == AF_INET6) {
        b[n++] = 6;
        st16(b + n, ss_port(seen));
        n += 2;
        memcpy(b + n, &((const struct sockaddr_in6 *)seen)->sin6_addr, 16);
        n += 16;
    } else {
        b[n++] = 4;
        st16(b + n, ss_port(seen));
        n += 2;
        memcpy(b + n, &((const struct sockaddr_in *)seen)->sin_addr, 4);
        n += 4;
    }
    return n;
}

static void send_pkt(int fd, const npf_siv_keys *keys, int dir, int type,
                     const uint8_t *body, size_t blen, const struct sockaddr_storage *to)
{
    uint8_t wire[256], txid[NPF_TXID_SIZE];
    size_t len = npf_rand_range(64, 256);
    int n;
    npf_random(txid, sizeof(txid));
    n = npf_pkt_seal(keys, dir, type, txid, (uint32_t)npf_mono_ms(), body, blen, len, wire);
    if (n > 0)
        (void)npf_udp_send(fd, wire, (size_t)n, to);
}

/* trace: "ADDR:PORT" for the punch lines */
static const char *ss_txt(const struct sockaddr_storage *a, char *buf, size_t cap)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    inet_ntop(a->ss_family, a->ss_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)a)->sin6_addr
                                                     : (const void *)&((const struct sockaddr_in *)a)->sin_addr,
              ip, sizeof ip);
    snprintf(buf, cap, "%s:%u", ip, ss_port(a));
    return buf;
}

static void probe(npf_punch *p, int sock, const struct sockaddr_storage *to)
{
    uint8_t b[16];
    size_t n = sid_body(b, p->cfg.plan.session_id);
    int fd = p->socks[sock].fd;
    if (sock == 0 && to->ss_family == AF_INET6) {     /* S0: IPv6 peers from the IPv6 socket */
        if (p->cfg.fd6 < 0)
            return;
        fd = p->cfg.fd6;
    }
    st16(b + n, (uint16_t)sock);
    send_pkt(fd, &p->kp, p->cfg.plan.role, NPF_PKT_PROBE, b, n + 2, to);
    if (sock == 0 && p->res.probes_sent < p->cfg.npeers && npf_log_on(NPF_LOG_TRACE)) {
        char a[64];     /* the first round, in candidate order */
        npf_logt("punch: PROBE -> %s", ss_txt(to, a, sizeof a));
    }
    p->res.probes_sent++;
}

static int same_ss(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family || ss_port(a) != ss_port(b))
        return 0;
    return a->ss_family == AF_INET6
               ? memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr, 16) == 0
               : ((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr;
}

/* A triggered check (ICE): a PROBE that came in shows a path from the peer
 * to this socket; probing back at once lets this side validate it too. In S3
 * the easy side's sprayed probe to a port often arrives before the hard
 * side's mapping exists and is lost, while the hard side's probes from that
 * mapping get through later (the easy side sent there): without probing back
 * the caller never sees a PROBE_ACK and cannot nominate (a Mac -> a host
 * behind a cloud NAT gateway, 2026-10-07: 6 probes in, none of its own
 * answered, the round failed). */
static void triggered(npf_punch *p, int sock, const struct sockaddr_storage *from)
{
    int64_t now = npf_mono_ms();
    int i;
    if (p->have_valid || p->finished)
        return;
    for (i = 0; i < p->ntrig; i++)
        if (p->trig[i].sock == sock && same_ss(&p->trig[i].a, from)) {
            if (now - p->trig[i].at < TRIG_GAP_MS)
                return;
            p->trig[i].at = now;
            probe(p, sock, from);
            return;
        }
    if (p->ntrig == TRIG_MAX)
        return;
    p->trig[p->ntrig].a = *from;
    p->trig[p->ntrig].sock = sock;
    p->trig[p->ntrig].at = now;
    p->ntrig++;
    if (npf_log_on(NPF_LOG_TRACE)) {
        char a[64];
        npf_logt("punch: triggered PROBE -> %s (sock %d)", ss_txt(from, a, sizeof a), sock);
    }
    probe(p, sock, from);
}

static void finish(npf_punch *p, int ok)
{
    int i, fd = -1;
    if (p->finished)
        return;
    p->finished = 1;
    p->res.ok = ok;
    p->res.elapsed_ms = (int)(npf_mono_ms() - p->start);
    if (p->tick) {
        npf_timer_cancel(p->loop, p->tick);
        p->tick = NULL;
    }
    if (ok) {
        struct sockaddr_storage la;
        socklen_t ll = sizeof la;
        fd = p->win_fd;
        p->res.peer = p->winner;
        p->res.peer_len = ss_len(&p->winner);
        p->res.sock_idx = p->win_sock;
        if (getsockname(fd, (struct sockaddr *)&la, &ll) == 0)
            p->res.local_port = ss_port(&la);
    }
    /* close the S3 sockets that lost; the winner goes to the owner */
    for (i = 0; i < p->nsock; i++) {
        if (p->socks[i].owned && !(ok && i == p->win_sock)) {
            npf_loop_del(p->loop, p->socks[i].fd);
            npf_sock_close(p->socks[i].fd);
            p->socks[i].fd = -1;
        }
        if (ok && i == p->win_sock && p->socks[i].owned) {
            npf_loop_del(p->loop, p->socks[i].fd);  /* the owner registers it again */
            p->socks[i].owned = 0;
        }
    }
    if (ok && p->win_sock != 0) {
        /* keep answering on the primary only */
        p->socks[0] = p->socks[p->win_sock];
    }
    if (ok && p->win_fd != p->socks[0].fd)
        p->socks[0].fd = p->win_fd;     /* fd6: late PROBE / NOMINATE arrive there */
    p->nsock = ok ? 1 : 0;
    if (ok)
        p->win_sock = 0;
    p->done(p, &p->res, fd, p->arg);
}

static void schedule(npf_punch *p);

static void tick_cb(npf_loop *loop, void *arg)
{
    npf_punch *p = arg;
    const npf_punch_plan *pl = &p->cfg.plan;
    int64_t now = npf_mono_ms();
    int i, k;
    (void)loop;
    p->tick = NULL;
    if (now >= p->deadline) {
        finish(p, 0);
        return;
    }
    if (pl->strategy == NPF_PUNCH_S1 || (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY)) {
        int64_t ivl = now - p->start < S1_FAST_MS ? S1_FAST_IVL : S1_SLOW_IVL;
        if (now >= p->socks[0].next_send) {
            for (k = 0; k < p->cfg.npeers; k++)
                probe(p, 0, &p->cfg.peers[k]);
            p->socks[0].next_send = now + ivl;
        }
    }
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD && p->nsock == 1) {
        /* no sockets of its own (the node's budget is held by other punches):
         * the main socket probes the peer, like S1 */
        int64_t ivl = now - p->start < S1_FAST_MS ? S1_FAST_IVL : S1_SLOW_IVL;
        if (now >= p->socks[0].next_send) {
            for (k = 0; k < p->cfg.npeers; k++)
                probe(p, 0, &p->cfg.peers[k]);
            p->socks[0].next_send = now + ivl;
        }
    }
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_HARD) {
        for (i = 1; i < p->nsock; i++) {
            if (now >= p->socks[i].next_send) {
                probe(p, i, &pl->peer_srflx);
                p->socks[i].next_send = now + S3_RESEND_MS;
            }
        }
    }
    if (pl->strategy == NPF_PUNCH_S3 && pl->side == NPF_PUNCH_EASY) {
        int64_t ivl = pl->pps > 0 ? 1000 / pl->pps : 5;
        uint16_t lo = pl->range_lo ? pl->range_lo : 1024;
        uint16_t hi = pl->range_hi ? pl->range_hi : 65535;
        if (ivl < 1)
            ivl = 1;
        while (p->sprayed < pl->m_total && now >= p->spray_next) {
            struct sockaddr_storage to;
            struct sockaddr_in *t4 = (struct sockaddr_in *)&to;
            memset(&to, 0, sizeof to);
            t4->sin_family = AF_INET;
            t4->sin_addr = pl->peer_ip4;
            t4->sin_port = htons((uint16_t)npf_rand_range(lo, hi));
            probe(p, 0, &to);
            p->sprayed++;
            p->spray_next += ivl;
        }
    }
    if (pl->role == NPF_PUNCH_CONTROLLING && p->have_valid) {
        uint8_t b[8];
        if ((!p->nom_sent && now >= p->validated_at + NOM_GRACE_MS) || (p->nom_sent && now >= p->nom_next)) {
            send_pkt(p->win_fd, &p->kn, pl->role, NPF_PKT_NOMINATE,
                     b, sid_body(b, pl->session_id), &p->winner);
            p->nom_sent = 1;
            p->nom_next = now + NOM_IVL_MS;
        }
    }
    schedule(p);
}

static void schedule(npf_punch *p)
{
    if (!p->tick && !p->finished)
        p->tick = npf_timer_add(p->loop, TICK_MS, tick_cb, p);
}

static int handle(npf_punch *p, int sock, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    const npf_punch_plan *pl = &p->cfg.plan;
    int peer_dir = 1 - pl->role;
    uint8_t plain[NPF_PKT_MAX];
    npf_pkt pkt;
    if (len > NPF_PKT_MAX || len < 64 || len > 256)
        return 0;
    if (npf_pkt_open(&p->kp, peer_dir, buf, len, plain, &pkt) == 0
        && (pkt.type == NPF_PKT_PROBE || pkt.type == NPF_PKT_PROBE_ACK)
        && pkt.body_len >= 10 && body_sid(pkt.body) == pl->session_id) {
        if (p->cfg.test_deaf)
            return 1;
        if (pkt.type == NPF_PKT_PROBE) {
            uint8_t b[40];
            p->res.probes_recv++;
            if (p->res.probes_recv <= 3 && npf_log_on(NPF_LOG_TRACE)) {
                char a[64];
                npf_logt("punch: PROBE from %s (sock %d, %d ms) -> PROBE_ACK", ss_txt(from, a, sizeof a), sock,
                         (int)(npf_mono_ms() - p->start));
            }
            send_pkt(fd, &p->kp, pl->role, NPF_PKT_PROBE_ACK,
                     b, ack_body(b, pl->session_id, ld16(pkt.body + 8), from), from);
            triggered(p, sock, from);
        } else {
            p->res.acks_recv++;
            if (!p->have_valid && !p->finished) {
                p->have_valid = 1;
                p->winner = *from;
                p->win_sock = sock;
                p->win_fd = fd;
                p->validated_at = npf_mono_ms();
                if (npf_log_on(NPF_LOG_TRACE)) {
                    char a[64];
                    npf_logt("punch: path validated via %s (sock %d, %d ms)", ss_txt(from, a, sizeof a), sock,
                             (int)(npf_mono_ms() - p->start));
                }
            }
        }
        return 1;
    }
    if (npf_pkt_open(&p->kn, peer_dir, buf, len, plain, &pkt) == 0
        && pkt.body_len >= 8 && body_sid(pkt.body) == pl->session_id) {
        if (pkt.type == NPF_PKT_NOMINATE && pl->role == NPF_PUNCH_CONTROLLED) {
            uint8_t b[8];
            send_pkt(fd, &p->kn, pl->role, NPF_PKT_NOMINATE_ACK,
                     b, sid_body(b, pl->session_id), from);
            if (!p->finished) {
                p->winner = *from;
                p->win_sock = sock;
                p->win_fd = fd;
                finish(p, 1);
            }
        } else if (pkt.type == NPF_PKT_NOMINATE_ACK && pl->role == NPF_PUNCH_CONTROLLING && p->nom_sent) {
            if (!p->finished) {
                p->res.rtt_ms = (int)(npf_mono_ms() - (p->nom_next - NOM_IVL_MS));
                if (p->res.rtt_ms < 0)
                    p->res.rtt_ms = 0;
                finish(p, 1);
            }
        }
        return 1;
    }
    return 0;
}

static void sock_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_punch *p = arg;
    int i;
    (void)loop;
    (void)ev;
    for (i = 1; i < p->nsock; i++)
        if (p->socks[i].fd == fd)
            break;
    if (i >= p->nsock)
        return;
    for (;;) {
        uint8_t buf[512];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        handle(p, i, fd, buf, (size_t)r, &from);
        if (p->finished)
            break;  /* the socket table changed */
    }
}

npf_punch *npf_punch_new(npf_loop *loop, const npf_punch_cfg *cfg, int primary_fd,
                         npf_punch_done_fn done, void *arg)
{
    npf_punch *p = calloc(1, sizeof *p);
    int i;
    if (!p)
        return NULL;
    p->loop = loop;
    p->cfg = *cfg;
    p->done = done;
    p->arg = arg;
    p->res.sock_idx = -1;
    p->res.rtt_ms = -1;
    npf_siv_derive(&p->kp, cfg->plan.punch_key, NPF_SIV_LABEL_PUNCH);
    npf_siv_derive(&p->kn, cfg->plan.nominate_key, NPF_SIV_LABEL_NOMIN);
    p->start = npf_mono_ms();
    p->deadline = p->start + (cfg->plan.timeout_ms > 0 ? cfg->plan.timeout_ms : 8000);
    p->socks[0].fd = primary_fd;
    p->socks[0].next_send = p->start;
    p->nsock = 1;
    if (cfg->plan.strategy == NPF_PUNCH_S3 && cfg->plan.side == NPF_PUNCH_EASY)
        p->spray_next = p->start + S3_EASY_LEAD;
    if (cfg->plan.strategy == NPF_PUNCH_S3 && cfg->plan.side == NPF_PUNCH_HARD) {
        int n = cfg->plan.n_sockets;
        if (n > NPF_PUNCH_MAX_SOCKETS - 1)
            n = NPF_PUNCH_MAX_SOCKETS - 1;
        for (i = 0; i < n; i++) {
            struct sockaddr_in a;
            int fd = npf_udp_socket(AF_INET, 0);
            if (fd < 0)
                break;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || npf_loop_add(loop, fd, NPF_EV_READ, sock_cb, p) < 0) {
                npf_sock_close(fd);
                break;
            }
            p->socks[p->nsock].fd = fd;
            p->socks[p->nsock].owned = 1;
            p->socks[p->nsock].next_send = p->start + (i % 50);   /* spread the first burst */
            p->nsock++;
        }
    }
    schedule(p);
    return p;
}

int npf_punch_input(npf_punch *p, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    if (!p || p->nsock == 0 || (fd != p->socks[0].fd && (p->cfg.fd6 < 0 || fd != p->cfg.fd6)))
        return 0;
    return handle(p, 0, fd, buf, len, from);
}

int npf_punch_finished(const npf_punch *p)
{
    return p->finished;
}

void npf_punch_free(npf_punch *p)
{
    int i;
    if (!p)
        return;
    if (p->tick)
        npf_timer_cancel(p->loop, p->tick);
    for (i = 0; i < p->nsock; i++) {
        if (p->socks[i].owned && p->socks[i].fd >= 0) {
            npf_loop_del(p->loop, p->socks[i].fd);
            npf_sock_close(p->socks[i].fd);
        }
    }
    free(p);
}

#define _DEFAULT_SOURCE
#include "npf/log.h"
#include "npf/sys.h"
#include <stdio.h>
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

static const char *ss_str(const struct sockaddr_storage *a, char *b, size_t n)
{
    char ip[INET6_ADDRSTRLEN];
    if (a->ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)a)->sin6_addr, ip, sizeof(ip));
        snprintf(b, n, "[%s]:%u", ip, ss_port(a));
    } else {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)a)->sin_addr, ip, sizeof(ip));
        snprintf(b, n, "%s:%u", ip, ss_port(a));
    }
    return b;
}

/* PROBE body: session_id(8) | sock_idx(2); PROBE_ACK appends the seen source. */
static size_t probe_body(uint8_t *b, uint64_t sid, uint16_t idx)
{
    int i;
    for (i = 0; i < 8; i++)
        b[i] = (uint8_t)(sid >> (8 * i));
    st16(b + 8, idx);
    return 10;
}

static size_t ack_body(uint8_t *b, uint64_t sid, uint16_t idx, const struct sockaddr_storage *seen)
{
    size_t n = probe_body(b, sid, idx);
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

static size_t nom_body(uint8_t *b, uint64_t sid)
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

static int send_pkt(int fd, const npf_siv_keys *keys, int dir, int type,
                    const uint8_t *body, size_t blen, const struct sockaddr_storage *to)
{
    uint8_t wire[256], txid[NPF_TXID_SIZE];
    size_t len = npf_rand_range(64, 256);
    int n;
    npf_random(txid, sizeof(txid));
    n = npf_pkt_seal(keys, dir, type, txid, (uint32_t)npf_mono_ms(), body, blen, len, wire);
    if (n < 0)
        return -1;
    return npf_udp_send(fd, wire, (size_t)n, to);
}

typedef struct psock {
    int     fd;
    int     owned;
    int64_t next_send;
} psock;

int npf_punch_run(const npf_punch_plan *plan, int primary_fd, npf_punch_result *res)
{
    npf_siv_keys kp, kn;
    int peer_dir = 1 - plan->role;
    int fam = plan->family ? plan->family : AF_INET;
    psock socks[NPF_PUNCH_MAX_SOCKETS];
    int nsock = 0, i;
    int64_t start, deadline, spray_next = 0, nom_next = 0, validated_at = 0;
    int sprayed = 0, nom_sent = 0, have_valid = 0, win_sock = -1;
    struct sockaddr_storage winner;
    struct pollfd pfd[NPF_PUNCH_MAX_SOCKETS];
    char ab[80];

    memset(res, 0, sizeof(*res));
    res->sock_idx = -1;
    res->rtt_ms = -1;
    memset(&winner, 0, sizeof(winner));
    npf_siv_derive(&kp, plan->punch_key, NPF_SIV_LABEL_PUNCH);
    npf_siv_derive(&kn, plan->nominate_key, NPF_SIV_LABEL_NOMIN);
    start = npf_mono_ms();
    deadline = start + plan->timeout_ms;

    if (plan->strategy == NPF_PUNCH_S3 && plan->side == NPF_PUNCH_HARD) {
        int n = plan->n_sockets > NPF_PUNCH_MAX_SOCKETS ? NPF_PUNCH_MAX_SOCKETS : plan->n_sockets;
        for (i = 0; i < n; i++) {
            struct sockaddr_in a;
            int fd = npf_udp_socket(AF_INET, 1);
            if (fd < 0)
                break;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
                npf_sock_close(fd);
                break;
            }
            socks[nsock].fd = fd;
            socks[nsock].owned = 1;
            socks[nsock].next_send = start;
            nsock++;
        }
    } else {
        socks[0].fd = primary_fd;
        socks[0].owned = 0;
        socks[0].next_send = start;
        nsock = 1;
        if (plan->strategy == NPF_PUNCH_S3 && plan->side == NPF_PUNCH_EASY)
            spray_next = start + S3_EASY_LEAD;
    }
    if (nsock == 0)
        return -1;

    for (;;) {
        int64_t now = npf_mono_ms(), wake = deadline;
        if (now >= deadline)
            break;

        if (plan->strategy == NPF_PUNCH_S1) {
            int64_t ivl = now - start < S1_FAST_MS ? S1_FAST_IVL : S1_SLOW_IVL;
            if (now >= socks[0].next_send) {
                uint8_t b[16];
                send_pkt(socks[0].fd, &kp, plan->role, NPF_PKT_PROBE,
                         b, probe_body(b, plan->session_id, 0), &plan->peer_srflx);
                res->probes_sent++;
                socks[0].next_send = now + ivl;
            }
            if (socks[0].next_send < wake)
                wake = socks[0].next_send;
        } else if (plan->side == NPF_PUNCH_HARD) {
            for (i = 0; i < nsock; i++) {
                if (now >= socks[i].next_send) {
                    uint8_t b[16];
                    send_pkt(socks[i].fd, &kp, plan->role, NPF_PKT_PROBE,
                             b, probe_body(b, plan->session_id, (uint16_t)i), &plan->peer_srflx);
                    res->probes_sent++;
                    socks[i].next_send = now + S3_RESEND_MS;
                }
                if (socks[i].next_send < wake)
                    wake = socks[i].next_send;
            }
        } else {
            int64_t ivl = plan->pps > 0 ? 1000 / plan->pps : 5;
            if (ivl < 1)
                ivl = 1;
            while (sprayed < plan->m_total && now >= spray_next) {
                struct sockaddr_storage to;
                struct sockaddr_in *t4 = (void *)&to;
                uint8_t b[16];
                uint16_t lo = plan->range_lo ? plan->range_lo : 1024;
                uint16_t hi = plan->range_hi ? plan->range_hi : 65535;
                memset(&to, 0, sizeof(to));
                t4->sin_family = AF_INET;
                t4->sin_addr = plan->peer_ip4;
                /* lo > hi: the range wraps past 65535 (punch.h); npf_rand_range
                 * would always give lo */
                t4->sin_port = htons((uint16_t)(lo + npf_rand_range(0, (uint32_t)(uint16_t)(hi - lo))));
                send_pkt(socks[0].fd, &kp, plan->role, NPF_PKT_PROBE,
                         b, probe_body(b, plan->session_id, 0), &to);
                res->probes_sent++;
                sprayed++;
                spray_next = now + ivl;
            }
            if (sprayed < plan->m_total && spray_next < wake)
                wake = spray_next;
        }

        if (plan->role == NPF_PUNCH_CONTROLLING && have_valid) {
            if (!nom_sent && now >= validated_at + NOM_GRACE_MS) {
                uint8_t b[8];
                send_pkt(socks[win_sock].fd, &kn, plan->role, NPF_PKT_NOMINATE,
                         b, nom_body(b, plan->session_id), &winner);
                nom_sent = 1;
                nom_next = now + NOM_IVL_MS;
                npf_logt("punch: NOMINATE -> %s", ss_str(&winner, ab, sizeof(ab)));
            } else if (nom_sent && now >= nom_next) {
                uint8_t b[8];
                send_pkt(socks[win_sock].fd, &kn, plan->role, NPF_PKT_NOMINATE,
                         b, nom_body(b, plan->session_id), &winner);
                nom_next = now + NOM_IVL_MS;
            }
            if (nom_sent && nom_next < wake)
                wake = nom_next;
            else if (!nom_sent && validated_at + NOM_GRACE_MS < wake)
                wake = validated_at + NOM_GRACE_MS;
        }

        for (i = 0; i < nsock; i++) {
            pfd[i].fd = socks[i].fd;
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }
        if (poll(pfd, (nfds_t)nsock, (int)(wake > now ? wake - now : 0)) <= 0)
            continue;

        for (i = 0; i < nsock; i++) {
            uint8_t buf[512], plain[512];
            struct sockaddr_storage from;
            socklen_t flen = sizeof(from);
            ssize_t r;
            npf_pkt pkt;
            if (!(pfd[i].revents & POLLIN))
                continue;
            r = recvfrom(socks[i].fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (r <= 0)
                continue;

            if (npf_pkt_open(&kp, peer_dir, buf, (size_t)r, plain, &pkt) == 0
                && (pkt.type == NPF_PKT_PROBE || pkt.type == NPF_PKT_PROBE_ACK)
                && pkt.body_len >= 10 && body_sid(pkt.body) == plan->session_id) {
                if (pkt.type == NPF_PKT_PROBE) {
                    uint8_t b[32];
                    res->probes_recv++;
                    send_pkt(socks[i].fd, &kp, plan->role, NPF_PKT_PROBE_ACK,
                             b, ack_body(b, plan->session_id, ld16(pkt.body + 8), &from), &from);
                    npf_logt("punch: PROBE from %s sock %d -> ACK", ss_str(&from, ab, sizeof(ab)), i);
                } else {
                    res->acks_recv++;
                    if (!have_valid) {
                        have_valid = 1;
                        winner = from;
                        win_sock = i;
                        validated_at = npf_mono_ms();
                        npf_logt("punch: PROBE_ACK from %s sock %d (validated)",
                                    ss_str(&from, ab, sizeof(ab)), i);
                    }
                }
                continue;
            }
            if (npf_pkt_open(&kn, peer_dir, buf, (size_t)r, plain, &pkt) == 0
                && pkt.body_len >= 8 && body_sid(pkt.body) == plan->session_id) {
                /* as punch_ev.c: each side takes only its own half of the
                 * exchange; an ACK before our NOMINATE has no win_sock */
                if (pkt.type == NPF_PKT_NOMINATE && plan->role == NPF_PUNCH_CONTROLLED) {
                    uint8_t b[8];
                    send_pkt(socks[i].fd, &kn, plan->role, NPF_PKT_NOMINATE_ACK,
                             b, nom_body(b, plan->session_id), &from);
                    winner = from;
                    win_sock = i;
                    res->ok = 1;
                    npf_logt("punch: NOMINATE from %s sock %d -> ACK (done)",
                                ss_str(&from, ab, sizeof(ab)), i);
                    goto finish;
                } else if (pkt.type == NPF_PKT_NOMINATE_ACK && plan->role == NPF_PUNCH_CONTROLLING && nom_sent) {
                    res->ok = 1;
                    res->rtt_ms = (int)(npf_mono_ms() - (validated_at + NOM_GRACE_MS));
                    if (res->rtt_ms < 0)
                        res->rtt_ms = 0;
                    npf_logt("punch: NOMINATE_ACK from %s (done)", ss_str(&from, ab, sizeof(ab)));
                    goto finish;
                }
            }
        }
    }

finish:
    (void)fam;
    res->elapsed_ms = (int)(npf_mono_ms() - start);
    if (res->ok) {
        struct sockaddr_storage la;
        socklen_t llen = sizeof(la);
        res->peer = winner;
        res->peer_len = ss_len(&winner);
        res->sock_idx = win_sock;
        if (getsockname(socks[win_sock].fd, (struct sockaddr *)&la, &llen) == 0)
            res->local_port = ss_port(&la);
    }
    for (i = 0; i < nsock; i++)
        if (socks[i].owned)
            npf_sock_close(socks[i].fd);
    return res->ok ? 0 : -1;
}

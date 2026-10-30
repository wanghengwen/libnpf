/* UDP signaling: the node's session with one server (npf/sig.h,
 * signaling-udp.md 3-6). Integers little-endian.
 *
 *   handshake  tag(12) | ChaCha20(P), keys from the server's dh_pub under
 *              "NPF-SIGHS-v1" (nat-traversal.md 6.2, npf/siv.h)
 *              P = type | flags(0) | body_len(2) | txid(12) | ts_ms(4) | body | random pad
 *     SIG_HELLO      [160, 256] bytes, body = noise1(48) | cookie_mac(16)
 *     SIG_COOKIE     body = cookie(16): SIG_HELLO again with cookie_mac =
 *                    BLAKE2b-128(key = cookie, P[0..68))
 *     SIG_HELLO_ACK  body = noise2(52), its payload srv_idx(4)
 *     message 3      srv_idx(4) | noise3, its payload 0..64 random bytes;
 *                    sent again on each RTO until a transport packet comes
 *   transport  node -> server  srv_idx(4) | ctr(8) | AEAD(k1, ad = srv_idx | ctr)
 *              server -> node  ctr(8) | AEAD(k2, ad = ctr)
 *              nonce 0(4) | ctr(8); a 64-packet replay window
 *              plaintext flags | ack(2) [| sn(2) | data]: a pure ack (3
 *              bytes, flags 0), a segment (END: a message's last), or
 *              CLOSE (flags 0x02 alone, then a reason of 0..32 bytes)
 *
 * The reliable layer: 16-bit segment numbers, cumulative acks, 32 segments
 * in flight, an RTO (RFC 6298, Karn) of 200 ms .. 1 s that resends the
 * oldest segment only; the receiver keeps segments out of order. After an
 * RTO, until what was in flight then is acked, an ack that moves but leaves
 * some of it unacked resends the new oldest at once (NewReno's partial
 * ack): k holes cost an RTO and k round trips, not k RTOs. Every
 * datagram with a segment is answered with the current ack (a segment of
 * ours rides along when there is one); an empty message is a ping. Nothing
 * reaches the reliable layer or the JSON parser before the AEAD and the
 * replay check pass (signaling-udp.md 9.1). */
#define _DEFAULT_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "npf/bind.h"
#include "npf/log.h"
#include "npf/platform.h"
#include "npf/siv.h"

#include "sig_int.h"

#define LABEL       "NPF-SIGHS-v1"      /* exactly 12 bytes */
#define PROLOGUE    "npf-sigudp-v1"
enum { SIG_HELLO = 11, SIG_HELLO_ACK = 12, SIG_COOKIE = 13 };
#define HELLO_MIN   160
#define HELLO_MAX   256
#define NOISE1_LEN  48
#define NOISE2_LEN  52
#define MAC_LEN     16                  /* the cookie, cookie_mac */
#define MAC_OVER    (NPF_PKT_HDR_SIZE + NOISE1_LEN)    /* 68: what cookie_mac covers */
#define PAD3_MAX    64
#define DGRAM_MAX   1200
#define SEG_DATA    (DGRAM_MAX - 4 - 8 - NPF_AEAD_TAG_SIZE - 5)   /* 1167 */
#define WND         32                  /* segments in flight, kept out of order */
#define QUEUE_MAX   256                 /* messages waiting: more closes the session */
#define RTO_MIN     200
#define RTO_MAX     1000
#define GIVE_UP_MS  7500
#define COOKIE_MS   120000
#define REASON_MAX  32
#define F_END       1
#define F_CLOSE     2

static const int hello_at[] = {0, 500, 1500, 3500};
#define NHELLO      (int)(sizeof hello_at / sizeof hello_at[0])

enum { SU_HELLO, SU_FINISH, SU_UP };

typedef struct omsg {                   /* a message to send, segments sn0 .. sn0 + nseg - 1 */
    struct omsg *next;
    uint16_t     sn0, nseg;
    size_t       len;
    uint8_t      d[];
} omsg;

typedef struct sigudp {
    npf_loop          *loop;
    npf_sig_send_fn    send_fn;          /* not "send": Winsock's macro (npf/sys.h) */
    struct sockaddr_in srv;
    npf_sig_cookie    *ck;
    npf_timer          t;               /* the next hello, else the RTO (embedded: npf/loop.h) */
    int                state;
    const char        *fail;            /* a failure to report from the timer (not inside a send) */
    /* the handshake */
    npf_siv_keys       hk;
    npf_noise_hs       hs;
    int64_t            t0;
    int                nhello;
    uint8_t            txid[NPF_TXID_SIZE], m1[NOISE1_LEN], cookie[MAC_LEN];
    int                has_cookie;
    uint8_t            idx[4], m3[4 + 48 + NPF_AEAD_TAG_SIZE + PAD3_MAX];
    size_t             m3_len;
    /* the transport */
    uint8_t            k1[32], k2[32];
    uint64_t           tx_ctr, rx_top, rx_bits;     /* rx_top: the highest ctr + 1, 0 none */
    int64_t            last_rx;
    /* sending */
    omsg              *q, **q_end;
    int                nq;
    uint16_t           snd_una, snd_nxt, sn_tail;
    uint16_t           recover;         /* after an RTO: snd_nxt then (recovering: partial acks resend) */
    int                recovering;
    int64_t            seg_at[WND];
    uint8_t            seg_once[WND];   /* sent once: an RTT sample (Karn) */
    int                has_rtt, srtt, rttvar, rto;
    unsigned           retrans;
    /* receiving */
    uint16_t           rcv_nxt;
    int                ack_due;
    uint8_t           *ooo[WND];        /* by sn % WND */
    uint16_t           ooo_len[WND];
    uint8_t            ooo_end[WND];
    uint8_t           *ra;              /* a message being put together, NPF_JSON_MAX_SIZE bytes */
    size_t             ra_len;
} sigudp;

static void timer_cb(npf_loop *loop, void *arg);

static void out(npf_sig *s, const uint8_t *p, size_t len)
{
    (void)s->udp->send_fn(p, len, &s->udp->srv, s->arg);
    s->last_tx = npf_mono_ms();
}

static uint16_t in_flight(const sigudp *u) { return (uint16_t)(u->snd_nxt - u->snd_una); }

/* ---- the handshake ---- */

static void hello_send(npf_sig *s)
{
    sigudp *u = s->udp;
    uint8_t w[HELLO_MAX], *p = w + NPF_SIV_TAG_SIZE;
    size_t wl = npf_rand_range(HELLO_MIN, HELLO_MAX), plen = wl - NPF_SIV_TAG_SIZE;
    p[0] = SIG_HELLO;
    p[1] = 0;
    npf_le16(p + 2, NOISE1_LEN + MAC_LEN);
    memcpy(p + 4, u->txid, NPF_TXID_SIZE);
    npf_le32(p + 16, (uint32_t)npf_mono_ms());          /* echoed: the round trip */
    memcpy(p + NPF_PKT_HDR_SIZE, u->m1, NOISE1_LEN);
    if (u->has_cookie)
        crypto_blake2b_keyed(p + MAC_OVER, MAC_LEN, u->cookie, MAC_LEN, p, MAC_OVER);
    else
        memset(p + MAC_OVER, 0, MAC_LEN);
    npf_random(p + MAC_OVER + MAC_LEN, plen - MAC_OVER - MAC_LEN);   /* the envelope's keys are public */
    npf_siv_seal(&u->hk, NPF_DIR_REQ, w, plen);
    out(s, w, wl);
}

/* the next hello on its schedule (0, 0.5, 1.5, 3.5 s), no answer by 7.5 s: down */
static void hello_due(npf_sig *s)
{
    sigudp *u = s->udp;
    if (u->nhello == NHELLO) {
        sig_down(s, NPF_SIG_DOWN_NO_ANSWER, "udp: no answer");
        return;
    }
    hello_send(s);
    u->nhello++;
    npf_timer_set(u->loop, &u->t, u->t0 + (u->nhello < NHELLO ? hello_at[u->nhello] : GIVE_UP_MS) - npf_mono_ms());
}

/* RTO = SRTT + 4 RTTVAR in [200 ms, 1 s]; no sample yet: 1 s */
static int rto_of(const sigudp *u)
{
    int rto = u->srtt + 4 * u->rttvar;
    return !u->has_rtt ? RTO_MAX : rto < RTO_MIN ? RTO_MIN : rto > RTO_MAX ? RTO_MAX : rto;
}

static void rtt_sample(sigudp *u, int r)
{
    if (!u->has_rtt) {
        u->has_rtt = 1;
        u->srtt = r;
        u->rttvar = r / 2;
    } else {
        u->rttvar = (3 * u->rttvar + abs(u->srtt - r)) / 4;
        u->srtt = (7 * u->srtt + r) / 8;
    }
    u->rto = rto_of(u);
}

/* the RTO timer: on while message 3 is unanswered or segments are in flight */
static void arm(npf_sig *s)
{
    sigudp *u = s->udp;
    if (u->fail)
        return;                         /* its timer runs */
    if (u->state == SU_FINISH || in_flight(u))
        npf_timer_set(u->loop, &u->t, u->rto);
    else
        npf_timer_cancel(u->loop, &u->t);
}

static void cookie_in(npf_sig *s, const uint8_t *c)
{
    sigudp *u = s->udp;
    char a[64];
    if (u->has_cookie && memcmp(u->cookie, c, MAC_LEN) == 0)
        return;
    memcpy(u->cookie, c, MAC_LEN);
    u->has_cookie = 1;
    if (u->ck) {
        u->ck->to = u->srv;
        memcpy(u->ck->c, c, MAC_LEN);
        u->ck->until = npf_mono_ms() + COOKIE_MS;
    }
    npf_log("signaling: server %s busy, handshake with a cookie", npf_addr_str(&u->srv, a, sizeof a));
    hello_send(s);
}

static void ack_hs_in(npf_sig *s, const uint8_t *noise2, uint32_t ts_ms)
{
    sigudp *u = s->udp;
    uint8_t pl[8], pad[PAD3_MAX];
    uint32_t r = (uint32_t)npf_mono_ms() - ts_ms;
    size_t np = npf_rand_range(0, PAD3_MAX);
    int k;
    if (npf_noise_read(&u->hs, noise2, NOISE2_LEN, pl, sizeof pl) != 4) {
        sig_down(s, NPF_SIG_DOWN_ERROR, "udp: server authentication failed");
        return;
    }
    memcpy(u->idx, pl, 4);              /* opaque, echoed as it came */
    memcpy(u->m3, u->idx, 4);
    npf_random(pad, np);
    k = npf_noise_write(&u->hs, pad, np, u->m3 + 4, sizeof u->m3 - 4);
    if (k < 0 || npf_noise_split(&u->hs, NULL, NULL, u->k1, u->k2, s->hash) < 0) {
        sig_down(s, NPF_SIG_DOWN_ERROR, "udp: noise handshake failed");
        return;
    }
    npf_wipe(&u->hs, sizeof u->hs);
    u->m3_len = 4 + (size_t)k;
    u->state = SU_FINISH;
    s->ready = 1;
    if (r <= GIVE_UP_MS)
        rtt_sample(u, (int)r);          /* the first sample; none: RTO 1 s */
    npf_logt("sig udp: handshake answered (rtt %u ms), rto %d ms", (unsigned)r, u->rto);
    out(s, u->m3, u->m3_len);
    arm(s);
    if (s->cbs.on_ready)
        s->cbs.on_ready(s, s->arg);     /* login goes out right after message 3 */
}

static void hs_in(npf_sig *s, const uint8_t *buf, size_t len)
{
    sigudp *u = s->udp;
    uint8_t plain[HELLO_MAX];
    npf_pkt pkt;
    /* the answers are no longer than our requests */
    if (len > HELLO_MAX || npf_pkt_open(&u->hk, NPF_DIR_RESP, buf, len, plain, &pkt) < 0 || plain[1] != 0
        || npf_ct_eq(pkt.txid, u->txid, NPF_TXID_SIZE) != 0)
        return;
    if (pkt.type == SIG_COOKIE && pkt.body_len == MAC_LEN) {
        u->last_rx = npf_mono_ms();
        cookie_in(s, pkt.body);
    } else if (pkt.type == SIG_HELLO_ACK && pkt.body_len == NOISE2_LEN) {
        u->last_rx = npf_mono_ms();
        ack_hs_in(s, pkt.body, pkt.ts_ms);
    }
}

/* ---- the transport ---- */

static int fresh(const sigudp *u, uint64_t ctr)
{
    uint64_t back;
    if (ctr == UINT64_MAX)
        return 0;
    if (ctr >= u->rx_top)
        return 1;
    back = u->rx_top - 1 - ctr;
    return back < 64 && !(u->rx_bits >> back & 1);
}

static void seen(sigudp *u, uint64_t ctr)
{
    if (ctr >= u->rx_top) {
        uint64_t sh = ctr + 1 - u->rx_top;
        u->rx_bits = sh >= 64 ? 0 : u->rx_bits << sh;
        u->rx_bits |= 1;
        u->rx_top = ctr + 1;
    } else {
        u->rx_bits |= 1ULL << (u->rx_top - 1 - ctr);
    }
}

static void pkt_send(npf_sig *s, const uint8_t *pt, size_t len)
{
    sigudp *u = s->udp;
    uint8_t w[DGRAM_MAX], nonce[12] = {0};
    memcpy(w, u->idx, 4);
    npf_le64(w + 4, u->tx_ctr++);
    memcpy(nonce + 4, w + 4, 8);
    if (npf_aead_seal(u->k1, nonce, w, 12, pt, len, w + 12) < 0)
        return;
    u->ack_due = 0;                     /* every packet carries the ack */
    out(s, w, 12 + len + NPF_AEAD_TAG_SIZE);
}

static void close_send(npf_sig *s, const char *reason)
{
    uint8_t pt[3 + REASON_MAX];
    size_t rl = strlen(reason);
    if (s->udp->state == SU_HELLO)
        return;                         /* no session at the server */
    pt[0] = F_CLOSE;
    npf_le16(pt + 1, s->udp->rcv_nxt);
    memcpy(pt + 3, reason, rl);
    pkt_send(s, pt, 3 + rl);
}

/* a protocol failure: CLOSE to the server, the session down */
static void fail(npf_sig *s, const char *reason, const char *why)
{
    close_send(s, reason);
    sig_down(s, NPF_SIG_DOWN_ERROR, why);
}

static void seg_send(npf_sig *s, uint16_t sn, int first)
{
    sigudp *u = s->udp;
    uint8_t pt[5 + SEG_DATA];
    omsg *m;
    uint16_t i;
    size_t off, dl;
    for (m = u->q; m && (uint16_t)(sn - m->sn0) >= m->nseg; m = m->next)
        ;
    if (!m)
        return;
    i = (uint16_t)(sn - m->sn0);
    off = (size_t)i * SEG_DATA;
    dl = m->len - off < SEG_DATA ? m->len - off : SEG_DATA;
    pt[0] = i == m->nseg - 1 ? F_END : 0;
    npf_le16(pt + 1, u->rcv_nxt);
    npf_le16(pt + 3, sn);
    memcpy(pt + 5, m->d + off, dl);
    pkt_send(s, pt, 5 + dl);
    npf_wipe(pt, 5 + dl);
    u->seg_at[sn % WND] = npf_mono_ms();
    u->seg_once[sn % WND] = (uint8_t)first;
}

/* new segments while the window has room */
static void try_send(npf_sig *s)
{
    sigudp *u = s->udp;
    while (u->snd_nxt != u->sn_tail && in_flight(u) < WND) {
        seg_send(s, u->snd_nxt, 1);
        u->snd_nxt++;
    }
    if (!npf_timer_pending(&u->t) && in_flight(u))
        arm(s);
}

static void rto_due(npf_sig *s)
{
    sigudp *u = s->udp;
    if (u->state == SU_FINISH)
        out(s, u->m3, u->m3_len);       /* until the server's first transport packet */
    if (in_flight(u)) {
        seg_send(s, u->snd_una, 0);     /* the oldest only */
        u->retrans++;
        u->recover = u->snd_nxt;
        u->recovering = 1;
    }
    npf_logt("sig udp: rto %d ms: resent%s%s (sn %u)", u->rto, u->state == SU_FINISH ? " message 3" : "",
             in_flight(u) ? " the oldest segment" : "", (unsigned)u->snd_una);
    u->rto = u->rto * 2 > RTO_MAX ? RTO_MAX : u->rto * 2;
    arm(s);
}

static void ack_in(npf_sig *s, uint16_t a)
{
    sigudp *u = s->udp;
    uint16_t d = (uint16_t)(a - u->snd_una), i;
    omsg *m;
    int once = 1;
    if (d == 0 || d > in_flight(u))
        return;                         /* nothing new, or outside what we sent: ignored */
    /* a sample from the newest segment acked, when none of those acked was
     * sent again (Karn; a segment that waited behind a hole would count
     * the hole's RTO in) */
    for (i = u->snd_una; i != a; i++)
        once &= u->seg_once[i % WND];
    if (once)
        rtt_sample(u, (int)(npf_mono_ms() - u->seg_at[(uint16_t)(a - 1) % WND]));
    u->rto = rto_of(u);                 /* the backoff ends */
    u->snd_una = a;
    while ((m = u->q) != NULL && (int16_t)(uint16_t)(m->sn0 + m->nseg - a) <= 0) {
        u->q = m->next;
        if (!u->q)
            u->q_end = &u->q;
        u->nq--;
        npf_wipe_free(m, sizeof *m + m->len);
    }
    if (u->recovering && (int16_t)(uint16_t)(a - u->recover) < 0) {
        seg_send(s, a, 0);              /* a partial ack: the next hole now */
        u->retrans++;
    } else
        u->recovering = 0;
    arm(s);
}

/* a whole message: to on_msg; an empty one is a ping */
static void deliver(npf_sig *s, const uint8_t *d, size_t len)
{
    const char *bad;
    if (len && (bad = sig_json(s, d, len)) != NULL)
        fail(s, "protocol", bad);
}

/* the next segment in order */
static void take(npf_sig *s, const uint8_t *d, size_t len, int end)
{
    sigudp *u = s->udp;
    uint8_t *ra;
    if (end && !u->ra) {
        deliver(s, d, len);             /* one segment, one message: no copy */
        return;
    }
    if (!u->ra && !(u->ra = malloc(NPF_JSON_MAX_SIZE))) {
        fail(s, "closed", "no memory");
        return;
    }
    if (u->ra_len + len > NPF_JSON_MAX_SIZE) {
        fail(s, "protocol", "udp: message too large");
        return;
    }
    memcpy(u->ra + u->ra_len, d, len);
    u->ra_len += len;
    if (!end)
        return;
    ra = u->ra;
    u->ra = NULL;
    deliver(s, ra, u->ra_len);
    npf_wipe_free(ra, NPF_JSON_MAX_SIZE);
    u->ra_len = 0;
}

static void seg_in(npf_sig *s, uint16_t sn, const uint8_t *d, size_t len, int end)
{
    sigudp *u = s->udp;
    uint16_t off = (uint16_t)(sn - u->rcv_nxt);
    int k;
    u->ack_due = 1;                     /* in order, out of order, again: acked */
    if (off >= WND)
        return;                         /* had, or beyond the window */
    if (off) {
        k = sn % WND;
        if (!u->ooo[k] && (u->ooo[k] = malloc(len + 1))) {
            memcpy(u->ooo[k], d, len);
            u->ooo_len[k] = (uint16_t)len;
            u->ooo_end[k] = (uint8_t)end;
        }
        return;
    }
    u->rcv_nxt++;                       /* first: a reply sent from on_msg acks it */
    take(s, d, len, end);
    while (!s->dead && u->ooo[k = u->rcv_nxt % WND]) {
        uint8_t *p = u->ooo[k];
        u->ooo[k] = NULL;
        u->rcv_nxt++;
        take(s, p, u->ooo_len[k], u->ooo_end[k]);
        npf_wipe_free(p, u->ooo_len[k] + 1u);
    }
}

/* the server's CLOSE: no CLOSE back */
static void close_in(npf_sig *s, const uint8_t *r, size_t len)
{
    char why[16 + REASON_MAX];
    size_t i, o = (size_t)snprintf(why, sizeof why, "closed: ");
    for (i = 0; i < len && o + 1 < sizeof why; i++)
        why[o++] = r[i] >= 0x20 && r[i] < 0x7f ? (char)r[i] : '?';
    why[o] = 0;
    sig_down(s, len == 4 && memcmp(r, "busy", 4) == 0 ? NPF_SIG_DOWN_BUSY : NPF_SIG_DOWN_CLOSED, why);
}

static void tr_in(npf_sig *s, const uint8_t *buf, size_t len)
{
    sigudp *u = s->udp;
    uint8_t pt[DGRAM_MAX], nonce[12] = {0}, fl;
    uint64_t ctr;
    size_t n;
    if (len < 8 + NPF_AEAD_TAG_SIZE + 3 || len > DGRAM_MAX || !fresh(u, ctr = npf_rd64(buf)))
        return;
    memcpy(nonce + 4, buf, 8);
    if (npf_aead_open(u->k2, nonce, buf, 8, buf + 8, len - 8, pt) < 0)
        return;
    n = len - 8 - NPF_AEAD_TAG_SIZE;
    fl = pt[0];
    if (fl == F_CLOSE ? n - 3 > REASON_MAX : n == 3 ? fl != 0 : n < 5 || (fl & ~F_END))
        goto done;                      /* malformed: dropped whole */
    seen(u, ctr);
    u->last_rx = npf_mono_ms();
    if (u->state == SU_FINISH) {        /* message 3 arrived */
        u->state = SU_UP;
        arm(s);
    }
    if (fl == F_CLOSE) {
        close_in(s, pt + 3, n - 3);
        goto done;
    }
    ack_in(s, npf_rd16(pt + 1));
    if (n >= 5)
        seg_in(s, npf_rd16(pt + 3), pt + 5, n - 5, fl & F_END);
    if (!s->dead) {
        try_send(s);
        if (u->ack_due) {
            uint8_t a[3] = {0};
            npf_le16(a + 1, u->rcv_nxt);
            pkt_send(s, a, 3);
        }
    }
done:
    npf_wipe(pt, n);
}

/* ---- the carrier ---- */

static void timer_cb(npf_loop *loop, void *arg)
{
    npf_sig *s = arg;
    sigudp *u = s->udp;
    (void)loop;
    sig_enter(s);
    if (u->fail)
        fail(s, "closed", u->fail);
    else if (u->state == SU_HELLO)
        hello_due(s);
    else
        rto_due(s);
    sig_leave(s);
}

static int su_input(npf_sig *s, const struct sockaddr_storage *from, const uint8_t *buf, size_t len)
{
    if (!npf_addr_eq(from, &s->udp->srv))
        return 0;
    if (s->dead)
        return 1;
    sig_enter(s);
    if (s->udp->state == SU_HELLO)
        hs_in(s, buf, len);
    else
        tr_in(s, buf, len);
    sig_leave(s);
    return 1;
}

static int su_send(npf_sig *s, const char *json, size_t len)
{
    sigudp *u = s->udp;
    omsg *m;
    if (u->fail)
        return -1;
    if (u->nq >= QUEUE_MAX) {           /* closed from the loop, not under the caller */
        u->fail = "udp: send queue full";
        npf_timer_set(u->loop, &u->t, 0);
        return -1;
    }
    if (!(m = malloc(sizeof *m + len)))
        return -1;
    m->next = NULL;
    m->len = len;
    m->nseg = (uint16_t)(len ? (len + SEG_DATA - 1) / SEG_DATA : 1);
    m->sn0 = u->sn_tail;
    memcpy(m->d, json, len);
    u->sn_tail = (uint16_t)(u->sn_tail + m->nseg);
    *u->q_end = m;
    u->q_end = &m->next;
    u->nq++;
    try_send(s);
    return 0;
}

static int su_ping(npf_sig *s)
{
    return in_flight(s->udp) ? 0 : su_send(s, "", 0);  /* in flight: its ack answers */
}

static int64_t su_last_rx(const npf_sig *s)
{
    return s->udp->last_rx;
}

static int su_rtt(const npf_sig *s)
{
    return s->udp->has_rtt ? (s->udp->srtt > 0 ? s->udp->srtt : 1) : 0;
}

static const char *su_diag(const npf_sig *s, char *buf, size_t cap)
{
    const sigudp *u = s->udp;
    if (u->state == SU_HELLO)
        snprintf(buf, cap, "udp: handshake, %d hellos sent%s", u->nhello, u->last_rx ? ", answered" : "");
    else
        snprintf(buf, cap, "udp: in flight %u, queued %u, srtt %d ms, rto %d ms, retrans %u, last rx %lld s ago",
                 (unsigned)in_flight(u), (unsigned)(uint16_t)(u->sn_tail - u->snd_nxt), u->srtt, u->rto, u->retrans,
                 u->last_rx ? (long long)(npf_mono_ms() - u->last_rx) / 1000 : -1LL);
    return buf;
}

static void su_bye(npf_sig *s)
{
    close_send(s, "closed");
}

static void su_free(npf_sig *s)
{
    sigudp *u = s->udp;
    omsg *m;
    int i;
    npf_timer_cancel(u->loop, &u->t);
    while ((m = u->q) != NULL) {
        u->q = m->next;
        npf_wipe_free(m, sizeof *m + m->len);
    }
    for (i = 0; i < WND; i++)
        if (u->ooo[i])
            npf_wipe_free(u->ooo[i], u->ooo_len[i] + 1u);
    if (u->ra)
        npf_wipe_free(u->ra, NPF_JSON_MAX_SIZE);
    npf_wipe_free(u, sizeof *u);        /* the keys */
}

npf_sig *npf_sig_open_udp(npf_loop *loop, npf_sig_send_fn send, const struct sockaddr_in *server,
                          const uint8_t server_pub[32], const npf_identity *id, npf_sig_cookie *cookie,
                          const npf_sig_cbs *cbs, void *arg)
{
    static const sig_ops ops = {"udp", su_send, su_ping, su_last_rx, su_rtt, su_diag, su_input, su_bye, su_free};
    static const char prologue[] = PROLOGUE;
    npf_sig *s = calloc(1, sizeof *s);
    sigudp *u = calloc(1, sizeof *u);
    if (!s || !u) {
        free(s);
        free(u);
        return NULL;
    }
    s->ops = &ops;
    s->cbs = *cbs;
    s->arg = arg;
    s->udp = u;
    u->loop = loop;
    npf_timer_init(&u->t, timer_cb, s);
    u->send_fn = send;
    u->srv = *server;
    u->ck = cookie;
    u->rto = RTO_MAX;
    u->q_end = &u->q;
    npf_siv_derive(&u->hk, server_pub, LABEL);
    if (npf_noise_init(&u->hs, NPF_NOISE_XK, 1, prologue, sizeof prologue - 1, id->dh_sk, server_pub, NULL) < 0
        || npf_noise_write(&u->hs, NULL, 0, u->m1, sizeof u->m1) != NOISE1_LEN) {
        npf_sig_close(s);               /* nothing sent yet: no CLOSE */
        return NULL;
    }
    npf_random(u->txid, sizeof u->txid);
    u->t0 = npf_mono_ms();
    if (cookie && cookie->until > u->t0 && npf_addr_eq(&cookie->to, server)) {
        memcpy(u->cookie, cookie->c, MAC_LEN);
        u->has_cookie = 1;
    }
    hello_due(s);
    return s;
}

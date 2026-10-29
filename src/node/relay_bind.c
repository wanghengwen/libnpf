/* Binding a relay allocation (data-channel.md 9.2): the binder of a call's
 * allocation and of the node's spare (relay_bind.h) */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <string.h>

#include "npf/crypto.h"
#include "npf/platform.h"

#include "node_internal.h"
#include "relay_bind.h"

/* family(1) | port(2) | addr(4): IPv4 only; the bytes after it, or NULL */
static const uint8_t *addr_parse(const uint8_t *b, size_t len, struct sockaddr_storage *ss)
{
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    memset(ss, 0, sizeof *ss);
    if (len < 7 || b[0] != 4)
        return NULL;
    a->sin_family = AF_INET;
    a->sin_port = htons(npf_rd16(b + 1));
    memcpy(&a->sin_addr, b + 3, 4);
    return b + 7;
}

/* a control packet's body (plain: pl bytes, the header first): its length, or -1 */
static int pkt_body(const uint8_t *plain, size_t pl)
{
    size_t blen;
    if (pl < NPF_PKT_HDR_SIZE || NPF_PKT_HDR_SIZE + (blen = npf_rd16(plain + 2)) > pl)
        return -1;
    return (int)blen;
}

static int relay_ack_parse(const uint8_t *plain, size_t pl, relay_ack *a)
{
    const uint8_t *b = plain + NPF_PKT_HDR_SIZE, *p;
    int len = pkt_body(plain, pl);
    memset(a, 0, sizeof *a);
    if (len < 7 + 8 + 1 + 8 + 8 + 1 + 3 || !(p = addr_parse(b, (size_t)len, &a->addr)))
        return -1;
    a->srv_ms = (int64_t)npf_rd64(p);
    a->state = p[8];
    memcpy(a->cookie, p + 9, 8);
    a->kseq = npf_rd64(p + 17);
    a->t_s = npf_rd16(p + 26);
    a->learn = p[28];
    return 0;
}

int relay_ping_parse(const uint8_t *plain, size_t pl, relay_ping *q)
{
    const uint8_t *b = plain + NPF_PKT_HDR_SIZE, *p;
    int len = pkt_body(plain, pl);
    memset(q, 0, sizeof *q);
    if (len < 7 + 8 + 4 + 2 + 1 + 1 || !(p = addr_parse(b, (size_t)len, &q->addr)))
        return -1;
    q->srv_ms = (int64_t)npf_rd64(p);
    q->ping_id = npf_rd32(p + 8);
    q->t_s = npf_rd16(p + 12);
    q->learn = p[14];
    return 0;
}

void relay_bind_take(relay_c *r, npf_node *n, const uint8_t id[8], const uint8_t key[32],
                     const struct sockaddr_storage *addr, int naddr)
{
    memcpy(r->relay_id, id, 8);
    memcpy(r->alloc_key, key, 32);
    npf_siv_derive(&r->keys, key, LABEL_RELAY);
    rdata_derive(&r->dkeys, key);
    memcpy(r->addr, addr, (size_t)naddr * sizeof addr[0]);
    r->naddr = naddr;
    memset(r->cookie, 0, sizeof r->cookie);     /* a cookie is the allocation's */
    memset(r->sent, 0, sizeof r->sent);         /* so are the binds answered */
    r->chal_srv = 0;
    /* above whatever the relay took on this allocation before (a holder
     * that lost its state): 1024 binds a millisecond of server time */
    r->kseq = (uint64_t)npf_node_time(n) << 10;
    relay_bind_begin(r, 0, npf_mono_ms());
}

/* a RELAY_BIND in wire (256 bytes): its length, or -1. flags RELAY_F_PONG:
 * the answer to ping_id, shorter than a bind (72..95) */
static int relay_bind_pack(relay_c *r, npf_node *n, int flags, uint32_t ping_id, uint8_t *wire)
{
    uint8_t txid[NPF_TXID_SIZE], body[RELAY_BIND_BODY];
    size_t len = flags & RELAY_F_PONG ? npf_rand_range(72, NPF_BIND_REQ_MIN - 1)
                                      : npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
    uint32_t ts = (uint32_t)npf_node_time(n);
    int k = r->nsent++ % RELAY_SENT, w;
    npf_random(txid, sizeof txid);
    r->kseq++;
    memcpy(r->sent[k].txid, txid, sizeof txid);     /* its BIND_ACK echoes them (relay_bind_ack) */
    r->sent[k].ts = ts;
    r->sent[k].kseq = r->kseq;
    r->sent[k].at = r->last_tx = npf_mono_ms();
    memcpy(body, r->cookie, 8);                     /* cookie | kseq | flags | ping_id */
    npf_le64(body + 8, r->kseq);
    body[16] = (uint8_t)flags;
    npf_le32(body + 17, ping_id);
    memcpy(wire, r->relay_id, RELAY_HINT_SIZE);
    w = npf_pkt_seal(&r->keys, NPF_DIR_REQ, PKT_RELAY_BIND, txid, ts, body, sizeof body, len - RELAY_HINT_SIZE,
                     wire + RELAY_HINT_SIZE);
    return w > 0 ? w + RELAY_HINT_SIZE : -1;
}

void relay_bind_send(relay_c *r, npf_node *n, int flags, uint32_t ping_id)
{
    uint8_t wire[256];
    int len;
    if (n->udp_fd >= 0 && !call_relay_addr_blocked(n, RELAY_BIND_DST(r))
        && (len = relay_bind_pack(r, n, flags, ping_id, wire)) > 0)
        (void)npf_udp_send(n->udp_fd, wire, (size_t)len, RELAY_BIND_DST(r));
}

/* the run's nth address: the one it began with, then the others in order */
static int run_addr(const relay_c *r, int nth)
{
    if (nth == 0)
        return r->first;
    return nth - 1 < r->first ? nth - 1 : nth;
}

void relay_bind_begin(relay_c *r, int probe, int64_t now)
{
    r->state = probe && r->cur < r->naddr ? RB_PROBING : RB_BINDING;
    r->first = r->bi = r->cur = r->state == RB_PROBING ? r->cur : 0;
    r->nth = r->tries = 0;
    r->at = now + RELAY_BIND_MS;
}

int relay_bind_tick(relay_c *r, int64_t now, int ka)
{
    if (!r->at || now < r->at)
        return 0;
    if (r->state == RB_BOUND) {         /* (no deadline without a keepalive) */
        r->at = now + ka;
        return 1;
    }
    if (++r->tries > 3) {               /* the first and 3 more to an address */
        if (r->nth + 1 >= r->naddr) {
            r->state = RB_GAVE_UP;
            r->at = 0;
            return -1;
        }
        r->bi = run_addr(r, ++r->nth);
        r->tries = 0;
        if (r->state == RB_BINDING)
            r->cur = r->bi;             /* binding from scratch: the data goes along */
    }
    r->at = now + RELAY_BIND_MS;
    return 1;
}

int relay_bind_up(relay_c *r, int64_t now, int ka)
{
    int was = r->state != RB_BOUND;
    r->state = RB_BOUND;
    r->at = ka ? now + ka : 0;
    return was;
}

int relay_addr_index(const relay_c *r, const struct sockaddr_storage *from)
{
    int i;
    for (i = 0; i < r->naddr; i++)
        if (npf_addr_eq(from, &r->addr[i]))
            return i;
    return -1;
}

int relay_addr_take(relay_c *r, int i)
{
    /* (one tried earlier may answer late; while probing, the one in use may) */
    if (r->state != RB_NONE && r->state != RB_BOUND) {
        r->cur = r->bi = i;
        return 1;
    }
    return i == r->cur;
}

int relay_bind_open(relay_c *r, const uint8_t *buf, size_t len, const struct sockaddr_storage *from, uint8_t *plain)
{
    int i, pl;
    if ((i = relay_addr_index(r, from)) < 0 || len > 2048 + NPF_SIV_TAG_SIZE)
        return -1;
    if ((pl = npf_siv_open(&r->keys, NPF_DIR_RESP, buf, len, plain)) < 6)
        return -1;
    return relay_addr_take(r, i) ? pl : 0;
}

/* A BIND_ACK counts only when it answers one of our last binds (RELAY_SENT,
 * RELAY_ACK_AGE_MS old at most: its txid, ts_ms and kseq echoed), and once:
 * a replayed one (an old challenge, sent again by someone on the path with
 * the relay's address) would have us bind again each time, burning the
 * allocation's bind tokens. A challenge to our RELAY_DATA (a new NAT port)
 * has no txid: it counts when its srv_time_ms is newer than the last one
 * taken and within RELAY_ACK_WINDOW_MS of now. */
#define RELAY_ACK_AGE_MS    10000
#define RELAY_ACK_WINDOW_MS 60000

int relay_bind_ack(relay_c *r, npf_node *n, const uint8_t *plain, size_t pl, relay_ack *a)
{
    static const uint8_t none[NPF_TXID_SIZE];
    const uint8_t *txid = plain + 4;
    uint32_t ts;
    int64_t now = npf_mono_ms(), d;
    int i;
    if (relay_ack_parse(plain, pl, a) < 0)
        return 0;
    ts = npf_rd32(plain + 4 + NPF_TXID_SIZE);
    if (memcmp(txid, none, sizeof none) == 0) {
        d = a->srv_ms - npf_node_time(n);
        if (a->state == RELAY_ACK_BOUND || (uint64_t)a->srv_ms <= r->chal_srv || d > RELAY_ACK_WINDOW_MS
            || d < -RELAY_ACK_WINDOW_MS)
            return 0;
        r->chal_srv = (uint64_t)a->srv_ms;
        a->rtt = -1;
    } else {
        for (i = 0; i < RELAY_SENT; i++)
            if (r->sent[i].at && now - r->sent[i].at <= RELAY_ACK_AGE_MS && r->sent[i].ts == ts
                && r->sent[i].kseq == a->kseq && npf_ct_eq(r->sent[i].txid, txid, NPF_TXID_SIZE) == 0)
                break;
        if (i == RELAY_SENT)
            return 0;
        a->rtt = now - r->sent[i].at;
        r->sent[i].at = 0;
    }
    memcpy(r->cookie, a->cookie, RELAY_COOKIE_SIZE);
    if (a->state == RELAY_ACK_BOUND || now - r->echo_ms < 200)
        return 1;
    r->echo_ms = now;
    return 2;
}

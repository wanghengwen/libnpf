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
    a->sin_port = htons((uint16_t)(b[1] | b[2] << 8));
    memcpy(&a->sin_addr, b + 3, 4);
    return b + 7;
}

static int relay_ack_parse(const uint8_t *b, size_t len, relay_ack *a)
{
    const uint8_t *p;
    memset(a, 0, sizeof *a);
    if (!(p = addr_parse(b, len, &a->addr)) || len < 7 + 8 + 1 + 8 + 8 + 1 + 3)
        return -1;
    a->srv_ms = (int64_t)npf_rd64(p);
    a->state = p[8];
    memcpy(a->cookie, p + 9, 8);
    a->kseq = npf_rd64(p + 17);
    a->flags = p[25];
    a->t_s = p[26] | p[27] << 8;
    a->learn = p[28];
    return 0;
}

int relay_ping_parse(const uint8_t *b, size_t len, relay_ping *q)
{
    const uint8_t *p;
    memset(q, 0, sizeof *q);
    if (!(p = addr_parse(b, len, &q->addr)) || len < 7 + 8 + 4 + 2 + 1 + 1)
        return -1;
    q->srv_ms = (int64_t)npf_rd64(p);
    q->ping_id = npf_rd32(p + 8);
    q->t_s = p[12] | p[13] << 8;
    q->learn = p[14];
    q->try_n = p[15];
    return 0;
}

void relay_bind_take(relay_c *r, npf_node *n, const uint8_t id[8], const uint8_t key[32],
                     const struct sockaddr_storage *addr, int naddr)
{
    memcpy(r->relay_id, id, 8);
    memcpy(r->alloc_key, key, 32);
    if (addr) {
        npf_siv_derive(&r->keys, key, LABEL_RELAY);
        memcpy(r->addr, addr, (size_t)naddr * sizeof addr[0]);
        r->naddr = naddr;
    }
    r->cur = r->tries = 0;
    memset(r->cookie, 0, sizeof r->cookie);     /* a cookie is the allocation's */
    memset(r->sent, 0, sizeof r->sent);         /* so are the binds answered */
    r->chal_srv = 0;
    /* above whatever the relay took on this allocation before (a holder
     * that lost its state): 1024 binds a millisecond of server time */
    r->kseq = (uint64_t)npf_node_time(n) << 10;
}

int relay_bind_pack(relay_c *r, npf_node *n, int flags, uint32_t ping_id, uint8_t *wire)
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

static void run_timer(npf_loop *l, void *arg)
{
    relay_c *r = arg;
    r->t_bind = NULL;
    if (++r->tries > 3) {               /* the first and 3 more to an address */
        if (r->cur + 1 >= r->naddr) {
            r->on_gave_up(r->arg);
            return;
        }
        r->cur++;
        r->tries = 0;
    }
    r->on_send(r->arg);
    r->t_bind = npf_timer_add(l, RELAY_BIND_MS, run_timer, r);
}

void relay_bind_run(relay_c *r, npf_loop *l, void (*on_send)(void *), void (*on_gave_up)(void *), void *arg)
{
    timer_stop(l, &r->t_bind);
    r->on_send = on_send;
    r->on_gave_up = on_gave_up;
    r->arg = arg;
    r->cur = r->tries = 0;
    on_send(arg);
    r->t_bind = npf_timer_add(l, RELAY_BIND_MS, run_timer, r);
}

int relay_obj_parse(const npf_json *j, int r, char mode[8], uint8_t id[8], uint8_t key[32],
                    struct sockaddr_storage addr[4])
{
    int arr = npf_json_get(j, r, "udp"), i, naddr = 0;
    mode[0] = 0;
    npf_json_get_str(j, r, "mode", mode, 8);
    if (npf_json_get_b64(j, r, "relay_id", id, 8) != 8 || npf_json_get_b64(j, r, "alloc_key", key, 32) != 32)
        return -1;
    for (i = 0; arr >= 0 && i < j->tok[arr].size && naddr < 4; i++) {
        char a[80];
        if (npf_json_str(j, npf_json_item(j, arr, i), a, sizeof a) > 0 && npf_addr_parse(a, &addr[naddr]) == 0
            && addr[naddr].ss_family == AF_INET)
            naddr++;
    }
    return naddr;
}

int call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const void *)a, *y = (const void *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    return 0;
}

int relay_bind_open(relay_c *r, const uint8_t *buf, size_t len, const struct sockaddr_storage *from, uint8_t *plain)
{
    int i, pl;
    for (i = 0; i < r->naddr && !call_same_addr(from, &r->addr[i]); i++)
        ;
    if (i == r->naddr || len > 2048 + NPF_SIV_TAG_SIZE)
        return -1;
    if ((pl = npf_siv_open(&r->keys, NPF_DIR_RESP, buf, len, plain)) < 6)
        return -1;
    /* an address tried earlier answered late (the binds moved on to the
     * next one): the one that works is the one to use */
    if (i != r->cur && r->active && !r->bound)
        r->cur = i;
    else if (i != r->cur)
        return 0;
    return pl;
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
    size_t blen;
    int64_t now = npf_mono_ms(), d;
    int i;
    if (pl < NPF_PKT_HDR_SIZE)
        return 0;
    blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    if (NPF_PKT_HDR_SIZE + blen > pl || relay_ack_parse(plain + NPF_PKT_HDR_SIZE, blen, a) < 0)
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
    return 1;
}

int relay_bind_echo_due(relay_c *r)
{
    int64_t now = npf_mono_ms();
    if (now - r->echo_ms < 200)
        return 0;
    r->echo_ms = now;
    return 1;
}

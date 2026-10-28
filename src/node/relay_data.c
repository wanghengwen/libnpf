/* RELAY_DATA (data-channel.md 9.2, 2026-10-28), both ways:
 *
 *   wire = tag(8) | hint(3) ^ hm(3) | tf(1) ^ m[0] | seq(4) ^ m[1..4] | AnLiu datagram
 *   tag  = SipHash-2-4-64(k_tag[dir], hint | tf | seq | len(2) | atag(12))
 *   m    = SipHash-2-4-64(k_mask[dir], tag)[0..4]
 *   hm   = tag[1 + (tag[0] & 3) ..][0..2]
 *
 * Only the header is authenticated: the AnLiu datagram is sealed end to end
 * already, and its first 12 bytes (its tag, over all of it) and its length
 * are under the header's tag, so the relay drops a datagram cut or extended
 * under a kept header. hm is unkeyed (as AnLiu's conv mask): the receiver
 * finds the allocation without a key. No ChaCha20 per datagram (until
 * 2026-10-28 RELAY_DATA was SIV-sealed whole, as the control packets are). */
#include "npf/sys.h"
#include <string.h>

#include "npf/crypto.h"
#include "npf/platform.h"

#include "node_internal.h"
#include "relay_bind.h"

void rdata_derive(rdata_keys *k, const uint8_t alloc_key[32])
{
    npf_siv_keys t;
    int dir;
    npf_siv_derive(&t, alloc_key, LABEL_RDATA);
    for (dir = 0; dir < 2; dir++) {
        memcpy(k->tag[dir], t.enc[dir], 16);
        memcpy(k->mask[dir], t.enc[dir] + 16, 16);
    }
    npf_wipe(&t, sizeof t);
}

static int hm_off(const uint8_t *tag)
{
    return 1 + (tag[0] & 3);
}

/* the tag over hint | tf | seq | len | atag */
static uint64_t mac(const rdata_keys *k, int dir, const uint8_t hint[RDATA_HINT], uint8_t tf, uint32_t seq,
                    const uint8_t *dg, size_t dlen)
{
    uint8_t in[RDATA_HINT + 1 + 4 + 2 + RDATA_ATAG];
    memcpy(in, hint, RDATA_HINT);
    in[3] = tf;
    npf_le32(in + 4, seq);
    in[8] = (uint8_t)dlen;
    in[9] = (uint8_t)(dlen >> 8);
    memcpy(in + 10, dg, RDATA_ATAG);
    return npf_siphash64(k->tag[dir], in, sizeof in);
}

void rdata_seal(const rdata_keys *k, int dir, const uint8_t hint[RDATA_HINT], uint32_t seq, uint8_t *w, size_t dlen)
{
    uint64_t t = mac(k, dir, hint, RDATA_TF, seq, w + RDATA_HDR, dlen), m;
    int o;
    npf_le64(w, t);
    m = npf_siphash64(k->mask[dir], w, 8);
    o = hm_off(w);
    w[8] = hint[0] ^ w[o];
    w[9] = hint[1] ^ w[o + 1];
    w[10] = hint[2] ^ w[o + 2];
    w[11] = (uint8_t)(RDATA_TF ^ (uint8_t)m);
    npf_le32(w + 12, seq ^ (uint32_t)(m >> 8));
}

int rdata_hint(const uint8_t *w, size_t len, uint8_t hint[RDATA_HINT])
{
    int o;
    if (len < RDATA_HDR + RDATA_ATAG)
        return -1;
    o = hm_off(w);
    hint[0] = w[8] ^ w[o];
    hint[1] = w[9] ^ w[o + 1];
    hint[2] = w[10] ^ w[o + 2];
    return 0;
}

int rdata_open(const rdata_keys *k, int dir, const uint8_t hint[RDATA_HINT], const uint8_t *w, size_t len,
                uint32_t *seq)
{
    uint64_t m, t;
    uint8_t tf, tb[8];
    if (len < RDATA_HDR + RDATA_ATAG || len - RDATA_HDR > 0xffff)
        return -1;
    m = npf_siphash64(k->mask[dir], w, 8);
    tf = (uint8_t)(w[11] ^ (uint8_t)m);
    if (tf != RDATA_TF)
        return -1;
    *seq = npf_rd32(w + 12) ^ (uint32_t)(m >> 8);
    t = mac(k, dir, hint, tf, *seq, w + RDATA_HDR, len - RDATA_HDR);
    npf_le64(tb, t);
    return npf_ct_eq(tb, w, 8) == 0 ? 0 : -1;
}

int relay_data_open(relay_c *r, const uint8_t hint[RDATA_HINT], const uint8_t *buf, size_t len,
                    const struct sockaddr_storage *from)
{
    uint32_t seq;
    int i;
    if (memcmp(hint, r->relay_id, RDATA_HINT) != 0 || (i = relay_addr_index(r, from)) < 0
        || rdata_open(&r->dkeys, NPF_DIR_RESP, hint, buf, len, &seq) < 0)
        return -1;
    /* the outer seq is not checked: the AnLiu datagram's own is (its
     * replay window) */
    return relay_addr_take(r, i);
}

size_t relay_data_pack(relay_c *r, const uint8_t *dgram, size_t len, uint8_t *wire)
{
    if (len < RDATA_ATAG || len + RDATA_HDR > 2048)
        return 0;
    memcpy(wire + RDATA_HDR, dgram, len);
    rdata_seal(&r->dkeys, NPF_DIR_REQ, r->relay_id, r->seq++, wire, len);
    return len + RDATA_HDR;
}

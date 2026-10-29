/* SIV sealing, a copy of the AnLiu construction (see npf/siv.h). Kept
 * byte-for-byte compatible with anliu.c; the known-answer tests are shared.
 * ChaCha20 (RFC 8439) is Monocypher's, in both crypto backends. */
#include <string.h>

#include "monocypher.h"
#include "npf/crypto.h"
#include "npf/siv.h"

#define ROTL64(v, n) (((v) << (n)) | ((v) >> (64 - (n))))
#define SIPROUND \
    v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); \
    v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                      \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                      \
    v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);

/* SipHash-2-4 (reference construction): s, the state keyed and (128-bit
 * output) its v1 ^ 0xee, through the message and the first finalization
 * (v2 ^ fin, four rounds); the 64-bit output is v0 ^ v1 ^ v2 ^ v3 */
static void sip(uint64_t s[4], const uint8_t *in, size_t len, uint64_t fin)
{
    uint64_t v0 = s[0], v1 = s[1], v2 = s[2], v3 = s[3], b = (uint64_t)len << 56;
    const uint8_t *end = in + (len & ~(size_t)7);
    for (; in != end; in += 8) {
        uint64_t m = npf_rd64(in);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }
    switch (len & 7) {
    case 7: b |= (uint64_t)in[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)in[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)in[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)in[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)in[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)in[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)in[0];       /* fallthrough */
    default: break;
    }
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= fin;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    s[0] = v0, s[1] = v1, s[2] = v2, s[3] = v3;
}

static void sip_init(uint64_t s[4], const uint8_t key[16])
{
    uint64_t k0 = npf_rd64(key), k1 = npf_rd64(key + 8);
    s[0] = 0x736f6d6570736575ULL ^ k0;
    s[1] = 0x646f72616e646f6dULL ^ k1;
    s[2] = 0x6c7967656e657261ULL ^ k0;
    s[3] = 0x7465646279746573ULL ^ k1;
}

void npf_siphash128(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t out[16])
{
    uint64_t s[4], v0, v1, v2, v3;
    sip_init(s, key);
    s[1] ^= 0xee;
    sip(s, in, len, 0xee);
    npf_le64(out, s[0] ^ s[1] ^ s[2] ^ s[3]);
    v0 = s[0], v1 = s[1] ^ 0xdd, v2 = s[2], v3 = s[3];
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    npf_le64(out + 8, v0 ^ v1 ^ v2 ^ v3);
}

uint64_t npf_siphash64(const uint8_t key[16], const uint8_t *in, size_t len)
{
    uint64_t s[4];
    sip_init(s, key);
    sip(s, in, len, 0xff);
    return s[0] ^ s[1] ^ s[2] ^ s[3];
}

void npf_siv_derive(npf_siv_keys *keys, const uint8_t key[NPF_SIV_KEY_SIZE], const char label[12])
{
    int dir;
    for (dir = 0; dir < 2; dir++) {
        uint8_t blk[64];
        crypto_chacha20_ietf(blk, NULL, sizeof blk, key, (const uint8_t *)label, (uint32_t)dir);
        memcpy(keys->enc[dir], blk, 32);
        memcpy(keys->mac[dir], blk + 32, 16);
    }
}

void npf_siv_seal(const npf_siv_keys *keys, int dir, uint8_t *buf, size_t plen)
{
    uint8_t tag[16];
    npf_siphash128(keys->mac[dir], buf + NPF_SIV_TAG_SIZE, plen, tag);
    memcpy(buf, tag, NPF_SIV_TAG_SIZE);
    crypto_chacha20_ietf(buf + NPF_SIV_TAG_SIZE, buf + NPF_SIV_TAG_SIZE, plen, keys->enc[dir], buf, 0);
}

int npf_siv_open(const npf_siv_keys *keys, int dir, const uint8_t *in, size_t len, uint8_t *plain)
{
    uint8_t tag[16];
    size_t plen;
    if (len < NPF_SIV_TAG_SIZE)
        return -1;
    plen = len - NPF_SIV_TAG_SIZE;
    crypto_chacha20_ietf(plain, in + NPF_SIV_TAG_SIZE, plen, keys->enc[dir], in, 0);
    npf_siphash128(keys->mac[dir], plain, plen, tag);
    if (npf_ct_eq(tag, in, NPF_SIV_TAG_SIZE)) {
        npf_wipe(plain, plen);              /* nothing unauthenticated left behind */
        return -1;
    }
    return (int)plen;
}

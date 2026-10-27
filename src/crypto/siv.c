/* SIV sealing, a copy of the AnLiu construction (see npf/siv.h). Kept
 * byte-for-byte compatible with anliu.c; the known-answer tests are shared.
 * ChaCha20 (RFC 8439) is Monocypher's, in both crypto backends. */
#include <string.h>

#include "monocypher.h"
#include "npf/siv.h"

#define ROTL64(v, n) (((v) << (n)) | ((v) >> (64 - (n))))

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint64_t ld64(const uint8_t *p)
{
    return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32);
}

static void st64(uint8_t *p, uint64_t v)
{
    st32(p, (uint32_t)v);
    st32(p + 4, (uint32_t)(v >> 32));
}

#define SIPROUND \
    v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); \
    v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                      \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                      \
    v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);

/* SipHash-2-4 with 128-bit output (reference construction) */
void npf_siphash128(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t out[16])
{
    uint64_t k0 = ld64(key), k1 = ld64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1 ^ 0xeeULL;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    const uint8_t *end = in + (len & ~(size_t)7);
    int left = (int)(len & 7);

    for (; in != end; in += 8) {
        uint64_t m = ld64(in);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }
    switch (left) {
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
    v2 ^= 0xeeULL;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    st64(out, v0 ^ v1 ^ v2 ^ v3);
    v1 ^= 0xddULL;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    st64(out + 8, v0 ^ v1 ^ v2 ^ v3);
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
    uint8_t tag[16], d = 0;
    size_t plen, i;
    if (len < NPF_SIV_TAG_SIZE)
        return -1;
    plen = len - NPF_SIV_TAG_SIZE;
    crypto_chacha20_ietf(plain, in + NPF_SIV_TAG_SIZE, plen, keys->enc[dir], in, 0);
    npf_siphash128(keys->mac[dir], plain, plen, tag);
    for (i = 0; i < NPF_SIV_TAG_SIZE; i++) d |= (uint8_t)(tag[i] ^ in[i]);
    return d == 0 ? (int)plen : -1;
}

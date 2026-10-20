/* SIV sealing, a copy of the AnLiu construction (see npf/siv.h). Kept
 * byte-for-byte compatible with anliu.c; the known-answer tests are shared. */
#include <string.h>

#include "npf/siv.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
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

#define CHACHA_QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

/* RFC 8439 block function: 32-byte key, 32-bit counter, 96-bit nonce */
void npf_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16], x[16];
    int i;
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
    s[12] = counter;
    s[13] = ld32(nonce); s[14] = ld32(nonce + 4); s[15] = ld32(nonce + 8);
    memcpy(x, s, sizeof(x));
    for (i = 0; i < 10; i++) {
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) st32(out + 4 * i, x[i] + s[i]);
}

void npf_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *buf, size_t len)
{
    uint8_t ks[64];
    while (len > 0) {
        size_t n = len < 64 ? len : 64, i;
        npf_chacha20_block(key, counter++, nonce, ks);
        for (i = 0; i < n; i++) buf[i] ^= ks[i];
        buf += n;
        len -= n;
    }
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
        npf_chacha20_block(key, (uint32_t)dir, (const uint8_t *)label, blk);
        memcpy(keys->enc[dir], blk, 32);
        memcpy(keys->mac[dir], blk + 32, 16);
    }
}

void npf_siv_seal(const npf_siv_keys *keys, int dir, uint8_t *buf, size_t plen)
{
    uint8_t tag[16];
    npf_siphash128(keys->mac[dir], buf + NPF_SIV_TAG_SIZE, plen, tag);
    memcpy(buf, tag, NPF_SIV_TAG_SIZE);
    npf_chacha20_xor(keys->enc[dir], buf, 0, buf + NPF_SIV_TAG_SIZE, plen);
}

int npf_siv_open(const npf_siv_keys *keys, int dir, const uint8_t *in, size_t len, uint8_t *plain)
{
    uint8_t tag[16], d = 0;
    size_t plen, i;
    if (len < NPF_SIV_TAG_SIZE)
        return -1;
    plen = len - NPF_SIV_TAG_SIZE;
    memcpy(plain, in + NPF_SIV_TAG_SIZE, plen);
    npf_chacha20_xor(keys->enc[dir], in, 0, plain, plen);
    npf_siphash128(keys->mac[dir], plain, plen, tag);
    for (i = 0; i < NPF_SIV_TAG_SIZE; i++) d |= (uint8_t)(tag[i] ^ in[i]);
    return d == 0 ? (int)plen : -1;
}

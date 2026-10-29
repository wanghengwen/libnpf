#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "npf/crypto.h"
#include "npf/platform.h"
#ifdef NPF_USE_OPENSSL
#include "openssl_impl.h"
#endif

/* BLAKE2b of a || b, keyed when key_len (Monocypher's) */
static void b2(uint8_t *out, size_t size, const void *key, size_t key_len, const void *a, size_t a_len,
               const void *b, size_t b_len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, size, key, key_len);
    crypto_blake2b_update(&ctx, a, a_len);
    crypto_blake2b_update(&ctx, b, b_len);
    crypto_blake2b_final(&ctx, out);
}

void npf_kdf(uint8_t out[32], const void *key, size_t key_len, const void *msg, size_t msg_len)
{
    npf_kdf2(out, key, key_len, msg, msg_len, NULL, 0);
}

void npf_kdf2(uint8_t out[32], const void *key, size_t key_len,
              const void *a, size_t a_len, const void *b, size_t b_len)
{
#ifdef NPF_USE_OPENSSL
    /* OpenSSL 3.0 has no variable-length unkeyed BLAKE2b: Monocypher's then
     * (and when EVP fails to allocate: these helpers cannot fail) */
    if (key_len && ossl_mac(out, 32, 0, key, key_len, a, a_len, b, b_len) == 0)
        return;
#endif
    b2(out, 32, key, key_len, a, a_len, b, b_len);
}

#ifndef NPF_USE_OPENSSL
static const uint8_t zero16[16];

static void poly_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t ad_len, const uint8_t *ct, size_t len)
{
    uint8_t block[64], lens[16];
    crypto_poly1305_ctx p;
    crypto_chacha20_ietf(block, NULL, 64, key, nonce, 0);
    crypto_poly1305_init(&p, block);
    crypto_poly1305_update(&p, ad, ad_len);
    crypto_poly1305_update(&p, zero16, (16 - ad_len % 16) % 16);
    crypto_poly1305_update(&p, ct, len);
    crypto_poly1305_update(&p, zero16, (16 - len % 16) % 16);
    npf_le64(lens, ad_len);
    npf_le64(lens + 8, len);
    crypto_poly1305_update(&p, lens, 16);
    crypto_poly1305_final(&p, tag);
    crypto_wipe(block, sizeof block);
}

#endif

int npf_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                   const uint8_t *in, size_t len, uint8_t *out)
{
#ifdef NPF_USE_OPENSSL
    return ossl_aead(1, key, nonce, ad, ad_len, in, len, out + len, out);
#else
    crypto_chacha20_ietf(out, in, len, key, nonce, 1);
    poly_tag(out + len, key, nonce, ad, ad_len, out, len);
    return 0;
#endif
}

int npf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                  const uint8_t *in, size_t len, uint8_t *out)
{
#ifndef NPF_USE_OPENSSL
    uint8_t tag[16];
#endif
    if (len < NPF_AEAD_TAG_SIZE)
        return -1;
    len -= NPF_AEAD_TAG_SIZE;
#ifdef NPF_USE_OPENSSL
    return ossl_aead(0, key, nonce, ad, ad_len, in, len, (uint8_t *)(in + len), out);
#else
    poly_tag(tag, key, nonce, ad, ad_len, in, len);
    if (crypto_verify16(tag, in + len))
        return -1;
    crypto_chacha20_ietf(out, in, len, key, nonce, 1);
    return 0;
#endif
}

void npf_hash2(uint8_t out[64], const void *a, size_t alen, const void *b, size_t blen)
{
#ifdef NPF_USE_OPENSSL
    if (ossl_hash2(out, a, alen, b, blen) == 0) return;
#endif
    b2(out, 64, NULL, 0, a, alen, b, blen);
}

void npf_hmac_blake2b(uint8_t out[64], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len)
{
    uint8_t k[128], pad[128], inner[64];
    size_t i;
#ifdef NPF_USE_OPENSSL
    if (ossl_mac(out, 64, 1, key, key_len, data, data_len, NULL, 0) == 0) return;
#endif
    memset(k, 0, sizeof k);
    if (key_len > 128)
        crypto_blake2b(k, 64, key, key_len);
    else
        memcpy(k, key, key_len);
    for (i = 0; i < 128; i++) pad[i] = k[i] ^ 0x36;
    b2(inner, 64, NULL, 0, pad, 128, data, data_len);
    for (i = 0; i < 128; i++) pad[i] = k[i] ^ 0x5c;
    b2(out, 64, NULL, 0, pad, 128, inner, 64);
    crypto_wipe(k, sizeof k);
    crypto_wipe(pad, sizeof pad);
    crypto_wipe(inner, sizeof inner);
}

void npf_identity_from_seed(npf_identity *id, const uint8_t seed[32])
{
    uint8_t s[32];
    memmove(id->seed, seed, 32);
    npf_kdf(s, id->seed, 32, "npf sign v1", 11);
#ifdef NPF_USE_OPENSSL
    if (ossl_public(EVP_PKEY_ED25519, id->sign_pub, s) == 0) {
        memcpy(id->sign_sk, s, 32);
        memcpy(id->sign_sk + 32, id->sign_pub, 32);
        npf_wipe(s, 32);
    } else
#endif
        crypto_ed25519_key_pair(id->sign_sk, id->sign_pub, s); /* wipes s */
    npf_kdf(id->dh_sk, id->seed, 32, "npf dh v1", 9);
    npf_x25519_pub(id->dh_pub, id->dh_sk);
}

void npf_identity_wipe(npf_identity *id)
{
    crypto_wipe(id, sizeof *id);
}

uint64_t npf_fp(const uint8_t dh_pub[32])
{
    uint8_t h[32];
    b2(h, 32, NULL, 0, dh_pub, 32, NULL, 0);
    return npf_rd64(h);
}

/* Ed25519 has no streaming interface in Monocypher: domain | msg in one
 * buffer, on the stack for the short ones (certificates, grants, bind
 * proofs), else on the heap (server lists, up to 64 KiB); NULL: no memory */
#define SIGN2_MAX 4096

static uint8_t *cat2(uint8_t stack[SIGN2_MAX], const void *a, size_t al, const void *b, size_t bl)
{
    uint8_t *p = stack;
    if (al > SIZE_MAX - bl || (al + bl > SIGN2_MAX && !(p = malloc(al + bl))))
        return NULL;
    memcpy(p, a, al);
    if (bl)
        memcpy(p + al, b, bl);
    return p;
}

void npf_sign2(uint8_t sig[64], const uint8_t sign_sk[64],
               const void *domain, size_t dlen, const void *msg, size_t len)
{
    uint8_t stack[SIGN2_MAX], *buf = cat2(stack, domain, dlen, msg, len);
    if (!buf) {
        memset(sig, 0, 64);             /* never verifies */
        return;
    }
#ifdef NPF_USE_OPENSSL
    if (ossl_sign(sig, sign_sk, buf, dlen + len) != 0)
#endif
        crypto_ed25519_sign(sig, sign_sk, buf, dlen + len);
    if (buf != stack)
        free(buf);
}

int npf_verify2(const uint8_t sig[64], const uint8_t pub[32],
                const void *domain, size_t dlen, const void *msg, size_t len)
{
    uint8_t stack[SIGN2_MAX], *buf = cat2(stack, domain, dlen, msg, len);
    int r;
    if (!buf)
        return -1;
#ifdef NPF_USE_OPENSSL
    r = ossl_verify(sig, pub, buf, dlen + len);
#else
    r = crypto_ed25519_check(sig, pub, buf, dlen + len) ? -1 : 0;
#endif
    if (buf != stack)
        free(buf);
    return r;
}

int npf_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32])
{
    static const uint8_t zero[32];
#ifdef NPF_USE_OPENSSL
    if (ossl_dh(shared, sk, pk) < 0) return -1;
#else
    crypto_x25519(shared, sk, pk);
#endif
    return crypto_verify32(shared, zero) == 0 ? -1 : 0;
}

void npf_x25519_pub(uint8_t pk[32], const uint8_t sk[32])
{
#ifdef NPF_USE_OPENSSL
    if (ossl_public(EVP_PKEY_X25519, pk, sk) == 0) return;
#endif
    crypto_x25519_public_key(pk, sk);
}

int npf_ct_eq(const void *a, const void *b, size_t n)
{
#ifdef NPF_USE_OPENSSL
    return CRYPTO_memcmp(a, b, n) != 0;
#else
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++)
        d |= x[i] ^ y[i];
    return d != 0;
#endif
}

void npf_wipe(void *p, size_t n)
{
#ifdef NPF_USE_OPENSSL
    OPENSSL_cleanse(p, n);
#else
    crypto_wipe(p, n);
#endif
}

void npf_wipe_free(void *p, size_t n)
{
    if (p) {
        npf_wipe(p, n);
        free(p);
    }
}

static size_t b64_encode(const uint8_t *in, size_t n, char *out, const char t[64], int pad)
{
    size_t i, o = 0;
    for (i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = t[v >> 18];
        out[o++] = t[(v >> 12) & 63];
        if (i + 1 < n || pad)
            out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        if (i + 2 < n || pad)
            out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

size_t npf_b64url_encode(const uint8_t *in, size_t n, char *out)
{
    return b64_encode(in, n, out, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 0);
}

size_t npf_b64std_encode(const uint8_t *in, size_t n, char *out)
{
    return b64_encode(in, n, out, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 1);
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int npf_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap)
{
    size_t i, o = 0;
    uint32_t acc = 0;
    int bits = 0, v;
    if (n % 4 == 1 || n / 4 * 3 + (n % 4 ? n % 4 - 1 : 0) > cap)
        return -1;
    for (i = 0; i < n; i++) {
        if ((v = b64val(in[i])) < 0)
            return -1;
        acc = acc << 6 | (uint32_t)v;
        if ((bits += 6) >= 8)
            out[o++] = (uint8_t)(acc >> (bits -= 8));
    }
    return acc & ((1u << bits) - 1) ? -1 : (int)o;  /* the tail's spare bits zero: one text per value */
}

/* SHA-1: only WebSocket's Sec-WebSocket-Accept (RFC 6455 4.1), never for
 * security; OpenSSL's, else this one (Monocypher has none) */
#ifdef NPF_USE_OPENSSL
void npf_sha1(uint8_t out[20], const void *data, size_t len)
{
    if (!EVP_Digest(data, len, out, NULL, EVP_sha1(), NULL))
        memset(out, 0, 20);             /* no memory: the handshake fails */
}
#else
static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void npf_sha1(uint8_t out[20], const void *data, size_t len)
{
    const uint8_t *msg = data;
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t blk[64];
    size_t total = ((len + 8) / 64 + 1) * 64, off;
    int i;
    for (off = 0; off < total; off += 64) {
        uint32_t w[80], a, b, c, d, e;
        for (i = 0; i < 64; i++) {
            size_t k = off + (size_t)i;
            if (k < len) blk[i] = msg[k];
            else if (k == len) blk[i] = 0x80;
            else if (k >= total - 8) blk[i] = (uint8_t)(((uint64_t)len * 8) >> (8 * (total - 1 - k)));
            else blk[i] = 0;
        }
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) | ((uint32_t)blk[4 * i + 2] << 8) | blk[4 * i + 3];
        for (i = 16; i < 80; i++)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
        for (i = 0; i < 80; i++) {
            uint32_t f, k, tmp;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            tmp = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}
#endif

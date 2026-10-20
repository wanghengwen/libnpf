#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "npf/crypto.h"
#include "npf/platform.h"
#ifdef NPF_USE_OPENSSL
#include "openssl_impl.h"
#endif

void npf_kdf(uint8_t out[32], const void *key, size_t key_len, const void *msg, size_t msg_len)
{
#ifdef NPF_USE_OPENSSL
    if (key_len && ossl_mac(out, 32, "BLAKE2BMAC", key, key_len, msg, msg_len, NULL, 0) == 0)
        return;
#endif
    /* OpenSSL 3.0 has no variable-length unkeyed BLAKE2b. Keep its exact
     * protocol construction; void helpers also fall back on EVP allocation failure. */
    crypto_blake2b_keyed(out, 32, key, key_len, msg, msg_len);
}

void npf_kdf2(uint8_t out[32], const void *key, size_t key_len,
              const void *a, size_t a_len, const void *b, size_t b_len)
{
    crypto_blake2b_ctx ctx;
#ifdef NPF_USE_OPENSSL
    if (key_len && ossl_mac(out, 32, "BLAKE2BMAC", key, key_len, a, a_len, b, b_len) == 0)
        return;
#endif
    crypto_blake2b_keyed_init(&ctx, 32, key, key_len);
    crypto_blake2b_update(&ctx, a, a_len);
    crypto_blake2b_update(&ctx, b, b_len);
    crypto_blake2b_final(&ctx, out);
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
    return ossl_seal(key, nonce, ad, ad_len, in, len, out);
#else
    crypto_chacha20_ietf(out, in, len, key, nonce, 1);
    poly_tag(out + len, key, nonce, ad, ad_len, out, len);
    return 0;
#endif
}

int npf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                  const uint8_t *in, size_t len, uint8_t *out)
{
#ifdef NPF_USE_OPENSSL
    return ossl_open(key, nonce, ad, ad_len, in, len, out);
#else
    uint8_t tag[16];
    if (len < NPF_AEAD_TAG_SIZE)
        return -1;
    len -= NPF_AEAD_TAG_SIZE;
    poly_tag(tag, key, nonce, ad, ad_len, in, len);
    if (crypto_verify16(tag, in + len))
        return -1;
    crypto_chacha20_ietf(out, in, len, key, nonce, 1);
    return 0;
#endif
}

void npf_hash2(uint8_t out[64], const void *a, size_t alen, const void *b, size_t blen)
{
    crypto_blake2b_ctx ctx;
#ifdef NPF_USE_OPENSSL
    if (ossl_hash2(out, a, alen, b, blen) == 0) return;
#endif
    crypto_blake2b_init(&ctx, 64);
    crypto_blake2b_update(&ctx, a, alen);
    crypto_blake2b_update(&ctx, b, blen);
    crypto_blake2b_final(&ctx, out);
}

void npf_hmac_blake2b(uint8_t out[64], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len)
{
    uint8_t k[128], pad[128], inner[64];
    crypto_blake2b_ctx ctx;
    size_t i;
#ifdef NPF_USE_OPENSSL
    if (ossl_mac(out, 64, "HMAC", key, key_len, data, data_len, NULL, 0) == 0) return;
#endif
    memset(k, 0, sizeof k);
    if (key_len > 128)
        crypto_blake2b(k, 64, key, key_len);
    else
        memcpy(k, key, key_len);
    for (i = 0; i < 128; i++) pad[i] = k[i] ^ 0x36;
    crypto_blake2b_init(&ctx, 64);
    crypto_blake2b_update(&ctx, pad, 128);
    crypto_blake2b_update(&ctx, data, data_len);
    crypto_blake2b_final(&ctx, inner);
    for (i = 0; i < 128; i++) pad[i] = k[i] ^ 0x5c;
    crypto_blake2b_init(&ctx, 64);
    crypto_blake2b_update(&ctx, pad, 128);
    crypto_blake2b_update(&ctx, inner, 64);
    crypto_blake2b_final(&ctx, out);
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

void npf_identity_generate(npf_identity *id)
{
    uint8_t seed[32];
    npf_random(seed, 32);
    npf_identity_from_seed(id, seed);
    crypto_wipe(seed, 32);
}

void npf_identity_wipe(npf_identity *id)
{
    crypto_wipe(id, sizeof *id);
}

uint64_t npf_fp(const uint8_t dh_pub[32])
{
    uint8_t h[32];
    crypto_blake2b(h, 32, dh_pub, 32);
    return npf_rd64(h);
}

void npf_sign(uint8_t sig[64], const npf_identity *id, const void *msg, size_t len)
{
#ifdef NPF_USE_OPENSSL
    if (ossl_sign(sig, id->sign_sk, msg, len) == 0) return;
#endif
    crypto_ed25519_sign(sig, id->sign_sk, msg, len);
}

/* Ed25519 has no streaming interface in Monocypher; domain-separated messages
 * are short (certificates, grants, bind proofs), so concatenate on the stack. */
#define SIGN2_MAX 4096

void npf_sign2(uint8_t sig[64], const uint8_t sign_sk[64],
               const void *domain, size_t dlen, const void *msg, size_t len)
{
    uint8_t buf[SIGN2_MAX];
    if (dlen > sizeof buf || len > sizeof buf - dlen) {
        memset(sig, 0, 64);
        return;
    }
    memcpy(buf, domain, dlen);
    memcpy(buf + dlen, msg, len);
#ifdef NPF_USE_OPENSSL
    if (ossl_sign(sig, sign_sk, buf, dlen + len) == 0) return;
#endif
    crypto_ed25519_sign(sig, sign_sk, buf, dlen + len);
}

int npf_verify2(const uint8_t sig[64], const uint8_t pub[32],
                const void *domain, size_t dlen, const void *msg, size_t len)
{
    uint8_t stack[SIGN2_MAX], *buf = stack;
    int r;
    if (dlen > SIZE_MAX - len)
        return -1;
    if (dlen + len > sizeof stack) {
        buf = malloc(dlen + len);      /* server lists (up to 64 KiB) */
        if (!buf)
            return -1;
    }
    memcpy(buf, domain, dlen);
    memcpy(buf + dlen, msg, len);
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

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t npf_b64url_encode(const uint8_t *in, size_t n, char *out)
{
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
        out[o++] = b64[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
    }
    out[o] = 0;
    return o;
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
    size_t i, o = 0, rem = n % 4;
    uint32_t v;
    int a, b, c, d;
    if (rem == 1)
        return -1;
    if (n / 4 * 3 + (rem ? rem - 1 : 0) > cap)
        return -1;
    for (i = 0; i + 3 < n; i += 4) {
        a = b64val(in[i]); b = b64val(in[i + 1]); c = b64val(in[i + 2]); d = b64val(in[i + 3]);
        if ((a | b | c | d) < 0)
            return -1;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
        out[o++] = (uint8_t)v;
    }
    if (rem == 2) {
        a = b64val(in[i]); b = b64val(in[i + 1]);
        if ((a | b) < 0 || (b & 15))
            return -1;
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (rem == 3) {
        a = b64val(in[i]); b = b64val(in[i + 1]); c = b64val(in[i + 2]);
        if ((a | b | c) < 0 || (c & 3))
            return -1;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
    }
    return (int)o;
}

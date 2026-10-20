/* Application-layer cryptography (security.md 12.1).
 * NPF_USE_OPENSSL selects OpenSSL 3 where the protocol primitives are available.
 *
 *   KDF       BLAKE2b-256(key, msg)                          (security.md 3.1)
 *   AEAD      ChaCha20-Poly1305, RFC 8439 (12-byte nonce)    (Noise, WS records)
 *   identity  one 32-byte seed -> Ed25519 signing key + X25519 DH key
 *   fp        BLAKE2b-256(dh_pub)[0..7]: client_id and paired-list fingerprint
 *
 * Everything here is deterministic given its inputs; randomness comes from
 * npf_random() (platform.h). */
#ifndef NPF_CRYPTO_H
#define NPF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define NPF_AEAD_TAG_SIZE 16

/* out = BLAKE2b-256(key = key, msg = msg); key may be NULL / 0 (unkeyed) */
void npf_kdf(uint8_t out[32], const void *key, size_t key_len, const void *msg, size_t msg_len);

/* out = BLAKE2b-256(key, label | data) without concatenating in a buffer */
void npf_kdf2(uint8_t out[32], const void *key, size_t key_len,
              const void *a, size_t a_len, const void *b, size_t b_len);

/* RFC 8439 AEAD. seal writes len bytes of ciphertext followed by the 16-byte tag
 * (out may equal in); returns 0 or -1. open returns 0 and writes len - 16 bytes, or -1. */
int  npf_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                   const uint8_t *in, size_t len, uint8_t *out);
int  npf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                   const uint8_t *in, size_t len, uint8_t *out);

/* BLAKE2b-512(a | b), allowing output to alias either input. */
void npf_hash2(uint8_t out[64], const void *a, size_t alen, const void *b, size_t blen);

/* HMAC-BLAKE2b (block 128, output 64), the Noise HASH = BLAKE2b instance */
void npf_hmac_blake2b(uint8_t out[64], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len);

typedef struct npf_identity {
    uint8_t seed[32];
    uint8_t sign_sk[64];        /* Monocypher Ed25519 secret key (seed | pub) */
    uint8_t sign_pub[32];
    uint8_t dh_sk[32];
    uint8_t dh_pub[32];
} npf_identity;

/* sign seed = KDF(seed, "npf sign v1"), dh_sk = KDF(seed, "npf dh v1") */
void npf_identity_from_seed(npf_identity *id, const uint8_t seed[32]);
void npf_identity_generate(npf_identity *id);
void npf_identity_wipe(npf_identity *id);

/* BLAKE2b-256(dh_pub)[0..7] as a little-endian integer */
uint64_t npf_fp(const uint8_t dh_pub[32]);

void npf_sign(uint8_t sig[64], const npf_identity *id, const void *msg, size_t len);
/* Ed25519 over domain | msg; returns 0 if valid */
int  npf_verify2(const uint8_t sig[64], const uint8_t pub[32],
                 const void *domain, size_t dlen, const void *msg, size_t len);
void npf_sign2(uint8_t sig[64], const uint8_t sign_sk[64],
               const void *domain, size_t dlen, const void *msg, size_t len);

/* X25519; returns -1 when the shared secret is all zero (low-order point) */
int  npf_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32]);
void npf_x25519_pub(uint8_t pk[32], const uint8_t sk[32]);

/* constant-time compare of n bytes, 0 if equal */
int  npf_ct_eq(const void *a, const void *b, size_t n);
void npf_wipe(void *p, size_t n);

/* Base64url without padding. encode returns the string length (out needs
 * 4*ceil(n/3)+1). decode returns the byte count or -1 (bad char, padding,
 * non-canonical tail bits, or more than cap bytes). */
size_t npf_b64url_encode(const uint8_t *in, size_t n, char *out);
int    npf_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap);
#define NPF_B64_LEN(n) ((((n) + 2) / 3) * 4 + 1)

/* little-endian helpers */
static inline void npf_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void npf_le32(uint8_t *p, uint32_t v) { int i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline void npf_le64(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline uint16_t npf_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t npf_rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t npf_rd64(const uint8_t *p) { return (uint64_t)npf_rd32(p) | ((uint64_t)npf_rd32(p + 4) << 32); }

#endif

/* The application layer's cryptography (security.md 12.1): Monocypher, or
 * OpenSSL 3 where it has the primitive (NPF_USE_OPENSSL). Internal to
 * libnpf; in include/npf because npf's app, tray and modules use its
 * base64url, wiping, constant-time compare, hashes and fingerprints (the
 * control socket's token and handshake, key fingerprints in the status).
 *
 *   KDF       BLAKE2b-256(key, msg)                          (security.md 3.1)
 *   AEAD      ChaCha20-Poly1305, RFC 8439 (12-byte nonce)    (Noise)
 *   identity  one 32-byte seed -> Ed25519 signing key + X25519 DH key
 *   fp        BLAKE2b-256(dh_pub)[0..7]: client_id and paired-list fingerprint
 *
 * Every function is deterministic and thread-safe; randomness comes from
 * npf_random() (npf/platform.h). */
#ifndef NPF_CRYPTO_H
#define NPF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define NPF_AEAD_TAG_SIZE 16

/* out = BLAKE2b-256 keyed with key (NULL / 0: unkeyed) of msg. */
void npf_kdf(uint8_t out[32], const void *key, size_t key_len, const void *msg, size_t msg_len);
/* The same of a | b, without joining them in a buffer. */
void npf_kdf2(uint8_t out[32], const void *key, size_t key_len,
              const void *a, size_t a_len, const void *b, size_t b_len);

/* ChaCha20-Poly1305 (RFC 8439). seal writes len bytes of ciphertext and
 * the 16-byte tag to out (out may be in): 0, or -1 (OpenSSL failed). open
 * takes len bytes with the tag and writes len - 16 bytes of plaintext: 0,
 * or -1 (too short, forged) with no plaintext left in out. */
int  npf_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                   const uint8_t *in, size_t len, uint8_t *out);
int  npf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                   const uint8_t *in, size_t len, uint8_t *out);

/* out = BLAKE2b-512(a | b); out may alias either input. */
void npf_hash2(uint8_t out[64], const void *a, size_t alen, const void *b, size_t blen);

/* SHA-1, only for WebSocket's Sec-WebSocket-Accept (not a security use). */
void npf_sha1(uint8_t out[20], const void *data, size_t len);

/* HMAC with BLAKE2b-512 (block 128 bytes), as Noise uses it. */
void npf_hmac_blake2b(uint8_t out[64], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len);

typedef struct npf_identity {
    uint8_t seed[32];
    uint8_t sign_sk[64];        /* Monocypher Ed25519 secret key (seed | pub) */
    uint8_t sign_pub[32];
    uint8_t dh_sk[32];
    uint8_t dh_pub[32];
} npf_identity;

/* Derives the keys from seed (which may be id->seed): the Ed25519 seed is
 * KDF(seed, "npf sign v1"), dh_sk is KDF(seed, "npf dh v1"). npf_identity_wipe
 * wipes all of id: call it when done, it holds secret keys. */
void npf_identity_from_seed(npf_identity *id, const uint8_t seed[32]);
void npf_identity_wipe(npf_identity *id);

/* BLAKE2b-256(dh_pub)[0..7] as a little-endian integer. */
uint64_t npf_fp(const uint8_t dh_pub[32]);

/* Ed25519 over domain | msg. verify: 0 when valid, else -1 (also when out
 * of memory). sign: on no memory sig is zeros, which never verify. */
int  npf_verify2(const uint8_t sig[64], const uint8_t pub[32],
                 const void *domain, size_t dlen, const void *msg, size_t len);
void npf_sign2(uint8_t sig[64], const uint8_t sign_sk[64],
               const void *domain, size_t dlen, const void *msg, size_t len);

/* X25519: 0, or -1 when the shared secret is all zero (a low-order pk). */
int  npf_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32]);
void npf_x25519_pub(uint8_t pk[32], const uint8_t sk[32]);

/* Compares n bytes in constant time: 0 when equal (note: not a boolean). */
int  npf_ct_eq(const void *a, const void *b, size_t n);
/* Zeroes n bytes in a way the compiler keeps. */
void npf_wipe(void *p, size_t n);
void npf_wipe_free(void *p, size_t n);     /* npf_wipe, then free; NULL does nothing */

/* Base64url without padding. encode writes NPF_B64_LEN(n) bytes at most,
 * NUL included, and returns the length without the NUL. decode: the byte
 * count, or -1 for a bad character (padding too), a non-canonical tail, or
 * more than cap bytes. */
size_t npf_b64url_encode(const uint8_t *in, size_t n, char *out);
int    npf_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap);
#define NPF_B64_LEN(n) ((((n) + 2) / 3) * 4 + 1)
/* Standard base64 with padding (WebSocket's keys), as encode above. */
size_t npf_b64std_encode(const uint8_t *in, size_t n, char *out);

/* little-endian helpers */
static inline void npf_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void npf_le32(uint8_t *p, uint32_t v) { int i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline void npf_le64(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline uint16_t npf_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t npf_rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t npf_rd64(const uint8_t *p) { return (uint64_t)npf_rd32(p) | ((uint64_t)npf_rd32(p + 4) << 32); }
/* big-endian (network order: DNS, PCP, NAT-PMP, IPv4 addresses) */
static inline void npf_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void npf_be32(uint8_t *p, uint32_t v) { npf_be16(p, (uint16_t)(v >> 16)); npf_be16(p + 2, (uint16_t)v); }
static inline uint16_t npf_rdbe16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t npf_rdbe32(const uint8_t *p) { return (uint32_t)npf_rdbe16(p) << 16 | npf_rdbe16(p + 2); }

#endif

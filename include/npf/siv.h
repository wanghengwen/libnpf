/* SIV packet sealing shared by address probing, hole punching and AnLiu.
 *
 * Same construction as AnLiu (DESIGN 3.1/3.2): per-direction keys derived with
 * one ChaCha20 block, tag = SipHash-2-4-128(k_mac[dir], P)[0..11], P encrypted
 * with ChaCha20(k_enc[dir], nonce = tag). Only the KDF label differs, so the
 * packet classes cannot be confused with each other (nat-traversal.md 6.2). */
#ifndef NPF_SIV_H
#define NPF_SIV_H

#include <stddef.h>
#include <stdint.h>

#define NPF_SIV_TAG_SIZE  12
#define NPF_SIV_KEY_SIZE  32

/* KDF labels, exactly 12 bytes (the ChaCha20 nonce of the KDF block) */
#define NPF_SIV_LABEL_PROBE "NPF-PROBE-v1"
#define NPF_SIV_LABEL_PUNCH "NPF-PUNCH-v1"   /* PROBE / PROBE_ACK, keyed by punch_key */
#define NPF_SIV_LABEL_NOMIN "NPF-NOMIN-v1"   /* NOMINATE / NOMINATE_ACK, keyed by nominate_key */

typedef struct npf_siv_keys {
    uint8_t enc[2][32];         /* ChaCha20 key, index = sender direction */
    uint8_t mac[2][16];         /* SipHash key */
} npf_siv_keys;

void npf_siv_derive(npf_siv_keys *keys, const uint8_t key[NPF_SIV_KEY_SIZE], const char label[12]);

/* Seal in place: buf = tag slot (12) followed by plen bytes of P. */
void npf_siv_seal(const npf_siv_keys *keys, int dir, uint8_t *buf, size_t plen);

/* Verify and decrypt `in` (tag + ciphertext) into `plain` (capacity >= len - 12).
 * `in` is left untouched so the caller can try other keys on failure.
 * Returns plen, or -1 when authentication fails. */
int npf_siv_open(const npf_siv_keys *keys, int dir, const uint8_t *in, size_t len, uint8_t *plain);

/* primitives, exported for the known-answer tests */
void npf_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]);
void npf_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *buf, size_t len);
void npf_siphash128(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t out[16]);

#endif

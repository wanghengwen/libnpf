/* Noise Protocol Framework, 25519 / ChaChaPoly / BLAKE2b (security.md 7.2, 9.3, 9.4).
 *
 *   XK      node/client -> server signaling (prologue "npf-ws-v1"), WS relay ("npf-relay-v1")
 *   IK      caller -> callee daily connection (prologue "npf-conn-v1" | call_id | number)
 *   XXpsk3  first pairing, psk = CPace output (prologue "npf-pair-v1" | sid)
 *   NNpsk0  direct connection to IP:port with a pre-shared key (prologue "npf-direct-v1")
 *
 * One implementation serves both roles. Messages are produced and consumed
 * whole; the caller moves them over whatever carrier (WebSocket, JSON field). */
#ifndef NPF_NOISE_H
#define NPF_NOISE_H

#include <stddef.h>
#include <stdint.h>

#include "npf/crypto.h"

enum { NPF_NOISE_XK = 1, NPF_NOISE_IK = 2, NPF_NOISE_XXPSK3 = 3, NPF_NOISE_NNPSK0 = 4 };

#define NPF_NOISE_MAX_MSG   65535
#define NPF_NOISE_HASHLEN   64

typedef struct npf_noise_cs {
    uint8_t  k[32];
    uint64_t n;
    int      has_key;
} npf_noise_cs;

typedef struct npf_noise_hs {
    int      pattern;
    int      initiator;
    int      step;                  /* index of the next message */
    int      done;
    uint8_t  ck[NPF_NOISE_HASHLEN];
    uint8_t  h[NPF_NOISE_HASHLEN];
    npf_noise_cs cs;
    uint8_t  s_sk[32], s_pub[32];
    uint8_t  e_sk[32], e_pub[32];
    uint8_t  rs[32], re[32];
    uint8_t  psk[32];
    int      has_s, has_e, has_rs, has_re, has_psk;
    int      fixed_e;               /* tests: e_sk preset */
} npf_noise_hs;

/* s_sk: local static private key (NULL if the pattern has none for this side);
 * rs: the peer's static public key when known beforehand (XK/IK initiator);
 * psk: XXpsk3 only. Returns 0 or -1 (missing key for the pattern). */
int npf_noise_init(npf_noise_hs *hs, int pattern, int initiator,
                   const void *prologue, size_t prologue_len,
                   const uint8_t *s_sk, const uint8_t *rs, const uint8_t *psk);

/* tests only: use this ephemeral private key instead of a random one */
void npf_noise_fix_ephemeral(npf_noise_hs *hs, const uint8_t e_sk[32]);

/* XXpsk3: the psk may become known only after the first messages (CPace runs
 * in parallel); set it before the message carrying the psk token. */
void npf_noise_set_psk(npf_noise_hs *hs, const uint8_t psk[32]);

/* Next handshake message. Returns its length, or -1 (wrong turn, buffer too
 * small, DH failure). */
int npf_noise_write(npf_noise_hs *hs, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap);

/* Consume the peer's message. Returns the payload length, or -1 (decryption
 * failure, wrong length, wrong turn). On failure the state must be discarded. */
int npf_noise_read(npf_noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload, size_t cap);

/* Is it our turn to write? */
int npf_noise_my_turn(const npf_noise_hs *hs);

/* After the last message: transport keys. tx encrypts what we send.
 * Returns -1 if the handshake is not finished. The handshake state is wiped. */
int npf_noise_split(npf_noise_hs *hs, npf_noise_cs *tx, npf_noise_cs *rx,
                    uint8_t k1[32], uint8_t k2[32], uint8_t hash[NPF_NOISE_HASHLEN]);

/* Peer static key, valid once it has been received (or preset). */
const uint8_t *npf_noise_remote_static(const npf_noise_hs *hs);

/* Transport: out = ciphertext | tag (len + 16). out may equal in.
 * decrypt returns the plaintext length or -1. */
int npf_noise_encrypt(npf_noise_cs *cs, const uint8_t *ad, size_t ad_len,
                      const uint8_t *in, size_t len, uint8_t *out);
int npf_noise_decrypt(npf_noise_cs *cs, const uint8_t *ad, size_t ad_len,
                      const uint8_t *in, size_t len, uint8_t *out);

#endif

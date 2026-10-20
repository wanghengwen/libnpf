/* CPace over X25519 with Elligator2 (security.md 9.3).
 *
 *   G   = Elligator2(BLAKE2b-256("npf-cpace-v1" | len(pw) | pw | len(sid) | sid))
 *   Y   = X25519(y, G)                     y random, one message each way
 *   K   = X25519(y, Y_peer)
 *   ISK = BLAKE2b-256(key = K, "npf-cpace-isk-v1" | sid | Y_initiator | Y_responder)
 *
 * ISK is the psk of the Noise XXpsk3 handshake that follows. A party that does
 * not know pw learns nothing it can test offline; each run tests one guess. */
#ifndef NPF_CPACE_H
#define NPF_CPACE_H

#include <stddef.h>
#include <stdint.h>

typedef struct npf_cpace {
    uint8_t y[32];
    uint8_t Y[32];
    uint8_t sid[64];
    size_t  sid_len;
} npf_cpace;

/* returns 0 and the 32-byte message to send, -1 on bad input */
int npf_cpace_start(npf_cpace *c, const char *pw, size_t pw_len, const uint8_t *sid, size_t sid_len,
                    uint8_t msg[32]);
/* tests: fixed scalar */
int npf_cpace_start_fixed(npf_cpace *c, const char *pw, size_t pw_len, const uint8_t *sid, size_t sid_len,
                          const uint8_t y[32], uint8_t msg[32]);
/* returns 0 and the shared key, -1 if the peer message is invalid */
int npf_cpace_finish(npf_cpace *c, const uint8_t peer[32], int initiator, uint8_t isk[32]);

#endif

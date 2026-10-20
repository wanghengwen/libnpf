#include <string.h>

#include "monocypher.h"
#include "npf/cpace.h"
#include "npf/crypto.h"
#include "npf/platform.h"

int npf_cpace_start_fixed(npf_cpace *c, const char *pw, size_t pw_len, const uint8_t *sid, size_t sid_len,
                          const uint8_t y[32], uint8_t msg[32])
{
    crypto_blake2b_ctx h;
    uint8_t rep[32], G[32], l;
    static const uint8_t zero[32];
    if (pw_len > 255 || sid_len > sizeof c->sid)
        return -1;
    crypto_blake2b_init(&h, 32);
    crypto_blake2b_update(&h, (const uint8_t *)"npf-cpace-v1", 12);
    l = (uint8_t)pw_len;
    crypto_blake2b_update(&h, &l, 1);
    crypto_blake2b_update(&h, (const uint8_t *)pw, pw_len);
    l = (uint8_t)sid_len;
    crypto_blake2b_update(&h, &l, 1);
    crypto_blake2b_update(&h, sid, sid_len);
    crypto_blake2b_final(&h, rep);
    crypto_elligator_map(G, rep);
    memcpy(c->y, y, 32);
    if (npf_x25519(c->Y, c->y, G) < 0) {
        npf_wipe(rep, 32);
        npf_wipe(G, 32);
        npf_wipe(c->y, 32);
        return -1;
    }
    memcpy(c->sid, sid, sid_len);
    c->sid_len = sid_len;
    crypto_wipe(rep, 32);
    crypto_wipe(G, 32);
    if (crypto_verify32(c->Y, zero) == 0)
        return -1;
    memcpy(msg, c->Y, 32);
    return 0;
}

int npf_cpace_start(npf_cpace *c, const char *pw, size_t pw_len, const uint8_t *sid, size_t sid_len,
                    uint8_t msg[32])
{
    uint8_t y[32];
    int r;
    npf_random(y, 32);
    r = npf_cpace_start_fixed(c, pw, pw_len, sid, sid_len, y, msg);
    crypto_wipe(y, 32);
    return r;
}

int npf_cpace_finish(npf_cpace *c, const uint8_t peer[32], int initiator, uint8_t isk[32])
{
    uint8_t K[32];
    crypto_blake2b_ctx h;
    if (npf_x25519(K, c->y, peer) < 0)
        return -1;
    crypto_blake2b_keyed_init(&h, 32, K, 32);
    crypto_blake2b_update(&h, (const uint8_t *)"npf-cpace-isk-v1", 16);
    crypto_blake2b_update(&h, c->sid, c->sid_len);
    crypto_blake2b_update(&h, initiator ? c->Y : peer, 32);
    crypto_blake2b_update(&h, initiator ? peer : c->Y, 32);
    crypto_blake2b_final(&h, isk);
    crypto_wipe(K, 32);
    crypto_wipe(c->y, 32);
    return 0;
}

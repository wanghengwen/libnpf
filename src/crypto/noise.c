/* Noise handshake state machine (Noise spec rev 34, sections 5 and 7). */
#include <string.h>

#include "npf/noise.h"
#include "npf/platform.h"

enum { T_E = 1, T_S, T_EE, T_ES, T_SE, T_SS, T_PSK, T_END = 0 };

#define MAX_TOKENS 6
#define MAX_MSGS   3

typedef struct pattern {
    const char *name;
    int pre_rs;                     /* responder static is a pre-message */
    int nmsg;
    int tok[MAX_MSGS][MAX_TOKENS];
    int psk;
} pattern;

static const pattern patterns[] = {
    [NPF_NOISE_XK] = {"Noise_XK_25519_ChaChaPoly_BLAKE2b", 1, 3,
                      {{T_E, T_ES}, {T_E, T_EE}, {T_S, T_SE}}, 0},
    [NPF_NOISE_IK] = {"Noise_IK_25519_ChaChaPoly_BLAKE2b", 1, 2,
                      {{T_E, T_ES, T_S, T_SS}, {T_E, T_EE, T_SE}}, 0},
    [NPF_NOISE_XXPSK3] = {"Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b", 0, 3,
                          {{T_E}, {T_E, T_EE, T_S, T_ES}, {T_S, T_SE, T_PSK}}, 1},
    [NPF_NOISE_NNPSK0] = {"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2b", 0, 2,
                          {{T_PSK, T_E}, {T_E, T_EE}}, 1},
};

static void mix_hash(npf_noise_hs *hs, const uint8_t *data, size_t len)
{
    npf_hash2(hs->h, hs->h, 64, data, len);
}

/* HKDF(ck, ikm) -> n outputs of 64 bytes */
static void hkdf(const uint8_t ck[64], const uint8_t *ikm, size_t ikm_len, int n,
                 uint8_t o1[64], uint8_t o2[64], uint8_t o3[64])
{
    uint8_t temp[64], buf[65];
    npf_hmac_blake2b(temp, ck, 64, ikm, ikm_len);
    buf[0] = 1;
    npf_hmac_blake2b(o1, temp, 64, buf, 1);
    memcpy(buf, o1, 64);
    buf[64] = 2;
    npf_hmac_blake2b(o2, temp, 64, buf, 65);
    if (n == 3) {
        memcpy(buf, o2, 64);
        buf[64] = 3;
        npf_hmac_blake2b(o3, temp, 64, buf, 65);
    }
    npf_wipe(temp, sizeof temp);
    npf_wipe(buf, sizeof buf);
}

static void mix_key(npf_noise_hs *hs, const uint8_t *ikm, size_t len)
{
    uint8_t ck[64], k[64];
    hkdf(hs->ck, ikm, len, 2, ck, k, NULL);
    memcpy(hs->ck, ck, 64);
    memcpy(hs->cs.k, k, 32);
    hs->cs.n = 0;
    hs->cs.has_key = 1;
    npf_wipe(ck, 64);
    npf_wipe(k, 64);
}

static void mix_key_and_hash(npf_noise_hs *hs, const uint8_t *ikm, size_t len)
{
    uint8_t ck[64], th[64], k[64];
    hkdf(hs->ck, ikm, len, 3, ck, th, k);
    memcpy(hs->ck, ck, 64);
    mix_hash(hs, th, 64);
    memcpy(hs->cs.k, k, 32);
    hs->cs.n = 0;
    hs->cs.has_key = 1;
    npf_wipe(ck, 64);
    npf_wipe(th, 64);
    npf_wipe(k, 64);
}

static void nonce_of(uint8_t nonce[12], uint64_t n)
{
    memset(nonce, 0, 4);
    npf_le64(nonce + 4, n);
}

int npf_noise_encrypt(npf_noise_cs *cs, const uint8_t *ad, size_t ad_len,
                      const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t nonce[12];
    if (cs->n == UINT64_MAX)
        return -1;
    nonce_of(nonce, cs->n++);
    if (npf_aead_seal(cs->k, nonce, ad, ad_len, in, len, out) < 0)
        return -1;
    return (int)(len + NPF_AEAD_TAG_SIZE);
}

int npf_noise_decrypt(npf_noise_cs *cs, const uint8_t *ad, size_t ad_len,
                      const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t nonce[12];
    if (cs->n == UINT64_MAX || len < NPF_AEAD_TAG_SIZE)
        return -1;
    nonce_of(nonce, cs->n);
    if (npf_aead_open(cs->k, nonce, ad, ad_len, in, len, out))
        return -1;
    cs->n++;
    return (int)(len - NPF_AEAD_TAG_SIZE);
}

/* EncryptAndHash: out gets len (+16 when keyed) bytes */
static int enc_hash(npf_noise_hs *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    int n;
    if (!hs->cs.has_key) {
        memmove(out, in, len);
        mix_hash(hs, out, len);
        return (int)len;
    }
    n = npf_noise_encrypt(&hs->cs, hs->h, 64, in, len, out);
    if (n >= 0)
        mix_hash(hs, out, (size_t)n);
    return n;
}

static int dec_hash(npf_noise_hs *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t h[64];
    int n;
    if (!hs->cs.has_key) {
        mix_hash(hs, in, len);
        memmove(out, in, len);
        return (int)len;
    }
    memcpy(h, hs->h, 64);
    mix_hash(hs, in, len);          /* h after = HASH(h || ciphertext) */
    n = npf_noise_decrypt(&hs->cs, h, 64, in, len, out);
    return n;
}

int npf_noise_init(npf_noise_hs *hs, int pattern_id, int initiator,
                   const void *prologue, size_t prologue_len,
                   const uint8_t *s_sk, const uint8_t *rs, const uint8_t *psk)
{
    const pattern *p;
    size_t nl;
    if (pattern_id < NPF_NOISE_XK || pattern_id > NPF_NOISE_NNPSK0)
        return -1;
    p = &patterns[pattern_id];
    memset(hs, 0, sizeof *hs);
    hs->pattern = pattern_id;
    hs->initiator = initiator;
    nl = strlen(p->name);
    if (nl <= 64) {
        memcpy(hs->h, p->name, nl);
    } else {
        npf_hash2(hs->h, p->name, nl, NULL, 0);
    }
    memcpy(hs->ck, hs->h, 64);
    mix_hash(hs, prologue, prologue_len);

    if (s_sk) {
        memcpy(hs->s_sk, s_sk, 32);
        npf_x25519_pub(hs->s_pub, hs->s_sk);
        hs->has_s = 1;
    }
    if (rs) {
        memcpy(hs->rs, rs, 32);
        hs->has_rs = 1;
    }
    if (psk) {
        memcpy(hs->psk, psk, 32);
        hs->has_psk = 1;
    }
    /* every pattern here except NN needs a local static on both sides */
    if (!hs->has_s && pattern_id != NPF_NOISE_NNPSK0)
        return -1;
    if (p->pre_rs) {
        if (initiator) {
            if (!hs->has_rs)
                return -1;
            mix_hash(hs, hs->rs, 32);
        } else {
            mix_hash(hs, hs->s_pub, 32);
        }
    }
    return 0;
}

void npf_noise_fix_ephemeral(npf_noise_hs *hs, const uint8_t e_sk[32])
{
    memcpy(hs->e_sk, e_sk, 32);
    hs->fixed_e = 1;
}

void npf_noise_set_psk(npf_noise_hs *hs, const uint8_t psk[32])
{
    memcpy(hs->psk, psk, 32);
    hs->has_psk = 1;
}

int npf_noise_my_turn(const npf_noise_hs *hs)
{
    return !hs->done && ((hs->step % 2 == 0) == (hs->initiator != 0));
}

/* the DH for a token from this side's point of view */
static int token_dh(npf_noise_hs *hs, int t)
{
    uint8_t shared[32];
    const uint8_t *sk, *pk;
    int r;
    int ini = hs->initiator;
    switch (t) {
    case T_EE: sk = hs->e_sk; pk = hs->re; break;
    case T_ES: sk = ini ? hs->e_sk : hs->s_sk; pk = ini ? hs->rs : hs->re; break;
    case T_SE: sk = ini ? hs->s_sk : hs->e_sk; pk = ini ? hs->re : hs->rs; break;
    case T_SS: sk = hs->s_sk; pk = hs->rs; break;
    default: return -1;
    }
    r = npf_x25519(shared, sk, pk);
    if (r == 0)
        mix_key(hs, shared, 32);
    npf_wipe(shared, 32);
    return r;
}

int npf_noise_write(npf_noise_hs *hs, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap)
{
    const pattern *p = &patterns[hs->pattern];
    const int *tok;
    size_t o = 0;
    int i, n;
    if (!npf_noise_my_turn(hs) || hs->step >= p->nmsg)
        return -1;
    tok = p->tok[hs->step];
    for (i = 0; i < MAX_TOKENS && tok[i] != T_END; i++) {
        switch (tok[i]) {
        case T_E:
            if (o + 32 > cap)
                return -1;
            if (!hs->fixed_e)
                npf_random(hs->e_sk, 32);
            npf_x25519_pub(hs->e_pub, hs->e_sk);
            hs->has_e = 1;
            memcpy(out + o, hs->e_pub, 32);
            mix_hash(hs, hs->e_pub, 32);
            if (p->psk)
                mix_key(hs, hs->e_pub, 32);
            o += 32;
            break;
        case T_S:
            if (o + 32 + (hs->cs.has_key ? 16 : 0) > cap)
                return -1;
            n = enc_hash(hs, hs->s_pub, 32, out + o);
            if (n < 0)
                return -1;
            o += (size_t)n;
            break;
        case T_PSK:
            if (!hs->has_psk)
                return -1;
            mix_key_and_hash(hs, hs->psk, 32);
            break;
        default:
            if (token_dh(hs, tok[i]))
                return -1;
        }
    }
    if (o + plen + (hs->cs.has_key ? 16 : 0) > cap)
        return -1;
    n = enc_hash(hs, payload, plen, out + o);
    if (n < 0)
        return -1;
    o += (size_t)n;
    hs->step++;
    if (hs->step == p->nmsg)
        hs->done = 1;
    return (int)o;
}

int npf_noise_read(npf_noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload, size_t cap)
{
    const pattern *p = &patterns[hs->pattern];
    const int *tok;
    size_t o = 0, need;
    int i, n;
    if (hs->done || npf_noise_my_turn(hs) || hs->step >= p->nmsg)
        return -1;
    tok = p->tok[hs->step];
    for (i = 0; i < MAX_TOKENS && tok[i] != T_END; i++) {
        switch (tok[i]) {
        case T_E:
            if (o + 32 > len)
                return -1;
            memcpy(hs->re, msg + o, 32);
            hs->has_re = 1;
            mix_hash(hs, hs->re, 32);
            if (p->psk)
                mix_key(hs, hs->re, 32);
            o += 32;
            break;
        case T_S:
            need = 32 + (hs->cs.has_key ? 16 : 0);
            if (o + need > len)
                return -1;
            if (dec_hash(hs, msg + o, need, hs->rs) != 32)
                return -1;
            hs->has_rs = 1;
            o += need;
            break;
        case T_PSK:
            if (!hs->has_psk)
                return -1;
            mix_key_and_hash(hs, hs->psk, 32);
            break;
        default:
            if (token_dh(hs, tok[i]))
                return -1;
        }
    }
    need = len - o;
    if (need - (hs->cs.has_key ? 16 : 0) > cap || (hs->cs.has_key && need < 16))
        return -1;
    n = dec_hash(hs, msg + o, need, payload);
    if (n < 0)
        return -1;
    hs->step++;
    if (hs->step == p->nmsg)
        hs->done = 1;
    return n;
}

int npf_noise_split(npf_noise_hs *hs, npf_noise_cs *tx, npf_noise_cs *rx,
                    uint8_t k1[32], uint8_t k2[32], uint8_t hash[NPF_NOISE_HASHLEN])
{
    uint8_t t1[64], t2[64];
    if (!hs->done)
        return -1;
    hkdf(hs->ck, NULL, 0, 2, t1, t2, NULL);
    if (k1) memcpy(k1, t1, 32);
    if (k2) memcpy(k2, t2, 32);
    if (hash) memcpy(hash, hs->h, 64);
    if (tx && rx) {
        memset(tx, 0, sizeof *tx);
        memset(rx, 0, sizeof *rx);
        memcpy(hs->initiator ? tx->k : rx->k, t1, 32);
        memcpy(hs->initiator ? rx->k : tx->k, t2, 32);
        tx->has_key = rx->has_key = 1;
    }
    npf_wipe(t1, 64);
    npf_wipe(t2, 64);
    /* keep rs for npf_noise_remote_static; wipe the secrets */
    npf_wipe(hs->ck, 64);
    npf_wipe(&hs->cs, sizeof hs->cs);
    npf_wipe(hs->s_sk, 32);
    npf_wipe(hs->e_sk, 32);
    npf_wipe(hs->psk, 32);
    return 0;
}

const uint8_t *npf_noise_remote_static(const npf_noise_hs *hs)
{
    return hs->has_rs ? hs->rs : NULL;
}

/* Private helpers included by crypto.c only when NPF_USE_OPENSSL is set.
 * No global EVP contexts: calls from independent instances can run in parallel. */
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

static int ossl_mac(uint8_t *out, size_t size, const char *name,
                    const void *key, size_t key_len, const void *a, size_t alen, const void *b, size_t blen)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM params[2];
    size_t got = 0;
    int ok;
    if (strcmp(name, "HMAC") == 0)
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "BLAKE2B-512", 0);
    else
        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    ok = ctx && EVP_MAC_init(ctx, key, key_len, params) == 1
         && (!alen || EVP_MAC_update(ctx, a, alen) == 1)
         && (!blen || EVP_MAC_update(ctx, b, blen) == 1)
         && EVP_MAC_final(ctx, out, &got, size) == 1 && got == size;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok ? 0 : -1;
}

static int ossl_hash2(uint8_t out[64], const void *a, size_t alen, const void *b, size_t blen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned got = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL) == 1
        && (!alen || EVP_DigestUpdate(ctx, a, alen) == 1)
        && (!blen || EVP_DigestUpdate(ctx, b, blen) == 1)
        && EVP_DigestFinal_ex(ctx, out, &got) == 1 && got == 64;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int ossl_public(int type, uint8_t out[32], const uint8_t sk[32])
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(type, NULL, sk, 32);
    size_t size = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key, out, &size) == 1 && size == 32;
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

static int ossl_sign(uint8_t sig[64], const uint8_t sk[32], const void *msg, size_t len)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t size = 64;
    int ok = key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1
        && EVP_DigestSign(ctx, sig, &size, msg, len) == 1 && size == 64;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

static int ossl_verify(const uint8_t sig[64], const uint8_t pk[32], const void *msg, size_t len)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1
        && EVP_DigestVerify(ctx, sig, 64, msg, len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

static int ossl_dh(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, 32);
    EVP_PKEY_CTX *ctx = key ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    size_t size = 32;
    int ok = ctx && peer && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1
        && EVP_PKEY_derive(ctx, out, &size) == 1 && size == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(key);
    if (!ok) OPENSSL_cleanse(out, 32);
    return ok ? 0 : -1;
}

static int ossl_seal(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                     const uint8_t *in, size_t len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int n = 0, tail = 0, ok;
    if (len > INT_MAX || ad_len > INT_MAX) return -1;
    ctx = EVP_CIPHER_CTX_new();
    ok = ctx && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1
        && (!ad_len || EVP_EncryptUpdate(ctx, NULL, &n, ad, (int)ad_len) == 1)
        && EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1 && (size_t)n == len
        && EVP_EncryptFinal_ex(ctx, out + n, &tail) == 1 && tail == 0
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) OPENSSL_cleanse(out, len + 16);
    return ok ? 0 : -1;
}

static int ossl_open(const uint8_t key[32], const uint8_t nonce[12], const void *ad, size_t ad_len,
                     const uint8_t *in, size_t len, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int n = 0, tail = 0, ok;
    if (len < 16 || len - 16 > INT_MAX || ad_len > INT_MAX) return -1;
    len -= 16;
    ctx = EVP_CIPHER_CTX_new();
    ok = ctx && EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(in + len)) == 1
        && (!ad_len || EVP_DecryptUpdate(ctx, NULL, &n, ad, (int)ad_len) == 1)
        && EVP_DecryptUpdate(ctx, out, &n, in, (int)len) == 1 && (size_t)n == len
        && EVP_DecryptFinal_ex(ctx, out + n, &tail) == 1 && tail == 0;
    EVP_CIPHER_CTX_free(ctx);
    /* EVP writes plaintext before checking its tag; never leave it on failure. */
    if (!ok) OPENSSL_cleanse(out, len);
    return ok ? 0 : -1;
}

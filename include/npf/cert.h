/* NPF certificates and the signed server list (security.md 3.2, 7.5).
 *
 *   cert = ver(1)=1 | type(1) | issuer_key_id(4) | serial(8) | subject(8)
 *        | not_before(4) | not_after(4) | ext_len(2) | ext | sign_pub(32) | dh_pub(32) | sig(64)
 *   sig  = Ed25519(issuer, "npf-cert-v1" | everything before sig)
 *   issuer_key_id = BLAKE2b-256(issuer sign_pub)[0..3]
 *
 * The C side only parses and verifies; the platform signs. Internal to
 * libnpf; in include/npf because npf's upgrade module verifies its signed
 * manifest with npf_signed_verify. Pointers into a parsed buffer are valid
 * while that buffer lives. */
#ifndef NPF_CERT_H
#define NPF_CERT_H

#include <stddef.h>
#include <stdint.h>

enum {
    NPF_CERT_INTERMEDIATE = 1,
    NPF_CERT_MODEL = 2,             /* a model credential, signed by its vendor's certificate */
    NPF_CERT_NODE = 3,
    NPF_CERT_CLIENT = 5,
    NPF_CERT_VENDOR = 6,            /* a vendor, signed by NPF's vendor issuer */
};

#define NPF_PERM_SERVERLIST (1u << 8)
#define NPF_PERM_GRANT      (1u << 9)
#define NPF_PERM_UPDATE     (1u << 10)
#define NPF_CERT_MAX        512

typedef struct npf_cert {
    int      type;
    uint32_t issuer_key;
    uint64_t serial;
    uint64_t subject;
    uint32_t not_before, not_after;
    uint32_t key_gen, vendor, product;
    uint64_t account;
    uint16_t perms;
    int      hosted;
    uint8_t  sign_pub[32];
    uint8_t  dh_pub[32];
    uint8_t  sig[64];
    const uint8_t *raw;             /* the whole certificate, in the parsed buffer */
    size_t   raw_len;
} npf_cert;

/* Parses one certificate at the start of buf; no signature or validity
 * check. Unknown extensions are skipped; a known one of the wrong length
 * fails. The bytes it takes, or -1. */
int npf_cert_parse(const uint8_t *buf, size_t len, npf_cert *c);

/* Parses and verifies buf, exactly "inter | leaf": inter is an
 * intermediate signed by one of the roots whose perms include the bit
 * 1 << leaf->type, leaf is signed by inter, and both are valid at now
 * (Unix s; 0 skips the validity periods). The caller checks the leaf's
 * type and subject. 0 or -1. */
int npf_cert_chain_parse(const uint8_t (*roots)[32], int nroots, const uint8_t *buf, size_t len,
                         npf_cert *inter, npf_cert *leaf, int64_t now);

/* Verifies a signed blob: the server list (perm NPF_PERM_SERVERLIST) or an
 * update manifest (NPF_PERM_UPDATE), each signed under its own domain by
 * an intermediate that has perm and is signed by one of the roots. 0 with
 * *payload (JSON) pointing into blob, or -1 (any other perm too). Validity
 * periods are not checked: an expired list stays usable (D15). */
int npf_signed_verify(const uint8_t (*roots)[32], int nroots, unsigned perm, const uint8_t *blob, size_t len,
                      const uint8_t **payload, size_t *payload_len);

/* A grant, the platform's leave for a caller: an account's or hosted trust's (security.md 8.2, 8.4):
 *   ver(1)=1 | kind(1) | number(8) | caller_dh(32) | account(8) | issued(4) | expires(4)
 *   | tlen(2) | targets | issuer_key_id(4) | sig(64);  target = host_len(1) | host | port(2)
 *   sig = Ed25519(intermediate, "npf-grant-v1" or "npf-grant-hosted-v1" | everything before sig) */
enum { NPF_GRANT_ACCOUNT = 1, NPF_GRANT_HOSTED = 2 };

typedef struct npf_grant {
    int      kind;
    uint64_t number;
    uint8_t  caller_dh[32];
    uint64_t account;
    uint32_t issued, expires;
    const uint8_t *targets;         /* in the parsed buffer */
    size_t   tlen;
} npf_grant;

/* Parses a grant and checks its format, its issuer key id and its
 * signature by issuer_pub (domain by kind: NPF_GRANT_HOSTED's, else the
 * account one's). It does not check kind, number, caller_dh, account or
 * expiry: the caller does. 0 or -1. */
int npf_grant_verify(const uint8_t *b, size_t len, const uint8_t issuer_pub[32], npf_grant *g);
/* 1 when host (compared byte for byte) and port are in g's target list. */
int npf_grant_target_allowed(const npf_grant *g, const char *host, uint16_t port);

/* Writes the message a node signs to accept an owner (security.md 8.2)
 * and returns its length, 60. */
size_t npf_bind_proof_msg(uint8_t out[64], uint64_t number, uint32_t key_gen, uint64_t account,
                          const uint8_t op[16], const uint8_t challenge[16], int64_t expires);

#endif

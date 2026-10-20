/* NPF certificates and the signed server list (security.md 3.2, 7.5).
 *
 *   cert = ver(1)=1 | type(1) | issuer_key_id(4) | serial(8) | subject(8)
 *        | not_before(4) | not_after(4) | ext_len(2) | ext | sign_pub(32) | dh_pub(32) | sig(64)
 *   sig  = Ed25519(issuer, "npf-cert-v1" | everything before sig)
 *   issuer_key_id = BLAKE2b-256(issuer sign_pub)[0..3]
 *
 * The C side only parses and verifies; signing happens on the platform (Go,
 * server/internal/npfcrypto). */
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
    const uint8_t *raw;             /* points into the parsed buffer */
    size_t   raw_len;
} npf_cert;

/* Parse one certificate at the start of buf. Returns bytes consumed or -1. */
int npf_cert_parse(const uint8_t *buf, size_t len, npf_cert *c);

uint32_t npf_key_id(const uint8_t sign_pub[32]);

/* signature check against an issuer key (key id must match); 0 if valid */
int npf_cert_check_sig(const npf_cert *c, const uint8_t issuer_pub[32]);

/* Verify an intermediate against the root keys (and, when leaf != NULL, the
 * leaf against the intermediate). now == 0 skips validity periods.
 * Returns 0 if valid. */
int npf_cert_chain_verify(const uint8_t (*roots)[32], int nroots, const npf_cert *inter,
                          unsigned perm, const npf_cert *leaf, int64_t now);

/* Parse and verify "inter | leaf" (the chain as the platform sends it). */
int npf_cert_chain_parse(const uint8_t (*roots)[32], int nroots, const uint8_t *buf, size_t len,
                         npf_cert *inter, npf_cert *leaf, int64_t now);

/* Verify a server-list blob; on success *payload points into blob. Validity
 * periods are not checked (an expired list stays usable, D15). */
int npf_serverlist_verify(const uint8_t (*roots)[32], int nroots, const uint8_t *blob, size_t len,
                          const uint8_t **payload, size_t *payload_len);

/* Hosted-trust grant (security.md 8.2, 8.4):
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
    const uint8_t *targets;         /* into the parsed buffer */
    size_t   tlen;
} npf_grant;

int npf_grant_verify(const uint8_t *b, size_t len, const uint8_t issuer_pub[32], npf_grant *g);
/* hosted grants: is host:port in the target list? */
int npf_grant_target_allowed(const npf_grant *g, const char *host, uint16_t port);

/* the message a node signs to accept an owner (security.md 8.2); returns its length (60) */
size_t npf_bind_proof_msg(uint8_t out[64], uint64_t number, uint32_t key_gen, uint64_t account,
                          const uint8_t op[16], const uint8_t challenge[16], int64_t expires);

#endif

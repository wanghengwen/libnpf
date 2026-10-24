#include <string.h>

#include "monocypher.h"
#include "npf/cert.h"
#include "npf/crypto.h"

#define CERT_FIXED 32
#define CERT_TAIL  128
static const char cert_domain[] = "npf-cert-v1";
static const char list_domain[] = "npf-serverlist-v1";

uint32_t npf_key_id(const uint8_t sign_pub[32])
{
    uint8_t h[32];
    crypto_blake2b(h, 32, sign_pub, 32);
    return npf_rd32(h);
}

int npf_cert_parse(const uint8_t *b, size_t len, npf_cert *c)
{
    size_t el, n, p;
    const uint8_t *e, *end;
    if (len < CERT_FIXED + CERT_TAIL || b[0] != 1)
        return -1;
    el = npf_rd16(b + 30);
    n = CERT_FIXED + el + CERT_TAIL;
    if (n > len || n > NPF_CERT_MAX)
        return -1;
    memset(c, 0, sizeof *c);
    c->type = b[1];
    c->issuer_key = npf_rd32(b + 2);
    c->serial = npf_rd64(b + 6);
    c->subject = npf_rd64(b + 14);
    c->not_before = npf_rd32(b + 22);
    c->not_after = npf_rd32(b + 26);
    e = b + CERT_FIXED;
    end = e + el;
    while (e < end) {
        unsigned t, l;
        if (end - e < 2 || (size_t)(end - e - 2) < e[1])
            return -1;
        t = e[0];
        l = e[1];
        if (t == 1 && l == 4) c->key_gen = npf_rd32(e + 2);
        else if (t == 2 && l == 4) c->vendor = npf_rd32(e + 2);
        else if (t == 3 && l == 4) c->product = npf_rd32(e + 2);
        else if (t == 4 && l == 8) c->account = npf_rd64(e + 2);
        else if (t == 5 && l == 2) c->perms = npf_rd16(e + 2);
        else if (t == 6 && l == 1) c->hosted = e[2] != 0;
        else if (t <= 6) return -1;     /* known type, wrong length */
        e += 2 + l;
    }
    p = CERT_FIXED + el;
    memcpy(c->sign_pub, b + p, 32);
    memcpy(c->dh_pub, b + p + 32, 32);
    memcpy(c->sig, b + p + 64, 64);
    c->raw = b;
    c->raw_len = n;
    return (int)n;
}

int npf_cert_check_sig(const npf_cert *c, const uint8_t issuer_pub[32])
{
    if (npf_key_id(issuer_pub) != c->issuer_key)
        return -1;
    return npf_verify2(c->sig, issuer_pub, cert_domain, sizeof cert_domain - 1, c->raw, c->raw_len - 64);
}

static int valid_at(const npf_cert *c, int64_t now)
{
    return now == 0 || (now >= c->not_before && now <= c->not_after);
}

int npf_cert_chain_verify(const uint8_t (*roots)[32], int nroots, const npf_cert *inter,
                          unsigned perm, const npf_cert *leaf, int64_t now)
{
    int i, ok = 0;
    for (i = 0; i < nroots && !ok; i++)
        ok = npf_cert_check_sig(inter, roots[i]) == 0;
    if (!ok || inter->type != NPF_CERT_INTERMEDIATE || !(inter->perms & perm) || !valid_at(inter, now))
        return -1;
    if (leaf) {
        if (npf_cert_check_sig(leaf, inter->sign_pub) || !valid_at(leaf, now))
            return -1;
        if (leaf->type < 16 && !(inter->perms & (1u << leaf->type)))
            return -1;
    }
    return 0;
}

int npf_cert_chain_parse(const uint8_t (*roots)[32], int nroots, const uint8_t *buf, size_t len,
                         npf_cert *inter, npf_cert *leaf, int64_t now)
{
    int n1, n2;
    n1 = npf_cert_parse(buf, len, inter);
    if (n1 < 0)
        return -1;
    n2 = npf_cert_parse(buf + n1, len - (size_t)n1, leaf);
    if (n2 < 0 || (size_t)(n1 + n2) != len || leaf->type >= 16)   /* a permission bit, below */
        return -1;
    return npf_cert_chain_verify(roots, nroots, inter, 1u << leaf->type, leaf, now);
}

int npf_serverlist_verify(const uint8_t (*roots)[32], int nroots, const uint8_t *blob, size_t len,
                          const uint8_t **payload, size_t *payload_len)
{
    npf_cert inter;
    size_t il, pl, p;
    if (len < 8 + 64 || blob[0] != 1)
        return -1;
    il = npf_rd16(blob + 2);
    if (4 + il + 4 > len)
        return -1;
    if (npf_cert_parse(blob + 4, il, &inter) != (int)il)
        return -1;
    if (npf_cert_chain_verify(roots, nroots, &inter, NPF_PERM_SERVERLIST, NULL, 0))
        return -1;
    pl = npf_rd32(blob + 4 + il);
    p = 8 + il;
    if (pl > len || p + pl + 64 != len)
        return -1;
    if (npf_verify2(blob + p + pl, inter.sign_pub, list_domain, sizeof list_domain - 1, blob + p, pl))
        return -1;
    *payload = blob + p;
    *payload_len = pl;
    return 0;
}

int npf_grant_verify(const uint8_t *b, size_t len, const uint8_t issuer_pub[32], npf_grant *g)
{
    size_t p = 2, tl, q;
    const char *dom;
    if (len < 2 + 8 + 32 + 8 + 8 + 2 + 4 + 64 || b[0] != 1)
        return -1;
    memset(g, 0, sizeof *g);
    g->kind = b[1];
    g->number = npf_rd64(b + p);
    p += 8;
    memcpy(g->caller_dh, b + p, 32);
    p += 32;
    g->account = npf_rd64(b + p);
    p += 8;
    g->issued = npf_rd32(b + p);
    g->expires = npf_rd32(b + p + 4);
    p += 8;
    tl = npf_rd16(b + p);
    p += 2;
    if (p + tl + 4 + 64 != len)
        return -1;
    g->targets = b + p;
    g->tlen = tl;
    for (q = 0; q < tl;) {                      /* well-formed target list */
        size_t hl = b[p + q];
        if (q + 1 + hl + 2 > tl)
            return -1;
        q += 1 + hl + 2;
    }
    p += tl;
    if (npf_rd32(b + p) != npf_key_id(issuer_pub))
        return -1;
    p += 4;
    dom = g->kind == NPF_GRANT_HOSTED ? "npf-grant-hosted-v1" : "npf-grant-v1";
    return npf_verify2(b + p, issuer_pub, dom, strlen(dom), b, p);
}

int npf_grant_target_allowed(const npf_grant *g, const char *host, uint16_t port)
{
    size_t q, hl = strlen(host);
    for (q = 0; q < g->tlen;) {
        size_t l = g->targets[q];
        if (l == hl && memcmp(g->targets + q + 1, host, hl) == 0 && npf_rd16(g->targets + q + 1 + l) == port)
            return 1;
        q += 1 + l + 2;
    }
    return 0;
}

size_t npf_bind_proof_msg(uint8_t out[64], uint64_t number, uint32_t key_gen, uint64_t account,
                          const uint8_t op[16], const uint8_t challenge[16], int64_t expires)
{
    npf_le64(out, number);
    npf_le32(out + 8, key_gen);
    npf_le64(out + 12, account);
    memcpy(out + 20, op, 16);
    memcpy(out + 36, challenge, 16);
    npf_le64(out + 52, (uint64_t)expires);
    return 60;
}

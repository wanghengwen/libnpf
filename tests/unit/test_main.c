#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/siv.h"
#include "npf/candidates.h"
#include "npf/natprobe.h"
#include "npf/portmap.h"
#include "npf/version.h"

static int failures;
int test_crypto(void);
int test_json(void);
int test_tunnel(void);
int test_policy(void);
int test_conf(void);
int test_local(void);
int test_direct(void);
int test_loop(void);
int test_log(void);
int test_resolve(void);
int test_dns(void);
int test_punch(void);
int test_media(void);
int test_anlsec(void);
int test_sys(void);
int test_text(void);

#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static void hex2bin(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* the same known answers as AnLiu test.c (the construction must stay identical) */
static void test_kat(void)
{
    uint8_t key[32], nonce[12], out[64], exp[64], k[16], msg[16], tag[16];
    size_t i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    hex2bin("000000090000004a00000000", nonce, 12);
    npf_chacha20_block(key, 1, nonce, out);
    hex2bin("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", exp, 64);
    CHECK(memcmp(out, exp, 64) == 0, "chacha20 block vector");

    for (i = 0; i < 16; i++) { k[i] = (uint8_t)i; msg[i] = (uint8_t)i; }
    npf_siphash128(k, msg, 0, tag);
    hex2bin("a3817f04ba25a8e66df67214c7550293", exp, 16);
    CHECK(memcmp(tag, exp, 16) == 0, "siphash128 len 0");
    npf_siphash128(k, msg, 1, tag);
    hex2bin("da87c1d86b99af44347659119b22fc45", exp, 16);
    CHECK(memcmp(tag, exp, 16) == 0, "siphash128 len 1");
}

/* fixed vector shared with the platform's Go implementation (the probe server) */
static void test_probe_vector(void)
{
    npf_siv_keys keys;
    uint8_t key[32], buf[64], plain[64], exp[16];
    size_t i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x40 + i);
    npf_siv_derive(&keys, key, NPF_SIV_LABEL_PROBE);
    for (i = 0; i < 40; i++) buf[NPF_SIV_TAG_SIZE + i] = (uint8_t)i;
    npf_siv_seal(&keys, NPF_DIR_REQ, buf, 40);
    hex2bin("ee8061d3211c7bbc89ec8aa9", exp, 12);
    CHECK(memcmp(buf, exp, 12) == 0, "probe vector tag (must match natprobe_test.go)");
    {   /* the allocation from mapped ports: a busy sequential NAT (other
         * traffic takes ports in between: seen in natlab's s2b-busy), the
         * range wrapping, and a block of 512 ports in random order */
        static const struct { uint16_t p[6]; int n, alloc, delta; } cases[] = {
            {{21878, 21880, 21884, 21887}, 4, NPF_ALLOC_SEQUENTIAL, 2},
            {{27847, 27848, 27851, 27853}, 4, NPF_ALLOC_SEQUENTIAL, 1},
            {{24278, 24280, 24282, 24284, 24307}, 5, NPF_ALLOC_SEQUENTIAL, 2},
            {{29997, 29998, 20000, 20001, 20002, 20003}, 6, NPF_ALLOC_SEQUENTIAL, 1},
            {{20311, 20044, 20490, 20120}, 4, NPF_ALLOC_BLOCK, 0},
            {{20100, 20130, 20090, 20200, 20150}, 5, NPF_ALLOC_BLOCK, 0},
        };
        size_t c;
        int k;
        for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            npf_natprobe_result r;
            memset(&r, 0, sizeof r);
            r.alloc_n = cases[c].n;
            for (k = 0; k < cases[c].n; k++) {
                r.alloc_got[k] = 1;
                r.alloc_local[k] = (uint16_t)(40000 + k);
                r.alloc_mapped[k] = cases[c].p[k];
            }
            npf_natprobe_classify_alloc(&r);
            CHECK(r.profile.allocation == cases[c].alloc
                      && (cases[c].alloc != NPF_ALLOC_SEQUENTIAL || r.profile.seq_delta == cases[c].delta),
                  "allocation case %zu: %d (delta %d), want %d (%d)", c, r.profile.allocation, r.profile.seq_delta,
                  cases[c].alloc, cases[c].delta);
        }
    }
    CHECK(npf_siv_open(&keys, NPF_DIR_REQ, buf, 52, plain) == 40, "open own direction");
    CHECK(npf_siv_open(&keys, NPF_DIR_RESP, buf, 52, plain) < 0, "reflection rejected");
}

static void test_pkt(void)
{
    npf_siv_keys keys;
    uint8_t key[32], txid[12], body[28], wire[NPF_PKT_MAX], plain[NPF_PKT_MAX];
    npf_pkt pkt;
    int i, n;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);
    for (i = 0; i < 12; i++) txid[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < 28; i++) body[i] = (uint8_t)(i + 1);
    npf_siv_derive(&keys, key, NPF_SIV_LABEL_PROBE);
    for (i = 0; i < 200; i++) {
        size_t len = npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
        CHECK(len >= NPF_BIND_REQ_MIN && len <= NPF_BIND_REQ_MAX, "length range %zu", len);
        n = npf_pkt_seal(&keys, NPF_DIR_REQ, NPF_PKT_BIND_REQ, txid, 0x12345678u, body, sizeof(body), len, wire);
        CHECK(n == (int)len, "seal length");
        CHECK(npf_pkt_open(&keys, NPF_DIR_REQ, wire, len, plain, &pkt) == 0, "open");
        CHECK(pkt.type == NPF_PKT_BIND_REQ && pkt.ts_ms == 0x12345678u && pkt.body_len == 28
              && memcmp(pkt.body, body, 28) == 0 && memcmp(pkt.txid, txid, 12) == 0, "fields");
        wire[len - 1] ^= 1;
        CHECK(npf_pkt_open(&keys, NPF_DIR_REQ, wire, len, plain, &pkt) < 0, "tamper rejected");
    }
    CHECK(npf_pkt_seal(&keys, NPF_DIR_REQ, NPF_PKT_BIND_REQ, txid, 0, body, 28, 40, wire) < 0, "too short");
}

static void test_portmap(void)
{
    /* PCP MAP request: fixed nonce + client, check the header and opcode-data layout (RFC 6887). */
    uint8_t out[60], nonce[12];
    struct in_addr cli;
    npf_portmap r;
    int i;
    for (i = 0; i < 12; i++) nonce[i] = (uint8_t)(0xA0 + i);
    inet_pton(AF_INET, "192.168.1.50", &cli);
    npf_pcp_build_map(out, nonce, &cli, 24000, 24000, 3600);
    CHECK(out[0] == 2 && out[1] == 1, "pcp version/opcode");
    CHECK(out[4] == 0 && out[5] == 0 && out[6] == 0x0e && out[7] == 0x10, "pcp lifetime 3600");
    CHECK(out[16] == 0 && out[18] == 0xff && out[19] == 0xff, "pcp client v4-mapped prefix");
    CHECK(memcmp(out + 20, &cli.s_addr, 4) == 0, "pcp client addr");
    CHECK(memcmp(out + 24, nonce, 12) == 0 && out[36] == 17, "pcp nonce/proto");
    CHECK(out[40] == (24000 >> 8) && out[41] == (24000 & 0xff), "pcp internal port");

    /* craft a PCP success response and parse it */
    {
        uint8_t resp[60];
        memset(resp, 0, sizeof(resp));
        resp[0] = 2; resp[1] = 0x81; resp[3] = 0;           /* version, R+opcode, SUCCESS */
        resp[4] = 0; resp[5] = 0; resp[6] = 0x0e; resp[7] = 0x10;
        memcpy(resp + 24, nonce, 12);
        resp[36] = 17;
        resp[40] = 24000 >> 8; resp[41] = 24000 & 0xff;
        resp[42] = 0xd4; resp[43] = 0x31;                   /* external 54321 */
        resp[54] = 0xff; resp[55] = 0xff;                   /* v4-mapped */
        inet_pton(AF_INET, "203.0.113.9", resp + 56);
        CHECK(npf_pcp_parse_map(resp, 60, nonce, &r) == 0, "pcp parse ok");
        CHECK(r.external_port == 54321 && r.ext_family == 4, "pcp external port/family");
        resp[3] = 2;                                        /* NOT_AUTHORIZED */
        CHECK(npf_pcp_parse_map(resp, 60, nonce, &r) < 0, "pcp error rejected");
    }

    /* NAT-PMP MAP request + response */
    {
        uint8_t req[12], resp[16];
        npf_natpmp_build_map(req, 24000, 24000, 3600);
        CHECK(req[0] == 0 && req[1] == 1, "natpmp version/opcode");
        CHECK(req[2] == 0 && req[3] == 0, "natpmp reserved");
        memset(resp, 0, sizeof(resp));
        resp[0] = 0; resp[1] = 129; resp[2] = 0; resp[3] = 0;
        resp[8] = 24000 >> 8; resp[9] = 24000 & 0xff;
        resp[10] = 0xd4; resp[11] = 0x31;
        resp[12] = 0; resp[13] = 0; resp[14] = 0x0e; resp[15] = 0x10;
        CHECK(npf_natpmp_parse_map(resp, 16, &r) == 0, "natpmp parse ok");
        CHECK(r.external_port == 54321 && r.lifetime == 3600, "natpmp external/lifetime");
        resp[2] = 0; resp[3] = 2;                           /* result != 0 */
        CHECK(npf_natpmp_parse_map(resp, 16, &r) < 0, "natpmp error rejected");
    }
}

int main(void)
{
    {
        unsigned a, b, c;
        char end;
        /* the project() version: MAJOR.MINOR.PATCH, nothing after it */
        CHECK(sscanf(npf_version(), "%u.%u.%u%c", &a, &b, &c, &end) == 3, "version %s", npf_version());
    }
    test_kat();
    test_probe_vector();
    test_pkt();
    test_portmap();
    failures += test_crypto();
    failures += test_json();
    failures += test_tunnel();
    failures += test_policy();
    failures += test_conf();
    failures += test_local();
    failures += test_direct();
    failures += test_loop();
    failures += test_log();
    failures += test_resolve();
    failures += test_dns();
    failures += test_media();
    failures += test_anlsec();
    failures += test_sys();
    failures += test_text();
    failures += test_punch();
    { struct in6_addr v6[8]; struct in_addr v4[8];
      int c6 = npf_gather_host6(v6, 8), c4 = npf_gather_host4(v4, 8);
      CHECK(c6 >= 0 && c6 <= 8, "gather host6 count %d", c6);
      CHECK(c4 >= 0 && c4 <= 8, "gather host4 count %d", c4); }
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}

/* npf_unit_tests [NAME...]: every unit test linked into one program (the
 * named ones only), each one's time; and this file's own: the version,
 * known answers, the probe packets, the port allocation, the wake delays. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "monocypher.h"
#include "npf/bind.h"
#include "npf/siv.h"
#include "npf/candidates.h"
#include "npf/natprobe.h"
#include "npf/portmap.h"
#include "npf/version.h"
#include "test.h"

int test_crypto(void), test_json(void), test_msg(void), test_tunnel(void), test_tunnel_tick(void), test_policy(void), test_conf(void),
    test_local(void), test_direct(void), test_loop(void), test_log(void), test_resolve(void), test_dns(void),
    test_punch(void), test_anlsec(void), test_sys(void), test_text(void), test_why(void), test_creply(void),
    test_portmap_gw(void), test_callee(void), test_relay(void), test_relay_data(void), test_peeraddr(void),
    test_home(void), test_call(void), test_call_state(void), test_path(void), test_path_health(void),
    test_path_decide(void), test_peers(void), test_sigudp(void), test_sigconn(void), test_udpfwd(void);
int node_wake_delay(int ms);        /* node_signal.c */

/* the same known answers as AnLiu test.c (the construction must stay identical) */
static void test_kat(void)
{
    uint8_t key[32], nonce[12], out[64], exp[64], k[16], msg[16], tag[16];
    size_t i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    hex2bin("000000090000004a00000000", nonce, 12);
    crypto_chacha20_ietf(out, NULL, 64, key, nonce, 1);   /* what siv.c uses */
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
    {   /* a datagram longer than any packet is refused before it is decrypted
         * into the caller's NPF_PKT_MAX bytes (it overflowed the stack: no key
         * needed, the NAT probe's input; ASan) */
        static uint8_t big[2048];
        uint8_t plain[NPF_PKT_MAX], key[32] = {1};
        npf_siv_keys k;
        npf_pkt pkt;
        npf_siv_derive(&k, key, "NPF-TEST-v01");
        CHECK(npf_pkt_open(&k, NPF_DIR_RESP, big, sizeof big, plain, &pkt) < 0, "an oversized packet is refused");
    }
    CHECK(npf_siv_open(&keys, NPF_DIR_REQ, buf, 52, plain) == 40, "open own direction");
    CHECK(npf_siv_open(&keys, NPF_DIR_RESP, buf, 52, plain) < 0, "reflection rejected");
}

/* r classified from n alloc samples p and the main socket's M1, M2 (m: 0 none) */
static void classify(npf_natprobe_result *r, const uint16_t *p, int n, const uint16_t *m)
{
    int k;
    memset(r, 0, sizeof *r);
    r->alloc_n = n;
    for (k = 0; k < n; k++) {
        r->alloc_got[k] = 1;
        r->alloc_local[k] = (uint16_t)(40000 + k);
        r->alloc_mapped[k] = p[k];
    }
    for (k = 0; k < 2 && m; k++)
        if (m[k]) {
            r->got[k] = 1;
            r->mapped[k].sin_family = AF_INET;
            r->mapped[k].sin_addr.s_addr = htonl(0xc6336401);
            r->mapped[k].sin_port = htons(m[k]);
        }
    npf_natprobe_classify_alloc(r);
}

/* the allocation from mapped ports: a busy sequential NAT (other traffic
 * takes ports in between: seen in natlab's s2b-busy), the range wrapping,
 * and a block of 512 ports in random order; in doubt (sequential but for one
 * sample: RN-16's node e right after its restart, a mapping left from its
 * last process), not with three samples, and an older port first is still
 * sequential */
static void test_alloc(void)
{
    static const struct { uint16_t p[6]; int n, alloc, delta, doubt; } cases[] = {
        {{21878, 21880, 21884, 21887}, 4, NPF_ALLOC_SEQUENTIAL, 2, 0},
        {{27847, 27848, 27851, 27853}, 4, NPF_ALLOC_SEQUENTIAL, 1, 0},
        {{24278, 24280, 24282, 24284, 24307}, 5, NPF_ALLOC_SEQUENTIAL, 2, 0},
        {{29997, 29998, 20000, 20001, 20002, 20003}, 6, NPF_ALLOC_SEQUENTIAL, 1, 0},
        {{20311, 20044, 20490, 20120}, 4, NPF_ALLOC_BLOCK, 0, 0},
        {{20100, 20130, 20090, 20200, 20150}, 5, NPF_ALLOC_BLOCK, 0, 0},
        {{53868, 53863, 53869, 53870}, 4, NPF_ALLOC_BLOCK, 0, 1},
        {{53868, 53869, 53870, 53863}, 4, NPF_ALLOC_BLOCK, 0, 1},
        {{40100, 40101, 40102, 40104, 33000}, 5, NPF_ALLOC_RANDOM, 0, 1},
        {{53868, 53863, 53869}, 3, NPF_ALLOC_BLOCK, 0, 0},
        {{53863, 53868, 53869, 53870}, 4, NPF_ALLOC_SEQUENTIAL, 1, 0},
    };
    /* M1 and M2 samples of the range too: four random ports within 1526,
     * the main socket's far off (natlab eif-sym; EIM: M1 = M2); a block
     * with them, one wrapping past 65535 */
    static const struct { uint16_t p[4], m[2]; int alloc; uint16_t lo, hi; } ranges[] = {
        {{3108, 2509, 1638, 1582}, {0, 0}, NPF_ALLOC_BLOCK, 1582, 3108},
        {{3108, 2509, 1638, 1582}, {11786, 20507}, NPF_ALLOC_RANDOM, 0, 0},
        {{3108, 2509, 1638, 1582}, {36826, 36826}, NPF_ALLOC_RANDOM, 0, 0},
        {{20311, 20044, 20490, 20120}, {20503, 20012}, NPF_ALLOC_BLOCK, 20012, 20503},
        {{65400, 1100, 65300, 1200}, {1300, 1300}, NPF_ALLOC_BLOCK, 65300, 1300},
    };
    size_t c;
    npf_natprobe_result r;
    for (c = 0; c < sizeof ranges / sizeof ranges[0]; c++) {
        classify(&r, ranges[c].p, 4, ranges[c].m);
        CHECK(r.profile.allocation == ranges[c].alloc
                  && (ranges[c].alloc != NPF_ALLOC_BLOCK
                      || (r.profile.block_lo == ranges[c].lo && r.profile.block_hi == ranges[c].hi)),
              "allocation range case %zu: %d [%u %u], want %d [%u %u]", c, r.profile.allocation,
              r.profile.block_lo, r.profile.block_hi, ranges[c].alloc, ranges[c].lo, ranges[c].hi);
    }
    for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        classify(&r, cases[c].p, cases[c].n, NULL);
        CHECK(r.profile.allocation == cases[c].alloc && r.alloc_doubt == cases[c].doubt
                  && (cases[c].alloc != NPF_ALLOC_SEQUENTIAL || r.profile.seq_delta == cases[c].delta),
              "allocation case %zu: %d (delta %d, doubt %d), want %d (%d, %d)", c, r.profile.allocation,
              r.profile.seq_delta, r.alloc_doubt, cases[c].alloc, cases[c].delta, cases[c].doubt);
    }
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

#ifdef NPF_PORTMAP
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
#endif

/* the platform's wake on demand: sig_wake_ms +-20 %, drawn each time
 * (instances asleep together drift apart) */
static void test_wake(void)
{
    int i, d, lo = 1 << 30, hi = 0, same = 1, first = node_wake_delay(600000);
    for (i = 0; i < 2000; i++) {
        d = node_wake_delay(600000);
        lo = d < lo ? d : lo;
        hi = d > hi ? d : hi;
        same &= d == first;
    }
    CHECK(lo >= 480000 && hi <= 720000 && lo < 490000 && hi > 710000 && !same, "wake delays %d .. %d", lo, hi);
    CHECK(node_wake_delay(1) == 1 && node_wake_delay(5) >= 4 && node_wake_delay(5) <= 6, "short wake delays");
}

static int test_own(void)
{
    unsigned a, b, c;
    char end;
    struct in6_addr v6[8];
    struct in_addr v4[8];
    int c6 = npf_gather_host(AF_INET6, v6, 8), c4 = npf_gather_host(AF_INET, v4, 8);
    /* the project() version: MAJOR.MINOR.PATCH, nothing after it */
    CHECK(sscanf(npf_version(), "%u.%u.%u%c", &a, &b, &c, &end) == 3, "version %s", npf_version());
    CHECK(c6 >= 0 && c6 <= 8 && c4 >= 0 && c4 <= 8, "gathered host addresses: %d, %d", c6, c4);
    test_kat();
    test_probe_vector();
    test_alloc();
    test_pkt();
#ifdef NPF_PORTMAP
    test_portmap();
#endif
    test_wake();
    return fails;
}

static const struct {
    const char *name;
    int (*fn)(void);
} tests[] = {
    {"main", test_own}, {"crypto", test_crypto}, {"json", test_json}, {"msg", test_msg}, {"tunnel", test_tunnel}, {"tunnel_tick", test_tunnel_tick},
    {"policy", test_policy}, {"conf", test_conf}, {"local", test_local}, {"direct", test_direct}, {"loop", test_loop},
    {"log", test_log}, {"resolve", test_resolve}, {"dns", test_dns}, {"anlsec", test_anlsec}, {"sys", test_sys},
    {"text", test_text}, {"why", test_why}, {"creply", test_creply},
#ifdef NPF_PORTMAP
    {"portmap", test_portmap_gw},
#endif
    {"callee", test_callee}, {"relay", test_relay}, {"relay_data", test_relay_data}, {"peeraddr", test_peeraddr},
    {"home", test_home}, {"call", test_call}, {"call_state", test_call_state}, {"path", test_path},
    {"path_health", test_path_health}, {"path_decide", test_path_decide}, {"peers", test_peers}, {"sigudp", test_sigudp},
    {"sigconn", test_sigconn}, {"punch", test_punch},
    {"udpfwd", test_udpfwd},
};

int main(int argc, char **argv)
{
    size_t i;
    int k, total = 0, run;
    for (i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int64_t t0 = npf_mono_ms();
        int n;
        for (k = 1, run = argc == 1; k < argc; k++)
            run |= strcmp(argv[k], tests[i].name) == 0;
        if (!run)
            continue;
        n = tests[i].fn();
        total += n;
        printf("%-12s %s %5lld ms\n", tests[i].name, n ? "FAIL" : "ok  ", (long long)(npf_mono_ms() - t0));
    }
    if (total)
        fprintf(stderr, "%d failure(s)\n", total);
    return total != 0;
}

/* The UDP relay client's RELAY_BIND_ACKs (data-channel.md 9.2, 9.3): only
 * an answer to one of its last binds counts (its txid, ts_ms and kseq echoed), and
 * each once; a challenge to its RELAY_DATA (no txid) only when newer than the
 * last one taken and of about now. A replayed or foreign BIND_ACK makes the
 * client send nothing (it would burn the allocation's bind tokens) and
 * binds nothing. A fake relay on loopback: the
 * client's binds read from its socket, the answers fed to call_relay_input.
 * First the binder's order of addresses (relay_bind.h): binding from the
 * first address, the data along; probing from the address in use, the
 * data staying on it until another answers (architecture.md Q2). */
#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "call_internal.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

typedef struct bind_seen {
    uint8_t txid[NPF_TXID_SIZE];
    uint32_t ts;
    uint64_t kseq;
    uint8_t cookie[RELAY_COOKIE_SIZE];
} bind_seen;

static int udp_on_loopback(struct sockaddr_storage *ss)
{
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    socklen_t l = sizeof *a;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(ss, 0, sizeof *ss);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)a, sizeof *a) < 0 || getsockname(fd, (struct sockaddr *)a, &l) < 0)
        return -1;
    return fd;
}

/* the next RELAY_BIND the client sent within ms: 1, 0 none */
static int next_bind(int fd, const npf_siv_keys *keys, int ms, bind_seen *b)
{
    uint8_t wire[2048], plain[NPF_PKT_MAX];
    struct pollfd p = {fd, POLLIN, 0};
    npf_pkt pk;
    ssize_t n;
    while (poll(&p, 1, ms) > 0) {
        n = recv(fd, wire, sizeof wire, 0);
        if (n <= RELAY_HINT_SIZE || npf_pkt_open(keys, 0, wire + RELAY_HINT_SIZE, (size_t)n - RELAY_HINT_SIZE, plain, &pk) < 0
            || pk.type != PKT_RELAY_BIND || pk.body_len < RELAY_BIND_BODY)
            continue;
        memcpy(b->txid, pk.txid, NPF_TXID_SIZE);
        b->ts = pk.ts_ms;
        memcpy(b->cookie, pk.body, RELAY_COOKIE_SIZE);
        b->kseq = npf_rd64(pk.body + 8);
        return 1;
    }
    return 0;
}

/* a RELAY_BIND_ACK as the relay sends it: body = family | port | addr |
 * srv_time_ms | state | cookie | kseq | flags | t_s | learn */
static int ack(npf_call *c, const npf_siv_keys *keys, const struct sockaddr_storage *relay, const uint8_t *txid,
               uint32_t ts, uint64_t kseq, int64_t srv_ms, int state, const uint8_t cookie[RELAY_COOKIE_SIZE])
{
    uint8_t body[3 + 4 + 8 + 1 + RELAY_COOKIE_SIZE + 8 + 1 + 3] = {4, 0x12, 0x34, 127, 0, 0, 1}, out[128];
    int n;
    npf_le64(body + 7, (uint64_t)srv_ms);
    body[15] = (uint8_t)state;
    memcpy(body + 16, cookie, RELAY_COOKIE_SIZE);
    npf_le64(body + 24, kseq);
    n = npf_pkt_seal(keys, 1, PKT_RELAY_BIND_ACK, txid, ts, body, sizeof body, 80, out);
    return n > 0 ? call_relay_input(c, out, (size_t)n, relay) : -1;
}

/* the binder (relay_bind.h): the run from the first address, 4 binds to
 * each, the data along; the probe from the address in use, then the others
 * in order, the data staying until another answers */
static void bind_order(void)
{
    relay_c r;
    int seq[16], cur[16], n = 0, k;
    static const int run3[] = {0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2};
    static const int probe3[] = {1, 1, 1, 1, 0, 0, 0, 0, 2, 2, 2, 2};
    memset(&r, 0, sizeof r);
    r.naddr = 3;
    r.cur = r.bi = 2;
    relay_bind_begin(&r, 0);
    do {
        seq[n] = r.bi;
        cur[n] = r.cur;
    } while (++n < 16 && relay_bind_step(&r) == 0);
    CHECK(n == 12, "a run of %d binds", n);
    for (k = 0; k < 12 && k < n; k++)
        CHECK(seq[k] == run3[k] && cur[k] == run3[k], "run: bind %d to %d (data to %d)", k, seq[k], cur[k]);

    r.cur = r.bi = 1;
    relay_bind_begin(&r, 1);
    n = 0;
    do {
        seq[n] = r.bi;
        cur[n] = r.cur;
    } while (++n < 16 && relay_bind_step(&r) == 0);
    CHECK(n == 12, "a probe of %d binds", n);
    for (k = 0; k < 12 && k < n; k++)
        CHECK(seq[k] == probe3[k] && cur[k] == 1, "probe: bind %d to %d (data to %d)", k, seq[k], cur[k]);

    /* the first address answers a probe from the second: the one in use, the binds there */
    r.active = 1;
    r.bound = 0;
    r.cur = r.bi = 1;
    relay_bind_begin(&r, 1);
    for (k = 0; k < 5; k++)
        relay_bind_step(&r);
    CHECK(r.bi == 0 && r.cur == 1, "probing the first address (%d, %d)", r.bi, r.cur);
    CHECK(relay_addr_take(&r, 0) == 1 && r.cur == 0 && r.bi == 0, "the answer of the first");
    /* the one in use answers late, the binds at the next: back to it */
    r.cur = r.bi = 1;
    relay_bind_begin(&r, 1);
    for (k = 0; k < 9; k++)
        relay_bind_step(&r);
    CHECK(r.bi == 2 && relay_addr_take(&r, 1) == 1 && r.cur == 1 && r.bi == 1, "a late answer of the one in use");
    /* bound: only the address in use */
    r.bound = 1;
    CHECK(relay_addr_take(&r, 0) == 0 && relay_addr_take(&r, 1) == 1, "bound: another address taken");

    /* one address: its 4 binds */
    memset(&r, 0, sizeof r);
    r.naddr = 1;
    relay_bind_begin(&r, 1);
    for (n = 1; n < 16 && relay_bind_step(&r) == 0; n++)
        CHECK(r.bi == 0 && r.cur == 0, "one address: bind to %d", r.bi);
    CHECK(n == 4, "one address: %d binds", n);
}

int test_relay(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    npf_siv_keys keys;
    struct sockaddr_storage relay, me;
    uint8_t seed[32], rid[8], akey[32], foreign[NPF_TXID_SIZE], zero[NPF_TXID_SIZE] = {0};
    uint8_t ck1[RELAY_COOKIE_SIZE] = {1, 1, 1, 1, 1, 1, 1, 1}, ck2[RELAY_COOKIE_SIZE] = {2, 2, 2, 2, 2, 2, 2, 2},
            ck3[RELAY_COOKIE_SIZE] = {3, 3, 3, 3, 3, 3, 3, 3};
    char js[512], rb[16], kb[48], ra[64];
    npf_jtok tok[32];
    npf_json j;
    bind_seen b1, b2, b3;
    npf_call *c;
    int fr, fc, len;

    bind_order();
    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    fr = udp_on_loopback(&relay);
    fc = udp_on_loopback(&me);
    CHECK(loop && fr >= 0 && fc >= 0 && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return fails;
    node.udp_fd = fc;                   /* the node's main socket: the test's */
    c = call_new(&node, 1);
    CHECK(c != NULL, "call");
    if (!c)
        return fails;
    snprintf(c->call_id_s, sizeof c->call_id_s, "relay-test");
    npf_random(rid, 8);
    npf_random(akey, 32);
    npf_random(foreign, sizeof foreign);
    npf_siv_derive(&keys, akey, LABEL_RELAY);
    npf_b64url_encode(rid, 8, rb);
    npf_b64url_encode(akey, 32, kb);
    len = snprintf(js, sizeof js, "{\"relay\":{\"mode\":\"udp\",\"relay_id\":\"%s\",\"alloc_key\":\"%s\",\"udp\":[\"%s\"]}}",
                   rb, kb, npf_addr_str(&relay, ra, sizeof ra));
    CHECK(npf_json_parse(&j, js, (size_t)len, tok, 32) >= 0, "relay JSON");
    call_relay_setup(c, &j, 0);
    CHECK(call_has_relay(c) && !c->pu.r.bound, "the relay taken");

    /* the first bind; a challenge to a txid it never sent, and ones with its
     * txid but another ts_ms or kseq: nothing sent */
    CHECK(next_bind(fr, &keys, 500, &b1) == 1, "the first RELAY_BIND");
    ack(c, &keys, &relay, foreign, b1.ts, b1.kseq, npf_node_time(&node), 0, ck1);
    ack(c, &keys, &relay, b1.txid, b1.ts - 5000, b1.kseq, npf_node_time(&node), 0, ck1);
    ack(c, &keys, &relay, b1.txid, b1.ts, b1.kseq + 1, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 100, &b2) == 0, "a foreign challenge answered");
    /* its own: echoed at once with the cookie */
    ack(c, &keys, &relay, b1.txid, b1.ts, b1.kseq, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 300, &b2) == 1 && memcmp(b2.cookie, ck1, sizeof ck1) == 0, "the challenge echoed");
    /* the same challenge again (a replay, past the 200 ms between echoes): nothing */
    usleep(250 * 1000);
    ack(c, &keys, &relay, b1.txid, b1.ts, b1.kseq, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 100, &b3) == 0, "a replayed challenge answered");
    /* "bound" for a txid it did not send, or for none: not bound */
    ack(c, &keys, &relay, foreign, b2.ts, b2.kseq, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    ack(c, &keys, &relay, zero, b2.ts, 0, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    CHECK(!c->pu.r.bound, "bound by a foreign BIND_ACK");
    /* the answer to the echo binds */
    ack(c, &keys, &relay, b2.txid, b2.ts, b2.kseq, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    CHECK(c->pu.r.bound, "not bound by its own BIND_ACK");

    /* a challenge to its RELAY_DATA (no txid: the NAT gave a new port):
     * answered when newer than the last one and of about now, once */
    usleep(250 * 1000);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), 0, npf_node_time(&node), 0, ck2);
    CHECK(next_bind(fr, &keys, 300, &b3) == 1 && memcmp(b3.cookie, ck2, sizeof ck2) == 0, "a data challenge echoed");
    usleep(250 * 1000);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), 0, npf_node_time(&node) - 1000, 0, ck3);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), 0, npf_node_time(&node) - 120000, 0, ck3);
    ack(c, &keys, &relay, b1.txid, b1.ts, b1.kseq, npf_node_time(&node), 0, ck3);
    CHECK(next_bind(fr, &keys, 100, &b3) == 0, "an old data challenge answered");
    /* the cookie of what was refused was not taken */
    CHECK(memcmp(c->pu.r.cookie, ck2, sizeof ck2) == 0, "cookie of a refused BIND_ACK taken");

    call_free(c);
    node.udp_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    close(fr);
    close(fc);
    return fails;
}

/* ---- RELAY_DATA (data-channel.md 9.2) ---- */

#include "vectors_go.h"

static size_t unhex2(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    unsigned v;
    while (hex[0] && hex[1] && n < cap && sscanf(hex, "%2x", &v) == 1) {
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

/* the Go relay's vectors (npfcrypto vectors_test.go): the keys of an
 * alloc_key, a datagram each way, the hint unmasked; and SipHash-2-4-64's
 * reference vector */
static void rdata_vectors(void)
{
    static const char *pkts[2] = {V_RDATA_PKT0, V_RDATA_PKT1};
    static const char *ktag[2] = {V_RDATA_KTAG0, V_RDATA_KTAG1}, *kmask[2] = {V_RDATA_KMASK0, V_RDATA_KMASK1};
    static const uint32_t seqs[2] = {V_RDATA_SEQ0, V_RDATA_SEQ1};
    static const int lens[2] = {40, RDATA_ATAG};
    uint8_t key[32], rid[8], want[128], w[128], k16[16], m[15], hint[3];
    rdata_keys k;
    uint32_t seq;
    int i, dir;
    size_t n;
    for (i = 0; i < 16; i++) k16[i] = (uint8_t)i;
    for (i = 0; i < 15; i++) m[i] = (uint8_t)i;
    CHECK(npf_siphash64(k16, m, 15) == 0xa129ca6149be45e5ULL, "SipHash-2-4-64 reference vector");
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x20 + i);
    unhex2(V_RDATA_RELAY_ID, rid, 8);
    rdata_derive(&k, key);
    for (dir = 0; dir < 2; dir++) {
        CHECK(unhex2(ktag[dir], want, 16) == 16 && memcmp(k.tag[dir], want, 16) == 0, "k_tag[%d]", dir);
        CHECK(unhex2(kmask[dir], want, 16) == 16 && memcmp(k.mask[dir], want, 16) == 0, "k_mask[%d]", dir);
        n = unhex2(pkts[dir], want, sizeof want);
        CHECK(n == (size_t)(RDATA_HDR + lens[dir]), "vector %d length", dir);
        for (i = 0; i < lens[dir]; i++)
            w[RDATA_HDR + i] = (uint8_t)(0x30 + i + dir);
        rdata_seal(&k, dir, rid, seqs[dir], w, (size_t)lens[dir]);
        CHECK(memcmp(w, want, n) == 0, "RELAY_DATA dir %d differs from the Go relay's", dir);
        CHECK(rdata_hint(want, n, hint) == 0 && memcmp(hint, rid, 3) == 0, "hint of dir %d", dir);
        CHECK(rdata_open(&k, dir, hint, want, n, &seq) == 0 && seq == seqs[dir], "open dir %d", dir);
        CHECK(rdata_open(&k, 1 - dir, hint, want, n, &seq) < 0, "opened with the other direction's keys");
        CHECK(rdata_open(&k, dir, hint, want, n - 1, &seq) < 0, "a cut datagram opened");
        want[RDATA_HDR + 2] ^= 1;
        CHECK(rdata_open(&k, dir, hint, want, n, &seq) < 0, "a changed AnLiu tag opened");
    }
    CHECK(rdata_hint(want, RDATA_HDR + RDATA_ATAG - 1, hint) < 0, "a too short RELAY_DATA");
}

/* a RELAY_DATA from the relay (seq, a 40-byte datagram) */
static size_t rdata_from(const rdata_keys *k, const uint8_t rid[8], uint32_t seq, uint8_t *w)
{
    memset(w + RDATA_HDR, 0x5a, 40);
    rdata_seal(k, NPF_DIR_RESP, rid, seq, w, 40);
    return RDATA_HDR + 40;
}

/* a call with the relay object of a UDP allocation at addr */
static npf_call *relay_call(npf_node *n, npf_json *j, npf_jtok *tok, const uint8_t rid[8], const uint8_t key[32],
                            const struct sockaddr_storage *addr)
{
    static char js[2][512];
    static int k;
    char rb[16], kb[48], ra[64];
    char *s = js[k++ & 1];
    npf_call *c = call_new(n, 1);
    int len;
    if (!c)
        return NULL;
    snprintf(c->call_id_s, sizeof c->call_id_s, "rdata-%d", k);
    npf_b64url_encode(rid, 8, rb);
    npf_b64url_encode(key, 32, kb);
    len = snprintf(s, 512, "{\"relay\":{\"mode\":\"udp\",\"relay_id\":\"%s\",\"alloc_key\":\"%s\",\"udp\":[\"%s\"]}}",
                   rb, kb, npf_addr_str(addr, ra, sizeof ra));
    if (npf_json_parse(j, s, (size_t)len, tok, 32) < 0)
        return NULL;
    call_relay_setup(c, j, 0);
    return c;
}

/* the node's demux: a RELAY_DATA finds its call by the hint (two calls on
 * two relays with the same 3-byte hint: the source and the tag decide),
 * nothing else takes it; one in the SIV encapsulation of before 2026-10-28
 * is not taken. What goes out has 16 bytes before the datagram. */
int test_relay_data(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    struct sockaddr_storage r1, r2, me;
    uint8_t seed[32], rid1[8], rid2[8], key1[32], key2[32], w[2048], got[2048], dgram[40], hint[3];
    npf_jtok tok[2][32];
    npf_json j[2];
    rdata_keys k1, k2;
    npf_siv_keys siv1;
    npf_call *c1, *c2;
    int f1, f2, fc;
    ssize_t n;
    uint32_t seq;
    size_t len;

    fails = 0;
    rdata_vectors();
    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    f1 = udp_on_loopback(&r1);
    f2 = udp_on_loopback(&r2);
    fc = udp_on_loopback(&me);
    CHECK(loop && f1 >= 0 && f2 >= 0 && fc >= 0 && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return fails;
    node.udp_fd = fc;
    npf_random(rid1, 8);
    memcpy(rid2, rid1, 3);              /* the same 3-byte hint on another relay */
    rid2[3] = (uint8_t)~rid1[3];
    npf_random(key1, 32);
    npf_random(key2, 32);
    rdata_derive(&k1, key1);
    rdata_derive(&k2, key2);
    npf_siv_derive(&siv1, key1, LABEL_RELAY);
    c1 = relay_call(&node, &j[0], tok[0], rid1, key1, &r1);
    c2 = relay_call(&node, &j[1], tok[1], rid2, key2, &r2);
    CHECK(c1 && c2, "the calls");
    if (fails)
        return fails;

    /* to the relay: 16 bytes more than the datagram */
    memset(dgram, 0x11, sizeof dgram);
    while (recv(f1, got, sizeof got, MSG_DONTWAIT) > 0)        /* the binds */
        ;
    call_relay_send_data(c1, dgram, sizeof dgram);
    call_relay_send_data(c1, dgram, sizeof dgram);
    n = recv(f1, got, sizeof got, 0);
    CHECK(n == RDATA_HDR + (ssize_t)sizeof dgram && rdata_hint(got, (size_t)n, hint) == 0 && memcmp(hint, rid1, 3) == 0
          && rdata_open(&k1, NPF_DIR_REQ, hint, got, (size_t)n, &seq) == 0 && seq == 0
          && memcmp(got + RDATA_HDR, dgram, sizeof dgram) == 0, "a RELAY_DATA to the relay");
    n = recv(f1, got, sizeof got, 0);
    CHECK(n > 0 && rdata_open(&k1, NPF_DIR_REQ, hint, got, (size_t)n, &seq) == 0 && seq == 1, "the next seq");
    call_relay_send_data(c1, dgram, RDATA_ATAG - 1);           /* no AnLiu datagram is this short */
    CHECK(recv(f1, got, sizeof got, MSG_DONTWAIT) < 0, "a datagram shorter than its tag sent");

    /* from the relays: by the hint, the source and the tag (the caller has
     * no keys yet: the datagram is kept for them, relay_early_keep) */
    len = rdata_from(&k2, rid2, 5, w);
    CHECK(node_udp_input(&node, fc, w, len, &r2) == 1 && c2->nrearly == 1 && c1->nrearly == 0, "to the second call");
    len = rdata_from(&k1, rid1, 5, w);
    CHECK(node_udp_input(&node, fc, w, len, &r1) == 1 && c1->nrearly == 1 && c2->nrearly == 1, "to the first call");
    CHECK(node_udp_input(&node, fc, w, len, &r2) == 0 && c1->nrearly == 1 && c2->nrearly == 1,
          "a RELAY_DATA from the other relay's address taken");
    w[RDATA_HDR + 20] ^= 1;    /* past the AnLiu tag: the node's AnLiu decides (here: kept for it) */
    CHECK(node_relay_data_input(&node, w, len, &r1) == 1 && c1->nrearly == 2, "a same-length change");
    w[RDATA_HDR + 1] ^= 1;     /* the AnLiu tag */
    CHECK(node_relay_data_input(&node, w, len, &r1) == 0 && c1->nrearly == 2, "a changed AnLiu tag taken");
    len = rdata_from(&k1, rid1, 6, w);
    CHECK(node_relay_data_input(&node, w, len + 1, &r1) == 0 && node_relay_data_input(&node, w, len - 1, &r1) == 0
          && c1->nrearly == 2, "a longer or shorter datagram taken");
    w[11] ^= 0x10;              /* tf */
    CHECK(node_relay_data_input(&node, w, len, &r1) == 0, "another type taken");

    /* the SIV encapsulation of before 2026-10-28, with the allocation's key: not taken */
    {
        uint8_t *p = w + NPF_SIV_TAG_SIZE;
        p[0] = PKT_RELAY_DATA;
        p[1] = 0;
        npf_le32(p + 2, 1);
        memset(p + 6, 0x77, 40);
        npf_siv_seal(&siv1, NPF_DIR_RESP, w, 46);
        node_udp_input(&node, fc, w, NPF_SIV_TAG_SIZE + 46, &r1);
        CHECK(c1->nrearly == 2, "a RELAY_DATA in the old format taken");
    }

    call_free(c1);
    call_free(c2);
    node.udp_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    close(f1);
    close(f2);
    close(fc);
    return fails;
}

/* The persistent binding (home-binding.md v0.4): the packets against the
 * platform's vectors (home_test.go), and the node against a fake relay on
 * loopback: only answers to its own HOME_BINDs count, the challenge echoed;
 * a ping answered at once (PONG with its id, "sent elsewhere" when the main
 * socket did), a replayed or stale ping not; R's change counted; the
 * watchdog binds again only when nothing came from the relay by the last
 * datagram + T + the relay's tries + a margin. */
#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/natprobe.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "home.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static void hex2bin(const char *h, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* must equal TestHomeVectors in server/internal/relay/home_test.go */
#define V_HOME_BIND "4ecd3cb9a7f2182efa5da1a961a609635708e224030b89b9e9af45e2cb6112e9611208af70baef33b15861b2dcf606e327b87822b0"
#define V_HOME_ACK  "7d1e0181d511d021bfbb917e7974a7c125c06558415514e63a51dc704e5dec29608efaa0d601a198f31b55993079a29075f897d74be8" \
                    "0f8af296414ccd6787c9d52cc52e"
#define V_HOME_PING "5d4a5e46e25cf61dd5b515282e68e507204e7d65c6b682e801de55c6f8b3d23f1a1cbc59e76bea68a119544bbb260b62381f67438277be"

static void test_vectors(void)
{
    uint8_t key[32], txid[12], ck[8], body[HOME_BIND_BODY], out[64], exp[80], plain[NPF_PKT_MAX];
    npf_siv_keys keys;
    npf_pkt pk;
    home_ack a;
    home_ping p;
    int i, n;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x60 + i);
    for (i = 0; i < 12; i++) txid[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < 8; i++) ck[i] = (uint8_t)(0x10 + i);
    npf_siv_derive(&keys, key, LABEL_HOME);
    home_bind_body(body, ck, 0x0102030405060708ULL, HOME_F_PONG | HOME_F_OTHER, 0xdeadbeefu);
    n = npf_pkt_seal(&keys, NPF_DIR_REQ, PKT_HOME_BIND, txid, 0x11223344u, body, sizeof body,
                     NPF_SIV_TAG_SIZE + NPF_PKT_HDR_SIZE + sizeof body, out);
    hex2bin(V_HOME_BIND, exp, (size_t)n);
    CHECK(n == 53 && memcmp(out, exp, (size_t)n) == 0, "HOME_BIND vector (must match home_test.go)");
    hex2bin(V_HOME_ACK, exp, 68);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 68, plain, &pk) == 0 && pk.type == PKT_HOME_ACK
          && home_ack_parse(pk.body, pk.body_len, &a) == 0, "HOME_ACK vector opens");
    CHECK(a.addr.sin_addr.s_addr == inet_addr("198.51.100.7") && ntohs(a.addr.sin_port) == 40312
          && a.srv_ms == 1793000000123LL && a.state == 1 && memcmp(a.cookie, ck, 8) == 0
          && a.kseq == 0x0102030405060708ULL && a.flags == HOME_A_MOVED && a.t_s == 45 && a.learn == HOME_LEARNING,
          "HOME_ACK fields");
    hex2bin(V_HOME_PING, exp, 55);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 55, plain, &pk) == 0 && pk.type == PKT_HOME_PING
          && home_ping_parse(pk.body, pk.body_len, &p) == 0 && p.srv_ms == 1793000045123LL && p.ping_id == 0xdeadbeefu
          && p.t_s == 45 && p.learn == HOME_LEARNED && p.try_n == 2 && ntohs(p.addr.sin_port) == 40312, "HOME_PING vector");
    CHECK(npf_pkt_open(&keys, NPF_DIR_REQ, exp, 55, plain, &pk) < 0, "a reflected HOME_PING opens");
}

/* ---- the node against a fake relay ---- */

static int udp_lo(struct sockaddr_in *a)
{
    socklen_t l = sizeof *a;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)a, sizeof *a) < 0 || getsockname(fd, (struct sockaddr *)a, &l) < 0)
        return -1;
    return fd;
}

typedef struct seen {
    uint8_t  txid[NPF_TXID_SIZE];
    uint32_t ts;
    uint8_t  cookie[8];
    uint64_t kseq;
    int      flags, len;
    uint32_t ping_id;
} seen;

/* the next HOME_BIND the node sent within ms: 1, 0 none */
static int next_bind(int fd, const npf_siv_keys *keys, const uint8_t id[8], int ms, seen *b)
{
    uint8_t wire[2048], plain[NPF_PKT_MAX];
    struct pollfd p = {fd, POLLIN, 0};
    npf_pkt pk;
    ssize_t n;
    while (poll(&p, 1, ms) > 0) {
        n = recv(fd, wire, sizeof wire, 0);
        if (n <= 4 || memcmp(wire, id, 4) != 0 || npf_pkt_open(keys, 0, wire + 4, (size_t)n - 4, plain, &pk) < 0
            || pk.type != PKT_HOME_BIND || pk.body_len < HOME_BIND_BODY)
            continue;
        memcpy(b->txid, pk.txid, NPF_TXID_SIZE);
        b->ts = pk.ts_ms;
        memcpy(b->cookie, pk.body, 8);
        b->kseq = npf_rd64(pk.body + 8);
        b->flags = pk.body[16];
        b->ping_id = npf_rd32(pk.body + 17);
        b->len = (int)n;
        return 1;
    }
    return 0;
}

static void feed(npf_node *n, const struct sockaddr_in *relay, const uint8_t *out, int r)
{
    struct sockaddr_storage from;
    memset(&from, 0, sizeof from);
    memcpy(&from, relay, sizeof *relay);
    if (r > 0)
        node_home_input(n, n->udp_fd, out, (size_t)r, &from);
}

static void put_addr(uint8_t *b, const struct sockaddr_in *a)
{
    b[0] = 4;
    b[1] = (uint8_t)ntohs(a->sin_port);
    b[2] = (uint8_t)(ntohs(a->sin_port) >> 8);
    memcpy(b + 3, &a->sin_addr, 4);
}

static void answer(npf_node *n, const npf_siv_keys *keys, const struct sockaddr_in *relay, const struct sockaddr_in *R,
                   const uint8_t *txid, uint32_t ts, uint64_t kseq, int state, const uint8_t ck[8], int t_s)
{
    uint8_t body[7 + 8 + 1 + 8 + 8 + 1 + 3], out[128];
    put_addr(body, R);
    npf_le64(body + 7, (uint64_t)npf_node_time(n));
    body[15] = (uint8_t)state;
    memcpy(body + 16, ck, 8);
    npf_le64(body + 24, kseq);
    body[32] = 0;
    body[33] = (uint8_t)t_s;
    body[34] = (uint8_t)(t_s >> 8);
    body[35] = HOME_LEARNING;
    feed(n, relay, out, npf_pkt_seal(keys, NPF_DIR_RESP, PKT_HOME_ACK, txid, ts, body, sizeof body, 80, out));
}

static void ping(npf_node *n, const npf_siv_keys *keys, const struct sockaddr_in *relay, const struct sockaddr_in *R,
                 int64_t srv_ms, uint32_t id, int t_s, int learn)
{
    uint8_t body[7 + 8 + 4 + 2 + 1 + 1], out[64], txid[NPF_TXID_SIZE] = {9};
    put_addr(body, R);
    npf_le64(body + 7, (uint64_t)srv_ms);
    npf_le32(body + 15, id);
    body[19] = (uint8_t)t_s;
    body[20] = (uint8_t)(t_s >> 8);
    body[21] = (uint8_t)learn;
    body[22] = 1;
    feed(n, relay, out, npf_pkt_seal(keys, NPF_DIR_RESP, PKT_HOME_PING, txid, (uint32_t)srv_ms, body, sizeof body,
                                     55, out));
}

static void test_client(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    npf_siv_keys keys;
    struct sockaddr_in relay, me, other, R2;
    uint8_t seed[32], bid[8], key[32], foreign[NPF_TXID_SIZE], ck[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    char js[1024];
    seen b1, b2, b3;
    int fr, fc, fo;
    int64_t t0;

    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    fr = udp_lo(&relay);
    fc = udp_lo(&me);
    fo = udp_lo(&other);
    CHECK(loop && fr >= 0 && fc >= 0 && fo >= 0 && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return;
    node.udp_fd = fc;
    npf_random(bid, 8);
    npf_random(key, 32);
    npf_random(foreign, sizeof foreign);
    npf_siv_derive(&keys, key, LABEL_HOME);
    CHECK(node_home_test_take(&node, bid, key, &relay) == 0, "the binding taken");
    /* the first HOME_BIND: its cookie zero, kseq 1, padded to 96 at least */
    CHECK(next_bind(fr, &keys, bid, 500, &b1) == 1 && b1.kseq == 1 && b1.cookie[0] == 0 && !b1.flags && b1.len >= 96,
          "the first HOME_BIND");
    /* answers to what it did not send: nothing */
    answer(&node, &keys, &relay, &me, foreign, b1.ts, b1.kseq, 0, ck, 25);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq + 5, 0, ck, 25);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts - 1, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "a foreign challenge answered");
    /* its own challenge: echoed with the cookie, the next kseq; a replay of it not */
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && memcmp(b2.cookie, ck, 8) == 0 && b2.kseq == 2, "the challenge echoed");
    usleep(250 * 1000);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 100, &b3) == 0 && node_home_state(&node) != 3, "a replayed challenge answered");
    answer(&node, &keys, &relay, &me, b2.txid, b2.ts, b2.kseq, 1, ck, 25);
    CHECK(node_home_state(&node) == 3, "not bound by its own HOME_ACK");

    /* a ping: answered at once, a PONG naming it, shorter than a HOME_BIND */
    t0 = npf_node_time(&node);
    ping(&node, &keys, &relay, &me, t0, 0x1234, 25, HOME_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b1) == 1 && b1.flags == HOME_F_PONG && b1.ping_id == 0x1234 && b1.len < 96
          && b1.kseq == 3, "the PONG: flags %d id %x len %d", b1.flags, b1.ping_id, b1.len);
    /* the same ping again, an older one, one far from now: not answered */
    ping(&node, &keys, &relay, &me, t0, 0x1234, 25, HOME_LEARNING);
    ping(&node, &keys, &relay, &me, t0 - 10, 0x1235, 25, HOME_LEARNING);
    ping(&node, &keys, &relay, &me, t0 + 120000, 0x1236, 25, HOME_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "a replayed or stale ping answered");
    /* the main socket sends elsewhere: the next PONG says so; then not again */
    (void)npf_udp_send(fc, "x", 1, &other);
    ping(&node, &keys, &relay, &me, t0 + 1000, 0x2000, 45, HOME_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && b2.flags == (HOME_F_PONG | HOME_F_OTHER) && b2.ping_id == 0x2000,
          "a PONG after a send elsewhere: flags %d", b2.flags);
    ping(&node, &keys, &relay, &me, t0 + 2000, 0x2001, 45, HOME_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && b2.flags == HOME_F_PONG, "the next PONG: flags %d", b2.flags);
    /* R moved (a new port): counted; the status */
    R2 = me;
    R2.sin_port = htons((uint16_t)(ntohs(me.sin_port) + 1));
    ping(&node, &keys, &relay, &R2, t0 + 3000, 0x2002, 36, HOME_LEARNED);
    next_bind(fr, &keys, bid, 300, &b2);
    {
        size_t l = npf_node_home_json(&node, js, sizeof js);
        CHECK(l > 0 && strstr(js, "\"state\":\"bound\"") && strstr(js, "\"iv_s\":36") && strstr(js, "\"learn\":\"learned\"")
              && strstr(js, "\"moved\":1") && strstr(js, "\"keepalives\":4") && strstr(js, "\"drops\":0"), "status %s", js);
    }
    /* the watchdog: not before the last datagram + T + the tries + a margin; then it binds again */
    CHECK(node_home_test_dog(&node, npf_mono_ms() + 36000 + HOME_RETRY_MS) == 0 && node_home_state(&node) == 3,
          "the watchdog before its deadline");
    CHECK(node_home_test_dog(&node, npf_mono_ms() + 36000 + HOME_RETRY_MS + 6000) == 1 && node_home_state(&node) == 4,
          "the watchdog after its deadline");
    CHECK(next_bind(fr, &keys, bid, 300, &b3) == 1 && !(b3.flags & HOME_F_PONG), "the HOME_BIND of the watchdog");
    node_home_stop(&node);
    node.udp_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    close(fr);
    close(fc);
    close(fo);
}

int test_home(void)
{
    test_vectors();
    test_client();
    return fails;
}

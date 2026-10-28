/* The spare allocation (home-binding.md v0.5): the packets against the
 * platform's vectors (spare_test.go), and the node against a fake relay on
 * loopback: only answers to its own RELAY_BINDs count (txid, ts_ms, kseq),
 * the challenge echoed;
 * a ping answered at once (PONG with its id, "sent elsewhere" when the main
 * socket did), a replayed or stale ping not; R's change counted; the
 * watchdog binds again only when nothing came from the relay by the last
 * datagram + T + the relay's tries + a margin; a call takes the spare with
 * its binding (kseq goes on), relay_spare brings the next one; a spare
 * backing off keeps its timer through a login (home_open resume) and a
 * refused home_open. */
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
#include "npf/json.h"
#include "npf/crypto.h"
#include "npf/natprobe.h"
#include "npf/node.h"
#include "npf/platform.h"
/* home.c and relay_bind.c themselves: their static parts (the binding taken
 * without signaling, the watchdog at a given time, the packet bodies) with
 * no test entry points in the library */
#include "../../src/node/relay_bind.c"
#include "../../src/node/home.c"

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

/* must equal TestBindVectors in server/internal/relay/spare_test.go */
#define V_BIND "67e11a510f117fab15ba88f2a0c7e2b2735bf0fccefd01c194277595c0f6a86c684305a3c9a34c227e2628895490980248e02c330c"
#define V_ACK  "47b0f19b8e20a81a2c397fb70ee47ebc4ea3bb4422ccd83234770f138a009933a63c394396c878c0010a13d32917ac96cd44cf2750d5" \
               "488944273edd441a541c37a722ca"
#define V_PING "a37f1b33d14f85517f57b60941b98f30d77ffa9c50194e482f2c813d2ac0f7c71e73c7c37c6088d260e54b6cbbc3fa7df177885bb8764e"

static void test_vectors(void)
{
    uint8_t key[32], txid[12], ck[8], body[RELAY_BIND_BODY], out[64], exp[80], plain[NPF_PKT_MAX];
    npf_siv_keys keys;
    npf_pkt pk;
    relay_ack a;
    relay_ping p;
    int i, n;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x60 + i);
    for (i = 0; i < 12; i++) txid[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < 8; i++) ck[i] = (uint8_t)(0x10 + i);
    npf_siv_derive(&keys, key, LABEL_RELAY);
    memcpy(body, ck, 8);
    npf_le64(body + 8, 0x0102030405060708ULL);
    body[16] = RELAY_F_PONG | RELAY_F_OTHER;
    npf_le32(body + 17, 0xdeadbeefu);
    n = npf_pkt_seal(&keys, NPF_DIR_REQ, PKT_RELAY_BIND, txid, 0x11223344u, body, sizeof body,
                     NPF_SIV_TAG_SIZE + NPF_PKT_HDR_SIZE + sizeof body, out);
    hex2bin(V_BIND, exp, (size_t)n);
    CHECK(n == 53 && memcmp(out, exp, (size_t)n) == 0, "RELAY_BIND vector (must match spare_test.go)");
    hex2bin(V_ACK, exp, 68);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 68, plain, &pk) == 0 && pk.type == PKT_RELAY_BIND_ACK
          && relay_ack_parse(pk.body, pk.body_len, &a) == 0, "RELAY_BIND_ACK vector opens");
    CHECK(((struct sockaddr_in *)&a.addr)->sin_addr.s_addr == inet_addr("198.51.100.7")
          && ntohs(((struct sockaddr_in *)&a.addr)->sin_port) == 40312
          && a.srv_ms == 1793000000123LL && a.state == 1 && memcmp(a.cookie, ck, 8) == 0
          && a.kseq == 0x0102030405060708ULL && a.t_s == 45 && a.learn == RELAY_LEARNING,
          "RELAY_BIND_ACK fields");
    hex2bin(V_PING, exp, 55);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 55, plain, &pk) == 0 && pk.type == PKT_RELAY_PING
          && relay_ping_parse(pk.body, pk.body_len, &p) == 0 && p.srv_ms == 1793000045123LL && p.ping_id == 0xdeadbeefu
          && p.t_s == 45 && p.learn == RELAY_LEARNED && ntohs(((struct sockaddr_in *)&p.addr)->sin_port) == 40312, "RELAY_PING vector");
    CHECK(npf_pkt_open(&keys, NPF_DIR_REQ, exp, 55, plain, &pk) < 0, "a reflected RELAY_PING opens");
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

/* the next RELAY_BIND the node sent within ms: 1, 0 none */
static int next_bind(int fd, const npf_siv_keys *keys, const uint8_t id[8], int ms, seen *b)
{
    uint8_t wire[2048], plain[NPF_PKT_MAX];
    struct pollfd p = {fd, POLLIN, 0};
    npf_pkt pk;
    ssize_t n;
    while (poll(&p, 1, ms) > 0) {
        n = recv(fd, wire, sizeof wire, 0);
        if (n <= 4 || memcmp(wire, id, 4) != 0 || npf_pkt_open(keys, 0, wire + 4, (size_t)n - 4, plain, &pk) < 0
            || pk.type != PKT_RELAY_BIND || pk.body_len < RELAY_BIND_BODY)
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
    body[35] = RELAY_LEARNING;
    feed(n, relay, out, npf_pkt_seal(keys, NPF_DIR_RESP, PKT_RELAY_BIND_ACK, txid, ts, body, sizeof body, 80, out));
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
    feed(n, relay, out, npf_pkt_seal(keys, NPF_DIR_RESP, PKT_RELAY_PING, txid, (uint32_t)srv_ms, body, sizeof body,
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
    npf_siv_derive(&keys, key, LABEL_RELAY);
    {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &relay, sizeof relay);
        home_take(home_new(&node), bid, key, &ss, 1);
    }
    /* the first RELAY_BIND: its cookie zero, kseq from the server time (above
     * whatever the relay took before), padded to 96 at least */
    CHECK(next_bind(fr, &keys, bid, 500, &b1) == 1 && b1.kseq > (uint64_t)(npf_node_time(&node) - 1000) << 10
          && b1.cookie[0] == 0 && !b1.flags && b1.len >= 96, "the first RELAY_BIND");
    /* answers to what it did not send: nothing */
    answer(&node, &keys, &relay, &me, foreign, b1.ts, b1.kseq, 0, ck, 25);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq + 5, 0, ck, 25);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts - 1, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "a foreign challenge answered");
    /* its own challenge: echoed with the cookie, the next kseq; a replay of it not */
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && memcmp(b2.cookie, ck, 8) == 0 && b2.kseq == b1.kseq + 1, "the challenge echoed");
    usleep(250 * 1000);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 25);
    CHECK(next_bind(fr, &keys, bid, 100, &b3) == 0 && node.home->state != 3, "a replayed challenge answered");
    answer(&node, &keys, &relay, &me, b2.txid, b2.ts, b2.kseq, 1, ck, 25);
    CHECK(node.home->state == 3, "not bound by its own BIND_ACK");

    /* a ping: answered at once, a PONG naming it, shorter than a RELAY_BIND */
    t0 = npf_node_time(&node);
    ping(&node, &keys, &relay, &me, t0, 0x1234, 25, RELAY_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b1) == 1 && b1.flags == RELAY_F_PONG && b1.ping_id == 0x1234 && b1.len < 96
          && b1.kseq == b2.kseq + 1, "the PONG: flags %d id %x len %d", b1.flags, b1.ping_id, b1.len);
    /* the same ping again, an older one, one far from now: not answered */
    ping(&node, &keys, &relay, &me, t0, 0x1234, 25, RELAY_LEARNING);
    ping(&node, &keys, &relay, &me, t0 - 10, 0x1235, 25, RELAY_LEARNING);
    ping(&node, &keys, &relay, &me, t0 + 120000, 0x1236, 25, RELAY_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "a replayed or stale ping answered");
    /* the main socket sends elsewhere: the next PONG says so; then not again */
    (void)npf_udp_send(fc, "x", 1, &other);
    ping(&node, &keys, &relay, &me, t0 + 1000, 0x2000, 45, RELAY_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && b2.flags == (RELAY_F_PONG | RELAY_F_OTHER) && b2.ping_id == 0x2000,
          "a PONG after a send elsewhere: flags %d", b2.flags);
    ping(&node, &keys, &relay, &me, t0 + 2000, 0x2001, 45, RELAY_LEARNING);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && b2.flags == RELAY_F_PONG, "the next PONG: flags %d", b2.flags);
    /* R moved (a new port): counted; the status */
    R2 = me;
    R2.sin_port = htons((uint16_t)(ntohs(me.sin_port) + 1));
    ping(&node, &keys, &relay, &R2, t0 + 3000, 0x2002, 36, RELAY_LEARNED);
    next_bind(fr, &keys, bid, 300, &b2);
    {
        size_t l = npf_node_home_status(&node, js, sizeof js);
        CHECK(l > 0 && strstr(js, "\"state\":\"bound\"") && strstr(js, "\"iv_s\":36") && strstr(js, "\"learn\":\"learned\"")
              && strstr(js, "\"moved\":1") && strstr(js, "\"keepalives\":4") && strstr(js, "\"drops\":0"), "status %s", js);
        CHECK(strstr(js, "\"relay\":\"127.0.0.1:"), "the relay it is bound via %s", js);
    }
    /* the watchdog: not before the last datagram + T + the tries + a margin; then it binds again */
    CHECK(dog_check(node.home, npf_mono_ms() + 36000 + HOME_RETRY_MS) == 0 && node.home->state == 3,
          "the watchdog before its deadline");
    CHECK(dog_check(node.home, npf_mono_ms() + 36000 + HOME_RETRY_MS + 6000) == 1 && node.home->state == 4,
          "the watchdog after its deadline");
    CHECK(next_bind(fr, &keys, bid, 300, &b3) == 1 && !(b3.flags & RELAY_F_PONG), "the RELAY_BIND of the watchdog");
    /* bound again; a call takes it: its binding moves (the kseq goes on),
     * the spare is no longer the node's until relay_spare */
    answer(&node, &keys, &relay, &me, b3.txid, b3.ts, b3.kseq, 1, ck, 36);
    CHECK(node.home->state == 3, "bound again");
    {
        relay_c rc;
        uint8_t nid[8], nkey[32];
        char rb[16], kb[48], ra[64], ev[512];
        npf_jtok tok[32];
        npf_json j;
        struct sockaddr_storage ss;
        int len;
        memset(&rc, 0, sizeof rc);
        nid[0] = (uint8_t)~bid[0];
        CHECK(!node_home_adopt(&node, nid, &rc), "another allocation adopted");
        CHECK(node_home_adopt(&node, bid, &rc) == 1 && rc.bound && rc.kseq == b3.kseq && !node.home->t_bind
              && memcmp(rc.cookie, ck, 8) == 0 && node.home->state == 6, "the spare adopted");
        CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "the spare taken still binds");
        /* relay_spare: the next one, bound from scratch */
        npf_random(nid, 8);
        npf_random(nkey, 32);
        npf_siv_derive(&keys, nkey, LABEL_RELAY);
        npf_b64url_encode(nid, 8, rb);
        npf_b64url_encode(nkey, 32, kb);
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &relay, sizeof relay);
        len = snprintf(ev, sizeof ev, "{\"relay\":{\"mode\":\"udp\",\"relay_id\":\"%s\",\"alloc_key\":\"%s\","
                       "\"udp\":[\"%s\"],\"spare\":true},\"why\":\"taken\"}", rb, kb, npf_addr_str(&ss, ra, sizeof ra));
        CHECK(npf_json_parse(&j, ev, (size_t)len, tok, 32) >= 0, "relay_spare JSON");
        node_home_spare(&node, &j, 0);
        CHECK(node.home->state == 2 && next_bind(fr, &keys, nid, 300, &b1) == 1 && b1.cookie[0] == 0,
              "the next spare binds");
        CHECK(npf_node_home_status(&node, js, sizeof js) > 0 && strstr(js, "\"taken\":1") && strstr(js, "\"iv_s\":36"),
              "status %s", js);
    }
    /* backing off when the node logs in again (home_open with resume): the
     * timer stays, also when home_open is refused with the spare kept */
    gave_up(node.home);
    CHECK(node.home->state == H_BACKOFF && node.home->t_retry, "backing off");
    node.cfg.offline = 0;               /* a spare allowed (home_allowed) */
    node.cfg.callable = 1;
    node_home_login(&node);
    CHECK(node.home && node.home->state == H_BACKOFF && node.home->t_retry, "no timer after a login while backing off");
    {
        npf_jtok tok[16];
        npf_json j;
        char m[] = "{\"v\":1,\"type\":\"reply\",\"status\":\"error\",\"error\":\"rate_limited\"}";
        CHECK(npf_json_parse(&j, m, strlen(m), tok, 16) == 0, "reply JSON");
        open_reply(&node, &j, 0, node.home);
        CHECK(node.home->r.active && node.home->t_retry, "no timer after home_open refused while backing off");
    }
    node.cfg.offline = 1;
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

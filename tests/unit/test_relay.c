/* The UDP relay client's RELAY_BIND_ACKs (data-channel.md 9.2, 9.3): only
 * an answer to one of its last binds counts (its txid and ts_ms echoed), and
 * each once; a challenge to its RELAY_DATA (no txid) only when newer than the
 * last one taken and of about now. A replayed or foreign BIND_ACK makes the
 * client send nothing (it would burn the allocation's bind tokens and roll
 * the relay's txid ring) and binds nothing. A fake relay on loopback: the
 * client's binds read from its socket, the answers fed to call_relay_input. */
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
            || pk.type != PKT_RELAY_BIND || pk.body_len < RELAY_COOKIE_SIZE)
            continue;
        memcpy(b->txid, pk.txid, NPF_TXID_SIZE);
        b->ts = pk.ts_ms;
        memcpy(b->cookie, pk.body, RELAY_COOKIE_SIZE);
        return 1;
    }
    return 0;
}

/* a RELAY_BIND_ACK as the relay sends it: body = family | port | addr |
 * srv_time_ms | state | cookie */
static int ack(npf_call *c, const npf_siv_keys *keys, const struct sockaddr_storage *relay, const uint8_t *txid,
               uint32_t ts, int64_t srv_ms, int state, const uint8_t cookie[RELAY_COOKIE_SIZE])
{
    uint8_t body[3 + 4 + 8 + 1 + RELAY_COOKIE_SIZE] = {4, 0x12, 0x34, 127, 0, 0, 1}, out[128];
    int n;
    npf_le64(body + 7, (uint64_t)srv_ms);
    body[15] = (uint8_t)state;
    memcpy(body + 16, cookie, RELAY_COOKIE_SIZE);
    n = npf_pkt_seal(keys, 1, PKT_RELAY_BIND_ACK, txid, ts, body, sizeof body, 80, out);
    return n > 0 ? call_relay_input(c, out, (size_t)n, relay) : -1;
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
    CHECK(c->relay.active && !c->relay.bound, "the relay taken");

    /* the first bind; a challenge to a txid it never sent, and one with its
     * txid but another ts_ms: nothing sent */
    CHECK(next_bind(fr, &keys, 500, &b1) == 1, "the first RELAY_BIND");
    ack(c, &keys, &relay, foreign, b1.ts, npf_node_time(&node), 0, ck1);
    ack(c, &keys, &relay, b1.txid, b1.ts - 5000, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 100, &b2) == 0, "a foreign challenge answered");
    /* its own: echoed at once with the cookie */
    ack(c, &keys, &relay, b1.txid, b1.ts, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 300, &b2) == 1 && memcmp(b2.cookie, ck1, sizeof ck1) == 0, "the challenge echoed");
    /* the same challenge again (a replay, past the 200 ms between echoes): nothing */
    usleep(250 * 1000);
    ack(c, &keys, &relay, b1.txid, b1.ts, npf_node_time(&node), 0, ck1);
    CHECK(next_bind(fr, &keys, 100, &b3) == 0, "a replayed challenge answered");
    /* "bound" for a txid it did not send, or for none: not bound */
    ack(c, &keys, &relay, foreign, b2.ts, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    ack(c, &keys, &relay, zero, b2.ts, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    CHECK(!c->relay.bound, "bound by a foreign BIND_ACK");
    /* the answer to the echo binds */
    ack(c, &keys, &relay, b2.txid, b2.ts, npf_node_time(&node), RELAY_ACK_BOUND, ck1);
    CHECK(c->relay.bound, "not bound by its own BIND_ACK");

    /* a challenge to its RELAY_DATA (no txid: the NAT gave a new port):
     * answered when newer than the last one and of about now, once */
    usleep(250 * 1000);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), npf_node_time(&node), 0, ck2);
    CHECK(next_bind(fr, &keys, 300, &b3) == 1 && memcmp(b3.cookie, ck2, sizeof ck2) == 0, "a data challenge echoed");
    usleep(250 * 1000);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), npf_node_time(&node) - 1000, 0, ck3);
    ack(c, &keys, &relay, zero, (uint32_t)npf_node_time(&node), npf_node_time(&node) - 120000, 0, ck3);
    ack(c, &keys, &relay, b1.txid, b1.ts, npf_node_time(&node), 0, ck3);
    CHECK(next_bind(fr, &keys, 100, &b3) == 0, "an old data challenge answered");
    /* the cookie of what was refused was not taken */
    CHECK(memcmp(c->relay.cookie, ck2, sizeof ck2) == 0, "cookie of a refused BIND_ACK taken");

    call_free(c);
    node.udp_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    close(fr);
    close(fc);
    return fails;
}

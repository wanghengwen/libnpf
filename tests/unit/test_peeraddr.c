/* The node's own check of the peer's addresses (security.md H-1, under the
 * platform's): a punch_start or punch_info naming loopback, multicast, the
 * broadcast, unspecified, link-local addresses or the platform's probe and
 * relay endpoints gets none of them probed, and no spray at a public IP that
 * is such an address. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

static void sin_of(struct sockaddr_storage *ss, const char *ip, int port)
{
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    memset(ss, 0, sizeof *ss);
    a->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &a->sin_addr);
    a->sin_port = htons((uint16_t)port);
}

/* punch_start round with these candidates and pub_ip: the candidates taken */
static int start(npf_call *c, int round, const char *cands, const char *pub)
{
    char js[2048], pid[16], key[48];
    uint8_t b[32];
    npf_jtok tok[160];
    npf_json j;
    int len;
    npf_random(b, 32);
    npf_b64url_encode(b, 8, pid);
    npf_b64url_encode(b, 32, key);
    len = snprintf(js, sizeof js, "{\"call_id\":\"x\",\"round\":%d,\"punch_id\":\"%s\",\"punch_key\":\"%s\",\"strategy\":\"S3\","
                   "\"side\":\"easy\",\"peer\":{\"cand\":[%s],\"pub_ip\":\"%s\"},\"m_total\":10,\"timeout_ms\":1000}",
                   round, pid, key, cands, pub);
    if (npf_json_parse(&j, js, (size_t)len, tok, 160) < 0)
        return -1;
    call_handle_punch_start(c, &j, 0);
    return c->pcfg ? c->pcfg->npeers : -1;
}

int test_peeraddr(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    uint8_t seed[32];
    char a[64];
    npf_call *c;
    struct sockaddr_storage ss;
    struct in_addr ip;
    int n, i;

    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    CHECK(loop && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return fails;
    node.udp6_fd = socket(AF_INET6, SOCK_DGRAM, 0);     /* IPv6 candidates are taken with one */
    inet_pton(AF_INET, "198.51.100.9", &node.srflx.sin_addr);   /* not the platform's host */
    node.srflx.sin_family = AF_INET;
    sin_of(&ss, "203.0.113.7", 19910);
    memcpy(&node.probe_ep[0], &ss, sizeof node.probe_ep[0]);
    node.nprobe_ep = 1;
    c = call_new(&node, 1);
    CHECK(c != NULL, "call");
    if (!c)
        return fails;
    snprintf(c->call_id_s, sizeof c->call_id_s, "peeraddr-test");
    c->keys_ready = 0;                  /* the punch waits for the keys: nothing is sent */
    sin_of(&c->relay.addr[0], "203.0.113.5", 9900);
    c->relay.naddr = 1;

    n = start(c, 1,
              "{\"t\":\"host4\",\"a\":\"127.0.0.1:5000\"},{\"t\":\"srflx\",\"a\":\"224.0.0.1:5000\"},"
              "{\"t\":\"srflx\",\"a\":\"255.255.255.255:5000\"},{\"t\":\"srflx\",\"a\":\"169.254.1.1:5000\"},"
              "{\"t\":\"srflx\",\"a\":\"0.0.0.0:5000\"},{\"t\":\"srflx\",\"a\":\"240.1.2.3:5000\"},"
              "{\"t\":\"srflx\",\"a\":\"203.0.113.7:19910\"},{\"t\":\"srflx\",\"a\":\"203.0.113.5:9900\"},"
              "{\"t\":\"host6\",\"a\":\"[fe80::1]:5000\"},{\"t\":\"host6\",\"a\":\"[ff02::1]:5000\"},"
              "{\"t\":\"host6\",\"a\":\"[::1]:5000\"},{\"t\":\"host6\",\"a\":\"[::ffff:127.0.0.1]:5000\"},"
              "{\"t\":\"host4\",\"a\":\"10.0.0.2:5000\"},{\"t\":\"srflx\",\"a\":\"198.51.100.20:4000\"}",
              "127.0.0.1");
    CHECK(n == 2, "%d candidates taken, want 2 (10.0.0.2, 198.51.100.20)", n);
    for (i = 0; c->pcfg && i < c->pcfg->npeers; i++) {
        npf_addr_str(&c->pcfg->peers[i], a, sizeof a);
        CHECK(strcmp(a, "10.0.0.2:5000") == 0 || strcmp(a, "198.51.100.20:4000") == 0, "candidate %s taken", a);
    }
    CHECK(c->pcfg && c->pcfg->plan.peer_ip4.s_addr == 0, "a loopback public IP kept for the spray");
    CHECK(start(c, 2, "{\"t\":\"srflx\",\"a\":\"198.51.100.20:4000\"}", "203.0.113.5") == 1
          && c->pcfg->plan.peer_ip4.s_addr == 0, "the relay's IP kept for the spray");
    CHECK(start(c, 3, "{\"t\":\"srflx\",\"a\":\"198.51.100.20:4000\"}", "255.255.255.255") == 1
          && c->pcfg->plan.peer_ip4.s_addr == 0, "the broadcast kept for the spray");
    inet_pton(AF_INET, "198.51.100.20", &ip);
    CHECK(start(c, 4, "{\"t\":\"srflx\",\"a\":\"198.51.100.20:4000\"}", "198.51.100.20") == 1
          && c->pcfg->plan.peer_ip4.s_addr == ip.s_addr, "a public IP not taken for the spray");
    if (node.udp6_fd >= 0)
        CHECK(start(c, 5, "{\"t\":\"host6\",\"a\":\"[2001:db8::5]:4000\"}", "198.51.100.20") == 1, "a global IPv6 dropped");

    /* punch_info's srflx: the same check */
    {
        static const char *bad[] = {"127.0.0.1:6000", "224.0.0.5:6000", "203.0.113.7:19910", "0.0.0.0:6000"};
        char js[256];
        npf_jtok tok[32];
        npf_json j;
        int len;
        for (i = 0; i < 4; i++) {
            len = snprintf(js, sizeof js, "{\"call_id\":\"x\",\"round\":5,\"cand\":{\"t\":\"srflx\",\"a\":\"%s\"}}", bad[i]);
            CHECK(npf_json_parse(&j, js, (size_t)len, tok, 32) >= 0, "JSON");
            call_handle_punch_info(c, &j, 0);
            CHECK(c->tcand.ss_family == 0, "punch_info %s taken", bad[i]);
        }
        len = snprintf(js, sizeof js, "{\"call_id\":\"x\",\"round\":5,\"cand\":{\"t\":\"srflx\",\"a\":\"198.51.100.20:6000\"}}");
        CHECK(npf_json_parse(&j, js, (size_t)len, tok, 32) >= 0, "JSON");
        call_handle_punch_info(c, &j, 0);
        CHECK(c->tcand.ss_family == AF_INET, "a public srflx not taken");
    }
    /* this node's srflx on loopback does not make loopback usable; the tests' switch does */
    inet_pton(AF_INET, "127.0.0.1", &node.srflx.sin_addr);
    CHECK(start(c, 6, "{\"t\":\"srflx\",\"a\":\"127.0.0.1:5000\"}", "127.0.0.1") == 0 && c->pcfg->plan.peer_ip4.s_addr == 0,
          "loopback usable from the srflx");
    node.cfg.test_one_host = 1;
    CHECK(start(c, 7, "{\"t\":\"srflx\",\"a\":\"127.0.0.1:5000\"}", "127.0.0.1") == 1 && c->pcfg->plan.peer_ip4.s_addr != 0,
          "loopback with test_one_host");

    /* the IPs the main socket sent to lately (sprays, direct paths): an
     * unsolicited probe from them shows nothing of the filter (7.8) */
    {
        struct in_addr x, y;
        inet_pton(AF_INET, "198.51.100.30", &x);
        inet_pton(AF_INET, "198.51.100.31", &y);
        CHECK(!call_contact_recent(&node, x), "no contact yet");
        call_contact_note(&node, x);
        CHECK(call_contact_recent(&node, x) && !call_contact_recent(&node, y), "the contact noted, only its IP");
        for (i = 0; i < 9; i++) {           /* eight kept: the oldest goes */
            struct in_addr z;
            z.s_addr = htonl(0xc6336400u + 40 + (unsigned)i);
            call_contact_note(&node, z);
        }
        CHECK(!call_contact_recent(&node, x), "the oldest of nine contacts kept");
    }
    call_free(c);
    if (node.udp6_fd >= 0)
        close(node.udp6_fd);
    node.udp6_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

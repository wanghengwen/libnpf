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
#include "test.h"

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
    len = snprintf(js, sizeof js, "{\"v\":1,\"type\":\"punch_start\",\"data\":{\"call_id\":\"%s\",\"round\":%d,"
                   "\"punch_id\":\"%s\",\"punch_key\":\"%s\",\"strategy\":\"S3\",\"side\":\"easy\","
                   "\"peer\":{\"cand\":[%s],\"pub_ip\":\"%s\"},\"m_total\":10,\"timeout_ms\":1000}}",
                   c->call_id_s, round, pid, key, cands, pub);
    if (npf_json_parse(&j, js, (size_t)len, tok, 160) < 0)
        return -1;
    node_msg(c->n, &j);
    return c->pcfg ? c->pcfg->npeers : -1;
}

int test_peeraddr(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    char a[64];
    npf_call *c;
    struct sockaddr_storage ss;
    struct in_addr ip;
    int n, i;

    CHECK(offline_node(&node, loop, NULL, NULL) == 0, "set-up");
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
    npf_random(c->call_id, 16);
    npf_b64url_encode(c->call_id, 16, c->call_id_s);
    c->keys_ready = 0;                  /* the punch waits for the keys: nothing is sent */
    sin_of(&c->pu.r.addr[0], "203.0.113.5", 9900);
    c->pu.r.naddr = 1;

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
            len = snprintf(js, sizeof js, "{\"v\":1,\"type\":\"punch_info\",\"data\":{\"call_id\":\"%s\",\"round\":5,"
                           "\"cand\":{\"t\":\"srflx\",\"a\":\"%s\"}}}", c->call_id_s, bad[i]);
            CHECK(npf_json_parse(&j, js, (size_t)len, tok, 32) >= 0, "JSON");
            node_msg(&node, &j);
            CHECK(c->tcand.ss_family == 0, "punch_info %s taken", bad[i]);
        }
        len = snprintf(js, sizeof js, "{\"v\":1,\"type\":\"punch_info\",\"data\":{\"call_id\":\"%s\",\"round\":5,"
                       "\"cand\":{\"t\":\"srflx\",\"a\":\"198.51.100.20:6000\"}}}", c->call_id_s);
        CHECK(npf_json_parse(&j, js, (size_t)len, tok, 32) >= 0, "JSON");
        node_msg(&node, &j);
        CHECK(c->tcand.ss_family == AF_INET, "a public srflx not taken");
    }
    /* this node's srflx on loopback does not make loopback usable; the tests' switch does */
    inet_pton(AF_INET, "127.0.0.1", &node.srflx.sin_addr);
    CHECK(start(c, 6, "{\"t\":\"srflx\",\"a\":\"127.0.0.1:5000\"}", "127.0.0.1") == 0 && c->pcfg->plan.peer_ip4.s_addr == 0,
          "loopback usable from the srflx");
    node.cfg.test_one_host = 1;
    CHECK(start(c, 7, "{\"t\":\"srflx\",\"a\":\"127.0.0.1:5000\"}", "127.0.0.1") == 1 && c->pcfg->plan.peer_ip4.s_addr != 0,
          "loopback with test_one_host");

    call_free(c);
    if (node.udp6_fd >= 0)
        close(node.udp6_fd);
    node.udp6_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}

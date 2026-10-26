/* The persistent binding (home-binding.md): the packets against the
 * platform's vectors (home_test.go), the learner as a pure function (5.3,
 * 5.4, 5.5, 5.7: the steps, the bisection, downward, a doubtful failure
 * measured again, the EIM tracks, the corrections), what the main socket
 * did during a step, the network's key, home.json, and the client against
 * a fake relay on loopback (only answers to its own HOME_BINDs count, the
 * challenge echoed, the echo of its step). */
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
#include "npf/conf.h"
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
#define V_HOME_BIND "661eb7195a7846ad827a675f4b0fc22c7306056470beda789711e0b293060ad48d977c572e27508e4d07a657f624ea38c7b96b859a"
#define V_HOME_ACK  "530dd4632f4fe0fb748f11b4208b8ffa054bff06e5e88e497803534f8ae91b0e3f8bab44fe8bf10a380240ffd5592f7b1331fd" \
                    "fc2db7d70dd7c55a5af5a80abc54"
#define V_HOME_PING "981b55f7c67b99c3193b813688128bc3bee54d5e7e44b2c40561dba26e0b9c89f5141416f35cca9ff47033"

static void test_vectors(void)
{
    uint8_t key[32], txid[12], ck[8], body[HOME_BIND_BODY], out[64], exp[80], plain[NPF_PKT_MAX];
    npf_siv_keys keys;
    npf_pkt pk;
    home_ack a;
    int i, n, probe, nn;
    int64_t ms;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x60 + i);
    for (i = 0; i < 12; i++) txid[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < 8; i++) ck[i] = (uint8_t)(0x10 + i);
    npf_siv_derive(&keys, key, LABEL_HOME);
    home_bind_body(body, ck, 0x0102030405060708ULL, 96, 45, HOME_F_INBOUND);
    n = npf_pkt_seal(&keys, NPF_DIR_REQ, PKT_HOME_BIND, txid, 0x11223344u, body, sizeof body,
                     NPF_SIV_TAG_SIZE + NPF_PKT_HDR_SIZE + sizeof body, out);
    hex2bin(V_HOME_BIND, exp, (size_t)n);
    CHECK(n == 53 && memcmp(out, exp, (size_t)n) == 0, "HOME_BIND vector (must match home_test.go)");
    hex2bin(V_HOME_ACK, exp, 65);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 65, plain, &pk) == 0 && pk.type == PKT_HOME_ACK
          && home_ack_parse(pk.body, pk.body_len, &a) == 0, "HOME_ACK vector opens");
    CHECK(a.addr.sin_addr.s_addr == inet_addr("198.51.100.7") && ntohs(a.addr.sin_port) == 40312
          && a.srv_ms == 1793000000123LL && a.state == 1 && memcmp(a.cookie, ck, 8) == 0
          && a.kseq == 0x0102030405060708ULL && a.flags == (HOME_A_PROBE_SET | HOME_A_MOVED), "HOME_ACK fields");
    hex2bin(V_HOME_PING, exp, 43);
    CHECK(npf_pkt_open(&keys, NPF_DIR_RESP, exp, 43, plain, &pk) == 0 && pk.type == PKT_HOME_PING
          && memcmp(pk.txid, txid, 12) == 0 && home_ping_parse(pk.body, pk.body_len, &ms, &probe, &nn) == 0
          && ms == 1793000045123LL && probe == 45 && nn == 2, "HOME_PING vector");
    CHECK(npf_pkt_open(&keys, NPF_DIR_REQ, exp, 43, plain, &pk) < 0, "a reflected HOME_PING opens");
}

/* the learner, driven: each step's outcome by the mapping's lifetime */
typedef struct nat_model {
    int life;           /* s the mapping lives idle */
    int preserve;       /* an expired one comes back on the same port */
    int busy_keeps;     /* other traffic keeps it (a true EIM; not a per-flow NAT) */
} nat_model;

static int outcome(const nat_model *m, const hl_step *st, int busy, int *noecho_seen)
{
    if (st->T < m->life || (busy && m->busy_keeps))
        return HL_OK;
    if (!m->preserve)
        return HL_EXPIRED;
    (*noecho_seen)++;
    return HL_NOECHO;
}

/* run the learning of track t to its end: the waits tried, in order */
static int learn(hl_state *L, const nat_model *m, int track, int64_t *now, int *tried, int max)
{
    hl_step st;
    int n = 0, noecho = 0;
    while (n < max && hl_next(L, track, *now, *now * 1000, &st)) {
        tried[n++] = st.inbound ? -st.T : st.T;
        *now += st.T + 3;
        hl_done(L, &st, outcome(m, &st, track == HL_BUSY, &noecho), track, *now, *now * 1000);
    }
    return n;
}

static int seq_eq(const int *a, int n, const int *b, int m)
{
    return n == m && memcmp(a, b, (size_t)n * sizeof *a) == 0;
}

static void test_learner(void)
{
    hl_state L;
    hl_step st;
    int tried[32], n;
    int64_t now = 1793000000;

    /* random ports, 50 s: 25, 45 live, 75 expires, 60 once (bisected), then 0.8 x 45 */
    {
        nat_model m = {50, 0, 0};
        static const int want[] = {25, 45, 75, 60, -60};
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        CHECK(hl_iv(&L, HL_QUIET) == 25, "the interval before learning: %d", hl_iv(&L, HL_QUIET));
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(seq_eq(tried, n, want, 5), "random 50 s: %d steps (%d %d %d %d)", n, tried[0], tried[1], tried[2], tried[3]);
        CHECK(hl_iv(&L, HL_QUIET) == 36 && L.tr[HL_QUIET].phase == HL_LEARNED && L.tr[HL_QUIET].t_ok == 45
              && L.tr[HL_QUIET].t_fail == 60 && L.preserve == 0, "random 50 s: iv %d", hl_iv(&L, HL_QUIET));
        CHECK(L.refresh == HL_REFRESH_OUT, "the inbound test with the ping at 30 s, lifetime 50: out (%d)", L.refresh);
        CHECK(hl_iv(&L, HL_BUSY) == 36, "busy not learned: the quiet interval (%d)", hl_iv(&L, HL_BUSY));
    }
    /* the port kept, 50 s: every failure measured twice (no new address tells) */
    {
        nat_model m = {50, 1, 0};
        static const int want[] = {25, 45, 75, 75, 60, 60, -60};
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(seq_eq(tried, n, want, 7), "preserve 50 s: %d steps", n);
        CHECK(hl_iv(&L, HL_QUIET) == 36 && L.preserve == 1, "preserve 50 s: iv %d preserve %d", hl_iv(&L, HL_QUIET),
              L.preserve);
    }
    /* the port kept, 300 s: up to 180, 144 (the cap 150 above it); no expiry: refresh unknown */
    {
        nat_model m = {300, 1, 0};
        static const int want[] = {25, 45, 75, 120, 180};
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(seq_eq(tried, n, want, 5) && hl_iv(&L, HL_QUIET) == 144 && L.refresh == HL_REFRESH_UNKNOWN,
              "300 s: %d steps, iv %d", n, hl_iv(&L, HL_QUIET));
        hl_init(&L, NPF_MAP_EIM, 60, 0);    /* home_iv_max */
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(hl_iv(&L, HL_QUIET) == 60, "home_iv_max 60: iv %d", hl_iv(&L, HL_QUIET));
    }
    /* downward: 20 s (25 fails, 15 lives: 12), 9 s (none lives: 8, unstable) */
    {
        nat_model m = {20, 0, 0};
        static const int want[] = {25, 15, -25};
        hl_init(&L, NPF_MAP_APDM, 150, 0);
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(seq_eq(tried, n, want, 3) && hl_iv(&L, HL_QUIET) == 12, "20 s: %d steps, iv %d", n, hl_iv(&L, HL_QUIET));
        m.life = 9;
        hl_init(&L, NPF_MAP_APDM, 150, 0);
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(n == 3 && tried[2] == 10 && hl_iv(&L, HL_QUIET) == 8 && L.tr[HL_QUIET].unstable,
              "9 s: %d steps, iv %d", n, hl_iv(&L, HL_QUIET));
    }
    /* EIM busy: other traffic keeps a true EIM mapping (the busy track to
     * 180), the quiet track learns on its own once quiet */
    {
        nat_model m = {50, 1, 1};
        static const int busy[] = {25, 45, 75, 120, 180};
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        n = learn(&L, &m, HL_BUSY, &now, tried, 32);
        CHECK(seq_eq(tried, n, busy, 5) && hl_iv(&L, HL_BUSY) == 144 && !L.per_flow,
              "busy, kept by the traffic: %d steps, iv %d", n, hl_iv(&L, HL_BUSY));
        CHECK(hl_iv(&L, HL_QUIET) == 25 && L.tr[HL_QUIET].phase != HL_LEARNED, "the quiet track not learned meanwhile");
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(hl_iv(&L, HL_QUIET) == 36 && hl_iv(&L, HL_BUSY) == 144, "then quiet: iv %d / %d", hl_iv(&L, HL_QUIET),
              hl_iv(&L, HL_BUSY));
        /* a per-flow NAT: busy fails too, both tracks 36 */
        m.busy_keeps = 0;
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        n = learn(&L, &m, HL_BUSY, &now, tried, 32);
        CHECK(L.per_flow && hl_iv(&L, HL_BUSY) == 36 && L.tr[HL_QUIET].t_fail == 60 && L.tr[HL_QUIET].t_ok == 45
              && hl_iv(&L, HL_QUIET) == 36, "per-flow: busy iv %d, quiet t_ok %d t_fail %d", hl_iv(&L, HL_BUSY),
              L.tr[HL_QUIET].t_ok, L.tr[HL_QUIET].t_fail);
        /* a quiet success counts for busy too */
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        hl_next(&L, HL_QUIET, now, now * 1000, &st);
        hl_done(&L, &st, HL_OK, HL_QUIET, now, now * 1000);
        CHECK(L.tr[HL_BUSY].t_ok == 25, "quiet success, busy t_ok %d", L.tr[HL_BUSY].t_ok);
    }
    /* APDM: one track, a step classified busy counts for it */
    {
        hl_init(&L, NPF_MAP_APDM, 150, 0);
        CHECK(hl_next(&L, HL_BUSY, now, now * 1000, &st) && st.track == HL_QUIET, "APDM: one track");
    }
    /* a void step: tried again 60 s later, the same wait */
    {
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        hl_next(&L, HL_QUIET, now, now * 1000, &st);
        hl_done(&L, &st, HL_OK, HL_QUIET, now, now * 1000);
        hl_next(&L, HL_QUIET, now, now * 1000, &st);
        CHECK(st.T == 45, "after 25: %d", st.T);
        hl_done(&L, &st, HL_VOID, HL_QUIET, now, now * 1000);
        CHECK(!hl_next(&L, HL_QUIET, now + 59, (now + 59) * 1000, &st), "a void step tried again within 60 s");
        CHECK(hl_next(&L, HL_QUIET, now + 61, (now + 61) * 1000, &st) && st.T == 45, "and after 60 s: %d", st.T);
        hl_done(&L, &st, HL_OK, -1, now, now * 1000);
        CHECK(L.tr[HL_QUIET].t_ok == 25, "a step without a class counted");
    }
    /* once learned: the day's step upward; a move (5.7) */
    {
        nat_model m = {50, 0, 0};
        int r;
        hl_init(&L, NPF_MAP_EIM, 150, 0);
        learn(&L, &m, HL_QUIET, &now, tried, 32);
        CHECK(!hl_next(&L, HL_QUIET, now + 3600, (now + 3600) * 1000, &st), "a step within the day");
        now += 86401;
        m.life = 100;                       /* the NAT keeps them longer now */
        n = learn(&L, &m, HL_QUIET, &now, tried, 32);
        {
            static const int up[] = {60, 75, 120, 95};
            CHECK(seq_eq(tried, n, up, 4) && hl_iv(&L, HL_QUIET) == 76, "the day's step up: %d steps (%d, %d), iv %d",
                  n, tried[0], tried[1], hl_iv(&L, HL_QUIET));
        }
        r = hl_moved(&L, HL_QUIET, 1, now);
        CHECK(r == 0 && hl_iv(&L, HL_QUIET) == 76, "a network event changes nothing");
        r = hl_moved(&L, HL_QUIET, 0, now);
        CHECK(r == 1 && hl_iv(&L, HL_QUIET) == 60 && hl_drops_24h(&L, now) == 1, "a move: iv %d", hl_iv(&L, HL_QUIET));
        hl_moved(&L, HL_QUIET, 0, now + 10);
        r = hl_moved(&L, HL_QUIET, 0, now + 20);
        CHECK(r == 2 && L.tr[HL_QUIET].phase == HL_NEW && hl_iv(&L, HL_QUIET) == 25, "the third in a day: learned again");
    }
    /* home_learn = 0: never a step, 25 s */
    hl_init(&L, NPF_MAP_EIM, 150, 1);
    CHECK(!hl_next(&L, HL_QUIET, now, now * 1000, &st) && hl_iv(&L, HL_QUIET) == 25, "home_learn 0");
    /* the gateway maps the port: 144 at once */
    hl_init(&L, NPF_MAP_EIM, 150, 0);
    hl_mapped(&L, now);
    CHECK(hl_iv(&L, HL_QUIET) == 144, "mapped: iv %d", hl_iv(&L, HL_QUIET));
}

static void test_classify(void)
{
    npf_udp_watch w;
    int64_t s = 100000, e = s + 45000;
    memset(&w, 0, sizeof w);
    CHECK(hl_classify(NPF_MAP_EIM, &w, s, e) == HL_QUIET, "EIM, nothing sent: quiet");
    w.n_relay = 1;
    CHECK(hl_classify(NPF_MAP_APDM, &w, s, e) < 0, "anything to the relay: void");
    w.n_relay = 0;
    w.n_relay_ip = 1;
    w.first_other = w.prev_other = s + 1000;
    CHECK(hl_classify(NPF_MAP_ADM, &w, s, e) < 0, "ADM: the relay's IP (a probe server): void");
    CHECK(hl_classify(NPF_MAP_APDM, &w, s, e) == HL_QUIET, "APDM: the relay's IP, another port: quiet");
    w.n_relay_ip = 0;
    w.n_other = 4;
    w.first_other = s + 10000;
    w.prev_other = s + 40000;
    w.gap_other = 15000;
    CHECK(hl_classify(NPF_MAP_EIM, &w, s, e) == HL_BUSY, "EIM, sending every 15 s: busy");
    CHECK(hl_classify(NPF_MAP_ADM, &w, s, e) == HL_QUIET, "ADM, sending elsewhere: quiet");
    w.first_other = s + 30000;              /* started midway */
    CHECK(hl_classify(NPF_MAP_EIM, &w, s, e) < 0, "EIM, started sending midway: void");
    w.first_other = s + 1000;
    w.prev_other = s + 20000;               /* stopped midway */
    CHECK(hl_classify(NPF_MAP_EIM, &w, s, e) < 0, "EIM, stopped midway: void");
}

static void test_store(void)
{
    char dir[] = "/tmp/npf-home-XXXXXX", path[128];
    hl_state L, M;
    int64_t used = 0, now = 1793000000;
    uint64_t k1 = home_net_key(0x0101a8c0, "aa:bb:cc:dd:ee:ff", 0x0001a8c0, 24, inet_addr("198.51.100.7"), 0);
    uint64_t k2 = home_net_key(0x0101a8c0, "aa:bb:cc:dd:ee:ff", 0x0001a8c0, 24, inet_addr("198.51.7.9"), 0);
    uint64_t k3 = home_net_key(0x0101a8c0, "aa:bb:cc:dd:ee:ff", 0x0001a8c0, 24, inet_addr("198.52.100.7"), 0);
    uint64_t k4 = home_net_key(0x0101a8c0, "aa:bb:cc:dd:ee:00", 0x0001a8c0, 24, inet_addr("198.51.100.7"), 0);
    int i;
    CHECK(k1 == k2 && k1 != k3 && k1 != k4 && k1 != home_net_key(0x0101a8c0, "aa:bb:cc:dd:ee:ff", 0x0001a8c0, 24,
                                                                 inet_addr("198.51.100.7"), 1),
          "the network key: the public IP's /16, the gateway's MAC, cellular");
    CHECK(mkdtemp(dir) != NULL, "temp dir");
    snprintf(path, sizeof path, "%s/home.json", dir);
    hl_init(&L, NPF_MAP_EIM, 150, 0);
    CHECK(home_store_load(path, k1, &L, &used) < 0, "no file: no record");
    L.tr[HL_QUIET].phase = HL_LEARNED;
    L.tr[HL_QUIET].t_ok = 45;
    L.tr[HL_QUIET].t_fail = 60;
    L.tr[HL_QUIET].learned_at = now;
    L.tr[HL_QUIET].up_at = now + 86400;
    L.tr[HL_BUSY].t_ok = 180;
    L.refresh = HL_REFRESH_OUT;
    L.preserve = 1;
    L.per_flow = 1;
    L.drops[2] = now - 5;
    CHECK(home_store_save(path, k1, &L, now) == 0, "saved");
    hl_init(&M, NPF_MAP_UNKNOWN, 150, 0);
    CHECK(home_store_load(path, k1, &M, &used) == 0 && used == now, "loaded");
    CHECK(M.map == NPF_MAP_EIM && M.tr[HL_QUIET].phase == HL_LEARNED && M.tr[HL_QUIET].t_ok == 45
          && M.tr[HL_QUIET].t_fail == 60 && M.tr[HL_BUSY].t_ok == 180 && M.refresh == HL_REFRESH_OUT && M.preserve == 1
          && M.per_flow && M.drops[2] == now - 5 && hl_iv(&M, HL_QUIET) == 36, "the record as saved");
    /* 18 networks: the 16 used last kept */
    for (i = 0; i < 18; i++) {
        hl_init(&M, NPF_MAP_APDM, 150, 0);
        M.tr[HL_QUIET].t_ok = 10 + i;
        home_store_save(path, 1000 + (uint64_t)i, &M, now + 1 + i);
    }
    CHECK(home_store_load(path, k1, &M, NULL) < 0 && home_store_load(path, 1001, &M, NULL) < 0
          && home_store_load(path, 1002, &M, NULL) == 0 && M.tr[HL_QUIET].t_ok == 12
          && home_store_load(path, 1017, &M, NULL) == 0, "LRU of 16");
    /* damaged: ignored, written anew */
    npf_file_write(path, "{\"nets\": [{\"key\": ", 18, 0600);
    CHECK(home_store_load(path, 1017, &M, NULL) < 0, "a damaged file read");
    CHECK(home_store_save(path, k1, &L, now) == 0 && home_store_load(path, k1, &M, NULL) == 0, "written over a damaged one");
    unlink(path);
    rmdir(dir);
}

/* ---- the client against a fake relay ---- */

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
    int      iv, probe, flags, len;
} seen;

/* the next HOME_BIND the client sent within ms: 1, 0 none */
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
        b->iv = pk.body[16] | pk.body[17] << 8;
        b->probe = pk.body[18] | pk.body[19] << 8;
        b->flags = pk.body[20];
        b->len = (int)n;
        return 1;
    }
    return 0;
}

static void answer(npf_node *n, const npf_siv_keys *keys, const struct sockaddr_in *relay, const struct sockaddr_in *me,
                   const uint8_t *txid, uint32_t ts, uint64_t kseq, int state, const uint8_t ck[8], int flags)
{
    uint8_t body[3 + 4 + 8 + 1 + 8 + 8 + 1] = {4}, out[128];
    struct sockaddr_storage from;
    int r;
    body[1] = (uint8_t)ntohs(me->sin_port);
    body[2] = (uint8_t)(ntohs(me->sin_port) >> 8);
    memcpy(body + 3, &me->sin_addr, 4);
    npf_le64(body + 7, (uint64_t)npf_node_time(n));
    body[15] = (uint8_t)state;
    memcpy(body + 16, ck, 8);
    npf_le64(body + 24, kseq);
    body[32] = (uint8_t)flags;
    r = npf_pkt_seal(keys, NPF_DIR_RESP, PKT_HOME_ACK, txid, ts, body, sizeof body, 80, out);
    memset(&from, 0, sizeof from);
    memcpy(&from, relay, sizeof *relay);
    if (r > 0)
        node_home_input(n, n->udp_fd, out, (size_t)r, &from);
}

static void ping(npf_node *n, const npf_siv_keys *keys, const struct sockaddr_in *relay, const uint8_t *txid,
                 uint32_t ts, int probe, int nn)
{
    uint8_t body[11], out[64];
    struct sockaddr_storage from;
    int r;
    npf_le64(body, (uint64_t)npf_node_time(n));
    body[8] = (uint8_t)probe;
    body[9] = (uint8_t)(probe >> 8);
    body[10] = (uint8_t)nn;
    r = npf_pkt_seal(keys, NPF_DIR_RESP, PKT_HOME_PING, txid, ts, body, sizeof body, 43, out);
    memset(&from, 0, sizeof from);
    memcpy(&from, relay, sizeof *relay);
    if (r > 0)
        node_home_input(n, n->udp_fd, out, (size_t)r, &from);
}

static void test_client(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    npf_siv_keys keys;
    struct sockaddr_in relay, me;
    uint8_t seed[32], bid[8], key[32], foreign[NPF_TXID_SIZE], ck[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    char js[1024];
    seen b1, b2, b3;
    int fr, fc, m = 0;

    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    fr = udp_lo(&relay);
    fc = udp_lo(&me);
    CHECK(loop && fr >= 0 && fc >= 0 && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "set-up");
    if (fails)
        return;
    node.udp_fd = fc;
    npf_random(bid, 8);
    npf_random(key, 32);
    npf_random(foreign, sizeof foreign);
    npf_siv_derive(&keys, key, LABEL_HOME);
    CHECK(node_home_test_take(&node, bid, key, &relay) == 0, "the binding taken");
    /* the first HOME_BIND: its cookie zero, kseq 1 */
    CHECK(next_bind(fr, &keys, bid, 500, &b1) == 1 && b1.kseq == 1 && b1.cookie[0] == 0 && !b1.probe, "the first HOME_BIND");
    /* answers to what it did not send: nothing */
    answer(&node, &keys, &relay, &me, foreign, b1.ts, b1.kseq, 0, ck, 0);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq + 5, 0, ck, 0);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts - 1, b1.kseq, 0, ck, 0);
    CHECK(next_bind(fr, &keys, bid, 100, &b2) == 0, "a foreign challenge answered");
    /* its own challenge: echoed with the cookie, the next kseq */
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 0);
    CHECK(next_bind(fr, &keys, bid, 300, &b2) == 1 && memcmp(b2.cookie, ck, 8) == 0 && b2.kseq == 2, "the challenge echoed");
    /* the same again (a replay): taken once */
    usleep(250 * 1000);
    answer(&node, &keys, &relay, &me, b1.txid, b1.ts, b1.kseq, 0, ck, 0);
    CHECK(next_bind(fr, &keys, bid, 100, &b3) == 0, "a replayed challenge answered");
    CHECK(node_home_state(&node, NULL) != 3, "bound by a challenge");
    /* bound: the first step of the learning at the first keepalive (25 s, long enough for the echo) */
    answer(&node, &keys, &relay, &me, b2.txid, b2.ts, b2.kseq, 1, ck, 0);
    CHECK(node_home_state(&node, &m) == 3 && m == 0, "bound, measuring %d s", m);
    node_home_test_due(&node);
    CHECK(node_home_state(&node, &m) == 3 && m == 25, "the keepalive due: measuring %d s", m);
    CHECK(next_bind(fr, &keys, bid, 300, &b3) == 1 && b3.probe == 25 && b3.len >= HOME_PROBE_LEN && b3.iv >= 30
          && b3.kseq == 3, "the step's HOME_BIND: probe_s %d, %d bytes, iv %d", b3.probe, b3.len, b3.iv);
    answer(&node, &keys, &relay, &me, b3.txid, b3.ts, b3.kseq, 1, ck, HOME_A_PROBE_SET);
    /* an echo of another keepalive, of another wait: nothing */
    ping(&node, &keys, &relay, b2.txid, b2.ts, 25, 1);
    ping(&node, &keys, &relay, b3.txid, b3.ts, 45, 1);
    CHECK(node_home_state(&node, &m) == 3 && m == 25, "a foreign echo taken");
    /* its echo: 25 s lives, the next step (45) at once */
    ping(&node, &keys, &relay, b3.txid, b3.ts, 25, 1);
    CHECK(node_home_state(&node, &m) == 3 && m == 45, "after the echo: measuring %d s", m);
    CHECK(next_bind(fr, &keys, bid, 300, &b1) == 1 && b1.probe == 45, "the next step's HOME_BIND: %d", b1.probe);
    {
        size_t l = npf_node_home_json(&node, js, sizeof js);
        CHECK(l > 0 && strstr(js, "\"state\":\"bound\"") && strstr(js, "\"step_s\":45") && strstr(js, "\"t_ok\":25"),
              "status %s", js);
    }
    node_home_stop(&node);
    node.udp_fd = -1;
    npf_node_stop(&node);
    npf_loop_free(loop);
    close(fr);
    close(fc);
}

int test_home(void)
{
    test_vectors();
    test_learner();
    test_classify();
    test_store();
    test_client();
    return fails;
}

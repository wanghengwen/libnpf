/* Mutation fuzzer for the parsers that face the network: JSON, sublink frames
 * and control messages, Noise handshake messages (responder side), certificates,
 * grants, server lists, SIV / probe packets.
 *
 *   npf_fuzz TARGET [ITERATIONS] [SEED]      mutate built-in seeds, run under ASan + UBSan
 *   npf_fuzz TARGET -f FILE...               replay inputs (crash reproducers)
 *
 * TARGET: json | msg | control | tunnel | noise | cert | pkt | dns | http | ws | all. With a clang that has
 * libFuzzer, -DNPF_LIBFUZZER builds the same targets as LLVMFuzzerTestOneInput
 * entry points (one target per binary, selected with -DNPF_FUZZ_TARGET=name). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "npf/bind.h"
#include "npf/cert.h"
#include "npf/crypto.h"
#include "npf/dns.h"
#include "npf/json.h"
#include "npf/log.h"
#include "npf/loop.h"
#include "npf/msg.h"
#include "npf/node.h"
#include "npf/noise.h"
#include "npf/siv.h"
#include "npf/tunnel.h"
#include "call_internal.h"
#include "msgs.h"

#define MAX_IN 4096

/* ---- targets ---- */

static void fuzz_json(const uint8_t *d, size_t n)
{
    static npf_jtok tok[NPF_JSON_MAX_TOKENS];
    npf_json j;
    char s[MAX_IN + 1], buf[300];
    int64_t v;
    uint8_t b[64];
    int t, i, ok;
    if (n > MAX_IN)
        return;
    memcpy(s, d, n);
    s[n] = 0;
    if (npf_json_parse(&j, s, n, tok, NPF_JSON_MAX_TOKENS) < 0)
        return;
    npf_json_get_str(&j, 0, "type", buf, sizeof buf);
    npf_json_get_int(&j, 0, "v", 0, 100, &v);
    npf_json_get_b64(&j, 0, "hs", b, sizeof b);
    npf_json_bool(&j, npf_json_get(&j, 0, "ok"), &ok);
    t = npf_json_get(&j, 0, "data");
    if (t >= 0) {
        npf_json_get_str(&j, t, "call_id", buf, sizeof buf);
        for (i = 0; i < 4; i++) {
            int it = npf_json_item(&j, npf_json_get(&j, t, "cand"), i);
            if (it >= 0)
                npf_json_get_str(&j, it, "a", buf, sizeof buf);
        }
    }
    npf_json_eq(&j, npf_json_get(&j, 0, "status"), "ok");
}

/* what a parse leaves, whatever the input: strings terminated within their
 * buffer, lengths and counts within theirs (else the handlers would read past
 * them) */
static void msg_check(const npf_msgdesc *d, const uint8_t *base)
{
    int i, k, v = 0;
    for (i = 0; i < d->nf; i++) {
        const npf_field *f = &d->f[i];
        const uint8_t *p = base + f->off;
        if (f->aux)
            memcpy(&v, base + f->aux, sizeof v);
        if ((f->type == NPF_F_STR && !memchr(p, 0, f->size)) || (f->aux && (v < 0 || v > f->size)))
            abort();
        if (f->type == NPF_F_OBJ)
            msg_check(f->sub, p);
        for (k = 0; f->type == NPF_F_ARR && k < v; k++)
            msg_check(f->sub, p + (size_t)k * f->sub->size);
    }
}

/* every table (msgs.c: the messages', the server list's, the files') on the
 * message and on its data, then wiped */
static void fuzz_msg(const uint8_t *d, size_t n)
{
    static npf_jtok tok[NPF_JSON_MAX_TOKENS];
    static union { int64_t i; struct sockaddr_storage ss; uint8_t b[32768]; } u;
    const npf_msgdesc *const *all[2] = {node_msgdescs, node_filedescs}, *m;
    npf_json j;
    char s[MAX_IN + 1], err[160];
    int a, i, k, t[2];
    if (n > MAX_IN)
        return;
    memcpy(s, d, n);
    s[n] = 0;
    if (npf_json_parse(&j, s, n, tok, NPF_JSON_MAX_TOKENS) < 0)
        return;
    t[0] = 0;
    t[1] = npf_json_get(&j, 0, "data");
    for (a = 0; a < 2; a++)
        for (i = 0; (m = all[a][i]); i++)
            for (k = 0; k < 2; k++) {
                if (m->size > sizeof u)
                    abort();
                if (npf_msg_parse(m, &j, t[k], &u, err, sizeof err) == 0)
                    msg_check(m, u.b);
                else if (!memchr(err, 0, sizeof err))
                    abort();
                npf_msg_wipe(m, &u);
            }
}

static npf_loop *g_loop;

/* a call's tunnel control messages (call_transport.c:call_control): the
 * callee's and the caller's side of a call, up, of an offline node (no
 * policy: every reverse_listen forbidden; no tunnel: the replies go nowhere) */
static void fuzz_control(const uint8_t *d, size_t n)
{
    static npf_jtok tok[NPF_JSON_MAX_TOKENS];
    static npf_node node;
    npf_json j;
    char s[MAX_IN + 1];
    int k;
    if (!node.loop) {
        npf_node_cfg cfg = {0};
        npf_node_hooks hooks = {0};
        npf_identity id;
        uint8_t seed[32] = {7};
        cfg.offline = 1;
        npf_identity_from_seed(&id, seed);
        if (!(g_loop = g_loop ? g_loop : npf_loop_new()) || npf_node_init(&node, g_loop, &cfg, &id, &hooks, NULL) < 0)
            abort();
    }
    if (n > MAX_IN)
        return;
    memcpy(s, d, n);
    s[n] = 0;
    if (npf_json_parse(&j, s, n, tok, NPF_JSON_MAX_TOKENS) < 0 || tok[0].type != NPF_JT_OBJECT)
        return;                             /* the tunnel's own check (tunnel.c:handle_control) */
    for (k = 0; k < 2; k++) {
        npf_call *c = call_new(&node, k);
        if (!c)
            abort();
        c->st = CS_UP;
        call_control(c, &j);
        npf_call_end(c, "fuzz");
    }
    npf_loop_once(g_loop, 0);               /* the calls freed */
}
static int io_write(void *a, const uint8_t *b, size_t n) { (void)a; (void)b; (void)n; return 0; }
static size_t io_backlog(void *a) { (void)a; return 0; }
static void io_ready(void *a) { (void)a; }
static void io_control(void *a, const npf_json *j) { (void)a; (void)j; }
static void io_broken(void *a, const char *w) { (void)a; (void)w; }
static const npf_tunnel_io io = {io_write, io_write, io_backlog, io_ready, io_control, io_broken, NULL, NULL, NULL, NULL};

/* the caller's hello unit, so that the fuzzed input reaches the sublink code */
static const char hello_json[] = "{\"v\":2,\"type\":\"hello\",\"data\":{\"init_window\":262144,\"max_sublinks\":128}}";

/* the first half of the input is control channel bytes (delivered in two
 * pieces: reassembly across chunks), the second a sequence of data messages
 * len(2) | message */
static void fuzz_tunnel(const uint8_t *d, size_t n)
{
    uint8_t hello[3 + sizeof hello_json];
    npf_tunnel *t;
    size_t h = n / 2, off;
    int i;
    if (!g_loop)
        g_loop = npf_loop_new();
    t = npf_tunnel_new(g_loop, 0, &io, NULL, NULL);   /* callee: no policy -> every target refused */
    if (!t)
        return;
    npf_tunnel_start(t);
    hello[0] = NPF_CU_JSON;
    hello[1] = (uint8_t)(sizeof hello_json - 1);
    hello[2] = (uint8_t)((sizeof hello_json - 1) >> 8);
    memcpy(hello + 3, hello_json, sizeof hello_json - 1);
    npf_tunnel_input_ctrl(t, hello, 3 + sizeof hello_json - 1);
    npf_tunnel_input_ctrl(t, d, h / 2);
    npf_tunnel_input_ctrl(t, d + h / 2, h - h / 2);
    for (off = h; off + 2 <= n;) {
        size_t m = (size_t)(d[off] | d[off + 1] << 8);
        off += 2;
        if (m > n - off)
            m = n - off;
        npf_tunnel_input_data(t, d + off, m);
        off += m;
    }
    for (i = 0; i < 3; i++)
        npf_loop_once(g_loop, 0);
    npf_tunnel_free(t);
}

static void fuzz_noise(const uint8_t *d, size_t n)
{
    static const int patterns[] = {NPF_NOISE_XK, NPF_NOISE_IK, NPF_NOISE_XXPSK3, NPF_NOISE_NNPSK0};
    static uint8_t sk[32], psk[32];
    static int init;
    uint8_t payload[512];
    size_t i;
    if (!init) {
        for (i = 0; i < 32; i++) { sk[i] = (uint8_t)(i + 1); psk[i] = (uint8_t)(0x80 + i); }
        init = 1;
    }
    for (i = 0; i < sizeof patterns / sizeof patterns[0]; i++) {
        npf_noise_hs hs;
        if (npf_noise_init(&hs, patterns[i], 0, "npf-fuzz", 8, patterns[i] == NPF_NOISE_NNPSK0 ? NULL : sk, NULL,
                           psk) < 0)
            continue;
        if (npf_noise_read(&hs, d, n, payload, sizeof payload) >= 0) {
            uint8_t out[512];
            npf_noise_write(&hs, NULL, 0, out, sizeof out);   /* a lucky message 1: answer it */
        }
    }
}

static void fuzz_cert(const uint8_t *d, size_t n)
{
    static uint8_t roots[1][32], pub[32];
    static npf_server_entry list[NPF_MAX_SERVERS];
    npf_list_meta meta;
    npf_cert c, inter, leaf;
    npf_grant g;
    const uint8_t *pl;
    size_t plen;
    int64_t serial;
    npf_cert_parse(d, n, &c);
    npf_cert_chain_parse((const uint8_t (*)[32])roots, 1, d, n, &inter, &leaf, 0);
    npf_grant_verify(d, n, pub, &g);
    if (npf_signed_verify((const uint8_t (*)[32])roots, 1, NPF_PERM_SERVERLIST, d, n, &pl, &plen) == 0)
        npf_serverlist_parse((const char *)pl, plen, list, &serial, &meta);
    if (n <= MAX_IN) {                      /* the payload parser on its own: it is JSON */
        char s[MAX_IN + 1];
        memcpy(s, d, n);
        s[n] = 0;
        npf_serverlist_parse(s, n, list, &serial, &meta);
    }
}

static void fuzz_pkt(const uint8_t *d, size_t n)
{
    static npf_siv_keys keys;
    static int init;
    uint8_t plain[MAX_IN];
    npf_pkt pkt;
    if (!init) {
        uint8_t k[32];
        size_t i;
        for (i = 0; i < 32; i++) k[i] = (uint8_t)(0x40 + i);
        npf_siv_derive(&keys, k, NPF_SIV_LABEL_PROBE);
        init = 1;
    }
    if (n > MAX_IN)
        return;
    npf_pkt_open(&keys, NPF_DIR_REQ, d, n, plain, &pkt);
    npf_siv_open(&keys, 1, d, n, plain);
}

/* DNS answers from a DoH service (the server list's seed, security.md 7.5) */
static void count_txt(const uint8_t *t, size_t n, void *arg)
{
    (void)t;
    *(size_t *)arg += n;
}

static void fuzz_dns(const uint8_t *d, size_t n)
{
    size_t total = 0;
    npf_dns_txt_answers(d, n, count_txt, &total);
}

typedef void (*target_fn)(const uint8_t *, size_t);

void npf_fuzz_http(const uint8_t *data, size_t len);
void npf_fuzz_ws(const uint8_t *data, size_t len);

static const struct {
    const char *name;
    target_fn   fn;
    const char *seed;               /* a valid input to start from */
} targets[] = {
    {"http", npf_fuzz_http, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"},
    {"ws", npf_fuzz_ws, "\x82\x03" "abc"},
    {"json", fuzz_json, "{\"v\":1,\"type\":\"call\",\"id\":\"c1\",\"data\":{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\","
                        "\"callee\":\"123456789\",\"auth\":\"ik\",\"hs\":\"AAAA\",\"nat\":{\"udp\":true},"
                        "\"cand\":[{\"t\":\"srflx\",\"a\":\"1.2.3.4:5\"}]}}"},
    {"msg", fuzz_msg, "{\"v\":1,\"type\":\"punch_start\",\"id\":\"r1\",\"data\":{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\","
                      "\"round\":1,\"punch_id\":\"AAAAAAAAAAA\",\"punch_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
                      "\"strategy\":\"S3\",\"side\":\"easy\",\"peer\":{\"cand\":[{\"t\":\"srflx\",\"a\":\"1.2.3.4:5\"},"
                      "{\"t\":\"host6\",\"a\":\"[2001:db8::1]:9\"}],\"pub_ip\":\"1.2.3.4\"},\"range\":[1,65535],"
                      "\"m_total\":10,\"start_at\":1,\"relay\":{\"mode\":\"udp\",\"relay_id\":\"AAAAAAAAAAA\","
                      "\"alloc_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"udp\":[\"1.2.3.4:5\",\"[::1]:3\"],"
                      "\"ws\":{\"url\":\"wss://a/r\",\"server_id\":1},\"spare\":true},\"probe_keys\":[{\"day\":1,"
                      "\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}],\"probe\":[\"1.2.3.4:9\"],"
                      "\"ticket\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"upgrade\":{\"latest\":\"1.0\",\"packages\":[]},"
                      "\"hs\":\"AAAA\",\"caller\":{\"kind\":\"node\",\"id\":\"1\",\"app\":{\"name\":\"a\",\"ver\":\"1\"}},"
                      "\"auth\":\"ik\",\"cand\":{\"t\":\"srflx\",\"a\":\"1.2.3.4:5\"},\"port\":2000,\"listen_id\":1,"
                      "\"target_host\":\"h\",\"target_port\":1,\"account_id\":\"1\",\"operation_id\":\"AAAAAAAAAAAAAAAAAAAAAA\","
                      "\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"expires\":1,\"before\":1,\"number\":\"1\",\"cert\":\"AAAA\","
                      "\"step\":3,\"msg\":\"AAAA\",\"error\":\"x\",\"reason\":\"y\",\"grant\":\"AAAA\"}}"},
    {"tunnel", fuzz_tunnel, "\x01\x00\x00\x00\x01\x00\x0d\x00\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"},
    {"control", fuzz_control, "{\"v\":1,\"type\":\"reverse_listen\",\"id\":\"7\",\"data\":{\"bind\":\"*\",\"port\":0,"
                              "\"target_host\":\"127.0.0.1\",\"target_port\":22,\"udp\":true}}"},
    {"noise", fuzz_noise, NULL},
    {"cert", fuzz_cert, "{\"serial\":1,\"servers\":[{\"id\":1,\"ws\":[\"wss://a/s\"],\"dh_pub\":\"AAAA\"}]}"},
    {"pkt", fuzz_pkt, NULL},
    {"dns", fuzz_dns, NULL},
};

/* ---- driver ---- */

#ifdef NPF_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    size_t i;
    npf_log_set_level(NPF_LOG_ERROR);       /* a refused server list is a warning */
    for (i = 0; i < sizeof targets / sizeof targets[0]; i++)
        if (strcmp(targets[i].name, NPF_FUZZ_TARGET) == 0)
            targets[i].fn(d, n);
    return 0;
}
#else

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return x;
}

/* a few random edits: bit flips, byte sets, insertions, deletions, truncation, duplication */
static size_t mutate(uint8_t *b, size_t n, size_t cap)
{
    int ops = 1 + (int)(rnd() % 8), k;
    for (k = 0; k < ops; k++) {
        size_t p = n ? rnd() % n : 0;
        switch (rnd() % 7) {
        case 0: if (n) b[p] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: if (n) b[p] = (uint8_t)rnd(); break;
        case 2: if (n) b[p] = (uint8_t)"\x00\xff\x7f\x80\x01\x10\x20\x40"[rnd() % 8]; break;
        case 3: if (n + 1 < cap) { memmove(b + p + 1, b + p, n - p); b[p] = (uint8_t)rnd(); n++; } break;
        case 4: if (n) { memmove(b + p, b + p + 1, n - p - 1); n--; } break;
        case 5: if (n) n = p; break;
        case 6: { size_t l = n ? rnd() % (n - p + 1) : 0;
                  if (l && n + l < cap) { memmove(b + p + l, b + p, n - p); memcpy(b + p, b + p + l, l); n += l; } }
                break;
        }
    }
    return n;
}

static void run_file(target_fn fn, const char *path)
{
    static uint8_t b[65536];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) {
        perror(path);
        return;
    }
    n = fread(b, 1, sizeof b, f);
    fclose(f);
    fn(b, n);
    printf("%s: %zu bytes ok\n", path, n);
}

int main(int argc, char **argv)
{
    static uint8_t buf[MAX_IN];
    long iters = 20000, it;
    size_t t, first = 0, last = sizeof targets / sizeof targets[0];
    npf_log_set_level(NPF_LOG_ERROR);       /* a refused server list is a warning */
    if (argc < 2) {
        fprintf(stderr, "usage: npf_fuzz json|msg|control|tunnel|noise|cert|pkt|dns|http|ws|all [ITERATIONS] [SEED] | TARGET -f FILE...\n");
        return 2;
    }
    if (strcmp(argv[1], "all") != 0) {
        for (t = 0; t < last && strcmp(targets[t].name, argv[1]) != 0; t++)
            ;
        if (t == last) {
            fprintf(stderr, "unknown target %s\n", argv[1]);
            return 2;
        }
        first = t;
        last = t + 1;
    }
    if (argc > 2 && strcmp(argv[2], "-f") == 0) {
        int i;
        for (i = 3; i < argc; i++)
            for (t = first; t < last; t++)
                run_file(targets[t].fn, argv[i]);
        return 0;
    }
    if (argc > 2)
        iters = atol(argv[2]);
    rng_state ^= argc > 3 ? (uint64_t)atoll(argv[3]) : (uint64_t)time(NULL);
    printf("seed %llu\n", (unsigned long long)rng_state);
    for (t = first; t < last; t++) {
        for (it = 0; it < iters; it++) {
            size_t n;
            if (targets[t].seed && (it % 2 == 0)) {
                n = strlen(targets[t].seed);
                if (strcmp(targets[t].name, "tunnel") == 0)
                    n = 21;             /* the seed holds a NUL: a 13-byte DATA frame */
                memcpy(buf, targets[t].seed, n);
            } else {
                size_t i;
                n = rnd() % 300;
                for (i = 0; i < n; i++)
                    buf[i] = (uint8_t)rnd();
            }
            n = mutate(buf, n, sizeof buf);
            targets[t].fn(buf, n);
        }
        printf("%s: %ld inputs\n", targets[t].name, iters);
    }
    npf_loop_free(g_loop);
    return 0;
}
#endif

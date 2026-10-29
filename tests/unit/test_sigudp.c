/* UDP signaling (src/proto/sigudp.c, signaling-udp.md 11.2) against a small
 * responder on libnpf's own Noise: the handshake (lengths, random padding,
 * the handshake hash), the cookie (and kept for the next attempt), answers
 * without this attempt's txid ignored, message 3 sent again until the
 * server's first transport packet, the reliable layer under loss, reordering
 * and duplicates both ways, segmentation, ping while segments are in
 * flight, CLOSE, the replay window, packets only from the server's address,
 * malformed packets dropped, the send queue's limit, the hellos' schedule,
 * and roaming to another source port over real sockets. The client's
 * datagrams go into a queue the test hands to the responder (dropping some
 * on purpose); the responder's go straight to npf_sig_input. */
#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/node.h"
#include "npf/noise.h"
#include "npf/sig.h"
#include "npf/siv.h"
#include "node_internal.h"
#include "test.h"

#ifdef NPF_SIG_UDP

#define PROLOGUE "npf-sigudp-v1"
#define REQUIRE_V(cond) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return; } \
} while (0)

/* ---- the client's datagrams ---- */

typedef struct dgram { uint8_t b[1500]; size_t n; } dgram;
static dgram q[512];
static int nq;
static int real_fd = -1;                /* the roaming test: sent on this socket instead */

static int cb_send(const void *p, size_t n, const struct sockaddr_in *to, void *arg)
{
    (void)arg;
    if (real_fd >= 0)
        return (int)sendto(real_fd, p, n, 0, (const struct sockaddr *)to, sizeof *to);
    if (nq < (int)(sizeof q / sizeof q[0]) && n <= sizeof q[0].b) {
        memcpy(q[nq].b, p, n);
        q[nq++].n = n;
    }
    return (int)n;
}

/* ---- the client's callbacks ---- */

static int ready, downs, msgs;
static char down_why[64], last_msg[256];

static void cb_ready(npf_sig *s, void *arg) { (void)s, (void)arg; ready++; }
static void cb_down(npf_sig *s, const char *why, void *arg)
{
    npf_sig **h = arg;
    (void)s;
    downs++;
    snprintf(down_why, sizeof down_why, "%s", why);
    if (h)
        *h = NULL;                      /* freed after this */
}
static void cb_msg(npf_sig *s, const npf_json *j, void *arg)
{
    (void)s, (void)arg;
    msgs++;
    snprintf(last_msg, sizeof last_msg, "%.*s", (int)j->tok[0].end - j->tok[0].start, j->s + j->tok[0].start);
}
static const npf_sig_cbs cbs = {cb_ready, cb_msg, cb_down};

/* ---- the responder ---- */

typedef struct srv {
    npf_identity id;
    struct sockaddr_in addr;
    npf_siv_keys hk;
    npf_noise_hs hs;
    int state;                          /* 0 none, 1 half-open, 2 up */
    uint8_t idx[4], k1[32], k2[32], hash[64], rs[32];
    uint8_t txid[NPF_TXID_SIZE];
    uint64_t tx_ctr, rx_max;
    int rx_any;
    uint16_t rcv_nxt, snd_sn;
    /* what came */
    int hellos, hello_bad_len, hello_mac_ok, m3s, m3_bad_len, early, pings, closes, acks_in, segs_in;
    int pad_zero;                       /* a hello whose padding was all zeros */
    char close_reason[40];
    uint8_t *ra;
    size_t ra_len;
    int nmsg;
    size_t msg_len[512];
    uint32_t msg_sum[512];
    char first[256];
    /* behaviour */
    uint8_t *ooo[64];                   /* by sn % 64: kept out of order */
    size_t ooo_len[64];
    uint8_t ooo_end[64];
    int tr_bad;                         /* at the session, not authenticated (message 3 again) */
    const char *prologue;
    int loss_out;                       /* % of the responder's datagrams lost */
    int need_cookie;
    int silent;                         /* real sockets: nothing in or out */
    int busy;                           /* message 3 answered with CLOSE "busy" */
    int logins;                         /* logins answered with a welcome */
    void (*on_login)(void *arg);        /* a login answered */
    void *on_login_arg;
    uint8_t cookie[16];
    int no_ack;                         /* no acks to the client's segments */
    int drop_m3;                        /* message 3s dropped before reading */
    int late_welcome;                   /* the next welcome held back in late, sent by the test */
    char late[160];
    struct sockaddr_in peer;            /* real sockets: where the client is */
    int fd;                             /* real sockets: the responder's */
} srv;

static uint32_t sum_of(const uint8_t *p, size_t n)
{
    uint32_t h = 2166136261u;
    while (n--)
        h = (h ^ *p++) * 16777619u;
    return h;
}

static npf_sig *cli;

static void srv_out(srv *v, const uint8_t *w, size_t n)
{
    struct sockaddr_storage from;
    memset(&from, 0, sizeof from);
    memcpy(&from, &v->addr, sizeof v->addr);
    if ((int)npf_rand_range(0, 99) < v->loss_out)
        return;
    if (v->fd >= 0)
        sendto(v->fd, w, n, 0, (const struct sockaddr *)&v->peer, sizeof v->peer);
    else if (cli)
        npf_sig_input(cli, &from, w, n);
}

static void srv_free(srv *v);

/* v: zeroed, or used before (its buffers freed) */
static void srv_init(srv *v, int seed)
{
    uint8_t s[32];
    srv_free(v);
    memset(v, 0, sizeof *v);
    memset(s, seed, sizeof s);
    npf_identity_from_seed(&v->id, s);
    v->addr.sin_family = AF_INET;
    v->addr.sin_addr.s_addr = htonl(0x7f000001);
    v->addr.sin_port = htons(9940);
    v->fd = -1;
    v->prologue = PROLOGUE;
    npf_siv_derive(&v->hk, v->id.dh_pub, "NPF-SIGHS-v1");
}

static void srv_free(srv *v)
{
    int i;
    free(v->ra);
    v->ra = NULL;
    for (i = 0; i < 64; i++) {
        free(v->ooo[i]);
        v->ooo[i] = NULL;
    }
}

static void env_raw(srv *v, int type, int flags, const uint8_t *body, size_t blen, uint32_t ts, size_t wire)
{
    uint8_t w[512], *p = w + NPF_SIV_TAG_SIZE;
    memset(w, 0, sizeof w);
    p[0] = (uint8_t)type;
    p[1] = (uint8_t)flags;
    npf_le16(p + 2, (uint16_t)blen);
    memcpy(p + 4, v->txid, NPF_TXID_SIZE);
    npf_le32(p + 16, ts);
    memcpy(p + 20, body, blen);
    npf_siv_seal(&v->hk, NPF_DIR_RESP, w, wire - NPF_SIV_TAG_SIZE);
    srv_out(v, w, wire);
}

static void env_send(srv *v, int type, const uint8_t *body, size_t blen, uint32_t ts, size_t wire)
{
    env_raw(v, type, 0, body, blen, ts, wire);
}

/* one transport plaintext to the client */
static void tr_send(srv *v, const uint8_t *pt, size_t n)
{
    uint8_t w[1300], nonce[12] = {0};
    npf_le64(w, v->tx_ctr++);
    memcpy(nonce + 4, w, 8);
    npf_aead_seal(v->k2, nonce, w, 8, pt, n, w + 8);
    srv_out(v, w, 8 + n + 16);
}

static void ack_send(srv *v)
{
    uint8_t a[3] = {0};
    npf_le16(a + 1, v->rcv_nxt);
    tr_send(v, a, 3);
}

/* a segment to the client: flags, our ack, sn, data */
static void seg_to(srv *v, int flags, uint16_t sn, const char *data, size_t len)
{
    uint8_t pt[1300];
    pt[0] = (uint8_t)flags;
    npf_le16(pt + 1, v->rcv_nxt);
    npf_le16(pt + 3, sn);
    memcpy(pt + 5, data, len);
    tr_send(v, pt, 5 + len);
}

static void msg_to(srv *v, const char *json)
{
    seg_to(v, 1, v->snd_sn++, json, strlen(json));
}

static void hello_in(srv *v, const uint8_t *b, size_t n)
{
    uint8_t plain[300], pl[8], mac[16], m2[64];
    npf_pkt pkt;
    size_t i;
    int z = 1;
    if (n < 160 || n > 256) {
        v->hello_bad_len++;
        return;
    }
    if (npf_pkt_open(&v->hk, NPF_DIR_REQ, b, n, plain, &pkt) < 0 || pkt.type != 11 || pkt.body_len != 64
        || plain[1] != 0)
        return;
    v->hellos++;
    for (i = 84; i < n - 12; i++)
        z &= plain[i] == 0;
    v->pad_zero += z && n - 12 > 84 + 8;
    memcpy(v->txid, pkt.txid, sizeof v->txid);
    crypto_blake2b_keyed(mac, 16, v->cookie, 16, plain, 68);
    if (memcmp(mac, plain + 68, 16) == 0)
        v->hello_mac_ok++;
    else if (v->need_cookie) {
        env_send(v, 13, v->cookie, 16, pkt.ts_ms, 48 + (size_t)npf_rand_range(0, n - 48));
        return;
    }
    if (v->state == 0) {
        npf_noise_init(&v->hs, NPF_NOISE_XK, 0, v->prologue, strlen(v->prologue), v->id.dh_sk, NULL, NULL);
        if (npf_noise_read(&v->hs, pkt.body, 48, pl, sizeof pl) != 0)
            return;
        npf_random(v->idx, 4);
        v->idx[0] |= 1;
        if (npf_noise_write(&v->hs, v->idx, 4, m2, sizeof m2) != 52)
            return;
        v->state = 1;
        env_send(v, 12, m2, 52, pkt.ts_ms, 84 + (size_t)npf_rand_range(0, n - 84));
    }
}

static void m3_in(srv *v, const uint8_t *b, size_t n)
{
    npf_noise_hs copy = v->hs;          /* a failed message 3 keeps the half-open state */
    uint8_t pl[80];
    if (n < 68 || n > 132)
        v->m3_bad_len++;
    if (v->drop_m3 > 0) {
        v->drop_m3--;
        return;
    }
    if (npf_noise_read(&copy, b + 4, n - 4, pl, sizeof pl) < 0) {
        v->early++;
        return;
    }
    v->m3s++;
    memcpy(v->rs, npf_noise_remote_static(&copy), 32);
    npf_noise_split(&copy, NULL, NULL, v->k1, v->k2, v->hash);
    v->state = 2;
    if (v->busy) {                      /* not admitted: CLOSE "busy", forgotten */
        uint8_t pt[8] = {2, 0, 0, 'b', 'u', 's', 'y'};
        tr_send(v, pt, 7);
        v->state = 0;
        v->tx_ctr = 0;
    }
}

static void take(srv *v, int end, const uint8_t *d, size_t dl)
{
    if (!v->ra)
        v->ra = malloc(40000);
    memcpy(v->ra + v->ra_len, d, dl);
    v->ra_len += dl;
    if (end) {
            if (!v->ra_len)
                v->pings++;
            else if (v->nmsg < 512) {
                char *id;
                if (v->fd >= 0 && v->ra_len < 4000 && (v->ra[v->ra_len] = 0, strstr((char *)v->ra, "\"type\":\"login\""))
                    && (id = strstr((char *)v->ra, "\"id\":\"r")) != NULL) {
                    char w[128];
                    snprintf(w, sizeof w, "{\"v\":1,\"type\":\"login\",\"reply_to\":\"r%d\",\"status\":\"ok\",\"data\":{\"server_id\":1}}",
                             atoi(id + 7));
                    if (v->late_welcome) {
                        v->late_welcome = 0;
                        snprintf(v->late, sizeof v->late, "%s", w);
                    } else
                        msg_to(v, w);
                    v->logins++;
                    if (v->on_login)
                        v->on_login(v->on_login_arg);
                }
                if (!v->nmsg)
                    snprintf(v->first, sizeof v->first, "%.*s", (int)v->ra_len, v->ra);
                v->msg_len[v->nmsg] = v->ra_len;
                v->msg_sum[v->nmsg++] = sum_of(v->ra, v->ra_len);
            }
            v->ra_len = 0;
    }
}

static void seg_in(srv *v, const uint8_t *pt, size_t n)
{
    uint16_t sn = npf_rd16(pt + 3), off = (uint16_t)(sn - v->rcv_nxt);
    int k;
    v->segs_in++;
    if (off && off < 32 && !v->ooo[k = sn % 64]) {
        v->ooo[k] = malloc(n - 5 + 1);
        memcpy(v->ooo[k], pt + 5, n - 5);
        v->ooo_len[k] = n - 5;
        v->ooo_end[k] = pt[0] & 1;
    } else if (!off) {
        v->rcv_nxt++;
        take(v, pt[0] & 1, pt + 5, n - 5);
        while (v->ooo[k = v->rcv_nxt % 64]) {
            v->rcv_nxt++;
            take(v, v->ooo_end[k], v->ooo[k], v->ooo_len[k]);
            free(v->ooo[k]);
            v->ooo[k] = NULL;
        }
    }
    if (!v->no_ack)
        ack_send(v);
}

/* from: real sockets, the sender (the peer follows the newest authenticated packet) */
static void srv_in(srv *v, const uint8_t *b, size_t n, const struct sockaddr_storage *from)
{
    uint8_t pt[1300], nonce[12] = {0};
    uint64_t ctr;
    if (v->state >= 1 && n >= 4 && memcmp(b, v->idx, 4) == 0) {
        if (v->state == 1) {
            m3_in(v, b, n);
            if (from && v->state == 2)
                memcpy(&v->peer, from, sizeof v->peer);
            return;
        }
        if (n < 4 + 8 + 16 + 3 || n > 1200)
            return;
        ctr = npf_rd64(b + 4);
        memcpy(nonce + 4, b + 4, 8);
        if (npf_aead_open(v->k1, nonce, b, 12, b + 12, n - 12, pt) < 0) {
            v->tr_bad++;                /* message 3 again, say */
            return;
        }
        if (!v->rx_any || ctr > v->rx_max) {
            v->rx_max = ctr, v->rx_any = 1;
            if (from)
                memcpy(&v->peer, from, sizeof v->peer);     /* roaming */
        }
        n -= 12 + 16;
        if (pt[0] == 2) {
            v->closes++;
            snprintf(v->close_reason, sizeof v->close_reason, "%.*s", (int)n - 3, pt + 3);
        } else if (n >= 5)
            seg_in(v, pt, n);
        else
            v->acks_in++;
        return;
    }
    if (from)
        memcpy(&v->peer, from, sizeof v->peer);
    hello_in(v, b, n);
}

/* the client's datagrams to the responder, each lost with probability loss_pct */
static void pump(srv *v, int loss_pct)
{
    int i, k = nq;
    static dgram tmp[512];
    memcpy(tmp, q, sizeof q[0] * (size_t)k);
    nq = 0;
    for (i = 0; i < k; i++)
        if ((int)npf_rand_range(0, 99) >= loss_pct)
            srv_in(v, tmp[i].b, tmp[i].n, NULL);
}

#define RUN(loop, v, loss, cond, ms) do { \
    int64_t until_ = npf_mono_ms() + (ms); \
    while (!(cond) && npf_mono_ms() < until_) { \
        pump((v), (loss)); \
        npf_loop_once((loop), 2); \
    } \
} while (0)

static npf_identity cid;

static npf_sig *open_cli(npf_loop *loop, srv *v, npf_sig_cookie *ck)
{
    ready = downs = msgs = 0;
    down_why[0] = 0;
    nq = 0;
    return cli = npf_sig_open_udp(loop, cb_send, &v->addr, v->id.dh_pub, &cid, ck, &cbs, &cli);
}

static void close_cli(void)
{
    npf_sig_close(cli);
    cli = NULL;
}

/* ---- the tests ---- */

static void t_handshake(npf_loop *loop)
{
    srv v = {0};
    char d[200];
    srv_init(&v, 1);
    REQUIRE_V(open_cli(loop, &v, NULL));
    EXPECT(nq == 1 && q[0].n >= 160 && q[0].n <= 256);
    EXPECT(strcmp(npf_sig_via(cli), "udp") == 0);
    EXPECT(npf_sig_send(cli, "{}", 2) < 0);         /* not before the handshake */
    pump(&v, 0);
    EXPECT(ready == 1);
    EXPECT(npf_sig_send(cli, "{\"type\":\"login\"}", 16) == 0);
    pump(&v, 0);                        /* message 3, then the login */
    CHECK(v.state == 2 && v.m3s == 1 && !v.m3_bad_len, "message 3 read (%d %d)", v.state, v.m3s);
    EXPECT(memcmp(v.rs, cid.dh_pub, 32) == 0);
    EXPECT(memcmp(v.hash, npf_sig_hash(cli), 64) == 0);
    EXPECT(v.nmsg == 1 && strcmp(v.first, "{\"type\":\"login\"}") == 0);
    EXPECT(v.pad_zero == 0);
    msg_to(&v, "{\"type\":\"welcome\"}");
    EXPECT(msgs == 1 && strcmp(last_msg, "{\"type\":\"welcome\"}") == 0);
    EXPECT(npf_sig_last_rx(cli) > 0 && npf_sig_rtt(cli) > 0);
    pump(&v, 0);                        /* the client's ack of the welcome */
    EXPECT(v.acks_in == 1);
    npf_sig_diag(cli, d, sizeof d);
    CHECK(strncmp(d, "udp: in flight 0, queued 0", 26) == 0, "diag: %s", d);
    close_cli();
    pump(&v, 0);
    CHECK(v.closes == 1 && strcmp(v.close_reason, "closed") == 0, "CLOSE on close (%s)", v.close_reason);
    {   /* the WebSocket's prologue at the server: its answer does not authenticate */
        srv w = {0};
        srv_init(&w, 1);
        w.prologue = "npf-ws-v1";
        REQUIRE_V(open_cli(loop, &w, NULL));
        pump(&w, 0);
        EXPECT(ready == 0 && w.state == 0 && nq == 0);   /* the server cannot read message 1 */
        close_cli();
        srv_free(&w);
    }
    srv_free(&v);
}

static void t_cookie(npf_loop *loop)
{
    srv v = {0};
    npf_sig_cookie ck;
    memset(&ck, 0, sizeof ck);
    srv_init(&v, 2);
    v.need_cookie = 1;
    npf_random(v.cookie, 16);
    REQUIRE_V(open_cli(loop, &v, &ck));
    pump(&v, 0);                        /* SIG_COOKIE back, the hello again at once */
    EXPECT(nq == 1);
    pump(&v, 0);
    EXPECT(ready == 1 && v.hello_mac_ok == 1);
    EXPECT(ck.until > npf_mono_ms() && memcmp(ck.c, v.cookie, 16) == 0 && npf_addr_eq(&ck.to, &v.addr));
    close_cli();
    /* the next attempt carries it from its first hello */
    srv_init(&v, 2);
    v.need_cookie = 1;
    memcpy(v.cookie, ck.c, 16);
    REQUIRE_V(open_cli(loop, &v, &ck));
    pump(&v, 0);
    EXPECT(ready == 1 && v.hellos == 1 && v.hello_mac_ok == 1);
    close_cli();
    srv_free(&v);
}

static void t_txid(npf_loop *loop)
{
    srv v = {0};
    uint8_t m2[64], pl[8];
    srv_init(&v, 3);
    REQUIRE_V(open_cli(loop, &v, NULL));
    /* a valid answer, but to another txid; a cookie likewise; flags not 0 */
    npf_noise_init(&v.hs, NPF_NOISE_XK, 0, PROLOGUE, sizeof PROLOGUE - 1, v.id.dh_sk, NULL, NULL);
    {
        uint8_t plain[300];
        npf_pkt pkt;
        REQUIRE_V(npf_pkt_open(&v.hk, NPF_DIR_REQ, q[0].b, q[0].n, plain, &pkt) == 0);
        REQUIRE_V(npf_noise_read(&v.hs, pkt.body, 48, pl, sizeof pl) == 0);
        memcpy(v.txid, pkt.txid, sizeof v.txid);
    }
    REQUIRE_V(npf_noise_write(&v.hs, (const uint8_t *)"abcd", 4, m2, sizeof m2) == 52);
    v.txid[0] ^= 1;
    env_send(&v, 12, m2, 52, 0, 100);
    env_send(&v, 13, v.cookie, 16, 0, 100);
    EXPECT(ready == 0 && nq == 1 && npf_sig_last_rx(cli) == 0);
    v.txid[0] ^= 1;
    env_raw(&v, 12, 1, m2, 52, 0, 100);   /* flags not 0 */
    env_raw(&v, 12, 0, m2, 51, 0, 100);   /* body_len not 52 */
    EXPECT(ready == 0);
    env_send(&v, 12, m2, 52, 0, 100);   /* this attempt's: taken */
    EXPECT(ready == 1);
    close_cli();
    srv_free(&v);
}

/* message 3 lost: the login reaches the half-open state first and is
 * dropped; message 3 again on the RTO, then the login again */
static void t_m3_lost(npf_loop *loop)
{
    srv v = {0};
    srv_init(&v, 4);
    v.drop_m3 = 1;
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    REQUIRE_V(ready == 1);
    npf_sig_send(cli, "{\"type\":\"login\"}", 16);
    pump(&v, 0);
    EXPECT(v.state == 1 && v.early == 1);
    RUN(loop, &v, 0, v.nmsg == 1, 3000);
    EXPECT(v.state == 2 && v.nmsg == 1);
    /* the server's first transport packet (the ack) ends message 3 */
    {
        int bad;
        RUN(loop, &v, 0, 0, 300);       /* a message 3 sent before the ack came, perhaps */
        bad = v.tr_bad;
        RUN(loop, &v, 0, 0, 1500);
        CHECK(v.tr_bad == bad, "message 3 still sent (%d, %d)", bad, v.tr_bad);
    }
    close_cli();
    srv_free(&v);
}

static void t_reliable(npf_loop *loop)
{
    srv v = {0};
    static char big[32768];
    size_t len[24];
    uint32_t sum[24];
    int i, n = 24, ok = 1;
    srv_init(&v, 5);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    for (i = 0; i < n; i++) {
        size_t l = i == 7 ? sizeof big : i == 15 ? 5000 : 10 + (size_t)npf_rand_range(0, 1150);
        npf_random(big, l);
        len[i] = l;
        sum[i] = sum_of((uint8_t *)big, l);
        EXPECT(npf_sig_send(cli, big, l) == 0);
    }
    EXPECT(npf_sig_send(cli, big, sizeof big + 1) < 0);
    /* 20 % lost each way (the acks: the client's input is the responder's output) */
    v.loss_out = 20;
    RUN(loop, &v, 20, v.nmsg == n, 30000);
    v.loss_out = 0;
    CHECK(v.nmsg == n, "%d of %d messages (%s)", v.nmsg, n, down_why);
    for (i = 0; i < v.nmsg && i < n; i++)
        ok &= v.msg_len[i] == len[i] && v.msg_sum[i] == sum[i];
    EXPECT(ok);
    RUN(loop, &v, 0, 0, 1200);          /* the last acks again */
    {
        char d[200];
        npf_sig_diag(cli, d, sizeof d);
        CHECK(strncmp(d, "udp: in flight 0, queued 0", 26) == 0, "all acked: %s", d);
    }
    /* the other way: out of order, again, and beyond the window */
    msgs = 0;
    seg_to(&v, 1, 2, "{\"m\":2}", 7);
    seg_to(&v, 1, 1, "{\"m\":1}", 7);
    seg_to(&v, 1, 40, "{\"m\":40}", 8);   /* beyond 32: dropped */
    seg_to(&v, 1, 1, "{\"m\":1}", 7);
    EXPECT(msgs == 0);
    seg_to(&v, 1, 0, "{\"m\":0}", 7);
    EXPECT(msgs == 3 && strcmp(last_msg, "{\"m\":2}") == 0);
    seg_to(&v, 1, 0, "{\"m\":0}", 7);  /* again: acked, not delivered */
    EXPECT(msgs == 3);
    /* a message of three segments, its middle last */
    seg_to(&v, 0, 3, "{\"a\":", 5);
    seg_to(&v, 1, 5, "}", 1);
    seg_to(&v, 0, 4, "\"xyz\"", 5);
    EXPECT(msgs == 4 && strcmp(last_msg, "{\"a\":\"xyz\"}") == 0);
    /* the acks it sent: the last one says 6 */
    {
        int i2;
        uint16_t a = 0;
        for (i2 = 0; i2 < nq; i2++) {
            uint8_t pt[1300], nonce[12] = {0};
            memcpy(nonce + 4, q[i2].b + 4, 8);
            if (npf_aead_open(v.k1, nonce, q[i2].b, 12, q[i2].b + 12, q[i2].n - 12, pt) == 0)
                a = npf_rd16(pt + 1);
        }
        CHECK(a == 6, "ack %u", a);
    }
    nq = 0;
    close_cli();
    srv_free(&v);
}

/* after an RTO, partial acks: each the next hole at once (NewReno), not
 * an RTO each; the recovery over once all sent before the RTO is acked */
static void t_partial(npf_loop *loop)
{
    srv v = {0};
    int i;
    int64_t t0;
    srv_init(&v, 7);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    pump(&v, 0);                        /* message 3 */
    ack_send(&v);                       /* the server's first transport packet: up */
    for (i = 0; i < 3; i++)
        npf_sig_send(cli, "{\"x\":1}", 7);
    nq = 0;                             /* all three lost */
    t0 = npf_mono_ms();
    while (nq == 0 && npf_mono_ms() - t0 < 2000)
        npf_loop_once(loop, 5);
    CHECK(nq == 1, "after the RTO: %d datagrams", nq);  /* the oldest */
    t0 = npf_mono_ms();
    for (i = 0; i < 3 && nq; i++)
        pump(&v, 0);                    /* its ack: the next one at once, and again */
    CHECK(v.nmsg == 3 && nq == 0 && npf_mono_ms() - t0 < 50, "%d messages, %d left", v.nmsg, nq);
    npf_sig_send(cli, "{\"x\":2}", 7);
    npf_sig_send(cli, "{\"x\":3}", 7);
    v.no_ack = 1;
    pump(&v, 0);
    v.no_ack = 0;
    ack_send(&v);                       /* covers both; then one alone: no resend without an RTO */
    EXPECT(nq == 0 && v.nmsg == 5);
    close_cli();
    srv_free(&v);
}

static void t_ping(npf_loop *loop)
{
    srv v = {0};
    int64_t rx;
    srv_init(&v, 6);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    v.no_ack = 1;
    npf_sig_send(cli, "{\"x\":1}", 7);
    pump(&v, 0);
    EXPECT(npf_sig_ping(cli) == 0 && nq == 0);   /* in flight: no other segment */
    v.no_ack = 0;
    ack_send(&v);
    EXPECT(npf_sig_ping(cli) == 0 && nq == 1);   /* an empty segment */
    rx = npf_sig_last_rx(cli);
    RUN(loop, &v, 0, npf_sig_last_rx(cli) > rx, 100);
    pump(&v, 0);
    EXPECT(v.pings == 1);
    /* the server's empty segment (its RTT sample): acked, not delivered */
    msgs = 0;
    seg_to(&v, 1, v.snd_sn++, "", 0);
    EXPECT(msgs == 0 && nq == 1);
    close_cli();
    srv_free(&v);
}

static void t_close(npf_loop *loop)
{
    srv v = {0};
    uint8_t pt[64];
    srv_init(&v, 7);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    npf_sig_send(cli, "{}", 2);
    pump(&v, 0);
    /* malformed: CLOSE with END, a reason over 32 bytes, 4 bytes, unknown flags, a pure ack with flags */
    pt[0] = 3; npf_le16(pt + 1, 0); memcpy(pt + 3, "x", 1);
    tr_send(&v, pt, 4);
    pt[0] = 2; memset(pt + 3, 'a', 33);
    tr_send(&v, pt, 36);
    pt[0] = 1;
    tr_send(&v, pt, 4);
    pt[0] = 4; npf_le16(pt + 3, v.snd_sn);
    tr_send(&v, pt, 5);
    pt[0] = 1;
    tr_send(&v, pt, 3);
    EXPECT(downs == 0 && cli);
    pt[0] = 2; memcpy(pt + 3, "shutdown", 8);
    tr_send(&v, pt, 11);
    EXPECT(downs == 1 && strcmp(down_why, "closed: shutdown") == 0 && !cli);
    pump(&v, 0);
    EXPECT(v.closes == 0);              /* no CLOSE back */
    /* a CLOSE with no reason */
    srv_init(&v, 7);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    npf_sig_send(cli, "{}", 2);
    pump(&v, 0);
    pt[0] = 2; npf_le16(pt + 1, 0);
    tr_send(&v, pt, 3);
    EXPECT(downs == 1 && strcmp(down_why, "closed: ") == 0 && !cli);
    srv_free(&v);
}

static void t_replay(npf_loop *loop)
{
    srv v = {0};
    uint8_t keep[3][1300];
    size_t kn[3];
    int i;
    struct sockaddr_storage other;
    srv_init(&v, 8);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    npf_sig_send(cli, "{}", 2);
    pump(&v, 0);
    /* three packets made, the second given first: in the window, taken */
    for (i = 0; i < 3; i++) {
        uint8_t pt[64], nonce[12] = {0};
        int l = snprintf((char *)pt + 5, 40, "{\"r\":%d}", i);
        pt[0] = 1;
        npf_le16(pt + 1, v.rcv_nxt);
        npf_le16(pt + 3, (uint16_t)(v.snd_sn + i));
        npf_le64(keep[i], v.tx_ctr++);
        memcpy(nonce + 4, keep[i], 8);
        npf_aead_seal(v.k2, nonce, keep[i], 8, pt, 5 + (size_t)l, keep[i] + 8);
        kn[i] = 8 + 5 + (size_t)l + 16;
    }
    v.snd_sn += 3;
    msgs = 0;
    srv_out(&v, keep[1], kn[1]);
    srv_out(&v, keep[0], kn[0]);
    srv_out(&v, keep[2], kn[2]);
    EXPECT(msgs == 3);
    {
        int64_t rx = npf_sig_last_rx(cli);
        nq = 0;
        srv_out(&v, keep[1], kn[1]);    /* again: dropped before the reliable layer (no ack) */
        EXPECT(msgs == 3 && nq == 0 && npf_sig_last_rx(cli) == rx);
    }
    /* 70 packets later the first is outside the window */
    for (i = 0; i < 70; i++)
        ack_send(&v);
    nq = 0;
    {
        uint8_t pt[8] = {0}, w[64], nonce[12] = {0};
        npf_le16(pt + 1, v.rcv_nxt);
        npf_le64(w, v.tx_ctr - 66);     /* never sent, but too old */
        memcpy(nonce + 4, w, 8);
        npf_aead_seal(v.k2, nonce, w, 8, pt, 3, w + 8);
        srv_out(&v, w, 27);
        EXPECT(nq == 0);
    }
    /* from another address: not this session's */
    memset(&other, 0, sizeof other);
    memcpy(&other, &v.addr, sizeof v.addr);
    ((struct sockaddr_in *)&other)->sin_port = htons(9941);
    EXPECT(npf_sig_input(cli, &other, keep[2], kn[2]) == 0);
    /* garbage from the server's address: taken, nothing happens */
    {
        uint8_t junk[100];
        struct sockaddr_storage from;
        memset(&from, 0, sizeof from);
        memcpy(&from, &v.addr, sizeof v.addr);
        npf_random(junk, sizeof junk);
        EXPECT(npf_sig_input(cli, &from, junk, sizeof junk) == 1);
    }
    EXPECT(msgs == 3 && downs == 0);
    close_cli();
    srv_free(&v);
}

static void t_limits(npf_loop *loop)
{
    srv v = {0};
    static char big[1200];
    int i;
    srv_init(&v, 9);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    pump(&v, 0);                        /* message 3 */
    /* the server's message over 32768 bytes: CLOSE "protocol" */
    memset(big, ' ', sizeof big);
    seg_to(&v, 0, v.snd_sn++, "{", 1);
    for (i = 0; i < 30 && cli; i++)
        seg_to(&v, 0, v.snd_sn++, big, 1167);
    EXPECT(downs == 1 && strstr(down_why, "too large") && !cli);
    pump(&v, 0);
    EXPECT(v.closes == 1 && strcmp(v.close_reason, "protocol") == 0);
    /* 256 messages waiting: the 257th closes the session (from the loop) */
    srv_init(&v, 9);
    REQUIRE_V(open_cli(loop, &v, NULL));
    pump(&v, 0);
    v.no_ack = 1;
    for (i = 0; i < 256; i++)
        npf_sig_send(cli, "{}", 2);
    EXPECT(npf_sig_send(cli, "{}", 2) < 0 && downs == 0);
    RUN(loop, &v, 0, downs, 500);
    EXPECT(downs == 1 && strstr(down_why, "queue full"));
    srv_free(&v);
}

/* the hellos at 0, 0.5, 1.5 and 3.5 s, then no answer at 7.5 s */
static void t_no_answer(npf_loop *loop)
{
    srv v = {0};
    int64_t t0 = npf_mono_ms();
    srv_init(&v, 10);
    REQUIRE_V(open_cli(loop, &v, NULL));
    LOOP_UNTIL(loop, nq == 2, 1000);
    CHECK(nq == 2 && npf_mono_ms() - t0 >= 450, "the second hello at 0.5 s");
    LOOP_UNTIL(loop, nq == 4, 4000);
    CHECK(nq == 4 && npf_mono_ms() - t0 >= 3400, "the fourth at 3.5 s");
    LOOP_UNTIL(loop, downs, 5000);
    CHECK(downs == 1 && strcmp(down_why, "udp: no answer") == 0 && npf_mono_ms() - t0 >= 7400, "no answer: %s",
          down_why);
    EXPECT(nq == 4);
    {   /* the txid stayed, each hello's length its own */
        uint8_t p0[300], p3[300];
        npf_pkt a, b;
        npf_pkt_open(&v.hk, NPF_DIR_REQ, q[0].b, q[0].n, p0, &a);
        npf_pkt_open(&v.hk, NPF_DIR_REQ, q[3].b, q[3].n, p3, &b);
        EXPECT(memcmp(a.txid, b.txid, NPF_TXID_SIZE) == 0 && memcmp(a.body, b.body, 48) == 0);
    }
    srv_free(&v);
}

/* real sockets: the client's socket replaced (another source port), the
 * responder follows the newest authenticated packet (as the server roams) */
static void roam_poll(npf_loop *loop, srv *v, int fa, int fb)
{
    struct pollfd p[3] = {{v->fd, POLLIN, 0}, {fa, POLLIN, 0}, {fb, POLLIN, 0}};
    int k;
    npf_loop_once(loop, 0);
    if (poll(p, 3, 5) <= 0)
        return;
    for (k = 0; k < 3; k++) {
        uint8_t b[1500];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t n;
        while ((p[k].revents & POLLIN) && (n = recvfrom(p[k].fd, b, sizeof b, 0, (struct sockaddr *)&from, &fl)) > 0) {
            fl = sizeof from;
            if (k == 0) {
                srv_in(v, b, (size_t)n, &from);
            } else {
                npf_sig_input(cli, &from, b, (size_t)n);
            }
        }
    }
}

static void t_roam(npf_loop *loop)
{
    srv v = {0};
    struct sockaddr_in ca, cb2;
    int fa, fb, i;
    srv_init(&v, 11);
    REQUIRE_V((v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr)) >= 0);
    REQUIRE_V((fa = lo_socket(SOCK_DGRAM, 0, &ca, sizeof ca)) >= 0);
    REQUIRE_V((fb = lo_socket(SOCK_DGRAM, 0, &cb2, sizeof cb2)) >= 0);
    real_fd = fa;
    REQUIRE_V(open_cli(loop, &v, NULL));
    for (i = 0; i < 400 && !ready; i++)
        roam_poll(loop, &v, fa, fb);
    npf_sig_send(cli, "{\"a\":1}", 7);
    for (i = 0; i < 400 && v.nmsg < 1; i++)
        roam_poll(loop, &v, fa, fb);
    EXPECT(v.peer.sin_port == ca.sin_port);
    real_fd = fb;                       /* another socket: another source port */
    npf_sig_send(cli, "{\"b\":2}", 7);
    for (i = 0; i < 400 && v.nmsg < 2; i++)
        roam_poll(loop, &v, fa, fb);
    CHECK(v.nmsg == 2 && v.peer.sin_port == cb2.sin_port, "%d messages, peer %u (a %u, b %u)", v.nmsg,
          ntohs(v.peer.sin_port), ntohs(ca.sin_port), ntohs(cb2.sin_port));
    msg_to(&v, "{\"one\":1}");          /* to the new port, and in */
    for (i = 0; i < 400 && msgs < 1; i++)
        roam_poll(loop, &v, fa, fb);
    EXPECT(msgs == 1 && strcmp(last_msg, "{\"one\":1}") == 0);
    real_fd = -1;
    close_cli();
    close(fa);
    close(fb);
    close(v.fd);
    srv_free(&v);
}

/* ---- the node (node_signal.c, signaling-udp.md 5.3): UDP to the responder
 * above, the WebSocket to a small ws:// server here (Noise_XK, "npf-ws-v1") ---- */

typedef struct wsrv {
    int lfd, fd;
    struct sockaddr_in addr;
    const npf_identity *id;
    uint8_t in[70000];
    size_t inl;
    int up, conns, logins, closing;
    npf_noise_hs hs;
    npf_noise_cs tx, rx;
} wsrv;

static void ws_frame(wsrv *w, int op, const uint8_t *p, size_t n)
{
    uint8_t h[4] = {(uint8_t)(0x80 | op)};
    size_t hl = 2;
    if (n < 126)
        h[1] = (uint8_t)n;
    else {
        h[1] = 126;
        h[2] = (uint8_t)(n >> 8);
        h[3] = (uint8_t)n;
        hl = 4;
    }
    if (send(w->fd, h, hl, MSG_NOSIGNAL) < 0 || send(w->fd, p, n, MSG_NOSIGNAL) < 0)
        return;
}

static void ws_json(wsrv *w, const char *json)
{
    uint8_t c[600];
    int n = npf_noise_encrypt(&w->tx, NULL, 0, (const uint8_t *)json, strlen(json), c);
    if (n > 0)
        ws_frame(w, 2, c, (size_t)n);
}

static void ws_drop(wsrv *w)
{
    if (w->fd >= 0)
        close(w->fd);
    w->fd = -1;
    w->inl = 0;
    w->up = 0;
    w->closing = 0;
}

static void ws_msg_in(wsrv *w, const uint8_t *p, size_t n)
{
    uint8_t out[128], pl[4100];
    int k;
    if (w->up == 1) {                   /* message 1 */
        npf_noise_init(&w->hs, NPF_NOISE_XK, 0, "npf-ws-v1", 9, w->id->dh_sk, NULL, NULL);
        if (npf_noise_read(&w->hs, p, n, pl, sizeof pl) < 0 || (k = npf_noise_write(&w->hs, NULL, 0, out, sizeof out)) < 0)
            return ws_drop(w);
        ws_frame(w, 2, out, (size_t)k);
        w->up = 2;
    } else if (w->up == 2) {            /* message 3 */
        if (npf_noise_read(&w->hs, p, n, pl, sizeof pl) < 0)
            return ws_drop(w);
        npf_noise_split(&w->hs, &w->tx, &w->rx, NULL, NULL, NULL);
        w->up = 3;
    } else if (n <= sizeof pl && (k = npf_noise_decrypt(&w->rx, NULL, 0, p, n, pl)) >= 0) {
        char *id, r[128];
        pl[k] = 0;
        if (strstr((char *)pl, "\"type\":\"login\"") && (id = strstr((char *)pl, "\"id\":\"r")) != NULL) {
            snprintf(r, sizeof r, "{\"v\":1,\"type\":\"login\",\"reply_to\":\"r%d\",\"status\":\"ok\",\"data\":{\"server_id\":1}}",
                     atoi(id + 7));
            ws_json(w, r);
            w->logins++;
        }
    }
}

static void ws_poll(wsrv *w)
{
    ssize_t r;
    if (w->fd < 0 && (w->fd = accept(w->lfd, NULL, NULL)) >= 0) {
        fcntl(w->fd, F_SETFL, O_NONBLOCK);
        w->conns++;
        w->up = 0;
    }
    if (w->fd < 0)
        return;
    while ((r = recv(w->fd, w->in + w->inl, sizeof w->in - w->inl, 0)) > 0)
        w->inl += (size_t)r;
    if (r == 0)
        return ws_drop(w);
    if (!w->up) {
        char *e, *k, acc[64], kg[128], rsp[256];
        uint8_t dg[20];
        w->in[w->inl < sizeof w->in ? w->inl : sizeof w->in - 1] = 0;
        if (!(e = strstr((char *)w->in, "\r\n\r\n")) || !(k = strstr((char *)w->in, "Sec-WebSocket-Key: ")))
            return;
        snprintf(kg, sizeof kg, "%.24s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", k + 19);
        npf_sha1(dg, kg, strlen(kg));
        npf_b64std_encode(dg, 20, acc);
        snprintf(rsp, sizeof rsp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
        if (send(w->fd, rsp, strlen(rsp), MSG_NOSIGNAL) < 0)
            return ws_drop(w);
        w->inl -= (size_t)(e + 4 - (char *)w->in);
        memmove(w->in, e + 4, w->inl);
        w->up = 1;
    }
    for (;;) {                          /* the client's frames: masked */
        size_t hl = 2, n, i;
        uint8_t *m;
        if (w->inl < 2)
            return;
        n = w->in[1] & 0x7f;
        if (n == 126) {
            if (w->inl < 4)
                return;
            n = (size_t)w->in[2] << 8 | w->in[3];
            hl = 4;
        }
        if (w->inl < hl + 4 + n)
            return;
        m = w->in + hl;
        for (i = 0; i < n; i++)
            m[4 + i] ^= m[i % 4];
        if ((w->in[0] & 0x0f) == 2)
            ws_msg_in(w, m + 4, n);
        else if ((w->in[0] & 0x0f) == 9)
            ws_frame(w, 10, m + 4, n);  /* pong */
        if (w->fd < 0)
            return;
        w->inl -= hl + 4 + n;
        memmove(w->in, w->in + hl + 4 + n, w->inl);
    }
}

/* the UDP login came while the WebSocket is up: the platform replaces it */
static void replace_ws(void *arg)
{
    wsrv *w = arg;
    if (w->fd >= 0 && w->up == 3) {
        ws_json(w, "{\"v\":1,\"type\":\"replaced\",\"data\":{}}");
        w->closing = 1;
    }
}

static void udp_poll(srv *v)
{
    uint8_t b[1500];
    struct sockaddr_storage from;
    socklen_t fl = sizeof from;
    ssize_t n;
    while ((n = recvfrom(v->fd, b, sizeof b, 0, (struct sockaddr *)&from, &fl)) > 0) {
        fl = sizeof from;
        if (!v->silent)
            srv_in(v, b, (size_t)n, &from);
    }
}

#define NODE_UNTIL(cond, ms) do { \
    int64_t until_ = npf_mono_ms() + (ms); \
    while (!(cond) && npf_mono_ms() < until_) { \
        npf_loop_once(loop, 5); \
        udp_poll(&v); \
        ws_poll(&w); \
        if (w.closing && ++w.closing > 40) ws_drop(&w);   /* closed some 200 ms after "replaced" */ \
        if (v.late[0] && w.fd < 0) { msg_to(&v, v.late); v.late[0] = 0; }   /* after the close */ \
    } \
} while (0)

static int node_up(npf_node *n, npf_loop *loop, srv *v, wsrv *w, char *url, size_t ul)
{
    npf_node_cfg cfg;
    npf_identity id;
    uint8_t seed[32];
    memset(&cfg, 0, sizeof cfg);
    snprintf(url, ul, "ws://127.0.0.1:%u/s", ntohs(w->addr.sin_port));
    cfg.server_url = url;
    memcpy(cfg.server_pub, v->id.dh_pub, 32);
    cfg.no_host_report = 1;
    cfg.no_portmap = 1;
    npf_random(seed, sizeof seed);
    npf_identity_from_seed(&id, seed);
    if (npf_node_init(n, loop, &cfg, &id, NULL, NULL) < 0)
        return -1;
    npf_identity_wipe(&id);
    n->servers[0].udp[0] = v->addr;     /* the list's "udp" */
    n->servers[0].nudp = 1;
    n->th.sig_udp_again_ms = 600;
    npf_node_start(n);
    return 0;
}

static void t_node(npf_loop *loop)
{
    static npf_node node;
    static srv v;
    static wsrv w;
    npf_node *n = &node;
    npf_log_ctx lc, *old;
    char url[64];
    memset(&w, 0, sizeof w);
    srv_init(&v, 12);
    REQUIRE_V((v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr)) >= 0);
    REQUIRE_V((w.lfd = lo_socket(SOCK_STREAM, 4, &w.addr, sizeof w.addr)) >= 0);
    w.fd = -1;
    w.id = &v.id;
    v.on_login = replace_ws;
    v.on_login_arg = &w;
    old = log_capture(&lc);

    /* UDP answers: over UDP within the second, no WebSocket */
    log_clear();
    REQUIRE_V(node_up(n, loop, &v, &w, url, sizeof url) == 0);
    NODE_UNTIL(n->online, 3000);
    CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0, "online over udp (%s)", logged);
    EXPECT(w.conns == 0 && strcmp(npf_node_udp_sig(n), "ok") == 0 && npf_sig_rtt(n->sig) > 0);
    EXPECT(count_of(logged, "signaling: connecting to server 0 udp 127.0.0.1:") == 1);
    EXPECT(count_of(logged, "over udp (handshake") == 1);
    NODE_UNTIL(0, 700);                 /* no move from UDP */
    EXPECT(!n->sig_move && w.conns == 0);
    npf_node_stop(n);
    NODE_UNTIL(v.closes, 500);
    EXPECT(v.closes == 1);

    /* a call's UDP path went silent (path_udp.c, path_direct.c): a ping;
     * answered, UDP stays; unanswered (the node's UDP cut, natlab udp-lost)
     * the WebSocket 3 s later at once (not UDP first), udp_bad */
    srv_init(&v, 12);
    v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr);
    log_clear();
    REQUIRE_V(node_up(n, loop, &v, &w, url, sizeof url) == 0);
    NODE_UNTIL(n->online, 3000);
    node_sig_udp_check(n);
    NODE_UNTIL(0, 3500);
    CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0 && w.conns == 0 && !n->udp_bad,
          "path silent, udp answers: stays (%s)", logged);
    v.silent = 1;
    {
        int64_t t0 = npf_mono_ms();
        node_sig_udp_check(n);
        NODE_UNTIL(n->online && n->sig && strcmp(npf_sig_via(n->sig), "ws") == 0, 5000);
        CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "ws") == 0 && n->udp_bad
              && npf_mono_ms() - t0 >= 2900 && npf_mono_ms() - t0 < 3800, "path silent, no udp: ws after %lld ms (%s)",
              (long long)(npf_mono_ms() - t0), logged);
    }
    EXPECT(count_of(logged, "pinging the server over udp") == 2 && count_of(logged, "no answer over udp either") == 1);
    EXPECT(count_of(logged, "signaling: connecting to server 0 udp") == 1);   /* not UDP again first */
    npf_node_stop(n);
    ws_drop(&w);
    close(v.fd);

    /* UDP silent: the WebSocket after a second, udp_bad; then UDP answers
     * and the idle node moves to it, the WebSocket replaced */
    srv_init(&v, 12);
    v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr);
    v.on_login = replace_ws;
    v.on_login_arg = &w;
    v.silent = 1;
    log_clear();
    REQUIRE_V(node_up(n, loop, &v, &w, url, sizeof url) == 0);
    {
        int64_t t0 = npf_mono_ms();
        NODE_UNTIL(n->online, 4000);
        CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "ws") == 0 && npf_mono_ms() - t0 >= 900,
              "online over ws after 1 s (%s)", logged);
    }
    EXPECT(n->udp_bad == 1 && strcmp(npf_node_udp_sig(n), "no_answer") == 0);
    EXPECT(count_of(logged, "over ws (udp: no answer)") == 1);
    EXPECT(count_of(logged, "udp did not answer, using ws") == 1);
    v.silent = 0;
    NODE_UNTIL(n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0 && !n->sig_old, 4000);
    CHECK(n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0, "moved to udp (%s)", logged);
    EXPECT(!n->sig_old && n->online && n->logins == 1 && n->udp_bad == 0 && n->replaced_ms == 0);
    EXPECT(count_of(logged, "signaling: moving to udp") == 1 && count_of(logged, "on udp, ws closed") == 1);
    EXPECT(count_of(logged, "logged in elsewhere") == 0);
    npf_node_stop(n);
    ws_drop(&w);
    close(v.fd);

    /* the same move with the welcome late (lost, sent again): the server's
     * close of the WebSocket it replaced comes first. The move all the
     * same: no drop, one login (before: "disconnected (connection closed),
     * the udp session goes on" and a second login; natlab sig-loss20,
     * 2026-10-30) */
    srv_init(&v, 12);
    v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr);
    v.on_login = replace_ws;
    v.on_login_arg = &w;
    v.silent = 1;
    log_clear();
    REQUIRE_V(node_up(n, loop, &v, &w, url, sizeof url) == 0);
    NODE_UNTIL(n->online, 4000);
    CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "ws") == 0, "late welcome: on ws first (%s)", logged);
    v.silent = 0;
    v.late_welcome = 1;
    NODE_UNTIL(v.logins == 1 && !v.late[0] && n->move_taken == 0 && n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0, 4000);
    CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "udp") == 0 && !n->sig_move && n->move_taken == 0,
          "late welcome: moved to udp (%s)", logged);
    EXPECT(n->logins == 1 && n->udp_bad == 0 && n->replaced_ms == 0);
    EXPECT(count_of(logged, "ws closed after the move, the udp welcome on its way") == 1);
    EXPECT(count_of(logged, "the udp session goes on") == 0 && count_of(logged, "signaling: disconnected") == 0);
    npf_node_stop(n);
    ws_drop(&w);
    close(v.fd);

    /* the server too busy for the session: CLOSE "busy", the WebSocket now, udp_bad */
    srv_init(&v, 12);
    v.fd = lo_socket(SOCK_DGRAM, 0, &v.addr, sizeof v.addr);
    v.busy = 1;
    log_clear();
    REQUIRE_V(node_up(n, loop, &v, &w, url, sizeof url) == 0);
    NODE_UNTIL(n->online, 4000);
    CHECK(n->online && n->sig && strcmp(npf_sig_via(n->sig), "ws") == 0 && n->udp_bad == 1, "busy (hellos %d m3s %d early %d): %s", v.hellos, v.m3s, v.early, logged);
    EXPECT(count_of(logged, "busy over udp, using ws") == 1 && v.m3s == 1);
    npf_node_stop(n);
    ws_drop(&w);

    npf_log_ctx_swap(old);
    close(v.fd);
    close(w.lfd);
    srv_free(&v);
}

int test_sigudp(void)
{
    npf_loop *loop = npf_loop_new();
    uint8_t seed[32] = {42};
    if (!loop)
        return 1;
    npf_identity_from_seed(&cid, seed);
    t_handshake(loop);
    t_cookie(loop);
    t_txid(loop);
    t_m3_lost(loop);
    t_reliable(loop);
    t_partial(loop);
    t_ping(loop);
    t_close(loop);
    t_replay(loop);
    t_limits(loop);
    t_roam(loop);
    t_node(loop);
    t_no_answer(loop);
    if (cli)
        close_cli();
    npf_identity_wipe(&cid);
    npf_loop_free(loop);
    return fails;
}

#else
int test_sigudp(void)
{
    return 0;                           /* NPF_SIG_UDP off */
}
#endif

/* The UDP signaling session's input (npf_sig_input, src/proto/sigudp.c) in
 * each state: a session in its handshake given raw datagrams or authentic
 * envelopes (any type, flags, body) with its txid; an established one (a
 * responder on libnpf's Noise made it) given raw datagrams or authentic
 * transport packets carrying the input as plaintext, at counters the input
 * picks (replays, reordering, the window's edges). input[0] picks the mode. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/bind.h"
#include "npf/crypto.h"
#include "npf/loop.h"
#include "npf/noise.h"
#include "npf/platform.h"
#include "npf/sig.h"
#include "npf/siv.h"

void npf_fuzz_sigudp(const uint8_t *d, size_t n);

#ifdef NPF_SIG_UDP

static uint8_t sent[4][300];            /* the client's first datagrams */
static size_t sent_len[4];
static int nsent;

static int fz_send(const void *p, size_t len, const struct sockaddr_in *to, void *arg)
{
    (void)to, (void)arg;
    if (nsent < 4 && len <= sizeof sent[0]) {
        memcpy(sent[nsent], p, len);
        sent_len[nsent] = len;
    }
    nsent++;
    return (int)len;
}

static void fz_ready(npf_sig *s, void *arg) { (void)s, (void)arg; }
static void fz_msg(npf_sig *s, const npf_json *j, void *arg) { (void)s, (void)j, (void)arg; }
static void fz_down(npf_sig *s, npf_sig_down code, const char *why, void *arg)
{
    (void)s, (void)code, (void)why;
    *(npf_sig **)arg = NULL;
}

static npf_loop *loop;
static npf_identity srv_id, cli_id;
static struct sockaddr_storage from;
static npf_siv_keys hk;

static void deliver(npf_sig **s, const uint8_t *p, size_t len)
{
    if (*s)
        npf_sig_input(*s, &from, p, len);
}

/* the rest as datagrams: a length byte, then that many */
static void raw(npf_sig **s, const uint8_t *d, size_t n)
{
    while (n && *s) {
        size_t l = d[0] < n - 1 ? d[0] : n - 1;
        deliver(s, d + 1, l);
        d += 1 + l;
        n -= 1 + l;
    }
}

/* an envelope with the attempt's txid: type, flags, body length, body */
static void envelope(npf_sig **s, const uint8_t *d, size_t n)
{
    uint8_t plain[300], w[300], *p = w + NPF_SIV_TAG_SIZE;
    npf_pkt pkt;
    size_t bl, wl;
    if (n < 3 || npf_pkt_open(&hk, NPF_DIR_REQ, sent[0], sent_len[0], plain, &pkt) < 0)
        return;
    memset(w, 0, sizeof w);
    p[0] = (uint8_t)(11 + d[0] % 4);
    p[1] = d[1] & 0x80 ? d[1] : 0;
    bl = n - 3 < 200 ? n - 3 : 200;
    npf_le16(p + 2, d[2] & 0x80 ? d[2] : (uint16_t)bl);
    memcpy(p + 4, pkt.txid, NPF_TXID_SIZE);
    memcpy(p + NPF_PKT_HDR_SIZE, d + 3, bl);
    wl = NPF_SIV_TAG_SIZE + NPF_PKT_HDR_SIZE + bl + (d[0] >> 4);
    npf_siv_seal(&hk, NPF_DIR_RESP, w, wl - NPF_SIV_TAG_SIZE);
    deliver(s, w, wl);
}

/* the handshake to the end with a responder: its keys in k2 (server -> node) */
static int establish(npf_sig **s, uint8_t k2[32])
{
    static const char pro[] = "npf-sigudp-v1";
    npf_noise_hs hs;
    uint8_t plain[300], m2[64], pl[80], w[300], idx[4] = {1, 2, 3, 4};
    npf_pkt pkt;
    int r = -1, n;
    if (npf_pkt_open(&hk, NPF_DIR_REQ, sent[0], sent_len[0], plain, &pkt) < 0)
        return -1;
    npf_noise_init(&hs, NPF_NOISE_XK, 0, pro, sizeof pro - 1, srv_id.dh_sk, NULL, NULL);
    if (npf_noise_read(&hs, pkt.body, 48, pl, sizeof pl) == 0 && npf_noise_write(&hs, idx, 4, m2, sizeof m2) == 52
        && (n = npf_pkt_seal(&hk, NPF_DIR_RESP, 12, pkt.txid, pkt.ts_ms, m2, 52, 100, w)) > 0) {
        nsent = 0;
        deliver(s, w, (size_t)n);       /* message 3 out */
        if (*s && nsent >= 1 && npf_noise_read(&hs, sent[0] + 4, sent_len[0] - 4, pl, sizeof pl) >= 0
            && npf_noise_split(&hs, NULL, NULL, NULL, k2, NULL) == 0)
            r = 0;
    }
    npf_wipe(&hs, sizeof hs);
    return r;
}

/* transport packets: ctr step (signed), length, then a plaintext as it is
 * (its first byte with the high bit) or a segment made from a control byte
 * (flags = c & 3, ack = c >> 2 & 7, sn = c >> 5 & 3) and its data */
static void transport(npf_sig **s, const uint8_t *k2, const uint8_t *d, size_t n)
{
    uint64_t ctr = 100;
    while (n >= 3 && *s) {
        uint8_t w[1300], pt[1200], nonce[12] = {0};
        size_t l = d[1] < n - 2 ? d[1] : n - 2, pl;
        const uint8_t *c = d + 2;
        ctr += (uint64_t)(int64_t)(int8_t)d[0];
        if (d[0] == 0x7f)
            l = n - 2 < 1180 ? n - 2 : 1180;     /* a long one */
        if (!l)
            l = 1;                      /* the control byte at least (n >= 3) */
        if (c[0] & 0x80) {
            memcpy(pt, c + 1, pl = l - 1);
        } else {
            pt[0] = c[0] & 3;
            npf_le16(pt + 1, c[0] >> 2 & 7);
            npf_le16(pt + 3, c[0] >> 5 & 3);
            pl = 5 + (l - 1 < sizeof pt - 5 ? l - 1 : sizeof pt - 5);
            memcpy(pt + 5, c + 1, pl - 5);
        }
        npf_le64(w, ctr);
        memcpy(nonce + 4, w, 8);
        npf_aead_seal(k2, nonce, w, 8, pt, pl, w + 8);
        deliver(s, w, 8 + pl + 16);
        d += 2 + l;
        n -= 2 + l;
    }
}

void npf_fuzz_sigudp(const uint8_t *d, size_t n)
{
    static const npf_sig_cbs cbs = {fz_ready, fz_msg, fz_down};
    struct sockaddr_in srv;
    npf_sig *s;
    uint8_t k2[32];
    int i;
    if (!loop) {
        uint8_t seed[32] = {7};
        loop = npf_loop_new();
        npf_identity_from_seed(&srv_id, seed);
        seed[0] = 8;
        npf_identity_from_seed(&cli_id, seed);
        npf_siv_derive(&hk, srv_id.dh_pub, "NPF-SIGHS-v1");
    }
    if (!loop || n < 1)
        return;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(0x7f000001);
    srv.sin_port = htons(9940);
    memset(&from, 0, sizeof from);
    memcpy(&from, &srv, sizeof srv);
    nsent = 0;
    s = npf_sig_open_udp(loop, fz_send, &srv, srv_id.dh_pub, &cli_id, NULL, &cbs, &s);
    if (!s)
        return;
    switch (d[0] % 4) {
    case 0: raw(&s, d + 1, n - 1); break;
    case 1: envelope(&s, d + 1, n - 1); break;
    default:
        if (establish(&s, k2) == 0) {
            if (d[0] % 4 == 2)
                transport(&s, k2, d + 1, n - 1);
            else
                raw(&s, d + 1, n - 1);
        }
        break;
    }
    for (i = 0; i < 3 && s; i++) {
        if (npf_sig_send(s, "{\"type\":\"x\"}", 12) == 0)
            npf_sig_ping(s);
        npf_loop_once(loop, 0);
    }
    npf_sig_close(s);
    npf_wipe(k2, sizeof k2);
}

#else
void npf_fuzz_sigudp(const uint8_t *d, size_t n)
{
    (void)d, (void)n;
}
#endif

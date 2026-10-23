/* Calls: the WS relay transport, records sealed for the relay */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* ---- WS relay (data-channel.md 10.2) ----
 *   k_ws[dir] = BLAKE2b-256(key = k1 | k2, "npf ws tunnel v1" | dir | salt), dir "a2b" (caller -> callee) / "b2a"
 *   RECORD    = ChaCha20-Poly1305(k_ws[dir], nonce = 0(4) | LE64(counter), frames) */

static void ws_key(npf_call *c, const char *dir, const uint8_t salt[16], uint8_t out[32])
{
    uint8_t msg[16 + 3 + 16];
    memcpy(msg, "npf ws tunnel v1", 16);
    memcpy(msg + 16, dir, 3);
    memcpy(msg + 19, salt, 16);
    npf_kdf(out, c->k12, 64, msg, sizeof msg);
}

static void ws_nonce(uint8_t n[12], uint64_t ctr)
{
    memset(n, 0, 4);
    npf_le64(n + 4, ctr);
}

void call_ws_flush_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_wsflush = NULL;
    while (c->ws_out_len && c->wsr && c->ws_tx_ready) {
        size_t n = c->ws_out_len > 65536 ? 65536 : c->ws_out_len;
        uint8_t *rec = malloc(n + 16), nonce[12];
        if (!rec)
            return;
        ws_nonce(nonce, c->ws_ctr_tx++);
        if (npf_aead_seal(c->ws_ktx, nonce, NULL, 0, c->ws_out, n, rec) < 0
            || npf_wsr_send(c->wsr, NPF_WSR_RECORD, rec, n + 16) < 0) {
            free(rec);
            npf_call_end(c, "transport_lost");
            return;
        }
        free(rec);
        memmove(c->ws_out, c->ws_out + n, c->ws_out_len - n);
        c->ws_out_len -= n;
    }
    if (c->tun)
        npf_tunnel_kick(c->tun);
}

/* a new round: reset the transport's sublinks and counters */
static void ws_reset(npf_call *c)
{
    if (c->tun)
        npf_tunnel_free(c->tun);
    npf_media_free(c->media);
    c->media = NULL;
    npf_udpf_free(c->udp);
    c->udp = NULL;
    c->tun = call_tunnel_new(c);
    c->ws_out_len = 0;
    c->ws_in_len = 0;
    c->ws_ctr_tx = c->ws_ctr_rx = 0;
    c->ws_tx_ready = c->ws_rx_ready = 0;
}

static void ws_send_start(npf_call *c, const char *dir)
{
    uint8_t salt[16];
    npf_random(salt, 16);
    ws_key(c, dir, salt, c->ws_ktx);
    npf_wsr_send(c->wsr, NPF_WSR_START, salt, 16);
    c->ws_tx_ready = 1;
}

void call_wsr_paired(npf_wsr *r, void *arg)
{
    npf_call *c = arg;
    (void)r;
    c->ws_paired_once = 1;
    npf_log("call %s: WS relay paired", c->call_id_s);
    if (!c->caller || !c->keys_ready)
        return;
    ws_reset(c);
    ws_send_start(c, "a2b");    /* only the caller starts a round (10.2) */
}

void call_wsr_start(npf_wsr *r, const uint8_t salt[16], void *arg)
{
    npf_call *c = arg;
    int i;
    (void)r;
    if (!c->keys_ready) {
        memcpy(c->ws_pending_salt, salt, 16);
        c->ws_has_pending = 1;
        return;
    }
    for (i = 0; i < c->ws_nsalts; i++)
        if (memcmp(c->ws_salts[i], salt, 16) == 0) {
            npf_log("call %s: repeated WS relay salt, ignored", c->call_id_s);
            return;
        }
    if (c->ws_nsalts < 8)
        memcpy(c->ws_salts[c->ws_nsalts++], salt, 16);
    else
        memcpy(c->ws_salts[i % 8], salt, 16);
    if (c->caller) {
        ws_key(c, "b2a", salt, c->ws_krx);
        c->ws_rx_ready = 1;
        return;                 /* now wait for the callee's hello */
    }
    ws_reset(c);
    ws_key(c, "a2b", salt, c->ws_krx);
    c->ws_rx_ready = 1;
    ws_send_start(c, "b2a");
    npf_tunnel_start(c->tun);
}

/* records -> channel units -> the tunnel's control / data input */
static void ws_demux(npf_call *c, const uint8_t *p, size_t len)
{
    size_t off = 0;
    if (c->ws_in_len + len > c->ws_in_cap) {
        size_t cap = c->ws_in_cap ? c->ws_in_cap : 65536;
        uint8_t *q;
        while (cap < c->ws_in_len + len)
            cap *= 2;
        if (!(q = realloc(c->ws_in, cap)))
            return;
        c->ws_in = q;
        c->ws_in_cap = cap;
    }
    memcpy(c->ws_in + c->ws_in_len, p, len);
    c->ws_in_len += len;
    while (c->ws_in_len - off >= 3) {
        const uint8_t *u = c->ws_in + off;
        size_t n = npf_rd16(u + 1);
        int r = 0;
        if (c->ws_in_len - off < 3 + n)
            break;
        if (u[0] == 2) {
            npf_media *m = call_media_of(c);
            if (m)
                npf_media_ws_input(m, u + 3, n);
            if (c->ended)
                return;
        } else if (u[0] == 3) {
            npf_udpf *uf = call_udp_of(c);
            if (uf)
                npf_udpf_ws_input(uf, u + 3, n);
        } else if (c->tun) {
            r = u[0] == 0 ? npf_tunnel_input_ctrl(c->tun, u + 3, n) : u[0] == 1 ? npf_tunnel_input_data(c->tun, u + 3, n) : 0;
        }
        if (r < 0)
            return;                         /* broken: the call is ending */
        off += 3 + n;
    }
    memmove(c->ws_in, c->ws_in + off, c->ws_in_len - off);
    c->ws_in_len -= off;
}

static void wsr_record(npf_wsr *r, const uint8_t *rec, size_t len, void *arg)
{
    npf_call *c = arg;
    uint8_t nonce[12], *plain;
    (void)r;
    if (!c->ws_rx_ready || len < 16 || len > 65536 + 16)
        return;
    plain = malloc(len);
    if (!plain)
        return;
    ws_nonce(nonce, c->ws_ctr_rx);
    if (npf_aead_open(c->ws_krx, nonce, NULL, 0, rec, len, plain) < 0) {
        free(plain);
        npf_logw("call %s: WS relay record failed authentication", c->call_id_s);
        npf_call_end(c, "transport_lost");
        return;
    }
    c->ws_ctr_rx++;
    c->rx_bytes += len - 16;
    ws_demux(c, plain, len - 16);
    free(plain);
}

/* The WS relay failed. Before it ever worked: the caller asks for a relay on
 * its own server (the platform's servers share the work), the callee waits for that;
 * afterwards the transport is lost. */
void call_ws_failed(npf_call *c, const char *why)
{
    char data[128];
    npf_log("call %s: WS relay %s", c->call_id_s, why);
    if (c->ended)
        return;
    if (c->ws_paired_once) {
        npf_call_end(c, "transport_lost");
        return;
    }
    if (c->caller && !c->relay_asked) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"unreachable\":true}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        c->relay_asked = 1;
        npf_log("call %s: relay unreachable, asking for one on our own server", c->call_id_s);
    }
}

static void wsr_gone(npf_wsr *r, const char *why, void *arg)
{
    npf_call *c = arg;
    if (!r)
        c->wsr = NULL;          /* already freed */
    call_ws_failed(c, why);
}

static void wsr_drained(npf_wsr *r, void *arg)
{
    npf_call *c = arg;
    (void)r;
    if (c->ws_out_len && !c->t_wsflush)
        c->t_wsflush = npf_timer_add(c->n->loop, 0, call_ws_flush_timer, c);
    if (c->tun)
        npf_tunnel_kick(c->tun);
}

static const npf_wsr_cbs wsr_cbs = {call_wsr_paired, call_wsr_start, wsr_record, wsr_gone, wsr_drained};

int call_ws_setup(npf_call *c, const npf_json *j, int r)
{
    int w = npf_json_get(j, r, "ws"), i;
    int64_t sid = 0;
    char url[256];
    const uint8_t *pub = NULL;
    if (w < 0 || npf_json_get_str(j, w, "url", url, sizeof url) <= 0)
        return -1;
    npf_json_get_int(j, w, "server_id", 0, 1 << 30, &sid);
    for (i = 0; i < c->n->nlist; i++)
        if (c->n->list[i].id == sid)
            pub = c->n->list[i].dh_pub;
    if (!pub && c->n->cfg.server_url && sid == c->n->server_id)
        pub = c->n->cfg.server_pub;
    if (!pub) {
        npf_logw("call %s: WS relay server %lld not in the server list", c->call_id_s, (long long)sid);
        return -1;
    }
    /* drop the AnLiu transport: the WS relay carries the sublinks itself */
    if (c->tun) {
        npf_tunnel_free(c->tun);
        c->tun = NULL;
    }
    npf_udpf_free(c->udp);
    c->udp = NULL;
    if (c->anl) {
        call_conv_unlink(c);
        anl_release(c->anl);
        c->anl = NULL;
        c->stream = NULL;
        call_dpend_free(c);
    }
    c->ws_mode = 1;
    c->relay.active = 0;
    if (c->wsr)
        npf_wsr_close(c->wsr);
    c->wsr = NULL;
    if (call_relay_blocked(url))
        return -1;
    c->wsr = npf_wsr_open(c->n->loop, url, pub, &c->n->id, c->relay.relay_id, &wsr_cbs, c);
    if (!c->wsr)
        return -1;
    npf_log("call %s: WS relay %s", c->call_id_s, url);
    return 0;
}

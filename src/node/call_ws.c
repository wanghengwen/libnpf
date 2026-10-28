/* Calls: the WS relay as a carrier of the session's AnLiu connection
 * (data-channel.md 10). Each AnLiu datagram is one ANL message on the relay
 * connection; moving to the WS relay and back to UDP switches the
 * connection's carrier (ANL_OPT_CARRIER) and keeps everything on it: the
 * sublinks, media streams and UDP flows. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* datagrams are dropped above this in the connection's queue: AnLiu's
 * windows bound what it has in flight, this only bounds the memory when the
 * TCP connection stalls (AnLiu sends them again) */
#define WS_QUEUE_MAX     (8u << 20)
#define WS_RECONNECT_MS  2000       /* the connection lost after pairing: the same allocation again */

static void ws_flush_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_wsflush = NULL;
    if (c->wsr)
        npf_wsr_flush(c->wsr);
}

/* AnLiu's output on the WS relay: queued, written once this turn of the
 * loop is over (one write and TLS record for what a flush sends, not one
 * per datagram). Nothing goes before both sides are bound (AnLiu sends it
 * again) */
void call_ws_send(npf_call *c, const uint8_t *d, size_t len)
{
    if (!c->wsr || npf_wsr_pending(c->wsr) > WS_QUEUE_MAX || npf_wsr_queue(c->wsr, d, len) < 0)
        return;
    if (!c->t_wsflush)
        c->t_wsflush = npf_timer_add(c->n->loop, 0, ws_flush_timer, c);
}

/* the WS relay carries the session now (paired, the AnLiu connection made):
 * a stream carrier (no fast retransmission, no FEC parity), set from this
 * side's own carrier alone, also when the relay hands the datagrams on to
 * the peer's UDP allocation (the user's choice, 2026-10-28: a loss on that
 * leg is then resent after the timeout, at least 1 s); AnLiu starts its path
 * model again and sends what is unacknowledged once */
void call_ws_carrier(npf_call *c)
{
    if (!c->ws_mode || !c->anl || !c->wsr || !npf_wsr_paired(c->wsr) || c->ended)
        return;
    anl_set_option(c->anl, ANL_OPT_CARRIER, ANL_CARRIER_STREAM);
    call_path_up(c);
}

static void wsr_paired(npf_wsr *r, int peer_udp, void *arg)
{
    npf_call *c = arg;
    (void)r;
    c->ws_paired_once = 1;
    npf_log("call %s: WS relay paired%s", c->call_id_s, peer_udp ? " (the peer on a UDP allocation)" : "");
    call_ws_carrier(c);
}

static void wsr_datagram(npf_wsr *r, const uint8_t *d, size_t len, void *arg)
{
    npf_call *c = arg;
    (void)r;
    if (!c->ws_mode || c->ended)
        return;                 /* back on UDP: a late one of the old carrier */
    if (c->caller && !c->keys_ready) {
        call_relay_early_keep(c, d, len);   /* the callee's hello before the accept brought the keys */
        return;
    }
    call_anl_feed(c, d, len);
}

static int ws_open(npf_call *c);

static void ws_reconnect(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_wsre = NULL;
    if (!c->ws_mode || c->wsr || c->ended)
        return;
    npf_log("call %s: WS relay: connecting again", c->call_id_s);
    if (ws_open(c) < 0)
        c->t_wsre = npf_timer_add(c->n->loop, WS_RECONNECT_MS, ws_reconnect, c);
}

/* The WS relay failed. Before it ever worked: the caller asks for a relay on
 * its own server (the platform's servers share the work), the callee waits
 * for that. Afterwards it is a carrier lost: the session goes on (AnLiu
 * keeps its state and ends it at its idle timeout if nothing comes back),
 * the same allocation is connected again, and the platform may move the
 * session meanwhile (relay_switch). */
void call_ws_failed(npf_call *c, const char *why)
{
    char data[128];
    npf_log("call %s: WS relay %s", c->call_id_s, why);
    if (c->ended || !c->ws_mode)
        return;
    if (c->ws_paired_once) {
        if (!c->wsr && !c->t_wsre)
            c->t_wsre = npf_timer_add(c->n->loop, WS_RECONNECT_MS, ws_reconnect, c);
        return;
    }
    if (c->caller && c->state == NPF_CALL_CALLING) {
        /* connected from the reply to the call: the platform takes no
         * relay_switch before the accept (call_caller_accepted asks then) */
        c->ws_fail_wait = 1;
        return;
    }
    if (c->caller && call_relay_ask_ok(c)) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"unreachable\":true}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        call_relay_asked(c);
        npf_log("call %s: relay unreachable, asking for one on our own server", c->call_id_s);
    }
}

static void wsr_gone(npf_wsr *r, const char *why, void *arg)
{
    npf_call *c = arg;
    if (r) {                    /* the peer's connection left: it comes back or the session moves */
        npf_log("call %s: WS relay: %s", c->call_id_s, why);
        return;
    }
    c->wsr = NULL;              /* already freed */
    npf_timer_stop(c->n->loop, &c->t_wsflush);
    call_ws_failed(c, why);
}

static const npf_wsr_cbs wsr_cbs = {wsr_paired, wsr_datagram, wsr_gone};

static int ws_open(npf_call *c)
{
    if (call_relay_blocked(c->n, c->ws_url))
        return -1;
    c->wsr = npf_wsr_open(c->n->loop, c->ws_url, c->ws_pub, &c->n->id, c->relay.relay_id, &wsr_cbs, c);
    return c->wsr ? 0 : -1;
}

/* the platform's WS relay allocation (relay_switch, call_relay_setup): the
 * AnLiu connection's datagrams go there from now on. The UDP paths go: the
 * UDP relay was released, and the direct path, if there was one, is given up
 * (the session moves because UDP does not work); punching comes back with
 * UDP (call_relay_setup) */
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
    if (!c->ws_mode && c->anl)
        npf_log("call %s: the session moves to the WS relay (its connections stay)", c->call_id_s);
    c->ws_mode = 1;
    c->ws_paired_once = 0;
    c->relay.active = 0;
    call_relay_leave(c);
    if (call_has_p2p(c))
        call_p2p_drop(c);
    call_ws_leave_conn(c);
    snprintf(c->ws_url, sizeof c->ws_url, "%s", url);
    memcpy(c->ws_pub, pub, 32);
    if (ws_open(c) < 0)
        return -1;
    npf_log("call %s: WS relay %s", c->call_id_s, url);
    return 0;
}

/* the relay connection closed, its timers stopped (the carrier stays) */
void call_ws_leave_conn(npf_call *c)
{
    npf_timer_stop(c->n->loop, &c->t_wsflush);
    npf_timer_stop(c->n->loop, &c->t_wsre);
    if (c->wsr)
        npf_wsr_close(c->wsr);
    c->wsr = NULL;
}

/* back to UDP (a UDP relay allocation): the AnLiu connection's carrier is a
 * datagram one again, the relay connection goes */
void call_ws_leave(npf_call *c)
{
    if (!c->ws_mode)
        return;
    npf_log("call %s: the session leaves the WS relay for UDP (its connections stay)", c->call_id_s);
    c->ws_mode = 0;
    c->ws_paired_once = 0;
    call_ws_leave_conn(c);
    if (c->anl)
        anl_set_option(c->anl, ANL_OPT_CARRIER, ANL_CARRIER_DGRAM);
}

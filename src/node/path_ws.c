/* The WS relay (path.h) as a carrier of the session's AnLiu connection
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
#define WS_PAIR_MS       10000      /* a connection made again pairs by then, or it failed */
#define WS_RECONNECTS    5          /* connections made again in a row that did not pair: the relay given up */

static void ws_flush_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pw.t_flush = NULL;
    if (c->pw.wsr)
        npf_wsr_flush(c->pw.wsr);
}

/* AnLiu's output on the WS relay: queued, written once this turn of the
 * loop is over (one write and TLS record for what a flush sends, not one
 * per datagram). Nothing goes before both sides are bound (AnLiu sends it
 * again) */
void call_ws_send(npf_call *c, const uint8_t *d, size_t len)
{
    if (!c->pw.wsr || npf_wsr_pending(c->pw.wsr) > WS_QUEUE_MAX || npf_wsr_queue(c->pw.wsr, d, len) < 0)
        return;
    if (!c->pw.t_flush)
        c->pw.t_flush = npf_timer_add(c->n->loop, 0, ws_flush_timer, c);
}

static void ws_send(npf_path *p, const uint8_t *dgram, size_t len)
{
    call_ws_send(CALL_OF(p, pw.p), dgram, len);
}

static const char *ws_name(const npf_path *p)
{
    (void)p;
    return "ws relay";
}

static void ws_suspect(npf_path *p, int64_t quiet);

/* its probe is a new connection, its verdict WS_RECONNECTS of them that did
 * not pair (call_ws_failed) */
const npf_path_ops path_ws_ops = {ws_send, ws_name, ws_suspect, NULL, NULL};

/* the path's last_rx from the connection's frames (pm_check: not per
 * datagram, the connection keeps the time of its last frame) */
void path_ws_heard(npf_call *c)
{
    int64_t t = c->pw.wsr ? npf_wsr_last_rx(c->pw.wsr) : 0;
    if (t > c->pw.p.last_rx)
        c->pw.p.last_rx = t;
}

/* the WS relay carries the session now (paired, the AnLiu connection made):
 * a stream carrier (no fast retransmission, no FEC parity), set from this
 * side's own carrier alone, also when the relay hands the datagrams on to
 * the peer's UDP allocation (the user's choice, 2026-10-28: a loss on that
 * leg is then resent after the timeout, at least 1 s); AnLiu starts its path
 * model again and sends what is unacknowledged once */
void call_ws_carrier(npf_call *c)
{
    if (!call_has_ws(c) || !c->anl || !c->pw.wsr || !npf_wsr_paired(c->pw.wsr) || c->ended)
        return;
    anl_set_option(c->anl, ANL_OPT_CARRIER, ANL_CARRIER_STREAM);
    call_path_up(c);
}

static void wsr_paired(npf_wsr *r, int peer_udp, void *arg)
{
    npf_call *c = arg;
    int64_t now = npf_mono_ms();
    int again = c->pw.p.health == PH_SUSPECT;
    (void)r;
    c->pw.paired_once = 1;
    c->pw.fails = 0;
    npf_timer_stop(c->n->loop, &c->pw.t_re);    /* its pairing's deadline */
    c->pw.p.since = c->pw.p.last_rx = now;
    pm_rt(&c->pm, &c->pw.p, now);
    npf_log("call %s: WS relay paired%s%s", c->call_id_s, again ? " again" : "",
            peer_udp ? " (the peer on a UDP allocation)" : "");
    call_ws_carrier(c);
    pm_check(c);                                /* its silence counted from now */
}

static void wsr_datagram(npf_wsr *r, const uint8_t *d, size_t len, void *arg)
{
    npf_call *c = arg;
    (void)r;
    if (!call_has_ws(c) || c->ended)
        return;                 /* back on UDP: a late one of the old carrier */
    if (c->caller && !c->keys_ready) {
        call_relay_early_keep(c, d, len);   /* the callee's hello before the accept brought the keys */
        return;
    }
    call_anl_feed(c, d, len);
}

static int ws_open(npf_call *c);

/* a connection made again that has not paired by now: it failed */
static void ws_pair_late(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pw.t_re = NULL;
    if (!c->pw.wsr || npf_wsr_paired(c->pw.wsr))
        return;
    call_ws_leave_conn(c);
    call_ws_failed(c, "not paired again within 10 s");
}

static void ws_reconnect(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pw.t_re = NULL;
    if (!call_has_ws(c) || c->pw.wsr || c->ended || c->pw.p.health == PH_DEAD)
        return;
    npf_log("call %s: WS relay: connecting again", c->call_id_s);
    if (ws_open(c) < 0)
        call_ws_failed(c, "cannot connect");
    else
        c->pw.t_re = npf_timer_add(c->n->loop, WS_PAIR_MS, ws_pair_late, c);
}

/* nothing from the relay for 30 s (the health rules, pm_tick; its pong
 * every 25 s, the peer's keepalives): the TCP connection is half-open (a
 * NAT or a firewall on the way lost it without a word, the relay
 * restarted): closed, connected again at once. Before, the session waited
 * on TCP's own timeout, minutes, and AnLiu ended it after 60 s */
static void ws_suspect(npf_path *p, int64_t quiet)
{
    npf_call *c = CALL_OF(p, pw.p);
    npf_logw("call %s: nothing from the WS relay for %lld s: its connection is half-open", c->call_id_s,
             (long long)quiet / 1000);
    c->pw.fails = 0;
    call_ws_leave_conn(c);
    ws_reconnect(c->n->loop, c);
}

/* the relay cannot be reached before it ever worked, or given up after:
 * the caller asks for a relay on its own server (the platform's servers
 * share the work: relay_switch{unreachable}, architecture.md 2.4
 * PM_NEED_WS_ELSEWHERE), the callee waits for that */
static void ws_elsewhere(npf_call *c)
{
    char data[128];
    if (c->caller && c->state == NPF_CALL_CALLING) {
        /* connected from the reply to the call: the platform takes no
         * relay_switch before the accept (call_caller_accepted asks then) */
        c->pw.fail_wait = 1;
        return;
    }
    if (c->caller && call_relay_ask_ok(c)) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"unreachable\":true}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        call_relay_asked(c);
        npf_log("call %s: relay unreachable, asking for one on our own server", c->call_id_s);
    }
}

/* The WS relay failed. Before it ever worked: elsewhere (ws_elsewhere).
 * Afterwards it is a carrier lost (SUSPECT): the session goes on (AnLiu
 * keeps its state and ends it at its idle timeout if nothing comes back),
 * the same allocation is connected again every 2 s, and the platform may
 * move the session meanwhile (relay_switch); WS_RECONNECTS in a row that do
 * not pair (architecture.md Q5): the relay is DEAD, given up, elsewhere.
 * The requests' deadlines are the manager's (architecture.md 3.6, step 1c) */
void call_ws_failed(npf_call *c, const char *why)
{
    npf_log("call %s: WS relay %s", c->call_id_s, why);
    if (c->ended || !call_has_ws(c))
        return;
    if (c->pw.paired_once) {
        if (c->pw.p.health == PH_DEAD)
            return;
        if (c->pw.p.health != PH_SUSPECT) {
            pm_suspect(&c->pm, &c->pw.p, npf_mono_ms());
        } else if (++c->pw.fails >= WS_RECONNECTS) {
            npf_logw("call %s: WS relay: connected again %d times, never paired: giving it up", c->call_id_s,
                     c->pw.fails);
            pm_dead(&c->pm, &c->pw.p);
            call_ws_leave_conn(c);
            ws_elsewhere(c);
            if (!c->caller)
                npf_log("call %s: waiting for the platform to move the session (the caller asks)", c->call_id_s);
            return;
        }
        if (!c->pw.wsr && !c->pw.t_re)
            c->pw.t_re = npf_timer_add(c->n->loop, WS_RECONNECT_MS, ws_reconnect, c);
        return;
    }
    ws_elsewhere(c);
}

static void wsr_gone(npf_wsr *r, const char *why, void *arg)
{
    npf_call *c = arg;
    if (r) {                    /* the peer's connection left: it comes back or the session moves */
        npf_log("call %s: WS relay: %s", c->call_id_s, why);
        return;
    }
    c->pw.wsr = NULL;              /* already freed */
    npf_timer_stop(c->n->loop, &c->pw.t_flush);
    npf_timer_stop(c->n->loop, &c->pw.t_re);    /* its pairing's deadline */
    call_ws_failed(c, why);
}

static const npf_wsr_cbs wsr_cbs = {wsr_paired, wsr_datagram, wsr_gone};

static int ws_open(npf_call *c)
{
    if (call_relay_blocked(c->n, c->pw.url))
        return -1;
    c->pw.wsr = npf_wsr_open(c->n->loop, c->pw.url, c->pw.pub, &c->n->id, c->pu.r.relay_id, &wsr_cbs, c);
    c->pw.p.last_rx = npf_mono_ms();            /* its silence counts from now */
    return c->pw.wsr ? 0 : -1;
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
    if (!call_has_ws(c) && c->anl)
        npf_log("call %s: the session moves to the WS relay (its connections stay)", c->call_id_s);
    c->pw.p.health = PH_NEW;                    /* UP once paired */
    c->pw.fails = 0;
    pm_add(&c->pm, &c->pw.p);
    c->pw.paired_once = 0;
    path_udp_off(c);
    call_relay_leave(c);
    if (call_has_p2p(c))
        call_p2p_drop(c);
    call_ws_leave_conn(c);
    snprintf(c->pw.url, sizeof c->pw.url, "%s", url);
    memcpy(c->pw.pub, pub, 32);
    if (ws_open(c) < 0)
        return -1;
    npf_log("call %s: WS relay %s", c->call_id_s, url);
    return 0;
}

/* the relay connection closed, its timers stopped (the carrier stays) */
void call_ws_leave_conn(npf_call *c)
{
    npf_timer_stop(c->n->loop, &c->pw.t_flush);
    npf_timer_stop(c->n->loop, &c->pw.t_re);
    if (c->pw.wsr)
        npf_wsr_close(c->pw.wsr);
    c->pw.wsr = NULL;
}

/* back to UDP (a UDP relay allocation): the AnLiu connection's carrier is a
 * datagram one again, the relay connection goes */
void call_ws_leave(npf_call *c)
{
    if (!call_has_ws(c))
        return;
    npf_log("call %s: the session leaves the WS relay for UDP (its connections stay)", c->call_id_s);
    pm_del(&c->pm, &c->pw.p);
    c->pw.paired_once = 0;
    call_ws_leave_conn(c);
    if (c->anl)
        anl_set_option(c->anl, ANL_OPT_CARRIER, ANL_CARRIER_DGRAM);
}

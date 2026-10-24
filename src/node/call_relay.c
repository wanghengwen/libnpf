/* Calls: the UDP relay client (data-channel.md 9), binding and keeping its
 * allocation, and the way to the WS relay when it cannot be reached */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* ---- UDP relay client (data-channel.md 9) ---- */

/* RELAY_BIND: hint | sealed with alloc_key, body = the relay's cookie for
 * our address (zeros before the first BIND_ACK: the relay answers with a
 * challenge carrying it, and binds the address when a BIND echoes it) */
static void relay_bind_send(npf_call *c)
{
    uint8_t txid[NPF_TXID_SIZE], wire[256];
    size_t len = npf_rand_range(96, 200);
    int n;
    npf_random(txid, sizeof txid);
    memcpy(wire, c->relay.relay_id, RELAY_HINT_SIZE);
    n = npf_pkt_seal(&c->relay.keys, 0, PKT_RELAY_BIND, txid, (uint32_t)npf_node_time(c->n), c->relay.cookie,
                     RELAY_COOKIE_SIZE, len - RELAY_HINT_SIZE, wire + RELAY_HINT_SIZE);
    if (n > 0 && !call_relay_addr_blocked(c))
        call_udp_send(c, c->n->udp_fd, &c->relay.addr[c->relay.cur], wire, (size_t)n + RELAY_HINT_SIZE);
}

/* RELAY_DATA: hint | tag | type | flags | seq | the AnLiu datagram */
void call_relay_send_data(npf_call *c, const uint8_t *dgram, size_t len)
{
    uint8_t buf[2048];
    uint8_t *w = buf + RELAY_HINT_SIZE, *p = w + NPF_SIV_TAG_SIZE;
    if (len + RELAY_DATA_OVERHEAD > sizeof buf || call_relay_addr_blocked(c))
        return;
    memcpy(buf, c->relay.relay_id, RELAY_HINT_SIZE);
    p[0] = PKT_RELAY_DATA;
    p[1] = 0;
    npf_le32(p + 2, c->relay.seq++);
    memcpy(p + 6, dgram, len);
    npf_siv_seal(&c->relay.keys, 0, w, len + 6);
    call_udp_send(c, c->n->udp_fd, &c->relay.addr[c->relay.cur], buf, len + RELAY_DATA_OVERHEAD);
}
/* the WS relay for this call (relay_switch{mode:"ws"}); the platform moves both sides */
void call_ask_ws_relay(npf_call *c)
{
    char data[128];
    timer_stop(c->n->loop, &c->t_ws_wait);
    if (c->ws_mode)                 /* on it already: asking again reset its sublinks */
        return;
    npf_log("call %s: asking for the WS relay", c->call_id_s);
    snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"ws\"}", c->call_id_s);
    npf_node_send(c->n, "relay_switch", 0, data);
    c->relay_asked = 1;
}

static void ws_wait_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_ws_wait = NULL;
    c->relay_waits_ports = 0;
    if (!c->p2p && !c->relay.bound) {
        npf_log("call %s: no direct path within %d s", c->call_id_s, WS_WAIT_MS / 1000);
        call_ask_ws_relay(c);
    }
}

static void relay_bind_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->relay.t_bind = NULL;
    if (c->relay.bound) {
        /* refresh the binding (NAT mapping, server idle timer) while in use */
        if (c->relay.active) {
            relay_bind_send(c);
            c->relay.t_bind = npf_timer_add(c->n->loop, RELAY_KEEPALIVE_MS, relay_bind_timer, c);
        }
        return;
    }
    if (++c->relay.tries > RELAY_BIND_TRIES) {
        if (c->relay.cur + 1 < c->relay.naddr) {
            c->relay.cur++;
            c->relay.tries = 0;
        } else if (c->p2p) {
            /* in doubt (p2p_suspect): the verdict decides (lost: the WS
             * relay, check_p2p); a WS relay session cannot go direct again */
            npf_log("call %s: UDP relay unreachable; the direct path carries the session%s", c->call_id_s,
                    c->p2p_suspect ? " while it is checked" : "");
            return;
        } else if (!c->relay_ports_waited && call_hard_punches(c) > 0) {
            /* a hard-side punch holds hundreds of the NAT's ports: a carrier
             * NAT with a quota of them (the phone's APDM CGNAT, about 500) then
             * maps nothing new, the relay included. Measured: every relay bind
             * failed while two punches ran, the next one after them bound at
             * once. Again when they end (call_punch_sockets_back), WS_WAIT_MS at most */
            npf_log("call %s: UDP relay unreachable while a punch holds the NAT's ports: trying again when it ends",
                    c->call_id_s);
            c->relay_ports_waited = 1;
            c->relay_waits_ports = 1;
            if (!c->t_ws_wait)
                c->t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
            return;
        } else if (!c->punched && !call_no_p2p(c)) {
            /* a WS relay session cannot move to a direct path later (the
             * transport is replaced): let the first punch round decide.
             * Measured: a Linux node's UDP relay unreachable 2 s before the
             * punch plan arrived, the direct path up 6 s later, the session
             * stuck on the WS relay at 14 KB/s */
            npf_log("call %s: UDP relay unreachable; waiting for the punch before asking for the WS relay",
                    c->call_id_s);
            if (!c->t_ws_wait)
                c->t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
            return;
        } else {
            npf_log("call %s: UDP relay unreachable", c->call_id_s);
            call_ask_ws_relay(c);
            return;
        }
    }
    relay_bind_send(c);
    c->relay.t_bind = npf_timer_add(c->n->loop, 700, relay_bind_timer, c);
}

/* the UDP relay bound again from its first address (a BIND every 700 ms) */
void call_relay_rebind(npf_call *c)
{
    c->relay.tries = 0;
    c->relay.cur = 0;
    timer_stop(c->n->loop, &c->relay.t_bind);
    relay_bind_send(c);
    c->relay.t_bind = npf_timer_add(c->n->loop, 700, relay_bind_timer, c);
}

/* the binding refreshed every RELAY_KEEPALIVE_MS while the relay is in use */
static void relay_keepalive(npf_call *c)
{
    timer_stop(c->n->loop, &c->relay.t_bind);
    c->relay.t_bind = npf_timer_add(c->n->loop, RELAY_KEEPALIVE_MS, relay_bind_timer, c);
}


/* an allocation taken: the relay of the session from now on */
static void relay_take(npf_call *c, const uint8_t id[8], const uint8_t key[32], const char *mode)
{
    memcpy(c->relay.relay_id, id, 8);
    memcpy(c->relay.alloc_key, key, 32);
    memset(c->relay.cookie, 0, sizeof c->relay.cookie);     /* a cookie is the allocation's */
    snprintf(c->relay.mode, sizeof c->relay.mode, "%s", mode);
    c->relay_asked = 0;
    timer_stop(c->n->loop, &c->t_standby);
}

/* the platform's relay allocation; one that is no use leaves the relay in use
 * as it is (it used to take its id and key at once, then bind the old
 * addresses with them) */
void call_relay_setup(npf_call *c, const npf_json *j, int d)
{
    int r = npf_json_get(j, d, "relay"), arr, i, naddr = 0;
    char mode[8] = "";
    uint8_t id[8], key[32];
    struct sockaddr_storage addr[4];
    if (r < 0 || j->tok[r].type != NPF_JT_OBJECT)
        return;
    npf_json_get_str(j, r, "mode", mode, sizeof mode);
    if (npf_json_get_b64(j, r, "relay_id", id, 8) != 8 || npf_json_get_b64(j, r, "alloc_key", key, 32) != 32)
        return;
    if (strcmp(mode, "ws") == 0) {
        if (c->ws_mode && c->wsr && memcmp(id, c->relay.relay_id, 8) == 0)
            return;                 /* the one in use, sent again (both sides asked): its sublinks stay */
        relay_take(c, id, key, mode);
        if (call_ws_setup(c, j, r) < 0)
            call_ws_failed(c, "cannot connect");
        return;
    }
    if (strcmp(mode, "udp") != 0)
        return;
    arr = npf_json_get(j, r, "udp");
    for (i = 0; arr >= 0 && i < j->tok[arr].size && naddr < 4; i++) {
        char a[80];
        if (npf_json_str(j, npf_json_item(j, arr, i), a, sizeof a) > 0 && npf_addr_parse(a, &addr[naddr]) == 0
            && addr[naddr].ss_family == AF_INET)
            naddr++;
    }
    if (!naddr)
        return;
    relay_take(c, id, key, mode);
    memcpy(c->relay.addr, addr, (size_t)naddr * sizeof addr[0]);
    c->relay.naddr = naddr;
    npf_siv_derive(&c->relay.keys, c->relay.alloc_key, LABEL_RELAY);
    c->relay.active = 1;
    c->relay.bound = 0;
    call_relay_rebind(c);
}

int call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const void *)a, *y = (const void *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    return 0;
}

/* the relay works (a BIND_ACK, or the peer's data through it): bound, the
 * binding kept fresh from now on */
static void relay_bound(npf_call *c, const char *how)
{
    c->relay.bound = 1;
    c->relay_waits_ports = 0;
    if (c->t_ws_wait && !c->ws_mode) {     /* no WS relay needed after all */
        npf_timer_cancel(c->n->loop, c->t_ws_wait);
        c->t_ws_wait = NULL;
    }
    relay_keepalive(c);
    npf_log("call %s: UDP relay bound%s", c->call_id_s, how);
    call_path_up(c);
}

/* RELAY_BIND_ACK: body = family(1) | port(2) | addr(4/16) | srv_time_ms(8) |
 * state(1) | cookie(8). The cookie is kept for the next binds; a challenge
 * (the address is not ours on the relay yet, or no longer: a new NAT port)
 * is answered at once with a BIND echoing it, 200 ms apart at most */
static void relay_ack(npf_call *c, const uint8_t *plain, size_t pl)
{
    const uint8_t *b = plain + NPF_PKT_HDR_SIZE;
    size_t blen, alen;
    int64_t now;
    if (pl < NPF_PKT_HDR_SIZE)
        return;
    blen = (size_t)plain[2] | (size_t)plain[3] << 8;
    if (blen < 1 || NPF_PKT_HDR_SIZE + blen > pl)
        return;
    alen = b[0] == 4 ? 4 : b[0] == 6 ? 16 : 0;
    if (!alen || blen < 3 + alen + 8 + 1 + RELAY_COOKIE_SIZE)
        return;
    memcpy(c->relay.cookie, b + 3 + alen + 9, RELAY_COOKIE_SIZE);
    if (b[3 + alen + 8] == RELAY_ACK_BOUND) {
        /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that confirms
         * the binding (the challenges still come: without one nothing binds) */
        if (!c->relay.bound && !getenv("NPF_TEST_DROP_BIND_ACK"))
            relay_bound(c, "");
        return;
    }
    now = npf_mono_ms();
    if (c->relay.active && now - c->relay.echo_ms >= 200) {
        c->relay.echo_ms = now;
        relay_bind_send(c);
    }
}

/* returns 1 if consumed */
int call_relay_input(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    uint8_t plain[2048];
    int pl, i;
    /* a relay released here may still be in use by the peer: only the
     * caller releases the allocations on the server, and the peer may have
     * given up the direct path just after our standby ended (a path dead in
     * one direction looks fine from this side) */
    for (i = 0; i < c->relay.naddr && !call_same_addr(from, &c->relay.addr[i]); i++)
        ;
    if (i == c->relay.naddr || len > sizeof plain + NPF_SIV_TAG_SIZE)
        return 0;
    pl = npf_siv_open(&c->relay.keys, 1, buf, len, plain);
    if (pl < 6)
        return 0;
    /* an address tried earlier answered late (the binds moved on to the
     * next one): the one that works is the one to use */
    if (i != c->relay.cur && c->relay.active && !c->relay.bound)
        c->relay.cur = i;
    else if (i != c->relay.cur)
        return 1;
    if (plain[0] == PKT_RELAY_DATA) {
        /* AnLiu first: a relayed datagram proves nothing until it takes it
         * (the relay's keys are not the session's: a replay of an old one
         * with the relay's address would bring back a relay given up, on
         * the WS relay too) */
        if (call_anl_feed(c, plain + 6, (size_t)pl - 6) < 0 || c->ended)
            return 1;
        if (!c->relay.active) {     /* the peer sends on it: take it back, keep the binding fresh */
            npf_log("call %s: the peer uses the relay again, keeping it", c->call_id_s);
            c->relay.active = 1;
            c->relay.bound = 1;
            relay_bind_send(c);
            relay_keepalive(c);
        } else if (!c->relay.bound) {
            /* the relay forwards the peer's data to us: it has our binding,
             * whether or not its BIND_ACK came. Measured (a Mac <-> a Linux
             * node): data through the relay, no BIND_ACK in 2.1 s,
             * "unreachable", the move to the WS relay cut the forwarded
             * connection */
            relay_bound(c, " (the peer's data came through it)");
        }
        return 1;
    }
    if (plain[0] == PKT_RELAY_BIND_ACK)
        relay_ack(c, plain, (size_t)pl);
    return 1;
}
/* a round that did not go direct (failed, or none planned) while the UDP
 * relay was unreachable: the UDP relay once more, then the WS relay */
void call_ws_wait_end(npf_call *c, int ok)
{
    if (!c->t_ws_wait)
        return;
    npf_timer_cancel(c->n->loop, c->t_ws_wait);
    c->t_ws_wait = NULL;
    if (!ok && !c->relay.bound && c->relay.t_bind) {
        /* the UDP relay is being bound again (the punch gave the NAT's ports
         * back): its answer first; when it gives up, relay_bind_timer asks
         * for the WS relay (asked here at once, a bind about to succeed was
         * replaced: the phone's sessions, measured) */
        npf_log("call %s: the UDP relay is being bound: its answer before the WS relay", c->call_id_s);
        return;
    }
    if (!ok && !c->relay_retried && !c->relay.bound && !c->relay.t_bind) {
        /* once more first: a WS relay session cannot punch again later, and
         * the UDP relay may have been lost to a passing storm (the phone at a
         * start, five punches at once: its binds went unanswered for 5 s) */
        npf_log("call %s: trying the UDP relay once more before the WS relay", c->call_id_s);
        c->relay_retried = 1;
        call_relay_rebind(c);
    } else if (!ok) {
        call_ask_ws_relay(c);
    }
}

/* Calls: the UDP relay client (data-channel.md 9), binding and keeping its
 * allocation, and the way to the WS relay when it cannot be reached */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

/* ---- UDP relay client (data-channel.md 9) ---- */

/* RELAY_BIND (relay_bind.c): the relay's cookie for our address in it
 * (zeros before the first BIND_ACK: the relay answers with a challenge
 * carrying it, and binds the address when a BIND echoes it) */
static void relay_bind_send(void *arg)
{
    npf_call *c = arg;
    uint8_t wire[256];
    int n = relay_bind_pack(&c->relay, c->n, 0, 0, wire);
    if (n > 0 && !call_relay_addr_blocked(c))
        npf_udp_send(c->n->udp_fd, wire, (size_t)n, &c->relay.addr[c->relay.cur]);
}

/* RELAY_DATA (relay_data.c): a 16-byte header before the AnLiu datagram */
void call_relay_send_data(npf_call *c, const uint8_t *dgram, size_t len)
{
    uint8_t buf[2048];
    size_t n;
    if (call_relay_addr_blocked(c) || !(n = relay_data_pack(&c->relay, dgram, len, buf)))
        return;
    npf_udp_send(c->n->udp_fd, buf, n, &c->relay.addr[c->relay.cur]);
}
/* the WS relay for this call (relay_switch{mode:"ws"}); the platform moves both sides */
void call_ask_ws_relay(npf_call *c)
{
    char data[128];
    npf_timer_stop(c->n->loop, &c->t_ws_wait);
    if (c->ws_mode)                 /* on it already */
        return;
    npf_log("call %s: asking for the WS relay", c->call_id_s);
    snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"ws\"}", c->call_id_s);
    npf_node_send(c->n, "relay_switch", 0, data);
    call_relay_asked(c);
}

/* may a relay_switch go out: none is waiting for its allocation, or the last
 * one is RELAY_ASK_AGAIN_MS old. The platform drops some without a word (the
 * call not accepted yet, no token left, refused before the session is up, no
 * relay to give): a session asked once only never had a relay again */
int call_relay_ask_ok(const npf_call *c)
{
    return !c->relay_asked_ms || npf_mono_ms() - c->relay_asked_ms >= RELAY_ASK_AGAIN_MS;
}

void call_relay_asked(npf_call *c)
{
    int64_t now = npf_mono_ms();
    c->relay_asked_ms = now ? now : 1;
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

/* refresh the binding (NAT mapping, server idle timer) while in use */
static void relay_keepalive_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    c->relay.t_bind = NULL;
    if (c->relay.bound && c->relay.active) {
        relay_bind_send(c);
        c->relay.t_bind = npf_timer_add(loop, RELAY_KEEPALIVE_MS, relay_keepalive_timer, c);
    }
}

/* every address of the relay tried (relay_bind_run) */
static void relay_gave_up(void *arg)
{
    npf_call *c = arg;
    if (c->caller && c->state == NPF_CALL_CALLING) {
        /* bound from the reply to the call, before the callee accepted:
         * the platform takes no relay_switch yet. The accept brings the
         * same allocation, which binds it again from its first address
         * (call_relay_setup), the usual way on from there */
        npf_log("call %s: UDP relay unreachable before the accept: binding it again then", c->call_id_s);
    } else if (c->p2p) {
        /* in doubt (p2p_suspect): the verdict decides (lost: the WS
         * relay, check_p2p); no punching on the WS relay */
        npf_log("call %s: UDP relay unreachable; the direct path carries the session%s", c->call_id_s,
                c->p2p_suspect ? " while it is checked" : "");
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
        call_port_pressure(c->n, "the UDP relay unreachable");
        if (!c->t_ws_wait)
            c->t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
    } else if (!c->punched && !call_no_p2p(c)) {
        /* a WS relay session gets no punching rounds (they come back
         * only with UDP): let the first punch round decide.
         * Measured: a Linux node's UDP relay unreachable 2 s before the
         * punch plan arrived, the direct path up 6 s later, the session
         * stuck on the WS relay at 14 KB/s */
        npf_log("call %s: UDP relay unreachable; waiting for the punch before asking for the WS relay",
                c->call_id_s);
        if (!c->t_ws_wait)
            c->t_ws_wait = npf_timer_add(c->n->loop, WS_WAIT_MS, ws_wait_done, c);
    } else {
        npf_log("call %s: UDP relay unreachable", c->call_id_s);
        call_ask_ws_relay(c);
    }
}

/* the UDP relay bound again from its first address (a BIND every 700 ms) */
void call_relay_rebind(npf_call *c)
{
    relay_bind_run(&c->relay, c->n->loop, relay_bind_send, relay_gave_up, c);
}

/* the binding refreshed every RELAY_KEEPALIVE_MS while the relay is in use */
static void relay_keepalive(npf_call *c)
{
    npf_timer_stop(c->n->loop, &c->relay.t_bind);
    c->relay.t_bind = npf_timer_add(c->n->loop, RELAY_KEEPALIVE_MS, relay_keepalive_timer, c);
}


static void relay_bound(npf_call *c, const char *how);

/* an allocation taken: the relay of the session from now on (addr NULL: a
 * WS relay's); 1 when it is the node's spare (home-binding.md v0.5, 7),
 * bound already from the main socket or being bound */
static int relay_take(npf_call *c, const uint8_t id[8], const uint8_t key[32],
                      const struct sockaddr_storage *addr, int naddr)
{
    int spare = addr && node_home_adopt(c->n, id, &c->relay);
    if (!spare)
        relay_bind_take(&c->relay, c->n, id, key, addr, naddr);
    c->relay_asked_ms = 0;
    npf_timer_stop(c->n->loop, &c->t_standby);
    return spare;
}

/* the platform's relay allocation; one that is no use leaves the relay in use
 * as it is (it used to take its id and key at once, then bind the old
 * addresses with them) */
void call_relay_setup(npf_call *c, const npf_json *j, int d)
{
    int r = npf_json_get(j, d, "relay"), naddr;
    char mode[8];
    uint8_t id[8], key[32];
    struct sockaddr_storage addr[4];
    if (r < 0 || j->tok[r].type != NPF_JT_OBJECT || (naddr = relay_obj_parse(j, r, mode, id, key, addr)) < 0)
        return;
    if (strcmp(mode, "ws") == 0) {
        if (c->ws_mode && (c->wsr || c->ws_fail_wait) && memcmp(id, c->relay.relay_id, 8) == 0)
            return;                 /* the one in use, sent again (both sides asked; the reply to the
                                     * call, then call_accepted): its sublinks stay */
        relay_take(c, id, key, NULL, 0);
        if (call_ws_setup(c, j, r) < 0)
            call_ws_failed(c, "cannot connect");
        return;
    }
    if (strcmp(mode, "udp") != 0 || !naddr)
        return;
    /* from the WS relay back to UDP (udp_back): the same AnLiu connection,
     * a datagram carrier again; punching rounds come again too */
    call_ws_leave(c);
    if (c->relay.active && memcmp(id, c->relay.relay_id, 8) == 0
        && npf_ct_eq(key, c->relay.alloc_key, 32) == 0) {
        /* the one in use, sent again (the reply to the call, then
         * call_accepted; both sides asked for it): bound or being bound, it
         * stays so; one that gave up binding before the accept binds again */
        if (!c->relay.bound && !c->relay.t_bind)
            call_relay_rebind(c);
        return;
    }
    npf_timer_stop(c->n->loop, &c->relay.t_bind);
    if (relay_take(c, id, key, addr, naddr)) {
        /* the node's spare: nothing to bind when bound; the platform sends another */
        c->relay.active = 1;
        if (c->relay.bound) {
            relay_bound(c, " (the node's spare)");
        } else {
            npf_log("call %s: UDP relay: the node's spare, binding it", c->call_id_s);
            call_relay_rebind(c);
            call_path_up(c);
        }
        return;
    }
    c->relay.active = 1;
    c->relay.bound = 0;
    call_relay_rebind(c);
    /* our data may go at once, with the first bind: the relay forwards what
     * our key seals from an address it has not bound yet; only what comes to
     * us waits for the cookie's round trip (the callee's hello, call_path_up) */
    call_path_up(c);
}

/* the relay works (a BIND_ACK, or the peer's data through it): bound, the
 * binding kept fresh from now on */
static void relay_bound(npf_call *c, const char *how)
{
    c->relay.bound = 1;
    c->relay_waits_ports = 0;
    if (c->t_ws_wait && !c->ws_mode)     /* no WS relay needed after all */
        npf_timer_stop(c->n->loop, &c->t_ws_wait);
    relay_keepalive(c);
    npf_log("call %s: UDP relay bound%s", c->call_id_s, how);
    call_path_up(c);
}

/* RELAY_BIND_ACK of ours (relay_bind_ack): the cookie kept for the next
 * binds; a challenge (the address is not ours on the relay yet, or no
 * longer: a new NAT port) is answered at once with a BIND echoing it, 200 ms
 * apart at most */
static void relay_ack_in(npf_call *c, const uint8_t *plain, size_t pl)
{
    relay_ack a;
    if (!relay_bind_ack(&c->relay, c->n, plain, pl, &a))
        return;
    if (a.state == RELAY_ACK_BOUND) {
        /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that confirms
         * the binding (the challenges still come: without one nothing binds) */
        if (!c->relay.bound && !getenv("NPF_TEST_DROP_BIND_ACK"))
            relay_bound(c, "");
        return;
    }
    if (c->relay.active && relay_bind_echo_due(&c->relay))
        relay_bind_send(c);
}

/* The caller binds its relay from the reply to the call, before it has the
 * session's keys (call_accepted brings them): the callee's first datagrams
 * (its AnLiu hello as soon as its own side is bound) may come through the
 * relay before the accept does. A few wait here for the keys instead of an
 * AnLiu retransmission. */
#define RELAY_EARLY_MAX 8

typedef struct relay_early {
    struct relay_early *next;
    size_t              len;
    uint8_t             d[];
} relay_early;

void call_relay_early_keep(npf_call *c, const uint8_t *dgram, size_t len)
{
    relay_early *e, **pp;
    if (c->nrearly >= RELAY_EARLY_MAX || !(e = malloc(sizeof *e + len)))
        return;
    e->next = NULL;
    e->len = len;
    memcpy(e->d, dgram, len);
    for (pp = &c->rearly; *pp; pp = &(*pp)->next)
        ;
    *pp = e;
    c->nrearly++;
}

void call_relay_early_free(npf_call *c)
{
    while (c->rearly) {
        relay_early *e = c->rearly;
        c->rearly = e->next;
        free(e);
    }
    c->nrearly = 0;
}

/* the keys are there: what came early goes to AnLiu */
void call_relay_early_feed(npf_call *c)
{
    relay_early *e = c->rearly;
    int fed = 0;
    c->rearly = NULL;
    c->nrearly = 0;
    while (e) {
        relay_early *next = e->next;
        if (!c->ended && c->anl && call_anl_feed(c, e->d, e->len) == 0)
            fed++;
        free(e);
        e = next;
    }
    if (fed && !c->ended)
        npf_log("call %s: %d datagram%s from the peer came through the relay before the accept", c->call_id_s, fed,
                fed == 1 ? "" : "s");
    if (fed && !c->ended && c->relay.active && !c->relay.bound)
        relay_bound(c, " (the peer's data came through it)");
}

/* the peer's AnLiu datagram through the relay (its RELAY_DATA authenticated) */
static void relay_data_in(npf_call *c, const uint8_t *dg, size_t len)
{
    if (c->caller && !c->keys_ready && c->relay.active) {
        call_relay_early_keep(c, dg, len);
        return;
    }
    /* AnLiu first: a relayed datagram proves nothing until it takes it
     * (the relay's keys are not the session's: a replay of an old one
     * with the relay's address would bring back a relay given up, on
     * the WS relay too) */
    if (call_anl_feed(c, dg, len) < 0 || c->ended)
        return;
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
}

/* a control packet (RELAY_BIND_ACK) of c's allocation: 1 if consumed */
int call_relay_input(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    uint8_t plain[2048];
    int pl;
    /* a relay released here may still be in use by the peer: only the
     * caller releases the allocations on the server, and the peer may have
     * given up the direct path just after our standby ended (a path dead in
     * one direction looks fine from this side) */
    if ((pl = relay_bind_open(&c->relay, buf, len, from, plain)) <= 0)
        return pl == 0;
    if (plain[0] == PKT_RELAY_BIND_ACK)
        relay_ack_in(c, plain, (size_t)pl);
    return 1;
}

/* RELAY_DATA: the hint, unmasked without a key, names the allocation;
 * one SipHash over the header decides (no trying every session's keys).
 * Allocations on two relay servers may share a hint: the source address
 * and the tag tell them apart. The last one hit first. */
static int relay_data_try(npf_call *c, const uint8_t hint[RDATA_HINT], const uint8_t *buf, size_t len,
                          const struct sockaddr_storage *from)
{
    int r;
    if (c->ended || (r = relay_data_open(&c->relay, hint, buf, len, from)) < 0)
        return 0;
    if (r > 0)
        relay_data_in(c, buf + RDATA_HDR, len - RDATA_HDR);
    return 1;
}

int node_relay_data_input(npf_node *n, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    uint8_t hint[RDATA_HINT];
    npf_call *c;
    if (rdata_hint(buf, len, hint) < 0)
        return 0;
    if ((c = n->relay_hit) && relay_data_try(c, hint, buf, len, from))
        return 1;
    for (c = n->calls; c; c = c->next)
        if (c != n->relay_hit && relay_data_try(c, hint, buf, len, from)) {
            n->relay_hit = c;
            return 1;
        }
    return 0;
}
/* a round that did not go direct (failed, or none planned) while the UDP
 * relay was unreachable: the UDP relay once more, then the WS relay */
void call_ws_wait_end(npf_call *c, int ok)
{
    if (!c->t_ws_wait)
        return;
    npf_timer_stop(c->n->loop, &c->t_ws_wait);
    if (!ok && !c->relay.bound && c->relay.t_bind) {
        /* the UDP relay is being bound again (the punch gave the NAT's ports
         * back): its answer first; when it gives up, relay_bind_timer asks
         * for the WS relay (asked here at once, a bind about to succeed was
         * replaced: the phone's sessions, measured) */
        npf_log("call %s: the UDP relay is being bound: its answer before the WS relay", c->call_id_s);
        return;
    }
    if (!ok && !c->relay_retried && !c->relay.bound && !c->relay.t_bind) {
        /* once more first: a WS relay session gets no punching rounds, and
         * the UDP relay may have been lost to a passing storm (the phone at a
         * start, five punches at once: its binds went unanswered for 5 s) */
        npf_log("call %s: trying the UDP relay once more before the WS relay", c->call_id_s);
        c->relay_retried = 1;
        call_relay_rebind(c);
    } else if (!ok) {
        call_ask_ws_relay(c);
    }
}

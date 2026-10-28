/* The UDP relay (path.h, data-channel.md 9): its sending, binding and
 * keeping the allocation, the relayed datagrams and the relay's answers,
 * its check while the session relies on it. What a session does when it
 * cannot be reached is the manager's (path_mgr.c). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

/* ---- UDP relay client (data-channel.md 9) ---- */

/* tests: NPF_TEST_BLOCK_RELAY="addr,url,..." makes these relay endpoints unreachable */
int call_relay_blocked(const npf_node *n, const char *what)
{
    const char *v = n->th->block_relay;
    return v && *what && strstr(v, what) != NULL;
}

int call_relay_addr_blocked(const npf_call *c)
{
    char a[64];
    return c->n->th->block_relay
           && call_relay_blocked(c->n, npf_addr_str(&c->pu.r.addr[c->pu.r.cur], a, sizeof a));
}

/* RELAY_BIND (relay_bind.c): the relay's cookie for our address in it
 * (zeros before the first BIND_ACK: the relay answers with a challenge
 * carrying it, and binds the address when a BIND echoes it) */
static void relay_bind_send(void *arg)
{
    npf_call *c = arg;
    uint8_t wire[256];
    int n = relay_bind_pack(&c->pu.r, c->n, 0, 0, wire);
    if (n > 0 && !call_relay_addr_blocked(c))
        npf_udp_send(c->n->udp_fd, wire, (size_t)n, &c->pu.r.addr[c->pu.r.cur]);
}

/* RELAY_DATA (relay_data.c): a 16-byte header before the AnLiu datagram */
void call_relay_send_data(npf_call *c, const uint8_t *dgram, size_t len)
{
    uint8_t buf[2048];
    size_t n;
    if (call_relay_addr_blocked(c) || !(n = relay_data_pack(&c->pu.r, dgram, len, buf)))
        return;
    npf_udp_send(c->n->udp_fd, buf, n, &c->pu.r.addr[c->pu.r.cur]);
}

static void udp_send(npf_path *p, const uint8_t *dgram, size_t len)
{
    call_relay_send_data(CALL_OF(p, pu.p), dgram, len);
}

static const char *udp_name(const npf_path *p)
{
    return ((const path_udp *)(const void *)p)->r.bound ? "relay" : "relay (binding)";
}

const npf_path_ops path_udp_ops = {udp_send, udp_name};

/* the allocation in use from now on, or no longer (the binder's active
 * says the same: relay_addr_take reads it) */
void path_udp_on(npf_call *c)
{
    c->pu.r.active = 1;
    pm_add(&c->pm, &c->pu.p);
}

void path_udp_off(npf_call *c)
{
    c->pu.r.active = 0;
    pm_del(&c->pm, &c->pu.p);
}

/* refresh the binding (NAT mapping, server idle timer) while in use */
static void relay_keepalive_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    c->pu.r.t_bind = NULL;
    if (c->pu.r.bound && call_has_relay(c)) {
        relay_bind_send(c);
        c->pu.r.t_bind = npf_timer_add(loop, RELAY_KEEPALIVE_MS, relay_keepalive_timer, c);
    }
}

/* the UDP relay bound again from its first address (a BIND every 700 ms) */
void call_relay_rebind(npf_call *c)
{
    relay_bind_run(&c->pu.r, c->n->loop, relay_bind_send, call_relay_gave_up, c);
}

/* the binding refreshed every RELAY_KEEPALIVE_MS while the relay is in use */
static void relay_keepalive(npf_call *c)
{
    npf_timer_stop(c->n->loop, &c->pu.r.t_bind);
    c->pu.r.t_bind = npf_timer_add(c->n->loop, RELAY_KEEPALIVE_MS, relay_keepalive_timer, c);
}


static void relay_bound(npf_call *c, const char *how);

/* an allocation taken: the relay of the session from now on (addr NULL: a
 * WS relay's); 1 when it is the node's spare (home-binding.md v0.5, 7),
 * bound already from the main socket or being bound */
int call_relay_take(npf_call *c, const uint8_t id[8], const uint8_t key[32],
                    const struct sockaddr_storage *addr, int naddr)
{
    int spare = addr && node_home_adopt(c->n, id, &c->pu.r);
    if (!spare)
        relay_bind_take(&c->pu.r, c->n, id, key, addr, naddr);
    c->pm.asked_ms = 0;
    c->pu.p.last_rx = npf_mono_ms();         /* a new allocation: silent from now on counts */
    c->pu.p.busy_since = 0;
    npf_timer_stop(c->n->loop, &c->pu.t_standby);
    return spare;
}

/* the platform's UDP relay allocation (call_relay_setup); one that is no use
 * leaves the relay in use as it is (it used to take its id and key at once,
 * then bind the old addresses with them) */
void path_udp_setup(npf_call *c, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_storage *addr,
                    int naddr)
{
    if (call_has_relay(c) && memcmp(id, c->pu.r.relay_id, 8) == 0
        && npf_ct_eq(key, c->pu.r.alloc_key, 32) == 0) {
        /* the one in use, sent again (the reply to the call, then
         * call_accepted; both sides asked for it): bound or being bound, it
         * stays so; one that gave up binding before the accept binds again */
        if (!c->pu.r.bound && !c->pu.r.t_bind)
            call_relay_rebind(c);
        return;
    }
    npf_timer_stop(c->n->loop, &c->pu.r.t_bind);
    if (call_relay_take(c, id, key, addr, naddr)) {
        /* the node's spare: nothing to bind when bound; the platform sends another */
        path_udp_on(c);
        if (c->pu.r.bound) {
            relay_bound(c, " (the node's spare)");
        } else {
            npf_log("call %s: UDP relay: the node's spare, binding it", c->call_id_s);
            call_relay_rebind(c);
            call_path_up(c);
        }
        return;
    }
    path_udp_on(c);
    c->pu.r.bound = 0;
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
    node_home_udp_ok(c->n);                 /* a spare stuck backing off: UDP works */
    c->pu.r.bound = 1;
    c->pu.waits_ports = 0;
    if (c->pm.t_ws_wait && !call_has_ws(c))     /* no WS relay needed after all */
        npf_timer_stop(c->n->loop, &c->pm.t_ws_wait);
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
    if (!relay_bind_ack(&c->pu.r, c->n, plain, pl, &a))
        return;
    c->pu.p.last_rx = npf_mono_ms();
    if (a.state == RELAY_ACK_BOUND) {
        /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that confirms
         * the binding (the challenges still come: without one nothing binds) */
        if (!c->pu.r.bound && !c->n->th->drop_bind_ack)
            relay_bound(c, "");
        return;
    }
    if (call_has_relay(c) && relay_bind_echo_due(&c->pu.r))
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
    if (fed && !c->ended && call_has_relay(c) && !c->pu.r.bound)
        relay_bound(c, " (the peer's data came through it)");
}

/* the peer's AnLiu datagram through the relay (its RELAY_DATA authenticated) */
static void relay_data_in(npf_call *c, const uint8_t *dg, size_t len)
{
    if (c->caller && !c->keys_ready && call_has_relay(c)) {
        call_relay_early_keep(c, dg, len);
        return;
    }
    /* AnLiu first: a relayed datagram proves nothing until it takes it
     * (the relay's keys are not the session's: a replay of an old one
     * with the relay's address would bring back a relay given up, on
     * the WS relay too) */
    if (call_anl_feed(c, dg, len) < 0 || c->ended)
        return;
    c->pu.p.last_rx = npf_mono_ms();
    if (!call_has_relay(c)) {     /* the peer sends on it: take it back, keep the binding fresh */
        npf_log("call %s: the peer uses the relay again, keeping it", c->call_id_s);
        path_udp_on(c);
        c->pu.r.bound = 1;
        relay_bind_send(c);
        relay_keepalive(c);
    } else if (!c->pu.r.bound) {
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
    if ((pl = relay_bind_open(&c->pu.r, buf, len, from, plain)) <= 0)
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
    if (c->ended || (r = relay_data_open(&c->pu.r, hint, buf, len, from)) < 0)
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

/* A bound UDP relay can die under a session (the node's UDP blocked, the
 * relay's address unreachable): its BIND every 25 s goes unanswered and
 * nothing comes through it, while the session waits on AnLiu's retries and
 * the idle timeout (measured: all UDP of a node dropped, 41 s on a dead relay
 * after the direct path was lost, 90 s: transport_lost). While the session
 * relies on it (no direct path, or one in doubt), silence for max(3 s,
 * 2 RTO) with data in flight - or 10 s without (a session waiting for its
 * peer's credit sends nothing; a bind is a probe of a round trip) - binds it
 * again from its first address: an answer keeps it (the peer, not the relay,
 * gone quiet), none gives it up as at the start (call_relay_gave_up: the WS
 * relay, once the direct path's verdict is in). Checked every second while
 * relied on: AnLiu's own timer can be many seconds away (backed off) */
#define RELAY_SILENT_MS      3000
#define RELAY_IDLE_SILENT_MS 10000
#define RELAY_CHECK_MS       1000

static void relay_check_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pu.t_check = NULL;
    if (!c->ended)
        call_check_relay(c);
}

void call_check_relay(npf_call *c)
{
    anl_stats st;
    int64_t now = npf_mono_ms(), quiet;
    /* bound: t_bind is its keepalive (binding is !bound with t_bind) */
    if (!call_has_relay(c) || !c->pu.r.bound || call_has_ws(c) || c->direct || (call_has_p2p(c) && !c->pd.suspect)
        || !c->anl || anl_get_stats(c->anl, &st) < 0) {
        c->pu.p.busy_since = 0;
        npf_timer_stop(c->n->loop, &c->pu.t_check);
        return;
    }
    if (!c->pu.t_check)
        c->pu.t_check = npf_timer_add(c->n->loop, RELAY_CHECK_MS, relay_check_timer, c);
    if (st.inflight == 0) {
        c->pu.p.busy_since = 0;
        quiet = RELAY_IDLE_SILENT_MS;
        if (now - c->pu.p.last_rx < quiet)
            return;
    } else {
        if (!c->pu.p.busy_since)
            c->pu.p.busy_since = now;
        quiet = 2 * (int64_t)st.rto > RELAY_SILENT_MS ? 2 * (int64_t)st.rto : RELAY_SILENT_MS;
        if (now - (c->pu.p.last_rx > c->pu.p.busy_since ? c->pu.p.last_rx : c->pu.p.busy_since) < quiet)
            return;
    }
    npf_logw("call %s: the UDP relay silent for %lld ms while the session relies on it: binding it again",
             c->call_id_s, (long long)quiet);
    c->pu.r.bound = 0;
    c->pu.p.busy_since = 0;
    npf_timer_stop(c->n->loop, &c->pu.t_check);
    npf_timer_stop(c->n->loop, &c->pu.r.t_bind);
    call_relay_rebind(c);
}

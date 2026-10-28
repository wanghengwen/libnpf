/* The UDP relay (path.h, data-channel.md 9): sending, binding and keeping
 * the allocation, the relayed datagrams and the relay's answers, its probe.
 * What a session does when it cannot be reached is the manager's. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"
#include "home.h"

/* tests: NPF_TEST_BLOCK_RELAY="addr,url,..." makes these relay endpoints unreachable */
int call_relay_blocked(const npf_node *n, const char *what)
{
    const char *v = n->th.block_relay;
    return v && *what && strstr(v, what) != NULL;
}

static int addr_blocked(const npf_call *c, const struct sockaddr_storage *a)
{
    char s[64];
    return c->n->th.block_relay && call_relay_blocked(c->n, npf_addr_str(a, s, sizeof s));
}

/* RELAY_BIND to the address being bound or kept (relay_bind.h) */
static void relay_bind_send(void *arg)
{
    npf_call *c = arg;
    uint8_t wire[256];
    int n = relay_bind_pack(&c->pu.r, c->n, 0, 0, wire);
    if (n > 0 && !addr_blocked(c, RELAY_BIND_DST(&c->pu.r)))
        npf_udp_send(c->n->udp_fd, wire, (size_t)n, RELAY_BIND_DST(&c->pu.r));
}

/* RELAY_DATA (relay_data.c) to the address in use (cur): a 16-byte header
 * before the AnLiu datagram */
void call_relay_send_data(npf_call *c, const uint8_t *dgram, size_t len)
{
    uint8_t buf[2048];
    size_t n;
    if (addr_blocked(c, &c->pu.r.addr[c->pu.r.cur]) || !(n = relay_data_pack(&c->pu.r, dgram, len, buf)))
        return;
    npf_udp_send(c->n->udp_fd, buf, n, &c->pu.r.addr[c->pu.r.cur]);
}

static void udp_send(npf_path *p, const uint8_t *dgram, size_t len)
{
    call_relay_send_data(CALL_OF(p, pu.p), dgram, len);
}

/* the allocation in use from now on (UP when bound, else NEW), or no
 * longer, its binding stopped (NONE) */
void path_udp_on(npf_call *c)
{
    c->pu.p.since = npf_mono_ms();
    c->pu.p.health = c->pu.r.state == RB_BOUND ? PH_UP : PH_NEW;
    pm_add(&c->pm, &c->pu.p);
}

void path_udp_off(npf_call *c)
{
    c->pu.r.state = RB_NONE;
    c->pu.r.at = 0;
    pm_del(&c->pm, &c->pu.p);
}

/* a binding run from now (relay_bind_begin; probe: from the address in use) */
static void bind_run(npf_call *c, int probe)
{
    relay_bind_begin(&c->pu.r, probe, npf_mono_ms());
    relay_bind_send(c);
    call_at(c, c->pu.r.at);
}

/* the binder's deadline: the run's next bind, or the keepalive; every
 * address tried: DEAD, pm_decide's (before the accept: the accept brings
 * the same allocation, bound again then) */
void path_udp_tick(npf_call *c)
{
    int r = relay_bind_tick(&c->pu.r, npf_mono_ms(), RELAY_KEEPALIVE_MS);
    if (r > 0) {
        relay_bind_send(c);
    } else if (r < 0) {
        npf_log("call %s: UDP relay unreachable%s", c->call_id_s,
                c->caller && c->st == CS_CALLING ? " before the accept: binding it again then" : "");
        pm_health(&c->pm, &c->pu.p, PH_DEAD);
        pm_check(c);
    }
}

/* the UDP relay (not bound) bound again from its first address */
void call_relay_rebind(npf_call *c)
{
    pm_health(&c->pm, &c->pu.p, PH_NEW);
    bind_run(c, 0);
}

/* silent while relied on (the node's UDP blocked, the relay's address
 * unreachable): probed with binds from the address in use, the data staying
 * on it until another one answers (architecture.md 3.3, Q2); an answer
 * keeps it, none gives it up (pm_decide) */
static void udp_suspect(npf_path *p, int64_t quiet)
{
    npf_call *c = CALL_OF(p, pu.p);
    npf_logw("call %s: the UDP relay silent for %lld ms while the session relies on it: probing it, %s first",
             c->call_id_s, (long long)quiet, c->pu.r.naddr > 1 ? "its address in use" : "its address");
    bind_run(c, 1);
}

/* its probe is a bind and its verdict the binder's: none by time */
const npf_path_ops path_udp_ops = {udp_send, udp_suspect, NULL, NULL};

/* the relay works (a BIND_ACK, or the peer's data through it): bound, the
 * binding kept fresh from now on */
static void relay_bound(npf_call *c, const char *how)
{
    node_home_udp_ok(c->n);                 /* a spare stuck backing off: UDP works */
    relay_bind_up(&c->pu.r, npf_mono_ms(), RELAY_KEEPALIVE_MS);
    call_at(c, c->pu.r.at);
    pm_rt(&c->pm, &c->pu.p, npf_mono_ms());
    npf_log("call %s: UDP relay bound%s", c->call_id_s, how);
    call_path_up(c);
}

/* the platform's UDP relay allocation (call_relay_setup) */
void path_udp_setup(npf_call *c, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_storage *addr,
                    int naddr)
{
    int spare;
    if (call_has_relay(c) && memcmp(id, c->pu.r.relay_id, 8) == 0
        && npf_ct_eq(key, c->pu.r.alloc_key, 32) == 0) {
        /* the one in use, sent again (the reply to the call, then
         * call_accepted; both sides asked for it): bound or being bound, it
         * stays so; one that gave up binding before the accept binds again */
        if (c->pu.r.state == RB_GAVE_UP)
            call_relay_rebind(c);
        return;
    }
    c->pu.p.last_rx = npf_mono_ms();         /* a new allocation: silent from now on counts */
    c->pu.p.busy_since = 0;
    /* the node's spare (home-binding.md 7), bound or being bound already */
    if (!(spare = node_home_adopt(c->n, id, &c->pu.r)))
        relay_bind_take(&c->pu.r, c->n, id, key, addr, naddr);
    path_udp_on(c);
    if (c->pu.r.state == RB_BOUND) {
        relay_bound(c, " (the node's spare)");
        return;
    }
    if (spare)
        npf_log("call %s: UDP relay: the node's spare, binding it", c->call_id_s);
    bind_run(c, 0);
    /* our data may go at once, with the first bind: the relay forwards what
     * our key seals from an address it has not bound yet; only what comes to
     * us waits for the cookie's round trip (the callee's hello, call_path_up) */
    call_path_up(c);
}

/* RELAY_BIND_ACK of ours (relay_bind_ack): a challenge (the address not
 * ours on the relay yet, or no longer: a new NAT port) is answered at once */
static void relay_ack_in(npf_call *c, const uint8_t *plain, size_t pl)
{
    relay_ack a;
    int k = relay_bind_ack(&c->pu.r, c->n, plain, pl, &a);
    if (!k)
        return;
    c->pu.p.last_rx = npf_mono_ms();
    if (a.state == RELAY_ACK_BOUND) {
        /* tests: NPF_TEST_DROP_BIND_ACK=1 loses every BIND_ACK that confirms
         * the binding (the challenges still come: without one nothing binds) */
        if (c->pu.r.state != RB_BOUND && !c->n->th.drop_bind_ack && call_has_relay(c))
            relay_bound(c, "");     /* (a late one after the relay went, the standby's or the move to WS: no) */
        return;
    }
    if (call_has_relay(c) && k == 2)
        relay_bind_send(c);
}

/* The caller binds its relay before it has the session's keys (the accept
 * brings them): the callee's first datagrams may come through the relay
 * first. A few wait here for the keys instead of an AnLiu retransmission. */
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
        if (!call_over(c) && c->anl && call_anl_feed(c, e->d, e->len) == 0)
            fed++;
        free(e);
        e = next;
    }
    if (fed && !call_over(c))
        npf_log("call %s: %d datagram%s from the peer came through the relay before the accept", c->call_id_s, fed,
                fed == 1 ? "" : "s");
    if (fed && !call_over(c) && call_has_relay(c) && c->pu.r.state != RB_BOUND)
        relay_bound(c, " (the peer's data came through it)");
}

/* the peer's AnLiu datagram through the relay (its RELAY_DATA authenticated) */
static void relay_data_in(npf_call *c, const uint8_t *dg, size_t len)
{
    if (c->caller && !c->keys_ready && call_has_relay(c)) {
        call_relay_early_keep(c, dg, len);
        return;
    }
    /* AnLiu first: a relayed datagram proves nothing until it takes it (a
     * replay with the relay's address would bring back a relay given up) */
    if (call_anl_feed(c, dg, len) < 0 || call_over(c))
        return;
    c->pu.p.last_rx = npf_mono_ms();
    if (!call_has_relay(c)) {     /* the peer sends on it: take it back, keep the binding fresh */
        npf_log("call %s: the peer uses the relay again, keeping it", c->call_id_s);
        relay_bind_up(&c->pu.r, npf_mono_ms(), RELAY_KEEPALIVE_MS);
        path_udp_on(c);
        relay_bind_send(c);
        call_at(c, c->pu.r.at);
    } else if (c->pu.r.state != RB_BOUND) {
        /* the relay forwards the peer's data to us: it has our binding,
         * whether or not its BIND_ACK came */
        relay_bound(c, " (the peer's data came through it)");
    }
}

/* a control packet (RELAY_BIND_ACK) of c's allocation: 1 if consumed */
int call_relay_input(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    uint8_t plain[2048];
    int pl;
    /* (a relay released here may still be the peer's: only the caller
     * releases the allocations on the server) */
    if ((pl = relay_bind_open(&c->pu.r, buf, len, from, plain)) <= 0)
        return pl == 0;
    if (plain[0] == PKT_RELAY_BIND_ACK)
        relay_ack_in(c, plain, (size_t)pl);
    return 1;
}

/* RELAY_DATA (data-channel.md 9.2): the hint names the allocation, one
 * SipHash over the header decides; two relay servers' allocations sharing
 * a hint: the source address and the tag tell them apart. The last one hit first */
static int relay_data_try(npf_call *c, const uint8_t hint[RDATA_HINT], const uint8_t *buf, size_t len,
                          const struct sockaddr_storage *from)
{
    int r;
    if (call_over(c) || (r = relay_data_open(&c->pu.r, hint, buf, len, from)) < 0)
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

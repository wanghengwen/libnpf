/* The direct path (path.h): a punched one, or a direct connection's fixed
 * one (call_direct.c). Its sending, its check both ways (PATH_CHECK /
 * PATH_ECHO), the suspicion when it goes silent and the fall back to the
 * relay (nat-traversal.md 10.3). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define PKT_PATH_CHECK     10         /* direct path check (both directions work?) */
#define PKT_PATH_ECHO      11
/* tests: NPF_TEST_DROP_P2P=ms cuts the direct path that long after it came
 * up; with NPF_TEST_DROP_P2P_PORT only the one to the peer on that port */
int call_p2p_cut(const npf_call *c)
{
    int64_t cut = c->n->th.drop_p2p_ms;
    int port = (int)c->n->th.drop_p2p_port;
    if (!cut || !call_has_p2p(c) || npf_mono_ms() - c->pd.p.since < cut)
        return 0;
    return !port || npf_addr_port(&c->pd.addr) == port;
}

void path_direct_tx(npf_path *p, const uint8_t *dgram, size_t len)
{
    npf_call *c = CALL_OF(p, pd.p);
    if (!call_p2p_cut(c))
        npf_udp_send(c->pd.fd, dgram, len, &c->pd.addr);
}

/* a punch's path (punch_done): fd the main socket, or an S3 one handed over;
 * NEW, it carries nothing before an echo from there (the peer's proof: a
 * spoofed NOMINATE's source never answers, security.md 11.1). 0, or -1 when
 * an owned socket could not be watched (closed here; caller falls back). */
int path_direct_up(npf_call *c, int fd, const struct sockaddr_storage *peer)
{
    int own = fd != c->n->udp_fd && fd != c->n->udp6_fd;
    if (own && npf_loop_add(c->n->loop, fd, NPF_EV_READ, call_p2p_input_cb, c) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    c->pd.owned = own;
    c->pd.fd = fd;
    c->pd.addr = *peer;
    c->pd.p.last_rx = c->pd.p.since = c->pd.p.suspect_at = c->pd.p.probe_at = npf_mono_ms();
    c->pd.p.rt_ok = c->pd.p.busy_since = c->pd.p.probe_until = 0;
    c->pd.p.health = PH_NEW;            /* checked as in doubt (pm_tick) */
    path_direct_check(c);
    pm_add(&c->pm, &c->pd.p);
    return 0;
}

/* a direct connection's path, used once its handshake is done (pm_add) */
void path_direct_fixed(npf_call *c, int fd, const struct sockaddr_storage *peer)
{
    c->pm.fixed = 1;
    c->pd.fd = fd;
    c->pd.addr = *peer;
    c->pd.p.last_rx = c->pd.p.since = npf_mono_ms();
    c->pd.p.health = PH_UP;
}

/* ---- direct path check (nat-traversal.md 10.3) ----
 * Hearing the peer does not prove that it hears us (a path dead one way: a
 * firewall, a cut in a test). New, in doubt, or for consent (every 15 s),
 * PATH_CHECK{nonce} goes out every 500 ms, the peer answers each with
 * PATH_ECHO{nonce}: only a matching echo from the path's address, a round
 * trip, proves the path or brings it back. SIV-sealed with a key of the
 * session and the sender's direction: nobody else can make one, and a
 * reflected check is no echo; each nonce proves once. */
static void path_send(npf_call *c, int type, uint64_t nonce)
{
    uint8_t buf[PATH_PKT_LEN], *p = buf + NPF_SIV_TAG_SIZE;
    if (!c->keys_ready || !call_has_p2p(c) || call_p2p_cut(c))
        return;
    p[0] = (uint8_t)type;
    p[1] = 0;
    npf_le64(p + 2, nonce);
    npf_siv_seal(&c->pd.keys, c->caller ? 0 : 1, buf, 10);
    npf_udp_send(c->pd.fd, buf, sizeof buf, &c->pd.addr);
}

/* 1 when the datagram was a path check or echo of this call (from the
 * path's address: the callers check) */
int call_path_input(npf_call *c, const uint8_t *buf, size_t len)
{
    uint8_t plain[16];
    int h = c->pd.p.health;
    if (!c->keys_ready || len != PATH_PKT_LEN || npf_siv_open(&c->pd.keys, c->caller ? 1 : 0, buf, len, plain) < 0)
        return 0;
    if (plain[0] == PKT_PATH_CHECK)
        path_send(c, PKT_PATH_ECHO, npf_rd64(plain + 2));
    else if (plain[0] == PKT_PATH_ECHO && (h == PH_NEW || h == PH_SUSPECT || c->pd.p.probe_until)
             && npf_rd64(plain + 2) == c->pd.nonce) {
        /* an echo of these checks (a new path's, a doubt's, consent's, the
         * standby's): UP; the relay standing by may go (pm_decide) */
        path_direct_check(c);
        if (pm_rt(&c->pm, &c->pd.p, npf_mono_ms()))
            npf_log("call %s: direct path %s (checked both ways)", c->call_id_s, h == PH_NEW ? "proven" : "alive again");
        if (h == PH_NEW)
            call_path_up(c);
        pm_check(c);
    }
    return 1;
}

/* the checks from now on (pm_tick sends them): a new nonce, only an echo of these counts */
void path_direct_check(npf_call *c)
{
    npf_random(&c->pd.nonce, sizeof c->pd.nonce);
}

void path_direct_probe(npf_path *p)
{
    npf_call *c = CALL_OF(p, pd.p);
    path_send(c, PKT_PATH_CHECK, c->pd.nonce);
}

/* in doubt (SUSPECT): checked both ways, the data on the relay too
 * meanwhile (asked for when it was released: pm_decide) */
static void direct_doubt(npf_call *c, const char *why)
{
    path_direct_check(c);
    npf_log("call %s: %s%s", c->call_id_s, why, call_has_relay(c) ? ", sending on the relay too" : "");
    anl_flush(c->anl);
}

/* silent (a loaded uplink's queue can hold packets for seconds: silence
 * alone is no verdict, nat-traversal.md 10.3) */
void path_direct_suspect(npf_path *p, int64_t quiet)
{
    npf_call *c = CALL_OF(p, pd.p);
    char why[80];
    if (!quiet)
        snprintf(why, sizeof why, "no echo on the direct path for %d s (consent)", pm_rules_of[PK_DIRECT].t_consent / 1000);
    else if (p->busy_since)
        snprintf(why, sizeof why, "direct path silent for %lld ms", (long long)quiet);
    else
        snprintf(why, sizeof why, "nothing from the peer on the direct path for %lld s", (long long)quiet / 1000);
    direct_doubt(c, why);
    node_sig_udp_check(c->n);
}

/* in doubt 10 s, no echo: lost (pm_decide drops it) */
void path_direct_dead(npf_path *p)
{
    npf_call *c = CALL_OF(p, pd.p);
    npf_logw("call %s: direct path %s%s", c->call_id_s, p->rt_ok ? "lost" : "never answered its checks",
             call_has_relay(c) && c->pu.r.state == RB_BOUND ? ", staying on the relay"
             : call_has_relay(c) && c->pu.r.at ? ", the UDP relay still binding" : "");
}

/* the direct path given up (lost, the session on the WS relay, its socket gone), its own socket closed */
void call_p2p_drop(npf_call *c)
{
    pm_del(&c->pm, &c->pd.p);
    if (c->pd.owned) {
        npf_loop_del(c->n->loop, c->pd.fd);
        npf_sock_close(c->pd.fd);
        c->pd.owned = 0;
    }
    c->pd.fd = -1;
}

/* in doubt for a reason of the node's (a network change): as when silent */
void call_p2p_suspect_start(npf_call *c, const char *why)
{
    pm_suspect(&c->pm, &c->pd.p, npf_mono_ms());
    direct_doubt(c, why);
    pm_check(c);                /* its first check now */
}

void call_p2p_input_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_call *c = arg;
    int k;
    (void)loop;
    (void)ev;
    for (k = 0; k < 256; k++) {         /* level-triggered: leave time for timers and other sessions */
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (c->punch && npf_punch_input(c->punch, fd, buf, (size_t)r, &from))
            continue;
        if (npf_addr_eq(&from, &c->pd.addr) && call_path_input(c, buf, (size_t)r))
            continue;
        if (call_anl_feed(c, buf, (size_t)r) == 0 && !call_over(c) && npf_addr_eq(&from, &c->pd.addr))
            c->pd.p.last_rx = npf_mono_ms();
        if (call_over(c))
            return;
    }
}

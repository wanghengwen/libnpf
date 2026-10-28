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
/* tests: NPF_TEST_DROP_P2P=ms[:port] cuts the direct path that long after it
 * came up; with a port only the path to the peer on that port (many-to-many) */
int call_p2p_cut(const npf_call *c)
{
    int64_t cut = c->n->th.drop_p2p_ms;
    int port = c->n->th.drop_p2p_port;
    if (cut < 0 || !call_has_p2p(c) || npf_mono_ms() - c->pd.p.since <= cut)
        return 0;
    return !port || ntohs(c->pd.addr.ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)&c->pd.addr)->sin6_port
                                                             : ((const struct sockaddr_in *)&c->pd.addr)->sin_port) == port;
}

static void direct_send(npf_path *p, const uint8_t *dgram, size_t len)
{
    npf_call *c = CALL_OF(p, pd.p);
    if (!call_p2p_cut(c))
        npf_udp_send(c->pd.fd, dgram, len, &c->pd.addr);
}

/* a punch's path (punch_done): fd the main socket, or an S3 one handed over */
void path_direct_up(npf_call *c, int fd, const struct sockaddr_storage *peer)
{
    c->pd.fd = fd;
    c->pd.addr = *peer;
    c->pd.p.last_rx = npf_mono_ms();
    c->pd.p.since = c->pd.p.last_rx;
    c->pd.p.rt_ok = c->pd.p.busy_since = 0;
    c->pd.p.health = PH_UP;
    pm_add(&c->pm, &c->pd.p);
    if (fd != c->n->udp_fd && fd != c->n->udp6_fd) {
        c->pd.owned = 1;
        npf_loop_add(c->n->loop, fd, NPF_EV_READ, call_p2p_input_cb, c);
    }
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
 * firewall, a cut in a test). In doubt, PATH_CHECK{nonce} goes out every
 * 500 ms, the peer answers each with PATH_ECHO{nonce}: only a matching
 * echo, a round trip, brings the path back. SIV-sealed with a key of the
 * session and the sender's direction: nobody else can make one, and a
 * reflected check is no echo. */
static void path_send(npf_call *c, int type, uint64_t nonce)
{
    uint8_t buf[PATH_PKT_LEN], *p = buf + NPF_SIV_TAG_SIZE;
    if (!c->pd.keys_ready || !call_has_p2p(c) || call_p2p_cut(c))
        return;
    p[0] = (uint8_t)type;
    p[1] = 0;
    npf_le64(p + 2, nonce);
    npf_siv_seal(&c->pd.keys, c->caller ? 0 : 1, buf, 10);
    npf_udp_send(c->pd.fd, buf, sizeof buf, &c->pd.addr);
}

/* 1 when the datagram was a path check or echo of this call */
int call_path_input(npf_call *c, const uint8_t *buf, size_t len)
{
    uint8_t plain[16];
    if (!c->pd.keys_ready || len != PATH_PKT_LEN || npf_siv_open(&c->pd.keys, c->caller ? 1 : 0, buf, len, plain) < 0)
        return 0;
    if (plain[0] == PKT_PATH_CHECK)
        path_send(c, PKT_PATH_ECHO, npf_rd64(plain + 2));
    else if (plain[0] == PKT_PATH_ECHO && (c->pd.p.health == PH_SUSPECT || c->pd.p.probe_until)
             && npf_rd64(plain + 2) == c->pd.nonce) {
        /* an echo of these checks (a doubt's, the standby's): UP; the relay
         * standing by may go (pm_decide) */
        if (pm_rt(&c->pm, &c->pd.p, npf_mono_ms()))
            npf_log("call %s: direct path alive again (checked both ways)", c->call_id_s);
        pm_check(c);
    }
    return 1;
}

/* the checks from now on (pm_tick sends them): a new nonce, only an echo of these counts */
void path_direct_check(npf_call *c)
{
    npf_random(&c->pd.nonce, sizeof c->pd.nonce);
}

static void direct_probe(npf_path *p)
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
static void direct_suspect(npf_path *p, int64_t quiet)
{
    npf_call *c = CALL_OF(p, pd.p);
    char why[80];
    if (p->busy_since)
        snprintf(why, sizeof why, "direct path silent for %lld ms", (long long)quiet);
    else
        snprintf(why, sizeof why, "nothing from the peer on the direct path for %lld s", (long long)quiet / 1000);
    direct_doubt(c, why);
}

/* in doubt 10 s, no echo: lost (pm_decide drops it) */
static void direct_lost(npf_path *p)
{
    npf_call *c = CALL_OF(p, pd.p);
    npf_logw("call %s: direct path lost%s", c->call_id_s,
             call_has_relay(c) && c->pu.r.state == RB_BOUND ? ", staying on the relay"
             : call_has_relay(c) && c->pu.r.at ? ", the UDP relay still binding" : "");
}

const npf_path_ops path_direct_ops = {direct_send, direct_suspect, direct_probe, direct_lost};

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
        if (call_path_input(c, buf, (size_t)r))
            continue;
        if (call_anl_feed(c, buf, (size_t)r) == 0 && !call_over(c))
            c->pd.p.last_rx = npf_mono_ms();
        if (call_over(c))
            return;
    }
}

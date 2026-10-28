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

#define P2P_SILENT_MS      3000      /* nat-traversal.md 10.3; at least 2 x RTO */
#define P2P_IDLE_SILENT_MS 20000     /* nothing from the peer this long: no data, not even AnLiu's keepalive (15 s) */
#define P2P_DUAL_MS        10000     /* suspected path: send on both paths this long */
#define PKT_PATH_CHECK     10         /* direct path check (both directions work?) */
#define PKT_PATH_ECHO      11
#define PATH_CHECK_MS      500
/* tests: NPF_TEST_DROP_P2P=ms[:port] cuts the direct path that long after it
 * came up; with a port only the path to the peer on that port (many-to-many) */
int call_p2p_cut(const npf_call *c)
{
    int64_t cut = c->n->th->drop_p2p_ms;
    int port = c->n->th->drop_p2p_port;
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

static const char *direct_name(const npf_path *p)
{
    (void)p;
    return "p2p";
}

const npf_path_ops path_direct_ops = {direct_send, direct_name};

/* a punch's path (punch_done): fd the main socket, or an S3 one handed over */
void path_direct_up(npf_call *c, int fd, const struct sockaddr_storage *peer)
{
    pm_add(&c->pm, &c->pd.p);
    c->pd.fd = fd;
    c->pd.addr = *peer;
    c->pd.p.last_rx = npf_mono_ms();
    c->pd.p.since = c->pd.p.last_rx;
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
}

/* its socket gone (not one of its own): the path too */
void path_direct_gone(npf_call *c)
{
    pm_del(&c->pm, &c->pd.p);
    c->pd.fd = -1;
}

/* in doubt since (monotonic ms), 0 no longer: the manager sends on the
 * relay too meanwhile */
void path_direct_suspect(npf_call *c, int64_t since)
{
    c->pd.suspect = since;
    pm_health(&c->pm, &c->pd.p, since ? PH_SUSPECT : PH_UP);
}


/* ---- direct path check ----
 * Hearing the peer on the direct path does not prove that it hears us: with
 * a path that died one way (a firewall, a cut in a test) the peer's
 * datagrams still arrive while ours are lost, and the path was taken back
 * and the session lost (mesh.sh, 2026-10-06). While the path is suspect,
 * PATH_CHECK{nonce} goes out on it every 500 ms; the peer answers each on
 * the direct path with PATH_ECHO{nonce}. Only a matching echo, a round
 * trip over the path, brings it back. The packets are SIV-sealed with a
 * key of the session and the sender's direction: nobody else can make one,
 * and a reflected check is no echo. */
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
    else if (plain[0] == PKT_PATH_ECHO && c->pd.suspect && npf_rd64(plain + 2) == c->pd.nonce)
        c->pd.echo_ms = npf_mono_ms();
    return 1;
}


static void path_check_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->pd.t_check = NULL;
    if (!c->pd.suspect || c->ended)
        return;
    call_check_p2p(c);                           /* an echo, or the time is up (an idle session's AnLiu timer is far) */
    if (!c->pd.suspect || c->ended)
        return;
    path_send(c, PKT_PATH_CHECK, c->pd.nonce);
    c->pd.t_check = npf_timer_add(c->n->loop, PATH_CHECK_MS, path_check_timer, c);
}

/* the check both ways, every PATH_CHECK_MS from now on while in doubt (a
 * new nonce: only an echo of these counts) */
void path_direct_check(npf_call *c)
{
    npf_random(&c->pd.nonce, sizeof c->pd.nonce);
    if (!c->pd.t_check)
        path_check_timer(c->n->loop, c);
}


/* nat-traversal.md 10.3. A long queue on a loaded uplink can hold packets for
 * seconds, so silence alone does not prove the direct path dead: with
 * unacknowledged data and nothing heard for max(3 s, 2 RTO), send on both
 * paths (asking for a relay if it was released); give the direct path up
 * only if it stays silent for another 10 s. */
void call_check_p2p(npf_call *c)
{
    anl_stats st;
    int64_t now = npf_mono_ms(), quiet;
    if (!call_has_p2p(c) || c->direct || !c->anl || anl_get_stats(c->anl, &st) < 0)
        return;
    if (c->pd.suspect) {
        if (c->pd.echo_ms > c->pd.suspect) {
            path_direct_suspect(c, 0);
            if (c->pd.standby_check) {         /* both ways: now the relay may go */
                c->pd.standby_check = 0;
                call_standby_done(c->n->loop, c);
                return;
            }
            npf_log("call %s: direct path alive again (checked both ways)", c->call_id_s);
            pm_standby_start(c);
            return;
        }
        if (now - c->pd.suspect < P2P_DUAL_MS)
            return;
        npf_logw("call %s: direct path lost%s", c->call_id_s,
                 c->relay.active && c->relay.bound ? ", staying on the relay"
                 : c->relay.active && c->relay.t_bind ? ", the UDP relay still binding" : "");
        call_p2p_drop(c);
        anl_flush(c->anl);
        if (c->relay.active && !c->relay.bound && !c->relay.t_bind) {
            /* the UDP relay did not bind either (binding still: it asks for
             * the WS relay itself when it gives up) */
            npf_logw("call %s: no UDP relay bound: the WS relay", c->call_id_s);
            call_ask_ws_relay(c);
            return;
        }
        /* the platform plans the next round (at once: with no relay to fall
         * back on, an anonymous caller's session ends at AnLiu's idle timeout) */
        call_punch_report(c, "path_lost");
        return;
    }
    /* silence counts from the later of the last datagram heard and the moment
     * data went in flight: after an idle spell the first new request must not
     * look like a path that has been quiet all along. With nothing in flight
     * (a sender waiting for its peer's credit, an idle session) a peer that
     * is there still sends AnLiu's keepalive every 15 s: nothing for 20 s is
     * as suspect (measured: all of a node's UDP dropped mid-download, the
     * sender idle on credit, noticed only by the standby's check 22 s later) */
    if (st.inflight == 0) {
        c->pd.p.busy_since = 0;
        if (now - (c->pd.p.last_rx > c->pd.p.since ? c->pd.p.last_rx : c->pd.p.since) >= P2P_IDLE_SILENT_MS)
            call_p2p_suspect_start(c, "nothing from the peer on the direct path for 20 s");
        return;
    }
    if (!c->pd.p.busy_since)
        c->pd.p.busy_since = now;
    quiet = 2 * (int64_t)st.rto > P2P_SILENT_MS ? 2 * (int64_t)st.rto : P2P_SILENT_MS;
    if (now - (c->pd.p.last_rx > c->pd.p.busy_since ? c->pd.p.last_rx : c->pd.p.busy_since) < quiet)
        return;
    {
        char why[64];
        snprintf(why, sizeof why, "direct path silent for %lld ms", (long long)quiet);
        call_p2p_suspect_start(c, why);
    }
}

/* the direct path given up (lost, or the session moves to the WS relay) */
void call_p2p_drop(npf_call *c)
{
    path_direct_suspect(c, 0);
    c->pd.standby_check = 0;
    pm_del(&c->pm, &c->pd.p);
    npf_timer_stop(c->n->loop, &c->pd.t_check);
    npf_timer_stop(c->n->loop, &c->t_standby);
    if (c->pd.owned) {
        npf_loop_del(c->n->loop, c->pd.fd);
        npf_sock_close(c->pd.fd);
        c->pd.owned = 0;
    }
    c->pd.fd = -1;
}

/* the direct path is in doubt: checked both ways (PATH_CHECK), the data on
 * the relay too meanwhile (asked for when it was released) */
void call_p2p_suspect_start(npf_call *c, const char *why)
{
    path_direct_suspect(c, npf_mono_ms());
    path_direct_check(c);
    npf_timer_stop(c->n->loop, &c->t_standby);
    if (c->relay.active) {
        npf_log("call %s: %s, sending on the relay too", c->call_id_s, why);
        if (!c->relay.bound && !c->relay.t_bind) {
            /* it never bound (the direct path carried the session): bound
             * now, or the session had nothing left when the path went */
            npf_log("call %s: the UDP relay never bound: binding it again", c->call_id_s);
            call_relay_rebind(c);
        }
    } else if (call_relay_ask_ok(c)) {
        /* the relay was released after the standby: ask for a new allocation */
        char data[96];
        npf_log("call %s: %s, asking for a relay", c->call_id_s, why);
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"udp\"}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        call_relay_asked(c);
    }
    anl_flush(c->anl);
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
        if (call_anl_feed(c, buf, (size_t)r) == 0 && !c->ended)
            c->pd.p.last_rx = npf_mono_ms();
        if (c->ended)
            return;
    }
}

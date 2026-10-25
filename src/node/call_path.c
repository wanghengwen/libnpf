/* Calls: the direct path once it is up. Its check both ways (PATH_CHECK /
 * PATH_ECHO), the suspicion when it goes silent and the fall back to the
 * relay, the relay released when it held (nat-traversal.md 10.3). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define P2P_SILENT_MS      3000      /* nat-traversal.md 10.3; at least 2 x RTO */
#define P2P_DUAL_MS        10000     /* suspected path: send on both paths this long */
#define PKT_PATH_CHECK     10         /* direct path check (both directions work?) */
#define PKT_PATH_ECHO      11
#define PATH_CHECK_MS      500
/* tests: NPF_TEST_DROP_P2P=ms[:port] cuts the direct path that long after it
 * came up; with a port only the path to the peer on that port (many-to-many) */
int call_p2p_cut(const npf_call *c)
{
    int64_t cut = c->n->test_cut_ms;
    int port = c->n->test_cut_port;
    if (cut < 0 || !c->p2p || npf_mono_ms() - c->p2p_since <= cut)
        return 0;
    return !port || ntohs(c->p2p_addr.ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)&c->p2p_addr)->sin6_port
                                                             : ((const struct sockaddr_in *)&c->p2p_addr)->sin_port) == port;
}


/* no punching in this session: connect_mode secure on either side (relays
 * only, neither side's address goes to the other), or tests (NPF_NO_P2P) */
int call_no_p2p(const npf_call *c)
{
    return c->secure || getenv("NPF_NO_P2P") != NULL;
}


/* nat-traversal.md 10.3: unacknowledged data and nothing heard on the direct
 * path for 3 s while the relay is bound -> back to the relay, punch again later */
/* nat-traversal.md 10.3. A long queue on a loaded uplink can hold packets for
 * seconds, so silence alone does not prove the direct path dead: with
 * unacknowledged data and nothing heard for max(3 s, 2 RTO), send on both
 * paths (asking for a relay if it was released); give the direct path up
 * only if it stays silent for another 10 s. */
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
    if (!c->path_ready || !c->p2p || call_p2p_cut(c))
        return;
    p[0] = (uint8_t)type;
    p[1] = 0;
    npf_le64(p + 2, nonce);
    npf_siv_seal(&c->path_keys, c->caller ? 0 : 1, buf, 10);
    call_udp_send(c, c->p2p_fd, &c->p2p_addr, buf, sizeof buf);
}

/* 1 when the datagram was a path check or echo of this call */
int call_path_input(npf_call *c, const uint8_t *buf, size_t len)
{
    uint8_t plain[16];
    if (!c->path_ready || len != PATH_PKT_LEN || npf_siv_open(&c->path_keys, c->caller ? 1 : 0, buf, len, plain) < 0)
        return 0;
    if (plain[0] == PKT_PATH_CHECK)
        path_send(c, PKT_PATH_ECHO, npf_rd64(plain + 2));
    else if (plain[0] == PKT_PATH_ECHO && c->p2p_suspect && npf_rd64(plain + 2) == c->path_nonce)
        c->path_echo_ms = npf_mono_ms();
    return 1;
}


static void path_check_timer(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_pcheck = NULL;
    if (!c->p2p_suspect || c->ended)
        return;
    call_check_p2p(c);                           /* an echo, or the time is up (an idle session's AnLiu timer is far) */
    if (!c->p2p_suspect || c->ended)
        return;
    path_send(c, PKT_PATH_CHECK, c->path_nonce);
    c->t_pcheck = npf_timer_add(c->n->loop, PATH_CHECK_MS, path_check_timer, c);
}


/* nat-traversal.md 10.3 */
void call_check_p2p(npf_call *c)
{
    anl_stats st;
    int64_t now = npf_mono_ms(), quiet;
    if (!c->p2p || c->direct || !c->anl || anl_get_stats(c->anl, &st) < 0)
        return;
    if (c->p2p_suspect) {
        if (c->path_echo_ms > c->p2p_suspect) {
            c->p2p_suspect = 0;
            if (c->standby_check) {         /* both ways: now the relay may go */
                c->standby_check = 0;
                call_standby_done(c->n->loop, c);
                return;
            }
            npf_log("call %s: direct path alive again (checked both ways)", c->call_id_s);
            if (c->relay.active && !c->t_standby)
                c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
            return;
        }
        if (now - c->p2p_suspect < P2P_DUAL_MS)
            return;
        npf_logw("call %s: direct path lost%s", c->call_id_s,
                 c->relay.active && c->relay.bound ? ", staying on the relay"
                 : c->relay.active && c->relay.t_bind ? ", the UDP relay still binding" : "");
        c->p2p_suspect = 0;
        c->standby_check = 0;
        c->p2p = 0;
        if (c->p2p_owned) {
            npf_loop_del(c->n->loop, c->p2p_fd);
            npf_sock_close(c->p2p_fd);
            c->p2p_owned = 0;
        }
        c->p2p_fd = -1;
        anl_flush(c->anl);
        if (c->relay.active && !c->relay.bound && !c->relay.t_bind) {
            /* the UDP relay did not bind either (binding still: it asks for
             * the WS relay itself when it gives up) */
            npf_logw("call %s: no UDP relay bound: the WS relay", c->call_id_s);
            call_ask_ws_relay(c);
            return;
        }
        if (!c->relay.active && c->caller && !call_no_p2p(c)) {
            /* no relay to fall back on (an anonymous caller, D6): the only way
             * out is a new round now, before AnLiu's idle timeout ends the session */
            timer_stop(c->n->loop, &c->t_repunch);
            c->repunch_waiting = 0;
            c->punch_retries = 0;
            if (c->punch_requests < PUNCH_ROUNDS_MAX - 1)
                call_repunch_timer(c->n->loop, c);
            else
                npf_logw("call %s: %d punching rounds, no more", c->call_id_s, PUNCH_ROUNDS_MAX);
        } else {
            call_schedule_repunch(c);
        }
        return;
    }
    /* silence counts from the later of the last datagram heard and the moment
     * data went in flight: after an idle spell the first new request must not
     * look like a path that has been quiet all along */
    if (st.inflight == 0) {
        c->p2p_busy_since = 0;
        return;
    }
    if (!c->p2p_busy_since)
        c->p2p_busy_since = now;
    quiet = 2 * (int64_t)st.rto > P2P_SILENT_MS ? 2 * (int64_t)st.rto : P2P_SILENT_MS;
    if (now - (c->p2p_rx_ms > c->p2p_busy_since ? c->p2p_rx_ms : c->p2p_busy_since) < quiet)
        return;
    {
        char why[64];
        snprintf(why, sizeof why, "direct path silent for %lld ms", (long long)quiet);
        call_p2p_suspect_start(c, why);
    }
}

/* the direct path is in doubt: checked both ways (PATH_CHECK), the data on
 * the relay too meanwhile (asked for when it was released) */
void call_p2p_suspect_start(npf_call *c, const char *why)
{
    c->p2p_suspect = npf_mono_ms();
    npf_random(&c->path_nonce, sizeof c->path_nonce);
    if (!c->t_pcheck)
        path_check_timer(c->n->loop, c);
    timer_stop(c->n->loop, &c->t_standby);
    if (c->relay.active) {
        npf_log("call %s: %s, sending on the relay too", c->call_id_s, why);
        if (!c->relay.bound && !c->relay.t_bind) {
            /* it never bound (the direct path carried the session): bound
             * now, or the session had nothing left when the path went */
            npf_log("call %s: the UDP relay never bound: binding it again", c->call_id_s);
            call_relay_rebind(c);
        }
    } else if (!c->relay_asked) {
        /* the relay was released after the standby: ask for a new allocation */
        char data[96];
        npf_log("call %s: %s, asking for a relay", c->call_id_s, why);
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"mode\":\"udp\"}", c->call_id_s);
        npf_node_send(c->n, "relay_switch", 0, data);
        c->relay_asked = 1;
    }
    anl_flush(c->anl);
}

/* the direct path held for 30 s: stop using the relay; the caller tells the
 * platform to free both allocations (data-channel.md 3) */
void call_standby_done(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    char data[96];
    (void)loop;
    c->t_standby = NULL;
    if (!c->p2p || !c->relay.active)
        return;
    if (c->p2p_suspect) {   /* not while the direct path is in doubt */
        if (!c->standby_check)
            c->t_standby = npf_timer_add(c->n->loop, RELAY_STANDBY_MS, call_standby_done, c);
        return;
    }
    if (c->path_echo_ms < c->p2p_since) {
        /* the punch proved only that the peer's datagrams reach us (a path
         * cut one way still passes it): a path check answered over the direct
         * path first, else the session would lose the relay it still needs */
        c->standby_check = 1;
        c->p2p_suspect = npf_mono_ms();
        npf_random(&c->path_nonce, sizeof c->path_nonce);
        if (!c->t_pcheck)
            path_check_timer(c->n->loop, c);
        return;
    }
    c->relay.active = 0;
    c->relay.bound = 0;
    timer_stop(c->n->loop, &c->relay.t_bind);
    if (c->caller) {
        snprintf(data, sizeof data, "{\"call_id\":\"%s\"}", c->call_id_s);
        npf_node_send(c->n, "relay_release", 0, data);
    }
    npf_log("call %s: relay released", c->call_id_s);
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
            c->p2p_rx_ms = npf_mono_ms();
        if (c->ended)
            return;
    }
}

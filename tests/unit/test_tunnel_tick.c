/* The sublink's one timer (architecture.md 3.10): each state's deadline,
 * the timer at the earliest one, and what tunnel_sub_tick does at a given
 * time, called here with the times of the test's choosing (no waiting):
 * the peer's greeting, Happy Eyeballs' next address and the connection's
 * deadline, a lookup that never returns, -D's local greeting, a virtual
 * end closed by its owner and the peer's FIN that never comes. Every
 * state has a deadline or waits for an event, and the timer is never
 * later than the deadline. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/crypto.h"
#include "npf/tunnel.h"
#include "../../src/tunnel/tunnel_internal.h"
#include "test.h"

static npf_loop *loop;
static npf_policy pol;
static uint8_t data[4][16];             /* the last data messages out (their heads), [0] the latest */
static size_t dlen[4];
static uint8_t ctrl[16];                /* the last control unit out */
static char done_end[32];
static uint16_t lport;                  /* a listener nobody accepts from: the attempts stay pending */

static int w_ctrl(void *arg, const uint8_t *buf, size_t len)
{
    (void)arg;
    memcpy(ctrl, buf, len < sizeof ctrl ? len : sizeof ctrl);
    return 0;
}

static int w_data(void *arg, const uint8_t *msg, size_t len)
{
    (void)arg;
    memmove(data[1], data[0], 3 * sizeof data[0]);
    memmove(dlen + 1, dlen, 3 * sizeof dlen[0]);
    memcpy(data[0], msg, len < sizeof data[0] ? len : sizeof data[0]);
    dlen[0] = len;
    return 0;
}

static size_t backlog(void *arg) { (void)arg; return 0; }

static void sub_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    (void)arg;
    (void)id;
    snprintf(done_end, sizeof done_end, "%s", st->end);
}

/* "tick.test": three addresses of the listener; other names the system's */
static int resolve3(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens, int max)
{
    int i;
    (void)port;
    if (strcmp(host, "tick.test") != 0 || max < 3)
        return -1;
    for (i = 0; i < 3; i++) {
        struct sockaddr_in *a = (struct sockaddr_in *)&out[i];
        memset(&out[i], 0, sizeof out[i]);
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(lport);
        lens[i] = sizeof *a;
    }
    return 3;
}

static ssize_t v_read(void *arg, uint8_t *p, size_t n) { (void)arg; (void)p; (void)n; return -1; }
static ssize_t v_write(void *arg, const uint8_t *p, size_t n) { (void)arg; (void)p; return (ssize_t)n; }
static unsigned v_ready(void *arg) { (void)arg; return 0; }
static void v_shutdown(void *arg) { (void)arg; }
static void v_closed(void *arg, int reset) { (void)arg; (void)reset; }
static const npf_vend_io k_vend = {v_read, v_write, v_ready, v_shutdown, v_closed};

/* the timer is where the earliest deadline is, none without one */
static int armed(const sublink *s)
{
    int64_t d = tunnel_sub_due(s);
    return d == INT64_MAX ? s->t_due == NULL : s->t_due != NULL && s->due_at == d;
}

/* about now + ms (the deadline was set between t0 and now) */
static int near(int64_t at, int64_t t0, int ms)
{
    return at >= t0 + ms && at <= npf_mono_ms() + ms;
}

/* a SOCKS reply REP and then a FIN, the last two data messages, of sublink id */
static int replied(uint32_t id, uint8_t rep)
{
    return dlen[0] == 4 && npf_rd32(data[0]) == id && dlen[1] == 14 && npf_rd32(data[1]) == id && data[1][4] == 5
           && data[1][5] == rep;
}

static int reset_sent(uint32_t id, int reason)
{
    return ctrl[0] == NPF_CU_RESET && npf_rd32(ctrl + 3) == id && ctrl[7] == reason;
}

/* the callee: a peer's sublink through its greeting, request and connection */
static void server_side(npf_tunnel *t)
{
    uint8_t m[4 + 3 + 7 + 9 + 2] = {0, 0, 0, 0, 5, 1, 0, 5, 1, 0, 3, 9};
    sublink *s;
    sl_hs *h;
    int64_t t0 = npf_mono_ms(), he, at;

    npf_le32(m, 1);
    m[5] = 2;                           /* two methods announced, none sent */
    npf_tunnel_input_data(t, m, 6);
    s = tunnel_find(t, 1);
    CHECK(s && s->state == SL_SOCKS_GREETING && near(s->at, t0, npf_tunnel_greet_ms) && armed(s),
          "the peer's greeting: its deadline, the timer there");
    if (!s)
        return;
    CHECK(tunnel_sub_tick(s, s->at - 1) == 0 && npf_tunnel_count(t) == 1, "not due a ms before");
    CHECK(tunnel_sub_tick(s, s->at) < 0 && npf_tunnel_count(t) == 0 && reset_sent(1, NPF_RST_PROTOCOL),
          "due: reset (PROTOCOL)");

    /* greeting and request for a name of three addresses, together */
    m[5] = 1;
    memcpy(m + 4 + 3 + 5, "tick.test", 9);
    npf_be16(m + sizeof m - 2, 80);
    npf_le32(m, 3);
    t0 = npf_mono_ms();
    npf_tunnel_input_data(t, m, sizeof m);
    s = tunnel_find(t, 3);
    h = s ? s->hs : NULL;
    CHECK(h && s->state == SL_CONNECTING && h->ncfd == 1 && near(s->at, t0, 10000) && near(h->he_at, t0, 250)
              && tunnel_sub_due(s) == h->he_at && armed(s),
          "connecting: the first address, the next one's turn first, then the deadline");
    if (!h)
        return;
    he = h->he_at;
    at = s->at;
    CHECK(tunnel_sub_tick(s, he) == 0 && h->ncfd == 2 && h->he_at == he + 250 && s->at == at,
          "the next address's turn: the second attempt, the third in 250 ms");
    CHECK(armed(s), "the timer moved to the third one's turn");
    CHECK(tunnel_sub_tick(s, h->he_at) == 0 && h->ncfd == 3 && h->he_at == 0 && tunnel_sub_due(s) == at,
          "the third attempt: only the deadline left");
    CHECK(armed(s) && tunnel_sub_tick(s, at - 1) == 0 && npf_tunnel_count(t) == 1, "the deadline not yet");
    CHECK(tunnel_sub_tick(s, at) < 0 && npf_tunnel_count(t) == 0 && replied(3, 6),
          "the deadline: REP 6 (TTL expired), FIN, the attempts closed");

    /* a name the system resolves (its answer never taken: the loop does not
     * run here): the deadline from the lookup on */
    memcpy(m + 4 + 3 + 5, "localhost", 9);
    npf_le32(m, 5);
    t0 = npf_mono_ms();
    npf_tunnel_input_data(t, m, sizeof m);
    s = tunnel_find(t, 5);
    CHECK(s && s->state == SL_RESOLVING && s->resolve && near(s->at, t0, 10000) && armed(s),
          "resolving: the deadline");
    if (s)
        CHECK(tunnel_sub_tick(s, s->at) < 0 && npf_tunnel_count(t) == 0 && replied(5, 6),
              "a lookup that never returns: REP 6, FIN");
}

/* the caller: -D's local greeting, a virtual end its owner closed */
static void client_side(npf_tunnel *t)
{
    uint8_t g[3] = {5, 1, 0}, b[2], m[4 + 10] = {0};
    int sp[2], id;
    sublink *s;
    int64_t t0 = npf_mono_ms(), at;

    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    id = npf_tunnel_open(t, sp[0], 1, NULL, 0);
    s = id > 0 ? tunnel_find(t, (uint32_t)id) : NULL;
    CHECK(s && s->state == SL_LOCAL_GREETING && near(s->at, t0, npf_tunnel_greet_ms) && armed(s),
          "-D: the application's greeting, its deadline");
    if (!s)
        return;
    CHECK(write(sp[1], g, sizeof g) == 3, "the greeting");
    tunnel_io_cb(loop, sp[0], NPF_EV_READ, s);
    CHECK(recv(sp[1], b, 2, MSG_DONTWAIT) == 2 && s->state == SL_CLIENT_WAIT && !s->hs && !s->at
              && tunnel_sub_due(s) == INT64_MAX && armed(s),
          "answered: waiting for the server's replies (an event), no deadline, no timer");
    npf_tunnel_sub_reset(t, (uint32_t)id, "test");
    close(sp[1]);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    id = npf_tunnel_open(t, sp[0], 1, NULL, 0);
    s = id > 0 ? tunnel_find(t, (uint32_t)id) : NULL;
    if (s)
        CHECK(tunnel_sub_tick(s, s->at) < 0 && npf_tunnel_count(t) == 0 && !strcmp(done_end, "greeting_timeout")
                  && recv(sp[1], b, 1, MSG_DONTWAIT) <= 0,
              "no greeting by the deadline: the application closed (%s)", done_end);
    close(sp[1]);

    /* a virtual end closed (not reset) by its owner: the peer's FIN awaited */
    id = npf_tunnel_open_v(t, &k_vend, NULL, "127.0.0.1", 80);
    s = id > 0 ? tunnel_find(t, (uint32_t)id) : NULL;
    CHECK(s && s->vend == VE_NONE && tunnel_sub_due(s) == INT64_MAX && armed(s), "a virtual end: no deadline");
    if (!s)
        return;
    npf_tunnel_vclose(t, (uint32_t)id, 0);
    CHECK(s->vend == VE_CLOSED && t->ngone == 1, "closed by its owner: for the next poll");
    t0 = npf_mono_ms();
    npf_loop_once(loop, 0);
    CHECK(s->vend == VE_GONE && t->ngone == 0 && s->local_eof && near(s->at, t0, 30000) && armed(s)
              && dlen[0] == 4 && npf_rd32(data[0]) == (uint32_t)id,
          "polled: FIN sent, the peer's FIN awaited till the deadline");
    at = s->at;
    npf_le32(m, (uint32_t)id);
    npf_tunnel_input_data(t, m, sizeof m);
    CHECK(npf_tunnel_count(t) == 1 && s->rx_freed == 10 && s->at == at, "the peer's data meanwhile: dropped");
    CHECK(tunnel_sub_tick(s, at - 1) == 0 && npf_tunnel_count(t) == 1, "not yet");
    CHECK(tunnel_sub_tick(s, at) < 0 && npf_tunnel_count(t) == 0 && reset_sent((uint32_t)id, NPF_RST_TIMEOUT)
              && !strcmp(done_end, "local_reset"),
          "no FIN by the deadline: reset (TIMEOUT, %s)", done_end);

    /* the FIN comes: the sublink goes, its timer with it */
    id = npf_tunnel_open_v(t, &k_vend, NULL, "127.0.0.1", 80);
    npf_tunnel_vclose(t, (uint32_t)id, 0);
    npf_loop_once(loop, 0);
    s = tunnel_find(t, (uint32_t)id);
    CHECK(s && s->vend == VE_GONE && s->t_due, "another one waits for the FIN");
    npf_le32(m, (uint32_t)id);
    npf_tunnel_input_data(t, m, 4);
    CHECK(npf_tunnel_count(t) == 0, "its FIN: released");
}

int test_tunnel_tick(void)
{
    static const npf_tunnel_io io = {w_ctrl, w_data, backlog, NULL, NULL, NULL, NULL, NULL, sub_done, NULL};
    struct sockaddr_in a;
    npf_tunnel *callee, *caller;
    int lfd;
    loop = npf_loop_new();
    memset(&pol, 0, sizeof pol);
    npf_policy_add(&pol, "lan");
    npf_policy_refresh(&pol);
    lfd = lo_socket(SOCK_STREAM, 8, &a, sizeof a);
    lport = ntohs(a.sin_port);
    npf_tunnel_test_resolve = resolve3;
    callee = npf_tunnel_new(loop, 0, &io, NULL, &pol);
    caller = npf_tunnel_new(loop, 1, &io, NULL, NULL);
    npf_tunnel_start(callee);
    npf_tunnel_start(caller);
    npf_tunnel_open_early(caller);
    server_side(callee);
    client_side(caller);
    npf_tunnel_free(callee);
    npf_tunnel_free(caller);
    npf_tunnel_test_resolve = NULL;
    close(lfd);
    npf_loop_free(loop);
    return fails;
}

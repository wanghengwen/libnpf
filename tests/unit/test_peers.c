/* Public mappings and the application's callbacks, on an offline node (a
 * direct peer on demand: its session never comes up here):
 * - a connection whose admission (the opened callback) removed the mapping
 *   is closed at once and reported refused (mapping_closed), not left to
 *   wait for the session on the forward no longer used;
 * - a waiting connection refused when its mapping goes, whose refusal's
 *   callback removes the peer (the waiting queue dropped again from inside
 *   its own drop): each told once and closed once (a descriptor the
 *   callback opened, taking the number, stays open);
 * - direct peers by name: looked up off the loop thread (npf/resolve.h), a
 *   name with an IPv6 address only connects from the IPv6 main socket, a
 *   name without an address (or only IPv6 and no IPv6 socket) ends the peer
 *   "unreachable", a peer removed during its lookup hears nothing of it;
 * - the peer's and its forwards' states and their one timer (architecture.md
 *   3.9), by the test's clock (peer_tick): retry with backoff, retry_now,
 *   ONCE, a wake, on demand, the login's spread, a forward retried, drained,
 *   -R waiting, the network change; removal (again, from its done callback)
 *   freed at the next turn. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf.h"
#include "npf/node.h"
#include "npf/peers.h"
#include "npf/platform.h"
#include "npf/resolve.h"
#include "call_internal.h"
#include "peers_internal.h"
#include "test.h"

#ifdef NPF_NO_PEERS
int test_peers(void) { return 0; }
#else
static npf_peers *ps;
static int opened, refused, refused_opened, del_in_opened, canary = -1;
static char refused_why[32];
static int done;
static char done_why[32];

static void on_done(npf_peer *p, const char *why, void *arg)
{
    (void)p, (void)arg;
    done++;
    snprintf(done_why, sizeof done_why, "%s", why);
}

/* the fake DNS (on the resolver's threads): v6.example has ::1 only,
 * slow.example answers once let go, the rest have no address */
static int g_hold;
static int fake_gai(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    struct addrinfo h = *hints;
    h.ai_flags |= AI_NUMERICHOST;
    if (strcmp(node, "v6.example") == 0)
        return getaddrinfo("::1", service, &h, res);
    while (strcmp(node, "slow.example") == 0 && __atomic_load_n(&g_hold, __ATOMIC_SEQ_CST))
        npf_sleep_ms(2);
    *res = NULL;
    return EAI_NONAME;
}

/* a direct peer to host:port, ONCE, started */
static npf_peer *direct_peer(const char *host, int port)
{
    static const uint8_t psk[32] = {9};
    npf_peer_new pn = {.host = host, .port = (uint16_t)port, .psk = psk, .connect = NPF_CONNECT_ONCE};
    char err[128];
    npf_peer *p = npf_peers_create(ps, &pn, err, sizeof err, NULL);
    CHECK(p != NULL, "a direct peer at %s (%s)", host, p ? "" : err);
    if (p)
        npf_peer_start(p);
    return p;
}

static void test_names(npf_loop *loop, npf_node *node)
{
    static npf_node L;
    static const uint8_t psk[32] = {9};
    npf_resolve_gai_fn saved = npf_resolve_gai;
    npf_direct *dl = NULL;
    npf_peer *p;
    char spec[32];
    int port = 20000 + (int)npf_rand_range(0, 20000), fd6 = node->udp6_fd, i;
    npf_resolve_gai = fake_gai;

    /* v6.example: ::1, from the IPv6 main socket, to a listener there */
    snprintf(spec, sizeof spec, "[::1]:%d", port);
    if (offline_node(&L, loop, NULL, NULL) == 0)
        dl = npf_direct_listen(&L, spec, psk, NULL);
    if (!dl || fd6 < 0) {
        printf("  note: no IPv6 loopback here: the name's IPv6 session not tried\n");
    } else if ((p = direct_peer("v6.example", port))) {
        CHECK(npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTING && p->st == PS_ASKING && !p->call,
              "the name being looked up: connecting, no session yet");
        LOOP_UNTIL(loop, npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTED, 3000);
        CHECK(npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTED && p->call && p->call->pd.fd == fd6,
              "v6.example: a session from the IPv6 socket");
        npf_peers_remove(ps, p);
    }

    /* no IPv6 socket: v6.example has no address it can reach */
    done = 0;
    node->udp6_fd = -1;
    p = direct_peer("v6.example", port);
    LOOP_UNTIL(loop, done, 3000);
    CHECK(done == 1 && strcmp(done_why, "unreachable") == 0 && p && npf_peer_state(p, NULL, NULL) == NPF_PEER_ENDED,
          "no IPv6 socket: ended unreachable (%d %s)", done, done_why);
    if (p)
        npf_peers_remove(ps, p);
    node->udp6_fd = fd6;

    /* no address: ended unreachable */
    done = 0;
    p = direct_peer("none.example", port);
    LOOP_UNTIL(loop, done, 3000);
    CHECK(done == 1 && strcmp(done_why, "unreachable") == 0, "no address: ended unreachable (%d %s)", done, done_why);
    if (p)
        npf_peers_remove(ps, p);

    /* removed while its lookup runs: the lookup cancelled, nothing heard */
    done = 0;
    __atomic_store_n(&g_hold, 1, __ATOMIC_SEQ_CST);
    p = direct_peer("slow.example", port);
    CHECK(p && p->rs && p->st == PS_ASKING, "a lookup running");
    if (p)
        npf_peers_remove(ps, p);
    __atomic_store_n(&g_hold, 0, __ATOMIC_SEQ_CST);
    for (i = 0; i < 500 && npf_resolve_active() > 0; i++)
        npf_loop_once(loop, 2);
    npf_loop_once(loop, 10);
    CHECK(npf_resolve_active() == 0 && done == 0, "removed during its lookup: nothing heard of it");

    npf_resolve_gai = saved;
    npf_direct_close(dl);
    npf_node_stop(&L);
}

static void on_opened(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, void *arg)
{
    (void)mapping; (void)port; (void)from; (void)arg;
    opened++;
    if (del_in_opened)
        npf_peer_forward_del_at(p, 0);      /* the mapping goes meanwhile */
}

static void on_refused(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                       const char *why, int was_opened, void *arg)
{
    (void)mapping; (void)port; (void)from; (void)arg;
    refused++;
    refused_opened = was_opened;
    snprintf(refused_why, sizeof refused_why, "%s", why);
    if (!del_in_opened && p) {
        canary = socket(AF_INET, SOCK_DGRAM, 0);    /* the descriptor just closed, most likely */
        npf_peers_remove(ps, p);            /* the application lets the peer go */
    }
}

/* the client sees its connection's end (EOF): on loopback Linux delivers the
 * FIN within the close, macOS a moment later (its network input thread) */
static int eof_seen(int fd)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    char b;
    return fd >= 0 && poll(&pfd, 1, 2000) == 1 && recv(fd, &b, 1, MSG_DONTWAIT) == 0;
}

/* a peer with a public mapping, and a connection to it (its fd) */
static int mapped(npf_loop *loop, npf_peer **pp, int port)
{
    static const uint8_t psk[32] = {7};
    npf_peer_new pn = {.host = "127.0.0.1", .port = (uint16_t)port, .psk = psk, .connect = NPF_CONNECT_ON_DEMAND};
    npf_fwd_new fn = {.opt = 'L', .port = 0, .host = "127.0.0.1", .hostport = 80};
    npf_fwd_state st = {0};
    struct sockaddr_in a;
    char err[128];
    int code, fd;
    npf_peer *p = npf_peers_create(ps, &pn, err, sizeof err, &code);
    CHECK(p && npf_peer_forward_add_parts(p, &fn, 0, 42, err, sizeof err) == 0
              && npf_peer_forward_set_public(p, 0, NULL, 0, 0) == 0, "a public mapping (%s)", p ? err : "");
    if (!p)
        return -1;
    npf_peer_start(p);
    LOOP_UNTIL(loop, npf_peer_forward_state(p, 0, &st) >= 0 && st.lport, 250);
    CHECK(st.lport > 0, "it listens");
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)st.lport);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0, "connected");
    LOOP_UNTIL(loop, opened, 250);
    *pp = p;
    return fd;
}

/* ---- the peer's and its forwards' states (architecture.md 3.9) ---- */

static npf_peers *sps;
static int remove_in_done;

static void st_hook(npf_node *n, npf_call *c, int st, const char *why, void *arg)
{
    (void)n, (void)arg;
    npf_peers_on_call_state(sps, c, st, why);
}

static void st_done(npf_peer *p, const char *why, void *arg)
{
    on_done(p, why, arg);
    if (remove_in_done)
        npf_peers_remove(sps, p);
}

/* after each step: a state waiting for a time has its deadline, and the
 * peer's one timer is no later than its earliest deadline */
static void due_ok(const npf_peer *p, const char *step)
{
    int64_t d = peer_due(p);
    CHECK(!peer_waits(p) || (p->retry_at && d <= p->retry_at),
          "%s: waiting to (re)start, with its deadline", step);
    CHECK(d == INT64_MAX || (npf_timer_pending(&p->t_due) && p->due_at <= d), "%s: the timer no later than the deadline", step);
}

/* the session ends (the peer hears it closed) */
static void end_call(npf_peer *p, const char *why)
{
    CHECK(p->st == PS_CALL && p->call, "%s: a session to end (%d)", why, p->st);
    if (p->call)
        npf_call_end(p->call, why);
}

static void test_states(npf_loop *loop)
{
    static npf_node node;
    static const uint8_t psk[32] = {5};
    static const npf_node_hooks hooks = {.on_call_state = st_hook};
    static const npf_peers_cbs cbs = {.done = st_done};
    struct sockaddr_in a, b;
    npf_peer_new pn = {.host = "127.0.0.1", .psk = psk, .connect = NPF_CONNECT_KEEP};
    npf_fwd_new fn = {.opt = 'L', .host = "127.0.0.1", .hostport = 80};
    npf_peer_new pp = {.number = 4242, .connect = NPF_CONNECT_KEEP};
    npf_fwd_state fs;
    npf_peer *p, *q, *r;
    char err[128];
    int ms, i, n0;
    int64_t at, d1;
    int sink = lo_socket(SOCK_DGRAM, 0, &a, sizeof a);   /* the direct peer: never answers */
    int block = lo_socket(SOCK_STREAM, 4, &b, sizeof b); /* a port taken */

    CHECK(sink >= 0 && block >= 0 && offline_node(&node, loop, &hooks, NULL) == 0, "states: set-up");
    if (sink < 0 || block < 0 || !(sps = npf_peers_new(&node, NULL, &cbs, NULL)))
        return;
    pn.port = ntohs(a.sin_port);

    /* a platform peer, offline: waits for the login, no deadline */
    q = npf_peers_create(sps, &pp, err, sizeof err, NULL);
    CHECK(q != NULL, "a platform peer (%s)", err);
    if (!q)
        return;
    npf_peer_start(q);
    CHECK(q->st == PS_IDLE && npf_peer_state(q, NULL, NULL) == NPF_PEER_WAITING && peer_due(q) == INT64_MAX,
          "offline: idle, waiting for the server, no deadline");

    /* a direct one, kept: a session at once */
    p = npf_peers_create(sps, &pn, err, sizeof err, NULL);
    CHECK(p != NULL, "a direct peer (%s)", err);
    if (!p)
        return;
    npf_peer_start(p);
    CHECK(p->st == PS_CALL && npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTING, "started: a session, connecting");

    /* it ends: reconnecting after 1 s +-25 % */
    end_call(p, "transport_lost");
    CHECK(p->st == PS_RETRY && !p->call && npf_peer_state(p, NULL, &ms) == NPF_PEER_RETRY && ms > 0 && ms <= 1250
              && strcmp(p->last_why, "transport_lost") == 0, "ended: retry in %d ms (%s)", ms, p->last_why);
    due_ok(p, "retry");
    d1 = p->retry_at;
    peer_tick(p, d1 - 1);
    CHECK(p->st == PS_RETRY, "1 ms before: still waiting");
    peer_tick(p, d1);
    CHECK(p->st == PS_CALL, "at the deadline: a session again");
    due_ok(p, "again");

    /* the second time the delay doubles; an account session tries now */
    end_call(p, "closed");
    CHECK(p->st == PS_RETRY && p->retry_at - npf_mono_ms() > 1250, "backoff: about 2 s now");
    npf_peers_retry_now(sps);
    CHECK(p->st == PS_CALL && q->st == PS_IDLE, "retry_now: the waiting one tries at once (the offline one waits)");

    /* waiting to retry, made ONCE: ended now, told once */
    end_call(p, "closed");
    done = 0;
    npf_peer_connect_put(p, NPF_CONNECT_ONCE, 0, 1);
    CHECK(p->st == PS_ENDED && done == 1 && strcmp(done_why, "closed") == 0 && peer_due(p) == INT64_MAX
              && npf_peer_state(p, NULL, NULL) == NPF_PEER_ENDED, "ONCE while waiting: ended (%d %s)", done, done_why);
    npf_peer_connect_put(p, NPF_CONNECT_ONCE, 0, 1);
    CHECK(done == 1, "ended once");

    /* woken: one more try; ONCE: its end ends the peer */
    npf_peer_wake_now(p);
    CHECK(p->st == PS_CALL, "woken: a session");
    end_call(p, "closed");
    CHECK(p->st == PS_ENDED && done == 2, "ONCE: its session's end ends it");

    /* KEEP again: a session now; on demand: no reconnecting, the idle check runs */
    npf_peer_connect_put(p, NPF_CONNECT_KEEP, 0, 1);
    CHECK(p->st == PS_CALL, "KEEP: a session again");
    npf_peer_connect_put(p, NPF_CONNECT_ON_DEMAND, 60000, 1);
    CHECK(p->st == PS_CALL && p->demand_at, "on demand with a session: the idle check set");
    due_ok(p, "on demand");
    end_call(p, "closed");
    CHECK(p->st == PS_IDLE && npf_peer_state(p, NULL, NULL) == NPF_PEER_IDLE && !(peer_due(p) < INT64_MAX && !p->demand_at),
          "on demand: idle after its session, no retry");
    npf_peer_wake_now(p);
    CHECK(p->st == PS_CALL, "on demand, woken: a session");

    /* forwards: a name to listen on is refused when the forward is made (no
     * DNS on the loop thread) */
    fn.bind = "localhost.example";
    i = npf_peer_forward_add_parts(p, &fn, 0, 0, err, sizeof err);
    CHECK(i < 0 && strstr(err, "not a name") && p->nfwd == 0, "a name to listen on: refused (%s)", err);
    fn.bind = NULL;

    /* the port taken, retried with backoff by the peer's tick */
    fn.port = ntohs(b.sin_port);
    i = npf_peer_forward_add_parts(p, &fn, 0, 0, err, sizeof err);
    CHECK(i >= 0 && npf_peer_forward_state(p, i, &fs) == 0 && fs.state == NPF_FWD_FAILED
              && fs.why_code == NPF_FWD_WHY_PORT_IN_USE && p->fwds[i]->st == FS_RETRY,
          "a forward on a taken port: failed, to retry (%s)", i < 0 ? err : fs.why);
    if (i < 0)
        return;
    due_ok(p, "forward retry");
    CHECK(peer_due(p) <= p->fwds[i]->retry_at, "the forward's retry is the peer's deadline");
    close(block);
    peer_tick(p, p->fwds[i]->retry_at - 1);
    CHECK(p->fwds[i]->st == FS_RETRY, "1 ms before: still waiting");
    peer_tick(p, p->fwds[i]->retry_at);
    CHECK(p->fwds[i]->st == FS_UP && npf_peer_forward_state(p, i, &fs) == 0 && fs.state == NPF_FWD_UP && fs.lport == fn.port,
          "at its deadline: up on the freed port");

    /* a public mapping drained: suspended, then up again */
    CHECK(npf_peer_forward_set_public(p, i, NULL, 0, 0) == 0 && npf_peer_forward_drain(p, i, 1) == 0, "drain on");
    CHECK(npf_peer_forward_drained(p, i) == 1 && p->fwds[i]->st == FS_SUSPENDED && p->fwds[i]->fd < 0
              && npf_peer_forward_state(p, i, &fs) == 0 && fs.state == NPF_FWD_WAITING, "drained: suspended, closed");
    npf_peer_forward_drain(p, i, 0);
    CHECK(p->fwds[i]->st == FS_UP && p->fwds[i]->fd >= 0, "drain off: listening again");

    /* -R waits for an established session; the network change retries a
     * failed forward at once */
    fn.opt = 'R';
    fn.port = 0;
    npf_peer_connect_put(p, NPF_CONNECT_KEEP, 0, 1);
    i = npf_peer_forward_add_parts(p, &fn, 0, 0, err, sizeof err);
    CHECK(i >= 0 && p->fwds[i]->st == FS_WAIT && npf_peer_forward_state(p, i, &fs) == 0
              && strcmp(fs.text, "waiting for the session") == 0, "-R: waiting for the session (%s)", i < 0 ? err : fs.text);
    block = lo_socket(SOCK_STREAM, 4, &b, sizeof b);
    fn.opt = 'L';
    fn.port = ntohs(b.sin_port);
    i = npf_peer_forward_add_parts(p, &fn, 0, 0, err, sizeof err);
    CHECK(i >= 0 && p->fwds[i]->st == FS_RETRY, "another on a taken port: to retry");
    if (i >= 0) {
        at = p->fwds[i]->retry_at;
        close(block);
        npf_peers_net_changed(sps);
        CHECK(p->fwds[i]->st == FS_UP, "the network changed: tried now, up (was due in %lld ms)",
              (long long)(at - npf_mono_ms()));
    }

    /* at the login, several platform peers start spread over 2 s */
    r = npf_peers_create(sps, &(npf_peer_new){.number = 4343, .connect = NPF_CONNECT_KEEP}, err, sizeof err, NULL);
    CHECK(r != NULL, "a second platform peer (%s)", err);
    node.online = 1;
    node.th.no_spread = 0;
    npf_peers_on_login(sps);
    node.online = 0;
    CHECK(q->st == PS_START && r && r->st == PS_START && npf_peer_state(q, NULL, NULL) == NPF_PEER_WAITING
              && q->retry_at - npf_mono_ms() <= 2000, "login: both start spread, still waiting for the server");
    due_ok(q, "spread");
    peer_tick(q, q->retry_at);
    CHECK(q->st == PS_IDLE, "its time, offline again: idle until the next login");
    npf_peers_retry_now(sps);
    CHECK(r && r->st == PS_IDLE, "retry_now: the spread one tried now (offline: idle)");

    /* removed: freed at the next turn, once; a callback's removal too */
    n0 = npf_peers_count(sps);
    npf_peers_remove(sps, q);
    CHECK(q->st == PS_REMOVED && peer_due(q) == 0 && npf_timer_pending(&q->t_due) && npf_peers_count(sps) == n0 - 1,
          "removed: its timer due now");
    npf_peers_remove(sps, q);
    CHECK(sps->gone == q && !q->gone_next, "removed again: nothing more");
    npf_peer_wake_now(q);
    npf_peer_connect_put(q, NPF_CONNECT_KEEP, 0, 1);
    CHECK(q->st == PS_REMOVED, "removed: nothing starts it again");
    npf_peer_connect_put(p, NPF_CONNECT_ONCE, 0, 1);
    remove_in_done = 1;
    end_call(p, "closed");
    remove_in_done = 0;
    CHECK(p->st == PS_REMOVED && done == 3, "removed in its done callback");
    for (i = 0; i < 5 && sps->gone; i++)
        npf_loop_once(loop, 1);
    CHECK(!sps->gone && npf_peers_count(sps) == 1, "freed at the next turn (%d left)", npf_peers_count(sps));

    npf_peers_free(sps);
    sps = NULL;
    close(sink);
    npf_node_stop(&node);
}

int test_peers(void)
{
    static npf_node node;
    static const npf_peers_cbs cbs = {.done = on_done, .refused = on_refused, .opened = on_opened};
    npf_loop *loop = npf_loop_new();
    npf_peer *p = NULL;
    int fd, i;

    CHECK(offline_node(&node, loop, NULL, NULL) == 0, "peers: set-up");
    if (fails || !(ps = npf_peers_new(&node, NULL, &cbs, NULL)))
        return fails + 1;

    del_in_opened = 1;
    fd = mapped(loop, &p, 9);
    LOOP_UNTIL(loop, refused, 250);
    CHECK(opened == 1 && refused == 1 && refused_opened && strcmp(refused_why, "mapping_closed") == 0,
          "removed by opened: refused once, as opened, mapping_closed (%d, %d, %s)", opened, refused, refused_why);
    CHECK(eof_seen(fd), "the connection closed");
    CHECK(ps->nconns == 0 && p && p->npend == 0, "not waiting for the session, not counted (%d, %d)", ps->nconns,
          p ? p->npend : -1);
    if (fd >= 0)
        close(fd);

    del_in_opened = opened = refused = 0;
    fd = mapped(loop, &p, 10);
    CHECK(opened == 1 && p && p->npend == 1, "a connection waits for the session (%d)", p ? p->npend : -1);
    if (p)
        npf_peer_forward_del_at(p, 0);      /* refused: its callback removes the peer */
    CHECK(refused == 1 && ps->nconns == 0 && npf_peers_count(ps) == 1, "the mapping gone, the peer removed in its "
          "refusal: told once (%d), not counted (%d)", refused, ps->nconns);
    CHECK(eof_seen(fd), "the waiting connection closed");
    CHECK(canary >= 0 && fcntl(canary, F_GETFD) >= 0, "closed once: a descriptor opened in the callback stays");
    if (canary >= 0)
        close(canary);
    if (fd >= 0)
        close(fd);
    for (i = 0; i < 5; i++)
        npf_loop_once(loop, 1);             /* the removed peer freed */
    test_names(loop, &node);
    for (i = 0; i < 5; i++)
        npf_loop_once(loop, 1);
    test_states(loop);
    npf_peers_free(ps);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}
#endif

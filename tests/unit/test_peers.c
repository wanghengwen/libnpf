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
 *   "unreachable", a peer removed during its lookup hears nothing of it. */
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
        CHECK(npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTING && p->waiting && !p->call,
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
    CHECK(p && p->rs && p->waiting, "a lookup running");
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
    npf_peers_free(ps);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}
#endif

/* A public mapping's connection whose admission (the opened callback)
 * removed the mapping: closed at once and reported refused
 * (mapping_closed), not waiting for the session (it went on, on the forward
 * no longer used). On an offline node, a direct peer on demand. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf.h"
#include "npf/node.h"
#include "npf/peers.h"
#include "npf/platform.h"
#include "peers_internal.h"

#ifdef NPF_NO_PEERS
int test_peers(void) { return 0; }
#else
static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static int opened, refused, refused_opened;
static char refused_why[32];

static void on_opened(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, void *arg)
{
    (void)mapping; (void)port; (void)from; (void)arg;
    opened++;
    npf_peer_forward_del_at(p, 0);          /* the mapping goes meanwhile */
}

static void on_refused(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                       const char *why, int was_opened, void *arg)
{
    (void)p; (void)mapping; (void)port; (void)from; (void)arg;
    refused++;
    refused_opened = was_opened;
    snprintf(refused_why, sizeof refused_why, "%s", why);
}

int test_peers(void)
{
    static npf_node node;
    static const npf_peers_cbs cbs = {.refused = on_refused, .opened = on_opened};
    static const uint8_t psk[32] = {7};
    npf_loop *loop = npf_loop_new();
    npf_node_cfg cfg;
    npf_node_hooks hooks;
    npf_identity id;
    npf_peers *ps;
    npf_peer *p;
    npf_peer_new pn = {.host = "127.0.0.1", .port = 9, .psk = psk, .connect = NPF_CONNECT_ON_DEMAND};
    npf_fwd_new fn = {.opt = 'L', .port = 0, .host = "127.0.0.1", .hostport = 80};
    npf_fwd_state st;
    struct sockaddr_in a;
    char err[128], b;
    uint8_t seed[32];
    int code, fd, i;

    memset(&cfg, 0, sizeof cfg);
    memset(&hooks, 0, sizeof hooks);
    cfg.offline = 1;
    npf_random(seed, 32);
    npf_identity_from_seed(&id, seed);
    CHECK(loop && npf_node_init(&node, loop, &cfg, &id, &hooks, NULL) == 0, "peers: set-up");
    if (fails)
        return fails;
    ps = npf_peers_new(&node, NULL, &cbs, NULL);
    p = ps ? npf_peers_create(ps, &pn, err, sizeof err, &code) : NULL;
    CHECK(p && npf_peer_forward_add_parts(p, &fn, 0, 42, err, sizeof err) == 0
              && npf_peer_forward_set_public(p, 0, NULL, 0, 0) == 0, "a public mapping (%s)", p ? err : "");
    npf_peers_start(ps);
    for (i = 0; i < 50 && p && (npf_peer_forward_state(p, 0, &st) < 0 || !st.lport); i++)
        npf_loop_once(loop, 5);
    CHECK(p && st.lport > 0, "it listens");
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)st.lport);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0, "connected");
    for (i = 0; i < 50 && !refused; i++)
        npf_loop_once(loop, 5);
    CHECK(opened == 1 && refused == 1 && refused_opened && strcmp(refused_why, "mapping_closed") == 0,
          "removed by opened: refused once, as opened, mapping_closed (%d, %d, %s)", opened, refused, refused_why);
    CHECK(fd >= 0 && recv(fd, &b, 1, MSG_DONTWAIT) == 0, "the connection closed");
    CHECK(ps && ps->nconns == 0 && p && p->npend == 0, "not waiting for the session, not counted (%d, %d)",
          ps ? ps->nconns : -1, p ? p->npend : -1);
    if (fd >= 0)
        close(fd);
    npf_peers_free(ps);
    npf_node_stop(&node);
    npf_loop_free(loop);
    return fails;
}
#endif

/* The node's UDP sockets and the platform's hook (sys.h): the hook sees each
 * one while it is on, none when off or for other sockets; a failing hook
 * leaves a working socket. Without one, the built-in VPN bypass: no VPN here,
 * nothing bound; tunnel interface names known; a listening UDP port is
 * never shared (npf_sock_listen_opts); the main sockets' send watches
 * (npf_udp_watch). The test switches (npf/testhooks.h):
 * unset, empty and 0 are off. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/node.h"
#include "npf/testhooks.h"
#include "test.h"

static int seen, last_fd, last_family, answer;

static int hook(int fd, int family, void *arg)
{
    seen++;
    last_fd = fd;
    last_family = family;
    *(int *)arg += 1;
    return answer;
}

#ifdef __linux__
/* npf_sock_tcp_diag on a connected loopback socket: its queues, empty */
static void tcp_diag(void)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    char d[200];
    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(l >= 0 && c >= 0 && bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0
          && getsockname(l, (struct sockaddr *)&a, &al) == 0 && connect(c, (struct sockaddr *)&a, sizeof a) == 0,
          "a loopback TCP connection");
    npf_sock_tcp_diag(c, d, sizeof d);
    {
        static const char want[] = "kernel send queue 0 B (0 unsent), 0 segments unacked";
        CHECK(strncmp(d, want, sizeof want - 1) == 0, "TCP diag: %s", d);
    }
    close(c);
    close(l);
}
#endif

/* npf_udp_watch: six on one thread (a shared runtime's nodes), each sees
 * its own socket's sends only; stopped, it sees none; one stopped again
 * after its socket's number went to another's does not stop that one */
static void udp_watch(void)
{
    npf_udp_watch w[6];
    struct sockaddr_in to;
    int fd[6], i, ok = 1, fresh;
    memset(w, 0, sizeof w);
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons(9);
    for (i = 0; i < 6; i++) {
        fd[i] = socket(AF_INET, SOCK_DGRAM, 0);
        w[i].fd = -1;
        w[i].mode = NPF_WATCH_ANY;
        npf_udp_watch_on(&w[i], fd[i]);
    }
    npf_udp_send(fd[5], "x", 1, &to);
    for (i = 0; i < 6; i++)
        ok = ok && (i == 5) == (w[i].other != 0);
    CHECK(ok, "six watches on a thread: the sending socket's only");
    for (i = 0; i < 6; i++)
        npf_udp_send(fd[i], "x", 1, &to);
    for (i = 0; i < 6; i++)
        ok = ok && w[i].other != 0;
    CHECK(ok, "every one of them sees its socket");
    npf_udp_watch_on(&w[0], -1);
    w[0].other = 0;
    npf_udp_send(fd[0], "x", 1, &to);
    CHECK(w[0].other == 0 && w[0].fd == -1, "a stopped watch sees nothing");
    npf_sock_close(fd[0]);
    fresh = socket(AF_INET, SOCK_DGRAM, 0);          /* most likely fd[0]'s number */
    npf_udp_watch_on(&w[1], fresh);
    npf_udp_watch_on(&w[0], -1);                     /* stopped again (the old node's stop) */
    w[1].other = 0;
    npf_udp_send(fresh, "x", 1, &to);
    CHECK(w[1].other != 0, "stopping one again leaves the watch of another on its old number");
    for (i = 0; i < 6; i++)
        npf_udp_watch_on(&w[i], -1);
    npf_sock_close(fresh);
    for (i = 1; i < 6; i++)
        npf_sock_close(fd[i]);
}

int test_sys(void)
{
    int arg = 0, fd;
#ifdef __linux__
    tcp_diag();
#endif
    udp_watch();
    {   /* npf_abspath: out empty when it does not fit */
        char out[8];
        errno = 0;
        CHECK(npf_abspath("/a/rather/long/path", out, sizeof out) < 0 && out[0] == 0 && errno == ENAMETOOLONG,
              "npf_abspath too long: out empty, ENAMETOOLONG");
        CHECK(npf_abspath("/a", out, sizeof out) == 0 && strcmp(out, "/a") == 0, "npf_abspath");
    }
    fd = npf_udp_socket(AF_INET, 0, 1);             /* no hook yet */
    CHECK(fd >= 0 && seen == 0, "a socket without a hook");
    npf_sock_close(fd);
    npf_udp_hook_set(hook, &arg);
    fd = npf_udp_socket(AF_INET, 0, 1);
    CHECK(fd >= 0 && seen == 1 && last_fd == fd && last_family == AF_INET && arg == 1, "the hook sees the socket");
    npf_sock_close(fd);
    answer = -1;                                    /* the platform cannot bind it: the socket stays */
    fd = npf_udp_socket(AF_INET, 1, 1);
    CHECK(fd >= 0 && seen == 2, "a failing hook leaves the socket");
    npf_sock_close(fd);
    fd = npf_udp_socket(AF_INET, 0, 0);             /* a node in connect_mode secure */
    CHECK(fd >= 0 && seen == 2, "without bypass the hook is not called");
    npf_sock_close(fd);
    fd = npf_udp_socket(AF_INET, 0, 1);             /* ... while one in p2p goes on around the VPN */
    CHECK(fd >= 0 && seen == 3, "bypass is the caller's: one socket's does not change the next");
    npf_sock_close(fd);
    fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);     /* not the node's (the loop's wake-up) */
    CHECK(fd >= 0 && seen == 3, "other sockets are not the hook's");
    npf_sock_close(fd);
    npf_udp_hook_set(NULL, NULL);
    answer = 0;
    fd = npf_udp_socket(AF_INET, 0, 1);             /* the built-in one: no VPN on a test host */
    CHECK(fd >= 0 && npf_vpn_bypass(fd, AF_INET, NULL) == 0, "built-in bypass without a VPN: nothing to do");
    npf_sock_close(fd);
    CHECK(npf_if_tunnel_name("utun3") && npf_if_tunnel_name("wg0") && npf_if_tunnel_name("tun0")
          && npf_if_tunnel_name("ppp0") && npf_if_tunnel_name("Wintun") && !npf_if_tunnel_name("en0")
          && !npf_if_tunnel_name("eth0") && !npf_if_tunnel_name("wlan0") && !npf_if_tunnel_name("pdp_ip0"),
          "tunnel interface names");
    {   /* a listening UDP port is its own: not even a socket that allows
         * sharing (SO_REUSEADDR, as another program may set) shares it */
        struct sockaddr_in a;
        socklen_t al = sizeof a;
        int one = 1, other = npf_socket(AF_INET, SOCK_DGRAM, 0, 0), mine = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        setsockopt(other, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        CHECK(other >= 0 && bind(other, (struct sockaddr *)&a, sizeof a) == 0
              && getsockname(other, (struct sockaddr *)&a, &al) == 0, "a UDP socket of another program");
        npf_sock_listen_opts(mine, SOCK_DGRAM);
        CHECK(mine >= 0 && bind(mine, (struct sockaddr *)&a, sizeof a) < 0, "its port is not taken over");
        npf_sock_close(mine);
        npf_sock_close(other);
    }
    {
        static const char *env[][2] = {{"NPF_NO_P2P", "1"}, {"NPF_TEST_DROP_P2P", "0"}, {"NPF_TEST_UDP_AGAIN_MS", "15000"},
                                       {"NPF_TEST_BLOCK_RELAY", ""}, {"NPF_TEST_PUB_IP", "192.0.2.66"}};
        npf_test_hooks t;
        size_t i;
        for (i = 0; i < sizeof env / sizeof env[0]; i++)
            setenv(env[i][0], env[i][1], 1);
        npf_th_read(&t);
        CHECK(t.no_p2p == 1 && !t.drop_p2p_ms && t.udp_again_ms == 15000 && !t.block_relay && !t.no_udp
              && t.pub_ip && strcmp(t.pub_ip, "192.0.2.66") == 0, "test switches: on, off, a number, a text");
        for (i = 0; i < sizeof env / sizeof env[0]; i++)
            unsetenv(env[i][0]);
    }
    return fails;
}

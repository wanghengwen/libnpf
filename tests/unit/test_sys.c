/* The node's UDP sockets and the platform's hook (sys.h): the hook sees each
 * one while it is on, none when off or for other sockets; a failing hook
 * leaves a working socket. Without one, the built-in VPN bypass: no VPN here,
 * nothing bound; tunnel interface names known; a listening UDP port is
 * never shared (npf_sock_listen_opts). The test switches (npf/testhooks.h):
 * unset, empty and 0 are off. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/testhooks.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

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

int test_sys(void)
{
    int arg = 0, fd;
#ifdef __linux__
    tcp_diag();
#endif
    fd = npf_udp_socket(AF_INET, 0);                /* no hook yet */
    CHECK(fd >= 0 && seen == 0, "a socket without a hook");
    npf_sock_close(fd);
    npf_udp_hook_set(hook, &arg);
    fd = npf_udp_socket(AF_INET, 0);
    CHECK(fd >= 0 && seen == 1 && last_fd == fd && last_family == AF_INET && arg == 1, "the hook sees the socket");
    npf_sock_close(fd);
    answer = -1;                                    /* the platform cannot bind it: the socket stays */
    fd = npf_udp_socket(AF_INET, 1);
    CHECK(fd >= 0 && seen == 2, "a failing hook leaves the socket");
    npf_sock_close(fd);
    npf_udp_hook_on(0);                             /* connect_mode secure */
    fd = npf_udp_socket(AF_INET, 0);
    CHECK(fd >= 0 && seen == 2, "off: the hook is not called");
    npf_sock_close(fd);
    npf_udp_hook_on(1);
    fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);     /* not the node's (the loop's wake-up) */
    CHECK(fd >= 0 && seen == 2, "other sockets are not the hook's");
    npf_sock_close(fd);
    npf_udp_hook_set(NULL, NULL);
    answer = 0;
    fd = npf_udp_socket(AF_INET, 0);                /* the built-in one: no VPN on a test host */
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

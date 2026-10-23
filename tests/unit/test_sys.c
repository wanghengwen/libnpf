/* The node's UDP sockets and the platform's hook (sys.h): the hook sees each
 * one while it is on, none when off or for other sockets; a failing hook
 * leaves a working socket. Without one, the built-in VPN bypass: no VPN here,
 * nothing bound; tunnel interface names known; a listening UDP port is
 * never shared (npf_sock_listen_opts). */
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

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

int test_sys(void)
{
    int arg = 0, fd;
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
    CHECK(fd >= 0 && seen == 2 && !npf_udp_hook_is_on(), "off: the hook is not called");
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
    return fails;
}

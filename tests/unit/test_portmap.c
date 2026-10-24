/* Port mapping against a stand-in gateway (NPF_TEST_PORTMAP_GW) on a
 * thread: a reply for another internal port (a LAN host spoofing the
 * gateway) is not taken, the right one is; a mapping is removed with one
 * short try of the method that made it. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/platform.h"
#include "npf/portmap.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static int gw_fd;
static int gw_mode;        /* 0: a wrong reply, then the right one; 1: wrong replies only */
static int gw_stop;

static void *gateway(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&gw_stop, __ATOMIC_ACQUIRE)) {
        uint8_t b[128], r[60];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        struct timeval tv = {0, 100000};
        ssize_t n;
        setsockopt(gw_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        n = recvfrom(gw_fd, b, sizeof b, 0, (struct sockaddr *)&from, &fl);
        if (n != 60 || b[0] != 2)
            continue;                   /* PCP only here */
        memset(r, 0, sizeof r);
        r[0] = 2;
        r[1] = 0x80 | 1;
        memcpy(r + 4, b + 4, 4);        /* lifetime as asked */
        memcpy(r + 24, b + 24, 12);     /* nonce */
        r[36] = 17;
        r[42] = 0x9c;                   /* external port 40000 */
        r[43] = 0x40;
        r[54] = 0xff;
        r[55] = 0xff;
        r[56] = 203;                    /* external 203.0.113.7 */
        r[57] = 0;
        r[58] = 113;
        r[59] = 7;
        r[40] = (uint8_t)(b[40] ^ 1);   /* another internal port */
        r[41] = b[41];
        sendto(gw_fd, r, sizeof r, 0, (struct sockaddr *)&from, fl);
        if (__atomic_load_n(&gw_mode, __ATOMIC_ACQUIRE) == 0) {
            r[40] = b[40];
            sendto(gw_fd, r, sizeof r, 0, (struct sockaddr *)&from, fl);
        }
    }
    return NULL;
}

int test_portmap_gw(void)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    char env[64];
    pthread_t th;
    npf_portmap res;
    int64_t t0;

    gw_fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (gw_fd < 0 || bind(gw_fd, (struct sockaddr *)&a, sizeof a) < 0
        || getsockname(gw_fd, (struct sockaddr *)&a, &al) < 0) {
        CHECK(0, "stand-in gateway");
        return fails;
    }
    snprintf(env, sizeof env, "127.0.0.1:%u", ntohs(a.sin_port));
    setenv("NPF_TEST_PORTMAP_GW", env, 1);
    pthread_create(&th, NULL, gateway, NULL);

    memset(&res, 0, sizeof res);
    CHECK(npf_portmap_request(4242, 3600, &res) == 0 && res.method == NPF_PORTMAP_PCP, "PCP mapping made");
    CHECK(res.internal_port == 4242 && res.external_port == 40000, "the reply for our port taken (%u -> %u)",
          res.internal_port, res.external_port);

    CHECK(npf_portmap_remove(4242, NPF_PORTMAP_PCP) == 0, "removed");
    __atomic_store_n(&gw_mode, 1, __ATOMIC_RELEASE);
    t0 = npf_mono_ms();
    CHECK(npf_portmap_remove(4242, NPF_PORTMAP_PCP) < 0, "a removal answered for another port does not count");
    CHECK(npf_mono_ms() - t0 < 1000, "one short try (%lld ms)", (long long)(npf_mono_ms() - t0));

    __atomic_store_n(&gw_stop, 1, __ATOMIC_RELEASE);
    pthread_join(th, NULL);
    close(gw_fd);
    unsetenv("NPF_TEST_PORTMAP_GW");
    return fails;
}

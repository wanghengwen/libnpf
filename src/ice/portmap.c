#define _DEFAULT_SOURCE
#include "npf/log.h"
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"
#include "npf/portmap.h"

#define PCP_VERSION   2
#define PCP_OP_MAP    1
#define PCP_PROTO_UDP 17
#define RETRY_MS_0    250           /* RFC 6886/6887: 250 ms, double, a few tries */
#define RETRIES       4             /* ~250/500/1000/2000 ms, give up < 4 s */

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* ---- PCP ---- */

int npf_pcp_build_map(uint8_t out[60], const uint8_t nonce[12], const struct in_addr *client,
                      uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime)
{
    memset(out, 0, 60);
    out[0] = PCP_VERSION;
    out[1] = PCP_OP_MAP;                 /* R=0 (request), opcode=1 */
    wr32(out + 4, lifetime);
    /* client IP as IPv4-mapped IPv6 ::ffff:a.b.c.d */
    out[18] = 0xff;
    out[19] = 0xff;
    memcpy(out + 20, &client->s_addr, 4);
    /* MAP opcode data at offset 24 */
    memcpy(out + 24, nonce, 12);
    out[36] = PCP_PROTO_UDP;
    wr16(out + 40, internal_port);
    wr16(out + 42, suggest_ext);
    /* suggested external IP (out+44..59) left zero = "no preference" */
    return 60;
}

int npf_pcp_parse_map(const uint8_t *in, size_t len, const uint8_t nonce[12], npf_portmap *res)
{
    if (len < 60 || in[0] != PCP_VERSION || in[1] != (0x80 | PCP_OP_MAP))
        return -1;
    if (in[3] != 0)                      /* result code != SUCCESS */
        return -1;
    if (memcmp(in + 24, nonce, 12) != 0 || in[36] != PCP_PROTO_UDP)
        return -1;
    memset(res, 0, sizeof(*res));
    res->method = NPF_PORTMAP_PCP;
    res->lifetime = rd32(in + 4);
    res->epoch = rd32(in + 8);
    res->internal_port = rd16(in + 40);
    res->external_port = rd16(in + 42);
    /* assigned external IP at in+44..59; v4-mapped -> IPv4, else IPv6 */
    if (memcmp(in + 44, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
        res->ext_family = 4;
        memcpy(res->external_ip, in + 56, 4);
    } else {
        res->ext_family = 6;
        memcpy(res->external_ip, in + 44, 16);
    }
    return 0;
}

/* ---- NAT-PMP ---- */

int npf_natpmp_build_map(uint8_t out[12], uint16_t internal_port, uint16_t suggest_ext, uint32_t lifetime)
{
    memset(out, 0, 12);
    out[0] = 0;                          /* version */
    out[1] = 1;                          /* opcode 1 = map UDP */
    wr16(out + 4, internal_port);
    wr16(out + 6, suggest_ext);
    wr32(out + 8, lifetime);
    return 12;
}

int npf_natpmp_parse_map(const uint8_t *in, size_t len, npf_portmap *res)
{
    if (len < 16 || in[0] != 0 || in[1] != (128 + 1))
        return -1;
    if (rd16(in + 2) != 0)               /* result code */
        return -1;
    memset(res, 0, sizeof(*res));
    res->method = NPF_PORTMAP_NATPMP;
    res->epoch = rd32(in + 4);
    res->internal_port = rd16(in + 8);
    res->external_port = rd16(in + 10);
    res->lifetime = rd32(in + 12);
    res->ext_family = 4;                 /* filled by the get-external-address step */
    return 0;
}

/* NAT-PMP opcode 0: public IPv4 address */
static int natpmp_external_ip(int fd, uint8_t ip[4])
{
    uint8_t req[2] = { 0, 0 }, buf[64];
    int i;
    struct pollfd pfd = { fd, POLLIN, 0 };
    for (i = 0; i < RETRIES; i++) {
        ssize_t r;
        (void)!send(fd, req, sizeof(req), 0);   /* connected (udp_connect): no address */
        if (poll(&pfd, 1, RETRY_MS_0 << i) <= 0)
            continue;
        r = recv(fd, buf, sizeof(buf), 0);
        if (r >= 12 && buf[0] == 0 && buf[1] == 128 && rd16(buf + 2) == 0) {
            memcpy(ip, buf + 8, 4);
            return 0;
        }
    }
    return -1;
}

int npf_portmap_gateway_v4(struct in_addr *gw)
{
    uint32_t a;
    if (npf_default_gw4(&a) < 0)
        return -1;
    gw->s_addr = a;
    return 0;
}

static int udp_connect(const struct sockaddr_in *gw, struct in_addr *local)
{
    struct sockaddr_in la;
    socklen_t llen = sizeof(la);
    int fd = npf_udp_socket(AF_INET, 1);
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)gw, sizeof(*gw)) < 0
        || getsockname(fd, (struct sockaddr *)&la, &llen) < 0) {
        npf_sock_close(fd);
        return -1;
    }
    *local = la.sin_addr;
    return fd;
}

/* a reply for this request: the port asked for, and (not a removal) an
 * external port. A LAN host spoofing the gateway gets no say in another */
static int reply_ok(const npf_portmap *res, uint16_t internal_port, uint32_t lifetime)
{
    return res->internal_port == internal_port && (lifetime == 0 || res->external_port != 0);
}

/* ms to until, 0 when past (poll then only looks) */
static int wait_left(int64_t until)
{
    int64_t d = until - npf_mono_ms();
    return d > 0 ? (int)d : 0;
}

static int try_pcp(const struct sockaddr_in *gw, uint16_t internal_port, uint32_t lifetime,
                   npf_portmap *res, int tries)
{
    struct in_addr local;
    uint8_t nonce[12], req[60], buf[128];
    int fd = udp_connect(gw, &local), i, ok = -1;
    struct pollfd pfd;
    if (fd < 0)
        return -1;
    pfd.fd = fd;
    pfd.events = POLLIN;
    npf_random(nonce, sizeof(nonce));
    npf_pcp_build_map(req, nonce, &local, internal_port, internal_port, lifetime);
    for (i = 0; i < tries && ok < 0; i++) {
        int64_t until = npf_mono_ms() + (RETRY_MS_0 << i);
        (void)!send(fd, req, sizeof(req), 0);
        while (ok < 0 && poll(&pfd, 1, wait_left(until)) > 0) {    /* a stray reply does not hide ours */
            ssize_t r = recv(fd, buf, sizeof(buf), 0);
            if (r > 0 && npf_pcp_parse_map(buf, (size_t)r, nonce, res) == 0 && reply_ok(res, internal_port, lifetime))
                ok = 0;
            else if (r > 0)
                npf_logd("portmap: PCP reply not a success MAP for us (%zd bytes, result %d)", r, r >= 4 ? buf[3] : -1);
        }
    }
    npf_sock_close(fd);
    return ok;
}

static int try_natpmp(const struct sockaddr_in *gw, uint16_t internal_port, uint32_t lifetime,
                      npf_portmap *res, int tries)
{
    struct in_addr local;
    uint8_t req[12], buf[64];
    int fd = udp_connect(gw, &local), i, ok = -1;
    struct pollfd pfd;
    if (fd < 0)
        return -1;
    pfd.fd = fd;
    pfd.events = POLLIN;
    npf_natpmp_build_map(req, internal_port, internal_port, lifetime);
    for (i = 0; i < tries && ok < 0; i++) {
        int64_t until = npf_mono_ms() + (RETRY_MS_0 << i);
        (void)!send(fd, req, sizeof(req), 0);
        while (ok < 0 && poll(&pfd, 1, wait_left(until)) > 0) {
            ssize_t r = recv(fd, buf, sizeof(buf), 0);
            if (r > 0 && npf_natpmp_parse_map(buf, (size_t)r, res) == 0 && reply_ok(res, internal_port, lifetime))
                ok = 0;
        }
    }
    if (ok == 0 && lifetime && natpmp_external_ip(fd, res->external_ip) != 0)
        npf_logd("portmap: NAT-PMP mapped but external address query failed");
    npf_sock_close(fd);
    return ok;
}

static int gateway(struct sockaddr_in *gw)
{
    char gs[INET_ADDRSTRLEN];
    memset(gw, 0, sizeof(*gw));
    gw->sin_family = AF_INET;
    gw->sin_port = htons(NPF_PORTMAP_PORT);
    if (getenv("NPF_TEST_PORTMAP_GW")) {      /* tests: "IP:PORT" of a stand-in gateway */
        char ip[64], *colon;
        snprintf(ip, sizeof ip, "%s", getenv("NPF_TEST_PORTMAP_GW"));
        if ((colon = strrchr(ip, ':')) != NULL) {
            *colon = 0;
            gw->sin_port = htons((uint16_t)atoi(colon + 1));
        }
        if (inet_pton(AF_INET, ip, &gw->sin_addr) != 1)
            return -1;
    } else if (npf_portmap_gateway_v4(&gw->sin_addr) < 0) {
        npf_logd("portmap: no default IPv4 gateway");
        return -1;
    }
    inet_ntop(AF_INET, &gw->sin_addr, gs, sizeof(gs));
    npf_logd("portmap: gateway %s:%d", gs, NPF_PORTMAP_PORT);
    return 0;
}

int npf_portmap_request(uint16_t internal_port, uint32_t lifetime, npf_portmap *res)
{
    struct sockaddr_in gw;
    if (gateway(&gw) < 0)
        return -1;
    if (try_pcp(&gw, internal_port, lifetime, res, RETRIES) == 0)
        return 0;
    npf_logd("portmap: no PCP, trying NAT-PMP");
    return try_natpmp(&gw, internal_port, lifetime, res, RETRIES);
}

int npf_portmap_remove(uint16_t internal_port, int method)
{
    struct sockaddr_in gw;
    npf_portmap res;
    if (gateway(&gw) < 0)
        return -1;
    return method == NPF_PORTMAP_NATPMP ? try_natpmp(&gw, internal_port, 0, &res, 1)
                                         : try_pcp(&gw, internal_port, 0, &res, 1);
}

const char *npf_portmap_method_str(int method)
{
    switch (method) {
    case NPF_PORTMAP_PCP:    return "PCP";
    case NPF_PORTMAP_NATPMP: return "NAT-PMP";
    default:                 return "none";
    }
}

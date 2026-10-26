/* UPnP IGD detection (npf/upnp.h): the parsers on fixtures, hostile ones
 * among them (another host, a hostname, injected request lines, oversized
 * and malformed bodies), then the whole detection against a stand-in IGD
 * on loopback (NPF_TEST_UPNP_GW: unicast SSDP only, nothing on the LAN). */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/upnp.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static uint32_t ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a.s_addr;
}

static int ssdp(const char *loc, const char *st, uint32_t gw, npf_upnp_url *u)
{
    char b[2048];
    snprintf(b, sizeof b, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: %s\r\n"
             "USN: uuid:1234::%s\r\nEXT:\r\nSERVER: Linux UPnP/1.1 MiniUPnPd/2.3\r\nLOCATION: %s\r\n\r\n", st, st, loc);
    return npf_upnp_parse_ssdp(b, strlen(b), gw, u);
}

#define IGD1 "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

static void test_ssdp(void)
{
    uint32_t gw = ip4("192.168.1.1");
    npf_upnp_url u;
    char big[1500];
    CHECK(ssdp("http://192.168.1.1:5000/rootDesc.xml", IGD1, gw, &u) == 0 && u.port == 5000
          && strcmp(u.path, "/rootDesc.xml") == 0, "an IGD's answer");
    CHECK(ssdp("http://192.168.1.1/", "urn:schemas-upnp-org:service:WANPPPConnection:1", gw, &u) == 0 && u.port == 80
          && strcmp(u.path, "/") == 0, "a WAN connection service's answer, port 80");
    CHECK(ssdp("HTTP://192.168.1.1:80", IGD1, gw, &u) == 0 && strcmp(u.path, "/") == 0, "no path, scheme in capitals");
    {
        const char *b = "HTTP/1.1 200 OK\r\nst: " IGD1 "\r\nlocation:http://192.168.1.1:1900/d.xml\r\n\r\n";
        CHECK(npf_upnp_parse_ssdp(b, strlen(b), gw, &u) == 0 && u.port == 1900, "lower-case headers, no space");
    }
    /* hostile or not ours */
    CHECK(ssdp("http://192.168.1.2:5000/rootDesc.xml", IGD1, gw, &u) < 0, "LOCATION at another host");
    CHECK(ssdp("http://router.lan:5000/rootDesc.xml", IGD1, gw, &u) < 0, "LOCATION by a hostname");
    CHECK(ssdp("http://192.168.1.1@evil.example/x", IGD1, gw, &u) < 0, "user info in LOCATION");
    CHECK(ssdp("http://192.168.1.1.evil.example/x", IGD1, gw, &u) < 0, "the gateway's address as a name's prefix");
    CHECK(ssdp("https://192.168.1.1/x", IGD1, gw, &u) < 0, "https");
    CHECK(ssdp("http://192.168.1.1:0/x", IGD1, gw, &u) < 0 && ssdp("http://192.168.1.1:70000/x", IGD1, gw, &u) < 0
          && ssdp("http://192.168.1.1:/x", IGD1, gw, &u) < 0 && ssdp("http://192.168.1.1:80x/x", IGD1, gw, &u) < 0,
          "bad ports");
    CHECK(ssdp("http://192.168.1.1/a b", IGD1, gw, &u) < 0, "a space in the path");
    CHECK(ssdp("http://192.168.1.1/a\rHost: evil", IGD1, gw, &u) < 0, "a CR in the path (header injection)");
    CHECK(ssdp("http://192.168.1.1/x", "urn:schemas-upnp-org:device:MediaServer:1", gw, &u) < 0, "not an IGD");
    memset(big, 'a', sizeof big);
    big[0] = '/';
    {
        char loc[600];
        snprintf(loc, sizeof loc, "http://192.168.1.1%.*s", 300, big);
        CHECK(ssdp(loc, IGD1, gw, &u) < 0, "a path too long");
    }
    {
        const char *b = "HTTP/1.1 404 Not Found\r\nST: " IGD1 "\r\nLOCATION: http://192.168.1.1/x\r\n\r\n";
        CHECK(npf_upnp_parse_ssdp(b, strlen(b), gw, &u) < 0, "not 200");
        b = "NOTIFY * HTTP/1.1\r\nNT: " IGD1 "\r\nLOCATION: http://192.168.1.1/x\r\n\r\n";
        CHECK(npf_upnp_parse_ssdp(b, strlen(b), gw, &u) < 0, "a NOTIFY, not an answer");
        b = "HTTP/1.1 200 OK\r\nST: " IGD1 "\r\n\r\n";
        CHECK(npf_upnp_parse_ssdp(b, strlen(b), gw, &u) < 0, "no LOCATION");
        CHECK(npf_upnp_parse_ssdp("HTTP/1.1 2", 10, gw, &u) < 0, "cut short");
    }
    /* a full datagram of junk headers after a valid start, not NUL-terminated */
    {
        char d[1500];
        int l = snprintf(d, sizeof d, "HTTP/1.1 200 OK\r\nST: " IGD1 "\r\nLOCATION: http://192.168.1.1:5000/r.xml\r\n");
        memset(d + l, 'X', sizeof d - (size_t)l);
        CHECK(npf_upnp_parse_ssdp(d, sizeof d, gw, &u) == 0 && u.port == 5000, "a full datagram");
    }
}

static int http(const char *resp, char *buf, const char **body, size_t *blen)
{
    size_t n = strlen(resp);
    memcpy(buf, resp, n + 1);
    return npf_upnp_parse_http(buf, n, body, blen);
}

static void test_http(void)
{
    char buf[512];
    const char *b;
    size_t n;
    CHECK(http("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello and more", buf, &b, &n) == 0 && n == 5
          && memcmp(b, "hello", 5) == 0, "Content-Length");
    CHECK(http("HTTP/1.0 200 OK\r\n\r\nall of it", buf, &b, &n) == 0 && n == 9, "until the close");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n",
               buf, &b, &n) == 0 && n == 11 && memcmp(b, "hello world", 11) == 0, "chunked");
    CHECK(http("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort", buf, &b, &n) < 0, "Content-Length past the end");
    CHECK(http("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\nx", buf, &b, &n) < 0, "a huge length");
    CHECK(http("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\nx", buf, &b, &n) < 0, "a length not a number");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab\r\n0\r\n\r\n", buf, &b, &n) < 0,
          "a chunk past the end");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX0\r\n\r\n", buf, &b, &n) < 0,
          "a chunk without its CRLF");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", buf, &b, &n) < 0, "no last chunk");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", buf, &b, &n) < 0, "a chunk size not hex");
    CHECK(http("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx", buf, &b, &n) < 0, "another encoding");
    CHECK(http("HTTP/1.1 500 Internal Server Error\r\n\r\n<fault/>", buf, &b, &n) < 0, "not 200");
    CHECK(http("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n", buf, &b, &n) < 0, "no end of the headers");
    CHECK(http("SSH-2.0-OpenSSH_9\r\n\r\n", buf, &b, &n) < 0, "not HTTP");
}

static const char *DESC =
    "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
    "<specVersion><major>1</major><minor>0</minor></specVersion>%s"
    "<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>"
    "<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>"
    "<controlURL>/ctl/L3F</controlURL></service></serviceList>"
    "<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>"
    "<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>"
    "<serviceList>%s</serviceList></device></deviceList></device></deviceList></device></root>";

static int desc(const char *base, const char *services, npf_upnp_url *ctl, char *st, int nth)
{
    char x[4096];
    npf_upnp_url loc = {5000, "/rootDesc.xml"};
    snprintf(x, sizeof x, DESC, base, services);
    return npf_upnp_parse_desc(x, strlen(x), ip4("192.168.1.1"), &loc, ctl, st, 96, nth);
}

#define SVC(t, c) "<service><serviceType>" t "</serviceType><serviceId>urn:upnp-org:serviceId:X</serviceId>" \
                  "<controlURL>" c "</controlURL><eventSubURL>/evt</eventSubURL></service>"
#define WANIP1 "urn:schemas-upnp-org:service:WANIPConnection:1"
#define WANPPP1 "urn:schemas-upnp-org:service:WANPPPConnection:1"

static void test_desc(void)
{
    npf_upnp_url c;
    char st[96];
    CHECK(desc("", SVC(WANIP1, "/ctl/IPConn"), &c, st, 0) == 0 && c.port == 5000 && strcmp(c.path, "/ctl/IPConn") == 0
          && strcmp(st, WANIP1) == 0, "WANIPConnection, a path at the description's port");
    CHECK(desc("", SVC(WANPPP1, "/ctl/PPP") SVC(WANIP1, "/ctl/IP"), &c, st, 1) == 0 && strcmp(c.path, "/ctl/IP") == 0
          && strcmp(st, WANIP1) == 0, "the second WAN connection service");
    CHECK(desc("", SVC(WANPPP1, "/ctl/PPP"), &c, st, 1) < 0, "no second one");
    CHECK(desc("", SVC("urn:schemas-upnp-org:service:WANIPConnection:2", "\n  upnp/control/IP2 \n"), &c, st, 0) == 0
          && strcmp(c.path, "/upnp/control/IP2") == 0, "IGD v2, a relative URL with white space");
    CHECK(desc("<URLBase>http://192.168.1.1:49152/</URLBase>", SVC(WANIP1, "ctl"), &c, st, 0) == 0 && c.port == 49152
          && strcmp(c.path, "/ctl") == 0, "URLBase at the gateway");
    CHECK(desc("", SVC(WANIP1, "http://192.168.1.1:2869/ctl"), &c, st, 0) == 0 && c.port == 2869, "an absolute URL at the gateway");
    /* hostile */
    CHECK(desc("<URLBase>http://10.0.0.9:80/</URLBase>", SVC(WANIP1, "/ctl"), &c, st, 0) < 0, "URLBase at another host");
    CHECK(desc("", SVC(WANIP1, "http://169.254.169.254/latest/meta-data"), &c, st, 0) < 0, "a control URL at another host");
    CHECK(desc("", SVC(WANIP1, "file:///etc/passwd"), &c, st, 0) < 0, "another scheme");
    CHECK(desc("", SVC(WANIP1, "/ctl x"), &c, st, 0) < 0, "a space in the control path");
    CHECK(desc("", SVC(WANIP1 "\"><x", "/ctl"), &c, st, 0) < 0, "a service type with more after it (injection)");
    CHECK(desc("", SVC("urn:schemas-upnp-org:service:WANIPConnection:", "/ctl"), &c, st, 0) < 0, "no version");
    CHECK(desc("", SVC("urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "/ctl"), &c, st, 0) < 0,
          "no WAN connection service");
    CHECK(desc("", "<service><serviceType>" WANIP1 "</serviceType><controlURL>/ctl</controlURL>", &c, st, 0) < 0,
          "a service not closed");
    CHECK(desc("", "<service><serviceType>" WANIP1 "</serviceType><controlURL></controlURL></service>", &c, st, 0) < 0,
          "an empty control URL");
    {
        char x[1024], longpath[400];
        npf_upnp_url loc = {80, "/"};
        memset(longpath, 'a', sizeof longpath - 1);
        longpath[sizeof longpath - 1] = 0;
        snprintf(x, sizeof x, "<service><serviceType>" WANIP1 "</serviceType><controlURL>/%s</controlURL></service>", longpath);
        CHECK(npf_upnp_parse_desc(x, strlen(x), ip4("192.168.1.1"), &loc, &c, st, 96, 0) < 0, "a control path too long");
        snprintf(x, sizeof x, "<service><serviceType>" WANIP1 "</serviceType><controlURL>/c</controlURL></service>");
        CHECK(npf_upnp_parse_desc(x, strlen(x), ip4("192.168.1.1"), &loc, &c, st, 10, 0) < 0, "a service type longer than its room");
        CHECK(npf_upnp_parse_desc(x, strlen(x) - 12, ip4("192.168.1.1"), &loc, &c, st, 96, 0) < 0, "cut short");
    }
}

static int extip(const char *s, uint8_t ip[4])
{
    return npf_upnp_parse_extip(s, strlen(s), ip);
}

static void test_extip(void)
{
    uint8_t ip[4];
    const char *ok = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>"
                     "<u:GetExternalIPAddressResponse xmlns:u=\"" WANIP1 "\"><NewExternalIPAddress> 203.0.113.5 "
                     "</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
    CHECK(npf_upnp_parse_extip(ok, strlen(ok), ip) == 0 && ip[0] == 203 && ip[3] == 5, "the WAN address");
    CHECK(extip("<NewExternalIPAddress>100.64.3.4</NewExternalIPAddress>", ip) == 0 && ip[0] == 100,
          "a carrier NAT's address (the caller judges it)");
    CHECK(extip("<NewExternalIPAddress></NewExternalIPAddress>", ip) < 0, "empty: no WAN address");
    CHECK(extip("<NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>", ip) < 0, "0.0.0.0: WAN down");
    CHECK(extip("<NewExternalIPAddress>1.2.3.4.5</NewExternalIPAddress>", ip) < 0, "not an address");
    CHECK(extip("<NewExternalIPAddress>999.1.1.1</NewExternalIPAddress>", ip) < 0, "out of range");
    CHECK(extip("<NewExternalIPAddress>2001:db8::1</NewExternalIPAddress>", ip) < 0, "IPv6");
    CHECK(extip("<NewExternalIPAddress>203.0.113.5", ip) < 0, "not closed");
    CHECK(extip("<NewExternalIPAddress/>", ip) < 0, "self-closing");
    CHECK(extip("<s:Fault><errorCode>501</errorCode></s:Fault>", ip) < 0, "a fault");
}

/* ---- the stand-in IGD on loopback ---- */

enum { IGD_OK, IGD_OTHER_HOST, IGD_HUGE, IGD_NO_ADDR };
static int igd_mode, igd_udp, igd_tcp, igd_stop, igd_requests;
static uint16_t igd_tcp_port;

static void *igd_ssdp(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&igd_stop, __ATOMIC_ACQUIRE)) {
        char b[1500], r[512];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        struct timeval tv = {0, 100000};
        ssize_t n;
        setsockopt(igd_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        n = recvfrom(igd_udp, b, sizeof b - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0)
            continue;
        b[n] = 0;
        if (strncmp(b, "M-SEARCH * HTTP/1.1\r\n", 21) != 0 || !strstr(b, "ST: " IGD1))
            continue;
        snprintf(r, sizeof r, "HTTP/1.1 200 OK\r\nST: " IGD1 "\r\nLOCATION: http://%s:%u/rootDesc.xml\r\n\r\n",
                 igd_mode == IGD_OTHER_HOST ? "127.0.0.2" : "127.0.0.1", igd_tcp_port);
        sendto(igd_udp, r, strlen(r), 0, (struct sockaddr *)&from, fl);
    }
    return NULL;
}

static void *igd_http(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&igd_stop, __ATOMIC_ACQUIRE)) {
        char req[4096], d[4096], *big;
        size_t got = 0;
        ssize_t n;
        struct timeval tv = {0, 100000};
        int c;
        setsockopt(igd_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if ((c = accept(igd_tcp, NULL, NULL)) < 0)
            continue;
        __atomic_add_fetch(&igd_requests, 1, __ATOMIC_ACQ_REL);
        tv.tv_sec = 2;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        while (got < sizeof req - 1 && (n = recv(c, req + got, sizeof req - 1 - got, 0)) > 0) {
            req[got += (size_t)n] = 0;
            if (strstr(req, "\r\n\r\n") && (strncmp(req, "GET ", 4) == 0 || strstr(req, "</s:Envelope>")))
                break;
        }
        req[got] = 0;
        if (strncmp(req, "GET /rootDesc.xml HTTP/1.1\r\nHost: 127.0.0.1:", 44) == 0) {
            const char *svc = SVC(WANPPP1, "/ctl/PPP") SVC(WANIP1, "/ctl/IP");
            char x[3000];
            int l = snprintf(x, sizeof x, DESC, "", svc), h;
            if (igd_mode == IGD_HUGE) {     /* more than the description may be */
                const char *hd = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
                size_t sz = 80 << 10;
                big = malloc(sz);
                memset(big, ' ', sz);
                send(c, hd, strlen(hd), MSG_NOSIGNAL);
                send(c, big, sz, MSG_NOSIGNAL);
                free(big);
            } else {                        /* chunked, in two pieces */
                h = snprintf(d, sizeof d, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%.*s\r\n%x\r\n%s\r\n0\r\n\r\n",
                             l / 2, l / 2, x, l - l / 2, x + l / 2);
                send(c, d, (size_t)h, MSG_NOSIGNAL);
            }
        } else if (strncmp(req, "POST /ctl/", 10) == 0 && strstr(req, "SOAPAction: \"urn:schemas-upnp-org:service:")
                   && strstr(req, "#GetExternalIPAddress\"")) {
            /* the PPP service has no address (not connected), the IP one has */
            const char *ip = igd_mode == IGD_NO_ADDR || strncmp(req, "POST /ctl/PPP", 13) == 0 ? "" : "198.51.100.7";
            char body[512];
            int bl = snprintf(body, sizeof body, "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>"
                              "<NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>", ip);
            int h = snprintf(d, sizeof d, "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", bl, body);
            send(c, d, (size_t)h, MSG_NOSIGNAL);
        } else {
            const char *e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(c, e, strlen(e), MSG_NOSIGNAL);
        }
        close(c);
    }
    return NULL;
}

static void test_detect(void)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    char env[64];
    pthread_t t1, t2;
    uint8_t ip[4] = {0};
    int r, one = 1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    igd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    igd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(igd_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (igd_udp < 0 || igd_tcp < 0 || bind(igd_udp, (struct sockaddr *)&a, sizeof a) < 0
        || getsockname(igd_udp, (struct sockaddr *)&a, &al) < 0) {
        CHECK(0, "stand-in IGD");
        return;
    }
    snprintf(env, sizeof env, "127.0.0.1:%u", ntohs(a.sin_port));
    a.sin_port = 0;
    al = sizeof a;
    if (bind(igd_tcp, (struct sockaddr *)&a, sizeof a) < 0 || listen(igd_tcp, 4) < 0
        || getsockname(igd_tcp, (struct sockaddr *)&a, &al) < 0) {
        CHECK(0, "stand-in IGD's HTTP");
        return;
    }
    igd_tcp_port = ntohs(a.sin_port);
    setenv("NPF_TEST_UPNP_GW", env, 1);
    pthread_create(&t1, NULL, igd_ssdp, NULL);
    pthread_create(&t2, NULL, igd_http, NULL);

    r = npf_upnp_detect(ip);
    CHECK(r == NPF_UPNP_ADDR && ip[0] == 198 && ip[1] == 51 && ip[2] == 100 && ip[3] == 7,
          "the stand-in's WAN address, from its second service (%d, %u.%u.%u.%u)", r, ip[0], ip[1], ip[2], ip[3]);
    __atomic_store_n(&igd_mode, IGD_NO_ADDR, __ATOMIC_RELEASE);
    CHECK(npf_upnp_detect(ip) == NPF_UPNP_PRESENT, "an IGD without a WAN address");
    __atomic_store_n(&igd_mode, IGD_HUGE, __ATOMIC_RELEASE);
    CHECK(npf_upnp_detect(ip) == NPF_UPNP_PRESENT, "a description over the limit is not read");
    __atomic_store_n(&igd_mode, IGD_OTHER_HOST, __ATOMIC_RELEASE);
    __atomic_store_n(&igd_requests, 0, __ATOMIC_RELEASE);
    CHECK(npf_upnp_detect(ip) == NPF_UPNP_NONE && __atomic_load_n(&igd_requests, __ATOMIC_ACQUIRE) == 0,
          "LOCATION at another host: nothing fetched");
    snprintf(env, sizeof env, "127.0.0.1:%u", igd_tcp_port);    /* no SSDP there */
    setenv("NPF_TEST_UPNP_GW", env, 1);
    CHECK(npf_upnp_detect(ip) == NPF_UPNP_NONE, "no answer");

    __atomic_store_n(&igd_stop, 1, __ATOMIC_RELEASE);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    close(igd_udp);
    close(igd_tcp);
    unsetenv("NPF_TEST_UPNP_GW");
}

int test_upnp(void)
{
    test_ssdp();
    test_http();
    test_desc();
    test_extip();
    test_detect();
    return fails;
}

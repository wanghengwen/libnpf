/* UPnP IGD detection only (npf/upnp.h, nat-traversal.md 5.1): nothing here
 * makes, changes or deletes a mapping. Everything goes to the default
 * gateway's address and nowhere else. */
#define _DEFAULT_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/platform.h"
#include "npf/portmap.h"
#include "npf/upnp.h"

#define SSDP_MS   3000              /* the answers to M-SEARCH (sent twice, 1 s apart) */
#define HTTP_MS   3000              /* one exchange with the gateway */
#define ALL_MS    9000              /* the whole detection after SSDP */
#define DESC_MAX  (64 << 10)        /* the device description */
#define SOAP_MAX  (16 << 10)        /* the SOAP answer */
#define TRIES     2                 /* WAN connection services asked for their address */

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* pat in [p, end), ASCII case ignored; NULL when not there */
static const char *find(const char *p, const char *end, const char *pat)
{
    size_t n = strlen(pat), i;
    for (; p && end - p >= (ptrdiff_t)n; p++) {
        for (i = 0; i < n && lower((unsigned char)p[i]) == lower((unsigned char)pat[i]); i++)
            ;
        if (i == n)
            return p;
    }
    return NULL;
}

static int ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static void trim(const char **p, const char **e)
{
    while (*p < *e && ws(**p))
        (*p)++;
    while (*e > *p && ws((*e)[-1]))
        (*e)--;
}

/* the text of <tag>...</tag> in [p, end), trimmed */
static int element(const char *p, const char *end, const char *tag, const char **s, const char **e)
{
    char open[32], close[32];
    snprintf(open, sizeof open, "<%s>", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    if (!(p = find(p, end, open)))
        return -1;
    *s = p + strlen(open);
    if (!(*e = find(*s, end, close)))
        return -1;
    trim(s, e);
    return 0;
}

/* a path of a request line: printable ASCII, no spaces; slash: "/" put first */
static int set_path(npf_upnp_url *u, const char *p, const char *e, int slash)
{
    size_t n = (size_t)(e - p), i;
    if (n + 1 >= sizeof u->path)
        return -1;
    for (i = 0; i < n; i++)
        if ((unsigned char)p[i] <= 0x20 || (unsigned char)p[i] >= 0x7f)
            return -1;
    u->path[0] = '/';
    memcpy(u->path + (slash ? 1 : 0), p, n);
    u->path[n + (slash ? 1 : 0)] = 0;
    return u->path[0] == '/' ? 0 : -1;
}

/* "http://IP[:PORT][/PATH]", IP the gateway's: never another host */
static int parse_url(const char *p, const char *e, uint32_t gw, npf_upnp_url *u)
{
    char host[16];
    const char *h;
    struct in_addr a;
    long port = 80;
    if (e - p < 7 || find(p, p + 7, "http://") != p)
        return -1;
    for (h = p += 7; p < e && *p != ':' && *p != '/'; p++)
        ;
    if (p == h || p - h >= (ptrdiff_t)sizeof host)
        return -1;
    memcpy(host, h, (size_t)(p - h));
    host[p - h] = 0;
    if (inet_pton(AF_INET, host, &a) != 1 || a.s_addr != gw)
        return -1;
    if (p < e && *p == ':')
        for (port = 0, p++; p < e && *p >= '0' && *p <= '9' && port <= 65535; p++)
            port = port * 10 + (*p - '0');
    if (port < 1 || port > 65535)
        return -1;
    u->port = (uint16_t)port;
    if (p == e) {
        strcpy(u->path, "/");
        return 0;
    }
    return *p == '/' ? set_path(u, p, e, 0) : -1;
}

int npf_upnp_parse_ssdp(const char *buf, size_t len, uint32_t gw, npf_upnp_url *loc)
{
    const char *p = buf, *end = buf + len, *ls = NULL, *le = NULL;
    int igd = 0;
    if (len < 12 || find(p, p + 7, "HTTP/1.") != p || p[8] != ' ' || memcmp(p + 9, "200", 3) != 0)
        return -1;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p)), *e = nl ? nl : end;
        if (find(p, e, "LOCATION:") == p) {
            ls = p + 9;
            le = e;
        } else if ((find(p, e, "ST:") == p || find(p, e, "USN:") == p)
                   && (find(p, e, ":device:InternetGatewayDevice:") || find(p, e, ":service:WANIPConnection:")
                       || find(p, e, ":service:WANPPPConnection:")))
            igd = 1;
        p = nl ? nl + 1 : end;
    }
    if (!igd || !ls)
        return -1;
    trim(&ls, &le);
    return parse_url(ls, le, gw, loc);
}

/* a chunked body decoded in place: its length, -1 when malformed */
static long dechunk(char *p, const char *end)
{
    char *w = p, *start = p;
    for (;;) {
        size_t n = 0;
        int digits = 0, v;
        for (; p < end && (((v = lower((unsigned char)*p)) >= '0' && v <= '9') || (v >= 'a' && v <= 'f')); p++, digits++)
            if ((n = n * 16 + (size_t)(v <= '9' ? v - '0' : v - 'a' + 10)) > (size_t)(end - p))
                return -1;
        if (!digits)
            return -1;
        while (p < end && *p != '\n')       /* chunk extensions */
            p++;
        if (p++ == end)
            return -1;
        if (n == 0)
            return w - start;
        if ((size_t)(end - p) < n)
            return -1;
        memmove(w, p, n);
        w += n;
        p += n;
        if (p < end && *p == '\r')
            p++;
        if (p == end || *p++ != '\n')
            return -1;
    }
}

int npf_upnp_parse_http(char *buf, size_t len, const char **body, size_t *blen)
{
    const char *end = buf + len, *h, *v;
    char *b;
    if (len < 12 || find(buf, buf + 7, "HTTP/1.") != buf || buf[8] != ' ' || memcmp(buf + 9, "200", 3) != 0
        || !(h = find(buf, end, "\r\n\r\n")))
        return -1;
    b = buf + (h - buf) + 4;
    *body = b;
    *blen = (size_t)(end - b);
    if ((v = find(buf, h, "\r\nTransfer-Encoding:")) != NULL) {
        const char *e = find(v + 2, h + 2, "\r\n");
        long n;
        if (!find(v, e, "chunked") || (n = dechunk(b, end)) < 0)
            return -1;
        *blen = (size_t)n;
    } else if ((v = find(buf, h, "\r\nContent-Length:")) != NULL) {
        size_t n = 0;
        for (v += 17; *v == ' ' || *v == '\t'; v++)
            ;
        if (*v < '0' || *v > '9')
            return -1;
        for (; *v >= '0' && *v <= '9'; v++)
            if ((n = n * 10 + (size_t)(*v - '0')) > *blen)
                return -1;              /* cut short */
        *blen = n;
    }
    return 0;
}

/* urn:schemas-upnp-org:service:WAN{IP,PPP}Connection:N */
static int wan_type(const char *s, const char *e)
{
    static const char *const t[] = {"urn:schemas-upnp-org:service:WANIPConnection:",
                                    "urn:schemas-upnp-org:service:WANPPPConnection:"};
    size_t i, n;
    for (i = 0; i < 2; i++) {
        const char *p = s + (n = strlen(t[i]));
        if ((size_t)(e - s) <= n || memcmp(s, t[i], n) != 0)
            continue;
        while (p < e && *p >= '0' && *p <= '9')
            p++;
        if (p == e)
            return 1;
    }
    return 0;
}

int npf_upnp_parse_desc(const char *xml, size_t len, uint32_t gw, const npf_upnp_url *loc, npf_upnp_url *ctl,
                        char *st, size_t stcap, int nth)
{
    const char *end = xml + len, *p = xml, *s, *e, *cs, *ce;
    npf_upnp_url base = *loc;
    if (element(xml, end, "URLBase", &s, &e) == 0 && s < e && parse_url(s, e, gw, &base) < 0)
        return -1;                      /* a base elsewhere: nothing of this description */
    while ((p = find(p, end, "<service>")) != NULL) {
        const char *se = find(p, end, "</service>");
        if (!se)
            return -1;
        if (element(p, se, "serviceType", &s, &e) == 0 && wan_type(s, e) && (size_t)(e - s) < stcap
            && element(p, se, "controlURL", &cs, &ce) == 0 && cs < ce && nth-- == 0) {
            memcpy(st, s, (size_t)(e - s));
            st[e - s] = 0;
            if (find(cs, ce, "http://") == cs)
                return parse_url(cs, ce, gw, ctl);
            if (find(cs, ce, "://"))
                return -1;              /* another scheme */
            ctl->port = base.port;
            return set_path(ctl, cs, ce, *cs != '/');
        }
        p = se;
    }
    return -1;
}

int npf_upnp_parse_extip(const char *body, size_t len, uint8_t ip[4])
{
    const char *end = body + len, *s, *e;
    char a[16];
    struct in_addr x;
    if (!(s = find(body, end, "NewExternalIPAddress>")))
        return -1;
    s += 21;
    if (!(e = memchr(s, '<', (size_t)(end - s))))
        return -1;
    trim(&s, &e);
    if (e - s < 7 || e - s > 15)
        return -1;
    memcpy(a, s, (size_t)(e - s));
    a[e - s] = 0;
    if (inet_pton(AF_INET, a, &x) != 1 || x.s_addr == 0)
        return -1;
    memcpy(ip, &x.s_addr, 4);
    return 0;
}

static int left(int64_t until)
{
    int64_t d = until - npf_mono_ms();
    return d > 0 ? (int)d : 0;
}

/* one HTTP exchange with the gateway: the response into buf (NUL after it)
 * until the gateway closes; -1 on a failure, too large or too late */
static long http_x(uint32_t gw, uint16_t port, const char *req, size_t rlen, char *buf, size_t cap, int64_t until)
{
    struct sockaddr_in a;
    struct pollfd pfd;
    size_t got = 0, sent = 0;
    int fd = npf_socket(AF_INET, SOCK_STREAM, 0, 0), err = 1;
    socklen_t el = sizeof err;
    if (fd < 0)
        return -1;
    if (until > npf_mono_ms() + HTTP_MS)
        until = npf_mono_ms() + HTTP_MS;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = gw;
    a.sin_port = htons(port);
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if ((connect(fd, (const struct sockaddr *)&a, sizeof a) < 0 && !npf_sock_inprogress())
        || poll(&pfd, 1, left(until)) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err)
        goto fail;
    while (sent < rlen) {
        ssize_t r = send(fd, req + sent, rlen - sent, MSG_NOSIGNAL);
        if (r > 0)
            sent += (size_t)r;
        else if (r == 0 || !npf_sock_again() || poll(&pfd, 1, left(until)) <= 0)
            goto fail;
    }
    pfd.events = POLLIN;
    for (;;) {
        ssize_t r;
        if (poll(&pfd, 1, left(until)) <= 0)
            goto fail;
        if ((r = recv(fd, buf + got, cap - 1 - got, 0)) == 0)
            break;
        if (r < 0 && (!npf_sock_again() || !left(until)))
            goto fail;
        if (r > 0 && (got += (size_t)r) == cap - 1)
            goto fail;                  /* too large */
    }
    npf_sock_close(fd);
    buf[got] = 0;
    return (long)got;
fail:
    npf_sock_close(fd);
    return -1;
}

static const char *const sts[] = {
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1"};

static void msearch(int fd, const struct sockaddr_in *to, int multicast)
{
    char m[256], host[INET_ADDRSTRLEN];
    size_t i;
    inet_ntop(AF_INET, &to->sin_addr, host, sizeof host);
    for (i = 0; i < sizeof sts / sizeof *sts; i++) {
        int l = snprintf(m, sizeof m, "M-SEARCH * HTTP/1.1\r\nHOST: %s:%u\r\nMAN: \"ssdp:discover\"\r\n%sST: %s\r\n\r\n",
                         host, ntohs(to->sin_port), multicast ? "MX: 2\r\n" : "", sts[i]);
        (void)!sendto(fd, m, (size_t)l, 0, (const struct sockaddr *)to, sizeof *to);
    }
}

/* M-SEARCH to the gateway (unicast) and, on the real network, the SSDP
 * group on the gateway's interface; the first IGD answer from the gateway */
static int ssdp(uint32_t gw, uint16_t port, int multicast, npf_upnp_url *loc)
{
    struct sockaddr_in uc, mc;
    int64_t t0 = npf_mono_ms(), next = t0;
    int fd = npf_udp_socket(AF_INET, 0), sent = 0, other = 0, found = -1;
    struct pollfd pfd;
    if (fd < 0)
        return -1;
    memset(&uc, 0, sizeof uc);
    uc.sin_family = AF_INET;
    uc.sin_addr.s_addr = gw;
    uc.sin_port = htons(port);
    mc = uc;
    if (multicast) {                    /* out on the interface toward the gateway */
        struct sockaddr_in la;
        socklen_t ll = sizeof la;
        int t = npf_udp_socket(AF_INET, 1);
        if (t >= 0 && connect(t, (const struct sockaddr *)&uc, sizeof uc) == 0
            && getsockname(t, (struct sockaddr *)&la, &ll) == 0)
            (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &la.sin_addr, sizeof la.sin_addr);
        if (t >= 0)
            npf_sock_close(t);
        inet_pton(AF_INET, "239.255.255.250", &mc.sin_addr);
        mc.sin_port = htons(NPF_UPNP_SSDP_PORT);
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    while (found < 0 && left(t0 + SSDP_MS)) {
        char buf[1501];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t r;
        if (sent < 2 && npf_mono_ms() >= next) {
            msearch(fd, &uc, 0);
            if (multicast)
                msearch(fd, &mc, 1);
            sent++;
            next += 1000;
        }
        if (poll(&pfd, 1, sent < 2 ? left(next) : left(t0 + SSDP_MS)) <= 0)
            continue;
        while (found < 0 && (r = recvfrom(fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl)) > 0) {
            if (from.sin_addr.s_addr != gw)
                other++;                /* only the gateway is asked: nobody else on the LAN */
            else
                found = npf_upnp_parse_ssdp(buf, (size_t)r, gw, loc);
            fl = sizeof from;
        }
    }
    npf_sock_close(fd);
    if (other)
        npf_logd("upnp: %d SSDP answers from other hosts than the gateway ignored", other);
    return found;
}

int npf_upnp_detect(uint8_t ip[4])
{
    const char *t = getenv("NPF_TEST_UPNP_GW");     /* tests: "IP:PORT" of a stand-in, unicast only */
    struct in_addr g;
    uint16_t port = NPF_UPNP_SSDP_PORT;
    npf_upnp_url loc, ctl;
    char host[INET_ADDRSTRLEN], req[1024], st[96], *desc = NULL, *soap = NULL;
    const char *body, *sb;
    size_t blen, slen;
    long n;
    int64_t until;
    int got = NPF_UPNP_PRESENT, i;
    if (t) {
        char a[64], *colon;
        snprintf(a, sizeof a, "%s", t);
        if ((colon = strrchr(a, ':')) != NULL) {
            *colon = 0;
            port = (uint16_t)atoi(colon + 1);
        }
        if (inet_pton(AF_INET, a, &g) != 1)
            return -1;
    } else if (npf_portmap_gateway_v4(&g) < 0) {
        return -1;
    }
    inet_ntop(AF_INET, &g, host, sizeof host);
    if (ssdp(g.s_addr, port, !t, &loc) < 0) {
        npf_logd("upnp: no IGD answer from the gateway %s", host);
        return NPF_UPNP_NONE;
    }
    until = npf_mono_ms() + ALL_MS;
    npf_logd("upnp: an IGD at the gateway, description at port %u %s", loc.port, loc.path);
    n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n", loc.path, host, loc.port);
    if (!(desc = malloc(DESC_MAX)) || !(soap = malloc(SOAP_MAX))
        || (n = http_x(g.s_addr, loc.port, req, (size_t)n, desc, DESC_MAX, until)) < 0
        || npf_upnp_parse_http(desc, (size_t)n, &body, &blen) < 0) {
        npf_logd("upnp: no device description");
        goto out;
    }
    for (i = 0; i < TRIES && got != NPF_UPNP_ADDR
                && npf_upnp_parse_desc(body, blen, g.s_addr, &loc, &ctl, st, sizeof st, i) == 0; i++) {
        char env[512];
        int el = snprintf(env, sizeof env,
                          "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                          "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>"
                          "<u:GetExternalIPAddress xmlns:u=\"%s\"></u:GetExternalIPAddress></s:Body></s:Envelope>\r\n", st);
        n = snprintf(req, sizeof req,
                     "POST %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
                     "SOAPAction: \"%s#GetExternalIPAddress\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                     ctl.path, host, ctl.port, st, el, env);
        if (n > 0 && (size_t)n < sizeof req && (n = http_x(g.s_addr, ctl.port, req, (size_t)n, soap, SOAP_MAX, until)) >= 0
            && npf_upnp_parse_http(soap, (size_t)n, &sb, &slen) == 0 && npf_upnp_parse_extip(sb, slen, ip) == 0)
            got = NPF_UPNP_ADDR;
        else
            npf_logd("upnp: no WAN address from %s at port %u %s", st, ctl.port, ctl.path);
    }
out:
    free(desc);
    free(soap);
    return got;
}

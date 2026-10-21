/* Callee target policy (security.md D22, data-channel.md 7): only what the
 * published resources cover; "lan" is the host itself and its directly
 * attached private subnets, "*" everything; nothing published, nothing
 * allowed. And the resources themselves (resources.h). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/peers.h"
#include "npf/resources.h"
#include "npf/tunnel.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static int allowed4(npf_policy *p, const char *ip, int port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return npf_policy_allowed(p, (struct sockaddr *)&a);
}

static int udp4(npf_policy *p, const char *ip, int port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return npf_policy_udp_allowed(p, (struct sockaddr *)&a);
}

static int allowed6(npf_policy *p, const char *ip, int port)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons((uint16_t)port);
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return npf_policy_allowed(p, (struct sockaddr *)&a);
}

int test_policy(void)
{
    npf_policy p;
    memset(&p, 0, sizeof p);
    CHECK(!allowed4(&p, "127.0.0.1", 80) && !allowed4(&p, "192.168.1.1", 80), "nothing published, nothing allowed");
    CHECK(npf_policy_add(&p, "lan") == 0 && p.lan && p.nrules == 0, "lan");

    {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        CHECK(!npf_policy_allowed(NULL, (struct sockaddr *)&a), "no policy allows nothing");
    }
    CHECK(allowed4(&p, "127.0.0.1", 80), "loopback allowed");
    CHECK(allowed4(&p, "127.5.6.7", 22), "all of 127/8 allowed");
    CHECK(allowed4(&p, "0.0.0.0", 80), "0.0.0.0 is the host itself");
    CHECK(allowed6(&p, "::1", 80), "::1 allowed");
    CHECK(!allowed4(&p, "1.1.1.1", 80), "public IPv4 refused");
    CHECK(!allowed6(&p, "2001:4860:4860::8888", 53), "public IPv6 refused");
    CHECK(!allowed6(&p, "::ffff:1.1.1.1", 80), "v4-mapped public address refused");
    CHECK(allowed6(&p, "::ffff:127.0.0.1", 80), "v4-mapped loopback allowed");
    /* the interface addresses themselves are local (there is at least loopback) */
    CHECK(p.nlocal >= 2, "local rules computed (%d)", p.nlocal);

    /* resource targets: network, single host with a port range */
    CHECK(npf_policy_add(&p, "10.1.0.0/16") == 0, "add a /16");
    CHECK(npf_policy_add(&p, "192.0.2.10:80-443") == 0, "add host:ports");
    CHECK(npf_policy_add(&p, "[2001:db8::]/32") == 0, "add an IPv6 prefix");
    CHECK(npf_policy_add(&p, "[2001:db9::5]:8080") == 0, "add IPv6 host:port");
    CHECK(allowed4(&p, "10.1.200.3", 9999), "inside the /16");
    CHECK(!allowed4(&p, "10.2.0.1", 80), "outside the /16");
    CHECK(allowed4(&p, "192.0.2.10", 443), "host in the port range");
    CHECK(!allowed4(&p, "192.0.2.10", 8080), "host outside the port range");
    CHECK(!allowed4(&p, "192.0.2.11", 443), "neighbour of the host refused");
    CHECK(allowed6(&p, "2001:db8:ffff::1", 1), "inside the IPv6 prefix");
    CHECK(!allowed6(&p, "2001:db7::1", 1), "outside the IPv6 prefix");
    CHECK(allowed6(&p, "2001:db9::5", 8080), "IPv6 host:port");
    CHECK(!allowed6(&p, "2001:db9::5", 8081), "IPv6 host, other port");
    CHECK(npf_policy_add(&p, "[2001:dba::]/48:443") == 0, "add an IPv6 prefix with a port");
    CHECK(allowed6(&p, "2001:dba:0:1::7", 443), "inside the IPv6 prefix, its port");
    CHECK(!allowed6(&p, "2001:dba:0:1::7", 80), "inside the IPv6 prefix, another port");
    CHECK(npf_policy_add(&p, "[2001:dba::]/48:") < 0 && npf_policy_add(&p, "[2001:dba::]/129:443") < 0,
          "IPv6 prefix with a bad port or prefix rejected");

    CHECK(npf_policy_add(&p, "300.1.1.1") < 0, "bad address rejected");
    CHECK(npf_policy_add(&p, "10.0.0.0/33") < 0, "bad prefix rejected");
    CHECK(npf_policy_add(&p, "[2001:db8::") < 0, "unclosed bracket rejected");
    CHECK(npf_policy_add(&p, "nonsense") < 0, "name rejected");
    {   /* R6: wrong numbers are refused, not read loosely (/typo was /0: everything) */
        static const char *const bad[] = {"10.0.0.0/", "10.0.0.0/typo", "10.0.0.0/24junk", "10.0.0.0/-1",
                                          "10.0.0.0/99999999999999999999", "192.0.2.1:", "192.0.2.1:65536",
                                          "192.0.2.1:65537", "192.0.2.1:-5", "192.0.2.1:0", "192.0.2.1:443-80",
                                          "192.0.2.1:80-", "192.0.2.1:80x", "192.0.2.1:80-90-100",
                                          "[2001:db8::]/abc", "[2001:db8::]/129", "[2001:db8::5]:70000",
                                          "[2001:db8::5]:", "[2001:db8::]/32:", "[2001:db8::]/32:0", NULL};
        int i, before = p.nrules;
        for (i = 0; bad[i]; i++)
            CHECK(npf_policy_add(&p, bad[i]) < 0, "bad rule %s rejected", bad[i]);
        CHECK(p.nrules == before, "no bad rule entered the table");
        CHECK(!allowed4(&p, "203.0.113.9", 443), "a public address stays refused");
        CHECK(npf_policy_add(&p, "198.51.100.0/24:1-65535") == 0 && allowed4(&p, "198.51.100.7", 65535),
              "full port range");
    }
    {
        int before = p.nrules, i;
        for (i = 0; i < 80; i++)
            npf_policy_add(&p, "10.9.9.9");
        CHECK(p.nrules <= 64 && p.nrules >= before, "rule table bounded (%d)", p.nrules);
    }
    CHECK(npf_policy_add(&p, "*") == 0 && allowed4(&p, "1.1.1.1", 80), "* allows everything (an exit node)");
    npf_policy_clear(&p);
    CHECK(!allowed4(&p, "127.0.0.1", 80) && !p.lan && !p.any, "cleared: nothing allowed");

    /* resources: the policy they make; the fields checked */
    {
        npf_res r[4];
        char e[200];
        memset(r, 0, sizeof r);
        CHECK(npf_res_from_line(&r[0], "tcp/http 127.0.0.1:8080/admin NAS 管理 | 网页管理界面", e, sizeof e) == 0
                  && strcmp(r[0].name, "NAS 管理") == 0 && strcmp(r[0].target, "127.0.0.1:8080") == 0
                  && strcmp(r[0].type, "tcp") == 0 && strcmp(r[0].svc, "http") == 0 && npf_res_is_web(&r[0])
                  && strcmp(r[0].path, "/admin") == 0 && strcmp(r[0].desc, "网页管理界面") == 0 && r[0].fixed,
              "a conf line: %s", e);
        CHECK(npf_res_from_line(&r[1], "tcp/ssh localhost:22 ssh", e, sizeof e) == 0 && strcmp(r[1].svc, "ssh") == 0
                  && !npf_res_is_web(&r[1]), "localhost, a service: %s", e);
        CHECK(npf_res_from_line(&r[2], "net 192.168.50.0/24 office", e, sizeof e) == 0, "a net: %s", e);
        CHECK(npf_res_from_line(&r[3], "socks * exit | the internet", e, sizeof e) == 0, "socks *: %s", e);
        CHECK(npf_res_rules(&p, r, 3) == 0, "rules of three");
        CHECK(allowed4(&p, "127.0.0.1", 8080) && !allowed4(&p, "127.0.0.1", 8081), "a service: its port only");
        CHECK(allowed4(&p, "127.0.0.1", 22) && allowed6(&p, "::1", 22), "localhost: v4 and v6");
        CHECK(allowed4(&p, "0.0.0.0", 8080), "0.0.0.0 is the host itself");
        CHECK(allowed4(&p, "192.168.50.9", 445) && !allowed4(&p, "192.168.51.9", 445), "a net");
        CHECK(!allowed4(&p, "1.1.1.1", 80) && !p.lan, "nothing else");
        CHECK(npf_res_rules(&p, r, 4) == 0 && allowed4(&p, "1.1.1.1", 80), "with the exit");
        CHECK(npf_res_rules(&p, r, 0) == 0 && !allowed4(&p, "127.0.0.1", 8080), "none: nothing");
        {   /* reverse: the ports a caller may have this node listen on (-R) */
            npf_res rv[2];
            CHECK(!npf_policy_reverse_ok(&p, 8000, 0) && !npf_policy_reverse_ok(NULL, 8000, 0), "no reverse resource: -R refused");
            CHECK(npf_res_from_line(&rv[0], "reverse 8000-8009 rv", e, sizeof e) == 0, "reverse range: %s", e);
            CHECK(npf_res_rules(&p, rv, 1) == 0 && npf_policy_reverse_ok(&p, 8000, 0) && npf_policy_reverse_ok(&p, 8009, 0)
                      && !npf_policy_reverse_ok(&p, 8010, 0) && !npf_policy_reverse_ok(&p, 0, 0)
                      && !npf_policy_reverse_ok(&p, 8000, 1)
                      && !allowed4(&p, "127.0.0.1", 8000),
                  "reverse 8000-8009: those ports on loopback, no system-chosen one, not for the LAN, no target");
            CHECK(npf_res_from_line(&rv[1], "reverse * any", e, sizeof e) == 0, "reverse *: %s", e);
            CHECK(npf_res_rules(&p, rv, 2) == 0 && npf_policy_reverse_ok(&p, 0, 0) && npf_policy_reverse_ok(&p, 65535, 0)
                      && !npf_policy_reverse_ok(&p, 1023, 0),
                  "reverse *: 1024 and up, and one the system picks");
            CHECK(npf_res_from_line(&rv[1], "reverse lan:9000-9001 lan", e, sizeof e) == 0, "reverse lan:: %s", e);
            CHECK(npf_res_rules(&p, rv, 2) == 0 && npf_policy_reverse_ok(&p, 9000, 1) && npf_policy_reverse_ok(&p, 9001, 0)
                      && !npf_policy_reverse_ok(&p, 8000, 1) && npf_policy_reverse_ok(&p, 8000, 0)
                      && !npf_policy_reverse_ok(&p, 9002, 1),
                  "reverse lan:9000-9001: those ports on every address too; 8000-8009 on loopback only");
            {
                struct sockaddr_in a;
                memset(&a, 0, sizeof a);
                a.sin_family = AF_INET;
                inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
                CHECK(npf_policy_lan_peer(&p, (struct sockaddr *)&a), "lan peer: this host");
                inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);
                CHECK(!npf_policy_lan_peer(&p, (struct sockaddr *)&a), "lan peer: not the internet");
            }
            npf_policy_clear(&p);
            CHECK(!npf_policy_reverse_ok(&p, 8000, 0), "cleared: no -R");
        }
        {
            static const char *const bad[] = {"web 127.0.0.1:80 x", "tcp/http example.com:80 x", "tcp/http 127.0.0.1 x",
                                              "tcp/http 127.0.0.1:0 x", "tcp/http 127.0.0.1:80", "tcp 127.0.0.1:22/a x",
                                              "net 10.0.0.0/33 x", "socks nowhere x", "tcp/http ::1:80 x",
                                              "http 127.0.0.1:80 x", "tcp/rdp 127.0.0.1:3389/a x", "tcp/RDP 127.0.0.1:3389 x",
                                              "tcp/ 127.0.0.1:3389 x", "tcp/abcdefghijklmnop 127.0.0.1:1 x", "net/rdp lan x",
                                              "tcp/r_p 127.0.0.1:3389 x",
                                              "reverse 80 x", "reverse 9000-8000 x", "reverse 70000 x", "reverse lan: x", "reverse wan:8000 x",
                                              "reverse lan x", NULL};
            int i;
            npf_res b;
            for (i = 0; bad[i]; i++)
                CHECK(npf_res_from_line(&b, bad[i], e, sizeof e) < 0, "bad resource %s refused", bad[i]);
        }
        {   /* JSON there and back; names unique */
            npf_out o = {0};
            char *n1, *n2;
            npf_res_json(&o, r, 4);
            n1 = npf_res_normalize(o.p, o.len);
            n2 = n1 ? npf_res_normalize(n1, strlen(n1)) : NULL;
            CHECK(n1 && n2 && strcmp(n1, n2) == 0 && strstr(n1, "\"path\":\"/admin\"")
                      && strstr(n1, "\"type\":\"tcp\",\"svc\":\"http\""), "JSON round trip: %s",
                  n1 ? n1 : "-");
            free(n1);
            free(n2);
            static const char old[] = "[{\"name\":\"w\",\"type\":\"https\",\"target\":\"127.0.0.1:443\",\"path\":\"/a\"}]";
            n1 = npf_res_normalize(old, strlen(old));
            CHECK(n1 && strstr(n1, "\"type\":\"tcp\",\"svc\":\"https\"") && strstr(n1, "\"path\":\"/a\""),
                  "a web page saved as type https is read as tcp/https: %s", n1 ? n1 : "-");
            free(n1);
            static const char dup[] = "[{\"name\":\"a\",\"target\":\"127.0.0.1:1\"},"
                                      "{\"name\":\"a\",\"target\":\"127.0.0.1:2\"}]";
            n1 = npf_res_normalize(dup, strlen(dup));
            CHECK(!n1, "two of one name refused");
            free(n1);
            npf_out_free(&o);
        }
    }


    /* UDP (data-channel.md 15): only "udp" resources let it through; "lan"
     * and "*" (net, socks) are TCP only, and a udp resource opens no TCP */
    {
        npf_policy q;
        npf_res r[3];
        memset(&q, 0, sizeof q);
        memset(r, 0, sizeof r);
        strcpy(r[0].name, "dns");
        strcpy(r[0].type, "udp");
        strcpy(r[0].target, "localhost:53");
        strcpy(r[1].name, "all");
        strcpy(r[1].type, "net");
        strcpy(r[1].target, "*");
        strcpy(r[2].name, "game");
        strcpy(r[2].type, "udp");
        strcpy(r[2].target, "192.0.2.7:27015");
        {
            char err[160];
            CHECK(npf_res_check(&r[0], err, sizeof err) == 0, "a udp resource is valid: %s", err);
        }
        CHECK(npf_res_rules(&q, r, 3) == 0 && q.nudp == 3, "udp rules (localhost is two): %d", q.nudp);
        CHECK(udp4(&q, "127.0.0.1", 53) && udp4(&q, "192.0.2.7", 27015), "the udp resources allow UDP");
        CHECK(!udp4(&q, "127.0.0.1", 54) && !udp4(&q, "10.0.0.1", 53), "nothing else: net * is TCP only");
        CHECK(allowed4(&q, "192.0.2.8", 80), "net * allows TCP");
        npf_policy_clear(&q);
        CHECK(q.nudp == 0 && !udp4(&q, "127.0.0.1", 53), "clear takes the udp rules too");
        memset(&q, 0, sizeof q);
        CHECK(npf_res_rules(&q, r, 1) == 0 && !allowed4(&q, "127.0.0.1", 53), "a udp resource opens no TCP");
    }

    /* the control interface (the web console) is never a forward's target */
    {
        struct sockaddr_storage g;
        struct sockaddr_in d;
        npf_res r;
        char err[200];
        memset(&g, 0, sizeof g);
        ((struct sockaddr_in *)&g)->sin_family = AF_INET;
        ((struct sockaddr_in *)&g)->sin_port = htons(24411);
        inet_pton(AF_INET, "127.158.73.84", &((struct sockaddr_in *)&g)->sin_addr);
        memset(&d, 0, sizeof d);
        d.sin_family = AF_INET;
        d.sin_port = htons(24411);
        inet_pton(AF_INET, "127.158.73.84", &d.sin_addr);
        CHECK(!npf_guard_blocked((struct sockaddr *)&d), "nothing guarded yet");
        npf_guard_control(&g);
        CHECK(npf_guard_blocked((struct sockaddr *)&d), "its own address and port");
        inet_pton(AF_INET, "127.0.0.1", &d.sin_addr);
        CHECK(npf_guard_blocked((struct sockaddr *)&d), "another loopback address, the same port");
        d.sin_port = htons(24412);
        CHECK(!npf_guard_blocked((struct sockaddr *)&d), "another port");
        d.sin_port = htons(24411);
        inet_pton(AF_INET, "192.0.2.9", &d.sin_addr);
        CHECK(!npf_guard_blocked((struct sockaddr *)&d), "another host's port");
        memset(&r, 0, sizeof r);
        strcpy(r.name, "console");
        strcpy(r.type, "tcp");
        strcpy(r.target, "localhost:24411");
        CHECK(npf_res_check(&r, err, sizeof err) == 0, "a resource naming it is taken (the connection is what fails): %s", err);
    }
    return fails;
}

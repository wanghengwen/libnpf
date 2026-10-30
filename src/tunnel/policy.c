/* Callee target policy: the published resources (security.md D22, data-channel.md 7, resources.h). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <string.h>

#include "npf/lock.h"
#include "npf/platform.h"
#include "npf/text.h"
#include "npf/tunnel.h"

#define REFRESH_MS 30000

static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, zero[16];  /* ::1, :: */

static int prefix_match(const uint8_t *a, const uint8_t *b, int bits)
{
    int i;
    for (i = 0; bits >= 8; i++, bits -= 8)
        if (a[i] != b[i])
            return 0;
    if (bits) {
        uint8_t m = (uint8_t)(0xff << (8 - bits));
        if ((a[i] & m) != (b[i] & m))
            return 0;
    }
    return 1;
}

static int is_private4(const uint8_t *a)
{
    return a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16) || (a[0] == 192 && a[1] == 168);
}

static int is_private6(const uint8_t *a)
{
    return (a[0] & 0xfe) == 0xfc;           /* fc00::/7 */
}

static void add_local(npf_policy *p, int fam, const uint8_t *addr, int prefix)
{
    npf_policy_rule *r;
    if (p->nlocal >= (int)(sizeof p->local / sizeof p->local[0]))
        return;
    r = &p->local[p->nlocal++];
    memset(r, 0, sizeof *r);
    r->family = fam;
    memcpy(r->addr, addr, fam == AF_INET ? 4 : 16);
    r->prefix = prefix;
    r->port_hi = 65535;
}

void npf_policy_refresh(npf_policy *p)
{
    static const uint8_t lo4[4] = {127, 0, 0, 0};
    p->nlocal = 0;
    add_local(p, AF_INET, lo4, 8);
    add_local(p, AF_INET6, lo6, 128);
    {
        npf_ifaddr ifs[64];
        int k, n = npf_if_list(ifs, 64);
        for (k = 0; k < n; k++) {
            const uint8_t *a = ifs[k].addr;
            int fam = ifs[k].family;
            /* the interface's own address is always local */
            add_local(p, fam, a, fam == AF_INET ? 32 : 128);
            /* its subnet only when private: a public prefix (VPS, global IPv6)
             * would turn the callee into a proxy for strangers' hosts */
            if (ifs[k].prefix > 0 && (fam == AF_INET ? is_private4(a) : is_private6(a)))
                add_local(p, fam, a, ifs[k].prefix);
        }
    }
    p->refreshed_ms = npf_mono_ms();
}

/* "PORT" or "LO-HI", 1..65535, LO <= HI; the numbers here strict (npf_text_dec:
 * atoi read "typo" as 0, a /0 prefix that allowed every address, and cast
 * 65537 to port 1) */
static int ports(char *s, npf_policy_rule *r)
{
    char *dash = strchr(s, '-');
    long lo, hi;
    if (dash)
        *dash = 0;
    if (npf_text_dec(s, 1, 65535, &lo) < 0)
        return -1;
    hi = lo;
    if (dash && (npf_text_dec(dash + 1, 1, 65535, &hi) < 0 || hi < lo))
        return -1;
    r->port_lo = (uint16_t)lo;
    r->port_hi = (uint16_t)hi;
    return 0;
}

/* the prefix after '/' (slash points at the '/' or is NULL: the whole address) */
static int prefix(const char *slash, int max, int *out)
{
    long v = max;
    if (slash && npf_text_dec(slash + 1, 0, max, &v) < 0)
        return -1;
    *out = (int)v;
    return 0;
}

static int parse_rule(const char *spec, npf_policy_rule *out)
{
    char buf[128], *slash = NULL, *colon = NULL;
    npf_policy_rule r;
    if (strlen(spec) >= sizeof buf)
        return -1;
    memset(&r, 0, sizeof r);
    strcpy(buf, spec);
    r.port_hi = 65535;
    /* "addr[/prefix][:lo[-hi]]"; an IPv6 address goes in brackets when a
     * prefix or a port follows: "[2001:db8::]/32", "[2001:db8::5]:443",
     * "[2001:db8::]/32:443" */
    if (buf[0] == '[') {
        char *rb = strchr(buf, ']');
        if (!rb)
            return -1;
        *rb = 0;
        if (rb[1] == ':')
            colon = rb + 1;
        else if (rb[1] == '/')
            colon = strchr(slash = rb + 1, ':');    /* a port after the prefix */
        else if (rb[1])
            return -1;
        memmove(buf, buf + 1, strlen(buf + 1) + 1);   /* only the address moves; slash, colon stay put */
    } else if (strchr(buf, '.')) {
        colon = strchr(buf, ':');
    }
    if (colon) {
        *colon = 0;
        if (ports(colon + 1, &r) < 0)
            return -1;
    }
    if (!slash)
        slash = strchr(buf, '/');
    if (slash)
        *slash = 0;
    if (inet_pton(AF_INET, buf, r.addr) == 1) {
        r.family = AF_INET;
        if (prefix(slash, 32, &r.prefix) < 0)
            return -1;
    } else if (inet_pton(AF_INET6, buf, r.addr) == 1) {
        r.family = AF_INET6;
        if (prefix(slash, 128, &r.prefix) < 0)
            return -1;
    } else {
        return -1;
    }
    *out = r;
    return 0;
}

/* one rule more into rules[*n] (cap of them); 0, -1 bad or full */
static int add_rule(npf_policy_rule *rules, int *n, int cap, const char *spec)
{
    if (*n >= cap || parse_rule(spec, &rules[*n]) < 0)
        return -1;
    (*n)++;
    return 0;
}

int npf_policy_add(npf_policy *p, const char *spec)
{
    if (strcmp(spec, "*") == 0)
        p->any = 1;
    else if (strcmp(spec, "lan") == 0)
        p->lan = 1;
    else
        return add_rule(p->rules, &p->nrules, (int)(sizeof p->rules / sizeof p->rules[0]), spec);
    return 0;
}

int npf_policy_add_udp(npf_policy *p, const char *spec)
{
    if (strcmp(spec, "*") != 0)
        return add_rule(p->udp, &p->nudp, (int)(sizeof p->udp / sizeof p->udp[0]), spec);
    p->udp_any = 1;
    return 0;
}

void npf_policy_clear(npf_policy *p)
{
    p->nrules = 0;
    p->nudp = 0;
    p->lan = p->any = p->udp_any = 0;
    p->nrev = 0;
}

/* the ports as the other rules write them (ports(): digits only), at least 1024 */
int npf_policy_add_reverse(npf_policy *p, const char *spec)
{
    npf_policy_rule r = {0};
    char buf[16];
    int lan = strncmp(spec, "lan:", 4) == 0;
    if (lan)
        spec += 4;
    r.port_lo = 1024;
    r.port_hi = 65535;
    if (p->nrev >= (int)(sizeof p->rev / sizeof p->rev[0])
        || (strcmp(spec, "*") != 0
            && (strlen(spec) >= sizeof buf || ports(strcpy(buf, spec), &r) < 0 || r.port_lo < 1024)))
        return -1;
    p->rev[p->nrev].lo = r.port_lo;
    p->rev[p->nrev].hi = r.port_hi;
    p->rev[p->nrev].lan = (uint8_t)lan;
    p->nrev++;
    return 0;
}

int npf_policy_reverse_ok(const npf_policy *p, int port, int lan)
{
    int i;
    if (!p)
        return 0;
    for (i = 0; i < p->nrev; i++)
        if ((!lan || p->rev[i].lan)
            && (port == 0 ? p->rev[i].lo == 1024 && p->rev[i].hi == 65535 : port >= p->rev[i].lo && port <= p->rev[i].hi))
            return 1;
    return 0;
}

/* the "lan" rules, computed again when older than REFRESH_MS */
static void lan_fresh(npf_policy *p)
{
    if (!p->refreshed_ms || npf_mono_ms() - p->refreshed_ms > REFRESH_MS)
        npf_policy_refresh(p);
}

int npf_policy_lan_peer(npf_policy *p, const struct sockaddr *a)
{
    lan_fresh(p);
    return npf_policy_rules_match(p->local, p->nlocal, a);
}

/* port -1: any */
static int match(const npf_policy_rule *r, int n, int fam, const uint8_t *a, int port)
{
    int i;
    for (i = 0; i < n; i++)
        if (r[i].family == fam && prefix_match(a, r[i].addr, r[i].prefix)
            && (port < 0 || (port >= r[i].port_lo && port <= r[i].port_hi)))
            return 1;
    return 0;
}

/* the address of sa as 16 bytes (a v4-mapped IPv6 address, ::ffff:a.b.c.d,
 * as IPv4), its family and port; dst: 0.0.0.0/8 as 127.0.0.1 (it reaches
 * the host itself on Linux). 0, or -1 for another family */
static int sa_parts(const struct sockaddr *sa, int dst, uint8_t a[16], int *famp, uint16_t *portp)
{
    int fam = sa->sa_family;
    uint16_t port;
    if (fam == AF_INET) {
        memcpy(a, &((const struct sockaddr_in *)sa)->sin_addr, 4);
        port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    } else if (fam == AF_INET6) {
        const struct in6_addr *v6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(v6)) {
            fam = AF_INET;
            memcpy(a, (const uint8_t *)v6 + 12, 4);
        } else {
            memcpy(a, v6, 16);
        }
    } else {
        return -1;
    }
    if (dst && fam == AF_INET && a[0] == 0)
        memcpy(a, (const uint8_t[]){127, 0, 0, 1}, 4);
    *famp = fam;
    *portp = port;
    return 0;
}

int npf_policy_rules_match(const npf_policy_rule *r, int n, const struct sockaddr *sa)
{
    uint8_t a[16];
    int fam;
    uint16_t port;
    if (sa_parts(sa, 0, a, &fam, &port) < 0)
        return 0;
    return match(r, n, fam, a, -1);
}

/* UDP: only the "udp" resources (theirs "*" too), never net's or socks'
 * "lan" or "*" (data-channel.md 15) */
int npf_policy_udp_allowed(npf_policy *p, const struct sockaddr *dst)
{
    uint8_t a[16];
    int fam;
    uint16_t port;
    if (!p || sa_parts(dst, 1, a, &fam, &port) < 0)
        return 0;
    if (p->udp_any)
        return 1;
    return match(p->udp, p->nudp, fam, a, port);
}

int npf_policy_allowed(npf_policy *p, const struct sockaddr *dst)
{
    uint8_t a[16];
    int fam;
    uint16_t port;
    if (!p)
        return 0;
    if (p->any)
        return 1;
    if (sa_parts(dst, 1, a, &fam, &port) < 0)
        return 0;
    if (match(p->rules, p->nrules, fam, a, port))
        return 1;
    if (!p->lan)
        return 0;                               /* nothing published covers it */
    lan_fresh(p);
    return match(p->local, p->nlocal, fam, a, port);
}

/* ---- this host's own control interface: never a forward's target ---- */

/* the addresses the control interfaces of this process listen on (the web
 * console and its API: a forward to it would hand those connecting this
 * node's console, and through it every resource of it); set by the
 * program's thread, read by every loop's */
#define GUARDS 4
static struct sockaddr_storage g_guard[GUARDS];
static int g_nguard;
static npf_mutex g_guard_mu = NPF_MUTEX_INIT;

static int is_any(int fam, const uint8_t *a)
{
    return memcmp(a, zero, fam == AF_INET ? 4 : 16) == 0;
}

static int is_loopback(int fam, const uint8_t *a)
{
    return fam == AF_INET ? a[0] == 127 || a[0] == 0 : memcmp(a, lo6, 16) == 0 || is_any(fam, a);
}

int npf_guard_control(const struct sockaddr_storage *a, int on)
{
    int i, rc = 0;
    npf_mutex_lock(&g_guard_mu);
    for (i = 0; i < g_nguard && memcmp(&g_guard[i], a, sizeof *a) != 0; i++)
        ;
    if (!on && i < g_nguard)
        g_guard[i] = g_guard[--g_nguard];
    else if (on && i == g_nguard && g_nguard < GUARDS)
        g_guard[g_nguard++] = *a;
    else if (on && i == g_nguard)
        rc = -1;
    npf_mutex_unlock(&g_guard_mu);
    return rc;
}

int npf_guard_blocked(const struct sockaddr *dst)
{
    struct sockaddr_storage gs[GUARDS];
    uint8_t d[16], g[16];
    int df, gf, i, ng;
    uint16_t dp, gp;
    npf_mutex_lock(&g_guard_mu);            /* a copy: npf_if_has is slow */
    ng = g_nguard;
    memcpy(gs, g_guard, sizeof gs);
    npf_mutex_unlock(&g_guard_mu);
    if (!ng || sa_parts(dst, 0, d, &df, &dp) < 0)
        return 0;
    for (i = 0; i < ng; i++) {
        if (sa_parts((const struct sockaddr *)&gs[i], 0, g, &gf, &gp) < 0 || gp != dp)
            continue;
        /* its port on this host: a loopback address (any of 127/8, the port
         * may be served there too), its own address, or any local one when
         * it listens on all of them */
        if (is_loopback(df, d) || (df == gf && memcmp(d, g, df == AF_INET ? 4 : 16) == 0)
            || (is_any(gf, g) && npf_if_has(df, d)))
            return 1;
    }
    return 0;
}

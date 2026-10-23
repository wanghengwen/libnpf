/* Calls: reverse mapping (-R), the callee's listeners and the caller's requests */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* ---- reverse mapping, callee side (data-channel.md 7.1) ---- */

/* an address of this host's interfaces (a -R listening on one of them) */
static int own_addr(const char *a)
{
    npf_ifaddr ifs[32];
    unsigned char b[16];
    int fam, len, n, i;
    if (inet_pton(AF_INET, a, b) == 1)
        fam = AF_INET, len = 4;
    else if (inet_pton(AF_INET6, a, b) == 1)
        fam = AF_INET6, len = 16;
    else
        return 0;
    n = npf_if_list(ifs, 32);
    for (i = 0; i < n; i++)
        if (ifs[i].family == fam && memcmp(ifs[i].addr, b, (size_t)len) == 0)
            return 1;
    return 0;
}

/* the published resources still let this listener be (a "reverse" resource
 * removed, its ports narrowed, its "lan:" taken back: no longer) */
static int rev_allowed(struct rev_listener *l)
{
    return npf_policy_reverse_ok(call_policy(l->c), l->want, l->lan);
}

static void rev_accept(npf_loop *loop, int lfd, unsigned ev, void *arg)
{
    struct rev_listener *l = arg;
    (void)loop;
    (void)ev;
    for (;;) {
        int fd = npf_accept(lfd);
        if (fd < 0)
            break;
        if (!rev_allowed(l)) {          /* npf_node_reverse_recheck closes it; until then, nothing */
            npf_sock_close(fd);
            continue;
        }
        if (l->lan) {
            /* listening on every address: from this host and its LAN only, as
             * the reverse resource says ("lan:"), not the internet */
            struct sockaddr_storage from;
            socklen_t fl = sizeof from;
            struct npf_policy *p = call_policy(l->c);
            if (getpeername(fd, (struct sockaddr *)&from, &fl) < 0 || !p
                || !npf_policy_lan_peer(p, (struct sockaddr *)&from)) {
                if (npf_mono_ms() - l->refused_ms > 60000) {
                    char a[64] = "?";
                    npf_addr_str(&from, a, sizeof a);
                    npf_logw("call %s: reverse mapping port: %s is not on this host's LAN, refused", l->c->call_id_s, a);
                    l->refused_ms = npf_mono_ms();
                }
                npf_sock_close(fd);
                continue;
            }
        }
        /* the callee is the SOCKS5 client here: CONNECT the registered target back on the caller */
        if (!l->c->tun || npf_tunnel_open(l->c->tun, fd, 0, l->host, l->port) < 0)
            npf_sock_close(fd);
    }
}

/* a datagram on a -R .../udp listener: a flow of ours (even numbers) back to
 * the caller, who sends it to the target it registered */
static void rev_udp(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    struct rev_listener *l = arg;
    npf_call *c = l->c;
    uint8_t *buf = npf_scratch(NPF_UDP_PAYLOAD_MAX + 1);
    int k;
    (void)loop;
    (void)ev;
    if (!buf)
        return;
    for (k = 0; k < 64; k++) {
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, NPF_UDP_PAYLOAD_MAX + 1, 0, (struct sockaddr *)&from, &fl);
        struct npf_policy *p = call_policy(c);
        if (r < 0) {
            if (npf_sock_again())
                break;
            continue;                       /* an ICMP error of an earlier reply */
        }
        if (r > NPF_UDP_PAYLOAD_MAX || !rev_allowed(l))
            continue;
        if (l->lan && (!p || !npf_policy_lan_peer(p, (struct sockaddr *)&from))) {
            if (npf_mono_ms() - l->refused_ms > 60000) {
                char a[64] = "?";
                npf_addr_str(&from, a, sizeof a);
                npf_logw("call %s: reverse mapping port (UDP): %s is not on this host's LAN, dropped", c->call_id_s, a);
                l->refused_ms = npf_mono_ms();
            }
            continue;
        }
        if (c->state == NPF_CALL_ESTABLISHED && call_udp_of(c))
            npf_udpf_send_rev(c->udp, fd, &from, fl, l->id, buf, (size_t)r);
    }
    npf_scratch_done(buf);
}

void call_rev_close_all(npf_call *c)
{
    int i;
    for (i = 0; i < c->nrev; i++) {
        npf_loop_del(c->n->loop, c->rev[i].fd);
        npf_sock_close(c->rev[i].fd);
    }
    c->nrev = 0;
}

/* close listener i; the last one takes its place */
static void rev_close(npf_call *c, int i)
{
    if (c->rev[i].udp)
        npf_udpf_forget_fd(c->udp, c->rev[i].fd);   /* its flows end */
    npf_loop_del(c->n->loop, c->rev[i].fd);
    npf_sock_close(c->rev[i].fd);
    c->rev[i] = c->rev[--c->nrev];
    if (i < c->nrev) {                  /* moved: re-register with its new address */
        npf_loop_del(c->n->loop, c->rev[i].fd);
        npf_loop_add(c->n->loop, c->rev[i].fd, NPF_EV_READ, c->rev[i].udp ? rev_udp : rev_accept, &c->rev[i]);
    }
}

void npf_node_reverse_recheck(npf_node *n)
{
    npf_call *c;
    int i;
    for (c = n->calls; c; c = c->next)
        for (i = c->nrev - 1; i >= 0; i--)
            if (!rev_allowed(&c->rev[i])) {
                char m[112];
                int len = snprintf(m, sizeof m, "{\"v\":1,\"type\":\"reverse_closed\",\"data\":"
                                   "{\"listen_id\":%u,\"reason\":\"forbidden\"}}", c->rev[i].id);
                npf_log("call %s: reverse mapping %u closed: the published resources no longer allow it",
                        c->call_id_s, c->rev[i].id);
                if (c->tun && npf_tunnel_is_ready(c->tun))  /* the caller forgets it (reverse_closed) */
                    npf_tunnel_control(c->tun, m, (size_t)len);
                rev_close(c, i);
            }
}

void call_reverse_request(npf_call *c, const char *type, const npf_json *j)
{
    int d = npf_json_get(j, 0, "data"), i, fd;
    int64_t port = 0, tport, lid;
    char bind_addr[64] = "127.0.0.1", host[256], reply[96];
    struct sockaddr_storage ss;
    socklen_t sl;
    int lan, udp = 0, ut = npf_json_get(j, d, "udp");
    if (strcmp(type, "reverse_close") == 0) {
        if (npf_json_get_int(j, d, "listen_id", 1, UINT32_MAX, &lid) == 0)
            for (i = 0; i < c->nrev; i++)
                if (c->rev[i].id == (uint32_t)lid) {
                    rev_close(c, i);
                    break;
                }
        npf_call_ctl_reply(c, type, j, "ok", NULL, NULL);
        return;
    }
    if (c->hosted_grant) {              /* a hosted client (security.md 8.4): -L only, its grant's targets */
        npf_call_ctl_reply(c, type, j, "error", "forbidden", NULL);
        return;
    }
    npf_json_get_str(j, d, "bind", bind_addr, sizeof bind_addr);
    npf_json_get_int(j, d, "port", 0, 65535, &port);
    if (npf_json_get_str(j, d, "target_host", host, sizeof host) <= 0
        || npf_json_get_int(j, d, "target_port", 1, 65535, &tport) < 0) {
        npf_call_ctl_reply(c, type, j, "error", "bad_request", NULL);
        return;
    }
    /* policy: a port a "reverse" resource publishes (0, chosen by us: with
     * "*"), on loopback; on every address, or on one of this host's own,
     * only when it says "lan:" (and then from this host and its LAN only);
     * 16 per session */
    if (strcmp(bind_addr, "localhost") == 0)
        strcpy(bind_addr, "127.0.0.1");
    if (!bind_addr[0] || strcmp(bind_addr, "*") == 0)
        strcpy(bind_addr, "0.0.0.0");
    lan = strcmp(bind_addr, "127.0.0.1") != 0 && strcmp(bind_addr, "::1") != 0;
    if ((lan && strcmp(bind_addr, "0.0.0.0") != 0 && strcmp(bind_addr, "::") != 0 && !own_addr(bind_addr))
        || !npf_policy_reverse_ok(call_policy(c), (int)port, lan)) {
        npf_call_ctl_reply(c, type, j, "error", "forbidden", NULL);
        return;
    }
    if (c->nrev >= NPF_MAX_REVERSE) {
        npf_call_ctl_reply(c, type, j, "error", "rate_limited", NULL);
        return;
    }
    {
        char a[80];
        snprintf(a, sizeof a, strchr(bind_addr, ':') ? "[%s]:%d" : "%s:%d", bind_addr, (int)port);
        npf_addr_parse(a, &ss);
    }
    if (ut >= 0)
        npf_json_bool(j, ut, &udp);         /* -R .../udp: a UDP socket (data-channel.md 15) */
    fd = npf_socket(ss.ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0, 0);
    npf_sock_listen_opts(fd, udp ? SOCK_DGRAM : SOCK_STREAM);   /* a UDP port is not shared: no other listener's */
    if (fd >= 0 && strcmp(bind_addr, "::") == 0) {
        int zero = 0;                       /* "::": IPv4 too */
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof zero);
    }
    sl = ss.ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (fd < 0 || bind(fd, (struct sockaddr *)&ss, sl) < 0 || (!udp && listen(fd, 32) < 0)) {
        if (fd >= 0)
            npf_sock_close(fd);
        npf_call_ctl_reply(c, type, j, "error", "conflict", NULL);
        return;
    }
    getsockname(fd, (struct sockaddr *)&ss, &sl);
    i = c->nrev++;
    c->rev[i].c = c;
    c->rev[i].id = ++c->rev_seq;
    c->rev[i].fd = fd;
    snprintf(c->rev[i].host, sizeof c->rev[i].host, "%s", host);
    c->rev[i].port = (uint16_t)tport;
    c->rev[i].lan = lan;
    c->rev[i].want = (int)port;
    c->rev[i].refused_ms = 0;
    c->rev[i].udp = udp;
    npf_loop_add(c->n->loop, fd, NPF_EV_READ, udp ? rev_udp : rev_accept, &c->rev[i]);
    snprintf(reply, sizeof reply, "{\"listen_id\":%u,\"port\":%u}", c->rev[i].id,
             ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port : ((struct sockaddr_in *)&ss)->sin_port));
    npf_call_ctl_reply(c, type, j, "ok", NULL, reply);
    npf_log("call %s: reverse mapping%s %s -> caller %s:%d", c->call_id_s, udp ? " (UDP)" : "", reply, host, (int)tport);
}

/* ---- reverse mapping, caller side ---- */

typedef struct rev_req {
    char host[256];
    uint16_t port;
    int udp;
    npf_rev_fn fn;
    void *arg;
} rev_req;

static void rev_reply(npf_call *c, const npf_json *j, int ok, void *arg)
{
    rev_req *r = arg;
    int64_t id = 0, port = 0;
    int d = j ? npf_json_get(j, 0, "data") : -1;
    char err[32] = "";
    if (ok && npf_json_get_int(j, d, "listen_id", 1, UINT32_MAX, &id) == 0
        && npf_json_get_int(j, d, "port", 1, 65535, &port) == 0) {
        if (c->tun && (r->udp ? npf_udpf_rev_add(call_udp_of(c), (uint32_t)id, r->host, r->port)
                              : npf_tunnel_rev_add(c->tun, (uint32_t)id, r->host, r->port)) == 0) {
            r->fn(c, (int)port, (uint32_t)id, NULL, r->arg);
            free(r);
            return;
        }
        npf_call_reverse_close(c, (uint32_t)id);    /* listening there, not usable here: not left behind */
    } else if (j) {
        npf_json_get_str(j, 0, "error", err, sizeof err);
    }
    r->fn(c, -1, 0, err[0] ? err : j ? "failed" : "no reply", r->arg);
    free(r);
}

int npf_call_reverse(npf_call *c, const char *bind_addr, int port, const char *host, uint16_t hostport, int udp,
                     npf_rev_fn fn, void *arg)
{
    char data[512];
    npf_jw w;
    rev_req *r = calloc(1, sizeof *r);
    if (!r || strlen(host) >= sizeof r->host) {
        free(r);
        return -1;
    }
    strcpy(r->host, host);
    r->port = hostport;
    r->udp = udp;
    r->fn = fn;
    r->arg = arg;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "bind", bind_addr);
    npf_jw_kint(&w, "port", port);
    npf_jw_kstr(&w, "target_host", host);
    npf_jw_kint(&w, "target_port", hostport);
    if (udp) {
        npf_jw_kbool(&w, "udp", 1);
        npf_udpf_prepare(call_udp_of(c));   /* the stream the callee sends on */
    }
    npf_jw_end(&w);
    if (npf_jw_finish(&w) < 0 || npf_call_ctl_request(c, "reverse_listen", data, rev_reply, r) < 0) {
        free(r);
        return -1;
    }
    return 0;
}

void npf_call_reverse_close(npf_call *c, uint32_t listen_id)
{
    char data[48];
    if (c->tun)
        npf_tunnel_rev_del(c->tun, listen_id);
    npf_udpf_rev_del(c->udp, listen_id);
    snprintf(data, sizeof data, "{\"listen_id\":%u}", listen_id);
    npf_call_ctl_event(c, "reverse_close", data);  /* an event: no request slot it could fail for */
}

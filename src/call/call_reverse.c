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
    unsigned char b[16];
    int fam = inet_pton(AF_INET, a, b) == 1 ? AF_INET : inet_pton(AF_INET6, a, b) == 1 ? AF_INET6 : 0;
    return fam && npf_if_has(fam, b);
}

/* the published resources still let this listener be (a "reverse" resource
 * removed, its ports narrowed, its "lan:" taken back: no longer) */
static int rev_allowed(struct rev_map *l)
{
    return npf_policy_reverse_ok(call_policy(l->c), l->want, l->lan);
}

static void rev_accept(npf_loop *loop, int lfd, unsigned ev, void *arg)
{
    struct rev_map *l = arg;
    int k;
    (void)loop;
    (void)ev;
    for (k = 0; k < 64; k++) {
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
            struct sockaddr_storage from = {0};
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
    struct rev_map *l = arg;
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
        if (call_up(c) && call_udp_of(c))
            npf_udpf_send_rev(c->udp, fd, &from, fl, l->id, buf, (size_t)r);
    }
    npf_scratch_done(buf);
}

/* a mapping more (NPF_MAX_REVERSE at most), or NULL */
static struct rev_map *rev_new(npf_call *c, uint32_t id, int fd, const char *host, uint16_t port, int udp)
{
    struct rev_map *r;
    if (c->nrev >= NPF_MAX_REVERSE || strlen(host) >= sizeof r->host || !(r = calloc(1, sizeof *r)))
        return NULL;
    r->c = c;
    r->id = id;
    r->fd = fd;
    strcpy(r->host, host);
    r->port = port;
    r->udp = udp;
    return c->rev[c->nrev++] = r;
}

static void rev_free(npf_call *c, struct rev_map *r)
{
    if (r->fd >= 0) {
        npf_loop_del(c->n->loop, r->fd);
        npf_sock_close(r->fd);
    }
    free(r);
}

void call_rev_close_all(npf_call *c)
{
    while (c->nrev)
        rev_free(c, c->rev[--c->nrev]);
}

/* end mapping i, its UDP flows with it; the last one takes its place */
static void rev_close(npf_call *c, int i)
{
    struct rev_map *r = c->rev[i];
    if (r->udp && r->fd >= 0)
        npf_udpf_forget_fd(c->udp, r->fd);
    else if (r->udp)
        npf_udpf_rev_del(c->udp, r->id);
    c->rev[i] = c->rev[--c->nrev];
    rev_free(c, r);
}

void call_rev_drop(npf_call *c, uint32_t id)
{
    int i;
    for (i = 0; i < c->nrev; i++)
        if (c->rev[i]->id == id) {
            rev_close(c, i);
            return;
        }
}

/* caller: the target of a reverse sublink (host:port) or UDP flow (its id) */
const struct rev_map *call_rev_target(const npf_call *c, int udp, uint32_t id, const char *host, uint16_t port)
{
    int i;
    for (i = 0; i < c->nrev; i++) {
        const struct rev_map *r = c->rev[i];
        if (r->udp == udp && (udp ? r->id == id : r->port == port && strcmp(r->host, host) == 0))
            return r;
    }
    return NULL;
}

void npf_node_reverse_recheck(npf_node *n)
{
    npf_call *c;
    int i;
    for (c = n->calls; c; c = c->next)
        for (i = c->nrev - 1; i >= 0 && !c->caller; i--)
            if (!rev_allowed(c->rev[i])) {
                char m[64];
                snprintf(m, sizeof m, "{\"listen_id\":%u,\"reason\":\"forbidden\"}", c->rev[i]->id);
                npf_log("call %s: reverse mapping %u closed: the published resources no longer allow it",
                        c->call_id_s, c->rev[i]->id);
                npf_call_ctl_event(c, "reverse_closed", m);     /* the caller forgets it */
                rev_close(c, i);
            }
}

void call_reverse_request(npf_call *c, const m_env *e)
{
    const char *type = e->type;
    const npf_json *j = e->j;
    int fd, udp, lan;
    int64_t port;
    char bind_addr[64], reply[96];
    struct rev_map *l;
    struct sockaddr_storage ss;
    socklen_t sl;
    m_reverse_listen m;
    if (strcmp(type, "reverse_close") == 0) {
        m_listen_id li;
        if (npf_msg_parse(&m_listen_id_d, j, e->data, &li, NULL, 0) == 0)
            call_rev_drop(c, (uint32_t)li.listen_id);
        npf_call_ctl_reply(c, type, j, "ok", NULL, NULL);
        return;
    }
    if (c->hosted_grant) {              /* a hosted client (security.md 8.4): -L only, its grant's targets */
        npf_call_ctl_reply(c, type, j, "error", "forbidden", NULL);
        return;
    }
    if (npf_msg_parse(&m_reverse_listen_d, j, e->data, &m, reply, sizeof reply) < 0) {
        npf_logd("call %s: reverse_listen refused (%s)", c->call_id_s, reply);
        npf_call_ctl_reply(c, type, j, "error", "bad_request", NULL);
        return;
    }
    port = m.port;
    udp = m.udp;                        /* -R .../udp: a UDP socket (data-channel.md 15) */
    snprintf(bind_addr, sizeof bind_addr, "%s", m.bind[0] ? m.bind : "127.0.0.1");
    /* policy: a port a "reverse" resource publishes (0, chosen by us: with
     * "*"), on loopback; on every address, or on one of this host's own,
     * only when it says "lan:" (and then from this host and its LAN only);
     * 16 per session */
    if (strcmp(bind_addr, "localhost") == 0)
        strcpy(bind_addr, "127.0.0.1");
    if (strcmp(bind_addr, "*") == 0)
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
    fd = npf_socket(ss.ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0, 0);
    if (fd >= 0)
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
    if (!(l = rev_new(c, ++c->rev_seq, fd, m.target_host, (uint16_t)m.target_port, udp))) {
        npf_sock_close(fd);
        npf_call_ctl_reply(c, type, j, "error", "internal_error", NULL);
        return;
    }
    l->lan = lan;
    l->want = (int)port;
    if (npf_loop_add(c->n->loop, fd, NPF_EV_READ, udp ? rev_udp : rev_accept, l) < 0) {
        c->nrev--;                  /* not on the loop: drop the slot, close fd */
        rev_free(c, l);
        npf_call_ctl_reply(c, type, j, "error", "internal_error", NULL);
        return;
    }
    snprintf(reply, sizeof reply, "{\"listen_id\":%u,\"port\":%u}", l->id, npf_addr_port(&ss));
    npf_call_ctl_reply(c, type, j, "ok", NULL, reply);
    npf_log("call %s: reverse mapping%s %s -> caller %s:%d", c->call_id_s, udp ? " (UDP)" : "", reply, m.target_host,
            (int)m.target_port);
}

/* ---- reverse mapping, caller side ---- */

typedef struct rev_req {
    char host[256];
    uint16_t port;
    int udp;
    npf_rev_fn fn;
    void *arg;
} rev_req;

static void rev_reply(npf_call *c, const npf_env *e, int ok, void *arg)
{
    rev_req *r = arg;
    m_listening m;
    const char *err = !e ? "no reply" : e->error[0] ? e->error : "failed";
    if (ok && npf_msg_parse(&m_listening_d, e->j, e->data, &m, NULL, 0) == 0) {
        if (c->tun && rev_new(c, (uint32_t)m.listen_id, -1, r->host, r->port, r->udp)) {
            r->fn(c, (int)m.port, (uint32_t)m.listen_id, NULL, r->arg);
            free(r);
            return;
        }
        npf_call_reverse_close(c, (uint32_t)m.listen_id);  /* listening there, not usable here: not left behind */
    }
    r->fn(c, -1, 0, err, r->arg);
    free(r);
}

int npf_call_reverse(npf_call *c, const char *bind_addr, int port, const char *host, uint16_t hostport, int udp,
                     npf_rev_fn fn, void *arg)
{
    npf_out w = {0};
    int rc;
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
    npf_out_jobj(&w);
    npf_out_kstr(&w, "bind", bind_addr);
    npf_out_kint(&w, "port", port);
    npf_out_kstr(&w, "target_host", host);
    npf_out_kint(&w, "target_port", hostport);
    if (udp) {
        npf_out_kbool(&w, "udp", 1);
        npf_udpf_prepare(call_udp_of(c));   /* the stream the callee sends on */
    }
    npf_out_jend(&w);
    rc = w.failed ? -1 : npf_call_ctl_request(c, "reverse_listen", w.p, rev_reply, r);
    npf_out_free(&w);
    if (rc < 0)
        free(r);
    return rc < 0 ? -1 : 0;
}

void npf_call_reverse_close(npf_call *c, uint32_t listen_id)
{
    char data[48];
    call_rev_drop(c, listen_id);
    snprintf(data, sizeof data, "{\"listen_id\":%u}", listen_id);
    npf_call_ctl_event(c, "reverse_close", data);  /* an event: no request slot it could fail for */
}

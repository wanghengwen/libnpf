/* Forward definitions, listeners, retries and state. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/conf.h"
#include "npf/out.h"
#include "npf/crypto.h"
#include "npf/peers.h"
#include "npf/tunnel.h"
#include "npf.h"
#include "npf/platform.h"
#include "udpfwd.h"

#include "peers_internal.h"

static void fwd_start(pfwd *f);

#define FWD_BACKOFF_MAX_MS 60000

/* ---- forwards ---- */

/* the listening address as given: empty or "*" is every address */
static const char *bind_of(const char *s)
{
    return !*s || strcmp(s, "*") == 0 ? "0.0.0.0" : s;
}

/* the slot after the last (p->nfwd), allocated, zeroed: counted once taken */
static pfwd *fwd_slot(npf_peer *p)
{
    pfwd *f = p->fwds[p->nfwd];
    if (!f && !(f = p->fwds[p->nfwd] = malloc(sizeof *f)))
        return NULL;
    memset(f, 0, sizeof *f);
    f->idx = p->nfwd;
    return f;
}

/* f from its parts, checked; its spec (for the log) written from them */
static int fwd_fill(pfwd *f, const npf_fwd_new *fn, char *err, size_t errcap)
{
    const char *bind = fn->bind ? bind_of(fn->bind) : "127.0.0.1";
    int socks = fn->opt == 'D';
    if (strcmp(bind, "localhost") == 0)
        bind = "127.0.0.1";                 /* as the callee takes it: the spec and the state stay the same */
    if (fn->opt != 'L' && fn->opt != 'D' && fn->opt != 'R') {
        snprintf(err, errcap, "-L, -D or -R");
        return -1;
    }
    if (fn->port < 0 || fn->port > 65535 || strlen(bind) >= sizeof f->bind) {
        snprintf(err, errcap, "bad listening port or address");
        return -1;
    }
    if (!socks && (!fn->host || !*fn->host || strlen(fn->host) >= sizeof f->host || strchr(fn->host, ' ')
                   || fn->hostport <= 0 || fn->hostport > 65535)) {
        snprintf(err, errcap, "the target needs a host and a port");
        return -1;
    }
    if (fn->udp && socks) {
        snprintf(err, errcap, "UDP forwards are -L or -R, not -D");
        return -1;
    }
    f->opt = fn->opt;
    f->socks = socks;
    f->reverse = fn->opt == 'R';
    f->udp = fn->udp;
    f->fd = -1;
    f->used = 1;
    snprintf(f->bind, sizeof f->bind, "%s", bind);
    f->port = fn->port;
    snprintf(f->host, sizeof f->host, "%s", socks ? "" : fn->host);
    f->hostport = socks ? 0 : fn->hostport;
    {                                       /* what it is, for people (the logs, the status) */
        int b6 = strchr(f->bind, ':') != NULL, h6 = strchr(f->host, ':') != NULL, o;
        o = snprintf(f->spec, sizeof f->spec, "%s%s %s%s%s:%d", f->reverse ? "remote" : socks ? "socks" : "local",
                     f->udp ? " udp" : "", b6 ? "[" : "", f->bind, b6 ? "]" : "", f->port);
        if (!socks)
            snprintf(f->spec + o, sizeof f->spec - (size_t)o, " -> %s%s%s:%d", h6 ? "[" : "", f->host, h6 ? "]" : "",
                     f->hostport);
    }
    return 0;
}

/* the same forward, however it was written */
static int fwd_same(const pfwd *a, const pfwd *b)
{
    if (a->kind || b->kind)
        return a->kind == b->kind && strcmp(a->spec, b->spec) == 0;
    return a->opt == b->opt && a->udp == b->udp && a->port == b->port && a->hostport == b->hostport
        && strcmp(a->bind, b->bind) == 0 && strcmp(a->host, b->host) == 0;
}

/* ---- the modules' kinds of forward ---- */

int npf_peers_add_kind(npf_peers *ps, const npf_fwd_kind *k, void *arg)
{
    if (ps->nkinds >= NPF_FWD_KINDS || k->opt < 'A' || k->opt > 'Z' || k->opt == 'L' || k->opt == 'D'
        || k->opt == 'R')
        return -1;
    ps->kinds[ps->nkinds].k = k;
    ps->kinds[ps->nkinds++].arg = arg;
    return 0;
}

static const struct kind_reg *kind_of(const npf_peers *ps, char opt)
{
    int i;
    for (i = 0; i < ps->nkinds; i++)
        if (ps->kinds[i].k->opt == opt)
            return &ps->kinds[i];
    return NULL;
}

/* -X SPEC of a kind: checked by it, the form it keeps in spec */
static int parse_kind(pfwd *f, const struct kind_reg *r, const char *spec, char *err, size_t errcap)
{
    if (r->k->parse(r->arg, spec, f->spec, sizeof f->spec, err, errcap) < 0)
        return -1;
    f->kind = r;
    f->fd = -1;
    f->used = 1;
    return 0;
}

/* the same forward of a kind (as kept) goes through another peer already? */
static int kind_taken(const npf_peers *ps, const pfwd *f, char *err, size_t errcap)
{
    const npf_peer *q;
    int i;
    for (q = ps->list; q; q = q->next)
        for (i = 0; i < q->nfwd; i++)
            if (q->fwds[i]->used && q->fwds[i]->kind == f->kind && strcmp(q->fwds[i]->spec, f->spec) == 0) {
                snprintf(err, errcap, "-%c %s goes through %s already (forward #%d)", f->kind->k->opt, f->spec,
                         q->name, q->fwds[i]->id);
                return 1;
            }
    return 0;
}

static int kind_check(const pfwd *f, char *err, size_t errcap)
{
    return f->kind->k->check ? f->kind->k->check(f->kind->arg, f->spec, err, errcap) : 0;
}

/* a forward for the log: what it is, or a module's kind in its form */
static const char *fwd_label(const pfwd *f, char *b, size_t cap)
{
    if (f->kind)
        snprintf(b, cap, "-%c %s", f->opt, f->spec);
    else
        snprintf(b, cap, "%s", f->spec);
    return b;
}

/* a connection or a datagram may wait for the session: a peer that will
 * have one (on demand, or kept), not one that ended (no password, no
 * account: it was closed after DEMAND_WAIT_MS instead of at once) */
static int peer_may_wait(const npf_peer *p)
{
    return !p->finished && (p->idle_ms || p->keep);
}

static void accept_resume(npf_loop *loop, void *arg)
{
    pfwd *f = arg;
    f->t_accept = NULL;
    if (f->fd >= 0)
        npf_loop_mod(loop, f->fd, NPF_EV_READ);
}

/* accept failed for want of descriptors or memory: the connection stays
 * queued and the listener readable, so it waits a moment (else the loop
 * would spin on it) */
static int accept_starved(void)
{
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEMFILE || e == WSAENOBUFS;
#else
    return errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM;
#endif
}

/* a public connection whose visitor went away (no FIN: off line, a NAT
 * that forgot it) ends within about 4 minutes, not when the idle check
 * finds it */
static void public_keepalive(int fd)
{
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&one, sizeof one);
#ifdef TCP_KEEPIDLE
    {
        int idle = 120, intvl = 30, cnt = 4;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (const char *)&idle, sizeof idle);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char *)&intvl, sizeof intvl);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (const char *)&cnt, sizeof cnt);
    }
#endif
}

#define ACCEPT_ROUND 64                 /* connections taken per wakeup: the loop's other work goes on */

static void accept_cb(npf_loop *loop, int lfd, unsigned ev, void *arg)
{
    pfwd *f = arg;
    int round;
    (void)ev;
    for (round = 0; round < ACCEPT_ROUND; round++) {
        int fd;
        /* a callback of the last round (refused, opened, a session's start)
         * may have removed the peer or the forward: lfd closed, maybe reused */
        if (f->p->removed || !f->used || f->fd != lfd)
            break;
        fd = npf_accept(lfd);
        if (fd < 0) {
            if (accept_starved() && !f->t_accept) {
                npf_logw("%s: %s: out of descriptors, not accepting for 250 ms", f->p->name, f->spec);
                npf_loop_mod(loop, lfd, 0);
                f->t_accept = npf_timer_add(loop, 250, accept_resume, f);
            }
            break;
        }
        uint64_t cid = 0;
        if (f->pub) {                       /* a public mapping: who may, how many */
            struct sockaddr_storage ss;
            socklen_t sl = sizeof ss;
            const char *why = NULL;
            int ip = -1;
            memset(&ss, 0, sizeof ss);
            if (getpeername(fd, (struct sockaddr *)&ss, &sl) < 0) {
                why = "allow_from";
            } else {
                peers_unmap_v4(&ss);
                if (f->acl && !npf_policy_rules_match(f->acl, f->nacl, (const struct sockaddr *)&ss))
                    why = "allow_from";
                else if (f->draining)
                    why = "quota";          /* the account's quota is used up */
                else
                    why = peers_conn_admit(f, &ss, &ip);
            }
            if (why) {
                npf_sock_close(fd);
                peers_conn_refused(f, &ss, why);
                continue;
            }
            cid = peers_conn_add(f, &ss, ip);
            if (!cid) {                     /* no memory to track it: not let in untracked (limits, idle) */
                npf_sock_close(fd);
                continue;
            }
            public_keepalive(fd);
        } else if (f->draining) {
            npf_sock_close(fd);
            continue;
        }
        if (peer_may_wait(f->p)
            && (!f->p->call || npf_call_state(f->p->call) != NPF_CALL_ESTABLISHED)) {
            /* no session yet (on demand), or between two (a kept peer
             * reconnecting): it waits, and the session starts now */
            peers_demand_wait(f, fd, cid);
            continue;
        }
        peers_conn_open(f, fd, cid);
    }
}

static void udp_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    pfwd *f = arg;
    npf_peer *p = f->p;
    int k;
    (void)loop;
    (void)ev;
    if (!p->ps->ubuf && !(p->ps->ubuf = malloc(NPF_UDP_PAYLOAD_MAX + 1)))
        return;
    for (k = 0; k < 64 && f->fd == fd; k++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        ssize_t r = recvfrom(fd, p->ps->ubuf, NPF_UDP_PAYLOAD_MAX + 1, 0, (struct sockaddr *)&ss, &sl);
        if (r < 0) {
            if (npf_sock_again())
                break;
            continue;                       /* an ICMP error of an earlier reply (Windows: WSAECONNRESET) */
        }
        if (r > NPF_UDP_PAYLOAD_MAX)
            continue;
        if (p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED)
            npf_call_udp_send(p->call, fd, &ss, sl, f->host, (uint16_t)f->hostport, p->ps->ubuf, (size_t)r);
        else if (peer_may_wait(p))
            peers_udp_wait(f, &ss, sl, p->ps->ubuf, (size_t)r);
    }
}

static int fwd_state_of(const pfwd *f)
{
    if (f->up)
        return NPF_FWD_UP;
    if (f->t_retry || f->refused)
        return NPF_FWD_FAILED;
    return NPF_FWD_WAITING;
}

/* the why code of a failure's text */
static int fwd_why_code(const pfwd *f, const char *why)
{
    if (f->refused)
        return NPF_FWD_WHY_FORBIDDEN;
    if (!why)
        return NPF_FWD_WHY_NONE;
    if (strstr(why, "in use") || strstr(why, "taken"))
        return NPF_FWD_WHY_PORT_IN_USE;
    if (strstr(why, "cannot listen") || strstr(why, "bind"))
        return NPF_FWD_WHY_BIND;
    if (strstr(why, "too many") || strstr(why, "limit"))
        return NPF_FWD_WHY_TOO_MANY;
    if (f->reverse)
        return NPF_FWD_WHY_REQUEST;
    return NPF_FWD_WHY_OTHER;
}

/* tell the application when the state, the port in use or the failure changed */
static void fwd_changed(pfwd *f)
{
    npf_peers *ps = f->p->ps;
    int st = fwd_state_of(f);
    if (st == f->told_state && f->lport == f->told_port && f->why_code == f->told_why)
        return;
    f->told_state = st;
    f->told_port = f->lport;
    f->told_why = f->why_code;
    if (ps->cbs.fwd)
        ps->cbs.fwd(f->p, f->idx, st == NPF_FWD_UP, st == NPF_FWD_UP ? NULL : f->why, ps->arg);
}

/* tell the application: the mapping is up, or failed (why) */
static void fwd_report(pfwd *f, int up, const char *why)
{
    if (!up && why && why != f->why)
        snprintf(f->why, sizeof f->why, "%s", why);
    f->why_code = up ? NPF_FWD_WHY_NONE : fwd_why_code(f, why);
    fwd_changed(f);
}

static void fwd_retry_cb(npf_loop *loop, void *arg)
{
    pfwd *f = arg;
    (void)loop;
    f->t_retry = NULL;
    fwd_start(f);
}

/* try this mapping again later; the session goes on */
static void fwd_retry(pfwd *f, const char *why)
{
    int d;
    if (f->t_retry || !f->used)
        return;
    f->backoff = f->backoff ? (f->backoff * 2 > FWD_BACKOFF_MAX_MS ? FWD_BACKOFF_MAX_MS : f->backoff * 2) : 1000;
    d = peers_retry_delay(f->backoff);
    snprintf(f->why, sizeof f->why, "%s", why);
    f->retry_at = npf_mono_ms() + d;
    {
        char lb[320];
        npf_logw("%s: %s: %s, again in %d s", f->p->name, fwd_label(f, lb, sizeof lb), why, (d + 999) / 1000);
    }
    f->t_retry = npf_timer_add(f->p->ps->n->loop, d, fwd_retry_cb, f);
    fwd_report(f, 0, why);
}

void peers_fwd_stop(pfwd *f)
{
    npf_loop *loop = f->p->ps->n->loop;
    if (f->t_retry)
        npf_timer_cancel(loop, f->t_retry);
    f->t_retry = NULL;
    if (f->t_accept)
        npf_timer_cancel(loop, f->t_accept);
    f->t_accept = NULL;
    if (f->udp) {
        peers_udp_queue_drop(f->p, f->idx);
        if (f->fd >= 0 && f->p->call)
            npf_call_udp_forget(f->p->call, f->fd);     /* its flows end */
    }
    if (f->kind && f->up && f->kind->k->down)
        f->kind->k->down(f->kind->arg, f->id);          /* its connections and flows end */
    if (f->fd >= 0) {
        npf_loop_del(loop, f->fd);
        npf_sock_close(f->fd);
        f->fd = -1;
    }
    f->up = 0;
    if (!f->reverse)
        f->lport = 0;
}

static void rev_done(npf_call *call, int port, uint32_t listen_id, const char *err, void *arg)
{
    pfwd *f = arg;
    f->asked = 0;
    if (!f->used || call != f->p->call) {           /* deleted meanwhile, or an old session */
        if (port >= 0 && call == f->p->call)
            npf_call_reverse_close(call, listen_id);
        return;
    }
    if (port < 0 && err && strcmp(err, "forbidden") == 0) {
        /* the callee's policy: the same request is refused again */
        f->refused = 1;
        snprintf(f->why, sizeof f->why, strcmp(f->bind, "0.0.0.0") == 0
                 ? "refused by the device (port or LAN not allowed)" : "refused by the device (its policy)");
        npf_logw("%s: %s: refused by the device's policy", f->p->name, f->spec);
        fwd_report(f, 0, f->why);
        return;
    }
    if (port < 0) {
        fwd_retry(f, err && *err ? err : "refused by the callee");
        return;
    }
    f->up = 1;
    f->rev_id = listen_id;
    f->rport = port;
    f->lport = port;
    f->backoff = 0;
    npf_log("%s: reverse mapping: callee %s:%d -> %s:%d here", f->p->name, f->bind, port, f->host, f->hostport);
    fwd_report(f, 1, NULL);
}

npf_call *npf_peers_fwd_call(npf_peers *ps, int id)
{
    npf_peer *p;
    int i;
    for (p = ps->list; p; p = p->next)
        for (i = 0; i < p->nfwd; i++)
            if (p->fwds[i]->used && p->fwds[i]->kind && p->fwds[i]->id == id) {
                if (npf_call_ready(p->call)) {
                    p->idle_since = 0;
                    return p->call;
                }
                if (!p->call && !p->waiting && !p->finished) {
                    if (p->t_retry) {           /* someone is waiting: no backoff */
                        npf_timer_cancel(ps->n->loop, p->t_retry);
                        p->t_retry = NULL;
                    }
                    npf_log("%s: a connection through -%c %s: starting the session", p->name,
                            p->fwds[i]->kind->k->opt, p->fwds[i]->spec);
                    peers_start_call(p);
                    if (p->idle_ms)
                        peers_demand_timer(p);
                }
                return NULL;
            }
    return NULL;
}


/* start one mapping: a -L / -D listener stays across sessions (it refuses
 * while none is up); a -R mapping is asked of each new session */
/* a TCP listener on bind:port ("::": IPv6 and IPv4 on one socket); the
 * socket, or -1 with why */
/* a listening socket, -1 with why; *in_use: the port is taken (as opposed
 * to the address family missing) */
static int listen_on(const char *bind_host, int port, int type, char *why, size_t whycap, int *in_use)
{
    struct addrinfo hints, *res;
    char ps[8];
    int fd;
    *in_use = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = type;               /* SOCK_DGRAM: a UDP forward's socket, bound only */
    hints.ai_flags = AI_PASSIVE;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(bind_host, ps, &hints, &res) != 0) {
        snprintf(why, whycap, "bad bind address");
        return -1;
    }
    fd = npf_socket(res->ai_family, type, 0, 0);
    if (fd >= 0) {
        npf_sock_listen_opts(fd, type);
        if (res->ai_family == AF_INET6 && strcmp(bind_host, "::") == 0) {
            int zero = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof zero);
        }
    }
    if (fd < 0 || bind(fd, res->ai_addr, res->ai_addrlen) < 0 || (type == SOCK_STREAM && listen(fd, 64) < 0)) {
        *in_use = fd >= 0 && npf_sock_in_use();
        snprintf(why, whycap, "cannot listen: %s", npf_sock_strerror());
        if (fd >= 0)
            npf_sock_close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void fwd_start(pfwd *f)
{
    npf_peer *p = f->p;
    char why[64];
    int in_use, type = f->udp ? SOCK_DGRAM : SOCK_STREAM;
    if (!f->used || f->up || f->t_retry || (f->pub && p->ps->closing))
        return;
    if (f->reverse) {
        if (!p->call || npf_call_state(p->call) != NPF_CALL_ESTABLISHED || f->asked)
            return;
        if (npf_call_reverse(p->call, f->bind, f->port, f->host, (uint16_t)f->hostport, f->udp, rev_done, f) < 0)
            fwd_retry(f, "request failed");
        else
            f->asked = 1, f->refused = 0;
        return;
    }
    if (f->kind) {                          /* a module's: it carries the forward itself */
        char tw[160];
        if (f->kind->k->up(f->kind->arg, f->id, f->spec, tw, sizeof tw) < 0) {
            fwd_retry(f, tw);
            return;
        }
        f->up = 1;
        f->backoff = 0;
        npf_log("%s: -%c %s: through %s", p->name, f->opt, f->spec, f->kind->k->name ? f->kind->k->name(f->kind->arg) : "");
        fwd_report(f, 1, NULL);
        return;
    }
    if ((f->fd = listen_on(f->bind, f->port, type, why, sizeof why, &in_use)) < 0 && !in_use && strcmp(f->bind, "::") == 0) {
        /* no IPv6 on this host: IPv4 only (a port taken is not that) */
        npf_logw("%s: %s: no IPv6 here (%s), listening on IPv4 only", p->name, f->spec, why);
        snprintf(f->bind, sizeof f->bind, "0.0.0.0");
        f->fd = listen_on(f->bind, f->port, type, why, sizeof why, &in_use);
    }
    if (f->fd < 0) {
        fwd_retry(f, why);
        return;
    }
    npf_set_nonblock(f->fd);
    npf_loop_add(p->ps->n->loop, f->fd, NPF_EV_READ, f->udp ? udp_cb : accept_cb, f);
    {                                       /* the port in use (0 asked: the system's choice) */
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        f->lport = f->port;
        if (getsockname(f->fd, (struct sockaddr *)&ss, &sl) == 0)
            f->lport = ss.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6 *)&ss)->sin6_port)
                                                : ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    f->up = 1;
    f->backoff = 0;
    if (f->socks)
        npf_log("%s: SOCKS5 proxy on %s:%d", p->name, f->bind, f->lport);
    else if (f->udp)
        npf_log("%s: forwarding UDP %s:%d -> %s:%d on the callee", p->name, f->bind, f->lport, f->host, f->hostport);
    else
        npf_log("%s: forwarding %s:%d -> %s:%d on the callee", p->name, f->bind, f->lport, f->host, f->hostport);
    fwd_report(f, 1, NULL);
}

void peers_listeners_close(npf_peer *p)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        peers_fwd_stop(p->fwds[i]);
    p->listening = 0;
}

void peers_forwards_start(npf_peer *p)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        fwd_start(p->fwds[i]);
    p->listening = 1;
}

/* the session ended: reverse mappings go with it (asked again next time) */
void peers_forwards_session_gone(npf_peer *p)
{
    int i;
    for (i = 0; i < p->nfwd; i++) {
        pfwd *f = p->fwds[i];
        if (f->reverse) {
            if (f->t_retry)
                npf_timer_cancel(p->ps->n->loop, f->t_retry);
            f->t_retry = NULL;
            f->up = f->asked = 0;
            f->lport = 0;
            if (f->used)
                fwd_changed(f);             /* waiting for the next session */
        }
    }
}

/* two listeners on one port: the same address, or one of them on every address */
static int binds_meet(const char *a, const char *b)
{
    if (strcmp(a, "localhost") == 0)
        a = "127.0.0.1";
    if (strcmp(b, "localhost") == 0)
        b = "127.0.0.1";
    return strcmp(a, b) == 0 || strcmp(a, "0.0.0.0") == 0 || strcmp(b, "0.0.0.0") == 0
        || strcmp(a, "::") == 0 || strcmp(b, "::") == 0;
}

/* a forward of ours (any peer's -L or -D) listening where f would: added,
 * f would only wait for the port, and a page opened on it would reach the
 * other one's target (a stale forward left from before the device moved
 * its service) */
static const pfwd *port_taken(const npf_peers *ps, const pfwd *f, const npf_peer **owner)
{
    const npf_peer *q;
    int i;
    if (!f->port)
        return NULL;                        /* the system picks one */
    for (q = ps->list; q; q = q->next)
        for (i = 0; i < q->nfwd; i++) {
            const pfwd *g = q->fwds[i];
            if (g->used && !g->reverse && !g->kind && !f->kind && g->udp == f->udp && g->port == f->port
                && binds_meet(g->bind, f->bind)) {
                *owner = q;
                return g;
            }
        }
    return NULL;
}

/* f (parsed, its parts in tmp) into a slot of p: its index, or -1 bad, -2 full, -3 other */
static int fwd_put(npf_peer *p, pfwd *tmp, int perm, uint64_t ext, char *err, size_t errcap)
{
    const npf_peer *owner = NULL;
    const pfwd *taken;
    pfwd *f = NULL;
    int i;
    char o = tmp->opt;
    for (i = 0; i < p->nfwd; i++)
        if (p->fwds[i]->used && fwd_same(p->fwds[i], tmp)) {
            snprintf(err, errcap, "%s: forward #%d is that one already (%s)", p->name, p->fwds[i]->id, p->fwds[i]->spec);
            return -1;
        }
    if (tmp->kind) {
        if (kind_taken(p->ps, tmp, err, errcap) || kind_check(tmp, err, errcap) < 0)
            return -1;
    }
    if (o == 'R' && p->idle_ms && !ext) {
        snprintf(err, errcap, "%s: an on-demand node cannot have a reverse forward", p->name);
        return -1;
    }
    /* the platform's mappings report a taken port themselves */
    if (o != 'R' && !ext && (taken = port_taken(p->ps, tmp, &owner))) {
        snprintf(err, errcap, "%s: port %d is taken by forward #%d (%s: %s)", p->name, tmp->port, taken->id,
                 owner->name, taken->spec);
        return -3;
    }
    for (i = 0; i < p->nfwd && !f; i++)
        if (!p->fwds[i]->used && !p->fwds[i]->asked)
            f = p->fwds[i];                /* a free slot, no pending reply points at it (a -R's
                                              reverse_listen answered later took the new one up) */
    if (!f) {
        if (p->nfwd >= NPF_PEER_MAX_FWD) {
            snprintf(err, errcap, "%s: at most %d mappings", p->name, NPF_PEER_MAX_FWD);
            return -2;
        }
        if (!(f = fwd_slot(p))) {
            snprintf(err, errcap, "no memory");
            return -3;
        }
        p->nfwd++;
    }
    tmp->idx = f->idx;
    *f = *tmp;
    f->p = p;
    f->id = ++p->ps->fwd_seq;
    f->perm = perm;
    f->ext = ext;                           /* before it starts: its state callback names it */
    f->told_state = -1;
    if (p->listening || p->call)
        fwd_start(f);
    else
        fwd_changed(f);                     /* waiting */
    return f->idx;
}

int npf_peer_forward_add_parts(npf_peer *p, const npf_fwd_new *fn, int perm, uint64_t ext, char *err, size_t errcap)
{
    pfwd tmp;
    memset(&tmp, 0, sizeof tmp);
    if (fwd_fill(&tmp, fn, err, errcap) < 0)
        return -1;
    return fwd_put(p, &tmp, perm, ext, err, errcap);
}

const char *npf_peers_kind_norm(npf_peers *ps, char opt, const char *spec, char *buf, size_t cap)
{
    const struct kind_reg *r = kind_of(ps, opt);
    char why[160];
    if (!r || r->k->parse(r->arg, spec, buf, cap, why, sizeof why) < 0)
        return spec;
    return buf;
}

int npf_peer_forward_add_kind(npf_peer *p, char opt, const char *spec, int perm, char *err, size_t errcap)
{
    const struct kind_reg *kind = kind_of(p->ps, opt);
    pfwd tmp;
    if (!kind) {
        snprintf(err, errcap, "%s: no kind of forward -%c here", p->name, opt);
        return -1;
    }
    memset(&tmp, 0, sizeof tmp);
    if (parse_kind(&tmp, kind, spec, err, errcap) < 0)
        return -1;
    tmp.opt = opt;
    return fwd_put(p, &tmp, perm, 0, err, errcap);
}

pfwd *peers_fwd_by_id(const npf_peers *ps, int id)
{
    int i;
    npf_peer *p = npf_peers_fwd_find(ps, id, &i);
    return p ? p->fwds[i] : NULL;
}

npf_peer *npf_peers_fwd_find(const npf_peers *ps, int id, int *idx)
{
    npf_peer *p;
    int i;
    for (p = ps && id ? ps->list : NULL; p; p = p->next)
        for (i = 0; i < p->nfwd; i++)
            if (p->fwds[i]->used && p->fwds[i]->id == id) {
                if (idx)
                    *idx = i;
                return p;
            }
    return NULL;
}

int npf_peer_forward_state(const npf_peer *p, int i, npf_fwd_state *st)
{
    const pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return -1;
    f = p->fwds[i];
    memset(st, 0, sizeof *st);
    st->opt = f->opt;
    st->udp = f->udp;
    st->perm = f->perm;
    snprintf(st->bind, sizeof st->bind, "%s", f->bind);
    st->port = f->port;
    st->lport = f->up ? (f->reverse ? f->rport : f->lport) : 0;
    snprintf(st->host, sizeof st->host, "%s", f->host);
    st->hostport = f->hostport;
    st->state = fwd_state_of(f);
    st->why_code = st->state == NPF_FWD_FAILED ? f->why_code : NPF_FWD_WHY_NONE;
    snprintf(st->why, sizeof st->why, "%s", st->state == NPF_FWD_UP ? "" : f->why);
    st->conns = f->open;
    st->refused = f->nrefused;
    snprintf(st->refused_why, sizeof st->refused_why, "%s", f->refused_why);
    st->ctx = f->ctx;
    st->ext = f->ext;
    snprintf(st->spec, sizeof st->spec, "%s", f->spec);
    return 0;
}

void npf_peer_forward_set_ctx(npf_peer *p, int i, void *ctx)
{
    if (i >= 0 && i < p->nfwd && p->fwds[i]->used)
        p->fwds[i]->ctx = ctx;
}

int npf_peer_forward_id(const npf_peer *p, int i)
{
    return i >= 0 && i < p->nfwd && p->fwds[i]->used ? p->fwds[i]->id : 0;
}

int npf_peer_forward_by_id(const npf_peer *p, int id)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        if (p->fwds[i]->used && p->fwds[i]->id == id)
            return i;
    return -1;
}

int npf_peer_forward_del_at(npf_peer *p, int i)
{
    pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return -1;
    f = p->fwds[i];
    if (f->reverse && f->up && p->call)
        npf_call_reverse_close(p->call, f->rev_id);
    /* a public mapping taken off (turned off, expired, deleted): its open
     * connections end with it */
    if (f->pub && p->call && npf_call_group_reset(p->call, (uint32_t)f->id, "mapping_closed") > 0)
        npf_log("%s: %s: closed, its open connections ended", p->name, f->spec);
    peers_demand_drop_slot(p, i);   /* its waiting connections go with it (a forward reusing the slot
                                       got them, past its allow_from), while it still counts them */
    peers_fwd_stop(f);
    if (p->ps->cbs.fwd_gone)
        p->ps->cbs.fwd_gone(p, i, p->ps->arg);
    if (f->t_refused)
        npf_timer_cancel(p->ps->n->loop, f->t_refused);
    f->t_refused = NULL;
    f->used = 0;                    /* a reply still on its way finds the slot unused */
    f->ext = 0;
    f->ctx = NULL;
    free(f->acl);
    f->acl = NULL;
    f->nacl = 0;
    f->rate = 0;
    f->pub = f->draining = f->suspended = 0;
    return 0;
}

int npf_peer_forward_drain(npf_peer *p, int i, int on)
{
    pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return -1;
    f = p->fwds[i];
    if (on) {
        f->draining = 1;
        return 0;
    }
    f->draining = 0;
    if (f->suspended) {
        f->suspended = 0;
        fwd_start(f);                       /* listening again */
    }
    return 0;
}

int npf_peer_forward_drained(npf_peer *p, int i)
{
    pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return 0;
    f = p->fwds[i];
    if (f->draining && !f->suspended && (!p->call || npf_call_group_count(p->call, (uint32_t)f->id) == 0)) {
        peers_fwd_stop(f);                  /* its connections have ended: the port closes */
        f->suspended = 1;
        npf_log("%s: %s: closed (quota)", p->name, f->spec);
    }
    return f->suspended;
}

int npf_peer_forward_set_public(npf_peer *p, int i, const char *const *allow, int nallow, uint32_t rate)
{
    npf_policy tmp;
    pfwd *f;
    int k;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used || p->fwds[i]->udp || nallow < 0
        || nallow > (int)(sizeof tmp.rules / sizeof tmp.rules[0]))
        return -1;                          /* public mappings are TCP (data-channel.md 15) */
    f = p->fwds[i];
    memset(&tmp, 0, sizeof tmp);
    for (k = 0; k < nallow; k++)            /* addresses only ("lan" and "*" are not sources) */
        if (npf_policy_add(&tmp, allow[k]) < 0 || tmp.nrules != k + 1)
            return -1;
    free(f->acl);
    f->acl = NULL;
    f->nacl = 0;
    if (nallow) {
        if (!(f->acl = malloc((size_t)nallow * sizeof *f->acl)))
            return -1;
        memcpy(f->acl, tmp.rules, (size_t)nallow * sizeof *f->acl);
        f->nacl = nallow;
    }
    f->rate = rate;
    f->pub = 1;
    if (p->ps->closing && (f->fd >= 0 || f->t_retry))
        peers_fwd_stop(f);                  /* the public ports stay closed (it listened, made before it was public) */
    return 0;
}

void npf_peer_forward_set_ext(npf_peer *p, int i, uint64_t ext)
{
    if (i >= 0 && i < p->nfwd)
        p->fwds[i]->ext = ext;
}

uint64_t npf_peer_forward_ext(const npf_peer *p, int i)
{
    return i >= 0 && i < p->nfwd && p->fwds[i]->used ? p->fwds[i]->ext : 0;
}

int npf_peer_forward_udp(const npf_peer *p, int i)
{
    return i >= 0 && i < p->nfwd && p->fwds[i]->used && p->fwds[i]->udp;
}

int npf_peer_forward_ends(const npf_peer *p, int i, int *port, const char **host, int *hostport)
{
    const pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return -1;
    f = p->fwds[i];
    *port = f->port;
    *host = f->socks ? "" : f->host;
    *hostport = f->socks ? 0 : f->hostport;
    return 0;
}

int npf_peer_forward_used(const npf_peer *p)
{
    int i, n = 0;
    for (i = 0; i < p->nfwd; i++)
        n += p->fwds[i]->used;
    return n;
}

void npf_peer_forward_perm_set(npf_peer *p, int i, int perm)
{
    if (i >= 0 && i < p->nfwd && p->fwds[i]->used)
        p->fwds[i]->perm = perm;
}

void npf_peer_forward_mark(npf_peer *p, int perm)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        p->fwds[i]->perm = perm;
}

const char *npf_peer_forward_info(const npf_peer *p, int i, char *opt, const char **spec, int *perm, char *state,
                                  size_t cap)
{
    const pfwd *f;
    if (i < 0 || i >= p->nfwd || !p->fwds[i]->used)
        return NULL;
    f = p->fwds[i];
    *opt = f->opt;
    *spec = f->spec;
    *perm = f->perm;
    if (f->up && f->reverse)
        snprintf(state, cap, "up (callee port %d)", f->rport);
    else if (f->up && f->kind)
        snprintf(state, cap, "up (%s)", f->kind->k->name ? f->kind->k->name(f->kind->arg) : "");
    else if (f->up)
        snprintf(state, cap, "up");
    else if (f->t_retry)
        snprintf(state, cap, "retry in %lld s (%s)", (long long)((f->retry_at - npf_mono_ms() + 999) / 1000), f->why);
    else if (f->refused)
        snprintf(state, cap, "%s", f->why);
    else if (f->reverse)
        snprintf(state, cap, f->asked ? "asked" : "waiting for the session");
    else
        snprintf(state, cap, "waiting");
    return state;
}

void npf_peers_net_changed(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        int i;
        p->backoff = 0;
        for (i = 0; i < p->nfwd; i++) {
            pfwd *f = p->fwds[i];
            if (f && f->used && f->t_retry) {
                npf_timer_cancel(ps->n->loop, f->t_retry);
                f->backoff = 0;
                fwd_retry_cb(ps->n->loop, f);
            }
        }
    }
    npf_peers_retry_now(ps);
}

/* libnpf: the tunnel's SOCKS5 server side and the connection to the target
 * (data-channel.md 7): Happy Eyeballs, the deadlines, the greeting */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/log.h"
#include "npf/platform.h"
#include "tunnel_internal.h"

#define CONNECT_MS     10000
#define HE_DELAY_MS    250      /* Happy Eyeballs (RFC 8305): the next address after this long without an answer */
#define GREET_MS       10000    /* a peer-opened sublink's SOCKS greeting and request, at most this long */
#define RESOLVING_MAX  4        /* lookups of one tunnel at once: with a session's UDP flows' (2), one caller's
                                 * SESSIONS_PER_KEY sessions take at most 24 of the peers' 32 (resolve.h) */

static void socks_reply(sublink *s, uint8_t rep)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};    /* BND = 0.0.0.0:0 */
    tunnel_sub_send(s, r, sizeof r);
}

/* after a refusal: FIN, and the sublink goes */
static void socks_close(sublink *s)
{
    tunnel_send_fin(s->t, s->id);
    tunnel_sub_free(s, 0);
}

static void socks_fail(sublink *s, uint8_t rep)
{
    socks_reply(s, rep);
    socks_close(s);
}

static void connect_timeout(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    (void)loop;
    s->hs->t_connect = NULL;
    t->depth++;                         /* sublink_done may free the tunnel (tunnel_leave) */
    socks_fail(s, 6);
    tunnel_leave(t);
}

static int map_errno(int e)
{
    switch (e) {
    case NPF_SE(CONNREFUSED): return 5;
    case NPF_SE(NETUNREACH): return 3;
    case NPF_SE(HOSTUNREACH): return 4;
    case NPF_SE(TIMEDOUT): return 6;
    default: return 1;
    }
}

int npf_tunnel_greet_ms = GREET_MS;
int (*npf_tunnel_test_resolve)(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens,
                               int max);

/* RFC 8305 4: the families taken in turns, the first address's first, each
 * family's own order kept */
void npf_he_order(struct sockaddr_storage *a, socklen_t *l, int n)
{
    struct sockaddr_storage ta[NPF_RESOLVE_MAX];
    socklen_t tl[NPF_RESOLVE_MAX];
    int used[NPF_RESOLVE_MAX] = {0}, k = 0, fam;
    if (n < 3 || n > NPF_RESOLVE_MAX)
        return;                         /* two: already in turns, or one family */
    fam = a[0].ss_family;
    while (k < n) {
        int i, found = 0;
        for (i = 0; i < n; i++)         /* the next unused of fam, else of any */
            if (!used[i] && a[i].ss_family == fam) {
                found = 1;
                break;
            }
        if (!found)
            for (i = 0; i < n && used[i]; i++)
                ;
        used[i] = 1;
        ta[k] = a[i];
        tl[k++] = l[i];
        fam = fam == AF_INET6 ? AF_INET : AF_INET6;
    }
    memcpy(a, ta, (size_t)n * sizeof *a);
    memcpy(l, tl, (size_t)n * sizeof *l);
}

static void conn_cb(npf_loop *loop, int fd, unsigned ev, void *arg);
static int connect_next(sublink *s);

static void he_timer(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    (void)loop;
    s->hs->t_he = NULL;
    t->depth++;
    connect_next(s);                    /* no answer yet: the next address too */
    tunnel_leave(t);
}

/* start the next address's attempt (Happy Eyeballs: the others keep going);
 * the one after it follows in HE_DELAY_MS, or at once when this one fails.
 * Returns -1 when the sublink was released (nothing left to try). */
static int connect_next(sublink *s)
{
    sl_hs *h = s->hs;
    while (h->icand < h->ncand) {
        int i = h->icand++, fd, one = 1;
        fd = npf_socket(h->cand[i].ss_family, SOCK_STREAM, 0, 0);
        if (fd < 0) {
            h->last_err = npf_sock_err();
            continue;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, (const struct sockaddr *)&h->cand[i], h->clen[i]) < 0 && !npf_sock_inprogress()) {
            h->last_err = npf_sock_err();
            npf_sock_close(fd);
            continue;
        }
        h->cfd[h->ncfd++] = fd;
        npf_loop_add(s->t->loop, fd, NPF_EV_WRITE, conn_cb, s);
        if (h->icand < h->ncand && !h->t_he)
            h->t_he = npf_timer_add(s->t->loop, HE_DELAY_MS, he_timer, s);
        return 0;
    }
    if (h->ncfd)
        return 0;                       /* the ones under way may still answer */
    socks_fail(s, (uint8_t)map_errno(h->last_err));
    return -1;
}

/* an attempt answered: connected (the others closed, the sublink open) or
 * failed (the next address at once, or the end when none is left) */
static void conn_cb(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    sl_hs *h = s->hs;
    int err = 0, k;
    socklen_t el = sizeof err;
    (void)ev;
    t->depth++;                         /* sublink_done may free the tunnel (tunnel_leave) */
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &el);
    for (k = 0; k < h->ncfd && h->cfd[k] != fd; k++)
        ;
    if (k == h->ncfd)
        goto out;
    npf_loop_del(loop, fd);
    h->cfd[k] = h->cfd[--h->ncfd];      /* no longer an attempt: closed here, or the winner */
    if (err) {
        npf_sock_close(fd);
        h->last_err = err;
        /* its turn is now */
        npf_timer_stop(loop, &h->t_he);
        connect_next(s);
        goto out;
    }
    s->fd = fd;
    s->ev = 0;
    tunnel_hs_done(s);                  /* connected: the slower attempts and the deadline go */
    socks_reply(s, 0);
    s->state = SL_OPEN;
    if (tunnel_flush_local(s, NULL, 0) == 0)
        tunnel_update_ev(s);
out:
    tunnel_leave(t);
}

/* check the policy for every address, then connect to them (Happy Eyeballs).
 * Returns -1 when the sublink was released. */
static int socks_connect_addrs(sublink *s, const struct sockaddr_storage *cand, const socklen_t *clen, int nc)
{
    int i;
    /* every resolved address must pass: a name must not smuggle in a denied
     * target. Not a reverse sublink's: the caller's own -R named it */
    for (i = 0; i < nc && !s->t->caller; i++) {
        if (!npf_policy_allowed(s->t->policy, (const struct sockaddr *)&cand[i])) {
            socks_fail(s, 2);
            return -1;
        }
    }
    /* this host's control interface (the web console): never, whoever asks
     * (a resource that covers it, a -R naming it) */
    for (i = 0; i < nc; i++) {
        if (npf_guard_blocked((const struct sockaddr *)&cand[i])) {
            char a[64];
            npf_logw("tunnel: %s is this computer's control interface (the web console): not forwarded",
                     npf_addr_str(&cand[i], a, sizeof a));
            socks_fail(s, 2);
            return -1;
        }
    }
    if (nc == 0) {
        socks_fail(s, 4);
        return -1;
    }
    if (nc > NPF_RESOLVE_MAX)
        nc = NPF_RESOLVE_MAX;
    if (!(s->hs->cand = malloc((size_t)nc * sizeof *cand))) {
        socks_fail(s, 1);
        return -1;
    }
    memcpy(s->hs->cand, cand, (size_t)nc * sizeof *cand);
    memcpy(s->hs->clen, clen, (size_t)nc * sizeof *clen);
    npf_he_order(s->hs->cand, s->hs->clen, nc);
    s->hs->ncand = nc;
    s->state = SL_CONNECTING;
    if (!s->hs->t_connect)              /* a name: the deadline runs since the lookup began */
        s->hs->t_connect = npf_timer_add(s->t->loop, CONNECT_MS, connect_timeout, s);
    return connect_next(s);
}

/* the worker thread's answer for a domain-name target */
static void resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens, int n,
                     void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    (void)r;
    t->depth++;
    s->resolve = NULL;
    if (err != 0)
        socks_fail(s, 4);           /* host unreachable: the name did not resolve */
    else
        socks_connect_addrs(s, addrs, lens, n);
    tunnel_leave(t);
}

/* a CONNECT's address (ATYP 1 IPv4, 4 IPv6, 3 a name of alen bytes) as text */
static void atyp_host(int atyp, const uint8_t *addr, size_t alen, char host[256])
{
    if (atyp == 1)
        inet_ntop(AF_INET, addr, host, 256);
    else if (atyp == 4)
        inet_ntop(AF_INET6, addr, host, 256);
    else {
        memcpy(host, addr, alen);
        host[alen] = 0;
    }
}

/* literal addresses connect at once; names are resolved off the loop thread.
 * Returns -1 when the sublink was released. */
static int socks_connect(sublink *s, int atyp, const uint8_t *addr, size_t alen, uint16_t port)
{
    struct sockaddr_storage cand;
    socklen_t clen;
    char host[256];
    atyp_host(atyp, addr, alen, host);
    if ((s->t->io.target_ok || s->t->caller)
        && (!s->t->io.target_ok || !s->t->io.target_ok(s->t->arg, host, port))) {
        socks_fail(s, 2);
        return -1;
    }
    memset(&cand, 0, sizeof cand);
    if (atyp == 1) {
        struct sockaddr_in *a = (struct sockaddr_in *)&cand;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, addr, 4);
        a->sin_port = htons(port);
        clen = sizeof *a;
    } else if (atyp == 4) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&cand;
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, addr, 16);
        a->sin6_port = htons(port);
        clen = sizeof *a;
    } else {
        if (npf_tunnel_test_resolve) {     /* tests: the addresses of their choosing, at once */
            struct sockaddr_storage ta[NPF_RESOLVE_MAX];
            socklen_t tl[NPF_RESOLVE_MAX];
            int tn = npf_tunnel_test_resolve(host, port, ta, tl, NPF_RESOLVE_MAX);
            if (tn >= 0)
                return socks_connect_addrs(s, ta, tl, tn);
        }
        {
            int i, busy = 0;
            for (i = 0; i < s->t->nsubs; i++)
                busy += s->t->subs[i]->state == SL_RESOLVING;
            if (busy >= RESOLVING_MAX) {
                socks_fail(s, 1);
                return -1;
            }
        }
        s->state = SL_RESOLVING;
        s->resolve = npf_resolve_start_peer(s->t->loop, host, port, SOCK_STREAM, resolved, s);
        if (!s->resolve) {
            socks_fail(s, 1);       /* the resolver's budget is used up (or no memory) */
            return -1;
        }
        /* one deadline for the lookup and the connection: a lookup that
         * never returns fails the sublink after CONNECT_MS (the worker is
         * released by the system, the request's callback is cancelled) */
        s->hs->t_connect = npf_timer_add(s->t->loop, CONNECT_MS, connect_timeout, s);
        return 0;
    }
    return socks_connect_addrs(s, &cand, &clen, 1);
}

/* the greeting and request did not come in time: a peer's sublink is reset
 * (it holds one of the session's sublinks), a local application's (-D) closed
 * (nothing went to the peer yet) */
static void greet_timeout(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    (void)loop;
    s->t_greet = NULL;
    t->depth++;                         /* sublink_done may free the tunnel (tunnel_leave) */
    if (s->state == SL_LOCAL_GREETING) {
        s->end = "greeting_timeout";
        tunnel_sub_free(s, 1);
    } else if (s->state == SL_SOCKS_GREETING || s->state == SL_SOCKS_REQUEST) {
        tunnel_sub_reset(s, NPF_RST_PROTOCOL);
    }
    tunnel_leave(t);
}

void tunnel_greet_wait(sublink *s)
{
    s->t_greet = npf_timer_add(s->t->loop, npf_tunnel_greet_ms, greet_timeout, s);
}

int tunnel_socks_greeting(const uint8_t *b, size_t n, int *noauth)
{
    if (n < 2)
        return 0;
    if (b[0] != 5)
        return -1;
    if (n < 2 + (size_t)b[1])
        return 0;
    *noauth = memchr(b + 2, 0, b[1]) != NULL;
    return 2 + b[1];
}

/* parse what the client sent so far; returns -1 if the sublink was freed */
int tunnel_socks_parse(sublink *s)
{
    uint8_t *b = s->hs->sb;
    if (s->state == SL_SOCKS_GREETING) {
        int noauth, n = tunnel_socks_greeting(b, s->sl, &noauth);
        static const uint8_t ok[2] = {5, 0}, none[2] = {5, 0xff};
        if (n <= 0) {
            if (n < 0)
                tunnel_sub_reset(s, NPF_RST_PROTOCOL);
            return n;
        }
        if (!noauth) {
            tunnel_sub_send(s, none, sizeof none);
            socks_close(s);
            return -1;
        }
        tunnel_sub_send(s, ok, sizeof ok);
        tunnel_credit_back(s, (size_t)n);
        memmove(b, b + n, s->sl - (size_t)n);
        s->sl -= (size_t)n;
        s->state = SL_SOCKS_REQUEST;
    }
    if (s->state == SL_SOCKS_REQUEST) {
        size_t need, alen;
        int atyp;
        uint16_t port;
        const uint8_t *addr = b + 4;
        if (s->sl < 5)
            return 0;
        if (b[0] != 5 || b[2] != 0) {
            tunnel_sub_reset(s, NPF_RST_PROTOCOL);
            return -1;
        }
        atyp = b[3];
        if (atyp == 1) alen = 4;
        else if (atyp == 4) alen = 16;
        else if (atyp == 3) alen = b[4], addr++;
        else {
            socks_fail(s, 8);
            return -1;
        }
        need = (size_t)(addr - b) + alen + 2;
        if (s->sl < need)
            return 0;
        if (b[1] != 1) {                /* only CONNECT (C5) */
            socks_fail(s, 7);
            return -1;
        }
        if (atyp == 3 && alen == 0) {
            socks_fail(s, 4);
            return -1;
        }
        port = npf_rdbe16(b + need - 2);
        /* pipelined data after the request waits in wq until connected */
        if (s->sl > need && tunnel_queue(s, b + need, s->sl - need) < 0)
            return -1;
        s->sl = 0;
        tunnel_credit_back(s, need);
        npf_timer_stop(s->t->loop, &s->t_greet);
        /* addr stays in hs->sb (nothing writes there now) while socks_connect reads it */
        return socks_connect(s, atyp, addr, alen, port);
    }
    return 0;
}

int tunnel_socks_request(const char *host, uint16_t port, uint8_t req[300], size_t *len)
{
    size_t hl = strlen(host), n = 0;
    struct in_addr a4;
    struct in6_addr a6;
    req[n++] = 5; req[n++] = 1; req[n++] = 0;          /* greeting: no authentication */
    req[n++] = 5; req[n++] = 1; req[n++] = 0;          /* CONNECT, pipelined */
    if (inet_pton(AF_INET, host, &a4) == 1) {
        req[n++] = 1;
        memcpy(req + n, &a4, 4);
        n += 4;
    } else if (inet_pton(AF_INET6, host, &a6) == 1) {
        req[n++] = 4;
        memcpy(req + n, &a6, 16);
        n += 16;
    } else {
        if (hl == 0 || hl > 255)
            return -1;
        req[n++] = 3;
        req[n++] = (uint8_t)hl;
        memcpy(req + n, host, hl);
        n += hl;
    }
    npf_be16(req + n, port);
    *len = n + 2;
    return 0;
}

void tunnel_hs_done(sublink *s)
{
    sl_hs *h = s->hs;
    int i;
    if (!h)
        return;
    for (i = 0; i < h->ncfd; i++) {
        npf_loop_del(s->t->loop, h->cfd[i]);
        npf_sock_close(h->cfd[i]);
    }
    npf_timer_cancel(s->t->loop, h->t_connect);
    npf_timer_cancel(s->t->loop, h->t_he);
    free(h->cand);
    free(h);
    s->hs = NULL;
}

/* client side: the server's method reply (05 00) and its CONNECT reply
 * (05 REP 00 ATYP BND.ADDR BND.PORT), however the frames split them. Only
 * what judging them takes is kept (their first 7 bytes in rep), nothing to
 * deliver later: of p[0..n), the first *drop bytes are the replies' own
 * (the method reply; the CONNECT reply too, unless fwd_rep: -D gives it to
 * the application as it is, a failure too), the rest goes to the local
 * end. 0: fine, s->state SL_OPEN once both replies are complete; -1: the
 * target failed (s->end says how); -2: not a SOCKS5 reply */
int tunnel_client_reply(sublink *s, const uint8_t *p, size_t n, size_t *drop)
{
    size_t k = 0;
    *drop = 0;
    while (k < n && s->state == SL_CLIENT_WAIT) {
        size_t at = s->sl++;            /* this byte's place in the replies */
        uint8_t b = p[k++];
        if (at < 7)
            s->rep[at] = b;
        if (at < 2 || !s->fwd_rep)
            *drop = k;
        switch (at) {
        case 0:                         /* VER, the method reply's and the CONNECT reply's */
        case 2:
            if (b != 5)
                return -2;
            break;
        case 1:                         /* METHOD: no authentication, the only one offered */
        case 4:                         /* RSV */
            if (b != 0)
                return -2;
            break;
        case 3:                         /* REP */
            if (b != 0) {
                s->end = b == 2 ? "target_refused" : "target_failed";  /* 2: the other side's policy */
                if (!s->fwd_rep)
                    return -1;          /* -D: the reply goes on to the application */
            }
            break;
        case 5:                         /* ATYP */
            if (b != 1 && b != 3 && b != 4)
                return -2;
            break;
        default:
            break;
        }
        if (s->sl >= 7) {
            size_t len = 2 + 4 + (s->rep[5] == 1 ? 4 : s->rep[5] == 4 ? 16 : 1 + (size_t)s->rep[6]) + 2;
            if (s->sl == len) {
                s->state = SL_OPEN;
                s->t_ok = npf_mono_ms();
                s->sl = 0;
            }
        }
    }
    return 0;
}

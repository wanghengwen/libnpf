/* UDP forwarding of a session (udpfwd.h; data-channel.md 15). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "udpfwd.h"
#include "npf/crypto.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/resolve.h"

#define HDR           5             /* flow(4) | flags(1) */
#define F_TARGET      1             /* caller: the -L target follows */
#define F_LID         2             /* callee: the -R listener's id follows */
#define BUF_MAX       (NPF_UDP_PAYLOAD_MAX + HDR + 1 + 255 + 2 + 4)
#define UDP_WND       512           /* AnLiu receive window of the stream (segments; media.h's for media) */
#define WS_BACKLOG    (256 * 1024)  /* WS relay: datagrams dropped above this */
#define TICK_MS       5000
#define PEND_MAX      4             /* datagrams kept while the target's name is resolved */
#define CLOSED_RING   32            /* the peer's flows closed lately (a late frame does not open them again) */
#define READ_BURST    64            /* datagrams read from a socket at once */
#define WARN_EVERY_MS 10000
#define VFD           (-2)          /* the "socket" of the virtual flows: they count as one forward's */

typedef struct pend {
    size_t   len;
    uint8_t *d;
} pend;

/* a flow is "out" on the side whose socket the local application sent to
 * (the caller's -L, the callee's -R listener: that socket is not the flow's,
 * replies go to src through it) and "in" on the other side (a socket of the
 * flow's own, connected to the target) */
typedef struct uflow {
    struct uflow *nid, *nsrc;       /* hash chains: by id, by source (out) */
    npf_udpf *u;
    uint32_t id;
    int      out;
    int      fd;                    /* out: the listening socket (VFD: a virtual flow); in: ours, -1 while resolving */
    void    *vkey;                  /* out, virtual (npf_udpf_send_v): the local end's flow, replies to deliver */
    npf_udpf_deliver deliver;
    struct sockaddr_storage src;    /* out: where the local application sends from */
    socklen_t srclen;
    char     host[256];             /* out on the caller: the target, sent until OK; in: the target */
    uint16_t port;
    uint32_t lid;                   /* out on the callee: its -R listener, sent until OK; in on the caller: the same */
    int      ok;                    /* out: the other side has opened it */
    int64_t  last;                  /* the last datagram either way (ms) */
    npf_resolve *res;               /* in: the target's name being resolved */
    int      counted;               /* in: its socket counted in the shares (npf_udpf_set_shared) */
    pend     q[PEND_MAX];
    int      nq;
} uflow;

typedef struct urev {               /* caller: a -R .../udp mapping's target */
    uint32_t lid;
    char     host[256];
    uint16_t port;
} urev;

struct npf_udpf {
    npf_loop    *loop;
    anl_t       *anl;
    int          caller;
    npf_policy  *policy;
    npf_udpf_io  io;
    void        *arg;
    anl_stream_t *s;
    uflow       *by_id[256], *by_src[256];
    int          nflows;
    int          nresolving;        /* flows whose names are being resolved (UDP_RESOLVING_MAX) */
    uint32_t     next_id;
    uint32_t     closed[CLOSED_RING];
    int          nclosed;
    urev         rev[NPF_MAX_REVERSE];
    int          nrev;
    npf_timer   *t_tick;
    uint8_t     *out, *in;          /* frame being built / a datagram read */
    npf_udpf_stats st;
    int64_t      warned_at;
    npf_tunnel_shared *shared[2];   /* the node's and the caller key's descriptors, with the sublinks */
};

/* ---- the flow table ---- */

static unsigned src_hash(int fd, const struct sockaddr_storage *a)
{
    const uint8_t *p = (const uint8_t *)a;
    size_t n = a->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in), i;
    unsigned h = (unsigned)fd * 2654435761u;
    for (i = 0; i < n; i++)
        h = (h ^ p[i]) * 16777619u;
    return h & 255;
}

static int same_src(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a, *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a, *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    return 0;
}

static uflow *find_id(const npf_udpf *u, uint32_t id)
{
    uflow *f;
    for (f = u->by_id[id & 255]; f; f = f->nid)
        if (f->id == id)
            return f;
    return NULL;
}

static uflow *find_src(const npf_udpf *u, int fd, const struct sockaddr_storage *src)
{
    uflow *f;
    for (f = u->by_src[src_hash(fd, src)]; f; f = f->nsrc)
        if (f->fd == fd && !f->vkey && same_src(&f->src, src))
            return f;
    return NULL;
}

static unsigned key_hash(const void *key)
{
    uintptr_t k = (uintptr_t)key;
    return (unsigned)((k >> 4) ^ (k >> 12)) & 255;
}

/* an out flow's chain in by_src */
static unsigned src_slot(const uflow *f)
{
    return f->vkey ? key_hash(f->vkey) : src_hash(f->fd, &f->src);
}

static uflow *find_key(const npf_udpf *u, const void *key)
{
    uflow *f;
    for (f = u->by_src[key_hash(key)]; f; f = f->nsrc)
        if (f->vkey == key)
            return f;
    return NULL;
}

static void link_flow(npf_udpf *u, uflow *f)
{
    f->nid = u->by_id[f->id & 255];
    u->by_id[f->id & 255] = f;
    if (f->out) {
        unsigned h = src_slot(f);
        f->nsrc = u->by_src[h];
        u->by_src[h] = f;
    }
    u->nflows++;
}

static void unlink_flow(npf_udpf *u, uflow *f)
{
    uflow **pp;
    for (pp = &u->by_id[f->id & 255]; *pp; pp = &(*pp)->nid)
        if (*pp == f) {
            *pp = f->nid;
            break;
        }
    if (f->out)
        for (pp = &u->by_src[src_slot(f)]; *pp; pp = &(*pp)->nsrc)
            if (*pp == f) {
                *pp = f->nsrc;
                break;
            }
    u->nflows--;
}

static int unit(npf_udpf *u, int op, uint32_t id, int reason)
{
    uint8_t b[6];
    b[0] = (uint8_t)op;
    npf_le32(b + 1, id);
    b[5] = (uint8_t)reason;
    return u->io.unit(u->arg, b, op == NPF_UDP_CLOSE ? 6 : 5);
}

static void free_flow(npf_udpf *u, uflow *f)
{
    int i;
    if (!f->out && f->fd >= 0) {
        npf_loop_del(u->loop, f->fd);
        npf_sock_close(f->fd);
    }
    if (f->counted)
        for (i = 0; i < 2; i++)
            if (u->shared[i])
                u->shared[i]->subs--;
    if (f->res) {
        npf_resolve_cancel(f->res);
        f->u->nresolving--;
    }
    for (i = 0; i < f->nq; i++)
        free(f->q[i].d);
    free(f);
}

/* the flow goes; send: tell the peer (CLOSE with reason) */
static void drop_flow(npf_udpf *u, uflow *f, int send, int reason)
{
    unlink_flow(u, f);
    if (!f->out)
        u->closed[u->nclosed++ % CLOSED_RING] = f->id;
    if (send)
        unit(u, NPF_UDP_CLOSE, f->id, reason);
    free_flow(u, f);
}

static void tick(npf_loop *loop, void *arg);

static void tick_arm(npf_udpf *u)
{
    if (!u->t_tick && u->nflows)
        u->t_tick = npf_timer_add(u->loop, getenv("NPF_TEST_UDP_IDLE_MS") ? 500 : TICK_MS, tick, u);
}

/* flows without a datagram for NPF_UDP_IDLE_MS (tests: NPF_TEST_UDP_IDLE_MS) end on this side */
static void tick(npf_loop *loop, void *arg)
{
    npf_udpf *u = arg;
    int64_t now = npf_mono_ms();
    const char *t = getenv("NPF_TEST_UDP_IDLE_MS");
    int i, idle = t ? atoi(t) : NPF_UDP_IDLE_MS;
    (void)loop;
    u->t_tick = NULL;
    for (i = 0; i < 256; i++) {
        uflow *f = u->by_id[i], *next;
        for (; f; f = next) {
            next = f->nid;
            if (now - f->last >= idle)
                drop_flow(u, f, 1, NPF_UDP_R_CLOSED);
        }
    }
    tick_arm(u);
}

/* ---- life ---- */

npf_udpf *npf_udpf_new(npf_loop *loop, anl_t *anl, int caller, npf_policy *policy, const npf_udpf_io *io, void *arg)
{
    npf_udpf *u = calloc(1, sizeof *u);
    if (!u)
        return NULL;
    u->loop = loop;
    u->anl = anl;
    u->caller = caller;
    u->policy = policy;
    u->io = *io;
    u->arg = arg;
    return u;
}

void npf_udpf_set_shared(npf_udpf *u, npf_tunnel_shared *node, npf_tunnel_shared *key)
{
    u->shared[0] = node;
    u->shared[1] = key;
}

void npf_udpf_free(npf_udpf *u)
{
    int i;
    if (!u)
        return;
    if (u->t_tick)
        npf_timer_cancel(u->loop, u->t_tick);
    for (i = 0; i < 256; i++)
        while (u->by_id[i]) {
            uflow *f = u->by_id[i];
            unlink_flow(u, f);
            free_flow(u, f);
        }
    /* the AnLiu stream goes with the connection */
    free(u->out);
    free(u->in);
    free(u);
}

void npf_udpf_get_stats(const npf_udpf *u, npf_udpf_stats *out)
{
    memset(out, 0, sizeof *out);
    if (!u)
        return;
    *out = u->st;
    out->flows = u->nflows;
}

/* ---- frames out ---- */

/* how long AnLiu may retry a frame: room for one resend at least (2 RTT +
 * 100 ms, 200..1000 ms). Measured 2026-10-16 on the UDP relay across the
 * Pacific (RTT 360 ms): with 200 ms nothing was resent and 7-16 % of the
 * datagrams were lost; with this, 498 of 500 came back. No FEC: adaptive
 * FEC on that path (a free plan's 128 kbps relay) made the delays grow to
 * 2 s and most datagrams expire. Tests: NPF_TEST_UDP_MAX_AGE_MS */
static void stream_opts(npf_udpf *u, anl_stream_opt *opt)
{
    anl_stats st;
    const char *t = getenv("NPF_TEST_UDP_MAX_AGE_MS");
    int age = NPF_UDP_MAX_AGE_MS;
    if (u->anl && anl_get_stats(u->anl, &st) == 0 && st.srtt > 0)
        age = (int)st.srtt * 2 + 100;
    if (age > NPF_UDP_MAX_AGE_HI)
        age = NPF_UDP_MAX_AGE_HI;
    if (age < NPF_UDP_MAX_AGE_MS)
        age = NPF_UDP_MAX_AGE_MS;
    opt->prio = 1;                          /* ahead of the forwards' data (2), behind control (0) */
    opt->max_age_ms = t ? atoi(t) : age;
    opt->fec = 0;
}

/* the caller opens the stream (at its first datagram, or before it asks for
 * a -R .../udp: the callee sends on it then); the callee takes it (accept) */
static anl_stream_t *stream(npf_udpf *u)
{
    anl_stream_opt opt;
    int e = 0;
    if (u->s || !u->caller || !u->anl)
        return u->s;
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.tag = NPF_TAG_UDP;
    opt.rcv_wnd = UDP_WND;
    stream_opts(u, &opt);
    if (!(u->s = anl_stream_open(u->anl, &opt, &e))) {
        npf_logw("udp: no AnLiu stream for the UDP forwards (%d)", e);
    } else {
        npf_log("udp: stream open (frames kept %d ms)", opt.max_age_ms);
        u->io.kick(u->arg);
    }
    return u->s;
}

void npf_udpf_prepare(npf_udpf *u)
{
    if (u)
        stream(u);
}

/* one datagram of flow f to the peer; an out flow not opened yet carries
 * what opens it there: the caller's target, the callee's listener */
static int frame_out(npf_udpf *u, uflow *f, const uint8_t *p, size_t len)
{
    size_t n = HDR;
    int open = f->out && !f->ok;
    if (len > NPF_UDP_PAYLOAD_MAX || (!u->out && !(u->out = malloc(BUF_MAX)))) {
        u->st.dropped++;
        return -1;
    }
    npf_le32(u->out, f->id);
    u->out[4] = (uint8_t)(open ? (u->caller ? F_TARGET : F_LID) : 0);
    if (open && u->caller) {
        size_t tl = strlen(f->host);
        u->out[5] = (uint8_t)tl;
        memcpy(u->out + 6, f->host, tl);
        npf_le16(u->out + 6 + tl, f->port);
        n += 1 + tl + 2;
    } else if (open) {
        npf_le32(u->out + n, f->lid);
        n += 4;
    }
    memcpy(u->out + n, p, len);
    n += len;
    if (u->anl) {
        anl_stream_t *s = stream(u);
        int r = s ? anl_stream_send_frame(s, 0, (const char *)u->out, (int)n, NULL) : -1;
        u->io.kick(u->arg);
        if (r < 0) {
            u->st.dropped++;
            return -1;
        }
    } else if (u->io.ws_backlog(u->arg) > WS_BACKLOG || u->io.ws_write(u->arg, u->out, n) < 0) {
        u->st.dropped++;                    /* UDP: dropped rather than queued behind the backlog */
        return -1;
    }
    u->st.dgrams_out++;
    u->st.bytes_out += len;
    if (n > NPF_UDP_ONE_SEG)
        u->st.split++;
    return 0;
}

/* ---- in flows: a socket to the target ---- */

static void flow_readable(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    uflow *f = arg;
    npf_udpf *u = f->u;
    int k;
    (void)loop;
    (void)ev;
    if (!u->in && !(u->in = malloc(NPF_UDP_PAYLOAD_MAX + 1)))
        return;
    for (k = 0; k < READ_BURST; k++) {
        ssize_t r = recv(fd, u->in, NPF_UDP_PAYLOAD_MAX + 1, MSG_DONTWAIT);
        if (r < 0) {
            if (npf_sock_again())
                break;
            continue;                       /* an ICMP error of an earlier datagram (port unreachable) */
        }
        if (r > NPF_UDP_PAYLOAD_MAX) {
            u->st.dropped++;
            continue;
        }
        f->last = npf_mono_ms();
        frame_out(u, f, u->in, (size_t)r);
    }
}

static void flow_send(npf_udpf *u, uflow *f, const uint8_t *p, size_t len)
{
    if (send(f->fd, p, len, MSG_DONTWAIT) < 0)
        u->st.dropped++;
}

/* the target's address (check: the callee's, within its "udp" resources; the
 * caller's -R targets are its own), a socket connected to it */
static void flow_connect(npf_udpf *u, uflow *f, const struct sockaddr_storage *to, socklen_t tl)
{
    char a[64];
    int fd, i;
    if (!u->caller && !npf_policy_udp_allowed(u->policy, (const struct sockaddr *)to)) {
        int64_t now = npf_mono_ms();
        if (now - u->warned_at > WARN_EVERY_MS) {
            u->warned_at = now;
            npf_logw("udp: %s is not a published udp resource: refused", npf_addr_str(to, a, sizeof a));
        }
        u->st.refused++;
        drop_flow(u, f, 1, NPF_UDP_R_REFUSED);
        return;
    }
    for (i = 0; i < 2; i++)
        if (u->shared[i] && u->shared[i]->subs >= u->shared[i]->subs_max) {
            /* a socket of ours for each of the peer's flows: in the same
             * budget as the sublinks, one peer cannot take the descriptors */
            drop_flow(u, f, 1, NPF_UDP_R_LIMIT);
            return;
        }
    fd = npf_socket(to->ss_family, SOCK_DGRAM, 0, 0);
    if (fd < 0 || connect(fd, (const struct sockaddr *)to, tl) < 0
        || npf_loop_add(u->loop, fd, NPF_EV_READ, flow_readable, f) < 0) {
        npf_logw("udp: no socket to %s: %s", npf_addr_str(to, a, sizeof a), npf_sock_strerror());
        if (fd >= 0)
            npf_sock_close(fd);
        drop_flow(u, f, 1, NPF_UDP_R_FAILED);
        return;
    }
    f->fd = fd;
    f->counted = 1;
    for (i = 0; i < 2; i++)
        if (u->shared[i])
            u->shared[i]->subs++;
    unit(u, NPF_UDP_OK, f->id, 0);
    for (i = 0; i < f->nq; i++) {
        flow_send(u, f, f->q[i].d, f->q[i].len);
        free(f->q[i].d);
    }
    f->nq = 0;
}

static void resolved(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens, int n,
                     void *arg)
{
    uflow *f = arg;
    npf_udpf *u = f->u;
    int i;
    (void)r;
    f->res = NULL;
    u->nresolving--;
    if (err || n < 1) {
        npf_logw("udp: %s: the name does not resolve", f->host);
        drop_flow(u, f, 1, NPF_UDP_R_FAILED);
        return;
    }
    for (i = 0; i < n && !u->caller; i++)   /* the first address the resources allow */
        if (npf_policy_udp_allowed(u->policy, (const struct sockaddr *)&addrs[i])) {
            flow_connect(u, f, &addrs[i], lens[i]);
            return;
        }
    flow_connect(u, f, &addrs[0], lens[0]); /* the callee refuses it there, with the reason logged */
}

/* an IP address (or localhost) and the port as a socket address; 0, or -1 for a name */
static int literal(const char *host, uint16_t port, struct sockaddr_storage *ss, socklen_t *sl)
{
    struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
    memset(ss, 0, sizeof *ss);
    if (strcmp(host, "localhost") == 0)
        host = "127.0.0.1";
    if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        *sl = sizeof *s4;
        return 0;
    }
    if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        *sl = sizeof *s6;
        return 0;
    }
    return -1;
}

static int closed_lately(const npf_udpf *u, uint32_t id)
{
    int i, n = u->nclosed < CLOSED_RING ? u->nclosed : CLOSED_RING;
    for (i = 0; i < n; i++)
        if (u->closed[i] == id)
            return 1;
    return 0;
}

/* names of one session's flows being resolved at once: with the tunnel's
 * (RESOLVING_MAX) and SESSIONS_PER_KEY sessions, one caller stays below the
 * peers' resolver capacity (RESOLVE_PEER_CAPACITY) */
#define UDP_RESOLVING_MAX 2

/* a flow the peer opened, to host:port here (lid: the -R mapping it came through, caller) */
static uflow *flow_open(npf_udpf *u, uint32_t id, const char *host, uint16_t port, uint32_t lid)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    uflow *f;
    if (!u->caller && (!u->policy || (u->io.allowed && !u->io.allowed(u->arg)))) {
        u->st.refused++;
        unit(u, NPF_UDP_CLOSE, id, NPF_UDP_R_REFUSED);
        return NULL;
    }
    if (u->nflows >= NPF_UDP_FLOWS || (u->nresolving >= UDP_RESOLVING_MAX && literal(host, port, &ss, &sl) < 0)
        || !(f = calloc(1, sizeof *f))) {
        unit(u, NPF_UDP_CLOSE, id, NPF_UDP_R_LIMIT);
        return NULL;
    }
    f->u = u;
    f->id = id;
    f->fd = -1;
    f->lid = lid;
    f->last = npf_mono_ms();
    snprintf(f->host, sizeof f->host, "%s", host);
    f->port = port;
    link_flow(u, f);
    tick_arm(u);
    if (literal(host, port, &ss, &sl) == 0) {
        flow_connect(u, f, &ss, sl);
    } else if (!(f->res = npf_resolve_start_peer(u->loop, host, port, SOCK_DGRAM, resolved, f))) {
        drop_flow(u, f, 1, NPF_UDP_R_FAILED);
        return NULL;
    } else {
        u->nresolving++;
    }
    return find_id(u, id);                  /* refused or failed at once: gone */
}

static const urev *rev_find(const npf_udpf *u, uint32_t lid)
{
    int i;
    for (i = 0; i < u->nrev; i++)
        if (u->rev[i].lid == lid)
            return &u->rev[i];
    return NULL;
}

/* ---- frames in ---- */

static void frame_in(npf_udpf *u, const uint8_t *p, size_t n)
{
    char host[256];
    uint16_t port = 0;
    size_t off = HDR;
    uint32_t id, lid = 0;
    int flags;
    uflow *f;
    if (n < HDR)
        return;
    id = npf_rd32(p);
    flags = p[4];
    host[0] = 0;
    if (flags & F_TARGET) {
        size_t tl;
        if (n < off + 1 || (tl = p[off]) == 0 || n < off + 1 + tl + 2)
            return;
        memcpy(host, p + off + 1, tl);
        host[tl] = 0;
        if (strlen(host) != tl)
            return;                         /* a NUL inside the name */
        port = npf_rd16(p + off + 1 + tl);
        off += 1 + tl + 2;
    }
    if (flags & F_LID) {
        if (n < off + 4)
            return;
        lid = npf_rd32(p + off);
        off += 4;
    }
    p += off;
    n -= off;
    u->st.dgrams_in++;
    u->st.bytes_in += n;
    if (!(f = find_id(u, id))) {
        /* a new flow of the peer: the caller's are odd, the callee's even;
         * the callee opens the caller's to a target, the caller the callee's
         * through one of its -R mappings */
        int peers = (id & 1) == (u->caller ? 0u : 1u);
        const urev *r;
        if (!peers || closed_lately(u, id) || (u->caller ? !(flags & F_LID) : !(flags & F_TARGET) || !port)) {
            unit(u, NPF_UDP_CLOSE, id, NPF_UDP_R_CLOSED);      /* the other side starts it again */
            u->st.dropped++;
            return;
        }
        if (u->caller) {
            if (!(r = rev_find(u, lid))) {
                unit(u, NPF_UDP_CLOSE, id, NPF_UDP_R_REFUSED);
                u->st.refused++;
                return;
            }
            f = flow_open(u, id, r->host, r->port, lid);
        } else {
            f = flow_open(u, id, host, port, 0);
        }
        if (!f)
            return;
    }
    f->last = npf_mono_ms();
    if (f->out && f->vkey) {
        f->deliver(f->vkey, p, n);
    } else if (f->out) {
        if (sendto(f->fd, p, n, 0, (const struct sockaddr *)&f->src, f->srclen) < 0)
            u->st.dropped++;
    } else if (f->fd >= 0) {
        flow_send(u, f, p, n);
    } else if (f->nq < PEND_MAX && (f->q[f->nq].d = malloc(n ? n : 1))) {
        memcpy(f->q[f->nq].d, p, n);        /* the name is being resolved */
        f->q[f->nq++].len = n;
    } else {
        u->st.dropped++;
    }
}

int npf_udpf_accept(npf_udpf *u, anl_stream_t *s, anl_stream_opt *opt)
{
    if (u->caller || u->s || opt->mode != ANL_SEMI || opt->rcv_wnd > UDP_WND)
        return -1;
    stream_opts(u, opt);                    /* this side's sending: as the caller's */
    u->s = s;
    return 0;
}

int npf_udpf_is_stream(const npf_udpf *u, const anl_stream_t *s)
{
    return u && s && u->s == s;
}

void npf_udpf_drain(npf_udpf *u, anl_stream_t *s)
{
    for (;;) {
        anl_frame_info fi;
        int sz = anl_stream_peeksize(s), r;
        uint8_t *buf;
        if (sz == ANL_ECLOSED) {            /* the peer closed it: the flows stay, a new frame opens a new stream */
            anl_stream_close(s);
            if (u->s == s)
                u->s = NULL;
            return;
        }
        if (sz < 0)
            return;
        if (!(buf = npf_scratch((size_t)sz + 1)))  /* reused, not a malloc per datagram (nested use: its own) */
            return;
        r = anl_stream_recv_frame(s, (char *)buf, sz + 1, &fi);
        if (r >= 0)
            frame_in(u, buf, (size_t)r);
        npf_scratch_done(buf);
        if (r < 0)
            return;
    }
}

void npf_udpf_ws_input(npf_udpf *u, const uint8_t *buf, size_t len)
{
    frame_in(u, buf, len);
}

void npf_udpf_unit_input(npf_udpf *u, const uint8_t *b, size_t len)
{
    uflow *f;
    uint32_t id;
    if (len < 5)
        return;
    id = npf_rd32(b + 1);
    if (!(f = find_id(u, id)))
        return;
    if (b[0] == NPF_UDP_OK && f->out) {
        f->ok = 1;
    } else if (b[0] == NPF_UDP_CLOSE) {
        int reason = len >= 6 ? b[5] : NPF_UDP_R_CLOSED;
        if (f->out && reason != NPF_UDP_R_CLOSED) {
            int64_t now = npf_mono_ms();
            u->st.refused++;
            if (now - u->warned_at > WARN_EVERY_MS) {
                u->warned_at = now;
                if (u->caller)
                    npf_logw("udp: %s:%u: %s on the other side", f->host, f->port,
                             reason == NPF_UDP_R_REFUSED ? "not a published udp resource, refused"
                             : reason == NPF_UDP_R_LIMIT ? "too many UDP flows, refused" : "failed");
                else
                    npf_logw("udp: reverse mapping %u: %s on the caller's side", f->lid,
                             reason == NPF_UDP_R_REFUSED ? "not a mapping there, refused"
                             : reason == NPF_UDP_R_LIMIT ? "too many UDP flows, refused" : "the target failed");
            }
        }
        drop_flow(u, f, 0, 0);
    }
}

/* ---- out flows: what the local applications send ---- */

/* the least recently used out flow (of the socket fd, or of any with -1) */
static uflow *least_recent(const npf_udpf *u, int fd, int *count)
{
    uflow *best = NULL, *f;
    int i, n = 0;
    for (i = 0; i < 256; i++)
        for (f = u->by_id[i]; f; f = f->nid)
            if (f->out && (fd < 0 || f->fd == fd)) {
                n++;
                if (!best || f->last < best->last)
                    best = f;
            }
    *count = n;
    return best;
}

static int send_out(npf_udpf *u, int lfd, const struct sockaddr_storage *src, socklen_t srclen, void *vkey,
                    npf_udpf_deliver deliver, const char *host, uint16_t port, uint32_t lid, const uint8_t *buf,
                    size_t len)
{
    uflow *f = vkey ? find_key(u, vkey) : find_src(u, lfd, src);
    if (!f) {
        int n;
        uflow *old;
        if (u->nflows >= NPF_UDP_FLOWS_FWD && (old = least_recent(u, lfd, &n)) && n >= NPF_UDP_FLOWS_FWD)
            drop_flow(u, old, 1, NPF_UDP_R_CLOSED);     /* the forward's oldest gives way */
        if (u->nflows >= NPF_UDP_FLOWS && (old = least_recent(u, -1, &n)))
            drop_flow(u, old, 1, NPF_UDP_R_CLOSED);
        if (!(f = calloc(1, sizeof *f))) {
            u->st.dropped++;
            return -1;
        }
        if (!++u->next_id || u->next_id > 0x7fffffffu)
            u->next_id = 1;
        f->u = u;
        f->id = u->caller ? u->next_id * 2 - 1 : u->next_id * 2;     /* caller odd, callee even */
        f->out = 1;
        f->fd = lfd;
        f->vkey = vkey;
        f->deliver = deliver;
        if (src) {
            memcpy(&f->src, src, (size_t)srclen < sizeof f->src ? (size_t)srclen : sizeof f->src);
            f->srclen = srclen;
        }
        snprintf(f->host, sizeof f->host, "%s", host);
        f->port = port;
        f->lid = lid;
        link_flow(u, f);
        tick_arm(u);
    }
    f->last = npf_mono_ms();
    return frame_out(u, f, buf, len);
}

int npf_udpf_send(npf_udpf *u, int lfd, const struct sockaddr_storage *src, socklen_t srclen, const char *host,
                  uint16_t port, const uint8_t *buf, size_t len)
{
    if (!u->caller || strlen(host) > 255 || !port) {
        u->st.dropped++;
        return -1;
    }
    return send_out(u, lfd, src, srclen, NULL, NULL, host, port, 0, buf, len);
}

int npf_udpf_send_v(npf_udpf *u, void *key, npf_udpf_deliver deliver, const char *host, uint16_t port,
                    const uint8_t *buf, size_t len)
{
    if (!u->caller || !key || !deliver || strlen(host) > 255 || !port) {
        u->st.dropped++;
        return -1;
    }
    return send_out(u, VFD, NULL, 0, key, deliver, host, port, 0, buf, len);
}

void npf_udpf_forget_v(npf_udpf *u, const void *key)
{
    uflow *f;
    if (u && key && (f = find_key(u, key)))
        drop_flow(u, f, 1, NPF_UDP_R_CLOSED);
}

int npf_udpf_send_rev(npf_udpf *u, int lfd, const struct sockaddr_storage *src, socklen_t srclen, uint32_t lid,
                      const uint8_t *buf, size_t len)
{
    if (u->caller) {
        u->st.dropped++;
        return -1;
    }
    return send_out(u, lfd, src, srclen, NULL, NULL, "", 0, lid, buf, len);
}

void npf_udpf_forget_fd(npf_udpf *u, int lfd)
{
    int i;
    if (!u)
        return;
    for (i = 0; i < 256; i++) {
        uflow *f = u->by_id[i], *next;
        for (; f; f = next) {
            next = f->nid;
            if (f->out && f->fd == lfd)
                drop_flow(u, f, 1, NPF_UDP_R_CLOSED);
        }
    }
}

int npf_udpf_rev_add(npf_udpf *u, uint32_t lid, const char *host, uint16_t port)
{
    if (!u || !u->caller || u->nrev >= NPF_MAX_REVERSE || strlen(host) >= sizeof u->rev[0].host)
        return -1;
    u->rev[u->nrev].lid = lid;
    snprintf(u->rev[u->nrev].host, sizeof u->rev[u->nrev].host, "%s", host);
    u->rev[u->nrev].port = port;
    u->nrev++;
    return 0;
}

void npf_udpf_rev_del(npf_udpf *u, uint32_t lid)
{
    int i;
    if (!u)
        return;
    for (i = 0; i < u->nrev; i++)
        if (u->rev[i].lid == lid) {
            u->rev[i] = u->rev[--u->nrev];
            break;
        }
    for (i = 0; i < 256; i++) {                 /* its flows end */
        uflow *f = u->by_id[i], *next;
        for (; f; f = next) {
            next = f->nid;
            if (!f->out && f->lid == lid)
                drop_flow(u, f, 1, NPF_UDP_R_CLOSED);
        }
    }
}

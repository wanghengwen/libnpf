/* Outgoing sessions to many peers (npf/peers.h). */
#define _GNU_SOURCE
#include "npf/sys.h"
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

/* Reconnecting without a storm: delays double from 1 s up to the cap, each
 * with +-25 % jitter (peers that lost the same server do not come back in
 * step); a session must stay up STABLE_MS before the delay starts again from
 * 1 s (a session that drops at once does not loop every second); at login
 * the peers start spread over up to 2 s. Port mappings retry the same way,
 * each on its own. */
#define BACKOFF_MAX_MS     120000
#define FWD_BACKOFF_MAX_MS 60000
#define STABLE_MS          60000
#define LOGIN_SPREAD_MS    2000
#define DEMAND_PENDING     64       /* connections waiting for an on-demand session */
#define DEMAND_WAIT_MS     30000    /* how long one waits for it */
#define DEMAND_TICK_MS     5000
#define UDP_PENDING        32       /* datagrams waiting for an on-demand session */
#define UDP_PENDING_BYTES  (256 * 1024)

typedef struct pfwd {
    npf_peer *p;
    int       used;                 /* a deleted mapping leaves its slot (pending replies point here) */
    int       id;                   /* its number: unique among the peers, for its lifetime */
    char      opt;                  /* 'L', 'D', 'R' */
    char      spec[300];            /* as given */
    int       perm;                 /* part of the saved configuration */
    uint64_t  ext;                  /* the application's id (a platform mapping), 0: none */
    int       socks;                /* -D */
    int       reverse;              /* -R */
    int       udp;                  /* -L ...:PORT/udp (data-channel.md 15) */
    const struct kind_reg *kind;    /* a module's kind of forward (npf_peers_add_kind), spec as it keeps it */
    char      bind[64];
    int       port;
    char      host[256];
    int       hostport;
    int       fd;                   /* -L / -D listener */
    int       up;                   /* listening, or the callee listens (-R) */
    int       asked;                /* -R: a request is outstanding */
    uint32_t  rev_id;               /* -R: the callee's listen_id */
    int       rport;                /* -R: the port the callee listens on */
    int       backoff;
    npf_timer *t_retry;
    int64_t   retry_at;
    char      why[64];
    int       refused;              /* the callee refused it for good (-R forbidden): no retry */
    int       pub;                  /* a public mapping (npf-hosted): its connections in a group of the tunnel */
    npf_policy_rule *acl;           /* its allow_from (malloc), NULL: anyone */
    int       nacl;
    uint32_t  rate;                 /* bytes per second each way, 0: no limit */
    int       draining;             /* the quota is used up: no new connection, closed once its own end */
    int       nconns;               /* public: its open connections (waiting ones too) */
    int       suspended;            /* drained: not listening until the quota is back */
    int       idx;                  /* its slot in p->fwds */
    void     *ctx;                  /* the application's (npf_forward_set_ctx) */
    int       lport;                /* the port in use (-L / -D: bound here; -R: rport), 0 none */
    int       why_code;             /* NPF_FWD_WHY_* of the last failure */
    int       open;                 /* connections open now (sublinks in the session) */
    uint32_t  nrefused;             /* connections the peer refused (its resources) */
    char      refused_why[64];
    int64_t   refused_told;         /* when fwd_refused was called last (ms) */
    int       told_state, told_port, told_why;   /* what the application was told last (fwd_changed) */
} pfwd;

struct npf_peer {
    npf_peer  *next;
    npf_peers *ps;
    uint32_t   id;                  /* its number (npf_peer_id) */
    void      *ctx;                 /* the application's (npf_peer_set_ctx) */
    int        connect;             /* NPF_CONNECT_* */
    int        idle_req;            /* on demand: the idle time it was made with, 0 the default */
    char       nick_here[NPF_NICK_MAX + 1];   /* a nick of this run only */
    int        has_nick_here;
    int        told_state, told_needs;        /* what the application was told last (peer_changed) */
    char       name[300];           /* number or HOST:PORT */
    char       label[33];           /* the name people gave it (local.json), "" none */
    uint64_t   number;              /* platform peer */
    int        direct;
    struct sockaddr_storage to;     /* direct peer */
    uint8_t    psk[32];
    char       password[128];       /* first pairing; wiped once paired */
    pfwd      *fwds[NPF_PEER_MAX_FWD];  /* 0 .. nfwd-1 allocated; a slot is never moved */
    int        nfwd;
    int        listening;
    int        keep;                /* NPF_CONNECT_KEEP: reconnect (a one-off is done when its session ends) */
    int64_t    up_since;            /* the session's start (ms), for STABLE_MS */
    int        backoff;             /* ms */
    npf_timer *t_retry;
    char      *resources;           /* what it published, as last heard (resources.h): a JSON array */
    npf_call  *call;
    int        waiting;             /* a grant_get is outstanding */
    int        call_pinned;         /* the session was started on the pinned key (IK) */
    int        pin_refused;         /* the device refused the pinned key's pairing: only a password now */
    int        by_account;          /* the account's grant let it in (this run): no password asked when the account goes */
    int        finished;
    int        tag;                 /* the application's (npf: from the configuration or not) */
    /* on demand (a hosted client): the listeners are up without a session;
     * a connection starts one, which ends idle_ms after the last connection */
    int        idle_ms;             /* 0: not on demand */
    struct { int fd, slot; int64_t at; uint64_t conn; } pend[DEMAND_PENDING];
    int        npend;
    /* UDP datagrams waiting for the session (a UDP forward of a peer on demand) */
    struct { int slot; struct sockaddr_storage src; socklen_t sl; int64_t at; size_t len; uint8_t *d; } uq[UDP_PENDING];
    int        nuq;
    size_t     uq_bytes;
    npf_timer *t_demand;            /* pending deadlines, idle check */
    int64_t    idle_since;          /* no connection in the session since (ms), 0: some */
    int64_t    retry_at;            /* monotonic ms of the next attempt */
    char       last_why[32];        /* why the last session ended */
};

/* an open public connection (or one waiting for its session) */
typedef struct pconn {
    uint64_t  id;                   /* ours, for the waiting ones */
    npf_peer *p;                    /* NULL: the peer went */
    int       slot, fid, port;      /* its mapping's slot and id (the slot may be reused) */
    uint64_t  mapping;
    npf_call *call;                 /* its session, NULL while it waits */
    uint32_t  sid;                  /* its sublink there */
    struct sockaddr_storage from;
    int64_t   start;                /* Unix ms */
    int       ip;                   /* its address's entry, -1 none */
} pconn;

#define IP_SLOTS 1024               /* source addresses tracked at once (the least recently seen give way) */

typedef struct ipent {
    uint8_t  a[16];
    int      used, conns;
    double   tokens;
    int64_t  at;                    /* last refill / use (ms) */
} ipent;

struct npf_peers {
    npf_node     *n;
    npf_local    *lc;               /* local.json: names, nicks, pinned keys (the engine's) */
    npf_peers_cbs cbs;
    void         *arg;
    npf_peer     *list;
    int           fwd_seq;          /* the last forward number given out */
    /* public connections: open ones, the source addresses, the limits */
    pconn        *conns;
    int           nconns, capconns;
    uint64_t      conn_seq;
    ipent        *ips;
    int           lim_mapping, lim_address, lim_rate;
    int           closing;          /* npf_peers_public_json(close): public ports stay closed */
    int           default_idle_ms;  /* npf_peers_set_idle: on-demand peers made without an idle time */
    int           no_cache;         /* local.json keeps no peer's resources (NPF_OPT_NO_SAVED_OBJECTS) */
    uint32_t      peer_seq;         /* the peers' numbers */
    struct psub {                   /* the forwards' connections in their sessions (counts, refusals) */
        npf_call *call;
        uint32_t  sid;
        int       fid;
    } *subs;
    int           nsubs, capsubs;
    uint8_t      *ubuf;             /* a datagram read from a UDP forward */
    struct kind_reg {               /* the modules' kinds of forward */
        const npf_fwd_kind *k;
        void               *arg;
    } kinds[NPF_FWD_KINDS];
    int           nkinds;
};

/* ---- known callee keys: the pinned public keys, in local.json ---- */

static int known_get(const npf_peers *ps, uint64_t number, uint8_t pub[32])
{
    char t[24];
    npf_ldev *d;
    snprintf(t, sizeof t, "%llu", (unsigned long long)number);
    d = ps->lc ? npf_local_dev(ps->lc, t, 0) : NULL;
    if (!d || !d->has_key)
        return 0;
    memcpy(pub, d->key, 32);
    return 1;
}

static void known_put(npf_peers *ps, uint64_t number, const uint8_t pub[32])
{
    char t[24];
    npf_ldev *d;
    snprintf(t, sizeof t, "%llu", (unsigned long long)number);
    if (!ps->lc || !(d = npf_local_dev(ps->lc, t, 1)))
        return;
    memcpy(d->key, pub, 32);
    d->has_key = 1;
    if (npf_local_save(ps->lc) < 0)
        npf_loge("cannot write %s", ps->lc->path);
}

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

/* what a peer holds besides itself: its forwards, the resources heard */
static void fwds_free(npf_peer *p)
{
    int i;
    free(p->resources);
    p->resources = NULL;
    for (i = 0; i < NPF_PEER_MAX_FWD && p->fwds[i]; i++) {
        free(p->fwds[i]->acl);
        npf_wipe(p->fwds[i], sizeof *p->fwds[i]);
        free(p->fwds[i]);
        p->fwds[i] = NULL;
    }
    p->nfwd = 0;
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

static int jitter(int ms)
{
    return ms * 3 / 4 + (int)npf_rand_range(0, (size_t)ms / 2 + 1);
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

static void demand_wait(pfwd *f, int fd, uint64_t cid);
static void unmap_v4(struct sockaddr_storage *ss);
static const char *conn_admit(pfwd *f, const struct sockaddr_storage *from, int *ip);
static uint64_t conn_add(pfwd *f, const struct sockaddr_storage *from, int ip);
static void conn_refused(pfwd *f, const struct sockaddr_storage *from, const char *why);
static void conn_open(pfwd *f, int fd, uint64_t cid);
static void conn_gone(npf_peers *ps, uint64_t cid, const char *why);

static void accept_cb(npf_loop *loop, int lfd, unsigned ev, void *arg)
{
    pfwd *f = arg;
    (void)loop;
    (void)ev;
    for (;;) {
        int fd = npf_accept(lfd);
        if (fd < 0)
            break;
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
                unmap_v4(&ss);
                if (f->acl && !npf_policy_rules_match(f->acl, f->nacl, (const struct sockaddr *)&ss))
                    why = "allow_from";
                else if (f->draining)
                    why = "quota";          /* the account's quota is used up */
                else
                    why = conn_admit(f, &ss, &ip);
            }
            if (why) {
                npf_sock_close(fd);
                conn_refused(f, &ss, why);
                continue;
            }
            cid = conn_add(f, &ss, ip);
        } else if (f->draining) {
            npf_sock_close(fd);
            continue;
        }
        if ((f->p->idle_ms || (f->p->keep && !f->p->finished))
            && (!f->p->call || npf_call_state(f->p->call) != NPF_CALL_ESTABLISHED)) {
            /* no session yet (on demand), or between two (a kept peer
             * reconnecting): it waits, and the session starts now */
            demand_wait(f, fd, cid);
            continue;
        }
        conn_open(f, fd, cid);
    }
}

static void fwd_start(pfwd *f);
static void fwd_stop(pfwd *f);
static void start_call(npf_peer *p);
static void demand_tick(npf_loop *loop, void *arg);
static void peer_changed(npf_peer *p);

static void demand_timer(npf_peer *p)
{
    if (!p->t_demand)
        p->t_demand = npf_timer_add(p->ps->n->loop, DEMAND_TICK_MS, demand_tick, p);
}

/* on demand: a connection before the session: it waits, and the session starts */
static void demand_wait(pfwd *f, int fd, uint64_t cid)
{
    npf_peer *p = f->p;
    if (p->npend == DEMAND_PENDING) {
        npf_sock_close(fd);
        npf_logw("%s: %s: too many connections waiting for the session, refused", p->name, f->spec);
        conn_gone(p->ps, cid, "no_session");
        return;
    }
    npf_set_nonblock(fd);
    p->pend[p->npend].fd = fd;
    p->pend[p->npend].slot = f->idx;
    p->pend[p->npend].at = npf_mono_ms();
    p->pend[p->npend].conn = cid;
    p->npend++;
    if (!p->call && !p->waiting) {
        if (p->t_retry) {                   /* someone is waiting: no backoff */
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        npf_log("%s: a connection to %s:%d: starting the session", p->name, f->bind, f->port);
        start_call(p);
    }
    demand_timer(p);
}

/* the session is up: the waiting connections go into it */
static void demand_flush(npf_peer *p)
{
    int k;
    for (k = 0; k < p->npend; k++) {
        pfwd *f = p->fwds[p->pend[k].slot];
        if (f->used)
            conn_open(f, p->pend[k].fd, p->pend[k].conn);
        else {
            npf_sock_close(p->pend[k].fd);
            conn_gone(p->ps, p->pend[k].conn, "no_session");
        }
    }
    p->npend = 0;
    p->idle_since = 0;
}

/* UDP datagrams that waited for the session: dropped (slot -1: all) */
static void udp_queue_drop(npf_peer *p, int slot)
{
    int k, n = 0;
    for (k = 0; k < p->nuq; k++) {
        if (slot < 0 || p->uq[k].slot == slot) {
            p->uq_bytes -= p->uq[k].len;
            free(p->uq[k].d);
        } else {
            p->uq[n++] = p->uq[k];
        }
    }
    p->nuq = n;
}

/* the session is up: the datagrams that waited go into it */
static void udp_queue_flush(npf_peer *p)
{
    int k;
    for (k = 0; k < p->nuq; k++) {
        pfwd *f = p->fwds[p->uq[k].slot];
        if (f->used && f->udp && f->fd >= 0 && p->call)
            npf_call_udp_send(p->call, f->fd, &p->uq[k].src, p->uq[k].sl, f->host, (uint16_t)f->hostport, p->uq[k].d,
                              p->uq[k].len);
    }
    udp_queue_drop(p, -1);
}

static void demand_drop(npf_peer *p, const char *why)
{
    int k;
    if (p->npend)
        npf_logw("%s: %d waiting connection(s) closed (%s)", p->name, p->npend, why);
    for (k = 0; k < p->npend; k++) {
        npf_sock_close(p->pend[k].fd);
        conn_gone(p->ps, p->pend[k].conn, "no_session");
    }
    p->npend = 0;
    if (p->nuq)
        npf_logw("%s: %d waiting UDP datagram(s) dropped (%s)", p->name, p->nuq, why);
    udp_queue_drop(p, -1);
}

/* a UDP datagram before the session (on demand, or between two): it waits, and the session starts */
static void udp_wait(pfwd *f, const struct sockaddr_storage *src, socklen_t sl, const uint8_t *buf, size_t len)
{
    npf_peer *p = f->p;
    if (p->nuq == UDP_PENDING || p->uq_bytes + len > UDP_PENDING_BYTES
        || !(p->uq[p->nuq].d = malloc(len ? len : 1)))
        return;                             /* UDP: dropped */
    memcpy(p->uq[p->nuq].d, buf, len);
    p->uq[p->nuq].len = len;
    p->uq[p->nuq].slot = f->idx;
    memcpy(&p->uq[p->nuq].src, src, sizeof *src);
    p->uq[p->nuq].sl = sl;
    p->uq[p->nuq].at = npf_mono_ms();
    p->nuq++;
    p->uq_bytes += len;
    if (!p->call && !p->waiting) {
        if (p->t_retry) {                   /* someone is waiting: no backoff */
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        npf_log("%s: a UDP datagram to %s:%d: starting the session", p->name, f->bind, f->port);
        start_call(p);
    }
    demand_timer(p);
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
        else if (p->idle_ms || (p->keep && !p->finished))
            udp_wait(f, &ss, sl, p->ps->ubuf, (size_t)r);
    }
}

/* waiting connections past their time; a session without connections ends */
static void demand_tick(npf_loop *loop, void *arg)
{
    npf_peer *p = arg;
    int64_t now = npf_mono_ms();
    int k, n = 0;
    (void)loop;
    p->t_demand = NULL;
    for (k = 0; k < p->npend; k++) {
        if (now - p->pend[k].at > DEMAND_WAIT_MS) {
            npf_sock_close(p->pend[k].fd);
            conn_gone(p->ps, p->pend[k].conn, "no_session");
        } else {
            p->pend[n++] = p->pend[k];
        }
    }
    if (n < p->npend)
        npf_logw("%s: %d connection(s) waited too long for the session, closed", p->name, p->npend - n);
    p->npend = n;
    for (k = n = 0; k < p->nuq; k++) {
        if (now - p->uq[k].at > DEMAND_WAIT_MS) {
            p->uq_bytes -= p->uq[k].len;
            free(p->uq[k].d);
        } else {
            p->uq[n++] = p->uq[k];
        }
    }
    p->nuq = n;
    if (p->idle_ms && p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED) {
        npf_call_info i;
        npf_call_info_get(p->call, &i);
        if (i.sublinks > 0 || i.udp_flows > 0 || p->npend || p->nuq)
            p->idle_since = 0;
        else if (!p->idle_since)
            p->idle_since = now;
        else if (now - p->idle_since >= p->idle_ms) {
            npf_log("%s: no connection for %d s: the session ends (the next connection starts one)", p->name,
                    p->idle_ms / 1000);
            p->idle_since = 0;
            npf_call_end(p->call, "idle");  /* the state callback does not reconnect */
            return;
        }
    }
    if (p->npend || p->nuq || (p->idle_ms && (p->call || p->waiting)))
        demand_timer(p);
}

/* ---- public connections: who, how many, how long, how much ---- */

/* an IPv4 visitor on the dual-stack listener (::ffff:a.b.c.d): as IPv4 */
static void unmap_v4(struct sockaddr_storage *ss)
{
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
    static const uint8_t pre[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    struct sockaddr_in s4;
    if (ss->ss_family != AF_INET6 || memcmp(s6->sin6_addr.s6_addr, pre, 12) != 0)
        return;
    memset(&s4, 0, sizeof s4);
    s4.sin_family = AF_INET;
    s4.sin_port = s6->sin6_port;
    memcpy(&s4.sin_addr, s6->sin6_addr.s6_addr + 12, 4);
    memset(ss, 0, sizeof *ss);
    memcpy(ss, &s4, sizeof s4);
}

/* the address as 16 bytes (IPv4 as v4-mapped) */
static void addr_key(const struct sockaddr_storage *ss, uint8_t a[16])
{
    memset(a, 0, 16);
    if (ss->ss_family == AF_INET) {
        a[10] = a[11] = 0xff;
        memcpy(a + 12, &((const struct sockaddr_in *)ss)->sin_addr, 4);
    } else if (ss->ss_family == AF_INET6) {
        memcpy(a, &((const struct sockaddr_in6 *)ss)->sin6_addr, 16);
    }
}

/* the address's entry (made when missing; the least recently seen without
 * open connections gives way), -1 when the table is full of busy ones */
static int ip_get(npf_peers *ps, const struct sockaddr_storage *from)
{
    uint8_t a[16];
    int k, free_k = -1, old_k = -1;
    int64_t now = npf_mono_ms();
    if (!ps->ips && !(ps->ips = calloc(IP_SLOTS, sizeof *ps->ips)))
        return -1;
    addr_key(from, a);
    for (k = 0; k < IP_SLOTS; k++) {
        ipent *e = &ps->ips[k];
        if (e->used && memcmp(e->a, a, 16) == 0)
            return k;
        if (!e->used && free_k < 0)
            free_k = k;
        else if (e->used && !e->conns && (old_k < 0 || e->at < ps->ips[old_k].at))
            old_k = k;
    }
    k = free_k >= 0 ? free_k : old_k;
    if (k < 0)
        return -1;
    memset(&ps->ips[k], 0, sizeof ps->ips[k]);
    memcpy(ps->ips[k].a, a, 16);
    ps->ips[k].used = 1;
    ps->ips[k].tokens = ps->lim_rate > 1 ? ps->lim_rate / 2.0 : 1;
    ps->ips[k].at = now;
    return k;
}

/* NULL and the counts taken, or why it is refused */
static const char *conn_admit(pfwd *f, const struct sockaddr_storage *from, int *ip)
{
    npf_peers *ps = f->p->ps;
    ipent *e;
    int64_t now = npf_mono_ms();
    *ip = -1;
    if (ps->lim_mapping > 0 && f->nconns >= ps->lim_mapping)
        return "mapping_full";
    if (ps->lim_address <= 0 && ps->lim_rate <= 0) {
        f->nconns++;
        return NULL;
    }
    if ((*ip = ip_get(ps, from)) < 0) {
        f->nconns++;
        return NULL;                        /* nothing to count it on: let it in */
    }
    e = &ps->ips[*ip];
    if (ps->lim_rate > 0) {
        double burst = ps->lim_rate > 1 ? ps->lim_rate / 2.0 : 1;
        e->tokens += (double)(now - e->at) * ps->lim_rate / 60000.0;
        if (e->tokens > burst)
            e->tokens = burst;
    }
    e->at = now;
    if (ps->lim_address > 0 && e->conns >= ps->lim_address) {
        *ip = -1;
        return "address_full";
    }
    if (ps->lim_rate > 0 && e->tokens < 1) {
        *ip = -1;
        return "address_rate";
    }
    if (ps->lim_rate > 0)
        e->tokens -= 1;
    e->conns++;
    f->nconns++;
    return NULL;
}

static void conn_refused(pfwd *f, const struct sockaddr_storage *from, const char *why)
{
    npf_peers *ps = f->p->ps;
    char a[80];
    npf_logd("%s: %s: connection from %s refused (%s)", f->p->name, f->spec, npf_addr_str(from, a, sizeof a), why);
    if (ps->cbs.refused)
        ps->cbs.refused(f->p, f->ext, f->port, from, why, 0, ps->arg);
}

static uint64_t conn_add(pfwd *f, const struct sockaddr_storage *from, int ip)
{
    npf_peers *ps = f->p->ps;
    pconn *c;
    if (ps->nconns == ps->capconns) {
        int n = ps->capconns ? ps->capconns * 2 : 32;
        pconn *nc = realloc(ps->conns, (size_t)n * sizeof *nc);
        if (!nc)
            return 0;
        ps->conns = nc;
        ps->capconns = n;
    }
    c = &ps->conns[ps->nconns++];
    memset(c, 0, sizeof *c);
    c->id = ++ps->conn_seq;
    c->p = f->p;
    c->slot = f->idx;
    c->fid = f->id;
    c->port = f->port;
    c->mapping = f->ext;
    c->from = *from;
    c->start = npf_node_time(ps->n);
    c->ip = ip;
    if (ps->cbs.opened)
        ps->cbs.opened(f->p, f->ext, f->port, from, ps->arg);
    return c->id;
}

/* a connection ends: its counts go back; reported as a connection (it had a
 * session) or as refused (why: it never got one) */
static void conn_end(npf_peers *ps, int k, const npf_sublink_stats *st, const char *why)
{
    pconn c = ps->conns[k];
    ps->conns[k] = ps->conns[--ps->nconns];
    if (c.p && c.slot < c.p->nfwd && c.p->fwds[c.slot]->used && c.p->fwds[c.slot]->id == c.fid
        && c.p->fwds[c.slot]->nconns > 0)
        c.p->fwds[c.slot]->nconns--;
    if (c.ip >= 0 && ps->ips && ps->ips[c.ip].conns > 0)
        ps->ips[c.ip].conns--;
    if (why) {
        if (ps->cbs.refused)
            ps->cbs.refused(c.p, c.mapping, c.port, &c.from, why, 1, ps->arg);
    } else if (ps->cbs.conn) {
        ps->cbs.conn(c.p, c.call, c.mapping, c.port, &c.from, c.start, npf_node_time(ps->n), st, ps->arg);
    }
}

static void conn_gone(npf_peers *ps, uint64_t cid, const char *why)
{
    int k;
    for (k = 0; cid && k < ps->nconns; k++)
        if (ps->conns[k].id == cid) {
            conn_end(ps, k, NULL, why);
            return;
        }
}

static pfwd *fwd_by_id(const npf_peers *ps, int id);

/* a forward's connection is in its session now: counted until it ends */
static void sub_add(npf_peers *ps, npf_call *c, uint32_t sid, int fid)
{
    pfwd *f;
    if (ps->nsubs == ps->capsubs) {
        int n = ps->capsubs ? ps->capsubs * 2 : 32;
        struct psub *ns = realloc(ps->subs, (size_t)n * sizeof *ns);
        if (!ns)
            return;
        ps->subs = ns;
        ps->capsubs = n;
    }
    ps->subs[ps->nsubs].call = c;
    ps->subs[ps->nsubs].sid = sid;
    ps->subs[ps->nsubs].fid = fid;
    ps->nsubs++;
    if ((f = fwd_by_id(ps, fid)))
        f->open++;
}

/* a forward's connection ended; refused by the peer's policy: counted, and
 * the application told at most once a second */
static void sub_done(npf_peers *ps, npf_call *c, uint32_t sid, const npf_sublink_stats *st)
{
    int k;
    for (k = 0; k < ps->nsubs; k++)
        if (ps->subs[k].call == c && ps->subs[k].sid == sid) {
            pfwd *f = fwd_by_id(ps, ps->subs[k].fid);
            ps->subs[k] = ps->subs[--ps->nsubs];
            if (!f)
                return;
            if (f->open > 0)
                f->open--;
            if (st && st->end && strcmp(st->end, "target_refused") == 0) {
                int64_t now = npf_mono_ms();
                f->nrefused++;
                if (f->socks)
                    snprintf(f->refused_why, sizeof f->refused_why, "a target not published by the peer");
                else
                    snprintf(f->refused_why, sizeof f->refused_why, "%.24s:%d not published by the peer", f->host,
                             f->hostport);
                if (ps->cbs.fwd_refused && now - f->refused_told >= 1000) {
                    f->refused_told = now;
                    ps->cbs.fwd_refused(f->p, f->idx, ps->arg);
                }
            }
            return;
        }
}

/* a session's sublink opened here ended: a public connection's, a forward's */
static void conn_sublink_done(npf_call *c, uint32_t sid, const npf_sublink_stats *st, void *arg)
{
    npf_peers *ps = arg;
    int k;
    sub_done(ps, c, sid, st);
    for (k = 0; k < ps->nconns; k++)
        if (ps->conns[k].call == c && ps->conns[k].sid == sid) {
            conn_end(ps, k, st, NULL);
            return;
        }
}

/* the session ended: its connections are no longer counted */
static void subs_call_gone(npf_peers *ps, npf_call *c)
{
    int k;
    for (k = 0; k < ps->nsubs;) {
        if (ps->subs[k].call == c) {
            pfwd *f = fwd_by_id(ps, ps->subs[k].fid);
            if (f && f->open > 0)
                f->open--;
            ps->subs[k] = ps->subs[--ps->nsubs];
        } else {
            k++;
        }
    }
}

/* into the session (fd is its now) */
static void conn_open(pfwd *f, int fd, uint64_t cid)
{
    npf_peer *p = f->p;
    int sid = -1, k;
    if (p->call)
        sid = npf_call_open_rated(p->call, fd, f->socks, f->host, (uint16_t)f->hostport, f->pub ? (uint32_t)f->id : 0,
                                  f->rate);
    if (sid < 0) {
        /* no session, or one that carries as many connections as the
         * other side takes (NPF_MAX_SUBLINKS) */
        int full = p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED;
        npf_sock_close(fd);
        if (cid)
            npf_logd("%s: connection to %s:%d refused (%s)", p->name, f->bind, f->port, full ? "session full" : "no session");
        else
            npf_logw("%s: %s, connection to %s:%d refused", p->name, full ? "the session carries all it can" : "session not ready",
                     f->bind, f->port);
        conn_gone(p->ps, cid, full ? "session_full" : "no_session");
        return;
    }
    if (!f->udp && !f->kind)
        sub_add(p->ps, p->call, (uint32_t)sid, f->id);
    npf_call_on_sublink_done(p->call, conn_sublink_done, p->ps);
    for (k = 0; cid && k < p->ps->nconns; k++)
        if (p->ps->conns[k].id == cid) {
            p->ps->conns[k].call = p->call;
            p->ps->conns[k].sid = (uint32_t)sid;
            break;
        }
}

void npf_peers_public_json(npf_peers *ps, int close, npf_out *o)
{
    npf_peer *p;
    int k, first = 1;
    if (close && !ps->closing) {
        ps->closing = 1;
        npf_log("public ports: closing (stopping), %d connection(s) open", ps->nconns);
    }
    npf_out_printf(o, "{\"open\":%d,\"closing\":%s,\"mappings\":[", ps->nconns, ps->closing ? "true" : "false");
    for (p = ps->list; p; p = p->next)
        for (k = 0; k < p->nfwd; k++) {
            pfwd *f = p->fwds[k];
            if (!f->used || !f->pub)
                continue;
            if (ps->closing && (f->fd >= 0 || f->t_retry)) {
                fwd_stop(f);
                npf_log("%s: %s: closed (stopping)", p->name, f->spec);
            }
            npf_out_printf(o, "%s{\"mapping_id\":\"%llu\",\"port\":%d,\"listening\":%s,\"conns\":%d}", first ? "" : ",",
                           (unsigned long long)f->ext, f->port, f->fd >= 0 ? "true" : "false", f->nconns);
            first = 0;
        }
    npf_out_printf(o, "]}");
}

void npf_peers_set_limits(npf_peers *ps, int per_mapping, int per_address, int per_address_minute)
{
    ps->lim_mapping = per_mapping > 0 ? per_mapping : 0;
    ps->lim_address = per_address > 0 ? per_address : 0;
    ps->lim_rate = per_address_minute > 0 ? per_address_minute : 0;
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
    d = jitter(f->backoff);
    snprintf(f->why, sizeof f->why, "%s", why);
    f->retry_at = npf_mono_ms() + d;
    {
        char lb[320];
        npf_logw("%s: %s: %s, again in %d s", f->p->name, fwd_label(f, lb, sizeof lb), why, (d + 999) / 1000);
    }
    f->t_retry = npf_timer_add(f->p->ps->n->loop, d, fwd_retry_cb, f);
    fwd_report(f, 0, why);
}

static void fwd_stop(pfwd *f)
{
    npf_loop *loop = f->p->ps->n->loop;
    if (f->t_retry)
        npf_timer_cancel(loop, f->t_retry);
    f->t_retry = NULL;
    if (f->udp) {
        udp_queue_drop(f->p, f->idx);
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
                    start_call(p);
                    if (p->idle_ms)
                        demand_timer(p);
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
    int one = 1, fd;
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
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
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

static void close_listeners(npf_peer *p)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        fwd_stop(p->fwds[i]);
    p->listening = 0;
}

static void start_forwards(npf_peer *p)
{
    int i;
    for (i = 0; i < p->nfwd; i++)
        fwd_start(p->fwds[i]);
    p->listening = 1;
}

/* the session ended: reverse mappings go with it (asked again next time) */
static void forwards_session_gone(npf_peer *p)
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

/* ---- sessions ---- */

static void start_call(npf_peer *p);

/* the peer gives up (it stays, finished, until removed or tried again) */
static void finish(npf_peer *p, const char *why)
{
    if (p->finished)
        return;
    p->finished = 1;
    demand_drop(p, why);
    snprintf(p->last_why, sizeof p->last_why, "%s", why);
    if (p->ps->cbs.done)
        p->ps->cbs.done(p, why, p->ps->arg);
    peer_changed(p);
}

/* a need of a finished peer that an account session may meet */
static int account_may_help(const npf_peer *p)
{
    return strcmp(p->last_why, "no_account") == 0 || strcmp(p->last_why, "not_paired") == 0;
}

/* a finished peer tries again, as it was made */
static void unfinish(npf_peer *p)
{
    p->finished = 0;
    p->backoff = 0;
}

static void retry_cb(npf_loop *loop, void *arg)
{
    npf_peer *p = arg;
    (void)loop;
    p->t_retry = NULL;
    start_call(p);
}

void npf_peers_retry_now(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->direct || p->call || p->waiting)
            continue;
        if (p->finished && account_may_help(p)) {
            npf_log("%s: an account session: trying again", p->name);
            unfinish(p);
            start_call(p);
        } else if (p->t_retry && !p->idle_ms && !p->finished) {
            npf_timer_cancel(ps->n->loop, p->t_retry);
            p->t_retry = NULL;
            npf_log("%s: retrying now", p->name);
            start_call(p);
        }
    }
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

/* reconnect later, or report the peer finished */
static void again(npf_peer *p, const char *why)
{
    if (p->idle_ms) {                       /* on demand: the next connection tries again */
        demand_drop(p, why);
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
        peer_changed(p);
        return;
    }
    if (strcmp(why, "udp_back") == 0) {    /* not an end: the session starts again over UDP */
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
        if (!p->t_retry)
            p->t_retry = npf_timer_add(p->ps->n->loop, 0, retry_cb, p);
        return;
    }
    if (!p->keep) {
        finish(p, why);
        return;
    }
    if (p->t_retry)
        return;
    {
        int d;
        p->backoff = p->backoff ? (p->backoff * 2 > BACKOFF_MAX_MS ? BACKOFF_MAX_MS : p->backoff * 2) : 1000;
        d = jitter(p->backoff);
        snprintf(p->last_why, sizeof p->last_why, "%s", why);
        p->retry_at = npf_mono_ms() + d;
        npf_log("%s: reconnecting in %d s", p->name, (d + 999) / 1000);
        p->t_retry = npf_timer_add(p->ps->n->loop, d, retry_cb, p);
        peer_changed(p);
    }
}

/* why it cannot connect without a password: a refused one stays the reason
 * (the console says the password was wrong) until another is given */
static const char *unpaired_why(const npf_peer *p)
{
    return strcmp(p->last_why, "wrong_password") == 0 ? "wrong_password" : "not_paired";
}

/* no account session now: a device the account let in waits for the login
 * (the session expired or was revoked: a password reset, a logout elsewhere),
 * any other one for its password */
static const char *no_account_why(const npf_peer *p)
{
    return p->by_account ? "no_account" : unpaired_why(p);
}

static void grant_got(npf_node *n, const npf_json *j, int ok, void *arg)
{
    npf_peer *p = arg;
    uint8_t chain[1024], grant[512];
    int d, cl, gl;
    char err[32] = "no reply";
    p->waiting = 0;
    if (p->finished || p->call)
        return;
    if (!ok) {
        if (j)
            npf_json_get_str(j, 0, "error", err, sizeof err);
        if (strcmp(err, "unavailable") == 0) {  /* the account neither owns it nor was given it */
            p->by_account = 0;
            npf_logw("%s: not paired yet, and the account has no access to it: give its password (-p)", p->name);
            finish(p, unpaired_why(p));     /* a password tries again */
        } else {
            npf_logw("%s: the account's grant refused (%s)", p->name, err);
            again(p, err);
        }
        return;
    }
    d = npf_json_get(j, 0, "data");
    cl = npf_json_get_b64(j, d, "cert", chain, sizeof chain);
    gl = npf_json_get_b64(j, d, "grant", grant, sizeof grant);
    if (cl > 0 && gl > 0) {
        p->by_account = 1;
        p->call_pinned = 0;
        p->call = npf_call_start_grant(n, p->number, chain, (size_t)cl, grant, (size_t)gl);
    }
    if (!p->call)
        again(p, "error");
}

static void grant_updated(npf_call *c, const npf_json *j, int ok, void *arg)
{
    npf_peer *p = arg;
    char err[32] = "no reply";
    (void)c;
    if (ok) {
        npf_log("%s: the device took the new target list", p->name);
        return;
    }
    if (j)
        npf_json_get_str(j, 0, "error", err, sizeof err);
    npf_logw("%s: grant_update refused (%s): the session starts again", p->name, err);
    if (p->call)
        npf_call_end(p->call, "closed");    /* the next session brings the new grant */
}

static void grant_renewed(npf_node *n, const npf_json *j, int ok, void *arg)
{
    npf_peer *p = arg;
    uint8_t grant[512];
    char data[NPF_B64_LEN(512) + 32], g64[NPF_B64_LEN(512) + 1];
    int gl;
    (void)n;
    p->waiting = 0;
    if (!p->call || npf_call_state(p->call) != NPF_CALL_ESTABLISHED)
        return;                             /* a new session gets a new grant anyway */
    gl = ok ? npf_json_get_b64(j, npf_json_get(j, 0, "data"), "grant", grant, sizeof grant) : -1;
    if (gl <= 0) {
        npf_logw("%s: no new grant: the session ends (no target left?)", p->name);
        npf_call_end(p->call, "closed");
        return;
    }
    g64[npf_b64url_encode(grant, (size_t)gl, g64)] = 0;
    snprintf(data, sizeof data, "{\"grant\":\"%s\"}", g64);
    if (npf_call_ctl_request(p->call, "grant_update", data, grant_updated, p) < 0)
        npf_call_end(p->call, "closed");
}

void npf_peer_grant_update(npf_peer *p)
{
    npf_node *n = p->ps->n;
    char data[64];
    if (!n->cfg.hosted_exec || !p->call || p->waiting || npf_call_state(p->call) != NPF_CALL_ESTABLISHED)
        return;
    snprintf(data, sizeof data, "{\"callee\":\"%llu\"}", (unsigned long long)p->number);
    if (npf_node_request(n, "grant_get", data, grant_renewed, p) == 0)
        p->waiting = 1;
}

static void start_call(npf_peer *p)
{
    npf_node *n = p->ps->n;
    uint8_t pub[32];
    int pinned;
    if (p->call || p->waiting || p->finished)
        return;
    if (p->direct) {
        p->call = npf_direct_connect(n, &p->to, p->psk);
        if (!p->call)
            again(p, "error");
        else
            peer_changed(p);
        return;
    }
    if (!n->online) {
        if (p->npend || p->nuq) {           /* signaling on demand: a connection waits */
            npf_node_udp_open(n);           /* UDP on demand: meanwhile */
            npf_node_wake(n, "a connection to a public port");
        }
        return;                             /* the next login starts it */
    }
    if (!npf_node_udp_ready(n))
        return;                             /* UDP on demand: on_udp_ready starts it */
    /* a hosted client always comes with a grant: the device never pairs it */
    pinned = !n->cfg.hosted_exec && known_get(p->ps, p->number, pub);
    if (pinned && p->pin_refused && !p->password[0]) {
        /* paired by password: never the account's grant instead (security.md 9.6) */
        finish(p, "pairing_lost");          /* a new password tries again */
        return;
    }
    if (!pinned && !p->password[0]) {
        if (n->account_id) {
            char data[64];
            snprintf(data, sizeof data, "{\"callee\":\"%llu\"}", (unsigned long long)p->number);
            if (npf_node_request(n, "grant_get", data, grant_got, p) == 0) {
                p->waiting = 1;
                peer_changed(p);
            } else {
                again(p, "error");
            }
            return;
        }
        if (p->by_account)
            npf_logw("%s: the account is logged out (its session expired or was revoked): log in again", p->name);
        else
            npf_log("%s: not paired yet: give its password (-p)", p->name);
        finish(p, no_account_why(p));       /* a password or an account session tries again */
        return;
    }
    p->call_pinned = pinned && !p->password[0];
    p->call = npf_call_start(n, p->number, pinned && !p->password[0] ? NULL : p->password, pinned ? pub : NULL);
    if (!p->call)
        again(p, "error");
    else
        peer_changed(p);
}

/* ---- public ---- */

/* ---- names people give peers (local.json) ---- */

int npf_peers_name_set(npf_peers *ps, const char *name, const char *target, char *err, size_t errcap)
{
    npf_ldev *d, *other;
    npf_peer *p;
    if (!ps->lc) {
        snprintf(err, errcap, "no local.json to keep names in");
        return -1;
    }
    if (*name && !npf_name_valid(name)) {
        snprintf(err, errcap, "%s: a name is letters, digits, '.', '_', '-' (at most 32), not only digits", name);
        return -1;
    }
    if (*name && (other = npf_local_by_name(ps->lc, name)) && strcmp(other->target, target) != 0) {
        snprintf(err, errcap, "the name %s is %s's already", name, other->target);
        return -1;
    }
    if (!(d = npf_local_dev(ps->lc, target, 1))) {
        snprintf(err, errcap, "too many devices in %s", ps->lc->path);
        return -1;
    }
    snprintf(d->name, sizeof d->name, "%s", name);
    if (npf_local_save(ps->lc) < 0) {
        snprintf(err, errcap, "cannot write %s", ps->lc->path);
        return -1;
    }
    for (p = ps->list; p; p = p->next)
        if (strcmp(p->name, target) == 0)
            snprintf(p->label, sizeof p->label, "%s", name);
    return 0;
}

const char *npf_peers_resolve(const npf_peers *ps, const char *word, char *buf, size_t cap)
{
    npf_ldev *d;
    if (ps->lc && npf_name_valid(word) && (d = npf_local_by_name(ps->lc, word))) {
        snprintf(buf, cap, "%s", d->target);
        return buf;
    }
    return word;
}

const char *npf_peer_nick(const npf_peer *p)
{
    npf_ldev *d = p->ps->lc ? npf_local_dev(p->ps->lc, p->name, 0) : NULL;
    return d ? d->nick : "";
}

const char *npf_peer_resources(const npf_peer *p)
{
    npf_ldev *d;
    if (p->resources)
        return p->resources;
    d = p->ps->lc ? npf_local_dev(p->ps->lc, p->name, 0) : NULL;
    return d ? d->resources : NULL;
}

int npf_peer_resources_set(npf_peer *p, const char *json)
{
    npf_ldev *d = p->ps->lc ? npf_local_dev(p->ps->lc, p->name, 0) : NULL;
    char *s = strdup(json);
    if (!s)
        return -1;
    free(p->resources);
    p->resources = s;
    /* its local.json record keeps the last one (shown while it is away);
     * a peer without a record gets none for it */
    if (d && !p->ps->no_cache && (!d->resources || strcmp(d->resources, json) != 0)) {
        char *k = strdup(json);
        if (!k)
            return -1;
        free(d->resources);
        d->resources = k;
        return npf_local_save(p->ps->lc);
    }
    return 0;
}

npf_peers *npf_peers_new(npf_node *n, npf_local *lc, const npf_peers_cbs *cbs, void *arg)
{
    npf_peers *ps = calloc(1, sizeof *ps);
    if (!ps)
        return NULL;
    ps->n = n;
    ps->lc = lc;
    if (cbs)
        ps->cbs = *cbs;
    ps->arg = arg;
    return ps;
}

/* end the session without the done callback and close the listeners */
static void peer_drop(npf_peer *p)
{
    npf_call *c = p->call;
    p->finished = 1;                        /* no done callback */
    p->call = NULL;                         /* the state callback does not find it */
    if (p->t_retry)
        npf_timer_cancel(p->ps->n->loop, p->t_retry);
    p->t_retry = NULL;
    if (p->waiting)
        npf_node_cancel_requests(p->ps->n, p);
    p->waiting = 0;
    if (p->t_demand)
        npf_timer_cancel(p->ps->n->loop, p->t_demand);
    p->t_demand = NULL;
    demand_drop(p, "closed");
    if (c)
        npf_call_end(c, "closed");
    close_listeners(p);
}

/* the order of what the application hears: the session's end (peer_drop),
 * each forward, the peer */
void npf_peers_remove(npf_peers *ps, npf_peer *p)
{
    npf_peer **pp;
    int k;
    for (k = 0; k < ps->nconns; k++)       /* its open connections end later, without it */
        if (ps->conns[k].p == p)
            ps->conns[k].p = NULL;
    for (pp = &ps->list; *pp; pp = &(*pp)->next)
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    if (p->call)
        subs_call_gone(ps, p->call);
    peer_drop(p);
    for (k = 0; k < p->nfwd; k++)
        if (p->fwds[k]->used && ps->cbs.fwd_gone)
            ps->cbs.fwd_gone(p, k, ps->arg);
    if (ps->cbs.gone)
        ps->cbs.gone(p, ps->arg);
    fwds_free(p);
    npf_wipe(p, sizeof *p);
    free(p);
}

/* HOST:PORT in its canonical form ("" when it is not one) */
static void canon_target(const char *word, char *out, size_t cap)
{
    char host[300];
    const char *colon = strrchr(word, ':');
    out[0] = 0;
    if (!colon || colon == word || (size_t)(colon - word) >= sizeof host)
        return;
    if (word[0] == '[' && colon[-1] == ']')
        snprintf(host, sizeof host, "%.*s", (int)(colon - word - 2), word + 1);
    else
        snprintf(host, sizeof host, "%.*s", (int)(colon - word), word);
    if (npf_peer_target_name(0, host, (uint16_t)atoi(colon + 1), out, cap) < 0)
        out[0] = 0;
}

npf_peer *npf_peers_find(const npf_peers *ps, const char *name)
{
    npf_peer *p;
    uint64_t num = npf_number_parse(name);
    char canon[320];
    canon_target(name, canon, sizeof canon);
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (strcmp(p->name, name) == 0 || (num && p->number == num) || (canon[0] && strcmp(p->name, canon) == 0)
            || (p->label[0] && strcmp(p->label, name) == 0))
            return p;
    return NULL;
}

npf_peer *npf_peers_first(const npf_peers *ps) { return ps ? ps->list : NULL; }
npf_peer *npf_peer_next(const npf_peer *p) { return p->next; }
void      npf_peer_set_tag(npf_peer *p, int tag) { p->tag = tag; }
int       npf_peer_tag(const npf_peer *p) { return p->tag; }

const char *npf_peer_status(const npf_peer *p, char *buf, size_t cap)
{
    if (p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED)
        snprintf(buf, cap, "connected");
    else if (p->call || p->waiting)
        snprintf(buf, cap, "connecting");
    else if (p->idle_ms && !p->finished)
        snprintf(buf, cap, "on demand"); /* a connection (or node wake) starts the session */
    else if (p->t_retry) {
        int64_t s = (p->retry_at - npf_mono_ms() + 999) / 1000;
        snprintf(buf, cap, "retry in %lld s (%s)", (long long)(s > 0 ? s : 0), p->last_why);
    } else if (p->finished)
        snprintf(buf, cap, "ended (%s)", p->last_why);
    else
        snprintf(buf, cap, "waiting for the server");
    return buf;
}

void npf_peers_free(npf_peers *ps)
{
    npf_peer *p;
    if (!ps)
        return;
    /* unlink first: ending a call reports its state, and the callback walks
     * the list (several peers end one after another) */
    while ((p = ps->list) != NULL) {
        ps->list = p->next;
        peer_drop(p);
        fwds_free(p);
        npf_wipe(p, sizeof *p);
        free(p);
    }
    {   /* the sessions still being freed must not call back into us */
        npf_call *c;
        for (c = npf_node_calls(ps->n); c; c = npf_call_next(c))
            npf_call_on_sublink_done(c, NULL, NULL);
    }
    free(ps->conns);
    free(ps->ips);
    free(ps->ubuf);
    free(ps->subs);
    free(ps);
}

int npf_peer_target_name(uint64_t number, const char *host, uint16_t port, char *out, size_t cap)
{
    char h[256], a[64];
    unsigned char bin[16];
    size_t i;
    int n;
    if (number) {
        n = snprintf(out, cap, "%llu", (unsigned long long)number);
        return n < 0 || (size_t)n >= cap ? -1 : 0;
    }
    if (!host || !*host || !port || strlen(host) >= sizeof h || strchr(host, ' '))
        return -1;
    for (i = 0; host[i]; i++)
        h[i] = (char)((host[i] >= 'A' && host[i] <= 'Z') ? host[i] - 'A' + 'a' : host[i]);
    h[i] = 0;
    if (inet_pton(AF_INET, h, bin) == 1 && inet_ntop(AF_INET, bin, a, sizeof a))
        n = snprintf(out, cap, "%s:%u", a, (unsigned)port);
    else if (inet_pton(AF_INET6, h, bin) == 1 && inet_ntop(AF_INET6, bin, a, sizeof a))
        n = snprintf(out, cap, "[%s]:%u", a, (unsigned)port);
    else if (strchr(h, ':'))
        return -1;
    else
        n = snprintf(out, cap, "%s:%u", h, (unsigned)port);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}

npf_peer *npf_peers_create(npf_peers *ps, const npf_peer_new *pn, char *err, size_t errcap, int *code)
{
    npf_peer *p, **pp;
    npf_ldev *d;
    char name[320];
    int dummy;
    if (!code)
        code = &dummy;
    *code = 1;
    if (npf_peer_target_name(pn->number, pn->host, pn->port, name, sizeof name) < 0 || strlen(name) >= sizeof p->name) {
        snprintf(err, errcap, "peer: a number, or a host and a port");
        return NULL;
    }
    if (pn->number && pn->number == ps->n->cfg.number) {
        snprintf(err, errcap, "%llu is this computer's own number: it cannot connect to itself",
                 (unsigned long long)pn->number);
        return NULL;
    }
    if (pn->password && strlen(pn->password) >= sizeof p->password) {
        snprintf(err, errcap, "peer %s: the password is too long", name);
        return NULL;
    }
    if (!pn->number && !pn->psk) {
        snprintf(err, errcap, "peer %s: a direct peer needs its pre-shared key", name);
        return NULL;
    }
    if (npf_peers_find(ps, name)) {
        *code = 2;
        snprintf(err, errcap, "%s is a peer already", name);
        return NULL;
    }
    *code = 3;
    if (!(p = calloc(1, sizeof *p))) {
        snprintf(err, errcap, "no memory");
        return NULL;
    }
    p->ps = ps;
    memcpy(p->name, name, strlen(name) + 1);        /* it fits: checked above */
    p->number = pn->number;
    if (!pn->number) {
        p->direct = 1;
        if (npf_direct_resolve(name, &p->to) < 0) {
            *code = 1;
            snprintf(err, errcap, "peer %s: cannot resolve", name);
            free(p);
            return NULL;
        }
        memcpy(p->psk, pn->psk, 32);
    }
    if (pn->password)
        snprintf(p->password, sizeof p->password, "%s", pn->password);
    p->connect = pn->connect;
    p->keep = pn->connect != NPF_CONNECT_ONCE;
    if (pn->connect == NPF_CONNECT_ON_DEMAND) {
        p->idle_req = pn->idle_ms > 0 ? pn->idle_ms : 0;
        p->idle_ms = p->idle_req ? p->idle_req : ps->default_idle_ms;
        if (!p->idle_ms)
            p->idle_ms = 300000;
    }
    d = ps->lc ? npf_local_dev(ps->lc, p->name, 0) : NULL;
    if (d)
        snprintf(p->label, sizeof p->label, "%s", d->name);
    p->id = ++ps->peer_seq;
    p->told_state = -1;
    for (pp = &ps->list; *pp; pp = &(*pp)->next)
        ;
    *pp = p;
    if (p->idle_ms)
        start_forwards(p);                  /* on demand: listening, a connection starts the session */
    return p;
}

int npf_peers_count(const npf_peers *ps)
{
    const npf_peer *p;
    int n = 0;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        n++;
    return n;
}

void npf_peers_start(npf_peers *ps)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (p->direct)
            start_call(p);
}

void npf_peers_on_login(npf_peers *ps)
{
    npf_peer *p;
    int waiting = 0;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        waiting += !p->idle_ms && !p->direct && !p->t_retry && !p->call && !p->waiting && !p->finished;
    for (p = ps ? ps->list : NULL; p; p = p->next) {
        if (p->idle_ms) {                   /* on demand: listening; a connection starts the session */
            if (!p->listening)
                start_forwards(p);
            if ((p->npend || p->nuq) && !p->call && !p->waiting)
                start_call(p);
            continue;
        }
        if (p->direct || p->t_retry)
            continue;
        if (waiting > 1 && !p->call && !p->waiting && !p->finished && !getenv("NPF_TEST_NO_SPREAD")) {
            /* many peers: spread the calls (and their punching); tests that
             * need concurrent punches turn it off (NPF_TEST_NO_SPREAD) */
            int d = (int)npf_rand_range(0, LOGIN_SPREAD_MS);
            snprintf(p->last_why, sizeof p->last_why, "starting");
            p->retry_at = npf_mono_ms() + d;
            p->t_retry = npf_timer_add(ps->n->loop, d, retry_cb, p);
        } else {
            start_call(p);
        }
    }
}

int npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why)
{
    npf_peer *p;
    for (p = ps ? ps->list : NULL; p; p = p->next)
        if (p->call == c)
            break;
    if (!p)
        return 0;
    if (st == NPF_CALL_ESTABLISHED) {
        npf_log("%s: connected (%s)", p->name, npf_call_path_label(c));
        p->up_since = npf_mono_ms();
        start_forwards(p);              /* a mapping that fails retries on its own */
        demand_flush(p);                /* the connections that waited for it */
        udp_queue_flush(p);
        {                               /* and those of the modules' forwards */
            int k;
            for (k = 0; k < p->ps->nkinds; k++)
                if (p->ps->kinds[k].k->kick)
                    p->ps->kinds[k].k->kick(p->ps->kinds[k].arg);
        }
        if (p->idle_ms)
            demand_timer(p);
        if (p->ps->cbs.up)
            p->ps->cbs.up(p, c, p->ps->arg);
        peer_changed(p);
    } else if (st == NPF_CALL_CLOSED) {
        npf_log("%s: session closed (%s)", p->name, why ? why : "");
        p->call = NULL;
        subs_call_gone(p->ps, c);
        if (why && strcmp(why, "auth_failed") == 0 && p->password[0] && !p->up_since) {
            /* the device refused the password: not tried again (each try counts
             * against it there, security.md 8.3); the user gives it anew */
            npf_logw("%s: the password was not accepted: give it again (-p)", p->name);
            npf_wipe(p->password, sizeof p->password);
            why = "wrong_password";
        }
        if (why && strcmp(why, "unauthorized") == 0 && p->call_pinned) {
            /* the device does not know the pairing any more (reset or
             * reinstalled: new keys, or the pairing revoked): trying again
             * never helps, and the account's grant does not replace a
             * password pairing (security.md 9.6): the user pairs anew */
            npf_logw("%s: the device no longer accepts this computer's pairing (reset, reinstalled, "
                     "or the pairing revoked): pair again with its password (-p)", p->name);
            p->pin_refused = 1;
            why = "pairing_lost";
        }
        p->call_pinned = 0;
        forwards_session_gone(p);
        if (p->up_since && npf_mono_ms() - p->up_since >= STABLE_MS)
            p->backoff = 0;             /* it was up long enough: start from 1 s again */
        p->up_since = 0;
        if (strcmp(why ? why : "", "wrong_password") == 0 || strcmp(why ? why : "", "pairing_lost") == 0) {
            finish(p, why);                 /* a new password tries again */
            return 1;
        }
        if (p->idle_ms) {
            /* on demand: no reconnecting; the connections that waited for this
             * session go, a new connection starts the next one */
            demand_drop(p, why ? why : "closed");
            snprintf(p->last_why, sizeof p->last_why, "%s", why ? why : "closed");
            peer_changed(p);
            return 1;
        }
        again(p, why ? why : "closed");
        if (!p->finished && !p->t_retry)
            peer_changed(p);                /* waiting for the server, or started again at once */
    }
    return 1;
}

void npf_peers_on_paired(npf_peers *ps, uint64_t number, const uint8_t pub[32])
{
    npf_peer *p;
    uint8_t old[32];
    if (!ps)
        return;
    if (known_get(ps, number, old) && memcmp(old, pub, 32) != 0)
        npf_log("note: the key of %llu changed; the new key replaces the pinned one", (unsigned long long)number);
    known_put(ps, number, pub);
    npf_log("paired with %llu; later connections need no password", (unsigned long long)number);
    for (p = ps->list; p; p = p->next)
        if (p->number == number) {
            npf_wipe(p->password, sizeof p->password);    /* IK from now on */
            p->pin_refused = 0;
        }
}

npf_call   *npf_peer_call(const npf_peer *p) { return p->call; }
uint64_t    npf_peer_number(const npf_peer *p) { return p->number; }
const char *npf_peer_name(const npf_peer *p) { return p->name; }
const char *npf_peer_label(const npf_peer *p) { return p->label; }
const char *npf_peer_shown(const npf_peer *p) { return p->label[0] ? p->label : p->name; }
int         npf_peer_nfwd(const npf_peer *p) { return p->nfwd; }
uint32_t    npf_peer_id(const npf_peer *p) { return p->id; }
void       *npf_peer_ctx(const npf_peer *p) { return p->ctx; }
void        npf_peer_ctx_put(npf_peer *p, void *ctx) { p->ctx = ctx; }
int         npf_peer_connect_mode(const npf_peer *p) { return p->connect; }
int         npf_peer_idle_asked(const npf_peer *p) { return p->idle_req; }
int         npf_peer_finished(const npf_peer *p) { return p->finished; }
const char *npf_peer_last_why(const npf_peer *p) { return p->last_why; }

npf_peer *npf_peers_by_id(const npf_peers *ps, uint32_t id)
{
    npf_peer *p;
    for (p = ps && id ? ps->list : NULL; p; p = p->next)
        if (p->id == id)
            return p;
    return NULL;
}

int npf_peer_direct_target(const npf_peer *p, const char **host, uint16_t *port)
{
    static char h[300];
    const char *colon;
    if (!p->direct)
        return -1;
    colon = strrchr(p->name, ':');
    if (p->name[0] == '[') {
        snprintf(h, sizeof h, "%.*s", (int)(colon - p->name - 2), p->name + 1);
    } else {
        snprintf(h, sizeof h, "%.*s", (int)(colon - p->name), p->name);
    }
    *host = h;
    *port = (uint16_t)atoi(colon + 1);
    return 0;
}

void npf_peer_set_nick_here(npf_peer *p, const char *nick)
{
    p->has_nick_here = nick != NULL;
    snprintf(p->nick_here, sizeof p->nick_here, "%s", nick ? nick : "");
}

void npf_peer_set_label(npf_peer *p, const char *name)
{
    snprintf(p->label, sizeof p->label, "%s", name ? name : "");
}

int npf_peer_state(const npf_peer *p, int *needs, int *retry_in_ms)
{
    int nd = 0, st;
    if (retry_in_ms)
        *retry_in_ms = 0;
    if (!p->call && !p->password[0]) {
        if (strcmp(p->last_why, "not_paired") == 0)
            nd = NPF_NEED_PASSWORD;
        else if (strcmp(p->last_why, "wrong_password") == 0)
            nd = NPF_NEED_PASSWORD | NPF_NEED_PASSWORD_WRONG;
        else if (strcmp(p->last_why, "pairing_lost") == 0)
            nd = NPF_NEED_PASSWORD | NPF_NEED_PAIRING_LOST;
        else if (strcmp(p->last_why, "no_account") == 0)
            nd = NPF_NEED_ACCOUNT;
    }
    if (p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED)
        st = NPF_PEER_CONNECTED;
    else if (p->call || p->waiting)
        st = NPF_PEER_CONNECTING;
    else if (p->finished)
        st = NPF_PEER_ENDED;
    else if (p->idle_ms)
        st = NPF_PEER_IDLE;
    else if (p->t_retry && strcmp(p->last_why, "starting") != 0) {
        int64_t ms = p->retry_at - npf_mono_ms();
        st = NPF_PEER_RETRY;
        if (retry_in_ms)
            *retry_in_ms = ms > 0 ? (int)ms : 0;
    } else
        st = NPF_PEER_WAITING;
    if (needs)
        *needs = st == NPF_PEER_CONNECTED || st == NPF_PEER_CONNECTING ? 0 : nd;
    return st;
}

/* tell the application when the state or the needs changed */
static void peer_changed(npf_peer *p)
{
    int needs, st = npf_peer_state(p, &needs, NULL);
    if (st == p->told_state && needs == p->told_needs && st != NPF_PEER_RETRY)
        return;
    p->told_state = st;
    p->told_needs = needs;
    if (p->ps->cbs.changed)
        p->ps->cbs.changed(p, p->ps->arg);
}

void npf_peer_set_on_demand(npf_peer *p, int idle_ms)
{
    p->idle_req = idle_ms > 0 ? idle_ms : 0;
    p->idle_ms = p->idle_req ? p->idle_req : p->ps->default_idle_ms;
    p->connect = p->idle_ms ? NPF_CONNECT_ON_DEMAND : NPF_CONNECT_KEEP;
    if (p->idle_ms && p->t_retry) {         /* no reconnecting: a connection starts the next one */
        npf_timer_cancel(p->ps->n->loop, p->t_retry);
        p->t_retry = NULL;
    }
    if (p->idle_ms && !p->listening)
        start_forwards(p);                  /* listening now, the session when a connection comes */
    if (p->idle_ms && p->call)
        demand_timer(p);
    peer_changed(p);
}

void npf_peer_connect_put(npf_peer *p, int connect, int idle_ms, int running)
{
    int busy = p->call || p->waiting;
    if (connect == NPF_CONNECT_ON_DEMAND) {
        p->idle_req = idle_ms > 0 ? idle_ms : 0;
        p->idle_ms = p->idle_req ? p->idle_req : p->ps->default_idle_ms;
        if (!p->idle_ms)
            p->idle_ms = 300000;
        p->connect = NPF_CONNECT_ON_DEMAND;
        p->keep = 1;
        p->idle_since = 0;                  /* the idle time runs from now */
        if (p->t_retry) {                   /* no reconnecting: a connection starts the next one */
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        if (!p->listening)
            start_forwards(p);              /* listening now, the session when a connection comes */
        if (p->call)
            demand_timer(p);
        peer_changed(p);
        return;
    }
    p->idle_req = p->idle_ms = 0;
    p->connect = connect;
    p->keep = connect != NPF_CONNECT_ONCE;
    if (connect == NPF_CONNECT_KEEP) {
        if (p->finished)
            unfinish(p);
        if (running && !busy && !p->t_retry && !p->direct)
            start_call(p);                  /* no session: one now */
    } else if (!busy) {                     /* ONCE, no session to end first: ended now */
        if (p->t_retry) {
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        finish(p, p->last_why[0] ? p->last_why : "local");
    }
    peer_changed(p);
}

void npf_peers_set_idle(npf_peers *ps, int idle_ms)
{
    npf_peer *p;
    if (!ps)
        return;
    ps->default_idle_ms = idle_ms > 0 ? idle_ms : 0;
    for (p = ps->list; p; p = p->next)
        if (p->connect == NPF_CONNECT_ON_DEMAND && !p->idle_req && ps->default_idle_ms)
            p->idle_ms = ps->default_idle_ms;
}

int npf_peers_idle(const npf_peers *ps) { return ps ? ps->default_idle_ms : 0; }
void npf_peers_no_cache(npf_peers *ps) { ps->no_cache = 1; }
int npf_peer_on_demand(const npf_peer *p) { return p->idle_ms > 0; }

int npf_peer_needs_password(const npf_peer *p)
{
    return !p->password[0] && !p->call
           && (strcmp(p->last_why, "not_paired") == 0 || strcmp(p->last_why, "wrong_password") == 0
               || strcmp(p->last_why, "pairing_lost") == 0);
}

int npf_peer_pairing_lost(const npf_peer *p)
{
    return npf_peer_needs_password(p) && strcmp(p->last_why, "pairing_lost") == 0;
}

int npf_peer_needs_account(const npf_peer *p)
{
    return !p->password[0] && !p->call && strcmp(p->last_why, "no_account") == 0;
}

int npf_peer_password_wrong(const npf_peer *p)
{
    return npf_peer_needs_password(p) && strcmp(p->last_why, "wrong_password") == 0;
}

int npf_peer_password_try(npf_peer *p, const char *password)
{
    if (!password[0] || strlen(password) >= sizeof p->password)
        return -1;
    snprintf(p->password, sizeof p->password, "%s", password);
    if (strcmp(p->last_why, "not_paired") == 0 || strcmp(p->last_why, "wrong_password") == 0
        || strcmp(p->last_why, "no_account") == 0 || strcmp(p->last_why, "pairing_lost") == 0)
        p->last_why[0] = 0;
    npf_log("%s: password given", p->name);
    npf_peer_wake_now(p);
    return 0;
}

int npf_peer_wake_now(npf_peer *p)
{
    if (p->call || p->waiting)
        return 1;
    if (p->finished) {
        npf_log("%s: trying again", p->name);
        unfinish(p);
        if (p->t_retry) {
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        start_call(p);
        if (p->idle_ms && (p->call || p->waiting))
            demand_timer(p);
        peer_changed(p);
        return 0;
    }
    if (p->idle_ms) {
        npf_log("%s: woken: starting the session", p->name);
        start_call(p);
        demand_timer(p);                    /* it ends idle_ms later unless used */
        return 0;
    }
    if (p->t_retry && !p->direct) {
        npf_timer_cancel(p->ps->n->loop, p->t_retry);
        p->t_retry = NULL;
        npf_log("%s: retrying now", p->name);
        start_call(p);
    }
    return 0;
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
        if (!p->fwds[i]->used)
            f = p->fwds[i];                /* a free slot, no pending reply points at it */
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

static pfwd *fwd_by_id(const npf_peers *ps, int id)
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
    fwd_stop(f);
    if (p->ps->cbs.fwd_gone)
        p->ps->cbs.fwd_gone(p, i, p->ps->arg);
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
        fwd_stop(f);                        /* its connections have ended: the port closes */
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

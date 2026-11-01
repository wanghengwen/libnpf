/* Private peer implementation state. Forward slots must stay at stable
 * addresses: pending replies may still refer to them after deletion. */
#ifndef NPF_PEERS_INTERNAL_H
#define NPF_PEERS_INTERNAL_H

#include "npf/peers.h"
#include "npf/tunnel.h"

#define DEMAND_PENDING     64       /* connections waiting for an on-demand session */
#define UDP_PENDING        32       /* datagrams waiting for an on-demand session */

/* a forward's state, one at a time (architecture.md 3.9); its deadlines
 * (retry_at, accept_at) are driven by its peer's tick */
enum {
    FS_WAIT = 0,                    /* not up: no session, or not started (-R: not asked yet) */
    FS_ASKED,                       /* -R: a request is outstanding (stays on a deleted slot: its reply points here) */
    FS_UP,                          /* listening, or the callee listens (-R), or a module's kind carries it */
    FS_RETRY,                       /* failed: tried again at retry_at (backoff); the session goes on */
    FS_REFUSED,                     /* -R: the callee refused it for good (forbidden): asked again next session */
    FS_SUSPENDED,                   /* a public mapping drained (quota): not listening until it is back */
};

typedef struct pfwd {
    npf_peer *p;
    int       used;                 /* a deleted mapping leaves its slot (pending replies point here) */
    int       st;                   /* FS_* */
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
    uint32_t  rev_id;               /* -R: the callee's listen_id */
    int       backoff;
    int64_t   retry_at;             /* FS_RETRY: monotonic ms of the next try */
    int64_t   accept_at;            /* out of descriptors: accepting again then, 0 not waiting */
    char      why[64];
    int       pub;                  /* a public mapping (npf-hosted): its connections in a group of the tunnel */
    npf_policy_rule *acl;           /* its allow_from (malloc), NULL: anyone */
    int       nacl;
    uint32_t  rate;                 /* bytes per second each way, 0: no limit */
    int       draining;             /* the quota is used up: no new connection, closed once its own end */
    int       nconns;               /* public: its open connections (waiting ones too) */
    int       idx;                  /* its slot in p->fwds */
    void     *ctx;                  /* the application's (NPF_FWD_OPT_CTX) */
    int       lport;                /* the port in use (-L / -D: bound here; -R: the callee's), 0 none */
    int       why_code;             /* NPF_FWD_WHY_* of the last failure */
    int       open;                 /* connections open now (sublinks in the session) */
    uint32_t  nrefused;             /* connections the peer refused (its resources) */
    char      refused_why[64];
    int       told_state, told_port, told_why;   /* what the application was told last (fwd_changed) */
} pfwd;

/* a peer's state, one at a time (architecture.md 3.9) */
enum {
    PS_IDLE = 0,                    /* no session and nothing pending: on demand, or waiting for a login or UDP */
    PS_START,                       /* starting at retry_at (spread over LOGIN_SPREAD_MS at login) */
    PS_RETRY,                       /* reconnecting at retry_at (backoff) */
    PS_ASKING,                      /* for a session: a grant_get, or a direct peer's lookup, outstanding */
    PS_CALL,                        /* a session: call */
    PS_ENDED,                       /* given up (npf/peers.h): until tried again or removed */
    PS_REMOVED,                     /* npf_peers_remove ran: freed at the next turn (its timer at 0) */
};

struct npf_peer {
    npf_peer  *next;
    npf_peers *ps;
    uint32_t   id;                  /* its number (npf_peer_id) */
    void      *ctx;                 /* the application's (NPF_PEER_OPT_CTX) */
    int        connect;             /* NPF_CONNECT_* */
    int        idle_req;            /* on demand: the idle time it was made with, 0 the default */
    char       nick_here[NPF_NICK_MAX + 1];   /* a nick of this run only */
    int        has_nick_here;
    char       name[300];           /* number or HOST:PORT */
    char       label[33];           /* the name people gave it (local.json), "" none */
    uint64_t   number;              /* platform peer */
    int        direct;
    struct sockaddr_storage to;     /* direct peer: its address; family 0: a name, looked up per session */
    struct npf_resolve *rs;         /* that lookup, while it runs (PS_ASKING) */
    uint8_t    psk[32];
    char       password[128];       /* first pairing; wiped once paired */
    pfwd      *fwds[NPF_PEER_MAX_FWD];  /* 0 .. nfwd-1 allocated; a slot is never moved */
    int        nfwd;
    int        listening;
    int64_t    up_since;            /* the session's start (ms), for STABLE_MS */
    int        backoff;             /* ms */
    char      *resources;           /* what it published, as last heard (resources.h): a JSON array */
    npf_call  *call;                /* PS_CALL */
    int        st;                  /* PS_* */
    int        renewing;            /* a grant_get for the session's grant (a hosted client's) */
    int        call_pinned;         /* the session was started on the pinned key (IK) */
    int        pin_refused;         /* the device refused the pinned key's pairing: only a password now */
    int        by_account;          /* the account's grant let it in (this run): no password asked when the account goes */
    int        tag;                 /* the application's (npf: from the configuration or not) */
    /* on demand (a hosted client): the listeners are up without a session;
     * a connection starts one, which ends idle_ms after the last connection */
    int        idle_ms;             /* 0: not on demand */
    /* the waiting ones: made when the first waits, freed when none does (a
     * peer that never waits keeps 7 KB less) */
    struct pend_conn { int fd, slot, fid; int64_t at; uint64_t conn; } *pend;   /* DEMAND_PENDING; fid: its forward's id */
    int        npend;
    /* UDP datagrams waiting for the session (a UDP forward of a peer on demand) */
    struct pend_dgram { int slot; struct sockaddr_storage src; socklen_t sl; int64_t at; size_t len; uint8_t *d; } *uq;   /* UDP_PENDING */
    int        nuq;
    size_t     uq_bytes;
    int64_t    idle_since;          /* no connection in the session since (ms), 0: some */
    char       last_why[32];        /* why the last session ended */
    /* the peer's one timer (architecture.md 3.9): its deadlines (monotonic
     * ms, 0 none) and its forwards' */
    npf_timer  t_due;               /* embedded (npf/loop.h) */
    int64_t    due_at;              /* when t_due fires */
    int64_t    retry_at;            /* PS_START, PS_RETRY: the next attempt */
    int64_t    demand_at;           /* the waiting ones (their deadlines, the transport asked again) and the idle check */
    struct npf_peer *gone_next;     /* npf_peers.gone */
};

/* an open public connection (or one waiting for its session) */
typedef struct pconn {
    uint64_t  id;                   /* ours, for the waiting ones */
    npf_peer *p;                    /* NULL: the peer went */
    int       fid, port;            /* its mapping's id */
    uint64_t  mapping;
    npf_call *call;                 /* its session, NULL while it waits */
    uint32_t  sid;                  /* its sublink there */
    struct sockaddr_storage from;
    int64_t   start;                /* Unix ms */
    int       ip;                   /* its address's entry, -1 none */
    uint64_t  bytes;                /* in its session: both ways, at the last idle check */
    int64_t   active;               /* monotonic ms the bytes last moved */
} pconn;

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
    npf_peer     *gone;             /* removed, freed on the next turn (a callback of theirs removed them) */
    npf_timer    *t_save;           /* local.json written later: a peer's lists come faster than flash should be written */
    int64_t       saved_at;
    int           fwd_seq;          /* the last forward number given out */
    /* public connections: open ones, the source addresses, the limits */
    pconn        *conns;
    int           nconns;
    size_t        capconns;
    uint64_t      conn_seq;
    ipent        *ips;
    int           lim_mapping, lim_address, lim_rate, lim_account, lim_total;
    npf_timer    *t_idle;           /* idle public connections end (PUBLIC_IDLE_MS, PUBLIC_HELLO_MS) */
    int           closing;          /* npf_peers_public_json(close): public ports stay closed */
    int           default_idle_ms;  /* npf_peers_set_idle: on-demand peers made without an idle time */
    int           no_cache;         /* local.json keeps no peer's resources (NPF_OPT_NO_SAVED_OBJECTS) */
    uint32_t      peer_seq;         /* the peers' numbers */
    struct psub {                   /* the forwards' connections in their sessions (counts, refusals) */
        npf_call *call;
        uint32_t  sid;
        int       fid;
    } *subs;
    int           nsubs;
    size_t        capsubs;
    struct kind_reg {               /* the modules' kinds of forward */
        const npf_fwd_kind *k;
        void               *arg;
    } kinds[NPF_FWD_KINDS];
    int           nkinds;
};

/* no session, none coming, not given up: one may start now */
static inline int peer_startable(const npf_peer *p) { return p->st <= PS_RETRY; }
/* waiting for retry_at to start */
static inline int peer_waits(const npf_peer *p) { return p->st == PS_START || p->st == PS_RETRY; }

/* peers.c */
/* a deadline of the peer's or its forwards' was set to at: the timer moved
 * only when earlier (one moved later leaves it early: the tick finds nothing due) */
void peers_at(npf_peer *p, int64_t at);
int64_t peer_due(const npf_peer *p);            /* the earliest; INT64_MAX none, 0 now (removed) */
void peer_tick(npf_peer *p, int64_t now);       /* what is due: retry, the waiting ones, the forwards */
/* someone waits for the session (a connection, a datagram, a module's
 * forward, a wake): it starts now, no backoff; -1 when the start removed the
 * peer (in the done callback of a start that failed: its fds went) */
int  peers_kick(npf_peer *p);
void peers_start_call(npf_peer *p);

/* peers_forward.c */
void peers_fwd_stop(pfwd *f);
void peers_listeners_close(npf_peer *p);
void peers_forwards_start(npf_peer *p);
void peers_forwards_session_gone(npf_peer *p);
pfwd *peers_fwd_by_id(const npf_peers *ps, int id);
void peers_forwards_tick(npf_peer *p, int64_t now);   /* their retries, the accepting resumed */

/* peers_demand.c */
void peers_demand_timer(npf_peer *p);          /* the waiting ones' check DEMAND_TICK_MS from now, unless set */
void peers_demand_tick(npf_peer *p, int64_t now);
void peers_demand_wait(pfwd *f, int fd, uint64_t cid);
/* what waits for the session goes into it: now when its transport is ready, else as soon as it is */
void peers_ready(npf_peer *p);
void peers_udp_queue_drop(npf_peer *p, int slot);
void peers_demand_drop(npf_peer *p, const char *why);
/* the connections waiting for a forward that goes (its slot may be reused): closed, mapping_closed */
void peers_demand_drop_slot(npf_peer *p, int slot);
void peers_udp_wait(pfwd *f, const struct sockaddr_storage *src, socklen_t sl, const uint8_t *buf, size_t len);

/* peers_connections.c */
/* a visitor's connection fd on the public mapping f: who may (allow_from),
 * the quota, the limits; its record's id, or 0 with fd closed (refused, or
 * no memory to track it: not let in untracked) */
uint64_t peers_public_admit(pfwd *f, int fd);
void peers_conn_gone(npf_peers *ps, uint64_t cid, const char *why);
void peers_subs_call_gone(npf_peers *ps, npf_call *c);
void peers_conn_open(pfwd *f, int fd, uint64_t cid);
void peers_conns_free(npf_peers *ps);     /* (npf_peers_free) */

#endif

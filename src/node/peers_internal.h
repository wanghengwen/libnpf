/* Private peer implementation state. Forward slots must stay at stable
 * addresses: pending replies may still refer to them after deletion. */
#ifndef NPF_PEERS_INTERNAL_H
#define NPF_PEERS_INTERNAL_H

#include "npf/peers.h"
#include "npf/tunnel.h"

#define DEMAND_PENDING     64       /* connections waiting for an on-demand session */
#define UDP_PENDING        32       /* datagrams waiting for an on-demand session */

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
    void     *ctx;                  /* the application's (NPF_FWD_OPT_CTX) */
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
    void      *ctx;                 /* the application's (NPF_PEER_OPT_CTX) */
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

/* peers.c */
int peers_retry_delay(int ms);
void peers_start_call(npf_peer *p);

/* peers_forward.c */
void peers_fwd_stop(pfwd *f);
void peers_listeners_close(npf_peer *p);
void peers_forwards_start(npf_peer *p);
void peers_forwards_session_gone(npf_peer *p);
pfwd *peers_fwd_by_id(const npf_peers *ps, int id);

/* peers_demand.c */
void peers_demand_timer(npf_peer *p);
void peers_demand_wait(pfwd *f, int fd, uint64_t cid);
void peers_demand_flush(npf_peer *p);
void peers_udp_queue_drop(npf_peer *p, int slot);
void peers_udp_queue_flush(npf_peer *p);
void peers_demand_drop(npf_peer *p, const char *why);
void peers_udp_wait(pfwd *f, const struct sockaddr_storage *src, socklen_t sl, const uint8_t *buf, size_t len);

/* peers_connections.c */
void peers_unmap_v4(struct sockaddr_storage *ss);
const char *peers_conn_admit(pfwd *f, const struct sockaddr_storage *from, int *ip);
void peers_conn_refused(pfwd *f, const struct sockaddr_storage *from, const char *why);
uint64_t peers_conn_add(pfwd *f, const struct sockaddr_storage *from, int ip);
void peers_conn_gone(npf_peers *ps, uint64_t cid, const char *why);
void peers_subs_call_gone(npf_peers *ps, npf_call *c);
void peers_conn_open(pfwd *f, int fd, uint64_t cid);

#endif

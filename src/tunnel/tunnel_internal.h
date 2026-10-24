/* the tunnel's state, shared by tunnel.c (frames, flow control, sublinks,
 * the public calls) and tunnel_socks.c (SOCKS5, connecting to the target) */
#ifndef NPF_TUNNEL_INTERNAL_H
#define NPF_TUNNEL_INTERNAL_H

#include "npf/resolve.h"
#include "npf/tunnel.h"

#define SOCKS_BUF      600

enum { FR_DATA = 1, FR_FIN = 2, FR_RESET = 3, FR_WINDOW = 4 };   /* what handle_frame acts on */

enum {
    SL_SOCKS_GREETING,      /* server: waiting for the greeting */
    SL_SOCKS_REQUEST,       /* server: waiting for the request */
    SL_RESOLVING,           /* server: the target name is being resolved (worker thread) */
    SL_CONNECTING,          /* server: connecting to the target */
    SL_OPEN,
    SL_CLIENT_WAIT,         /* client (port mapping): waiting for the two replies */
    SL_LOCAL_GREETING,      /* client (-D): the local application's greeting, answered here */
};

/* bytes for the local end: p[off .. off+len) (written from the front
 * without moving the rest; moved down only when the space runs out) */
typedef struct wbuf {
    uint8_t *p;
    size_t   off, len, cap;
} wbuf;

/* a rate group: token buckets (1 s of burst) for each direction */
typedef struct rgroup {
    uint32_t id, rate;
    int64_t  up, down;          /* tokens: bytes we may read from / write to the local sockets */
    int64_t  at_ms;             /* last refill */
} rgroup;

typedef struct sublink {
    npf_tunnel *t;
    uint32_t id;
    int      fd;
    int      state;
    int      server;            /* we run the SOCKS5 server for this sublink */
    uint8_t  sb[SOCKS_BUF];     /* SOCKS bytes being parsed / replies being stripped */
    size_t   sl;
    size_t   strip;             /* client: reply bytes still to strip (0 = unknown yet) */
    int      skip_method;       /* client (-D): bytes of the server's method reply still to drop */
    int      socks_rep;         /* client (-D): its CONNECT reply not seen yet (REP 2: the policy) */
    int64_t  tx_credit;         /* DATA bytes we may still send */
    uint32_t rx_freed;          /* written locally since the last WINDOW */
    uint32_t rx_window;
    wbuf     wq;                /* to be written to the local socket */
    int      local_eof;         /* local read side ended, FIN sent */
    int      peer_fin;          /* FIN received */
    int      shut_wr;           /* local write side shut down */
    unsigned ev;                /* registered events */
    int      reverse;           /* caller side of a reverse mapping: target checked against rev[] */
    npf_timer *t_connect;
    npf_timer *t_greet;         /* the SOCKS greeting and request still to come (GREET_MS) */
    npf_timer *t_he;            /* SL_CONNECTING: the next address's turn (HE_DELAY_MS) */
    int      cfd[NPF_RESOLVE_MAX];  /* SL_CONNECTING: the attempts under way (the winner becomes fd) */
    int      ncfd;
    int      last_err;          /* SL_CONNECTING: the last attempt's error */
    struct rgroup *rg;          /* its rate group, NULL: none */
    uint64_t in, out;           /* read from / written to its local socket */
    int      shared;            /* counted in the node's (npf_tunnel_shared.subs) */
    npf_resolve *resolve;       /* SL_RESOLVING: the pending lookup */
    struct sockaddr_storage *cand;  /* SL_CONNECTING: a name's addresses still to try (malloc) */
    socklen_t clen[NPF_RESOLVE_MAX];
    int      ncand, icand;
    /* opened here: for its record (npf_sublink_stats) */
    int64_t  t_open, t_ok, t_first;     /* mono ms: opened, CONNECT reply, first byte to the local socket */
    int      fin_first;                 /* 1: the local side closed first, 2: the peer */
    const char *end;                    /* why it ended, when not by FIN (npf_sublink_stats.end) */
    const npf_vend_io *v;               /* a virtual local end (npf_tunnel_open_v), fd -1; NULL: none */
    void    *varg;
    int      vgone;                     /* its owner closed the virtual end (1, 2: reset): for virt_poll */
    int      gone;                      /* closed so: the peer's data dropped until its FIN (or t_gone) */
    npf_timer *t_gone;
} sublink;

struct npf_tunnel {
    npf_loop   *loop;
    int         caller;
    npf_tunnel_io io;
    void       *arg;
    npf_policy *policy;
    npf_tunnel_shared *shared;  /* the node's limits over all its tunnels, NULL none */
    /* the sublinks: ids[i] is subs[i]'s, looked up by a scan of ids (a few
     * hundred at most: one cache line per 16), the last one found first */
    sublink   **subs;
    uint32_t   *ids;
    int         nsubs, cap, last;
    uint32_t    next_id;
    uint32_t    peer_max_seen;  /* largest peer-opened id */
    uint64_t    peer_seen[NPF_MAX_SUBLINKS / 64];  /* the NPF_MAX_SUBLINKS peer ids below it (its
                                   parity: every other one), bit k = peer_max_seen - 2(k + 1): seen
                                   (opened, or reset first) */
    uint8_t    *rb;             /* frame reassembly */
    size_t      rl, rcap;
    int         hello_sent, hello_recv;
    uint32_t    peer_window;
    int64_t     rx_total;       /* its sublinks' receive windows together (NPF_RX_BUDGET) */
    int         peer_max;
    int         paused;
    int         dead;
    rgroup      rg[NPF_RATE_GROUPS];
    int         nrg;
    npf_budget *budget;         /* NULL: none */
    uint64_t    local_in, local_out;    /* read from / written to the local sockets */
    npf_timer  *t_rate;         /* a group ran dry: look again soon */
    /* caller: targets registered for reverse mapping (data-channel.md 7.1) */
    struct { uint32_t id; char host[256]; uint16_t port; } rev[NPF_MAX_REVERSE];
    int         nrev;
    npf_timer  *t_virt;         /* virtual local ends to look at (virt_poll) */
    int         in_poll;        /* virt_poll runs (it arms itself again) */
    int         depth;          /* calls in here that may call out (the transport, the local ends,
                                   sublink_done): npf_tunnel_free from one waits for their end */
    int         free_later;
    int         ngone;          /* virtual ends their owner closed, not handled yet */
};

/* tunnel.c */
int  tunnel_wb_put(wbuf *b, const void *p, size_t n);
int  tunnel_send_frame(npf_tunnel *t, uint32_t id, int type, const void *payload, size_t len);
void tunnel_update_ev(sublink *s);
void tunnel_sub_free(sublink *s, int rst);
void tunnel_sub_reset(sublink *s, int reason);
int  tunnel_flush_local(sublink *s);
/* n bytes of the peer's data taken here: WINDOW back once a quarter of the window is free */
void tunnel_credit_back(sublink *s, size_t n);

/* tunnel_socks.c */
/* parse what the client sent so far; -1 if the sublink was freed */
int  tunnel_socks_parse(sublink *s);
/* client side (port mapping): strip "05 00" and the CONNECT reply */
int  tunnel_client_strip(sublink *s, const uint8_t *p, size_t n, size_t *used);
void tunnel_greet_wait(sublink *s);
void tunnel_greet_done(sublink *s);

#endif

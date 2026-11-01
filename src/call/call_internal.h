/* the call (npf_call) shared by call*.c and the paths (path.h): the call,
 * what sets it up and ends it, then the session's transport from the keys on */
#ifndef NPF_CALL_INTERNAL_H
#define NPF_CALL_INTERNAL_H

#include "npf/sys.h"

#include "anliu.h"
#include "npf/cpace.h"
#include "npf/node.h"
#include "npf/noise.h"
#include "npf/platform.h"
#include "npf/punch.h"
#include "npf/tunnel.h"
#include "../stream/media.h"
#include "../stream/udpfwd.h"
#include "../node/node_internal.h"
#include "path.h"

/* short names for npf_node.h's NPF_AUTH_* */
enum { AUTH_IK = NPF_AUTH_IK, AUTH_PAKE = NPF_AUTH_PAKE, AUTH_GRANT = NPF_AUTH_GRANT, AUTH_DIRECT = NPF_AUTH_DIRECT };

/* control requests awaiting a reply in a session: a reverse_listen for each
 * -R (NPF_MAX_REVERSE) and a few more (grant_update) */
#define NPF_CALL_CTL_MAX (NPF_MAX_REVERSE + 4)

/* both halves in one object (architecture.md 2.5): a datagram goes from
 * the conv table to AnLiu and out through pm_send with no pointer between */
struct npf_call {
    npf_call   *next;
    npf_node   *n;
    int         caller;
    int         st;                 /* CS_* (architecture.md 3.1) */
    int         auth;
    int         direct;             /* direct connection: no platform, fixed path */
    int         secure;             /* connect_mode secure on either side: relays only, no punching */
    uint8_t     call_id[16];
    char        call_id_s[32];
    uint64_t    number;             /* the callee's number */
    uint64_t    caller_number;      /* callee: the caller's number when it is a node, else 0 */
    int         call_req;           /* caller: id of our call request */
    int64_t     up_ms;              /* established at (monotonic ms), 0 = not yet */
    /* the call's one timer (architecture.md 4); the deadlines (mono ms, 0
     * none): the time limit (before CS_UP), punching's (punch_st), a direct
     * initiator's message 1 again */
    npf_timer   t_due;              /* embedded (npf/loop.h) */
    int64_t     due_at;             /* when t_due fires */
    int         ticking;            /* in call_tick: what it sets is scheduled after it */
    int64_t     limit_at, punch_at, direct_at;
    npf_timer  *t_free;             /* its free on the next turn of the loop (ended) */

    struct call_hs *hs;             /* the handshake's state, until the keys are ready */
    int         keys_ready;
    uint8_t     peer_pub[32];
    uint8_t     nominate_key[32];   /* the punch's NOMINATE (call_punch.c), from the keys */
    /* the callee's admission of the caller */
    struct npf_policy *policy;      /* target policy of this session's sublinks */
    uint64_t    grant_account;      /* the account of the grant that admitted the caller */
    char        caller_app[72];     /* the caller's program ("name ver", incoming caller.app) */
    int         caller_hosted;      /* the caller is a hosted client (a public mapping) */
    int         hosted_grant;       /* admitted by a hosted grant */
    uint8_t    *targets;            /* a hosted grant's targets, the only ones it may open */
    size_t      tlen;
    uint32_t    grant_issued;       /* of the grant in effect (grant_update takes newer ones) */
    /* punching (architecture.md 3.2, call_punch.c) */
    int         punch_st;           /* PN_* */
    int         punch_round;        /* the last round planned (punch_start) */
    npf_punch  *punch;              /* that round's, in PN_RUNNING and PN_LINGER */
    int         punch_socks;        /* S3 hard-side sockets of the running punch (node budget) */
    uint16_t    punch_port;         /* S2B: the peer's punch_info port of the round, come before it started */
    npf_punch_cfg *pcfg;            /* the rounds' plan and candidates: made at the first punch_start */
    struct sockaddr_storage tcand;  /* the peer's new srflx (its punch_info "cand"): in this round and the next */
    int         spray_refused_said; /* "not an address to spray" logged in this call */
    /* reverse mappings (data-channel.md 7.1): the callee's listeners, each
     * made when the caller asks for it; the caller's targets (fd -1), each
     * once the callee listens: the only ones its reverse sublinks and UDP
     * flows reach */
    struct rev_map {
        npf_call *c;
        uint32_t id;                /* listen_id */
        int      fd;
        char     host[256];
        uint16_t port;
        int      lan;               /* on every address: this host and its LAN may connect */
        int      want;              /* the port asked for (0: any), as the policy allowed it */
        int64_t  refused_ms;        /* last connection from elsewhere logged */
        int      udp;               /* a UDP socket (-R .../udp; data-channel.md 15) */
    } *rev[NPF_MAX_REVERSE];
    int         nrev;
    uint32_t    rev_seq;

    /* ---- the session's transport (call_transport.c) ---- */
    anl_t      *anl;
    uint32_t    conv;
    npf_call   *conv_next;          /* n->conv_tab chain while c->anl exists */
    anl_stream_t *stream;           /* the data stream: the caller opens it, both send on it */
    struct dmsg  *dpend;            /* callee: data messages before the stream reached us */
    struct dmsg **dpend_tail;
    size_t        dpend_bytes;
    int         flush_pending;      /* anl_flush at the next tick (a send asked for it) */
    uint64_t    auth_fail_seen;     /* AnLiu rx_auth_fail last reported (forged datagrams with our conv) */
    int64_t     auth_fail_at;       /* when */
    int         anl_srtt;           /* AnLiu's srtt at its last timer (ms, 0 none yet) */
    npf_tunnel *tun;
    npf_media  *media;              /* libnpf media streams (media.h), made on first use */
    npf_udpf   *udp;                /* the UDP forwards' flows (udpfwd.h), made on first use */
    struct npf_key_share *kshare;   /* callee: its caller key's share of the node's tunnel limits */
    uint64_t    tx_bytes, rx_bytes; /* tunnel bytes (sublink frames) */
    uint64_t    rep_tx, rep_rx;     /* caller: bytes already reported (npf_call_usage_take) */
    npf_sublink_fn sub_done;        /* a connection opened here ended (npf_call_on_sublink_done) */
    void       *sub_arg;
    struct {                        /* control requests over the tunnel awaiting a reply */
        int id;
        npf_ctl_fn fn;
        void *arg;
    } ctl[NPF_CALL_CTL_MAX];
    int         ctl_seq;
    /* its paths (path.h) */
    npf_pm      pm;
    path_direct pd;
    path_udp    pu;
    path_ws     pw;
    struct relay_early *rearly[8];  /* caller: the peer's relayed datagrams before the keys (path_udp.c) */
    int         nrearly;
};

/* the handshake's state: made with the call, freed once the keys are ready
 * (call_start_transport): an established session carries none of it */
typedef struct call_hs {
    npf_noise_hs noise;
    npf_cpace   cp;
    uint8_t     k12[64];            /* k1 | k2 (security.md 9.5): the session's keys come from it */
    char        password[128];
    char        share[NPF_SHARE_ID + 1];    /* a pairing by a share code: its locator ("" the password) */
    uint8_t     grant[512];         /* caller: hosted-trust grant to present */
    size_t      grant_len;
    uint8_t     dmsg1[256];         /* direct initiator: handshake message 1 for retransmission */
    size_t      dmsg1_len;
    int         dtries;             /* direct initiator: message 1 sent this many times */
    int         direct_tries;       /* direct initiator: message 2 attempts read (64 at most) */
} call_hs;

/* The call's state (architecture.md 3.1), forward only: ANSWERED a callee's
 * answer sent; CONNECTING accepted; HALF a caller established on its own
 * hello; UP both hellos; CLOSED ended, freed on the next turn */
enum { CS_NEW, CS_CALLING, CS_ANSWERED, CS_CONNECTING, CS_HALF, CS_UP, CS_CLOSED };
static inline int call_over(const npf_call *c) { return c->st == CS_CLOSED; }
static inline int call_accepted(const npf_call *c) { return c->st >= CS_CONNECTING; }
static inline int call_up(const npf_call *c) { return c->st == CS_HALF || c->st == CS_UP; }

/* Punching (architecture.md 3.2), one round at a time: NONE rounds to come,
 * SCHEDULED at punch_at, WAIT_KEYS, RUNNING, LINGER (over, its punch freed
 * at punch_at), IDLE */
enum { PN_NONE, PN_SCHEDULED, PN_WAIT_KEYS, PN_RUNNING, PN_LINGER, PN_IDLE };

/* shared by call.c, call_punch.c, the paths */
#define RELAY_KEEPALIVE_MS 25000     /* RELAY_BIND refresh while the relay is in use */
#define RELAY_ASK_AGAIN_MS 10000     /* a request with no allocation: sent again after this, */
#define RELAY_ASK_LATER_MS 30000     /* ... then after this each time (call_need) */
#define PUNCH_LINGER_MS    10000
#define PUNCH_ROUNDS_MAX 10         /* the platform's counted rounds of a call (a sanity limit here) */
#define LABEL_PATH         "NPF-PCHECK-1"       /* the direct path check (path_direct.c), its keys from the session's */
#define PATH_PKT_LEN       (NPF_SIV_TAG_SIZE + 10)
/* n->conv_tab: AnLiu datagrams find their call by conv without a scan */
#define CONV_SLOT(conv) (((conv) ^ ((conv) >> 8) ^ ((conv) >> 16) ^ ((conv) >> 24)) & 255)

/* call.c: the state, the end, dispatch, the node's sessions */
/* the call's one timer (architecture.md 4): call_at a part's deadline, the
 * timer moved only when earlier (inline: each datagram asks; one moved
 * later leaves it early, the tick finds nothing due); call_due the
 * earliest (INT64_MAX none); call_tick does what is due */
void call_arm(npf_call *c, int64_t at);
static inline void call_at(npf_call *c, int64_t at)
{
    if (!npf_timer_pending(&c->t_due) || at < c->due_at)
        call_arm(c, at);
}
int64_t call_due(const npf_call *c, int64_t now);
void call_tick(npf_call *c, int64_t now);
void call_accept(npf_call *c);
void call_set_state(npf_call *c, int st, const char *why);      /* CS_*, forward only */
void call_tell(const npf_call *c, const char *type);  /* a message to the platform naming this call alone */
/* the end; how: CALL_END_LOCAL (npf_call_end: call_end and close), _PEER (the
 * same, the record naming the peer), _QUIET (no word: the platform told us) */
enum { CALL_END_LOCAL, CALL_END_PEER, CALL_END_QUIET };
void call_close(npf_call *c, const char *why, int how);
npf_call *call_new(npf_node *n, int caller);
void call_free(npf_call *c);
void call_hs_free(npf_call *c);         /* the handshake's state wiped and freed (keys ready, or the call goes) */
/* the platform's messages to a call (msgs.c): m_call_rejected, m_relay_switch, m_call_ended */
void call_on_rejected(npf_call *c, const void *m);
void call_on_relay_switch(npf_call *c, const void *m);
void call_on_ended(npf_call *c, const void *m);

/* call_handshake.c: the caller's call, the callee's answer, the keys */
int call_set_targets(npf_call *c, const npf_grant *g);
void node_on_incoming(npf_node *n, const m_env *e, const void *m);   /* m_incoming (msgs.c) */
void call_on_accepted(npf_call *c, const void *m);                     /* m_call_accepted */
void call_on_handshake(npf_call *c, const void *m);                    /* m_handshake */

/* call_direct.c: direct connections (no platform) */
int call_direct_reply(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void call_direct_tick(npf_call *c);     /* direct_at: message 1 again */

/* call_punch.c: the punching rounds the platform sends, their sockets (nat-traversal.md 7) */
void call_punch_report(npf_call *c, const char *why);
int call_hard_punches(const npf_node *n, const npf_call *c);
void call_punch_to(npf_call *c, int st, int64_t at);    /* PN_*: the one transition, at its deadline */
void call_on_punch_info(npf_call *c, const void *m);    /* m_punch_info (msgs.c) */
void call_punch_go(npf_call *c);        /* SCHEDULED at its start, WAIT_KEYS with the keys */
void call_punch_done(npf_punch *p, const npf_punch_result *res, int fd, void *arg);
void call_punch_tick(npf_call *c);     /* punch_at */
void call_on_punch_start(npf_call *c, const void *m);   /* m_punch_start */
int call_no_p2p(const npf_call *c);

/* call_reverse.c: reverse mapping (data-channel.md 7.1) */
void call_rev_close_all(npf_call *c);
void call_rev_drop(npf_call *c, uint32_t id);
const struct rev_map *call_rev_target(const npf_call *c, int udp, uint32_t id, const char *host, uint16_t port);
void call_reverse_request(npf_call *c, const m_env *e);

/* ---- the session's transport ---- */

/* call_transport.c: AnLiu and its carriers, the tunnel's callbacks, media and UDP adapters;
 * tr_*: the session's part of the call's tick, end (the peer told), free and npf_call_info */
int64_t tr_due(const npf_call *c, int64_t now);         /* anl_check's (INT64_MAX: no connection) */
void tr_tick(npf_call *c, int64_t now);
void tr_close(npf_call *c, const char *reason);
void tr_free(npf_call *c);
void tr_info(const npf_call *c, npf_call_info *i);
int call_anl_feed(npf_call *c, const uint8_t *buf, size_t len);
void call_path_up(npf_call *c);
void call_hello(npf_call *c);         /* our hello, the session has a path (a caller established with it) */
struct npf_policy *call_policy(npf_call *c);
npf_media *call_media_of(npf_call *c);
npf_udpf *call_udp_of(npf_call *c);
npf_tunnel *call_tunnel_new(npf_call *c);
void call_ctl_fail_all(npf_call *c);
int call_start_transport(npf_call *c);
void call_control(void *c, const npf_json *j);         /* the tunnel's control message (and the fuzzer's) */

/* the call of one of its paths (path.h): p is &c->member */
#define CALL_OF(p, member) ((npf_call *)(void *)((char *)(p) - offsetof(npf_call, member)))

static inline int call_has_p2p(const npf_call *c) { return c->pm.p[PK_DIRECT] != NULL; }
static inline int call_has_relay(const npf_call *c) { return c->pm.p[PK_UDP_RELAY] != NULL; }
static inline int call_has_ws(const npf_call *c) { return c->pm.p[PK_WS_RELAY] != NULL; }

/* path_mgr.c: the session's paths, the decisions, the allocations, the requests */
void call_paths_init(npf_call *c);
void pm_check(npf_call *c);             /* the health rules and the decisions now, the next at pm.check_at */
void call_relay_setup(npf_call *c, const m_relay *r);  /* none: mode "" */
void call_need(npf_call *c, int need, int64_t now);     /* PM_NEED_* to the platform, its deadline */

/* path_direct.c: the direct path, its check, its loss */
int  path_direct_up(npf_call *c, int fd, const struct sockaddr_storage *peer); /* 0, or -1: owned fd not watched */
void path_direct_fixed(npf_call *c, int fd, const struct sockaddr_storage *peer);
void path_direct_check(npf_call *c);
int call_p2p_cut(const npf_call *c);
int call_path_input(npf_call *c, const uint8_t *buf, size_t len);
void call_p2p_suspect_start(npf_call *c, const char *why);
void call_p2p_drop(npf_call *c);
void call_p2p_input_cb(npf_loop *loop, int fd, unsigned ev, void *arg);

/* path_udp.c: the UDP relay client (data-channel.md 9) */
void path_udp_off(npf_call *c);
void path_udp_setup(npf_call *c, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_storage *addr,
                    int naddr);
void call_relay_rebind(npf_call *c);
void path_udp_tick(npf_call *c);        /* pu.r.at: a bind again, or the keepalive */
void call_relay_early_feed(npf_call *c);
void call_relay_early_keep(npf_call *c, const uint8_t *dgram, size_t len);
void call_relay_early_free(npf_call *c);
int call_relay_input(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* a RELAY_DATA from a relay (data-channel.md 9.2) to one of the calls'
 * allocations: its hint names it, its tag verifies; 1 consumed, 0 not one */
int node_relay_data_input(npf_node *n, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);

/* path_ws.c: the WS relay as a carrier of the AnLiu connection (data-channel.md 10) */
void call_ws_carrier(npf_call *c);      /* paired, keys ready: AnLiu's carrier and the path up */
void call_ws_failed(npf_call *c, const char *why);
int call_ws_setup(npf_call *c, const m_relay *r);
void call_ws_leave(npf_call *c);        /* back to UDP: the WS relay connection goes */
void call_ws_leave_conn(npf_call *c);
void path_ws_heard(npf_call *c);        /* the path's last_rx from the connection's last frame */
void path_ws_tick(npf_call *c);         /* pw.re_at: connected again, or not paired again in time */
void path_ws_flush_timer(npf_loop *loop, void *arg);   /* pw.t_flush's callback (arg: the call) */

#endif

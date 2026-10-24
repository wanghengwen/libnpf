/* the call (npf_call) shared by call.c (the state, dispatch, the node's
 * sessions), call_handshake.c, call_transport.c, call_path.c, call_punch.c,
 * call_relay.c, call_reverse.c, call_ws.c and call_direct.c */
#ifndef NPF_CALL_INTERNAL_H
#define NPF_CALL_INTERNAL_H

#include "npf/sys.h"

#include "anliu.h"
#include "npf/bind.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/cpace.h"
#include "npf/natprobe.h"
#include "npf/node.h"
#include "npf/noise.h"
#include "npf/platform.h"
#include "npf/punch.h"
#include "npf/siv.h"
#include "npf/tunnel.h"
#include "npf/wsrelay.h"
#include "media.h"
#include "udpfwd.h"
#include "node_internal.h"

/* short names for npf_node.h's NPF_AUTH_* */
enum { AUTH_IK = NPF_AUTH_IK, AUTH_PAKE = NPF_AUTH_PAKE, AUTH_GRANT = NPF_AUTH_GRANT, AUTH_DIRECT = NPF_AUTH_DIRECT };

typedef struct relay_c {
    int      active;
    int      bound;
    uint8_t  relay_id[8];
    uint8_t  alloc_key[32];
    npf_siv_keys keys;
    struct sockaddr_storage addr[4];
    int      naddr, cur;
    uint32_t seq;
    uint8_t  cookie[8];         /* the relay's cookie for our address (RELAY_BIND_ACK), echoed in RELAY_BIND */
    int64_t  echo_ms;           /* when a challenge was last answered at once (mono ms) */
    int      tries;
    npf_timer *t_bind;
    int64_t  expires;
    char     mode[8];
} relay_c;

/* control requests awaiting a reply in a session: a reverse_listen for each
 * -R (NPF_MAX_REVERSE) and a few more (grant_update) */
#define NPF_CALL_CTL_MAX (NPF_MAX_REVERSE + 4)

struct npf_call {
    npf_call   *next;
    npf_call   *conv_next;          /* n->conv_tab chain while c->anl exists */
    uint64_t    caller_number;      /* callee: the caller's number when it is a node, else 0 */
    npf_node   *n;
    int         caller;
    int         state;
    int         auth;
    uint8_t     call_id[16];
    char        call_id_s[32];
    uint64_t    number;             /* the callee's number */
    char        req_id[24];         /* callee: id of the incoming request to answer */
    int         call_req;           /* caller: id of our call request */

    struct call_hs *hs;             /* the handshake's state, until the keys are ready */
    uint8_t     peer_pub[32];
    int         keys_ready;
    uint8_t     k12[64];            /* k1 | k2 */
    uint8_t     nominate_key[32];

    anl_t      *anl;
    uint32_t    conv;
    anl_stream_t *stream;           /* the data stream: the caller opens it, both send on it */
    struct dmsg  *dpend;            /* callee: data messages before the stream reached us */
    struct dmsg **dpend_tail;
    size_t        dpend_bytes;
    npf_tunnel *tun;
    npf_timer  *t_anl, *t_timeout, *t_punch, *t_linger;
    int64_t     anl_due;            /* when t_anl fires (monotonic ms) */
    int         flush_pending;
    int         punched;            /* a punch round has finished (either way) */
    npf_timer  *t_ws_wait;          /* UDP relay unreachable: waiting for the punch first */

    relay_c     relay;
    int         p2p;
    int         p2p_fd;
    int         p2p_owned;          /* S3 socket handed over by the punch */
    struct sockaddr_storage p2p_addr;
    int64_t     p2p_rx_ms;
    uint64_t    auth_fail_seen;     /* AnLiu rx_auth_fail last reported (forged datagrams with our conv) */
    int64_t     auth_fail_at;       /* when */
    int64_t     p2p_since;
    int64_t     p2p_suspect;        /* direct path suspected dead since (ms); 0 = no */
    npf_siv_keys path_keys;         /* PATH_CHECK / PATH_ECHO, from the E2E keys */
    int         path_ready;
    uint64_t    path_nonce;         /* of the checks in flight */
    int64_t     path_echo_ms;       /* the last matching echo (ms) */
    int         standby_check;      /* the check before the relay goes: echo -> release */
    npf_timer  *t_pcheck;
    int64_t     p2p_busy_since;     /* data in flight since (ms); 0 = nothing unacknowledged */
    npf_punch  *punch;
    int         punch_socks;        /* S3 hard-side sockets of the running punch (node budget) */
    int64_t     up_ms;              /* established at (monotonic ms), 0 = not yet */
    uint64_t    tx_bytes, rx_bytes; /* tunnel bytes (sublink frames) */
    int         punch_round;
    int         accepted;           /* the platform's accept arrived: t_timeout counts from it */
    int         secure;             /* connect_mode secure on either side: relays only, no punching */
    int         punch_retries;      /* caller: backoff step of punch_request (schedule_repunch) */
    int         empty_rounds;       /* caller: rounds let go for want of candidates (empty_round) */
    int         punch_requests;     /* caller: punch_request sent in this session (PUNCH_ROUNDS_MAX) */
    int         repunch_waiting;    /* t_repunch waits for the round a punch_request asked for */
    int         relay_retried;      /* the UDP relay tried again once after a failed punch, before the WS relay */
    int         relay_waits_ports;  /* the UDP relay unreachable while punches held the NAT's ports: again when they end */
    int         relay_ports_waited; /* that wait was had (once) */
    int         sock_wait;          /* caller, hard side: a round skipped for want of S3 sockets; asked
                                       for again when another punch gives them back */
    npf_timer  *t_repunch, *t_standby;
    int         relay_asked;        /* relay_switch sent, waiting for a new allocation */
    int         ws_paired_once;     /* the WS relay worked at least once */
    int         ws_round;           /* caller: a round began on this relay connection (one each: a
                                       repeated relay_paired starts none) */
    npf_punch_cfg *pcfg;            /* the rounds' plan and candidates: made at the first punch_start */
    uint16_t    info_port;          /* S2B: the peer's punch_info come before the punch started */
    int         info_round;
    int         punch_wait_keys;

    int         ended;
    int         direct;             /* direct connection: no platform, fixed path */
    struct npf_policy *policy;      /* callee: target policy of this session's sublinks */
    int         dtries;             /* direct initiator: message 1 sent this many times */
    int         direct_tries;       /* direct initiator: message 2 attempts read (64 at most) */
    struct call_crev *crev;         /* caller: the reverse mappings in use (NPF_MAX_REVERSE, malloc'd at the first),
                                     * registered again in a new tunnel / UDP forwarding (the move to the WS relay) */
    int         ncrev;
    npf_timer  *t_direct;
    struct npf_key_share *kshare;   /* callee: its caller key's share of the node's tunnel limits */
    uint64_t    grant_account;      /* callee: the account of the grant that admitted the caller */
    char        caller_app[72];     /* callee: the caller's program ("name ver", incoming caller.app) */
    int         caller_hosted;      /* callee: the caller is a hosted client (a public mapping) */
    int         hosted_grant;       /* callee: admitted by a hosted grant */
    uint8_t    *targets;            /* callee: a hosted grant's targets, the only ones it may open */
    size_t      tlen;
    uint32_t    grant_issued;       /* callee: of the grant in effect (grant_update takes newer ones) */
    uint64_t    rep_tx, rep_rx;     /* caller: bytes already reported (npf_call_usage_take) */
    npf_sublink_fn sub_done;        /* a connection opened here ended (npf_call_on_sublink_done) */
    void       *sub_arg;
    struct {                        /* control requests over the tunnel awaiting a reply */
        int id;
        npf_ctl_fn fn;
        void *arg;
    } ctl[NPF_CALL_CTL_MAX];
    int         ctl_seq;
    /* WS relay transport (data-channel.md 10) */
    int         ws_mode;
    npf_wsr    *wsr;
    uint8_t     ws_ktx[32], ws_krx[32];
    uint64_t    ws_ctr_tx, ws_ctr_rx;
    int         ws_tx_ready, ws_rx_ready;
    uint8_t     ws_salts[8][16];    /* the peer's salts seen in this session: no replays */
    uint8_t     ws_pending_salt[16];/* callee: START that arrived before the handshake finished */
    int         ws_has_pending;
    int         ws_nsalts;
    uint8_t    *ws_out;             /* tunnel bytes waiting to be sealed into records */
    uint8_t    *ws_in;              /* received record bytes: channel units not yet complete */
    size_t      ws_in_len, ws_in_cap;
    size_t      ws_out_len, ws_out_cap;
    uint64_t    ws_out_total;       /* all bytes ever put into ws_out (the media's rate estimate) */
    npf_media  *media;              /* libnpf media streams (media.h), made on first use */
    npf_udpf   *udp;                /* the UDP forwards' flows (udpfwd.h), made on first use */
    npf_timer  *t_wsflush;
    npf_timer  *t_free;             /* its free on the next turn of the loop (ended) */
    /* callee: reverse-mapping listeners (data-channel.md 7.1), each made
     * when the caller asks for it */
    struct rev_listener {
        npf_call *c;
        uint32_t id;
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
};

/* the handshake's state: made with the call, freed once the keys are ready
 * (call_start_transport): an established session carries none of it */
typedef struct call_hs {
    npf_noise_hs noise;
    npf_cpace   cp;
    char        password[128];
    uint8_t     pinned[32];
    uint8_t     grant[512];         /* caller: hosted-trust grant to present */
    size_t      grant_len;
    uint8_t     dmsg1[256];         /* direct initiator: handshake message 1 for retransmission */
    size_t      dmsg1_len;
} call_hs;

/* shared by call.c, call_punch.c, call_relay.c */
#define RELAY_BIND_TRIES   3
#define RELAY_KEEPALIVE_MS 25000     /* RELAY_BIND refresh while the relay is in use */
#define RELAY_STANDBY_MS   30000     /* relay kept after the direct path is up, then released */
#define WS_WAIT_MS         15000     /* UDP relay unreachable: the first punch round's result first, at most this */
#define PUNCH_LINGER_MS    10000
#define LABEL_RELAY        "NPF-RELAY-v1"
#define PKT_RELAY_BIND     7
#define PKT_RELAY_BIND_ACK 8
#define PKT_RELAY_DATA     9
#define RELAY_HINT_SIZE    4         /* relay_id[0..3] in the clear before every datagram to the relay */
#define RELAY_COOKIE_SIZE  8
#define RELAY_ACK_BOUND    1         /* RELAY_BIND_ACK state: the relay sends to this address (0: a challenge) */
#define RELAY_DATA_OVERHEAD (RELAY_HINT_SIZE + NPF_SIV_TAG_SIZE + 6)
#define PUNCH_ROUNDS_MAX 10
#define LABEL_PATH         "NPF-PCHECK-1"       /* the direct path check (call_path.c), its keys from the session's */
#define PATH_PKT_LEN       (NPF_SIV_TAG_SIZE + 10)
/* n->conv_tab: AnLiu datagrams find their call by conv without a scan */
#define CONV_SLOT(conv) (((conv) ^ ((conv) >> 8) ^ ((conv) >> 16) ^ ((conv) >> 24)) & 255)

/* a caller key's share of the node's tunnel limits: its sessions here
 * together get half the node's sublinks and receive window, so one visitor
 * leaves room for the others; the entry is reused once no session holds it
 * and nothing is counted in it */
typedef struct npf_key_share {
    uint8_t pub[32];
    int     calls;
    npf_tunnel_shared sh;
} npf_key_share;

/* a timer stopped, if it runs, and forgotten */
static inline void timer_stop(npf_loop *l, npf_timer **t)
{
    if (*t)
        npf_timer_cancel(l, *t);
    *t = NULL;
}

/* call.c: the state, the end, dispatch, the node's sessions */
void call_accept_seen(npf_call *c);
void call_b64_of(const uint8_t *b, size_t n, char *out);
npf_call *call_find(npf_node *n, const npf_json *j, int d);
int call_udp_send(npf_call *c, int fd, const struct sockaddr_storage *to, const uint8_t *buf, size_t len);
int call_relay_blocked(const npf_node *n, const char *what);
int call_relay_addr_blocked(const npf_call *c);
void call_relay_leave(npf_call *c);
int call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
void call_set_state(npf_call *c, int st, const char *why);
npf_call *call_new(npf_node *n, int caller);
void call_free(npf_call *c);
void call_hs_free(npf_call *c);         /* the handshake's state wiped and freed (keys ready, or the call goes) */
/* the data transport (tunnel, UDP forwarding, media) off the call and freed;
 * then the AnLiu connection */
void call_data_free(npf_call *c);
/* caller: a reverse mapping in use / gone (call_reverse.c), and every one
 * registered again in the tunnel or the UDP forwarding just made */
void call_crev_add(npf_call *c, uint32_t lid, const char *host, uint16_t port, int udp);
void call_crev_del(npf_call *c, uint32_t lid);
void call_crev_restore(npf_call *c, npf_tunnel *t, npf_udpf *u);
void call_anl_drop(npf_call *c);

/* call_handshake.c: the caller's call, the callee's answer, the keys */
int call_set_targets(npf_call *c, const npf_grant *g);
int call_finish_handshake(npf_call *c);
void call_caller_accepted(npf_call *c, const npf_json *j, int d);
void call_handle_incoming(npf_node *n, const npf_json *j, int d);
void call_handle_handshake(npf_call *c, const npf_json *j, int d);

/* call_transport.c: AnLiu, the WS mux, the tunnel's callbacks, media and UDP adapters */
int call_anl_feed(npf_call *c, const uint8_t *buf, size_t len);
void call_path_up(npf_call *c);
void call_dpend_free(npf_call *c);
struct npf_policy *call_policy(npf_call *c);
void call_conv_unlink(npf_call *c);
npf_media *call_media_of(npf_call *c);
npf_udpf *call_udp_of(npf_call *c);
npf_tunnel *call_tunnel_new(npf_call *c);
void call_ctl_fail_all(npf_call *c);
int call_start_transport(npf_call *c);

/* call_path.c: the direct path's check, its loss, the relay's standby */
int call_no_p2p(const npf_call *c);
int call_p2p_cut(const npf_call *c);
int call_path_input(npf_call *c, const uint8_t *buf, size_t len);
void call_check_p2p(npf_call *c);
void call_p2p_suspect_start(npf_call *c, const char *why);
void call_standby_done(npf_loop *loop, void *arg);
void call_p2p_input_cb(npf_loop *loop, int fd, unsigned ev, void *arg);

/* call_reverse.c: reverse mapping (data-channel.md 7.1) */
void call_rev_close_all(npf_call *c);
void call_reverse_request(npf_call *c, const char *type, const npf_json *j);

/* call_ws.c: the WS relay transport (data-channel.md 10.2) */
void call_ws_flush_timer(npf_loop *loop, void *arg);
void call_wsr_paired(npf_wsr *r, void *arg);
void call_wsr_start(npf_wsr *r, const uint8_t salt[16], void *arg);
void call_ws_failed(npf_call *c, const char *why);
int call_ws_setup(npf_call *c, const npf_json *j, int r);

/* call_direct.c: direct connections (no platform) */
int call_direct_reply(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);

/* call_punch.c: punching rounds, their sockets and gaps, repunching (nat-traversal.md 7) */
void call_repunch_timer(npf_loop *loop, void *arg);
void call_schedule_repunch(npf_call *c);
int call_hard_punches(const npf_call *c);
void call_punch_sockets_back(npf_node *n);
void call_handle_punch_info(npf_call *c, const npf_json *j, int d);
void call_start_punch_now(npf_call *c);
void call_handle_punch_start(npf_call *c, const npf_json *j, int d);

/* call_relay.c: the UDP relay client, the way to the WS relay (data-channel.md 9) */
void call_ask_ws_relay(npf_call *c);
void call_relay_rebind(npf_call *c);
void call_relay_setup(npf_call *c, const npf_json *j, int d);
int call_relay_input(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void call_relay_send_data(npf_call *c, const uint8_t *dgram, size_t len);
void call_ws_wait_end(npf_call *c, int ok);

#endif

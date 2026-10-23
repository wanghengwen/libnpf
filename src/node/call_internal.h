/* the call (npf_call) shared by call.c (handshake, AnLiu, UDP relay,
 * punching, the state, dispatch) and call_reverse.c, call_ws.c, call_direct.c */
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

    npf_noise_hs hs;
    npf_cpace   cp;
    char        password[128];
    uint8_t     pinned[32];
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
    npf_punch_cfg pcfg;
    uint16_t    info_port;          /* S2B: the peer's punch_info come before the punch started */
    int         info_round;
    int         punch_wait_keys;

    /* peer data from signaling */
    struct sockaddr_storage peer_cand[NPF_PUNCH_MAX_PEERS];
    int         npeer_cand;
    int         ended;
    int         direct;             /* direct connection: no platform, fixed path */
    struct npf_policy *policy;      /* callee: target policy of this session's sublinks */
    uint8_t     dmsg1[256];         /* direct initiator: handshake message 1 for retransmission */
    size_t      dmsg1_len;
    int         dtries;
    npf_timer  *t_direct;
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
    uint8_t     grant[512];         /* caller: hosted-trust grant to present */
    size_t      grant_len;
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
    /* callee: reverse-mapping listeners (data-channel.md 7.1) */
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
    } rev[NPF_MAX_REVERSE];
    int         nrev;
    uint32_t    rev_seq;
};

/* call.c */
void call_dpend_free(npf_call *c);
void call_b64_of(const uint8_t *b, size_t n, char *out);
int call_udp_send(npf_call *c, int fd, const struct sockaddr_storage *to, const uint8_t *buf, size_t len);
int call_relay_blocked(const char *what);
struct npf_policy *call_policy(npf_call *c);
void call_conv_unlink(npf_call *c);
npf_media *call_media_of(npf_call *c);
npf_udpf *call_udp_of(npf_call *c);
npf_tunnel *call_tunnel_new(npf_call *c);
void call_ctl_fail_all(npf_call *c);
int call_start_transport(npf_call *c);
int call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
void call_set_state(npf_call *c, int st, const char *why);
npf_call *call_new(npf_node *n, int caller);
void call_free(npf_call *c);

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

#endif

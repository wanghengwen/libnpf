/* The node: identity, signed server list, signaling connection, main UDP
 * sockets, NAT profile and calls (sessions) of one npf_t. Internal to libnpf;
 * in include/npf because npf's modules use calls, signaling requests and
 * struct npf_node's members, and the app uses npf_number_parse and
 * npf_direct_genpsk. Every function and hook runs on the node's loop thread. */
#ifndef NPF_NODE_H
#define NPF_NODE_H

#include "npf/log.h"
#include <stdint.h>
#include "npf/sys.h"

#include "npf/cert.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/loop.h"
#include "npf/natprobe.h"
#include "npf/portmap.h"
#include "npf/sig.h"
#include "npf/testhooks.h"
#include "npf/tunnel.h"

#define NPF_MAX_SERVERS   32
#define NPF_MAX_ROOTS     2
#define NPF_MAX_CANDS     16

/* a server list's expiry, kind and external channels (security.md 7.5) */
#define NPF_SOURCES_MAX 4
typedef struct npf_list_meta {
    int64_t expires;                            /* Unix s, 0 none */
    int     full;                               /* 0: a seed list (from DNS) */
    char    doh[NPF_SOURCES_MAX][256];          /* names with the seed in TXT records */
    int     ndoh;
    char    https[NPF_SOURCES_MAX][256];        /* static files with the full list */
    int     nhttps;
} npf_list_meta;

typedef struct npf_server_entry {
    int      id;
    int      prio, weight;
    char     ws[2][256];
    int      nws;
    struct sockaddr_in udp[2];  /* signaling over UDP (signaling-udp.md 3.6), nudp of them */
    int      nudp;
    uint8_t  dh_pub[32];
    int      fails;
    int64_t  degraded_until;    /* monotonic ms; 3 failures deprioritise it for an hour */
} npf_server_entry;

/* a parsed signaling or tunnel control message: data is the token of its
 * data object in j; j is lent for the callback only */
typedef struct npf_env {
    int64_t         v;
    char            type[32], id[24], reply_to[24], status[16], error[32], message[64];
    int             data;
    const npf_json *j;
} npf_env;

typedef struct npf_node npf_node;
/* a request's reply: ok is status "ok"; e NULL when none will come (the
 * connection, the node or the session ended) */
typedef void (*npf_reply_fn)(npf_node *n, const npf_env *e, int ok, void *arg);

#define NPF_PENDING_MAX 16             /* signaling requests awaiting replies at once */

typedef struct npf_pending {
    int          id;
    npf_reply_fn fn;
    void        *arg;
} npf_pending;

typedef struct npf_daykey {
    int64_t day;
    uint8_t key[32];
} npf_daykey;

typedef struct npf_cand {
    char t[8];                      /* host6 / mapped / host4 / srflx / pred */
    struct sockaddr_storage a;
} npf_cand;

typedef struct npf_call npf_call;
struct npf_policy;

/* call states (on_call_state, npf_call_state) */
enum { NPF_CALL_CALLING = 1, NPF_CALL_CONNECTING, NPF_CALL_ESTABLISHED, NPF_CALL_CLOSED };

typedef void (*npf_ctl_fn)(npf_call *c, const npf_env *e, int ok, void *arg);     /* as npf_reply_fn */

/* The callee side's operations (npf/callee.h installs them). */
typedef struct npf_callee_ops {
    int  (*authorized)(npf_node *n, const uint8_t caller_pub[32], void *arg);
    /* the pairing password, NULL: pairing disabled */
    const char *(*password)(npf_node *n, void *arg);
    /* nonzero while password pairing is locked */
    int  (*locked)(npf_node *n, void *arg);
    void (*paired)(npf_node *n, const uint8_t caller_pub[32], void *arg);
    void (*pair_failed)(npf_node *n, void *arg);
    /* hosted trust: 0 when grant is valid (not revoked) for caller_pub, with its account
     * and contents (out's targets point into grant); -1 refused */
    int  (*grant_check)(npf_node *n, const uint8_t *grant, size_t len, const uint8_t caller_pub[32],
                        uint64_t *account, npf_grant *out, void *arg);
    /* the platform's revoke{account, before, owner} */
    void (*revoke)(npf_node *n, uint64_t account, int64_t before, int owner, void *arg);
    void (*bind_committed)(npf_node *n, uint64_t account, const uint8_t op[16], void *arg);
    /* a caller's tunnel control request the library does not handle (bind_approve) */
    void (*control)(npf_node *n, npf_call *c, const npf_json *j, void *arg);
    struct npf_policy *policy;
} npf_callee_ops;

/* the node's callbacks (all optional); strings and JSON are lent for the call */
typedef struct npf_node_hooks {
    /* logged in; with a UDP socket, after the first NAT profile */
    void (*on_login)(npf_node *n, void *arg);
    /* why: the reason of NPF_CALL_CLOSED */
    void (*on_call_state)(npf_node *n, npf_call *c, int state, const char *why, void *arg);
    /* caller: the first pairing with number succeeded; pin callee_pub */
    void (*on_paired)(npf_node *n, uint64_t number, const uint8_t callee_pub[32], void *arg);
    /* a platform event the node does not handle (mappings_changed ...); d: its data */
    void (*on_event)(npf_node *n, const char *type, const npf_json *j, int d, void *arg);
    /* a model credential's enrolment gave this identity number (cfg.number
     * and n->cert are set); the node logs in next */
    void (*on_enrolled)(npf_node *n, uint64_t number, void *arg);
    /* application data from the session's peer (npf_call_app_send there) */
    void (*on_app_data)(npf_node *n, npf_call *c, const uint8_t *buf, size_t len, void *arg);
    /* the peer opened media stream number media with tag: 1 takes it, 0 refuses */
    int  (*on_media_open)(npf_node *n, npf_call *c, uint32_t media, int tag, void *arg);
    void (*on_media_frame)(npf_node *n, npf_call *c, uint32_t media, const uint8_t *buf, size_t len,
                           uint32_t frame_no, int flags, uint32_t lost_before, void *arg);
    /* the peer closed or refused a media stream */
    void (*on_media_closed)(npf_node *n, npf_call *c, uint32_t media, void *arg);
    /* cfg.sig_idle_ms: nonzero while the program needs the connection */
    int  (*busy)(npf_node *n, void *arg);
    /* caller: the callee's published resources (control event "resources"); d: its data */
    void (*on_resources)(npf_node *n, npf_call *c, const npf_json *j, int d, void *arg);
    /* the process was suspended or the addresses changed: what waits to
     * reconnect may try at once */
    void (*on_net_change)(npf_node *n, const char *why, void *arg);
    /* the platform refused the enrolment (reason: signaling.md "enroll", may be
     * ""); the node tries again in about retry_s seconds */
    void (*on_enroll_failed)(npf_node *n, const char *error, const char *reason, int retry_s, void *arg);
    /* the signaling connection was lost after a login; the node logs in again by itself */
    void (*on_offline)(npf_node *n, const char *why, void *arg);
} npf_node_hooks;

/* npf_node.enroll_state */
enum { NPF_ENROLL_NONE, NPF_ENROLL_SENT, NPF_ENROLL_DONE, NPF_ENROLL_REFUSED };

/* a model credential's enrolment, sent before the first login of an
 * identity without a number (security.md 4.1, 5.2); secret: model_sk */
typedef struct npf_enroll_req {
    uint8_t model_chain[1024];      /* the credential's vendor and model certificates */
    size_t  model_chain_len;
    uint8_t model_sk[64];           /* the model's signing key */
    char    serial[65];             /* the device's serial number (or one from its hardware) */
    int     nhw;                    /* hardware fingerprint items, sorted by kind */
    char    hw_kind[8][16];
    uint8_t hw_hash[8][16];         /* BLAKE2b(key = model_seed, "npf hwfp v2" | kind | 0 | value)[0..15] */
    uint8_t hw_fp[32];              /* their digest, signed by the enrolment */
} npf_enroll_req;

typedef struct npf_node_cfg {
    int         callable;           /* logs in as role "node" (else "client") */
    uint64_t    number;             /* callable: its number */
    const char *model, *fw;         /* fw: the library's version */
    const char *app_name, *app_ver; /* the program, sent at login */
    uint8_t     roots[NPF_MAX_ROOTS][32];
    int         nroots;
    const char *serverlist_builtin; /* file of the signed list shipped with the program */
    const char *serverlist_saved;   /* file for the lists the platform sends; NULL none */
    const char *doh_servers;        /* tests: "IP:PORT=HOST,..." instead of the public DoH services */
    const char *server_url;         /* tests: this one server instead of the list ... */
    uint8_t     server_pub[32];     /* ... with this key ... */
    struct sockaddr_in server_udp;  /* ... and this UDP signaling address (AF_INET when given) */
    int         udp_port;           /* 0 any */
    int         offline;            /* no platform: no server list, no signaling (direct mode) */
    int         max_calls;          /* callee: platform sessions at once, 0: 32 */
    int         punch_lead_ms;      /* punching starts this long before start_at; -1 automatic (300 with
                                       the macOS application firewall on, else 0) */
    int         no_host_report;     /* report_host = 0: no host details at login */
    int         punch_sockets;      /* hard-side sockets of all punches together, 0 automatic */
    const npf_enroll_req *enroll;   /* number 0: enrol first, then log in as the node */
    int         no_portmap;         /* no PCP / NAT-PMP mapping on the router */
    int         test_one_host;      /* TESTS ONLY: a peer's loopback addresses are probed (security.md 11.1) */
    int         secure;             /* connect_mode secure: relays only, no address to peers, a VPN kept */
    /* npf-hosted (security.md 8.4): hosted_service logs in as the hosted
     * service (role "hosted"); hosted_exec = ID makes this the hosted client
     * of service ID, which carries an account's public mappings */
    int         hosted_service;
    uint64_t    hosted_exec;
    /* signaling on demand (hosted clients): the connection closes after
     * sig_idle_ms with no session, no request and hooks.busy 0 (0: always
     * connected); npf_node_wake opens it again, and so does a timer every
     * sig_wake_ms +-20 % (0: none) */
    int         sig_idle_ms;
    int         sig_wake_ms;
    /* UDP on demand (with sig_idle_ms): no UDP socket until a session needs
     * one (npf_node_udp_ready); it closes with the signaling connection when
     * no session is left. A reopened socket waits for a probe of its mapping;
     * with udp_public (the operator says the address is not translated) it
     * takes the last probe's address with its new port when that probe found
     * the port kept */
    int         udp_on_demand;
    int         udp_public;
    /* home_bind = off: no spare allocation on the server's relay (home-binding.md 17.1) */
    int         home_off;
    /* sig_udp = off: signaling over WebSocket only (signaling-udp.md 5.3) */
    int         sig_udp_off;
} npf_node_cfg;

/* a call_end report not answered yet (npf_node_call_end) */
#define NPF_ENDS_MAX 32
typedef struct npf_end_report {
    char    call_id[32];
    char    reason[24];
    int64_t at_ms;                      /* monotonic: when the session ended */
    int     state;                      /* 0 free, 1 to send, 2 sent */
    int     peer;                       /* the peer ended it */
} npf_end_report;

/* The signaling connections (signaling-udp.md 5.3), a state machine in
 * src/node/sigconn.c, by role: MAIN the one in use (logging in or logged
 * in), RACE the access point tried beside it, MOVE a UDP session logging in
 * to take over from a MAIN on the WebSocket, OLD the WebSocket it replaced
 * until that closes */
enum { SR_MAIN, SR_RACE, SR_MOVE, SR_OLD, SR_N };
enum {
    SS_IDLE,        /* none: the next attempt waits (backoff) */
    SS_CONNECT,     /* MAIN connects and logs in; RACE beside it, or due (UDP first) */
    SS_ONLINE,      /* MAIN logged in (OLD, the WebSocket a move replaced, until it closes) */
    SS_MOVE,        /* on the WebSocket, MOVE logs in over UDP */
    SS_TAKEN,       /* ... and the server took its login ("replaced" on MAIN) */
    SS_WELCOME,     /* the replaced WebSocket closed first: MAIN is the UDP session, its welcome due */
};
typedef struct npf_sigconn {
    npf_sig *s;                     /* NULL: none (server, url: the last one's) */
    int      server;                /* index into the node's servers */
    int      url;                   /* its WebSocket URL; -1 its UDP */
} npf_sigconn;
typedef struct npf_sigc {
    npf_sigconn c[SR_N];
    int      state;                 /* SS_* */
    int      udp_silent;            /* this attempt's UDP: -1 none, 0 tried, 1 never answered */
    int      udp_bad;               /* WebSocket only, until the network changes or UDP logs in */
    int64_t  race_at, login_at, move_at, old_at;    /* monotonic ms: due; 0 not */
    void   (*close)(npf_sig *s);    /* a connection the machine drops (NULL: npf_sig_close; tests) */
} npf_sigc;

struct npf_node {
    npf_loop     *loop;
    npf_node_cfg  cfg;
    struct npf_budget *budget;      /* a hosted client's quota: every tunnel spends it (npf/tunnel.h) */
    npf_node_hooks hooks;
    void         *hook_arg;
    /* optional (a module's): nonzero skips a peer's candidate (one this host
     * would send into a virtual interface of its own); shown, call_id: for the log */
    int         (*skip_cand)(void *arg, const struct sockaddr_storage *to, const char *shown, const char *call_id);
    void         *skip_cand_arg;
    npf_identity  id;

    /* certificates (raw "inter | leaf" chains) */
    uint8_t       cert[1024];
    size_t        cert_len;
    uint8_t       account_cert[1024];
    size_t        account_cert_len;
    void        (*on_cert)(npf_node *n, void *arg);   /* a node certificate was (re)issued */
    void         *on_cert_arg;
    void        (*on_account_cert)(npf_node *n, void *arg);   /* a renewed account certificate */
    void         *on_account_cert_arg;

    /* server list */
    npf_server_entry *servers;      /* where to connect (at most NPF_MAX_SERVERS) */
    int           nservers;
    npf_server_entry *list;         /* the whole verified list (relay keys by server_id): nlist */
    int           nlist;
    int64_t       sl_serial;
    int64_t       sl_full_serial;   /* of the full list kept on disk */
    npf_list_meta sl_meta;          /* of the list in use */
    int64_t       unreachable_since;/* monotonic ms: no server reached since; 0 online */
    char          sig_error[160];   /* why the last attempt did not log in ("" none since the last login) */
    int           sig_refused;      /* ... the platform refused the login (not the network) */
    /* the platform's upgrade offer for this program (signaling.md "升级") */
    struct {
        int  required;                  /* below the lowest version: no login until upgraded */
        char min[40], latest[40];
        char url[320], notes[320];
        char *packages;                 /* signed install manifests, a JSON array as sent (malloc'd; NULL none) */
    } upgrade;
    int64_t       src_next;         /* monotonic ms: no round before */
    int           src_backoff;      /* ms */
    void         *src_req[2 * NPF_SOURCES_MAX * 2];    /* external-channel requests in flight */
    int           nsrc_req;
    int           cur_server;       /* index into servers, -1 none */

    /* signaling */
    npf_sigc      sc;               /* the connections (node_sig: the one in use) */
    npf_timer    *t_sc;             /* at sc's next due */
    npf_sig      *msg_sig;          /* the connection the message being handled came on */
    int64_t       sig_open_ms;      /* monotonic: the attempt began */
    npf_sig_cookie sig_cookie;      /* the server's, for the next attempts */
    int           online;           /* logged in (welcome received) */
    int           host_full;        /* this connection's login sends the host's JSON (host_required) */
    /* counters for status */
    int64_t       started_unix_ms;  /* npf_node_init's wall clock */
    int64_t       started_mono_ms;
    int64_t       last_login_unix_ms;   /* the last welcome, 0 none */
    int           logins;           /* welcomes since the start */
    int           calls_out, calls_in;  /* sessions started / incoming calls (platform and direct) */
    int           backoff_ms;
    int64_t       replaced_ms;          /* monotonic: the platform said this identity logged in elsewhere; 0 not */
    int           replaced_backoff_ms;  /* the wait after that: 10 s doubling to 5 min */
    /* the last enrolment (status "enroll") */
    int           enroll_state;     /* NPF_ENROLL_* */
    char          enroll_error[32], enroll_reason[24];
    int64_t       enroll_at_unix_ms;
    npf_timer    *t_reconnect, *t_ping;
    npf_timer    *t_expect;         /* something from the server is due */
    int64_t       expect_since;     /* ... since then (monotonic ms) */
    int           expect_probed;    /* ... and a ping asked for it already */
    int           sig_via_vpn;      /* signaling goes through a VPN: around it did not log in */
    int           dormant;          /* cfg.sig_idle_ms: closed for want of use, until npf_node_wake */
    int64_t       busy_at;          /* monotonic: the last time something needed the connection */
    npf_timer    *t_idle, *t_wake;
    int           req_seq;
    npf_pending   pending[NPF_PENDING_MAX];
    npf_end_report ends[NPF_ENDS_MAX];  /* call_end reports not answered yet */
    uint64_t      account_id;       /* the account session of this connection, 0 none */
    /* the account session began (account_id) or ended: the platform's
     * "account", or a login without the session the certificate was for */
    void        (*on_account)(npf_node *n, void *arg);
    int           server_id;
    uint64_t      client_id;
    int64_t       clock_offset_ms;  /* server time - local wall clock */
    int64_t       login_sent_ms;    /* monotonic */
    uint8_t       ticket[28];
    npf_daykey    probe_keys[2];
    struct sockaddr_in probe_ep[3]; /* the address probes: E1, E2 [, E3] (nat-traversal.md 4.1) */
    int           nprobe_ep;
    int           ping_s;
    int           punch_lead_ms;    /* cfg.punch_lead_ms resolved */
    int           punch_budget;     /* default hard-side socket budget: 1024, at most half the descriptor limit */
    npf_tunnel_shared tun_shared;   /* limits of all sessions' tunnels: sublinks, receive windows */
    struct npf_key_share **kshares; /* per caller key: a share of tun_shared */
    int           nkshares;
    int64_t       hard_punch_end;   /* monotonic ms: a hard-side punch last gave its sockets back; 0 none */
    int64_t       port_pressure;    /* monotonic ms: the last sign the NAT ran short of ports around a
                                       hard-side punch; 0 none */

    /* UDP */
    int           udp_fd;
    uint16_t      udp_port;
    npf_test_hooks th;              /* tests only (npf/testhooks.h) */
    struct npf_call *relay_hit;     /* the call the last relayed datagram was for: tried first */
    int           udp6_fd;          /* IPv6 main socket, -1 none */
    uint16_t      pred_port;        /* sequential allocation: the next mapping's port ("pred" candidate) */
    /* the router's port mapping */
    struct npf_portmap pm;
    int           pm_ok, pm_tried;
    int           pm_gw, pm_m;      /* what the gateway did (PM_GW_*), the method that answered */
    void         *pm_job;
    uint64_t      pm_net;           /* npf_portmap_net at the last start */
    npf_timer    *t_pm;
    uint16_t      udp6_port;
    npf_nat_profile nat;
    int           nat_valid;
    int           nat_udp;          /* probe servers answered */
    struct npf_natprobe *probe;     /* the NAT probe running, NULL none */
    int           login_waits_nat;  /* hooks.on_login after the first profile */
    int           nat_kept_port;    /* the last probe: the mapping kept the port, and it is endpoint-
                                       independent or the address is local (no NAT) */
    int           nat_quick;        /* the next probe measures only the socket's mapping (a reopened socket) */
    int           udp_waiters;      /* cfg.udp_on_demand: sessions wait for the profile (on_udp_ready) */
    npf_timer    *t_udp_reopen;     /* a main socket failed: reopened on the loop */
    npf_timer    *t_nat_retry;      /* a NAT probe went unanswered: again soon */
    int           nat_retries;
    int           nat_again;        /* measuring once more: no answer, or the allocation in doubt */
    int64_t       nat_ok_ms;        /* monotonic: the last answered probe */
    int64_t       udp_back_ms;      /* monotonic: an answered probe after an unanswered one */
    /* the network watch: after a suspended process or changed addresses the
     * connections are checked at once */
    npf_timer    *t_watch, *t_netcheck;
    int64_t       watch_boot_ms;    /* npf_boot_ms of the last tick */
    uint32_t      watch_addrs;      /* digest of the interfaces' addresses, 0 not yet */
    int64_t       netcheck_ms;      /* monotonic: a check's signaling ping went out */
    int           netcheck_path;    /* the check is a call's: its UDP path went silent (node_sig_udp_check) */
    int           repunch_on_nat;   /* a network check: relayed calls report again once the NAT is measured */
    void        (*on_udp_ready)(npf_node *n, void *arg);
    struct sockaddr_in srflx;
    struct in_addr pub_ip;
    npf_cand      cands[NPF_MAX_CANDS];
    int           ncands;

    struct npf_home *home;          /* the spare allocation on the relay, NULL none */

    npf_call     *calls;
    npf_call     *conv_tab[256];    /* calls with an AnLiu connection, by conv (datagram demux) */
    const npf_callee_ops *callee;   /* callable nodes */
    void         *callee_arg;
};

/* ---- calls ---- */

/* Caller: calls number. With password: the first pairing (CPace + XXpsk3);
 * else IK to pinned, the key pinned at pairing. States come through
 * hooks.on_call_state. NULL: not logged in, or the call cannot start. */
npf_call *npf_call_start(npf_node *n, uint64_t number, const char *password, const uint8_t pinned[32]);
/* Caller with hosted trust: IK to the key of chain's leaf, which must verify
 * against the roots and be number's node certificate; grant goes with the
 * call (both copied). NULL when they do not verify or the call cannot start. */
npf_call *npf_call_start_grant(npf_node *n, uint64_t number, const uint8_t *chain, size_t chain_len,
                               const uint8_t *grant, size_t grant_len);
/* A control request in the tunnel (data_json: the data object, NULL {}).
 * fn gets the reply once, or e NULL when the session or tunnel ends first.
 * 0, or -1: the tunnel is not ready, no request slot, or it does not fit. */
int  npf_call_ctl_request(npf_call *c, const char *type, const char *data_json, npf_ctl_fn fn, void *arg);
/* A control event (no reply): 0, or -1 (tunnel not ready, over NPF_CTRL_MAX). */
int  npf_call_ctl_event(npf_call *c, const char *type, const char *data_json);

/* ---- application data and media streams of an established session ---- */

/* Application data on the control channel (<= NPF_CTRL_MAX bytes, copied): 0, -1 not ready. */
int  npf_call_app_send(npf_call *c, const void *buf, size_t len);

typedef struct npf_call_media_opt {
    int tag;                        /* the application's, 0..999 */
    int prio, max_age_ms, drop_until_key, fec, fec_ratio, latency_rtt, rcv_deadline_ms, rcv_drop_until_key;
} npf_call_media_opt;

typedef struct npf_call_media_stats {
    uint32_t target_rate, srtt_ms, min_rtt_ms, frames_dropped, frames_skipped, fec_recovered;
    uint32_t peer_frame_delay_avg_ms, peer_frame_delay_max_ms, peer_jitter_ms;
    int      capacity_short;
} npf_call_media_stats;

/* the same values as npf.h's NPF_E* */
enum { NPF_CALL_ENOENT = -2, NPF_CALL_ESTATE = -3, NPF_CALL_EUNAVAIL = -4, NPF_CALL_ETOOBIG = -5, NPF_CALL_ENOMEM = -6,
       NPF_CALL_EBUSY = -8 };

/* Opens a media stream to the peer (on any path): its number in the
 * session, or 0 with *err (NPF_CALL_ESTATE: the session is not up,
 * NPF_CALL_EBUSY: too many streams). The other media calls return 0 or an
 * NPF_CALL_E* (NPF_CALL_ESTATE once the call is closed). */
uint32_t npf_call_media_open(npf_call *c, const npf_call_media_opt *o, int *err);
/* buf is copied; max_age_ms counts from t_submit (npf_mono_ms) */
int      npf_call_media_send(npf_call *c, uint32_t media, int flags, const void *buf, size_t len, int64_t t_submit);
int      npf_call_media_get_stats(npf_call *c, uint32_t media, npf_call_media_stats *out);
int      npf_call_media_close(npf_call *c, uint32_t media);
/* Replies to the control request req with status ("ok" / "error"), error
 * and data_json: 0, or -1 when req has no id or it cannot be sent. */
int  npf_call_ctl_reply(npf_call *c, const char *type, const npf_json *req, const char *status, const char *error,
                        const char *data_json);
enum { NPF_AUTH_IK = 1, NPF_AUTH_PAKE, NPF_AUTH_GRANT, NPF_AUTH_DIRECT };

/* ---- direct connections (no platform): Noise_NNpsk0 over UDP with a
 * 32-byte pre-shared key, then the same tunnel as a call ---- */
typedef struct npf_direct npf_direct;
/* Listens on "ADDR:PORT" or "[IPv6]:PORT" (an address; PORT alone: every
 * IPv4 address); psk is copied and wiped at close. policy: the target
 * policy of its sessions (kept, not owned). NULL on failure. */
npf_direct *npf_direct_listen(npf_node *n, const char *spec, const uint8_t psk[32], struct npf_policy *policy);
/* Ends its sessions and closes it; NULL is ignored. */
void        npf_direct_close(npf_direct *d);
/* Connects to a listener from the node's main socket of to's family; the
 * call reports its states like any other. NULL on failure (no such socket). */
npf_call   *npf_direct_connect(npf_node *n, const struct sockaddr_storage *to, const uint8_t psk[32]);
/* The pre-shared key from key (Base64url of 32 bytes) or, key NULL, from file;
 * on POSIX a file open to group or others is refused. 0, or -1 (logged). */
int         npf_direct_psk(const char *key, const char *file, uint8_t psk[32]);
/* A new random key as Base64url: 43 characters and a NUL. */
void        npf_direct_genpsk(char out[44]);
/* Caller: a reverse mapping (data-channel.md 7.1, 15): the callee listens on
 * bind_addr:port (0: it picks, if its resources allow) and its connections
 * (udp: datagrams) come back to host:hostport here. fn gets the port and
 * listen_id, or port -1 with err, once. 0, or -1 when the request is not sent. */
typedef void (*npf_rev_fn)(npf_call *c, int port, uint32_t listen_id, const char *err, void *arg);
int  npf_call_reverse(npf_call *c, const char *bind_addr, int port, const char *host, uint16_t hostport, int udp,
                      npf_rev_fn fn, void *arg);
/* Caller: ends a reverse mapping; the callee closes its listener. */
void npf_call_reverse_close(npf_call *c, uint32_t listen_id);
/* how the session was admitted: NPF_AUTH_* */
int  npf_call_auth(const npf_call *c);
/* Ends the call: close to the peer, call_end to the platform, the state
 * NPF_CALL_CLOSED at once; c is freed on a later loop turn. */
void npf_call_end(npf_call *c, const char *reason);
/* Ends every call (shutdown); run the loop a moment after so the ends go out. */
void npf_node_end_calls(npf_node *n, const char *reason);
/* Main UDP socket fd failed: the calls on it end and nothing sends on it any more. */
void npf_node_calls_lost_fd(npf_node *n, int fd, const char *reason);
/* The network may have changed: direct paths in use are checked, the relay meanwhile. */
void npf_node_check_paths(npf_node *n, const char *why);
/* The NAT was measured again: each accepted platform call without a direct
 * or WS path sends punch_update with this side's profile and candidates;
 * the platform decides whether a round follows. */
void node_calls_punch_report(npf_node *n, const char *why);
/* Callee: closes the reverse mappings the published resources no longer allow. */
void npf_node_reverse_recheck(npf_node *n);
/* The node's UDP works again (or tests: gone or back): every session chooses its path again. */
void npf_node_calls_decide(npf_node *n);
/* The network the UDP sockets use changed (a VPN came or went): both are
 * opened again as when they fail (their calls end and reconnect). 0: they
 * reopen and the network check after it calls hooks.on_net_change; -1:
 * nothing reopens here (no socket, or cfg.udp_on_demand: no check follows). */
int  npf_node_udp_reset(npf_node *n, const char *why);
/* Caller: a local TCP connection becomes a sublink, in rate group group (0
 * none), as npf_tunnel_open_rated: its id (> 0), or -1 (the caller keeps fd). */
int  npf_call_open(npf_call *c, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                   uint32_t rate);
/* fn is called when a sublink of c ends, with the bytes read from / written
 * to it (st NULL: none); also while c is freed, so clear it before arg goes. */
struct npf_sublink_stats;
typedef void (*npf_sublink_fn)(npf_call *c, uint32_t id, const struct npf_sublink_stats *st, void *arg);
void npf_call_on_sublink_done(npf_call *c, npf_sublink_fn fn, void *arg);
/* the sublinks open in a rate group; 0 without a tunnel */
int  npf_call_group_count(const npf_call *c, uint32_t group);
/* Resets a rate group's sublinks (a public mapping turned off): how many. */
int  npf_call_group_reset(npf_call *c, uint32_t group, const char *why);
/* npf_tunnel_sub_bytes, npf_tunnel_sub_reset; -1 without a tunnel */
int  npf_call_sub_bytes(npf_call *c, uint32_t sid, uint64_t *in, uint64_t *out);
int  npf_call_sub_reset(npf_call *c, uint32_t sid, const char *why);
/* Caller: the bytes its forwarded connections moved since the last call,
 * read from them (tx, to the peer) and written to them (rx); a hosted
 * client's usage report, the same bytes its quota counts. */
void npf_call_usage_take(npf_call *c, uint64_t *tx, uint64_t *rx);
/* NPF_CALL_*, 0 before calling */
int  npf_call_state(const npf_call *c);
/* debugging: the calls, AnLiu and tunnel state to stderr */
void npf_node_dump(npf_node *n);
/* The path the session sends on, for JSON and logs: "p2p", "relay",
 * "relay (binding)", "ws relay", "direct", "none". Static string. */
const char *npf_call_path(const npf_call *c);
/* The path for people: "P2P", "Relayed" (UDP or WS relay, also while it is
 * set up), "Direct", "none". Static string. */
const char *npf_call_path_label(const npf_call *c);

/* a call's state for status (npf_call_info_get); its strings live as long as the call */
typedef struct npf_call_info {
    char     id[32];
    int      caller, direct, state;
    uint64_t number;                /* the other side's number; 0 for clients and direct sessions */
    uint8_t  peer_pub[32];          /* zero until the handshake */
    const char *path;               /* npf_call_path */
    int      path_code;             /* npf.h's NPF_PATH_*, 0 none */
    struct sockaddr_storage p2p_addr;
    int      has_p2p_addr;
    int64_t  up_s;                  /* seconds since established, -1 not yet */
    uint64_t tx_bytes, rx_bytes;    /* through the tunnel */
    int      srtt_ms;               /* AnLiu's smoothed RTT, -1 none */
    uint32_t retrans;
    int      sublinks;              /* open forwarded connections */
    int      udp_flows;             /* UDP forwards' flows (data-channel.md 15) */
    uint64_t udp_out, udp_in;       /* datagrams sent to / received from the peer */
    uint64_t udp_dropped, udp_split;/* not sent (backlog, no flow); sent in more than one AnLiu segment */
    const char *app;                /* callee: the caller's program ("name ver"), "" unknown */
    int      hosted;                /* callee: the caller is a hosted client (a public mapping) */
} npf_call_info;
void npf_call_info_get(const npf_call *c, npf_call_info *i);
/* Caller, a UDP forward: a datagram from src on the forward's socket lfd for
 * host:port on the peer's side; replies go to src on lfd. 0, or -1 when
 * dropped (no session up: the caller queues it). */
int  npf_call_udp_send(npf_call *c, int lfd, const struct sockaddr_storage *src, socklen_t srclen, const char *host,
                       uint16_t port, const uint8_t *buf, size_t len);
/* The forward's socket lfd closes: its flows end. */
void npf_call_udp_forget(npf_call *c, int lfd);
/* Caller, a module's kind of forward (npf_fwd_kind): a connection with a
 * virtual local end (npf_tunnel_open_v; *tun gets the tunnel), a datagram
 * of a virtual UDP flow identified by key (npf_udpf_send_v); -1 when the
 * call is not up. npf_node_udp_forget_v ends key's flows in every call. */
struct npf_vend_io;
struct npf_tunnel;
int  npf_call_open_v(npf_call *c, const struct npf_vend_io *v, void *varg, const char *host, uint16_t port,
                     struct npf_tunnel **tun);
int  npf_call_udp_send_v(npf_call *c, void *key, void (*deliver)(void *key, const uint8_t *buf, size_t len),
                         const char *host, uint16_t port, const uint8_t *buf, size_t len);
void npf_node_udp_forget_v(npf_node *n, const void *key);
/* 1 when connections and datagrams may go in (established, tunnel ready); c may be NULL */
int  npf_call_ready(const npf_call *c);
/* the node's calls, newest first (npf_call_next walks on); closed ones stay
 * listed until freed on a later loop turn */
npf_call *npf_node_calls(npf_node *n);
/* the hard-side sockets all punches may hold together (cfg.punch_sockets or the default) */
int npf_node_punch_budget(const npf_node *n);
npf_call *npf_call_next(const npf_call *c);

/* a callee's session, as npf_node_end_callers shows it */
typedef struct npf_caller {
    const uint8_t *pub;             /* the caller's key */
    int            auth;            /* NPF_AUTH_* */
    uint64_t       grant_account;   /* NPF_AUTH_GRANT: the grant's account and issue time */
    uint32_t       grant_issued;
} npf_caller;
/* Callee: ends each platform session, past its handshake, for which drop
 * returns nonzero (direct sessions are not asked). */
void npf_node_end_callers(npf_node *n, int (*drop)(const npf_caller *who, void *arg), void *arg);
/* Sets up n (cfg, id, hooks copied): loads the server list and, unless
 * cfg.udp_on_demand, opens the main UDP sockets. 0, or -1 (logged): no server
 * list or no socket. Nothing is connected until npf_node_start. */
int  npf_node_init(npf_node *n, npf_loop *loop, const npf_node_cfg *cfg, const npf_identity *id,
                   const npf_node_hooks *hooks, void *arg);
/* Starts the network watch and, with a platform, port mapping and signaling. */
void npf_node_start(npf_node *n);
/* cfg.sig_idle_ms: connects again now if the connection was closed for want
 * of use (why: for the log). 1 when it connects, 0 when it was not closed. */
int  npf_node_wake(npf_node *n, const char *why);
/* UDP signaling for the status (signaling-udp.md 10.1): "ok", "no_answer"
 * (it did not answer, the WebSocket is used), "off" (not for this program,
 * build or server) */
const char *npf_node_udp_sig(const npf_node *n);
/* cfg.udp_on_demand: opens the main sockets now. 0, or -1 (logged). */
int  npf_node_udp_open(npf_node *n);
/* May a session start now? 1 yes (also when it has to go without UDP); 0:
 * the main socket's NAT profile is being measured and n->on_udp_ready(n,
 * hook_arg) follows. */
int  npf_node_udp_ready(npf_node *n);
/* the signaling connection in use (logging in or logged in), NULL none */
static inline npf_sig *node_sig(const npf_node *n) { return n->sc.c[SR_MAIN].s; }
/* Frees the calls and closes everything npf_node_start and npf_node_init
 * opened; pending requests get their callbacks with e NULL. */
void npf_node_stop(npf_node *n);

/* Sends a signaling message; the envelope (v, type, id) is added and
 * data_json is the data object (NULL {}). The text is wiped after sending.
 * request: 0 an event, 1 a request, NPF_REQ_APP an application's request
 * (envelope "app": the platform takes only its platform requests so).
 * Returns the request id (> 0) for a request, 0 for an event, -1 when not
 * connected or it does not fit. */
enum { NPF_REQ_APP = 2 };
int  npf_node_send(npf_node *n, const char *type, int request, const char *data_json);
int  npf_node_reply(npf_node *n, const char *type, const char *reply_to, const char *status,
                    const char *error, const char *data_json);
/* A request with a reply callback: fn gets the reply once, or e NULL when
 * the connection is lost or the node stops first. 0, or -1 (not sent: not
 * connected, or NPF_PENDING_MAX requests waiting). */
int  npf_node_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg);
/* npf_node_request as NPF_REQ_APP (npf_request) */
int  npf_node_app_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg);
/* Forgets the waiting requests with callback argument arg: their callbacks never come. */
void npf_node_cancel_requests(npf_node *n, void *arg);

/* Reports a call's end to the platform (call_end): kept until the platform
 * answers, and while signaling is down sent after the next login with how
 * long ago it ended. peer: the peer ended the session. At most NPF_ENDS_MAX
 * wait: when full, the oldest unsent one is replaced, or with every one
 * already sent this one is dropped. */
void npf_node_call_end(npf_node *n, const char *call_id, const char *reason, int peer);

/* the platform's time in Unix ms (the wall clock corrected at login) */
int64_t npf_node_time(const npf_node *n);
/* The next wait of a doubling backoff in ms: *cur becomes first the first
 * time, then doubles up to max; the result has +-25 % jitter. */
int     npf_backoff(int *cur, int first, int max);

/* Parses a server list's payload into out (NPF_MAX_SERVERS entries), its
 * serial and meta: the number of servers, or -1 (logged). */
int npf_serverlist_parse(const char *json, size_t len, npf_server_entry *out, int64_t *serial, npf_list_meta *meta);

/* Write the "nat" object and the "cand" array into an open JSON object;
 * connect_mode secure: no addresses. */
void npf_node_write_nat(npf_node *n, npf_out *w);
void npf_node_write_cands(npf_node *n, npf_out *w);
/* A callable node online: sends nat_report with the NAT profile. */
void npf_node_report_nat(npf_node *n);
/* Writes the spare allocation's status as a JSON object: 1, or 0 (nothing
 * written) when there is none. */
int npf_node_home_status(npf_node *n, npf_out *o);
/* connect_mode: 0 p2p (direct paths first, around a VPN), 1 secure (relays
 * only, no address to the peer, the VPN kept). On a change the platform is
 * told and the UDP sockets reopen (npf_node_udp_reset). */
void npf_node_set_secure(npf_node *n, int on);


/* ---- setup helpers ---- */
struct npf_conf;
/* Fills cfg (zeroed first) from conf's platform and network keys; the
 * program sets callable, number, model, fw, app, enroll and offline.
 * Strings point into conf, which must outlive cfg. Also sets the
 * process-wide npf_udp_hook_on: on unless connect_mode is secure.
 * 0, or -1 (logged): no or bad root, or server without server_pub. */
int npf_node_cfg_from_conf(npf_node_cfg *cfg, const struct npf_conf *conf);
/* Applies conf's log_level to the log; always 0 (the key table checked it). */
int npf_conf_apply_log_level(const struct npf_conf *conf);
/* Reads a seed (Base64url of 32 bytes) from path. Only when path does not
 * exist and create is set, writes a new random one (mode 0600); a file that
 * exists but cannot be read is never replaced. 0, -1. */
int npf_seed_file(const char *path, uint8_t seed[32], int create);
/* A node number from "123 456 789" (spaces and '-' ignored): 9 digits, no
 * leading 0, a valid Damm check digit; 0 otherwise. */
uint64_t npf_number_parse(const char *s);
/* A platform error reply j (NULL: none came) for people: "CODE: meaning",
 * or "CODE (REASON): meaning" with the reply's reason; the code and reason
 * stay first so a console can translate them (signaling.md "错误"). */
void npf_platform_err(const npf_json *j, char *buf, size_t cap);

#endif

/* Node runtime shared by the device daemon and the client (security.md 7, 8.5;
 * signaling.md "接入与服务器列表").
 *
 * One npf_node owns: the event loop hooks, the identity, the signed server
 * list, the signaling connection (with login, reconnection and keepalive), the
 * main UDP socket (AnLiu, relay, punching and NAT probing share it) and the
 * calls. A callable node (NAS device, console node) logs in with role "node";
 * a pure client with role "client". */
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

#define NPF_MAX_SERVERS   32
#define NPF_MAX_ROOTS     2
#define NPF_MAX_CANDS     16

/* the rest of a list (security.md 7.5): expiry, full or seed, and the
 * external channels that deliver it */
#define NPF_SOURCES_MAX 4
typedef struct npf_list_meta {
    int64_t expires;                            /* Unix s, 0 none */
    int     full;                               /* 0: a seed list (DNS) */
    char    doh[NPF_SOURCES_MAX][128];          /* names with the seed in TXT records */
    int     ndoh;
    char    https[NPF_SOURCES_MAX][256];        /* static files with the full list */
    int     nhttps;
} npf_list_meta;

typedef struct npf_server_entry {
    int      id;
    int      prio, weight;
    int      cdn;
    char     ws[2][256];
    int      nws;
    uint8_t  dh_pub[32];
    int      relay;
    int      fails;
    int64_t  degraded_until;    /* monotonic ms: deprioritised after 3 failures for an hour (security.md 7.5) */
} npf_server_entry;

typedef struct npf_node npf_node;
typedef void (*npf_reply_fn)(npf_node *n, const npf_json *j, int ok, void *arg);

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

/* call states reported through on_call_state */
enum { NPF_CALL_CALLING = 1, NPF_CALL_CONNECTING, NPF_CALL_ESTABLISHED, NPF_CALL_CLOSED };

typedef void (*npf_ctl_fn)(npf_call *c, const npf_json *j, int ok, void *arg);

/* What the callee side needs from the program (device or console node). */
typedef struct npf_callee_ops {
    int  (*authorized)(npf_node *n, const uint8_t caller_pub[32], void *arg);
    /* current pairing password, NULL = pairing disabled */
    const char *(*password)(npf_node *n, void *arg);
    /* Unix seconds until which password pairing is locked, 0 = not locked */
    int64_t (*locked_until)(npf_node *n, void *arg);
    void (*paired)(npf_node *n, const uint8_t caller_pub[32], void *arg);
    void (*pair_failed)(npf_node *n, void *arg);
    /* hosted trust: verify a grant for this caller key; 0 and the account
     * and the grant (out: its targets point into grant), or -1 */
    int  (*grant_check)(npf_node *n, const uint8_t *grant, size_t len, const uint8_t caller_pub[32],
                        uint64_t *account, npf_grant *out, void *arg);
    /* revoke{account, before, owner} from the platform */
    void (*revoke)(npf_node *n, uint64_t account, int64_t before, int owner, void *arg);
    void (*bind_committed)(npf_node *n, uint64_t account, const uint8_t op[16], void *arg);
    /* control requests from a caller inside the tunnel (bind_approve ...) */
    void (*control)(npf_node *n, npf_call *c, const npf_json *j, void *arg);
    struct npf_policy *policy;
} npf_callee_ops;

/* callbacks into the program (device or client main) */
typedef struct npf_node_hooks {
    void (*on_login)(npf_node *n, void *arg);                       /* welcome received */
    /* why: the reason of a CLOSED state, valid only during the callback */
    void (*on_call_state)(npf_node *n, npf_call *c, int state, const char *why, void *arg);
    /* caller: first pairing succeeded, pin this key for the number */
    void (*on_paired)(npf_node *n, uint64_t number, const uint8_t callee_pub[32], void *arg);
    /* another event from the platform (mappings_changed, devices_changed ...); d: its data */
    void (*on_event)(npf_node *n, const char *type, const npf_json *j, int d, void *arg);
    /* one key per model: the platform gave this identity a number (cfg.number
     * and the certificate n->cert are set); the node logs in next */
    void (*on_enrolled)(npf_node *n, uint64_t number, void *arg);
    /* libnpf: the application's data from a session's peer (control channel) */
    void (*on_app_data)(npf_node *n, npf_call *c, const uint8_t *buf, size_t len, void *arg);
    /* libnpf: the peer opened media stream (its number in the session; tag:
     * the application's): 1 takes it */
    int  (*on_media_open)(npf_node *n, npf_call *c, uint32_t media, int tag, void *arg);
    void (*on_media_frame)(npf_node *n, npf_call *c, uint32_t media, const uint8_t *buf, size_t len,
                           uint32_t frame_no, int flags, uint32_t lost_before, void *arg);
    /* a media stream ended from the other side (closed or refused there) */
    void (*on_media_closed)(npf_node *n, npf_call *c, uint32_t media, void *arg);
    /* signaling on demand: nonzero while the application needs the connection */
    int  (*busy)(npf_node *n, void *arg);
    /* caller: the callee published its resources (control event "resources",
     * resources.h); d: the event's data */
    void (*on_resources)(npf_node *n, npf_call *c, const npf_json *j, int d, void *arg);
    /* the process was suspended or the addresses changed (why): whatever
     * waits to reconnect may try at once */
    void (*on_net_change)(npf_node *n, const char *why, void *arg);
    /* one key per model: the platform refused the enrolment (error, and the
     * reason of signaling.md "enroll", "" from an older server); the
     * node tries again in about retry_s seconds */
    void (*on_enroll_failed)(npf_node *n, const char *error, const char *reason, int retry_s, void *arg);
    /* the signaling connection was lost after a login (why); it logs in again by itself */
    void (*on_offline)(npf_node *n, const char *why, void *arg);
} npf_node_hooks;

/* npf_node.enroll_state */
enum { NPF_ENROLL_NONE, NPF_ENROLL_SENT, NPF_ENROLL_DONE, NPF_ENROLL_REFUSED };

/* one key per model (security.md 4.1, 5.2): what enrol sends before the
 * first login of an identity without a number */
typedef struct npf_enroll_req {
    uint8_t model_chain[1024];      /* the credential's vendor and model certificates */
    size_t  model_chain_len;
    uint8_t model_sk[64];           /* the model key (from the credential's vendor_seed) */
    char    serial[65];             /* the vendor's serial number of the device (or one from its hardware) */
    int     nhw;                    /* the hardware fingerprint's items (security.md 5.2), sorted by kind */
    char    hw_kind[8][16];
    uint8_t hw_hash[8][16];         /* BLAKE2b(key = model_seed, "npf hwfp v2" | kind | 0 | value)[0..15] */
    uint8_t hw_fp[32];              /* their digest, what the enrolment signs */
} npf_enroll_req;

typedef struct npf_node_cfg {
    int         callable;           /* login as role "node" */
    uint64_t    number;             /* node number (callable) */
    const char *model, *fw;         /* a node's (fw: the version of npf) */
    const char *app_name, *app_ver; /* the program (login "app") */
    uint8_t     roots[NPF_MAX_ROOTS][32];
    int         nroots;
    const char *serverlist_builtin; /* signed blob shipped with the program */
    const char *serverlist_saved;   /* where updates are stored */
    const char *doh_servers;        /* tests: "IP:PORT=HOST,..." instead of the public DoH services */
    const char *server_url;         /* optional override: one URL ... */
    uint8_t     server_pub[32];     /* ... with this Noise key (tests) */
    int         udp_port;           /* 0 = any */
    int         offline;            /* no platform: no server list, no signaling (direct mode) */
    int         max_calls;          /* callee: concurrent platform sessions, 0 = 32 (busy beyond) */
    int         punch_lead_ms;      /* start punching this much before start_at; -1 = automatic (macOS
                                       application firewall on: 300), 0 = on time */
    int         no_host_report;     /* report_host = 0: no host details in login */
    int         punch_sockets;      /* S3 hard-side sockets of all concurrent punches, 0 = automatic
                                       (npf_node_punch_budget) */
    const npf_enroll_req *enroll;   /* number 0: enrol first, then log in as the node */
    int         no_portmap;         /* portmap = 0: no PCP / NAT-PMP mapping on the router */
    int         secure;             /* connect_mode secure: relays only, no address to peers, a VPN
                                       kept (npf_node_set_secure at run time) */
    /* npf-hosted (security.md 8.4): hosted_service = 1 logs in as the hosted
     * service itself (login role "hosted"); hosted_exec = ID makes this the
     * hosted client of service ID: it executes the account's public mappings */
    int         hosted_service;
    uint64_t    hosted_exec;
    /* signaling on demand (hosted clients): after this long with nothing
     * that needs it (no session, no request, hooks.busy says no) the
     * connection closes; npf_node_wake opens it again, and so does a timer
     * every sig_wake_ms (0: none). 0: always connected */
    int         sig_idle_ms;
    int         sig_wake_ms;
    /* UDP on demand (hosted clients with sig_idle_ms): no UDP socket until a
     * session needs one (npf_node_udp_ready); closed again with the
     * signaling connection when no session is left. udp_public: the
     * operator says the address is public with no translation: a socket
     * opened again takes the last probe's address with its new port, when
     * that probe found the port kept (nat_kept_port); otherwise sessions
     * wait for a probe of the new socket's mapping (the NAT's port
     * allocation, a property of the NAT, kept from the full probe) */
    int         udp_on_demand;
    int         udp_public;
} npf_node_cfg;

/* a call_end waiting for the platform's answer (npf_node_call_end) */
#define NPF_ENDS_MAX 32
typedef struct npf_end_report {
    char    call_id[32];
    char    reason[24];
    int64_t at_ms;                      /* monotonic: when the session ended */
    int     state;                      /* 0 free, 1 to send, 2 sent */
} npf_end_report;

struct npf_node {
    npf_loop     *loop;
    npf_node_cfg  cfg;
    struct npf_budget *budget;      /* a hosted client's quota: every tunnel spends it (npf/tunnel.h) */
    npf_node_hooks hooks;
    void         *hook_arg;
    /* a peer's candidate of no use here, not punched (a module's: one this
     * host would send into a virtual interface of its own); shown and
     * call_id for its log; optional */
    int         (*skip_cand)(void *arg, const struct sockaddr_storage *to, const char *shown, const char *call_id);
    void         *skip_cand_arg;
    npf_identity  id;

    /* certificates (raw "inter | leaf" chains) */
    uint8_t       cert[1024];
    size_t        cert_len;
    uint8_t       account_cert[1024];
    size_t        account_cert_len;
    void        (*on_cert)(npf_node *n, void *arg);   /* a (re)issued node certificate arrived */
    void         *on_cert_arg;
    void        (*on_account_cert)(npf_node *n, void *arg);   /* a renewed account certificate */
    void         *on_account_cert_arg;

    /* server list */
    npf_server_entry *servers;      /* where to connect: nservers (allocated, at most NPF_MAX_SERVERS) */
    int           nservers;
    npf_server_entry *list;         /* the whole verified list (relay keys by server_id): nlist */
    int           nlist;
    int64_t       sl_serial;
    int64_t       sl_full_serial;   /* of the full list kept on disk (login reports it) */
    npf_list_meta sl_meta;          /* of the list in use */
    /* external channels of the server list (sources.c) */
    int64_t       unreachable_since;/* monotonic ms: no server reached since; 0 = online */
    int64_t       src_next;         /* monotonic ms: no round before */
    int           src_backoff;      /* ms */
    void         *src_req[2 * NPF_SOURCES_MAX * 2];    /* requests in flight (sources.c) */
    int           nsrc_req;
    int           cur_server;       /* index into servers, -1 none */

    /* signaling */
    npf_sig      *sig;
    npf_sig      *race;             /* a second access point tried at the same time (security.md 7.5) */
    int           race_server;      /* its index into servers */
    int           online;           /* welcome received */
    /* counters for status */
    int64_t       started_unix_ms;  /* npf_node_init (wall clock) */
    int64_t       started_mono_ms;
    int64_t       last_login_unix_ms;   /* the last welcome, 0 none */
    int           logins;           /* welcomes since the start: logins - 1 are logins again */
    int           calls_out, calls_in;  /* sessions started / incoming calls (platform and direct) */
    int           backoff_ms;
    int           replaced;             /* the platform said this identity logged in elsewhere (replaced) */
    int           replaced_backoff_ms;  /* the wait after that, 10 s doubling to 5 min (two processes of one
                                           identity would push each other off every second) */
    /* one key per model: the last enrolment (status "enroll") */
    int           enroll_state;     /* NPF_ENROLL_* */
    char          enroll_error[32], enroll_reason[24];
    int64_t       enroll_at_unix_ms;
    npf_timer    *t_reconnect, *t_ping;
    npf_timer    *t_expect;         /* something from the server is due (node.c sig_expect) */
    int64_t       expect_since;     /* ... since then (monotonic ms) */
    int           expect_probed;    /* ... and a ping asked for it already */
    int           sig_via_vpn;      /* signaling through a VPN: going around it did not log in */
    npf_timer    *t_login;          /* a connection attempt must reach welcome in time */
    /* signaling on demand (cfg.sig_idle_ms) */
    int           dormant;          /* closed for want of use: no reconnect until npf_node_wake */
    int64_t       busy_at;          /* monotonic: the last time something needed the connection */
    npf_timer    *t_idle, *t_wake;
    int           sleeps;           /* times it went dormant */
    int           req_seq;
    npf_pending   pending[NPF_PENDING_MAX];
    npf_end_report ends[NPF_ENDS_MAX];  /* call_end reports not answered yet */
    uint64_t      account_id;       /* account session of this connection, 0 = none */
    void        (*on_account_lost)(npf_node *n, void *arg);   /* session certificate rejected */
    int           server_id;
    uint64_t      client_id;
    int64_t       clock_offset_ms;  /* server time - local wall clock */
    int64_t       login_sent_ms;    /* monotonic, for the offset's transit correction */
    uint8_t       ticket[28];
    npf_daykey    probe_keys[2], relay_keys[2];
    struct sockaddr_in probe_ep[3]; /* the address probes the server named: E1, E2 [, E3] (nat-traversal.md 4.1) */
    int           nprobe_ep;
    int           ping_s;
    int           punch_lead_ms;    /* effective lead of punching (cfg.punch_lead_ms resolved) */
    int           punch_budget;     /* default S3 socket budget: 1024, at most half the descriptor limit */
    int64_t       hard_punch_end;   /* when a hard-side punch last gave its sockets back (monotonic ms), 0: none */
    npf_timer    *t_punch_gap;      /* the next hard-side punch once the gap after it is over */

    /* UDP */
    int           udp_fd;
    uint16_t      udp_port;
    int64_t       test_cut_ms;      /* NPF_TEST_DROP_P2P (call.c), read once per node */
    const char   *test_block_relay; /* NPF_TEST_BLOCK_RELAY (call.c), read once: not at each relayed datagram */
    struct npf_call *relay_hit;     /* the call the last relayed datagram was for: tried first */
    int           test_cut_port;
    int           udp6_fd;          /* IPv6 main socket (S0, host6 candidates), -1 when the host has no IPv6 */
    uint16_t      pred_port;        /* sequential allocation: the next new mapping's port (the "pred" candidate) */
    /* the router's port mapping (nodemap.c) */
    struct npf_portmap pm;
    int           pm_ok, pm_tried;
    void         *pm_job;
    npf_timer    *t_pm;
    uint16_t      udp6_port;
    npf_nat_profile nat;
    int           nat_valid;
    int           nat_udp;          /* probe servers answered */
    struct npf_natprobe *probe;     /* a NAT probe running on the loop */
    int           login_waits_nat;  /* hooks.on_login after the first profile */
    int           nat_kept_port;    /* the last probe: the mapping kept the port, and it is endpoint-
                                       independent or the address is on a local interface (no NAT) */
    int           nat_quick;        /* the next probe: the socket's mapping only (a reopened socket);
                                       the port allocation stays the NAT's, from the full probe */
    int           udp_waiters;      /* cfg.udp_on_demand: sessions wait for the profile (on_udp_ready) */
    npf_timer    *t_udp_reopen;     /* a main socket failed: reopened on the loop */
    npf_timer    *t_nat_retry;      /* a NAT probe without an answer: again soon (nat.c) */
    int           nat_retries;
    /* the network watch (node.c): a suspended process (iOS, a laptop's
     * sleep) or other addresses: the connections are checked at once */
    npf_timer    *t_watch, *t_netcheck;
    int64_t       watch_boot_ms;    /* npf_boot_ms of the last tick */
    uint32_t      watch_addrs;      /* digest of the interfaces' addresses, 0 not yet */
    int64_t       netcheck_ms;      /* monotonic: the signaling ping of a check went out */
    int           netchecks;        /* checks since the start (status) */
    int           repunch_on_nat;   /* a network check: the relayed calls punch again once the NAT is measured */
    void        (*on_udp_ready)(npf_node *n, void *arg);
    struct sockaddr_in srflx;
    struct in_addr pub_ip;
    npf_cand      cands[NPF_MAX_CANDS];
    int           ncands;

    npf_call     *calls;
    npf_call     *conv_tab[256];    /* calls with an AnLiu connection, by conv (datagram demux) */
    const npf_callee_ops *callee;   /* callable nodes */
    void         *callee_arg;
    const uint8_t *pending_grant;   /* npf_call_start_grant -> npf_call_start */
    size_t        pending_grant_len;
    void         *app;              /* device / client state */
};

/* ---- calls (call.c) ---- */

/* Caller: start a call. password != NULL: first pairing (CPace + XXpsk3);
 * otherwise pinned is the callee's static key from an earlier pairing (IK). */
npf_call *npf_call_start(npf_node *n, uint64_t number, const char *password, const uint8_t pinned[32]);
/* Caller with hosted trust: the callee certificate chain and grant come from grant_get. */
npf_call *npf_call_start_grant(npf_node *n, uint64_t number, const uint8_t *chain, size_t chain_len,
                               const uint8_t *grant, size_t grant_len);
/* control messages inside the tunnel (sublink 0) */
int  npf_call_ctl_request(npf_call *c, const char *type, const char *data_json, npf_ctl_fn fn, void *arg);
/* a control event (no reply): {"v":1,"type":TYPE,"data":DATA}; 0, or -1 when
 * the tunnel is not up or it does not fit (NPF_CTRL_MAX) */
int  npf_call_ctl_event(npf_call *c, const char *type, const char *data_json);

/* ---- libnpf: application data and media streams of an established session ---- */

/* data on the tunnel's control channel (<= 16384 bytes): 0 or -1 (not up) */
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

/* the values of npf.h's NPF_E* */
enum { NPF_CALL_ENOENT = -2, NPF_CALL_ESTATE = -3, NPF_CALL_EUNAVAIL = -4, NPF_CALL_ETOOBIG = -5, NPF_CALL_ENOMEM = -6,
       NPF_CALL_EBUSY = -8 };

/* a media stream to the peer (direct path, UDP or WS relay; media.h): its
 * number in the session, or 0 with *err (NPF_CALL_ESTATE before the session
 * is up, NPF_CALL_EBUSY with too many at once). The others: 0 or NPF_CALL_E* */
uint32_t npf_call_media_open(npf_call *c, const npf_call_media_opt *o, int *err);
/* t_submit: when the application gave it (npf_mono_ms); max_age counts from there */
int      npf_call_media_send(npf_call *c, uint32_t media, int flags, const void *buf, size_t len, int64_t t_submit);
int      npf_call_media_get_stats(npf_call *c, uint32_t media, npf_call_media_stats *out);
int      npf_call_media_close(npf_call *c, uint32_t media);
int  npf_call_ctl_reply(npf_call *c, const char *type, const npf_json *req, const char *status, const char *error,
                        const char *data_json);
enum { NPF_AUTH_IK = 1, NPF_AUTH_PAKE, NPF_AUTH_GRANT, NPF_AUTH_DIRECT };

/* ---- direct connections (no platform): Noise_NNpsk0 over UDP, then the same
 * AnLiu tunnel as a call. The listener sets a 32-byte pre-shared key. ---- */
typedef struct npf_direct npf_direct;
/* listen on "[addr:]port" with psk; policy = target policy of its sessions */
npf_direct *npf_direct_listen(npf_node *n, const char *spec, const uint8_t psk[32], struct npf_policy *policy);
void        npf_direct_close(npf_direct *d);
/* connect to a listener; the call reports its states like any other call */
npf_call   *npf_direct_connect(npf_node *n, const struct sockaddr_storage *to, const uint8_t psk[32]);
/* "HOST:PORT" -> IPv4 address (synchronous lookup) */
int         npf_direct_resolve(const char *spec, struct sockaddr_storage *out);
/* the key: given as text (key != NULL) or read from a file; Base64url of 32
 * bytes. A key file readable by group or others is refused. */
int         npf_direct_psk(const char *key, const char *file, uint8_t psk[32]);
/* new random key as Base64url text (43 characters + NUL) */
void        npf_direct_genpsk(char out[44]);
/* caller: reverse mapping (data-channel.md 7.1): the callee listens on
 * bind:port and connections come back to host:hostport here (udp: datagrams,
 * data-channel.md 15). fn gets the port the callee listens on, or -1 and the error. */
typedef void (*npf_rev_fn)(npf_call *c, int port, uint32_t listen_id, const char *err, void *arg);
int  npf_call_reverse(npf_call *c, const char *bind_addr, int port, const char *host, uint16_t hostport, int udp,
                      npf_rev_fn fn, void *arg);
/* caller: end a reverse mapping (the callee closes its listener) */
void npf_call_reverse_close(npf_call *c, uint32_t listen_id);
int  npf_call_auth(const npf_call *c);
uint64_t npf_call_grant_account(const npf_call *c);
/* end a call (sends close / call_end) */
void npf_call_end(npf_call *c, const char *reason);
/* end every call of the node (shutdown); the loop must run a moment afterwards */
void npf_node_end_calls(npf_node *n, const char *reason);
/* a main UDP socket (fd) failed and is replaced: the calls on it end and
 * none sends on the old descriptor any more */
void npf_node_calls_lost_fd(npf_node *n, int fd, const char *reason);
/* the network may have changed: the direct paths in use are checked both
 * ways (with the relay meanwhile), as when they fall silent */
void npf_node_check_paths(npf_node *n, const char *why);
/* the network changed: each call this side made that is on the UDP relay
 * punches again now (call.c; within its rounds) */
void npf_node_repunch_now(npf_node *n);
/* the published resources changed: reverse-mapping listeners they no longer
 * allow are closed (call.c) */
void npf_node_reverse_recheck(npf_node *n);
/* UDP works again after a NAT probe without an answer: the calls this side
 * made on the WS relay end, their peers reconnect over UDP (call.c) */
void npf_node_ws_calls_udp_back(npf_node *n);
/* the network the UDP sockets go out on changed (an app: a VPN came or went):
 * both are opened again, as when they fail (their calls end and reconnect) */
void npf_node_udp_reset(npf_node *n, const char *why);
/* caller: a local TCP connection becomes a sublink (see npf_tunnel_open) */
/* a forwarded connection in the session: its id (> 0), or -1 */
int  npf_call_open(npf_call *c, int fd, int passthrough, const char *host, uint16_t port);
/* the same in a rate group (npf_tunnel_open_rated) */
int  npf_call_open_rated(npf_call *c, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                         uint32_t rate);
/* a connection opened with npf_call_open* (its id, what it returned) ended:
 * the bytes read from / written to it; NULL: none. Also while the call is
 * being freed (its tunnel goes): clear it before what arg points to goes */
struct npf_sublink_stats;
typedef void (*npf_sublink_fn)(npf_call *c, uint32_t id, const struct npf_sublink_stats *st, void *arg);
void npf_call_on_sublink_done(npf_call *c, npf_sublink_fn fn, void *arg);
/* the sublinks open in a group of the call's tunnel */
int  npf_call_group_count(const npf_call *c, uint32_t group);
/* resets the connections of a group (a public mapping turned off) */
int  npf_call_group_reset(npf_call *c, uint32_t group, const char *why);
/* caller: the bytes its forwarded connections moved since the last call:
 * read from them (up, to the peer) and written to them (down); a hosted
 * client's usage_report, the same bytes as its quota budget */
void npf_call_usage_take(npf_call *c, uint64_t *tx, uint64_t *rx);
int  npf_call_state(const npf_call *c);
uint64_t npf_call_peer(const npf_call *c);
/* debugging: calls, AnLiu and tunnel state to stderr */
void npf_node_dump(npf_node *n);
/* "p2p" / "relay" / "none" */
const char *npf_call_path(const npf_call *c);
/* the path as shown to people: P2P, Relayed (UDP or WS relay, also while it
 * is being set up), Direct (npf listen / connect HOST:PORT); npf_call_path
 * keeps the precise names for JSON and logs of the details */
const char *npf_call_path_label(const npf_call *c);

/* for status queries (npf status) */
typedef struct npf_call_info {
    char     id[32];
    int      caller, direct, state;
    uint64_t number;                /* the other side's number: the callee's, or a calling node's; 0 for clients and direct sessions */
    uint8_t  peer_pub[32];          /* zero until the handshake */
    const char *path;               /* npf_call_path */
    struct sockaddr_storage p2p_addr;
    int      has_p2p_addr;
    int64_t  up_s;                  /* seconds since established, -1 = not yet */
    uint64_t tx_bytes, rx_bytes;    /* through the tunnel */
    int      srtt_ms;               /* AnLiu smoothed RTT, -1 = none (WS relay) */
    uint32_t retrans;
    int      sublinks;              /* open forwarded connections */
    int      udp_flows;             /* UDP forwards' flows (data-channel.md 15) */
    uint64_t udp_out, udp_in;       /* datagrams sent to / received from the peer */
    uint64_t udp_dropped, udp_split;/* not sent (backlog, no flow); sent in more than one AnLiu segment */
    const char *app;                /* callee: the caller's program ("name ver"), "" unknown */
    int      hosted;                /* callee: the caller is a hosted client (a public mapping) */
} npf_call_info;
void npf_call_info_get(const npf_call *c, npf_call_info *i);
/* caller, a UDP forward (peers.c): a datagram from src on the forward's
 * socket lfd, for host:port there; replies go to src on lfd. 0, or -1 when
 * dropped (no session yet: the caller queues it) */
int  npf_call_udp_send(npf_call *c, int lfd, const struct sockaddr_storage *src, socklen_t srclen, const char *host,
                       uint16_t port, const uint8_t *buf, size_t len);
/* the forward's socket closes: its flows end */
void npf_call_udp_forget(npf_call *c, int lfd);
/* caller, a module's kind of forward (npf_fwd_kind): a connection with a virtual local end
 * (npf_tunnel_open_v), a datagram of a virtual UDP flow (npf_udpf_send_v);
 * a virtual flow's key goes: its flows end in every call of the node */
struct npf_vend_io;
struct npf_tunnel;
int  npf_call_open_v(npf_call *c, const struct npf_vend_io *v, void *varg, const char *host, uint16_t port,
                     struct npf_tunnel **tun);
int  npf_call_udp_send_v(npf_call *c, void *key, void (*deliver)(void *key, const uint8_t *buf, size_t len),
                         const char *host, uint16_t port, const uint8_t *buf, size_t len);
void npf_node_udp_forget_v(npf_node *n, const void *key);
/* may a connection or datagram go into the call now (established, its tunnel ready)? */
int  npf_call_ready(const npf_call *c);
/* every call of the node, newest first */
npf_call *npf_node_calls(npf_node *n);
/* the S3 hard-side sockets all concurrent punches may hold (punch_sockets or the default) */
int npf_node_punch_budget(const npf_node *n);
npf_call *npf_call_next(const npf_call *c);

int  npf_node_init(npf_node *n, npf_loop *loop, const npf_node_cfg *cfg, const npf_identity *id,
                   const npf_node_hooks *hooks, void *arg);
void npf_node_start(npf_node *n);
/* signaling on demand: connect now if the connection was closed for want
 * of use (why: for the log); 0 when it is already there or on its way */
int  npf_node_wake(npf_node *n, const char *why);
/* cfg.udp_on_demand: open the main sockets now (0, -1: cannot) */
int  npf_node_udp_open(npf_node *n);
/* may a session start now? 1; 0: the main sockets' NAT profile is being
 * measured, n->on_udp_ready(n, hook_arg) when it is */
int  npf_node_udp_ready(npf_node *n);
void npf_node_stop(npf_node *n);

/* Send a signaling message built with the writer: the envelope (v, type, id)
 * is added here. data_json is the "data" object. Returns the request id (>0)
 * for requests, 0 for events, -1 on failure. */
int  npf_node_send(npf_node *n, const char *type, int request, const char *data_json);
int  npf_node_reply(npf_node *n, const char *type, const char *reply_to, const char *status,
                    const char *error, const char *data_json);
/* request with a reply callback (ok = status "ok"; j is the whole reply, NULL
 * if the connection was lost). Returns 0 or -1. */
int  npf_node_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg);
/* forget the outstanding requests whose callback argument is arg (it is going away) */
void npf_node_cancel_requests(npf_node *n, void *arg);

/* Report the end of a call to the platform (call_end, signaling.md): a
 * request kept until the platform answers; while signaling is down it waits
 * for the next login and then says how long ago the session ended. */
void npf_node_call_end(npf_node *n, const char *call_id, const char *reason);

/* server time in ms (wall clock corrected by welcome.time) */
int64_t npf_node_time(const npf_node *n);

/* Parse a server-list payload into entries; returns the count or -1. */
int npf_serverlist_parse(const char *json, size_t len, npf_server_entry *out, int max, int64_t *serial);

void npf_serverlist_meta(const char *json, size_t len, npf_list_meta *m);

/* write the "nat" and "cand" fields into an open JSON object */
struct npf_jw;
void npf_node_write_nat(npf_node *n, struct npf_jw *w);
void npf_node_write_cands(npf_node *n, struct npf_jw *w);
/* nat_report: the profile (or, connect_mode secure, only that) to the platform */
void npf_node_report_nat(npf_node *n);
/* connect_mode: 0 p2p (direct paths first, around a VPN), 1 secure (relays
 * only, no address to the peer, the VPN kept): the platform hears it, the
 * sessions open again under it */
void npf_node_set_secure(npf_node *n, int on);

/* format / parse "1.2.3.4:5" and "[::1]:5" */
int  npf_addr_parse(const char *s, struct sockaddr_storage *out);
const char *npf_addr_str(const struct sockaddr_storage *a, char *buf, size_t n);


/* ---- setup helpers (setup.c) ---- */
struct npf_conf;
/* root, serverlist, serverlist_saved, server, server_pub, udp_port, max_calls,
 * punch_lead_ms, punch_sockets. Strings point into conf, which must outlive cfg. Returns 0 or -1. */
int npf_node_cfg_from_conf(npf_node_cfg *cfg, const struct npf_conf *conf);
/* log_level = error | warn | info | debug | trace (default info): applied
 * to the log; 0, or -1 for an unknown name (the level is left as it is) */
int npf_conf_apply_log_level(const struct npf_conf *conf);
/* read a base64url seed file, or create one (mode 0600) when create is set */
int npf_seed_file(const char *path, uint8_t seed[32], int create);
/* "123 456 789" -> number with a valid Damm check digit, or 0 */
uint64_t npf_number_parse(const char *s);
/* a platform request's error reply j (NULL: none came) as people read it:
 * "CODE: what it means" or, with the reply's reason, "CODE (REASON): ...";
 * the code and reason stay first for the console, which says it in its
 * own language (signaling.md "错误") */
void npf_platform_err(const npf_json *j, char *buf, size_t cap);

#endif

/* A session's tunnel (data-channel.md 5-8): sublinks, each a SOCKS5 CONNECT
 * the other side serves, over an abstract transport (npf_tunnel_io) of
 * control units (type(1) | len(2) | body) and data messages (sublink(4) |
 * payload; an empty one is FIN). Sublink ids are odd for the caller, even
 * for the callee, never reused. Also the callee's target policy and the
 * control interface guard. All of it runs on the session's loop thread.
 * Internal to libnpf; in include/npf because npf's modules use virtual
 * local ends (tun/tun.c), the sublink stats (mappings.c) and the guard
 * (app/control.c). */
#ifndef NPF_TUNNEL_H
#define NPF_TUNNEL_H

#include <stddef.h>
#include <stdint.h>
#include "npf/sys.h"

#include "npf/json.h"
#include "npf/loop.h"

enum { NPF_CU_JSON = 1, NPF_CU_WINDOW = 2, NPF_CU_RESET = 3, NPF_CU_APP = 4, NPF_CU_UDP = 6 };
enum { NPF_RST_LOCAL = 1, NPF_RST_PROTOCOL = 2, NPF_RST_LIMIT = 3, NPF_RST_TIMEOUT = 4, NPF_RST_TRANSPORT = 5 };

#define NPF_CU_HDR        3         /* control unit header */
#define NPF_DATA_HDR      4         /* data message header */
#define NPF_FRAME_MAX     16384     /* data payload per message */
#define NPF_CTRL_MAX      16384     /* control unit body */
/* A sublink's receive window starts at NPF_INIT_WINDOW and doubles while its
 * data is taken at once, up to NPF_MAX_WINDOW; a tunnel's windows grow only
 * while their sum stays within NPF_RX_BUDGET. */
#define NPF_INIT_WINDOW   (64 * 1024)
#define NPF_MAX_WINDOW    (4 * 1024 * 1024)
#define NPF_RX_BUDGET     (32 * 1024 * 1024)
#define NPF_MAX_SUBLINKS  1024
#define NPF_MAX_REVERSE   16        /* reverse mappings per session (data-channel.md 7.1) */
#define NPF_TUNNEL_BACKLOG  (1024 * 1024)   /* default npf_tunnel_io.backlog_max */

/* A callee's target policy (security.md D22): what the published resources
 * (npf/resources.h) cover, nothing else. "lan" is this host's addresses,
 * loopback and its attached private networks (computed again every 30 s);
 * "*" is every target. An IPv4-mapped IPv6 address counts as IPv4, a
 * destination in 0.0.0.0/8 as 127.0.0.1. */
typedef struct npf_policy_rule {
    int      family;
    uint8_t  addr[16];
    int      prefix;
    uint16_t port_lo, port_hi;
} npf_policy_rule;

typedef struct npf_policy {
    npf_policy_rule rules[64];      /* TCP targets */
    int      nrules;
    int      lan;                   /* "lan" allowed (TCP) */
    int      any;                   /* "*" allowed (TCP) */
    npf_policy_rule local[64];      /* what "lan" stands for */
    int      nlocal;
    int64_t  refreshed_ms;
    /* ports a caller may have this node listen on for -R (data-channel.md
     * 7.1): on loopback, or with lan on every address; none: -R refused */
    struct { uint16_t lo, hi; uint8_t lan; } rev[16];
    int      nrev;
    /* UDP targets (data-channel.md 15); TCP's "lan" and "*" do not cover UDP */
    npf_policy_rule udp[32];
    int      nudp;
    int      udp_any;               /* "*" allowed (UDP) */
} npf_policy;

/* Allows one TCP target: ADDR[/PREFIX][:PORT[-PORT]] (IPv6 in brackets when
 * a prefix or port follows: "[::1]:80"), "lan" or "*". 0, or -1 bad or full. */
int  npf_policy_add(npf_policy *p, const char *spec);
void npf_policy_clear(npf_policy *p);       /* nothing allowed */
/* Allows -R ports: "*" (1024-65535), PORT or PORT-PORT, all at least 1024;
 * "lan:" before it: on every address. 0, or -1 bad or full. */
int  npf_policy_add_reverse(npf_policy *p, const char *spec);
/* 1 when a caller may have this node listen on port (0: one the system
 * picks, only with all of 1024-65535), on every address when lan. NULL p: 0. */
int  npf_policy_reverse_ok(const npf_policy *p, int port, int lan);
/* 1 when the address is one of what "lan" stands for (any port). */
int  npf_policy_lan_peer(npf_policy *p, const struct sockaddr *a);
void npf_policy_refresh(npf_policy *p);     /* computes "lan" from the interfaces now */
/* 1 when a TCP connection to dst is allowed; NULL p: 0. */
int  npf_policy_allowed(npf_policy *p, const struct sockaddr *dst);
/* Allows one UDP target: ADDR[/PREFIX][:PORT[-PORT]] or "*". 0, or -1 bad or full. */
int  npf_policy_add_udp(npf_policy *p, const char *spec);
int  npf_policy_udp_allowed(npf_policy *p, const struct sockaddr *dst);     /* NULL p: 0 */
/* 1 when the address is in one of the n rules, whatever their ports (an allow_from list). */
int  npf_policy_rules_match(const npf_policy_rule *r, int n, const struct sockaddr *a);

/* The control interface of this process (the web console and its API)
 * listens on a: no sublink connects to that port on this host (a loopback
 * address, a's address, or any local one when a is the any address),
 * whatever the resources, a -R or a public mapping allow; such a CONNECT
 * fails with a warning in the log. Process-wide, up to 4 addresses; call it
 * before any instance runs (no lock). */
void npf_guard_control(const struct sockaddr_storage *a);
int  npf_guard_blocked(const struct sockaddr *dst);     /* 1: dst is a guarded control interface */

typedef struct npf_tunnel npf_tunnel;

/* A sublink opened here, as it ended (npf_tunnel_io.sublink_done). */
typedef struct npf_sublink_stats {
    uint64_t    in, out;            /* bytes read from / written to its local end */
    int         connect_ms;         /* open to the other side's CONNECT reply (target reached); -1 never */
    int         first_byte_ms;      /* open to the first byte written to the local end; -1 none */
    const char *end;                /* local_closed / peer_closed (who closed first), target_failed (the
                                     * other side could not reach the target), target_refused (its policy),
                                     * peer_reset, local_reset, session_ended, greeting_timeout, or the why
                                     * of npf_tunnel_sub_reset / npf_tunnel_group_reset; a static string */
} npf_sublink_stats;

/* The transport and the owner's hooks, called on the loop thread. A hook
 * may call npf_tunnel_free; the tunnel then goes when the call into it
 * returns. */
typedef struct npf_tunnel_io {
    int    (*write_ctrl)(void *arg, const uint8_t *buf, size_t len);  /* control units (byte stream); 0 or -1 */
    int    (*write_data)(void *arg, const uint8_t *msg, size_t len);  /* one data message; 0 or -1 */
    size_t (*backlog)(void *arg);                                     /* data bytes not yet sent */
    void   (*ready)(void *arg);                                   /* both hellos exchanged */
    void   (*control)(void *arg, const npf_json *j);              /* a JSON control message other than hello */
    void   (*broken)(void *arg, const char *why);                 /* protocol violation or failed write */
    /* an NPF_CU_APP or NPF_CU_UDP unit; optional */
    void   (*unit)(void *arg, int type, const uint8_t *buf, size_t len);
    /* A CONNECT target as the peer wrote it (an address or a name): 0 refuses
     * it (REP 02). On the callee it is asked before the policy (optional);
     * on the caller it decides a reverse sublink, refused when NULL. */
    int    (*target_ok)(void *arg, const char *host, uint16_t port);
    /* a sublink opened here ended; optional */
    void   (*sublink_done)(void *arg, uint32_t id, const struct npf_sublink_stats *st);
    /* local reads pause above this backlog and resume at half; optional,
     * NULL: NPF_TUNNEL_BACKLOG */
    size_t (*backlog_max)(void *arg);
} npf_tunnel_io;

/* policy: the callee's (borrowed, outlives the tunnel), NULL on the caller.
 * NULL when out of memory. */
npf_tunnel *npf_tunnel_new(npf_loop *loop, int caller, const npf_tunnel_io *io, void *arg, npf_policy *policy);
/* Ends every sublink (local sockets reset) and frees t; from inside a call
 * into the tunnel (a hook) it goes when that call returns. NULL: nothing. */
void npf_tunnel_free(npf_tunnel *t);
/* Sends our hello (once) when the transport has a path. */
void npf_tunnel_start(npf_tunnel *t);
/* Caller, the peer authenticated by the handshake already (IK, a grant, a
 * direct path): the tunnel is ready once our hello is sent, before the
 * peer's (io.ready still waits for both). Never for a first pairing: the
 * callee's hello proves it took handshake message 3. */
void npf_tunnel_open_early(npf_tunnel *t);
/* Control bytes / one data message from the transport. 0, or -1: the tunnel
 * is dead (a protocol violation, io.broken called; no memory; or freed by a
 * hook meanwhile). */
int  npf_tunnel_input_ctrl(npf_tunnel *t, const uint8_t *buf, size_t len);
int  npf_tunnel_input_data(npf_tunnel *t, const uint8_t *msg, size_t len);
/* The transport drained: local reads resume once its backlog is at half. */
void npf_tunnel_kick(npf_tunnel *t);
/* 1 when sublinks and control messages may go: both hellos (or ours, early). */
int  npf_tunnel_is_ready(const npf_tunnel *t);
/* Sends a JSON control message (up to NPF_CTRL_MAX bytes). 0, or -1. */
int  npf_tunnel_control(npf_tunnel *t, const char *json, size_t len);
/* Sends an NPF_CU_APP or NPF_CU_UDP unit (up to NPF_CTRL_MAX). 0, or -1 (not
 * ready, another type, too big). */
int  npf_tunnel_unit_send(npf_tunnel *t, int type, const void *buf, size_t len);
int  npf_tunnel_count(const npf_tunnel *t);     /* sublinks open */
void npf_tunnel_dump(const npf_tunnel *t);     /* debugging, to stderr */

/* Caller: the local TCP connection fd becomes a sublink. passthrough: the
 * application speaks SOCKS5 itself (-D); otherwise the tunnel sends CONNECT
 * host:port and strips the reply. The id (> 0), the sublink then owning and
 * closing fd; or -1 (not ready, a limit, a bad host), fd still the caller's. */
int  npf_tunnel_open(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port);
/* npf_tunnel_open in rate group group (> 0, a public mapping): the group's
 * sublinks together move at most rate bytes per second each way (0: no
 * limit, counted only). -1 also when NPF_RATE_GROUPS groups are in use. */
#define NPF_RATE_GROUPS 16
int  npf_tunnel_open_rated(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                           uint32_t rate);
int  npf_tunnel_group_count(const npf_tunnel *t, uint32_t group);     /* its sublinks open */
/* Resets the group's sublinks (their end: why, a static string) and frees
 * the group's place. How many were reset. */
int  npf_tunnel_group_reset(npf_tunnel *t, uint32_t group, const char *why);
/* Bytes read from / written to the sublinks' local ends, in the tunnel's life. */
void npf_tunnel_local_bytes(const npf_tunnel *t, uint64_t *in, uint64_t *out);
/* One sublink's local bytes so far; 0, or -1 no such sublink. */
int  npf_tunnel_sub_bytes(npf_tunnel *t, uint32_t id, uint64_t *in, uint64_t *out);
/* Resets a sublink, why (a static string) its end. 0, or -1 no such sublink. */
int  npf_tunnel_sub_reset(npf_tunnel *t, uint32_t id, const char *why);

/* A traffic budget tunnels share (a hosted client's quota): the bytes moved
 * to and from the local ends come off left; at 0 they go at slow bytes per
 * second. The owner fills left and slow; tokens and at_ms are the tunnel's. */
typedef struct npf_budget {
    int64_t  left;
    uint32_t slow;
    double   tokens;
    int64_t  at_ms;
    /* set by the owner: the next byte spent clears it and calls wake(wake_arg) */
    int      idle;
    void   (*wake)(void *arg);
    void    *wake_arg;
} npf_budget;
void npf_tunnel_set_budget(npf_tunnel *t, npf_budget *b);       /* b borrowed; NULL none */
/* Limits shared by tunnels on the sublinks the peers open: sockets (subs)
 * and receive window granted (rx). A sublink over subs_max is refused
 * (NPF_RST_LIMIT); no window grows past rx_max. */
typedef struct npf_tunnel_shared {
    int     subs, subs_max;
    int64_t rx, rx_max;
} npf_tunnel_shared;
/* node: the node's limits (all sessions); key: the caller key's (its
 * sessions here). Borrowed; NULL none. */
void npf_tunnel_set_shared(npf_tunnel *t, npf_tunnel_shared *node, npf_tunnel_shared *key);

/* Caller: a sublink whose local end is not a socket (a module's kind of
 * forward). The tunnel calls these from its own loop work (frames from the
 * peer, a poll), never from inside npf_tunnel_vkick or npf_tunnel_vclose. */
typedef struct npf_vend_io {
    /* bytes from the local end: > 0, 0 at its end (FIN), -1 none now */
    ssize_t  (*read)(void *arg, uint8_t *buf, size_t cap);
    /* bytes to the local end: how many it took (0: no room now), -1 broken */
    ssize_t  (*write)(void *arg, const uint8_t *buf, size_t len);
    /* NPF_EV_READ: something to read (data or the end); NPF_EV_WRITE: room to write */
    unsigned (*ready)(void *arg);
    void     (*shutdown)(void *arg);        /* the peer's FIN, after everything was written */
    void     (*closed)(void *arg, int reset);   /* the sublink is gone (reset: abortively); no call after */
} npf_vend_io;
/* CONNECT host:port with a virtual local end (v and varg borrowed until
 * closed() or npf_tunnel_vclose). The id (> 0), or -1 (closed() not called). */
int  npf_tunnel_open_v(npf_tunnel *t, const npf_vend_io *v, void *varg, const char *host, uint16_t port);
/* The virtual ends may read or write again: they are polled soon. */
void npf_tunnel_vkick(npf_tunnel *t);
/* The owner closed a virtual end; v is not called again (closed() neither).
 * reset: the sublink is reset; else FIN follows what was sent and the
 * sublink waits up to 30 s for the peer's FIN, dropping its data. May be
 * called from inside v's own calls. Unknown id: nothing. */
void npf_tunnel_vclose(npf_tunnel *t, uint32_t id, int reset);

/* Tests: the SOCKS greeting deadline (ms); a resolver giving a name's
 * addresses at once (NULL, or -1 from it: the system's). */
extern int npf_tunnel_greet_ms;
extern int (*npf_tunnel_test_resolve)(const char *host, uint16_t port, struct sockaddr_storage *out,
                                      socklen_t *lens, int max);
/* Reorders n addresses for Happy Eyeballs (RFC 8305): the families in turns,
 * the first one's first. */
void npf_he_order(struct sockaddr_storage *a, socklen_t *l, int n);

#endif

/* Sublinks inside one tunnel transport (data-channel.md 5-8). Two channels:
 *
 *   control (AnLiu default stream 0, strict priority; a byte stream):
 *     unit    = type(1) | len(2) | body                     (little-endian)
 *     JSON=1 (control messages), WINDOW=2 sublink(4) | increment(4),
 *     RESET=3 sublink(4) | reason(1), APP=4 the application's data (libnpf
 *     npf_session_send), MEDIA=5 the media streams' signals (node/media.c),
 *     UDP=6 the UDP forwards' flows (node/udpfwd.c);
 *     unknown types are skipped
 *   data (one message stream per direction, priority 2; message boundaries kept):
 *     message = sublink(4) | payload; an empty payload is FIN
 *
 * FIN stays with the data (the control channel would overtake it and cut the
 * last bytes off); WINDOW and RESET take the fast lane. Sublink ids start at
 * 1 (caller odd, callee even) and are never reused.
 *
 * Every sublink opened by the caller is a SOCKS5 session served by the callee
 * (CONNECT only); the callee checks each target against its policy. The
 * transport (AnLiu tunnel stream or WS relay records) is abstract. */
#ifndef NPF_TUNNEL_H
#define NPF_TUNNEL_H

#include <stddef.h>
#include <stdint.h>
#include "npf/sys.h"

#include "npf/json.h"
#include "npf/loop.h"

enum { NPF_CU_JSON = 1, NPF_CU_WINDOW = 2, NPF_CU_RESET = 3, NPF_CU_APP = 4, NPF_CU_MEDIA = 5, NPF_CU_UDP = 6 };
enum { NPF_RST_LOCAL = 1, NPF_RST_PROTOCOL = 2, NPF_RST_LIMIT = 3, NPF_RST_TIMEOUT = 4, NPF_RST_TRANSPORT = 5 };

#define NPF_CU_HDR        3         /* control unit header */
#define NPF_DATA_HDR      4         /* data message header */
#define NPF_FRAME_MAX     16384     /* data payload per message */
#define NPF_INIT_WINDOW   (256 * 1024)
#define NPF_MAX_WINDOW    (4 * 1024 * 1024)
#define NPF_MAX_SUBLINKS  128
#define NPF_CTRL_MAX      16384
#define NPF_MAX_REVERSE   16        /* reverse mappings per session (data-channel.md 7.1) */

/* Target policy (security.md D22): what the published resources cover
 * (resources.h), nothing else. "lan" stands for this host's addresses and
 * its directly attached private networks (recomputed now and then), "*" for
 * every target. */
typedef struct npf_policy_rule {
    int      family;
    uint8_t  addr[16];
    int      prefix;
    uint16_t port_lo, port_hi;
} npf_policy_rule;

typedef struct npf_policy {
    npf_policy_rule rules[64];      /* the resources' targets */
    int      nrules;
    int      lan;                   /* a resource covers "lan": the local rules count */
    int      any;                   /* a resource covers "*": every target */
    npf_policy_rule local[64];      /* "lan", computed from the interfaces */
    int      nlocal;
    int64_t  refreshed_ms;
    /* "reverse" resources: the ports a caller may have this node listen on
     * (-R; data-channel.md 7.1): its loopback address, every address with
     * "lan:" (connections from this host and its LAN only); none: -R refused */
    struct { uint16_t lo, hi; uint8_t lan; } rev[16];
    int      nrev;
    /* "udp" resources: the UDP targets (data-channel.md 15); net / socks
     * resources ("lan", "*") cover TCP only */
    npf_policy_rule udp[32];
    int      nudp;
} npf_policy;

/* one target more: "10.1.0.0/16", "10.1.2.3:80-443", "[::1]:80", "lan" or
 * "*"; 0, -1 bad or full */
int  npf_policy_add(npf_policy *p, const char *spec);
void npf_policy_clear(npf_policy *p);       /* nothing allowed */
/* ports for -R: "*" (1024-65535), PORT or PORT-PORT, at least 1024; "lan:"
 * before it: on every address, for the LAN too; 0, -1 bad or full */
int  npf_policy_add_reverse(npf_policy *p, const char *spec);
/* may a caller have this node listen on port (0: one the system picks, only
 * with "*"), on every address when lan? */
int  npf_policy_reverse_ok(const npf_policy *p, int port, int lan);
/* is the address this host's or on a private network attached to it ("lan")? */
int  npf_policy_lan_peer(npf_policy *p, const struct sockaddr *a);
void npf_policy_refresh(npf_policy *p);
int  npf_policy_allowed(npf_policy *p, const struct sockaddr *dst);
/* one UDP target more: "127.0.0.1:53", "[::1]:53" (the "udp" resources); 0, -1 */
int  npf_policy_add_udp(npf_policy *p, const char *spec);
int  npf_policy_udp_allowed(npf_policy *p, const struct sockaddr *dst);
/* is the address (any port) in one of the rules (an allow_from list)? */
int  npf_policy_rules_match(const npf_policy_rule *r, int n, const struct sockaddr *a);

/* The control interface of this process (the web console and its API, on
 * the address given): never a target of a forward, whatever the published
 * resources say (security, user's request 2026-10-16): a connection to its
 * port on this host (a loopback address, its own address, any local one
 * when it listens on all) fails with a warning in the log, whether a
 * resource, a -R or a public mapping led there. Nothing is refused before:
 * the attempt is what fails. Process-wide; set once the control interface listens. */
void npf_guard_control(const struct sockaddr_storage *a);
int  npf_guard_blocked(const struct sockaddr *dst);

typedef struct npf_tunnel npf_tunnel;

/* a sublink opened here, as it ended (the public connections' records) */
typedef struct npf_sublink_stats {
    uint64_t    in, out;            /* bytes read from / written to its local socket */
    int         connect_ms;         /* from the open to the other side's CONNECT reply: the target reached; -1 never */
    int         first_byte_ms;      /* from the open to the first byte written to the local socket; -1 none */
    const char *end;                /* local_closed / peer_closed (who closed first), target_failed (the
                                     * other side could not reach the target), peer_reset, local_reset,
                                     * session_ended */
} npf_sublink_stats;

typedef struct npf_tunnel_io {
    int    (*write_ctrl)(void *arg, const uint8_t *buf, size_t len);  /* control units (byte stream); 0 or -1 */
    int    (*write_data)(void *arg, const uint8_t *msg, size_t len);  /* one data message; 0 or -1 */
    size_t (*backlog)(void *arg);                                     /* data bytes not yet sent */
    void   (*ready)(void *arg);                                   /* hellos exchanged */
    void   (*control)(void *arg, const npf_json *j);              /* other control messages */
    void   (*broken)(void *arg, const char *why);                 /* protocol violation */
    /* an APP, MEDIA or UDP unit (type NPF_CU_APP / NPF_CU_MEDIA / NPF_CU_UDP); optional */
    void   (*unit)(void *arg, int type, const uint8_t *buf, size_t len);
    /* a CONNECT target as the caller wrote it (an address or a name), before
     * the policy: 0 refuses it (REP = 02); optional (security.md 8.4) */
    int    (*target_ok)(void *arg, const char *host, uint16_t port);
    /* a sublink opened here (npf_tunnel_open*) ended (npf_sublink_stats);
     * optional */
    void   (*sublink_done)(void *arg, uint32_t id, const struct npf_sublink_stats *st);
} npf_tunnel_io;

npf_tunnel *npf_tunnel_new(npf_loop *loop, int caller, const npf_tunnel_io *io, void *arg, npf_policy *policy);
/* resets every sublink (local sockets get RST) and frees */
void npf_tunnel_free(npf_tunnel *t);
/* callee: send hello right after the transport exists */
void npf_tunnel_start(npf_tunnel *t);
/* control channel bytes / one data message received; 0 or -1 (the transport is broken) */
int  npf_tunnel_input_ctrl(npf_tunnel *t, const uint8_t *buf, size_t len);
int  npf_tunnel_input_data(npf_tunnel *t, const uint8_t *msg, size_t len);
/* the transport drained: resume local reads */
void npf_tunnel_kick(npf_tunnel *t);
int  npf_tunnel_is_ready(const npf_tunnel *t);
int  npf_tunnel_control(npf_tunnel *t, const char *json, size_t len);
/* an APP, MEDIA or UDP unit on the control channel (<= NPF_CTRL_MAX) */
int  npf_tunnel_unit_send(npf_tunnel *t, int type, const void *buf, size_t len);
int  npf_tunnel_count(const npf_tunnel *t);
void npf_tunnel_dump(const npf_tunnel *t);     /* debugging, to stderr */

/* caller: allow reverse sublinks to host:port (after reverse_listen succeeded) */
int  npf_tunnel_rev_add(npf_tunnel *t, uint32_t listen_id, const char *host, uint16_t port);
void npf_tunnel_rev_del(npf_tunnel *t, uint32_t listen_id);

/* caller: a local TCP connection becomes a sublink.
 * passthrough: the application speaks SOCKS5 itself (SOCKS5 proxy mode);
 * otherwise the tunnel sends CONNECT host:port and strips the replies. */
/* the sublink's id (> 0), or -1 */
int  npf_tunnel_open(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port);
/* the same, the sublink in group `group` (> 0, a public mapping): its
 * sublinks together move at most rate bytes per second each way (0: no
 * limit); the tunnel keeps up to NPF_RATE_GROUPS groups */
#define NPF_RATE_GROUPS 16
/* a traffic budget shared by tunnels (a hosted client's quota, signaling.md
 * "流量额度"): the bytes moved to and from the local sockets come off
 * budget; with none left they go at slow bytes per second */
typedef struct npf_budget {
    int64_t  left;
    uint32_t slow;
    double   tokens;
    int64_t  at_ms;
    /* idle (set by the owner): the first byte spent calls wake(wake_arg) and
     * clears it, so that the owner can look after the budget closely again */
    int      idle;
    void   (*wake)(void *arg);
    void    *wake_arg;
} npf_budget;
void npf_tunnel_set_budget(npf_tunnel *t, npf_budget *b);
/* the sublinks open in a rate group */
int  npf_tunnel_group_count(const npf_tunnel *t, uint32_t group);
/* resets a group's sublinks (their end: why, a static string); how many */
int  npf_tunnel_group_reset(npf_tunnel *t, uint32_t group, const char *why);
/* bytes read from / written to the local sockets of the sublinks (what a
 * public mapping moved for the people connected to it) */
void npf_tunnel_local_bytes(const npf_tunnel *t, uint64_t *in, uint64_t *out);
int  npf_tunnel_open_rated(npf_tunnel *t, int fd, int passthrough, const char *host, uint16_t port, uint32_t group,
                           uint32_t rate);

/* caller: a sublink whose local end is not a socket (a module's kind of
 * forward, npf_fwd_kind: connections it ends itself). The tunnel calls these from
 * its own event loop work (frames from the peer, a scheduled poll), never
 * from inside npf_tunnel_vkick / npf_tunnel_vclose. */
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
/* CONNECT host:port with a virtual local end; the sublink's id (> 0), or -1 */
int  npf_tunnel_open_v(npf_tunnel *t, const npf_vend_io *v, void *varg, const char *host, uint16_t port);
/* the local end of sublink id may read or write again: looked at soon */
void npf_tunnel_vkick(npf_tunnel *t, uint32_t id);
/* the local end went away by itself: the sublink is reset (reset) or
 * finished as by FIN and dropped; closed() is not called */
void npf_tunnel_vclose(npf_tunnel *t, uint32_t id, int reset);

#endif

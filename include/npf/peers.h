/* An instance's outgoing sessions to any number of peers, each with its own
 * forwards (-L / -D / -R, a module's kinds) and reconnect backoff. A peer is
 * a node number (pairing with a password the first time, then the pinned
 * key, or an account's grant) or HOST:PORT with a pre-shared key (direct).
 * npf.h's peers and forwards are these. Peers and forwards have ids unique
 * in the npf_peers' life. A peer that gives up (NPF_CONNECT_ONCE ended, or a
 * need: not paired, the password refused, the pairing lost, no account
 * session) stays until removed; meeting the need tries it again.
 *
 * Everything runs on the instance's loop thread; callbacks too. Internal to
 * libnpf; in include/npf because npf's modules (cli.c, cli_basic.c, apps.c,
 * platform_console.c, pmap.c, tun/tun_mod.c) work on struct npf.peers. In a
 * build with NPF_PEERS=OFF making a peer or forward fails and the rest are
 * stubs. */
#ifndef NPF_PEERS_H
#define NPF_PEERS_H

#include <stdint.h>
#include "npf/local.h"
#include "npf/node.h"

#define NPF_PEER_MAX_FWD 16

typedef struct npf_peers npf_peers;
typedef struct npf_peer npf_peer;

/* Callbacks, all optional. */
typedef struct npf_peers_cbs {
    /* the session is established (its forwards are being started) */
    void (*up)(npf_peer *p, npf_call *c, void *arg);
    /* the peer gave up (see above); why says why */
    void (*done)(npf_peer *p, const char *why, void *arg);
    /* forward i's state changed: up, or not (why: waiting, failed, retrying) */
    void (*fwd)(npf_peer *p, int i, int up, const char *why, void *arg);
    /* Public mappings (npf_peer_forward_set_public). conn: a connection let
     * in ended (start, end: Unix ms; st: its bytes and end; c: its session;
     * p NULL when the peer is gone). refused: a connection was refused, at
     * once (opened 0: allow_from, quota, mapping_full, address_full,
     * address_rate) or after opened (1: no_session, session_full,
     * mapping_closed). opened: one was let in; conn or refused follows. */
    void (*conn)(npf_peer *p, npf_call *c, uint64_t mapping, int port, const struct sockaddr_storage *from,
                 int64_t start, int64_t end, const struct npf_sublink_stats *st, void *arg);
    void (*refused)(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, const char *reason,
                    int opened, void *arg);
    void (*opened)(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, void *arg);
} npf_peers_cbs;

/* A new peer; the strings and psk are copied. */
typedef struct npf_peer_new {
    uint64_t       number;          /* a platform peer, or 0 and */
    const char    *host;            /* a direct one: an address or name (IPv6 without brackets) */
    uint16_t       port;
    const uint8_t *psk;             /* direct: 32 bytes */
    const char    *password;        /* for the first pairing, NULL none */
    int            connect;         /* NPF_CONNECT_* (npf.h) */
    int            idle_ms;         /* NPF_CONNECT_ON_DEMAND: 0 the default (npf_peers_set_idle) */
} npf_peer_new;

/* The target's canonical name into out: the number, or HOST:PORT with the
 * host in lower case and an IP address in its standard form ([ADDR]:PORT
 * for IPv6). 0, or -1 (no target, a bad host, out too small). */
int npf_peer_target_name(uint64_t number, const char *host, uint16_t port, char *out, size_t cap);
/* Makes a peer; it starts with npf_peer_start (an on-demand one listens at
 * once). A direct peer's host is resolved here, IPv4 only, with a blocking lookup. NULL with err
 * and *code (code may be NULL): 1 a bad part (this node's own number, no
 * psk, unresolvable), 2 a peer with this target exists, 3 other. */
npf_peer *npf_peers_create(npf_peers *ps, const npf_peer_new *pn, char *err, size_t errcap, int *code);

/* A new forward; the strings are copied. */
typedef struct npf_fwd_new {
    char        opt;                /* 'L', 'D', 'R' */
    int         udp;
    const char *bind;               /* NULL: 127.0.0.1; "*" and "": every address */
    int         port;               /* 0: picked (by the system here, by the peer for -R) */
    const char *host;               /* -L / -R: the target */
    int         hostport;
} npf_fwd_new;
/* Adds a forward to p. perm: it is saved (npf_fwd_state.perm); ext: the
 * application's id (a platform mapping), 0 none. It starts when the peer
 * listens or has a session; one that cannot start (port in use, refused by
 * the callee) retries with backoff while the session goes on. Its index
 * (>= 0), or -1 with err: bad, an equal one there, -R (ext 0) on an on-demand peer;
 * -2: NPF_PEER_MAX_FWD; -3: the port taken by another forward, no memory. */
int npf_peer_forward_add_parts(npf_peer *p, const npf_fwd_new *fn, int perm, uint64_t ext, char *err, size_t errcap);
/* spec of the kind opt in the form the kind keeps it (into buf), else spec itself. */
const char *npf_peers_kind_norm(npf_peers *ps, char opt, const char *spec, char *buf, size_t cap);
/* Adds a forward of a module's kind (npf_fwd_kind), spec in its own form.
 * Its index, or -1 with err (no such kind, refused by its parse or check,
 * the same one through another peer), -2, -3 as above. */
int npf_peer_forward_add_kind(npf_peer *p, char opt, const char *spec, int perm, char *err, size_t errcap);

/* Names people give peers, kept in lc. Sets target's name ("" removes it)
 * and saves lc. 0, or -1 with err: no lc, an invalid name, another's name,
 * lc full or not written. */
int npf_peers_name_set(npf_peers *ps, const char *name, const char *target, char *err, size_t errcap);
/* The target the name word stands for (into buf), else word itself. */
const char *npf_peers_resolve(const npf_peers *ps, const char *word, char *buf, size_t cap);

/* n, lc (the pinned keys, names and nicks; may be NULL) and arg are
 * borrowed; cbs is copied. NULL when out of memory. */
npf_peers *npf_peers_new(npf_node *n, npf_local *lc, const npf_peers_cbs *cbs, void *arg);
/* Ends every session and closes the listeners, without done callbacks;
 * a save of lc that waited is done now. NULL: nothing. */
void npf_peers_free(npf_peers *ps);

int  npf_peers_count(const npf_peers *ps);

/* Starts the direct peers; the platform peers start at login. */
void npf_peers_start(npf_peers *ps);
/* Starts a peer made while the instance runs: a direct one's session now;
 * a platform one's when logged in (now, or at the next login), an on-demand
 * one's listeners. */
void npf_peer_start(npf_peer *p);

/* The node's hooks, passed on. on_login starts the platform peers (spread
 * over 2 s when several). on_call_state: 1 when the call is a peer's.
 * on_paired pins pub for number in lc and drops the peers' passwords. */
void npf_peers_on_login(npf_peers *ps);
int  npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why);
void npf_peers_on_paired(npf_peers *ps, uint64_t number, const uint8_t pub[32]);
/* An account session started: the peers that gave up for want of an account
 * or a pairing, and those waiting out a backoff (not on demand), try now. */
void npf_peers_retry_now(npf_peers *ps);
/* The network changed or the process was suspended: backoffs restart from
 * 1 s, forwards waiting to retry try now, and as npf_peers_retry_now. */
void npf_peers_net_changed(npf_peers *ps);

/* Ends the peer's session (no done callback), closes its listeners and
 * forgets it. p is freed at the next loop turn, so a caller still holding it
 * (a callback) may finish. Its open public connections end later, with p NULL. */
void      npf_peers_remove(npf_peers *ps, npf_peer *p);
/* The peer named so: its number (any spelling), HOST:PORT (canonical or
 * not), or the name people gave it. NULL none. */
npf_peer *npf_peers_find(const npf_peers *ps, const char *name);
npf_peer *npf_peers_by_id(const npf_peers *ps, uint32_t id);
uint32_t  npf_peer_id(const npf_peer *p);
void     *npf_peer_ctx(const npf_peer *p);
void      npf_peer_ctx_put(npf_peer *p, void *ctx);
int       npf_peer_connect_mode(const npf_peer *p);  /* NPF_CONNECT_* */
int       npf_peer_idle_asked(const npf_peer *p);    /* its own idle time, 0: the default */
/* NPF_PEER_* (npf.h); *needs: NPF_NEED_* (0 while connected or connecting);
 * *retry_in_ms: until the next try (NPF_PEER_RETRY). Either may be NULL. */
int       npf_peer_state(const npf_peer *p, int *needs, int *retry_in_ms);
const char *npf_peer_last_why(const npf_peer *p);     /* why the last session ended, or why it waits; "" */
/* A direct peer's host (no brackets, into host) and port: 0, or -1 a platform peer. */
int       npf_peer_direct_target(const npf_peer *p, char *host, size_t cap, uint16_t *port);
/* A nick for this run, not saved (copied; NULL: back to lc's). */
void      npf_peer_set_nick_here(npf_peer *p, const char *nick);
void      npf_peer_set_label(npf_peer *p, const char *name);
npf_peer *npf_peers_first(const npf_peers *ps);
npf_peer *npf_peer_next(const npf_peer *p);
void      npf_peer_set_tag(npf_peer *p, int tag);
int       npf_peer_tag(const npf_peer *p);
/* The strings below are the peer's, valid while it lives (a nick or
 * resources from lc: until lc changes). */
/* its name ("" none); what to show people: the name, else number or HOST:PORT */
const char *npf_peer_label(const npf_peer *p);
const char *npf_peer_shown(const npf_peer *p);
const char *npf_peer_nick(const npf_peer *p);   /* this run's nick, else lc's; "" none */
/* What it published as last heard in a session, else as its lc record
 * keeps it: a JSON array; NULL none. */
const char *npf_peer_resources(const npf_peer *p);
/* Keeps a list just heard (copied), also in its lc record when it has one
 * (saved at most every 30 s). 0, or -1 (no memory, not saved). */
int npf_peer_resources_set(npf_peer *p, const char *json);
/* 1 when json is the list its session gave last. */
int npf_peer_resources_same(const npf_peer *p, const char *json);
/* npf_peer_state for people, into buf: "connected", "connecting", "on
 * demand", "retry in N s (why)", "ended (why)", "waiting for the server". */
const char *npf_peer_status(const npf_peer *p, char *buf, size_t cap);
/* What the last attempt left the user to do, NPF_NEED_*: a password (not
 * paired, the last one refused, or the pairing lost), or a login again;
 * 0 with a session or a password given. */
int         npf_peer_needs(const npf_peer *p);
/* Gives the pairing password (copied, wiped once paired) and tries at once,
 * also a peer that gave up. 0, or -1 empty or too long. */
int         npf_peer_password_try(npf_peer *p, const char *password);

/* Sets the connect mode, NPF_CONNECT_*. KEEP: a session now when running
 * (the instance started) and there is none. ONCE: it ends with its session,
 * at once without one. ON_DEMAND: the listeners are up without a session,
 * the first connection starts one (connections wait for it), which ends
 * idle_ms (0: the default) after its last connection; the idle time runs
 * from now; no reconnecting. */
void        npf_peer_connect_put(npf_peer *p, int connect, int idle_ms, int running);
/* A direct peer's pre-shared key (32 bytes, the peer's); NULL for a platform peer. */
const uint8_t *npf_peer_psk(const npf_peer *p);
/* Its own idle time on demand (0: the default), in effect now if on demand. */
void        npf_peer_idle_put(npf_peer *p, int idle_ms);
/* The default idle time on demand (0: 300 s), for the peers without their own. */
void        npf_peers_set_idle(npf_peers *ps, int idle_ms);
/* A kind of forward a module adds (npf/module.h), option -X with its capital
 * letter: the module carries its traffic through the peer's session
 * (npf_peers_fwd_call); the peers keep it like the others (saved, retried,
 * removed with the peer). The callbacks get arg. */
#define NPF_FWD_KINDS 4
typedef struct npf_fwd_kind {
    char opt;
    /* checks spec and writes the form it is kept in (norm): 0, or -1 with err */
    int  (*parse)(void *arg, const char *spec, char *norm, size_t cap, char *err, size_t errcap);
    /* may it be added now: 0, or -1 with err; optional */
    int  (*check)(void *arg, const char *norm, char *err, size_t errcap);
    /* forward id goes up: 0, or -1 with why (retried later) */
    int  (*up)(void *arg, int id, const char *norm, char *why, size_t cap);
    /* forward id went down: its connections end; optional */
    void (*down)(void *arg, int id);
    /* a session came up: what waited for one goes on; optional */
    void (*kick)(void *arg);
    /* what carries it, shown in the forward's state ("up (npf0)"); optional */
    const char *(*name)(void *arg);
} npf_fwd_kind;
/* Registers a kind (k and arg borrowed). 0, or -1: NPF_FWD_KINDS, or not a
 * capital letter other than L, D, R. */
int         npf_peers_add_kind(npf_peers *ps, const npf_fwd_kind *k, void *arg);
/* The ready session of a kind's forward id, else NULL (the peer's session
 * is started when it has none and has not given up). */
npf_call   *npf_peers_fwd_call(npf_peers *ps, int id);
int         npf_peers_idle(const npf_peers *ps);    /* the default idle time set, 0 none */
/* The peers' resources are not kept in lc. */
void        npf_peers_no_cache(npf_peers *ps);
/* Starts the session now when it has none and is on demand, waiting to
 * reconnect, or given up (one more try, as made); else nothing. */
void        npf_peer_wake_now(npf_peer *p);
/* Removes forward i (closes a -R on the peer; ends a public mapping's open
 * connections). 0, or -1 no such forward. */
int         npf_peer_forward_del_at(npf_peer *p, int i);
/* Makes TCP forward i a public mapping (npf-hosted): connections from the
 * allow list only (nallow ADDR[/PREFIX] entries, at most 64; none: anyone),
 * at most rate bytes per second each way over all its connections (0: no
 * limit). 0, or -1: no such TCP forward, a bad entry, no memory. */
int         npf_peer_forward_set_public(npf_peer *p, int i, const char *const *allow, int nallow, uint32_t rate);
/* drain on (the account's quota used up): a public mapping takes no new
 * connection, and npf_peer_forward_drained closes its port once its
 * connections have ended (1: closed). Off: listening again. drain: 0, or
 * -1 no such forward. */
int         npf_peer_forward_drain(npf_peer *p, int i, int on);
int         npf_peer_forward_drained(npf_peer *p, int i);
/* Limits on public connections over all peers (0: none): open ones per
 * mapping, open ones per source address, new ones per source address a
 * minute (bursts of half that). */
void        npf_peers_set_limits(npf_peers *ps, int per_mapping, int per_address, int per_address_minute);
/* Writes the public mappings to o: {"open": connections open (waiting ones
 * too), "closing": bool, "mappings": [{"mapping_id", "port", "listening",
 * "conns"}]}. close: every public port closes now and stays closed; the
 * open connections go on. */
struct npf_out;
void        npf_peers_public_json(npf_peers *ps, int close, struct npf_out *o);
/* A hosted client with a session up: fetches a new grant (the targets
 * changed) and sends it to the device (grant_update); a refusal or no grant
 * ends the session. */
void        npf_peer_grant_update(npf_peer *p);
/* Forward i's application id, 0 none or no such forward. */
uint64_t    npf_peer_forward_ext(const npf_peer *p, int i);
/* Forward i's id (unique among all peers' forwards), 0 no such forward. */
int         npf_peer_forward_id(const npf_peer *p, int i);
int         npf_peer_forward_used(const npf_peer *p);   /* forwards it has */
void        npf_peer_forward_perm_set(npf_peer *p, int i, int perm);
/* Forward i's parts and state into st: 0, or -1 no such forward. */
typedef struct npf_fwd_state {
    char     opt;                   /* 'L', 'D', 'R', or a module's */
    int      udp, perm;
    char     bind[64];
    int      port;                  /* as asked (0: picked) */
    int      lport;                 /* the port in use: here, or the peer's for -R; 0 not yet */
    char     host[256];
    int      hostport;
    int      state, why_code;       /* NPF_FWD_*, NPF_FWD_WHY_* */
    char     why[64];
    int      conns;                 /* connections open now */
    uint32_t refused;               /* connections the peer refused */
    char     refused_why[64];
    void    *ctx;
    uint64_t ext;                   /* the application's id (a platform mapping), 0 none */
    char     spec[300];             /* a module's kind: its form; else for people
                                       ("local 127.0.0.1:8080 -> 127.0.0.1:80") */
    char     text[112];             /* its state for people: "up", "retry in N s (why)", ... */
} npf_fwd_state;
int         npf_peer_forward_state(const npf_peer *p, int i, npf_fwd_state *st);
void        npf_peer_forward_set_ctx(npf_peer *p, int i, void *ctx);
/* The peer with forward id, its index in *idx (idx may be NULL); NULL none. */
npf_peer   *npf_peers_fwd_find(const npf_peers *ps, int id, int *idx);
npf_call   *npf_peer_call(const npf_peer *p);
uint64_t    npf_peer_number(const npf_peer *p);        /* 0 for a direct peer */
const char *npf_peer_name(const npf_peer *p);          /* the number or HOST:PORT, for logs */
int         npf_peer_nfwd(const npf_peer *p);

#endif

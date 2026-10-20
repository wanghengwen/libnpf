/* Outgoing sessions of a node or client to any number of peers (many-to-many):
 * each peer is a node number (platform call: pairing with a password the
 * first time, then IK with the pinned key, or hosted trust with an account
 * session) or HOST:PORT with a pre-shared key (direct connection), with its
 * own -L / -D / -R forwards and its own reconnect backoff. One process keeps
 * all of them: the platform keeps one signaling connection per identity, so
 * two processes with the same identity would push each other off.
 *
 * A peer is described like the connect command line:
 *   NUMBER [-p PASSWORD] [-L [BIND:]PORT:HOST:HOSTPORT]... [-D [BIND:]PORT]... [-R [BIND:]PORT:HOST:HOSTPORT]...
 *   HOST:PORT (--psk-file F | --psk KEY) [-L ...] [-D ...] [-R ...]
 * and in configuration files as "peer = ..." lines. */
#ifndef NPF_PEERS_H
#define NPF_PEERS_H

#include <stdint.h>
#include "npf/local.h"
#include "npf/node.h"

#define NPF_PEER_MAX_FWD 16

typedef struct npf_peers npf_peers;
typedef struct npf_peer npf_peer;

typedef struct npf_peers_cbs {
    /* the session is established and the forwards are up */
    void (*up)(npf_peer *p, npf_call *c, void *arg);
    /* a peer without keep is finished (session closed or could not start);
     * why: "closed" after an orderly end */
    void (*done)(npf_peer *p, const char *why, void *arg);
    /* port mapping i of the peer is up (listening, or the callee listens
     * for -R), or failed and retries later (why); optional */
    void (*fwd)(npf_peer *p, int i, int up, const char *why, void *arg);
    /* public mappings (npf_peer_forward_set_public): a connection ended
     * (start / end: Unix ms; st: its bytes (in: read from it, out: written
     * to it), times and end; c: its session; p: NULL when the peer went), or
     * one was refused (reason: allow_from, quota, mapping_full, address_full,
     * address_rate at once; no_session, session_full after opened); optional */
    void (*conn)(npf_peer *p, npf_call *c, uint64_t mapping, int port, const struct sockaddr_storage *from,
                 int64_t start, int64_t end, const struct npf_sublink_stats *st, void *arg);
    void (*refused)(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, const char *reason,
                    int opened, void *arg);
    /* a public connection was let in (conn or refused with opened follow
     * when it ends); optional */
    void (*opened)(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, void *arg);
} npf_peers_cbs;

/* lc: local.json, where the pinned callee keys, the names and nicks are */
/* Split a forward like -L [BIND:]PORT:HOST:HOSTPORT at its colons, in place:
 * empty fields are kept (":1080" is an empty BIND), an IPv6 address goes in
 * brackets ([::1]:8080) which are removed. The number of fields, -1 when
 * there are more than max. */
int npf_fwd_split(char *s, char **parts, int max);

/* names people give peers (connect --name): kept in local.json (npf/local.h);
 * name "" removes it. -1 with err when the name is invalid or another's */
int npf_peers_name_set(npf_peers *ps, const char *name, const char *target, char *err, size_t errcap);
/* the target a name stands for, else word itself */
const char *npf_peers_resolve(const npf_peers *ps, const char *word, char *buf, size_t cap);
/* the listening address as written: empty or "*" is every address (as ssh) */
const char *npf_fwd_bind(const char *s);

npf_peers *npf_peers_new(npf_node *n, npf_local *lc, const npf_peers_cbs *cbs, void *arg);
/* the session ends, listeners close; done is not called */
void npf_peers_free(npf_peers *ps);

/* add a peer from words (argv[0] is the target); keep: reconnect after the
 * session ends (1 s .. 60 s backoff). NULL and a message in err on bad input. */
npf_peer *npf_peers_add(npf_peers *ps, int argc, char **argv, int keep, char *err, size_t errcap);
/* the same from one line ("peer = ..." in a configuration file); a relative
 * --psk-file is taken relative to base_dir (the configuration's directory) */
npf_peer *npf_peers_add_line(npf_peers *ps, const char *line, int keep, const char *base_dir, char *err, size_t errcap);
int  npf_peers_count(const npf_peers *ps);

/* start what can start now (direct peers); platform peers start on login */
void npf_peers_start(npf_peers *ps);

/* forward the node hooks here; on_call_state returns 1 if the call is a peer's */
void npf_peers_on_login(npf_peers *ps);
int  npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why);
void npf_peers_on_paired(npf_peers *ps, uint64_t number, const uint8_t pub[32]);
/* an account session started: the peers waiting out a backoff (not paired
 * yet, say: the account may let them in now) try again at once */
void npf_peers_retry_now(npf_peers *ps);
/* the network changed or the process was suspended: no peer waits out a
 * backoff, and the reverse forwards waiting to be set up again try now */
void npf_peers_net_changed(npf_peers *ps);

/* end the peer's session (no done callback), close its listeners, forget it */
void      npf_peers_remove(npf_peers *ps, npf_peer *p);
/* by name: the number (any spelling) or HOST:PORT */
npf_peer *npf_peers_find(const npf_peers *ps, const char *name);
npf_peer *npf_peers_first(const npf_peers *ps);
npf_peer *npf_peer_next(const npf_peer *p);
void      npf_peer_set_tag(npf_peer *p, int tag);
int       npf_peer_tag(const npf_peer *p);
/* "connected", "connecting", "retry in N s (why)", "ended (why)", "waiting for the server" */
/* its name ("" none), and what to show people: the name, else number / HOST:PORT */
const char *npf_peer_label(const npf_peer *p);
const char *npf_peer_shown(const npf_peer *p);
const char *npf_peer_nick(const npf_peer *p);   /* its nick (local.json), "" none */
/* the resources it published (resources.h) as last heard in a session, else
 * as its local.json record keeps them: a JSON array; NULL none */
const char *npf_peer_resources(const npf_peer *p);
/* heard now: kept, and in its local.json record when it has one; 0, -1 */
int npf_peer_resources_set(npf_peer *p, const char *json);
const char *npf_peer_status(const npf_peer *p, char *buf, size_t cap);
/* the last attempt found it not paired (no pinned key, no password, no
 * grant through the account): the user gives its password */
int         npf_peer_needs_password(const npf_peer *p);
/* the account let it in, and there is no account session now (it expired or
 * was revoked): the user logs in again (no password asked) */
int         npf_peer_needs_account(const npf_peer *p);
/* ... because the device refused the last password given */
int         npf_peer_password_wrong(const npf_peer *p);
/* ... because the device refused the pairing it had (reset, reinstalled, the
 * pairing revoked): paired by password, it pairs anew (security.md 9.6) */
int         npf_peer_pairing_lost(const npf_peer *p);
/* the pairing password for a peer not connected: tried at once; -1 when it
 * ended (a one-off peer: add it again) */
int         npf_peer_set_password(npf_peer *p, const char *password);
/* "-L 127.0.0.1:8080:host:80 -D 127.0.0.1:1080 ..." (no secrets) */
const char *npf_peer_forwards(const npf_peer *p, char *buf, size_t cap);

/* a peer kept for good (the configuration, connect --permanent): tried for
 * ever, also while not paired yet; others give up on what retrying cannot fix */
void        npf_peer_set_persist(npf_peer *p, int on);
/* on demand (a hosted client's public mappings): the listeners are up
 * without a session; the first connection starts one (connections wait for
 * it, at most 30 s), and it ends idle_ms after its last connection closed;
 * no reconnecting in between. 0: off */
void        npf_peer_set_on_demand(npf_peer *p, int idle_ms);
/* the node's rule: every kept platform peer without a -R mapping on demand,
 * ending idle_ms after its last connection (0: kept connected, as before) */
void        npf_peers_set_idle(npf_peers *ps, int idle_ms);
/* A kind of forward a module adds (npf/module.h), the option -X with its
 * capital letter: the module carries such a forward's traffic itself
 * through the peer's session (npf_peers_fwd_call), the peers keep it like
 * the others (saved, retried, removed with the peer). */
#define NPF_FWD_KINDS 4
typedef struct npf_fwd_kind {
    char opt;
    /* SPEC checked, in the form it is kept (norm): 0, or -1 with err */
    int  (*parse)(void *arg, const char *spec, char *norm, size_t cap, char *err, size_t errcap);
    /* may it be added now (it would meet another route ...): 0, or -1 with err; optional */
    int  (*check)(void *arg, const char *norm, char *err, size_t errcap);
    /* forward id is up: 0, or -1 with why (retried later) */
    int  (*up)(void *arg, int id, const char *norm, char *why, size_t cap);
    /* it went: its connections end; optional */
    void (*down)(void *arg, int id);
    /* a session came up: what waited for one goes on; optional */
    void (*kick)(void *arg);
    /* what carries it, for the forward's state ("up (npf0)"); optional */
    const char *(*name)(void *arg);
} npf_fwd_kind;
/* 0, or -1 (too many, or the letter of L, D, R, of another kind) */
int         npf_peers_add_kind(npf_peers *ps, const npf_fwd_kind *k, void *arg);
/* the session of a kind's forward id: ready, else NULL now (its peer is
 * woken: on demand, or waiting out a backoff) */
npf_call   *npf_peers_fwd_call(npf_peers *ps, int id);
/* SPEC as it is kept (a kind's form; others as given) */
const char *npf_peers_fwd_norm(npf_peers *ps, const char *opt, const char *spec, char *buf, size_t cap);
int         npf_peers_idle(const npf_peers *ps);
int         npf_peer_on_demand(const npf_peer *p);
/* start the session now (on demand: it ends idle_ms later unless used; a
 * kept peer waiting to reconnect: at once): 1 there is one already, 0 started,
 * -1 the peer is finished */
int         npf_peer_wake(npf_peer *p);
int         npf_peer_persist(const npf_peer *p);
/* port mappings at run time: opt "-L", "-D" or "-R", spec as on the command
 * line; perm marks it as part of the saved configuration (the application
 * edits the file). A mapping that cannot start (port in use, refused by the
 * callee) retries with backoff, the session goes on. Its index (>= 0) or -1 (err set) */
int         npf_peer_forward_add(npf_peer *p, const char *opt, const char *spec, int perm, char *err, size_t errcap);
/* 0, -1 when there is no such mapping, -2 for one with an application id
 * (a platform mapping: removed only with npf_peer_forward_del_at); *perm: was it saved */
int         npf_peer_forward_del(npf_peer *p, const char *opt, const char *spec, int *perm);
/* the same with the application's id (see npf_peer_forward_ext) */
int         npf_peer_forward_add_ext(npf_peer *p, const char *opt, const char *spec, int perm, uint64_t ext, char *err,
                                     size_t errcap);
/* by index (what npf_peer_forward_add returned): 0 or -1 */
int         npf_peer_forward_del_at(npf_peer *p, int i);
/* a public mapping (npf-hosted): connections from the allow list only (CIDRs
 * or addresses; none: anyone), at most rate bytes per second each way (0:
 * no limit); 0, or -1 for a bad entry */
int         npf_peer_forward_set_public(npf_peer *p, int i, const char *const *allow, int nallow, uint32_t rate);
/* a public mapping when the account's quota is used up: on, no new
 * connection; npf_peer_forward_drained closes the port once its connections
 * have ended (1: closed); off: listening again */
int         npf_peer_forward_drain(npf_peer *p, int i, int on);
int         npf_peer_forward_drained(npf_peer *p, int i);
/* the limits of public connections, for all the peers (0: none): open ones
 * per mapping, open ones per source address, new ones per source address
 * a minute (half of it as a burst) */
void        npf_peers_set_limits(npf_peers *ps, int per_mapping, int per_address, int per_address_minute);
/* the public mappings as JSON: {"open": connections open (waiting ones
 * too), "closing": bool, "mappings": [{"mapping_id", "port", "listening",
 * "conns"}]}. close: every public port closes now and for good (the
 * hosted client is stopping); the open connections go on */
struct npf_out;
void        npf_peers_public_json(npf_peers *ps, int close, struct npf_out *o);
/* a hosted client: fetch a new grant (the targets changed) and hand it to the
 * device in the session (grant_update) */
void        npf_peer_grant_update(npf_peer *p);
/* the application's id of mapping i (a platform mapping), 0: none */
void        npf_peer_forward_set_ext(npf_peer *p, int i, uint64_t ext);
uint64_t    npf_peer_forward_ext(const npf_peer *p, int i);
/* mapping i's parts: its port (-L / -D: here; -R: the one asked of the
 * device) and, for -L / -R, its target (*host without brackets, "" for -D);
 * 0, or -1 for a free slot */
int         npf_peer_forward_ends(const npf_peer *p, int i, int *port, const char **host, int *hostport);
/* is forward i a UDP one (-L PORT:HOST:HOSTPORT/udp; data-channel.md 15)? */
int         npf_peer_forward_udp(const npf_peer *p, int i);
/* mapping i's number (shown by forward and status; unique among the peers),
 * and the mapping with a number (-1: none) */
int         npf_peer_forward_id(const npf_peer *p, int i);
int         npf_peer_forward_by_id(const npf_peer *p, int id);
/* mappings in use */
int         npf_peer_forward_used(const npf_peer *p);
/* mark every mapping saved or not (a peer saved or loaded from the configuration) */
void        npf_peer_forward_mark(npf_peer *p, int perm);
/* mapping i (0 .. npf_peer_nfwd - 1): NULL for a free slot, else its state
 * ("up", "retry in N s (why)", ...) in state */
const char *npf_peer_forward_info(const npf_peer *p, int i, char *opt, const char **spec, int *perm, char *state,
                                  size_t cap);

npf_call   *npf_peer_call(const npf_peer *p);
uint64_t    npf_peer_number(const npf_peer *p);        /* 0 for a direct peer */
const char *npf_peer_name(const npf_peer *p);          /* the number or HOST:PORT, for logs */
int         npf_peer_nfwd(const npf_peer *p);

#endif

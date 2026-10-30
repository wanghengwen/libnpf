/* Internal interfaces between the node lifecycle, signaling, network,
 * server-list, NAT and call modules. */
#ifndef NPF_NODE_INTERNAL_H
#define NPF_NODE_INTERNAL_H

#include "npf/node.h"
#include "msgs.h"

/* node_servers.c */
/* a signed list from the login, a push or an external channel (via): 1 when adopted */
int  node_server_list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via);
void node_servers_load(npf_node *n);
void node_server_failed(npf_server_entry *e, int weight);
int node_eff_prio(const npf_server_entry *e);
/* by weight among the entries of priority prio (-1: the best) but skip; -1 none */
int node_server_pick(npf_node *n, int prio, int skip);

/* node_signal.c */
/* a reply to a request of npf_node_request: to its callback (1), or not one (0) */
int  node_sig_reply(npf_node *n, const m_env *e);
/* the platform's messages to the node (msgs.c); m: the type's struct */
void node_on_login(npf_node *n, const m_env *e, const void *m);
void node_on_account(npf_node *n, const m_env *e, const void *m);
void node_on_server_list(npf_node *n, const m_env *e, const void *m);
void node_on_upgrade(npf_node *n, const m_env *e, const void *m);
void node_on_probe(npf_node *n, const m_env *e, const void *m);
void node_on_keys(npf_node *n, const m_env *e, const void *m);
void node_on_replaced(npf_node *n, const m_env *e, const void *m);
void node_on_redirect(npf_node *n, const m_env *e, const void *m);
int  node_wake_delay(int ms);           /* sig_wake_ms +-20 % (the unit tests) */
const uint8_t *node_day_key(const npf_node *n, const npf_daykey keys[2]);
void node_sig_fail_pending(npf_node *n);
/* the connection in use and the second access point closed: offline, the
 * ping and the watch stopped */
void node_sig_close(npf_node *n);
void node_sig_abort(npf_node *n, const char *why);
void node_sig_connect(npf_node *n);
/* something seems lost (a call of ours timed out): ask the server with a ping;
 * no answer in time and the signaling is made again */
void node_sig_probe(npf_node *n);
void node_sig_udp_check(npf_node *n);
/* a call is being set up (needs the signaling connection as it is) */
int  node_calls_setting_up(const npf_node *n);
/* a call is up: the signaling reconnects to the same server (its calls are rebound there) */
int  node_calls_up(const npf_node *n);
/* logged in again: what the calls up sent on the connection that went is
 * sent again (a pending relay_switch, call_established); the platform
 * moved them to this connection (same server) */
void node_calls_relogin(npf_node *n);
/* a datagram on a main socket from the UDP signaling server: taken (1), else 0 */
int  node_sig_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);

/* connect again now (a new server list arrived) */
void node_reconnect_now(npf_node *n);

/* sigconn.c: the signaling connections' state machine (npf/node.h npf_sigc).
 * Each event returns what the node does next (SA_*; SA_UDP_BAD or'ed in:
 * udp_bad was set just now); r: the role the event's connection has */
#define SIG_WS_AFTER_MS 1000            /* UDP first, the WebSocket this much later */
#define SIG_LOGIN_MS    20000           /* connect, TLS, upgrade, Noise and login together */
#define SIG_OLD_MS      10000           /* the WebSocket a move replaced: the server closes it, else we do */
enum {
    SA_NONE,
    SA_FIRST,           /* ready: MAIN first, RACE dropped: log in (or enrol) */
    SA_RACE_WON,        /* ready: RACE first: MAIN now, the other dropped: log in */
    SA_MOVE_LOGIN,      /* ready: MOVE logs in */
    SA_OLD_CLOSED,      /* down, due: OLD gone */
    SA_MOVE_FAILED,     /* down, refused: MOVE gone, on the WebSocket still */
    SA_RACE_FAILED,     /* down: RACE gone, MAIN goes on */
    SA_WS_NOW,          /* down: UDP failed before its WebSocket's turn: the node opens that as MAIN */
    SA_TO_RACE,         /* down: MAIN failed, RACE goes on as MAIN */
    SA_UDP_GOES_ON,     /* down: the WebSocket went while MOVE logs in: MOVE is MAIN, offline */
    SA_TAKEN,           /* down: the replaced WebSocket went first: MOVE is MAIN, its welcome due */
    SA_GONE,            /* down: no connection left */
    SA_WELCOME,         /* login: online */
    SA_MOVED,           /* login: online on UDP after a move (the WebSocket OLD) */
    SA_REFUSED,         /* login: refused */
    SA_OPEN_RACE,       /* due: the node opens RACE (c[SR_RACE]'s server and URL) */
    SA_LATE,            /* due: no login in time: MAIN is aborted */
    SA_MOVE_DUE,        /* due: on the WebSocket: MOVE is opened, when idle */
    SA_UDP_BAD = 0x100
};
int  sc_role(const npf_sigc *m, const npf_sig *s);      /* -1 none; NULL: MAIN */
/* a new attempt as MAIN (on UDP: url is the race's WebSocket) */
void sc_start(npf_sigc *m, npf_sig *s, int server, int url, int udp, int64_t now);
void sc_open(npf_sigc *m, int r, npf_sig *s, int server, int url);    /* RACE beside MAIN, MOVE */
void sc_close(npf_sigc *m);
int  sc_ready(npf_sigc *m, int r, int heard);
int  sc_down(npf_sigc *m, int r, int heard, int busy, int64_t now);
int  sc_abort(npf_sigc *m, int heard, int64_t now);    /* MAIN dropped by the node (RACE with it) */
int  sc_login(npf_sigc *m, int r, int ok, int64_t now);
int  sc_replaced(npf_sigc *m, int r);
int  sc_tick(npf_sigc *m, int64_t now);                 /* one due at a time, SA_NONE: none left */
int64_t sc_next(const npf_sigc *m);                     /* the next due, 0 none */

/* node_network.c */
/* the main sockets: IPv4 (-1 when it cannot be opened) and, online, IPv6 */
int  node_udp_open(npf_node *n);
void node_udp_close(npf_node *n);
void node_udp_close_idle(npf_node *n);
void node_watch_start(npf_node *n);

/* nat.c */
void node_nat_refresh(npf_node *n);

/* sources.c: the server list's external channels */
void node_sources_check(npf_node *n);   /* at each failed attempt: time for a round? */
void node_sources_stop(npf_node *n);
/* nodemap.c: the router's port mapping (NPF_PORTMAP; without it, none) */
#ifdef NPF_PORTMAP
void node_portmap_start(npf_node *n);
void node_portmap_stop(npf_node *n);
/* the main socket has another port: the old lease is left to expire, a new one is asked for */
void node_portmap_restart(npf_node *n);
int  node_portmap_cand(const npf_node *n, struct sockaddr_storage *out);
/* a network change: on another network (gateway, address) the mapping again */
void node_portmap_net_change(npf_node *n);
/* the nat profile's "pm": what the gateway did (PCP / NAT-PMP), no address */
void node_portmap_write(const npf_node *n, npf_out *w);
#else
static inline void node_portmap_start(npf_node *n) { (void)n; }
static inline void node_portmap_stop(npf_node *n) { (void)n; }
static inline void node_portmap_restart(npf_node *n) { (void)n; }
static inline int  node_portmap_cand(const npf_node *n, struct sockaddr_storage *out) { (void)n, (void)out; return 0; }
static inline void node_portmap_net_change(npf_node *n) { (void)n; }
static inline void node_portmap_write(const npf_node *n, npf_out *w)
{
    (void)n;
    npf_out_jkey(w, "pm");
    npf_out_jobj(w);
    npf_out_kstr(w, "gw", "off");
    npf_out_jend(w);
}
#endif
/* nat.c: candidates again (a port mapping came or went) */
void node_nat_regather(npf_node *n);
/* at login: probe (on the loop); hooks.on_login at once with a profile from
 * before, else once the first one is measured */
void node_nat_login(npf_node *n);

/* call_punch.c: a check of the NAT unanswered: a sign it is short of ports
 * if a hard-side punch held them or just did (nat-traversal.md 8) */
void call_port_pressure(npf_node *n, const char *what);

/* call.c: the platform's messages about calls (msgs.c) */
void node_on_punch_request(npf_node *n, const m_env *e, const void *m);
void node_on_revoke(npf_node *n, const m_env *e, const void *m);
void node_on_bind_committed(npf_node *n, const m_env *e, const void *m);
void node_on_call(npf_node *n, const m_env *e, const void *m);
void node_sig_lost(npf_node *n);
/* returns 1 when the datagram belonged to a call */
int  node_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void node_calls_free(npf_node *n);
void call_key_shares_free(npf_node *n);      /* call_transport.c: the caller keys' shares, after the calls */

#endif

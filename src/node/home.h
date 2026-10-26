/* The persistent binding on the relay of this node's server (home-binding.md):
 * home.c binds and keeps it alive from the main socket, home_learn.c finds
 * the longest keepalive interval the NAT allows (5: a pure function of what
 * the node saw) and keeps it per network (home.json). */
#ifndef NPF_HOME_H
#define NPF_HOME_H

#include <stdint.h>

#include "npf/json.h"
#include "npf/node.h"
#include "npf/sys.h"

/* ---- the relay's packets (4) ---- */
#define PKT_HOME_BIND      10
#define PKT_HOME_ACK       11
#define PKT_HOME_DATA      12
#define PKT_HOME_PING      13
#define LABEL_HOME         "NPF-HOMEB-v1"
#define HOME_BIND_BODY     21       /* cookie(8) | kseq(8) | iv_s(2) | probe_s(2) | flags(1) */
#define HOME_PROBE_LEN     160      /* the shortest HOME_BIND that gets an echo; with the inbound test: */
#define HOME_INBOUND_LEN   200
#define HOME_F_INBOUND     1        /* HOME_BIND flags: a ping at probe_s / 2 as well */
#define HOME_A_PROBE_SET   1        /* HOME_ACK flags */
#define HOME_A_MOVED       2
#define HOME_A_NEAR_IDLE   4

/* a HOME_BIND body */
void home_bind_body(uint8_t out[HOME_BIND_BODY], const uint8_t cookie[8], uint64_t kseq, int iv_s, int probe_s,
                    int flags);
/* a HOME_ACK body: 0, or -1 when it does not parse */
typedef struct home_ack {
    struct sockaddr_in addr;        /* the source the relay saw (R); IPv4 only */
    int64_t  srv_ms;
    int      state;                 /* 1 bound, 0 a challenge */
    uint8_t  cookie[8];
    uint64_t kseq;
    int      flags;
} home_ack;
int home_ack_parse(const uint8_t *body, size_t len, home_ack *a);
/* a HOME_PING body: srv_time_ms(8) | probe_s(2) | n(1); 0 or -1 */
int home_ping_parse(const uint8_t *body, size_t len, int64_t *srv_ms, int *probe_s, int *n);

/* ---- the learner (5) ---- */
#define HL_TCAP         180         /* the longest wait tried (s) */
#define HL_IV_MIN       8
#define HL_IV_START     25          /* before anything is known */
#define HL_IV_MAPPED    144         /* the gateway maps the port (PCP / NAT-PMP, 5.6) */
#define HL_BUSY_GAP_MS  15000       /* EIM busy: the main socket sends elsewhere at least this often */
#define HL_RETRY_MS     60000       /* a void step: tried again after this long */
#define HL_UP_S         86400       /* LEARNED: a step upward once a day */
#define HL_STALE_S      (30 * 86400)/* a record this old: confirmed from its t_ok upward */

enum { HL_QUIET, HL_BUSY };         /* the tracks, and what the main socket did during a step */
enum { HL_OK, HL_EXPIRED, HL_NOECHO, HL_VOID };   /* a step's outcome: the echo came; it did not
                                                   * and the mapping moved; it did not, same address; no verdict */
enum { HL_NEW, HL_MEASURING, HL_LEARNED };
enum { HL_REFRESH_UNKNOWN, HL_REFRESH_OUT, HL_REFRESH_BOTH, HL_REFRESH_NONE };   /* NONE: not tried yet */

typedef struct hl_track {
    int     phase;
    int     t_ok, t_fail;           /* s, 0: none */
    int     doubt;                  /* a failure at this wait without a new address: measured once more */
    int     bisected, down, upping, unstable;
    int64_t up_at;                  /* LEARNED: the next step upward (Unix s) */
    int64_t learned_at;             /* Unix s */
} hl_track;

typedef struct hl_state {
    int     map;                    /* NPF_MAP_* the learning goes by */
    int     iv_max;                 /* home_iv_max (s) */
    int     off;                    /* home_learn = 0: no steps, HL_IV_START */
    hl_track tr[2];
    int     refresh;                /* HL_REFRESH_* */
    int     preserve;               /* -1 unknown, 0 an expired mapping came back on another port, 1 the same */
    int     per_flow;               /* EIM busy failed: other traffic does not keep the mapping (5.4) */
    int     mapped;                 /* the gateway maps the port */
    int64_t drops[3];               /* Unix s of the last expiries once learned (5.7) */
    int64_t retry_ms;               /* npf_mono_ms: no step before (a void one) */
} hl_state;

typedef struct hl_step {
    int T;                          /* the wait (s) */
    int track;                      /* whose step */
    int inbound;                    /* the refresh test (5.5) */
} hl_step;

void hl_init(hl_state *L, int map, int iv_max, int off);
/* the keepalive interval of a track (s) */
int  hl_iv(const hl_state *L, int track);
/* the step to make now on the track the main socket is on (busy: sending
 * elsewhere): 1 and st, or 0: a plain keepalive after hl_iv */
int  hl_next(hl_state *L, int track, int64_t now_s, int64_t now_ms, hl_step *st);
/* a step's outcome; cls: what the main socket did meanwhile (hl_classify) */
void hl_done(hl_state *L, const hl_step *st, int outcome, int cls, int64_t now_s, int64_t now_ms);
/* a plain keepalive of a LEARNED track found the mapping moved (5.7);
 * network: a network event (the signaling dropped with it, another public
 * IP, a network change): nothing learned. 0 nothing changed, 1 the
 * interval lowered, 2 the third expiry in 24 h: learned again */
int  hl_moved(hl_state *L, int track, int network, int64_t now_s);
int  hl_drops_24h(const hl_state *L, int64_t now_s);
/* the gateway maps the main socket's port and the relay sees that mapping (5.6) */
void hl_mapped(hl_state *L, int64_t now_s);
/* what the main socket did during a step [start, end] (5.4): HL_QUIET,
 * HL_BUSY, or -1 (the step is void: it sent to the relay, or what the
 * mapping behaviour says may refresh the mapping, or started or stopped
 * sending meanwhile) */
int  hl_classify(int map, const npf_udp_watch *w, int64_t start, int64_t end);
/* the track's state as people read it: "new", "measuring", "learned" */
const char *hl_phase_str(int phase);
const char *hl_refresh_str(int refresh);

/* ---- per network (5.7) ---- */
#define HOME_NETS_MAX 16
/* the network's key: BLAKE2b-256 of the gateway's IPv4 and MAC, the
 * interface's IPv4 prefix, the public IP's /16, cellular; its first 8 bytes */
uint64_t home_net_key(uint32_t gw, const char *gw_mac, uint32_t if_net, int if_prefix, uint32_t pub_ip, int cellular);
/* the key of the network the node is on now (pub_ip: R, network order) */
uint64_t home_net_now(uint32_t pub_ip, int cellular);
/* home.json: the learning of key, 0 (loaded) or -1 (none); save: it is
 * written (LRU, HOME_NETS_MAX networks, 0600) */
int  home_store_load(const char *path, uint64_t key, hl_state *L, int64_t *used);
int  home_store_save(const char *path, uint64_t key, const hl_state *L, int64_t now_s);

/* ---- the node (home.c) ---- */
/* after welcome: home_open (the binding opened or resumed) when it may */
void node_home_login(npf_node *n);
/* the signaling connection went: the binding stays (U6) */
void node_home_sig_lost(npf_node *n);
/* the network may have changed, the main socket was opened again: bind again at once */
void node_home_net_change(npf_node *n);
/* shutting down: home_close (best effort), no more keepalives */
void node_home_close(npf_node *n);
/* stopping: home_close if not yet, everything freed */
void node_home_stop(npf_node *n);
/* a datagram on the main socket: 1 when it was the binding's */
int  node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* tests: a binding taken as from home_open (no signaling); the state
 * (3: bound) and the wait being measured (0 none) */
int  node_home_test_take(npf_node *n, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_in *relay);
int  node_home_state(const npf_node *n, int *measuring_s);
/* tests: the keepalive due now */
void node_home_test_due(npf_node *n);
/* the event home_rekey */
void node_home_rekey(npf_node *n, const npf_json *j, int d);
/* nat.home into the nat object being written; whether a client reports its nat (the binding's learning) */
void node_home_write_nat(npf_node *n, struct npf_jw *w);
int  node_home_reports(const npf_node *n);

#endif

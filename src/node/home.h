/* The persistent binding on the relay of this node's server (home-binding.md
 * v0.4): home.c binds it from the main socket and answers the relay's
 * keepalive pings; the relay learns the interval itself. */
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
#define HOME_BIND_BODY     21       /* cookie(8) | kseq(8) | flags(1) | ping_id(4) */
#define HOME_F_PONG        1        /* HOME_BIND flags: the answer to the ping ping_id */
#define HOME_F_OTHER       2        /* ... the main socket sent elsewhere since the last ping (as may keep the mapping) */
#define HOME_F_NEWNET      4        /* the network changed (the main socket opened again): the relay learns again */
#define HOME_A_MOVED       2        /* HOME_ACK flags */
#define HOME_RETRY_MS      4500     /* the relay's tries of a ping: 3, 1.5 s apart */
enum { HOME_LEARNING, HOME_LEARNED, HOME_UNSTABLE };   /* the relay's learning (HOME_PING, HOME_ACK) */

/* a HOME_BIND body */
void home_bind_body(uint8_t out[HOME_BIND_BODY], const uint8_t cookie[8], uint64_t kseq, int flags, uint32_t ping_id);
/* a HOME_ACK body: family | port | addr | srv_time_ms | state | cookie | kseq | flags | t_s(2) | learn(1) */
typedef struct home_ack {
    struct sockaddr_in addr;        /* the source the relay saw (R); IPv4 only */
    int64_t  srv_ms;
    int      state;                 /* 1 bound, 0 a challenge */
    uint8_t  cookie[8];
    uint64_t kseq;
    int      flags;
    int      t_s, learn;            /* the silence after which the relay pings, its learning */
} home_ack;
int home_ack_parse(const uint8_t *body, size_t len, home_ack *a);
/* a HOME_PING body: family | port | addr (R) | srv_time_ms(8) | ping_id(4) | t_s(2) | learn(1) | try(1) */
typedef struct home_ping {
    struct sockaddr_in addr;
    int64_t  srv_ms;
    uint32_t ping_id;
    int      t_s, learn, try_n;
} home_ping;
int home_ping_parse(const uint8_t *body, size_t len, home_ping *p);
const char *home_learn_str(int learn);

/* ---- the node (home.c) ---- */
/* after welcome: home_open (the binding opened or resumed) when it may */
void node_home_login(npf_node *n);
/* the signaling connection went: the binding stays (U6) */
void node_home_sig_lost(npf_node *n);
/* the network may have changed, the main socket was opened again: bind again at once (the relay learns anew) */
void node_home_net_change(npf_node *n);
/* shutting down: home_close (best effort), no more keepalives */
void node_home_close(npf_node *n);
/* stopping: home_close if not yet, everything freed */
void node_home_stop(npf_node *n);
/* a datagram on the main socket: 1 when it was the binding's */
int  node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* the event home_rekey */
void node_home_rekey(npf_node *n, const npf_json *j, int d);
/* tests: a binding taken as from home_open (no signaling); the state (3:
 * bound); the watchdog as of now_ms (1: it bound again) */
int  node_home_test_take(npf_node *n, const uint8_t id[8], const uint8_t key[32], const struct sockaddr_in *relay);
int  node_home_state(const npf_node *n);
int  node_home_test_dog(npf_node *n, int64_t now_ms);

#endif

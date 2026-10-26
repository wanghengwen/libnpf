/* Binding a relay allocation (data-channel.md 9.2): one binder for a call's
 * allocation (call_relay.c) and the node's spare (home.c, home-binding.md
 * v0.5). A zero-cookie RELAY_BIND, the relay's challenge with the cookie of
 * our address, a RELAY_BIND echoing it; 700 ms apart, 3 to an address; only
 * a BIND_ACK answering one of our last binds counts (its txid, ts_ms and
 * kseq echoed). The relay drops a bind whose kseq is not above the last one
 * it took: a replay, or a bind reordered. */
#ifndef NPF_RELAY_BIND_H
#define NPF_RELAY_BIND_H

#include "npf/sys.h"
#include <stdint.h>

#include "npf/bind.h"
#include "npf/node.h"
#include "npf/siv.h"

#define LABEL_RELAY        "NPF-RELAY-v1"
#define PKT_RELAY_BIND     7
#define PKT_RELAY_BIND_ACK 8
#define PKT_RELAY_DATA     9
#define PKT_RELAY_PING     10        /* a spare's keepalive (home-binding.md 9.4) */
#define RELAY_HINT_SIZE    4         /* relay_id[0..3] in the clear before every datagram to the relay */
#define RELAY_COOKIE_SIZE  8
#define RELAY_BIND_BODY    21        /* cookie(8) | kseq(8) | flags(1) | ping_id(4) */
#define RELAY_F_PONG       1         /* RELAY_BIND flags: the answer to the ping ping_id (a spare) */
#define RELAY_F_OTHER      2         /* ... the main socket sent elsewhere since the last ping */
#define RELAY_F_NEWNET     4         /* ... the network changed: the relay learns again */
#define RELAY_ACK_BOUND    1         /* RELAY_BIND_ACK state: the relay sends to this address (0: a challenge) */
#define RELAY_A_MOVED      2         /* RELAY_BIND_ACK flags: the address moved to this one */
#define RELAY_BIND_MS      700
#define RELAY_BIND_TRIES   3
#define RELAY_SENT         8         /* the last RELAY_BINDs whose BIND_ACK is taken */
enum { RELAY_LEARNING, RELAY_LEARNED, RELAY_UNSTABLE };   /* a spare's learning (RELAY_PING, BIND_ACK) */

typedef struct relay_c {
    int      active;
    int      bound;             /* the relay sends to us: a BIND_ACK "bound", or the peer's data through it */
    uint8_t  relay_id[8];
    uint8_t  alloc_key[32];
    npf_siv_keys keys;
    struct sockaddr_storage addr[4];
    int      naddr, cur;
    uint32_t seq;
    uint8_t  cookie[8];         /* the relay's cookie for our address (RELAY_BIND_ACK), echoed in RELAY_BIND */
    uint64_t kseq;              /* the last bind's */
    int64_t  echo_ms;           /* when a challenge was last answered at once (mono ms) */
    int      tries;
    struct {                    /* the last binds: a BIND_ACK counts once, for one of them */
        uint8_t  txid[NPF_TXID_SIZE];
        uint32_t ts;
        uint64_t kseq;
        int64_t  at;            /* sent (mono ms); 0: answered */
    } sent[RELAY_SENT];
    int      nsent;
    uint64_t chal_srv;          /* srv_time_ms of the last challenge to our RELAY_DATA taken */
    int64_t  last_tx;           /* the last bind sent (mono ms) */
    npf_timer *t_bind;
    int64_t  expires;
    char     mode[8];
} relay_c;

/* a RELAY_BIND_ACK body: family | port | addr | srv_time_ms | state | cookie | kseq | flags | t_s(2) | learn(1) */
typedef struct relay_ack {
    struct sockaddr_in addr;    /* the source the relay saw (R); IPv4 only */
    int64_t  srv_ms;
    int      state;
    uint8_t  cookie[8];
    uint64_t kseq;
    int      flags;
    int      t_s, learn;        /* a spare's: the silence after which the relay pings, its learning */
    int64_t  rtt;               /* since the bind it answers (-1: a challenge to RELAY_DATA) */
} relay_ack;
/* a RELAY_PING body: family | port | addr (R) | srv_time_ms(8) | ping_id(4) | t_s(2) | learn(1) | try(1) */
typedef struct relay_ping {
    struct sockaddr_in addr;
    int64_t  srv_ms;
    uint32_t ping_id;
    int      t_s, learn, try_n;
} relay_ping;

void relay_bind_body(uint8_t out[RELAY_BIND_BODY], const uint8_t cookie[8], uint64_t kseq, int flags, uint32_t ping_id);
int  relay_ack_parse(const uint8_t *body, size_t len, relay_ack *a);
int  relay_ping_parse(const uint8_t *body, size_t len, relay_ping *p);

/* an allocation to bind from its first address: no cookie, no binds answered */
void relay_bind_take(relay_c *r, npf_node *n, const uint8_t id[8], const uint8_t key[32],
                     const struct sockaddr_storage *addr, int naddr);
/* a RELAY_BIND to the address in use, in wire (256 bytes): its length, or -1.
 * flags RELAY_F_PONG: the answer to ping_id, shorter than a bind (72..95) */
int  relay_bind_pack(relay_c *r, npf_node *n, int flags, uint32_t ping_id, uint8_t *wire);
/* the 700 ms step: 0 another bind to this address, 1 the next address, -1 every address tried */
int  relay_bind_next(relay_c *r);
int  call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
/* tests: NPF_TEST_BLOCK_RELAY="addr,url,..." makes these relay endpoints unreachable (call.c) */
int  call_relay_blocked(const npf_node *n, const char *what);
/* a datagram from one of the relay's addresses opened (plain: 2048 bytes):
 * its length; 0 from an address given up on (consumed); -1 not ours */
int  relay_bind_open(relay_c *r, const uint8_t *buf, size_t len, const struct sockaddr_storage *from, uint8_t *plain);
/* a RELAY_BIND_ACK: 1 when it answers one of our last binds (or is a new
 * challenge to our RELAY_DATA), its cookie taken; 0 not ours */
int  relay_bind_ack(relay_c *r, npf_node *n, const uint8_t *plain, size_t pl, relay_ack *a);
/* a challenge answered at once: 200 ms apart at most */
int  relay_bind_echo_due(relay_c *r);

#endif

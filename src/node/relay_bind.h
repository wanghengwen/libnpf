/* Binding a relay allocation (data-channel.md 9.2), a call's (path_udp.c)
 * or the node's spare (home.c): zero-cookie RELAY_BIND, the challenge with
 * our address's cookie, a RELAY_BIND echoing it; only BIND_ACKs answering
 * our last binds count (txid, ts_ms, kseq); the relay drops a kseq not above
 * the last it took. */
#ifndef NPF_RELAY_BIND_H
#define NPF_RELAY_BIND_H

#include "npf/sys.h"
#include <stdint.h>

#include "npf/bind.h"
#include "npf/json.h"
#include "npf/node.h"
#include "npf/siv.h"

#define LABEL_RELAY        "NPF-RELAY-v1"
#define PKT_RELAY_BIND     7
#define PKT_RELAY_BIND_ACK 8
#define PKT_RELAY_DATA     9
#define PKT_RELAY_PING     10        /* a spare's keepalive (home-binding.md 9.4) */
#define RELAY_HINT_SIZE    4         /* relay_id[0..3] in the clear before every control packet to the relay */
#define RELAY_COOKIE_SIZE  8
#define RELAY_BIND_BODY    21        /* cookie(8) | kseq(8) | flags(1) | ping_id(4) */
#define RELAY_F_PONG       1         /* RELAY_BIND flags: the answer to the ping ping_id (a spare) */
#define RELAY_F_OTHER      2         /* ... the main socket sent elsewhere since the last ping */
#define RELAY_F_NEWNET     4         /* ... the network changed: the relay learns again */
#define RELAY_ACK_BOUND    1         /* RELAY_BIND_ACK state: the relay sends to this address (0: a challenge) */
#define RELAY_BIND_MS      700       /* binding: a RELAY_BIND every 700 ms, 3 to an address, then the next */
#define RELAY_SENT         8         /* the last RELAY_BINDs whose BIND_ACK is taken */
enum { RELAY_LEARNING, RELAY_LEARNED, RELAY_UNSTABLE };   /* a spare's learning (RELAY_PING, BIND_ACK) */

/* RELAY_DATA (data-channel.md 9.2, relay_data.c): a 16-byte header, the AnLiu datagram after it */
#define LABEL_RDATA        "NPF-RDATA-v2"
#define RDATA_HINT         3         /* relay_id[0..2], masked in the header */
#define RDATA_HDR          16        /* tag(8) | hint(3) | tf(1) | seq(4), before the AnLiu datagram */
#define RDATA_ATAG         12        /* the AnLiu datagram's tag, its first bytes, covered by the header's */
#define RDATA_TF           (PKT_RELAY_DATA << 4)    /* tf: type (high 4 bits) | flags (low 4, none yet) */

/* RELAY_DATA's keys: k_tag[dir], k_mask[dir] (SipHash), bytes 0..15 and 16..31 of
 * the KDF block dir of alloc_key under LABEL_RDATA (npf_siv_derive's enc[dir]) */
typedef struct rdata_keys {
    uint8_t tag[2][16], mask[2][16];
} rdata_keys;

void rdata_derive(rdata_keys *k, const uint8_t alloc_key[32]);
/* w = header(RDATA_HDR) | the datagram (dlen >= RDATA_ATAG): the header filled in for dir, hint, seq */
void rdata_seal(const rdata_keys *k, int dir, const uint8_t hint[RDATA_HINT], uint32_t seq, uint8_t *w, size_t dlen);
/* the hint of a RELAY_DATA, unmasked (no key needed): 0, or -1 too short to be one */
int  rdata_hint(const uint8_t *w, size_t len, uint8_t hint[RDATA_HINT]);
/* verify a RELAY_DATA of dir whose unmasked hint is hint: 0 and its seq, or -1 */
int  rdata_open(const rdata_keys *k, int dir, const uint8_t hint[RDATA_HINT], const uint8_t *w, size_t len,
                uint32_t *seq);

typedef struct relay_c {
    int      active;
    int      bound;             /* the relay sends to us: a BIND_ACK "bound", or the peer's data through it */
    uint8_t  relay_id[8];
    uint8_t  alloc_key[32];
    npf_siv_keys keys;          /* the control packets */
    rdata_keys dkeys;           /* RELAY_DATA */
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
    void   (*on_send)(void *), (*on_gave_up)(void *);   /* relay_bind_run's */
    void    *arg;
} relay_c;

/* a RELAY_BIND_ACK body: family | port | addr | srv_time_ms | state | cookie | kseq | flags | t_s(2) | learn(1) */
typedef struct relay_ack {
    struct sockaddr_storage addr;   /* the source the relay saw (R); IPv4 only */
    int64_t  srv_ms;
    int      state;
    uint8_t  cookie[8];
    uint64_t kseq;
    int      t_s, learn;        /* a spare's: the silence after which the relay pings, its learning */
    int64_t  rtt;               /* since the bind it answers (-1: a challenge to RELAY_DATA) */
} relay_ack;
/* a RELAY_PING body: family | port | addr (R) | srv_time_ms(8) | ping_id(4) | t_s(2) | learn(1) | try(1) */
typedef struct relay_ping {
    struct sockaddr_storage addr;
    int64_t  srv_ms;
    uint32_t ping_id;
    int      t_s, learn;
} relay_ping;

int  relay_ping_parse(const uint8_t *body, size_t len, relay_ping *p);
/* a relay object (signaling.md "relay") at j[r]: its mode, id and key; the
 * IPv4 addresses (4 at most) into addr, their number returned; -1 no id or key */
int  relay_obj_parse(const npf_json *j, int r, char mode[8], uint8_t id[8], uint8_t key[32],
                     struct sockaddr_storage addr[4]);

/* an allocation to bind from its first address: no cookie, no binds
 * answered; addr NULL: the addresses and keys kept (a WS relay's id and key) */
void relay_bind_take(relay_c *r, npf_node *n, const uint8_t id[8], const uint8_t key[32],
                     const struct sockaddr_storage *addr, int naddr);
/* a RELAY_BIND to the address in use, in wire (256 bytes): its length, or -1.
 * flags RELAY_F_PONG: the answer to ping_id, shorter than a bind (72..95) */
int  relay_bind_pack(relay_c *r, npf_node *n, int flags, uint32_t ping_id, uint8_t *wire);
/* binding from the first address: send(arg) now and every RELAY_BIND_MS
 * (3 to an address, then the next), gave_up(arg) once every address was
 * tried; the owner stops r->t_bind when it is bound */
void relay_bind_run(relay_c *r, npf_loop *l, void (*on_send)(void *), void (*on_gave_up)(void *), void *arg);
int  call_same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
/* tests: NPF_TEST_BLOCK_RELAY="addr,url,..." makes these relay endpoints unreachable (path_udp.c) */
int  call_relay_blocked(const npf_node *n, const char *what);
/* a datagram from one of the relay's addresses opened (plain: 2048 bytes):
 * its length; 0 from an address given up on (consumed); -1 not ours */
int  relay_bind_open(relay_c *r, const uint8_t *buf, size_t len, const struct sockaddr_storage *from, uint8_t *plain);
/* from: which of the relay's addresses (-1 none) */
int  relay_addr_index(const relay_c *r, const struct sockaddr_storage *from);
/* an authenticated datagram from the relay's address i: 1 to take, 0 from
 * an address given up on (consumed); a late answer of an address tried
 * earlier while binding makes it the one in use */
int  relay_addr_take(relay_c *r, int i);
/* a RELAY_DATA from the relay to r (hint: its unmasked hint): 1 to take
 * (the datagram at RDATA_HDR), 0 consumed, -1 not ours */
int  relay_data_open(relay_c *r, const uint8_t hint[RDATA_HINT], const uint8_t *buf, size_t len,
                     const struct sockaddr_storage *from);
/* a RELAY_DATA to the relay: dgram (len bytes) into wire (2048 bytes),
 * its length; 0 too long or too short (RDATA_ATAG at least) */
size_t relay_data_pack(relay_c *r, const uint8_t *dgram, size_t len, uint8_t *wire);
/* a RELAY_BIND_ACK: 1 when it answers one of our last binds (or is a new
 * challenge to our RELAY_DATA), its cookie taken; 0 not ours */
int  relay_bind_ack(relay_c *r, npf_node *n, const uint8_t *plain, size_t pl, relay_ack *a);
/* a challenge answered at once: 200 ms apart at most */
int  relay_bind_echo_due(relay_c *r);

#endif

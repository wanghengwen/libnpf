/* Address-probe packets between a device and a probe server (nat-traversal.md 6.2-6.4).
 *
 *   wire = tag(12) || ChaCha20(k_enc[dir], nonce = tag, P)
 *   P    = type(1) | flags(1) | body_len(2) | txid(12) | ts_ms(4) | body | pad
 *
 * Integers are little-endian (as in AnLiu); IP addresses are in network order. */
#ifndef NPF_BIND_H
#define NPF_BIND_H

#include <stddef.h>
#include <stdint.h>
#include "npf/sys.h"

#include "npf/siv.h"

/* packet types (shared numbering with the punch packets of 6.5) */
#define NPF_PKT_BIND_REQ      1
#define NPF_PKT_BIND_RESP     2

/* key directions */
#define NPF_DIR_REQ           0     /* device -> probe server */
#define NPF_DIR_RESP          1     /* probe server -> device */

#define NPF_PKT_HDR_SIZE      20    /* type .. ts_ms */
#define NPF_TXID_SIZE         12
#define NPF_TICKET_SIZE       28    /* id(8) | expire(4) | mac(16) */

/* wire length ranges (6.3/6.4) */
#define NPF_BIND_REQ_MIN      96
#define NPF_BIND_REQ_MAX      200
#define NPF_BIND_RESP_MIN     64
#define NPF_PKT_MAX           1500

typedef struct npf_pkt {
    int      type;
    uint8_t  txid[NPF_TXID_SIZE];
    uint32_t ts_ms;
    const uint8_t *body;        /* points into the caller's plaintext buffer */
    size_t   body_len;
} npf_pkt;

/* Build a sealed packet of exactly wire_len bytes into out (random padding).
 * Returns wire_len, or -1 if the body does not fit. */
int npf_pkt_seal(const npf_siv_keys *keys, int dir, int type, const uint8_t txid[NPF_TXID_SIZE],
                 uint32_t ts_ms, const uint8_t *body, size_t body_len, size_t wire_len, uint8_t *out);

/* Verify, decrypt and parse. plain needs len bytes. Returns 0 or -1. */
int npf_pkt_open(const npf_siv_keys *keys, int dir, const uint8_t *in, size_t len,
                 uint8_t *plain, npf_pkt *pkt);

/* BIND_RESP body: family(1) | port(2) | addr(4 or 16) | srv_time_ms(8) */
typedef struct npf_bind_resp {
    int      family;            /* 4 or 6 */
    uint16_t port;
    uint8_t  addr[16];
    uint64_t srv_time_ms;
} npf_bind_resp;

int npf_bind_resp_parse(const npf_pkt *pkt, npf_bind_resp *resp);

/* uniform random integer in [lo, hi] */
size_t npf_rand_range(size_t lo, size_t hi);

/* One BIND_REQ/RESP exchange on an already-open UDP socket `fd` against `ep`,
 * using probe keys `keys` and `ticket`. `offset_ms` is added to the local clock
 * for ts_ms. On success writes the mapped address to `mapped` and returns 0;
 * -1 on timeout. Retransmits at 0/200/600 ms. */
int npf_bind_query(int fd, const struct sockaddr_in *ep, const npf_siv_keys *keys,
                   const uint8_t *ticket, size_t ticket_len, int64_t offset_ms,
                   struct sockaddr_in *mapped, int timeout_ms);

#endif

/* The node's cost per relayed datagram (data-channel.md 9.2): sealing a
 * RELAY_DATA to the relay and opening one from it, against the SIV
 * encapsulation it had until 2026-10-28 (ChaCha20 and SipHash over all of
 * it, written out here for the comparison only). Not a test:
 * npf_relayprobe [bytes] [rounds]. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "npf/crypto.h"
#include "npf/platform.h"
#include "relay_bind.h"

static double now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

/* the old RELAY_DATA to the relay: hint(4) | tag(12) | ChaCha20(type | flags | seq | datagram) */
static size_t siv_pack(relay_c *r, const uint8_t *dgram, size_t len, uint8_t *wire)
{
    uint8_t *w = wire + RELAY_HINT_SIZE, *p = w + NPF_SIV_TAG_SIZE;
    memcpy(wire, r->relay_id, RELAY_HINT_SIZE);
    p[0] = PKT_RELAY_DATA;
    p[1] = 0;
    npf_le32(p + 2, r->seq++);
    memcpy(p + 6, dgram, len);
    npf_siv_seal(&r->keys, NPF_DIR_REQ, w, len + 6);
    return len + RELAY_HINT_SIZE + NPF_SIV_TAG_SIZE + 6;
}

int main(int argc, char **argv)
{
    static relay_c r;
    size_t len = argc > 1 ? (size_t)atoi(argv[1]) : 1200, wl;
    long rounds = argc > 2 ? atol(argv[2]) : 200000, i;
    uint8_t dgram[2048], wire[2048], plain[2048], hint[RDATA_HINT];
    volatile unsigned sink = 0;
    int now_fmt;
    if (len < RDATA_ATAG || len > 2000)
        return 2;
    npf_random(r.relay_id, 8);
    npf_random(r.alloc_key, 32);
    npf_random(dgram, len);
    npf_siv_derive(&r.keys, r.alloc_key, LABEL_RELAY);
    rdata_derive(&r.dkeys, r.alloc_key);
    for (now_fmt = 0; now_fmt < 2; now_fmt++) {
        double t0, t1, t2;
        t0 = now_ns();
        for (i = 0; i < rounds; i++)
            sink += (unsigned)(now_fmt ? relay_data_pack(&r, dgram, len, wire) : siv_pack(&r, dgram, len, wire));
        t1 = now_ns();
        /* what comes from the relay */
        if (!now_fmt) {
            uint8_t *p = wire + NPF_SIV_TAG_SIZE;
            p[0] = PKT_RELAY_DATA, p[1] = 0;
            npf_le32(p + 2, 1);
            memcpy(p + 6, dgram, len);
            npf_siv_seal(&r.keys, NPF_DIR_RESP, wire, len + 6);
            wl = NPF_SIV_TAG_SIZE + 6 + len;
        } else {
            memcpy(wire + RDATA_HDR, dgram, len);
            rdata_seal(&r.dkeys, NPF_DIR_RESP, r.relay_id, 1, wire, len);
            wl = RDATA_HDR + len;
        }
        t2 = now_ns();
        for (i = 0; i < rounds; i++) {
            uint32_t seq;
            if (!now_fmt)
                sink += (unsigned)npf_siv_open(&r.keys, NPF_DIR_RESP, wire, wl, plain);
            else
                sink += (unsigned)(rdata_hint(wire, wl, hint) + rdata_open(&r.dkeys, NPF_DIR_RESP, hint, wire, wl, &seq));
        }
        t2 = now_ns() - t2;
        printf("%s %zu bytes: seal %.0f ns, open %.0f ns (from the relay %zu bytes)\n",
               now_fmt ? "header only" : "old SIV   ", len, (t1 - t0) / (double)rounds, t2 / (double)rounds, wl);
    }
    return sink == 12345 ? 1 : 0;
}

/* Media streams on the WS relay (node/media.c) with a fake connection: a
 * send never blocks; while the connection is backlogged frames wait, those
 * older than max_age are dropped, and with drop_until_key the frames up to
 * the next key frame too; the receiver gets lost_before; a large frame goes
 * in pieces and arrives whole; a stream's queue has a limit. A peer that
 * sends pieces beyond the frame limit, or interleaves frames in pieces,
 * loses those frames: reassembly stays bounded. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "media.h"
#include "npf/platform.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* the fake connection: records and units kept, the backlog set by the test */
typedef struct fake {
    size_t   pending;
    uint64_t total;
    uint8_t *rec[64];
    size_t   rec_len[64];
    int      nrec;
    uint8_t  unit[16][16];
    size_t   unit_len[16];
    int      nunit;
    /* receiver */
    int      frames;
    uint32_t last_fno, last_lost;
    size_t   last_len;
    int      last_ok;
    npf_media *media;
    int close_on_open;
} fake;

static int f_unit(void *arg, const uint8_t *buf, size_t len)
{
    fake *f = arg;
    if (f->nunit < 16 && len <= 16) {
        memcpy(f->unit[f->nunit], buf, len);
        f->unit_len[f->nunit++] = len;
    }
    return 0;
}

static int f_ws_write(void *arg, const uint8_t *buf, size_t len)
{
    fake *f = arg;
    if (f->nrec < 64 && (f->rec[f->nrec] = malloc(len))) {
        memcpy(f->rec[f->nrec], buf, len);
        f->rec_len[f->nrec++] = len;
    }
    f->total += len;
    return 0;
}

static void f_backlog(void *arg, size_t *pending, uint64_t *total)
{
    fake *f = arg;
    *pending = f->pending;
    *total = f->total;
}

static void f_kick(void *arg) { (void)arg; }
static int f_open(void *arg, uint32_t id, int tag)
{
    fake *f = arg;
    if (f->close_on_open)
        CHECK(npf_media_close_stream(f->media, id) == 0, "close inside open callback");
    return tag == 7;
}
static void f_closed(void *arg, uint32_t id) { (void)arg; (void)id; }
static int f_ended(void *arg) { (void)arg; return 0; }

static void f_frame(void *arg, uint32_t id, const uint8_t *buf, size_t len, uint32_t fno, int flags, uint32_t lost)
{
    fake *f = arg;
    size_t i;
    (void)id;
    (void)flags;
    f->frames++;
    f->last_fno = fno;
    f->last_lost = lost;
    f->last_len = len;
    f->last_ok = 1;
    for (i = 0; i < len; i++)
        if (buf[i] != (uint8_t)(i * 7 + fno))
            f->last_ok = 0;
}

static const npf_media_io io = {f_unit, f_ws_write, f_backlog, f_kick, f_open, f_frame, f_closed, f_ended};

static void frame(uint8_t *b, size_t len, uint32_t fno)
{
    size_t i;
    for (i = 0; i < len; i++)
        b[i] = (uint8_t)(i * 7 + fno);
}

int test_media(void)
{
    npf_loop *loop = npf_loop_new();
    fake tx, rx;
    npf_media *a, *b;
    npf_call_media_opt o;
    npf_call_media_stats st;
    uint8_t *big = malloc(200000), small[100];
    uint32_t id;
    int e = 0, i;
    memset(&tx, 0, sizeof tx);
    memset(&rx, 0, sizeof rx);
    a = npf_media_new(loop, NULL, 0, &io, &tx);
    b = npf_media_new(loop, NULL, 1, &io, &rx);
    memset(&o, 0, sizeof o);
    o.tag = 7;
    o.prio = 1;
    o.max_age_ms = 50;
    o.drop_until_key = 1;
    id = npf_media_open_stream(a, &o, &e);
    CHECK(id && (id & 1) == 0 && tx.nunit == 1 && tx.unit[0][0] == 1, "open: an OPEN unit, an even id");
    npf_media_unit_input(b, tx.unit[0], tx.unit_len[0]);
    CHECK(npf_media_count(b) == 1, "the receiver took it");

    /* backlogged: the frames wait (send returns at once) */
    tx.pending = 10u << 20;
    for (i = 0; i < 3; i++) {
        frame(small, sizeof small, (uint32_t)i);
        CHECK(npf_media_send_frame(a, id, i == 0, small, sizeof small, 0) == 0, "send while backlogged");
    }
    CHECK(tx.nrec == 0 && npf_media_ws_queued(a) == 3 * sizeof small, "nothing written, 3 frames queued");
    npf_sleep_ms(80);
    /* drained: the old ones go, and the next non-key frame (no key frame before it) */
    tx.pending = 0;
    frame(small, sizeof small, 3);
    npf_media_send_frame(a, id, 0, small, sizeof small, 0);
    CHECK(tx.nrec == 0, "expired frames and the non-key frame after them dropped");
    frame(small, sizeof small, 4);
    npf_media_send_frame(a, id, 1, small, sizeof small, 0);
    CHECK(tx.nrec == 1, "the key frame written");
    CHECK(npf_media_stream_stats(a, id, &st) == 0 && st.frames_dropped == 4 && st.capacity_short == 1,
          "stats: 4 dropped, capacity short (%u)", st.frames_dropped);
    npf_media_ws_input(b, tx.rec[0], tx.rec_len[0]);
    CHECK(rx.frames == 1 && rx.last_fno == 4 && rx.last_lost == 4 && rx.last_ok, "receiver: frame 4, 4 lost before");

    /* a large frame in pieces */
    frame(big, 200000, 5);
    npf_media_send_frame(a, id, 1, big, 200000, 0);
    CHECK(tx.nrec == 5, "200000 bytes in 4 records (%d)", tx.nrec - 1);
    for (i = 1; i < tx.nrec; i++)
        npf_media_ws_input(b, tx.rec[i], tx.rec_len[i]);
    CHECK(rx.frames == 2 && rx.last_len == 200000 && rx.last_ok && rx.last_lost == 0, "the large frame whole");

    /* the queue limit: the oldest go, the send never blocks */
    tx.pending = 10u << 20;
    o.max_age_ms = 0;                       /* never too old: only the limit drops */
    o.drop_until_key = 0;
    o.tag = 7;
    {
        uint32_t id2 = npf_media_open_stream(a, &o, &e);
        for (i = 0; i < 100; i++)
            npf_media_send_frame(a, id2, 0, big, 200000, 0);
        CHECK(npf_media_ws_queued(a) <= (2u << 20) && npf_media_ws_queued(a) >= 2000000, "queue capped at 2 MiB (%zu)",
              npf_media_ws_queued(a));
        CHECK(npf_media_stream_stats(a, id2, &st) == 0 && st.frames_dropped > 50, "the oldest dropped");
        CHECK(npf_media_close_stream(a, id2) == 0 && npf_media_ws_queued(a) == 0, "close frees the queue");
    }

    {
        uint32_t tiny = npf_media_open_stream(a, &o, &e);
        for (i = 0; i < 5000; i++)
            npf_media_send_frame(a, tiny, 0, small, 1, 0);
        CHECK(npf_media_ws_queued(a) == 4096, "tiny frames are bounded by the frame count");
        CHECK(npf_media_stream_stats(a, tiny, &st) == 0 && st.frames_dropped == 904,
              "oldest tiny frames dropped at 4096 entries");
        npf_media_close_stream(a, tiny);
    }

    {
        uint8_t *huge = malloc((2u << 20) + 1);
        uint32_t large = npf_media_open_stream(a, &o, &e);
        CHECK(huge && npf_media_send_frame(a, large, 1, huge, (2u << 20) + 1, 0) == NPF_CALL_ETOOBIG,
              "a single frame cannot exceed the 2 MiB WS queue");
        CHECK(npf_media_ws_queued(a) == 0, "oversized frame allocates no queue");
        free(huge);
        npf_media_close_stream(a, large);
    }
    {
        int before = npf_media_count(b);
        rx.media = b;
        rx.close_on_open = 1;
        tx.nunit = 0;
        npf_media_open_stream(a, &o, &e);
        npf_media_unit_input(b, tx.unit[0], tx.unit_len[0]);
        CHECK(npf_media_count(b) == before, "closing in open callback leaves no ghost stream");
        rx.close_on_open = 0;
    }

    /* refused: CLOSE back */
    o.tag = 8;
    tx.nunit = 0;
    id = npf_media_open_stream(a, &o, &e);
    rx.nunit = 0;
    npf_media_unit_input(b, tx.unit[0], tx.unit_len[0]);
    CHECK(rx.nunit == 1 && rx.unit[0][0] == 2, "a refused stream: CLOSE back");
    npf_media_unit_input(a, rx.unit[0], rx.unit_len[0]);
    CHECK(npf_media_send_frame(a, id, 0, small, 10, 0) == NPF_CALL_ENOENT, "the sender's stream is gone");

    /* a peer's records, made here: pieces beyond 4 MB are dropped, the
     * next frame comes through */
    {
        static uint8_t rec[9 + 65526];
        uint32_t sid;
        int k, before;
        o.tag = 7;
        tx.nunit = 0;
        sid = npf_media_open_stream(a, &o, &e);
        npf_media_unit_input(b, tx.unit[0], tx.unit_len[0]);
        before = rx.frames;
        for (k = 0; k < 80; k++) {           /* 80 x 64 KB = 5 MB, all "more" */
            memset(rec, 0, sizeof rec);
            rec[0] = (uint8_t)sid;
            rec[1] = (uint8_t)(sid >> 8);
            rec[4] = 3;                     /* frame_no 3 */
            rec[8] = 0x80 | (k == 0);
            npf_media_ws_input(b, rec, sizeof rec);
        }
        rec[8] = 0;                         /* the last piece */
        npf_media_ws_input(b, rec, 100);
        CHECK(rx.frames == before, "a frame above 4 MB is not delivered");
        rec[4] = 4;                         /* the next frame, whole */
        rec[8] = 1;
        frame(rec + 9, 50, 4);
        npf_media_ws_input(b, rec, 9 + 50);
        CHECK(rx.frames == before + 1 && rx.last_fno == 4 && rx.last_ok, "the next frame comes through");
        /* interleaved: a frame in pieces, then another stream's record */
        {
            uint32_t sid2;
            tx.nunit = 0;
            sid2 = npf_media_open_stream(a, &o, &e);
            npf_media_unit_input(b, tx.unit[0], tx.unit_len[0]);
            rec[4] = 5;
            rec[8] = 0x80;
            npf_media_ws_input(b, rec, 9 + 1000);       /* stream 1, frame 5 in pieces */
            rec[0] = (uint8_t)sid2;
            rec[1] = (uint8_t)(sid2 >> 8);
            rec[4] = 0;
            rec[8] = 1;
            frame(rec + 9, 50, 0);
            npf_media_ws_input(b, rec, 9 + 50);         /* stream 2: frame 5 of stream 1 is gone */
            rec[0] = (uint8_t)sid;
            rec[1] = (uint8_t)(sid >> 8);
            rec[4] = 5;
            rec[8] = 1;
            frame(rec + 9, 50, 5);
            npf_media_ws_input(b, rec, 9 + 50);         /* its last piece alone: a whole frame of 50 */
            CHECK(rx.frames == before + 3 && rx.last_len == 50 && rx.last_ok, "interleaved pieces: the partial frame dropped");
        }
    }

    for (i = 0; i < tx.nrec; i++)
        free(tx.rec[i]);
    free(big);
    npf_media_free(a);
    npf_media_free(b);
    npf_loop_free(loop);
    return fails;
}

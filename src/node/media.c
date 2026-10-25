/* Media streams of a session (media.h; data-channel.md 14).
 *
 * On AnLiu (the direct path, the UDP relay) a media stream is a
 * semi-reliable AnLiu stream of its own: opened for it, closed with it (the
 * close tells the peer), its frames as they are - no header of ours; the
 * frame number, key flag and loss counts are AnLiu's. The AnLiu tag says
 * what it is: NPF_TAG_MEDIA + the application's tag, NPF_MEDIA_TAG_RDK set
 * when the receiver should drop non-key frames after a loss.
 *
 * On the WS relay (no AnLiu) the streams share one ordered byte stream:
 *   MEDIA unit (control channel): op(1) | id(4) | ...
 *     OPEN=1   id | tag(2) | flags(1)   bit 0: the receiver drops non-key frames after a loss
 *     CLOSE=2  id                       either side: the stream is over (also: refused)
 *   WS record (channel 2):    id(4) | frame_no(4) | flags(1) | piece
 *     flags bit 0 key, bit 7 more pieces follow (a record holds < 64 KB)
 * Ids there: the opener's counter << 1 | its side (callee 1), never reused. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "media.h"
#include "npf/crypto.h"
#include "npf/log.h"
#include "npf/platform.h"

enum { OP_OPEN = 1, OP_CLOSE = 2 };

#define WS_HDR       9              /* id | frame_no | flags */
#define WS_MORE      0x80
#define WS_PIECE     (65535 - WS_HDR)
#define WS_TICK_MS   10
#define WS_QUEUE_MAX (2u << 20)     /* bytes per stream waiting for the relay */

typedef struct qframe {
    struct qframe *next;
    int64_t  t;
    int      flags;
    uint32_t fno;
    size_t   len;
    uint8_t  d[];
} qframe;

typedef struct mst {
    uint32_t id;
    int      tag, out;
    anl_stream_t *s;                /* AnLiu: its stream; NULL on the WS relay */
    int      asked;                 /* AnLiu, the peer's: the application said yes */
    /* sending */
    uint32_t next_fno;              /* the WS relay's frame numbers */
    int      prio, max_age_ms, drop_until_key;
    qframe  *qh, *qt;               /* WS relay */
    size_t   qbytes;
    unsigned qcount;
    int      need_key;
    uint32_t dropped;               /* too old before AnLiu / the relay took them */
    /* receiving (WS relay) */
    uint32_t expect, lost;
    int      wait_key, rcv_drop_until_key;
    uint32_t skipped;
    uint8_t *frag;                  /* a frame in pieces */
    size_t   frag_len;
    uint32_t frag_fno;
    int      frag_skip;             /* the frame in pieces is too large: drop its pieces */
} mst;

struct npf_media {
    npf_loop    *loop;
    anl_t       *anl;
    int          odd;
    npf_media_io io;
    void        *arg;
    mst         *st[NPF_MEDIA_MAX];
    int          nst;
    uint32_t     next_id, peer_max;
    int          nout;              /* AnLiu: streams opened here */
    int          nin;               /* AnLiu: streams the peer opened */
    int          warned;            /* a peer's stream was refused (logged once) */
    uint32_t     frag_id;           /* WS relay: the stream whose frame is in pieces (0: none) */
    npf_timer   *t_ws;
    /* WS relay: what the connection drains while backlogged (bytes/s) */
    int64_t      rate_t, drop_t;
    uint64_t     rate_wire;
    uint32_t     rate;
};

/* ---- helpers ---- */

static int find(const npf_media *m, uint32_t id)
{
    int i;
    for (i = 0; i < m->nst; i++)
        if (m->st[i]->id == id)
            return i;
    return -1;
}

static int find_s(const npf_media *m, const anl_stream_t *s)
{
    int i;
    for (i = 0; s && i < m->nst; i++)
        if (m->st[i]->s == s)
            return i;
    return -1;
}

static int unit(npf_media *m, int op, uint32_t id, int tag, int flags)
{
    uint8_t b[8];
    size_t n = 5;
    b[0] = (uint8_t)op;
    npf_le32(b + 1, id);
    if (op == OP_OPEN) {
        npf_le16(b + 5, (uint16_t)tag);
        b[7] = (uint8_t)flags;
        n = 8;
    }
    return m->io.unit(m->arg, b, n);
}

static void queue_free(mst *s)
{
    while (s->qh) {
        qframe *f = s->qh;
        s->qh = f->next;
        free(f);
    }
    s->qt = NULL;
    s->qbytes = 0;
    s->qcount = 0;
}

/* forget stream i (its AnLiu stream is the caller's business) */
static void drop_stream(npf_media *m, int i)
{
    mst *s = m->st[i];
    if (s->out && s->s)
        m->nout--;
    else if (!s->out && s->s && m->nin > 0)
        m->nin--;
    queue_free(s);
    if (m->frag_id == s->id)
        m->frag_id = 0;
    free(s->frag);
    free(s);
    m->st[i] = m->st[--m->nst];
}

static uint32_t new_id(npf_media *m)
{
    if (!++m->next_id)
        m->next_id = 1;
    return m->next_id << 1 | (uint32_t)m->odd;
}

/* ---- life ---- */

npf_media *npf_media_new(npf_loop *loop, anl_t *anl, int odd, const npf_media_io *io, void *arg)
{
    npf_media *m = calloc(1, sizeof *m);
    if (!m)
        return NULL;
    m->loop = loop;
    m->anl = anl;
    m->odd = odd ? 1 : 0;
    m->io = *io;
    m->arg = arg;
    return m;
}

void npf_media_free(npf_media *m)
{
    if (!m)
        return;
    if (m->t_ws)
        npf_timer_cancel(m->loop, m->t_ws);
    while (m->nst)
        drop_stream(m, m->nst - 1);
    /* AnLiu streams go with the connection */
    free(m);
}

int npf_media_count(const npf_media *m)
{
    return m ? m->nst : 0;
}

/* ---- receiving ---- */

static void deliver(npf_media *m, mst *s, uint32_t fno, int flags, const uint8_t *d, size_t len)
{
    uint32_t id = s->id, lost;
    if ((int32_t)(fno - s->expect) < 0)
        return;                             /* older than one delivered */
    lost = fno - s->expect;
    s->expect = fno + 1;
    s->lost += lost;
    if (lost && s->rcv_drop_until_key)
        s->wait_key = 1;
    if (s->wait_key) {
        if (!(flags & NPF_FRAME_KEY_FLAG)) {
            s->skipped++;
            s->lost++;
            return;
        }
        s->wait_key = 0;
    }
    lost = s->lost;
    s->lost = 0;
    m->io.on_frame(m->arg, id, d, len, fno, flags & NPF_FRAME_KEY_FLAG, lost);
}

static void frag_reset(npf_media *m, mst *s)
{
    free(s->frag);
    s->frag = NULL;
    s->frag_len = 0;
    s->frag_skip = 0;
    if (m->frag_id == s->id)
        m->frag_id = 0;
}

/* A frame in pieces: the sender writes a frame's pieces one after the other,
 * so at most one frame of the session is in pieces at a time, and it is
 * never above NPF_MEDIA_FRAME_MAX; a peer that does otherwise loses the
 * frame (reassembly is bounded by 4 MB per session). */
void npf_media_ws_input(npf_media *m, const uint8_t *buf, size_t len)
{
    uint32_t id, fno;
    int flags, i;
    mst *s;
    if (len < WS_HDR)
        return;
    id = npf_rd32(buf);
    fno = npf_rd32(buf + 4);
    flags = buf[8];
    buf += WS_HDR;
    len -= WS_HDR;
    if (m->frag_id && m->frag_id != id && (i = find(m, m->frag_id)) >= 0)
        frag_reset(m, m->st[i]);            /* another stream: that frame never ends */
    if ((i = find(m, id)) < 0 || m->st[i]->out)
        return;
    s = m->st[i];
    if ((s->frag || s->frag_skip) && s->frag_fno != fno)
        frag_reset(m, s);
    if ((flags & WS_MORE) || s->frag || s->frag_skip) {
        uint8_t *q;
        s->frag_fno = fno;
        m->frag_id = id;
        if (!s->frag_skip && s->frag_len + len > NPF_MEDIA_FRAME_MAX) {
            free(s->frag);
            s->frag = NULL;
            s->frag_len = 0;
            s->frag_skip = 1;               /* too large: its other pieces go too */
        }
        if (s->frag_skip) {
            if (!(flags & WS_MORE))
                frag_reset(m, s);
            return;
        }
        if (!(q = realloc(s->frag, s->frag_len + len + 1))) {
            frag_reset(m, s);
            s->frag_skip = (flags & WS_MORE) != 0;
            return;
        }
        s->frag = q;
        memcpy(s->frag + s->frag_len, buf, len);
        s->frag_len += len;
        if (flags & WS_MORE)
            return;
        q = s->frag;
        len = s->frag_len;
        s->frag = NULL;
        s->frag_len = 0;
        m->frag_id = 0;
        deliver(m, s, fno, flags & 1 ? NPF_FRAME_KEY_FLAG : 0, q, len);
        free(q);
        return;
    }
    deliver(m, s, fno, flags & 1 ? NPF_FRAME_KEY_FLAG : 0, buf, len);
}

/* ---- MEDIA units (WS relay) ---- */

void npf_media_unit_input(npf_media *m, const uint8_t *b, size_t len)
{
    uint32_t id;
    int i, op;
    if (len < 5 || m->anl)
        return;
    op = b[0];
    id = npf_rd32(b + 1);
    if (op == OP_OPEN && len >= 8) {
        mst *s;
        if ((id & 1) == (uint32_t)m->odd || (int32_t)(id - m->peer_max) <= 0)
            return;
        m->peer_max = id;
        if (m->nst == NPF_MEDIA_MAX || !(s = calloc(1, sizeof *s))) {
            unit(m, OP_CLOSE, id, 0, 0);
            return;
        }
        s->id = id;
        s->tag = npf_rd16(b + 5);
        s->rcv_drop_until_key = b[7] & 1;
        s->asked = 1;
        m->st[m->nst++] = s;     /* callbacks may close it immediately */
        if (!m->io.on_open(m->arg, id, s->tag) && (i = find(m, id)) >= 0) {
            drop_stream(m, i);
            unit(m, OP_CLOSE, id, 0, 0);
        }
        return;
    }
    if (op == OP_CLOSE) {
        if ((i = find(m, id)) < 0)
            return;
        drop_stream(m, i);
        m->io.on_closed(m->arg, id);
    }
}

/* ---- AnLiu: a stream per media stream ---- */

/* the accept callback: AnLiu allows no other call from here, so the
 * application is asked after the input (npf_media_poll) */
int npf_media_accept(npf_media *m, anl_stream_t *s, anl_stream_opt *opt)
{
    int tag = anl_stream_tag(s) & ~NPF_MEDIA_TAG_RDK;
    mst *x;
    if (opt->mode != ANL_SEMI || tag < NPF_TAG_MEDIA || tag >= NPF_TAG_MEDIA + NPF_MEDIA_TAGS
        || m->nst == NPF_MEDIA_MAX)
        return -1;
    /* what the peer may make this end hold: as many streams as one side
     * opens, each with the window both use (media.h) */
    if (opt->rcv_wnd > NPF_ANL_MEDIA_WND || m->nin >= NPF_MEDIA_OUT_MAX) {
        if (!m->warned) {
            m->warned = 1;
            npf_logw("media: the peer's stream refused (%s)", m->nin >= NPF_MEDIA_OUT_MAX ? "too many streams"
                                                                                          : "receive window too large");
        }
        return -1;
    }
    if (!(x = calloc(1, sizeof *x)))
        return -1;
    opt->rcv_drop_until_key = (anl_stream_tag(s) & NPF_MEDIA_TAG_RDK) != 0;
    x->id = new_id(m);
    x->tag = tag - NPF_TAG_MEDIA;
    x->s = s;
    m->st[m->nst++] = x;
    m->nin++;
    return 0;
}

int npf_media_is_stream(const npf_media *m, anl_stream_t *s)
{
    return m && find_s(m, s) >= 0;
}

/* streams the peer opened since: the application takes them or not (a
 * refused one is closed: the peer's end is over). -1 when a callback ended
 * the session */
int npf_media_poll(npf_media *m)
{
    int i;
    for (i = 0; m && i < m->nst; i++) {
        mst *x = m->st[i];
        uint32_t id = x->id;
        if (x->out || x->asked || !x->s)
            continue;
        x->asked = 1;
        if (!m->io.on_open(m->arg, id, x->tag)) {
            if ((i = find(m, id)) >= 0) {
                anl_stream_close(m->st[i]->s);
                drop_stream(m, i);
            }
            i = -1;                         /* the table changed: from the start */
        }
        if (m->io.ended && m->io.ended(m->arg))
            return -1;
    }
    return 0;
}

/* a stream is readable: its frames to the application, or its end */
int npf_media_drain(npf_media *m, anl_stream_t *s)
{
    for (;;) {
        anl_frame_info fi;
        char small[2048], *buf = small;
        int i = find_s(m, s), sz, r;
        uint32_t id;
        if (i < 0)
            return 0;
        id = m->st[i]->id;
        sz = anl_stream_peeksize(s);
        if (sz == ANL_ECLOSED) {            /* closed (or refused) by the peer */
            anl_stream_close(s);
            drop_stream(m, i);
            m->io.on_closed(m->arg, id);
            return m->io.ended && m->io.ended(m->arg) ? -1 : 0;
        }
        if (sz < 0 || m->st[i]->out || !m->st[i]->asked)
            return 0;                       /* ours sends only; not taken yet: it waits in AnLiu */
        if (sz > NPF_MEDIA_FRAME_MAX) {
            anl_stream_close(s);
            drop_stream(m, i);
            m->io.on_closed(m->arg, id);
            return m->io.ended && m->io.ended(m->arg) ? -1 : 0;
        }
        if (sz > (int)sizeof small && !(buf = malloc((size_t)sz)))
            return 0;
        r = anl_stream_recv_frame(s, buf, sz > (int)sizeof small ? sz : (int)sizeof small, &fi);
        if (r >= 0)
            m->io.on_frame(m->arg, id, (const uint8_t *)buf, (size_t)r, fi.frame_no,
                           (fi.flags & ANL_FRAME_KEY) ? NPF_FRAME_KEY_FLAG : 0, fi.lost_before);
        if (buf != small)
            free(buf);
        if (r < 0)
            return 0;
        if (m->io.ended && m->io.ended(m->arg))
            return -1;
    }
}

/* ---- WS relay: the queues ---- */

static void ws_tick(npf_loop *loop, void *arg);

static void rate_sample(npf_media *m, size_t pending, uint64_t total)
{
    int64_t now = npf_mono_ms();
    uint64_t wire = total > pending ? total - pending : 0;
    if (!m->rate_t) {
        m->rate_t = now;
        m->rate_wire = wire;
        return;
    }
    if (now - m->rate_t < 200)
        return;
    if (pending > 16384 && wire >= m->rate_wire) {  /* backlogged: the drain is what the path carries */
        uint32_t r = (uint32_t)((wire - m->rate_wire) * 1000 / (uint64_t)(now - m->rate_t));
        m->rate = m->rate ? (m->rate * 3 + r) / 4 : r;
    }
    m->rate_t = now;
    m->rate_wire = wire;
}

static int ws_write_frame(npf_media *m, mst *s, const qframe *f)
{
    uint8_t *rec = npf_scratch(WS_HDR + WS_PIECE);
    size_t off = 0;
    int r = 0;
    if (!rec)
        return -1;
    do {
        size_t n = f->len - off > WS_PIECE ? WS_PIECE : f->len - off;
        npf_le32(rec, s->id);
        npf_le32(rec + 4, f->fno);
        rec[8] = (uint8_t)((f->flags & NPF_FRAME_KEY_FLAG ? 1 : 0) | (off + n < f->len ? WS_MORE : 0));
        memcpy(rec + WS_HDR, f->d + off, n);
        if (m->io.ws_write(m->arg, rec, WS_HDR + n) < 0) {
            r = -1;
            break;
        }
        off += n;
    } while (off < f->len);
    npf_scratch_done(rec);
    return r;
}

/* drop what is too old at the head of each queue */
static void ws_expire(npf_media *m, int64_t now)
{
    int i;
    for (i = 0; i < m->nst; i++) {
        mst *s = m->st[i];
        while (s->qh) {
            qframe *f = s->qh;
            int old = s->max_age_ms > 0 && now - f->t > s->max_age_ms;
            if (!old && !(s->need_key && !(f->flags & NPF_FRAME_KEY_FLAG)))
                break;
            if (old && s->drop_until_key)
                s->need_key = 1;            /* what follows cannot be decoded without it */
            s->qh = f->next;
            if (!s->qh)
                s->qt = NULL;
            s->qbytes -= f->len;
            s->qcount--;
            s->dropped++;
            m->drop_t = now;
            free(f);
        }
        if (s->qh && (s->qh->flags & NPF_FRAME_KEY_FLAG))
            s->need_key = 0;
    }
}

static void ws_pump(npf_media *m)
{
    size_t pending = 0, high;
    uint64_t total = 0;
    int64_t now = npf_mono_ms();
    int waiting = 0, i;
    m->io.ws_backlog(m->arg, &pending, &total);
    rate_sample(m, pending, total);
    /* about 200 ms of what the path carries may wait in the connection */
    high = m->rate ? m->rate / 5 : 256 * 1024;
    if (high < 32 * 1024)
        high = 32 * 1024;
    ws_expire(m, now);
    while (pending < high) {
        mst *best = NULL;
        qframe *f;
        for (i = 0; i < m->nst; i++) {
            mst *s = m->st[i];
            if (s->qh && (!best || s->prio < best->prio || (s->prio == best->prio && s->qh->t < best->qh->t)))
                best = s;
        }
        if (!best)
            break;
        f = best->qh;
        best->qh = f->next;
        if (!best->qh)
            best->qt = NULL;
        best->qbytes -= f->len;
        best->qcount--;
        ws_write_frame(m, best, f);
        pending += f->len + WS_HDR * (f->len / WS_PIECE + 1);
        free(f);
    }
    for (i = 0; i < m->nst; i++)
        if (m->st[i]->qh)
            waiting = 1;
    if (waiting && !m->t_ws)
        m->t_ws = npf_timer_add(m->loop, WS_TICK_MS, ws_tick, m);
}

static void ws_tick(npf_loop *loop, void *arg)
{
    npf_media *m = arg;
    (void)loop;
    m->t_ws = NULL;
    ws_pump(m);
}

size_t npf_media_ws_queued(const npf_media *m)
{
    size_t n = 0;
    int i;
    for (i = 0; m && i < m->nst; i++)
        n += m->st[i]->qbytes;
    return n;
}

/* ---- the application's side ---- */

uint32_t npf_media_open_stream(npf_media *m, const npf_call_media_opt *o, int *err)
{
    mst *s;
    if (m->nst == NPF_MEDIA_MAX || (m->anl && m->nout >= NPF_MEDIA_OUT_MAX)) {
        *err = NPF_CALL_EBUSY;
        return 0;
    }
    if (!(s = calloc(1, sizeof *s))) {
        *err = NPF_CALL_ENOMEM;
        return 0;
    }
    s->id = new_id(m);
    s->tag = o->tag;
    s->out = 1;
    s->prio = o->prio;
    s->max_age_ms = o->max_age_ms < 0 ? 500 : o->max_age_ms;
    s->drop_until_key = o->drop_until_key;
    if (m->anl) {
        anl_stream_opt opt;
        int e = 0;
        anl_stream_opt_default(&opt, ANL_SEMI);
        opt.rcv_wnd = NPF_ANL_MEDIA_WND;    /* what the peer takes (media.h) */
        opt.tag = NPF_TAG_MEDIA + o->tag + (o->rcv_drop_until_key ? NPF_MEDIA_TAG_RDK : 0);
        opt.prio = o->prio;
        if (o->max_age_ms >= 0)
            opt.max_age_ms = o->max_age_ms;
        opt.drop_until_key = o->drop_until_key;
        if (o->fec >= 0)
            opt.fec = o->fec;
        if (o->fec_ratio > 0)
            opt.fec_ratio = o->fec_ratio;
        opt.latency_rtt = o->latency_rtt;
        if (!(s->s = anl_stream_open(m->anl, &opt, &e))) {
            free(s);
            *err = e == ANL_EBUSY ? NPF_CALL_EBUSY : NPF_CALL_ESTATE;
            return 0;
        }
        m->nout++;
        m->st[m->nst++] = s;
        return s->id;
    }
    m->st[m->nst++] = s;
    if (unit(m, OP_OPEN, s->id, o->tag, o->rcv_drop_until_key ? 1 : 0) < 0) {
        drop_stream(m, m->nst - 1);
        *err = NPF_CALL_ESTATE;
        return 0;
    }
    return s->id;
}

int npf_media_send_frame(npf_media *m, uint32_t id, int flags, const void *buf, size_t len, int64_t t_submit)
{
    int i = find(m, id);
    int64_t now = npf_mono_ms();
    mst *s;
    if (i < 0 || !m->st[i]->out)
        return NPF_CALL_ENOENT;
    if (len > NPF_MEDIA_FRAME_MAX || (!m->anl && len > WS_QUEUE_MAX))
        return NPF_CALL_ETOOBIG;
    s = m->st[i];
    if (!t_submit || t_submit > now)
        t_submit = now;
    if (s->max_age_ms > 0 && now - t_submit > s->max_age_ms) {
        s->dropped++;                       /* too old already (it waited for the library's thread) */
        if (s->drop_until_key)
            s->need_key = 1;
        m->drop_t = now;
        if (!m->anl)
            s->next_fno++;
        return 0;
    }
    if (m->anl) {
        int r;
        if (s->need_key) {                  /* the rest until a key frame goes too */
            if (!(flags & NPF_FRAME_KEY_FLAG)) {
                s->dropped++;
                return 0;
            }
            s->need_key = 0;
        }
        r = anl_stream_send_frame(s->s, flags & NPF_FRAME_KEY_FLAG ? ANL_FRAME_KEY : 0, buf, (int)len, NULL);
        m->io.kick(m->arg);
        if (r < 0 && r != ANL_EDROPPED)
            return r == ANL_ECLOSED ? NPF_CALL_ESTATE : NPF_CALL_ETOOBIG;
        return 0;
    }
    {
        qframe *f = malloc(sizeof *f + len);
        if (!f)
            return NPF_CALL_ENOMEM;
        f->next = NULL;
        f->t = t_submit;
        f->flags = flags & NPF_FRAME_KEY_FLAG;
        f->fno = s->next_fno++;
        f->len = len;
        memcpy(f->d, buf, len);
        if (s->qt)
            s->qt->next = f;
        else
            s->qh = f;
        s->qt = f;
        s->qbytes += len;
        s->qcount++;
        while ((s->qbytes > WS_QUEUE_MAX || s->qcount > 4096) && s->qh != s->qt) {    /* the oldest go */
            qframe *o = s->qh;
            s->qh = o->next;
            s->qbytes -= o->len;
            s->qcount--;
            s->dropped++;
            if (s->drop_until_key)
                s->need_key = 1;
            m->drop_t = f->t;
            free(o);
        }
        ws_pump(m);
        return 0;
    }
}

int npf_media_stream_stats(npf_media *m, uint32_t id, npf_call_media_stats *out)
{
    int i = find(m, id);
    mst *s;
    if (i < 0)
        return NPF_CALL_ENOENT;
    s = m->st[i];
    memset(out, 0, sizeof *out);
    out->frames_skipped = s->skipped;
    out->frames_dropped = s->dropped;
    if (m->anl) {
        anl_stats st;
        anl_stream_stats ss;
        if (anl_get_stats(m->anl, &st) == 0) {
            out->target_rate = st.target_rate;
            out->srtt_ms = st.srtt;
            out->min_rtt_ms = st.min_rtt;
            out->capacity_short = st.capacity_short;
        }
        if (anl_stream_get_stats(s->s, &ss) == 0) {
            out->frames_dropped += ss.frames_dropped;
            out->frames_skipped += ss.frames_skipped;
            out->fec_recovered = s->out ? ss.peer.fec_recovered : ss.fec_recovered;
            out->peer_frame_delay_avg_ms = ss.peer.frame_delay_avg_ms;
            out->peer_frame_delay_max_ms = ss.peer.frame_delay_max_ms;
            out->peer_jitter_ms = ss.peer.jitter_ms;
        }
        return 0;
    }
    out->target_rate = m->rate;
    out->capacity_short = m->drop_t && npf_mono_ms() - m->drop_t < 2000;
    return 0;
}

int npf_media_close_stream(npf_media *m, uint32_t id)
{
    int i = find(m, id);
    if (i < 0)
        return NPF_CALL_ENOENT;
    if (m->st[i]->s)
        anl_stream_close(m->st[i]->s);      /* AnLiu tells the peer */
    else
        unit(m, OP_CLOSE, id, 0, 0);
    drop_stream(m, i);
    return 0;
}

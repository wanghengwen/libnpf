/* Media streams and channels of a session (media.h; data-channel.md 14).
 * The application's ids: a counter << 1 | the side (callee 1), local only,
 * one counter for both kinds. */
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

#define CHAN_READ 65536             /* bytes of a channel per on_chan_data at most */

typedef struct mst {
    uint32_t id;
    int      tag, out;
    int      chan;                  /* a channel (reliable bytes), else a media stream (frames) */
    anl_stream_t *s;
    int      asked;                 /* the peer's: the application said yes */
    int      max_age_ms, drop_until_key;
    int      need_key;
    uint32_t dropped;               /* too old before AnLiu took them */
    int      paused;                /* a channel: not read */
    int      want_room;             /* a channel: a send was refused, on_chan_writable is owed */
    int64_t  linger_until;          /* a channel closed here: its data still going (0: open) */
} mst;

struct npf_media {
    anl_t       *anl;
    int          odd;
    npf_media_io io;
    void        *arg;
    /* each stream is ours (nout) or the peer's (nin), each side at most
     * NPF_MEDIA_OUT_MAX: nst = nout + nin always fits */
    mst         *st[2 * NPF_MEDIA_OUT_MAX];
    int          nst, nout, nin;
    uint32_t     next_id;
    unsigned     gen;               /* AnLiu streams closed here (npf_media_gen) */
    int          warned;            /* a peer's stream was refused (logged once) */
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

/* the application's: not a channel closed already (its data still going) */
static int find_app(const npf_media *m, uint32_t id)
{
    int i = find(m, id);
    return i >= 0 && !m->st[i]->linger_until ? i : -1;
}

static int find_s(const npf_media *m, const anl_stream_t *s)
{
    int i;
    for (i = 0; s && i < m->nst; i++)
        if (m->st[i]->s == s)
            return i;
    return -1;
}

/* forget stream i (its AnLiu stream is the caller's business) */
static void drop_stream(npf_media *m, int i)
{
    mst *s = m->st[i];
    if (s->out)
        m->nout--;
    else
        m->nin--;
    free(s);
    m->st[i] = m->st[--m->nst];
}

/* stream i closed here (AnLiu tells the peer) and forgotten */
static void close_at(npf_media *m, int i)
{
    anl_stream_close(m->st[i]->s);
    m->gen++;
    drop_stream(m, i);
}

static uint32_t new_id(npf_media *m)
{
    if (!++m->next_id)
        m->next_id = 1;
    return m->next_id << 1 | (uint32_t)m->odd;
}

/* -1 when a callback ended the session: stop delivering */
static int ended(const npf_media *m)
{
    return m->io.ended && m->io.ended(m->arg) ? -1 : 0;
}

/* stream i is over from the other side (closed or refused there, or a
 * frame over the limit): closed here too, the application told (not of a
 * channel it closed already) */
static int gone(npf_media *m, int i)
{
    uint32_t id = m->st[i]->id;
    int told = !m->st[i]->linger_until;
    close_at(m, i);
    if (told)
        m->io.on_closed(m->arg, id);
    return ended(m);
}

/* a channel's bytes queued or in flight */
static uint32_t backlog(const mst *s)
{
    anl_stream_stats ss;
    return anl_stream_get_stats(s->s, &ss) == 0 ? ss.backlog_bytes : 0;
}

/* ---- life ---- */

npf_media *npf_media_new(anl_t *anl, int odd, const npf_media_io *io, void *arg)
{
    npf_media *m = calloc(1, sizeof *m);
    if (!m)
        return NULL;
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
    while (m->nst)
        drop_stream(m, m->nst - 1);
    /* AnLiu streams go with the connection */
    free(m);
}

int npf_media_count(const npf_media *m)
{
    return m ? m->nst : 0;
}

unsigned npf_media_gen(const npf_media *m)
{
    return m ? m->gen : 0;
}

/* ---- AnLiu: a stream per media stream or channel ---- */

/* the accept callback: AnLiu allows no other call from here, so the
 * application is asked after the input (npf_media_poll) */
int npf_media_accept(npf_media *m, anl_stream_t *s, anl_stream_opt *opt)
{
    int raw = anl_stream_tag(s), tag = raw & ~NPF_MEDIA_TAG_RDK, chan;
    mst *x;
    if (opt->mode == ANL_SEMI && tag >= NPF_TAG_MEDIA && tag < NPF_TAG_MEDIA + NPF_MEDIA_TAGS)
        chan = 0;
    else if (opt->mode == ANL_RELIABLE && opt->stream && raw >= NPF_TAG_CHAN && raw < NPF_TAG_CHAN + NPF_MEDIA_TAGS)
        chan = 1;
    else
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
    if (!chan)
        opt->rcv_drop_until_key = (raw & NPF_MEDIA_TAG_RDK) != 0;
    x->id = new_id(m);
    x->chan = chan;
    x->tag = chan ? raw - NPF_TAG_CHAN : tag - NPF_TAG_MEDIA;
    x->s = s;
    m->st[m->nst++] = x;
    m->nin++;
    return 0;
}

int npf_media_is_stream(const npf_media *m, anl_stream_t *s)
{
    return m && find_s(m, s) >= 0;
}

/* stream i's turn in npf_media_poll: 1 when a callback ran or the table
 * changed (the caller starts over), -1 when a callback ended the session */
static int poll_one(npf_media *m, int i, int64_t now)
{
    mst *x = m->st[i];
    uint32_t id = x->id;
    if (x->linger_until) {                  /* closed here: goes once its data is acknowledged */
        if (anl_stream_waitsnd(x->s) > 0 && now < x->linger_until)
            return 0;
        close_at(m, i);
        return 1;
    }
    if (!x->out && !x->asked) {             /* the peer's, new: the application takes it or not */
        int (*fn)(void *, uint32_t, int) = x->chan ? m->io.on_chan_open : m->io.on_open;
        x->asked = 1;
        if (!fn || !fn(m->arg, id, x->tag)) {
            if ((i = find(m, id)) >= 0)     /* a refused one is closed: the peer's end is over */
                close_at(m, i);
        }
        return ended(m) < 0 ? -1 : 1;
    }
    if (x->want_room && backlog(x) < NPF_CHANNEL_BUFFER / 2) {
        x->want_room = 0;
        if (m->io.on_chan_writable)
            m->io.on_chan_writable(m->arg, id);
        return ended(m) < 0 ? -1 : 1;
    }
    return 0;
}

int npf_media_poll(npf_media *m)
{
    int64_t now = npf_mono_ms();
    int i, r;
    /* each turn that does something clears its own cause: starting over ends */
    for (i = 0; m && i < m->nst; i++) {
        if ((r = poll_one(m, i, now)) < 0)
            return -1;
        if (r)
            i = -1;
    }
    return 0;
}

/* a channel is readable: its bytes to the application (dropped once it is
 * closed here), or its end */
static int drain_chan(npf_media *m, anl_stream_t *s)
{
    for (;;) {
        uint8_t *buf;
        int i = find_s(m, s), sz, r;
        if (i < 0)
            return 0;
        sz = anl_stream_peeksize(s);
        if (sz == ANL_ECLOSED)
            return gone(m, i);
        if (sz <= 0 || m->st[i]->paused || (!m->st[i]->out && !m->st[i]->asked))
            return 0;                       /* paused, or not taken yet: it waits in AnLiu */
        if (sz > CHAN_READ)
            sz = CHAN_READ;
        if (!(buf = npf_scratch((size_t)sz)))
            return 0;
        r = anl_stream_recv(s, (char *)buf, sz);
        if (r > 0 && !m->st[i]->linger_until)
            m->io.on_chan_data(m->arg, m->st[i]->id, buf, (size_t)r);
        npf_scratch_done(buf);
        if (r <= 0)
            return 0;
        if (ended(m) < 0)
            return -1;
    }
}

/* a stream is readable: its frames to the application, or its end */
int npf_media_drain(npf_media *m, anl_stream_t *s)
{
    int i0 = find_s(m, s);
    if (i0 >= 0 && m->st[i0]->chan)
        return drain_chan(m, s);
    for (;;) {
        anl_frame_info fi;
        uint8_t *buf;
        int i = find_s(m, s), sz, r;
        if (i < 0)
            return 0;
        sz = anl_stream_peeksize(s);
        if (sz == ANL_ECLOSED)              /* closed (or refused) by the peer */
            return gone(m, i);
        if (sz < 0 || m->st[i]->out || !m->st[i]->asked)
            return 0;                       /* ours sends only; not taken yet: it waits in AnLiu */
        if ((unsigned)sz > NPF_MEDIA_FRAME_MAX)
            return gone(m, i);              /* a frame no application takes: the stream ends */
        if (!(buf = npf_scratch((size_t)sz + 1)))  /* reused, not a malloc per frame (nested use: its own) */
            return 0;
        r = anl_stream_recv_frame(s, (char *)buf, sz + 1, &fi);
        if (r >= 0)
            m->io.on_frame(m->arg, m->st[i]->id, buf, (size_t)r, fi.frame_no,
                           (fi.flags & ANL_FRAME_KEY) ? NPF_FRAME_KEY : 0, fi.lost_before);
        npf_scratch_done(buf);
        if (r < 0)
            return 0;
        if (ended(m) < 0)
            return -1;
    }
}

/* ---- the application's side ---- */

/* a stream of ours, its AnLiu stream opened with opt; NULL with *err */
static mst *open_out(npf_media *m, const anl_stream_opt *opt, int *err)
{
    int e = 0;
    mst *s;
    if (m->nout >= NPF_MEDIA_OUT_MAX) {
        *err = NPF_CALL_EBUSY;
        return NULL;
    }
    if (!(s = calloc(1, sizeof *s))) {
        *err = NPF_CALL_ENOMEM;
        return NULL;
    }
    if (!(s->s = anl_stream_open(m->anl, opt, &e))) {
        free(s);
        *err = e == ANL_EBUSY ? NPF_CALL_EBUSY : NPF_CALL_ESTATE;
        return NULL;
    }
    s->id = new_id(m);
    s->out = 1;
    m->nout++;
    m->st[m->nst++] = s;
    return s;
}

uint32_t npf_media_open_stream(npf_media *m, const npf_call_media_opt *o, int *err)
{
    anl_stream_opt opt;
    mst *s;
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.rcv_wnd = NPF_ANL_MEDIA_WND;        /* what the peer takes (media.h) */
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
    if (!(s = open_out(m, &opt, err)))
        return 0;
    s->tag = o->tag;
    s->max_age_ms = o->max_age_ms < 0 ? 500 : o->max_age_ms;
    s->drop_until_key = o->drop_until_key;
    return s->id;
}

int npf_media_send_frame(npf_media *m, uint32_t id, int flags, const void *buf, size_t len, int64_t t_submit)
{
    int i = find_app(m, id), r;
    int64_t now = npf_mono_ms();
    mst *s;
    if (i < 0 || !m->st[i]->out || m->st[i]->chan)
        return NPF_CALL_ENOENT;
    if (len > NPF_MEDIA_FRAME_MAX)
        return NPF_CALL_ETOOBIG;
    s = m->st[i];
    if (!t_submit || t_submit > now)
        t_submit = now;
    if (s->max_age_ms > 0 && now - t_submit > s->max_age_ms) {
        s->dropped++;                       /* too old already (it waited for the library's thread) */
        if (s->drop_until_key)
            s->need_key = 1;
        return 0;
    }
    if (s->need_key) {                      /* the rest until a key frame goes too */
        if (!(flags & NPF_FRAME_KEY)) {
            s->dropped++;
            return 0;
        }
        s->need_key = 0;
    }
    r = anl_stream_send_frame(s->s, flags & NPF_FRAME_KEY ? ANL_FRAME_KEY : 0, buf, (int)len, NULL);
    m->io.kick(m->arg);
    if (r < 0 && r != ANL_EDROPPED)
        return r == ANL_ECLOSED ? NPF_CALL_ESTATE : NPF_CALL_ETOOBIG;
    return 0;
}

int npf_media_stream_stats(npf_media *m, uint32_t id, npf_call_media_stats *out)
{
    int i = find_app(m, id);
    anl_stats st;
    anl_stream_stats ss;
    mst *s;
    if (i < 0 || m->st[i]->chan)
        return NPF_CALL_ENOENT;
    s = m->st[i];
    memset(out, 0, sizeof *out);
    out->frames_dropped = s->dropped;
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

int npf_media_close_stream(npf_media *m, uint32_t id)
{
    int i = find_app(m, id);
    mst *s;
    if (i < 0)
        return NPF_CALL_ENOENT;
    s = m->st[i];
    if (s->chan && anl_stream_waitsnd(s->s) > 0) {
        /* AnLiu's close drops what is not acknowledged: the channel waits
         * for it (npf_media_poll), its bytes from the peer dropped */
        s->linger_until = npf_mono_ms() + NPF_CHAN_LINGER_MS;
        s->paused = 0;
        s->want_room = 0;
        m->io.kick(m->arg);
        return 0;
    }
    close_at(m, i);
    return 0;
}

/* ---- channels ---- */

uint32_t npf_media_open_chan(npf_media *m, const npf_call_chan_opt *o, int *err)
{
    anl_stream_opt opt;
    mst *s;
    anl_stream_opt_default(&opt, ANL_RELIABLE);
    opt.rcv_wnd = NPF_ANL_MEDIA_WND;        /* what the peer takes (media.h) */
    opt.tag = NPF_TAG_CHAN + o->tag;
    opt.stream = 1;                         /* bytes, as TCP */
    opt.prio = o->prio;
    if (!(s = open_out(m, &opt, err)))
        return 0;
    s->tag = o->tag;
    s->chan = 1;
    return s->id;
}

static int chan_at(const npf_media *m, uint32_t id)
{
    int i = find_app(m, id);
    return i >= 0 && m->st[i]->chan ? i : -1;
}

int npf_media_chan_send(npf_media *m, uint32_t id, const void *buf, size_t len)
{
    int i = chan_at(m, id), r;
    mst *s;
    if (i < 0)
        return NPF_CALL_ENOENT;
    if (len > NPF_CHANNEL_BUFFER)
        return NPF_CALL_ETOOBIG;
    s = m->st[i];
    if (backlog(s) >= NPF_CHANNEL_BUFFER) {
        s->want_room = 1;
        return NPF_CALL_EBUSY;
    }
    r = anl_stream_send(s->s, (const char *)buf, (int)len);
    m->io.kick(m->arg);
    if (r < 0)
        return r == ANL_ENOMEM ? NPF_CALL_ENOMEM : NPF_CALL_ESTATE;   /* ECLOSED: on_closed comes */
    return 0;
}

int npf_media_chan_pause(npf_media *m, uint32_t id, int paused)
{
    int i = chan_at(m, id);
    if (i < 0)
        return NPF_CALL_ENOENT;
    if (m->st[i]->paused && !paused)
        m->io.kick(m->arg);                 /* what waited is read at the next tick */
    m->st[i]->paused = paused != 0;
    return 0;
}

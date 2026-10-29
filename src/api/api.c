/* libnpf: npf.h's queries, settings, commands, platform requests, and a
 * session's application data and media streams. Each runs on the
 * instance's thread (npf_api_op); npf_media_send from another thread only
 * queues a copy. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"

/* ---- queries: JSON for the caller (npf_free) ---- */

typedef struct q_arg {
    int     max, close;
    npf_out o;
} q_arg;

static int status_run(npf_t *n, void *arg)
{
    npf_status_out(n, &((q_arg *)arg)->o);
    return NPF_OK;
}

static int config_run(npf_t *n, void *arg)
{
    npf_cmd_config_json(n, &((q_arg *)arg)->o);
    return NPF_OK;
}

static int log_run(npf_t *n, void *arg)
{
    q_arg *q = arg;
    char *buf = malloc((size_t)q->max + 1);
    (void)n;
    if (!buf)
        return NPF_ENOMEM;
    npf_out_printf(&q->o, "{\"lines\":");
    npf_out_json_str(&q->o, buf, npf_log_recent(buf, (size_t)q->max + 1));
    npf_out_printf(&q->o, "}");
    free(buf);
    return NPF_OK;
}

static int sessions_run(npf_t *n, void *arg)
{
    npf_sessions_out(n, &((q_arg *)arg)->o);
    return NPF_OK;
}

static int public_run(npf_t *n, void *arg)
{
    q_arg *q = arg;
    if (n->peers)
        npf_peers_public_json(n->peers, q->close, &q->o);
    else
        npf_out_printf(&q->o, "{\"open\":0,\"closing\":false,\"mappings\":[]}");
    return NPF_OK;
}

static char *query(npf_t *n, int (*fn)(npf_t *n, void *arg), int max, int close)
{
    q_arg q;
    int rc;
    memset(&q, 0, sizeof q);
    q.max = max > 0 ? max : 16384;
    if (q.max > NPF_LOG_RING)
        q.max = NPF_LOG_RING;               /* no query can return more bytes than the ring holds */
    q.close = close != 0;
    rc = npf_api_op(n, fn, &q);
    npf_out_write(&q.o, "\n", 1);
    if (rc != NPF_OK || q.o.failed) {
        npf_out_free(&q.o);
        return NULL;
    }
    return q.o.p;                           /* npf_out's text: malloc'd, freed by npf_free */
}

char *npf_status_json(npf_t *n) { return query(n, status_run, 0, 0); }
char *npf_config_json(npf_t *n) { return query(n, config_run, 0, 0); }
char *npf_log_json(npf_t *n, int max) { return query(n, log_run, max, 0); }
char *npf_sessions_json(npf_t *n) { return query(n, sessions_run, 0, 0); }
char *npf_public_json(npf_t *n, int close) { return query(n, public_run, 0, close); }

/* ---- settings ---- */

typedef struct kv_arg {
    const char *key, *value;
    int         save;
    char       *out;
    size_t      cap;
    npf_out     o;                      /* npf_cmd_set's text: why it failed */
} kv_arg;

static int get_run(npf_t *n, void *arg)
{
    kv_arg *x = arg;
    char buf[NPF_CONF_VAL_MAX];
    int l;
    if (!npf_key_find(x->key))
        return NPF_ENOENT;
    l = snprintf(x->out, x->cap, "%s", npf_key_is(x->key, NPF_K_SECRET) ? "(hidden)" : npf_cmd_get(n, x->key, buf, sizeof buf));
    return l < 0 || (size_t)l >= x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_config_get(npf_t *n, const char *key, char *out, size_t cap)
{
    kv_arg x = {.key = key, .out = out, .cap = cap};
    if (!key || !out || !cap)
        return NPF_EINVAL;
    return npf_api_op(n, get_run, &x);
}

/* 1 when it applies at the next start */
static int set_run(npf_t *n, void *arg)
{
    kv_arg *x = arg;
    int r;
    if (x->save && (n->opt_flags & NPF_OPT_NO_SAVED_SETTINGS))
        return NPF_EUNAVAIL;                /* the application keeps the settings */
    r = npf_cmd_set(n, x->key, x->value, x->save, &x->o);
    return r == 0 ? !npf_key_is(x->key, NPF_K_LIVE) : r == 2 ? NPF_EINVAL : r == NPF_CMD_UNSAVED ? NPF_ESAVE : NPF_EFAIL;
}

int npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    kv_arg x = {.key = key, .value = value, .save = save};
    int r;
    err_clear(err, errcap);
    if (!key || !value)
        return NPF_EINVAL;
    r = npf_api_op(n, set_run, &x);
    if (x.o.failed)
        r = NPF_ENOMEM;
    else if (r < 0 && x.o.p && err)
        snprintf(err, errcap, "%s", x.o.p);
    npf_out_free(&x.o);
    return r;
}

/* ---- commands and platform requests ---- */

typedef struct c_arg {
    int          argc;
    char       **argv;
    npf_text_cb  cb;
    void        *user;
} c_arg;

static int c_run(npf_t *n, void *arg)
{
    c_arg *x = arg;
    npf_out o = {0};
    int r = npf_cmd_run(n, x->argc, x->argv, &o, x->cb, x->user);
    if (r >= 0 && x->cb)
        x->cb(x->user, o.failed ? 1 : r, o.failed ? "no memory" : o.p ? o.p : "");
    npf_out_free(&o);
    return NPF_OK;
}

int npf_command(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user)
{
    c_arg x = {.argc = argc, .cb = cb, .user = user};
    char **own;
    int i, rc = NPF_ENOMEM;
    if (!n || argc < 1 || !argv)
        return NPF_EINVAL;
    /* the copies own[0..argc) are freed here; the command gets own[argc..]
     * to the same strings, which it may rearrange (connect drops its
     * options in place) */
    if (!(own = calloc(2 * (size_t)argc + 1, sizeof *own)))
        return NPF_ENOMEM;
    for (i = 0; i < argc && (own[i] = strdup(argv[i] ? argv[i] : "")); i++)
        ;
    if (i == argc) {
        memcpy(own + argc, own, (size_t)argc * sizeof *own);
        x.argv = own + argc;
        rc = npf_api_op(n, c_run, &x);
    }
    for (i = 0; i < argc && own[i]; i++)
        npf_wipe_free(own[i], strlen(own[i]));      /* passwords */
    free(own);
    return rc;
}

typedef struct r_arg {
    const char  *type, *data;
    int          proof;
    npf_reply_cb cb;
    void        *user;
    npf_out      err;
} r_arg;

static int r_run(npf_t *n, void *arg)
{
    r_arg *x = arg;
    return npf_plat_request(n, x->type, x->data, x->proof, x->cb, x->user, &x->err);
}

int npf_request(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb, void *user)
{
    r_arg x = {.type = type, .data = data_json, .proof = key_proof, .cb = cb, .user = user};
    int rc;
    if (!n || !type)
        return NPF_EINVAL;
    rc = npf_api_op(n, r_run, &x);
    if (rc != NPF_OK && x.err.p)
        npf_log("npf_request %s: %s", type, x.err.p);
    npf_out_free(&x.err);
    return rc;
}

/* ---- sessions: application data and media ---- */

/* a session's data, a media stream's frame (from this thread) */
typedef struct s_arg {
    uint32_t    id;
    int         flags;
    const void *buf;
    size_t      len;
    int64_t     t;                      /* a frame: max_age counts from here */
} s_arg;

static int send_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_call *call = npf_session_call(n, x->id);
    if (!call)
        return NPF_ENOENT;
    return npf_call_app_send(call, x->buf, x->len) == 0 ? NPF_OK : NPF_ESTATE;
}

int npf_session_send(npf_t *n, uint32_t session, const void *buf, size_t len)
{
    s_arg x = {.id = session, .buf = buf, .len = len};
    if (!n || (!buf && len))
        return NPF_EINVAL;
    if (len > 16384)
        return NPF_ETOOBIG;
    return npf_api_op(n, send_run, &x);
}

static int open_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    const npf_media_opt *o = x->in;
    npf_call *call = npf_session_call(n, x->id);
    npf_call_media_opt co;
    uint32_t lid, media;
    int e = 0;
    if (o->tag < 0 || o->tag > 999)
        return NPF_EINVAL;
    if (!call)
        return NPF_ENOENT;
    if (n->nmed >= NPF_MAX_MEDIA)
        return NPF_EBUSY;
    memset(&co, 0, sizeof co);
    co.tag = o->tag;
    co.prio = o->prio < 0 || o->prio > 3 ? 1 : o->prio;
    co.max_age_ms = o->max_age_ms;
    co.drop_until_key = o->drop_until_key;
    co.fec = o->fec;
    co.fec_ratio = o->fec_ratio;
    co.latency_rtt = o->latency_rtt;
    co.rcv_drop_until_key = o->rcv_drop_until_key;
    if (!(lid = npf_call_media_open(call, &co, &e)))
        return e ? e : NPF_ESTATE;
    if (!(media = npf_media_add(n, x->id, call, lid))) {
        npf_call_media_close(call, lid);
        return NPF_ENOMEM;
    }
    *(uint32_t *)x->out = media;
    return NPF_OK;
}

int npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, uint32_t *media)
{
    npf_media_opt mo;
    op_arg x = {.id = session, .out = media};
    if (!media)
        return NPF_EINVAL;
    npf_media_opt_init(&mo);
    return op_take(n, open_run, &x, &mo, sizeof mo, o, SIZE_TO(npf_media_opt, rcv_drop_until_key),
                   "npf_media_opt_init");
}

static int frame_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    if (!m)
        return NPF_ENOENT;
    return npf_call_media_send(m->call, m->lid, x->flags & NPF_FRAME_KEY, x->buf, x->len, x->t);
}

/* a frame queued from another thread: its copy follows */
typedef struct m_frame {
    npf_t  *n;
    s_arg   x;
    uint8_t data[];
} m_frame;

/* the frame leaves the queue: sent (if its stream is still there) or dropped */
static void frame_done(void *arg)
{
    m_frame *f = arg;
    npf_t *n = f->n;
    LOCK();
    n->send_queued -= f->x.len;
    n->send_jobs--;
    UNLOCK();
    free(f);
}

static void frame_posted(npf_loop *loop, void *arg)
{
    m_frame *f = arg;
    (void)loop;
    if (!f->n->ended)
        frame_run(f->n, &f->x);
    frame_done(f);
}

/* Frames from other threads wait for the instance's thread with a budget:
 * over NPF_MEDIA_SEND_QUEUE bytes (or 4096 frames) the send is refused
 * (NPF_EBUSY) and the application decides (skip to the next key frame,
 * lower the rate). What goes wrong later (the stream ended meanwhile) only
 * drops the frame. */
static int media_send(npf_t *n, s_arg *x)
{
    m_frame *f;
    int here, rc = NPF_OK;
    LOCK();
    here = !n->running || n->loop_tid == self_tid();
    if (n->ended)
        rc = NPF_ESTATE;
    else if (!npf_media_find(n, x->id))
        rc = NPF_ENOENT;
    else if (!here && (n->send_queued + x->len > NPF_MEDIA_SEND_QUEUE || n->send_jobs >= 4096))
        rc = NPF_EBUSY;
    else if (!here) {
        n->send_queued += x->len;
        n->send_jobs++;
    }
    UNLOCK();
    if (rc != NPF_OK)
        return rc;
    if (here)                               /* a callback (or not running): at once, no copy */
        return sync_call(n, frame_run, x);
    if (!(f = malloc(sizeof *f + x->len))) {
        LOCK();
        n->send_queued -= x->len;
        n->send_jobs--;
        UNLOCK();
        return NPF_ENOMEM;
    }
    f->n = n;
    f->x = *x;
    f->x.buf = f->data;
    memcpy(f->data, x->buf, x->len);
    if (npf_loop_post_drop(n->loop, frame_posted, frame_done, f) < 0) {
        frame_done(f);
        return NPF_ENOMEM;
    }
    return NPF_OK;
}

int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    s_arg x = {.id = media, .flags = flags, .buf = frame, .len = len, .t = npf_mono_ms()};
    int r;
    if (!frame || !len)
        return NPF_EINVAL;
    if (len > NPF_MEDIA_FRAME_MAX)
        return NPF_ETOOBIG;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = media_send(n, &x);
    api_leave(n);
    return r;
}

static int stats_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    npf_call_media_stats cs;
    npf_media_stats st;
    int rc;
    memset(&st, 0, sizeof st);
    if (!m)
        return NPF_ENOENT;
    if ((rc = npf_call_media_get_stats(m->call, m->lid, &cs)) < 0)
        return rc;
    st.target_rate = cs.target_rate;
    st.srtt_ms = cs.srtt_ms;
    st.min_rtt_ms = cs.min_rtt_ms;
    st.frames_dropped = cs.frames_dropped;
    st.frames_skipped = cs.frames_skipped;
    st.fec_recovered = cs.fec_recovered;
    st.peer_frame_delay_avg_ms = cs.peer_frame_delay_avg_ms;
    st.peer_frame_delay_max_ms = cs.peer_frame_delay_max_ms;
    st.peer_jitter_ms = cs.peer_jitter_ms;
    st.capacity_short = cs.capacity_short;
    put_out(x->out, x->size, &st, sizeof st);
    return NPF_OK;
}

int npf_media_stats_get_size(npf_t *n, uint32_t media, npf_media_stats *out, size_t size)
{
    return op_get(n, stats_run, media, out, size);
}

static int close_run(npf_t *n, void *arg)
{
    uint32_t id = *(uint32_t *)arg;
    npf_med *m = npf_media_find(n, id);
    int rc;
    if (!m)
        return NPF_ENOENT;
    if ((rc = npf_call_media_close(m->call, m->lid)) == NPF_OK)
        npf_media_forget(n, id);            /* by its number: the close's callbacks may move m */
    return rc;
}

int npf_media_close(npf_t *n, uint32_t media)
{
    return npf_api_op(n, close_run, &media);
}

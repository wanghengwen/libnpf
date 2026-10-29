/* libnpf: the public functions of npf.h. Each one runs on the library thread:
 * at once when called there (callbacks) or before npf_start / npf_run;
 * otherwise posted to the loop while the caller waits for the result
 * (npf_media_send only queues a copy). The thread itself, the runtime and
 * sync_call in api_thread.c. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"
#include "api_internal.h"
#include "npf/module.h"

/* ---- the lifetime guard: every call below goes through it ---- */

typedef struct op_job {
    int  (*fn)(npf_t *n, void *arg);
    void  *arg;
    int    rc;
} op_job;

static void op_run(npf_t *n, void *arg)
{
    op_job *j = arg;
    j->rc = j->fn(n, j->arg);
}

static int op_sync(npf_t *n, void *arg)
{
    op_job *j = arg;
    int r = sync_call(n, op_run, j);
    return r < 0 ? r : j->rc;
}

/* fn on the library thread, with a reference held: fn's answer, or
 * NPF_EINVAL / NPF_ESTATE / NPF_ENOMEM when it did not run */
int npf_api_op(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg)
{
    op_job j;
    j.fn = fn;
    j.arg = arg;
    j.rc = NPF_OK;
    return npf_api_guard(n, op_sync, &j);
}

/* ---- queries ---- */

typedef struct q_arg {
    int     max, close;
    npf_out o;
} q_arg;

static int status_run(npf_t *n, void *arg)
{
    npf_cmd_status_json(n, &((q_arg *)arg)->o);
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
    if (buf) {
        size_t len = npf_log_recent(buf, (size_t)q->max + 1);
        npf_out_printf(&q->o, "{\"lines\":");
        npf_out_json_str(&q->o, buf, len);
        npf_out_printf(&q->o, "}\n");
        free(buf);
    }
    return NPF_OK;
}

static int sessions_run(npf_t *n, void *arg)
{
    npf_cmd_sessions_json(n, &((q_arg *)arg)->o);
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
    memset(&q, 0, sizeof q);
    q.max = max > 0 ? max : 16384;
    if (q.max > NPF_LOG_RING)
        q.max = NPF_LOG_RING;                /* no query can return more bytes than the ring holds */
    q.close = close != 0;
    if (npf_api_op(n, fn, &q) < 0 || q.o.failed) {
        npf_out_free(&q.o);
        return NULL;
    }
    return q.o.p;                           /* npf_out text: malloc'd, freed by npf_free */
}

char *npf_status_json(npf_t *n) { return query(n, status_run, 0, 0); }
char *npf_config_json(npf_t *n) { return query(n, config_run, 0, 0); }
char *npf_log_json(npf_t *n, int max) { return query(n, log_run, max, 0); }
char *npf_sessions_json(npf_t *n) { return query(n, sessions_run, 0, 0); }
char *npf_public_json(npf_t *n, int close) { return query(n, public_run, 0, close); }

/* ---- settings ---- */

typedef struct kv_arg {
    const char *key, *value;
    int         save, failed;           /* failed: npf_cmd_set said why in o */
    char       *out;
    size_t      cap;
    npf_out     o;
} kv_arg;

static int get_run(npf_t *n, void *arg)
{
    kv_arg *x = arg;
    char buf[NPF_CONF_VAL_MAX];
    int l;
    if (!npf_key_find(x->key) && !npf_mod_key_known(n, x->key))
        return NPF_ENOENT;
    l = snprintf(x->out, x->cap, "%s", npf_key_is(x->key, NPF_K_SECRET) ? "(hidden)" : npf_cmd_get(n, x->key, buf, sizeof buf));
    return l < 0 || (size_t)l >= x->cap ? NPF_ETOOBIG : NPF_OK;
}

int npf_config_get(npf_t *n, const char *key, char *out, size_t cap)
{
    kv_arg x;
    if (!key || !out || !cap)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.key = key;
    x.out = out;
    x.cap = cap;
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
    x->failed = r != 0;
    return r == 0 ? !npf_key_is(x->key, NPF_K_LIVE) : r == 2 ? NPF_EINVAL : r == NPF_CMD_UNSAVED ? NPF_ESAVE : NPF_EFAIL;
}

int npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    kv_arg x;
    int r;
    if (!key || !value)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.key = key;
    x.value = value;
    x.save = save;
    r = npf_api_op(n, set_run, &x);
    if (x.o.failed)
        r = NPF_ENOMEM;
    else if (x.failed && err && errcap)
        snprintf(err, errcap, "%s", x.o.p ? x.o.p : "failed");
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
    c_arg x;
    char **own, **work;
    int i, rc = NPF_ENOMEM;
    if (!n || argc < 1 || !argv)
        return NPF_EINVAL;
    /* own: the copies, freed here; work: what the command gets, which it may
     * rearrange (connect drops its options in place) */
    own = calloc((size_t)argc + 1, sizeof *own);
    work = calloc((size_t)argc + 1, sizeof *work);
    for (i = 0; own && work && i < argc; i++)
        if (!(own[i] = strdup(argv[i] ? argv[i] : "")))
            break;
    if (own && work && i == argc) {
        memcpy(work, own, (size_t)argc * sizeof *work);
        x.argc = argc;
        x.argv = work;
        x.cb = cb;
        x.user = user;
        rc = npf_api_op(n, c_run, &x);
    }
    for (i = 0; own && i < argc; i++) {
        if (own[i])
            npf_wipe(own[i], strlen(own[i]));      /* passwords */
        free(own[i]);
    }
    free(own);
    free(work);
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
    r_arg x;
    int rc;
    if (!n || !type)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.type = type;
    x.data = data_json;
    x.proof = key_proof;
    x.cb = cb;
    x.user = user;
    rc = npf_api_op(n, r_run, &x);
    if (rc != NPF_OK && x.err.p)
        npf_log("npf_request %s: %s", type, x.err.p);
    npf_out_free(&x.err);
    return rc;
}

/* ---- sessions: application data and media ---- */

typedef struct s_arg {
    uint32_t    id;
    const void *buf;
    size_t      len;                    /* stats: out's size */
    npf_media_stats *st;
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
    s_arg x;
    if (!n || (!buf && len))
        return NPF_EINVAL;
    if (len > 16384)
        return NPF_ETOOBIG;
    memset(&x, 0, sizeof x);
    x.id = session;
    x.buf = buf;
    x.len = len;
    return npf_api_op(n, send_run, &x);
}

void npf_media_opt_default_size(npf_media_opt *o, size_t size)
{
    npf_media_opt d;
    memset(&d, 0, sizeof d);
    d.prio = 1;
    d.max_age_ms = 500;
    d.fec = -1;
    d.rcv_deadline_ms = -1;
    npf_init_sized(o, size, &d, sizeof d);
}

typedef struct m_open {
    uint32_t session, media;
    const npf_media_opt *o;
} m_open;

static int open_run(npf_t *n, void *arg)
{
    m_open *x = arg;
    npf_call *call = npf_session_call(n, x->session);
    npf_call_media_opt co;
    uint32_t lid;
    int e = 0;
    if (!call)
        return NPF_ENOENT;
    if (n->nmed >= NPF_MAX_MEDIA)
        return NPF_EBUSY;
    co.tag = x->o->tag;
    co.prio = x->o->prio < 0 || x->o->prio > 3 ? 1 : x->o->prio;
    co.max_age_ms = x->o->max_age_ms;
    co.drop_until_key = x->o->drop_until_key;
    co.fec = x->o->fec;
    co.fec_ratio = x->o->fec_ratio;
    co.latency_rtt = x->o->latency_rtt;
    co.rcv_deadline_ms = x->o->rcv_deadline_ms;
    co.rcv_drop_until_key = x->o->rcv_drop_until_key;
    if (!(lid = npf_call_media_open(call, &co, &e)))
        return e ? e : NPF_ESTATE;
    if (!(x->media = npf_media_add(n, x->session, call, lid))) {
        npf_call_media_close(call, lid);
        return NPF_ENOMEM;
    }
    return NPF_OK;
}

uint32_t npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, int *err)
{
    m_open x;
    npf_media_opt opt;
    int e;
    if (!err)
        err = &e;
    npf_media_opt_default(&opt);
    if (o) {                                /* what the application's build has, defaults for the rest */
        if (o->size < offsetof(npf_media_opt, rcv_drop_until_key) + sizeof o->rcv_drop_until_key) {
            *err = NPF_EINVAL;
            return 0;
        }
        memcpy(&opt, o, o->size < sizeof opt ? o->size : sizeof opt);
        opt.size = sizeof opt;
    }
    o = &opt;
    if (o->tag < 0 || o->tag > 999) {
        *err = NPF_EINVAL;
        return 0;
    }
    memset(&x, 0, sizeof x);
    x.session = session;
    x.o = o;
    *err = npf_api_op(n, open_run, &x);
    return *err == NPF_OK ? x.media : 0;
}

typedef struct m_frame {
    npf_t   *n;
    uint32_t media;
    int      flags;
    int64_t  t;                     /* npf_media_send: max_age counts from here */
    size_t   len;
    uint8_t  data[];
} m_frame;

static int frame_send(npf_t *n, uint32_t media, int flags, const void *d, size_t len, int64_t t)
{
    npf_med *m = n->ended ? NULL : npf_media_find(n, media);
    if (!m)
        return n->ended ? NPF_ESTATE : NPF_ENOENT;
    return npf_call_media_send(m->call, m->lid, flags & NPF_FRAME_KEY, d, len, t);
}

static void frame_run(npf_loop *loop, void *arg)
{
    m_frame *f = arg;
    npf_t *n = f->n;
    (void)loop;
    LOCK();
    f->n->send_queued -= f->len;
    f->n->send_jobs--;
    UNLOCK();
    frame_send(f->n, f->media, f->flags, f->data, f->len, f->t);
    free(f);
}

static void frame_drop(void *arg)
{
    m_frame *f = arg;
    npf_t *n = f->n;
    LOCK();
    f->n->send_queued -= f->len;
    f->n->send_jobs--;
    UNLOCK();
    free(f);
}

/* Frames from other threads wait for the library's thread with a budget:
 * over NPF_MEDIA_SEND_QUEUE bytes the send is refused (NPF_EBUSY) and the
 * application decides (skip to the next key frame, lower the rate). The
 * number is checked on every thread alike; what goes wrong later (the
 * stream ended meanwhile) only drops the frame. */
static int media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    m_frame *f;
    npf_med *m;
    int here, rc = NPF_OK;
    int64_t t = npf_mono_ms();
    if (!n || !frame || !len)
        return NPF_EINVAL;
    if (len > NPF_MEDIA_FRAME_MAX)
        return NPF_ETOOBIG;
    LOCK();
    here = !n->running || n->loop_tid == self_tid();
    if (n->ended)
        rc = NPF_ESTATE;
    else if (!(m = npf_media_find(n, media)))
        rc = NPF_ENOENT;
    else if (len > m->frame_max)
        rc = NPF_ETOOBIG;
    else if (!here && (n->send_queued + len > NPF_MEDIA_SEND_QUEUE || n->send_jobs >= 4096))
        rc = NPF_EBUSY;
    else if (!here) {
        n->send_queued += len;
        n->send_jobs++;
    }
    UNLOCK();
    if (rc != NPF_OK)
        return rc;
    if (here) {                             /* a callback (or not running): at once, no copy */
        rc = exec_mode(n);
        if (rc == EXEC_POST)                /* it started meanwhile */
            return NPF_EBUSY;
        {
            npf_log_ctx *prev = npf_log_ctx_swap(&n->logctx);
            int r = frame_send(n, media, flags, frame, len, t);
            npf_log_ctx_swap(prev);
            if (rc == EXEC_TURN)
                turn_end(n);
            return r;
        }
    }
    if (!(f = malloc(sizeof *f + len))) {
        LOCK();
        n->send_queued -= len;
        n->send_jobs--;
        UNLOCK();
        return NPF_ENOMEM;
    }
    f->n = n;
    f->media = media;
    f->flags = flags;
    f->t = t;
    f->len = len;
    memcpy(f->data, frame, len);
    if (npf_loop_post_drop(n->loop, frame_run, frame_drop, f) < 0) {
        frame_drop(f);
        return NPF_ENOMEM;
    }
    return NPF_OK;
}

/* out (x->st, x->len bytes of it) is written whenever this runs */
static int stats_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    npf_call_media_stats cs;
    npf_media_stats st;
    int rc = NPF_ENOENT;
    memset(&st, 0, sizeof st);
    if (m && (rc = npf_call_media_get_stats(m->call, m->lid, &cs)) >= 0) {
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
        rc = NPF_OK;
    }
    st.size = x->len;
    memcpy(x->st, &st, x->len);
    return rc;
}

int npf_media_stats_get(npf_t *n, uint32_t media, npf_media_stats *out)
{
    s_arg x;
    if (!n || !out || out->size < offsetof(npf_media_stats, capacity_short) + sizeof out->capacity_short)
        return NPF_EINVAL;                  /* the caller sets out->size */
    memset(&x, 0, sizeof x);
    x.id = media;
    x.st = out;
    x.len = out->size < sizeof *out ? out->size : sizeof *out;
    return npf_api_op(n, stats_run, &x);
}

static int close_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    int rc;
    if (!m)
        return NPF_ENOENT;
    rc = npf_call_media_close(m->call, m->lid);
    if (rc == NPF_OK)
        npf_media_forget(n, x->id);
    return rc;
}

int npf_media_close(npf_t *n, uint32_t media)
{
    s_arg x;
    memset(&x, 0, sizeof x);
    x.id = media;
    return npf_api_op(n, close_run, &x);
}

int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = media_send(n, media, flags, frame, len);
    api_leave(n);
    return r;
}

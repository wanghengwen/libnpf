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

/* ---- queries ---- */

typedef struct q_arg {
    int     what, max;
    npf_out o;
} q_arg;

static void q_run(npf_t *n, void *arg)
{
    q_arg *q = arg;
    if (q->what == 0) {
        npf_cmd_status_json(n, &q->o);
    } else if (q->what == 1) {
        npf_cmd_config_json(n, &q->o);
    } else if (q->what == 2) {
        char *buf = malloc((size_t)q->max + 1);
        if (buf) {
            size_t len = npf_log_recent(buf, (size_t)q->max + 1);
            npf_out_printf(&q->o, "{\"lines\":");
            npf_out_json_str(&q->o, buf, len);
            npf_out_printf(&q->o, "}\n");
            free(buf);
        }
    } else if (q->what == 3) {
        npf_cmd_sessions_json(n, &q->o);
    } else if (n->peers) {
        npf_peers_public_json(n->peers, q->what == 5, &q->o);
    } else {
        npf_out_printf(&q->o, "{\"open\":0,\"closing\":false,\"mappings\":[]}");
    }
}

static char *query(npf_t *n, int what, int max)
{
    q_arg q;
    memset(&q, 0, sizeof q);
    q.what = what;
    q.max = max > 0 ? max : 16384;
    if (!n)
        return NULL;
    if (sync_call(n, q_run, &q) < 0 || q.o.failed) {
        npf_out_free(&q.o);
        return NULL;
    }
    return q.o.p;                           /* npf_out text: malloc'd, freed by npf_free */
}

static char *npf_status_json_impl(npf_t *n) { return query(n, 0, 0); }
static char *npf_config_json_impl(npf_t *n) { return query(n, 1, 0); }
static char *npf_log_json_impl(npf_t *n, int max) { return query(n, 2, max); }
static char *npf_sessions_json_impl(npf_t *n) { return query(n, 3, 0); }
static char *npf_public_json_impl(npf_t *n, int close) { return query(n, close ? 5 : 4, 0); }

/* ---- the operations (ops.c) ---- */

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

int npf_api_op(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg)
{
    op_job j;
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    j.fn = fn;
    j.arg = arg;
    j.rc = NPF_OK;
    r = sync_call(n, op_run, &j);
    api_leave(n);
    return r < 0 ? r : j.rc;
}

/* ---- settings ---- */

typedef struct a_arg {
    int         what, flags, rc, live, code;     /* code: an NPF_E* answer of its own */
    const char *a, *b, *c, *d;
    int         argc;
    char      **argv;
    char        *out;
    size_t       cap;
    npf_out      o;
} a_arg;

static void a_run(npf_t *n, void *arg)
{
    a_arg *x = arg;
    switch (x->what) {
    case 0: {                               /* config_get */
        char buf[NPF_CONF_VAL_MAX];
        int l;
        if (!npf_conf_known(x->a) && !npf_mod_key_known(n, x->a)) {
            x->code = NPF_ENOENT;
            break;
        }
        l = snprintf(x->out, x->cap, "%s", npf_cmd_is_secret(x->a) ? "(hidden)" : npf_cmd_get(n, x->a, buf, sizeof buf));
        x->code = l < 0 || (size_t)l >= x->cap ? NPF_ETOOBIG : NPF_OK;
        break;
    }
    case 1:                                 /* config_set: 1 when it applies at the next start */
        if (x->flags && (n->opt_flags & NPF_OPT_NO_SAVED_SETTINGS)) {
            x->code = NPF_EUNAVAIL;         /* the application keeps the settings */
            break;
        }
        x->rc = npf_cmd_set(n, x->a, x->b, x->flags, &x->o);
        if (x->rc == 0 && !npf_cmd_is_settable(x->a))
            x->live = 1;
        break;
    default:
        break;
    }
}

static int action(npf_t *n, a_arg *x, char *err, size_t errcap)
{
    if (!n)
        return NPF_EINVAL;
    if (sync_call(n, a_run, x) < 0)
        return NPF_ESTATE;
    if (x->o.failed) {
        npf_out_free(&x->o);
        return NPF_ENOMEM;
    }
    if (x->code)
        return x->code;
    if (x->rc && err && errcap)
        snprintf(err, errcap, "%s", x->o.p ? x->o.p : "failed");
    npf_out_free(&x->o);
    return x->rc == 0 ? x->live : x->rc == 2 ? NPF_EINVAL : x->rc == NPF_CMD_UNSAVED ? NPF_ESAVE : NPF_EFAIL;
}

static int npf_config_get_impl(npf_t *n, const char *key, char *out, size_t cap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!key || !out || !cap)
        return NPF_EINVAL;
    x.what = 0;
    x.a = key;
    x.out = out;
    x.cap = cap;
    return action(n, &x, NULL, 0);
}

static int npf_config_set_impl(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    a_arg x;
    memset(&x, 0, sizeof x);
    if (!key || !value)
        return NPF_EINVAL;
    x.what = 1;
    x.a = key;
    x.b = value;
    x.flags = save;
    return action(n, &x, err, errcap);
}

/* ---- commands and platform requests ---- */

typedef struct c_arg {
    int          argc;
    char       **argv;
    npf_text_cb  cb;
    void        *user;
    int          rc;
} c_arg;

static void c_run(npf_t *n, void *arg)
{
    c_arg *x = arg;
    npf_out o = {0};
    int r = npf_cmd_run(n, x->argc, x->argv, &o, x->cb, x->user);
    if (r >= 0 && x->cb)
        x->cb(x->user, o.failed ? 1 : r, o.failed ? "no memory" : o.p ? o.p : "");
    npf_out_free(&o);
    x->rc = NPF_OK;
}

static int npf_command_impl(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user)
{
    c_arg x;
    char **own, **work;
    int i, ok = 1;
    if (!n || argc < 1 || !argv)
        return NPF_EINVAL;
    /* own: the copies, freed here; work: what the command gets, which it may
     * rearrange (connect drops its options in place) */
    own = calloc((size_t)argc + 1, sizeof *own);
    work = calloc((size_t)argc + 1, sizeof *work);
    for (i = 0; own && work && i < argc; i++)
        if (!(own[i] = strdup(argv[i] ? argv[i] : "")))
            break;
    if (!own || !work || i < argc) {
        ok = 0;
    } else {
        memcpy(work, own, (size_t)argc * sizeof *work);
        x.argc = argc;
        x.argv = work;
        x.cb = cb;
        x.user = user;
        x.rc = NPF_EFAIL;
        if (sync_call(n, c_run, &x) < 0)
            x.rc = NPF_ESTATE;
    }
    for (i = 0; own && i < argc; i++) {
        if (own[i])
            npf_wipe(own[i], strlen(own[i]));      /* passwords */
        free(own[i]);
    }
    free(own);
    free(work);
    return ok ? x.rc : NPF_ENOMEM;
}

typedef struct r_arg {
    const char  *type, *data;
    int          proof, rc;
    npf_reply_cb cb;
    void        *user;
    npf_out      err;
} r_arg;

static void r_run(npf_t *n, void *arg)
{
    r_arg *x = arg;
    x->rc = npf_plat_request(n, x->type, x->data, x->proof, x->cb, x->user, &x->err);
}

static int npf_request_impl(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb, void *user)
{
    r_arg x;
    if (!n || !type)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.type = type;
    x.data = data_json;
    x.proof = key_proof;
    x.cb = cb;
    x.user = user;
    if (sync_call(n, r_run, &x) < 0)
        x.rc = NPF_ESTATE;
    if (x.rc != NPF_OK && x.err.p)
        npf_log("npf_request %s: %s", type, x.err.p);
    npf_out_free(&x.err);
    return x.rc;
}

/* ---- sessions: application data and media ---- */

typedef struct s_arg {
    uint32_t    id;
    const void *buf;
    size_t      len;
    int         rc, flags;
    const npf_media_opt *mo;
    npf_media_stats *st;
} s_arg;

static void send_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_call *call = npf_session_call(n, x->id);
    if (!call) {
        x->rc = NPF_ENOENT;
        return;
    }
    x->rc = npf_call_app_send(call, x->buf, x->len) == 0 ? NPF_OK : NPF_ESTATE;
}

static int npf_session_send_impl(npf_t *n, uint32_t session, const void *buf, size_t len)
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
    if (sync_call(n, send_run, &x) < 0)
        return NPF_ESTATE;
    return x.rc;
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
    int err;
} m_open;

static void open_run(npf_t *n, void *arg)
{
    m_open *x = arg;
    npf_call *call = npf_session_call(n, x->session);
    npf_call_media_opt co;
    uint32_t lid;
    int e = 0;
    if (!call) {
        x->err = NPF_ENOENT;
        return;
    }
    if (n->nmed >= NPF_MAX_MEDIA) {
        x->err = NPF_EBUSY;
        return;
    }
    co.tag = x->o->tag;
    co.prio = x->o->prio < 0 || x->o->prio > 3 ? 1 : x->o->prio;
    co.max_age_ms = x->o->max_age_ms;
    co.drop_until_key = x->o->drop_until_key;
    co.fec = x->o->fec;
    co.fec_ratio = x->o->fec_ratio;
    co.latency_rtt = x->o->latency_rtt;
    co.rcv_deadline_ms = x->o->rcv_deadline_ms;
    co.rcv_drop_until_key = x->o->rcv_drop_until_key;
    if (!(lid = npf_call_media_open(call, &co, &e))) {
        x->err = e ? e : NPF_ESTATE;
        return;
    }
    if (!(x->media = npf_media_add(n, x->session, call, lid))) {
        npf_call_media_close(call, lid);
        x->err = NPF_ENOMEM;
    }
}

static uint32_t npf_media_open_impl(npf_t *n, uint32_t session, const npf_media_opt *o, int *err)
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
    if (!n) {
        *err = NPF_EINVAL;
        return 0;
    }
    if (o->tag < 0 || o->tag > 999) {
        *err = NPF_EINVAL;
        return 0;
    }
    memset(&x, 0, sizeof x);
    x.session = session;
    x.o = o;
    if (sync_call(n, open_run, &x) < 0)
        x.err = NPF_ESTATE;
    *err = x.media ? NPF_OK : x.err;
    return x.media;
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
static int npf_media_send_impl(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
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

static void stats_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    npf_call_media_stats cs;
    if (!m) {
        x->rc = NPF_ENOENT;
        return;
    }
    if ((x->rc = npf_call_media_get_stats(m->call, m->lid, &cs)) < 0)
        return;
    x->st->target_rate = cs.target_rate;
    x->st->srtt_ms = cs.srtt_ms;
    x->st->min_rtt_ms = cs.min_rtt_ms;
    x->st->frames_dropped = cs.frames_dropped;
    x->st->frames_skipped = cs.frames_skipped;
    x->st->fec_recovered = cs.fec_recovered;
    x->st->peer_frame_delay_avg_ms = cs.peer_frame_delay_avg_ms;
    x->st->peer_frame_delay_max_ms = cs.peer_frame_delay_max_ms;
    x->st->peer_jitter_ms = cs.peer_jitter_ms;
    x->st->capacity_short = cs.capacity_short;
    x->rc = NPF_OK;
}

static int npf_media_stats_get_impl(npf_t *n, uint32_t media, npf_media_stats *out)
{
    s_arg x;
    npf_media_stats st;
    size_t size;
    if (!n || !out || out->size < offsetof(npf_media_stats, capacity_short) + sizeof out->capacity_short)
        return NPF_EINVAL;                  /* the caller sets out->size */
    size = out->size < sizeof st ? out->size : sizeof st;
    memset(&x, 0, sizeof x);
    memset(&st, 0, sizeof st);
    x.id = media;
    x.st = &st;
    if (sync_call(n, stats_run, &x) < 0)
        return NPF_ESTATE;
    st.size = size;
    memcpy(out, &st, size);
    return x.rc;
}

static void close_run(npf_t *n, void *arg)
{
    s_arg *x = arg;
    npf_med *m = npf_media_find(n, x->id);
    if (!m) {
        x->rc = NPF_ENOENT;
        return;
    }
    x->rc = npf_call_media_close(m->call, m->lid);
    if (x->rc == NPF_OK)
        npf_media_forget(n, x->id);
}

static int npf_media_close_impl(npf_t *n, uint32_t media)
{
    s_arg x;
    if (!n)
        return NPF_EINVAL;
    memset(&x, 0, sizeof x);
    x.id = media;
    if (sync_call(n, close_run, &x) < 0)
        return NPF_ESTATE;
    return x.rc;
}

/* ---- public entry points: lifetime guards ---- */

char *npf_status_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_status_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_config_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_config_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_log_json(npf_t *n, int max)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_log_json_impl(n, max);
    api_leave(n);
    return r;
}

char *npf_sessions_json(npf_t *n)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_sessions_json_impl(n);
    api_leave(n);
    return r;
}

char *npf_public_json(npf_t *n, int close)
{
    char *r;
    if (!api_enter(n))
        return NULL;
    r = npf_public_json_impl(n, close);
    api_leave(n);
    return r;
}

int npf_config_get(npf_t *n, const char *key, char *out, size_t cap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_config_get_impl(n, key, out, cap);
    api_leave(n);
    return r;
}

int npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_config_set_impl(n, key, value, save, err, errcap);
    api_leave(n);
    return r;
}

int npf_command(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_command_impl(n, argc, argv, cb, user);
    api_leave(n);
    return r;
}

int npf_request(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb, void *user)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_request_impl(n, type, data_json, key_proof, cb, user);
    api_leave(n);
    return r;
}

int npf_session_send(npf_t *n, uint32_t session, const void *buf, size_t len)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_session_send_impl(n, session, buf, len);
    api_leave(n);
    return r;
}

uint32_t npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, int *err)
{
    uint32_t r;
    if (!api_enter(n)) { if (err) *err = NPF_ESTATE; return 0; }
    r = npf_media_open_impl(n, session, o, err);
    api_leave(n);
    return r;
}

int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_send_impl(n, media, flags, frame, len);
    api_leave(n);
    return r;
}

int npf_media_stats_get(npf_t *n, uint32_t media, npf_media_stats *out)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_stats_get_impl(n, media, out);
    api_leave(n);
    return r;
}

int npf_media_close(npf_t *n, uint32_t media)
{
    int r;
    if (!api_enter(n))
        return n ? NPF_ESTATE : NPF_EINVAL;
    r = npf_media_close_impl(n, media);
    api_leave(n);
    return r;
}

/* libnpf: the engine's events, the node's and the peers' callbacks, and the
 * sessions and media streams by number */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "engine_internal.h"
#include "npf/module.h"

/* ---- events ---- */

/* a module's event (npf/module.h): NPF_EV_MODULE under notify */
void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    if (!n->cb.event && !n->cb.notify)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n->cb.notify) {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_MODULE;
        ev.name = name;
        ev.json = buf;
        npf_ev_queue(n, &ev);
    } else {
        n->cb.event(n->cb.user, name, buf);
    }
}

/* one of the library's events: typed (notify), or the legacy name and JSON */
void npf_engine_event(npf_t *n, const npf_event *ev, const char *name, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    if (n->cb.notify) {
        npf_ev_queue(n, ev);
        return;
    }
    if (!n->cb.event)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    n->cb.event(n->cb.user, name, buf);
}

void npf_ev_account(npf_t *n)
{
    npf_event ev;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_ACCOUNT;
    ev.number = n->node.account_id;
    if (n->node.account_id)
        npf_engine_event(n, &ev, "account", "{\"account_id\":\"%llu\"}", (unsigned long long)n->node.account_id);
    else
        npf_engine_event(n, &ev, "account", "{\"account_id\":null}");
}

/* ---- sessions and media streams by number ---- */

uint32_t npf_session_of(npf_t *n, npf_call *call)
{
    int i;
    for (i = 0; i < n->nsess; i++)
        if (n->sess[i].call == call)
            return n->sess[i].id;
    return 0;
}

npf_call *npf_session_call(npf_t *n, uint32_t id)
{
    int i;
    for (i = 0; id && i < n->nsess; i++)
        if (n->sess[i].id == id)
            return n->sess[i].call;
    return NULL;
}

/* the peer whose session this is (an outgoing one) */
static npf_peer *peer_of_call(npf_t *n, npf_call *call)
{
    npf_peer *p;
    for (p = n->peers ? npf_peers_first(n->peers) : NULL; p; p = npf_peer_next(p))
        if (npf_peer_call(p) == call)
            return p;
    return NULL;
}

static uint32_t sess_add(npf_t *n, npf_call *call)
{
    if (n->nsess == n->capsess) {           /* an instance has a few at a time, a node up to the limit */
        int cap = n->capsess ? 2 * n->capsess : 4;
        npf_sess *s;
        if (cap > NPF_MAX_SESS)
            cap = NPF_MAX_SESS;
        if (n->nsess == cap || !(s = realloc(n->sess, (size_t)cap * sizeof *s)))
            return 0;
        n->sess = s;
        n->capsess = cap;
    }
    if (n->nsess == NPF_MAX_SESS)
        return 0;
    if (!++n->next_sess)
        n->next_sess = 1;
    {
        npf_sess *ss = &n->sess[n->nsess];
        npf_peer *p = peer_of_call(n, call);
        npf_call_info ci;
        npf_call_info_get(call, &ci);
        memset(ss, 0, sizeof *ss);
        ss->id = n->next_sess;
        ss->call = call;
        ss->peer = p ? npf_peer_id(p) : 0;
        ss->ctx = p ? npf_peer_ctx(p) : NULL;
        ss->number = ci.number;
        ss->outgoing = ci.caller;
        ss->path = npf_path_code(ci.path);
    }
    n->nsess++;
    return n->next_sess;
}

static void med_drop(npf_t *n, int i, int tell)
{
    uint32_t id = n->med[i].id;
    npf_api_lock(n);                         /* npf_media_send looks at the registry from any thread */
    n->med[i] = n->med[--n->nmed];
    npf_api_unlock(n);
    if (tell && n->cb.media_closed)
        n->cb.media_closed(n->cb.user, id);
}

static void sess_end(npf_t *n, npf_call *call, const char *why)
{
    int i;
    uint32_t id = 0;
    npf_sess was;
    memset(&was, 0, sizeof was);
    for (i = 0; i < n->nsess; i++)
        if (n->sess[i].call == call) {
            id = n->sess[i].id;
            was = n->sess[i];
            n->sess[i] = n->sess[--n->nsess];
            break;
        }
    if (!id)
        return;
    for (i = n->nmed - 1; i >= 0;) {           /* callbacks may remove other streams */
        if (n->med[i].session == id) {
            med_drop(n, i, 1);
            i = n->nmed - 1;
        } else {
            i--;
        }
    }
    if (n->cb.notify) {                     /* its peer may be gone (removed): the end is ours then */
        npf_event ev;
        npf_peer *p = was.peer ? npf_peers_by_id(n->peers, was.peer) : NULL;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_SESSION_DOWN;
        ev.session = id;
        ev.peer = was.peer;
        ev.ctx = p ? npf_peer_ctx(p) : was.ctx;
        ev.number = was.number;
        ev.outgoing = was.outgoing;
        ev.path = was.path;
        ev.reason = npf_end_code(why, was.peer && !p);
        ev.why = why ? why : "closed";
        npf_ev_queue(n, &ev);
    } else if (n->cb.session) {
        npf_out o = {0};
        npf_out_printf(&o, "{\"why\":");
        npf_out_json_str(&o, why ? why : "closed", strlen(why ? why : "closed"));
        npf_out_printf(&o, "}");
        n->cb.session(n->cb.user, id, 0, o.p);
        npf_out_free(&o);
    }
}

/* the session's description for the session callback and npf_sessions_json */
void npf_session_info_out(npf_t *n, npf_call *call, npf_out *o)
{
    npf_call_info i;
    char peer[40];
    npf_call_info_get(call, &i);
    if (i.number)
        snprintf(peer, sizeof peer, "%llu", (unsigned long long)i.number);
    else
        snprintf(peer, sizeof peer, "key:%016llx", (unsigned long long)npf_fp(i.peer_pub));
    npf_out_printf(o, "{\"session\":%u,\"peer\":", npf_session_of(n, call));
    npf_out_json_str(o, peer, strlen(peer));
    npf_out_printf(o, ",\"path\":");
    npf_out_json_str(o, i.path, strlen(i.path));
    npf_out_printf(o, ",\"direction\":\"%s\",\"call_id\":", i.caller ? "out" : "in");
    npf_out_json_str(o, i.id, strlen(i.id));
    if (i.app && *i.app) {
        npf_out_printf(o, ",\"app\":");
        npf_out_json_str(o, i.app, strlen(i.app));
    }
    if (i.hosted)
        npf_out_printf(o, ",\"hosted\":true");
    npf_out_printf(o, "}");
}

static void on_account_cert(npf_node *node, void *arg)
{
    (void)node;
    npf_save_account_cert(arg);
}

static void on_account_lost(npf_node *node, void *arg)
{
    npf_t *n = arg;
    (void)node;
    unlink(n->cert_path);
    npf_ev_account(n);
}

/* ---- node hooks ---- */

static void on_enrolled(npf_node *node, uint64_t number, void *arg)
{
    npf_t *n = arg;
    (void)node;
    if (npf_become_node(n, number, NULL) == 0)
        npf_log("enrolled: number %llu, default password in %s (show)", (unsigned long long)number, n->node_path);
}

static void on_enroll_failed(npf_node *node, const char *error, const char *reason, int retry_s, void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_event ev;
    char why[96];
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_ENROLL_FAILED;
    ev.retry_in_ms = retry_s * 1000;
    snprintf(why, sizeof why, "%s%s%s", error, reason && *reason ? ": " : "", reason ? reason : "");
    ev.why = why;
    npf_engine_event(n, &ev, "enroll_failed", "{\"error\":\"%s\",\"reason\":\"%s\",\"retry_in\":%d}", error,
                     reason, retry_s);
}

/* signaling on demand: a module's work not done yet keeps the connection */
static int sig_busy(npf_node *node, void *arg)
{
    (void)node;
    return npf_mods_sig_busy(arg);
}

static void on_login(npf_node *node, void *arg)
{
    npf_t *n = arg;
    if (n->cfg.callable && n->callee)
        npf_callee_on_login(n->callee);
    npf_peers_on_login(n->peers);
    npf_mods_login(n);
    npf_account_info(n);
    {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_ONLINE;
        ev.number = node->account_id;
        npf_engine_event(n, &ev, "online", "{\"server\":%d,\"account_id\":%s%llu%s}", node->server_id,
                         node->account_id ? "\"" : "", (unsigned long long)node->account_id,
                         node->account_id ? "\"" : "");
    }
}

/* the process was suspended or the network changed (node.c's watch) */
static void on_net_change(npf_node *node, const char *why, void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_peers_net_changed(n->peers);
    {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_NETWORK;
        ev.why = why;
        npf_engine_event(n, &ev, "network", "{\"why\":\"%s\"}", why);
    }
}

/* signaling lost after a login */
static void on_offline(npf_node *node, const char *why, void *arg)
{
    npf_t *n = arg;
    npf_event ev;
    char w[120];
    size_t i, k = 0;
    (void)node;
    for (i = 0; why && why[i] && k + 1 < sizeof w; i++)     /* for the JSON: no quotes or backslashes */
        if (why[i] != '"' && why[i] != '\\' && (unsigned char)why[i] >= 0x20)
            w[k++] = why[i];
    w[k] = 0;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_OFFLINE;
    ev.why = w;
    npf_engine_event(n, &ev, "offline", "{\"why\":\"%s\"}", w);
}

/* UDP on demand: the profile is there, the sessions waiting for it start */
static void on_udp_ready(npf_node *node, void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_peers_on_login(n->peers);
}

/* a platform event (signaling.md): to the modules, and to the application
 * as "platform" {"type", "data"} (data as the platform sent it) */
static void on_event(npf_node *node, const char *type, const npf_json *j, int d, void *arg)
{
    npf_t *n = arg;
    const char *s;
    char *buf;
    size_t len, i, cap;
    (void)node;
    npf_mods_event(n, type, j, d);
    if (!n->cb.event && !n->cb.notify)
        return;
    for (i = 0; type[i]; i++)               /* a name of the protocol: nothing to escape */
        if (!((type[i] >= 'a' && type[i] <= 'z') || (type[i] >= '0' && type[i] <= '9') || type[i] == '_'))
            return;
    if (!i || i > 64)
        return;
    if (d >= 0) {
        int str = j->tok[d].type == NPF_JT_STRING;
        s = j->s + j->tok[d].start - (str ? 1 : 0);     /* a string with its quotes */
        len = j->tok[d].end - j->tok[d].start + (str ? 2 : 0);
    } else {
        s = "null";
        len = 4;
    }
    cap = len + i + 32;
    if (!(buf = malloc(cap)))
        return;
    if (n->cb.notify) {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_PLATFORM;
        ev.name = type;
        snprintf(buf, cap, "%.*s", (int)len, s);
        ev.json = buf;
        npf_ev_queue(n, &ev);
    } else {
        snprintf(buf, cap, "{\"type\":\"%s\",\"data\":%.*s}", type, (int)len, s);
        n->cb.event(n->cb.user, "platform", buf);
    }
    free(buf);
}

static void on_paired(npf_node *node, uint64_t number, const uint8_t pub[32], void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_peers_on_paired(n->peers, number, pub);
}

static void on_call_state(npf_node *node, npf_call *call, int st, const char *why, void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_mods_call_state(n, call, st, why);
    if (st == NPF_CALL_ESTABLISHED) {       /* a caller here: what it may reach */
        npf_call_info ci;
        npf_call_info_get(call, &ci);
        if (!ci.caller)
            npf_pub_send(n, call);
    }
    if (st == NPF_CALL_ESTABLISHED && !npf_session_of(n, call)) {
        uint32_t id = sess_add(n, call);
        if (id && n->cb.notify) {
            npf_sess *ss = &n->sess[n->nsess - 1];
            npf_event ev;
            memset(&ev, 0, sizeof ev);
            ev.type = NPF_EV_SESSION_UP;
            ev.session = id;
            ev.peer = ss->peer;
            ev.ctx = ss->ctx;
            ev.number = ss->number;
            ev.outgoing = ss->outgoing;
            ev.path = ss->path;
            npf_ev_queue(n, &ev);
        } else if (id && n->cb.session) {
            npf_out o = {0};
            npf_session_info_out(n, call, &o);
            n->cb.session(n->cb.user, id, 1, o.p);
            npf_out_free(&o);
        }
    } else if (st == NPF_CALL_CLOSED) {
        sess_end(n, call, why);
    }
    if (npf_peers_on_call_state(n->peers, call, st, why))
        return;
    {   /* an incoming session: which call, and who (many at once) */
        npf_call_info i;
        char who[40];
        npf_call_info_get(call, &i);
        if (i.number)
            snprintf(who, sizeof who, "node %llu", (unsigned long long)i.number);
        else
            snprintf(who, sizeof who, "key %016llx", (unsigned long long)npf_fp(i.peer_pub));
        if (st == NPF_CALL_ESTABLISHED)
            npf_log("call %s: session with %s established (%s)", i.id, who, npf_call_path_label(call));
        else if (st == NPF_CALL_CLOSED)
            npf_log("call %s: session with %s closed (%s; rtt %d ms, %u segments sent again)", i.id, who,
                    why ? why : "", i.srtt_ms, (unsigned)i.retrans);
    }
}

/* the node called published its resources */
static void on_resources(npf_node *node, npf_call *call, const npf_json *j, int d, void *arg)
{
    (void)node;
    npf_pub_heard(arg, call, j, d);
}

static void on_app_data(npf_node *node, npf_call *call, const uint8_t *buf, size_t len, void *arg)
{
    npf_t *n = arg;
    uint32_t id = npf_session_of(n, call);
    (void)node;
    npf_events_flush(n);                    /* SESSION_UP before its data */
    if (id && n->cb.data)
        n->cb.data(n->cb.user, id, buf, len);
}

static int on_media_open(npf_node *node, npf_call *call, uint32_t lid, int tag, void *arg)
{
    npf_t *n = arg;
    uint32_t sid = npf_session_of(n, call), id;
    (void)node;
    npf_events_flush(n);
    if (!sid || !n->cb.media_open || !(id = npf_media_add(n, sid, call, lid)))
        return 0;
    if (!n->cb.media_open(n->cb.user, sid, id, tag)) {
        npf_media_forget(n, id);
        return 0;
    }
    return npf_media_find(n, id) != NULL;
}

static int med_find(npf_t *n, npf_call *call, uint32_t lid)
{
    int i;
    for (i = 0; i < n->nmed; i++)
        if (n->med[i].call == call && n->med[i].lid == lid)
            return i;
    return -1;
}

static void on_media_frame(npf_node *node, npf_call *call, uint32_t lid, const uint8_t *buf, size_t len,
                           uint32_t frame_no, int flags, uint32_t lost_before, void *arg)
{
    npf_t *n = arg;
    int i = med_find(n, call, lid);
    (void)node;
    if (i >= 0 && n->cb.media_frame) {
        npf_frame_info fi;
        fi.frame_no = frame_no;
        fi.flags = flags;
        fi.lost_before = lost_before;
        n->cb.media_frame(n->cb.user, n->med[i].id, buf, len, &fi);
    }
}

static void on_media_closed(npf_node *node, npf_call *call, uint32_t lid, void *arg)
{
    npf_t *n = arg;
    int i = med_find(n, call, lid);
    (void)node;
    if (i >= 0)
        med_drop(n, i, 1);
}

uint32_t npf_media_add(npf_t *n, uint32_t session, npf_call *call, uint32_t lid)
{
    uint32_t id;
    npf_api_lock(n);
    if (n->nmed >= NPF_MAX_MEDIA) {
        npf_api_unlock(n);
        return 0;
    }
    if (!++n->next_med)
        n->next_med = 1;
    id = n->next_med;
    n->med[n->nmed].id = id;
    n->med[n->nmed].session = session;
    n->med[n->nmed].call = call;
    n->med[n->nmed].lid = lid;
    n->med[n->nmed].frame_max = strcmp(npf_call_path(call), "ws relay") == 0
                                  ? NPF_MEDIA_WS_FRAME_MAX : NPF_MEDIA_FRAME_MAX;
    n->nmed++;
    npf_api_unlock(n);
    return id;
}

npf_med *npf_media_find(npf_t *n, uint32_t id)
{
    int i;
    for (i = 0; id && i < n->nmed; i++)
        if (n->med[i].id == id)
            return &n->med[i];
    return NULL;
}

void npf_media_forget(npf_t *n, uint32_t id)
{
    int i;
    for (i = 0; i < n->nmed; i++)
        if (n->med[i].id == id) {
            med_drop(n, i, 0);
            return;
        }
}

/* ---- peers' hooks ---- */

static void peer_up(npf_peer *p, npf_call *call, void *arg)
{
    npf_t *n = arg;
    npf_mods_peer_up(n, p, call);           /* a binding waits for this session */
    if (npf_peer_tag(p) == PEER_TEMP && npf_peer_nfwd(p) == 0 && n->role == NPF_ROLE_CLIENT)
        npf_log("%s: no -L/-D/-R given; the session stays open", npf_peer_name(p));
}

static void peer_fwd(npf_peer *p, int i, int up, const char *why, void *arg)
{
    npf_t *n = arg;
    char opt;
    const char *spec;
    int perm;
    char st[160];
    npf_mods_peer_fwd(n, p, i, up, why);
    if (n->cb.notify) {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_FORWARD;
        ev.peer = npf_peer_id(p);
        ev.forward = (uint32_t)npf_peer_forward_id(p, i);
        ev.why = why ? why : "";
        npf_ev_queue(n, &ev);               /* state, reason and ctx: read when delivered */
        return;
    }
    if (npf_peer_forward_info(p, i, &opt, &spec, &perm, st, sizeof st)) {
        npf_out o = {0};
        char sp[320];
        snprintf(sp, sizeof sp, "-%c %s", opt, spec);
        npf_out_printf(&o, "{\"peer\":");
        npf_out_json_str(&o, npf_peer_name(p), strlen(npf_peer_name(p)));
        npf_out_printf(&o, ",\"spec\":");
        npf_out_json_str(&o, sp, strlen(sp));
        npf_out_printf(&o, ",\"up\":%s,\"why\":", up ? "true" : "false");
        npf_out_json_str(&o, why ? why : "", strlen(why ? why : ""));
        npf_out_printf(&o, "}");
        if (n->cb.event)
            n->cb.event(n->cb.user, "forward", o.p ? o.p : "{}");
        npf_out_free(&o);
    }
}

static void peer_done(npf_peer *p, const char *why, void *arg)
{
    npf_t *n = arg;
    npf_out o = {0};
    if (n->role == NPF_ROLE_NODE)
        npf_logw("%s: gave up (%s)", npf_peer_name(p), why);
    npf_mods_peer_done(n, p, why);
    npf_out_printf(&o, "{\"peer\":");
    npf_out_json_str(&o, npf_peer_name(p), strlen(npf_peer_name(p)));
    npf_out_printf(&o, ",\"why\":");
    npf_out_json_str(&o, why, strlen(why));
    npf_out_printf(&o, "}");
    if (n->cb.event && !n->cb.notify)       /* typed: NPF_EV_PEER (ended) */
        n->cb.event(n->cb.user, "peer_done", o.p);
    npf_out_free(&o);
}

static void peer_changed(npf_peer *p, void *arg)
{
    npf_t *n = arg;
    npf_event ev;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_PEER;
    ev.peer = npf_peer_id(p);
    ev.why = npf_peer_last_why(p);
    npf_ev_queue(n, &ev);                   /* its state and ctx: read when delivered */
}

static void peer_fwd_gone(npf_peer *p, int i, void *arg)
{
    npf_t *n = arg;
    npf_fwd_state st;
    npf_event ev;
    if (npf_peer_forward_state(p, i, &st) < 0)
        return;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_FORWARD_GONE;
    ev.peer = npf_peer_id(p);
    ev.forward = (uint32_t)npf_peer_forward_id(p, i);
    ev.ctx = st.ctx;
    npf_ev_queue(n, &ev);
}

static void peer_gone(npf_peer *p, void *arg)
{
    npf_t *n = arg;
    npf_event ev;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_PEER_GONE;
    ev.peer = npf_peer_id(p);
    ev.ctx = npf_peer_ctx(p);
    ev.number = npf_peer_number(p);
    ev.reason = NPF_END_LOCAL;
    npf_ev_queue(n, &ev);
}

static void peer_fwd_refused(npf_peer *p, int i, void *arg)
{
    npf_t *n = arg;
    npf_fwd_state st;
    npf_event ev;
    if (npf_peer_forward_state(p, i, &st) < 0)
        return;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_FORWARD_REFUSED;
    ev.peer = npf_peer_id(p);
    ev.forward = (uint32_t)npf_peer_forward_id(p, i);
    ev.why = st.refused_why;
    npf_ev_queue(n, &ev);
}

/* public connections (npf_peers_cbs): the modules' */
static void peer_opened(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from, void *arg)
{
    npf_mods_peer_opened(arg, p, mapping, port, from);
}

static void peer_conn(npf_peer *p, npf_call *call, uint64_t mapping, int port, const struct sockaddr_storage *from,
                      int64_t start, int64_t end, const npf_sublink_stats *st, void *arg)
{
    npf_mods_peer_conn(arg, p, call, mapping, port, from, start, end, st);
}

static void peer_refused(npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                         const char *why, int opened, void *arg)
{
    npf_mods_peer_refused(arg, p, mapping, port, from, why, opened);
}

/* the node with its callbacks here (create() in engine.c owns it) */
int npf_engine_node_init(npf_t *n)
{
    npf_node_hooks hooks = {on_login, on_call_state, on_paired, on_event, on_enrolled, on_app_data, on_media_open,
                            on_media_frame, on_media_closed, sig_busy, on_resources, on_net_change,
                            on_enroll_failed, on_offline};
    int r = npf_node_init(&n->node, n->loop, &n->cfg, &n->id, &hooks, n);
    if (r < 0)
        return r;
    n->node.on_account_lost = on_account_lost;
    n->node.on_udp_ready = on_udp_ready;
    n->node.on_account_cert = on_account_cert;
    n->node.on_account_cert_arg = n;
    return r;
}

static const npf_peers_cbs k_peers_cbs = {peer_up,      peer_done,     peer_fwd,  peer_conn,       peer_refused,
                                          peer_opened,  peer_changed,  peer_fwd_gone, peer_gone, peer_fwd_refused};

npf_peers *npf_engine_peers_new(npf_t *n)
{
    return npf_peers_new(&n->node, &n->lc, &k_peers_cbs, n);
}

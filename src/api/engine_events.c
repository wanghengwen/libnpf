/* libnpf: the engine's events, the node's and the peers' callbacks, and the
 * sessions, media streams and channels by number */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"

/* ---- events ---- */

/* an event with o's JSON to the application, o freed */
static void emit_out(npf_t *n, const char *name, npf_out *o)
{
    if (n->cb.event && !o->failed && o->p)
        n->cb.event(n->cb.user, name, o->p);
    npf_out_free(o);
}

void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
{
    npf_out o = {0};
    va_list ap;
    if (!n->cb.event)
        return;
    va_start(ap, fmt);
    npf_out_vprintf(&o, fmt, ap);
    va_end(ap);
    emit_out(n, name, &o);
}

/* an event whose JSON is {"key": text} (the text may be the platform's) */
static void emit_text(npf_t *n, const char *name, const char *key, const char *text)
{
    npf_out o = {0};
    npf_out_jobj(&o);
    npf_out_kstr(&o, key, text);
    npf_out_jend(&o);
    emit_out(n, name, &o);
}

/* "online" {server, account_id} (with the server) and "account" {account_id}:
 * the account session's id as a string, null none */
static void emit_account(npf_t *n, const char *name, int server)
{
    npf_out o = {0};
    char a[24];
    snprintf(a, sizeof a, "%llu", (unsigned long long)n->node.account_id);
    npf_out_jobj(&o);
    if (server >= 0)
        npf_out_kint(&o, "server", server);
    npf_out_kstr(&o, "account_id", n->node.account_id ? a : NULL);
    npf_out_jend(&o);
    emit_out(n, name, &o);
}

void npf_ev_account(npf_t *n)
{
    emit_account(n, "account", -1);
}

/* ---- sessions, media streams and channels by number ---- */

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

npf_peer *npf_peer_of_call(npf_t *n, npf_call *call)
{
    npf_peer *p;
    for (p = npf_peers_first(n->peers); p; p = npf_peer_next(p))
        if (npf_peer_call(p) == call)
            return p;
    return NULL;
}

static uint32_t sess_add(npf_t *n, npf_call *call)
{
    npf_peer *p = npf_peer_of_call(n, call);
    /* an instance has a few at a time, a node up to the limit */
    if (n->nsess >= NPF_MAX_SESS || npf_grow(&n->sess, &n->capsess, (size_t)n->nsess + 1, sizeof *n->sess, 4) < 0)
        return 0;
    if (!++n->next_sess)
        n->next_sess = 1;
    n->sess[n->nsess++] = (npf_sess){.id = n->next_sess, .call = call, .peer = p ? npf_peer_id(p) : 0};
    return n->next_sess;
}

static void med_drop(npf_t *n, int i, int tell)
{
    uint32_t id = n->med[i].id;
    int chan = n->med[i].chan;
    npf_api_lock(n);                         /* npf_media_send looks at the registry from any thread */
    n->nchan -= chan;
    n->med[i] = n->med[--n->nmed];
    npf_api_unlock(n);
    if (tell && chan && n->cb.channel_closed)
        n->cb.channel_closed(n->cb.user, id);
    else if (tell && !chan && n->cb.media_closed)
        n->cb.media_closed(n->cb.user, id);
}

static void sess_end(npf_t *n, npf_call *call, const char *why)
{
    int i;
    uint32_t id = 0;
    for (i = 0; i < n->nsess; i++)
        if (n->sess[i].call == call) {
            id = n->sess[i].id;
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
    if (n->cb.session) {
        npf_out o = {0};
        npf_out_jobj(&o);
        npf_out_kstr(&o, "why", why ? why : "closed");
        npf_out_jend(&o);
        if (!o.failed)
            n->cb.session(n->cb.user, id, 0, o.p);
        npf_out_free(&o);
    }
}

static void on_account_cert(npf_node *node, void *arg)
{
    (void)node;
    npf_save_account_cert(arg);
}

/* the account session began (its certificate saved already) or ended (a
 * logout, the account deleted, a login without it): the certificate
 * forgotten; the modules told either way */
static void on_account(npf_node *node, void *arg)
{
    npf_t *n = arg;
    if (!node->account_id) {
        npf_forget_account(n);
        npf_mods_account(n, 0);             /* the platform's mappings go */
        return;
    }
    npf_mods_account(n, 1);                 /* its mappings saved on the platform, its devices' nicks */
    npf_peers_retry_now(n->peers);          /* its devices let them in now */
    npf_account_info(n);
    npf_ev_account(n);
}

/* ---- node hooks ---- */

static void on_enrolled(npf_node *node, uint64_t number, void *arg)
{
    npf_t *n = arg;
    (void)node;
    if (npf_become_node(n, number) == 0)
        npf_log("enrolled: number %llu, default password in %s (show)", (unsigned long long)number, n->node_path);
}

static void on_enroll_failed(npf_node *node, const char *error, const char *reason, int retry_s, void *arg)
{
    npf_t *n = arg;
    npf_out o = {0};
    (void)node;
    npf_out_jobj(&o);
    npf_out_kstr(&o, "error", error);
    npf_out_kstr(&o, "reason", reason);
    npf_out_kint(&o, "retry_in", retry_s);
    npf_out_jend(&o);
    emit_out(n, "enroll_failed", &o);
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
    if (n->node.cfg.callable && n->callee)
        npf_callee_on_login(n->callee);
    npf_peers_on_login(n->peers);
    npf_mods_login(n);
    npf_account_info(n);
    emit_account(n, "online", node->server_id);
}

/* the process was suspended or the network changed (node.c's watch) */
static void on_net_change(npf_node *node, const char *why, void *arg)
{
    npf_t *n = arg;
    (void)node;
    npf_peers_net_changed(n->peers);
    emit_text(n, "network", "why", why);
}

/* signaling lost after a login */
static void on_offline(npf_node *node, const char *why, void *arg)
{
    npf_t *n = arg;
    (void)node;
    emit_text(n, "offline", "why", why ? why : "");
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
    npf_out o = {0};
    size_t i;
    (void)node;
    npf_mods_event(n, type, j, d);
    for (i = 0; type[i]; i++)               /* a name of the protocol: nothing to escape */
        if (!((type[i] >= 'a' && type[i] <= 'z') || (type[i] >= '0' && type[i] <= '9') || type[i] == '_'))
            return;
    if (!i || i > 64 || !n->cb.event)
        return;
    npf_out_printf(&o, "{\"type\":\"%s\",\"data\":", type);
    if (d < 0)
        npf_out_printf(&o, "null");
    else if (j->tok[d].type == NPF_JT_STRING)   /* the string with its quotes, as it came */
        npf_out_write(&o, j->s + j->tok[d].start - 1, j->tok[d].end - j->tok[d].start + 2);
    else
        npf_out_write(&o, j->s + j->tok[d].start, j->tok[d].end - j->tok[d].start);
    npf_out_printf(&o, "}");
    emit_out(n, "platform", &o);
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
        if (id && n->cb.session) {
            npf_out o = {0};
            npf_session_out(n, call, &o);
            if (!o.failed)
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
        npf_who(&i, who, sizeof who);
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
    if (id && n->cb.data)
        n->cb.data(n->cb.user, id, buf, len);
}

/* the peer's new media stream or channel: numbered, the application asks */
static int peer_open(npf_t *n, npf_call *call, uint32_t lid, int tag, int chan)
{
    int (*fn)(void *, uint32_t, uint32_t, int) = chan ? n->cb.channel_open : n->cb.media_open;
    uint32_t sid, id;
    sid = npf_session_of(n, call);          /* (a stream of a session gone was never removed) */
    if (!sid || npf_call_state(call) != NPF_CALL_ESTABLISHED || !fn || !(id = npf_media_add(n, sid, call, lid, chan)))
        return 0;
    if (!fn(n->cb.user, sid, id, tag)) {
        npf_media_forget(n, id);
        return 0;
    }
    return (chan ? npf_chan_find(n, id) : npf_media_find(n, id)) != NULL;   /* (closed in the callback) */
}

static int on_media_open(npf_node *node, npf_call *call, uint32_t lid, int tag, void *arg)
{
    (void)node;
    return peer_open(arg, call, lid, tag, 0);
}

static int on_chan_open(npf_node *node, npf_call *call, uint32_t lid, int tag, void *arg)
{
    (void)node;
    return peer_open(arg, call, lid, tag, 1);
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

static void on_chan_data(npf_node *node, npf_call *call, uint32_t lid, const uint8_t *buf, size_t len, void *arg)
{
    npf_t *n = arg;
    int i = med_find(n, call, lid);
    (void)node;
    if (i >= 0 && n->med[i].chan && n->cb.channel_data)
        n->cb.channel_data(n->cb.user, n->med[i].id, buf, len);
}

static void on_chan_writable(npf_node *node, npf_call *call, uint32_t lid, void *arg)
{
    npf_t *n = arg;
    int i = med_find(n, call, lid);
    (void)node;
    if (i >= 0 && n->med[i].chan && n->cb.channel_writable)
        n->cb.channel_writable(n->cb.user, n->med[i].id);
}

uint32_t npf_media_add(npf_t *n, uint32_t session, npf_call *call, uint32_t lid, int chan)
{
    uint32_t id;
    chan = chan != 0;
    npf_api_lock(n);
    if ((chan ? n->nchan >= NPF_MAX_CHAN : n->nmed - n->nchan >= NPF_MAX_MEDIA)
        || (!n->med && !(n->med = calloc(NPF_MAX_MEDIA + NPF_MAX_CHAN, sizeof *n->med)))) {
        npf_api_unlock(n);
        return 0;
    }
    if (!++n->next_med)
        n->next_med = 1;
    id = n->next_med;
    n->med[n->nmed++] = (npf_med){.id = id, .session = session, .call = call, .lid = lid, .chan = chan};
    n->nchan += chan;
    npf_api_unlock(n);
    return id;
}

static npf_med *reg_find(npf_t *n, uint32_t id, int chan)
{
    int i;
    for (i = 0; id && i < n->nmed; i++)
        if (n->med[i].id == id)
            return n->med[i].chan == chan ? &n->med[i] : NULL;
    return NULL;
}

npf_med *npf_media_find(npf_t *n, uint32_t id)
{
    return reg_find(n, id, 0);
}

npf_med *npf_chan_find(npf_t *n, uint32_t id)
{
    return reg_find(n, id, 1);
}

void npf_media_forget(npf_t *n, uint32_t id)
{
    npf_med *m = reg_find(n, id, 0);
    if (!m)
        m = reg_find(n, id, 1);
    if (m)
        med_drop(n, (int)(m - n->med), 0);
}

/* ---- peers' hooks ---- */

static void peer_up(npf_peer *p, npf_call *call, void *arg)
{
    npf_t *n = arg;
    npf_mods_peer_up(n, p, call);           /* a binding waits for this session */
    if (npf_peer_tag(p) == 0 && npf_peer_nfwd(p) == 0 && n->role == NPF_ROLE_CLIENT)
        npf_log("%s: no -L/-D/-R given; the session stays open", npf_peer_name(p));
}

static void peer_fwd(npf_peer *p, int i, int up, const char *why, void *arg)
{
    npf_t *n = arg;
    npf_fwd_state st;
    char sp[320];
    npf_out o = {0};
    npf_mods_peer_fwd(n, p, i, up, why);
    if (npf_peer_forward_state(p, i, &st) < 0)
        return;
    snprintf(sp, sizeof sp, "-%c %s", st.opt, st.spec);
    npf_out_jobj(&o);
    npf_out_kstr(&o, "peer", npf_peer_name(p));
    npf_out_kstr(&o, "spec", sp);
    npf_out_kbool(&o, "up", up);
    npf_out_kstr(&o, "why", why ? why : "");
    npf_out_jend(&o);
    emit_out(n, "forward", &o);
}

static void peer_done(npf_peer *p, const char *why, void *arg)
{
    npf_t *n = arg;
    npf_out o = {0};
    if (n->role == NPF_ROLE_NODE)
        npf_logw("%s: gave up (%s)", npf_peer_name(p), why);
    npf_mods_peer_done(n, p, why);
    npf_out_jobj(&o);
    npf_out_kstr(&o, "peer", npf_peer_name(p));
    npf_out_kstr(&o, "why", why ? why : "");
    npf_out_jend(&o);
    emit_out(n, "peer_done", &o);
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
int npf_engine_node_init(npf_t *n, const npf_node_cfg *cfg)
{
    npf_node_hooks hooks = {on_login, on_call_state, on_paired, on_event, on_enrolled, on_app_data, on_media_open,
                            on_media_frame, on_media_closed, sig_busy, on_resources, on_net_change,
                            on_enroll_failed, on_offline, on_chan_open, on_chan_data, on_chan_writable};
    int r = npf_node_init(&n->node, n->loop, cfg, &n->id, &hooks, n);
    if (r < 0)
        return r;
    n->node.on_account = on_account;
    n->node.on_udp_ready = on_udp_ready;
    n->node.on_account_cert = on_account_cert;
    n->node.on_account_cert_arg = n;
    return r;
}

static const npf_peers_cbs k_peers_cbs = {peer_up, peer_done, peer_fwd, peer_conn, peer_refused, peer_opened};

npf_peers *npf_engine_peers_new(npf_t *n)
{
    return npf_peers_new(&n->node, &n->lc, &k_peers_cbs, n);
}

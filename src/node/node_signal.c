/* Signaling requests, login, enrolment and reconnection. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/cert.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/why.h"

#include "node_internal.h"
#include "home.h"

static void ends_flush(npf_node *n);
static void sig_expect(npf_node *n, int ms, int probed);
static void sig_down(npf_sig *s, npf_sig_down code, const char *why, void *arg);
static void sig_ready(npf_sig *s, void *arg);
static void sig_msg(npf_sig *s, const npf_json *j, void *arg);
static void idle_watch(npf_node *n);
static int  node_waiting(const npf_node *n);
static void sig_do(npf_node *n, int a, npf_sig *s, npf_sig_down code, const char *why);
static void sc_arm(npf_node *n);

static const npf_sig_cbs sig_cbs = {sig_ready, sig_msg, sig_down};

static int is_udp(const npf_sig *s) { return s && npf_sig_via(s)[0] == 'u'; }
static int heard(const npf_sig *s) { return s && npf_sig_last_rx(s) != 0; }

/* ---- signaling ---- */

int64_t npf_node_time(const npf_node *n)
{
    return npf_unix_ms() + n->clock_offset_ms;
}

static int send_env(npf_sig *s, const char *type, const char *id, int app, const char *reply_to, const char *status,
                    const char *error, const char *data_json)
{
    npf_out w = {.max = NPF_JSON_MAX_SIZE, .secret = 1};    /* data carries passwords, codes, keys */
    int r = -1;
    if (!s)
        return -1;
    npf_out_jobj(&w);
    npf_out_kint(&w, "v", 1);
    npf_out_kstr(&w, "type", type);
    if (id) npf_out_kstr(&w, "id", id);
    if (app) npf_out_kbool(&w, "app", 1);
    if (reply_to) npf_out_kstr(&w, "reply_to", reply_to);
    if (status) npf_out_kstr(&w, "status", status);
    if (error) npf_out_kstr(&w, "error", error);
    npf_out_jkey(&w, "data");
    npf_out_jraw(&w, data_json ? data_json : "{}");
    npf_out_jend(&w);
    if (!w.failed) {
        /* the envelope only, never data (R10) */
        npf_logt("sig > %s%s%s%s%s%s%s%s%s, %d bytes", type, id ? " id=" : "", id ? id : "",
                 reply_to ? " reply_to=" : "", reply_to ? reply_to : "", status ? " " : "", status ? status : "",
                 error ? " " : "", error ? error : "", (int)w.len);
        r = npf_sig_send(s, w.p, w.len);
    }
    npf_out_free(&w);
    return r;
}

/* npf_node_send on connection s (request NPF_REQ_APP: an application's) */
static int send_on(npf_node *n, npf_sig *s, const char *type, int request, const char *data_json)
{
    char id[16];
    if (!request)
        return send_env(s, type, NULL, 0, NULL, NULL, NULL, data_json) < 0 ? -1 : 0;
    if (n->req_seq == INT_MAX)
        return -1;                         /* never wrap into negative / reused request ids */
    n->req_seq++;
    snprintf(id, sizeof id, "r%d", n->req_seq);
    return send_env(s, type, id, request == NPF_REQ_APP, NULL, NULL, NULL, data_json) < 0 ? -1 : n->req_seq;
}

int npf_node_send(npf_node *n, const char *type, int request, const char *data_json)
{
    return send_on(n, node_sig(n), type, request, data_json);
}

#define SIG_REPLY_MS 10000      /* a request sent: something from the server within, else a ping asks */
#define SIG_PONG_MS  10000      /* a ping sent: its pong (or anything) within */

static int request_as(npf_node *n, const char *type, int how, const char *data_json, npf_reply_fn fn, void *arg)
{
    int i, id;
    for (i = 0; i < NPF_PENDING_MAX; i++)
        if (!n->pending[i].fn)
            break;
    if (!fn || i == NPF_PENDING_MAX)
        return -1;
    id = npf_node_send(n, type, how, data_json);
    if (id < 0)
        return -1;
    n->pending[i].id = id;
    n->pending[i].fn = fn;
    n->pending[i].arg = arg;
    sig_expect(n, SIG_REPLY_MS, 0);     /* a connection that took it and carries nothing: found */
    return 0;
}

int npf_node_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg)
{
    return request_as(n, type, 1, data_json, fn, arg);
}

int npf_node_app_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg)
{
    return request_as(n, type, NPF_REQ_APP, data_json, fn, arg);
}

/* ---- call_end reports ---- */

static void end_reply(npf_node *n, const npf_env *env, int ok, void *arg)
{
    npf_end_report *e = arg;
    (void)ok;
    e->state = env ? 0 : 1;             /* answered: done; connection lost: again after the next login */
    if (env)
        ends_flush(n);                  /* a request slot is free again */
}

static void ends_flush(npf_node *n)
{
    char data[160];
    int i;
    if (!n->online)
        return;
    for (i = 0; i < NPF_ENDS_MAX; i++) {
        npf_end_report *e = &n->ends[i];
        if (e->state != 1)
            continue;
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"reason\":\"%s\",\"ago_ms\":%lld%s}", e->call_id, e->reason,
                 (long long)(npf_mono_ms() - e->at_ms), e->peer ? ",\"peer\":true" : "");
        if (npf_node_request(n, "call_end", data, end_reply, e) < 0)
            return;                     /* no request slot: on the next answer */
        e->state = 2;
    }
}

void npf_node_call_end(npf_node *n, const char *call_id, const char *reason, int peer)
{
    npf_end_report *e = NULL;
    int i;
    for (i = 0; i < NPF_ENDS_MAX && !(e && e->state == 0); i++)    /* a free one; full: the oldest waiting goes */
        if (n->ends[i].state == 0 || (n->ends[i].state == 1 && (!e || n->ends[i].at_ms < e->at_ms)))
            e = &n->ends[i];
    if (!e)
        return;
    snprintf(e->call_id, sizeof e->call_id, "%s", call_id);
    snprintf(e->reason, sizeof e->reason, "%s", reason);
    e->peer = peer;
    e->at_ms = npf_mono_ms();
    e->state = 1;
    if (!n->online)
        npf_log("call %s: ended (%s), the platform is told after the next login", call_id, reason);
    ends_flush(n);
}

void npf_node_cancel_requests(npf_node *n, void *arg)
{
    int i;
    for (i = 0; i < NPF_PENDING_MAX; i++)
        if (n->pending[i].fn && n->pending[i].arg == arg)
            n->pending[i].fn = NULL;
}

void node_sig_fail_pending(npf_node *n)
{
    int i;
    for (i = 0; i < NPF_PENDING_MAX; i++) {
        npf_reply_fn fn = n->pending[i].fn;
        if (fn) {
            n->pending[i].fn = NULL;
            fn(n, NULL, 0, n->pending[i].arg);
        }
    }
}

int npf_node_reply(npf_node *n, const char *type, const char *reply_to, const char *status,
                   const char *error, const char *data_json)
{
    return send_env(node_sig(n), type, NULL, 0, reply_to, status, error, data_json);
}

/* a new list from an external channel: drop the attempt in progress (to
 * the old list's servers) and connect again at once */
void node_reconnect_now(npf_node *n)
{
    if (n->online)
        return;
    node_sig_close(n);
    npf_timer_stop(n->loop, &n->t_reconnect);
    n->backoff_ms = 0;
    node_sig_connect(n);
}

/* The platform's upgrade policy for this program, from a welcome's
 * "upgrade", an "upgrade" event or the data of upgrade_required (j[d]: the
 * object; d < 0: none, which clears what was offered); the modules and
 * the application hear of an offer, or of its end, as kept (upgrade_event) */
#define UPGRADE_PACKAGES_MAX 16384

/* "upgrade" to the modules and the application: the offer as kept, not as
 * sent (its download page https only; the packages are read from
 * n->upgrade, where they are checked before use) */
static void upgrade_event(npf_node *n)
{
    static const char *const key[] = {"min", "latest", "url", "notes"};
    const char *v[] = {n->upgrade.min, n->upgrade.latest, n->upgrade.url, n->upgrade.notes};
    npf_out o = {0};
    npf_jtok tok[12];
    npf_json j;
    size_t k;
    if (!n->hooks.on_event)
        return;
    npf_out_jobj(&o);
    npf_out_kbool(&o, "required", n->upgrade.required);
    for (k = 0; k < sizeof v / sizeof v[0]; k++)
        if (v[k][0])
            npf_out_kstr(&o, key[k], v[k]);
    npf_out_jend(&o);
    if (!o.failed && npf_json_parse(&j, o.p, o.len, tok, 12) >= 0)
        n->hooks.on_event(n, "upgrade", &j, 0, n->hook_arg);
    npf_out_free(&o);
}

static void node_upgrade_apply(npf_node *n, const npf_json *j, int d, int required)
{
    int was = n->upgrade.latest[0] || n->upgrade.required;
    m_upgrade u;
    free(n->upgrade.packages);
    memset(&n->upgrade, 0, sizeof n->upgrade);
    if (npf_msg_parse(&m_upgrade_d, j, d, &u, NULL, 0) == 0) {
        const npf_jtok *pk = u.packages >= 0 ? &j->tok[u.packages] : NULL;
        n->upgrade.required = u.required || required;
        memcpy(n->upgrade.min, u.min, sizeof u.min);
        memcpy(n->upgrade.latest, u.latest, sizeof u.latest);
        if (strncmp(u.url, "https://", 8) == 0)   /* a link people click (the console, the tray): https only */
            memcpy(n->upgrade.url, u.url, sizeof u.url);
        else if (u.url[0])
            npf_logw("upgrade: the download page is not an https URL: not shown");
        memcpy(n->upgrade.notes, u.notes, sizeof u.notes);
        if (pk && pk->end - pk->start <= UPGRADE_PACKAGES_MAX && (n->upgrade.packages = malloc(pk->end - pk->start + 1))) {
            memcpy(n->upgrade.packages, j->s + pk->start, pk->end - pk->start);
            n->upgrade.packages[pk->end - pk->start] = 0;
        }
        if (n->upgrade.required)
            npf_logw("upgrade: this version is too old for the platform (%s needed%s%s)", u.min,
                     n->upgrade.url[0] ? ", see " : "", n->upgrade.url);
        else if (u.latest[0])
            npf_log("upgrade: version %s is available%s%s", u.latest, n->upgrade.url[0] ? ", see " : "", n->upgrade.url);
    } else if (was) {
        npf_log("upgrade: no newer version offered any more");
    }
    if (was || n->upgrade.required || n->upgrade.latest[0])
        upgrade_event(n);               /* an offer, or none any more */
}

static void reconnect_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_reconnect = NULL;
    node_sig_connect(n);
}

static void schedule_reconnect(npf_node *n)
{
    int d;
    if (!n->unreachable_since)
        n->unreachable_since = npf_mono_ms();   /* no server since now (sources.c counts from it) */
    node_sources_check(n);
    if (n->t_reconnect)
        return;
    /* exponential backoff with jitter, 1 s .. 60 s (security.md 7.3): the
     * wait is backoff_ms +-25 %, so the number logged and handed to
     * on_enroll_failed is what it is on average */
    d = n->backoff_ms ? n->backoff_ms : 1000;
    n->backoff_ms = d * 2 > 60000 ? 60000 : d * 2;
    d = d * 3 / 4 + (int)npf_rand_range(0, (size_t)d / 2);
    if (n->upgrade.required)        /* only an upgrade helps: 5..10 minutes between tries */
        d = n->th.upgrade_retry_ms ? (int)n->th.upgrade_retry_ms : 300000 + (int)npf_rand_range(0, 300000);
    n->t_reconnect = npf_timer_add(n->loop, d, reconnect_cb, n);
}

/* what is bound to the connection in use, which has gone: offline, its
 * ping and its watch stopped */
static void sig_drop(npf_node *n)
{
    n->online = 0;
    npf_timer_stop(n->loop, &n->t_ping);
    npf_timer_stop(n->loop, &n->t_expect);
}

void node_sig_close(npf_node *n)
{
    sc_close(&n->sc);
    npf_timer_stop(n->loop, &n->t_sc);
    sig_drop(n);
}

/* after a connection went: the requests on it learn there is no answer, the
 * calls being set up end, the next attempt is due when none is left, the
 * application told */
static void sig_gone(npf_node *n, const char *why, int was_online)
{
    node_sig_fail_pending(n);           /* (the spare stays: home-binding.md 9.3) */
    node_sig_lost(n);
    if (n->sc.state == SS_IDLE)
        schedule_reconnect(n);
    if (was_online && n->hooks.on_offline)
        n->hooks.on_offline(n, why, n->hook_arg);
}

static int cur_id(const npf_node *n) { return n->cur_server >= 0 ? n->servers[n->cur_server].id : -1; }

/* the platform turned this connection down (a login, an enrolment): it
 * goes; counted against the server by weight (0: not at all), and not a
 * failure of the network (the way around a VPN stays as it is) */
static void sig_refused(npf_node *n, int weight)
{
    if (weight && n->cur_server >= 0)
        node_server_failed(&n->servers[n->cur_server], weight);
    node_sig_close(n);
    sig_gone(n, "refused", 0);
}

/* drops the connection in use (and a second access point beside it) */
void node_sig_abort(npf_node *n, const char *why)
{
    npf_sig *s = node_sig(n);
    char d[300];
    npf_logw("signaling: %s, reconnecting (%s)", why, npf_sig_diag(s, d, sizeof d));
    sig_do(n, sc_abort(&n->sc, heard(s), npf_mono_ms()), s, NPF_SIG_DOWN_ERROR, why);
    npf_sig_close(s);
}

/* A connection can look up and carry nothing (a VPN's tunnel after the
 * system slept: the server's messages lost for a minute and more, calls to
 * this node timing out meanwhile; 2026-10-20). Something from the server is
 * due after each ping and each request: none in time, a ping asks; none to
 * that either, the connection is dropped and made again. */

static void expect_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    npf_sig *s = node_sig(n);
    (void)loop;
    n->t_expect = NULL;
    npf_logt("sig: watch due (%s, since %lld ms ago, heard %lld ms ago)", n->expect_probed ? "probed" : "a request",
             (long long)(npf_mono_ms() - n->expect_since), s ? (long long)(npf_mono_ms() - npf_sig_last_rx(s)) : -1LL);
    if (!s || !n->online || npf_sig_last_rx(s) >= n->expect_since)
        return;                     /* heard from it */
    if (!n->expect_probed) {
        n->expect_probed = 1;
        n->expect_since = npf_mono_ms();
        npf_sig_ping(s);
        n->t_expect = npf_timer_add(n->loop, SIG_PONG_MS, expect_cb, n);
        return;
    }
    node_sig_abort(n, "the server stopped answering");
}

/* something from the server is due within ms; probed: a ping is out for it.
 * One watch at a time: the one running stays, unless the server answered
 * since it began (it is done) or this one has a ping out and it has not
 * (a ping's pong is due sooner than a request's answer and then a ping's:
 * a request out at login, the server frozen, kept the ping's watch off and
 * the freeze went unnoticed for 20 s instead of 10) */
static void sig_expect(npf_node *n, int ms, int probed)
{
    if (!node_sig(n) || !n->online)
        return;
    if (n->t_expect) {
        if (npf_sig_last_rx(node_sig(n)) < n->expect_since && (n->expect_probed || !probed)) {
            npf_logt("sig: watch kept (%s, since %lld ms ago)", n->expect_probed ? "probed" : "a request",
                     (long long)(npf_mono_ms() - n->expect_since));
            return;
        }
        npf_timer_stop(n->loop, &n->t_expect);
    }
    n->expect_since = npf_mono_ms();
    n->expect_probed = probed;
    n->t_expect = npf_timer_add(n->loop, ms, expect_cb, n);
    npf_logt("sig: watch %d ms (%s)", ms, probed ? "probed" : "a request");
}

void node_sig_probe(npf_node *n)
{
    if (!node_sig(n) || !n->online || n->t_expect)
        return;
    npf_sig_ping(node_sig(n));
    sig_expect(n, SIG_PONG_MS, 1);
}

/* A ping only when the connection was quiet one way or the other for an
 * interval: nothing sent (the NAT's mapping, the server's read deadline) or
 * nothing heard (is the server there). A connection busy both ways needs
 * none; its requests are watched on their own (SIG_REPLY_MS). Each ping's
 * watch notices silence within 10 s. */
static void ping_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t ivl = (n->ping_s > 0 ? n->ping_s : 25) * 1000, now = npf_mono_ms();
    int64_t tx = npf_sig_last_tx(node_sig(n)), rx = npf_sig_last_rx(node_sig(n));
    int64_t due = (tx < rx ? tx : rx) + ivl;
    (void)loop;
    n->t_ping = NULL;
    if (due > now) {
        n->t_ping = npf_timer_add(n->loop, (int)(due - now), ping_cb, n);
        return;
    }
    npf_logt("sig: ping");
    npf_sig_ping(node_sig(n));
    sig_expect(n, SIG_PONG_MS, 1);      /* its pong in time, else the connection goes */
    n->t_ping = npf_timer_add(n->loop, (int)ivl, ping_cb, n);
}

/* ---- UDP first, the WebSocket the fallback (signaling-udp.md 5.3) ----
 * The connections, their roles and states: sigconn.c; here what each of
 * its transitions asks of the node (sig_do). udp_bad (the next attempts
 * are today's two WebSockets, until the network changes or UDP works
 * again): a WebSocket logged in while UDP never answered, the server was
 * too busy for the UDP session, or a UDP session did not log in. On the
 * WebSocket, every 10 min when no call is being set up and no request
 * waits, a UDP session logs in and takes over; the server replaces the
 * WebSocket (its "replaced" here is no reason to back off) and closes it. */

#define SIG_UDP_AGAIN_MS 600000     /* on the WebSocket: UDP again (+-20 %), when idle */

/* server e's signaling may go over UDP: it has an address, the main socket
 * is open, sig_udp is not off, and this is no hosted or on-demand program
 * (signaling-udp.md D16) */
static int udp_for(const npf_node *n, const npf_server_entry *e)
{
    return e->nudp > 0 && n->udp_fd >= 0 && !n->cfg.sig_udp_off && !n->cfg.udp_on_demand && !n->cfg.sig_idle_ms
           && !n->cfg.hosted_service && !n->cfg.hosted_exec;
}

const char *npf_node_udp_sig(const npf_node *n)
{
    return n->cur_server < 0 || !udp_for(n, &n->servers[n->cur_server]) ? "off" : n->sc.udp_bad ? "no_answer" : "ok";
}

/* the main socket carries the session (tests without UDP: lost) */
static int udp_send(const void *p, size_t len, const struct sockaddr_in *to, void *arg)
{
    npf_node *n = arg;
    return n->udp_fd >= 0 && !n->th.no_udp ? npf_udp_send(n->udp_fd, p, len, to) : -1;
}

static npf_sig *udp_open(npf_node *n, const npf_server_entry *e)
{
    return npf_sig_open_udp(n->loop, udp_send, &e->udp[e->fails % e->nudp], e->dh_pub, &n->id, &n->sig_cookie,
                            &sig_cbs, n);
}

int node_sig_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    if (fd != n->udp_fd || n->th.no_udp)
        return 0;
    return npf_sig_input(node_sig(n), from, buf, len) || npf_sig_input(n->sc.c[SR_MOVE].s, from, buf, len);
}

/* the WebSocket of connection r's server and URL, as r (how: for the log).
 * Around a VPN like the UDP sockets (connect_mode p2p: a tunnel that stalls
 * after the system slept took the signaling with it, 2026-10-20); through
 * it the next time when going around did not log in */
static npf_sig *ws_open(npf_node *n, int r, const char *how)
{
    npf_sigconn *c = &n->sc.c[r];
    npf_server_entry *f = &n->servers[c->server];
    npf_log("signaling: %s server %d %s", how, f->id, f->ws[c->url]);
    return c->s = npf_sig_open(n->loop, f->ws[c->url], f->dh_pub, &n->id, &sig_cbs, n, !n->cfg.secure && !n->sig_via_vpn);
}

static void move_arm(npf_node *n)
{
    int ms = n->th.sig_udp_again_ms > 0 ? (int)n->th.sig_udp_again_ms : node_wake_delay(SIG_UDP_AGAIN_MS);
    n->sc.move_at = 0;
    if (n->sc.state == SS_ONLINE && !is_udp(node_sig(n)) && n->cur_server >= 0
        && udp_for(n, &n->servers[n->cur_server]))
        n->sc.move_at = npf_mono_ms() + ms;
}

/* the leaf of a kept chain "inter | leaf": the platform has its
 * intermediates (a peer is given the whole chain) */
static void out_leaf(npf_out *w, const char *k, const uint8_t *chain, size_t len)
{
    npf_cert c;
    int i = npf_cert_parse(chain, len, &c);
    size_t at = i > 0 && (size_t)i < len ? (size_t)i : 0;
    npf_out_kb64(w, k, chain + at, len - at);
}

/* 1 when this node has no certificate or one with less than 30 days left by
 * its clock: login asks for a new one (the platform's record decides too) */
static int cert_due(const npf_node *n)
{
    npf_cert inter, leaf;
    int i = npf_cert_parse(n->cert, n->cert_len, &inter);
    return i <= 0 || npf_cert_parse(n->cert + i, n->cert_len - (size_t)i, &leaf) <= 0
           || (int64_t)leaf.not_after - npf_node_time(n) / 1000 < 30 * 86400;
}

/* the host the platform records (OS, machine, interfaces): a node sends the
 * first 12 bytes of BLAKE2b-256 of its JSON, and the JSON itself only once
 * the platform said it does not have that one (host_required) */
static void out_host(npf_node *n, npf_out *w)
{
    npf_host_info h;
    npf_out o = {0};
    uint8_t d[32];
    int i;
    npf_host_info_get(&h);
    npf_out_jobj(&o);
    npf_out_kstr(&o, "os", h.os);
    npf_out_kstr(&o, "arch", h.arch);
    npf_out_kstr(&o, "hostname", h.hostname);
    npf_out_kstr(&o, "machine_id", h.machine_id);
    npf_out_jkey(&o, "macs");
    npf_out_jarr(&o);
    for (i = 0; i < h.nmacs; i++)
        npf_out_jstr(&o, h.macs[i]);
    npf_out_jend(&o);
    npf_out_jend(&o);
    if (o.failed) {
        w->failed = 1;
    } else if (n->cfg.callable && !n->host_full) {
        npf_kdf(d, NULL, 0, o.p, o.len);
        npf_out_kb64(w, "host_digest", d, 12);
    } else {
        npf_out_jkey(w, "host");
        npf_out_jraw(w, o.p);
    }
    npf_out_free(&o);
}

static void send_login(npf_node *n, npf_sig *s)
{
    char num[24];
    npf_out w = {0};
    npf_out_jobj(&w);
    if (n->cfg.callable) {
        npf_out_kstr(&w, "role", "node");
        snprintf(num, sizeof num, "%llu", (unsigned long long)n->cfg.number);
        npf_out_kstr(&w, "number", num);
        if (cert_due(n))
            npf_out_kbool(&w, "renew", 1);
        if (n->account_cert_len)
            out_leaf(&w, "account_cert", n->account_cert, n->account_cert_len);
    } else if (n->cfg.hosted_service) {
        npf_out_kstr(&w, "role", "hosted");          /* npf-hosted itself (its key: hosted_keys) */
    } else {
        npf_out_kstr(&w, "role", "client");
        if (n->account_cert_len)
            out_leaf(&w, "cert", n->account_cert, n->account_cert_len);
    }
    if (n->cfg.callable && n->cfg.model) npf_out_kstr(&w, "model", n->cfg.model);
    if (n->cfg.callable && n->cfg.fw) npf_out_kstr(&w, "fw", n->cfg.fw);
    if (n->cfg.app_name) {
        npf_out_jkey(&w, "app");
        npf_out_jobj(&w);
        npf_out_kstr(&w, "name", n->cfg.app_name);
        npf_out_kstr(&w, "ver", n->cfg.app_ver);
        npf_out_jend(&w);
    }
    /* the full list's serial: after a seed list from DNS the server still
     * sends the full one */
    npf_out_kint(&w, "sl_serial", n->sl_full_serial ? n->sl_full_serial : n->sl_serial);
    if (!n->cfg.no_host_report)
        out_host(n, &w);                /* report_host = 0: none */
    npf_out_jend(&w);
    n->login_sent_ms = npf_mono_ms();
    if (w.failed || send_on(n, s, "login", 1, w.p) < 0)
        npf_logw("login: send failed");
    npf_out_free(&w);
}

/* ---- one key per model: enrol (security.md 5.2) ---- */

/* the number and the certificate an enrolment gave: a device number (nine
 * digits, its check digit right) and a node certificate for this
 * identity's key that the roots signed. Its validity period is not looked
 * at: an enrolment comes before the login sets the clock (a board without
 * a clock of its own starts in 1970); welcome's checks it */
static int enroll_got(npf_node *n, const m_enrolled *m)
{
    npf_cert inter, leaf;
    if (!npf_number_parse(m->number))
        return -1;
    if (npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, m->cert, (size_t)m->cert_len, &inter,
                             &leaf, 0) < 0
        || leaf.type != NPF_CERT_NODE || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
        npf_loge("enrol: the certificate given does not verify");
        return -1;
    }
    return 0;
}

static void enroll_reply(npf_node *n, const npf_env *e, int ok, void *arg)
{
    m_enrolled m;
    (void)arg;
    if (!e)
        return;                             /* the connection went: enrol again on the next one */
    if (!ok || npf_msg_parse(&m_enrolled_d, e->j, e->data, &m, NULL, 0) < 0 || enroll_got(n, &m) < 0) {
        const char *err = !ok ? (e->error[0] ? e->error : "no reply") : "bad_reply";
        npf_loge("enrol: refused (%s%s%s): %s", err, e->message[0] ? ", " : "", e->message,
                 npf_why_enroll_text(err, e->message));
        if (n->backoff_ms < 10000)
            n->backoff_ms = 10000;          /* enrol again later, not every second */
        n->enroll_state = NPF_ENROLL_REFUSED;
        snprintf(n->enroll_error, sizeof n->enroll_error, "%s", err);
        snprintf(n->enroll_reason, sizeof n->enroll_reason, "%.23s", e->message);
        n->enroll_at_unix_ms = npf_unix_ms();
        if (n->hooks.on_enroll_failed)
            n->hooks.on_enroll_failed(n, err, n->enroll_reason, n->backoff_ms / 1000, n->hook_arg);
        if (node_sig(n))                    /* the platform's answer: not the server's fault, nor the network's */
            sig_refused(n, 0);
        return;
    }
    n->enroll_state = NPF_ENROLL_DONE;
    n->enroll_error[0] = n->enroll_reason[0] = 0;
    n->enroll_at_unix_ms = npf_unix_ms();
    memcpy(n->cert, m.cert, (size_t)m.cert_len);
    n->cert_len = (size_t)m.cert_len;
    n->cfg.number = npf_number_parse(m.number);
    n->cfg.callable = 1;
    npf_log("enrol: number %.3s %.3s %.3s", m.number, m.number + 3, m.number + 6);
    if (n->hooks.on_enrolled)
        n->hooks.on_enrolled(n, n->cfg.number, n->hook_arg);
    send_login(n, node_sig(n));             /* on the same connection */
}

static void send_enroll(npf_node *n)
{
    const npf_enroll_req *e = n->cfg.enroll;
    uint8_t msg[64 + 1 + 64 + 32 + 32], sv[64], sd[64];   /* h is the 64-byte BLAKE2b handshake hash */
    size_t sl = strlen(e->serial), ml;
    int i;
    npf_out w = {0};
    if (sl == 0 || sl > 64) {
        npf_loge("enrol: no serial number (serial / serial_file)");
        return;
    }
    memcpy(msg, npf_sig_hash(node_sig(n)), 64);
    msg[64] = (uint8_t)sl;
    memcpy(msg + 65, e->serial, sl);
    memcpy(msg + 65 + sl, e->hw_fp, 32);
    memcpy(msg + 97 + sl, n->id.sign_pub, 32);
    ml = 129 + sl;
    npf_sign2(sv, e->model_sk, "npf-enroll-v1", 13, msg, ml);
    npf_sign2(sd, n->id.sign_sk, "npf-enroll-v1", 13, msg, ml);
    npf_out_jobj(&w);
    npf_out_kb64(&w, "model_chain", e->model_chain, e->model_chain_len);
    npf_out_kstr(&w, "serial", e->serial);
    npf_out_jkey(&w, "hw");
    npf_out_jarr(&w);
    for (i = 0; i < e->nhw; i++) {
        npf_out_jobj(&w);
        npf_out_kstr(&w, "k", e->hw_kind[i]);
        npf_out_kb64(&w, "h", e->hw_hash[i], 16);
        npf_out_jend(&w);
    }
    npf_out_jend(&w);
    npf_out_kb64(&w, "sign_pub", n->id.sign_pub, 32);
    npf_out_kb64(&w, "sig_v", sv, 64);
    npf_out_kb64(&w, "sig_d", sd, 64);
    if (n->cfg.model) npf_out_kstr(&w, "model", n->cfg.model);
    if (n->cfg.fw) npf_out_kstr(&w, "fw", n->cfg.fw);
    npf_out_jend(&w);
    {
        char kinds[8 * 17] = "";
        size_t o = 0;
        for (i = 0; i < e->nhw && o < sizeof kinds; i++)
            o += (size_t)snprintf(kinds + o, sizeof kinds - o, "%s%s", i ? ", " : "", e->hw_kind[i]);
        npf_log("enrol: serial %s with the model credential, hardware items: %s", e->serial, kinds);
    }
    i = w.failed || npf_node_request(n, "enroll", w.p, enroll_reply, NULL) < 0;
    npf_out_free(&w);
    if (i) {
        npf_logw("enrol: send failed");
        return;
    }
    if (n->enroll_state != NPF_ENROLL_REFUSED)
        n->enroll_state = NPF_ENROLL_SENT;  /* a refusal stays until the next answer */
}

const uint8_t *node_day_key(const npf_node *n, const npf_daykey keys[2])
{
    int64_t day = npf_node_time(n) / 86400000;
    int i;
    for (i = 0; i < 2; i++)
        if (keys[i].day == day)
            return keys[i].key;
    return keys[0].day ? keys[0].key : NULL;
}

/* the address probes the server names (login, "keys", "probe"): E1, E2 on
 * one probe server, E3 on another; none: no probe there. Returns 1 when
 * they changed */
static int node_apply_probe(npf_node *n, const m_welcome *m)
{
    struct sockaddr_in old[3];
    int k, nold = n->nprobe_ep;
    memcpy(old, n->probe_ep, sizeof old);
    memset(n->probe_ep, 0, sizeof n->probe_ep);
    for (k = 0; k < m->nprobe; k++)
        memcpy(&n->probe_ep[k], &m->probe[k], sizeof n->probe_ep[k]);
    n->nprobe_ep = m->nprobe;
    return n->nprobe_ep != nold || memcmp(old, n->probe_ep, sizeof old) != 0;
}

static void apply_keys(npf_node *n, const m_welcome *m)
{
    int i;
    if (m->ticket_len)
        memcpy(n->ticket, m->ticket, 28);
    memset(n->probe_keys, 0, sizeof n->probe_keys);
    for (i = 0; i < m->nprobe_keys; i++) {
        n->probe_keys[i].day = m->probe_keys[i].day;
        memcpy(n->probe_keys[i].key, m->probe_keys[i].key, 32);
    }
}

/* a (re)issued certificate from welcome or "account", this node's own or
 * (account) the account's (client) one, for this key: kept, and the program told */
static void cert_in(npf_node *n, const uint8_t *blob, size_t bl, int account)
{
    const char *what = account ? "account" : "node";
    npf_cert inter, leaf;
    /* bl: at most 1024 (msgs.h), the size of either */
    if (npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, blob, bl, &inter, &leaf,
                             npf_node_time(n) / 1000) < 0
        || leaf.type != (account ? NPF_CERT_CLIENT : NPF_CERT_NODE) || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
        npf_log("received %s certificate does not verify, ignored", what);
        return;
    }
    memcpy(account ? n->account_cert : n->cert, blob, bl);
    *(account ? &n->account_cert_len : &n->cert_len) = bl;
    npf_log("%s certificate received (expires in %lld days)", what,
            (long long)(leaf.not_after - npf_node_time(n) / 1000) / 86400);
    if (account && n->on_account_cert)
        n->on_account_cert(n, n->on_account_cert_arg);
    else if (!account && n->on_cert)
        n->on_cert(n, n->on_cert_arg);
}

/* a server list sent as base64url (welcome, server_list) at token t */
static void server_list_in(npf_node *n, const npf_json *j, int t)
{
    uint8_t *blob = t >= 0 ? malloc(65536) : NULL;     /* per call: other instances' threads */
    int bl = blob ? npf_json_b64(j, t, blob, 65536) : -1;
    if (bl > 0)
        node_server_list_update(n, blob, (size_t)bl, NULL);
    free(blob);
}

/* logged in (a: SA_WELCOME, SA_MOVED: on UDP after a move, no drop) */
static void welcome(npf_node *n, const npf_json *j, const m_welcome *m, int a)
{
    int moved = a == SA_MOVED;
    if (moved)
        npf_timer_stop(n->loop, &n->t_expect);  /* the old one's watch */
    if (m->time >= 0) {
        /* welcome.time was read half a round trip ago (punch start_at needs this) */
        int64_t rtt = npf_mono_ms() - n->login_sent_ms;
        n->clock_offset_ms = m->time + (rtt > 0 && rtt < 10000 ? rtt / 2 : 0) - npf_unix_ms();
    }
    if (m->server_id >= 0)
        n->server_id = (int)m->server_id;
    if (m->client_id[0])
        n->client_id = strtoull(m->client_id, NULL, 10);
    n->account_id = strtoull(m->account_id, NULL, 10);
    if (!n->account_id && n->account_cert_len) {
        /* the platform no longer accepts our account session */
        npf_logw("login: account session expired or revoked, log in again");
        n->account_cert_len = 0;
        if (n->on_account)
            n->on_account(n, n->hook_arg);
    }
    if (m->ping_s)
        n->ping_s = (int)m->ping_s;
    node_upgrade_apply(n, j, m->upgrade, 0);
    apply_keys(n, m);
    node_apply_probe(n, m);             /* measured below (node_nat_login) */
    /* a node's own certificate in "cert"; the account's in "account_cert"
     * for nodes, in "cert" for pure clients (signaling.md "welcome") */
    if (m->cert_len)
        cert_in(n, m->cert, (size_t)m->cert_len, !n->cfg.callable);
    if (m->account_cert_len)
        cert_in(n, m->account_cert, (size_t)m->account_cert_len, 1);
    server_list_in(n, j, m->server_list);
    n->online = 1;
    if (!moved)
        n->logins++;                    /* a move to UDP is no drop */
    if (a & SA_UDP_BAD)
        npf_log("signaling: udp did not answer, using ws; udp again in 10 min");
    n->last_login_unix_ms = npf_unix_ms();
    n->unreachable_since = 0;
    n->sig_error[0] = 0;
    n->sig_refused = 0;
    n->src_backoff = 0;
    n->src_next = 0;
    n->backoff_ms = 0;
    if (n->cur_server >= 0)
        n->servers[n->cur_server].fails = 0;
    npf_log("login: online at server %d (clock offset %lld ms)", n->server_id, (long long)n->clock_offset_ms);
    npf_timer_cancel(n->loop, n->t_ping);
    n->t_ping = npf_timer_add(n->loop, (n->ping_s > 0 ? n->ping_s : 25) * 1000, ping_cb, n);
    ends_flush(n);                      /* call ends from while signaling was down */
    if (!moved)
        node_calls_relogin(n);          /* what the calls sent on the connection that went */
    idle_watch(n);
    move_arm(n);
    node_home_login(n);                 /* the spare allocation, while the NAT is measured */
    node_nat_login(n);                  /* calls hooks.on_login at once, or after the first probe */
}

/* login's reply: welcome, or a refusal */
void node_on_login(npf_node *n, const m_env *e, const void *m)
{
    int ok = strcmp(e->status, "ok") == 0, a;
    if (!e->reply_to[0])
        return;
    if (!ok && strcmp(e->error, "host_required") == 0 && n->cfg.callable && !n->host_full) {
        n->host_full = 1;               /* the platform lacks this host digest: the JSON, on this connection */
        send_login(n, n->msg_sig ? n->msg_sig : node_sig(n));
        return;
    }
    a = sc_login(&n->sc, sc_role(&n->sc, n->msg_sig), ok, npf_mono_ms());
    if (a != SA_REFUSED) {
        if ((a & ~SA_UDP_BAD) == SA_WELCOME || a == SA_MOVED)
            welcome(n, e->j, m, a);
        else if (a == SA_MOVE_FAILED)
            sig_do(n, a, n->msg_sig, NPF_SIG_DOWN_ERROR, e->error);     /* the UDP login refused: on the WebSocket still */
        sc_arm(n);
        return;
    }
    npf_logw("login: rejected (%s)", e->error);
    if (strcmp(e->error, "upgrade_required") == 0) {
        node_upgrade_apply(n, e->j, e->data, 1);
        snprintf(n->sig_error, sizeof n->sig_error, "this version is too old for the platform: upgrade to %s%s",
                 n->upgrade.min[0] ? n->upgrade.min : "the newest version", n->upgrade.url[0] ? " (see the download page)" : "");
    } else {
        snprintf(n->sig_error, sizeof n->sig_error, "server %d refused the login (%s)", cur_id(n), e->error);
    }
    n->sig_refused = 1;
    sig_refused(n, 3);
}

/* the connection's account session began or ended (signaling.md
 * "account": a login, logout, deletion, a session no longer valid) */
void node_on_account(npf_node *n, const m_env *e, const void *msg)
{
    const m_welcome *m = msg;
    uint64_t was = n->account_id;
    (void)e;
    n->account_id = strtoull(m->account_id, NULL, 10);
    npf_log("account %llu: session %s", (unsigned long long)(n->account_id ? n->account_id : was),
            n->account_id ? "started" : "ended");
    if (!n->account_id)
        n->account_cert_len = 0;
    else if (m->account_cert_len)
        cert_in(n, m->account_cert, (size_t)m->account_cert_len, 1);
    if (n->on_account)
        n->on_account(n, n->hook_arg);
}

void node_on_server_list(npf_node *n, const m_env *e, const void *m)
{
    server_list_in(n, e->j, ((const m_server_list *)m)->blob);
}

/* the policy changed (the modules and the application hear of it there) */
void node_on_upgrade(npf_node *n, const m_env *e, const void *m)
{
    (void)m;
    node_upgrade_apply(n, e->j, e->data, 0);
}

void node_on_probe(npf_node *n, const m_env *e, const void *m)
{
    (void)e;
    /* other probes while online (another server came or went): measured again */
    if (node_apply_probe(n, m) && n->online && n->udp_fd >= 0 && !n->probe)
        node_nat_refresh(n);
}

void node_on_keys(npf_node *n, const m_env *e, const void *m)
{
    apply_keys(n, m);
    node_on_probe(n, e, m);
}

/* the server closes this connection next: not when it is the one our
 * move to UDP replaces (another connection's, or while the move logs in) */
void node_on_replaced(npf_node *n, const m_env *e, const void *m)
{
    (void)e, (void)m;
    if (sc_replaced(&n->sc, sc_role(&n->sc, n->msg_sig)))
        n->replaced_ms = npf_mono_ms();
}

void node_on_redirect(npf_node *n, const m_env *e, const void *msg)
{
    const m_redirect *m = msg;
    int i, was_online = n->online;
    (void)e;
    for (i = 0; i < n->nservers && n->servers[i].id != m->server_id; i++)
        ;
    if (i == n->nservers)
        return;                         /* not in the signed list: ignore */
    npf_log("redirect to server %lld", (long long)m->server_id);
    /* a disconnect like any other, not the server's failure (it kept its
     * ping and watch running, its requests waiting, and told the
     * application nothing) */
    n->cur_server = i;
    node_sig_close(n);
    n->backoff_ms = 1000;
    sig_gone(n, "redirected", was_online);
}

int node_sig_reply(npf_node *n, const m_env *e)
{
    int i;
    for (i = 0; i < NPF_PENDING_MAX && e->reply_to[0] == 'r'; i++) {
        char expected[24];
        npf_reply_fn fn = n->pending[i].fn;
        if (!fn)
            continue;
        snprintf(expected, sizeof expected, "r%d", n->pending[i].id);
        if (strcmp(e->reply_to, expected) == 0) {
            n->pending[i].fn = NULL;
            fn(n, e, strcmp(e->status, "ok") == 0, n->pending[i].arg);
            return 1;
        }
    }
    return 0;
}

/* ---- the transitions (sigconn.c) and what they ask of the node ---- */

static void sc_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int a;
    (void)loop;
    n->t_sc = NULL;
    while ((a = sc_tick(&n->sc, npf_mono_ms())) != SA_NONE)
        sig_do(n, a, node_sig(n), NPF_SIG_DOWN_ERROR, NULL);
    sc_arm(n);
}

/* the timer at the machine's next due */
static void sc_arm(npf_node *n)
{
    int64_t at = sc_next(&n->sc), now = npf_mono_ms();
    npf_timer_stop(n->loop, &n->t_sc);
    if (at)
        n->t_sc = npf_timer_add(n->loop, at > now ? (int)(at - now) : 0, sc_cb, n);
}

/* no connection is left: offline, the next attempt due */
static void sig_failed(npf_node *n, npf_sig *s, npf_sig_down code, const char *why)
{
    int was_online = n->online;
    if (!was_online && !is_udp(s) && !n->cfg.secure && npf_net_bypass_active()) {
        /* no login this time: the next attempt the other way (around a VPN, or
         * on the default route for servers reachable through the VPN only) */
        n->sig_via_vpn = !n->sig_via_vpn;
        npf_log("signaling: the next attempt %s", n->sig_via_vpn ? "on the default route (through the VPN)"
                                                                : "around the VPN");
    }
    sig_drop(n);
    /* "replaced" counts for the close that follows it, not for one long
     * after (a server that did not close) */
    if (n->replaced_ms && npf_mono_ms() - n->replaced_ms < 10000) {
        /* not the server's fault: the same identity logged in again elsewhere
         * (another process with these files, a copy of them on another host).
         * Taking it back at once would push that one off in turn, both every
         * second; back off instead, and say why */
        int up = n->last_login_unix_ms && npf_unix_ms() - n->last_login_unix_ms > 120000;
        n->replaced_backoff_ms = up || !n->replaced_backoff_ms ? 10000
                                 : n->replaced_backoff_ms * 2 > 300000 ? 300000 : n->replaced_backoff_ms * 2;
        n->backoff_ms = n->replaced_backoff_ms;
        npf_logw("signaling: this identity logged in elsewhere (another npf with the same files?): "
                 "logging in again in %d s", n->replaced_backoff_ms / 1000);
    } else if (n->cur_server >= 0)
        node_server_failed(&n->servers[n->cur_server], 1);
    n->replaced_ms = 0;
    if (!was_online) {              /* an attempt that did not log in: the status says why */
        snprintf(n->sig_error, sizeof n->sig_error, "server %d: %s", cur_id(n), why ? why : "?");
        n->sig_refused = 0;
    }
    if (code == NPF_SIG_DOWN_CLOSED || code == NPF_SIG_DOWN_BUSY)     /* the server's CLOSE */
        npf_log("signaling: udp session lost (%s)", why);
    else
        npf_log("signaling: disconnected (%s)", why);
    sig_gone(n, why, was_online);
}

/* what the machine's transition a asks of the node; s, why: the event's
 * connection and reason (timers: the connection in use, none) */
static void sig_do(npf_node *n, int a, npf_sig *s, npf_sig_down code, const char *why)
{
    npf_sigc *m = &n->sc;
    int was_online = n->online;
    if (a & SA_UDP_BAD) {
        if ((a &= ~SA_UDP_BAD) == SA_LATE)
            npf_log("signaling: no login over udp, using ws; udp again in 10 min");
        else
            npf_log("signaling: server %d busy over udp, using ws; udp again in 10 min", cur_id(n));
    }
    switch (a) {
    case SA_RACE_WON:
        n->cur_server = m->c[SR_MAIN].server;
        npf_log("signaling: server %d %s answered first", cur_id(n), "(second access point)");
        /* fall through */
    case SA_FIRST:
        if (is_udp(s))
            npf_log("signaling: server %d over udp (handshake %lld ms)", cur_id(n),
                    (long long)(npf_mono_ms() - n->sig_open_ms));
        else if (m->udp_silent >= 0)
            npf_log("signaling: server %d over ws (udp: %s)", cur_id(n), m->udp_silent ? "no answer" : "slower");
        n->host_full = 0;
        if (n->cfg.enroll && !n->cfg.number)
            send_enroll(n);                 /* the first message instead of login (security.md 5.2) */
        else
            send_login(n, s);
        break;
    case SA_MOVE_LOGIN:
        send_login(n, s);                   /* it takes over once logged in */
        break;
    case SA_OLD_CLOSED:                     /* replaced by the UDP session, closed by the server or us */
        npf_log("signaling: on udp, ws closed");
        break;
    case SA_MOVE_FAILED:
        npf_log("signaling: udp failed (%s), staying on ws", why);
        move_arm(n);
        break;
    case SA_RACE_FAILED:                    /* the second access point failed: the first one goes on */
        npf_log("signaling: second access point server %d failed (%s)", n->servers[m->c[SR_RACE].server].id, why);
        node_server_failed(&n->servers[m->c[SR_RACE].server], 1);
        break;
    case SA_WS_NOW:
        npf_log("signaling: server %d udp failed (%s), ws now", cur_id(n), why);
        if (!ws_open(n, SR_MAIN, "and to"))
            sig_do(n, sc_down(m, SR_MAIN, 1, 0, npf_mono_ms()), s, NPF_SIG_DOWN_ERROR, why);
        break;
    case SA_TO_RACE:                        /* the first failed while the second still tries */
        npf_log("signaling: server %d failed (%s), waiting for the second access point", cur_id(n), why);
        if (n->cur_server >= 0)
            node_server_failed(&n->servers[n->cur_server], 1);
        n->cur_server = m->c[SR_MAIN].server;
        break;
    case SA_TAKEN:
        /* the server closed the WebSocket it replaced by the UDP login,
         * whose welcome is late (lost, sent again): the move, no drop */
        npf_log("signaling: ws closed after the move, the udp welcome on its way");
        npf_timer_stop(n->loop, &n->t_expect);
        sig_expect(n, SIG_REPLY_MS, 0);     /* the welcome is due */
        break;
    case SA_UDP_GOES_ON:
        npf_log("signaling: disconnected (%s), the udp session goes on", why);
        sig_drop(n);
        sig_gone(n, why, was_online);
        break;
    case SA_GONE:
        sig_failed(n, s, code, why);
        break;
    case SA_OPEN_RACE:                      /* the WebSocket of the server UDP is tried on */
        ws_open(n, SR_RACE, "and to");
        break;
    case SA_LATE:
        /* drop a connection that makes no progress: nothing else would notice (a
         * stalled TCP/TLS/handshake, or a server that went silent behind a NAT),
         * and the node stayed offline for an hour (Mac, 2026-10-06) */
        node_sig_abort(n, "no login within 20 s");
        break;
    case SA_MOVE_DUE:
        if (n->cur_server < 0)
            break;
        if (node_calls_setting_up(n) || node_waiting(n)) {
            m->move_at = npf_mono_ms() + 30000;     /* when idle */
            break;
        }
        npf_log("signaling: moving to udp");
        if ((s = udp_open(n, &n->servers[n->cur_server])) != NULL)
            sc_open(m, SR_MOVE, s, n->cur_server, -1);
        else
            move_arm(n);
        break;
    }
    sc_arm(n);
}

/* the first access point to finish the Noise handshake stays, the other one
 * is closed before it logs in (security.md 7.5) */
static void sig_ready(npf_sig *s, void *arg)
{
    npf_node *n = arg;
    sig_do(n, sc_ready(&n->sc, sc_role(&n->sc, s), heard(node_sig(n))), s, NPF_SIG_DOWN_ERROR, NULL);
}

static void sig_msg(npf_sig *s, const npf_json *j, void *arg)
{
    npf_node *n = arg;
    n->msg_sig = s;
    node_msg(n, j);
    n->msg_sig = NULL;
}

static void sig_down(npf_sig *s, npf_sig_down code, const char *why, void *arg)
{
    npf_node *n = arg;
    sig_do(n, sc_down(&n->sc, sc_role(&n->sc, s), heard(s), code == NPF_SIG_DOWN_BUSY, npf_mono_ms()), s, code, why);
}

void node_sig_connect(npf_node *n)
{
    npf_server_entry *e;
    npf_sig *s;
    int i, r = -1, u = 0;
    if (n->sc.state != SS_IDLE)
        return;
    if (n->cur_server < 0 || n->servers[n->cur_server].fails >= 3)
        n->cur_server = node_server_pick(n, -1, -1);
    if (n->cur_server < 0) {
        npf_log("signaling: no usable server in the list");
        snprintf(n->sig_error, sizeof n->sig_error, "no usable server in the list");
        n->sig_refused = 0;
        schedule_reconnect(n);
        return;
    }
    e = &n->servers[n->cur_server];
    i = e->fails % (e->nws ? e->nws : 1);
    n->sig_open_ms = npf_mono_ms();
    if (udp_for(n, e) && !n->sc.udp_bad) {  /* UDP, and the WebSocket a second later */
        char a[64];
        npf_log("signaling: connecting to server %d udp %s (ws after 1 s)", e->id,
                npf_addr_str(&e->udp[e->fails % e->nudp], a, sizeof a));
        if ((s = udp_open(n, e)) != NULL) {
            sc_start(&n->sc, s, n->cur_server, i, 1, n->sig_open_ms);
            sc_arm(n);
            return;
        }
    }
    sc_start(&n->sc, NULL, n->cur_server, i, 0, n->sig_open_ms);
    if (!ws_open(n, SR_MAIN, "connecting to")) {
        sc_close(&n->sc);
        node_server_failed(e, 1);
        npf_logw("signaling: cannot connect to %s", e->ws[i]);
        /* the URL cut to what sig_error holds (a 256-byte URL in 160) */
        snprintf(n->sig_error, sizeof n->sig_error, "cannot connect to %.*s",
                 (int)(sizeof n->sig_error - sizeof "cannot connect to "), e->ws[i]);
        n->sig_refused = 0;
        schedule_reconnect(n);
        return;
    }
    /* and a second access point at the same time: the server's next URL (a
     * domain and an IP), else another server of the same priority, but not
     * while a call is up: the server rebinds a call to the identity's new
     * connection only on itself (as the UDP attempt's race, this server's
     * own; another one once fails says it is gone) */
    if (e->nws > 1) {
        r = n->cur_server;
        u = (i + 1) % e->nws;
    } else if (!node_calls_up(n) && (r = node_server_pick(n, node_eff_prio(e), n->cur_server)) >= 0)
        u = n->servers[r].fails % n->servers[r].nws;
    if (r >= 0) {
        sc_open(&n->sc, SR_RACE, NULL, r, u);
        ws_open(n, SR_RACE, "and to");
    }
    sc_arm(n);
}

/* ---- signaling on demand (cfg.sig_idle_ms: hosted clients) ---- */

#define SIG_IDLE_TICK_MS 1000

/* the time to the next periodic wake: sig_wake_ms +-20 %, drawn each
 * time. Instances that went to sleep together (npf-hosted's accounts after
 * a restart: 200 at once) would else wake together every period for good:
 * a herd of logins every 10.5 min, 0.9 s for another node's login */
int node_wake_delay(int ms)
{
    return ms - ms / 5 + (int)npf_rand_range(0, (size_t)(ms / 5) * 2);
}

static void wake_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_wake = NULL;
    npf_node_wake(n, "periodic refresh");
}

/* a request waits for its reply, or a call end for its report's */
static int node_waiting(const npf_node *n)
{
    int i;
    for (i = 0; i < NPF_PENDING_MAX; i++)
        if (n->pending[i].fn)
            return 1;
    for (i = 0; i < NPF_ENDS_MAX; i++)
        if (n->ends[i].state)
            return 1;
    return 0;
}

/* something needs the connection: a call, a request waiting for its
 * reply, a call end to report, or the application says so */
static int node_busy(npf_node *n)
{
    return n->calls || node_waiting(n) || (n->hooks.busy && n->hooks.busy(n, n->hook_arg));
}

static void idle_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int64_t now = npf_mono_ms();
    n->t_idle = NULL;
    if (!n->online || n->dormant)
        return;
    if (node_busy(n))
        n->busy_at = now;
    if (now - n->busy_at < n->cfg.sig_idle_ms) {
        n->t_idle = npf_timer_add(loop, SIG_IDLE_TICK_MS, idle_cb, n);
        return;
    }
    npf_log("signaling: not needed for %d s: disconnecting until it is", n->cfg.sig_idle_ms / 1000);
    node_sig_close(n);
    n->dormant = 1;
    if (n->cfg.udp_on_demand && !n->calls)
        node_udp_close_idle(n);
    node_sig_fail_pending(n);
    if (n->cfg.sig_wake_ms > 0)
        n->t_wake = npf_timer_add(loop, node_wake_delay(n->cfg.sig_wake_ms), wake_cb, n);
}

/* logged in: on demand, watch for the time nothing needs the connection */
static void idle_watch(npf_node *n)
{
    if (n->cfg.sig_idle_ms <= 0 || n->t_idle)
        return;
    n->busy_at = npf_mono_ms();
    n->t_idle = npf_timer_add(n->loop, SIG_IDLE_TICK_MS, idle_cb, n);
}

int npf_node_wake(npf_node *n, const char *why)
{
    if (!n->dormant)
        return 0;
    n->dormant = 0;
    npf_timer_stop(n->loop, &n->t_wake);
    npf_log("signaling: connecting (%s)", why);
    n->backoff_ms = 0;
    node_sig_connect(n);
    return 1;
}

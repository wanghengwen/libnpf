/* Signaling requests, login, enrolment and reconnection. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "npf/candidates.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"
#include "home.h"

static void ends_flush(npf_node *n);
static void sig_expect(npf_node *n, int ms, int probed);
static void expect_stop(npf_node *n);
static void sig_down(npf_sig *s, const char *why, void *arg);
static void idle_watch(npf_node *n);

/* ---- signaling ---- */

int64_t npf_node_time(const npf_node *n)
{
    return npf_unix_ms() + n->clock_offset_ms;
}

static int send_env(npf_node *n, const char *type, const char *id, const char *reply_to, const char *status,
                    const char *error, const char *data_json)
{
    npf_out w = {.max = NPF_JSON_MAX_SIZE, .secret = 1};    /* data carries passwords, codes, keys */
    int r = -1;
    if (!n->sig)
        return -1;
    npf_out_jobj(&w);
    npf_out_kint(&w, "v", 1);
    npf_out_kstr(&w, "type", type);
    if (id) npf_out_kstr(&w, "id", id);
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
        r = npf_sig_send(n->sig, w.p, w.len);
    }
    npf_out_free(&w);
    return r;
}

int npf_node_send(npf_node *n, const char *type, int request, const char *data_json)
{
    char id[16];
    if (!request)
        return send_env(n, type, NULL, NULL, NULL, NULL, data_json) < 0 ? -1 : 0;
    if (n->req_seq == INT_MAX)
        return -1;                         /* never wrap into negative / reused request ids */
    n->req_seq++;
    snprintf(id, sizeof id, "r%d", n->req_seq);
    return send_env(n, type, id, NULL, NULL, NULL, data_json) < 0 ? -1 : n->req_seq;
}

#define SIG_REPLY_MS 10000      /* a request sent: something from the server within, else a ping asks */
#define SIG_PONG_MS  10000      /* a ping sent: its pong (or anything) within */

int npf_node_request(npf_node *n, const char *type, const char *data_json, npf_reply_fn fn, void *arg)
{
    int i, id;
    for (i = 0; i < NPF_PENDING_MAX; i++)
        if (!n->pending[i].fn)
            break;
    if (!fn || i == NPF_PENDING_MAX)
        return -1;
    id = npf_node_send(n, type, 1, data_json);
    if (id < 0)
        return -1;
    n->pending[i].id = id;
    n->pending[i].fn = fn;
    n->pending[i].arg = arg;
    sig_expect(n, SIG_REPLY_MS, 0);     /* a connection that took it and carries nothing: found */
    return 0;
}

/* ---- call_end reports ---- */


static void end_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    npf_end_report *e = arg;
    (void)ok;
    e->state = j ? 0 : 1;               /* answered: done; connection lost: again after the next login */
    if (j)
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
    for (i = 0; i < NPF_ENDS_MAX && !e; i++)
        if (n->ends[i].state == 0)
            e = &n->ends[i];
    for (i = 0; i < NPF_ENDS_MAX && !e; i++)      /* full: the oldest waiting one goes */
        if (n->ends[i].state == 1 && (!e || n->ends[i].at_ms < e->at_ms))
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
    return send_env(n, type, NULL, reply_to, status, error, data_json);
}


/* a new list from an external channel: drop the attempt in progress (to
 * the old list's servers) and connect again at once */
void node_reconnect_now(npf_node *n)
{
    if (n->online)
        return;
    node_sig_close(n);
    npf_timer_stop(n->loop, &n->t_reconnect);
    npf_timer_stop(n->loop, &n->t_login);
    n->backoff_ms = 0;
    node_sig_connect(n);
}

/* The platform's upgrade policy for this program, from a welcome's
 * "upgrade", an "upgrade" event or the data of upgrade_required (j[d]: the
 * object; d < 0: none, which clears what was offered); notify: tell the
 * modules of an offer (the "upgrade" event does reach them by itself; a
 * welcome's does not) */
#define UPGRADE_PACKAGES_MAX 16384

static void node_upgrade_apply(npf_node *n, const npf_json *j, int d, int required, int notify)
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
        memcpy(n->upgrade.url, u.url, sizeof u.url);
        memcpy(n->upgrade.notes, u.notes, sizeof u.notes);
        if (pk && pk->end - pk->start <= UPGRADE_PACKAGES_MAX && (n->upgrade.packages = malloc(pk->end - pk->start + 1))) {
            memcpy(n->upgrade.packages, j->s + pk->start, pk->end - pk->start);
            n->upgrade.packages[pk->end - pk->start] = 0;
        }
        if (n->upgrade.required)
            npf_logw("upgrade: this version is too old for the platform (%s needed%s%s)", u.min,
                     u.url[0] ? ", see " : "", u.url);
        else if (u.latest[0])
            npf_log("upgrade: version %s is available%s%s", u.latest, u.url[0] ? ", see " : "", u.url);
        if (notify && (n->upgrade.required || u.latest[0]) && n->hooks.on_event)
            n->hooks.on_event(n, "upgrade", j, d, n->hook_arg);
    } else if (was) {
        npf_log("upgrade: no newer version offered any more");
    }
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

#define SIG_LOGIN_MS 20000         /* connect, TLS, upgrade, Noise and login together */


/* the second access point closed */
static void race_drop(npf_node *n)
{
    if (n->race)
        npf_sig_close(n->race);
    n->race = NULL;
}

/* what is bound to the connection in use, which has gone (the caller closes
 * or has closed it): offline, its ping and its watch stopped */
static void sig_drop(npf_node *n)
{
    n->sig = NULL;
    n->online = 0;
    npf_timer_stop(n->loop, &n->t_ping);
    expect_stop(n);
}

void node_sig_close(npf_node *n)
{
    npf_sig *s = n->sig;
    race_drop(n);
    sig_drop(n);
    if (s)
        npf_sig_close(s);
}

/* after a connection went: the requests on it learn there is no answer, the
 * calls being set up end, the next attempt is due, the application told */
static void sig_gone(npf_node *n, const char *why, int was_online)
{
    node_sig_fail_pending(n);           /* (the spare stays: home-binding.md 9.3) */
    node_sig_lost(n);
    schedule_reconnect(n);
    if (was_online && n->hooks.on_offline)
        n->hooks.on_offline(n, why, n->hook_arg);
}

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

void node_sig_abort(npf_node *n, const char *why)
{
    npf_sig *s = n->sig;
    race_drop(n);
    npf_logw("signaling: %s, reconnecting", why);
    sig_down(s, why, n);            /* n->sig = NULL, reconnect scheduled */
    npf_sig_close(s);
}

/* drop a connection that makes no progress: nothing else would notice (a
 * stalled TCP/TLS/handshake, or a server that went silent behind a NAT),
 * and the node stayed offline for an hour (Mac, 2026-10-06) */
static void login_deadline(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_login = NULL;
    if (n->sig && !n->online)
        node_sig_abort(n, "no login within 20 s");
}

/* A connection can look up and carry nothing (a VPN's tunnel after the
 * system slept: the server's messages lost for a minute and more, calls to
 * this node timing out meanwhile; 2026-10-20). Something from the server is
 * due after each ping and each request: none in time, a ping asks; none to
 * that either, the connection is dropped and made again. */

static void expect_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_expect = NULL;
    npf_logt("sig: watch due (%s, since %lld ms ago, heard %lld ms ago)", n->expect_probed ? "probed" : "a request",
             (long long)(npf_mono_ms() - n->expect_since),
             n->sig ? (long long)(npf_mono_ms() - npf_sig_last_rx(n->sig)) : -1LL);
    if (!n->sig || !n->online || npf_sig_last_rx(n->sig) >= n->expect_since)
        return;                     /* heard from it */
    if (!n->expect_probed) {
        n->expect_probed = 1;
        n->expect_since = npf_mono_ms();
        npf_sig_ping(n->sig);
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
    if (!n->sig || !n->online)
        return;
    if (n->t_expect) {
        if (npf_sig_last_rx(n->sig) < n->expect_since && (n->expect_probed || !probed)) {
            npf_logt("sig: watch kept (%s, since %lld ms ago)", n->expect_probed ? "probed" : "a request",
                     (long long)(npf_mono_ms() - n->expect_since));
            return;
        }
        expect_stop(n);
    }
    n->expect_since = npf_mono_ms();
    n->expect_probed = probed;
    n->t_expect = npf_timer_add(n->loop, ms, expect_cb, n);
    npf_logt("sig: watch %d ms (%s)", ms, probed ? "probed" : "a request");
}

static void expect_stop(npf_node *n)
{
    npf_timer_stop(n->loop, &n->t_expect);
}

void node_sig_probe(npf_node *n)
{
    if (!n->sig || !n->online || n->t_expect)
        return;
    npf_sig_ping(n->sig);
    sig_expect(n, SIG_PONG_MS, 1);
}

static void ping_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    int ivl = (n->ping_s > 0 ? n->ping_s : 25) * 1000;
    (void)loop;
    n->t_ping = NULL;
    if (!n->sig)
        return;
    /* no check of its own for silence here: each ping's watch notices it
     * within 10 s (sooner than three intervals of silence ever could: at
     * ping_s 5 both came due at once, and the reason was either one) */
    npf_logt("sig: ping");
    npf_sig_ping(n->sig);
    sig_expect(n, SIG_PONG_MS, 1);      /* its pong in time, else the connection goes */
    n->t_ping = npf_timer_add(n->loop, ivl, ping_cb, n);
}

static void send_login(npf_node *n)
{
    char num[24];
    npf_out w = {0};
    npf_out_jobj(&w);
    if (n->cfg.callable) {
        npf_out_kstr(&w, "role", "node");
        snprintf(num, sizeof num, "%llu", (unsigned long long)n->cfg.number);
        npf_out_kstr(&w, "number", num);
        if (n->cert_len)
            npf_out_kb64(&w, "cert", n->cert, n->cert_len);
        if (n->account_cert_len)
            npf_out_kb64(&w, "account_cert", n->account_cert, n->account_cert_len);
    } else if (n->cfg.hosted_service) {
        npf_out_kstr(&w, "role", "hosted");          /* npf-hosted itself (its key: hosted_keys) */
    } else {
        npf_out_kstr(&w, "role", "client");
        if (n->account_cert_len)
            npf_out_kb64(&w, "cert", n->account_cert, n->account_cert_len);
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
    if (!n->cfg.no_host_report) {
        /* the platform's connection record: OS, machine, interfaces (report_host = 0: none) */
        npf_host_info h;
        int i;
        npf_host_info_get(&h);
        npf_out_jkey(&w, "host");
        npf_out_jobj(&w);
        npf_out_kstr(&w, "os", h.os);
        npf_out_kstr(&w, "arch", h.arch);
        npf_out_kstr(&w, "hostname", h.hostname);
        npf_out_kstr(&w, "machine_id", h.machine_id);
        npf_out_jkey(&w, "macs");
        npf_out_jarr(&w);
        for (i = 0; i < h.nmacs; i++)
            npf_out_jstr(&w, h.macs[i]);
        npf_out_jend(&w);
        npf_out_jend(&w);
    }
    npf_out_jend(&w);
    n->login_sent_ms = npf_mono_ms();
    if (w.failed || npf_node_send(n, "login", 1, w.p) < 0)
        npf_logw("login: send failed");
    npf_out_free(&w);
}

/* ---- one key per model: enrol (security.md 5.2) ---- */

/* what an enrolment refusal's reason means (signaling.md "enroll") */
static const char *enroll_why(const char *err, const char *reason)
{
    static const struct { const char *r, *text; } t[] = {
        {"bad_chain", "the model credential is not one NPF's vendors signed"},
        {"bad_sig", "the enrolment's signatures are wrong"},
        {"unregistered", "the model is not registered on the platform (the vendor registers it)"},
        {"unbound", "this model credential was never given to the platform (the vendor binds it)"},
        {"revoked", "the model is disabled or this model credential revoked"},
        {"expired", "the model's registration has ended"},
        {"whitelist", "this serial number is not on the model's whitelist"},
        {"quota", "the model has all the devices it may have"},
        {"rate", "the model has had all its enrolments this hour"},
        {"clone", "a device with this serial number is online with other keys"},
        {"conflict", "this serial number belongs to another device (its owner releases it)"},
        {"wait", "the old identity was online moments ago"},
        {"disabled", "this device's number is disabled on the platform"},
    };
    size_t i;
    for (i = 0; reason[0] && i < sizeof t / sizeof t[0]; i++)
        if (strcmp(reason, t[i].r) == 0)
            return t[i].text;
    return strcmp(err, "rate_limited") == 0 ? "over the model's quota or rate, or the old identity was online moments ago"
           : strcmp(err, "conflict") == 0   ? "this serial number belongs to another device (the owner releases it)"
           : strcmp(err, "forbidden") == 0  ? "revoked credential, serial not on the whitelist, or the old identity is online"
                                            : "no reason given";
}

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

static void enroll_reply(npf_node *n, const npf_json *j, int ok, void *arg)
{
    m_env e;
    m_enrolled m;
    (void)arg;
    if (!j || node_env(j, &e) < 0)
        return;                             /* the connection went: enrol again on the next one */
    if (!ok || npf_msg_parse(&m_enrolled_d, j, e.data, &m, NULL, 0) < 0 || enroll_got(n, &m) < 0) {
        const char *err = !ok ? (e.error[0] ? e.error : "no reply") : "bad_reply";
        npf_loge("enrol: refused (%s%s%s): %s", err, e.message[0] ? ", " : "", e.message, enroll_why(err, e.message));
        if (n->backoff_ms < 10000)
            n->backoff_ms = 10000;          /* enrol again later, not every second */
        n->enroll_state = NPF_ENROLL_REFUSED;
        snprintf(n->enroll_error, sizeof n->enroll_error, "%s", err);
        snprintf(n->enroll_reason, sizeof n->enroll_reason, "%.23s", e.message);
        n->enroll_at_unix_ms = npf_unix_ms();
        if (n->hooks.on_enroll_failed)
            n->hooks.on_enroll_failed(n, err, n->enroll_reason, n->backoff_ms / 1000, n->hook_arg);
        if (n->sig)                         /* the platform's answer: not the server's fault, nor the network's */
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
    send_login(n);                          /* on the same connection */
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
    memcpy(msg, npf_sig_hash(n->sig), 64);
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

/* other probes while online (another server came or went): measured again */
static void probe_changed(npf_node *n)
{
    if (n->online && n->udp_fd >= 0 && !n->probe)
        node_nat_refresh(n);
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

/* a renewed account (client) certificate from welcome: keep it and tell the program */
static void node_accept_account_cert(npf_node *n, const uint8_t *blob, size_t bl)
{
    npf_cert inter, leaf;
    if (bl > sizeof n->account_cert
        || npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, blob, bl, &inter, &leaf,
                                npf_node_time(n) / 1000) < 0
        || leaf.type != NPF_CERT_CLIENT || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
        npf_log("login: received account certificate does not verify, ignored");
        return;
    }
    memcpy(n->account_cert, blob, bl);
    n->account_cert_len = bl;
    npf_log("login: account certificate renewed (expires in %lld days)",
            (long long)(leaf.not_after - npf_node_time(n) / 1000) / 86400);
    if (n->on_account_cert)
        n->on_account_cert(n, n->on_account_cert_arg);
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

static void welcome(npf_node *n, const npf_json *j, const m_welcome *m)
{
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
        if (n->on_account_lost)
            n->on_account_lost(n, n->hook_arg);
    }
    if (m->ping_s)
        n->ping_s = (int)m->ping_s;
    node_upgrade_apply(n, j, m->upgrade, 0, 1);
    apply_keys(n, m);
    node_apply_probe(n, m);             /* measured below (node_nat_login) */
    /* a (re)issued certificate: a node's own certificate in "cert"; the
     * account (client) certificate in "account_cert" for nodes, in "cert" for
     * pure clients (signaling.md "welcome") */
    if (m->cert_len) {
        npf_cert inter, leaf;
        if (npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, m->cert, (size_t)m->cert_len,
                                 &inter, &leaf, npf_node_time(n) / 1000) < 0
            || memcmp(leaf.dh_pub, n->id.dh_pub, 32) != 0) {
            npf_log("login: received certificate does not verify, ignored");
        } else if (n->cfg.callable && leaf.type == NPF_CERT_NODE) {
            memcpy(n->cert, m->cert, (size_t)m->cert_len);
            n->cert_len = (size_t)m->cert_len;
            npf_log("login: certificate issued (expires in %lld days)",
                    (long long)(leaf.not_after - npf_node_time(n) / 1000) / 86400);
            if (n->on_cert)
                n->on_cert(n, n->on_cert_arg);
        } else if (!n->cfg.callable && leaf.type == NPF_CERT_CLIENT) {
            node_accept_account_cert(n, m->cert, (size_t)m->cert_len);
        } else {
            npf_logw("login: certificate of the wrong type, ignored");
        }
    }
    if (m->account_cert_len)
        node_accept_account_cert(n, m->account_cert, (size_t)m->account_cert_len);
    server_list_in(n, j, m->server_list);
    n->online = 1;
    n->logins++;
    n->last_login_unix_ms = npf_unix_ms();
    n->unreachable_since = 0;
    n->sig_error[0] = 0;
    n->sig_refused = 0;
    n->src_backoff = 0;
    n->src_next = 0;
    npf_timer_stop(n->loop, &n->t_login);
    n->backoff_ms = 0;
    if (n->cur_server >= 0)
        n->servers[n->cur_server].fails = 0;
    npf_log("login: online at server %d (clock offset %lld ms)", n->server_id, (long long)n->clock_offset_ms);
    npf_timer_cancel(n->loop, n->t_ping);
    n->t_ping = npf_timer_add(n->loop, (n->ping_s > 0 ? n->ping_s : 25) * 1000, ping_cb, n);
    ends_flush(n);                      /* call ends from while signaling was down */
    idle_watch(n);
    node_home_login(n);                 /* the spare allocation, while the NAT is measured */
    node_nat_login(n);                  /* calls hooks.on_login at once, or after the first probe */
}

/* login's reply: welcome, or a refusal */
void node_on_login(npf_node *n, const m_env *e, const void *m)
{
    if (!e->reply_to[0])
        return;
    if (strcmp(e->status, "ok") == 0) {
        welcome(n, e->j, m);
        return;
    }
    npf_logw("login: rejected (%s)", e->error);
    if (strcmp(e->error, "upgrade_required") == 0) {
        node_upgrade_apply(n, e->j, e->data, 1, 1);
        snprintf(n->sig_error, sizeof n->sig_error, "this version is too old for the platform: upgrade to %s%s",
                 n->upgrade.min[0] ? n->upgrade.min : "the newest version", n->upgrade.url[0] ? " (see the download page)" : "");
    } else {
        snprintf(n->sig_error, sizeof n->sig_error, "server %d refused the login (%s)",
                 n->cur_server >= 0 ? n->servers[n->cur_server].id : -1, e->error);
    }
    n->sig_refused = 1;
    sig_refused(n, 3);
}

void node_on_server_list(npf_node *n, const m_env *e, const void *m)
{
    server_list_in(n, e->j, ((const m_server_list *)m)->blob);
}

/* the policy changed; the application hears of it too */
void node_on_upgrade(npf_node *n, const m_env *e, const void *m)
{
    (void)m;
    node_upgrade_apply(n, e->j, e->data, 0, 0);
    if (n->hooks.on_event)
        n->hooks.on_event(n, e->type, e->j, e->data, n->hook_arg);
}

void node_on_probe(npf_node *n, const m_env *e, const void *m)
{
    (void)e;
    if (node_apply_probe(n, m))
        probe_changed(n);
}

void node_on_keys(npf_node *n, const m_env *e, const void *m)
{
    apply_keys(n, m);
    node_on_probe(n, e, m);
}

/* the server closes this connection next */
void node_on_replaced(npf_node *n, const m_env *e, const void *m)
{
    (void)e, (void)m;
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
            fn(n, e->j, strcmp(e->status, "ok") == 0, n->pending[i].arg);
            return 1;
        }
    }
    return 0;
}

/* the first access point to finish the Noise handshake stays, the other one
 * is closed before it logs in (security.md 7.5) */
static void sig_ready(npf_sig *s, void *arg)
{
    npf_node *n = arg;
    if (s == n->race) {
        npf_log("signaling: server %d %s answered first", n->servers[n->race_server].id, "(second access point)");
        if (n->sig)
            npf_sig_close(n->sig);
        n->sig = s;
        n->cur_server = n->race_server;
        n->race = NULL;
    } else if (s != n->sig) {
        return;
    } else {
        race_drop(n);
    }
    if (n->cfg.enroll && !n->cfg.number)
        send_enroll(n);                     /* the first message instead of login (security.md 5.2) */
    else
        send_login(n);
}

static void sig_msg(npf_sig *s, const npf_json *j, void *arg)
{
    (void)s;
    node_msg(arg, j);
}

static void sig_down(npf_sig *s, const char *why, void *arg)
{
    npf_node *n = arg;
    int was_online = n->online && n->sig == s;
    if (s == n->race) {             /* the second access point failed: the first one goes on */
        npf_log("signaling: second access point server %d failed (%s)", n->servers[n->race_server].id, why);
        node_server_failed(&n->servers[n->race_server], 1);
        n->race = NULL;
        return;
    }
    if (n->sig != s)
        return;
    if (n->race && !n->online) {    /* the first failed while the second still tries */
        npf_log("signaling: server %d failed (%s), waiting for the second access point", n->cur_server >= 0 ?
                n->servers[n->cur_server].id : -1, why);
        if (n->cur_server >= 0)
            node_server_failed(&n->servers[n->cur_server], 1);
        n->sig = n->race;
        n->cur_server = n->race_server;
        n->race = NULL;
        return;
    }
    if (!n->online && npf_net_bypass_active()) {
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
        snprintf(n->sig_error, sizeof n->sig_error, "server %d: %s", n->cur_server >= 0 ?
                 n->servers[n->cur_server].id : -1, why ? why : "?");
        n->sig_refused = 0;
    }
    npf_log("signaling: disconnected (%s)", why);
    sig_gone(n, why, was_online);
}

void node_sig_connect(npf_node *n)
{
    static const npf_sig_cbs cbs = {sig_ready, sig_msg, sig_down, NULL};
    npf_server_entry *e;
    int i;
    if (n->sig)
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
    npf_log("signaling: connecting to server %d %s", e->id, e->ws[i]);
    /* around a VPN like the UDP sockets (connect_mode p2p: a tunnel that
     * stalls after the system slept took the signaling with it, 2026-10-20);
     * through it the next time when going around did not log in */
    n->sig = npf_sig_open(n->loop, e->ws[i], e->dh_pub, &n->id, "npf-ws-v1", &cbs, n, !n->sig_via_vpn);
    if (!n->sig) {
        node_server_failed(e, 1);
        npf_logw("signaling: cannot connect to %s", e->ws[i]);
        /* the URL cut to what sig_error holds (a 256-byte URL in 160) */
        snprintf(n->sig_error, sizeof n->sig_error, "cannot connect to %.*s",
                 (int)(sizeof n->sig_error - sizeof "cannot connect to "), e->ws[i]);
        n->sig_refused = 0;
        schedule_reconnect(n);
        return;
    }
    {   /* and a second access point at the same time: the server's next URL
         * (a domain and an IP), else another server of the same priority */
        int r = -1, u = 0;
        if (e->nws > 1) {
            r = n->cur_server;
            u = (i + 1) % e->nws;
        } else if ((r = node_server_pick(n, node_eff_prio(e), n->cur_server)) >= 0)
            u = n->servers[r].fails % n->servers[r].nws;
        if (r >= 0) {
            npf_server_entry *f = &n->servers[r];
            npf_log("signaling: and to server %d %s", f->id, f->ws[u]);
            n->race = npf_sig_open(n->loop, f->ws[u], f->dh_pub, &n->id, "npf-ws-v1", &cbs, n, !n->sig_via_vpn);
            n->race_server = r;
        }
    }
    npf_timer_cancel(n->loop, n->t_login);
    n->t_login = npf_timer_add(n->loop, SIG_LOGIN_MS, login_deadline, n);
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

/* nothing needs the connection: no call, no request waiting for its
 * reply, no call end to report, and the application agrees */
static int node_busy(npf_node *n)
{
    int i;
    if (n->calls)
        return 1;
    for (i = 0; i < NPF_PENDING_MAX; i++)
        if (n->pending[i].fn)
            return 1;
    for (i = 0; i < NPF_ENDS_MAX; i++)
        if (n->ends[i].state)
            return 1;
    return n->hooks.busy && n->hooks.busy(n, n->hook_arg);
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

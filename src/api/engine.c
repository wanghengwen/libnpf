/* libnpf: the engine behind npf.h - configuration, identity, the node and its
 * hooks, sessions and media streams by number. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "npf_int.h"
#include "npf/module.h"
#include "npf/tunnel.h"

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
static void lib_event(npf_t *n, const npf_event *ev, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
    ;
static void lib_event(npf_t *n, const npf_event *ev, const char *name, const char *fmt, ...)
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
        lib_event(n, &ev, "account", "{\"account_id\":\"%llu\"}", (unsigned long long)n->node.account_id);
    else
        lib_event(n, &ev, "account", "{\"account_id\":null}");
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

/* ---- account certificate (data_dir/account.cert) ---- */

void npf_save_account_cert(npf_t *n)
{
    char out[NPF_B64_LEN(1024) + 2];
    size_t l = npf_b64url_encode(n->node.account_cert, n->node.account_cert_len, out);
    out[l++] = '\n';
    if (npf_file_write(n->cert_path, out, l, 0600) < 0)
        npf_loge("cannot write %s", n->cert_path);
}

static void load_account_cert(npf_t *n)
{
    char *s;
    long len = npf_file_read(n->cert_path, &s);
    int r;
    if (len <= 0)
        return;
    s[strcspn(s, "\r\n")] = 0;
    r = npf_b64url_decode(s, strlen(s), n->node.account_cert, sizeof n->node.account_cert);
    n->node.account_cert_len = r > 0 ? (size_t)r : 0;
    free(s);
}

void npf_forget_account(npf_t *n)
{
    unlink(n->cert_path);
    n->node.account_cert_len = 0;
    n->node.account_id = 0;
    n->account_login[0] = 0;
    npf_ev_account(n);
}

static void account_got(npf_node *node, const npf_json *j, int ok, void *arg)
{
    npf_t *n = arg;
    int d;
    (void)node;
    if (!ok || !j || (d = npf_json_get(j, 0, "data")) < 0)
        return;
    if (npf_json_get_str(j, d, "email", n->account_login, sizeof n->account_login) <= 0
        && npf_json_get_str(j, d, "phone", n->account_login, sizeof n->account_login) <= 0)
        npf_json_get_str(j, d, "name", n->account_login, sizeof n->account_login);
}

void npf_account_info(npf_t *n)
{
    n->account_login[0] = 0;
    if (n->node.online && n->node.account_id && !n->cfg.hosted_exec)
        npf_node_request(&n->node, "account_get", "{}", account_got, n);
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

/* ---- identity ---- */

/* one key per device: "NPFD1." + b64url(vendor | product | number | seed | chk) (security.md 4.2) */
static int parse_cred(const char *s, uint64_t *number, uint8_t seed[32])
{
    uint8_t b[64], h[32];
    if (strncmp(s, "NPFD1.", 6) != 0 || npf_b64url_decode(s + 6, strlen(s + 6), b, sizeof b) != 52)
        return -1;
    npf_kdf(h, NULL, 0, b, 48);
    if (memcmp(h, b + 48, 4) != 0)
        return -1;
    *number = npf_rd64(b + 8);
    memcpy(seed, b + 16, 32);
    npf_wipe(b, sizeof b);
    return 0;
}

void npf_random_password(char out[10])
{
    static const char alpha[] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    int i, o = 0;
    for (i = 0; i < 8; i++) {
        uint8_t r;
        do {
            npf_random(&r, 1);
        } while (r >= 248);         /* 248 = 8 * 31: no modulo bias */
        if (i == 4)
            out[o++] = '-';
        out[o++] = alpha[r % 31];
    }
    out[o] = 0;
}

/* data_dir/node.json: {"number", "password"} of an enrolled identity */
static int load_node(npf_t *n)
{
    npf_jtok tok[32];
    char *s, num[24];
    long len = npf_file_read(n->node_path, &s);
    npf_json j;
    int ok;
    if (len < 0)
        return -1;
    ok = npf_json_parse(&j, s, (size_t)len, tok, 32) == 0 && npf_json_get_str(&j, 0, "number", num, sizeof num) > 0
         && npf_json_get_str(&j, 0, "password", n->default_pw, sizeof n->default_pw) > 0;
    free(s);
    if (!ok)
        return -1;
    n->number = strtoull(num, NULL, 10);
    return 0;
}

/* a MAC address the manufacturer burnt in (universally administered), not
 * one made up by the system: a private Wi-Fi address, a bridge, a VM */
static int mac_universal(const char *mac)
{
    return (strtol(mac, NULL, 16) & 0x02) == 0;
}

/* the physical network cards' addresses, sorted, "|"-joined (only the burnt-in
 * ones when there are any: made-up ones change); -1: none */
static int hw_macs(const npf_host_info *hi, char *out, size_t cap)
{
    const char *m[NPF_HOST_MAX_MACS], *t;
    size_t o = 0;
    int i, j, k = 0, uni = 0;
    for (i = 0; i < hi->nmacs; i++)
        uni |= mac_universal(hi->macs[i]);
    for (i = 0; i < hi->nmacs; i++)
        if (!uni || mac_universal(hi->macs[i]))
            m[k++] = hi->macs[i];
    if (k <= 0)
        return -1;
    for (i = 1; i < k; i++)
        for (j = i; j > 0 && strcmp(m[j - 1], m[j]) > 0; j--)
            t = m[j], m[j] = m[j - 1], m[j - 1] = t;
    out[0] = 0;
    for (i = 0; i < k && o < cap; i++)
        o += (size_t)snprintf(out + o, cap - o, "%s%s", i ? "|" : "", m[i]);
    return 0;
}

/* a serial number from the hardware when the vendor gives none: the lowest
 * burnt-in address of the physical network cards ("mac-001132aabbcc"), which survives
 * reinstalling the system; else a hash of the machine id ("mid-" 24 hex) */
static int auto_serial(const npf_host_info *hi, char *out, size_t cap)
{
    const char *low = NULL;
    int i, uni = 0;
    for (i = 0; i < hi->nmacs; i++)
        uni |= mac_universal(hi->macs[i]);
    for (i = 0; i < hi->nmacs; i++)
        if ((!uni || mac_universal(hi->macs[i])) && (!low || strcmp(hi->macs[i], low) < 0))
            low = hi->macs[i];
    if (low) {
        size_t o = (size_t)snprintf(out, cap, "mac-");
        for (; *low && o + 1 < cap; low++)
            if (*low != ':')
                out[o++] = *low;
        out[o] = 0;
        return 0;
    }
    if (hi->machine_id[0]) {
        uint8_t h[32];
        char hex[25];
        npf_kdf(h, NULL, 0, (const uint8_t *)hi->machine_id, strlen(hi->machine_id));
        for (i = 0; i < 12; i++)
            snprintf(hex + 2 * i, 3, "%02x", h[i]);
        snprintf(out, cap, "mid-%s", hex);
        return 0;
    }
    return -1;
}

/* the hardware fingerprint (security.md 5.2): items of the board that stay
 * for its life, each hashed with the model seed, so that a device whose
 * part was replaced still matches most of them (5.3). hw_info "a|b|c": the
 * vendor's items (v1, v2, ...); else the network cards, the eMMC, the board
 * and SoC serials found here; the machine id only when there is nothing else
 * (it changes when the system is reinstalled) */
static int hw_fingerprint(npf_t *n, const npf_host_info *hi, const uint8_t seed[32], char *err, size_t errcap)
{
    npf_hw_item it[8];
    npf_enroll_req *e = &n->enroll;
    const char *cfg = npf_conf_get(&n->conf, "hw_info", NULL);
    uint8_t buf[16 + 8 * (1 + 16 + 16)], h[32];
    size_t o;
    int k = 0, i, j;
    if (cfg) {
        const char *p = cfg;
        while (*p && k < 8) {
            size_t l = strcspn(p, "|");
            snprintf(it[k].kind, sizeof it[k].kind, "v%d", k + 1);
            snprintf(it[k].value, sizeof it[k].value, "%.*s", (int)l, p);
            if (it[k].value[0])
                k++;
            p += l + (p[l] == '|');
        }
    } else {
        if (hw_macs(hi, it[0].value, sizeof it[0].value) == 0)
            snprintf(it[k++].kind, sizeof it[0].kind, "mac");
        k += npf_hw_items(it + k, NPF_HW_MAX);
        if (k == 0 && hi->machine_id[0]) {
            snprintf(it[0].kind, sizeof it[0].kind, "mid");
            snprintf(it[0].value, sizeof it[0].value, "%s", hi->machine_id);
            k = 1;
        }
    }
    if (k == 0) {
        snprintf(err, errcap, "config: no hardware to tell this device by: give 'hw_info'");
        return -1;
    }
    for (i = 1; i < k; i++)                                 /* sorted by kind */
        for (j = i; j > 0 && strcmp(it[j - 1].kind, it[j].kind) > 0; j--) {
            npf_hw_item t = it[j];
            it[j] = it[j - 1];
            it[j - 1] = t;
        }
    memcpy(buf, "npf-hw-v2", 9);
    o = 9;
    for (i = 0; i < k; i++) {
        char v[200];
        size_t kl = strlen(it[i].kind);
        int vl = snprintf(v, sizeof v, "%s%c%s", it[i].kind, 0, it[i].value);
        npf_kdf2(h, seed, 32, "npf hwfp v2", 11, v, (size_t)vl);
        snprintf(e->hw_kind[i], sizeof e->hw_kind[i], "%.*s", (int)sizeof e->hw_kind[i] - 1, it[i].kind);
        memcpy(e->hw_hash[i], h, 16);
        buf[o++] = (uint8_t)kl;
        memcpy(buf + o, it[i].kind, kl);
        o += kl;
        memcpy(buf + o, h, 16);
        o += 16;
    }
    e->nhw = k;
    npf_kdf(e->hw_fp, NULL, 0, buf, o);
    npf_wipe(it, sizeof it);
    return 0;
}

/* one key per model (security.md 4.1, 5.2): the credential (the chain vendor
 * certificate | model certificate, then the model's seed), the serial number
 * (configured, or made from the hardware), the hardware fingerprint
 * BLAKE2b(key = model_seed, "npf hwfp v1" | hw_info) */
static int model_setup(npf_t *n, char *err, size_t errcap)
{
    const char *s = npf_conf_get(&n->conf, "model_cred", NULL), *sf;
    uint8_t b[1200], h[32], seed[32];
    npf_identity mid;
    npf_cert vc, mc;
    npf_host_info hi;
    int len = 0, n1 = -1, n2 = -1;
    if (!s)
        return 0;
    if (strncmp(s, "NPFV2.", 6) == 0 && (len = npf_b64url_decode(s + 6, strlen(s + 6), b, sizeof b)) > 36) {
        n1 = npf_cert_parse(b, (size_t)len - 36, &vc);
        if (n1 > 0)
            n2 = npf_cert_parse(b + n1, (size_t)len - 36 - (size_t)n1, &mc);
    }
    if (n1 <= 0 || n2 <= 0 || n1 + n2 + 36 != len || vc.type != NPF_CERT_VENDOR || mc.type != NPF_CERT_MODEL
        || (npf_kdf(h, NULL, 0, b, (size_t)len - 4), memcmp(h, b + len - 4, 4) != 0)
        || (size_t)(n1 + n2) > sizeof n->enroll.model_chain) {
        snprintf(err, errcap, "config: bad 'model_cred' (an NPFV2 model credential from npf-vendor model)");
        return -1;
    }
    n->enroll.model_chain_len = (size_t)(n1 + n2);
    memcpy(n->enroll.model_chain, b, n->enroll.model_chain_len);
    memcpy(seed, b + len - 36, 32);
    npf_identity_from_seed(&mid, seed);
    memcpy(n->enroll.model_sk, mid.sign_sk, 64);
    npf_identity_wipe(&mid);
    npf_host_info_get(&hi);
    if ((sf = npf_conf_get(&n->conf, "serial", NULL)) != NULL) {
        snprintf(n->enroll.serial, sizeof n->enroll.serial, "%s", sf);
    } else if ((sf = npf_conf_get(&n->conf, "serial_file", NULL)) != NULL) {
        char *t;
        if (npf_file_read(sf, &t) < 0) {
            snprintf(err, errcap, "config: cannot read serial_file %s", sf);
            return -1;
        }
        t[strcspn(t, "\r\n")] = 0;
        snprintf(n->enroll.serial, sizeof n->enroll.serial, "%s", t);
        free(t);
    } else if (auto_serial(&hi, n->enroll.serial, sizeof n->enroll.serial) < 0) {
        snprintf(err, errcap, "config: 'model_cred' needs the device's serial number ('serial' or 'serial_file'): "
                              "this host has neither a network card address nor a machine id");
        return -1;
    }
    if (!n->enroll.serial[0]) {
        snprintf(err, errcap, "config: the serial number is empty");
        return -1;
    }
    if (hw_fingerprint(n, &hi, seed, err, errcap) < 0)
        return -1;
    npf_wipe(seed, sizeof seed);
    npf_wipe(b, sizeof b);
    n->model_dev = 1;
    return 0;
}

/* a number for this identity (one key per model, or node_enroll): node.json,
 * the callee state, and callable from now on; pw_out gets the default password */
int npf_become_node(npf_t *n, uint64_t number, char *pw_out)
{
    char pw[10], out[128];
    int len;
    npf_random_password(pw);
    len = snprintf(out, sizeof out, "{\"number\":\"%llu\",\"password\":\"%s\"}\n", (unsigned long long)number, pw);
    if (npf_file_write(n->node_path, out, (size_t)len, 0600) < 0) {
        npf_loge("cannot write %s: the number is lost at the next start", n->node_path);
        return -1;
    }
    n->number = number;
    n->has_number = 1;
    snprintf(n->default_pw, sizeof n->default_pw, "%s", pw);
    if (!n->callee && !(n->callee = calloc(1, sizeof *n->callee))) {
        npf_loge("no memory for the callee state");
        return -1;
    }
    npf_callee_init(n->callee, n->state_path, number, n->node.id.seed, pw);
    /* the published resources make the callee's policy now; without it an
     * exit node enrolled at run time refused every internet target until a
     * restart (2026-10-13) */
    npf_pub_apply(n);
    memcpy(n->callee->cert, n->node.cert, n->node.cert_len);
    n->callee->cert_len = n->node.cert_len;
    npf_callee_save(n->callee);
    n->callee->hosted_trust = atoi(npf_conf_get(&n->conf, "hosted_trust", "1"));
    npf_callee_attach(n->callee, &n->node);
    if (pw_out)
        strcpy(pw_out, pw);
    {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_ENROLLED;
        ev.number = number;
        lib_event(n, &ev, "enrolled", "{\"number\":\"%llu\"}", (unsigned long long)number);
    }
    return 0;
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
    lib_event(n, &ev, "enroll_failed", "{\"error\":\"%s\",\"reason\":\"%s\",\"retry_in\":%d}", error, reason,
              retry_s);
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
        lib_event(n, &ev, "online", "{\"server\":%d,\"account_id\":%s%llu%s}", node->server_id,
                  node->account_id ? "\"" : "", (unsigned long long)node->account_id, node->account_id ? "\"" : "");
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
        lib_event(n, &ev, "network", "{\"why\":\"%s\"}", why);
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
    lib_event(n, &ev, "offline", "{\"why\":\"%s\"}", w);
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

/* a public connection's record for the platform (conn_report), queued */

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

void npf_start_peers(npf_t *n)
{
    if (!n->started)
        return;                             /* the run starts them */
    npf_peers_start(n->peers);
    if (n->node.online)
        npf_peers_on_login(n->peers);
}

/* ---- configuration ---- */

static void dir_of(const char *path, char *out, size_t cap)
{
    char *slash;
    snprintf(out, cap, "%s", path);
    slash = strrchr(out, '/');
#ifdef _WIN32
    if (!slash || strrchr(out, '\\') > slash)
        slash = strrchr(out, '\\');
#endif
    if (slash)
        *slash = 0;
    else
        snprintf(out, cap, ".");
}

/* the configurations, and the paths made from them */
static void free_confs(npf_t *n)
{
    npf_conf_free(&n->ro);
    npf_conf_free(&n->ov);
    npf_conf_free(&n->conf);
    free(n->conf_dir);
    free(n->data_dir);
    free(n->cert_path);
    free(n->node_path);
    free(n->state_path);
    n->conf_dir = n->data_dir = n->cert_path = n->node_path = n->state_path = NULL;
}

/* *p = the formatted path, on the heap (an instance keeps a few: not 1 KB each) */
static int path_set(char **p, const char *fmt, ...)
{
    va_list ap;
    int len;
    char *s;
    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len < 0 || !(s = malloc((size_t)len + 1)))
        return -1;
    va_start(ap, fmt);
    vsnprintf(s, (size_t)len + 1, fmt, ap);
    va_end(ap);
    free(*p);
    *p = s;
    return 0;
}

/* "key = value" lines into c (the same rules as a file) */
static void conf_text(npf_conf *c, const char *text)
{
    char line[1024];
    const char *p = text, *e;
    while (p && *p) {
        size_t l;
        char *eq, *k, *v, *h;
        e = strchr(p, '\n');
        l = e ? (size_t)(e - p) : strlen(p);
        snprintf(line, sizeof line, "%.*s", (int)(l < sizeof line ? l : sizeof line - 1), p);
        p = e ? e + 1 : NULL;
        if ((h = strchr(line, '#')) != NULL)
            *h = 0;
        if (!(eq = strchr(line, '=')))
            continue;
        *eq = 0;
        for (k = line; *k == ' ' || *k == '\t'; k++)
            ;
        for (h = eq - 1; h >= k && (*h == ' ' || *h == '\t'); h--)
            *h = 0;
        for (v = eq + 1; *v == ' ' || *v == '\t'; v++)
            ;
        for (h = v + strlen(v) - 1; h >= v && (*h == ' ' || *h == '\t' || *h == '\r'); h--)
            *h = 0;
        if (*k)
            npf_conf_set(c, k, v);
    }
}

/* the configuration in effect: npf.conf, then the overrides, then local.json's settings */
static void conf_merge(npf_conf *dst, const npf_conf *src)
{
    int i;
    for (i = 0; i < src->n; i++)
        npf_conf_set(dst, src->key[i], src->val[i]);
}

/* the peers of local.json saved to be connected at every start, and their
 * saved forwards (a record that does not make one is left out, with a
 * warning) */
static void add_saved_peers(npf_t *n)
{
    int i, k;
    for (i = 0; i < n->lc.ndev; i++) {
        npf_ldev *d = &n->lc.dev[i];
        npf_peer_new pn;
        npf_peer *p;
        char host[300], e[300];
        uint8_t psk[32];
        int code;
        if (!d->save || npf_peers_find(n->peers, d->target))
            continue;
        memset(&pn, 0, sizeof pn);
        if (!(pn.number = npf_number_parse(d->target))) {
            const char *colon = strrchr(d->target, ':');
            char path[1600];
            if (!colon)
                continue;
            if (d->target[0] == '[')
                snprintf(host, sizeof host, "%.*s", (int)(colon - d->target - 2), d->target + 1);
            else
                snprintf(host, sizeof host, "%.*s", (int)(colon - d->target), d->target);
            pn.host = host;
            pn.port = (uint16_t)atoi(colon + 1);
            if (d->psk_file[0]) {
                if (npf_path_is_abs(d->psk_file))
                    snprintf(path, sizeof path, "%s", d->psk_file);
                else
                    snprintf(path, sizeof path, "%s/%s", n->data_dir, d->psk_file);
            }
            if (npf_direct_psk(d->psk[0] ? d->psk : NULL, d->psk_file[0] ? path : NULL, psk) < 0) {
                npf_logw("local.json: %s: no key to connect with: left out", d->target);
                continue;
            }
            pn.psk = psk;
        }
        pn.connect = d->on_demand ? NPF_CONNECT_ON_DEMAND : NPF_CONNECT_KEEP;
        pn.idle_ms = d->idle_ms;
        p = npf_peers_create(n->peers, &pn, e, sizeof e, &code);
        npf_wipe(psk, sizeof psk);
        if (!p) {
            npf_logw("local.json: %s: %s: left out", d->target, e);
            continue;
        }
        npf_peer_set_tag(p, PEER_SAVED);
        for (k = 0; k < d->nfwd; k++) {
            const npf_lfwd *lf = &d->fwd[k];
            int r;
            if (lf->opt == 'L' || lf->opt == 'D' || lf->opt == 'R') {
                npf_fwd_new fn;
                memset(&fn, 0, sizeof fn);
                fn.opt = lf->opt;
                fn.udp = lf->udp;
                fn.bind = lf->bind[0] ? lf->bind : NULL;
                fn.port = lf->port;
                fn.host = lf->host;
                fn.hostport = lf->hostport;
                r = npf_peer_forward_add_parts(p, &fn, 1, 0, e, sizeof e);
            } else {
                r = npf_peer_forward_add_kind(p, lf->opt, lf->spec, 1, e, sizeof e);
            }
            if (r < 0)
                npf_logw("local.json: %s: a forward left out: %s", d->target, e);
        }
    }
}

/* ---- lifecycle ---- */

int npf_app_name_valid(const char *s)
{
    size_t i, l = strlen(s);
    if (l < 1 || l > 32)
        return 0;
    for (i = 0; i < l; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == '_' || s[i] == '-'))
            return 0;
    return 1;
}

int npf_app_ver_valid(const char *s)
{
    size_t i, l = strlen(s);
    if (l < 1 || l > 32)
        return 0;
    for (i = 0; i < l; i++)
        if ((unsigned char)s[i] <= 0x20 || (unsigned char)s[i] >= 0x7f)
            return 0;
    return 1;
}

/* the defaults d (sizeof d bytes) into the application's s of size bytes:
 * what both know, zeros past this build's structure */
void npf_init_sized(void *s, size_t size, const void *d, size_t dsize)
{
    if (!s || size < sizeof(size_t))
        return;
    memset(s, 0, size);
    memcpy(s, d, size < dsize ? size : dsize);
    memcpy(s, &size, sizeof size);          /* the first field: size */
}

void npf_options_init_size(npf_options *o, size_t size)
{
    npf_options d;
    memset(&d, 0, sizeof d);
    d.log_level = -1;
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_callbacks_init_size(npf_callbacks *cb, size_t size)
{
    npf_callbacks d;
    memset(&d, 0, sizeof d);
    npf_init_sized(cb, size, &d, sizeof d);
}

int npf_api_version(void)
{
    return NPF_API_VERSION;
}

static const npf_peers_cbs k_peers_cbs = {peer_up,      peer_done,     peer_fwd,  peer_conn,       peer_refused,
                                          peer_opened,  peer_changed,  peer_fwd_gone, peer_gone, peer_fwd_refused};

static int create(const npf_options *o, npf_t **out, char *err, size_t errcap);

/* the structures as this build knows them: what the application's build has,
 * the defaults for the rest (fields are only ever added at the end) */
int npf_create(const npf_options *uo, npf_t **out, char *err, size_t errcap)
{
    npf_options o;
    npf_callbacks cb;
    if (!out || !err || !errcap)
        return NPF_EINVAL;
    *out = NULL;
    if (!uo || uo->size < offsetof(npf_options, cb) + sizeof uo->cb) {
        snprintf(err, errcap, "options not initialised (npf_options_init)");
        return NPF_EINVAL;
    }
    npf_options_init(&o);
    memcpy(&o, uo, uo->size < sizeof o ? uo->size : sizeof o);
    o.size = sizeof o;
    npf_callbacks_init(&cb);
    if (o.cb) {
        if (o.cb->size < offsetof(npf_callbacks, media_closed) + sizeof o.cb->media_closed) {
            snprintf(err, errcap, "callbacks not initialised (npf_callbacks_init)");
            return NPF_EINVAL;
        }
        memcpy(&cb, o.cb, o.cb->size < sizeof cb ? o.cb->size : sizeof cb);
        cb.size = sizeof cb;
    }
    o.cb = &cb;
    return create(&o, out, err, errcap);
}

static int create(const npf_options *o, npf_t **out, char *err, size_t errcap)
{
    npf_t *n;
    char conf_path[1100], seed_path[1100];
    const char *cred;
    uint8_t seed[32];
    npf_node_hooks hooks = {on_login, on_call_state, on_paired, on_event, on_enrolled, on_app_data, on_media_open,
                            on_media_frame, on_media_closed, sig_busy, on_resources, on_net_change,
                            on_enroll_failed, on_offline};
    int have_conf, fail_rc = NPF_EFAIL;
    npf_log_ctx *prev_log;
    *out = NULL;
    if (!o || (!o->setup && !o->conf_dir && !o->conf_file)) {
        snprintf(err, errcap, "conf_dir (or npf_options.setup) is needed");
        return NPF_EINVAL;
    }
    if (o->setup && (o->conf_dir || o->conf_file || !o->data_dir)) {
        snprintf(err, errcap, "npf_options.setup: no conf_dir or conf_file, and a data_dir");
        return NPF_EINVAL;
    }
    if (o->flags & ~(NPF_OPT_NO_SAVED_SETTINGS | NPF_OPT_NO_SAVED_OBJECTS)) {
        snprintf(err, errcap, "npf_options.flags: unknown flags");
        return NPF_EINVAL;
    }
    if (!(n = calloc(1, sizeof *n))) {
        snprintf(err, errcap, "no memory");
        return NPF_ENOMEM;
    }
    n->role = o->role;
    n->cb = *o->cb;
    n->opt_flags = o->flags;
    n->from_setup = o->setup != NULL;
    npf_mods_take(n);                   /* the modules registered by now */
    if (!npf_app_name_valid(o->app_name ? o->app_name : "libnpf")
        || !npf_app_ver_valid(o->app_ver ? o->app_ver : npf_version())) {
        snprintf(err, errcap, "app_name: 1..32 of a-z 0-9 . _ -; app_ver: up to 32 printable characters");
        free(n->logctx.ring);
        free(n);
        return NPF_EINVAL;
    }
    if (npf_api_init(n) < 0) {
        snprintf(err, errcap, "no memory for API synchronization");
        free(n->logctx.ring);
        free(n);
        return NPF_ENOMEM;
    }
    snprintf(n->app_name, sizeof n->app_name, "%s", o->app_name ? o->app_name : "libnpf");
    snprintf(n->app_ver, sizeof n->app_ver, "%s", o->app_ver ? o->app_ver : npf_version());
    /* the instance's own log from here on: its level starts as the process's */
    n->logctx.hook = o->cb->log;
    n->logctx.user = o->cb->user;
    /* recent lines for npf_log_json, unless the application asked for none */
    if (!o->no_log_ring && !(n->logctx.ring = malloc(NPF_LOG_RING))) {
        snprintf(err, errcap, "no memory");
        free(n->logctx.ring);
        free(n);
        return NPF_ENOMEM;
    }
    n->logctx.level = npf_log_get_level();
    prev_log = npf_log_ctx_swap(&n->logctx);
    /* the read-only configuration: npf.conf, or the application's fields */
    if (o->setup) {
        snprintf(conf_path, sizeof conf_path, "%s/(npf_setup)", o->data_dir);
        npf_mkdir_p(o->data_dir);
        if (npf_setup_conf(o->setup, o->role, o->data_dir, &n->ro, err, errcap) < 0)
            goto fail_inval;
        snprintf(n->ro.path, sizeof n->ro.path, "%.1000s", conf_path);
        have_conf = 1;
    } else {
        if (o->conf_file && npf_path_is_abs(o->conf_file))
            snprintf(conf_path, sizeof conf_path, "%s", o->conf_file);
        else
            snprintf(conf_path, sizeof conf_path, "%s/%s", o->conf_dir ? o->conf_dir : ".",
                     o->conf_file ? o->conf_file : "npf.conf");
        have_conf = npf_conf_load(&n->ro, conf_path) == 0;
    }
    if (!have_conf && n->role != NPF_ROLE_DIRECT) {
        snprintf(err, errcap, "cannot read %s", conf_path);
        goto fail;
    }
    if (!have_conf && (size_t)snprintf(n->ro.path, sizeof n->ro.path, "%s", conf_path) >= sizeof n->ro.path) {
        snprintf(err, errcap, "path too long");
        goto fail_inval;
    }
    if (n->ro.bad[0]) {
        snprintf(err, errcap, "%s: the value of '%s' is too long (at most %d characters)", conf_path, n->ro.bad,
                 NPF_CONF_VAL_MAX - 1);
        goto fail_inval;
    }
    {
        char d[1100];
        dir_of(n->ro.path, d, sizeof d);
        if (path_set(&n->conf_dir, "%s", d) < 0) {
            snprintf(err, errcap, "no memory");
            goto fail;
        }
    }
    if (o->overrides)
        conf_text(&n->ov, o->overrides);
    if (npf_conf_get(&n->ro, "node", NULL) || npf_conf_get(&n->ov, "node", NULL)) {
        snprintf(err, errcap, "config: \"node =\" lines are gone: the application makes its peers (npf_peer_create)");
        goto fail_inval;
    }
    if (o->setup) {                         /* one source for each: a field, or the overrides */
        const char *k = npf_setup_key_taken(&n->ov);
        if (k) {
            snprintf(err, errcap, "overrides: '%s' is a field of npf_setup", k);
            goto fail_inval;
        }
    }
    /* the writable directory: the option, the configuration's "dir", conf_dir */
    if (path_set(&n->data_dir, "%s", o->data_dir                        ? o->data_dir
                                     : npf_conf_get(&n->ov, "dir", NULL) ? npf_conf_get(&n->ov, "dir", NULL)
                                     : npf_conf_get(&n->ro, "dir", NULL) ? npf_conf_get(&n->ro, "dir", NULL)
                                                                         : n->conf_dir) < 0) {
        snprintf(err, errcap, "no memory");
        goto fail;
    }
    npf_mkdir_p(n->data_dir);
    if (npf_local_load(&n->lc, n->data_dir, err, errcap) < 0)
        goto fail;
    n->local_path = n->lc.path;
    if (npf_conf_copy(&n->conf, &n->ro) < 0) {
        snprintf(err, errcap, "no memory");
        goto fail;
    }
    conf_merge(&n->conf, &n->ov);
    if (!(n->opt_flags & NPF_OPT_NO_SAVED_SETTINGS)) {   /* local.json: its settings over the others */
        int i;
        for (i = 0; i < n->lc.settings.n; i++)
            npf_conf_set(&n->conf, n->lc.settings.key[i], n->lc.settings.val[i]);
    }
    if (o->log_level >= 0)
        npf_log_set_level(o->log_level);
    else
        npf_conf_apply_log_level(&n->conf);
    if (path_set(&n->cert_path, "%s/account.cert", n->data_dir) < 0
        || path_set(&n->node_path, "%s/node.json", n->data_dir) < 0
        || (npf_conf_get(&n->conf, "state", NULL) ? path_set(&n->state_path, "%s", npf_conf_get(&n->conf, "state", NULL))
                                                  : path_set(&n->state_path, "%s/state.json", n->data_dir)) < 0) {
        snprintf(err, errcap, "no memory");
        goto fail;
    }
    if (!npf_conf_get(&n->conf, "serverlist_saved", NULL)) {
        /* the lists the platform sends are kept with what changes ("off": not kept) */
        char p[1200];
        snprintf(p, sizeof p, "%s/serverlist-saved.bin", n->data_dir);
        if (npf_conf_set(&n->conf, "serverlist_saved", p) < 0) {
            snprintf(err, errcap, "no memory");
            goto fail;
        }
    }

    /* the identity: a device credential (read-only), or the key in data_dir/identity */
    cred = npf_conf_get(&n->conf, "cred", NULL);
    if (cred) {
        if (parse_cred(cred, &n->number, seed) < 0) {
            snprintf(err, errcap, "config: bad 'cred' (NPFD1 device credential)");
            goto fail;
        }
        n->cred = 1;
        n->has_number = 1;
        snprintf(n->default_pw, sizeof n->default_pw, "%s", npf_conf_get(&n->conf, "password", ""));
        if (!n->default_pw[0]) {
            snprintf(err, errcap, "config: 'password' (the device's default password) goes with 'cred'");
            goto fail;
        }
    } else {
        snprintf(seed_path, sizeof seed_path, "%s/identity", n->data_dir);
        if (npf_seed_file(seed_path, seed, 1) < 0) {
            snprintf(err, errcap, "cannot read or make %s", seed_path);
            goto fail;
        }
        n->has_number = load_node(n) == 0;
        if (model_setup(n, err, errcap) < 0)
            goto fail;
    }
    npf_identity_from_seed(&n->id, seed);
    if (n->has_number) {
        if (!(n->callee = calloc(1, sizeof *n->callee))) {
            npf_wipe(seed, 32);
            snprintf(err, errcap, "no memory");
            goto fail;
        }
        npf_callee_init(n->callee, n->state_path, n->number, seed, n->default_pw);
    }
    npf_wipe(seed, 32);

    /* the node */
    if (n->role == NPF_ROLE_DIRECT) {
        memset(&n->cfg, 0, sizeof n->cfg);
        n->cfg.offline = 1;
        n->cfg.udp_port = atoi(npf_conf_get(&n->conf, "udp_port", "0"));
    } else if (npf_node_cfg_from_conf(&n->cfg, &n->conf) < 0) {
        snprintf(err, errcap, "config: root keys and a server list are needed");
        goto fail;
    }
    n->cfg.callable = n->role == NPF_ROLE_NODE && n->has_number;
    n->cfg.number = n->cfg.callable ? n->number : 0;
    if (n->role == NPF_ROLE_NODE && n->model_dev && !n->has_number)
        n->cfg.enroll = &n->enroll;
    if (n->role != NPF_ROLE_NODE || n->cfg.hosted_service || n->cfg.hosted_exec)
        n->cfg.no_portmap = 1;
    n->cfg.model = npf_conf_get(&n->conf, "model", n->cred || n->model_dev ? "NAS" : "console");
    n->cfg.fw = npf_version();
    n->cfg.app_name = n->app_name;
    n->cfg.app_ver = n->app_ver;
    n->loop = o->runtime ? npf_runtime_child(o->runtime, &n->rt_slot) : npf_loop_new();
    if (n->loop && o->runtime) {
        n->rt = o->runtime;
        npf_loop_set_logctx(n->loop, &n->logctx);
    }
    if (!n->loop || npf_node_init(&n->node, n->loop, &n->cfg, &n->id, &hooks, n) < 0) {
        snprintf(err, errcap, "cannot start the node (UDP socket or server list)");
        goto fail;
    }
    n->node.on_account_lost = on_account_lost;
    n->node.on_udp_ready = on_udp_ready;
    n->node.on_account_cert = on_account_cert;
    n->node.on_account_cert_arg = n;
    if (!n->cfg.offline && !n->cred)
        load_account_cert(n);
    /* target policy of the sessions accepted here: the published resources
     * (resources.h, security.md D22) */
    if (npf_pub_load(n, err, errcap) < 0)
        goto fail;
    if (n->cfg.callable) {
        n->callee->hosted_trust = atoi(npf_conf_get(&n->conf, "hosted_trust", "1"));
        npf_callee_attach(n->callee, &n->node);
    }
    /* peers: the application's, and those it saved in local.json */
    if (!(n->peers = npf_peers_new(&n->node, &n->lc, &k_peers_cbs, n))) {
        snprintf(err, errcap, "no memory");
        goto fail;
    }
    if (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS)
        npf_peers_no_cache(n->peers);
    {   /* peer_idle = S: the peers on demand without an idle time of their own end S s after their last connection */
        int idle = atoi(npf_conf_get(&n->conf, "peer_idle", "0"));
        npf_peers_set_idle(n->peers, (idle > 0 ? idle : 300) * 1000);
    }
    /* the modules, before the peers come: their forwards' callbacks go to them */
    if (npf_mods_create(n, err, errcap) < 0)
        goto fail;
    /* a long-running role brings back what it saved (a client's one-off tasks do not) */
    if (n->role != NPF_ROLE_CLIENT && !(n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS))
        add_saved_peers(n);
    /* the file as read and the overrides were for the start: the merged conf stays */
    npf_conf_free(&n->ro);
    npf_conf_free(&n->ov);
    {   /* direct connections (no platform): "direct = [ADDR:]PORT" with its key */
        const char *direct = npf_conf_get(&n->conf, "direct", NULL);
        if (direct && *direct && n->role != NPF_ROLE_CLIENT) {
            uint8_t psk[32];
            if (npf_direct_psk(npf_conf_get(&n->conf, "direct_psk", NULL), npf_conf_get(&n->conf, "direct_psk_file", NULL),
                               psk) < 0) {
                snprintf(err, errcap, "direct needs direct_psk_file (or direct_psk)");
                goto fail;
            }
            n->dl = npf_direct_listen(&n->node, direct, psk, n->cfg.callable ? NULL : &n->policy);
            npf_wipe(psk, 32);
            if (!n->dl) {
                snprintf(err, errcap, "cannot listen for direct connections on %s", direct);
                goto fail;
            }
        }
    }
    npf_log_ctx_swap(prev_log);
    *out = n;
    return NPF_OK;
fail_inval:
    fail_rc = NPF_EINVAL;
fail:
    npf_mods_end(n, 2);                     /* the modules made: what they keep of the peers first */
    if (n->peers)
        npf_peers_free(n->peers);
    npf_mods_destroy(n);
    npf_pub_free(n);
    npf_local_free(&n->lc);
    free_confs(n);
    free(n->callee);
    if (n->loop) {
        npf_node_stop(&n->node);
        npf_loop_free(n->loop);
    }
    if (n->rt)
        npf_runtime_leave(n->rt, n->rt_slot);
    npf_identity_wipe(&n->id);
    npf_log_ctx_swap(prev_log);
    npf_api_fini(n);
    free(n->logctx.ring);
    free(n);
    return fail_rc;
}

/* the start of the run, on the loop's thread */
void npf_engine_begin(npf_t *n)
{
    n->started_unix = npf_unix_ms() / 1000;
    npf_events_start(n);
    if (n->role == NPF_ROLE_NODE)
        npf_log("npf %s: %s %llu, %d peer(s), UDP port %u", npf_version(), n->cfg.callable ? "node" : "client",
                n->cfg.callable ? (unsigned long long)n->number : 0ULL, npf_peers_count(n->peers), n->node.udp_port);
    npf_node_start(&n->node);
    npf_peers_start(n->peers);
    npf_mods_begin(n);
}

/* The end of the run in steps, on the loop's thread: each returns how long
 * the loop goes on (its sockets and timers) before the next, or -1 at the
 * end. A shared runtime's thread runs other instances meanwhile. */
int npf_engine_end_step(npf_t *n)
{
    int ms;
    switch (n->end_stage++) {
    case 0:                         /* the modules' work with the sessions still up (a hosted client's reports) */
        if ((ms = npf_mods_end(n, 0)) > 0)
            return ms;
        n->end_stage = 2;
        return npf_engine_end_step(n);
    case 1:
        return npf_mods_end(n, 1);
    case 2:
        npf_mods_end(n, 2);
        npf_api_lock(n);
        n->ended = 1;                           /* calls from now on: NPF_ESTATE */
        npf_api_unlock(n);
        /* the end: peers' sessions, then the accepted ones (callers are told at once) */
        npf_peers_free(n->peers);
        n->peers = NULL;
        npf_node_end_calls(&n->node, "closed");
        return 50;
    default:
        npf_direct_close(n->dl);
        n->dl = NULL;
        npf_node_stop(&n->node);
        n->torn_down = 1;
        if (n->cb.notify) {
            npf_events_stop(n);             /* NPF_EV_STOPPED, the last */
        } else if (n->cb.event) {
            n->cb.event(n->cb.user, "stopped", "{}");
        }
        n->started_unix = 0;
        return -1;
    }
}

/* the run on the loop's thread (npf_run, or npf_start's thread) */
int npf_engine_run(npf_t *n)
{
    int ms;
    npf_engine_begin(n);
    npf_loop_run(n->loop);
    while ((ms = npf_engine_end_step(n)) >= 0)
        npf_loop_once(n->loop, ms);
    return 0;
}

npf_loop *npf_engine_loop(npf_t *n)
{
    return n->loop;
}

void npf_engine_free(npf_t *n)
{
    npf_log_ctx *prev;
    if (!n)
        return;
    prev = npf_log_ctx_swap(&n->logctx);
    if (!n->torn_down) {                    /* never run */
        npf_mods_end(n, 2);                 /* what the modules keep of the peers goes first */
        npf_peers_free(n->peers);
        npf_direct_close(n->dl);
        npf_node_stop(&n->node);
    }
    npf_mods_destroy(n);
    npf_events_clear(n);                    /* before its loop: a timer of it */
    npf_loop_free(n->loop);
    if (n->rt)
        npf_runtime_leave(n->rt, n->rt_slot);
    npf_pub_free(n);
    npf_local_free(&n->lc);
    free_confs(n);
    free(n->callee);
    free(n->sess);
    npf_identity_wipe(&n->id);
    npf_log_ctx_swap(prev == &n->logctx ? NULL : prev);
    npf_api_fini(n);
    free(n->logctx.ring);
    free(n);
}

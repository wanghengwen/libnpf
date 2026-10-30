/* Calls: the end-to-end handshake over signaling. The caller's call and
 * what the callee answers (PAKE with the password, IK to a pinned key, the
 * account's grant), the callee gate, the keys that come out of it
 * (signaling.md "呼叫与端到端连接", security.md 8, 9). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

#define MAX_CALLS_DEFAULT  32        /* concurrent sessions a callee accepts (signaling.md "incoming": busy; R46) */
/* callee: what a grant admits; a hosted grant: its targets only */
int call_set_targets(npf_call *c, const npf_grant *g)
{
    uint8_t *t = NULL;
    c->grant_issued = g->issued;
    if (g->kind != NPF_GRANT_HOSTED)
        return 0;
    if (g->tlen && !(t = malloc(g->tlen)))
        return -1;
    if (g->tlen)
        memcpy(t, g->targets, g->tlen);
    free(c->targets);
    c->targets = t;
    c->tlen = g->tlen;
    c->hosted_grant = 1;
    return 0;
}

static void prologue(const npf_call *c, uint8_t *out, size_t *len)
{
    const char *pre = c->auth == AUTH_PAKE ? "npf-pair-v1" : "npf-conn-v1";
    size_t l = strlen(pre);
    memcpy(out, pre, l);
    memcpy(out + l, c->call_id, 16);
    npf_le64(out + l + 16, c->number);
    *len = l + 24;
}

static void sid_of(const npf_call *c, uint8_t sid[24])
{
    memcpy(sid, c->call_id, 16);
    npf_le64(sid + 16, c->number);
}

static int call_finish_handshake(npf_call *c)
{
    const uint8_t *rs = npf_noise_remote_static(&c->hs->noise);
    if (!rs || npf_noise_split(&c->hs->noise, NULL, NULL, c->hs->k12, c->hs->k12 + 32, NULL) < 0)
        return -1;
    memcpy(c->peer_pub, rs, 32);
    if (c->hs->password[0])
        npf_wipe(c->hs->password, sizeof c->hs->password);
    return call_start_transport(c);
}

/* ---- caller ---- */

/* a call as auth says: PAKE with the password, IK to the pinned key, the
 * account's grant with IK to the certified key (grant, grant_len) */
static npf_call *call_start(npf_node *n, uint64_t number, int auth, const char *password, const uint8_t pinned[32],
                            const uint8_t *grant, size_t grant_len)
{
    npf_call *c;
    uint8_t pro[64], msg[256], cmsg[32], sid[24];
    size_t pl;
    int len;
    char num[24];
    npf_out w = {0};
    if (!n->online)
        return NULL;
    c = call_new(n, 1);
    if (!c)
        return NULL;
    c->number = number;
    npf_random(c->call_id, 16);
    npf_b64url_encode(c->call_id, 16, c->call_id_s);
    c->auth = auth;
    if (auth == AUTH_GRANT) {
        memcpy(c->hs->grant, grant, grant_len);
        c->hs->grant_len = grant_len;
    }
    prologue(c, pro, &pl);
    if (auth == AUTH_PAKE) {
        snprintf(c->hs->password, sizeof c->hs->password, "%s", password);
        sid_of(c, sid);
        if (npf_cpace_start(&c->hs->cp, c->hs->password, strlen(c->hs->password), sid, sizeof sid, cmsg) < 0
            || npf_noise_init(&c->hs->noise, NPF_NOISE_XXPSK3, 1, pro, pl, n->id.dh_sk, NULL, NULL) < 0)
            goto fail;
    } else {
        if (npf_noise_init(&c->hs->noise, NPF_NOISE_IK, 1, pro, pl, n->id.dh_sk, pinned, NULL) < 0)
            goto fail;
    }
    len = npf_noise_write(&c->hs->noise, NULL, 0, msg, sizeof msg);
    if (len < 0)
        goto fail;
    snprintf(num, sizeof num, "%llu", (unsigned long long)number);
    npf_out_jobj(&w);
    npf_out_kstr(&w, "call_id", c->call_id_s);
    npf_out_kstr(&w, "callee", num);
    npf_out_kstr(&w, "auth", c->auth == AUTH_PAKE ? "pake" : c->auth == AUTH_GRANT ? "grant" : "ik");
    npf_out_kb64(&w, "hs", msg, (size_t)len);
    if (c->auth == AUTH_GRANT)
        npf_out_kb64(&w, "grant", c->hs->grant, c->hs->grant_len);
    if (c->auth == AUTH_PAKE)
        npf_out_kb64(&w, "cpace", cmsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_out_jend(&w);
    c->call_req = w.failed ? -1 : npf_node_send(n, "call", 1, w.p);
    npf_out_free(&w);
    if (c->call_req < 0)
        goto fail;
    c->st = CS_CALLING;
    npf_log("call %s: calling %llu (%s)", c->call_id_s, (unsigned long long)number,
            c->auth == AUTH_PAKE ? "pairing" : c->auth == AUTH_GRANT ? "the account's grant" : "paired");
    return c;
fail:
    call_free(c);
    return NULL;
}

npf_call *npf_call_start_grant(npf_node *n, uint64_t number, const uint8_t *chain, size_t chain_len,
                               const uint8_t *grant, size_t grant_len)
{
    npf_cert inter, leaf;
    npf_call *c;
    if (!grant || grant_len == 0 || grant_len > sizeof c->hs->grant) {
        npf_logw("call: no usable grant for %llu", (unsigned long long)number);
        return NULL;
    }
    if (npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, chain, chain_len, &inter, &leaf,
                             npf_node_time(n) / 1000) < 0
        || leaf.type != NPF_CERT_NODE || leaf.subject != number) {
        npf_log("call: the platform's certificate for %llu does not verify", (unsigned long long)number);
        return NULL;
    }
    /* IK with the certified key; the grant goes with the call (security.md 8.2) */
    return call_start(n, number, AUTH_GRANT, NULL, leaf.dh_pub, grant, grant_len);
}

npf_call *npf_call_start(npf_node *n, uint64_t number, const char *password, const uint8_t pinned[32])
{
    return call_start(n, number, password ? AUTH_PAKE : AUTH_IK, password, pinned, NULL, 0);
}

/* incoming / call_accepted: "secure" when the session is to stay on relays
 * (connect_mode secure here or on the other side) */
static void secure_of(npf_call *c, int secure)
{
    if (secure && !c->secure) {
        c->secure = 1;
        npf_log("call %s: secure: relays only, no direct path", c->call_id_s);
    }
}

void call_on_accepted(npf_call *c, const void *msg)
{
    const m_call_accepted *m = msg;
    uint8_t out[256], isk[32], p[64];
    int ol;
    if (!c->caller || c->st != CS_CALLING)
        return;
    secure_of(c, m->secure);
    if (c->auth == AUTH_PAKE) {
        char data[1024], b[NPF_B64_LEN(256)];
        if (!m->cpace_len || npf_cpace_finish(&c->hs->cp, m->cpace, 1, isk) < 0)
            goto fail;
        npf_noise_set_psk(&c->hs->noise, isk);
        npf_wipe(isk, 32);
        if (npf_noise_read(&c->hs->noise, m->hs, (size_t)m->hs_len, p, sizeof p) < 0
            || (ol = npf_noise_write(&c->hs->noise, NULL, 0, out, sizeof out)) < 0)
            goto fail;
        npf_b64url_encode(out, (size_t)ol, b);
        snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"step\":3,\"msg\":\"%s\"}", c->call_id_s, b);
        npf_node_send(c->n, "handshake", 0, data);
    } else if (npf_noise_read(&c->hs->noise, m->hs, (size_t)m->hs_len, p, sizeof p) < 0) {
        goto fail;
    }
    npf_log("call %s: accepted%s", c->call_id_s,
            call_has_ws(c) ? (c->pw.wsr ? " (the WS relay connected since the reply)" : "")
            : c->pu.r.state == RB_BOUND ? " (the UDP relay bound since the reply)" : call_has_relay(c) ? " (the UDP relay being bound)" : "");
    /* accepted, connecting first: with the relay from the reply our hello
     * goes as the transport is made, and the session is established then
     * (the caller does not wait for the callee's hello, call_hello) */
    call_accept(c);
    if (call_finish_handshake(c) < 0)
        goto fail;
    if (m->relay.mode[0])
        call_relay_setup(c, &m->relay);
    pm_check(c);                /* a relay that failed before the accept: replaced now (pm_decide) */
    /* what the callee sent through the relay before the keys, now: after
     * connecting (its hello may establish the session at once) */
    if (!call_over(c))
        call_relay_early_feed(c);
    return;
fail:
    npf_logw("call %s: handshake with the callee failed", c->call_id_s);
    npf_call_end(c, "auth_failed");
}

/* ---- callee ---- */

static void callee_reply_error(npf_node *n, const char *req, const char *err)
{
    npf_node_reply(n, "incoming", req, "error", err, NULL);
}

/* an incoming pairing (CPace, then Noise XXpsk3 with its key): the answer
 * in out (*ol bytes), the CPace message in ymsg; NULL, or the error to reply */
static const char *incoming_pake(npf_call *c, const m_incoming *m, uint8_t *out, size_t outcap, int *ol,
                                 uint8_t ymsg[32])
{
    npf_node *n = c->n;
    const char *pw = n->callee->password ? n->callee->password(n, n->callee_arg) : NULL;
    uint8_t p[64], pro[64], sid[24], isk[32];
    size_t pl;
    int ok;
    c->auth = AUTH_PAKE;
    if (n->callee->locked && n->callee->locked(n, n->callee_arg))
        return "locked";
    if (!pw || !*pw || !m->cpace_len)
        return "unauthorized";
    prologue(c, pro, &pl);
    sid_of(c, sid);
    ok = npf_cpace_start(&c->hs->cp, pw, strlen(pw), sid, sizeof sid, ymsg) >= 0
         && npf_cpace_finish(&c->hs->cp, m->cpace, 0, isk) >= 0
         && npf_noise_init(&c->hs->noise, NPF_NOISE_XXPSK3, 0, pro, pl, n->id.dh_sk, NULL, isk) >= 0
         && npf_noise_read(&c->hs->noise, m->hs, (size_t)m->hs_len, p, sizeof p) >= 0
         && (*ol = npf_noise_write(&c->hs->noise, NULL, 0, out, outcap)) >= 0;
    npf_wipe(isk, 32);
    return ok ? NULL : "unauthorized";
}

#define SESSIONS_PER_KEY 4

/* the platform's sessions here (pub NULL), or those of the caller with this key */
static int key_sessions(npf_node *n, const uint8_t *pub)
{
    npf_call *x;
    int k = 0;
    for (x = n->calls; x; x = x->next)
        k += !x->caller && !x->direct && !call_over(x)
             && (!pub || (x->keys_ready && npf_ct_eq(x->peer_pub, pub, 32) == 0));
    return k;
}

/* an incoming session of a paired caller (Noise IK) or of a grant: the
 * callee gate (security.md 8.3): the caller's key is authorized, or hosted
 * trust with a valid grant bound to that key; the answer in out (*ol bytes) */
static const char *incoming_ik(npf_call *c, const m_incoming *m, uint8_t *out, size_t outcap, int *ol)
{
    npf_node *n = c->n;
    uint8_t p[64], pro[64];
    size_t pl;
    prologue(c, pro, &pl);
    if (npf_noise_init(&c->hs->noise, NPF_NOISE_IK, 0, pro, pl, n->id.dh_sk, NULL, NULL) < 0
        || npf_noise_read(&c->hs->noise, m->hs, (size_t)m->hs_len, p, sizeof p) < 0)
        return "unauthorized";
    if (key_sessions(n, npf_noise_remote_static(&c->hs->noise)) >= SESSIONS_PER_KEY)
        return "busy";                      /* one caller does not take all the sessions */
    if (c->auth == AUTH_IK) {
        if (!n->callee->authorized || !n->callee->authorized(n, npf_noise_remote_static(&c->hs->noise), n->callee_arg))
            return "unauthorized";
    } else {
        npf_grant gr;
        if (!m->grant_len || !n->callee->grant_check
            || n->callee->grant_check(n, m->grant, (size_t)m->grant_len, npf_noise_remote_static(&c->hs->noise),
                                      &c->grant_account, &gr, n->callee_arg) < 0
            || call_set_targets(c, &gr) < 0)
            return "unauthorized";
    }
    *ol = npf_noise_write(&c->hs->noise, NULL, 0, out, outcap);
    if (*ol < 0 || call_finish_handshake(c) < 0)
        return "unauthorized";
    return NULL;
}

void node_on_incoming(npf_node *n, const m_env *e, const void *msg)
{
    const m_incoming *m = msg;
    const char *req = e->id, *err;
    uint8_t out[512], ymsg[32];
    int ol = -1;
    npf_call *c;
    npf_out w = {0};
    if (!req[0])
        return;
    if (!n->callee) {
        callee_reply_error(n, req, "unauthorized");
        return;
    }
    for (c = n->calls; c && memcmp(c->call_id, m->call_id, 16) != 0; c = c->next)
        ;
    if (c) {
        callee_reply_error(n, req, "conflict");
        return;
    }
    /* concurrent sessions (signaling.md "incoming": busy); direct sessions
     * have their own limit on the listener */
    {
        int sessions = key_sessions(n, NULL), max = n->cfg.max_calls > 0 ? n->cfg.max_calls : MAX_CALLS_DEFAULT;
        if (sessions >= max) {
            npf_logw("call: %d sessions already, refusing a new one (busy)", sessions);
            callee_reply_error(n, req, "busy");
            return;
        }
    }
    c = call_new(n, 0);
    if (!c) {
        callee_reply_error(n, req, "busy");
        return;
    }
    c->number = n->cfg.number;
    if (strcmp(m->caller.kind, "node") == 0)
        c->caller_number = strtoull(m->caller.id, NULL, 10);
    if (m->caller.app.name[0])
        snprintf(c->caller_app, sizeof c->caller_app, "%s %s", m->caller.app.name, m->caller.app.ver);
    c->caller_hosted = m->caller.hosted;
    memcpy(c->call_id, m->call_id, 16);
    npf_b64url_encode(c->call_id, 16, c->call_id_s);
    secure_of(c, m->secure);
    if (strcmp(m->auth, "pake") == 0) {
        err = incoming_pake(c, m, out, sizeof out, &ol, ymsg);
    } else if (strcmp(m->auth, "ik") == 0 || strcmp(m->auth, "grant") == 0) {
        c->auth = strcmp(m->auth, "ik") == 0 ? AUTH_IK : AUTH_GRANT;
        err = incoming_ik(c, m, out, sizeof out, &ol);
    } else {
        err = "unauthorized";
    }
    if (err) {
        callee_reply_error(n, req, err);
        call_free(c);
        return;
    }
    npf_out_jobj(&w);
    npf_out_kb64(&w, "hs", out, (size_t)ol);
    if (c->auth == AUTH_PAKE)
        npf_out_kb64(&w, "cpace", ymsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_out_jend(&w);
    if (w.failed) {
        npf_out_free(&w);
        callee_reply_error(n, req, "busy");
        call_free(c);
        return;
    }
    npf_node_reply(n, "incoming", req, "ok", NULL, w.p);
    npf_out_free(&w);
    c->st = CS_ANSWERED;
    npf_log("call %s: incoming %s call accepted", c->call_id_s, c->auth == AUTH_PAKE ? "pairing" : "paired");
    if (m->relay.mode[0])
        call_relay_setup(c, &m->relay);
}

void call_on_handshake(npf_call *c, const void *msg)
{
    const m_handshake *m = msg;
    uint8_t p[64];
    if (c->caller || c->auth != AUTH_PAKE || c->keys_ready)
        return;
    /* locked while this pairing was under way (other guesses in parallel
     * failed): no guess for it either (security.md 8.3) */
    if (c->n->callee->locked && c->n->callee->locked(c->n, c->n->callee_arg)) {
        npf_call_end(c, "locked");
        return;
    }
    if (npf_noise_read(&c->hs->noise, m->msg, (size_t)m->msg_len, p, sizeof p) < 0) {
        /* wrong password: count it (security.md 8.3) */
        npf_logw("call %s: pairing failed (wrong password)", c->call_id_s);
        if (c->n->callee->pair_failed)
            c->n->callee->pair_failed(c->n, c->n->callee_arg);
        npf_call_end(c, "auth_failed");
        return;
    }
    /* the same limit per key as a paired caller's (incoming_ik): checked
     * where the session is admitted, in the step that admits it */
    if (key_sessions(c->n, npf_noise_remote_static(&c->hs->noise)) >= SESSIONS_PER_KEY) {
        npf_logw("call %s: pairing refused: this key has %d sessions here already", c->call_id_s, SESSIONS_PER_KEY);
        npf_call_end(c, "busy");
        return;
    }
    if (call_finish_handshake(c) < 0) {
        npf_call_end(c, "error");
        return;
    }
    /* msg 3 depends on our fresh ephemeral key: not a replay, the caller knows the password */
    if (c->n->callee->paired)
        c->n->callee->paired(c->n, c->peer_pub, c->n->callee_arg);
    npf_log("call %s: paired", c->call_id_s);
    /* the platform plans no punching round before this (signaling.md
     * handshake_done, security.md 8.3) */
    call_tell(c, "handshake_done");
}

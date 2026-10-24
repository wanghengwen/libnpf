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

int call_finish_handshake(npf_call *c)
{
    uint8_t k1[32], k2[32];
    const uint8_t *rs = npf_noise_remote_static(&c->hs->noise);
    if (!rs || npf_noise_split(&c->hs->noise, NULL, NULL, k1, k2, NULL) < 0)
        return -1;
    memcpy(c->peer_pub, rs, 32);
    memcpy(c->k12, k1, 32);
    memcpy(c->k12 + 32, k2, 32);
    npf_wipe(k1, 32);
    npf_wipe(k2, 32);
    if (c->hs->password[0])
        npf_wipe(c->hs->password, sizeof c->hs->password);
    return call_start_transport(c);
}
/* ---- caller ---- */

/* a call as auth says: PAKE with the password, IK to the pinned key, the
 * account's grant with IK to the certified key (grant, grant_len) */
static npf_call *call_start(npf_node *n, uint64_t number, int auth, const char *password, const uint8_t pinned[32],
                            const uint8_t *grant, size_t grant_len);

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

static npf_call *call_start(npf_node *n, uint64_t number, int auth, const char *password, const uint8_t pinned[32],
                            const uint8_t *grant, size_t grant_len)
{
    char data[4096];
    npf_call *c;
    uint8_t pro[64], msg[256], cmsg[32], sid[24];
    size_t pl;
    int len;
    char num[24], hs[NPF_B64_LEN(256)];
    npf_jw w;
    if (!n->online)
        return NULL;
    c = call_new(n, 1);
    if (!c)
        return NULL;
    c->number = number;
    npf_random(c->call_id, 16);
    call_b64_of(c->call_id, 16, c->call_id_s);
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
        memcpy(c->hs->pinned, pinned, 32);
        if (npf_noise_init(&c->hs->noise, NPF_NOISE_IK, 1, pro, pl, n->id.dh_sk, pinned, NULL) < 0)
            goto fail;
    }
    len = npf_noise_write(&c->hs->noise, NULL, 0, msg, sizeof msg);
    if (len < 0)
        goto fail;
    call_b64_of(msg, (size_t)len, hs);
    snprintf(num, sizeof num, "%llu", (unsigned long long)number);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "call_id", c->call_id_s);
    npf_jw_kstr(&w, "callee", num);
    npf_jw_kstr(&w, "auth", c->auth == AUTH_PAKE ? "pake" : c->auth == AUTH_GRANT ? "grant" : "ik");
    npf_jw_kstr(&w, "hs", hs);
    if (c->auth == AUTH_GRANT)
        npf_jw_kb64(&w, "grant", c->hs->grant, c->hs->grant_len);
    if (c->auth == AUTH_PAKE)
        npf_jw_kb64(&w, "cpace", cmsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) < 0)
        goto fail;
    c->call_req = npf_node_send(n, "call", 1, data);
    if (c->call_req < 0)
        goto fail;
    c->state = NPF_CALL_CALLING;
    npf_log("call %s: calling %llu (%s)", c->call_id_s, (unsigned long long)number,
            c->auth == AUTH_PAKE ? "pairing" : c->auth == AUTH_GRANT ? "the account's grant" : "paired");
    return c;
fail:
    call_free(c);
    return NULL;
}

/* incoming / call_accepted: "secure" when the session is to stay on relays
 * (connect_mode secure here or on the other side) */
static void secure_of(npf_call *c, const npf_json *j, int d)
{
    int v = 0;
    if (npf_json_bool(j, npf_json_get(j, d, "secure"), &v) == 0 && v && !c->secure) {
        c->secure = 1;
        npf_log("call %s: secure: relays only, no direct path", c->call_id_s);
    }
}

void call_caller_accepted(npf_call *c, const npf_json *j, int d)
{
    uint8_t msg[512], out[256], peer_y[32], isk[32], p[64];
    int ml, ol;
    ml = npf_json_get_b64(j, d, "hs", msg, sizeof msg);
    if (ml < 0)
        goto fail;
    secure_of(c, j, d);
    if (c->auth == AUTH_PAKE) {
        char data[1024];
        if (npf_json_get_b64(j, d, "cpace", peer_y, 32) != 32 || npf_cpace_finish(&c->hs->cp, peer_y, 1, isk) < 0)
            goto fail;
        npf_noise_set_psk(&c->hs->noise, isk);
        npf_wipe(isk, 32);
        if (npf_noise_read(&c->hs->noise, msg, (size_t)ml, p, sizeof p) < 0)
            goto fail;
        ol = npf_noise_write(&c->hs->noise, NULL, 0, out, sizeof out);
        if (ol < 0)
            goto fail;
        {
            char b[NPF_B64_LEN(256)];
            call_b64_of(out, (size_t)ol, b);
            snprintf(data, sizeof data, "{\"call_id\":\"%s\",\"step\":3,\"msg\":\"%s\"}", c->call_id_s, b);
        }
        npf_node_send(c->n, "handshake", 0, data);
    } else {
        if (npf_noise_read(&c->hs->noise, msg, (size_t)ml, p, sizeof p) < 0)
            goto fail;
    }
    if (call_finish_handshake(c) < 0)
        goto fail;
    call_set_state(c, NPF_CALL_CONNECTING, NULL);
    call_relay_setup(c, j, d);
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
static const char *incoming_pake(npf_call *c, const npf_json *j, int d, const uint8_t *msg, int ml, uint8_t *out,
                                 size_t outcap, int *ol, uint8_t ymsg[32])
{
    npf_node *n = c->n;
    const char *pw = n->callee->password ? n->callee->password(n, n->callee_arg) : NULL;
    uint8_t p[64], pro[64], sid[24], isk[32], peer_y[32];
    size_t pl;
    int ok;
    c->auth = AUTH_PAKE;
    if (n->callee->locked && n->callee->locked(n, n->callee_arg))
        return "locked";
    if (!pw || !*pw || npf_json_get_b64(j, d, "cpace", peer_y, 32) != 32)
        return "unauthorized";
    prologue(c, pro, &pl);
    sid_of(c, sid);
    ok = npf_cpace_start(&c->hs->cp, pw, strlen(pw), sid, sizeof sid, ymsg) >= 0
         && npf_cpace_finish(&c->hs->cp, peer_y, 0, isk) >= 0
         && npf_noise_init(&c->hs->noise, NPF_NOISE_XXPSK3, 0, pro, pl, n->id.dh_sk, NULL, isk) >= 0
         && npf_noise_read(&c->hs->noise, msg, (size_t)ml, p, sizeof p) >= 0
         && (*ol = npf_noise_write(&c->hs->noise, NULL, 0, out, outcap)) >= 0;
    npf_wipe(isk, 32);
    return ok ? NULL : "unauthorized";
}

#define SESSIONS_PER_KEY 4

/* the sessions here of the caller with this key */
static int key_sessions(npf_node *n, const uint8_t *pub)
{
    npf_call *x;
    int k = 0;
    for (x = n->calls; pub && x; x = x->next)
        if (!x->caller && !x->direct && !x->ended && x->keys_ready && npf_ct_eq(x->peer_pub, pub, 32) == 0)
            k++;
    return k;
}

/* an incoming session of a paired caller (Noise IK) or of a grant: the
 * callee gate (security.md 8.3): the caller's key is authorized, or hosted
 * trust with a valid grant bound to that key; the answer in out (*ol bytes) */
static const char *incoming_ik(npf_call *c, const npf_json *j, int d, const uint8_t *msg, int ml, uint8_t *out,
                               size_t outcap, int *ol)
{
    npf_node *n = c->n;
    uint8_t p[64], pro[64];
    size_t pl;
    prologue(c, pro, &pl);
    if (npf_noise_init(&c->hs->noise, NPF_NOISE_IK, 0, pro, pl, n->id.dh_sk, NULL, NULL) < 0
        || npf_noise_read(&c->hs->noise, msg, (size_t)ml, p, sizeof p) < 0)
        return "unauthorized";
    if (key_sessions(n, npf_noise_remote_static(&c->hs->noise)) >= SESSIONS_PER_KEY)
        return "busy";                      /* one caller does not take all the sessions */
    if (c->auth == AUTH_IK) {
        if (!n->callee->authorized || !n->callee->authorized(n, npf_noise_remote_static(&c->hs->noise), n->callee_arg))
            return "unauthorized";
    } else {
        uint8_t g[512];
        npf_grant gr;
        int gl = npf_json_get_b64(j, d, "grant", g, sizeof g);
        if (gl <= 0 || !n->callee->grant_check
            || n->callee->grant_check(n, g, (size_t)gl, npf_noise_remote_static(&c->hs->noise), &c->grant_account, &gr,
                                      n->callee_arg) < 0
            || call_set_targets(c, &gr) < 0)
            return "unauthorized";
    }
    *ol = npf_noise_write(&c->hs->noise, NULL, 0, out, outcap);
    if (*ol < 0 || call_finish_handshake(c) < 0)
        return "unauthorized";
    return NULL;
}

void call_handle_incoming(npf_node *n, const npf_json *j, int d)
{
    char data[4096];
    char req[24], auth[8], hs_b[NPF_B64_LEN(512)];
    uint8_t msg[512], out[512], ymsg[32];
    const char *err;
    int ml, ol = -1;
    npf_call *c;
    npf_jw w;
    if (npf_json_get_str(j, 0, "id", req, sizeof req) < 0)
        return;
    if (!n->callee) {
        callee_reply_error(n, req, "unauthorized");
        return;
    }
    if (call_find(n, j, d)) {
        callee_reply_error(n, req, "conflict");
        return;
    }
    /* concurrent sessions (signaling.md "incoming": busy); direct sessions
     * have their own limit on the listener */
    {
        int sessions = 0, max = n->cfg.max_calls > 0 ? n->cfg.max_calls : MAX_CALLS_DEFAULT;
        for (c = n->calls; c; c = c->next)
            if (!c->caller && !c->direct && !c->ended)
                sessions++;
        if (sessions >= max) {
            npf_logw("call: %d sessions already, refusing a new one (busy)", sessions);
            callee_reply_error(n, req, "busy");
            return;
        }
    }
    c = call_new(n, 0);
    if (!c)
        return;
    snprintf(c->req_id, sizeof c->req_id, "%s", req);
    c->number = n->cfg.number;
    {
        int who = npf_json_get(j, d, "caller");
        char id[24];
        if (who >= 0 && npf_json_eq(j, npf_json_get(j, who, "kind"), "node")
            && npf_json_get_str(j, who, "id", id, sizeof id) > 0)
            c->caller_number = strtoull(id, NULL, 10);
        if (who >= 0) {
            int a = npf_json_get(j, who, "app");
            char an[40] = "", av[40] = "";
            if (a >= 0 && npf_json_get_str(j, a, "name", an, sizeof an) > 0
                && npf_json_get_str(j, a, "ver", av, sizeof av) > 0)
                snprintf(c->caller_app, sizeof c->caller_app, "%.32s %.32s", an, av);   /* each 1..32 (signaling.md) */
            npf_json_bool(j, npf_json_get(j, who, "hosted"), &c->caller_hosted);
        }
    }
    if (npf_json_get_b64(j, d, "call_id", c->call_id, 16) != 16
        || npf_json_get_str(j, d, "auth", auth, sizeof auth) < 0
        || (ml = npf_json_get_b64(j, d, "hs", msg, sizeof msg)) < 0) {
        callee_reply_error(n, req, "bad_request");
        call_free(c);
        return;
    }
    call_b64_of(c->call_id, 16, c->call_id_s);
    secure_of(c, j, d);
    if (strcmp(auth, "pake") == 0) {
        err = incoming_pake(c, j, d, msg, ml, out, sizeof out, &ol, ymsg);
    } else if (strcmp(auth, "ik") == 0 || strcmp(auth, "grant") == 0) {
        c->auth = strcmp(auth, "ik") == 0 ? AUTH_IK : AUTH_GRANT;
        err = incoming_ik(c, j, d, msg, ml, out, sizeof out, &ol);
    } else {
        err = "unauthorized";
    }
    if (err) {
        callee_reply_error(n, req, err);
        call_free(c);
        return;
    }
    call_b64_of(out, (size_t)ol, hs_b);
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "hs", hs_b);
    if (c->auth == AUTH_PAKE)
        npf_jw_kb64(&w, "cpace", ymsg, 32);
    npf_node_write_nat(n, &w);
    npf_node_write_cands(n, &w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) < 0) {
        call_free(c);
        return;
    }
    npf_node_reply(n, "incoming", req, "ok", NULL, data);
    c->state = NPF_CALL_CONNECTING;
    npf_log("call %s: incoming %s call accepted", c->call_id_s, c->auth == AUTH_PAKE ? "pairing" : "paired");
    call_relay_setup(c, j, d);
}

void call_handle_handshake(npf_call *c, const npf_json *j, int d)
{
    uint8_t msg[512], p[64];
    int ml;
    int64_t step;
    if (c->caller || c->auth != AUTH_PAKE || c->keys_ready)
        return;
    if (npf_json_get_int(j, d, "step", 3, 3, &step) < 0 || (ml = npf_json_get_b64(j, d, "msg", msg, sizeof msg)) < 0)
        return;
    /* locked while this pairing was under way (other guesses in parallel
     * failed): no guess for it either (security.md 8.3) */
    if (c->n->callee->locked && c->n->callee->locked(c->n, c->n->callee_arg)) {
        npf_call_end(c, "locked");
        return;
    }
    if (npf_noise_read(&c->hs->noise, msg, (size_t)ml, p, sizeof p) < 0) {
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
}

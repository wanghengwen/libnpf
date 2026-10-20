/* Callee-side local state shared by the NAS device and console nodes
 * (security.md 5.5, 8.2, 8.3, D20, D21): current / default password,
 * paired callers, password lock, owner, revocations, hosted trust.
 * Kept in a JSON state file; only local commands change it. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "npf/out.h"
#include "npf/callee.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/node.h"

/* ---- state file ---- */

static int state_load(npf_callee *d)
{
    npf_jtok *tok;
    char *s;
    long n = npf_file_read(d->state_path, &s);
    npf_json j;
    int arr, i;
    int64_t v;
    struct stat st;
    snprintf(d->password, sizeof d->password, "%s", d->default_pw);
    d->npaired = 0;
    d->fails = 0;
    d->locked_until = 0;
    d->lock_secs = 0;
    d->cert_len = 0;
    d->owner = 0;
    d->nrevokes = 0;
    d->owner_reset_pending = 0;
    if (n < 0)
        return 0;   /* first run: defaults */
    if (stat(d->state_path, &st) == 0)
        d->state_mtime = st.st_mtime;
    if (!(tok = malloc(2048 * sizeof *tok)) || npf_json_parse(&j, s, (size_t)n, tok, 2048) < 0
        || tok[0].type != NPF_JT_OBJECT) {
        npf_log("state: %s is corrupt, using defaults", d->state_path);
        free(tok);
        free(s);
        return 0;
    }
    if (npf_json_get_str(&j, 0, "password", d->password, sizeof d->password) <= 0)
        snprintf(d->password, sizeof d->password, "%s", d->default_pw);
    arr = npf_json_get(&j, 0, "paired");
    for (i = 0; arr >= 0 && i < tok[arr].size && d->npaired < NPF_MAX_PAIRED; i++) {
        int it = npf_json_item(&j, arr, i);
        if (npf_json_get_b64(&j, it, "pub", d->paired[d->npaired].pub, 32) == 32) {
            npf_json_get_int(&j, it, "added", 0, INT64_MAX, &d->paired[d->npaired].added);
            d->npaired++;
        }
    }
    if (npf_json_get_int(&j, 0, "fails", 0, 1000000, &v) == 0) d->fails = (int)v;
    if (npf_json_get_int(&j, 0, "locked_until", 0, INT64_MAX, &v) == 0) d->locked_until = v;
    if (npf_json_get_int(&j, 0, "lock_secs", 0, INT64_MAX, &v) == 0) d->lock_secs = v;
    {
        int cl = npf_json_get_b64(&j, 0, "cert", d->cert, sizeof d->cert);
        d->cert_len = cl > 0 ? (size_t)cl : 0;
    }
    {
        char a[32];
        d->owner = npf_json_get_str(&j, 0, "owner", a, sizeof a) > 0 ? strtoull(a, NULL, 10) : 0;
    }
    if (npf_json_get_int(&j, 0, "owner_reset_pending", 0, 1, &v) == 0) d->owner_reset_pending = (int)v;
    arr = npf_json_get(&j, 0, "revokes");
    d->nrevokes = 0;
    for (i = 0; arr >= 0 && i < tok[arr].size && d->nrevokes < NPF_MAX_REVOKES; i++) {
        int it = npf_json_item(&j, arr, i);
        char a[32];
        if (npf_json_get_str(&j, it, "account", a, sizeof a) > 0
            && npf_json_get_int(&j, it, "before", 0, INT64_MAX, &d->revokes[d->nrevokes].before) == 0) {
            d->revokes[d->nrevokes].account = strtoull(a, NULL, 10);
            d->nrevokes++;
        }
    }
    free(tok);
    free(s);
    return 0;
}

static int state_save(npf_callee *d)
{
    char *buf = malloc(65536);
    npf_jw w;
    int i, n;
    struct stat st;
    if (!buf)
        return -1;
    npf_jw_init(&w, buf, 65536);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "password", d->password);
    npf_jw_key(&w, "paired");
    npf_jw_arr(&w);
    for (i = 0; i < d->npaired; i++) {
        npf_jw_obj(&w);
        npf_jw_kb64(&w, "pub", d->paired[i].pub, 32);
        npf_jw_kint(&w, "added", d->paired[i].added);
        npf_jw_end(&w);
    }
    npf_jw_end(&w);
    npf_jw_kint(&w, "fails", d->fails);
    npf_jw_kint(&w, "locked_until", d->locked_until);
    npf_jw_kint(&w, "lock_secs", d->lock_secs);
    if (d->cert_len)
        npf_jw_kb64(&w, "cert", d->cert, d->cert_len);
    if (d->owner) {
        char a[24];
        snprintf(a, sizeof a, "%llu", (unsigned long long)d->owner);
        npf_jw_kstr(&w, "owner", a);
    }
    npf_jw_kint(&w, "owner_reset_pending", d->owner_reset_pending);
    npf_jw_key(&w, "revokes");
    npf_jw_arr(&w);
    for (i = 0; i < d->nrevokes; i++) {
        char a[24];
        snprintf(a, sizeof a, "%llu", (unsigned long long)d->revokes[i].account);
        npf_jw_obj(&w);
        npf_jw_kstr(&w, "account", a);
        npf_jw_kint(&w, "before", d->revokes[i].before);
        npf_jw_end(&w);
    }
    npf_jw_end(&w);
    npf_jw_end(&w);
    n = npf_jw_finish(&w);
    if (n < 0 || npf_file_write(d->state_path, buf, (size_t)n, 0600) < 0) {
        npf_loge("state: cannot write %s: %s", d->state_path, strerror(errno));
        free(buf);
        return -1;
    }
    npf_wipe(buf, (size_t)n);           /* the password */
    free(buf);
    if (stat(d->state_path, &st) == 0)
        d->state_mtime = st.st_mtime;
    return 0;
}

/* reload when the local command line changed the file */
static void state_refresh(npf_callee *d)
{
    struct stat st;
    if (stat(d->state_path, &st) == 0 && st.st_mtime != d->state_mtime) {
        state_load(d);
        npf_log("state: reloaded (local change)");
    }
}

static void sync_paired(npf_callee *d)
{
    char data[8192];
    npf_jw w;
    int i;
    npf_jw_init(&w, data, sizeof data);
    npf_jw_obj(&w);
    npf_jw_key(&w, "fps");
    npf_jw_arr(&w);
    for (i = 0; i < d->npaired; i++) {
        uint8_t fp[8];
        npf_le64(fp, npf_fp(d->paired[i].pub));
        npf_jw_b64(&w, fp, 8);
    }
    npf_jw_end(&w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        npf_node_send(d->node, "paired_sync", 0, data);
}

static void report_lock(npf_callee *d)
{
    char data[64];
    snprintf(data, sizeof data, "{\"locked_until\":%lld}", (long long)d->locked_until);
    npf_node_send(d->node, "lock_report", 0, data);
}

/* ---- callee operations ---- */

static int op_authorized(npf_node *n, const uint8_t pub[32], void *arg)
{
    npf_callee *d = arg;
    int i;
    (void)n;
    state_refresh(d);
    for (i = 0; i < d->npaired; i++)
        if (npf_ct_eq(d->paired[i].pub, pub, 32) == 0)
            return 1;
    return 0;
}

static const char *op_password(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    state_refresh(d);
    return d->password;
}

static int64_t op_locked(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    return d->locked_until;
}

static void op_paired(npf_node *n, const uint8_t pub[32], void *arg)
{
    npf_callee *d = arg;
    int i;
    (void)n;
    d->fails = 0;
    d->lock_secs = 0;
    for (i = 0; i < d->npaired; i++)
        if (memcmp(d->paired[i].pub, pub, 32) == 0)
            break;
    if (i == d->npaired && d->npaired < NPF_MAX_PAIRED) {
        memcpy(d->paired[d->npaired].pub, pub, 32);
        d->paired[d->npaired].added = time(NULL);
        d->npaired++;
    }
    state_save(d);
    sync_paired(d);
}

/* 5 failures lock 15 minutes, doubling up to 24 hours (security.md 8.3) */
static void op_pair_failed(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    d->fails++;
    if (d->fails >= 5) {
        d->lock_secs = d->lock_secs ? d->lock_secs * 2 : 15 * 60;
        if (d->lock_secs > 24 * 3600)
            d->lock_secs = 24 * 3600;
        d->locked_until = time(NULL) + d->lock_secs;
        d->fails = 0;
        npf_logw("pairing locked for %lld s after repeated wrong passwords", (long long)d->lock_secs);
        report_lock(d);
    }
    state_save(d);
}

/* hosted trust (security.md 8.2): the grant is signed by the platform's
 * intermediate (the issuer of our own certificate), names us and this caller
 * key, is unexpired and not older than a revocation of its account */
static int op_grant_check(npf_node *n, const uint8_t *g, size_t len, const uint8_t pub[32], uint64_t *account,
                          npf_grant *out, void *arg)
{
    npf_callee *d = arg;
    npf_cert inter;
    npf_grant gr;
    int64_t now = npf_node_time(n) / 1000;
    int i;
    state_refresh(d);
    if (!d->hosted_trust || n->cert_len == 0 || npf_cert_parse(n->cert, n->cert_len, &inter) < 0
        || !(inter.perms & NPF_PERM_GRANT) || npf_grant_verify(g, len, inter.sign_pub, &gr) < 0)
        return -1;
    /* an account's client, or the hosted client of its public mappings
     * (security.md 8.4: then only the grant's targets) */
    if ((gr.kind != NPF_GRANT_ACCOUNT && gr.kind != NPF_GRANT_HOSTED) || gr.number != d->number
        || memcmp(gr.caller_dh, pub, 32) != 0)
        return -1;
    if ((int64_t)gr.expires + 300 < now || (int64_t)gr.issued > now + 300)   /* 5 minutes of clock skew */
        return -1;
    for (i = 0; i < d->nrevokes; i++)
        if (d->revokes[i].account == gr.account && (int64_t)gr.issued < d->revokes[i].before)
            return -1;
    *account = gr.account;
    *out = gr;
    return 0;
}

static void op_revoke(npf_node *n, uint64_t account, int64_t before, int owner, void *arg)
{
    npf_callee *d = arg;
    int i;
    (void)n;
    for (i = 0; i < d->nrevokes; i++)
        if (d->revokes[i].account == account)
            break;
    if (i == d->nrevokes) {
        if (d->nrevokes == NPF_MAX_REVOKES) {       /* drop the oldest */
            memmove(&d->revokes[0], &d->revokes[1], (NPF_MAX_REVOKES - 1) * sizeof d->revokes[0]);
            d->nrevokes--;
            i = d->nrevokes;
        }
        d->nrevokes++;
    }
    d->revokes[i].account = account;
    d->revokes[i].before = before;
    if (owner && d->owner == account)
        d->owner = 0;
    npf_log("revoked account %llu%s", (unsigned long long)account, owner ? " (owner)" : "");
    state_save(d);
}

static void op_bind_committed(npf_node *n, uint64_t account, const uint8_t op[16], void *arg)
{
    npf_callee *d = arg;
    (void)n;
    if (d->pending_owner != account || memcmp(d->pending_op, op, 16) != 0 || time(NULL) > d->pending_until)
        return;
    d->owner = account;
    d->pending_owner = 0;
    state_save(d);
    npf_log("owner is now account %llu", (unsigned long long)account);
}

/* bind_approve inside the tunnel (signaling.md "隧道内控制消息") */
static void op_control(npf_node *n, npf_call *c, const npf_json *j, void *arg)
{
    npf_callee *d = arg;
    char type[32], a[32], reply[256];
    int dd = npf_json_get(j, 0, "data");
    uint8_t op[16], ch[16], msg[64], sig[64];
    int64_t expires;
    npf_cert inter, leaf;
    npf_identity id;
    if (npf_json_get_str(j, 0, "type", type, sizeof type) <= 0)
        return;
    if (strcmp(type, "bind_approve") != 0) {
        npf_call_ctl_reply(c, type, j, "error", "unsupported_type", NULL);
        return;
    }
    state_refresh(d);
    if (npf_call_auth(c) != NPF_AUTH_IK && npf_call_auth(c) != NPF_AUTH_PAKE) {   /* paired callers only */
        npf_call_ctl_reply(c, type, j, "error", "forbidden", NULL);
        return;
    }
    if (d->owner) {
        npf_call_ctl_reply(c, type, j, "error", "conflict", NULL);
        return;
    }
    if (npf_json_get_str(j, dd, "account_id", a, sizeof a) <= 0 || npf_json_get_b64(j, dd, "operation_id", op, 16) != 16
        || npf_json_get_b64(j, dd, "challenge", ch, 16) != 16
        || npf_json_get_int(j, dd, "expires", 0, INT64_MAX, &expires) < 0
        || npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, n->cert, n->cert_len, &inter,
                                &leaf, 0) < 0) {
        npf_call_ctl_reply(c, type, j, "error", "bad_request", NULL);
        return;
    }
    d->pending_owner = strtoull(a, NULL, 10);
    memcpy(d->pending_op, op, 16);
    d->pending_until = time(NULL) + 600;
    npf_bind_proof_msg(msg, d->number, leaf.key_gen, d->pending_owner, op, ch, expires);
    npf_identity_from_seed(&id, d->seed);
    npf_sign2(sig, id.sign_sk, "npf-bind-v1", 11, msg, 60);
    npf_identity_wipe(&id);
    {
        char b[NPF_B64_LEN(64)];
        npf_b64url_encode(sig, 64, b);
        snprintf(reply, sizeof reply, "{\"proof\":\"%s\",\"key_gen\":%u}", b, leaf.key_gen);
    }
    npf_call_ctl_reply(c, type, j, "ok", NULL, reply);
    npf_log("bind requested for account %s", a);
}

void npf_callee_show(npf_callee *d, npf_out *o)
{
    int i;
    char num[16];
    snprintf(num, sizeof num, "%09llu", (unsigned long long)d->number);
    npf_out_printf(o, "number:           %.3s %.3s %.3s\n", num, num + 3, num + 6);
    npf_out_printf(o, "current password: %s%s\n", d->password, strcmp(d->password, d->default_pw) ? " (changed)" : "");
    npf_out_printf(o, "default password: %s\n", d->default_pw);
    if (d->locked_until > time(NULL))
        npf_out_printf(o, "pairing locked:   %lld s left\n", (long long)(d->locked_until - time(NULL)));
    if (d->owner)
        npf_out_printf(o, "owner account:    %llu\n", (unsigned long long)d->owner);
    else
        npf_out_printf(o, "owner account:    none\n");
    npf_out_printf(o, "paired callers:   %d\n", d->npaired);
    for (i = 0; i < d->npaired; i++) {
        char b[64], t[32];
        time_t a = (time_t)d->paired[i].added;
        npf_b64url_encode(d->paired[i].pub, 32, b);
        strftime(t, sizeof t, "%Y-%m-%d %H:%M", localtime(&a));
        npf_out_printf(o, "  %2d  %016llx  %s  %s\n", i + 1, (unsigned long long)npf_fp(d->paired[i].pub), t, b);
    }
}


static void on_cert(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    memcpy(d->cert, n->cert, n->cert_len);
    d->cert_len = n->cert_len;
    state_save(d);
}

int npf_callee_init(npf_callee *d, const char *state_path, uint64_t number, const uint8_t seed[32],
                    const char *default_pw)
{
    memset(d, 0, sizeof *d);
    d->state_path = state_path;
    d->number = number;
    memcpy(d->seed, seed, 32);
    snprintf(d->default_pw, sizeof d->default_pw, "%s", default_pw);
    d->hosted_trust = 1;
    npf_policy_refresh(&d->policy);
    return state_load(d);
}

int npf_callee_save(npf_callee *d)
{
    return state_save(d);
}

void npf_callee_attach(npf_callee *d, npf_node *n)
{
    d->node = n;
    d->ops.authorized = op_authorized;
    d->ops.password = op_password;
    d->ops.locked_until = op_locked;
    d->ops.paired = op_paired;
    d->ops.pair_failed = op_pair_failed;
    d->ops.grant_check = op_grant_check;
    d->ops.revoke = op_revoke;
    d->ops.bind_committed = op_bind_committed;
    d->ops.control = op_control;
    d->ops.policy = &d->policy;
    n->callee = &d->ops;
    n->callee_arg = d;
    n->on_cert = on_cert;
    n->on_cert_arg = d;
    if (d->cert_len) {
        memcpy(n->cert, d->cert, d->cert_len);
        n->cert_len = d->cert_len;
    }
}

void npf_callee_on_login(npf_callee *d)
{
    sync_paired(d);
    report_lock(d);
    if (d->owner_reset_pending) {
        npf_node_send(d->node, "owner_reset", 0, NULL);
        d->owner_reset_pending = 0;
        state_save(d);
    }
}

/* local commands (D21); returns the exit code, or -2 if cmd is not one of them */
int npf_callee_cmd(npf_callee *d, const char *cmd, int argc, char **argv, npf_out *o)
{
    if (strcmp(cmd, "show") == 0) {
        npf_callee_show(d, o);
        return 0;
    }
    if (strcmp(cmd, "passwd") == 0) {
        int clear = 0, i;
        const char *np = NULL;
        for (i = 0; i < argc; i++) {
            if (strcmp(argv[i], "--clear") == 0) clear = 1;
            else if (strcmp(argv[i], "--reset") == 0) np = d->default_pw;
            else np = argv[i];
        }
        if (!np) {
            npf_out_printf(o, "passwd NEW | --reset [--clear]\n");
            return 2;
        }
        if (strlen(np) < 8 || strlen(np) >= sizeof d->password) {
            npf_out_printf(o, "the password needs at least 8 characters\n");
            return 1;
        }
        snprintf(d->password, sizeof d->password, "%s", np);
        d->fails = 0;
        d->locked_until = 0;
        d->lock_secs = 0;
        if (clear)
            d->npaired = 0;
        if (state_save(d) < 0)
            return 1;
        npf_out_printf(o, "password %s%s\n", np == d->default_pw ? "reset to the default" : "changed",
               clear ? ", all paired callers removed" : "");
        return 0;
    }
    if (strcmp(cmd, "unpair") == 0) {
        if (argc < 1) {
            npf_out_printf(o, "unpair N | all\n");
            return 2;
        }
        if (strcmp(argv[0], "all") == 0) {
            d->npaired = 0;
        } else {
            int k = atoi(argv[0]);
            if (k < 1 || k > d->npaired) {
                npf_out_printf(o, "no such entry\n");
                return 1;
            }
            memmove(&d->paired[k - 1], &d->paired[k], (size_t)(d->npaired - k) * sizeof d->paired[0]);
            d->npaired--;
        }
        if (state_save(d) < 0)
            return 1;
        npf_out_printf(o, "removed\n");
        return 0;
    }
    if (strcmp(cmd, "owner-reset") == 0) {
        d->owner = 0;
        d->owner_reset_pending = 1;
        if (state_save(d) < 0)
            return 1;
        npf_out_printf(o, "owner forgotten; the platform is told at the next login\n");
        return 0;
    }
    return -2;
}

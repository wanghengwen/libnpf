/* libnpf: requests to the platform (npf_request), for the command line and
 * the web console; the console's commands are in platform_console.c. Replies
 * come back through the caller's callback on the library thread. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"
#include "npf/peers.h"


/* data (a JSON object) with the key proof of this connection added:
 * sign_pub and key_sig = Ed25519(sign key, "npf-client-key-v1" | Noise handshake hash) */
static int add_key_proof(npf_node *n, const char *data, char *out, size_t cap)
{
    uint8_t sig[64];
    char pub64[NPF_B64_LEN(32) + 1], sig64[NPF_B64_LEN(64) + 1];
    size_t l = strlen(data);
    int r;
    while (l && data[l - 1] != '}')
        l--;
    if (!l || !n->sig)
        return -1;
    npf_sign2(sig, n->id.sign_sk, "npf-client-key-v1", 17, npf_sig_hash(n->sig), 64);
    pub64[npf_b64url_encode(n->id.sign_pub, 32, pub64)] = 0;
    sig64[npf_b64url_encode(sig, 64, sig64)] = 0;
    r = snprintf(out, cap, "%.*s%s\"sign_pub\":\"%s\",\"key_sig\":\"%s\"}", (int)(l - 1), data,
                 strchr(data, ':') ? "," : "", pub64, sig64);
    return r < 0 || (size_t)r >= cap ? -1 : 0;
}

/* data of a relayed request: one JSON object, nothing after it */
static int json_object_ok(const char *data)
{
    npf_jtok *tok = malloc(NPF_JSON_MAX_TOKENS * sizeof *tok);
    npf_json j;
    int ok;
    if (!tok)
        return 0;
    ok = npf_json_parse(&j, data, strlen(data), tok, NPF_JSON_MAX_TOKENS) == 0 && tok[0].type == NPF_JT_OBJECT;
    free(tok);
    return ok;
}

/* ---- the running npf: requests relayed for the command line ---- */

static const char *const k_relay[] = {"verify_begin", "verify_finish", "account_register", "account_login",
                                      "account_logout", "account_get", "account_update", "account_delete", "plan_list",
                                      "pay_ticket", "password_change", "password_reset_begin", "password_reset_finish", "device_list",
                                      "device_get", "device_update", "device_unbind", "share_create", "share_accept",
                                      "share_list", "share_revoke", "share_set", "share_leave", "owner_reset", "mapping_list",
                                      "mapping_create", "mapping_update", "mapping_delete", "hosted_register",
                                      "hosted_token", "hosted_accounts", "hosted_stats", "hosted_login", "auth_providers",
                                      "auth_begin", "auth_status", "auth_finish", "login_method_bind",
                                      "login_method_unbind", "pubconn_list", NULL};

typedef struct relay {
    npf_t       *c;
    npf_reply_cb cb;
    void        *user;
    char         type[32];
} relay;

/* what the reply changes here: the account session and its certificate */
static void relay_apply(npf_t *c, const char *type, const npf_json *j)
{
    npf_node *n = &c->node;
    int d = npf_json_get(j, 0, "data");
    if (strcmp(type, "account_login") == 0 || strcmp(type, "account_register") == 0
        || strcmp(type, "password_reset_finish") == 0 || strcmp(type, "hosted_login") == 0
        || strcmp(type, "auth_finish") == 0) {
        char a[24];
        int cl = npf_json_get_b64(j, d, "cert", n->account_cert, sizeof n->account_cert);
        if (cl > 0) {
            n->account_cert_len = (size_t)cl;
            npf_save_account_cert(c);
        }
        if (npf_json_get_str(j, d, "account_id", a, sizeof a) > 0)
            n->account_id = strtoull(a, NULL, 10);
        npf_log("account %llu: session started", (unsigned long long)n->account_id);
        npf_mods_account(c, 1);             /* its mappings saved on the platform, its devices' nicks */
        npf_peers_retry_now(c->peers);      /* its devices let them in now */
        npf_account_info(c);
        npf_emit(c, "account", "{\"account_id\":\"%llu\"}", (unsigned long long)n->account_id);
    } else if (strcmp(type, "account_logout") == 0 || strcmp(type, "account_delete") == 0) {
        npf_log("account %llu: %s", (unsigned long long)n->account_id, type[8] == 'l' ? "logged out" : "deleted");
        npf_forget_account(c);
        npf_mods_account(c, 0);             /* the platform's mappings go */
    }
}

static void relay_done(npf_node *n, const npf_json *j, int ok, void *arg)
{
    relay *r = arg;
    (void)n;
    if (j && ok)
        relay_apply(r->c, r->type, j);
    if (r->cb) {
        if (j) {
            char *t = malloc(j->len + 1);
            if (t) {
                memcpy(t, j->s, j->len);
                t[j->len] = 0;
            }
            r->cb(r->user, ok, t ? t : "{}");
            free(t);
        } else {
            r->cb(r->user, 0, NULL);
        }
    }
    free(r);
}

int npf_plat_request(npf_t *c, const char *type, const char *data, int proof, npf_reply_cb cb, void *user, npf_out *err)
{
    char *buf = NULL;
    relay *r;
    int i, rc;
    for (i = 0; k_relay[i] && strcmp(k_relay[i], type) != 0; i++)
        ;
    if (!k_relay[i]) {
        npf_out_printf(err, "not a request an application may send\n");
        return NPF_EINVAL;
    }
    if (!c->node.online) {
        npf_out_printf(err, "not connected to the platform yet\n");
        return NPF_ESTATE;
    }
    if (data && *data && !json_object_ok(data)) {
        /* sent as it is inside the envelope: the server would drop the
         * whole signaling connection over it (and every request in flight) */
        npf_out_printf(err, "bad request data (not a JSON object)\n");
        return NPF_EINVAL;
    }
    if (proof && (!(buf = malloc(NPF_JSON_MAX_SIZE))
                  || add_key_proof(&c->node, data && *data ? data : "{}", buf, NPF_JSON_MAX_SIZE) < 0)) {
        free(buf);
        npf_out_printf(err, "bad request data\n");
        return NPF_EINVAL;
    }
    if (!(r = calloc(1, sizeof *r))) {
        free(buf);
        return NPF_ENOMEM;
    }
    r->c = c;
    r->cb = cb;
    r->user = user;
    snprintf(r->type, sizeof r->type, "%s", type);
    rc = npf_node_request(&c->node, type, proof ? buf : data && *data ? data : NULL, relay_done, r);
    if (buf) {
        npf_wipe(buf, NPF_JSON_MAX_SIZE);   /* passwords */
        free(buf);
    }
    if (rc < 0) {
        free(r);
        npf_out_printf(err, "cannot send the request\n");
        return NPF_ESTATE;
    }
    return NPF_OK;
}

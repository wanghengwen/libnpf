/* libnpf: requests to the platform (npf_request). Replies come back through
 * the caller's callback on the library thread. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"


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
    if (!l || !node_sig(n))
        return -1;
    npf_sign2(sig, n->id.sign_sk, "npf-client-key-v1", 17, npf_sig_hash(node_sig(n)), 64);
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

/* ---- the application's requests (npf_request) ---- */

typedef struct relay {
    npf_reply_cb cb;
    void        *user;
} relay;

static void relay_done(npf_node *n, const npf_env *e, int ok, void *arg)
{
    relay *r = arg;
    (void)n;
    if (r->cb) {
        if (e) {
            char *t = malloc(e->j->len + 1);
            if (t) {
                memcpy(t, e->j->s, e->j->len);
                t[e->j->len] = 0;
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
    int rc;
    /* any type the platform has (it takes from an application only its
     * platform requests: "app"); the reply's envelope holds 31 bytes */
    if (!*type || strlen(type) > 31) {
        npf_out_printf(err, "not a request type\n");
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
    r->cb = cb;
    r->user = user;
    rc = npf_node_app_request(&c->node, type, proof ? buf : data && *data ? data : NULL, relay_done, r);
    npf_wipe_free(buf, NPF_JSON_MAX_SIZE);  /* passwords */
    if (rc < 0) {
        free(r);
        npf_out_printf(err, "cannot send the request\n");
        return NPF_ESTATE;
    }
    return NPF_OK;
}

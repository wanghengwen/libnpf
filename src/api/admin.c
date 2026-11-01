/* libnpf: the node configured in a session by its admins (security.md D25;
 * signaling.md "隧道内控制消息" admin_*): the paired callers listed, members
 * unpaired, share codes made and revoked, resources published and removed.
 * Only a paired session (IK or PAKE) whose verified key is an admin's, and
 * only as remote_admin allows (on; members: no resources; off: nothing).
 * Roles, the password, hosted trust and the other settings stay local. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "npf/resources.h"
#include "../node/msgs.h"

#define ADMIN_PAGE 100                      /* members in one admin_get reply */

enum { RA_ON, RA_MEMBERS, RA_OFF };         /* remote_admin's values */

static npf_t *of_node(npf_node *node)
{
    return (npf_t *)(void *)((char *)node - offsetof(npf_t, node));
}

/* npf_pub_put / npf_pub_remove's result as the reply's error (NULL: done;
 * not saved yet is done, as for the local command) */
static const char *res_err(int rc)
{
    return rc == NPF_OK || rc == NPF_ESAVE ? NULL : rc == NPF_EINVAL ? "bad_request"
         : rc == NPF_EREADONLY ? "forbidden" : rc == NPF_ENOENT ? "not_found" : rc == NPF_EBUSY ? "rate_limited"
         : "internal_error";
}

static void members(npf_callee *d, const uint8_t self[32], int64_t offset, npf_out *o)
{
    int i;
    npf_out_kstr(o, "role", "admin");
    npf_out_jkey(o, "members");
    npf_out_jarr(o);
    for (i = (int)offset; i < d->npaired && i < offset + ADMIN_PAGE; i++) {
        npf_out_jobj(o);
        npf_out_kb64(o, "key", d->paired[i].pub, 32);
        npf_out_kint(o, "since", d->paired[i].added);
        npf_out_kstr(o, "role", npf_callee_is_admin(d, d->paired[i].pub) ? "admin" : "member");
        npf_out_kbool(o, "self", npf_ct_eq(d->paired[i].pub, self, 32) == 0);
        npf_out_jend(o);
    }
    npf_out_jend(o);
    npf_out_kint(o, "total", d->npaired);
    npf_out_jkey(o, "shares");              /* never their secrets */
    npf_out_jarr(o);
    for (i = 0; i < d->nshares; i++)
        if (d->shares[i].expires > (int64_t)time(NULL) && d->shares[i].uses > 0 && d->shares[i].fails < 5) {
            npf_out_jobj(o);
            npf_out_kstr(o, "locator", d->shares[i].id);
            npf_out_kint(o, "uses", d->shares[i].uses);
            npf_out_kint(o, "expires", d->shares[i].expires);
            npf_out_jend(o);
        }
    npf_out_jend(o);
}

static const char *share_err(int rc)
{
    return rc == -1 ? "rate_limited" : rc == -2 ? "forbidden" : rc == -3 ? "offline" : rc == -4 ? "no_owner"
         : "internal_error";
}

/* admin_share_new answered when the platform gave the locator */
typedef struct later {
    npf_t  *n;
    char    call[32], id[24];
    uint8_t pub[32];                        /* the admin that asked */
} later;

npf_call *npf_admin_session_again(npf_t *n, const char *call_id, const uint8_t pub[32])
{
    npf_call *c = npf_node_call(&n->node, call_id);
    return c && npf_callee_admin_session(n->callee, npf_call_auth(c), npf_call_peer_pub(c))
               && npf_ct_eq(npf_call_peer_pub(c), pub, 32) == 0 ? c : NULL;
}

static void share_made(void *arg, int rc, const char *code, const npf_share *v)
{
    later *l = arg;
    npf_call *c = npf_admin_session_again(l->n, l->call, l->pub);
    npf_out o = {.secret = 1};              /* the code: to this admin only, never in the log */
    char what[96] = "";
    npf_out_jobj(&o);
    if (rc == 0) {
        npf_out_kstr(&o, "code", code);
        npf_out_kstr(&o, "locator", v->id);
        npf_out_kint(&o, "uses", v->uses);
        npf_out_kint(&o, "expires", v->expires);
        snprintf(what, sizeof what, "share code %s made (%lld uses)%s", v->id, (long long)v->uses,
                 c ? "" : ", revoked: that admin's session ended first");
        if (!c)
            npf_callee_share_del(l->n->callee, v->id);  /* nobody has it */
    }
    npf_callee_admin_log(l->n->callee, l->pub, "admin_share_new", rc ? share_err(rc) : NULL, what);
    npf_out_jend(&o);
    if (c)
        npf_call_ctl_reply_to(c, "admin_share_new", l->id, rc ? "error" : "ok", rc ? share_err(rc) : NULL,
                              o.failed ? NULL : o.p);
    npf_out_free(&o);
    free(l);
}

/* the members' requests: unpair, share codes; LATER: the reply comes later */
static const char LATER[] = "";

static const char *member_op(npf_t *n, npf_call *c, const npf_env *e, const uint8_t pub[32], const void *msg,
                             char *what, size_t cap)
{
    npf_callee *d = n->callee;
    const m_admin_key *k = msg;
    unsigned long long fp;
    later *l;
    int rc;
    if (strcmp(e->type, "admin_share_new") == 0) {
        const m_admin_share_new *m = msg;
        if (!(l = calloc(1, sizeof *l)))
            return "internal_error";
        *l = (later){.n = n};
        memcpy(l->pub, pub, 32);
        snprintf(l->call, sizeof l->call, "%s", c ? npf_call_id(c) : "");
        snprintf(l->id, sizeof l->id, "%s", e->id);
        if ((rc = npf_callee_share_new(d, (int)m->uses, m->ttl_s, share_made, l)) < 0)
            free(l);
        return rc < 0 ? share_err(rc) : LATER;
    }
    if (strcmp(e->type, "admin_share_del") == 0) {
        const m_admin_share_del *m = msg;
        int gone = npf_callee_share_del(d, m->locator) != -1;
        snprintf(what, cap, "share code %s %s", m->locator, gone ? "revoked" : "unknown");
        return gone ? NULL : "not_found";
    }
    fp = (unsigned long long)npf_fp(k->key);    /* admin_unpair: its sessions end (the recheck) */
    if (npf_callee_is_admin(d, k->key)) {
        snprintf(what, cap, "%016llx is an admin: unpaired locally only", fp);
        return "forbidden";
    }
    rc = npf_callee_unpair_key(d, k->key) != -1;
    snprintf(what, cap, "%s %016llx", rc ? "unpaired" : "not paired:", fp);
    return rc ? NULL : "not_found";
}

static const char *admin_op(npf_t *n, npf_call *c, int auth, const uint8_t pub[32], const npf_env *e, npf_out *o,
                            char *what, size_t cap)
{
    npf_callee *d = n->callee;
    int mode = (int)npf_conf_int(&n->conf, "remote_admin"), rc;
    union { m_admin_get g; m_admin_key k; m_admin_share_new sn; m_admin_share_del sd; m_admin_res_put p; m_admin_res_del r; } u;
    static const struct { const char *type; const npf_msgdesc *md; } reqs[] = {
        {"admin_get", &m_admin_get_d}, {"admin_unpair", &m_admin_key_d},
        {"admin_share_new", &m_admin_share_new_d}, {"admin_share_del", &m_admin_share_del_d},
        {"admin_res_put", &m_admin_res_put_d}, {"admin_res_del", &m_admin_res_del_d},
    };
    const npf_msgdesc *md = NULL;
    char err[200];
    npf_res r;
    size_t i;
    npf_out_jobj(o);
    for (i = 0; i < sizeof reqs / sizeof reqs[0]; i++)
        if (strcmp(e->type, reqs[i].type) == 0)
            md = reqs[i].md;
    if (!md)
        return "unsupported_type";
    if (npf_msg_parse(md, e->j, e->data, &u, what, cap) < 0)
        return "bad_request";
    npf_callee_refresh(d);
    /* a paired key only: never a grant (the platform could make one), a
     * direct session or a hosted client */
    if ((auth != NPF_AUTH_IK && auth != NPF_AUTH_PAKE) || mode == RA_OFF || d->damaged) {
        snprintf(what, cap, "%s", mode == RA_OFF ? "remote_admin off" : d->damaged ? "the state is damaged"
                                                                                   : "not a paired session");
        return "forbidden";
    }
    if (!npf_callee_is_admin(d, pub)) {
        if (md == &m_admin_get_d) {
            npf_out_kstr(o, "role", "member");  /* members do not see each other */
            snprintf(what, cap, "a member: its role");
            return NULL;
        }
        snprintf(what, cap, "not an admin");
        return "forbidden";
    }
    if (md == &m_admin_get_d) {
        members(d, pub, u.g.offset, o);
        snprintf(what, cap, "the members from %lld", (long long)u.g.offset);
        return NULL;
    }
    if (md != &m_admin_res_put_d && md != &m_admin_res_del_d)
        return member_op(n, c, e, pub, &u, what, cap);
    if (mode == RA_MEMBERS) {
        snprintf(what, cap, "remote_admin members");
        return "forbidden";
    }
    if (md == &m_admin_res_put_d) {
        if (npf_res_obj(e->j, u.p.resource, &r, err, sizeof err) == 0) {
            r.persist = !no_saved_objects(n);
            rc = npf_pub_put(n, &r, err, sizeof err);
        } else {
            rc = NPF_EINVAL;
        }
    } else {
        rc = npf_pub_remove(n, u.r.name, err, sizeof err);
    }
    if (res_err(rc)) {
        npf_out_kstr(o, "message", err);
        snprintf(what, cap, "%s", err);
        return res_err(rc);
    }
    snprintf(what, cap, "resource %s %s", md == &m_admin_res_put_d ? r.name : u.r.name,
             md == &m_admin_res_put_d ? "published" : "deleted");
    return NULL;
}

/* each request, done or refused, one line in the log with the caller's
 * fingerprint (security.md 8.6); admin_share_new's when the code comes */
const char *npf_admin_do(npf_t *n, npf_call *c, int auth, const uint8_t pub[32], const npf_env *e, npf_out *o)
{
    char what[256] = "";
    const char *err = admin_op(n, c, auth, pub, e, o, what, sizeof what);
    if (err != LATER)
        npf_callee_admin_log(n->callee, pub, e->type, err, what);
    return err;
}

void npf_admin_control(npf_node *node, npf_call *c, const npf_json *j, void *arg)
{
    npf_out o = {.max = NPF_CTRL_MAX - 256, .secret = 1};      /* a share code */
    const char *err;
    m_env e;
    if (node_env(j, &e) < 0)
        return;
    if (strncmp(e.type, "admin_", 6) != 0) {
        npf_callee_control(node, c, j, arg);
        return;
    }
    err = npf_admin_do(of_node(node), c, npf_call_auth(c), npf_call_peer_pub(c), &e, &o);
    npf_out_jend(&o);
    if (err != LATER)
        npf_call_ctl_reply(c, e.type, j, err ? "error" : "ok", err, o.failed ? NULL : o.p);
    npf_out_free(&o);
}

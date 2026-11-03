/* libnpf: the node configured in a session by its admins (security.md D25;
 * signaling.md "隧道内控制消息" admin_*): the paired callers listed, members
 * unpaired, share codes made and revoked, resources published and removed,
 * the node's own peers and their -L forwards (remote-peers.md).
 * Only a paired session (IK or PAKE) whose verified key is an admin's, and
 * only as remote_admin allows (on; members: no resources, no peers; off: nothing).
 * Roles, the password, hosted trust and the other settings stay local. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "npf/peers.h"
#include "npf/resources.h"
#include "npf/text.h"
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

#ifndef NPF_NO_PEERS
/* ---- the node's own peers and forwards (remote-peers.md) ---- */

#define REMOTE_PEERS 8                      /* peers remote admins added, at most */
#define REMOTE_FWDS  8                      /* forwards they added, per peer */

/* who added p: an admin's fingerprint, "" here */
static const char *peer_by(npf_t *n, const npf_peer *p)
{
    npf_ldev *d = npf_peer_tag(p) == NPF_PERSIST ? npf_local_dev(&n->lc, npf_peer_name(p), 0) : NULL;
    return d ? d->by : "";
}

static void hostport(char *buf, size_t cap, const char *host, int port)
{
    int v6 = strchr(host, ':') != NULL;
    snprintf(buf, cap, "%s%s%s:%d", v6 ? "[" : "", host, v6 ? "]" : "", port);
}

#define PEER_ROOM 6000                      /* a peer with 16 forwards, at most, in the reply */

static void peers_ls(npf_t *n, npf_out *o)
{
    npf_peer *p;
    char buf[300];
    int i, more = 0;
    npf_out_jkey(o, "peers");
    npf_out_jarr(o);
    for (p = npf_peers_first(n->peers); p; p = npf_peer_next(p)) {
        if (npf_peer_tag(p) == NPF_PLATFORM)
            continue;                       /* a hosted client's mappings: the account's, not the node's */
        if (o->max && o->len + PEER_ROOM > o->max) {
            more = 1;                       /* the rest would not fit in the control message */
            break;
        }
        npf_out_jobj(o);
        npf_out_kint(o, "id", npf_peer_id(p));
        npf_out_kstr(o, "target", npf_peer_name(p));
        npf_out_kstr(o, "name", npf_peer_label(p));
        npf_out_kstr(o, "remote_name", npf_peer_remote_name(p));
        npf_out_kbool(o, "connected", npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTED);
        npf_out_kstr(o, "state", npf_peer_status(p, buf, sizeof buf));
        npf_out_kstr(o, "role", npf_peer_role(p));
        npf_out_kbool(o, "saved", npf_peer_tag(p) == NPF_PERSIST);
        npf_out_kstr(o, "by", peer_by(n, p));
        npf_out_jkey(o, "forwards");
        npf_out_jarr(o);
        for (i = 0; i < npf_peer_nfwd(p); i++) {
            npf_fwd_state st;
            if (npf_peer_forward_state(p, i, &st) < 0)
                continue;
            npf_out_jobj(o);
            npf_out_kint(o, "id", npf_peer_forward_id(p, i));
            npf_out_kstr(o, "spec", st.spec);
            if (st.opt == 'L') {
                hostport(buf, sizeof buf, st.bind, st.lport ? st.lport : st.port);
                npf_out_kstr(o, "listen", buf);
                hostport(buf, sizeof buf, st.host, st.hostport);
                npf_out_kstr(o, "target", buf);
                npf_out_kbool(o, "udp", st.udp);
            }
            npf_out_kbool(o, "up", st.state == NPF_FWD_UP);
            npf_out_kstr(o, "state", st.text);
            npf_out_kstr(o, "by", st.by);
            npf_out_jend(o);
        }
        npf_out_jend(o);
        npf_out_jend(o);
    }
    npf_out_jend(o);
    npf_out_kbool(o, "more", more);
}

static const char *peer_add(npf_t *n, const uint8_t pub[32], const m_admin_peer_add *m, npf_out *o, char *what,
                            size_t cap)
{
    char t[24], err[200];
    npf_peer_opt po;
    npf_ldev *d;
    npf_peer *p;
    uint32_t id = 0;
    int k, nby = 0, rc;
    snprintf(t, sizeof t, "%lld", (long long)m->number);
    if (!npf_number_parse(t) || (n->has_number && n->number == (uint64_t)m->number)) {
        snprintf(what, cap, "%s: not another device's number", t);
        return "bad_request";
    }
    if ((p = npf_peers_find(n->peers, t))) {
        npf_out_kint(o, "id", npf_peer_id(p));
        npf_out_kbool(o, "existing", 1);
        snprintf(what, cap, "peer %s: one already", t);
        return NULL;
    }
    /* a share code only: a password would put an admin of that device here */
    if (m->share[0] && npf_share_parse(m->share, NULL, NULL) != 0) {
        snprintf(what, cap, "peer %s: not a share code", t);
        return "bad_request";
    }
    d = npf_local_dev(&n->lc, t, 0);
    if (!m->share[0] && !(d && d->has_key)) {   /* paired here before: that pairing (remote-peers.md 4.2) */
        snprintf(what, cap, "peer %s: the node has not paired with it: its share code is needed", t);
        return "need_share";
    }
    for (k = 0; k < n->lc.ndev; k++)
        nby += n->lc.dev[k].save && n->lc.dev[k].by[0];
    if (nby >= REMOTE_PEERS) {
        snprintf(what, cap, "peer %s: %d added remotely already", t, nby);
        return "limit";
    }
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_NUMBER;
    po.number = (uint64_t)m->number;
    po.password = m->share[0] ? m->share : NULL;
    po.flags = NPF_PERSIST;
    po.name = m->name[0] ? m->name : NULL;
    rc = npf_peer_create(n, &po, &id, err, sizeof err);
    if (rc != NPF_OK && rc != NPF_ESAVE) {
        snprintf(what, cap, "peer %s: %s", t, err);
        return rc == NPF_EINVAL || rc == NPF_EEXIST ? "bad_request" : rc == NPF_EBUSY ? "limit"
             : rc == NPF_EUNAVAIL ? "unsupported_type" : "internal_error";
    }
    if ((d = npf_local_dev(&n->lc, t, 0))) {
        snprintf(d->by, sizeof d->by, "%016llx", (unsigned long long)npf_fp(pub));
        d->added = (int64_t)time(NULL);
        saved_rc(n);
    }
    npf_out_kint(o, "id", id);
    npf_out_kbool(o, "existing", 0);
    snprintf(what, cap, "peer %s added%s", t, m->share[0] ? " with a share code" : " (paired before)");
    return NULL;
}

/* host:port is one of the services (tcp) the peer published, as last heard */
static int published(const npf_peer *p, const char *host, uint16_t port)
{
    const char *json = npf_peer_resources(p);
    npf_jtok *tok;
    npf_res *r;
    npf_json j;
    char err[96], h[64];
    int k, c, yes = 0;
    uint16_t rp;
    if (!json)
        return 0;
    tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
    r = malloc(NPF_RES_MAX * sizeof *r);
    if (tok && r && npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) >= 0
        && (c = npf_res_parse(&j, 0, r, NPF_RES_MAX, err, sizeof err)) > 0)
        for (k = 0; k < c && !yes; k++)
            yes = strcmp(r[k].type, "tcp") == 0 && npf_hostport(r[k].target, h, sizeof h, &rp) == 0 && rp == port
                  && strcmp(h, host) == 0;
    free(tok);
    free(r);
    return yes;
}

static const char *fwd_add(npf_t *n, const uint8_t pub[32], const m_admin_fwd_add *m, npf_out *o, char *what,
                           size_t cap)
{
    npf_peer *p = peer_of(n, (uint32_t)m->id);
    char host[256], err[200], by[17], buf[300];
    npf_forward_opt fo;
    npf_forward_info fi;
    uint32_t fid = 0;
    uint16_t port;
    int i, nby = 0, rc;
    if (!p)
        return "not_found";
    if (npf_hostport(m->target, host, sizeof host, &port) < 0 || !port || (m->port && m->port < 1024)) {
        snprintf(what, cap, "bad target or port (1024-65535)");
        return "bad_request";
    }
    if (npf_peer_tag(p) != NPF_PERSIST) {
        snprintf(what, cap, "%s: not a saved peer", npf_peer_name(p));
        return "forbidden";
    }
    if (!published(p, host, port)) {
        snprintf(what, cap, "%s: %s is not a service it published", npf_peer_name(p), m->target);
        return "forbidden";
    }
    for (i = 0; i < npf_peer_nfwd(p); i++) {
        npf_fwd_state st;
        nby += npf_peer_forward_state(p, i, &st) == 0 && st.by[0];
    }
    if (nby >= REMOTE_FWDS) {
        snprintf(what, cap, "%s: %d forwards added remotely already", npf_peer_name(p), nby);
        return "limit";
    }
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    fo.listen.host = m->lan ? "*" : "127.0.0.1";    /* every address: LAN connections only (by) */
    fo.listen.port = (uint16_t)m->port;
    fo.target.host = host;
    fo.target.port = port;
    fo.flags = NPF_PERSIST;
    rc = npf_forward_create(n, npf_peer_id(p), &fo, &fid, err, sizeof err);
    if (rc != NPF_OK && rc != NPF_ESAVE) {
        snprintf(what, cap, "%s: %s", npf_peer_name(p), err);
        return rc == NPF_EFAIL ? "in_use" : rc == NPF_EBUSY ? "limit" : rc == NPF_EINVAL ? "bad_request"
             : "internal_error";
    }
    snprintf(by, sizeof by, "%016llx", (unsigned long long)npf_fp(pub));
    if (npf_peers_fwd_find(n->peers, (int)fid, &i) == p) {
        npf_peer_forward_set_by(p, i, by, (int64_t)time(NULL));
        npf_ops_record(n, p, 1, NULL);
    }
    npf_out_kint(o, "id", fid);
    if (npf_forward_get(n, fid, &fi) == NPF_OK) {
        hostport(buf, sizeof buf, fi.listen_host, fi.listen_port);
        npf_out_kstr(o, "listen", buf);     /* port 0: not listening yet (no session) */
    }
    snprintf(what, cap, "forward %u added: %s %s:%d -> %s %s", (unsigned)fid, m->lan ? "LAN" : "local", fo.listen.host,
             (int)fo.listen.port, npf_peer_name(p), m->target);
    return NULL;
}

/* admin_peer_*, admin_fwd_*: remote_admin on only; a refusal's reason in its message */
static const char *peer_req(npf_t *n, const uint8_t pub[32], const npf_env *e, const void *msg, npf_out *o, char *what,
                            size_t cap)
{
    const m_admin_id *m = msg;
    npf_peer *p;
    const char *res;
    int i;
    if (!n->peers || no_saved_objects(n)) {
        snprintf(what, cap, "no saved peers here");
        return "unsupported_type";
    }
    if (strcmp(e->type, "admin_peer_ls") == 0) {
        peers_ls(n, o);
        snprintf(what, cap, "the peers");
        return NULL;
    }
    if (strcmp(e->type, "admin_peer_add") == 0)
        return peer_add(n, pub, msg, o, what, cap);
    if (strcmp(e->type, "admin_fwd_add") == 0)
        return fwd_add(n, pub, msg, o, what, cap);
    if (strcmp(e->type, "admin_fwd_del") == 0) {
        npf_fwd_state st;
        if (!(p = npf_peers_fwd_find(n->peers, (int)m->id, &i)) || npf_peer_forward_state(p, i, &st) < 0)
            return "not_found";
        snprintf(what, cap, "forward %lld was added on the node: removed there only", (long long)m->id);
        if (!st.by[0])
            return "forbidden";
        npf_forward_remove(n, (uint32_t)m->id);
        snprintf(what, cap, "forward %lld removed: %s", (long long)m->id, st.spec);
        return NULL;
    }
    if (!(p = peer_of(n, (uint32_t)m->id)) || npf_peer_tag(p) == NPF_PLATFORM)
        return "not_found";
    if (strcmp(e->type, "admin_peer_res") == 0) {
        if (!(res = npf_peer_resources(p)))
            return "offline";               /* never heard */
        npf_out_jkey(o, "resources");
        npf_out_jraw(o, res);
        npf_out_kbool(o, "connected", npf_peer_state(p, NULL, NULL) == NPF_PEER_CONNECTED);
        snprintf(what, cap, "the resources of %s", npf_peer_name(p));
        return NULL;
    }
    snprintf(what, cap, "peer %s was added on the node: removed there only", npf_peer_name(p));    /* admin_peer_del */
    if (!peer_by(n, p)[0])
        return "forbidden";
    snprintf(what, cap, "peer %s removed", npf_peer_name(p));
    npf_peer_remove(n, (uint32_t)m->id);
    return NULL;
}

static const char *peer_op(npf_t *n, const uint8_t pub[32], const npf_env *e, const void *msg, npf_out *o, char *what,
                           size_t cap)
{
    const char *err = peer_req(n, pub, e, msg, o, what, cap);
    if (err && *what)
        npf_out_kstr(o, "message", what);
    return err;
}
#endif

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
    union {
        m_admin_get g; m_admin_key k; m_admin_share_new sn; m_admin_share_del sd; m_admin_res_put p; m_admin_res_del r;
        m_admin_id id; m_admin_peer_add pa; m_admin_fwd_add fa;
    } u;
    static const struct { const char *type; const npf_msgdesc *md; int peers; } reqs[] = {
        {"admin_get", &m_admin_get_d, 0}, {"admin_unpair", &m_admin_key_d, 0},
        {"admin_share_new", &m_admin_share_new_d, 0}, {"admin_share_del", &m_admin_share_del_d, 0},
        {"admin_res_put", &m_admin_res_put_d, 0}, {"admin_res_del", &m_admin_res_del_d, 0},
#ifndef NPF_NO_PEERS
        {"admin_peer_ls", &m_admin_get_d, 1}, {"admin_peer_add", &m_admin_peer_add_d, 1},
        {"admin_peer_del", &m_admin_id_d, 1}, {"admin_peer_res", &m_admin_id_d, 1},
        {"admin_fwd_add", &m_admin_fwd_add_d, 1}, {"admin_fwd_del", &m_admin_id_d, 1},
#endif
    };
    const npf_msgdesc *md = NULL;
    int peers = 0;
    char err[200];
    npf_res r;
    size_t i;
    npf_out_jobj(o);
    for (i = 0; i < sizeof reqs / sizeof reqs[0]; i++)
        if (strcmp(e->type, reqs[i].type) == 0) {
            md = reqs[i].md;
            peers = reqs[i].peers;
        }
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
        if (md == &m_admin_get_d && !peers) {
            npf_out_kstr(o, "role", "member");  /* members do not see each other */
            snprintf(what, cap, "a member: its role");
            return NULL;
        }
        snprintf(what, cap, "not an admin");
        return "forbidden";
    }
    if (md == &m_admin_get_d && !peers) {
        members(d, pub, u.g.offset, o);
        snprintf(what, cap, "the members from %lld", (long long)u.g.offset);
        return NULL;
    }
    if (md != &m_admin_res_put_d && md != &m_admin_res_del_d && !peers)
        return member_op(n, c, e, pub, &u, what, cap);
    if (mode == RA_MEMBERS) {
        snprintf(what, cap, "remote_admin members");
        return "forbidden";
    }
#ifndef NPF_NO_PEERS
    if (peers)
        return peer_op(n, pub, e, &u, o, what, cap);
#endif
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
    char what[768] = "";
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

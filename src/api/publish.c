/* Published resources (resources.h): this node's list (npf.conf "resource"
 * lines, fixed; local.json "resources", changed at run time), the
 * policy it makes, the "resources" event to each caller; the lists heard
 * from the nodes this one calls. */
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "npf/log.h"
#include "npf/resources.h"

/* the list as JSON must fit a control message with room to spare */
#define RES_JSON_MAX 12000

/* the sessions accepted here: a node's (the callee, once it has a number:
 * possibly since a moment, cfg.callable still from the start) and a direct
 * listener's */
int npf_pub_apply(npf_t *n)
{
    if (npf_res_rules(&n->policy, n->res, n->nres) < 0
        || (n->callee && npf_res_rules(&n->callee->policy, n->res, n->nres) < 0)) {
        npf_loge("resources: a target does not fit the policy table");
        return -1;
    }
    npf_node_reverse_recheck(&n->node);    /* a reverse resource taken back closes its listeners */
    return 0;
}

int npf_pub_res_text(const char *json, npf_res **out, char *err, size_t errcap)
{
    npf_jtok *tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
    npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
    npf_json j;
    int m = NPF_ENOMEM;
    err[0] = 0;
    if (tok && r && (npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) < 0
                     || (m = npf_res_parse(&j, 0, r, NPF_RES_MAX, err, errcap)) < 0))
        m = NPF_EFAIL;
    free(tok);
    if (m < 0) {
        free(r);
        r = NULL;
        if (!err[0])
            snprintf(err, errcap, "%s", m == NPF_ENOMEM ? "no memory" : "not valid JSON");
    }
    *out = r;
    return m;
}

int npf_pub_load(npf_t *n, char *err, size_t errcap)
{
    npf_res *r = NULL, *saved = NULL;
    const char *line;
    char e[200];
    int i, k, m = 0, nsaved = 0, rc = -1;
    if (npf_conf_get(&n->conf, "allow", NULL) || npf_conf_get(&n->conf, "allow_all", NULL))
        npf_logw("config: allow / allow_all are gone: what callers may reach is what this node publishes "
                 "(resource lines, the resource command)");
    if (!(r = malloc(NPF_RES_MAX * sizeof *r))) {
        snprintf(err, errcap, "no memory");
        return -1;
    }
    for (i = 0; (line = npf_conf_get_n(&n->conf, "resource", i)); i++) {
        if (m >= NPF_RES_MAX) {
            snprintf(err, errcap, "config: at most %d resources", NPF_RES_MAX);
            goto out;
        }
        if (npf_res_from_line(&r[m], line, e, sizeof e) < 0) {
            snprintf(err, errcap, "config: resource: %s", e);
            goto out;
        }
        for (k = 0; k < m; k++)
            if (strcmp(r[k].name, r[m].name) == 0) {
                snprintf(err, errcap, "config: two resources named %s", r[k].name);
                goto out;
            }
        m++;
    }
    /* those added at run time (checked when read): none left out without a
     * word, a resource missing here is a service its callers no longer reach */
    if (n->lc.resources && !(n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS)
        && (nsaved = npf_pub_res_text(n->lc.resources, &saved, e, sizeof e)) < 0) {
        snprintf(err, errcap, "resources of local.json: %s", e);
        npf_loge("%s", err);
        goto out;
    }
    for (i = 0; i < nsaved; i++) {
        for (k = 0; k < m && strcmp(r[k].name, saved[i].name) != 0; k++)
            ;
        if (k < m || m >= NPF_RES_MAX) {
            npf_logw("resources: %s of local.json left out (%s)", saved[i].name,
                     k < m ? "npf.conf has one of that name" : "too many");
            continue;
        }
        r[m] = saved[i];
        r[m++].persist = 1;
    }
    if (m) {                                /* the list's own size (most nodes publish none) */
        npf_res *fit = realloc(r, (size_t)m * sizeof *r);
        n->res = fit ? fit : r;
        r = NULL;
    }
    n->nres = m;
    if (npf_pub_apply(n) < 0)
        snprintf(err, errcap, "resources: too many targets");
    else
        rc = 0;
out:
    free(r);
    free(saved);
    return rc;
}

void npf_pub_free(npf_t *n)
{
    free(n->res);
    n->res = NULL;
    n->nres = 0;
}

/* the event's data: {"resources": [...]} */
static void pub_event(npf_t *n, npf_out *o)
{
    npf_out_printf(o, "{\"resources\":");
    npf_res_json(o, n->res, n->nres);
    npf_out_printf(o, "}");
}

void npf_pub_send(npf_t *n, npf_call *c)
{
    npf_out o = {0};
    pub_event(n, &o);
    if (!o.failed && npf_call_ctl_event(c, "resources", o.p) < 0)
        npf_logd("resources: not sent (the session is going)");
    npf_out_free(&o);
}

/* to every session this node accepted */
static void pub_push(npf_t *n)
{
    npf_call *c;
    for (c = npf_node_calls(&n->node); c; c = npf_call_next(c)) {
        npf_call_info i;
        npf_call_info_get(c, &i);
        if (!i.caller && i.state == NPF_CALL_ESTABLISHED)
            npf_pub_send(n, c);
    }
}

/* the ones of local.json (not npf.conf's) saved */
static int pub_save(npf_t *n)
{
    npf_res *r;
    npf_out o = {0};
    int i, m = 0;
    if (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS)
        return 0;                           /* local.json's list stays as it was */
    if (!(r = malloc((size_t)(n->nres ? n->nres : 1) * sizeof *r)))
        return -1;
    for (i = 0; i < n->nres; i++)
        if (!n->res[i].fixed && n->res[i].persist)
            r[m++] = n->res[i];
    if (m)
        npf_res_json(&o, r, m);
    free(r);
    if (o.failed) {
        npf_out_free(&o);
        return -1;
    }
    free(n->lc.resources);
    n->lc.resources = o.p;                  /* NULL: none */
    return npf_local_save(&n->lc);
}

/* The list becomes r (m of them, malloc'd: taken), if it fits the event and
 * the policy table (else the list stays as it was): the policy, the callers,
 * local.json. NPF_OK, NPF_ESAVE (in effect and told to the callers,
 * local.json not written yet), or an error */
static int pub_set(npf_t *n, npf_res *r, int m, char *err, size_t errcap)
{
    npf_res *old = n->res;
    int nold = n->nres;
    npf_out t = {0};
    npf_res_json(&t, r, m);
    if (t.failed || t.len > RES_JSON_MAX) {
        npf_out_free(&t);
        free(r);
        snprintf(err, errcap, "the list would be too long (descriptions take room)");
        return NPF_EINVAL;
    }
    npf_out_free(&t);
    n->res = r;
    n->nres = m;
    if (npf_pub_apply(n) < 0) {             /* the policies unchanged: the list stays as it was */
        n->res = old;
        n->nres = nold;
        free(r);
        snprintf(err, errcap, "too many targets for the policy table");
        return NPF_EFAIL;
    }
    free(old);
    pub_push(n);
    if (pub_save(n) < 0) {
        snprintf(err, errcap, "in effect now, but cannot write %s yet", n->lc.path);
        return NPF_ESAVE;
    }
    return NPF_OK;
}

/* the list now with room for one more */
static npf_res *pub_copy(const npf_t *n)
{
    npf_res *r = malloc((size_t)(n->nres + 1) * sizeof *r);
    if (r && n->nres)
        memcpy(r, n->res, (size_t)n->nres * sizeof *r);
    return r;
}

int npf_pub_put(npf_t *n, const npf_res *r, char *err, size_t errcap)
{
    npf_res *nw;
    int k, rc;
    for (k = 0; k < n->nres && strcmp(n->res[k].name, r->name) != 0; k++)
        ;
    if (k < n->nres && n->res[k].fixed) {
        snprintf(err, errcap, "%s: fixed (npf.conf): not changed here", r->name);
        return NPF_EREADONLY;
    }
    if (k == n->nres && n->nres >= NPF_RES_MAX) {
        snprintf(err, errcap, "at most %d resources", NPF_RES_MAX);
        return NPF_EBUSY;
    }
    if (r->persist && (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS)) {
        snprintf(err, errcap, "resources are not saved here (NPF_OPT_NO_SAVED_OBJECTS)");
        return NPF_EUNAVAIL;
    }
    if (!(nw = pub_copy(n))) {
        snprintf(err, errcap, "no memory");
        return NPF_ENOMEM;
    }
    nw[k] = *r;
    nw[k].fixed = 0;
    rc = pub_set(n, nw, k < n->nres ? n->nres : n->nres + 1, err, errcap);
    if (rc == NPF_OK || rc == NPF_ESAVE)
        npf_log("resource %s: %s%s%s %s%s", r->name, r->type, r->svc[0] ? "/" : "", r->svc, r->target, r->path);
    return rc;
}

int npf_pub_remove(npf_t *n, const char *name, char *err, size_t errcap)
{
    npf_res *nw;
    int i, m = 0, rc;
    for (i = 0; name && i < n->nres; i++)
        if (strcmp(n->res[i].name, name) == 0 && n->res[i].fixed) {
            snprintf(err, errcap, "%s: fixed (npf.conf): not changed here", name);
            return NPF_EREADONLY;
        }
    if (!(nw = pub_copy(n))) {
        snprintf(err, errcap, "no memory");
        return NPF_ENOMEM;
    }
    for (i = 0; i < n->nres; i++)           /* all but those going (name NULL: all but npf.conf's) */
        if (n->res[i].fixed || (name && strcmp(n->res[i].name, name) != 0))
            nw[m++] = n->res[i];
    if (m == n->nres) {
        free(nw);
        snprintf(err, errcap, "%s: %s", name ? name : "all", name ? "no such resource added here" : "nothing to delete");
        return NPF_ENOENT;
    }
    rc = pub_set(n, nw, m, err, errcap);
    if (rc == NPF_OK || rc == NPF_ESAVE)
        npf_log("resource %s deleted", name ? name : "all");
    return rc;
}

void npf_pub_heard(npf_t *n, npf_call *c, const npf_json *j, int d)
{
    npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
    npf_out o = {0};
    npf_peer *p;
    char e[200];
    int m;
    if (!r)
        return;
    m = npf_res_parse(j, npf_json_get(j, d, "resources"), r, NPF_RES_MAX, e, sizeof e);
    if (m < 0) {
        npf_logw("resources from the peer refused: %s", e);
        free(r);
        return;
    }
    npf_res_json(&o, r, m);
    free(r);
    if (o.failed) {
        npf_out_free(&o);
        return;
    }
    p = npf_peer_of_call(n, c);
    if (p && npf_peer_resources_same(p, o.p)) {
        npf_out_free(&o);                   /* the same list again: no log, no event */
        return;
    }
    if (p) {
        npf_peer_resources_set(p, o.p);
        npf_log("%s: %d resource%s published", npf_peer_name(p), m, m == 1 ? "" : "s");
    }
    if (n->cb.event) {
        npf_out ev = {0};
        npf_out_printf(&ev, "{\"session\":%u,\"resources\":%s}", (unsigned)npf_session_of(n, c), o.p);
        if (!ev.failed)
            n->cb.event(n->cb.user, "resources", ev.p);
        npf_out_free(&ev);
    }
    npf_out_free(&o);
}

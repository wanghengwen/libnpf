/* Published resources (resources.h): this node's list (npf.conf "resource"
 * lines, fixed; local.json "resources", changed by "npf resource"), the
 * policy it makes, the "resources" event to each caller; the lists heard
 * from the nodes this one calls. */
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
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

int npf_pub_load(npf_t *n, char *err, size_t errcap)
{
    const char *line;
    char e[200];
    int i, k;
    if (!n->res && !(n->res = calloc(NPF_RES_MAX, sizeof *n->res))) {
        snprintf(err, errcap, "no memory");
        return -1;
    }
    n->nres = 0;
    if (npf_conf_get(&n->conf, "allow", NULL) || npf_conf_get(&n->conf, "allow_all", NULL))
        npf_logw("config: allow / allow_all are gone: what callers may reach is what this node publishes "
                 "(resource lines, npf resource; npf help resource)");
    for (i = 0; (line = npf_conf_get_n(&n->conf, "resource", i)); i++) {
        if (n->nres >= NPF_RES_MAX) {
            snprintf(err, errcap, "config: at most %d resources", NPF_RES_MAX);
            return -1;
        }
        if (npf_res_from_line(&n->res[n->nres], line, e, sizeof e) < 0) {
            snprintf(err, errcap, "config: resource: %s", e);
            return -1;
        }
        for (k = 0; k < n->nres; k++)
            if (strcmp(n->res[k].name, n->res[n->nres].name) == 0) {
                snprintf(err, errcap, "config: two resources named %s", n->res[k].name);
                return -1;
            }
        n->nres++;
    }
    if (n->lc.resources) {                  /* those added at run time (already checked when read) */
        npf_jtok *tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
        npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
        npf_json j;
        int m = -1;
        if (tok && r && npf_json_parse(&j, n->lc.resources, strlen(n->lc.resources), tok, NPF_RES_JSON_TOK) == 0)
            m = npf_res_parse(&j, 0, r, NPF_RES_MAX, e, sizeof e);
        for (i = 0; i < m; i++) {
            for (k = 0; k < n->nres && strcmp(n->res[k].name, r[i].name) != 0; k++)
                ;
            if (k < n->nres || n->nres >= NPF_RES_MAX) {
                npf_logw("resources: %s of local.json left out (%s)", r[i].name,
                         k < n->nres ? "npf.conf has one of that name" : "too many");
                continue;
            }
            n->res[n->nres++] = r[i];
        }
        free(tok);
        free(r);
    }
    return npf_pub_apply(n) < 0 ? (snprintf(err, errcap, "resources: too many targets"), -1) : 0;
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

void npf_pub_json(npf_t *n, npf_out *o)
{
    npf_res_json(o, n->res, n->nres);
}

/* the ones of local.json (not npf.conf's) saved */
static int pub_save(npf_t *n)
{
    npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
    npf_out o = {0};
    int i, m = 0, rc;
    if (!r)
        return -1;
    for (i = 0; i < n->nres; i++)
        if (!n->res[i].fixed)
            r[m++] = n->res[i];
    free(n->lc.resources);
    n->lc.resources = NULL;
    if (m) {
        npf_res_json(&o, r, m);
        if (o.failed || !(n->lc.resources = malloc(o.len + 1))) {
            npf_out_free(&o);
            free(r);
            return -1;
        }
        memcpy(n->lc.resources, o.p, o.len);
        n->lc.resources[o.len] = 0;
    }
    npf_out_free(&o);
    free(r);
    rc = npf_local_save(&n->lc);
    return rc;
}

/* the list changed: policy, local.json, the callers */
static int pub_changed(npf_t *n, npf_out *o)
{
    if (npf_pub_apply(n) < 0) {
        npf_out_printf(o, "too many targets for the policy table\n");
        return 1;
    }
    if (pub_save(n) < 0) {
        npf_out_printf(o, "cannot write %s\n", n->local_path);
        return 1;
    }
    pub_push(n);
    return 0;
}

static void list_text(npf_out *o, const npf_res *r, int n, int mine)
{
    int i;
    if (!n) {
        npf_out_printf(o, mine ? "no resources: whoever connects here reaches nothing (npf resource add)\n"
                               : "no resources published\n");
        return;
    }
    for (i = 0; i < n; i++) {
        char ty[sizeof r[i].type + sizeof r[i].svc + 1];
        snprintf(ty, sizeof ty, "%s%s%s", r[i].type, r[i].svc[0] ? "/" : "", r[i].svc);
        npf_out_printf(o, "%-20s %-9s %s%s%s%s%s\n", r[i].name, ty, r[i].target, r[i].path,
                       r[i].desc[0] ? "  " : "", r[i].desc, r[i].fixed ? "  (fixed: npf.conf or --allow)" : "");
    }
}

/* npf resource [ls [NODE]] | add TYPE[/SERVICE] TARGET NAME [--desc TEXT] | del NAME|all */
int npf_cmd_resource(npf_t *n, int argc, char **argv, npf_out *o)
{
    const char *sub = argc > 1 ? argv[1] : "ls";
    char e[200];
    int i;
    if (strcmp(sub, "ls") == 0 && argc > 2) {          /* what a node we call published */
        char buf[300];
        const char *who = npf_peers_resolve(n->peers, argv[2], buf, sizeof buf), *json = NULL;
        npf_peer *p;
        npf_ldev *d;
        for (p = npf_peers_first(n->peers); p && strcmp(npf_peer_name(p), who) != 0; p = npf_peer_next(p))
            ;
        if (p)
            json = npf_peer_resources(p);
        else if ((d = npf_local_dev(&n->lc, who, 0)))
            json = d->resources;
        if (!json) {
            npf_out_printf(o, "%s: nothing heard yet (its resources come with a session)\n", argv[2]);
            return 1;
        }
        {
            npf_jtok *tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
            npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
            npf_json j;
            int m = -1;
            if (tok && r && npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) == 0)
                m = npf_res_parse(&j, 0, r, NPF_RES_MAX, e, sizeof e);
            if (m >= 0)
                list_text(o, r, m, 0);
            free(tok);
            free(r);
            return m < 0;
        }
    }
    if (strcmp(sub, "ls") == 0) {
        list_text(o, n->res, n->nres, 1);
        return 0;
    }
    if (strcmp(sub, "add") == 0) {
        npf_res r;
        npf_out t = {0};
        char line[600];
        size_t l;
        int a = 5, k;
        if (argc < 5) {
            npf_out_printf(o, "resource add TYPE[/SERVICE] TARGET NAME [--desc TEXT]\n");
            return 2;
        }
        /* the conf line's form: TYPE TARGET NAME | DESCRIPTION */
        l = (size_t)snprintf(line, sizeof line, "%s %s %s", argv[2], argv[3], argv[4]);
        for (; a < argc; a++) {
            if (strcmp(argv[a], "--desc") == 0 && a + 1 < argc && !strchr(argv[a + 1], '|')) {
                l += (size_t)snprintf(line + l, l < sizeof line ? sizeof line - l : 0, " | %s", argv[++a]);
            } else {
                npf_out_printf(o, "resource add TYPE[/SERVICE] TARGET NAME [--desc TEXT]: %s?\n", argv[a]);
                return 2;
            }
        }
        if (l >= sizeof line || strchr(argv[4], '|') || npf_res_from_line(&r, line, e, sizeof e) < 0) {
            npf_out_printf(o, "%s\n", l >= sizeof line ? "too long" : strchr(argv[4], '|') ? "no | in a name" : e);
            return 2;
        }
        r.fixed = 0;
        for (k = 0; k < n->nres && strcmp(n->res[k].name, r.name) != 0; k++)
            ;
        if (k < n->nres && n->res[k].fixed) {
            npf_out_printf(o, "%s: fixed (npf.conf or --allow): not changed here\n", r.name);
            return 2;
        }
        if (k == n->nres && n->nres >= NPF_RES_MAX) {
            npf_out_printf(o, "at most %d resources\n", NPF_RES_MAX);
            return 2;
        }
        {   /* the whole list must still fit the event */
            npf_res keep = k < n->nres ? n->res[k] : r;
            int had = n->nres;
            n->res[k] = r;
            if (k == n->nres)
                n->nres++;
            npf_res_json(&t, n->res, n->nres);
            if (t.failed || t.len > RES_JSON_MAX) {
                n->res[k] = keep;
                n->nres = had;
                npf_out_free(&t);
                npf_out_printf(o, "the list would be too long (descriptions take room)\n");
                return 2;
            }
            npf_out_free(&t);
        }
        if ((i = pub_changed(n, o)) != 0)
            return i;
        npf_log("resource %s: %s%s%s %s%s", r.name, r.type, r.svc[0] ? "/" : "", r.svc, r.target, r.path);
        npf_out_printf(o, "%s: published (%s%s%s %s%s)\n", r.name, r.type, r.svc[0] ? "/" : "", r.svc, r.target,
                       r.path);
        return 0;
    }
    if (strcmp(sub, "del") == 0 && argc > 2) {
        int all = strcmp(argv[2], "all") == 0, m = 0, gone = 0;
        for (i = 0; i < n->nres; i++) {
            if (!n->res[i].fixed && (all || strcmp(n->res[i].name, argv[2]) == 0)) {
                gone++;
                continue;
            }
            n->res[m++] = n->res[i];
        }
        if (!gone) {
            npf_out_printf(o, "%s: %s\n", argv[2], all ? "nothing to delete" : "no such resource added here");
            return 1;
        }
        n->nres = m;
        if ((i = pub_changed(n, o)) != 0)
            return i;
        npf_log("resource %s deleted", argv[2]);
        npf_out_printf(o, "%s: deleted\n", argv[2]);
        return 0;
    }
    npf_out_printf(o, "resource [ls [NODE]] | add TYPE[/SERVICE] TARGET NAME [--desc TEXT] | del NAME|all\n");
    return 2;
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
    for (p = npf_peers_first(n->peers); p && npf_peer_call(p) != c; p = npf_peer_next(p))
        ;
    if (p) {
        npf_peer_resources_set(p, o.p);
        npf_log("%s: %d resource%s published", npf_peer_name(p), m, m == 1 ? "" : "s");
    }
    {
        uint32_t id = npf_session_of(n, c);
        npf_emit(n, "resources", "{\"session\":%u,\"resources\":%s}", (unsigned)id, o.p);
    }
    npf_out_free(&o);
}

/* libnpf: the operations on published resources (npf_resource_put and the
 * rest): this node's put and removed, a peer's listed. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"
#include "npf/resources.h"
#include "ops_internal.h"
/* ---- resources ---- */

typedef struct rp_arg {
    npf_resource r;
    char        *err;
    size_t       errcap;
} rp_arg;

static const char *res_type_name(int t)
{
    switch (t) {
    case NPF_RES_TCP: return "tcp";
    case NPF_RES_UDP: return "udp";
    case NPF_RES_NET: return "net";
    case NPF_RES_SOCKS: return "socks";
    case NPF_RES_REVERSE: return "reverse";
    default: return NULL;
    }
}

static int res_type_code(const char *t)
{
    static const char *const names[] = {"", "tcp", "udp", "net", "socks", "reverse"};
    int i;
    for (i = 1; i < 6; i++)
        if (strcmp(names[i], t) == 0)
            return i;
    return 0;
}

static int res_put_run(npf_t *n, void *arg)
{
    rp_arg *x = arg;
    npf_resource *u = &x->r;
    npf_res r;
    const char *type = res_type_name(u->type);
    /* udp: one service (service.host), or "*" / networks as a rule */
    int service = u->type == NPF_RES_TCP || (u->type == NPF_RES_UDP && !(u->rule && *u->rule && !u->service.host)), l;
    memset(&r, 0, sizeof r);
    if (!type || !u->name || !*u->name || strlen(u->name) >= sizeof r.name || (u->flags & ~NPF_PERSIST)
        || (u->svc && strlen(u->svc) >= sizeof r.svc) || (u->desc && strlen(u->desc) >= sizeof r.desc)
        || (u->path && strlen(u->path) >= sizeof r.path)) {
        err_set(x->err, x->errcap, "%s", "bad type or flags, or a name, service, path or description too long");
        return NPF_EINVAL;
    }
    snprintf(r.type, sizeof r.type, "%s", type);
    snprintf(r.name, sizeof r.name, "%s", u->name);
    if (u->svc)
        snprintf(r.svc, sizeof r.svc, "%s", u->svc);
    if (u->desc)
        snprintf(r.desc, sizeof r.desc, "%s", u->desc);
    if (service) {
        const char *h = u->service.host;
        if (!h || !*h || !u->service.port) {
            err_set(x->err, x->errcap, "%s", "a service needs an address and a port");
            return NPF_EINVAL;
        }
        l = strchr(h, ':') ? snprintf(r.target, sizeof r.target, "[%s]:%u", h, (unsigned)u->service.port)
                           : snprintf(r.target, sizeof r.target, "%s:%u", h, (unsigned)u->service.port);
        if (l < 0 || (size_t)l >= sizeof r.target) {
            err_set(x->err, x->errcap, "%s", "the service's address is too long");
            return NPF_EINVAL;
        }
        if (u->path && *u->path && strcmp(u->path, "/") != 0)
            snprintf(r.path, sizeof r.path, "%s", u->path);
    } else {
        if (!u->rule || !*u->rule || strlen(u->rule) > 63) {
            err_set(x->err, x->errcap, "%s", "a rule of 1 to 63 bytes is needed");
            return NPF_EINVAL;
        }
        snprintf(r.target, sizeof r.target, "%s", u->rule);
    }
    if (npf_res_check(&r, x->err, x->errcap) < 0)
        return NPF_EINVAL;
    r.persist = (u->flags & NPF_PERSIST) != 0;
    return npf_pub_put(n, &r, x->err, x->errcap);
}

int npf_resource_put(npf_t *n, const npf_resource *r, char *err, size_t errcap)
{
    rp_arg x;
    if (err && errcap)
        err[0] = 0;
    memset(&x, 0, sizeof x);
    npf_resource_init(&x.r);
    if (copy_in(&x.r, sizeof x.r, r, offsetof(npf_resource, flags) + sizeof r->flags) < 0) {
        err_set(err, errcap, "%s", "not initialised (npf_resource_init)");
        return NPF_EINVAL;
    }
    x.err = err;
    x.errcap = errcap;
    return npf_api_op(n, res_put_run, &x);
}

static int res_remove_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    char err[200];
    return npf_pub_remove(n, x->a, err, sizeof err);
}

int npf_resource_remove(npf_t *n, const char *name)
{
    pid_arg x = {.a = name};
    if (!name || !*name)
        return NPF_EINVAL;
    return npf_api_op(n, res_remove_run, &x);
}

typedef struct rl_arg {
    uint32_t           peer;
    npf_resource_info *out;
    size_t             elem, cap, *count;
} rl_arg;

static void res_info(const npf_res *r, int saved, npf_resource_info *i)
{
    memset(i, 0, sizeof *i);
    i->size = sizeof *i;
    i->type = res_type_code(r->type);
    i->flags = (r->persist ? NPF_PERSIST : 0) | (r->fixed ? NPF_FIXED : 0);
    i->saved = r->persist && saved;
    snprintf(i->name, sizeof i->name, "%s", r->name);
    snprintf(i->svc, sizeof i->svc, "%s", r->svc);
    if (npf_res_is_service(r)) {
        const char *colon = strrchr(r->target, ':');
        if (colon) {
            if (r->target[0] == '[')
                snprintf(i->host, sizeof i->host, "%.*s", (int)(colon - r->target - 2), r->target + 1);
            else
                snprintf(i->host, sizeof i->host, "%.*s", (int)(colon - r->target), r->target);
            i->port = (uint16_t)atoi(colon + 1);
        }
    } else {
        snprintf(i->rule, sizeof i->rule, "%s", r->target);
    }
    snprintf(i->path, sizeof i->path, "%s", r->path);
    snprintf(i->desc, sizeof i->desc, "%s", r->desc);
}

static int res_list_run(npf_t *n, void *arg)
{
    rl_arg *x = arg;
    npf_resource_info i;
    int k;
    if (!x->peer) {
        for (k = 0; k < n->nres; k++) {
            if (*x->count < x->cap) {
                res_info(&n->res[k], !n->lc.unsaved, &i);
                put_elem(x->out, x->elem, *x->count, &i, sizeof i);
            }
            (*x->count)++;
        }
    } else {
        npf_peer *p = peer_of(n, x->peer);
        const char *json;
        npf_jtok *tok;
        npf_res *r;
        npf_json j;
        char e[160];
        int m = -1;
        if (!p)
            return NPF_ENOENT;
        if (!(json = npf_peer_resources(p)))
            return NPF_OK;
        tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
        r = malloc(NPF_RES_MAX * sizeof *r);
        if (tok && r && npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) == 0)
            m = npf_res_parse(&j, 0, r, NPF_RES_MAX, e, sizeof e);
        for (k = 0; k < m; k++) {
            if (*x->count < x->cap) {
                r[k].persist = 0;
                res_info(&r[k], 0, &i);
                i.flags = 0;
                put_elem(x->out, x->elem, *x->count, &i, sizeof i);
            }
            (*x->count)++;
        }
        free(tok);
        free(r);
    }
    return list_rc(*x->count, x->cap);
}

int npf_resource_list_size(npf_t *n, uint32_t peer, npf_resource_info *out, size_t elem_size, size_t cap,
                           size_t *count)
{
    rl_arg x = {.peer = peer, .out = out, .elem = elem_size, .cap = cap, .count = count};
    if (!count || (cap && !out) || elem_size < offsetof(npf_resource_info, desc) + sizeof out->desc)
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, res_list_run, &x);
}

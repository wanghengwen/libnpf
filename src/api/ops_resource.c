/* libnpf: the operations on published resources (npf_resource_put and the
 * rest): this node's put and removed, a peer's listed. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"
#include "npf/resources.h"
#include "npf/text.h"

/* npf.h's NPF_RES_TCP .. NPF_RES_REVERSE (1 .. 5) by their names in the resources */
static const char *const res_types[] = {NULL, "tcp", "udp", "net", "socks", "reverse"};

static const char *res_type_name(int t)
{
    return t > 0 && t < 6 ? res_types[t] : NULL;
}

static int res_type_code(const char *t)
{
    int i;
    for (i = 1; i < 6; i++)
        if (strcmp(res_types[i], t) == 0)
            return i;
    return 0;
}

static int res_put_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    const npf_resource *u = x->in;
    const char *type = res_type_name(u->type);
    /* udp: one service (service.host), or "*" / networks as a rule */
    int service = u->type == NPF_RES_TCP || (u->type == NPF_RES_UDP && !(u->rule && *u->rule && !u->service.host)), l;
    npf_res r;
    memset(&r, 0, sizeof r);
    if (!type || !u->name || !*u->name || strlen(u->name) >= sizeof r.name || (u->flags & ~NPF_PERSIST)
        || (u->svc && strlen(u->svc) >= sizeof r.svc) || (u->desc && strlen(u->desc) >= sizeof r.desc)
        || (u->path && strlen(u->path) >= sizeof r.path))
        return op_fail(x, NPF_EINVAL, "bad type or flags, or a name, service, path or description too long");
    snprintf(r.type, sizeof r.type, "%s", type);
    snprintf(r.name, sizeof r.name, "%s", u->name);
    snprintf(r.svc, sizeof r.svc, "%s", u->svc ? u->svc : "");
    snprintf(r.desc, sizeof r.desc, "%s", u->desc ? u->desc : "");
    if (service) {
        const char *h = u->service.host;
        if (!h || !*h || !u->service.port)
            return op_fail(x, NPF_EINVAL, "a service needs an address and a port");
        l = snprintf(r.target, sizeof r.target, strchr(h, ':') ? "[%s]:%u" : "%s:%u", h, (unsigned)u->service.port);
        if (l < 0 || (size_t)l >= sizeof r.target)
            return op_fail(x, NPF_EINVAL, "the service's address is too long");
        if (u->path && *u->path && strcmp(u->path, "/") != 0)
            snprintf(r.path, sizeof r.path, "%s", u->path);
    } else {
        if (!u->rule || !*u->rule || strlen(u->rule) >= sizeof r.target)
            return op_fail(x, NPF_EINVAL, "a rule of 1 to 63 bytes is needed");
        snprintf(r.target, sizeof r.target, "%s", u->rule);
    }
    if (npf_res_check(&r, x->err, x->errcap) < 0)
        return NPF_EINVAL;
    r.persist = (u->flags & NPF_PERSIST) != 0;
    return npf_pub_put(n, &r, x->err, x->errcap);
}

int npf_resource_put(npf_t *n, const npf_resource *r, char *err, size_t errcap)
{
    npf_resource res;
    op_arg x = {.in = &res, .err = err, .errcap = errcap};
    err_clear(err, errcap);
    npf_resource_init(&res);
    if (take_in(&res, sizeof res, r, SIZE_TO(npf_resource, flags)) < 0)
        return op_fail(&x, NPF_EINVAL, "not initialised (npf_resource_init)");
    return npf_api_op(n, res_put_run, &x);
}

static int res_remove_run(npf_t *n, void *arg)
{
    char err[200];
    return npf_pub_remove(n, arg, err, sizeof err);
}

int npf_resource_remove(npf_t *n, const char *name)
{
    if (!name || !*name)
        return NPF_EINVAL;
    return npf_api_op(n, res_remove_run, (void *)name);
}

static void res_info(const npf_res *r, int flags, int saved, npf_resource_info *i)
{
    memset(i, 0, sizeof *i);
    i->type = res_type_code(r->type);
    i->flags = flags;
    i->saved = saved;
    snprintf(i->name, sizeof i->name, "%s", r->name);
    snprintf(i->svc, sizeof i->svc, "%s", r->svc);
    if (npf_res_is_service(r))
        npf_hostport(r->target, i->host, sizeof i->host, &i->port);
    else
        snprintf(i->rule, sizeof i->rule, "%s", r->target);
    snprintf(i->path, sizeof i->path, "%s", r->path);
    snprintf(i->desc, sizeof i->desc, "%s", r->desc);
}

static int res_list_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_resource_info i;
    npf_peer *p;
    npf_res *r;
    const char *json;
    char e[160];
    int k, m;
    if (!x->id) {                           /* this node's */
        for (k = 0; k < n->nres; k++) {
            const npf_res *q = &n->res[k];
            res_info(q, (q->persist ? NPF_PERSIST : 0) | (q->fixed ? NPF_FIXED : 0), q->persist && !n->lc.unsaved, &i);
            list_put(x, &i, sizeof i);
        }
        return NPF_OK;
    }
    if (!(p = peer_of(n, x->id)))
        return NPF_ENOENT;
    if (!(json = npf_peer_resources(p)))
        return NPF_OK;
    if ((m = npf_pub_res_text(json, &r, e, sizeof e)) < 0) {   /* (checked when it came: no memory) */
        npf_loge("resources of %s: %s", npf_peer_name(p), e);
        return m;
    }
    for (k = 0; k < m; k++) {               /* the peer's, as last heard */
        res_info(&r[k], 0, 0, &i);
        list_put(x, &i, sizeof i);
    }
    free(r);
    return NPF_OK;
}

int npf_resource_list_size(npf_t *n, uint32_t peer, npf_resource_info *out, size_t size, size_t cap,
                           size_t *count)
{
    return op_list(n, res_list_run, peer, out, size, cap, count);
}

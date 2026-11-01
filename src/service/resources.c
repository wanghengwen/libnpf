/* Published resources (resources.h). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/resources.h"
#include "npf/text.h"

/* HOST:PORT with HOST an IPv4 address, [IPv6] or localhost: the address
 * part (brackets off) in host, the port in *port; 0 or -1 */
static int split_target(const char *t, char *host, size_t cap, int *port)
{
    uint8_t a[16];
    uint16_t p;
    if (npf_hostport(t, host, cap, &p) < 0 || !p)
        return -1;
    *port = p;
    if (t[0] == '[')
        return inet_pton(AF_INET6, host, a) == 1 ? 0 : -1;
    return strcmp(host, "localhost") == 0 || inet_pton(AF_INET, host, a) == 1 ? 0 : -1;
}

/* one service: tcp, or a udp resource of one HOST:PORT (a udp resource may
 * also be "*" or networks with ports, like net: data-channel.md 15) */
int npf_res_is_service(const npf_res *r)
{
    char host[64];
    int port;
    if (strcmp(r->type, "tcp") == 0)
        return 1;
    return strcmp(r->type, "udp") == 0 && split_target(r->target, host, sizeof host, &port) == 0;
}

int npf_res_is_web(const npf_res *r)
{
    return strcmp(r->type, "tcp") == 0 && (strcmp(r->svc, "http") == 0 || strcmp(r->svc, "https") == 0);
}

/* the types: the policy rules their targets become (npf_res_rules), the
 * targets' forms (a service's, tcp or udp HOST:PORT: split_target's) */
static const struct {
    const char *type, *form;
    int (*add)(npf_policy *p, const char *spec);
} k_types[] = {
    {"tcp", NULL, npf_policy_add},
    {"udp", "HOST:PORT, *, or ADDR[/PREFIX][:PORT[-PORT]]", npf_policy_add_udp},
    {"net", "lan, *, or ADDR[/PREFIX][:PORT[-PORT]]", npf_policy_add},
    {"socks", "lan, *, or ADDR[/PREFIX][:PORT[-PORT]]", npf_policy_add},
    {"reverse", "[lan:]* or [lan:]PORT[-PORT] (1024 to 65535)", npf_policy_add_reverse},
};
#define NTYPES ((int)(sizeof k_types / sizeof k_types[0]))

static int type_of(const npf_res *r)
{
    int k;
    for (k = 0; k < NTYPES && strcmp(r->type, k_types[k].type) != 0; k++)
        ;
    return k < NTYPES ? k : -1;
}

int npf_res_check(const npf_res *r, char *err, size_t errcap)
{
    char host[64];
    int port, k = type_of(r);
    npf_policy t;
    if (!r->name[0] || !npf_text_plain(r->name)) {
        snprintf(err, errcap, "a name of 1 to %d bytes without control characters", NPF_RES_NAME_MAX);
        return -1;
    }
    if (k < 0) {
        snprintf(err, errcap, "%s: the type is tcp, udp, net, socks or reverse (a web page: tcp/http)", r->name);
        return -1;
    }
    memset(&t, 0, sizeof t);
    if (npf_res_is_service(r)) {
        if (split_target(r->target, host, sizeof host, &port) < 0) {
            snprintf(err, errcap, "%s: a %s target is HOST:PORT, HOST an IP address ([v6]) or localhost", r->name,
                     r->type);
            return -1;
        }
    } else if (k_types[k].add(&t, r->target) < 0) {
        snprintf(err, errcap, "%s: a %s target is %s", r->name, r->type, k_types[k].form);
        return -1;
    }
    if (!npf_text_plain(r->desc)) {
        snprintf(err, errcap, "%s: a description of up to %d bytes without control characters", r->name,
                 NPF_RES_DESC_MAX);
        return -1;
    }
    if (r->path[0] && (r->path[0] != '/' || strpbrk(r->path, " \"<>\\") || !npf_text_plain(r->path))) {
        snprintf(err, errcap, "%s: the path starts with / (no spaces)", r->name);
        return -1;
    }
    if (r->svc[0]) {
        const char *s;
        for (s = r->svc; *s; s++)
            if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-'))
                break;
        if (*s || strlen(r->svc) > NPF_RES_SVC_MAX) {
            snprintf(err, errcap, "%s: a service is 1 to %d of a-z, 0-9 and -", r->name, NPF_RES_SVC_MAX);
            return -1;
        }
        if (!npf_res_is_service(r)) {
            snprintf(err, errcap, "%s: a service (TYPE/SERVICE) is for tcp and for udp of one HOST:PORT", r->name);
            return -1;
        }
    }
    if (r->path[0] && !npf_res_is_web(r)) {
        snprintf(err, errcap, "%s: a path is for web pages (tcp/http, tcp/https)", r->name);
        return -1;
    }
    return 0;
}

int npf_res_from_line(npf_res *r, const char *line, char *err, size_t errcap)
{
    char buf[600], *p, *bar, *tok, *save, *slash;
    memset(r, 0, sizeof *r);
    if (strlen(line) >= sizeof buf) {
        snprintf(err, errcap, "resource: too long");
        return -1;
    }
    strcpy(buf, line);
    if ((bar = strchr(buf, '|'))) {         /* the description */
        *bar = 0;
        for (p = bar + 1; *p == ' '; p++)
            ;
        snprintf(r->desc, sizeof r->desc, "%s", p);
        for (p = r->desc + strlen(r->desc); p > r->desc && p[-1] == ' ';)
            *--p = 0;
    }
    if ((tok = strtok_r(buf, " \t", &save)) && (slash = strchr(tok, '/'))) {     /* tcp/rdp */
        *slash = 0;
        if (!slash[1] || strlen(slash + 1) >= sizeof r->svc) {
            snprintf(err, errcap, "resource: TYPE/SERVICE, the service 1 to %d characters", NPF_RES_SVC_MAX);
            return -1;
        }
        strcpy(r->svc, slash + 1);
    }
    if (!tok || strlen(tok) >= sizeof r->type) {
        snprintf(err, errcap, "resource = TYPE[/SERVICE] TARGET NAME [| DESCRIPTION]");
        return -1;
    }
    strcpy(r->type, tok);
    if (!(tok = strtok_r(NULL, " \t", &save))) {
        snprintf(err, errcap, "resource = TYPE TARGET NAME [| DESCRIPTION]");
        return -1;
    }
    if (npf_res_is_web(r) && (slash = strchr(tok, '/'))) {
        snprintf(r->path, sizeof r->path, "%s", slash);
        *slash = 0;
    }
    snprintf(r->target, sizeof r->target, "%s", tok);
    if (!(p = strtok_r(NULL, "", &save))) {
        snprintf(err, errcap, "resource = TYPE TARGET NAME [| DESCRIPTION]: the name");
        return -1;
    }
    while (*p == ' ' || *p == '\t')
        p++;
    snprintf(r->name, sizeof r->name, "%s", p);
    for (p = r->name + strlen(r->name); p > r->name && (p[-1] == ' ' || p[-1] == '\t');)
        *--p = 0;
    r->fixed = 1;
    return npf_res_check(r, err, errcap);
}

int npf_res_obj(const npf_json *j, int e, npf_res *r, char *err, size_t errcap)
{
    memset(r, 0, sizeof *r);
    if (e < 0 || j->tok[e].type != NPF_JT_OBJECT || npf_json_get_str(j, e, "name", r->name, sizeof r->name) <= 0
        || npf_json_get_str(j, e, "target", r->target, sizeof r->target) <= 0) {
        snprintf(err, errcap, "a resource needs a name and a target");
        return -1;
    }
    if (npf_json_get(j, e, "type") < 0)
        strcpy(r->type, "tcp");
    else if (npf_json_get_str(j, e, "type", r->type, sizeof r->type) <= 0) {
        snprintf(err, errcap, "%s: the type is tcp, udp, net, socks or reverse (a web page: tcp/http)", r->name);
        return -1;
    }
    if ((npf_json_get(j, e, "desc") >= 0 && npf_json_get_str(j, e, "desc", r->desc, sizeof r->desc) < 0)
        || (npf_json_get(j, e, "path") >= 0 && npf_json_get_str(j, e, "path", r->path, sizeof r->path) < 0)
        || (npf_json_get(j, e, "svc") >= 0 && npf_json_get_str(j, e, "svc", r->svc, sizeof r->svc) <= 0)) {
        snprintf(err, errcap, "%s: a description of up to %d bytes, a path of up to %d, a service of up to %d",
                 r->name, NPF_RES_DESC_MAX, NPF_RES_PATH_MAX, NPF_RES_SVC_MAX);
        return -1;
    }
    return npf_res_check(r, err, errcap);
}

int npf_res_parse(const npf_json *j, int arr, npf_res *out, int max, char *err, size_t errcap)
{
    int i, k;
    if (arr < 0 || j->tok[arr].type != NPF_JT_ARRAY) {
        snprintf(err, errcap, "not a list of resources");
        return -1;
    }
    if (j->tok[arr].size > max) {
        snprintf(err, errcap, "at most %d resources", max);
        return -1;
    }
    for (i = 0; i < j->tok[arr].size; i++) {
        if (npf_res_obj(j, npf_json_item(j, arr, i), &out[i], err, errcap) < 0)
            return -1;
        for (k = 0; k < i; k++)
            if (strcmp(out[k].name, out[i].name) == 0) {
                snprintf(err, errcap, "%s: two resources of that name", out[i].name);
                return -1;
            }
    }
    return i;
}

static void kv(npf_out *o, const char *k, const char *v, int first)
{
    npf_out_printf(o, "%s\"%s\":", first ? "" : ",", k);
    npf_out_json_str(o, v, strlen(v));
}

void npf_res_json1(npf_out *o, const npf_res *r)
{
    npf_out_printf(o, "{");
    kv(o, "name", r->name, 1);
    kv(o, "target", r->target, 0);
    kv(o, "type", r->type, 0);
    if (r->svc[0])
        kv(o, "svc", r->svc, 0);
    if (r->desc[0])
        kv(o, "desc", r->desc, 0);
    if (r->path[0])
        kv(o, "path", r->path, 0);
    if (r->fixed)
        npf_out_printf(o, ",\"fixed\":true");
    npf_out_printf(o, "}");
}

void npf_res_json(npf_out *o, const npf_res *r, int n)
{
    int i;
    npf_out_printf(o, "[");
    for (i = 0; i < n; i++) {
        npf_out_printf(o, "%s", i ? "," : "");
        npf_res_json1(o, &r[i]);
    }
    npf_out_printf(o, "]");
}

int npf_res_rules(npf_policy *p, const npf_res *r, int n)
{
    npf_policy q = *p;                      /* made apart (what "lan" stands for kept): p whole or untouched */
    char host[64], spec[96];
    int i, k, port = 0;
    npf_policy_clear(&q);
    for (i = 0; i < n; i++) {
        const char *t = r[i].target;
        if ((k = type_of(&r[i])) < 0)
            return -1;
        /* a service's target (IPv4:PORT, [IPv6]:PORT) is a rule as it is
         * (checked again: never "*", "lan" or a network); localhost stands
         * for both loopback addresses */
        if (npf_res_is_service(&r[i]) && split_target(t, host, sizeof host, &port) < 0)
            return -1;
        if (npf_res_is_service(&r[i]) && strcmp(host, "localhost") == 0) {
            snprintf(spec, sizeof spec, "127.0.0.1:%d", port);
            if (k_types[k].add(&q, spec) < 0)
                return -1;
            snprintf(spec, sizeof spec, "[::1]:%d", port);
            t = spec;
        }
        if (k_types[k].add(&q, t) < 0)
            return -1;
    }
    *p = q;
    return 0;
}

char *npf_res_normalize(const char *json, size_t len)
{
    npf_jtok *tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
    npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
    npf_json j;
    npf_out o = {0};
    char err[160], *out = NULL;
    int n, e = ENOMEM;
    if (tok && r) {
        e = EINVAL;
        if (npf_json_parse(&j, json, len, tok, NPF_RES_JSON_TOK) == 0
            && (n = npf_res_parse(&j, 0, r, NPF_RES_MAX, err, sizeof err)) >= 0) {
            npf_res_json(&o, r, n);
            e = ENOMEM;
            if (!o.failed)
                out = o.p;                  /* the buffer, NUL-terminated, is the caller's now */
        }
    }
    if (!out) {
        npf_out_free(&o);
        errno = e;
    }
    free(tok);
    free(r);
    return out;
}

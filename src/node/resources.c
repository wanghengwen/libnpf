/* Published resources (resources.h). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/resources.h"

/* no control characters (UTF-8 itself the JSON parser checks) */
static int text_ok(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return 0;
    return 1;
}

/* HOST:PORT with HOST an IPv4 address, [IPv6] or localhost: the address
 * part (brackets off) in host, the port in *port; 0 or -1 */
static int split_target(const char *t, char *host, size_t cap, int *port)
{
    const char *colon;
    char *e;
    long p;
    uint8_t a[16];
    if (t[0] == '[') {
        const char *rb = strchr(t, ']');
        if (!rb || rb[1] != ':' || (size_t)(rb - t - 1) >= cap)
            return -1;
        memcpy(host, t + 1, (size_t)(rb - t - 1));
        host[rb - t - 1] = 0;
        if (inet_pton(AF_INET6, host, a) != 1)
            return -1;
        colon = rb + 1;
    } else {
        colon = strrchr(t, ':');
        if (!colon || (size_t)(colon - t) >= cap || colon == t)
            return -1;
        memcpy(host, t, (size_t)(colon - t));
        host[colon - t] = 0;
        if (strcmp(host, "localhost") != 0 && inet_pton(AF_INET, host, a) != 1)
            return -1;
    }
    if (!colon[1] || colon[1] == '0')
        return -1;
    p = strtol(colon + 1, &e, 10);
    if (*e || p < 1 || p > 65535)
        return -1;
    *port = (int)p;
    return 0;
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

int npf_res_check(const npf_res *r, char *err, size_t errcap)
{
    char host[64];
    int port;
    if (!r->name[0] || !text_ok(r->name)) {
        snprintf(err, errcap, "a name of 1 to %d bytes without control characters", NPF_RES_NAME_MAX);
        return -1;
    }
    if (npf_res_is_service(r)) {
        if (split_target(r->target, host, sizeof host, &port) < 0) {
            snprintf(err, errcap, "%s: a %s target is HOST:PORT, HOST an IP address ([v6]) or localhost", r->name,
                     r->type);
            return -1;
        }
    } else if (strcmp(r->type, "udp") == 0) {
        npf_policy t;
        memset(&t, 0, sizeof t);
        if (npf_policy_add_udp(&t, r->target) < 0) {
            snprintf(err, errcap, "%s: a udp target is HOST:PORT, *, or ADDR[/PREFIX][:PORT[-PORT]]", r->name);
            return -1;
        }
    } else if (strcmp(r->type, "net") == 0 || strcmp(r->type, "socks") == 0) {
        npf_policy t;
        memset(&t, 0, sizeof t);
        if (npf_policy_add(&t, r->target) < 0) {
            snprintf(err, errcap, "%s: a %s target is lan, *, or ADDR[/PREFIX][:PORT[-PORT]]", r->name, r->type);
            return -1;
        }
    } else if (strcmp(r->type, "reverse") == 0) {
        npf_policy t;
        memset(&t, 0, sizeof t);
        if (npf_policy_add_reverse(&t, r->target) < 0) {
            snprintf(err, errcap, "%s: a reverse target is [lan:]* or [lan:]PORT[-PORT] (1024 to 65535)", r->name);
            return -1;
        }
    } else {
        snprintf(err, errcap, "%s: the type is tcp, udp, net, socks or reverse (a web page: tcp/http)", r->name);
        return -1;
    }
    if (!text_ok(r->desc)) {
        snprintf(err, errcap, "%s: a description of up to %d bytes without control characters", r->name,
                 NPF_RES_DESC_MAX);
        return -1;
    }
    if (r->path[0] && (r->path[0] != '/' || strpbrk(r->path, " \"<>\\") || !text_ok(r->path))) {
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

int npf_res_parse(const npf_json *j, int arr, npf_res *out, int max, char *err, size_t errcap)
{
    int i, k, n = 0;
    if (arr < 0 || j->tok[arr].type != NPF_JT_ARRAY) {
        snprintf(err, errcap, "not a list of resources");
        return -1;
    }
    if (j->tok[arr].size > max) {
        snprintf(err, errcap, "at most %d resources", max);
        return -1;
    }
    for (i = 0; i < j->tok[arr].size; i++) {
        int e = npf_json_item(j, arr, i);
        npf_res *r = &out[n];
        memset(r, 0, sizeof *r);
        if (e < 0 || j->tok[e].type != NPF_JT_OBJECT || npf_json_get_str(j, e, "name", r->name, sizeof r->name) <= 0
            || npf_json_get_str(j, e, "target", r->target, sizeof r->target) <= 0) {
            snprintf(err, errcap, "resource %d: a name and a target", i + 1);
            return -1;
        }
        if (npf_json_get(j, e, "type") < 0)
            strcpy(r->type, "tcp");
        else if (npf_json_get_str(j, e, "type", r->type, sizeof r->type) <= 0) {
            snprintf(err, errcap, "%s: the type is tcp, udp, net, socks or reverse (a web page: tcp/http)", r->name);
            return -1;
        }
        if (strcmp(r->type, "http") == 0 || strcmp(r->type, "https") == 0) {
            /* saved before web pages were tcp/http (2026-10-16): local.json, an
             * older node's list */
            strcpy(r->svc, r->type);
            strcpy(r->type, "tcp");
        }
        if ((npf_json_get(j, e, "desc") >= 0 && npf_json_get_str(j, e, "desc", r->desc, sizeof r->desc) < 0)
            || (npf_json_get(j, e, "path") >= 0 && npf_json_get_str(j, e, "path", r->path, sizeof r->path) < 0)
            || (npf_json_get(j, e, "svc") >= 0 && npf_json_get_str(j, e, "svc", r->svc, sizeof r->svc) <= 0)) {
            snprintf(err, errcap, "%s: a description of up to %d bytes, a path of up to %d, a service of up to %d",
                     r->name, NPF_RES_DESC_MAX, NPF_RES_PATH_MAX, NPF_RES_SVC_MAX);
            return -1;
        }
        if (npf_res_check(r, err, errcap) < 0)
            return -1;
        for (k = 0; k < n; k++)
            if (strcmp(out[k].name, r->name) == 0) {
                snprintf(err, errcap, "%s: two resources of that name", r->name);
                return -1;
            }
        n++;
    }
    return n;
}

static void kv(npf_out *o, const char *k, const char *v, int first)
{
    npf_out_printf(o, "%s\"%s\":", first ? "" : ",", k);
    npf_out_json_str(o, v, strlen(v));
}

void npf_res_json(npf_out *o, const npf_res *r, int n)
{
    int i;
    npf_out_printf(o, "[");
    for (i = 0; i < n; i++) {
        npf_out_printf(o, "%s{", i ? "," : "");
        kv(o, "name", r[i].name, 1);
        kv(o, "target", r[i].target, 0);
        kv(o, "type", r[i].type, 0);
        if (r[i].svc[0])
            kv(o, "svc", r[i].svc, 0);
        if (r[i].desc[0])
            kv(o, "desc", r[i].desc, 0);
        if (r[i].path[0])
            kv(o, "path", r[i].path, 0);
        if (r[i].fixed)
            npf_out_printf(o, ",\"fixed\":true");
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]");
}

int npf_res_rules(npf_policy *p, const npf_res *r, int n)
{
    char host[64], spec[96];
    int i, port, udp;
    npf_policy_clear(p);
    for (i = 0; i < n; i++) {
        if (strcmp(r[i].type, "reverse") == 0) {
            if (npf_policy_add_reverse(p, r[i].target) < 0)
                return -1;
            continue;
        }
        if (!npf_res_is_service(&r[i])) {
            /* net, socks; udp of "*" or networks: rules of their own */
            if ((strcmp(r[i].type, "udp") == 0 ? npf_policy_add_udp(p, r[i].target) : npf_policy_add(p, r[i].target)) < 0)
                return -1;
            continue;
        }
        if (split_target(r[i].target, host, sizeof host, &port) < 0)
            return -1;
        udp = strcmp(r[i].type, "udp") == 0;    /* UDP rules of their own (data-channel.md 15) */
        if (strcmp(host, "localhost") == 0) {
            snprintf(spec, sizeof spec, "127.0.0.1:%d", port);
            if ((udp ? npf_policy_add_udp(p, spec) : npf_policy_add(p, spec)) < 0)
                return -1;
            snprintf(spec, sizeof spec, "[::1]:%d", port);
        } else if (strchr(host, ':')) {
            snprintf(spec, sizeof spec, "[%s]:%d", host, port);
        } else {
            snprintf(spec, sizeof spec, "%s:%d", host, port);
        }
        if ((udp ? npf_policy_add_udp(p, spec) : npf_policy_add(p, spec)) < 0)
            return -1;
    }
    return 0;
}

char *npf_res_normalize(const char *json, size_t len)
{
    npf_jtok *tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
    npf_res *r = malloc(NPF_RES_MAX * sizeof *r);
    npf_json j;
    npf_out o = {0};
    char err[160], *out = NULL;
    int n;
    if (tok && r && npf_json_parse(&j, json, len, tok, NPF_RES_JSON_TOK) == 0
        && (n = npf_res_parse(&j, 0, r, NPF_RES_MAX, err, sizeof err)) >= 0) {
        npf_res_json(&o, r, n);
        if (!o.failed && (out = malloc(o.len + 1))) {
            memcpy(out, o.p, o.len);
            out[o.len] = 0;
        }
    }
    npf_out_free(&o);
    free(tok);
    free(r);
    return out;
}

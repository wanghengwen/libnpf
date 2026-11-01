/* Published resources: what a node lets the peers that connect to it reach on
 * its side (data-channel.md 7, security.md D22). A target no resource covers
 * is refused. Types:
 *   tcp       one service, HOST:PORT (an IP address, [v6] or localhost)
 *   udp       HOST:PORT, "*" or ADDR[/PREFIX][:PORT[-PORT]]: the only type
 *             that lets UDP through
 *   net       "lan" (this host's addresses and its attached private
 *             networks), "*" or ADDR[/PREFIX][:PORT[-PORT]]; TCP only
 *   socks     the same, meant for a SOCKS5 proxy (-D); "*" is an exit node
 *   reverse   ports a caller may have this node listen on for -R: "*"
 *             (1024-65535), PORT or PORT-PORT, on loopback only; "lan:"
 *             before it: on every address
 * A tcp resource, or a udp one of one HOST:PORT, may name its service (svc:
 * http, https, rdp, ssh, ...) for the program that opens it; a web page
 * (tcp/http, tcp/https) may give the page to open (path). The node enforces
 * only the target. A node's list comes from npf.conf's "resource" lines
 * (fixed) and local.json; callers get it in each session (event
 * "resources"). Internal to libnpf; in include/npf because npf's modules
 * (cli_basic.c, apps.c) and app (files_main.c) read and check resource lists. */
#ifndef NPF_RESOURCES_H
#define NPF_RESOURCES_H

#include <stddef.h>

#include "npf/json.h"
#include "npf/tunnel.h"

#define NPF_RES_MAX      32
#define NPF_RES_NAME_MAX 64         /* bytes of UTF-8 */
#define NPF_RES_DESC_MAX 256
#define NPF_RES_PATH_MAX 128
#define NPF_RES_SVC_MAX  15
/* npf_jtok entries enough to parse a list of NPF_RES_MAX resources */
#define NPF_RES_JSON_TOK (4 + NPF_RES_MAX * 16)

typedef struct npf_res {
    char name[NPF_RES_NAME_MAX + 1];
    char target[64];                /* as the type takes it (above) */
    char type[8];                   /* "tcp", "udp", "net", "socks" or "reverse" */
    char svc[NPF_RES_SVC_MAX + 1];  /* the service ("http", "rdp"), "" none */
    char desc[NPF_RES_DESC_MAX + 1];
    char path[NPF_RES_PATH_MAX + 1]; /* a web page (tcp/http, tcp/https): the page to open, "" for "/" */
    int  fixed;                     /* from a "resource" line of the configuration: not changed at run time */
    int  persist;                   /* kept in local.json (NPF_PERSIST); never in the JSON */
} npf_res;

/* 1 for one service: tcp, or udp of one HOST:PORT. */
int  npf_res_is_service(const npf_res *r);
/* 1 for a web page: tcp/http or tcp/https. */
int  npf_res_is_web(const npf_res *r);
/* Parses and checks a "resource" line, TYPE[/SVC] TARGET NAME [| DESCRIPTION]
 * (a web page's target may carry the page: tcp/http 127.0.0.1:80/admin);
 * the result is fixed. 0, or -1 with err. */
int  npf_res_from_line(npf_res *r, const char *line, char *err, size_t errcap);

/* 0 when every field of r is valid, else -1 with the reason in err. */
int  npf_res_check(const npf_res *r, char *err, size_t errcap);
/* Reads the JSON array at token arr into out: each resource checked, names
 * unique, type "tcp" when missing; "fixed" is not read. The count, or -1 with
 * err (also for more than max). */
int  npf_res_parse(const npf_json *j, int arr, npf_res *out, int max, char *err, size_t errcap);
/* Writes n resources as a JSON array (fixed ones with "fixed": true). */
void npf_res_json(npf_out *o, const npf_res *r, int n);
/* Makes p allow what the resources cover, and nothing else; localhost
 * stands for 127.0.0.1 and ::1. 0, or -1 when one does not fit (p unchanged). */
int  npf_res_rules(npf_policy *p, const npf_res *r, int n);
/* A list checked and written again in the form local.json and the
 * "resources" event keep: malloc'd JSON text (free), or NULL with errno
 * EINVAL (not a valid list) or ENOMEM. */
char *npf_res_normalize(const char *json, size_t len);

#endif

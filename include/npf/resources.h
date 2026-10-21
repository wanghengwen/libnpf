/* Published resources: what a node lets the nodes and clients that connect to
 * it reach on its side (data-channel.md 7, security.md D22), and nothing
 * else: a target not covered by a resource is refused. A resource is a
 * name, a description and one of
 *   tcp               one service, HOST:PORT (an IP address, [v6] or
 *                     localhost)
 *   udp               one UDP service, HOST:PORT: the only kind that lets
 *                     UDP through (data-channel.md 15)
 *   net               addresses: "lan" (this host's addresses and directly
 *                     attached private networks), ADDR[/PREFIX][:PORT[-PORT]],
 *                     or "*"
 *   socks             the same, meant as a proxy (-D): "*" is an exit node
 *   reverse           callers may have this node listen on its loopback
 *                     address (-R) on these ports: "*" (1024-65535), PORT or
 *                     PORT-PORT. A caller's -R also needs its own target
 *                     published on its side (a service or net resource)
 * A tcp or udp resource may name the service it is (svc; written tcp/http):
 * http and https (a web page, with the page to open: path), rdp, ssh, vnc,
 * ... It is for those who open it (a browser for a web page, a remote
 * desktop for rdp); the node treats it as any other.
 * From npf.conf ("resource" lines: fixed) and local.json ("resources":
 * npf resource add|del). Each caller gets the list in the session's control
 * channel (event "resources") when the session comes up and whenever it
 * changes, and keeps the last one (status JSON, the web console). */
#ifndef NPF_RESOURCES_H
#define NPF_RESOURCES_H

#include <stddef.h>

#include "npf/json.h"
#include "npf/out.h"
#include "npf/tunnel.h"

#define NPF_RES_MAX      32
#define NPF_RES_NAME_MAX 64         /* bytes of UTF-8 */
#define NPF_RES_DESC_MAX 256
#define NPF_RES_PATH_MAX 128
#define NPF_RES_SVC_MAX  15
/* JSON tokens a list of NPF_RES_MAX takes: the array, each object and its
 * up to 7 keys with their values (name, target, type, svc, desc, path, fixed) */
#define NPF_RES_JSON_TOK (4 + NPF_RES_MAX * 16)

typedef struct npf_res {
    char name[NPF_RES_NAME_MAX + 1];
    char target[64];                /* service: HOST:PORT; net / socks: "lan", "*" or a rule */
    char type[8];                   /* "tcp", "udp", "net", "socks" or "reverse" */
    char svc[NPF_RES_SVC_MAX + 1];  /* tcp / udp: the service ("http", "rdp"), "" none */
    char desc[NPF_RES_DESC_MAX + 1];
    char path[NPF_RES_PATH_MAX + 1]; /* a web page (tcp/http, tcp/https): the page to open, "" for "/" */
    int  fixed;                     /* npf.conf or the command line: not changed at run time ("fixed": true) */
    int  persist;                   /* kept in local.json (NPF_PERSIST); not in its JSON */
} npf_res;

/* a service (tcp, udp) rather than addresses (net, socks) or ports (reverse) */
int  npf_res_is_service(const npf_res *r);
/* a web page: tcp/http or tcp/https */
int  npf_res_is_web(const npf_res *r);
/* an npf.conf "resource" line: TYPE[/SVC] TARGET NAME [| DESCRIPTION]; a
 * web page's target may carry the page: tcp/http 127.0.0.1:80/admin. 0, or
 * -1 with err */
int  npf_res_from_line(npf_res *r, const char *line, char *err, size_t errcap);

/* the fields of one resource checked: 0, or -1 with the reason in err */
int  npf_res_check(const npf_res *r, char *err, size_t errcap);
/* the array at token arr: at most max into out (each checked, the names
 * unique); the count, or -1 with err */
int  npf_res_parse(const npf_json *j, int arr, npf_res *out, int max, char *err, size_t errcap);
/* n resources as a JSON array */
void npf_res_json(npf_out *o, const npf_res *r, int n);
/* the policy of these resources (replacing what p allowed); localhost
 * stands for 127.0.0.1 and ::1. 0, or -1 when one does not fit */
int  npf_res_rules(npf_policy *p, const npf_res *r, int n);
/* JSON text of a list checked and written again (the form local.json and
 * the event keep); NULL when not a valid list. Freed by the caller */
char *npf_res_normalize(const char *json, size_t len);

#endif

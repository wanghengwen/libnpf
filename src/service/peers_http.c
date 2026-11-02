/* A web page's local forward: its first request's Host (security.md 8.8).
 *
 * A web site can make its own name resolve to 127.0.0.1 (DNS rebinding)
 * and have the browser read what a forward of a peer's web page serves
 * there, unauthenticated parts included. The browser sends that site's
 * name as the Host: so a forward of an http resource lets a connection in
 * only once its first request names an IP address (rebinding needs a
 * name), localhost or a *.localhost name (the console's r<hash>.localhost).
 * The head is read with MSG_PEEK: what was read goes on untouched.
 *
 * The first request only: a browser keeps a connection to the origin it
 * opened it for (plain http is never coalesced across names), so every
 * later request on it carries the same Host. */
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/json.h"
#include "npf/platform.h"
#include "npf/resources.h"
#include "npf/text.h"

#include "peers_internal.h"

#define HTTP_WAIT_MS  10000         /* for the first request (a browser's preconnect waits; it opens another) */
#define HTTP_POLL_MS  20            /* a head in parts: looked at again this often */

struct hwait {
    npf_peers *ps;
    int        fd, fid;
    uint64_t   cid;
    int64_t    until;
    npf_timer  t;                   /* the deadline, or the next look at a head in parts */
};

/* ---- the forward: one of the peer's http resources ---- */

static int same_host(const char *a, const char *b)
{
    if (strcmp(a, "localhost") == 0)
        a = "127.0.0.1";
    if (strcmp(b, "localhost") == 0)
        b = "127.0.0.1";
    return strcmp(a, b) == 0;
}

int peers_fwd_http(const pfwd *f)
{
    const char *json;
    npf_jtok *tok;
    npf_res *r;
    npf_json j;
    char err[96];
    int n, k, yes = 0;
    if (f->pub || f->socks || f->reverse || f->udp || f->kind || !(json = npf_peer_resources(f->p)))
        return 0;
    tok = malloc(NPF_RES_JSON_TOK * sizeof *tok);
    r = malloc(NPF_RES_MAX * sizeof *r);
    if (tok && r && npf_json_parse(&j, json, strlen(json), tok, NPF_RES_JSON_TOK) >= 0
        && (n = npf_res_parse(&j, 0, r, NPF_RES_MAX, err, sizeof err)) > 0)
        for (k = 0; k < n && !yes; k++) {
            char host[64];
            uint16_t port;
            yes = strcmp(r[k].type, "tcp") == 0 && strcmp(r[k].svc, "http") == 0
                  && npf_hostport(r[k].target, host, sizeof host, &port) == 0 && port == f->hostport
                  && same_host(host, f->host);
        }
    free(tok);
    free(r);
    return yes;
}

/* ---- the head ---- */

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int starts_ci(const char *s, size_t n, const char *w)
{
    size_t k, m = strlen(w);
    if (n < m)
        return 0;
    for (k = 0; k < m; k++)
        if (lower((unsigned char)s[k]) != w[k])
            return 0;
    return 1;
}

/* the Host's name (port and brackets off, lower case) is an address or localhost's */
static int host_ok(const char *v)
{
    char name[256];
    uint8_t a[16];
    size_t n = 0;
    const char *e;
    if (*v == '[') {
        if (!(e = strchr(v, ']')) || (size_t)(e - v - 1) >= sizeof name)
            return 0;
        memcpy(name, v + 1, (size_t)(e - v - 1));
        name[e - v - 1] = 0;
        return inet_pton(AF_INET6, name, a) == 1;
    }
    for (; v[n] && v[n] != ':' && n + 1 < sizeof name; n++)
        name[n] = (char)lower((unsigned char)v[n]);
    name[n] = 0;
    if (inet_pton(AF_INET, name, a) == 1 || strcmp(name, "localhost") == 0)
        return 1;
    return n > 10 && strcmp(name + n - 10, ".localhost") == 0;
}

int npf_http_host_ok(const char *b, size_t n, char *host, size_t hcap)
{
    const char *line = b, *end = b + n, *nl;
    int first = 1;
    host[0] = 0;
    while ((nl = memchr(line, '\n', (size_t)(end - line)))) {
        size_t len = (size_t)(nl - line);
        if (len && line[len - 1] == '\r')
            len--;
        if (first) {
            /* METHOD SP TARGET SP HTTP/1.x: else not a browser's request (it is let in) */
            if (len < 9 || !starts_ci(line + len - 8, 8, "http/1.") || !memchr(line, ' ', len))
                return 1;
            first = 0;
        } else if (!len) {
            return 1;                       /* the head's end, no Host: HTTP/1.0, not a browser's */
        } else if (starts_ci(line, len, "host:")) {
            const char *v = line + 5, *ve = line + len;
            while (v < ve && (*v == ' ' || *v == '\t'))
                v++;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
                ve--;
            snprintf(host, hcap, "%.*s", (int)(ve - v), v);
            return (size_t)(ve - v) < hcap && host_ok(host);
        }
        line = nl + 1;
    }
    if (first && n >= 16 && !memchr(b, ' ', n))
        return 1;                           /* 16 bytes, no space: no request line coming */
    return n >= HTTP_HEAD_MAX ? 0 : -1;     /* a head that big without a Host: refused */
}

/* ---- the waiting connections ---- */

static void hw_drop(struct hwait *w)
{
    npf_peers *ps = w->ps;
    int k;
    for (k = 0; k < ps->nhw; k++)
        if (ps->hw[k] == w) {
            ps->hw[k] = ps->hw[--ps->nhw];
            break;
        }
    npf_timer_cancel(ps->n->loop, &w->t);
    free(w);
}

static const char REFUSED[] =
    "HTTP/1.1 421 Misdirected Request\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 82\r\n\r\n"
    "npf: this forward answers to localhost and IP addresses only (not to this name).\r\n";

/* decided (1 in, 0 refused, -1 gone): the connection goes on or is closed */
static void hw_done(struct hwait *w, int in, const char *host)
{
    npf_peers *ps = w->ps;
    pfwd *f = peers_fwd_by_id(ps, w->fid);
    int fd = w->fd;
    uint64_t cid = w->cid;
    npf_loop_del(ps->n->loop, fd);
    hw_drop(w);
    if (in > 0 && f && f->used && f->fd >= 0 && f->p->st != PS_REMOVED) {
        peers_fwd_admitted(f, fd, cid);
        return;
    }
    if (in == 0) {
        char head[HTTP_HEAD_MAX], name[81];
        size_t k;
        for (k = 0; host[k] && k + 1 < sizeof name; k++)    /* the page's text: printable ASCII only in the log */
            name[k] = host[k] > ' ' && host[k] < 127 ? host[k] : '?';
        name[k] = 0;
        recv(fd, head, sizeof head, 0);    /* read (closed with it unread: a reset, the answer lost) */
        send(fd, REFUSED, sizeof REFUSED - 1, MSG_NOSIGNAL);
        npf_logw("%s: %s: a web page's request for %s refused (421: not localhost or an address; DNS rebinding?)",
                 f ? f->p->name : "?", f ? f->spec : "?", name[0] ? name : "(no Host in 8 KB)");
    }
    npf_sock_close(fd);
    peers_conn_gone(ps, cid, in == 0 ? "host" : "mapping_closed");
}

static void hw_look(struct hwait *w);

static void hw_timer(npf_loop *loop, void *arg)
{
    struct hwait *w = arg;
    (void)loop;
    if (npf_mono_ms() >= w->until)
        hw_done(w, -1, "");
    else
        hw_look(w);
}

static void hw_read(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    (void)loop;
    (void)fd;
    (void)ev;
    hw_look(arg);
}

/* what came so far: decided, or looked at again (the socket stays readable
 * while its bytes are unread: not watched until then) */
static void hw_look(struct hwait *w)
{
    char b[HTTP_HEAD_MAX], host[256];
    npf_loop *loop = w->ps->n->loop;
    int64_t left = w->until - npf_mono_ms();
    int r = (int)recv(w->fd, b, sizeof b, MSG_PEEK), v;
    if (r < 0 && npf_sock_again()) {
        npf_loop_mod(loop, w->fd, NPF_EV_READ);
        npf_timer_set(loop, &w->t, left);
        return;
    }
    if (r <= 0) {                           /* closed, or failed */
        hw_done(w, -1, "");
        return;
    }
    if ((v = npf_http_host_ok(b, (size_t)r, host, sizeof host)) >= 0) {
        hw_done(w, v, host);
        return;
    }
    npf_loop_mod(loop, w->fd, 0);
    npf_timer_set(loop, &w->t, left < HTTP_POLL_MS ? left : HTTP_POLL_MS);
}

void peers_http_wait(pfwd *f, int fd, uint64_t cid)
{
    npf_peers *ps = f->p->ps;
    struct hwait *w = NULL;
    if (ps->nhw < HTTP_WAITING && (w = calloc(1, sizeof *w))) {
        *w = (struct hwait){.ps = ps, .fd = fd, .fid = f->id, .cid = cid, .until = npf_mono_ms() + HTTP_WAIT_MS};
        npf_timer_init(&w->t, hw_timer, w);
        npf_set_nonblock(fd);
        if (npf_loop_add(ps->n->loop, fd, NPF_EV_READ, hw_read, w) == 0
            && npf_timer_set(ps->n->loop, &w->t, HTTP_WAIT_MS) == 0) {
            ps->hw[ps->nhw++] = w;
            return;
        }
        npf_loop_del(ps->n->loop, fd);
        free(w);
    }
    npf_sock_close(fd);
    npf_logw("%s: %s: too many web connections waiting for their first request, refused", f->p->name, f->spec);
    peers_conn_gone(ps, cid, "no_session");
}

void peers_http_drop(npf_peers *ps, int fid, const char *why)
{
    int k = ps->nhw;
    while (k-- > 0)                     /* hw_drop moves the last one into k: those above are done */
        if (k < ps->nhw && ps->hw[k]->fid == fid) {
            struct hwait *w = ps->hw[k];
            uint64_t cid = w->cid;
            npf_loop_del(ps->n->loop, w->fd);
            npf_sock_close(w->fd);
            hw_drop(w);
            peers_conn_gone(ps, cid, why);
        }
}

void peers_http_free(npf_peers *ps)
{
    while (ps->nhw) {
        struct hwait *w = ps->hw[ps->nhw - 1];
        npf_loop_del(ps->n->loop, w->fd);
        npf_sock_close(w->fd);
        hw_drop(w);
    }
}

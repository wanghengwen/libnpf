/* local.json (local.h). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/local.h"
#include "npf/resources.h"
#include "npf/out.h"
#include "npf/platform.h"
#include "npf/text.h"

#include "msgs.h"

#define MAX_TOK 32768

int npf_name_valid(const char *s)
{
    size_t i, n = strlen(s);
    int digits = 1;
    if (n == 0 || n > 32 || strcmp(s, "all") == 0)
        return 0;
    for (i = 0; i < n; i++) {
        char ch = s[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_'
              || ch == '-'))
            return 0;
        if (ch < '0' || ch > '9')
            digits = 0;
    }
    return !digits;                         /* all digits would read as a number */
}

int npf_nick_valid(const char *s)
{
    return strlen(s) <= NPF_NICK_MAX && npf_text_plain(s);
}

npf_ldev *npf_local_dev(npf_local *l, const char *target, int create)
{
    int i;
    for (i = 0; i < l->ndev; i++)
        if (strcmp(l->dev[i].target, target) == 0)
            return &l->dev[i];
    if (!create || l->ndev >= NPF_LOCAL_MAX_DEV || strlen(target) >= sizeof l->dev[0].target)
        return NULL;
    if (npf_grow(&l->dev, &l->cap, (size_t)l->ndev + 1, sizeof *l->dev, 4) < 0)
        return NULL;
    memset(&l->dev[l->ndev], 0, sizeof l->dev[0]);
    snprintf(l->dev[l->ndev].target, sizeof l->dev[0].target, "%s", target);
    return &l->dev[l->ndev++];
}

npf_ldev *npf_local_by_name(npf_local *l, const char *name)
{
    int i;
    for (i = 0; i < l->ndev; i++)
        if (l->dev[i].name[0] && strcmp(l->dev[i].name, name) == 0)
            return &l->dev[i];
    return NULL;
}

/* ---- the modules' keys ---- */

static void ext_clear(npf_ldev *d)
{
    int i;
    for (i = 0; i < d->next; i++) {
        free(d->ext[i].key);
        free(d->ext[i].val);
    }
    free(d->ext);
    d->ext = NULL;
    d->next = 0;
}

static void dev_free(npf_ldev *d)
{
    npf_local_fwd_clear(d);
    free(d->resources);
    ext_clear(d);
}

int npf_local_drop(npf_local *l, const char *target)
{
    npf_ldev *d = npf_local_dev(l, target, 0);
    if (!d)
        return -1;
    dev_free(d);
    memmove(d, d + 1, (size_t)(l->ndev - (d - l->dev) - 1) * sizeof *d);
    l->ndev--;
    return 0;
}

static int ext_find(const npf_ldev *d, const char *key)
{
    int i;
    for (i = 0; i < d->next; i++)
        if (strcmp(d->ext[i].key, key) == 0)
            return i;
    return -1;
}

const char *npf_local_ext(const npf_ldev *d, const char *key)
{
    int i = ext_find(d, key);
    return i < 0 ? NULL : d->ext[i].val;
}

/* key's value: (a copy of) the JSON text json[0..n) */
static int ext_put(npf_ldev *d, const char *key, const char *json, size_t n)
{
    struct npf_lext *e;
    int i = ext_find(d, key);
    char *v = malloc(n + 1);
    if (!v)
        return -1;
    memcpy(v, json, n);
    v[n] = 0;
    if (i >= 0) {
        free(d->ext[i].val);
        d->ext[i].val = v;
        return 0;
    }
    if (d->next >= NPF_LOCAL_MAX_EXT || !(e = realloc(d->ext, (size_t)(d->next + 1) * sizeof *e))) {
        free(v);
        return -1;
    }
    d->ext = e;
    if (!(e[d->next].key = strdup(key))) {
        free(v);
        return -1;
    }
    e[d->next++].val = v;
    return 0;
}

int npf_local_ext_set(npf_ldev *d, const char *key, const char *json)
{
    int i;
    if (json)
        return ext_put(d, key, json, strlen(json));
    if ((i = ext_find(d, key)) >= 0) {      /* removed */
        free(d->ext[i].key);
        free(d->ext[i].val);
        d->next--;
        memmove(&d->ext[i], &d->ext[i + 1], (size_t)(d->next - i) * sizeof *d->ext);
    }
    return 0;
}

static int fwd_same(const npf_lfwd *a, const npf_lfwd *b)
{
    if (a->opt != b->opt)
        return 0;
    if (a->opt != 'L' && a->opt != 'D' && a->opt != 'R')
        return strcmp(a->spec, b->spec) == 0;
    return a->udp == b->udp && a->port == b->port && a->hostport == b->hostport && strcmp(a->bind, b->bind) == 0
        && strcmp(a->host, b->host) == 0;
}

/* one forward "-L SPEC" more, unless it is there */
int npf_local_fwd_add(npf_ldev *d, const npf_lfwd *f)
{
    npf_lfwd *a;
    int i;
    for (i = 0; i < d->nfwd; i++)
        if (fwd_same(&d->fwd[i], f))
            return 0;
    if (d->nfwd >= NPF_LOCAL_MAX_FWD || !(a = realloc(d->fwd, (size_t)(d->nfwd + 1) * sizeof *a)))
        return -1;
    d->fwd = a;
    d->fwd[d->nfwd++] = *f;
    return 0;
}

void npf_local_fwd_clear(npf_ldev *d)
{
    free(d->fwd);
    d->fwd = NULL;
    d->nfwd = 0;
}

int npf_local_fwd_del(npf_ldev *d, const npf_lfwd *f)
{
    int i;
    for (i = 0; i < d->nfwd; i++)
        if (fwd_same(&d->fwd[i], f)) {
            memmove(&d->fwd[i], &d->fwd[i + 1], (size_t)(d->nfwd - i - 1) * sizeof d->fwd[0]);
            d->nfwd--;
            return 0;
        }
    return -1;
}

/* a device's record at token v of j over s (m: room to read it into): 0,
 * -1 out of memory */
static int device(npf_local *l, const char *s, const npf_json *j, int v, const char *target, m_device *m)
{
    npf_ldev *d;
    int i, q, rc = 0;
    if (npf_msg_parse(&m_device_d, j, v, m, NULL, 0) < 0 || !(d = npf_local_dev(l, target, 1)))
        return 0;                           /* not an object: not carried over */
    if (npf_name_valid(m->name))
        snprintf(d->name, sizeof d->name, "%s", m->name);
    snprintf(d->nick, sizeof d->nick, "%s", m->nick);
    d->save = m->save;
    d->on_demand = strcmp(m->connect, "on_demand") == 0;
    d->idle_ms = (int)m->idle_ms;
    snprintf(d->psk_file, sizeof d->psk_file, "%s", m->psk_file);
    snprintf(d->psk, sizeof d->psk, "%s", m->psk);
    for (i = 0; i < m->nforwards && rc == 0; i++) {
        const m_forward *f = &m->forwards[i];
        npf_lfwd lf = {0};
        lf.opt = strcmp(f->kind, "local") == 0 ? 'L' : strcmp(f->kind, "socks") == 0 ? 'D'
               : strcmp(f->kind, "remote") == 0 ? 'R' : f->kind[0] >= 'A' && f->kind[0] <= 'Z' && !f->kind[1] ? f->kind[0] : 0;
        lf.udp = strcmp(f->proto, "udp") == 0;
        snprintf(lf.bind, sizeof lf.bind, "%s", f->listen);
        snprintf(lf.host, sizeof lf.host, "%s", f->host);
        snprintf(lf.spec, sizeof lf.spec, "%s", f->spec);
        lf.port = (int)f->port;
        lf.hostport = (int)f->hostport;
        if (lf.opt)                         /* else an earlier version's: not carried over */
            rc = npf_local_fwd_add(d, &lf);
    }
    if ((d->has_key = m->key_len == 32))
        memcpy(d->key, m->key, 32);
    if (m->resources >= 0)
        d->resources = npf_res_normalize(s + j->tok[m->resources].start,
                                         j->tok[m->resources].end - j->tok[m->resources].start);
    for (i = 0, q = v + 1; i < j->tok[v].size && rc == 0; i++, q = j->tok[q + 1].next) {
        /* the keys not in the table are the modules': kept as they are (a string's text with its quotes) */
        char key[48];
        int k, str = j->tok[q + 1].type == NPF_JT_STRING;
        size_t vs = j->tok[q + 1].start - (str ? 1 : 0), vl = j->tok[q + 1].end + (str ? 1 : 0) - vs;
        if (npf_json_str(j, q, key, sizeof key) < 0)
            continue;
        for (k = 0; k < m_device_d.nf && strcmp(key, m_device_d.f[k].key) != 0; k++)
            ;
        if (k == m_device_d.nf)
            rc = ext_put(d, key, s + vs, vl);
    }
    npf_msg_wipe(&m_device_d, m);
    return rc;
}

static int parse(npf_local *l, const char *s, size_t len)
{
    /* a token takes 2 bytes of the text at least ("1," ...): no 512 KB for a
     * file of a few hundred tokens */
    int cap = len / 2 + 8 < MAX_TOK ? (int)(len / 2 + 8) : MAX_TOK;
    npf_jtok *tok = malloc((size_t)cap * sizeof *tok);
    m_device *m = malloc(sizeof *m);
    npf_json j;
    int t, i, rc = -1;
    if (!tok || !m)
        goto out;
    if (npf_json_parse_file(&j, s, len, tok, cap) < 0 || j.tok[0].type != NPF_JT_OBJECT)
        goto out;
    if ((t = npf_json_get(&j, 0, "settings")) >= 0 && j.tok[t].type == NPF_JT_OBJECT) {
        int k = t + 1;
        for (i = 0; i < j.tok[t].size; i++, k = j.tok[k + 1].next) {
            char key[48], val[512];
            if (npf_json_str(&j, k, key, sizeof key) >= 0 && npf_json_str(&j, k + 1, val, sizeof val) >= 0)
                npf_conf_set_rel(&l->settings, l->path, key, val);
        }
    }
    if ((t = npf_json_get(&j, 0, "start")) >= 0 && j.tok[t].type == NPF_JT_ARRAY)
        for (i = 0; i < j.tok[t].size && l->nstart < NPF_LOCAL_MAX_START; i++) {
            char opt[1024];
            if (npf_json_str(&j, npf_json_item(&j, t, i), opt, sizeof opt) >= 0 && npf_local_start_add(l, opt) < 0)
                goto out;
        }
    if ((t = npf_json_get(&j, 0, "devices")) >= 0 && j.tok[t].type == NPF_JT_OBJECT) {
        int k = t + 1;
        for (i = 0; i < j.tok[t].size; i++, k = j.tok[k + 1].next) {
            char target[300];
            if (npf_json_str(&j, k, target, sizeof target) >= 0 && device(l, s, &j, k + 1, target, m) < 0)
                goto out;
        }
    }
    if ((t = npf_json_get(&j, 0, "resources")) >= 0) {
        if (j.tok[t].type != NPF_JT_ARRAY || !(l->resources = npf_res_normalize(s + j.tok[t].start,
                                                                                j.tok[t].end - j.tok[t].start)))
            goto out;                       /* ours, written by us: not to be lost by a silent drop */
    }
    rc = 0;
out:
    free(tok);
    if (m)
        npf_msg_wipe(&m_device_d, m);       /* the last record's psk, on every path */
    free(m);
    return rc;
}

int npf_local_load(npf_local *l, const char *dir, char *err, size_t errcap)
{
    char *s = NULL;
    long n;
    int rc;
    memset(l, 0, sizeof *l);
    snprintf(l->path, sizeof l->path, "%s/local.json", dir);
    snprintf(l->settings.path, sizeof l->settings.path, "%s", l->path);
    n = npf_file_read(l->path, &s);
    if (n < 0) {                            /* none yet: a first run */
        int e = npf_file_unreadable(l->path);
        if (e) {
            /* there but not readable (another user's file, an I/O error): not
             * taken for a first run, which would write it over and lose the
             * saved nodes, settings and pinned keys */
            snprintf(err, errcap, "cannot read %s: %s (it must belong to the user npf runs as)", l->path,
                     strerror(e));
            return -1;
        }
        return 0;
    }
    rc = parse(l, s, (size_t)n);
    npf_wipe_free(s, (size_t)n);            /* the direct peers' keys */
    if (rc < 0)
        snprintf(err, errcap, "%s: not readable as npf's JSON (move it away to start afresh)", l->path);
    return rc;
}

void npf_local_start_clear(npf_local *l)
{
    int i;
    for (i = 0; i < l->nstart; i++)
        free(l->start[i]);
    free(l->start);
    l->start = NULL;
    l->nstart = 0;
}

int npf_local_start_add(npf_local *l, const char *opt)
{
    char **s, *o;
    if (l->nstart >= NPF_LOCAL_MAX_START || !(s = realloc(l->start, (size_t)(l->nstart + 1) * sizeof *s)))
        return -1;
    l->start = s;
    if (!(o = strdup(opt)))
        return -1;
    l->start[l->nstart++] = o;
    return 0;
}

void npf_local_free(npf_local *l)
{
    int i;
    for (i = 0; i < l->ndev; i++)
        dev_free(&l->dev[i]);
    free(l->resources);
    l->resources = NULL;
    free(l->dev);
    l->dev = NULL;
    l->ndev = 0;
    l->cap = 0;
    npf_local_start_clear(l);
    npf_conf_free(&l->settings);
}

/* the next member's key, on a line of its own at indent ind (a comma
 * before all but the first); its value follows */
static void member(npf_out *o, int *first, const char *ind, const char *k)
{
    npf_out_printf(o, "%s\n%s", *first ? "" : ",", ind);
    *first = 0;
    npf_out_json_str(o, k, strlen(k));
    npf_out_printf(o, ": ");
}

static void kstr(npf_out *o, int *first, const char *ind, const char *k, const char *v)
{
    member(o, first, ind, k);
    npf_out_json_str(o, v, strlen(v));
}

int npf_local_save(npf_local *l)
{
    npf_out o = {0};
    int i, k, first = 1, f2, rc;
    npf_out_printf(&o, "{");
    if (l->settings.n) {
        member(&o, &first, "  ", "settings");
        npf_out_printf(&o, "{");
        for (i = 0, f2 = 1; i < l->settings.n; i++)
            kstr(&o, &f2, "    ", l->settings.key[i], l->settings.val[i]);
        npf_out_printf(&o, "\n  }");
    }
    if (l->nstart) {
        member(&o, &first, "  ", "start");
        npf_out_printf(&o, "[");
        for (i = 0; i < l->nstart; i++) {
            npf_out_printf(&o, "%s", i ? ", " : "");
            npf_out_json_str(&o, l->start[i], strlen(l->start[i]));
        }
        npf_out_printf(&o, "]");
    }
    member(&o, &first, "  ", "devices");
    npf_out_printf(&o, "{");
    for (i = 0, f2 = 1; i < l->ndev; i++) {
        const npf_ldev *d = &l->dev[i];
        int f3 = 1;
        if (!d->name[0] && !d->nick[0] && !d->save && !d->has_key && !d->next)
            continue;                       /* nothing left to keep */
        member(&o, &f2, "    ", d->target);
        npf_out_printf(&o, "{");
        if (d->name[0])
            kstr(&o, &f3, "      ", "name", d->name);
        if (d->nick[0])
            kstr(&o, &f3, "      ", "nick", d->nick);
        if (d->save) {
            member(&o, &f3, "      ", "save");
            npf_out_printf(&o, "true");
            if (d->on_demand)
                kstr(&o, &f3, "      ", "connect", "on_demand");
            if (d->idle_ms) {               /* on demand, or for when it is */
                member(&o, &f3, "      ", "idle_ms");
                npf_out_printf(&o, "%d", d->idle_ms);
            }
        }
        if (d->psk_file[0])
            kstr(&o, &f3, "      ", "psk_file", d->psk_file);
        if (d->psk[0])
            kstr(&o, &f3, "      ", "psk", d->psk);
        if (d->nfwd) {
            member(&o, &f3, "      ", "forwards");
            npf_out_printf(&o, "[");
            for (k = 0; k < d->nfwd; k++) {
                const npf_lfwd *lf = &d->fwd[k];
                npf_out_printf(&o, "%s\n        {\"kind\": ", k ? "," : "");
                if (lf->opt == 'L' || lf->opt == 'D' || lf->opt == 'R') {
                    npf_out_printf(&o, "\"%s\", \"proto\": \"%s\", \"listen\": ",
                                   lf->opt == 'L' ? "local" : lf->opt == 'D' ? "socks" : "remote", lf->udp ? "udp" : "tcp");
                    npf_out_json_str(&o, lf->bind, strlen(lf->bind));
                    npf_out_printf(&o, ", \"port\": %d", lf->port);
                    if (lf->opt != 'D') {
                        npf_out_printf(&o, ", \"host\": ");
                        npf_out_json_str(&o, lf->host, strlen(lf->host));
                        npf_out_printf(&o, ", \"hostport\": %d", lf->hostport);
                    }
                } else {
                    npf_out_printf(&o, "\"%c\", \"spec\": ", lf->opt);
                    npf_out_json_str(&o, lf->spec, strlen(lf->spec));
                }
                npf_out_printf(&o, "}");
            }
            npf_out_printf(&o, "]");
        }
        if (d->has_key) {
            char b[NPF_B64_LEN(32)];
            b[npf_b64url_encode(d->key, 32, b)] = 0;
            kstr(&o, &f3, "      ", "key", b);
        }
        if (d->resources) {
            member(&o, &f3, "      ", "resources");
            npf_out_printf(&o, "%s", d->resources);
        }
        for (k = 0; k < d->next; k++) {     /* the modules' keys, their values as they are */
            member(&o, &f3, "      ", d->ext[k].key);
            npf_out_printf(&o, "%s", d->ext[k].val);
        }
        npf_out_printf(&o, "\n    }");
    }
    npf_out_printf(&o, "\n  }");
    if (l->resources) {
        member(&o, &first, "  ", "resources");
        npf_out_printf(&o, "%s", l->resources);
    }
    npf_out_printf(&o, "\n}\n");
    rc = o.failed || o.len > NPF_JSON_MAX_FILE ? -1 : npf_file_write(l->path, o.p, o.len, 0600);
    npf_out_free(&o);
    l->unsaved = rc < 0;
    return rc;
}

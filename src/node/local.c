/* local.json (local.h). */
#define _GNU_SOURCE
#include "npf/text.h"
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

#define MAX_TOK 32768

static void ext_clear(npf_ldev *d);

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
    size_t n = strlen(s), i;
    if (n > NPF_NICK_MAX)
        return 0;
    for (i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
            return 0;
    return 1;
}

npf_ldev *npf_local_dev(npf_local *l, const char *target, int create)
{
    int i;
    for (i = 0; i < l->ndev; i++)
        if (strcmp(l->dev[i].target, target) == 0)
            return &l->dev[i];
    if (!create || l->ndev >= NPF_LOCAL_MAX_DEV || strlen(target) >= sizeof l->dev[0].target)
        return NULL;
    if (l->ndev == l->cap) {                /* grown as needed */
        int cap = l->cap ? l->cap * 2 : 4;
        npf_ldev *n = realloc(l->dev, (size_t)cap * sizeof *n);
        if (!n)
            return NULL;
        l->dev = n;
        l->cap = cap;
    }
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

int npf_local_drop(npf_local *l, const char *target)
{
    npf_ldev *d = npf_local_dev(l, target, 0);
    if (!d)
        return -1;
    npf_local_fwd_clear(d);
    free(d->resources);
    ext_clear(d);
    memmove(d, d + 1, (size_t)(l->ndev - (d - l->dev) - 1) * sizeof *d);
    l->ndev--;
    return 0;
}

/* ---- the modules' keys ---- */

static void ext_clear(npf_ldev *d)
{
    int i;
    for (i = 0; i < d->next; i++) {
        free(d->ext_key[i]);
        free(d->ext_val[i]);
    }
    free(d->ext_key);
    free(d->ext_val);
    d->ext_key = d->ext_val = NULL;
    d->next = 0;
}

const char *npf_local_ext(const npf_ldev *d, const char *key)
{
    int i;
    for (i = 0; i < d->next; i++)
        if (strcmp(d->ext_key[i], key) == 0)
            return d->ext_val[i];
    return NULL;
}

int npf_local_ext_set(npf_ldev *d, const char *key, const char *json)
{
    char **k, **v, *nk, *nv;
    int i;
    for (i = 0; i < d->next; i++)
        if (strcmp(d->ext_key[i], key) == 0) {
            if (!json) {                    /* removed */
                free(d->ext_key[i]);
                free(d->ext_val[i]);
                d->next--;
                memmove(&d->ext_key[i], &d->ext_key[i + 1], (size_t)(d->next - i) * sizeof *d->ext_key);
                memmove(&d->ext_val[i], &d->ext_val[i + 1], (size_t)(d->next - i) * sizeof *d->ext_val);
                return 0;
            }
            if (!(nv = strdup(json)))
                return -1;
            free(d->ext_val[i]);
            d->ext_val[i] = nv;
            return 0;
        }
    if (!json)
        return 0;
    if (d->next >= NPF_LOCAL_MAX_EXT)
        return -1;
    if (!(k = realloc(d->ext_key, (size_t)(d->next + 1) * sizeof *k)))
        return -1;
    d->ext_key = k;
    if (!(v = realloc(d->ext_val, (size_t)(d->next + 1) * sizeof *v)))
        return -1;
    d->ext_val = v;
    nk = strdup(key);
    nv = strdup(json);
    if (!nk || !nv) {
        free(nk);
        free(nv);
        return -1;
    }
    d->ext_key[d->next] = nk;
    d->ext_val[d->next++] = nv;
    return 0;
}

/* one forward "-L SPEC" more, unless it is there */
int npf_local_fwd_same(const npf_lfwd *a, const npf_lfwd *b)
{
    if (a->opt != b->opt)
        return 0;
    if (a->opt != 'L' && a->opt != 'D' && a->opt != 'R')
        return strcmp(a->spec, b->spec) == 0;
    return a->udp == b->udp && a->port == b->port && a->hostport == b->hostport && strcmp(a->bind, b->bind) == 0
        && strcmp(a->host, b->host) == 0;
}

int npf_local_fwd_add(npf_ldev *d, const npf_lfwd *f)
{
    npf_lfwd *a;
    int i;
    for (i = 0; i < d->nfwd; i++)
        if (npf_local_fwd_same(&d->fwd[i], f))
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
        if (npf_local_fwd_same(&d->fwd[i], f)) {
            memmove(&d->fwd[i], &d->fwd[i + 1], (size_t)(d->nfwd - i - 1) * sizeof d->fwd[0]);
            d->nfwd--;
            return 0;
        }
    return -1;
}

static char *trim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t')
        s++;
    for (e = s + strlen(s); e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r');)
        *--e = 0;
    return s;
}

/* the words of a saved peer ("TARGET [-L SPEC]... [--psk-file F] ...") into a
 * record: the "peer = ..." lines of local.conf of earlier versions */
static void dev_from_words(npf_local *l, char *line)
{
    char *w[64], *t, *save;
    int n = 0, i;
    npf_ldev *d;
    for (t = strtok_r(line, " \t", &save); t && n < 64; t = strtok_r(NULL, " \t", &save))
        w[n++] = t;
    if (n < 1 || !(d = npf_local_dev(l, w[0], 1)))
        return;
    d->save = 1;
    for (i = 1; i + 1 < n; i += 2) {
        if (strcmp(w[i], "--psk-file") == 0)    /* (their forwards are not carried over) */
            snprintf(d->psk_file, sizeof d->psk_file, "%s", w[i + 1]);
        else if (strcmp(w[i], "--psk") == 0)
            snprintf(d->psk, sizeof d->psk, "%s", w[i + 1]);
        else if (strcmp(w[i], "--name") == 0 && npf_name_valid(w[i + 1]))
            snprintf(d->name, sizeof d->name, "%s", w[i + 1]);
    }
}

/* earlier versions: local.conf ("key = value"; peer lines) and known
 * ("NUMBER KEY" lines); renamed *.old once taken over */
static int convert_old(npf_local *l, const char *dir)
{
    char p[1100], old[1110], line[1200];
    FILE *f;
    int any = 0;
    snprintf(p, sizeof p, "%s/local.conf", dir);
    if ((f = fopen(p, "r"))) {
        while (fgets(line, sizeof line, f)) {
            char *eq, *k, *v, *h = strchr(line, '#');
            if (h)
                *h = 0;
            if (!(eq = strchr(line, '=')))
                continue;
            *eq = 0;
            k = trim(line);
            v = trim(eq + 1);
            if (strcmp(k, "peer") == 0)
                dev_from_words(l, v);
            else if (*k)
                npf_conf_set(&l->settings, k, v);
        }
        fclose(f);
        snprintf(old, sizeof old, "%s.old", p);
        rename(p, old);
        any = 1;
    }
    snprintf(p, sizeof p, "%s/known", dir);
    if ((f = fopen(p, "r"))) {
        while (fgets(line, sizeof line, f)) {
            char num[32], k[128];
            const char *p = line;
            npf_ldev *d;
            if (npf_text_word(&p, num, sizeof num) == 0 && npf_text_word(&p, k, sizeof k) == 0 && (d = npf_local_dev(l, num, 1))
                && npf_b64url_decode(k, strlen(k), d->key, 32) == 32)
                d->has_key = 1;
        }
        fclose(f);
        snprintf(old, sizeof old, "%s.old", p);
        rename(p, old);
        any = 1;
    }
    return any;
}

static void get_str(const npf_json *j, int obj, const char *k, char *buf, size_t cap)
{
    if (npf_json_get_str(j, obj, k, buf, cap) < 0)
        buf[0] = 0;
}

/* the keys of a device's record read above */
static int core_key(const char *k)
{
    static const char *const keys[] = {"name", "nick", "save", "connect", "idle_ms", "psk_file", "psk", "forwards", "key",
                                       "resources", NULL};
    int i;
    for (i = 0; keys[i]; i++)
        if (strcmp(keys[i], k) == 0)
            return 1;
    return 0;
}

static int parse(npf_local *l, const char *s, size_t len)
{
    npf_jtok *tok = malloc(MAX_TOK * sizeof *tok);
    npf_json j;
    int t, i, n, rc = -1;
    if (!tok)
        return -1;
    if (npf_json_parse_file(&j, s, len, tok, MAX_TOK) < 0 || j.tok[0].type != NPF_JT_OBJECT)
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
            char target[300], b[64];
            int v = k + 1, f;
            npf_ldev *d;
            if (npf_json_str(&j, k, target, sizeof target) < 0 || j.tok[v].type != NPF_JT_OBJECT
                || !(d = npf_local_dev(l, target, 1)))
                continue;
            get_str(&j, v, "name", d->name, sizeof d->name);
            if (d->name[0] && !npf_name_valid(d->name))
                d->name[0] = 0;
            get_str(&j, v, "nick", d->nick, sizeof d->nick);
            if ((f = npf_json_get(&j, v, "save")) >= 0 && npf_json_bool(&j, f, &d->save) < 0)
                d->save = 0;
            d->on_demand = npf_json_eq(&j, npf_json_get(&j, v, "connect"), "on_demand");
            {
                int64_t ms;
                if (npf_json_get_int(&j, v, "idle_ms", 0, 86400000, &ms) == 0)
                    d->idle_ms = (int)ms;
            }
            get_str(&j, v, "psk_file", d->psk_file, sizeof d->psk_file);
            get_str(&j, v, "psk", d->psk, sizeof d->psk);
            if ((f = npf_json_get(&j, v, "forwards")) >= 0 && j.tok[f].type == NPF_JT_ARRAY)
                for (n = 0; n < j.tok[f].size && d->nfwd < NPF_LOCAL_MAX_FWD; n++) {
                    int e = npf_json_item(&j, f, n);
                    npf_lfwd lf;
                    char kind[16] = "", proto[8] = "";
                    int64_t x;
                    if (e < 0 || j.tok[e].type != NPF_JT_OBJECT)
                        continue;           /* an earlier version's text: not carried over */
                    memset(&lf, 0, sizeof lf);
                    npf_json_get_str(&j, e, "kind", kind, sizeof kind);
                    npf_json_get_str(&j, e, "proto", proto, sizeof proto);
                    lf.opt = strcmp(kind, "local") == 0 ? 'L' : strcmp(kind, "socks") == 0 ? 'D'
                           : strcmp(kind, "remote") == 0 ? 'R'
                           : kind[0] >= 'A' && kind[0] <= 'Z' && !kind[1] ? kind[0] : 0;
                    if (!lf.opt)
                        continue;
                    lf.udp = strcmp(proto, "udp") == 0;
                    get_str(&j, e, "listen", lf.bind, sizeof lf.bind);
                    get_str(&j, e, "host", lf.host, sizeof lf.host);
                    get_str(&j, e, "spec", lf.spec, sizeof lf.spec);
                    if (npf_json_get_int(&j, e, "port", 0, 65535, &x) == 0)
                        lf.port = (int)x;
                    if (npf_json_get_int(&j, e, "hostport", 0, 65535, &x) == 0)
                        lf.hostport = (int)x;
                    if (npf_local_fwd_add(d, &lf) < 0)
                        goto out;
                }
            if (npf_json_get_str(&j, v, "key", b, sizeof b) > 0 && npf_b64url_decode(b, strlen(b), d->key, 32) == 32)
                d->has_key = 1;
            if ((f = npf_json_get(&j, v, "resources")) >= 0 && j.tok[f].type == NPF_JT_ARRAY)
                d->resources = npf_res_normalize(s + j.tok[f].start, j.tok[f].end - j.tok[f].start);
            {   /* the other keys are the modules': kept as they are */
                int q = v + 1;
                for (n = 0; n < j.tok[v].size; n++, q = j.tok[q + 1].next) {
                    char key[48], *val;
                    if (npf_json_str(&j, q, key, sizeof key) < 0 || core_key(key))
                        continue;
                    /* the value's text (a string's with its quotes) */
                    int str = j.tok[q + 1].type == NPF_JT_STRING;
                    size_t vs = j.tok[q + 1].start - (str ? 1 : 0), vl = j.tok[q + 1].end + (str ? 1 : 0) - vs;
                    if (!(val = malloc(vl + 1)))
                        goto out;
                    memcpy(val, s + vs, vl);
                    val[vl] = 0;
                    if (npf_local_ext_set(d, key, val) < 0) {
                        free(val);
                        goto out;
                    }
                    free(val);
                }
            }
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
    return rc;
}

int npf_local_load(npf_local *l, const char *dir, char *err, size_t errcap)
{
    char *s = NULL;
    long n;
    memset(l, 0, sizeof *l);
    snprintf(l->path, sizeof l->path, "%s/local.json", dir);
    snprintf(l->settings.path, sizeof l->settings.path, "%s", l->path);
    n = npf_file_read(l->path, &s);
    if (n < 0) {                            /* none yet: perhaps the files of an earlier version */
        if (convert_old(l, dir) && npf_local_save(l) < 0) {
            snprintf(err, errcap, "cannot write %s", l->path);
            return -1;
        }
        return 0;
    }
    if (parse(l, s, (size_t)n) < 0) {
        snprintf(err, errcap, "%s: not readable as npf's JSON (move it away to start afresh)", l->path);
        free(s);
        return -1;
    }
    free(s);
    return 0;
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
    for (i = 0; i < l->ndev; i++) {
        npf_local_fwd_clear(&l->dev[i]);
        free(l->dev[i].resources);
        ext_clear(&l->dev[i]);
    }
    free(l->resources);
    l->resources = NULL;
    free(l->dev);
    l->dev = NULL;
    l->ndev = l->cap = 0;
    npf_local_start_clear(l);
    npf_conf_free(&l->settings);
}

static void kstr(npf_out *o, int *first, const char *ind, const char *k, const char *v)
{
    npf_out_printf(o, "%s\n%s", *first ? "" : ",", ind);
    *first = 0;
    npf_out_json_str(o, k, strlen(k));
    npf_out_printf(o, ": ");
    npf_out_json_str(o, v, strlen(v));
}

int npf_local_save(npf_local *l)
{
    npf_out o = {0};
    int i, k, first = 1, f2, rc;
    npf_out_printf(&o, "{");
    if (l->settings.n) {
        npf_out_printf(&o, "\n  \"settings\": {");
        f2 = 1;
        for (i = 0; i < l->settings.n; i++)
            kstr(&o, &f2, "    ", l->settings.key[i], l->settings.val[i]);
        npf_out_printf(&o, "\n  }");
        first = 0;
    }
    if (l->nstart) {
        npf_out_printf(&o, "%s\n  \"start\": [", first ? "" : ",");
        for (i = 0; i < l->nstart; i++) {
            npf_out_printf(&o, "%s", i ? ", " : "");
            npf_out_json_str(&o, l->start[i], strlen(l->start[i]));
        }
        npf_out_printf(&o, "]");
        first = 0;
    }
    npf_out_printf(&o, "%s\n  \"devices\": {", first ? "" : ",");
    f2 = 1;
    for (i = 0; i < l->ndev; i++) {
        const npf_ldev *d = &l->dev[i];
        int f3 = 1;
        if (!d->name[0] && !d->nick[0] && !d->save && !d->has_key && !d->next)
            continue;                       /* nothing left to keep */
        npf_out_printf(&o, "%s\n    ", f2 ? "" : ",");
        f2 = 0;
        npf_out_json_str(&o, d->target, strlen(d->target));
        npf_out_printf(&o, ": {");
        if (d->name[0])
            kstr(&o, &f3, "      ", "name", d->name);
        if (d->nick[0])
            kstr(&o, &f3, "      ", "nick", d->nick);
        if (d->save) {
            npf_out_printf(&o, "%s\n      \"save\": true", f3 ? "" : ",");
            f3 = 0;
            if (d->on_demand)
                kstr(&o, &f3, "      ", "connect", "on_demand");
            if (d->idle_ms)                 /* on demand, or for when it is */
                npf_out_printf(&o, ",\n      \"idle_ms\": %d", d->idle_ms);
        }
        if (d->psk_file[0])
            kstr(&o, &f3, "      ", "psk_file", d->psk_file);
        if (d->psk[0])
            kstr(&o, &f3, "      ", "psk", d->psk);
        if (d->nfwd) {
            npf_out_printf(&o, "%s\n      \"forwards\": [", f3 ? "" : ",");
            f3 = 0;
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
            npf_out_printf(&o, "%s\n      \"resources\": %s", f3 ? "" : ",", d->resources);
            f3 = 0;
        }
        for (k = 0; k < d->next; k++) {     /* the modules' keys */
            npf_out_printf(&o, "%s\n      ", f3 ? "" : ",");
            npf_out_json_str(&o, d->ext_key[k], strlen(d->ext_key[k]));
            npf_out_printf(&o, ": %s", d->ext_val[k]);
            f3 = 0;
        }
        npf_out_printf(&o, "\n    }");
    }
    npf_out_printf(&o, "\n  }");
    if (l->resources)
        npf_out_printf(&o, ",\n  \"resources\": %s", l->resources);
    npf_out_printf(&o, "\n}\n");
    rc = o.failed || o.len > NPF_JSON_MAX_FILE ? -1 : npf_file_write(l->path, o.p, o.len, 0600);
    npf_out_free(&o);
    l->unsaved = rc < 0;
    return rc;
}

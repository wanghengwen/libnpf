/* libnpf: configuration sources, paths and saved peers. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "engine_internal.h"

/* ---- configuration ---- */

static void dir_of(const char *path, char *out, size_t cap)
{
    char *slash;
    snprintf(out, cap, "%s", path);
    slash = strrchr(out, '/');
#ifdef _WIN32
    if (!slash || strrchr(out, '\\') > slash)
        slash = strrchr(out, '\\');
#endif
    if (slash)
        *slash = 0;
    else
        snprintf(out, cap, ".");
}

/* the configurations, and the paths made from them */
void npf_engine_config_free(npf_t *n)
{
    npf_conf_free(&n->conf);
    free(n->conf_dir);
    free(n->data_dir);
    free(n->cert_path);
    free(n->node_path);
    free(n->state_path);
    n->conf_dir = n->data_dir = n->cert_path = n->node_path = n->state_path = NULL;
}

/* *p = the formatted path, on the heap (an instance keeps a few: not 1 KB each) */
static int path_set(char **p, const char *fmt, ...)
{
    va_list ap;
    int len;
    char *s;
    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len < 0 || !(s = malloc((size_t)len + 1)))
        return -1;
    va_start(ap, fmt);
    vsnprintf(s, (size_t)len + 1, fmt, ap);
    va_end(ap);
    free(*p);
    *p = s;
    return 0;
}

/* "key = value" lines into c (the same rules as a file) */
static void conf_text(npf_conf *c, const char *text)
{
    char line[4096];                        /* as a file's: a value too long reaches npf_conf_set (c->bad) */
    const char *p = text, *e;
    while (p && *p) {
        size_t l;
        char *eq, *k, *v, *h;
        e = strchr(p, '\n');
        l = e ? (size_t)(e - p) : strlen(p);
        snprintf(line, sizeof line, "%.*s", (int)(l < sizeof line ? l : sizeof line - 1), p);
        p = e ? e + 1 : NULL;
        if ((h = strchr(line, '#')) != NULL)
            *h = 0;
        if (!(eq = strchr(line, '=')))
            continue;
        *eq = 0;
        for (k = line; *k == ' ' || *k == '\t'; k++)
            ;
        for (h = eq - 1; h >= k && (*h == ' ' || *h == '\t'); h--)
            *h = 0;
        for (v = eq + 1; *v == ' ' || *v == '\t'; v++)
            ;
        for (h = v + strlen(v) - 1; h >= v && (*h == ' ' || *h == '\t' || *h == '\r'); h--)
            *h = 0;
        if (*k)
            npf_conf_set(c, k, v);
    }
}

/* the configuration in effect: npf.conf, then the overrides, then local.json's settings */
static void conf_merge(npf_conf *dst, const npf_conf *src)
{
    int i;
    for (i = 0; i < src->n; i++)
        npf_conf_set(dst, src->key[i], src->val[i]);
}

/* the peers of local.json saved to be connected at every start, and their
 * saved forwards (a record that does not make one is left out, with a
 * warning) */
void npf_engine_restore_peers(npf_t *n)
{
    int i, k;
    for (i = 0; i < n->lc.ndev; i++) {
        npf_ldev *d = &n->lc.dev[i];
        npf_peer_new pn;
        npf_peer *p;
        char host[300], e[300];
        uint8_t psk[32];
        int code;
        if (!d->save || npf_peers_find(n->peers, d->target))
            continue;
        memset(&pn, 0, sizeof pn);
        if (!(pn.number = npf_number_parse(d->target))) {
            const char *colon = strrchr(d->target, ':');
            char path[1600];
            if (!colon)
                continue;
            if (d->target[0] == '[')
                snprintf(host, sizeof host, "%.*s", (int)(colon - d->target - 2), d->target + 1);
            else
                snprintf(host, sizeof host, "%.*s", (int)(colon - d->target), d->target);
            pn.host = host;
            pn.port = (uint16_t)atoi(colon + 1);
            if (d->psk_file[0]) {
                if (npf_path_is_abs(d->psk_file))
                    snprintf(path, sizeof path, "%s", d->psk_file);
                else
                    snprintf(path, sizeof path, "%s/%s", n->data_dir, d->psk_file);
            }
            if (npf_direct_psk(d->psk[0] ? d->psk : NULL, d->psk_file[0] ? path : NULL, psk) < 0) {
                npf_logw("local.json: %s: no key to connect with: left out", d->target);
                continue;
            }
            pn.psk = psk;
        }
        pn.connect = d->on_demand ? NPF_CONNECT_ON_DEMAND : NPF_CONNECT_KEEP;
        pn.idle_ms = d->idle_ms;
        p = npf_peers_create(n->peers, &pn, e, sizeof e, &code);
        npf_wipe(psk, sizeof psk);
        if (!p) {
            npf_logw("local.json: %s: %s: left out", d->target, e);
            continue;
        }
        npf_peer_set_tag(p, PEER_SAVED);
        for (k = 0; k < d->nfwd; k++) {
            const npf_lfwd *lf = &d->fwd[k];
            int r;
            if (lf->opt == 'L' || lf->opt == 'D' || lf->opt == 'R') {
                npf_fwd_new fn;
                memset(&fn, 0, sizeof fn);
                fn.opt = lf->opt;
                fn.udp = lf->udp;
                fn.bind = lf->bind[0] ? lf->bind : NULL;
                fn.port = lf->port;
                fn.host = lf->host;
                fn.hostport = lf->hostport;
                r = npf_peer_forward_add_parts(p, &fn, 1, 0, e, sizeof e);
            } else {
                r = npf_peer_forward_add_kind(p, lf->opt, lf->spec, 1, e, sizeof e);
            }
            if (r < 0)
                npf_logw("local.json: %s: a forward left out: %s", d->target, e);
        }
    }
}

/* the configuration in effect and the paths made from it: ro (npf.conf or
 * the setup) and ov (the overrides) read, merged into n->conf */
static int config_load(npf_t *n, const npf_options *o, npf_conf *ro, npf_conf *ov, char *err, size_t errcap)
{
    char conf_path[1100];
    int have_conf;

    /* the read-only configuration: npf.conf, or the application's fields */
    if (o->setup) {
        snprintf(conf_path, sizeof conf_path, "%s/(npf_setup)", o->data_dir);
        npf_mkdir_p(o->data_dir);
        if (npf_setup_conf(o->setup, o->role, o->data_dir, ro, err, errcap) < 0)
            return NPF_EINVAL;
        snprintf(ro->path, sizeof ro->path, "%.1000s", conf_path);
        have_conf = 1;
    } else {
        if (o->conf_file && npf_path_is_abs(o->conf_file))
            snprintf(conf_path, sizeof conf_path, "%s", o->conf_file);
        else
            snprintf(conf_path, sizeof conf_path, "%s/%s", o->conf_dir ? o->conf_dir : ".",
                     o->conf_file ? o->conf_file : "npf.conf");
        have_conf = npf_conf_load(ro, conf_path) == 0;
    }
    if (!have_conf && n->role != NPF_ROLE_DIRECT) {
        snprintf(err, errcap, "cannot read %s", conf_path);
        return NPF_EFAIL;
    }
    if (!have_conf && (size_t)snprintf(ro->path, sizeof ro->path, "%s", conf_path) >= sizeof ro->path) {
        snprintf(err, errcap, "path too long");
        return NPF_EINVAL;
    }
    if (ro->bad[0]) {
        snprintf(err, errcap, "%s: the value of '%s' is too long (at most %d characters)", conf_path, ro->bad,
                 NPF_CONF_VAL_MAX - 1);
        return NPF_EINVAL;
    }
    {
        char d[1100];
        dir_of(ro->path, d, sizeof d);
        if (path_set(&n->conf_dir, "%s", d) < 0) {
            snprintf(err, errcap, "no memory");
            return NPF_EFAIL;
        }
    }
    if (o->overrides)
        conf_text(ov, o->overrides);
    if (ov->bad[0]) {                     /* as for the file: not cut short in silence */
        snprintf(err, errcap, "overrides: the value of '%s' is too long (at most %d characters)", ov->bad,
                 NPF_CONF_VAL_MAX - 1);
        return NPF_EINVAL;
    }
    if (npf_conf_get(ro, "node", NULL) || npf_conf_get(ov, "node", NULL)) {
        snprintf(err, errcap, "config: \"node =\" lines are gone: the application makes its peers (npf_peer_create)");
        return NPF_EINVAL;
    }
    if (o->setup) {                         /* one source for each: a field, or the overrides */
        const char *k = npf_setup_key_taken(ov);
        if (k) {
            snprintf(err, errcap, "overrides: '%s' is a field of npf_setup", k);
            return NPF_EINVAL;
        }
    }
    /* the writable directory: the option, the configuration's "dir", conf_dir */
    if (path_set(&n->data_dir, "%s", o->data_dir                        ? o->data_dir
                                     : npf_conf_get(ov, "dir", NULL) ? npf_conf_get(ov, "dir", NULL)
                                     : npf_conf_get(ro, "dir", NULL) ? npf_conf_get(ro, "dir", NULL)
                                                                         : n->conf_dir) < 0) {
        snprintf(err, errcap, "no memory");
        return NPF_EFAIL;
    }
    npf_mkdir_p(n->data_dir);
    if (npf_local_load(&n->lc, n->data_dir, err, errcap) < 0)
        return NPF_EFAIL;
    n->local_path = n->lc.path;
    if (npf_conf_copy(&n->conf, ro) < 0) {
        snprintf(err, errcap, "no memory");
        return NPF_EFAIL;
    }
    conf_merge(&n->conf, ov);
    if (!(n->opt_flags & NPF_OPT_NO_SAVED_SETTINGS)) {   /* local.json: its settings over the others */
        int i;
        for (i = 0; i < n->lc.settings.n; i++) {
            if (npf_conf_file_only(n->lc.settings.key[i])) {    /* not from here (npf_cmd_set refuses it) */
                npf_logw("%s: %s ignored: only in npf.conf", n->lc.path, n->lc.settings.key[i]);
                continue;
            }
            npf_conf_set(&n->conf, n->lc.settings.key[i], n->lc.settings.val[i]);
        }
    }
    if (o->log_level >= 0)
        npf_log_set_level(o->log_level);
    else
        npf_conf_apply_log_level(&n->conf);
    if (path_set(&n->cert_path, "%s/account.cert", n->data_dir) < 0
        || path_set(&n->node_path, "%s/node.json", n->data_dir) < 0
        || (npf_conf_get(&n->conf, "state", NULL) ? path_set(&n->state_path, "%s", npf_conf_get(&n->conf, "state", NULL))
                                                  : path_set(&n->state_path, "%s/state.json", n->data_dir)) < 0) {
        snprintf(err, errcap, "no memory");
        return NPF_EFAIL;
    }
    if (!npf_conf_get(&n->conf, "serverlist_saved", NULL)) {
        /* the lists the platform sends are kept with what changes ("off": not kept) */
        char p[1200];
        snprintf(p, sizeof p, "%s/serverlist-saved.bin", n->data_dir);
        if (npf_conf_set(&n->conf, "serverlist_saved", p) < 0) {
            snprintf(err, errcap, "no memory");
            return NPF_EFAIL;
        }
    }
    return NPF_OK;
}

/* (engine_internal.h) the read-only configuration and the overrides only
 * while they are merged: n->conf keeps copies of their values */
int npf_engine_config_load(npf_t *n, const npf_options *o, char *err, size_t errcap)
{
    npf_conf *ro = calloc(2, sizeof *ro);   /* 2.2 KB: not on a small thread's stack */
    int rc;
    if (!ro) {
        snprintf(err, errcap, "no memory");
        return NPF_EFAIL;
    }
    rc = config_load(n, o, &ro[0], &ro[1], err, errcap);
    npf_conf_free(&ro[0]);
    npf_conf_free(&ro[1]);
    free(ro);
    return rc;
}

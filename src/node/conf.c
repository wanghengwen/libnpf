#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/sys.h"

#ifdef _WIN32
#include <sddl.h>
#else
#include <unistd.h>
#endif

static char *trim(char *s)
{
    char *e;
    while (isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = 0;
    return s;
}

/* ---- the keys (architecture.md 7.1): what each is, where it may come from ----
 * NPF_K_FILE: where to connect, what to trust or run, the files the program
 * writes: only in npf.conf (whoever may write it may run the program), never
 * set through the control interface or taken from local.json (a Windows
 * service's control token is every local user's) */

#define S(name, fl)                {name, NPF_K_STR, fl, 0, 0, "", NULL}
#define I(name, fl, lo, hi, def)   {name, NPF_K_INT, fl, lo, hi, def, NULL}
#define B(name, fl, def)           {name, NPF_K_INT, fl, 0, 1, def, NULL}
#define E(name, fl, def, vals)     {name, NPF_K_ENUM, fl, 0, 0, def, vals}
enum { F = NPF_K_FILE, L = NPF_K_LIVE, X = NPF_K_SECRET, U = NPF_K_SETUP, P = NPF_K_PATH, M = NPF_K_MULTI,
       H = NPF_K_UNLISTED };
static const npf_key keys[] = {
    /* the platform, the identity: npf.conf (or npf_setup) only, except the password and the serial */
    S("root", F | U), S("server", F | U), S("server_pub", F | U), S("serverlist", F | U | P),
    S("serverlist_saved", F | U | P), S("doh_servers", F | U), B("report_host", F | U, "1"), S("cred", F | X | U),
    S("model_cred", F | X | U), S("model", F | U), S("password", X | U), S("serial", U), S("serial_file", F | U),
    S("hw_info", U), S("direct", F | U), S("direct_psk", F | X | U), S("direct_psk_file", F | U | P),
    /* the files */
    S("dir", F | P), S("state", F | P), S("log", F | P), S("pidfile", F | P),
    /* the network */
    I("udp_port", U, 0, 65535, "0"), B("portmap", U, "1"), E("connect_mode", L | U, "p2p", "p2p|secure"),
    I("max_calls", L | U, 0, 4096, "0"), I("punch_lead_ms", L | U, -1, 5000, "-1"), I("punch_sockets", L | U, 0, 4096, "0"),
    E("home_bind", 0, "auto", "auto|off"), B("test_one_host", F, "0"),
    /* sessions; the log (its values in the order of NPF_LOG_*) */
    B("hosted_trust", L | U, "1"), I("peer_idle", L | U, 0, 86400, "0"),
    E("log_level", L, "info", "trace|debug|info|warn|error"), S("node", F | M), S("resource", F | M),
    /* npf-hosted (security.md 8.4) */
    B("hosted_service", F, "0"), S("hosted_exec", F), S("hosted_ports", F),
    I("hosted_max_conns", L | H, 0, 100000, "128"), I("hosted_ip_conns", L | H, 0, 100000, "32"),
    I("hosted_ip_rate", L | H, 0, 100000, "120"), I("sig_idle_s", 0, 0, 86400, "0"), I("sig_wake_s", 0, 0, 86400, "600"),
    B("udp_on_demand", 0, "0"), B("udp_public", 0, "0"),
    /* npf's own (architecture.md 7: its module's, later) */
    S("control", F), S("control_token", F), S("web_dir", F), E("keep_awake", L, "busy", "busy|ac|always|off"),
    {NULL, 0, 0, 0, 0, NULL, NULL},
};
#undef S
#undef I
#undef B
#undef E

const npf_key *npf_key_find(const char *name)
{
    const npf_key *k;
    for (k = keys; k->name && strcmp(k->name, name) != 0; k++)
        ;
    return k->name ? k : NULL;
}

int npf_key_is(const char *name, int flag)
{
    const npf_key *k = npf_key_find(name);
    return k && (k->flags & flag);
}

const npf_key *npf_key_next(const npf_key *k)
{
    k = k ? k + 1 : keys;
    return k->name ? k : NULL;
}

/* an NPF_K_ENUM value's index in vals ("a|b"), -1 none */
static int enum_index(const char *vals, const char *v)
{
    size_t l = strlen(v);
    int i;
    for (i = 0; *vals; i++) {
        const char *e = strchr(vals, '|');
        size_t n = e ? (size_t)(e - vals) : strlen(vals);
        if (n == l && strncmp(vals, v, l) == 0)
            return i;
        vals += n + (e != NULL);
    }
    return -1;
}

/* v as k's value: an NPF_K_INT's number, an NPF_K_ENUM's index; -1 not one */
static int value_of(const npf_key *k, const char *v, int64_t *out)
{
    char *e;
    if (k->type == NPF_K_ENUM)
        return (*out = enum_index(k->vals, v)) < 0 ? -1 : 0;
    *out = strtoll(v, &e, 10);
    return k->type == NPF_K_STR || (*v && !*e && *out >= k->lo && *out <= k->hi) ? 0 : -1;
}

int npf_key_check(const npf_key *k, const char *v, char *err, size_t cap)
{
    char list[96];
    const char *p, *last = k->vals ? strrchr(k->vals, '|') : NULL;
    size_t o = 0;
    int64_t x;
    if (value_of(k, v, &x) == 0)
        return 0;
    if (k->type == NPF_K_INT) {
        snprintf(err, cap, "%s: a number from %lld to %lld", k->name, (long long)k->lo, (long long)k->hi);
        return -1;
    }
    for (p = k->vals; *p && o + 5 < sizeof list; p++) {     /* "a|b|c": "a, b or c" */
        if (*p != '|')
            list[o++] = *p;
        else
            o += (size_t)snprintf(list + o, sizeof list - o, p == last ? " or " : ", ");
    }
    list[o] = 0;
    snprintf(err, cap, "%s: %s", k->name, list);
    return -1;
}

int npf_conf_check(const npf_conf *c, char *err, size_t cap)
{
    int i;
    for (i = 0; i < c->n; i++) {
        const npf_key *k = npf_key_find(c->key[i]);
        if (k && npf_key_check(k, c->val[i], err, cap) < 0)
            return -1;
    }
    return 0;
}

int64_t npf_conf_int(const npf_conf *c, const char *key)
{
    const npf_key *k = npf_key_find(key);
    int64_t x = 0;
    if (k && k->type != NPF_K_STR && value_of(k, npf_conf_get(c, key, k->def), &x) < 0)
        value_of(k, k->def, &x);
    return x;
}

int npf_conf_set(npf_conf *c, const char *key, const char *val)
{
    size_t vl = strlen(val);
    char *v, **o;
    int i;
    for (i = 0; i < c->n && !npf_key_is(key, NPF_K_MULTI); i++)
        if (strcmp(c->key[i], key) == 0)
            break;
    if (npf_key_is(key, NPF_K_MULTI))
        i = c->n;
    if (vl >= NPF_CONF_VAL_MAX) {
        if (!c->bad[0])
            snprintf(c->bad, sizeof c->bad, "%s", key);
        return -1;
    }
    if (i < c->n) {                         /* replace: in place when it fits */
        if (vl < c->room[i]) {
            memcpy(c->val[i], val, vl + 1);
            npf_wipe(c->val[i] + vl + 1, c->room[i] - vl - 1);   /* a longer old value (a password) gone too */
            return 0;
        }
        o = realloc(c->old, (size_t)(c->nold + 1) * sizeof *o);
        if (!o || !(v = strdup(val))) {
            if (o)
                c->old = o;
            return -1;
        }
        c->old = o;
        c->old[c->nold++] = c->val[i];      /* a pointer someone read stays valid */
        c->val[i] = v;
        c->room[i] = vl + 1;
        return 0;
    }
    if (c->n >= NPF_CONF_MAX || strlen(key) >= NPF_CONF_KEY_MAX)
        return -1;
    if (c->n == c->cap) {
        int cap = c->cap ? 2 * c->cap : 16;
        char **k = realloc(c->key, (size_t)cap * sizeof *k), **vv;
        size_t *r;
        if (!k)
            return -1;
        c->key = k;
        if (!(vv = realloc(c->val, (size_t)cap * sizeof *vv)))
            return -1;
        c->val = vv;
        if (!(r = realloc(c->room, (size_t)cap * sizeof *r)))
            return -1;
        c->room = r;
        c->cap = cap;
    }
    if (!(c->key[i] = strdup(key)))
        return -1;
    if (!(c->val[i] = strdup(val))) {
        free(c->key[i]);
        return -1;
    }
    c->room[i] = vl + 1;
    c->n++;
    return 0;
}

void npf_conf_free(npf_conf *c)
{
    int i;
    /* values may be secrets (password, cred, direct_psk): wiped first */
    for (i = 0; i < c->n; i++) {
        free(c->key[i]);
        npf_wipe(c->val[i], c->room[i]);
        free(c->val[i]);
    }
    for (i = 0; i < c->nold; i++) {
        npf_wipe(c->old[i], strlen(c->old[i]));
        free(c->old[i]);
    }
    free(c->key);
    free(c->val);
    free(c->room);
    free(c->old);
    memset(c, 0, sizeof *c);
}

int npf_conf_copy(npf_conf *dst, const npf_conf *src)
{
    int i;
    npf_conf_free(dst);
    memcpy(dst->path, src->path, sizeof dst->path);
    memcpy(dst->bad, src->bad, sizeof dst->bad);
    for (i = 0; i < src->n; i++) {
        /* repeatable keys append; the others are unique in src */
        if (npf_conf_set(dst, src->key[i], src->val[i]) < 0) {
            npf_conf_free(dst);
            return -1;
        }
    }
    return 0;
}

const char *npf_conf_get_path(const npf_conf *c, const char *key, const char *def_name, char *out, size_t cap)
{
    const char *v = npf_conf_get(c, key, NULL), *slash;
    if (v) {
        snprintf(out, cap, "%s", v);
        return out;
    }
    slash = strrchr(c->path, '/');
#ifdef _WIN32
    if (!slash || strrchr(c->path, '\\') > slash)
        slash = strrchr(c->path, '\\');
#endif
    if (!c->path[0] || !slash)
        snprintf(out, cap, "%s", def_name);
    else
        snprintf(out, cap, "%.*s%s", (int)(slash - c->path + 1), c->path, def_name);
    return out;
}

void npf_conf_set_rel(npf_conf *c, const char *conf_path, const char *k, const char *v)
{
    char dir[1024], full[1024];
    const char *slash;
    if (!npf_key_is(k, NPF_K_PATH) || !*v || strcmp(v, "off") == 0 || npf_path_is_abs(v) || npf_abspath(conf_path, dir, sizeof dir) < 0) {
        npf_conf_set(c, k, v);
        return;
    }
    slash = strrchr(dir, '/');
#ifdef _WIN32
    if (!slash || strrchr(dir, '\\') > slash)
        slash = strrchr(dir, '\\');
#endif
    if (!slash) {
        npf_conf_set(c, k, v);
        return;
    }
    snprintf(full, sizeof full, "%.*s%s", (int)(slash - dir + 1), dir, v);
    npf_conf_set(c, k, full);
}

int npf_conf_load(npf_conf *c, const char *path)
{
    char line[4096];
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (npf_abspath(path, c->path, sizeof c->path) < 0)
        snprintf(c->path, sizeof c->path, "%s", path);
    while (fgets(line, sizeof line, f)) {
        char *eq, *k, *v, *h = strchr(line, '#');
        if (h)
            *h = 0;
        eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        k = trim(line);
        v = trim(eq + 1);
        if (*k)
            npf_conf_set_rel(c, path, k, v);
    }
    fclose(f);
    return 0;
}

int npf_conf_value_ok(const char *value)
{
    const unsigned char *s;
    for (s = (const unsigned char *)value; *s; s++)
        if (*s < 0x20 || *s == 0x7f || *s == '#')
            return 0;
    return strlen(value) < 1000;            /* a value holds up to 1023 bytes */
}

const char *npf_conf_get_n(const npf_conf *c, const char *key, int n)
{
    int i;
    for (i = 0; i < c->n; i++)
        if (strcmp(c->key[i], key) == 0 && n-- == 0)
            return c->val[i];
    return NULL;
}

const char *npf_conf_get(const npf_conf *c, const char *key, const char *def)
{
    int i;
    for (i = 0; i < c->n; i++)
        if (strcmp(c->key[i], key) == 0)
            return c->val[i];
    return def;
}

long npf_file_read(const char *path, char **out)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *b;
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) < 0 || (n = ftell(f)) < 0 || n > (16 << 20) || fseek(f, 0, SEEK_SET) < 0) {
        fclose(f);
        return -1;
    }
    b = malloc((size_t)n + 1);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        fclose(f);
        return -1;
    }
    fclose(f);
    b[n] = 0;
    *out = b;
    return n;
}

int npf_file_unreadable(const char *path)
{
    struct stat st;
    FILE *f;
    if (stat(path, &st) != 0)
        return errno == ENOENT ? 0 : errno;
    if (!(f = fopen(path, "rb")))
        return errno ? errno : EACCES;
    fclose(f);
    return EIO;
}

int npf_file_write(const char *path, const void *data, size_t len, int mode)
{
    char tmp[1024];
#ifdef _WIN32
    /* secrets (mode & 077 == 0) are created with a protected DACL from the
     * start: SYSTEM, Administrators and the owner; nothing is inherited */
    SECURITY_ATTRIBUTES sa, *psa = NULL;
    HANDLE h;
    DWORD wrote = 0;
    BOOL ok;
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return -1;
    memset(&sa, 0, sizeof sa);
    sa.nLength = sizeof sa;
    if ((mode & 077) == 0
        && ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",
                                                                SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
        psa = &sa;
    /* CREATE_ALWAYS on a tmp file someone else made keeps its DACL (and
     * MoveFileEx then the file's): removed, then made new with ours */
    DeleteFileA(tmp);
    h = CreateFileA(tmp, GENERIC_WRITE, 0, psa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (psa)
        LocalFree(sa.lpSecurityDescriptor);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    ok = (len == 0 || (WriteFile(h, data, (DWORD)len, &wrote, NULL) && wrote == len)) && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) {
        DeleteFileA(tmp);
        return -1;
    }
    return MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
#else
    int fd;
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return -1;
    /* a tmp file someone else left (with its own owner, mode or a symlink)
     * is not written into: removed, then made new */
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    if (write(fd, data, len) != (ssize_t)len || fsync(fd) < 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, path) < 0)
        return -1;
    {   /* the rename on the disk too: after a power cut the old file must
         * not come back (an unpairing, a new password, a revocation undone) */
        char dir[1024];
        const char *sl = strrchr(path, '/');
        int dfd;
        if (!sl)
            snprintf(dir, sizeof dir, ".");
        else
            snprintf(dir, sizeof dir, "%.*s", sl == path ? 1 : (int)(sl - path), path);
        if ((dfd = open(dir, O_RDONLY | O_CLOEXEC)) >= 0) {
            fsync(dfd);                 /* EINVAL where directories cannot be: nothing more to do */
            close(dfd);
        }
    }
    return 0;
#endif
}

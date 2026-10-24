#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* keys that may appear several times; each line adds a value */
static const char *const multi_keys[] = {"node", "resource", NULL};

static int is_multi(const char *key)
{
    int i;
    for (i = 0; multi_keys[i]; i++)
        if (strcmp(multi_keys[i], key) == 0)
            return 1;
    return 0;
}

int npf_conf_set(npf_conf *c, const char *key, const char *val)
{
    size_t vl = strlen(val);
    char *v, **o;
    int i;
    for (i = 0; i < c->n && !is_multi(key); i++)
        if (strcmp(c->key[i], key) == 0)
            break;
    if (is_multi(key))
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

static const char *const path_keys[] = {"dir", "state", "serverlist", "serverlist_saved", "direct_psk_file",
                                        "log", "pidfile", NULL};

void npf_conf_set_rel(npf_conf *c, const char *conf_path, const char *k, const char *v)
{
    char dir[1024], full[1024];
    const char *slash;
    int i;
    for (i = 0; path_keys[i] && strcmp(path_keys[i], k) != 0; i++)
        ;
    if (!path_keys[i] || !*v || strcmp(v, "off") == 0 || npf_path_is_abs(v) || npf_abspath(conf_path, dir, sizeof dir) < 0) {
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

/* the key of a line ("" for comments and blank lines), and its value */
static void line_kv(const char *line, char *k, size_t kc, char *v, size_t vc)
{
    char buf[4096], *eq, *h;
    snprintf(buf, sizeof buf, "%s", line);
    k[0] = v[0] = 0;
    if ((h = strchr(buf, '#')) != NULL)
        *h = 0;
    if (!(eq = strchr(buf, '=')))
        return;
    *eq = 0;
    snprintf(k, kc, "%s", trim(buf));
    snprintf(v, vc, "%s", trim(eq + 1));
}

static const char *const known_keys[] = {
    "control", "control_token", "cred", "dir", "direct", "direct_psk_file", "hosted_trust",
    "hosted_service", "hosted_exec", "hosted_ports", "hosted_max_conns", "hosted_ip_conns", "hosted_ip_rate", "sig_idle_s", "sig_wake_s",
    "udp_on_demand", "udp_public",
    "doh_servers", "hw_info", "keep_awake", "log", "log_level", "max_calls", "model", "model_cred", "password", "node",
    "peer_idle", "pidfile", "portmap", "web_dir", "punch_lead_ms", "punch_sockets", "report_host", "resource", "root", "serial", "serial_file", "server", "server_pub",
    "serverlist", "serverlist_saved", "state", "connect_mode", "udp_port", NULL};

/* keys that say where to connect, what to trust or run, and which files
 * the program writes: only in npf.conf (whoever may write it may run the
 * program), never set through the control interface or taken from
 * local.json (a Windows service's control token is every local user's) */
static const char *const file_only_keys[] = {
    "control", "control_token", "web_dir", "log", "pidfile", "dir", "state", "root", "server", "server_pub",
    "serverlist", "serverlist_saved", "doh_servers", "report_host", "serial_file", "direct", "direct_psk",
    "direct_psk_file", "hosted_exec", "hosted_service", "hosted_ports", "model", "model_cred", "cred", "node", "resource", NULL};

int npf_conf_file_only(const char *key)
{
    int i;
    for (i = 0; file_only_keys[i]; i++)
        if (strcmp(file_only_keys[i], key) == 0)
            return 1;
    return 0;
}

int npf_conf_known(const char *key)
{
    int i;
    for (i = 0; known_keys[i]; i++)
        if (strcmp(known_keys[i], key) == 0)
            return 1;
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

int npf_conf_file_edit(const char *path, const char *key, const char *old, const char *value)
{
    char *in = NULL, *out, *line, *next, k[64], v[1024];
    long n;
    size_t cap, o = 0;
    int multi = is_multi(key), placed = 0, r;
    const char *kc;
    for (kc = key; *kc; kc++)
        if (!(*kc >= 'a' && *kc <= 'z') && *kc != '_')
            return -1;
    if (!*key || (value && !npf_conf_value_ok(value)))
        return -1;
    n = npf_file_read(path, &in);
    if (n < 0) {
        n = 0;
        in = calloc(1, 1);
        if (!in)
            return -1;
    }
    cap = (size_t)n + strlen(key) + (value ? strlen(value) : 0) + 16;
    out = malloc(cap);
    if (!out) {
        free(in);
        return -1;
    }
    for (line = in; *line; line = next) {
        size_t len;
        next = strchr(line, '\n');
        next = next ? next + 1 : line + strlen(line);
        len = (size_t)(next - line);
        {
            char l[4096];
            snprintf(l, sizeof l, "%.*s", (int)(len < sizeof l ? len : sizeof l - 1), line);
            line_kv(l, k, sizeof k, v, sizeof v);
        }
        if (strcmp(k, key) == 0) {
            if (multi ? (old && strcmp(v, old) == 0) : 1) {
                if (!multi && value && !placed) {
                    o += (size_t)snprintf(out + o, cap - o, "%s = %s\n", key, value);
                    placed = 1;
                }
                continue;                   /* the line goes */
            }
        }
        memcpy(out + o, line, len);
        o += len;
        if (len && line[len - 1] != '\n' && o < cap)
            out[o++] = '\n';
    }
    if (value && !placed)
        o += (size_t)snprintf(out + o, cap - o, "%s = %s\n", key, value);
    r = npf_file_write(path, out, o, 0600);
    free(in);
    free(out);
    return r;
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
    return rename(tmp, path);
#endif
}

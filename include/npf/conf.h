/* Configuration ("key = value" files such as npf.conf, the key tables) and
 * whole-file read and atomic write. Internal to libnpf; in include/npf because
 * npf reads npf.conf itself (app/main.c, host.c, start.c), its modules declare
 * their keys with npf_key tables (npf/module.h), and app and modules use the
 * file helpers. */
#ifndef NPF_CONF_H
#define NPF_CONF_H

#include <stddef.h>
#include <stdint.h>

#define NPF_CONF_MAX     128    /* entries */
#define NPF_CONF_KEY_MAX 48     /* bytes of a key, its NUL included */
#define NPF_CONF_VAL_MAX 1024   /* bytes of a value, its NUL included */

/* A zeroed npf_conf is empty. Free it with npf_conf_free; copy it with
 * npf_conf_copy, never by assignment. A pointer npf_conf_get returned stays
 * valid until npf_conf_free (a later set may change the text it points to).
 * Values may be secrets: npf_conf_free wipes them all, replaced ones too. */
typedef struct npf_conf {
    int     n;
    size_t  cap;
    char  **key, **val;         /* n entries */
    size_t *room;               /* bytes each val has */
    char  **old;                /* values replaced by longer ones, kept until npf_conf_free */
    int     nold;
    char    path[1024];         /* the file, absolute */
    char    bad[NPF_CONF_KEY_MAX]; /* the first key whose value was too long and dropped; "" none */
} npf_conf;

void npf_conf_free(npf_conf *c);
/* Frees dst, then makes it a copy of src. 0, or -1 (no memory; dst is empty then). */
int  npf_conf_copy(npf_conf *dst, const npf_conf *src);

/* Adds the "key = value" lines of the file to c ('#' starts a comment, lines
 * without '=' are skipped) and records its absolute path. A relative value of
 * a path-valued key (NPF_K_PATH, a registered module's too: register modules
 * first) is made absolute against the file's directory. 0, or -1 when the
 * file cannot be opened. Values are not checked (npf_conf_check). */
int npf_conf_load(npf_conf *c, const char *path);
/* The key's value, or def when unset. For a repeatable key, the first. */
const char *npf_conf_get(const npf_conf *c, const char *key, const char *def);
/* A repeatable key's i-th value (from 0); NULL past the last. */
const char *npf_conf_get_n(const npf_conf *c, const char *key, int i);
/* The key's value, or when unset def_name in the directory of the file c was
 * loaded from (def_name itself without one), into out (cap bytes). Returns out. */
const char *npf_conf_get_path(const npf_conf *c, const char *key, const char *def_name, char *out, size_t cap);
/* Sets the key (an NPF_K_MULTI key gets one more value). 0, or -1: the value
 * has NPF_CONF_VAL_MAX bytes or more (the key goes into bad), NPF_CONF_MAX
 * entries, the key too long, or no memory. */
int npf_conf_set(npf_conf *c, const char *key, const char *val);
/* npf_conf_set, a relative value of an NPF_K_PATH key ("" and "off" aside)
 * made absolute against the directory of the file conf_path. */
void npf_conf_set_rel(npf_conf *c, const char *conf_path, const char *key, const char *val);

/* The configuration keys: libnpf's table (npf_keys) and each registered
 * module's (npf_module.keys) give every key's type, range, default and the
 * sources it may come from. A table ends with NPF_KEY_END. */
enum { NPF_K_STR, NPF_K_INT, NPF_K_ENUM };      /* a flag is an NPF_K_INT of 0..1 */
enum {
    NPF_K_FILE = 1,         /* only from npf.conf or npf_setup: refused by npf_config_set, ignored in local.json */
    NPF_K_LIVE = 2,         /* npf_config_set puts it in effect at once */
    NPF_K_SECRET = 4,       /* npf_config_get and npf set show "(hidden)" */
    NPF_K_SETUP = 8,        /* an npf_setup field: with a setup, refused in the overrides */
    NPF_K_PATH = 16,        /* a relative value is taken against the configuration file's directory */
    NPF_K_MULTI = 32,       /* repeatable: each line adds a value */
    NPF_K_UNLISTED = 64,    /* with NPF_K_LIVE: left out of npf_config_json (npf-hosted's limits) */
};
typedef struct npf_key {
    const char *name;
    uint8_t     type, flags;
    int64_t     lo, hi;             /* NPF_K_INT */
    const char *def;                /* the value when unset; "" none */
    const char *vals;               /* NPF_K_ENUM: "a|b|c" */
} npf_key;
#define NPF_KEY_S(name, fl)              {name, NPF_K_STR, fl, 0, 0, "", NULL}
#define NPF_KEY_I(name, fl, lo, hi, def) {name, NPF_K_INT, fl, lo, hi, def, NULL}
#define NPF_KEY_B(name, fl, def)         {name, NPF_K_INT, fl, 0, 1, def, NULL}
#define NPF_KEY_E(name, fl, def, vals)   {name, NPF_K_ENUM, fl, 0, 0, def, vals}
#define NPF_KEY_END                      {NULL, 0, 0, 0, 0, NULL, NULL}
extern const npf_key npf_keys[];                        /* libnpf's */
/* The key of that name in table t (NULL t: none), else NULL. */
const npf_key *npf_key_in(const npf_key *t, const char *name);
/* libnpf's key of that name, else a registered module's, else NULL. Any thread. */
const npf_key *npf_key_find(const char *name);
const npf_key *npf_mods_key(const char *name);          /* a registered module's only */
int  npf_key_is(const char *name, int flag);            /* 1: a known key with that NPF_K_* flag */
/* 0 when v is a valid value of k, else -1 with "key: what it takes" in err. */
int  npf_key_check(const npf_key *k, const char *v, char *err, size_t cap);
/* npf_key_check on every value of a known key in c (unknown keys pass). */
int  npf_conf_check(const npf_conf *c, char *err, size_t cap);
/* An NPF_K_INT key's value, an NPF_K_ENUM key's index in its vals; the
 * default's when unset or invalid; 0 for an unknown or string key. */
int64_t npf_conf_int(const npf_conf *c, const char *key);
/* 1 when the value can be written as one line and read back the same: no
 * control characters, no '#', under 1000 bytes. */
int npf_conf_value_ok(const char *value);

/* Reads a whole file of up to 16 MB into *out (malloc'd, NUL added; the
 * caller frees it). Its length, or -1 (*out unchanged). */
long npf_file_read(const char *path, char **out);
/* After npf_file_read failed: 0 when the file does not exist, else an errno
 * value (EACCES; EIO when it opens but did not read). */
int  npf_file_unreadable(const char *path);
/* Replaces the file atomically: a new path.tmp (one left there is removed
 * first, never written through) with mode, flushed, renamed over path; on
 * POSIX the directory is synced too. On Windows a mode without group or
 * other bits gives the file a DACL of SYSTEM, Administrators and the owner
 * only. 0, or -1. */
int npf_file_write(const char *path, const void *data, size_t len, int mode);

#endif

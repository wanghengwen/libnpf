/* "key = value" configuration files and small file helpers. */
#ifndef NPF_CONF_H
#define NPF_CONF_H

#include <stddef.h>
#include <stdint.h>

#define NPF_CONF_MAX     128    /* entries */
#define NPF_CONF_KEY_MAX 48     /* bytes of a key, its NUL included */
#define NPF_CONF_VAL_MAX 1024   /* bytes of a value, its NUL included */

/* Entries are allocated as they are set (a zeroed npf_conf is empty; free it
 * with npf_conf_free, copy it with npf_conf_copy, never by assignment). A
 * value read with npf_conf_get stays valid until npf_conf_free: a longer
 * value set later takes a new buffer and the old one is kept until then. */
typedef struct npf_conf {
    int     n;
    size_t  cap;
    char  **key, **val;         /* n entries */
    size_t *room;               /* bytes each val has */
    char  **old;                /* values replaced by longer ones: freed with the conf */
    int     nold;
    char    path[1024];         /* the file, absolute */
    char    bad[NPF_CONF_KEY_MAX]; /* the first key whose value was too long (dropped) */
} npf_conf;

void npf_conf_free(npf_conf *c);
/* dst (freed first) becomes a copy of src; 0, or -1 when out of memory */
int  npf_conf_copy(npf_conf *dst, const npf_conf *src);

/* Lines "key = value"; '#' starts a comment. Returns 0 or -1 (unreadable).
 * Relative paths in the path-valued keys (dir, state, serverlist,
 * serverlist_saved, direct_psk_file, log, pidfile) are taken relative to the
 * directory of the configuration file, so a daemon or service finds them
 * whatever its working directory. */
int npf_conf_load(npf_conf *c, const char *path);
const char *npf_conf_get(const npf_conf *c, const char *key, const char *def);
/* repeatable keys ("peer"): the i-th value, NULL past the last */
const char *npf_conf_get_n(const npf_conf *c, const char *key, int i);
/* a path-valued key; when unset, def_name next to the configuration file.
 * out holds cap bytes; returns out. */
const char *npf_conf_get_path(const npf_conf *c, const char *key, const char *def_name, char *out, size_t cap);
int npf_conf_set(npf_conf *c, const char *key, const char *val);
/* set, a relative value of a path-valued key taken next to the file conf_path */
void npf_conf_set_rel(npf_conf *c, const char *conf_path, const char *key, const char *val);

/* libnpf's keys, one table (conf.c, architecture.md 7.1): each key's type,
 * range, default and where it may come from; a module's keys are its own
 * (npf_module.keys and check) */
enum { NPF_K_STR, NPF_K_INT, NPF_K_ENUM };      /* a flag is an NPF_K_INT of 0..1 */
enum {
    NPF_K_FILE = 1,         /* npf.conf (or npf_setup) only: where to connect, what to trust or run, the files written */
    NPF_K_LIVE = 2,         /* npf_config_set: in effect at once */
    NPF_K_SECRET = 4,       /* its value never shown (npf_config_get: "(hidden)") nor logged */
    NPF_K_SETUP = 8,        /* an npf_setup field gives it: not in the overrides as well */
    NPF_K_PATH = 16,        /* relative to the configuration file's directory */
    NPF_K_MULTI = 32,       /* each line adds a value */
    NPF_K_UNLISTED = 64,    /* live, not in npf_config's list (npf-hosted sets it) */
};
typedef struct npf_key {
    const char *name;
    uint8_t     type, flags;
    int64_t     lo, hi;             /* NPF_K_INT */
    const char *def;                /* when unset ("": none) */
    const char *vals;               /* NPF_K_ENUM: "a|b|c" */
} npf_key;
const npf_key *npf_key_find(const char *name);         /* NULL: not libnpf's */
const npf_key *npf_key_next(const npf_key *k);          /* the first after k (NULL: the first; NULL at the end) */
int  npf_key_is(const char *name, int flag);            /* libnpf's, with the NPF_K_* flag */
/* a value of k: 0, or -1 with "key: what it takes" in err */
int  npf_key_check(const npf_key *k, const char *v, char *err, size_t cap);
/* every value of a key of libnpf's in c: 0, or -1 (err as above) */
int  npf_conf_check(const npf_conf *c, char *err, size_t cap);
/* an NPF_K_INT's value (its default when unset or bad), an NPF_K_ENUM's index in its values */
int64_t npf_conf_int(const npf_conf *c, const char *key);
/* a value that can be written as one line and read back the same: no
 * control characters (a line break would add lines), no '#' (a comment) */
int npf_conf_value_ok(const char *value);

/* Read a whole file (NUL-terminated). Returns length or -1. *out is malloc'd. */
long npf_file_read(const char *path, char **out);
/* after npf_file_read failed: why the file is there but cannot be read (an
 * errno value: EACCES, EIO when it opened but did not read through), 0 when
 * it is not there (a first run) */
int  npf_file_unreadable(const char *path);
/* Atomic replace: temp file, fsync, rename. mode e.g. 0600. Returns 0 or -1. */
int npf_file_write(const char *path, const void *data, size_t len, int mode);

#endif

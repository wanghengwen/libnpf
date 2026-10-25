/* "key = value" configuration files and small file helpers. */
#ifndef NPF_CONF_H
#define NPF_CONF_H

#include <stddef.h>

#define NPF_CONF_MAX     128    /* entries */
#define NPF_CONF_KEY_MAX 48     /* bytes of a key, its NUL included */
#define NPF_CONF_VAL_MAX 1024   /* bytes of a value, its NUL included */

/* Entries are allocated as they are set (a zeroed npf_conf is empty; free it
 * with npf_conf_free, copy it with npf_conf_copy, never by assignment). A
 * value read with npf_conf_get stays valid until npf_conf_free: a longer
 * value set later takes a new buffer and the old one is kept until then. */
typedef struct npf_conf {
    int     n, cap;
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

/* Edit the file in place, keeping comments and the other lines (atomic
 * replace, mode 0600). value NULL removes. For a single-valued key: every
 * line of the key goes and "key = value" is written where the first one was
 * (at the end if there was none). For a repeatable key ("peer"): old != NULL
 * removes the lines with that value, value != NULL appends a line. 0 or -1. */
int npf_conf_file_edit(const char *path, const char *key, const char *old, const char *value);
/* a key the programs read (the configuration accepts others silently) */
/* where to connect, what to trust, the files written: npf.conf only */
int  npf_conf_file_only(const char *key);
int npf_conf_known(const char *key);
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

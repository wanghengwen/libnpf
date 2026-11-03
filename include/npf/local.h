/* local.json in the data directory: what an instance saves at run time (npf.conf
 * is only read). Internal to libnpf; in include/npf because npf's modules
 * read and write the instance's record (struct npf.lc: names, nicks, their
 * own per-device keys) and npf's app keeps the start options in it.
 *
 *   {"settings": {"log_level": "debug", ...},          npf_config_set with save
 *    "start":    ["--log", "/tmp/npf.log", ...],       the options of npf start
 *    "devices":  {"611631552": {                       per peer target (number or HOST:PORT)
 *        "name": "dev", "nick": "...",                 its name and nick
 *        "save": true,                                 a saved peer, connected at every start
 *        "connect": "on_demand", "idle_ms": 300000,    a saved peer on demand
 *        "forwards": [{"kind": "local", "proto": "tcp", "listen": "127.0.0.1",
 *                      "port": 28290, "host": "127.0.0.1", "hostport": 28290}],
 *                                                      saved forwards (local, socks, remote; a
 *                                                      module's: its letter and "spec")
 *        "psk_file": "key", "psk": "...",              a direct peer's key: a file, or base64url
 *        "key": "<base64url>",                         the peer's pinned public key
 *        "resources": [...],                           what it published, as last heard
 *        "remote_name": "...",                         its own name, as last heard
 *        "by": "<fingerprint>", "added": 1793000000,   added by a remote admin (a forward too)
 *        ...}},                                        modules' keys (npf_local_ext)
 *    "resources": [...]}                               what this node publishes (npf/resources.h)
 *
 * The file is written atomically with mode 0600, and its text is wiped from
 * memory after reading and writing: it may hold direct peers' keys. Not
 * thread-safe: the instance's record is used on the instance's thread only. */
#ifndef NPF_LOCAL_H
#define NPF_LOCAL_H

#include <stdint.h>

#include "npf/conf.h"

#define NPF_LOCAL_MAX_DEV   256
#define NPF_LOCAL_MAX_FWD   16
#define NPF_LOCAL_MAX_START 32
#define NPF_LOCAL_MAX_EXT   8       /* the modules' keys, per device */
#define NPF_LOCAL_EXT_KEY   47      /* bytes of a module's key, at most */
#define NPF_NICK_MAX        128     /* bytes of UTF-8 (the platform takes 128) */
#define NPF_PEER_NAME_MAX   128     /* a peer's own name (npf name), as it sends it: bytes of UTF-8 */

/* a saved forward */
typedef struct npf_lfwd {
    char opt;                       /* 'L', 'D', 'R', or a module's kind's capital letter */
    int  udp;
    char bind[64];
    int  port;                      /* as asked: 0 picked */
    char host[256];
    int  hostport;
    char spec[300];                 /* a module's kind: in its own form */
    char by[17];                    /* added by a remote admin: its key's fingerprint (hex); "" here */
    int64_t added;                  /* then (Unix s) */
} npf_lfwd;

typedef struct npf_ldev {
    char    target[300];            /* a number, or HOST:PORT */
    char    name[33];
    char    nick[NPF_NICK_MAX + 1];
    int     save;
    int     on_demand;              /* a saved peer's connect: NPF_CONNECT_ON_DEMAND, else KEEP */
    int     idle_ms;                /* its idle time; 0: the instance's peer_idle */
    char    psk_file[512];          /* a direct peer's key file; relative: to the data directory */
    char    psk[64];                /* or its key, base64url (a secret) */
    int     nfwd;
    npf_lfwd *fwd;                  /* nfwd saved forwards (npf_local_fwd_*) */
    int     has_key;
    uint8_t key[32];                /* the pinned public key, when has_key */
    char   *resources;              /* its resources as last heard: a normalised JSON array, or NULL */
    char    remote_name[NPF_PEER_NAME_MAX + 1];    /* its own name as last heard (npf_text_display); "" none */
    char    by[17];                 /* a saved peer a remote admin added: its key's fingerprint; "" here */
    int64_t added;                  /* then (Unix s) */
    int     next;                   /* the modules' keys (npf_local_ext) */
    struct npf_lext { char *key, *val; } *ext;
} npf_ldev;

typedef struct npf_local {
    char      path[1000];
    npf_conf  settings;
    int       nstart;
    char    **start;                /* the start options */
    int       ndev;
    size_t    cap;
    npf_ldev *dev;                  /* ndev records */
    char     *resources;            /* what this node publishes: a JSON array, or NULL */
    int       unsaved;              /* 1 after a failed save, until a save succeeds */
} npf_local;

/* Reads dir/local.json into l (l is overwritten, not freed: free a loaded
 * one first). A missing file gives an empty record. A relative value of a
 * path-valued setting is taken against dir. 0, or -1 with err: the file is
 * there but cannot be read, or is not valid. Free l with npf_local_free
 * either way. */
int  npf_local_load(npf_local *l, const char *dir, char *err, size_t errcap);
/* Writes the whole record to the file. A device record with no name, nick,
 * save, pinned key or module key is left out. 0, or -1 (unsaved set). */
int  npf_local_save(npf_local *l);
/* Frees what l holds; it is an empty record after. */
void npf_local_free(npf_local *l);
/* Adds one start option (copied). 0, or -1: NPF_LOCAL_MAX_START, or no memory. */
int  npf_local_start_add(npf_local *l, const char *opt);
void npf_local_start_clear(npf_local *l);

/* 1 when s is a forward's option word: '-' and one capital letter (-L, -D,
 * -R, or a module's kind, npf_peers_add_kind). */
static inline int npf_fwd_opt(const char *s)
{
    return s[0] == '-' && s[1] >= 'A' && s[1] <= 'Z' && !s[2];
}

/* The record of a target (number or HOST:PORT). create: make an empty one
 * when there is none (NULL: NPF_LOCAL_MAX_DEV, or no memory). The pointer is
 * valid until a record is created or dropped. */
npf_ldev *npf_local_dev(npf_local *l, const char *target, int create);
npf_ldev *npf_local_by_name(npf_local *l, const char *name);
/* Removes the target's record with everything in it. 0, or -1 none. */
int  npf_local_drop(npf_local *l, const char *target);
/* Adds a saved forward (copied) unless an equal one is there. 0, or -1:
 * NPF_LOCAL_MAX_FWD, or no memory. */
int  npf_local_fwd_add(npf_ldev *d, const npf_lfwd *f);
int  npf_local_fwd_del(npf_ldev *d, const npf_lfwd *f);    /* 0, or -1 none equal */
void npf_local_fwd_clear(npf_ldev *d);
/* A module's own key in a device record (not one of the keys above): its
 * value as JSON text, NULL when unset; valid until the key is set again.
 * npf_local_ext_set copies json, which must be valid JSON (it is written to
 * the file unchecked); NULL removes the key. 0, or -1: NPF_LOCAL_MAX_EXT
 * keys, a key longer than NPF_LOCAL_EXT_KEY, or no memory. */
const char *npf_local_ext(const npf_ldev *d, const char *key);
int  npf_local_ext_set(npf_ldev *d, const char *key, const char *json);

/* 1 for a valid peer name: 1..32 of letters, digits, '.', '_', '-', not
 * only digits, not "all". */
int  npf_name_valid(const char *s);
/* 1 for a valid nick: up to NPF_NICK_MAX bytes, no control characters. */
int  npf_nick_valid(const char *s);

#endif

/* local.json: what npf keeps for itself in the writable directory, next to
 * the identity (npf.conf, written by people, is only read):
 *
 *   {"settings": {"log_level": "debug", ...},          npf set
 *    "start":    ["--log", "/tmp/npf.log", ...],       the options of npf start
 *    "devices":  {"611631552": {                       per device (number or HOST:PORT)
 *        "name": "dev",                                npf connect/devices --name: stands for the number
 *        "nick": "上海测试机",                         --nick: a note to remember it by
 *        "save": true,                                 connect --save: connected at every start
 *        "connect": "on_demand", "idle_ms": 300000,     a saved peer on demand (npf_peer_opt.connect)
 *        "forwards": [{"kind": "local", "proto": "tcp", "listen": "127.0.0.1",
 *                      "port": 28290, "host": "127.0.0.1", "hostport": 28290}],
 *                                                      its saved forwards (kind local, socks,
 *                                                      remote; a module's: its letter and "spec")
 *        "psk_file": "key", "psk": "...",              a direct peer's key
 *        "key": "<base64url>",                         the pinned public key (pairing)
 *        "resources": [...],                           what it published, as last heard (resources.h)
 *        ...}},                                        the modules' keys (npf_local_ext)
 *    "resources": [{"name", "target", "type", "desc", "path"}]   what this node publishes
 *
 * The secrets (identity, state.json, control.token) and the certificates
 * stay in files of their own. A local.conf of "key = value" lines and a
 * "known" file of earlier versions are converted once, then renamed *.old.
 * Written atomically; at most NPF_LOCAL_MAX_DEV devices. */
#ifndef NPF_LOCAL_H
#define NPF_LOCAL_H

#include <stdint.h>

#include "npf/conf.h"

#define NPF_LOCAL_MAX_DEV   256
#define NPF_LOCAL_MAX_FWD   16
#define NPF_LOCAL_MAX_START 32
#define NPF_LOCAL_MAX_EXT   8       /* the modules' keys, per device */
#define NPF_NICK_MAX        128     /* bytes of UTF-8 (the platform takes 128) */

/* a saved forward */
typedef struct npf_lfwd {
    char opt;                       /* 'L', 'D', 'R', or a module's kind (its capital letter) */
    int  udp;
    char bind[64];
    int  port;                      /* as asked: 0 picked */
    char host[256];
    int  hostport;
    char spec[300];                 /* a module's kind: in its own form */
} npf_lfwd;

typedef struct npf_ldev {
    char    target[300];            /* a number, or HOST:PORT */
    char    name[33];
    char    nick[NPF_NICK_MAX + 1];
    int     save;
    int     on_demand;              /* a saved peer's connect: NPF_CONNECT_ON_DEMAND (else KEEP) */
    int     idle_ms;                /* ... its idle time, 0: the instance's */
    char    psk_file[512];
    char    psk[64];
    int     nfwd;
    npf_lfwd *fwd;                  /* nfwd saved forwards, at most NPF_LOCAL_MAX_FWD (npf_local_fwd_*) */
    int     has_key;
    uint8_t key[32];
    char   *resources;              /* its resources as last heard: a JSON array (npf_res_normalize), or NULL */
    int     next;                   /* the modules' keys and their values (JSON text): npf_local_ext */
    char  **ext_key, **ext_val;
} npf_ldev;

typedef struct npf_local {
    char      path[1000];
    npf_conf  settings;
    int       nstart;
    char    **start;                /* nstart options (npf_local_start_add), at most NPF_LOCAL_MAX_START */
    int       ndev, cap;
    npf_ldev *dev;                  /* grown as needed, at most NPF_LOCAL_MAX_DEV */
    char     *resources;            /* what this node publishes: a JSON array, or NULL (none) */
    int       unsaved;              /* the last save failed: what is in memory is not in the file yet */
} npf_local;

/* local.json in dir (converting the files of earlier versions once). A
 * missing file is an empty record. Returns 0, or -1 with err (unreadable,
 * not our JSON). */
int  npf_local_load(npf_local *l, const char *dir, char *err, size_t errcap);
/* the whole record into the file (atomically); 0, or -1 (l->unsaved set
 * until a save succeeds) */
int  npf_local_save(npf_local *l);
/* frees what the record holds (settings, start options, devices); l is empty after */
void npf_local_free(npf_local *l);
/* the start options: one more (0, -1 full or out of memory), or none */
int  npf_local_start_add(npf_local *l, const char *opt);
void npf_local_start_clear(npf_local *l);

/* a forward's option word: -L, -D, -R, or a module's kind (npf_peers_add_kind):
 * a capital letter */
static inline int npf_fwd_opt(const char *s)
{
    return s[0] == '-' && s[1] >= 'A' && s[1] <= 'Z' && !s[2];
}

/* a device's record (valid until the next one is created: the table grows);
 * create: make an empty one when there is none (NULL
 * when full). A record with nothing left in it is dropped at the save. */
npf_ldev *npf_local_dev(npf_local *l, const char *target, int create);
npf_ldev *npf_local_by_name(npf_local *l, const char *name);
/* forget a device: its record goes (name, nick, saved forwards, key); 0, -1 none */
int  npf_local_drop(npf_local *l, const char *target);
int  npf_local_fwd_add(npf_ldev *d, const npf_lfwd *f);    /* 0 (there already too), -1 full */
int  npf_local_fwd_del(npf_ldev *d, const npf_lfwd *f);    /* 0, -1 none */
int  npf_local_fwd_same(const npf_lfwd *a, const npf_lfwd *b);
void npf_local_fwd_clear(npf_ldev *d);
/* a module's key in the device's record (a key of its own, not one of the
 * above): its value as JSON text, NULL none; set (json NULL: removed) 0, or
 * -1 (full, no memory). Kept in the file as they are */
const char *npf_local_ext(const npf_ldev *d, const char *key);
int  npf_local_ext_set(npf_ldev *d, const char *key, const char *json);

/* a name: 1..32 of letters, digits, '.', '_', '-', not only digits, not "all" */
int  npf_name_valid(const char *s);
/* a nick: up to NPF_NICK_MAX bytes, no control characters */
int  npf_nick_valid(const char *s);

#endif

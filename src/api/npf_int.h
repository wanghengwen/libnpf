/* libnpf internals: the npf_t behind npf.h, and what the program's modules
 * (npf/module.h) use of it. Everything here runs on the instance's thread
 * (api.c moves calls from other threads onto it); what only src/api uses
 * is in api_internal.h. */
#ifndef NPF_INT_H
#define NPF_INT_H

#include "npf.h"
#include "npf/callee.h"
#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/out.h"
#include "npf/local.h"
#include "npf/peers.h"
#include "npf/platform.h"
#include "npf/tunnel.h"
#include "npf/version.h"

#define NPF_MAX_SESS  256
#define NPF_MAX_MEDIA NPF_MEDIA_STREAMS_MAX
#define NPF_MOD_MAX   8          /* modules (npf/module.h) */

typedef struct npf_sess {
    uint32_t  id;
    npf_call *call;
    uint32_t  peer;                 /* its peer's number (npf_peer_id), 0: someone calling here */
} npf_sess;

typedef struct npf_med {
    uint32_t  id, session;
    npf_call *call;
    uint32_t  lid;                  /* its number in the session (node/media.h) */
} npf_med;

struct npf_api_sync;

struct npf {
    struct npf_api_sync *sync;
    int           role;
    char          app_name[33], app_ver[33];  /* the program (npf_options) */
    npf_callbacks cb;
    /* configuration: npf.conf, the overrides and local.json's settings in
     * effect (later ones win, peer lines add up); and each alone (where a peer
     * is from). local.json also keeps the devices (npf/local.h) */
    npf_conf      conf;
    npf_local     lc;
    char         *conf_dir, *data_dir;   /* malloc (path_set) */
    /* identity (data_dir) */
    int           cred;             /* NPFD1 device credential */
    int           model_dev;        /* NPFV1 model credential: enrols */
    int           has_number;
    uint64_t      number;
    char          default_pw[64];
    char         *cert_path, *node_path, *state_path;
    char          account_login[128];         /* the account's email, phone or name (account_get); "" unknown */
    npf_enroll_req enroll;
    npf_identity  id;
    npf_callee   *callee;          /* a node with a number only (allocated then) */
    /* runtime */
    npf_loop     *loop;
    npf_node      node;
    npf_node_cfg  cfg;
    npf_peers    *peers;
    npf_policy    policy;           /* a client's / a direct listener's sessions */
    struct npf_res *res;            /* the published resources (publish.c), nres of them */
    int           nres;
    npf_direct   *dl;
    /* state shared with other threads: under the API lock (api.c) */
    int           started, running, stopping, ended, torn_down;
    int           end_stage;        /* npf_engine_end_step */
    npf_runtime  *rt;               /* a shared runtime's (npf_options.runtime), or NULL */
    int           rt_slot;          /* its thread */
    void         *thread;
    unsigned long loop_tid;
    int           exec_busy;        /* not running: a caller executes a call (they take turns) */
    unsigned long exec_owner;
    unsigned      send_jobs;        /* also bound metadata for tiny frames */
    size_t        send_queued;      /* media frames posted from other threads, bytes */
    /* this instance's log: level, recent lines, the application's callback */
    npf_log_ctx   logctx;
    /* sessions and media streams by number */
    npf_sess     *sess;             /* nsess of capsess, grown up to NPF_MAX_SESS */
    int           nsess, capsess;
    uint32_t      next_sess;
    npf_med      *med;              /* NPF_MAX_MEDIA, made with the first stream (under the API lock) */
    int           nmed;
    uint32_t      next_med;
    /* the modules registered when it was created (npf/module.h), NULL at
     * the end, and the state of each */
    const struct npf_module *mods[NPF_MOD_MAX + 1];
    void         *mod_state[NPF_MOD_MAX];
    int           mods_created;     /* the first ones made (their create done): only they end and are destroyed */
    int           mods_made;        /* npf_mods_create done: the hooks are called from then on */
    /* what a hosted client's tunnels may spend (its account's quota; a
     * module keeps it filled) */
    npf_budget    budget;
    int           opt_flags;        /* npf_options.flags: NPF_OPT_* */
    int64_t       started_unix;     /* the run's start (Unix s), 0 not running */
};

/* A peer's tag (npf/peers.h) says where it comes from, as npf_peer_info.flags
 * does: 0 the application's for this run, NPF_PERSIST saved in local.json (or
 * brought back from it), NPF_PLATFORM opened for port mappings saved on the
 * platform. Its name: "temporary", "saved", "platform" */
const char *npf_source_name(int tag);
/* a peer's record in local.json: saved (connected at every start, with its
 * saved forwards) or not; psk_file: a direct peer's key file as given, NULL
 * its key. NPF_OK, NPF_ESAVE */
int  npf_ops_record(npf_t *n, npf_peer *p, int save, const char *psk_file);
/* a saved peer's forward into its record or out of it: NPF_OK, NPF_ESAVE */
int  npf_ops_record_fwd(npf_t *n, npf_peer *p, int i, int add);

/* an event to the application (npf_callbacks.event): the library's, a module's */
void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)))
#endif
    ;
/* the status object (npf_status_json) */
void npf_status_out(npf_t *n, npf_out *o);
/* a device enrolled at run time got its number: keep it, become callable */
int  npf_become_node(npf_t *n, uint64_t number);

/* published resources (publish.c, resources.h): add or replace (by name) /
 * remove one (name NULL: all but npf.conf's): NPF_OK, NPF_ESAVE, or an error
 * with the reason in err */
int  npf_pub_put(npf_t *n, const struct npf_res *r, char *err, size_t errcap);
int  npf_pub_remove(npf_t *n, const char *name, char *err, size_t errcap);

/* cmd.c: a command (argv[0] = its name); the exit code with the text in o
 * (0 done, 1 failed, 2 a bad command, NPF_CMD_UNSAVED done but local.json
 * not written: it is with the next change saved), or -1 when it answers
 * later through cb. libnpf's own commands come before the modules' */
#define NPF_CMD_UNSAVED 3
int  npf_cmd_run(npf_t *n, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user);
int  npf_cmd_builtin(const char *name);     /* one of libnpf's own commands? */
void npf_cmd_config_json(npf_t *n, npf_out *o);
int  npf_cmd_set(npf_t *n, const char *k, const char *v, int save, npf_out *o);
const char *npf_cmd_get(npf_t *n, const char *k, char *buf, size_t cap);
int  npf_cmd_is_settable(const char *k);
int  npf_cmd_is_secret(const char *k);

#endif

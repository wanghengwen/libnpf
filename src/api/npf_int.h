/* libnpf internals: the npf_t behind npf.h. Everything here runs on the
 * library thread (the loop); api.c moves calls from other threads onto it. */
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

/* where a peer comes from (npf_peer_info.flags) */
enum { PEER_TEMP = 0,       /* the application's, not saved */
       PEER_SAVED = 1,      /* the application's saved in local.json, or brought back from it */
       PEER_PLATFORM = 3 }; /* opened for port mappings saved on the platform */

#define NPF_MAX_SESS  256
#define NPF_MAX_MEDIA NPF_MEDIA_STREAMS_MAX
#define NPF_MOD_MAX   8          /* modules (npf/module.h) */

typedef struct npf_sess {
    uint32_t  id;
    npf_call *call;
    uint32_t  peer;                 /* its peer's number (npf_peer_id), 0: someone calling here */
    void     *ctx;                  /* the peer's ctx when it came up (the peer may go first) */
    uint64_t  number;               /* the other side's, 0 none */
    int       outgoing, path;       /* NPF_PATH_* */
} npf_sess;

struct npf_evi;

typedef struct npf_med {
    uint32_t  id, session;
    npf_call *call;
    size_t    frame_max;
    uint32_t  lid;                  /* its number in the session (node/media.h) */
} npf_med;

struct npf_bindjob;

struct npf_api_sync;

struct npf {
    struct npf_api_sync *sync;
    int           role;
    char          app_name[33], app_ver[33];  /* the program (npf_options) */
    npf_callbacks cb;
    /* configuration: npf.conf, the overrides and local.json's settings in
     * effect (later ones win, peer lines add up); and each alone (where a peer
     * is from). local.json also keeps the devices (npf/local.h) */
    npf_conf      conf, ro, ov;
    npf_local     lc;
    char         *conf_dir, *data_dir;   /* malloc (path_set) */
    const char   *local_path;           /* lc.path */
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
    struct npf_res *res;            /* the published resources (publish.c), NPF_RES_MAX of room */
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
    npf_med       med[NPF_MAX_MEDIA];
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
    /* typed events (events.c) */
    struct npf_evi *ev_head, *ev_tail;
    npf_timer    *ev_timer;
    int           ev_on, ev_flushing;
    int           opt_flags;        /* npf_options.flags: NPF_OPT_* */
    int           from_setup;       /* started from npf_setup (no configuration file) */
    int64_t       started_unix;     /* the run's start (Unix s), 0 not running */
};

/* api.c: an operation for the instance (on its thread while it runs, else
 * on the caller's), with the API's entry checks: its result, or NPF_ESTATE
 * when it did not run */
int  npf_api_op(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg);

/* events.c: the typed events (npf_callbacks.notify) */
int  npf_events_typed(const npf_t *n);              /* notify set: the legacy events are not sent */
void npf_ev_queue(npf_t *n, const npf_event *ev);   /* strings copied */
void npf_ev_simple(npf_t *n, int type, const char *why);
void npf_events_flush(npf_t *n);                     /* before a data or media callback: SESSION_UP first */
void npf_events_start(npf_t *n);
void npf_events_stop(npf_t *n);                      /* NPF_EV_STOPPED, the last */
void npf_events_clear(npf_t *n);
int  npf_end_code(const char *why, int local);

/* setup.c: npf_setup's fields as configuration keys (c); 0, or -1 with err */
int  npf_setup_conf(const npf_setup *s, int role, const char *data_dir, npf_conf *c, char *err, size_t errcap);
/* a key of the overrides that is a field of npf_setup, NULL none */
const char *npf_setup_key_taken(const npf_conf *ov);
/* engine.c: the account session began or ended (event "account" / NPF_EV_ACCOUNT) */
void npf_ev_account(npf_t *n);

/* ops.c: the operations of npf.h's objects, shared with the command line */
uint32_t npf_ops_flags(const npf_t *n, const npf_peer *p);  /* NPF_PERSIST, NPF_PLATFORM */
int  npf_path_code(const char *path);                /* npf_call_path as NPF_PATH_*, 0 none */
/* a peer's record in local.json: saved (connected at every start, with its
 * saved forwards) or not; psk_file: a direct peer's key file as given, NULL
 * its key. NPF_OK, NPF_ESAVE */
int  npf_ops_record(npf_t *n, npf_peer *p, int save, const char *psk_file);
/* a saved peer's forward into its record or out of it: NPF_OK, NPF_ESAVE */
int  npf_ops_record_fwd(npf_t *n, npf_peer *p, int i, int add);

/* api.c: the lock of the state above, of the media registry (npf_media_send
 * reads it on any thread) */
int  npf_api_init(npf_t *n);
void npf_api_fini(npf_t *n);
void npf_api_lock(npf_t *n);
void npf_api_unlock(npf_t *n);

/* engine.c */
int  npf_app_name_valid(const char *s);
int  npf_app_ver_valid(const char *s);
/* a public structure's defaults into the application's size bytes (engine.c) */
void npf_init_sized(void *s, size_t size, const void *d, size_t dsize);
void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)))
#endif
    ;
uint32_t npf_session_of(npf_t *n, npf_call *call);
npf_call *npf_session_call(npf_t *n, uint32_t id);
void npf_save_account_cert(npf_t *n);
void npf_forget_account(npf_t *n);
/* ask for the account's login name (status "account_login") once a session is there */
void npf_account_info(npf_t *n);
/* a console node got its number (node_enroll): keep it, become callable */
int  npf_become_node(npf_t *n, uint64_t number, char *pw_out);
void npf_start_peers(npf_t *n);
void npf_random_password(char out[10]);
/* {"session", "peer", "path", "direction", "call_id"} */
void npf_session_info_out(npf_t *n, npf_call *call, npf_out *o);
uint32_t npf_media_add(npf_t *n, uint32_t session, npf_call *call, uint32_t lid);
npf_med *npf_media_find(npf_t *n, uint32_t id);
void npf_media_forget(npf_t *n, uint32_t id);
/* the run on the library thread: the node until npf_loop_stop, then its end */
int  npf_engine_run(npf_t *n);
void npf_engine_begin(npf_t *n);
int  npf_engine_end_step(npf_t *n);
/* a shared runtime: the loop of an instance on one of its threads (api.c) */
npf_loop *npf_runtime_child(npf_runtime *rt, int *slot);
void npf_runtime_leave(npf_runtime *rt, int slot);
npf_loop *npf_engine_loop(npf_t *n);
void npf_engine_free(npf_t *n);

/* cmd.c: a command (argv[0] = its name); the exit code with the text in o
 * (0 done, 1 failed, 2 a bad command, NPF_CMD_UNSAVED done but local.json
 * not written: it is with the next change saved), or -1 when it answers
 * later through cb. libnpf's own commands come before the modules' */
#define NPF_CMD_UNSAVED 3
int  npf_cmd_run(npf_t *n, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user);
int  npf_cmd_builtin(const char *name);     /* one of libnpf's own commands? */
void npf_cmd_status_json(npf_t *n, npf_out *o);
void npf_cmd_config_json(npf_t *n, npf_out *o);
/* where a peer comes from (npf/peers.h tags): "saved", "platform", "temporary" */
const char *npf_cmd_tag_name(int tag);
/* published resources (publish.c, resources.h) */
int  npf_pub_load(npf_t *n, char *err, size_t errcap);  /* npf.conf + local.json, the policy */
int  npf_pub_apply(npf_t *n);                           /* the policy again (a node now) */
void npf_pub_free(npf_t *n);
void npf_pub_send(npf_t *n, npf_call *c);               /* to a caller whose session came up */
void npf_pub_json(npf_t *n, npf_out *o);                /* this node's list (status) */
void npf_pub_heard(npf_t *n, npf_call *c, const npf_json *j, int d);
int  npf_cmd_resource(npf_t *n, int argc, char **argv, npf_out *o);
/* add or replace (by name) / remove one (name NULL: all but npf.conf's):
 * NPF_OK, NPF_ESAVE, or an error with the reason in err */
int  npf_pub_put(npf_t *n, const struct npf_res *r, char *err, size_t errcap);
int  npf_pub_remove(npf_t *n, const char *name, char *err, size_t errcap);
int  npf_cmd_set(npf_t *n, const char *k, const char *v, int save, npf_out *o);
const char *npf_cmd_get(npf_t *n, const char *k, char *buf, size_t cap);
void npf_cmd_sessions_json(npf_t *n, npf_out *o);
int  npf_cmd_is_settable(const char *k);
int  npf_cmd_is_secret(const char *k);

/* platform.c */
int  npf_plat_request(npf_t *n, const char *type, const char *data, int proof, npf_reply_cb cb, void *user,
                      npf_out *err);

#endif

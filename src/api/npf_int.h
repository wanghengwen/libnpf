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

/* where a peer comes from */
enum { PEER_TEMP = 0,       /* npf_peer_add without SAVE, connect */
       PEER_SAVED = 1,      /* local.json (data_dir): can be unsaved */
       PEER_OPTION = 2,     /* the options' overrides (npf run --node) */
       PEER_PLATFORM = 3,   /* opened for port mappings saved on the platform */
       PEER_FIXED = 4 };    /* npf.conf (conf_dir, read-only) */

#define NPF_MAX_SESS  256
#define NPF_MAX_MEDIA NPF_MEDIA_STREAMS_MAX
#define NPF_MOD_MAX   8          /* modules (npf/module.h) */

typedef struct npf_sess {
    uint32_t  id;
    npf_call *call;
} npf_sess;

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
    int           mods_made;        /* npf_mods_create done: the hooks are called from then on */
    /* what a hosted client's tunnels may spend (its account's quota; a
     * module keeps it filled) */
    npf_budget    budget;
};

/* api.c: the lock of the state above, of the media registry (npf_media_send
 * reads it on any thread) */
int  npf_api_init(npf_t *n);
void npf_api_fini(npf_t *n);
void npf_api_lock(npf_t *n);
void npf_api_unlock(npf_t *n);

/* engine.c */
int  npf_app_name_valid(const char *s);
int  npf_app_ver_valid(const char *s);
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
void npf_session_info(npf_t *n, npf_call *call, npf_out *o);
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

/* cmd.c: a command (argv[0] = its name); 0.. the exit code with the text in o,
 * or -1 when it answers later through cb */
int  npf_cmd_run(npf_t *n, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user);
void npf_cmd_status_json(npf_t *n, npf_out *o);
void npf_cmd_config_json(npf_t *n, npf_out *o);
int  npf_cmd_peer_add(npf_t *n, int argc, char **argv, int flags, npf_out *o);
int  npf_cmd_peer_remove(npf_t *n, const char *name, int unsave, npf_out *o);
int  npf_cmd_forward(npf_t *n, int argc, char **argv, npf_out *o);
/* cmd_peers.c (NPF_PEERS; else cmd_peers_none.c): node and its subcommands */
int  npf_cmd_node(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o);
/* where a peer comes from (npf/peers.h tags): "saved", "config", "--node", "platform", "temporary" */
const char *npf_cmd_tag_name(int tag);
/* published resources (publish.c, resources.h) */
int  npf_pub_load(npf_t *n, char *err, size_t errcap);  /* npf.conf + local.json, the policy */
int  npf_pub_apply(npf_t *n);                           /* the policy again (a node now) */
void npf_pub_free(npf_t *n);
void npf_pub_send(npf_t *n, npf_call *c);               /* to a caller whose session came up */
void npf_pub_json(npf_t *n, npf_out *o);                /* this node's list (status) */
void npf_pub_heard(npf_t *n, npf_call *c, const npf_json *j, int d);
int  npf_cmd_resource(npf_t *n, int argc, char **argv, npf_out *o);
int  npf_cmd_set(npf_t *n, const char *k, const char *v, int save, npf_out *o);
const char *npf_cmd_get(npf_t *n, const char *k, char *buf, size_t cap);
void npf_cmd_sessions_json(npf_t *n, npf_out *o);
int  npf_cmd_is_settable(const char *k);
int  npf_cmd_is_secret(const char *k);

/* nodes.c: the node command's list and settings (npf/module.h node_list, nick_set) */
int  npf_cmd_nodes(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o);
int  npf_nodes_set_nick(npf_t *n, const char *target, const char *nick, npf_out *o);
void npf_nodes_header(npf_out *o);
/* a node's line; acct: what the account says of it (NULL: "-") */
void npf_nodes_line(npf_t *n, npf_out *o, const char *target, const npf_ldev *d, const char *acct);
/* the lines of local.json's nodes and the peers connected, but those
 * listed (a module's list has them); 1 when there was one */
int  npf_nodes_local(npf_t *n, npf_out *o, int (*listed)(void *arg, const char *target), void *arg);

/* platform.c */
int  npf_plat_request(npf_t *n, const char *type, const char *data, int proof, npf_reply_cb cb, void *user,
                      npf_out *err);

#endif

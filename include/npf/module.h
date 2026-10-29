/* Modules: features a program adds to libnpf without changing it (commands
 * and settings of its own, the platform's events, keys in the status, more
 * kinds of forwards). The modules are the program's own code: it registers
 * them (npf_register_module) before it creates instances (and before it reads
 * npf.conf itself: their keys), and libnpf calls their hooks on each
 * instance's thread, in the order they were registered. Every hook is
 * optional; a module keeps its state per instance (npf_mod_state).
 *
 * This header is a module's interface to libnpf: the instance (struct npf:
 * the members before src/api's own), the hooks, and what libnpf does for modules, with
 * the other headers of include/npf/ for the parts (the node, the peers,
 * local.json ...). A module links the static library target npf_common, not
 * the installed libnpf, and is built again with each version of libnpf. */
#ifndef NPF_MODULE_H
#define NPF_MODULE_H

#include <stddef.h>
#include <stdint.h>

#include "npf.h"
#include "npf/callee.h"
#include "npf/conf.h"
#include "npf/json.h"
#include "npf/local.h"
#include "npf/log.h"
#include "npf/node.h"
#include "npf/peers.h"
#include "npf/platform.h"

#define NPF_MOD_MAX 8          /* modules registered */

/* ---- the instance: the npf_t behind npf.h (src/api) ---- */

struct npf_api_sync;

struct npf {
    int           role;
    char          app_name[33], app_ver[33];  /* the program (npf_options) */
    npf_callbacks cb;
    int           opt_flags;        /* npf_options.flags: NPF_OPT_* */
    /* the configuration in effect: npf.conf (or npf_setup), the overrides
     * and local.json's settings, later ones winning; local.json also keeps
     * the peers, forwards and resources saved (npf/local.h) */
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
    npf_node      node;             /* its cfg: the node's configuration (npf_node_cfg_from_conf) */
    npf_peers    *peers;
    npf_policy    policy;           /* a client's / a direct listener's sessions */
    struct npf_res *res;            /* the published resources (publish.c), nres of them */
    int           nres;
    npf_direct   *dl;
    /* what a hosted client's tunnels may spend (its account's quota; a
     * module keeps it filled) */
    npf_budget    budget;
    int           end_stage;        /* npf_engine_end_step: the run ending */
    int64_t       started_unix;     /* the run's start (Unix s), 0 not running */

    /* ---- src/api's own from here on ---- */
    struct npf_api_sync *sync;
    /* state shared with other threads: under the API lock (api.c) */
    int           started, running, stopping, ended, torn_down;
    npf_runtime  *rt;               /* a shared runtime's (npf_options.runtime), or NULL */
    int           rt_slot;          /* its thread */
    void         *thread;
    unsigned long loop_tid;
    int           exec_busy;        /* not running: a caller executes a call (they take turns) */
    unsigned long exec_owner;
    unsigned      send_jobs;        /* media frames posted from other threads (at most 4096) */
    size_t        send_queued;      /* and their bytes (NPF_MEDIA_SEND_QUEUE) */
    /* this instance's log: level, recent lines, the application's callback */
    npf_log_ctx   logctx;
    /* sessions and media streams by number */
    struct npf_sess *sess;          /* nsess of capsess, grown up to NPF_MAX_SESS */
    int           nsess;
    size_t        capsess;
    uint32_t      next_sess;
    struct npf_med *med;            /* NPF_MAX_MEDIA, made with the first stream (under the API lock) */
    int           nmed;
    uint32_t      next_med;
    /* the modules registered when it was created, NULL at the end, and the
     * state of each */
    const struct npf_module *mods[NPF_MOD_MAX + 1];
    void         *mod_state[NPF_MOD_MAX];
    int           mods_created;     /* the first ones made (their create done): only they end and are destroyed */
    int           mods_made;        /* npf_mods_create done: the hooks are called from then on */
};

struct npf_sublink_stats;

/* a command of the command line (npf_command): argv[0] is its name; 0.. the
 * exit code with the text in o, or -1 when it answers later through cb */
typedef struct npf_mod_cmd {
    const char *name;
    int (*run)(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o);
} npf_mod_cmd;

typedef struct npf_module {
    const char *name;
    /* npf_create (its thread), once the node is there, before the saved
     * peers are brought back: the module's state
     * (npf_mod_set_state); 0, or -1 with err (the instance is not made: this
     * module frees what it made, the modules made before it are destroyed) */
    int  (*create)(npf_t *n, char *err, size_t errcap);
    /* the run begins (the node started) */
    void (*begin)(npf_t *n);
    /* the run ends in steps, the loop going on in between: 0 the sessions
     * still up, 1 after a step 0 that asked for time, 2 the last (timers
     * off, before the peers go). How long the loop should go on before the
     * next step (ms), 0 for no need */
    int  (*end)(npf_t *n, int step);
    /* npf_destroy (also of an instance never run), the last module first:
     * its state freed; only for the modules whose create succeeded */
    void (*destroy)(npf_t *n);

    /* signaling: logged in; a platform event (mappings_changed ...); keep
     * the connection up (on demand: work not done yet) */
    void (*login)(npf_t *n);
    void (*event)(npf_t *n, const char *type, const npf_json *j, int d);
    int  (*sig_busy)(npf_t *n);
    /* an account session started (1) or ended (0): login, logout, delete */
    void (*account)(npf_t *n, int on);
    /* a session's state (NPF_CALL_*) */
    void (*call_state)(npf_t *n, npf_call *call, int st, const char *why);

    /* the peers (npf/peers.h npf_peers_cbs) */
    void (*peer_up)(npf_t *n, npf_peer *p, npf_call *call);
    void (*peer_done)(npf_t *n, npf_peer *p, const char *why);
    void (*peer_fwd)(npf_t *n, npf_peer *p, int i, int up, const char *why);
    void (*peer_opened)(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from);
    void (*peer_conn)(npf_t *n, npf_peer *p, npf_call *call, uint64_t mapping, int port,
                      const struct sockaddr_storage *from, int64_t start, int64_t end,
                      const struct npf_sublink_stats *st);
    void (*peer_refused)(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                         const char *why, int opened);
    /* a peer is removed (npf_peer_remove): 1 when the module opens it again
     * (its sync below), so the reply says so */
    int  (*peer_removing)(npf_t *n, npf_peer *p);
    void (*peer_removed)(npf_t *n);
    /* a peer's nick was set here (local.json): the module may pass it on */
    void (*nick_set)(npf_t *n, const char *target, const char *nick);
    /* a device's saved forwards changed (local.json, saved after): what
     * the module keeps of them in the record goes with them */
    void (*fwds_saved)(npf_t *n, npf_ldev *d);

    /* the command line (npf_command): commands of its own */
    const npf_mod_cmd *cmds;

    /* the status: members of its own in the JSON object, written with
     * npf_out_kstr, npf_out_jkey and the rest (npf/json.h: the commas come by
     * themselves); names with the module's prefix */
    void (*status_json)(npf_t *n, npf_out *o);

    /* its configuration keys (npf.conf, npf set), checked, kept and listed
     * as libnpf's own are (npf/conf.h); NPF_KEY_END ends them */
    const npf_key *keys;
    /* a key that changes at run time (NPF_K_LIVE: log_level, peer_idle,
     * a module's ...) set (npf set, npf_config_set), now in effect */
    void (*conf_set)(npf_t *n, const char *k, const char *v);
} npf_module;

/* Registers a module with libnpf: the instances created from then on have it
 * (an instance takes the modules registered at its npf_create). Any thread;
 * the module stays the program's and must outlive the instances. 0, or -1:
 * NULL, no name, registered already, 8 registered, or a name, command or
 * configuration key that libnpf or a module registered before has. */
int   npf_register_module(const npf_module *m);

/* each module's state in an instance */
void *npf_mod_state(npf_t *n, const npf_module *m);
void  npf_mod_set_state(npf_t *n, const npf_module *m, void *state);

/* ---- what libnpf does for modules ---- */

/* an event to the application (npf_callbacks.event) */
void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)))
#endif
    ;
/* a device enrolled at run time got its number: keep it, become callable */
int  npf_become_node(npf_t *n, uint64_t number);
/* published resources (publish.c, resources.h): add or replace (by name) /
 * remove one (name NULL: all but npf.conf's): NPF_OK, NPF_ESAVE, or an error
 * with the reason in err */
struct npf_res;
int  npf_pub_put(npf_t *n, const struct npf_res *r, char *err, size_t errcap);
int  npf_pub_remove(npf_t *n, const char *name, char *err, size_t errcap);
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
/* a command's exit code (npf_mod_cmd): done, but local.json not written (it
 * is with the next change saved) */
#define NPF_CMD_UNSAVED 3

/* the other modules' hooks, for a module that changes what they hear of:
 * a peer's nick set, a peer about to be removed (1: one opens it again) */
void npf_mods_nick_set(npf_t *n, const char *target, const char *nick);
int  npf_mods_peer_removing(npf_t *n, npf_peer *p);

#endif

/* Modules: a program's own features on libnpf (commands, settings, platform
 * events, status members, kinds of forwards), without changing the library.
 * npf's modules (client/modules) are the users.
 *
 * A module is code of the program. It is registered (npf_register_module)
 * before instances are created, and before the program reads npf.conf
 * itself (its keys must be known). libnpf calls its hooks on each
 * instance's thread, in the order the modules were registered. Every hook
 * is optional; a module keeps its state per instance (npf_mod_state).
 *
 * This header and the include/npf headers it pulls in (node, peers,
 * local.json, ...) are internal: no stable ABI. A module links the build
 * target npf_common, not the installed libnpf, and is rebuilt with each
 * version of libnpf. */
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

/* ---- the instance: the npf_t of npf.h ----
 * Modules use the members before "src/api's own", from the instance's
 * thread (their hooks and commands). */

struct npf_api_sync;

struct npf {
    int           role;             /* NPF_ROLE_* */
    char          app_name[33], app_ver[33];
    npf_callbacks cb;
    int           opt_flags;        /* NPF_OPT_* */
    /* the settings in effect: npf.conf (or npf_setup), the overrides, then
     * local.json's settings, later ones winning */
    npf_conf      conf;
    npf_local     lc;               /* local.json: the settings, peers, forwards and resources saved */
    char         *conf_dir, *data_dir;
    /* the identity */
    int           cred;             /* from an NPFD1 device credential */
    int           model_dev;        /* from a model credential: enrols */
    int           has_number;
    uint64_t      number;
    char          default_pw[64];
    char         *cert_path, *node_path, *state_path;
    char          account_login[128];   /* the account's email, phone or name; "": unknown */
    npf_enroll_req enroll;
    npf_identity  id;
    npf_callee   *callee;           /* a node with a number only */
    /* the run */
    npf_loop     *loop;
    npf_node      node;
    npf_peers    *peers;
    npf_policy    policy;           /* what sessions accepted by a client or a direct listener may reach */
    struct npf_res *res;            /* the published resources, nres of them */
    int           nres;
    npf_direct   *dl;
    npf_budget    budget;           /* what a hosted client's tunnels may spend (a module keeps it filled) */
    int           end_stage;
    int64_t       started_unix;     /* the run's start (Unix s); 0: not running */

    /* ---- src/api's own from here on ---- */
    struct npf_api_sync *sync;
    /* shared with other threads: under the API lock */
    int           started, running, stopping, ended, torn_down;
    npf_runtime  *rt;               /* the shared runtime, or NULL */
    int           rt_slot;
    void         *thread;
    unsigned long loop_tid;
    int           exec_busy;        /* not running: a caller is executing a call */
    unsigned long exec_owner;
    unsigned      send_jobs;        /* media frames queued from other threads (at most 4096) */
    size_t        send_queued;      /* and their bytes (NPF_MEDIA_SEND_QUEUE) */
    npf_log_ctx   logctx;
    /* sessions and media streams by number */
    struct npf_sess *sess;          /* nsess of capsess, up to NPF_MAX_SESS */
    int           nsess;
    size_t        capsess;
    uint32_t      next_sess;
    struct npf_med *med;            /* NPF_MAX_MEDIA, allocated with the first stream */
    int           nmed;
    uint32_t      next_med;
    /* the modules registered at npf_create (NULL-terminated) and their state */
    const struct npf_module *mods[NPF_MOD_MAX + 1];
    void         *mod_state[NPF_MOD_MAX];
    int           mods_created;     /* the first ones whose create succeeded: only they end and are destroyed */
    int           mods_made;        /* all created: the other hooks are called from then on */
};

struct npf_sublink_stats;

/* A command (npf_command). argv[0] is its name; run may reorder argv.
 * Returns the exit code (0..) with the text written to o, or -1 when it
 * answers later through cb (on the instance's thread). */
typedef struct npf_mod_cmd {
    const char *name;
    int (*run)(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o);
} npf_mod_cmd;

typedef struct npf_module {
    const char *name;
    /* In npf_create, once the node is made and before the saved peers come
     * back: makes the module's state (npf_mod_set_state). 0, or -1 with the
     * message in err: then npf_create fails, this module frees what it
     * made, and the modules created before it end and are destroyed. */
    int  (*create)(npf_t *n, char *err, size_t errcap);
    /* the run begins (the node has started) */
    void (*begin)(npf_t *n);
    /* The run ends in steps, the loop running in between. Step 0: the
     * sessions are still up. Step 1: only after a step 0 that returned a
     * time. Step 2: the last, before the peers go. Returns how long (ms) the
     * loop should run before the next step, 0 for no need. An instance that
     * never ran gets step 2 alone, in npf_destroy. */
    int  (*end)(npf_t *n, int step);
    /* npf_destroy, the last module first: frees the module's state. Only
     * for modules whose create succeeded. */
    void (*destroy)(npf_t *n);

    /* logged in to the platform */
    void (*login)(npf_t *n);
    /* a platform event (signaling.md): its type, the message and the data's token (d < 0: none) */
    void (*event)(npf_t *n, const char *type, const npf_json *j, int d);
    /* 1: keep the on-demand signaling connection up (work not done yet) */
    int  (*sig_busy)(npf_t *n);
    /* an account session began (1) or ended (0): login, logout, delete */
    void (*account)(npf_t *n, int on);
    /* a session's state changed (NPF_CALL_*) */
    void (*call_state)(npf_t *n, npf_call *call, int st, const char *why);

    /* the peers' callbacks (npf/peers.h npf_peers_cbs) */
    void (*peer_up)(npf_t *n, npf_peer *p, npf_call *call);
    void (*peer_done)(npf_t *n, npf_peer *p, const char *why);
    void (*peer_fwd)(npf_t *n, npf_peer *p, int i, int up, const char *why);
    void (*peer_opened)(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from);
    void (*peer_conn)(npf_t *n, npf_peer *p, npf_call *call, uint64_t mapping, int port,
                      const struct sockaddr_storage *from, int64_t start, int64_t end,
                      const struct npf_sublink_stats *st);
    void (*peer_refused)(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                         const char *why, int opened);
    /* A peer is about to be removed. Return 1 when the module will open it
     * again; peer_removed then follows, after the peer is gone. */
    int  (*peer_removing)(npf_t *n, npf_peer *p);
    void (*peer_removed)(npf_t *n);
    /* a peer's nick was set here */
    void (*nick_set)(npf_t *n, const char *target, const char *nick);
    /* a peer's saved forwards changed in its record d (written after the
     * hook): the module updates what it keeps in the record */
    void (*fwds_saved)(npf_t *n, npf_ldev *d);

    /* its commands, ended by an entry with a NULL name */
    const npf_mod_cmd *cmds;

    /* Writes members of its own into the status object (npf_status_json)
     * with npf_out_kstr, npf_out_jkey and the rest (npf/json.h); the commas
     * come by themselves. Names carry the module's prefix. */
    void (*status_json)(npf_t *n, npf_out *o);

    /* its configuration keys, ended by NPF_KEY_END: checked, kept and
     * listed as libnpf's own are (npf/conf.h) */
    const npf_key *keys;
    /* An NPF_K_LIVE key (libnpf's or any module's) was set at run time and
     * is in effect now. */
    void (*conf_set)(npf_t *n, const char *k, const char *v);
} npf_module;

/* Registers a module. Instances created from then on have it. Any thread;
 * m stays the program's and must outlive the instances. 0, or -1: m is
 * NULL, has no name, is registered already, NPF_MOD_MAX are registered, or
 * its name, a command (also one without run) or a key is libnpf's or an
 * earlier module's. */
int   npf_register_module(const npf_module *m);

/* a module's state in an instance; NULL: none set, or m is not in it */
void *npf_mod_state(npf_t *n, const npf_module *m);
void  npf_mod_set_state(npf_t *n, const npf_module *m, void *state);

/* ---- what libnpf does for modules (on the instance's thread) ---- */

/* sends an event to the application (npf_callbacks.event); fmt and the
 * arguments print its JSON */
void npf_emit(npf_t *n, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)))
#endif
    ;
/* A device enrolled at run time got its number: writes node.json and the
 * pairing state, and makes the node callable. 0, or -1 (logged). */
int  npf_become_node(npf_t *n, uint64_t number);
/* Adds or replaces (by name) a published resource (npf/resources.h), or
 * removes one (name NULL: all but npf.conf's). NPF_OK, NPF_ESAVE, or an
 * error with the reason in err. */
struct npf_res;
int  npf_pub_put(npf_t *n, const struct npf_res *r, char *err, size_t errcap);
int  npf_pub_remove(npf_t *n, const char *name, char *err, size_t errcap);
/* A peer's tag (npf/peers.h) says where it comes from, as
 * npf_peer_info.flags does: 0 the application's for this run, NPF_PERSIST
 * saved in local.json, NPF_PLATFORM opened for port mappings saved on the
 * platform. Its name: "temporary", "saved", "platform". */
const char *npf_source_name(int tag);
/* Writes a peer's record in local.json as saved (connected at every start,
 * with its saved forwards) or not. psk_file: a direct peer's key file as
 * given; NULL: its key. NPF_OK, NPF_ESAVE, NPF_EBUSY (local.json is full). */
int  npf_ops_record(npf_t *n, npf_peer *p, int save, const char *psk_file);
/* adds forward i of a saved peer to its record, or removes it: NPF_OK, NPF_ESAVE */
int  npf_ops_record_fwd(npf_t *n, npf_peer *p, int i, int add);
/* a command's exit code: done, but local.json not written yet (it is with the next change saved) */
#define NPF_CMD_UNSAVED 3

/* For a module that changes what the others hear of: runs the other
 * modules' nick_set; removes peer p, between the modules' peer_removing
 * and (when one of them opens it again) peer_removed. */
void npf_mods_nick_set(npf_t *n, const char *target, const char *nick);
void npf_mods_peer_remove(npf_t *n, npf_peer *p);

#endif

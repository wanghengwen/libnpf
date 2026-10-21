/* Modules: features a program adds to libnpf without changing it (commands
 * and settings of its own, the platform's events, keys in the status, more
 * kinds of forwards). The modules are the program's own code: it registers
 * them (npf_register_module) before it creates instances, and libnpf calls
 * their hooks on each instance's thread, in the order they were registered.
 * Every hook is optional; a module keeps its state per instance
 * (npf_mod_state).
 *
 * A module uses libnpf's internal interface (this header, the others in
 * include/npf/, src/api/npf_int.h): it links the static library target
 * npf_common, not the installed libnpf, and is built again with each
 * version of libnpf. */
#ifndef NPF_MODULE_H
#define NPF_MODULE_H

#include <stddef.h>
#include <stdint.h>

#include "npf.h"
#include "npf/json.h"
#include "npf/node.h"
#include "npf/out.h"
#include "npf/peers.h"

struct npf_sublink_stats;

/* a command of the command line (npf_command): argv[0] is its name; 0.. the
 * exit code with the text in o, or -1 when it answers later through cb */
typedef struct npf_mod_cmd {
    const char *name;
    int (*run)(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o);
} npf_mod_cmd;

typedef struct npf_module {
    const char *name;
    /* npf_create, once the node and its peers are there: the module's state
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
    /* the user removes a peer (node del): 1 when the module opens it again
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

    /* the status: keys of its own in the JSON object (npf_mod_jkey for each,
     * first as there), lines of its own in the text */
    void (*status_json)(npf_t *n, npf_out *o, int *first);
    void (*status_text)(npf_t *n, npf_out *o);

    /* configuration keys it reads (npf.conf, npf set); NULL ends them */
    const char *const *keys;
    /* a value for one of its keys: 0, or the exit code with the reason in o */
    int  (*check)(npf_t *n, const char *k, const char *v, npf_out *o);
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

/* a key of the status JSON object: the comma before it unless it is the first */
void npf_mod_jkey(npf_out *o, int *first, const char *k);

/* one of the instance's modules' configuration keys? */
int  npf_mod_key_known(npf_t *n, const char *k);

/* ---- what libnpf calls (module.c) ---- */
void npf_mods_take(npf_t *n);              /* the modules registered by now */
int  npf_mods_create(npf_t *n, char *err, size_t errcap);
void npf_mods_begin(npf_t *n);
int  npf_mods_end(npf_t *n, int step);      /* the longest wait asked for */
void npf_mods_destroy(npf_t *n);
void npf_mods_login(npf_t *n);
void npf_mods_event(npf_t *n, const char *type, const npf_json *j, int d);
int  npf_mods_sig_busy(npf_t *n);
void npf_mods_account(npf_t *n, int on);
void npf_mods_call_state(npf_t *n, npf_call *call, int st, const char *why);
void npf_mods_peer_up(npf_t *n, npf_peer *p, npf_call *call);
void npf_mods_peer_done(npf_t *n, npf_peer *p, const char *why);
void npf_mods_peer_fwd(npf_t *n, npf_peer *p, int i, int up, const char *why);
void npf_mods_peer_opened(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from);
void npf_mods_peer_conn(npf_t *n, npf_peer *p, npf_call *call, uint64_t mapping, int port,
                        const struct sockaddr_storage *from, int64_t start, int64_t end,
                        const struct npf_sublink_stats *st);
void npf_mods_peer_refused(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                           const char *why, int opened);
int  npf_mods_peer_removing(npf_t *n, npf_peer *p);
void npf_mods_peer_removed(npf_t *n);
void npf_mods_nick_set(npf_t *n, const char *target, const char *nick);
void npf_mods_fwds_saved(npf_t *n, npf_ldev *d);
/* a module's command: 1 found (*rc its result), 0 none of that name */
int  npf_mods_cmd(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o, int *rc);
void npf_mods_status_json(npf_t *n, npf_out *o, int *first);
void npf_mods_status_text(npf_t *n, npf_out *o);
/* -1: not a module's key; else check's result */
int  npf_mods_check(npf_t *n, const char *k, const char *v, npf_out *o);

#endif

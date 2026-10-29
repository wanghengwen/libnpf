/* Shared by src/api's files only (what modules use is in npf/module.h): how a
 * call reaches the instance's thread (api_thread.c), the engine's parts
 * (engine*.c), and the operations of npf.h's objects (ops*.c, api.c). */
#ifndef NPF_API_INTERNAL_H
#define NPF_API_INTERNAL_H

#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "npf/callee.h"
#include "npf/crypto.h"
#include "npf/module.h"
#include "npf/platform.h"
#include "npf/tunnel.h"
#include "npf/version.h"

/* sessions and media streams by number (npf_t's sess, med) */
#define NPF_MAX_SESS  256
#define NPF_MAX_MEDIA NPF_MEDIA_STREAMS_MAX

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

/* the status object (npf_status_json) */
void npf_status_out(npf_t *n, npf_out *o);

/* cmd.c: a command (argv[0] = its name); the exit code with the text in o
 * (0 done, 1 failed, 2 a bad command, NPF_CMD_UNSAVED), or -1 when it answers
 * later through cb. libnpf's own commands come before the modules' */
int  npf_cmd_run(npf_t *n, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user);
int  npf_cmd_builtin(const char *name);     /* one of libnpf's own commands? */
void npf_cmd_config_json(npf_t *n, npf_out *o);
/* a hosted client's limits on its public mappings (hosted_max_conns ...: npf-hosted sets them from the platform) */
void npf_hosted_limits(npf_t *n);
int  npf_cmd_set(npf_t *n, const char *k, const char *v, int save, npf_out *o);
const char *npf_cmd_get(npf_t *n, const char *k, char *buf, size_t cap);

/* ---- the instance's thread (api_thread.c) ---- */

struct npf_api_sync {
#ifdef _WIN32
    CRITICAL_SECTION mu;
    CONDITION_VARIABLE cv;
#else
    pthread_mutex_t mu;
    pthread_cond_t cv;
#endif
    unsigned calls;                 /* public calls in progress: npf_destroy waits for them */
    int destroying;
};

/* the instance's lock and condition (n in scope) */
#ifdef _WIN32
#define LOCK()   EnterCriticalSection(&n->sync->mu)
#define UNLOCK() LeaveCriticalSection(&n->sync->mu)
#define WAIT()   SleepConditionVariableCS(&n->sync->cv, &n->sync->mu, INFINITE)
#define WAKE()   WakeAllConditionVariable(&n->sync->cv)
static inline unsigned long self_tid(void) { return (unsigned long)GetCurrentThreadId(); }
#else
#define LOCK()   pthread_mutex_lock(&n->sync->mu)
#define UNLOCK() pthread_mutex_unlock(&n->sync->mu)
#define WAIT()   pthread_cond_wait(&n->sync->cv, &n->sync->mu)
#define WAKE()   pthread_cond_broadcast(&n->sync->cv)
static inline unsigned long self_tid(void) { return (unsigned long)pthread_self(); }
#endif

/* a public call holds a reference from its start to its end: 0 when the
 * instance is being destroyed (no call may start then) */
int  api_enter(npf_t *n);
void api_leave(npf_t *n);
/* fn for the instance and its answer, or NPF_ESTATE / NPF_ENOMEM when it did
 * not run. Running: on the loop's thread (posted, the caller waits, unless
 * it is that thread); not running (before the start, after the end): on the
 * caller's, one call at a time per instance, a call from inside one (a
 * callback) at once */
int  sync_call(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg);

/* ---- the engine's parts (engine.c the lifecycle) ---- */

/* engine_config.c: npf.conf (or npf_setup), the overrides and local.json's
 * settings into n->conf, and the paths; NPF_OK, NPF_EINVAL or NPF_EFAIL with
 * err (what was made stays in n: npf_engine_config_free) */
int  npf_engine_config_load(npf_t *n, const npf_options *o, char *err, size_t errcap);
void npf_engine_config_free(npf_t *n);
/* engine_identity.c: the identity and the callee state, after the configuration; 0, or -1 with err */
int  npf_engine_identity_load(npf_t *n, char *err, size_t errcap);
void npf_engine_callee_attach(npf_t *n);
void npf_engine_account_load(npf_t *n);
/* engine_events.c: the node and the peers with the engine's callbacks */
int  npf_engine_node_init(npf_t *n, const npf_node_cfg *cfg);
npf_peers *npf_engine_peers_new(npf_t *n);
/* setup.c: npf_setup's fields as configuration keys (c), their values
 * checked (npf_conf_check); 0, or -1 with err */
int  npf_setup_conf(const npf_setup *s, int role, const char *data_dir, npf_conf *c, char *err, size_t errcap);
/* the run on the library thread: the node until npf_loop_stop, then its end */
int  npf_engine_run(npf_t *n);
void npf_engine_begin(npf_t *n);
int  npf_engine_end_step(npf_t *n);
void npf_engine_free(npf_t *n);
/* a shared runtime: the loop of an instance on one of its threads (api_thread.c) */
npf_loop *npf_runtime_child(npf_runtime *rt, int *slot);
void npf_runtime_leave(npf_runtime *rt, int slot);
int  npf_api_init(npf_t *n);
void npf_api_fini(npf_t *n);
/* the network changed (npf_network_changed, the command netcheck): the UDP
 * sockets again, then the peers (ops.c) */
void npf_net_changed(npf_t *n);
/* engine_identity.c: the account certificate kept, forgotten; the
 * account's login name asked for (status "account_login") */
void npf_save_account_cert(npf_t *n);
void npf_forget_account(npf_t *n);
void npf_account_info(npf_t *n);
/* engine_events.c: event "account" (the account session began or ended);
 * sessions and media streams by number */
void npf_ev_account(npf_t *n);
uint32_t  npf_session_of(npf_t *n, npf_call *call);
npf_call *npf_session_call(npf_t *n, uint32_t id);
npf_peer *npf_peer_of_call(npf_t *n, npf_call *call);   /* an outgoing call's peer, or NULL */
uint32_t  npf_media_add(npf_t *n, uint32_t session, npf_call *call, uint32_t lid);
npf_med  *npf_media_find(npf_t *n, uint32_t id);
void      npf_media_forget(npf_t *n, uint32_t id);
/* status.c: the other side of a call for people ("318204776", "key:<fingerprint>");
 * a session as the session callback has it; the sessions up */
const char *npf_who(const npf_call_info *i, char *buf, size_t cap);
void npf_session_out(npf_t *n, npf_call *call, npf_out *o);
void npf_sessions_out(npf_t *n, npf_out *o);
/* publish.c: this node's resources (npf.conf + local.json) and the policy
 * they make; the list to a caller whose session came up, into the status;
 * a callee's list heard */
int  npf_pub_load(npf_t *n, char *err, size_t errcap);
int  npf_pub_apply(npf_t *n);
void npf_pub_free(npf_t *n);
void npf_pub_send(npf_t *n, npf_call *c);
void npf_pub_json(npf_t *n, npf_out *o);
void npf_pub_heard(npf_t *n, npf_call *c, const npf_json *j, int d);
/* the resources of a JSON text (an array): their number, *r (malloc'd,
 * NPF_RES_MAX of them, for the caller to free); NPF_ENOMEM or NPF_EFAIL with
 * err and *r NULL */
int  npf_pub_res_text(const char *json, struct npf_res **r, char *err, size_t errcap);
/* platform.c: npf_request on the instance's thread */
int  npf_plat_request(npf_t *n, const char *type, const char *data, int proof, npf_reply_cb cb, void *user,
                      npf_out *err);
/* api.c: fn on the instance's thread (sync_call) for a public call: its
 * answer, or NPF_EINVAL (no instance) / NPF_ESTATE / NPF_ENOMEM when it did
 * not run */
int  npf_api_op(npf_t *n, int (*fn)(npf_t *n, void *arg), void *arg);
/* the instance's lock: the state shared with other threads (started,
 * running, ...), the media registry (npf_media_send reads it on any thread) */
void npf_api_lock(npf_t *n);
void npf_api_unlock(npf_t *n);

/* ---- the operations of npf.h's objects ---- */

/* the bytes of T up to and with field f: the least an application's
 * structure has (fields only come at the end) */
#define SIZE_TO(T, f) (offsetof(T, f) + sizeof(((T *)0)->f))

/* the application's structure (src, its size first) into ours (dst, with
 * the defaults): what both builds know. -1: NULL, or smaller than min */
static inline int take_in(void *dst, size_t dsize, const void *src, size_t min)
{
    size_t size;
    if (!src)
        return -1;
    memcpy(&size, src, sizeof size);
    if (size < min)
        return -1;
    memcpy(dst, src, size < dsize ? size : dsize);
    memcpy(dst, &dsize, sizeof dsize);
    return 0;
}

/* ours (src, ssize bytes) into the application's out of size bytes (its
 * sizeof): what both builds know, zeros past ours */
static inline void put_out(void *out, size_t size, const void *src, size_t ssize)
{
    memcpy(out, src, size < ssize ? size : ssize);
    if (size > ssize)
        memset((char *)out + ssize, 0, size - ssize);
}

/* an operation's arguments: the object, what goes in, where the answer
 * goes (out of size bytes; a list: cap of them, all counted in count), the
 * error text */
typedef struct op_arg {
    uint32_t    id;
    const void *in;
    void       *out;
    size_t      size, cap, *count;
    char       *err;
    size_t      errcap;
} op_arg;

/* rc, with the reason in x->err (x NULL: none) */
int  op_fail(op_arg *x, int rc, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 3, 4)))
#endif
    ;
/* fn for the object id: its info into out (put_out, size bytes) */
int  op_get(npf_t *n, int (*fn)(npf_t *n, void *arg), uint32_t id, void *out, size_t size);
/* fn lists those of id (0: all) with list_put; NPF_ETOOBIG when cap was too small */
int  op_list(npf_t *n, int (*fn)(npf_t *n, void *arg), uint32_t id, void *out, size_t size, size_t cap,
             size_t *count);
static inline void list_put(op_arg *x, const void *e, size_t esize)
{
    if (*x->count < x->cap)
        put_out((char *)x->out + *x->count * x->size, x->size, e, esize);
    (*x->count)++;
}

/* ops.c: the peers saved in local.json brought back with their forwards,
 * after the modules (their forward kinds); "HOST:PORT", "[V6]:PORT" split */
void npf_ops_restore(npf_t *n);

static inline void err_clear(char *err, size_t errcap)
{
    if (err && errcap)
        err[0] = 0;
}

static inline int no_saved_objects(const npf_t *n)
{
    return (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS) != 0;
}

static inline int saved_rc(npf_t *n)
{
    return npf_local_save(&n->lc) < 0 ? NPF_ESAVE : NPF_OK;
}

static inline npf_peer *peer_of(npf_t *n, uint32_t id)
{
    return n->peers ? npf_peers_by_id(n->peers, id) : NULL;
}

/* ---- the modules' hooks (module.c) ---- */
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
void npf_mods_peer_removed(npf_t *n);
void npf_mods_fwds_saved(npf_t *n, npf_ldev *d);
/* a module's command: 1 found (*rc its result), 0 none of that name */
int  npf_mods_cmd(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o, int *rc);
void npf_mods_status_json(npf_t *n, npf_out *o);
void npf_mods_conf_set(npf_t *n, const char *k, const char *v);

#endif

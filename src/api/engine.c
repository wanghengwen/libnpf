/* libnpf: engine creation, execution and teardown. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_internal.h"

/* ---- lifecycle ---- */

/* npf_options.app_name: 1..32 of a-z 0-9 . _ -; app_ver: 1..32 printable characters */
static int app_name_ok(const char *s)
{
    size_t l = strlen(s);
    return l >= 1 && l <= 32 && strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789._-") == l;
}

static int app_ver_ok(const char *s)
{
    size_t i, l = strlen(s);
    for (i = 0; i < l; i++)
        if ((unsigned char)s[i] <= 0x20 || (unsigned char)s[i] >= 0x7f)
            return 0;
    return l >= 1 && l <= 32;
}

int npf_api_version(void)
{
    return NPF_API_VERSION;
}

/* create()'s stages, in order. The first makes the instance (or nothing);
 * each after it leaves what it made in n, failing or not: npf_engine_free
 * undoes any part of them */

/* why the options cannot be taken, NULL: they can (app_name, app_ver: npf_create set them) */
static const char *options_bad(const npf_options *o)
{
    if (!o->setup && !o->conf_dir && !o->conf_file)
        return "conf_dir (or npf_options.setup) is needed";
    if (o->setup && (o->conf_dir || o->conf_file || !o->data_dir))
        return "npf_options.setup: no conf_dir or conf_file, and a data_dir";
    if (o->flags & ~(NPF_OPT_NO_SAVED_SETTINGS | NPF_OPT_NO_SAVED_OBJECTS | NPF_OPT_NO_LOG_RING))
        return "npf_options.flags: unknown flags";
    if (!app_name_ok(o->app_name) || !app_ver_ok(o->app_ver))
        return "app_name: 1..32 of a-z 0-9 . _ -; app_ver: up to 32 printable characters";
    return NULL;
}

/* the instance with its lock and log, NULL: no memory */
static npf_t *instance_new(const npf_options *o)
{
    npf_t *n = calloc(1, sizeof *n);
    if (!n)
        return NULL;
    /* recent lines for npf_log_json, unless the application asked for none */
    if ((!(o->flags & NPF_OPT_NO_LOG_RING) && !(n->logctx.ring = malloc(NPF_LOG_RING))) || npf_api_init(n) < 0) {
        free(n->logctx.ring);
        free(n);
        return NULL;
    }
    n->role = o->role;
    n->cb = *o->cb;
    n->opt_flags = o->flags;
    npf_mods_take(n);                       /* the modules registered by now */
    snprintf(n->app_name, sizeof n->app_name, "%s", o->app_name);
    snprintf(n->app_ver, sizeof n->app_ver, "%s", o->app_ver);
    /* the instance's own log from here on: its level starts as the process's */
    n->logctx.hook = o->cb->log;
    n->logctx.user = o->cb->user;
    n->logctx.level = npf_log_get_level();
    return n;
}

/* the configuration, the identity and the node on its loop */
static int node_up(npf_t *n, const npf_options *o, char *err, size_t errcap)
{
    npf_node_cfg cfg;                   /* the node's (its copy: n->node.cfg) */
    int rc = npf_engine_config_load(n, o, err, errcap);
    if (rc != NPF_OK)
        return rc;
    if (npf_engine_identity_load(n, err, errcap) < 0)
        return NPF_EFAIL;
    if (n->role == NPF_ROLE_DIRECT) {
        memset(&cfg, 0, sizeof cfg);
        cfg.offline = 1;
        cfg.udp_port = (int)npf_conf_int(&n->conf, "udp_port");
    } else if (npf_node_cfg_from_conf(&cfg, &n->conf) < 0) {
        snprintf(err, errcap, "config: root keys and a server list are needed");
        return NPF_EFAIL;
    }
    cfg.callable = n->role == NPF_ROLE_NODE && n->has_number;
    cfg.number = cfg.callable ? n->number : 0;
    if (n->role == NPF_ROLE_NODE && n->model_dev && !n->has_number)
        cfg.enroll = &n->enroll;
    if (n->role != NPF_ROLE_NODE || cfg.hosted_service || cfg.hosted_exec)
        cfg.no_portmap = 1;
    cfg.model = npf_conf_get(&n->conf, "model", n->cred || n->model_dev ? "NAS" : "console");
    cfg.fw = npf_version();
    cfg.app_name = n->app_name;
    cfg.app_ver = n->app_ver;
    n->loop = o->runtime ? npf_runtime_child(o->runtime, &n->rt_slot) : npf_loop_new();
    if (n->loop && o->runtime) {
        n->rt = o->runtime;
        npf_loop_set_logctx(n->loop, &n->logctx);
    }
    if (!n->loop || npf_engine_node_init(n, &cfg) < 0) {
        snprintf(err, errcap, "cannot start the node (UDP socket or server list)");
        return NPF_EFAIL;
    }
    if (!n->node.cfg.offline && !n->cred)
        npf_engine_account_load(n);
    return NPF_OK;
}

/* what runs on the node: the published resources, the peers, the modules */
static int services_up(npf_t *n, char *err, size_t errcap)
{
    int idle = (int)npf_conf_int(&n->conf, "peer_idle");
    /* target policy of the sessions accepted here: the published resources
     * (resources.h, security.md D22) */
    if (npf_pub_load(n, err, errcap) < 0)
        return NPF_EFAIL;
    if (n->node.cfg.callable)
        npf_engine_callee_attach(n);
    if (!(n->peers = npf_engine_peers_new(n))) {
        snprintf(err, errcap, "no memory");
        return NPF_EFAIL;
    }
    if (no_saved_objects(n))
        npf_peers_no_cache(n->peers);
    /* peer_idle = S: the peers on demand without an idle time of their own end S s after their last connection */
    npf_peers_set_idle(n->peers, (idle > 0 ? idle : 300) * 1000);
    if (n->node.cfg.hosted_exec)
        npf_hosted_limits(n);
    /* the modules, before the peers come: their forwards' callbacks go to them */
    return npf_mods_create(n, err, errcap) < 0 ? NPF_EFAIL : NPF_OK;
}

/* what a long-running role saved (a client's one-off tasks do not), and
 * the direct connections (no platform): "direct = [ADDR:]PORT" with its key */
static int restore(npf_t *n, char *err, size_t errcap)
{
    const char *direct = npf_conf_get(&n->conf, "direct", NULL);
    uint8_t psk[32];
    if (n->role == NPF_ROLE_CLIENT)
        return NPF_OK;
    if (!no_saved_objects(n))
        npf_ops_restore(n);
    if (!direct || !*direct)
        return NPF_OK;
    if (npf_direct_psk(npf_conf_get(&n->conf, "direct_psk", NULL), npf_conf_get(&n->conf, "direct_psk_file", NULL),
                       psk) < 0) {
        snprintf(err, errcap, "direct needs direct_psk_file (or direct_psk)");
        return NPF_EFAIL;
    }
    n->dl = npf_direct_listen(&n->node, direct, psk, n->node.cfg.callable ? NULL : &n->policy);
    npf_wipe(psk, 32);
    if (!n->dl) {
        snprintf(err, errcap, "cannot listen for direct connections on %s", direct);
        return NPF_EFAIL;
    }
    return NPF_OK;
}

static int create(const npf_options *o, npf_t **out, char *err, size_t errcap)
{
    const char *bad = options_bad(o);
    npf_log_ctx *prev_log;
    npf_t *n;
    int rc;
    if (bad) {
        snprintf(err, errcap, "%s", bad);
        return NPF_EINVAL;
    }
    if (!(n = instance_new(o))) {
        snprintf(err, errcap, "no memory");
        return NPF_ENOMEM;
    }
    prev_log = npf_log_ctx_swap(&n->logctx);
    if ((rc = node_up(n, o, err, errcap)) == NPF_OK && (rc = services_up(n, err, errcap)) == NPF_OK)
        rc = restore(n, err, errcap);
    npf_log_ctx_swap(prev_log);
    if (rc != NPF_OK)
        npf_engine_free(n);                 /* the one unwind: whatever the stages made */
    else
        *out = n;
    return rc;
}

/* the structures as this build knows them: what the application's build has,
 * the defaults for the rest */
int npf_create(const npf_options *uo, npf_t **out, char *err, size_t errcap)
{
    npf_options o;
    npf_callbacks cb;
    op_arg x = {.err = err, .errcap = errcap};
    if (!out || !err || !errcap)
        return NPF_EINVAL;
    *out = NULL;
    npf_options_init(&o);
    npf_callbacks_init(&cb);
    if (take_in(&x, &o, sizeof o, uo, SIZE_TO(npf_options, flags), "npf_options_init")
        || (o.cb && take_in(&x, &cb, sizeof cb, o.cb, SIZE_TO(npf_callbacks, media_closed), "npf_callbacks_init")))
        return NPF_EINVAL;
    o.cb = &cb;
    if (!o.app_name)
        o.app_name = "libnpf";
    if (!o.app_ver)
        o.app_ver = npf_version();
    return create(&o, out, err, errcap);
}

/* the start of the run, on the loop's thread */
void npf_engine_begin(npf_t *n)
{
    n->started_unix = npf_unix_ms() / 1000;
    if (n->role == NPF_ROLE_NODE)
        npf_log("npf %s: %s %llu, %d peer(s), UDP port %u", npf_version(), n->node.cfg.callable ? "node" : "client",
                n->node.cfg.callable ? (unsigned long long)n->number : 0ULL, npf_peers_count(n->peers), n->node.udp_port);
    npf_node_start(&n->node);
    npf_peers_start(n->peers);
    npf_mods_begin(n);
}

/* The end of the run in steps, on the loop's thread: each returns how long
 * the loop goes on (its sockets and timers) before the next, or -1 at the
 * end. A shared runtime's thread runs other instances meanwhile. */
int npf_engine_end_step(npf_t *n)
{
    int ms;
    switch (n->end_stage++) {
    case 0:                         /* the modules' work with the sessions still up (a hosted client's reports) */
        if ((ms = npf_mods_end(n, 0)) > 0)
            return ms;
        n->end_stage = 2;
        return npf_engine_end_step(n);
    case 1:
        return npf_mods_end(n, 1);
    case 2:
        npf_mods_end(n, 2);
        npf_api_lock(n);
        n->ended = 1;                           /* calls from now on: NPF_ESTATE */
        npf_api_unlock(n);
        /* the end: peers' sessions, then the accepted ones (callers are told at once) */
        npf_peers_free(n->peers);
        n->peers = NULL;
        npf_node_end_calls(&n->node, "closed");
        return 50;
    default:
        npf_direct_close(n->dl);
        n->dl = NULL;
        npf_node_stop(&n->node);
        n->torn_down = 1;
        if (n->cb.event)
            n->cb.event(n->cb.user, "stopped", "{}");   /* the last event */
        n->started_unix = 0;
        return -1;
    }
}

/* the run on the loop's thread (npf_run, or npf_start's thread) */
int npf_engine_run(npf_t *n)
{
    int ms;
    npf_engine_begin(n);
    npf_loop_run(n->loop);
    while ((ms = npf_engine_end_step(n)) >= 0)
        npf_loop_once(n->loop, ms);
    return 0;
}

void npf_engine_free(npf_t *n)
{
    npf_log_ctx *prev;
    if (!n)
        return;
    prev = npf_log_ctx_swap(&n->logctx);
    if (!n->torn_down) {                    /* never run (or made only in part: create() failed) */
        npf_mods_end(n, 2);                 /* what the modules keep of the peers goes first */
        npf_peers_free(n->peers);
        npf_direct_close(n->dl);
        if (n->loop)                        /* a node never set up has fd 0 for its socket: not that */
            npf_node_stop(&n->node);
    }
    npf_mods_destroy(n);
    npf_loop_free(n->loop);
    if (n->rt)
        npf_runtime_leave(n->rt, n->rt_slot);
    npf_pub_free(n);
    npf_local_free(&n->lc);
    npf_engine_config_free(n);
    npf_wipe_free(n->callee, sizeof *n->callee);
    free(n->sess);
    free(n->med);
    npf_log_ctx_swap(prev == &n->logctx ? NULL : prev);
    npf_api_fini(n);
    free(n->logctx.ring);
    npf_wipe_free(n, sizeof *n);            /* the keys: its own, the node's copy, the model's; the passwords */
}

/* libnpf: engine creation, execution and teardown. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "engine_internal.h"
#include "npf/module.h"

/* ---- lifecycle ---- */

int npf_app_name_valid(const char *s)
{
    size_t i, l = strlen(s);
    if (l < 1 || l > 32)
        return 0;
    for (i = 0; i < l; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == '_' || s[i] == '-'))
            return 0;
    return 1;
}

int npf_app_ver_valid(const char *s)
{
    size_t i, l = strlen(s);
    if (l < 1 || l > 32)
        return 0;
    for (i = 0; i < l; i++)
        if ((unsigned char)s[i] <= 0x20 || (unsigned char)s[i] >= 0x7f)
            return 0;
    return 1;
}

/* the defaults d (sizeof d bytes) into the application's s of size bytes:
 * what both know, zeros past this build's structure */
void npf_init_sized(void *s, size_t size, const void *d, size_t dsize)
{
    if (!s || size < sizeof(size_t))
        return;
    memset(s, 0, size);
    memcpy(s, d, size < dsize ? size : dsize);
    memcpy(s, &size, sizeof size);          /* the first field: size */
}

void npf_options_init_size(npf_options *o, size_t size)
{
    npf_options d;
    memset(&d, 0, sizeof d);
    d.log_level = -1;
    npf_init_sized(o, size, &d, sizeof d);
}

void npf_callbacks_init_size(npf_callbacks *cb, size_t size)
{
    npf_callbacks d;
    memset(&d, 0, sizeof d);
    npf_init_sized(cb, size, &d, sizeof d);
}

int npf_api_version(void)
{
    return NPF_API_VERSION;
}

static int create(const npf_options *o, npf_t **out, char *err, size_t errcap);

/* the structures as this build knows them: what the application's build has,
 * the defaults for the rest (fields are only ever added at the end) */
int npf_create(const npf_options *uo, npf_t **out, char *err, size_t errcap)
{
    npf_options o;
    npf_callbacks cb;
    if (!out || !err || !errcap)
        return NPF_EINVAL;
    *out = NULL;
    if (!uo || uo->size < offsetof(npf_options, cb) + sizeof uo->cb) {
        snprintf(err, errcap, "options not initialised (npf_options_init)");
        return NPF_EINVAL;
    }
    npf_options_init(&o);
    memcpy(&o, uo, uo->size < sizeof o ? uo->size : sizeof o);
    o.size = sizeof o;
    npf_callbacks_init(&cb);
    if (o.cb) {
        if (o.cb->size < offsetof(npf_callbacks, media_closed) + sizeof o.cb->media_closed) {
            snprintf(err, errcap, "callbacks not initialised (npf_callbacks_init)");
            return NPF_EINVAL;
        }
        memcpy(&cb, o.cb, o.cb->size < sizeof cb ? o.cb->size : sizeof cb);
        cb.size = sizeof cb;
    }
    o.cb = &cb;
    return create(&o, out, err, errcap);
}

static int create(const npf_options *o, npf_t **out, char *err, size_t errcap)
{
    npf_t *n;
    int rc, fail_rc = NPF_EFAIL;
    npf_log_ctx *prev_log;
    *out = NULL;
    if (!o || (!o->setup && !o->conf_dir && !o->conf_file)) {
        snprintf(err, errcap, "conf_dir (or npf_options.setup) is needed");
        return NPF_EINVAL;
    }
    if (o->setup && (o->conf_dir || o->conf_file || !o->data_dir)) {
        snprintf(err, errcap, "npf_options.setup: no conf_dir or conf_file, and a data_dir");
        return NPF_EINVAL;
    }
    if (o->flags & ~(NPF_OPT_NO_SAVED_SETTINGS | NPF_OPT_NO_SAVED_OBJECTS)) {
        snprintf(err, errcap, "npf_options.flags: unknown flags");
        return NPF_EINVAL;
    }
    if (!(n = calloc(1, sizeof *n))) {
        snprintf(err, errcap, "no memory");
        return NPF_ENOMEM;
    }
    n->role = o->role;
    n->cb = *o->cb;
    n->opt_flags = o->flags;
    n->from_setup = o->setup != NULL;
    npf_mods_take(n);                   /* the modules registered by now */
    if (!npf_app_name_valid(o->app_name ? o->app_name : "libnpf")
        || !npf_app_ver_valid(o->app_ver ? o->app_ver : npf_version())) {
        snprintf(err, errcap, "app_name: 1..32 of a-z 0-9 . _ -; app_ver: up to 32 printable characters");
        free(n->logctx.ring);
        free(n);
        return NPF_EINVAL;
    }
    if (npf_api_init(n) < 0) {
        snprintf(err, errcap, "no memory for API synchronization");
        free(n->logctx.ring);
        free(n);
        return NPF_ENOMEM;
    }
    snprintf(n->app_name, sizeof n->app_name, "%s", o->app_name ? o->app_name : "libnpf");
    snprintf(n->app_ver, sizeof n->app_ver, "%s", o->app_ver ? o->app_ver : npf_version());
    /* the instance's own log from here on: its level starts as the process's */
    n->logctx.hook = o->cb->log;
    n->logctx.user = o->cb->user;
    /* recent lines for npf_log_json, unless the application asked for none */
    if (!o->no_log_ring && !(n->logctx.ring = malloc(NPF_LOG_RING))) {
        snprintf(err, errcap, "no memory");
        npf_api_fini(n);
        free(n);
        return NPF_ENOMEM;
    }
    n->logctx.level = npf_log_get_level();
    prev_log = npf_log_ctx_swap(&n->logctx);
    rc = npf_engine_config_load(n, o, err, errcap);
    if (rc != NPF_OK) {
        fail_rc = rc;
        goto fail;
    }

    if (npf_engine_identity_load(n, err, errcap) < 0)
        goto fail;

    /* the node */
    if (n->role == NPF_ROLE_DIRECT) {
        memset(&n->cfg, 0, sizeof n->cfg);
        n->cfg.offline = 1;
        n->cfg.udp_port = atoi(npf_conf_get(&n->conf, "udp_port", "0"));
    } else if (npf_node_cfg_from_conf(&n->cfg, &n->conf) < 0) {
        snprintf(err, errcap, "config: root keys and a server list are needed");
        goto fail;
    }
    n->cfg.callable = n->role == NPF_ROLE_NODE && n->has_number;
    n->cfg.number = n->cfg.callable ? n->number : 0;
    if (n->role == NPF_ROLE_NODE && n->model_dev && !n->has_number)
        n->cfg.enroll = &n->enroll;
    if (n->role != NPF_ROLE_NODE || n->cfg.hosted_service || n->cfg.hosted_exec)
        n->cfg.no_portmap = 1;
    n->cfg.model = npf_conf_get(&n->conf, "model", n->cred || n->model_dev ? "NAS" : "console");
    n->cfg.fw = npf_version();
    n->cfg.app_name = n->app_name;
    n->cfg.app_ver = n->app_ver;
    n->loop = o->runtime ? npf_runtime_child(o->runtime, &n->rt_slot) : npf_loop_new();
    if (n->loop && o->runtime) {
        n->rt = o->runtime;
        npf_loop_set_logctx(n->loop, &n->logctx);
    }
    if (!n->loop || npf_engine_node_init(n) < 0) {
        snprintf(err, errcap, "cannot start the node (UDP socket or server list)");
        goto fail;
    }
    if (!n->cfg.offline && !n->cred)
        npf_engine_account_load(n);
    /* target policy of the sessions accepted here: the published resources
     * (resources.h, security.md D22) */
    if (npf_pub_load(n, err, errcap) < 0)
        goto fail;
    if (n->cfg.callable) {
        n->callee->hosted_trust = atoi(npf_conf_get(&n->conf, "hosted_trust", "1"));
        npf_callee_attach(n->callee, &n->node);
    }
    /* peers: the application's, and those it saved in local.json */
    if (!(n->peers = npf_engine_peers_new(n))) {
        snprintf(err, errcap, "no memory");
        goto fail;
    }
    if (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS)
        npf_peers_no_cache(n->peers);
    {   /* peer_idle = S: the peers on demand without an idle time of their own end S s after their last connection */
        int idle = atoi(npf_conf_get(&n->conf, "peer_idle", "0"));
        npf_peers_set_idle(n->peers, (idle > 0 ? idle : 300) * 1000);
    }
    /* the modules, before the peers come: their forwards' callbacks go to them */
    if (npf_mods_create(n, err, errcap) < 0)
        goto fail;
    /* a long-running role brings back what it saved (a client's one-off tasks do not) */
    if (n->role != NPF_ROLE_CLIENT && !(n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS))
        npf_engine_restore_peers(n);
    /* the file as read and the overrides were for the start: the merged conf stays */
    npf_conf_free(&n->ro);
    npf_conf_free(&n->ov);
    {   /* direct connections (no platform): "direct = [ADDR:]PORT" with its key */
        const char *direct = npf_conf_get(&n->conf, "direct", NULL);
        if (direct && *direct && n->role != NPF_ROLE_CLIENT) {
            uint8_t psk[32];
            if (npf_direct_psk(npf_conf_get(&n->conf, "direct_psk", NULL), npf_conf_get(&n->conf, "direct_psk_file", NULL),
                               psk) < 0) {
                snprintf(err, errcap, "direct needs direct_psk_file (or direct_psk)");
                goto fail;
            }
            n->dl = npf_direct_listen(&n->node, direct, psk, n->cfg.callable ? NULL : &n->policy);
            npf_wipe(psk, 32);
            if (!n->dl) {
                snprintf(err, errcap, "cannot listen for direct connections on %s", direct);
                goto fail;
            }
        }
    }
    npf_log_ctx_swap(prev_log);
    *out = n;
    return NPF_OK;
fail:
    npf_mods_end(n, 2);                     /* the modules made: what they keep of the peers first */
    if (n->peers)
        npf_peers_free(n->peers);
    npf_mods_destroy(n);
    npf_pub_free(n);
    npf_local_free(&n->lc);
    npf_engine_config_free(n);
    free(n->callee);
    if (n->loop) {
        npf_node_stop(&n->node);
        npf_loop_free(n->loop);
    }
    if (n->rt)
        npf_runtime_leave(n->rt, n->rt_slot);
    npf_identity_wipe(&n->id);
    npf_log_ctx_swap(prev_log);
    npf_api_fini(n);
    free(n->logctx.ring);
    free(n);
    return fail_rc;
}

/* the start of the run, on the loop's thread */
void npf_engine_begin(npf_t *n)
{
    n->started_unix = npf_unix_ms() / 1000;
    npf_events_start(n);
    if (n->role == NPF_ROLE_NODE)
        npf_log("npf %s: %s %llu, %d peer(s), UDP port %u", npf_version(), n->cfg.callable ? "node" : "client",
                n->cfg.callable ? (unsigned long long)n->number : 0ULL, npf_peers_count(n->peers), n->node.udp_port);
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
        if (n->cb.notify) {
            npf_events_stop(n);             /* NPF_EV_STOPPED, the last */
        } else if (n->cb.event) {
            n->cb.event(n->cb.user, "stopped", "{}");
        }
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

void npf_start_peers(npf_t *n)
{
    if (!n->started)
        return;                             /* the run starts them */
    npf_peers_start(n->peers);
    if (n->node.online)
        npf_peers_on_login(n->peers);
}

npf_loop *npf_engine_loop(npf_t *n)
{
    return n->loop;
}

void npf_engine_free(npf_t *n)
{
    npf_log_ctx *prev;
    if (!n)
        return;
    prev = npf_log_ctx_swap(&n->logctx);
    if (!n->torn_down) {                    /* never run */
        npf_mods_end(n, 2);                 /* what the modules keep of the peers goes first */
        npf_peers_free(n->peers);
        npf_direct_close(n->dl);
        npf_node_stop(&n->node);
    }
    npf_mods_destroy(n);
    npf_events_clear(n);                    /* before its loop: a timer of it */
    npf_loop_free(n->loop);
    if (n->rt)
        npf_runtime_leave(n->rt, n->rt_slot);
    npf_pub_free(n);
    npf_local_free(&n->lc);
    npf_engine_config_free(n);
    free(n->callee);
    free(n->sess);
    npf_identity_wipe(&n->id);
    npf_log_ctx_swap(prev == &n->logctx ? NULL : prev);
    npf_api_fini(n);
    free(n->logctx.ring);
    free(n);
}

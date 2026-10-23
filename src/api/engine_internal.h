/* between the engine's files (engine.c the lifecycle, engine_config.c,
 * engine_identity.c, engine_events.c); what the rest of the library uses of
 * them is in npf_int.h */
#ifndef NPF_ENGINE_INTERNAL_H
#define NPF_ENGINE_INTERNAL_H

#include "npf_int.h"

/* engine_config.c: npf.conf (or npf_setup), the overrides and local.json's
 * settings into n->conf, and the paths; NPF_OK, NPF_EINVAL or NPF_EFAIL with
 * err (what was made stays in n: npf_engine_config_free) */
int  npf_engine_config_load(npf_t *n, const npf_options *o, char *err, size_t errcap);
void npf_engine_config_free(npf_t *n);
/* the peers saved in local.json, after the modules (their forward kinds) */
void npf_engine_restore_peers(npf_t *n);

/* engine_identity.c: the identity and the callee state, after the configuration; 0, or -1 with err */
int  npf_engine_identity_load(npf_t *n, char *err, size_t errcap);
void npf_engine_account_load(npf_t *n);

/* engine_events.c: the node and the peers with the engine's callbacks */
int  npf_engine_node_init(npf_t *n);
npf_peers *npf_engine_peers_new(npf_t *n);
/* one of the library's events: typed (notify), or the legacy name and JSON */
void npf_engine_event(npf_t *n, const npf_event *ev, const char *name, const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#endif

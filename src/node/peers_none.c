/* libnpf without sessions of its own to other nodes (NPF_PEERS=OFF: a
 * device that is only called): the peers.h interface with no peer ever.
 * Making one fails (npf_peer_create: NPF_EUNAVAIL); the rest is never
 * reached. */
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "npf/out.h"
#include "npf/peers.h"

struct npf_peers {
    int idle_ms;
};

static const char not_built[] = "sessions to other nodes are not in this build (NPF_PEERS=OFF)";

int npf_peers_name_set(npf_peers *ps, const char *name, const char *target, char *err, size_t errcap)
{
    (void)ps, (void)name, (void)target;
    snprintf(err, errcap, "%s", not_built);
    return -1;
}

const char *npf_peers_resolve(const npf_peers *ps, const char *word, char *buf, size_t cap)
{
    (void)ps, (void)buf, (void)cap;
    return word;
}

npf_peers *npf_peers_new(npf_node *n, npf_local *lc, const npf_peers_cbs *cbs, void *arg)
{
    (void)n, (void)lc, (void)cbs, (void)arg;
    return calloc(1, sizeof(npf_peers));
}

void npf_peers_free(npf_peers *ps) { free(ps); }

int npf_peer_target_name(uint64_t number, const char *host, uint16_t port, char *out, size_t cap)
{
    (void)number, (void)host, (void)port, (void)out, (void)cap;
    return -1;
}

npf_peer *npf_peers_create(npf_peers *ps, const npf_peer_new *pn, char *err, size_t errcap, int *code)
{
    (void)ps, (void)pn;
    snprintf(err, errcap, "%s", not_built);
    if (code)
        *code = 3;
    return NULL;
}

int npf_peers_count(const npf_peers *ps) { (void)ps; return 0; }
void npf_peers_start(npf_peers *ps) { (void)ps; }
void npf_peers_on_login(npf_peers *ps) { (void)ps; }

int npf_peers_on_call_state(npf_peers *ps, npf_call *c, int st, const char *why)
{
    (void)ps, (void)c, (void)st, (void)why;
    return 0;
}

void npf_peers_on_paired(npf_peers *ps, uint64_t number, const uint8_t pub[32]) { (void)ps, (void)number, (void)pub; }
void npf_peers_retry_now(npf_peers *ps) { (void)ps; }
void npf_peers_net_changed(npf_peers *ps) { (void)ps; }
void npf_peers_remove(npf_peers *ps, npf_peer *p) { (void)ps, (void)p; }
npf_peer *npf_peers_find(const npf_peers *ps, const char *name) { (void)ps, (void)name; return NULL; }
npf_peer *npf_peers_first(const npf_peers *ps) { (void)ps; return NULL; }
void npf_peers_set_idle(npf_peers *ps, int idle_ms) { ps->idle_ms = idle_ms; }
int npf_peers_idle(const npf_peers *ps) { return ps->idle_ms; }
int npf_peers_add_kind(npf_peers *ps, const npf_fwd_kind *k, void *arg)
{
    (void)ps, (void)k, (void)arg;
    return -1;
}

npf_call *npf_peers_fwd_call(npf_peers *ps, int id)
{
    (void)ps, (void)id;
    return NULL;
}

void npf_peers_set_limits(npf_peers *ps, int per_mapping, int per_address, int per_address_minute)
{
    (void)ps, (void)per_mapping, (void)per_address, (void)per_address_minute;
}

void npf_peers_public_json(npf_peers *ps, int close, struct npf_out *o)
{
    (void)ps, (void)close;
    npf_out_printf(o, "[]");
}

/* no npf_peer exists: the rest is never called */
npf_peer *npf_peer_next(const npf_peer *p) { (void)p; return NULL; }
void npf_peer_set_tag(npf_peer *p, int tag) { (void)p, (void)tag; }
int npf_peer_tag(const npf_peer *p) { (void)p; return 0; }
const char *npf_peer_label(const npf_peer *p) { (void)p; return ""; }
const char *npf_peer_shown(const npf_peer *p) { (void)p; return ""; }
const char *npf_peer_nick(const npf_peer *p) { (void)p; return ""; }
const char *npf_peer_resources(const npf_peer *p) { (void)p; return NULL; }
int npf_peer_resources_set(npf_peer *p, const char *json) { (void)p, (void)json; return -1; }

const char *npf_peer_status(const npf_peer *p, char *buf, size_t cap)
{
    (void)p;
    snprintf(buf, cap, "ended");
    return buf;
}

void npf_peer_set_on_demand(npf_peer *p, int idle_ms) { (void)p, (void)idle_ms; }
void npf_peer_idle_put(npf_peer *p, int idle_ms) { (void)p, (void)idle_ms; }
void npf_peer_connect_put(npf_peer *p, int connect, int idle_ms, int running)
{
    (void)p, (void)connect, (void)idle_ms, (void)running;
}
int npf_peer_on_demand(const npf_peer *p) { (void)p; return 0; }
int npf_peer_wake_now(npf_peer *p) { (void)p; return -1; }
int npf_peer_password_try(npf_peer *p, const char *password) { (void)p, (void)password; return -1; }

int npf_peer_forward_add_parts(npf_peer *p, const npf_fwd_new *fn, int perm, uint64_t ext, char *err, size_t errcap)
{
    (void)p, (void)fn, (void)perm, (void)ext;
    snprintf(err, errcap, "%s", not_built);
    return -1;
}

const char *npf_peers_kind_norm(npf_peers *ps, char opt, const char *spec, char *buf, size_t cap)
{
    (void)ps, (void)opt, (void)buf, (void)cap;
    return spec;
}

int npf_peer_forward_add_kind(npf_peer *p, char opt, const char *spec, int perm, char *err, size_t errcap)
{
    (void)p, (void)opt, (void)spec, (void)perm;
    snprintf(err, errcap, "%s", not_built);
    return -1;
}

int npf_peer_forward_del_at(npf_peer *p, int i) { (void)p, (void)i; return -1; }

int npf_peer_forward_set_public(npf_peer *p, int i, const char *const *allow, int nallow, uint32_t rate)
{
    (void)p, (void)i, (void)allow, (void)nallow, (void)rate;
    return -1;
}

int npf_peer_forward_drain(npf_peer *p, int i, int on) { (void)p, (void)i, (void)on; return -1; }
int npf_peer_forward_drained(npf_peer *p, int i) { (void)p, (void)i; return 1; }
void npf_peer_grant_update(npf_peer *p) { (void)p; }
void npf_peer_forward_set_ext(npf_peer *p, int i, uint64_t ext) { (void)p, (void)i, (void)ext; }
uint64_t npf_peer_forward_ext(const npf_peer *p, int i) { (void)p, (void)i; return 0; }

int npf_peer_forward_udp(const npf_peer *p, int i) { (void)p, (void)i; return 0; }
int npf_peer_forward_id(const npf_peer *p, int i) { (void)p, (void)i; return 0; }
int npf_peer_forward_by_id(const npf_peer *p, int id) { (void)p, (void)id; return -1; }
int npf_peer_forward_used(const npf_peer *p) { (void)p; return 0; }
void npf_peer_forward_mark(npf_peer *p, int perm) { (void)p, (void)perm; }
void npf_peer_forward_perm_set(npf_peer *p, int i, int perm) { (void)p, (void)i, (void)perm; }
int npf_peer_forward_state(const npf_peer *p, int i, npf_fwd_state *st) { (void)p, (void)i, (void)st; return -1; }
void npf_peer_forward_set_ctx(npf_peer *p, int i, void *ctx) { (void)p, (void)i, (void)ctx; }
npf_peer *npf_peers_fwd_find(const npf_peers *ps, int id, int *idx) { (void)ps, (void)id, (void)idx; return NULL; }
npf_peer *npf_peers_by_id(const npf_peers *ps, uint32_t id) { (void)ps, (void)id; return NULL; }
void npf_peers_no_cache(npf_peers *ps) { (void)ps; }
uint32_t npf_peer_id(const npf_peer *p) { (void)p; return 0; }
void *npf_peer_ctx(const npf_peer *p) { (void)p; return NULL; }
void npf_peer_ctx_put(npf_peer *p, void *ctx) { (void)p, (void)ctx; }
int npf_peer_connect_mode(const npf_peer *p) { (void)p; return 0; }
int npf_peer_idle_asked(const npf_peer *p) { (void)p; return 0; }
int npf_peer_finished(const npf_peer *p) { (void)p; return 1; }
const char *npf_peer_last_why(const npf_peer *p) { (void)p; return ""; }
int npf_peer_direct_target(const npf_peer *p, const char **host, uint16_t *port)
{
    (void)p, (void)host, (void)port;
    return -1;
}
void npf_peer_set_nick_here(npf_peer *p, const char *nick) { (void)p, (void)nick; }
void npf_peer_set_label(npf_peer *p, const char *name) { (void)p, (void)name; }
int npf_peer_state(const npf_peer *p, int *needs, int *retry_in_ms)
{
    (void)p;
    if (needs)
        *needs = 0;
    if (retry_in_ms)
        *retry_in_ms = 0;
    return 0;
}

const char *npf_peer_forward_info(const npf_peer *p, int i, char *opt, const char **spec, int *perm, char *state,
                                  size_t cap)
{
    (void)p, (void)i, (void)opt, (void)spec, (void)perm, (void)state, (void)cap;
    return NULL;
}

npf_call *npf_peer_call(const npf_peer *p) { (void)p; return NULL; }
uint64_t npf_peer_number(const npf_peer *p) { (void)p; return 0; }
const char *npf_peer_name(const npf_peer *p) { (void)p; return ""; }
int npf_peer_nfwd(const npf_peer *p) { (void)p; return 0; }

int npf_peer_needs_password(const npf_peer *p) { (void)p; return 0; }
int npf_peer_password_wrong(const npf_peer *p) { (void)p; return 0; }
int npf_peer_pairing_lost(const npf_peer *p) { (void)p; return 0; }
int npf_peer_needs_account(const npf_peer *p) { (void)p; return 0; }

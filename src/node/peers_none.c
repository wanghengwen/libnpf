/* npf without sessions of its own to other nodes (NPF_PEERS=OFF: a device
 * that is only called): the peers.h interface with no
 * peer ever. Adding one fails with an error, so "peer =" lines, run --node
 * and node add say it is not built in; the rest is never reached. */
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "npf/out.h"
#include "npf/peers.h"

struct npf_peers {
    int idle_ms;
};

static const char not_built[] = "sessions to other nodes are not built into this npf (NPF_PEERS=OFF)";

int npf_fwd_split(char *s, char **parts, int max)
{
    (void)s, (void)parts, (void)max;
    return -1;
}

const char *npf_fwd_bind(const char *s)
{
    return !*s || strcmp(s, "*") == 0 ? "0.0.0.0" : s;
}

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

npf_peer *npf_peers_add(npf_peers *ps, int argc, char **argv, int keep, char *err, size_t errcap)
{
    (void)ps, (void)argc, (void)argv, (void)keep;
    snprintf(err, errcap, "%s", not_built);
    return NULL;
}

npf_peer *npf_peers_add_line(npf_peers *ps, const char *line, int keep, const char *base_dir, char *err, size_t errcap)
{
    (void)ps, (void)line, (void)keep, (void)base_dir;
    snprintf(err, errcap, "%s", not_built);
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

const char *npf_peers_fwd_norm(npf_peers *ps, const char *opt, const char *spec, char *buf, size_t cap)
{
    (void)ps, (void)opt, (void)buf, (void)cap;
    return spec;
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

const char *npf_peer_forwards(const npf_peer *p, char *buf, size_t cap)
{
    (void)p;
    snprintf(buf, cap, "%s", "");
    return buf;
}

void npf_peer_set_persist(npf_peer *p, int on) { (void)p, (void)on; }
void npf_peer_set_on_demand(npf_peer *p, int idle_ms) { (void)p, (void)idle_ms; }
int npf_peer_on_demand(const npf_peer *p) { (void)p; return 0; }
int npf_peer_wake(npf_peer *p) { (void)p; return -1; }
int npf_peer_persist(const npf_peer *p) { (void)p; return 0; }

int npf_peer_forward_add(npf_peer *p, const char *opt, const char *spec, int perm, char *err, size_t errcap)
{
    (void)p, (void)opt, (void)spec, (void)perm;
    snprintf(err, errcap, "%s", not_built);
    return -1;
}

int npf_peer_forward_del(npf_peer *p, const char *opt, const char *spec, int *perm)
{
    (void)p, (void)opt, (void)spec, (void)perm;
    return -1;
}

int npf_peer_forward_add_ext(npf_peer *p, const char *opt, const char *spec, int perm, uint64_t ext, char *err,
                             size_t errcap)
{
    (void)ext;
    return npf_peer_forward_add(p, opt, spec, perm, err, errcap);
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

int npf_peer_forward_ends(const npf_peer *p, int i, int *port, const char **host, int *hostport)
{
    (void)p, (void)i, (void)port, (void)host, (void)hostport;
    return -1;
}

int npf_peer_forward_udp(const npf_peer *p, int i) { (void)p, (void)i; return 0; }
int npf_peer_forward_id(const npf_peer *p, int i) { (void)p, (void)i; return 0; }
int npf_peer_forward_by_id(const npf_peer *p, int id) { (void)p, (void)id; return -1; }
int npf_peer_forward_used(const npf_peer *p) { (void)p; return 0; }
void npf_peer_forward_mark(npf_peer *p, int perm) { (void)p, (void)perm; }

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

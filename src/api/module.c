/* The modules' hooks (npf/module.h): each module in the table's order. */
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"

#define EACH(m) for (const npf_module *const *mp_ = npf_modules; ((m) = *mp_) != NULL; mp_++)

static int slot_of(const npf_module *m)
{
    int i;
    for (i = 0; i < NPF_MOD_MAX && npf_modules[i]; i++)
        if (npf_modules[i] == m)
            return i;
    return -1;
}

void *npf_mod_state(npf_t *n, const npf_module *m)
{
    int i = slot_of(m);
    return i >= 0 ? n->mod_state[i] : NULL;
}

void npf_mod_set_state(npf_t *n, const npf_module *m, void *state)
{
    int i = slot_of(m);
    if (i >= 0)
        n->mod_state[i] = state;
}

void npf_mod_jkey(npf_out *o, int *first, const char *k)
{
    npf_out_printf(o, "%s\"%s\":", *first ? "" : ",", k);
    *first = 0;
}

int npf_mod_key_known(const char *k)
{
    const npf_module *m;
    EACH(m) {
        const char *const *kk;
        for (kk = m->keys; kk && *kk; kk++)
            if (strcmp(*kk, k) == 0)
                return 1;
    }
    return 0;
}

int npf_mods_create(npf_t *n, char *err, size_t errcap)
{
    const npf_module *m;
    int i = 0;
    EACH(m) {
        if (++i > NPF_MOD_MAX) {
            snprintf(err, errcap, "more than %d modules", NPF_MOD_MAX);
            return -1;
        }
        if (m->create && m->create(n, err, errcap) < 0)
            return -1;
    }
    n->mods_made = 1;
    return 0;
}

/* a hook of every module, once they are all made (a module's own end and
 * destroy also after a failed npf_create: they look at their state) */
#define CALL(hook, ...)                                                                                              \
    do {                                                                                                             \
        const npf_module *m;                                                                                         \
        if (n->mods_made)                                                                                            \
            EACH(m) if (m->hook) m->hook(__VA_ARGS__);                                                               \
    } while (0)
#define CALL_ALWAYS(hook, ...)                                                                                       \
    do {                                                                                                             \
        const npf_module *m;                                                                                         \
        EACH(m) if (m->hook) m->hook(__VA_ARGS__);                                                                   \
    } while (0)

void npf_mods_begin(npf_t *n) { CALL(begin, n); }

int npf_mods_end(npf_t *n, int step)
{
    const npf_module *m;
    int ms = 0, r;
    EACH(m) if (m->end && (r = m->end(n, step)) > ms) ms = r;
    return ms;
}
void npf_mods_destroy(npf_t *n) { CALL_ALWAYS(destroy, n); }
void npf_mods_login(npf_t *n) { CALL(login, n); }
void npf_mods_event(npf_t *n, const char *type, const npf_json *j, int d) { CALL(event, n, type, j, d); }
void npf_mods_account(npf_t *n, int on) { CALL(account, n, on); }
void npf_mods_call_state(npf_t *n, npf_call *call, int st, const char *why) { CALL(call_state, n, call, st, why); }
void npf_mods_peer_up(npf_t *n, npf_peer *p, npf_call *call) { CALL(peer_up, n, p, call); }
void npf_mods_peer_done(npf_t *n, npf_peer *p, const char *why) { CALL(peer_done, n, p, why); }
void npf_mods_peer_fwd(npf_t *n, npf_peer *p, int i, int up, const char *why) { CALL(peer_fwd, n, p, i, up, why); }
void npf_mods_peer_removed(npf_t *n) { CALL(peer_removed, n); }
void npf_mods_nick_set(npf_t *n, const char *target, const char *nick) { CALL(nick_set, n, target, nick); }
void npf_mods_fwds_saved(npf_t *n, npf_ldev *d) { CALL(fwds_saved, n, d); }
void npf_mods_status_json(npf_t *n, npf_out *o, int *first) { CALL(status_json, n, o, first); }
void npf_mods_status_text(npf_t *n, npf_out *o) { CALL(status_text, n, o); }

void npf_mods_peer_opened(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from)
{
    CALL(peer_opened, n, p, mapping, port, from);
}

void npf_mods_peer_conn(npf_t *n, npf_peer *p, npf_call *call, uint64_t mapping, int port,
                        const struct sockaddr_storage *from, int64_t start, int64_t end,
                        const struct npf_sublink_stats *st)
{
    CALL(peer_conn, n, p, call, mapping, port, from, start, end, st);
}

void npf_mods_peer_refused(npf_t *n, npf_peer *p, uint64_t mapping, int port, const struct sockaddr_storage *from,
                           const char *why, int opened)
{
    CALL(peer_refused, n, p, mapping, port, from, why, opened);
}

int npf_mods_sig_busy(npf_t *n)
{
    const npf_module *m;
    if (!n->mods_made)
        return 0;
    EACH(m) if (m->sig_busy && m->sig_busy(n)) return 1;
    return 0;
}

int npf_mods_peer_removing(npf_t *n, npf_peer *p)
{
    const npf_module *m;
    int again = 0;
    if (!n->mods_made)
        return 0;
    EACH(m) if (m->peer_removing && m->peer_removing(n, p)) again = 1;
    return again;
}

int npf_mods_cmd(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o, int *rc)
{
    const npf_module *m;
    if (!n->mods_made)
        return 0;
    EACH(m) {
        const npf_mod_cmd *c;
        for (c = m->cmds; c && c->name; c++)
            if (strcmp(c->name, argv[0]) == 0) {
                *rc = c->run(n, argc, argv, cb, user, o);
                return 1;
            }
    }
    return 0;
}

int npf_mods_node_list(npf_t *n, npf_text_cb cb, void *user, npf_out *o, int *rc)
{
    const npf_module *m;
    if (!n->mods_made)
        return 0;
    EACH(m) if (m->node_list && m->node_list(n, cb, user, o, rc)) return 1;
    return 0;
}

int npf_mods_check(npf_t *n, const char *k, const char *v, npf_out *o)
{
    const npf_module *m;
    EACH(m) {
        const char *const *kk;
        for (kk = m->keys; kk && *kk; kk++)
            if (strcmp(*kk, k) == 0)
                return m->check ? m->check(n, k, v, o) : 0;
    }
    return -1;
}

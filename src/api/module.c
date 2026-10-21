/* The modules (npf/module.h): their registration, and the hooks of an
 * instance's modules in the order they were registered. */
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf_int.h"
#include "npf/conf.h"
#include "npf/module.h"

#ifdef _WIN32
#include <windows.h>
static SRWLOCK g_mu = SRWLOCK_INIT;
#define LOCK()   AcquireSRWLockExclusive(&g_mu)
#define UNLOCK() ReleaseSRWLockExclusive(&g_mu)
#else
#include <pthread.h>
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define LOCK()   pthread_mutex_lock(&g_mu)
#define UNLOCK() pthread_mutex_unlock(&g_mu)
#endif

/* the modules registered, NULL at the end: an instance takes them at npf_create */
static const npf_module *g_mods[NPF_MOD_MAX + 1];

static int has_cmd(const npf_module *m, const char *name)
{
    const npf_mod_cmd *c;
    for (c = m->cmds; c && c->name; c++)
        if (strcmp(c->name, name) == 0)
            return 1;
    return 0;
}

static int has_key(const npf_module *m, const char *k)
{
    const char *const *kk;
    for (kk = m->keys; kk && *kk; kk++)
        if (strcmp(*kk, k) == 0)
            return 1;
    return 0;
}

/* m's name, commands and keys clash with none of libnpf's and of the
 * modules registered (count of them)? */
static int fits(const npf_module *m, int count)
{
    const npf_mod_cmd *c;
    const char *const *kk;
    int i;
    if (!m->name || !*m->name)
        return 0;
    for (i = 0; i < count; i++)
        if (strcmp(g_mods[i]->name, m->name) == 0)
            return 0;
    for (c = m->cmds; c && c->name; c++) {
        if (!c->run || npf_cmd_builtin(c->name))
            return 0;
        for (i = 0; i < count; i++)
            if (has_cmd(g_mods[i], c->name))
                return 0;
    }
    for (kk = m->keys; kk && *kk; kk++) {
        if (npf_conf_known(*kk))
            return 0;
        for (i = 0; i < count; i++)
            if (has_key(g_mods[i], *kk))
                return 0;
    }
    return 1;
}

int npf_register_module(const npf_module *m)
{
    int i, r = -1;
    if (!m)
        return -1;
    LOCK();
    for (i = 0; i < NPF_MOD_MAX && g_mods[i]; i++)
        ;
    if (i < NPF_MOD_MAX && fits(m, i)) {
        g_mods[i] = m;
        r = 0;
    }
    UNLOCK();
    return r;
}

void npf_mods_take(npf_t *n)
{
    LOCK();
    memcpy(n->mods, g_mods, sizeof n->mods);
    UNLOCK();
}

#define EACH(m) for (const npf_module *const *mp_ = n->mods; ((m) = *mp_) != NULL; mp_++)

static int slot_of(const npf_t *n, const npf_module *m)
{
    int i;
    for (i = 0; i < NPF_MOD_MAX && n->mods[i]; i++)
        if (n->mods[i] == m)
            return i;
    return -1;
}

void *npf_mod_state(npf_t *n, const npf_module *m)
{
    int i = slot_of(n, m);
    return i >= 0 ? n->mod_state[i] : NULL;
}

void npf_mod_set_state(npf_t *n, const npf_module *m, void *state)
{
    int i = slot_of(n, m);
    if (i >= 0)
        n->mod_state[i] = state;
}

void npf_mod_jkey(npf_out *o, int *first, const char *k)
{
    npf_out_printf(o, "%s\"%s\":", *first ? "" : ",", k);
    *first = 0;
}

int npf_mod_key_known(npf_t *n, const char *k)
{
    const npf_module *m;
    EACH(m) if (has_key(m, k)) return 1;
    return 0;
}

/* in order; one that fails cleans up after itself, and only those made
 * before it are ended and destroyed */
int npf_mods_create(npf_t *n, char *err, size_t errcap)
{
    int i;
    for (i = 0; n->mods[i]; i++) {
        if (n->mods[i]->create && n->mods[i]->create(n, err, errcap) < 0)
            return -1;
        n->mods_created = i + 1;
    }
    n->mods_made = 1;
    return 0;
}

/* a hook of every module, once they are all made */
#define CALL(hook, ...)                                                                                              \
    do {                                                                                                             \
        const npf_module *m;                                                                                         \
        if (n->mods_made)                                                                                            \
            EACH(m) if (m->hook) m->hook(__VA_ARGS__);                                                               \
    } while (0)

void npf_mods_begin(npf_t *n) { CALL(begin, n); }

/* the modules made (also after a failed npf_create) */
int npf_mods_end(npf_t *n, int step)
{
    int i, ms = 0, r;
    for (i = 0; i < n->mods_created; i++)
        if (n->mods[i]->end && (r = n->mods[i]->end(n, step)) > ms)
            ms = r;
    return ms;
}

/* the modules made, the last first */
void npf_mods_destroy(npf_t *n)
{
    int i;
    for (i = n->mods_created; i-- > 0;)
        if (n->mods[i]->destroy)
            n->mods[i]->destroy(n);
    n->mods_created = 0;
    n->mods_made = 0;
}
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

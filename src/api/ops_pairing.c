/* libnpf: a device's pairing (npf_pairing_*, npf_owner_reset and
 * npf_share_*): its password, the keys paired and their roles, the owner
 * reset, the share codes. Without a number (no callee state yet) or in safe
 * mode: NPF_ESTATE. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api_internal.h"

/* the callee state, once there is a number (npf_become_node makes the
 * state first), out of safe mode (callee.h: its file and the copy damaged,
 * nothing known or changed; a repaired file is read first) */
static npf_callee *callee_of(npf_t *n)
{
    npf_callee *c = n->has_number ? n->callee : NULL;
    if (c)
        npf_callee_refresh(c);
    return c && !c->damaged ? c : NULL;
}

static int callee_rc(int r)
{
    return r == 0 ? NPF_OK : r == -2 ? NPF_ESAVE : NPF_EINVAL;
}

static int pw_get_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_callee *c = callee_of(n);
    if (!c)
        return NPF_ESTATE;
    if (strlen(c->password) >= x->size)
        return NPF_ETOOBIG;
    snprintf(x->out, x->size, "%s", c->password);
    return NPF_OK;
}

int npf_pairing_password_get(npf_t *n, char *out, size_t cap)
{
    op_arg x = {.out = out, .size = cap};
    if (!out || !cap)
        return NPF_EINVAL;
    out[0] = 0;
    return npf_api_op(n, pw_get_run, &x);
}

static int pw_set_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    npf_callee *c = callee_of(n);
    int r;
    if (!c)
        return n->has_number ? op_fail(x, NPF_ESTATE, "not changed: the device's state file is damaged (safe mode)")
                             : NPF_ESTATE;
    if ((r = npf_callee_password_set(c, x->in)) == -1)
        return op_fail(x, NPF_EINVAL, "the password needs 8 to 127 bytes and must not look like a share code");
    if (r == -2)
        return op_fail(x, NPF_ESAVE, "in effect, but the device's state could not be written");
    return callee_rc(r);
}

int npf_pairing_password_set(npf_t *n, const char *password, char *err, size_t errcap)
{
    op_arg x = {.in = password, .err = err, .errcap = errcap};
    err_clear(err, errcap);
    if (!password)
        return NPF_EINVAL;
    return npf_api_op(n, pw_set_run, &x);
}

static int pairing_list_run(npf_t *n, void *arg)
{
    npf_callee *c = callee_of(n);
    npf_pairing pr;
    int k;
    if (!c)
        return NPF_ESTATE;
    for (k = 0; k < c->npaired; k++) {
        memset(&pr, 0, sizeof pr);
        memcpy(pr.key, c->paired[k].pub, 32);
        pr.since = c->paired[k].added;
        pr.admin = npf_callee_is_admin(c, pr.key);
        list_put(arg, &pr, sizeof pr);
    }
    return NPF_OK;
}

int npf_pairing_list_size(npf_t *n, npf_pairing *out, size_t size, size_t cap, size_t *count)
{
    return op_list(n, pairing_list_run, 0, out, size, cap, count);
}

static int unpair_run(npf_t *n, void *arg)
{
    npf_callee *c = callee_of(n);
    int r;
    if (!c)
        return NPF_ESTATE;
    r = npf_callee_unpair_key(c, arg);
    return r == -1 ? NPF_ENOENT : callee_rc(r);
}

int npf_pairing_remove(npf_t *n, const uint8_t key[32])
{
    return npf_api_op(n, unpair_run, (void *)key);
}

static int owner_reset_run(npf_t *n, void *arg)
{
    npf_callee *c = callee_of(n);
    (void)arg;
    return c ? callee_rc(npf_callee_owner_reset(c)) : NPF_ESTATE;
}

int npf_owner_reset(npf_t *n)
{
    return npf_api_op(n, owner_reset_run, NULL);
}

/* ---- share codes ---- */

_Static_assert(NPF_SHARES_MAX == NPF_MAX_SHARES && NPF_SHARE_CODE_LEN == NPF_SHARE_LEN, "npf.h's share limits");

typedef struct share_job {
    npf_share_cb cb;
    void        *user;
} share_job;

static void share_info(npf_share_info *i, const npf_share *s)
{
    memset(i, 0, sizeof *i);
    snprintf(i->locator, sizeof i->locator, "%s", s->id);
    i->uses = s->uses;
    i->expires = s->expires;
}

static void share_made(void *arg, int rc, const char *code, const npf_share *s)
{
    share_job *j = arg;
    npf_share_info i;
    if (rc == 0)
        share_info(&i, s);
    j->cb(j->user,
          rc == 0 ? NPF_OK : rc == -1 ? NPF_EBUSY : rc == -3 ? NPF_ESTATE : rc == -4 ? NPF_EUNAVAIL : NPF_EFAIL,
          rc == 0 ? code : NULL, rc == 0 ? &i : NULL);
    if (rc == 0)
        npf_wipe(&i, sizeof i);
    free(j);
}

static int share_new_run(npf_t *n, void *arg)
{
    op_arg *x = arg;
    const int64_t *ttl = x->in;
    npf_callee *c = callee_of(n);
    int r;
    if (!c)
        return NPF_ESTATE;
    r = npf_callee_share_new(c, (int)x->id, *ttl, share_made, x->out);
    return r == 0 ? NPF_OK : r == -1 ? NPF_EBUSY : r == -5 ? NPF_ENOMEM : NPF_ESTATE;
}

int npf_share_new(npf_t *n, int uses, int64_t ttl_s, npf_share_cb cb, void *user)
{
    share_job *j;
    op_arg x;
    int rc;
    if (!cb)
        return NPF_EINVAL;
    if (!(j = calloc(1, sizeof *j)))
        return NPF_ENOMEM;
    *j = (share_job){.cb = cb, .user = user};
    x = (op_arg){.id = uses < 0 ? 0 : (uint32_t)uses, .in = &ttl_s, .out = j};
    if ((rc = npf_api_op(n, share_new_run, &x)) != NPF_OK)
        free(j);
    return rc;
}

static int share_list_run(npf_t *n, void *arg)
{
    npf_callee *c = callee_of(n);
    npf_share_info i;
    int64_t now = (int64_t)time(NULL);
    int k;
    if (!c)
        return NPF_ESTATE;
    for (k = 0; k < c->nshares; k++)
        if (c->shares[k].expires > now && c->shares[k].uses > 0 && c->shares[k].fails < 5) {
            share_info(&i, &c->shares[k]);
            list_put(arg, &i, sizeof i);
        }
    return NPF_OK;
}

int npf_share_list_size(npf_t *n, npf_share_info *out, size_t size, size_t cap, size_t *count)
{
    return op_list(n, share_list_run, 0, out, size, cap, count);
}

static int share_del_run(npf_t *n, void *arg)
{
    npf_callee *c = callee_of(n);
    int r;
    if (!c)
        return NPF_ESTATE;
    r = npf_callee_share_del(c, arg);
    return r == -1 ? NPF_ENOENT : callee_rc(r);
}

int npf_share_del(npf_t *n, const char *locator)
{
    if (!locator || strlen(locator) != NPF_SHARE_ID)
        return locator ? NPF_ENOENT : NPF_EINVAL;
    return npf_api_op(n, share_del_run, (void *)locator);
}

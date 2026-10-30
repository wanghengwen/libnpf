/* libnpf: a device's pairing (npf_pairing_* and npf_owner_reset): its
 * password, the keys paired, the owner reset. Without a number (no callee
 * state yet) or in safe mode: NPF_ESTATE. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

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
        return op_fail(x, NPF_EINVAL, "the password needs 8 to 127 bytes");
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

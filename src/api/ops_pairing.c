/* libnpf: a device's pairing (npf_pairing_* and npf_owner_reset): its
 * password, the keys paired, the owner reset. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"
#include "ops_internal.h"
/* ---- a device's pairing ---- */

static int callee_rc(int r)
{
    return r == 0 ? NPF_OK : r == -2 ? NPF_ESAVE : NPF_EINVAL;
}

static int pw_get_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    if (strlen(n->callee->password) >= (size_t)x->flags)
        return NPF_ETOOBIG;
    snprintf(x->out, (size_t)x->flags, "%s", n->callee->password);
    return NPF_OK;
}

int npf_pairing_password_get(npf_t *n, char *out, size_t cap)
{
    pid_arg x = {.flags = (int)cap, .out = out};
    if (!out || !cap || cap > 1 << 20)
        return NPF_EINVAL;
    out[0] = 0;
    return npf_api_op(n, pw_get_run, &x);
}

static int pw_set_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int r;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    r = npf_callee_password_set(n->callee, x->a);
    if (r == -1)
        err_set(x->err, x->errcap, "%s", "the password needs 8 to 127 bytes");
    else if (r == -2)
        err_set(x->err, x->errcap, "%s", "in effect, but the device's state could not be written");
    return callee_rc(r);
}

int npf_pairing_password_set(npf_t *n, const char *password, char *err, size_t errcap)
{
    pid_arg x = {.a = password, .err = err, .errcap = errcap};
    if (err && errcap)
        err[0] = 0;
    if (!password)
        return NPF_EINVAL;
    return npf_api_op(n, pw_set_run, &x);
}

typedef struct pl_arg {
    npf_pairing *out;
    size_t       elem, cap, *count;
} pl_arg;

static int pairing_list_run(npf_t *n, void *arg)
{
    pl_arg *x = arg;
    npf_pairing pr;
    int k;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    for (k = 0; k < n->callee->npaired; k++) {
        if (*x->count < x->cap) {
            memset(&pr, 0, sizeof pr);
            pr.size = sizeof pr;
            memcpy(pr.key, n->callee->paired[k].pub, 32);
            pr.since = n->callee->paired[k].added;
            put_elem(x->out, x->elem, *x->count, &pr, sizeof pr);
        }
        (*x->count)++;
    }
    return list_rc(*x->count, x->cap);
}

int npf_pairing_list_size(npf_t *n, npf_pairing *out, size_t elem_size, size_t cap, size_t *count)
{
    pl_arg x = {.out = out, .elem = elem_size, .cap = cap, .count = count};
    if (!count || (cap && !out) || elem_size < sizeof(npf_pairing))
        return NPF_EINVAL;
    *count = 0;
    return npf_api_op(n, pairing_list_run, &x);
}

static int unpair_run(npf_t *n, void *arg)
{
    pid_arg *x = arg;
    int r;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    r = npf_callee_unpair_key(n->callee, x->out);
    return r == -1 ? NPF_ENOENT : callee_rc(r);
}

int npf_pairing_remove(npf_t *n, const uint8_t key[32])
{
    pid_arg x = {.out = (void *)key};
    return npf_api_op(n, unpair_run, &x);
}

static int owner_reset_run(npf_t *n, void *arg)
{
    (void)arg;
    if (!n->callee || !n->has_number)
        return NPF_ESTATE;
    return callee_rc(npf_callee_owner_reset(n->callee));
}

int npf_owner_reset(npf_t *n)
{
    return npf_api_op(n, owner_reset_run, NULL);
}

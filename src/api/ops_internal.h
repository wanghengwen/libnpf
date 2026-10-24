/* shared by the operations of npf.h's objects: ops.c (the records, this
 * node), ops_peer.c, ops_forward.c, ops_resource.c, ops_pairing.c. Each
 * operation is an argument structure, a _run that runs on the instance's
 * thread (npf_api_op) and the public function that fills the one and waits
 * for the other. */
#ifndef NPF_OPS_INTERNAL_H
#define NPF_OPS_INTERNAL_H

#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "npf_int.h"

/* the application's structure into ours: what both know (size first) */
static inline int copy_in(void *dst, size_t dsize, const void *src, size_t min)
{
    size_t size;
    if (!src)
        return -1;
    memcpy(&size, src, sizeof size);
    if (size < min)
        return -1;
    memcpy(dst, src, size < dsize ? size : dsize);
    memcpy(dst, &dsize, sizeof dsize);
    return 0;
}

/* ours into the application's (its size kept, the rest of ours left out) */
static inline int copy_out(void *dst, const void *src, size_t ssize)
{
    size_t size;
    if (!dst)
        return -1;
    memcpy(&size, dst, sizeof size);
    if (size < sizeof size)
        return -1;
    memcpy(dst, src, size < ssize ? size : ssize);
    if (size > ssize)
        memset((char *)dst + ssize, 0, size - ssize);
    memcpy(dst, &size, sizeof size);
    return 0;
}

/* a list of structures with the caller's element size: element i at i * elem */
static inline void put_elem(void *out, size_t elem, size_t i, const void *src, size_t ssize)
{
    char *d = (char *)out + i * elem;
    memset(d, 0, elem);
    memcpy(d, src, elem < ssize ? elem : ssize);
    memcpy(d, &elem, sizeof elem);
}

static inline void err_set(char *err, size_t errcap, const char *fmt, const char *s)
{
    if (err && errcap)
        snprintf(err, errcap, fmt, s ? s : "");
}

static inline int no_saved_objects(const npf_t *n)
{
    return (n->opt_flags & NPF_OPT_NO_SAVED_OBJECTS) != 0;
}

static inline int saved_rc(npf_t *n)
{
    return npf_local_save(&n->lc) < 0 ? NPF_ESAVE : NPF_OK;
}

static inline npf_peer *peer_of(npf_t *n, uint32_t id)
{
    return n->peers ? npf_peers_by_id(n->peers, id) : NULL;
}

/* an operation on one object: its id, a flag, two words, a context, where
 * its answer goes, the error text */
typedef struct pid_arg {
    uint32_t    id;
    int         flags;
    const char *a, *b;
    void       *ctx;
    void       *out;
    char       *err;
    size_t      errcap;
} pid_arg;

/* an option set on an object (npf_peer_setopt, npf_forward_setopt) */
typedef struct so_arg {
    uint32_t    id;
    int         opt;
    int         iv;                 /* an int option's value */
    const char *sv;                 /* a string option's */
    void       *ctx;
} so_arg;

/* a list of ids: those of one object (of), or all */
typedef struct list_arg {
    uint32_t  of;
    uint32_t *ids;
    size_t    cap, *count;
} list_arg;

static inline void list_put(list_arg *x, uint32_t id)
{
    if (*x->count < x->cap)
        x->ids[*x->count] = id;
    (*x->count)++;
}

#endif

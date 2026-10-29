/* A shared runtime (npf/loop.h): child loops run by a host loop's thread.
 * Attaching (on the host's thread), each child's round within the host's,
 * and its end: end() steps until it returns -1, then detached and done(). */
#include <stdint.h>
#include <stdlib.h>

#include "npf/out.h"
#include "npf/platform.h"

#include "loop_int.h"

npf_loop *npf_loop_new_child(npf_loop *host)
{
    npf_loop *l = calloc(1, sizeof *l);
    if (!l)
        return NULL;
    l->host = host;
    l->wake_fd = -1;
#ifdef NPF_EVQ
    l->epfd = -1;
#endif
    npf_mutex_init(&l->post_mu);
    l->now = npf_mono_ms();
    return l;
}

void npf_loop_set_logctx(npf_loop *l, npf_log_ctx *ctx)
{
    l->logctx = ctx;
}

static void attach_run(npf_loop *h, void *arg)
{
    npf_loop *c = arg;
    npf_log_ctx *prev;
    if (npf_grow(&h->kids, &h->capkids, (size_t)h->nkids + 1, sizeof *h->kids, 16) < 0) {
        c->cf.done(c, c->carg);         /* the child cannot run: it ends at once */
        return;
    }
    h->kids[h->nkids++] = c;
    c->attached = 1;
    loop_ep_all(c, 1);
    c->now = npf_mono_ms();
    prev = loop_ctx_enter(c);
    c->cf.start(c, c->carg);
    npf_log_ctx_swap(prev);
    npf_loop_wake(c);                   /* what was posted to it before */
}

int npf_loop_attach(npf_loop *c, const npf_child_fns *fns, void *arg)
{
    if (!c->host)
        return -1;
    c->cf = *fns;
    c->carg = arg;
    return npf_loop_post(c->host, attach_run, c);
}

int64_t loop_child_due(npf_loop *c)
{
    int64_t d = c->nheap > 0 ? c->heap[0]->due : INT64_MAX;
    if (__atomic_load_n(&c->woken, __ATOMIC_ACQUIRE) || (__atomic_load_n(&c->stop, __ATOMIC_ACQUIRE) && !c->ending))
        return 0;
    if (c->ending && c->end_due < d)
        d = c->end_due;
    return d;
}

/* each child: a few loads unless it has work */
void loop_run_kids(npf_loop *l)
{
    int k;
    for (k = 0; k < l->nkids; k++) {
        npf_loop *c = l->kids[k];
        int woken = __atomic_load_n(&c->woken, __ATOMIC_ACQUIRE);
        int timers = c->nheap > 0 && c->heap[0]->due <= l->now;
        int stop = __atomic_load_n(&c->stop, __ATOMIC_ACQUIRE);
        npf_log_ctx *prev;
        if (!woken && !timers && !stop)
            continue;
        c->now = l->now;
        prev = loop_ctx_enter(c);
        if (woken)
            loop_run_woken(c);
        if (timers)
            loop_fire_timers(c);
        if (stop && !c->ending) {
            c->ending = 1;
            c->end_due = l->now;
        }
        if (c->ending && c->end_due <= npf_mono_ms()) {
            int ms = c->cf.end(c, c->carg);
            if (ms < 0) {
                npf_log_ctx_swap(prev);
                loop_ep_all(c, 0);      /* its sockets out of the queue: they may be closed and reused */
                c->attached = 0;
                l->kids[k] = l->kids[--l->nkids];
                k--;
                c->cf.done(c, c->carg);     /* the last use of c here */
                continue;
            }
            c->end_due = npf_mono_ms() + ms;
        }
        npf_log_ctx_swap(prev);
    }
}

/* libnpf: the tunnel's rate limits. A port mapping's rate group (its
 * sublinks share the bytes it may move each way), a hosted client's budget
 * (the quota, then the slow speed), the groups counted and reset. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/platform.h"
#include "tunnel_internal.h"

#define RATE_TICK_MS 50     /* a group ran dry: its sublinks looked at again after this */

static void rg_refill(rgroup *g)
{
    int64_t now = npf_mono_ms(), add;
    if (now <= g->at_ms)
        return;
    add = (now - g->at_ms) * (int64_t)g->rate / 1000;
    if (add <= 0)
        return;
    g->at_ms = now;
    g->up = g->up + add > (int64_t)g->rate ? (int64_t)g->rate : g->up + add;
    g->down = g->down + add > (int64_t)g->rate ? (int64_t)g->rate : g->down + add;
}

static void rate_tick_in(npf_tunnel *t);

/* every loop callback into the tunnel holds it (depth): a sublink_done or a
 * transport's write it causes may free the tunnel, which then goes when the
 * callback is done with it (tunnel_leave) */
static void rate_tick(npf_loop *loop, void *arg)
{
    npf_tunnel *t = arg;
    (void)loop;
    t->t_rate = NULL;
    t->depth++;
    rate_tick_in(t);
    tunnel_leave(t);
}

static void rate_tick_in(npf_tunnel *t)
{
    int i;
    for (i = 0; i < t->nrg; i++)
        rg_refill(&t->rg[i]);
    for (i = 0; i < t->nsubs; i++)
        if (t->subs[i]->rg || t->budget)
            tunnel_update_ev(t->subs[i]);
}

/* a group ran dry: its sublinks wait for the next tick */
static void rate_wait(npf_tunnel *t)
{
    if (!t->t_rate)
        t->t_rate = npf_timer_add(t->loop, RATE_TICK_MS, rate_tick, t);
}

/* the budget's slow bucket (none left): one second of burst */
static void budget_refill(npf_budget *b)
{
    int64_t now = npf_mono_ms();
    if (b->at_ms == 0 || b->tokens > b->slow) {
        b->tokens = b->slow;
        b->at_ms = now;
    }
    b->tokens += (double)(now - b->at_ms) * b->slow / 1000;
    if (b->tokens > b->slow)
        b->tokens = b->slow;
    b->at_ms = now;
}

/* bytes the sublink may move now (up: local -> tunnel), at most want */
size_t tunnel_rate_allow(sublink *s, int up, size_t want)
{
    npf_budget *b = s->t->budget;
    if (s->rg && s->rg->rate) {
        int64_t *tok;
        rg_refill(s->rg);
        tok = up ? &s->rg->up : &s->rg->down;
        if (*tok <= 0) {
            rate_wait(s->t);
            return 0;
        }
        if ((int64_t)want > *tok)
            want = (size_t)*tok;
    }
    if (b && b->left <= 0) {                /* the quota is used up: the slow speed */
        budget_refill(b);
        if (b->tokens < 1) {
            rate_wait(s->t);
            return 0;
        }
        if ((double)want > b->tokens)
            want = (size_t)b->tokens;
    } else if (b && (int64_t)want > b->left) {
        want = (size_t)b->left;
    }
    return want;
}

void tunnel_rate_take(sublink *s, int up, size_t n)
{
    npf_budget *b = s->t->budget;
    if (s->rg && s->rg->rate)
        *(up ? &s->rg->up : &s->rg->down) -= (int64_t)n;
    if (b) {
        if (b->idle && b->wake) {
            b->idle = 0;
            b->wake(b->wake_arg);
        }
        if (b->left > 0)
            b->left -= (int64_t)n;
        else
            b->tokens -= (double)n;
    }
}

int npf_tunnel_group_count(const npf_tunnel *t, uint32_t group)
{
    int i, n = 0;
    for (i = 0; i < t->nsubs; i++)
        n += t->subs[i]->rg && t->subs[i]->rg->id == group;
    return n;
}

int npf_tunnel_group_reset(npf_tunnel *t, uint32_t group, const char *why)
{
    int i, n = 0;
    t->depth++;                             /* sublink_done may free the tunnel */
    for (i = t->nsubs - 1; i >= 0 && !t->dead; i--) {   /* from the end: a released one's place takes one seen already */
        sublink *s;
        if (i >= t->nsubs)
            continue;
        s = t->subs[i];
        if (s->rg && s->rg->id == group) {
            s->end = why;
            tunnel_sub_reset(s, NPF_RST_LOCAL);
            n++;
        }
    }
    for (i = 0; i < t->nrg && !t->dead; i++)
        if (t->rg[i].id == group)
            t->rg[i].id = 0;                /* none of its sublinks left: the place is free */
    tunnel_leave(t);
    return n;
}

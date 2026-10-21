/* libnpf: the typed events (npf_callbacks.notify, npf.h). They are queued
 * on the instance's thread and delivered after what made them (never inside
 * the callback or call that made them), in order; an event about a peer or a
 * forward that is still there carries its ctx as it is when delivered. Only
 * while the instance runs: none before npf_start, none after
 * NPF_EV_STOPPED. Without notify the application has the event and session
 * callbacks instead (the legacy JSON events, engine.c). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"

typedef struct npf_evi {
    struct npf_evi *next;
    npf_event       ev;
    char           *why, *name, *json;      /* owned copies */
} npf_evi;

static char *dup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

static void evi_free(npf_evi *e)
{
    free(e->why);
    free(e->name);
    free(e->json);
    free(e);
}

static void deliver_soon(npf_t *n);

int npf_events_typed(const npf_t *n)
{
    return n->cb.notify != NULL;
}

void npf_ev_queue(npf_t *n, const npf_event *ev)
{
    npf_evi *e;
    if (!n->cb.notify || !n->ev_on)
        return;
    if (!(e = calloc(1, sizeof *e)))
        return;
    e->ev = *ev;
    e->ev.size = sizeof e->ev;
    e->why = dup_or_null(ev->why);
    e->name = dup_or_null(ev->name);
    e->json = dup_or_null(ev->json);
    if (n->ev_tail)
        n->ev_tail->next = e;
    else
        n->ev_head = e;
    n->ev_tail = e;
    deliver_soon(n);
}

void npf_ev_simple(npf_t *n, int type, const char *why)
{
    npf_event ev;
    memset(&ev, 0, sizeof ev);
    ev.type = type;
    ev.why = why;
    npf_ev_queue(n, &ev);
}

/* the ctx and state of the object an event is about, as they are now */
static void refresh(npf_t *n, npf_event *ev)
{
    npf_peer *p;
    int i;
    if (ev->type == NPF_EV_PEER_GONE || ev->type == NPF_EV_FORWARD_GONE)
        return;                             /* gone: as it was */
    if (ev->forward) {
        if ((p = npf_peers_fwd_find(n->peers, (int)ev->forward, &i))) {
            npf_fwd_state st;
            if (npf_peer_forward_state(p, i, &st) == 0) {
                ev->ctx = st.ctx;
                if (ev->type == NPF_EV_FORWARD) {
                    ev->state = st.state;
                    ev->reason = st.state == NPF_FWD_FAILED ? st.why_code : 0;
                }
            }
        }
        return;
    }
    if (ev->peer && (p = npf_peers_by_id(n->peers, ev->peer))) {
        ev->ctx = npf_peer_ctx(p);
        if (ev->type == NPF_EV_PEER)
            ev->state = npf_peer_state(p, NULL, &ev->retry_in_ms);
    }
}

void npf_events_flush(npf_t *n)
{
    if (n->ev_flushing)
        return;                             /* from a callback: after it, in the loop below */
    n->ev_flushing = 1;
    while (n->ev_head && n->cb.notify) {
        npf_evi *e = n->ev_head;
        n->ev_head = e->next;
        if (!n->ev_head)
            n->ev_tail = NULL;
        e->ev.why = e->why ? e->why : "";
        e->ev.name = e->name ? e->name : "";
        e->ev.json = e->json;
        refresh(n, &e->ev);
        n->cb.notify(n->cb.user, &e->ev);
        evi_free(e);
    }
    n->ev_flushing = 0;
}

static void flush_timer(npf_loop *loop, void *arg)
{
    npf_t *n = arg;
    (void)loop;
    n->ev_timer = NULL;
    npf_events_flush(n);
}

static void deliver_soon(npf_t *n)
{
    if (!n->ev_timer && n->loop && !n->ev_flushing)
        n->ev_timer = npf_timer_add(n->loop, 0, flush_timer, n);
}

void npf_events_start(npf_t *n)
{
    n->ev_on = 1;
}

/* the run has ended: what is queued, then NPF_EV_STOPPED, the last */
void npf_events_stop(npf_t *n)
{
    npf_event ev;
    if (!n->ev_on)
        return;
    memset(&ev, 0, sizeof ev);
    ev.type = NPF_EV_STOPPED;
    npf_ev_queue(n, &ev);
    npf_events_flush(n);
    npf_events_clear(n);
}

void npf_events_clear(npf_t *n)
{
    npf_evi *e;
    n->ev_on = 0;
    if (n->ev_timer && n->loop)
        npf_timer_cancel(n->loop, n->ev_timer);
    n->ev_timer = NULL;
    while ((e = n->ev_head)) {
        n->ev_head = e->next;
        evi_free(e);
    }
    n->ev_tail = NULL;
}

/* why a session ended, as an NPF_END_* code */
int npf_end_code(const char *why, int local)
{
    static const struct { const char *why; int code; } map[] = {
        {"transport_lost", NPF_END_LOST}, {"timeout", NPF_END_LOST},
        {"auth_failed", NPF_END_REFUSED}, {"unauthorized", NPF_END_REFUSED}, {"wrong_password", NPF_END_REFUSED},
        {"not_paired", NPF_END_REFUSED}, {"pairing_lost", NPF_END_REFUSED}, {"no_account", NPF_END_REFUSED},
        {"revoked", NPF_END_REFUSED}, {"forbidden", NPF_END_REFUSED}, {"busy", NPF_END_REFUSED},
        {"no_path", NPF_END_UNREACHABLE}, {"unreachable", NPF_END_UNREACHABLE}, {"offline", NPF_END_UNREACHABLE},
        {"quota", NPF_END_PLATFORM}, {"secure_plan", NPF_END_PLATFORM}, {"plan_limit", NPF_END_PLATFORM},
        {"idle", NPF_END_LOCAL},
    };
    size_t i;
    if (local)
        return NPF_END_LOCAL;
    if (!why || !*why || strcmp(why, "closed") == 0)
        return NPF_END_PEER;
    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i].why, why) == 0)
            return map[i].code;
    return NPF_END_OTHER;
}

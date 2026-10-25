/* libnpf: the tunnel's virtual local ends (npf_tunnel_open_v): no socket,
 * the owner's read / write / ready instead, polled from a timer; an end
 * closed by its owner (npf_tunnel_vclose) goes at the next poll. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/platform.h"
#include "tunnel_internal.h"

#define VIRT_ROUNDS 64                  /* passes of one poll (a pass reads a frame per sublink) */
#define GONE_MS     30000               /* a closed virtual end waits this long for the peer's FIN */

static void gone_timeout(npf_loop *loop, void *arg)
{
    sublink *s = arg;
    npf_tunnel *t = s->t;
    (void)loop;
    s->t_gone = NULL;
    if (!s->end)
        s->end = "local_reset";
    t->depth++;
    tunnel_sub_reset(s, NPF_RST_TIMEOUT);
    tunnel_leave(t);
}

/* a virtual end its owner closed (npf_tunnel_vclose). A reset: the sublink
 * goes. Else a close: FIN after what was sent (on the data channel, in
 * order), and the sublink waits for the peer's FIN, its data dropped (a
 * RESET at once on the faster control channel overtook what was still on
 * its way: a POST's tail, a QUIT); no credit for it, so the peer stops
 * sending once its window is used up */
static void vend_close(sublink *s)
{
    npf_tunnel *t = s->t;
    int reset = s->vgone == 2;
    s->vgone = 0;
    t->ngone--;
    if (reset) {
        if (!s->end)
            s->end = "local_reset";
        tunnel_sub_reset(s, NPF_RST_LOCAL);
        return;
    }
    s->rx_freed += (uint32_t)s->wq.len; /* discarded bytes still used the peer's window */
    free(s->wq.p);                     /* nobody reads it now; do not retain up to 4 MB until FIN */
    memset(&s->wq, 0, sizeof s->wq);
    if (!s->local_eof) {
        s->local_eof = 1;
        if (!s->fin_first)
            s->fin_first = 1;
        tunnel_send_frame(t, s->id, FR_FIN, NULL, 0);
    }
    s->shut_wr = 1;                     /* no local end to shut down */
    s->gone = 1;
    if (s->peer_fin) {
        tunnel_sub_free(s, 0);
        return;
    }
    s->t_gone = npf_timer_add(t->loop, GONE_MS, gone_timeout, s);
}

/* every virtual end closed since the last look; from the end: freeing s
 * moves the last sublink (seen already) into its place */
static void vends_closed(npf_tunnel *t)
{
    int i;
    for (i = t->nsubs - 1; i >= 0 && t->ngone > 0 && !t->dead; i--)
        if (i < t->nsubs && t->subs[i]->vgone)
            vend_close(t->subs[i]);
}

static void virt_poll(npf_loop *loop, void *arg)
{
    npf_tunnel *t = arg;
    int round, busy = 1;
    (void)loop;
    t->t_virt = NULL;
    t->in_poll = 1;
    t->depth++;
    vends_closed(t);
    for (round = 0; round < VIRT_ROUNDS && busy && !t->dead; round++) {
        int i;
        busy = 0;
        /* from the end: tunnel_io_cb releases s at most, never another, and the
         * last one (seen already) takes its place */
        for (i = t->nsubs - 1; i >= 0 && !t->dead; i--) {
            sublink *s;
            unsigned ev;
            if (i >= t->nsubs)
                continue;
            s = t->subs[i];
            if (!s->v || !(ev = s->ev & s->v->ready(s->varg)))
                continue;
            busy = 1;
            tunnel_io_cb(t->loop, -1, ev, s);
        }
    }
    if (!t->dead)
        vends_closed(t);                /* the ends closed meanwhile */
    t->in_poll = 0;
    if (tunnel_leave(t))
        return;
    if (busy || t->ngone)
        tunnel_virt_arm(t);                    /* more next time: other work goes first */
}

void tunnel_virt_arm(npf_tunnel *t)
{
    if (!t->t_virt && !t->in_poll && !t->dead)
        t->t_virt = npf_timer_add(t->loop, 0, virt_poll, t);
}

void npf_tunnel_vkick(npf_tunnel *t, uint32_t id)
{
    (void)id;
    tunnel_virt_arm(t);
}

/* the owner closed the virtual end: not called again from now on, the rest
 * at the next virt_poll (vend_close). Never here: it may be called from
 * inside one of the end's own calls (write, read, shutdown), whose callers
 * still use the sublink */
void npf_tunnel_vclose(npf_tunnel *t, uint32_t id, int reset)
{
    sublink *s = tunnel_find(t, id);
    if (!s || !s->v)
        return;
    s->v = NULL;
    s->vgone = reset ? 2 : 1;
    t->ngone++;
    tunnel_virt_arm(t);
}

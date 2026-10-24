/* Connections and datagrams waiting for a session, and idle expiry. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/conf.h"
#include "npf/out.h"
#include "npf/crypto.h"
#include "npf/peers.h"
#include "npf/tunnel.h"
#include "npf.h"
#include "npf/platform.h"
#include "udpfwd.h"

#include "peers_internal.h"

static void demand_tick(npf_loop *loop, void *arg);

#define DEMAND_WAIT_MS     30000    /* how long one waits for it */
#define DEMAND_TICK_MS     5000
#define UDP_PENDING_BYTES  (256 * 1024)

void peers_demand_timer(npf_peer *p)
{
    if (!p->t_demand)
        p->t_demand = npf_timer_add(p->ps->n->loop, DEMAND_TICK_MS, demand_tick, p);
}

/* the queues' room freed when nothing waits in them */
static void queues_trim(npf_peer *p)
{
    if (!p->npend) {
        free(p->pend);
        p->pend = NULL;
    }
    if (!p->nuq) {
        free(p->uq);
        p->uq = NULL;
    }
}

/* the peer goes: its queues' room (emptied by peers_demand_drop before) */
void peers_demand_queues_free(npf_peer *p)
{
    p->npend = p->nuq = 0;
    queues_trim(p);
}

/* on demand: a connection before the session: it waits, and the session starts */
void peers_demand_wait(pfwd *f, int fd, uint64_t cid)
{
    npf_peer *p = f->p;
    if (p->npend == DEMAND_PENDING || (!p->pend && !(p->pend = calloc(DEMAND_PENDING, sizeof *p->pend)))) {
        npf_sock_close(fd);
        npf_logw("%s: %s: too many connections waiting for the session, refused", p->name, f->spec);
        peers_conn_gone(p->ps, cid, "no_session");
        return;
    }
    npf_set_nonblock(fd);
    p->pend[p->npend].fd = fd;
    p->pend[p->npend].slot = f->idx;
    p->pend[p->npend].fid = f->id;
    p->pend[p->npend].at = npf_mono_ms();
    p->pend[p->npend].conn = cid;
    p->npend++;
    if (!p->call && !p->waiting) {
        if (p->t_retry) {                   /* someone is waiting: no backoff */
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        npf_log("%s: a connection to %s:%d: starting the session", p->name, f->bind, f->port);
        peers_start_call(p);
        if (p->removed)
            return;                         /* in the done callback of a start that failed: its fds went */
    }
    peers_demand_timer(p);
}

/* the session is up: the waiting connections go into it */
void peers_demand_flush(npf_peer *p)
{
    int k;
    for (k = 0; k < p->npend; k++) {
        pfwd *f = p->fwds[p->pend[k].slot];
        if (f->used && f->id == p->pend[k].fid)    /* still its forward, not another in the slot */
            peers_conn_open(f, p->pend[k].fd, p->pend[k].conn);
        else {
            npf_sock_close(p->pend[k].fd);
            peers_conn_gone(p->ps, p->pend[k].conn, "no_session");
        }
    }
    p->npend = 0;
    p->idle_since = 0;
    queues_trim(p);
}

/* UDP datagrams that waited for the session: dropped (slot -1: all) */
void peers_udp_queue_drop(npf_peer *p, int slot)
{
    int k, n = 0;
    for (k = 0; k < p->nuq; k++) {
        if (slot < 0 || p->uq[k].slot == slot) {
            p->uq_bytes -= p->uq[k].len;
            free(p->uq[k].d);
        } else {
            p->uq[n++] = p->uq[k];
        }
    }
    p->nuq = n;
    queues_trim(p);
}

/* the session is up: the datagrams that waited go into it */
void peers_udp_queue_flush(npf_peer *p)
{
    int k;
    for (k = 0; k < p->nuq; k++) {
        pfwd *f = p->fwds[p->uq[k].slot];
        if (f->used && f->udp && f->fd >= 0 && p->call)
            npf_call_udp_send(p->call, f->fd, &p->uq[k].src, p->uq[k].sl, f->host, (uint16_t)f->hostport, p->uq[k].d,
                              p->uq[k].len);
    }
    peers_udp_queue_drop(p, -1);
}

void peers_demand_drop_slot(npf_peer *p, int slot)
{
    int k, n = 0;
    for (k = 0; k < p->npend; k++)
        if (p->pend[k].slot == slot) {
            npf_sock_close(p->pend[k].fd);
            peers_conn_gone(p->ps, p->pend[k].conn, "mapping_closed");
        } else {
            p->pend[n++] = p->pend[k];
        }
    p->npend = n;
    queues_trim(p);
}

void peers_demand_drop(npf_peer *p, const char *why)
{
    int k;
    if (p->npend)
        npf_logw("%s: %d waiting connection(s) closed (%s)", p->name, p->npend, why);
    for (k = 0; k < p->npend; k++) {
        npf_sock_close(p->pend[k].fd);
        peers_conn_gone(p->ps, p->pend[k].conn, "no_session");
    }
    p->npend = 0;
    if (p->nuq)
        npf_logw("%s: %d waiting UDP datagram(s) dropped (%s)", p->name, p->nuq, why);
    peers_udp_queue_drop(p, -1);
}

/* a UDP datagram before the session (on demand, or between two): it waits, and the session starts */
void peers_udp_wait(pfwd *f, const struct sockaddr_storage *src, socklen_t sl, const uint8_t *buf, size_t len)
{
    npf_peer *p = f->p;
    if (p->nuq == UDP_PENDING || p->uq_bytes + len > UDP_PENDING_BYTES
        || (!p->uq && !(p->uq = calloc(UDP_PENDING, sizeof *p->uq)))
        || !(p->uq[p->nuq].d = malloc(len ? len : 1)))
        return;                             /* UDP: dropped */
    memcpy(p->uq[p->nuq].d, buf, len);
    p->uq[p->nuq].len = len;
    p->uq[p->nuq].slot = f->idx;
    memcpy(&p->uq[p->nuq].src, src, sizeof *src);
    p->uq[p->nuq].sl = sl;
    p->uq[p->nuq].at = npf_mono_ms();
    p->nuq++;
    p->uq_bytes += len;
    if (!p->call && !p->waiting) {
        if (p->t_retry) {                   /* someone is waiting: no backoff */
            npf_timer_cancel(p->ps->n->loop, p->t_retry);
            p->t_retry = NULL;
        }
        npf_log("%s: a UDP datagram to %s:%d: starting the session", p->name, f->bind, f->port);
        peers_start_call(p);
        if (p->removed)
            return;
    }
    peers_demand_timer(p);
}

/* waiting connections past their time; a session without connections ends */
static void demand_tick(npf_loop *loop, void *arg)
{
    npf_peer *p = arg;
    int64_t now = npf_mono_ms();
    int k, n = 0;
    (void)loop;
    p->t_demand = NULL;
    for (k = 0; k < p->npend; k++) {
        if (now - p->pend[k].at > DEMAND_WAIT_MS) {
            npf_sock_close(p->pend[k].fd);
            peers_conn_gone(p->ps, p->pend[k].conn, "no_session");
        } else {
            p->pend[n++] = p->pend[k];
        }
    }
    if (n < p->npend)
        npf_logw("%s: %d connection(s) waited too long for the session, closed", p->name, p->npend - n);
    p->npend = n;
    for (k = n = 0; k < p->nuq; k++) {
        if (now - p->uq[k].at > DEMAND_WAIT_MS) {
            p->uq_bytes -= p->uq[k].len;
            free(p->uq[k].d);
        } else {
            p->uq[n++] = p->uq[k];
        }
    }
    p->nuq = n;
    queues_trim(p);
    if (p->idle_ms && p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED) {
        npf_call_info i;
        npf_call_info_get(p->call, &i);
        if (i.sublinks > 0 || i.udp_flows > 0 || p->npend || p->nuq)
            p->idle_since = 0;
        else if (!p->idle_since)
            p->idle_since = now;
        else if (now - p->idle_since >= p->idle_ms) {
            npf_log("%s: no connection for %d s: the session ends (the next connection starts one)", p->name,
                    p->idle_ms / 1000);
            p->idle_since = 0;
            npf_call_end(p->call, "idle");  /* the state callback does not reconnect */
            return;
        }
    }
    if (p->npend || p->nuq || (p->idle_ms && (p->call || p->waiting)))
        peers_demand_timer(p);
}

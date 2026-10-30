/* Connections and datagrams waiting for a session, and idle expiry. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"

#include "peers_internal.h"

static void ready_wait(npf_peer *p);

#define DEMAND_WAIT_MS     30000    /* how long one waits for it */
#define DEMAND_TICK_MS     5000
#define READY_POLL_MS      100      /* an established session whose transport is not ready: asked this often */
#define UDP_PENDING_BYTES  (256 * 1024)

void peers_demand_timer(npf_peer *p)
{
    if (!p->demand_at)
        peers_at(p, p->demand_at = npf_mono_ms() + DEMAND_TICK_MS);
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

#define ALL INT64_MAX                    /* (conns_drop, dgrams_drop: any time) */

/* someone waits (what: for the log): the session starts unless one is
 * coming; what waits goes in once it is ready, or after DEMAND_WAIT_MS */
static void wait_start(npf_peer *p, const char *what, const pfwd *f)
{
    if (peer_startable(p)) {
        npf_log("%s: %s to %s:%d: starting the session", p->name, what, f->bind, f->port);
        if (peers_kick(p) < 0)
            return;
    }
    peers_demand_timer(p);
    ready_wait(p);
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
    p->pend[p->npend++] = (struct pend_conn){.fd = fd, .slot = f->idx, .fid = f->id, .at = npf_mono_ms(), .conn = cid};
    wait_start(p, "a connection", f);
}

/* a UDP datagram before the session (on demand, or between two): it waits, and the session starts */
void peers_udp_wait(pfwd *f, const struct sockaddr_storage *src, socklen_t sl, const uint8_t *buf, size_t len)
{
    npf_peer *p = f->p;
    uint8_t *d;
    if (p->nuq == UDP_PENDING || p->uq_bytes + len > UDP_PENDING_BYTES
        || (!p->uq && !(p->uq = calloc(UDP_PENDING, sizeof *p->uq))) || !(d = malloc(len ? len : 1)))
        return;                             /* UDP: dropped */
    memcpy(d, buf, len);
    p->uq[p->nuq++] =
        (struct pend_dgram){.slot = f->idx, .src = *src, .sl = sl, .at = npf_mono_ms(), .len = len, .d = d};
    p->uq_bytes += len;
    wait_start(p, "a UDP datagram", f);
}

/* the waiting connections of the forward in slot (-1: any) that came
 * before `before` are closed (why: their record's end); how many */
static int conns_drop(npf_peer *p, int slot, int64_t before, const char *why)
{
    uint64_t gone[DEMAND_PENDING];
    int k, n = 0, ng = 0;
    for (k = 0; k < p->npend; k++)
        if ((slot < 0 || p->pend[k].slot == slot) && p->pend[k].at < before) {
            npf_sock_close(p->pend[k].fd);
            gone[ng++] = p->pend[k].conn;
        } else {
            p->pend[n++] = p->pend[k];
        }
    p->npend = n;
    queues_trim(p);
    /* told once the queue is whole again: the application's callback (an
     * event) may remove the forward or the peer, dropping it in turn */
    for (k = 0; k < ng; k++)
        peers_conn_gone(p->ps, gone[k], why);
    return ng;
}

/* the same for the waiting UDP datagrams: dropped */
static void dgrams_drop(npf_peer *p, int slot, int64_t before)
{
    int k, n = 0;
    for (k = 0; k < p->nuq; k++)
        if ((slot < 0 || p->uq[k].slot == slot) && p->uq[k].at < before) {
            p->uq_bytes -= p->uq[k].len;
            free(p->uq[k].d);
        } else {
            p->uq[n++] = p->uq[k];
        }
    p->nuq = n;
    queues_trim(p);
}

/* the session is up: the waiting connections go into it */
static void demand_flush(npf_peer *p)
{
    struct pend_conn *q = p->pend;          /* taken out: a refusal's callback may drop the queue (conns_drop) */
    int k, n = p->npend;
    p->pend = NULL;
    p->npend = 0;
    p->idle_since = 0;
    for (k = 0; k < n; k++) {
        pfwd *f = p->fwds[q[k].slot];
        if (f->used && f->id == q[k].fid)  /* still its forward, not another in the slot */
            peers_conn_open(f, q[k].fd, q[k].conn);     /* (a removed peer has no session: refused) */
        else {
            npf_sock_close(q[k].fd);
            peers_conn_gone(p->ps, q[k].conn, "no_session");
        }
    }
    free(q);
    queues_trim(p);
}

/* the session is up: the datagrams that waited go into it */
static void udp_queue_flush(npf_peer *p)
{
    int k;
    for (k = 0; k < p->nuq; k++) {
        pfwd *f = p->fwds[p->uq[k].slot];
        if (f->used && f->udp && f->fd >= 0 && p->call)
            npf_call_udp_send(p->call, f->fd, &p->uq[k].src, p->uq[k].sl, f->host, (uint16_t)f->hostport, p->uq[k].d,
                              p->uq[k].len);
    }
    dgrams_drop(p, -1, ALL);
}

/* the session is established but its tunnel cannot take a connection yet
 * (its transport not ready): what waits goes in as soon as it can (the
 * demand tick every READY_POLL_MS meanwhile), not at the next state change
 * (there may be none: the state stays established) */
static void ready_wait(npf_peer *p)
{
    int64_t at = npf_mono_ms() + READY_POLL_MS;
    if ((p->npend || p->nuq) && p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED
        && (!p->demand_at || p->demand_at > at))
        peers_at(p, p->demand_at = at);
}

void peers_ready(npf_peer *p)
{
    if (npf_call_ready(p->call)) {
        demand_flush(p);
        udp_queue_flush(p);
    } else {
        ready_wait(p);
    }
}

void peers_udp_queue_drop(npf_peer *p, int slot)
{
    dgrams_drop(p, slot, ALL);
}

void peers_demand_drop_slot(npf_peer *p, int slot)
{
    conns_drop(p, slot, ALL, "mapping_closed");
}

void peers_demand_drop(npf_peer *p, const char *why)
{
    if (p->npend)
        npf_logw("%s: %d waiting connection(s) closed (%s)", p->name, p->npend, why);
    if (p->nuq)
        npf_logw("%s: %d waiting UDP datagram(s) dropped (%s)", p->name, p->nuq, why);
    conns_drop(p, -1, ALL, "no_session");
    dgrams_drop(p, -1, ALL);
}

/* what waits: into the session if it can take it now, or closed past its
 * time; a session on demand without connections ends */
void peers_demand_tick(npf_peer *p, int64_t now)
{
    int n;
    if (!p->demand_at || p->demand_at > now)
        return;                             /* (none for a removed peer) */
    p->demand_at = 0;
    if (p->npend || p->nuq)
        peers_ready(p);                     /* (a refusal's callback may remove the peer: then nothing waits) */
    if ((n = conns_drop(p, -1, now - DEMAND_WAIT_MS, "no_session")))
        npf_logw("%s: %d connection(s) waited too long for the session, closed", p->name, n);
    dgrams_drop(p, -1, now - DEMAND_WAIT_MS);
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
    if (p->npend || p->nuq || (p->idle_ms && (p->st == PS_CALL || p->st == PS_ASKING)))
        peers_demand_timer(p);
}

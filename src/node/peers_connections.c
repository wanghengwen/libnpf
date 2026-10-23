/* Connection admission, accounting and sublink completion. */
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

#define IP_SLOTS 1024               /* source addresses tracked at once (the least recently seen give way) */

/* ---- public connections: who, how many, how long, how much ---- */

/* an IPv4 visitor on the dual-stack listener (::ffff:a.b.c.d): as IPv4 */
void peers_unmap_v4(struct sockaddr_storage *ss)
{
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
    static const uint8_t pre[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    struct sockaddr_in s4;
    if (ss->ss_family != AF_INET6 || memcmp(s6->sin6_addr.s6_addr, pre, 12) != 0)
        return;
    memset(&s4, 0, sizeof s4);
    s4.sin_family = AF_INET;
    s4.sin_port = s6->sin6_port;
    memcpy(&s4.sin_addr, s6->sin6_addr.s6_addr + 12, 4);
    memset(ss, 0, sizeof *ss);
    memcpy(ss, &s4, sizeof s4);
}

/* the address as 16 bytes (IPv4 as v4-mapped) */
static void addr_key(const struct sockaddr_storage *ss, uint8_t a[16])
{
    memset(a, 0, 16);
    if (ss->ss_family == AF_INET) {
        a[10] = a[11] = 0xff;
        memcpy(a + 12, &((const struct sockaddr_in *)ss)->sin_addr, 4);
    } else if (ss->ss_family == AF_INET6) {
        memcpy(a, &((const struct sockaddr_in6 *)ss)->sin6_addr, 16);
    }
}

/* the address's entry (made when missing; the least recently seen without
 * open connections gives way), -1 when the table is full of busy ones */
static int ip_get(npf_peers *ps, const struct sockaddr_storage *from)
{
    uint8_t a[16];
    int k, free_k = -1, old_k = -1;
    int64_t now = npf_mono_ms();
    if (!ps->ips && !(ps->ips = calloc(IP_SLOTS, sizeof *ps->ips)))
        return -1;
    addr_key(from, a);
    for (k = 0; k < IP_SLOTS; k++) {
        ipent *e = &ps->ips[k];
        if (e->used && memcmp(e->a, a, 16) == 0)
            return k;
        if (!e->used && free_k < 0)
            free_k = k;
        else if (e->used && !e->conns && (old_k < 0 || e->at < ps->ips[old_k].at))
            old_k = k;
    }
    k = free_k >= 0 ? free_k : old_k;
    if (k < 0)
        return -1;
    memset(&ps->ips[k], 0, sizeof ps->ips[k]);
    memcpy(ps->ips[k].a, a, 16);
    ps->ips[k].used = 1;
    ps->ips[k].tokens = ps->lim_rate > 1 ? ps->lim_rate / 2.0 : 1;
    ps->ips[k].at = now;
    return k;
}

/* NULL and the counts taken, or why it is refused */
const char *peers_conn_admit(pfwd *f, const struct sockaddr_storage *from, int *ip)
{
    npf_peers *ps = f->p->ps;
    ipent *e;
    int64_t now = npf_mono_ms();
    *ip = -1;
    if (ps->lim_mapping > 0 && f->nconns >= ps->lim_mapping)
        return "mapping_full";
    if (ps->lim_address <= 0 && ps->lim_rate <= 0) {
        f->nconns++;
        return NULL;
    }
    if ((*ip = ip_get(ps, from)) < 0) {
        f->nconns++;
        return NULL;                        /* nothing to count it on: let it in */
    }
    e = &ps->ips[*ip];
    if (ps->lim_rate > 0) {
        double burst = ps->lim_rate > 1 ? ps->lim_rate / 2.0 : 1;
        e->tokens += (double)(now - e->at) * ps->lim_rate / 60000.0;
        if (e->tokens > burst)
            e->tokens = burst;
    }
    e->at = now;
    if (ps->lim_address > 0 && e->conns >= ps->lim_address) {
        *ip = -1;
        return "address_full";
    }
    if (ps->lim_rate > 0 && e->tokens < 1) {
        *ip = -1;
        return "address_rate";
    }
    if (ps->lim_rate > 0)
        e->tokens -= 1;
    e->conns++;
    f->nconns++;
    return NULL;
}

void peers_conn_refused(pfwd *f, const struct sockaddr_storage *from, const char *why)
{
    npf_peers *ps = f->p->ps;
    char a[80];
    npf_logd("%s: %s: connection from %s refused (%s)", f->p->name, f->spec, npf_addr_str(from, a, sizeof a), why);
    if (ps->cbs.refused)
        ps->cbs.refused(f->p, f->ext, f->port, from, why, 0, ps->arg);
}

uint64_t peers_conn_add(pfwd *f, const struct sockaddr_storage *from, int ip)
{
    npf_peers *ps = f->p->ps;
    pconn *c;
    if (ps->nconns == ps->capconns) {
        int n = ps->capconns ? ps->capconns * 2 : 32;
        pconn *nc = realloc(ps->conns, (size_t)n * sizeof *nc);
        if (!nc) {                          /* not recorded: nor counted (it would never be uncounted) */
            f->nconns--;
            if (ip >= 0)
                ps->ips[ip].conns--;
            return 0;
        }
        ps->conns = nc;
        ps->capconns = n;
    }
    c = &ps->conns[ps->nconns++];
    memset(c, 0, sizeof *c);
    c->id = ++ps->conn_seq;
    c->p = f->p;
    c->slot = f->idx;
    c->fid = f->id;
    c->port = f->port;
    c->mapping = f->ext;
    c->from = *from;
    c->start = npf_node_time(ps->n);
    c->ip = ip;
    if (ps->cbs.opened)
        ps->cbs.opened(f->p, f->ext, f->port, from, ps->arg);
    return c->id;
}

/* a connection ends: its counts go back; reported as a connection (it had a
 * session) or as refused (why: it never got one) */
static void conn_end(npf_peers *ps, int k, const npf_sublink_stats *st, const char *why)
{
    pconn c = ps->conns[k];
    ps->conns[k] = ps->conns[--ps->nconns];
    if (c.p && c.slot < c.p->nfwd && c.p->fwds[c.slot]->used && c.p->fwds[c.slot]->id == c.fid
        && c.p->fwds[c.slot]->nconns > 0)
        c.p->fwds[c.slot]->nconns--;
    if (c.ip >= 0 && ps->ips && ps->ips[c.ip].conns > 0)
        ps->ips[c.ip].conns--;
    if (why) {
        if (ps->cbs.refused)
            ps->cbs.refused(c.p, c.mapping, c.port, &c.from, why, 1, ps->arg);
    } else if (ps->cbs.conn) {
        ps->cbs.conn(c.p, c.call, c.mapping, c.port, &c.from, c.start, npf_node_time(ps->n), st, ps->arg);
    }
}

void peers_conn_gone(npf_peers *ps, uint64_t cid, const char *why)
{
    int k;
    for (k = 0; cid && k < ps->nconns; k++)
        if (ps->conns[k].id == cid) {
            conn_end(ps, k, NULL, why);
            return;
        }
}


/* a forward's connection is in its session now: counted until it ends */
static void sub_add(npf_peers *ps, npf_call *c, uint32_t sid, int fid)
{
    pfwd *f;
    if (ps->nsubs == ps->capsubs) {
        int n = ps->capsubs ? ps->capsubs * 2 : 32;
        struct psub *ns = realloc(ps->subs, (size_t)n * sizeof *ns);
        if (!ns)
            return;
        ps->subs = ns;
        ps->capsubs = n;
    }
    ps->subs[ps->nsubs].call = c;
    ps->subs[ps->nsubs].sid = sid;
    ps->subs[ps->nsubs].fid = fid;
    ps->nsubs++;
    if ((f = peers_fwd_by_id(ps, fid)))
        f->open++;
}

/* a forward's connection ended; refused by the peer's policy: counted, and
 * the application told at most once a second */
static void sub_done(npf_peers *ps, npf_call *c, uint32_t sid, const npf_sublink_stats *st)
{
    int k;
    for (k = 0; k < ps->nsubs; k++)
        if (ps->subs[k].call == c && ps->subs[k].sid == sid) {
            pfwd *f = peers_fwd_by_id(ps, ps->subs[k].fid);
            ps->subs[k] = ps->subs[--ps->nsubs];
            if (!f)
                return;
            if (f->open > 0)
                f->open--;
            if (st && st->end && strcmp(st->end, "target_refused") == 0) {
                int64_t now = npf_mono_ms();
                f->nrefused++;
                if (f->socks)
                    snprintf(f->refused_why, sizeof f->refused_why, "a target not published by the peer");
                else
                    snprintf(f->refused_why, sizeof f->refused_why, "%.24s:%d not published by the peer", f->host,
                             f->hostport);
                if (ps->cbs.fwd_refused && now - f->refused_told >= 1000) {
                    f->refused_told = now;
                    ps->cbs.fwd_refused(f->p, f->idx, ps->arg);
                }
            }
            return;
        }
}

/* a session's sublink opened here ended: a public connection's, a forward's */
static void conn_sublink_done(npf_call *c, uint32_t sid, const npf_sublink_stats *st, void *arg)
{
    npf_peers *ps = arg;
    int k;
    sub_done(ps, c, sid, st);
    for (k = 0; k < ps->nconns; k++)
        if (ps->conns[k].call == c && ps->conns[k].sid == sid) {
            conn_end(ps, k, st, NULL);
            return;
        }
}

/* the session ended: its connections are no longer counted */
void peers_subs_call_gone(npf_peers *ps, npf_call *c)
{
    int k;
    for (k = 0; k < ps->nsubs;) {
        if (ps->subs[k].call == c) {
            pfwd *f = peers_fwd_by_id(ps, ps->subs[k].fid);
            if (f && f->open > 0)
                f->open--;
            ps->subs[k] = ps->subs[--ps->nsubs];
        } else {
            k++;
        }
    }
}

/* into the session (fd is its now) */
void peers_conn_open(pfwd *f, int fd, uint64_t cid)
{
    npf_peer *p = f->p;
    int sid = -1, k;
    if (p->call)
        sid = npf_call_open_rated(p->call, fd, f->socks, f->host, (uint16_t)f->hostport, f->pub ? (uint32_t)f->id : 0,
                                  f->rate);
    if (sid < 0) {
        /* no session, or one that carries as many connections as the
         * other side takes (NPF_MAX_SUBLINKS) */
        int full = p->call && npf_call_state(p->call) == NPF_CALL_ESTABLISHED;
        npf_sock_close(fd);
        if (cid)
            npf_logd("%s: connection to %s:%d refused (%s)", p->name, f->bind, f->port, full ? "session full" : "no session");
        else
            npf_logw("%s: %s, connection to %s:%d refused", p->name, full ? "the session carries all it can" : "session not ready",
                     f->bind, f->port);
        peers_conn_gone(p->ps, cid, full ? "session_full" : "no_session");
        return;
    }
    if (!f->udp && !f->kind)
        sub_add(p->ps, p->call, (uint32_t)sid, f->id);
    npf_call_on_sublink_done(p->call, conn_sublink_done, p->ps);
    for (k = 0; cid && k < p->ps->nconns; k++)
        if (p->ps->conns[k].id == cid) {
            p->ps->conns[k].call = p->call;
            p->ps->conns[k].sid = (uint32_t)sid;
            break;
        }
}

void npf_peers_public_json(npf_peers *ps, int close, npf_out *o)
{
    npf_peer *p;
    int k, first = 1;
    if (close && !ps->closing) {
        ps->closing = 1;
        npf_log("public ports: closing (stopping), %d connection(s) open", ps->nconns);
    }
    npf_out_printf(o, "{\"open\":%d,\"closing\":%s,\"mappings\":[", ps->nconns, ps->closing ? "true" : "false");
    for (p = ps->list; p; p = p->next)
        for (k = 0; k < p->nfwd; k++) {
            pfwd *f = p->fwds[k];
            if (!f->used || !f->pub)
                continue;
            if (ps->closing && (f->fd >= 0 || f->t_retry)) {
                peers_fwd_stop(f);
                npf_log("%s: %s: closed (stopping)", p->name, f->spec);
            }
            npf_out_printf(o, "%s{\"mapping_id\":\"%llu\",\"port\":%d,\"listening\":%s,\"conns\":%d}", first ? "" : ",",
                           (unsigned long long)f->ext, f->port, f->fd >= 0 ? "true" : "false", f->nconns);
            first = 0;
        }
    npf_out_printf(o, "]}");
}

void npf_peers_set_limits(npf_peers *ps, int per_mapping, int per_address, int per_address_minute)
{
    ps->lim_mapping = per_mapping > 0 ? per_mapping : 0;
    ps->lim_address = per_address > 0 ? per_address : 0;
    ps->lim_rate = per_address_minute > 0 ? per_address_minute : 0;
}

/* Node lifecycle and address helpers. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "npf/candidates.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "node_internal.h"

/* ---- addresses ---- */

int npf_addr_parse(const char *s, struct sockaddr_storage *out)
{
    char host[64];
    const char *colon;
    long port;
    char *end;
    memset(out, 0, sizeof *out);
    if (*s == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':' || (size_t)(rb - s - 1) >= sizeof host)
            return -1;
        memcpy(host, s + 1, (size_t)(rb - s - 1));
        host[rb - s - 1] = 0;
        colon = rb + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon || (size_t)(colon - s) >= sizeof host)
            return -1;
        memcpy(host, s, (size_t)(colon - s));
        host[colon - s] = 0;
    }
    port = strtol(colon + 1, &end, 10);
    if (*end || port < 0 || port > 65535)
        return -1;
    if (strchr(host, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)port);
        return inet_pton(AF_INET6, host, &a->sin6_addr) == 1 ? 0 : -1;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)port);
        return inet_pton(AF_INET, host, &a->sin_addr) == 1 ? 0 : -1;
    }
}

const char *npf_addr_str(const struct sockaddr_storage *a, char *b, size_t n)
{
    char ip[INET6_ADDRSTRLEN];
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)a;
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
        snprintf(b, n, "[%s]:%u", ip, ntohs(s6->sin6_port));
    } else if (a->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)a;
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
        snprintf(b, n, "%s:%u", ip, ntohs(s4->sin_port));
    } else {
        snprintf(b, n, "-");
    }
    return b;
}

int npf_node_init(npf_node *n, npf_loop *loop, const npf_node_cfg *cfg, const npf_identity *id,
                  const npf_node_hooks *hooks, void *arg)
{
    memset(n, 0, sizeof *n);
    n->started_unix_ms = npf_unix_ms();
    n->started_mono_ms = npf_mono_ms();
    n->loop = loop;
    n->cfg = *cfg;
    n->id = *id;
    if (hooks)
        n->hooks = *hooks;
    n->hook_arg = arg;
    n->cur_server = -1;
    n->udp_fd = -1;
    n->udp6_fd = -1;
    {
        const char *v = getenv("NPF_TEST_DROP_P2P");
        n->test_cut_ms = v ? atoll(v) : -1;
        n->test_cut_port = v && strchr(v, ':') ? atoi(strchr(v, ':') + 1) : 0;
    }
    n->punch_lead_ms = cfg->punch_lead_ms >= 0 ? cfg->punch_lead_ms : npf_firewall_lead_ms();
    {   /* four S3 hard sides at full size at once (256 each) when the descriptors allow */
        long lim = npf_fd_limit(65536);        /* sublinks: a descriptor each, NPF_MAX_SUBLINKS a session */
        n->punch_budget = lim / 2 >= 1024 ? 1024 : lim / 2 < 64 ? 64 : (int)(lim / 2);
    }
    if (n->punch_lead_ms > 0)
        npf_log("node: punching starts %d ms early (%s)", n->punch_lead_ms,
                cfg->punch_lead_ms >= 0 ? "punch_lead_ms" : "the application firewall drops unsolicited UDP");
    if (!cfg->offline)
        node_servers_load(n);
    if (n->nservers == 0 && !cfg->offline) {
        npf_log("node: no server list (built-in %s, saved %s)", cfg->serverlist_builtin ? cfg->serverlist_builtin : "-",
                cfg->serverlist_saved ? cfg->serverlist_saved : "-");
        return -1;
    }
    if (cfg->udp_on_demand)
        return 0;                       /* the sockets when a session needs them */
    if (node_udp_open4(n) < 0) {
        npf_loge("node: cannot open UDP socket: %s", npf_sock_strerror());
        return -1;
    }
    if (!cfg->offline)
        node_udp_open6(n);
    return 0;
}

void npf_node_start(npf_node *n)
{
    node_watch_start(n);
    if (!n->cfg.offline) {
        node_portmap_start(n);
        node_sig_connect(n);
    }
}

void npf_node_stop(npf_node *n)
{
    node_portmap_stop(n);
    node_calls_free(n);
    node_sources_stop(n);
    node_sig_race_drop(n);
    if (n->sig)
        npf_sig_close(n->sig);
    n->sig = NULL;
    node_sig_fail_pending(n);               /* requests still waiting learn there is no reply (their memory goes) */
    if (n->t_reconnect)
        npf_timer_cancel(n->loop, n->t_reconnect);
    if (n->t_ping)
        npf_timer_cancel(n->loop, n->t_ping);
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    if (n->t_login)
        npf_timer_cancel(n->loop, n->t_login);
    n->t_reconnect = n->t_ping = n->t_login = NULL;
    if (n->t_idle)
        npf_timer_cancel(n->loop, n->t_idle);
    if (n->t_wake)
        npf_timer_cancel(n->loop, n->t_wake);
    n->t_idle = n->t_wake = NULL;
    n->dormant = 0;
    if (n->t_watch)
        npf_timer_cancel(n->loop, n->t_watch);
    if (n->t_netcheck)
        npf_timer_cancel(n->loop, n->t_netcheck);
    if (n->t_udp_reopen)
        npf_timer_cancel(n->loop, n->t_udp_reopen);
    if (n->t_nat_retry)
        npf_timer_cancel(n->loop, n->t_nat_retry);
    if (n->t_punch_gap)
        npf_timer_cancel(n->loop, n->t_punch_gap);
    n->t_punch_gap = NULL;
    n->t_watch = n->t_netcheck = n->t_udp_reopen = n->t_nat_retry = NULL;
    if (n->udp_fd >= 0) {
        npf_loop_del(n->loop, n->udp_fd);
        npf_sock_close(n->udp_fd);
        n->udp_fd = -1;
    }
    if (n->udp6_fd >= 0) {
        npf_loop_del(n->loop, n->udp6_fd);
        npf_sock_close(n->udp6_fd);
        n->udp6_fd = -1;
    }
    free(n->servers);
    free(n->list);
    n->servers = n->list = NULL;
    n->nservers = n->nlist = 0;
    n->cur_server = -1;
}

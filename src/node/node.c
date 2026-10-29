/* Node lifecycle. */
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
#include "home.h"

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
    npf_th_read(&n->th);
    n->test_udp_fail = getenv("NPF_TEST_UDP_FAIL");
    n->test_no_udp = getenv("NPF_NO_UDP") != NULL;
    n->test_ws_file = getenv("NPF_TEST_WS_FILE");
    n->punch_lead_ms = cfg->punch_lead_ms >= 0 ? cfg->punch_lead_ms : npf_firewall_lead_ms();
    {   /* four S3 hard sides at full size at once (256 each) when the descriptors allow */
        long lim = npf_fd_limit(65536);        /* sublinks: a descriptor each, NPF_MAX_SUBLINKS a session */
        n->punch_budget = lim / 2 >= 1024 ? 1024 : lim / 2 < 64 ? 64 : (int)(lim / 2);
        /* the peers' sublinks together: half the descriptors (signaling,
         * UDP and accepting go on), windows to 8 sessions' worth */
        n->tun_shared.subs_max = lim / 2 < 64 ? 64 : (int)(lim / 2);
        n->tun_shared.rx_max = 8 * (int64_t)NPF_RX_BUDGET;
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
    if (node_udp_open(n) < 0) {
        npf_loge("node: cannot open UDP socket: %s", npf_sock_strerror());
        return -1;
    }
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
    node_home_stop(n);                      /* home_close while the signaling is there */
    node_portmap_stop(n);
    node_calls_free(n);
    call_key_shares_free(n);
    node_sources_stop(n);
    node_sig_close(n);                      /* offline, its ping and watch stopped (the watch ran on) */
    node_sig_fail_pending(n);               /* requests still waiting learn there is no reply (their memory goes) */
    npf_timer_stop(n->loop, &n->t_reconnect);
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    npf_timer_stop(n->loop, &n->t_login);
    npf_timer_stop(n->loop, &n->t_idle);
    npf_timer_stop(n->loop, &n->t_wake);
    n->dormant = 0;
    npf_timer_stop(n->loop, &n->t_watch);
    npf_timer_stop(n->loop, &n->t_netcheck);
    npf_timer_stop(n->loop, &n->t_udp_reopen);
    npf_timer_stop(n->loop, &n->t_nat_retry);
    node_udp_close(n);
    free(n->upgrade.packages);
    n->upgrade.packages = NULL;
    free(n->servers);
    free(n->list);
    n->servers = n->list = NULL;
    n->nservers = n->nlist = 0;
    n->cur_server = -1;
}

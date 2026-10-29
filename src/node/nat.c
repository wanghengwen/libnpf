/* NAT profile and candidates of the main UDP socket (nat-traversal.md 4, 5). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/candidates.h"
#include "npf/json.h"
#include "npf/natprobe.h"
#include "npf/platform.h"
#include "npf/node.h"

#include "node_internal.h"
#include "home.h"

static void add_cand(npf_node *n, const char *t, const struct sockaddr_storage *a)
{
    int i;
    if (n->ncands >= NPF_MAX_CANDS)
        return;
    for (i = 0; i < n->ncands; i++)
        if (memcmp(&n->cands[i].a, a, sizeof *a) == 0)
            return;
    strcpy(n->cands[n->ncands].t, t);
    n->cands[n->ncands].a = *a;
    n->ncands++;
}

static void add_host6(npf_node *n, const struct in6_addr *ip)
{
    struct sockaddr_storage ss;
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
    memset(&ss, 0, sizeof ss);
    a->sin6_family = AF_INET6;
    a->sin6_addr = *ip;
    a->sin6_port = htons(n->udp6_port);
    add_cand(n, "host6", &ss);
}

static void gather(npf_node *n)
{
    struct in_addr v4[8];
    struct in6_addr v6[8];
    int c4, c6, i;
    const char *t6 = n->th.host6;       /* tests: these IPv6 addresses count as global (::1) */
    n->ncands = 0;
    /* S0 first: a global IPv6 address needs no NAT traversal, only the firewall's */
    if (n->udp6_fd >= 0) {
        c6 = npf_gather_host(AF_INET6, v6, 8);
        for (i = 0; i < c6; i++)
            add_host6(n, &v6[i]);
        if (t6) {
            char buf[256], *tok, *save;
            struct in6_addr ip;
            snprintf(buf, sizeof buf, "%s", t6);
            for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
                if (inet_pton(AF_INET6, tok, &ip) == 1)
                    add_host6(n, &ip);
        }
    }
    if (t6)                             /* tests: and no IPv4 candidates (the session must use IPv6) */
        return;
    {
        struct sockaddr_storage ss;
        if (node_portmap_cand(n, &ss))
            add_cand(n, "mapped", &ss);
    }
    if (n->nat_valid && n->nat_udp) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &n->srflx, sizeof n->srflx);
        add_cand(n, "srflx", &ss);
        if (n->pred_port) {
            ((struct sockaddr_in *)&ss)->sin_port = htons(n->pred_port);
            add_cand(n, "pred", &ss);
        }
    }
    c4 = npf_gather_host(AF_INET, v4, 8);
    for (i = 0; i < c4; i++) {
        struct sockaddr_storage ss;
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        memset(&ss, 0, sizeof ss);
        a->sin_family = AF_INET;
        a->sin_addr = v4[i];
        a->sin_port = htons(n->udp_port);
        add_cand(n, "host4", &ss);
    }
}

void node_nat_regather(npf_node *n)
{
    gather(n);
    npf_logd("nat: %d candidates", n->ncands);
}

/* the profile is known (or the probe servers did not answer): candidates,
 * the log line, the report to the platform, and a login that waited for it.
 * first: the node's first profile (a call made before it had no candidates) */
static void nat_settled(npf_node *n, int first)
{
    char a[64];
    gather(n);
    npf_log("nat: udp=%d map=%s alloc=%s filter=%s srflx=%s cands=%d%s", n->nat_udp,
            npf_nat_mapping_str(n->nat.mapping), npf_nat_alloc_str(n->nat.allocation), npf_nat_filter_str(n->nat.filtering),
            n->nat_valid && n->nat_udp ? npf_addr_str(&n->srflx, a, sizeof a) : "-", n->ncands,
            n->th.no_udp ? " (tests: reported as udp=0, NPF_NO_UDP)" : "");
    /* a network change: the calls' platforms hear the new profile and punch
     * again; the first profile: the calls made without candidates get them.
     * Not otherwise: a side's srflx during a call is where the platform's
     * relay sees its allocation (signaling.md punch_update) */
    if (n->online && (n->repunch_on_nat || first))
        node_calls_punch_report(n, n->repunch_on_nat ? "network" : "profile");
    n->repunch_on_nat = 0;
    npf_node_report_nat(n);
    if (n->login_waits_nat) {
        n->login_waits_nat = 0;
        if (n->online && n->hooks.on_login)
            n->hooks.on_login(n, n->hook_arg);
    }
    if (n->udp_waiters) {               /* UDP on demand: sessions waited for it */
        n->udp_waiters = 0;
        if (n->on_udp_ready)
            n->on_udp_ready(n, n->hook_arg);
    }
}

static void nat_retry_cb(npf_loop *loop, void *arg);
static int nat_probe_start(npf_node *n);

static int in_arc(uint16_t lo, uint16_t hi, uint16_t p)
{
    return (uint16_t)(p - lo) <= (uint16_t)(hi - lo);
}

/* the smallest circular range covering two (lo > hi: past 65535): the
 * complement of the largest gap between their ends that neither covers */
static void arc_union(uint16_t lo1, uint16_t hi1, uint16_t lo2, uint16_t hi2, uint16_t *lo, uint16_t *hi)
{
    uint16_t e[4] = {lo1, hi1, lo2, hi2}, t;
    int i, j, best = -1, at = 0;
    for (i = 1; i < 4; i++)
        for (j = i; j > 0 && e[j - 1] > e[j]; j--) {
            t = e[j]; e[j] = e[j - 1]; e[j - 1] = t;
        }
    for (i = 0; i < 4; i++) {
        uint16_t a = e[i], b = e[(i + 1) % 4];
        int gap = (uint16_t)(b - a);
        uint16_t mid = (uint16_t)(a + gap / 2);
        if (gap <= 1 || in_arc(lo1, hi1, mid) || in_arc(lo2, hi2, mid))
            continue;
        if (gap > best) {
            best = gap;
            at = i;
        }
    }
    if (best < 0) {                 /* covers the ring */
        *lo = 0;
        *hi = 65535;
        return;
    }
    *lo = e[(at + 1) % 4];
    *hi = e[at];
}

static void probe_done(int ok, const npf_natprobe_result *res, void *arg)
{
    npf_node *n = arg;
    int udp_back = ok && n->nat_valid && !n->nat_udp;   /* the last probe had no answer */
    int first = !n->nat_valid;
    n->probe = NULL;
    /* No answer at all: measured once more at once before udp = 0. One
     * round is four sends to each probe server over 2.2 s; a burst lost
     * (a cold start: measured 1 of 13 in the field) put the node's sessions
     * on the WS relay. A node that has UDP answers the second round as
     * fast as the first; one without waits 2.2 s more. */
    if (!ok && !n->nat_again) {
        n->nat_again = 1;
        npf_log("nat: no answer from the probe servers: measuring once more");
        if (nat_probe_start(n) == 0)
            return;
    }
    n->nat_again = 0;
    if (ok) {
        int i, last = -1;
        npf_nat_profile was = n->nat;
        struct in_addr was_ip = n->pub_ip;
        n->nat = res->profile;
        /* a port block is the range of a few samples: each full probe's are
         * added to the last one's while the NAT stays the same (nat-traversal.md
         * 4.2), up to what a block can be */
        if (!n->nat_quick && n->nat_valid && n->nat_udp && was.allocation == NPF_ALLOC_BLOCK
            && n->nat.allocation == NPF_ALLOC_BLOCK && was_ip.s_addr == res->mapped[0].sin_addr.s_addr) {
            uint16_t lo, hi;
            arc_union(was.block_lo, was.block_hi, n->nat.block_lo, n->nat.block_hi, &lo, &hi);
            if ((uint16_t)(hi - lo) < 4096) {
                n->nat.block_lo = lo;
                n->nat.block_hi = hi;
            }
        }
        if (n->nat_quick) {             /* the allocation test skipped: the NAT's, from the full probe */
            n->nat.allocation = was.allocation;
            n->nat.seq_delta = was.seq_delta;
            n->nat.block_lo = was.block_lo;
            n->nat.block_hi = was.block_hi;
            n->nat.filtering = was.filtering;
        }
        n->nat_udp = 1;
        n->srflx = res->mapped[0];
        n->pub_ip = res->mapped[0].sin_addr;
        n->nat_kept_port = ntohs(res->mapped[0].sin_port) == n->udp_port
                           && (n->nat.mapping == NPF_MAP_EIM || n->nat.open);
        /* sequential allocation: new mappings continue from the last one seen
         * (nat-traversal.md 7.3, the S2 prediction) */
        for (i = 0; i < res->alloc_n; i++)
            if (res->alloc_got[i])
                last = i;
        n->pred_port = 0;
        if (!n->nat_quick && n->nat.allocation == NPF_ALLOC_SEQUENTIAL && last >= 0 && n->nat.seq_delta != 0) {
            int p = res->alloc_mapped[last] + n->nat.seq_delta;
            if (p > 1024 && p < 65536)
                n->pred_port = (uint16_t)p;
        }
        n->nat_retries = 0;
        n->nat_ok_ms = npf_mono_ms();
        node_home_udp_ok(n);                /* a spare stuck backing off: UDP works */
    } else {
        n->nat_udp = 0;
        memset(&n->nat, 0, sizeof n->nat);
        call_port_pressure(n, "the NAT probe unanswered");
        /* no answer: perhaps passing (a carrier NAT's ports all held by a
         * punch; the phone thought it had no UDP for an hour, every session
         * on the WS relay; once after the app's restart, the network not
         * ready yet): measured again soon, not at the next period; then
         * every minute while there is none: the sessions it put on the WS
         * relay come back (udp_back) within a minute of UDP's return (it
         * used to stop after 3 min: a node whose UDP went for longer stayed
         * on the WS relay until the next periodic probe) */
        {
            static const int again_s[] = {5, 10, 20, 30, 60};
            int k = n->nat_retries < 5 ? n->nat_retries++ : 4;
            npf_timer_cancel(n->loop, n->t_nat_retry);
            n->t_nat_retry = npf_timer_add(n->loop, again_s[k] * 1000, nat_retry_cb, n);
        }
    }
    n->nat_quick = 0;
    n->nat_valid = 1;
    nat_settled(n, first);
    /* the sessions made meanwhile went to the WS relay (udp false: no UDP
     * relay, no punching) and would stay there: they ask for UDP again
     * (their AnLiu connection moves, nothing ends) */
    if (udp_back) {
        n->udp_back_ms = npf_mono_ms();
        npf_node_calls_decide(n);
    }
}

static void nat_retry_cb(npf_loop *loop, void *arg)
{
    npf_node *n = arg;
    (void)loop;
    n->t_nat_retry = NULL;
    if (!n->probe && n->udp_fd >= 0)
        node_nat_refresh(n);
}

/* Measure the NAT profile of the main socket on the event loop (1.1): the
 * sessions go on meanwhile, the probe gets only the probe servers' answers
 * (node_udp_input hands them over). A profile measured before stays in use
 * until the new one is there. */
void node_nat_refresh(npf_node *n)
{
    n->nat_again = 0;                   /* a measurement of its own: its own second chance */
    if (nat_probe_start(n) < 0)
        nat_settled(n, 0);              /* no probe servers: what is known (local tests) */
}

/* a probe started (any running one replaced): 0, or -1 when none can run */
static int nat_probe_start(npf_node *n)
{
    npf_natprobe_cfg cfg;
    const uint8_t *pk = node_day_key(n, n->probe_keys);
    int i;
    npf_natprobe_cancel(n->probe);
    n->probe = NULL;
    /* the probes the server named at login (E1, E2 on one probe server, E3 on another) */
    if (n->nprobe_ep && pk && n->udp_fd >= 0) {
        npf_natprobe_cfg_init(&cfg);
        for (i = 0; i < n->nprobe_ep; i++)
            cfg.ep[i] = n->probe_ep[i];
        cfg.n_ep = n->nprobe_ep;
        memcpy(cfg.probe_key, pk, 32);
        memcpy(cfg.ticket, n->ticket, sizeof cfg.ticket);
        cfg.clock_offset_ms = n->clock_offset_ms;
        cfg.alloc_sockets = n->nat_quick ? 0 : 4;  /* quick: a reopened socket, the NAT measured before */
        cfg.main_fd = n->udp_fd;
        if ((n->probe = npf_natprobe_start(n->loop, &cfg, probe_done, n)) != NULL)
            return 0;
    }
    return -1;
}

/* at login: the hook waits for a first profile (nat_settled runs it, at
 * once when no probe can start); with one from before, or no UDP socket (on
 * demand, measured when a session needs it), it runs now and the profile is
 * measured again in the background */
void node_nat_login(npf_node *n)
{
    int wait = n->udp_fd >= 0 && !n->nat_valid;
    n->login_waits_nat = wait;
    if (n->udp_fd >= 0)
        node_nat_refresh(n);
    if (!wait && n->hooks.on_login)
        n->hooks.on_login(n, n->hook_arg);
}

void npf_node_report_nat(npf_node *n)
{
    npf_out w = {0};
    if (!n->cfg.callable || !n->online)
        return;
    npf_out_jobj(&w);
    npf_node_write_nat(n, &w);
    npf_out_jend(&w);
    if (!w.failed)
        npf_node_send(n, "nat_report", 0, w.p);
    npf_out_free(&w);
}

void npf_node_write_nat(npf_node *n, npf_out *w)
{
    char ip[INET_ADDRSTRLEN];
    int known = n->nat_valid && n->nat_udp;
    npf_out_jkey(w, "nat");
    npf_out_jobj(w);
    /* no probe servers configured: assume UDP works (local tests) */
    npf_out_kbool(w, "udp", n->th.no_udp ? 0 : n->nat_valid ? n->nat_udp : 1);   /* tests: force the WS relay */
    node_portmap_write(n, w);       /* the router's port mapping: enums only, secure too */
    if (n->cfg.secure) {            /* connect_mode secure: relays only, nothing of the addresses */
        npf_out_kbool(w, "secure", 1);
        npf_out_jend(w);
        return;
    }
    npf_out_kstr(w, "map", known ? npf_nat_mapping_str(n->nat.mapping) : "UNKNOWN");
    npf_out_kstr(w, "alloc", known ? npf_nat_alloc_str(n->nat.allocation) : "UNKNOWN");
    npf_out_kint(w, "delta", n->nat.seq_delta);
    npf_out_kstr(w, "filter", known ? npf_nat_filter_str(n->nat.filtering) : "UNKNOWN");
    if (n->nat.allocation == NPF_ALLOC_BLOCK) {
        npf_out_jkey(w, "block");
        npf_out_jarr(w);
        npf_out_jint(w, n->nat.block_lo);
        npf_out_jint(w, n->nat.block_hi);
        npf_out_jend(w);
    }
    npf_out_kbool(w, "open", n->nat.open);
    npf_out_kbool(w, "ip_varies", n->nat.ip_varies);
    if (n->punch_lead_ms > 0)       /* a host firewall: this side sends first, S1 keeps the agreed start */
        npf_out_kbool(w, "lead", 1);
    if (n->th.pub_ip)                   /* tests: a forged public IP (the platform must not spray it) */
        npf_out_kstr(w, "pub_ip", n->th.pub_ip);
    else if (known)
        npf_out_kstr(w, "pub_ip", inet_ntop(AF_INET, &n->pub_ip, ip, sizeof ip));
    npf_out_kint(w, "at", n->nat.measured_at);
    npf_out_jend(w);
}

void npf_node_write_cands(npf_node *n, npf_out *w)
{
    int i, none = n->cfg.secure;      /* secure: none, the peer learns no address */
    char a[64];
    if (n->th.cands_late_ms) {  /* tests: none for this many ms after the first time (a node just come up) */
        static int64_t first;
        if (!first)
            first = npf_mono_ms();
        none |= npf_mono_ms() - first < n->th.cands_late_ms;
    }
    npf_out_jkey(w, "cand");
    npf_out_jarr(w);
    for (i = 0; i < n->ncands && !none; i++) {     /* secure: none, the peer learns no address */
        npf_out_jobj(w);
        npf_out_kstr(w, "t", n->cands[i].t);
        npf_out_kstr(w, "a", npf_addr_str(&n->cands[i].a, a, sizeof a));
        npf_out_jend(w);
    }
    if (n->th.cands_extra && !none) {      /* tests: forged candidates "t=addr,..." */
        char buf[512], *tok, *save, *eq;
        snprintf(buf, sizeof buf, "%s", n->th.cands_extra);
        for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
            if ((eq = strchr(tok, '=')) != NULL) {
                *eq = 0;
                npf_out_jobj(w);
                npf_out_kstr(w, "t", tok);
                npf_out_kstr(w, "a", eq + 1);
                npf_out_jend(w);
            }
    }
    npf_out_jend(w);
}

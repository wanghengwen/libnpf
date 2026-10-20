/* libnpf: the commands of the npf command line, the status and the
 * settings (npf_command, npf_status_json, npf_config_*, npf_peer_*,
 * npf_forward_*). Settings, saved peers, names and nicks go to local.json in
 * data_dir (npf/local.h); npf.conf (conf_dir) is never written. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "npf/natprobe.h"
#include "npf/platform.h"
#include "npf_int.h"
#include "npf/module.h"

static void jstr(npf_out *o, const char *s)
{
    npf_out_json_str(o, s, strlen(s));
}

static void jkey(npf_out *o, int *first, const char *k)
{
    npf_out_printf(o, "%s\"%s\":", *first ? "" : ",", k);
    *first = 0;
}

static void jkstr(npf_out *o, int *first, const char *k, const char *v)
{
    jkey(o, first, k);
    if (v)
        jstr(o, v);
    else
        npf_out_printf(o, "null");
}

static void jkint(npf_out *o, int *first, const char *k, long long v)
{
    jkey(o, first, k);
    npf_out_printf(o, "%lld", v);
}

static const char *state_name(int st)
{
    switch (st) {
    case NPF_CALL_ESTABLISHED: return "established";
    case NPF_CALL_CLOSED:      return "closed";
    default:                   return "connecting";
    }
}

static const char *human_bytes(uint64_t b, char *buf, size_t cap)
{
    if (b < 10240)
        snprintf(buf, cap, "%llu B", (unsigned long long)b);
    else if (b < 10ULL << 20)
        snprintf(buf, cap, "%.1f KB", b / 1024.0);
    else if (b < 10ULL << 30)
        snprintf(buf, cap, "%.1f MB", b / 1048576.0);
    else
        snprintf(buf, cap, "%.1f GB", b / 1073741824.0);
    return buf;
}

/* a wall-clock time in ms as local "YYYY-MM-DD HH:MM:SS" */
static const char *local_time(int64_t ms, char *buf, size_t cap)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(buf, cap, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

/* a running time for people: "3 d 4 h", "2 h 05 min", "7 min", "40 s" */
static const char *running_time(int64_t s, char *buf, size_t cap)
{
    if (s < 60)
        snprintf(buf, cap, "%lld s", (long long)s);
    else if (s < 3600)
        snprintf(buf, cap, "%lld min", (long long)(s / 60));
    else if (s < 86400)
        snprintf(buf, cap, "%lld h %02lld min", (long long)(s / 3600), (long long)(s / 60 % 60));
    else
        snprintf(buf, cap, "%lld d %lld h", (long long)(s / 86400), (long long)(s / 3600 % 24));
    return buf;
}

static const char *duration(int64_t s, char *buf, size_t cap)
{
    if (s < 0)
        snprintf(buf, cap, "-");
    else if (s < 120)
        snprintf(buf, cap, "%llds", (long long)s);
    else if (s < 7200)
        snprintf(buf, cap, "%lldm", (long long)(s / 60));
    else if (s < 172800)
        snprintf(buf, cap, "%lldh%02lldm", (long long)(s / 3600), (long long)(s / 60 % 60));
    else
        snprintf(buf, cap, "%lldd%02lldh", (long long)(s / 86400), (long long)(s / 3600 % 24));
    return buf;
}

/* the other side of a session, for people: the callee's number, or a
 * caller's key fingerprint (callers have no number of their own here) */
static const char *peer_of(const npf_call_info *i, char *buf, size_t cap)
{
    static const uint8_t zero[32];
    if (i->number)
        snprintf(buf, cap, "%llu", (unsigned long long)i->number);
    else if (memcmp(i->peer_pub, zero, 32) != 0)
        snprintf(buf, cap, "key %016llx", (unsigned long long)npf_fp(i->peer_pub));
    else
        snprintf(buf, cap, "-");
    return buf;
}

const char *npf_cmd_tag_name(int tag)
{
    return tag == PEER_SAVED ? "saved" : tag == PEER_FIXED ? "config" : tag == PEER_OPTION ? "--node"
         : tag == PEER_PLATFORM ? "platform" : "temporary";
}


static void mappings_json(const npf_peer *p, npf_out *o)
{
    int i, first = 1;
    npf_out_printf(o, "[");
    for (i = 0; i < npf_peer_nfwd(p); i++) {
        char opt, st[120], t[4];
        const char *spec;
        int perm, g = 1;
        if (!npf_peer_forward_info(p, i, &opt, &spec, &perm, st, sizeof st))
            continue;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        snprintf(t, sizeof t, "-%c", opt);
        jkint(o, &g, "id", npf_peer_forward_id(p, i));
        jkstr(o, &g, "type", t);
        jkstr(o, &g, "spec", spec);
        jkstr(o, &g, "proto", npf_peer_forward_udp(p, i) ? "udp" : "tcp");
        {                               /* its parts: the apps need not split spec ("25000:[::1]:80") */
            int port, hport;
            const char *host;
            if (npf_peer_forward_ends(p, i, &port, &host, &hport) == 0) {
                jkint(o, &g, "port", port);
                if (host[0]) {
                    jkstr(o, &g, "target_host", host);
                    jkint(o, &g, "target_port", hport);
                }
            }
        }
        jkey(o, &g, "saved");
        npf_out_printf(o, "%s", perm ? "true" : "false");
        if (npf_peer_forward_ext(p, i)) {
            jkey(o, &g, "platform_id");
            npf_out_printf(o, "\"%llu\"", (unsigned long long)npf_peer_forward_ext(p, i));
        }
        jkstr(o, &g, "state", st);
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]");
}


/* this computer's private IPv4 addresses, those on the default route's network
 * first: where the other computers of the LAN reach a forward open to them */
static void lan_addrs_json(npf_out *o)
{
    npf_ifaddr ifs[32];
    uint32_t gw = 0, ip, mask;
    int n = npf_if_list(ifs, 32), i, pass, on_gw, first = 1, have_gw = npf_default_gw4(&gw) == 0;
    char a[INET_ADDRSTRLEN];
    npf_out_printf(o, "[");
    for (pass = 0; pass < 2; pass++)
        for (i = 0; i < n; i++) {
            const uint8_t *b = ifs[i].addr;
            if (ifs[i].family != AF_INET || ifs[i].loopback
                || !(b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168)))
                continue;
            memcpy(&ip, b, 4);
            mask = ifs[i].prefix > 0 && ifs[i].prefix <= 32 ? htonl(0xffffffffu << (32 - ifs[i].prefix)) : 0;
            on_gw = have_gw && mask && (ip & mask) == (gw & mask);
            if (on_gw != (pass == 0))
                continue;
            inet_ntop(AF_INET, b, a, sizeof a);
            npf_out_printf(o, "%s\"%s\"", first ? "" : ",", a);
            first = 0;
        }
    npf_out_printf(o, "]");
}

/* the peer whose session this is, if any */
static npf_peer *peer_of_call(npf_t *c, npf_call *call)
{
    npf_peer *p;
    for (p = npf_peers_first(c->peers); p; p = npf_peer_next(p))
        if (npf_peer_call(p) == call)
            return p;
    return NULL;
}

/* ---- status ---- */

void npf_cmd_status_json(npf_t *c, npf_out *o)
{
    npf_node *n = &c->node;
    npf_peer *p;
    npf_call *call;
    char a[80], b[400];
    int f = 1, first;
    static npf_host_info hi;                /* read once: it does not change while running */
    static int got_hi;
    npf_out_printf(o, "{");
    jkstr(o, &f, "version", npf_version());
    if (!got_hi) {
        npf_host_info_get(&hi);
        got_hi = 1;
    }
    jkey(o, &f, "host");                    /* the system it runs on (the console's log header) */
    {
        int g = 1;
        npf_out_printf(o, "{");
        jkstr(o, &g, "os", hi.os);
        jkstr(o, &g, "arch", hi.arch);
        npf_out_printf(o, "}");
    }
    if (n->cfg.app_name) {                  /* the app npf runs in (npf_host) */
        int g = 1;
        jkey(o, &f, "app");
        npf_out_printf(o, "{");
        jkstr(o, &g, "name", n->cfg.app_name);
        jkstr(o, &g, "ver", n->cfg.app_ver);
        npf_out_printf(o, "}");
    }
    if (c->has_number) {
        snprintf(a, sizeof a, "%llu", (unsigned long long)c->number);
        jkstr(o, &f, "number", a);
    } else {
        jkstr(o, &f, "number", NULL);
    }
    jkstr(o, &f, "role", n->cfg.callable ? "node" : "client");
    if (c->model_dev) {                     /* one key per model: the enrolment (signaling.md "enroll") */
        static const char *const st[] = {"none", "enrolling", "enrolled", "refused"};
        int g = 1, s = c->has_number && n->enroll_state != NPF_ENROLL_REFUSED ? NPF_ENROLL_DONE : n->enroll_state;
        jkey(o, &f, "enroll");
        npf_out_printf(o, "{");
        jkstr(o, &g, "state", st[s]);
        jkstr(o, &g, "error", n->enroll_error[0] ? n->enroll_error : NULL);
        jkstr(o, &g, "reason", n->enroll_reason[0] ? n->enroll_reason : NULL);
        jkint(o, &g, "at", n->enroll_at_unix_ms / 1000);
        npf_out_printf(o, "}");
    }
    jkey(o, &f, "online");
    npf_out_printf(o, "%s", n->online ? "true" : "false");
    jkint(o, &f, "server", n->online ? n->server_id : 0);
    snprintf(a, sizeof a, "%llu", (unsigned long long)n->account_id);
    jkstr(o, &f, "account", n->account_id ? a : NULL);
    jkstr(o, &f, "account_login", n->account_id && c->account_login[0] ? c->account_login : NULL);
    jkint(o, &f, "udp_port", n->udp_port);
    jkint(o, &f, "started", n->started_unix_ms / 1000);            /* Unix s */
    jkint(o, &f, "uptime_s", (npf_mono_ms() - n->started_mono_ms) / 1000);
    jkint(o, &f, "last_login", n->last_login_unix_ms / 1000);      /* Unix s, 0 none */
    jkint(o, &f, "logins", n->logins);
    jkint(o, &f, "drops", n->logins > 1 ? n->logins - 1 : 0);        /* the connection lost, then back */
    jkint(o, &f, "calls_out", n->calls_out);
    jkint(o, &f, "calls_in", n->calls_in);
    jkey(o, &f, "nat");
    {
        int g = 1;
        struct sockaddr_storage ss;
        npf_out_printf(o, "{");
        jkey(o, &g, "udp");
        npf_out_printf(o, "%s", n->nat_valid && n->nat_udp ? "true" : "false");
        jkstr(o, &g, "mapping", npf_nat_mapping_str(n->nat.mapping));
        jkstr(o, &g, "allocation", npf_nat_alloc_str(n->nat.allocation));
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &n->srflx, sizeof n->srflx);
        jkstr(o, &g, "srflx", n->nat_valid && n->nat_udp ? npf_addr_str(&ss, a, sizeof a) : NULL);
        npf_out_printf(o, "}");
    }
    jkstr(o, &f, "log_level", npf_log_level_name(npf_log_get_level()));
    jkey(o, &f, "lan_addrs");               /* where the LAN reaches a forward open to it */
    lan_addrs_json(o);
    jkey(o, &f, "resources");               /* what this node publishes (resources.h) */
    npf_pub_json(c, o);
    npf_mods_status_json(c, o, &f);         /* the modules' keys (npf/module.h) */
    jkey(o, &f, "peers");
    npf_out_printf(o, "[");
    for (first = 1, p = npf_peers_first(c->peers); p; p = npf_peer_next(p)) {
        int g = 1;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        jkstr(o, &g, "name", npf_peer_name(p));
        jkstr(o, &g, "label", npf_peer_label(p)[0] ? npf_peer_label(p) : NULL);
        jkstr(o, &g, "nick", npf_peer_nick(p)[0] ? npf_peer_nick(p) : NULL);
        jkey(o, &g, "saved");
        npf_out_printf(o, "%s", npf_peer_tag(p) == PEER_SAVED || npf_peer_tag(p) == PEER_FIXED ? "true" : "false");
        jkstr(o, &g, "source", npf_cmd_tag_name(npf_peer_tag(p)));
        jkstr(o, &g, "status", npf_peer_status(p, b, sizeof b));
        if (npf_peer_needs_password(p)) {   /* not paired: the console asks for its password */
            jkey(o, &g, "need_password");
            npf_out_printf(o, "true");
            if (npf_peer_password_wrong(p)) {
                jkey(o, &g, "password_wrong");
                npf_out_printf(o, "true");
            }
            if (npf_peer_pairing_lost(p)) {
                jkey(o, &g, "pairing_lost");
                npf_out_printf(o, "true");
            }
        }
        if (npf_peer_needs_account(p)) {    /* the account let it in: log in again */
            jkey(o, &g, "need_account");
            npf_out_printf(o, "true");
        }
        jkstr(o, &g, "path", npf_peer_call(p) ? npf_call_path(npf_peer_call(p)) : NULL);
        jkstr(o, &g, "forwards", npf_peer_forwards(p, b, sizeof b));
        jkey(o, &g, "mappings");
        mappings_json(p, o);
        if (npf_peer_resources(p)) {        /* what it published, as last heard */
            jkey(o, &g, "resources");
            npf_out_printf(o, "%s", npf_peer_resources(p));
        }
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]");
    jkey(o, &f, "sessions");
    npf_out_printf(o, "[");
    for (first = 1, call = npf_node_calls(n); call; call = npf_call_next(call)) {
        npf_call_info i;
        npf_peer *pp = peer_of_call(c, call);
        int g = 1;
        npf_call_info_get(call, &i);
        if (i.state == NPF_CALL_CLOSED)
            continue;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        jkstr(o, &g, "id", i.id);
        jkstr(o, &g, "direction", i.caller ? "out" : "in");
        jkstr(o, &g, "peer", pp ? npf_peer_name(pp) : peer_of(&i, a, sizeof a));
        jkstr(o, &g, "state", state_name(i.state));
        jkstr(o, &g, "path", i.path);
        jkstr(o, &g, "address", i.has_p2p_addr ? npf_addr_str(&i.p2p_addr, a, sizeof a) : NULL);
        jkint(o, &g, "up_s", i.up_s);
        jkint(o, &g, "rtt_ms", i.srtt_ms);
        jkint(o, &g, "tx_bytes", (long long)i.tx_bytes);
        jkint(o, &g, "rx_bytes", (long long)i.rx_bytes);
        jkint(o, &g, "sublinks", i.sublinks);
        if (i.udp_flows || i.udp_out || i.udp_in) {  /* UDP forwards (data-channel.md 15) */
            jkey(o, &g, "udp");
            npf_out_printf(o, "{\"flows\":%d,\"out\":%llu,\"in\":%llu,\"dropped\":%llu,\"split\":%llu}", i.udp_flows,
                           (unsigned long long)i.udp_out, (unsigned long long)i.udp_in,
                           (unsigned long long)i.udp_dropped, (unsigned long long)i.udp_split);
        }
        jkstr(o, &g, "app", i.app && *i.app ? i.app : NULL);
        if (i.hosted)
            npf_out_printf(o, ",\"hosted\":true");
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]}\n");
}

static void status_text(npf_t *c, npf_out *o)
{
    npf_node *n = &c->node;
    npf_call *call;
    char a[80], b[400], up[24], t1[24], t2[24], t3[24], who[100];
    int ns = 0;
    npf_out_printf(o, "npf %s\n", npf_version());
    if (c->has_number)
        npf_out_printf(o, "number:  %llu (%s)\n", (unsigned long long)c->number,
                       c->cred ? "device credential" : "enrolled");
    else if (c->model_dev)
        npf_out_printf(o, "number:  none yet (%s)\n", n->enroll_state == NPF_ENROLL_REFUSED ? "the enrolment was refused" : "enrolling");
    if (n->enroll_state == NPF_ENROLL_REFUSED)
        npf_out_printf(o, "enrol:   refused (%s%s%s)\n", n->enroll_error, n->enroll_reason[0] ? ", " : "", n->enroll_reason);
    npf_out_printf(o, "started: %s, running %s\n", local_time(n->started_unix_ms, t1, sizeof t1),
                   running_time((npf_mono_ms() - n->started_mono_ms) / 1000, t2, sizeof t2));
    if (n->cfg.offline)
        npf_out_printf(o, "server:  none (direct connections only)\n");
    else if (n->online)
        npf_out_printf(o, "server:  online at server %d%s\n", n->server_id, n->account_id ? ", account session" : "");
    else
        npf_out_printf(o, "server:  offline (connecting)\n");
    if (!n->cfg.offline) {
        if (n->logins)
            npf_out_printf(o, "login:   last %s, the connection dropped %d time%s since the start\n",
                           local_time(n->last_login_unix_ms, t1, sizeof t1), n->logins - 1, n->logins == 2 ? "" : "s");
        else
            npf_out_printf(o, "login:   not logged in yet\n");
    }
    npf_out_printf(o, "calls:   %d made, %d received\n", n->calls_out, n->calls_in);
    npf_out_printf(o, "udp:     local port %u\n", n->udp_port);
    if (n->nat_valid && n->nat_udp) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &n->srflx, sizeof n->srflx);
        npf_out_printf(o, "nat:     mapping %s, allocation %s, public %s\n", npf_nat_mapping_str(n->nat.mapping),
                       npf_nat_alloc_str(n->nat.allocation), npf_addr_str(&ss, a, sizeof a));
    } else if (!n->cfg.offline) {
        npf_out_printf(o, "nat:     unknown (no answer from the probe servers)\n");
    }
    for (call = npf_node_calls(n); call; call = npf_call_next(call)) {
        npf_call_info i;
        npf_peer *pp = peer_of_call(c, call);
        npf_call_info_get(call, &i);
        if (i.state == NPF_CALL_CLOSED)
            continue;
        if (!ns++)
            npf_out_printf(o, "\nsessions:\n  %-3s %-22s %-12s %-22s %7s %7s %10s %10s %4s\n", "", "peer", "path",
                           "address", "up", "rtt", "sent", "received", "conn");
        snprintf(t3, sizeof t3, "%d ms", i.srtt_ms);
        /* who called: a public mapping of the platform, or the caller's program */
        snprintf(who, sizeof who, "%s%s", i.hosted ? "  platform public mapping" : i.app && *i.app ? "  " : "",
                 i.hosted || !i.app ? "" : i.app);
        npf_out_printf(o, "  %-3s %-22s %-12s %-22s %7s %7s %10s %10s %4d%s\n", i.caller ? "out" : "in",
                       pp ? npf_peer_shown(pp) : peer_of(&i, a, sizeof a),
                       i.state == NPF_CALL_ESTABLISHED ? npf_call_path_label(call) : state_name(i.state),
                       i.has_p2p_addr ? npf_addr_str(&i.p2p_addr, b, sizeof b) : "-", duration(i.up_s, up, sizeof up),
                       i.srtt_ms >= 0 ? t3 : "-", human_bytes(i.tx_bytes, t1, sizeof t1),
                       human_bytes(i.rx_bytes, t2, sizeof t2), i.sublinks, who);
    }
    if (!ns)
        npf_out_printf(o, "\nno sessions (npf node lists the nodes)\n");
    npf_mods_status_text(c, o);
}


/* ---- settings ---- */

static const char *const settable[] = {"log_level", "max_calls", "punch_lead_ms", "punch_sockets", "hosted_trust",
                                       "connect_mode", "peer_idle", "keep_awake", NULL};
/* also live, not listed: a hosted client's limits (npf-hosted sets them, the platform decides) */
static const char *const settable_hosted[] = {"hosted_max_conns", "hosted_ip_conns", "hosted_ip_rate", NULL};

static int is_settable(const char *k)
{
    int i;
    for (i = 0; settable[i]; i++)
        if (strcmp(settable[i], k) == 0)
            return 1;
    for (i = 0; settable_hosted[i]; i++)
        if (strcmp(settable_hosted[i], k) == 0)
            return 1;
    return 0;
}

static int apply_setting(npf_t *c, const char *k, const char *v, npf_out *o)
{
    npf_node *n = &c->node;
    if (strcmp(k, "log_level") == 0) {
        int lv = npf_log_level_parse(v);
        if (lv < 0) {
            npf_out_printf(o, "log_level: error, warn, info, debug or trace\n");
            return 2;
        }
        npf_log_set_level(lv);
    } else if (strcmp(k, "max_calls") == 0) {
        n->cfg.max_calls = atoi(v);
    } else if (strcmp(k, "punch_lead_ms") == 0) {
        n->cfg.punch_lead_ms = atoi(v);
        n->punch_lead_ms = n->cfg.punch_lead_ms >= 0 ? n->cfg.punch_lead_ms : npf_firewall_lead_ms();
    } else if (strcmp(k, "punch_sockets") == 0) {
        n->cfg.punch_sockets = atoi(v);
    } else if (strcmp(k, "hosted_trust") == 0) {
        if (c->callee)
            c->callee->hosted_trust = atoi(v);
    } else if (strcmp(k, "connect_mode") == 0) {
        npf_node_set_secure(n, strcmp(v, "secure") == 0);
    } else if (strcmp(k, "peer_idle") == 0) {
        npf_peers_set_idle(c->peers, atoi(v) * 1000);
    } else if (strncmp(k, "hosted_", 7) == 0 && strcmp(k, "hosted_trust") != 0) {     /* settable_hosted */
        /* a hosted client's limits on its public mappings (npf-hosted sets them from the platform) */
#define LIMIT(key, def) atoi(strcmp(k, key) == 0 ? v : npf_conf_get(&c->conf, key, def))
        npf_peers_set_limits(c->peers, LIMIT("hosted_max_conns", "128"), LIMIT("hosted_ip_conns", "32"),
                             LIMIT("hosted_ip_rate", "120"));
#undef LIMIT
    }
    return 0;
}

const char *npf_cmd_get(npf_t *c, const char *k, char *buf, size_t cap)
{
    npf_node *n = &c->node;
    if (strcmp(k, "log_level") == 0)
        snprintf(buf, cap, "%s", npf_log_level_name(npf_log_get_level()));
    else if (strcmp(k, "max_calls") == 0)
        snprintf(buf, cap, "%d", n->cfg.max_calls > 0 ? n->cfg.max_calls : 32);
    else if (strcmp(k, "punch_lead_ms") == 0)
        snprintf(buf, cap, "%d", n->punch_lead_ms);
    else if (strcmp(k, "punch_sockets") == 0)
        snprintf(buf, cap, "%d", npf_node_punch_budget(n));
    else if (strcmp(k, "hosted_trust") == 0)
        snprintf(buf, cap, "%d", c->callee ? c->callee->hosted_trust : atoi(npf_conf_get(&c->conf, "hosted_trust", "1")));
    else if (strcmp(k, "connect_mode") == 0)
        snprintf(buf, cap, "%s", n->cfg.secure ? "secure" : "p2p");
    else if (strcmp(k, "peer_idle") == 0)
        snprintf(buf, cap, "%d", npf_peers_idle(c->peers) / 1000);
    else if (strcmp(k, "keep_awake") == 0)  /* the program's (client/app: Windows) */
        snprintf(buf, cap, "%s", npf_conf_get(&c->conf, k, "busy"));
    else
        snprintf(buf, cap, "%s", npf_conf_get(&c->conf, k, ""));
    return buf;
}

/* integer keys and their ranges (0 = the default where it has one) */
static const struct {
    const char *key;
    long lo, hi;
} int_keys[] = {{"max_calls", 0, 4096},  {"punch_lead_ms", -1, 5000}, {"punch_sockets", 0, 4096},
                {"hosted_trust", 0, 1},  {"udp_port", 0, 65535}, {"peer_idle", 0, 86400},
                {"hosted_max_conns", 0, 100000}, {"hosted_ip_conns", 0, 100000}, {"hosted_ip_rate", 0, 100000}};

/* keys whose values stay out of the log and the replies */
static int is_secret(const char *k)
{
    return strcmp(k, "password") == 0;
}

/* 0, or the exit code with the reason in o */
static int check_value(const char *k, const char *v, npf_out *o)
{
    size_t i;
    int r;
    if (!npf_conf_value_ok(v)) {
        npf_out_printf(o, "%s: the value must be one line without '#' (and under 1000 bytes)\n", k);
        return 2;
    }
    if ((r = npf_mods_check(NULL, k, v, o)) >= 0)
        return r;                           /* a module's key */
    if (strcmp(k, "connect_mode") == 0 && strcmp(v, "p2p") != 0 && strcmp(v, "secure") != 0) {
        npf_out_printf(o, "connect_mode: p2p (direct paths first) or secure (relays only)\n");
        return 2;
    }
    if (strcmp(k, "keep_awake") == 0 && strcmp(v, "busy") != 0 && strcmp(v, "ac") != 0 && strcmp(v, "always") != 0
        && strcmp(v, "off") != 0) {
        npf_out_printf(o, "keep_awake: busy (while others are connected), ac (on mains power), always or off\n");
        return 2;
    }
    for (i = 0; i < sizeof int_keys / sizeof int_keys[0]; i++)
        if (strcmp(int_keys[i].key, k) == 0) {
            char *e;
            long n = strtol(v, &e, 10);
            if (!*v || *e || n < int_keys[i].lo || n > int_keys[i].hi) {
                npf_out_printf(o, "%s: a number from %ld to %ld\n", k, int_keys[i].lo, int_keys[i].hi);
                return 2;
            }
        }
    return 0;
}

/* set KEY VALUE: at once when the key can change at run time, and in the
 * configuration file unless save is 0 */
int npf_cmd_set(npf_t *c, const char *k, const char *v, int save, npf_out *o)
{
    int live = is_settable(k), r;
    const char *shown = is_secret(k) ? "(hidden)" : v;
    if (strcmp(k, "node") == 0 || strcmp(k, "cred") == 0) {
        npf_out_printf(o, "%s: cannot be set this way%s\n", k, strcmp(k, "node") == 0 ? " (npf node add)" : "");
        return 2;
    }
    /* where the writable directory and its files are: read before local.json */
    if (strcmp(k, "dir") == 0 || strcmp(k, "state") == 0) {
        npf_out_printf(o, "%s: only in npf.conf (it says where local.json is)\n", k);
        return 2;
    }
    if (!npf_conf_known(k) && !npf_mod_key_known(k)) {   /* libnpf's or a module's */
        npf_out_printf(o, "%s: not a configuration key\n", k);
        return 2;
    }
    if ((r = check_value(k, v, o)) != 0)
        return r;
    if (live && (r = apply_setting(c, k, v, o)) != 0)
        return r;
    if (save) {
        npf_conf_set(&c->lc.settings, k, v);
        if (npf_local_save(&c->lc) < 0) {
            npf_out_printf(o, "cannot write %s\n", c->local_path);
            return 1;
        }
    }
    npf_conf_set(&c->conf, k, v);
    npf_out_printf(o, "%s = %s%s%s\n", k, shown, live ? "" : " (takes effect after a restart)",
                   save ? "" : " (not saved)");
    npf_log("%s = %s%s", k, shown, save ? " (saved)" : "");
    return 0;
}

/* ---- commands (POST /v1/cmd) ---- */


static void stop_timer(npf_loop *loop, void *arg)
{
    (void)arg;
    npf_loop_stop(loop);
}



int npf_cmd_run(npf_t *c, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user)
{
    const char *cmd = argv[0];
    int rc;
    if (npf_mods_cmd(c, argc, argv, cb, user, o, &rc))
        return rc;                          /* a module's (mapping, bind, enroll, app ...) */
    if (strcmp(cmd, "id") == 0) {
        npf_out_printf(o, "client_id: %016llx\n", (unsigned long long)npf_fp(c->id.dh_pub));
        if (c->has_number)
            npf_out_printf(o, "number:    %llu (%s)\n", (unsigned long long)c->number,
                           c->cred ? "device credential" : c->model_dev ? "model credential" : "enrolled");
        return 0;
    }
    if (strcmp(cmd, "status") == 0) {
        if (argc > 1 && strcmp(argv[1], "--json") == 0)
            npf_cmd_status_json(c, o);
        else
            status_text(c, o);
        return 0;
    }
    if (strcmp(cmd, "forward") == 0)
        return npf_cmd_forward(c, argc - 1, argv + 1, o);
    if (strcmp(cmd, "resource") == 0)
        return npf_cmd_resource(c, argc, argv, o);
    if (strcmp(cmd, "node") == 0)
        return npf_cmd_node(c, argc, argv, cb, user, o);
    if (strcmp(cmd, "get") == 0) {
        char b[600];
        int i;
        if (argc > 1) {
            npf_out_printf(o, "%s\n", is_secret(argv[1]) ? "(hidden)" : npf_cmd_get(c, argv[1], b, sizeof b));
            return 0;
        }
        for (i = 0; settable[i]; i++)
            npf_out_printf(o, "%-14s = %s\n", settable[i], npf_cmd_get(c, settable[i], b, sizeof b));
        return 0;
    }
    if (strcmp(cmd, "set") == 0) {
        int save = !(argc > 3 && strcmp(argv[3], "--no-save") == 0);
        if (argc < 3) {
            npf_out_printf(o, "set KEY VALUE [--no-save]\n");
            return 2;
        }
        return npf_cmd_set(c, argv[1], argv[2], save, o);
    }
    if (strcmp(cmd, "log") == 0) {
        char *buf = malloc(16384);
        int want = argc > 2 && strcmp(argv[1], "-n") == 0 ? atoi(argv[2]) : 50;
        size_t n;
        const char *s;
        if (!buf)
            return 1;
        n = npf_log_recent(buf, 16384);
        s = buf + n;
        while (s > buf && want >= 0) {
            s--;
            if (*s == '\n' && s + 1 < buf + n && want-- == 0) {
                s++;
                break;
            }
        }
        npf_out_printf(o, "%s", s);
        free(buf);
        return 0;
    }
    if (strcmp(cmd, "netcheck") == 0) {      /* an app: the network under a VPN changed (npf_host) */
        npf_node_udp_reset(&c->node, "the network changed");
        return 0;
    }
    if (strcmp(cmd, "dump") == 0) {          /* the node's state into the log (SIGUSR1) */
        npf_node_dump(&c->node);
        return 0;
    }
    if (strcmp(cmd, "stop") == 0) {
        npf_log("stop requested");
        npf_out_printf(o, "stopping\n");
        npf_timer_add(c->loop, 100, stop_timer, NULL);
        return 0;
    }
    if (strcmp(cmd, "show") == 0 || strcmp(cmd, "passwd") == 0 || strcmp(cmd, "unpair") == 0
        || strcmp(cmd, "owner-reset") == 0) {
        int r;
        if (!c->has_number) {
            npf_out_printf(o, "this identity has no number yet (npf enroll, or a device credential)\n");
            return 1;
        }
        r = npf_callee_cmd(c->callee, cmd, argc - 1, argv + 1, o);
        return r == -2 ? 2 : r;
    }
    npf_out_printf(o, "unknown command %s\n", cmd);
    return 2;
}

/* ---- HTTP routes ---- */

void npf_cmd_config_json(npf_t *c, npf_out *o)
{
    char b[600];
    int i, f = 1;
    npf_out_printf(o, "{");
    for (i = 0; settable[i]; i++)
        jkstr(o, &f, settable[i], npf_cmd_get(c, settable[i], b, sizeof b));
    npf_out_printf(o, "}\n");
}

void npf_cmd_sessions_json(npf_t *c, npf_out *o)
{
    int i;
    npf_out_printf(o, "[");
    for (i = 0; i < c->nsess; i++) {
        if (i)
            npf_out_printf(o, ",");
        npf_session_info(c, c->sess[i].call, o);
    }
    npf_out_printf(o, "]\n");
}

int npf_cmd_is_secret(const char *k)
{
    return is_secret(k);
}

int npf_cmd_is_settable(const char *k)
{
    return is_settable(k);
}

/* libnpf: the status and the settings (npf_status_json, npf_config_*), and
 * npf_command: libnpf's own commands (set, netcheck), the modules' others
 * (the text of npf's command line is npf's, client/modules). Settings go to
 * local.json in data_dir (npf/local.h); npf.conf (conf_dir) is never
 * written. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/natprobe.h"
#include "npf/platform.h"
#include "npf_int.h"
#include "npf/module.h"

static const char *state_name(int st)
{
    switch (st) {
    case NPF_CALL_ESTABLISHED: return "established";
    case NPF_CALL_CLOSED:      return "closed";
    default:                   return "connecting";
    }
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
    return tag == PEER_SAVED ? "saved" : tag == PEER_PLATFORM ? "platform" : "temporary";
}

static const char *const fwd_state_names[] = {"waiting", "up", "failed"};


/* a peer's forwards: their parts and state (npf_forward_info's fields) */
static void mappings_json(const npf_peer *p, npf_out *o)
{
    int i, first = 1;
    npf_out_printf(o, "[");
    for (i = 0; i < npf_peer_nfwd(p); i++) {
        npf_fwd_state st;
        char t[2], text[120];
        const char *label;
        int perm, g = 1;
        if (npf_peer_forward_state(p, i, &st) < 0
            || !npf_peer_forward_info(p, i, &t[0], &label, &perm, text, sizeof text))
            continue;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        npf_out_jkint(o, &g, "id", npf_peer_forward_id(p, i));
        if (st.opt == 'L' || st.opt == 'D' || st.opt == 'R') {
            npf_out_jkstr(o, &g, "kind", st.opt == 'L' ? "local" : st.opt == 'D' ? "socks" : "remote");
            npf_out_jkstr(o, &g, "proto", st.udp ? "udp" : "tcp");
            npf_out_jkstr(o, &g, "listen_host", st.bind);
            npf_out_jkint(o, &g, "port", st.port);              /* as asked: 0 picked */
            npf_out_jkint(o, &g, "listen_port", st.lport);      /* in use, 0 not yet */
            if (st.opt != 'D') {
                npf_out_jkstr(o, &g, "target_host", st.host);
                npf_out_jkint(o, &g, "target_port", st.hostport);
            }
        } else {                                        /* a module's kind, in its form */
            t[1] = 0;
            npf_out_jkstr(o, &g, "kind", t);
            npf_out_jkstr(o, &g, "spec", st.spec);
        }
        npf_out_jkey(o, &g, "saved");
        npf_out_printf(o, "%s", perm ? "true" : "false");
        if (st.ext) {
            npf_out_jkey(o, &g, "platform_id");
            npf_out_printf(o, "\"%llu\"", (unsigned long long)st.ext);
        }
        npf_out_jkstr(o, &g, "state", fwd_state_names[st.state]);
        npf_out_jkstr(o, &g, "status", text);                   /* for people: "up", "retry in N s (why)" */
        npf_out_jkint(o, &g, "conns", st.conns);
        if (st.refused) {
            npf_out_jkint(o, &g, "refused", st.refused);
            npf_out_jkstr(o, &g, "refused_why", st.refused_why);
        }
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

/* ---- status ---- */

void npf_cmd_status_json(npf_t *c, npf_out *o)
{
    npf_node *n = &c->node;
    npf_peer *p;
    npf_call *call;
    char a[80], b[400];
    int f = 1, first;
    static npf_host_info g_hi;              /* read once: it does not change while running */
    static int got_hi, hi_lock;             /* (instances on their own threads ask at once) */
    npf_host_info hi;
    npf_out_printf(o, "{");
    npf_out_jkstr(o, &f, "version", npf_version());
    while (__atomic_exchange_n(&hi_lock, 1, __ATOMIC_ACQUIRE))
        ;
    if (!got_hi) {
        npf_host_info_get(&g_hi);
        got_hi = 1;
    }
    hi = g_hi;
    __atomic_store_n(&hi_lock, 0, __ATOMIC_RELEASE);
    npf_out_jkey(o, &f, "host");                    /* the system it runs on (the console's log header) */
    {
        int g = 1;
        npf_out_printf(o, "{");
        npf_out_jkstr(o, &g, "os", hi.os);
        npf_out_jkstr(o, &g, "arch", hi.arch);
        npf_out_printf(o, "}");
    }
    if (n->cfg.app_name) {                  /* the app npf runs in (npf_host) */
        int g = 1;
        npf_out_jkey(o, &f, "app");
        npf_out_printf(o, "{");
        npf_out_jkstr(o, &g, "name", n->cfg.app_name);
        npf_out_jkstr(o, &g, "ver", n->cfg.app_ver);
        npf_out_printf(o, "}");
    }
    if (c->has_number) {
        snprintf(a, sizeof a, "%llu", (unsigned long long)c->number);
        npf_out_jkstr(o, &f, "number", a);
    } else {
        npf_out_jkstr(o, &f, "number", NULL);
    }
    npf_out_jkstr(o, &f, "role", n->cfg.callable ? "node" : "client");
    if (c->callee && c->callee->damaged) {  /* safe mode (callee.h): calls and pairing refused */
        npf_out_jkey(o, &f, "state_damaged");
        npf_out_printf(o, "true");
    }
    if (c->model_dev) {                     /* one key per model: the enrolment (signaling.md "enroll") */
        static const char *const st[] = {"none", "enrolling", "enrolled", "refused"};
        int g = 1, s = c->has_number && n->enroll_state != NPF_ENROLL_REFUSED ? NPF_ENROLL_DONE : n->enroll_state;
        npf_out_jkey(o, &f, "enroll");
        npf_out_printf(o, "{");
        npf_out_jkstr(o, &g, "state", st[s]);
        npf_out_jkstr(o, &g, "error", n->enroll_error[0] ? n->enroll_error : NULL);
        npf_out_jkstr(o, &g, "reason", n->enroll_reason[0] ? n->enroll_reason : NULL);
        npf_out_jkint(o, &g, "at", n->enroll_at_unix_ms / 1000);
        npf_out_printf(o, "}");
    }
    npf_out_jkey(o, &f, "online");
    npf_out_printf(o, "%s", n->online ? "true" : "false");
    npf_out_jkint(o, &f, "server", n->online ? n->server_id : 0);
    /* no server reached for so long (0: online, or no attempt failed yet), and why */
    npf_out_jkint(o, &f, "unreachable_s", !n->online && n->unreachable_since ? (npf_mono_ms() - n->unreachable_since) / 1000 : 0);
    npf_out_jkstr(o, &f, "server_error", !n->online && n->sig_error[0] ? n->sig_error : NULL);
    if (!n->online && n->sig_error[0] && n->sig_refused) {
        npf_out_jkey(o, &f, "server_refused");      /* the platform turned the login down: not the network */
        npf_out_printf(o, "true");
    }
    if (n->upgrade.required || n->upgrade.latest[0]) {     /* the platform's upgrade policy for this program */
        int g = 1;
        npf_out_jkey(o, &f, "upgrade");
        npf_out_printf(o, "{");
        npf_out_jkey(o, &g, "required");
        npf_out_printf(o, "%s", n->upgrade.required ? "true" : "false");
        npf_out_jkstr(o, &g, "min", n->upgrade.min[0] ? n->upgrade.min : NULL);
        npf_out_jkstr(o, &g, "latest", n->upgrade.latest[0] ? n->upgrade.latest : NULL);
        npf_out_jkstr(o, &g, "url", n->upgrade.url[0] ? n->upgrade.url : NULL);
        npf_out_jkstr(o, &g, "notes", n->upgrade.notes[0] ? n->upgrade.notes : NULL);
        npf_out_printf(o, "}");
    }
    snprintf(a, sizeof a, "%llu", (unsigned long long)n->account_id);
    npf_out_jkstr(o, &f, "account", n->account_id ? a : NULL);
    npf_out_jkstr(o, &f, "account_login", n->account_id && c->account_login[0] ? c->account_login : NULL);
    npf_out_jkint(o, &f, "udp_port", n->udp_port);
    npf_out_jkint(o, &f, "started", n->started_unix_ms / 1000);            /* Unix s */
    npf_out_jkint(o, &f, "uptime_s", (npf_mono_ms() - n->started_mono_ms) / 1000);
    npf_out_jkint(o, &f, "last_login", n->last_login_unix_ms / 1000);      /* Unix s, 0 none */
    npf_out_jkint(o, &f, "logins", n->logins);
    npf_out_jkint(o, &f, "drops", n->logins > 1 ? n->logins - 1 : 0);        /* the connection lost, then back */
    npf_out_jkint(o, &f, "calls_out", n->calls_out);
    npf_out_jkint(o, &f, "calls_in", n->calls_in);
    npf_out_jkey(o, &f, "nat");
    {
        int g = 1;
        struct sockaddr_storage ss;
        npf_out_printf(o, "{");
        npf_out_jkey(o, &g, "udp");
        npf_out_printf(o, "%s", n->nat_valid && n->nat_udp ? "true" : "false");
        npf_out_jkstr(o, &g, "mapping", npf_nat_mapping_str(n->nat.mapping));
        npf_out_jkstr(o, &g, "allocation", npf_nat_alloc_str(n->nat.allocation));
        npf_out_jkstr(o, &g, "filtering", npf_nat_filter_str(n->nat.filtering));
        memset(&ss, 0, sizeof ss);
        memcpy(&ss, &n->srflx, sizeof n->srflx);
        npf_out_jkstr(o, &g, "srflx", n->nat_valid && n->nat_udp ? npf_addr_str(&ss, a, sizeof a) : NULL);
        npf_out_printf(o, "}");
    }
    {   /* the spare allocation (home-binding.md 14.1) */
        char hb[1024];
        if (npf_node_home_status(n, hb, sizeof hb)) {
            npf_out_jkey(o, &f, "home");
            npf_out_printf(o, "%s", hb);
        }
    }
    npf_out_jkstr(o, &f, "log_level", npf_log_level_name(npf_log_get_level()));
    npf_out_jkey(o, &f, "lan_addrs");               /* where the LAN reaches a forward open to it */
    lan_addrs_json(o);
    npf_out_jkey(o, &f, "resources");               /* what this node publishes (resources.h) */
    npf_pub_json(c, o);
    npf_mods_status_json(c, o, &f);         /* the modules' keys (npf/module.h) */
    npf_out_jkey(o, &f, "peers");
    npf_out_printf(o, "[");
    for (first = 1, p = npf_peers_first(c->peers); p; p = npf_peer_next(p)) {
        int g = 1;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        npf_out_jkstr(o, &g, "name", npf_peer_name(p));
        npf_out_jkstr(o, &g, "label", npf_peer_label(p)[0] ? npf_peer_label(p) : NULL);
        npf_out_jkstr(o, &g, "nick", npf_peer_nick(p)[0] ? npf_peer_nick(p) : NULL);
        npf_out_jkey(o, &g, "saved");
        npf_out_printf(o, "%s", npf_peer_tag(p) == PEER_SAVED ? "true" : "false");
        npf_out_jkint(o, &g, "peer_id", npf_peer_id(p));
        npf_out_jkstr(o, &g, "connect", npf_peer_connect_mode(p) == NPF_CONNECT_ON_DEMAND ? "on_demand"
                              : npf_peer_connect_mode(p) == NPF_CONNECT_ONCE ? "once" : "keep");
        npf_out_jkstr(o, &g, "source", npf_cmd_tag_name(npf_peer_tag(p)));
        npf_out_jkstr(o, &g, "status", npf_peer_status(p, b, sizeof b));
        if (npf_peer_needs_password(p)) {   /* not paired: the console asks for its password */
            npf_out_jkey(o, &g, "need_password");
            npf_out_printf(o, "true");
            if (npf_peer_password_wrong(p)) {
                npf_out_jkey(o, &g, "password_wrong");
                npf_out_printf(o, "true");
            }
            if (npf_peer_pairing_lost(p)) {
                npf_out_jkey(o, &g, "pairing_lost");
                npf_out_printf(o, "true");
            }
        }
        if (npf_peer_needs_account(p)) {    /* the account let it in: log in again */
            npf_out_jkey(o, &g, "need_account");
            npf_out_printf(o, "true");
        }
        npf_out_jkstr(o, &g, "path", npf_peer_call(p) ? npf_call_path(npf_peer_call(p)) : NULL);
        npf_out_jkey(o, &g, "mappings");
        mappings_json(p, o);
        if (npf_peer_resources(p)) {        /* what it published, as last heard */
            npf_out_jkey(o, &g, "resources");
            npf_out_printf(o, "%s", npf_peer_resources(p));
        }
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]");
    npf_out_jkey(o, &f, "sessions");
    npf_out_printf(o, "[");
    for (first = 1, call = npf_node_calls(n); call; call = npf_call_next(call)) {
        npf_call_info i;
        npf_peer *pp = npf_peer_of_call(c, call);
        int g = 1;
        npf_call_info_get(call, &i);
        if (i.state == NPF_CALL_CLOSED)
            continue;
        npf_out_printf(o, "%s{", first ? "" : ",");
        first = 0;
        npf_out_jkstr(o, &g, "id", i.id);
        npf_out_jkstr(o, &g, "direction", i.caller ? "out" : "in");
        npf_out_jkstr(o, &g, "peer", pp ? npf_peer_name(pp) : peer_of(&i, a, sizeof a));
        npf_out_jkstr(o, &g, "state", state_name(i.state));
        npf_out_jkstr(o, &g, "path", i.path);
        npf_out_jkstr(o, &g, "address", i.has_p2p_addr ? npf_addr_str(&i.p2p_addr, a, sizeof a) : NULL);
        npf_out_jkint(o, &g, "up_s", i.up_s);
        npf_out_jkint(o, &g, "rtt_ms", i.srtt_ms);
        npf_out_jkint(o, &g, "tx_bytes", (long long)i.tx_bytes);
        npf_out_jkint(o, &g, "rx_bytes", (long long)i.rx_bytes);
        npf_out_jkint(o, &g, "sublinks", i.sublinks);
        if (i.udp_flows || i.udp_out || i.udp_in) {  /* UDP forwards (data-channel.md 15) */
            npf_out_jkey(o, &g, "udp");
            npf_out_printf(o, "{\"flows\":%d,\"out\":%llu,\"in\":%llu,\"dropped\":%llu,\"split\":%llu}", i.udp_flows,
                           (unsigned long long)i.udp_out, (unsigned long long)i.udp_in,
                           (unsigned long long)i.udp_dropped, (unsigned long long)i.udp_split);
        }
        npf_out_jkstr(o, &g, "app", i.app && *i.app ? i.app : NULL);
        if (i.hosted)
            npf_out_printf(o, ",\"hosted\":true");
        npf_out_printf(o, "}");
    }
    npf_out_printf(o, "]}\n");
}

/* ---- settings ---- */

/* a live key's value (checked) in effect */
static void apply_setting(npf_t *c, const char *k, const char *v)
{
    npf_node *n = &c->node;
    if (strcmp(k, "log_level") == 0) {
        npf_log_set_level(npf_log_level_parse(v));      /* one of the key's values (check_value) */
    } else if (strcmp(k, "max_calls") == 0) {
        n->cfg.max_calls = atoi(v);
    } else if (strcmp(k, "punch_lead_ms") == 0) {
        n->cfg.punch_lead_ms = atoi(v);
        n->punch_lead_ms = n->cfg.punch_lead_ms >= 0 ? n->cfg.punch_lead_ms : npf_firewall_lead_ms();
    } else if (strcmp(k, "punch_sockets") == 0) {
        n->cfg.punch_sockets = atoi(v);
    } else if (strcmp(k, "hosted_trust") == 0) {
        if (c->callee) {
            c->callee->hosted_trust = atoi(v);
            npf_callee_changed(c->callee);     /* off: the grant sessions end */
        }
    } else if (strcmp(k, "connect_mode") == 0) {
        npf_node_set_secure(n, strcmp(v, "secure") == 0);
    } else if (strcmp(k, "peer_idle") == 0) {
        npf_peers_set_idle(c->peers, (atoi(v) > 0 ? atoi(v) : 300) * 1000);     /* 0: the default, as at a start */
    } else if (npf_key_is(k, NPF_K_UNLISTED)) {
        /* a hosted client's limits on its public mappings (npf-hosted sets them from the platform) */
#define LIMIT(key) (strcmp(k, key) == 0 ? atoi(v) : (int)npf_conf_int(&c->conf, key))
        npf_peers_set_limits(c->peers, LIMIT("hosted_max_conns"), LIMIT("hosted_ip_conns"), LIMIT("hosted_ip_rate"));
#undef LIMIT
    }
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
        snprintf(buf, cap, "%d", c->callee ? c->callee->hosted_trust : (int)npf_conf_int(&c->conf, k));
    else if (strcmp(k, "connect_mode") == 0)
        snprintf(buf, cap, "%s", n->cfg.secure ? "secure" : "p2p");
    else if (strcmp(k, "peer_idle") == 0)
        snprintf(buf, cap, "%d", npf_peers_idle(c->peers) / 1000);
    else
        snprintf(buf, cap, "%s", npf_conf_get(&c->conf, k, npf_key_find(k) ? npf_key_find(k)->def : ""));
    return buf;
}

/* 0, or the exit code with the reason in o */
static int check_value(npf_t *n, const char *k, const char *v, npf_out *o)
{
    const npf_key *key = npf_key_find(k);
    char why[96];
    int r;
    if (!npf_conf_value_ok(v)) {
        npf_out_printf(o, "%s: the value must be one line without '#' (and under 1000 bytes)\n", k);
        return 2;
    }
    if ((r = npf_mods_check(n, k, v, o)) >= 0)
        return r;                           /* a module's key */
    if (key && npf_key_check(key, v, why, sizeof why) < 0) {
        npf_out_printf(o, "%s\n", why);
        return 2;
    }
    return 0;
}

/* set KEY VALUE: at once when the key can change at run time, and in the
 * configuration file unless save is 0 */
int npf_cmd_set(npf_t *c, const char *k, const char *v, int save, npf_out *o)
{
    int live = npf_key_is(k, NPF_K_LIVE), r;
    const char *shown = npf_key_is(k, NPF_K_SECRET) ? "(hidden)" : v;
    /* where to connect, what to trust, the files written (dir and state
     * also say where local.json is); the peers (node) and the resources
     * have their own calls */
    if (npf_key_is(k, NPF_K_FILE)) {
        npf_out_printf(o, "%s: only in npf.conf%s\n", k, strcmp(k, "resource") == 0 ? " (or the resource command)" : "");
        return 2;
    }
    if (!npf_key_find(k) && !npf_mod_key_known(c, k)) {   /* libnpf's or a module's */
        npf_out_printf(o, "%s: not a configuration key\n", k);
        return 2;
    }
    if ((r = check_value(c, k, v, o)) != 0)
        return r;
    if (live)
        apply_setting(c, k, v);
    if (save) {
        npf_conf_set(&c->lc.settings, k, v);
        if (npf_local_save(&c->lc) < 0) {   /* written with the next change saved */
            npf_conf_set(&c->conf, k, v);   /* as get says */
            npf_out_printf(o, "%s = %s%s, but cannot write %s yet\n", k, shown,
                           live ? ": in effect now" : " (takes effect after a restart)", c->local_path);
            if (live)
                npf_mods_conf_set(c, k, v);
            return NPF_CMD_UNSAVED;
        }
    }
    npf_conf_set(&c->conf, k, v);
    npf_out_printf(o, "%s = %s%s%s\n", k, shown, live ? "" : " (takes effect after a restart)",
                   save ? "" : " (not saved)");
    npf_log("%s = %s%s", k, shown, save ? " (saved)" : "");
    if (live)
        npf_mods_conf_set(c, k, v);
    return 0;
}

/* ---- commands (POST /v1/cmd) ---- */

/* libnpf's own commands (npf_cmd_run below): no module takes these names */
static const char *const builtin_cmds[] = {"set", "netcheck", NULL};

int npf_cmd_builtin(const char *name)
{
    int i;
    for (i = 0; builtin_cmds[i]; i++)
        if (strcmp(builtin_cmds[i], name) == 0)
            return 1;
    return 0;
}

int npf_cmd_run(npf_t *c, int argc, char **argv, npf_out *o, npf_text_cb cb, void *user)
{
    const char *cmd = argv[0];
    int rc;
    if (!npf_cmd_builtin(cmd)) {
        if (npf_mods_cmd(c, argc, argv, cb, user, o, &rc))
            return rc;                      /* a module's */
        npf_out_printf(o, "unknown command %s\n", cmd);
        return 2;
    }
    if (strcmp(cmd, "set") == 0) {
        int save = !(argc > 3 && strcmp(argv[3], "--no-save") == 0);
        if (argc < 3 || argc > 4 || (argc == 4 && save)) {     /* nothing after VALUE but --no-save */
            npf_out_printf(o, "set KEY VALUE [--no-save]\n");
            return 2;
        }
        if (save && (c->opt_flags & NPF_OPT_NO_SAVED_SETTINGS)) {     /* as npf_config_set: NPF_EUNAVAIL */
            npf_out_printf(o, "%s: settings are not saved here (the application keeps them): set ... --no-save\n",
                           argv[1]);
            return 1;
        }
        return npf_cmd_set(c, argv[1], argv[2], save, o);
    }
    /* netcheck: the network changed (npf_host: under a VPN): npf_network_changed */
    npf_net_changed(c);
    return 0;
}

/* ---- HTTP routes ---- */

void npf_cmd_config_json(npf_t *c, npf_out *o)
{
    char b[NPF_CONF_VAL_MAX];
    const npf_key *k = NULL;
    int f = 1;
    npf_out_printf(o, "{");
    while ((k = npf_key_next(k)))
        if ((k->flags & (NPF_K_LIVE | NPF_K_UNLISTED)) == NPF_K_LIVE)
            npf_out_jkstr(o, &f, k->name, npf_cmd_get(c, k->name, b, sizeof b));
    npf_out_printf(o, "}\n");
}

void npf_cmd_sessions_json(npf_t *c, npf_out *o)
{
    int i;
    npf_out_printf(o, "[");
    for (i = 0; i < c->nsess; i++) {
        if (i)
            npf_out_printf(o, ",");
        npf_session_info_out(c, c->sess[i].call, o);
    }
    npf_out_printf(o, "]\n");
}

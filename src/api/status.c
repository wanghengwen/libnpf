/* libnpf: the state as JSON (npf_status_json, npf_sessions_json, the
 * session callback's info). Its text for people is the program's (npf's
 * status command, client/modules). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf/natprobe.h"
#include "api_internal.h"

/* the other side of a session: the callee's (or a calling node's) number,
 * or the caller's key fingerprint; "-" before the handshake */
const char *npf_who(const npf_call_info *i, char *buf, size_t cap)
{
    static const uint8_t zero[32];
    if (i->number)
        snprintf(buf, cap, "%llu", (unsigned long long)i->number);
    else if (memcmp(i->peer_pub, zero, 32) != 0)
        snprintf(buf, cap, "key:%016llx", (unsigned long long)npf_fp(i->peer_pub));
    else
        snprintf(buf, cap, "-");
    return buf;
}

/* {"session", "peer", "path", "direction", "call_id"[, "app", "hosted"]} */
void npf_session_out(npf_t *n, npf_call *call, npf_out *o)
{
    npf_call_info i;
    char who[40];
    npf_call_info_get(call, &i);
    npf_out_jobj(o);
    npf_out_kint(o, "session", npf_session_of(n, call));
    npf_out_kstr(o, "peer", npf_who(&i, who, sizeof who));
    npf_out_kstr(o, "path", i.path);
    npf_out_kstr(o, "direction", i.caller ? "out" : "in");
    npf_out_kstr(o, "call_id", i.id);
    if (i.app && *i.app)
        npf_out_kstr(o, "app", i.app);
    if (i.hosted)
        npf_out_kbool(o, "hosted", 1);
    npf_out_jend(o);
}

void npf_sessions_out(npf_t *n, npf_out *o)
{
    int i;
    npf_out_jarr(o);
    for (i = 0; i < n->nsess; i++)
        npf_session_out(n, n->sess[i].call, o);
    npf_out_jend(o);
}

/* a peer's forwards: their parts and state (npf_forward_info's fields) */
static void mappings_out(const npf_peer *p, npf_out *o)
{
    static const char *const states[] = {"waiting", "up", "failed"};
    int i;
    npf_out_jarr(o);
    for (i = 0; i < npf_peer_nfwd(p); i++) {
        npf_fwd_state st;
        char kind[2] = {0};
        if (npf_peer_forward_state(p, i, &st) < 0)
            continue;
        kind[0] = st.opt;
        npf_out_jobj(o);
        npf_out_kint(o, "id", npf_peer_forward_id(p, i));
        if (st.opt == 'L' || st.opt == 'D' || st.opt == 'R') {
            npf_out_kstr(o, "kind", st.opt == 'L' ? "local" : st.opt == 'D' ? "socks" : "remote");
            npf_out_kstr(o, "proto", st.udp ? "udp" : "tcp");
            npf_out_kstr(o, "listen_host", st.bind);
            npf_out_kint(o, "port", st.port);               /* as asked: 0 picked */
            npf_out_kint(o, "listen_port", st.lport);       /* in use, 0 not yet */
            if (st.opt != 'D') {
                npf_out_kstr(o, "target_host", st.host);
                npf_out_kint(o, "target_port", st.hostport);
            }
        } else {                                            /* a module's kind, in its form */
            npf_out_kstr(o, "kind", kind);
            npf_out_kstr(o, "spec", st.spec);
        }
        npf_out_kbool(o, "saved", st.perm);
        if (st.ext) {
            npf_out_jkey(o, "platform_id");
            npf_out_printf(o, "\"%llu\"", (unsigned long long)st.ext);
        }
        npf_out_kstr(o, "state", states[st.state]);
        npf_out_kstr(o, "status", st.text);                 /* for people: "up", "retry in N s (why)" */
        npf_out_kint(o, "conns", st.conns);
        if (st.refused) {
            npf_out_kint(o, "refused", st.refused);
            npf_out_kstr(o, "refused_why", st.refused_why);
        }
        npf_out_jend(o);
    }
    npf_out_jend(o);
}

/* this computer's private IPv4 addresses, those on the default route's network
 * first: where the other computers of the LAN reach a forward open to them */
static void lan_addrs_out(npf_out *o)
{
    npf_ifaddr ifs[32];
    uint32_t gw = 0, ip, mask;
    int n = npf_if_list(ifs, 32), i, pass, on_gw, have_gw = npf_default_gw4(&gw) == 0;
    char a[INET_ADDRSTRLEN];
    npf_out_jarr(o);
    for (pass = 0; pass < 2; pass++)
        for (i = 0; i < n; i++) {
            const uint8_t *b = ifs[i].addr;
            if (ifs[i].family != AF_INET || ifs[i].loopback
                || !(b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168)))
                continue;
            memcpy(&ip, b, 4);
            mask = ifs[i].prefix > 0 && ifs[i].prefix <= 32 ? htonl(0xffffffffu << (32 - ifs[i].prefix)) : 0;
            on_gw = have_gw && mask && (ip & mask) == (gw & mask);
            if (on_gw == (pass == 0))
                npf_out_jstr(o, inet_ntop(AF_INET, b, a, sizeof a));
        }
    npf_out_jend(o);
}

/* the system it runs on, read once (it does not change while running;
 * instances on threads of their own may ask at once) */
static void host_out(npf_out *o)
{
    static npf_host_info hi;
    static int got, lock;
    if (!__atomic_load_n(&got, __ATOMIC_ACQUIRE)) {
        while (__atomic_exchange_n(&lock, 1, __ATOMIC_ACQUIRE))
            ;
        if (!got) {
            npf_host_info_get(&hi);
            __atomic_store_n(&got, 1, __ATOMIC_RELEASE);
        }
        __atomic_store_n(&lock, 0, __ATOMIC_RELEASE);
    }
    npf_out_jobj(o);
    npf_out_kstr(o, "os", hi.os);
    npf_out_kstr(o, "arch", hi.arch);
    npf_out_jend(o);
}

static void nat_out(const npf_node *n, npf_out *o)
{
    struct sockaddr_storage ss;
    char a[80];
    int known = n->nat_valid && n->nat_udp;
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, &n->srflx, sizeof n->srflx);
    npf_out_jobj(o);
    npf_out_kbool(o, "udp", known);
    npf_out_kstr(o, "mapping", npf_nat_mapping_str(n->nat.mapping));
    npf_out_kstr(o, "allocation", npf_nat_alloc_str(n->nat.allocation));
    npf_out_kstr(o, "filtering", npf_nat_filter_str(n->nat.filtering));
    npf_out_kstr(o, "srflx", known ? npf_addr_str(&ss, a, sizeof a) : NULL);
    npf_out_jend(o);
}

static const char *nul_if_empty(const char *s)
{
    return s && *s ? s : NULL;
}

static void peers_out(npf_t *c, npf_out *o)
{
    static const char *const modes[] = {"keep", "once", "on_demand"};
    npf_peer *p;
    char b[400];
    int need;
    npf_out_jarr(o);
    for (p = npf_peers_first(c->peers); p; p = npf_peer_next(p)) {
        npf_out_jobj(o);
        npf_out_kstr(o, "name", npf_peer_name(p));
        npf_out_kstr(o, "label", nul_if_empty(npf_peer_label(p)));
        npf_out_kstr(o, "nick", nul_if_empty(npf_peer_nick(p)));
        npf_out_kbool(o, "saved", npf_peer_tag(p) == NPF_PERSIST);
        npf_out_kint(o, "peer_id", npf_peer_id(p));
        npf_out_kstr(o, "connect", modes[npf_peer_connect_mode(p)]);
        npf_out_kstr(o, "source", npf_source_name(npf_peer_tag(p)));
        npf_out_kstr(o, "status", npf_peer_status(p, b, sizeof b));
        need = npf_peer_needs(p);
        if (need & NPF_NEED_PASSWORD) {     /* not paired: the console asks for its password */
            npf_out_kbool(o, "need_password", 1);
            if (need & NPF_NEED_PASSWORD_WRONG)
                npf_out_kbool(o, "password_wrong", 1);
            if (need & NPF_NEED_PAIRING_LOST)
                npf_out_kbool(o, "pairing_lost", 1);
        }
        if (need & NPF_NEED_ACCOUNT)        /* the account let it in: log in again */
            npf_out_kbool(o, "need_account", 1);
        npf_out_kstr(o, "path", npf_peer_call(p) ? npf_call_path(npf_peer_call(p)) : NULL);
        npf_out_jkey(o, "mappings");
        mappings_out(p, o);
        if (npf_peer_resources(p)) {        /* what it published, as last heard */
            npf_out_jkey(o, "resources");
            npf_out_jraw(o, npf_peer_resources(p));
        }
        npf_out_jend(o);
    }
    npf_out_jend(o);
}

/* the calls not closed yet (the session callback's are the established ones) */
static void calls_out(npf_t *c, npf_out *o)
{
    npf_call *call;
    char a[80];
    npf_out_jarr(o);
    for (call = npf_node_calls(&c->node); call; call = npf_call_next(call)) {
        npf_call_info i;
        npf_peer *p = npf_peer_of_call(c, call);
        npf_call_info_get(call, &i);
        if (i.state == NPF_CALL_CLOSED)
            continue;
        npf_out_jobj(o);
        npf_out_kstr(o, "id", i.id);
        npf_out_kstr(o, "direction", i.caller ? "out" : "in");
        npf_out_kstr(o, "peer", p ? npf_peer_name(p) : npf_who(&i, a, sizeof a));
        npf_out_kstr(o, "state", i.state == NPF_CALL_ESTABLISHED ? "established" : "connecting");
        npf_out_kstr(o, "path", i.path);
        npf_out_kstr(o, "address", i.has_p2p_addr ? npf_addr_str(&i.p2p_addr, a, sizeof a) : NULL);
        npf_out_kint(o, "up_s", i.up_s);
        npf_out_kint(o, "rtt_ms", i.srtt_ms);
        npf_out_kint(o, "tx_bytes", (long long)i.tx_bytes);
        npf_out_kint(o, "rx_bytes", (long long)i.rx_bytes);
        npf_out_kint(o, "sublinks", i.sublinks);
        if (i.udp_flows || i.udp_out || i.udp_in) {     /* UDP forwards (data-channel.md 15) */
            npf_out_jkey(o, "udp");
            npf_out_printf(o,
                           "{\"flows\":%d,\"out\":%llu,\"in\":%llu,\"dropped\":%llu,\"split\":%llu,"
                           "\"target_refused\":%llu,\"limit\":%llu,\"failed\":%llu,\"target_failed\":%llu}",
                           i.udp_flows, (unsigned long long)i.udp_out, (unsigned long long)i.udp_in,
                           (unsigned long long)i.udp_dropped, (unsigned long long)i.udp_split,
                           (unsigned long long)i.udp_ends[0], (unsigned long long)i.udp_ends[1],
                           (unsigned long long)i.udp_ends[2], (unsigned long long)i.udp_ends[3]);
        }
        npf_out_kstr(o, "app", nul_if_empty(i.app));
        if (i.hosted)
            npf_out_kbool(o, "hosted", 1);
        npf_out_jend(o);
    }
    npf_out_jend(o);
}

void npf_status_out(npf_t *c, npf_out *o)
{
    npf_node *n = &c->node;
    char a[80];
    npf_out_jobj(o);
    npf_out_kstr(o, "version", npf_version());
    npf_out_jkey(o, "host");                    /* the system it runs on (the console's log header) */
    host_out(o);
    npf_out_jkey(o, "app");                     /* the program npf runs in (npf_options.app_name) */
    npf_out_jobj(o);
    npf_out_kstr(o, "name", c->app_name);
    npf_out_kstr(o, "ver", c->app_ver);
    npf_out_jend(o);
    snprintf(a, sizeof a, "%llu", (unsigned long long)c->number);
    npf_out_kstr(o, "number", c->has_number ? a : NULL);
    npf_out_kstr(o, "role", n->cfg.callable ? "node" : "client");
    if (c->callee && c->callee->damaged)        /* safe mode (callee.h): calls and pairing refused */
        npf_out_kbool(o, "state_damaged", 1);
    if (c->model_dev) {                         /* one key per model: the enrolment (signaling.md "enroll") */
        static const char *const st[] = {"none", "enrolling", "enrolled", "refused"};
        int s = c->has_number && n->enroll_state != NPF_ENROLL_REFUSED ? NPF_ENROLL_DONE : n->enroll_state;
        npf_out_jkey(o, "enroll");
        npf_out_jobj(o);
        npf_out_kstr(o, "state", st[s]);
        npf_out_kstr(o, "error", nul_if_empty(n->enroll_error));
        npf_out_kstr(o, "reason", nul_if_empty(n->enroll_reason));
        npf_out_kint(o, "at", n->enroll_at_unix_ms / 1000);
        npf_out_jend(o);
    }
    npf_out_kbool(o, "online", n->online);
    npf_out_kint(o, "server", n->online ? n->server_id : 0);
    /* the carrier (signaling-udp.md 10.1): udp / ws, its round trip (UDP), UDP's state */
    npf_out_kstr(o, "server_via", n->online && node_sig(n) ? npf_sig_via(node_sig(n)) : NULL);
    if (n->online && node_sig(n) && npf_sig_rtt(node_sig(n)) > 0)
        npf_out_kint(o, "server_rtt_ms", npf_sig_rtt(node_sig(n)));
    npf_out_kstr(o, "udp_sig", n->cfg.offline ? NULL : npf_node_udp_sig(n));
    if (n->cfg.offline)
        npf_out_kbool(o, "direct_only", 1);     /* no server configured (NPF_ROLE_DIRECT): never online */
    /* no server reached for so long (0: online, or no attempt failed yet), and why */
    npf_out_kint(o, "unreachable_s", !n->online && n->unreachable_since ? (npf_mono_ms() - n->unreachable_since) / 1000 : 0);
    npf_out_kstr(o, "server_error", !n->online ? nul_if_empty(n->sig_error) : NULL);
    if (!n->online && n->sig_error[0] && n->sig_refused)
        npf_out_kbool(o, "server_refused", 1);  /* the platform turned the login down: not the network */
    if (n->upgrade.required || n->upgrade.latest[0]) {     /* the platform's upgrade policy for this program */
        npf_out_jkey(o, "upgrade");
        npf_out_jobj(o);
        npf_out_kbool(o, "required", n->upgrade.required);
        npf_out_kstr(o, "min", nul_if_empty(n->upgrade.min));
        npf_out_kstr(o, "latest", nul_if_empty(n->upgrade.latest));
        npf_out_kstr(o, "url", nul_if_empty(n->upgrade.url));
        npf_out_kstr(o, "notes", nul_if_empty(n->upgrade.notes));
        npf_out_jend(o);
    }
    snprintf(a, sizeof a, "%llu", (unsigned long long)n->account_id);
    npf_out_kstr(o, "account", n->account_id ? a : NULL);
    npf_out_kstr(o, "account_login", n->account_id ? nul_if_empty(c->account_login) : NULL);
    npf_out_kint(o, "udp_port", n->udp_port);
    npf_out_kint(o, "started", n->started_unix_ms / 1000);         /* Unix s */
    npf_out_kint(o, "uptime_s", (npf_mono_ms() - n->started_mono_ms) / 1000);
    npf_out_kint(o, "last_login", n->last_login_unix_ms / 1000);   /* Unix s, 0 none */
    npf_out_kint(o, "logins", n->logins);
    npf_out_kint(o, "drops", n->logins > 1 ? n->logins - 1 : 0);   /* the connection lost, then back */
    npf_out_kint(o, "calls_out", n->calls_out);
    npf_out_kint(o, "calls_in", n->calls_in);
    npf_out_jkey(o, "nat");
    nat_out(n, o);
    if (n->home) {                              /* the spare allocation (home-binding.md 14.1) */
        npf_out_jkey(o, "home");
        npf_node_home_status(n, o);
    }
    npf_out_kstr(o, "log_level", npf_log_level_name(npf_log_get_level()));
    npf_out_jkey(o, "lan_addrs");               /* where the LAN reaches a forward open to it */
    lan_addrs_out(o);
    npf_out_jkey(o, "resources");               /* what this node publishes (resources.h) */
    npf_pub_json(c, o);
    npf_mods_status_json(c, o);                 /* the modules' keys (npf/module.h) */
    npf_out_jkey(o, "peers");
    peers_out(c, o);
    npf_out_jkey(o, "sessions");
    calls_out(c, o);
    npf_out_jend(o);
}

/* libnpf: the settings (npf_config_*), and npf_command: libnpf's own
 * commands (set, netcheck), the modules' others (the text of npf's command
 * line is npf's, client/modules). Settings go to local.json in data_dir
 * (npf/local.h); npf.conf (conf_dir) is never written. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"
#include "api_internal.h"
#include "npf/module.h"

/* ---- settings ---- */

static const char *const settable[] = {"log_level", "max_calls", "punch_lead_ms", "punch_sockets", "hosted_trust",
                                       "connect_mode", "peer_idle", "keep_awake", NULL};
/* also live, not listed: a hosted client's limits (npf-hosted sets them, the platform decides) */
static const char *const settable_hosted[] = {"hosted_max_conns", "hosted_ip_conns", "hosted_ip_rate", NULL};

int npf_cmd_is_settable(const char *k)
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
        if (c->callee) {
            c->callee->hosted_trust = atoi(v);
            npf_callee_changed(c->callee);     /* off: the grant sessions end */
        }
    } else if (strcmp(k, "connect_mode") == 0) {
        npf_node_set_secure(n, strcmp(v, "secure") == 0);
    } else if (strcmp(k, "peer_idle") == 0) {
        npf_peers_set_idle(c->peers, (atoi(v) > 0 ? atoi(v) : 300) * 1000);     /* 0: the default, as at a start */
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
    else if (strcmp(k, "keep_awake") == 0)  /* the program's (Windows: keep the computer awake) */
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
int npf_cmd_is_secret(const char *k)
{
    return strcmp(k, "password") == 0 || strcmp(k, "cred") == 0 || strcmp(k, "model_cred") == 0
           || strcmp(k, "direct_psk") == 0;
}

/* 0, or the exit code with the reason in o */
static int check_value(npf_t *n, const char *k, const char *v, npf_out *o)
{
    size_t i;
    int r;
    if (!npf_conf_value_ok(v)) {
        npf_out_printf(o, "%s: the value must be one line without '#' (and under 1000 bytes)\n", k);
        return 2;
    }
    if ((r = npf_mods_check(n, k, v, o)) >= 0)
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
            long x = strtol(v, &e, 10);
            if (!*v || *e || x < int_keys[i].lo || x > int_keys[i].hi) {
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
    int live = npf_cmd_is_settable(k), r;
    const char *shown = npf_cmd_is_secret(k) ? "(hidden)" : v;
    if (strcmp(k, "node") == 0 || strcmp(k, "cred") == 0) {
        npf_out_printf(o, "%s: cannot be set this way%s\n", k, strcmp(k, "node") == 0 ? " (peers: npf_peer_create)" : "");
        return 2;
    }
    if (strcmp(k, "resource") == 0) {
        npf_out_printf(o, "resource: with the resource command\n");
        return 2;
    }
    /* where to connect, what to trust, the files written (dir and state
     * also say where local.json is) */
    if (npf_conf_file_only(k)) {
        npf_out_printf(o, "%s: only in npf.conf\n", k);
        return 2;
    }
    if (!npf_conf_known(k) && !npf_mod_key_known(c, k)) {   /* libnpf's or a module's */
        npf_out_printf(o, "%s: not a configuration key\n", k);
        return 2;
    }
    if ((r = check_value(c, k, v, o)) != 0)
        return r;
    if (live && (r = apply_setting(c, k, v, o)) != 0)
        return r;
    if (save) {
        npf_conf_set(&c->lc.settings, k, v);
        if (npf_local_save(&c->lc) < 0) {   /* written with the next change saved */
            npf_conf_set(&c->conf, k, v);   /* as get says */
            npf_out_printf(o, "%s = %s%s, but cannot write %s yet\n", k, shown,
                           live ? ": in effect now" : " (takes effect after a restart)", c->lc.path);
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

/* the settings that change at run time, in effect (npf_config_json) */
void npf_cmd_config_json(npf_t *c, npf_out *o)
{
    char b[NPF_CONF_VAL_MAX];
    int i;
    npf_out_jopen(o, '{');
    for (i = 0; settable[i]; i++)
        npf_out_kstr(o, settable[i], npf_cmd_get(c, settable[i], b, sizeof b));
    npf_out_jclose(o, '}');
}

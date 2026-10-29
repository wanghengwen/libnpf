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

#include "api_internal.h"

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
        npf_hosted_limits(c);
    }
}

void npf_hosted_limits(npf_t *n)
{
    npf_peers_set_limits(n->peers, (int)npf_conf_int(&n->conf, "hosted_max_conns"),
                         (int)npf_conf_int(&n->conf, "hosted_ip_conns"), (int)npf_conf_int(&n->conf, "hosted_ip_rate"));
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

/* set KEY VALUE: at once when the key can change at run time, and in the
 * configuration file unless save is 0 */
int npf_cmd_set(npf_t *c, const char *k, const char *v, int save, npf_out *o)
{
    const npf_key *key = npf_key_find(k);   /* libnpf's or a module's */
    int live = key && (key->flags & NPF_K_LIVE);
    const char *shown = key && (key->flags & NPF_K_SECRET) ? "(hidden)" : v;
    char why[96];
    if (!key) {
        npf_out_printf(o, "%s: not a configuration key\n", k);
        return 2;
    }
    /* where to connect, what to trust, the files written (dir and state
     * also say where local.json is); the peers (node) and the resources
     * have their own calls */
    if (key->flags & NPF_K_FILE) {
        npf_out_printf(o, "%s: only in npf.conf%s\n", k, strcmp(k, "resource") == 0 ? " (or the resource command)" : "");
        return 2;
    }
    if (!npf_conf_value_ok(v)) {
        npf_out_printf(o, "%s: the value must be one line without '#' (and under 1000 bytes)\n", k);
        return 2;
    }
    if (npf_key_check(key, v, why, sizeof why) < 0) {
        npf_out_printf(o, "%s\n", why);
        return 2;
    }
    npf_conf_set(&c->conf, k, v);
    if (live) {
        apply_setting(c, k, v);
        npf_mods_conf_set(c, k, v);
    }
    if (save) {
        npf_conf_set(&c->lc.settings, k, v);
        if (npf_local_save(&c->lc) < 0) {   /* written with the next change saved */
            npf_out_printf(o, "%s = %s%s, but cannot write %s yet\n", k, shown,
                           live ? ": in effect now" : " (takes effect after a restart)", c->lc.path);
            return NPF_CMD_UNSAVED;
        }
    }
    npf_out_printf(o, "%s = %s%s%s\n", k, shown, live ? "" : " (takes effect after a restart)",
                   save ? "" : " (not saved)");
    npf_log("%s = %s%s", k, shown, save ? " (saved)" : "");
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
    const npf_key *k;
    int i;
    npf_out_jobj(o);
    for (i = -1; i < 0 || c->mods[i]; i++)       /* libnpf's, then each module's */
        for (k = i < 0 ? npf_keys : c->mods[i]->keys; k && k->name; k++)
            if ((k->flags & (NPF_K_LIVE | NPF_K_UNLISTED)) == NPF_K_LIVE)
                npf_out_kstr(o, k->name, npf_cmd_get(c, k->name, b, sizeof b));
    npf_out_jend(o);
}

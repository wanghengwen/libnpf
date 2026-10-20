#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/conf.h"
#include "npf/node.h"
#include "npf/platform.h"

int npf_node_cfg_from_conf(npf_node_cfg *cfg, const npf_conf *conf)
{
    const char *roots = npf_conf_get(conf, "root", NULL), *v;
    char buf[512], *tok, *save;
    memset(cfg, 0, sizeof *cfg);
    if (!roots) {
        npf_log("config: 'root' (platform root public key) is required");
        return -1;
    }
    snprintf(buf, sizeof buf, "%s", roots);
    for (tok = strtok_r(buf, ", ", &save); tok && cfg->nroots < NPF_MAX_ROOTS; tok = strtok_r(NULL, ", ", &save))
        if (npf_b64url_decode(tok, strlen(tok), cfg->roots[cfg->nroots], 32) == 32)
            cfg->nroots++;
    if (!cfg->nroots) {
        npf_loge("config: bad 'root'");
        return -1;
    }
    cfg->serverlist_builtin = npf_conf_get(conf, "serverlist", NULL);
    cfg->serverlist_saved = npf_conf_get(conf, "serverlist_saved", NULL);
    if (cfg->serverlist_saved && (!*cfg->serverlist_saved || strcmp(cfg->serverlist_saved, "off") == 0))
        cfg->serverlist_saved = NULL;
    cfg->server_url = npf_conf_get(conf, "server", NULL);
    if (cfg->server_url) {
        v = npf_conf_get(conf, "server_pub", "");
        if (npf_b64url_decode(v, strlen(v), cfg->server_pub, 32) != 32) {
            npf_log("config: 'server' needs 'server_pub'");
            return -1;
        }
    }
    cfg->udp_port = atoi(npf_conf_get(conf, "udp_port", "0"));
    cfg->max_calls = atoi(npf_conf_get(conf, "max_calls", "0"));
    cfg->punch_lead_ms = atoi(npf_conf_get(conf, "punch_lead_ms", "-1"));
    cfg->punch_sockets = atoi(npf_conf_get(conf, "punch_sockets", "0"));
    cfg->secure = strcmp(npf_conf_get(conf, "connect_mode", "p2p"), "secure") == 0;
    npf_udp_hook_on(!cfg->secure);         /* p2p: the UDP sockets go around a VPN */
    cfg->no_portmap = strcmp(npf_conf_get(conf, "portmap", "1"), "0") == 0;
    cfg->no_host_report = strcmp(npf_conf_get(conf, "report_host", "1"), "0") == 0;
    cfg->hosted_service = strcmp(npf_conf_get(conf, "hosted_service", "0"), "1") == 0;
    cfg->hosted_exec = strtoull(npf_conf_get(conf, "hosted_exec", "0"), NULL, 10);
    if (cfg->hosted_exec) {                 /* only hosted clients may go without signaling */
        cfg->sig_idle_ms = atoi(npf_conf_get(conf, "sig_idle_s", "0")) * 1000;
        cfg->sig_wake_ms = atoi(npf_conf_get(conf, "sig_wake_s", "600")) * 1000;
        cfg->udp_on_demand = cfg->sig_idle_ms > 0 && strcmp(npf_conf_get(conf, "udp_on_demand", "0"), "1") == 0;
        cfg->udp_public = strcmp(npf_conf_get(conf, "udp_public", "0"), "1") == 0;
    }
    cfg->doh_servers = npf_conf_get(conf, "doh_servers", NULL);
    return 0;
}

int npf_conf_apply_log_level(const npf_conf *conf)
{
    const char *v = npf_conf_get(conf, "log_level", "info");
    int lv = npf_log_level_parse(v);
    if (lv < 0) {
        npf_logw("config: unknown log_level '%s' (error, warn, info, debug, trace)", v);
        return -1;
    }
    npf_log_set_level(lv);
    return 0;
}

int npf_seed_file(const char *path, uint8_t seed[32], int create)
{
    char *s;
    long n = npf_file_read(path, &s);
    if (n >= 0) {
        int r;
        while (n > 0 && isspace((unsigned char)s[n - 1]))
            s[--n] = 0;
        r = npf_b64url_decode(s, (size_t)n, seed, 32);
        free(s);
        return r == 32 ? 0 : -1;
    }
    if (!create)
        return -1;
    {
        char out[64];
        size_t l;
        npf_random(seed, 32);
        l = npf_b64url_encode(seed, 32, out);
        out[l++] = '\n';
        if (npf_file_write(path, out, l, 0600) < 0) {
            npf_loge("cannot write %s: %s", path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static const uint8_t damm[10][10] = {
    {0, 3, 1, 7, 5, 9, 8, 6, 4, 2}, {7, 0, 9, 2, 1, 5, 4, 8, 6, 3}, {4, 2, 0, 6, 8, 7, 1, 3, 5, 9},
    {1, 7, 5, 0, 9, 8, 3, 4, 2, 6}, {6, 1, 2, 3, 0, 4, 5, 9, 7, 8}, {3, 6, 7, 4, 2, 0, 9, 5, 8, 1},
    {5, 8, 6, 9, 7, 2, 0, 1, 3, 4}, {8, 9, 4, 5, 3, 6, 2, 0, 1, 7}, {9, 4, 3, 8, 6, 1, 7, 2, 0, 5},
    {2, 5, 8, 1, 4, 3, 6, 7, 9, 0}};

uint64_t npf_number_parse(const char *s)
{
    uint64_t v = 0;
    int digits = 0, interim = 0;
    for (; *s; s++) {
        if (*s == ' ' || *s == '-')
            continue;
        if (!isdigit((unsigned char)*s))
            return 0;
        interim = damm[interim][*s - '0'];
        v = v * 10 + (uint64_t)(*s - '0');
        digits++;
    }
    return digits == 9 && interim == 0 && v >= 100000000ULL ? v : 0;
}

/* the reasons first (the reply's message), then the codes */
static const char *const k_err[][2] = {
    {"no_hosted", "no public-mapping server has room right now (all are full or offline); try again later, or "
                  "tell the platform's operator"},
    {"plan_limit", "the account's plan allows no more public mappings (the free plan: none); upgrade it or delete one"},
    {"not_publisher", "only the device's owner, or a visitor the owner allows, may open it to the internet"},
    {"choose_port", "choosing the public port needs a higher plan; leave the port to the platform"},
    {"port_range", "that public port is outside the platform's port ranges"},
    {"port_taken", "that port is already in use"},
    {"mapping_limit", "the account has as many mappings as it may have; delete one first"},
    {"device", "the account has no such device"},
    {"no reply", "the platform did not answer (no connection to it, or it timed out); try again"},
    {"unauthenticated", "not logged in to an account, or the login expired: log in again"},
    {"forbidden", "not allowed"},
    {"not_found", "not found"},
    {"conflict", "conflicts with what is there (or was changed elsewhere: look again)"},
    {"rate_limited", "too many attempts; wait a minute and try again"},
    {"unavailable", "the platform cannot do it right now; try again later"},
    {"timeout", "timed out; try again"},
    {"quota", "this month's traffic of the account is used up"},
    {"internal_error", "the platform had an internal error; try again later"},
    {"bad_request", "the platform did not accept the request (check the values)"},
    {"expired", "expired"},
    {"offline", "the other side is offline"},
    {"unsupported_type", "the platform does not support this (an older server?)"},
};

void npf_platform_err(const npf_json *j, char *buf, size_t cap)
{
    char code[32] = "no reply", why[32] = "";
    const char *say = NULL;
    size_t i;
    if (j) {
        npf_json_get_str(j, 0, "error", code, sizeof code);
        npf_json_get_str(j, 0, "message", why, sizeof why);
    }
    for (i = 0; i < sizeof k_err / sizeof k_err[0] && !say; i++)
        if (why[0] && strcmp(why, k_err[i][0]) == 0)
            say = k_err[i][1];
    for (i = 0; i < sizeof k_err / sizeof k_err[0] && !say; i++)
        if (strcmp(code, k_err[i][0]) == 0)
            say = k_err[i][1];
    if (why[0] && strspn(why, "abcdefghijklmnopqrstuvwxyz_") == strlen(why))
        snprintf(buf, cap, "%s (%s)%s%s", code, why, say ? ": " : "", say ? say : "");
    else
        snprintf(buf, cap, "%s%s%s", code, say ? ": " : "", say ? say : "");
}

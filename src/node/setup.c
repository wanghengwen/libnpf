#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/node.h"
#include "npf/platform.h"
#include "npf/why.h"

#include "msgs.h"

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
    /* the values as the key table checked them (conf.c), or its defaults */
    cfg->udp_port = (int)npf_conf_int(conf, "udp_port");
    cfg->max_calls = (int)npf_conf_int(conf, "max_calls");
    cfg->punch_lead_ms = (int)npf_conf_int(conf, "punch_lead_ms");
    cfg->punch_sockets = (int)npf_conf_int(conf, "punch_sockets");
    cfg->secure = npf_conf_int(conf, "connect_mode") == 1;     /* p2p|secure */
    npf_udp_hook_on(!cfg->secure);         /* p2p: the UDP sockets go around a VPN */
    cfg->no_portmap = !npf_conf_int(conf, "portmap");
    cfg->test_one_host = (int)npf_conf_int(conf, "test_one_host");     /* tests only */
    cfg->no_host_report = !npf_conf_int(conf, "report_host");
    cfg->hosted_service = (int)npf_conf_int(conf, "hosted_service");
    cfg->hosted_exec = strtoull(npf_conf_get(conf, "hosted_exec", "0"), NULL, 10);   /* a key's fingerprint: 64 bits */
    if (cfg->hosted_exec) {                 /* only hosted clients may go without signaling */
        cfg->sig_idle_ms = (int)npf_conf_int(conf, "sig_idle_s") * 1000;
        cfg->sig_wake_ms = (int)npf_conf_int(conf, "sig_wake_s") * 1000;
        cfg->udp_on_demand = cfg->sig_idle_ms > 0 && npf_conf_int(conf, "udp_on_demand");
        cfg->udp_public = (int)npf_conf_int(conf, "udp_public");
    }
    cfg->doh_servers = npf_conf_get(conf, "doh_servers", NULL);
    cfg->home_off = npf_conf_int(conf, "home_bind") == 1;     /* auto|off (home-binding.md 17.1) */
#ifdef NPF_SIG_UDP
    cfg->sig_udp_off = npf_conf_int(conf, "sig_udp") == 1;    /* auto|off (signaling-udp.md 5.3) */
#else
    cfg->sig_udp_off = 1;
#endif
    return 0;
}

int npf_conf_apply_log_level(const npf_conf *conf)
{
    npf_log_set_level((int)npf_conf_int(conf, "log_level"));     /* its index: NPF_LOG_* */
    return 0;
}

int npf_seed_file(const char *path, uint8_t seed[32], int create)
{
    char *s;
    long n = npf_file_read(path, &s);
    struct stat st;
    if (n >= 0) {
        int r;
        long len = n;
        while (n > 0 && isspace((unsigned char)s[n - 1]))
            s[--n] = 0;
        r = npf_b64url_decode(s, (size_t)n, seed, 32);
        npf_wipe_free(s, (size_t)len);
        return r == 32 ? 0 : -1;
    }
    /* made only when there is none: a key that cannot be read now (its
     * permissions, no descriptors left, an I/O error) is never replaced */
    if (stat(path, &st) == 0 || errno != ENOENT) {
        npf_loge("cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    if (!create)
        return -1;
    {
        char out[64];
        size_t l;
        int r;
        npf_random(seed, 32);
        l = npf_b64url_encode(seed, 32, out);
        out[l++] = '\n';
        r = npf_file_write(path, out, l, 0600);
        npf_wipe(out, sizeof out);
        if (r < 0) {
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

void npf_platform_err(const npf_json *j, char *buf, size_t cap)
{
    m_env e;
    const char *code = "no reply", *why = "", *say = NULL;
    if (j && npf_msg_parse(&m_env_d, j, 0, &e, NULL, 0) == 0) {
        code = e.error[0] ? e.error : code;
        why = e.message;
    }
    /* the reasons first (the reply's message), then the codes */
    if (why[0])
        say = npf_why_platform_text(why);
    if (!say)
        say = npf_why_platform_text(code);
    if (why[0] && strspn(why, "abcdefghijklmnopqrstuvwxyz_") == strlen(why))
        snprintf(buf, cap, "%s (%s)%s%s", code, why, say ? ": " : "", say ? say : "");
    else
        snprintf(buf, cap, "%s%s%s", code, say ? ": " : "", say ? say : "");
}

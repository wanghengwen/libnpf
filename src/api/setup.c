/* libnpf: starting from the application's fields (npf_setup, npf.h) instead
 * of a configuration file. Each field is the npf.conf key of the same meaning;
 * they become those keys here, so the rest of the start (the checks,
 * npf_config_get, the status) is the same either way. Keys come as bytes; the
 * server list as bytes is written to data_dir/serverlist-builtin.bin at each
 * start (a newer program's list wins over a file left from before). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"

void npf_setup_init_size(npf_setup *s, size_t size)
{
    npf_setup d;
    memset(&d, 0, sizeof d);
    d.punch_lead_ms = -1;
    npf_init_sized(s, size, &d, sizeof d);
}

/* a key set; *failed: the first that could not be (too long, no memory) */
static void set(npf_conf *c, const char *k, const char *v, const char **failed)
{
    if (npf_conf_set(c, k, v) < 0 && !*failed)
        *failed = k;
}

static void set_b64(npf_conf *c, const char *k, const uint8_t key[32], const char **failed)
{
    char b[NPF_B64_LEN(32) + 1];
    b[npf_b64url_encode(key, 32, b)] = 0;
    set(c, k, b, failed);
    npf_wipe(b, sizeof b);              /* direct_psk */
}

static void set_int(npf_conf *c, const char *k, int v, const char **failed)
{
    char b[24];
    snprintf(b, sizeof b, "%d", v);
    set(c, k, b, failed);
}

static int bad(char *err, size_t errcap, const char *what)
{
    snprintf(err, errcap, "npf_setup: %s", what);
    return -1;
}

int npf_setup_conf(const npf_setup *us, int role, const char *data_dir, npf_conf *c, char *err, size_t errcap)
{
    npf_setup s;
    size_t size;
    const char *failed = NULL;
    char why[96];
    int i;
    npf_setup_init(&s);
    memcpy(&size, us, sizeof size);
    if (size < offsetof(npf_setup, peer_idle_s) + sizeof s.peer_idle_s)
        return bad(err, errcap, "not initialised (npf_setup_init)");
    memcpy(&s, us, size < sizeof s ? size : sizeof s);
    /* the platform */
    if (role != NPF_ROLE_DIRECT) {
        char roots[2 * (NPF_B64_LEN(32) + 1) + 2];
        size_t o = 0;
        if (!s.roots || s.nroots < 1 || s.nroots > NPF_ROOTS_MAX)
            return bad(err, errcap, "roots: 1 or 2 root keys of the platform");
        for (i = 0; i < s.nroots; i++) {
            if (i)
                roots[o++] = ',';
            o += npf_b64url_encode(s.roots[i], 32, roots + o);
        }
        roots[o] = 0;
        set(c, "root", roots, &failed);
        if (!!s.serverlist == !!s.serverlist_file && !(s.server_url && !s.serverlist && !s.serverlist_file))
            return bad(err, errcap, "serverlist or serverlist_file: one of the two");
        if (s.serverlist) {
            char path[1100];
            if (!s.serverlist_len || s.serverlist_len > (1u << 20))
                return bad(err, errcap, "serverlist: 1 byte to 1 MB");
            snprintf(path, sizeof path, "%s/serverlist-builtin.bin", data_dir);
            if (npf_file_write(path, s.serverlist, s.serverlist_len, 0600) < 0) {
                snprintf(err, errcap, "npf_setup: serverlist: cannot write %s", path);
                return -1;
            }
            set(c, "serverlist", path, &failed);
        } else if (s.serverlist_file) {
            set(c, "serverlist", s.serverlist_file, &failed);
        }
        if (s.serverlist_saved)
            set(c, "serverlist_saved", *s.serverlist_saved ? s.serverlist_saved : "off", &failed);
        if (s.server_url) {
            if (!s.server_pub)
                return bad(err, errcap, "server_url needs server_pub");
            set(c, "server", s.server_url, &failed);
            set_b64(c, "server_pub", s.server_pub, &failed);
        }
        if (s.doh_servers)
            set(c, "doh_servers", s.doh_servers, &failed);
    }
    /* the identity */
    if (s.cred && s.model_cred)
        return bad(err, errcap, "cred or model_cred, not both");
    if (s.cred) {
        if (!s.password)
            return bad(err, errcap, "cred needs password (the device's default pairing password)");
        set(c, "cred", s.cred, &failed);
        set(c, "password", s.password, &failed);
    }
    if (s.model_cred) {
        set(c, "model_cred", s.model_cred, &failed);
        if (s.serial)
            set(c, "serial", s.serial, &failed);
        if (s.hw_info)
            set(c, "hw_info", s.hw_info, &failed);
    }
    if (s.model)
        set(c, "model", s.model, &failed);
    /* direct connections */
    if (s.direct_port) {
        char d[300];
        if (!s.direct_psk)
            return bad(err, errcap, "direct_port needs direct_psk");
        if (s.direct_host && strchr(s.direct_host, ':'))
            snprintf(d, sizeof d, "[%s]:%u", s.direct_host, (unsigned)s.direct_port);
        else if (s.direct_host)
            snprintf(d, sizeof d, "%s:%u", s.direct_host, (unsigned)s.direct_port);
        else
            snprintf(d, sizeof d, "%u", (unsigned)s.direct_port);
        set(c, "direct", d, &failed);
        set_b64(c, "direct_psk", s.direct_psk, &failed);
    }                                   /* none: a direct instance that only calls (its peers have their keys) */
    /* the network (its ranges: the keys', checked below) */
    if (s.udp_port)
        set_int(c, "udp_port", s.udp_port, &failed);
    if (s.no_portmap)
        set(c, "portmap", "0", &failed);
    if (s.relays_only)
        set(c, "connect_mode", "secure", &failed);
    if (s.max_calls)
        set_int(c, "max_calls", s.max_calls, &failed);
    if (s.punch_lead_ms != -1)          /* -1: automatic, the key's default */
        set_int(c, "punch_lead_ms", s.punch_lead_ms, &failed);
    if (s.punch_sockets)
        set_int(c, "punch_sockets", s.punch_sockets, &failed);
    if (s.no_host_report)
        set(c, "report_host", "0", &failed);
    if (s.no_hosted_trust)
        set(c, "hosted_trust", "0", &failed);
    if (s.peer_idle_s)
        set_int(c, "peer_idle", s.peer_idle_s, &failed);
    if (failed) {
        snprintf(err, errcap, "npf_setup: %s: too long, or no memory", failed);
        return -1;
    }
    if (npf_conf_check(c, why, sizeof why) < 0)
        return bad(err, errcap, why);
    return 0;
}

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

#include "api_internal.h"

/* the keys a field gives: not in the overrides as well */
static const char *const setup_keys[] = {
    "root", "serverlist", "serverlist_saved", "server", "server_pub", "doh_servers", "cred", "password",
    "model_cred", "serial", "serial_file", "hw_info", "model", "direct", "direct_psk", "direct_psk_file",
    "udp_port", "portmap", "connect_mode", "max_calls", "punch_lead_ms", "punch_sockets", "report_host",
    "hosted_trust", "peer_idle", NULL};

const char *npf_setup_key_taken(const npf_conf *ov)
{
    int i;
    for (i = 0; setup_keys[i]; i++)
        if (npf_conf_get(ov, setup_keys[i], NULL))
            return setup_keys[i];
    return NULL;
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
    /* the network: the ranges of npf_config_set */
    if (s.udp_port < 0 || s.udp_port > 65535 || s.max_calls < 0 || s.max_calls > 4096 || s.punch_lead_ms < -1
        || s.punch_lead_ms > 5000 || s.punch_sockets < 0 || s.punch_sockets > 4096 || s.peer_idle_s < 0
        || s.peer_idle_s > 86400)
        return bad(err, errcap, "udp_port, max_calls, punch_lead_ms, punch_sockets or peer_idle_s out of range");
    if (s.udp_port)
        set_int(c, "udp_port", s.udp_port, &failed);
    if (s.no_portmap)
        set(c, "portmap", "0", &failed);
    if (s.relays_only)
        set(c, "connect_mode", "secure", &failed);
    if (s.max_calls)
        set_int(c, "max_calls", s.max_calls, &failed);
    if (s.punch_lead_ms >= 0)
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
    return 0;
}

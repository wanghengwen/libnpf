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

static int set_b64(npf_conf *c, const char *k, const uint8_t key[32])
{
    char b[NPF_B64_LEN(32) + 1];
    b[npf_b64url_encode(key, 32, b)] = 0;
    return npf_conf_set(c, k, b);
}

static int set_int(npf_conf *c, const char *k, int v)
{
    char b[24];
    snprintf(b, sizeof b, "%d", v);
    return npf_conf_set(c, k, b);
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
        if (npf_conf_set(c, "root", roots) < 0)
            return bad(err, errcap, "no memory");
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
            npf_conf_set(c, "serverlist", path);
        } else if (s.serverlist_file) {
            npf_conf_set(c, "serverlist", s.serverlist_file);
        }
        if (s.serverlist_saved)
            npf_conf_set(c, "serverlist_saved", *s.serverlist_saved ? s.serverlist_saved : "off");
        if (s.server_url) {
            if (!s.server_pub)
                return bad(err, errcap, "server_url needs server_pub");
            npf_conf_set(c, "server", s.server_url);
            set_b64(c, "server_pub", s.server_pub);
        }
        if (s.doh_servers)
            npf_conf_set(c, "doh_servers", s.doh_servers);
    }
    /* the identity */
    if (s.cred && s.model_cred)
        return bad(err, errcap, "cred or model_cred, not both");
    if (s.cred) {
        if (!s.password)
            return bad(err, errcap, "cred needs password (the device's default pairing password)");
        npf_conf_set(c, "cred", s.cred);
        npf_conf_set(c, "password", s.password);
    }
    if (s.model_cred) {
        npf_conf_set(c, "model_cred", s.model_cred);
        if (s.serial)
            npf_conf_set(c, "serial", s.serial);
        if (s.hw_info)
            npf_conf_set(c, "hw_info", s.hw_info);
    }
    if (s.model)
        npf_conf_set(c, "model", s.model);
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
        npf_conf_set(c, "direct", d);
        set_b64(c, "direct_psk", s.direct_psk);
    } else if (role == NPF_ROLE_DIRECT && !s.direct_psk) {
        /* a direct instance that only calls: its peers have their keys */
    }
    /* the network: the ranges of npf_config_set */
    if (s.udp_port < 0 || s.udp_port > 65535 || s.max_calls < 0 || s.max_calls > 4096 || s.punch_lead_ms < -1
        || s.punch_lead_ms > 5000 || s.punch_sockets < 0 || s.punch_sockets > 4096 || s.peer_idle_s < 0
        || s.peer_idle_s > 86400)
        return bad(err, errcap, "udp_port, max_calls, punch_lead_ms, punch_sockets or peer_idle_s out of range");
    if (s.udp_port)
        set_int(c, "udp_port", s.udp_port);
    if (s.no_portmap)
        npf_conf_set(c, "portmap", "0");
    if (s.relays_only)
        npf_conf_set(c, "connect_mode", "secure");
    if (s.max_calls)
        set_int(c, "max_calls", s.max_calls);
    if (s.punch_lead_ms >= 0)
        set_int(c, "punch_lead_ms", s.punch_lead_ms);
    if (s.punch_sockets)
        set_int(c, "punch_sockets", s.punch_sockets);
    if (s.no_host_report)
        npf_conf_set(c, "report_host", "0");
    if (s.no_hosted_trust)
        npf_conf_set(c, "hosted_trust", "0");
    if (s.peer_idle_s)
        set_int(c, "peer_idle", s.peer_idle_s);
    return 0;
}

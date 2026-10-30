/* Configuration files: parsing, path keys relative to the file, the default
 * path next to the file, and atomic private file writes. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf/conf.h"
#include "npf/log.h"
#include "npf/sys.h"
#include "test.h"

/* the key table: where a key may come from, its values, its defaults */
static void key_table(void)
{
    static const char *const file[] = {"root", "server", "server_udp", "cred", "dir", "state", "node", "resource",
                                       "direct_psk", "hosted_exec", "test_one_host", NULL};
    static const char *const live[] = {"log_level", "max_calls", "punch_lead_ms", "punch_sockets", "hosted_trust",
                                       "connect_mode", "peer_idle", "hosted_max_conns", NULL};
    npf_conf c;
    char err[96];
    const npf_key *k;
    int i, n = 0;
    for (i = 0; file[i]; i++)
        CHECK(npf_key_is(file[i], NPF_K_FILE) && !npf_key_is(file[i], NPF_K_LIVE), "%s: npf.conf only", file[i]);
    for (i = 0; live[i]; i++)
        CHECK(npf_key_is(live[i], NPF_K_LIVE) && !npf_key_is(live[i], NPF_K_FILE), "%s: live", live[i]);
    CHECK(npf_key_is("password", NPF_K_SECRET) && !npf_key_is("password", NPF_K_FILE) && npf_key_is("dir", NPF_K_PATH)
          && !npf_key_is("serial_file", NPF_K_PATH) && npf_key_is("resource", NPF_K_MULTI)
          && npf_key_is("hosted_ip_rate", NPF_K_UNLISTED) && npf_key_is("peer_idle", NPF_K_SETUP)
          && !npf_key_is("log_level", NPF_K_SETUP), "the flags");
    for (k = npf_keys; k->name; k++) {
        char e2[96];
        n++;
        CHECK(k->def && (k->type == NPF_K_STR || npf_key_check(k, k->def, e2, sizeof e2) == 0), "%s: its default", k->name);
    }
    CHECK(n == 43, "%d keys", n);
#ifdef NPF_SIG_UDP
    CHECK(npf_key_check(npf_key_find("sig_udp"), "auto", err, sizeof err) == 0, "sig_udp auto");
#else
    CHECK(npf_key_check(npf_key_find("sig_udp"), "auto", err, sizeof err) < 0, "sig_udp only off");
#endif
    CHECK(npf_key_check(npf_key_find("sig_udp"), "off", err, sizeof err) == 0, "sig_udp off");
    CHECK(!npf_key_find("control") && !npf_key_find("log") && !npf_key_find("keep_awake") && !npf_key_find("hosted_ports"),
          "none of the program's (its module's: architecture.md 7)");
    CHECK(npf_key_check(npf_key_find("max_calls"), "4097", err, sizeof err) < 0
          && strcmp(err, "max_calls: a number from 0 to 4096") == 0, "max_calls: %s", err);
    CHECK(npf_key_check(npf_key_find("punch_lead_ms"), "-1", err, sizeof err) == 0
          && npf_key_check(npf_key_find("udp_port"), "12x", err, sizeof err) < 0
          && npf_key_check(npf_key_find("portmap"), "off", err, sizeof err) < 0
          && npf_key_check(npf_key_find("connect_mode"), "relay", err, sizeof err) < 0
          && strcmp(err, "connect_mode: p2p or secure") == 0
          && npf_key_check(npf_key_find("home_bind"), "off", err, sizeof err) == 0, "the values");
    memset(&c, 0, sizeof c);
    CHECK(npf_conf_int(&c, "hosted_ip_conns") == 32 && npf_conf_int(&c, "punch_lead_ms") == -1
          && npf_conf_int(&c, "log_level") == NPF_LOG_INFO && npf_conf_int(&c, "portmap") == 1, "the defaults");
    npf_conf_set(&c, "connect_mode", "secure");
    npf_conf_set(&c, "log_level", "trace");
    npf_conf_set(&c, "sig_wake_s", "90000");            /* not checked: the default */
    npf_conf_set(&c, "tun_mtu", "x");                   /* a module's: not libnpf's to check */
    CHECK(npf_conf_int(&c, "connect_mode") == 1 && npf_conf_int(&c, "log_level") == NPF_LOG_TRACE
          && npf_conf_int(&c, "sig_wake_s") == 600, "the values read");
    CHECK(npf_conf_check(&c, err, sizeof err) < 0 && strstr(err, "sig_wake_s"), "npf_conf_check: %s", err);
    npf_conf_set(&c, "sig_wake_s", "60");
    CHECK(npf_conf_check(&c, err, sizeof err) == 0, "npf_conf_check: %s", err);
    npf_conf_free(&c);
}

int test_conf(void)
{
    char dir[] = "/tmp/npf-conf-XXXXXX", path[300], want[400], out[600];
    npf_conf c;
    FILE *f;
    struct stat st;
    char *rd = NULL;
    if (!mkdtemp(dir)) {
        CHECK(0, "mkdtemp");
        return fails;
    }
    snprintf(path, sizeof path, "%s/node.conf", dir);
    f = fopen(path, "w");
    fputs("# a comment line\n"
          "state = state.json      # trailing comment\n"
          "log=/var/log/npf.log\n"
          "dir =   sub/ident  \n"
          "root = abc/def\n"             /* not a path key: kept as written */
          "serverlist_saved = \n"        /* empty value: kept empty */
          "serverlist = off\n"            /* "off": a word, not a file next to the config */
          "no equals sign here\n"
          "udp_port = 9850\n"
          "node = 123456789 -L 8080:127.0.0.1:80\n"   /* repeatable */
          "node = 10.0.0.2:9850 --psk-file k\n"
          "resource = net lan lan\n"                  /* repeatable */
          "resource = reverse * rv\n"
          "udp_port = 9851\n", f);
    fclose(f);

    memset(&c, 0, sizeof c);
    CHECK(npf_conf_load(&c, path) == 0, "load");
    CHECK(strcmp(c.path, path) == 0, "absolute config path kept (%s)", c.path);
    snprintf(want, sizeof want, "%s/state.json", dir);
    CHECK(strcmp(npf_conf_get(&c, "state", ""), want) == 0, "relative path key resolved: %s", npf_conf_get(&c, "state", ""));
    CHECK(strcmp(npf_conf_get(&c, "log", ""), "/var/log/npf.log") == 0, "absolute path kept");
    snprintf(want, sizeof want, "%s/sub/ident", dir);
    CHECK(strcmp(npf_conf_get(&c, "dir", ""), want) == 0, "dir resolved: %s", npf_conf_get(&c, "dir", ""));
    CHECK(strcmp(npf_conf_get(&c, "root", ""), "abc/def") == 0, "non-path key untouched");
    CHECK(strcmp(npf_conf_get(&c, "serverlist_saved", "x"), "") == 0, "empty value");
    CHECK(strcmp(npf_conf_get(&c, "serverlist", ""), "off") == 0, "off kept as written: %s", npf_conf_get(&c, "serverlist", ""));
    CHECK(strcmp(npf_conf_get(&c, "udp_port", ""), "9851") == 0, "a later line replaces a single-valued key");
    CHECK(strcmp(npf_conf_get_n(&c, "node", 0), "123456789 -L 8080:127.0.0.1:80") == 0, "first node line");
    CHECK(strcmp(npf_conf_get_n(&c, "node", 1), "10.0.0.2:9850 --psk-file k") == 0, "second node line");
    CHECK(npf_conf_get_n(&c, "node", 2) == NULL, "no third node line");
    CHECK(strcmp(npf_conf_get_n(&c, "resource", 0), "net lan lan") == 0
              && strcmp(npf_conf_get_n(&c, "resource", 1), "reverse * rv") == 0, "resource lines: each one counts");
    CHECK(npf_conf_get(&c, "missing", NULL) == NULL, "missing key");
    CHECK(strcmp(npf_conf_get(&c, "missing", "dflt"), "dflt") == 0, "default value");

    /* a path-valued key that is unset: the default file next to the config */
    snprintf(want, sizeof want, "%s/npf.pid", dir);
    CHECK(strcmp(npf_conf_get_path(&c, "pidfile", "npf.pid", out, sizeof out), want) == 0,
          "default next to the config: %s", out);
    CHECK(strcmp(npf_conf_get_path(&c, "log", "x.log", out, sizeof out), "/var/log/npf.log") == 0,
          "configured value wins");
    {
        npf_conf e;
        memset(&e, 0, sizeof e);        /* no config file at all */
        CHECK(strcmp(npf_conf_get_path(&e, "log", "svc.log", out, sizeof out), "svc.log") == 0, "no config: bare name");
    }
    CHECK(npf_conf_set(&c, "k", "v") == 0 && strcmp(npf_conf_get(&c, "k", ""), "v") == 0, "set");
    {   /* a value read stays valid when it is replaced; a copy is a copy */
        const char *p1 = npf_conf_get(&c, "k", NULL);
        npf_conf d;
        char big[NPF_CONF_VAL_MAX + 1];
        memset(&d, 0, sizeof d);
        CHECK(npf_conf_set(&c, "k", "w") == 0 && npf_conf_get(&c, "k", NULL) == p1 && strcmp(p1, "w") == 0,
              "a value that fits: in place");
        CHECK(npf_conf_set(&c, "k", "a much longer value") == 0 && strcmp(p1, "w") == 0
              && strcmp(npf_conf_get(&c, "k", ""), "a much longer value") == 0, "a longer value: the old pointer stays");
        CHECK(npf_conf_copy(&d, &c) == 0 && d.n == c.n && strcmp(d.path, c.path) == 0
              && strcmp(npf_conf_get_n(&d, "node", 1), "10.0.0.2:9850 --psk-file k") == 0, "copy");
        npf_conf_set(&d, "k", "changed");
        CHECK(strcmp(npf_conf_get(&c, "k", ""), "a much longer value") == 0, "the copy is apart");
        memset(big, 'x', sizeof big - 1);
        big[sizeof big - 1] = 0;
        CHECK(npf_conf_set(&d, "toolong", big) < 0 && strcmp(d.bad, "toolong") == 0, "a value too long");
        big[NPF_CONF_VAL_MAX - 1] = 0;
        CHECK(npf_conf_set(&d, "longest", big) == 0 && strlen(npf_conf_get(&d, "longest", "")) == NPF_CONF_VAL_MAX - 1,
              "the longest value");
        npf_conf_free(&d);
        CHECK(d.n == 0 && !d.key && npf_conf_get(&d, "k", NULL) == NULL, "freed");
    }

    CHECK(npf_conf_value_ok("10.0.0.0/8, 192.168.1.2:80-443") && !npf_conf_value_ok("a\tb")
          && !npf_conf_value_ok("info\ncred = x") && !npf_conf_value_ok("x # y"), "npf_conf_value_ok");
    CHECK(npf_key_find("punch_sockets") && npf_key_find("node") && !npf_key_find("verbose"), "npf_key_find");
    key_table();

    /* private, atomic file write */
    snprintf(path, sizeof path, "%s/secret", dir);
    CHECK(npf_file_write(path, "key\n", 4, 0600) == 0, "write");
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "mode 0600 (%o)", (unsigned)(st.st_mode & 0777));
    CHECK(!npf_file_too_open(path), "0600 is not too open");
    CHECK(npf_file_read(path, &rd) == 4 && strcmp(rd, "key\n") == 0, "read back");
    free(rd);
    CHECK(npf_file_write(path, "new", 3, 0644) == 0, "replace");
    CHECK(npf_file_read(path, &rd) == 3 && memcmp(rd, "new", 3) == 0, "replaced content");
    free(rd);
    chmod(path, 0644);
    CHECK(npf_file_too_open(path), "0644 is too open");
    snprintf(want, sizeof want, "%s/secret.tmp", dir);
    CHECK(stat(want, &st) < 0, "no temp file left behind");
    CHECK(npf_file_read("/nonexistent/npf", &rd) < 0, "missing file");

    rm_dir(dir);
    npf_conf_free(&c);
    return fails;
}

/* Configuration files: parsing, path keys relative to the file, the default
 * path next to the file, and atomic private file writes. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf/conf.h"
#include "npf/sys.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

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

    /* editing the file in place: comments and other lines stay */
    {
        char ep[300], *txt = NULL;
        snprintf(ep, sizeof ep, "%s/edit.conf", dir);
        f = fopen(ep, "w");
        fputs("# head comment\nlog_level = info   # trailing\nnode = 1 -L 1:a:1\nudp_port = 1\nnode = 2 -L 2:b:2\nlog_level = warn\nlast = x", f);
        fclose(f);
        CHECK(npf_conf_file_edit(ep, "log_level", NULL, "debug") == 0, "set");
        CHECK(npf_conf_file_edit(ep, "node", "1 -L 1:a:1", NULL) == 0, "remove a repeatable line");
        CHECK(npf_conf_file_edit(ep, "node", NULL, "3 -D 1080") == 0, "append a repeatable line");
        CHECK(npf_conf_file_edit(ep, "new_key", NULL, "v") == 0, "a new key");
        CHECK(npf_conf_file_edit(ep, "udp_port", NULL, NULL) == 0, "remove a key");
        /* refused, the file untouched: a line break would add lines, '#' be cut at the next load */
        CHECK(npf_conf_file_edit(ep, "log_level", NULL, "info\ncred = x") < 0, "a value with a line break");
        CHECK(npf_conf_file_edit(ep, "node", NULL, "4 -L 1:a:1\r") < 0, "a value with a carriage return");
        CHECK(npf_conf_file_edit(ep, "allow", NULL, "10.0.0.0/8 # x") < 0, "a value with '#'");
        CHECK(npf_conf_file_edit(ep, "a = b\nc", NULL, "v") < 0 && npf_conf_file_edit(ep, "", NULL, "v") < 0,
              "a bad key");
        CHECK(npf_conf_value_ok("10.0.0.0/8, 192.168.1.2:80-443") && !npf_conf_value_ok("a\tb"), "npf_conf_value_ok");
        CHECK(npf_conf_known("punch_sockets") && npf_conf_known("node") && !npf_conf_known("verbose"),
              "npf_conf_known");
        CHECK(npf_file_read(ep, &txt) > 0, "read back");
        CHECK(txt && strcmp(txt, "# head comment\nlog_level = debug\nnode = 2 -L 2:b:2\nlast = x\nnode = 3 -D 1080\nnew_key = v\n") == 0,
              "edited file:\n%s", txt ? txt : "");
        free(txt);
        CHECK(stat(ep, &st) == 0 && (st.st_mode & 0777) == 0600, "edited file is 0600");
        unlink(ep);
    }

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

    /* cleanup */
    unlink(path);
    snprintf(path, sizeof path, "%s/node.conf", dir);
    unlink(path);
    rmdir(dir);
    npf_conf_free(&c);
    return fails;
}

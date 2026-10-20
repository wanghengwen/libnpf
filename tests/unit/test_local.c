/* local.json (npf/local.h): a round trip of every field (a nick in UTF-8
 * with quotes), the files of earlier versions converted once, names and
 * nicks checked, a damaged file refused. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "npf/local.h"
#include "npf/sys.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static void put(const char *dir, const char *name, const char *text)
{
    char p[400];
    FILE *f;
    snprintf(p, sizeof p, "%s/%s", dir, name);
    if ((f = fopen(p, "w"))) {
        fputs(text, f);
        fclose(f);
    }
}

static int exists(const char *dir, const char *name)
{
    char p[400];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

int test_local(void)
{
    char dir[] = "/tmp/npf-local-XXXXXX", err[300];
    npf_local l, m;
    npf_ldev *d;
    if (!mkdtemp(dir)) {
        CHECK(0, "mkdtemp");
        return fails;
    }
    /* nothing there: an empty record */
    CHECK(npf_local_load(&l, dir, err, sizeof err) == 0 && l.ndev == 0 && l.settings.n == 0, "empty: %s", err);
    npf_conf_set(&l.settings, "log_level", "debug");
    npf_local_start_add(&l, "--log");
    npf_local_start_add(&l, "/tmp/a log");
    d = npf_local_dev(&l, "611631552", 1);
    snprintf(d->name, sizeof d->name, "dev");
    snprintf(d->nick, sizeof d->nick, "上海 \"测试\" 机");
    d->save = 1;
    npf_local_fwd_add(d, "-L", "28290:127.0.0.1:28290");
    npf_local_fwd_add(d, "-D", ":1088");
    npf_local_fwd_add(d, "-D", ":1088");                /* no duplicate */
    /* the modules' keys: kept as they are (a string, an array), one removed */
    CHECK(npf_local_ext_set(d, "nick_synced", "\"\"") == 0
          && npf_local_ext_set(d, "apps", "[{\"name\": \"管理 \\\"页面\\\"\", \"forward\": \"-L 28290:127.0.0.1:28290\"}]") == 0
          && npf_local_ext_set(d, "gone", "1") == 0 && npf_local_ext_set(d, "gone", NULL) == 0
          && !npf_local_ext(d, "gone"), "module keys set");
    d->has_key = 1;
    memset(d->key, 7, 32);
    d = npf_local_dev(&l, "203.0.113.5:9850", 1);
    snprintf(d->psk_file, sizeof d->psk_file, "key");
    d->save = 1;
    npf_local_dev(&l, "123456789", 1);                  /* nothing in it: not written */
    CHECK(npf_local_save(&l) == 0, "save");
    npf_local_free(&l);
    CHECK(npf_local_load(&m, dir, err, sizeof err) == 0, "load: %s", err);
    d = npf_local_dev(&m, "611631552", 0);
    CHECK(d && strcmp(d->name, "dev") == 0 && strcmp(d->nick, "上海 \"测试\" 机") == 0 && d->save && d->nfwd == 2 && strcmp(d->fwd[1], "-D :1088") == 0 && d->has_key && d->key[31] == 7,
          "the device record back");
    CHECK(npf_local_by_name(&m, "dev") == d && !npf_local_by_name(&m, "nas"), "by name");
    CHECK(d->next == 2 && npf_local_ext(d, "nick_synced") && strcmp(npf_local_ext(d, "nick_synced"), "\"\"") == 0
          && npf_local_ext(d, "apps")
          && strcmp(npf_local_ext(d, "apps"),
                    "[{\"name\": \"管理 \\\"页面\\\"\", \"forward\": \"-L 28290:127.0.0.1:28290\"}]") == 0,
          "the modules' keys back as they were");
    CHECK(npf_local_fwd_del(d, "-D", ":1088") == 0 && d->nfwd == 1 && npf_local_fwd_del(d, "-D", ":1088") == -1, "fwd del");
    CHECK(npf_local_fwd_del(d, "-L", "28290:127.0.0.1:28290") == 0 && d->nfwd == 0, "the last forward deleted");
    CHECK(npf_local_dev(&m, "203.0.113.5:9850", 0) && strcmp(npf_local_dev(&m, "203.0.113.5:9850", 0)->psk_file, "key") == 0,
          "a direct peer");
    CHECK(!npf_local_dev(&m, "123456789", 0), "an empty record is dropped");
    CHECK(m.nstart == 2 && strcmp(m.start[1], "/tmp/a log") == 0, "start options");
    CHECK(strcmp(npf_conf_get(&m.settings, "log_level", ""), "debug") == 0, "settings");
    npf_local_free(&m);

    /* names and nicks */
    CHECK(npf_name_valid("nas-1.home_b") && !npf_name_valid("123") && !npf_name_valid("all") && !npf_name_valid("a b")
          && !npf_name_valid("") && !npf_name_valid("x:1"), "names");
    CHECK(npf_nick_valid("老家 客厅的 NAS") && !npf_nick_valid("a\nb"), "nicks");

    /* a damaged file is refused, not overwritten */
    put(dir, "local.json", "{\"devices\": {");
    CHECK(npf_local_load(&m, dir, err, sizeof err) < 0 && strstr(err, "not readable"), "damaged");
    npf_local_free(&m);

    /* an earlier version's local.conf and known: converted once */
    unlink(strcat(strcpy(err, dir), "/local.json"));
    put(dir, "local.conf", "log_level = warn\npeer = 611631552 -L 1:127.0.0.1:2 --psk x\n# c\npeer = 10.0.0.1:9 --psk-file k\n");
    put(dir, "known", "611631552 BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n280604799 BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n");
    CHECK(npf_local_load(&m, dir, err, sizeof err) == 0, "convert: %s", err);
    d = npf_local_dev(&m, "611631552", 0);
    CHECK(d && d->save && d->nfwd == 1 && strcmp(d->fwd[0], "-L 1:127.0.0.1:2") == 0 && d->has_key, "converted peer");
    CHECK(npf_local_dev(&m, "280604799", 0) && npf_local_dev(&m, "280604799", 0)->has_key
          && !npf_local_dev(&m, "280604799", 0)->save, "converted key");
    CHECK(npf_local_dev(&m, "10.0.0.1:9", 0) && strcmp(npf_local_dev(&m, "10.0.0.1:9", 0)->psk_file, "k") == 0, "direct");
    CHECK(strcmp(npf_conf_get(&m.settings, "log_level", ""), "warn") == 0, "converted setting");
    CHECK(exists(dir, "local.json") && !exists(dir, "local.conf") && exists(dir, "local.conf.old") && exists(dir, "known.old"),
          "files after the conversion");
    npf_local_free(&m);
    return fails;
}

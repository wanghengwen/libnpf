/* local.json (npf/local.h): a round trip of every field (a nick in UTF-8
 * with quotes), names and nicks checked, a damaged file refused. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf/local.h"
#include "npf/sys.h"
#include "test.h"

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
    d->on_demand = 1;
    d->idle_ms = 60000;
    {
        npf_lfwd a, b, k;
        memset(&a, 0, sizeof a);
        a.opt = 'L';
        snprintf(a.bind, sizeof a.bind, "127.0.0.1");
        a.port = 28290;
        snprintf(a.host, sizeof a.host, "::1");
        a.hostport = 28290;
        a.udp = 1;
        memset(&b, 0, sizeof b);
        b.opt = 'D';
        snprintf(b.bind, sizeof b.bind, "0.0.0.0");
        b.port = 0;                                     /* picked: kept as 0 */
        memset(&k, 0, sizeof k);
        k.opt = 'T';
        snprintf(k.spec, sizeof k.spec, "10.77.0.0/24");
        npf_local_fwd_add(d, &a);
        npf_local_fwd_add(d, &b);
        npf_local_fwd_add(d, &b);                       /* no duplicate */
        npf_local_fwd_add(d, &k);
    }
    /* the modules' keys: kept as they are (a string, an array), one removed */
    CHECK(npf_local_ext_set(d, "nick_synced", "\"\"") == 0
          && npf_local_ext_set(d, "apps", "[{\"name\": \"管理 \\\"页面\\\"\", \"forward\": \"-L 28290:127.0.0.1:28290\"}]") == 0
          && npf_local_ext_set(d, "gone", "1") == 0 && npf_local_ext_set(d, "gone", NULL) == 0
          && !npf_local_ext(d, "gone"), "module keys set");
    CHECK(npf_local_ext_set(d, "k23456789012345678901234567890123456789012345678", "1") < 0
          && npf_local_ext_set(d, "k2345678901234567890123456789012345678901234567", "2") == 0,
          "a key over NPF_LOCAL_EXT_KEY bytes refused, one of that many kept");
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
    CHECK(d && strcmp(d->name, "dev") == 0 && strcmp(d->nick, "上海 \"测试\" 机") == 0 && d->save && d->nfwd == 3
          && d->fwd[0].opt == 'L' && d->fwd[0].udp && d->fwd[0].port == 28290 && strcmp(d->fwd[0].host, "::1") == 0
          && d->fwd[1].opt == 'D' && d->fwd[1].port == 0 && strcmp(d->fwd[1].bind, "0.0.0.0") == 0
          && d->fwd[2].opt == 'T' && strcmp(d->fwd[2].spec, "10.77.0.0/24") == 0 && d->has_key && d->key[31] == 7,
          "the device record back (forwards as records, port 0 kept, a module's kind in its form)");
    CHECK(d && d->on_demand && d->idle_ms == 60000, "a saved peer on demand");
    CHECK(npf_local_by_name(&m, "dev") == d && !npf_local_by_name(&m, "nas"), "by name");
    CHECK(d->next == 3 && npf_local_ext(d, "k2345678901234567890123456789012345678901234567")
          && npf_local_ext(d, "nick_synced") && strcmp(npf_local_ext(d, "nick_synced"), "\"\"") == 0
          && npf_local_ext(d, "apps")
          && strcmp(npf_local_ext(d, "apps"),
                    "[{\"name\": \"管理 \\\"页面\\\"\", \"forward\": \"-L 28290:127.0.0.1:28290\"}]") == 0,
          "the modules' keys back as they were");
    {
        npf_lfwd b = d->fwd[1], a = d->fwd[0], k = d->fwd[2];
        CHECK(npf_local_fwd_del(d, &b) == 0 && d->nfwd == 2 && npf_local_fwd_del(d, &b) == -1, "fwd del");
        CHECK(npf_local_fwd_del(d, &a) == 0 && npf_local_fwd_del(d, &k) == 0 && d->nfwd == 0, "the last forward deleted");
    }
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
    /* one that cannot be read (another user's, root's 0600 file) is not a
     * first run either: refused, and left as it is (R2 M6) */
    if (geteuid() != 0) {
        char lp[600];
        struct stat st;
        put(dir, "local.json", "{\"devices\": {}}");
        snprintf(lp, sizeof lp, "%s/local.json", dir);
        chmod(lp, 0);
        CHECK(npf_local_load(&m, dir, err, sizeof err) < 0 && strstr(err, "cannot read"), "unreadable: %s", err);
        npf_local_free(&m);
        CHECK(stat(lp, &st) == 0 && st.st_size == 15 && (st.st_mode & 0777) == 0, "and not written over");
        chmod(lp, 0600);
    }
    rm_dir(dir);
    return fails;
}

/* The callee's state file and its neighbours (POSIX):
 * - a local change (another process writes the file) is read before the
 *   daemon changes the state again: not saved over;
 * - a rewrite in the same second with the same size is seen;
 * - a reload of a file that does not parse keeps the state in force;
 * - at the start, a file that does not parse: its copy (.bak); both: safe
 *   mode (no default authorization), left by a repair or passwd NEW --clear;
 * - an identity seed file that is there but unreadable is not replaced;
 * - a tmp file left in the way (a symlink) is not written through. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf/callee.h"
#include "npf/conf.h"
#include "npf/node.h"
#include "npf/out.h"
#include "npf/sys.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* the password field of the file */
static int file_pw(const char *path, char *out, size_t cap)
{
    char *s, *p, *q;
    long n = npf_file_read(path, &s);
    if (n < 0)
        return -1;
    p = strstr(s, "\"password\":\"");
    q = p ? strchr(p + 12, '"') : NULL;
    if (!q || (size_t)(q - p - 12) >= cap) {
        free(s);
        return -1;
    }
    memcpy(out, p + 12, (size_t)(q - p - 12));
    out[q - p - 12] = 0;
    free(s);
    return 0;
}

/* what another process (npf-device passwd, control off) writes */
static void write_pw(const char *path, const char *pw)
{
    char b[256];
    int n = snprintf(b, sizeof b, "{\"password\":\"%s\",\"paired\":[],\"fails\":0,\"locked_until\":0,"
                                  "\"lock_secs\":0,\"owner_reset_pending\":0,\"revokes\":[]}", pw);
    npf_file_write(path, b, (size_t)n, 0600);
}

int test_callee(void)
{
    static npf_callee d;
    char dir[] = "/tmp/npf-callee-XXXXXX", path[256], pw[64], seedp[256], tmp[300], target[300];
    uint8_t seed[32] = {1};
    if (!mkdtemp(dir)) {
        CHECK(0, "temp dir");
        return fails;
    }
    snprintf(path, sizeof path, "%s/state.json", dir);
    CHECK(npf_callee_init(&d, path, 123, seed, "default-pw") == 0, "init");
    CHECK(npf_callee_password_set(&d, "daemon-pw-1") == 0, "the daemon's password saved");

    /* another process sets a password of the same length in the same second */
    write_pw(path, "local-pw-22");
    /* the daemon changes the state (here: an owner reset; in the field a
     * failed pairing, a login's certificate ...) before its 5 s watch */
    CHECK(npf_callee_owner_reset(&d) == 0, "a change by the daemon");
    CHECK(file_pw(path, pw, sizeof pw) == 0 && strcmp(pw, "local-pw-22") == 0,
          "the local password survives the daemon's save (%s)", pw);
    CHECK(strcmp(d.password, "local-pw-22") == 0, "and is in force (%s)", d.password);

    /* a file that does not parse, read on a reload: the state stays */
    npf_file_write(path, "{not json", 9, 0600);
    {
        static const uint8_t nobody[32] = {9};
        CHECK(npf_callee_unpair_key(&d, nobody) == -1, "a command reads it (nothing to unpair)");
    }
    CHECK(strcmp(d.password, "local-pw-22") == 0, "the state in force kept (%s)", d.password);
    {
        /* at the start: its copy (state.json.bak, written after each save)
         * is taken, and the file written again from it (R2 M7) */
        static npf_callee first;
        char bak[300], out[2048];
        npf_out o = {0};
        snprintf(bak, sizeof bak, "%s.bak", path);
        CHECK(file_pw(bak, pw, sizeof pw) == 0 && strcmp(pw, "local-pw-22") == 0, "the copy has the last save (%s)", pw);
        CHECK(npf_callee_init(&first, path, 123, seed, "default-pw") == 0 && !first.damaged
              && strcmp(first.password, "local-pw-22") == 0, "a corrupt file at startup: its copy taken (%s)",
              first.password);
        CHECK(file_pw(path, pw, sizeof pw) == 0 && strcmp(pw, "local-pw-22") == 0, "and the file written again");

        /* both unusable: safe mode, never the default authorization */
        npf_file_write(path, "{not json", 9, 0600);
        npf_file_write(bak, "{neither", 8, 0600);
        CHECK(npf_callee_init(&first, path, 123, seed, "default-pw") == 0 && first.damaged,
              "both corrupt at startup: safe mode, the start goes on");
        CHECK(!first.password[0] && first.npaired == 0, "no default password in force");
        CHECK(npf_callee_password_set(&first, "another-pw-1") == -2, "a password alone is not saved over it");
        {
            char *argv[] = {"all"};
            CHECK(npf_callee_cmd(&first, "unpair", 1, argv, &o) == 1 && o.p && strstr(o.p, "damaged"),
                  "unpair says the state is damaged");
        }
        npf_out_free(&o);
        {
            char *t = NULL;
            CHECK(npf_file_read(path, &t) == 9, "the damaged file left for its repair");
            free(t);
        }
        npf_callee_show(&first, &o);
        CHECK(o.p && strstr(o.p, "DAMAGED"), "show says so");
        npf_out_free(&o);
        {
            char *argv[] = {"fresh-pw-123", "--clear"};
            CHECK(npf_callee_cmd(&first, "passwd", 2, argv, &o) == 0 && !first.damaged, "passwd NEW --clear: a fresh state");
            npf_out_free(&o);
        }
        CHECK(file_pw(path, pw, sizeof pw) == 0 && strcmp(pw, "fresh-pw-123") == 0
              && file_pw(bak, out, sizeof out) == 0 && strcmp(out, "fresh-pw-123") == 0, "written with its copy");

        /* both unusable again, then the file repaired by hand: taken at the next look */
        npf_file_write(path, "{not json", 9, 0600);
        npf_file_write(bak, "{neither", 8, 0600);
        CHECK(npf_callee_init(&first, path, 123, seed, "default-pw") == 0 && first.damaged, "safe mode again");
        write_pw(path, "repaired-pw1");
        CHECK(npf_callee_cmd(&first, "show", 0, NULL, &o) == 0 && !first.damaged
              && strcmp(first.password, "repaired-pw1") == 0, "a repaired file ends safe mode (%s)", first.password);
        npf_out_free(&o);
    }

    /* the identity seed: unreadable now, not replaced */
    snprintf(seedp, sizeof seedp, "%s/identity", dir);
    CHECK(npf_seed_file(seedp, seed, 1) == 0, "a seed made");
    if (geteuid() != 0) {
        uint8_t again[32];
        char *before, *after;
        long nb = npf_file_read(seedp, &before), na;
        chmod(seedp, 0);
        CHECK(npf_seed_file(seedp, again, 1) < 0, "an unreadable seed file is an error");
        chmod(seedp, 0600);
        na = npf_file_read(seedp, &after);
        CHECK(nb > 0 && na == nb && memcmp(before, after, (size_t)nb) == 0, "and stays as it was");
        free(before);
        free(after);
    }

    /* a symlink where the tmp file goes: removed, not written through */
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    snprintf(target, sizeof target, "%s/elsewhere", dir);
    npf_file_write(target, "keep", 4, 0644);
    unlink(tmp);
    CHECK(symlink(target, tmp) == 0, "symlink");
    write_pw(path, "after-link1");
    {
        char *s;
        long n = npf_file_read(target, &s);
        CHECK(n == 4 && memcmp(s, "keep", 4) == 0, "the link's target untouched");
        if (n >= 0)
            free(s);
    }
    CHECK(file_pw(path, pw, sizeof pw) == 0 && strcmp(pw, "after-link1") == 0, "the file written (%s)", pw);

    unlink(target);
    unlink(path);
    unlink(seedp);
    unlink(tmp);
    rmdir(dir);
    return fails;
}

/* The callee's state file and its neighbours (POSIX):
 * - a local change (another process writes the file) is read before the
 *   daemon changes the state again: not saved over;
 * - a rewrite in the same second with the same size is seen;
 * - a reload of a file that does not parse keeps the state in force;
 * - at the start, a file that does not parse: its copy (.bak); both: safe
 *   mode (no default authorization), left by a repair or passwd NEW --clear;
 * - a failed write: in force and unsaved until a later save writes it;
 * - an identity seed file that is there but unreadable is not replaced;
 * - a tmp file left in the way (a symlink) is not written through;
 * - roles and share codes (security.md D25): entries of before the roles
 *   are admins; the password pairs an admin (a member too), a share code a
 *   member (an admin stays one); the code's form (any case, dashes and
 *   spaces, no 0 O 1 I L) and its secret; a code's uses, expiry, revocation
 *   (by hand, by 5 wrong secrets: the password lock untouched, and the
 *   password's lock leaves the codes), its secret never in state.json; no
 *   code without an owner account or offline, 16 at most; an owner reset,
 *   the owner's revocation and a fresh state drop them; only an admin's
 *   paired session may bind. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf/callee.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/loop.h"
#include "npf/node.h"
#include "npf/out.h"
#include "npf/sys.h"
#include "test.h"

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

/* a state with the paired keys ka (no role: of before the roles), and the share code */
static void roles_state(const char *path, const uint8_t ka[32], const char *code, int64_t uses, int64_t expires)
{
    char b[600], k[NPF_B64_LEN(32)], id[8], sec[NPF_SHARE_SECRET];
    int n;
    npf_b64url_encode(ka, 32, k);
    npf_share_parse(code, id, sec);
    n = snprintf(b, sizeof b, "{\"password\":\"the-pw-123\",\"owner\":\"77\",\"paired\":[{\"pub\":\"%s\",\"added\":5}],"
                              "\"shares\":[{\"id\":\"%s\",\"secret\":\"%s\",\"uses\":%lld,\"expires\":%lld}]}",
                 k, id, sec, (long long)uses, (long long)expires);
    npf_file_write(path, b, (size_t)n, 0600);
}

static void roles_shares(const char *dir)
{
    static npf_callee d, again;
    npf_loop *loop = npf_loop_new();
    npf_node node;
    char path[256], id[8], s1[NPF_SHARE_SECRET], s2[NPF_SHARE_SECRET], *f = NULL;
    uint8_t seed[32] = {2}, ka[32] = {1}, kb[32] = {2}, kc[32] = {3};
    const char *code = "K7Q2-ABCD-EFGH";
    const char *pw;
    int i;
    snprintf(path, sizeof path, "%s/roles-state.json", dir);
    memset(&node, 0, sizeof node);
    node.loop = loop;
    roles_state(path, ka, code, 2, time(NULL) + 3600);
    CHECK(loop && npf_callee_init(&d, path, 123, seed, "default-pw") == 0, "init");
    npf_callee_attach(&d, &node);
    npf_timer_cancel(loop, d.t_watch);
    d.t_watch = NULL;                       /* (a node offline: nothing goes to the platform) */
    CHECK(npf_callee_is_admin(&d, ka) && d.nshares == 1, "an entry of before the roles: an admin");
    snprintf(d.paired[0].role, sizeof d.paired[0].role, "Admin");
    CHECK(!npf_callee_is_admin(&d, ka), "a role neither none nor \"admin\" (\"Admin\"): a member's");
    d.paired[0].role[0] = 0;

    /* the code's form */
    CHECK(npf_share_parse(code, id, s1) == 0 && strcmp(id, "K7Q2") == 0 && npf_share_parse("k7q2abcd efgh", NULL, s2) == 0
              && strcmp(s1, s2) == 0, "a share code: any case, without dashes, with spaces; its locator");
    CHECK(npf_share_parse("K7Q2-ABCD-EFG0", NULL, NULL) < 0 && npf_share_parse("K7Q2-ABCD-EFGO", NULL, NULL) < 0
              && npf_share_parse("K7Q2-ABCD-EFG1", NULL, NULL) < 0 && npf_share_parse("K7Q2-ABCD-EFGI", NULL, NULL) < 0
              && npf_share_parse("K7Q2-ABCD-EFGL", NULL, NULL) < 0 && npf_share_parse("K7Q2-ABCD-EFG", NULL, NULL) < 0
              && npf_share_parse("K7Q2-ABCD-EFGHJ", NULL, NULL) < 0, "0 O 1 I L, 11 or 13 characters: not a code");
    CHECK(npf_share_parse("K7Q2-ABCD-EFGJ", NULL, s2) == 0 && strcmp(s1, s2) != 0, "another secret, another hash");
    CHECK(npf_callee_password_set(&d, "k7q2-abcd-efgh") == -1, "a password in a code's form is refused");
    CHECK(npf_file_read(path, &f) > 0 && !strstr(f, "ABCD-EFGH") && !strstr(f, "ABCDEFGH"), "state.json: never the code");
    free(f);

    /* roles */
    CHECK((pw = d.ops.password(&node, "K7Q2", &d)) && strcmp(pw, s1) == 0 && !d.ops.password(&node, "ZZZZ", &d)
              && strcmp(d.ops.password(&node, NULL, &d), "the-pw-123") == 0,
          "the pairing secret by locator: the code's, none for another, the password without");
    d.ops.pair_failed(&node, s2, &d);
    CHECK(d.ops.paired(&node, kb, s2, &d) == -1 && d.shares[0].uses == 2 && d.shares[0].fails == 0 && d.npaired == 1,
          "another code with that locator (a newer one): not this code, nothing spent or counted");
    i = d.npaired;
    d.npaired = NPF_MAX_PAIRED;
    CHECK(d.ops.paired(&node, kb, s1, &d) == -1 && d.shares[0].uses == 2, "the paired list full: refused before a use goes");
    d.npaired = i;
    CHECK(d.ops.paired(&node, kb, s1, &d) == 0 && !npf_callee_is_admin(&d, kb) && d.shares[0].uses == 1,
          "paired by the code: a member, a use gone");
    CHECK(d.ops.paired(&node, ka, s1, &d) == 0 && npf_callee_is_admin(&d, ka) && d.nshares == 0,
          "an admin by a code: still an admin; the last use: the code gone");
    CHECK(d.ops.paired(&node, kc, s1, &d) == -1 && d.npaired == 2, "used up: refused");
    CHECK(d.ops.paired(&node, kb, NULL, &d) == 0 && npf_callee_is_admin(&d, kb), "a member pairing with the password: an admin");
    CHECK(npf_callee_password_set(&d, "the-pw-456") == 0 && npf_callee_is_admin(&d, ka) && npf_callee_is_admin(&d, kb),
          "a new password: the admins stay");
    CHECK(npf_callee_admin_session(&d, NPF_AUTH_IK, ka) && npf_callee_admin_session(&d, NPF_AUTH_PAKE, ka)
              && !npf_callee_admin_session(&d, NPF_AUTH_GRANT, ka) && !npf_callee_admin_session(&d, NPF_AUTH_DIRECT, ka),
          "an admin's IK or PAKE session may bind, not a grant or a direct one");
    d.ops.paired(&node, kc, NULL, &d);
    roles_state(path, ka, code, 1, time(NULL) + 3600);  /* kc a member again (another process wrote it) */
    npf_callee_refresh(&d);
    d.ops.paired(&node, kc, s1, &d);
    CHECK(!npf_callee_admin_session(&d, NPF_AUTH_IK, kc) && !npf_callee_admin_session(&d, NPF_AUTH_PAKE, kc),
          "a member's session may not bind");
    CHECK(npf_callee_init(&again, path, 123, seed, "default-pw") == 0 && npf_callee_is_admin(&again, ka)
              && !npf_callee_is_admin(&again, kc), "the roles read again after a restart");

    /* the locks apart */
    roles_state(path, ka, code, 5, time(NULL) + 3600);
    npf_callee_refresh(&d);
    for (i = 0; i < 4; i++)
        d.ops.pair_failed(&node, s1, &d);
    CHECK(d.nshares == 1 && d.fails == 0 && !d.ops.locked(&node, &d), "4 wrong secrets: the code stays, no password lock");
    d.ops.pair_failed(&node, s1, &d);
    CHECK(d.nshares == 0 && !d.ops.password(&node, "K7Q2", &d) && !d.ops.locked(&node, &d),
          "the fifth: the code revoked, the password still unlocked");
    roles_state(path, ka, code, 5, time(NULL) + 3600);
    npf_callee_refresh(&d);
    for (i = 0; i < 5; i++)
        d.ops.pair_failed(&node, NULL, &d);
    CHECK(d.ops.locked(&node, &d) && d.ops.password(&node, "K7Q2", &d), "5 wrong passwords: locked, the code still offered");

    /* expiry, revocation, the limits, unbinding */
    roles_state(path, ka, code, 5, time(NULL) - 1);
    npf_callee_refresh(&d);
    CHECK(!d.ops.password(&node, "K7Q2", &d) && d.nshares == 0, "expired: gone");
    roles_state(path, ka, code, 5, time(NULL) + 3600);
    npf_callee_refresh(&d);
    CHECK(npf_callee_share_del(&d, "ZZZZ") == -1 && npf_callee_share_del(&d, "K7Q2") == 0 && d.nshares == 0,
          "revoked by hand; an unknown locator: -1");
    CHECK(npf_callee_share_new(&d, 1, 3600, NULL, NULL) == -3, "offline: no new code (the platform gives the locator)");
    d.nshares = NPF_MAX_SHARES;
    for (i = 0; i < NPF_MAX_SHARES; i++)
        d.shares[i] = (npf_share){.id = "AAAA", .uses = 1, .expires = time(NULL) + 60};
    CHECK(npf_callee_share_new(&d, 1, 3600, NULL, NULL) == -1, "16 active: no more");
    CHECK(npf_callee_owner_reset(&d) == 0 && d.nshares == 0 && npf_callee_share_new(&d, 1, 3600, NULL, NULL) == -3,
          "an owner reset drops them; no owner: the platform decides (a model device may), offline here");
    d.nshares = 1;
    d.shares[0] = (npf_share){.id = "AAAA", .uses = 1, .expires = time(NULL) + 60};
    d.pending_owner = 79;
    memset(d.pending_op, 7, 16);
    d.pending_until = time(NULL) + 60;
    d.ops.bind_committed(&node, 79, d.pending_op, &d);
    CHECK(d.owner == 79 && d.nshares == 0, "bound: the codes of no owner gone");
    roles_state(path, ka, code, 5, time(NULL) + 3600);
    npf_callee_refresh(&d);
    d.ops.revoke(&node, 78, 1000, 1, &d);
    CHECK(d.nshares == 1, "another account's revocation: the codes stay");
    d.ops.revoke(&node, 77, 1000, 1, &d);
    CHECK(d.nshares == 0 && npf_callee_is_admin(&d, ka), "the owner's revocation: the codes gone, the roles stay");
    roles_state(path, ka, code, 5, time(NULL) + 3600);
    npf_callee_refresh(&d);
    d.damaged = 1;
    CHECK(!npf_callee_is_admin(&d, ka) && !d.ops.password(&node, "K7Q2", &d) && npf_callee_share_new(&d, 1, 60, NULL, NULL) == -2,
          "safe mode: nobody is admin, no code taken or made");
    CHECK(npf_callee_fresh(&d, "fresh-pw-123") == 0 && d.nshares == 0 && d.npaired == 0, "a fresh state: no codes");
    npf_loop_free(loop);
}

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) { le16(p, v & 0xffff); le16(p + 2, v >> 16); }

/* a grant of account for caller to callee 123, signed by iss */
static size_t grant_of(uint8_t g[128], const npf_identity *iss, uint64_t account, const uint8_t caller[32])
{
    uint8_t sig[64];
    memset(g, 0, 128);
    g[0] = 1, g[1] = NPF_GRANT_ACCOUNT;
    npf_le64(g + 2, 123);
    memcpy(g + 10, caller, 32);
    npf_le64(g + 42, account);
    le32(g + 50, (uint32_t)time(NULL));
    le32(g + 54, (uint32_t)time(NULL) + 600);
    le32(g + 60, (uint32_t)npf_fp(iss->sign_pub));
    npf_sign2(sig, iss->sign_sk, "npf-grant-v1", 12, g, 64);
    memcpy(g + 64, sig, 64);
    return 128;
}

/* the platform's grants admit the owner's clients only (lib-core audit 2,
 * 6): another account's grant is refused, an owner reset cuts the old
 * owner off at once and asks the platform (owner_reset_pending), and so
 * does a fresh state leaving safe mode */
static void owner_grants(const char *dir)
{
    static npf_callee d;
    static npf_node node;
    static const char st[] = "{\"password\":\"pw-123456\",\"owner\":\"77\"}";
    npf_loop *loop = npf_loop_new();
    npf_identity iss;
    uint8_t seed[32] = {9}, nseed[32] = {3}, g[128], caller[32] = {0x11};
    char path[256];
    uint64_t acct = 0;
    npf_grant gr;
    size_t gl;
    snprintf(path, sizeof path, "%s/owner-state.json", dir);
    npf_file_write(path, st, sizeof st - 1, 0600);
    CHECK(loop && offline_node(&node, loop, NULL, NULL) == 0 && npf_callee_init(&d, path, 123, nseed, "default-pw-0") == 0
              && d.owner == 77, "owner: init");
    npf_callee_attach(&d, &node);
    /* the intermediate (as the login gives it): may sign grants */
    npf_identity_from_seed(&iss, seed);
    memset(node.cert, 0, 164);
    node.cert[0] = 1, node.cert[1] = NPF_CERT_INTERMEDIATE;
    le32(node.cert + 26, 0xffffffffu);
    le16(node.cert + 30, 4);
    node.cert[32] = 5, node.cert[33] = 2, le16(node.cert + 34, NPF_PERM_GRANT);
    memcpy(node.cert + 36, iss.sign_pub, 32);
    node.cert_len = 164;
    gl = grant_of(g, &iss, 77, caller);
    CHECK(d.ops.grant_check(&node, g, gl, caller, &acct, &gr, &d) == 0 && acct == 77, "the owner's grant taken");
    gl = grant_of(g, &iss, 555, caller);
    CHECK(d.ops.grant_check(&node, g, gl, caller, &acct, &gr, &d) < 0, "another account's grant refused");
    CHECK(npf_callee_owner_reset(&d) == 0 && d.owner == 0 && d.owner_reset_pending && !d.owner_reset_asked,
          "an owner reset: pending, offline (asked once online)");
    gl = grant_of(g, &iss, 77, caller);
    CHECK(d.ops.grant_check(&node, g, gl, caller, &acct, &gr, &d) < 0, "the old owner's grant refused after the reset");
    d.owner_reset_pending = 0;
    d.damaged = 1;
    CHECK(npf_callee_fresh(&d, "fresh-pw-123") == 0 && d.owner_reset_pending, "a fresh state: the platform asked to forget the owner");
    npf_node_stop(&node);
    npf_loop_free(loop);
}

/* a role that is there but invalid is a member's: only a record without
 * the key is of before the roles, an admin (lib-core audit 3) */
static void role_values(const char *dir)
{
    static npf_callee d;
    static const char *const roles[] = {"\"member\"", "\"Member\"", "\"moderator\"", "\"memb\\u0001er\"",
                                        "null", "1", "[\"admin\"]", "\"\"", "\"administrator\"", "{}"};
    char path[256], e[NPF_B64_LEN(32)], b[300];
    uint8_t seed[32] = {1}, k[32];
    size_t i;
    int n;
    snprintf(path, sizeof path, "%s/role-state.json", dir);
    memset(k, 7, 32);
    npf_b64url_encode(k, 32, e);
    for (i = 0; i < sizeof roles / sizeof roles[0]; i++) {
        n = snprintf(b, sizeof b, "{\"password\":\"pw-123456\",\"paired\":[{\"pub\":\"%s\",\"added\":1,\"role\":%s}]}",
                     e, roles[i]);
        npf_file_write(path, b, (size_t)n, 0600);
        CHECK(npf_callee_init(&d, path, 123, seed, "default-pw-0") == 0 && !d.damaged
                  && (d.npaired == 0 || !npf_callee_is_admin(&d, k)), "role %s: not an admin", roles[i]);
    }
    n = snprintf(b, sizeof b, "{\"password\":\"pw-123456\",\"paired\":[{\"pub\":\"%s\",\"added\":1}]}", e);
    npf_file_write(path, b, (size_t)n, 0600);
    CHECK(npf_callee_init(&d, path, 123, seed, "default-pw-0") == 0 && npf_callee_is_admin(&d, k),
          "no role key (before the roles): an admin");
}

/* an existing state.json without a usable password (a key mistyped, null,
 * "", a number) is damaged, not a first run: never the default password
 * with the pairings kept (lib-core audit 4); its copy when that has one */
static void password_damaged(const char *dir)
{
    static npf_callee d;
    static const char *const pws[] = {"\"passwore\":\"changed-pw-1\"", "\"password\":null", "\"password\":\"\"",
                                      "\"password\":12345678", "\"password\":[\"changed-pw-1\"]"};
    char path[256], bak[300], b[300];
    uint8_t seed[32] = {1};
    size_t i;
    int n;
    snprintf(path, sizeof path, "%s/pw-state.json", dir);
    snprintf(bak, sizeof bak, "%s.bak", path);
    for (i = 0; i < sizeof pws / sizeof pws[0]; i++) {
        n = snprintf(b, sizeof b, "{%s,\"paired\":[],\"owner\":\"77\"}", pws[i]);
        npf_file_write(path, b, (size_t)n, 0600);
        remove(bak);
        CHECK(npf_callee_init(&d, path, 123, seed, "default-pw-0") == 0 && d.damaged && !d.password[0],
              "%s: safe mode, not the default password", pws[i]);
        write_pw(bak, "copy-pw-123");
        CHECK(npf_callee_init(&d, path, 123, seed, "default-pw-0") == 0 && !d.damaged
                  && strcmp(d.password, "copy-pw-123") == 0, "%s: its copy taken", pws[i]);
    }
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
        CHECK(npf_callee_unpair_key(&first, NULL) == -2 && npf_callee_owner_reset(&first) == -2,
              "unpair and the owner reset refused (damaged)");
        {
            char *t = NULL;
            CHECK(npf_file_read(path, &t) == 9, "the damaged file left for its repair");
            free(t);
        }
        npf_callee_refresh(&first);
        CHECK(first.damaged, "still damaged when the file did not change");
        CHECK(npf_callee_fresh(&first, "short") == -1 && first.damaged, "a fresh state needs a password of 8 or more");
        CHECK(npf_callee_fresh(&first, "fresh-pw-123") == 0 && !first.damaged && first.npaired == 0,
              "npf_callee_fresh (passwd NEW --clear): a fresh state");
        CHECK(file_pw(path, pw, sizeof pw) == 0 && strcmp(pw, "fresh-pw-123") == 0
              && file_pw(bak, out, sizeof out) == 0 && strcmp(out, "fresh-pw-123") == 0, "written with its copy");

        /* both unusable again, then the file repaired by hand: taken at the next look */
        npf_file_write(path, "{not json", 9, 0600);
        npf_file_write(bak, "{neither", 8, 0600);
        CHECK(npf_callee_init(&first, path, 123, seed, "default-pw") == 0 && first.damaged, "safe mode again");
        write_pw(path, "repaired-pw1");
        npf_callee_refresh(&first);
        CHECK(!first.damaged && strcmp(first.password, "repaired-pw1") == 0, "a repaired file ends safe mode (%s)",
              first.password);
    }

    /* a write that fails: in force, unsaved until a later save (npf_save) */
    chmod(dir, 0500);
    if (access(dir, W_OK) != 0) {
        CHECK(npf_callee_password_set(&d, "unsaved-pw-1") == -2 && d.unsaved && !strcmp(d.password, "unsaved-pw-1"),
              "the state cannot be written: in force, unsaved");
        chmod(dir, 0700);
        CHECK(npf_callee_save(&d) == 0 && !d.unsaved && file_pw(path, pw, sizeof pw) == 0
              && strcmp(pw, "unsaved-pw-1") == 0, "a later save writes it (%s)", pw);
    }
    chmod(dir, 0700);

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

    roles_shares(dir);
    owner_grants(dir);
    role_values(dir);
    password_damaged(dir);
    rm_dir(dir);
    return fails;
}

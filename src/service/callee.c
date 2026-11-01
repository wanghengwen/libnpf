/* Callee-side local state shared by the NAS device and console nodes
 * (security.md 5.5, 8.2, 8.3, D20, D21, D25): current / default password,
 * paired callers and their roles, share codes, password lock, owner,
 * revocations, hosted trust.
 * Kept in a JSON state file; only local commands change it. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "npf/callee.h"
#include "npf/cert.h"
#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/loop.h"
#include "npf/node.h"
#include "npf/platform.h"

#include "../node/msgs.h"

/* ---- state file ---- */

#define STATE_MAX 32768     /* the largest is about 25 KB (256 paired, 64 revocations, a cert) */

/* the index of a paired key, or -1 */
static int paired_at(const npf_callee *d, const uint8_t pub[32])
{
    int i;
    for (i = 0; i < d->npaired; i++)
        if (npf_ct_eq(d->paired[i].pub, pub, 32) == 0)
            return i;
    return -1;
}

/* admin: paired with the password ("admin"), or a file of before the roles
 * (none); any other role is a member's (security.md D25) */
static int is_admin(const npf_paired *p)
{
    return !p->role[0] || strcmp(p->role, "admin") == 0;
}

/* the platform forgets a locator (signaling.md share_del; offline: share_sync at the login) */
static void share_tell_del(npf_callee *d, const char *id)
{
    char data[40];
    snprintf(data, sizeof data, "{\"locator\":\"%s\"}", id);
    if (d->node && d->node->online)
        npf_node_send(d->node, "share_del", 1, data);
}

/* the active share code with this locator, or -1; the expired, used up
 * and revoked dropped first */
static int share_at(npf_callee *d, const char *id)
{
    int i, k = -1;
    for (i = d->nshares - 1; i >= 0; i--)
        if (d->shares[i].expires <= (int64_t)time(NULL) || d->shares[i].uses <= 0 || d->shares[i].fails >= 5) {
            share_tell_del(d, d->shares[i].id);
            npf_wipe(&d->shares[i], sizeof d->shares[i]);
            memmove(&d->shares[i], &d->shares[i + 1], (size_t)(d->nshares - i - 1) * sizeof d->shares[0]);
            d->nshares--;
        }
    for (i = 0; id && i < d->nshares; i++)
        if (strcmp(d->shares[i].id, id) == 0)
            k = i;
    return k;
}

/* the active share code with this secret (password() gave it for a
 * locator: this code, not a newer one with that locator), or -1 */
static int share_of(npf_callee *d, const char *code)
{
    size_t l = strlen(code);
    int i, k = -1;
    share_at(d, NULL);
    for (i = 0; i < d->nshares; i++)
        if (strlen(d->shares[i].secret) == l && npf_ct_eq(d->shares[i].secret, code, l) == 0)
            k = i;
    return k;
}

static void share_sync(npf_callee *d);

/* unbound: the share codes go (the platform drops their locators itself) */
static void shares_drop(npf_callee *d)
{
    npf_wipe(d->shares, sizeof d->shares);
    d->nshares = 0;
}

#if defined(__APPLE__)
#define MTIME_NS(st) ((long)(st).st_mtimespec.tv_nsec)
#elif defined(_WIN32)
#define MTIME_NS(st) 0L
#else
#define MTIME_NS(st) ((long)(st).st_mtim.tv_nsec)
#endif

/* the state file as it is now (read or written by us) */
static void stamp(npf_callee *d, const char *buf, size_t n)
{
    npf_stat_t st;
    if (npf_stat(d->state_path, &st) == 0) {
        d->state_mtime = st.st_mtime;
        d->state_mtime_ns = MTIME_NS(st);
        d->state_size = (int64_t)st.st_size;
        d->state_ino = (uint64_t)st.st_ino;
        d->state_dev = (uint64_t)st.st_dev;
    }
    d->state_settled = 0;
    npf_kdf(d->state_hash, NULL, 0, (const uint8_t *)buf, n);
}

/* changed since: its time, size or (POSIX) file, or its content. A rewrite
 * within the time's resolution (a second on Windows) with the same size
 * shows only in the content: hashed at each check until one hash, taken
 * after that second was over, still matched */
static int state_changed(npf_callee *d)
{
    npf_stat_t st;
    char *s;
    long n;
    uint8_t h[32];
    int changed;
    if (npf_stat(d->state_path, &st) != 0)
        return 0;
    if (st.st_mtime != d->state_mtime || MTIME_NS(st) != d->state_mtime_ns || (int64_t)st.st_size != d->state_size)
        return 1;
#ifndef _WIN32
    if ((uint64_t)st.st_ino != d->state_ino || (uint64_t)st.st_dev != d->state_dev)
        return 1;
#endif
    if (d->state_settled || (n = npf_file_read(d->state_path, &s)) < 0)
        return 0;
    npf_kdf(h, NULL, 0, (const uint8_t *)s, (size_t)n);
    npf_wipe_free(s, (size_t)n);
    changed = memcmp(h, d->state_hash, 32) != 0;
    if (!changed && (int64_t)time(NULL) - (int64_t)st.st_mtime > 2)
        d->state_settled = 1;
    return changed;
}

/* a state file's text and its JSON (tok on the heap): 0; -1 when it cannot
 * be read (*missing: it is not there at all) or parsed */
static int state_read(const char *path, char **s, long *n, npf_jtok **tok, npf_json *j, int *missing)
{
    npf_stat_t st;
    *tok = NULL;
    *missing = 0;
    if ((*n = npf_file_read(path, s)) < 0) {
        *missing = npf_stat(path, &st) != 0 && errno == ENOENT;
        if (!*missing)
            npf_loge("state: cannot read %s", path);
        return -1;
    }
    if (!(*tok = malloc(2048 * sizeof **tok)) || npf_json_parse(j, *s, (size_t)*n, *tok, 2048) < 0
        || (*tok)[0].type != NPF_JT_OBJECT) {
        npf_loge("state: %s cannot be parsed", path);
        free(*tok);
        *tok = NULL;
        return -1;
    }
    return 0;
}

static int state_load(npf_callee *d)
{
    npf_jtok *tok = NULL;
    char *s = NULL, bak[1100];
    long n;
    npf_json j;
    m_state *m;
    int i, missing, from_bak = 0;
    if (state_read(d->state_path, &s, &n, &tok, &j, &missing) < 0) {
        if (missing) {
            n = -1;                         /* only a missing file means first run */
        } else if (d->state_loaded) {
            /* a reload: what is in force stays (told once, not at every check) */
            npf_loge("state: %s kept the state in force", d->state_path);
            if (n >= 0) {
                stamp(d, s, (size_t)n);
                npf_wipe_free(s, (size_t)n);
            }
            return -1;
        } else {
            /* the start: its copy, written after the file at each save */
            int bm;
            stamp(d, n >= 0 ? s : "", n >= 0 ? (size_t)n : 0);    /* safe mode: until the file changes */
            if (n >= 0)
                npf_wipe_free(s, (size_t)n);
            snprintf(bak, sizeof bak, "%s.bak", d->state_path);
            if (state_read(bak, &s, &n, &tok, &j, &bm) < 0) {
                if (n >= 0)
                    npf_wipe_free(s, (size_t)n);
                if (!d->damaged)
                    npf_loge("state: %s and %s cannot be used: safe mode, every call and pairing refused until "
                             "the file is repaired (or passwd NEW --clear writes a fresh one); never the default "
                             "authorization", d->state_path, bak);
                d->damaged = 1;
                return -1;
            }
            npf_logw("state: %s cannot be used; its copy %s taken (written again)", d->state_path, bak);
            from_bak = 1;
        }
    }
    if (!(m = malloc(sizeof *m))) {
        npf_loge("state: no memory");
        if (n >= 0)
            npf_wipe_free(s, (size_t)n);
        free(tok);
        return -1;
    }
    d->state_loaded = 1;
    if (d->damaged)
        npf_log("state: %s readable again: safe mode over", d->state_path);
    d->damaged = 0;
    if (n >= 0 && !from_bak)
        stamp(d, s, (size_t)n);
    if (n < 0 || npf_msg_parse(&m_state_d, &j, 0, m, NULL, 0) < 0)
        memset(m, 0, sizeof *m);            /* a first run: the defaults */
    if (n < 0 || m->password < 0 || npf_json_str(&j, m->password, d->password, sizeof d->password) <= 0)
        snprintf(d->password, sizeof d->password, "%s", d->default_pw);
    memcpy(d->paired, m->paired, (size_t)m->npaired * sizeof *d->paired);
    d->npaired = m->npaired;
    memcpy(d->shares, m->shares, (size_t)m->nshares * sizeof *d->shares);
    d->nshares = m->nshares;
    d->fails = (int)m->fails;
    d->locked_until = m->locked_until;
    d->lock_secs = m->lock_secs;
    memcpy(d->cert, m->cert, sizeof d->cert);
    d->cert_len = (size_t)m->cert_len;
    d->owner = strtoull(m->owner, NULL, 10);
    d->owner_reset_pending = (int)m->owner_reset_pending;
    for (i = 0; i < m->nrevokes; i++) {
        d->revokes[i].account = strtoull(m->revokes[i].account, NULL, 10);
        d->revokes[i].before = m->revokes[i].before;
    }
    d->nrevokes = m->nrevokes;
    free(m);
    free(tok);
    if (n >= 0)
        npf_wipe_free(s, (size_t)n);        /* the password */
    if (from_bak)
        npf_callee_save(d);                      /* the file from its copy */
    return 0;
}

int npf_callee_save(npf_callee *d)
{
    char bak[1100];
    npf_out w = {.max = STATE_MAX - 1, .secret = 1};    /* the password */
    int i;
    if (d->damaged)
        return -1;                      /* safe mode: the damaged file stays for its repair */
    npf_out_jobj(&w);
    npf_out_kstr(&w, "password", d->password);
    npf_out_jkey(&w, "paired");
    npf_out_jarr(&w);
    for (i = 0; i < d->npaired; i++) {
        npf_out_jobj(&w);
        npf_out_kb64(&w, "pub", d->paired[i].pub, 32);
        npf_out_kint(&w, "added", d->paired[i].added);
        npf_out_kstr(&w, "role", is_admin(&d->paired[i]) ? "admin" : "member");
        npf_out_jend(&w);
    }
    npf_out_jend(&w);
    npf_out_jkey(&w, "shares");
    npf_out_jarr(&w);
    for (i = 0; i < d->nshares; i++) {
        npf_out_jobj(&w);
        npf_out_kstr(&w, "id", d->shares[i].id);
        npf_out_kstr(&w, "secret", d->shares[i].secret);
        npf_out_kint(&w, "uses", d->shares[i].uses);
        npf_out_kint(&w, "expires", d->shares[i].expires);
        npf_out_kint(&w, "fails", d->shares[i].fails);
        npf_out_jend(&w);
    }
    npf_out_jend(&w);
    npf_out_kint(&w, "fails", d->fails);
    npf_out_kint(&w, "locked_until", d->locked_until);
    npf_out_kint(&w, "lock_secs", d->lock_secs);
    if (d->cert_len)
        npf_out_kb64(&w, "cert", d->cert, d->cert_len);
    if (d->owner) {
        char a[24];
        snprintf(a, sizeof a, "%llu", (unsigned long long)d->owner);
        npf_out_kstr(&w, "owner", a);
    }
    npf_out_kint(&w, "owner_reset_pending", d->owner_reset_pending);
    npf_out_jkey(&w, "revokes");
    npf_out_jarr(&w);
    for (i = 0; i < d->nrevokes; i++) {
        char a[24];
        snprintf(a, sizeof a, "%llu", (unsigned long long)d->revokes[i].account);
        npf_out_jobj(&w);
        npf_out_kstr(&w, "account", a);
        npf_out_kint(&w, "before", d->revokes[i].before);
        npf_out_jend(&w);
    }
    npf_out_jend(&w);
    npf_out_jend(&w);
    d->unsaved = w.failed || npf_file_write(d->state_path, w.p, w.len, 0600) < 0;
    if (d->unsaved) {
        npf_loge("state: cannot write %s: %s", d->state_path, strerror(errno));
        npf_out_free(&w);
        return -1;
    }
    stamp(d, w.p, w.len);
    /* its copy, after it: taken at the start when the file cannot be used
     * (the medium damaged it); the same content, so no change is undone */
    snprintf(bak, sizeof bak, "%s.bak", d->state_path);
    if (npf_file_write(bak, w.p, w.len, 0600) < 0)
        npf_logw("state: cannot write its copy %s: %s", bak, strerror(errno));
    npf_out_free(&w);
    return 0;
}

static void report_lock(npf_callee *d);

/* reload when the local command line changed the file */
void npf_callee_refresh(npf_callee *d)
{
    if (state_changed(d)) {
        int64_t lock = d->locked_until;
        if (state_load(d) < 0)
            return;
        npf_log("state: reloaded (local change)");
        npf_callee_changed(d);
        if (d->locked_until != lock)
            report_lock(d);                 /* a local passwd lifted it: the platform's gate too */
    }
}

/* a local change of the state file (unpair, passwd on the command line)
 * takes effect within 5 s: its sessions end, a lock lifted is told; not only
 * at the next call that reads the state (while locked the platform lets
 * none through) */
static void state_watch(npf_loop *loop, void *arg)
{
    npf_callee *d = arg;
    d->t_watch = npf_timer_add(loop, 5000, state_watch, d);
    npf_callee_refresh(d);
}

static void state_watch_start(npf_callee *d)
{
    if (d->node && !d->t_watch)
        d->t_watch = npf_timer_add(d->node->loop, 5000, state_watch, d);
}

static void sync_paired(npf_callee *d)
{
    npf_out w = {0};
    int i;
    npf_out_jobj(&w);
    npf_out_jkey(&w, "fps");
    npf_out_jarr(&w);
    for (i = 0; i < d->npaired; i++) {
        uint8_t fp[8];
        npf_le64(fp, npf_fp(d->paired[i].pub));
        npf_out_jb64(&w, fp, 8);
    }
    npf_out_jend(&w);
    npf_out_jend(&w);
    if (!w.failed)
        npf_node_send(d->node, "paired_sync", 0, w.p);
    npf_out_free(&w);
}

/* the lock in the platform's time: the device's clock may be off (a NAS
 * without a clock boots at 1970), the server gate compares with its own */
static void report_lock(npf_callee *d)
{
    char data[64];
    int64_t left = d->locked_until - (int64_t)time(NULL);
    if (!d->node)
        return;                             /* not attached yet: told at the login */
    snprintf(data, sizeof data, "{\"locked_until\":%lld}",
             (long long)(left > 0 ? npf_node_time(d->node) / 1000 + left : 0));
    npf_node_send(d->node, "lock_report", 0, data);
}

/* the account's grants issued before a revocation of it are void */
static int revoked(const npf_callee *d, uint64_t account, int64_t issued)
{
    int i;
    for (i = 0; i < d->nrevokes; i++)
        if (d->revokes[i].account == account && issued < d->revokes[i].before)
            return 1;
    return 0;
}

/* the sessions of callers this state no longer admits end: a key unpaired
 * (also one paired in a session that is still open), grants when hosted
 * trust is off; checked at the handshake only otherwise */
static int drop_caller(const npf_caller *w, void *arg)
{
    npf_callee *d = arg;
    if (w->auth == NPF_AUTH_GRANT)          /* as op_grant_check: trust off, or the account's grants revoked */
        return !d->hosted_trust || revoked(d, w->grant_account, (int64_t)w->grant_issued);
    return (w->auth == NPF_AUTH_IK || w->auth == NPF_AUTH_PAKE) && paired_at(d, w->pub) < 0;
}

static void recheck_timer(npf_loop *loop, void *arg)
{
    npf_callee *d = arg;
    (void)loop;
    d->recheck = NULL;
    npf_node_end_callers(d->node, drop_caller, d);
}

/* from the loop, not inside the operation that changed the state (it may
 * run during another session's handshake) */
void npf_callee_changed(npf_callee *d)
{
    if (!d->node)
        return;
    sync_paired(d);
    if (!d->recheck)
        d->recheck = npf_timer_add(d->node->loop, 0, recheck_timer, d);
}

/* ---- callee operations ---- */

static int op_authorized(npf_node *n, const uint8_t pub[32], void *arg)
{
    npf_callee *d = arg;
    (void)n;
    npf_callee_refresh(d);
    return !d->damaged && paired_at(d, pub) >= 0;   /* safe mode: who is paired is not known */
}

static const char *op_password(npf_node *n, const char *share, void *arg)
{
    npf_callee *d = arg;
    int i;
    (void)n;
    npf_callee_refresh(d);
    if (d->damaged)
        return NULL;                        /* safe mode: no pairing (never the default password) */
    return !share ? d->password : (i = share_at(d, share)) < 0 ? NULL : d->shares[i].secret;
}

/* 1 while password pairing is locked (on the local clock, as it was set) */
static int op_locked(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    return d->damaged || d->locked_until > (int64_t)time(NULL);
}

/* a pairing: with the password an admin, with a share code a member (an
 * admin stays one), a use of the code gone */
static int op_paired(npf_node *n, const uint8_t pub[32], const char *code, void *arg)
{
    npf_callee *d = arg;
    unsigned long long fp = (unsigned long long)npf_fp(pub);
    int k;
    (void)n;
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    if (code) {
        if ((k = share_of(d, code)) < 0) {
            npf_logw("pairing of %016llx refused: its share code used up, expired or deleted meanwhile", fp);
            return -1;
        }
        if (paired_at(d, pub) < 0 && d->npaired >= NPF_MAX_PAIRED) {
            npf_logw("pairing of %016llx by share code %s refused: %d callers paired already", fp, d->shares[k].id,
                     NPF_MAX_PAIRED);
            return -1;                      /* (before a use goes) */
        }
        d->shares[k].uses--;
        d->shares[k].fails = 0;
        npf_log("paired %016llx by share code %s (%lld uses left): a member", fp, d->shares[k].id,
                (long long)d->shares[k].uses);
        share_at(d, NULL);
    } else {
        d->fails = 0;
        d->lock_secs = 0;
    }
    if ((k = paired_at(d, pub)) < 0 && d->npaired < NPF_MAX_PAIRED) {
        k = d->npaired++;
        memset(&d->paired[k], 0, sizeof d->paired[k]);
        memcpy(d->paired[k].pub, pub, 32);
        d->paired[k].added = time(NULL);
        snprintf(d->paired[k].role, sizeof d->paired[k].role, "member");
    }
    if (k >= 0 && !code)
        snprintf(d->paired[k].role, sizeof d->paired[k].role, "admin");
    npf_callee_save(d);
    sync_paired(d);
    return 0;
}

/* 5 wrong passwords in a row lock 15 minutes, each failure after that
 * doubles it, up to 24 hours (security.md 8.3); a pairing or a new password
 * starts the count again. A share code counts its own: 5 revoke it, the
 * password (the admins') is not locked by them (D25). */
static void op_pair_failed(npf_node *n, const char *code, void *arg)
{
    npf_callee *d = arg;
    int k;
    (void)n;
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    if (code) {
        if ((k = share_of(d, code)) >= 0 && ++d->shares[k].fails >= 5) {
            npf_logw("share code %s revoked after 5 wrong secrets", d->shares[k].id);
            share_at(d, NULL);
        }
        npf_callee_save(d);
        return;
    }
    d->fails++;
    if (d->fails >= 5) {
        d->lock_secs = d->lock_secs >= 12 * 3600 ? 24 * 3600
                       : d->lock_secs ? d->lock_secs * 2 : 15 * 60;
        d->locked_until = time(NULL) + d->lock_secs;
        state_watch_start(d);
        npf_logw("pairing locked for %lld s after repeated wrong passwords", (long long)d->lock_secs);
        report_lock(d);
    }
    npf_callee_save(d);
}

/* hosted trust (security.md 8.2): the grant is signed by the platform's
 * intermediate (the issuer of our own certificate), names us and this caller
 * key, is unexpired and not older than a revocation of its account */
static int op_grant_check(npf_node *n, const uint8_t *g, size_t len, const uint8_t pub[32], uint64_t *account,
                          npf_grant *out, void *arg)
{
    npf_callee *d = arg;
    npf_cert inter;
    npf_grant gr;
    int64_t now = npf_node_time(n) / 1000;
    npf_callee_refresh(d);
    if (d->damaged)
        return -1;                      /* safe mode: the revocations are not known */
    if (!d->hosted_trust || n->cert_len == 0 || npf_cert_parse(n->cert, n->cert_len, &inter) < 0
        || !(inter.perms & NPF_PERM_GRANT) || npf_grant_verify(g, len, inter.sign_pub, &gr) < 0)
        return -1;
    /* an account's client, or the hosted client of its public mappings
     * (security.md 8.4: then only the grant's targets) */
    if ((gr.kind != NPF_GRANT_ACCOUNT && gr.kind != NPF_GRANT_HOSTED) || gr.number != d->number
        || memcmp(gr.caller_dh, pub, 32) != 0)
        return -1;
    if ((int64_t)gr.expires + 300 < now || (int64_t)gr.issued > now + 300)   /* 5 minutes of clock skew */
        return -1;
    if (revoked(d, gr.account, (int64_t)gr.issued))
        return -1;
    *account = gr.account;
    *out = gr;
    return 0;
}

static void op_revoke(npf_node *n, uint64_t account, int64_t before, int owner, void *arg)
{
    npf_callee *d = arg;
    int i;
    (void)n;
    npf_callee_refresh(d);
    for (i = 0; i < d->nrevokes; i++)
        if (d->revokes[i].account == account)
            break;
    if (i == d->nrevokes) {
        if (d->nrevokes == NPF_MAX_REVOKES) {       /* drop the oldest */
            memmove(&d->revokes[0], &d->revokes[1], (NPF_MAX_REVOKES - 1) * sizeof d->revokes[0]);
            d->nrevokes--;
            i = d->nrevokes;
        }
        d->nrevokes++;
    }
    d->revokes[i].account = account;
    d->revokes[i].before = before;
    if (owner && d->owner == account) {
        d->owner = 0;
        shares_drop(d);
    }
    npf_log("revoked account %llu%s", (unsigned long long)account, owner ? " (owner)" : "");
    npf_callee_save(d);
    npf_callee_changed(d);                  /* grant sessions the revocation covers end (also by a local change) */
}

static void op_bind_committed(npf_node *n, uint64_t account, const uint8_t op[16], void *arg)
{
    npf_callee *d = arg;
    (void)n;
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    if (d->pending_owner != account || memcmp(d->pending_op, op, 16) != 0 || time(NULL) > d->pending_until)
        return;
    d->owner = account;
    d->pending_owner = 0;
    npf_callee_save(d);
    npf_log("owner is now account %llu", (unsigned long long)account);
}

/* bind_approve inside the tunnel (signaling.md "隧道内控制消息") */
void npf_callee_control(npf_node *n, npf_call *c, const npf_json *j, void *arg)
{
    npf_callee *d = arg;
    char reply[256];
    uint8_t msg[64], sig[64];
    npf_cert inter, leaf;
    npf_identity id;
    m_env e;
    m_bind_approve m;
    if (node_env(j, &e) < 0)
        return;
    if (strcmp(e.type, "bind_approve") != 0) {
        npf_call_ctl_reply(c, e.type, j, "error", "unsupported_type", NULL);
        return;
    }
    npf_callee_refresh(d);
    if (!npf_callee_admin_session(d, npf_call_auth(c), npf_call_peer_pub(c))) {  /* a member binds it to no account */
        npf_call_ctl_reply(c, e.type, j, "error", "forbidden", NULL);
        return;
    }
    if (d->owner) {
        npf_call_ctl_reply(c, e.type, j, "error", "conflict", NULL);
        return;
    }
    if (npf_msg_parse(&m_bind_approve_d, j, e.data, &m, NULL, 0) < 0
        || npf_cert_chain_parse((const uint8_t (*)[32])n->cfg.roots, n->cfg.nroots, n->cert, n->cert_len, &inter,
                                &leaf, 0) < 0) {
        npf_call_ctl_reply(c, e.type, j, "error", "bad_request", NULL);
        return;
    }
    d->pending_owner = strtoull(m.account_id, NULL, 10);
    memcpy(d->pending_op, m.operation_id, 16);
    d->pending_until = time(NULL) + 600;
    npf_bind_proof_msg(msg, d->number, leaf.key_gen, d->pending_owner, m.operation_id, m.challenge, m.expires);
    npf_identity_from_seed(&id, d->seed);
    npf_sign2(sig, id.sign_sk, "npf-bind-v1", 11, msg, 60);
    npf_identity_wipe(&id);
    {
        char b[NPF_B64_LEN(64)];
        npf_b64url_encode(sig, 64, b);
        snprintf(reply, sizeof reply, "{\"proof\":\"%s\",\"key_gen\":%u}", b, leaf.key_gen);
    }
    npf_call_ctl_reply(c, e.type, j, "ok", NULL, reply);
    npf_log("bind requested for account %s", m.account_id);
}

static void on_cert(npf_node *n, void *arg)
{
    npf_callee *d = arg;
    (void)n;
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    memcpy(d->cert, n->cert, n->cert_len);
    d->cert_len = n->cert_len;
    npf_callee_save(d);
}

int npf_callee_init(npf_callee *d, const char *state_path, uint64_t number, const uint8_t seed[32],
                    const char *default_pw)
{
    memset(d, 0, sizeof *d);
    d->state_path = state_path;
    d->number = number;
    memcpy(d->seed, seed, 32);
    snprintf(d->default_pw, sizeof d->default_pw, "%s", default_pw);
    d->hosted_trust = 1;
    npf_policy_refresh(&d->policy);
    if (state_load(d) < 0 && !d->damaged)
        return -1;
    return 0;                           /* loaded, first run, or safe mode (d->damaged) */
}

void npf_callee_attach(npf_callee *d, npf_node *n)
{
    d->node = n;
    d->ops.authorized = op_authorized;
    d->ops.password = op_password;
    d->ops.locked = op_locked;
    d->ops.paired = op_paired;
    d->ops.pair_failed = op_pair_failed;
    d->ops.grant_check = op_grant_check;
    d->ops.revoke = op_revoke;
    d->ops.bind_committed = op_bind_committed;
    d->ops.control = npf_callee_control;
    d->ops.policy = &d->policy;
    n->callee = &d->ops;
    n->callee_arg = d;
    n->on_cert = on_cert;
    n->on_cert_arg = d;
    if (d->cert_len) {
        memcpy(n->cert, d->cert, d->cert_len);
        n->cert_len = d->cert_len;
    }
    state_watch_start(d);
}

void npf_callee_on_login(npf_callee *d)
{
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    if (d->damaged)
        npf_loge("state: %s damaged: online, but every call and pairing refused (safe mode)", d->state_path);
    sync_paired(d);
    report_lock(d);
    share_sync(d);
    state_watch_start(d);
    if (d->owner_reset_pending) {
        npf_node_send(d->node, "owner_reset", 0, NULL);
        d->owner_reset_pending = 0;
        npf_callee_save(d);
    }
}

/* safe mode left by writing a fresh state: this password, nobody paired,
 * no owner, no lock (the revocations are lost: grants made before them
 * work again until they expire) */
int npf_callee_fresh(npf_callee *d, const char *np)
{
    if (strlen(np) < 8 || strlen(np) >= sizeof d->password || npf_share_parse(np, NULL, NULL) == 0)
        return -1;                      /* a share code's form would be taken for one */
    npf_logw("state: %s written afresh (safe mode over): a new password, no paired callers", d->state_path);
    d->damaged = 0;
    d->state_loaded = 1;
    snprintf(d->password, sizeof d->password, "%s", np);
    d->npaired = 0;
    d->fails = 0;
    d->locked_until = 0;
    d->lock_secs = 0;
    d->cert_len = 0;
    d->owner = 0;
    shares_drop(d);
    d->nrevokes = 0;
    d->owner_reset_pending = 0;
    npf_callee_changed(d);
    return npf_callee_save(d) < 0 ? -2 : 0;
}

int npf_callee_password_set(npf_callee *d, const char *np)
{
    if (strlen(np) < 8 || strlen(np) >= sizeof d->password || npf_share_parse(np, NULL, NULL) == 0)
        return -1;                      /* a share code's form would be taken for one */
    npf_callee_refresh(d);
    if (d->damaged)
        return -2;                      /* safe mode: npf_callee_fresh writes a fresh state */
    snprintf(d->password, sizeof d->password, "%s", np);
    d->fails = 0;
    d->locked_until = 0;
    d->lock_secs = 0;
    report_lock(d);
    return npf_callee_save(d) < 0 ? -2 : 0;
}

int npf_callee_unpair_key(npf_callee *d, const uint8_t *key)
{
    int k;
    npf_callee_refresh(d);
    if (d->damaged)
        return -2;
    if (!key) {
        d->npaired = 0;
    } else {
        if ((k = paired_at(d, key)) < 0)
            return -1;
        memmove(&d->paired[k], &d->paired[k + 1], (size_t)(d->npaired - k - 1) * sizeof d->paired[0]);
        d->npaired--;
    }
    npf_callee_changed(d);
    return npf_callee_save(d) < 0 ? -2 : 0;
}

int npf_callee_owner_reset(npf_callee *d)
{
    npf_callee_refresh(d);                   /* a local change first: not saved over */
    if (d->damaged)
        return -2;
    d->owner = 0;
    shares_drop(d);
    d->owner_reset_pending = 1;
    return npf_callee_save(d) < 0 ? -2 : 0;
}

int npf_callee_is_admin(const npf_callee *d, const uint8_t pub[32])
{
    int i = paired_at(d, pub);
    return !d->damaged && i >= 0 && is_admin(&d->paired[i]);
}

int npf_callee_admin_session(const npf_callee *d, int auth, const uint8_t pub[32])
{
    return (auth == NPF_AUTH_IK || auth == NPF_AUTH_PAKE) && npf_callee_is_admin(d, pub);
}

/* n random characters of the alphabet */
static void share_rand(char *out, int n)
{
    uint8_t r;
    int i;
    for (i = 0; i < n; i++) {
        do                                  /* uniform: 248 = 8 * 31 */
            npf_random(&r, 1);
        while (r >= 248);
        out[i] = NPF_SHARE_ABC[r % 31];
    }
    r = 0;
}

/* the platform kept these of our locators: the others' codes go (it lost them, or they expired there) */
static void share_synced(npf_node *n, const npf_env *e, int ok, void *arg)
{
    npf_callee *d = arg;
    char id[8];
    int a, i, k, kept;
    (void)n;
    if (!e || !ok || (a = npf_json_get(e->j, e->data, "locators")) < 0 || e->j->tok[a].type != NPF_JT_ARRAY)
        return;
    for (k = 0; k < d->nshares; k++) {
        for (i = 0, kept = 0; i < e->j->tok[a].size && !kept; i++)
            kept = npf_json_str(e->j, npf_json_item(e->j, a, i), id, sizeof id) > 0 && strcmp(id, d->shares[k].id) == 0;
        if (!kept) {
            npf_logw("share code %s revoked: the platform no longer has it", d->shares[k].id);
            d->shares[k].uses = 0;
        }
    }
    share_at(d, NULL);
    npf_callee_save(d);
}

/* at the login: our active locators; the platform drops its others and answers those it kept */
static void share_sync(npf_callee *d)
{
    npf_out w = {0};
    int i;
    if (d->damaged || !d->owner)
        return;                             /* unbound: the platform dropped them */
    share_at(d, NULL);
    npf_out_jobj(&w);
    npf_out_jkey(&w, "locators");
    npf_out_jarr(&w);
    for (i = 0; i < d->nshares; i++)
        npf_out_jstr(&w, d->shares[i].id);
    npf_out_jend(&w);
    npf_out_jend(&w);
    if (!w.failed)
        npf_node_request(d->node, "share_sync", w.p, share_synced, d);
    npf_out_free(&w);
}

typedef struct share_req {
    npf_callee  *d;
    int          uses;
    int64_t      ttl_s;
    npf_share_fn fn;
    void        *arg;
} share_req;

/* the platform's locator for a new code: the secret made here, the code
 * kept (never the code itself), and fn told */
static void share_made(npf_node *n, const npf_env *e, int ok, void *arg)
{
    share_req *q = arg;
    npf_callee *d = q->d;
    char loc[8] = "", k[16], code[NPF_SHARE_LEN] = "";
    int64_t exp = 0;
    npf_share v;
    int rc = -3;
    (void)n;
    memset(&v, 0, sizeof v);
    d->share_reqs--;
    if (e && !ok)
        rc = strcmp(e->error, "no_owner") == 0 ? -4 : strcmp(e->error, "rate_limited") == 0 ? -1 : -5;
    if (e && ok && npf_json_get_str(e->j, e->data, "locator", loc, sizeof loc) == NPF_SHARE_ID
        && strspn(loc, NPF_SHARE_ABC) == NPF_SHARE_ID && npf_json_get_int(e->j, e->data, "expires", 0, INT64_MAX, &exp) == 0) {
        npf_callee_refresh(d);
        share_at(d, NULL);
        memcpy(k, loc, NPF_SHARE_ID);
        share_rand(k + NPF_SHARE_ID, 8);
        snprintf(code, sizeof code, "%.4s-%.4s-%.4s", k, k + 4, k + 8);
        npf_wipe(k, sizeof k);
        npf_share_parse(code, v.id, v.secret);
        v.uses = q->uses;
        /* the platform's time, but never later than asked by our clock (the lock's rule, 8.3) */
        v.expires = exp < (int64_t)time(NULL) + q->ttl_s ? exp : (int64_t)time(NULL) + q->ttl_s;
        rc = d->damaged || !d->owner || d->nshares >= NPF_MAX_SHARES ? -5 : 0;
        if (rc == 0) {
            d->shares[d->nshares++] = v;
            npf_callee_save(d);
        } else {
            share_tell_del(d, loc);         /* not kept: the platform forgets it too */
        }
    }
    q->fn(q->arg, rc, rc ? NULL : code, rc ? NULL : &v);
    npf_wipe(code, sizeof code);
    npf_wipe(&v, sizeof v);
    free(q);
}

int npf_callee_share_new(npf_callee *d, int uses, int64_t ttl_s, npf_share_fn fn, void *arg)
{
    char data[64];
    share_req *q;
    npf_callee_refresh(d);
    if (d->damaged)
        return -2;
    if (!d->owner)
        return -4;
    share_at(d, NULL);
    if (d->nshares + d->share_reqs >= NPF_MAX_SHARES)
        return -1;
    if (!d->node || !d->node->online)
        return -3;
    if (!(q = calloc(1, sizeof *q)))
        return -5;
    q->d = d;
    q->uses = uses < 1 || uses > NPF_SHARE_USES_MAX ? 1 : uses;
    q->ttl_s = ttl_s < 1 || ttl_s > NPF_SHARE_TTL_MAX ? NPF_SHARE_TTL : ttl_s;
    q->fn = fn;
    q->arg = arg;
    snprintf(data, sizeof data, "{\"ttl_s\":%lld,\"uses\":%d}", (long long)q->ttl_s, q->uses);
    if (npf_node_request(d->node, "share_new", data, share_made, q) < 0) {
        free(q);
        return -3;
    }
    d->share_reqs++;
    return 0;
}

int npf_callee_share_del(npf_callee *d, const char *id)
{
    int i;
    npf_callee_refresh(d);
    if ((i = share_at(d, id)) < 0)
        return -1;
    d->shares[i].uses = 0;
    share_at(d, NULL);
    return npf_callee_save(d) < 0 ? -2 : 0;
}

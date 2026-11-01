/* A node's callee state (state.json in data_dir): pairing password and lock,
 * paired callers and their roles, share codes, owner, revocations, certificate. Internal to libnpf; in
 * include/npf because npf's basic module (show, passwd, unpair) and console
 * module (enroll) read and change it through struct npf's callee. */
#ifndef NPF_CALLEE_H
#define NPF_CALLEE_H

#include <stdint.h>
#include <time.h>

#include "npf/node.h"
#include "npf/tunnel.h"

#define NPF_MAX_PAIRED  256
#define NPF_MAX_REVOKES 64
#define NPF_MAX_SHARES  16
#define NPF_SHARE_TTL   (24 * 3600)     /* a share code's default life; 30 days at most */
#define NPF_SHARE_TTL_MAX (30 * 86400)
#define NPF_SHARE_USES_MAX 100

/* role "admin" (paired with the password) or "member" (with a share code);
 * "" (a record of before the roles, without the key) is admin; a role
 * there but invalid is a member's (security.md D25) */
typedef struct npf_paired {
    uint8_t pub[32];
    int64_t added;
    char    role[8];
} npf_paired;

/* an active share code (security.md D25), in state.json: never the code */
typedef struct npf_share {
    char    id[NPF_SHARE_ID + 1];       /* the locator: public, the platform's (it gave it) */
    char    secret[NPF_SHARE_SECRET];   /* what CPace runs with: a hash of the code */
    int64_t uses, expires, fails;       /* pairings left; wrong secrets (5 revoke it) */
} npf_share;

typedef struct npf_callee {
    const char *state_path;
    uint64_t   number;
    uint8_t    seed[32];
    char       default_pw[64];
    char       password[128];
    npf_paired paired[NPF_MAX_PAIRED];
    int        npaired;
    int        fails;
    int64_t    locked_until;
    int64_t    lock_secs;
    uint8_t    cert[1024];
    size_t     cert_len;
    uint64_t   owner;                   /* owner account, 0 none */
    uint64_t   pending_owner;           /* a bind proof signed for it; owner once bind_committed comes */
    uint8_t    pending_op[16];
    int64_t    pending_until;
    npf_share  shares[NPF_MAX_SHARES];
    int        nshares;
    int        share_reqs;              /* share_new requests unanswered */
    int        owner_reset_pending;     /* owner_reset asked of the platform until it answers */
    int        owner_reset_asked;       /* ... its request unanswered */
    struct { uint64_t account; int64_t before; } revokes[NPF_MAX_REVOKES];
    int        nrevokes;
    int        hosted_trust;            /* platform grants accepted (default 1) */
    /* the state file as last read or written: time, size, content, inode
     * (a change within the same second and size is still seen) */
    time_t     state_mtime;
    long       state_mtime_ns;
    int64_t    state_size;
    uint8_t    state_hash[32];
    uint64_t   state_ino, state_dev;
    int        state_settled;
    int        state_loaded;            /* read once: a later file that does not parse is not taken */
    int        damaged;                 /* safe mode: the file and its copy were unusable at the start;
                                           every call and pairing is refused and nothing is saved */
    int        unsaved;                 /* 1 after a failed write, until one succeeds (npf_save retries) */
    npf_policy policy;
    npf_callee_ops ops;
    npf_node  *node;
    struct npf_timer *recheck;
    struct npf_timer *t_watch;
} npf_callee;

/* Loads state_path (the defaults when it is missing). A file that cannot be
 * read or parsed is replaced by its copy STATE.bak (written after each save);
 * if both are unusable, d is in safe mode (damaged). A repaired file is
 * taken within 5 s; npf_callee_fresh writes a new one. 0 (loaded, first
 * run, or safe mode), -1 out of memory. Copies seed; state_path must
 * outlive d. */
int  npf_callee_init(npf_callee *d, const char *state_path, uint64_t number, const uint8_t seed[32],
                     const char *default_pw);
/* Writes the state file (0600), then its copy: 0, -1 the file not written
 * (unsaved set; always in safe mode, without unsaved). */
int  npf_callee_save(npf_callee *d);
/* Makes d n's callee (ops, certificate) and starts watching the state file. */
void npf_callee_attach(npf_callee *d, npf_node *n);
/* After each login: sends the paired fingerprints and lock, asks a pending owner reset. */
void npf_callee_on_login(npf_callee *d);
/* Reads the state file again if it changed; call it before a change so a local edit is kept. */
void npf_callee_refresh(npf_callee *d);
/* Leaves safe mode with a fresh state: this password, nobody paired, no
 * owner (the platform asked to forget it, as npf_callee_owner_reset), no
 * lock, no revocations. 0, -1 password not 8..127 bytes, -2 not saved. */
int  npf_callee_fresh(npf_callee *d, const char *password);
/* Sets the pairing password (8..127 bytes, not a share code's form) and
 * clears the lock. 0, -1 bad, -2 not saved (or safe mode). */
int  npf_callee_password_set(npf_callee *d, const char *password);
/* Unpairs the caller with this key (NULL: everyone), admin or not; its
 * sessions end. 0, -1 not paired, -2 not saved (or safe mode). */
int  npf_callee_unpair_key(npf_callee *d, const uint8_t *key);
/* Forgets the owner, and so the share codes; its grant sessions end. The
 * platform is asked to forget it (owner_reset) until it answers. 0, -2 not
 * saved (or safe mode). */
int  npf_callee_owner_reset(npf_callee *d);
/* 1 when pub is paired as an admin (security.md D25) */
int  npf_callee_is_admin(const npf_callee *d, const uint8_t pub[32]);
/* 1 for an admin's paired session (IK or PAKE): never a grant, which the
 * platform could make, a direct session or a hosted client. It may bind the
 * node and configure it (src/api/admin.c). */
int  npf_callee_admin_session(const npf_callee *d, int auth, const uint8_t pub[32]);
/* A share code for uses pairings (1..100) within ttl_s seconds (1..30
 * days), as a member: the platform gives its locator (share_new), the
 * secret is made here. 0: fn comes once with rc 0, the code (NPF_SHARE_LEN)
 * and its record, or rc -1 NPF_MAX_SHARES active, -3 offline, -4 no owner,
 * -5 refused; else that rc at once, without fn (-2 safe mode). */
typedef void (*npf_share_fn)(void *arg, int rc, const char *code, const npf_share *s);
int  npf_callee_share_new(npf_callee *d, int uses, int64_t ttl_s, npf_share_fn fn, void *arg);
/* Revokes the share code with this locator: 0, -1 none, -2 not saved */
int  npf_callee_share_del(npf_callee *d, const char *id);
/* The callee's tunnel control requests (bind_approve): ops.control, which
 * the library's admin requests (src/api/admin.c) come before. */
void npf_callee_control(npf_node *n, npf_call *c, const npf_json *j, void *arg);
/* The paired list or hosted trust changed: sends paired_sync to the
 * platform and, on the next loop turn, ends the sessions the state no
 * longer admits. Loop thread. */
void npf_callee_changed(npf_callee *d);

#endif

/* A node's callee state (state.json in data_dir): pairing password and lock,
 * paired callers, owner, revocations, certificate. Internal to libnpf; in
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

typedef struct npf_paired {
    uint8_t pub[32];
    int64_t added;
} npf_paired;

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
    int        owner_reset_pending;     /* owner_reset is sent at the next login */
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
 * (always in safe mode). */
int  npf_callee_save(npf_callee *d);
/* Makes d n's callee (ops, certificate) and starts watching the state file. */
void npf_callee_attach(npf_callee *d, npf_node *n);
/* After each login: sends the paired fingerprints, lock and pending owner reset. */
void npf_callee_on_login(npf_callee *d);
/* Reads the state file again if it changed; call it before a change so a local edit is kept. */
void npf_callee_refresh(npf_callee *d);
/* Leaves safe mode with a fresh state: this password, nobody paired, no
 * owner, no lock, no revocations (grants issued before a lost revocation
 * work again until they expire). 0, -1 password not 8..127 bytes, -2 not
 * saved. */
int  npf_callee_fresh(npf_callee *d, const char *password);
/* Sets the pairing password (8..127 bytes) and clears the lock. 0, -1 bad
 * length, -2 not saved (or safe mode). */
int  npf_callee_password_set(npf_callee *d, const char *password);
/* Unpairs the caller with this key (NULL: everyone); its sessions end. 0,
 * -1 not paired, -2 not saved (or safe mode). */
int  npf_callee_unpair_key(npf_callee *d, const uint8_t *key);
/* Forgets the owner; the platform is told at the next login. 0, -2 not
 * saved (or safe mode). */
int  npf_callee_owner_reset(npf_callee *d);
/* The paired list or hosted trust changed: sends paired_sync to the
 * platform and, on the next loop turn, ends the sessions the state no
 * longer admits. Loop thread. */
void npf_callee_changed(npf_callee *d);

#endif

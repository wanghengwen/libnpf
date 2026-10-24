/* Callee-side local state (callee.c) of every node (device credential or enrolled). */
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
    uint64_t   owner;                   /* owner account, 0 = none */
    uint64_t   pending_owner;           /* signed a bind proof, waiting for bind_committed */
    uint8_t    pending_op[16];
    int64_t    pending_until;
    int        owner_reset_pending;     /* tell the platform at next login */
    struct { uint64_t account; int64_t before; } revokes[NPF_MAX_REVOKES];
    int        nrevokes;
    int        hosted_trust;            /* accept platform grants (D3, default on) */
    time_t     state_mtime;             /* the state file as last read or written: */
    long       state_mtime_ns;          /*   its time, size and content (a change */
    int64_t    state_size;              /*   within the same second, same size) */
    uint8_t    state_hash[32];
    npf_policy policy;
    npf_callee_ops ops;
    npf_node  *node;
    struct npf_timer *recheck;          /* npf_callee_changed: the sessions checked again */
    struct npf_timer *t_watch;          /* the state file looked at (local changes) */
} npf_callee;

/* load the state file (defaults when missing) */
int  npf_callee_init(npf_callee *d, const char *state_path, uint64_t number, const uint8_t seed[32],
                     const char *default_pw);
int  npf_callee_save(npf_callee *d);
/* install the callee operations and the cached certificate into the node */
void npf_callee_attach(npf_callee *d, npf_node *n);
/* after each login: paired fingerprints, lock state, pending owner reset */
void npf_callee_on_login(npf_callee *d);
struct npf_out;
void npf_callee_show(npf_callee *d, struct npf_out *o);
/* the pairing password (8 .. 127 bytes): 0, -1 too short or long, -2 not saved */
int  npf_callee_password_set(npf_callee *d, const char *password);
/* the caller with this key unpaired (NULL: all): 0, -1 none, -2 not saved */
int  npf_callee_unpair_key(npf_callee *d, const uint8_t *key);
/* the owner forgotten, the platform told at the next login: 0, -2 not saved */
int  npf_callee_owner_reset(npf_callee *d);
/* the paired list or hosted trust changed: the platform told, and the
 * sessions this state no longer admits ended (from the loop) */
void npf_callee_changed(npf_callee *d);
/* show / passwd / unpair / owner-reset: exit code, or -2 for other commands */
int  npf_callee_cmd(npf_callee *d, const char *cmd, int argc, char **argv, struct npf_out *o);

#endif

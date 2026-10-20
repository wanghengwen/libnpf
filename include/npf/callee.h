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
    time_t     state_mtime;
    npf_policy policy;
    npf_callee_ops ops;
    npf_node  *node;
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
/* show / passwd / unpair / owner-reset: exit code, or -2 for other commands */
int  npf_callee_cmd(npf_callee *d, const char *cmd, int argc, char **argv, struct npf_out *o);

#endif

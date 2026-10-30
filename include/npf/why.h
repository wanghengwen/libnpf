/* Canonical why / error strings → NPF_END_*, NPF_NEED_*, NPF_FWD_WHY_* and
 * human text. One place for the strcmp / strstr tables that used to live in
 * ops_peer, peers, setup, node_signal and peers_forward. Internal to libnpf. */
#ifndef NPF_WHY_H
#define NPF_WHY_H

#include <stddef.h>

#include "npf.h"

/* Session end why → NPF_END_* (empty / "closed" → NPF_END_PEER; unknown → NPF_END_OTHER). */
int npf_why_end(const char *why);

/* What a session that ended for why waits for: NPF_NEED_* bits, or 0. */
int npf_why_needs(const char *why);

/* Platform reply code or message → human text, or NULL when unknown. */
const char *npf_why_platform_text(const char *code);

/* Enrolment refusal: reason first, then err; never NULL. */
const char *npf_why_enroll_text(const char *err, const char *reason);

/* Forward failure text → NPF_FWD_WHY_*. refused: policy (FS_REFUSED);
 * reverse: else NPF_FWD_WHY_REQUEST when no needle matches. */
int npf_why_fwd(int refused, int reverse, const char *why);

/* A free-form reason as the peer and the platform get it: a-z 0-9 _, at most
 * 23 characters into out; "closed" when none is left. Returns out or the
 * literal "closed". */
const char *npf_why_wire(const char *r, char out[24]);

#endif

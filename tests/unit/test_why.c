/* Canonical why / error string tables (npf/why.h): the mappings that the
 * API, peers, platform errors, enrolment and forwards rely on. The string
 * literals here must match why.c; renaming a wire why without updating both
 * fails these checks. */
#include <stdio.h>
#include <string.h>

#include "npf/why.h"
#include "test.h"

int test_why(void)
{
    char wire[24];

    /* session end → NPF_END_* (empty / closed → PEER) */
    EXPECT(npf_why_end("") == NPF_END_PEER);
    EXPECT(npf_why_end(NULL) == NPF_END_PEER);
    EXPECT(npf_why_end("closed") == NPF_END_PEER);
    EXPECT(npf_why_end("transport_lost") == NPF_END_LOST);
    EXPECT(npf_why_end("timeout") == NPF_END_LOST);
    EXPECT(npf_why_end("auth_failed") == NPF_END_REFUSED);
    EXPECT(npf_why_end("unauthorized") == NPF_END_REFUSED);
    EXPECT(npf_why_end("wrong_password") == NPF_END_REFUSED);
    EXPECT(npf_why_end("not_paired") == NPF_END_REFUSED);
    EXPECT(npf_why_end("pairing_lost") == NPF_END_REFUSED);
    EXPECT(npf_why_end("no_account") == NPF_END_REFUSED);
    EXPECT(npf_why_end("revoked") == NPF_END_REFUSED);
    EXPECT(npf_why_end("forbidden") == NPF_END_REFUSED);
    EXPECT(npf_why_end("busy") == NPF_END_REFUSED);
    EXPECT(npf_why_end("no_path") == NPF_END_UNREACHABLE);
    EXPECT(npf_why_end("unreachable") == NPF_END_UNREACHABLE);
    EXPECT(npf_why_end("offline") == NPF_END_UNREACHABLE);
    EXPECT(npf_why_end("quota") == NPF_END_PLATFORM);
    EXPECT(npf_why_end("secure_plan") == NPF_END_PLATFORM);
    EXPECT(npf_why_end("plan_limit") == NPF_END_PLATFORM);
    EXPECT(npf_why_end("idle") == NPF_END_LOCAL);
    EXPECT(npf_why_end("something_new") == NPF_END_OTHER);
    EXPECT(npf_why_end("Transport_lost") == NPF_END_OTHER); /* case-sensitive */

    /* pairing / account needs from the same why strings */
    EXPECT(npf_why_needs("not_paired") == NPF_NEED_PASSWORD);
    EXPECT(npf_why_needs("wrong_password") == (NPF_NEED_PASSWORD | NPF_NEED_PASSWORD_WRONG));
    EXPECT(npf_why_needs("pairing_lost") == (NPF_NEED_PASSWORD | NPF_NEED_PAIRING_LOST));
    EXPECT(npf_why_needs("no_account") == NPF_NEED_ACCOUNT);
    EXPECT(npf_why_needs("closed") == 0);
    EXPECT(npf_why_needs("transport_lost") == 0);
    EXPECT(npf_why_needs("forbidden") == 0);
    EXPECT(npf_why_needs("") == 0);

    /* platform human text: known codes, and message preferred over code by caller */
    EXPECT(npf_why_platform_text("quota")
           && strstr(npf_why_platform_text("quota"), "traffic"));
    EXPECT(npf_why_platform_text("plan_limit")
           && strstr(npf_why_platform_text("plan_limit"), "public mappings"));
    EXPECT(npf_why_platform_text("no reply")
           && strstr(npf_why_platform_text("no reply"), "did not answer"));
    EXPECT(npf_why_platform_text("credentials")
           && strstr(npf_why_platform_text("credentials"), "password"));
    EXPECT(npf_why_platform_text("port_taken")
           && strstr(npf_why_platform_text("port_taken"), "in use"));
    EXPECT(npf_why_platform_text("no_hosted") != NULL);
    EXPECT(npf_why_platform_text("not_publisher") != NULL);
    EXPECT(npf_why_platform_text("choose_port") != NULL);
    EXPECT(npf_why_platform_text("port_range") != NULL);
    EXPECT(npf_why_platform_text("mapping_limit") != NULL);
    EXPECT(npf_why_platform_text("device") != NULL);
    EXPECT(npf_why_platform_text("password") != NULL);
    EXPECT(npf_why_platform_text("no_password") != NULL);
    EXPECT(npf_why_platform_text("verification") != NULL);
    EXPECT(npf_why_platform_text("unauthenticated") != NULL);
    EXPECT(npf_why_platform_text("forbidden") != NULL);
    EXPECT(npf_why_platform_text("not_found") != NULL);
    EXPECT(npf_why_platform_text("conflict") != NULL);
    EXPECT(npf_why_platform_text("rate_limited") != NULL);
    EXPECT(npf_why_platform_text("unavailable") != NULL);
    EXPECT(npf_why_platform_text("timeout") != NULL);
    EXPECT(npf_why_platform_text("internal_error") != NULL);
    EXPECT(npf_why_platform_text("bad_request") != NULL);
    EXPECT(npf_why_platform_text("expired") != NULL);
    EXPECT(npf_why_platform_text("offline") != NULL);
    EXPECT(npf_why_platform_text("unsupported_type") != NULL);
    EXPECT(npf_why_platform_text("unknown_code") == NULL);
    EXPECT(npf_why_platform_text("") == NULL);
    EXPECT(npf_why_platform_text(NULL) == NULL);

    /* enrol: reason wins over err; err fallbacks; default */
    EXPECT(strstr(npf_why_enroll_text("forbidden", "bad_chain"), "vendors signed"));
    EXPECT(strstr(npf_why_enroll_text("forbidden", "whitelist"), "whitelist"));
    EXPECT(strstr(npf_why_enroll_text("forbidden", "quota"), "devices it may have"));
    EXPECT(strstr(npf_why_enroll_text("rate_limited", ""), "quota or rate"));
    EXPECT(strstr(npf_why_enroll_text("conflict", ""), "another device"));
    EXPECT(strstr(npf_why_enroll_text("forbidden", ""), "revoked credential"));
    EXPECT(strstr(npf_why_enroll_text("no reply", ""), "no reason given"));
    EXPECT(strstr(npf_why_enroll_text("bad_reply", "clone"), "other keys"));
    EXPECT(strstr(npf_why_enroll_text("x", "unregistered"), "not registered"));
    EXPECT(strstr(npf_why_enroll_text("x", "unbound"), "never given"));
    EXPECT(strstr(npf_why_enroll_text("x", "revoked"), "revoked"));
    EXPECT(strstr(npf_why_enroll_text("x", "expired"), "registration has ended"));
    EXPECT(strstr(npf_why_enroll_text("x", "rate"), "this hour"));
    EXPECT(strstr(npf_why_enroll_text("x", "wait"), "moments ago"));
    EXPECT(strstr(npf_why_enroll_text("x", "disabled"), "disabled"));
    EXPECT(strstr(npf_why_enroll_text("x", "bad_sig"), "signatures"));
    EXPECT(strstr(npf_why_enroll_text("x", "conflict"), "another device"));

    /* forward why_code: refused / needles (order) / reverse / other */
    EXPECT(npf_why_fwd(1, 0, "anything") == NPF_FWD_WHY_FORBIDDEN);
    EXPECT(npf_why_fwd(1, 1, "cannot listen") == NPF_FWD_WHY_FORBIDDEN);
    EXPECT(npf_why_fwd(0, 0, "port 80 is in use") == NPF_FWD_WHY_PORT_IN_USE);
    EXPECT(npf_why_fwd(0, 0, "port 80 is taken by forward #1") == NPF_FWD_WHY_PORT_IN_USE);
    EXPECT(npf_why_fwd(0, 0, "cannot listen: Address already in use") == NPF_FWD_WHY_PORT_IN_USE);
    EXPECT(npf_why_fwd(0, 0, "cannot listen: Permission denied") == NPF_FWD_WHY_BIND);
    EXPECT(npf_why_fwd(0, 0, "bad bind address") == NPF_FWD_WHY_BIND);
    EXPECT(npf_why_fwd(0, 0, "cannot listen") == NPF_FWD_WHY_BIND);
    EXPECT(npf_why_fwd(0, 0, "too many reverse mappings") == NPF_FWD_WHY_TOO_MANY);
    EXPECT(npf_why_fwd(0, 0, "over the limit") == NPF_FWD_WHY_TOO_MANY);
    EXPECT(npf_why_fwd(0, 1, "request failed") == NPF_FWD_WHY_REQUEST);
    EXPECT(npf_why_fwd(0, 1, "refused by the callee") == NPF_FWD_WHY_REQUEST);
    EXPECT(npf_why_fwd(0, 0, "module said no") == NPF_FWD_WHY_OTHER);
    EXPECT(npf_why_fwd(0, 0, NULL) == NPF_FWD_WHY_OTHER);
    EXPECT(npf_why_fwd(0, 0, "") == NPF_FWD_WHY_OTHER);

    /* wire form of a free-form reason (was call.c reason_code) */
    EXPECT(strcmp(npf_why_wire(NULL, wire), "closed") == 0);
    EXPECT(strcmp(npf_why_wire("", wire), "closed") == 0);
    EXPECT(strcmp(npf_why_wire("!!!", wire), "closed") == 0);
    EXPECT(strcmp(npf_why_wire("transport_lost", wire), "transport_lost") == 0);
    EXPECT(strcmp(npf_why_wire("A B-c_1!", wire), "c_1") == 0);
    EXPECT(strlen(npf_why_wire("abcdefghijklmnopqrstuvwxyz0123456789", wire)) == 23);

    return fails;
}

/* Canonical why / error string tables (npf/why.h). */
#include <string.h>

#include "npf/why.h"

/* ---- session end: NPF_END_* and NPF_NEED_* ---- */

typedef struct {
    const char *why;
    int         end;    /* NPF_END_* */
    int         needs;  /* NPF_NEED_* bits, or 0 */
} why_end_row;

static const why_end_row k_end[] = {
    {"closed", NPF_END_PEER, 0},
    {"transport_lost", NPF_END_LOST, 0},
    {"timeout", NPF_END_LOST, 0},
    {"auth_failed", NPF_END_REFUSED, 0},
    {"unauthorized", NPF_END_REFUSED, 0},
    {"wrong_password", NPF_END_REFUSED, NPF_NEED_PASSWORD | NPF_NEED_PASSWORD_WRONG},
    {"wrong_share_code", NPF_END_REFUSED, NPF_NEED_PASSWORD | NPF_NEED_PASSWORD_WRONG},
    {"not_paired", NPF_END_REFUSED, NPF_NEED_PASSWORD},
    {"pairing_lost", NPF_END_REFUSED, NPF_NEED_PASSWORD | NPF_NEED_PAIRING_LOST},
    {"no_account", NPF_END_REFUSED, NPF_NEED_ACCOUNT},
    {"revoked", NPF_END_REFUSED, 0},
    {"forbidden", NPF_END_REFUSED, 0},
    {"busy", NPF_END_REFUSED, 0},
    {"remote_access_off", NPF_END_REFUSED, 0},
    {"no_path", NPF_END_UNREACHABLE, 0},
    {"unreachable", NPF_END_UNREACHABLE, 0},
    {"offline", NPF_END_UNREACHABLE, 0},
    {"quota", NPF_END_PLATFORM, 0},
    {"secure_plan", NPF_END_PLATFORM, 0},
    {"plan_limit", NPF_END_PLATFORM, 0},
    {"idle", NPF_END_LOCAL, 0},
};

static const why_end_row *end_find(const char *why)
{
    size_t i;
    if (!why || !*why)
        why = "closed";
    for (i = 0; i < sizeof k_end / sizeof k_end[0]; i++)
        if (strcmp(k_end[i].why, why) == 0)
            return &k_end[i];
    return NULL;
}

int npf_why_end(const char *why)
{
    const why_end_row *r = end_find(why);
    return r ? r->end : NPF_END_OTHER;
}

int npf_why_needs(const char *why)
{
    const why_end_row *r = end_find(why);
    return r ? r->needs : 0;
}

/* ---- platform reply codes / messages → human text ---- */

typedef struct {
    const char *code;
    const char *text;
} why_text_row;

static const why_text_row k_platform[] = {
    {"no_hosted", "no public-mapping server has room right now (all are full or offline); try again later, or "
                  "tell the platform's operator"},
    {"plan_limit", "the account's plan allows no more public mappings (the free plan: none); upgrade it or delete one"},
    {"choose_port", "choosing the public port needs a higher plan; leave the port to the platform"},
    {"port_range", "that public port is outside the platform's port ranges"},
    {"port_taken", "that port is already in use"},
    {"mapping_limit", "the account has as many mappings as it may have; delete one first"},
    {"device", "the account has no such device"},
    {"credentials", "wrong email / phone number or password (forgot it? npf account reset EMAIL|PHONE)"},
    {"password", "wrong password"},
    {"no_password", "the account has no password (signed up with Google or WeChat): log in that way, or set one "
                    "with npf account reset"},
    {"verification", "the code is wrong or has expired; ask for a new one"},
    {"no reply", "the platform did not answer (no connection to it, or it timed out); try again"},
    {"unauthenticated", "not logged in to an account, or the login expired: log in again"},
    {"forbidden", "not allowed"},
    {"not_found", "not found"},
    {"conflict", "conflicts with what is there (or was changed elsewhere: look again)"},
    {"rate_limited", "too many attempts; wait a minute and try again"},
    {"unavailable", "the platform cannot do it right now; try again later"},
    {"timeout", "timed out; try again"},
    {"quota", "this month's traffic of the account is used up"},
    {"internal_error", "the platform had an internal error; try again later"},
    {"bad_request", "the platform did not accept the request (check the values)"},
    {"expired", "expired"},
    {"offline", "the other side is offline"},
    {"unsupported_type", "the platform does not support this (an older server?)"},
};

static const char *text_find(const why_text_row *t, size_t n, const char *code)
{
    size_t i;
    if (!code || !*code)
        return NULL;
    for (i = 0; i < n; i++)
        if (strcmp(code, t[i].code) == 0)
            return t[i].text;
    return NULL;
}

const char *npf_why_platform_text(const char *code)
{
    return text_find(k_platform, sizeof k_platform / sizeof k_platform[0], code);
}

/* ---- enrolment refusal reasons / errors → human text ---- */

static const why_text_row k_enroll_reason[] = {
    {"bad_chain", "the model credential is not one NPF's vendors signed"},
    {"bad_sig", "the enrolment's signatures are wrong"},
    {"unregistered", "the model is not registered on the platform (the vendor registers it)"},
    {"unbound", "this model credential was never given to the platform (the vendor binds it)"},
    {"revoked", "the model is disabled or this model credential revoked"},
    {"expired", "the model's registration has ended"},
    {"whitelist", "this serial number is not on the model's whitelist"},
    {"quota", "the model has all the devices it may have"},
    {"rate", "the model has had all its enrolments this hour"},
    {"clone", "a device with this serial number is online with other keys"},
    {"conflict", "this serial number belongs to another device (its owner releases it)"},
    {"wait", "the old identity was online moments ago"},
    {"disabled", "this device's number is disabled on the platform"},
};

static const why_text_row k_enroll_err[] = {
    {"rate_limited", "over the model's quota or rate, or the old identity was online moments ago"},
    {"conflict", "this serial number belongs to another device (the owner releases it)"},
    {"forbidden", "revoked credential, serial not on the whitelist, or the old identity is online"},
};

const char *npf_why_enroll_text(const char *err, const char *reason)
{
    const char *t = text_find(k_enroll_reason, sizeof k_enroll_reason / sizeof k_enroll_reason[0],
                              reason);
    if (t)
        return t;
    t = text_find(k_enroll_err, sizeof k_enroll_err / sizeof k_enroll_err[0], err);
    return t ? t : "no reason given";
}

/* ---- forward failure text → NPF_FWD_WHY_* (strstr needles, order matters) ---- */

typedef struct {
    const char *needle;
    int         code;   /* NPF_FWD_WHY_* */
} why_fwd_row;

static const why_fwd_row k_fwd[] = {
    {"in use", NPF_FWD_WHY_PORT_IN_USE},
    {"taken", NPF_FWD_WHY_PORT_IN_USE},
    {"cannot listen", NPF_FWD_WHY_BIND},
    {"bind", NPF_FWD_WHY_BIND},
    {"too many", NPF_FWD_WHY_TOO_MANY},
    {"limit", NPF_FWD_WHY_TOO_MANY},
};

int npf_why_fwd(int refused, int reverse, const char *why)
{
    size_t i;
    if (refused)
        return NPF_FWD_WHY_FORBIDDEN;
    if (!why)
        why = "";
    for (i = 0; i < sizeof k_fwd / sizeof k_fwd[0]; i++)
        if (strstr(why, k_fwd[i].needle))
            return k_fwd[i].code;
    if (reverse)
        return NPF_FWD_WHY_REQUEST;
    return NPF_FWD_WHY_OTHER;
}

/* ---- wire form of a free-form reason ---- */

const char *npf_why_wire(const char *r, char out[24])
{
    size_t k = 0;
    for (; r && *r && k < 23; r++)
        if ((*r >= 'a' && *r <= 'z') || (*r >= '0' && *r <= '9') || *r == '_')
            out[k++] = *r;
    out[k] = 0;
    return k ? out : "closed";
}

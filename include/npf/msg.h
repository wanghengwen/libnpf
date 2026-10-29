/* Signaling messages described by tables (architecture.md 5): each field's
 * key, type, place in the message's struct, length or range, and whether it
 * is required, as data; one parser checks every message against its table,
 * so that a handler gets a struct of checked values and does only its work.
 *
 * The rules, the same for every message (signaling.md "JSON 与 C 解析约束"):
 * unknown keys are ignored; duplicate keys never get here (npf_json_parse
 * refuses them); null is absent; a required field missing or wrong refuses
 * the message; an optional field that is wrong is absent (logged at the
 * debug level) unless it is NPF_F_STRICT; arrays keep at most their size, the rest is ignored; the
 * error says which field and why, never its value (it may be a secret). */
#ifndef NPF_MSG_H
#define NPF_MSG_H

#include <stddef.h>
#include <stdint.h>

#include "npf/json.h"

enum {
    NPF_F_STR = 1,  /* char[size]: no control characters, NUL-terminated; "" absent */
    NPF_F_INT,      /* int64_t in [min, max]; absent: def */
    NPF_F_BOOL,     /* int 1 (true) or 0 (false); absent: def */
    NPF_F_B64,      /* uint8_t[size] from base64url, min..size bytes; the length in the int at aux (0:
                       absent); no length for a required field of one length (min == size, aux 0) */
    NPF_F_ADDR,     /* struct sockaddr_storage from "ip:port" or "[ip6]:port"; family 0 absent */
    NPF_F_OBJ,      /* the struct of sub; zeroed when absent */
    NPF_F_ARR,      /* up to size elements of sub (its one field without a key: single values), the
                       count in the int at aux; a required one is not empty */
    NPF_F_TOK,      /* int: the value's token, of the JSON type min (NPF_JT_*, 0 any); -1 absent */
};
enum {
    NPF_F_REQ = 1,      /* required */
    NPF_F_SECRET = 2,   /* a key, a token: npf_msg_wipe clears it */
    NPF_F_SKIP = 4,     /* NPF_F_ARR: an element that does not parse is left out, the rest kept */
    NPF_F_V4 = 8,       /* NPF_F_ADDR: IPv4 only */
    NPF_F_STRICT = 16,  /* optional, but a value that is wrong refuses the message */
};

struct npf_msgdesc;

typedef struct npf_field {
    const char *key;
    uint8_t     type, flags;
    uint16_t    off, size, aux;
    int64_t     min, max, def;
    const struct npf_msgdesc *sub;
} npf_field;

typedef struct npf_msgdesc {
    const char      *name;          /* for the logs */
    const npf_field *f;
    uint16_t         nf, size;      /* fields (at most 64); the struct's size */
} npf_msgdesc;

/* the object at token obj into out (zeroed first): 0, or -1 with "field:
 * why" in err (cap may be 0) */
int  npf_msg_parse(const npf_msgdesc *d, const npf_json *j, int obj, void *out, char *err, size_t cap);
/* the NPF_F_SECRET fields cleared (after a parse, whatever it returned) */
void npf_msg_wipe(const npf_msgdesc *d, void *msg);

#endif

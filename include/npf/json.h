/* Strict token-based JSON for signaling (signaling.md "JSON 与 C 解析约束").
 *
 * The parser builds a flat token array over the input buffer (no object tree,
 * no allocation beyond the caller's token array). It rejects: invalid UTF-8,
 * bad escapes, duplicate keys (compared after unescaping), nesting deeper than
 * NPF_JSON_MAX_DEPTH, arrays longer than NPF_JSON_MAX_ARRAY, trailing data.
 *
 * Token slices point into the input buffer and are valid only while it lives. */
#ifndef NPF_JSON_H
#define NPF_JSON_H

#include <stddef.h>
#include <stdint.h>

#define NPF_JSON_MAX_SIZE   32768
#define NPF_JSON_MAX_FILE   (512 * 1024)  /* npf_json_parse_file: our own files (local.json) */
#define NPF_JSON_MAX_DEPTH  6
#define NPF_JSON_MAX_TOKENS 2048
#define NPF_JSON_MAX_ARRAY  256   /* hard cap; message schemas use lower limits */

enum { NPF_JT_OBJECT = 1, NPF_JT_ARRAY, NPF_JT_STRING, NPF_JT_NUMBER, NPF_JT_TRUE, NPF_JT_FALSE, NPF_JT_NULL };

typedef struct npf_jtok {
    uint8_t  type;
    uint8_t  escaped;       /* string contains escapes */
    uint16_t size;          /* object: number of keys; array: number of items */
    uint32_t start, end;    /* string: inside the quotes */
    int32_t  next;          /* index of the token after this value's subtree */
} npf_jtok;

typedef struct npf_json {
    const char *s;
    size_t      len;
    npf_jtok   *tok;
    int         ntok, cap;
} npf_json;

/* Parse s[0..len). tok/cap: caller's token storage. Returns 0 or -1. */
int npf_json_parse(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap);
/* the same for a file of our own, up to NPF_JSON_MAX_FILE bytes (objects and
 * arrays still hold at most NPF_JSON_MAX_ARRAY items) */
int npf_json_parse_file(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap);

/* Look up key in the object at token obj. Returns the value token or -1. */
int npf_json_get(const npf_json *j, int obj, const char *key);

/* i-th item of an array (O(i)). Returns token or -1. */
int npf_json_item(const npf_json *j, int arr, int i);

/* Copy an unescaped string value into buf (NUL-terminated). Returns the length,
 * or -1 if t is not a string, does not fit, or contains NUL. */
int npf_json_str(const npf_json *j, int t, char *buf, size_t cap);

/* Is token t a string equal to lit? (no escapes allowed in the token) */
int npf_json_eq(const npf_json *j, int t, const char *lit);

/* Integer without fraction/exponent, in [min, max]. Returns 0 or -1. */
int npf_json_int(const npf_json *j, int t, int64_t min, int64_t max, int64_t *out);
int npf_json_bool(const npf_json *j, int t, int *out);

/* Base64url string into bytes. Returns byte count or -1. */
int npf_json_b64(const npf_json *j, int t, uint8_t *out, size_t cap);

/* convenience: key lookups with type checks; return -1 when absent or wrong */
int npf_json_get_str(const npf_json *j, int obj, const char *key, char *buf, size_t cap);
int npf_json_get_int(const npf_json *j, int obj, const char *key, int64_t min, int64_t max, int64_t *out);
int npf_json_get_b64(const npf_json *j, int obj, const char *key, uint8_t *out, size_t cap);

/* ---- writer ---- */

typedef struct npf_jw {
    char   *buf;
    size_t  cap, len;
    int     err;
    int     depth;
    uint8_t first[NPF_JSON_MAX_DEPTH + 2];
    uint8_t kind[NPF_JSON_MAX_DEPTH + 2];
    int     after_key;
} npf_jw;

void npf_jw_init(npf_jw *w, char *buf, size_t cap);
void npf_jw_obj(npf_jw *w);                 /* { */
void npf_jw_arr(npf_jw *w);                 /* [ */
void npf_jw_end(npf_jw *w);                 /* } or ] */
void npf_jw_key(npf_jw *w, const char *k);
void npf_jw_str(npf_jw *w, const char *v);
void npf_jw_strn(npf_jw *w, const char *v, size_t n);
void npf_jw_int(npf_jw *w, int64_t v);
void npf_jw_bool(npf_jw *w, int v);
void npf_jw_null(npf_jw *w);
void npf_jw_b64(npf_jw *w, const uint8_t *v, size_t n);
void npf_jw_raw(npf_jw *w, const char *json, size_t n);   /* pre-encoded value */
/* key + value shortcuts */
void npf_jw_kstr(npf_jw *w, const char *k, const char *v);
void npf_jw_kint(npf_jw *w, const char *k, int64_t v);
void npf_jw_kbool(npf_jw *w, const char *k, int v);
void npf_jw_kb64(npf_jw *w, const char *k, const uint8_t *v, size_t n);
/* Returns the length (NUL-terminated in buf) or -1 on overflow / misuse. */
int  npf_jw_finish(npf_jw *w);

#endif

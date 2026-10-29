/* JSON, the library's one reader and one writer.
 *
 * The reader is strict and token based, for signaling (signaling.md "JSON 与
 * C 解析约束"): it builds a flat token array over the input buffer (no
 * object tree; the caller's tokens, or the heap's for npf_json_parse_big)
 * and rejects invalid UTF-8, bad escapes, duplicate keys (compared after
 * unescaping), nesting deeper than NPF_JSON_MAX_DEPTH, arrays longer than
 * NPF_JSON_MAX_ARRAY, trailing data. Token slices point into the input
 * buffer and are valid only while it lives.
 *
 * The writer writes into an npf_out (npf/out.h) and puts in the commas
 * between members and items by itself. */
#ifndef NPF_JSON_H
#define NPF_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "npf/out.h"

#define NPF_JSON_MAX_SIZE   32768
#define NPF_JSON_MAX_FILE   (512 * 1024)  /* npf_json_parse_big: our own JSON */
#define NPF_JSON_MAX_DEPTH  6
#define NPF_JSON_MAX_TOKENS 2048
#define NPF_JSON_MAX_ARRAY  256   /* hard cap; message schemas use lower limits */

enum { NPF_JT_OBJECT = 1, NPF_JT_ARRAY, NPF_JT_STRING, NPF_JT_NUMBER, NPF_JT_TRUE, NPF_JT_FALSE, NPF_JT_NULL };

typedef struct npf_jtok {
    uint8_t  type;
    uint8_t  escaped;       /* string contains escapes */
    uint16_t size;          /* object: number of keys; array: number of items */
    uint32_t start, end;    /* string: inside the quotes; object, array: the brackets too */
    int32_t  next;          /* index of the token after this value's subtree */
} npf_jtok;

typedef struct npf_json {
    const char *s;
    size_t      len;
    npf_jtok   *tok;
    int         ntok, cap;
} npf_json;

/* ---- reading ---- */

/* Parse s[0..len). tok/cap: caller's token storage. Returns 0 or -1. */
int npf_json_parse(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap);
/* our own JSON (a file of ours, the status): up to NPF_JSON_MAX_FILE bytes,
 * arrays of up to 65535 items (objects still NPF_JSON_MAX_ARRAY keys), the
 * tokens on the heap: 0, then npf_json_free; -1 (j zeroed: freeing it is
 * harmless) */
int  npf_json_parse_big(npf_json *j, const char *s, size_t len);
void npf_json_free(npf_json *j);

/* Look up key in the object at token obj. Returns the value token or -1. */
int npf_json_get(const npf_json *j, int obj, const char *key);

/* i-th item of an array (O(i)). Returns token or -1. */
int npf_json_item(const npf_json *j, int arr, int i);

/* Copy an unescaped string value into buf (NUL-terminated). Returns the length,
 * or -1 if t is not a string, does not fit, or contains NUL. */
int npf_json_str(const npf_json *j, int t, char *buf, size_t cap);

/* Is token t a string equal to lit after unescaping? (an escaped one of
 * more than 255 bytes equals none) */
int npf_json_eq(const npf_json *j, int t, const char *lit);

/* Integer without fraction/exponent, in [min, max]. Returns 0 or -1. */
int npf_json_int(const npf_json *j, int t, int64_t min, int64_t max, int64_t *out);
/* true or false into *out (untouched otherwise, t -1 too): 0 or -1 */
int npf_json_bool(const npf_json *j, int t, int *out);

/* Base64url string into bytes. Returns byte count or -1. */
int npf_json_b64(const npf_json *j, int t, uint8_t *out, size_t cap);

/* convenience: key lookups with type checks; return -1 when absent or wrong */
int npf_json_get_str(const npf_json *j, int obj, const char *key, char *buf, size_t cap);
int npf_json_get_int(const npf_json *j, int obj, const char *key, int64_t min, int64_t max, int64_t *out);
int npf_json_get_b64(const npf_json *j, int obj, const char *key, uint8_t *out, size_t cap);

/* ---- writing ---- */

/* s as a JSON string, quoted and escaped, as it is (no comma: text of
 * one's own) */
void npf_out_json_str(npf_out *o, const char *s, size_t n);

/* JSON with the commas between members and items written by itself inside
 * what npf_out_jobj / npf_out_jarr opened. Any text may stand for a value
 * after npf_out_jkey (npf_out_printf, npf_out_json_str, a writer of its own). */
void npf_out_jobj(npf_out *o);                  /* { */
void npf_out_jarr(npf_out *o);                  /* [ */
void npf_out_jend(npf_out *o);                  /* the } or ] of the innermost */
void npf_out_jkey(npf_out *o, const char *k);   /* k as it is (a name of ours) */
/* values: members after npf_out_jkey, else items */
void npf_out_jstr(npf_out *o, const char *s);   /* NULL: null */
void npf_out_jint(npf_out *o, long long v);
void npf_out_jb64(npf_out *o, const uint8_t *v, size_t n);   /* base64url */
void npf_out_jraw(npf_out *o, const char *json);  /* JSON already */
/* members: key and value */
void npf_out_kstr(npf_out *o, const char *k, const char *v);
void npf_out_kint(npf_out *o, const char *k, long long v);
void npf_out_kbool(npf_out *o, const char *k, int v);
void npf_out_kb64(npf_out *o, const char *k, const uint8_t *v, size_t n);

#endif

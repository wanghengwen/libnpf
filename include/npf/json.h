/* JSON: the library's one reader and one writer. Internal to libnpf; in
 * include/npf because npf's modules write their status members with it
 * (npf_module.status_json) and npf's app, tray and tools read and write
 * JSON with it.
 *
 * The reader is strict, for signaling (signaling.md "JSON 与 C 解析约束"):
 * it makes a flat token array over the input (no tree) and rejects invalid
 * UTF-8, bad escapes, duplicate keys (compared unescaped), nesting deeper
 * than NPF_JSON_MAX_DEPTH, longer arrays or objects than allowed, and
 * trailing data. Tokens point into the input: valid only while it lives.
 *
 * The writer appends to an npf_out (npf/out.h) and writes the commas
 * between members and items by itself. Misuse (npf_out_jend with nothing
 * open, nesting deeper than 31) marks the npf_out failed. */
#ifndef NPF_JSON_H
#define NPF_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "npf/out.h"

#define NPF_JSON_MAX_SIZE   32768
#define NPF_JSON_MAX_FILE   (512 * 1024)  /* npf_json_parse_big */
#define NPF_JSON_MAX_DEPTH  6
#define NPF_JSON_MAX_TOKENS 2048
#define NPF_JSON_MAX_ARRAY  256   /* items or keys; message schemas use lower limits */

enum { NPF_JT_OBJECT = 1, NPF_JT_ARRAY, NPF_JT_STRING, NPF_JT_NUMBER, NPF_JT_TRUE, NPF_JT_FALSE, NPF_JT_NULL };

typedef struct npf_jtok {
    uint8_t  type;
    uint8_t  escaped;       /* a string with escapes */
    uint16_t size;          /* object: its keys; array: its items */
    uint32_t start, end;    /* offsets; a string's inside the quotes, a container's with its brackets */
    int32_t  next;          /* the token after this value and everything in it */
} npf_jtok;

typedef struct npf_json {
    const char *s;
    size_t      len;
    npf_jtok   *tok;
    int         ntok, cap;
} npf_json;

/* ---- reading ---- */

/* Parses s[0..len), at most NPF_JSON_MAX_SIZE bytes, into the caller's cap
 * tokens. 0, or -1 when invalid, too big or short of tokens. Token 0 is
 * the top value. */
int npf_json_parse(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap);
/* The same for our own files and status: up to NPF_JSON_MAX_FILE bytes,
 * arrays of up to 65535 items (objects still NPF_JSON_MAX_ARRAY keys), the
 * tokens on the heap. 0, then free them with npf_json_free; or -1 with j
 * zeroed (npf_json_free on it is harmless). */
int  npf_json_parse_big(npf_json *j, const char *s, size_t len);
void npf_json_free(npf_json *j);

/* The functions below take token indexes and return -1 for a token that
 * is -1, out of range or of another type, so lookups can be chained. */

/* The value of key in the object obj, or -1. */
int npf_json_get(const npf_json *j, int obj, const char *key);
/* The i-th item of the array arr (O(i)), or -1. */
int npf_json_item(const npf_json *j, int arr, int i);
/* The string t unescaped into buf, NUL-terminated: its length, or -1 when
 * it does not fit or holds a NUL. */
int npf_json_str(const npf_json *j, int t, char *buf, size_t cap);
/* 1 when t is a string equal to lit unescaped (an escaped one of more than
 * 255 bytes equals nothing), else 0. */
int npf_json_eq(const npf_json *j, int t, const char *lit);
/* An integer (no fraction or exponent) in [min, max] into *out: 0 or -1. */
int npf_json_int(const npf_json *j, int t, int64_t min, int64_t max, int64_t *out);
/* true or false into *out: 0, or -1 with *out untouched. */
int npf_json_bool(const npf_json *j, int t, int *out);
/* A base64url string without escapes decoded into out: the byte count, or
 * -1 (bad, or more than cap bytes). */
int npf_json_b64(const npf_json *j, int t, uint8_t *out, size_t cap);

/* npf_json_get followed by the reader of that type. */
int npf_json_get_str(const npf_json *j, int obj, const char *key, char *buf, size_t cap);
int npf_json_get_int(const npf_json *j, int obj, const char *key, int64_t min, int64_t max, int64_t *out);
int npf_json_get_b64(const npf_json *j, int obj, const char *key, uint8_t *out, size_t cap);

/* ---- writing ---- */

/* Writes n bytes of s as a quoted JSON string: '"', '\\' and control bytes
 * escaped, other bytes as they are (s must be UTF-8). No comma: for text
 * of the caller's own, or a value after npf_out_jkey. */
void npf_out_json_str(npf_out *o, const char *s, size_t n);

/* Inside what npf_out_jobj / npf_out_jarr opened, each member (from its
 * key) or item gets the comma before it. After npf_out_jkey any text may
 * be the value (npf_out_printf, npf_out_json_str, a writer of its own). */
void npf_out_jobj(npf_out *o);                  /* { */
void npf_out_jarr(npf_out *o);                  /* [ */
void npf_out_jend(npf_out *o);                  /* the } or ] of the innermost one open */
void npf_out_jkey(npf_out *o, const char *k);   /* "k": with k escaped */
/* A value: the member's after npf_out_jkey, else an item. */
void npf_out_jstr(npf_out *o, const char *s);   /* NULL writes null */
void npf_out_jint(npf_out *o, long long v);
void npf_out_jb64(npf_out *o, const uint8_t *v, size_t n);   /* base64url; its buffer wiped when o->secret */
void npf_out_jraw(npf_out *o, const char *json);  /* json written as it is */
/* A member: npf_out_jkey, then the value. */
void npf_out_kstr(npf_out *o, const char *k, const char *v);
void npf_out_kint(npf_out *o, const char *k, long long v);
void npf_out_kbool(npf_out *o, const char *k, int v);
void npf_out_kb64(npf_out *o, const char *k, const uint8_t *v, size_t n);

#endif

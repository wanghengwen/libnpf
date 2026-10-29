/* Growable buffers, and output text: command output, JSON replies, the
 * messages we send (the one JSON writer of the library). */
#ifndef NPF_OUT_H
#define NPF_OUT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* *pp, an array of *cap items of size bytes, made to hold need items: its
 * capacity doubled from first (> 0) until it does. 0, or -1 when out of
 * memory or too large (nothing changed) */
int npf_grow(void *pp, size_t *cap, size_t need, size_t size, size_t first);

typedef struct npf_out {
    char    *p;
    size_t   len, cap;
    size_t   max;              /* set by its user: more than max bytes fail (0: no limit) */
    int      failed;           /* sticky: incomplete output must never be saved or sent */
    int      secret;           /* set by its user: no copy left behind, wiped when freed */
    /* JSON written with the functions below: how deep, which containers
     * have a member already (bit d: the comma before the next at depth d)
     * and are arrays (bit d), a key written whose value comes next */
    uint8_t  jdepth, jkey;
    uint32_t jmore, jarr;
} npf_out;

#ifdef __MINGW32__
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
#else
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
void npf_out_vprintf(npf_out *o, const char *fmt, va_list ap);
void npf_out_write(npf_out *o, const char *s, size_t n);

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
void npf_out_jbool(npf_out *o, int v);
void npf_out_jb64(npf_out *o, const uint8_t *v, size_t n);   /* base64url */
void npf_out_jraw(npf_out *o, const char *json);  /* JSON already */
/* members: key and value */
void npf_out_kstr(npf_out *o, const char *k, const char *v);
void npf_out_kint(npf_out *o, const char *k, long long v);
void npf_out_kbool(npf_out *o, const char *k, int v);
void npf_out_kb64(npf_out *o, const char *k, const uint8_t *v, size_t n);
void npf_out_free(npf_out *o);                  /* the text; max and secret stay */

#endif

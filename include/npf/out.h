/* Growable output text: command output, JSON replies. */
#ifndef NPF_OUT_H
#define NPF_OUT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef struct npf_out {
    char    *p;
    size_t   len, cap;
    int      failed;           /* sticky: incomplete output must never be saved or sent */
    /* JSON written with the functions below: how deep, which containers
     * have a member already (bit d: the comma before the next at depth d),
     * a key written whose value comes next */
    uint8_t  jdepth, jkey;
    uint32_t jmore;
} npf_out;

#ifdef __MINGW32__
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
#else
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
void npf_out_vprintf(npf_out *o, const char *fmt, va_list ap);
void npf_out_write(npf_out *o, const char *s, size_t n);

/* s as a JSON string, quoted and escaped, as it is (no comma: text of
 * one's own); npf_out_jstr: a C string's (NULL: "") */
void npf_out_json_str(npf_out *o, const char *s, size_t n);
void npf_out_jstr(npf_out *o, const char *s);

/* JSON with the commas between members and items written by itself inside
 * what npf_out_jopen opened. Any text may stand for a value after
 * npf_out_jkey (npf_out_printf, npf_out_jstr, a writer of its own). */
void npf_out_jopen(npf_out *o, char c);         /* '{' or '[' */
void npf_out_jclose(npf_out *o, char c);        /* '}' or ']' */
void npf_out_jkey(npf_out *o, const char *k);   /* k as it is (a name of ours) */
void npf_out_jitem(npf_out *o, const char *s);  /* a string item of an array */
void npf_out_jraw(npf_out *o, const char *json);  /* a value or item that is JSON already */
/* a member: key and value (npf_out_kstr's NULL is null) */
void npf_out_kstr(npf_out *o, const char *k, const char *v);
void npf_out_kint(npf_out *o, const char *k, long long v);
void npf_out_kbool(npf_out *o, const char *k, int v);
/* the JSON escape of byte c into e (\" \\ \n \r \t, other control bytes
 * \u00xx): its length, 0 when c goes as it is (npf_jw's strings too) */
size_t npf_json_esc(unsigned char c, char e[6]);
void npf_out_free(npf_out *o);

#endif

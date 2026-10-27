/* Growable output text: command output, JSON replies. */
#ifndef NPF_OUT_H
#define NPF_OUT_H

#include <stddef.h>

/* growable output text */
typedef struct npf_out {
    char  *p;
    size_t len, cap;
    int    failed;             /* sticky: incomplete output must never be saved or sent */
} npf_out;

#ifdef __MINGW32__
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
#else
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
void npf_out_write(npf_out *o, const char *s, size_t n);
/* s as a JSON string, quoted and escaped; npf_out_jstr: a C string's (NULL: "") */
void npf_out_json_str(npf_out *o, const char *s, size_t n);
void npf_out_jstr(npf_out *o, const char *s);
/* an object's member: k (written as it is) after a comma unless *first;
 * npf_out_jkstr's NULL is null */
void npf_out_jkey(npf_out *o, int *first, const char *k);
void npf_out_jkstr(npf_out *o, int *first, const char *k, const char *v);
void npf_out_jkint(npf_out *o, int *first, const char *k, long long v);
/* the JSON escape of byte c into e (\" \\ \n \r \t, other control bytes
 * \u00xx): its length, 0 when c goes as it is (npf_jw's strings too) */
size_t npf_json_esc(unsigned char c, char e[6]);
void npf_out_free(npf_out *o);

#endif

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
/* s as a JSON string, quoted and escaped */
void npf_out_json_str(npf_out *o, const char *s, size_t n);
void npf_out_free(npf_out *o);

#endif

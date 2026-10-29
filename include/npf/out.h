/* Growable buffers, and output text: command output, JSON replies (the
 * writer of npf/json.h), the messages we send. */
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
    /* npf/json.h's writer: how deep, which containers have a member already
     * (bit d: the comma before the next at depth d) and are arrays (bit d),
     * a key written whose value comes next */
    uint8_t  jdepth, jkey;
    uint32_t jmore, jarr;
} npf_out;

/* vsnprintf with C99's formats (%zu, %lld) on MinGW too: msvcrt's lacks them */
#ifdef __MINGW32__
#define npf_vsnprintf __mingw_vsnprintf
#else
#define npf_vsnprintf vsnprintf
#endif

#ifdef __MINGW32__
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
#else
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
void npf_out_vprintf(npf_out *o, const char *fmt, va_list ap);
void npf_out_write(npf_out *o, const char *s, size_t n);
void npf_out_free(npf_out *o);                  /* the text; max and secret stay */

#endif

/* Growable arrays and npf_out, the growing text buffer of command output,
 * JSON (npf/json.h) and messages. Internal to libnpf; in include/npf
 * because npf's modules write command output into an npf_out
 * (npf_mod_cmd.run) and npf's app and TUN module use both. */
#ifndef NPF_OUT_H
#define NPF_OUT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* Makes the array *pp of *cap items of size bytes hold at least need
 * items, doubling the capacity from first (> 0) until it does; *pp and
 * *cap are updated. 0, or -1 when out of memory or too large, with
 * nothing changed. */
int npf_grow(void *pp, size_t *cap, size_t need, size_t size, size_t first);

/* Start from {0} (with max and secret as wanted). p is NUL-terminated
 * once anything was written, NULL before; it belongs to the npf_out. */
typedef struct npf_out {
    char    *p;
    size_t   len, cap;
    size_t   max;              /* set by its user: writing past max bytes fails it (0: no limit) */
    int      failed;           /* sticky: a write failed (memory, max); never save or send the text */
    int      secret;           /* set by its user: a buffer outgrown is wiped, and so is p when freed */
    /* npf/json.h's writer state: depth; per depth d, bit d of jmore (a
     * member or item written: the next gets a comma) and of jarr (an
     * array); jkey: a key written, its value next */
    uint8_t  jdepth, jkey;
    uint32_t jmore, jarr;
} npf_out;

/* vsnprintf with C99's formats (%zu, %lld), also on MinGW */
#ifdef __MINGW32__
#define npf_vsnprintf __mingw_vsnprintf
#else
#define npf_vsnprintf vsnprintf
#endif

#ifdef __MINGW32__
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
#elif defined(__GNUC__)
void npf_out_printf(npf_out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#else
void npf_out_printf(npf_out *o, const char *fmt, ...);
#endif
void npf_out_vprintf(npf_out *o, const char *fmt, va_list ap);
/* Appending to a failed npf_out does nothing. */
void npf_out_write(npf_out *o, const char *s, size_t n);
/* Frees the text and resets o for reuse; max and secret stay. */
void npf_out_free(npf_out *o);

#endif

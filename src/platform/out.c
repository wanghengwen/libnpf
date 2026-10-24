/* Growable output text (npf/out.h). */
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "npf/out.h"

#ifdef __MINGW32__
#define vsnprintf __mingw_vsnprintf     /* C99 formats (%zu) */
#endif


static int out_grow(npf_out *o, size_t more)
{
    size_t cap = o->cap ? o->cap : 256;
    char *p;
    if (o->failed)
        return -1;
    if (more > SIZE_MAX - o->len - 1) {
        o->failed = 1;
        return -1;
    }
    if (o->len + more + 1 <= o->cap)
        return 0;
    while (o->len + more + 1 > cap) {
        if (cap > SIZE_MAX / 2) {
            cap = o->len + more + 1;
            break;
        }
        cap *= 2;
    }
    p = realloc(o->p, cap);
    if (!p) {
        o->failed = 1;
        return -1;
    }
    o->p = p;
    o->cap = cap;
    return 0;
}

void npf_out_write(npf_out *o, const char *s, size_t n)
{
    if (out_grow(o, n) < 0)
        return;
    if (n)
        memcpy(o->p + o->len, s, n);
    o->len += n;
    o->p[o->len] = 0;
}

void npf_out_printf(npf_out *o, const char *fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        o->failed = 1;
        return;
    }
    if (out_grow(o, (size_t)n) < 0)
        return;
    va_start(ap, fmt);
    vsnprintf(o->p + o->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    o->len += (size_t)n;
}

void npf_out_json_str(npf_out *o, const char *s, size_t n)
{
    size_t i, run;
    npf_out_write(o, "\"", 1);
    for (i = 0; i < n && !o->failed; i++) {
        unsigned char ch = (unsigned char)s[i];
        for (run = i; run < n && (unsigned char)s[run] >= 0x20 && s[run] != '"' && s[run] != '\\'; run++)
            ;
        if (run > i) {                      /* the plain bytes up to the next escape: one write */
            npf_out_write(o, s + i, run - i);
            i = run - 1;
            continue;
        }
        if (ch == '"' || ch == '\\') {
            char e[2] = {'\\', (char)ch};
            npf_out_write(o, e, 2);
        } else if (ch == '\n') {
            npf_out_write(o, "\\n", 2);
        } else if (ch == '\r') {
            npf_out_write(o, "\\r", 2);
        } else if (ch == '\t') {
            npf_out_write(o, "\\t", 2);
        } else if (ch < 0x20) {
            npf_out_printf(o, "\\u%04x", ch);
        } else {
            npf_out_write(o, (const char *)&s[i], 1);
        }
    }
    npf_out_write(o, "\"", 1);
}

void npf_out_free(npf_out *o)
{
    free(o->p);
    memset(o, 0, sizeof *o);
}

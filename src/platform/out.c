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

size_t npf_json_esc(unsigned char c, char e[6])
{
    static const char hex[] = "0123456789abcdef";
    e[0] = '\\';
    switch (c) {
    case '"': case '\\': e[1] = (char)c; return 2;
    case '\n': e[1] = 'n'; return 2;
    case '\r': e[1] = 'r'; return 2;
    case '\t': e[1] = 't'; return 2;
    default: break;
    }
    if (c >= 0x20)
        return 0;
    e[1] = 'u'; e[2] = '0'; e[3] = '0'; e[4] = hex[c >> 4]; e[5] = hex[c & 15];
    return 6;
}

void npf_out_json_str(npf_out *o, const char *s, size_t n)
{
    size_t i, run = 0, el;              /* run: the plain bytes from there on go in one write */
    char e[6];
    npf_out_write(o, "\"", 1);
    for (i = 0; i < n; i++)
        if ((el = npf_json_esc((unsigned char)s[i], e))) {
            npf_out_write(o, s + run, i - run);
            npf_out_write(o, e, el);
            run = i + 1;
        }
    npf_out_write(o, s + run, n - run);
    npf_out_write(o, "\"", 1);
}

void npf_out_jstr(npf_out *o, const char *s)
{
    npf_out_json_str(o, s ? s : "", s ? strlen(s) : 0);
}

void npf_out_jkey(npf_out *o, int *first, const char *k)
{
    npf_out_printf(o, "%s\"%s\":", *first ? "" : ",", k);
    *first = 0;
}

void npf_out_jkstr(npf_out *o, int *first, const char *k, const char *v)
{
    npf_out_jkey(o, first, k);
    if (v)
        npf_out_jstr(o, v);
    else
        npf_out_write(o, "null", 4);
}

void npf_out_jkint(npf_out *o, int *first, const char *k, long long v)
{
    npf_out_jkey(o, first, k);
    npf_out_printf(o, "%lld", v);
}

void npf_out_free(npf_out *o)
{
    free(o->p);
    memset(o, 0, sizeof *o);
}

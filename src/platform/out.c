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

void npf_out_vprintf(npf_out *o, const char *fmt, va_list ap)
{
    va_list aq;
    int n;
    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (n < 0) {
        o->failed = 1;
        return;
    }
    if (out_grow(o, (size_t)n) < 0)
        return;
    vsnprintf(o->p + o->len, (size_t)n + 1, fmt, ap);
    o->len += (size_t)n;
}

void npf_out_printf(npf_out *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    npf_out_vprintf(o, fmt, ap);
    va_end(ap);
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

/* before a value: the comma when its container has a member already (none
 * at the top level, none after a key) */
static void jsep(npf_out *o)
{
    if (o->jkey) {
        o->jkey = 0;
        return;
    }
    if (!o->jdepth)
        return;
    if (o->jmore & (1u << o->jdepth))
        npf_out_write(o, ",", 1);
    o->jmore |= 1u << o->jdepth;
}

void npf_out_jopen(npf_out *o, char c)
{
    jsep(o);
    if (o->jdepth >= 31) {                  /* deeper than the mask: never in our replies */
        o->failed = 1;
        return;
    }
    npf_out_write(o, &c, 1);
    o->jdepth++;
    o->jmore &= ~(1u << o->jdepth);
}

void npf_out_jclose(npf_out *o, char c)
{
    o->jkey = 0;
    if (o->jdepth)
        o->jdepth--;
    npf_out_write(o, &c, 1);
}

/* the member counts from here, so a value written with printf after it
 * still has the comma before the next key */
void npf_out_jkey(npf_out *o, const char *k)
{
    o->jkey = 0;
    jsep(o);
    npf_out_printf(o, "\"%s\":", k);
    o->jkey = 1;
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

void npf_out_jitem(npf_out *o, const char *s)
{
    jsep(o);
    npf_out_jstr(o, s);
}

void npf_out_jraw(npf_out *o, const char *json)
{
    jsep(o);
    npf_out_write(o, json, strlen(json));
}

void npf_out_kstr(npf_out *o, const char *k, const char *v)
{
    npf_out_jkey(o, k);
    if (v)
        npf_out_jstr(o, v);
    else
        npf_out_jraw(o, "null");
}

void npf_out_kint(npf_out *o, const char *k, long long v)
{
    npf_out_jkey(o, k);
    jsep(o);
    npf_out_printf(o, "%lld", v);
}

void npf_out_kbool(npf_out *o, const char *k, int v)
{
    npf_out_jkey(o, k);
    npf_out_jraw(o, v ? "true" : "false");
}

void npf_out_free(npf_out *o)
{
    free(o->p);
    memset(o, 0, sizeof *o);
}

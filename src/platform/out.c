/* Growable buffers and output text (npf/out.h). */
#include "npf/sys.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "npf/crypto.h"
#include "npf/out.h"

#ifdef __MINGW32__
#define vsnprintf __mingw_vsnprintf     /* C99 formats (%zu) */
#endif

int npf_grow(void *pp, size_t *cap, size_t need, size_t size, size_t first)
{
    size_t c = *cap ? *cap : first;
    void *p;
    if (need <= *cap)
        return 0;
    while (c < need)
        c = c > SIZE_MAX / 2 ? need : 2 * c;
    if (c > SIZE_MAX / size || !(p = realloc(*(void **)pp, c * size)))
        return -1;
    *(void **)pp = p;
    *cap = c;
    return 0;
}

static int out_grow(npf_out *o, size_t more)
{
    size_t cap = o->cap;
    char *p;
    if (o->failed || more > SIZE_MAX - o->len - 1 || (o->max && o->len + more > o->max))
        goto fail;
    if (o->len + more + 1 <= cap)
        return 0;
    p = o->secret ? NULL : o->p;        /* a secret: a new buffer, the old one wiped (realloc leaves it behind) */
    if (npf_grow(&p, &cap, o->len + more + 1, 1, 256) < 0)
        goto fail;
    if (o->secret && o->p) {
        memcpy(p, o->p, o->len + 1);
        npf_wipe(o->p, o->cap);
        free(o->p);
    }
    o->p = p;
    o->cap = cap;
    return 0;
fail:
    o->failed = 1;
    return -1;
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

/* the JSON escape of byte c into e (\" \\ \n \r \t, other control bytes
 * \u00xx): its length, 0 when c goes as it is */
static size_t json_esc(unsigned char c, char e[6])
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

static void jopen(npf_out *o, char c)
{
    uint32_t bit;
    jsep(o);
    if (o->jdepth >= 31) {                  /* deeper than the masks: never in ours */
        o->failed = 1;
        return;
    }
    npf_out_write(o, &c, 1);
    bit = 1u << ++o->jdepth;
    o->jmore &= ~bit;
    o->jarr = c == '[' ? o->jarr | bit : o->jarr & ~bit;
}

void npf_out_jobj(npf_out *o) { jopen(o, '{'); }
void npf_out_jarr(npf_out *o) { jopen(o, '['); }

void npf_out_jend(npf_out *o)
{
    o->jkey = 0;
    if (!o->jdepth) {
        o->failed = 1;
        return;
    }
    npf_out_write(o, o->jarr >> o->jdepth & 1 ? "]" : "}", 1);
    o->jdepth--;
}

/* the member counts from here, so a value written with printf after it
 * still has the comma before the next key */
void npf_out_jkey(npf_out *o, const char *k)
{
    o->jkey = 0;
    jsep(o);
    npf_out_json_str(o, k, strlen(k));
    npf_out_write(o, ":", 1);
    o->jkey = 1;
}

void npf_out_json_str(npf_out *o, const char *s, size_t n)
{
    size_t i, run = 0, el;              /* run: the plain bytes from there on go in one write */
    char e[6];
    npf_out_write(o, "\"", 1);
    for (i = 0; i < n; i++)
        if ((el = json_esc((unsigned char)s[i], e))) {
            npf_out_write(o, s + run, i - run);
            npf_out_write(o, e, el);
            run = i + 1;
        }
    npf_out_write(o, s + run, n - run);
    npf_out_write(o, "\"", 1);
}

void npf_out_jstr(npf_out *o, const char *s)
{
    jsep(o);
    if (s)
        npf_out_json_str(o, s, strlen(s));
    else
        npf_out_write(o, "null", 4);
}

void npf_out_jint(npf_out *o, long long v)
{
    jsep(o);
    npf_out_printf(o, "%lld", v);
}

void npf_out_jbool(npf_out *o, int v)
{
    npf_out_jraw(o, v ? "true" : "false");
}

void npf_out_jb64(npf_out *o, const uint8_t *v, size_t n)
{
    jsep(o);
    if (n > SIZE_MAX / 2 || out_grow(o, NPF_B64_LEN(n) + 1) < 0)   /* the quotes, the text */
        return;
    o->p[o->len++] = '"';
    o->len += npf_b64url_encode(v, n, o->p + o->len);
    o->p[o->len++] = '"';
    o->p[o->len] = 0;
}

void npf_out_jraw(npf_out *o, const char *json)
{
    jsep(o);
    npf_out_write(o, json, strlen(json));
}

void npf_out_kstr(npf_out *o, const char *k, const char *v) { npf_out_jkey(o, k); npf_out_jstr(o, v); }
void npf_out_kint(npf_out *o, const char *k, long long v) { npf_out_jkey(o, k); npf_out_jint(o, v); }
void npf_out_kbool(npf_out *o, const char *k, int v) { npf_out_jkey(o, k); npf_out_jbool(o, v); }
void npf_out_kb64(npf_out *o, const char *k, const uint8_t *v, size_t n) { npf_out_jkey(o, k); npf_out_jb64(o, v, n); }

void npf_out_free(npf_out *o)
{
    if (o->secret && o->p)
        npf_wipe(o->p, o->cap);
    free(o->p);
    *o = (npf_out){.max = o->max, .secret = o->secret};     /* the settings stay for its next use */
}

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

void npf_out_free(npf_out *o)
{
    if (o->secret && o->p)
        npf_wipe(o->p, o->cap);
    free(o->p);
    *o = (npf_out){.max = o->max, .secret = o->secret};     /* the settings stay for its next use */
}

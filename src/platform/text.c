#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "npf/text.h"

static const char *space(const char *s)
{
    while (isspace((unsigned char)*s)) s++;
    return s;
}

int npf_text_word(const char **p, char *out, size_t cap)
{
    const char *s = space(*p), *end = s;
    size_t n;
    while (*end && !isspace((unsigned char)*end)) end++;
    n = (size_t)(end - s);
    if (!n || n >= cap)
        return -1;
    memcpy(out, s, n);
    out[n] = 0;
    *p = end;
    return 0;
}

int npf_text_int(const char **p, int *out)
{
    char *end;
    long n;
    errno = 0;
    n = strtol(*p, &end, 10);
    if (end == *p || errno == ERANGE || n < INT_MIN || n > INT_MAX)
        return -1;
    *out = (int)n;
    *p = end;
    return 0;
}

int npf_text_hex(const char **p, unsigned long *out)
{
    const char *s = space(*p);
    char *end;
    unsigned long n;
    if (*s == '-')
        return -1;
    errno = 0;
    n = strtoul(s, &end, 16);
    if (end == s || errno == ERANGE)
        return -1;
    *out = n;
    *p = end;
    return 0;
}

int npf_text_mac(const char *s, unsigned char out[6])
{
    int i;
    for (i = 0; i < 6; i++) {
        unsigned long n;
        if (npf_text_hex(&s, &n) < 0 || n > 255)
            return -1;
        out[i] = (unsigned char)n;
        if (i < 5 && *s++ != ':')
            return -1;
    }
    return *s ? -1 : 0;
}

int npf_text_dec(const char *s, long lo, long hi, long *out)
{
    long v = 0;
    if (!*s || (s[0] == '0' && s[1]))
        return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return -1;
        v = v * 10 + (*s - '0');
        if (v > hi)
            return -1;
    }
    if (v < lo)
        return -1;
    *out = v;
    return 0;
}

int npf_hostport(const char *s, char *host, size_t cap, uint16_t *port)
{
    const char *h = s, *colon;
    long p;
    size_t n;
    if (*s == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':')
            return -1;
        h = s + 1;
        colon = rb + 1;
    } else if (!(colon = strrchr(s, ':'))) {
        return -1;
    }
    n = (size_t)((*s == '[' ? colon - 1 : colon) - h);
    if (!n || n >= cap || npf_text_dec(colon + 1, 0, 65535, &p) < 0)
        return -1;
    memcpy(host, h, n);
    host[n] = 0;
    *port = (uint16_t)p;
    return 0;
}

int npf_http_status(const char *s)
{
    int code = 0, i;
    if (strncmp(s, "HTTP/1.", 7) != 0)
        return -1;
    s += 7;
    if (*s < '0' || *s > '9')
        return -1;
    do { s++; } while (*s >= '0' && *s <= '9');
    if (*s++ != ' ')
        return -1;
    for (i = 0; i < 3; i++, s++) {
        if (*s < '0' || *s > '9')
            return -1;
        code = code * 10 + *s - '0';
    }
    return code >= 100 && (*s == ' ' || *s == '\r' || *s == '\n') ? code : -1;
}

/* ASCII only: tolower would follow the locale (a Latin-1 one folds 0xC4 to 0xE4) */
static int ascii_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

int npf_prefix_nocase(const char *s, const char *p)
{
    for (; *p; s++, p++)
        if (ascii_lower((unsigned char)*s) != ascii_lower((unsigned char)*p))
            return 0;
    return 1;
}

/* the code point of the UTF-8 sequence at s (*len its bytes), or -1: not
 * UTF-8 (overlong, a surrogate, past U+10FFFF, cut) */
static long utf8_at(const unsigned char *s, int *len)
{
    long c;
    int n, i;
    if (s[0] < 0x80) {
        *len = 1;
        return s[0];
    }
    n = s[0] >= 0xf0 && s[0] <= 0xf4 ? 4 : s[0] >= 0xe0 ? (s[0] < 0xf0 ? 3 : 0) : s[0] >= 0xc2 ? 2 : 0;
    if (!n)
        return -1;
    c = s[0] & (0x7f >> n);
    for (i = 1; i < n; i++) {
        if ((s[i] & 0xc0) != 0x80)
            return -1;
        c = c << 6 | (s[i] & 0x3f);
    }
    if ((n == 3 && c < 0x800) || (n == 4 && (c < 0x10000 || c > 0x10ffff)) || (c >= 0xd800 && c <= 0xdfff))
        return -1;
    *len = n;
    return c;
}

/* shown as nothing, or turning the text around it */
static int hidden(long c)
{
    return c < 0x20 || (c >= 0x7f && c <= 0x9f) || c == 0x61c || (c >= 0x200b && c <= 0x200f)
        || (c >= 0x202a && c <= 0x202e) || (c >= 0x2060 && c <= 0x2069) || c == 0xfeff;
}

int npf_text_display(char *s, size_t max)
{
    unsigned char *r = (unsigned char *)s, *w = r;
    size_t n;
    int len, full = 0;
    while (*r) {
        long c = utf8_at(r, &len);
        if (c < 0) {
            s[0] = 0;
            return -1;
        }
        if (!hidden(c) && (w > (unsigned char *)s || c != ' ') && !full) {
            if ((size_t)(w - (unsigned char *)s) + (size_t)len > max)
                full = 1;                   /* cut at a character; the rest still checked */
            else {
                memmove(w, r, (size_t)len);
                w += len;
            }
        }
        r += len;
    }
    *w = 0;
    n = strlen(s);
    while (n && s[n - 1] == ' ')
        s[--n] = 0;
    return (int)n;
}

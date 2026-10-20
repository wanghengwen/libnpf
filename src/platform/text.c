#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* Scale decimal digits directly to whole seconds. No libc floating scanner,
 * and no binary rounding of e.g. 1.15h to just below an integer second. */
static int64_t duration(const char *s, int64_t now)
{
    const char *begin, *end, *p;
    size_t digits = 0, whole_digits = 0, i;
    int dot = 0, nonzero = 0, exp = 0;
    int64_t split;
    uint64_t unit, whole = 0, frac = 0, limit;
    s = space(s);
    if (*s == '+') s++;
    begin = s;
    for (; *s; s++) {
        if (*s == '.' && !dot) {
            dot = 1;
        } else if (*s >= '0' && *s <= '9') {
            digits++;
            if (!dot) whole_digits++;
            nonzero |= *s != '0';
        } else {
            break;
        }
    }
    end = s;
    if (!nonzero || digits > INT_MAX || now < 0)
        return -1;
    if (*s == 'e' || *s == 'E') {
        s++;
        if (isspace((unsigned char)*s) || npf_text_int(&s, &exp) < 0)
            return -1;
    }
    unit = *s == 's' ? 1 : *s == 'm' ? 60 : *s == 'h' ? 3600 : *s == 'd' ? 86400 : *s == 'w' ? 604800 : 0;
    if (!unit || s[1])
        return -1;
    split = (int64_t)whole_digits + exp;
    limit = ((uint64_t)INT64_MAX - (uint64_t)now) / unit;
    /* Digits before the (possibly exponent-shifted) decimal point. */
    for (p = begin, i = 0; (int64_t)i < split; i++) {
        unsigned d = 0;
        if (p < end && *p == '.') p++;
        if (p < end) d = (unsigned)(*p++ - '0');
        if (whole > limit / 10 || (whole == limit / 10 && d > limit % 10))
            return -1;
        whole = whole * 10 + d;
    }
    /* Reverse accumulation keeps every intermediate below 10 * unit. */
    for (p = end, i = digits; p > begin && (int64_t)i > split;) {
        unsigned char c = (unsigned char)*--p;
        if (c == '.') continue;
        frac = (frac + (uint64_t)(c - '0') * unit) / 10;
        i--;
    }
    while (split < 0 && frac) { frac /= 10; split++; }
    whole = whole * unit + frac;
    if (whole > (uint64_t)INT64_MAX - (uint64_t)now)
        return -1;
    return now + (int64_t)whole;
}

int64_t npf_text_expiry(const char *s, int64_t now)
{
    const char *p = s;
    int y, mo, d, h, mi;
    struct tm tm;
    time_t t;
    int64_t relative;
    if (strcmp(s, "never") == 0)
        return 0;
    relative = duration(s, now);
    if (relative >= 0)
        return relative;
    if (npf_text_int(&p, &y) < 0 || *p++ != '-' || npf_text_int(&p, &mo) < 0 || *p++ != '-'
        || npf_text_int(&p, &d) < 0 || (*p != ' ' && *p != 'T'))
        return -1;
    do { p++; } while (*p == ' ' || *p == 'T');
    if (npf_text_int(&p, &h) < 0 || *p++ != ':' || npf_text_int(&p, &mi) < 0 || *p
        || y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59)
        return -1;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_isdst = -1;
    t = mktime(&tm);
    return t == (time_t)-1 ? -1 : (int64_t)t;
}

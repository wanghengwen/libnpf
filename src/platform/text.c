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

int npf_hostport(const char *s, char *host, size_t cap, uint16_t *port)
{
    const char *h = s, *colon;
    long p = 0;
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
    if (!n || n >= cap || (colon[1] == '0' && colon[2]))
        return -1;
    for (s = colon + 1; *s >= '0' && *s <= '9' && p <= 65535; s++)
        p = p * 10 + *s - '0';
    if (s == colon + 1 || *s || p > 65535)
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

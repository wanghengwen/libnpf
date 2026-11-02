/* Small strict parsers of numbers, words, host:port and MAC addresses.
 * Internal to libnpf; in include/npf because npf's app, modules and tools
 * parse their command lines and files with them. */
#ifndef NPF_TEXT_H
#define NPF_TEXT_H

#include <stddef.h>
#include <stdint.h>

/* Read a white-space separated word (it must fit in cap with its NUL), a
 * decimal int or a hex unsigned long (no minus) at *p, after any white
 * space. 0 with *p past it, or -1 with *p unchanged. npf_text_mac: s whole
 * as "aa:bb:cc:dd:ee:ff" into out, 0 or -1. */
int npf_text_word(const char **p, char *out, size_t cap);
int npf_text_int(const char **p, int *out);
int npf_text_hex(const char **p, unsigned long *out);
int npf_text_mac(const char *s, unsigned char out[6]);
/* A hex digit's value, -1 for anything else. */
static inline int npf_hexval(int c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* 1 when s has no control characters (bytes below 0x20, 0x7f), else 0.
 * It does not check UTF-8. */
static inline int npf_text_plain(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return 0;
    return 1;
}

/* Makes s, text from elsewhere to be shown to people (a peer's name), safe
 * to show, in place: no control characters (C0, DEL, C1), no direction or
 * invisible format characters (U+061C, U+200B..U+200F, U+202A..U+202E,
 * U+2060..U+2069, U+FEFF), no white space at either end, at most max bytes
 * (cut at a character). Its length, or -1 when s is not UTF-8 (s is then
 * ""). */
int npf_text_display(char *s, size_t max);

/* s whole as a decimal number in lo..hi (hi < LONG_MAX / 10): digits only,
 * no sign, no leading zero. 0 with *out set, or -1. */
int npf_text_dec(const char *s, long lo, long hi, long *out);

/* Splits "HOST:PORT" (at the last colon) or "[IPV6]:PORT": the host, not
 * empty and without brackets, into host of cap bytes; the port as for
 * npf_text_dec, 0..65535. 0 or -1. */
int npf_hostport(const char *s, char *host, size_t cap, uint16_t *port);

/* The status code (100..999) of an HTTP/1.x status line, or -1. */
int npf_http_status(const char *s);

/* An HTTP Host value (":PORT" and IPv6 brackets allowed) that only this
 * host's own pages use: an IP address, "localhost" or a name under
 * ".localhost", in either case. 1, else 0. Local web servers refuse other
 * names (DNS rebinding: a site's own name resolved to 127.0.0.1). */
int npf_http_host_local(const char *v);

/* s begins with p, ASCII letters in either case: 1, else 0 */
int npf_prefix_nocase(const char *s, const char *p);

#endif

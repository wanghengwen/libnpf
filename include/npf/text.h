/* Small parsers for the fixed text formats used by npf. */
#ifndef NPF_TEXT_H
#define NPF_TEXT_H

#include <stddef.h>
#include <stdint.h>

/* Read a whitespace-separated word, a decimal int, or a hex unsigned long.
 * On success return 0 and advance *p; on failure return -1 without advancing.
 * Words must fit including the terminator. Integers must fit their type. */
int npf_text_word(const char **p, char *out, size_t cap);
int npf_text_int(const char **p, int *out);
int npf_text_hex(const char **p, unsigned long *out);
int npf_text_mac(const char *s, unsigned char out[6]);
/* a hex digit's value, -1 for anything else */
static inline int npf_hexval(int c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* "HOST:PORT" or "[IPV6]:PORT": the host (brackets off, not empty) into
 * host, the port (digits, no leading zero, 0..65535); 0 or -1 */
int npf_hostport(const char *s, char *host, size_t cap, uint16_t *port);

/* HTTP/1.x response status (three digits), or -1. s is NUL-terminated. */
int npf_http_status(const char *s);

#endif

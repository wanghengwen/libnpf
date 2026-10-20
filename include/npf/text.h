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

/* HTTP/1.x response status (three digits), or -1. s is NUL-terminated. */
int npf_http_status(const char *s);

/* Mapping expiry: never, positive decimal duration (s/m/h/d/w, fractions
 * and decimal exponents allowed), or local YYYY-MM-DD HH:MM (also T).
 * Sub-second durations truncate toward zero. -1 on invalid/overflow. */
int64_t npf_text_expiry(const char *s, int64_t now);

#endif

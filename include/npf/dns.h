/* DNS messages for DoH (RFC 8484): the server list's seed in TXT records
 * (security.md 7.5). Only what that needs: a TXT query, the TXT answers. */
#ifndef NPF_DNS_H
#define NPF_DNS_H

#include <stddef.h>
#include <stdint.h>

/* a query for name's TXT records; returns its length or -1 */
int npf_dns_txt_query(const char *name, uint16_t id, uint8_t *out, size_t cap);

/* calls fn for each TXT answer of a response, its character strings joined
 * (a record longer than 255 bytes is split into several strings); returns
 * the number of TXT answers or -1 when the message is malformed */
typedef void (*npf_dns_txt_fn)(const uint8_t *txt, size_t len, void *arg);
int npf_dns_txt_answers(const uint8_t *msg, size_t len, npf_dns_txt_fn fn, void *arg);

#endif

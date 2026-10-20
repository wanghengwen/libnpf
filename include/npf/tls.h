/* TLS 1.3 client session over a non-blocking socket (mbedTLS 3.6, security.md 12.2).
 * The server certificate is not verified (D5). Built only with NPF_WITH_TLS. */
#ifndef NPF_TLS_H
#define NPF_TLS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct npf_tls npf_tls;

#define NPF_TLS_WANT_READ  -2
#define NPF_TLS_WANT_WRITE -3

/* returns NULL when TLS support is not compiled in */
npf_tls *npf_tls_new(int fd, const char *sni);
void     npf_tls_free(npf_tls *t);
/* 0 done, NPF_TLS_WANT_*, or -1 */
int      npf_tls_handshake(npf_tls *t);
/* >0 bytes, 0 EOF, NPF_TLS_WANT_*, or -1 */
ssize_t  npf_tls_read(npf_tls *t, void *buf, size_t n);
ssize_t  npf_tls_write(npf_tls *t, const void *buf, size_t n);
int      npf_tls_available(void);

#endif

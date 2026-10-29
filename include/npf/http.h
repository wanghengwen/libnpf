/* A minimal asynchronous HTTP(S) GET on an event loop, for content whose
 * integrity the caller checks itself: the signed server list's channels
 * (security.md 7.5), the upgrade module's package (hash in a signed
 * manifest), npf-fetch. The server's certificate is NOT checked (D5).
 * Internal to libnpf; in include/npf for npf's upgrade module and tools.
 * One request per connection (HTTP/1.1, "Connection: close"), identity or
 * chunked bodies, one deadline for the whole request. */
#ifndef NPF_HTTP_H
#define NPF_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "npf/loop.h"
#include "npf/sys.h"

typedef struct npf_http npf_http;

/* The result: status is the HTTP status (any, not only 2xx) with the
 * decoded body, or -1 with err. body and err are valid during the call. */
typedef void (*npf_http_fn)(int status, const uint8_t *body, size_t len, const char *err, void *arg);

/* GETs url (https:// or http://) on the loop's thread. addr: connect there
 * instead of resolving the URL's host (which still goes into Host and SNI);
 * accept: the Accept header, NULL for any; max: the largest body taken,
 * more is an error; timeout_ms <= 0: 15 s. fn runs once, later, on the
 * loop's thread, unless the request is cancelled; the handle is freed when
 * fn returns. NULL when the request cannot start (fn never runs). */
npf_http *npf_http_get(npf_loop *loop, const char *url, const struct sockaddr_storage *addr, const char *accept,
                       size_t max, int timeout_ms, npf_http_fn fn, void *arg);
/* Drops a request whose fn has not run: fn never runs. NULL, or a call
 * from within fn, does nothing. */
void npf_http_cancel(npf_http *h);

#endif

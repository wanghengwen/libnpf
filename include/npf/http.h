/* A minimal asynchronous HTTP(S) GET on the event loop: the server list's
 * external channels (security.md 7.5: DoH TXT queries and static files).
 * The content is signed, so the server's certificate is not checked (D5),
 * as for the signaling. One request per connection, HTTP/1.1 with
 * "Connection: close", identity or chunked bodies, a deadline for the whole
 * request. */
#ifndef NPF_HTTP_H
#define NPF_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "npf/loop.h"
#include "npf/sys.h"

typedef struct npf_http npf_http;

/* status: the HTTP status, or -1 with err; body: the decoded body (status
 * 2xx and others alike), valid during the call */
typedef void (*npf_http_fn)(int status, const uint8_t *body, size_t len, const char *err, void *arg);

/* GET url (https:// or http://). addr: connect there instead of resolving
 * the URL's host (DoH servers are reached by IP; the URL's host still goes
 * into Host and SNI); accept: the Accept header or NULL; max: the largest
 * body taken (larger: an error). fn runs exactly once unless cancelled.
 * NULL when the request cannot start. */
npf_http *npf_http_get(npf_loop *loop, const char *url, const struct sockaddr_storage *addr, const char *accept,
                       size_t max, int timeout_ms, npf_http_fn fn, void *arg);
/* drop a request: fn does not run */
void npf_http_cancel(npf_http *h);

#endif

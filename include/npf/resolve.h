/* Name resolution off the loop thread: getaddrinfo runs in a small pool of
 * worker threads and the result comes back through npf_loop_post. A slow or
 * dead DNS server then stalls one sublink instead of every session on the
 * node. The pool is bounded (RESOLVE_WORKERS threads, RESOLVE_CAPACITY
 * requests queued or running, cancelled ones included until their worker is
 * done); a loop may be freed while lookups for it are still running.
 * Lookups a peer asks for (a sublink's or a UDP flow's target) take at most
 * RESOLVE_PEER_WORKERS threads and RESOLVE_PEER_CAPACITY requests: whatever
 * peers send, the node's own (its signaling, HTTP) always find a thread and
 * room. */
#ifndef NPF_RESOLVE_H
#define NPF_RESOLVE_H

#include <stdint.h>
#include "npf/sys.h"
#ifndef _WIN32
#include <netdb.h>                  /* struct addrinfo */
#endif
#include "npf/loop.h"

#define NPF_RESOLVE_MAX 8
#define RESOLVE_WORKERS  4
#define RESOLVE_CAPACITY 64
#define RESOLVE_PEER_WORKERS  (RESOLVE_WORKERS - 1)
#define RESOLVE_PEER_CAPACITY (RESOLVE_CAPACITY / 2)

typedef struct npf_resolve npf_resolve;

/* err: 0 with n >= 1 addresses (port filled in), or a getaddrinfo error code */
typedef void (*npf_resolve_fn)(npf_resolve *r, int err, const struct sockaddr_storage *addrs, const socklen_t *lens,
                               int n, void *arg);

/* resolve host for socktype (SOCK_STREAM / SOCK_DGRAM); fn runs on the loop
 * thread later, exactly once unless cancelled or the loop is freed first.
 * NULL on failure, also when the pool is full. */
npf_resolve *npf_resolve_start(npf_loop *loop, const char *host, uint16_t port, int socktype, npf_resolve_fn fn,
                               void *arg);
/* the same for a name a peer asked for (the peers' share of the pool) */
npf_resolve *npf_resolve_start_peer(npf_loop *loop, const char *host, uint16_t port, int socktype, npf_resolve_fn fn,
                                    void *arg);
/* the callback will not run; the request frees itself when the worker is
 * done (it counts against the pool until then). Not after the callback ran. */
void npf_resolve_cancel(npf_resolve *r);

/* requests queued or running (tests, status); the peers' of them */
int npf_resolve_active(void);
int npf_resolve_active_peer(void);

/* tests: the lookup function the workers call (getaddrinfo) */
typedef int (*npf_resolve_gai_fn)(const char *node, const char *service, const struct addrinfo *hints,
                                  struct addrinfo **res);
extern npf_resolve_gai_fn npf_resolve_gai;

#endif

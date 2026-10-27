/* The TCP connection, with TLS or without, of a WebSocket (ws.c, where it
 * is) and of an HTTP request (http.c): every address of the host in turn
 * (one second each, the last five), then the TLS handshake. */
#ifndef NPF_TCP_H
#define NPF_TCP_H

#include "npf/sys.h"
#include "npf/loop.h"
#include "npf/resolve.h"
#include "npf/tls.h"

typedef struct npf_tcp {
    npf_loop    *loop;
    const char  *host;              /* the owner's: looked up, and the SNI */
    int          port, use_tls, outside_vpn;    /* the owner sets them before npf_tcp_start */
    npf_io_fn    io;                /* the socket's from the start, with arg */
    void       (*fail)(void *arg, const char *why);    /* the last thing done: the owner may go */
    void        *arg;
    int          fd, state;
    npf_tls     *tls;
    npf_resolve *resolve;
    npf_timer   *t;
    struct sockaddr_storage cand[NPF_RESOLVE_MAX];
    socklen_t    cand_len[NPF_RESOLVE_MAX];
    int          ncand, icand;
} npf_tcp;

void    npf_tcp_init(npf_tcp *c, npf_loop *loop, const char *host, npf_io_fn io,
                     void (*fail)(void *arg, const char *why), void *arg);
/* connect to addr, or to the host's addresses (NULL; a literal address
 * without a lookup): 0, or -1 (fail is not called) */
int     npf_tcp_start(npf_tcp *c, const struct sockaddr_storage *addr);
/* in io until it is connected: 1 connected (TLS done), 0 not yet, -1 failed
 * (fail called) */
int     npf_tcp_step(npf_tcp *c, unsigned events);
/* >0 bytes, 0 EOF (read), NPF_TLS_WANT_*, or -1 */
ssize_t npf_tcp_read(npf_tcp *c, void *p, size_t n);
ssize_t npf_tcp_write(npf_tcp *c, const void *p, size_t n);
void    npf_tcp_close(npf_tcp *c);

#endif

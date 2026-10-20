/* OpenSSL TLS backend. SSL objects belong to a single instance's thread;
 * OpenSSL 3 handles its shared state without a libnpf-wide serialization lock. */
#include "npf/sys.h"
#include "npf/tls.h"
#include <stdlib.h>
#include <limits.h>

#ifdef NPF_WITH_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

struct npf_tls {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO_METHOD *method;
    size_t retry_len;
};

/* A socket BIO using MSG_NOSIGNAL: the library must not change the host
 * application's SIGPIPE disposition. The socket remains owned by ws/http. */
static int bio_create(BIO *b) { BIO_set_init(b, 1); return 1; }
static int bio_destroy(BIO *b) { (void)b; return 1; }
static long bio_ctrl(BIO *b, int cmd, long n, void *p)
{
    (void)b; (void)n; (void)p;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}
static int bio_read(BIO *b, char *buf, int len)
{
    npf_tls *t = BIO_get_data(b);
    int r;
    BIO_clear_retry_flags(b);
    r = (int)recv(t->fd, buf, (size_t)len, 0);
    if (r < 0 && npf_sock_again())
        BIO_set_retry_read(b);
    return r;
}
static int bio_write(BIO *b, const char *buf, int len)
{
    npf_tls *t = BIO_get_data(b);
    int r;
    BIO_clear_retry_flags(b);
    r = (int)send(t->fd, buf, (size_t)len, MSG_NOSIGNAL);
    if (r < 0 && npf_sock_again())
        BIO_set_retry_write(b);
    return r;
}

int npf_tls_available(void) { return 1; }

void npf_tls_free(npf_tls *t)
{
    if (!t) return;
    SSL_free(t->ssl);
    SSL_CTX_free(t->ctx);
    BIO_meth_free(t->method);
    free(t);
}

npf_tls *npf_tls_new(int fd, const char *sni)
{
    npf_tls *t = calloc(1, sizeof *t);
    BIO *bio;
    if (!t) return NULL;
    t->fd = fd;
    ERR_clear_error();
    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx || !SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION))
        goto fail;
    /* Same trust model as mbedTLS: Noise / signed content authenticates the
     * server; TLS is camouflage (security.md D5). */
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_RENEGOTIATION);
    t->ssl = SSL_new(t->ctx);
    t->method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "npf nonblocking socket");
    if (!t->ssl || !t->method || !BIO_meth_set_create(t->method, bio_create)
        || !BIO_meth_set_destroy(t->method, bio_destroy) || !BIO_meth_set_ctrl(t->method, bio_ctrl)
        || !BIO_meth_set_read(t->method, bio_read) || !BIO_meth_set_write(t->method, bio_write))
        goto fail;
    if (sni && !SSL_set_tlsext_host_name(t->ssl, sni))
        goto fail;
    bio = BIO_new(t->method);
    if (!bio) goto fail;
    BIO_set_data(bio, t);
    SSL_set_bio(t->ssl, bio, bio);
    SSL_set_connect_state(t->ssl);
    SSL_set_mode(t->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
    return t;
fail:
    npf_tls_free(t);
    return NULL;
}

static int result(npf_tls *t, int r)
{
    switch (SSL_get_error(t->ssl, r)) {
    case SSL_ERROR_WANT_READ: return NPF_TLS_WANT_READ;
    case SSL_ERROR_WANT_WRITE: return NPF_TLS_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN: return 0;
    default: return -1;
    }
}

int npf_tls_handshake(npf_tls *t)
{
    int r;
    ERR_clear_error();
    r = SSL_do_handshake(t->ssl);
    if (r == 1) return 0;
    r = result(t, r);
    return r == 0 ? -1 : r;
}

ssize_t npf_tls_read(npf_tls *t, void *buf, size_t n)
{
    int r;
    size_t got = 0;
    ERR_clear_error();
    r = SSL_read_ex(t->ssl, buf, n, &got);
    return r == 1 ? (ssize_t)got : result(t, r);
}

ssize_t npf_tls_write(npf_tls *t, const void *buf, size_t n)
{
    int r;
    size_t sent = 0;
    if (t->retry_len) {
        if (n < t->retry_len) return -1;
        n = t->retry_len;   /* a growing WS buffer keeps the pending prefix */
    }
    ERR_clear_error();
    r = SSL_write_ex(t->ssl, buf, n, &sent);
    if (r == 1) {
        t->retry_len = 0;
        return (ssize_t)sent;
    }
    r = result(t, r);
    t->retry_len = r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE ? n : 0;
    return r;
}

#else
int npf_tls_available(void) { return 0; }
npf_tls *npf_tls_new(int fd, const char *sni) { (void)fd; (void)sni; return NULL; }
void npf_tls_free(npf_tls *t) { (void)t; }
int npf_tls_handshake(npf_tls *t) { (void)t; return -1; }
ssize_t npf_tls_read(npf_tls *t, void *b, size_t n) { (void)t; (void)b; (void)n; return -1; }
ssize_t npf_tls_write(npf_tls *t, const void *b, size_t n) { (void)t; (void)b; (void)n; return -1; }
#endif

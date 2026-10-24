#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "npf/sys.h"

#include "npf/platform.h"
#include "npf/tls.h"

#ifdef NPF_WITH_TLS

#include "mbedtls/ssl.h"
#include "psa/crypto.h"

struct npf_tls {
    int                fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
    size_t              retry_len;      /* a write that wants again: its length */
};

/* mbedTLS is built without MBEDTLS_THREADING_C and its PSA key store is
 * process-wide: libnpf instances on their own threads take turns. TLS here
 * carries only the signaling and the WS relay. */
#ifdef _WIN32
#include <windows.h>
static SRWLOCK g_tls_lock = SRWLOCK_INIT;
#define TLS_LOCK()   AcquireSRWLockExclusive(&g_tls_lock)
#define TLS_UNLOCK() ReleaseSRWLockExclusive(&g_tls_lock)
#else
#include <pthread.h>
static pthread_mutex_t g_tls_lock = PTHREAD_MUTEX_INITIALIZER;
#define TLS_LOCK()   pthread_mutex_lock(&g_tls_lock)
#define TLS_UNLOCK() pthread_mutex_unlock(&g_tls_lock)
#endif
static int g_psa_ready;                 /* under the lock */

static int rng(void *p, unsigned char *out, size_t n)
{
    (void)p;
    npf_random(out, n);
    return 0;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    npf_tls *t = ctx;
    ssize_t r = send(t->fd, buf, len, MSG_NOSIGNAL);
    if (r < 0)
        return npf_sock_again() ? MBEDTLS_ERR_SSL_WANT_WRITE : -1;
    return (int)r;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    npf_tls *t = ctx;
    ssize_t r = recv(t->fd, buf, len, 0);
    if (r < 0)
        return npf_sock_again() ? MBEDTLS_ERR_SSL_WANT_READ : -1;
    return (int)r;
}

int npf_tls_available(void)
{
    return 1;
}

static void tls_free_locked(npf_tls *t);

static npf_tls *tls_new_locked(int fd, const char *sni)
{
    npf_tls *t;
    if (!g_psa_ready) {
        if (psa_crypto_init() != PSA_SUCCESS)
            return NULL;
        g_psa_ready = 1;
    }
    t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->fd = fd;
    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    if (mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT))
        goto fail;
    /* TLS is camouflage only; the Noise handshake inside authenticates the server (D5) */
    mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&t->conf, rng, NULL);
    if (mbedtls_ssl_setup(&t->ssl, &t->conf))
        goto fail;
    if (sni && mbedtls_ssl_set_hostname(&t->ssl, sni))
        goto fail;
    mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
    return t;
fail:
    tls_free_locked(t);
    return NULL;
}

npf_tls *npf_tls_new(int fd, const char *sni)
{
    npf_tls *t;
    TLS_LOCK();
    t = tls_new_locked(fd, sni);
    TLS_UNLOCK();
    return t;
}

static void tls_free_locked(npf_tls *t)
{
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    free(t);
}

void npf_tls_free(npf_tls *t)
{
    if (!t)
        return;
    TLS_LOCK();
    tls_free_locked(t);
    TLS_UNLOCK();
}

static int map(int r)
{
    if (r == MBEDTLS_ERR_SSL_WANT_READ)
        return NPF_TLS_WANT_READ;
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE)
        return NPF_TLS_WANT_WRITE;
    return -1;
}

int npf_tls_handshake(npf_tls *t)
{
    int r;
    TLS_LOCK();
    r = mbedtls_ssl_handshake(&t->ssl);
    TLS_UNLOCK();
    return r == 0 ? 0 : map(r);
}

ssize_t npf_tls_read(npf_tls *t, void *buf, size_t n)
{
    int r;
    TLS_LOCK();
    do {    /* TLS 1.3 session tickets arrive after the handshake; just read again */
        r = mbedtls_ssl_read(&t->ssl, buf, n);
    } while (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET);
    TLS_UNLOCK();
    if (r >= 0)
        return r;
    if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    return map(r);
}

ssize_t npf_tls_write(npf_tls *t, const void *buf, size_t n)
{
    int r;
    /* mbedTLS expects the same data again after WANT_*, and then returns
     * the length it is given although it sends only the record it kept: a
     * WS buffer that grew in between would lose the bytes after it */
    if (t->retry_len) {
        if (n < t->retry_len)
            return -1;
        n = t->retry_len;
    }
    TLS_LOCK();
    r = mbedtls_ssl_write(&t->ssl, buf, n);
    TLS_UNLOCK();
    if (r >= 0) {
        t->retry_len = 0;
        return r;
    }
    r = map(r);
    t->retry_len = r == NPF_TLS_WANT_READ || r == NPF_TLS_WANT_WRITE ? n : 0;
    return r;
}

#else

int npf_tls_available(void) { return 0; }
npf_tls *npf_tls_new(int fd, const char *sni) { (void)fd; (void)sni; return NULL; }
void npf_tls_free(npf_tls *t) { (void)t; }
int npf_tls_handshake(npf_tls *t) { (void)t; return -1; }
ssize_t npf_tls_read(npf_tls *t, void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }
ssize_t npf_tls_write(npf_tls *t, const void *buf, size_t n) { (void)t; (void)buf; (void)n; return -1; }

#endif

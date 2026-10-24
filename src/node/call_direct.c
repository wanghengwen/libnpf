/* Calls: direct connections, no platform (NNpsk0 handshake, listener) */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "call_internal.h"

/* ---- direct connections ----
 *
 *   initiator -> listener   NNpsk0 message 1: e, payload = ts_ms(8) | random padding
 *   listener  -> initiator  NNpsk0 message 2: e, ee, payload = padding (never longer than message 1)
 *
 * Both are sent as they are: no plaintext type, the listener tells them from
 * AnLiu datagrams by trying the sessions' keys first. Message 1 is accepted
 * only with the right psk, a timestamp within 60 s and an ephemeral key not
 * seen in the last 2 minutes; a retransmitted message 1 (the same bytes from
 * the same source) gets the same message 2 again and creates no second
 * session. */

#define DIRECT_PROLOGUE   "npf-direct-v1"
#define DIRECT_TS_WINDOW  60000
#define DIRECT_SEEN       128
#define DIRECT_SEEN_MS    120000
#define DIRECT_MAX_SESS   64
#define DIRECT_IP_RATE    5         /* handshakes per second per source (burst 10; a new one 2) */

struct npf_direct {
    npf_node   *n;
    int         fd;
    uint8_t     psk[32];
    struct npf_policy *policy;
    struct {
        uint8_t  e[32];
        uint8_t  h1[32];            /* the whole message 1's hash: only that one again is a retransmission */
        int64_t  at;
        struct sockaddr_storage from;
        uint8_t  msg2[256];
        size_t   msg2_len;
    } seen[DIRECT_SEEN];
    int         nseen_next;
    struct { uint64_t src; double tokens; int64_t last; } rate[64];   /* src 0: free */
};

static npf_call *direct_call(npf_node *n, int caller, int fd, const struct sockaddr_storage *peer)
{
    npf_call *c = call_new(n, caller);
    if (!c)
        return NULL;
    c->direct = 1;
    c->auth = AUTH_DIRECT;
    npf_random(c->call_id, 16);
    call_b64_of(c->call_id, 16, c->call_id_s);
    c->p2p_fd = fd;
    c->p2p_addr = *peer;
    c->p2p_rx_ms = c->p2p_since = npf_mono_ms();
    return c;
}

/* keys from the handshake, then the same transport as a call */
static int direct_up(npf_call *c)
{
    uint8_t k1[32], k2[32];
    if (npf_noise_split(&c->hs->noise, NULL, NULL, k1, k2, NULL) < 0)
        return -1;
    memcpy(c->k12, k1, 32);
    memcpy(c->k12 + 32, k2, 32);
    npf_wipe(k1, 32);
    npf_wipe(k2, 32);
    c->p2p = 1;
    if (call_start_transport(c) < 0)
        return -1;
    call_set_state(c, NPF_CALL_CONNECTING, NULL);
    return 0;
}

/* initiator */

static void direct_retry(npf_loop *loop, void *arg)
{
    npf_call *c = arg;
    (void)loop;
    c->t_direct = NULL;
    if (c->keys_ready || c->ended)
        return;
    if (++c->dtries > 8) {
        char a[64];
        npf_logw("direct %s: no answer from %s (wrong key, or the port is not reachable)", c->call_id_s,
                npf_addr_str(&c->p2p_addr, a, sizeof a));
        npf_call_end(c, "timeout");
        return;
    }
    call_udp_send(c, c->p2p_fd, &c->p2p_addr, c->hs->dmsg1, c->hs->dmsg1_len);
    c->t_direct = npf_timer_add(c->n->loop, c->dtries < 3 ? 300LL << c->dtries : 2000, direct_retry, c);   /* ~14 s in all */
}

npf_call *npf_direct_connect(npf_node *n, const struct sockaddr_storage *to, const uint8_t psk[32])
{
    uint8_t pay[8 + 64];
    size_t pl = 8 + npf_rand_range(0, 64);
    int len;
    char a[64];
    npf_call *c = direct_call(n, 1, n->udp_fd, to);
    if (!c)
        return NULL;
    if (npf_noise_init(&c->hs->noise, NPF_NOISE_NNPSK0, 1, DIRECT_PROLOGUE, strlen(DIRECT_PROLOGUE), NULL, NULL, psk) < 0) {
        call_free(c);
        return NULL;
    }
    npf_le64(pay, (uint64_t)npf_unix_ms());
    npf_random(pay + 8, pl - 8);
    len = npf_noise_write(&c->hs->noise, pay, pl, c->hs->dmsg1, sizeof c->hs->dmsg1);
    if (len < 0) {
        call_free(c);
        return NULL;
    }
    c->hs->dmsg1_len = (size_t)len;
    c->state = NPF_CALL_CALLING;
    call_udp_send(c, c->p2p_fd, &c->p2p_addr, c->hs->dmsg1, c->hs->dmsg1_len);
    c->t_direct = npf_timer_add(n->loop, 300, direct_retry, c);
    npf_log("direct %s: connecting to %s", c->call_id_s, npf_addr_str(to, a, sizeof a));
    return c;
}

/* message 2 from the listener; returns 1 if consumed */
int call_direct_reply(npf_call *c, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    uint8_t p[256];
    npf_noise_hs hs = c->hs->noise;               /* a failed read spoils the state: keep ours for the real one */
    (void)from;
    /* message 2 is e (32) and the sealed payload (16 and more), no longer
     * than message 1 (no amplification): anything else is no attempt at it.
     * Each attempt costs an X25519 before the tag says no; a sender spoofing
     * the listener's address gets 64 of them per session */
    if (len < 48 || len > c->hs->dmsg1_len || len > 256 || ++c->direct_tries > 64) {
        npf_wipe(&hs, sizeof hs);
        return 0;
    }
    if (npf_noise_read(&hs, buf, len, p, sizeof p) < 0) {
        npf_wipe(&hs, sizeof hs);
        return 0;
    }
    c->hs->noise = hs;
    npf_wipe(&hs, sizeof hs);
    if (c->t_direct) {
        npf_timer_cancel(c->n->loop, c->t_direct);
        c->t_direct = NULL;
    }
    if (direct_up(c) < 0) {
        npf_call_end(c, "error");
        return 1;
    }
    npf_logd("direct %s: handshake done", c->call_id_s);
    return 1;
}

/* listener */

/* a source of handshakes: an IPv4 address, an IPv6 /64 (one host has many
 * addresses there); never 0 */
static uint64_t direct_src(const struct sockaddr_storage *from)
{
    uint64_t k = 0;
    if (from->ss_family == AF_INET)
        k = 0x100000000ULL | npf_rd32((const uint8_t *)&((const struct sockaddr_in *)from)->sin_addr);
    else if (from->ss_family == AF_INET6)
        k = npf_rd64(((const struct sockaddr_in6 *)from)->sin6_addr.s6_addr) | 1;
    return k ? k : 1;
}

/* DIRECT_IP_RATE handshakes a second for each source, a burst of twice that.
 * A source not in the table takes the place of the one unused the longest,
 * with only a little to spend: changing sources buys no fresh bursts (the
 * table was by the address's first byte, a new one got a full burst) */
static int direct_rate_ok(npf_direct *d, const struct sockaddr_storage *from)
{
    uint64_t src = direct_src(from);
    int64_t now = npf_mono_ms();
    int i, slot = -1, old = 0;
    for (i = 0; i < 64; i++) {
        if (d->rate[i].src == src) {
            slot = i;
            break;
        }
        if (!d->rate[i].src) {              /* a free one before any used one */
            if (d->rate[old].src)
                old = i;
        } else if (d->rate[old].src && d->rate[i].last < d->rate[old].last) {
            old = i;
        }
    }
    if (slot < 0) {
        slot = old;
        d->rate[slot].src = src;
        d->rate[slot].tokens = 2;           /* a handshake and a retry */
        d->rate[slot].last = now;
    }
    d->rate[slot].tokens += (double)(now - d->rate[slot].last) * DIRECT_IP_RATE / 1000.0;
    if (d->rate[slot].tokens > 2 * DIRECT_IP_RATE)
        d->rate[slot].tokens = 2 * DIRECT_IP_RATE;
    d->rate[slot].last = now;
    if (d->rate[slot].tokens < 1)
        return 0;
    d->rate[slot].tokens -= 1;
    return 1;
}

static void direct_hello(npf_direct *d, const uint8_t *buf, size_t len, const struct sockaddr_storage *from)
{
    npf_node *n = d->n;
    npf_noise_hs hs;
    uint8_t p[256], m2[256], pad[256], h1[32];
    int pl, ml, i, sessions = 0;
    int64_t now = npf_mono_ms(), ts;
    npf_call *c;
    if (len < 32 + 8 + 16 || len > 256)
        return;
    /* a retransmitted message 1 (the same message from the same source): the
     * same answer; anything else with a seen ephemeral key: a replay */
    for (i = 0; i < DIRECT_SEEN; i++)
        if (d->seen[i].at && now - d->seen[i].at < DIRECT_SEEN_MS && memcmp(d->seen[i].e, buf, 32) == 0) {
            npf_kdf(h1, NULL, 0, buf, len);     /* only then: not for every datagram of a flood */
            if (call_same_addr(&d->seen[i].from, from) && d->seen[i].msg2_len
                && memcmp(d->seen[i].h1, h1, sizeof h1) == 0)
                (void)npf_udp_send(d->fd, d->seen[i].msg2, d->seen[i].msg2_len, from);
            return;
        }
    if (!direct_rate_ok(d, from))
        return;
    for (c = n->calls; c; c = c->next)
        if (c->direct && !c->caller && !c->ended)
            sessions++;
    if (sessions >= DIRECT_MAX_SESS)
        return;
    /* the handshake state holds what the psk gave: wiped on every way out */
    if (npf_noise_init(&hs, NPF_NOISE_NNPSK0, 0, DIRECT_PROLOGUE, strlen(DIRECT_PROLOGUE), NULL, NULL, d->psk) < 0)
        goto out;
    pl = npf_noise_read(&hs, buf, len, p, sizeof p);
    if (pl < 8)
        goto out;                           /* wrong key or garbage: silent */
    ts = (int64_t)npf_rd64(p);
    if (ts < npf_unix_ms() - DIRECT_TS_WINDOW || ts > npf_unix_ms() + DIRECT_TS_WINDOW) {
        npf_logw("direct: handshake with a stale timestamp ignored (clock skew or replay)");
        goto out;
    }
    {
        size_t padlen = npf_rand_range(0, len - 48 < sizeof pad ? len - 48 : sizeof pad);
        npf_random(pad, padlen);
        ml = npf_noise_write(&hs, pad, padlen, m2, sizeof m2);
    }
    if (ml < 0)
        goto out;
    npf_kdf(h1, NULL, 0, buf, len);
    i = d->nseen_next++ % DIRECT_SEEN;
    memcpy(d->seen[i].e, buf, 32);
    memcpy(d->seen[i].h1, h1, sizeof h1);
    d->seen[i].at = now;
    d->seen[i].from = *from;
    memcpy(d->seen[i].msg2, m2, (size_t)ml);
    d->seen[i].msg2_len = (size_t)ml;
    c = direct_call(n, 0, d->fd, from);
    if (!c)
        goto out;
    c->policy = d->policy;
    c->hs->noise = hs;
    npf_wipe(&hs, sizeof hs);
    (void)npf_udp_send(d->fd, m2, (size_t)ml, from);
    if (direct_up(c) < 0) {
        npf_call_end(c, "error");
        return;
    }
    {
        char a[64];
        npf_log("direct %s: session from %s", c->call_id_s, npf_addr_str(from, a, sizeof a));
    }
    return;
out:
    npf_wipe(&hs, sizeof hs);
}

static void direct_io(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    npf_direct *d = arg;
    int k;
    (void)loop;
    (void)ev;
    for (k = 0; k < 64; k++) {          /* a bounded batch (level-triggered): a flood does not hold the loop */
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            break;
        if (!node_udp_input(d->n, fd, buf, (size_t)r, &from))
            direct_hello(d, buf, (size_t)r, &from);
    }
}

int npf_direct_resolve(const char *spec, struct sockaddr_storage *out)
{
    char host[256];
    const char *colon = strrchr(spec, ':');
    struct addrinfo hints, *res;
    int r;
    if (!colon || (size_t)(colon - spec) >= sizeof host)
        return -1;
    memcpy(host, spec, (size_t)(colon - spec));
    host[colon - spec] = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;             /* the node's sockets are IPv4 */
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host[0] ? host : "0.0.0.0", colon + 1, &hints, &res) != 0)
        return -1;
    memset(out, 0, sizeof *out);
    memcpy(out, res->ai_addr, res->ai_addrlen);
    r = ((struct sockaddr_in *)out)->sin_port ? 0 : -1;
    freeaddrinfo(res);
    return r;
}

int npf_direct_psk(const char *key, const char *file, uint8_t psk[32])
{
    char *s = NULL;
    long n;
    int r;
    if (key) {
        r = npf_b64url_decode(key, strlen(key), psk, 32) == 32 ? 0 : -1;
        if (r < 0)
            npf_log("direct: the key must be 32 random bytes in Base64url");
        return r;
    }
    if (!file)
        return -1;
    if (npf_file_too_open(file)) {
        npf_log("direct: %s is readable by others; chmod 600 it", file);
        return -1;
    }
    n = npf_file_read(file, &s);
    if (n < 0) {
        npf_loge("direct: cannot read %s", file);
        return -1;
    }
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = 0;
    r = npf_b64url_decode(s, (size_t)n, psk, 32) == 32 ? 0 : -1;
    npf_wipe(s, (size_t)n);
    free(s);
    if (r < 0)
        npf_log("direct: %s does not hold 32 random bytes in Base64url", file);
    return r;
}

void npf_direct_genpsk(char out[44])
{
    uint8_t k[32];
    npf_random(k, 32);
    npf_b64url_encode(k, 32, out);
    npf_wipe(k, 32);
}

npf_direct *npf_direct_listen(npf_node *n, const char *spec, const uint8_t psk[32], struct npf_policy *policy)
{
    struct sockaddr_storage a;
    char buf[300];
    npf_direct *d;
    int fd, sz = 4 << 20;
    /* "port" alone means all interfaces */
    if (!strchr(spec, ':'))
        snprintf(buf, sizeof buf, "0.0.0.0:%s", spec);
    else
        snprintf(buf, sizeof buf, "%s", spec);
    if (npf_direct_resolve(buf, &a) < 0)
        return NULL;
    fd = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (fd < 0)
        return NULL;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    if (bind(fd, (struct sockaddr *)&a, sizeof(struct sockaddr_in)) < 0) {
        npf_sock_close(fd);
        return NULL;
    }
    d = calloc(1, sizeof *d);
    if (!d) {
        npf_sock_close(fd);
        return NULL;
    }
    d->n = n;
    d->fd = fd;
    d->policy = policy;
    memcpy(d->psk, psk, 32);
    if (npf_loop_add(n->loop, fd, NPF_EV_READ, direct_io, d) < 0) {
        npf_sock_close(fd);
        free(d);
        return NULL;
    }
    npf_log("direct: listening on %s", npf_addr_str(&a, buf, sizeof buf));
    return d;
}

void npf_direct_close(npf_direct *d)
{
    npf_call *c, *next;
    if (!d)
        return;
    for (c = d->n->calls; c; c = next) {
        next = c->next;
        if (c->direct && c->p2p_fd == d->fd) {
            npf_call_end(c, "closed");      /* tells the peer; freed later with the other calls */
            c->p2p = 0;
            c->p2p_fd = -1;
        }
    }
    npf_loop_del(d->n->loop, d->fd);
    npf_sock_close(d->fd);
    npf_wipe(d, sizeof *d);
    free(d);
}

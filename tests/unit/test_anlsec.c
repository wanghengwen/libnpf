/* AnLiu as NPF uses it, against the AnLiu security audit
 * (third_party/anliu: SECURITY_AUDIT.md 4.1 and 5), with two real AnLiu
 * ends in memory:
 *   - conv: a session's datagram, replayed into another session that has
 *     the same conv (NPF derives conv and key from each session's own
 *     keys), fails authentication and changes nothing there; replayed into
 *     its own session it is a replay. No connection is ever made for a conv
 *     (NPF has none for an unknown one), so no zombie;
 *   - rcv_wnd: a peer's media stream asking for a larger receive window
 *     than NPF's (NPF_ANL_MEDIA_WND) is refused (the opener sees the stream
 *     over), one within it is taken; past NPF_MEDIA_OUT_MAX streams opened
 *     by the peer the next is refused. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "media.h"
#include "npf/loop.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* datagrams on their way: one queue a side */
#define QMAX 512
typedef struct q {
    char *d[QMAX];
    int   len[QMAX];
    int   n;
} q;

static q to_server, to_client;
static uint32_t now_ms = 1000;

static int out_server(char *buf, int len, anl_t *w, void *user)    /* the client's output */
{
    (void)w;
    (void)user;
    if (to_server.n < QMAX && (to_server.d[to_server.n] = malloc((size_t)len))) {
        memcpy(to_server.d[to_server.n], buf, (size_t)len);
        to_server.len[to_server.n++] = len;
    }
    return 0;
}

static int out_client(char *buf, int len, anl_t *w, void *user)
{
    (void)w;
    (void)user;
    if (to_client.n < QMAX && (to_client.d[to_client.n] = malloc((size_t)len))) {
        memcpy(to_client.d[to_client.n], buf, (size_t)len);
        to_client.len[to_client.n++] = len;
    }
    return 0;
}

static void q_clear(q *x)
{
    while (x->n > 0)
        free(x->d[--x->n]);
}

static void q_deliver(q *x, anl_t *w)
{
    int i, n = x->n;
    for (i = 0; i < n; i++)
        anl_input(w, x->d[i], x->len[i]);
    for (i = 0; i < n; i++)
        free(x->d[i]);
    memmove(x->d, x->d + n, (size_t)(x->n - n) * sizeof x->d[0]);
    memmove(x->len, x->len + n, (size_t)(x->n - n) * sizeof x->len[0]);
    x->n -= n;
}

/* a few rounds both ways */
static void pump(anl_t *c, anl_t *s)
{
    int r;
    for (r = 0; r < 8; r++) {
        now_ms += 10;
        anl_update(c, now_ms);
        anl_update(s, now_ms);
        anl_flush(c);
        q_deliver(&to_server, s);
        anl_flush(s);
        q_deliver(&to_client, c);
    }
}

static anl_t *end(int role, uint32_t conv, uint8_t key, anl_output_fn out)
{
    anl_config cfg;
    anl_t *w;
    anl_config_default(&cfg, role);
    memset(cfg.psk, key, sizeof cfg.psk);
    cfg.mtu = 1200;
    w = anl_create(conv, &cfg, NULL);
    if (w) {
        anl_setoutput(w, out);
        anl_update(w, now_ms);
    }
    return w;
}

/* the server's media: NPF's accept (media.c) */
static npf_media *g_media;

static int accept_media(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    (void)w;
    (void)user;
    return npf_media_accept(g_media, s, opt);
}

static int m_unit(void *a, const uint8_t *b, size_t l) { (void)a; (void)b; (void)l; return 0; }
static int m_ws(void *a, const uint8_t *b, size_t l) { (void)a; (void)b; (void)l; return 0; }
static void m_backlog(void *a, size_t *p, uint64_t *t) { (void)a; *p = 0; *t = 0; }
static void m_kick(void *a) { (void)a; }
static int m_open(void *a, uint32_t id, int tag) { (void)a; (void)id; (void)tag; return 1; }
static void m_frame(void *a, uint32_t id, const uint8_t *b, size_t l, uint32_t f, int fl, uint32_t lo)
{
    (void)a; (void)id; (void)b; (void)l; (void)f; (void)fl; (void)lo;
}
static void m_closed(void *a, uint32_t id) { (void)a; (void)id; }
static int m_ended(void *a) { (void)a; return 0; }
static const npf_media_io mio = {m_unit, m_ws, m_backlog, m_kick, m_open, m_frame, m_closed, m_ended};

/* a semi-reliable media stream from the client with this receive window;
 * after a while: 1 the server took it, 0 it was refused */
static int open_media(anl_t *c, anl_t *s, int rcv_wnd, anl_stream_t **out)
{
    anl_stream_opt opt;
    anl_stream_t *st;
    int err = 0, before = npf_media_count(g_media), r;
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.tag = NPF_TAG_MEDIA + 3;
    opt.rcv_wnd = rcv_wnd;
    st = anl_stream_open(c, &opt, &err);
    if (!st)
        return -1;
    anl_stream_send_frame(st, 1, "key frame", 9, NULL);
    pump(c, s);
    r = npf_media_count(g_media) > before;
    if (out)
        *out = st;
    return r;
}

static void test_conv(void)
{
    const uint32_t conv = 0x5a5a1234;
    anl_t *c1 = end(ANL_ROLE_CLIENT, conv, 0x11, out_server), *s1 = end(ANL_ROLE_SERVER, conv, 0x11, out_client);
    anl_t *s2 = end(ANL_ROLE_SERVER, conv, 0x22, out_client);   /* another session, the same conv */
    anl_stats st;
    char buf[64];
    char *d;
    int len, r;
    CHECK(c1 && s1 && s2, "AnLiu ends");
    if (!c1 || !s1 || !s2)
        return;
    q_clear(&to_server);
    anl_send(c1, "session one", 11);
    anl_flush(c1);
    CHECK(to_server.n >= 1, "a datagram of session one");
    if (to_server.n < 1)
        return;
    len = to_server.len[0];
    d = malloc((size_t)len);
    memcpy(d, to_server.d[0], (size_t)len);
    r = anl_input(s2, d, len);                  /* replayed into the other session */
    CHECK(r == ANL_EAUTH, "into another session with the same conv: %d, not ANL_EAUTH", r);
    CHECK(anl_get_stats(s2, &st) == 0 && st.rx_auth_fail == 1, "counted as an authentication failure");
    CHECK(anl_recv(s2, buf, sizeof buf) < 0, "nothing delivered there");
    q_deliver(&to_server, s1);
    CHECK(anl_recv(s1, buf, sizeof buf) == 11, "its own session takes it");
    r = anl_input(s1, d, len);                  /* and again */
    CHECK(r == ANL_EREPLAY, "replayed into its own session: %d, not ANL_EREPLAY", r);
    CHECK(anl_recv(s1, buf, sizeof buf) < 0, "not delivered twice");
    free(d);
    q_clear(&to_client);
    anl_release(c1);
    anl_release(s1);
    anl_release(s2);
}

static void test_rcv_wnd(void)
{
    const uint32_t conv = 0x77;
    npf_loop *loop = npf_loop_new();
    anl_t *c = end(ANL_ROLE_CLIENT, conv, 0x33, out_server), *s = end(ANL_ROLE_SERVER, conv, 0x33, out_client);
    anl_stream_t *st = NULL;
    char buf[64];
    int k, took;
    CHECK(loop && c && s, "setup");
    if (!loop || !c || !s)
        return;
    g_media = npf_media_new(loop, s, 1, &mio, NULL);
    anl_set_accept(s, accept_media);
    /* AnLiu's largest window: refused, the opener sees the stream over */
    CHECK(open_media(c, s, ANL_MAX_WND, &st) == 0, "a media stream with rcv_wnd %d was taken", ANL_MAX_WND);
    pump(c, s);
    CHECK(st && anl_stream_recv_frame(st, buf, sizeof buf, NULL) == ANL_ECLOSED, "the opener sees it refused");
    if (st)
        anl_stream_close(st);
    CHECK(open_media(c, s, NPF_ANL_MEDIA_WND + 1, NULL) == 0, "rcv_wnd one above NPF_ANL_MEDIA_WND was taken");
    /* NPF's own window: taken, up to NPF_MEDIA_OUT_MAX streams */
    for (k = 0, took = 0; k < NPF_MEDIA_OUT_MAX; k++)
        took += open_media(c, s, NPF_ANL_MEDIA_WND, NULL) == 1;
    CHECK(took == NPF_MEDIA_OUT_MAX, "%d of %d media streams within the window taken", took, NPF_MEDIA_OUT_MAX);
    CHECK(open_media(c, s, NPF_ANL_MEDIA_WND, NULL) == 0, "stream %d past NPF_MEDIA_OUT_MAX was taken",
          NPF_MEDIA_OUT_MAX + 1);
    npf_media_free(g_media);
    g_media = NULL;
    q_clear(&to_server);
    q_clear(&to_client);
    anl_release(c);
    anl_release(s);
    npf_loop_free(loop);
}

int test_anlsec(void)
{
    fails = 0;
    test_conv();
    test_rcv_wnd();
    printf("anlsec: %s\n", fails ? "FAIL" : "ok");
    return fails;
}

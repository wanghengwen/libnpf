/* libnpf's channels (npf_channel_*) through npf.h only: two instances on
 * loopback, A listening for direct connections, B connecting. Checks:
 *   - a channel B opens reaches A with its tag; 8 MiB over it arrive intact
 *     and in order (the sender waits for channel_writable on NPF_EBUSY);
 *   - both sides send on one channel;
 *   - a paused receiver holds the sender back: NPF_EBUSY, then
 *     channel_writable once it goes on, nothing lost;
 *   - a close right after a send: the peer still gets every byte, then
 *     channel_closed; the closer gets no channel_closed, the number is stale;
 *   - a refused channel ends at its opener (channel_closed);
 *   - channel and media numbers are not each other's (NPF_ENOENT);
 *   - a callback closing another channel whose bytes wait to be read in
 *     the same drain (nothing of it is delivered; run it under ASan: the
 *     library's list of readable streams must not keep the closed one);
 *   - the session's end closes the channels left (channel_closed).
 *
 *   test_channel [PORT]   exit 0 when everything passed */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE                    /* mkdtemp on macOS */
#include <stdlib.h>

#include "api_test.h"

#define REFUSE_TAG 999
#define MAXCH      4096
#define BULK       (8u << 20)

typedef struct side {
    const char     *name;
    pthread_mutex_t mu;
    npf_t          *n;
    uint32_t        session;
    int             up;
    int             opened, closed, writable, bad;
    uint32_t        last_opened;
    int             tag[MAXCH];         /* channel number -> tag + 1 (the peer's ones) */
    size_t          got[MAXCH];         /* bytes received on it */
    int             closed_ch[MAXCH];
    /* what a callback does */
    uint32_t        x, y;               /* "go" (on another channel) resumes both; x's bytes close y */
    int             closed_in_cb;
} side;

static uint8_t pat(size_t k, int seed)
{
    return (uint8_t)(k ^ (k >> 8) ^ (k >> 16) ^ (size_t)seed * 37u);
}

static void cb_session(void *user, uint32_t session, int up, const char *info)
{
    side *s = user;
    (void)info;
    pthread_mutex_lock(&s->mu);
    if (up) {
        s->session = session;
        s->up++;
    }
    pthread_mutex_unlock(&s->mu);
}

static int cb_open(void *user, uint32_t session, uint32_t ch, int tag)
{
    side *s = user;
    (void)session;
    if (tag == REFUSE_TAG)
        return 0;
    pthread_mutex_lock(&s->mu);
    s->opened++;
    s->last_opened = ch;
    if (ch < MAXCH)
        s->tag[ch] = tag + 1;
    pthread_mutex_unlock(&s->mu);
    return 1;
}

/* the bytes of a channel: the pattern seeded with its tag, from 0 */
static void cb_data(void *user, uint32_t ch, const void *buf, size_t len)
{
    side *s = user;
    const uint8_t *p = buf;
    uint32_t cl = 0, x = 0, y = 0;
    size_t i;
    pthread_mutex_lock(&s->mu);
    if (s->x && ch != s->x && ch != s->y && len == 2 && memcmp(buf, "go", 2) == 0) {
        x = s->x;                       /* not the pattern: the cue */
        y = s->y;
    } else if (ch >= MAXCH || s->closed_ch[ch]) {
        s->bad++;
    } else {
        int seed = s->tag[ch] ? s->tag[ch] - 1 : 100;   /* ours: the peer answers with 100 */
        for (i = 0; i < len; i++)
            if (p[i] != pat(s->got[ch] + i, seed)) {
                s->bad++;
                break;
            }
        s->got[ch] += len;
    }
    if (s->x && ch == s->x && !s->closed_in_cb)
        cl = s->y;
    pthread_mutex_unlock(&s->mu);
    if (cl && npf_channel_close(s->n, cl) == NPF_OK) {
        pthread_mutex_lock(&s->mu);
        s->closed_ch[cl] = 1;           /* nothing more of it may come */
        s->closed_in_cb = 1;
        pthread_mutex_unlock(&s->mu);
    }
    if (x) {                            /* both in one turn of the library's thread: read in one drain */
        npf_channel_pause(s->n, x, 0);
        npf_channel_pause(s->n, y, 0);
    }
}

static void cb_writable(void *user, uint32_t ch)
{
    side *s = user;
    (void)ch;
    pthread_mutex_lock(&s->mu);
    s->writable++;
    pthread_mutex_unlock(&s->mu);
}

static void cb_closed(void *user, uint32_t ch)
{
    side *s = user;
    pthread_mutex_lock(&s->mu);
    s->closed++;
    if (ch < MAXCH)
        s->closed_ch[ch] = 1;
    pthread_mutex_unlock(&s->mu);
}

static int get(side *s, const int *v)
{
    int r;
    pthread_mutex_lock(&s->mu);
    r = *v;
    pthread_mutex_unlock(&s->mu);
    return r;
}

static size_t got(side *s, uint32_t ch)
{
    size_t r;
    pthread_mutex_lock(&s->mu);
    r = ch < MAXCH ? s->got[ch] : 0;
    pthread_mutex_unlock(&s->mu);
    return r;
}

static npf_t *make(side *s, const char *dir, const char *overrides)
{
    npf_options o;
    npf_callbacks cb;
    npf_t *n = NULL;
    char err[300];
    npf_options_init(&o);
    o.conf_dir = dir;
    o.data_dir = dir;
    o.overrides = overrides;
    o.role = NPF_ROLE_DIRECT;
    o.log_level = NPF_LEVEL_WARN;
    npf_callbacks_init(&cb);
    cb.user = s;
    cb.session = cb_session;
    cb.channel_open = cb_open;
    cb.channel_data = cb_data;
    cb.channel_writable = cb_writable;
    cb.channel_closed = cb_closed;
    o.cb = &cb;
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK) {
        printf("npf_create %s: %s\n", s->name, err);
        return NULL;
    }
    s->n = n;
    return n;
}

static uint32_t chan_open(npf_t *n, uint32_t session, int tag, int *e)
{
    npf_channel_opt o;
    uint32_t ch = 0;
    npf_channel_opt_init(&o);
    o.tag = tag;
    *e = npf_channel_open(n, session, &o, &ch);
    return ch;
}

/* total bytes of the pattern (seed) from offset *off on, in pieces of
 * piece; on NPF_EBUSY waits for channel_writable. busy counts the refusals;
 * stop_at_busy: return at the first. 0, or the error */
static int send_pat(side *s, uint32_t ch, int seed, size_t *off, size_t total, size_t piece, int *busy,
                    int stop_at_busy)
{
    static uint8_t buf[1u << 20];
    size_t end = *off + total;
    while (*off < end) {
        size_t len = end - *off < piece ? end - *off : piece, i;
        int w = get(s, &s->writable), r;
        for (i = 0; i < len; i++)
            buf[i] = pat(*off + i, seed);
        r = npf_channel_send(s->n, ch, buf, len);
        if (r == NPF_EBUSY) {
            if (busy)
                (*busy)++;
            if (stop_at_busy)
                return r;
            WAIT_UNTIL(get(s, &s->writable) > w, 10000);
            if (get(s, &s->writable) <= w)
                return NPF_EBUSY;       /* no channel_writable */
            continue;
        }
        if (r != NPF_OK)
            return r;
        *off += len;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static side a, b;
    char da[] = "/tmp/npf-chan-a-XXXXXX", db[] = "/tmp/npf-chan-b-XXXXXX", ov[256];
    const char *key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";   /* 32 zero bytes */
    int port = argc > 1 ? atoi(argv[1]) : 27800 + (int)(getpid() % 30), e, busy, w;
    npf_t *na, *nb;
    uint32_t c1, ac1, c2, c3, x, y, media = 0;
    size_t off, back;
    char err[300];
    if (!mkdtemp(da) || !mkdtemp(db))
        return 2;
    a.name = "A";
    b.name = "B";
    pthread_mutex_init(&a.mu, NULL);
    pthread_mutex_init(&b.mu, NULL);
    alarm(120);
    snprintf(ov, sizeof ov, "direct = 127.0.0.1:%d\ndirect_psk = %s\nudp_port = 0\n", port, key);
    na = make(&a, da, ov);
    nb = make(&b, db, "udp_port = 0\n");
    if (!na || !nb)
        return 1;
    check(npf_start(na) == NPF_OK && npf_start(nb) == NPF_OK, "start");
    {
        static const uint8_t zero[32];
        npf_peer_opt po;
        uint32_t id = 0;
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.1";
        po.port = (uint16_t)port;
        po.psk = zero;
        check(npf_peer_create(nb, &po, &id, err, sizeof err) == NPF_OK && id, "peer create");
    }
    WAIT_UNTIL(get(&a, &a.up) && get(&b, &b.up), 10000);
    check(get(&a, &a.up) && get(&b, &b.up), "sessions up on both sides");

    /* arguments */
    {
        npf_channel_opt o;
        uint32_t ch = 0;
        npf_channel_opt_init(&o);
        o.tag = 1000;
        check(npf_channel_open(nb, b.session, &o, &ch) == NPF_EINVAL && !ch, "tag 1000: NPF_EINVAL");
        o.tag = 1;
        check(npf_channel_open(nb, 999999, &o, &ch) == NPF_ENOENT, "no such session: NPF_ENOENT");
        check(npf_channel_open(nb, b.session, NULL, &ch) == NPF_EINVAL, "no options: NPF_EINVAL");
        check(npf_channel_send(nb, 999999, "x", 1) == NPF_ENOENT, "send on no channel: NPF_ENOENT");
    }

    /* 8 MiB one way, intact and in order */
    c1 = chan_open(nb, b.session, 5, &e);
    check(c1 && e == NPF_OK, "B opens a channel");
    check(npf_channel_send(nb, c1, "", 0) == NPF_EINVAL, "an empty send: NPF_EINVAL");
    {
        static uint8_t big[NPF_CHANNEL_BUFFER + 1];
        check(npf_channel_send(nb, c1, big, sizeof big) == NPF_ETOOBIG, "over NPF_CHANNEL_BUFFER: NPF_ETOOBIG");
    }
    off = 0;
    busy = 0;
    check(send_pat(&b, c1, 5, &off, BULK, 256u << 10, &busy, 0) == 0, "8 MiB sent (waiting on NPF_EBUSY)");
    WAIT_UNTIL(get(&a, &a.opened) >= 1 && got(&a, a.last_opened) >= BULK, 20000);
    ac1 = a.last_opened;
    check(get(&a, &a.opened) == 1 && ac1 < MAXCH && a.tag[ac1] == 6, "A took it with tag 5");
    check(got(&a, ac1) == BULK && !get(&a, &a.bad), "8 MiB arrived intact, in order");
    printf("(%d refusals on the way)\n", busy);

    /* the other way on the same channel */
    back = 0;
    check(send_pat(&a, ac1, 100, &back, 300000, 7000, NULL, 0) == 0, "A sends back on it");
    WAIT_UNTIL(got(&b, c1) >= 300000, 10000);
    check(got(&b, c1) == 300000 && !get(&b, &b.bad), "B gets it intact");

    /* a paused receiver: the sender is refused, then told */
    check(npf_channel_pause(na, ac1, 1) == NPF_OK, "A pauses");
    sleep_ms(100);
    {
        size_t before = got(&a, ac1), start = off;
        busy = 0;
        send_pat(&b, c1, 5, &off, 16u << 20, 256u << 10, &busy, 1);
        check(busy == 1, "B is refused (NPF_EBUSY) while A does not read");
        check(off - start < (6u << 20), "within the window and the send buffer");
        sleep_ms(200);
        check(got(&a, ac1) == before, "nothing delivered while paused");
        w = get(&b, &b.writable);
        check(npf_channel_pause(na, ac1, 0) == NPF_OK, "A goes on");
        WAIT_UNTIL(get(&b, &b.writable) > w, 10000);
        check(get(&b, &b.writable) > w, "B gets channel_writable");
        check(send_pat(&b, c1, 5, &off, 1u << 20, 256u << 10, NULL, 0) == 0, "B sends more");
        WAIT_UNTIL(got(&a, ac1) >= off, 10000);
        check(got(&a, ac1) == off && !get(&a, &a.bad), "every byte arrived, in order");
    }

    /* a close right after the send */
    c2 = chan_open(nb, b.session, 6, &e);
    off = 0;
    check(c2 && send_pat(&b, c2, 6, &off, 1u << 20, 1u << 20, NULL, 0) == 0, "1 MiB on a second channel");
    check(npf_channel_close(nb, c2) == NPF_OK, "closed at once");
    check(npf_channel_send(nb, c2, "x", 1) == NPF_ENOENT && npf_channel_close(nb, c2) == NPF_ENOENT,
          "its number is stale");
    {
        uint32_t ac2;
        WAIT_UNTIL(get(&a, &a.closed) >= 1, 10000);
        ac2 = a.last_opened;
        check(get(&a, &a.closed) == 1 && a.closed_ch[ac2] && got(&a, ac2) == (1u << 20) && !get(&a, &a.bad),
              "the peer got all of it, then channel_closed");
        check(get(&b, &b.closed) == 0, "no channel_closed at the closer");
    }

    /* refused */
    c3 = chan_open(nb, b.session, REFUSE_TAG, &e);
    check(c3 != 0, "a channel A refuses");
    WAIT_UNTIL(get(&b, &b.closed) >= 1, 10000);
    check(get(&b, &b.closed) == 1 && b.closed_ch[c3], "the opener gets channel_closed");

    /* not each other's numbers */
    {
        npf_media_opt mo;
        npf_media_opt_init(&mo);
        check(npf_media_open(nb, b.session, &mo, &media) == NPF_OK && media, "a media stream");
        check(npf_media_send(nb, c1, 0, "x", 1) == NPF_ENOENT, "npf_media_send on a channel: NPF_ENOENT");
        check(npf_media_close(nb, c1) == NPF_ENOENT, "npf_media_close on a channel: NPF_ENOENT");
        check(npf_channel_send(nb, media, "x", 1) == NPF_ENOENT, "npf_channel_send on a media stream: NPF_ENOENT");
        check(npf_channel_close(nb, media) == NPF_ENOENT, "npf_channel_close on a media stream: NPF_ENOENT");
    }

    /* a callback closes another channel with bytes waiting: B pauses x and
     * y, A sends on both, "go" resumes both in one callback, and the first
     * bytes of x close y */
    x = chan_open(na, a.session, 21, &e);
    y = chan_open(na, a.session, 22, &e);
    check(x && y, "A opens two channels");
    WAIT_UNTIL(get(&b, &b.opened) >= 2, 10000);
    check(get(&b, &b.opened) == 2, "B took them");
    {
        uint32_t bx = 0, by = 0, i;
        size_t ox = 0, oy = 0;
        pthread_mutex_lock(&b.mu);
        for (i = 1; i < MAXCH; i++) {
            if (b.tag[i] == 22)
                bx = i;
            if (b.tag[i] == 23)
                by = i;
        }
        pthread_mutex_unlock(&b.mu);
        check(bx && by && npf_channel_pause(nb, bx, 1) == NPF_OK && npf_channel_pause(nb, by, 1) == NPF_OK,
              "B pauses both");
        check(send_pat(&a, x, 21, &ox, 60000, 60000, NULL, 0) == 0 && send_pat(&a, y, 22, &oy, 60000, 60000, NULL, 0) == 0,
              "A sends on both");
        sleep_ms(300);                  /* in B's AnLiu, not read */
        check(got(&b, bx) == 0 && got(&b, by) == 0, "nothing delivered while paused");
        pthread_mutex_lock(&b.mu);
        b.x = bx;
        b.y = by;
        pthread_mutex_unlock(&b.mu);
        check(npf_channel_send(na, ac1, "go", 2) == NPF_OK, "A says go");
        WAIT_UNTIL(get(&b, &b.closed_in_cb) && got(&b, bx) >= 60000, 10000);
        sleep_ms(200);
        check(get(&b, &b.closed_in_cb) && got(&b, bx) == 60000, "x delivered, y closed from its callback");
        check(got(&b, by) == 0 && !get(&b, &b.bad), "nothing of y delivered after its close");
        WAIT_UNTIL(get(&a, &a.closed) >= 2, 10000);
        check(get(&a, &a.closed) == 2 && a.closed_ch[y], "A gets channel_closed for y");
    }

    /* the session's end */
    {
        int before = get(&a, &a.closed);
        npf_destroy(nb);
        nb = NULL;
        WAIT_UNTIL(get(&a, &a.closed) >= before + 2, 10000);
        check(get(&a, &a.closed) == before + 2 && a.closed_ch[ac1] && a.closed_ch[x],
              "the session's end: channel_closed for each one left");
    }
    npf_destroy(na);
    rm_dir(da);
    rm_dir(db);
    printf("%s\n", fails ? "FAILED" : "all passed");
    return fails ? 1 : 0;
}

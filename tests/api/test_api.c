/* libnpf through npf.h only, linked with the shared library: two instances
 * on loopback, A listening for direct connections and B connecting to it
 * (no platform). Checks: sessions up on both sides; application data both
 * ways; media streams at once with their frames intact and in order; many
 * opens and closes (more than AnLiu's 64 streams: each one opened and closed for real);
 * a refused stream ends at the sender; streams refused or closed by the
 * receiver, 100 in turn: each one's end is taken at the sender (AnLiu counts
 * the over ones not yet released toward its 64); too many at once gives NPF_EBUSY and
 * a close makes room; a stream from the other side; stop and destroy.
 *
 * And what a review found: a command whose options are taken
 * out of argv (no double free); a log callback that calls the API (no
 * deadlock); each instance its own log and level; frames from another
 * thread while the library's thread is busy: refused over the budget
 * (NPF_EBUSY), not piling up; config_get of an unknown key / a secret / a
 * small buffer; a peer given as words with a space in one; three instances
 * at once in one process (run it under ThreadSanitizer: NPF_TSAN).
 *
 * NPF_TEST_RUNTIME=N: every instance on a shared runtime of N threads; with
 * one thread, a callback's npf_destroy of another instance there is refused.
 *
 *   test_api [PORT]       exit 0 when everything passed */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE                    /* mkdtemp on macOS */
#include <stdlib.h>

#include "api_test.h"

#define NTAGS 4
#define FRAMES 30
#define CYCLES 200
#define REFUSE_TAG 999

typedef struct side {
    const char     *name;
    pthread_mutex_t mu;
    uint32_t        session;
    int             up, data_n;
    char            data[64];
    int             opened, closed, frames, bad, refused_closed;
    uint32_t        last_opened;        /* the peer's last media stream taken */
    int             tag_frames[1000];
    uint32_t        media_tag[4096];     /* media number -> tag + 1 */
    uint32_t        next_fno[4096];
    npf_t          *n;
    int             log_lines, reenter, reentered, block_ms, in_cb;
    npf_t          *destroy_other;      /* cb_data tries npf_destroy of it (refused) */
    int             destroy_tried;
} side;

/* a stream's number, 0 with the reason in *e */
static uint32_t media_open(npf_t *n, uint32_t session, const npf_media_opt *o, int *e)
{
    uint32_t m = 0;
    *e = npf_media_open(n, session, o, &m);
    return m;
}

static npf_runtime *rt;

/* wait until *v >= want (under the side's lock) */
static int wait_for(side *s, const int *v, int want, int ms)
{
    int i, ok = 0;
    for (i = 0; i < ms / 10; i++) {
        pthread_mutex_lock(&s->mu);
        ok = *v >= want;
        pthread_mutex_unlock(&s->mu);
        if (ok)
            break;
        sleep_ms(10);
    }
    return ok;
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

static void cb_data(void *user, uint32_t session, const void *buf, size_t len)
{
    side *s = user;
    (void)session;
    pthread_mutex_lock(&s->mu);
    snprintf(s->data, sizeof s->data, "%.*s", (int)len, (const char *)buf);
    s->data_n++;
    if (s->destroy_other) {
        npf_t *o = s->destroy_other;
        s->destroy_other = NULL;
        pthread_mutex_unlock(&s->mu);
        npf_destroy(o);                 /* on its runtime thread: refused, at once */
        pthread_mutex_lock(&s->mu);
        s->destroy_tried = 1;
    }
    if (len == 5 && memcmp(buf, "block", 5) == 0 && s->block_ms) {
        int ms = s->block_ms;
        s->in_cb = 1;
        pthread_mutex_unlock(&s->mu);
        sleep_ms(ms);                   /* the library's thread busy */
        pthread_mutex_lock(&s->mu);
        s->in_cb = 0;
    }
    pthread_mutex_unlock(&s->mu);
}

/* the instance's log lines; with reenter, the callback asks for the log
 * itself (the library holds no lock while it calls) */
static void cb_log(void *user, int level, const char *line)
{
    side *s = user;
    int re;
    (void)level;
    (void)line;
    pthread_mutex_lock(&s->mu);
    s->log_lines++;
    re = s->reenter;
    s->reenter = 0;
    pthread_mutex_unlock(&s->mu);
    if (re) {
        char *j = npf_log_json(s->n, 4000);
        pthread_mutex_lock(&s->mu);
        s->reentered = j != NULL;
        pthread_mutex_unlock(&s->mu);
        npf_free(j);
    }
}

static int cb_media_open(void *user, uint32_t session, uint32_t media, int tag)
{
    side *s = user;
    (void)session;
    if (tag == REFUSE_TAG)
        return 0;
    pthread_mutex_lock(&s->mu);
    s->opened++;
    s->last_opened = media;
    if (media < 4096) {
        s->media_tag[media] = (uint32_t)tag + 1;
        s->next_fno[media] = 0;
    }
    pthread_mutex_unlock(&s->mu);
    return 1;
}

/* frame: tag(2) | frame_no(4) | filler (frame_no & 0xff) */
static void cb_media_frame(void *user, uint32_t media, const void *buf, size_t len, const npf_frame_info *fi)
{
    side *s = user;
    const unsigned char *p = buf;
    size_t i;
    int ok = len >= 6 && media < 4096 && s->media_tag[media];
    pthread_mutex_lock(&s->mu);
    if (ok) {
        int tag = p[0] | p[1] << 8;
        uint32_t fno = (uint32_t)p[2] | (uint32_t)p[3] << 8 | (uint32_t)p[4] << 16 | (uint32_t)p[5] << 24;
        ok = tag + 1 == (int)s->media_tag[media] && fno == fi->frame_no && fno == s->next_fno[media]
             && fi->lost_before == 0 && (fno % 10 == 0) == !!(fi->flags & NPF_FRAME_KEY);
        for (i = 6; ok && i < len; i++)
            ok = p[i] == (unsigned char)fno;
        s->next_fno[media] = fno + 1;
        if (ok && tag < 1000)
            s->tag_frames[tag]++;
    }
    if (!ok)
        s->bad++;
    s->frames++;
    pthread_mutex_unlock(&s->mu);
}

static void cb_media_closed(void *user, uint32_t media)
{
    side *s = user;
    pthread_mutex_lock(&s->mu);
    s->closed++;
    if (media < 4096 && !s->media_tag[media])
        s->refused_closed++;            /* one of ours, refused by the peer */
    pthread_mutex_unlock(&s->mu);
}

static npf_t *make(side *s, const char *dir, const char *overrides)
{
    npf_options o;
    npf_callbacks cb;                   /* copied by npf_create */
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
    cb.data = cb_data;
    cb.media_open = cb_media_open;
    cb.media_frame = cb_media_frame;
    cb.media_closed = cb_media_closed;
    cb.log = cb_log;
    o.cb = &cb;
    o.runtime = rt;
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK) {
        printf("npf_create %s: %s\n", s->name, err);
        return NULL;
    }
    s->n = n;
    return n;
}

static int send_frames(npf_t *n, uint32_t media, int tag, int count, size_t size)
{
    unsigned char buf[4096];
    int f;
    for (f = 0; f < count; f++) {
        buf[0] = (unsigned char)tag;
        buf[1] = (unsigned char)(tag >> 8);
        buf[2] = (unsigned char)f;
        buf[3] = (unsigned char)(f >> 8);
        buf[4] = buf[5] = 0;
        memset(buf + 6, f & 0xff, size - 6);
        if (npf_media_send(n, media, f % 10 == 0 ? NPF_FRAME_KEY : 0, buf, size) != NPF_OK)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static side a, b, c;
    char da[] = "/tmp/npf-api-a-XXXXXX", db[] = "/tmp/npf-api-b-XXXXXX", ov[256];
    const char *key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";   /* 32 zero bytes */
    /* below the ephemeral ports (other programs on this machine take those) */
    int port = argc > 1 ? atoi(argv[1]) : 27760 + (int)(getpid() % 30), i, t, ok, opened, e;
    npf_t *na, *nb;
    uint32_t ms[NTAGS], busy[40], back;
    npf_media_opt mo;
    char err[300];
    if (!mkdtemp(da) || !mkdtemp(db))
        return 2;
    a.name = "A";
    b.name = "B";
    c.name = "C";
    pthread_mutex_init(&a.mu, NULL);
    pthread_mutex_init(&b.mu, NULL);
    pthread_mutex_init(&c.mu, NULL);
    alarm(120);                         /* a deadlock fails the test instead of hanging it */
    check(npf_api_version() == NPF_API_VERSION && npf_version()[0], "api version");
    if (getenv("NPF_TEST_RUNTIME") && *getenv("NPF_TEST_RUNTIME")) {
        rt = npf_runtime_new(atoi(getenv("NPF_TEST_RUNTIME")));
        check(rt != NULL, "a shared runtime");
        if (!rt)
            return 1;
    }
    snprintf(ov, sizeof ov, "direct = 127.0.0.1:%d\ndirect_psk = %s\nudp_port = 0\n", port, key);
    na = make(&a, da, ov);
    nb = make(&b, db, "udp_port = 0\n");
    if (!na || !nb)
        return 1;
    check(npf_start(na) == NPF_OK && npf_start(nb) == NPF_OK, "start");
    {
        static const uint8_t zero[32];      /* key: 32 zero bytes */
        npf_peer_opt po;
        uint32_t id = 0;
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.1";
        po.port = (uint16_t)port;
        po.psk = zero;
        check(npf_peer_create(nb, &po, &id, err, sizeof err) == NPF_OK && id, "peer create");
    }
    check(wait_for(&a, &a.up, 1, 10000) && wait_for(&b, &b.up, 1, 10000), "sessions up on both sides");

    /* application data, both ways */
    if (rt && atoi(getenv("NPF_TEST_RUNTIME")) == 1) {
        pthread_mutex_lock(&a.mu);
        a.destroy_other = nb;           /* A's callback, on the thread B runs on too */
        pthread_mutex_unlock(&a.mu);
    }
    check(npf_session_send(nb, b.session, "hello", 5) == NPF_OK, "session_send B -> A");
    check(npf_session_send(na, a.session, "world", 5) == NPF_OK, "session_send A -> B");
    ok = wait_for(&a, &a.data_n, 1, 5000) && wait_for(&b, &b.data_n, 1, 5000);
    check(ok && strcmp(a.data, "hello") == 0 && strcmp(b.data, "world") == 0, "application data arrived");
    check(npf_session_send(nb, 999999, "x", 1) == NPF_ENOENT, "session_send to no session");
    if (rt && atoi(getenv("NPF_TEST_RUNTIME")) == 1)
        check(a.destroy_tried && npf_session_send(nb, b.session, "again", 5) == NPF_OK,
              "runtime: npf_destroy from a callback on the instance's thread refused");

    /* streams at once */
    npf_media_opt_init(&mo);
    for (t = 0; t < NTAGS; t++) {
        mo.tag = t + 1;
        ms[t] = media_open(nb, b.session, &mo, &e);
        if (!ms[t])
            printf("open tag %d: %d\n", t + 1, e);
    }
    ok = 1;
    for (i = 0; i < FRAMES; i++)            /* interleaved */
        for (t = 0; t < NTAGS; t++) {
            unsigned char buf[1200];
            buf[0] = (unsigned char)(t + 1);
            buf[1] = 0;
            buf[2] = (unsigned char)i;
            buf[3] = buf[4] = buf[5] = 0;
            memset(buf + 6, i, sizeof buf - 6);
            if (npf_media_send(nb, ms[t], i % 10 == 0 ? NPF_FRAME_KEY : 0, buf, sizeof buf) != NPF_OK)
                ok = 0;
        }
    check(ok && ms[0] && ms[1] && ms[2] && ms[3], "4 streams opened and sent");
    ok = wait_for(&a, &a.frames, NTAGS * FRAMES, 10000);
    for (t = 0; t < NTAGS; t++)
        ok = ok && a.tag_frames[t + 1] == FRAMES;
    check(ok && a.bad == 0, "every frame intact, in order, key flags kept");
    {
        npf_media_stats st;
        check(npf_media_stats_get(nb, ms[0], &st) == NPF_OK && st.srtt_ms < 1000, "stats");
    }
    for (t = 0; t < NTAGS; t++)
        npf_media_close(nb, ms[t]);
    check(wait_for(&a, &a.closed, NTAGS, 5000), "closes reached the receiver");

    /* open and close many times: more than AnLiu's 64 streams */
    opened = 0;
    for (i = 0; i < CYCLES; i++) {
        uint32_t m;
        int retry;
        mo.tag = 100 + i % 7;
        mo.prio = i % 2;                    /* two sets of options */
        /* CLOSE still occupies a transport slot until its acknowledgement.
         * A busy loop may produce streams faster than the peer can retire
         * them; respect that backpressure while testing repeated reuse. */
        for (retry = 0; retry < 500; retry++) {
            m = media_open(nb, b.session, &mo, &e);
            if (m || e != NPF_EBUSY)
                break;
            sleep_ms(10);
        }
        if (!m) {
            printf("cycle %d: open failed %d\n", i, e);
            break;
        }
        opened++;
        send_frames(nb, m, mo.tag, 3, 300);
        npf_media_close(nb, m);
    }
    check(opened == CYCLES, "200 opens and closes");
    ok = wait_for(&a, &a.opened, NTAGS + CYCLES, 10000) && wait_for(&a, &a.closed, NTAGS + CYCLES, 10000);
    check(ok, "the receiver saw every open and close");
    check(a.bad == 0, "no frame broken or out of order");
    mo.prio = 1;

    /* refused by the receiver: ends at the sender */
    mo.tag = REFUSE_TAG;
    check(media_open(nb, b.session, &mo, &e) != 0, "open a stream the peer refuses");
    check(wait_for(&b, &b.refused_closed, 1, 5000), "the refusal ends it at the sender");

    /* over and over, refused (the receiver's AnLiu RST) or taken and closed
     * by the receiver: the sender releases each one's AnLiu handle, which
     * counts toward AnLiu's 64 until then; no retry on NPF_EBUSY here */
    for (i = 0, ok = 1; ok && i < 100; i++) {
        int took;
        mo.tag = i % 2 ? 11 : REFUSE_TAG;
        pthread_mutex_lock(&a.mu);
        took = a.opened;
        pthread_mutex_unlock(&a.mu);
        ok = media_open(nb, b.session, &mo, &e) != 0;
        if (ok && i % 2) {
            uint32_t m;
            ok = wait_for(&a, &a.opened, took + 1, 5000);
            pthread_mutex_lock(&a.mu);
            m = a.last_opened;
            pthread_mutex_unlock(&a.mu);
            ok = ok && npf_media_close(na, m) == NPF_OK;
        }
        ok = ok && wait_for(&b, &b.refused_closed, 2 + i, 5000);
    }
    check(ok, "100 streams refused or closed by the receiver in turn: each ends at the sender, opens go on");
    if (!ok)
        printf("     (stopped at %d: %d)\n", i, e);

    /* too many at once */
    mo.tag = 7;
    for (i = 0; i < 40; i++)
        if (!(busy[i] = media_open(nb, b.session, &mo, &e)))
            break;
    check(i < 40 && i >= 20 && e == NPF_EBUSY, "too many streams at once: NPF_EBUSY");
    printf("     (%d streams open at once)\n", i);
    if (i > 0) {
        npf_media_close(nb, busy[0]);
        check((busy[0] = media_open(nb, b.session, &mo, &e)) != 0, "a close makes room");
    }
    while (i-- > 0)
        npf_media_close(nb, busy[i]);

    /* the other direction */
    mo.tag = 5;
    back = media_open(na, a.session, &mo, &e);
    check(back && send_frames(na, back, 5, 20, 2000) == 0, "A opens a stream to B");
    check(wait_for(&b, &b.tag_frames[5], 20, 5000) && b.bad == 0, "B receives it");

    /* frames from another thread while the library's thread is busy: the
     * budget (NPF_MEDIA_SEND_QUEUE) refuses the rest, nothing piles up */
    {
        static unsigned char mb[1 << 20];
        uint32_t m;
        int busyc = 0, okc = 0;
        mo.tag = 9;
        mo.max_age_ms = 0;
        m = media_open(nb, b.session, &mo, &e);
        pthread_mutex_lock(&b.mu);
        b.block_ms = 1500;
        pthread_mutex_unlock(&b.mu);
        npf_session_send(na, a.session, "block", 5);
        ok = wait_for(&b, &b.in_cb, 1, 5000);
        for (i = 0; ok && i < 24; i++) {
            int r = npf_media_send(nb, m, NPF_FRAME_KEY, mb, sizeof mb);
            busyc += r == NPF_EBUSY;
            okc += r == NPF_OK;
        }
        check(ok && okc == 16 && busyc == 8, "a busy library thread: frames over 16 MB refused with NPF_EBUSY");
        printf("     (%d queued, %d refused)\n", okc, busyc);
        pthread_mutex_lock(&b.mu);
        b.block_ms = 0;
        pthread_mutex_unlock(&b.mu);
        sleep_ms(1600);
        check(npf_media_send(nb, m, NPF_FRAME_KEY, mb, 1000) == NPF_OK, "after it: sends again");
        check(npf_media_send(nb, 999999, 0, mb, 10) == NPF_ENOENT, "a stale stream number: NPF_ENOENT from this thread too");
        npf_media_close(nb, m);
        mo.max_age_ms = 500;
    }

    /* each instance its own log: lines, level, callback; a callback that
     * calls the API back */
    {
        int la, lb;
        char lv[16] = "", *ja, *jb;
        la = a.log_lines;
        lb = b.log_lines;
        npf_config_set(na, "log_level", "info", 0, NULL, err, sizeof err);
        npf_config_set(na, "max_calls", "31", 0, NULL, err, sizeof err);
        wait_for(&a, &a.log_lines, la + 1, 5000);
        pthread_mutex_lock(&a.mu);
        pthread_mutex_lock(&b.mu);
        ok = a.log_lines > la && b.log_lines == lb;
        pthread_mutex_unlock(&b.mu);
        pthread_mutex_unlock(&a.mu);
        check(ok, "A's lines go to A's callback only");
        npf_config_get(nb, "log_level", lv, sizeof lv);
        check(strcmp(lv, "warn") == 0, "B's level stays (warn)");
        ja = npf_log_json(na, 8000);
        jb = npf_log_json(nb, 8000);
        check(ja && strstr(ja, "max_calls = 31") && jb && !strstr(jb, "max_calls = 31"), "npf_log_json: the instance's own lines");
        npf_free(ja);
        npf_free(jb);
        pthread_mutex_lock(&a.mu);
        a.reenter = 1;
        pthread_mutex_unlock(&a.mu);
        npf_config_set(na, "max_calls", "32", 0, NULL, err, sizeof err);
        check(wait_for(&a, &a.reentered, 1, 5000), "a log callback that calls the API (no deadlock)");
    }

    /* settings: unknown, secret, too small */
    {
        char v[64];
        check(npf_config_get(na, "no_such_key", v, sizeof v) == NPF_ENOENT, "config_get of an unknown key: NPF_ENOENT");
        check(npf_config_get(na, "password", v, sizeof v) == NPF_OK && strcmp(v, "(hidden)") == 0,
              "config_get of a secret: hidden");
        check(npf_config_get(na, "max_calls", v, 2) == NPF_ETOOBIG, "config_get into a small buffer: NPF_ETOOBIG");
    }

        /* a third instance: a log callback calling the API before the start;
     * a one-off direct peer; three instances in one process at once */
    {
        static const uint8_t zero[32];
        char dc[] = "/tmp/npf-api-c-XXXXXX";
        npf_peer_opt po;
        npf_t *nc;
        if (!mkdtemp(dc))
            return 2;
        nc = make(&c, dc, "udp_port = 0\n");
        ok = nc != NULL;
        if (rt)
            check(nc && npf_run(nc) == NPF_ESTATE, "runtime: npf_run refused");
        pthread_mutex_lock(&c.mu);
        c.reenter = 1;                      /* not running: the caller's thread executes */
        pthread_mutex_unlock(&c.mu);
        npf_config_set(nc, "log_level", "info", 0, NULL, err, sizeof err);   /* logged at info */
        check(c.reentered, "a log callback calling the API before the start (no deadlock)");
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.1";
        po.port = (uint16_t)port;
        po.psk = zero;
        po.connect = NPF_CONNECT_ONCE;
        err[0] = 0;
        ok = ok && npf_peer_create(nc, &po, NULL, err, sizeof err) == NPF_OK && npf_start(nc) == NPF_OK;
        if (!ok)
            printf("     peer_create: %s\n", err);
        check(ok && wait_for(&c, &c.up, 1, 10000), "a peer made before the start connects with it; three instances at once");
        npf_destroy(nc);
        rm_dir(dc);
    }

    /* JSON queries */
    {
        char *s = npf_sessions_json(nb);
        check(s && strstr(s, "\"session\""), "sessions_json");
        npf_free(s);
        s = npf_status_json(na);
        check(s && s[0] == '{', "status_json");
        npf_free(s);
    }
    if (rt)
        check(npf_runtime_free(rt) == NPF_ESTATE, "runtime: not freed while instances live");
    npf_stop(nb);
    npf_stop(na);
    npf_destroy(nb);
    npf_destroy(na);
    check(1, "stopped");
    if (rt)
        check(npf_runtime_free(rt) == NPF_OK, "runtime: freed after the last instance");
    rm_dir(da);
    rm_dir(db);
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails ? 1 : 0;
}

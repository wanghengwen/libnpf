/* Include the receive queue internals to construct a full window of broken
 * frame starts without depending on packet scheduling / retransmission. */
#include "../../third_party/anliu/anliu.c"
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "media.h"
#include "udpfwd.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)
typedef struct heap { int until_fail, live; } heap;
static void *alloc(void *arg, size_t n)
{
    heap *h = arg;
    void *p;
    if (h->until_fail == 0) return NULL;
    if (h->until_fail > 0) h->until_fail--;
    p = malloc(n);
    if (p) h->live++;
    return p;
}
static void release(void *arg, void *p) { ((heap *)arg)->live--; free(p); }

static int send_failure(int mode, int bytes)
{
    heap h = {-1, 0};
    anl_config cfg;
    anl_stream_opt opt;
    anl_t *w;
    anl_stream_t *s;
    anl_stream_stats before, after;
    uint32_t frame = 12345;
    char data[5000] = {0};
    int err, live, r;
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    cfg.malloc_fn = alloc; cfg.free_fn = release; cfg.alloc_user = &h;
    w = anl_create(123, &cfg, NULL);
    CHECK(w);
    anl_stream_opt_default(&opt, mode);
    opt.stream = bytes;
    opt.flush_on_send = 0;
    opt.fec = 0;
    s = anl_stream_open(w, &opt, &err);
    CHECK(s);
    if (bytes) CHECK(anl_stream_send(s, "prefix", 6) == ANL_OK);
    CHECK(anl_stream_get_stats(s, &before) == ANL_OK);
    live = h.live;
    h.until_fail = 1;   /* first segment / byte-stream replacement succeeds */
    r = mode == ANL_SEMI ? anl_stream_send_frame(s, ANL_FRAME_KEY, data, sizeof data, &frame)
                        : anl_stream_send(s, data, sizeof data);
    CHECK(r == ANL_ENOMEM);
    CHECK(anl_stream_get_stats(s, &after) == ANL_OK);
    CHECK(after.wait_snd == before.wait_snd && after.backlog_bytes == before.backlog_bytes && h.live == live);
    if (mode == ANL_SEMI) CHECK(frame == 12345);
    h.until_fail = -1;
    r = mode == ANL_SEMI ? anl_stream_send_frame(s, ANL_FRAME_KEY, data, sizeof data, &frame)
                        : anl_stream_send(s, data, sizeof data);
    CHECK(r == ANL_OK);
    if (mode == ANL_SEMI) CHECK(frame == 0);
    anl_release(w);
    CHECK(h.live == 0);
    return 0;
}
static int input_length(void)
{
#if LONG_MAX > 0xffffffffL
    anl_config cfg;
    anl_t *w;
    char tiny[64] = {0};
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    w = anl_create(123, &cfg, NULL);
    CHECK(w);
    CHECK(anl_input(w, tiny, (long)(0x100000000ULL + sizeof tiny)) == ANL_EFORMAT);
    anl_release(w);
#endif
    return 0;
}
static int option_limits(void)
{
    anl_config cfg;
    anl_stream_opt opt;
    anl_t *w;
    anl_stream *s;
    int err;
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    w = anl_create(123, &cfg, NULL);
    CHECK(w);
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.max_age_ms = INT_MAX;
    s = anl_stream_open(w, &opt, &err);
    CHECK(s && s->sm->rcv_deadline_ms == (int)((int64_t)INT_MAX * RCV_WAIT_PCT / 100));
    anl_release(w);
    return 0;
}
static void *peek_thread(void *arg)
{
    int r = anl_stream_peeksize(arg);
    return (void *)(intptr_t)r;
}
static int broken_frames(void)
{
    anl_config cfg;
    anl_stream_opt opt;
    anl_t *w;
    anl_stream *s;
    pthread_attr_t attr;
    pthread_t thread;
    void *result;
    unsigned i;
    int err;
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    w = anl_create(123, &cfg, NULL);
    CHECK(w);
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.flush_on_send = 0;
    opt.fec = 0;
    opt.rcv_wnd = ANL_MAX_WND;
    s = anl_stream_open(w, &opt, &err);
    CHECK(s);
    for (i = 0; i < ANL_MAX_WND; i++) {
        anl_seg *seg = seg_new(w, 1);
        CHECK(seg);
        seg->sn = i;
        seg->frg = 1;                       /* the next frame starts where this tail should be */
        seg->frame_no = i;
        seg->flags = F_HAS_FRAME | F_KEY;
        qadd_tail(&seg->node, &s->rcv_queue);
        s->nrcv_que++;
        rcv_bytes_add(w, 1);
    }
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setstacksize(&attr, 1 << 20) == 0);
    CHECK(pthread_create(&thread, &attr, peek_thread, s) == 0);
    pthread_attr_destroy(&attr);
    CHECK(pthread_join(thread, &result) == 0);
    CHECK((intptr_t)result == ANL_EAGAIN && s->nrcv_que == 1 && s->frames_skipped == ANL_MAX_WND - 1);
    anl_release(w);
    return 0;
}

static int media_frames, media_closed;
static int take_media(void *arg, uint32_t id, int tag)
{
    (void)arg; (void)id; (void)tag;
    return 1;
}
static void got_media(void *arg, uint32_t id, const uint8_t *p, size_t n, uint32_t fno, int flags, uint32_t lost)
{
    (void)arg; (void)id; (void)p; (void)n; (void)fno; (void)flags; (void)lost;
    media_frames++;
}
static void closed_media(void *arg, uint32_t id) { (void)arg; (void)id; media_closed++; }

/* Build a completed frame directly, isolating the application's copy limit
 * from packet scheduling and the transport's receive-window limit. */
static int queue_frame(anl_stream *s, uint32_t len)
{
    anl_seg *seg = seg_new(s->w, len);
    if (!seg) return -1;
    memset(seg->data, 0, len);
    seg->flags = F_HAS_FRAME | F_KEY;
    qadd_tail(&seg->node, &s->rcv_queue);
    s->nrcv_que++;
    rcv_bytes_add(s->w, len);
    return 0;
}

static int receive_limits(void)
{
    anl_config cfg;
    anl_stream_opt opt;
    anl_t *w;
    anl_stream *s;
    npf_media *m;
    npf_udpf *u;
    npf_udpf_stats stats;
    npf_media_io mio = {0};
    npf_udpf_io uio = {0};
    int err;
    anl_config_default(&cfg, ANL_ROLE_SERVER);
    w = anl_create(123, &cfg, NULL);
    CHECK(w);
    anl_stream_opt_default(&opt, ANL_SEMI);
    opt.tag = NPF_TAG_MEDIA;
    opt.rcv_wnd = NPF_ANL_MEDIA_WND;
    s = anl_stream_open(w, &opt, &err);
    CHECK(s);
    mio.on_open = take_media; mio.on_frame = got_media; mio.on_closed = closed_media;
    m = npf_media_new(NULL, w, 1, &mio, NULL);
    CHECK(m && npf_media_accept(m, s, &opt) == 0 && npf_media_poll(m) == 0);
    CHECK(queue_frame(s, NPF_MEDIA_FRAME_MAX + 1) == 0);
    CHECK(npf_media_drain(m, s) == 0);
    CHECK(npf_media_count(m) == 0 && media_closed == 1 && media_frames == 0);
    npf_media_free(m);

    opt.tag = NPF_TAG_UDP;
    s = anl_stream_open(w, &opt, &err);
    CHECK(s);
    u = npf_udpf_new(NULL, w, 0, NULL, &uio, NULL);
    CHECK(u && npf_udpf_accept(u, s, &opt) == 0);
    CHECK(queue_frame(s, 65536) == 0);
    npf_udpf_drain(u, s);
    npf_udpf_get_stats(u, &stats);
    CHECK(!npf_udpf_is_stream(u, s) && stats.dropped == 1 && stats.flows == 0);
    npf_udpf_free(u);
    anl_release(w);
    return 0;
}
int main(int argc, char **argv)
{
    int failures = 0;
    (void)argc;
    if (!argv[1] || strcmp(argv[1], "message") == 0) failures += send_failure(ANL_RELIABLE, 0);
    if (!argv[1] || strcmp(argv[1], "bytes") == 0) failures += send_failure(ANL_RELIABLE, 1);
    if (!argv[1] || strcmp(argv[1], "frame") == 0) failures += send_failure(ANL_SEMI, 0);
    if (!argv[1] || strcmp(argv[1], "length") == 0) failures += input_length();
    if (!argv[1] || strcmp(argv[1], "options") == 0) failures += option_limits();
    if (!argv[1] || strcmp(argv[1], "broken_frames") == 0) failures += broken_frames();
    if (!argv[1] || strcmp(argv[1], "receive_limits") == 0) failures += receive_limits();
    return failures != 0;
}

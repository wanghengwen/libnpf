/* Regression cases from the memory / protocol audit. Each case can also run
 * alone, so a sanitizer failure does not hide the other reproductions. */
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/crypto.h"
#include "npf/callee.h"
#include "npf/out.h"
#include "npf/platform.h"
#include "call_internal.h"
#include "../../src/tunnel/tunnel_internal.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

typedef struct fixture {
    npf_tunnel *t;
    int free_ctrl, free_data, recurse, done, reset_result;
    uint8_t control[2048];
    size_t control_len;
} fixture;

static int write_ctrl(void *arg, const uint8_t *p, size_t n)
{
    fixture *f = arg;
    if (n <= sizeof f->control) {
        memcpy(f->control, p, n);
        f->control_len = n;
    }
    if (f->free_ctrl) {
        npf_tunnel_free(f->t);
        f->t = NULL;
    }
    return 0;
}
static int write_data(void *arg, const uint8_t *p, size_t n)
{
    fixture *f = arg;
    (void)p; (void)n;
    if (f->free_data) {
        npf_tunnel_free(f->t);
        f->t = NULL;
    }
    return 0;
}
static size_t backlog(void *arg) { (void)arg; return 0; }
static void sub_done(void *arg, uint32_t id, const npf_sublink_stats *st)
{
    fixture *f = arg;
    (void)st;
    f->done++;
    if (f->recurse && f->done == 1)
        f->reset_result = npf_tunnel_sub_reset(f->t, id, "local_reset");
}
static const npf_tunnel_io io = {write_ctrl, write_data, backlog, NULL, NULL, NULL, NULL, NULL, sub_done};

static void setup(fixture *f, npf_loop *loop)
{
    memset(f, 0, sizeof *f);
    f->t = npf_tunnel_new(loop, 1, &io, f, NULL);
    f->t->hello_sent = f->t->hello_recv = 1;
    f->t->peer_max = NPF_MAX_SUBLINKS;
}
static int data_frame(fixture *f, uint32_t id, const void *p, size_t n)
{
    uint8_t msg[NPF_DATA_HDR + NPF_FRAME_MAX];
    npf_le32(msg, id);
    if (n) memcpy(msg + NPF_DATA_HDR, p, n);
    return npf_tunnel_input_data(f->t, msg, NPF_DATA_HDR + n);
}
static int recursive_reset(npf_loop *loop)
{
    fixture f;
    int sp[2], id;
    setup(&f, loop);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    id = npf_tunnel_open(f.t, sp[0], 0, "127.0.0.1", 80);
    CHECK(id > 0);
    f.recurse = 1;
    CHECK(npf_tunnel_sub_reset(f.t, (uint32_t)id, "local_reset") == 0);
    CHECK(f.done == 1 && f.reset_result == -1 && npf_tunnel_count(f.t) == 0);
    npf_tunnel_free(f.t);
    close(sp[1]);
    return 0;
}
static int start_freed(npf_loop *loop)
{
    fixture f;
    setup(&f, loop);
    f.t->hello_sent = 0;
    f.free_ctrl = 1;
    npf_tunnel_start(f.t);
    CHECK(!f.t);
    return 0;
}
static int open_freed(npf_loop *loop)
{
    fixture f;
    int sp[2], id;
    setup(&f, loop);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    f.free_data = 1;
    id = npf_tunnel_open(f.t, sp[0], 0, "127.0.0.1", 80);
    CHECK(id == -1 && !f.t);
    /* A failed open leaves ownership with its caller. */
    CHECK(send(sp[0], "x", 1, MSG_NOSIGNAL) == 1);
    close(sp[0]);
    close(sp[1]);
    return 0;
}
static int credit_limit(npf_loop *loop)
{
    fixture f;
    uint8_t cu[11] = {NPF_CU_WINDOW, 8, 0};
    int sp[2], id;
    setup(&f, loop);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    id = npf_tunnel_open(f.t, sp[0], 0, "127.0.0.1", 80);
    CHECK(id > 0);
    npf_le32(cu + 3, (uint32_t)id);
    npf_le32(cu + 7, UINT32_MAX);
    CHECK(npf_tunnel_input_ctrl(f.t, cu, sizeof cu) == 0);
    CHECK(npf_tunnel_count(f.t) == 0 && f.done == 1);
    npf_tunnel_free(f.t);
    close(sp[1]);
    return 0;
}
static int reply_json(npf_loop *loop)
{
    fixture f;
    npf_call c = {0};
    npf_json j, out;
    npf_jtok tok[32], otok[64];
    const char req[] = "{\"id\":\"a\\\"b\\\\c\"}";
    char id[24];
    setup(&f, loop);
    c.tun = f.t;
    CHECK(npf_json_parse(&j, req, sizeof req - 1, tok, 32) == 0);
    CHECK(npf_call_ctl_reply(&c, "bad\"type", &j, "error", "bad\"error", NULL) == 0);
    CHECK(f.control_len > NPF_CU_HDR);
    CHECK(npf_json_parse(&out, (char *)f.control + NPF_CU_HDR, f.control_len - NPF_CU_HDR, otok, 64) == 0);
    CHECK(npf_json_get_str(&out, 0, "reply_to", id, sizeof id) > 0 && strcmp(id, "a\"b\\c") == 0);
    npf_tunnel_free(f.t);
    return 0;
}
static void ctl_done(npf_call *c, const npf_json *j, int ok, void *arg)
{
    (void)c; (void)j; (void)ok;
    if (arg) (*(int *)arg)++;
}
static int ctl_sequence(npf_loop *loop)
{
    fixture f;
    npf_call c = {0};
    int i;
    setup(&f, loop);
    c.tun = f.t;
    c.ctl_seq = INT_MAX;
    CHECK(npf_call_ctl_request(&c, "test", NULL, NULL, NULL) == -1);
    /* A response callback is required to reserve a request slot. */
    for (i = 0; i < NPF_CALL_CTL_MAX; i++) CHECK(!c.ctl[i].fn);
    c.ctl[0].id = 1;
    c.ctl[0].fn = ctl_done;
    CHECK(npf_call_ctl_request(&c, "test", NULL, ctl_done, NULL) == 0);
    CHECK(c.ctl_seq == 2 && c.ctl[1].id == 2);
    npf_tunnel_free(f.t);
    {
        npf_node n = {0};
        n.req_seq = INT_MAX;
        CHECK(npf_node_send(&n, "test", 1, NULL) == -1 && n.req_seq == INT_MAX);
    }
    return 0;
}

static int ctl_matching(npf_loop *loop)
{
    static const char *invalid[] = {"x7", "c7tail", "c07", "c2147483648", "c999999999999999999999"};
    npf_node n = {0};
    npf_call c = {0};
    uint8_t unit[160];
    size_t i;
    int calls = 0, len;
    n.loop = loop;
    c.n = &n;
    c.caller = 1;
    c.tun = call_tunnel_new(&c);
    CHECK(c.tun);
    c.ctl[0].id = 7; c.ctl[0].fn = ctl_done; c.ctl[0].arg = &calls;
    for (i = 0; i <= sizeof invalid / sizeof invalid[0]; i++) {
        const char *id = i == sizeof invalid / sizeof invalid[0] ? "c7" : invalid[i];
        len = snprintf((char *)unit + 3, sizeof unit - 3,
                       "{\"type\":\"test\",\"reply_to\":\"%s\",\"status\":\"ok\"}", id);
        unit[0] = NPF_CU_JSON;
        npf_le16(unit + 1, (uint16_t)len);
        CHECK(npf_tunnel_input_ctrl(c.tun, unit, 3 + (size_t)len) == 0);
        CHECK(calls == (i == sizeof invalid / sizeof invalid[0]));
    }
    npf_tunnel_free(c.tun);
    return 0;
}

static int gone_window(npf_loop *loop)
{
    fixture f;
    int sp[2], id, i;
    uint8_t data[NPF_FRAME_MAX] = {0};
    setup(&f, loop);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    id = npf_tunnel_open(f.t, sp[0], 0, "127.0.0.1", 80);
    CHECK(id > 0);
    tunnel_find(f.t, (uint32_t)id)->gone = 1;
    for (i = 0; i <= NPF_INIT_WINDOW / NPF_FRAME_MAX; i++)
        CHECK(data_frame(&f, (uint32_t)id, data, sizeof data) == 0);
    CHECK(npf_tunnel_count(f.t) == 0 && f.done == 1);
    npf_tunnel_free(f.t);
    close(sp[1]);
    return 0;
}

static int input_fairness(npf_loop *loop)
{
    npf_call c = {0};
    struct sockaddr_in a = {0};
    socklen_t al = sizeof a;
    int in = npf_socket(AF_INET, SOCK_DGRAM, 0, 0), out = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
    int sz = 4 << 20, i, remaining = 0;
    char byte;
    CHECK(in >= 0 && out >= 0);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(in, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(getsockname(in, (struct sockaddr *)&a, &al) == 0);
    CHECK(setsockopt(in, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz) == 0);
    for (i = 0; i < 300; i++)
        CHECK(sendto(out, "x", 1, 0, (struct sockaddr *)&a, sizeof a) == 1);
    call_p2p_input_cb(loop, in, NPF_EV_READ, &c);
    while (recv(in, &byte, 1, MSG_DONTWAIT) == 1) remaining++;
    CHECK(remaining > 0);                   /* one event cannot drain an unbounded flood */
    close(in); close(out);
    return 0;
}

static int buffer_lengths(npf_loop *loop)
{
    npf_jw w;
    wbuf b = {0};
    char buf[16];
    (void)loop;
    npf_jw_init(&w, buf, sizeof buf);
    npf_jw_raw(&w, "x", SIZE_MAX);
    CHECK(npf_jw_finish(&w) == -1);
    b.len = 1;
    CHECK(tunnel_wb_put(&b, "x", SIZE_MAX) == -1 && !b.p);
    return 0;
}

static int crypto_lengths(npf_loop *loop)
{
    npf_noise_hs hs;
    npf_noise_cs cs = {0};
    uint8_t psk[32] = {1}, out[256];
    (void)loop;
    CHECK(npf_noise_init(&hs, NPF_NOISE_NNPSK0, 1, "test", 4, NULL, NULL, psk) == 0);
    CHECK(npf_noise_write(&hs, (const uint8_t *)"x", SIZE_MAX, out, sizeof out) == -1);
    CHECK(npf_noise_encrypt(&cs, NULL, 0, (const uint8_t *)"x", SIZE_MAX, out) == -1 && cs.n == 0);
    CHECK(npf_noise_decrypt(&cs, NULL, 0, (const uint8_t *)"x", SIZE_MAX, out) == -1 && cs.n == 0);
    npf_wipe(&hs, sizeof hs);
    return 0;
}

static ssize_t idle_read(void *arg, uint8_t *p, size_t n) { (void)arg; (void)p; (void)n; return -1; }
static ssize_t idle_write(void *arg, const uint8_t *p, size_t n) { (void)arg; (void)p; return (ssize_t)n; }
static unsigned idle_ready(void *arg) { (void)arg; return 0; }
static void idle_shutdown(void *arg) { (void)arg; }
static void idle_closed(void *arg, int reset) { (void)arg; (void)reset; }
static const npf_vend_io idle_io = {idle_read, idle_write, idle_ready, idle_shutdown, idle_closed};
static int gone_buffer(npf_loop *loop)
{
    fixture f;
    sublink *s;
    int id;
    setup(&f, loop);
    id = npf_tunnel_open_v(f.t, &idle_io, NULL, "127.0.0.1", 80);
    CHECK(id > 0);
    s = tunnel_find(f.t, (uint32_t)id);
    s->wq.p = malloc(NPF_INIT_WINDOW);
    CHECK(s->wq.p);
    s->wq.cap = NPF_INIT_WINDOW;
    s->wq.len = 100;
    npf_tunnel_vclose(f.t, (uint32_t)id, 0);
    npf_loop_once(loop, 0);
    s = tunnel_find(f.t, (uint32_t)id);
    CHECK(s && s->gone && !s->wq.p && !s->wq.cap && s->rx_freed == 100);
    npf_tunnel_free(f.t);
    return 0;
}
static int idle_rate(npf_loop *loop)
{
    npf_tunnel t = {0};
    sublink s = {0};
    rgroup g = {0};
    t.loop = loop;
    s.t = &t; s.rg = &g;
    g.rate = UINT32_MAX;
    g.at_ms = npf_mono_ms() - 4000000000LL;
    CHECK(tunnel_rate_allow(&s, 1, 16) == 16 && g.up == UINT32_MAX);
    return 0;
}

typedef struct grow_state { int fd[128], done; } grow_state;
static void noop_event(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    (void)loop; (void)fd; (void)ev; (void)arg;
}
static void grow_event(npf_loop *loop, int fd, unsigned ev, void *arg)
{
    grow_state *g = arg;
    char b;
    int i;
    (void)ev;
    recv(fd, &b, 1, 0);
    for (i = 0; i < 128; i++) {
        g->fd[i] = npf_socket(AF_INET, SOCK_DGRAM, 0, 0);
        if (g->fd[i] >= 0)
            npf_loop_add(loop, g->fd[i], NPF_EV_READ, noop_event, NULL);
    }
    npf_sleep_ms(1001);                      /* triggers TIMED's diagnostic after handler-array growth */
    g->done = 1;
}
static void slow_callback(npf_loop *unused)
{
    npf_loop *l = npf_loop_new();
    grow_state g = {{0}, 0};
    int sp[2], i;
    (void)unused;
    if (!l || socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) abort();
    if (npf_loop_add(l, sp[0], NPF_EV_READ, grow_event, &g) < 0) abort();
    if (send(sp[1], "x", 1, 0) != 1) abort();
    npf_loop_once(l, 100);
    if (!g.done) abort();
    for (i = 0; i < 128; i++) if (g.fd[i] >= 0) npf_sock_close(g.fd[i]);
    close(sp[0]); close(sp[1]);
    npf_loop_free(l);
}
static int loop_callbacks(npf_loop *loop)
{
    slow_callback(loop);
    return 0;
}
static void timer_flag(npf_loop *loop, void *arg) { (void)loop; (*(int *)arg)++; }
static int timer_limit(npf_loop *loop)
{
    int called = 0;
    npf_timer *t = npf_timer_add(loop, INT64_MAX, timer_flag, &called);
    CHECK(t);
    npf_loop_once(loop, 0);
    CHECK(!called);
    npf_timer_cancel(loop, t);
    return 0;
}
static int callee_time(npf_loop *loop)
{
    npf_callee d = {0};
    npf_out out = {0};
    (void)loop;
    d.npaired = 1;
    d.paired[0].added = INT64_MAX;
    npf_callee_show(&d, &out);
    CHECK(!out.failed && strstr(out.p, "unknown"));
    npf_out_free(&out);
    return 0;
}
static int callee_lock(npf_loop *loop)
{
    npf_callee d;
    npf_node node = {0};
    uint8_t seed[32] = {0};
    char dir[] = "/tmp/npf-audit-lock-XXXXXX", path[128];
    CHECK(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/state", dir);
    CHECK(npf_callee_init(&d, path, 123, seed, "password") == 0);
    node.loop = loop;
    npf_callee_attach(&d, &node);
    npf_timer_cancel(loop, d.t_watch);
    d.t_watch = NULL;
    d.node = NULL;
    d.fails = 4;
    d.lock_secs = INT64_MAX;                 /* a syntactically valid local state value */
    d.ops.pair_failed(&node, &d);
    CHECK(d.lock_secs == 86400 && d.locked_until > time(NULL));
    unlink(path);
    rmdir(dir);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*fn)(npf_loop *); } cases[] = {
        {"recursive_reset", recursive_reset}, {"start_freed", start_freed},
        {"open_freed", open_freed}, {"credit_limit", credit_limit},
        {"reply_json", reply_json}, {"ctl_sequence", ctl_sequence},
        {"ctl_matching", ctl_matching}, {"gone_window", gone_window},
        {"input_fairness", input_fairness}, {"buffer_lengths", buffer_lengths},
        {"crypto_lengths", crypto_lengths}, {"gone_buffer", gone_buffer}, {"idle_rate", idle_rate},
        {"loop_callbacks", loop_callbacks}, {"timer_limit", timer_limit}, {"callee_time", callee_time},
        {"callee_lock", callee_lock}
    };
    npf_loop *loop = npf_loop_new();
    size_t i;
    int failures = 0;
    CHECK(loop);
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (argc == 1 || strcmp(argv[1], cases[i].name) == 0)
            failures += cases[i].fn(loop);
    npf_loop_free(loop);
    return failures != 0;
}

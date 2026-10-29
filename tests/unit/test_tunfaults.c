/* The tunnel without memory for a local read (npf_scratch failing): the
 * sublink is reset, not read again at each event (the loop is
 * level-triggered: it would spin). */
#define _GNU_SOURCE
#include <stddef.h>
void *test_scratch(size_t n);
#define npf_scratch test_scratch
#include "../../src/tunnel/tunnel.c"
#undef npf_scratch

void *npf_scratch(size_t n);
static int failing, reads, closed, reset;
void *test_scratch(size_t n) { return failing ? NULL : npf_scratch(n); }

static int w_ctrl(void *arg, const uint8_t *buf, size_t len) { (void)arg; (void)buf; (void)len; return 0; }
static int w_data(void *arg, const uint8_t *msg, size_t len) { (void)arg; (void)msg; (void)len; return 0; }
static size_t backlog(void *arg) { (void)arg; return 0; }
static ssize_t v_read(void *arg, uint8_t *buf, size_t cap)
{
    (void)arg;
    reads++;
    memset(buf, 'x', cap < 100 ? cap : 100);
    return cap < 100 ? (ssize_t)cap : 100;
}
static ssize_t v_write(void *arg, const uint8_t *buf, size_t len) { (void)arg; (void)buf; return (ssize_t)len; }
static unsigned v_ready(void *arg) { (void)arg; return NPF_EV_READ; }  /* always something to read */
static void v_shutdown(void *arg) { (void)arg; }
static void v_closed(void *arg, int r)
{
    (void)arg;
    closed++;
    reset = r;
}

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
int main(void)
{
    static const npf_tunnel_io io = {w_ctrl, w_data, backlog, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    static const npf_vend_io v = {v_read, v_write, v_ready, v_shutdown, v_closed};
    npf_loop *loop = npf_loop_new();
    npf_tunnel *t;
    int i;
    CHECK(loop && (t = npf_tunnel_new(loop, 1, &io, NULL, NULL)));
    npf_tunnel_start(t);                    /* the caller's hello */
    npf_tunnel_open_early(t);               /* sublinks before the callee's */
    failing = 1;
    CHECK(npf_tunnel_open_v(t, &v, NULL, "127.0.0.1", 80) > 0);
    for (i = 0; i < 20 && !closed; i++)
        npf_loop_once(loop, 1);
    CHECK(closed == 1 && reset && reads == 0 && npf_tunnel_count(t) == 0);
    failing = 0;
    npf_tunnel_free(t);
    npf_loop_free(loop);
    puts("PASS no memory for a local read: the sublink is reset");
    return 0;
}

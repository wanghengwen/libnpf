/* The tunnel without memory (npf_scratch failing): a sublink whose local
 * read finds none is reset, not read again at each event (the loop is
 * level-triggered: it would spin); a -D application whose request cannot
 * be passed on after its greeting was answered is reset, not left half
 * greeted (its next bytes were parsed as a greeting again). */
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/socket.h>
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
    {   /* -D: the greeting and a CONNECT to a long name (no room on the stack for it) */
        uint8_t req[3 + 5 + 100 + 2] = {5, 1, 0, 5, 1, 0, 3, 100}, b[4];
        int sp[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
        memset(req + 8, 'a', 100);
        CHECK(npf_tunnel_open(t, sp[0], 1, NULL, 0) > 0 && write(sp[1], req, sizeof req) == (ssize_t)sizeof req);
        for (i = 0; i < 20 && npf_tunnel_count(t); i++)
            npf_loop_once(loop, 1);
        CHECK(npf_tunnel_count(t) == 0 && recv(sp[1], b, sizeof b, 0) == 2 && b[0] == 5 && b[1] == 0);
        close(sp[1]);
    }
    failing = 0;
    npf_tunnel_free(t);
    npf_loop_free(loop);
    puts("PASS no memory for a local read or a -D request: the sublink is reset");
    return 0;
}

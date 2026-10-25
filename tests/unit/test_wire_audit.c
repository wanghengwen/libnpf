/* Private parser / lifecycle entry points, compiled as in fuzz/net.c. */
#include "../../src/proto/http.c"
#include "../../src/ws/ws.c"
#include <stdio.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

static int closed;
static void close_from_callback(npf_ws *ws, int code, const char *why, void *arg)
{
    (void)code; (void)why; (void)arg;
    closed++;
    npf_ws_free(ws);
}
static void cancel_from_callback(int status, const uint8_t *body, size_t len, const char *err, void *arg)
{
    (void)status; (void)body; (void)len; (void)err;
    npf_http_cancel(arg);
}
int main(int argc, char **argv)
{
    (void)argc;
    if (!argv[1] || strcmp(argv[1], "ws_close") == 0) {
        npf_ws *ws = calloc(1, sizeof *ws);
        CHECK(ws);
        ws->fd = -1;
        ws->state = ST_RESOLVING;
        ws->cbs.on_close = close_from_callback;
        ws_fail(ws, 0, "resolution failed");
        CHECK(closed == 1);
    }
    if (!argv[1] || strcmp(argv[1], "http_cancel") == 0) {
        npf_http *h = calloc(1, sizeof *h);
        CHECK(h);
        h->fd = -1;
        h->fn = cancel_from_callback;
        h->arg = h;
        h_fail(h, "read failed");
    }
    if (!argv[1] || strcmp(argv[1], "lengths") == 0) {
        npf_ws ws = {0};
        buf b = {0};
        int tls, port;
        char host[256], path[512];
        CHECK(npf_url_parse("ws://example.com/a\r\nInjected: yes", &tls, host, sizeof host, &port, path, sizeof path) == -1);
        CHECK(send_frame2(&ws, 2, "x", 1, "x", SIZE_MAX) == -1 && ws.out.len == 0);
        b.len = 1;
        CHECK(buf_room(&b, SIZE_MAX) == -1 && !b.p);
    }
    return 0;
}

/* White-box harnesses: exercise production parsers without a network peer.
 * Their public symbols satisfy the static archive's references in this binary. */
#include "../../src/proto/http.c"
#include "../../src/ws/ws.c"

static void discard_http(int status, const uint8_t *body, size_t len, const char *err, void *arg)
{
    (void)status; (void)body; (void)len; (void)err; (void)arg;
}
static void discard_ws(npf_ws *ws, const uint8_t *data, size_t len, int binary, void *arg)
{
    (void)ws; (void)data; (void)len; (void)binary; (void)arg;
}

void npf_fuzz_http(const uint8_t *data, size_t len)
{
    npf_http *h = calloc(1, sizeof *h);
    if (!h) return;
    h->fd = -1;
    h->fn = discard_http;
    h->in = malloc(len + 1);
    if (!h->in) { free(h); return; }
    memcpy(h->in, data, len);
    h->in[len] = 0;
    h->in_len = len;
    (void)h_body_complete(h);
    h_response(h);
}

void npf_fuzz_ws(const uint8_t *data, size_t len)
{
    npf_ws *ws = calloc(1, sizeof *ws);
    size_t split = len / 2;
    if (!ws) return;
    ws->fd = -1;
    ws->busy = 1;
    ws->state = ST_OPEN;
    ws->cbs.on_message = discard_ws;
    if (buf_put(&ws->in, data, split) == 0 && parse_frames(ws) == 0
        && buf_put(&ws->in, data + split, len - split) == 0)
        parse_frames(ws);
    real_free(ws);
}

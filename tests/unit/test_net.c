/* HTTP and WebSocket parsing at their boundaries (the fuzz harness's parsers
 * themselves), and the TCP connect's fallback to a name's next address. */
#include "../fuzz/net.c"
#include <assert.h>
#include "test.h"

static char closed_why[128];
static int http_failed;
static void note_http(int status, const uint8_t *body, size_t len, const char *err, void *arg)
{
    (void)status; (void)body; (void)len; (void)arg;
    http_failed += err != NULL;
}
static void capture_close(npf_ws *ws, int code, const char *why, void *arg)
{
    (void)ws; (void)code; (void)arg;
    snprintf(closed_why, sizeof closed_why, "%s", why);
}

int main(void)
{
    static const char *bad[] = {
        "ffffffffffffffff\r\nX\r\n0\r\n\r\n", "10000000000000000\r\nX\r\n", "-1\r\nX\r\n",
        "+1\r\na\r\n0\r\n\r\n", "1z\r\na\r\n0\r\n\r\n", "1\r\naXX0\r\n\r\n", "0\r\n"
    };
    size_t i;
    char good[] = "3;foo=bar\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\n";
    uint8_t frame[] = {0x00, 0, 0x80, 1, 'x'};
    npf_ws *ws;
    npf_loop *loop;
    npf_http *h;
    struct sockaddr_storage a[2];
    socklen_t al[2];
    int server, rejected, k;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char *copy = strdup(bad[i]);
        REQUIRE(chunk_body((uint8_t *)copy, strlen(copy), 1) < 0);
        free(copy);
    }
    REQUIRE(chunk_body((uint8_t *)good, strlen(good), 1) == 3 && memcmp(good, "abc", 3) == 0);
    {
        char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab";
        char chunks[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n";
        npf_http framed = {0};
        framed.in = (uint8_t *)response; framed.in_len = strlen(response);
        REQUIRE(!h_body_complete(&framed));
        /* A complete framed body needs no connection EOF. */
        *strstr(response, "3") = '2';
        REQUIRE(h_body_complete(&framed));
        framed.in = (uint8_t *)chunks; framed.in_len = strlen(chunks);
        REQUIRE(h_body_complete(&framed));
        REQUIRE(strstr(chunks, "1\r\na\r\n0") != NULL); /* readiness must not decode in place */
        framed.in_len -= 2; chunks[framed.in_len] = 0;
        REQUIRE(!h_body_complete(&framed));
    }
    ws = calloc(1, sizeof *ws);
    ws->tcp.fd = -1; ws->busy = 1; ws->state = ST_OPEN; ws->cbs.on_message = discard_ws;
    REQUIRE(buf_put(&ws->in, frame, 2) == 0 && parse_frames(ws) < 0); /* stray continuation */
    ws->in.len = 0;
    frame[0] = 0x02; /* an empty initial fragment must still open a fragmented message */
    REQUIRE(buf_put(&ws->in, frame, sizeof frame) == 0 && parse_frames(ws) == 0 && !ws->frag_active);
    real_free(ws);

    /* A ping flood from a peer that reads nothing: pongs stop at 64 KB of
     * queue; all the tiny frames are taken in one pass. */
    ws = calloc(1, sizeof *ws);
    ws->tcp.fd = -1; ws->busy = 1; ws->state = ST_OPEN; ws->cbs.on_message = discard_ws;
    for (k = 0; k < 30000; k++)
        REQUIRE(buf_put(&ws->in, "\x89\x00", 2) == 0);
    REQUIRE(parse_frames(ws) == 0 && ws->in.len == 0);
    REQUIRE(ws->out.len > 0 && ws->out.len <= 65536 + 16);
    real_free(ws);
    /* A close reason reaches the log without control characters. */
    ws = calloc(1, sizeof *ws);
    ws->tcp.fd = -1; ws->busy = 1; ws->state = ST_OPEN; ws->cbs.on_message = discard_ws; ws->cbs.on_close = capture_close;
    {
        static const uint8_t cf[] = {0x88, 7, 0x03, 0xe8, 'a', '\n', 'b', 0x1b, 'c'};
        REQUIRE(buf_put(&ws->in, cf, sizeof cf) == 0 && parse_frames(ws) == -2 && strcmp(closed_why, "a?b?c") == 0);
    }
    real_free(ws);
    /* An HTTP body over max is refused, not taken up to twice that. */
    {
        static char big[2300];
        npf_http *hb = calloc(1, sizeof *hb);
        int n = snprintf(big, sizeof big, "HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n");
        memset(big + n, 'x', 2000);
        hb->tcp.fd = -1; hb->max = 1024; hb->fn = discard_http;
        hb->in = malloc((size_t)n + 2001);
        memcpy(hb->in, big, (size_t)n + 2000);
        hb->in_len = (size_t)n + 2000;
        hb->in[hb->in_len] = 0;
        http_failed = 0;
        hb->fn = note_http;
        h_response(hb);                     /* frees hb */
        REQUIRE(http_failed == 1);
    }

    /* First address refuses asynchronously; the second accepts. No DNS dependency. */
    loop = npf_loop_new();
    REQUIRE(loop);
    rejected = lo_socket(SOCK_STREAM, 8, &a[0], sizeof a[0]);
    server = lo_socket(SOCK_STREAM, 8, &a[1], sizeof a[1]);
    al[0] = al[1] = sizeof(struct sockaddr_in);
    REQUIRE(rejected >= 0 && server >= 0);
    npf_sock_close(rejected);
    ws = calloc(1, sizeof *ws);
    ws->loop = loop;
    npf_tcp_init(&ws->tcp, loop, ws->host, on_io, ws_tcp_failed, ws);
    strcpy(ws->host, "localhost"); strcpy(ws->path, "/"); ws->tcp.port = 80;
    memcpy(ws->tcp.cand, a, sizeof a); memcpy(ws->tcp.cand_len, al, sizeof al); ws->tcp.ncand = 2;
    REQUIRE(tcp_next(&ws->tcp) == 0);
    LOOP_UNTIL(loop, ws->state != ST_CONNECTING, 2000);
    REQUIRE(ws->state == ST_UPGRADE && ws->tcp.icand == 2);
    {   /* a peer reading slowly: what is left is written later, in order, frames queued meanwhile behind it */
        static uint8_t got[1 << 21], msg[1000];
        size_t glen = 0, at = 0;
        int64_t t0;
        int peer = accept(server, NULL, NULL), small = 4096, i, k, partial = 0;
        REQUIRE(peer >= 0 && fcntl(peer, F_SETFL, O_NONBLOCK) == 0);
        setsockopt(ws->tcp.fd, SOL_SOCKET, SO_SNDBUF, (const char *)&small, sizeof small);
        for (k = 0; k < 1000 && !find_mem(got, glen, "\r\n\r\n", 4); k++) {     /* the upgrade request */
            ssize_t r;
            REQUIRE(flush_out(ws) == 0);
            r = recv(peer, (char *)got + glen, 8192, 0);
            glen += r > 0 ? (size_t)r : 0;
        }
        REQUIRE(ws->out.len == 0 && find_mem(got, glen, "\r\n\r\n", 4) == (char *)got + glen - 4);
        glen = 0;
        ws->state = ST_OPEN;
        for (i = 0; i < 1500; i++) {
            memset(msg, (uint8_t)i, sizeof msg);
            msg[0] = (uint8_t)(i >> 8);
            REQUIRE(send_frame(ws, 2, msg, sizeof msg) == 0);
            if (i % 20 == 19) {
                REQUIRE(flush_out(ws) == 0);
                partial |= ws->out_off > 0;
            }
            if (i % 40 == 39) {
                ssize_t r = recv(peer, (char *)got + glen, 8192, 0);
                glen += r > 0 ? (size_t)r : 0;
            }
        }
        for (t0 = npf_mono_ms(); npf_mono_ms() - t0 < 5000 && (out_left(ws) || glen < 1500 * 1008);) {
            ssize_t r;
            REQUIRE(flush_out(ws) == 0);
            r = recv(peer, (char *)got + glen, sizeof got - glen, 0);
            glen += r > 0 ? (size_t)r : 0;
        }
        REQUIRE(ws->out.len == 0 && ws->out_off == 0 && glen == 1500 * 1008);
        for (i = 0; i < 1500; i++, at += 1008) {    /* 2 + 2 (126) + 4 (mask) + 1000 */
            const uint8_t *f = got + at, *m = f + 4;
            REQUIRE(f[0] == 0x82 && f[1] == (0x80 | 126) && f[2] == 1000 >> 8 && f[3] == (1000 & 255));
            REQUIRE((f[8] ^ m[0]) == (uint8_t)(i >> 8) && (f[9] ^ m[1]) == (uint8_t)i
                    && (f[1007] ^ m[999 & 3]) == (uint8_t)i);
        }
        REQUIRE(partial);
        npf_sock_close(peer);
    }
    npf_ws_free(ws);
    h = calloc(1, sizeof *h);
    h->loop = loop; h->max = 1024; h->fn = discard_http;
    npf_tcp_init(&h->tcp, loop, h->host, h_io, h_tcp_failed, h);
    memcpy(h->tcp.cand, a, sizeof a); memcpy(h->tcp.cand_len, al, sizeof al); h->tcp.ncand = 2;
    strcpy(h->req, "GET / HTTP/1.0\r\n\r\n"); h->req_len = strlen(h->req);
    REQUIRE(tcp_next(&h->tcp) == 0);
    LOOP_UNTIL(loop, h->state != H_CONNECTING, 2000);
    REQUIRE(h->state == H_READ && h->tcp.icand == 2);
    h_free(h);
    npf_sock_close(server);
    npf_loop_free(loop);
    puts("PASS HTTP boundaries, WS fragmentation and multi-address fallback");
    return 0;
}

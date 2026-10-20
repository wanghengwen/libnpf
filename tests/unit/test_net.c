#include "../fuzz/net.c"
#include <assert.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static int listen_local(struct sockaddr_storage *addr, socklen_t *len)
{
    int fd = npf_socket(AF_INET, SOCK_STREAM, 0, 0);
    struct sockaddr_in *a = (struct sockaddr_in *)addr;
    memset(addr, 0, sizeof *addr);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *len = sizeof *a;
    if (fd < 0 || bind(fd, (struct sockaddr *)a, *len) < 0
        || getsockname(fd, (struct sockaddr *)a, len) < 0 || listen(fd, 8) < 0)
        return -1;
    return fd;
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
        CHECK(dechunk((uint8_t *)copy, strlen(copy)) < 0);
        free(copy);
    }
    CHECK(dechunk((uint8_t *)good, strlen(good)) == 3 && memcmp(good, "abc", 3) == 0);
    {
        char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab";
        char chunks[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n";
        npf_http framed = {0};
        framed.in = (uint8_t *)response; framed.in_len = strlen(response);
        CHECK(!h_body_complete(&framed));
        /* A complete framed body needs no connection EOF. */
        *strstr(response, "3") = '2';
        CHECK(h_body_complete(&framed));
        framed.in = (uint8_t *)chunks; framed.in_len = strlen(chunks);
        CHECK(h_body_complete(&framed));
        CHECK(strstr(chunks, "1\r\na\r\n0") != NULL); /* readiness must not decode in place */
        framed.in_len -= 2; chunks[framed.in_len] = 0;
        CHECK(!h_body_complete(&framed));
    }
    ws = calloc(1, sizeof *ws);
    ws->fd = -1; ws->busy = 1; ws->state = ST_OPEN; ws->cbs.on_message = discard_ws;
    CHECK(buf_put(&ws->in, frame, 2) == 0 && parse_frames(ws) < 0); /* stray continuation */
    ws->in.len = 0;
    frame[0] = 0x02; /* an empty initial fragment must still open a fragmented message */
    CHECK(buf_put(&ws->in, frame, sizeof frame) == 0 && parse_frames(ws) == 0 && !ws->frag_active);
    real_free(ws);

    /* First address refuses asynchronously; the second accepts. No DNS dependency. */
    loop = npf_loop_new();
    CHECK(loop);
    rejected = listen_local(&a[0], &al[0]);
    server = listen_local(&a[1], &al[1]);
    CHECK(rejected >= 0 && server >= 0);
    npf_sock_close(rejected);
    ws = calloc(1, sizeof *ws);
    ws->fd = -1; ws->loop = loop;
    strcpy(ws->host, "localhost"); strcpy(ws->path, "/"); ws->port = 80;
    CHECK(start_connect(ws, a, al, 2) == 0);
    for (k = 0; k < 200 && ws->state == ST_CONNECTING; k++) npf_loop_once(loop, 10);
    CHECK(ws->state == ST_UPGRADE && ws->icand == 2);
    npf_ws_free(ws);
    h = calloc(1, sizeof *h);
    h->fd = -1; h->loop = loop; h->max = 1024; h->fn = discard_http;
    memcpy(h->cand, a, sizeof a); memcpy(h->cand_len, al, sizeof al); h->ncand = 2;
    strcpy(h->req, "GET / HTTP/1.0\r\n\r\n"); h->req_len = strlen(h->req);
    CHECK(h_next(h) == 0);
    for (k = 0; k < 200 && h->state == H_CONNECTING; k++) npf_loop_once(loop, 10);
    CHECK(h->state == H_READ && h->icand == 2);
    h_free(h);
    npf_sock_close(server);
    npf_loop_free(loop);
    puts("PASS HTTP boundaries, WS fragmentation and multi-address fallback");
    return 0;
}

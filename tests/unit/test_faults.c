#define _GNU_SOURCE
#include <stdlib.h>
static void *test_realloc(void *p, size_t size);
#define realloc test_realloc
#include "../../src/platform/out.c"
#undef realloc
#include "npf/local.h"
#define npf_ws_send test_ws_send
#define npf_ws_free test_ws_free
#include "../../src/proto/wsrelay.c"
#undef npf_ws_send
#undef npf_ws_free
#include <unistd.h>

static int failing, sends, gone, left;
static void *test_realloc(void *p, size_t size) { return failing && size > 256 ? NULL : realloc(p, size); }
int test_ws_send(npf_ws *ws, const void *data, size_t len, int binary)
{
    (void)ws; (void)data; (void)len; (void)binary;
    return ++sends == 1 ? -1 : 0;
}
void test_ws_free(npf_ws *ws) { (void)ws; }
static void relay_gone(npf_wsr *r, const char *why, void *arg)
{
    (void)why; (void)arg;
    if (r)
        left++;
    else
        gone++;
}
static int paired, paired_udp;
static void relay_paired(npf_wsr *r, int peer_udp, void *arg)
{
    (void)r; (void)arg;
    paired++;
    paired_udp = peer_udp;
}
/* a relay connection as npf_wsr_open makes it, on no WebSocket */
static npf_wsr *relay_new(npf_loop *loop)
{
    npf_wsr *r = calloc(1, sizeof *r);
    if (!r)
        abort();
    r->loop = loop;
    r->cbs.gone = relay_gone;
    r->cbs.paired = relay_paired;
    r->ws = (npf_ws *)r;                /* not used: npf_ws_send, npf_ws_free are the test's */
    return r;
}
static void msg_in(npf_wsr *r, uint8_t type, uint8_t ev, size_t len)
{
    uint8_t m[2] = {type, ev};
    ws_msg(NULL, m, len, 1, r);
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
int main(void)
{
    npf_local l = {0};
    char dir[] = "/tmp/npf-faults-XXXXXX", value[400], *before = NULL, *after = NULL;
    long len;
    npf_wsr *r;
    npf_loop *loop;
    CHECK(mkdtemp(dir));
    snprintf(l.path, sizeof l.path, "%s/local.json", dir);
    memset(value, 'a', sizeof value - 1); value[sizeof value - 1] = 0;
    npf_conf_set(&l.settings, "server", value);
    CHECK(npf_local_save(&l) == 0);
    len = npf_file_read(l.path, &before);
    failing = 1;
    CHECK(npf_local_save(&l) < 0);
    failing = 0;
    CHECK(npf_file_read(l.path, &after) == len && memcmp(before, after, (size_t)len) == 0);
    free(before); free(after); unlink(l.path); rmdir(dir);
    npf_local_free(&l);

    loop = npf_loop_new();
    CHECK(loop);
    r = relay_new(loop);
    ws_open(NULL, r);                   /* the bind not sent */
    CHECK(gone == 1 && sends == 1);
    npf_loop_once(loop, 0);

    /* the relay's events, one byte each; anything else ends the connection */
    r = relay_new(loop);
    gone = 0;
    msg_in(r, NPF_WSR_CTL, 9, 2);
    CHECK(gone == 1 && !paired);
    r = relay_new(loop);
    gone = 0;
    msg_in(r, NPF_WSR_CTL, NPF_WSR_PAIRED, 2);
    CHECK(paired == 1 && r->paired && !gone && !paired_udp);
    /* the peer on a UDP allocation (the relay bridges): told */
    msg_in(r, NPF_WSR_CTL, NPF_WSR_PAIRED_UDP, 2);
    CHECK(paired == 2 && paired_udp);
    msg_in(r, NPF_WSR_ANL, 0, 1);       /* an empty datagram: nothing */
    msg_in(r, NPF_WSR_CTL, NPF_WSR_PEER_GONE, 2);
    CHECK(left == 1 && !gone && r->paired);     /* told, still paired: the peer comes back */
    msg_in(r, NPF_WSR_CTL, NPF_WSR_PAIRED, 1);
    CHECK(gone == 1);                   /* closed and freed (wsr_down) */
    npf_loop_once(loop, 0);
    npf_loop_free(loop);
    puts("PASS failed serialization preserves the file; failed relay bind releases once; the relay's events");
    return 0;
}

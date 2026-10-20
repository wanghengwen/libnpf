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

static int failing, sends, gone;
static void *test_realloc(void *p, size_t size) { return failing && size > 256 ? NULL : realloc(p, size); }
int test_ws_send(npf_ws *ws, const void *data, size_t len, int binary)
{
    (void)ws; (void)data; (void)len; (void)binary;
    return ++sends == 2 ? -1 : 0;
}
void test_ws_free(npf_ws *ws) { (void)ws; }
static void relay_gone(npf_wsr *r, const char *why, void *arg)
{
    (void)r; (void)why; (void)arg;
    gone++;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
int main(void)
{
    npf_local l = {0};
    char dir[] = "/tmp/npf-faults-XXXXXX", value[400], *before = NULL, *after = NULL;
    long len;
    npf_wsr *r;
    npf_loop *loop;
    npf_noise_hs server;
    uint8_t client_sk[32] = {1}, server_sk[32] = {2}, server_pk[32];
    uint8_t msg1[128], msg2[128], payload[128];
    int n1, n2;
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
    r = calloc(1, sizeof *r);
    CHECK(loop && r);
    r->loop = loop; r->cbs.gone = relay_gone;
    npf_x25519_pub(server_pk, server_sk);
    CHECK(npf_noise_init(&r->hs, NPF_NOISE_XK, 1, "npf-relay-v1", 12, client_sk, server_pk, NULL) == 0);
    CHECK(npf_noise_init(&server, NPF_NOISE_XK, 0, "npf-relay-v1", 12, server_sk, NULL, NULL) == 0);
    n1 = npf_noise_write(&r->hs, NULL, 0, msg1, sizeof msg1);
    CHECK(n1 > 0 && npf_noise_read(&server, msg1, (size_t)n1, payload, sizeof payload) >= 0);
    n2 = npf_noise_write(&server, NULL, 0, msg2, sizeof msg2);
    CHECK(n2 > 0);
    on_msg(NULL, msg2, (size_t)n2, 1, r);
    CHECK(gone == 1 && sends == 2);
    npf_loop_once(loop, 0);
    npf_loop_free(loop);
    puts("PASS failed serialization preserves the file; failed relay bind releases once");
    return 0;
}

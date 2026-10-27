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
static int paired;
static void relay_paired(npf_wsr *r, void *arg)
{
    (void)r; (void)arg;
    paired++;
}
/* a control message from the relay, sealed with the relay's cipher state */
static void ctl_in(npf_wsr *r, npf_noise_cs *relay_tx, const char *json)
{
    uint8_t m[1100];
    int n;
    m[0] = NPF_WSR_CTL;
    n = npf_noise_encrypt(relay_tx, NULL, 0, (const uint8_t *)json, strlen(json), m + 1);
    if (n > 0)
        on_msg(NULL, m, (size_t)n + 1, 1, r);
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

    /* control messages by their type: another type's name in the data
     * changes nothing */
    {
        npf_noise_cs relay_tx;
        r = calloc(1, sizeof *r);
        CHECK(r);
        r->loop = loop; r->cbs.gone = relay_gone; r->cbs.paired = relay_paired;
        r->ready = 1;
        memset(&relay_tx, 0, sizeof relay_tx);
        memset(relay_tx.k, 5, 32);
        relay_tx.has_key = 1;
        r->rx = relay_tx;
        gone = 0;
        ctl_in(r, &relay_tx, "{\"v\":1,\"type\":\"relay_note\",\"data\":{\"after\":\"relay_paired\"}}");
        CHECK(!paired && !gone && !r->bound);
        ctl_in(r, &relay_tx, "{\"v\":1,\"type\":\"relay_bound\",\"data\":{}}");
        CHECK(r->bound && !paired);
        ctl_in(r, &relay_tx, "{\"v\":1,\"type\":\"relay_paired\",\"data\":{}}");
        CHECK(paired == 1 && r->paired && !gone);
        ctl_in(r, &relay_tx, "{\"v\":1,\"type\":\"relay_error\",\"data\":{\"error\":\"forbidden\"}}");
        CHECK(gone == 1);                   /* closed and freed (wsr_down) */
        npf_loop_once(loop, 0);
    }
    npf_loop_free(loop);
    puts("PASS failed serialization preserves the file; failed relay bind releases once; control messages by type");
    return 0;
}

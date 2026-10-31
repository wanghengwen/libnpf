/* The MSVC build's smoke test (scripts/msvc-check.sh), on npf.h alone: two
 * direct instances on this machine, B's session to A, application data
 * there and back (A echoes), then both stopped. The unit tests are POSIX
 * programs; this is what runs on Windows. 0: passed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "npf.h"

static volatile LONG a_up, b_up, b_session, a_session, echoed;
static npf_t *g_a;                      /* set before its start: its callbacks come after */

static void on_session_a(void *user, uint32_t session, int up, const char *info)
{
    (void)user; (void)info;
    if (up) {
        InterlockedExchange(&a_session, (LONG)session);
        InterlockedExchange(&a_up, 1);
    }
}

static void on_session_b(void *user, uint32_t session, int up, const char *info)
{
    (void)user; (void)info;
    if (up) {
        InterlockedExchange(&b_session, (LONG)session);
        InterlockedExchange(&b_up, 1);
    }
}

static void on_data_a(void *user, uint32_t session, const void *buf, size_t len)
{
    (void)user;
    npf_session_send(g_a, session, buf, len);
}

static void on_data_b(void *user, uint32_t session, const void *buf, size_t len)
{
    (void)user; (void)session;
    if (len == 4 && memcmp(buf, "ping", 4) == 0)
        InterlockedExchange(&echoed, 1);
}

static npf_t *make(const char *dir, const char *ov, npf_callbacks *cb)
{
    npf_options o;
    npf_t *n = NULL;
    char err[256] = "";
    CreateDirectoryA(dir, NULL);
    npf_options_init(&o);
    o.conf_dir = dir;
    o.data_dir = dir;
    o.overrides = ov;
    o.role = NPF_ROLE_DIRECT;
    o.log_level = NPF_LEVEL_WARN;
    o.flags = NPF_OPT_NO_SAVED_SETTINGS | NPF_OPT_NO_SAVED_OBJECTS;
    o.cb = cb;
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK)
        printf("npf_create (%s): %s\n", dir, err);
    return n;
}

/* until *flag, at most ms */
static int wait_for(volatile LONG *flag, int ms)
{
    for (; ms > 0 && !InterlockedCompareExchange(flag, 0, 0); ms -= 20)
        Sleep(20);
    return InterlockedCompareExchange(flag, 0, 0) != 0;
}

int main(void)
{
    static const uint8_t key[32] = {1, 2, 3};
    char tmp[MAX_PATH], da[MAX_PATH + 16], db[MAX_PATH + 16], ov[160], *st;
    npf_callbacks ca, cbb;
    npf_peer_opt po;
    npf_t *a, *b = NULL;
    uint32_t peer = 0;
    int port = 27990 + (int)(GetCurrentProcessId() % 9), ok = 0;

    printf("libnpf %s, API %d\n", npf_version(), npf_api_version());
    GetTempPathA(sizeof tmp, tmp);
    snprintf(da, sizeof da, "%snpf-smoke-a", tmp);
    snprintf(db, sizeof db, "%snpf-smoke-b", tmp);
    snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", port);

    npf_callbacks_init(&ca);
    ca.session = on_session_a;
    ca.data = on_data_a;
    if (!(g_a = a = make(da, ov, &ca)) || npf_start(a) != NPF_OK)
        return 1;
    npf_callbacks_init(&cbb);
    cbb.session = on_session_b;
    cbb.data = on_data_b;
    if (!(b = make(db, "udp_port = 0\n", &cbb)) || npf_start(b) != NPF_OK)
        return 1;

    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_DIRECT;
    po.host = "127.0.0.1";
    po.port = (uint16_t)port;
    po.psk = key;
    po.connect = NPF_CONNECT_ONCE;
    if (npf_peer_create(b, &po, &peer, NULL, 0) != NPF_OK)
        printf("FAIL peer create\n");
    else if (!wait_for(&b_up, 10000) || !wait_for(&a_up, 2000))
        printf("FAIL no session in 10 s\n");
    else if (npf_session_send(b, (uint32_t)b_session, "ping", 4) != NPF_OK)
        printf("FAIL session send\n");
    else if (!wait_for(&echoed, 5000))
        printf("FAIL no echo in 5 s\n");
    else
        ok = 1;
    if (ok) {
        st = npf_sessions_json(b);
        printf("PASS a direct session, data there and back: %.300s\n", st ? st : "");
        npf_free(st);
    }
    npf_stop(b);
    npf_stop(a);
    npf_destroy(b);
    npf_destroy(a);
    printf("%s\n", ok ? "smoke: passed" : "smoke: FAILED");
    return ok ? 0 : 1;
}

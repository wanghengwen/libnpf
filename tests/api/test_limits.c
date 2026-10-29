/* An instance's 64 media streams at most, across its sessions, the peer's
 * opens counted too; a close makes room. On test_api.c's helpers (its main
 * not run here). */
#define main api_baseline_main
#include "test_api.c"
#undef main

int main(void)
{
    side s[4] = {{0}};
    npf_t *n[4] = {0};
    char dirs[4][64], ov[256], err[300];
    const char *key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t sessions[3], media[64], replacement;
    npf_media_opt mo;
    int port = 28900 + (int)(getpid() % 25) * 3, i, j, count = 0, e = 0;
    alarm(60);
    for (i = 0; i < 4; i++) {
        pthread_mutex_init(&s[i].mu, NULL);
        s[i].name = "limits";
        snprintf(dirs[i], sizeof dirs[i], "/tmp/npf-limits-%d-XXXXXX", i);
        if (!mkdtemp(dirs[i])) return 2;
        snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = %s\n", port + i, key);
        n[i] = make(&s[i], dirs[i], i ? ov : "udp_port = 0\n");
        if (!n[i] || npf_start(n[i])) return 2;
    }
    for (i = 0; i < 3; i++) {
        static const uint8_t zero[32];      /* the key: 32 zero bytes */
        npf_peer_opt po;
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.1";
        po.port = (uint16_t)(port + i + 1);
        po.psk = zero;
        check(npf_peer_create(n[0], &po, NULL, err, sizeof err) == NPF_OK, "add a session for the aggregate limit");
        check(wait_for(&s[0], &s[0].up, i + 1, 10000), "session up");
        pthread_mutex_lock(&s[0].mu);
        sessions[i] = s[0].session;
        pthread_mutex_unlock(&s[0].mu);
    }
    npf_media_opt_init(&mo);
    for (i = 0; i < 3; i++)
        for (j = 0; j < (i < 2 ? 30 : 4); j++) {
            media[count] = media_open(n[0], sessions[i], &mo, &e);
            if (media[count]) count++;
        }
    check(count == 64, "64 media streams across three sessions");
    check(media_open(n[0], sessions[2], &mo, &e) == 0 && e == NPF_EBUSY, "65th media stream refused by instance budget");
    /* Receiver-initiated streams count against that same budget. */
    check(wait_for(&s[3], &s[3].up, 1, 10000), "remote session ready");
    pthread_mutex_lock(&s[3].mu);
    replacement = s[3].session;
    pthread_mutex_unlock(&s[3].mu);
    check(media_open(n[3], replacement, &mo, &e) != 0, "remote tries an incoming stream");
    check(wait_for(&s[3], &s[3].refused_closed, 1, 5000), "incoming stream refused at 64 too");
    check(npf_media_close(n[0], media[0]) == NPF_OK, "close frees an instance slot");
    check(media_open(n[0], sessions[2], &mo, &e) != 0, "slot reused on another session");
    for (i = 0; i < 4; i++) {
        npf_destroy(n[i]);
        rm_dir(dirs[i]);
        pthread_mutex_destroy(&s[i].mu);
    }
    return fails ? 1 : 0;
}

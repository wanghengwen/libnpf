/* Reuse the public-only test helpers; the baseline's main is not run here. */
#define main api_baseline_main
#include "test_api.c"
#undef main

int main(void)
{
    side s[4] = {{0}};
    npf_t *n[4] = {0};
    char dirs[4][64], ov[256], spec[256], err[300], path[128];
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
        snprintf(ov, sizeof ov, "udp_port = 0\n%s", "");
        if (i)
            snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = %s\n", port + i, key);
        n[i] = make(&s[i], dirs[i], ov);
        if (!n[i] || npf_start(n[i])) return 2;
    }
    for (i = 0; i < 3; i++) {
        snprintf(spec, sizeof spec, "127.0.0.1:%d --psk %s", port + i + 1, key);
        say("add a session for the aggregate limit", npf_peer_add(n[0], spec, 0, err, sizeof err) == NPF_OK);
        say("session up", wait_for(&s[0], &s[0].up, i + 1, 10000));
        pthread_mutex_lock(&s[0].mu);
        sessions[i] = s[0].session;
        pthread_mutex_unlock(&s[0].mu);
    }
    npf_media_opt_default(&mo);
    for (i = 0; i < 3; i++)
        for (j = 0; j < (i < 2 ? 30 : 4); j++) {
            media[count] = npf_media_open(n[0], sessions[i], &mo, &e);
            if (media[count]) count++;
        }
    say("64 media streams across three sessions", count == 64);
    say("65th media stream refused by instance budget", npf_media_open(n[0], sessions[2], &mo, &e) == 0 && e == NPF_EBUSY);
    /* Receiver-initiated streams count against that same budget. */
    say("remote session ready", wait_for(&s[3], &s[3].up, 1, 10000));
    pthread_mutex_lock(&s[3].mu);
    replacement = s[3].session;
    pthread_mutex_unlock(&s[3].mu);
    say("remote tries an incoming stream", npf_media_open(n[3], replacement, &mo, &e) != 0);
    say("incoming stream refused at 64 too", wait_for(&s[3], &s[3].refused_closed, 1, 5000));
    say("close frees an instance slot", npf_media_close(n[0], media[0]) == NPF_OK);
    say("slot reused on another session", npf_media_open(n[0], sessions[2], &mo, &e) != 0);
    for (i = 0; i < 4; i++) {
        npf_destroy(n[i]);
        snprintf(path, sizeof path, "%s/identity", dirs[i]); unlink(path);
        snprintf(path, sizeof path, "%s/local.json", dirs[i]); unlink(path);
        rmdir(dirs[i]);
        pthread_mutex_destroy(&s[i].mu);
    }
    return fails ? 1 : 0;
}

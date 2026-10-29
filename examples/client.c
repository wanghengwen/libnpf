/* A client on libnpf, through npf.h only: it connects to a device by its
 * number and pairing password, opens a local port to the device's web page
 * and says when it is there. Started from its own parameters (npf_setup).
 *
 *   cc -o npf-client client.c $(pkg-config --cflags --libs npf) -lpthread
 *   NPF_PASSWORD=... ./npf-client ETC DATA_DIR NUMBER [LOCAL_PORT [TARGET_PORT]]
 *
 * ETC: root.bin and serverlist.bin (as for examples/device.c). DATA_DIR
 * keeps this client's identity and the device's key once paired, so the
 * password is needed only the first time. LOCAL_PORT 0 (the default) lets
 * the system pick one. Stops on SIGINT / SIGTERM. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf.h"

static npf_t *cli;

static uint32_t peer;   /* the device (set before npf_start: callbacks come after it) */

/* a forward is up or failed ({"peer", "spec", "up", "why"}): the port the
 * system picked, from npf_forward_get */
static void forward_changed(void)
{
    npf_forward_info fi;
    uint32_t fwd;
    size_t count;
    if (npf_forward_list(cli, peer, &fwd, 1, &count) != NPF_OK || !count || npf_forward_get(cli, fwd, &fi) != NPF_OK)
        return;
    if (fi.state == NPF_FWD_UP)
        printf("the device's port %d is at http://127.0.0.1:%d/\n", fi.target_port, fi.listen_port);
    else if (fi.state == NPF_FWD_FAILED)
        printf("the forward failed: %s\n", fi.why);
}

/* the library's events (npf.h, npf_callbacks.event): the name, details in JSON */
static void on_event(void *user, const char *name, const char *json)
{
    (void)user;
    (void)json;
    if (strcmp(name, "forward") == 0) {
        forward_changed();
    } else if (strcmp(name, "peer_done") == 0) {     /* it gave up: why, from npf_peer_get */
        npf_peer_info pi;
        if (npf_peer_get(cli, peer, &pi) == NPF_OK)
            printf("%s\n", pi.needs & NPF_NEED_PASSWORD ? "the device needs its pairing password (NPF_PASSWORD)"
                                                       : pi.why);
    }
    fflush(stdout);
}

/* the session with the device came up or ended (info: JSON) */
static void on_session(void *user, uint32_t session, int up, const char *info)
{
    (void)user;
    (void)session;
    printf("%s: %s\n", up ? "connected" : "disconnected", info);
    fflush(stdout);
}

static long read_file(const char *dir, const char *name, void *buf, size_t max)
{
    char path[1024];
    FILE *f;
    long n;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (!(f = fopen(path, "rb")))
        return -1;
    n = (long)fread(buf, 1, max, f);
    fclose(f);
    return n;
}

int main(int argc, char **argv)
{
    static uint8_t roots[1][32];
    static unsigned char list[64 * 1024];
    long list_len;
    char err[256];
    int rc;
    if (argc < 4) {
        fprintf(stderr, "usage: [NPF_PASSWORD=...] %s ETC DATA_DIR NUMBER [LOCAL_PORT [TARGET_PORT]]\n", argv[0]);
        return 2;
    }
    if (read_file(argv[1], "root.bin", roots[0], 32) != 32
        || (list_len = read_file(argv[1], "serverlist.bin", list, sizeof list)) <= 0) {
        fprintf(stderr, "%s: root.bin (32 bytes) and serverlist.bin are needed\n", argv[1]);
        return 2;
    }
    sigset_t stop;
    sigemptyset(&stop);
    sigaddset(&stop, SIGINT);
    sigaddset(&stop, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &stop, NULL);

    npf_setup setup;
    npf_setup_init(&setup);
    setup.roots = (const uint8_t(*)[32])roots;
    setup.nroots = 1;
    setup.serverlist = list;
    setup.serverlist_len = (size_t)list_len;

    npf_callbacks cb;
    npf_callbacks_init(&cb);
    cb.event = on_event;
    cb.session = on_session;

    npf_options o;
    npf_options_init(&o);
    o.setup = &setup;
    o.data_dir = argv[2];
    o.role = NPF_ROLE_CLIENT;
    o.log_level = -1;
    o.cb = &cb;
    o.app_name = "npf-client-example";
    o.app_ver = "1";
    if (npf_create(&o, &cli, err, sizeof err) != NPF_OK) {
        fprintf(stderr, "npf_create: %s\n", err);
        return 1;
    }

    /* the device */
    npf_peer_opt po;
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_NUMBER;
    po.number = strtoull(argv[3], NULL, 10);
    po.password = getenv("NPF_PASSWORD");   /* NULL once paired */
    if ((rc = npf_peer_create(cli, &po, &peer, err, sizeof err)) != NPF_OK) {
        fprintf(stderr, "%s: %s (%d)\n", argv[3], err, rc);
        npf_destroy(cli);
        return 1;
    }
    /* its web page here: a local port (0: the system's choice) */
    npf_forward_opt fo;
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    fo.listen.port = (uint16_t)(argc > 4 ? atoi(argv[4]) : 0);
    fo.target.host = "127.0.0.1";
    fo.target.port = (uint16_t)(argc > 5 ? atoi(argv[5]) : 80);
    if ((rc = npf_forward_create(cli, peer, &fo, NULL, err, sizeof err)) != NPF_OK) {
        fprintf(stderr, "forward: %s (%d)\n", err, rc);
        npf_destroy(cli);
        return 1;
    }
    if (npf_start(cli) != NPF_OK) {
        fprintf(stderr, "npf_start failed\n");
        npf_destroy(cli);
        return 1;
    }
    int sig;
    sigwait(&stop, &sig);
    npf_destroy(cli);
    return 0;
}

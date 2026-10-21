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

/* the peer's and the forward's ctx: what this program keeps of them */
typedef struct device {
    const char *number;
} device;
typedef struct web_forward {
    int target_port;
} web_forward;

static void on_notify(void *user, const npf_event *ev)
{
    (void)user;
    if (ev->type == NPF_EV_PEER && ev->ctx) {
        const device *d = ev->ctx;
        if (ev->state == NPF_PEER_CONNECTED)
            printf("%s: connected\n", d->number);
        else if (ev->state == NPF_PEER_ENDED) {
            npf_peer_info pi;
            npf_peer_info_init(&pi);
            npf_peer_get(cli, ev->peer, &pi);
            printf("%s: %s%s\n", d->number, pi.needs & NPF_NEED_PASSWORD ? "needs its pairing password (NPF_PASSWORD)"
                                             : "gave up: ", pi.needs ? "" : pi.why);
        } else if (ev->state == NPF_PEER_RETRY)
            printf("%s: again in %d s (%s)\n", d->number, ev->retry_in_ms / 1000, ev->why);
    } else if (ev->type == NPF_EV_FORWARD && ev->ctx) {
        npf_forward_info fi;
        npf_forward_info_init(&fi);
        if (npf_forward_get(cli, ev->forward, &fi) == NPF_OK && fi.state == NPF_FWD_UP)
            printf("the device's port %d is at http://127.0.0.1:%d/\n", fi.target_port, fi.listen_port);
        else if (fi.state == NPF_FWD_FAILED)
            printf("the forward failed: %s\n", fi.why);
    } else if (ev->type == NPF_EV_FORWARD_REFUSED) {
        printf("the device refused: %s (not a resource it published)\n", ev->why);
    }
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
    static device dev;
    static web_forward web;
    long list_len;
    char err[256];
    uint32_t peer = 0;
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
    cb.notify = on_notify;

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

    /* the device: its ctx ready before the call (its events may come first) */
    dev.number = argv[3];
    npf_peer_opt po;
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_NUMBER;
    po.number = strtoull(argv[3], NULL, 10);
    po.password = getenv("NPF_PASSWORD");   /* NULL once paired */
    po.ctx = &dev;
    if ((rc = npf_peer_create(cli, &po, &peer, err, sizeof err)) != NPF_OK) {
        fprintf(stderr, "%s: %s (%d)\n", argv[3], err, rc);
        npf_destroy(cli);
        return 1;
    }
    /* its web page here: a local port (0: the system's choice) */
    web.target_port = argc > 5 ? atoi(argv[5]) : 80;
    npf_forward_opt fo;
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    fo.listen.port = (uint16_t)(argc > 4 ? atoi(argv[4]) : 0);
    fo.target.host = "127.0.0.1";
    fo.target.port = (uint16_t)web.target_port;
    fo.ctx = &web;
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

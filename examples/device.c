/* A device on libnpf, through npf.h only: the smallest program a vendor
 * builds into its firmware. It runs one instance as a node, started from
 * its own parameters (npf_setup: no configuration file): it enrols with the
 * model credential the first time (the platform gives the device its
 * number), stays online, and answers sessions: what a peer sends on the
 * session's control channel comes back to it. It publishes one resource,
 * its web page on port 80, so the peers may reach it.
 *
 *   cc -o npf-device device.c $(pkg-config --cflags --libs npf) -lpthread
 *   NPF_MODEL_CRED=NPFV2... NPF_SERIAL=SN0001 ./npf-device ETC DATA_DIR
 *
 * ETC has the platform's root key (root.bin, 32 bytes) and its signed server
 * list (serverlist.bin), as in the SDK's etc/: a vendor compiles them into
 * the firmware instead. DATA_DIR keeps the identity and the number
 * (persistent storage). The credential comes from the environment here, so
 * it is never written to disk; a vendor reads it from its own secure
 * storage. Stops on SIGINT / SIGTERM. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf.h"

static npf_t *dev; /* set before npf_start: callbacks come after it */

/* what the library tells: an event's name and its details as JSON (npf.h,
 * npf_callbacks.event); a real device parses the JSON, this one prints it */
static void on_event(void *user, const char *name, const char *json)
{
    (void)user;
    if (strcmp(name, "enrolled") == 0)          /* {"number"}: also in DATA_DIR/node.json */
        printf("enrolled: %s\n", json);
    else if (strcmp(name, "enroll_failed") == 0)    /* the platform refused: the library tries again by itself */
        printf("enrolment refused: %s\n", json);
    else if (strcmp(name, "online") == 0)
        printf("online\n");
    else if (strcmp(name, "offline") == 0)
        printf("offline: %s\n", json);
    /* others, and those of later versions: not needed here */
    fflush(stdout);
}

/* a session came up ({"peer", "path", "direction", "call_id"}) or ended ({"why"}) */
static void on_session(void *user, uint32_t session, int up, const char *info)
{
    (void)user;
    printf("session %u %s: %s\n", session, up ? "up" : "down", info);
    fflush(stdout);
}

/* application data: sent back to the peer */
static void on_data(void *user, uint32_t session, const void *buf, size_t len)
{
    (void)user;
    npf_session_send(dev, session, buf, len);
}

/* a whole file (at most max bytes): its length, -1 none */
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
    if (argc != 3) {
        fprintf(stderr, "usage: NPF_MODEL_CRED=NPFV2... [NPF_SERIAL=SN] %s ETC DATA_DIR\n", argv[0]);
        return 2;
    }
    if (read_file(argv[1], "root.bin", roots[0], 32) != 32
        || (list_len = read_file(argv[1], "serverlist.bin", list, sizeof list)) <= 0) {
        fprintf(stderr, "%s: root.bin (32 bytes) and serverlist.bin are needed\n", argv[1]);
        return 2;
    }

    /* SIGINT and SIGTERM for sigwait below (blocked before the library's
     * thread starts, so it inherits the mask) */
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
    setup.model_cred = getenv("NPF_MODEL_CRED");
    setup.serial = getenv("NPF_SERIAL");

    npf_callbacks cb;
    npf_callbacks_init(&cb);
    cb.event = on_event;
    cb.session = on_session;
    cb.data = on_data;

    npf_options o;
    npf_options_init(&o);
    o.setup = &setup;
    o.data_dir = argv[2];
    o.role = NPF_ROLE_NODE;
    o.log_level = -1;
    o.cb = &cb;
    o.app_name = "npf-device-example";
    o.app_ver = "2";

    char err[256];
    if (npf_create(&o, &dev, err, sizeof err) != NPF_OK) {
        fprintf(stderr, "npf_create: %s\n", err);
        return 1;
    }
    printf("libnpf %s\n", npf_version());

    /* what the peers may reach here: the web page (in effect for this run;
     * NPF_PERSIST would keep it in DATA_DIR for the next one) */
    npf_resource web;
    npf_resource_init(&web);
    web.type = NPF_RES_TCP;
    web.svc = "http";
    web.name = "web";
    web.service.host = "127.0.0.1";
    web.service.port = 80;
    if (npf_resource_put(dev, &web, err, sizeof err) != NPF_OK)
        fprintf(stderr, "resource: %s\n", err);

    if (npf_start(dev) != NPF_OK) {
        fprintf(stderr, "npf_start failed\n");
        npf_destroy(dev);
        return 1;
    }
    int sig;
    sigwait(&stop, &sig);
    npf_destroy(dev); /* stops, waits for the run, frees */
    return 0;
}

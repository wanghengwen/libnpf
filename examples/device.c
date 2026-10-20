/* A device on libnpf, through npf.h only: the smallest program a vendor
 * builds into its firmware. It runs one instance as
 * a node: enrols with the model credential the first time (the platform
 * gives the device its number), stays online, and answers sessions: what a
 * peer sends on the session's control channel comes back to it. Port
 * forwards to the device's own services need no code: the peers ask for
 * them and the configuration allows them.
 *
 *   cc -o npf-device device.c $(pkg-config --cflags --libs npf) -lpthread
 *   NPF_MODEL_CRED=NPFV2... NPF_SERIAL=SN0001 ./npf-device CONF_DIR DATA_DIR
 *
 * CONF_DIR has npf.conf (root, serverlist: as in the SDK's etc/), read
 * only; DATA_DIR keeps the identity and the number (persistent storage).
 * The credential and the serial come in through the overrides here, so
 * the credential is never written to disk; a vendor reads it from its own
 * secure storage. Stops on SIGINT / SIGTERM. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf.h"

static npf_t *dev; /* set before npf_start: callbacks come after it */

static void on_event(void *user, const char *name, const char *json)
{
    (void)user;
    /* enrolled {"number"}: the device's number (also in DATA_DIR/node.json);
     * enroll_failed {"error", "reason", "retry_in"}: the platform refused,
     * the library tries again by itself (reasons: docs/protocol/signaling.md, enroll) */
    printf("event %s %s\n", name, json);
    fflush(stdout);
}

static void on_session(void *user, uint32_t session, int up, const char *info)
{
    (void)user;
    printf("session %u %s %s\n", session, up ? "up" : "down", info);
    fflush(stdout);
}

/* application data: sent back to the peer */
static void on_data(void *user, uint32_t session, const void *buf, size_t len)
{
    (void)user;
    npf_session_send(dev, session, buf, len);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: NPF_MODEL_CRED=NPFV2... [NPF_SERIAL=SN] %s CONF_DIR DATA_DIR\n", argv[0]);
        return 2;
    }
    const char *cred = getenv("NPF_MODEL_CRED"), *serial = getenv("NPF_SERIAL");
    char overrides[2048] = "";
    if (cred && *cred)
        snprintf(overrides, sizeof overrides, "model_cred = %s\n", cred);
    if (serial && *serial)
        snprintf(overrides + strlen(overrides), sizeof overrides - strlen(overrides), "serial = %s\n", serial);

    /* SIGINT and SIGTERM for sigwait below (blocked before the library's
     * thread starts, so it inherits the mask) */
    sigset_t stop;
    sigemptyset(&stop);
    sigaddset(&stop, SIGINT);
    sigaddset(&stop, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &stop, NULL);

    npf_callbacks cb;
    npf_callbacks_init(&cb);
    cb.event = on_event;
    cb.session = on_session;
    cb.data = on_data;

    npf_options o;
    npf_options_init(&o);
    o.conf_dir = argv[1];
    o.data_dir = argv[2];
    o.overrides = overrides;
    o.role = NPF_ROLE_NODE;
    o.log_level = -1;
    o.cb = &cb;
    o.app_name = "npf-device-example";
    o.app_ver = "1";

    char err[256];
    if (npf_create(&o, &dev, err, sizeof err) != NPF_OK) {
        fprintf(stderr, "npf_create: %s\n", err);
        return 1;
    }
    printf("libnpf %s\n", npf_version());
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

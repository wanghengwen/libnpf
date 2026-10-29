/* The public API's contracts, on npf.h alone: the initialisers write only
 * the caller's size; a change in effect that cannot be saved says so
 * (NPF_ESAVE, exit code 3) and is written with the next change saved. */
#define _DEFAULT_SOURCE                     /* mkdtemp */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf.h"

static int fails;
static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

/* bytes from off on are all v */
static int all(const unsigned char *b, size_t off, size_t end, unsigned char v)
{
    for (; off < end; off++)
        if (b[off] != v)
            return 0;
    return 1;
}

static void inits(void)
{
    unsigned char buf[sizeof(npf_options) + 64];
    npf_options *o = (npf_options *)(void *)buf;
    npf_callbacks *cb = (npf_callbacks *)(void *)buf;
    npf_media_opt *mo = (npf_media_opt *)(void *)buf;
    size_t small = offsetof(npf_options, cb) + sizeof o->cb;     /* an older application's build */

    memset(buf, 0xaa, sizeof buf);
    npf_options_init_size(o, small);
    check(o->size == small && o->log_level == -1 && all(buf, small, sizeof buf, 0xaa),
          "options: an older, smaller structure: written up to its size only");
    memset(buf, 0xaa, sizeof buf);
    npf_options_init_size(o, sizeof buf);
    check(o->size == sizeof buf && o->log_level == -1 && all(buf, sizeof(npf_options), sizeof buf, 0),
          "options: a newer, larger structure: the rest zero, its size kept");
    memset(buf, 0xaa, sizeof buf);
    npf_callbacks_init_size(cb, offsetof(npf_callbacks, log));
    check(cb->size == offsetof(npf_callbacks, log) && all(buf, offsetof(npf_callbacks, log), sizeof buf, 0xaa),
          "callbacks: written up to the caller's size only");
    memset(buf, 0xaa, sizeof buf);
    npf_media_opt_init(mo);
    check(mo->size == sizeof *mo && all(buf, sizeof *mo, sizeof buf, 0xaa), "media options: the macro passes sizeof");
}

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int got, got_code;
static char got_text[512];

static void on_text(void *user, int code, const char *text)
{
    (void)user;
    pthread_mutex_lock(&mu);
    got = 1;
    got_code = code;
    snprintf(got_text, sizeof got_text, "%s", text ? text : "");
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
}

static int command(npf_t *n, int argc, const char *const *argv)
{
    pthread_mutex_lock(&mu);
    got = 0;
    pthread_mutex_unlock(&mu);
    if (npf_command(n, argc, argv, on_text, NULL) != NPF_OK)
        return -100;
    pthread_mutex_lock(&mu);
    while (!got)
        pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    return got_code;
}

/* local.json's text ("" when there is none) */
static void local_json(const char *dir, char *out, size_t cap)
{
    char path[400];
    FILE *f;
    size_t l = 0;
    snprintf(path, sizeof path, "%s/local.json", dir);
    if ((f = fopen(path, "r"))) {
        l = fread(out, 1, cap - 1, f);
        fclose(f);
    }
    out[l] = 0;
}

static void unsaved(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], val[64], path[400], js[8192];
    const char *set[] = {"set", "punch_sockets", "8"};
    const char *files[] = {"identity", "seed", "local.json"};
    npf_options o;
    npf_t *n = NULL;
    size_t i;
    int rc;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = NPF_ROLE_DIRECT;
    o.overrides = "udp_port = 0\n";
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK || npf_start(n) != NPF_OK) {
        check(0, "an instance");
        return;
    }
    chmod(dir, 0500);                       /* local.json cannot be written now */
    if (access(dir, W_OK) == 0) {
        printf("SKIP unsaved changes: the directory stays writable (root?)\n");
    } else {
        rc = npf_config_set(n, "peer_idle", "30", 1, err, sizeof err);
        check(rc == NPF_ESAVE && strstr(err, "in effect now") && strstr(err, "cannot write"),
              "set: in effect, not written: NPF_ESAVE with the reason");
        check(npf_config_get(n, "peer_idle", val, sizeof val) == NPF_OK && strcmp(val, "30") == 0,
              "set: get shows the value in effect");
        rc = command(n, 3, set);
        check(rc == 3 && strstr(got_text, "punch_sockets = 8") && strstr(got_text, "cannot write"),
              "the set command: in effect, not written: exit code 3, both said");
        {
            npf_resource r;
            npf_resource_info ri[4];
            size_t count = 0;
            npf_resource_init(&r);
            r.type = NPF_RES_TCP;
            r.name = "ssh";
            r.service.host = "127.0.0.1";
            r.service.port = 22;
            r.flags = NPF_PERSIST;
            rc = npf_resource_put(n, &r, err, sizeof err);
            check(rc == NPF_ESAVE && strstr(err, "cannot write"), "resource put: in effect, not written: NPF_ESAVE");
            check(npf_resource_list(n, 0, ri, 4, &count) == NPF_OK && count == 1 && strcmp(ri[0].name, "ssh") == 0,
                  "resource put: in effect");
        }
        chmod(dir, 0700);
        local_json(dir, js, sizeof js);
        check(!strstr(js, "ssh") && !strstr(js, "peer_idle") && !strstr(js, "punch_sockets"),
              "nothing of them in local.json yet");
        check(npf_config_set(n, "max_calls", "20", 1, err, sizeof err) == NPF_OK, "a later change saved");
        local_json(dir, js, sizeof js);
        check(strstr(js, "max_calls") && strstr(js, "peer_idle") && strstr(js, "punch_sockets") && strstr(js, "ssh"),
              "the later save writes them too");
    }
    chmod(dir, 0700);
    npf_destroy(n);
    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        unlink(path);
    }
    rmdir(dir);
}

/* where to connect, what to trust, the files written: never through set,
 * never from local.json (another local user may hold the control token) */
static void file_only(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], val[300], path[400];
    const char *files[] = {"identity", "seed", "local.json"};
    npf_options o;
    npf_t *n = NULL;
    size_t i;
    FILE *f;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    snprintf(path, sizeof path, "%s/local.json", dir);
    if (!(f = fopen(path, "w"))) {
        check(0, "local.json written");
        return;
    }
    fprintf(f, "{\"settings\":{\"root\":\"AAAA\",\"state\":\"%s/planted.json\",\"peer_idle\":\"7\",\"max_calls\":\"9999\"}}\n",
            dir);
    fclose(f);
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = NPF_ROLE_DIRECT;
    o.overrides = "udp_port = 0\n";
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK) {
        check(0, "an instance");
        return;
    }
    check(npf_config_get(n, "peer_idle", val, sizeof val) == NPF_OK && strcmp(val, "7") == 0,
          "local.json: an ordinary setting taken");
    check(npf_config_get(n, "root", val, sizeof val) == NPF_OK && strcmp(val, "AAAA") != 0,
          "local.json: root ignored");
    check(npf_config_get(n, "state", val, sizeof val) == NPF_OK && !strstr(val, "planted"), "local.json: state ignored");
    check(npf_config_get(n, "max_calls", val, sizeof val) == NPF_OK && strcmp(val, "32") == 0,
          "local.json: a value out of the key's range taken");
    check(npf_config_set(n, "max_calls", "4097", 0, err, sizeof err) == NPF_EINVAL && strstr(err, "0 to 4096"),
          "set max_calls 4097: taken");
    check(npf_config_set(n, "root", "BBBB", 1, err, sizeof err) != NPF_OK && strstr(err, "npf.conf"),
          "set root: refused, only in npf.conf");
    check(npf_config_set(n, "serverlist_saved", "/tmp/x", 0, err, sizeof err) != NPF_OK, "set serverlist_saved: refused");
    check(npf_config_set(n, "direct_psk", "x", 0, err, sizeof err) != NPF_OK, "set direct_psk: refused");
    npf_destroy(n);
    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        unlink(path);
    }
    snprintf(path, sizeof path, "%s/planted.log", dir);
    check(access(path, F_OK) != 0, "the planted log path not written");
    o.overrides = "udp_port = 70000\n";         /* each source's values as the key table says */
    check(npf_create(&o, &n, err, sizeof err) == NPF_EINVAL && strstr(err, "overrides: udp_port: a number from 0 to 65535"),
          "overrides: udp_port 70000 taken");
    rmdir(dir);
}

/* a damaged node.json (an enrolled identity's number) is not "not enrolled",
 * which would enroll again under another number: its copy node.json.bak is
 * taken, and without one npf_create says so */
static void put_file(const char *dir, const char *name, const char *text)
{
    char path[400];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if ((f = fopen(path, "w"))) {
        fputs(text, f);
        fclose(f);
    }
}

static void node_json(void)
{
    static const char *const files[] = {"identity", "seed", "local.json", "node.json", "node.json.bak", "state.json",
                                        "state.json.bak", "npf.conf"};
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], path[400];
    npf_options o;
    npf_t *n = NULL;
    size_t i;
    int rc;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = NPF_ROLE_NODE;
    o.overrides = "udp_port = 0\n";
    put_file(dir, "npf.conf", "root = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\n");
    put_file(dir, "node.json", "{\"number\":\"1234");
    rc = npf_create(&o, &n, err, sizeof err);
    check(rc != NPF_OK && strstr(err, "node.json is damaged"), "a damaged node.json: npf_create says so");
    if (rc == NPF_OK)
        npf_destroy(n);
    n = NULL;
    put_file(dir, "node.json.bak", "{\"number\":\"123456789\",\"password\":\"ABCD-EFGH\"}\n");
    rc = npf_create(&o, &n, err, sizeof err);
    {
        char text[200] = "";
        FILE *f;
        snprintf(path, sizeof path, "%s/node.json", dir);
        if ((f = fopen(path, "r"))) {
            if (!fgets(text, sizeof text, f))
                text[0] = 0;
            fclose(f);
        }
        /* (no server list here: npf_create stops later, at the configuration) */
        check(!strstr(err, "damaged") && strstr(text, "123456789"), "its copy taken, and the file written again");
    }
    if (rc == NPF_OK)
        npf_destroy(n);
    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        unlink(path);
    }
    rmdir(dir);
}

/* a structure not initialised (no _init: its size 0) or NULL: NPF_EINVAL
 * naming the _init, the number out 0, nothing made */
static void not_initialised(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], path[400];
    const char *files[] = {"identity", "seed", "local.json"};
    npf_options o, zo;
    npf_peer_opt po;
    npf_forward_opt fo;
    npf_resource r;
    npf_media_opt mo;
    npf_resource_info ri[1];
    npf_t *n = NULL;
    uint32_t id = 7;
    size_t i, count = 9;
    memset(&zo, 0, sizeof zo);
    check(npf_create(&zo, &n, err, sizeof err) == NPF_EINVAL && !n && strstr(err, "(npf_options_init)"),
          "npf_create: options not initialised");
    check(npf_create(NULL, &n, err, sizeof err) == NPF_EINVAL && !n, "npf_create: no options");
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = NPF_ROLE_DIRECT;
    o.overrides = "udp_port = 0\n";
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK) {
        check(0, "an instance");
        return;
    }
    memset(&po, 0, sizeof po);
    memset(&fo, 0, sizeof fo);
    memset(&r, 0, sizeof r);
    memset(&mo, 0, sizeof mo);
    check(npf_peer_create(n, &po, &id, err, sizeof err) == NPF_EINVAL && id == 0 && strstr(err, "(npf_peer_opt_init)"),
          "npf_peer_create: options not initialised");
    id = 7;
    check(npf_peer_create(n, NULL, &id, err, sizeof err) == NPF_EINVAL && id == 0, "npf_peer_create: no options");
    id = 7;
    check(npf_forward_create(n, 1, &fo, &id, err, sizeof err) == NPF_EINVAL && id == 0
          && strstr(err, "(npf_forward_opt_init)"), "npf_forward_create: options not initialised");
    check(npf_resource_put(n, &r, err, sizeof err) == NPF_EINVAL && strstr(err, "(npf_resource_init)"),
          "npf_resource_put: not initialised");
    id = 7;
    check(npf_media_open(n, 1, &mo, &id) == NPF_EINVAL && id == 0, "npf_media_open: options not initialised");
    id = 7;
    check(npf_media_open(n, 1, NULL, &id) == NPF_EINVAL && id == 0, "npf_media_open: no options");
    check(npf_peer_list(n, NULL, 0, &count) == NPF_OK && count == 0
          && npf_resource_list(n, 0, ri, 1, &count) == NPF_OK && count == 0, "nothing made");
    npf_destroy(n);
    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        unlink(path);
    }
    rmdir(dir);
}

int main(void)
{
    alarm(30);
    inits();
    not_initialised();
    unsaved();
    file_only();
    node_json();
    return fails != 0;
}

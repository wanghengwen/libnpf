/* The public API's contracts, on npf.h alone: the initialisers write only
 * the caller's size; a change in effect that cannot be saved says so
 * (NPF_ESAVE, exit code 3) and is written with the next change saved; a
 * change refused in safe mode says that instead; a shared runtime's
 * callback never waits for another thread; the admin device in the
 * pairing list and npf_pairing_admin_set. */
#define _DEFAULT_SOURCE                     /* mkdtemp */
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "api_test.h"

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

static void unsaved(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], val[64], js[8192];
    const char *set[] = {"set", "punch_sockets", "8"};
    npf_t *n;
    int rc;
    if (!mkdtemp(dir) || !(n = instance(dir, NPF_ROLE_DIRECT, "udp_port = 0\n", NULL, err, sizeof err))
        || npf_start(n) != NPF_OK) {
        check(0, "an instance");
        return;
    }
    chmod(dir, 0500);                       /* local.json cannot be written now */
    if (access(dir, W_OK) == 0) {
        printf("SKIP unsaved changes: the directory stays writable (root?)\n");
    } else {
        rc = npf_config_set(n, "peer_idle", "30", 1, NULL, err, sizeof err);
        check(rc == NPF_ESAVE && strstr(err, "in effect now") && strstr(err, "cannot write"),
              "set: in effect, not written: NPF_ESAVE with the reason");
        check(npf_config_get(n, "peer_idle", val, sizeof val) == NPF_OK && strcmp(val, "30") == 0,
              "set: get shows the value in effect");
        rc = cmd(n, 3, set);
        check(rc == 3 && strstr(cmd_text, "punch_sockets = 8") && strstr(cmd_text, "cannot write"),
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
        file_text(dir, "local.json", js, sizeof js);
        check(!strstr(js, "ssh") && !strstr(js, "peer_idle") && !strstr(js, "punch_sockets"),
              "nothing of them in local.json yet");
        check(npf_config_set(n, "max_calls", "20", 1, NULL, err, sizeof err) == NPF_OK, "a later change saved");
        file_text(dir, "local.json", js, sizeof js);
        check(strstr(js, "max_calls") && strstr(js, "peer_idle") && strstr(js, "punch_sockets") && strstr(js, "ssh"),
              "the later save writes them too");
    }
    chmod(dir, 0700);
    npf_destroy(n);
    rm_dir(dir);
}

/* where to connect, what to trust, the files written: never through set,
 * never from local.json (another local user may hold the control token) */
static void file_only(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300], val[300], path[400];
    npf_t *n;
    int rc;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    snprintf(val, sizeof val,
             "{\"settings\":{\"root\":\"AAAA\",\"state\":\"%s/planted.json\",\"peer_idle\":\"7\",\"max_calls\":\"9999\"}}\n",
             dir);
    put_file(dir, "local.json", val);
    if (!(n = instance(dir, NPF_ROLE_DIRECT, "udp_port = 0\n", NULL, err, sizeof err))) {
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
    check(npf_config_set(n, "max_calls", "4097", 0, NULL, err, sizeof err) == NPF_EINVAL && strstr(err, "0 to 4096"),
          "set max_calls 4097: taken");
    check(npf_config_set(n, "root", "BBBB", 1, NULL, err, sizeof err) != NPF_OK && strstr(err, "npf.conf"),
          "set root: refused, only in npf.conf");
    check(npf_config_set(n, "serverlist_saved", "/tmp/x", 0, NULL, err, sizeof err) != NPF_OK, "set serverlist_saved: refused");
    check(npf_config_set(n, "direct_psk", "x", 0, NULL, err, sizeof err) != NPF_OK, "set direct_psk: refused");
    npf_destroy(n);
    snprintf(path, sizeof path, "%s/planted.log", dir);
    check(access(path, F_OK) != 0, "the planted log path not written");
    n = instance(dir, NPF_ROLE_DIRECT, "udp_port = 70000\n", &rc, err, sizeof err);   /* each source's values as the key table says */
    check(rc == NPF_EINVAL && strstr(err, "overrides: udp_port: a number from 0 to 65535"), "overrides: udp_port 70000 taken");
    rm_dir(dir);
}

/* a damaged node.json (an enrolled identity's number) is not "not enrolled",
 * which would enroll again under another number: its copy node.json.bak is
 * taken, and without one npf_create says so */
static void node_json(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300] = "", text[200];
    int rc;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    put_file(dir, "npf.conf", "root = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\n");
    put_file(dir, "node.json", "{\"number\":\"1234");
    npf_destroy(instance(dir, NPF_ROLE_NODE, "udp_port = 0\n", &rc, err, sizeof err));
    check(rc != NPF_OK && strstr(err, "node.json is damaged"), "a damaged node.json: npf_create says so");
    put_file(dir, "node.json.bak", "{\"number\":\"123456789\",\"password\":\"AB\\\"CD-EFGH\"}\n");
    npf_destroy(instance(dir, NPF_ROLE_NODE, "udp_port = 0\n", NULL, err, sizeof err));
    /* (no server list here: npf_create stops later, at the configuration) */
    check(!strstr(err, "damaged") && strstr(file_text(dir, "node.json", text, sizeof text), "123456789")
              && strstr(text, "\"password\":\"AB\\\"CD-EFGH\""),
          "its copy taken, and the file written again (the password JSON-escaped)");
    rm_dir(dir);
}

/* safe mode (state.json and its copy damaged): the pairing calls neither
 * read nor change anything and say so (NPF_ESTATE, not NPF_ESAVE's "in
 * effect, not written"); a repaired file is taken at the next call */
static void safe_mode(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300] = "", pw[64];
    npf_pairing pr[4];
    size_t count = 9;
    npf_t *n;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    put_file(dir, "npf.conf", "root = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\nserver = wss://127.0.0.1:1/v1/ws\n"
                              "server_pub = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\n");
    put_file(dir, "node.json", "{\"number\":\"123456789\",\"password\":\"ABCD-EFGH\"}\n");
    put_file(dir, "state.json", "{\"password\":");
    put_file(dir, "state.json.bak", "not json");
    if (!(n = instance(dir, NPF_ROLE_NODE, "udp_port = 0\n", NULL, err, sizeof err))) {
        printf("     (%s)\n", err);
        check(0, "a node with a number");
        rm_dir(dir);
        return;
    }
    check(npf_pairing_password_set(n, "new-password-1", err, sizeof err) == NPF_ESTATE && strstr(err, "safe mode")
              && strstr(err, "not changed"),
          "safe mode: password set NPF_ESTATE, \"not changed ... safe mode\"");
    check(npf_pairing_password_get(n, pw, sizeof pw) == NPF_ESTATE && !pw[0], "password get: NPF_ESTATE, nothing");
    check(npf_pairing_list(n, pr, 4, &count) == NPF_ESTATE, "pairing list: NPF_ESTATE (who is paired is not known)");
    check(npf_pairing_remove(n, NULL) == NPF_ESTATE && npf_owner_reset(n) == NPF_ESTATE,
          "unpair and owner reset: NPF_ESTATE");
    put_file(dir, "state.json", "{\"password\":\"repaired-pw-1\",\"paired\":[]}\n");
    check(npf_pairing_password_set(n, "new-password-1", err, sizeof err) == NPF_OK
              && npf_pairing_password_get(n, pw, sizeof pw) == NPF_OK && strcmp(pw, "new-password-1") == 0,
          "the file repaired: taken, the password set");
    npf_destroy(n);
    rm_dir(dir);
}

/* roles (security.md D25): npf_pairing_list marks the admins (an entry of
 * before the roles is one), a member is none, an older, smaller
 * npf_pairing is still listed; an owner reset keeps the roles */
static void roles(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300] = "";
    /* keys 0x01.. and 0x02.. (Base64url of 32 bytes) */
    const char *ka = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", *kb = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t b[32] = {2};
    npf_pairing pr[4];
    struct { uint8_t key[32]; int64_t since; } old[4];     /* npf_pairing before admin */
    char st[400];
    size_t count = 0;
    npf_t *n;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return;
    }
    put_file(dir, "npf.conf", "root = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\nserver = wss://127.0.0.1:1/v1/ws\n"
                              "server_pub = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\n");
    put_file(dir, "node.json", "{\"number\":\"123456789\",\"password\":\"ABCD-EFGH\"}\n");
    snprintf(st, sizeof st, "{\"password\":\"pw-123456\",\"owner\":\"77\",\"paired\":[{\"pub\":\"%s\"},"
             "{\"pub\":\"%s\",\"role\":\"member\"}]}", ka, kb);
    put_file(dir, "state.json", st);
    if (!(n = instance(dir, NPF_ROLE_NODE, "udp_port = 0\n", NULL, err, sizeof err))) {
        printf("     (%s)\n", err);
        check(0, "a node with a number");
        rm_dir(dir);
        return;
    }
    check(npf_pairing_list(n, pr, 4, &count) == NPF_OK && count == 2 && pr[0].admin && !pr[1].admin,
          "pairing list: the admin (no role: of before the roles) marked, the member not");
    check(npf_pairing_list_size(n, (npf_pairing *)(void *)old, sizeof old[0], 4, &count) == NPF_OK && count == 2
              && memcmp(old[1].key, b, 32) == 0, "an older npf_pairing (no admin member) is listed as before");
    check(npf_owner_reset(n) == NPF_OK && npf_pairing_list(n, pr, 4, &count) == NPF_OK && pr[0].admin && !pr[1].admin
              && strstr(file_text(dir, "state.json", st, sizeof st), "\"role\":\"admin\""),
          "an owner reset keeps the roles; state.json writes them");
    npf_destroy(n);
    rm_dir(dir);
}

/* a structure not initialised (no _init: its size 0) or NULL: NPF_EINVAL
 * naming the _init, the number out 0, nothing made */
static void not_initialised(void)
{
    char dir[] = "/tmp/npf-contract-XXXXXX", err[300];
    npf_options zo;
    npf_peer_opt po;
    npf_forward_opt fo;
    npf_resource r;
    npf_media_opt mo;
    npf_resource_info ri[1];
    npf_t *n = NULL;
    uint32_t id = 7;
    size_t count = 9;
    memset(&zo, 0, sizeof zo);
    check(npf_create(&zo, &n, err, sizeof err) == NPF_EINVAL && !n && strstr(err, "(npf_options_init)"),
          "npf_create: options not initialised");
    check(npf_create(NULL, &n, err, sizeof err) == NPF_EINVAL && !n, "npf_create: no options");
    if (!mkdtemp(dir) || !(n = instance(dir, NPF_ROLE_DIRECT, "udp_port = 0\n", NULL, err, sizeof err))) {
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
    rm_dir(dir);
}

/* a shared runtime's callback never waits for another thread: a call for
 * an instance there, and npf_destroy, are refused (else two such calls at
 * once, each for the other's thread, would hang both) */
static npf_t *rt_n[3];
static int rt_rc[3];

static void on_runtime(void *user, int code, const char *text)
{
    char v[32];
    (void)user, (void)code, (void)text;
    rt_rc[0] = npf_config_get(rt_n[1], "max_calls", v, sizeof v);     /* B: on the other thread */
    rt_rc[1] = npf_config_get(rt_n[2], "max_calls", v, sizeof v);     /* C: on this one */
    rt_rc[2] = npf_config_get(rt_n[0], "max_calls", v, sizeof v);     /* A itself */
    npf_destroy(rt_n[1]);
}

static void runtime_guard(void)
{
    char dirs[3][32], err[300], v[32];
    const char *set[] = {"set", "max_calls", "30", "--no-save"};
    npf_runtime *rt = npf_runtime_new(2);
    npf_options o;
    int i, ok = rt != NULL;
    for (i = 0; i < 3; i++) {               /* A and C on the first thread, B on the second */
        snprintf(dirs[i], sizeof dirs[i], "/tmp/npf-contract-XXXXXX");
        npf_options_init(&o);
        o.conf_dir = mkdtemp(dirs[i]);
        o.role = NPF_ROLE_DIRECT;
        o.overrides = "udp_port = 0\n";
        o.runtime = rt;
        rt_n[i] = NULL;
        ok = ok && o.conf_dir && npf_create(&o, &rt_n[i], err, sizeof err) == NPF_OK && npf_start(rt_n[i]) == NPF_OK;
    }
    check(ok, "three instances on a runtime of two threads");
    if (ok) {
        check(npf_command(rt_n[0], 4, set, on_runtime, NULL) == NPF_OK && rt_rc[0] == NPF_ESTATE,
              "from a runtime's callback, a call for an instance on another thread: NPF_ESTATE, no wait");
        check(rt_rc[1] == NPF_OK && rt_rc[2] == NPF_OK, "for one on the same thread, and its own: done");
        check(npf_config_get(rt_n[1], "max_calls", v, sizeof v) == NPF_OK, "npf_destroy from there: refused");
    }
    for (i = 0; i < 3; i++) {
        npf_destroy(rt_n[i]);
        rm_dir(dirs[i]);
    }
    check(npf_runtime_free(rt) == NPF_OK, "the runtime freed");
}

int main(void)
{
    alarm(30);
    inits();
    not_initialised();
    unsaved();
    file_only();
    node_json();
    safe_mode();
    roles();
    runtime_guard();
    return fails != 0;
}

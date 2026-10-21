/* A program's module registered with npf_register_module: its state,
 * command, configuration key, status key and destroy; an instance created
 * before does not have them; twice, a name, command or key taken already
 * and more than the limit are refused; when a module's create fails only
 * those made before it are destroyed, the last first. */
#define _DEFAULT_SOURCE                     /* mkdtemp */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "npf.h"
#include "npf/module.h"
#include "npf/out.h"

#define NPF_MOD_LIMIT 8                     /* npf_register_module */

typedef struct acme {
    int calls;
} acme;

extern const npf_module acme_module;
static int destroyed;
static char order[64];                 /* the destroys of a failed create */

static int acme_create(npf_t *n, char *err, size_t errcap)
{
    acme *a = calloc(1, sizeof *a);
    if (!a) {
        snprintf(err, errcap, "acme: no memory");
        return -1;
    }
    npf_mod_set_state(n, &acme_module, a);
    return 0;
}

static void acme_destroy(npf_t *n)
{
    free(npf_mod_state(n, &acme_module));
    destroyed++;
    strcat(order, "acme ");
}

static int acme_hello(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    acme *a = npf_mod_state(n, &acme_module);
    (void)argc, (void)argv, (void)cb, (void)user;
    npf_out_printf(o, "hello %d\n", ++a->calls);
    return 0;
}

static void acme_status(npf_t *n, npf_out *o, int *first)
{
    acme *a = npf_mod_state(n, &acme_module);
    npf_mod_jkey(o, first, "acme");
    npf_out_printf(o, "{\"calls\":%d}", a->calls);
}

static int acme_check(npf_t *n, const char *k, const char *v, npf_out *o)
{
    (void)n;
    if (strcmp(v, "on") != 0 && strcmp(v, "off") != 0) {
        npf_out_printf(o, "%s: on or off\n", k);
        return 2;
    }
    return 0;
}

static const npf_mod_cmd acme_cmds[] = {{"hello", acme_hello}, {NULL, NULL}};
static const char *const acme_keys[] = {"acme_mode", NULL};
const npf_module acme_module = {.name = "acme", .create = acme_create, .destroy = acme_destroy,
                                .cmds = acme_cmds, .status_json = acme_status, .keys = acme_keys,
                                .check = acme_check};

/* clashes: each refused */
static const npf_mod_cmd status_cmds[] = {{"status", acme_hello}, {NULL, NULL}};
static const char *const builtin_keys[] = {"udp_port", NULL};
static const npf_module clash_name = {.name = "acme"};
static const npf_module clash_builtin_cmd = {.name = "b1", .cmds = status_cmds};
static const npf_module clash_builtin_key = {.name = "b2", .keys = builtin_keys};
static const npf_module clash_cmd = {.name = "b3", .cmds = acme_cmds};
static const npf_module clash_key = {.name = "b4", .keys = acme_keys};
static const npf_module no_name = {.name = ""};

/* a create that fails: what is destroyed, in which order */
static int first_create(npf_t *n, char *err, size_t errcap) { (void)n, (void)err, (void)errcap; return 0; }
static void first_destroy(npf_t *n) { (void)n; strcat(order, "first "); }
static int failing_create(npf_t *n, char *err, size_t errcap) { (void)n; snprintf(err, errcap, "failing: refused"); return -1; }
static void failing_destroy(npf_t *n) { (void)n; strcat(order, "failing "); }
static int after_create(npf_t *n, char *err, size_t errcap) { (void)n, (void)err, (void)errcap; strcat(order, "after-made "); return 0; }
static void after_destroy(npf_t *n) { (void)n; strcat(order, "after "); }
static const npf_module first_mod = {.name = "first", .create = first_create, .destroy = first_destroy};
static const npf_module failing_mod = {.name = "failing", .create = failing_create, .destroy = failing_destroy};
static const npf_module after_mod = {.name = "after", .create = after_create, .destroy = after_destroy};

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int got, got_code;
static char got_text[256];

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

/* the command's exit code, its text in got_text */
static int command(npf_t *n, const char *name)
{
    const char *argv[] = {name};
    pthread_mutex_lock(&mu);
    got = 0;
    pthread_mutex_unlock(&mu);
    if (npf_command(n, 1, argv, on_text, NULL) != NPF_OK)
        return -100;
    pthread_mutex_lock(&mu);
    while (!got)
        pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    return got_code;
}

static int fails;
static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

static npf_t *make(const char *dir, int *rc)
{
    npf_options o;
    npf_t *n = NULL;
    char err[300];
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = NPF_ROLE_DIRECT;
    o.overrides = "udp_port = 0\n";
    *rc = npf_create(&o, &n, err, sizeof err);
    if (*rc == NPF_OK && npf_start(n) != NPF_OK) {
        npf_destroy(n);
        *rc = -100;
        n = NULL;
    }
    return n;
}

static void cleanup(const char *dir)
{
    const char *files[] = {"identity", "seed", "local.json", "local.conf"};
    char path[400];
    size_t i;
    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        unlink(path);
    }
    rmdir(dir);
}

int main(void)
{
    char dir[] = "/tmp/npf-module-XXXXXX", dir2[] = "/tmp/npf-module-XXXXXX", err[300], val[64], *s;
    static npf_module others[NPF_MOD_LIMIT];
    static char names[NPF_MOD_LIMIT][16];
    npf_t *n, *before;
    int rc, i, ok;
    alarm(30);
    if (!mkdtemp(dir) || !mkdtemp(dir2))
        return 2;

    before = make(dir2, &rc);
    check(before != NULL, "an instance before the module is registered");
    check(npf_register_module(&acme_module) == 0, "the module registered");
    check(npf_register_module(&acme_module) < 0 && npf_register_module(NULL) < 0, "twice, or NULL: refused");
    check(npf_register_module(&clash_name) < 0 && npf_register_module(&no_name) < 0,
          "a name taken already, or none: refused");
    check(npf_register_module(&clash_builtin_cmd) < 0 && npf_register_module(&clash_builtin_key) < 0,
          "a command or key of libnpf's own: refused");
    check(npf_register_module(&clash_cmd) < 0 && npf_register_module(&clash_key) < 0,
          "a command or key of another module: refused");
    n = make(dir, &rc);
    check(n != NULL, "an instance created after has the module");
    if (!n)
        return 1;
    check(command(n, "hello") == 0 && strcmp(got_text, "hello 1\n") == 0, "the module's command, its state");
    s = npf_status_json(n);
    check(s && strstr(s, "\"acme\":{\"calls\":1}") != NULL, "the module's key in the status");
    npf_free(s);
    check(npf_config_set(n, "acme_mode", "maybe", 0, err, sizeof err) < 0 && strstr(err, "on or off"),
          "the module checks its configuration key");
    rc = npf_config_set(n, "acme_mode", "on", 0, err, sizeof err);
    check(rc >= 0 && npf_config_get(n, "acme_mode", val, sizeof val) == NPF_OK, "the module's key is known");
    npf_destroy(n);
    check(destroyed == 1, "the module's destroy");

    if (before) {
        check(command(before, "hello") != 0, "the earlier instance: no module's command");
        check(npf_config_get(before, "acme_mode", val, sizeof val) == NPF_ENOENT, "nor its key");
        npf_destroy(before);
    }
    check(destroyed == 1, "the earlier instance never called the module");

    destroyed = 0;
    order[0] = 0;
    check(npf_register_module(&first_mod) == 0 && npf_register_module(&failing_mod) == 0
          && npf_register_module(&after_mod) == 0, "three more registered");
    {
        npf_options o;
        npf_t *x = NULL;
        npf_options_init(&o);
        o.conf_dir = dir;
        o.role = NPF_ROLE_DIRECT;
        o.overrides = "udp_port = 0\n";
        rc = npf_create(&o, &x, err, sizeof err);
        check(rc != NPF_OK && !x && strstr(err, "failing: refused"), "a module's create fails: no instance, its reason");
        check(strcmp(order, "first acme ") == 0 && destroyed == 1,
              "only the modules made before it are destroyed, the last first");
    }

    for (i = 0, ok = 1; i < NPF_MOD_LIMIT - 4; i++) {
        snprintf(names[i], sizeof names[i], "other%d", i);
        others[i].name = names[i];
        ok &= npf_register_module(&others[i]) == 0;
    }
    others[i].name = "one-too-many";
    check(ok && npf_register_module(&others[i]) < 0, "up to the limit, not more");

    cleanup(dir);
    cleanup(dir2);
    return fails != 0;
}

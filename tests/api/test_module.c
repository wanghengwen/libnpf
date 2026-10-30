/* A program's module registered with npf_register_module: its state,
 * command, configuration key, status key and destroy; an instance created
 * before does not have them; twice, a name, command or key taken already
 * and more than the limit are refused; when a module's create fails only
 * those made before it are destroyed, the last first. */
#define _DEFAULT_SOURCE                     /* mkdtemp */
#include <stdlib.h>

#include "api_test.h"
#include "npf/conf.h"
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

static void acme_status(npf_t *n, npf_out *o)
{
    acme *a = npf_mod_state(n, &acme_module);
    npf_out_jkey(o, "acme");
    npf_out_printf(o, "{\"calls\":%d}", a->calls);
}

static char acme_set[64];           /* the last live key set: "key=value" */
static void acme_conf_set(npf_t *n, const char *k, const char *v)
{
    (void)n;
    snprintf(acme_set, sizeof acme_set, "%s=%s", k, v);
}

static const npf_mod_cmd acme_cmds[] = {{"hello", acme_hello}, {NULL, NULL}};
static const npf_key acme_keys[] = {NPF_KEY_E("acme_mode", 0, "off", "on|off"), NPF_KEY_E("acme_live", NPF_K_LIVE, "a", "a|b"),
                                     NPF_KEY_S("acme_file", NPF_K_FILE), NPF_KEY_END};
const npf_module acme_module = {.name = "acme", .create = acme_create, .destroy = acme_destroy,
                                .cmds = acme_cmds, .status_json = acme_status, .keys = acme_keys,
                                .conf_set = acme_conf_set};

/* clashes: each refused */
static const npf_mod_cmd set_cmds[] = {{"set", acme_hello}, {NULL, NULL}};
static const npf_key builtin_keys[] = {NPF_KEY_S("udp_port", 0), NPF_KEY_END};
static const npf_module clash_name = {.name = "acme"};
static const npf_module clash_builtin_cmd = {.name = "b1", .cmds = set_cmds};
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

static const char *const hello[] = {"hello"};

/* a started instance in dir */
static npf_t *make(const char *dir)
{
    char err[300];
    npf_t *n = instance(dir, NPF_ROLE_DIRECT, "udp_port = 0\n", NULL, err, sizeof err);
    if (n && npf_start(n) != NPF_OK) {
        npf_destroy(n);
        n = NULL;
    }
    return n;
}

int main(void)
{
    char dir[] = "/tmp/npf-module-XXXXXX", dir2[] = "/tmp/npf-module-XXXXXX", err[300], val[64], *s;
    static npf_module others[NPF_MOD_LIMIT];
    static char names[NPF_MOD_LIMIT][16];
    npf_t *n, *before;
    int rc, i, ok, restart = -1;
    alarm(30);
    if (!mkdtemp(dir) || !mkdtemp(dir2))
        return 2;

    before = make(dir2);
    check(before != NULL, "an instance before the module is registered");
    check(npf_register_module(&acme_module) == 0, "the module registered");
    check(npf_register_module(&acme_module) < 0 && npf_register_module(NULL) < 0, "twice, or NULL: refused");
    check(npf_register_module(&clash_name) < 0 && npf_register_module(&no_name) < 0,
          "a name taken already, or none: refused");
    check(npf_register_module(&clash_builtin_cmd) < 0 && npf_register_module(&clash_builtin_key) < 0,
          "a command or key of libnpf's own: refused");
    check(npf_register_module(&clash_cmd) < 0 && npf_register_module(&clash_key) < 0,
          "a command or key of another module: refused");
    n = make(dir);
    check(n != NULL, "an instance created after has the module");
    if (!n)
        return 1;
    check(cmd(n, 1, hello) == 0 && strcmp(cmd_text, "hello 1\n") == 0, "the module's command, its state");
    s = npf_status_json(n);
    check(s && strstr(s, "\"acme\":{\"calls\":1}") != NULL, "the module's key in the status");
    npf_free(s);
    check(npf_config_set(n, "acme_mode", "maybe", 0, NULL, err, sizeof err) < 0 && strstr(err, "on or off"),
          "its key checked by its table");
    rc = npf_config_set(n, "acme_mode", "on", 0, &restart, err, sizeof err);
    check(rc == NPF_OK && restart == 1 && npf_config_get(n, "acme_mode", val, sizeof val) == NPF_OK,
          "the module's key is known, a start-up one: NPF_OK, restart 1");
    check(!acme_set[0] && npf_config_set(n, "peer_idle", "7", 0, &restart, err, sizeof err) == NPF_OK && !restart
          && strcmp(acme_set, "peer_idle=7") == 0,
          "a live key set (restart 0): the module hears it (conf_set), not its own key (not live)");
    check(npf_config_set(n, "acme_live", "b", 0, NULL, err, sizeof err) == 0 && strcmp(acme_set, "acme_live=b") == 0
          && npf_config_set(n, "acme_file", "x", 0, NULL, err, sizeof err) == NPF_EINVAL && strstr(err, "only in npf.conf"),
          "its live key in effect at once, its file key refused");
    s = npf_config_json(n);
    check(s && strstr(s, "\"acme_live\":\"b\"") && !strstr(s, "acme_mode"), "its live key listed");
    npf_free(s);
    check(npf_key_is("password", NPF_K_SECRET) && npf_key_is("cred", NPF_K_SECRET) && npf_key_is("model_cred", NPF_K_SECRET)
          && npf_key_is("direct_psk", NPF_K_SECRET) && !npf_key_is("log_level", NPF_K_SECRET),
          "the credentials and the password are hidden in get");
    npf_destroy(n);
    check(destroyed == 1, "the module's destroy");

    if (before) {
        check(cmd(before, 1, hello) != 0, "the earlier instance: no module's command");
        npf_destroy(before);
    }
    check(destroyed == 1, "the earlier instance never called the module");

    destroyed = 0;
    order[0] = 0;
    check(npf_register_module(&first_mod) == 0 && npf_register_module(&failing_mod) == 0
          && npf_register_module(&after_mod) == 0, "three more registered");
    check(!instance(dir, NPF_ROLE_DIRECT, "udp_port = 0\n", &rc, err, sizeof err) && rc != NPF_OK
          && strstr(err, "failing: refused"), "a module's create fails: no instance, its reason");
    check(strcmp(order, "first acme ") == 0 && destroyed == 1, "only the modules made before it are destroyed, the last first");

    for (i = 0, ok = 1; i < NPF_MOD_LIMIT - 4; i++) {
        snprintf(names[i], sizeof names[i], "other%d", i);
        others[i].name = names[i];
        ok &= npf_register_module(&others[i]) == 0;
    }
    others[i].name = "one-too-many";
    check(ok && npf_register_module(&others[i]) < 0, "up to the limit, not more");

    rm_dir(dir);
    rm_dir(dir2);
    return fails != 0;
}

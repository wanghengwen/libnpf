/* Deterministic scheduling at the API's job allocation: destroy must wait for
 * a caller that has entered but has not posted yet. Compile the real
 * api_thread.c (sync_call and its job) here so this hook never becomes part
 * of the installed library. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static void *test_calloc(size_t count, size_t size);
#define calloc test_calloc
#include "../../src/api/api_thread.c"
#undef calloc

static pthread_mutex_t test_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_cv = PTHREAD_COND_INITIALIZER;
static int armed, entered, resume_call, destroyed;

static void *test_calloc(size_t count, size_t size)
{
    pthread_mutex_lock(&test_mu);
    if (armed && size == sizeof(job)) {
        armed = 0; entered = 1;
        pthread_cond_broadcast(&test_cv);
        while (!resume_call) pthread_cond_wait(&test_cv, &test_mu);
    }
    pthread_mutex_unlock(&test_mu);
    return calloc(count, size);
}
static void *query_thread(void *arg) { npf_free(npf_status_json(arg)); return NULL; }
static void *destroy_thread(void *arg)
{
    npf_destroy(arg);
    pthread_mutex_lock(&test_mu);
    destroyed = 1;
    pthread_mutex_unlock(&test_mu);
    return NULL;
}
int main(void)
{
    char dir[] = "/tmp/npf-lifecycle-XXXXXX", err[300], path[400];
    npf_options o;
    npf_t *n;
    pthread_t caller, destroyer;
    int closing = 0, ok;
    alarm(30);
    if (!mkdtemp(dir)) return 2;
    npf_options_init(&o);
    o.conf_dir = dir; o.role = NPF_ROLE_DIRECT; o.overrides = "udp_port = 0\n";
    if (npf_create(&o, &n, err, sizeof err) || npf_start(n)) return 2;
    pthread_mutex_lock(&test_mu);
    armed = 1;
    pthread_create(&caller, NULL, query_thread, n);
    while (!entered) pthread_cond_wait(&test_cv, &test_mu);
    pthread_mutex_unlock(&test_mu);
    pthread_create(&destroyer, NULL, destroy_thread, n);
    while (!closing) {
        npf_api_lock(n);
        closing = n->sync->destroying;
        npf_api_unlock(n);
        if (!closing) usleep(1000);
    }
    pthread_mutex_lock(&test_mu);
    ok = !destroyed;
    resume_call = 1;
    pthread_cond_broadcast(&test_cv);
    pthread_mutex_unlock(&test_mu);
    pthread_join(caller, NULL);
    pthread_join(destroyer, NULL);
    snprintf(path, sizeof path, "%s/identity", dir); unlink(path);
    snprintf(path, sizeof path, "%s/seed", dir); unlink(path);
    rmdir(dir);
    printf("%s destroy waits for an entered, not-yet-posted API call\n", ok ? "PASS" : "FAIL");
    return !ok;
}

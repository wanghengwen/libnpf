/* What libnpf's API tests share, on npf.h and the C library only
 * (test_api.c builds on an installed SDK too): the checks (a PASS or FAIL
 * line each), waits, temporary directories and their files, an instance,
 * a command's answer. */
#ifndef NPF_API_TEST_H
#define NPF_API_TEST_H

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "npf.h"

static int fails;

static inline void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

static inline void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* cond polled every 10 ms, at most ms */
#define WAIT_UNTIL(cond, ms) do { \
    int left_ = (ms) / 10; \
    while (!(cond) && left_-- > 0) \
        sleep_ms(10); \
} while (0)

/* a directory made by mkdtemp, with what is in it */
static inline void rm_dir(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[1024];
    while (d && (e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")
            && snprintf(path, sizeof path, "%s/%s", dir, e->d_name) < (int)sizeof path && unlink(path) < 0)
            rm_dir(path);               /* a directory */
    if (d)
        closedir(d);
    rmdir(dir);
}

/* dir/name's text in out ("" when there is none) */
static inline char *file_text(const char *dir, const char *name, char *out, size_t cap)
{
    char path[1024];
    FILE *f;
    size_t l = 0;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if ((f = fopen(path, "r"))) {
        l = fread(out, 1, cap - 1, f);
        fclose(f);
    }
    out[l] = 0;
    return out;
}

static inline void put_file(const char *dir, const char *name, const char *text)
{
    char path[1024];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if ((f = fopen(path, "w"))) {
        fputs(text, f);
        fclose(f);
    }
}

/* npf_create in dir as role with overrides: the instance (NULL when it
 * failed: the reason in err), npf_create's code in *rc (rc may be NULL) */
static inline npf_t *instance(const char *dir, int role, const char *ov, int *rc, char *err, size_t errcap)
{
    npf_options o;
    npf_t *n = NULL;
    int r;
    npf_options_init(&o);
    o.conf_dir = dir;
    o.role = role;
    o.overrides = ov;
    r = npf_create(&o, &n, err, errcap);
    if (rc)
        *rc = r;
    return n;
}

/* npf_command: its exit code (-1: no answer in 5 s), its text in cmd_text */
static char cmd_text[512] __attribute__((unused));
static pthread_mutex_t cmd_mu __attribute__((unused)) = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cmd_cv __attribute__((unused)) = PTHREAD_COND_INITIALIZER;
static int cmd_done __attribute__((unused)), cmd_code __attribute__((unused));

static inline void cmd_answer(void *user, int code, const char *text)
{
    (void)user;
    pthread_mutex_lock(&cmd_mu);
    cmd_done = 1;
    cmd_code = code;
    snprintf(cmd_text, sizeof cmd_text, "%s", text ? text : "");
    pthread_cond_broadcast(&cmd_cv);
    pthread_mutex_unlock(&cmd_mu);
}

static inline int cmd(npf_t *n, int argc, const char *const *argv)
{
    struct timespec t;
    int code = -1;
    pthread_mutex_lock(&cmd_mu);
    cmd_done = 0;
    cmd_text[0] = 0;
    pthread_mutex_unlock(&cmd_mu);
    if (npf_command(n, argc, argv, cmd_answer, NULL) != NPF_OK)
        return -1;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += 5;
    pthread_mutex_lock(&cmd_mu);
    while (!cmd_done && pthread_cond_timedwait(&cmd_cv, &cmd_mu, &t) == 0)
        ;
    if (cmd_done)
        code = cmd_code;
    pthread_mutex_unlock(&cmd_mu);
    return code;
}

#endif

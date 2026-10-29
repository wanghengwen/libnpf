/* What the unit tests share. CHECK and EXPECT count a failure (printed with
 * its line: CHECK's message, EXPECT's expression) and go on: a test function
 * returns its file's count. REQUIRE returns 1 from the function at once (the
 * tests that are programs of their own). */
#ifndef NPF_TEST_H
#define NPF_TEST_H

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "npf/loop.h"
#include "npf/platform.h"

static int fails __attribute__((unused));

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } \
} while (0)
#define EXPECT(cond) CHECK(cond, "%s", #cond)
#define REQUIRE(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

/* run the loop until cond holds, at most ms */
#define LOOP_UNTIL(loop, cond, ms) do { \
    int64_t until_ = npf_mono_ms() + (ms); \
    while (!(cond) && npf_mono_ms() < until_) \
        npf_loop_once((loop), 5); \
} while (0)

static inline void hex2bin(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* a non-blocking socket on 127.0.0.1, a port of its own (a stream one
 * listening with backlog); its address in addr, a sockaddr_in or larger
 * (size bytes: the rest zero); -1 on failure */
static inline int lo_socket(int type, int backlog, void *addr, size_t size)
{
    struct sockaddr_in *a = addr;
    socklen_t l = sizeof *a;
    int fd = socket(AF_INET, type, 0);
    memset(addr, 0, size);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || bind(fd, (struct sockaddr *)a, sizeof *a) < 0
        || getsockname(fd, (struct sockaddr *)a, &l) < 0 || (type == SOCK_STREAM && listen(fd, backlog) < 0)) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

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

#ifdef NPF_NODE_H                       /* the tests of a node (npf/node.h) */
/* an offline node on loop, a random identity, hooks (NULL: none) with
 * their arg; 0 ok */
static inline int offline_node(npf_node *n, npf_loop *loop, const npf_node_hooks *hooks, void *arg)
{
    npf_node_cfg cfg;
    npf_identity id;
    uint8_t seed[32];
    memset(&cfg, 0, sizeof cfg);
    cfg.offline = 1;
    npf_random(seed, sizeof seed);
    npf_identity_from_seed(&id, seed);
    return loop ? npf_node_init(n, loop, &cfg, &id, hooks, arg) : -1;
}

/* the lines logged at debug and up while log_capture's context is in
 * effect (npf_log_ctx_swap back to what it returned), since log_clear */
static char logged[8192] __attribute__((unused));
static size_t logged_len __attribute__((unused));

static inline void logged_line(void *user, int level, const char *line)
{
    size_t l = strlen(line);
    (void)user, (void)level;
    if (logged_len + l + 2 < sizeof logged) {
        memcpy(logged + logged_len, line, l);
        logged_len += l;
        logged[logged_len++] = '\n';
        logged[logged_len] = 0;
    }
}

static inline void log_clear(void)
{
    logged_len = 0;
    logged[0] = 0;
}

static inline npf_log_ctx *log_capture(npf_log_ctx *lc)
{
    memset(lc, 0, sizeof *lc);
    lc->hook = logged_line;
    lc->level = NPF_LOG_DEBUG;
    return npf_log_ctx_swap(lc);
}

/* how many times what is in s */
static inline int count_of(const char *s, const char *what)
{
    int k = 0;
    for (; (s = strstr(s, what)) != NULL; s++)
        k++;
    return k;
}
#endif

#endif

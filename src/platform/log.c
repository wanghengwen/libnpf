/* Logging (npf/log.h): the process log's sink writes a line under a lock to
 * the application's writer (its log file) or stderr and keeps the last lines
 * in memory for the control socket. A libnpf instance's lines (this thread's
 * log context) stay with the instance: its recent lines and its callback,
 * which runs outside every lock. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "npf/lock.h"
#include "npf/log.h"
#include "npf/platform.h"
#include "npf/sys.h"

static npf_mutex g_lock = NPF_MUTEX_INIT;
void npf_log_lock(void) { npf_mutex_lock(&g_lock); }
void npf_log_unlock(void) { npf_mutex_unlock(&g_lock); }

static void (*g_writer)(const char *line, size_t len);     /* NULL: stderr */
static int   g_level = NPF_LOG_INFO;     /* the process's; atomic */
static NPF_THREAD_LOCAL npf_log_ctx *t_ctx;

#define LOAD(v)     __atomic_load_n(&(v), __ATOMIC_RELAXED)
#define STORE(v, x) __atomic_store_n(&(v), (x), __ATOMIC_RELAXED)

#define RING NPF_LOG_RING             /* recent lines for the log command */
static char   g_ring[RING];
static size_t g_ring_pos, g_ring_len;

static const char *const names[] = {"trace", "debug", "info", "warn", "error"};
static const char *const tags[] = {"TRACE", "DEBUG", "INFO ", "WARN ", "ERROR"};

static void ring_put(char *ring, size_t *pos, size_t *len, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        ring[*pos] = s[i];
        *pos = (*pos + 1) % RING;
    }
    *len = *len + n > RING ? RING : *len + n;
}

/* "date time.ms LEVEL message[ (file:line)]\n"; its length (> 0) */
static int make_line(int lv, const char *file, int ln, const char *msg, char *line, size_t cap)
{
    char tb[32];
    int64_t ms = npf_unix_ms();
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
    int n;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(tb, sizeof tb, "%Y-%m-%d %H:%M:%S", &tm);
    if (lv <= NPF_LOG_DEBUG) {
        const char *f = strrchr(file, '/');
        n = snprintf(line, cap, "%s.%03d %s %s (%s:%d)\n", tb, (int)(ms % 1000), tags[lv], msg, f ? f + 1 : file, ln);
    } else {
        n = snprintf(line, cap, "%s.%03d %s %s\n", tb, (int)(ms % 1000), tags[lv], msg);
    }
    if (n < 0) {
        line[0] = '\n';
        return 1;
    }
    if ((size_t)n >= cap) {
        n = (int)cap - 1;
        line[n - 1] = '\n';
    }
    return n;
}

/* the terminal gets the time only */
void npf_log_stderr(const char *line, size_t len)
{
    size_t skip = len > 11 ? 11 : 0;        /* make_line returns one byte on a formatting error */
    fwrite(line + skip, 1, len - skip, stderr);
    fflush(stderr);
}

void npf_log_set_writer(void (*fn)(const char *line, size_t len))
{
    npf_log_lock();
    g_writer = fn;
    npf_log_unlock();
}

npf_log_ctx *npf_log_ctx_swap(npf_log_ctx *c)
{
    npf_log_ctx *old = t_ctx;
    t_ctx = c;
    return old;
}

static int level_now(void)
{
    return t_ctx ? t_ctx->level : LOAD(g_level);
}

void npf_log_at(int level, const char *file, int line, const char *fmt, ...)
{
    char msg[2048], ln[2300];
    va_list ap;
    npf_log_ctx *c = t_ctx;
    int lv = level < 0 ? 0 : level > NPF_LOG_ERROR ? NPF_LOG_ERROR : level, n;
    if (level < level_now())
        return;
    va_start(ap, fmt);
#ifdef __MINGW32__
    __mingw_vsnprintf(msg, sizeof msg, fmt, ap);
#else
    vsnprintf(msg, sizeof msg, fmt, ap);
#endif
    va_end(ap);
    n = make_line(lv, file, line, msg, ln, sizeof ln);
    if (c) {                                /* an instance's line: its ring, its callback */
        if (c->ring)
            ring_put(c->ring, &c->ring_pos, &c->ring_len, ln, (size_t)n);
        if (c->hook) {
            ln[n - 1] = 0;                  /* the line without its newline; no lock held */
            c->hook(c->user, lv, ln);
            return;
        }
    }
    npf_log_lock();                         /* the process log: the writer runs under the lock */
    ring_put(g_ring, &g_ring_pos, &g_ring_len, ln, (size_t)n);
    if (g_writer)
        g_writer(ln, (size_t)n);
    else
        npf_log_stderr(ln, (size_t)n);
    npf_log_unlock();
}

void npf_log_set_level(int level)
{
    if (level < NPF_LOG_TRACE || level > NPF_LOG_ERROR)
        return;
    if (t_ctx)
        t_ctx->level = level;
    else
        STORE(g_level, level);
}

int npf_log_get_level(void)
{
    return level_now();
}

int npf_log_on(int level)
{
    return level >= level_now();
}

int npf_log_level_parse(const char *s)
{
    int i;
    for (i = 0; s && i <= NPF_LOG_ERROR; i++)
        if (strcmp(s, names[i]) == 0)
            return i;
    return -1;
}

const char *npf_log_level_name(int level)
{
    return level >= NPF_LOG_TRACE && level <= NPF_LOG_ERROR ? names[level] : "?";
}

static size_t ring_copy(const char *ring, size_t pos, size_t len, char *out, size_t cap)
{
    size_t n, start, skip = 0, i;
    n = len;
    start = (pos + RING - n) % RING;
    if (n > cap - 1)
        skip = n - (cap - 1);
    /* whole lines only: after a cut, start past the next newline */
    if (skip || n == RING) {
        while (skip < n && ring[(start + skip) % RING] != '\n')
            skip++;
        if (skip < n)
            skip++;
    }
    for (i = skip; i < n; i++)
        out[i - skip] = ring[(start + i) % RING];
    out[n - skip] = 0;
    return n - skip;
}

size_t npf_log_recent(char *out, size_t cap)
{
    size_t r;
    if (!cap)
        return 0;
    if (t_ctx) {                            /* the instance's: only its thread touches it */
        if (!t_ctx->ring) {
            out[0] = 0;
            return 0;
        }
        return ring_copy(t_ctx->ring, t_ctx->ring_pos, t_ctx->ring_len, out, cap);
    }
    npf_log_lock();
    r = ring_copy(g_ring, g_ring_pos, g_ring_len, out, cap);
    npf_log_unlock();
    return r;
}

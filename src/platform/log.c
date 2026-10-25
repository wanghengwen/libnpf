/* Logging (npf/log.h): rxi/log.c dispatches by level under a lock; the one
 * sink here writes the line to the log file (rotated) or stderr and keeps the
 * last lines in memory for the control socket. A libnpf instance's lines
 * (this thread's log context) stay with the instance: its recent lines and
 * its callback, which runs outside every lock. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "log.h"                    /* third_party/log */
#include "npf/log.h"
#include "npf/platform.h"
#include "npf/sys.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
static SRWLOCK g_lock = SRWLOCK_INIT;
static void lock_fn(bool lock, void *udata)
{
    (void)udata;
    if (lock)
        AcquireSRWLockExclusive(&g_lock);
    else
        ReleaseSRWLockExclusive(&g_lock);
}
#else
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void lock_fn(bool lock, void *udata)
{
    (void)udata;
    if (lock)
        pthread_mutex_lock(&g_lock);
    else
        pthread_mutex_unlock(&g_lock);
}
#endif

static FILE *g_logf;                /* NULL: stderr */
static int   g_echo;                /* daemon start-up: the terminal sees the log too */
static int   g_own_stderr = 1;      /* stderr goes to the log file too (not in an application) */
static char  g_log_path[1024];
static long  g_log_max = 10L << 20;
static long  g_log_size;            /* bytes in the file (counted: no ftell per line) */
static long  g_log_rot;             /* rotated past this size (g_log_max; more after a failed rotation) */
static int   g_level = NPF_LOG_INFO;     /* the process's; atomic */
static NPF_THREAD_LOCAL npf_log_ctx *t_ctx;

#define LOAD(v)     __atomic_load_n(&(v), __ATOMIC_RELAXED)
#define STORE(v, x) __atomic_store_n(&(v), (x), __ATOMIC_RELAXED)

#define RING NPF_LOG_RING             /* recent lines for the log command */
static char   g_ring[RING];
static size_t g_ring_pos, g_ring_len;

static const char *const names[] = {"trace", "debug", "info", "warn", "error"};
static const char *const tags[] = {"TRACE", "DEBUG", "INFO ", "WARN ", "ERROR"};

static int log_attach(int to_stderr)
{
#ifndef _WIN32
    /* a new log is private (0600); an existing one keeps its mode */
    int fd = open(g_log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    FILE *f = fd >= 0 ? fdopen(fd, "a") : NULL;
    if (!f) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
#else
    /* as on POSIX: a new log is private, the handle not inherited (N) */
    int existed = GetFileAttributesA(g_log_path) != INVALID_FILE_ATTRIBUTES;
    FILE *f = fopen(g_log_path, "aN");
    if (!f)
        return -1;
    if (!existed)
        npf_file_private(g_log_path);
#endif
#ifndef _WIN32
    fcntl(fileno(f), F_SETFD, FD_CLOEXEC);
    if (to_stderr)
        dup2(fileno(f), 2);         /* stray stderr output lands in the log too */
#else
    if (to_stderr) {
        /* as POSIX dup2s: stray stderr output (a start-up error, the CRT's
         * own messages) lands in the log too. A handle of its own that
         * shares delete, so that it does not hold the file against the
         * rotation's rename */
        HANDLE h = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        int fd = h != INVALID_HANDLE_VALUE ? _open_osfhandle((intptr_t)h, _O_WRONLY | _O_APPEND) : -1;
        if (fd >= 0) {
            fflush(stderr);
            if (_dup2(fd, 2) == 0) {
                HANDLE e = (HANDLE)_get_osfhandle(2);
                SetHandleInformation(e, HANDLE_FLAG_INHERIT, 0);    /* _dup2 makes it inheritable */
                SetStdHandle(STD_ERROR_HANDLE, e);
            }
            _close(fd);
        } else if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
#endif
    if (g_logf)
        fclose(g_logf);
    g_logf = f;
    fseek(f, 0, SEEK_END);
    g_log_size = ftell(f);
    if (g_log_size < 0)
        g_log_size = 0;
    g_log_rot = g_log_max;
    return 0;
}

static void log_rotate(void)
{
    char old[1100];
    snprintf(old, sizeof old, "%s.1", g_log_path);
    fclose(g_logf);
    g_logf = NULL;
    remove(old);
    if (rename(g_log_path, old) != 0) {
        /* held open elsewhere (Windows) or the directory not writable: the
         * file is not rotated at each line from now on, it goes on growing
         * to twice the size and then this tries again */
        if (log_attach(!g_echo && g_own_stderr) == 0)
            g_log_rot = g_log_size + g_log_max;
        return;
    }
    log_attach(!g_echo && g_own_stderr);
}

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

/* rxi/log.c callback, called under the lock; ev->fmt is "%s" with the
 * formatted message. Only the process log: no application code here. */
static void sink(log_Event *ev)
{
    char line[2300];
    int lv = ev->level < 0 ? 0 : ev->level > NPF_LOG_ERROR ? NPF_LOG_ERROR : ev->level;
    const char *msg = va_arg(ev->ap, const char *);
    int n = make_line(lv, ev->file, ev->line, msg, line, sizeof line);
    ring_put(g_ring, &g_ring_pos, &g_ring_len, line, (size_t)n);
    /* a file gets the date as well; the terminal only the time */
    if (g_logf) {
        fwrite(line, 1, (size_t)n, g_logf);
        fflush(g_logf);
        g_log_size += n;
    }
    if (!g_logf || g_echo) {
        size_t skip = n > 11 ? 11 : 0;     /* make_line returns one byte on a formatting error */
        fwrite(line + skip, 1, (size_t)n - skip, stderr);
        fflush(stderr);
    }
    if (g_logf && g_log_size > g_log_rot)
        log_rotate();
}

static void init_rxi(void)
{
    log_set_lock(lock_fn, NULL);
    log_set_quiet(true);            /* rxi's own stderr writer: the sink does it */
    log_set_level(NPF_LOG_TRACE);   /* filtered in npf_log_at, before formatting */
    log_add_callback(sink, NULL, NPF_LOG_TRACE);
}

#ifdef _WIN32
static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK once_fn(PINIT_ONCE o, PVOID p, PVOID *c)
{
    (void)o;
    (void)p;
    (void)c;
    init_rxi();
    return TRUE;
}
static void init(void)
{
    InitOnceExecuteOnce(&g_once, once_fn, NULL, NULL);
}
#else
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void init(void)
{
    pthread_once(&g_once, init_rxi);
}
#endif

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
    char msg[2048];
    va_list ap;
    npf_log_ctx *c = t_ctx;
    if (level < level_now())
        return;
    init();
    va_start(ap, fmt);
#ifdef __MINGW32__
    __mingw_vsnprintf(msg, sizeof msg, fmt, ap);
#else
    vsnprintf(msg, sizeof msg, fmt, ap);
#endif
    va_end(ap);
    if (c) {                                /* an instance's line: its ring, its callback */
        char ln[2300];
        int lv = level < 0 ? 0 : level > NPF_LOG_ERROR ? NPF_LOG_ERROR : level;
        int n = make_line(lv, file, line, msg, ln, sizeof ln);
        if (c->ring)
            ring_put(c->ring, &c->ring_pos, &c->ring_len, ln, (size_t)n);
        if (c->hook) {
            ln[n - 1] = 0;                  /* the line without its newline; no lock held */
            c->hook(c->user, lv, ln);
            return;
        }
    }
    log_log(level, file, line, "%s", msg);
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

static size_t ring_copy(const char *ring, size_t pos, size_t len, char *out, size_t cap);

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
    lock_fn(true, NULL);
    r = ring_copy(g_ring, g_ring_pos, g_ring_len, out, cap);
    lock_fn(false, NULL);
    return r;
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

/* ---- files (npf/log.h) ---- */

int npf_log_open(const char *path, long max_bytes)
{
    char abs[sizeof g_log_path];
    int r;
    if (npf_abspath(path, abs, sizeof abs) < 0)
        return -1;
    lock_fn(true, NULL);                /* a line being written may rotate the old path */
    memcpy(g_log_path, abs, sizeof abs);
    if (max_bytes > 0)
        g_log_max = max_bytes;
    g_own_stderr = 1;
    r = log_attach(1);
    lock_fn(false, NULL);
    return r;
}

int npf_log_open_app(const char *path, long max_bytes)
{
    char abs[sizeof g_log_path];
    int r;
    if (npf_abspath(path, abs, sizeof abs) < 0)
        return -1;
    lock_fn(true, NULL);                /* a line being written may rotate the old path */
    memcpy(g_log_path, abs, sizeof abs);
    if (max_bytes > 0)
        g_log_max = max_bytes;
    g_own_stderr = 0;
    r = log_attach(0);
    lock_fn(false, NULL);
    return r;
}

/* Unix daemon start-up: path is absolute; stderr is still the terminal and
 * sees every line until npf_log_detach_terminal() */
int npf_log_open_daemon(const char *path)
{
    int r;
    lock_fn(true, NULL);
    snprintf(g_log_path, sizeof g_log_path, "%s", path);
    r = log_attach(0);
    g_echo = r == 0;
    lock_fn(false, NULL);
    return r;
}

void npf_log_detach_terminal(void)
{
    lock_fn(true, NULL);
    g_echo = 0;
#ifndef _WIN32
    if (g_logf)
        dup2(fileno(g_logf), 2);    /* from now on the terminal may be gone */
#endif
    lock_fn(false, NULL);
}

void npf_log_reopen(void)
{
    if (!g_log_path[0])
        return;
    lock_fn(true, NULL);
    log_attach(!g_echo && g_own_stderr);
    lock_fn(false, NULL);
}

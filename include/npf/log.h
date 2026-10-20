/* Logging: levels and sinks on rxi/log.c (third_party/log, MIT).
 *
 *   2026-10-06 13:01:14.013 INFO  call x: direct path 1.2.3.4:5 (213 ms)
 *
 * One line per event: local date and time with milliseconds (the terminal
 * gets the time only), the level, the message; DEBUG and TRACE add the
 * source file and line. The level comes from the configuration (log_level =
 * error | warn | info | debug | trace, default info) and can be changed at
 * run time. Thread-safe: the resolver thread logs too.
 *
 * libnpf instances: each has a log context (its level, its recent lines,
 * the application's callback). The thread that works for an instance (its
 * loop thread, or a caller while it does not run) has it set; lines logged
 * there go to that instance only. Lines of other threads go to the process
 * log (stderr or the log file). */
#ifndef NPF_LOG_H
#define NPF_LOG_H

#include <stddef.h>

/* the same values as rxi/log.c's LOG_TRACE .. LOG_FATAL */
enum { NPF_LOG_TRACE, NPF_LOG_DEBUG, NPF_LOG_INFO, NPF_LOG_WARN, NPF_LOG_ERROR };

/* MinGW: the C99 formats (%zu, %lld) of its own printf (log.c uses it) */
#ifdef __MINGW32__
#define NPF_LOG_FORMAT __attribute__((format(gnu_printf, 4, 5)))
#else
#define NPF_LOG_FORMAT __attribute__((format(printf, 4, 5)))
#endif
void npf_log_at(int level, const char *file, int line, const char *fmt, ...) NPF_LOG_FORMAT;

#define npf_loge(...) npf_log_at(NPF_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logw(...) npf_log_at(NPF_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define npf_log(...)  npf_log_at(NPF_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logd(...) npf_log_at(NPF_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logt(...) npf_log_at(NPF_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

/* the level of this thread's instance, else of the process */
void npf_log_set_level(int level);
int  npf_log_get_level(void);
/* is a message at this level written? (to skip expensive formatting) */
int  npf_log_on(int level);
/* "error", "warn", "info", "debug", "trace" -> level; -1 if unknown */
int  npf_log_level_parse(const char *s);
const char *npf_log_level_name(int level);

/* the last lines logged (this thread's instance, else the process), oldest
 * first: copies up to cap bytes (whole lines) and returns the length */
size_t npf_log_recent(char *out, size_t cap);

/* ---- log files (the application's daemon and service use them) ---- */

/* log to path (append) instead of stderr; rotated to path.1 at max_bytes
 * (0 = 10 MB). 0 or -1. */
int  npf_log_open(const char *path, long max_bytes);
/* the same in an application: the file only, its stderr left alone (other
 * code writes there: an Android GPU driver) */
int  npf_log_open_app(const char *path, long max_bytes);
void npf_log_reopen(void);
/* Unix daemon start-up (service.c): open the log at an absolute path while
 * stderr, still the terminal, sees every line too; then let go of it */
int  npf_log_open_daemon(const char *path);
void npf_log_detach_terminal(void);

/* ---- an instance's log (libnpf) ---- */

#define NPF_LOG_RING 16384

typedef struct npf_log_ctx {
    /* the application's callback (NULL: the process log); called with no
     * lock held, on the thread that logged */
    void  (*hook)(void *user, int level, const char *line);
    void   *user;
    int     level;
    char   *ring;                 /* recent lines, NPF_LOG_RING bytes (NULL: none kept,
                                     the application's hook has every line) */
    size_t  ring_pos, ring_len;
} npf_log_ctx;

/* this thread now works for c (NULL: for no instance); returns the one before */
npf_log_ctx *npf_log_ctx_swap(npf_log_ctx *c);

#endif

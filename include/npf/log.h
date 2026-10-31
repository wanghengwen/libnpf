/* Logging: levels, the process log and each instance's log. Internal to
 * libnpf; in include/npf because npf's app (its log file), modules and
 * tools log through it.
 *
 *   2026-10-06 13:01:14.013 INFO  call x: direct path 1.2.3.4:5 (213 ms)
 *
 * A line is the local date and time with ms, the level, the message, and at
 * DEBUG and TRACE the source file and line; stderr gets it without the
 * date. All functions may be called from any thread.
 *
 * A thread that works for a libnpf instance (its loop thread, or a caller
 * while it does not run) has the instance's log context set: its lines,
 * level and recent lines are the instance's. Other threads use the process
 * log (stderr, or the application's writer). */
#ifndef NPF_LOG_H
#define NPF_LOG_H

#include <stddef.h>

enum { NPF_LOG_TRACE, NPF_LOG_DEBUG, NPF_LOG_INFO, NPF_LOG_WARN, NPF_LOG_ERROR };

/* MinGW: checked against the C99 formats (%zu, %lld) its own printf has;
 * MSVC: not checked */
#ifdef __MINGW32__
#define NPF_LOG_FORMAT __attribute__((format(gnu_printf, 4, 5)))
#elif defined(__GNUC__)
#define NPF_LOG_FORMAT __attribute__((format(printf, 4, 5)))
#else
#define NPF_LOG_FORMAT
#endif
/* Writes a line when level is at or above the current level. Messages are
 * cut at 2 KB. */
void npf_log_at(int level, const char *file, int line, const char *fmt, ...) NPF_LOG_FORMAT;

#define npf_loge(...) npf_log_at(NPF_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logw(...) npf_log_at(NPF_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define npf_log(...)  npf_log_at(NPF_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logd(...) npf_log_at(NPF_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define npf_logt(...) npf_log_at(NPF_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

/* The level of this thread's instance, else of the process (default INFO).
 * A level out of range is ignored. */
void npf_log_set_level(int level);
int  npf_log_get_level(void);
/* 1 when a line at level would be written (to skip costly formatting). */
int  npf_log_on(int level);
/* "trace" .. "error" to NPF_LOG_*, -1 for anything else; and back ("?"). */
int  npf_log_level_parse(const char *s);
const char *npf_log_level_name(int level);

/* The last lines of this thread's instance (none when it keeps no ring),
 * else of the process, oldest first: whole lines into out, NUL-terminated
 * within cap bytes. Returns the length. */
size_t npf_log_recent(char *out, size_t cap);

/* ---- the process log's sink ---- */

/* Sends each line of the process log (with its date and "\n") to fn instead
 * of stderr; NULL: stderr again. fn runs under the log lock and must not
 * log. */
void npf_log_set_writer(void (*fn)(const char *line, size_t len));
/* Writes a line to stderr without its date. */
void npf_log_stderr(const char *line, size_t len);
/* The log lock, for state the writer shares with other threads. */
void npf_log_lock(void);
void npf_log_unlock(void);

/* ---- an instance's log ---- */

#define NPF_LOG_RING 16384

typedef struct npf_log_ctx {
    /* the application's callback, or NULL for the process log; it gets the
     * line without "\n", on the thread that logged, with no lock held */
    void  (*hook)(void *user, int level, const char *line);
    void   *user;
    int     level;
    char   *ring;                 /* recent lines, NPF_LOG_RING bytes; NULL: none kept.
                                     Only the thread working for the instance uses it */
    size_t  ring_pos, ring_len;
} npf_log_ctx;

/* Sets this thread's log context (NULL: none) and returns the one before. */
npf_log_ctx *npf_log_ctx_swap(npf_log_ctx *c);

#endif

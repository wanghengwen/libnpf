/* The library's one lock, for what threads share (the log, the resolver's
 * pool, the VPN choice, a loop's posted calls, TLS, the modules, an
 * instance's calls): an SRWLOCK on Windows, a pthread mutex elsewhere; not
 * recursive. NPF_MUTEX_INIT for a static one, npf_mutex_init (0, or an
 * error) and npf_mutex_free for one in an allocated struct. A condition goes
 * with it where a thread waits; a wait may return early: wait in a loop. */
#ifndef NPF_LOCK_H
#define NPF_LOCK_H

#ifdef _WIN32
#include "npf/sys.h"                /* windows.h after winsock2.h */
typedef SRWLOCK npf_mutex;
typedef CONDITION_VARIABLE npf_cond;
#define NPF_MUTEX_INIT          SRWLOCK_INIT
static inline int npf_mutex_init(npf_mutex *m) { InitializeSRWLock(m); return 0; }
#define npf_mutex_free(m)       ((void)(m))
#define npf_mutex_lock(m)       AcquireSRWLockExclusive(m)
#define npf_mutex_unlock(m)     ReleaseSRWLockExclusive(m)
#define NPF_COND_INIT           CONDITION_VARIABLE_INIT
static inline int npf_cond_init(npf_cond *c) { InitializeConditionVariable(c); return 0; }
#define npf_cond_free(c)        ((void)(c))
#define npf_cond_wait(c, m)     ((void)SleepConditionVariableSRW((c), (m), INFINITE, 0))
#define npf_cond_signal(c)      WakeConditionVariable(c)
#define npf_cond_broadcast(c)   WakeAllConditionVariable(c)
#else
#include <pthread.h>
typedef pthread_mutex_t npf_mutex;
typedef pthread_cond_t npf_cond;
#define NPF_MUTEX_INIT          PTHREAD_MUTEX_INITIALIZER
#define npf_mutex_init(m)       pthread_mutex_init((m), NULL)
#define npf_mutex_free(m)       pthread_mutex_destroy(m)
#define npf_mutex_lock(m)       pthread_mutex_lock(m)
#define npf_mutex_unlock(m)     pthread_mutex_unlock(m)
#define NPF_COND_INIT           PTHREAD_COND_INITIALIZER
#define npf_cond_init(c)        pthread_cond_init((c), NULL)
#define npf_cond_free(c)        pthread_cond_destroy(c)
#define npf_cond_wait(c, m)     pthread_cond_wait((c), (m))
#define npf_cond_signal(c)      pthread_cond_signal(c)
#define npf_cond_broadcast(c)   pthread_cond_broadcast(c)
#endif

#endif

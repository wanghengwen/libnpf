/* shared by api.c (the public functions) and api_thread.c (the library
 * thread, the runtime, how a call reaches the instance's thread) */
#ifndef NPF_API_INTERNAL_H
#define NPF_API_INTERNAL_H

#include "npf/sys.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "npf_int.h"

struct npf_api_sync {
#ifdef _WIN32
    CRITICAL_SECTION mu;
    CONDITION_VARIABLE cv;
#else
    pthread_mutex_t mu;
    pthread_cond_t cv;
#endif
    unsigned calls;
    int destroying;
};

/* the instance's lock and condition (n in scope) */
#ifdef _WIN32
#define LOCK()   EnterCriticalSection(&n->sync->mu)
#define UNLOCK() LeaveCriticalSection(&n->sync->mu)
#define WAIT()   SleepConditionVariableCS(&n->sync->cv, &n->sync->mu, INFINITE)
#define WAKE()   WakeAllConditionVariable(&n->sync->cv)
static inline unsigned long self_tid(void) { return (unsigned long)GetCurrentThreadId(); }
#else
#define LOCK()   pthread_mutex_lock(&n->sync->mu)
#define UNLOCK() pthread_mutex_unlock(&n->sync->mu)
#define WAIT()   pthread_cond_wait(&n->sync->cv, &n->sync->mu)
#define WAKE()   pthread_cond_broadcast(&n->sync->cv)
static inline unsigned long self_tid(void) { return (unsigned long)pthread_self(); }
#endif

/* Public entry points hold a reference through preparation, posting and
 * completion. The owner prevents new calls from starting once destroy begins. */
int  api_enter(npf_t *n);
void api_leave(npf_t *n);

/* Who executes a call. Running: the loop thread (others post to it). Not
 * running (before the start, after the end): the caller itself, one at a
 * time per instance; a call from inside one (a callback) goes on at once. */
enum { EXEC_POST, EXEC_HERE, EXEC_TURN };
int  exec_mode(npf_t *n);
void turn_end(npf_t *n);

/* run fn for the instance and wait for it: 0, or NPF_ESTATE when it did not
 * run (the run has ended) */
int  sync_call(npf_t *n, void (*fn)(npf_t *n, void *arg), void *arg);

#endif

/* Atomic flags, counts and pointers shared by threads: GCC and Clang's
 * __atomic builtins, MSVC's Interlocked functions (no C11 <stdatomic.h> in
 * MSVC's C before VS 2022 17.5). All sequentially consistent: none of them
 * is on a path where a weaker order would matter. */
#ifndef NPF_ATOMIC_H
#define NPF_ATOMIC_H

#include <stddef.h>

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>

static inline int npf_atomic_get(int *p) { return (int)_InterlockedOr((volatile long *)p, 0); }
static inline void npf_atomic_set(int *p, int v) { (void)_InterlockedExchange((volatile long *)p, v); }
static inline int npf_atomic_swap(int *p, int v) { return (int)_InterlockedExchange((volatile long *)p, v); }
static inline int npf_atomic_add(int *p, int d) { return (int)_InterlockedExchangeAdd((volatile long *)p, d) + d; }
static inline void *npf_atomic_getp(void **p) { return _InterlockedCompareExchangePointer((void *volatile *)p, NULL, NULL); }
static inline void npf_atomic_setp(void **p, void *v) { (void)_InterlockedExchangePointer((void *volatile *)p, v); }
/* *p from NULL to v: 1, or 0 with *p left as it was */
static inline int npf_atomic_initp(void **p, void *v)
{
    return _InterlockedCompareExchangePointer((void *volatile *)p, v, NULL) == NULL;
}
#else
static inline int npf_atomic_get(int *p) { return __atomic_load_n(p, __ATOMIC_SEQ_CST); }
static inline void npf_atomic_set(int *p, int v) { __atomic_store_n(p, v, __ATOMIC_SEQ_CST); }
static inline int npf_atomic_swap(int *p, int v) { return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST); }
static inline int npf_atomic_add(int *p, int d) { return __atomic_add_fetch(p, d, __ATOMIC_SEQ_CST); }
static inline void *npf_atomic_getp(void **p) { return __atomic_load_n(p, __ATOMIC_SEQ_CST); }
static inline void npf_atomic_setp(void **p, void *v) { __atomic_store_n(p, v, __ATOMIC_SEQ_CST); }
static inline int npf_atomic_initp(void **p, void *v)
{
    void *none = NULL;
    return __atomic_compare_exchange_n(p, &none, v, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
#endif

#endif

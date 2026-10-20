#ifndef _WIN32
#define _DEFAULT_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "npf/platform.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

void npf_random(void *buf, size_t len)
{
    if (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, "BCryptGenRandom failed\n");
        abort();
    }
}

void npf_sleep_ms(int ms)
{
    Sleep((DWORD)ms);
}

long npf_fd_limit(long want)
{
    (void)want;
    return 16384;                   /* sockets are handles: no small per-process limit */
}

int64_t npf_mono_ms(void)
{
    LARGE_INTEGER freq, c;
    QueryPerformanceFrequency(&freq);       /* fixed at boot; no cache shared between threads */
    QueryPerformanceCounter(&c);
    return (int64_t)(c.QuadPart / (freq.QuadPart / 1000));
}

int64_t npf_boot_ms(void)
{
    return (int64_t)GetTickCount64();       /* counts sleep and hibernation */
}

int64_t npf_unix_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimePreciseAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (int64_t)(u.QuadPart / 10000) - 11644473600000LL;   /* 1601 -> 1970 */
}

#else

#include <sys/resource.h>

#if defined(__APPLE__) || defined(__ANDROID__)
void npf_random(void *buf, size_t len)
{
    arc4random_buf(buf, len);       /* kernel CSPRNG, never fails (Android: getrandom only from API 28) */
}
#else
#include <sys/random.h>

void npf_random(void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("getrandom");
            abort();
        }
        p += n;
        len -= (size_t)n;
    }
}
#endif

void npf_sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

long npf_fd_limit(long want)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
        return 1024;
    if (rl.rlim_cur != RLIM_INFINITY && (long)rl.rlim_cur < want) {
        rlim_t to = rl.rlim_max == RLIM_INFINITY || (long)rl.rlim_max > want ? (rlim_t)want : rl.rlim_max;
        if (to > rl.rlim_cur) {
            struct rlimit nl = {to, rl.rlim_max};
            if (setrlimit(RLIMIT_NOFILE, &nl) == 0)
                rl.rlim_cur = to;
        }
    }
    return rl.rlim_cur == RLIM_INFINITY ? want : (long)rl.rlim_cur;
}

int64_t npf_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int64_t npf_boot_ms(void)
{
#if defined(CLOCK_BOOTTIME)
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
    return npf_mono_ms();               /* macOS / iOS: CLOCK_MONOTONIC counts sleep */
}

int64_t npf_unix_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

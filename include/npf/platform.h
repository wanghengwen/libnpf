/* Randomness, clocks, descriptor limits and what the platform is told of
 * the host. Internal to libnpf; in include/npf because npf's app, modules,
 * tools and tray use its random bytes and clocks. All functions are
 * thread-safe. */
#ifndef NPF_PLATFORM_H
#define NPF_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Fills buf with len cryptographically secure random bytes (getrandom or
 * /dev/urandom, arc4random_buf, BCryptGenRandom). Never fails: aborts the
 * process when the system cannot give them. */
void npf_random(void *buf, size_t len);

/* Monotonic ms, for timers. */
int64_t npf_mono_ms(void);
/* Monotonic ms that also count while the system sleeps: a gap against
 * npf_mono_ms shows the process was suspended or the machine slept. */
int64_t npf_boot_ms(void);
/* Wall-clock Unix time in ms. */
int64_t npf_unix_ms(void);

/* Blocks the calling thread. Never on a loop thread. */
void npf_sleep_ms(int ms);
/* Raises the soft limit of open descriptors towards want (not past the hard
 * limit). Returns the limit now in force: want when there is no limit, 1024
 * when it cannot be read, 16384 on Windows. */
long npf_fd_limit(long want);

/* The host as reported at login, for the platform's connection records.
 * npf_host_info_get fills every field ("" or 0 when unknown); it reads
 * files and system calls, so it is not for a hot path. */
#define NPF_HOST_MAX_MACS 8
#define NPF_MAC_LEN       18
typedef struct npf_host_info {
    char os[128];                   /* "Linux 6.6.87 (Ubuntu 22.04.4 LTS)", "macOS 26.5 (Darwin 25.5.0)", "Windows 10.0.19045" */
    char arch[32];                  /* x86_64, arm64 */
    char hostname[128];
    char machine_id[128];           /* /etc/machine-id, IOPlatformUUID, MachineGuid */
    char macs[NPF_HOST_MAX_MACS][NPF_MAC_LEN];   /* aa:bb:cc:dd:ee:ff, network interfaces */
    int  nmacs;
} npf_host_info;
void npf_host_info_get(npf_host_info *h);

/* Hardware items for a device's fingerprint (security.md 5.2): what stays
 * with the board for life and cannot be read from afar. Linux: the
 * soldered eMMC's CID ("emmc"), the DMI system UUID or else the board
 * serial ("board"), the SoC serial ("soc"); macOS: the hardware UUID
 * ("board"); none on iOS, Android and Windows. Placeholder values are
 * skipped, removable disks never used. Fills up to max items and returns
 * how many. The network cards' addresses are in npf_host_info. */
#define NPF_HW_MAX 4
typedef struct npf_hw_item {
    char kind[16];
    char value[160];
} npf_hw_item;
int npf_hw_items(npf_hw_item *it, int max);

#endif

/* Small platform helpers: randomness and clocks. */
#ifndef NPF_PLATFORM_H
#define NPF_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* cryptographically secure random bytes (getrandom / arc4random_buf / BCryptGenRandom); aborts on failure */
void npf_random(void *buf, size_t len);

/* monotonic milliseconds, for timers */
int64_t npf_mono_ms(void);

/* milliseconds that keep counting while the system sleeps (Linux
 * CLOCK_BOOTTIME; npf_mono_ms on macOS and iOS already does; Windows
 * GetTickCount64): compared with a timer's due time, it tells that the
 * process was suspended or the machine slept */
int64_t npf_boot_ms(void);

/* wall-clock Unix milliseconds */
int64_t npf_unix_ms(void);

/* block the calling thread (command line tools only, never on the loop) */
void npf_sleep_ms(int ms);
/* raise the soft limit of open descriptors towards the hard one (at most
 * want); returns the limit now in force (a large value where there is none) */
long npf_fd_limit(long want);

/* the host, as reported at login for the platform's connection records */
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
 * with the board for its life and cannot be read from afar. Linux: the
 * soldered eMMC's CID ("emmc"), the DMI system UUID or board serial
 * ("board"), the SoC serial ("soc"); macOS: the hardware UUID ("board");
 * placeholder values are skipped, removable disks never used. Returns the
 * count (0..max). The network cards' addresses are in npf_host_info. */
#define NPF_HW_MAX 4
typedef struct npf_hw_item {
    char kind[16];
    char value[160];
} npf_hw_item;
int npf_hw_items(npf_hw_item *it, int max);

#endif

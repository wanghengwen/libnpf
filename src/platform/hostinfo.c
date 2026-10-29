/* What a node or client reports about its host at login (npf/platform.h,
 * npf_host_info): the platform keeps it with each connection record. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"
#include "npf/version.h"

#if !defined(__ANDROID__)                   /* Android: no MACs, no serial numbers (below) */
static void fmt_mac(const unsigned char *m, char out[NPF_MAC_LEN])
{
    snprintf(out, NPF_MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void add_mac(npf_host_info *h, const unsigned char *m)
{
    char s[NPF_MAC_LEN];
    int i;
    if (h->nmacs >= NPF_HOST_MAX_MACS || !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]))
        return;
    fmt_mac(m, s);
    for (i = 0; i < h->nmacs; i++)
        if (strcmp(h->macs[i], s) == 0)
            return;
    strcpy(h->macs[h->nmacs++], s);
}
#endif

#if !defined(_WIN32) && !defined(__ANDROID__)
/* a usable hardware serial: not empty, not a vendor placeholder, not all
 * one character ("00000000", "FFFF-FFFF") */
static int hw_value_ok(const char *v)
{
    static const char *const junk[] = {"o.e.m", "default", "not specified", "not applicable", "none", "filled",
                                       "serial number", "0123456789", "03000200-0400-0500-0006-000700080009"};
    char low[160];
    size_t i, n = strlen(v);
    int same = 1;
    if (n < 4)
        return 0;
    for (i = 0; i < n && i + 1 < sizeof low; i++)
        low[i] = (char)((v[i] >= 'A' && v[i] <= 'Z') ? v[i] + 32 : v[i]);
    low[i] = 0;
    for (i = 0; i < sizeof junk / sizeof junk[0]; i++)
        if (strstr(low, junk[i]))
            return 0;
    for (i = 1; i < n; i++)
        if (v[i] != '-' && v[i] != ' ' && v[i] != v[0])
            same = 0;
    return !same;
}

static int hw_add(npf_hw_item *it, int n, int max, const char *kind, const char *value)
{
    if (n >= max || !hw_value_ok(value))
        return n;
    snprintf(it[n].kind, sizeof it[n].kind, "%s", kind);
    snprintf(it[n].value, sizeof it[n].value, "%s", value);
    return n + 1;
}
#endif

#if defined(_WIN32)

#include "npf/sys.h"                /* winsock2 / ws2tcpip before iphlpapi */
#include <windows.h>
#include <iphlpapi.h>

typedef LONG(WINAPI *rtl_get_version_fn)(PRTL_OSVERSIONINFOW);

static void hostinfo_win(npf_host_info *h)
{
    SYSTEM_INFO si;
    DWORD sz;
    HKEY k;
    {
        RTL_OSVERSIONINFOW v;
        rtl_get_version_fn f = (rtl_get_version_fn)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
        memset(&v, 0, sizeof v);
        v.dwOSVersionInfoSize = sizeof v;
        if (f && f(&v) == 0)
            snprintf(h->os, sizeof h->os, "Windows %lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
        else
            snprintf(h->os, sizeof h->os, "Windows");
    }
    GetNativeSystemInfo(&si);
    snprintf(h->arch, sizeof h->arch, "%s",
             si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? "x86_64"
             : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64"
             : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86"
                                                                         : "other");
    sz = sizeof h->hostname;
    GetComputerNameExA(ComputerNameDnsHostname, h->hostname, &sz);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &k) == 0) {
        DWORD type, len = sizeof h->machine_id - 1;
        if (RegQueryValueExA(k, "MachineGuid", NULL, &type, (BYTE *)h->machine_id, &len) != 0 || type != REG_SZ)
            h->machine_id[0] = 0;
        RegCloseKey(k);
    }
    {
        IP_ADAPTER_ADDRESSES *aa = npf_win_adapters(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                                    | GAA_FLAG_SKIP_DNS_SERVER), *a;
        for (a = aa; a; a = a->Next)
            if (a->PhysicalAddressLength == 6 && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
                add_mac(h, a->PhysicalAddress);
        free(aa);
    }
}

/* Windows: the system UUID needs WMI; the network cards and MachineGuid serve */
int npf_hw_items(npf_hw_item *it, int max)
{
    (void)it;
    (void)max;
    return 0;
}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/utsname.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#elif defined(__ANDROID__)
#include <sys/system_properties.h>
#else
#include <dirent.h>
#endif

/* the machine, "sysname release" (each system's own text replaces it) and
 * the host name; u for that text */
static void host_uname(npf_host_info *h, struct utsname *u)
{
    if (uname(u) == 0) {
        snprintf(h->arch, sizeof h->arch, "%.31s", u->machine);
        snprintf(h->os, sizeof h->os, "%.40s %.60s", u->sysname, u->release);
    } else {
        memset(u, 0, sizeof *u);
    }
    gethostname(h->hostname, sizeof h->hostname - 1);
}

#if defined(__APPLE__)

#if !TARGET_OS_IPHONE
/* IOPlatformUUID: the hardware's, not the system's (iOS has none for apps) */
static void hw_uuid(char *out, size_t cap)
{
    struct timespec ts = {0, 0};
    uuid_t id;
    if (gethostuuid(id, &ts) == 0)
        snprintf(out, cap, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", id[0], id[1], id[2],
                 id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
}
#endif

static void hostinfo_apple(npf_host_info *h)
{
    struct utsname u;
    struct ifaddrs *ifs, *i;
    char v[64] = "";
    size_t l = sizeof v;
    host_uname(h, &u);
    if (sysctlbyname("kern.osproductversion", v, &l, NULL, 0) == 0)
        snprintf(h->os, sizeof h->os, "%s %s (Darwin %s)", TARGET_OS_IPHONE ? "iOS" : "macOS", v, u.release);
#if !TARGET_OS_IPHONE
    hw_uuid(h->machine_id, sizeof h->machine_id);
#endif
    if (TARGET_OS_IPHONE || getifaddrs(&ifs) != 0)
        return;                             /* iOS: every interface reports the same made-up MAC */
    for (i = ifs; i; i = i->ifa_next) {
        const struct sockaddr_dl *dl = (const void *)i->ifa_addr;
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_LINK && dl->sdl_alen == 6 && strncmp(i->ifa_name, "en", 2) == 0)
            add_mac(h, (const unsigned char *)LLADDR(dl));
    }
    freeifaddrs(ifs);
}

int npf_hw_items(npf_hw_item *it, int max)
{
    char id[128] = "";
#if !TARGET_OS_IPHONE
    hw_uuid(id, sizeof id);
#endif
    return hw_add(it, 0, max, "board", id);
}

#elif defined(__ANDROID__)

/* Android's version, and the model for a name (the host name is
 * "localhost"); apps see no machine id and no MAC (the mobile apps) */
static void hostinfo_android(npf_host_info *h)
{
    struct utsname u;
    char v[PROP_VALUE_MAX] = "", m[PROP_VALUE_MAX] = "", k[sizeof h->os];
    host_uname(h, &u);
    __system_property_get("ro.build.version.release", v);
    __system_property_get("ro.product.model", m);
    snprintf(k, sizeof k, "%s", h->os);
    snprintf(h->os, sizeof h->os, "Android %s (%s)", v, k);
    if (m[0])
        snprintf(h->hostname, sizeof h->hostname, "%s", m);
}

/* apps cannot read the hardware's serial numbers */
int npf_hw_items(npf_hw_item *it, int max)
{
    (void)it;
    (void)max;
    return 0;
}

#else

static void read_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    if (fgets(out, (int)cap, f)) {
        size_t n = strlen(out);
        while (n && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
            out[--n] = 0;
    }
    fclose(f);
}

static void hostinfo_linux(npf_host_info *h)
{
    struct utsname u;
    FILE *f = fopen("/etc/os-release", "r");
    char line[256];
    int pass;
    host_uname(h, &u);
    while (f && fgets(line, sizeof line, f))        /* its PRETTY_NAME */
        if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
            char *v = line + 12, *e;
            if (*v == '"')
                v++;
            if ((e = strpbrk(v, "\"\n")))
                *e = 0;
            snprintf(h->os + strlen(h->os), sizeof h->os - strlen(h->os), " (%s)", v);
            break;
        }
    if (f)
        fclose(f);
    read_line("/etc/machine-id", h->machine_id, sizeof h->machine_id);
    if (!h->machine_id[0])
        read_line("/var/lib/dbus/machine-id", h->machine_id, sizeof h->machine_id);
    /* physical interfaces first (they have a device); else all but lo */
    for (pass = 0; pass < 2 && h->nmacs == 0; pass++) {
        DIR *d = opendir("/sys/class/net");
        struct dirent *e;
        while (d && (e = readdir(d))) {
            char p[300], mac[NPF_MAC_LEN] = "";
            unsigned char b[6];
            if (e->d_name[0] == '.' || strcmp(e->d_name, "lo") == 0)
                continue;
            if (pass == 0) {
                snprintf(p, sizeof p, "/sys/class/net/%s/device", e->d_name);
                if (access(p, F_OK) != 0)
                    continue;
            }
            snprintf(p, sizeof p, "/sys/class/net/%s/address", e->d_name);
            read_line(p, mac, sizeof mac);
            if (npf_text_mac(mac, b) == 0)
                add_mac(h, b);
        }
        if (d)
            closedir(d);
    }
}

int npf_hw_items(npf_hw_item *it, int max)
{
    int n = 0;
    char v[160] = "";
    DIR *d;
    struct dirent *e;
    /* the soldered eMMC (type MMC, not an SD card): mmcblkN, the lowest */
    {
        char best[32] = "", p[300], type[16];
        if ((d = opendir("/sys/block")) != NULL) {
            while ((e = readdir(d)) != NULL) {
                const char *q = e->d_name + 6;
                if (strncmp(e->d_name, "mmcblk", 6) != 0 || !*q || strspn(q, "0123456789") != strlen(q))
                    continue;
                snprintf(p, sizeof p, "/sys/block/%s/device/type", e->d_name);
                type[0] = 0;
                read_line(p, type, sizeof type);
                if (strcmp(type, "MMC") == 0 && (!best[0] || strcmp(e->d_name, best) < 0))
                    snprintf(best, sizeof best, "%.31s", e->d_name);
            }
            closedir(d);
        }
        if (best[0]) {
            snprintf(p, sizeof p, "/sys/block/%s/device/cid", best);
            read_line(p, v, sizeof v);
            n = hw_add(it, n, max, "emmc", v);
        }
    }
    /* the board: DMI system UUID (x86), else the board's serial */
    v[0] = 0;
    read_line("/sys/class/dmi/id/product_uuid", v, sizeof v);
    if (!hw_value_ok(v)) {
        v[0] = 0;
        read_line("/sys/class/dmi/id/board_serial", v, sizeof v);
    }
    n = hw_add(it, n, max, "board", v);
    /* the SoC (ARM): the device tree's serial number, else /proc/cpuinfo "Serial" */
    v[0] = 0;
    read_line("/sys/firmware/devicetree/base/serial-number", v, sizeof v);
    if (!hw_value_ok(v)) {
        FILE *f = fopen("/proc/cpuinfo", "r");
        char line[256];
        v[0] = 0;
        while (f && fgets(line, sizeof line, f))
            if (strncmp(line, "Serial", 6) == 0 && strchr(line, ':')) {
                char *c = strchr(line, ':') + 1;
                while (*c == ' ' || *c == '\t')
                    c++;
                c[strcspn(c, "\r\n")] = 0;
                snprintf(v, sizeof v, "%s", c);
                break;
            }
        if (f)
            fclose(f);
    }
    return hw_add(it, n, max, "soc", v);
}

#endif
#endif

static int mac_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

void npf_host_info_get(npf_host_info *h)
{
    memset(h, 0, sizeof *h);
#if defined(_WIN32)
    hostinfo_win(h);
#elif defined(__APPLE__)
    hostinfo_apple(h);
#elif defined(__ANDROID__)
    hostinfo_android(h);
#else
    hostinfo_linux(h);
#endif
    /* sorted: the same host, the same text (login names it by its digest) */
    qsort(h->macs, (size_t)h->nmacs, sizeof h->macs[0], mac_cmp);
}

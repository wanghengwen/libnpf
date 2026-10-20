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

void npf_host_info_get(npf_host_info *h)
{
    SYSTEM_INFO si;
    DWORD sz;
    HKEY k;
    memset(h, 0, sizeof *h);
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
        ULONG len = 16384;
        IP_ADAPTER_ADDRESSES *aa = malloc(len), *a;
        if (aa && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                       NULL, aa, &len) == NO_ERROR) {
            for (a = aa; a; a = a->Next)
                if (a->PhysicalAddressLength == 6 && a->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
                    add_mac(h, a->PhysicalAddress);
        }
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

#if !defined(__APPLE__) && !defined(__ANDROID__)
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
#endif

void npf_host_info_get(npf_host_info *h)
{
    struct utsname u;
    memset(h, 0, sizeof *h);
    if (uname(&u) == 0) {
        snprintf(h->arch, sizeof h->arch, "%.31s", u.machine);
        snprintf(h->os, sizeof h->os, "%.40s %.60s", u.sysname, u.release);
    }
    gethostname(h->hostname, sizeof h->hostname - 1);
#if defined(__APPLE__)
    {
        char v[64] = "";
        size_t l = sizeof v;
        struct timespec ts = {0, 0};
        uuid_t id;
#if TARGET_OS_IPHONE
        /* no machine id, and every interface reports the same made-up MAC */
        (void)ts;
        (void)id;
        if (sysctlbyname("kern.osproductversion", v, &l, NULL, 0) == 0)
            snprintf(h->os, sizeof h->os, "iOS %s (Darwin %s)", v, u.release);
        return;
#else
        if (sysctlbyname("kern.osproductversion", v, &l, NULL, 0) == 0)
            snprintf(h->os, sizeof h->os, "macOS %s (Darwin %s)", v, u.release);
        if (gethostuuid(id, &ts) == 0)
            snprintf(h->machine_id, sizeof h->machine_id,
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", id[0], id[1], id[2],
                     id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
#endif
    }
    {
        struct ifaddrs *ifs, *i;
        if (getifaddrs(&ifs) == 0) {
            for (i = ifs; i; i = i->ifa_next) {
                const struct sockaddr_dl *dl = (const void *)i->ifa_addr;
                if (i->ifa_addr && i->ifa_addr->sa_family == AF_LINK && dl->sdl_alen == 6 && strncmp(i->ifa_name, "en", 2) == 0)
                    add_mac(h, (const unsigned char *)LLADDR(dl));
            }
            freeifaddrs(ifs);
        }
    }
#elif defined(__ANDROID__)
    {
        /* Android's version, and the model for a name (the host name is
         * "localhost"); apps see no machine id and no MAC (the mobile apps) */
        char v[PROP_VALUE_MAX] = "", m[PROP_VALUE_MAX] = "", k[sizeof h->os];
        __system_property_get("ro.build.version.release", v);
        __system_property_get("ro.product.model", m);
        snprintf(k, sizeof k, "%s", h->os);
        snprintf(h->os, sizeof h->os, "Android %s (%s)", v, k);
        if (m[0])
            snprintf(h->hostname, sizeof h->hostname, "%s", m);
    }
#else
    {
        /* PRETTY_NAME of /etc/os-release */
        FILE *f = fopen("/etc/os-release", "r");
        char line[256];
        while (f && fgets(line, sizeof line, f))
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
    }
    read_line("/etc/machine-id", h->machine_id, sizeof h->machine_id);
    if (!h->machine_id[0])
        read_line("/var/lib/dbus/machine-id", h->machine_id, sizeof h->machine_id);
    {
        /* physical interfaces first (they have a device); else all but lo */
        int pass;
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
#endif
}

int npf_hw_items(npf_hw_item *it, int max)
{
    int n = 0;
#if defined(__APPLE__)
    npf_host_info h;
    npf_host_info_get(&h);
    n = hw_add(it, n, max, "board", h.machine_id);     /* IOPlatformUUID: the hardware's, not the system's */
#elif defined(__ANDROID__)
    (void)it;                                           /* apps cannot read the hardware's serial numbers */
    (void)max;
#else
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
    n = hw_add(it, n, max, "soc", v);
#endif
    return n;
}

#endif

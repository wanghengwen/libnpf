/* The system layer (npf/sys.h) on Windows: Winsock, the IP helper API,
 * UTF-8 paths, file ACLs. The portable rest is in sys.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/sys.h"

#include <iphlpapi.h>
#include <mstcpip.h>
#include <sddl.h>
#include <aclapi.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET _WSAIOW(IOC_VENDOR, 15)
#endif

int npf_sys_init(void)
{
    WSADATA wd;
    /* reference counted and thread-safe: every node calls it */
    return WSAStartup(MAKEWORD(2, 2), &wd) != 0 ? -1 : 0;
}

int npf_set_nonblock(int fd)
{
    u_long on = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &on) == 0 ? 0 : -1;
}

int npf_socket(int family, int type, int proto, int blocking)
{
    SOCKET s;
    npf_sys_init();
    s = WSASocketW(family, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET)
        return -1;
    if (type == SOCK_DGRAM) {
        /* an ICMP port unreachable must not fail the next recvfrom() (punching sends to dead ports) */
        BOOL off = FALSE;
        DWORD ret;
        WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
        WSAIoctl(s, SIO_UDP_NETRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
    }
    if (!blocking && npf_set_nonblock((int)s) < 0) {
        closesocket(s);
        return -1;
    }
    return (int)s;
}

int npf_accept(int lfd)
{
    SOCKET s = accept((SOCKET)lfd, NULL, NULL);
    if (s == INVALID_SOCKET)
        return -1;
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    if (npf_set_nonblock((int)s) < 0) {
        closesocket(s);
        return -1;
    }
    return (int)s;
}

void npf_sock_close(int fd)
{
    if (fd >= 0)
        closesocket((SOCKET)fd);
}

void npf_sock_listen_opts(int fd, int type)
{
    BOOL one = TRUE;
    (void)type;
    if (fd >= 0)
        setsockopt((SOCKET)fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one);
}

int npf_sock_err(void)
{
    return WSAGetLastError();
}

const char *npf_sock_strerror_code(int e)
{
    static NPF_THREAD_LOCAL char buf[160];
    /* English, like the rest of the log; the localized text would arrive in the ANSI code page */
    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)e,
                        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof buf, NULL))
        snprintf(buf, sizeof buf, "error %d", e);
    else
        buf[strcspn(buf, "\r\n")] = 0;
    return buf;
}

void *npf_win_adapters(unsigned long flags)
{
    ULONG len = 16384;
    int tries;
    for (tries = 0; tries < 3; tries++) {
        IP_ADAPTER_ADDRESSES *aa = malloc(len);
        ULONG r;
        if (!aa)
            return NULL;
        if ((r = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, aa, &len)) == NO_ERROR)
            return aa;
        free(aa);
        if (r != ERROR_BUFFER_OVERFLOW)
            return NULL;
    }
    return NULL;
}

int npf_if_list(npf_ifaddr *out, int max)
{
    IP_ADAPTER_ADDRESSES *aa = npf_win_adapters(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER),
                         *a;
    int n = 0;
    for (a = aa; a && n < max; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        if (a->OperStatus != IfOperStatusUp)
            continue;
        for (u = a->FirstUnicastAddress; u && n < max; u = u->Next) {
            struct sockaddr *sa = u->Address.lpSockaddr;
            if (sa->sa_family == AF_INET)
                memcpy(out[n].addr, &((struct sockaddr_in *)sa)->sin_addr, 4);
            else if (sa->sa_family == AF_INET6)
                memcpy(out[n].addr, &((struct sockaddr_in6 *)sa)->sin6_addr, 16);
            else
                continue;
            out[n].family = sa->sa_family;
            out[n].prefix = u->OnLinkPrefixLength;
            out[n].loopback = a->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            n++;
        }
    }
    free(aa);
    return n;
}

/* Windows Defender Firewall lets replies to our own traffic in; whether an
 * early unsolicited packet poisons the flow has not been measured: on time */
int npf_firewall_lead_ms(void)
{
    return 0;
}

int npf_default_gw4(uint32_t *gw)
{
    MIB_IPFORWARDROW row;
    if (GetBestRoute(htonl(0x08080808), 0, &row) != NO_ERROR || row.dwForwardNextHop == 0)
        return -1;
    *gw = row.dwForwardNextHop;             /* network order */
    return 0;
}

/* ---- UTF-8 paths (sys.h): the wide-character calls ---- */

#define WPATH 1024

int npf_wpath(const char *path, wchar_t *out, size_t cap)
{
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, (int)cap) > 0)
        return 0;
    errno = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? ENAMETOOLONG : EINVAL;
    return -1;
}

FILE *npf_fopen(const char *path, const char *mode)
{
    wchar_t w[WPATH], m[8];
    return npf_wpath(path, w, WPATH) < 0 || npf_wpath(mode, m, 8) < 0 ? NULL : _wfopen(w, m);
}

int npf_stat(const char *path, npf_stat_t *st)
{
    wchar_t w[WPATH];
    return npf_wpath(path, w, WPATH) < 0 ? -1 : _wstat64(w, st);
}

int npf_remove(const char *path)
{
    wchar_t w[WPATH];
    return npf_wpath(path, w, WPATH) < 0 ? -1 : _wremove(w);
}

int npf_win_errno(unsigned long err)
{
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return ENOENT;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return EACCES;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return EEXIST;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        return ENOSPC;
    case ERROR_WRITE_PROTECT:
        return EROFS;
    case ERROR_FILENAME_EXCED_RANGE:
        return ENAMETOOLONG;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return ENOMEM;
    default:
        return EIO;
    }
}

int npf_file_private(const char *path)
{
    wchar_t w[WPATH];
    /* SYSTEM, Administrators and the file's owner; inherited entries removed */
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD r;
    if (npf_wpath(path, w, WPATH) < 0)
        return -1;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)",
                                                              SDDL_REVISION_1, &sd, NULL))
        return -1;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
        LocalFree(sd);
        return -1;
    }
    r = SetNamedSecurityInfoW(w, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL,
                              NULL, dacl, NULL);
    LocalFree(sd);
    return r == ERROR_SUCCESS ? 0 : -1;
}

int npf_file_too_open(const char *path)
{
    (void)path;
    return 0;
}

int npf_path_is_abs(const char *p)
{
    return (p[0] && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || (p[0] == '\\' && p[1] == '\\');
}

int npf_abspath(const char *p, char *out, size_t cap)
{
    wchar_t w[WPATH], full[WPATH];
    DWORD r;
    if (npf_wpath(p, w, WPATH) < 0)
        return -1;
    r = GetFullPathNameW(w, WPATH, full, NULL);
    return r > 0 && r < WPATH && WideCharToMultiByte(CP_UTF8, 0, full, -1, out, (int)cap, NULL, NULL) > 0 ? 0 : -1;
}

/* no tcp_info here */
const char *npf_sock_tcp_diag(int fd, char *buf, size_t cap)
{
    (void)fd;
    snprintf(buf, cap, "-");
    return buf;
}

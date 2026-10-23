/* Portable system layer: socket headers and the few calls that differ
 * between POSIX and Windows (Winsock).
 *
 * Sockets are kept in an int everywhere. On Windows a SOCKET handle is a
 * small kernel handle value, so it fits; INVALID_SOCKET becomes -1.
 * Close sockets with npf_sock_close(), never close(). */
#ifndef NPF_SYS_H
#define NPF_SYS_H

#include <stddef.h>
#include <stdint.h>

/* per-thread storage: each libnpf instance runs on a thread of its own */
#if defined(_MSC_VER)
#define NPF_THREAD_LOCAL __declspec(thread)
#else
#define NPF_THREAD_LOCAL __thread
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sys/types.h>

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0          /* npf sockets are non-blocking already */
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0          /* no SIGPIPE on Windows */
#endif
typedef ULONG nfds_t;
#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH
#define poll(fds, n, ms) WSAPoll((fds), (n), (ms))

/* Winsock takes char buffers and int lengths */
#define setsockopt(s, l, o, v, n)   setsockopt((SOCKET)(s), (l), (o), (const char *)(v), (int)(n))
#define getsockopt(s, l, o, v, n)   getsockopt((SOCKET)(s), (l), (o), (char *)(v), (n))
#define send(s, b, n, f)            send((SOCKET)(s), (const char *)(b), (int)(n), (f))
#define recv(s, b, n, f)            recv((SOCKET)(s), (char *)(b), (int)(n), (f))
#define sendto(s, b, n, f, a, al)   sendto((SOCKET)(s), (const char *)(b), (int)(n), (f), (a), (int)(al))
#define recvfrom(s, b, n, f, a, al) recvfrom((SOCKET)(s), (char *)(b), (int)(n), (f), (a), (al))

#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0          /* macOS: SO_NOSIGPIPE is set on every socket instead */
#endif
#endif

/* WSAStartup on Windows (idempotent); nothing elsewhere. 0 or -1. */
int  npf_sys_init(void);

/* socket(): non-blocking unless blocking != 0, close-on-exec; UDP sockets
 * on Windows do not report ICMP port unreachable as recv errors. -1 on error. */
int  npf_socket(int family, int type, int proto, int blocking);
/* The node's UDP sockets (the main ones, punching, NAT probing, port
 * mapping; not the loop's wake-up or a direct listener): npf_socket, then
 * the hook while it is on (connect_mode p2p; off in secure): the platform's
 * (the Android app binds them to the network under a VPN, so punching sees
 * the phone's own NAT), else the built-in npf_vpn_bypass. A hook that fails
 * (the VPN lets no app bypass it) leaves the socket on the default route.
 * Process-wide. */
typedef int (*npf_udp_hook_fn)(int fd, int family, void *arg);
void npf_udp_hook_set(npf_udp_hook_fn fn, void *arg);
void npf_udp_hook_on(int on);
int  npf_udp_hook_is_on(void);
/* a socket of the node's (its UDP ones, its signaling's TCP) out on the
 * physical network under a VPN when the hook is on (connect_mode p2p): the
 * application's hook, else npf_vpn_bypass; <0 the platform could not */
int  npf_net_bypass(int fd, int family);
/* a VPN has the default route and the node's sockets may go around it (as
 * npf_vpn_bypass last saw it) */
int  npf_vpn_in_way(void);
/* npf_net_bypass may take a socket around a VPN now: the hook is on, and the
 * application's own hook is set (it knows its VPN) or a VPN is in the way */
int  npf_net_bypass_active(void);
int  npf_udp_socket(int family, int blocking);
/* the built-in hook (platform/vpnbypass.c): a VPN with the default route:
 * the socket bound to the physical interface under it; 0, or -1 when that
 * failed; and whether an interface name is a tunnel's (utun, wg, tun, ...) */
int  npf_vpn_bypass(int fd, int family, void *arg);
int  npf_if_tunnel_name(const char *name);
int  npf_accept(int lfd);                       /* non-blocking accepted socket or -1 */
int  npf_set_nonblock(int fd);
void npf_sock_close(int fd);
/* before bind() of a listening socket (type SOCK_STREAM or SOCK_DGRAM): its
 * port is its own. TCP may bind again at once after a restart (POSIX
 * SO_REUSEADDR); a UDP port is never shared with another socket; on Windows
 * SO_EXCLUSIVEADDRUSE for both (its SO_REUSEADDR would take a port in use) */
void npf_sock_listen_opts(int fd, int type);

/* after a failed socket call */
int  npf_sock_again(void);                      /* would block / interrupted: try later */
int  npf_sock_in_use(void);                     /* bind: the address is taken (or not ours to take) */
int  npf_sock_inprogress(void);                 /* non-blocking connect() started */
/* the socket itself is unusable (iOS reclaims a suspended app's sockets, a
 * descriptor gone): reopen it; not an ICMP report or a full buffer */
int  npf_sock_broken(void);
int  npf_sock_broken_code(int err);             /* an SO_ERROR value */
const char *npf_sock_strerror(void);
const char *npf_sock_strerror_code(int err);         /* an SO_ERROR value */

/* addresses of the interfaces that are up (loopback included) */
typedef struct npf_ifaddr {
    int     family;                             /* AF_INET / AF_INET6 */
    uint8_t addr[16];
    int     prefix;                             /* netmask length, -1 unknown */
    int     loopback;                           /* on a loopback interface (WSL puts 10.255.255.254 on lo) */
} npf_ifaddr;
int  npf_if_list(npf_ifaddr *out, int max);

/* sendto() on a non-blocking UDP socket; to is a sockaddr_in / sockaddr_in6 /
 * sockaddr_storage. A failure other than a full queue is logged (warning,
 * the same error at most once a minute per thread, with how many more there
 * were); on macOS "No route to host" to the local network says how to allow
 * it. 0 or -1. */
int  npf_udp_send(int fd, const void *buf, size_t len, const void *to);

/* How early to start punching because of a host firewall that blocks a UDP
 * flow whose first packet is unsolicited inbound (and keeps blocking it):
 * 300 on macOS with the application firewall on, else 0. */
int  npf_firewall_lead_ms(void);

/* IPv4 default gateway (network byte order), 0 or -1 */
int  npf_default_gw4(uint32_t *gw);

/* files */
int  npf_mkdir(const char *path);               /* 0700 where it matters; 0 if it exists */
int  npf_mkdir_p(const char *path);
/* restrict a file holding secrets to its owner (POSIX mode 0600; Windows:
 * protected DACL for SYSTEM, Administrators and the owner) */
int  npf_file_private(const char *path);
/* is the file readable by other users? (POSIX: group/other bits; Windows: no check) */
int  npf_file_too_open(const char *path);
/* absolute path of p (no symlink resolution needed); out holds cap bytes */
int  npf_abspath(const char *p, char *out, size_t cap);
int  npf_path_is_abs(const char *p);

/* Scratch buffers for the loop's deep paths (a datagram, a frame, a control
 * message) on the heap rather than the stack: a thread's stack keeps every
 * page it ever touched, so a 64 KB frame once makes 64 KB of memory for good
 * (npf-hosted: a thread per account). The thread keeps the last few for reuse
 * until npf_scratch_trim(); nested use gets buffers of its own. */
void *npf_scratch(size_t n);                    /* NULL: no memory */
void npf_scratch_done(void *p);                 /* NULL is fine */
void npf_scratch_trim(void);                    /* frees the ones kept */

#endif

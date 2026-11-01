/* The portable system layer: socket headers, threads, socket errors,
 * addresses, the node's UDP sockets, files. Internal to libnpf; in
 * include/npf because npf's app, modules, tools, tray and Android JNI use
 * its sockets, addresses and files too.
 *
 * A socket is an int everywhere (a Windows SOCKET fits; INVALID_SOCKET is
 * -1). Close it with npf_sock_close(), never close(). */
#ifndef NPF_SYS_H
#define NPF_SYS_H

#include <stddef.h>
#include <stdint.h>

/* ======== system headers, and what Winsock spells otherwise ======== */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sys/types.h>
#ifdef _MSC_VER                 /* what MinGW's headers have and MSVC's do not */
typedef SSIZE_T ssize_t;
#define strtok_r strtok_s
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0          /* npf sockets are non-blocking already */
#endif
#define NPF_SE(x) WSAE##x
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

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31        /* (older MinGW headers) */
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif

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
#include <errno.h>
#define NPF_SE(x) E##x
#endif

/* ======== threads ======== */

#if defined(_MSC_VER)
#define NPF_THREAD_LOCAL __declspec(thread)
#else
#define NPF_THREAD_LOCAL __thread
#endif
/* Runs fn(arg) on a new detached thread (256 KB stack on POSIX). 0, or -1
 * when no thread could be made (fn does not run). */
int npf_thread_detached(void (*fn)(void *), void *arg);

/* ======== sockets and their errors ======== */

/* WSAStartup on Windows (reference counted, any thread); nothing elsewhere.
 * npf_socket calls it. 0 or -1. */
int  npf_sys_init(void);

/* socket(), non-blocking unless blocking != 0, not inherited by child
 * processes; no SIGPIPE where MSG_NOSIGNAL is missing (SO_NOSIGPIPE). On
 * Windows an ICMP port unreachable does not fail a UDP socket's next recv.
 * The socket, or -1. npf_accept: the same for an accepted connection (always
 * non-blocking). */
int  npf_socket(int family, int type, int proto, int blocking);
int  npf_accept(int lfd);
int  npf_set_nonblock(int fd);
void npf_sock_close(int fd);
/* Call before bind() of a listening socket (type SOCK_STREAM or SOCK_DGRAM).
 * The port is never shared with another socket; on POSIX a TCP port can be
 * bound again at once after a restart (SO_REUSEADDR), on Windows both get
 * SO_EXCLUSIVEADDRUSE. */
void npf_sock_listen_opts(int fd, int type);

/* The error of the last failed socket call on this thread: errno, or
 * WSAGetLastError() on Windows. NPF_SE(X) names a code on both (EX, WSAEX).
 * The predicates below test that error; the _code forms test an SO_ERROR
 * value. */
int  npf_sock_err(void);
int  npf_sock_again(void);                      /* would block or interrupted: try again later */
int  npf_sock_in_use(void);                     /* bind: the address is taken, or access is denied */
int  npf_sock_inprogress(void);                 /* a non-blocking connect() has started */
/* The socket itself is unusable (a descriptor gone, iOS reclaimed a
 * suspended app's socket, the connection shut down): reopen it. Not true
 * for an ICMP report or a full buffer. */
int  npf_sock_broken(void);
int  npf_sock_broken_code(int err);
int  npf_sock_starved(void);                    /* out of descriptors or buffer memory */
/* A TCP socket's kernel send queue, retransmissions, RTT and RTO as text in
 * buf, for a log line (Linux; "-" elsewhere). Returns buf. */
const char *npf_sock_tcp_diag(int fd, char *buf, size_t cap);
/* The error's text, in English. Valid until the next call on this thread. */
const char *npf_sock_strerror(void);
const char *npf_sock_strerror_code(int err);

/* ======== addresses and interfaces ======== */

/* sa is a sockaddr_in, a sockaddr_in6, or a sockaddr_storage holding one.
 * npf_addr_port is in host order. npf_addr_eq: same family, address and port
 * (0 for any other family). npf_addr_str writes "1.2.3.4:5" or "[::1]:5"
 * ("-" for another family) into buf and returns buf. npf_addr_parse reads
 * that form back (a numeric address only, the port in digits): 0 or -1.
 * npf_addr_ip: an IPv4 or IPv6 address (no name, no brackets) and port: 0
 * or -1. npf_addr_set: family's address (4 or 16 bytes, network order) and
 * port, the rest zero. */
socklen_t   npf_addr_len(const void *sa);
uint16_t    npf_addr_port(const void *sa);
int         npf_addr_eq(const void *a, const void *b);
const char *npf_addr_str(const void *sa, char *buf, size_t cap);
int         npf_addr_parse(const char *s, struct sockaddr_storage *out);
int         npf_addr_ip(const char *host, uint16_t port, struct sockaddr_storage *out);
void        npf_addr_set(struct sockaddr_storage *out, int family, const void *ip, uint16_t port);

/* The addresses of the interfaces that are up, loopback included. */
typedef struct npf_ifaddr {
    int     family;                             /* AF_INET / AF_INET6 */
    uint8_t addr[16];
    int     prefix;                             /* netmask length, -1 unknown */
    int     loopback;                           /* on a loopback interface (WSL puts 10.255.255.254 on lo) */
} npf_ifaddr;
int  npf_if_list(npf_ifaddr *out, int max);     /* up to max of them: the count (0 on error) */
/* 1 when addr (an in_addr, or an in6_addr's 16 bytes) is one of them */
int  npf_if_has(int family, const void *addr);

/* ======== UDP sends and the node's socket hook ======== */

/* sendto() without blocking; to as for npf_addr_len. 0, or -1 when the
 * datagram was not sent. A full queue is not logged; another error is, at
 * most once a minute per thread and error, with how many more there were
 * (unroutable destinations at DEBUG, others at WARN; on macOS a blocked
 * local network says how to allow it). */
int  npf_udp_send(int fd, const void *buf, size_t len, const void *to);

/* When a node's main socket last sent a datagram that may keep the NAT
 * mapping its spare allocation's relay sees (home-binding.md 5.4). What
 * counts depends on the NAT's mapping: ANY (EIM, or unknown) any datagram
 * not to the relay itself, IP (ADM) one to the relay's IP on another port,
 * NONE (APDM) none. */
enum { NPF_WATCH_ANY, NPF_WATCH_IP, NPF_WATCH_NONE };
typedef struct npf_udp_watch {
    uint32_t relay_ip;                          /* network order; 0: none yet */
    uint16_t relay_port;                        /* network order */
    int      mode;                              /* NPF_WATCH_* */
    int64_t  other;                             /* npf_mono_ms of the last such datagram, 0: none */
    int      fd;                                /* watched; -1: none (set it so before the first call) */
    struct npf_udp_watch *next;                 /* the thread's watches */
} npf_udp_watch;
/* From now on npf_udp_send on this thread notes into w->other the datagrams
 * on fd that count; fd -1 stops w. w must stay valid until stopped, on this
 * thread: stop it before fd is closed (the number may be reused). */
void npf_udp_watch_on(npf_udp_watch *w, int fd);

/* The node's UDP sockets (main, punching, NAT probing, port mapping; not
 * the loop's wake-up or a direct listener) come from npf_udp_socket:
 * npf_socket, then, with bypass (the node's connect_mode p2p, not secure),
 * the application's hook or else the built-in npf_vpn_bypass, so the
 * socket goes around a VPN (the Android app binds it to the physical
 * network). A hook that fails leaves the socket on the default route
 * (logged once). The hook is process-wide, set from any thread; it runs on
 * the thread that opens the socket. */
typedef int (*npf_udp_hook_fn)(int fd, int family, void *arg);
void npf_udp_hook_set(npf_udp_hook_fn fn, void *arg);
/* Takes one of the node's sockets (UDP, or the signaling's TCP) around a
 * VPN as above: 0, or < 0 when the hook could not. */
int  npf_net_bypass(int fd, int family);
/* 1 when npf_net_bypass may take a socket around a VPN now: the
 * application's hook is set or a VPN is in the way. */
int  npf_net_bypass_active(void);
int  npf_udp_socket(int family, int blocking, int bypass);

/* ======== the network around: adapters, VPN, firewall, gateway ======== */

#ifdef _WIN32
/* GetAdaptersAddresses(AF_UNSPEC, flags): an IP_ADAPTER_ADDRESSES list
 * the caller frees with free(), or NULL. */
void *npf_win_adapters(unsigned long flags);
#endif
/* 1 when, as npf_vpn_bypass last looked, a VPN has the default route and a
 * physical interface is there to go around it. */
int  npf_vpn_in_way(void);
/* The built-in hook: when a VPN has the default route, binds fd to the
 * physical interface under it (Linux needs CAP_NET_RAW). It looks at the
 * interfaces again at most every 3 s. 0 (also without a VPN), or -1 when
 * the socket could not be bound. Any thread. npf_if_tunnel_name: 1 when an
 * interface name looks like a tunnel's (utun, wg, tun, ...). */
int  npf_vpn_bypass(int fd, int family, void *arg);
int  npf_if_tunnel_name(const char *name);

/* How many ms early to start punching because a host firewall blocks a
 * UDP flow whose first packet is unsolicited inbound: 300 on macOS with
 * the application firewall on, else 0. Runs a program on macOS: slow. */
int  npf_firewall_lead_ms(void);

/* The IPv4 default gateway in network order: 0, or -1 when unknown (always
 * on iOS and Android). */
int  npf_default_gw4(uint32_t *gw);

/* ======== files and their permissions ======== */

/* Paths are UTF-8 (npf.h). Windows' narrow calls take the ANSI code page,
 * so there they go through the wide ones: npf_fopen, npf_stat, npf_remove
 * instead of fopen, stat, remove; npf_wpath for the Win32 calls (0, or -1
 * with errno: EINVAL not UTF-8, ENAMETOOLONG). */
#ifdef _WIN32
#include <stdio.h>
#include <sys/stat.h>
typedef struct _stat64 npf_stat_t;
int   npf_wpath(const char *path, wchar_t *out, size_t cap);
FILE *npf_fopen(const char *path, const char *mode);
int   npf_stat(const char *path, npf_stat_t *st);
int   npf_remove(const char *path);
/* a Win32 error (GetLastError) as the errno that says the same, EIO: other */
int   npf_win_errno(unsigned long err);
#else
#include <sys/stat.h>
typedef struct stat npf_stat_t;
#define npf_fopen  fopen
#define npf_stat   stat
#define npf_remove remove
#endif

/* Makes path and its parents (mode 0700 on POSIX). 0 when it exists after,
 * -1 on error or a path of 1024 bytes or more. */
int  npf_mkdir_p(const char *path);
/* Restricts a file holding secrets to its owner (POSIX mode 0600; Windows:
 * a protected DACL for SYSTEM, Administrators and the owner). 0 or -1. */
int  npf_file_private(const char *path);
/* 1 when group or others have any permission on the file (POSIX); always 0
 * on Windows. */
int  npf_file_too_open(const char *path);
/* p made absolute against the working directory (symlinks not resolved),
 * into out of cap bytes. 0, or -1 with errno and out empty (an error, or it
 * does not fit: ENAMETOOLONG). */
int  npf_abspath(const char *p, char *out, size_t cap);
int  npf_path_is_abs(const char *p);
/* p's last separator ('/', on Windows '\\' too), NULL: none; its directory
 * into out ("." when it has none) */
const char *npf_path_sep(const char *p);
void        npf_dirname(const char *p, char *out, size_t cap);

/* ======== scratch buffers ======== */

/* Large temporary buffers (a datagram, a frame) from the heap instead of
 * the stack, which keeps every page it once touched. npf_scratch returns n
 * bytes or NULL; give each back with npf_scratch_done on the same thread
 * (NULL is fine). Each thread keeps up to 4 for reuse until
 * npf_scratch_trim frees the ones not in use; nested calls get distinct
 * buffers. */
void *npf_scratch(size_t n);
void npf_scratch_done(void *p);
void npf_scratch_trim(void);

#endif

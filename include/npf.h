/* libnpf: NAS P2P networking (the public interface).
 *
 * One npf_t is one identity on the NPF platform: a node (a NAS device with
 * its vendor credential, or an enrolled console node) that others call, a
 * client that calls them, or both. It keeps the signaling connection,
 * punches direct paths (relays when it cannot), and carries per session:
 *   - port forwards (-L / -D / -R, SOCKS5) in the tunnel's data channel;
 *   - application data on the tunnel's control channel (reliable, ordered,
 *     ahead of the forwards' data);
 *   - audio / video streams, several at once, opened and closed at will:
 *     AnLiu's semi-reliable frame streams on the direct path and the UDP
 *     relay (frames dropped when late, key frames, FEC, delay reports),
 *     queued records on the WS relay (frames dropped when late).
 *
 * Directories (npf_options): conf_dir is read-only for the library (the
 * configuration npf.conf and what it names: the device credential, the root
 * keys, the built-in server list); data_dir is where it keeps what changes
 * (identity, number, pairing state, pinned peer keys, account certificate,
 * the saved server list, and local.json: settings, peers, port forwards and
 * resources saved at run time; its settings override npf.conf's).
 *
 * Lifecycle and threads (one instance):
 *   npf_create -> [calls] -> npf_start | npf_run -> [calls] -> npf_stop
 *   -> (the run ends: event "stopped"; npf_run returns) -> npf_destroy.
 *   - npf_start runs the instance on a thread of its own, npf_run on the
 *     caller's until the run ends; either one once, never after npf_stop.
 *   - Every other function may be called from any thread at any time until
 *     npf_destroy. While it runs, calls execute on its thread (the caller
 *     waits; npf_media_send only queues); otherwise on the caller's thread,
 *     one call at a time per instance. After the run: NPF_ESTATE.
 *   - npf_destroy: from any thread but the instance's own (not from its
 *     callbacks); it stops the run and waits for it (also for an npf_run on
 *     another thread) and for calls in progress, then frees. No call on
 *     the instance may start after it.
 *   - Instances are independent: each its own thread, log and state; one
 *     process may have several.
 *   - A shared runtime (npf_runtime_new, npf_options.runtime): npf_start
 *     puts the instance on one of the runtime's threads, which runs many
 *     instances, each on the same thread until it ends (npf_run: NPF_ESTATE).
 *     Its callbacks must not block, nor wait for an instance on another
 *     runtime thread; npf_destroy of an instance is refused from any
 *     callback on its thread. npf_runtime_free after the last npf_destroy.
 * Sessions and media streams are numbers (0 = none), never reused while the
 * npf_t lives: a stale number only gives NPF_ENOENT.
 *
 * Memory: JSON and text returned by a function belong to the caller, freed
 * with npf_free (NULL: the instance does not run any more, or no memory).
 * What callbacks get is lent for the call only. */
#ifndef NPF_H
#define NPF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(NPF_SHARED)
#  ifdef NPF_BUILDING
#    define NPF_API __declspec(dllexport)
#  else
#    define NPF_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__)
#  define NPF_API __attribute__((visibility("default")))
#else
#  define NPF_API
#endif

#define NPF_API_VERSION 1

typedef struct npf npf_t;
typedef struct npf_runtime npf_runtime;

/* return codes */
enum {
    NPF_OK = 0,
    NPF_EINVAL = -1,        /* bad argument */
    NPF_ENOENT = -2,        /* no such session / stream / peer */
    NPF_ESTATE = -3,        /* not now: not started, not online, the session not up */
    NPF_EUNAVAIL = -4,      /* not available here */
    NPF_ETOOBIG = -5,
    NPF_ENOMEM = -6,
    NPF_EFAIL = -7,         /* other: the message in err */
    NPF_EBUSY = -8,         /* a limit reached: media streams, forwards, resources, ... */
    NPF_ESAVE = -9,         /* done, but local.json could not be written: it is with the next change
                               saved (npf_save), a restart before that loses it; the message in err */
    NPF_EEXIST = -10,       /* already there: a peer with this target, a name taken */
    NPF_EREADONLY = -11     /* from npf.conf (or the platform's): not changed at run time */
};

/* limits (NPF_EBUSY when reached) */
#define NPF_PEER_FORWARDS_MAX 16          /* forwards of one peer */
#define NPF_RESOURCES_MAX     32          /* published resources */
#define NPF_PEERS_SAVED_MAX   256         /* peer records in local.json */
#define NPF_PAIRINGS_MAX      256         /* a device's paired callers */
#define NPF_PASSWORD_MAX      127         /* bytes of a pairing password (at least 8) */
#define NPF_NAME_MAX          32          /* bytes of a peer's name */
#define NPF_NICK_MAX          128         /* bytes of UTF-8 of a peer's nick */
#define NPF_ROOTS_MAX         2           /* the platform's root keys (one in use, one coming) */

enum { NPF_ROLE_NODE = 0, NPF_ROLE_CLIENT = 1, NPF_ROLE_DIRECT = 2 };
enum { NPF_LEVEL_TRACE = 0, NPF_LEVEL_DEBUG, NPF_LEVEL_INFO, NPF_LEVEL_WARN, NPF_LEVEL_ERROR };
enum { NPF_FRAME_KEY = 1 };
#define NPF_MEDIA_FRAME_MAX (4u << 20)     /* bytes per frame */
#define NPF_MEDIA_SEND_QUEUE (16u << 20)   /* bytes of frames from other threads waiting per instance */

#define NPF_MEDIA_STREAMS_MAX 64          /* sending + receiving, across all sessions of one instance */
#define NPF_MEDIA_WS_FRAME_MAX (2u << 20)  /* WS relay: also the per-stream queue byte limit */

/* ---- typed events (npf_callbacks.notify) ---- */

enum { NPF_EV_ONLINE = 1, NPF_EV_OFFLINE, NPF_EV_ENROLLED, NPF_EV_ENROLL_FAILED, NPF_EV_ACCOUNT,
       NPF_EV_PEER,                    /* a peer's state or needs changed: npf_peer_get */
       NPF_EV_PEER_GONE,               /* a peer was removed: the last event about it */
       NPF_EV_FORWARD,                 /* a forward's state or port changed: npf_forward_get */
       NPF_EV_FORWARD_GONE,            /* removed, or with its peer: the last event about it */
       NPF_EV_FORWARD_REFUSED,         /* connections refused by the peer (at most 1/s per forward) */
       NPF_EV_SESSION_UP,              /* a session came up (outgoing or incoming) */
       NPF_EV_SESSION_DOWN,            /* a session ended: what it was, why */
       NPF_EV_RESOURCES,               /* a peer's published list changed: npf_resource_list(peer) */
       NPF_EV_NETWORK,                 /* suspended, or the addresses changed: libnpf mends by itself */
       NPF_EV_PLATFORM,                /* an event the platform sent: name, json */
       NPF_EV_MODULE,                  /* a module's own event (npf/module.h): name, json */
       NPF_EV_STOPPED };               /* the run has ended: the last event; no *_GONE for what is left */

/* why a session ended */
enum { NPF_END_LOCAL = 1,              /* ended here (removed, stopped) */
       NPF_END_PEER,                   /* the other side ended it */
       NPF_END_LOST,                   /* the path was lost */
       NPF_END_REFUSED,                /* not let in: pairing, grant, the device's policy */
       NPF_END_UNREACHABLE,            /* no path could be made */
       NPF_END_PLATFORM,               /* the platform ended or refused it (plan, quota) */
       NPF_END_OTHER };

/* Lent for the call only. Fields only ever grow at the end: one is there
 * when ev->size covers it. Events about an object may come before the call
 * that made it returns (on another thread): use ev->peer / ev->forward and
 * the ctx given at its creation. */
typedef struct npf_event {
    size_t      size;
    int         type;                  /* NPF_EV_*; an unknown one: ignore it */
    uint32_t    peer, forward, session;    /* 0 when not about one */
    void       *ctx;                   /* PEER*, FORWARD*, SESSION_* of a peer: its ctx (read when delivered) */
    uint64_t    number;                /* ENROLLED: the number; ACCOUNT: the account, 0 none;
                                          SESSION_*: the other side's number, 0 none */
    int         state;                 /* PEER: NPF_PEER_*; FORWARD: NPF_FWD_* */
    int         outgoing, path;        /* SESSION_UP / SESSION_DOWN: NPF_PATH_* */
    int         reason;                /* SESSION_DOWN, PEER_GONE: NPF_END_*; FORWARD (failed): NPF_FWD_WHY_* */
    int         retry_in_ms;           /* ENROLL_FAILED, PEER (NPF_PEER_RETRY) */
    const char *why;                   /* for people; "" none */
    const char *name;                  /* PLATFORM: the event's type; MODULE: the module's event; else "" */
    const char *json;                  /* PLATFORM, MODULE: its data; else NULL */
} npf_event;

typedef struct npf_frame_info {
    uint32_t frame_no;          /* from 0, per stream */
    int      flags;             /* NPF_FRAME_KEY */
    uint32_t lost_before;       /* frames lost since the last one delivered */
} npf_frame_info;

/* Callbacks run on the instance's thread, one at a time. What they get
 * (JSON, text, frames, npf_frame_info) is lent for the call only: copy what
 * is kept. A callback may call any function of the same instance except
 * npf_destroy, and must not block it for long. */
typedef struct npf_callbacks {
    size_t size;                /* sizeof(npf_callbacks) of the application's build (npf_callbacks_init) */
    void *user;
    /* a log line ("date time level message"), level NPF_LEVEL_*; without
     * this callback lines go to stderr */
    void (*log)(void *user, int level, const char *line);
    /* events, details in JSON: "online" {server, account_id}, "offline" {why}, "enrolled"
     * {number}, "enroll_failed" {error, reason, retry_in} (one key per model:
     * the platform refused the enrolment; reason: docs/protocol/signaling.md,
     * enroll; tried again in about retry_in seconds), "account" {account_id
     * or null}, "peer_done" {peer, why}, "forward" {peer, spec, up, why},
     * "network" {why} (the process was suspended or the addresses changed:
     * libnpf checks its connections and mends them by itself),
     * "stopped" {} (the run has ended: npf_stop, or the stop command),
     * "platform" {type, data} (an event the platform sent, data as it came:
     * docs/protocol/signaling.md), "resources" {session, resources} (the
     * peer's published list); and those of the program's modules
     * (npf/module.h). "peer_done" and "forward" come from inside the
     * library's work on that peer: removing the peer there (npf_peer_remove_id)
     * is not allowed, do it later (the typed events of notify come from a
     * queue and have no such limit) */
    void (*event)(void *user, const char *name, const char *json);
    /* a session came up (up 1; info: {"peer", "path", "direction", "call_id"})
     * or ended (up 0, info: {"why"}); its media streams end with it */
    void (*session)(void *user, uint32_t session, int up, const char *info);
    /* application data from the peer of a session (npf_session_send) */
    void (*data)(void *user, uint32_t session, const void *buf, size_t len);
    /* the peer opened a media stream with tag (npf_media_opt.tag): return 1
     * to take it (frames arrive through media_frame), 0 to refuse */
    int  (*media_open)(void *user, uint32_t session, uint32_t media, int tag);
    void (*media_frame)(void *user, uint32_t media, const void *buf, size_t len, const npf_frame_info *fi);
    void (*media_closed)(void *user, uint32_t media);
    /* typed events (npf_event): when set, event and session are not called
     * (modules' events come as NPF_EV_MODULE, the platform's as
     * NPF_EV_PLATFORM) */
    void (*notify)(void *user, const npf_event *ev);
} npf_callbacks;

/* Starting without a configuration file: the parameters as fields (each is
 * the npf.conf key of the same meaning, docs/design/libnpf.md); the keys
 * without a field go in npf_options.overrides. Keys are bytes. */
typedef struct npf_setup {
    size_t         size;
    /* the platform (every role but NPF_ROLE_DIRECT) */
    const uint8_t (*roots)[32];        /* its root public keys, 1..NPF_ROOTS_MAX */
    int            nroots;
    const void    *serverlist;         /* the signed server list shipped with the program, as bytes ... */
    size_t         serverlist_len;
    const char    *serverlist_file;    /* ... or as a file; one of the two */
    const char    *serverlist_saved;   /* where the lists the platform sends are kept; NULL:
                                          data_dir/serverlist-saved.bin; "": not kept */
    const char    *server_url;         /* tests: this one server instead of the list ... */
    const uint8_t *server_pub;         /* ... with its 32-byte key */
    const char    *doh_servers;        /* tests: "IP:PORT=HOST,..." instead of the public DoH services */
    /* the identity of a device (NPF_ROLE_NODE); neither: a console node or a client */
    const char    *cred;               /* "NPFD1...." one credential per device ... */
    const char    *password;           /* ... with its default pairing password */
    const char    *model_cred;         /* "NPFV2...." one credential per model: enrols at the first start */
    const char    *serial;             /* model_cred: the device's serial; NULL: the smallest MAC address */
    const char    *hw_info;            /* model_cred: "v1|v2|v3"; NULL: read here */
    const char    *model;              /* the product, for the platform's statistics; NULL: "NAS" / "console" */
    /* direct connections (NPF_ROLE_DIRECT, or a node that also listens) */
    const char    *direct_host;        /* listen here for direct peers; NULL: every address */
    uint16_t       direct_port;        /* 0: no direct listener */
    const uint8_t *direct_psk;         /* 32 bytes, with direct_port */
    /* the network: 0 / NULL is the default */
    int            udp_port;           /* the main UDP port, 0 any */
    int            no_portmap;         /* 1: no PCP / NAT-PMP mapping on the router */
    int            relays_only;        /* 1: connect_mode secure */
    int            max_calls;          /* sessions accepted at once, 0: 32 */
    int            punch_lead_ms;      /* -1 automatic (the default) */
    int            punch_sockets;      /* 0 automatic */
    int            no_host_report;     /* 1: report_host = 0 */
    int            no_hosted_trust;    /* 1: hosted_trust = 0 */
    int            peer_idle_s;        /* the default idle time of NPF_CONNECT_ON_DEMAND peers; 0: 300 */
} npf_setup;

enum { NPF_OPT_NO_SAVED_SETTINGS = 1,  /* local.json's settings are not applied (nor saved) */
       NPF_OPT_NO_SAVED_OBJECTS = 2 }; /* its peers, forwards and resources are not brought back (nor saved) */

/* ABI: the structures carry their size and only grow at the end; the
 * library reads what the application's build has and takes the defaults
 * for the rest. Initialise them with the _init / _default functions. */
typedef struct npf_options {
    size_t      size;           /* sizeof(npf_options) of the application's build (npf_options_init) */
    const char *conf_dir;       /* read-only for the library */
    const char *data_dir;       /* writable; NULL: conf_dir */
    const char *conf_file;      /* NULL: "npf.conf" in conf_dir (an absolute path also works) */
    /* settings on top of the configuration, "key = value" lines (tests,
     * command-line options); local.json's settings still override them */
    const char *overrides;
    int         role;           /* NPF_ROLE_NODE: long running (callable with a number, saved peers,
                                   router port mapping); NPF_ROLE_CLIENT: one-off tasks (account,
                                   devices, a session in the foreground); NPF_ROLE_DIRECT: no platform */
    int         log_level;      /* -1: the configuration's log_level */
    const npf_callbacks *cb;    /* NULL: none; copied by npf_create */
    /* the program, told to the platform at login (its records, the other
     * side of a session): a name of 1..32 of a-z 0-9 . _ - and a version
     * of up to 32 printable characters; NULL: "libnpf" and the library's
     * version */
    const char *app_name;
    const char *app_ver;
    /* 1: keep no recent lines for npf_log_json (16 KB an instance; for an
     * application with a log callback and many instances) */
    int         no_log_ring;
    /* a shared runtime to run on (see Lifecycle); NULL: a thread of its own */
    npf_runtime *runtime;
    /* NULL: conf_dir / conf_file; given: no configuration file is read,
     * conf_dir and conf_file must be NULL, data_dir is needed */
    const npf_setup *setup;
    int          flags;         /* NPF_OPT_* */
} npf_options;

NPF_API const char *npf_version(void);
NPF_API int         npf_api_version(void);
/* the defaults, for size bytes (the application's sizeof: the macros give
 * it), so a library with larger structures never writes past them */
NPF_API void        npf_options_init_size(npf_options *o, size_t size);
NPF_API void        npf_callbacks_init_size(npf_callbacks *cb, size_t size);
NPF_API void        npf_setup_init_size(npf_setup *s, size_t size);
#define npf_options_init(o)    npf_options_init_size((o), sizeof *(o))
#define npf_callbacks_init(cb) npf_callbacks_init_size((cb), sizeof *(cb))
#define npf_setup_init(s)      npf_setup_init_size((s), sizeof *(s))

/* Reads the configuration and the identity (makes data_dir and an identity
 * when there is none). NPF_OK, or an error with the message in err. */
NPF_API int  npf_create(const npf_options *o, npf_t **out, char *err, size_t errcap);
NPF_API int  npf_start(npf_t *n);           /* on a thread of its own; NPF_ESTATE: started or stopped before */
NPF_API int  npf_run(npf_t *n);             /* on this thread, until the run ends */
NPF_API void npf_stop(npf_t *n);            /* any thread; sessions end; returns at once */
NPF_API void npf_destroy(npf_t *n);         /* stops, waits, frees (see Lifecycle) */
NPF_API void npf_free(void *p);

/* a shared runtime of threads threads (<= 0: one per CPU); NULL: no memory
 * or no thread. npf_runtime_free: NPF_ESTATE while an instance created on it
 * is not destroyed yet, else it stops the threads and frees */
NPF_API npf_runtime *npf_runtime_new(int threads);
NPF_API int          npf_runtime_free(npf_runtime *rt);

/* ---- state ---- */

/* identity, server, NAT, peers with their forwards, sessions */
NPF_API char *npf_status_json(npf_t *n);
/* the settings in effect (secrets hidden) */
NPF_API char *npf_config_json(npf_t *n);
/* the last lines of the log, up to max bytes */
NPF_API char *npf_log_json(npf_t *n, int max);
/* a setting in effect ("" when unset); NPF_ENOENT: not a configuration key,
 * NPF_ETOOBIG: out too small. Secrets read "(hidden)" */
NPF_API int   npf_config_get(npf_t *n, const char *key, char *out, size_t cap);
/* save: also into local.json (data_dir). NPF_OK: in effect now; 1: saved,
 * in effect at the next start (a start-up setting) */
NPF_API int   npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap);

/* local.json again (what NPF_ESAVE left): NPF_OK, or NPF_ESAVE with nothing lost */
NPF_API int   npf_save(npf_t *n);

/* ---- objects: peers, forwards, resources ----
 * Peers and forwards are numbers (0 none) never reused while the npf_t lives;
 * a stale one gives NPF_ENOENT. Lists: count is always the number there is;
 * with too small an array the first cap are filled and NPF_ETOOBIG returned.
 * Creating: NPF_OK / NPF_ESAVE (made; not saved yet) give the new one,
 * NPF_EEXIST the one there is (what was given is ignored), other errors 0
 * and nothing made. */

enum { NPF_TARGET_NUMBER = 1,          /* a node on the platform, by its number */
       NPF_TARGET_DIRECT = 2 };        /* HOST:PORT with a pre-shared key, no platform */
enum { NPF_CONNECT_KEEP = 0,           /* connected, again after a drop (backoff) */
       NPF_CONNECT_ONCE = 1,           /* one session: NPF_PEER_ENDED when it ends */
       NPF_CONNECT_ON_DEMAND = 2 };    /* a session when a forward is used, ended when idle */
enum { NPF_PERSIST = 1,                /* saved in local.json, back at the next start */
       NPF_FIXED = 2,                  /* info only: a resource of npf.conf */
       NPF_PLATFORM = 8 };             /* info only: a peer opened for port mappings saved on the platform
                                          (a hosted client's), or one of those forwards */

typedef struct npf_peer_opt {
    size_t         size;
    int            target;             /* NPF_TARGET_* */
    uint64_t       number;             /* NPF_TARGET_NUMBER */
    const char    *host;               /* NPF_TARGET_DIRECT: an address or name, IPv6 without brackets */
    uint16_t       port;
    const uint8_t *psk;                /* NPF_TARGET_DIRECT: 32 bytes */
    const char    *password;           /* the device's pairing password the first time; NULL: a pinned
                                          key or the account's grant */
    int            connect;            /* NPF_CONNECT_*; NPF_CONNECT_ONCE with NPF_PERSIST: NPF_EINVAL */
    int            idle_ms;            /* NPF_CONNECT_ON_DEMAND: ends this long after the last connection;
                                          0: the instance's peer_idle */
    int            flags;              /* NPF_PERSIST */
    const char    *name;               /* a name for it, NULL none */
    const char    *nick;               /* what to show people, NULL none */
    void          *ctx;                /* the application's, given back in its events */
} npf_peer_opt;

enum { NPF_PEER_IDLE = 0,              /* on demand, no session now */
       NPF_PEER_WAITING,               /* waiting for the platform (not logged in yet) */
       NPF_PEER_CONNECTING,
       NPF_PEER_CONNECTED,
       NPF_PEER_RETRY,                 /* retry_in_ms from now */
       NPF_PEER_ENDED };               /* given up: NPF_CONNECT_ONCE ended, or a need below (met: tried
                                          again by itself); it stays until removed */
enum { NPF_NEED_PASSWORD = 1,          /* not paired: the user gives its password */
       NPF_NEED_PASSWORD_WRONG = 2,    /* the device refused the last one */
       NPF_NEED_PAIRING_LOST = 4,      /* the device forgot the pairing (reset): a password again */
       NPF_NEED_ACCOUNT = 8 };         /* let in through the account: log in again */

typedef struct npf_peer_info {
    size_t   size;
    int      target;
    uint64_t number;
    char     host[256];
    uint16_t port;
    char     name[NPF_NAME_MAX + 1], nick[NPF_NICK_MAX + 1];
    int      connect;
    int      flags;                    /* NPF_PERSIST (meant to be saved), NPF_PLATFORM */
    int      saved;                    /* NPF_PERSIST and its record in local.json up to date */
    int      state;                    /* NPF_PEER_* */
    int      needs;                    /* NPF_NEED_* */
    int      retry_in_ms;
    int      end_reason;               /* the last session's: NPF_END_*, 0 none yet */
    char     why[64];                  /* the same, or why it waits, for people */
    uint32_t session;                  /* the session up now, 0 none */
    int      nforwards;
    void    *ctx;                      /* the application's (NPF_PEER_OPT_CTX) */
} npf_peer_info;

NPF_API void npf_peer_opt_init_size(npf_peer_opt *o, size_t size);
NPF_API void npf_peer_info_init_size(npf_peer_info *o, size_t size);
#define npf_peer_opt_init(o)  npf_peer_opt_init_size((o), sizeof *(o))
#define npf_peer_info_init(o) npf_peer_info_init_size((o), sizeof *(o))

NPF_API int npf_peer_create(npf_t *n, const npf_peer_opt *o, uint32_t *peer, char *err, size_t errcap);
/* its session ends, its forwards go; a persisted one leaves local.json */
NPF_API int npf_peer_remove_id(npf_t *n, uint32_t peer);
/* by target ("318204776", "host:9000") or name */
NPF_API int npf_peer_find(npf_t *n, const char *target_or_name, uint32_t *peer);
NPF_API int npf_peer_list(npf_t *n, uint32_t *peers, size_t cap, size_t *count);
NPF_API int npf_peer_get(npf_t *n, uint32_t peer, npf_peer_info *out);
/* NPF_CONNECT_ON_DEMAND: the session now; NPF_PEER_ENDED: one more try */
NPF_API int npf_peer_connect_now(npf_t *n, uint32_t peer);

/* A peer's settings, one at a time (npf_peer_setopt). int options: an int,
 * len sizeof(int); strings: NUL-terminated, len 0, "" removes; CTX: the
 * pointer itself as val, len 0. A wrong len or value, a string too long or
 * an unknown option: NPF_EINVAL, the peer unchanged. A persisted peer is
 * saved after the change (NPF_ESAVE: in effect, not written yet). On an
 * NPF_PLATFORM peer CONNECT, IDLE_MS and PERSIST are NPF_EREADONLY,
 * PASSWORD NPF_EINVAL. */
enum { NPF_PEER_OPT_CONNECT = 1,       /* NPF_CONNECT_*: KEEP connects now when it has no session;
                                          ON_DEMAND needs NPF_PERSIST and no remote forward, the
                                          session goes on and the idle time runs from now; ONCE
                                          ends it with its session (at once without one), not for a
                                          persisted peer */
       NPF_PEER_OPT_IDLE_MS,           /* on demand: ms without a connection before the session
                                          ends, 0 the instance's peer_idle (kept for later when it
                                          is not on demand now) */
       NPF_PEER_OPT_PERSIST,           /* 1: saved now with its forwards (not ONCE); 0: not brought
                                          back at the next start, its saved forwards leave
                                          local.json, its pinned key and names stay (not ON_DEMAND) */
       NPF_PEER_OPT_NAME,              /* a name (NPF_NAME_MAX), unique among the peers */
       NPF_PEER_OPT_NICK,              /* what people see (NPF_NICK_MAX) */
       NPF_PEER_OPT_CTX,               /* the application's, in its events from now on (also NULL) */
       NPF_PEER_OPT_PASSWORD };        /* not paired yet, or the password was refused: tried at
                                          once, not kept (NPF_PASSWORD_MAX) */
NPF_API int npf_peer_setopt(npf_t *n, uint32_t peer, int opt, const void *val, size_t len);

enum { NPF_FWD_LOCAL = 1,              /* -L: a port here to a target on the peer's side */
       NPF_FWD_SOCKS = 2,              /* -D: a SOCKS5 proxy here, through the peer */
       NPF_FWD_REMOTE = 3 };           /* -R: a port on the peer to a target here */
enum { NPF_PROTO_TCP = 0, NPF_PROTO_UDP = 1 };

typedef struct npf_endpoint {
    const char *host;                  /* IPv6 without brackets; listen: NULL is 127.0.0.1 */
    uint16_t    port;                  /* listen: 0 picked (here by the system, -R by the peer) */
} npf_endpoint;

typedef struct npf_forward_opt {
    size_t       size;
    int          kind;                 /* NPF_FWD_* */
    int          proto;                /* NPF_PROTO_* (UDP: LOCAL and REMOTE) */
    npf_endpoint listen;
    npf_endpoint target;               /* NPF_FWD_SOCKS: none */
    int          flags;                /* NPF_PERSIST: with the peer (it must be NPF_PERSIST too) */
    void        *ctx;
} npf_forward_opt;

enum { NPF_FWD_WAITING = 0,            /* for the session (-R: for the peer to listen) */
       NPF_FWD_UP,                     /* the listener works (here, or on the peer for -R) */
       NPF_FWD_FAILED };               /* the rule as a whole: why_code; tried again with backoff
                                          (NPF_FWD_WHY_FORBIDDEN: with the next session only) */
enum { NPF_FWD_WHY_NONE = 0,
       NPF_FWD_WHY_PORT_IN_USE,        /* the port here is taken */
       NPF_FWD_WHY_BIND,               /* the listen address cannot be bound here */
       NPF_FWD_WHY_FORBIDDEN,          /* -R: the peer's reverse resource does not allow it */
       NPF_FWD_WHY_TOO_MANY,           /* -R: 16 reverse mappings in the session already */
       NPF_FWD_WHY_REQUEST,            /* -R: the request failed or timed out */
       NPF_FWD_WHY_OTHER };            /* why has the text */

typedef struct npf_forward_info {
    size_t   size;
    uint32_t peer;
    int      kind, proto;
    int      flags, saved;             /* as for peers */
    char     listen_host[64];
    uint16_t listen_port;              /* the port in use (also when 0 was asked); 0 not yet */
    char     target_host[256];
    uint16_t target_port;
    int      state;                    /* NPF_FWD_* */
    int      why_code;                 /* NPF_FWD_FAILED: NPF_FWD_WHY_* */
    char     why[64];
    int      conns;                    /* connections open now */
    uint32_t refused;                  /* connections the peer refused (its resources), so far */
    char     refused_why[64];          /* the last one's target */
    void    *ctx;                      /* the application's (NPF_FWD_OPT_CTX) */
} npf_forward_info;

NPF_API void npf_forward_opt_init_size(npf_forward_opt *o, size_t size);
NPF_API void npf_forward_info_init_size(npf_forward_info *o, size_t size);
#define npf_forward_opt_init(o)  npf_forward_opt_init_size((o), sizeof *(o))
#define npf_forward_info_init(o) npf_forward_info_init_size((o), sizeof *(o))

NPF_API int npf_forward_create(npf_t *n, uint32_t peer, const npf_forward_opt *o, uint32_t *fwd, char *err,
                               size_t errcap);
NPF_API int npf_forward_remove(npf_t *n, uint32_t fwd);
/* peer 0: every peer's */
NPF_API int npf_forward_list(npf_t *n, uint32_t peer, uint32_t *fwds, size_t cap, size_t *count);
NPF_API int npf_forward_get(npf_t *n, uint32_t fwd, npf_forward_info *out);
/* a forward's settings, as npf_peer_setopt: NPF_FWD_OPT_CTX the pointer as val, len 0 */
enum { NPF_FWD_OPT_CTX = 1 };
NPF_API int npf_forward_setopt(npf_t *n, uint32_t fwd, int opt, const void *val, size_t len);

enum { NPF_RES_TCP = 1, NPF_RES_UDP, NPF_RES_NET, NPF_RES_SOCKS, NPF_RES_REVERSE };

typedef struct npf_resource {
    size_t       size;
    int          type;                 /* NPF_RES_* */
    const char  *name;                 /* unique, up to 64 bytes of UTF-8 */
    const char  *svc;                  /* tcp / udp: "http", "https", "rdp", "ssh" ...; NULL none */
    npf_endpoint service;              /* tcp / udp: an IP address (no brackets) or localhost, and port */
    const char  *rule;                 /* net / socks: "lan", "*", ADDR[/PREFIX][:PORT[-PORT]];
                                          udp without a service host: "*" or ADDR[/PREFIX][:PORT[-PORT]];
                                          reverse: [lan:]"*", PORT or PORT-PORT; up to 63 bytes */
    const char  *path;                 /* a web page: the page to open, NULL "/" */
    const char  *desc;                 /* NULL none, up to 256 bytes */
    int          flags;                /* NPF_PERSIST */
} npf_resource;

typedef struct npf_resource_info {
    size_t   size;
    int      type, flags, saved;       /* flags: NPF_PERSIST, NPF_FIXED */
    char     name[65], svc[16];
    char     host[64];                 /* tcp, udp of one service */
    uint16_t port;
    char     rule[64];                 /* net / socks / reverse, udp of "*" or networks */
    char     path[129], desc[257];
} npf_resource_info;

NPF_API void npf_resource_init_size(npf_resource *r, size_t size);
#define npf_resource_init(r) npf_resource_init_size((r), sizeof *(r))
/* added, or the one of that name replaced (as given: a persisted one
 * replaced by one without NPF_PERSIST leaves local.json) */
NPF_API int npf_resource_put(npf_t *n, const npf_resource *r, char *err, size_t errcap);
NPF_API int npf_resource_remove(npf_t *n, const char *name);
/* this node's (peer 0), or what that peer published as last heard; elem_size:
 * the caller's sizeof (the macro) */
NPF_API int npf_resource_list_size(npf_t *n, uint32_t peer, npf_resource_info *out, size_t elem_size, size_t cap,
                                   size_t *count);
#define npf_resource_list(n, peer, out, cap, count) \
    npf_resource_list_size((n), (peer), (out), sizeof *(out), (cap), (count))

/* ---- a device's pairing and owner ---- */

/* the pairing password (NPF_ESTATE: no number yet) */
NPF_API int npf_pairing_password_get(npf_t *n, char *out, size_t cap);
/* 8 .. NPF_PASSWORD_MAX bytes */
NPF_API int npf_pairing_password_set(npf_t *n, const char *password, char *err, size_t errcap);
typedef struct npf_pairing {
    size_t  size;
    uint8_t key[32];                   /* the caller's public key */
    int64_t since;                     /* Unix time it paired */
} npf_pairing;
NPF_API int npf_pairing_list_size(npf_t *n, npf_pairing *out, size_t elem_size, size_t cap, size_t *count);
#define npf_pairing_list(n, out, cap, count) npf_pairing_list_size((n), (out), sizeof *(out), (cap), (count))
/* key NULL: all of them */
NPF_API int npf_pairing_remove(npf_t *n, const uint8_t key[32]);
/* the owner account forgotten here, the platform told at the next login; the pairings stay */
NPF_API int npf_owner_reset(npf_t *n);

/* ---- this node, sessions, the network ---- */

enum { NPF_NAT_UNKNOWN = 0, NPF_NAT_EIM, NPF_NAT_ADM, NPF_NAT_APDM };
enum { NPF_PATH_DIRECT = 1, NPF_PATH_UDP_RELAY, NPF_PATH_WS_RELAY };

typedef struct npf_node_info {
    size_t   size;
    uint64_t number;                   /* 0: none yet */
    int      role;
    int      online;                   /* logged in to the platform */
    int      server;                   /* its id, 0 none */
    uint64_t account_id;               /* the account session, 0 none */
    int      enrolling;                /* a model credential: enrolment going on */
    int      nat, nat_filtering;       /* NPF_NAT_*: the mapping, the filtering */
    char     public_addr[64];          /* as the probe saw it, "" not known */
    uint16_t udp_port;
    int64_t  started;                  /* Unix time, 0 not running */
    int      peers, sessions;
    int      unsaved;                  /* changes waiting for local.json (npf_save) */
} npf_node_info;

typedef struct npf_session_info {
    size_t   size;
    uint32_t peer;                     /* the peer it belongs to, 0: someone calling here */
    uint64_t number;                   /* the other side's number, 0 none */
    int      outgoing;
    int      path;                     /* NPF_PATH_* */
    char     call_id[40];
} npf_session_info;

NPF_API void npf_node_info_init_size(npf_node_info *o, size_t size);
NPF_API void npf_session_info_init_size(npf_session_info *o, size_t size);
#define npf_node_info_init(o)    npf_node_info_init_size((o), sizeof *(o))
#define npf_session_info_init(o) npf_session_info_init_size((o), sizeof *(o))
NPF_API int npf_node_get(npf_t *n, npf_node_info *out);
NPF_API int npf_session_get(npf_t *n, uint32_t session, npf_session_info *out);
NPF_API int npf_session_list(npf_t *n, uint32_t *sessions, size_t cap, size_t *count);
/* the network changed (a VPN up or down, another Wi-Fi): checked and mended now */
NPF_API int npf_network_changed(npf_t *n);

/* ---- commands and platform requests ---- */

/* A command of the command line (status, resource, get, set, log, show,
 * passwd, unpair, owner-reset, netcheck, id, ..., and the modules' own;
 * peers and forwards are not commands: the objects above): the exit code
 * and output text come to cb, at once or when the platform has answered.
 * NPF_OK when it runs. */
typedef void (*npf_text_cb)(void *user, int code, const char *text);
NPF_API int npf_command(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user);

/* A request to the platform (account_*, verify_*, password_reset_*, auth_*,
 * login_method_*, device_*, share_*, mapping_*: signaling.md); key_proof adds
 * this connection's key proof (account_register / account_login /
 * password_reset_finish / auth_finish). The library keeps the account session and its
 * certificate that a reply gives. cb gets the whole reply (JSON) or NULL
 * when the connection was lost. */
typedef void (*npf_reply_cb)(void *user, int ok, const char *reply);
NPF_API int npf_request(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb,
                        void *user);

/* ---- sessions: application data ---- */

/* sessions up now, JSON array of {"session", "peer", "path", "direction", "call_id"} */
NPF_API char *npf_sessions_json(npf_t *n);
/* a hosted client's public mappings (npf-hosted): {"open": connections open,
 * "closing", "mappings": [{"mapping_id", "port", "listening", "conns"}]};
 * close != 0: the public ports close now and stay closed (stopping), the
 * open connections go on */
NPF_API char *npf_public_json(npf_t *n, int close);
/* application data to the peer (cb.data there): reliable, ordered, ahead of
 * the forwards' data; up to 16384 bytes per call */
NPF_API int   npf_session_send(npf_t *n, uint32_t session, const void *buf, size_t len);

/* ---- sessions: audio / video (AnLiu semi-reliable streams) ---- */

typedef struct npf_media_opt {
    size_t size;                /* sizeof(npf_media_opt) of the application's build (npf_media_opt_default) */
    int tag;                    /* the application's stream kind, 0..999 (the peer's media_open gets it) */
    int prio;                   /* 0 (first) .. 3; default 1: ahead of the forwards' data (2) */
    int max_age_ms;             /* a frame not sent this long after npf_media_send is dropped; default 500 */
    int drop_until_key;         /* after a dropped frame, drop the others until a key frame */
    int fec;                    /* -1 automatic (default), 0 off, 1 on */
    int fec_ratio;              /* fixed parity per 100 packets, 0 adaptive (default) */
    int latency_rtt;            /* the receiver may wait this many round trips for a frame; 0 = off */
    int rcv_deadline_ms;        /* reserved: needs AnLiu to change a stream's receiving
                                   options; AnLiu's default applies */
    int rcv_drop_until_key;     /* the peer, receiving: after a lost frame skip to the next key frame */
} npf_media_opt;

typedef struct npf_media_stats {
    size_t   size;              /* set by the caller: sizeof(npf_media_stats) */
    uint32_t target_rate;       /* bytes/s the encoder may send over all streams of the session */
    uint32_t srtt_ms, min_rtt_ms;
    uint32_t frames_dropped;    /* sender: too old */
    uint32_t frames_skipped;    /* receiver: skipped over */
    uint32_t fec_recovered;
    uint32_t peer_frame_delay_avg_ms, peer_frame_delay_max_ms;  /* the peer's last report on our frames */
    uint32_t peer_jitter_ms;
    int      capacity_short;    /* the path is slower than the media */
} npf_media_stats;

NPF_API void npf_media_opt_default_size(npf_media_opt *o, size_t size);
#define npf_media_opt_default(o) npf_media_opt_default_size((o), sizeof *(o))
/* a stream of frames to the peer of a session (any path); returns the
 * stream number, 0 with *err: NPF_ESTATE (the session is not up), NPF_EBUSY
 * (64 streams per instance, or 30 outgoing streams per AnLiu session). Opening and closing
 * often is fine: AnLiu's streams are kept and reused (data-channel.md 14) */
NPF_API uint32_t npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, int *err);
/* one frame, up to NPF_MEDIA_FRAME_MAX (WS: NPF_MEDIA_WS_FRAME_MAX;
 * any thread; copied, never blocks):
 * NPF_OK when queued; from a callback it is sent at once and errors show */
NPF_API int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len);
NPF_API int npf_media_stats_get(npf_t *n, uint32_t media, npf_media_stats *out);
NPF_API int npf_media_close(npf_t *n, uint32_t media);

#ifdef __cplusplus
}
#endif

#endif

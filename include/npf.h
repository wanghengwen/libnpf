/* libnpf's public API: the one header of the installed library, for
 * applications and device firmware (docs/design/libnpf.md).
 *
 * An npf_t is one identity on the NPF platform: a node others call (a
 * device with its vendor credential, or an enrolled console node), a client
 * that calls nodes, or both. It keeps the signaling connection, makes direct
 * paths to peers (relays when it cannot), and carries in each session port
 * forwards, application data and media streams.
 *
 * Directories (npf_options): the library only reads conf_dir (npf.conf and
 * the files it names). It writes data_dir: the identity, the number, the
 * pairing state, pinned peer keys, the account certificate, the saved
 * server list, and local.json (settings, peers, forwards and resources saved
 * at run time; its settings override npf.conf's).
 *
 * Lifecycle: npf_create, then npf_start or npf_run (once, never after
 * npf_stop), npf_stop, and npf_destroy. The run ends with the event
 * "stopped"; npf_run returns then.
 *
 * Threads:
 *   - Any function may be called from any thread until npf_destroy. While
 *     the instance runs, a call executes on its thread and the caller waits
 *     (npf_media_send only queues). Before the run, a call executes on the
 *     caller's thread, one at a time per instance. After the run, calls
 *     return NPF_ESTATE (functions returning text: NULL).
 *   - npf_destroy may be called from any thread except the instance's own:
 *     from its callbacks it is refused (an error is logged, nothing freed).
 *     It stops the run, waits for it and for calls in progress, and frees.
 *     No call on the instance may start after it.
 *   - Instances are independent (thread, log, state); a process may have
 *     several.
 *   - A shared runtime (npf_runtime_new, npf_options.runtime) runs many
 *     instances on a few threads; each instance stays on one thread. Its
 *     callbacks must not block: on its threads a call for an instance on
 *     another thread gives NPF_ESTATE (NULL) and npf_destroy is refused,
 *     an error logged, instead of waiting (two such waits, each for the
 *     other's thread, would never end). npf_run is not available
 *     (NPF_ESTATE).
 *
 * Peers, forwards, sessions and media streams are numbers (0 = none), never
 * reused while the npf_t lives: a stale number gives NPF_ENOENT.
 *
 * Memory: text returned by a function is the caller's, freed with npf_free;
 * NULL means the run has ended or no memory. What a callback gets is lent
 * for the call only. */
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
    NPF_ENOENT = -2,        /* no such peer, forward, resource, session or stream */
    NPF_ESTATE = -3,        /* not now: not started, not online, no number, the session not up, the run ended,
                               a device's state.json damaged (safe mode); or from a shared runtime's callback
                               for an instance on another thread */
    NPF_EUNAVAIL = -4,      /* not available here: this build, role or npf_options.flags */
    NPF_ETOOBIG = -5,       /* the output buffer or the input is too large */
    NPF_ENOMEM = -6,
    NPF_EFAIL = -7,         /* other failure: the message in err */
    NPF_EBUSY = -8,         /* a limit is reached (media streams, forwards, resources, a queue) */
    NPF_ESAVE = -9,         /* done and in effect, but its file in data_dir (local.json, state.json)
                               could not be written; npf_save writes it, else a restart loses it */
    NPF_EEXIST = -10,       /* already there: a peer with this target, or the name is taken */
    NPF_EREADONLY = -11     /* set by npf.conf or the platform: not changed at run time */
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
#define NPF_MEDIA_SEND_QUEUE (16u << 20)   /* bytes of frames queued from other threads, per instance */

#define NPF_MEDIA_STREAMS_MAX 64          /* sending + receiving, across all sessions of one instance */

/* why a peer's last session ended (npf_peer_info.end_reason) */
enum { NPF_END_LOCAL = 1,              /* ended here (removed, stopped) */
       NPF_END_PEER,                   /* the other side ended it */
       NPF_END_LOST,                   /* the path was lost */
       NPF_END_REFUSED,                /* not let in: pairing, grant, the device's policy */
       NPF_END_UNREACHABLE,            /* no path could be made */
       NPF_END_PLATFORM,               /* the platform ended or refused it (plan, quota) */
       NPF_END_OTHER };

typedef struct npf_frame_info {
    uint32_t frame_no;          /* from 0, per stream */
    int      flags;             /* NPF_FRAME_KEY */
    uint32_t lost_before;       /* frames lost since the last one delivered */
} npf_frame_info;

/* Callbacks run on the instance's thread, one at a time. Their arguments
 * are lent for the call only: copy what is kept. A callback may call any
 * function of its instance except npf_destroy, and must return soon. Every
 * callback is optional. */
typedef struct npf_callbacks {
    size_t size;                /* set by npf_callbacks_init */
    void *user;
    /* A log line ("date time level message"), level NPF_LEVEL_*. Without
     * this callback lines go to stderr. */
    void (*log)(void *user, int level, const char *line);
    /* An event, details in a JSON object, its members strings unless said
     * (64-bit numbers as decimal strings):
     *   "online" {server: its id (a number), account_id: the account
     *     session's, or null}; "offline" {why};
     *   "enrolled" {number}; "enroll_failed" {error, reason, retry_in: seconds
     *     (a number)}: the platform refused a model credential's enrolment
     *     (reason: signaling.md, enroll); tried again in about retry_in s;
     *   "account" {account_id, or null}: an account session began or ended;
     *   "peer_done" {peer, why}: a peer gave up (npf_peer_info.state
     *     NPF_PEER_ENDED); "forward" {peer, spec: "-L ...", "-D ...", "-R ..."
     *     or a module's, up: true or false, why}; peer is the peer's target
     *     text ("318204776", "host:9000");
     *   "network" {why}: the process was suspended or the addresses changed;
     *     the library checks and mends its connections itself;
     *   "platform" {type, data: as the platform sent it, null for none};
     *   "resources" {session: a number, resources: [{name, target, type, and
     *     svc, desc, path when set, fixed: true when from npf.conf}]}: the
     *     peer's published list, at the session's start and when it changes;
     *   "stopped" {}: the run has ended; the last event;
     *   and the events of the program's modules (npf/module.h).
     * Any of them may remove the peer (npf_peer_remove), "peer_done" and
     * "forward" of that peer too: nothing more comes of it. */
    void (*event)(void *user, const char *name, const char *json);
    /* A session came up (up 1) or ended (up 0, info {"why"}). Up, info is
     * {"session": a number, "peer": the other side (its number, "key:" and
     * its key's fingerprint, or "-"), "path": "p2p", "relay", "relay
     * (binding)", "ws relay", "direct" or "none", "direction": "out" or
     * "in", "call_id"}, for a caller here also "app" (its program, "name
     * ver", when known) and "hosted": true (a hosted client). Its media
     * streams end first, each with media_closed. */
    void (*session)(void *user, uint32_t session, int up, const char *info);
    /* application data from the session's peer (npf_session_send there) */
    void (*data)(void *user, uint32_t session, const void *buf, size_t len);
    /* The peer opened stream media with its tag (npf_media_opt.tag). Return
     * 1 to take it (frames come to media_frame), 0 to refuse. Without this
     * callback every stream is refused. */
    int  (*media_open)(void *user, uint32_t session, uint32_t media, int tag);
    void (*media_frame)(void *user, uint32_t media, const void *buf, size_t len, const npf_frame_info *fi);
    /* a stream ended: the peer closed it or its session ended (not after npf_media_close) */
    void (*media_closed)(void *user, uint32_t media);
} npf_callbacks;

/* The configuration as fields, instead of npf.conf (npf_options.setup).
 * Each field is the npf.conf key of the same meaning (docs/design/libnpf.md);
 * other keys go in npf_options.overrides. NULL / 0 is the default. Keys are
 * raw bytes. Everything is copied by npf_create. */
typedef struct npf_setup {
    size_t         size;               /* set by npf_setup_init */
    /* the platform (every role but NPF_ROLE_DIRECT) */
    const uint8_t (*roots)[32];        /* its root public keys, 1..NPF_ROOTS_MAX */
    int            nroots;
    const void    *serverlist;         /* the signed server list shipped with the program, as bytes, */
    size_t         serverlist_len;
    const char    *serverlist_file;    /* or as a file: one of the two */
    const char    *serverlist_saved;   /* where lists the platform sends are kept; NULL:
                                          data_dir/serverlist-saved.bin; "": not kept */
    const char    *server_url;         /* tests: this one server instead of the list, */
    const uint8_t *server_pub;         /* with its 32-byte key */
    const char    *doh_servers;        /* tests: "IP:PORT=HOST,..." instead of the public DoH services */
    /* a device's identity (NPF_ROLE_NODE); neither: a console node or a client */
    const char    *cred;               /* "NPFD1...": the credential of one device, */
    const char    *password;           /* with its default pairing password */
    const char    *model_cred;         /* "NPFV2...": a model's credential; the device enrols at its first start */
    const char    *serial;             /* model_cred: the device's serial; NULL: its smallest MAC address */
    const char    *hw_info;            /* model_cred: "v1|v2|v3"; NULL: read from the system */
    const char    *model;              /* the product, for the platform's statistics; NULL: "NAS" / "console" */
    /* direct connections (NPF_ROLE_DIRECT, or a node that also listens) */
    const char    *direct_host;        /* listen here for direct peers; NULL: every address */
    uint16_t       direct_port;        /* 0: no direct listener */
    const uint8_t *direct_psk;         /* 32 bytes, with direct_port */
    /* the network */
    int            udp_port;           /* the main UDP port; 0: any */
    int            no_portmap;         /* 1: no PCP / NAT-PMP mapping on the router */
    int            relays_only;        /* 1: connect_mode secure */
    int            max_calls;          /* sessions accepted at once; 0: 32 */
    int            punch_lead_ms;      /* -1: automatic (the default) */
    int            punch_sockets;      /* 0: automatic */
    int            no_host_report;     /* 1: report_host = 0 */
    int            no_hosted_trust;    /* 1: hosted_trust = 0 */
    int            peer_idle_s;        /* idle time of NPF_CONNECT_ON_DEMAND peers without their own; 0: 300 */
} npf_setup;

enum { NPF_OPT_NO_SAVED_SETTINGS = 1,  /* local.json's settings are neither applied nor saved */
       NPF_OPT_NO_SAVED_OBJECTS = 2,   /* its peers, forwards and resources are neither brought back nor saved */
       NPF_OPT_NO_LOG_RING = 4 };      /* no recent lines for npf_log_json (saves 16 KB per instance) */

/* ABI: structures only grow at the end. A structure the application passes
 * starts with its size, set by its _init macro with the defaults. A
 * structure the library fills is sized by the macro that passes the
 * caller's sizeof (npf_peer_get, npf_resource_list, ...). The library uses
 * what both builds know: the defaults or zeros for the rest. */
typedef struct npf_options {
    size_t      size;           /* set by npf_options_init */
    const char *conf_dir;       /* read only */
    const char *data_dir;       /* written; NULL: conf_dir */
    const char *conf_file;      /* NULL: "npf.conf" in conf_dir (an absolute path also works) */
    /* settings on top of the configuration, "key = value" lines (tests,
     * command-line options); local.json's settings still override them */
    const char *overrides;
    int         role;           /* NPF_ROLE_NODE: long running (callable with a number, saved peers,
                                   router port mapping); NPF_ROLE_CLIENT: one-off tasks (account,
                                   devices, a session in the foreground); NPF_ROLE_DIRECT: no platform */
    int         log_level;      /* NPF_LEVEL_*; -1: the configuration's log_level */
    const npf_callbacks *cb;    /* NULL: none; copied by npf_create (cb->user is kept as given) */
    /* The program, told to the platform at login and to the other side of a
     * session: a name of 1..32 of a-z 0-9 . _ - and a version of 1..32
     * printable ASCII characters. NULL: "libnpf" and the library's version. */
    const char *app_name;
    const char *app_ver;
    /* a shared runtime to run on; NULL: a thread of the instance's own. It
     * must outlive the instance. */
    npf_runtime *runtime;
    /* NULL: read conf_dir / conf_file. Given: no configuration file is
     * read; conf_dir and conf_file must be NULL and data_dir set. */
    const npf_setup *setup;
    int          flags;         /* NPF_OPT_* */
} npf_options;

NPF_API const char *npf_version(void);
NPF_API int         npf_api_version(void);
/* The defaults, written for size bytes (the application's sizeof: use the
 * macros), so a newer library never writes past an older structure. */
NPF_API void        npf_options_init_size(npf_options *o, size_t size);
NPF_API void        npf_callbacks_init_size(npf_callbacks *cb, size_t size);
NPF_API void        npf_setup_init_size(npf_setup *s, size_t size);
#define npf_options_init(o)    npf_options_init_size((o), sizeof *(o))
#define npf_callbacks_init(cb) npf_callbacks_init_size((cb), sizeof *(cb))
#define npf_setup_init(s)      npf_setup_init_size((s), sizeof *(s))

/* Makes an instance: reads the configuration and the identity (making
 * data_dir and an identity when there are none), opens the UDP socket and
 * brings back the peers local.json saved. NPF_ROLE_CLIENT never does,
 * by design: a client is a one-off task (one session, an account
 * request) whose peers are the ones it makes; the saved ones are the long
 * running node's, which keeps them connected. NPF_OK with *out set; else
 * *out is NULL and the message is in err. */
NPF_API int  npf_create(const npf_options *o, npf_t **out, char *err, size_t errcap);
/* Runs the instance on a thread of its own (or its runtime's) and returns.
 * NPF_ESTATE: started or stopped before. */
NPF_API int  npf_start(npf_t *n);
/* Runs the instance on the calling thread until the run ends. NPF_ESTATE:
 * started or stopped before, or on a shared runtime. */
NPF_API int  npf_run(npf_t *n);
/* Ends the run: the sessions end, then "stopped". Returns at once. */
NPF_API void npf_stop(npf_t *n);
NPF_API void npf_destroy(npf_t *n);         /* see Threads above; NULL is ignored */
NPF_API void npf_free(void *p);

/* A shared runtime of threads threads (<= 0: one per CPU); NULL: no memory
 * or no thread. npf_runtime_free stops its threads and frees it; NPF_ESTATE
 * while an instance created on it is not destroyed yet. */
NPF_API npf_runtime *npf_runtime_new(int threads);
NPF_API int          npf_runtime_free(npf_runtime *rt);

/* ---- state ---- */

/* identity, server, NAT, peers with their forwards, sessions, the modules' members */
NPF_API char *npf_status_json(npf_t *n);
/* the settings that can change at run time, with their values in effect */
NPF_API char *npf_config_json(npf_t *n);
/* {"lines": the last lines of the log}, up to max bytes (<= 0 or more than
 * 16384: 16384); empty with NPF_OPT_NO_LOG_RING */
NPF_API char *npf_log_json(npf_t *n, int max);
/* A setting in effect, "" when unset; secrets read "(hidden)". NPF_ENOENT:
 * not a configuration key; NPF_ETOOBIG: out is too small. */
NPF_API int   npf_config_get(npf_t *n, const char *key, char *out, size_t cap);
/* Sets a setting; save also writes it to local.json. NPF_OK or NPF_ESAVE:
 * taken, and *restart (NULL: not wanted) says when it applies: 0 now, 1 at
 * the next start (a start-up setting: lost then unless saved). NPF_EINVAL
 * (unknown key, bad value, or only allowed in npf.conf), NPF_EUNAVAIL (save
 * with NPF_OPT_NO_SAVED_SETTINGS); the message in err. */
NPF_API int   npf_config_set(npf_t *n, const char *key, const char *value, int save, int *restart, char *err,
                             size_t errcap);

/* Writes what a failed write left waiting (NPF_ESAVE, npf_node_info.unsaved):
 * local.json, and state.json (a device's pairing and owner). NPF_OK, or
 * NPF_ESAVE again with nothing lost. */
NPF_API int   npf_save(npf_t *n);

/* ---- objects: peers, forwards, resources ----
 * Lists: *count is always the number there is; with too small an array the
 * first cap are filled and NPF_ETOOBIG returned. Creating: NPF_OK and
 * NPF_ESAVE give the new number in *out; any other result gives 0 and makes
 * nothing, except NPF_EEXIST for a peer with the same target, which gives
 * that peer's number (the options given are ignored). With
 * NPF_OPT_NO_SAVED_OBJECTS, NPF_PERSIST is NPF_EUNAVAIL. */

enum { NPF_TARGET_NUMBER = 1,          /* a node on the platform, by its number */
       NPF_TARGET_DIRECT = 2 };        /* HOST:PORT with a pre-shared key, no platform */
enum { NPF_CONNECT_KEEP = 0,           /* connected, again after a drop (with backoff) */
       NPF_CONNECT_ONCE = 1,           /* one session: NPF_PEER_ENDED when it ends */
       NPF_CONNECT_ON_DEMAND = 2 };    /* a session when a forward is used, ended when idle */
enum { NPF_PERSIST = 1,                /* saved in local.json, back at the next start */
       NPF_FIXED = 2,                  /* info only: a resource from npf.conf */
       NPF_PLATFORM = 4 };             /* info only: a peer the library opened for port mappings saved
                                          on the platform (a hosted client's), or one of its forwards */

typedef struct npf_peer_opt {
    size_t         size;               /* set by npf_peer_opt_init */
    int            target;             /* NPF_TARGET_* */
    uint64_t       number;             /* NPF_TARGET_NUMBER */
    const char    *host;               /* NPF_TARGET_DIRECT: an address or name, IPv6 without brackets */
    uint16_t       port;
    const uint8_t *psk;                /* NPF_TARGET_DIRECT: 32 bytes */
    const char    *password;           /* the device's pairing password, the first time; NULL: a pinned
                                          key or the account's grant lets it in */
    int            connect;            /* NPF_CONNECT_*; ON_DEMAND needs NPF_PERSIST, ONCE excludes it */
    int            idle_ms;            /* NPF_CONNECT_ON_DEMAND: the session ends this long after the
                                          last connection; 0: the instance's peer_idle */
    int            flags;              /* NPF_PERSIST */
    const char    *name;               /* a name for it, unique among the peers; NULL: none */
    const char    *nick;               /* what people see; NULL: none */
    void          *ctx;                /* the application's, given back by npf_peer_get */
} npf_peer_opt;

enum { NPF_PEER_IDLE = 0,              /* on demand, no session now */
       NPF_PEER_WAITING,               /* waiting for the platform (not logged in yet) */
       NPF_PEER_CONNECTING,
       NPF_PEER_CONNECTED,
       NPF_PEER_RETRY,                 /* tried again in retry_in_ms */
       NPF_PEER_ENDED };               /* given up: NPF_CONNECT_ONCE ended, or a need below (tried
                                          again by itself once it is met); it stays until removed */
enum { NPF_NEED_PASSWORD = 1,          /* not paired: the user gives the device's password */
       NPF_NEED_PASSWORD_WRONG = 2,    /* the device refused the last one */
       NPF_NEED_PAIRING_LOST = 4,      /* the device forgot the pairing (reset): a password again */
       NPF_NEED_ACCOUNT = 8 };         /* let in through the account: log in again */

typedef struct npf_peer_info {
    int      target;
    uint64_t number;
    char     host[256];
    uint16_t port;
    char     name[NPF_NAME_MAX + 1], nick[NPF_NICK_MAX + 1];
    int      connect;
    int      flags;                    /* NPF_PERSIST, NPF_PLATFORM */
    int      saved;                    /* NPF_PERSIST and its record in local.json is up to date */
    int      state;                    /* NPF_PEER_* */
    int      needs;                    /* NPF_NEED_* */
    int      retry_in_ms;
    int      end_reason;               /* the last session's NPF_END_*; 0: none yet */
    char     why[64];                  /* the same, or why it waits, for people */
    uint32_t session;                  /* the session up now; 0: none */
    int      nforwards;
    void    *ctx;
} npf_peer_info;

NPF_API void npf_peer_opt_init_size(npf_peer_opt *o, size_t size);
#define npf_peer_opt_init(o) npf_peer_opt_init_size((o), sizeof *(o))

/* Adds a peer and starts connecting when running. NPF_EINVAL (bad options,
 * with the message in err), NPF_EEXIST (the target or the name is taken),
 * NPF_EUNAVAIL (no platform with NPF_ROLE_DIRECT, or no peers in this
 * build), NPF_EBUSY (NPF_PEERS_SAVED_MAX). */
NPF_API int npf_peer_create(npf_t *n, const npf_peer_opt *o, uint32_t *peer, char *err, size_t errcap);
/* Ends its session and removes its forwards; a persisted one leaves
 * local.json. NPF_EREADONLY: an NPF_PLATFORM peer. From any callback too. */
NPF_API int npf_peer_remove(npf_t *n, uint32_t peer);
/* by target ("318204776", "host:9000") or name */
NPF_API int npf_peer_find(npf_t *n, const char *target_or_name, uint32_t *peer);
NPF_API int npf_peer_list(npf_t *n, uint32_t *peers, size_t cap, size_t *count);
NPF_API int npf_peer_get_size(npf_t *n, uint32_t peer, npf_peer_info *out, size_t size);
#define npf_peer_get(n, peer, out) npf_peer_get_size((n), (peer), (out), sizeof *(out))
/* Tries now: starts an idle on-demand peer's session, retries a peer
 * waiting for its retry, tries an ended one again. NPF_ESTATE: not running;
 * NPF_EREADONLY: an NPF_PLATFORM peer. */
NPF_API int npf_peer_connect_now(npf_t *n, uint32_t peer);

/* Changes one setting of a peer. Int options: val points to an int, len
 * sizeof(int). Strings: NUL-terminated, len 0; "" removes. CTX: the pointer
 * itself as val, len 0. A wrong len or value, a string too long or an
 * unknown option: NPF_EINVAL, the peer unchanged. A persisted peer is saved
 * after the change (NPF_ESAVE: in effect, not written yet). On an
 * NPF_PLATFORM peer CONNECT, IDLE_MS and PERSIST are NPF_EREADONLY,
 * PASSWORD NPF_EINVAL. */
enum { NPF_PEER_OPT_CONNECT = 1,       /* NPF_CONNECT_*. KEEP connects now if there is no session.
                                          ON_DEMAND needs NPF_PERSIST and no remote forward; the
                                          session goes on and the idle time runs from now. ONCE ends
                                          the peer with its session (at once without one); not for
                                          a persisted peer. */
       NPF_PEER_OPT_IDLE_MS,           /* on demand: ms without a connection before the session
                                          ends, 0..86400000; 0: the instance's peer_idle. Kept for
                                          later when the peer is not on demand. */
       NPF_PEER_OPT_PERSIST,           /* 1: saved now with its forwards (not ONCE). 0: not brought
                                          back at the next start, its forwards leave local.json, its
                                          pinned key and names stay (not ON_DEMAND). */
       NPF_PEER_OPT_NAME,              /* NPF_NAME_MAX; NPF_EEXIST: another peer's */
       NPF_PEER_OPT_NICK,              /* NPF_NICK_MAX */
       NPF_PEER_OPT_CTX,
       NPF_PEER_OPT_PASSWORD };        /* a platform peer not paired yet, or whose password was
                                          refused: tried at once, not kept (NPF_PASSWORD_MAX) */
NPF_API int npf_peer_setopt(npf_t *n, uint32_t peer, int opt, const void *val, size_t len);

enum { NPF_FWD_LOCAL = 1,              /* -L: a port here to a target on the peer's side */
       NPF_FWD_SOCKS = 2,              /* -D: a SOCKS5 proxy here, through the peer */
       NPF_FWD_REMOTE = 3 };           /* -R: a port on the peer to a target here */
enum { NPF_PROTO_TCP = 0, NPF_PROTO_UDP = 1 };

typedef struct npf_endpoint {
    const char *host;                  /* IPv6 without brackets; listen: NULL is 127.0.0.1 */
    uint16_t    port;                  /* listen: 0 is picked (here by the system, for -R by the peer) */
} npf_endpoint;

typedef struct npf_forward_opt {
    size_t       size;                 /* set by npf_forward_opt_init */
    int          kind;                 /* NPF_FWD_* */
    int          proto;                /* NPF_PROTO_*; UDP: LOCAL and REMOTE only */
    npf_endpoint listen;               /* -R: an IP address of the peer or "*"; NULL: 127.0.0.1 */
    npf_endpoint target;               /* NPF_FWD_SOCKS: none */
    int          flags;                /* NPF_PERSIST: saved with its peer, which must be NPF_PERSIST */
    void        *ctx;
} npf_forward_opt;

enum { NPF_FWD_WAITING = 0,            /* for the session (-R: for the peer to listen) */
       NPF_FWD_UP,                     /* listening (here, or on the peer for -R) */
       NPF_FWD_FAILED };               /* why_code says why; tried again with backoff
                                          (NPF_FWD_WHY_FORBIDDEN: with the next session only) */
enum { NPF_FWD_WHY_NONE = 0,
       NPF_FWD_WHY_PORT_IN_USE,        /* the port here is taken */
       NPF_FWD_WHY_BIND,               /* the listen address cannot be bound here */
       NPF_FWD_WHY_FORBIDDEN,          /* -R: the peer's reverse resource does not allow it */
       NPF_FWD_WHY_TOO_MANY,           /* -R: 16 reverse mappings in the session already */
       NPF_FWD_WHY_REQUEST,            /* -R: the request failed or timed out */
       NPF_FWD_WHY_OTHER };            /* why has the text */

typedef struct npf_forward_info {
    uint32_t peer;
    int      kind, proto;
    int      flags, saved;             /* as for peers */
    char     listen_host[64];
    uint16_t listen_port;              /* the port in use (also when 0 was asked); 0: not yet */
    char     target_host[256];
    uint16_t target_port;
    int      state;                    /* NPF_FWD_* */
    int      why_code;                 /* NPF_FWD_FAILED: NPF_FWD_WHY_* */
    char     why[64];
    int      conns;                    /* connections open now */
    uint32_t refused;                  /* connections the peer refused so far (its resources) */
    char     refused_why[64];          /* the last refused one's target */
    void    *ctx;
} npf_forward_info;

NPF_API void npf_forward_opt_init_size(npf_forward_opt *o, size_t size);
#define npf_forward_opt_init(o) npf_forward_opt_init_size((o), sizeof *(o))

/* Adds a forward to a peer. NPF_EFAIL: the port here is taken or the
 * address cannot be bound (nothing is kept); NPF_EBUSY:
 * NPF_PEER_FORWARDS_MAX; NPF_EREADONLY: an NPF_PLATFORM peer; NPF_EINVAL:
 * bad options (also -R on an on-demand peer). The message is in err. */
NPF_API int npf_forward_create(npf_t *n, uint32_t peer, const npf_forward_opt *o, uint32_t *fwd, char *err,
                               size_t errcap);
/* NPF_EREADONLY: a forward of an NPF_PLATFORM peer or of a module */
NPF_API int npf_forward_remove(npf_t *n, uint32_t fwd);
/* peer 0: every peer's */
NPF_API int npf_forward_list(npf_t *n, uint32_t peer, uint32_t *fwds, size_t cap, size_t *count);
NPF_API int npf_forward_get_size(npf_t *n, uint32_t fwd, npf_forward_info *out, size_t size);
#define npf_forward_get(n, fwd, out) npf_forward_get_size((n), (fwd), (out), sizeof *(out))
/* as npf_peer_setopt; NPF_FWD_OPT_CTX: the pointer as val, len 0 */
enum { NPF_FWD_OPT_CTX = 1 };
NPF_API int npf_forward_setopt(npf_t *n, uint32_t fwd, int opt, const void *val, size_t len);

enum { NPF_RES_TCP = 1, NPF_RES_UDP, NPF_RES_NET, NPF_RES_SOCKS, NPF_RES_REVERSE };

/* a resource this node publishes: what its callers may reach through it */
typedef struct npf_resource {
    size_t       size;                 /* set by npf_resource_init */
    int          type;                 /* NPF_RES_* */
    const char  *name;                 /* unique, up to 64 bytes of UTF-8 */
    const char  *svc;                  /* tcp / udp: "http", "https", "rdp", "ssh" ...; NULL: none */
    npf_endpoint service;              /* tcp / udp: an IP address (no brackets) or localhost, and port */
    const char  *rule;                 /* net / socks: "lan", "*", ADDR[/PREFIX][:PORT[-PORT]];
                                          udp without a service host: "*" or ADDR[/PREFIX][:PORT[-PORT]];
                                          reverse: [lan:]"*", PORT or PORT-PORT; up to 63 bytes */
    const char  *path;                 /* a web page: the page to open; NULL: "/" */
    const char  *desc;                 /* up to 256 bytes; NULL: none */
    int          flags;                /* NPF_PERSIST */
} npf_resource;

typedef struct npf_resource_info {
    int      type, flags, saved;       /* flags: NPF_PERSIST, NPF_FIXED */
    char     name[65], svc[16];
    char     host[64];                 /* tcp, udp of one service */
    uint16_t port;
    char     rule[64];                 /* net / socks / reverse, udp of "*" or networks */
    char     path[129], desc[257];
} npf_resource_info;

NPF_API void npf_resource_init_size(npf_resource *r, size_t size);
#define npf_resource_init(r) npf_resource_init_size((r), sizeof *(r))
/* Adds a resource, or replaces the one of that name as given (a persisted
 * one replaced by one without NPF_PERSIST leaves local.json). NPF_EINVAL
 * (the message in err), NPF_EBUSY (NPF_RESOURCES_MAX), NPF_EREADONLY (one
 * from npf.conf). */
NPF_API int npf_resource_put(npf_t *n, const npf_resource *r, char *err, size_t errcap);
/* NPF_ENOENT: none of that name; NPF_EREADONLY: one from npf.conf */
NPF_API int npf_resource_remove(npf_t *n, const char *name);
/* peer 0: this node's; else what that peer published, as last heard */
NPF_API int npf_resource_list_size(npf_t *n, uint32_t peer, npf_resource_info *out, size_t size, size_t cap,
                                   size_t *count);
#define npf_resource_list(n, peer, out, cap, count) \
    npf_resource_list_size((n), (peer), (out), sizeof *(out), (cap), (count))

/* ---- a device's pairing and owner (state.json in data_dir) ----
 * Only for a node with a number, out of safe mode (state.json and its copy
 * damaged: nothing read or changed; npf_status_json's state_damaged): else
 * NPF_ESTATE. NPF_ESAVE: in effect, state.json not written (npf_save). */

NPF_API int npf_pairing_password_get(npf_t *n, char *out, size_t cap);
/* 8 .. NPF_PASSWORD_MAX bytes, else NPF_EINVAL */
NPF_API int npf_pairing_password_set(npf_t *n, const char *password, char *err, size_t errcap);
typedef struct npf_pairing {
    uint8_t key[32];                   /* the caller's public key */
    int64_t since;                     /* Unix time it paired */
} npf_pairing;
NPF_API int npf_pairing_list_size(npf_t *n, npf_pairing *out, size_t size, size_t cap, size_t *count);
#define npf_pairing_list(n, out, cap, count) npf_pairing_list_size((n), (out), sizeof *(out), (cap), (count))
/* key NULL: all of them; NPF_ENOENT: that key is not paired */
NPF_API int npf_pairing_remove(npf_t *n, const uint8_t key[32]);
/* Forgets the owner account here; the platform is told at the next login.
 * The pairings stay. */
NPF_API int npf_owner_reset(npf_t *n);

/* ---- this node, sessions, the network ---- */

enum { NPF_NAT_UNKNOWN = 0, NPF_NAT_EIM, NPF_NAT_ADM, NPF_NAT_APDM };
enum { NPF_PATH_DIRECT = 1, NPF_PATH_UDP_RELAY, NPF_PATH_WS_RELAY };

typedef struct npf_node_info {
    uint64_t number;                   /* 0: none yet */
    int      role;
    int      online;                   /* logged in to the platform */
    int      server;                   /* its id; 0: none */
    uint64_t account_id;               /* the account session; 0: none */
    int      enrolling;                /* a model credential without a number yet */
    int      nat, nat_filtering;       /* NPF_NAT_*: the mapping, the filtering */
    char     public_addr[64];          /* as the probe saw it; "": not known */
    uint16_t udp_port;
    int64_t  started;                  /* Unix time; 0: not running */
    int      peers, sessions;
    int      unsaved;                  /* changes waiting for local.json or state.json (npf_save) */
} npf_node_info;

typedef struct npf_session_info {
    uint32_t peer;                     /* its peer; 0: someone calling here */
    uint64_t number;                   /* the other side's number; 0: none */
    int      outgoing;
    int      path;                     /* NPF_PATH_* */
    char     call_id[40];
} npf_session_info;

NPF_API int npf_node_get_size(npf_t *n, npf_node_info *out, size_t size);
#define npf_node_get(n, out) npf_node_get_size((n), (out), sizeof *(out))
/* This node's identity public key (X25519, the key the platform and peers
 * know it by) in base64url: NPF_KEY_TEXT_LEN characters and a NUL.
 * NPF_ETOOBIG: cap is too small. Works before the run. */
#define NPF_KEY_TEXT_LEN 43
NPF_API int npf_node_key(npf_t *n, char *out, size_t cap);
NPF_API int npf_session_get_size(npf_t *n, uint32_t session, npf_session_info *out, size_t size);
#define npf_session_get(n, session, out) npf_session_get_size((n), (session), (out), sizeof *(out))
NPF_API int npf_session_list(npf_t *n, uint32_t *sessions, size_t cap, size_t *count);
/* The network changed (a VPN up or down, another Wi-Fi): the sockets are
 * opened again and the peers try again. NPF_ESTATE: not running. */
NPF_API int npf_network_changed(npf_t *n);

/* ---- commands and platform requests ---- */

/* Runs a command: libnpf's own ("set KEY VALUE [--no-save]" as
 * npf_config_set, "netcheck" as npf_network_changed) or one of the
 * program's modules (npf/module.h). cb gets the exit code and the output
 * text on the instance's thread, before npf_command returns or later when
 * the platform has answered; an unknown command gives code 2. The
 * arguments are copied. NPF_OK when it runs. */
typedef void (*npf_text_cb)(void *user, int code, const char *text);
NPF_API int npf_command(npf_t *n, int argc, const char *const *argv, npf_text_cb cb, void *user);

/* Sends a request to the platform (signaling.md): any type, marked as an
 * application's; the platform takes only its platform requests so (account_*,
 * device_*, share_*, mapping_*, hosted_* ...: the library's own messages get
 * unsupported_type). data_json is a JSON object or NULL, else NPF_EINVAL.
 * key_proof adds this connection's key proof (account_register,
 * account_login, password_reset_finish, auth_finish, hosted_login). The
 * library keeps the account session the platform reports (event "account").
 * cb gets, on the instance's thread, the whole reply in JSON, or NULL when
 * the connection was lost. NPF_ESTATE: not online. */
typedef void (*npf_reply_cb)(void *user, int ok, const char *reply);
NPF_API int npf_request(npf_t *n, const char *type, const char *data_json, int key_proof, npf_reply_cb cb,
                        void *user);

/* ---- sessions: application data ---- */

/* the sessions up now, a JSON array of the session callback's info objects */
NPF_API char *npf_sessions_json(npf_t *n);
/* A hosted client's public mappings (npf-hosted): {"open": connections
 * open, "closing", "mappings": [{"mapping_id", "port", "listening",
 * "conns"}]}. close != 0: the public ports close now and stay closed; the
 * open connections go on. */
NPF_API char *npf_public_json(npf_t *n, int close);
/* Sends application data to the peer (its data callback): reliable,
 * ordered, ahead of the forwards' data. Up to 16384 bytes per call, else
 * NPF_ETOOBIG. NPF_ESTATE: the session cannot send now. */
NPF_API int   npf_session_send(npf_t *n, uint32_t session, const void *buf, size_t len);

/* ---- sessions: audio / video (AnLiu semi-reliable frame streams) ---- */

typedef struct npf_media_opt {
    size_t size;                /* set by npf_media_opt_init */
    int tag;                    /* the application's stream kind, 0..999 (the peer's media_open gets it) */
    int prio;                   /* 0 (first) .. 3; default 1: ahead of the forwards' data (2) */
    int max_age_ms;             /* a frame not sent this long after npf_media_send is dropped; default 500 */
    int drop_until_key;         /* after a dropped frame, drop the others until a key frame */
    int fec;                    /* -1 automatic (default), 0 off, 1 on */
    int fec_ratio;              /* fixed parity per 100 packets; 0: adaptive (default) */
    int latency_rtt;            /* the receiver may wait this many round trips for a frame; 0: off */
    int rcv_drop_until_key;     /* the peer, receiving: after a lost frame skip to the next key frame */
} npf_media_opt;

typedef struct npf_media_stats {
    uint32_t target_rate;       /* bytes/s the encoder may send over all streams of the session */
    uint32_t srtt_ms, min_rtt_ms;
    uint32_t frames_dropped;    /* sender: too old */
    uint32_t frames_skipped;    /* receiver: skipped over */
    uint32_t fec_recovered;
    uint32_t peer_frame_delay_avg_ms, peer_frame_delay_max_ms;  /* the peer's last report on our frames */
    uint32_t peer_jitter_ms;
    int      capacity_short;    /* the path is slower than the media */
} npf_media_stats;

NPF_API void npf_media_opt_init_size(npf_media_opt *o, size_t size);
#define npf_media_opt_init(o) npf_media_opt_init_size((o), sizeof *(o))
/* Opens a stream of frames to the session's peer, on any path. NPF_ESTATE:
 * the session is not up; NPF_EBUSY: NPF_MEDIA_STREAMS_MAX per instance, or
 * 30 outgoing streams per session. Opening and closing often is cheap. */
NPF_API int npf_media_open(npf_t *n, uint32_t session, const npf_media_opt *o, uint32_t *media);
/* Sends one frame of up to NPF_MEDIA_FRAME_MAX bytes. From another thread
 * the frame is copied and queued and the call does not wait: NPF_OK when
 * queued, NPF_EBUSY when NPF_MEDIA_SEND_QUEUE bytes or 4096 frames wait;
 * later failures only drop the frame. From a callback it is sent at once
 * and errors are returned. */
NPF_API int npf_media_send(npf_t *n, uint32_t media, int flags, const void *frame, size_t len);
NPF_API int npf_media_stats_get_size(npf_t *n, uint32_t media, npf_media_stats *out, size_t size);
#define npf_media_stats_get(n, media, out) npf_media_stats_get_size((n), (media), (out), sizeof *(out))
/* closes a stream, sending or receiving; no media_closed follows */
NPF_API int npf_media_close(npf_t *n, uint32_t media);

#ifdef __cplusplus
}
#endif

#endif

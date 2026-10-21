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
 * the saved server list, and local.conf: settings, peers and port forwards
 * saved at run time, which override and extend npf.conf).
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
    NPF_EBUSY = -8,         /* too many media streams at once */
    NPF_ESAVE = -9          /* done, but local.json could not be written: it is with the next change
                               saved, a restart before that loses it; the message in err */
};

enum { NPF_ROLE_NODE = 0, NPF_ROLE_CLIENT = 1, NPF_ROLE_DIRECT = 2 };
enum { NPF_LEVEL_TRACE = 0, NPF_LEVEL_DEBUG, NPF_LEVEL_INFO, NPF_LEVEL_WARN, NPF_LEVEL_ERROR };
enum { NPF_FRAME_KEY = 1 };
#define NPF_MEDIA_FRAME_MAX (4u << 20)     /* bytes per frame */
#define NPF_MEDIA_SEND_QUEUE (16u << 20)   /* bytes of frames from other threads waiting per instance */

#define NPF_MEDIA_STREAMS_MAX 64          /* sending + receiving, across all sessions of one instance */
#define NPF_MEDIA_WS_FRAME_MAX (2u << 20)  /* WS relay: also the per-stream queue byte limit */

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
    /* events, details in JSON: "online" {server}, "offline" {why}, "enrolled"
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
     * (npf/module.h) */
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
} npf_callbacks;

/* ABI: the structures carry their size and only grow at the end; the
 * library reads what the application's build has and takes the defaults
 * for the rest. Initialise them with the _init / _default functions. */
typedef struct npf_options {
    size_t      size;           /* sizeof(npf_options) of the application's build (npf_options_init) */
    const char *conf_dir;       /* read-only for the library */
    const char *data_dir;       /* writable; NULL: conf_dir */
    const char *conf_file;      /* NULL: "npf.conf" in conf_dir (an absolute path also works) */
    /* settings on top of the configuration, "key = value" lines (tests,
     * command-line options); local.conf still overrides them */
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
} npf_options;

NPF_API const char *npf_version(void);
NPF_API int         npf_api_version(void);
/* the defaults, for size bytes (the application's sizeof: the macros give
 * it), so a library with larger structures never writes past them */
NPF_API void        npf_options_init_size(npf_options *o, size_t size);
NPF_API void        npf_callbacks_init_size(npf_callbacks *cb, size_t size);
#define npf_options_init(o)    npf_options_init_size((o), sizeof *(o))
#define npf_callbacks_init(cb) npf_callbacks_init_size((cb), sizeof *(cb))

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
/* save: also into local.conf (data_dir). NPF_OK: in effect now; 1: saved,
 * in effect at the next start (a start-up setting) */
NPF_API int   npf_config_set(npf_t *n, const char *key, const char *value, int save, char *err, size_t errcap);

/* ---- peers and port forwards ---- */

enum { NPF_PEER_SAVE = 1,       /* keep in local.json, try for ever */
       NPF_PEER_ONCE = 2 };     /* no reconnecting: done when the session ends (event peer_done) */

/* the peer as words: {"NUMBER", "-p", "PASSWORD", "-L", "[BIND:]PORT:HOST:PORT", ...} or
 * {"HOST:PORT", "--psk-file", "FILE", ...} (a direct peer); words may hold spaces */
NPF_API int npf_peer_add_argv(npf_t *n, int argc, const char *const *argv, int flags, char *err, size_t errcap);
/* the same as one line, words separated by spaces (none inside a word) */
NPF_API int npf_peer_add(npf_t *n, const char *spec, int flags, char *err, size_t errcap);
NPF_API int npf_peer_remove(npf_t *n, const char *name, int unsave, char *err, size_t errcap);
/* opt "-L", "-D" or "-R"; save: with the peer in local.conf (the peer must be saved) */
NPF_API int npf_forward_add(npf_t *n, const char *peer, const char *opt, const char *spec, int save, char *err,
                            size_t errcap);
NPF_API int npf_forward_del(npf_t *n, const char *peer, const char *opt, const char *spec, char *err, size_t errcap);

/* ---- commands and platform requests ---- */

/* A command of the command line (status, node, forward, resource, get,
 * set, log, show, passwd, unpair, owner-reset, netcheck, id, ..., and the
 * modules' own): the exit code and output text come to cb, at once or
 * when the platform has answered. NPF_OK when it runs. */
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

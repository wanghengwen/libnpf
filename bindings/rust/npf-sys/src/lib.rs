//! Raw declarations of libnpf's public API (`include/npf.h`, API version 1).
//!
//! Written by hand from the header; `tests/layout.rs` checks every structure's
//! size and field offsets against the C compiler. Use the `npf` crate for a
//! safe interface.
#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};

pub const NPF_API_VERSION: c_int = 1;

#[repr(C)]
pub struct npf_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct npf_runtime {
    _private: [u8; 0],
}

/* return codes */
pub const NPF_OK: c_int = 0;
pub const NPF_EINVAL: c_int = -1;
pub const NPF_ENOENT: c_int = -2;
pub const NPF_ESTATE: c_int = -3;
pub const NPF_EUNAVAIL: c_int = -4;
pub const NPF_ETOOBIG: c_int = -5;
pub const NPF_ENOMEM: c_int = -6;
pub const NPF_EFAIL: c_int = -7;
pub const NPF_EBUSY: c_int = -8;
pub const NPF_ESAVE: c_int = -9;
pub const NPF_EEXIST: c_int = -10;
pub const NPF_EREADONLY: c_int = -11;

/* limits */
pub const NPF_PEER_FORWARDS_MAX: usize = 16;
pub const NPF_RESOURCES_MAX: usize = 32;
pub const NPF_PEERS_SAVED_MAX: usize = 256;
pub const NPF_PAIRINGS_MAX: usize = 256;
pub const NPF_PASSWORD_MAX: usize = 127;
pub const NPF_NAME_MAX: usize = 32;
pub const NPF_NICK_MAX: usize = 128;
pub const NPF_ROOTS_MAX: usize = 2;

pub const NPF_ROLE_NODE: c_int = 0;
pub const NPF_ROLE_CLIENT: c_int = 1;
pub const NPF_ROLE_DIRECT: c_int = 2;

pub const NPF_LEVEL_TRACE: c_int = 0;
pub const NPF_LEVEL_DEBUG: c_int = 1;
pub const NPF_LEVEL_INFO: c_int = 2;
pub const NPF_LEVEL_WARN: c_int = 3;
pub const NPF_LEVEL_ERROR: c_int = 4;

pub const NPF_FRAME_KEY: c_int = 1;
pub const NPF_MEDIA_FRAME_MAX: usize = 4 << 20;
pub const NPF_MEDIA_SEND_QUEUE: usize = 16 << 20;
pub const NPF_MEDIA_STREAMS_MAX: usize = 64;
pub const NPF_CHANNELS_MAX: usize = 64;
pub const NPF_CHANNEL_BUFFER: usize = 2 << 20;

pub const NPF_END_LOCAL: c_int = 1;
pub const NPF_END_PEER: c_int = 2;
pub const NPF_END_LOST: c_int = 3;
pub const NPF_END_REFUSED: c_int = 4;
pub const NPF_END_UNREACHABLE: c_int = 5;
pub const NPF_END_PLATFORM: c_int = 6;
pub const NPF_END_OTHER: c_int = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct npf_frame_info {
    pub frame_no: u32,
    pub flags: c_int,
    pub lost_before: u32,
}

#[repr(C)]
pub struct npf_callbacks {
    pub size: usize,
    pub user: *mut c_void,
    pub log: Option<unsafe extern "C" fn(user: *mut c_void, level: c_int, line: *const c_char)>,
    pub event:
        Option<unsafe extern "C" fn(user: *mut c_void, name: *const c_char, json: *const c_char)>,
    pub session: Option<
        unsafe extern "C" fn(user: *mut c_void, session: u32, up: c_int, info: *const c_char),
    >,
    pub data: Option<
        unsafe extern "C" fn(user: *mut c_void, session: u32, buf: *const c_void, len: usize),
    >,
    pub media_open: Option<
        unsafe extern "C" fn(user: *mut c_void, session: u32, media: u32, tag: c_int) -> c_int,
    >,
    pub media_frame: Option<
        unsafe extern "C" fn(
            user: *mut c_void,
            media: u32,
            buf: *const c_void,
            len: usize,
            fi: *const npf_frame_info,
        ),
    >,
    pub media_closed: Option<unsafe extern "C" fn(user: *mut c_void, media: u32)>,
    pub channel_open: Option<
        unsafe extern "C" fn(user: *mut c_void, session: u32, channel: u32, tag: c_int) -> c_int,
    >,
    pub channel_data: Option<
        unsafe extern "C" fn(user: *mut c_void, channel: u32, buf: *const c_void, len: usize),
    >,
    pub channel_writable: Option<unsafe extern "C" fn(user: *mut c_void, channel: u32)>,
    pub channel_closed: Option<unsafe extern "C" fn(user: *mut c_void, channel: u32)>,
}

#[repr(C)]
pub struct npf_setup {
    pub size: usize,
    pub roots: *const [u8; 32],
    pub nroots: c_int,
    pub serverlist: *const c_void,
    pub serverlist_len: usize,
    pub serverlist_file: *const c_char,
    pub serverlist_saved: *const c_char,
    pub server_url: *const c_char,
    pub server_pub: *const u8,
    pub doh_servers: *const c_char,
    pub cred: *const c_char,
    pub password: *const c_char,
    pub model_cred: *const c_char,
    pub serial: *const c_char,
    pub hw_info: *const c_char,
    pub model: *const c_char,
    pub direct_host: *const c_char,
    pub direct_port: u16,
    pub direct_psk: *const u8,
    pub udp_port: c_int,
    pub no_portmap: c_int,
    pub relays_only: c_int,
    pub max_calls: c_int,
    pub punch_lead_ms: c_int,
    pub punch_sockets: c_int,
    pub no_host_report: c_int,
    pub no_hosted_trust: c_int,
    pub peer_idle_s: c_int,
}

pub const NPF_OPT_NO_SAVED_SETTINGS: c_int = 1;
pub const NPF_OPT_NO_SAVED_OBJECTS: c_int = 2;
pub const NPF_OPT_NO_LOG_RING: c_int = 4;

#[repr(C)]
pub struct npf_options {
    pub size: usize,
    pub conf_dir: *const c_char,
    pub data_dir: *const c_char,
    pub conf_file: *const c_char,
    pub overrides: *const c_char,
    pub role: c_int,
    pub log_level: c_int,
    pub cb: *const npf_callbacks,
    pub app_name: *const c_char,
    pub app_ver: *const c_char,
    pub runtime: *mut npf_runtime,
    pub setup: *const npf_setup,
    pub flags: c_int,
}

pub const NPF_TARGET_NUMBER: c_int = 1;
pub const NPF_TARGET_DIRECT: c_int = 2;
pub const NPF_CONNECT_KEEP: c_int = 0;
pub const NPF_CONNECT_ONCE: c_int = 1;
pub const NPF_CONNECT_ON_DEMAND: c_int = 2;
pub const NPF_PERSIST: c_int = 1;
pub const NPF_FIXED: c_int = 2;
pub const NPF_PLATFORM: c_int = 4;

#[repr(C)]
pub struct npf_peer_opt {
    pub size: usize,
    pub target: c_int,
    pub number: u64,
    pub host: *const c_char,
    pub port: u16,
    pub psk: *const u8,
    pub password: *const c_char,
    pub connect: c_int,
    pub idle_ms: c_int,
    pub flags: c_int,
    pub name: *const c_char,
    pub nick: *const c_char,
    pub ctx: *mut c_void,
}

pub const NPF_PEER_IDLE: c_int = 0;
pub const NPF_PEER_WAITING: c_int = 1;
pub const NPF_PEER_CONNECTING: c_int = 2;
pub const NPF_PEER_CONNECTED: c_int = 3;
pub const NPF_PEER_RETRY: c_int = 4;
pub const NPF_PEER_ENDED: c_int = 5;
pub const NPF_NEED_PASSWORD: c_int = 1;
pub const NPF_NEED_PASSWORD_WRONG: c_int = 2;
pub const NPF_NEED_PAIRING_LOST: c_int = 4;
pub const NPF_NEED_ACCOUNT: c_int = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_peer_info {
    pub target: c_int,
    pub number: u64,
    pub host: [c_char; 256],
    pub port: u16,
    pub name: [c_char; NPF_NAME_MAX + 1],
    pub nick: [c_char; NPF_NICK_MAX + 1],
    pub connect: c_int,
    pub flags: c_int,
    pub saved: c_int,
    pub state: c_int,
    pub needs: c_int,
    pub retry_in_ms: c_int,
    pub end_reason: c_int,
    pub why: [c_char; 64],
    pub session: u32,
    pub nforwards: c_int,
    pub ctx: *mut c_void,
}

pub const NPF_PEER_OPT_CONNECT: c_int = 1;
pub const NPF_PEER_OPT_IDLE_MS: c_int = 2;
pub const NPF_PEER_OPT_PERSIST: c_int = 3;
pub const NPF_PEER_OPT_NAME: c_int = 4;
pub const NPF_PEER_OPT_NICK: c_int = 5;
pub const NPF_PEER_OPT_CTX: c_int = 6;
pub const NPF_PEER_OPT_PASSWORD: c_int = 7;

pub const NPF_FWD_LOCAL: c_int = 1;
pub const NPF_FWD_SOCKS: c_int = 2;
pub const NPF_FWD_REMOTE: c_int = 3;
pub const NPF_PROTO_TCP: c_int = 0;
pub const NPF_PROTO_UDP: c_int = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_endpoint {
    pub host: *const c_char,
    pub port: u16,
}

#[repr(C)]
pub struct npf_forward_opt {
    pub size: usize,
    pub kind: c_int,
    pub proto: c_int,
    pub listen: npf_endpoint,
    pub target: npf_endpoint,
    pub flags: c_int,
    pub ctx: *mut c_void,
}

pub const NPF_FWD_WAITING: c_int = 0;
pub const NPF_FWD_UP: c_int = 1;
pub const NPF_FWD_FAILED: c_int = 2;
pub const NPF_FWD_WHY_NONE: c_int = 0;
pub const NPF_FWD_WHY_PORT_IN_USE: c_int = 1;
pub const NPF_FWD_WHY_BIND: c_int = 2;
pub const NPF_FWD_WHY_FORBIDDEN: c_int = 3;
pub const NPF_FWD_WHY_TOO_MANY: c_int = 4;
pub const NPF_FWD_WHY_REQUEST: c_int = 5;
pub const NPF_FWD_WHY_OTHER: c_int = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_forward_info {
    pub peer: u32,
    pub kind: c_int,
    pub proto: c_int,
    pub flags: c_int,
    pub saved: c_int,
    pub listen_host: [c_char; 64],
    pub listen_port: u16,
    pub target_host: [c_char; 256],
    pub target_port: u16,
    pub state: c_int,
    pub why_code: c_int,
    pub why: [c_char; 64],
    pub conns: c_int,
    pub refused: u32,
    pub refused_why: [c_char; 64],
    pub ctx: *mut c_void,
}

pub const NPF_FWD_OPT_CTX: c_int = 1;

pub const NPF_RES_TCP: c_int = 1;
pub const NPF_RES_UDP: c_int = 2;
pub const NPF_RES_NET: c_int = 3;
pub const NPF_RES_SOCKS: c_int = 4;
pub const NPF_RES_REVERSE: c_int = 5;

#[repr(C)]
pub struct npf_resource {
    pub size: usize,
    pub type_: c_int,
    pub name: *const c_char,
    pub svc: *const c_char,
    pub service: npf_endpoint,
    pub rule: *const c_char,
    pub path: *const c_char,
    pub desc: *const c_char,
    pub flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_resource_info {
    pub type_: c_int,
    pub flags: c_int,
    pub saved: c_int,
    pub name: [c_char; 65],
    pub svc: [c_char; 16],
    pub host: [c_char; 64],
    pub port: u16,
    pub rule: [c_char; 64],
    pub path: [c_char; 129],
    pub desc: [c_char; 257],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct npf_pairing {
    pub key: [u8; 32],
    pub since: i64,
    pub admin: c_int,
}

pub const NPF_SHARES_MAX: usize = 16;
pub const NPF_SHARE_CODE_LEN: usize = 15;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct npf_share_info {
    pub locator: [c_char; 8],
    pub uses: i64,
    pub expires: i64,
}

pub type npf_share_cb = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        rc: c_int,
        code: *const c_char,
        s: *const npf_share_info,
    ),
>;

pub const NPF_NAT_UNKNOWN: c_int = 0;
pub const NPF_NAT_EIM: c_int = 1;
pub const NPF_NAT_ADM: c_int = 2;
pub const NPF_NAT_APDM: c_int = 3;
pub const NPF_PATH_DIRECT: c_int = 1;
pub const NPF_PATH_UDP_RELAY: c_int = 2;
pub const NPF_PATH_WS_RELAY: c_int = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_node_info {
    pub number: u64,
    pub role: c_int,
    pub online: c_int,
    pub server: c_int,
    pub account_id: u64,
    pub enrolling: c_int,
    pub nat: c_int,
    pub nat_filtering: c_int,
    pub public_addr: [c_char; 64],
    pub udp_port: u16,
    pub started: i64,
    pub peers: c_int,
    pub sessions: c_int,
    pub unsaved: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct npf_session_info {
    pub peer: u32,
    pub number: u64,
    pub outgoing: c_int,
    pub path: c_int,
    pub call_id: [c_char; 40],
}

pub const NPF_KEY_TEXT_LEN: usize = 43;

pub type npf_text_cb =
    Option<unsafe extern "C" fn(user: *mut c_void, code: c_int, text: *const c_char)>;
pub type npf_reply_cb =
    Option<unsafe extern "C" fn(user: *mut c_void, ok: c_int, reply: *const c_char)>;

#[repr(C)]
pub struct npf_media_opt {
    pub size: usize,
    pub tag: c_int,
    pub prio: c_int,
    pub max_age_ms: c_int,
    pub drop_until_key: c_int,
    pub fec: c_int,
    pub fec_ratio: c_int,
    pub latency_rtt: c_int,
    pub rcv_drop_until_key: c_int,
}

#[repr(C)]
pub struct npf_channel_opt {
    pub size: usize,
    pub tag: c_int,
    pub prio: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct npf_media_stats {
    pub target_rate: u32,
    pub srtt_ms: u32,
    pub min_rtt_ms: u32,
    pub frames_dropped: u32,
    pub frames_skipped: u32,
    pub fec_recovered: u32,
    pub peer_frame_delay_avg_ms: u32,
    pub peer_frame_delay_max_ms: u32,
    pub peer_jitter_ms: u32,
    pub capacity_short: c_int,
}

extern "C" {
    pub fn npf_version() -> *const c_char;
    pub fn npf_api_version() -> c_int;
    pub fn npf_options_init_size(o: *mut npf_options, size: usize);
    pub fn npf_callbacks_init_size(cb: *mut npf_callbacks, size: usize);
    pub fn npf_setup_init_size(s: *mut npf_setup, size: usize);

    pub fn npf_create(
        o: *const npf_options,
        out: *mut *mut npf_t,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_start(n: *mut npf_t) -> c_int;
    pub fn npf_run(n: *mut npf_t) -> c_int;
    pub fn npf_stop(n: *mut npf_t);
    pub fn npf_destroy(n: *mut npf_t);
    pub fn npf_free(p: *mut c_void);

    pub fn npf_runtime_new(threads: c_int) -> *mut npf_runtime;
    pub fn npf_runtime_free(rt: *mut npf_runtime) -> c_int;

    pub fn npf_status_json(n: *mut npf_t) -> *mut c_char;
    pub fn npf_config_json(n: *mut npf_t) -> *mut c_char;
    pub fn npf_log_json(n: *mut npf_t, max: c_int) -> *mut c_char;
    pub fn npf_config_get(n: *mut npf_t, key: *const c_char, out: *mut c_char, cap: usize)
        -> c_int;
    pub fn npf_config_set(
        n: *mut npf_t,
        key: *const c_char,
        value: *const c_char,
        save: c_int,
        restart: *mut c_int,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_save(n: *mut npf_t) -> c_int;

    pub fn npf_peer_opt_init_size(o: *mut npf_peer_opt, size: usize);
    pub fn npf_peer_create(
        n: *mut npf_t,
        o: *const npf_peer_opt,
        peer: *mut u32,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_peer_remove(n: *mut npf_t, peer: u32) -> c_int;
    pub fn npf_peer_find(n: *mut npf_t, target_or_name: *const c_char, peer: *mut u32) -> c_int;
    pub fn npf_peer_list(n: *mut npf_t, peers: *mut u32, cap: usize, count: *mut usize) -> c_int;
    pub fn npf_peer_get_size(
        n: *mut npf_t,
        peer: u32,
        out: *mut npf_peer_info,
        size: usize,
    ) -> c_int;
    pub fn npf_peer_connect_now(n: *mut npf_t, peer: u32) -> c_int;
    pub fn npf_peer_setopt(
        n: *mut npf_t,
        peer: u32,
        opt: c_int,
        val: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn npf_forward_opt_init_size(o: *mut npf_forward_opt, size: usize);
    pub fn npf_forward_create(
        n: *mut npf_t,
        peer: u32,
        o: *const npf_forward_opt,
        fwd: *mut u32,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_forward_remove(n: *mut npf_t, fwd: u32) -> c_int;
    pub fn npf_forward_list(
        n: *mut npf_t,
        peer: u32,
        fwds: *mut u32,
        cap: usize,
        count: *mut usize,
    ) -> c_int;
    pub fn npf_forward_get_size(
        n: *mut npf_t,
        fwd: u32,
        out: *mut npf_forward_info,
        size: usize,
    ) -> c_int;
    pub fn npf_forward_setopt(
        n: *mut npf_t,
        fwd: u32,
        opt: c_int,
        val: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn npf_resource_init_size(r: *mut npf_resource, size: usize);
    pub fn npf_resource_put(
        n: *mut npf_t,
        r: *const npf_resource,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_resource_remove(n: *mut npf_t, name: *const c_char) -> c_int;
    pub fn npf_resource_list_size(
        n: *mut npf_t,
        peer: u32,
        out: *mut npf_resource_info,
        size: usize,
        cap: usize,
        count: *mut usize,
    ) -> c_int;

    pub fn npf_pairing_password_get(n: *mut npf_t, out: *mut c_char, cap: usize) -> c_int;
    pub fn npf_pairing_password_set(
        n: *mut npf_t,
        password: *const c_char,
        err: *mut c_char,
        errcap: usize,
    ) -> c_int;
    pub fn npf_pairing_list_size(
        n: *mut npf_t,
        out: *mut npf_pairing,
        size: usize,
        cap: usize,
        count: *mut usize,
    ) -> c_int;
    pub fn npf_pairing_remove(n: *mut npf_t, key: *const u8) -> c_int;
    pub fn npf_owner_reset(n: *mut npf_t) -> c_int;
    pub fn npf_share_new(
        n: *mut npf_t,
        uses: c_int,
        ttl_s: i64,
        cb: npf_share_cb,
        user: *mut c_void,
    ) -> c_int;
    pub fn npf_share_list_size(
        n: *mut npf_t,
        out: *mut npf_share_info,
        size: usize,
        cap: usize,
        count: *mut usize,
    ) -> c_int;
    pub fn npf_share_del(n: *mut npf_t, locator: *const c_char) -> c_int;

    pub fn npf_node_get_size(n: *mut npf_t, out: *mut npf_node_info, size: usize) -> c_int;
    pub fn npf_node_key(n: *mut npf_t, out: *mut c_char, cap: usize) -> c_int;
    pub fn npf_session_get_size(
        n: *mut npf_t,
        session: u32,
        out: *mut npf_session_info,
        size: usize,
    ) -> c_int;
    pub fn npf_session_list(
        n: *mut npf_t,
        sessions: *mut u32,
        cap: usize,
        count: *mut usize,
    ) -> c_int;
    pub fn npf_network_changed(n: *mut npf_t) -> c_int;

    pub fn npf_command(
        n: *mut npf_t,
        argc: c_int,
        argv: *const *const c_char,
        cb: npf_text_cb,
        user: *mut c_void,
    ) -> c_int;
    pub fn npf_request(
        n: *mut npf_t,
        type_: *const c_char,
        data_json: *const c_char,
        key_proof: c_int,
        cb: npf_reply_cb,
        user: *mut c_void,
    ) -> c_int;

    pub fn npf_sessions_json(n: *mut npf_t) -> *mut c_char;
    pub fn npf_public_json(n: *mut npf_t, close: c_int) -> *mut c_char;
    pub fn npf_session_send(n: *mut npf_t, session: u32, buf: *const c_void, len: usize) -> c_int;

    pub fn npf_media_opt_init_size(o: *mut npf_media_opt, size: usize);
    pub fn npf_media_open(
        n: *mut npf_t,
        session: u32,
        o: *const npf_media_opt,
        media: *mut u32,
    ) -> c_int;
    pub fn npf_media_send(
        n: *mut npf_t,
        media: u32,
        flags: c_int,
        frame: *const c_void,
        len: usize,
    ) -> c_int;
    pub fn npf_media_stats_get_size(
        n: *mut npf_t,
        media: u32,
        out: *mut npf_media_stats,
        size: usize,
    ) -> c_int;
    pub fn npf_media_close(n: *mut npf_t, media: u32) -> c_int;

    pub fn npf_channel_opt_init_size(o: *mut npf_channel_opt, size: usize);
    pub fn npf_channel_open(
        n: *mut npf_t,
        session: u32,
        o: *const npf_channel_opt,
        channel: *mut u32,
    ) -> c_int;
    pub fn npf_channel_send(n: *mut npf_t, channel: u32, buf: *const c_void, len: usize) -> c_int;
    pub fn npf_channel_pause(n: *mut npf_t, channel: u32, paused: c_int) -> c_int;
    pub fn npf_channel_close(n: *mut npf_t, channel: u32) -> c_int;
}

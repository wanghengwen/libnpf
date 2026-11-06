//! The options, settings and information of npf.h as Rust types.

use crate::cbuf_str;
use npf_sys as sys;
use std::path::PathBuf;
use std::sync::Arc;

/// Bytes per media frame.
pub const MEDIA_FRAME_MAX: usize = sys::NPF_MEDIA_FRAME_MAX;
/// Bytes of frames queued from other threads, per instance.
pub const MEDIA_SEND_QUEUE: usize = sys::NPF_MEDIA_SEND_QUEUE;
/// Media streams, sending and receiving, across all sessions of an instance.
pub const MEDIA_STREAMS_MAX: usize = sys::NPF_MEDIA_STREAMS_MAX;
/// Bytes per [`crate::Instance::session_send`].
pub const SESSION_SEND_MAX: usize = 16384;
/// Channels, opened here or by peers, across all sessions of an instance.
pub const CHANNELS_MAX: usize = sys::NPF_CHANNELS_MAX;
/// Bytes a channel holds unacknowledged before [`crate::Instance::channel_send`]
/// is refused ([`crate::ErrorKind::Busy`]); also the most one call sends.
pub const CHANNEL_BUFFER: usize = sys::NPF_CHANNEL_BUFFER;

macro_rules! id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        /// Never reused while the instance lives.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}
id!(/// A peer.
    PeerId);
id!(/// A forward of a peer.
    ForwardId);
id!(/// A session with a peer.
    SessionId);
id!(/// A media stream, sending or receiving.
    MediaId);
id!(/// A channel: a reliable byte stream both sides send on.
    ChannelId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum Level {
    Trace = sys::NPF_LEVEL_TRACE,
    Debug = sys::NPF_LEVEL_DEBUG,
    Info = sys::NPF_LEVEL_INFO,
    Warn = sys::NPF_LEVEL_WARN,
    Error = sys::NPF_LEVEL_ERROR,
}
impl Level {
    pub(crate) fn from_raw(l: i32) -> Level {
        match l {
            sys::NPF_LEVEL_TRACE => Level::Trace,
            sys::NPF_LEVEL_DEBUG => Level::Debug,
            sys::NPF_LEVEL_INFO => Level::Info,
            sys::NPF_LEVEL_WARN => Level::Warn,
            _ => Level::Error,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum Role {
    /// long running: callable with a number, saved peers, router port mapping
    #[default]
    Node = sys::NPF_ROLE_NODE,
    /// one-off tasks: account requests, a session in the foreground
    Client = sys::NPF_ROLE_CLIENT,
    /// no platform: direct peers with a pre-shared key
    Direct = sys::NPF_ROLE_DIRECT,
}

/// `npf_options` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Flags(pub i32);
impl Flags {
    pub const NO_SAVED_SETTINGS: Flags = Flags(sys::NPF_OPT_NO_SAVED_SETTINGS);
    pub const NO_SAVED_OBJECTS: Flags = Flags(sys::NPF_OPT_NO_SAVED_OBJECTS);
    pub const NO_LOG_RING: Flags = Flags(sys::NPF_OPT_NO_LOG_RING);
}
impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, o: Flags) -> Flags {
        Flags(self.0 | o.0)
    }
}

/// How to make an instance (`npf_options`).
#[derive(Clone, Default)]
pub struct Options {
    /// read only: npf.conf and what it names; must be `None` with `setup`
    pub conf_dir: Option<PathBuf>,
    /// written: identity, number, pairing state, local.json; `None`: conf_dir
    pub data_dir: Option<PathBuf>,
    /// `None`: npf.conf in conf_dir
    pub conf_file: Option<PathBuf>,
    /// "key = value" settings on top of the configuration
    pub overrides: Vec<String>,
    pub role: Role,
    /// `None`: the configuration's log_level
    pub log_level: Option<Level>,
    /// the program, told to the platform and to peers: 1..32 of a-z 0-9 . _ -
    pub app_name: Option<String>,
    pub app_ver: Option<String>,
    /// a shared runtime; `None`: a thread of the instance's own
    pub runtime: Option<Arc<crate::Runtime>>,
    /// the configuration as fields instead of npf.conf
    pub setup: Option<Setup>,
    pub flags: Flags,
}

impl Options {
    pub fn new(role: Role) -> Self {
        Options {
            role,
            ..Default::default()
        }
    }
    /// A direct instance without a platform or configuration file, keeping
    /// its state in `data_dir` and listening on `listen` (port 0: none) with
    /// the pre-shared key.
    pub fn direct(
        data_dir: impl Into<PathBuf>,
        listen: Option<(&str, u16)>,
        psk: [u8; 32],
    ) -> Self {
        let mut s = Setup::default();
        if let Some((host, port)) = listen {
            s.direct_host = Some(host.to_owned());
            s.direct_port = port;
            s.direct_psk = Some(psk);
        }
        Options {
            role: Role::Direct,
            data_dir: Some(data_dir.into()),
            setup: Some(s),
            ..Default::default()
        }
    }
}

/// The configuration as fields (`npf_setup`); each is the npf.conf key of
/// the same meaning, other keys go in [`Options::overrides`]. The default is
/// the library's (`punch_lead_ms` -1, the rest empty or 0).
#[derive(Clone, Debug)]
pub struct Setup {
    /// the platform's root public keys, 1 or 2
    pub roots: Vec<[u8; 32]>,
    /// the signed server list shipped with the program, or `serverlist_file`
    pub serverlist: Option<Vec<u8>>,
    pub serverlist_file: Option<String>,
    /// where lists the platform sends are kept; `None`: data_dir; "": not kept
    pub serverlist_saved: Option<String>,
    /// tests: this one server with its key instead of the list
    pub server_url: Option<String>,
    pub server_pub: Option<[u8; 32]>,
    /// tests: "IP:PORT=HOST,..." instead of the public DoH services
    pub doh_servers: Option<String>,
    /// a device's credential "NPFD1..." with its default pairing password
    pub cred: Option<String>,
    pub password: Option<String>,
    /// a model's credential "NPFV2...": the device enrols at its first start
    pub model_cred: Option<String>,
    pub serial: Option<String>,
    pub hw_info: Option<String>,
    pub model: Option<String>,
    /// listen for direct peers (port 0: no listener), with the key
    pub direct_host: Option<String>,
    pub direct_port: u16,
    pub direct_psk: Option<[u8; 32]>,
    /// the main UDP port; 0: any
    pub udp_port: i32,
    pub no_portmap: bool,
    pub relays_only: bool,
    /// sessions accepted at once; 0: 32
    pub max_calls: i32,
    /// -1: automatic
    pub punch_lead_ms: i32,
    /// 0: automatic
    pub punch_sockets: i32,
    pub no_host_report: bool,
    pub no_hosted_trust: bool,
    /// idle time of on-demand peers; 0: 300 s
    pub peer_idle_s: i32,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            roots: Vec::new(),
            serverlist: None,
            serverlist_file: None,
            serverlist_saved: None,
            server_url: None,
            server_pub: None,
            doh_servers: None,
            cred: None,
            password: None,
            model_cred: None,
            serial: None,
            hw_info: None,
            model: None,
            direct_host: None,
            direct_port: 0,
            direct_psk: None,
            udp_port: 0,
            no_portmap: false,
            relays_only: false,
            max_calls: 0,
            punch_lead_ms: -1,
            punch_sockets: 0,
            no_host_report: false,
            no_hosted_trust: false,
            peer_idle_s: 0,
        }
    }
}

/* ---- peers ---- */

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// a node on the platform
    Number(u64),
    /// HOST:PORT with a pre-shared key, no platform
    Direct {
        host: String,
        port: u16,
        psk: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum Connect {
    /// connected, again after a drop (with backoff)
    #[default]
    Keep = sys::NPF_CONNECT_KEEP,
    /// one session; the peer ends with it
    Once = sys::NPF_CONNECT_ONCE,
    /// a session when a forward is used, ended when idle (needs persist)
    OnDemand = sys::NPF_CONNECT_ON_DEMAND,
}

#[derive(Clone, Debug)]
pub struct PeerOpt {
    pub target: Target,
    /// the device's pairing password, the first time
    pub password: Option<String>,
    pub connect: Connect,
    /// on demand: ms without a connection before the session ends; 0: default
    pub idle_ms: i32,
    /// saved in local.json, back at the next start
    pub persist: bool,
    pub name: Option<String>,
    pub nick: Option<String>,
}
impl PeerOpt {
    pub fn new(target: Target) -> Self {
        PeerOpt {
            target,
            password: None,
            connect: Connect::Keep,
            idle_ms: 0,
            persist: false,
            name: None,
            nick: None,
        }
    }
}

/// One setting of a peer ([`crate::Instance::peer_set`]).
#[derive(Clone, Copy, Debug)]
pub enum PeerSetting<'a> {
    Connect(Connect),
    IdleMs(i32),
    Persist(bool),
    Name(&'a str),
    Nick(&'a str),
    /// tried at once, not kept
    Password(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Idle,
    Waiting,
    Connecting,
    Connected,
    Retry,
    Ended,
    Other(i32),
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub target: i32,
    pub number: u64,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub nick: String,
    pub connect: i32,
    pub persist: bool,
    pub platform: bool,
    pub saved: bool,
    pub state: PeerState,
    /// `NEED_*` bits
    pub needs: i32,
    pub retry_in_ms: i32,
    /// the last session's `NPF_END_*`; 0: none yet
    pub end_reason: i32,
    pub why: String,
    pub session: Option<crate::SessionId>,
    pub nforwards: i32,
}
impl PeerInfo {
    pub const NEED_PASSWORD: i32 = sys::NPF_NEED_PASSWORD;
    pub const NEED_PASSWORD_WRONG: i32 = sys::NPF_NEED_PASSWORD_WRONG;
    pub const NEED_PAIRING_LOST: i32 = sys::NPF_NEED_PAIRING_LOST;
    pub const NEED_ACCOUNT: i32 = sys::NPF_NEED_ACCOUNT;

    pub(crate) fn from_raw(i: &sys::npf_peer_info) -> Self {
        PeerInfo {
            target: i.target,
            number: i.number,
            host: cbuf_str(&i.host),
            port: i.port,
            name: cbuf_str(&i.name),
            nick: cbuf_str(&i.nick),
            connect: i.connect,
            persist: i.flags & sys::NPF_PERSIST != 0,
            platform: i.flags & sys::NPF_PLATFORM != 0,
            saved: i.saved != 0,
            state: match i.state {
                sys::NPF_PEER_IDLE => PeerState::Idle,
                sys::NPF_PEER_WAITING => PeerState::Waiting,
                sys::NPF_PEER_CONNECTING => PeerState::Connecting,
                sys::NPF_PEER_CONNECTED => PeerState::Connected,
                sys::NPF_PEER_RETRY => PeerState::Retry,
                sys::NPF_PEER_ENDED => PeerState::Ended,
                s => PeerState::Other(s),
            },
            needs: i.needs,
            retry_in_ms: i.retry_in_ms,
            end_reason: i.end_reason,
            why: cbuf_str(&i.why),
            session: (i.session != 0).then_some(crate::SessionId(i.session)),
            nforwards: i.nforwards,
        }
    }
}

/* ---- forwards ---- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ForwardKind {
    /// -L: a port here to a target on the peer's side
    Local = sys::NPF_FWD_LOCAL,
    /// -D: a SOCKS5 proxy here, through the peer
    Socks = sys::NPF_FWD_SOCKS,
    /// -R: a port on the peer to a target here
    Remote = sys::NPF_FWD_REMOTE,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum Proto {
    #[default]
    Tcp = sys::NPF_PROTO_TCP,
    Udp = sys::NPF_PROTO_UDP,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// IPv6 without brackets; listen: `None` is 127.0.0.1
    pub host: Option<String>,
    /// listen: 0 is picked
    pub port: u16,
}
impl Endpoint {
    pub fn new(host: &str, port: u16) -> Self {
        Endpoint {
            host: Some(host.to_owned()),
            port,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ForwardOpt {
    pub kind: ForwardKind,
    pub proto: Proto,
    pub listen: Endpoint,
    /// Socks: none
    pub target: Endpoint,
    /// saved with its peer (which must persist)
    pub persist: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Waiting,
    Up,
    Failed,
    Other(i32),
}

#[derive(Clone, Debug)]
pub struct ForwardInfo {
    pub peer: crate::PeerId,
    pub kind: i32,
    pub proto: i32,
    pub persist: bool,
    pub saved: bool,
    pub listen_host: String,
    /// the port in use; 0: not yet
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub state: ForwardState,
    /// `NPF_FWD_WHY_*`
    pub why_code: i32,
    pub why: String,
    pub conns: i32,
    pub refused: u32,
    pub refused_why: String,
}
impl ForwardInfo {
    pub(crate) fn from_raw(i: &sys::npf_forward_info) -> Self {
        ForwardInfo {
            peer: crate::PeerId(i.peer),
            kind: i.kind,
            proto: i.proto,
            persist: i.flags & sys::NPF_PERSIST != 0,
            saved: i.saved != 0,
            listen_host: cbuf_str(&i.listen_host),
            listen_port: i.listen_port,
            target_host: cbuf_str(&i.target_host),
            target_port: i.target_port,
            state: match i.state {
                sys::NPF_FWD_WAITING => ForwardState::Waiting,
                sys::NPF_FWD_UP => ForwardState::Up,
                sys::NPF_FWD_FAILED => ForwardState::Failed,
                s => ForwardState::Other(s),
            },
            why_code: i.why_code,
            why: cbuf_str(&i.why),
            conns: i.conns,
            refused: i.refused,
            refused_why: cbuf_str(&i.refused_why),
        }
    }
}

/* ---- resources ---- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ResourceKind {
    Tcp = sys::NPF_RES_TCP,
    Udp = sys::NPF_RES_UDP,
    Net = sys::NPF_RES_NET,
    Socks = sys::NPF_RES_SOCKS,
    Reverse = sys::NPF_RES_REVERSE,
}

/// A resource this node publishes: what its callers may reach through it.
#[derive(Clone, Debug)]
pub struct Resource {
    pub kind: ResourceKind,
    pub name: String,
    /// tcp / udp: "http", "https", "rdp", "ssh" ...
    pub svc: Option<String>,
    /// tcp / udp: an IP address or localhost, and port
    pub service: Endpoint,
    /// net / socks / reverse / udp without a host: "lan", "*", ADDR[/PREFIX][:PORT[-PORT]] ...
    pub rule: Option<String>,
    pub path: Option<String>,
    pub desc: Option<String>,
    pub persist: bool,
}

#[derive(Clone, Debug)]
pub struct ResourceInfo {
    pub kind: i32,
    pub persist: bool,
    /// from npf.conf
    pub fixed: bool,
    pub saved: bool,
    pub name: String,
    pub svc: String,
    pub host: String,
    pub port: u16,
    pub rule: String,
    pub path: String,
    pub desc: String,
}
impl ResourceInfo {
    pub(crate) fn from_raw(i: &sys::npf_resource_info) -> Self {
        ResourceInfo {
            kind: i.type_,
            persist: i.flags & sys::NPF_PERSIST != 0,
            fixed: i.flags & sys::NPF_FIXED != 0,
            saved: i.saved != 0,
            name: cbuf_str(&i.name),
            svc: cbuf_str(&i.svc),
            host: cbuf_str(&i.host),
            port: i.port,
            rule: cbuf_str(&i.rule),
            path: cbuf_str(&i.path),
            desc: cbuf_str(&i.desc),
        }
    }
}

/* ---- pairing, node, sessions ---- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    /// the caller's public key
    pub key: [u8; 32],
    /// Unix time it paired
    pub since: i64,
    /// paired with the password (an admin), not a share code (a member)
    pub admin: bool,
}

/// A live share code of this device (its whole code is told only when made).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareInfo {
    /// the code's first group: the platform finds the device by it
    pub locator: String,
    /// pairings left
    pub uses: i64,
    /// Unix time
    pub expires: i64,
}

impl ShareInfo {
    pub(crate) fn from_raw(s: &sys::npf_share_info) -> Self {
        ShareInfo {
            locator: cbuf_str(&s.locator),
            uses: s.uses,
            expires: s.expires,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nat {
    Unknown,
    /// endpoint-independent
    Eim,
    /// address-dependent
    Adm,
    /// address and port dependent
    Apdm,
}
impl Nat {
    fn from_raw(v: i32) -> Nat {
        match v {
            sys::NPF_NAT_EIM => Nat::Eim,
            sys::NPF_NAT_ADM => Nat::Adm,
            sys::NPF_NAT_APDM => Nat::Apdm,
            _ => Nat::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    /// `None`: no number yet
    pub number: Option<u64>,
    pub role: i32,
    pub online: bool,
    pub server: i32,
    pub account_id: Option<u64>,
    pub enrolling: bool,
    pub nat: Nat,
    pub nat_filtering: Nat,
    pub public_addr: String,
    pub udp_port: u16,
    /// Unix time; 0: not running
    pub started: i64,
    pub peers: i32,
    pub sessions: i32,
    /// changes waiting for local.json or state.json ([`crate::Instance::save`])
    pub unsaved: bool,
}
impl NodeInfo {
    pub(crate) fn from_raw(i: &sys::npf_node_info) -> Self {
        NodeInfo {
            number: (i.number != 0).then_some(i.number),
            role: i.role,
            online: i.online != 0,
            server: i.server,
            account_id: (i.account_id != 0).then_some(i.account_id),
            enrolling: i.enrolling != 0,
            nat: Nat::from_raw(i.nat),
            nat_filtering: Nat::from_raw(i.nat_filtering),
            public_addr: cbuf_str(&i.public_addr),
            udp_port: i.udp_port,
            started: i.started,
            peers: i.peers,
            sessions: i.sessions,
            unsaved: i.unsaved != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPath {
    Direct,
    UdpRelay,
    WsRelay,
    Other(i32),
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    /// its peer; `None`: someone calling here
    pub peer: Option<crate::PeerId>,
    /// the other side's number
    pub number: Option<u64>,
    pub outgoing: bool,
    pub path: SessionPath,
    pub call_id: String,
}
impl SessionInfo {
    pub(crate) fn from_raw(i: &sys::npf_session_info) -> Self {
        SessionInfo {
            peer: (i.peer != 0).then_some(crate::PeerId(i.peer)),
            number: (i.number != 0).then_some(i.number),
            outgoing: i.outgoing != 0,
            path: match i.path {
                sys::NPF_PATH_DIRECT => SessionPath::Direct,
                sys::NPF_PATH_UDP_RELAY => SessionPath::UdpRelay,
                sys::NPF_PATH_WS_RELAY => SessionPath::WsRelay,
                p => SessionPath::Other(p),
            },
            call_id: cbuf_str(&i.call_id),
        }
    }
}

/* ---- media ---- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fec {
    Auto,
    Off,
    On,
}

/// A media stream's options (`npf_media_opt`). [`MediaOpt::new`] has the
/// library's defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaOpt {
    /// the application's stream kind, 0..999 (the peer's `media_open` gets it)
    pub tag: i32,
    /// 0 (first) .. 3; default 1, ahead of the forwards' data (2)
    pub prio: i32,
    /// a frame not sent this long after `media_send` is dropped; default 500
    pub max_age_ms: i32,
    /// after a dropped frame, drop the others until a key frame
    pub drop_until_key: bool,
    pub fec: Fec,
    /// fixed parity per 100 packets; 0: adaptive
    pub fec_ratio: i32,
    /// the receiver may wait this many round trips for a frame; 0: off
    pub latency_rtt: i32,
    /// the peer, receiving: after a lost frame skip to the next key frame
    pub rcv_drop_until_key: bool,
}

impl MediaOpt {
    pub fn new(tag: i32) -> Self {
        let mut o: sys::npf_media_opt = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_media_opt_init_size(&mut o, std::mem::size_of::<sys::npf_media_opt>()) };
        MediaOpt {
            tag,
            prio: o.prio,
            max_age_ms: o.max_age_ms,
            drop_until_key: o.drop_until_key != 0,
            fec: match o.fec {
                0 => Fec::Off,
                1 => Fec::On,
                _ => Fec::Auto,
            },
            fec_ratio: o.fec_ratio,
            latency_rtt: o.latency_rtt,
            rcv_drop_until_key: o.rcv_drop_until_key != 0,
        }
    }
    pub(crate) fn to_raw(self) -> sys::npf_media_opt {
        let mut o: sys::npf_media_opt = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_media_opt_init_size(&mut o, std::mem::size_of::<sys::npf_media_opt>()) };
        o.tag = self.tag;
        o.prio = self.prio;
        o.max_age_ms = self.max_age_ms;
        o.drop_until_key = self.drop_until_key as i32;
        o.fec = match self.fec {
            Fec::Auto => -1,
            Fec::Off => 0,
            Fec::On => 1,
        };
        o.fec_ratio = self.fec_ratio;
        o.latency_rtt = self.latency_rtt;
        o.rcv_drop_until_key = self.rcv_drop_until_key as i32;
        o
    }
}

/// A channel's options (`npf_channel_opt`). [`ChannelOpt::new`] has the
/// library's defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelOpt {
    /// the application's channel kind, 0..999 (the peer's `channel_open` gets it)
    pub tag: i32,
    /// 0 (first) .. 3; default 2, with the forwards' data
    pub prio: i32,
}

impl ChannelOpt {
    pub fn new(tag: i32) -> Self {
        let mut o: sys::npf_channel_opt = unsafe { std::mem::zeroed() };
        unsafe {
            sys::npf_channel_opt_init_size(&mut o, std::mem::size_of::<sys::npf_channel_opt>())
        };
        ChannelOpt { tag, prio: o.prio }
    }
    pub(crate) fn to_raw(self) -> sys::npf_channel_opt {
        let mut o: sys::npf_channel_opt = unsafe { std::mem::zeroed() };
        unsafe {
            sys::npf_channel_opt_init_size(&mut o, std::mem::size_of::<sys::npf_channel_opt>())
        };
        o.tag = self.tag;
        o.prio = self.prio;
        o
    }
}

/// A received frame's place in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    /// from 0, per stream
    pub frame_no: u32,
    pub key: bool,
    /// frames lost since the last one delivered
    pub lost_before: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaStats {
    /// bytes/s the encoder may send over all streams of the session
    pub target_rate: u32,
    pub srtt_ms: u32,
    pub min_rtt_ms: u32,
    /// sender: too old
    pub frames_dropped: u32,
    /// receiver: skipped over
    pub frames_skipped: u32,
    pub fec_recovered: u32,
    /// the peer's last report on our frames
    pub peer_frame_delay_avg_ms: u32,
    pub peer_frame_delay_max_ms: u32,
    pub peer_jitter_ms: u32,
    /// the path is slower than the media
    pub capacity_short: bool,
}
impl MediaStats {
    pub(crate) fn from_raw(s: &sys::npf_media_stats) -> Self {
        MediaStats {
            target_rate: s.target_rate,
            srtt_ms: s.srtt_ms,
            min_rtt_ms: s.min_rtt_ms,
            frames_dropped: s.frames_dropped,
            frames_skipped: s.frames_skipped,
            fec_recovered: s.fec_recovered,
            peer_frame_delay_avg_ms: s.peer_frame_delay_avg_ms,
            peer_frame_delay_max_ms: s.peer_frame_delay_max_ms,
            peer_jitter_ms: s.peer_jitter_ms,
            capacity_short: s.capacity_short != 0,
        }
    }
}

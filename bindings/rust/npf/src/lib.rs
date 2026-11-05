//! Safe Rust interface to libnpf (`npf.h`).
//!
//! An [`Npf`] is one instance: an identity with its own event-loop thread
//! (or a thread of a shared [`Runtime`]). It makes sessions to peers, direct
//! when it can and relayed when it cannot, and carries in each session
//! reliable application data ([`Instance::session_send`]), port forwards and
//! media frame streams ([`Instance::media_open`]): semi-reliable AnLiu streams
//! that drop late frames, skip to the next key frame and tell the sender the
//! rate the path takes ([`MediaStats::target_rate`]).
//!
//! Events come to a [`Handler`] on the instance's thread, one at a time. A
//! handler method gets the [`Instance`] and may call any of its functions; it
//! must return soon.
//!
//! Every function may be called from any thread. While the instance runs, a
//! call runs on its thread and waits for it ([`Instance::media_send`] only
//! queues).
//!
//! `NPF_ESAVE` (done and in effect, but `local.json` or `state.json` could not
//! be written) is not an error here: the call returns `Ok`, and
//! [`NodeInfo::unsaved`] and [`Instance::save`] tell and retry the write.

use npf_sys as sys;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::mem::ManuallyDrop;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;

mod types;
pub use types::*;

/* ---------------- errors ---------------- */

/// What went wrong, from libnpf's return codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// a bad argument
    Invalid,
    /// no such peer, forward, resource, session or stream
    NotFound,
    /// not now: not started, not online, the session not up, the run ended
    State,
    /// not in this build, role or with these options
    Unavailable,
    /// the input or the output is too large
    TooBig,
    NoMemory,
    /// another failure, see the message
    Failed,
    /// a limit is reached (streams, forwards, a queue)
    Busy,
    /// already there (a peer with this target, a name taken)
    Exists,
    /// set by npf.conf or the platform
    ReadOnly,
    /// a code this crate does not know
    Other(i32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// libnpf's message, when the function gives one
    pub message: Option<String>,
}

impl Error {
    fn new(kind: ErrorKind) -> Self {
        Error {
            kind,
            message: None,
        }
    }
    fn from_code(rc: c_int, err: &[c_char]) -> Self {
        let kind = match rc {
            sys::NPF_EINVAL => ErrorKind::Invalid,
            sys::NPF_ENOENT => ErrorKind::NotFound,
            sys::NPF_ESTATE => ErrorKind::State,
            sys::NPF_EUNAVAIL => ErrorKind::Unavailable,
            sys::NPF_ETOOBIG => ErrorKind::TooBig,
            sys::NPF_ENOMEM => ErrorKind::NoMemory,
            sys::NPF_EFAIL => ErrorKind::Failed,
            sys::NPF_EBUSY => ErrorKind::Busy,
            sys::NPF_EEXIST => ErrorKind::Exists,
            sys::NPF_EREADONLY => ErrorKind::ReadOnly,
            c => ErrorKind::Other(c),
        };
        let message = cbuf_str(err);
        Error {
            kind,
            message: (!message.is_empty()).then_some(message),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(m) => write!(f, "{:?}: {m}", self.kind),
            None => write!(f, "{:?}", self.kind),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

const ERRCAP: usize = 512;

fn check(rc: c_int) -> Result<()> {
    check_msg(rc, &[])
}
fn check_msg(rc: c_int, err: &[c_char]) -> Result<()> {
    match rc {
        sys::NPF_OK | sys::NPF_ESAVE => Ok(()),
        rc => Err(Error::from_code(rc, err)),
    }
}

/* ---------------- strings ---------------- */

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error {
        kind: ErrorKind::Invalid,
        message: Some("a NUL byte in a string".into()),
    })
}
fn opt_cstr(s: Option<&str>) -> Result<Option<CString>> {
    s.map(cstr).transpose()
}
fn path_cstr(p: &Path) -> Result<CString> {
    // libnpf takes UTF-8 paths on every system
    cstr(p.to_str().ok_or(Error {
        kind: ErrorKind::Invalid,
        message: Some("a path that is not UTF-8".into()),
    })?)
}
fn ptr_of(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(ptr::null(), |c| c.as_ptr())
}
fn cbuf_str(b: &[c_char]) -> String {
    let bytes: Vec<u8> = b
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
unsafe fn lent_str<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        ""
    } else {
        // libnpf's text is UTF-8; a bad byte would only come from a peer's data
        CStr::from_ptr(p).to_str().unwrap_or("")
    }
}
/// Text the library allocated: copied and freed.
unsafe fn owned_text(p: *mut c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::new(ErrorKind::State));
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    sys::npf_free(p.cast());
    Ok(s)
}

/// Calls f with a growing buffer until the text fits.
fn text_out(mut f: impl FnMut(*mut c_char, usize) -> c_int) -> Result<String> {
    let mut cap = 256;
    loop {
        let mut buf = vec![0 as c_char; cap];
        match f(buf.as_mut_ptr(), cap) {
            sys::NPF_ETOOBIG if cap < 1 << 20 => cap *= 4,
            rc => return check(rc).map(|_| cbuf_str(&buf)),
        }
    }
}

/// A list: count first, then the items (again if more came meanwhile).
fn list_out<T: Clone>(
    zero: T,
    mut f: impl FnMut(*mut T, usize, &mut usize) -> c_int,
) -> Result<Vec<T>> {
    let mut count = 0usize;
    let rc = f(ptr::null_mut(), 0, &mut count);
    if rc != sys::NPF_OK && rc != sys::NPF_ETOOBIG {
        check(rc)?;
    }
    loop {
        let mut v = vec![zero.clone(); count.max(1)];
        let cap = v.len();
        match f(v.as_mut_ptr(), cap, &mut count) {
            sys::NPF_ETOOBIG => continue,
            rc => {
                check(rc)?;
                v.truncate(count.min(cap));
                return Ok(v);
            }
        }
    }
}

/* ---------------- version ---------------- */

/// The library's version text.
pub fn version() -> &'static str {
    unsafe { lent_str(sys::npf_version()) }
}
/// The API version of the library linked (this crate is written for 1).
pub fn api_version() -> i32 {
    unsafe { sys::npf_api_version() }
}

/* ---------------- shared runtime ---------------- */

/// A few threads that run many instances (each instance stays on one of
/// them). On these threads a handler must not block; a call for an instance
/// on another of its threads fails with [`ErrorKind::State`], and
/// [`Instance::run`] is not available.
pub struct Runtime {
    raw: ptr::NonNull<sys::npf_runtime>,
}
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    /// `threads <= 0`: one per CPU.
    pub fn new(threads: i32) -> Result<Arc<Runtime>> {
        let raw = unsafe { sys::npf_runtime_new(threads) };
        ptr::NonNull::new(raw)
            .map(|raw| Arc::new(Runtime { raw }))
            .ok_or(Error::new(ErrorKind::NoMemory))
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        // every instance holds an Arc: none is left here
        unsafe { sys::npf_runtime_free(self.raw.as_ptr()) };
    }
}

/* ---------------- the handler ---------------- */

/// What the application hears from an instance. Every method has a default:
/// log lines go to stderr, the rest is ignored, peers' media streams are
/// refused.
#[allow(unused_variables)]
pub trait Handler: Send + Sync + 'static {
    /// A log line ("date time level message"). It may also come from the
    /// thread of [`Npf::new`] while the instance is made.
    fn log(&self, level: Level, line: &str) {
        eprintln!("{line}");
    }
    /// An event with its details in JSON (npf.h lists them): "online",
    /// "offline", "peer_done", "forward", "network", "resources", "stopped" ...
    fn event(&self, npf: &Instance, name: &str, json: &str) {}
    /// A session came up or ended; `info` is its JSON (see npf.h).
    fn session(&self, npf: &Instance, session: SessionId, up: bool, info: &str) {}
    /// Application data from the session's peer.
    fn data(&self, npf: &Instance, session: SessionId, data: &[u8]) {}
    /// The peer opened a media stream with its tag: true takes it.
    fn media_open(&self, npf: &Instance, session: SessionId, media: MediaId, tag: i32) -> bool {
        false
    }
    /// A frame of a stream taken in `media_open`.
    fn media_frame(&self, npf: &Instance, media: MediaId, frame: &[u8], info: FrameInfo) {}
    /// A stream ended: the peer closed it or its session ended (not after
    /// [`Instance::media_close`]).
    fn media_closed(&self, npf: &Instance, media: MediaId) {}
}

/// A handler that only logs to stderr.
pub struct NoHandler;
impl Handler for NoHandler {}

struct Ctx {
    inst: Instance,
    handler: Box<dyn Handler>,
}

thread_local! {
    /// the instance whose callback runs on this thread (npf_destroy is refused there)
    static IN_CALLBACK: std::cell::Cell<*const sys::npf_t> = const { std::cell::Cell::new(ptr::null()) };
}

/// Runs a handler method: with the instance, marked as in its callback, and
/// with a panic stopped here instead of unwinding through C.
unsafe fn dispatch<R>(user: *mut c_void, dflt: R, f: impl FnOnce(&Ctx) -> R) -> R {
    let ctx = &*(user as *const Ctx);
    let raw = ctx.inst.raw.load(Ordering::Acquire);
    let prev = IN_CALLBACK.with(|c| c.replace(raw));
    let r = catch_unwind(AssertUnwindSafe(|| f(ctx))).unwrap_or_else(|_| {
        eprintln!("npf: a Handler method panicked; the panic is stopped at libnpf's callback");
        dflt
    });
    IN_CALLBACK.with(|c| c.set(prev));
    r
}

unsafe extern "C" fn cb_log(user: *mut c_void, level: c_int, line: *const c_char) {
    dispatch(user, (), |c| {
        c.handler.log(Level::from_raw(level), lent_str(line))
    })
}
unsafe extern "C" fn cb_event(user: *mut c_void, name: *const c_char, json: *const c_char) {
    dispatch(user, (), |c| {
        c.handler.event(&c.inst, lent_str(name), lent_str(json))
    })
}
unsafe extern "C" fn cb_session(user: *mut c_void, session: u32, up: c_int, info: *const c_char) {
    dispatch(user, (), |c| {
        c.handler
            .session(&c.inst, SessionId(session), up != 0, lent_str(info))
    })
}
unsafe extern "C" fn cb_data(user: *mut c_void, session: u32, buf: *const c_void, len: usize) {
    let data = if len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(buf as *const u8, len)
    };
    dispatch(user, (), |c| {
        c.handler.data(&c.inst, SessionId(session), data)
    })
}
unsafe extern "C" fn cb_media_open(
    user: *mut c_void,
    session: u32,
    media: u32,
    tag: c_int,
) -> c_int {
    dispatch(user, false, |c| {
        c.handler
            .media_open(&c.inst, SessionId(session), MediaId(media), tag)
    }) as c_int
}
unsafe extern "C" fn cb_media_frame(
    user: *mut c_void,
    media: u32,
    buf: *const c_void,
    len: usize,
    fi: *const sys::npf_frame_info,
) {
    let frame = if len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(buf as *const u8, len)
    };
    let fi = &*fi;
    let info = FrameInfo {
        frame_no: fi.frame_no,
        key: fi.flags & sys::NPF_FRAME_KEY != 0,
        lost_before: fi.lost_before,
    };
    dispatch(user, (), |c| {
        c.handler.media_frame(&c.inst, MediaId(media), frame, info)
    })
}
unsafe extern "C" fn cb_media_closed(user: *mut c_void, media: u32) {
    dispatch(user, (), |c| {
        c.handler.media_closed(&c.inst, MediaId(media))
    })
}

/* ---------------- the instance ---------------- */

/// An instance, as the handler sees it: every function of npf.h but making
/// and destroying it. [`Npf`] dereferences to it.
pub struct Instance {
    raw: AtomicPtr<sys::npf_t>,
}

/// An owned instance: [`Drop`] stops it and frees it (`npf_destroy`).
///
/// Do not drop it in its own handler (keeping it there makes a cycle anyway):
/// libnpf refuses to destroy an instance from its thread, so it would be
/// leaked.
pub struct Npf {
    ctx: ManuallyDrop<Box<Ctx>>,
    runtime: ManuallyDrop<Option<Arc<Runtime>>>,
}

unsafe impl Send for Instance {}
unsafe impl Sync for Instance {}

impl std::ops::Deref for Npf {
    type Target = Instance;
    fn deref(&self) -> &Instance {
        &self.ctx.inst
    }
}

impl Npf {
    /// Makes an instance (`npf_create`): reads its configuration and
    /// identity, making data_dir and an identity when there are none, and
    /// opens its UDP socket. Start it with [`Instance::start`] or
    /// [`Instance::run`].
    pub fn new(opts: &Options, handler: impl Handler) -> Result<Npf> {
        let ctx = Box::new(Ctx {
            inst: Instance {
                raw: AtomicPtr::new(ptr::null_mut()),
            },
            handler: Box::new(handler),
        });

        let mut cb: sys::npf_callbacks = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_callbacks_init_size(&mut cb, std::mem::size_of::<sys::npf_callbacks>()) };
        cb.user = &*ctx as *const Ctx as *mut c_void;
        cb.log = Some(cb_log);
        cb.event = Some(cb_event);
        cb.session = Some(cb_session);
        cb.data = Some(cb_data);
        cb.media_open = Some(cb_media_open);
        cb.media_frame = Some(cb_media_frame);
        cb.media_closed = Some(cb_media_closed);

        let conf_dir = opts.conf_dir.as_deref().map(path_cstr).transpose()?;
        let data_dir = opts.data_dir.as_deref().map(path_cstr).transpose()?;
        let conf_file = opts.conf_file.as_deref().map(path_cstr).transpose()?;
        let overrides = if opts.overrides.is_empty() {
            None
        } else {
            Some(cstr(&opts.overrides.join("\n"))?)
        };
        let app_name = opt_cstr(opts.app_name.as_deref())?;
        let app_ver = opt_cstr(opts.app_ver.as_deref())?;
        let setup = opts.setup.as_ref().map(SetupC::new).transpose()?;

        let mut o: sys::npf_options = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_options_init_size(&mut o, std::mem::size_of::<sys::npf_options>()) };
        o.conf_dir = ptr_of(&conf_dir);
        o.data_dir = ptr_of(&data_dir);
        o.conf_file = ptr_of(&conf_file);
        o.overrides = ptr_of(&overrides);
        o.role = opts.role as c_int;
        o.log_level = opts.log_level.map_or(-1, |l| l as c_int);
        o.cb = &cb;
        o.app_name = ptr_of(&app_name);
        o.app_ver = ptr_of(&app_ver);
        o.runtime = opts
            .runtime
            .as_ref()
            .map_or(ptr::null_mut(), |r| r.raw.as_ptr());
        o.setup = setup.as_ref().map_or(ptr::null(), |s| &s.raw);
        o.flags = opts.flags.0;

        let mut out: *mut sys::npf_t = ptr::null_mut();
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe { sys::npf_create(&o, &mut out, err.as_mut_ptr(), err.len()) };
        if rc != sys::NPF_OK || out.is_null() {
            return Err(Error::from_code(
                if rc == sys::NPF_OK {
                    sys::NPF_EFAIL
                } else {
                    rc
                },
                &err,
            ));
        }
        ctx.inst.raw.store(out, Ordering::Release);
        Ok(Npf {
            ctx: ManuallyDrop::new(ctx),
            runtime: ManuallyDrop::new(opts.runtime.clone()),
        })
    }
}

impl Drop for Npf {
    fn drop(&mut self) {
        let raw = self.ctx.inst.raw.load(Ordering::Acquire);
        if ptr::eq(IN_CALLBACK.with(|c| c.get()), raw) {
            // libnpf refuses npf_destroy on its own thread: leak the instance and
            // its handler rather than free what that thread still uses
            eprintln!(
                "npf: an Npf dropped in its own handler is leaked (npf_destroy is refused there)"
            );
            return;
        }
        // stops the run and waits for it and for calls in progress: no callback after this
        unsafe {
            sys::npf_destroy(raw);
            ManuallyDrop::drop(&mut self.ctx);
            ManuallyDrop::drop(&mut self.runtime);
        }
    }
}

/// npf_setup with what its pointers point to (boxed: the addresses stay).
struct SetupC {
    raw: sys::npf_setup,
    _strings: Vec<CString>,
    _setup: Setup,
}

impl SetupC {
    fn new(s: &Setup) -> Result<Box<SetupC>> {
        if s.roots.len() > sys::NPF_ROOTS_MAX {
            return Err(Error {
                kind: ErrorKind::Invalid,
                message: Some("more than 2 root keys".into()),
            });
        }
        let mut c = Box::new(SetupC {
            raw: unsafe { std::mem::zeroed() },
            _strings: Vec::new(),
            _setup: s.clone(),
        });
        unsafe { sys::npf_setup_init_size(&mut c.raw, std::mem::size_of::<sys::npf_setup>()) };
        let mut strings = Vec::new();
        let mut text = |v: &Option<String>| -> Result<*const c_char> {
            let c = opt_cstr(v.as_deref())?;
            let p = ptr_of(&c);
            strings.extend(c);
            Ok(p)
        };
        let s = &c._setup;
        let mut raw = c.raw;
        raw.serverlist_file = text(&s.serverlist_file)?;
        raw.serverlist_saved = text(&s.serverlist_saved)?;
        raw.server_url = text(&s.server_url)?;
        raw.doh_servers = text(&s.doh_servers)?;
        raw.cred = text(&s.cred)?;
        raw.password = text(&s.password)?;
        raw.model_cred = text(&s.model_cred)?;
        raw.serial = text(&s.serial)?;
        raw.hw_info = text(&s.hw_info)?;
        raw.model = text(&s.model)?;
        raw.direct_host = text(&s.direct_host)?;
        if !s.roots.is_empty() {
            raw.roots = s.roots.as_ptr();
            raw.nroots = s.roots.len() as c_int;
        }
        if let Some(l) = &s.serverlist {
            raw.serverlist = l.as_ptr().cast();
            raw.serverlist_len = l.len();
        }
        raw.server_pub = s.server_pub.as_ref().map_or(ptr::null(), |k| k.as_ptr());
        raw.direct_psk = s.direct_psk.as_ref().map_or(ptr::null(), |k| k.as_ptr());
        raw.direct_port = s.direct_port;
        raw.udp_port = s.udp_port;
        raw.no_portmap = s.no_portmap as c_int;
        raw.relays_only = s.relays_only as c_int;
        raw.max_calls = s.max_calls;
        raw.punch_lead_ms = s.punch_lead_ms;
        raw.punch_sockets = s.punch_sockets;
        raw.no_host_report = s.no_host_report as c_int;
        raw.no_hosted_trust = s.no_hosted_trust as c_int;
        raw.peer_idle_s = s.peer_idle_s;
        c.raw = raw;
        c._strings = strings;
        Ok(c)
    }
}

/* boxed closures for npf_command / npf_request: called once */

type TextFn = Box<dyn FnOnce(i32, &str) + Send>;
type ReplyFn = Box<dyn FnOnce(Option<(bool, &str)>) + Send>;
type ShareFn = Box<dyn FnOnce(Result<(String, ShareInfo)>) + Send>;

unsafe extern "C" fn cb_text(user: *mut c_void, code: c_int, text: *const c_char) {
    let f = Box::from_raw(user as *mut TextFn);
    let text = lent_str(text);
    if catch_unwind(AssertUnwindSafe(|| f(code, text))).is_err() {
        eprintln!("npf: a command callback panicked");
    }
}
unsafe extern "C" fn cb_share(
    user: *mut c_void,
    rc: c_int,
    code: *const c_char,
    s: *const sys::npf_share_info,
) {
    let f = Box::from_raw(user as *mut ShareFn);
    let r = if rc == sys::NPF_OK && !code.is_null() && !s.is_null() {
        Ok((lent_str(code).to_owned(), ShareInfo::from_raw(&*s)))
    } else {
        Err(Error::from_code(rc, &[]))
    };
    if catch_unwind(AssertUnwindSafe(|| f(r))).is_err() {
        eprintln!("npf: a share code callback panicked");
    }
}
unsafe extern "C" fn cb_reply(user: *mut c_void, ok: c_int, reply: *const c_char) {
    let f = Box::from_raw(user as *mut ReplyFn);
    let r = if reply.is_null() {
        None
    } else {
        Some((ok != 0, lent_str(reply)))
    };
    if catch_unwind(AssertUnwindSafe(|| f(r))).is_err() {
        eprintln!("npf: a request callback panicked");
    }
}

impl Instance {
    fn n(&self) -> *mut sys::npf_t {
        self.raw.load(Ordering::Acquire)
    }

    /* ---- lifecycle ---- */

    /// Runs the instance on its own thread (or its runtime's) and returns.
    pub fn start(&self) -> Result<()> {
        check(unsafe { sys::npf_start(self.n()) })
    }
    /// Runs the instance on this thread until the run ends.
    pub fn run(&self) -> Result<()> {
        check(unsafe { sys::npf_run(self.n()) })
    }
    /// Ends the run: the sessions end, then the event "stopped". Returns at once.
    pub fn stop(&self) {
        unsafe { sys::npf_stop(self.n()) }
    }

    /* ---- state ---- */

    pub fn status_json(&self) -> Result<String> {
        unsafe { owned_text(sys::npf_status_json(self.n())) }
    }
    pub fn config_json(&self) -> Result<String> {
        unsafe { owned_text(sys::npf_config_json(self.n())) }
    }
    /// The last log lines, up to `max` bytes (0: 16384).
    pub fn log_json(&self, max: i32) -> Result<String> {
        unsafe { owned_text(sys::npf_log_json(self.n(), max)) }
    }
    /// A setting in effect ("" when unset, secrets "(hidden)").
    pub fn config_get(&self, key: &str) -> Result<String> {
        let key = cstr(key)?;
        text_out(|buf, cap| unsafe { sys::npf_config_get(self.n(), key.as_ptr(), buf, cap) })
    }
    /// Sets a setting (`save`: also into local.json). Returns true when it
    /// applies only at the next start.
    pub fn config_set(&self, key: &str, value: &str, save: bool) -> Result<bool> {
        let (key, value) = (cstr(key)?, cstr(value)?);
        let mut restart: c_int = 0;
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe {
            sys::npf_config_set(
                self.n(),
                key.as_ptr(),
                value.as_ptr(),
                save as c_int,
                &mut restart,
                err.as_mut_ptr(),
                ERRCAP,
            )
        };
        check_msg(rc, &err).map(|_| restart != 0)
    }
    /// Writes what a failed write left waiting (local.json, state.json).
    pub fn save(&self) -> Result<()> {
        match unsafe { sys::npf_save(self.n()) } {
            sys::NPF_ESAVE => Err(Error {
                kind: ErrorKind::Failed,
                message: Some("could not write data_dir".into()),
            }),
            rc => check(rc),
        }
    }

    /* ---- peers ---- */

    /// Adds a peer and starts connecting when running. A peer with the same
    /// target gives [`ErrorKind::Exists`]; [`Instance::peer_find`] finds it.
    pub fn peer_create(&self, p: &PeerOpt) -> Result<PeerId> {
        let (host, psk) = match &p.target {
            Target::Number(_) => (None, None),
            Target::Direct { host, psk, .. } => (Some(cstr(host)?), Some(*psk)),
        };
        let password = opt_cstr(p.password.as_deref())?;
        let name = opt_cstr(p.name.as_deref())?;
        let nick = opt_cstr(p.nick.as_deref())?;
        let mut o: sys::npf_peer_opt = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_peer_opt_init_size(&mut o, std::mem::size_of::<sys::npf_peer_opt>()) };
        match &p.target {
            Target::Number(num) => {
                o.target = sys::NPF_TARGET_NUMBER;
                o.number = *num;
            }
            Target::Direct { port, .. } => {
                o.target = sys::NPF_TARGET_DIRECT;
                o.host = ptr_of(&host);
                o.port = *port;
                o.psk = psk.as_ref().map_or(ptr::null(), |k| k.as_ptr());
            }
        }
        o.password = ptr_of(&password);
        o.connect = p.connect as c_int;
        o.idle_ms = p.idle_ms;
        o.flags = if p.persist { sys::NPF_PERSIST } else { 0 };
        o.name = ptr_of(&name);
        o.nick = ptr_of(&nick);
        let mut id = 0u32;
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe { sys::npf_peer_create(self.n(), &o, &mut id, err.as_mut_ptr(), ERRCAP) };
        check_msg(rc, &err).map(|_| PeerId(id))
    }
    pub fn peer_remove(&self, peer: PeerId) -> Result<()> {
        check(unsafe { sys::npf_peer_remove(self.n(), peer.0) })
    }
    /// By target ("318204776", "host:9000") or name.
    pub fn peer_find(&self, target_or_name: &str) -> Result<PeerId> {
        let t = cstr(target_or_name)?;
        let mut id = 0u32;
        check(unsafe { sys::npf_peer_find(self.n(), t.as_ptr(), &mut id) }).map(|_| PeerId(id))
    }
    pub fn peer_list(&self) -> Result<Vec<PeerId>> {
        let v = list_out(0u32, |p, cap, count| unsafe {
            sys::npf_peer_list(self.n(), p, cap, count)
        })?;
        Ok(v.into_iter().map(PeerId).collect())
    }
    pub fn peer_get(&self, peer: PeerId) -> Result<PeerInfo> {
        let mut i: sys::npf_peer_info = unsafe { std::mem::zeroed() };
        check(unsafe {
            sys::npf_peer_get_size(self.n(), peer.0, &mut i, std::mem::size_of_val(&i))
        })?;
        Ok(PeerInfo::from_raw(&i))
    }
    /// Tries now: an idle on-demand peer, one waiting to retry, an ended one.
    pub fn peer_connect_now(&self, peer: PeerId) -> Result<()> {
        check(unsafe { sys::npf_peer_connect_now(self.n(), peer.0) })
    }
    /// Changes one setting of a peer.
    pub fn peer_set(&self, peer: PeerId, s: PeerSetting<'_>) -> Result<()> {
        let n = self.n();
        let int = |opt: c_int, v: c_int| unsafe {
            sys::npf_peer_setopt(
                n,
                peer.0,
                opt,
                &v as *const c_int as *const c_void,
                std::mem::size_of::<c_int>(),
            )
        };
        let text = |opt: c_int, v: &str| -> Result<c_int> {
            let c = cstr(v)?;
            Ok(unsafe { sys::npf_peer_setopt(n, peer.0, opt, c.as_ptr().cast(), 0) })
        };
        check(match s {
            PeerSetting::Connect(c) => int(sys::NPF_PEER_OPT_CONNECT, c as c_int),
            PeerSetting::IdleMs(ms) => int(sys::NPF_PEER_OPT_IDLE_MS, ms),
            PeerSetting::Persist(p) => int(sys::NPF_PEER_OPT_PERSIST, p as c_int),
            PeerSetting::Name(v) => text(sys::NPF_PEER_OPT_NAME, v)?,
            PeerSetting::Nick(v) => text(sys::NPF_PEER_OPT_NICK, v)?,
            PeerSetting::Password(v) => text(sys::NPF_PEER_OPT_PASSWORD, v)?,
        })
    }

    /* ---- forwards ---- */

    pub fn forward_create(&self, peer: PeerId, f: &ForwardOpt) -> Result<ForwardId> {
        let lh = opt_cstr(f.listen.host.as_deref())?;
        let th = opt_cstr(f.target.host.as_deref())?;
        let mut o: sys::npf_forward_opt = unsafe { std::mem::zeroed() };
        unsafe {
            sys::npf_forward_opt_init_size(&mut o, std::mem::size_of::<sys::npf_forward_opt>())
        };
        o.kind = f.kind as c_int;
        o.proto = f.proto as c_int;
        o.listen = sys::npf_endpoint {
            host: ptr_of(&lh),
            port: f.listen.port,
        };
        o.target = sys::npf_endpoint {
            host: ptr_of(&th),
            port: f.target.port,
        };
        o.flags = if f.persist { sys::NPF_PERSIST } else { 0 };
        let mut id = 0u32;
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe {
            sys::npf_forward_create(self.n(), peer.0, &o, &mut id, err.as_mut_ptr(), ERRCAP)
        };
        check_msg(rc, &err).map(|_| ForwardId(id))
    }
    pub fn forward_remove(&self, fwd: ForwardId) -> Result<()> {
        check(unsafe { sys::npf_forward_remove(self.n(), fwd.0) })
    }
    /// `None`: every peer's.
    pub fn forward_list(&self, peer: Option<PeerId>) -> Result<Vec<ForwardId>> {
        let p = peer.map_or(0, |p| p.0);
        let v = list_out(0u32, |o, cap, count| unsafe {
            sys::npf_forward_list(self.n(), p, o, cap, count)
        })?;
        Ok(v.into_iter().map(ForwardId).collect())
    }
    pub fn forward_get(&self, fwd: ForwardId) -> Result<ForwardInfo> {
        let mut i: sys::npf_forward_info = unsafe { std::mem::zeroed() };
        check(unsafe {
            sys::npf_forward_get_size(self.n(), fwd.0, &mut i, std::mem::size_of_val(&i))
        })?;
        Ok(ForwardInfo::from_raw(&i))
    }

    /* ---- resources ---- */

    /// Publishes a resource, or replaces the one of that name.
    pub fn resource_put(&self, r: &Resource) -> Result<()> {
        let name = cstr(&r.name)?;
        let svc = opt_cstr(r.svc.as_deref())?;
        let host = opt_cstr(r.service.host.as_deref())?;
        let rule = opt_cstr(r.rule.as_deref())?;
        let path = opt_cstr(r.path.as_deref())?;
        let desc = opt_cstr(r.desc.as_deref())?;
        let mut o: sys::npf_resource = unsafe { std::mem::zeroed() };
        unsafe { sys::npf_resource_init_size(&mut o, std::mem::size_of::<sys::npf_resource>()) };
        o.type_ = r.kind as c_int;
        o.name = name.as_ptr();
        o.svc = ptr_of(&svc);
        o.service = sys::npf_endpoint {
            host: ptr_of(&host),
            port: r.service.port,
        };
        o.rule = ptr_of(&rule);
        o.path = ptr_of(&path);
        o.desc = ptr_of(&desc);
        o.flags = if r.persist { sys::NPF_PERSIST } else { 0 };
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe { sys::npf_resource_put(self.n(), &o, err.as_mut_ptr(), ERRCAP) };
        check_msg(rc, &err)
    }
    pub fn resource_remove(&self, name: &str) -> Result<()> {
        let name = cstr(name)?;
        check(unsafe { sys::npf_resource_remove(self.n(), name.as_ptr()) })
    }
    /// `None`: this node's; else what that peer published, as last heard.
    pub fn resource_list(&self, peer: Option<PeerId>) -> Result<Vec<ResourceInfo>> {
        let p = peer.map_or(0, |p| p.0);
        let zero: sys::npf_resource_info = unsafe { std::mem::zeroed() };
        let v = list_out(zero, |o, cap, count| unsafe {
            sys::npf_resource_list_size(
                self.n(),
                p,
                o,
                std::mem::size_of::<sys::npf_resource_info>(),
                cap,
                count,
            )
        })?;
        Ok(v.iter().map(ResourceInfo::from_raw).collect())
    }

    /* ---- pairing and owner ---- */

    pub fn pairing_password(&self) -> Result<String> {
        text_out(|buf, cap| unsafe { sys::npf_pairing_password_get(self.n(), buf, cap) })
    }
    pub fn set_pairing_password(&self, password: &str) -> Result<()> {
        let p = cstr(password)?;
        let mut err = [0 as c_char; ERRCAP];
        let rc = unsafe {
            sys::npf_pairing_password_set(self.n(), p.as_ptr(), err.as_mut_ptr(), ERRCAP)
        };
        check_msg(rc, &err)
    }
    pub fn pairing_list(&self) -> Result<Vec<Pairing>> {
        let zero = sys::npf_pairing {
            key: [0; 32],
            since: 0,
            admin: 0,
        };
        let v = list_out(zero, |o, cap, count| unsafe {
            sys::npf_pairing_list_size(
                self.n(),
                o,
                std::mem::size_of::<sys::npf_pairing>(),
                cap,
                count,
            )
        })?;
        Ok(v.iter()
            .map(|p| Pairing {
                key: p.key,
                since: p.since,
                admin: p.admin != 0,
            })
            .collect())
    }
    /// `None`: every pairing.
    pub fn pairing_remove(&self, key: Option<&[u8; 32]>) -> Result<()> {
        check(unsafe { sys::npf_pairing_remove(self.n(), key.map_or(ptr::null(), |k| k.as_ptr())) })
    }
    pub fn owner_reset(&self) -> Result<()> {
        check(unsafe { sys::npf_owner_reset(self.n()) })
    }

    /* ---- share codes ---- */

    /// Asks the platform for a share code good for `uses` pairings (1..=100)
    /// within `ttl_s` seconds (up to 30 days). `done` gets, on the
    /// instance's thread, the whole code (`XXXX-XXXX-XXXX`: told only here)
    /// and its record, or why not: [`ErrorKind::Busy`] (16 live, or the
    /// platform's limit), `State` (the platform's connection lost),
    /// `Unavailable` (no owner account), `Failed`.
    pub fn share_new(
        &self,
        uses: i32,
        ttl_s: i64,
        done: impl FnOnce(Result<(String, ShareInfo)>) + Send + 'static,
    ) -> Result<()> {
        let user = Box::into_raw(Box::new(Box::new(done) as ShareFn));
        let rc = unsafe { sys::npf_share_new(self.n(), uses, ttl_s, Some(cb_share), user.cast()) };
        if rc != sys::NPF_OK {
            drop(unsafe { Box::from_raw(user) });
        }
        check(rc)
    }
    /// The live share codes, oldest first.
    pub fn share_list(&self) -> Result<Vec<ShareInfo>> {
        let zero = sys::npf_share_info {
            locator: [0; 8],
            uses: 0,
            expires: 0,
        };
        let v = list_out(zero, |o, cap, count| unsafe {
            sys::npf_share_list_size(
                self.n(),
                o,
                std::mem::size_of::<sys::npf_share_info>(),
                cap,
                count,
            )
        })?;
        Ok(v.iter().map(ShareInfo::from_raw).collect())
    }
    /// Revokes the share code of this locator, here and on the platform.
    pub fn share_del(&self, locator: &str) -> Result<()> {
        let l = cstr(locator)?;
        check(unsafe { sys::npf_share_del(self.n(), l.as_ptr()) })
    }

    /* ---- this node, sessions, the network ---- */

    pub fn node_info(&self) -> Result<NodeInfo> {
        let mut i: sys::npf_node_info = unsafe { std::mem::zeroed() };
        check(unsafe { sys::npf_node_get_size(self.n(), &mut i, std::mem::size_of_val(&i)) })?;
        Ok(NodeInfo::from_raw(&i))
    }
    /// This node's identity public key in base64url.
    pub fn node_key(&self) -> Result<String> {
        text_out(|buf, cap| unsafe { sys::npf_node_key(self.n(), buf, cap) })
    }
    pub fn session_info(&self, session: SessionId) -> Result<SessionInfo> {
        let mut i: sys::npf_session_info = unsafe { std::mem::zeroed() };
        check(unsafe {
            sys::npf_session_get_size(self.n(), session.0, &mut i, std::mem::size_of_val(&i))
        })?;
        Ok(SessionInfo::from_raw(&i))
    }
    pub fn session_list(&self) -> Result<Vec<SessionId>> {
        let v = list_out(0u32, |o, cap, count| unsafe {
            sys::npf_session_list(self.n(), o, cap, count)
        })?;
        Ok(v.into_iter().map(SessionId).collect())
    }
    /// The sessions up now, as a JSON array.
    pub fn sessions_json(&self) -> Result<String> {
        unsafe { owned_text(sys::npf_sessions_json(self.n())) }
    }
    /// A hosted client's public mappings; `close`: close the public ports now.
    pub fn public_json(&self, close: bool) -> Result<String> {
        unsafe { owned_text(sys::npf_public_json(self.n(), close as c_int)) }
    }
    /// The network changed: reopen the sockets, try the peers again.
    pub fn network_changed(&self) -> Result<()> {
        check(unsafe { sys::npf_network_changed(self.n()) })
    }

    /* ---- commands and platform requests ---- */

    /// Runs a command (libnpf's own or a module's); `done` gets the exit code
    /// and the output, on the instance's thread, now or later.
    pub fn command(
        &self,
        args: &[&str],
        done: impl FnOnce(i32, &str) + Send + 'static,
    ) -> Result<()> {
        let cargs = args.iter().map(|a| cstr(a)).collect::<Result<Vec<_>>>()?;
        let argv: Vec<*const c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
        let user = Box::into_raw(Box::new(Box::new(done) as TextFn));
        let rc = unsafe {
            sys::npf_command(
                self.n(),
                argv.len() as c_int,
                argv.as_ptr(),
                Some(cb_text),
                user.cast(),
            )
        };
        if rc != sys::NPF_OK {
            drop(unsafe { Box::from_raw(user) });
        }
        check(rc)
    }
    /// Sends a request to the platform; `done` gets `Some((ok, reply JSON))`,
    /// or `None` when the connection was lost.
    pub fn request(
        &self,
        type_: &str,
        data_json: Option<&str>,
        key_proof: bool,
        done: impl FnOnce(Option<(bool, &str)>) + Send + 'static,
    ) -> Result<()> {
        let t = cstr(type_)?;
        let d = opt_cstr(data_json)?;
        let user = Box::into_raw(Box::new(Box::new(done) as ReplyFn));
        let rc = unsafe {
            sys::npf_request(
                self.n(),
                t.as_ptr(),
                ptr_of(&d),
                key_proof as c_int,
                Some(cb_reply),
                user.cast(),
            )
        };
        if rc != sys::NPF_OK {
            drop(unsafe { Box::from_raw(user) });
        }
        check(rc)
    }

    /* ---- application data ---- */

    /// Reliable, ordered data to the peer's [`Handler::data`], ahead of the
    /// forwards' data; up to [`SESSION_SEND_MAX`] bytes.
    pub fn session_send(&self, session: SessionId, data: &[u8]) -> Result<()> {
        check(unsafe {
            sys::npf_session_send(self.n(), session.0, data.as_ptr().cast(), data.len())
        })
    }

    /* ---- media ---- */

    /// Opens a stream of frames to the session's peer.
    pub fn media_open(&self, session: SessionId, o: &MediaOpt) -> Result<MediaId> {
        let raw = o.to_raw();
        let mut id = 0u32;
        check(unsafe { sys::npf_media_open(self.n(), session.0, &raw, &mut id) })
            .map(|_| MediaId(id))
    }
    /// Sends one frame (up to [`MEDIA_FRAME_MAX`] bytes). From another thread
    /// it is copied and queued: [`ErrorKind::Busy`] when the queue is full.
    pub fn media_send(&self, media: MediaId, frame: &[u8], key: bool) -> Result<()> {
        let flags = if key { sys::NPF_FRAME_KEY } else { 0 };
        check(unsafe {
            sys::npf_media_send(self.n(), media.0, flags, frame.as_ptr().cast(), frame.len())
        })
    }
    /// The stream's statistics, with the rate the encoder may send.
    pub fn media_stats(&self, media: MediaId) -> Result<MediaStats> {
        let mut s = sys::npf_media_stats::default();
        check(unsafe {
            sys::npf_media_stats_get_size(self.n(), media.0, &mut s, std::mem::size_of_val(&s))
        })?;
        Ok(MediaStats::from_raw(&s))
    }
    /// Closes a stream, sending or receiving (no `media_closed` follows).
    pub fn media_close(&self, media: MediaId) -> Result<()> {
        check(unsafe { sys::npf_media_close(self.n(), media.0) })
    }
}

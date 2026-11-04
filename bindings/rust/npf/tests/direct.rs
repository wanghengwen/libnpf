//! Two direct instances on loopback, no platform: A listens with a
//! pre-shared key and echoes application data; B connects, sends data and a
//! stream of media frames, and reads its stream statistics.

use npf::*;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [7; 32];
const TAG: i32 = 42;

#[derive(Debug)]
enum Ev {
    Session(SessionId, bool),
    Data(SessionId, Vec<u8>),
    Opened(MediaId, i32),
    Frame(MediaId, usize, FrameInfo, u8),
    Closed(MediaId),
}

struct H {
    tx: Sender<Ev>,
    echo: bool,
}

impl Handler for H {
    fn log(&self, level: Level, line: &str) {
        if level >= Level::Warn {
            eprintln!("{line}");
        }
    }
    fn session(&self, _: &Instance, s: SessionId, up: bool, _info: &str) {
        let _ = self.tx.send(Ev::Session(s, up));
    }
    fn data(&self, npf: &Instance, s: SessionId, data: &[u8]) {
        if self.echo {
            npf.session_send(s, data).expect("echo from the callback");
        }
        let _ = self.tx.send(Ev::Data(s, data.to_vec()));
    }
    fn media_open(&self, _: &Instance, _s: SessionId, m: MediaId, tag: i32) -> bool {
        let _ = self.tx.send(Ev::Opened(m, tag));
        tag == TAG
    }
    fn media_frame(&self, _: &Instance, m: MediaId, frame: &[u8], info: FrameInfo) {
        let _ = self.tx.send(Ev::Frame(m, frame.len(), info, frame[0]));
    }
    fn media_closed(&self, _: &Instance, m: MediaId) {
        let _ = self.tx.send(Ev::Closed(m));
    }
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("npf-rs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn wait<T>(rx: &Receiver<Ev>, what: &str, mut f: impl FnMut(Ev) -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        let left = end.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ev) => {
                if let Some(v) = f(ev) {
                    return v;
                }
            }
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

#[test]
fn defaults() {
    assert_eq!(api_version(), 1);
    assert!(!version().is_empty());
    let o = MediaOpt::new(3);
    assert_eq!((o.tag, o.prio, o.max_age_ms, o.fec), (3, 1, 500, Fec::Auto));
    assert!(!o.drop_until_key && !o.rcv_drop_until_key);
    assert_eq!(Setup::default().punch_lead_ms, -1);
}

#[test]
fn direct_data_and_media() {
    // below the ephemeral range, which other programs here take
    let port = 27800 + (std::process::id() % 100) as u16;
    let (da, db) = (tmpdir("a"), tmpdir("b"));
    let (txa, rxa) = channel();
    let (txb, rxb) = channel();

    let mut oa = Options::direct(&da, Some(("127.0.0.1", port)), PSK);
    oa.log_level = Some(Level::Warn);
    let a = Npf::new(
        &oa,
        H {
            tx: txa,
            echo: true,
        },
    )
    .expect("A");
    let mut ob = Options::direct(&db, None, PSK);
    ob.log_level = Some(Level::Warn);
    let b = Npf::new(
        &ob,
        H {
            tx: txb,
            echo: false,
        },
    )
    .expect("B");
    assert_eq!(b.node_key().unwrap().len(), 43);
    a.start().unwrap();
    b.start().unwrap();

    let peer = b
        .peer_create(&PeerOpt::new(Target::Direct {
            host: "127.0.0.1".into(),
            port,
            psk: PSK,
        }))
        .expect("peer");
    let sb = wait(&rxb, "B's session", |e| match e {
        Ev::Session(s, true) => Some(s),
        _ => None,
    });
    let sa = wait(&rxa, "A's session", |e| match e {
        Ev::Session(s, true) => Some(s),
        _ => None,
    });
    assert_eq!(b.peer_get(peer).unwrap().session, Some(sb));
    assert!(b.session_info(sb).unwrap().outgoing);
    assert!(!a.session_info(sa).unwrap().outgoing);
    assert_eq!(b.session_list().unwrap(), vec![sb]);
    assert!(b.sessions_json().unwrap().starts_with('['));

    // application data, echoed by A from its callback
    b.session_send(sb, b"hello npf").unwrap();
    let back = wait(&rxb, "the echo", |e| match e {
        Ev::Data(s, d) if s == sb => Some(d),
        _ => None,
    });
    assert_eq!(back, b"hello npf");
    assert_eq!(
        b.session_send(sb, &vec![0u8; SESSION_SEND_MAX + 1])
            .unwrap_err()
            .kind,
        ErrorKind::TooBig
    );

    // a refused stream, then frames on a taken one
    let refused = b.media_open(sb, &MediaOpt::new(TAG + 1)).unwrap();
    wait(&rxa, "the refused stream", |e| match e {
        Ev::Opened(_, t) if t == TAG + 1 => Some(()),
        _ => None,
    });
    let mut mo = MediaOpt::new(TAG);
    mo.drop_until_key = true;
    mo.rcv_drop_until_key = true;
    let m = b.media_open(sb, &mo).unwrap();
    const FRAMES: u32 = 60;
    for f in 0..FRAMES {
        let frame = vec![f as u8; if f % 10 == 0 { 20000 } else { 3000 }];
        b.media_send(m, &frame, f % 10 == 0).unwrap();
    }
    let mut got = 0u32;
    let mut am = None;
    wait(&rxa, "the frames", |e| {
        match e {
            Ev::Opened(id, TAG) => am = Some(id),
            Ev::Frame(id, len, fi, first) => {
                assert_eq!(Some(id), am);
                assert_eq!(fi.frame_no, got, "in order, none lost on loopback");
                assert_eq!(fi.key, got % 10 == 0);
                assert_eq!(first, got as u8);
                assert_eq!(len, if fi.key { 20000 } else { 3000 });
                got += 1;
            }
            _ => {}
        }
        (got == FRAMES).then_some(())
    });
    let st = b.media_stats(m).unwrap();
    assert!(st.srtt_ms < 1000, "{st:?}");
    assert_eq!(st.frames_dropped, 0);

    // closing on B ends A's receiving stream
    b.media_close(m).unwrap();
    let _ = b.media_close(refused);
    wait(&rxa, "media_closed", |e| {
        matches!(e, Ev::Closed(id) if Some(id) == am).then_some(())
    });
    assert_eq!(
        b.media_send(m, b"x", false).unwrap_err().kind,
        ErrorKind::NotFound
    );

    b.peer_remove(peer).unwrap();
    wait(&rxa, "the end of A's session", |e| {
        matches!(e, Ev::Session(s, false) if s == sa).then_some(())
    });
    drop(b);
    drop(a);
    let _ = std::fs::remove_dir_all(da);
    let _ = std::fs::remove_dir_all(db);
}

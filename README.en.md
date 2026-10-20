# libnpf

libnpf is a P2P networking library in C99: devices behind NAT (a NAS, a computer, a router, a phone) find each other, punch a direct path, fall back to a relay when they cannot, and run an end-to-end encrypted session between them. A session carries port forwards, application data and audio / video streams.

It is the core of the "Chuanshanjia" (pangolin) remote access service. Its transport is the open-source UDP protocol [AnLiu](https://github.com/wanghengwen/AnLiu).

## What it does

| Area | |
| --- | --- |
| NAT traversal | NAT detection against self-hosted probe servers; candidates: local IPv4, global IPv6, the public mapping, a PCP / NAT-PMP mapping where the router gives one; probing all the peer's candidates at once (S1), birthday-paradox punching for symmetric NATs (S3); retries after 10 s, then 1 / 5 / 30 minutes |
| Paths | a session starts on a UDP relay while punching goes on behind it, moves to the direct path when it opens (the relay is released 30 s later), and back to the relay when the direct path fails; a WebSocket relay (an ordinary HTTPS port) where UDP does not get through |
| Transport | AnLiu: encrypted, many streams, BBRv2 congestion control, SACK / RACK, FEC per stream, semi-reliable frames; one AnLiu connection moves between the direct path and the relay without being rebuilt |
| Security | to the platform: Noise XK inside WSS; first pairing: CPace (PAKE) + Noise XXpsk3, the password never leaves the device; paired: Noise IK; the account's grant: Noise IK + a grant the platform signs; lockout after wrong passwords; the callee lets through only what it published, any other target is refused |
| In a session | port forwards `-L` / `-D` (SOCKS5) / `-R`, UDP forwards; application data (reliable, ordered); media streams (up to 64 per instance; late frames dropped, key frames, FEC) |
| Running | a single-threaded event loop (poll; WSAPoll on Windows); several instances in one process, or many on a shared thread pool (`npf_runtime`); it mends itself after a suspend or a network change |
| Platforms | Linux, macOS, iOS, Android, Windows 10 and later; a device build of a whole program with musl, statically linked, is about 600 KB |

## Building

CMake 3.16 or later and a C99 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"     # libnpf.so / libnpf.a, npf.h, npf.pc
```

| Option | Default | |
| --- | --- | --- |
| `NPF_BUILD_TESTS` | ON | unit tests, API tests, fuzzing |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c` |
| `NPF_PEERS` | ON | sessions this node starts to other nodes; off for a device that is only called |
| `NPF_WITH_TLS` | ON | `wss://`, `https://` (mbedTLS 3.6) |
| `NPF_USE_OPENSSL` | OFF | OpenSSL 3 instead of mbedTLS (servers) |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

On Linux `libnpf.a` is one relocatable object with every symbol but those of `npf.h` made local, so the bundled AnLiu, Monocypher and mbedTLS cannot clash with the application's own copies.

## Using it

The public interface is `include/npf.h` alone. One `npf_t` is one identity on the platform: a node others call, a client that calls them, or both.

```c
#include "npf.h"

npf_options o;
npf_callbacks cb;
npf_t *n;
char err[256];

npf_options_init(&o);
npf_callbacks_init(&cb);
cb.event = on_event;            /* "online", "enrolled", "stopped" ... */
cb.session = on_session;        /* a session up, down */
cb.data = on_data;              /* the peer's application data */
o.conf_dir = "/etc/npf";        /* read only: npf.conf, the root key, the server list */
o.data_dir = "/var/lib/npf";    /* writable: identity, number, pairing state */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
if (npf_create(&o, &n, err, sizeof err) != NPF_OK || npf_start(n) != NPF_OK)
    return 1;
/* ... npf_peer_add, npf_forward_add, npf_session_send, npf_media_open ... */
npf_destroy(n);
```

`examples/device.c` is a whole device: it enrols with its model credential, stays online, and sends back what a peer sends it.

Without the platform: `NPF_ROLE_DIRECT` with a pre-shared key (Noise_NNpsk0), UDP and AnLiu straight between the two ends.

## Modules

A program can add features of its own without changing the library: `include/npf/module.h` defines a module's hooks (login, the platform's events, the sessions' states, the peers' forwards, commands and configuration keys of its own, keys in the status), and `npf_fwd_kind` in `npf/peers.h` adds a kind of forward. The program names its module sources and their table `npf_modules` in CMake with `NPF_MODULE_SOURCES`; without them the table is empty.

## Layout

```
include/npf.h          the public interface
include/npf/           the internal interfaces (modules use them too)
src/platform/          system layer, event loop, logging, asynchronous resolver
src/crypto/            Noise, CPace, certificates, SIV
src/proto/ src/ws/     JSON, DNS, HTTP, WebSocket, TLS, signaling, WS relay
src/ice/ src/punch/    NAT detection, candidates, PCP / NAT-PMP, hole punching
src/node/ src/tunnel/  the node, sessions, AnLiu, relays, the tunnel, UDP forwards, media, peers
src/api/               npf.h's implementation, commands, modules
third_party/           AnLiu, Monocypher, mbedTLS, rxi/log
tests/                 unit tests, API tests, fuzzing
docs/                  the signaling protocol, the data channel, NAT traversal, security, libnpf's design (in Chinese)
```

## Licence

MIT, see `LICENSE`. Third-party code: AnLiu (MIT), Monocypher (CC0 / BSD-2-Clause), mbedTLS (Apache-2.0), rxi/log.c (MIT); their licences are in `third_party/`.

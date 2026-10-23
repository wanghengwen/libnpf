# libnpf

[中文](README.md) | English

libnpf: a C99 P2P networking library that connects devices behind NAT by hole punching, falls back to a relay when needed, and runs end-to-end encrypted sessions for port forwarding, app data, and audio/video.

It is the core of the "Chuanshanjia" (pangolin) remote access service. Its transport is the open-source UDP protocol [AnLiu](https://github.com/wanghengwen/AnLiu).

## What it does

| Area | |
| --- | --- |
| NAT traversal | NAT detection against self-hosted probe servers (mapping, port allocation, filtering); candidates: local IPv4, global IPv6, the public mapping, a PCP / NAT-PMP mapping where the router gives one; a strategy chosen from both sides' NATs: simultaneous punching (S1), port prediction (S2; S2B when both allocate sequentially), birthday-paradox punching (S3), using one side's lenient filtering (S4), small port blocks (S5), and the relay alone when both ends are symmetric NATs with random ports; retries after 10 s, 30 s, then 1, 2 and 3 minutes, at most 10 rounds a session |
| Paths | a session starts on a UDP relay while punching goes on behind it, moves to the direct path when it opens (the relay is released 30 s later), and back to the relay when the direct path fails; a WebSocket relay (an ordinary HTTPS port) where UDP does not get through |
| Transport | AnLiu: encrypted, many streams, BBRv2 congestion control, SACK / RACK, FEC per stream, semi-reliable frames; one AnLiu connection moves between the direct path and the relay without being rebuilt |
| Security | to the platform: Noise XK inside WSS; first pairing: CPace (PAKE) + Noise XXpsk3, the password never leaves the device; paired: Noise IK; the account's grant: Noise IK + a grant the platform signs; pairing locked after repeated wrong passwords; the called side lets through only what it published, any other target is refused |
| In a session | port forwards: local, SOCKS5 proxy, and reverse (the peer opens a port that leads back here), TCP and UDP; application data (reliable, ordered); media streams (up to 64 per instance, at most 30 opened by one side of a session; late frames dropped, key frames, FEC) |
| Running | one event-loop thread per instance (poll; WSAPoll on Windows); several instances in one process, or many on a shared set of threads (`npf_runtime`); it mends itself after a suspend or a network change |
| Platforms | Linux, macOS, iOS, Android, Windows 10 and later; a program for a device that is only called, linked statically with musl, optimised for size and without `NPF_PEERS`, is about 600 KB |

## Building

CMake 3.16 or later and a C99 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix install     # npf.h, the shared library, libnpf.a on Linux, npf.pc
```

The installed `npf.pc` finds the library and the header relative to where it is, so the installed tree can be moved as a whole.

| Option | Default | |
| --- | --- | --- |
| `NPF_BUILD_LIB` | ON | the shared library (a DLL on Windows) and, on Linux, the static `libnpf.a` |
| `NPF_BUILD_TESTS` | ON | unit tests, API tests, fuzzing |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c`, `examples/client.c` (needs `NPF_BUILD_LIB`; not on Windows) |
| `NPF_PEERS` | ON | sessions this node starts to other nodes; off for a device that is only called, a smaller program |
| `NPF_WITH_TLS` | ON | `wss://`, `https://` (mbedTLS 3.6) |
| `NPF_USE_OPENSSL` | OFF | OpenSSL 3 instead of mbedTLS for TLS and the application crypto (servers) |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

On Linux `libnpf.a` is one relocatable object with every symbol but those of `npf.h` made local, so the bundled AnLiu, Monocypher and mbedTLS cannot clash with the application's own copies.

## Using it

The installed SDK has one public header, `npf.h` (`include/npf.h` in the source); the developer's guide is [docs/design/libnpf.md](docs/design/libnpf.md) (in Chinese). One `npf_t` is an instance with its own identity, configuration and state: a node others call, a client that calls them, or both; a direct instance needs no platform.

```c
#include <npf.h>

npf_setup su;
npf_options o;
npf_callbacks cb;
npf_t *n;
char err[256];

npf_setup_init(&su);
su.roots = roots;               /* the platform's root keys (bytes) */
su.nroots = 1;
su.serverlist = list;           /* its signed server list (bytes) */
su.serverlist_len = list_len;
npf_callbacks_init(&cb);
cb.notify = on_notify;          /* typed events: online, sessions, peers, forwards ... */
cb.data = on_data;              /* application data from a peer */
npf_options_init(&o);
o.setup = &su;                  /* no configuration file needed */
o.data_dir = data_dir;          /* writable: identity, number, pairing state, saved peers and resources */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
if (npf_create(&o, &n, err, sizeof err) != NPF_OK || npf_start(n) != NPF_OK)
    return 1;
/* ... npf_resource_put, npf_peer_create, npf_forward_create, npf_peer_setopt,
 *     npf_session_send, npf_media_open ... */
npf_destroy(n);
```

`examples/device.c` is a whole device (it enrols with its model credential, publishes a web page, stays online and sends back what a peer sends it), and `examples/client.c` a client (it connects to a device by its number and password and opens a local forward to it). Peers, forwards and resources are numbered, typed objects, changed one setting at a time with `npf_peer_setopt` / `npf_forward_setopt`; the library has no command syntax for them: the command line and the user interface are the application's.

Without the platform: `NPF_ROLE_DIRECT` with a pre-shared key (Noise_NNpsk0), UDP and AnLiu straight between the two ends.

## Modules

The installed SDK is `npf.h` alone; it has no module interface. Modules are an internal extension mechanism built together with libnpf's source (commands, configuration keys, platform events, status keys and kinds of forward of their own), and the internal headers in `include/npf/` are not installed; a program that only connects, forwards, sends application data or media uses `npf.h` and needs no module. When one is needed, see the [developer's guide](docs/design/libnpf.md), section 12.

## Layout

```
include/npf.h          the public interface (the installed SDK has this one alone)
include/npf/           the internal interfaces (not installed; for modules in a source build)
src/api/               npf.h's implementation: objects, events, npf_setup, commands, modules
src/platform/          system layer, event loop, logging, asynchronous resolver, the VPN bypass
src/crypto/            Noise, CPace, certificates, SIV
src/proto/ src/ws/     JSON, DNS, HTTP, signaling, WS relay; WebSocket, TLS
src/ice/ src/punch/    NAT detection, candidates, PCP / NAT-PMP, hole punching
src/node/ src/tunnel/  the node, sessions, AnLiu, relays, the tunnel, UDP forwards, media, peers, resources
third_party/           AnLiu, Monocypher, mbedTLS, rxi/log
examples/              device.c, client.c: a device and a client on npf.h alone
tests/                 unit tests, API tests, fuzzing
cmake/, scripts/       build options; the script that updates the bundled AnLiu
docs/                  the signaling protocol, the data channel, NAT traversal, security, and the developer's guide docs/design/libnpf.md (in Chinese)
```

## Licence

MIT, see `LICENSE`. Third-party code: AnLiu (MIT), Monocypher (CC0 / BSD-2-Clause), mbedTLS (Apache-2.0), rxi/log.c (MIT); their licences are in `third_party/` (rxi/log's in its source files' headers).

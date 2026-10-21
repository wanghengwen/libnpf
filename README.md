# libnpf

libnpf 是一个用 C99 写的 P2P 网络库：让藏在 NAT 后面的设备（NAS、电脑、路由器、手机）互相找到对方，打洞直连，打不通时自动走中转，并在两端之间建立端到端加密的会话。会话里可以跑端口转发、应用数据和音视频流。

它是“穿山甲”远程访问的核心，底层传输使用开源 UDP 协议 [AnLiu（暗流）](https://github.com/wanghengwen/AnLiu)。

## 能做什么

| 方面 | 内容 |
| --- | --- |
| NAT 穿透 | 自建探测服务器上的 NAT 类型探测；候选地址：本机 IPv4、全局 IPv6、公网映射地址，路由器支持时用 PCP / NAT-PMP 申请映射；向对方全部候选同时探测（S1），对称型 NAT 用生日悖论碰撞（S3）；失败后按 10 秒、1 / 5 / 30 分钟退避重试 |
| 路径 | 会话先在 UDP 中转上开始，打洞在后台进行，直连成功后无缝切换、30 秒后释放中转；直连失效时退回中转；UDP 不通时走 WebSocket 中转（普通 HTTPS 端口） |
| 传输 | AnLiu：加密、多流、BBRv2 拥塞控制、SACK / RACK、按流 FEC、半可靠帧；同一条 AnLiu 连接在直连和中转之间切换不用重建 |
| 安全 | 接入平台：WSS 内 Noise XK；首次配对：CPace（PAKE）+ Noise XXpsk3，口令不出设备；已配对：Noise IK；账户授权：Noise IK + 平台签发的授权；口令错误锁定；被叫按“发布的资源”放行，未发布的目标一律拒绝 |
| 会话内容 | 端口转发 `-L` / `-D`（SOCKS5）/ `-R`、UDP 转发；应用数据（可靠、有序）；音视频流（每个实例同时最多 64 个，迟到丢帧、关键帧、FEC） |
| 运行 | 单线程事件循环（Linux / macOS / iOS 用 poll，Windows 用 WSAPoll）；一个进程可以有多个实例，也可以共享线程池（`npf_runtime`）；挂起和网络变化后自己恢复 |
| 平台 | Linux、macOS、iOS、Android、Windows 10 起；设备端 musl 静态编译约 600 KB |

## 构建

需要 CMake 3.16 起和 C99 编译器。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"     # libnpf.so / libnpf.a、npf.h、npf.pc
```

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `NPF_BUILD_TESTS` | ON | 单元测试、API 测试、模糊测试 |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c` |
| `NPF_PEERS` | ON | 本节点主动连接别的节点；只被连接的设备可以关掉 |
| `NPF_WITH_TLS` | ON | `wss://`、`https://`（mbedTLS 3.6） |
| `NPF_USE_OPENSSL` | OFF | 用 OpenSSL 3 代替 mbedTLS（服务器上用） |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

Linux 上的 `libnpf.a` 是一个可重定位目标，除 `npf.h` 的函数外全部符号都是局部的，内置的 AnLiu、Monocypher、mbedTLS 不会和应用程序自己的副本冲突。

## 用法

公开接口只有 `include/npf.h`，完整的说明见 [开发者指南](docs/design/libnpf.md)。一个 `npf_t` 是平台上的一个身份：被别人连接的节点、主动连接的客户端，或者两者都是。

```c
#include "npf.h"

npf_options o;
npf_callbacks cb;
npf_t *n;
char err[256];

npf_options_init(&o);
npf_callbacks_init(&cb);
cb.event = on_event;            /* "online"、"enrolled"、"stopped" ... */
cb.session = on_session;        /* 会话建立、结束 */
cb.data = on_data;              /* 对端发来的应用数据 */
o.conf_dir = conf_dir;          /* 应用决定的目录，只读：npf.conf、根公钥、服务器列表 */
o.data_dir = data_dir;          /* 可写：身份、编号、配对状态 */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
if (npf_create(&o, &n, err, sizeof err) != NPF_OK || npf_start(n) != NPF_OK)
    return 1;
/* ... npf_peer_add、npf_forward_add、npf_session_send、npf_media_open ... */
npf_destroy(n);
```

完整的设备示例见 `examples/device.c`：用型号凭证自动注册、保持在线、把对端发来的数据原样发回。

不经平台也能用：`NPF_ROLE_DIRECT` 加预共享密钥（Noise_NNpsk0），两端直接 UDP + AnLiu。

## 模块

程序可以在 libnpf 之外加自己的功能，而不改库本身：`include/npf/module.h` 定义了模块的钩子（登录、平台事件、会话状态、对端的转发、自己的命令和配置键、状态里的字段），`npf/peers.h` 的 `npf_fwd_kind` 让模块增加一种转发。模块是程序自己的代码，在程序自己的构建里编译（链接静态目标 `npf_common`），运行时用 `npf_register_module` 注册，库本身不用改、也不用重新配置；见 `docs/design/libnpf.md` 第 11 节。

## 目录

```
include/npf.h          公开接口
include/npf/           内部接口（模块也用）
src/platform/          系统层、事件循环、日志、异步解析
src/crypto/            Noise、CPace、证书、SIV
src/proto/ src/ws/     JSON、DNS、HTTP、WebSocket、TLS、信令、WS 中转
src/ice/ src/punch/    NAT 探测、候选地址、PCP / NAT-PMP、打洞
src/node/ src/tunnel/  节点、会话、AnLiu、中转、隧道、UDP 转发、媒体、对端
src/api/               npf.h 的实现、命令、模块
third_party/           AnLiu、Monocypher、mbedTLS、rxi/log
tests/                 单元测试、API 测试、模糊测试
docs/                  信令协议、数据通道、NAT 穿透与安全设计，以及开发者指南（docs/design/libnpf.md）
```

## 许可

MIT，见 `LICENSE`。第三方：AnLiu（MIT）、Monocypher（CC0 / BSD-2-Clause）、mbedTLS（Apache-2.0）、rxi/log.c（MIT），各自的许可在 `third_party/` 下。

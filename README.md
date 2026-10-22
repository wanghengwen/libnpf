# libnpf

libnpf：一个 C99 写的 P2P 网络库，让 NAT 后面的设备打洞直连、打不通自动走中转，建立端到端加密的会话，承载端口转发、应用数据和音视频。

它是“穿山甲”远程访问的核心，底层传输使用开源 UDP 协议 [AnLiu（暗流）](https://github.com/wanghengwen/AnLiu)。

## 能做什么

| 方面 | 内容 |
| --- | --- |
| NAT 穿透 | 自建探测服务器上的 NAT 类型探测（映射、端口分配、过滤行为）；候选地址：本机 IPv4、全局 IPv6、公网映射地址，路由器支持时用 PCP / NAT-PMP 申请映射；按双方的 NAT 组合选策略：同时打洞（S1）、端口预测（S2，双方顺序分配时 S2B）、生日悖论碰撞（S3）、借助一方宽松过滤（S4）、小端口块（S5），两端都是随机分配的对称型 NAT 时直接中转；失败后按 10、30 秒，1、2、3 分钟退避重试，每个会话最多 10 轮 |
| 路径 | 会话先在 UDP 中转上开始，打洞在后台进行，直连成功后无缝切换、30 秒后释放中转；直连失效时退回中转；UDP 不通时走 WebSocket 中转（普通 HTTPS 端口） |
| 传输 | AnLiu：加密、多流、BBRv2 拥塞控制、SACK / RACK、按流 FEC、半可靠帧；同一条 AnLiu 连接在直连和中转之间切换不用重建 |
| 安全 | 接入平台：WSS 内 Noise XK；首次配对：CPace（PAKE）+ Noise XXpsk3，口令不出设备；已配对：Noise IK；账户授权：Noise IK + 平台签发的授权；口令多次错误后锁定配对；被连接的一方只放行它发布的资源，未发布的目标一律拒绝 |
| 会话内容 | 端口转发：本地转发、SOCKS5 代理、反向转发（对方开端口连回本机），TCP 与 UDP；应用数据（可靠、有序）；音视频流（每个实例同时最多 64 个，每个会话本端发出的最多 30 个；迟到丢帧、关键帧、FEC） |
| 运行 | 每个实例一个事件循环线程（poll，Windows 上 WSAPoll）；一个进程可以有多个实例，也可以让很多实例共享一组线程（`npf_runtime`）；挂起和网络变化后自己恢复 |
| 平台 | Linux、macOS、iOS、Android、Windows 10 起；用 musl 静态链接、按体积优化、关掉 `NPF_PEERS` 时，一个只被连接的设备程序约 600 KB |

## 构建

需要 CMake 3.16 起和 C99 编译器。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix install     # npf.h、共享库、Linux 上另有 libnpf.a、npf.pc
```

安装的 `npf.pc` 按自己所在的位置找库和头文件，安装目录可以整个搬走。

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `NPF_BUILD_LIB` | ON | 共享库（Windows 上是 DLL）与 Linux 上的静态库 `libnpf.a` |
| `NPF_BUILD_TESTS` | ON | 单元测试、API 测试、模糊测试 |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c`、`examples/client.c`（要 `NPF_BUILD_LIB`，Windows 上不构建） |
| `NPF_PEERS` | ON | 本节点主动连接别的节点；只被连接的设备可以关掉，程序更小 |
| `NPF_WITH_TLS` | ON | `wss://`、`https://`（mbedTLS 3.6） |
| `NPF_USE_OPENSSL` | OFF | 用 OpenSSL 3 代替 mbedTLS 做 TLS 和应用层密码学（服务器上用） |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

Linux 上的 `libnpf.a` 是一个可重定位目标，除 `npf.h` 的函数外全部符号都是局部的，内置的 AnLiu、Monocypher、mbedTLS 不会和应用程序自己的副本冲突。

## 用法

安装的 SDK 只有一个公开头文件 `npf.h`（源码里的 `include/npf.h`），完整的说明见 [开发者指南](docs/design/libnpf.md)。一个 `npf_t` 是一个实例，有自己的身份、配置和运行状态：被别人连接的节点、主动连接的客户端，或者两者都是；直连实例不需要平台。

```c
#include <npf.h>

npf_setup su;
npf_options o;
npf_callbacks cb;
npf_t *n;
char err[256];

npf_setup_init(&su);
su.roots = roots;               /* 平台的根公钥（字节） */
su.nroots = 1;
su.serverlist = list;           /* 签名的服务器列表（字节） */
su.serverlist_len = list_len;
npf_callbacks_init(&cb);
cb.notify = on_notify;          /* 类型化的事件：上线、会话、对端、转发 ... */
cb.data = on_data;              /* 对端发来的应用数据 */
npf_options_init(&o);
o.setup = &su;                  /* 不需要配置文件 */
o.data_dir = data_dir;          /* 可写：身份、编号、配对状态、保存的对端与资源 */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
if (npf_create(&o, &n, err, sizeof err) != NPF_OK || npf_start(n) != NPF_OK)
    return 1;
/* ... npf_resource_put、npf_peer_create、npf_forward_create、npf_peer_setopt、
 *     npf_session_send、npf_media_open ... */
npf_destroy(n);
```

完整的示例见 `examples/device.c`（用型号凭证自动注册、发布一个网页、保持在线、把对端发来的数据原样发回）和 `examples/client.c`（按编号和口令连接设备，建一条本地转发）。对端、转发、资源都是带编号的类型化对象，设置用 `npf_peer_setopt` / `npf_forward_setopt` 一次改一项；库里没有它们的命令语法，命令行和界面由应用自己实现。

不经平台也能用：`NPF_ROLE_DIRECT` 加预共享密钥（Noise_NNpsk0），两端直接 UDP + AnLiu。

## 模块

安装的 SDK 只有 `npf.h`，不包含模块接口。模块是需要和 libnpf 源码一起构建的内部扩展机制（扩展命令、配置键、平台事件、状态字段和转发类型），内部头文件 `include/npf/` 不安装；只用连接、转发、应用数据或音视频时直接用 `npf.h` 即可，不需要模块。需要时见 [开发者指南](docs/design/libnpf.md)第 12 节。

## 目录

```
include/npf.h          公开接口（安装的 SDK 只有它）
include/npf/           内部接口（不安装；源码构建的模块用）
src/api/               npf.h 的实现：对象、事件、npf_setup、命令、模块
src/platform/          系统层、事件循环、日志、异步解析、VPN 绕行
src/crypto/            Noise、CPace、证书、SIV
src/proto/ src/ws/     JSON、DNS、HTTP、信令、WS 中转；WebSocket、TLS
src/ice/ src/punch/    NAT 探测、候选地址、PCP / NAT-PMP、打洞
src/node/ src/tunnel/  节点、会话、AnLiu、中转、隧道、UDP 转发、媒体、对端、资源
third_party/           AnLiu、Monocypher、mbedTLS、rxi/log
examples/              device.c、client.c：只用 npf.h 的设备与客户端
tests/                 单元测试、API 测试、模糊测试
cmake/、scripts/       构建选项；更新内置 AnLiu 的脚本
docs/                  信令协议、数据通道、NAT 穿透与安全设计，以及开发者指南（docs/design/libnpf.md）
```

## 许可

MIT，见 `LICENSE`。第三方：AnLiu（MIT）、Monocypher（CC0 / BSD-2-Clause）、mbedTLS（Apache-2.0）、rxi/log.c（MIT），各自的许可在 `third_party/` 下（rxi/log 的在源文件头里）。

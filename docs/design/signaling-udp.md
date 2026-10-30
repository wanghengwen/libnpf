# UDP 信令设计：UDP 优先，WebSocket 兜底

状态：v0.4.4（已实现：12.2 的第 0–6 步与之后的四项修正，2026-10-30）。日期：2026-10-30。变更记录见文末。

**线上格式与安全分析**在 [信令协议](../protocol/signaling.md)"UDP 承载"（封装、握手、传输、可靠层、CLOSE、计时、限额、服务器列表的 `udp`、选择与兜底）与 [安全设计](security.md) 7.6（威胁与对策）。本文只留设计理由（第 0–9 节）与实施记录（第 7、11、12 节）；两边不一致时以那两份为准。

服务器、集成测试与负载工具在 npf 仓库：文中的 `server/`、`cmd/`、`tests/integration/`、`tests/load/`、`tests/natlab/`、`scripts/`、`docs/testcases/` 等路径都指那里，`src/`、`include/`、`tests/unit/`、`tests/fuzz/` 指 libnpf。

依据：`int-w6` 的源码与文档：[信令协议](../protocol/signaling.md)（0.61 的空闲保活，`w7-ping` 的 `cd2158c`）、[安全设计](security.md) 7、[数据通道](../protocol/data-channel.md) 9、[打洞设计](nat-traversal.md) 6、npf 的备用分配设计（home-binding.md） 5.4、npf 的多服务器设计（multi-server.md）；`login` 瘦身（`w7-login`，进行中）。

用户要求（原话译）："服务器维持这些连接太重。信令改为 UDP 优先，WebSocket 作为兜底；先写设计文档。" v0.3 的要求："确保设计优雅简洁省资源。"

测试阶段不做兼容：WS 只作为兜底的承载留下，不为旧客户端保留任何东西。目标是代码少而安全，不留新的漏洞。

---

## 0. 结论与关键决定

| # | 决定 | 理由（详见各节） | 另一种做法 |
|---|---|---|---|
| D1 | 信令有**自己的 UDP 端口**（`sig_udp_listen`，默认 `:9940`），由 `internal/sigudp` 独占：自己的 socket、读协程与会话表；节点从**主 socket** 发出 | 与中转完全解耦：不共用提示表、没有分流顺序与碰撞，中转的代码一行不改，中转数据的突发也不挡信令；代价只是 APDM 的 NAT 上多一个映射，而信令本来就自己保活（第 8 节） | v0.2 的共用中转端口：只为"一个流一份保活"，合并保活去掉后这个理由没有了 |
| D2 | 端口上**没有类型字节**：报文要么以会话的 4 字节索引开头，要么是 6.2 封装的握手；密钥由服务器公钥派生 | 线上没有明文字段，不知道公钥的探测得不到回应（nat-traversal.md 6.1、6.7） | 用户提议的"首字节为类型"：成为指纹 |
| D3 | 握手照旧是 **Noise_XK**（prologue `npf-sigudp-v1`），一条 Noise 消息一个数据报；`npf_sig_hash` 照旧是握手哈希 | 与 WS 上的认证完全相同，只换承载；prologue 不同，两种承载的握手与注册签名互不混用 | IK（省半个往返）：要重新分析身份保密，不值得 |
| D4 | 封装的 tag 就是 WireGuard 的 `mac1`；**只在半开状态多时**要 cookie（`mac2`） | 平时握手 1.5 个往返；只有冲击或重启后大批重连时多一个往返 | 一直要 cookie：每次多一个往返，Happy Eyeballs 里 UDP 更难赢（4.3） |
| D5 | `SIG_HELLO` 长度在 [160, 256] 内均匀随机；服务器的应答**不长于**请求 | 不放大；长度不成为指纹 | — |
| D6 | 传输报文：节点 → 服务器 `srv_idx(4) \| ctr(8) \| AEAD`，服务器 → 节点 `ctr(8) \| AEAD`；64 个报文的防重放窗口 | 服务器要靠索引找会话（节点会换地址）；节点只有一个信令会话，按源地址就认得 | — |
| D7 | 自己写一个**小的可靠层**：16 位段号、**累计确认 + RTO**（只重传最早的未确认段，超时之后的部分确认立即重传下一个空洞，接收方留住乱序段）、窗口 32 段、收到段就确认；ping 就是一个空段 | 信令依赖顺序；瘦身后几乎所有消息一个数据报装得下（6.1），SACK、快速重传、延迟确认省不了多少却要代码 | KCP、QUIC、移植 AnLiu：见 6.3 |
| D8 | 数据报上限 **1200 字节**（与数据通道相同） | 瘦身后的 `login` 与平常的 `welcome` 都在一个数据报里；1400 只帮到首次登录，却有分片的风险 | 1400：见 6.1 |
| D9 | **漫游**：认证通过、计数器最新的报文改变会话的地址；没有路径验证 | 与 WireGuard 相同；能利用的只有路径上的攻击者 | QUIC 的路径验证：多一个往返与一套状态 |
| D10 | **保活只有一条规则，与 WS 相同**：节点在 `ping_s`（25 秒）里没有发出或没有收到东西时 ping；服务器只应答，60 秒没有收到就关闭 | 用户要的简单规则（signaling.md 0.61）；崩溃的服务器至多 35 秒被发现，与今天相同 | v0.2 的合并保活（靠备用分配的 T）：用户认为太复杂，去掉 |
| D11 | **选择**：今天的两个槽：UDP 先发，1 秒后 WS；先完成的留下；UDP 没有回音记一个标志（`udp_bad`），之后照今天连两个 WS；在 WS 上时每 10 分钟、空闲时试一次 UDP，成功就换过去 | Happy Eyeballs 的最小形式；不按网络保存（home-binding.md U16） | v0.2 的三个尝试、10 分钟的封禁时刻、看备用分配是否绑上 |
| D12 | 会话中 UDP 断了就是一次普通的断线重连；没有信令层的"续接" | 已建立的数据通道不受影响，与今天 WS 断线相同 | 信令续接：要在服务器上保留断开的会话 |
| D13 | 服务器：Conn 下面加一个**承载接口**（WS、UDP 两个实现），第一步单独合入、行为不变；`sigudp` 的读协程解密、重组，整条消息交给按需启动的分发协程；DH 在至多 N 个协程里做 | 处理函数会访问数据库与 Redis，不能在读协程里跑；空闲的会话没有协程、没有计时器 | 每会话常驻协程：就是今天的开销 |
| D14 | 每个空闲的 UDP 节点在服务器上约 **2–3 KB**（Conn 约 2 KB，UDP 会话约 0.5 KB），WS 估计 30–40 KB（第 0 步先测） | 没有 TLS、读缓冲、读协程与内核 TCP socket | — |
| D15 | 手机（iOS、Android）**只用 WS**（用户决定） | 前后台切换、系统收回 socket；手机的服务器开销不是这次要省的 | 前台用 UDP：将来再做 |
| D16 | npf-hosted、托管客户端（`udp_on_demand`、`sig_idle_ms`）与 CDN 接入点只用 WS；编译选项 `NPF_SIG_UDP`：桌面与设备的构建开，`build-hosted.sh`、`build-ios.sh`、`build-android.sh` 关（用户决定） | 托管服务按需断开信令、数量少；CDN 不转发 UDP；关掉的构建里没有 `sigudp.c` | — |

对用户方案的改动：第 1 点的"首字节为类型"改为 D2；第 2 点的 cookie 选"负载高时"（D4）；第 6 点的"续接"在信令里不存在（D12）；第 7 点不是"没有协程"，而是按需协程（D13）；第 9 点手机后台不需要 WS（D15）。

**不做的**（理由见括号里的节）：合并保活（8.2）；信令与中转共用端口（D1）；SACK、快速重传、延迟确认（6.2）；KCP、QUIC（6.3）；0-RTT、无状态复位、路径验证（security.md 7.6）；IPv6（第 13 节）；手机用 UDP（D15）；批量查询（`device_list`、`hosted_accounts`、`conn_report`、`pubconn_list`）改走 HTTPS：不做（用户决定），照旧走信令，多段消息由可靠层承担。

---

## 1. 背景

### 1.1 今天的连接

| 项目 | WSS 信令（今天） |
|---|---|
| 承载 | TCP + TLS 1.3 + WebSocket，内层 Noise_XK（prologue `npf-ws-v1`），一条 binary 消息一条 Noise 消息 |
| 建立 | TCP 1 + TLS 1 + WS 升级 1 + Noise 1.5 + `login` 1 ≈ 5.5 个往返（UDP：Noise 1.5 + `login` 1，`login` 紧跟第 3 条消息） |
| 保活 | 节点在 `ping_s`（25 秒）里没有发出或没有收到东西时 WS ping，之后 10 秒内要有服务器的消息，否则重连（`sig_expect`）；两个方向都有往来的连接不 ping。服务器每 2 分钟 ping 一次，只为 RTT 样本；60 秒收不到任何帧就断开（`readTimeout`） |
| 服务器上的开销 | 一个读协程、TLS 状态、WebSocket 的 4 KB 读缓冲、内核的 TCP socket；发送时按需起 flush 协程；估计 30–40 KB（未测） |
| 上限 | 默认每台服务器 20000 条（`connlimit.go`） |
| 现场 | 中美之间的 TCP 在北京时间下午常常停住（"signaling: ..., reconnecting (N B queued here, kernel send queue ...)"）：TCP 的队头阻塞。UDP 自己重传，没有这个问题（可能的好处，要实测确认，11.6） |

### 1.2 已有的、可以利用的

- **同一个进程**：npf-server 里有信令、中转、地址探测与服务器链路；后两者已经各有自己的 UDP 端口（`probe_listen`、`rlink_listen`），信令的端口照同样的方式配置与部署。
- **6.2 的通用封装**（nat-traversal.md 6.2）：`tag(12) \| ChaCha20(k_enc[dir], nonce = tag, P)`，C（`src/ice`）与 Go（`internal/natprobe`）都有实现。
- **客户端的信令层很窄**：`npf/sig.h`（`open / send / ping / close / last_rx / last_tx / diag / hash` 与 `on_ready / on_msg / on_down`），`src/proto/sig.c` 180 行；重连、选服务器、登录、保活在 `node_signal.c`；今天就同时连两个接入点（`n->sig`、`n->race`），先完成 Noise 握手的留下。
- **服务器的 Conn**（`conn.go`）只经 `read()`、`write()`、读写期限、`WriteControl` 用到 WebSocket；Noise 握手在 `Conn.handshake()`。
- **主 socket 的发送监视**（home-binding.md 5.4，`npf_udp_watch`）：主 socket 发往可能刷新备用分配映射的地方时，备用分配的应答带 `OTHER`。信令的端口对它只是"中转那个 IP 的另一个端口"，规则不用改（8.2）。

---

## 2. 总体结构

```
节点                                                 npf-server
┌───────────────────────────┐              ┌──────────────────────────────────────┐
│ node_signal.c             │              │ signaling.Conn（登录、呼叫……不变）      │
│   槽 1：UDP  槽 2：WS（1 s）│              │   └─ 承载接口 transport               │
│ npf_sig（sig.h）           │◄──WSS（兜底）─►│        ├─ wsTransport（WSS + Noise）   │
│   ├─ WS 后端（sig.c）       │              │        └─ udpTransport                │
│   └─ UDP 后端（sigudp.c）   │              │ sigudp（:9940，自己的 socket）         │
│ 主 socket ─────────────────┼──UDP─────────►│   握手、会话表、可靠层、扫描            │
│   （也发中转、打洞、AnLiu）  │──UDP─────────►│ relay（:9920，不变）                   │
└───────────────────────────┘              └──────────────────────────────────────┘
```

- 信令只是 Conn 的一种承载；JSON 消息、登录、闸门、限额、路由全部不变。
- 握手、加密、可靠层在新模块里：libnpf `src/proto/sigudp.c`，服务器 `internal/sigudp`（不依赖 `signaling` 与 `relay`）。

---

## 3. 线上格式

已移入 libnpf 的 [信令协议](../protocol/signaling.md)"UDP 承载"（分流、握手报文的封装、握手、长度、传输报文、可靠层、CLOSE、计时、限额、服务器列表的 `udp`、选择与兜底），本节只留设计时的理由。

- **没有类型字节**（D2）：端口上的报文要么以会话的 4 字节索引开头，要么是封装的握手。分流先查表，长度对时再解一次 ≤ 256 字节的封装（ChaCha20 与 SipHash，不到 1 µs）；端口上没有别的协议，不存在分流顺序与碰撞。节点一侧按源地址分：服务器的信令地址上不会来别的东西，所以没有"认证失败再往下交"的分支。
- **封装的密钥由服务器公钥派生**：不提供保密性（由里面的 Noise 负责），只做三件事：tag 就是 WireGuard 的 `mac1`（不知道公钥的探测得不到回应）、线上没有明文字段与 X25519 公钥的结构、长度随机。`type` 编号 11–13 不与 nat-traversal.md 6.2 的其他报文重复只为日志好读（标签不同，密钥本来就不同）。`ts_ms` 不检查时间窗：没有 RTC 的板子时钟可能不准，重放由 Noise 挡住。
- **`SIG_HELLO` 长度随机、应答不长于请求**（D5）：不放大，长度也不成为指纹。
- **cookie 用 BLAKE2b-128**（摘要长度参数 16，Go `blake2b.New(16, key)`，不是截断），按源地址与端口、2 分钟一档；节点按服务器地址保存 120 秒，重启后大批重连时后面的尝试一开始就带上，省一个往返。
- **第 3 条消息读失败不丢掉半开状态**：第 3 条消息先在当前握手密钥下解 `s` 的 AEAD，第 3 条消息丢了之后先到的 `login` 传输报文在这一步就失败，还没做 DH；服务器用的 flynn/noise 在读之前存检查点、失败时回滚，随后重发的第 3 条消息照样成功。只有持有节点 `e` 私钥的发起方能让 DH 之后的一步失败（坏了的只是它自己的握手），所以每个半开状态给 8 次而不是 1 次。读的时候留住紧跟其后的 `login`（至多 4 个）：否则它总要等一个 RTO。
- **等 DH 名额而不是丢弃**：负载测试（11.5，2000 个节点、每秒 5000 个冲击报文）里名额满时丢弃，重启后重连要 11 秒、冲击下正常的登录平均 370 ms；改为等名额后 0.5 秒、7 ms。等名额的协程不需要自己的队列：每个都占着一个半开状态（第 1 条消息）或是它唯一一次在读的第 3 条消息，个数受半开的上限约束；等到名额时半开状态已过期（5 秒）的就放弃。
- **半开状态不计入连接限额**：伪造源地址的报文不能占掉 WS 也要用的名额；接纳（`admit`）在第 3 条消息证明了回程之后。不接纳时发一个认证过的 `CLOSE busy`（31 字节，短于第 3 条消息），节点把它当作 UDP 不可用。
- **服务器 → 节点不带索引**（D6）：服务器要靠索引找会话（节点会换地址），节点只有一个信令会话，按源地址就认得。
- **漫游没有路径验证**（D9）：与 WireGuard 相同，能利用的只有路径上的攻击者（security.md 7.6）。
- **不换钥**：2⁶⁴ 个报文用不完，会话可以持续数天。

---

## 4. 握手的保护

### 4.1 每一步的代价

| 报文 | 服务器的代价 | 挡住它的 |
|---|---|---|
| 垃圾 | 一次查表；长度对时一次 ≤ 256 字节的解封装 | 封装 tag（`mac1`） |
| 知道公钥、伪造源地址的 `SIG_HELLO` | 一次 DH 与一次密钥生成（约 100 µs），一个半开状态 | 半开 ≥ 1024 时只得到 cookie；全局 4096 |
| 真实源地址的 `SIG_HELLO` | 同上 | 每源 IP 20 / 秒 |
| 第 3 条消息 | 一次 DH | 要有 `srv_idx` 与同一源地址：伪造者收不到 `SIG_HELLO_ACK`；每个半开状态只给一次机会 |

### 4.2 规则与常数

只有四个：每源 IP 令牌桶 20 / 秒（突发 100）；半开 ≥ 1024 时要 cookie；半开 ≥ 4096 丢弃；DH 同时至多 N 个（其余等名额，第 3 节）。

- 令牌桶限住了一个来源的 DH 速率（第 1 条消息与它唯一一次第 3 条消息，至多 40 次 DH / 秒），也就限住了它的半开状态（20 × 20 + 100 = 500），v0.2 另设的"每来源 32 个半开"因此不要了。令牌桶表的条目由扫描清除；伪造的来源在 cookie 模式下到不了令牌桶，表的大小也有界。
- 负载只看半开状态的个数：DH 在至多 N 个名额里做，等名额的协程受半开的上限约束，没有自己的队列，也就没有 v0.2 的"队列过半"与工作池。
- N 个 DH 名额让 DH 至多用一半的核；重启后 2 万个节点同时重连约 2 秒的 DH。

### 4.3 为什么不"一直要 cookie"

一直要 cookie 少一个分支，但每次连接多一个往返（中美之间约 200 ms），Happy Eyeballs 的 1 秒余量更紧。负载的判断只是一个计数，WireGuard 也是这样做的。伪造源地址的冲击下，正常节点多一个往返仍能连上，而不是被挤到 WS。

---

## 5. 会话的状态机

### 5.1 节点（`sigudp.c` 的一个会话）

| 状态 | 进入 | 定时 | 离开 |
|---|---|---|---|
| `HELLO` | `npf_sig_open_udp` | 第 1 条消息 0 / 0.5 / 1.5 / 3.5 秒 | `SIG_COOKIE` → 带 cookie 重发；`SIG_HELLO_ACK` 认证通过 → `FINISH`；7.5 秒 → `on_down(NPF_SIG_DOWN_NO_ANSWER, "udp: no answer")` |
| `FINISH` | 写出第 3 条消息，`on_ready` | 第 3 条消息按 RTO 重发 | 第一个传输报文 → `UP`；登录期限（20 秒，`node_signal.c`） |
| `UP` | | 可靠层的 RTO（只在有段在途时） | `CLOSE` → `on_down(NPF_SIG_DOWN_CLOSED, "closed: 原因")`（原因是 `busy` 时 `NPF_SIG_DOWN_BUSY`）；节点的看门狗（第 8 节） |

`on_ready`、`on_msg`、`on_down` 与 WS 后端相同，`node_signal.c` 看到的接口不变（加一个"承载是哪种"的查询）。两种承载在 `sig.c` 里共用一张操作表（`sig_int.h` 的 `sig_ops`）与同一个生命周期：`on_down` 只有一次，`npf_sig_close` 在任何地方（包括这条连接自己的回调里）都可以调用，内存在这条连接最外层的回调返回时释放（`npf/sig.h`）；节点按 `on_down` 的原因码（`npf_sig_down`）而不是原因文字判断 `busy`。`NPF_SIG_UDP` 关时没有 `sigudp.c`，`sig_noudp.c` 的 `npf_sig_open_udp` 返回 NULL。

### 5.2 服务器

| 状态 | 进入 | 离开 |
|---|---|---|
| 半开 | `SIG_HELLO` 处理完 | 第 3 条消息 → 已建立；扫描（10–20 秒）→ 丢弃 |
| 已建立 | 第 3 条消息、`admit` 通过 | 照今天的 Conn；15 秒内没有登录 → 关闭 |
| 关闭中 | `closeSoon`（拒绝登录的应答之后）、`replaced`、停机 | 发出的都被确认后（至多 1 秒）发 `CLOSE`，释放 |
| （结束） | 60 秒没有收到（扫描）、发送队列满、`CLOSE` | Conn 照今天的 `close()`：注销路由、连接记录；备用分配留着（U6） |

### 5.3 节点的连接选择（`node_signal.c`、`sigconn.c`）

规则见 signaling.md"UDP 承载"的"选择与兜底"。理由：

- 这是 Happy Eyeballs 的最小形式：UDP 先发，1 秒后同一服务器的 WS，先完成握手的留下。连接与它们的状态是一个状态机（`src/node/sigconn.c`，2026-10-30）：每个连接有一个角色（`MAIN` 在用的、`RACE` 旁边试的接入点、`MOVE` 登录中要接替的 UDP 会话、`OLD` 被它替换、等关闭的 WS），状态是 `IDLE`、`CONNECT`、`ONLINE`、`MOVE`、`TAKEN`（服务器接受了 `MOVE` 的登录）、`WELCOME`（被替换的 WS 先关了，等 UDP 的 `welcome`）；每个事件（就绪、断开、登录的应答、`replaced`、到期）一个函数，返回节点要做的事；四个期限（WS 的一秒、20 秒的登录、10 分钟的换回、旧 WS 的 10 秒）用一个定时器。
- `udp_bad` 只是一个标志，不按网络保存（home-binding.md U16）：它让 UDP 不通的网络照今天连两个 WS 接入点，不每次多等 1 秒；网络变化、主 socket 重开、任何一次 UDP 登录时清掉。v0.2 的三个尝试、10 分钟的封禁时刻、看备用分配是否绑上都去掉了。
- 换回 UDP 用"同一身份的新连接"（`replaced`）：服务器不需要新的消息，备用分配随旧连接释放、新连接照常 `home_open`（学习按身份，不丢）。只在空闲时换，换的那一刻没有在建立的呼叫、没有等应答的请求。
- 网络变化时 UDP 会话的回答期限是 3 秒（WS 8 秒）：UDP 会话这时多半已经不在，早一点重连。

---

## 6. 可靠层

### 6.1 消息有多大

v0.2 的实测（2026-10-29，21 个集成测试的 3645 条消息）：

| 分位 | p50 | p90 | p99 | p99.9 | 最大 |
|---|---|---|---|---|---|
| 明文字节 | 174 | 493 | 889 | 1294 | 1572 |

超过 1167 字节的只有登录：`welcome`（最大 1572）与 `login`（最大 1295）；其次是 `incoming` 983、`enroll` 969、`mapping_list` 963。

`login` 瘦身（`w7-login`，与 UDP 信令无关、WS 上同样省流量）：证书链只发叶子，节点不再发自己的证书，主机信息平时只发摘要、变了才发全文。之后 `login` 约 400–600 字节；平常的 `welcome`（不换证书、服务器列表不变）300–400 字节。实测各部分：证书 458、`server_list` 678（2 台服务器）、`probe_keys` 133、票据 40、其余约 110。只有首次登录、换证书、服务器列表更新时 `welcome` 超过一个数据报。

满页的列表（`device_list` 50 项、`hosted_accounts` 200、`conn_report` 100 项、`pubconn_list` 60、`mapping_list`）远远超过一个数据报，32 KB 的上限照旧。

**结论**：一个数据报是常态，可靠层按"一条消息一个段"写；分段要有，但很少走到，它的恢复可以慢一些，不必为它加 SACK 与快速重传。

- **1200 还是 1400**（D8）：取 1200。1400 也装不下首次登录的 `welcome`，平常的又不需要；而 1400 在 PPPoE 加隧道、IPv6 隧道、某些移动网络上会被分片或丢弃。1200 与数据通道（AnLiu `mtu_max`）相同，已经在这些网络上验证过。

### 6.2 可靠层的取舍

保证、发送、接收、ping 与 `CLOSE` 的规则见 signaling.md"UDP 承载"的"可靠层"与"CLOSE"。设计时的理由：

- **一条消息一个段是常态**（6.1）：可靠层按"一条消息一个段"写，单段消息不经重组直接交出；分段要有，但很少走到，它的恢复可以慢一些。
- **累计确认 + RTO，只重传最早的未确认段**，接收方留住乱序的段：重传最早的那一段之后，累计确认会越过已经收到的段。单段消息丢了是一个 RTO（与 TCP 在低速流上靠 RTO / TLP 恢复相同）。v0.3 到此为止，一个空洞一个 RTO：Mac 上 UT-41 的 `t_reliable`（内存里两个方向各丢 20 %，24 条消息约 56 段）40 次中位数 5.5 秒、最长 26.8 秒，20 次中有 1 次超过 30 秒的期限（Linux 上 40 次：中位数 5.2 秒、P95 20.4 秒、最长 28.8 秒）。所以加 NewReno 的**部分确认**（2026-10-30，两侧对称、线上格式不变）：超时之后，超时那时在途的段全部确认之前，前进了却没到头的 `ack` 立即重传新的最早段，k 个空洞是一个 RTO 加 k 个往返；之后 Linux 上 40 次中位数 1.4 秒、P95 7.8 秒、最长 15.3 秒（剩下的尾巴是重传本身或它的确认又丢了时 RTO 的翻倍），Go 的 `TestReliable`（20 % 丢包、乱序、重复，各 1000 条）模拟时间 30 次中位数 150 秒 → 59 秒。只在超时之后：平时一个 `ack` 只确认已到的段，不会引出多余的重传。SACK 与快速重传仍然不加：省下的不多，却要代码。
- **不做延迟确认**：省下的只是请求与应答之间的一个小报文，RTT 样本也因此干净。纯确认从不引出回应。
- **RTO 上限 1 秒**：节点的看门狗在一次 ping 之后等 10 秒；1 秒的上限让 ping 在 10 秒里至少发 8 次，两个方向各丢 20 %（一次来回失败的概率 0.36）时一次 ping 全部失败的概率约 3 × 10⁻⁴（v0.2 的 3 秒上限只有约 6 次，约 2 × 10⁻³，空闲 5 分钟有约 3 % 的机会误判断线）。死掉的会话每秒只多一个段。
- **窗口 32 段**：一条 32 KB 的消息（29 段）一次发完；不做拥塞控制：信令的速率很低。处理慢的一方以收件箱（服务器 64 条）限住对方，不另设流控。
- **ping 就是一个空段**：可靠层负责重传，对方的确认就是回答，不需要单独的标志与重发逻辑；`npf_sig_last_rx` / `last_tx` 的含义不变，`node_signal.c` 的保活与看门狗不用改。服务器从不主动 ping，只在回答里每 2 分钟至多一次带一个自己的空段取 RTT 样本（对应 WS 上每 2 分钟一次的服务器 ping）。
- **`CLOSE` 发一次、不确认**：丢了由看门狗兜底。拒绝登录之后先等错误应答被确认（至多 1 秒）再发，与 WS 上"先应答、再关闭"相同。

### 6.3 为什么自己写

| 做法 | 问题 |
|---|---|
| AnLiu 移植到 Go | 7550 行 C 的多流 ARQ 与拥塞控制；信令只要一个低速的有序消息流 |
| 服务器上用 cgo 调 AnLiu | 每会话的 AnLiu 状态（窗口、缓冲）比要省下的还大 |
| QUIC | 服务器每条连接又是几十 KB；设备要 TLS 1.3 的 QUIC 栈，两层加密 |
| KCP（ikcp，C 约 1900 行；Go 用 kcp-go 的移植约 1100 行） | 考虑过，用户选了自己的小 ARQ：`ikcp_create` 为每个会话预先分配约 3.7 KB（10 万会话约 370 MB），空闲的会话也要每 10–100 ms 调 `ikcp_update`，两处都要改它的代码；两份上游要跟；它没有认证，外面照样要本节的封装。本节的做法不预先分配缓冲、空闲时没有计时器、C 与 Go 是同一份设计 |
| 每条消息停等 | 一次来回只能送一条：`call` 的应答、`call_accepted`、`punch_start` 连着到时，第三条要等两个来回 |
| 本节的做法 | C 约 150 行、Go 约 150 行（signaling.md"可靠层"），两边对称，便于对照测试 |

---

## 7. 服务器的结构

### 7.1 承载接口（第 1 步，行为不变）

```go
// transport carries one connection's messages, plaintext JSON both ways, in order.
type transport interface {
	send(msg []byte) error // one message; WS: written now (flush's goroutine), UDP: queued to the session
	close(graceful bool)   // graceful: what was sent goes out first (closeSoon)
	remote() netip.AddrPort
	rtt() time.Duration    // 0: not known yet
}
```

- Conn 不再有 `ws`、`tx`、`rx`：WS 的握手、`read`/`write`、ping / pong、读写期限移到 `wsTransport`（新文件 `wstransport.go`，基本是从 conn.go 搬过去的代码）。握手哈希、对方静态公钥由承载建 Conn 时给出。
- 读循环的主体变成 `c.input(pt []byte) bool`（解析、登录前的闸门、`dispatch`），由承载调用：WS 在自己的读协程里，UDP 在分发协程里（7.2）。
- 登录期限改为 Conn 自己的计时器（`time.AfterFunc`），不再借 WS 的读期限；WS 登录后的 60 秒读期限与 2 分钟的 RTT ping 留在 `wsTransport`。
- `flush` 与 `outQ` 不变，`writeOut` 改调 `t.send`；`where()` 改用 `t.remote()`（UDP 漫游后是新地址），`c.addr` 保留为接入时的地址（连接限额按它计数与释放）。

### 7.2 UDP（`internal/sigudp`）

- **socket**：`sig_udp_listen` 的每个地址一个 socket、一个读协程，收缓冲 4 MB（重启后的大批 `SIG_HELLO`）。不加 SO_REUSEPORT：10 万个空闲节点约 4 k 个报文 / 秒（第 8 节），一个读协程绰绰有余。
- **会话表**：`map[uint32]*session`，自己的锁；半开状态与已建立的会话在同一张表里（同一个索引空间），半开状态另按节点的 `e` 索引（去重重发的第 1 条消息）。
- **读协程**：查表、AEAD 解密（1 KB 约 1–2 µs）、防重放、可靠层（确认、重组）；完整的消息放进会话的收件箱，没有分发协程在跑就起一个，它取完收件箱就结束（与 Conn 按需起 flush 同一个模式）。一个会话的消息仍按顺序处理。
- **写**：从这个会话的报文进来的那个 socket 发出（`WriteToUDPAddrPort`，并发安全）。
- **计时**：每个会话一个计时器，只在有段在途或关闭中时开着；半开状态由 1 秒一次的扫描清除，一个 10 秒的扫描处理其余一切：60 秒没有收到的会话、令牌桶。没有延迟确认、没有服务器的 ping，空闲的会话不占计时器。
- **握手**：DH 在至多 N 个名额里（4.2），由每个握手自己的协程等名额，不阻塞读协程。

### 7.3 每个节点的内存（估计）

| 部分 | WS | UDP |
|---|---|---|
| Conn（信令状态，800 字节的结构，加 `pending` map、主机信息、NAT 画像） | 约 2 KB | 同左 |
| 承载 | 读协程的栈（至少 8 KB）、TLS 状态与记录缓冲、WebSocket 结构与 4 KB 读缓冲、`net.Conn`；内核的 TCP socket（数 KB） | 会话约 0.5 KB：两把密钥、计数器、防重放窗口、可靠层的计数、地址、索引、表项；队列与重组缓冲只在用时存在 |
| 合计 | 估计 30–40 KB（第 0 步先测） | 约 2–3 KB |

**实测（第 0 步，2026-10-29，`tests/load/sigudp-load.sh`，工具 `server/tools/sigload`）**：本机（12 核，WSL2）一台 npf-server，匿名客户端从 127.20.x.y 经 WSS 登录后空闲（安静 25 秒时 ping）；服务器的堆（GC 之后的 HeapInuse）、协程栈与 RSS，减去开始前、除以连接数：

| 连接数 | 堆 / 连接 | 协程栈 / 连接 | 协程 / 连接 | RSS / 连接 | 握手与登录 |
|---|---|---|---|---|---|
| 5 000 | 17.6 KB | 8.4 KB | 1 | 35.7 KB | 3000 / 秒 |
| 20 000 | 17.4 KB | 8.2 KB | 1 | 34.3 KB | 4200 / 秒 |

RSS 不含内核的 TCP socket（每条约 2–3 KB，未测）；匿名客户端的 Conn 比设备的小（没有记录快照、主机信息），两种承载的差别不受影响。

**UDP 实测（第 3 步，同一台机器、同样的客户端，`sigload udp`）**：

| 连接数 | 承载 | 堆 / 连接 | 协程栈 / 连接 | 协程 / 连接 | RSS / 连接 | 握手与登录 |
|---|---|---|---|---|---|---|
| 5 000 | WSS | 18.4 KB | 8.4 KB | 1 | 38.1 KB | 3000 / 秒 |
| 5 000 | UDP | 2.9 KB | 0 | 0 | 5.8 KB | 5000 / 秒 |
| 20 000 | WSS | 17.8 KB | 8.2 KB | 1 | 36.3 KB | 3650 / 秒 |
| 20 000 | UDP | 2.7 KB | 0 | 0 | 4.7 KB | 6400 / 秒 |

每个空闲节点的服务器内存从约 36 KB 降到约 5 KB（RSS），比估计的 2–3 KB 多的是堆的余量；空闲的 UDP 会话没有协程、没有计时器。

`max_conns`（默认 20000）此后只限 WS；UDP 另有 `max_udp_conns`，默认 200000，按负载测试（11.5）再定。

---

## 8. 保活与存活检测

### 8.1 一条规则

与 WS 相同（signaling.md 0.62，D10）：节点在连接 `ping_s`（25 秒）里没有发出或没有收到东西时 ping（一个空段），之后 10 秒内要收到东西，否则重连，崩溃的服务器至多 25 + 10 = 35 秒被发现；服务器只应答，60 秒没有收到就关闭（10 秒的扫描：60–70 秒）；计划内的重启、停机有 `CLOSE`，立即发现。代码就是今天的 `ping_cb` 与 `sig_expect`。

NAT 的 UDP 映射短于 25 秒的少见（RFC 4787 要求至少 2 分钟）；遇到时由服务器下发的 `ping_s` 调小，不按备用分配的 T 调（不与中转耦合）。

### 8.2 代价，与备用分配的关系

- **信令本身**：10 万个空闲节点约 4 k 个 ping / 秒加 4 k 个应答（加每 2 分钟一次的 RTT 样本约 0.8 k），线上约 61 / 55 字节，各方向约 2 Mbps，约一个核的 1–2 %。
- **备用分配**：信令从主 socket 发往服务器的 IP，按 home-binding.md 5.4 的现有规则，EIM 与 ADM 的节点的备用分配应答因此带 `OTHER`，中转不调高 T，T 停在起点 25 秒（或换到 UDP 之前已学到的值）：这些节点的中转也约 25 秒 ping 一次，10 万个节点再多约 4 k + 4 k 个报文 / 秒，合计约一个核的 3–4 %、各方向约 4–5 Mbps。规则本身是对的：这时信令确实保住了那个映射，中转的 ping 是多余的但无害；APDM 的节点上信令与备用分配是两个映射，T 照常学。`home.c` 与中转都不用改。
- v0.2 的合并保活（信令靠备用分配学到的 T）每个节点每 T 秒只有一对报文，但要 `SpareSeen`、服务器的 `max(60, T + 20)`、节点的模式判断与 `PONG` 上的 `OTHER`，崩溃的发现时间长到约 170 秒。用户选了简单的规则。是否还要省掉中转那份多余的 ping，见第 13 节的问题。

### 8.3 手机

手机只用 WS（D15）：iOS、Android 的构建关掉 `NPF_SIG_UDP`。后台照今天（ios.md、android.md），切到后台时 `home_close`（home-binding.md 9.7）。

---

## 9. 安全

已移入 libnpf 的 [安全设计](security.md) 7.6（不变式、威胁与对策、不做的）。设计时的要点：认证与加密只靠 Noise_XK，与 WS 上完全相同，UDP 只是另一种承载；服务器的每个应答不长于请求或发往证明过的地址；伪造源地址的报文占不了连接限额；可靠层与 JSON 只见到通过 AEAD 与防重放的明文。0-RTT、无状态复位、路径验证不做（理由在 security.md 7.6）。

---

## 10. 可观测性

### 10.1 节点

| 日志 | 何时 |
|---|---|
| `signaling: connecting to server 17 udp 203.0.113.5:9940 (ws after 1 s)` | 开始连接 |
| `signaling: server 17 over udp (handshake 182 ms)` / `over ws (udp: no answer)` | 选定 |
| `signaling: udp did not answer, using ws; udp again in 10 min` | `udp_bad` 置位 |
| `signaling: server 17 busy, handshake with a cookie` | 收到 `SIG_COOKIE` |
| `signaling: moving to udp` / `signaling: on udp, ws closed` | WS 换到 UDP |
| `signaling: udp session lost (closed: <原因>)` | 收到 `CLOSE`（看门狗的断线照今天的一行） |
| `npf_logt`：重传、RTT、漫游 | 跟踪 |

- `npf_sig_diag`（断线日志里的括号）在 UDP 上为 `udp: in flight 3, queued 0, srtt 180 ms, rto 400 ms, retrans 12, last rx 5 s ago`。
- `npf status --json`：`server_via`（`udp` / `ws`）、`server_rtt_ms`、`udp_sig`（`ok`、`no_answer`、`off`）；文字版在服务器一行后面写 `via udp`。

### 10.2 服务器

- 登录日志加承载：`signaling: node login 123456789 account=... from 1.2.3.4:5678 via udp`。
- 连接记录（`store.ConnRecord`）加 `via`；`npf-admin conns` 显示它；`multi` 的连接元数据用当前地址。
- 每 5 分钟一行：`sigudp: stats sessions=… halfopen=… hello=… hello_ok=… cookie_sent=… cookie_ok=… rate_drop=… full=… dh_busy=… auth_fail=… replay=… moved=… retrans=… close_idle=… close_peer=… junk=… rx=… tx=…`（计数是这 5 分钟的；`full`：半开 ≥ 4096 丢掉的 `SIG_HELLO`，`dh_busy`：等了名额的 DH，`junk`：既不是会话的也不是 `SIG_HELLO` 的数据报）；停机时再写一行。

---

## 11. 测试

### 11.1 单元（Go，`internal/sigudp`）

| 用例 | 检查 |
|---|---|
| 握手 | 正常建立；握手哈希、对方公钥与 Noise 一致；prologue 不同的握手失败 |
| 重发去重 | 同一个第 1 条消息重发：一次 DH，同样的 Noise 第 2 条消息 |
| cookie | 半开 ≥ 1024：没有 cookie 得到 `SIG_COOKIE` 且不建状态；带上后建立；错的、过期两档的、换了源地址的不行 |
| 不放大 | 随机长度的请求：每个应答 ≤ 请求；长度区间外的不解密 |
| 限额 | 令牌桶、全局 4096、DH 名额满时丢弃、扫描清除半开、第 3 条消息换了源地址被拒、一个半开只给一次第 3 条消息 |
| 防重放与漫游 | 重复、窗口外、乱序（窗口内）；更大的计数器从新地址来：地址改变；旧的从新地址来：不改、不更新 `last_rx` |
| 可靠层 | 种子固定的 20 % 丢包加乱序加重复，两个方向各 1000 条消息（含 32 KB 的）：按序、恰好一次；单段消息不经重组；窗口外的段丢弃；超过 32768 字节关闭会话；空段只确认不交出；只重传最早的段、RTO 上限 1 s（假时钟），超时之后的部分确认立即重传下一个空洞（只在超时之后）；16 位段号绕回 |
| 分流 | 垃圾、`SIG_HELLO`、第 3 条消息、传输报文在一个 socket 上各归其位 |
| 存活 | 60 秒没有收到的会话被扫描关闭（假时钟）；`CLOSE` |

另有 `signaling` 包里的 `udpTransport` 测试：登录、拒绝登录后先收到错误应答再收到 `CLOSE`、`replaced`、停机的 `CLOSE`、2 分钟一次的 RTT 样本。

### 11.2 单元（C，libnpf `tests/unit/test_sigudp.c`）

与 Go 对称：握手（用 libnpf 自己的 Noise 作 responder 写一个测试服务端，约 100 行）、cookie、`txid` 不对的应答不认、丢包乱序的可靠层、分段、ping 在有段在途时不另发、`CLOSE`、防重放、只收服务器地址来的报文。

### 11.3 模糊测试

- Go：`FuzzSigUDPInput`（任意报文送给监听者与一个已建立的会话）。
- C：`tests/fuzz/fuzz_sigudp.c`（`npf_sig_input` 在每个状态下）。

### 11.4 集成（`tests/integration/sigudp.sh`，进 `check.sh`）

1. 设备与客户端经 UDP 登录（`server_via udp`），呼叫、转发照常；`model.sh` 的一型一密注册在 UDP 上通过。
2. `NPF_TEST_WS_FILE`（客户端没有 UDP）：1–2 秒内改用 WS；去掉之后 10 分钟内（测试里调短）空闲时换回 UDP，进行中的转发不断。
3. `NPF_TEST_UDP_FAIL`（主 socket 失效、重开、换端口）：会话漫游，不重新登录（`logins` 不变）。
4. 服务器冻结（SIGSTOP，同 `sigfail.sh`）：35 秒内重连。
5. 服务器停机再启动：`CLOSE` 后重连。
6. `sig_udp off`：只用 WS。其余集成测试默认在 UDP 上跑，`wsswitch.sh` 与本脚本的第 2、6 条覆盖 WS。

**第 6 步的结果**（2026-10-30，docs/testcases/scripts/sigudp.md 的 SU-01 – 10，约 90 秒，进 `check.sh`）：第 1 条的一型一密改为在 `model.sh` 里查（MD-01 要求 `over udp`），第 4 条另见 `sigfail.sh`（`ping_s` 5 秒，信令同样在 UDP 上），不重复。连续 4 次全部通过：去掉 UDP 后 1.01 秒在 WS 上登录（UDP 没有回音、1 秒后的 WS），文件删掉后约 1.7 秒换回 UDP（`NPF_TEST_SIG_UDP_AGAIN_MS` 3 秒），`logins` 不变，30 MB 下载完整、一个会话；主 socket 重开后漫游，停机时服务器的统计 `moved=1`；`ping_s` 25 秒时冻结的服务器 34 秒被发现，解冻后约 1 秒经 UDP 重新登录；停机的 `CLOSE` 让节点立即重连。

各集成脚本的信令承载：`dev-env.sh` 的列表带 `udp`，所以 loopback、control、model、udp、mapping、tun、callsetup、upgrade、upgradeinstall、punch、media、sources、homebind、resume、sigfail、wsswitch、many、start、installer、sigudp 的节点都在 UDP 上（wsswitch 与 sigudp 的一部分故意换到 WS）；files.sh 没有平台服务器（直连）；`lib.sh` 的 `two_servers` 给第二台服务器也加了 `udp`。仍在 WS 上的：`pin`（`server =`，测试用的单个服务器覆盖，没有 `udp`）钉住服务器的节点（multi.sh、rlink.sh）与 mesh.sh 的 devD；sigfail.sh 的第 4 条故意去掉 `udp`；npf-hosted 与托管客户端（hosted*.sh、quota.sh，D16）；`NPF_NO_UDP` 的客户端（loopback、media、udp、rlink、quota、wsswitch 的一部分）。natlab 见 11.5：除 `home` 的设备（`sig_udp = off`）与 NL-42（信令端口被丢弃）外都在 UDP 上，WS 经 TCP、不经 natsim。

### 11.5 natlab 与负载

| 用例 | 设置（`natsim.py` 新增 `--loss P`、`--drop IP:PORT,...`） | 通过 |
|---|---|---|
| `sig-udp-blocked` | `--drop` 平台的信令端口 | 经 WS 登录、`udp_sig: no_answer`；呼叫照常走 UDP 中转（端口是分开的） |
| `sig-loss20` | 两个方向 `--loss 0.2` | 30 秒内登录；5 分钟内会话不失效；呼叫成功 |
| `sig-nat30` | `--timeout 30` | 空闲 10 分钟后呼叫照样立即到达设备 |
| `sig-roam` | `renat`（NAT 重启，外部端口变了） | 不重新登录；25 秒之内呼叫能到达设备 |

natlab 里主机的 TCP 不经 NAT，UDP 经过：有了 UDP 信令，现有用例的信令也经过 natsim，要重新核对它们的时间。

**第 6 步的结果**（2026-10-30，docs/testcases/scripts/natlab.md 的 NL-42 – 46）：

- **natlab 原来一直在 WS 上**：平台的 `sig_udp_listen` 是 `:19940`，通配地址上的应答由内核选源地址，回给 NAT 的公网地址 198.51.100.x 的报文就从 198.51.100.x 发出（目的地址在本机），natsim 按 APDF 过滤掉，节点只认服务器地址来的报文：所有节点 `udp: no answer`、改用 WS（第 5 步合入后的 natlab 全部通过，但信令一个都没走 UDP）。改为与中转、探测相同，绑在公网地址上（`203.0.113.1:19940`）。真实部署中有几个本机地址的服务器同样要按地址写 `sig_udp_listen`（只有一个地址、在云主机 1:1 NAT 后面的服务器不受影响；之后服务器改为从节点发往的地址应答，不必再写，见下面"第 6 步之后的四项"第 2 项）。
- 之后现有用例的信令都经过 natsim：除下面两处外时间与改前（WS）在波动之内。`udp-lost`（NL-36）：设备的 UDP 全部丢弃时信令也断了，请求 WS 中转要等信令的看门狗（距服务器最后一次应答至多 35 秒）、改连 WS 后重发（`node_calls_relogin`），移到 WS 中转从中转无声后的 10 秒变成约 17 秒，丢弃后至多约 37 秒，等待从 30 秒放宽到 45 秒。`home`（NL-14 – 18、22）的设备改设 `sig_udp = off`：UDP 信令从主 socket 每 25 秒一个 ping，EIM 的映射由它保住，备用分配的应答都带 `OTHER`，中转停在 25 秒（8.2 预期的行为），那几个用例要测的学习就不发生了；新用例 NL-46 `home-sigudp` 测的正是这个。
- 新用例：`sig-udp-blocked`（NL-42，WS 约 1.0 秒后登录，呼叫照常走 UDP 中转）；`sig-loss20`（NL-43，两个方向各丢 20 %：1 秒内登录，第一次是 WS 抢先、`NPF_TEST_SIG_UDP_AGAIN_MS` 20 秒后换回 UDP；空闲 120 秒（慢用例 300 秒）没有断线；呼叫约 6 秒取到页面）；`sig-nat30`（NL-44，映射寿命 30 秒，空闲 150 秒（慢用例 600 秒）后呼叫约 1 秒取到页面）；`sig-roam`（NL-45，NAT 重启换端口：不重新登录，`incoming` 约 20 秒后到达设备，即它下一个 ping 之后）。三个长的与其后的用例同时进行，natlab 合计约 12 分钟（`NATLAB_SLOW=1` 约 20 分钟）。全量跑了 3 次（一次 `NATLAB_SLOW=1`：`home-sigudp` 被告知的间隔为 25、45，没有过期与重新绑定），第三次 `sig-loss20` 发现节点的一个问题：换回 UDP 时 `welcome` 丢了、被替换的 WS 先关闭，节点当成断线（libnpf `node_signal.c` 已改，UT-41 加了这个情形），修正后 `sig-loss20` 又跑 4 次通过；修正后又跑了两次全量，最后一次全部通过。`s2b-busy`（S2B 加端口噪声）在 5 次全量里有 2 次 40 秒内没有直连（每一轮都什么也没收到）；单独跑时 UDP 信令 16 次失败 1 次、信令设 `sig_udp = off` 18 次全部通过。这个用例以前就偶发（实现说明第 1 步的记录），当时找不到 UDP 信令影响它的途径（平台规划只用信令地址的 IP），留作待查（原因见下面"第 6 步之后的四项"第 1 项）。

**第 6 步之后的四项**（2026-10-30，分支 `sigudp-fu`）：

1. **`s2b-busy` 的偶发失败不是信令映射造成的**。natsim 记下每个映射（`--verbose 100000`）后看：信令的映射在登录时建一次、之后一直有效（每 25 秒的 ping），探测与打洞期间没有新建，"信令从主 socket 发往新目标、占去顺序 NAT 的端口"的猜想不成立。失败的每一次都是**一侧的步长测成了 2**（真实是 1）：端口分配的 4 个请求原来相隔约 50 ms，NAT 每秒被别的连接占 10 个端口，三个间隔都被占过时最小的差值是 2（每侧约 6 %）；S2B 按错的步长预测，一轮的成功率只剩约 10–20 %（模型），4 轮全落空，每一轮都什么也没收到。UDP 信令只是让它更常见：同时在主 socket 上收发时，请求实际相隔约 64 ms（按占去的端口数估计；WS 信令时约 48 ms），步长测错的 20 次里有 6 次（WS 20 次里 2 次）。改为 4 个请求在 15 ms 内发出（libnpf `natprobe.c` 的 `ALLOC_SPREAD_MS`，nat-traversal.md 4.2）。单独跑 `s2b-busy`：改前 UDP 信令 20 次失败 3 次（都是步长测错），WS 信令 20 次失败 1 次（同样）；改后 UDP 信令 30 次全部直连，步长没有一次测错（请求实际相隔约 9 ms）。
2. **通配地址上从节点发往的地址应答**：新包 `server/internal/udpsock`（Linux 上 `IP_PKTINFO` / `IPV6_PKTINFO`，每个本机地址一个回复路径，按需建立；只有通配地址的 socket 才读控制消息），UDP 信令、中转（`relay_udp`，同样有这个问题：`relay_public` 列出几个地址而 `relay_udp` 是 `:9920` 时，绑定的应答与转发都从路由选的地址发出）、地址探测（`probe_listen`）都用它；服务器链路（`rlink`）照旧（它的对端只认 `rlink_addr`，主动发出的也要从那里发，通配地址上要另想办法）。`sig_udp_listen` 默认的 `:9940` 在有几个地址的机器上也可以用了（deploy.md）。测试 GO-126 与 GO-97、GO-122 的通配地址情形（127.0.0.1 与 127.0.0.2）。`callsetup.sh` 的节点原来同样因此退到 WS，CS-02、CS-03 用只在 TCP 上的延迟让信令变慢，改后 CS-03 失败；它的主叫改设 `sig_udp = off`。
3. **UDP 断了时更快改用 WS**：一个呼叫依靠的直连或 UDP 中转无声时（路径管理的判定），节点立即 ping UDP 信令，3 秒没有回答就置 `udp_bad`、立即改连 WSS（`node_sig_udp_check`，与网络变化共用一个检查），登录后呼叫重发 `relay_switch`。natlab `udp-lost`（NL-36）：改前（3 次）中转无声后 16.6–18.7 秒、丢弃后约 30 秒移到 WS 中转；改后（5 次）10.0 秒、约 22 秒，回到信令在 TCP 上时的数字（约 10 秒）。等待从 45 秒收回到 35 秒。
4. **可靠层的部分确认**（Mac 上 UT-41 的 `t_reliable` 20 次超时 1 次）：见 6.2。`t_reliable` 在 Linux 上 40 次：改前中位数 5.2 秒、P95 20.4 秒、最长 28.8 秒；改后 1.4 秒、7.8 秒、15.3 秒，30 秒的期限不变。

**负载**（`tests/load/sigudp-load.sh`，工具 `server/tools/sigload`：Go 的 initiator，来源取回环的多个 127.x.y.z）：5 万个 UDP 会话与 5 万个 WS 连接分别登录到一台 npf-server，量每个连接的堆与 RSS；空闲时的 CPU 与报文率（第 8 节的估计）；握手吞吐与延迟；重启后的大批重连（进入 cookie 模式，全部在若干秒内登录）；伪造的 `SIG_HELLO` 冲击期间正常的握手仍然成功。

第 3 步的结果（2026-10-29，本机 12 核、WSL2，按这台机器的余量只到 2 万）：内存与握手速率见 7.3；**重启后的大批重连**：2 万个 UDP 会话，服务器停机（`CLOSE shutdown`）再启动，全部重新登录用了 5.0 秒，其中 18976 个经 cookie（半开到了 1024），没有一次握手失败；**冲击**：每秒 2 万个有效的 `SIG_HELLO`（知道公钥、第 1 条消息正确，从 256 个来源发出、从不继续）持续 20 秒，同时 500 次正常登录全部成功、平均 3 ms（497 次经 cookie），半开停在 1024，服务器约 40 % 个核。

### 11.6 真实网络（agent 执行，docs/testcases 新增 RN 用例）

两台平台服务器与几台真实网络上的节点，一半 UDP、一半 `sig_udp off`，连续 48 小时，跨两个北京时间的下午：比较 `reconnecting` 次数、信令 RTT、呼叫建立时间；确认 1.1 里中美之间下午的停顿在 UDP 上是否消失。测试服务器的防火墙已开放 9940。

---

## 12. 实施

### 12.1 改动的文件

**服务器（npf `server/`）**

| 文件 | 改动 |
|---|---|
| `internal/signaling/conn.go` | 承载接口、`input()`、登录计时器；去掉 `ws`、`tx`、`rx`、ping / pong |
| `internal/signaling/wstransport.go`（新） | WSS 上的 Noise 握手、读循环、ping / pong、期限（从 conn.go 搬来） |
| `internal/signaling/udptransport.go`（新） | Conn 与 `sigudp` 会话的连接、`admit` |
| `internal/signaling/server.go`、`connlimit.go` | 配置 `sig_udp_listen`（默认 `:9940`，`off` 不开）、`max_udp_conns`；接上 `sigudp`；停机时 `CLOSE`；UDP 的计数 |
| `internal/signaling/login.go`、`records.go`、`multi.go`、`internal/store` | 连接记录的 `via`；`where()` 用当前地址 |
| `internal/sigudp/`（新）：`handshake.go`、`session.go`、`reliable.go`、`listener.go`、`initiator.go`（测试与负载工具用）、`stats.go` | 第 3–7 节 |
| `cmd/npf-server/main.go`、`cmd/npf-admin/main.go` | 起 `sigudp`；`conns` 显示 `via` |
| `tools/sigload/`（新） | 负载工具 |
| `deploy/ansible`、`docs/deploy.md`、`deploy-prod.md` | 防火墙开 UDP 9940、配置项、签名列表的 `udp` |

中转（`internal/relay`）与备用分配（`home.go`）不改。

**libnpf（`client/lib`，先提交到 libnpf，再移动子模块）**

| 文件 | 改动 |
|---|---|
| `include/npf/sig.h`、`src/proto/sig.c` | `npf_sig_open_udp`（发送回调、服务器地址）、`npf_sig_input`、`npf_sig_via`；两个后端的分派（WS 部分不变） |
| `src/proto/sigudp.c`（新） | 握手、cookie、传输、防重放、可靠层 |
| `src/node/node_signal.c` | 槽 1 的 UDP、1 秒后的 WS、`udp_bad`、10 分钟的换回、不是当前连接的 `replaced`、3 秒的醒来 ping |
| `include/npf/node.h`、`src/node/node_internal.h`、`msgs.h`、`msgs.c`、`node_servers.c` | 服务器列表的 `udp`、状态字段 |
| `src/node/call.c` | `node_udp_input` 先比较信令服务器的地址 |
| `src/node/node_network.c`、`src/node/conf.c`、`src/api/status.c` | 网络变化通知；`sig_udp = auto \| off`；`server_via`、`server_rtt_ms`、`udp_sig` |
| `tests/unit/test_sigudp.c`、`tests/fuzz/fuzz_sigudp.c`、CMake（`NPF_SIG_UDP`） | 11.2、11.3 |
| `docs/protocol/signaling.md`、`docs/design/security.md`、`architecture.md` | 线上格式与安全分析移入（实现之后） |

`home.c` 不改（8.2）。

**npf 其余**：`client/modules/cli_basic.c`（`via udp`）、`tests/integration/sigudp.sh`、`scripts/check.sh`、`tests/natlab/natsim.py`、`natlab.sh`、`tests/load/sigudp-load.sh`、`docs/testcases/`（README、用例、`scripts/testcases-check.py`）、`docs/implementation.md`；`build-hosted.sh`、`build-ios.sh`、`build-android.sh` 关 `NPF_SIG_UDP`。

### 12.2 步骤（每步单独可合入）

| 步 | 内容 | 合入后的行为 |
|---|---|---|
| 0 | `tools/sigload` 的 WS 部分：量今天每个 WS 连接的内存 | 不变；得到 7.3 的基准 |
| 1 | 服务器的承载接口（7.1），WS 是唯一的实现 | 不变（全部现有测试通过） |
| 2 | `internal/sigudp`：握手、cookie、会话、可靠层、initiator，单元与模糊测试；不接线 | 不变 |
| 3 | 服务器接线：`sig_udp_listen`、`udpTransport`、限额、连接记录、统计、停机 `CLOSE`；`sigload` 的 UDP 部分与负载测试 | 服务器接受 UDP 信令；还没有客户端用它 |
| 4 | libnpf `sigudp.c` 与 `sig.h`，C 单元与模糊测试 | 不变 |
| 5 | libnpf 节点：服务器列表 `udp`、选择与兜底、换回、`node_udp_input`、状态与日志、`sig_udp`；npf：`sigudp.sh`、`check.sh`、`npf status`；签名列表加 `udp`、开防火墙并部署 | 节点 UDP 优先 |
| 6 | natsim 与 natlab 用例、真实网络用例（11.6）、文档移入 libnpf、implementation.md | 不变（2026-10-30 完成，结果见 11.4、11.5） |

### 12.3 改动量（估计）

| 部分 | 代码 | 测试 |
|---|---|---|
| 服务器：承载接口（第 1 步） | 约 +150 / −110（多为搬动） | 0（现有测试） |
| 服务器：`internal/sigudp`（握手与 cookie 200、会话与传输 80、可靠层 150、监听 / 扫描 / 统计 120、initiator 90） | 约 640 | 约 550（单元 500、模糊 50） |
| 服务器：接线（`udpTransport` 100、配置 / 限额 / 记录 / 停机 / main 70） | 约 170 | 约 150 |
| 负载工具与脚本 | 约 300 | — |
| libnpf：`sigudp.c`（握手与 cookie 110、传输与防重放 50、可靠层 150、接口 40） | 约 350 | 约 400（单元 350、模糊 50） |
| libnpf：节点（`node_signal.c` 100、服务器列表 25、`node_udp_input` 10、其余 30） | 约 165 | — |
| npf：集成与 natlab（`sigudp.sh` 180、natsim 30、natlab 用例 90、`npf status` 10） | 约 10 | 约 300 |
| **合计** | **约 1490**（加负载工具约 1790） | **约 1400** |

**服务器部分的实际行数**（第 0–3 步，2026-10-29；行数含注释，括号里是去掉注释与空行的）：

| 部分 | 代码 | 测试 |
|---|---|---|
| 承载接口（第 1 步：`conn.go`、新的 `wstransport.go` 192（162）） | +255 / −197（多为搬动） | 0（现有测试，测试辅助改 7 行） |
| `internal/sigudp`：`handshake.go` 336（285）、`peer.go`（会话与传输、可靠层的收发、关闭）338（287）、`reliable.go` 205（169）、`listener.go`（表、分流、扫描、统计）355（284）、`initiator.go` 244（208） | 1478（1233） | 1121（单元 1082、模糊 39） |
| 接线：`udptransport.go` 103（79）、`connlimit.go` +43 / −18、`server.go` +18、记录与 `npf-admin` 约 10 | 约 175 | 165 |
| 负载工具 `tools/sigload` 576 与 `tests/load/sigudp-load.sh` 107 | 683 | — |

`sigudp` 比估计的 640 多一倍：等名额与过期检查、读第 3 条消息期间留住的报文、统计行、监听者的套接字与关闭、各处的注释；initiator 带 cookie 与第 3 条消息的重发。

v0.2 是约 1900（加负载工具 2200）与 1630：去掉的主要是合并保活（`SpareSeen`、`home.c`、模式判断）、中转端口上的分流与提示空间、SACK 与快速重传、延迟确认、单独的 PING、工作池。

---

## 13. 用户的决定与待定的问题

**已决定**（2026-10-29）：

1. **保活只有一条规则**（v0.3）：与 WS 相同，节点在一个方向安静 `ping_s` 时 ping，服务器只应答；崩溃的服务器至多 35 秒被发现。v0.2 接受的"合并模式下至多约 170 秒"随合并保活一起去掉。
2. **默认开**：第 5 步之后，带 UDP 信令的构建默认 UDP 优先（`sig_udp = auto`），真实网络用例（11.6）发现问题再关。
3. **只支持 IPv4**：信令的 UDP 地址只有 IPv4；只有 IPv6 的节点走 WS。
4. **npf-hosted 与手机只用 WS**：编译选项 `NPF_SIG_UDP`（CMake，默认 ON）在托管服务与 iOS / Android 的构建脚本里关掉（D15、D16）；关掉时 `sig_udp` 照常解析、只能是 `off`，`udp_sig` 为 `off`。
5. **`login` 瘦身**另做（`w7-login`，WS 上同样省流量）：只发证书链的叶子，节点不再发自己的证书，主机信息平时只发摘要（6.1）。
6. **批量查询不改走 HTTPS**：照旧走信令。
7. **不用 KCP**：用自己的小 ARQ（6.3）。

8. **EIM / ADM 节点上中转那份多余的 ping**（8.2）：接受，什么都不做；负载测试（11.5）若显示它要紧，再按这里原来写的最小办法（中转在备用分配的地址与信令会话的当前地址相同、且信令 T 秒内收到过报文时跳过 ping）处理。
9. **开始实现**（2026-10-29）：按 12.2 的步骤。

## 变更记录

| 日期 | 版本 | 内容 |
|---|---|---|
| 2026-10-30 | 0.4.4 | 5.3：连接的选择写成一个状态机（`sigconn.c`），单元测试 `test_sigconn.c` |
| 2026-10-30 | 0.4.3 | 按一份外部评审整理客户端的信令层：两种承载一张操作表、一个生命周期（5.1），`on_down` 带原因码 `npf_sig_down`；`on_ready` 只表示我方的握手做完（服务器靠应答确认）。线上格式不变 |
| 2026-10-30 | 0.4.2 | 从 npf 的 docs/design 移入 libnpf 的 docs/design；去掉测试主机的名字 |
| 2026-10-30 | 0.4.1 | 第 6 步之后的四项（11.5）：`s2b-busy` 的失败是端口分配的步长测错（请求在 15 ms 内发出）；服务器在通配地址上从节点发往的地址应答（`udpsock`，中转与探测同样）；呼叫的 UDP 路径无声时立即检查 UDP 信令、3 秒没有回答就改用 WSS；可靠层的部分确认（6.2） |
| 2026-10-30 | 0.4 | 实现完成（第 6 步）：线上格式与安全分析移入 libnpf 的 signaling.md"UDP 承载"与 security.md 7.6，第 3、9 节与 5.3、6.2、8.1 只留理由；11.4、11.5 记下第 6 步的结果（natlab 原来一直在 WS 上：通配地址的应答源地址不对） |
| 2026-10-29 | 0.3.1 | 用户的决定：多余的 ping 接受（第 13 节第 8 条）；开始实现 |
| 2026-10-29 | 0.3 | 按"优雅简洁省资源"评审：信令改用自己的 UDP 端口（`sig_udp_listen`，默认 `:9940`），去掉与中转共用的提示空间与分流；保活改为与 WS 相同的空闲规则，去掉合并保活（`SpareSeen`、`max(60, T + 20)`、`OTHER` 的新用法），崩溃发现回到 35 秒；可靠层改为累计确认 + RTO（只重传最早的段，RTO 上限 1 s），去掉 SACK、快速重传、延迟确认、`DATA` 与 `PING` 标志，ping 是一个空段，段号 16 位；服务器 → 节点的报文去掉 `node_idx`；握手去掉 `ver`、每来源 32 个半开、工作池与队列、最近 4 个 `txid`，cookie 只看半开个数，cookie 用 BLAKE2b；选择改为今天的两个槽加 `udp_bad` 标志与 10 分钟一次的换回；6.1 按 `login` 瘦身改写；用户的决定：HTTPS 不做、不用 KCP；重估改动量 |
| 2026-10-29 | 0.2 | 用户的决定：接受合并模式的发现时间、默认开、只支持 IPv4、npf-hosted 与手机只用 WS（编译选项 `NPF_SIG_UDP`）；`login` 瘦身另做 |
| 2026-10-29 | 0.1 | 初稿：中转端口上按提示表分流、6.2 封装的握手（公钥派生的 `mac1`，负载高时 cookie）、Noise_XK（`npf-sigudp-v1`）、显式计数器与防重放、可靠层（单段快速路径、SACK、RTO、30 秒失效）、漫游、Happy Eyeballs 与换回、与备用分配合并保活、服务器的承载接口与按需分发协程；消息大小的实测（6.1） |

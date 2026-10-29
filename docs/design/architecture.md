# libnpf 目标架构

文档版本：0.1（草案，待评审）。日期：2026-10-28。依据：libnpf `ee2f0f7`（现场测试中的版本）。

本文是 libnpf 逐步重构的依据：先写清现在的结构和问题（第 1 节），再给出目标的分层与接口（第 2 节）、各部分的状态机（第 3 节）、定时方式（第 4 节）、信令消息的描述表（第 5 节）、测试钩子（第 6 节）、库的边界（第 7 节），最后是分步迁移的计划（第 8 节）和不做的事（第 9 节）。重构是渐进的：每一步单独合入、单独现场测试，不做整体重写。

凡是说到现在代码的地方都给出 `文件:函数`，路径相对于 `client/lib/src`（另注明的除外）。行数、个数都是在 `ee2f0f7` 上数出来的，第 1.1 节说明了怎么数。第 1、3 节的位置是 `ee2f0f7` 上的：第 1a 步之后 `call_path.c` 的内容在 `path_direct.c`，`call_relay.c` 的客户端部分在 `path_udp.c`、路径之间的决定在 `path_mgr.c`（`relay_gave_up` 改名 `call_relay_gave_up`），`call_ws.c` 在 `path_ws.c`；第 1b 步去掉了 `call_check_p2p`、`call_check_relay`（第 2.4 节"1b 的实现"）；第 1c 步去掉了 `call_relay_gave_up`、`ws_wait_done`、`call_ws_wait_end`、`call_ask_ws_relay`、`call_standby_done`、`pm_standby_start`、`path_ws.c:ws_elsewhere`、`call.c:npf_node_ws_calls_udp_back` 与 `npf_node_calls_to_ws`，路径之间的决定都在 `path_mgr.c:pm_decide`，向平台的请求都经 `call_need`（第 3.6 节"1c 的实现"）；第 1d 步把呼叫的 8 个定时器合成一个（`call.c:call_tick`，`anl_timer`、`timeout_cb`、`punch_timer`、`linger_done`、`direct_retry`、`pm_timer`、`ws_reconnect` / `ws_pair_late` 的定时器、`relay_keepalive_timer` 变成各部分的截止时间与 tick），去掉了 `relay_bind.c` 的 `relay_bind_run`、`relay_bind_probe`（第 4 节"1d 的实现"）；第 2 步给绑定器与备用分配写了显式的状态与一个截止时间（第 3.3、3.4 节"2 的实现"）；第 3 步给呼叫与打洞写了显式的状态（第 3.1、3.2 节"第 3 步的实现"），去掉了 `call.c:call_relay_leave`、`call_accept_seen`、`call_close_quiet`、`call_punch.c:call_start_punch_now`、`call_punch_sockets_back`；之后的瘦身（第 8 节"瘦身实际"）去掉了 `npf_th`、`pm_dead`、`pm_has`、`path_direct_gone`、`call_relay_send_data`、`call_ws_send`、`direct_alive`、`anl_after_input`、`punch_end` 与路径操作表的 `name`。第 4、5 步把收到的信令与隧道控制消息改为按描述表解析（第 5 节，`call.c:node_dispatch`、`call_find`、`relay_bind.c:relay_obj_parse` 去掉，分发在 `node/msgs.c:node_msg`），配置键收进一张表（第 7.1 节，`conf.c` 的 `known_keys` 等与 `cmd.c` 的 `settable` 去掉）；第 7 步把 npf 自己的键移到 npf 的模块（模块的键也是 `npf_key` 表），`api/npf_int.h` 并入 `npf/module.h`（第 7.1 节"第 7 步的实现"）。协议细节见 [信令协议](../protocol/signaling.md)、[数据通道协议](../protocol/data-channel.md)，库的接口见 [libnpf 开发者指南](libnpf.md)。

## 1. 现状

### 1.1 规模

| 目录 | 文件 | 行数 | 内容 |
|---|---|---|---|
| `api` | 21 | 6 094 | npf.h 的实现：库线程与 `npf_runtime`、实例（`engine*.c`）、配置来源、事件、对象操作（`ops*.c`）、命令、模块注册、发布的资源 |
| `node` | 38（31 个 .c） | 15 426 | 节点：信令、服务器列表、UDP 套接字与 NAT、备用分配、呼叫（握手、传输、路径、打洞、中转）、对端与转发、local.json、npf.conf、媒体流、UDP 转发 |
| `tunnel` | 6 | 2 657 | 隧道：子链路帧、流控、SOCKS5、速率组、虚拟本地端 |
| `platform` | 9 | 3 759 | 事件循环、系统层、日志、异步解析、绕过 VPN、主机信息 |
| `proto` | 5 | 1 442 | JSON 解析与写出、信令连接、WS 中转连接、HTTP、DNS |
| `crypto` | 6 | 1 258 | Noise、CPace、证书、SIV、基础密码学 |
| `ice` | 4 | 1 181 | 地址探测（`BIND_REQ`）、本机候选、NAT 探测、路由器端口映射 |
| `ws` | 3 | 1 156 | WebSocket 与 TLS |
| `punch` | 1 | 984 | 打洞执行器 `punch_ev.c` |

`src` 合计 33 969 行，`node` 占 45 %；连同 `include` 的 3 879 行，`node` 约占 41 %。

本文其他数字的数法：结构体成员按顶层声明的名字计（同一行声明的多个名字分别计，内嵌的结构体数组算一个）；`npf_json_get*` 计 `npf_json_get`、`_str`、`_int`、`_b64` 四个函数在 `src/proto/json.c` 之外的调用；拼 JSON 的 `snprintf` 计格式串以 `{\"` 开头的调用。

| 项目 | 现在 |
|---|---|
| `struct npf_call`（`node/call_internal.h`） | 112 个成员，12 个 `npf_timer *`，另有 `relay.t_bind`（`relay_c` 里）；约 29 个充当状态的标志或时间戳 |
| `struct npf_node`（`include/npf/node.h`） | 131 个成员，11 个 `npf_timer *` |
| `c->ws_mode` 的判断 | 26 处，7 个文件 |
| `c->caller` 的判断 | 47 处（另有 `x->` 4、`u->` 17、`t->` 9，合计 78 处 `->caller`） |
| `npf_json_get*` | 224 处；其中信令处理器（`node_signal.c`、`call*.c`、`home.c`、`relay_bind.c`）约 140 处 |
| 拼 JSON | `snprintf` 22 处（14 个文件）；`npf_jw` 9 个文件（16 处 `npf_jw_init`） |
| 测试开关 | 25 个环境变量（22 个 `NPF_TEST_*`、3 个 `NPF_NO_*`），35 处 `getenv`，13 个文件 |

### 1.2 `src/node` 的文件

| 文件 | 行 | 做什么 | 目标层（第 2 节） |
|---|---|---|---|
| `node.c` | 171 | 节点的初始化、启动、停止；地址格式化 | 信令客户端 |
| `node_signal.c` | 1 133 | 信令连接、登录、注册、重连、请求与应答、`call_end` 队列、按需信令 | 信令客户端 |
| `node_servers.c` | 296 | 签名的服务器列表、接入点选择 | 信令客户端 |
| `sources.c` | 222 | 服务器列表的外部渠道（DoH、HTTPS） | 信令客户端 |
| `node_network.c` | 423 | UDP 主套接字、重开、网络变化的检查 | 网络（节点） |
| `nat.c` | 403 | NAT 画像与候选，`nat_report` | 网络（节点） |
| `nodemap.c` | 275 | 路由器端口映射（PCP、NAT-PMP） | 网络（节点） |
| `home.c` | 582 | 备用分配（home-binding.md） | 路径（中转绑定） |
| `relay_bind.c` | 238 | 中转分配的绑定器（呼叫与备用分配共用） | 路径（中转绑定） |
| `relay_data.c` | 117 | `RELAY_DATA` 的封装与验证 | 路径（UDP 中转） |
| `call.c` | 866 | 呼叫的状态、结束、信令分发、节点的数据报分发、对所有呼叫的操作 | 呼叫 |
| `call_handshake.c` | 443 | 端到端握手（IK、PAKE、grant），被叫闸门 | 呼叫 |
| `call_punch.c` | 689 | 打洞的轮次、难侧套接字预算、`punch_result` / `punch_update` | 呼叫（打洞） |
| `call_path.c` | 261 | 直连的检查（`PATH_CHECK`）、可疑与失效、中转热备 | 路径 |
| `call_relay.c` | 476 | UDP 中转客户端、无声检查、去 WS 中转的决定 | 路径 |
| `call_ws.c` | 206 | WS 中转作为 AnLiu 的载体 | 路径 |
| `call_transport.c` | 861 | AnLiu 连接、conv 表、隧道回调、控制消息、媒体与 UDP 的适配、调用方密钥份额 | 会话 |
| `call_reverse.c` | 321 | 反向映射（`-R`） | 流上的服务 |
| `call_direct.c` | 417 | 不经平台的直连（NNpsk0） | 呼叫（直连）+ 路径 |
| `callee.c` | 713 | 被叫的本地状态（口令、配对、锁定、所有者、吊销，state.json） | 身份 |
| `media.c` | 328 | 媒体流 | 流上的服务 |
| `udpfwd.c` | 876 | UDP 转发 | 流上的服务 |
| `peers.c` | 1 033 | 对端对象、主动会话、重连 | 对端（SDK 服务） |
| `peers_forward.c` | 911 | 转发规则、监听、重试 | 对端（SDK 服务） |
| `peers_connections.c` | 367 | 公开映射的连接准入与计数 | 对端（SDK 服务） |
| `peers_demand.c` | 258 | 按需会话的等待队列、空闲 | 对端（SDK 服务） |
| `peers_none.c` | 203 | `NPF_PEERS=OFF` 时的空实现 | 对端（SDK 服务） |
| `resources.c` | 323 | 发布的资源 | 流上的服务（策略） |
| `local.c` | 508 | local.json | 持久化 |
| `conf.c` | 377 | npf.conf 的读取、已知键 | 配置 |
| `setup.c` | 191 | `npf_node_cfg_from_conf`、种子文件、编号、平台错误文字 | 配置 |

头文件 7 个，938 行：`call_internal.h`、`node_internal.h`、`relay_bind.h`、`home.h`、`media.h`、`udpfwd.h`、`peers_internal.h`。

### 1.3 主要对象

| 对象 | 定义 | 拥有 | 定时器 | 隐含的状态（标志） |
|---|---|---|---|---|
| `npf_t` | `api/npf_int.h` `struct npf` | 配置（`conf`、`lc`）、身份、`callee`、事件循环、`npf_node`、`npf_peers`、资源、直连监听、会话与媒体编号表、模块 | 无 | `started`、`running`、`stopping`、`ended`、`torn_down`、`end_stage` |
| `npf_node` | `include/npf/node.h` | 信令（`sig`、`race`）、服务器列表、UDP 套接字、NAT 画像与候选、端口映射、`home`、`calls`、`conv_tab`、密钥份额 | `t_reconnect`、`t_ping`、`t_expect`、`t_login`、`t_idle`、`t_wake`、`t_pm`、`t_udp_reopen`、`t_nat_retry`、`t_watch`、`t_netcheck` | `online`、`dormant`、`sig_refused`、`replaced_ms`、`expect_probed`、`nat_valid`、`nat_udp`、`nat_again`、`nat_quick`、`login_waits_nat`、`repunch_on_nat`、`udp_waiters`、`test_no_udp` |
| `npf_call` | `node/call_internal.h` | 握手（`hs`）、密钥、AnLiu 连接与数据流、隧道、媒体、UDP 流、打洞（`punch`、`pcfg`）、UDP 中转（`relay`）、直连（`p2p_*`）、WS 中转（`wsr`）、反向监听、控制请求 | `t_anl`、`t_timeout`、`t_punch`、`t_linger`、`t_ws_wait`、`t_pcheck`、`t_standby`、`t_rcheck`、`t_direct`、`t_wsflush`、`t_wsre`、`t_free`，`relay.t_bind` | `state`、`ended`、`accepted`、`keys_ready`、`peer_hello`、`up_told`、`p2p`、`p2p_owned`、`p2p_suspect`、`standby_check`、`path_ready`、`ws_mode`、`ws_paired_once`、`ws_fail_wait`、`relay.active`、`relay.bound`、`relay_asked_ms`、`relay_retried`、`relay_waits_ports`、`relay_ports_waited`、`punched`、`punch_wait_keys`、`flush_pending`、`peer_closed`、`secure`、`direct`、`hosted_grant`… |
| `relay_c`（绑定器） | `node/relay_bind.h` | 一个中转分配：`relay_id`、`alloc_key`、两套密钥、最多 4 个地址、cookie、`kseq`、最近 8 个 `RELAY_BIND` | `t_bind`：未绑定时是 700 ms 的重发（`relay_bind.c:run_timer`），绑定后是 25 s 的保活（`call_relay.c:relay_keepalive`） | `active`、`bound`、`cur`、`tries`；"绑定中" = `!bound && t_bind`（`call_relay.c:call_check_relay` 的注释） |
| 备用分配 `npf_home` | `node/home.c` | 一个 `relay_c`、中转看到的地址 R、学习状态 | `t_dog`、`t_retry`、`r.t_bind` | 显式的 `enum {H_OFF … H_TAKEN}`，另有 `opening`、`lost`、`newnet`、`backoff` |
| `npf_peers` / `npf_peer` | `node/peers_internal.h` | 对端、转发（`pfwd`）、公开映射的连接、按需队列 | 对端 `t_retry`、`t_demand`、`t_ready`、`t_free`；转发 `t_retry`、`t_accept`；全体 `t_save`、`t_idle` | `waiting`、`renewing`、`finished`、`removed`、`keep`、`call_pinned`、`pin_refused`、`by_account` |
| `npf_tunnel` | `tunnel/tunnel_internal.h` | 子链路、控制通道、策略、速率组 | `t_rate`、`t_virt`；每条子链路 `t_connect`、`t_greet`、`t_he`、`t_gone` | 子链路的状态是显式的（`SL_*`） |
| `npf_media` | `node/media.c` | 一个会话的媒体流（各是 AnLiu 半可靠流） | 无 | — |
| `npf_udpf` | `node/udpfwd.c` | 一个会话的 UDP 流 | `t_tick` | — |
| `npf_punch` | `punch/punch_ev.c` | 一轮打洞的套接字与探测 | 一个 `tick`，排在 `next_due()` 算出的时刻 | `sprayed`、`nom_sent`、`have_valid`、`finished` |
| `npf_wsr` | `proto/wsrelay.c` | WS 中转连接（Noise_XK、`relay_bind`） | `t_ping`（25 s） | `ready`、`bound`、`paired` |

### 1.4 数据流

**建立**（已配对的主叫，UDP 可用）：

| # | 主叫 | 被叫 |
|---|---|---|
| 1 | `call_handshake.c:call_start`：`call_new`（`t_timeout` 25 s）、IK 消息 1，发 `call`（带 `nat`、`cand`） | |
| 2 | `call` 的应答：`call.c:node_dispatch` → `call_relay.c:call_relay_setup` → `relay_take`（是备用分配时 `home.c:node_home_adopt` 交出绑定）→ `call_relay_rebind` | `incoming`：`call_handshake.c:call_handle_incoming` → `incoming_ik` → `call_finish_handshake` → `call_transport.c:call_start_transport`（密钥、AnLiu、隧道）→ 应答 → `call_relay_setup` → `call_path_up` → `call_hello` |
| 3 | `call_accepted`：`call.c:call_accept_seen`（`t_timeout` 重新计 25 s）→ `call_handshake.c:call_caller_accepted` → `call_start_transport` → `call_relay_setup`（同一份分配：保留）→ `call_relay_early_feed` | |
| 4 | 自己的 `hello` 发出即 `ESTABLISHED`（`call_transport.c:call_hello`、`npf_tunnel_open_early`） | 主叫的 `hello` 到：`call_transport.c:tun_ready` → `ESTABLISHED`，发 `call_established` |
| 5 | `punch_start`：`call_punch.c:call_handle_punch_start` → `t_punch` → `call_start_punch_now`（没有密钥时 `punch_wait_keys`）→ `npf_punch_new` | 同左；被叫在这里 `call_accept_seen` |
| 6 | `call_punch.c:punch_done`：`p2p = 1`、`t_linger`、`t_standby`，`call_path_up`；`call_transport.c:anl_out` 改走直连 | 同左 |
| 7 | 30 s：`call_path.c:call_standby_done` → 没有往返过就 `standby_check`（`PATH_CHECK`）→ 有回应：`relay.active = 0`，主叫发 `relay_release` | 同左，不发 `relay_release` |

**换路径**：

| 起因 | 代码路径 |
|---|---|
| 直连无声 | `call_transport.c:anl_timer` → `call_path.c:call_check_p2p` → `call_p2p_suspect_start`（两条路都发；中转已释放时 `relay_switch{udp}`，未绑定时重绑）→ 回应：恢复；10 s：`call_p2p_drop` → `call_punch.c:call_punch_report("path_lost")`，或中转也不通时 `call_relay.c:call_ask_ws_relay` |
| UDP 中转无声 | `anl_timer` → `call_relay.c:call_check_relay`（依赖它时每秒）→ `call_relay_rebind` → 都不答：`relay_gave_up` → 五个分支之一（第 3.6 节） |
| 改用 WS | `call_ask_ws_relay` → `relay_switch{ws}` → 平台的 `relay_switch{relay}` → `call_relay_setup` → `call_ws.c:call_ws_setup`（`call_relay_leave`、`call_p2p_drop`）→ `wsr_paired` → `call_ws_carrier`（`ANL_CARRIER_STREAM`）|
| 回到 UDP | `nat.c:probe_done`（上一次探测无回应、这一次有）→ `call.c:npf_node_ws_calls_udp_back` → `relay_switch{udp, nat}` → `call_relay_setup` → `call_ws_leave`（`ANL_CARRIER_DGRAM`）→ 绑定 |
| 网络变化 | `node_network.c:node_net_check` → `call.c:npf_node_check_paths`（直连进入可疑）、`home.c:node_home_net_change`、`repunch_on_nat` → `nat.c:nat_settled` → `call_punch.c:node_calls_punch_report("network")` |

**结束**：

| 起因 | 代码路径 |
|---|---|
| 本地 | `call.c:npf_call_end`：先 `npf_node_call_end`（排队的 `call_end`），再在控制通道发 `close`，`CLOSED`，`call_ended`（`call_ctl_fail_all`、`call_timers_stop`、`t_free`）→ 下一轮 `call_free` |
| 对方 | `call_transport.c:call_control("close")` → `peer_closed = 1` → `npf_call_end` |
| 平台 | `call_ended` / `call_rejected` / `call` 的错误应答 → `call.c:call_close_quiet` |
| 传输 | `call_transport.c:anl_timer`：`anl_state < 0` → `transport_lost`；`tun_broken` → `error`；数据流关闭 → `closed` |
| 超时 | `call.c:timeout_cb`（主叫先 `node_sig_probe`） |
| 信令断开 | `call.c:node_sig_lost`：未建立的结束，已建立的继续 |
| 套接字失效 | `call.c:npf_node_calls_lost_fd` |

### 1.5 结构问题

"相关的现场问题"一列里，"10-27 (n)" 指 npf 的 `docs/implementation.md` 第 461 行（libnpf 代码评审的修正）的第 n 条，"int-1031" 指第 468 行（int-1031 现场测试发现的问题）。

| # | 问题 | 代码 | 相关的现场问题 |
|---|---|---|---|
| P1 | **路径没有对象**。往哪发由 `call_transport.c:anl_out` 按 `ws_mode`、`p2p`、`p2p_suspect`、`relay.active` 现场决定；显示的路径名由 `call.c:npf_call_path` 按同一组标志、另一种顺序推出；`api/ops.c:npf_path_code` 再把字符串解析回 `NPF_PATH_*`（1a 时核对：两处的先后实际上等价，没有发错过，风险只在结构上） | `anl_out`、`npf_call_path`、`npf_call_path_label`、`npf_path_code` | — |
| P2 | **四套健康判断，规则各不相同**：直连 3 s / 2 RTO、空闲 20 s、500 ms 检查、10 s 判定（`call_path.c:call_check_p2p`）；UDP 中转 3 s / 2 RTO、空闲 10 s、从第一个地址重绑（`call_relay.c:call_check_relay`）；备用分配 T + 4.5 + 5 s（`home.c:dog_check`）；WS 中转只看 TCP 断开，每 2 s 重连、不放弃（`call_ws.c:call_ws_failed`），连接本身没有无声检测（`proto/wsrelay.c:ping_cb` 发 ping，`npf_ws_last_rx` 只有信令在用） | 同左 | 已绑定的 UDP 中转从不检查（int-1031，`call_check_relay` 是事后补的） |
| P3 | **"向平台要什么"散在 7 处**，请求没有截止时间：`call_relay.c:call_ask_ws_relay`、`call_path.c:call_p2p_suspect_start`、`call_ws.c:call_ws_failed`、`call.c:npf_node_ws_calls_udp_back`、`call_path.c:call_check_p2p`（`path_lost`）、`call_path.c:call_standby_done`（`relay_release`）、`call_punch.c:call_punch_report`。`relay_asked_ms` 只挡住 10 s 内的再请求（`call_relay.c:call_relay_ask_ok`），没有谁在 10 s 后补发 | 同左 | `relay_switch` 只发一次（10-27 (2)） |
| P4 | **状态藏在"定时器存在与否"里**：`accepted` 与 `t_timeout`（`call.c:call_accept_seen`）；`relay.t_bind` 未绑定时是重发、绑定后是保活；`t_ws_wait` 存在 = "等这一轮打洞决定是否去 WS"（`call_punch.c:punch_quiet`、`call_relay.c:call_ws_wait_end` 都看它） | 同左 | `accepted` 依赖 `t_timeout`（10-27 (1)）；备用分配 BACKOFF 没有定时器（10-27 (6)，`home.c:node_home_login` 现在特意保留 `t_retry`） |
| P5 | **"每个呼叫一次"的标志从不复位**：`relay_retried`、`relay_ports_waited`、`punched` 只置位（`call_relay.c:relay_gave_up`、`call_ws_wait_end`，`call_punch.c:punch_done`）。同一会话第二次失去中转（例如 `udp_back` 之后再断）时，"再试一次""等端口""等这一轮打洞"三个分支都被跳过 | 同左 | — |
| P6 | **定时器多、检查挂在 AnLiu 的定时器上**：每个呼叫 12 个定时器加 `relay.t_bind`；`call_check_p2p`、`call_check_relay` 在 `call_transport.c:anl_timer` 里调用，另有 `t_pcheck`、`t_rcheck`、`t_standby`、`t_ws_wait` 各自补上 | `call_internal.h` | — |
| P7 | **节点级事件对每个呼叫各写一遍筛选**：`call.c:npf_node_check_paths`、`npf_node_ws_calls_udp_back`、`npf_node_calls_to_ws`、`npf_node_calls_lost_fd`，`call_punch.c:call_punch_sockets_back`、`node_calls_punch_report`、`call_port_pressure`、`call_hard_punches` | 同左 | 打洞结束后 WS 会话变成"直连"（10-27 (5)，`call.c:call_relay_leave` 现在结束打洞） |
| P8 | **JSON 手写**：224 处 `npf_json_get*`；两种写法（`snprintf` 22 处、`npf_jw` 9 个文件）；必需字段与范围由各处理器自己检查（signaling.md "JSON 与 C 解析约束"自己也这么写），例如 `call_punch.c:call_handle_punch_start` 缺 `punch_id` 时静默返回 | 同左 | — |
| P9 | **测试钩子散落**：35 处 `getenv`，5 个在 `node.c:npf_node_init` 读一次，其余每次用到都读（`call_path.c:call_no_p2p` 每个 `punch_start`，`call_punch.c:write_pressure` 每个结果） | 第 6 节 | — |
| P10 | **配置绕弯**：npf.conf、`npf_setup`、`overrides`、local.json 的 `settings` 都变成"键 = 字符串"合并（`api/engine_config.c:config_load`），`npf_setup` 先转成键（`api/setup.c`），再由 `node/setup.c:npf_node_cfg_from_conf` 解析回结构（22 次 `npf_conf_get`）；库认得 npf 程序自己的键（`node/conf.c` `known_keys` 里的 `control`、`control_token`、`web_dir`、`log`、`pidfile`、`keep_awake`、`hosted_ports`） | 同左 | — |
| P11 | **大结构体**：`npf_call` 112 个成员、`npf_node` 131 个，任何文件都能改任何字段 | — | — |

### 1.6 可以沿用的做法

- `punch/punch_ev.c:next_due` + `schedule`：一个对象一个定时器，排在下一件事的时刻，只在提前时重排。第 4 节就是把它推广到呼叫。
- `call_transport.c:anl_after_input`：每个数据报之后只在 AnLiu 要求更早时才动定时器，热路径上不做多余的堆操作。
- `home.c` 的显式状态枚举、`call_hs`（握手状态在密钥就绪后整体释放）、`relay_bind.c` 的共用绑定器、AnLiu 的 `ANL_OPT_CARRIER`（换载体不换连接）。

## 2. 目标结构

### 2.1 分层

```
  npf.h（公开 API）   npf/module.h（模块钩子）
        │                    │
  ┌─────┴────────────────────┴──────────────┐
  │ API 与 SDK 服务：实例、配置、local.json、对端与转发、命令、事件 │
  └─────┬───────────────────────────────────┘
        │ npf_call_*（会话句柄）
  ┌─────┴──────────┐   ┌──────────────────────────────┐
  │ 流上的服务      │   │ 呼叫（平台眼中的会话）            │
  │ 隧道 / 转发、媒体、│   │ call_id、接受、打洞轮次、中转分配、请求 │
  │ UDP 转发、-R    │   └───────┬───────────────┬──────┘
  └─────┬──────────┘           │ need / told    │ add / remove
        │ 流                    │               │
  ┌─────┴──────────────────────┐ ┌──────────────┴─────────────┐
  │ 会话：AnLiu 连接、密钥、流（控制、 │◄┤ 路径：路径对象 + 路径管理器       │
  │ 数据、媒体、UDP）、载体         │ │ 直连 / UDP 中转 / WS 中转        │
  └────────────────────────────┘ └──────────────┬─────────────┘
                                                │ 套接字、绑定器
  ┌─────────────────────────────────────────────┴──────────┐
  │ 身份与信令客户端；网络（UDP 套接字、NAT、端口映射）；备用分配         │
  └────────────────────────────────────────────────────────┘
```

| 层 | 拥有 | 不应知道 |
|---|---|---|
| 身份与信令客户端 | 身份、证书、服务器列表与外部渠道、信令连接、请求与应答、`call_end` 队列、消息描述表的分发 | 呼叫的内部状态；路径 |
| 网络（节点） | UDP 主套接字、NAT 画像与候选、端口映射、网络变化；数据报的分发（按 conv、`RELAY_DATA` 的 hint、控制报文） | 呼叫怎么用这些数据报 |
| 呼叫 | `call_id`、角色、握手、接受、建立期限、打洞轮次、本侧的中转分配（来自平台的身份与密钥）、向平台的请求及其截止时间 | 数据报往哪发；AnLiu |
| 路径 | 每条路径的发送、健康、RTT、载体；路径管理器的选择、热备、双发、切换 | 信令消息的格式；隧道、媒体 |
| 会话 | AnLiu 连接、`conv`、密钥派生、控制流与数据流、媒体流与 UDP 流的接入、`hello` | 路径的种类（只知道载体与 MTU） |
| 流上的服务 | 隧道（子链路、SOCKS、`-R`、策略）、媒体、UDP 转发 | 路径、平台 |
| API 与 SDK 服务 | `npf_t`、配置、local.json、对端与转发、事件、命令、模块 | `npf_call` 的字段（只用函数） |

### 2.2 各层的接口（草图）

**信令客户端**（今天在 `npf_node` 里）：

```c
/* 一条消息按描述表（第 5 节）发出；请求的应答回到 fn */
int  sigc_request(npf_sigc *s, const npf_msgdesc *d, const void *msg, npf_reply_fn fn, void *arg);
int  sigc_event(npf_sigc *s, const npf_msgdesc *d, const void *msg);
/* 带 call_id 的消息解析后交给呼叫表 */
void sigc_on_call_msg(npf_sigc *s, void (*fn)(void *arg, const npf_msgdesc *d, const void *msg), void *arg);
```

**呼叫**：

```c
npf_call *call_dial(npf_node *n, const npf_dial *how);        /* 主叫：call_start 的参数 */
void call_on_msg(npf_call *c, const npf_msgdesc *d, const void *msg);   /* call_accepted、punch_start … */
/* 路径管理器要的东西（第 2.4 节），由呼叫翻译成信令并负责截止时间 */
void call_need(npf_call *c, int need);                          /* PM_NEED_* */
int64_t call_due(const npf_call *c, int64_t now);
void    call_tick(npf_call *c, int64_t now);
```

**会话**（今天 `call_transport.c` 的大部分）：

```c
npf_transport *tr_new(npf_loop *l, int caller, const uint8_t k12[64], const tr_io *io, void *arg);
int  tr_input(npf_transport *t, const uint8_t *dgram, size_t len);   /* 0：AnLiu 认了 */
void tr_set_carrier(npf_transport *t, int carrier, int mtu);         /* ANL_OPT_CARRIER / ANL_OPT_MTU */
int  tr_load(const npf_transport *t, tr_load_info *out);             /* inflight、rto、srtt */
int64_t tr_due(const npf_transport *t, int64_t now);                 /* anl_check */
void    tr_tick(npf_transport *t, int64_t now);
/* tr_io.output(arg, dgram, len)：AnLiu 的输出，交给路径管理器 */
```

**流上的服务**：接口不变（`npf_tunnel_io`、`npf_media_io`、`npf_udpf_io`），只是适配函数从 `npf_call` 移到 `npf_transport`。

**API 与模块钩子**：npf.h、`npf_setup` 不变。`npf/module.h` 不变；npf 的模块用到的内部接口必须保留（`~/workspace/npf/client` 中数出）：`npf_node_request`（13 处）、`npf_node_time`、`npf_node_calls`、`npf_call_next`、`npf_call_state`、`npf_call_info_get`、`npf_call_path_label`、`npf_node_send`、`npf_node_cancel_requests`、`npf_node_wake`、`npf_node_home_status`、`npf_node_end_calls`、`npf_node_dump`、`npf_node_udp_forget_v`、`npf_call_usage_take`、`npf_call_udp_send_v`、`npf_call_open_v`、`npf_call_ctl_request`，以及 `npf_node` 的字段 `online`、`cfg.app_name`、`cfg.app_ver`、`cfg.roots`、`cfg.nroots`、`cfg.callable`、`account_id`、`upgrade.*`、`loop`、`skip_cand`、`skip_cand_arg`、`budget`。这些在第 8 节的每一步里保持可用（字段换位置时给访问函数）。

### 2.3 路径对象

```c
enum { PK_DIRECT, PK_UDP_RELAY, PK_WS_RELAY };                   /* 排名：直连 > UDP 中转 > WS 中转 */
enum { PH_NEW, PH_UP, PH_SUSPECT, PH_DEAD };                     /* 健康 */
enum { PR_IDLE, PR_PRIMARY, PR_SECOND, PR_STANDBY };             /* 在管理器里的角色 */

typedef struct npf_path_ops {
    int     (*send)(npf_path *p, const uint8_t *dgram, size_t len);  /* 热路径：不分配、不查表 */
    void    (*probe)(npf_path *p, int64_t now);   /* 证明一次往返：PATH_CHECK / RELAY_BIND / WS ping 或重连 */
    int64_t (*due)(const npf_path *p, int64_t now);   /* 自己的事（绑定重发、保活、重连），INT64_MAX 没有 */
    void    (*tick)(npf_path *p, int64_t now);
    void    (*close)(npf_path *p);
} npf_path_ops;

struct npf_path {
    const npf_path_ops *ops;
    uint8_t  kind, health, role, carrier;   /* carrier：ANL_CARRIER_DGRAM / STREAM */
    uint16_t mtu;                           /* 现在都是 1200 */
    int64_t  since;                         /* 加入的时刻 */
    int64_t  last_rx;                       /* 经它来的、AnLiu 认了的数据报 */
    int64_t  rt_ok;                         /* 最近一次证明的往返（回应、BIND_ACK、配对 / pong） */
    int64_t  suspect_at, busy_since;
    int      rtt_ms;
    int      tx_before_rx;                  /* 收到之前就可以发（UDP 中转：发送不等本侧绑定） */
};
```

第 1a 步实际的结构（`src/node/path.h`）比草图少：没有 `carrier`、`mtu`、`rt_ok`、`rtt_ms`、`tx_before_rx`，直连的可疑时刻在 `path_direct` 里；发送的操作叫 `tx`（MinGW 的头文件把 `send` 定义成宏）。第 1b 步加了 `rt_ok`、`suspect_at`、`probe_at`、`probe_until`，可疑时刻移到 `npf_path`（第 2.4 节"1b 的实现"）。第 3 步之后的瘦身去掉了操作表的 `name`：名字由管理器按种类查表（`pm_name`），UDP 中转不是 `UP` 时是 `relay (binding)`（路径的健康与绑定器的状态一一对应：`NEW` 绑定中、`UP` 已绑定、`SUSPECT` 探测中、`DEAD` 放弃），操作表只剩 `tx`、`suspect`、`probe`、`dead`。

三种路径的实现：

| 种类 | 来自今天的 | `send` | `probe` | 自己的定时 | 载体 |
|---|---|---|---|---|---|
| 直连 | `call_path.c`、`call_punch.c:punch_done` 的后半、`call_direct.c` 的路径部分 | `npf_udp_send(fd, addr)`，`fd` 可以是主套接字或 S3 留下的套接字（`p2p_owned`） | `PATH_CHECK{nonce}`（SIV，`LABEL_PATH`），500 ms 一次 | 无 | DGRAM |
| UDP 中转 | `call_relay.c`、`relay_bind.c`、`relay_data.c` | `relay_data_pack` → 当前地址 | `RELAY_BIND`（先当前地址，再其余，见 Q2） | 绑定重发 700 ms、保活 25 s | DGRAM |
| WS 中转 | `call_ws.c`、`proto/wsrelay.c` | 进 WS 发送队列，本轮循环结束时一次写出 | WS ping；连接断了就重连（2 s） | 重连、flush | STREAM |

不经平台的直连（`call_direct.c`）是一条**固定**的直连路径：管理器不找别的路径，健康判断只影响日志，失效由 AnLiu 的空闲超时结束会话（与今天相同，`call_path.c:call_check_p2p` 对 `c->direct` 直接返回）。

### 2.4 路径管理器

一个会话一个管理器（`npf_pm`），它是唯一决定"往哪发、要不要换、要平台给什么"的地方。

**加入路径**：

| 事件 | 今天 | 加入 | 初始状态 |
|---|---|---|---|
| 一轮打洞成功 | `call_punch.c:punch_done` | 直连（`fd`、`addr`、是否自有套接字） | `UP`，`rt_ok = 0`（打洞只证明对方的数据报能到，见 `call_path.c:call_standby_done` 的注释） |
| 直连握手完成 | `call_direct.c:direct_up` | 固定直连 | `UP` |
| UDP 中转分配（`call` 应答、`incoming`、`call_accepted`、`relay_switch`） | `call_relay.c:call_relay_setup` | UDP 中转；同一份分配再来时不重复加入 | `NEW`，`tx_before_rx = 1`；是自己绑好的备用分配时（`node_home_adopt`）直接 `UP` |
| 已释放的中转上又来了对方的数据 | `call_relay.c:relay_data_in` | UDP 中转重新启用 | `UP` |
| WS 中转分配 | `call_ws.c:call_ws_setup` | WS 中转；**排他**：同时移除 UDP 中转与直连（平台已释放本侧 UDP 分配，data-channel.md 3） | `NEW`，配对后 `UP` |

**健康（统一的模型）**。三个输入：`pm_rx(p, now)`（AnLiu 认了经它来的数据报）、`pm_rt(p, now)`（证明了一次往返）、会话的负载（`inflight`、`rto`，来自 `tr_load`）。规则只有一套，参数按种类：

| 规则 | 直连 | UDP 中转 | WS 中转 |
|---|---|---|---|
| 被依赖时（主路径，或可疑主路径的第二条），有数据在途：`now − max(last_rx, busy_since) ≥ max(T_busy, 2·RTO)` → `SUSPECT` | T_busy 3 s | 3 s | （新）同 3 s，或只看 TCP（Q5） |
| 被依赖、没有数据在途：`now − last_rx ≥ T_idle` → `SUSPECT`（AnLiu 的保活 15 s 一次） | 20 s | 今天 10 s（Q3） | （新）30 s，用 `npf_ws_last_rx`（Q5） |
| `SUSPECT`：每 P 毫秒 `probe` | 500 ms | 700 ms，每个地址 4 次 | ping；断了 2 s 重连 |
| `rt_ok > suspect_at` → `UP` | 匹配的 `PATH_ECHO` | 回应自己的 `BIND_ACK`（`relay_bind_ack`，`rtt ≥ 0`），或经它来的对方数据 | 重新 `relay_paired`，或 pong |
| `now − suspect_at ≥ T_verdict` → `DEAD` | 10 s | 所有地址都试过（约 2.8 s × 地址数） | 今天没有（Q5） |
| 不被依赖时 | —（直连在时总是主路径） | 只保活（25 s 的 `RELAY_BIND`） | —（WS 在时没有别的路径） |

**被依赖从听到对方起**（2026-10-29，RN-16）：会话 `UP`（对方的 hello 到了，`pm.heard_at`）之前没有路径被依赖（`pm_relied`），无声不算；之后空闲的无声从 `max(last_rx, since, heard_at)` 算，有数据在途的照旧从 `max(last_rx, busy_since)`（`busy_since` 在被依赖之后才记）。原来对方还没来时（主叫在等迟到的 `call_accepted`）被叫的 hello 在途、中转上什么也没有，3 秒就"无声"，探测并重新绑定中转，每 3 秒一次（一小时里一个节点 37 次）；那时的无声说明不了中转，中转本身的好坏由绑定器的保活判断（3.3）。建立之后的规则不变。

今天的四套判断（P2）都是这张表的特例；备用分配不属于任何会话，它的看门狗（`home.c:dog_deadline`）保留，但用同一个绑定器状态机（第 3.3 节）。

**1b 的实现与上面的不同之处**（2026-10-28）：

- 规则在 `path_mgr.c:pm_tick`（纯函数：路径、现在、在途数据、RTO → 事件与下一个截止时刻），参数在 `pm_rules_of`（`t_busy`、`t_idle`、`t_probe`、`t_verdict`，0 表示这一条由路径自己做）。路径的操作是 `tx`、`name` 与三个事件 `suspect`、`probe`、`dead`；路径证明往返时调用 `pm_rt`，自己判定失效时调用 `pm_dead`。2.3 草图里每条路径的 `due` / `tick` 留给 1d；管理器已经只有一个定时器（`pm.t_check`，排在下一个截止时刻，只在提前时重排），取代了 `t_pcheck` 与 `t_rcheck`。
- WS 中转有数据在途时不用 3 秒的规则（"只看 TCP"）：流式载体上排队几秒是正常的，重连会丢掉 8 MiB 的发送队列；只用 30 秒没有任何帧。可疑时不发 ping（25 秒的 ping 本来就在），而是关掉连接立即重连；每次重连要在 10 秒内配对（`WS_PAIR_MS`，表里没有：连上 TCP 之后 WebSocket、Noise 握手没有超时），连续 5 次不成是 `DEAD`。
- UDP 中转绑定期间是 `NEW`、绑上是 `UP`、探测期间 `SUSPECT`、所有地址试过 `DEAD`（`r.bound` 与健康一致）；`DEAD` 的 UDP 中转与 `DEAD` 的 WS 中转在没有别的路径时仍是主路径（发往它们没有坏处，去留由 1c 决定），只有 `DEAD` 的直连不再发送。探测期间名字仍显示 `relay (binding)`（D3 的翻转只剩真正的探测，空闲的会话不再探测）。
- 直连的 `PATH_ECHO` 一到就恢复（原来等下一次 500 ms 的检查）。
- Q2 也用于备用分配的看门狗（`home.c:bind_start(h, 1)` → `relay_bind_probe`，同一份代码，只多一个参数）。

**选择与切换**：

排名能这样简单地比，是因为 WS 中转是排他的（第 4 条）：它在时没有别的路径可比。

1. 主路径 = 健康为 `UP`（或 `NEW` 且 `tx_before_rx`）的路径中排名最高的；同名次保持现状（不来回切）。
2. 主路径 `SUSPECT`：每个数据报再经排名次高、未 `DEAD` 的路径发一份（`PR_SECOND`，AnLiu 去重）；没有这样的路径时 `call_need(PM_NEED_UDP)`。今天 `call_transport.c:anl_out` 在 `p2p_suspect` 时双发，与此相同。
3. 主路径 `DEAD`：移除；有下一条就换；没有时按第 3.6 节决定要 UDP、要 WS，或先等（这一轮打洞的结果、难侧打洞交还端口）。
4. WS 中转是排他的：它在时没有别的路径，也不安排打洞（平台不发 `punch_start`）。
5. 换主路径时比较载体：DGRAM ↔ STREAM 不同就 `tr_set_carrier`（今天 `call_ws.c:call_ws_carrier`、`call_ws_leave`）。MTU 现在都是 1200（`call_transport.c` 的 `ANL_MTU`，WS 中转的数据报上限也是 1200，data-channel.md 11），管理器只在不同时设 `ANL_OPT_MTU`，今天不会发生。
6. 第一次有可发送的路径时通知会话发 `hello`（今天 `call_transport.c:call_path_up` → `call_hello`）；换路径后 `anl_flush`（同今天）。

**热备**：直连成为主路径时，UDP 中转改为 `PR_STANDBY`，照常保活。截止时刻 `since(直连) + 30 s`（`RELAY_STANDBY_MS`）：直连的 `rt_ok < since` 时先 `probe` 直连（今天的 `standby_check`），有往返就移除中转、`call_need(PM_NEED_RELEASE)`（只有主叫发 `relay_release`）；直连期间可疑则中转回到 `PR_SECOND`，热备计时重新开始。第 1a 步的热备检查仍借用"可疑"（`standby_check` 时双发，10 秒没有回应就判直连失效）；第 1b 步起是不带可疑的探测（`pm_probe`：10 秒内每 500 ms 一个 `PATH_CHECK`，不双发、不判失效），没有回应时中转继续热备、30 秒后再查；单向不通的直连由对方一侧的无声判定发现。

**告诉平台**（管理器只说"要什么"，呼叫负责消息、规则与截止时间）：

| `PM_NEED_*` | 何时 | 呼叫发出 | 规则 |
|---|---|---|---|
| `UDP` | 直连可疑或失效，中转已释放 | `relay_switch{mode:"udp"}` | 已接受之后；10 s 内无新分配则重发（Q1） |
| `WS` | UDP 中转与直连都没有了（或 UDP 中转绑不上，且不再等打洞） | `relay_switch{mode:"ws"}`；同时重新测 NAT（今天 `call_relay.c:call_ask_ws_relay`） | 同上 |
| `WS_ELSEWHERE` | WS 中转首次配对之前就失败 | 主叫：`relay_switch{unreachable:true}`；主叫在接受之前等接受；被叫等 | 只有主叫发（`call_ws.c:call_ws_failed`） |
| `PATH_LOST` | 直连 `DEAD` | `punch_update{why:"path_lost"}` | 已接受、不在 WS 上、不是 `secure`（`call_punch.c:call_punch_report`） |
| `UDP_BACK` | 在 WS 上、本侧又有 UDP | `relay_switch{mode:"udp", nat}`（2026-10-29 起一条，原来先发 `punch_update{why:"udp_back"}`） | 今天只由节点的 NAT 探测触发（Q4） |
| `RELEASE` | 热备结束且直连往返过 | 主叫：`relay_release` | 被叫只停用 |

`call_established` 之前平台对 `relay_switch` 限次（每个呼叫分配 2 次）、所有 `relay_switch` 占切换配额（突发 6、之后 30 s 1 次，signaling.md "中转方式的选择"）：呼叫层的重发必须在这个配额内，第 3.6 节的"请求"状态带截止时间就是为此。

**1c 的实现**（2026-10-29）：`pm_decide(m, in, now)` 返回上表的一项（`PM_NEED_*`）或一个动作（等端口、等打洞、再绑一次、端口交还后重绑、探直连、继续热备、丢掉失效的直连）；呼叫的 `call_need(c, need, now)` 把它变成消息：`UDP`、`WS`、`WS_ELSEWHERE`、`UDP_BACK` 在需要成立期间 10 s、30 s、之后每 30 s 重发（一个请求开头 10 s 内两次，之后 30 s 一次，与配额补充的速度相同，用不完突发的 6 次），每次一行日志；`PATH_LOST`、`RELEASE` 只发一次（`RELEASE` 同时停用中转）。"需要成立"每次从路径状态重新算：新分配到来（WS 路径加入、UDP 路径加入）、直连恢复、中转又绑上，需要就不再成立，重发停止，不另记"已应答"。`UDP_BACK` 也用于 Q4（节点的 NAT 探测说 UDP 可用、会话在 WS 上：分配到来 `udp_again` 后，默认 5 分钟，测试 `NPF_TEST_UDP_AGAIN_MS`）：先 `punch_update{udp_back}` 再 `relay_switch{udp}`，与探测从无到有时相同，平台不区分。

### 2.5 `npf_call` 的字段去哪里

| 去处 | 字段（今天的名字） | 个数（约） |
|---|---|---|
| 路径（直连） | `p2p`、`p2p_fd`、`p2p_owned`、`p2p_addr`、`p2p_rx_ms`、`p2p_since`、`p2p_suspect`、`p2p_busy_since`、`path_keys`、`path_ready`、`path_nonce`、`path_echo_ms`、`standby_check`、`t_pcheck` | 14 |
| 路径（UDP 中转） | （1a 时：绑定器 `relay_c` 还带着 WS 分配的 `relay_id` 与 `alloc_key`，`call_relay_take(..., NULL, 0)` 写入，绑定器留着旧的 UDP 密钥与地址，旧中转的 `BIND_ACK` 仍能打开；1c 起 WS 分配的编号在 `path_ws.id`，`alloc_key` WS 连接用不着、不再存，绑定器只有 UDP 的状态）`relay`、`relay_rx_ms`、`relay_busy_since`、`t_rcheck`、`relay_retried`、`relay_waits_ports`、`relay_ports_waited`、`t_standby`（1c：后四个去掉，变成管理器的 `tried`、`wait`、`act_at`） | 8 |
| 路径（WS 中转） | `ws_mode`、`wsr`、`ws_url`、`ws_pub`、`t_wsflush`、`t_wsre`、`ws_paired_once`、`ws_fail_wait` | 8 |
| 路径管理器 | `t_ws_wait`、`relay_asked_ms`（变成请求状态；1c：`need`、`asks`、`ask_at`，`t_ws_wait` 与 `t_standby` 变成 `act_at`，管理器的定时器 `t_check` 排在它们与健康规则的最小值） | 2 |
| 会话 | `anl`、`conv`、`conv_next`、`stream`、`dpend*`、`tun`、`media`、`udp`、`t_anl`、`anl_due`、`flush_pending`、`k12`、`nominate_key`、`keys_ready`、`anl_srtt`、`auth_fail_*`、`tx_bytes`、`rx_bytes`、`peer_hello`、`ctl[]`、`ctl_seq`、`sub_done`、`sub_arg`、`rearly`、`nrearly` | 约 28 |
| 打洞 | `punch`、`punch_of`、`punch_socks`、`punch_round`、`pcfg`、`info_port`、`info_round`、`tcand`、`spray_refused_said`、`punch_wait_keys`、`punched`、`t_punch`、`t_linger` | 13 |
| 呼叫 | 其余：`call_id*`、`req_id`、`call_req`、`number`、`caller_number`、`auth`、`state`、`accepted`、`secure`、`up_told`、`peer_closed`、`ended`、`t_timeout`、`t_free`、被叫的准入（`grant_*`、`targets`、`hosted_grant`、`kshare`、`policy`、`caller_app`）、反向监听 | 约 40 |

## 3. 状态机

每个组件一个枚举和一个转移函数 `x_event(x, ev, now)`；转移函数只改自己的状态、返回要做的动作（发什么、通知谁），所以每一行都能在没有套接字、没有事件循环的单元测试里检查（今天的 `tests/unit/test_home.c` 要起一个假中转、用回环套接字）。每个状态都有"截止时间"一列：非终止状态没有截止时间就是缺陷（第 4 节的不变式）。

### 3.1 呼叫

| 状态 | 事件 | 下一状态 | 动作 / 截止时间 |
|---|---|---|---|
| `CALLING`（主叫） | `call` 应答 ok | `CALLING` | 带来的中转交给路径管理器（先绑） |
| `CALLING` | `call_accepted` | `CONNECTING` | 记下接受；期限 = 现在 + 25 s；握手、建会话 |
| `CALLING` | `call_rejected` / 错误应答 | `CLOSED` | 不发 `call_end` |
| 任何未建立的 | 信令断开 | `CLOSED` | 不发 `call_end`（今天 `call.c:node_sig_lost`）；已建立的不受影响 |
| `ANSWERING`（被叫，`incoming` 已到） | 闸门通过、应答发出 | `CONNECTING` | 期限 = 创建 + 25 s |
| `CONNECTING` / `ESTABLISHED` | 被叫的第一个 `punch_start` | 不变 | 记下接受（被叫）；期限还在时重新计 25 s（今天 `call.c:call_accept_seen`） |
| `CONNECTING` | 自己的 `hello` 发出（主叫，非首次配对） | `ESTABLISHED` | 期限保留，等对方的 `hello` |
| `CONNECTING` | 对方的 `hello` | `ESTABLISHED` | 取消期限；被叫发 `call_established` |
| `ESTABLISHED` | 对方的 `hello`（主叫） | `ESTABLISHED` | 取消期限 |
| 任何未结束 | 期限到 | `CLOSING` | `timeout`；主叫先探一下信令 |
| 任何未结束 | 本地结束 / 对方 `close` / `call_ended` / 传输失效 | `CLOSING` | 发 `call_end`（`call_ended` 时不发）、`close` |
| `CLOSING` | 下一轮循环 | `CLOSED` | 释放 |

**取代**：`state`、`accepted`、`t_timeout`（变成"期限"）、`peer_hello`、`up_told`、`ended`、`peer_closed`、`t_free`。"已接受"成为状态里记下的事实，不再与定时器绑在一起（10-27 (1) 那类缺陷从此不可能）。

**第 3 步的实现**（2026-10-29，`call.c`、`call_internal.h`）：`c->st` 是 `enum {CS_NEW, CS_CALLING, CS_ANSWERED, CS_CONNECTING, CS_HALF, CS_UP, CS_CLOSED}`，只向前走（`call_set_state` 不接受比现在小的状态），`npf_call_state` 按一张表给出 `NPF_CALL_*`（钩子只在它变了时听到），`npf.h`、module.h 的状态值与行为不变。与上表的对应：

| 实现 | 上表 | 说明 |
|---|---|---|
| `CS_NEW` | `ANSWERING` | 被叫在 `call_handle_incoming` 里、应答发出之前（直连的监听方也从这里开始） |
| `CS_CALLING` | `CALLING` | 主叫 |
| `CS_ANSWERED` | 被叫的 `CONNECTING`，还没有接受 | 应答已发出；平台的接受还没显出来，`punch_update` 不发 |
| `CS_CONNECTING` | `CONNECTING`，已接受 | 主叫的 `call_accepted`、被叫的第一个 `punch_start`（`call_accept`：期限从现在重新计 25 s）；直连两侧握手之后 |
| `CS_HALF` | 主叫的 `ESTABLISHED`，期限还在 | 自己的 `hello` 发出（非首次配对的主叫、直连的发起方） |
| `CS_UP` | 双方 `hello` 之后的 `ESTABLISHED` | 进入时取消期限；被叫（非直连）发 `call_established`，从此也算接受（Q6） |
| `CS_CLOSED` | `CLOSING` 与 `CLOSED` | `call_close` 置位，下一轮循环释放（`t_free`，第 4 节第 5 条的"下一轮回调"） |

"已接受" = `st >= CS_CONNECTING`（`call_accepted`），"已建立" = `CS_HALF` 或 `CS_UP`（`call_up`），"已结束" = `CS_CLOSED`（`call_over`），都由状态算出，没有另存的标志。结束只有一个函数 `call_close(c, why, how)`：`CALL_END_LOCAL`（`npf_call_end`：`call_end` 与隧道里的 `close`）、`CALL_END_PEER`（同上，记录写对方结束：对方的 `close`，原来的 `peer_closed`）、`CALL_END_QUIET`（不发：平台告诉我们的、被拒、信令断开），取代原来的 `npf_call_end`、`call_close_quiet`、`call_ended` 三处；结束时打洞立即结束（下表"呼叫结束"一行，原来等下一轮的释放）。去掉的成员：`state`（改为 `st`）、`accepted`、`peer_hello`、`up_told`、`ended`、`peer_closed`（`t_timeout` 在 1d 已变成期限 `limit_at`；`limit_at` 不再兼作"还没接受"的标志：接受只在 `CS_CALLING` 与 `CS_ANSWERED` 时重新计期限）。

### 3.2 打洞（节点一侧，每个呼叫）

| 状态 | 事件 | 下一状态 | 动作 / 截止时间 |
|---|---|---|---|
| `IDLE` | `punch_start{round > 当前}` | `SCHEDULED` | 记下计划；截止 = `start_at − lead`；主机防火墙时先开流（`firewall_open`） |
| `IDLE` | `punch_start{skip:"no_strategy"}` | `IDLE` | 告诉路径管理器"不会有直连" |
| `SCHEDULED` | 截止到、没有密钥 | `WAIT_KEYS` | 无截止（密钥到来是事件；呼叫的期限兜底） |
| `SCHEDULED` / `WAIT_KEYS` | 可以开始 | `RUNNING` 或 `IDLE` | 难侧套接字不够或已有难侧打洞：报 `busy`，回 `IDLE` |
| `SCHEDULED` | `punch_info{stop}` | `IDLE` | 不开始 |
| `RUNNING` | `punch_info{port}` / `{cand}` | `RUNNING` | 交给这一轮（只给同一轮） |
| `RUNNING` | 对方什么都没来（`quiet`） | `RUNNING` | 早报失败，除非路径管理器正等这一轮决定 WS |
| `RUNNING` | 成功 | `LINGER` | 报结果；直连交给路径管理器；截止 = 现在 + 10 s |
| `RUNNING` | 失败 | `IDLE` | 报结果；告诉路径管理器"这一轮没成" |
| `RUNNING` / `SCHEDULED` / `LINGER` | 换到 WS / 呼叫结束 | `IDLE` | 结束打洞、交还难侧套接字（`call.c:call_relay_leave`） |
| `LINGER` | 截止到 | `IDLE` | 释放打洞对象 |
| 任何 | 新的 `punch_start` | `SCHEDULED` | 上一轮的打洞结束（今天 `call_start_punch_now`） |

**取代**：`punch`、`punch_of`、`punch_round`、`punch_wait_keys`、`punched`、`info_port`、`info_round`、`t_punch`、`t_linger`。

**第 3 步的实现**（2026-10-29，`call_punch.c`）：`c->punch_st` 是 `enum {PN_NONE, PN_SCHEDULED, PN_WAIT_KEYS, PN_RUNNING, PN_LINGER, PN_IDLE}`，唯一的转移函数 `call_punch_to(c, st, at)` 同时设截止时间（`SCHEDULED`：开始时刻；`LINGER`：释放打洞对象的时刻；其余为 0）并保证打洞对象只在 `RUNNING` 与 `LINGER` 存在（其余状态进入时结束它、交还难侧套接字）。一个呼叫同一时间只有一轮：`c->punch` 一定属于 `punch_round`，`punch_of` 去掉。与上表的不同：

- 上表的 `IDLE` 分成两个：`PN_NONE`（还没有一轮、这一轮被让出、改走了 WS：平台还会发，回到 UDP 后重新安排，路径管理器的 `PM_IN_PUNCH` 仍成立）与 `PN_IDLE`（最后一轮已结束：失败、`no_strategy`、呼叫结束）；`PM_IN_PUNCH` = `punch_st < PN_LINGER`，取代 `punched`（原来 `punched` 改走 WS 时不变）。
- 失败也进 `LINGER`，截止时间是现在（打洞对象不能在自己的回调里释放；原来的 `linger_at = now`），下一次 tick 进 `IDLE`。
- 新的 `punch_start` 立即结束上一轮的打洞（原来等新一轮开始时，最多晚"两侧单向时延的较大值 + 100 ms"，有防火墙提前量时再加 300 ms）：于是 `punch_info{port}` 只可能交给它那一轮（10-27 (4) 从此不可能）。上一轮的端口丢掉；本轮开始之前到的端口记在 `punch_port`（取代 `info_port`、`info_round`），开始时交给打洞；比本轮新的轮次的端口也丢掉（原来留着：对方在测出端口之后才发，平台同时向双方发 `punch_start`，实际不会先到）。旧一轮在新一轮已经排上之后结束，也不再把"打洞已结束"记到新一轮上（原来 `punched` 置位，路径管理器不再等新一轮）。
- `punch_info{stop}` 在 `WAIT_KEYS` 时也回 `NONE`（原来只看 `SCHEDULED`：密钥来了照样开始、向不再打的对方喷包）。
- 呼叫结束时打洞立即结束（`call_close`），打洞的回调不再需要检查呼叫是否已结束。

去掉的成员：`punch_of`、`punched`、`punch_wait_keys`、`info_port`、`info_round`、`linger_at`（1d 里 `t_punch`、`t_linger` 已变成 `punch_at`、`linger_at`，现在只剩 `punch_at`）；加 `punch_st`、`punch_port`。难侧套接字的交还合成一个 `socks_back`（原来打洞结束的回调与 `call_punch_end` 各写一遍，`call_punch_sockets_back` 去掉），`call.c:call_relay_leave` 去掉（改走 WS 时 `call_punch_to(c, PN_NONE, 0)`）。

### 3.3 UDP 中转绑定（呼叫的与备用分配的共用）

| 状态 | 事件 | 下一状态 | 动作 / 截止时间 |
|---|---|---|---|
| `NONE` | 拿到分配 | `BINDING(i=0, k=0)` | 发 `RELAY_BIND`；截止 +700 ms |
| `BINDING` | 截止到，`k < 3` | `BINDING(i, k+1)` | 再发 |
| `BINDING` | 截止到，`k = 3`，还有地址 | `BINDING(i+1, 0)` | 发往下一个地址；数据跟着走 |
| `BINDING` / `PROBING` | 截止到，都试过 | `GAVE_UP` | 告诉所有者；无截止（所有者决定何时再绑：呼叫是路径管理器，备用分配是退避） |
| 未绑定的 | 质询 | 不变 | 立即回显 cookie（至少隔 200 ms）；`BOUND` 时同样（NAT 换了端口） |
| `BINDING` / `PROBING` / `GAVE_UP` | `BIND_ACK{state=1}` 或经它来的对方数据 | `BOUND` | 截止 = +25 s（保活；备用分配没有：中转 ping 它）；回应的地址成为当前地址（早先地址、放弃之后的迟到应答也是） |
| `BOUND` | 保活截止 | `BOUND` | 发 `RELAY_BIND`；+25 s |
| `BOUND` | 路径管理器判可疑（会话依赖它时）；备用分配的看门狗 | `PROBING(当前地址)` | 发 `RELAY_BIND`；截止 +700 ms；数据留在当前地址（Q2） |
| `PROBING` | 截止到 | `PROBING(其余地址按顺序)` → `GAVE_UP` | 同 `BINDING`，数据不动，直到别的地址回应 |
| `GAVE_UP` | 所有者重绑 | `BINDING(0, 0)` | 同 `NONE` |
| 任何 | 释放 / 交给呼叫（备用分配被取用） | `NONE` | 绑定（cookie、`kseq`、地址、状态）原样交出 |

**取代**：`relay.active`、`relay.bound`、`t_bind` 的两种用法、`cur`/`tries` 的含义、`relay_rx_ms`、`relay_busy_since`、`t_rcheck`。呼叫一侧在 `GAVE_UP` 之后的决定（今天 `call_relay.c:relay_gave_up` 的五个分支）交给路径管理器（第 3.6 节）。

**2 的实现**（2026-10-29，`relay_bind.h`）：`relay_c` 的 `state`（`RB_NONE`、`RB_BINDING`、`RB_PROBING`、`RB_BOUND`、`RB_GAVE_UP`）与唯一的截止时间 `at`（0 表示没有）；转移函数是 `relay_bind_take`（`NONE` → `BINDING`）、`relay_bind_begin(probe, now)`（`BINDING` 或 `PROBING`）、`relay_bind_tick(now, ka)`（到期的事：1 发一个绑定，−1 都试过）、`relay_bind_up(now, ka)`（`BOUND`，保活间隔 `ka`，备用分配给 0），以及原有的 `relay_addr_take`（回应的地址）和 `relay_bind_ack`（返回 2 表示这个质询要立即回显，原来的 `relay_bind_echo_due` 并入）。绑定器不发报文、不建定时器：所有者发 `RELAY_BIND`（呼叫的 `relay_bind_send`、备用分配的 `bind_send`），并把 `at` 排进自己的一个定时器（呼叫的 `call_due` 读 `pu.r.at`，备用分配的 `home_due`）。去掉的：`relay_c` 的 `active`、`bound`、`keep`，`path_udp` 的 `bind_at`，`relay_bind_step`，`relay_bind_take` 里给 WS 分配用的 `addr == NULL` 分支（1c 之后没有调用者），`path_udp.c` 的 `bind_next` 与 `udp_gave_up`。与上表原稿不同的两处都是保留今天的行为：`GAVE_UP` 也认迟到的应答（原来 `active && !bound` 就认）；`PROBING` 一直到放弃都把数据留在当前地址（1b 起）。单元测试 UT-25（`test_relay.c:bind_table`）在假时钟下逐行走这张表，不用套接字；回显与哪些 `BIND_ACK` 算数仍由同一文件里对着回环假中转的部分检查。

### 3.4 备用分配

原来已经是显式状态（`home.c` `enum {H_OFF, H_OPENING, H_BINDING, H_BOUND, H_LOST, H_BACKOFF, H_TAKEN}`），另有隐含的 `lost` 与三个定时器（`t_dog`、`t_retry`、`t_bind`）。第 2 步：有分配时的状态就是绑定器的（`BINDING`、`LOST` = `RB_PROBING`、`BOUND`、`BACKOFF` = `RB_GAVE_UP`），`home.c` 自己的 `state` 只剩没有分配时的 `OFF`、`OPENING`、`TAKEN`；三个定时器合成一个截止时间。

| 状态 | 事件 | 下一状态 | 动作 / 截止时间 |
|---|---|---|---|
| `OFF` | 登录且允许（`home.c:home_allowed`） | `OPENING` | `home_open`（无截止：应答或断线是事件） |
| `OPENING` | 应答：新分配 | `BINDING` | 绑定器开始（截止：绑定器的） |
| `OPENING` | 应答因断线丢掉 | `OPENING` | 无截止：下次登录再发 |
| `OPENING` | 被拒 | `OFF` | 截止 = +60 s（`rate_limited`）或 +300 s |
| `OFF` / `TAKEN` | 截止到且在线 | `OPENING` | `home_open` |
| `BINDING` / `LOST` | 绑定器的截止 | 不变 | 下一个绑定 |
| `BINDING` / `LOST` | 都试过 | `BACKOFF` | 截止 = +5 / 20 / 60 / 180 s（自上次绑上以来第几次放弃）；在线时每次都 `home_open{resume}` |
| `BINDING` / `LOST` / `BACKOFF` | 绑上 | `BOUND` | 看门狗截止 = max(最后发, 最后收) + T + 4.5 s + 5 s；放弃过（`backoff > 0`）就重测 NAT，`backoff` 清零 |
| `BOUND` | ping | `BOUND` | 立即 `PONG`（主 socket 向别处发过时带 `OTHER`）；看门狗后移 |
| `BOUND` | 看门狗到 | `LOST` | 从当前地址起重绑（Q2），`drops` 加 1 |
| `BOUND` | 网络变化 | `BOUND` | 立即发带 `NEWNET` 的 `RELAY_BIND`，看门狗从它算 |
| `LOST` / `BACKOFF` | 网络变化 | `LOST` / `BINDING` | 立即重绑 |
| `BACKOFF` | 截止到 | `BINDING` | 从第一个地址重绑 |
| `BACKOFF` | UDP 又通了（呼叫的中转绑上、NAT 探测有回应） | `BINDING` | 立即重绑并问一次 |
| `BACKOFF` | `resume` 的应答：还在 | `BACKOFF` | 等退避的截止（D11） |
| 任何有分配的 | 呼叫取用 | `TAKEN` | 绑定交给呼叫；截止 = +30 s（等 `relay_spare`） |
| 任何 | `relay_spare`（取用之后、每小时轮换）或 `home_open` 带来新分配 | `BINDING` | 换成新的 |
| 有分配的 | 登录到另一台服务器 | `OFF` → `OPENING` | 那里新开 |
| 任何 | 退出、`home_bind=off` | `OFF` | `home_close`（尽力），无截止 |

**2 的实现**（2026-10-29）：一个定时器 `t_due`，排在 `home_due`：`BINDING` / `LOST` 是绑定器的 `r.at`，`BOUND` 是看门狗（由最后收发的时刻与 T 算出，不另存），其余是 `at`（`BACKOFF` 的退避、`OFF` 被拒后的重试、`TAKEN` 的 30 s，0 表示等事件）；`home_tick(h, now)` 做到期的事，每个事件（登录、应答、`relay_spare`、取用、UDP 又通、网络变化、中转来的报文）之后 `home_arm` 重排一次（每个 ping 一次，与原来看门狗的重排相同）。去掉的：`t_dog`、`t_retry`、`t_bind` 与 `dog_arm`、`dog_check`、`dog_timer`、`retry_timer`、`bind_timer`；`lost`（就是 `backoff > 0`："上次绑上以来放弃过"）；`H_BINDING`、`H_BOUND`、`H_LOST`、`H_BACKOFF`（绑定器的状态）；`home_take`（并入 `spare_take`）；`node_home_sig_lost`（信令断开时 `node_sig_fail_pending` 已经以空应答调用 `open_reply`，清掉 `opening`）；D11 的分支。与原来不同之处：（1）`backoff` 只在绑上时清零（原来新分配到来、UDP 又通时也清零）：放弃之后到来的新分配、UDP 又通之后的重绑若又失败，退避接着 20、60、180 s，而不是从 5 s 重来；重测 NAT 的时机不变（原来 `lost` 也只在绑上时清零）；（2）状态 JSON 的 `BACKOFF` 显示为 `backoff`（Q8，原来是 `binding`）；（3）"spare bound again" 的日志也带上中转 ping 的间隔，与第一次绑上同一格式。单元测试 UT-29（`test_home.c:test_table`）在假时钟下逐行走这张表，不用套接字（没有主 socket 时不发绑定；节点"在线"而没有信令连接，问平台的次数看请求编号），并检查每个状态都有截止时间或在等事件；对着回环假中转的部分照旧。

### 3.5 WS 中转连接

| 状态 | 事件 | 下一状态 | 动作 / 截止时间 |
|---|---|---|---|
| `NONE` | WS 分配 | `CONNECTING` | 连接、Noise_XK、`relay_bind`（`proto/wsrelay.c`） |
| `CONNECTING` | `relay_paired` | `PAIRED` | 设 STREAM 载体；路径 `UP` |
| `CONNECTING` | 失败，从未配对，主叫且未接受 | `WAIT_ACCEPT` | 接受到来时转 `PM_NEED_WS_ELSEWHERE` |
| `CONNECTING` | 失败，从未配对，其余 | `FAILED` | 主叫：`PM_NEED_WS_ELSEWHERE`；被叫：等平台 |
| `PAIRED` | 连接断开 | `RECONNECT` | 截止 +2 s |
| `PAIRED` | （新）`npf_ws_last_rx` 超过 T_idle 且 ping 无回音 | `RECONNECT` | 关掉半开的连接（Q5） |
| `RECONNECT` | 截止到 | `CONNECTING` | 同一分配再连 |
| `RECONNECT` | （新）连续 N 次失败 | `FAILED` | 由路径管理器决定（Q5） |
| 任何 | 新的 UDP 分配（`udp_back`） | `NONE` | 关连接，载体回 DGRAM |

**取代**：`ws_mode`（由路径管理器的"有 WS 路径"代替）、`ws_paired_once`、`ws_fail_wait`、`t_wsre`。

### 3.6 路径管理器

管理器的状态 = 各路径的（健康，角色）+ 一个"请求"子状态 + 两个提示：

- 请求：`REQ_NONE`、`REQ_UDP(at)`、`REQ_WS(at)`、`REQ_WS_ELSEWHERE(at)`、`REQ_UDP_BACK(at)`；每个都有截止时间 `at + 10 s`（`RELAY_ASK_AGAIN_MS`），到了仍没有新分配就重发（在平台的切换配额内）。新分配到来回到 `REQ_NONE`。
- 提示（来自打洞与节点）：`DIRECT_PENDING(until)`（第一轮打洞还没结果，最多 15 s，今天的 `t_ws_wait`）、`PORTS_HELD`（难侧打洞占着 NAT 的端口，今天的 `relay_waits_ports`）。

| 情况 | 事件 | 结果 |
|---|---|---|
| 没有路径 | UDP 中转加入 | 主路径 = UDP（`NEW`，可以发）；通知会话发 `hello` |
| 主 = UDP | 直连加入 | 主 = 直连；UDP → `STANDBY`，30 s |
| 主 = 直连 | 直连可疑 | UDP → `SECOND`（双发）；没有 UDP：`REQ_UDP`；UDP 未绑定：重绑 |
| 主 = 直连，可疑 | 直连回应 | UDP → `STANDBY`（重新计 30 s） |
| 主 = 直连，可疑 | 直连 `DEAD` | 主 = UDP（`PATH_LOST`）；UDP 也没有绑上且不在绑定：`REQ_WS` |
| `STANDBY` 截止 | 直连往返过 | 移除 UDP（`RELEASE`） |
| `STANDBY` 截止 | 没往返过 | 探直连；回应后再判 |
| 主 = 直连（可疑） | UDP `GAVE_UP` | 等直连的判定：回应则照旧，失效则 `REQ_WS`（今天 `relay_gave_up` 的 `c->p2p` 分支只记日志，由 `call_check_p2p` 判定后要 WS） |
| 主 = UDP | UDP `GAVE_UP`，`PORTS_HELD`，本次失去中转还没等过 | 等端口交还（最多 15 s），交还后重绑 |
| 主 = UDP | UDP `GAVE_UP`，`DIRECT_PENDING` | 等这一轮打洞；失败且 UDP 在重绑：等重绑；都不成：`REQ_WS` |
| 主 = UDP | UDP `GAVE_UP`，本次失去中转还没重试过 | 再绑一次 |
| 主 = UDP | 以上都不是 | `REQ_WS` |
| 任何 | WS 分配 | 只剩 WS；结束打洞 |
| 主 = WS | 本侧又有 UDP | `REQ_UDP_BACK` |
| 主 = WS | UDP 分配 | 移除 WS；主 = UDP；载体 DGRAM |
| 任何 `REQ_*` | 截止到 | 重发同一请求（`relay_asked_ms` 的"可以再发"变成真的再发） |

**取代**：`t_ws_wait`、`relay_asked_ms`、`relay_retried`、`relay_waits_ports`、`relay_ports_waited`、`punched`（用于决定 WS 的那部分），以及 `call_relay.c:relay_gave_up`、`ws_wait_done`、`call_ws_wait_end`、`call_path.c:call_check_p2p` 的决定部分。表中"本次失去中转"指一次从 `BOUND` 到 `GAVE_UP` 的过程，每次重新计，不是每个呼叫一次（P5，Q7）。

**1c 的实现**（2026-10-29，`path_mgr.c:pm_decide`，纯函数：路径的健康、角色与一组输入位 → 一项需要或一个动作；单元测试 UT-34 逐行检查）：

- 输入位（`PM_IN_*`）：主叫；平台还不接受 `relay_switch`（主叫在接受之前）；已建立；打洞还可能带来直连（`call_punch_coming`，2026-10-29：一轮已排定、等密钥或正在进行，或者让出的一轮（`PN_NONE` 而 `punch_round > 0`：平台会再发它）；第一个 `punch_start` 之前的 `PN_NONE` 不算：配对一直核对不过、信令停住、平台不安排时没有一轮会来，原来 UDP 中转不通的会话要白等 15 秒才要 WS 中转。UT-31 检查）；难侧打洞占着端口；NAT 探测说 UDP 可用；UDP 在 WS 分配之后恢复过（节点的 `udp_back_ms`）；测试的没有 UDP。由 `pm_check` 每次算出（每个 AnLiu 定时器一次，热路径上没有）。
- 状态：`tried`（本次失去中转已经有过的：等端口、等打洞、再试一次，中转 `UP` 时清零），`wait` + `act_at`（正在等什么、到什么时候：端口、打洞、热备、热备的探测；在 WS 上是 Q4 的时刻），请求（`need`、`asks`、`ask_at`，属于 `call_need`）。"提示"不是另存的标志：`DIRECT_PENDING` = 打洞还可能带来直连，`PORTS_HELD` = 难侧打洞占着端口，等待在原因消失（打洞结束、端口交还）或 15 s 到时结束。
- 与上表不同或表里没写的：直连可疑时中转从没绑上就再绑一次，算作这次失去中转的"再试一次"；直连失效时中转也不通，不报 `path_lost`，直接按 UDP 中转的规则（已经再试过）要 WS；热备改为管理器的截止时间（`wait = PM_W_STANDBY / PM_W_PROBE`），取代 `t_standby` 与 `standby_check`，探测中收到回应在下一次 `pm_check` 释放（原来在回应的回调里立即释放，相差至多一次循环）；直连恢复之后才到的中转（直连可疑时要来的）也热备 30 s、之后释放（原来这时没有热备计时，中转一直保活到会话结束）；Q4 的试回把 `tried` 设满，新分配绑不上就直接要 WS（原来 `udp_back` 之后的失败也是这样，只是那时 `tried` 是每个呼叫的）。
- WS 中转首次配对之前失败也判 `DEAD`（原来只记 `fail_wait`），于是"主叫在接受之前等待、接受后请求别处"就是 `PM_IN_HOLD` 的一条规则，`fail_wait` 去掉。
- 节点级事件不再逐个呼叫写筛选：NAT 探测的 `udp_back` 与测试的 `NPF_TEST_WS_FILE` 只记下时刻 / 状态，`npf_node_calls_decide` 让每个呼叫 `pm_check` 一次；`npf_node_check_paths`（网络变化：直连可疑）与 `npf_node_calls_lost_fd` 仍是事件，没有动。

### 3.7 今天的行为与上表不同之处

| # | 不同之处 | 代码 | 性质 |
|---|---|---|---|
| D1 | 请求没有截止时间：`relay_switch` 发出后没有谁在 10 s 后补发；`relay_gave_up` 之后若平台丢了 `relay_switch{ws}`，会话没有任何可用路径，直到 AnLiu 60 s 空闲以 `transport_lost` 结束 | `call_relay.c:call_ask_ws_relay`（连 `call_relay_ask_ok` 都不看）、`call_relay_ask_ok` | 潜在缺陷 |
| D2 | 依赖中转时的重绑从第一个地址开始（`relay_bind.c:relay_bind_run` 把 `cur` 置 0），绑定期间 `RELAY_DATA` 也发往 `addr[cur]`（`call_relay.c:call_relay_send_data`）：经第二个地址绑定的会话，重绑的约 2.8 s 里数据发往第一个地址 | `call_relay.c:call_check_relay`、`relay_bind_run` | 潜在缺陷 |
| D3 | 空闲阈值 10 s 小于 AnLiu 的保活 15 s（`call_transport.c:call_start_transport` 的 `keepalive_ms`，AnLiu 在 15 s 没有发送时才发保活）：按代码推算，依赖中转、空闲的会话大约每 10–15 s 重绑一次（`bound` 由 1 变 0 再变 1，`npf_call_path` 这期间显示 `relay (binding)`）；与 D2 叠加时更明显。需要一份日志确认 | `call_relay.c` `RELAY_IDLE_SILENT_MS` | 待确认，设计选择 |
| D4 | `ws_wait_done` 到时立即要 WS，不看 UDP 中转是否正在重绑；`call_ws_wait_end` 却特意先等重绑的结果（注释说那样曾把即将成功的绑定换掉）。同一个决定两套规则 | `call_relay.c:ws_wait_done`、`call_ws_wait_end` | 潜在缺陷 |
| D5 | 只因自己的 UDP 中转不通（探测服务器照常有回应）而改用 WS 的会话，永远不回 UDP：`udp_back` 只在节点的 NAT 探测从"无回应"变为"有回应"时触发 | `nat.c:probe_done`（`udp_back` 的条件）、`call.c:npf_node_ws_calls_udp_back` | 设计缺口 |
| D6 | WS 中转连接没有无声检测（25 s 发 ping，没人看 `npf_ws_last_rx`）；配对之后断了每 2 s 重连、永不放弃，也不换中转 | `proto/wsrelay.c:ping_cb`、`call_ws.c:call_ws_failed` | 设计缺口 |
| D7 | `relay_retried`、`relay_ports_waited`、`punched` 每个呼叫只置一次：`udp_back` 之后再失去中转，三个等待 / 重试分支都被跳过，直接要 WS | `call_relay.c:relay_gave_up`、`call_ws_wait_end` | 潜在缺陷 |
| D8 | 被叫的"接受"只来自第一个 `punch_start`；一直没有 `punch_start` 的被叫（例如平台因没有候选不排这一轮）不算接受，它的 `punch_update`（`network`、`profile`）都被丢掉，尽管它已发出 `call_established` | `call_punch.c:call_punch_report`、`call_handle_punch_start` | 协议规定如此（signaling.md `punch_update`），可以讨论 |
| D9 | 直连与中转的空闲阈值不同（20 s 与 10 s），回答的是同一个问题 | `call_path.c` `P2P_IDLE_SILENT_MS`、`call_relay.c` `RELAY_IDLE_SILENT_MS` | 设计选择 |
| D10 | 备用分配 `BACKOFF` 在状态 JSON 里显示为 `binding` | `home.c` `k_state` | 显示上的选择 |
| D11 | `open_reply` 里"`resumed` 且 `H_BACKOFF && !lost` 就立即重绑"的分支走不到：进入 `H_BACKOFF` 只有 `gave_up` 一处，它同时置 `lost = 1`，而 `lost` 只在绑上（`H_BOUND`）时清零。隐含状态造成的死代码；按表删掉，行为不变 | `home.c:open_reply`、`gave_up`、`ack_in` | 死代码 |

1b 改掉了 D2、D3、D6、D9；1c（2026-10-29）改掉了 D1（请求的重发，`call_need`）、D4（等打洞到时也先等正在进行的重绑：决定只在 UDP 中转 `DEAD` 时做，绑定中的 `NEW` 什么都不决定）、D5（Q4，每 5 分钟试回 UDP）、D7（等待与重试按每次失去中转计）；第 2 步（2026-10-29）改掉了 D10（Q8，显示 `backoff`）与 D11（删掉，第 3.4 节）。第 3 步（2026-10-29）改掉了 D8（Q6：被叫发出 `call_established` 时也算接受，signaling.md 0.56）。

### 3.8 待用户决定的问题

- **Q1**（D1）请求加截止时间：10 s 没有新分配就重发，直到成功或会话结束？重发受平台配额限制（突发 6、之后 30 s 1 次；`call_established` 之前每个呼叫只分配 2 次），建议：重发间隔 10 s、30 s、之后 30 s，日志每次一行。
- **Q2**（D2）可疑时的探测先发当前地址、再按顺序试其余地址（数据一直发往当前地址，直到另一个地址回应），而不是从第一个地址重来？备用分配的看门狗是否同样处理？
- **Q3**（D3、D9）空闲时的探测周期：中转保持 10 s（实质上是 10 s 一次的往返探测），还是与直连统一为 20 s（AnLiu 保活 15 s 之上留余量）？
- **Q4**（D5）只因中转不通而在 WS 上的会话：要不要定期（例如 5 分钟一次）试着回 UDP（`relay_switch{mode:"udp"}`，平台分配新的 UDP 分配，绑不上再回 WS）？这会占平台的切换配额。
- **Q5**（D6）WS 中转：配对后多久没有任何帧算半开（建议 30 s，ping 25 s 一次）？重连连续失败几次（建议 5 次，约 10 s）后改要别的中转（`relay_switch{unreachable}` 只有主叫能发）还是试 UDP？
- **Q6**（D8）被叫是否在发出 `call_established` 时也算接受（协议改一句，平台本来就接受了这个呼叫）？
- **Q7**（D4、D7）"等打洞""等端口""再试一次"按每次失去中转计，而不是每个呼叫一次？`ws_wait_done` 是否也先等正在进行的重绑？
- **Q8**（D10）状态 JSON 的备用分配是否如实显示 `backoff`？（npf 的 `status` 文字可能依赖 `binding`。）
- **Q9** 测试钩子是否保留在发布构建里（第 6 节；集成测试与 natlab 用的是 `build-rel`）？
- **Q10** 第 7 节与原方向的冲突：local.json、对端与重连策略、服务器列表的外部渠道是否留在库里？

**决定**（2026-10-28，用户）：Q1–Q10 全部按建议——Q1 请求 10 s、30 s 后重发，之后每 30 s，在平台配额内；Q2 先探测当前地址；Q3 中转与直连的空闲阈值统一为 20 s；Q4 只因中转不通而在 WS 上的会话每 5 分钟试一次回 UDP；Q5 WS 中转 30 s 无帧算半开，重连连续失败 5 次后改要别的中转；Q6 被叫发出 `call_established` 时也算接受（signaling.md 改一句）；Q7 等待与重试按每次失去中转计，`ws_wait_done` 也先等正在进行的重绑；Q8 状态 JSON 如实显示 `backoff`；Q9 测试钩子留在发布构建里，集中到一个结构；Q10 库的边界按第 7 节。行为上的改动在 1b、1c、2、3 各步里做，1a 不改行为。

## 4. 定时：每个对象一个截止时间

**规则**：

1. 每个组件提供 `int64_t x_due(const x *, int64_t now)`：下一次要做事的单调毫秒，`INT64_MAX` 表示没有；和 `void x_tick(x *, int64_t now)`：做到期的事。组件不直接建定时器。
2. 对象（呼叫、备用分配、以后的节点）只有一个 `npf_timer`，排在各组件 `due` 的最小值。组件的截止时间变了就调用 `obj_reschedule()`：只在新的最小值比已排的早时取消重排，否则什么都不做（`punch/punch_ev.c:schedule`、`call_transport.c:anl_after_input` 都是这样）。
3. 定时器到时：`now = npf_mono_ms()`，按固定顺序 tick：会话（`anl_update`、flush、排空）→ 路径（健康、绑定器、重连）→ 路径管理器（选择、请求）→ 打洞 → 呼叫（期限）；每一步之后若对象已结束就停（同今天 `anl_timer` 检查 `c->ended`）；最后重排。
4. **不变式**：非终止状态都有有限的截止时间，或在表里注明"等事件"（第 3 节的最后一列）。单元测试对每个组件枚举所有状态检查这一点——"状态没有定时器"（BACKOFF 那次）从此在测试里就会失败。
5. "下一轮循环做"的两件事不是截止时间：释放（`t_free`）与 WS 的合并写出（`t_wsflush`），保留为 0 ms 的一次性回调。

**热路径**：每个数据报仍只算一次 `anl_check`（今天就是），再与缓存的"其余组件最小值"比较：多两次整数比较，没有额外的堆操作；`pm_rx` 只写一个时间戳（今天的 `p2p_rx_ms`、`relay_rx_ms` 也是）。

**今天的定时器到哪里**：

| 今天 | 对象 | 变成 |
|---|---|---|
| `t_anl` | 呼叫 | 会话的 `due`（`anl_check`） |
| `t_timeout` | 呼叫 | 呼叫的期限 |
| `t_punch`、`t_linger` | 呼叫 | 打洞的 `due` |
| `t_pcheck` | 呼叫 | 直连路径的探测时刻 |
| `t_rcheck` | 呼叫 | 去掉：健康由 `last_rx` 算出截止时间 |
| `t_standby` | 呼叫 | 管理器的热备截止 |
| `t_ws_wait` | 呼叫 | 管理器的 `DIRECT_PENDING(until)` |
| `relay.t_bind` | 呼叫 / 备用分配 | 绑定器的 `due`（重发、保活、探测）；第 2 步：`relay_c.at` |
| `t_wsre` | 呼叫 | WS 路径的重连截止 |
| `t_direct` | 呼叫 | 直连握手的重发（呼叫的 `due`） |
| `t_wsflush`、`t_free` | 呼叫 | 保留（下一轮循环） |
| `t_dog`、`t_retry` | 备用分配 | 备用分配的 `due`；第 2 步：`home_due`，连同 `t_bind` 一个定时器 |
| 节点的 11 个 | 节点 | 第 8 节之后再做：信令（`t_reconnect`、`t_ping`、`t_expect`、`t_login`、`t_idle`、`t_wake`）、网络（`t_watch`、`t_netcheck`、`t_udp_reopen`、`t_nat_retry`）、`t_pm` 各成一组 |

一个呼叫从 13 个定时器变成 1 个（另有 2 个下一轮回调），备用分配从 3 个变成 1 个。1b 去掉了 `t_pcheck`、`t_rcheck`（管理器的 `t_check`），1c 去掉了 `t_ws_wait` 与 `t_standby`（管理器的 `act_at`，同一个 `t_check`）：现在每个呼叫 9 个（`t_anl`、`t_timeout`、`t_punch`、`t_linger`、`t_direct`、`t_free`、`pm.t_check`、`pw.t_flush`、`pw.t_re`），另有 `relay.t_bind`。

**1d 的实现**（2026-10-29，`call.c` 的"the call's one timer"一节）：上面的 8 个定时器（`t_anl`、`t_timeout`、`t_punch`、`t_linger`、`t_direct`、`pm.t_check`、`pw.t_re`、`relay.t_bind`）合成 `npf_call` 的一个 `t_due`（排在 `due_at`），只留 `t_free` 与 `pw.t_flush` 两个下一轮回调。

- 各部分的截止时间（单调毫秒，0 表示没有）：呼叫的期限 `limit_at`、打洞的开始 `punch_at` 与余留 `linger_at`、直连发起方的重发 `direct_at`、管理器的 `pm.check_at`、UDP 中转的 `pu.bind_at`（绑定中是 700 ms 的下一次绑定，绑上后是 25 s 的保活，由绑定器的 `bound` 区分）、WS 中转的 `pw.re_at`（没有连接时是 2 s 后重连，重连的连接是 10 s 的配对期限）；AnLiu 的是 `tr_due`（`anl_check`）。
- `call_at(c, at)`：某个截止时间设成了 `at`；只在比已排的早时重排（内联：每个数据报都问一次，同今天 `anl_after_input`）。截止时间推后或取消时什么都不做，定时器早到一次、`call_tick` 发现没有到期的事，再按 `call_due` 排下一次。tick 期间（`ticking`）不重排，结束后排一次。
- `call_tick` 的顺序同规则 3：会话（`tr_tick`：`anl_update`、合并的 flush、失效检查、排空）→ 路径（`path_udp_tick`、`path_ws_tick`）→ 管理器（`pm_check`：有 AnLiu 连接时每次 tick 都跑，同 1c 的"每个 AnLiu 定时器一次"，没有时只在 `check_at`）→ 打洞（`call_punch_tick`）→ 直连重发（`call_direct_tick`）→ 期限；每一步之后呼叫结束了就停。
- AnLiu 的定时器合并了，没有单独留：忙时它约 20 ms 一次，合并后每次多做的只是 7 个截止时间的比较；每个数据报的 `call_at` 是两次比较（先内联、不跨文件调用：跨文件调用时 `npf_cpuprobe` 的指令数多约 0.15 %，内联后持平）。测量见第 8 节"1d 实际"。
- 不变式：没有结束的呼叫总有截止时间（建立之前是期限，有了密钥之后是 AnLiu 的 `anl_check`，它总是有限的：保活、空闲超时或 5 s 的安静检查），定时器不晚于最早的截止时间。单元测试 UT-35（`test_call.c`）在新呼叫、会话建立、已建立、UDP 中转绑定中、WS 中转待重连各检查一次，并检查截止时间提前、推后、完成三种重排。
- 绑定器（`relay_bind.c`）不再有自己的定时器：`relay_bind_run`、`relay_bind_probe` 与 `relay_c` 里的定时器和回调去掉，呼叫与备用分配都用 `relay_bind_begin` / `relay_bind_step`，时间由所有者管（呼叫是 `pu.bind_at`，备用分配是 `home.c` 的 `t_bind`，第 2 步并入备用分配的一个截止时间）。第 2 步之后：`pu.bind_at` 是绑定器自己的 `pu.r.at`，`relay_bind_step` 换成 `relay_bind_tick`，备用分配的三个定时器合成一个（第 3.3、3.4 节"2 的实现"）。

## 5. 信令消息描述表

（第 4、5 步实现，2026-10-29；原来的草案见下面 5.4 末尾的"与草案的差别"。）

### 5.1 格式

机制在 `include/npf/msg.h` 与 `proto/msg.c`，与消息无关：一个字段一行，一条消息一张表，一个解析器。

```c
enum { NPF_F_STR = 1, NPF_F_INT, NPF_F_BOOL, NPF_F_B64, NPF_F_ADDR, NPF_F_OBJ, NPF_F_ARR, NPF_F_TOK };
enum { NPF_F_REQ = 1, NPF_F_SECRET = 2, NPF_F_SKIP = 4, NPF_F_V4 = 8, NPF_F_STRICT = 16 };

typedef struct npf_field {
    const char *key;
    uint8_t     type, flags;
    uint16_t    off, size, aux;                /* 在结构里的位置；缓冲或数组的大小；长度或个数的位置 */
    int64_t     min, max, def;                 /* NPF_F_INT 的范围与缺省；NPF_F_B64 的最短；NPF_F_TOK 的 JSON 类型 */
    const struct npf_msgdesc *sub;             /* NPF_F_OBJ 的结构、NPF_F_ARR 的元素 */
} npf_field;
typedef struct npf_msgdesc { const char *name; const npf_field *f; uint16_t nf, size; } npf_msgdesc;

int  npf_msg_parse(const npf_msgdesc *d, const npf_json *j, int obj, void *out, char *err, size_t cap);
int  npf_msg_data(const npf_msgdesc *d, const npf_json *j, void *out, char *err, size_t cap);   /* 根的 "data" */
void npf_msg_wipe(const npf_msgdesc *d, void *msg);                                            /* NPF_F_SECRET 的字段 */
```

| 类型 | 结构里 | 规则 |
|---|---|---|
| `STR` | `char k[cap]` | 字符串，解码后最多 `cap − 1` 字节，没有控制字符（日志不会被拆成几行）、没有 NUL；必需的不能为空 |
| `INT` | `int64_t k` | 不带小数与指数的整数，在 `[min, max]` 内；缺失为 `def` |
| `BOOL` | `int k` | `true` / `false`；缺失为 `def`（`F_BOOL` 为 0，`F_BOOLD` 给出，如服务器列表的 `full` 为 1） |
| `B64` | `uint8_t k[cap]` 与 `int k_len` | Base64url，解码后 `min`–`cap` 字节；`k_len` 为 0 即缺失。必需、只有一种长度的（`call_id`、`relay_id`、`alloc_key`）没有 `k_len` |
| `ADDR` | `struct sockaddr_storage k` | `"ip:port"`、`"[ip6]:port"`（`npf_addr_parse`）；`V4`：只要 IPv4 |
| `OBJ` | 子结构 | 按子表解析 |
| `ARR` | `S k[cap]` 与 `int nk` | 元素按子表（单值的元素：子表只有一个没有键的字段，如 `m_addr4`、`m_port`、不为空的字符串 `m_s256`）；`SKIP`：不合格的元素跳过；必需的数组不能为空（服务器列表的 `servers`、每个服务器的 `ws`） |
| `TOK` | `int k` | 只记下值的 token（`-1` 缺失），检查 JSON 类型：64 KB 的服务器列表由处理器解码到堆上，`upgrade` 对象与 `packages` 原样交给钩子 |

规则对每条消息相同：未知键忽略；重复的键到不了这里（`npf_json_parse` 拒绝）；`null` 即缺失；必需字段缺失或不合格时整条拒绝，错误写成"字段：原因"（嵌套的写成 `relay.alloc_key: missing`），**从不带值**（可能是秘密）；可选字段不合格时按缺失（在 debug 级别记一行），带 `STRICT` 的除外：可选，但写错时整条拒绝（`reverse_listen` 的 `bind`、`port`、`udp`：data-channel.md 第 8 节"字段不合格时 `bad_request`"）；缺失的对象，它的字段也按各自的缺失（`TOK` 为 −1、`INT` 为缺省，不只是清零）；数组只取到上限，多出的忽略；只扫一遍对象（原来每个 `npf_json_get` 从头扫）。解析失败时已解出的部分也要擦：分发在处理器之后（解析失败时就在失败之后）总调用 `npf_msg_wipe`。

**消息本身**在 `node/msgs.h`：每条消息只写一次，是它的字段的列表；同一个列表在 `msgs.h` 里展开成结构，在 `msgs.c` 里展开成表（`F_*` 宏在两处的定义不同），结构与检查不会不一致，处理器读到的正是检查过的：

```c
#define M_PUNCH_INFO(T) F_B64X(T, call_id, 16, 0) F_INT(T, round, F_REQ, 0, 1000, 0) F_INT(T, port, 0, 1024, 65535, 0) \
    F_BOOL(T, stop) F_OBJ(T, cand, m_cand, 0)
NODE_MSG(m_punch_info, M_PUNCH_INFO)      /* msgs.h: typedef struct m_punch_info {...} m_punch_info; 与 m_punch_info_d */
TABLE(m_punch_info, M_PUNCH_INFO)         /* msgs.c: 它的表 m_punch_info_d */
```

### 5.2 例子

中转分配（`call` 应答、`incoming`、`call_accepted`、`relay_switch`、`relay_spare`、`home_open` 应答共用）：

```c
#define M_WS(T) F_STR(T, url, 256, F_REQ) F_INT(T, server_id, 0, 0, 1 << 30, 0)
#define M_RELAY(T) F_STR(T, mode, 8, F_REQ) F_B64X(T, relay_id, 8, 0) F_B64X(T, alloc_key, 32, F_SECRET) \
    F_ARR(T, udp, m_addr4, 4, F_SKIP) F_OBJ(T, ws, m_ws, 0) F_BOOL(T, spare)
```

`udp` 的 IPv6 地址与写错的地址跳过（`SKIP`、元素 `m_addr4` 只要 IPv4），与原来 `relay_obj_parse` 相同；`mode` 必需，所以没有 `mode` 的 `relay` 整个按缺失（原来也不用它）；处理器以 `relay.mode[0]` 判断有没有分配。

`punch_start`：signaling.md 的数值表就是这张表（`tests/unit/test_msg.c:doc_ranges` 读 signaling.md 对照 9 个可选数值的范围与缺省）：

```c
#define M_PUNCH_START(T) F_B64X(T, call_id, 16, 0) F_INT(T, round, F_REQ, 1, 1000, 0) F_STR(T, skip, 16, 0) \
    F_STR(T, strategy, 8, 0) F_STR(T, side, 8, 0) F_B64(T, punch_id, 8, 0, 8) F_B64(T, punch_key, 32, F_SECRET, 32) \
    F_OBJ(T, peer, m_peer, 0) F_ARR(T, range, m_port, 2, 0) F_INT(T, m_total, 0, 0, 4000, 1024) \
    F_INT(T, pps, 0, 1, 1000, 200) ... F_INT(T, start_at, 0, 0, F_TIME_MAX, -1)
```

"`skip` 时 `punch_id`、`punch_key` 不必需"这类字段之间的条件留在处理器里（`punch_id_len` 为 0 即缺失），表只管单个字段。处理器从约 70 行解析变成赋值。

### 5.3 分发

`msgs.c:node_msg` 是信令客户端唯一的入口（`node_signal.c:sig_msg` 只转给它）：

1. 信封按 `M_ENV` 检查：`v` 必须为 1，`type` 非空，`data` 为对象，`id`、`reply_to`、`status`、`error`、`message` 有上限；trace 级别只记信封（R10）；
2. 带 `reply_to` 的先找等它的请求（`node_signal.c:node_sig_reply`，`npf_reply_fn` 的签名不变：模块与 `api/` 用它）；
3. 按 `type` 查分发表 `{type, 表, 处理器}`（表写成 `D(m_x)`：只能是 `NODE_MSG` 的消息，它生成的 `m_x_fits` 保证结构不超过分发用的 4 KB `m_any`；服务器列表与文件的表用 `NODE_FILE`，放进分发表就编译不过）：节点的处理器 `node_on_*(n, 信封, 结构)`；给呼叫的（结构以 `call_id` 开头，`msgs.c` 里有一个编译期检查）找到它的呼叫再交给 `call_on_*(c, 结构)`，没有或已结束的丢弃；
4. 解析失败：记一行 WARN（类型与"字段：原因"），请求回 `bad_request`（原来只有 `incoming` 这样回，其他的静默返回，P8）；
5. 表里没有的类型：不是应答、没有 `call_id` 的交给 `hooks.on_event`（`mappings_changed` 这类给程序的事件），与原来相同。

隧道内的控制消息（`call_transport.c:call_control`）用同一个信封与各自的表（`close`、`reverse_closed`、`grant_update`；`reverse_listen` / `reverse_close` 在 `call_reverse.c`，`bind_approve` 在 `callee.c`），请求不合格同样回 `bad_request`。等平台应答的回调（`enroll`、`home_open`、`reverse_listen` 的应答）用 `node_env` 与各自的表读应答。

`welcome.time`、`punch_start.start_at` 的上限是 `F_TIME_MAX`（2^50 毫秒）：原来到 `INT64_MAX`，`time + RTT/2`、`npf_mono_ms() + (start_at − 现在)` 在平台给出极大值时会溢出（未定义行为）。

### 5.4 迁移了什么、改动量

| 类别 | 走描述表 | 仍是手写 |
|---|---|---|
| 平台 → 节点 | `welcome`（`login` 应答，及 `upgrade_required` 的 `data`）、`server_list`、`upgrade`、`probe`、`keys`（后两者用 `welcome` 的表）、`replaced`、`redirect`、`relay_spare`、`home_open` 应答、`enroll` 应答、`incoming`、`punch_request`、`revoke`、`bind_committed`、`call` 应答、`call_accepted`、`call_rejected`、`handshake`、`punch_start`、`punch_info`、`relay_switch`、`call_ended`：22 种 | `api/` 里等平台应答的回调（`engine_identity.c`、`platform.c`、`publish.c`、`peers.c`：每处读一两个字段，`npf_reply_fn` 改成结构不省行，见下）|
| 隧道内控制 | `close`、`reverse_listen` 及其应答、`reverse_close`、`reverse_closed`、`grant_update`、`bind_approve`：7 种 | `hello`（`tunnel/`：两个整数，表不比两行 `npf_json_get_int` 短）、`resources`（原样交给钩子） |
| WS 中转控制 | — | `proto/wsrelay.c` 的 4 种收到的（`relay_bound`、`relay_paired`、`relay_peer_gone`、`relay_error`）：只读 `type` 与 `relay_paired.peer`，表与分发都比这三行长；连接本身改在 `npf_sig` 上（下面"WS 与 XK 的骨架"） |
| 节点 → 平台、写出 | — | 全部：`npf_out` 的 JSON（第二波起库里唯一的写法，原来的 `npf_jw` 并入）与 `snprintf`（见下） |
| 服务器列表与文件 | 服务器列表的内容（`m_list`：`node_servers.c:npf_serverlist_parse`）、`state.json`（`m_state`：`callee.c:state_load`）、`local.json` 的设备记录（`m_device`：`local.c:device`）：`node_filedescs` | `local.json` 的 `settings`（键由文件给出，按键表检查）、`start`、根上的 `resources`（写错时整个文件拒绝，不是按缺失） |

`src/node` 里 `npf_json_get*` 与同类函数在信令处理器（`node_signal.c`、`call*.c`、`home.c`、`relay_bind.c`、`path_*.c`）中由约 140 处减到 3 处（服务器列表的解码、`npf_call_ctl_reply` 取请求的 `id`、未知类型有没有 `call_id`）。

**写出没有走描述表**：草案的 `npf_msg_emit` 要求每条发出的消息先有结构与表，再逐个字段赋值，行数与它要替换的 `npf_jw_k*`（现在是 `npf_out_k*`）调用相同，还多了结构；发出的消息的值都是本节点自己的，不是输入校验的问题。`snprintf` 拼的 13 处（`call_id` 是 Base64url、`reason` 经 `reason_code` 只剩 `a-z 0-9 _`）照旧。

**服务器列表与文件**（第二波，2026-10-29）：三者的检查与消息相同（同一个解析器、`tests/fuzz` 的 `msg` 目标也跑这三张表），处理器只把检查过的结构抄进 `npf_server_entry`、`npf_list_meta`、`npf_callee`、`npf_ldev`。与原来的手写解析相同的：服务器缺 `id`、`dh_pub` 不是 32 字节、没有可用的 `ws` 时跳过这台；`prio`、`weight` 越界取 1；`https` 只收 `https://` 开头的；`state.json` 的 `password` 用 `TOK` 原样取（口令可以含控制字符，`STR` 会把它当缺失而回到默认口令）；`local.json` 的设备记录，表里没有的键是模块的，原样保留（`core_key` 名单就是表）。不同的：服务器列表不合格时记一行 WARN（原来静默）、没有可用服务器的列表是 −1（原来是 0，调用者同样不用）；`doh` 名字的上限 127 → 255 字节（与 `https` 共用 `m_s256`）；`local.json` 的文本与解出的 `psk` 用后擦除（原来不擦）；字符串里的控制字符按缺失（原来照收）。

**WS 与 XK 的骨架**（第二波）：`proto/wsrelay.c` 原来自己开 WebSocket、自己做 XK 的两步（`npf_sig_xk_first` / `npf_sig_xk_finish`，sig.c 导出给它）、自己解密控制消息；现在 WS 中转连接就是一条 `npf_sig`（`npf_sig_open` 的 prologue `npf-relay-v1`），`npf_sig_cbs` 多一个 `on_raw`：设了它，握手之后每条消息先有一个类型字节，0 是密封的 JSON（`npf_sig_send` 也加这个字节），其余原样交给 `on_raw`（`NPF_WSR_ANL` 的数据报）。线上格式不变；中转的控制消息上限从 1 KB 明文变成信令的 32 KB（服务器经 XK 认证，同信令）；`npf_sig_xk_*` 两个导出函数没有了。数据报的热路径只多一次函数指针调用。

**改动量**（库的 `src` + `include`，`git diff 2491715`，同一个脚本数前后两版）：见第 8 节"4、5 实际"与"第二波实际"。

**与草案的差别**：草案写的是每条消息手写一个结构、一张表（估计每种 8–15 行）；实际用一个列表同时生成两者（每种 1–4 行），结构里的长度字段与数组个数由宏得出；`F_RAW`、`npf_msg_emit` 没有做；`hs`、`cpace` 不算秘密（Noise 与 CPace 的消息本来就是明文发送的）；`d_addr4` 的"不合适就跳过"是数组的 `SKIP` 标志。

## 6. 测试钩子

第 6 步之后（2026-10-29）：测试开关都在 `include/npf/testhooks.h` 的一张表 `NPF_TEST_HOOKS` 里，每个开关一行：结构里的成员、环境变量名、作用与起作用的文件；结构 `npf_test_hooks` 和 `platform/testhooks.c:npf_th_read` 读取用的表都由它展开。`npf_node_init` 用 `npf_th_read` 把开关读进节点自己的 `n->th`，每个节点一次（不是每个数据报、每个呼叫）；之后各处只读 `n->th`，库里别处没有 `getenv`（npf 的 `scripts/check.sh` 检查）。开关只有两种：数（正数才算开，没设、空、0、负数都是 0）和文字（没设或空是 `NULL`）。有开关打开时节点创建时记一行 `WARN test switches on: NPF_X=v ...`（原来只有 `NPF_TEST_UDP_FAIL`、`NPF_TEST_WS_FILE` 生效时、`NPF_NO_P2P`、`NPF_NO_UDP` 在各自的日志里提一句，那几行照旧）。

| 开关 | 类型 | 作用 | 起作用 | 用它的测试 |
|---|---|---|---|---|
| `NPF_NO_UDP` | 数 | 没有 UDP：报 `udp = 0`，会话走 WS，没有备用分配；`NPF_TEST_WS_FILE` 在运行中改它 | `nat.c`、`path_mgr.c`、`home.c` | loopback、media、quota、rlink、udp、wsswitch、natlab、`tests/bench/relay.sh`、realnet udp-fwd |
| `NPF_NO_P2P` | 数 | 不打洞，只走中转 | `call_punch.c:call_no_p2p` | loopback、quota、rlink、wsswitch、natlab、`relay.sh`、realnet fwd-billing |
| `NPF_NO_HOME` | 数 | 没有备用分配 | `home.c:home_allowed` | callsetup、natlab |
| `NPF_TEST_DROP_P2P` | 数 | 直连建立后这么久（ms）切断 | `path_direct.c:call_p2p_cut` | loopback、mesh |
| `NPF_TEST_DROP_P2P_PORT` | 数 | ……只切到对方这个端口的那条（**新**，原来是 `DROP_P2P=ms:port`） | 同上 | mesh |
| `NPF_TEST_BLOCK_RELAY` | 文字 | 这些中转地址或 URL 不可达 | `path_udp.c:call_relay_blocked` | loopback、wsswitch、natlab；单元 `test_call.c`、`test_direct.c` 直接改 `n->th` |
| `NPF_TEST_DROP_BIND_ACK` | 数 | 丢掉确认绑定的 `BIND_ACK` | `path_udp.c`、`home.c:ack_in` | loopback |
| `NPF_TEST_UDP_FAIL` | 文字 | 文件出现时 IPv4 主套接字失效 | `node_network.c:watch_cb` | homebind、resume |
| `NPF_TEST_WS_FILE` | 文字 | 文件存在期间没有 UDP（改 `n->th.no_udp`） | `watch_cb` | wsswitch |
| `NPF_TEST_PUNCH_FAIL` | 数 | 每一轮都失败（ms 后） | `call_punch.c` | callsetup、loopback、resume |
| `NPF_TEST_PUNCH_DELAY` | 数 | 这一侧晚开始（ms） | `call_punch.c` | loopback、natlab |
| `NPF_TEST_S3_HARD` | 数 | 这一侧当 S3 难侧、开 N 个套接字 | `call_punch.c` | mesh |
| `NPF_TEST_PUNCH_GAP_MS` | 数 | 报端口紧张与测试间隔（测试平台用） | `call_punch.c:write_pressure` | mesh |
| `NPF_TEST_REPUNCH_MS` | 数 | 测试平台的退避 | `write_pressure` | loopback、resume |
| `NPF_TEST_NO_SPREAD` | 数 | 登录后不分散对端的呼叫 | `peers.c:npf_peers_on_login` | mesh |
| `NPF_TEST_PUB_IP` | 文字 | 报一个伪造的公网 IP | `nat.c:npf_node_write_nat` | natlab |
| `NPF_TEST_CANDS_EXTRA` | 文字 | 加伪造的候选 | `nat.c:npf_node_write_cands` | natlab |
| `NPF_TEST_CANDS_LATE` | 数 | 第一次报候选后这么久不报 | `npf_node_write_cands` | punch |
| `NPF_TEST_HOST6` | 文字 | 这些 IPv6 地址算全局地址，不报 IPv4 候选（并入了 `NPF_TEST_ONLY_HOST6`） | `nat.c:gather` | punch |
| `NPF_TEST_PORTMAP_GW` | 文字 | 端口映射的替身网关 | `nodemap.c`（传给 `npf_portmap_*` 的 `at`） | punch |
| `NPF_TEST_SOURCES_AFTER_MS` | 数 | 外部渠道更早启动 | `sources.c:node_sources_check` | sources |
| `NPF_TEST_UPGRADE_RETRY_MS` | 数 | 必须升级时的重连间隔 | `node_signal.c:schedule_reconnect` | upgrade、upgradeinstall |
| `NPF_TEST_UDP_IDLE_MS` | 数 | UDP 流的空闲时间 | `call_transport.c`（传给 `npf_udpf_new`） | udp |
| `NPF_TEST_UDP_AGAIN_MS` | 数 | 只因中转不通而在 WS 上、UDP 仍可用时多久试回 UDP（Q4） | `path_mgr.c` | natlab |

**去掉的**：`NPF_TEST_PACE`、`NPF_TEST_UDP_MAX_AGE_MS`（诊断用，没有测试用；`udpfwd.c` 里只为后者存在的 `max_age_ms` 一起去掉），`NPF_TEST_ONLY_HOST6`（总是和 `NPF_TEST_HOST6` 一起用，并入）。npf 的模块与程序自己的开关（`NPF_TEST_IDLE_MS`、`NPF_TEST_QUOTA_AGAIN_MS`、`NPF_TEST_UPGRADE_WATCH_MS`、`NPF_TEST_FILES_MS`、`NPF_TEST_CALLER_CHECK`）不在这张表里：库不认程序的键（第 7 节）。另有配置键 `test_one_host`（安全设计 11.1）：它是配置而不是环境变量，留在配置里。

**行为上的变化**：

- 原来 `nat.c`、`call_punch.c`、`peers.c`、`sources.c`、`node_signal.c`、`udpfwd.c`、`ice/portmap.c` 在每次用到时 `getenv`（每个呼叫、每次写候选、每个 UDP 流）；现在节点创建时读一次，进程运行中改环境不再生效（没有测试这样用）。
- 数开关的 0 与负数是关：原来大多只看设没设（`NPF_NO_P2P=0` 也算开，`NPF_TEST_DROP_P2P=0` 是"立即切断"，loopback 改用 `=1`）；空的文字开关算没设。
- 节点的 `test_udp_fail`、`test_ws_file`、`test_no_udp` 并进 `n->th`。不在节点里的两处改由调用者给：`npf_portmap_request` / `_remove` / `_net` 多一个参数 `at`（网关的 `IP:PORT`，`NULL` 为默认路由的网关；`test_portmap.c` 直接传替身网关，不再 `setenv`），`npf_udpf_new` 多一个 `idle_ms`。
- 构建选项 `NPF_TEST_HOOKS`（原提议，关掉时没有 `getenv`）没有做：Q9 决定发布构建保留测试钩子；要做时只需在 `npf_th_read` 的循环外加一个条件。

**安全**：开关只从进程自己的环境读，不来自信令、中转、对端、配置文件或 API；能给进程设环境变量的人本来就能以这个用户运行任何程序，远端（平台、对端）打不开任何一个。发给平台的测试字段（`test_gap_ms`、`test_backoff_ms`）只在打开 `test_one_host` 的平台上生效（signaling.md）；`NPF_TEST_PUB_IP`、`NPF_TEST_CANDS_EXTRA` 伪造的地址要过平台的地址检查（安全设计 11.1），和一个恶意节点自己能发的一样。启动时的 WARN 让开着的开关不会悄悄留在产品里。

## 7. 库的边界（后续步骤）

原方向是把 npf.conf 的文字解析、local.json、服务器列表的外部渠道、按需连接与重连策略移到 npf。读过代码与文档后，其中三项与 libnpf 的公开约定冲突：

| 部分 | 今天 | 公开约定 | 建议 |
|---|---|---|---|
| npf.conf 的读取 | `node/conf.c:npf_conf_load`、`api/engine_config.c:config_load` | `npf_options.conf_dir` / `conf_file` 是两种启动方式之一（libnpf.md 第 4 节） | 留在库里，但只产出第 7.1 节的类型化配置；npf 自己的键（`control`、`control_token`、`web_dir`、`log`、`pidfile`、`keep_awake`、`hosted_ports`）从 `conf.c` `known_keys` 移到 npf 的模块（`npf_module.keys` 与 `check`；`keep_awake` 的取值今天还在 `api/cmd.c` 里校验，注释写着"the program's"）。`hosted_*` 键驱动库里公开映射的限额（`api/cmd.c` → `npf_peers_set_limits`），留在库里 |
| local.json | `node/local.c`、`api/ops*.c` | `NPF_PERSIST`、`npf_save`、`NPF_ESAVE`、`NPF_OPT_NO_SAVED_*`，"下次启动恢复"（libnpf.md 第 4、7 节） | **留在库里**（冲突）；整理成一个持久化接口，对端与转发只经它读写 |
| 服务器列表的外部渠道 | `node/sources.c` | 任何厂家设备在服务器换地址后都要能找回平台（security.md 7.5） | **留在库里**（冲突），归入信令客户端 |
| 按需连接与重连策略 | `node/peers*.c` | `NPF_CONNECT_KEEP` / `ONCE` / `ON_DEMAND`、对端状态与 `needs`、`peer_done` 事件（libnpf.md 第 7、10 节） | **留在库里**（冲突）；边界改为：对端层只用 `npf_call_*` 函数，不碰 `npf_node` 与 `npf_call` 的字段 |

所以"移到 npf"实际只剩 npf 自己的配置键与命令文字（后者已经移走）。库内部的边界（SDK 服务只经会话句柄与呼叫交互）比把代码挪进 npf 更有价值。

### 7.1 一个类型化的配置结构

今天四个来源都变成字符串键再合并（P10）。目标：

```c
typedef struct npf_cfg {                       /* 每个实例一份，内部 */
    /* 平台 */  uint8_t roots[2][32]; int nroots; const uint8_t *serverlist; size_t serverlist_len; ...
    /* 身份 */  const char *cred, *password, *model_cred, *serial, *hw_info, *model;
    /* 网络 */  int udp_port, portmap, secure, max_calls, punch_lead_ms, punch_sockets, report_host;
    /* 托管 */  int hosted_service; uint64_t hosted_exec; int sig_idle_s, sig_wake_s, udp_on_demand, udp_public;
    /* 运行时可改 */ int log_level, peer_idle_s, hosted_trust; ...
} npf_cfg;
```

- 一张键表（与第 5 节同一套描述表机制）：键名、类型、`offsetof`、范围、标志（`FILE_ONLY`：只能来自 npf.conf；`RUNTIME`：`npf_config_set` 即时生效；`SECRET`：`npf_config_get` 显示 `(hidden)`）。今天这些信息分在 `conf.c` 的 `known_keys`、`file_only_keys`、`path_keys` 和 `cmd.c` 的 `settable` 四张表里。
- `npf_setup` 直接填 `npf_cfg`，不再转成键（`api/setup.c` 的转换与 `node/setup.c:npf_node_cfg_from_conf` 的解析回去都可以去掉）；"字段与 `overrides` 冲突"的检查按键表做。
- npf.conf、`overrides`、local.json 的 `settings` 按键表写入同一个结构，顺序与今天相同（后者覆盖前者）。
- `npf_config_get` / `npf_config_set` 按键表读写；模块的键仍由模块校验。

**对公开接口的影响**：npf.h、`npf_setup`、`npf_config_*` 的行为不变；module.h 不变（可以加一个只读访问 `const npf_cfg *npf_mod_cfg(npf_t *)`，今天模块经 `npf_conf_get` 读键，`client/` 里 32 处）。

**第 5 步的实现**（2026-10-29）：做了键表，没有做 `npf_cfg`。

- 一张表（`node/conf.c` 的 `keys[]`，`npf/conf.h` 的 `npf_key`）：每个键的名字、类型（`STR`、`INT` 带范围、`0`–`1` 的开关、`ENUM` 带它的几个值）、缺省值（文字）和标志 `FILE`（只能来自 npf.conf、`overrides` 或 `npf_setup`）、`LIVE`（`npf_config_set` 即时生效）、`SECRET`（`(hidden)`，不记日志）、`SETUP`（有对应的 `npf_setup` 字段：不能再写在 `overrides` 里）、`PATH`（相对配置文件的目录）、`MULTI`（可以多行）、`UNLISTED`（即时生效、不在 `/v1/config` 的列表里：npf-hosted 的三个限额）。它取代了 `conf.c` 的 `multi_keys`、`path_keys`、`known_keys`、`file_only_keys`，`cmd.c` 的 `settable`、`settable_hosted`、`int_keys`、`npf_cmd_is_secret` 与 `check_value` 里的逐键检查，`api/setup.c` 的 `setup_keys` 与范围检查，`node/setup.c` 里各键的缺省值。
- 函数：`npf_key_find`、`npf_key_next`、`npf_key_is(名字, 标志)`（`npf_conf_known`、`npf_conf_file_only`、`npf_cmd_is_settable`、`npf_cmd_is_secret` 去掉了）、`npf_key_check`（"`max_calls: a number from 0 to 4096`"、"`connect_mode: p2p or secure`"）、`npf_conf_check`（一个来源的全部值）、`npf_conf_int`（整数键的值，没有或不合格时用表里的缺省；`ENUM` 返回它在值里的序号，`log_level` 的序号就是 `NPF_LOG_*`）。
- **每个来源都按表检查**（原来只有 `npf_config_set` 检查，npf.conf 与 `overrides` 的值 `atoi` 了事）：npf.conf、`overrides`、`npf_setup` 不合格时 `npf_create` 返回 `NPF_EINVAL` 并说明哪个键；`local.json` 的 `settings` 里只能来自 npf.conf 的、不合格的都记一行 WARN 后忽略。`hosted_exec` 是 64 位的指纹，按字符串（`strtoull`）。
- `npf_node_cfg_from_conf` 用 `npf_conf_int` 读，缺省值只在表里（原来散在各处的 `"0"`、`"-1"`、`"600"`、`"128"`……）；npf 的模块读库的整数键也用它（`modules/mappings.c` 的三个限额），`cli_basic.c` 与 `app/main.c` 用 `npf_key_is`。
- **没有做的**：类型化的 `npf_cfg` 与"`npf_setup` 直接填结构"。`npf_node_cfg` 本来就是节点的类型化配置，现在由键表读出；`npf_setup` 的字段仍转成键（每个字段一行），因为 `npf_config_get`、状态与模块都按键读，直接填结构就要为每个键另写一个"从结构读回文字"的函数，行数比转换多。npf 自己的键（`control`、`control_token`、`web_dir`、`log`、`pidfile`、`keep_awake`）仍在库的表里，标为 npf 的，移到 npf 的模块是第 7 步。

**第 7 步的实现**（2026-10-29）：库不再认得程序自己的键，模块只经一个头文件与库打交道。

- **键**：`npf_module.keys` 是与库自己的键同一种表（`npf_key`，`npf/conf.h` 的 `NPF_KEY_S` / `I` / `B` / `E` / `END` 写一行一个），`check` 钩子去掉：类型、范围、取值与 `FILE`、`LIVE`、`SECRET`、`PATH`、`MULTI` 都由表说，库对每个来源（npf.conf、`overrides`、local.json、`npf_config_set`）按表检查、隐藏秘密、拒绝只能来自 npf.conf 的、把 `LIVE` 的列进 `npf_config_json`。`npf_key_find` 先找库的表 `npf_keys`，再找已注册模块的（`npf_mods_key`，在注册表的锁里），所以不在实例里的 `npf_conf_load`（路径键）与 npf 自己读 local.json 时的过滤也认得模块的键：npf 在读 npf.conf 之前注册模块（`main.c`、`host.c`）。npf 的 `control`、`control_token`、`web_dir`、`log`、`pidfile`、`keep_awake` 移到 npf 的基本模块（`modules/cli_basic.c`），`hosted_ports` 移到映射模块（`mappings.c`）；`tun_*`、`auto_upgrade` 原来的 `t_check`、`u_check` 由表代替。`npf_mod_key_known`、`npf_mods_check`、`npf_key_next` 去掉。库的表 48 → 41 个键。反过来，库自己的键由库施行：npf-hosted 的三个限额在 `npf_create` 里设（`npf_hosted_limits`，原来是映射模块的 `m_begin` 读库的键再设）。
- **模块的接口**：`src/api/npf_int.h` 去掉。模块只包含 `npf/module.h`：实例 `struct npf`（前半是模块读写的：配置、身份、节点、对端、事件循环、额度；`src/api's own from here on` 之后是 API 线程、会话与媒体表、模块表）、钩子、库为模块做的事（`npf_emit`、`npf_become_node`、`npf_pub_put` / `remove`、`npf_ops_record*`、`npf_source_name`、`NPF_CMD_UNSAVED`，以及模块转告其他模块的 `npf_mods_nick_set`、`npf_mods_peer_removing`）；只有库调用的 `npf_mods_*`、`npf_sess` / `npf_med`、`npf_status_out`、`npf_cmd_*` 移进 `api_internal.h`；`src/api` 在 `npf_common` 的头文件路径上改为 `PRIVATE`（模块再也包含不到 `api_internal.h`）。npf 的 `get` 与 `status --json` 改用公开的 `npf_config_get`、`npf_config_json`、`npf_status_json`（不认得的键说 "not a configuration key"，原来打印空行）。没有把 `struct npf` 做成不透明的：模块读它的 21 个成员 248 处（`node` 99、`lc` 47、`peers` 41、`loop` 19……），每个换成访问函数要约 20 个函数、改 250 行而不少一行，模块又是随库一起重新编译的。
- **7.1 的类型化配置**：不做 `npf_cfg`（理由同"第 5 步的实现"）；去掉的是重复的一份：`npf_t` 的 `cfg` 是 `npf_node_cfg` 交给节点前的副本，节点复制一份（`node.cfg`）以后两份并存，`npf_become_node` 要两边都改。现在 `npf_create` 在局部变量里填好交给节点，此后只有 `n->node.cfg`（模块的 14 处一样）。
- **应答回调**：`npf_reply_fn`、`npf_ctl_fn` 拿解析好的信封 `npf_env`（`node.h`；`msgs.h` 的 `m_env` 就是它，编译期检查与 `M_ENV` 的字段一致），没有应答时为 `NULL`：原来每个处理器再取一遍 `error`、`message`、`data`（`home.c:open_reply`、`node_signal.c:enroll_reply`、`call_reverse.c:rev_reply` 甚至整个信封再解析一次），共 32 处。`npf_platform_err` 仍取 JSON（npf 的 `account.c` 用它解释 `npf_request` 的应答文字）。
- **转发的两种取法合一**：`npf_peer_forward_info` 并入 `npf_peer_forward_state`（`npf_fwd_state.text`：给人看的状态 "up"、"retry in N s (why)"）。`state.json` 的 `paired` 直接读进 `npf_callee.paired`（`m_paired` 就是 `npf_paired`，编译期检查），不再逐个拷贝。

## 8. 迁移步骤

**估计方法**：用 awk 量出要移动或去掉的函数的行数（例如路径相关的函数今天约 1 090 行：`call_path.c` 261、`call_ws.c` 206、`call_relay.c` 中约 430、`call.c` 中约 100、`call_transport.c` 中约 55、`call_punch.c` 中约 40），再按第 2–5 节的草图估新代码；误差 ±30 %。测试代码另计。

| 步 | 范围（文件） | 行数（库，净） | 风险 | 守护 | 新测试 | 从此不可能的错误 |
|---|---|---|---|---|---|---|
| **1a** 路径对象，不改行为（实际：净 +326 行，含测试开关 57 行） | 新 `node/path.h`、`path_direct.c`、`path_udp.c`、`path_ws.c`、`path_mgr.c`（先只做发送与命名）；`call_path.c`、`call_relay.c`、`call_ws.c` 的内容移入；`call_transport.c:anl_out` 改为 `pm_send`；`npf_call_path` 由管理器给出，`api/ops.c:npf_path_code` 改为枚举；路径用到的钩子（`DROP_P2P`、`BLOCK_RELAY`、`DROP_BIND_ACK`、`NO_P2P`）先进第 6 节的结构 | +150（约 1 000 行移动） | 中：热路径的发送与分发 | `scripts/check.sh`（单元、loopback、mesh、wsswitch 等）；natlab 全部；`npf_cpuprobe`（`tests/unit/cpuprobe.c`：一个会话搬 N MB 的 CPU 与空闲开销）前后对比 | `test_path.c`：假的路径实现，验证发送的路由（主、双发、WS 排他）；经 UDP 中转的吞吐与 CPU 对比（今天只有直连的 `cpuprobe` 与只测封装的 `relayprobe`） | 发送的路径与显示的路径不一致；路径名字符串被解析回枚举 |
| **1b** 统一的健康模型（实际见第 2.4 节"1b 的实现"与下文） | `path_*.c`、`path_mgr.c`；去掉 `call_check_p2p`、`call_check_relay` 的重复部分；WS 的无声检测（新） | −150（含新增 40） | 高：行为变化（Q2、Q3、Q5） | natlab `udp-lost`（NL-36）、`udp-back`、`stale`、`skew-relay`；mesh（单向切断）；wsswitch；RN-16 | 假时钟下每条健康规则一行一测；natlab 新用例：中转第一个地址不通、WS 半开（丢掉 TCP 而不关连接） | 被依赖却没有健康检查的路径（int-1031 那类）；同一问题几套规则 |
| **1c** 管理器的策略与请求 | `path_mgr.c`、`call.c`、`call_punch.c`（提示）；去掉 `relay_gave_up`、`ws_wait_done`、`call_ws_wait_end`、`call.c` 里四个对所有呼叫的循环中路径的部分 | −100 | 高：WS 的去留、请求的重发（Q1、Q4、Q7） | 同 1b，另加 resume、callsetup、hosted | 第 3.6 节逐行；平台不应答 `relay_switch` 时的重发（需要测试平台的一个开关：丢掉某呼叫的 `relay_switch`） | 没有截止时间的请求（`relay_switch` 只发一次那类）；WS 会话被打洞"打通"（10-27 (5)）；"每个呼叫一次"的重试 |
| **1d** 呼叫的单一截止时间 | `call.c`、`call_transport.c`、`call_punch.c`、`path_*`：13 个定时器 → 1 个（加 2 个下一轮回调） | −80 | 中：时序、热路径 | `npf_cpuprobe`（含 S 个空闲会话的开销）；RN-16（长时间、空闲唤醒）；check.sh | 不变式测试（每个状态有截止）；空闲会话的唤醒次数（不多于保活所需） | 标志依赖定时器存在（`accepted` 那类）；状态没有定时器 |
| **2** 绑定器与备用分配 | `relay_bind.c`（状态枚举，保活显式）、`home.c`（一个截止时间） | −60 | 中 | homebind；natlab `home*`、`learn`、`stale-nospare`；`test_home.c`、`test_relay.c` | 第 3.3、3.4 节逐行，不用套接字 | BACKOFF 没有定时器（10-27 (6)）；一直续用已回收的分配（int-1031） |
| **3** 打洞与呼叫的状态机 | `call_punch.c`、`call.c`、`call_handshake.c` | −120 | 中 | punch、callsetup、loopback；natlab 各策略 | 第 3.1、3.2 节逐行 | 漏记接受而丢掉 `punch_update`（10-27 (1)）；端口给错轮次（10-27 (4)） |
| **4** 描述表：呼叫相关的消息（实际见下文"4、5 实际"） | 新 `proto/msg.c`；`call*.c`、`home.c`、`relay_bind.c` 约 25 种消息 | −100（±100） | 低–中：解析的边界 | `test_json`、`tests/fuzz`；`test_home.c` 里平台的向量；集成全部 | 每张表的往返（解析 → 写出 → 解析）；按表生成的模糊输入；对照 signaling.md 的字段表 | 缺必需字段被静默忽略；同一字段两处范围不同；秘密字段忘了擦除 |
| **5** 描述表：其余消息；配置键表（实际见下文） | `node_signal.c`、`call_reverse.c`、`call_transport.c`（控制）、`proto/wsrelay.c`；`conf.c`、`api/engine_config.c`、`api/setup.c`、`node/setup.c`、`api/cmd.c` | −250 | 中：配置的优先次序 | `test_conf`；API 测试（`test_contract`、`test_api` 的 `npf_config_*`）；`test_module` | 每个键的来源优先次序；`npf_setup` 与 `overrides` 冲突 | 一个键在两处有不同的解析；只能来自 npf.conf 的键从别处进来 |
| **6** 测试钩子（实际见下文"6 实际"） | 新 `platform/testhooks.c`；13 个文件里的 `getenv` | −20 | 低 | 全部（它们用这些开关） | `NPF_TEST_HOOKS=OFF` 的构建里没有 `getenv`（检查符号） | 每个数据报或每个呼叫读环境变量；钩子悄悄地开着 |
| **7** 库的边界（实际见下文"7 实际"） | npf 的键移到模块；对端层只用 `npf_call_*` | −100（npf +100） | 中：npf 的模块 | npf 的客户端测试、`test_module`、API 测试 | — | 库认得程序自己的键 |
| **8** 主被叫的不对称 | `call*.c` 的 47 处 `c->caller` 收进一个"角色"表 | −50 | 低 | 全部 | 角色表的单元测试 | — |

**1b 实际**（2026-10-28）：库的 `src` + `include` 38 175 → 38 519 行（+344；不计注释与空行 31 690 → 31 911，+221），`src/node` 15 710 → 16 046 行，而不是计划的 −150。去掉的是 `call_check_p2p`、`call_check_relay` 与两个检查定时器（约 120 行）；加的是规则本身（`pm_tick`、`pm_rules_of`、`pm_check`，约 130 行）、WS 中转原来没有的无声检测、配对期限与放弃（约 80 行）、绑定器的两种次序（约 40 行）和热备的探测窗口（约 30 行），以及按这个仓库的习惯写在代码旁的说明。新增单元测试约 380 行（`test_path_health.c`、`test_relay.c` 的地址次序、`test_call.c` 的 WS 放弃）。

**1c 实际**（2026-10-29）：库的 `src` + `include` 38 527 → 38 423 行（−104；不计注释与空行 32 009 → 31 926，−83，用同一个脚本数的前后两版），`src/node` 16 054 → 15 948 行（−106）（`git diff` +349 −453）。去掉的：`call_relay_gave_up`、`ws_wait_done`、`call_ws_wait_end`、`call_ask_ws_relay`、`call_relay_ask_ok` / `asked`（约 125 行），`call_standby_done`、`pm_standby_start` 与 `t_standby`、`standby_check` 的各处（约 70 行），`ws_elsewhere` 与 `fail_wait`（约 25 行），`npf_node_ws_calls_udp_back`、`npf_node_calls_to_ws`（约 35 行），`direct_doubt` 与 `direct_lost` 里的请求（约 30 行），`call_relay_take`（并入 `path_udp_setup`），三处一样的"结束打洞、交还难侧套接字"（改为 `call_punch_end`）；加的：`pm_decide`（约 75 行，含注释）、`call_need`（约 60 行）、`pm_check` 里的输入与动作（约 35 行）、`path.h` 的状态与枚举（约 35 行）、Q4 的测试开关与节点的 `udp_back_ms`。新增单元测试 260 行（`test_path_decide.c`，`test_call.c` 的重发时刻）；测试平台的开关 `NPF_TEST_DROP_RELAY_SWITCH` 在 npf 的服务器里（8 行）。热路径没有动（每个数据报仍只写一个时间戳），`pm_decide` 在每次 `pm_check`（AnLiu 的定时器）跑一遍：`npf_cpuprobe`、`npf_relayprobe` 与 npf 的 `tests/bench/relay.sh`（UDP、WS 中转）前后持平，在波动之内（数字见 npf 的 `docs/implementation.md`）。

**1d 实际**（2026-10-29）：库的 `src` + `include` 38 423 → 38 440 行（+17；不计注释与空行 31 926 → 31 926，持平），`src/node` 15 948 → 15 965 行（`git diff` +259 −242），而不是计划的 −80。去掉的：8 个定时器的回调与它们的启停（`anl_timer` 的排程、`anl_after_input` 里的比较、`timeout_cb`、`call_timers_stop`、`punch_timer`、`linger_done`、`direct_retry`、`pm_timer`、`ws_pair_late` 与 `ws_reconnect` 的定时器部分、`relay_keepalive_timer` / `relay_keepalive`），以及绑定器自己的定时器（`relay_bind_run`、`relay_bind_probe`、`run_start`、`run_timer` 与 `relay_c` 的 `t_bind`、回调，约 45 行，备用分配改为在 `home.c` 自己驱动 `relay_bind_begin` / `relay_bind_step`）；加的：单一定时器本身（`call_arm` / `call_at`、`call_timer`、`call_due`、`call_tick`，约 55 行，含注释）、各部分的 tick 入口与截止时间字段（`tr_tick` / `tr_due`、`path_udp_tick`、`path_ws_tick`、`call_punch_tick`、`call_direct_tick`）。原来的回调本来就短，它们的内容变成 tick 照样留着，所以代码行持平；多出的 17 行是新接口与字段的注释。新增单元测试 79 行（UT-35，`test_call.c`）。

热路径与空闲（改前 1c `7ffe7bf`、改后交替运行；数字见 npf 的 `docs/implementation.md`）：AnLiu 的定时器并进来了，`call_at` 先在头文件里内联比较（跨文件调用时 `npf_cpuprobe` 的指令数多约 0.15 %，内联后持平：64 MB 8 次中位数 2 638.5 / 2 637.5 百万条）；每个空闲会话每分钟的唤醒（`npf` 进程的上下文切换，有会话减没有会话）直连 24–26 → 20–21、UDP 中转 25–28 → 22–23、WS 中转 24–25 → 23，少的是管理器那个定时器单独醒的几次；剩下的就是 AnLiu 的 5 s 安静检查、15 s 保活与对方的保活、中转 25 s 的保活与应答。

**2 实际**（2026-10-29）：库的 `src` + `include` 38 440 → 38 390 行（−50；不计注释与空行 31 926 → 31 874，−52），`src/node` 15 965 → 15 915 行（`git diff` +284 −334），计划是 −60。去掉的：`relay_c` 的 `active`、`bound`、`keep` 与读写它们的各处，`path_udp` 的 `bind_at`、`bind_next`、`udp_gave_up`，`relay_bind_step`、`relay_bind_echo_due`，`relay_bind_take` 里没有调用者的 WS 分支（约 45 行）；备用分配的 `t_dog`、`t_retry`、`t_bind`，`dog_arm`、`dog_check`、`dog_timer`、`retry_timer`、`bind_timer`，`lost`，`H_BINDING` 到 `H_BACKOFF` 四个状态，`home_take`，`node_home_sig_lost`，D11 的分支（约 110 行）；加的：绑定器的状态枚举与 `at`、`relay_bind_tick`、`relay_bind_up`（约 35 行，含注释），备用分配的 `home_due`、`home_tick`、`home_timer`、`home_arm`（约 55 行，含注释），`spare_bound`（从 `ack_in` 分出，单元测试直接调用它）。新增单元测试约 220 行（`test_relay.c:bind_table`、`test_home.c:test_table`）。热路径没有动：`RELAY_DATA` 的收发与分发不变，呼叫的截止时间里 `pu.bind_at` 换成 `pu.r.at`。

**3 实际**（2026-10-29）：库的 `src` + `include` 38 390 → 38 354 行（−36；不计注释与空行 31 874 → 31 831，−43），`src/node` 15 915 → 15 879 行（`git diff` +275 −311），计划是 −120。去掉的：`npf_call` 的 12 个成员（`state` 换成 `st`；`accepted`、`peer_hello`、`up_told`、`ended`、`peer_closed`、`punched`、`punch_of`、`punch_wait_keys`、`info_port`、`info_round`、`linger_at`）与读写它们的各处，`call_relay_leave`、`call_accept_seen`、`call_close_quiet`、`call_ended`（并入 `call_close`），`tun_ready` 里的 `call_established`（移进转移），`call_punch_sockets_back` 与打洞结束回调里重复的交还（`socks_back` 一处），`call_punch_tick` 的两套截止判断，`punch_info` 的两种轮次匹配，`call_handle_incoming` 自己的会话计数（用 `key_sessions`），打洞回调里"呼叫已结束、已有直连"的检查（状态保证不会）；加的：两个状态枚举与三个判断（约 15 行，含注释），`call_set_state` 的状态对照与转移（约 25 行，含注释），`call_close` 的三种方式（约 10 行），`call_punch_to`（约 12 行，含注释），`punch_port`，以及一行调试日志（`call_established`，单元测试据此检查）。−120 的估计以为 `call.c`、`call_handshake.c` 里有更多可以随状态去掉的代码；实际上那里的判断大多是会话与路径的（`keys_ready`、`tun`、`anl`），`ended` 的 75 处只是换成 `call_over`。新增单元测试约 390 行（`test_call_state.c`），`test_call.c` 移走约 140 行。热路径没有动：`npf_cpuprobe`、`npf_relayprobe`、`tests/bench/relay.sh udp` 前后持平（数字见 npf 的 `docs/implementation.md`）。

**瘦身实际**（2026-10-29，第 3 步之后、第 4 步之前，不改行为）：1a–3 合起来比计划多了约 500 行（库的 `src` + `include` 37 848 → 38 354，+506，计划 −360），这一遍收回一半。库的 `src` + `include` 38 354 → 38 093 行（−261；不计注释与空行 31 832 → 31 736，−96，用同一个脚本数的前后两版），`src/node` 15 879 → 15 638 行（−241）；1a–3 连同瘦身合计 +245 行（不计注释 +164）。去掉的：重复第 2.4、3.1–3.6 节与 nat-traversal.md 10.3、data-channel.md 3 / 10 的注释（规则、决定表、状态说明、当初的测量，约 165 行，改为指向章节）；测试开关的进程级副本与一次性锁（`npf_th`，改为每个节点读一份，−23）；路径操作表的 `name`（`pm_name` 按种类查表）与各文件的前置声明；`pm_dead`（就是 `pm_health(DEAD)`）、`pm_has`、`path_direct_gone`（就是对不属于路径的套接字的 `call_p2p_drop`，`call_free` 也经它关自己的套接字）；只有一个调用者的 `call_ws_send`、`call_relay_send_data`、`direct_alive`、`anl_after_input`、`punch_end`；`wsr_gone` 里重复 `call_ws_leave_conn` 的几行；呼叫与备用分配各写一遍的"中转地址被测试屏蔽"（`call_relay_addr_blocked`）；主叫在密钥之前经中转收到的数据报改为定长数组（最多 8 个，原来是链表）。考虑过而保留的：`pm_tick` 里两处相同的探测（合成一个函数反而多 2 行）；`path_direct_up` 与 `path_direct_fixed` 的公共部分（合并不省行）；`testhooks.c` 并进 `node.c`（第 6 步要在这里收齐 25 个开关）；`call_tick` 的部件表（条件各不相同，表不比现在短）。线上格式、npf.h、module.h、日志都不变；热路径只少了一次指针间接（`n->th` 在节点里）：`npf_cpuprobe`、`npf_relayprobe`、`tests/bench/relay.sh udp` 前后持平（数字见 npf 的 `docs/implementation.md`）。

**4、5 实际**（2026-10-29）：库的 `src` + `include` 38 093 → 38 556 行（+463；不计注释与空行 31 733 → 32 066，+333），计划是两步合计 −350。第 4 步（描述表与全部收到的消息，第 5 节）38 093 → 38 528（+435；不计注释 +312）：新的机制 `proto/msg.c` 与 `npf/msg.h` 约 265 行，消息的列表与分发 `node/msgs.h`、`node/msgs.c` 约 320 行；去掉的是各处理器的手写解析、`node_dispatch`、`call_find`、`relay_obj_parse`、`parse_daykeys` 与 `sig_msg` 里的类型判断（`src/node` 原有文件 −357 行）。第 5 步（键表，第 7.1 节）38 528 → 38 556（+28；不计注释 +21）：键表与 `npf_key_*`、`npf_conf_check`、`npf_conf_int` 约 110 行，去掉的是四张键名单、`cmd.c` 的可设置表、整数范围表、逐键检查与秘密判断、`api/setup.c` 的字段键表与范围检查、`node/setup.c` 里各键的缺省值（`api/` −66 行）。比计划多出的原因：计划把"写出"也算进去（草案的 `npf_msg_emit` 替换约 22 处 `snprintf` 与各处 `npf_jw`，估计去掉 700–800 行里的大半），实际写出没有走描述表，因为每条发出的消息先要有结构与表、再逐字段赋值，行数不比 `npf_jw_k*` 少（第 5.4 节）；收到的消息里，处理器的业务本身（证书的验证、呼叫与路径的决定）占了大部分，解析只是其中的一部分。得到的是表中第 4、5 行最后一列那些"从此不可能"的错误：必需字段缺失时整条拒绝并记日志（原来多处静默返回，P8）、同一字段在所有消息里的范围相同（`relay` 的六处共用一张表）、秘密字段统一擦除（原来 `call_relay_setup` 留着 `alloc_key`，`grant`、`ticket` 不擦）、一个键只有一处解析（npf.conf、`overrides`、`npf_setup`、`local.json`、`npf_config_set` 都按同一张表检查）。测试净增约 330 行（`test_msg.c` 198 行，`test_conf.c` 的键表约 50 行，模糊测试的目标 `msg` 约 60 行，`test_contract.c` 的三项；处理器的测试改为经 `node_msg` 送整条消息）。`msg` 目标：变异模糊 2 000 万条与 libFuzzer（clang 18，覆盖引导）1 000 万条，都没有报告。热路径没有动（数据报、隧道、中转的封装不经过这里）。

**第二波（描述表）实际**（2026-10-29，int-w1 之后）：库的 `src` + `include` 37 496 → 37 431 行（−65；不计注释与空行 30 977 → 30 904，−73），`src/node` 15 718 → 15 709（−9），`src/proto` 1 617 → 1 564（−53）（用同一个脚本数前后两版）。走描述表的：服务器列表（`node_servers.c` −33）、`state.json`（`callee.c` −13）、`local.json` 的设备记录（`local.c` −21），新表与生成宏 `msgs.h` / `msgs.c` +54；WS 中转连接改在 `npf_sig` 上（`wsrelay.c` −57，`sig.c` +2，`sig.h` −3）。没有走的（不省行）：`wsrelay.c` 的 4 种控制消息、隧道的 `hello`、`api/` 与 `peers.c` 等平台应答的回调（每处一两个字段）。安全评审的几项一并做了：缺失的对象按字段缺失（`absent` 递归）、`NODE_MSG` 与 `D()` 的编译期大小检查、`STRICT`（`reverse_listen`）、`grant_update` 送来相同的目标列表时不再分配与记 INFO（同一秒签发的 `issued` 相等仍接受，signaling.md）。测试：`test_msg.c` 的表检查覆盖 `node_filedescs`，新增嵌套缺失、`STRICT`、必需数组、服务器列表、`state.json`、设备记录的用例；模糊测试的 `msg` 目标跑全部表，新目标 `control`（离线节点上主被叫两侧的 `call_control`，即隧道控制消息的分发与处理器）。

**6 实际**（2026-10-29）：库的 `src` + `include` 37 496 → 37 524 行（+28；不计注释与空行 30 977 → 31 001，+24），`src/node` 15 718 → 15 701 行（−17），计划是 −20。`getenv` 从 12 个文件 35 处变成 `platform/testhooks.c` 的 1 处。去掉的：各处的 `getenv` 与 `atoi` / `atoll`（多数一处两三行，`call_punch.c:write_pressure` 的局部变量、`call_transport.c` 的 `NPF_TEST_PACE` 块、`sources.c`、`node_signal.c` 的块），节点的三个测试成员，`udpfwd.c` 的 `max_age_ms`，`NPF_TEST_ONLY_HOST6` 一个开关，`NPF_TEST_DROP_P2P` 的 `ms:port` 解析，`test_portmap.c` 的 `setenv`；加的：开关表（25 行，每行带注释）、展开结构与读取表的宏、通用的读取与 WARN（约 30 行），`npf_portmap_*` 的网关参数与 `pm_job.gw`。比计划多，是因为原来大多数开关一行就读完（`getenv(...) != NULL`），集中以后每个开关仍要一行表、一处使用；得到的是表中这一行最后一列那两条：每个数据报或每个呼叫读环境变量（原来写候选、每个 `punch_start`、每个 UDP 流都读），钩子悄悄地开着（现在启动时 WARN，`check.sh` 不许库里别处有 `getenv`）。新增单元测试 15 行（`test_sys.c`：开、关、0、空、数、文字）。热路径：`call_p2p_cut`（每个直连数据报）照旧读 `n->th` 的两个整数。

**第二波底层实际**（2026-10-29，w2-low，不改线上格式与 npf.h）：库的 `src` + `include` 37 496 → 37 051 行（−445；不计注释与空行 30 992 → 30 562，−430，用同一个脚本数的前后两版），`src/node` 15 718 → 15 541、`src/proto` 1 617 → 1 463、`src/crypto` 1 208 → 1 154、`src/tunnel` 2 612 → 2 574、`src/platform` 3 736 → 3 767（收进了别处的四样东西）。库里只剩一个 JSON 写法：`npf_jw` 并入 `npf_out`（`npf_out_jobj` / `jarr` / `jend` 记住每层的种类，`jstr` / `jint` / `jbool` / `jb64` / `jraw` 与 `k*` 成员，键也转义）；发出的消息的长度上限改为 `npf_out.max`（信封 `NPF_JSON_MAX_SIZE`、隧道控制 `NPF_CTRL_MAX`、`state.json` 照旧），含口令的文字用 `npf_out.secret`（增长时新开缓冲、擦掉旧的，释放时擦除；信封与 `state.json`）；信封自己估算的长度、登录的 8 KB 缓冲去掉。一个扩容函数 `npf_grow`（`npf_out`、WS 与 HTTP 的缓冲、隧道的写缓冲与控制缓冲、子链路表、循环的处理表 / 子循环 / 定时器堆 / Windows 的 poll 数组、对端的连接与子链路、会话；npf 里 httpd、文件服务、映射的访问、设备列表、TUN）取代 16 处各写一遍的倍增 `realloc`。地址的函数一组 `npf_addr_len` / `port` / `eq` / `str` / `parse` 在 `sys.h`（原来的 `npf_sa_*`、`node.c` 的两个、`relay_bind.c` 的 `call_same_addr`），`HOST:PORT` 的拆分一个 `npf_hostport`（原来三份，规则各不相同）；套接字错误的判断两种系统共用一份（`npf_sock_err`、`NPF_SE(x)`、`npf_sock_starved`），SOCKS 应答的原因在 Windows 上也读得到。密码学：Noise 的 psk 令牌与 DH 令牌一处、e 令牌的混合一处，`init` 先检查再拷贝密钥；Monocypher 的 BLAKE2b 一个函数（KDF、哈希、HMAC、指纹，证书的签发者 id 就是指纹的低 32 位）；签名与验证同样拼接；base64url 解码一个循环；OpenSSL 的 AEAD 两个方向一个函数；SIV 用 `npf_ct_eq` 比标签、不符时擦掉明文，CPace 失败时也擦掉标量。JSON 解析器读键只有一种方式（`str_view`）。去掉的检查（证明多余）：证书链里叶子权限的第二次检查（`npf_cert_chain_parse` 传入的 `perm` 就是同一位）。测试：UBSan 的报告从此让测试失败（`-fno-sanitize-recover`；`test_creply.c` 原来在日志里有一条 `memcpy` 空指针）。热路径（数据报、隧道帧、AEAD 与 SIV）只换了扩容与比较的函数，扩容仍只在放不下时调用：`npf_cpuprobe` 64 MB，改前（`6d50bc9`）与改后交替各 6 次，用户态指令数中位数 2 721.3 / 2 720.2 百万条，被叫一侧 CPU 335 / 331 ms；`tests/bench/relay.sh udp` 各 5 次，下载 69.4 / 71.1 MB/s、上传 65.7 / 74.2 MB/s，CPU 16.0 / 15.0 与 16.4 / 15.0 ms/MB：持平，在波动之内。

**7 实际**（2026-10-29，w3-api）：库的 `src` + `include` 37 021 → 36 979 行（−42；不计注释与空行 30 505 → 30 463，−42），`src/api` 5 467 → 5 359（−108，`npf_int.h` 的 145 行大半并入 `npf/module.h`，`include` 4 025 → 4 118）、`src/node` 15 522 → 15 495；npf 的 `client/`（不含库与第三方）21 983 → 21 950 行（−33；不计注释 19 068 → 19 031），计划是库 −100、npf +100：键表让模块的键不必各写检查（npf 少了 `u_check`、`t_check`，多了两张表与一张 npf 自己的键表），键从库移出、库的一份检查同时管了它们，所以两边都减。"对端层只用 `npf_call_*`"没有做（第 7 节表中那一行；对端层 `peers*.c` 是节点的一部分，归节点那一波）。从此不可能的错误：库认得程序自己的键（`test_conf.c` 检查表里没有）、模块的键与库的键检查方式不同、模块包含 `src/api` 的内部头文件（不在路径上）、`npf_t` 与节点的配置两份不一致。

**第三波·节点实际**（2026-10-29，w3-node：`src/node`、`tunnel`、`proto`、`ice`，不改 npf.h 与 module.h）：库的 `src` + `include` 37 021 → 36 469 行（−552；不计注释与空行 30 409 → 29 895，−514，用同一个脚本数的前后两版），`src/node` 15 522 → 15 175、`src/tunnel` 2 574 → 2 430、`src/proto` 1 410 → 1 399、`src/ice` 1 073 → 1 010、`include` 4 025 → 4 010，`src/platform` 3 786 → 3 818（收进了三处各写一份的东西：`npf_if_has`、`npf_text_dec`、`npf_thread_detached`）。做了的：`-R` 的目标一张表（原来 TCP 的在隧道里、UDP 的在 `udpfwd.c` 里各一张；现在是呼叫的 `rev[]`，被叫一侧是监听、主叫一侧是目标，隧道经 `npf_tunnel_io.target_ok`、UDP 流经 `npf_udpf_io.rev` 来问，没有回调的主叫一律拒绝）；服务器列表与升级清单一个验签函数 `npf_signed_verify`（域由权限位决定，别的权限位拒绝）；本机候选一个 `npf_gather_host(family)`；`local.c`、`conf.c` 的扩容用 `npf_grow`；`npf_wipe_free`；节点里的死成员（`req_id`、服务器项的 `cdn`、`relay`）与死函数（`npf_call_peer`、`npf_call_grant_account`、`npf_call_open` 并入带速率组的那个）；`call_punch.c` 的探测服务器配置一处（`punch_probes`）、地址检查改为文件内的（`ip != 0` 证明多余：`0/8` 已经拒绝）；`node_servers.c` 的读列表一处；`callee.c` 的 `paired_at`、`revoked`；`node_network.c` 的 `udp_dead`；隧道的 Happy Eyeballs 状态收进握手结构、写本地端一个 `write_out` 与带复位的 `tunnel_flush_local` / `tunnel_queue`、`shared_add`；`udpfwd.c` 收目标的回包直接读进帧里（少一次拷贝与 `u->in`）、`npf_addr_eq`；媒体帧用 `npf_scratch`（原来大于 2 KB 的每帧一次 `malloc`）；公网映射的准入整个在 `peers_connections.c`（`peers_public_admit`）；中转绑定的发送 `relay_bind_send` 一处（呼叫与备用分配共用）；NAT 与端口映射的名字查表；几十行用不到的 `#include`、几个一行的包装与前置声明、重复设计文档的文件头注释。行为上的变化：主叫没有反向映射时被叫开的子链路也走 SOCKS 应答 `REP = 02`（原来立即 `RESET(2)`，data-channel.md 0.52）、主叫一侧 TCP 与 UDP 的反向映射合计 16 个（原来各 16）；`node_nat_login` 在探测起不来时 `on_login` 只调一次（原来两次：两次 online 事件、两次模块登录）；配额暂停的公网映射在下一个会话建立时不再重新监听；`HOST:PORT` 形式的对端名、`NPF_TEST_PORTMAP_GW` 的端口按 `npf_text_dec` 严格解析。**第 8 步（角色表）不做**：重数一遍，能放进表的仍只有十来处常量（AnLiu 角色、打洞控制方、SIV 方向、流的方向），表与查表不比 `c->caller ? … : …` 短，其余是行为，见下面"关于第 8 步"。热路径（隧道的写本地端、UDP 回包、媒体帧、`RELAY_DATA` 的掩码）：`npf_cpuprobe` 64 MB，改前（`adade35`）与改后交替各 6 次，用户态指令数中位数 2 720.9 / 2 718.3 百万条；`npf_relayprobe`（`RELAY_DATA` 的封装）交替各 6 次中位数 12 194.88 / 12 194.88 百万条；npf 的 `tests/bench/relay.sh udp` 两轮（5 次、8 次），CPU 下载 13.8 / 15.0、14.7 / 15.1，上传 14.8 / 13.4、15.5 / 13.5 ms/MB（两边合计持平），吞吐互有高低：在这台机器的波动之内（同时有别的测试在跑）。

**第四波·节点实际**（2026-10-29，w4-node：`src/node`、`tunnel`，不改线上格式与 npf.h；module.h 之外的内部接口两处：`npf_peer_wake_now` 不再有返回值，新增 `npf_backoff`、`npf_text_plain`）：库的 `src` + `include` 36 427 → 36 243 行（−184；不计注释与空行 29 935 → 29 770，−165，用同一个脚本数的前后两版），`src/node` 15 148 → 14 993、`src/tunnel` 2 430 → 2 398、`src/api` 5 359 → 5 350、`include` 4 103 → 4 115；测试 +268 行（新 `test_peers.c`、`test_tunfaults.c`）。第三波留下的三个问题：来源名单（`allow_from`，`npf_policy_rules_match`）只看地址、不论规则的端口（原来按端口 0 或 65535 匹配，带端口范围的规则只在范围到 65535 时才算）；读本地端时 `npf_scratch` 没有内存，子链路复位（原来直接返回，电平触发的循环空转，虚拟本地端的轮询也是）；公网映射的准入回调（`opened`）删掉了映射，连接立即关闭、报 `mapping_closed`（原来照样等会话，挂在已删除的转发上）。审读时又找到三个：应用在 `refused` 事件里删除对端，等待队列在自己的清理中被再清理一次，同一个描述符关两次（那时可能已是别的套接字；现在先把队列整理好再报，`demand_flush` 先把队列取下）；`-D` 已答 `05 00` 而请求转不出去（没有内存或传输断了）时子链路停在问候状态，后来的字节又当问候解析（现在复位）；`call_end` 的报告排满时换掉的是第一个而不是等得最久的。做了的：`node_signal.c` 的两处证书接收合成 `cert_in`，`expect_stop`、`probe_changed` 内联，`cur_id`，没用的头文件；`npf_wipe_free` 用到其余各处（`sig.c` 与 `out.c` 正被别人改，留下）；对端、转发与服务器列表外部渠道共用 `npf_backoff`；资源的文字检查与昵称共用 `npf_text_plain`；对端层：`npf_peer_wake_now` 一条路径（会话起来时才开始算空闲，`npf_peers_on_call_state` 本来就做），`fwd_report(f, NULL)` 即"转发可用"，`npf_peer.keep`（就是 `connect != ONCE`）、`pconn.slot`（按转发的 id 找）去掉，几个一处调用的小函数内联；呼叫：只在一个文件里用的四个函数改为 `static`，`call_hs.pinned`（只写不读），媒体与 UDP 转发的 kick 就是 `anl_kick`；隧道：`socks_connect` 一遍分支同时得到地址与文字，控制与数据两个入口共用一个 `input`，限速桶的补充去掉算式已经覆盖的判断；`udpfwd.c` 的 `counted`（就是 `!out && fd >= 0`）。证明多余而去掉的检查：`cert_in` 的长度（消息表把两个证书都限在 1024，正是两个缓冲的大小）、`fwd_why_code` 的 `why == NULL`、`bind_send` 的绑定状态（每个调用者都有绑定在进行）、`ping_cb` 的 `n->sig`（连接断开时它的定时器一同停掉）、`npf_sig_close` 之前的三处非空判断（它接受 NULL）、`rg_refill` 的 `now <= at_ms`、`tunnel_destroy` 再置 `dead`、`npf_udpf_drain` 的 `u->s == s`。行为上的变化：错类型的证书记为"不通过验证"（原来另有一条警告）；节点证书的日志由"issued"改为"renewed"。"对端层只用 `npf_call_*`"（第 7 节）已经成立：对端层不包含 `call_internal.h`，`npf_call` 对它是不透明的；`npf_node` 只读 `loop` 与三个字段（`cfg.number`、`online`、`th.no_spread`），为它们加取值函数只会多出代码，不做。`npf_platform_err` 改取 `npf_env` 不做：npf 的 `account.c` 手里只有 `npf_request` 应答的 JSON，要它自己解析信封得再公开一个解析函数，两边都多。考虑过而保留的：`open_sub` 里 `t->dead` 分支对 fd 的处理（今天到不了，但它保护借来的 fd 不被关两次）、`idle_cb` 的 `node_sig_fail_pending`（依赖应用的 `busy` 回调不发请求）、`home_new`（`test_home.c` 直接调用）、`path_direct` 的 `keys_ready` 与呼叫的那份重复（`path.h` 正被别人改）。之后按一份对 `src/tunnel` 的外部评审（用户同意）又改了一次，为读起来对称而不是为行数：`tunnel_enter` 与 `tunnel_leave` 成对（原来 17 处裸的 `depth++`），本地端的读、写、关写各一个函数（`local_read`、`local_write`、`local_shutdown_wr`，套接字与虚拟本地端的分支各在一处），`vgone` 改为枚举，`struct sublink` 按握手、流控、限速、虚拟本地端、统计分节，`npf_tunnel_vkick` 去掉没用的 id（它本身就是轮询的预约，`tunnel_virt_arm` 去掉），`open_sub` 写明本地端在各条路径上归谁；`data_in` 的 SOCKS 分支没有拆出去（拆出去多几行）。`src/tunnel` 2 398 → 2 417（+19，注释与两个小函数；不计注释 2 018 → 2 021），库合计 36 262 行（不计注释 29 773）。

**第四波·JSON 实际**（2026-10-29，w4-json）：JSON 的读与写合成一个模块：`src/proto/json.c` 与 `include/npf/json.h`（原来写在 `platform/out.c` / `npf/out.h` 里，`out.h` 只剩通用的文字缓冲 `npf_out` 与 `npf_grow`；`npf_out` 里仍有写出用的四个状态字段）。留在 `src/proto`：它是信令的线上格式（上限是 signaling.md 的），唯一的结构性使用者 `msg.c` 在旁边，读的一半不必搬家。库的 `src` + `include` 36 427 → 36 422 行（−5；不计注释与空行 29 935 → 29 916，−19），`src/platform` 3 818 → 3 688、`src/proto` 1 399 → 1 522；npf 的 `client/`（`app`、`modules`、`tray`、`tools`）21 875 → 21 765 行（−110；不计注释 18 916 → 18 815）。去掉的：`npf_out_jbool`（没有调用者，`kbool` 直接写）；`msg.c` 里自己反转义比较键的 `find`（改为 `npf_json_eq`）与 B64 字段手写的解码（`npf_json_b64`）；`npf_json_get` 的循环（`npf_json_eq`）；npf 的第二个 JSON 读法 `app_json_member`（约 50 行，扫状态文字找顶层成员）、`start.c` 的四处 `strstr("\"online\":true")` 之类（字符串值里出现同样的文字就会读错）、`npf-punch` 的 `jstr` / `jint`（`strstr`，`session_id` 缺失时空指针）；`local.c`、托盘、`awake.c`、`files_main.c`（状态与 `files.json`）各自估算 token 数再 `malloc` 的几行。改了的：`npf_json_eq` 按反转义后比较（与 `npf_json_get`、重复键检查一致；原来带转义的一律不等）；`npf_json_parse_file` 改为 `npf_json_parse_big(j, s, len)`：自己的 JSON（local.json、状态），token 在堆上（`npf_json_free`），数组最多 65 535 项（原来 256：一个账户的对端多于 256 个时状态读不出来），对象仍最多 256 个键；`npf_out_jb64` 每次编码 192 字节再写（不再伸进 `npf_out` 的缓冲，秘密的文字用后擦）。托盘读状态与 `/v1/nodes` 原来是 512 / 2 048 个 token、32 KB，现在同样用 `parse_big`。测试：`test_json.c` 加转义的键与值、500 字节的 base64url、`parse_big` 的长数组 / 键数上限 / 文件上限；模糊测试的 `json` 目标加两条性质：`parse` 接受的 `parse_big` 也接受且 token 数相同、每个字符串写回再读相同（`json` 3 000 万条、`msg` 1 000 万条、`control` 200 万条，没有报告）。热路径没有动（数据报、隧道帧不经过 JSON）。

合计库净减约 800 行（±30 %），新增单元测试约 1 500 行。1a–1d 合起来就是"第 1 步：路径抽象及其截止时间与状态机"；四个小步各自可以合入、现场测试，任何一步都可以单独回退。

**关于第 8 步**：`c->caller` 的大部分不是打洞调度带来的，而是协议与安全模型的角色：主叫是打洞的控制方（`NOMINATE`）、只有主叫发 `relay_release` 与 `relay_switch{unreachable}`、主叫打开数据流而被叫在接受回调里取它、被叫有目标策略与密钥份额、主叫的中转先于接受到达（`rearly`）、首次配对的 `hello` 次序、被叫发 `call_established`、被叫以第一个 `punch_start` 或自己的 `call_established` 为接受（第 3 步，Q6）、只有主叫让出难侧轮次（`busy`）。`call_transport.c` 的 20 处多是流与策略的所有权。平台接管打洞调度之后，与调度有关的不对称已经去掉（signaling.md "`punch_result` 与重试"）。所以这一步只是把这些角色差异集中成一张表，收益有限，放在最后。第 6 步之后再数（2026-10-29）：`call*.c`、`path*.c` 里按主被叫分支的约 50 处，`call_transport.c` 19 处（流与隧道的所有权、AnLiu 的角色、控制消息谁可以收：那一段正随消息表改动），`udpfwd.c` 另有 18 处是 UDP 转发自己的方向，不属于呼叫。角色表能收进的只有常量那几类：AnLiu 角色（`call_transport.c`）、打洞的控制方（`call_punch.c`）、`path_direct.c` 的两个 SIV 方向、隧道与媒体的方向、谁开流，约 10 处；其余是行为（谁发 `relay_release`、谁等接受、谁让出难侧轮次），放进表也是一个标志或函数，不比 `if (c->caller)` 短。

## 9. 不做的事与取舍

- **不重写 AnLiu 的接入**：`anl_*` 的调用方式、`conv` 的分发（`call.c:node_udp_input`）、`ANL_OPT_CARRIER` 的用法都不变，只是从 `npf_call` 移到会话对象。
- **不改线上格式**，除非某个问题的决定需要：第 1–3 步只改节点的行为（何时重发、何时探测），用的都是现有消息；Q6 若决定改，是 signaling.md 一句话的语义，不改格式。
- **不拖慢热路径**：转发（隧道、子链路）、媒体、UDP 流、`RELAY_DATA` 的封装与验证、数据报分发的顺序不动；每个数据报不新增分配、不新增堆操作；1a 与 1d 用 `npf_cpuprobe`、`npf_relayprobe`（`tests/unit/`）对比前后，经中转的吞吐与 CPU 用 npf 的 `tests/bench/relay.sh`（1a 加的，两个构建交替运行）（`call_transport.c` 注释里提到的 `tests/bench/anlws/npf-backlog.sh` 不在这个树里）。
- **不在第 1 步里拆 `npf_node`**：节点的 11 个定时器、信令、NAT 都留到第 1–3 步之后；先做出问题最多的呼叫与路径。
- **不改 npf.h、`npf_setup`、module.h 的行为**；内部接口的变化按 npf 用到的那张清单（第 2.2 节）给访问函数。
- **不引入新的线程或回调线程**：一切仍在实例的事件循环上。
- **不做整体重写**：每一步单独合入、单独现场测试、可以回退；每一步之前与之后 check.sh、natlab、RN-16、wsswitch.sh、NL-36 都要通过。
- **平台不改**，除了测试平台可能要的一个开关（丢掉某个呼叫的 `relay_switch`，用来测 Q1 的重发）。

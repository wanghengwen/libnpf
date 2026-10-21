# libnpf 开发者指南

版本：1.0。更新日期：2026-10-21。

本文写给在自己的产品里集成 libnpf 的开发者：NAS、路由器、摄像头等设备的固件，以及连接这些设备的电脑、手机应用。公开接口只有 `include/npf.h`，本文按使用顺序说明它；协议细节见 [信令协议](../protocol/signaling.md)、[数据通道协议](../protocol/data-channel.md)，NAT 穿透与安全设计见同目录的 [nat-traversal.md](nat-traversal.md)、[security.md](security.md)。

## 1. 基本概念

| 概念 | 说明 |
|---|---|
| 平台 | 信令服务器、中转服务器和地址探测服务器。节点登录平台，平台负责找到对方、协调打洞、分配中转，不转发明文。libnpf 用根公钥（`root`）认平台，用服务器列表（`serverlist`）找服务器 |
| 实例 | 一个 `npf_t`，是平台上的一个身份。一个进程可以有多个实例 |
| 节点（`NPF_ROLE_NODE`） | 长期运行，有编号（9 位数字）时可以被连接，同时也可以主动连接别的节点 |
| 客户端（`NPF_ROLE_CLIENT`） | 一次性任务：连接设备、账户操作，用完即停 |
| 直连（`NPF_ROLE_DIRECT`） | 不用平台：两端用预共享密钥，经 UDP 直接连接 |
| 编号与配对口令 | 设备的编号由平台分配。第一次连接一台设备要用它的配对口令，配对后双方记住对方的公钥，以后凭密钥连接 |
| 会话 | 两个实例之间端到端加密的连接。先走 UDP 中转，打洞成功后无缝切到直连，直连失效时退回中转，UDP 不通时走 WebSocket 中转 |
| 资源 | 设备发布、允许别人访问的服务或地址。没有发布的目标一律拒绝 |
| 转发 | 主叫一方的端口转发：`-L`（本地端口到对方的服务）、`-D`（SOCKS5 代理）、`-R`（对方开端口连回本地） |
| 应用数据 | 会话控制通道上的消息：可靠、有序，每条不超过 16384 字节 |
| 媒体流 | 会话中的音视频帧流，可以多路同时进行、反复开关：迟到丢帧、关键帧、FEC、带宽估计 |

## 2. 构建与集成

需要 CMake 3.16 起和 C99 编译器，没有其他外部依赖（AnLiu、Monocypher、mbedTLS、rxi/log.c 都在 `third_party/`）。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"   # lib/libnpf.*、include/npf.h、lib/pkgconfig/npf.pc
cc app.c $(PKG_CONFIG_PATH="$PWD/install/lib/pkgconfig" pkg-config --cflags --libs npf) -lpthread
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `NPF_BUILD_TESTS` | ON | 单元测试、API 测试、模糊测试 |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c` |
| `NPF_PEERS` | ON | 本节点主动连接别的节点；只被连接的设备可以关掉，程序更小 |
| `NPF_WITH_TLS` | ON | `wss://`、`https://` |
| `NPF_USE_OPENSSL` | OFF | 用 OpenSSL 3 代替 mbedTLS 做 TLS 和应用层密码学（服务器上用；mbedTLS 的调用经一把进程级锁，OpenSSL 没有这把锁） |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

**产物**

- 共享库：`libnpf.so.1`（Linux）、`libnpf.dylib`（macOS）、`libnpf.dll` 与导入库（Windows / MinGW）；
- 静态库：Linux 上的 `libnpf.a` 是一个可重定位目标，除 npf.h 的函数外全部符号都是局部的，内置的 AnLiu、Monocypher、mbedTLS 不会和应用自己的同名库冲突。macOS、Windows 暂不做这一步；
- 所有目标文件都以隐藏可见性编译，导出的只有 npf.h 的 `npf_*` 函数。

**平台**：Linux（glibc、musl，x86_64、ARM）、macOS、iOS、Android、Windows 10 起。交叉编译用 CMake 的工具链文件；嵌入 iOS / Android 应用时把库静态链接进应用，应用自己提供可写的 `data_dir`。

**ABI**

- `NPF_API_VERSION` 为 1，soname 为 `libnpf.so.1`；不兼容的修改会提高 soname；
- 调用方分配的结构体第一个字段都是 `size`：`npf_options`、`npf_callbacks`、`npf_media_opt`、`npf_media_stats`。库只读调用方编译时就有的部分，其余用默认值；以后只在末尾增加字段；
- 用 `npf_options_init`、`npf_callbacks_init`、`npf_media_opt_default` 初始化，`npf_media_stats` 由调用方填 `size`。

## 3. 快速上手

### 3.1 设备：被别人连接

完整的程序见 `examples/device.c`，要点如下：

```c
npf_callbacks cb;
npf_options o;
npf_t *dev;
char err[256];

npf_callbacks_init(&cb);
cb.event = on_event;            /* "enrolled" {number}、"online"、"stopped" ... */
cb.session = on_session;        /* 有人连上、断开 */
cb.data = on_data;              /* 对方发来的应用数据 */

npf_options_init(&o);
o.conf_dir = conf_dir;          /* 应用决定的目录，只读：npf.conf、根公钥、服务器列表 */
o.data_dir = data_dir;          /* 持久化存储上的目录：身份、编号、配对状态 */
o.overrides = "model_cred = NPFV2....\nserial = SN0001\n";   /* 凭证不落盘 */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
o.app_name = "acme-nas";        /* 1-32 个 a-z 0-9 . _ -，平台的记录里看得到 */
o.app_ver = "2.3.0";
if (npf_create(&o, &dev, err, sizeof err) != NPF_OK || npf_start(dev) != NPF_OK)
    return 1;
/* ... 运行中 ... */
npf_destroy(dev);               /* 停止、等待、释放 */
```

两个目录由应用决定（第 4 节），`conf_dir` 里的 `npf.conf` 至少要有平台的根公钥和服务器列表：

```
root = <平台的根公钥>
serverlist = serverlist.bin
resource = tcp/http 127.0.0.1:5000 nas | 管理页面
```

第一次运行时库用型号凭证向平台注册，拿到编号和每台不同的默认配对口令（第 5 节）。用户在手机或电脑上输入编号和口令即可连接；`resource` 行决定连上的人能访问什么（第 6 节）。

### 3.2 客户端：连接一台设备

```c
o.role = NPF_ROLE_CLIENT;       /* 其余同上；客户端不需要凭证 */
npf_create(&o, &cli, err, sizeof err);
npf_start(cli);
/* 编号、口令、一个本地端口转发；ONCE：会话结束后不重连（事件 peer_done） */
npf_peer_add(cli, "318204776 -p 8fK2mQ7v -L 127.0.0.1:8080:127.0.0.1:5000", NPF_PEER_ONCE, err, sizeof err);
```

会话建立时 `session` 回调收到 `up = 1` 和会话编号，此后：

- 浏览器打开 `http://127.0.0.1:8080` 就是设备上的管理页面；
- `npf_session_send(cli, session, buf, len)` 发送应用数据，对方的 `data` 回调收到；
- `npf_media_open` / `npf_media_send` 发送音视频（第 9 节）。

第一次连接用口令配对，之后库在 `data_dir/local.json` 里记住对方的公钥，`-p` 可以不给。设备被重置、换了密钥时，旧的配对不再有效（状态里是 `pairing_lost`），要用它现在的口令重新配对。

对端的写法也可以按词给出，词里可以有空格：`npf_peer_add_argv(cli, argc, argv, flags, ...)`。`NPF_PEER_SAVE` 把对端连同转发记进 local.json，每次启动都连接，断开后一直重试。

### 3.3 不经平台的直连

两端在同一网络或有固定地址时，可以完全不用平台。先生成一个 32 字节的随机密钥，以 Base64url 写进一个文件（权限 0600，别人能读时库拒绝使用），两端各放一份，然后：

- 被连接的一方：`NPF_ROLE_DIRECT`，配置 `direct = 9850`（或 `ADDR:PORT`）与 `direct_psk_file = key`；
- 连接的一方：`NPF_ROLE_DIRECT`，`npf_peer_add(n, "203.0.113.5:9850 --psk-file key -L ...", 0, ...)`。

握手为 Noise_NNpsk0，传输同样是 AnLiu，转发、应用数据和媒体流都可以用。直连模式不需要 npf.conf。

## 4. 目录与配置

**两个目录**

| 目录 | 库的权限 | 内容 |
|---|---|---|
| `conf_dir` | 只读 | `npf.conf`（或 `conf_file`）及其中引用的文件：凭证、根公钥、服务器列表、直连密钥 |
| `data_dir` | 读写 | `identity`（本机密钥）、`node.json`（注册得到的编号与默认口令）、`state.json`（口令、配对、所有者）、`account.cert`、`serverlist-saved.bin`（平台下发的新服务器列表）、`local.json` |

- `data_dir` 不给时用配置中的 `dir`，再没有时等于 `conf_dir`；必须在持久化存储上，丢了会重新注册；
- 秘密（`identity`、`state.json`）各自成文件，权限 0600；
- 运行时库会锁住身份：同一个 `data_dir` 不能同时被两个实例或两个进程使用（直连模式除外）。

**生效的设置**按顺序叠加，后者覆盖前者：

1. `npf.conf`；
2. `npf_options.overrides`：应用传入的 `key = value` 行（命令行参数、从加密存储读出的凭证）；
3. `local.json` 的 `settings`：`npf_config_set` 带保存时写在这里。

库从不写 npf.conf；运行时保存的设置、对端和转发都写进 `data_dir/local.json`（临时文件 + rename，原子替换）。`node` 和 `resource` 行不覆盖，三处的都加入。

**常用配置键**

| 键 | 说明 |
|---|---|
| `root` | 平台的根公钥，可以多个（空格或逗号分隔） |
| `serverlist` | 签名的服务器列表文件；平台下发更新的列表时保存在 `serverlist_saved`（默认 `data_dir/serverlist-saved.bin`，`off` 不保存） |
| `server`、`server_pub` | 不用服务器列表时直接给一台服务器的地址与公钥（测试用） |
| `cred`、`password` | 一机一密的设备凭证 `NPFD1.…` 与默认口令 |
| `model_cred` | 一型一密的型号凭证 `NPFV2.…` |
| `serial` / `serial_file` | 设备序列号（文件取第一行）；不给时用最小的物理网卡地址 |
| `hw_info` | 硬件信息 `值1\|值2\|值3`（eMMC CID、SoC 序列号等）；不给时库自己读 |
| `model` | 产品型号，平台用于统计 |
| `resource` | 发布的资源（第 6 节），可以多行 |
| `node` | 启动时连接的对端，写法同 `npf_peer_add`，可以多行 |
| `udp_port` | 主 UDP 端口，0 为任意 |
| `portmap` | 0：不向路由器申请 PCP / NAT-PMP 端口映射 |
| `connect_mode` | `p2p`（默认，直连优先）或 `secure`（只走中转） |
| `max_calls` | 同时被连接的会话上限，默认 32 |
| `peer_idle` | 秒数：保存的对端按需连接，最后一个连接结束这么久后断开（适合手机）；0 为一直连接 |
| `punch_sockets` | 打洞可同时使用的 socket 数（默认 1024） |
| `hosted_trust` | 1（默认）：接受平台为设备所有者及其分享对象签发的授权，这些人不用口令 |
| `report_host` | 0：登录时不报告主机信息（系统、机器名） |
| `doh_servers` | 服务器列表的 DoH 备用渠道 |
| `log_level` | `error`、`warn`、`info`（默认）、`debug`、`trace` |
| `direct`、`direct_psk_file` | 直连模式的监听地址与密钥 |

`npf_config_get` / `npf_config_set` 读写设置；`npf_config_set` 返回 `NPF_OK` 表示立即生效，返回 1 表示下次启动生效。

## 5. 设备注册

设备拿到编号有两种方式：

| | 一型一密（`model_cred`） | 一机一密（`cred`） |
|---|---|---|
| 写进设备的 | 每个产品型号一串 `NPFV2.…`，所有设备相同 | 每台设备一串 `NPFD1.…` 和默认口令 |
| 编号 | 第一次联网时向平台注册，平台分配 | 出厂前已分配，可以印在标签上 |
| 适合 | 软件包形式分发、没有产线写入流程 | 自有硬件、有产线 |

一型一密的凭证由厂家用平台签发的厂家证书自己签发，是秘密：用 `overrides` 从加密存储传入，不要写进公开的仓库或日志。

以 `NPF_ROLE_NODE` 第一次运行时库自动注册：

- 成功：事件 `enrolled {"number": "..."}`。编号和库生成的默认口令保存在 `data_dir/node.json`，`npf_command(show)` 显示，应用把默认口令显示在设备界面或交给用户首次配对；
- 被拒：事件 `enroll_failed {"error", "reason", "retry_in"}`，库约 `retry_in` 秒后自己重试；状态 JSON 的 `enroll` 记着最近一次结果。

| `reason` | 含义 |
|---|---|
| `unregistered` | 产品型号没有在平台登记 |
| `unbound` | 这份型号凭证没有在平台绑定 |
| `revoked` | 产品型号已停用，或这份凭证已吊销 |
| `expired` | 产品型号的登记已到期 |
| `whitelist` | 序列号不在白名单 |
| `quota` / `rate` | 产品型号的注册总量已满 / 本小时注册数已满 |
| `conflict` | 这个序列号属于另一台设备（硬件对不上） |
| `clone` | 同一序列号的设备正以别的密钥在线（疑似克隆） |
| `wait` | 原设备刚刚还在线，稍后自动重试 |
| `bad_chain` / `bad_sig` | 凭证不是平台认可的 / 签名不对 |
| `disabled` | 这台设备的编号已被平台停用 |

**恢复出厂设置**：清空 `data_dir` 即可。下次运行重新注册，序列号相同、硬件多数项相同、原身份已离线 5 分钟以上时拿回原编号（密钥换新，已配对的一方需要重新配对）；一机一密的设备从凭证重新派生，编号、密钥、默认口令都不变。

## 6. 发布资源

设备只放行它发布的资源，别人连上后只能访问这些，其余一律拒绝；什么都不发布，就什么都访问不到。连上的一方在会话建立时收到资源列表（状态 JSON 的 `peers[].resources`）。

| 类型 | 目标 | 用途 |
|---|---|---|
| `tcp` | `HOST:PORT` | 一个服务。可以带服务类型：`tcp/http`、`tcp/https`（网页，目标可带起始页 `127.0.0.1:80/admin`）、`tcp/rdp`、`tcp/ssh` 等，供连接的一方决定怎么打开 |
| `udp` | `HOST:PORT` | 一个 UDP 服务（唯一放行 UDP 的类型） |
| `net` | `lan`、`ADDR[/PREFIX][:PORT[-PORT]]` 或 `*` | 一批地址：`lan` 为本机与直接相连的私有网段 |
| `socks` | 同 `net` | 作为代理（`-D`）访问，`*` 即互联网出口 |
| `reverse` | `*`、`PORT` 或 `PORT-PORT` | 允许连接的一方在本机回环地址上开端口（`-R`） |

- 写在 npf.conf：`resource = TYPE[/SVC] TARGET NAME [| 说明]`，这些是固定的；
- 运行时：`npf_command` 的 `resource add TYPE TARGET NAME` / `resource del NAME` / `resource ls`，保存在 local.json，立即生效，已连上的一方马上收到新列表；
- 最多 32 个资源；`HOST` 只能是 IP 地址或 `localhost`。

## 7. 线程与生命周期

`npf_create` →（调用）→ `npf_start` 或 `npf_run` →（调用）→ `npf_stop` → 运行结束（事件 `stopped`，`npf_run` 返回）→ `npf_destroy`。

- `npf_start` 让实例在自己的线程上运行，`npf_run` 在调用者的线程上运行；两者只能调用一次，`npf_stop` 之后也不能再调用；
- **除 `npf_destroy` 外，所有函数都可以在任何线程、任何时候调用**：运行期间调用投递到实例的线程执行，调用方等待结果（`npf_media_send` 只排队）；不在运行时在调用者的线程上执行，同一实例一次一个；运行结束后返回 `NPF_ESTATE`；
- **`npf_destroy`**：可以在任何线程调用，但不能在本实例的线程上（回调中）调用。它停止运行并等待结束，也等待正在进行的调用，然后释放；之后不能再使用这个实例；
- **回调**在实例的线程上执行，一次一个；可以调用本实例除 `npf_destroy` 外的任何函数，不要长时间阻塞。回调拿到的 JSON、文本、帧只在回调期间有效；函数返回的 JSON 和文本归调用方，用 `npf_free` 释放，返回 NULL 表示实例已不在运行或内存不足；
- **多个实例**：各自一个线程、一把锁，日志级别、最近日志和 `log` 回调也各自独立；
- **共享运行时**：实例很多时（例如服务器上为每个用户开一个），`npf_runtime_new(threads)` 建一组线程，`npf_options.runtime` 指向它，`npf_start` 把实例挂到实例最少的线程上，此后一直在这个线程上。回调不能阻塞，也不能同步等待另一个运行时线程上的实例；`npf_runtime_free` 在最后一个实例销毁之后调用；
- 会话和媒体流用整数编号，实例存续期间不重复使用；过时的编号只会得到 `NPF_ENOENT`。

## 8. 接口一览

| 类别 | 函数 |
|---|---|
| 生命周期 | `npf_options_init`、`npf_callbacks_init`、`npf_create`、`npf_start` / `npf_run`、`npf_stop`、`npf_destroy`、`npf_free`、`npf_version`、`npf_api_version`、`npf_runtime_new` / `npf_runtime_free` |
| 状态（JSON，调用方 `npf_free`） | `npf_status_json`、`npf_config_json`、`npf_log_json`、`npf_sessions_json`、`npf_public_json` |
| 设置 | `npf_config_get`（未知键 `NPF_ENOENT`，秘密显示 `(hidden)`，缓冲区不够 `NPF_ETOOBIG`）、`npf_config_set` |
| 对端与转发 | `npf_peer_add` / `npf_peer_add_argv`（`NPF_PEER_SAVE`、`NPF_PEER_ONCE`）、`npf_peer_remove`、`npf_forward_add`、`npf_forward_del` |
| 命令 | `npf_command(argv)`：结果文本和退出码交给回调，要等平台应答的稍后回调 |
| 平台请求 | `npf_request(type, data, key_proof, cb)`：账户、设备、分享等请求（信令协议的 `account_*`、`device_*`、`share_*` 等），应答 JSON 整个交给回调；库自己保存账户会话和证书 |
| 应用数据 | `npf_session_send` |
| 音视频 | `npf_media_open`、`npf_media_send`、`npf_media_stats_get`、`npf_media_close`，回调 `media_open`、`media_frame`、`media_closed` |

返回码：`NPF_OK`（0）、`NPF_EINVAL`、`NPF_ENOENT`、`NPF_ESTATE`（还没启动、不在线、会话没建立）、`NPF_EUNAVAIL`、`NPF_ETOOBIG`、`NPF_ENOMEM`、`NPF_EFAIL`（原因在 `err` 里）、`NPF_EBUSY`。

**命令**（`npf_command`，参数按词给出）：

| 命令 | 作用 |
|---|---|
| `status [--json]` | 状态（文字或 JSON） |
| `id` | 本机的密钥指纹与编号 |
| `show` / `passwd` / `unpair` / `owner-reset` | 设备的编号与配对口令 / 改口令 / 取消配对 / 重置所有者 |
| `node` / `node add` / `node del` / `node set` / `node state` / `node wake` | 对端：列表、加入、删除、名字与备注、状态、提前建立会话 |
| `forward NODE add\|del -L\|-D\|-R SPEC [--save]` | 端口转发 |
| `resource ls\|add\|del` | 发布的资源 |
| `get` / `set KEY VALUE [--no-save]` | 设置 |
| `log [-n N]` | 最近的日志 |
| `netcheck` | 网络变了（例如 VPN 开关）：立即重新检查 |
| `stop` | 结束运行 |

**状态 JSON**（`npf_status_json`）的主要字段：`version`、`number`、`role`、`online`、`server`、`account`、`enroll`、`nat`（映射、分配、过滤类型与公网地址）、`udp_port`、`lan_addrs`、`resources`（本机发布的）、`peers`（每个对端的状态、转发、它发布的资源，未配对时 `need_password`、配对失效时 `pairing_lost`）、`sessions`、`calls_out` / `calls_in`。

## 9. 事件

`event` 回调，参数为名称和 JSON：

| 事件 | 内容 |
|---|---|
| `online` | `{server, account_id}`：登录了平台 |
| `offline` | `{why}` |
| `enrolled` | `{number}` |
| `enroll_failed` | `{error, reason, retry_in}`（第 5 节） |
| `account` | `{account_id}`：账户会话开始或结束 |
| `peer_done` | `{peer, why}`：不重连的对端结束了 |
| `forward` | `{peer, spec, up, why}`：一条转发建立或失败（会自己重试） |
| `network` | `{why}`：进程被挂起过、本机地址变了；libnpf 已经在检查并修复连接，应用不需要做什么 |
| `stopped` | `{}`：运行结束 |

扩展模块（第 11 节）可以发出自己的事件。

`session` 回调：会话建立时 `up = 1`，info 为 `{peer, path, direction, call_id}`（`path`：直连、UDP 中转或 WS 中转）；结束时 `up = 0`，info 为 `{why}`，这个会话的媒体流随之结束。

## 10. 应用数据与音视频

**应用数据**：`npf_session_send` 在会话的控制通道上发送，可靠、有序，排在端口转发的数据前面，每条不超过 16384 字节；对方的 `data` 回调收到。适合命令、通知、小文件的分块。

**媒体流**

- 打开：`npf_media_open(n, session, &opt, &err)` 返回流的编号；对方的 `media_open` 回调收到 `tag`（应用自定的流类型，0–999），返回 1 接受、0 拒绝；
- 发送：`npf_media_send(n, media, flags, frame, len)`，`flags` 可带 `NPF_FRAME_KEY`；任何线程都可以调用，帧被复制后排队，不阻塞；
- 接收：`media_frame` 回调收到帧和 `npf_frame_info`（`frame_no`、`flags`、`lost_before`：上一帧之后丢了几帧，可以直接驱动解码器）；
- 关闭：`npf_media_close`；会话结束时它的流随之关闭；
- 统计：`npf_media_stats_get` 给出 `target_rate`（编码器可以用的码率，所有流合计，字节/秒）、往返时延、丢弃与 FEC 恢复的帧数、对方报告的帧时延与抖动、`capacity_short`（路径比媒体慢）。

**选项**（`npf_media_opt`，用 `npf_media_opt_default` 初始化）：

| 选项 | 默认 | 说明 |
|---|---|---|
| `tag` | 0 | 流类型，对方据此决定是否接受 |
| `prio` | 1 | 0（最先）到 3；端口转发的数据是 2 |
| `max_age_ms` | 500 | 帧在这么久内没发出就丢弃（从 `npf_media_send` 调用时算起） |
| `drop_until_key` | 0 | 丢了一帧后一直丢到下一个关键帧 |
| `fec`、`fec_ratio` | 自动、自适应 | 前向纠错：开关与每 100 包的固定冗余数 |
| `latency_rtt` | 0 | 接收方可以为一帧等几个往返 |
| `rcv_drop_until_key` | 0 | 要求对方接收时丢帧后跳到下一个关键帧 |

**限制**

- 一个实例全部会话合计最多同时 64 路（`NPF_MEDIA_STREAMS_MAX`），包括对方打开的；超限返回 `NPF_EBUSY`，关闭后可以再开；直连和 UDP 中转上每一方每个会话最多同时打开 30 路；
- 单帧不超过 `NPF_MEDIA_FRAME_MAX`（4 MiB），WS 中转上不超过 `NPF_MEDIA_WS_FRAME_MAX`（2 MiB）；
- 每个实例从其他线程排队等待的帧最多 `NPF_MEDIA_SEND_QUEUE`（16 MiB）或 4096 帧，超过返回 `NPF_EBUSY`，由应用决定丢帧还是降码率；
- 直连与 UDP 中转上一路就是一条 AnLiu 半可靠流；WS 中转上帧在本地按流排队，迟到的丢弃，带宽估计只在积压后才有。

## 11. 扩展：模块

产品需要库之外的功能（自己的命令、配置键、平台事件的处理、状态里的字段、一种新的转发）时，可以写成模块编进 libnpf，不必修改库的代码。模块看得到库的内部接口（`include/npf/*.h` 与 `src/api/npf_int.h`），不属于 npf.h 的稳定 ABI，升级库时要随之重新编译。

```c
#include "npf_int.h"
#include "npf/module.h"

static int hello(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    (void)n, (void)argc, (void)argv, (void)cb, (void)user;
    npf_out_printf(o, "hello\n");
    return 0;                           /* 退出码；-1 表示稍后经 cb 应答 */
}

static void on_login(npf_t *n) { npf_log("acme: online as %llu", (unsigned long long)n->number); }

static const npf_mod_cmd cmds[] = {{"hello", hello}, {NULL, NULL}};
const npf_module acme_module = {.name = "acme", .login = on_login, .cmds = cmds};

const npf_module *const npf_modules[] = {&acme_module, NULL};     /* 模块表 */
```

CMake 中在 `add_subdirectory(libnpf)` 之前给出：

```cmake
set(NPF_MODULE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/acme/acme.c)   # 其中一个文件定义 npf_modules
set(NPF_MODULE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/acme)
set(NPF_MODULE_LIBS "")                                        # 模块需要的静态库（CMake 目标）
add_subdirectory(libnpf)
```

- 钩子都在实例的线程上调用，都是可选的：创建、开始、分步结束、销毁，登录、平台事件、账户会话、会话状态，对端的建立 / 结束 / 转发，命令、`node` 列表，状态 JSON 与文字，配置键及其检查。每个实例的模块状态用 `npf_mod_state` / `npf_mod_set_state` 存取；
- 一种新的转发：在 `create` 钩子里用 `npf_peers_add_kind` 登记一个 `npf_fwd_kind`（选项字母，以及解析、检查、建立、撤销的回调），对端会像 `-L` 一样保存、重试、随对端删除；`npf_peers_fwd_call` 给出这条转发所在的会话；
- 模块可以在 local.json 的设备记录里保存自己的键（`npf_local_ext` / `npf_local_ext_set`），库原样保留；
- 没有给出 `NPF_MODULE_SOURCES` 时模块表为空。

## 12. 日志与排查

- 日志行为“日期 时间.毫秒 级别 消息”；有 `log` 回调时交给回调（在不持有锁时调用，可以回调 API），否则写到 stderr；`npf_log_json` / `log` 命令给出最近的日志（`no_log_ring` 可以关掉）；
- 连不上时先看状态 JSON 的 `online`、`nat` 和对端的状态；会话的 `path` 说明走的是直连还是中转；
- 本机开着别的 VPN 时，库会让 UDP 套接字走物理网卡，使打洞面对的是本机真实的 NAT；网络变化后可以调用命令 `netcheck` 让库立即重新检查。

## 13. 限制与后续

- macOS、Windows 的静态库还没有做符号局部化，与应用自带的 mbedTLS 等同名库一起静态链接时可能冲突，可以改用共享库；
- `rcv_deadline_ms` 暂不生效：要等 AnLiu 支持修改已打开的流的接收选项；
- WS 中转上的媒体流没有往返时延，`target_rate` 只在积压过之后才有估计值。

# libnpf 开发者指南

版本：2.0。更新日期：2026-10-21（对端、转发、资源改为类型化的对象接口，类型化事件，`npf_setup` 启动；见 api-draft.md）。

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
| 对端 | 本实例主动连接的一方（设备编号，或直连的地址与密钥），一个 `uint32_t` 编号；可以保存，下次启动时恢复 |
| 转发 | 一个对端上的端口转发：本地（`NPF_FWD_LOCAL`，本地端口到对方的服务）、SOCKS5 代理（`NPF_FWD_SOCKS`）、反向（`NPF_FWD_REMOTE`，对方开端口连回本地），也是一个编号 |
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
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c`、`examples/client.c` |
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
- 调用方分配的结构体第一个字段都是 `size`（`npf_options`、`npf_callbacks`、`npf_setup`、`npf_peer_opt`、`npf_forward_opt`、`npf_resource` 和各个 `*_info` 等）。库只读写调用方编译时就有的部分，其余用默认值；以后只在末尾增加字段；
- 用各自的 `*_init` 宏（媒体选项是 `npf_media_opt_default`）初始化。宏把调用方的 `sizeof` 传给库（`npf_options_init_size` 等），库只写这么多字节：旧程序配新库时不会越界，新程序配旧库时多出的字段为 0；`npf_media_stats` 由调用方填 `size`；
- 结构体数组（`npf_resource_list`、`npf_pairing_list`）由宏传入元素大小，库按调用方的步长定位每个元素，只写双方都知道的部分，多出的尾部清零；
- 事件 `npf_event` 由库分配，字段只在末尾增加：应用按 `ev->size` 判断某个字段是否存在，不认识的事件类型忽略即可。

## 3. 快速上手

### 3.1 设备：被别人连接

完整的程序见 `examples/device.c`。启动参数全部用字段给出（`npf_setup`），不需要配置文件：

```c
static uint8_t roots[1][32];        /* 平台的根公钥（字节），固件里自带 */
npf_setup su;
npf_callbacks cb;
npf_options o;
npf_t *dev;
char err[256];

npf_setup_init(&su);
su.roots = (const uint8_t (*)[32])roots;
su.nroots = 1;
su.serverlist = list;               /* 签名的服务器列表（字节），固件里自带 */
su.serverlist_len = list_len;
su.model_cred = cred;               /* 型号凭证，从加密存储读出，不落盘 */
su.serial = "SN0001";

npf_callbacks_init(&cb);
cb.notify = on_notify;              /* 类型化的事件（第 10 节） */
cb.data = on_data;                  /* 对方发来的应用数据 */

npf_options_init(&o);
o.setup = &su;
o.data_dir = data_dir;              /* 持久化存储上的目录：身份、编号、配对状态 */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
o.app_name = "acme-nas";            /* 1-32 个 a-z 0-9 . _ -，平台的记录里看得到 */
o.app_ver = "2.3.0";
if (npf_create(&o, &dev, err, sizeof err) != NPF_OK)
    return 1;

npf_resource web;                   /* 连上的人能访问什么（第 6 节） */
npf_resource_init(&web);
web.type = NPF_RES_TCP;
web.svc = "http";
web.name = "nas";
web.service.host = "127.0.0.1";
web.service.port = 5000;
web.flags = NPF_PERSIST;            /* 记进 local.json，下次启动还在 */
npf_resource_put(dev, &web, err, sizeof err);

npf_start(dev);
/* ... 运行中 ... */
npf_destroy(dev);                   /* 停止、等待、释放 */
```

第一次运行时库用型号凭证向平台注册，拿到编号和每台不同的默认配对口令（第 5 节）。用户在手机或电脑上输入编号和口令即可连接。

### 3.2 客户端：连接一台设备

完整的程序见 `examples/client.c`：

```c
o.role = NPF_ROLE_CLIENT;           /* 其余同上；客户端不需要凭证 */
npf_create(&o, &cli, err, sizeof err);

npf_peer_opt po;
npf_peer_opt_init(&po);
po.target = NPF_TARGET_NUMBER;
po.number = 318204776;
po.password = "8fK2mQ7v";           /* 第一次配对用；配对后可以不给 */
po.ctx = &my_device;                /* 应用自己的上下文，事件里原样带回 */
npf_peer_create(cli, &po, &peer, err, sizeof err);

npf_forward_opt fo;
npf_forward_opt_init(&fo);
fo.kind = NPF_FWD_LOCAL;
fo.listen.port = 0;                 /* 0：系统分配，NPF_EV_FORWARD 之后用 npf_forward_get 查 */
fo.target.host = "127.0.0.1";
fo.target.port = 5000;
npf_forward_create(cli, peer, &fo, &fwd, err, sizeof err);

npf_start(cli);
```

- `NPF_EV_SESSION_UP` 带会话编号和对端编号；`NPF_EV_FORWARD`（`NPF_FWD_UP`）之后浏览器打开 `http://127.0.0.1:端口` 就是设备上的页面；
- `npf_session_send(cli, session, buf, len)` 发送应用数据，对方的 `data` 回调收到；`npf_media_open` / `npf_media_send` 发送音视频（第 11 节）；
- 第一次连接用口令配对，之后库在 `data_dir/local.json` 里记住对方的公钥。设备被重置、换了密钥时，对端进入 `NPF_PEER_ENDED`，`needs` 带 `NPF_NEED_PAIRING_LOST`，要用 `npf_peer_give_password` 给它现在的口令。

### 3.3 不经平台的直连

两端在同一网络或有固定地址时，可以完全不用平台。两端各有一份同样的 32 字节随机密钥，然后：

- 被连接的一方：`NPF_ROLE_DIRECT`，`npf_setup` 里给 `direct_port`（和可选的 `direct_host`）与 `direct_psk`；
- 连接的一方：`NPF_ROLE_DIRECT`，`npf_peer_create` 的 `target = NPF_TARGET_DIRECT`，给 `host`、`port` 和 `psk`。

握手为 Noise_NNpsk0，传输同样是 AnLiu，转发、应用数据和媒体流都可以用。

## 4. 启动、目录与配置

**两种启动方式**，二选一：

- **`npf_setup`**（推荐）：应用把启动参数用字段给出，`conf_dir`、`conf_file` 为 NULL，`data_dir` 必填；
- **配置文件**：`conf_dir` 里的 `npf.conf`（或 `conf_file`），每行 `key = value`。

`npf_setup` 的每个字段对应 npf.conf 的一个键（下表），含义相同；库在 `npf_create` 里把字段转成键，所以两种方式得到的实例没有区别，`npf_config_get` 也按键读出。没有字段的键（`hosted_*`、`sig_idle_s`、模块的键等）放进 `npf_options.overrides` 的 `key = value` 行；`overrides` 里出现有字段的键是 `NPF_EINVAL`，一个参数只有一个来源。

| 字段 | 键 | 说明 |
|---|---|---|
| `roots`、`nroots` | `root` | 平台的根公钥（字节），1–2 个 |
| `serverlist` + `serverlist_len` / `serverlist_file` | `serverlist` | 签名的服务器列表，字节或文件，二选一；字节每次启动写到 `data_dir/serverlist-builtin.bin` |
| `serverlist_saved` | `serverlist_saved` | 平台下发的新列表保存在哪里，NULL 为 `data_dir/serverlist-saved.bin`，`""` 不保存 |
| `server_url`、`server_pub` | `server`、`server_pub` | 测试用：直接给一台服务器的地址与公钥 |
| `doh_servers` | `doh_servers` | 测试用：服务器列表的 DoH 备用渠道 |
| `cred`、`password` | `cred`、`password` | 一机一密的设备凭证 `NPFD1.…` 与默认口令 |
| `model_cred`、`serial`、`hw_info` | 同名 | 一型一密的型号凭证 `NPFV2.…`、序列号（不给时用最小的物理网卡地址）、硬件信息 |
| `model` | `model` | 产品型号，平台用于统计 |
| `direct_host`、`direct_port`、`direct_psk` | `direct`、`direct_psk` | 直连的监听地址与密钥（字节） |
| `udp_port` | `udp_port` | 主 UDP 端口，0 为任意 |
| `no_portmap` | `portmap = 0` | 不向路由器申请 PCP / NAT-PMP 端口映射 |
| `relays_only` | `connect_mode = secure` | 只走中转（默认 `p2p`，直连优先） |
| `max_calls` | `max_calls` | 同时被连接的会话上限，默认 32 |
| `punch_lead_ms`、`punch_sockets` | 同名 | 打洞参数，默认自动 |
| `no_host_report` | `report_host = 0` | 登录时不报告主机信息 |
| `no_hosted_trust` | `hosted_trust = 0` | 不接受平台为设备所有者及其分享对象签发的授权 |
| `peer_idle_s` | `peer_idle` | 按需连接的对端（第 7 节）默认的空闲秒数；0 为 300 |

`npf_setup` 在 `npf_create` 里校验，`err` 指出字段：非直连角色没有 `roots`；`serverlist` 和 `serverlist_file` 同时给或都没给；`cred` 没有 `password`；`cred` 和 `model_cred` 同时给；`direct_port` 没有 `direct_psk`；数值越界。配置文件方式下另有 `serial_file`、`direct_psk_file`（密钥文件，权限 0600）、`log_level` 等键。对端不写在配置里：npf.conf 和 `overrides` 的 `node =` 行是 `NPF_EINVAL`，对端由应用用第 7 节的函数建立。

**两个目录**

| 目录 | 库的权限 | 内容 |
|---|---|---|
| `conf_dir`（配置文件方式） | 只读 | `npf.conf` 及其中引用的文件 |
| `data_dir` | 读写 | `identity`（本机密钥）、`node.json`（注册得到的编号与默认口令）、`state.json`（口令、配对、所有者）、`account.cert`、`serverlist-saved.bin`、`local.json` |

- `data_dir` 必须在持久化存储上，丢了会重新注册；秘密（`identity`、`state.json`）各自成文件，权限 0600；
- 运行时库会锁住身份：同一个 `data_dir` 不能同时被两个实例或两个进程使用（直连模式除外）。

**生效的设置**按顺序叠加，后者覆盖前者：npf.conf（或 `npf_setup` 的字段）、`npf_options.overrides`、`local.json` 的 `settings`（带保存的 `npf_config_set` 写在这里）。库从不写 npf.conf；运行时保存的设置、对端、转发和资源都写进 `data_dir/local.json`（临时文件 + rename，原子替换）。

**两个开关**（`npf_options.flags`），给自己管理数据的应用：

- `NPF_OPT_NO_SAVED_SETTINGS`：不应用 local.json 里的设置，带保存的 `npf_config_set` 返回 `NPF_EUNAVAIL`；
- `NPF_OPT_NO_SAVED_OBJECTS`：不恢复、不保存对端、转发和资源；带 `NPF_PERSIST` 的创建返回 `NPF_EUNAVAIL`，名字和备注只在这次运行有效。local.json 里已有的记录原样保留；配对后固定的公钥照样写入。

## 5. 设备注册

设备拿到编号有两种方式：

| | 一型一密（`model_cred`） | 一机一密（`cred`） |
|---|---|---|
| 写进设备的 | 每个产品型号一串 `NPFV2.…`，所有设备相同 | 每台设备一串 `NPFD1.…` 和默认口令 |
| 编号 | 第一次联网时向平台注册，平台分配 | 出厂前已分配，可以印在标签上 |
| 适合 | 软件包形式分发、没有产线写入流程 | 自有硬件、有产线 |

一型一密的凭证由厂家用平台签发的厂家证书自己签发，是秘密：从加密存储读出后放进 `npf_setup`，不要写进公开的仓库或日志。

以 `NPF_ROLE_NODE` 第一次运行时库自动注册：

- 成功：事件 `NPF_EV_ENROLLED`（`number`）。编号和库生成的默认口令保存在 `data_dir/node.json`，`npf_pairing_password_get` 读出口令，应用把它显示在设备界面或交给用户首次配对；
- 被拒：事件 `NPF_EV_ENROLL_FAILED`（`why` 为错误与原因，`retry_in_ms`），库到时自己重试；状态 JSON 的 `enroll` 记着最近一次结果。

| 原因 | 含义 |
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

**配对与所有者**（设备一侧）：`npf_pairing_password_get` / `npf_pairing_password_set`（8–127 字节）读写配对口令；`npf_pairing_list` 列出已配对的一方（公钥与时间），`npf_pairing_remove` 取消一个或全部；`npf_owner_reset` 忘记所有者账户，下次登录时告诉平台。没有编号时这些函数返回 `NPF_ESTATE`。

## 6. 发布资源

设备只放行它发布的资源，别人连上后只能访问这些，其余一律拒绝；什么都不发布，就什么都访问不到。连上的一方在会话建立时和每次变化时收到资源列表（`NPF_EV_RESOURCES`，`npf_resource_list(n, peer, ...)` 读出）。

| 类型 | 目标 | 用途 |
|---|---|---|
| `NPF_RES_TCP` | `service`：IP 地址或 `localhost`，端口 | 一个服务。`svc` 说明它是什么：`http`、`https`（网页，`path` 为起始页）、`rdp`、`ssh` 等，供连接的一方决定怎么打开 |
| `NPF_RES_UDP` | 同上 | 一个 UDP 服务（唯一放行 UDP 的类型） |
| `NPF_RES_NET` | `rule`：`lan`、`*` 或 `ADDR[/PREFIX][:PORT[-PORT]]` | 一批地址：`lan` 为本机与直接相连的私有网段 |
| `NPF_RES_SOCKS` | 同 `net` | 作为代理（`NPF_FWD_SOCKS`）访问，`*` 即互联网出口 |
| `NPF_RES_REVERSE` | `rule`：`*`（1024–65535）、`PORT` 或 `PORT-PORT`，前面可加 `lan:` | 允许连接的一方在本机开端口（`NPF_FWD_REMOTE`）；默认只在回环地址上，带 `lan:` 时也可以在所有地址或本机的某个局域网地址上，只接受本机与直接相连的私有网段的连接 |

- `npf_resource_put`：增加，或按名字替换；`npf_resource_remove`；`npf_resource_list(n, 0, ...)` 列出本机的；
- 带 `NPF_PERSIST` 的保存在 local.json，下次启动恢复；不带的只在这次运行有效（把保存的替换成不带的，local.json 里的那条也去掉）；
- 配置文件方式下也可以写 `resource = TYPE[/SVC] TARGET NAME [| 说明]` 行，这些是固定的（`NPF_FIXED`），不能用函数修改；
- 最多 `NPF_RESOURCES_MAX`（32）个，超出时 `NPF_EBUSY`；规则不符合语法、超长、端口越界都是 `NPF_EINVAL`，从不截断。

## 7. 对端与转发

**对端**（`npf_peer_create`）：

| 字段 | 说明 |
|---|---|
| `target` | `NPF_TARGET_NUMBER`（`number`：设备编号）或 `NPF_TARGET_DIRECT`（`host`、`port`、32 字节 `psk`） |
| `password` | 第一次配对用的口令；配对后不再需要 |
| `connect` | `NPF_CONNECT_KEEP`（一直保持连接，断开后退避重连）、`NPF_CONNECT_ONCE`（一次会话，结束后进入 `NPF_PEER_ENDED`）、`NPF_CONNECT_ON_DEMAND`（有连接用到它的转发时才建立会话，空闲 `idle_ms` 后断开；只用于保存的对端，不能有反向转发） |
| `flags` | `NPF_PERSIST`：记进 local.json，下次启动恢复（`ONCE` 不能保存） |
| `name`、`nick` | 名字（`npf_peer_find` 可以按名字找）、备注 |
| `ctx` | 应用自己的上下文，事件里原样带回 |

- 同一个目标再次创建返回 `NPF_EEXIST` 和已有的编号（编号按数值比，直连目标按小写主机名和端口比）；
- `npf_peer_get` 给出状态（`NPF_PEER_WAITING`、`CONNECTING`、`CONNECTED`、`RETRY`、`IDLE`、`ENDED`）和 `needs`：`NPF_NEED_PASSWORD`（没配对，要口令；口令被拒时加 `NPF_NEED_PASSWORD_WRONG`，配对丢失时加 `NPF_NEED_PAIRING_LOST`）、`NPF_NEED_ACCOUNT`（经账户授权进入的，账户会话没了）。因为这些原因结束的对端，在条件满足时自己再试：给了口令（`npf_peer_give_password`）、账户会话开始；`npf_peer_connect_now` 让按需的对端现在就建立会话，也让结束了的对端再试一次；
- `npf_peer_set_names`、`npf_peer_set_flags`（打开或关闭保存，转发一起变；关闭后固定的公钥、名字和备注仍在）、`npf_peer_set_ctx`、`npf_peer_remove_id`（会话结束，转发删除，保存的记录不再恢复）；
- `npf_peer_set_connect(n, peer, connect, idle_ms)` 运行中改连接方式，立即生效，保存的对端写进记录：改为 `KEEP` 时没有会话就马上连接；改为 `ON_DEMAND` 要已经保存、没有反向转发（否则 `NPF_EINVAL`），当前会话继续，空闲时间从现在算（`idle_ms` 为 0 用 `peer_idle`）；改为 `ONCE` 要不保存，当前会话结束后进入 `ENDED`（没有会话就马上）。`peer_idle` 只是默认的空闲时间，改它不会切换任何对端的连接方式（应用要这样做，自己对相应的对端调用这个函数）；`ONCE` 的对端要保存，先改为 `KEEP` 再 `npf_peer_set_flags`；
- 为平台保存的公网映射打开的对端带 `NPF_PLATFORM`，由平台的映射决定，不能删除、改 flags 或加转发（`NPF_EREADONLY`）；
- `npf_peer_list`、`npf_peer_find`；`NPF_ROLE_NODE` 和 `NPF_ROLE_DIRECT` 启动时恢复保存的对端，`NPF_ROLE_CLIENT` 不恢复。恢复的对端在 `npf_start` 之前就能枚举，这时用 `npf_peer_set_ctx` 登记上下文。

**转发**（`npf_forward_create`）：

| kind | proto | listen | target |
|---|---|---|---|
| `NPF_FWD_LOCAL` | TCP、UDP | 本机地址，默认 `127.0.0.1`，所有地址要写 `0.0.0.0` 或 `::`；端口 0 由系统分配 | 对端一侧的主机和端口 |
| `NPF_FWD_SOCKS` | TCP | 同上 | 无 |
| `NPF_FWD_REMOTE` | TCP、UDP | 对端上的地址，默认 `127.0.0.1`；其他地址（所有地址，或对端的某个局域网地址）要对端的 reverse 资源带 `lan:`；端口 0 由对端选择，要它的 reverse 资源是 `*` 或 `lan:*` | 本机一侧的主机和端口 |

- 本机端口被占用、组合不合法这类立即可知的错误在创建时返回（`NPF_EFAIL`、`NPF_EINVAL`），不留下对象；每个对端最多 `NPF_PEER_FORWARDS_MAX`（16）条，超出 `NPF_EBUSY`；
- `npf_forward_get`：状态（`NPF_FWD_WAITING`、`UP`、`FAILED` 与 `why_code`）、实际使用的端口、当前连接数、被对端拒绝的连接数。`NPF_FWD_FAILED` 只表示整条规则不能用（端口被占、对端拒绝反向监听）；单条连接被对端拒绝（目标不在它发布的资源里）只计数并发 `NPF_EV_FORWARD_REFUSED`，同一个 SOCKS 代理上允许的目标照常连通；
- 带 `NPF_PERSIST` 的转发要求对端也是保存的；local.json 里保存的是请求的端口（0 仍是 0），实际端口只是运行状态；
- `npf_forward_remove`、`npf_forward_list(n, peer, ...)`（`peer` 为 0 列出全部）、`npf_forward_set_ctx`。

**保存失败**：写不进 local.json 时返回 `NPF_ESAVE`，修改已经生效，并记为待保存（`npf_node_get` 的 `unsaved`，对象 info 的 `saved` 为 0）。`npf_save` 重试，任何一次成功的保存都会写入全部内容；成功之前重启，新建的会丢失，删除的会回来。

库里没有对端和转发的命令语法：命令行、配置界面由应用自己实现，调用这些函数。

## 8. 线程与生命周期

`npf_create` →（建立对端、转发、资源）→ `npf_start` 或 `npf_run` →（调用）→ `npf_stop` → 运行结束（`NPF_EV_STOPPED`，`npf_run` 返回）→ `npf_destroy`。

- `npf_start` 让实例在自己的线程上运行，`npf_run` 在调用者的线程上运行；两者只能调用一次，`npf_stop` 之后也不能再调用；
- **除 `npf_destroy` 外，所有函数都可以在任何线程、任何时候调用**：运行期间调用投递到实例的线程执行，调用方等待结果（`npf_media_send` 只排队）；不在运行时在调用者的线程上执行，同一实例一次一个；运行结束后返回 `NPF_ESTATE`；
- **`npf_destroy`**：可以在任何线程调用，但不能在本实例的线程上（回调中）调用。它停止运行并等待结束，也等待正在进行的调用，然后释放；之后不再有回调，也不能再使用这个实例；
- **回调**在实例的线程上执行，一次一个；可以调用本实例除 `npf_destroy` 外的任何函数，不要长时间阻塞。回调拿到的数据只在回调期间有效；函数返回的 JSON 和文本归调用方，用 `npf_free` 释放；
- **多个实例**：各自一个线程、一把锁，日志级别、最近日志和 `log` 回调也各自独立；
- **共享运行时**：实例很多时（例如服务器上为每个用户开一个），`npf_runtime_new(threads)` 建一组线程，`npf_options.runtime` 指向它，`npf_start` 把实例挂到实例最少的线程上。回调不能阻塞，也不能同步等待另一个运行时线程上的实例；`npf_runtime_free` 在最后一个实例销毁之后调用；
- 对端、转发、会话、媒体流都用整数编号，实例存续期间不重复使用；过时的编号只会得到 `NPF_ENOENT`。

## 9. 接口一览

| 类别 | 函数 |
|---|---|
| 生命周期 | `npf_options_init`、`npf_callbacks_init`、`npf_setup_init`、`npf_create`、`npf_start` / `npf_run`、`npf_stop`、`npf_destroy`、`npf_free`、`npf_version`、`npf_api_version`、`npf_runtime_new` / `npf_runtime_free` |
| 对端 | `npf_peer_create`、`npf_peer_remove_id`、`npf_peer_find`、`npf_peer_list`、`npf_peer_get`、`npf_peer_give_password`、`npf_peer_set_names`、`npf_peer_set_flags`、`npf_peer_set_ctx`、`npf_peer_set_connect`、`npf_peer_connect_now` |
| 转发 | `npf_forward_create`、`npf_forward_remove`、`npf_forward_list`、`npf_forward_get`、`npf_forward_set_ctx` |
| 资源 | `npf_resource_put`、`npf_resource_remove`、`npf_resource_list` |
| 配对与所有者 | `npf_pairing_password_get` / `_set`、`npf_pairing_list`、`npf_pairing_remove`、`npf_owner_reset` |
| 本机与会话 | `npf_node_get`、`npf_session_get`、`npf_session_list`、`npf_network_changed`、`npf_save` |
| 设置 | `npf_config_get`（未知键 `NPF_ENOENT`，秘密显示 `(hidden)`，缓冲区不够 `NPF_ETOOBIG`）、`npf_config_set` |
| 诊断（JSON，调用方 `npf_free`） | `npf_status_json`、`npf_config_json`、`npf_log_json`、`npf_sessions_json`、`npf_public_json` |
| 命令 | `npf_command(argv)`：库自己的诊断与设备命令，结果文本和退出码交给回调 |
| 平台请求 | `npf_request(type, data, key_proof, cb)`：账户、设备、分享等请求（信令协议的 `account_*`、`device_*`、`share_*` 等），应答 JSON 整个交给回调；库自己保存账户会话和证书 |
| 应用数据 | `npf_session_send` |
| 音视频 | `npf_media_open`、`npf_media_send`、`npf_media_stats_get`、`npf_media_close`，回调 `media_open`、`media_frame`、`media_closed` |

**返回码**：`NPF_OK`（0）、`NPF_EINVAL`、`NPF_ENOENT`、`NPF_ESTATE`（还没启动、不在线、会话没建立）、`NPF_EUNAVAIL`、`NPF_ETOOBIG`、`NPF_ENOMEM`、`NPF_EFAIL`（原因在 `err` 里）、`NPF_EBUSY`（数量到了上限）、`NPF_ESAVE`（生效了，没写进 local.json：`npf_save` 重试）、`NPF_EEXIST`（已有：同一目标的对端、被占用的名字）、`NPF_EREADONLY`（来自 npf.conf 或平台的，不能改）。创建函数返回 `NPF_OK` 或 `NPF_ESAVE` 时输出新对象的编号，`NPF_EEXIST` 时输出已有的那个，其他错误时输出 0 且不留下任何东西。

**上限**：`NPF_PEER_FORWARDS_MAX`（16）、`NPF_RESOURCES_MAX`（32）、`NPF_PEERS_SAVED_MAX`（256）、`NPF_PAIRINGS_MAX`（256）、`NPF_PASSWORD_MAX`（127）、`NPF_NAME_MAX` / `NPF_NICK_MAX`（32 / 128 字节）。

**命令**（`npf_command`，参数按词给出）。回调里的退出码：0 完成，1 失败，2 命令或参数不对，3 已完成但 local.json 没写入。库自己的命令优先于模块的命令：

| 命令 | 作用 |
|---|---|
| `status [--json]` | 状态（文字或 JSON） |
| `id` | 本机的密钥指纹与编号 |
| `show` / `passwd` / `unpair` / `owner-reset` | 设备的编号与配对口令 / 改口令 / 取消配对 / 重置所有者 |
| `resource ls\|add\|del` | 发布的资源 |
| `get` / `set KEY VALUE [--no-save]` | 设置 |
| `log [-n N]` | 最近的日志 |
| `netcheck` | 网络变了：立即重新检查 |
| `stop` | 结束运行 |

**状态 JSON**（`npf_status_json`）的主要字段：`version`、`number`、`role`、`online`、`server`、`account`、`enroll`、`nat`、`udp_port`、`lan_addrs`、`resources`（本机发布的）、`peers`（每个对端的 `peer_id`、`connect`、状态、它发布的资源，`mappings` 为转发：`id`、`kind`、`proto`、`listen_host`、`port`、`listen_port`、`target_host`、`target_port`、`state`、`conns`）、`sessions`、`calls_out` / `calls_in`。

## 10. 事件

`npf_callbacks.notify` 收到类型化的事件 `npf_event`：

| 类型 | 说明 |
|---|---|
| `NPF_EV_ONLINE` / `NPF_EV_OFFLINE` | 登录了平台（`number` 为账户会话，没有为 0）/ 信令断开（`why`），库自己重新登录 |
| `NPF_EV_ENROLLED` / `NPF_EV_ENROLL_FAILED` | 注册成功（`number`）/ 被拒（`why`、`retry_in_ms`） |
| `NPF_EV_ACCOUNT` | 账户会话开始或结束（`number`，0 为结束） |
| `NPF_EV_PEER` | 对端的状态或 needs 变了（`state`；详细状态用 `npf_peer_get`） |
| `NPF_EV_PEER_GONE` | 对端被删除：关于它的最后一个事件，应用可以释放 `ctx` |
| `NPF_EV_FORWARD` / `NPF_EV_FORWARD_GONE` | 转发的状态或端口变了（`state`，失败时 `reason` 为 `NPF_FWD_WHY_*`）/ 转发被删除 |
| `NPF_EV_FORWARD_REFUSED` | 这条转发的连接被对端拒绝（每条每秒至多一次，`why` 为最近一次的目标） |
| `NPF_EV_SESSION_UP` / `NPF_EV_SESSION_DOWN` | 会话建立 / 结束（`session`、`peer`（别人连进来的为 0）、`number`、`outgoing`、`path`；结束时 `reason` 为 `NPF_END_*`） |
| `NPF_EV_RESOURCES` | 对端发布的资源变了（`peer`、`session`） |
| `NPF_EV_NETWORK` | 进程被挂起过、本机地址变了：库已经在检查并修复连接 |
| `NPF_EV_PLATFORM` / `NPF_EV_MODULE` | 平台推送的事件 / 模块的事件：`name` 与 `json` |
| `NPF_EV_STOPPED` | 运行结束：最后一个事件 |

**规则**

- 事件在实例的线程上排队，在产生它的调用或回调之后送达，同一对象的按发生顺序；`SESSION_UP` 先于这个会话的任何 `data` 和媒体回调；
- 从别的线程创建对象时，关于它的事件可能在创建函数返回之前到达：回调里只用 `ev->peer` / `ev->forward` 和创建时给的 `ctx`，`ctx` 指向的数据要在调用之前准备好；
- `ctx` 在送达时从对象读取，`npf_peer_set_ctx` 返回之后的回调都带新的；`*_GONE` 和 `SESSION_DOWN` 在对象移除之后发出，自带结束时的信息；
- 删除对端时依次发出 `SESSION_DOWN`（`NPF_END_LOCAL`）、它每条转发的 `FORWARD_GONE`、`PEER_GONE`；运行结束时不发 `*_GONE`，`NPF_EV_STOPPED` 之后应用自行释放所有 `ctx`；
- 回调里可以删除事件所说的对象，删除引起的事件排在本次回调之后。

不设 `notify` 时，库改用旧的两个回调：`event`（名称与 JSON：`online`、`offline`、`enrolled`、`enroll_failed`、`account`、`peer_done`、`forward`、`network`、`resources`、`platform`、`stopped`，以及模块的事件）和 `session`（会话建立时 `up = 1` 与 `{peer, path, direction, call_id}`，结束时 `up = 0` 与 `{why}`）。

## 11. 应用数据与音视频

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

## 12. 扩展：模块

产品需要库之外的功能（自己的命令、配置键、平台事件的处理、状态里的字段、一种新的转发）时，写成模块。模块是应用自己的代码，在应用自己的构建里编译，运行时用 `npf_register_module` 注册给 libnpf；libnpf 的代码和构建都不用改。

**注册**

```c
#include "npf/module.h"

extern const npf_module acme_module;               /* acme.c */

int main(void)
{
    if (npf_register_module(&acme_module) != 0)    /* 在创建实例之前 */
        return 1;
    /* ... npf_options_init、npf_create、npf_start，同第 3 节 ... */
}
```

- 实例在 `npf_create` 时取当时已注册的全部模块，按注册的顺序调用；之后再注册的模块只对之后创建的实例生效，所以通常在程序启动时、创建任何实例之前注册；
- 最多 8 个模块；可以在任何线程调用。以下情况返回 -1：`NULL`、没有名字、重复注册，名字与已注册的模块相同，命令与库自己的命令或其他模块的命令同名，配置键与库的配置键或其他模块的配置键相同。所以模块不能覆盖库的命令和配置；
- 创建实例时按顺序调用各模块的 `create`；某个模块失败时实例创建失败，失败的模块自己清理已分配的资源，库只对排在它前面、已经创建成功的模块调用 `end` / `destroy`，按相反顺序销毁；
- 模块结构体归应用所有，要比用到它的实例活得久（通常是静态常量）；
- 没有注册任何模块时，库只有自己的命令和配置键。

**编写模块**

```c
/* acme.c */
#include <stdio.h>
#include <stdlib.h>
#include "npf_int.h"
#include "npf/module.h"

extern const npf_module acme_module;
typedef struct acme { int hellos; } acme;

static int acme_create(npf_t *n, char *err, size_t errcap)
{
    acme *a = calloc(1, sizeof *a);
    if (!a) { snprintf(err, errcap, "acme: no memory"); return -1; }   /* 实例创建失败 */
    npf_mod_set_state(n, &acme_module, a);                             /* 每个实例一份状态 */
    return 0;
}
static void acme_destroy(npf_t *n) { free(npf_mod_state(n, &acme_module)); }

static int hello(npf_t *n, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    acme *a = npf_mod_state(n, &acme_module);
    (void)argc, (void)argv, (void)cb, (void)user;
    npf_out_printf(o, "hello %d\n", ++a->hellos);
    return 0;                           /* 退出码；-1 表示稍后经 cb 应答 */
}

static void on_login(npf_t *n) { npf_log("acme: online as %llu", (unsigned long long)n->number); }

static void status(npf_t *n, npf_out *o, int *first)       /* 状态 JSON 里的 "acme" */
{
    acme *a = npf_mod_state(n, &acme_module);
    npf_mod_jkey(o, first, "acme");
    npf_out_printf(o, "{\"hellos\":%d}", a->hellos);
}

static const npf_mod_cmd cmds[] = {{"hello", hello}, {NULL, NULL}};
static const char *const keys[] = {"acme_mode", NULL};    /* npf.conf、npf_config_set 认的键 */

const npf_module acme_module = {.name = "acme", .create = acme_create, .destroy = acme_destroy,
                                .login = on_login, .cmds = cmds, .status_json = status, .keys = keys};
```

**构建**

```cmake
add_subdirectory(libnpf)                               # 不需要为模块做任何设置
add_executable(acme-app main.c acme/acme.c)
target_link_libraries(acme-app PRIVATE npf_common)     # 模块用到库的内部接口
```

模块使用库的内部接口（`npf/module.h`、`include/npf/` 下的其他头文件、`src/api/npf_int.h`），所以链接静态目标 `npf_common`，而不是安装后的 libnpf.so / libnpf.a（那两个只导出 npf.h）。内部接口不属于 npf.h 的稳定 ABI，升级 libnpf 后模块要重新编译。只用 npf.h、不带模块的应用不受影响。

**钩子与扩展点**

- 钩子都在实例的线程上调用，都是可选的：创建、开始、分步结束、销毁，登录、平台事件、账户会话、会话状态，对端的建立 / 结束 / 转发，命令，状态 JSON 与文字，配置键及其检查（`check`：返回 0 接受，否则是退出码，原因写进输出），运行中改了库的可即时生效的键（`conf_set`：`log_level`、`peer_idle` 等，已生效之后）；模块的命令也经 `npf_command` 调用，应用可以用模块提供自己的命令（例如对端和转发的命令行）；
- 一种新的转发：在 `create` 钩子里用 `npf_peers_add_kind` 登记一个 `npf_fwd_kind`（大写字母，以及解析、检查、建立、撤销的回调），用 `npf_peer_forward_add_kind` 加到对端上，库像本地转发一样保存、重试、随对端删除；`npf_peers_fwd_call` 给出这条转发所在的会话；
- 模块可以在 local.json 的设备记录里保存自己的键（`npf_local_ext` / `npf_local_ext_set`），库原样保留；
- 状态 JSON 里模块的字段和库的字段在同一个对象里，模块应使用带自己前缀的键名，避免与库现有或以后的字段重名；
- `tests/api/test_module.c` 是一个完整的例子：注册（重复、冲突、上限）、命令、配置键、状态字段、销毁、创建失败时的清理，以及注册之前创建的实例。

## 13. 日志与排查

- 日志行为“日期 时间.毫秒 级别 消息”；有 `log` 回调时交给回调（在不持有锁时调用，可以回调 API），否则写到 stderr；`npf_log_json` / `log` 命令给出最近的日志（`no_log_ring` 可以关掉）；
- 连不上时先看状态 JSON 的 `online`、`nat` 和对端的状态；会话的 `path` 说明走的是直连还是中转；
- 本机开着别的 VPN 时，库会让 UDP 套接字走物理网卡，使打洞面对的是本机真实的 NAT；网络变化后调用 `npf_network_changed` 让库立即重新检查。

## 14. 限制与后续

- macOS、Windows 的静态库还没有做符号局部化，与应用自带的 mbedTLS 等同名库一起静态链接时可能冲突，可以改用共享库；
- `rcv_deadline_ms` 暂不生效：要等 AnLiu 支持修改已打开的流的接收选项；
- WS 中转上的媒体流没有往返时延，`target_rate` 只在积压过之后才有估计值。

# libnpf 开发者指南

文档版本：2.2。更新日期：2026-10-21。本版按当前公开头文件、实现和构建配置核对，并补充错误处理、事件生命周期和集成示例。文档版本与库版本、`NPF_API_VERSION` 分别编号。

本文面向在设备固件或客户端应用中集成 libnpf 的开发者。安装包提供的公开头文件是 [npf.h](../../include/npf.h)，应用写 `#include <npf.h>` 即可。第 3–11 节介绍公开 SDK；第 12 节介绍需要参与源码构建的内部模块，两种集成方式的接口边界不同。

本文以当前公开接口及其实现为准。协议细节见 [信令协议](../protocol/signaling.md)、[数据通道协议](../protocol/data-channel.md)；设计背景见 [NAT 穿透](nat-traversal.md)和[安全设计](security.md)。下文文件链接均为相对路径；构建命令默认在仓库根目录执行。

## 1. 基本概念

| 概念 | 说明 |
|---|---|
| 平台 | 提供信令、中转和地址探测。信令负责发现对方、协调打洞和分配中转；会话载荷端到端加密，中转不解密载荷。libnpf 用根公钥（`root`）验证平台，用服务器列表（`serverlist`）发现服务器 |
| 实例 | 一个 `npf_t`，持有独立的身份、配置和运行状态。一个进程可以有多个实例，直连实例不需要登录平台 |
| 节点（`NPF_ROLE_NODE`） | 长期运行，有编号（9 位数字）时可以被连接，同时也可以主动连接别的节点 |
| 客户端（`NPF_ROLE_CLIENT`） | 主动连接设备或进行账户操作；生命周期由应用控制，不自动恢复保存的对端 |
| 直连（`NPF_ROLE_DIRECT`） | 不用平台：两端用预共享密钥，经 UDP 直接连接 |
| 编号与配对口令 | 设备编号由平台分配。口令配对后双方保存公钥，后续连接可使用已保存的配对；账户授权是另一条认证路径，不一定需要口令 |
| 会话 | 两个实例之间端到端加密的连接。平台连接支持 P2P UDP、UDP 中转和 WebSocket 中转；库选择和切换路径，应用通过会话信息读取实际路径。直接地址连接不经过平台中转 |
| 资源 | 本端允许对方通过转发访问的服务、地址或反向监听范围；不控制应用数据和媒体回调的业务权限 |
| 对端 | 本实例主动连接的一方（设备编号，或直连的地址与密钥），一个 `uint32_t` 编号；可以保存，下次启动时恢复 |
| 转发 | 一个对端上的端口转发：本地（`NPF_FWD_LOCAL`，本地端口到对方的服务）、SOCKS5 代理（`NPF_FWD_SOCKS`）、反向（`NPF_FWD_REMOTE`，对方开端口连回本地），也是一个编号 |
| 应用数据 | 会话控制通道上的消息：可靠、有序，每条不超过 16384 字节 |
| 媒体流 | 会话中的音视频帧流，可以多路同时进行、反复开关：迟到丢帧、关键帧、FEC、带宽估计 |

## 2. 构建与集成

需要 CMake 3.16 或更新版本、C99 编译器和平台线程库。默认使用 `third_party/` 中的 AnLiu、Monocypher、mbedTLS 和 rxi/log.c；启用 `NPF_USE_OPENSSL` 时还需要 OpenSSL 3 的开发文件。下面以 Linux 和 `pkg-config` 为例，固定安装库目录为 `lib`：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib
cmake --build build --parallel
cmake -E chdir build ctest --output-on-failure
cmake --install build --prefix ./install
cc -o app app.c $(PKG_CONFIG_PATH=./install/lib/pkgconfig pkg-config --cflags --libs npf) -pthread
LD_LIBRARY_PATH=./install/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH} ./app
```

`app.c` 是应用自己的源文件。安装后得到 `install/include/npf.h`、`install/lib/` 下的库和 `install/lib/pkgconfig/npf.pc`。`pkg-config` 解决编译与链接参数；运行时仍需让系统找到共享库，上例用 `LD_LIBRARY_PATH` 指定。CMake 消费者可以用 `find_package(PkgConfig)` 和 `pkg_check_modules(... IMPORTED_TARGET npf)`；当前安装包没有提供 `find_package(npf CONFIG)` 所需的配置文件。

| 选项 | 默认 | 说明 |
|---|---|---|
| `NPF_BUILD_LIB` | ON | 构建共享库；Linux 上另生成静态库 `libnpf.a`（需要链接器和 objcopy，`NPF_SANITIZE` 时不生成）。可执行文件链接选项带 `-static` 时关闭 |
| `NPF_BUILD_TESTS` | ON | 单元测试、API 测试、模糊测试 |
| `NPF_BUILD_EXAMPLES` | ON | `examples/device.c`、`examples/client.c`（要 `NPF_BUILD_LIB`，Windows 上不构建） |
| `NPF_PEERS` | ON | 本节点主动连接别的节点；只被连接的设备可以关掉，程序更小 |
| `NPF_PORTMAP` | ON | 路由器端口映射（PCP、NAT-PMP），给家庭路由器后面的节点用；公网服务器上的程序（如托管服务）可以关掉，关掉后配置项 `portmap` 不起作用 |
| `NPF_TOOLS_API` | OFF | 调试工具用的同步探测、绑定查询和打洞（`npf_natprobe_run` 等）；节点用的是事件驱动的版本，不需要它 |
| `NPF_WITH_TLS` | ON | `wss://`、`https://` |
| `NPF_USE_OPENSSL` | OFF | 用 OpenSSL 3 代替 mbedTLS 做 TLS 和应用层密码学（服务器上用；mbedTLS 的调用经一把进程级锁，OpenSSL 没有这把锁） |
| `NPF_SANITIZE` / `NPF_TSAN` | OFF | ASan + UBSan / ThreadSanitizer |

**产物**

- 共享库：`libnpf.so.1`（Linux）、`libnpf.dylib`（macOS）、`libnpf.dll` 与导入库（Windows / MinGW）；
- 静态库：Linux 上的 `libnpf.a` 是一个可重定位目标，除 npf.h 的函数外全部符号都是局部的，内置的 AnLiu、Monocypher、mbedTLS 不会和应用自己的同名库冲突。macOS、Windows 暂不做这一步；
- 所有目标文件都以隐藏可见性编译，导出的只有 npf.h 的 `npf_*` 函数。

**平台与交叉编译**：代码包含 POSIX 与 Windows 平台适配；Windows 构建以 Windows 10 为最低目标。交叉编译通过 CMake 工具链文件选择目标系统和架构。当前构建脚本只在 Linux 上生成供安装的 `libnpf.a`；iOS 等需要静态库的平台还需补充打包步骤，不能直接套用 Linux 安装产物。移动端应用应自行选择可写的 `data_dir`，并按目标平台验证构建和运行行为。

**ABI**

- `NPF_API_VERSION` 为 1，soname 为 `libnpf.so.1`；不兼容的修改会提高 soname；
- 可扩展的选项和查询结构体以 `size` 开头，例如 `npf_options`、`npf_callbacks`、`npf_setup`、`npf_peer_opt`、`npf_forward_opt`、`npf_resource` 和各个对象的 `*_info`。库按双方已知的大小读写；输入缺少的尾部字段使用默认值，查询输出多出的尾部清零。`npf_endpoint`、`npf_frame_info` 等小结构没有 `size`，不能套用这一规则；
- 用各自的 `*_init` 宏（媒体选项是 `npf_media_opt_default`）初始化。宏把调用方的 `sizeof` 传给库（`npf_options_init_size` 等），库只写这么多字节：旧程序配新库时不会越界，新程序配旧库时多出的字段为 0；`npf_media_stats` 由调用方填 `size`；
- 结构体数组（`npf_resource_list`、`npf_pairing_list`）由宏传入元素大小，库按调用方的步长定位每个元素，只写双方都知道的部分，多出的尾部清零；
- 事件 `npf_event` 由库分配，字段只在末尾增加：应用按 `ev->size` 判断某个字段是否存在，不认识的事件类型忽略即可。

大小字段只解决结构体扩展，不保证新函数在旧库中存在。部署时仍应检查所需符号和行为；旧版头文件的兼容性应通过独立消费者验证。

## 3. 快速上手

### 3.1 设备：被别人连接

完整程序见 [device.c](../../examples/device.c)。下面是应用初始化函数中的片段，需要包含 `<npf.h>` 和 `<stdio.h>`。`roots`、`list`、`list_len` 和 `cred` 由应用提供；`roots` 必须是真实平台根公钥，不能使用全零占位值。`on_notify`、`on_data` 由应用实现。

```c
npf_setup su;
npf_callbacks cb;
npf_options o;
npf_t *dev = NULL;
char err[256];
int rc;

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
o.data_dir = "./device-data";        /* 每个实例使用独立的持久化目录 */
o.role = NPF_ROLE_NODE;
o.cb = &cb;
o.app_name = "acme-nas";            /* 1-32 个 a-z 0-9 . _ -，平台的记录里看得到 */
o.app_ver = "2.3.0";
if (npf_create(&o, &dev, err, sizeof err) != NPF_OK) {
    fprintf(stderr, "npf_create: %s\n", err);
    return 1;
}

npf_resource web;                   /* 连上的人能访问什么（第 6 节） */
npf_resource_init(&web);
web.type = NPF_RES_TCP;
web.svc = "http";
web.name = "nas";
web.service.host = "127.0.0.1";
web.service.port = 5000;
web.flags = NPF_PERSIST;            /* 记进 local.json，下次启动还在 */
rc = npf_resource_put(dev, &web, err, sizeof err);
if (rc == NPF_ESAVE) {
    fprintf(stderr, "资源已生效，但保存失败；稍后用 npf_save 重试\n");
} else if (rc != NPF_OK) {
    fprintf(stderr, "npf_resource_put: %s\n", err);
    npf_destroy(dev);
    return 1;
}
if (npf_start(dev) != NPF_OK) {
    npf_destroy(dev);
    return 1;
}
/* ... 运行中 ... */
npf_destroy(dev);                   /* 停止、等待、释放 */
```

第一次运行时库用型号凭证向平台注册，拿到编号和每台不同的默认配对口令（第 5 节）。用户在手机或电脑上输入编号和口令即可连接。

### 3.2 客户端：连接一台设备

完整程序见 [client.c](../../examples/client.c)。客户端仍需要平台根公钥和服务器列表，但不需要设备凭证。以下片段中的 `roots`、`list`、`list_len`、`device_number`、`pairing_password` 和 `my_device` 由应用提供；设备编号应来自实际注册结果，且包含有效校验位。

```c
npf_setup su;
npf_callbacks cb;
npf_options o;
npf_t *cli = NULL;
uint32_t peer = 0, fwd = 0;
char err[256];
int rc;

npf_setup_init(&su);
su.roots = (const uint8_t (*)[32])roots;
su.nroots = 1;
su.serverlist = list;
su.serverlist_len = list_len;
npf_callbacks_init(&cb);
cb.notify = on_notify;
npf_options_init(&o);
o.setup = &su;
o.data_dir = "./client-data";
o.role = NPF_ROLE_CLIENT;
o.cb = &cb;
if (npf_create(&o, &cli, err, sizeof err) != NPF_OK) {
    fprintf(stderr, "npf_create: %s\n", err);
    return 1;
}

npf_peer_opt po;
npf_peer_opt_init(&po);
po.target = NPF_TARGET_NUMBER;
po.number = device_number;
po.password = pairing_password;    /* 首次配对的口令；已有配对时可为 NULL */
po.ctx = &my_device;                /* 应用自己的上下文，事件里原样带回 */
rc = npf_peer_create(cli, &po, &peer, err, sizeof err);
if (rc != NPF_OK && rc != NPF_ESAVE) {
    fprintf(stderr, "npf_peer_create: %s\n", err);
    npf_destroy(cli);
    return 1;
}

npf_forward_opt fo;
npf_forward_opt_init(&fo);
fo.kind = NPF_FWD_LOCAL;
fo.listen.port = 0;                 /* 0：系统分配，NPF_EV_FORWARD 之后用 npf_forward_get 查 */
fo.target.host = "127.0.0.1";
fo.target.port = 5000;
rc = npf_forward_create(cli, peer, &fo, &fwd, err, sizeof err);
if (rc != NPF_OK && rc != NPF_ESAVE) {
    fprintf(stderr, "npf_forward_create: %s\n", err);
    npf_destroy(cli);
    return 1;
}
if (npf_start(cli) != NPF_OK) {
    npf_destroy(cli);
    return 1;
}
/* ... 等待事件并执行业务；完成后： */
npf_destroy(cli);
```

- `NPF_EV_SESSION_UP` 带会话编号和对端编号；`NPF_EV_FORWARD`（`NPF_FWD_UP`）之后浏览器打开 `http://127.0.0.1:端口` 就是设备上的页面；
- `npf_session_send(cli, session, buf, len)` 发送应用数据，对方的 `data` 回调收到；`npf_media_open` / `npf_media_send` 发送音视频（第 11 节）；
- 第一次连接用口令配对，之后库在 `data_dir/local.json` 里记住对方的公钥。设备被重置、换了密钥时，对端进入 `NPF_PEER_ENDED`，`needs` 带 `NPF_NEED_PAIRING_LOST`，要用 `npf_peer_setopt` 的 `NPF_PEER_OPT_PASSWORD` 给它现在的口令。

### 3.3 不经平台的直连

两端在同一网络或有固定地址时，可以完全不用平台。两端各有一份同样的 32 字节随机密钥，然后：

- 被连接的一方：`NPF_ROLE_DIRECT`，`npf_setup` 里给 `direct_port`（和可选的 `direct_host`）与 `direct_psk`；
- 连接的一方：`NPF_ROLE_DIRECT`，`npf_peer_create` 的 `target = NPF_TARGET_DIRECT`，给 `host`、`port` 和 `psk`。

`direct_port = 0` 表示不启动直连监听器，与转发的“端口 0 自动分配”不同；`direct_host = NULL` 默认监听所有地址，需要仅本机访问时显式设为 `"127.0.0.1"`。握手为 Noise_NNpsk0，传输使用 AnLiu，转发、应用数据和媒体流都可以用。

## 4. 启动、目录与配置

**两种启动方式**，二选一：

- **`npf_setup`**（推荐）：应用把启动参数用字段给出，`conf_dir`、`conf_file` 为 NULL，`data_dir` 必填；
- **配置文件**：`conf_dir` 里的 `npf.conf`（或 `conf_file`），每行 `key = value`。

`npf_setup` 的字段会转换为内部配置键，再进入相同的初始化流程；`npf_config_get` 仍按键查询。秘密键 `password`、`cred`、`model_cred`、`direct_psk` 返回 `(hidden)`。两种入口的区别主要在参数来源、默认值和文件路径处理。

没有对应字段的配置键，例如其他 `hosted_*` 键、`sig_idle_s`、`resource` 行和模块配置，可以写入 `npf_options.overrides`，格式为多行 `key = value`。使用 `npf_setup` 时，`overrides` 不能再包含下表对应的键，即使对应字段保持默认值也不行；冲突返回 `NPF_EINVAL`。`serial_file`、`direct_psk_file` 也不能通过该方式传入，应使用 `serial`、`direct_psk` 字段。配置文件入口没有这一字段冲突限制。

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

`npf_create` 会校验 `npf_setup`，失败时在 `err` 中说明字段或配置问题。常见原因包括：非直连角色没有 `roots`；同时给出 `serverlist` 和 `serverlist_file`；两者均未给出且没有 `server_url`；给了 `server_url` 却没有 `server_pub`；`cred` 缺少 `password`；同时给出 `cred` 和 `model_cred`；非零 `direct_port` 缺少 `direct_psk`；数值越界。

配置文件入口还支持 `serial_file`、`direct_psk_file` 等键。对端由应用通过第 7 节的 API 建立；npf.conf 和 `overrides` 中的 `node =` 行会返回 `NPF_EINVAL`。

**两个目录**

| 目录 | 库的权限 | 内容 |
|---|---|---|
| `conf_dir`（配置文件方式） | 只读 | `npf.conf` 及其中引用的文件 |
| `data_dir` | 读写 | `identity`（本机密钥）、`node.json`（注册得到的编号与默认口令）、`state.json`（口令、配对、所有者）、`account.cert`、`serverlist-saved.bin`、`serverlist-builtin.bin`（`npf_setup` 以字节给出的服务器列表，每次启动写入）、`local.json` |

- 需要保留身份和配对时，`data_dir` 应位于持久化存储上；丢失后的行为取决于角色和凭证，见第 5 节。POSIX 文件权限中，`identity`、`state.json`、`local.json` 等敏感文件按 0600 写入；保存的直连对端密钥也在 `local.json` 中；
- 同一个 `data_dir` 不要同时给两个实例或两个进程用：库不提供目录独占锁，应用需要自行保证独占访问。

**生效的设置**按顺序叠加，后者覆盖前者：npf.conf（或 `npf_setup` 的字段）、`npf_options.overrides`、`local.json` 的 `settings`（带保存的 `npf_config_set` 写在这里）。库从不写 npf.conf；运行时保存的设置、对端、转发和资源都写进 `data_dir/local.json`（临时文件 + rename，原子替换）。

**两个开关**（`npf_options.flags`），给自己管理数据的应用：

- `NPF_OPT_NO_SAVED_SETTINGS`：不应用 local.json 里的设置，带保存的 `npf_config_set` 返回 `NPF_EUNAVAIL`，`npf_command` 的 `set`（不带 `--no-save`）退出码 1；
- `NPF_OPT_NO_SAVED_OBJECTS`：不恢复、不保存对端、转发和资源；带 `NPF_PERSIST` 的创建或把 `NPF_PEER_OPT_PERSIST` 设为 1 都返回 `NPF_EUNAVAIL`。名字和备注只在本次运行有效，local.json 里原有的对象配置保留；协议需要保存的配对公钥不受此开关影响。当前按需对端要求持久化，因此不能与此开关组合使用。

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

**重建设备身份**：先停止并销毁实例，再由应用决定是否清空 `data_dir`。这会同时移除保存的设置、资源、配对和账户状态；若目录里还放着应用提供的服务器列表等文件，也要安排重新提供。型号凭证设备下次启动会生成新身份并重新申请编号；是否取回原编号由平台的序列号、硬件和离线时间规则决定，见[注册协议](../protocol/signaling.md)。一机一密设备仍从同一凭证派生身份，编号、密钥和默认口令不变，但删除的配对等本地状态不会自动回来。

**配对与所有者**（设备一侧）：`npf_pairing_password_get` / `npf_pairing_password_set`（8–127 字节）读写配对口令；`npf_pairing_list` 列出已配对的一方（公钥与时间），`npf_pairing_remove` 取消一个或全部；`npf_owner_reset` 忘记所有者账户，下次登录时告诉平台。没有编号时这些函数返回 `NPF_ESTATE`。

`npf_pairing_remove(n, NULL)` 删除全部配对；`npf_owner_reset` 不删除配对。这里修改的是设备的 `state.json`：保存失败也可能返回 `NPF_ESAVE`，但 `npf_save` 只重写 local.json，不能修复此类失败。应用需要区分这两种存储结果，并在设备状态未写入时报告失败；不能仅根据 `npf_node_info.unsaved` 判断配对或所有者状态是否保存成功。

## 6. 发布资源

资源决定 TCP/UDP 转发可以访问哪些目标，以及对方能否申请反向监听。没有发布对应资源，就不能通过这些转发访问目标；应用数据和媒体接口仍由应用自己的回调处理，不受资源列表直接控制。主叫方在会话建立时和资源更新时收到 `NPF_EV_RESOURCES`，使用事件中的对端 ID 调用 `npf_resource_list(n, peer, ...)` 查询。

| 类型 | 目标 | 用途 |
|---|---|---|
| `NPF_RES_TCP` | `service`：IP 地址或 `localhost`，端口 | 一个服务。`svc` 说明它是什么：`http`、`https`（网页，`path` 为起始页）、`rdp`、`ssh` 等，供连接的一方决定怎么打开 |
| `NPF_RES_UDP` | 同上 | 允许访问一个 UDP 目标服务；反向 UDP 监听则由 `NPF_RES_REVERSE` 授权 |
| `NPF_RES_NET` | `rule`：`lan`、`*` 或 `ADDR[/PREFIX][:PORT[-PORT]]` | 允许访问一批 TCP 目标地址：`lan` 为本机与直接相连的私有网段，不同时放行 UDP |
| `NPF_RES_SOCKS` | 同 `net` | 作为代理（`NPF_FWD_SOCKS`）访问，`*` 即互联网出口 |
| `NPF_RES_REVERSE` | `rule`：`*`（1024–65535）、`PORT` 或 `PORT-PORT`，前面可加 `lan:` | 允许连接的一方在本机开端口（`NPF_FWD_REMOTE`）；默认只在回环地址上，带 `lan:` 时也可以在所有地址或本机的某个局域网地址上，只接受本机与直接相连的私有网段的连接 |

- `npf_resource_put`：增加，或按名字替换；`npf_resource_remove`；`npf_resource_list(n, 0, ...)` 列出本机的；
- 带 `NPF_PERSIST` 的保存在 local.json，下次启动恢复；不带的只在这次运行有效（把保存的替换成不带的，local.json 里的那条也去掉）；
- npf.conf 或 `overrides` 里也可以写 `resource = TYPE[/SVC] TARGET NAME [| 说明]` 行，这些是固定的（`NPF_FIXED`），不能用函数修改；
- 最多 `NPF_RESOURCES_MAX`（32）个，超出时 `NPF_EBUSY`；规则不符合语法、超长、端口越界，以及整个列表的 JSON 超过 12000 字节，都是 `NPF_EINVAL`，从不截断。

查询资源和配对列表时，宏会传入数组元素大小，不需要逐个初始化元素。`count` 是实际总数；容量不足时只填前 `cap` 项并返回 `NPF_ETOOBIG`，不能用返回的总数越过数组边界。对端、转发、会话的 ID 列表也遵守这一容量规则。用 `cap = 0` 查询数量时，只要列表非空也会返回 `NPF_ETOOBIG`；之后读取列表时数量仍可能变化，需要继续处理容量不足。

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

- 参数通过校验后，同一个目标再次创建返回 `NPF_EEXIST` 和已有的编号，不更新已有对象的口令、配置或上下文。编号按数值比较；直连主机名转为小写，IPv6 地址规范化后再与端口一起比较。名字被其他记录占用也返回 `NPF_EEXIST`，此时输出 ID 为 0；
- `NPF_ROLE_DIRECT` 下建编号的对端、`NPF_PEERS=OFF` 的构建里建任何对端，都是 `NPF_EUNAVAIL`；
- `npf_peer_get` 给出状态（`NPF_PEER_WAITING`、`CONNECTING`、`CONNECTED`、`RETRY`、`IDLE`、`ENDED`）和 `needs`：`NPF_NEED_PASSWORD`（没配对，要口令；口令被拒时加 `NPF_NEED_PASSWORD_WRONG`，配对丢失时加 `NPF_NEED_PAIRING_LOST`）、`NPF_NEED_ACCOUNT`（经账户授权进入的，账户会话没了）。因为这些原因结束的对端，在条件满足时自己再试：给了口令（`NPF_PEER_OPT_PASSWORD`）、账户会话开始；`npf_peer_connect_now` 让按需的对端现在就建立会话，让在退避等待中的马上重试，也让结束了的对端再试一次（`npf_start` 之前 `NPF_ESTATE`，`NPF_PLATFORM` 的对端 `NPF_EREADONLY`）；
- `npf_peer_remove_id`（会话结束，转发删除，保存的记录不再恢复）；`npf_peer_get` 的 `ctx` 是应用登记的上下文；
- 由模块打开的对端（例如为平台保存的公网映射）带 `NPF_PLATFORM`：不能删除、不能加转发、不能 `npf_peer_connect_now`（`NPF_EREADONLY`），可修改的选项见下表；平台映射的转发也带 `NPF_PLATFORM`，不能删除；
- `npf_peer_list`、`npf_peer_find`；`NPF_ROLE_NODE` 和 `NPF_ROLE_DIRECT` 启动时恢复保存的对端，`NPF_ROLE_CLIENT` 不恢复。恢复的对端在 `npf_start` 之前就能枚举，这时用 `NPF_PEER_OPT_CTX` 登记上下文。

**修改对端选项**：`npf_peer_setopt(n, peer, opt, val, len)` 每次修改一项。整数传变量地址，`len = sizeof(int)`；字符串传 NUL 结尾的内容，`len = 0`；上下文直接传指针本身，`len = 0`，不要传指针变量的地址。

| 选项 | 值与行为 |
|---|---|
| `NPF_PEER_OPT_CONNECT` | 传 `int`。`KEEP` 在运行中没有会话时尝试连接；`ONCE` 要求对端未保存，已有会话结束后进入 `ENDED`，没有会话时直接进入 `ENDED`；`ON_DEMAND` 要求对端已保存且没有反向转发 |
| `NPF_PEER_OPT_IDLE_MS` | 传 `int`，范围 0–86400000 毫秒；0 使用实例的 `peer_idle`（秒，默认 300）。非按需对端也可以先设置，切换为按需时使用；修改 `peer_idle` 不会自动改变连接方式 |
| `NPF_PEER_OPT_PERSIST` | 传 `int`，只接受 0 或 1。1 保存对端、直连密钥和非平台转发；0 取消下次启动恢复，保留固定公钥、名字和备注。`ONCE` 不能设为 1，按需对端不能设为 0；禁用对象保存时不能设为 1 |
| `NPF_PEER_OPT_NAME` | 名字最多 32 字节，仅含字母、数字、`.`、`_`、`-`，不能全为数字或等于 `all`，不能与其他对端或本地记录重名；空串清除名字 |
| `NPF_PEER_OPT_NICK` | 备注最多 128 字节，不含控制字符；空串清除备注。未禁用对象保存时，名字和备注即使属于临时对端也会写入 local.json |
| `NPF_PEER_OPT_CTX` | 设置或清除应用上下文；允许 NULL。库不释放该指针，生命周期见第 10 节 |
| `NPF_PEER_OPT_PASSWORD` | 非空字符串，最多 127 字节；用于编号对端的后续配对，缺少口令或上次口令被拒时立即再试，不写入保存的对端配置。直连或平台对端不接受此选项 |

`NPF_PLATFORM` 对端的 `CONNECT`、`IDLE_MS`、`PERSIST` 返回 `NPF_EREADONLY`，`PASSWORD` 返回 `NPF_EINVAL`；可以修改 `NAME`、`NICK`、`CTX`。参数长度或取值不合法时返回 `NPF_EINVAL`。需要保存的变更若写盘失败，返回 `NPF_ESAVE`，运行状态已经改变。

例如，把一个临时对端改为持续连接并保存，应先改连接方式，再开启保存；每一步分别检查结果：

```c
int mode = NPF_CONNECT_KEEP;
int rc = npf_peer_setopt(n, peer, NPF_PEER_OPT_CONNECT, &mode, sizeof mode);
if (rc != NPF_OK && rc != NPF_ESAVE)
    return rc;
int persist = 1;
return npf_peer_setopt(n, peer, NPF_PEER_OPT_PERSIST, &persist, sizeof persist);
```

**转发**（`npf_forward_create`）：

| kind | proto | listen | target |
|---|---|---|---|
| `NPF_FWD_LOCAL` | TCP、UDP | 本机地址，默认 `127.0.0.1`，所有地址写 `0.0.0.0`、`::` 或 `*`；端口 0 由系统分配 | 对端一侧的主机和端口 |
| `NPF_FWD_SOCKS` | TCP | 同上 | 无 |
| `NPF_FWD_REMOTE` | TCP、UDP | 对端上的地址：IP 地址、`localhost` 或 `*`（主机名是 `NPF_EINVAL`），默认 `127.0.0.1`；其他地址（所有地址，或对端的某个局域网地址）要对端的 reverse 资源带 `lan:`；端口 0 由对端选择，要它的 reverse 资源是 `*` 或 `lan:*` | 本机一侧的主机和端口 |

- 本机端口被占用、组合不合法这类立即可知的错误在创建时返回（`NPF_EFAIL`、`NPF_EINVAL`），不留下对象；每个对端最多 `NPF_PEER_FORWARDS_MAX`（16）条，超出 `NPF_EBUSY`；
- `npf_forward_get`：状态（`NPF_FWD_WAITING`、`UP`、`FAILED` 与 `why_code`）、实际使用的端口、当前连接数、被对端拒绝的连接数。`NPF_FWD_FAILED` 只表示整条规则不能用（端口被占、对端拒绝反向监听），规则在会话中自己退避重试，`NPF_FWD_WHY_FORBIDDEN`（对端的策略）等下一次会话；模块类型的转发 `kind` 为 0；单条连接被对端拒绝（目标不在它发布的资源里）只计数并发 `NPF_EV_FORWARD_REFUSED`，同一个 SOCKS 代理上允许的目标照常连通；
- 带 `NPF_PERSIST` 的转发要求对端也是保存的；local.json 里保存的是请求的端口（0 仍是 0），实际端口只是运行状态；
- `npf_forward_remove`、`npf_forward_list(n, peer, ...)`（`peer` 为 0 列出全部）、`npf_forward_setopt`（`NPF_FWD_OPT_CTX`，同 `npf_peer_setopt` 的约定；`npf_forward_get` 的 `ctx` 读出它）。

**保存结果**：`NPF_PERSIST` 表示下次启动是否自动恢复对象，不等于对象是否已经成功写盘。即使对端没有此标志，名字、备注和配对公钥也可能保存在 local.json 中；关闭 `NPF_PERSIST` 不会删除这些信息。

local.json 写入失败时返回 `NPF_ESAVE`，运行变更已经生效，可以用 `npf_save` 重试。`npf_node_get` 的 `unsaved` 表示整个 local.json 有待保存内容；当前对象 info 的 `saved` 也依据这份全局状态计算，因此某个对象 `saved == 0` 不一定表示只有它的保存失败。成功保存会写入全部待保存内容；成功之前重启，新建的持久对象可能丢失，已删除的可能恢复。设备配对与所有者的保存失败另见第 5 节。

库里没有对端和转发的命令语法：命令行、配置界面由应用自己实现，调用这些函数。

## 8. 线程与生命周期

`npf_create` →（建立对端、转发、资源）→ `npf_start` 或 `npf_run` →（调用）→ `npf_stop` → 运行结束（`NPF_EV_STOPPED`，`npf_run` 返回）→ `npf_destroy`。

- `npf_start` 在后台线程运行实例；`npf_run` 在调用线程运行，直到结束才返回。每个实例只能成功启动一次，停止后不能重新启动。`npf_stop` 只请求停止并立即返回，不表示清理已完成；
- **线程安全不等于任何状态下都能成功**：实例运行时，其他线程的同步调用会投递到实例线程并等待结果；实例线程内调用直接执行。启动前可配置对象、读取状态，但连接和网络检查等操作可能返回 `NPF_ESTATE`。运行结束后，返回错误码的实例操作通常返回 `NPF_ESTATE`，返回 JSON 指针的查询返回 NULL；
- **销毁**：从实例执行线程之外调用 `npf_destroy`，它会停止运行，等待事件循环和已进入的调用结束，再释放实例。应用必须先阻止其他线程发起新的调用，不能与销毁竞争使用同一指针；不要在该实例的回调中销毁它；
- **回调与内存**：运行期间的业务回调在实例线程串行执行，可以调用本实例允许在当前状态使用的 API，不要阻塞。回调参数只在本次调用期间有效；库函数返回的 JSON 和文本用 `npf_free` 释放。启动前的同步命令回调以及初始化、销毁期间的日志回调可能在调用线程执行，不能假定全部回调都来自后台线程；
- **多个实例**：默认各自使用后台线程，日志级别、最近日志和 `log` 回调独立；共享运行时可以让多个实例共用线程。任何回调都应避免同步等待另一实例，以防形成循环等待；
- **共享运行时**：实例很多时（例如服务器上为每个用户开一个），`npf_runtime_new(threads)` 建一组线程，`npf_options.runtime` 指向它，`npf_create` 时选定实例最少的线程，`npf_start` 在那里运行（这样的实例不能 `npf_run`：`NPF_ESTATE`）。回调不能阻塞，也不能同步等待另一个运行时线程上的实例；`npf_runtime_free` 在最后一个实例销毁之后调用；
- 对端、转发、会话和媒体流都使用实例内的整数 ID，0 表示没有对象。ID 不能跨实例或跨重启使用；对象结束或删除后应丢弃其 ID。查询不存在的对象返回 `NPF_ENOENT`，查询仍需遵守实例运行状态限制。

## 9. 接口一览

| 类别 | 函数 |
|---|---|
| 初始化（宏，各有 `_init_size` 函数） | `npf_options_init`、`npf_callbacks_init`、`npf_setup_init`、`npf_peer_opt_init`、`npf_peer_info_init`、`npf_forward_opt_init`、`npf_forward_info_init`、`npf_resource_init`、`npf_node_info_init`、`npf_session_info_init`；列表元素的大小：`npf_resource_list_size`、`npf_pairing_list_size` |
| 生命周期 | `npf_create`、`npf_start` / `npf_run`、`npf_stop`、`npf_destroy`、`npf_free`、`npf_version`、`npf_api_version`、`npf_runtime_new` / `npf_runtime_free` |
| 对端 | `npf_peer_create`、`npf_peer_remove_id`、`npf_peer_find`、`npf_peer_list`、`npf_peer_get`、`npf_peer_setopt`、`npf_peer_connect_now` |
| 转发 | `npf_forward_create`、`npf_forward_remove`、`npf_forward_list`、`npf_forward_get`、`npf_forward_setopt` |
| 资源 | `npf_resource_put`、`npf_resource_remove`、`npf_resource_list` |
| 配对与所有者 | `npf_pairing_password_get` / `_set`、`npf_pairing_list`、`npf_pairing_remove`、`npf_owner_reset` |
| 本机与会话 | `npf_node_get`、`npf_session_get`、`npf_session_list`、`npf_network_changed`、`npf_save` |
| 设置 | `npf_config_get`（未知键 `NPF_ENOENT`；`password`、`cred`、`model_cred`、`direct_psk` 显示 `(hidden)`；缓冲区不足 `NPF_ETOOBIG`）；`npf_config_set`（0：即时设置已应用；1：启动时设置，需保存后重启生效；模块配置键属于后者） |
| 诊断（JSON，调用方 `npf_free`） | `npf_status_json`、`npf_config_json`（可即时修改的设置）、`npf_log_json`、`npf_sessions_json`、`npf_public_json` |
| 命令 | `npf_command(argv)`：库自己的诊断与设备命令，结果文本和退出码交给回调 |
| 平台请求 | `npf_request(type, data, key_proof, cb)`：账户、设备、分享等请求（信令协议的 `account_*`、`device_*`、`share_*` 等），应答 JSON 整个交给回调；库自己保存账户会话和证书 |
| 应用数据 | `npf_session_send` |
| 音视频 | `npf_media_open`、`npf_media_send`、`npf_media_stats_get`、`npf_media_close`，回调 `media_open`、`media_frame`、`media_closed` |

**常用返回码**：

| 返回码 | 调用方应如何理解 |
|---|---|
| `NPF_OK` | 本次操作成功；创建对端不代表会话已经建立 |
| `NPF_EINVAL` | 参数、选项组合或格式不合法 |
| `NPF_ENOENT` | 对象或配置键不存在 |
| `NPF_ESTATE` | 当前状态不能执行，例如尚未启动、运行已结束或会话未建立 |
| `NPF_EUNAVAIL` | 构建、角色或选项未提供该能力 |
| `NPF_ETOOBIG` | 缓冲区、列表容量或消息长度不符合限制 |
| `NPF_ENOMEM` / `NPF_EFAIL` | 内存不足或其他失败；有 `err` 参数的接口会尽可能提供说明 |
| `NPF_EBUSY` | 对象数量或发送队列达到上限 |
| `NPF_ESAVE` | 运行变更已发生，保存失败；local.json 可用 `npf_save` 重试，设备 state.json 的例外见第 5 节 |
| `NPF_EEXIST` | 对端目标或名字冲突 |
| `NPF_EREADONLY` | 操作受来源限制，例如修改固定资源、删除平台对端 |

创建对端或转发返回 `NPF_OK`、`NPF_ESAVE` 时输出新 ID；同目标对端的 `NPF_EEXIST` 输出已有 ID，名字冲突输出 0。同一对端上的重复转发返回 `NPF_EINVAL`。`npf_config_set` 还可能返回正值 1；`npf_media_open` 返回 ID，失败时为 0 并通过 `err` 输出错误码，不能用同一套返回值判断代替这些接口各自的约定。

`npf_config_set` 返回 1 表示该配置属于启动时设置，不表示本次已经保存。若传 `save = 0`，应用仍需另行保存或在下次创建实例时提供配置，单纯重启不会保留本次修改。

**上限**：`NPF_PEER_FORWARDS_MAX`（16）、`NPF_RESOURCES_MAX`（32）、`NPF_PEERS_SAVED_MAX`（256）、`NPF_PAIRINGS_MAX`（256）、`NPF_PASSWORD_MAX`（127）、`NPF_NAME_MAX` / `NPF_NICK_MAX`（32 / 128 字节）、`NPF_ROOTS_MAX`（2）。`NPF_PEERS_SAVED_MAX` 数的是 local.json 里全部对端记录，包括只有名字或固定公钥的。

**常量**：日志级别 `NPF_LEVEL_TRACE`、`DEBUG`、`INFO`、`WARN`、`ERROR`；`NPF_PROTO_TCP` / `UDP`；会话路径 `NPF_PATH_DIRECT`、`UDP_RELAY`、`WS_RELAY`；NAT 类型（`npf_node_info.nat`）`NPF_NAT_UNKNOWN`、`EIM`、`ADM`、`APDM`；会话结束 `NPF_END_LOCAL`、`PEER`、`LOST`、`REFUSED`、`UNREACHABLE`、`PLATFORM`、`OTHER`；转发失败 `NPF_FWD_WHY_NONE`、`PORT_IN_USE`、`BIND`、`FORBIDDEN`、`TOO_MANY`、`REQUEST`、`OTHER`。`npf_peer_info` 另有 `end_reason`（上次会话的 `NPF_END_*`）、`session`（现在的会话）、`nforwards`、`ctx`；`npf_forward_info` 另有 `refused_why`（最近一次被拒的目标）与 `ctx`。

**命令**（`npf_command`，参数按词给出）。回调里的退出码：0 完成，1 失败，2 命令或参数不对，3 已完成但 local.json 没写入。库自己的命令优先于模块的命令：

| 命令 | 作用 |
|---|---|
| `status [--json]` | 状态（文字或 JSON） |
| `id` | 本机的密钥指纹与编号 |
| `show` / `passwd` / `unpair` / `owner-reset` | 设备的编号与配对口令 / 改口令 / 取消配对 / 重置所有者 |
| `resource ls\|add\|del` | 发布的资源 |
| `get [KEY]` / `set KEY VALUE [--no-save]` | 设置（`get` 不带键时列出可即时修改的） |
| `dump` | 节点的内部状态写进日志 |
| `log [-n N]` | 最近的日志 |
| `netcheck` | 网络变了：立即重新检查 |
| `stop` | 结束运行 |

**状态 JSON**（`npf_status_json`）的主要字段：`version`、`number`、`role`、`online`、`server`、`account`、`enroll`、`nat`、`udp_port`、`lan_addrs`、`resources`（本机发布的）、`peers`（每个对端的 `peer_id`、`connect`、状态、它发布的资源，`mappings` 为转发：`id`、`kind`、`proto`、`listen_host`、`port`、`listen_port`、`target_host`、`target_port`、`state`、`conns`）、`sessions`、`calls_out` / `calls_in`。对端的状态是文字 `status`，转发的 `state` 为 `waiting`、`up`、`failed`；`role` 只对有编号的节点是 `node`。

## 10. 事件

`npf_callbacks.notify` 收到类型化的事件 `npf_event`：

| 类型 | 说明 |
|---|---|
| `NPF_EV_ONLINE` / `NPF_EV_OFFLINE` | 登录了平台（`number` 为账户会话，没有为 0）/ 信令断开（`why`），库自己重新登录 |
| `NPF_EV_ENROLLED` / `NPF_EV_ENROLL_FAILED` | 注册成功（`number`）/ 被拒（`why`、`retry_in_ms`） |
| `NPF_EV_ACCOUNT` | 账户会话开始或结束（`number`，0 为结束） |
| `NPF_EV_PEER` | 对端的状态或 needs 变了（`state`，`RETRY` 时带 `retry_in_ms`；详细状态用 `npf_peer_get`） |
| `NPF_EV_PEER_GONE` | 对端被删除（`number`，`reason` 为 `NPF_END_LOCAL`）：关于它的最后一个事件，应用可以释放 `ctx` |
| `NPF_EV_FORWARD` / `NPF_EV_FORWARD_GONE` | 转发的状态或端口变了（`state`，失败时 `reason` 为 `NPF_FWD_WHY_*`）/ 转发被删除 |
| `NPF_EV_FORWARD_REFUSED` | 这条转发的连接被对端拒绝（每条每秒至多一次，`why` 为最近一次的目标） |
| `NPF_EV_SESSION_UP` / `NPF_EV_SESSION_DOWN` | 会话建立 / 结束（`session`、`peer`（别人连进来的为 0）、`number`、`outgoing`、`path`；结束时 `reason` 为 `NPF_END_*`） |
| `NPF_EV_RESOURCES` | 对端发布的资源变了（`peer`、`session`） |
| `NPF_EV_NETWORK` | 进程被挂起过、本机地址变了：库已经在检查并修复连接 |
| `NPF_EV_PLATFORM` / `NPF_EV_MODULE` | 平台推送的事件 / 模块的事件：`name` 与 `json` |
| `NPF_EV_STOPPED` | 运行结束：最后一个事件 |

**规则**

- 类型化 `notify` 事件从实例开始运行后才产生；启动前创建或恢复的对象用 `npf_*_get` 查询，不能依赖补发创建事件。此规则不包含日志和同步命令结果回调；
- 类型化事件在实例线程中排队，按队列顺序送达，不在产生事件的同一业务回调内嵌套调用 `notify`；跨线程调用的返回顺序见下一条。`SESSION_UP` 先于这个会话的 `data` 和媒体回调；
- 从别的线程创建对象时，关于它的事件可能在创建函数返回之前到达：回调里只用 `ev->peer` / `ev->forward` 和创建时给的 `ctx`，`ctx` 指向的数据要在调用之前准备好；
- 对象仍存在时，交付前会更新 `ctx`；`NPF_EV_PEER` 更新当前 `state` 和 `retry_in_ms`，`NPF_EV_FORWARD` 更新当前 `state` 和失败 `reason`。因此它们是状态变化通知，不是每一次历史状态的快照；`why` 等文本也不应替代结构化查询。对象可能在排队期间已被删除，此时查询应处理 `NPF_ENOENT`；`*_GONE` 保留删除时的信息；
- 删除对端时依次发出 `SESSION_DOWN`（`NPF_END_LOCAL`）、它每条转发的 `FORWARD_GONE`、`PEER_GONE`；运行结束时不发 `*_GONE`，`NPF_EV_STOPPED` 之后应用自行释放所有 `ctx`；
- 回调里可以删除事件所说的对象，删除引起的事件排在本次回调之后。库不负责释放 `ctx`；更换指针时还要考虑正在执行的回调和已经移除对象的排队事件，不要把设置新指针当成旧指针可以立即释放的保证。最简单的管理方式是保持对象上下文到 `*_GONE`，或整体停止、销毁完成后再释放；
- 从未运行的实例不会产生 `STOPPED`。若创建对象后直接销毁实例，应用在 `npf_destroy` 返回后释放剩余上下文。`STOPPED` 是最后一个类型化事件，不代表后续销毁过程不会产生日志。

不设 `notify` 时，库改用旧的两个回调：`event`（名称与 JSON：`online`、`offline`、`enrolled`、`enroll_failed`、`account`、`peer_done`、`forward`、`network`、`resources`、`platform`、`stopped`，以及模块的事件）和 `session`（会话建立时 `up = 1` 与 `{peer, path, direction, call_id}`，结束时 `up = 0` 与 `{why}`）。

设置 `notify` 后仅替代 `event` 和 `session`；`data`、媒体回调和 `log` 仍按各自用途调用。

## 11. 应用数据与音视频

**应用数据**：`npf_session_send` 在会话控制通道上发送，可靠、有序，每条不超过 16384 字节；对方通过 `data` 回调接收。它优先于端口转发数据，适合小型业务消息和通知；持续的大流量传输应使用转发，避免占用控制通道。

**媒体流**

- 打开：`npf_media_open(n, session, &opt, &err)` 返回流的编号；对方的 `media_open` 回调收到 `tag`（应用自定的流类型，0–999），返回 1 接受、0 拒绝；
- 发送：`npf_media_send(n, media, flags, frame, len)`，`flags` 可带 `NPF_FRAME_KEY`。其他线程调用时复制帧并排队，`NPF_OK` 表示已接受入队，不保证之后一定发送；实例线程内调用直接提交帧并返回结果，不等待网络传输完成。函数返回后应用可复用输入缓冲区；
- 接收：`media_frame` 回调收到帧和 `npf_frame_info`（`frame_no`、`flags`、`lost_before`：上一帧之后丢了几帧，可以直接驱动解码器）；
- 关闭：`npf_media_close`；会话结束时它的流随之关闭；
- 统计：调用前设置 `npf_media_stats.size = sizeof(npf_media_stats)`。`npf_media_stats_get` 给出 `target_rate`（同一会话所有媒体流共享的建议发送速率，字节/秒）、往返时延、丢弃与 FEC 恢复统计、对方报告的帧时延与抖动、`capacity_short`（路径容量不足）。

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

模块用于扩展库内部的命令、配置键、平台事件处理、状态字段和转发类型，需要与 libnpf 源码一起构建。模块代码由应用维护，用 `npf_register_module` 注册。如果业务只需要连接、转发、消息或媒体，直接使用 `npf.h` 即可，无需编写内部模块。

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
- 最多 8 个模块；可以在任何线程调用。以下情况返回 -1：`NULL`、没有名字、重复注册、某条命令没有 `run`，名字与已注册的模块相同，命令与库自己的命令或其他模块的命令同名，配置键与库的配置键或其他模块的配置键相同。所以模块不能覆盖库的命令和配置；
- 创建实例时按顺序调用各模块的 `create`；某个模块失败时实例创建失败，失败的模块自己清理已分配的资源，库只对排在它前面、已经创建成功的模块调用 `end` / `destroy`，按相反顺序销毁；
- 注册表在进程内保存模块指针，没有注销接口。模块结构体及其引用的命令表、键名等应在进程运行期间一直有效，通常定义为静态常量；
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

以下示例假定应用目录中有 `main.c`、`acme/acme.c` 和 libnpf 源码目录 `libnpf`。父项目需要提供编译选项函数和功能开关；当前不能只写 `add_subdirectory(libnpf)`。应用的 `CMakeLists.txt` 可写为：

```cmake
cmake_minimum_required(VERSION 3.16)
project(acme VERSION 1.0.0 LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(npf_VERSION ${PROJECT_VERSION})
set(NPF_HAS_PEERS ON)
set(NPF_BUILD_TESTS OFF)
set(NPF_BUILD_LIB OFF)                                 # 只链接内部静态目标
include(libnpf/cmake/NpfOptions.cmake)
add_subdirectory(libnpf)
add_executable(acme-app main.c acme/acme.c)
target_link_libraries(acme-app PRIVATE npf_common)
```

在这个应用目录执行 `cmake -S . -B build` 和 `cmake --build build --parallel`。`npf_VERSION` 决定源码集成后的版本字符串，这里使用应用版本。

模块使用内部头文件 `include/npf/module.h`、`src/api/npf_int.h` 等，所以链接源码构建目标 `npf_common`。安装后的库只提供 `npf.h` 中的公开接口，不能用于这个模块示例。内部接口没有独立的稳定 ABI 保证；升级 libnpf 后应核对内部接口变化并重新编译模块。

**钩子与扩展点**

- 钩子均可选。`create` 在 `npf_create` 的调用线程上、恢复保存的对端之前执行；正常销毁时，`destroy` 在 `npf_destroy` 的调用线程上执行。创建失败的清理在创建线程执行；从未运行的实例销毁前会调用 `end(2)`。`end` 按注册顺序执行，`destroy` 按相反顺序执行；
- 运行中的业务钩子在实例线程执行，包括 `begin`、分步结束的 `end`、登录、平台事件、账户与会话状态等。启动前调用命令、查询或设置，也可能在调用线程触发对应钩子，不能假定所有钩子都在后台线程执行；
- 对端钩子覆盖连接、结束、转发变化（`peer_up`、`peer_done`、`peer_fwd`），平台公网映射的连接（`peer_opened`、`peer_conn`、`peer_refused`），以及删除（`peer_removing`、`peer_removed`）。`peer_removing` 返回 1 表示模块将重新打开对端；`sig_busy` 返回非零可在模块仍有业务时保持信令连接；
- 本地记录变更可触发 `nick_set` 和 `fwds_saved`，分别通知备注和保存的转发列表变化。这些钩子不代表磁盘写入成功；调用方仍要检查保存结果；
- 模块命令通过 `npf_command` 调用。模块还可提供状态 JSON、状态文字和配置键；`check` 校验配置，返回 0 接受，否则返回退出码并把原因写入输出。`conf_set` 在支持即时更新的配置（如 `log_level`、`peer_idle`）生效后调用；
- 一种新的转发：在 `create` 钩子里用 `npf_peers_add_kind` 登记一个 `npf_fwd_kind`（大写字母，以及解析、检查、建立、撤销的回调），用 `npf_peer_forward_add_kind` 加到对端上，库像本地转发一样保存、重试、随对端删除；`npf_peers_fwd_call` 给出这条转发所在的会话；
- 模块可以在 local.json 的设备记录里保存自己的键（`npf_local_ext` / `npf_local_ext_set`），库原样保留；
- 状态 JSON 里模块的字段和库的字段在同一个对象里，模块应使用带自己前缀的键名，避免与库现有或以后的字段重名；
- `tests/api/test_module.c` 是一个完整的例子：注册（重复、冲突、上限）、命令、配置键及其检查、`conf_set`、状态字段、销毁、创建失败时的清理，以及注册之前创建的实例。

## 13. 日志与排查

- 每条日志格式为“日期 时间.毫秒 级别 消息”。有 `log` 回调时交给回调，否则写到 stderr；`npf_log_json` / `log` 命令给出最近的日志（`no_log_ring` 可以关掉）。日志回调在产生日志的线程执行，创建和销毁阶段也可能调用；建议只做日志收集，避免在其中改变实例生命周期。业务回调的 API 调用规则见第 8 节；
- 连不上时先看状态 JSON 的 `online`、`nat` 和对端的状态；会话的 `path` 说明走的是直连还是中转；
- 在 `p2p` 模式下检测到 VPN 占用默认路由时，库会尝试让 UDP 套接字和信令连接使用物理网卡。是否成功取决于平台支持、可用网卡和绑定权限，不能保证绕过 VPN；网络变化后调用 `npf_network_changed` 让库立即重新检查。

## 14. 限制与后续

- 当前安装规则只在满足第 2 节条件的 Linux 构建中生成合并并隐藏内部符号的 `libnpf.a`。其他平台可使用共享库，或自行集成静态目标；自行静态链接时需处理与应用自带的 mbedTLS 等库的符号冲突；
- `rcv_deadline_ms` 暂不生效：要等 AnLiu 支持修改已打开的流的接收选项；
- WS 中转上的媒体流没有往返时延，`target_rate` 只在积压过之后才有估计值。

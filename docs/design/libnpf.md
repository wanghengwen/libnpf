# libnpf：库与应用端

版本：0.9。更新日期：2026-10-09。

NPF 的 C 节点拆成两部分：

- **libnpf**：给别人使用的库，唯一的公开头文件是 `include/npf.h`；
- **npf**：应用端程序，命令行、HTTP 控制接口和服务/守护进程都在这里。它自己也是 libnpf 的一个使用者。

需求来源：用户 2026-10-07 提出以下要求：

- "npf 需要拆成 libnpf 以及应用端，libnpf 需要给别人使用，http 接口部分留在应用端"；
- 配置目录由用户在初始化时指定，其中一部分只读、一部分要修改；
- 导出音视频接口；
- 控制通道上收发自定义数据；
- WS 中转下也能传音视频；
- 音视频流可以多路同时进行，并且会反复开关。

## 1. 组成

| 部分 | 位置 | 内容 |
|---|---|---|
| 公开接口 | `include/npf.h` | C ABI、整数句柄，`NPF_API` 导出 |
| 接口实现 | `src/api/` | `api.c`：线程安全的入口；`engine.c`：配置、身份、节点钩子、会话与媒体编号；`cmd.c`：命令（原 control.c 的命令部分）；`platform.c`：平台请求、绑定、映射、enroll |
| 音视频 | `src/node/media.c` | AnLiu 上一路一条流；WS 中转上的 `MEDIA` 单元、记录与发送队列（[数据通道协议](../protocol/data-channel.md)第 14 节） |
| 内部模块 | `src/...`、`include/npf/*.h` | 节点、呼叫、隧道、打洞、加密等，不公开 |
| 应用端 | `client/app/` | `main.c` 命令行与启动；`control.c` HTTP 控制接口及其客户端；`ctl.c` 控制接口的 HTTP 服务；`httpd.c` 控制接口与文件服务共用的 HTTP 服务端；`service.c` 守护进程与 Windows 服务 |

## 2. 构建与链接

- 共享库：`libnpf.so.1`（Linux）、`libnpf.dylib`（macOS）、`libnpf.dll` 与导入库 `libnpf.dll.a`（Windows / MinGW，导出表 `src/api/npf.def`）；
- 静态库：Linux 上生成 `libnpf.a`。做法是把内部各库用 `ld -r` 合成一个目标文件，再用 `objcopy --localize-hidden` 把 npf.h 以外的符号都改成局部符号。这样里面带的 AnLiu、Monocypher、mbedTLS 不会和应用自己的同名库冲突。macOS、Windows 的静态库暂不做这一步；
- 所有目标文件都用 `-fvisibility=hidden` 编译，位置无关。导出的只有 npf.h 中的 27 个函数，用 `nm -D` 可以核对；
- 安装：`cmake --install`，装入 `lib/libnpf.*`、`include/npf.h`、`lib/pkgconfig/npf.pc`。使用方 `cc app.c $(pkg-config --cflags --libs npf)`；
- ABI：
  - `NPF_API_VERSION` 为 1，soname 为 `libnpf.so.1`；
  - 调用方分配的结构体第一个字段都是 `size`：`npf_options`、`npf_callbacks`、`npf_media_opt`、`npf_media_stats`；
  - 以后的版本只在结构体末尾增加字段。库只读取调用方编译时就有的部分，其余用默认值；
  - 前三个结构体用 `npf_options_init`、`npf_callbacks_init`、`npf_media_opt_default` 初始化，`npf_media_stats` 由调用方填 `size`；
  - 回调放在单独的 `npf_callbacks` 中，选项通过指针引用它，选项和回调可以各自增加字段；
  - 不兼容的修改要提高 soname；
- 测试：
  - `tests/api/test_api.c` 只用 npf.h，链接共享库，在回环上起三个实例。check.sh 把它跑两遍：一遍在 ThreadSanitizer 构建上（`NPF_TSAN`）；一遍先 `cmake --install` 出 SDK，只用安装出的 npf.h、库和 `npf.pc` 编译再运行，同时检查共享库只导出 `npf_*`；
  - `client/tools/npf-mediatest` 配合 `tests/integration/media.sh` 在平台上测试，分别走 AnLiu 路径和 WS 中转。

服务器构建可用 `cmake -S . -B build-openssl-rel -DNPF_USE_OPENSSL=ON -DCMAKE_BUILD_TYPE=Release`，然后 `cmake --build build-openssl-rel`。CMake 为内部模块定义 `NPF_USE_OPENSSL` 宏，选择 OpenSSL 3.0+ 后端，不编译 mbedTLS。默认关闭，保留嵌入式构建。

- OpenSSL 承担 TLS、ChaCha20-Poly1305、Ed25519、X25519、BLAKE2b-512、HMAC 与有密钥 BLAKE2b；上下文按连接或调用分配，TLS 不经过 libnpf 全局锁。
- 无密钥 BLAKE2b-256（指纹、证书、CPace 等）和 CPace 的 Elligator 映射仍用 Monocypher；NPF / AnLiu 的 SIV 实现保持原样。OpenSSL 3.0 的无密钥 BLAKE2b 不支持所需的可变输出长度，不能简单截断 512 位摘要替代。内部返回 void 的摘要、签名、公钥派生函数在 EVP 分配失败时回退到原实现；AEAD、DH、验签失败则返回错误。
- TLS 的认证模型与原后端相同：由 Noise 或签名内容认证服务器，TLS 不验证证书。OpenSSL 不改变宿主进程的 SIGPIPE 处理，也不调用全局 cleanup。
- OpenSSL 是外部链接依赖。安装后的共享库使用 `pkg-config --libs npf`；静态链接还需 `pkg-config --static --libs npf` 给出的 OpenSSL 与线程库。`scripts/check.sh` 在安装 OpenSSL 开发包时同时检查两个后端、共享 / 静态 SDK，以及 OpenSSL 的直连、HTTPS 来源和 WS 媒体集成。

## 3. 目录

`npf_options` 中的程序标识：`app_name`（1–32 个 `a-z 0-9 . _ -`）与 `app_ver`（不超过 32 个可打印字符），登录时报给平台（signaling.md `login.app`），写进平台的连接与呼叫记录，被叫的会话信息中也能看到主叫的程序；不填时为 `libnpf` 与库的版本，不合格时 `npf_create` 失败。npf 命令行填 `npf`，托管服务填 `npf-hosted`。

`npf_options` 中的目录：

| 目录 | 库的权限 | 内容 |
|---|---|---|
| `conf_dir` | 只读 | `npf.conf`（或 `conf_file`）及其中引用的文件：设备凭据 `cred` / `model_cred`、根公钥、内置服务器列表 `serverlist`、直连密钥文件 |
| `data_dir` | 读写 | `identity`（没有设备凭据时生成的密钥）、`node.json`（enroll 得到的号码）、`state.json`（被叫状态：密码、配对、所有者）、`account.cert`、`serverlist-saved.bin`（平台下发的新服务器列表）、`local.json`（下文） |

- `data_dir` 的取值：选项 `data_dir`；没有时用配置中的 `dir`；再没有时等于 `conf_dir`。`state` 键仍可以指定文件；
- 平台下发的完整服务器列表默认保存为 `data_dir` 下的 `serverlist-saved.bin`，启动时与内置列表比较序号、用新的那份（安全设计 7.5）；配置 `serverlist_saved` 可以换成别的文件，`off` 表示不保存（重启后回到内置列表）；
- **生效的设置**按顺序叠加，后者覆盖前者：
  1. `npf.conf`；
  2. `overrides`，即应用传入的 `key = value` 行，例如命令行的 `--node`、`--direct`；
  3. `local.json` 的 `settings`。

  `node` 行不覆盖，三处的都加入，各自带来源标记：
  - npf.conf 中的为 fixed，不能删除，也不能在其上保存转发；
  - overrides 中的为 option；
  - local.json 中 `save` 为真的设备为 saved，可以删除；
- **运行时保存**（`npf_config_set` 带 save、`npf_peer_add` 带 `NPF_PEER_SAVE`、`npf_forward_add` 带 save、命令 `set` / `connect --save` / `forward 名字 add --save`）只写 `data_dir/local.json`，npf.conf 从不写。集成测试 control.sh 把 npf.conf 设为只读来验证这一点；
- `dir`、`state` 决定 local.json 自己在哪里，只能写在 npf.conf 中，`set` 拒绝它们；
- local.json 也保存应用自己的键：npf 程序的 `control`、`control_token`、`log`、`pidfile`。npf 程序启动时同样先读 npf.conf，再叠加 local.json 的 `settings`，所以 `set control off` 在重启后生效。其他使用 libnpf 的应用如果有自己的键，也应这样叠加。

**local.json**：库和应用自己记下的、不涉密的内容，JSON（`include/npf/local.h`）：

```json
{"settings": {"log_level": "debug"},
 "start": ["--log", "/tmp/npf.log"],
 "devices": {"611631552": {"name": "dev", "nick": "上海测试机", "nick_synced": "上海测试机", "save": true,
                           "forwards": ["-L 28290:127.0.0.1:28290", "-D :1088"], "key": "<固定的公钥>"},
             "203.0.113.5:9850": {"save": true, "psk_file": "key"}}}
```

- `settings`：`set` 保存的设置；`start`：`npf start` 的选项（应用端写，后台进程不运行时才写）；
- `devices`：按编号（或直连的 HOST:PORT）记每台设备：`name`（敲命令时代替编号的短名，只在本机）、`nick`（备注，任意文字）、`nick_synced`（上次与平台一致时的备注，见下）、`save` 与 `forwards`（启动时连接及其映射）、`psk_file` / `psk`（直连密钥）、`key`（配对时固定的公钥，原 `known` 文件）；什么都不剩的设备不写；
- 秘密（`identity`、`state.json`、`control.token`）和证书仍各自成文件，不放进 local.json；
- 写入是整个文件经临时文件 + rename 原子替换，权限 0600；后台进程运行时只由它写；读不了（损坏）时拒绝启动并说明，不覆盖；
- 上限 256 台设备、每台 16 个映射，文件不超过 512 KB；
- 旧版本的 `local.conf`（`键 = 值` 与 `peer =` 行）和 `known` 在第一次读取时转换过来，原文件改名为 `.old`。

**备注与平台同步**：账户下的设备（自己的或分享来的），备注同时是平台上的设备备注（`device_update` 的 `alias`，按账户），在别的电脑上也看得到。每次以账户会话登录（以及收到 `devices_changed`）时读取平台的设备列表，与 `nick_synced` 比较：只有平台变了就取平台的，只有本地变了就推给平台，两边都变了以平台为准并记日志；登录状态下修改的备注立即推送。不在账户里的设备、没有账户会话时，备注只在本机。名字不同步。

## 4. 角色

| 角色 | 用途 | 行为 |
|---|---|---|
| `NPF_ROLE_NODE` | 长期运行 | 有号码时可被呼叫；连接保存的对端；路由器端口映射；执行平台保存的端口映射；带 `model_cred` 时首次运行 enroll |
| `NPF_ROLE_CLIENT` | 一次性任务 | 以客户端登录：账户、设备、绑定、映射命令，前台会话 |
| `NPF_ROLE_DIRECT` | 不用平台 | 只做直连：按配置的 `direct` 监听，或连接 `HOST:PORT` 对端；没有 npf.conf 也可以 |

## 5. 线程

生命周期：`npf_create` →（调用）→ `npf_start` 或 `npf_run` →（调用）→ `npf_stop` → 运行结束（事件 `stopped`，`npf_run` 返回）→ `npf_destroy`。

- `npf_start` 让实例在自己的线程上运行，`npf_run` 在调用者的线程上运行，直到运行结束；
- 两者只能调用一次，`npf_stop` 之后也不能再调用。状态检查在锁内完成；
- **除 `npf_destroy` 外，所有函数都可以在任何线程、任何时候调用**：
  - 运行期间，其他线程的调用投递到实例的线程执行，调用方等待结果。`npf_media_send` 只排队；
  - 不在运行时（启动前、结束后），在调用者的线程上执行，同一实例同时只执行一个调用，其他调用方等待；
  - 回调里的调用直接执行；
  - 运行结束后的调用返回 `NPF_ESTATE`；
- **`npf_destroy`**：
  - 可以在任何线程调用，但不能在本实例的线程上（不能在回调中）调用，否则拒绝并记日志；
  - 它停止运行并等待运行结束，包括在其他线程上的 `npf_run`，也等待已经进入 API 的调用完成准备、投递及返回，然后释放；
  - 调用之后不能再对该实例发起调用；
- **回调**：
  - 在实例的线程上执行，一次一个；
  - 可以调用本实例除 `npf_destroy` 外的任何函数，不要长时间阻塞；
  - 回调拿到的 JSON、文本、帧和 `npf_frame_info` 只在回调期间有效，需要保留时自己复制。函数返回的 JSON 和文本归调用方，用 `npf_free` 释放。返回 NULL 表示实例已不在运行，或内存不足；
- **共享运行时**（`npf_runtime_new(threads)`、`npf_options.runtime`，2026-10-12）：
  - 运行时有若干个线程（`threads` ≤ 0 时每个 CPU 一个），每个线程跑一个宿主事件循环；实例的事件循环作为它的子循环，没有自己的唤醒描述符，唤醒子循环即唤醒宿主；
  - `npf_create` 把实例分到实例最少的线程上，`npf_start` 把它挂上去，此后一直在这个线程上，直到运行结束；`npf_run` 返回 `NPF_ESTATE`；
  - 宿主每轮把自己和所有子循环的套接字放进一次 `poll`，分派某个实例的回调、投递任务和定时器时切换到该实例的日志上下文；
  - 停止一个实例只撤销它自己的套接字、定时器和投递任务：结束分几步（`npf_engine_end_step`），每步之间宿主照常运行该实例和同线程的其他实例，原来阻塞的 `npf_loop_once(50)` 改为等待下一步的时间；最后一步之后子循环脱离宿主，`npf_destroy` 才释放它。解析线程的结果仍投递到实例自己的子循环，实例释放时丢弃；
  - 约束：回调不能阻塞，也不能同步等待另一个运行时线程上的实例（会互相等待）；在实例所在线程上（包括同线程其他实例的回调中）调用 `npf_destroy` 被拒绝并记日志；`npf_runtime_free` 在最后一个实例销毁之前返回 `NPF_ESTATE`；
  - 代价：同一线程上的实例互相影响，大流量的实例增加邻居的延迟；
  - npf-hosted 用它运行账户的托管客户端（`hosted.conf` 的 `threads`）。
- **多个实例**：同一进程可以有多个实例，各自一个线程（或在共享运行时上）、API 互斥锁和条件变量，相互独立。
  - 库里不再有可变的静态缓冲区：信令编解码、发送信封、服务器列表、被叫状态等原来共用的缓冲区都改为每次调用分配；
  - 进程级的状态只有以下几项：
    - 日志文件（应用用）；
    - DNS 解析线程池（有锁）；
    - 默认后端的 mbedTLS PSA 密钥表：mbedTLS 没有编译线程支持，TLS 调用经一把全局锁轮流执行，TLS 只承载信令和 WS 中转；
- **日志按实例**：
  - 每个实例有自己的日志级别、最近日志（`npf_log_json`、`log` 命令）和 `log` 回调；
  - 实现上，为实例工作的线程（它的线程，或不在运行时执行调用的调用方）带一个线程局部的日志上下文；
  - 其他线程（解析线程）的日志进入进程日志；
  - `log` 回调在不持有任何锁时调用，可以回调 API；
  - 没有 `log` 回调的实例，日志写到 stderr 或日志文件；
- 会话和媒体流用整数编号，`npf_t` 存续期间不重复使用。过时的编号只会得到 `NPF_ENOENT`，在任何线程上都一样。

**`npf_media_send`**：
- 在其他线程上调用时，帧被复制后投递到实例的线程；
- 每个实例最多 `NPF_MEDIA_SEND_QUEUE`（16 MiB）字节或 4096 帧等待，超过时返回 `NPF_EBUSY`，由应用决定丢帧还是降码率，不会无限积压；
- 帧龄从 `npf_media_send` 被调用的时刻算起，等待库线程的时间也计入 `max_age_ms`；
- 投递之后才发生的错误（例如流已关闭）只丢弃这一帧；
- 库线程每轮最多处理 256 个投递任务，其余留到下一轮，网络和定时器不会被饿死。

## 6. 接口

| 类别 | 函数 |
|---|---|
| 生命周期 | `npf_options_init`、`npf_callbacks_init`、`npf_create`、`npf_start` / `npf_run`、`npf_stop`、`npf_destroy`、`npf_free`、`npf_version`、`npf_api_version`、`npf_runtime_new` / `npf_runtime_free` |
| 查询（JSON，调用方 `npf_free`） | `npf_status_json`、`npf_config_json`、`npf_log_json`、`npf_sessions_json`、`npf_public_json`（托管客户端的公网映射：打开的连接数、各端口；`close` 非 0 时公网端口立即关闭且不再打开，已有连接继续，供 npf-hosted 优雅退出） |
| 设置 | `npf_config_get`（未知键返回 `NPF_ENOENT`，密钥类显示 `(hidden)`，缓冲区不够返回 `NPF_ETOOBIG`）、`npf_config_set`（返回 `NPF_OK` 表示立即生效，返回 1 表示下次启动生效） |
| 对端与转发 | `npf_peer_add_argv`（参数按词给出，词里可以有空格）、`npf_peer_add`（一行，空格分词）（都可带 `NPF_PEER_SAVE`、`NPF_PEER_ONCE`）、`npf_peer_remove`、`npf_forward_add`、`npf_forward_del` |
| 命令 | `npf_command(argv)`：status、connect、disconnect、peer、forward、get、set、log、stop、show、passwd、unpair、owner-reset、mapping、bind、enroll、id。结果文本和退出码交给回调；要等平台应答的（mapping、bind、enroll）稍后回调 |
| 平台请求 | `npf_request(type, data, key_proof, cb)`：白名单内的 account_*、verify_*、password_reset_*、device_*、share_*、owner_reset、mapping_*，以及 npf-hosted 用的 hosted_register、hosted_token、hosted_login。库自己保存账户会话和证书 |
| 应用数据 | `npf_session_send`：控制通道上的 `APP` 单元，每条不超过 16384 字节，对方的 `data` 回调收到 |
| 音视频 | `npf_media_open` / `send` / `stats_get` / `close`，回调 `media_open` / `media_frame` / `media_closed` |

**事件**（`event` 回调，参数为名称和 JSON）：

| 事件 | 内容 |
|---|---|
| `online` | `{server, account_id}` |
| `enrolled` | `{number}` |
| `enroll_failed` | `{error, reason, retry_in}`：一型一密的注册被拒，`reason` 见 signaling.md 的 `enroll`，约 `retry_in` 秒后重试；状态 JSON 的 `enroll`（`state` 为 none / enrolling / enrolled / refused，`error`、`reason`、`at`）记着最近一次 |
| `account` | `{account_id}` |
| `peer_done` | `{peer, why}` |
| `forward` | `{peer, spec, up, why}` |
| `public_conn` | `{mapping_id, port, from, start, end, in, out, call_id}`：公网映射的一条连接结束（只在托管客户端）；`from` 为来源 `IP:端口`，`start` / `end` 为 Unix 毫秒，`in` 为从来源收到的字节，`out` 为发给来源的字节 |
| `public_moved` | `{mapping_id, public_host, listen_port, from_host, from_port, reason}`：账户的一个公网映射因托管服务离线太久被平台迁到另一个托管服务，公网地址变了（`reason` 为 `service_offline`） |
| `public_refused` | `{mapping_id, port, from, reason}`：公网端口拒绝了一条连接，`reason` 为 `allow_from`、`quota`、`mapping_full`、`address_full`、`address_rate`、`no_session`（等会话超时或会话建立失败） |
| `mappings_changed` | `{}` |
| `devices_changed` | `{}` |
| `network` | `{why}`：进程被挂起过（`suspended for N s`）、本机地址变了或 UDP socket 重开过；libnpf 已经在检查并修复连接，应用不需要做什么 |
| `stopped` | `{}`：运行结束，原因是 `npf_stop` 或 stop 命令 |

**会话**回调：

- 建立时 `up = 1`，info 为 `{peer, path, direction, call_id}`；
- 结束时 `up = 0`，info 为 `{why}`，这个会话的媒体流随之结束。

## 7. 音视频

协议见数据通道第 14 节。下面是要点和限制。

**流与传输**

- 一个实例全部会话合计最多同时 64 路（`NPF_MEDIA_STREAMS_MAX`），包括本端和对端打开的流；超限本端返回 `NPF_EBUSY`、对端流被拒绝，关闭后可以再开；
- AnLiu 路径（直连、UDP 中转）上：
  - 一路就是一条 AnLiu 半可靠流，随它打开，随它关闭（AnLiu 0668f4a 起关闭会通知对端），帧上不加任何头；
  - 每一方最多同时打开 30 条，再打开返回 `NPF_EBUSY`。刚关闭的流在对端确认前（约一个往返）还占着名额；
  - 对方开的流先在 AnLiu 的 accept 回调里接下，输入处理完后再问应用（accept 回调里不能调用 AnLiu 的其他函数）。应用拒绝就关闭这条流；
- WS 中转上：
  - 用 `MEDIA` 单元打开、关闭，帧带 9 字节的记录头（多路共用一个字节流，需要区分）；
  - 接收：分段重组的帧不超过 `NPF_MEDIA_FRAME_MAX`（4 MiB），同一会话同时只重组一帧（发送方总是连续写出一帧的各段），超限或交错的分段整帧丢弃，重组内存每个会话不超过 4 MiB；
  - 帧在本地按流排队，按连接的排空速率写出；
  - 超过 `max_age_ms` 的帧丢弃；设了 `drop_until_key` 时，丢帧后一直丢到下一个关键帧；
  - 每条流的队列最多 2 MiB 或 4096 帧，超限丢弃最旧的帧；发送单帧不得超过 `NPF_MEDIA_WS_FRAME_MAX`（2 MiB），超过返回 `NPF_ETOOBIG`；
  - 有音视频时端口转发让路；
  - 大帧分段传送。

**选项的作用范围**

- 发送选项就是这条 AnLiu 流的选项：prio、max_age_ms、drop_until_key、fec、fec_ratio、latency_rtt；
- `rcv_drop_until_key` 是对接收方的要求：AnLiu 上随流的 tag 告诉对方，对方在 accept 时设置；WS 上随 `OPEN` 告诉对方；
- `rcv_deadline_ms` 不生效：它是接收方本地的选项，发送方的值不传给对方，接收方用 AnLiu 的默认值。

**帧号与统计**

- AnLiu 路径上：`frame_no`、`lost_before`、关键帧标志都直接来自 AnLiu，每条流从 0 开始；统计中 `target_rate`、`srtt_ms`、`capacity_short` 来自连接，时延报告和丢帧数来自这条流；
- WS 中转上：帧号是 NPF 自己的；`lost_before` 由 NPF 按帧号计算，包括为等关键帧而丢弃的帧；统计见协议第 14 节。

## 8. 应用端 npf

npf 程序按 libnpf 使用者的方式工作：

- **`npf run`**：
  - 以 `NPF_ROLE_NODE` 用 `npf_start` 运行库；
  - 主线程运行自己的事件循环，跑 HTTP 控制接口、信号处理和服务；
  - HTTP 的 `/v1/cmd` 调用 `npf_command`，`/v1/request` 调用 `npf_request`；
  - 两者的应答在库线程上产生，经 `npf_loop_post` 交回主线程，再用 `npf_ctl_reply` 回复；
  - 状态、配置、对端等路由直接调用对应函数；
- **`npf run --node ... --once`**（前台的一次会话；没有配置文件时只连直连节点也走这里，不加 `--once` 时断线重连）：
  - 有平台节点时以 `NPF_ROLE_CLIENT` 运行，只有直连节点时以 `NPF_ROLE_DIRECT` 运行；
  - 用 `node add ... --once` 加入节点，每个节点结束时收到一个 `peer_done` 事件，都结束后退出；
- **`npf listen`**：`NPF_ROLE_DIRECT`，`--psk-file`、`--allow` 作为 overrides 传入；
- **账户、设备命令**：
  - 有运行中的 npf 时，经它的 `/v1/request` 发送（和以前一样）；
  - 否则自己创建一个 `NPF_ROLE_CLIENT` 实例，等 `online` 事件，再调用 `npf_request`，同步等待应答。等待期间主线程可以读终端输入（验证码），库线程上的信令连接不受影响；
- **mapping、bind、enroll**：有运行中的 npf 时交给它，否则自己连接平台后调用 `npf_command`；
- **show、passwd、unpair、owner-reset、id**：
  - 没有运行中的 npf 时，用 `NPF_ROLE_DIRECT`、`udp_port = 0`、不监听的实例直接执行，不启动；
  - 这样不会占用运行中节点的端口；
- 日志：库的日志写到 stderr 或 `--log` 文件，和以前一样。有 `log` 回调时交给回调。

运行时日志里，库执行的动作不再带 `control:` 前缀，账户动作不再带 `(command line)`，因为库不知道请求来自哪里。

## 9. 评审修正（2026-10-07）

对 `6618129` 的评审提出的问题都已确认并修正：

| 问题 | 修正 | 回归测试 |
|---|---|---|
| `npf_command` 的 connect 原地挪动 argv，造成重复释放 | 命令拿到的是指针数组的副本，释放按原数组 | tests/api：`--once` 在首、中、尾 |
| 多实例共用可变静态缓冲区 | 全部改为每次调用分配或放到栈上；mbedTLS 调用加全局锁；`npf_sock_strerror` 用线程局部缓冲；`WSAStartup` 不再缓存 | tests/api 三个实例；media.sh 一个进程两个实例同时登录收发；check.sh 的 ThreadSanitizer 构建 |
| WS 媒体重组没有上限 | 第 7 节的重组限制 | test_media、fuzz media |
| 日志回调在锁内执行，回调里调 API 死锁 | 回调在锁外调用 | tests/api：运行前、运行中各一次 |
| 日志没有实例隔离 | 日志上下文按实例（第 5 节） | tests/api：行、级别、`npf_log_json` 互不串 |
| 跨线程媒体发送没有背压 | 16 MiB 预算、`NPF_EBUSY`、提交时刻计入帧龄、各线程一致的 `NPF_ENOENT`、投递任务批量上限 | tests/api：库线程忙时发 24 MiB |
| 应用的设置保存后自己不读 | npf 程序叠加 local.json 的 settings | — |
| 接口契约 | 结构体带 size、回调独立、生命周期写进 npf.h、`npf_destroy` 等待 `npf_run` 并拒绝在回调中调用、`npf_start`/`npf_run` 状态检查原子化、`npf_peer_add_argv`、`npf_config_get` 的错误码、安装后的 SDK 检查 | check.sh |

仍是过渡状态的一项：npf 程序还链接 `npf_common` 并使用内部的工具模块（配置文件、JSON、事件循环、HTTP 服务器）。它对库的调用只经过 npf.h，SDK 的独立可用由上面的安装检查保证。

ThreadSanitizer 还发现事件循环的唤醒标志和停止标志由其他线程写入，没有原子操作，已改为原子读写。

### 2026-10-09 复审修正

- HTTP chunk 大小改为逐位检查溢出，长度检查使用减法；补齐数据尾 CRLF、零块和 trailer 检查；Content-Length 或 chunk 已完整时交付响应，不依赖服务端发送 TLS close_notify。WS 区分空分片与没有分片，拒绝畸形控制帧，握手头上限只计算 HTTP 头。
- WS / HTTP 按解析器给出的候选地址依次连接，失败或连接超时后尝试下一地址；仍受整个请求的超时约束。连接中的任何事件都先查 `SO_ERROR`：macOS 上被拒绝的连接只有 `POLLHUP`，原来要等 1 秒超时才换地址，期间事件循环空转（2026-10-09 实机测试发现）。
- WS relay 的 bind 发送失败后立即退出回调，避免对象释放后继续访问；收到媒体 OPEN 时先注册再调用应用，允许回调内立即关闭。
- API 入口引用覆盖任务分配前的准备阶段，销毁等待已有调用；stop 直接原子停止并唤醒循环，不再依赖分配任务内存。事件循环新 handler 槽先清零再建索引。
- 输出缓冲记录分配失败，local.json 序列化不完整时拒绝保存，保留原文件；查询和命令报告内存错误。
- 网络解析新增 HTTP / WS 模糊测试；故障注入验证配置保存与 relay bind 失败；并发销毁与跨会话 64 路限制分别有回归测试（`tests/api`）。

## 10. 后续

- 对 AnLiu 接口的需求向 AnLiu 提出。A5（关闭通知对端）已由 AnLiu 0668f4a 实现，NPF 因此改为一路一条流，A1–A3 不再需要；仍有用的是 A4（流数上限可配置、可查询）；
- macOS、Windows 的静态库做符号局部化；
- 媒体流的 WS 中转没有 RTT，`target_rate` 只在积压过之后才有估计值。

## 变更记录

| 日期 | 版本 | 内容 |
|---|---|---|
| 2026-10-12 | 0.10 | 共享运行时：`npf_runtime_new` / `npf_runtime_free`、`npf_options.runtime`，多个实例在少量线程上运行，每个实例固定在一个线程上（第 5 节） |
| 2026-10-09 | 0.9 | 单实例 64 路、WS 每流 2 MiB；OpenSSL 编译后端；并发销毁、解析、错误处理与多地址回退修正 |
| 2026-10-08 | 0.8 | 事件 `public_conn` / `public_refused`；托管客户端的防滥用限制（配置键 `hosted_max_conns`、`hosted_ip_conns`、`hosted_ip_rate`）；信令按需（`sig_idle_s`、`sig_wake_s`，只对托管客户端：闲置时断开信令，公网连接、映射同步或定时刷新时再连）；`npf_public_json`；连接记录以 `conn_report` 上报平台；停止时先结束会话并上报用量与连接记录 |
| 2026-10-07 | 0.7 | 事件 `quota`（账户的流量额度：`warning`、`exhausted`、`ok`、`no_public`）；托管客户端（`hosted_exec`）向平台要额度，在隧道中逐字节扣减，用完立即降速、公网映射停止接受新连接并在连接结束后关闭 |
| 2026-10-07 | 0.6 | `npf_options` 增加 `app_name` / `app_ver`（程序标识）；配置键 `hosted_service` / `hosted_exec`（只供 npf-hosted 使用）；`npf_request` 可以发 `hosted_register` / `hosted_token` / `hosted_login` |
| 2026-10-07 | 0.5 | 应用端：`connect` / `disconnect` / `devices` 合并为 `npf node`（add / del / set / 列表），`run --peer` 改为 `run --node`、新增 `--once`，配置键 `peer` 改为 `node`，HTTP `/v1/peers` 改为 `/v1/nodes` |
| 2026-10-07 | 0.4 | 第 3 节：程序写的内容合并为 local.json（设置、启动选项、每台设备的名字、备注、保存与映射、固定公钥），取代 local.conf、known、start.args；备注与平台的设备备注在登录时同步 |
| 2026-10-07 | 0.3 | 第 7 节：AnLiu 上一路音视频一条流，真正打开、关闭，帧上不加头 |
| 2026-10-07 | 0.2 | 评审修正（第 9 节）：多实例隔离、日志按实例、结构体带 size、回调独立、生命周期约定、媒体发送预算、WS 重组上限、SDK 安装检查 |
| 2026-10-07 | 0.1 | 初稿：拆分、目录、线程、接口、音视频（AnLiu 通道复用、WS 中转）、应用端 |

# NPF JSON 信令协议草案

版本：0.27。更新日期：2026-10-22。变更记录见文末。

本文把信令与账户的需求转为可逐步讨论的消息和流程。JSON 格式及纯 C 设备端是已确认约束；本文其余消息名、字段、限额、状态机均为协议建议，尚未冻结。本文不逐条标注哪些条目已经实现。原平台消息名和报文不要求兼容。

## 参与方与承载

参与方分两类（安全设计 8.5）：**节点**是有编号的控制台程序（NAS 设备端、PC 或服务器上的控制台客户端），既能呼叫也能被呼叫；**纯客户端**（桌面 GUI、手机 App、匿名客户端）只能呼叫。一次呼叫中，发起方为**主叫**，被呼叫的节点为**被叫**。

| 范围 | 参与方 | 内容 | 节点（C 程序）的负担 |
|---|---|---|---|
| 平台管理 | 客户端（或登录了账户的控制台节点）与平台 | 注册、登录、密码、设备列表、映射配置 | 控制台节点只需实现登录账户与注册编号；NAS 设备端不需要 |
| 平台接入与呼叫 | 节点或客户端与平台 | 身份接入、呼叫、握手转发、候选交换 | 主叫与被叫两种角色的消息都要实现 |
| 隧道内控制 | 主叫与被叫 | 隧道 `hello`、会话关闭等（隧道的控制通道）；子链路本身为 SOCKS5 二进制协议 | 解析少量 JSON 控制消息与 SOCKS5 请求 |

原生端复用 WSS 内的 Noise 认证通道发送 JSON。JSON 是加密前或解密后的表示；线上发送的是 **binary** WebSocket 消息，一条消息就是一条 Noise 握手消息或一段传输密文，不再编码（安全设计 7.2）。服务器之间的信令同样如此（多服务器设计第 5 节）。初始 Noise 握手和 AnLiu 数据报保持各自格式，不强行转成 JSON。外层消息类型复用规则沿用安全文档作为背景，正式字节编码另行定稿。

**过渡期的 text 消息**：2026-10-22 之前的节点和服务器发 text 消息，内容是同样字节的无填充 Base64url。服务器对节点的连接暂时两种都收：按节点的第一条消息（Noise 握手的第一条）是 binary 还是 text 决定，此后服务器都用这种消息回复，节点之间经服务器转发的信令因此自动在两种形式间转换。服务器之间只用 binary（服务器一次全部升级），收到 text 消息即断开。节点只发 binary，收到 text 消息也能解码。部署时先升级服务器：未升级的服务器收到 binary 消息即断开。在用的旧版本节点都升级后去掉 text。

账户网页登录及第三方授权回调可使用正常校验证书的 HTTPS；其路径、Cookie 或令牌方式尚未确定。不能将已有 WSS 依赖内层 Noise 的“不校验 TLS 证书”约定用于普通 HTTPS。采用 HTTPS 时仍可复用本文的 JSON 消息语义。

WebSocket：一个完整的应用信令消息对应一个 JSON 对象；接收端先处理 WebSocket 分片，再验证解密。信令连接只承载信令，不承载数据。隧道内的控制消息放在隧道控制通道（AnLiu 默认流）的控制单元中，每个单元一条 JSON，见 [数据通道协议](data-channel.md) 第 8 节。

## 公共消息格式

请求示例：

```json
{
  "v": 1,
  "type": "device_list",
  "id": "req-101",
  "data": {"limit": 20}
}
```

响应示例：

```json
{
  "v": 1,
  "type": "device_list",
  "reply_to": "req-101",
  "status": "ok",
  "data": {"devices": []}
}
```

事件没有 `id`、`reply_to` 或 `status`，例如 `devices_changed`。请求与响应不可同时带 `id` 和 `reply_to`。

| 字段 | 类型 | 含义 |
|---|---|---|
| `v` | 整数 | 主版本，草案为 1 |
| `type` | 字符串 | 消息类型，使用固定 ASCII 名称 |
| `id` | 字符串 | 请求编号，在该连接本端未完成请求中唯一 |
| `reply_to` | 字符串 | 响应对应的对端请求编号 |
| `status` | 字符串 | 响应为 `ok`、`pending` 或 `error` |
| `error` | 字符串 | 仅失败时出现，供程序判断的错误码 |
| `message` | 字符串 | 可选说明，不作为客户端判断依据 |
| `data` | 对象 | 所有消息均携带，无业务字段时为空对象 |

请求编号不是身份凭据，也不是跨连接幂等键。平台转发呼叫时两侧可使用不同请求编号，通过独立的 `call_id` 关联。账户身份来自认证上下文，禁止使用请求体中的 `account_id` 代替鉴权。

`pending` 表示操作已受理但尚未完成，必须返回可查询的操作编号；最终结果由查询获得，通知只作提示。认证开始接口返回 `ok` 仅表示成功创建登录事务，不表示账户已经登录。

错误码草案：`bad_request`、`unsupported_version`、`unsupported_type`、`unauthenticated`、`forbidden`、`not_found`、`conflict`、`expired`、`rate_limited`、`offline`、`timeout`、`no_path`、`internal_error`。无权访问对象时，不通过错误详情泄露其存在或所有者。子链路可增加 `target_denied`、`connect_failed`。

## JSON 与 C 解析约束

建议采用 token 式解析器，按消息类型读取必需字段，不构造通用对象树。缓冲区切片只在其所属消息生命周期内有效，异步使用的内容应复制或明确延长缓冲区生命周期。

| 项目 | 初始建议 |
|---|---|
| 编码 | UTF-8；对象键和协议枚举使用 ASCII |
| 单条 JSON 上限 | 32768 字节，按 UTF-8 编码后计；每类消息可有更低上限 |
| 最大嵌套深度 | 6 层，顶层算第 1 层 |
| 解析 token 上限 | 2048；具体计数定义随解析器选型统一 |
| 单个数组上限 | 32 项；设备列表默认每页 20 项且受总字节数限制 |
| 名字与备注 | 非空值最多 128 个 UTF-8 字节；名字是昵称，不要求唯一（R27） |
| ID 与修订号 | 使用字符串；平台修订号视为不透明值，客户端只做相等比较 |
| 数值 | 端口、计数等严格按字段要求解析整数并检查范围；不接受浮点数冒充整数 |
| 二进制字段 | Base64url，无填充；检查编码及解码后长度 |

以上限额是待压测的提案，编码器和解码器需共同遵守，不可无界分配。分页响应即使未达到条数上限，也可因字节或 token 预算提前结束并给出下一页游标。

拒绝重复键，包括转义解码后相同的键；拒绝非法 UTF-8、无效转义和截断输入。协议关键字只允许规范 ASCII 表示。普通字符串正确处理转义；传给 C 字符串 API 的字段拒绝内嵌 NUL。字段顺序无意义。

必需字段缺失、已知字段类型错误、未知必需能力均拒绝。未知可选字段可忽略，不能用忽略字段的方式跳过权限要求。同一主版本只增加可选字段；不兼容的语义或必需字段修改需升级版本。

不对任意 JSON 序列化结果直接签名。绑定证明等签名对象应另定确定性编码及域分隔，然后以 Base64url 放入 JSON；该编码本稿未冻结。密码学对象解析与业务 JSON 解析分离。

## 接入与服务器列表

关联：安全设计 7.2（Noise 握手）、7.5（服务器列表）。WSS 连接上的 Noise_XK 握手完成后，第一条信令必须是 `login`，或者首次注册编号的 `enroll`（NAS 设备端凭厂商凭证注册，见安全设计 5.2；控制台节点凭账户注册，见下文的 `node_enroll`）；`welcome` 之前的其他消息一律拒绝。被拒的 `login` / `enroll`：服务器先送出 `status = error` 的应答（`error` 与 `message` 给出原因），再正常关闭连接（WebSocket 关闭码 1000）。

一条连接有两层身份：**接入身份**（节点或纯客户端，由握手中的静态公钥与证书确定，决定能否被呼叫、呼叫时以谁的名义）和可选的**账户会话**（决定能否做设备列表、绑定、映射等账户操作）。纯客户端的账户会话来自客户端证书（type 5）；控制台节点的账户会话来自平台为**同一把密钥**签发的客户端证书，在 `login` 中与节点证书一起出示。NAS 设备端没有账户会话，账户操作一律返回 `unauthenticated`。

| 类型 | 方向 | 形式 | 作用 |
|---|---|---|---|
| `login` | 节点 / 客户端 / 托管服务 → 平台 | 请求 | 登录；应答即 `welcome` |
| `enroll` | NAS 设备端 → 平台 | 请求 | 一型一密：握手后的第一条消息，凭型号凭证注册编号（安全设计 5.2）；成功后在同一条连接上 `login` |
| `node_enroll` | 控制台节点 → 平台 | 请求 | 以已登录的账户为控制台节点注册编号（安全设计 8.5） |
| `server_list` | 平台 → 节点 / 客户端 | 事件 | 推送新的服务器列表 |
| `keys` | 平台 → 节点 / 客户端 | 事件 | 推送新一天的 `probe_key`、`relay_day_key` 和新票据 |
| `probe` | 平台 → 节点 / 客户端 | 事件 | 地址探测的端点变了（另一台服务器上线或下线） |
| `redirect` | 平台 → 节点 / 客户端 | 事件 | 要求改连列表中的另一台服务器 |
| `replaced` | 平台 → 节点 / 客户端 | 事件 | 同一身份在别处登录了，这条连接随即被关闭（security.md 5.4） |

### `login`

```json
{"v": 1, "type": "login", "id": "l1", "data": {
  "role": "node", "number": "123456789", "cert": "<节点证书>",
  "model": "NAS-A", "fw": "0.1.0", "sl_serial": 1791100000}}
```

| 字段 | 说明 |
|---|---|
| `role` | `node`、`client`，或 `hosted`（托管服务 npf-hosted 自身，见"托管服务"） |
| `number`、`cert` | 节点：编号与节点证书（安全 3.2 的 type 3，控制台节点与 NAS 设备端相同）。服务器检查证书中的 `dh_pub` 与 Noise 握手得到的静态公钥一致。一机一密的设备首次登录时还没有证书，不带 `cert`：服务器用握手公钥与预存的公钥比对，一致即激活，并在 `welcome` 的 `cert` 中签发（安全 4.2） |
| `cert` | 纯客户端：注册账户的客户端证书；匿名客户端不带，身份就是握手中的静态公钥 |
| `account_cert` | 控制台节点可选：为同一把密钥签发的客户端证书，带上后该连接有账户会话。NAS 设备端不带 |
| `model`、`fw` | 只有节点带：型号与程序版本（设备信息上报的一部分），控制台节点的 `model` 为 `console` |
| `app` | 所有角色都带：程序的名称与版本 `{"name": "npf", "ver": "0.1.0"}`。名称 1–32 个 `a-z 0-9 . _ -`，版本 1–32 个可打印 ASCII 字符，不合格的登录回 `bad_request`。npf 命令行为 `npf`，托管服务及其托管客户端为 `npf-hosted`，基于 libnpf 的程序填自己的名称（库的默认值为 `libnpf`）。平台写进连接记录，并在呼叫时由服务器从双方的连接取出，写进呼叫记录、放进 `incoming.caller.app`（跨服务器的呼叫随呼叫转交），呼叫时不另外发送。它是程序的自述，只用于统计、排障和提示升级，不作为授权或计费的依据 |
| `sl_serial` | 本地服务器列表的 `serial`，没有时为 0 |
| `host` | 可选，所在主机的信息，平台写入连接记录（运维用）：`os`（如 `Linux 6.6.87 (Ubuntu 22.04.4 LTS)`、`macOS 26.5 (Darwin 25.5.0)`、`Windows 10.0.19045`）、`arch`、`hostname`、`machine_id`（Linux `/etc/machine-id`，macOS IOPlatformUUID，Windows MachineGuid）、`macs`（网卡硬件地址，最多 8 个）。服务器限制长度、去掉控制字符。节点配置 `report_host = 0` 时不发送 |

`welcome` 另带 `client_id`（本连接密钥的指纹，十进制字符串）和 `account_id`（本连接有账户会话时）。控制台节点出示的 `account_cert`、纯客户端出示的客户端证书已被吊销（别处改了密码、退出登录）或过期时，照常登录（纯客户端按匿名），`welcome` 中没有 `account_id`，客户端据此丢弃本地的账户证书、显示为未登录，而不是被拒绝后反复重连；平台查不了数据库时回 `internal_error`，不当作吊销。

### `enroll`（一型一密）

NAS 设备端没有编号时（身份文件新建或丢失），Noise 握手后的第一条消息是：

```json
{"v": 1, "type": "enroll", "id": "r1", "data": {
  "model_chain": "<厂家证书 | 型号证书>", "serial": "SN-0001",
  "hw": [{"k": "board", "h": "<16 字节>"}, {"k": "emmc", "h": "<16 字节>"}, {"k": "mac", "h": "<16 字节>"}],
  "sign_pub": "<设备签名公钥>", "sig_v": "<64 字节>", "sig_d": "<64 字节>", "model": "NAS-A", "fw": "0.1.0"}}
```

- `hw`：硬件指纹的各项（安全设计 5.2），1–8 项，按 `k` 排序、每种一次，`k` 为 1–15 个小写字母或数字，`h` 为该项的 16 字节哈希；`hw_fp = BLAKE2b-256("npf-hw-v2" | 每项 len(k)(1) | k | h)`，由平台按收到的列表计算；
- `T = h(64) | len(serial)(1) | serial | hw_fp(32) | sign_pub(32)`，`h` 为 Noise 握手哈希（BLAKE2b，64 字节）；`sig_v = Ed25519(型号密钥, "npf-enroll-v1" | T)`，`sig_d = Ed25519(设备签名私钥, "npf-enroll-v1" | T)`。`dh_pub` 由握手本身证明。`serial` 为 1–64 字节的 UTF-8；
- `serial` 由厂家配置，没有时设备用物理网卡中最小的 MAC 地址（`mac-…`）或机器 ID 的哈希（`mid-…`）；
- 平台校验证书链的签名（安全设计 4.1）：厂家证书由 NPF 的厂家签发证书签发，型号证书由该厂家证书签发、厂家号一致（不看两张证书的有效期）。再以平台的型号登记为准：型号要已登记、未停用、未过登记的有效期，这张型号证书要已绑定、未吊销；白名单、配额、每小时注册数用登记的（型号证书里也有时取较小的）。再按安全设计 5.3 的表处理：新序列号分配编号；同序列号、硬件指纹与记录的多数项一致（按记录的项数计，见安全设计 5.3）、原身份离线 5 分钟以上则把原编号换成新密钥（`key_gen + 1`，通知所有者）；同一把密钥再次注册得到原编号，不计数；
- 拒绝时 `message` 是原因：`bad_chain`、`bad_sig`（`unauthenticated`）；`unregistered`、`unbound`、`revoked`、`expired`、`whitelist`、`clone`（原身份在线，疑似克隆）、`disabled`（`forbidden`）；`quota`、`rate`、`wait`（原身份离线不到 5 分钟）（`rate_limited`）；`conflict`（硬件指纹的多数项不一致，`conflict`）。平台按原因计数；
- 应答：`{"number": "...", "cert": "<中间证书 | 节点证书>", "key_gen": 1}`。连接仍未登录，设备接着在同一条连接上发 `login{role: "node", number, cert}`；
- 设备在本地生成默认口令（安全设计 5.5）。

### `node_enroll`

控制台节点首次运行时没有编号。程序先以纯客户端登录（`login{role: "client"}`，无证书即匿名），用户在控制台中登录账户（`account_login` 等，见"账户信息与登录"，成功后连接取得账户会话与客户端证书）后，程序在同一条连接上发送：

```json
{"v": 1, "type": "node_enroll", "id": "e1", "data": {"name": "office-pc", "fw": "0.1.0"}}
```

- 平台分配一个 9 位编号（与 NAS 设备号共用同一个编号空间，含校验位），为握手中的静态公钥签发节点证书（type 3，`vendor_id` 为 NPF 自身、`model` 为 `console`），并把该节点**自动绑定到当前账户**，账户成为它的所有者（安全设计 8.2）；
- 应答：`{"number": "...", "cert": "<中间证书 | 节点证书>"}`。平台把这条连接当场转为节点连接（登记路由表，可以被呼叫），不需要重连；程序把编号、节点证书与客户端证书保存在本地，之后用 `login{role: "node", cert, account_cert}` 登录；
- 节点本地生成配对口令并在控制台显示，其余授权规则（本地授权列表、托管信任、分享、撤销）与 NAS 设备端相同；
- 每个账户最多注册 20 个控制台节点；未登录账户的控制台程序不能注册，只能作为纯客户端（匿名或账户客户端）去呼叫别人；
- 节点被解绑后保留编号与证书，但没有所有者；所有者可以在设备列表中**注销**控制台节点（`node_retire{number}`），平台吊销其节点证书，编号作废、不再分配（安全设计第 6 节）。NAS 设备端的身份由厂商凭证体系管理，不能这样注销。

### `welcome`（`login` 的成功应答）

```json
{"v": 1, "type": "login", "reply_to": "l1", "status": "ok", "data": {
  "time": 1791100000123,
  "server_id": 17,
  "cert": "<续签的证书，可选>",
  "ticket": "<28 字节>", "ticket_expires": 1791186400,
  "probe_keys": [{"day": 20730, "key": "..."}, {"day": 20731, "key": "..."}],
  "probe": ["203.0.113.5:9910", "203.0.113.5:9911", "198.51.100.7:9910"],
  "relay_keys": [{"day": 20730, "key": "..."}, {"day": 20731, "key": "..."}],
  "server_list": "<blob，可选>",
  "redirect": 23,
  "ping_s": 25}}
```

| 字段 | 说明 |
|---|---|
| `time` | 服务器时间（Unix 毫秒），用于校准时钟偏差（安全 7.2 的设备时钟、打洞的 `start_at`）。接收方按 `time + login 往返时间 / 2 - 本地时间` 计算偏差 |
| `cert`、`account_cert` | 证书临近过期时附上续签的证书；`account_cert` 只对有账户会话的控制台节点出现 |
| `ticket` | 地址探测票据（nat-traversal.md 6.4），有效期 24 小时 |
| `probe_keys`、`relay_keys` | 当天与次日的 `probe_key`、`relay_day_key`（data-channel.md 9.2），`day` 为 UTC 天数 |
| `probe` | 地址探测的端点（nat-traversal.md 4.1）：E1、E2 是同一台探测服务器（一般是这台服务器自己）的两个端口，E3 是另一台在线、公网 IP 不同的服务器的端口；只有两个时映射类型判断不出来，没有这个字段时不探测 |
| `server_list` | 仅当服务器上的列表 `serial` 大于 `sl_serial` 时附上，Base64url 编码的 blob（安全 7.5） |
| `redirect` | 可选，要求改连的 `server_id`，必须在签名列表中 |
| `ping_s` | WebSocket ping 的间隔（安全 7.3） |

失败的应答：`unauthenticated`（证书无效、与握手公钥不符）、`forbidden`（证书已吊销、设备被停用）。设备收到后不立即重试同一台服务器，按安全 7.3 退避。

### `server_list`

`data = {"blob": "<Base64url>"}`。发布新列表时，服务器向所有在线连接推送，在 10 分钟内随机打散。接收方按安全 7.5 的条件验证，通过才替换本地保存的列表；验证失败只记录日志，不回应。

### `keys`

连接会持续多天，而 `probe_key`、`relay_day_key` 每天轮换、票据 24 小时过期。服务器在每天 UTC 零点前 1 小时内（随机打散）推送：`data = {"ticket", "ticket_expires", "probe_keys", "relay_keys", "probe"}`，字段含义与 `welcome` 相同。

### `probe`

`data = {"probe": [...]}`，含义同 `welcome` 的 `probe`。另一台服务器上线或下线、使这台服务器下发的探测端点变了时，服务器向所有在线连接推送，30 秒内随机打散；接收方换用新的端点，端点有变化时重新测一次 NAT。

### `replaced`

`data = {}`。同一身份的新连接登录（在这台服务器，或在另一台服务器、经服务器之间的连接通知过来）时，平台先向旧连接发这个事件，约 200 ms 后关闭它。接收方不立即重连：10 秒后再登录，再被替换时翻倍，最长 5 分钟，并在日志里说明原因（security.md 5.4）。

### `redirect`

`data = {"server_id": 23, "reason": "maintenance", "within_s": 300}`。接收方在 `within_s` 秒内的随机时刻断开当前连接，改连指定服务器；目标不在本地签名列表中时忽略。已经建立的数据通道不受影响（数据不经过信令连接）。`reason` 为 `maintenance` 或 `balance`，只用于日志。

## 账户信息与登录

关联需求：R05、R11 至 R14、R27 至 R31、R36。账户管理只在原生客户端上进行，走已认证的 WSS 信令；Google 与微信登录经系统浏览器完成授权。

| 字段 | 含义 |
|---|---|
| `account_id` | 平台分配的稳定账户标识，不用第三方昵称作主键 |
| `name` | 昵称，必填；不要求唯一，不用于登录（R27）；非空，最多 128 个 UTF-8 字节 |
| `email` | 可选；验证后才能用于登录和找回 |
| `phone` | 可选；短信验证后才生效，用于登录、找回和安全通知；第一版只支持 +86（R30） |
| `login_methods` | 已绑定的登录方式：`password`、`google`、`wechat`；至少保留一种（R31）；仅向账户本人展示 |

**登录标识**（R28）：密码登录以已验证的邮箱或手机号作登录名。设置密码的账户必须至少有一个已验证的邮箱或手机号；只用 Google / 微信登录的账户可以都不填，也没有本地密码。

### 消息目录

| 类型 | 方向 | 主要内容 |
|---|---|---|
| `verify_begin` | 客户端到平台 | `channel`（`email` 或 `phone`）、`address`；平台发送验证码，返回 `verification_id`。手机号的验证码由短信网关发出后才回复；网关拒绝时回 `rate_limited`（号码的频控）、`bad_request`（`address`，号码无效）或 `unavailable`（`sms`：网关故障；`sms_daily_limit`：平台当天的短信总量到了上限） |
| `verify_finish` | 客户端到平台 | `verification_id`、`code`；成功后该验证可在 10 分钟内被注册、绑定或找回消费一次 |
| `account_register` | 客户端到平台 | `password`、`verification_id`（已验证的邮箱或手机号作为登录名），`name` 可选：不给时取邮箱 @ 前面的部分，或中间四位隐藏的手机号（`138****8000`；设备主人在 `share_list` 里看得到访客的名字），以后用 `account_update` 改 |
| `account_login` | 客户端到平台 | `login`（邮箱或手机号）、`password` |
| `auth_providers` | 客户端到平台 | → `{providers}`：本平台配置了的第三方登录（`google`、`wechat`），界面据此显示按钮 |
| `auth_begin`、`auth_status`、`auth_finish` | 客户端到平台 | Google / 微信登录事务，见下文 |
| `account_get`、`account_update` | 客户端到平台 | 本人资料；`account_update` 只能改 `name` |
| `plan_list` | 客户端到平台 | 可订阅的套餐 `plans`（`level, name, monthly_bytes, relay_kbps, public_max, public_kbps, choose_port, prices`，级别 0 为免费级；`prices` 为可购买的时长 `[{months, currency, amount}]`，金额为最小货币单位，账户已定币种时只给该币种）、账户当前的级别 `level` 与订阅 `sub{level, start, expires}`，以及支付页 `subscribe_url`（服务器配置 `subscribe_url`，没有配置时不给出：界面提示联系运营方） |
| `pay_ticket` | 客户端到平台 | `{level?, lang?}` → `{url}`：`subscribe_url` 加片段 `#ticket=…&level=N&lang=…`。票据一次有效、10 分钟过期，带它打开支付页不需要再登录（服务器配置 `pay_ticket_secret`，没有配置时网址不带票据）；没有支付页时回 `unavailable` |
| `login_method_bind` | 客户端到平台 | `{method, …}` 绑定新的登录方式：`google` / `wechat` 附 `purpose = bind` 的事务 `transaction_id` 与确认码 `code`；`email` / `phone` 附 `verification_id`（已有的被替换）；`password` 附 `password`，账户还没有邮箱或手机号时同时附 `verification_id`（R28）。应答为账户资料；已属于其他账户、或该第三方方式已绑定另一个身份时 `conflict`，已有密码时 `conflict`（改密码用 `password_change`） |
| `login_method_unbind` | 客户端到平台 | `{method}`：`password`、`google`、`wechat`、`email`、`phone`。解绑后必须还能登录（密码、Google、微信至少一种），有密码时还要留一个邮箱或手机号，否则 `conflict`；没有绑定该方式时 `not_found` |
| `password_change` | 客户端到平台 | 旧密码、新密码；成功后吊销该账户其他客户端的证书（R34） |
| `password_reset_begin`、`password_reset_finish` | 客户端到平台 | 用任一已验证的邮箱或手机号找回：先 `verify_begin`，再以 `verification_id` 设置新密码 |
| `account_logout` | 客户端到平台 | 吊销当前客户端的客户端证书 |
| `account_delete` | 客户端到平台 | 注销账户：有密码的账户附 `password`，没有密码的账户附 `purpose = confirm` 的事务 `transaction_id` 与 `code`（必须是本账户已绑定的身份）作二次验证；效果见安全设计 8.1（解除全部设备的所有者关系、撤销分享、删除公网映射、吊销全部客户端证书）。返回 `pending` 与操作号，完成后该账户的所有连接被关闭 |

- **登录的结果**：`account_login`、`auth_finish`、`account_register`、`password_reset_finish` 成功后，平台为当前连接的客户端公钥（Noise 握手中的静态公钥）签发客户端证书（安全设计 8.1，有效期 30 天），客户端之后在 `login` 中出示它；证书的续签在 `welcome` 中完成，不另设刷新消息。这三个请求都带 `sign_pub`（客户端的 Ed25519 公钥）和 `key_sig = Ed25519(签名私钥, "npf-client-key-v1" | Noise 握手哈希)`：证明持有签名私钥，并把证明绑定到这条连接；应答为账户资料加 `cert`（`中间证书 | 客户端证书`）；
- **账户不合并**（R31）：同一个邮箱、手机号或第三方身份只能属于一个账户。绑定时如果它已经属于另一个账户，返回 `conflict`；第一版不提供合并；
- **验证码**：6 位数字，10 分钟有效，每个 `verification_id` 最多尝试 5 次；每个地址、每个源 IP 发送验证码有频率限制；
- 密码只在已认证的加密信令内发送，平台保存适合密码验证的加盐哈希，算法参数另行定稿；第三方登录的账户没有本地密码，不生成用户不知道的默认密码。

### Google 与微信登录流程

```text
客户端 ──auth_begin{provider, purpose, origin?}──> 平台：建事务（数据库），回 {transaction_id, url, expires}
客户端 ──打开 url（系统浏览器）──> Google 登录页 / 微信扫码页
浏览器 <──302 到 public_url/auth/<provider>?code&state── 第三方
浏览器 ──GET /auth/<provider>──> 任一平台服务器：按 state 找事务，换取并校验身份，事务转 ready，页面显示确认码
客户端 ──auth_status（每 2 秒）──> 平台：ready（首次登录带 new_account、suggested_name）
客户端 ──auth_finish{transaction_id, code, name?, sign_pub, key_sig}──> 平台：账户会话（首次登录同时建号）
```

1. **`auth_begin{provider, purpose, origin?}`**：`provider` 为 `google` 或 `wechat`（平台没有配置时 `unavailable`）；`purpose` 为 `login`（默认，登录或首次注册）、`bind`（给当前账户绑定，需要账户会话）、`confirm`（没有密码的账户注销前确认，需要账户会话）。`origin` 可选，是控制台自己的回环地址（`http://127.0.0.1:端口`、`localhost`、`[::1]`），平台页面把确认码直接交给打开它的控制台窗口；其他值忽略。应答 `{transaction_id, url, expires}`：`url` 是第三方的授权地址，Google 为 OIDC 授权码流程（`scope = openid profile`，带 `state`、`nonce` 与 PKCE S256），微信为网站应用的扫码登录（`snsapi_login`，带 `state`）。事务默认 10 分钟有效（服务器配置 `login.txn_min`）。频率限制与密码登录共用（`login_per_minute`，按源 IP 与客户端密钥）。
2. **第三方回调**：第三方把浏览器送回 `public_url + "/auth/google"` 或 `"/auth/wechat"`。这个地址可以到达任何一台平台服务器：事务保存在数据库里，按随机的 `state` 查找（`state` 与 `transaction_id` 不同，`transaction_id` 不经过浏览器）。服务器只处理仍在等待、未过期、提供方一致的事务；向第三方换取身份时不持有数据库锁，换完重新读取事务、仍在等待才写入。
   - Google：用授权码、PKCE 校验码和应用秘密在令牌端点换取 ID 令牌，校验 Google 的 RS256 签名（公钥按 `kid` 从 JWKS 取，缓存 6 小时）、签发者、受众（本平台的 `client_id`）、过期时间和本事务的 `nonce`。身份为 `sub`，不用邮箱；名字取 `name`。依据：[Google OIDC 参考](https://developers.google.com/identity/openid-connect/reference)。
   - 微信：用授权码和应用秘密换 `access_token`、`openid` 与 `unionid`，再取昵称（取不到不影响登录）。身份优先用 `unionid`（同一开放平台账号下的网站应用与以后的移动应用相同），存为 `u:<unionid>`；没有 `unionid` 时用 `o:<appid>:<openid>`（应用绑定到开放平台账号之后会有 `unionid`，已有的 `o:` 身份不会自动转换，上线前应先完成绑定）。用户在扫码页拒绝时只带回 `state`，事务转 `denied`。依据：[微信网站应用登录](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)。
   - 成功：事务转 `ready`，生成 8 位数字的**确认码**，事务的有效期从此刻重新计算；页面显示确认码（`1234-5678`），并在有 `origin` 时用 `postMessage` 只发给该回环来源的打开者窗口。失败：事务转 `denied`，页面提示重新开始。页面按 `Accept-Language` 显示中文或英文，禁止缓存、禁止嵌入，脚本只允许本页带随机数的一段。
3. **`auth_status{transaction_id}`** → `{status, provider, purpose}`，`status` 为 `waiting`、`ready`、`denied`、`expired` 或 `consumed`；`purpose = login` 且 `ready`、而该身份还没有账户时，附 `new_account: true` 与第三方给的昵称 `suggested_name`（去掉控制字符，最多 128 字节）。只有发起事务的客户端密钥能查询，其他连接得到 `not_found`。
4. **确认码**：完成事务（`auth_finish`、`login_method_bind`、`account_delete`）都要附浏览器页面上的确认码 `code`（可以带 `-` 与空格）。它证明完成登录的浏览器在用户自己手里：别人发起事务、把授权链接发给受害者，受害者登录后确认码只出现在受害者的浏览器里，发起者拿不到会话。错 5 次事务转 `denied`。控制台收到 `postMessage` 的确认码时自动继续；收不到时（中间的页面切断了打开者关系、命令行）由用户输入。
5. **`auth_finish{transaction_id, code, name?, sign_pub, key_sig}`**：只有发起事务的客户端密钥能完成。身份已有账户时登录；没有账户时是**首次登录自动注册**（R29）：必须带 `name`（客户端的确认页预填 `suggested_name`，用户可以修改；缺少时 `bad_request`，消息为 `name`，事务不消耗），建号并把身份记入账户，邮箱与手机号留空，没有密码。应答与 `account_login` 相同（账户资料加 `cert`），新建账户时另带 `new_account: true`。事务随即转 `consumed`；完成后 2 分钟内（只为应答丢失的情况），同一客户端用同一 `transaction_id` 重发 `auth_finish` 得到同一账户与新签的证书，不会重复建号，之后回 `expired`。同一身份由数据库唯一约束保证只属于一个账户。

`transaction_id` 只是标识：查询和完成都要求同一个客户端密钥（Noise 握手中的静态公钥），完成还要确认码；换了密钥的客户端只能重新发起。第三方应用的秘密只保存在平台（`client_secret_file`、`app_secret_file`），平台不保存第三方的访问令牌。

NPF 登录凭据与 Google、微信的访问令牌分开；不向设备分发第三方令牌。客户端首次绑定到已存在账户时需单独验证双方归属，不按同名或同邮箱自动合并。

## 设备信息如何传输

关联需求：R06、R32 至 R34、R37、R38。本节的"设备"指账户名下的节点，既包括 NAS 设备端，也包括控制台节点（列表中以 `model = console` 区分）。设备信息通过三条逻辑流程流动：设备上报自身信息，平台保存账户与设备的关系，客户端查询和修改有权管理的记录。

```text
设备 ──认证接入与 device_report──> 平台
                                  ↑  ↓
                      device_list / device_get
                      device_update / 绑定与解绑
                                  ↑  ↓
                                客户端

平台 ──devices_changed 通知──> 客户端重新查询
平台 ──设备侧变更同步──> 设备 ──执行结果──> 平台
```

### 设备信息的组成

| 字段 | 含义与修改权 |
|---|---|
| `device_id` | 稳定设备号；平台与设备身份系统管理，用户不可直接修改 |
| `alias` | 当前账户中的设备备注；与设备自己的全局名称分开。账户没有设备注时，控制台节点用注册编号时起的名字（`node_enroll` 的 `name`，2026-10-19） |
| `model`、`firmware` | 认证设备上报的资料，平台校验后保存 |
| `online`、`last_seen` | 平台根据认证连接生成；时间建议为 UTC RFC 3339 字符串 |
| `role` | 当前账户对该设备的角色：`owner`（所有者）或 `visitor`（访问者，经分享获得）（R32） |
| `permissions` | 由角色决定的权限摘要：所有者为 `connect`、`edit_alias`、`share`、`unbind`、`public_map`；访问者为 `connect`、`edit_alias`（备注只属于自己的账户） |
| `revision` | 账户设备关系及可编辑元数据的版本，用于并发更新 |
| `binding_state` | 关联或解绑流程状态，例如 `active`、`pending_device` |

`online` 的变化不必推进可编辑字段的 `revision`，避免设备保活导致备注修改持续冲突。设备策略另有版本；列表展示版本、绑定版本、身份密钥代数不能混用。

普通列表不返回设备私钥、设备访问口令、第三方令牌或无关账户信息。连接所需设备证书和临时授权按专门的呼叫流程提供。平台从认证的设备连接确定上报者身份，不接受请求体替换成其他设备号。

### 查询列表和单个设备

`device_list` 请求使用 `limit`（默认 20，最多 50）和可选 `cursor`，平台从登录上下文确定账户。响应包含 `devices`（按设备号升序）、`complete` 和可选 `next_cursor`。游标对客户端不透明（实现中是上一页最后一个设备号），必须绑定该账户、查询条件和授权范围，后续分页仍重新检查权限。

```json
{
  "v": 1,
  "type": "device_list",
  "reply_to": "req-101",
  "status": "ok",
  "data": {
    "devices": [
      {
        "device_id": "123456789",
        "alias": "家里的 NAS",
        "model": "NAS-A",
        "firmware": "0.1.0",
        "online": true,
        "role": "owner",
        "permissions": ["connect", "edit_alias", "share", "unbind", "public_map"],
        "revision": "rel-7",
        "binding_state": "active"
      }
    ],
    "complete": true
  }
}
```

示例设备号仅为格式示意，不是已分配或已验证校验位的号码。`complete=false` 时必须返回非空 `next_cursor`；`true` 时省略游标。建议平台提供短期一致的分页快照；失效返回 `expired`，客户端清除本轮临时列表并重新查询。快照不能保留已撤销的访问权。

`device_get` 用 `device_id` 获取当前单个记录。平台只返回当前账户有权看到的字段；设备离线不影响读取平台已保存的信息。

### 修改备注

建议 `device_update` 第一版仅修改账户备注。新备注值可以为空表示清除，不接受任意字段合并。

```json
{
  "v": 1,
  "type": "device_update",
  "id": "req-102",
  "data": {
    "device_id": "123456789",
    "expected_revision": "rel-7",
    "operation_key": "op-alias-001",
    "alias": "书房 NAS"
  }
}
```

平台校验当前权限，比较版本后原子更新，返回最新记录和版本。不匹配则返回 `conflict`，客户端重新读取。该操作只更新账户元数据，设备离线也可以完成。

被叫侧设置（口令、授权列表、托管信任开关、目标策略）只能在 NAS 管理界面或控制台上修改（安全设计 D21），协议中没有远程修改这些设置的消息。

### 绑定设备

| 步骤 | 消息或动作 | 检查 |
|---|---|---|
| 1 | 客户端发送 `bind_begin{device_id}` | 已登录、限流、当前关联约束 |
| 2 | 平台返回 `operation_id`（16 字节）、`challenge`（16 字节）、`account_id` 和 `expires` | 平台记录目标账户、设备及绑定版本 |
| 3 | 客户端经端到端通道（隧道控制通道）向设备发 `bind_approve` | 设备确认该会话已通过被叫闸门、本地没有所有者；把目标账户记为待确认 |
| 4 | 设备返回 `{proof, key_gen}`，客户端用 `bind_commit{operation_id, proof, key_gen}` 提交 | 平台验签、检查身份密钥代数、声明中的账户等于请求账户、原子消费挑战（每个挑战只能提交一次） |
| 5 | 平台提交关联，向设备发送 `bind_committed{account_id, operation_id}` | 设备收到后才正式记录所有者；返回 `ok` 或带操作号的 `pending`，可以查询恢复 |

签名证明的内容见安全设计 8.2：协议用途、设备号与密钥代数、目标账户、操作号、挑战、有效期。具体编码另定。目标账户应与平台挑战记录及客户端当前账户一致，设备不能仅凭客户端的声明认定所有者，所以第 3 步只记"待确认"，第 5 步才生效；待确认的记录 10 分钟后自动清除。`bind_approve` 的字段见"隧道内控制消息"。

**谁能绑定**（R37）：配对口令只证明访问资格。设备**没有所有者**时，第一个完成上述流程的账户成为所有者；设备已有所有者时，第 3 步设备拒绝签署（设备在本地记录所有者的 `account_id`），平台也拒绝 `bind_begin`（`conflict`），其他账户只能经分享成为访问者。不允许靠重复绑定夺取已有所有者的设备。

**重置所有者**：设备管理员在 NAS 管理界面重置所有者后，设备清除本地记录，并向平台发送 `owner_reset` 事件（设备离线时上线后发送）。平台据此解除原所有者的绑定及其全部分享，之后可以重新绑定。

平台提交为事务的一步，不声称与设备形成跨网络原子写入。设备记录待确认操作；丢包、重启后通过操作号对账。平台成功、设备未同步时返回待同步状态，禁止误报两端均生效。`operation_get` 用于有权账户查询其操作结果。

### 分享

关联需求：R32。只有所有者能分享，被分享者成为访问者，经托管信任连接设备。

| 类型 | 方向 | 内容 |
|---|---|---|
| `share_create` | 所有者客户端到平台 | `device_id`；返回一次性邀请码 `invite`（设备编号 8 字节大端 + 16 字节随机数，Base64url）与过期时间（24 小时）。平台把邀请码的 SHA-256 随设备一起保存（不保存邀请码本身），所以被分享者经哪台服务器接受都可以；每台设备最多 16 个未接受的邀请码；设备换了所有者后，旧所有者的邀请码作废 |
| `share_accept` | 被分享者客户端到平台 | `invite`；成功后该设备出现在被分享者的设备列表中，`role = visitor` |
| `share_list` | 所有者客户端到平台 | `device_id`；返回访问者列表（昵称、接受时间、`public`：是否允许它建公网映射），不返回其邮箱或手机号 |
| `share_set` | 所有者客户端到平台 | `device_id`、`account_id`、`public`（布尔）：允许或不再允许该访问者在这台设备上建公网映射（security.md 8.4，D24）；不是访问者回 `not_found`，不是所有者回 `forbidden`。改为不允许时，平台删除该访问者在这台设备上的公网映射（释放端口，通知它的连接 `mappings_changed`、托管服务 `hosted_changed`），本地映射不动。访问者被撤销、自己退出，设备解绑或换所有者时，允许一并清除 |
| `share_revoke` | 所有者客户端到平台 | `device_id`、`account_id`；撤销该访问者，效果见"撤销的生效" |
| `share_leave` | 访问者客户端到平台 | `device_id`；访问者自己退出 |

用邀请码而不是按邮箱或手机号查找对方，平台不会泄露某个账户是否存在。邀请码只能被接受一次；所有者可以随时撤销。

### 删除与解绑

关联需求：R33。"删除设备"就是**解绑**：`device_unbind` 携带 `device_id`、`expected_revision` 和 `operation_key`。

- 所有者解绑：解除自己与设备的关系，同时撤销该设备的全部分享和公网映射；之后设备没有所有者，可以重新绑定；
- 访问者"删除设备"等同于 `share_leave`；
- 解绑**不**注销设备身份，也不恢复出厂；用口令配对过的客户端在设备本地的授权列表中，不受影响。

### 撤销的生效

关联需求：R34。数据库中删除记录不等于访问立即失效，撤销分两步：

1. 平台立即停止为被撤销的账户签发 `grant`，该账户之后的托管信任呼叫在服务器闸门处被拒绝；
2. 平台向设备发送请求 `revoke{account_id, before, owner}`。设备记下该账户在 `before`（Unix 秒）之前签发的 `grant` 一律无效（每个账户只保存最近一次的 `before`），并断开经该账户 `grant` 接入的全部会话；`owner` 为真（所有者解绑、账户注销）时设备同时清除本地记录的所有者。设备离线时，`revoke` 保存在平台（中心数据库中的待下发通知），设备下次登录后由它所在的服务器立即下发。设备执行后回应，平台据此把同步状态标为完成。`grant` 本身只有 10 分钟有效期（安全设计 8.2），所以即使通知迟到，新呼叫也很快就会被拒绝。

其他操作的影响：

| 操作 | 影响 |
|---|---|
| 修改账户密码 | 吊销该账户在其他客户端上的客户端证书，并关闭它们的信令连接（跨服务器时经 `kick`，多服务器设计第 5 节），那些客户端需要重新登录；已经建立的数据会话不断开 |
| 修改设备配对口令 | 不影响已经配对的客户端，也不影响托管信任 |
| 设备管理员关闭托管信任 | 设备拒绝所有 `grant`，等同于对所有账户执行 `revoke`；口令配对过的客户端不受影响 |

### 上报和变更同步

- `device_report`：设备认证后上报型号、固件等允许字段；平台限制大小和频率，在线状态由连接状态推导。
- `owner_reset`（设备到平台）与 `revoke`（平台到设备）：见上文的重置所有者与撤销的生效；`bind_committed`（平台到设备）：见"绑定设备"。
- `paired_sync`（节点到平台，事件）：`data = {"fps": ["<8 字节 Base64url>", ...]}`，本地授权列表中全部主叫的公钥指纹 `fp = BLAKE2b(dh_pub)[0..7]`（安全设计 8.3），登录后发一次，本地列表变化时再发完整列表；最多 256 项。平台只用它判断呼叫方是否已配对。
- `lock_report`（节点到平台，事件）：`data = {"locked_until": <Unix 秒，0 表示未锁定>}`，口令失败锁定状态变化时上报，服务器闸门据此直接拒绝未配对主叫的呼叫。
- `devices_changed`：平台向当前仍有权的账户连接发重新查询提示，无需携带敏感详情。撤销关系后可给原账户通用刷新提示，以清除旧列表。
- 客户端初次登录、账户切换、断线重连时重新拉取列表。第一版不依赖事件不丢失，不承诺离线补发。
- 原子提交后发送通知；多客户端编辑依靠 `revision` 解决冲突。UI 区分平台已保存、设备待同步和执行失败。

## 呼叫与端到端连接

关联需求：R02、R03、R21。本节定义一次连接从呼叫到数据通道可用的完整信令：E2E 握手、中转分配、NAT 画像与候选交换、打洞的同步开始与结果上报。数据通道本身见 [数据通道协议](data-channel.md)，打洞报文与策略见 [打洞设计](../design/nat-traversal.md)，握手的密码学见 [安全设计](../design/security.md) 第 9 节。

**主叫**可以是节点（有编号的控制台程序，包括 NAS 设备端）或纯客户端（桌面 GUI、手机 App、匿名客户端）；**被叫**只能是节点（安全设计 8.5）。下文的"平台"指主叫与被叫各自连接的服务器。双方连在不同服务器上时，消息经服务器之间转发，由被叫所在的服务器作为呼叫的属主（分配中转、计算打洞计划）；路由与分工属于平台的多服务器设计，不影响本节的消息格式。

### 总体流程

已配对的主叫（Noise IK），UDP 可用：

```
主叫 A                           平台 P                              被叫 B
 │ call{call_id, 编号, hs=IK 消息1,│
 │      nat, cand} ───────────────►│ 服务器闸门（安全 8.3）
 │◄─── 应答 ok                      │ 记录 call_id，分配双方中转、punch_key
 │                                  │ incoming{call_id, 呼叫方, hs, ──────►│ 被叫闸门：IK 消息1 中的
 │                                  │   A 的 nat/cand, B 的中转}           │ 主叫公钥在授权列表中
 │                                  │◄── 应答{hs=IK 消息2, nat, cand} ─────│ 握手完成（B 侧）
 │◄── call_accepted{hs, B 的 nat/   │                                       │ RELAY_BIND，创建 AnLiu，
 │      cand, A 的中转}              │                                       │ 打开隧道流，发 hello
 │ 握手完成（A 侧）；RELAY_BIND，创建 AnLiu，收到 hello，回 hello → 会话可用（经 UDP 中转）
 │                                  │
 │◄── punch_start{计划, start_at} ──┼── punch_start{计划, start_at} ──────►│
 │ ═══════════ 在 start_at 同时开始打洞（PROBE / NOMINATE）════════════════ │
 │ punch_result ───────────────────►│◄──────────────────────── punch_result │
 │ 成功：AnLiu 切换到 P2P 路径，UDP 中转热备 30 秒后释放
```

- **密钥协商在信令阶段完成**（R21）：IK 的消息 1 放在 `call` 中，消息 2 放在 `incoming` 的应答中，端到端只需 1 个往返；首次配对需要 1.5 个往返（见"握手的承载"）；
- **数据通道立即可用**：握手完成后双方就在 UDP 中转上建立 AnLiu 连接，打洞在后台进行，成功后无缝切换；
- **主叫始终是打洞的控制方**，由它发送 `NOMINATE`；易侧 / 难侧按画像另行决定，两者互不相关。

### 消息目录

| 类型 | 方向 | 形式 | 作用 |
|---|---|---|---|
| `nat_report` | 节点 → 平台 | 事件 | 上报 NAT 画像，平台据此在呼叫时选择中转方式 |
| `grant_get` | 主叫 → 平台 | 请求 | 托管信任：取得被叫的节点证书与 10 分钟有效的 `grant`，用于紧接着的 `call` |
| `call` | 主叫 → 平台 | 请求 | 发起呼叫，携带握手首条消息、画像与候选 |
| `incoming` | 平台 → 被叫 | 请求 | 通知新呼叫；被叫的应答携带握手回复、画像与候选 |
| `call_accepted` | 平台 → 主叫 | 事件 | 被叫已接受：握手回复、被叫的画像与候选、主叫的中转分配 |
| `call_rejected` | 平台 → 主叫 | 事件 | 呼叫失败：被叫拒绝、超时或不可用 |
| `call_cancel` | 主叫 → 平台 | 请求 | 取消尚未接受的呼叫；平台向被叫发 `call_ended` |
| `handshake` | 主叫 ⇄ 被叫，经平台转发 | 事件 | 握手的后续消息（首次配对时使用） |
| `relay_switch` | 任一方 → 平台 → 另一方 | 事件 | UDP 中转不通时双方改用 WS 中转；直连失效且中转已释放时重新分配；主叫连不上中转服务器时改在主叫所在的服务器上重新分配 |
| `relay_release` | 主叫 → 平台 | 事件 | 直连已稳定 30 秒，平台释放两侧的中转分配 |
| `punch_start` | 平台 → 双方 | 事件 | 一轮打洞的计划与同步开始时刻 |
| `punch_request` | 主叫 → 平台 → 被叫 | 请求 | 退避时间到或网络变化后，请求新一轮打洞；被叫的应答提供最新画像与候选 |
| `punch_result` | 双方 → 平台 | 事件 | 本轮打洞的结果与统计，以及这一轮看到的对方 NAT 的行为 |
| `punch_info` | 任一方 → 平台 → 另一方 | 事件 | S2B：本方新 socket 的映射端口（nat-traversal.md 7.6） |
| `call_end` | 任一方 → 平台 | 请求 | 会话结束，平台释放中转，在呼叫记录中写下结束时间 |
| `call_ended` | 平台 → 另一方 | 事件 | 对方结束了会话，或平台终止了会话 |

会话的正常关闭先在数据通道的控制通道上发送 `close`（见"隧道内控制消息"），再各自向平台发送 `call_end`。`call_end` 与 `call_ended` 的 `data = {"call_id", "reason"}`，`reason` 取值：`closed`（正常关闭）、`auth_failed`（口令错误或握手失败）、`timeout`（未在限时内进入 `established`）、`transport_lost`（数据通道断开且无法恢复）、`revoked`（被叫收到 `revoke` 后断开）、`quota`（保留，现在不用：额度用完时中转降速而不中断，见"流量额度"）、`error`。

`call_end` 是请求，发送方在收到应答之前一直保留它：会话结束时信令断开，就在下次登录后再发，并带上 `ago_ms`（会话结束距发送时的毫秒数），平台据此记下结束时间（见"呼叫记录"）。平台已经没有这个呼叫（例如服务器重启过），或者发送方是重连后的新连接时，只要发送方是这个呼叫的主叫或被叫，平台照样结束它的记录；其他人发来的 `call_end` 不起作用。

### 公共字段

| 字段 | 编码 | 说明 |
|---|---|---|
| `call_id` | Base64url，16 字节随机数 | 呼叫标识，**由主叫生成**：握手的 prologue 要绑定它，而握手首条消息随 `call` 一起发出，此时还没有平台的回应。平台只检查它不与现有呼叫重复。随机标识不代替身份验证 |
| 地址 | 字符串，`"1.2.3.4:5678"` 或 `"[2408::1]:5678"` | 候选、中转服务器地址等 |
| 二进制 | Base64url，无填充 | 握手消息、密钥 |
| `start_at` | 整数，Unix 毫秒，**服务器时间** | 被叫和主叫用登录时 `welcome.time` 与 `BIND_RESP` 的 `srv_time_ms` 校准时钟偏差 |

**NAT 画像 `nat`**（对应 `npf_nat_profile`，nat-traversal.md 4.3）：

```json
{"udp": true, "map": "EIM", "alloc": "BLOCK", "delta": 0, "block": [20480, 22527], "filter": "APDF",
 "open": false, "ip_varies": false, "pub_ip": "1.2.3.4", "at": 1791100000}
```

| 字段 | 说明 |
|---|---|
| `udp` | 地址探测是否有回应；`false` 表示 UDP 不通，平台不安排打洞和 UDP 中转 |
| `map` | `EIM` / `ADM` / `APDM` / `UNKNOWN` |
| `alloc` | `PRESERVE` / `SEQUENTIAL` / `BLOCK` / `RANDOM` / `UNKNOWN`；`delta` 为顺序分配的步长，`block` 为端口块区间（`block[0] > block[1]` 表示跨过 65535） |
| `filter` | 过滤行为（nat-traversal.md 4.2）：`EIF`（谁都能发进来）/ `ADF`（发过包的 IP 的任何端口）/ `APDF`（只有发过包的 IP:端口）/ `UNKNOWN`；只有一台探测服务器时测不出 EIF，`ADF` 表示"至少 ADF" |
| `open` | 有公网地址、没有 NAT |
| `ip_varies` | 不同目标看到不同的公网 IP，S3 不适用 |
| `pub_ip` | 探测到的公网 IPv4 |
| `at` | 探测时间（Unix 秒） |

**候选 `cand`**（nat-traversal.md 第 5 节）：数组，最多 16 项，每项 `{"t": 类型, "a": 地址}`，类型为 `host6`、`mapped`、`host4`、`srflx`。全部是打洞 socket（与 AnLiu 共用的那个 UDP socket）上的地址。`pred` 由平台按画像计算，不需要上报。

候选在呼叫前就已经备好：画像和 `srflx` 来自周期性的 NAT 探测，`mapped` 来自启动时建立的 PCP / NAT-PMP 映射，`host4` / `host6` 直接从网卡读取。第一版**不做逐步补充候选**（trickle）：候选有变化时，在下一轮 `punch_request` 中携带新的候选。

**中转分配 `relay`**（data-channel.md 9.1）：

```json
{"mode": "udp", "relay_id": "...", "alloc_key": "...",
 "udp": ["203.0.113.5:443", "[2001:db8::5]:443"],
 "ws": {"url": "wss://r1.example.com/r", "server_id": 17}, "expires": 1791103600}
```

`mode` 是平台为本次会话选定的中转方式（`udp` 或 `ws`），双方相同。匿名客户端的会话没有 `relay`（安全 D6）。

### `nat_report`

节点在登录后、画像变化时、以及每 30 分钟的周期探测后上报：`data = {"nat": {...}}`。平台只保存最新的一份，用于在 `incoming` 之前确定中转方式；打洞计划使用被叫在 `incoming` 应答中提供的最新画像。连接方式改变时（`connect_mode`，见下）也立即上报。

**连接方式 `connect_mode`**（2026-10-15）：节点的设置，`p2p`（默认，P2P 直连优先）或 `secure`（安全优先）。`secure` 的节点在 `nat`（`call`、`incoming` 应答、`nat_report`、`punch_request` 的应答里都一样）中只写 `{"udp": bool, "secure": true}`，没有映射类型、公网地址等，`cand` 为空数组，所以对方得不到它的任何地址。平台据此判定：主叫或被叫任一方是 `secure`，这个会话就是安全会话——

- 主叫必须是有付费套餐（订阅级别 > 0）的账户（托管客户端除外：它自己承担转发）；否则立即回 `call_rejected`，`error = "secure_plan"`；账户本月额度用完时回 `quota`；
- `incoming` 与 `call_accepted` 带 `"secure": true`，其中对方的 `nat` 只剩 `udp` 与 `secure`、`cand` 为空；
- 不发 `punch_start`，忽略 `punch_request`：会话全程走中转（UDP 中转，不通时 WebSocket 中转），双方也都不再要求打洞；
- `p2p` 的节点打开的 UDP 套接字绕过 VPN（Android 绑到 VPN 底下的网络，桌面与 iOS 绑到物理网卡），信令的 TCP 连接也一样（2026-10-20；一次没能登录，下一次改走默认路由，交替直到登录上），`secure` 时都不绕过。
- 信令连接的看门狗（2026-10-20）：每次 ping 之后 10 秒内要有服务器的消息（pong 或别的），发出请求后 10 秒内没有任何消息就先发 ping 问，再 10 秒没有回音就断开重连；本方呼叫超时也先问一次。原来只在连续三个 ping 间隔（默认 75 秒）没有消息时断开，系统睡醒后 VPN 卡住的一分多钟里被叫收不到呼叫。

### `call`

请求：

```json
{"v": 1, "type": "call", "id": "c1", "data": {
  "call_id": "<主叫生成>",
  "callee": "123456789",
  "auth": "ik",
  "hs": "<Noise 握手首条消息>",
  "cpace": "<CPace 主叫消息，32 字节，auth = pake 时>",
  "grant": "<托管信任的访问授权，auth = grant 时>",
  "nat": {...}, "cand": [...]
}}
```

| `auth` | 含义 | `hs` 的内容 |
|---|---|---|
| `ik` | 已配对，日常连接（安全 9.4） | Noise IK 消息 1 |
| `grant` | 托管信任（安全 8.2）：主叫先用 `grant_get{callee}` 取得被叫证书（type 3）与 `grant`，用证书中的 `dh_pub` 跑 IK，`call` 中出示 `grant` | Noise IK 消息 1 |
| `pake` | 首次口令配对（安全 9.3） | Noise XXpsk3 消息 1；CPace 的主叫消息放在 `cpace` 字段 |

`grant_get`：`data = {"callee": "123456789"}`，应答 `{"cert": "<中间证书 | 被叫的节点证书>", "grant": "<grant，二进制格式见安全设计 8.2>", "expires": ...}`；主叫用根公钥验证证书链、检查证书的编号就是被叫，再用证书中的 `dh_pub` 跑 IK；主叫无权访问该节点（不是所有者或访问者）、被叫不存在时一律 `unavailable`。主叫不长期保存 `grant`，每次呼叫前重新取得；`grant` 绑定主叫连接的静态公钥，换了密钥就要重新取得。

平台执行服务器闸门（安全 8.3）：限流、匿名客户端的配对次数、被叫锁定状态；`auth = grant` 时还验证 `grant` 是平台自己签发、未过期、绑定本连接的公钥与 `callee`。通过后立即应答 `ok`，呼叫的结果以 `call_accepted` 或 `call_rejected` 事件送达。

失败的应答：`rate_limited`（超出限流或匿名配对次数）、`unavailable`（被叫不存在、无权访问或离线）、`conflict`（`call_id` 重复，主叫换一个重新生成握手消息）。对没有配对过的主叫，这三种情况一律返回 `unavailable`，不泄露被叫是否存在（安全第 6 节）；已配对的主叫可以收到 `offline`。

### `incoming`

平台 → 被叫的请求：

```json
{"v": 1, "type": "incoming", "id": "p7", "data": {
  "call_id": "...",
  "caller": {"kind": "node", "id": "...", "account_id": "...", "anonymous": false, "paired_by_server": true,
             "app": {"name": "npf", "ver": "0.1.0"}, "hosted": false},
  "auth": "ik", "hs": "...", "grant": "...",
  "nat": {...}, "cand": [...],
  "relay": {...}
}}
```

- `caller` 是平台从认证连接得到的呼叫方信息，只用于展示和日志：`kind` 为 `node`（`id` 是主叫节点的编号）或 `client`（`id` 是 `client_id`）；`app` 是主叫登录时报的程序；`hosted` 表示主叫是平台公网映射的托管客户端（被叫的会话列表显示为"platform public mapping"，判断以 `grant` 的种类为准）。**被叫是否接纳只看握手**：IK 消息 1 中的主叫静态公钥在本地授权列表中、`grant` 有效，或口令配对成功（安全 8.3 的被叫闸门）；
- 被叫收到后立即 `RELAY_BIND`（`relay.mode = udp` 时）或建立 WS 中转连接，与握手并行进行。

被叫的应答（20 秒内，否则平台按超时处理；被叫收到后立即应答，但它到平台的路径短暂卡住时应答会晚到，2026-10-15 的 10 小时测试中见过 10.9 秒、13.5 秒，20 秒内到达的照样接通）：

```json
{"v": 1, "type": "incoming", "reply_to": "p7", "status": "ok",
 "data": {"hs": "<IK 消息 2 或 XXpsk3 消息 2>", "cpace": "<CPace 被叫消息，pake 时>", "nat": {...}, "cand": [...]}}
```

拒绝时 `status = "error"`，`error` 为 `unauthorized`（主叫不在授权列表中、`grant` 无效）、`locked`（口令配对处于锁定期）或 `busy`（并发会话已满，默认 32 个，可在本地调整；节点之间是多对多连接）。被叫不做任何其他会暴露状态的回应。

### `call_accepted` / `call_rejected`

```json
{"v": 1, "type": "call_accepted", "data": {
  "call_id": "...", "hs": "...", "nat": {...}, "cand": [...], "relay": {...}}}
```

`call_rejected`：`data = {"call_id", "error"}`，`error` 取值为被叫给出的 `unauthorized`、`locked`、`busy`，或平台给出的 `timeout`、`unavailable`、`no_path`、`quota`、`secure_plan`（安全会话而主叫没有付费套餐，见 `nat_report` 下的连接方式）。匿名主叫没有中转（D6），双方都能用 UDP 才可能打通：主叫自己 UDP 不可用时平台立即回 `no_path`；只有被叫不可用时回 `unavailable`（不向未配对的主叫透露号码存在）。主叫收到 `unauthorized` 后可以改用口令配对重新呼叫。

### 握手的承载

| 方式 | 消息流 | 往返 |
|---|---|---|
| `ik` / `grant` | `call` 带 IK 消息 1 → `incoming` 应答带 IK 消息 2 | 1 |
| `pake` | `call` 带 CPace 消息 a + XXpsk3 消息 1 → `incoming` 应答带 CPace 消息 b + XXpsk3 消息 2 → `handshake` 带 XXpsk3 消息 3 | 1.5 |

- CPace 只需一轮：被叫收到消息 a 时就能算出共享密钥 K，主叫收到消息 b 时算出 K；XXpsk3 直到消息 3 才混入 K，因此 CPace 与 XX 的前两条消息可以合并发送；
- `handshake`：`data = {"call_id", "step", "msg"}`，`step` 从 3 开始。口令错误时被叫解不开消息 3，向平台发送 `call_end{reason: "auth_failed"}` 并计入口令失败次数（安全 8.3）；
- **密钥确认与重放**：IK 中，主叫收到消息 2 即确认了被叫；被叫则无法确认消息 1 不是录下来重放的，因此**被叫在数据通道上收到主叫的 `hello` 之前，只发送自己的 `hello`，不执行任何有副作用的操作**。XXpsk3 中，消息 3 由主叫发出，主叫收到被叫能通过认证的 `hello`，才说明口令正确、握手在两端都成功了；
- 握手消息每条不超过 512 字节、每个会话最多 8 条（安全第 10 节，匿名客户端的限制对所有主叫适用）；
- 握手的 prologue 绑定 `call_id` 与编号（安全 9.4），录下的握手消息无法挪到其他呼叫中使用；
- 握手完成后两端派生 `anl_psk`、`conv`、`nominate_key`、`k_ws`（data-channel.md 第 2 节）。

### 中转方式的选择

- 平台在呼叫时决定 `relay.mode`：主叫 `call` 中的 `nat.udp` 与被叫最近一次 `nat_report` 中的 `nat.udp` **都为 `true`** 时用 `udp`，否则用 `ws`。UDP 中转与 WS 中转不能混用：WS 中转不跑 AnLiu，服务器无法在两种承载之间转换；
- **运行中回退**：一方的 `RELAY_BIND` 重传 3 次（约 2 秒）仍无回应，就发送 `relay_switch{call_id, mode: "ws"}`，平台转给另一方，双方都改用 WS 中转。已经在 UDP 中转上建立的 AnLiu 连接随之废弃，打洞仍可继续，成功后按 data-channel.md 第 3 节处理；
- **直连后释放、失效后重新分配**：直连成功 30 秒后主叫发送 `relay_release{call_id}`，平台释放两侧分配；直连之后失效时，任一方发送 `relay_switch{call_id, mode: "udp"}`，平台按会话原来的中转方式重新分配并向双方发送 `relay_switch{call_id, relay}`；分配仍在时原样再发一次（双方可能同时请求）；
- **主叫连不上中转服务器**：主叫经 UDP 和 WS 都连不上被叫所在服务器上的中转时，发送 `relay_switch{call_id, unreachable: true}`。平台改在主叫所在的服务器上为双方重新分配，再向双方发送 `relay_switch{call_id, relay: {...}}`，`relay` 的格式与 `incoming` 中相同；双方按新的分配重新建立中转。两台是同一台服务器（或中转已经在主叫所在的服务器上）时，改在网状互联中的其他服务器上分配，按编号依次试，第一台分到的为准；没有其他服务器时才放弃；
- `mode = ws` 时平台不发送 `punch_start`：UDP 不通，打洞没有意义。

### `punch_start`

平台拿到双方的画像和候选后（即被叫应答 `incoming` 之后）计算计划，分别发给双方。字段与 `npf_punch_plan` 对应：

```json
{"v": 1, "type": "punch_start", "data": {
  "call_id": "...", "round": 1,
  "punch_id": "<8 字节，PROBE 中的 session_id>",
  "punch_key": "...",
  "role": "controlling", "strategy": "S3", "side": "easy",
  "peer": {"cand": [...], "pub_ip": "198.51.100.7"},
  "range": [20480, 22527], "m_total": 1024, "pps": 200,
  "n_sockets": 0,
  "delta": 1, "peer_delta": 2, "window": 32, "passes": 4,
  "timeout_ms": 8000, "start_at": 1791100000300
}}
```

| 字段 | 说明 |
|---|---|
| `round` | 本次呼叫的第几轮打洞，迟到的旧轮次消息直接忽略 |
| `punch_id`、`punch_key` | 每轮新生成（nat-traversal.md 6.5） |
| `role` | 主叫为 `controlling`，被叫为 `controlled` |
| `strategy` | `S0`（IPv6）、`S1`、`S2`、`S3`、`S4`、`S2B`、`S5`（nat-traversal.md 7.1）|
| `side` | `easy` / `hard`，只对 S2、S3、S4 有意义；S4 的 `easy` 是喷包的一方（它自己也是难侧），`hard` 是开新 socket 接收的一方 |
| `peer.cand` | 对方的候选（含平台按画像算出的 `pred`） |
| `peer.pub_ip` | S3 易侧喷包的目标 IP |
| `range`、`m_total`、`pps` | S3 / S4 喷包一方的喷包范围、总数、速率；`range` 为空表示整个端口空间，`range[0] > range[1]` 表示跨过 65535；S5 双方各自的喷包范围（对方的端口块）与速率 |
| `n_sockets` | S3 / S4 开新 socket 的一方新建的 socket 数 |
| `delta`、`peer_delta`、`window`、`passes` | S2B：本方与对方 NAT 的分配步长，每遍的探测数与遍数 |
| `start_at` | 开始发包的时刻（服务器时间）。平台取"当前时间 + 两侧单向时延的较大值 + 150 ms 余量"；单向时延取实测往返时延的一半：平台每 30 秒（登录后 1 秒先测一次）向每条连接发 WebSocket ping，服务器之间同样测量，主叫在另一台服务器上时还要加上 SA 测得的主叫往返时延（`call` 帧的 `caller_rtt_ms`）与 SA–SB 的往返时延；未知时按 150 ms 计。S3 难侧比易侧早 100 ms 开始 |

用绝对时刻而不是延迟，是因为双方可能连在不同的服务器上，两台服务器各自只知道自己与一侧之间的 RTT。服务器之间用 NTP 同步，被叫和主叫的时钟偏差已经校准，误差在几十毫秒以内，满足同步要求。

平台按 nat-traversal.md 7.1 的决策表选择策略。双方都是难侧、双方的过滤行为都测出来了、又没有能用的策略时（例如两侧都是 APDM + APDF + 随机端口），平台在双方的 `punch_start` 里写 `"skip": "no_strategy"`：双方都不打洞，主叫也不再为这个会话要求打洞（网络变化重新测出 NAT 后照常 `punch_request`），会话一直走中转。不认识这个字段的旧节点照常打一轮 S1。过滤行为未知（旧节点）时照旧给 S1。

S2B 的双方在 `start_at` 各自用一个新 socket 向探测服务器 E1 测出它的映射端口，经平台把端口告诉对方：

```json
{"v": 1, "type": "punch_info", "data": {"call_id": "...", "round": 1, "port": 20517}}
```

平台把它原样转给另一方（对方连在另一台服务器上时经服务器之间的连接）。收到对方的端口后开始发送（nat-traversal.md 7.6）。

一方还没有候选（刚启动、NAT 还没测完，被叫应答 `incoming` 时 `cand` 为空）、这一轮没有可探测的目标时（S1 要双方都有候选；S3 只要易侧有候选，易侧向难侧的公网 IP 喷包），平台在双方的 `punch_start` 里加 `"skip": "no_candidates"`（S1 计划照旧附上，供不认识这个字段的旧节点照常打一轮）：双方都不打洞，主叫 2 秒后发 `punch_request`（被叫的应答带上它最新的候选）。这样的一轮不计入 10 次，连续 5 次之后按失败的一轮计、照常退避。以前这一轮会空跑 8 秒，再等 10 秒退避，刚启动的节点要约 19 秒才打通。

### `punch_result` 与重试

```json
{"v": 1, "type": "punch_result", "data": {
  "call_id": "...", "round": 1, "ok": true,
  "path": {"t": "srflx", "local": "192.168.1.2:40000", "peer": "198.51.100.7:51234", "family": 4},
  "elapsed_ms": 1840, "probes_sent": 612, "probes_recv": 3, "rtt_ms": 23,
  "seen": [40112, 40377], "unsolicited": 2}}
```

- 双方各自上报，平台用于统计各种画像组合下各个策略的成功率（nat-traversal.md 目标 5）；
- `seen`：这一轮收到的对方探测的源端口（最多 16 个），即对方 NAT 朝本方分配的映射；`unsolicited`：其中来自本方从没发过包的端口的个数，说明本方的过滤放行同一 IP 的其他端口。平台据此修正这个会话之后几轮的计划，并在内存里记住一天，用于同样两个公网地址之间的下一次呼叫（nat-traversal.md 7.8）；
- 打洞失败后，会话留在中转上。留在 **UDP 中转**上的会话，主叫按 10 秒、30 秒、1 分钟、2 分钟，之后每 3 分钟（最长间隔 3 分钟）退避，或者在网络变化后，发送 `punch_request{call_id, nat, cand}`；一个会话连第一轮最多打洞 10 次，之后一直留在中转上。网络变化（网卡地址变了、进程挂起后恢复）时，主叫在重新测出 NAT 后对 UDP 中转上的会话立即再打一轮（同样计入 10 次，之后的退避从 10 秒重新开始）。`punch_request` 发出后 30 秒没有等来新一轮的 `punch_start`（平台或被叫没有应答），按这一轮失败计，继续退避。**WebSocket 中转**上的会话不再打洞：它切不到之后找到的直连上，平台向被叫取最新的画像和候选（同样经 `punch_request` 转给被叫，被叫应答新的 `nat` 与 `cand`），再开始新一轮 `punch_start`；
- 直连失效、切回中转（nat-traversal.md 10.3）后，同样由主叫发起 `punch_request`。

### 状态

```
calling ──call_accepted──► connecting ──数据通道 hello──► established ──close / call_end──► closed
   │                          │
   └── call_rejected / call_cancel / 超时 ──────────────────────────────────────────────► closed
```

- `connecting`：握手进行中，中转正在建立；
- `established`：双方在数据通道上交换了 `hello`，可以打开子链路。打洞在 `established` 前后都可能进行，不影响状态；
- 超时：被叫 20 秒内未应答 `incoming`，或接受后 25 秒内没有进入 `established`，视为失败，双方发送 `call_end`。这 25 秒主叫从收到 `call_accepted` 起算、被叫从收到第一个 `punch_start` 起算（都表示平台已收到接受），所以晚到的接受也有完整的时间建立会话（包括退到 WebSocket 中转）；在这之前主叫最多等 25 秒；
- 信令连接断开不影响已经建立的数据通道：中转分配不依赖信令连接，只按空闲时间回收；P2P 路径也不受影响。信令断开期间无法重新打洞，撤销仍然有效：`revoke` 由被叫所在的服务器下发给被叫，被叫断开相应会话，与主叫的信令是否在线无关。

### 平台侧的资源

| 资源 | 何时分配 | 何时释放 |
|---|---|---|
| `call_id` 记录 | `call` 通过服务器闸门 | `call_end` 后保留 10 分钟（过滤迟到的消息） |
| 中转分配 | 生成 `incoming` 时同时为双方分配 | `call_end`；或空闲超过回收时间（data-channel.md 第 11 节） |
| 呼叫记录 | 呼叫到达被叫所在的服务器 | 保存 1 年（下一节） |

### 呼叫记录

平台为每个到达被叫所在服务器的呼叫写一条记录，用于运维和计费，存放在中心数据库，`npf-admin calls` 查询：

| 内容 | 来源 |
|---|---|
| 发起时间 `start` | 呼叫到达被叫所在的服务器（呼叫的属主）的时间 |
| 接受时间 `accepted`、结果 `result` | `incoming` 的应答：`accepted`，或 `call_rejected` 的错误码 |
| 结束时间 `end`、原因 `end_reason`、结束方 `ended_by` | 第一个 `call_end`（`caller` / `callee`），按 `ago_ms` 往前推，早于发起时间时取发起时间；平台终止的为 `server`（被叫未应答、没有路径） |
| 双方的身份、所在服务器、源地址 | 各自的信令连接：节点编号或客户端 ID，主叫的计费账户，服务器编号，服务器看到的源 IP:端口。主叫连在另一台服务器上时，由那台服务器随呼叫转交 |
| 双方的 NAT 类型 | `call` 与 `incoming` 应答中的 `nat` 和候选：UDP 是否可用，映射方式 `map`，端口分配 `alloc`，过滤行为 `filter`，端口块的大小 `block`，是否公网，公网 IP，是否有全局 IPv6 地址，是否在路由器上映射了端口（PCP / NAT-PMP） |
| 直连 `p2p`、`p2p_at`、`rounds` | `punch_result`：一方打通时报告的对端地址就是对方在直连路径上的地址；首次打通的时间；打洞轮数 |
| 各轮的策略 `plans`、打通那一轮的 `p2p_plan` | 每一轮 `punch_start` 的策略（`S1` … `S5`，不打的一轮为 `skip:原因`） |
| 中转分配 `relays` | 每次分配的方式（`udp` / `ws`）、所在服务器、时间 |
| 双方的程序 `app` | 各自登录时报的 `app`（名称与版本） |
| 中转流量 `usage` | 中转服务器转发的字节数：`up`（主叫发出的）、`down`（被叫发出的），以及其中计费的 `billed_up` / `billed_down`。**呼叫发起后的前 15 秒不计费**（服务器配置 `relay_free_s`），字节数照常记录 |
| 公网映射流量 `public_up` / `public_down` | 主叫是托管客户端时，它经公网映射转发的字节数（`usage_report`，见"托管服务"）：**全部计费，没有免费的前 15 秒**，同时加到 `billed_up` / `billed_down`。这种呼叫的中转字节只记录、不计费（已经按公网映射计了一次） |

- 中转在哪台服务器上，就由哪台服务器把字节数加到这条记录上：默认是被叫所在的服务器，回退到主叫所在的服务器时是那一台。每 30 秒写一次，释放分配时立即写；数据库暂时不可用时留到下一次；
- 信令断开期间结束的会话，`call_end` 在下次登录后补发（见上文），记录的结束时间仍是会话真正结束的时间；
- 双方都没能发出 `call_end` 就消失的呼叫（例如同时断电），记录没有结束时间。
| `punch_key` | 每轮 `punch_start` | 本轮超时后作废 |

## 子链路

关联需求：R04、R15 至 R19。子链路、隧道流和中转的二进制协议见 [数据通道协议](data-channel.md)，要点：

- 子链路在数据通道中复用：数据消息为 `sublink_id(4) | payload`（空负载为 `FIN`），`WINDOW` 与 `RESET` 走控制通道；
- 每条子链路的字节流就是一个标准的 SOCKS5 会话，第一版只支持 `CONNECT`；
- 隧道有控制通道（AnLiu 默认流，严格优先）和数据通道（双方各一条消息模式的流）；控制通道承载本协议格式的 JSON 消息（`hello`、`close` 等）以及 `WINDOW`、`RESET`；
- 中转分为 UDP 中转与独立连接的 WS 中转，WS 中转上的子链路帧另加端到端加密。呼叫时下发的中转分配字段见数据通道协议 9.1。

## 隧道内控制消息

隧道控制通道上的 JSON 消息（数据通道协议第 8 节），`hello` 与反向映射的消息在数据通道协议中定义，其余在此定义。这些消息经端到端加密，平台看不到。

| 类型 | 方向 | 形式 | `data` |
|---|---|---|---|
| `close` | 任一方 → 另一方 | 事件 | `reason`，取值同 `call_end`。发送方不再打开子链路，发出后等待最多 2 秒让在途的 `FIN` 送达，然后复位剩余子链路、关闭传输，再向平台发送 `call_end` |
| `bind_approve` | 主叫 → 被叫 | 请求 | `operation_id`、`account_id`、`challenge`（Base64url）、`expires`。被叫检查：本地没有所有者、本会话的主叫已通过被叫闸门；通过后把 `account_id` 记为待确认的所有者，应答 `{"proof": "<Base64url>", "key_gen"}`（安全设计 8.2）；已有所有者时 `conflict`，节点管理员关闭了绑定时 `forbidden` |
| `grant_update` | 主叫（托管客户端）→ 被叫 | 请求 | `grant`：平台为同一主叫公钥新签发的托管 `grant`（安全设计 8.4）。被叫验证签名、公钥、未过期且 `issued` 比当前的新，通过后替换目标列表，应答 `{}`；失败 `forbidden`，当前列表不变 |

被叫对 `bind_approve` 的待确认记录在 10 分钟后、或会话结束时清除；正式记录所有者由平台的 `bind_committed` 触发。

## 端口映射配置

关联需求：R07、R35。映射分两种：

| `kind` | 监听在哪 | 谁执行 | 谁能访问 |
|---|---|---|---|
| `local` | 用户的客户端上，默认回环地址 | 指定的客户端 | 该客户端所在机器上的程序 |
| `public` | 平台边缘服务器的公网端口（frp 方式，只有 `-L` 方向：不提供 SOCKS5，也不提供反向映射） | 托管服务上该账户的托管客户端（安全设计 8.4，见下一节） | 互联网上的任何人（可选来源 IP 白名单） |

| 字段 | 含义 |
|---|---|
| `mapping_id` | 平台分配的映射标识 |
| `kind` | `local` 或 `public` |
| `device_id` | 目标设备，创建与修改时检查账户权限；`public` 只有所有者与它允许的访问者（`share_set`）能创建和修改 |
| `executor` | 执行映射的一方：`{"kind": "client" 或 "node", "id"}`。`local`：用户指定自己账户的一个客户端或控制台节点；`public`：由平台填写 `{"kind": "hosted", "id": 托管服务的编号}`，请求中带 `executor` 回 `bad_request` |
| `protocol` | 第一版只有 `tcp`（R19） |
| `scheme` | 可选，目标服务说的协议：`http` 或 `https`（网页），客户端据此把入口显示成可以在浏览器中打开的链接；空或省略为不知道。其他值回 `bad_request` |
| `listen_host`、`listen_port` | `local`：客户端的监听地址和端口，默认 `127.0.0.1`；`public`：`listen_host` 为 `0.0.0.0`，`listen_port` 由平台从托管服务的端口范围中分配；**套餐允许自选端口**（`choose_port`，见"流量额度"）的账户可以在创建或修改时指定 `listen_port`，须在托管服务登记的 `vip_ports` 或 `ports` 范围内且未被占用（占用回 `conflict`），其他账户指定回 `forbidden` |
| `public_addr` | `public` 的公网入口 `host:port`，只读（托管服务登记的 `public_host`） |
| `allow_from` | `public` 的来源 IP 白名单（CIDR 或地址的数组，最多 16 项），空表示不限制；不在其中的连接由托管客户端直接关闭 |
| `rate_kbps` | `public` 的速率上限（KB/s，每个方向），只读，取自账户套餐的 `public_kbps`，0 为不限 |
| `target_host`、`target_port` | 设备侧目标地址和端口 |
| `enabled` | 期望启用状态 |
| `revision` | 配置修改版本 |

消息目录为 `mapping_list`、`mapping_create`、`mapping_update`、`mapping_delete` 和 `mapping_report`。写操作使用独立 `operation_key`，修改和删除检查版本；列表分页复用设备列表规则。执行状态通过 `mapping_report` 上报，只允许指定执行者报告自己的配置。

创建与修改失败时，应答的 `message` 给出原因（客户端据此向用户说明，判断仍以 `error` 为准）：`no_hosted`（`unavailable`：没有在线且还有空位的托管服务）、`plan_limit`（`forbidden`：套餐的公网映射数已满，免费级为 0）、`not_publisher`（`forbidden`：不是设备的所有者，也不是被允许发布公网映射的访问者）、`choose_port`（`forbidden`：套餐不能自选端口）、`port_range`（`bad_request`：端口不在托管服务的范围内）、`port_taken`（`conflict`：端口已被占用）、`mapping_limit`（`forbidden`：映射总数已满）、`device`（`not_found`：账户没有这台设备）。

- **`local`**：平台保存配置后通知指定的执行者拉取并应用（`mapping_list` 带 `executor` 过滤）；重连时执行者重新拉取。平台保存成功不等于端口监听成功，端口占用、设备离线等运行问题要单独显示；
- **`public`**：创建时客户端必须明确提示"服务将暴露在公网，任何人都能访问，平台能看到经过的数据"，用户确认后才提交。只有设备的所有者能创建（访问者回 `forbidden`）。平台选一个在线、有空闲端口、还能接纳账户的托管服务（依次优先：该账户已经在用的、设备所在服务器上的、账户最少的；都没有回 `unavailable`），分配端口，通知托管服务（`hosted_changed`），由它启动或更新该账户的托管客户端；托管客户端按映射监听，连接设备时出示带目标列表的托管 `grant`，映射变化后在会话中用 `grant_update` 换上新列表；开始监听后用 `mapping_report` 上报 `listening`。设备端不另设开关（安全设计 D23），是否暴露到公网由所有者在这一步决定；设备关闭了托管信任时，托管客户端连接设备失败。修改只能改目标、启用状态、`allow_from`（套餐允许时还可改端口），不能换设备；删除、所有者失去设备时端口回到托管服务；
- 平台在映射写入后向账户的连接和映射的执行者（无论连在哪台服务器）发 `mappings_changed` 事件（无数据）；执行者登录时和收到事件时用 `mapping_list{executor}` 拉取并应用。`mapping_report` 的 `data`：`mapping_id`、`revision`（报告针对的版本）、`state`（`listening`、`stopped`、`error`）、`error`（`state = error` 时的原因，最长 64 字节）；平台在映射的 `status` 中返回最近一次报告（`state`、`error`、`at`、`revision`）。账户失去对设备的访问权（解绑、撤销分享、注销账户）时，该账户指向这台设备的映射一并删除；
- 每次实际连接创建一条新子链路，并再次经过设备的目标授权；`public` 映射的目标还必须在托管客户端的 `grant` 目标列表中；
- 每个账户最多 50 个 `local` 映射；`public` 映射的个数与速率由套餐决定（免费级没有），超过回 `forbidden`；流量计入所有者账户（安全设计 8.4）。

目标地址以明文 JSON 保存在平台，平台知道内网地址和端口，这属于配置元数据的可见范围。`public` 映射的数据本身也对平台可见（安全设计 8.4）。

## 托管服务

公网映射由托管服务执行（安全设计 8.4）：边缘服务器上的 `npf-hosted` 程序，与 `npf-server` 部署在同一台有公网地址的机器上。它先以自己的身份登记，再为每个有公网映射的账户运行一个托管客户端。

| 类型 | 方向 | 形式 | 作用 |
|---|---|---|---|
| `login{role: "hosted"}` | 托管服务 → 平台 | 请求 | 托管服务的握手公钥必须列在该服务器配置的 `hosted_keys` 中（`npf-hosted key` 打印），否则 `unauthenticated` |
| `hosted_register` | 托管服务 → 平台 | 请求 | 登记自身：`name`、`public_host`（公网入口的地址）、`ports`（平台分配的端口范围 `{lo, hi}`）、`vip_ports`（套餐允许自选端口的账户可选的范围，缺省同 `ports`）、`max_accounts`（0 为不限）。平台写进中心数据库（`npf-admin hosted` 查看），记下它所在的服务器并标为在线；连接断开时标为离线。应答 `{"service_id", "accounts": N}`：在它上面有公网映射的账户数 |
| `hosted_accounts` | 托管服务 → 平台 | 请求 | `{"after", "limit"}`：登记之后分页取在它上面有公网映射的账户，按编号排序，`after` 之后最多 `limit`（≤ 200）个；应答 `{"accounts": [{"account_id", "mappings"}], "next"}`，`next` 非空时以它为 `after` 继续 |
| `hosted_stats` | 托管服务 → 平台 | 请求 | 每分钟一次（`report_s`）报告自身与主机：`uptime_s`、`accounts`（托管客户端数）、`logged_in`、`sessions`、`open_conns`、`conns`、`bytes_in`、`bytes_out`、`refused`、`refused_by`、`rss`（进程常驻内存，字节）、`cpu`（上一个间隔的进程 CPU，占一个核的百分比）、`cpus`、`load1`、`mem_total`、`mem_avail`（主机内存，字节），以及生效中的 `max_conns`、`ip_conns`、`ip_rate`、`log_level`；平台记下供管理界面显示。应答 `{"settings": {...}}`：平台为它设的参数（`max_conns`、`ip_conns`、`ip_rate`、`log_level`，没给的按它自己的 `hosted.conf`），托管服务立即应用到所有托管客户端与以后启动的；`hosted_register` 的应答也带 `settings`。暂停分配新账户与账户数上限由平台自己执行（选择托管服务时） |
| `hosted_changed` | 平台 → 托管服务 | 事件 | `{"account_id", "mappings"}`：该账户在它上面的公网映射变了，`mappings` 为现在的个数，0 表示托管客户端可以停止。无论映射在哪台服务器上修改，都送到托管服务所在的服务器 |
| `hosted_token` | 托管服务 → 平台 | 请求 | `{"account_id"}` → `{"token", "expires"}`：为该账户的托管客户端换证书用的一次性令牌，5 分钟有效；该账户在它上面没有公网映射时 `not_found` |
| `hosted_login` | 托管客户端 → 平台 | 请求 | 托管客户端先匿名登录，再带 `token` 和密钥证明（`sign_pub`、`key_sig`，同 `account_login`）发送；平台为它的密钥签发绑定该账户、标记 `hosted` 的客户端证书，这条连接取得账户会话。应答同 `account_login`：`{"account_id", "cert"}`。之后它用这张证书直接登录 |
| `quota` | 托管客户端 → 平台 | 请求 | `{"want"}` → `{"granted", "state", "slow_kbps", "public_kbps", "level"}`：从账户本月额度中取一段字节给它的公网映射（每次最多 4 MB），见"流量额度" |
| `usage_report` | 托管客户端 → 平台 | 事件或请求 | `{"call_id", "up", "down"}`：自上次报告以来该会话的公网映射在**公网端口上**收（`up`）、发（`down`）的字节数（访问者实际传过的数据，不含隧道开销；降速与排空阶段的也算），每 30 秒一次，会话结束时一次；只接受托管客户端为自己发起的呼叫报告，计入呼叫记录的 `public_up` / `public_down`，全部计费 |
| `public_moved` | 平台 → 账户的连接 | 事件 | `{"mapping_id", "public_host", "listen_port", "from_host", "from_port", "reason": "service_offline"}`：托管服务离线超过 `hosted_failover_s`（默认 600 秒）后，它的公网映射迁到另一个在线的托管服务（`pickHosted` 的规则；原端口号在新服务的范围内且空闲时保留，否则另分配），映射的 `revision` 加一、状态清空；发给执行迁移的服务器上该账户的连接，随后是 `mappings_changed`；新服务收到 `hosted_changed`。没有可用的服务时映射留在原处，等原服务回来。原服务重新登记时，不再属于它的账户的托管客户端停止 |
| `pubconn_list` | 客户端 → 平台 | 请求 | `{"mapping_id"?, "before"?, "limit"?}`：本账户的公网访问记录（`conn_report` 记下的，每次访问一条），新的在前，每页至多 60 条（默认 50）；应答 `{"conns": [{"id", "mapping_id", "port", "from", "start", "end", "conns", "refused", "in", "out", "connect_ms", "connect_avg", "first_byte_ms", "first_byte_avg", "path", "result"}], "next"}`，`next` 是下一页的 `before`，到头为空。命令行 `npf mapping log`，控制台"我的 → 公网映射"的「访问记录」 |
| `conn_report` | 托管客户端 → 平台 | 事件或请求 | `{"conns": [{"mapping_id", "port", "from", "start", "end", "conns", "refused", "in", "out", "connect_ms", "connect_avg", "first_byte_ms", "first_byte_avg", "path", "result"}]}`：已结束的公网访问，每次一项。**一次访问**是同一个来源 IP 对同一个映射的一串连接：最后一个连接断开后 30 秒内没有新连接（同一 IP），这次访问才结束（2026-10-15 起；之前每个连接一项）。`from` 为来源 IP，`start` 为第一个连接开始、`end` 为最后一个连接结束（Unix 毫秒），`conns` 为放进来的连接数、`refused` 为被拒绝的连接数，`in` / `out` 为从来源收到 / 发给来源的字节合计；`connect_ms` / `connect_avg` 为从接受连接到设备连上目标服务（设备的 CONNECT 应答）的最小 / 平均毫秒数，`first_byte_ms` / `first_byte_avg` 为到第一个字节发给来源的最小 / 平均毫秒数，没有为 -1；`path` 为最后一个连接结束时会话的路径；`result` 为最后一个连接的结束方式：`local_closed`（来源先关闭）、`peer_closed`（设备端先关闭）、`target_failed`（设备连不上目标服务）、`peer_reset`、`local_reset`、`session_ended`、`mapping_closed`（映射被关闭、到期或删除），或最后一次被拒绝的原因 `refused:原因`（`allow_from`、`quota`、`mapping_full`、`address_full`、`address_rate`、`no_session`、`session_full`）；托管客户端停止时进行中的访问一并结束上报；访问结束后 5 秒内或攒满 100 条时发送，一条消息最多 100 条，离线时暂存（最多 2000 条）；平台记在该账户名下（中心数据库 `public_conns`，保留 90 天，`npf-admin pubconns`），映射已删除的也记 |

- **托管客户端能做的事**：只有呼叫相关的消息（`call`、`call_end`、`punch_*`、`relay_*` 等）、`mapping_list`、`mapping_report`、`grant_get`、`quota`、`usage_report`、`conn_report`，其余账户操作一律 `forbidden`：它持有账户的证书，但运行在面向互联网的机器上，不能修改账户、设备或分享。托管服务的连接只能发 `hosted_register` 与 `hosted_token`；
- **拉取映射**：托管客户端用 `mapping_list{executor: {kind: "hosted", id: 托管服务编号}}` 拉取，只执行 `kind = public` 的映射；`mapping_report` 只接受该托管服务的托管客户端报告；
- **托管 `grant`**：托管客户端的 `grant_get` 得到 `kind = 2`（`npf-grant-hosted-v1`）的 `grant`，目标列表为该账户经这个托管服务指向该设备的全部启用的公网映射的目标；只对所有者签发。设备对这种会话的每条子链路检查目标（按 `CONNECT` 中写的地址或名称匹配），不在列表中回 `REP = 02`；
- **计费**：托管客户端的呼叫，中转只记录不计费；`usage_report` 报告的字节全部计费；
- **限速**：每个公网映射每个方向不超过 `rate_kbps`，由托管客户端在隧道中按映射限速（令牌桶，1 秒的突发）。

## 流量额度

需求：用户的订阅有有效期和流量限制（2026-10-07）；安全设计 D11。

**套餐**：平台定义若干级别（`npf-admin plan`，存在中心数据库）。级别 0 是免费级，所有账户都有；订阅（`npf-admin sub`，以后由支付系统开通）在有效期内把账户提到更高的级别，到期回到免费级。每一级规定：

| 字段 | 含义 |
|---|---|
| `monthly_bytes` | 每月的流量额度 |
| `relay_kbps` | 该账户中转的速率上限（kbps），0 为不限；免费级默认 128。呼叫发起后的前 15 秒（与不计费的开头相同，`relay_free_s`）不限速，会话在这段时间全速建立、测出路径；之后按上限，可以一次突发 2 秒的流量（免费级 32 KB，慢速套餐下打开一个网页、取一个小文件不用等），长期平均不超过上限：UDP 中转上超出速率的报文在中转服务器排队，至多等 250 ms 再转发，等不及才丢（只丢不排队时，会话开头的拥塞控制把丢包当作拥塞反复退避，实测一个 64 KB 的请求在 370 ms 往返的路径上要 20 多秒）；WS 中转按速率延后读取 |
| `public_max`、`public_kbps` | 公网映射的个数与每个映射每个方向的速率（KB/s）；免费级没有公网映射 |
| `choose_port` | 能否自选公网端口（更高级别的用户） |

没有在数据库中定义级别 0 时，免费级为每月 200 MB、128 kbps、没有公网映射。

**计入额度的流量**：中转转发的字节中呼叫发起 15 秒以后的部分（`relay_free_s`），以及公网映射的全部字节；直连不计。记到哪个账户同"呼叫记录"：客户端的账户、访问别人设备时访问者的账户、节点的所有者账户、公网映射的所有者账户。

**每月重置**：订阅从开通时刻起按月计（31 日开通的，在短的月份取月末），免费级从账户创建时刻起按月计；换了级别（开通、升级、到期）就从新级别的起点重新计。

**额度用完时**（到额度立即生效，不等下一次统计）：

| 场景 | 处理 |
|---|---|
| 进行中的中转会话 | 立即降到 `quota_slow_kbps`（默认 128 kbps），不中断 |
| 新呼叫 | 不分配中转，只能直连；双方 UDP 不通时 `call_rejected` 的 `error` 为 `quota` |
| 公网映射 | 已有的连接立即降速，不再接受新连接，已有的连接都结束后关闭监听端口，映射状态为 `error`（`quota: this month's traffic is used up`） |
| 下个月、续费或升级后 | 中转与新呼叫恢复；托管客户端下一次问额度时恢复监听 |

**订阅到期**（回到免费级）：免费级没有公网映射，托管客户端停止接受新连接、已有连接结束后关闭端口（`quota: the plan has no public mapping`）；中转按免费级的速率与额度。

**实现方式**（服务器内部）：每台服务器按账户从中心数据库**预支**一段额度（每月额度的 1/16，256 KB 到 64 MB），中转逐字节从中扣减，剩一半时再预支；数据库里预支是原子的，所以各服务器合计不超过额度。预支不到（用完）时该账户在这台服务器上立即受限；预支在等待中时允许少量透支（128 KB）。账户 2 分钟没有流量时退还未用的部分。账户的套餐每分钟重读一次（`quota_recheck_s`），后台改了订阅最多一分钟生效。托管客户端通过 `quota` 请求从同一份预支中取得字节，在隧道中逐字节扣减；用完时立即降速并再要，平台答"用完"或"套餐没有公网映射"时开始停止监听；没有用完也每分钟问一次，以便发现订阅结束。

**已用与预支**：给用户看的"已用"（`account_get.plan.used`、`quota` 事件的 `used`、`npf-admin sub`）是实际计费的字节：中转在免费开头之后、未超额时的字节，加上公网映射在公网端口上的全部字节；服务器与托管客户端预支的额度单独记录（`npf-admin sub` 显示"taken by the servers"），只用于限额，不算已用。`account_get.plan.exhausted` 表示本月额度已全部被预支（用完）。

**通知**：账户用到 80%、用完、恢复、订阅结束时，平台向该账户在这台服务器上的连接发送事件 `quota{state, level, plan, quota, used, period_end}`，`state` 为 `warning`、`exhausted`、`ok`、`no_public`。`account_get` 的应答增加 `plan`：`{level, name, quota, used, period_start, period_end, relay_kbps, public_max, public_kbps, choose_port, expires}`（`npf account show` 显示）。

## 重试与状态一致性

绑定、解绑、注册完成和映射写入等操作使用独立幂等键。平台按“认证主体、操作类型、幂等键”查找，并对规范化业务字段比较内容；相同键和不同内容返回 `conflict`。不使用原始 JSON 文本判断相同请求。

幂等结果与业务写入一起持久化；重放结果前仍检查当前身份和权限。保留窗口及客户端重试期限待定；超过窗口且结果未知时先查询，不能盲目重发创建操作。过期的绑定挑战即使遇到缓存清理也不能重新消费。

关闭和取消重复到达应无副作用。终态呼叫保留有限期记录，迟到的应答不得重新建立已取消会话。设备管理事件丢失由重新查询恢复，不以事件顺序代替数据库和设备实际状态。

## 本稿尚未冻结的实现细节

需求侧的问题已全部确认。协议侧还需确定：密码哈希的算法参数、绑定声明与 `grant` 等签名对象的确定性编码、各消息的长度上限、超时与重试窗口、幂等结果的保留窗口、密码学实现与测试向量；第三方登录的手机 App 方式（Google 的移动端客户端、微信的移动应用 SDK）。数量上限（2026-10-05 确认）：每个账户 20 个控制台节点、5 个公网映射、50 个本地映射；每个节点并发会话 32 个（2026-10-06 由 8 改为 32；超出回 `busy`，可在本地调整）、本地授权列表 256 项。

本稿先建立需求到协议的对应关系，后续每确认一项，同时更新需求状态、相关字段与异常流程，不仅补充成功示例。

## 变更记录

| 日期 | 版本 | 内容 |
|---|---|---|
| 2026-10-22 | 0.27 | 信令与服务器之间的连接改用 binary WebSocket 消息（原为 text 中的 Base64url）；过渡期服务器对节点两种都收，按节点第一条消息的形式回复；服务器之间只用 binary；被拒的 `login` / `enroll` 先收到错误应答再断开（之前应答可能被关闭抢先而丢失） |
| 2026-10-17 | 0.26 | `hosted_stats`：托管服务每分钟报告运行情况与主机资源，应答带平台为它设的参数（`hosted_register` 的应答也带） |
| 2026-10-17 | 0.25 | `enroll`：以平台的型号登记与绑定为准，拒绝时 `message` 给出原因 |
| 2026-10-15 | 0.24 | 映射创建与修改的失败原因（`message`：`no_hosted`、`plan_limit` 等）；映射的 `scheme`（`http` / `https`）；`conn_report` 改为每次访问一条（同一来源 IP 的连接相隔不超过 30 秒）：连接与被拒次数、连接服务与首字节时间的最小值与平均值、路径、结束方式；`pubconn_list`：账户自己的公网访问记录 |
| 2026-10-13 | 0.23 | `relay_switch{unreachable}`：中转已在主叫的服务器上（同一台服务器的呼叫）时，改在网状互联的其他服务器上分配 |
| 2026-10-13 | 0.22 | `share_set`：所有者允许访问者在设备上建公网映射；`share_list` 带 `public`；托管客户端的 `grant_get` 对被允许的访问者同样签发 |
| 2026-10-12 | 0.21 | 中转速率上限：呼叫的前 15 秒不限速；之后可突发 2 秒的流量，UDP 中转把超速的报文排队至多 250 ms，不再立即丢弃 |
| 2026-10-10 | 0.20 | Google 与微信登录定稿：`auth_providers`；`auth_begin` 的 `purpose`（`login` / `bind` / `confirm`）与 `origin`；事务存数据库，回调可以落在任一服务器；浏览器页面的确认码作为完成的条件；`login_method_bind` / `login_method_unbind` 的字段与规则；没有密码的账户用 `confirm` 事务注销 |
| 2026-10-09 | 0.19 | `enroll` 的 `model_cert` 改为 `model_chain`（厂家证书加型号证书，型号凭证由厂家自己签发）；`serial` 可由设备从硬件生成；`hw_fp` 改为逐项的 `hw`，按多数项判断是否同一硬件 |
| 2026-10-09 | 0.18 | `pay_ticket`：去支付页的一次性票据；`plan_list` 增加价格 `prices` 与订阅 `sub`；订阅改由订阅时段算出（支付、运营方开通共用） |
| 2026-10-08 | 0.17 | `hosted_register` 的回复只给账户数，账户列表改由 `hosted_accounts{after, limit}` 分页取（每页最多 200，`next` 为空表示结束）：一条消息装不下几百个账户；托管客户端可以不常连信令（闲置断开，有公网连接时再登录） |
| 2026-10-08 | 0.16 | `conn_report`：公网映射的逐连接记录（来源、起止时间、字节）；`public_moved`：托管服务离线超过 `hosted_failover_s` 时公网映射迁到另一个托管服务 |
| 2026-10-08 | 0.15 | 公网映射按公网端口上的字节计费（`usage_report`）；"已用"为实际计费字节，与预支分开（`plan.exhausted`）；托管客户端只在余量不足时领额度，例行询问不领，套餐级别变化时作废旧余额并重新拉取映射 |
| 2026-10-07 | 0.14 | 新增"流量额度"：套餐级别（免费级每月少量、128 kbps）、订阅有效期、每月重置；额度用完立即降速，新呼叫只能直连（`call_rejected` 的 `quota`），公网映射停止接受新连接、连接结束后关闭端口；订阅到期的公网映射停止；托管客户端的 `quota` 请求、`quota` 事件、`account_get.plan`；公网映射的个数、速率与自选端口由套餐决定（取代 VIP 标记与 `public_rate_kbps`） |
| 2026-10-07 | 0.13 | `login` 增加 `app`（程序名称与版本，所有角色），写进连接与呼叫记录、放进 `incoming.caller`；`host.app` 去掉，客户端不再带 `model`。公网映射实现：新增"托管服务"一节（`role = hosted`、`hosted_register`、`hosted_changed`、`hosted_token`、`hosted_login`、`usage_report`），只有 `-L` 方向，只有所有者能建，VIP 可选端口，`allow_from`、`rate_kbps`，流量全部计费，呼叫记录增加 `public_up` / `public_down` |
| 2026-10-07 | 0.12 | 新增"呼叫记录"：发起 / 接受 / 结束时间、双方的服务器与源地址、NAT 类型、直连地址、中转分配与中转流量（前 15 秒不计费）；`call_end` 改为请求，信令断开时在下次登录后补发，带 `ago_ms` |
| 2026-10-06 | 0.11 | 每节点并发会话默认 32（R46 修订） |
| 2026-10-06 | 0.11 | `incoming.caller.paired_by_server` 由服务器填写；`device_list` 分页定稿（`limit` 默认 20、最多 50，`cursor` 为上一页最后一个编号，不透明）；被叫的 `busy`、服务器闸门按源 IP 与每设备的计数已实现；本文不再标注实现状态，统一由实现说明维护 |
| 2026-10-05 | 0.10 | 新增 `relay_release`；`relay_switch` 增加 `mode: "udp"`（重新分配） |
| 2026-10-05 | 0.9 | 按第一版实现补齐字段：`call` 的 `cpace` 字段、`welcome` 的 `client_id` / `account_id`、账户请求的密钥证明、`bind_begin` / `bind_commit` / `grant_get` / `node_enroll` 的应答、`revoke` 改为请求 |
| 2026-10-05 | 0.8 | 设计评审：公网映射不设设备端开关，数量上限确认；连接的身份与账户会话分层，控制台节点的首次运行流程；新增 `grant_get`、`paired_sync`、`lock_report`、`bind_committed`、`account_delete`；`revoke` 改为按签发时间撤销并可清除所有者；新增"隧道内控制消息"一节定义 `close`、`bind_approve`、`grant_update`；`call_end` 的原因码；映射的执行者改为节点或客户端 |
| 2026-10-05 | 0.7 | 节点模型：控制台程序有编号、可被呼叫，呼叫按主叫 / 被叫描述，新增 `node_enroll` |
| 2026-10-05 | 0.6 | 账户、所有者与分享、撤销、公网映射按 Q01 至 Q12 的答复定稿 |
| 2026-10-05 | 0.5 | 跨服务器路由与中转回退 |
| 2026-10-04 | 0.4 | 接入与服务器列表 |
| 2026-10-04 | 0.3 | 呼叫、握手承载、中转分配、打洞信令定稿为可实现的字段 |
| 2026-10-04 | 0.2 | 子链路与中转改由数据通道协议定义 |
| 2026-09-30 | 0.1 | 初稿 |

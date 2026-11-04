# libnpf 的 Rust 绑定

| crate | 内容 |
| --- | --- |
| `npf-sys` | `npf.h` 的原始声明（手写，`tests/layout.rs` 用 C 编译器逐个核对结构体大小和字段偏移）；`build.rs` 构建或链接 libnpf |
| `npf` | 安全接口：`Npf` 实例、`Handler` 回调 trait、类型化的编号（`PeerId`、`SessionId`、`MediaId` ...）、`Error` |

## 构建

```sh
cd bindings/rust
cargo test
```

默认用 CMake 从本仓库源码构建 libnpf（Release，不带测试和示例）。Linux 上链接静态的 `libnpf.a`：只有 npf.h 的函数是全局符号，内置的 AnLiu、Monocypher、mbedTLS 不会和程序里的其他副本冲突。其他系统上链接共享库。

| 环境变量 | 作用 |
| --- | --- |
| `NPF_LIB_DIR` | 链接已经构建好的库（`NPF_INCLUDE_DIR` 默认 `$NPF_LIB_DIR/../include`） |
| `NPF_LINK` | `static` 或 `dylib` |
| `NPF_SRC_DIR` | libnpf 源码的位置（默认本仓库） |
| `NPF_CMAKE_ARGS` | 给 CMake 的其他选项，如 `-DNPF_PEERS=OFF -DNPF_USE_OPENSSL=ON` |

## 用法

```rust
use npf::*;

struct App;
impl Handler for App {
    fn session(&self, npf: &Instance, s: SessionId, up: bool, info: &str) {
        if up {
            let mut o = MediaOpt::new(1);          // 视频：迟到丢帧，丢帧后等关键帧
            o.drop_until_key = true;
            o.rcv_drop_until_key = true;
            let _video = npf.media_open(s, &o);
        }
    }
    fn data(&self, npf: &Instance, s: SessionId, data: &[u8]) {
        let _ = npf.session_send(s, data);         // 可靠、有序
    }
    fn media_open(&self, _: &Instance, _: SessionId, _: MediaId, tag: i32) -> bool {
        tag == 1
    }
    fn media_frame(&self, _: &Instance, m: MediaId, frame: &[u8], fi: FrameInfo) {
        // fi.key、fi.lost_before：解码器据此决定是否请求关键帧
    }
}

let npf = Npf::new(&Options::direct("/var/lib/app", Some(("0.0.0.0", 9000)), psk), App)?;
npf.start()?;
// 编码线程：npf.media_send(video, &frame, key)?; 码率跟着 npf.media_stats(video)?.target_rate 调整
```

要点：

- 回调在实例自己的线程上执行，一次一个，要尽快返回。回调里拿到的 `&Instance` 可以调用全部接口。
- `Npf` 被丢弃时会停止并释放实例（`npf_destroy`）。不要在它自己的回调里丢弃它：libnpf 拒绝在自己的线程上销毁实例，这种情况下实例会被泄漏，并打印一行提示。
- 回调里的 panic 在 C 边界被截住，不会跨过 C 的栈展开。
- `NPF_ESAVE`（已生效，但 `local.json` / `state.json` 没写成）返回 `Ok`；`NodeInfo::unsaved` 和 `Instance::save` 用来查看和重写。
- `media_send` 从其他线程调用时只是入队，不等待；队列满时返回 `ErrorKind::Busy`。

# log.c（vendored）

来源：rxi/log.c（https://github.com/rxi/log.c ，MIT 许可证，版权声明在 `log.c` / `log.h` 文件头），取自 pangolin 项目使用过的副本（`pangolin/npf/lib/core/`），去掉了 pangolin 在 `log.h` 末尾追加的 `NPF_LOG_*` 宏，其余未改。

| 项目 | 值 |
|---|---|
| 版本 | `LOG_VERSION "0.1.0"`（2020） |
| `log.c` SHA-256 | `146ec2eeec1c2243294f8c03b2dfba0f89cdd247f36c9f163efe669e440d82bd` |
| `log.h` SHA-256 | `0310f832288a1e4637965c9de8097f93b5aa9074057d560ccaaa8a26664c2ab5` |

NPF 只用它做按级别分发和加锁（`log_set_lock`、`log_add_callback`），自带的 stderr 输出关闭（`log_set_quiet`）；行格式、文件、轮转、最近日志缓存在 `src/platform/log.c`，接口见 `include/npf/log.h`。

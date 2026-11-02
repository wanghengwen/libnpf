# Mbed TLS（vendored）

来源：[github.com/Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) 的发布 `mbedtls-3.6.7`（LTS）。本目录是发布包中 `include/` 与 `library/` 的原样副本（274 个文件，没有改动；`LICENSE` 同发布包），libnpf 的配置在 `../mbedtls-config/npf_mbedtls_config.h`。

| 项目 | 值 |
|---|---|
| 上游标签 | `mbedtls-3.6.7`（提交 `068ff080b369adfac81509f9b57b2afabaf82dc5`） |
| 发布包 | `mbedtls-3.6.7.tar.bz2`，SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`（与发布说明中的一致） |
| 核对日期 | 2026-11-02：本目录每个文件与发布包中的相同 |
| 补丁 | 无 |

更新：下载新的发布包，核对发布说明里的 SHA-256，用其中的 `include/`、`library/`、`LICENSE` 替换本目录，更新本表，然后构建并运行全部测试。

# AnLiu（vendored）

来源：AnLiu 公开仓库 [github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu) 的 `main` 分支。libnpf 不改公开仓库；需要的修改以补丁形式放在本目录的 `patches/`（见其中的 README），更新上游后重新应用。

| 项目 | 值 |
|---|---|
| 上游提交 | `6986761ebe6986c836dbc881903b137b252e67b9` |
| 复制日期 | 2026-10-25 |
| `anliu.c` SHA-256 | `dc3536dc824ba277e5735ba917cdade7d23a0e4f57bb92ae05fd1686d0a1cd79`（上游文件，打补丁前） |
| `anliu.h` SHA-256 | `c3a003160f30924563d945d828122fae05252f0277f086a8d9d4bd39a655d7d3`（上游文件，打补丁前） |
| 线上版本 | `ANL_VERSION 1`，与 libnpf 之前使用的私有分叉（2026-10-01）互不兼容 |
| 补丁 | 无 |

更新：`scripts/anliu-update.sh [上游目录] [提交]`（上游目录是公开仓库的本地克隆；复制 `anliu.c`、`anliu.h`、`LICENSE`，按顺序应用 `patches/`，更新本表；不指定提交时取上游工作区），然后构建并运行全部测试（`ctest`）。

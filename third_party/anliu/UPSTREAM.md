# AnLiu（vendored）

来源：AnLiu 公开仓库 [github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu) 的 `main` 分支。libnpf 不改公开仓库；需要的修改以补丁形式放在本目录的 `patches/`（见其中的 README），更新上游后重新应用。

| 项目 | 值 |
|---|---|
| 上游提交 | `e2058d52bd84ef929bfde424a27e906177a700da` |
| 复制日期 | 2026-10-24 |
| `anliu.c` SHA-256 | `103c83e82c535ec7d60e6ca025c857a8773b736862ac7c3362f658d960c5fcd2`（上游文件，打补丁前） |
| `anliu.h` SHA-256 | `c3a003160f30924563d945d828122fae05252f0277f086a8d9d4bd39a655d7d3`（上游文件，打补丁前） |
| 线上版本 | `ANL_VERSION 1`，与 libnpf 之前使用的私有分叉（2026-10-01）互不兼容 |
| 补丁 | 无 |

更新：`scripts/anliu-update.sh [上游目录] [提交]`（上游目录是公开仓库的本地克隆；复制 `anliu.c`、`anliu.h`、`LICENSE`，按顺序应用 `patches/`，更新本表；不指定提交时取上游工作区），然后构建并运行全部测试（`ctest`）。

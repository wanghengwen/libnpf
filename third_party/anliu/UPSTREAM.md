# AnLiu（vendored）

来源：AnLiu 公开仓库 [github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu) 的 `main` 分支。libnpf 不改公开仓库；需要的修改以补丁形式放在本目录的 `patches/`（见其中的 README），更新上游后重新应用。

| 项目 | 值 |
|---|---|
| 上游提交 | `6c05c600a7edc72408b8305044574977f9f21862` |
| 复制日期 | 2026-10-28 |
| `anliu.c` SHA-256 | `2412e2d040e63ee406bcb4186e6caa9fe04599ec15058c3dedfed1b5719ba85d`（上游文件，打补丁前） |
| `anliu.h` SHA-256 | `918b8cc1b7cf8ad95de92079969f508ca4da2df31718482523355289009ff0fc`（上游文件，打补丁前） |
| 线上版本 | `ANL_VERSION 1`，与 libnpf 之前使用的私有分叉（2026-10-01）互不兼容 |
| 补丁 | 无 |

更新：`scripts/anliu-update.sh [上游目录] [提交]`（上游目录是公开仓库的本地克隆；复制 `anliu.c`、`anliu.h`、`LICENSE`，按顺序应用 `patches/`，更新本表；不指定提交时取上游工作区），然后构建并运行全部测试（`ctest`）。

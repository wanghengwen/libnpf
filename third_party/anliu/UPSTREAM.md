# AnLiu（vendored）

来源：AnLiu 公开仓库 [github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu) 的 `main` 分支。libnpf 不改公开仓库；需要的修改以补丁形式放在本目录的 `patches/`（见其中的 README），更新上游后重新应用。

| 项目 | 值 |
|---|---|
| 上游提交 | `60b0ffde805f5e18d74afdfab57e9e2e3c798add` |
| 复制日期 | 2026-10-28 |
| `anliu.c` SHA-256 | `e93f40ddcefde60146ab9d778eaf6d5a4d256ecd8bc71ed3668b5cac31a6f606`（上游文件，打补丁前） |
| `anliu.h` SHA-256 | `dbf9f4355065e62d670898161ea3e3f2a77e313b4a15e6d0d40d189160750145`（上游文件，打补丁前） |
| 线上版本 | `ANL_VERSION 1`，与 libnpf 之前使用的私有分叉（2026-10-01）互不兼容 |
| 补丁 | 无 |

更新：`scripts/anliu-update.sh [上游目录] [提交]`（上游目录是公开仓库的本地克隆；复制 `anliu.c`、`anliu.h`、`LICENSE`，按顺序应用 `patches/`，更新本表；不指定提交时取上游工作区），然后构建并运行全部测试（`ctest`）。

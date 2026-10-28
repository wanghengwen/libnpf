# AnLiu（vendored）

来源：AnLiu 公开仓库 [github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu) 的 `main` 分支。libnpf 不改公开仓库；需要的修改以补丁形式放在本目录的 `patches/`（见其中的 README），更新上游后重新应用。

| 项目 | 值 |
|---|---|
| 上游提交 | `39fa5f1a378e9ddada91118d5baedbb2fa5803fd` |
| 复制日期 | 2026-10-28 |
| `anliu.c` SHA-256 | `3ecd05a6d67c16eab1a91fd6a63a38245184628da7b302807d1b23eb3f0e485a`（上游文件，打补丁前） |
| `anliu.h` SHA-256 | `0f203e543aa061688dfe9bda8cbedeb4deabb65f83f7202ecb4cae9e83ab71af`（上游文件，打补丁前） |
| 线上版本 | `ANL_VERSION 1`，与 libnpf 之前使用的私有分叉（2026-10-01）互不兼容 |
| 补丁 | 无 |

更新：`scripts/anliu-update.sh [上游目录] [提交]`（上游目录是公开仓库的本地克隆；复制 `anliu.c`、`anliu.h`、`LICENSE`，按顺序应用 `patches/`，更新本表；不指定提交时取上游工作区），然后构建并运行全部测试（`ctest`）。

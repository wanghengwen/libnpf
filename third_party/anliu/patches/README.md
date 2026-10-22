# libnpf 对 AnLiu 副本的补丁

libnpf 不修改 AnLiu 的公开仓库（[github.com/wanghengwen/AnLiu](https://github.com/wanghengwen/AnLiu)）；需要的改动以补丁放在这里，`scripts/anliu-update.sh` 复制上游文件后按文件名顺序应用（`patch -p1`，在副本目录内，路径写成 `a/anliu.c`、`b/anliu.c`）。

- 文件名 `NNNN-简述.patch`，开头写明原因、对应的问题（如路线图 3.2 的 A3）与验证方法；
- 上游合入了同样的修改后删除对应补丁；
- 补丁不能应用时脚本停止，副本保持上游原样，修正或删除补丁后再运行。

# LNX-VR Linux 部署（MalTrace 总纲前置）

2026-10-06/07 在固定 REMnux 上端到端执行并通过两次同前提 triage 硬验收
（client `C.ad6af61fd3327c75`, os=linux）。guest 回滚到可信基线后按此重建。

- `deploy-remnux.sh` — guest 上的一键部署（binary 参数 + systemd 双 unit +
  api_client 凭据 + Linux 域模块/验收 runner 安装）。
- `server.config.yaml` / `client.config.yaml` — 自签配置参考副本
  （全部监听 127.0.0.1；client 只含 version+Client+CA，writeback 在
  Client 节内——v0.77 拒绝顶层 writeback_* 字段）。
- 二进制：上游 GitHub `Velocidex/velociraptor` v0.77.3
  `linux-amd64-musl.gz`（sha256 前 16 位 93171158fa081c07），host 侧
  `curl -sL` 下载后 gunzip/chmod 传入脚本。Datastore 默认
  `/var/tmp/velociraptor`。
- 访问模式：P01 authorized_keys 的 permitopen 白名单只放行 8765/8766，
  gRPC 8001 端口转发按设计被阻断——所有 API 操作走 guest 本地
  （`velociraptor --api_config /opt/velociraptor/api-access/api_client.yaml query ...`）。
- 验收：`tests/linux_domain_runner.py`（两次 triage/范围供给/平台路由），
  证据在 MalTrace `.tmp/linux-master-20260930/lnxvr-accept-20261007/`。


## 凭据文件说明（2026-10-07 补记）

`server.config.yaml`/`client.config.yaml` 含部署时生成的真实 RSA 私钥，禁止进入 Git；已移出仓库。重建方式：按 deploy-remnux.sh 内注释用 `velociraptor config generate -i` 等命令生成（127.0.0.1 自签、writeback 字段入 Client 节），生成后仅存 /opt/velociraptor（0600）。

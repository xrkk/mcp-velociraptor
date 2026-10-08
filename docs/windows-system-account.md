# .149 Velo SYSTEM 账号迁移

本记录保留迁移当时两个 read root 的历史证据；后续用户授权的盘根读取范围
变更见 [本地文件系统读取范围](windows-all-filesystem-read-roots.md)。

用户于 2026-10-08 明确选择 Velo 使用 SYSTEM，并询问现有 read_roots。
只维护 `mcp-velociraptor` 服务与其保活任务，不重启 VM、不恢复快照，
不停止 dnSpy、Windows-MCP、FakeNet 或其他应用。

## 迁移清单

- [x] 读取实际 policy 与能力：`velo149-20260928` 的 read_roots 为
  `E:\VeloTransfer-149\data`、`E:\VeloTransfer-149\artifact-export`；
  write_roots 仅为 data，work_root 为 `E:\VeloTransfer-149\transfer`。
- [x] 保存服务、保活 XML、配置 SHA/ACL 与进程基线；确认实际无活动 worker，
  持久 RootLease active=null。旧失败/中断任务保留，不将其全部称为完成。
- [x] 日常配置脚本支持 LocalSystem 默认与显式 VirtualAccount，保活匹配所选
  账号；verify 拒绝账号不符，configure 拒绝运行中迁移或启用保活的迁移。
- [x] 保留私有环境 ACL/备份，仅增加原服务 SID 的旧状态信任；policy/API 不改。
- [x] 停止 Velo，部署脚本，迁移账号并启动，核对实际进程 owner=SYSTEM。
- [x] 正式 HTTP 鉴权/工具列表/传输能力通过，原读取根不变。
- [x] 管理员创建 SYSTEM/admins-only 产物：迁移前拒绝，迁移后正式 pull COMPLETE，
  独立 SHA/大小与双端 cleanup 通过，原文件 ACL 不加服务 Read。
- [x] 保活按 SYSTEM 正常执行；最终无活动 worker，核对其他应用 PID/创建时间。
- [x] 文档、本地提交与以上清单逐项核对；不推送。

## 已发现的部署差异与证据

原服务为虚拟账户、Running PID7160；dnSpy PID5976、FakeNet 服务 PID1596。
私有状态中有原服务 SID 所有者和 ACE；SYSTEM 模式仍执行应用 ACL/owner
校验，故须通过已有 protected env 设置保留对此既有 SID 的信任，不能仅改 SCM。
不递归改旧状态 owner/DACL，不增加新的用户信任或公开读权。

原 SCM recovery reset 为 0，三次/后续重启间隔均为 10000ms、noncrash=1。
旧账户 verify 因与脚本的 86400 秒 daily target 不符而失败，已如实保留；
本次 configure 已恢复日常 24 小时 reset，重启间隔不变。Windows 原生解析通过；
两个身份拒绝检查通过。初次控制命令超过 Windows 命令行长度而未执行，
改用分块写入候选；初次宿主 CLI 因沙箱所有者映射拒绝，改用真实宿主权限视图，
未修改产品的 owner/ACL 门禁。

VM 证据在部署目录 `Logs/velo-system149-20261008-a84c21/`；宿主证据在
`/tmp/velo-system149-20261008-a84c21/`，凭据原件/备份只留私有 secrets。
dnSpy 默认产物目录不在上述 read_roots；本次不扩大路径范围或操作 dnSpy 导出。
历史 P05 虚拟账号安装/qualification 与严格审计批准不因此重新获得资格。

## 实际完成与验证范围

- Velo 已迁移至 LocalSystem，SCM Running/Auto；实际 PID7968，创建时间
  `2026-10-08T18:11:42.323692+08:00`，GetOwner 返回 NT AUTHORITY/SYSTEM。
  新配置脚本在部署位置 `-Mode verify` 通过。停服命令虽报错，独立 SCM 回读
  为 Stopped 后才迁移，没有强杀。原脚本及任务 XML 保留。
- 环境文件经已有私有 replace helper 更新，原 owner/DACL 与备份保持；
  与原备份逐字比较，只有追加旧服务 SID 信任设置及换行。API/policy SHA 和
  ACL 未变；policy SHA256 为
  `14d8fcab8fdeb07e039ef2e993d1de2eaeea4035526ecfbed0b9f2f509e23bd8`。
- 候选脚本从 Logs 发布时，继承使服务 ACE 从 RX 变为 Modify，最终 ACL 检查
  正常拒绝，尚未切换身份；已按原备份恢复正式脚本 RX ACL，并重新核对内容
  SHA 后再配置。失败及恢复差异在 `script-deploy.json`，未忽略该检查。
- 同一 85 字节管理员产物保持 protected SYSTEM/admins 两 ACE，未加原服务
  Read。迁移前 `velo-system149-a84c21-before` 在 SOURCE_PREPARING 返回
  source_unavailable；worker-error 原件保留完整绝对路径、open、PermissionError、
  errno13 与 Permission denied；实际 winerror=null，没有编造 Win32 错误。
  迁移后 `velo-system149-a84c21-after` 正式 Velo channel COMPLETE，
  destination_verified=true，guest/host cleanup=true；独立重读目标大小/SHA 通过：
  `a402c83e7fd284c7d8ad2a9b98097cacfb407ce3fe5859354422b7851317d50e`。
  原 source SHA/ACL 不变。
- 新官方 SDK 会话 initialize、tools/list（137 项）、capabilities 通过；能力
  启用、两个 read root ID 与原 policy 对应，boot_identity 与迁移前相同。
  初次独立验收脚本使用旧 SDK 字段名而失败；仅将验收脚本改成当前 SDK 的
  is_error/structured_content 后重跑通过，没有修改产品来放行。
- 保活已启用且按 LocalSystem 绑定；真实任务执行 LastTaskResult=0。
  这次任务在服务 Running 时检查，没有另做周期停服重启或整机启动测试。
  最终 RootLease active=null、实际 worker=0；FakeNet PID1596 和 Windows-MCP
  任务 Running。128 个基线进程中 122 个 PID/创建时间保持，6 个变化原件留存；
  dnSpy PID5976、两个 Velociraptor 进程、Explorer、Everything 的创建时间保持。
  未向其他程序发送停止/终止指令。
- `tests/daily_service_account_refusals.ps1` 的六项拒绝回归在原生 PowerShell 7 和
  Windows PowerShell 5.1 各执行通过，可用下面命令复查：

  ```powershell
  .\tests\daily_service_account_refusals.ps1 -RepoRoot $VeloRepository
  ```

  SCM/task/config 调用被隔离拦截，无部署写入；实际迁移/启动/回收证据另列如上。
  Python scoped 回归 14 通过、1 Windows-only 跳过；AGENTS 五文件编译与
  git diff --check 通过。这不等于全库、严格审计或 dnSpy 导出验收。

宿主独立记录：`verification.json`、`sdk-verification.json`、`native-evidence.json`，
以及 `.velo-transfer/tasks/<transfer-id>/` 中失败/成功 journal、result 和原始收据。
VM 另有 `private-files-after.json`、`refusal-tests*.json`、`final-state.json` 等原件。
私有 env 原件与备份不放入共享交接目录。测试源与接收件保留供复核。

# .149 本地文件系统读取范围

用户于 2026-10-08 在 SYSTEM 迁移后授权：read_roots 覆盖虚拟机所有文件系统，
并询问 write_roots。只扩展读取范围，不扩大写入范围；仅重载 Velo 服务，
不重启 VM、不恢复快照、不停止其他应用、不修改卷挂载或原文件 ACL。

实际可访问的本地文件系统为 C:/E: 两个 NTFS 卷；D: 是无介质光驱。
另有无盘符 FAT32 EFI 卷，只有设备 GUID 路径；当前普通文件传输接口不接受
该设备路径，本次不挂载它、不修改启动分区。新增卷不会自动加入静态策略。

已生效的 read_roots（旧精确根保留以兼容 producer export helper）：

```text
E:\VeloTransfer-149\data
E:\VeloTransfer-149\artifact-export
C:\
E:\
```

write_roots 仍为 `E:\VeloTransfer-149\data`：授权宿主 push 的 VM 目的目录。
work_root 仍为 `E:\VeloTransfer-149\transfer`：内部状态/worker/package 的私有存储，
它与 write_roots 的用途不同，不代表外部 push 可以写到该目录。

扩展后的 read_roots 也覆盖原先在策略外的桌面产物和私有路径。文件仍须存在、
生产已结束且实际可读；共享冲突、EFS、reparse/设备/别名拒绝及传输预算保持。
未执行全盘扫描或读取凭据来验证范围。

## 清单与验证

- [x] 保存实际卷、原 policy/code/私有配置 SHA/ACL、服务和其他进程基线；
  RootLease 空闲，实际 worker=0。
- [x] 复现盘根 `C:\` 被旧路径语法拒绝；最小修复保留 canonical drive anchor，
  拒绝重复分隔符、drive-relative、dot/device aliases。宿主 scoped 11 通过、
  1 Windows-only 跳过；沙箱权限映射失败保留，真实宿主视图重跑通过。
- [x] 部署修复，验证原生盘根路径与候选 policy；保护原代码 ACL。
- [x] 私有 policy 备份/替换，仅追加两个盘根；原 owner/DACL、write/work/limits 保持。
- [x] 只维护 Velo 服务，真实 SYSTEM 启动、capabilities roots 与原 boot identity 核对。
- [x] 正式 pull 两个旧范围外的自建 C:/E: 文件，独立大小/SHA、双端 cleanup 通过。
- [x] 保留 data 写入能力，并拒绝 write_roots 外目的地，未创建拒绝目的目录。
- [x] keepalive、RootLease/worker、原 env/API、其他程序状态与原记录核对。
- [x] 本地提交前文档/清单逐项核对；提交只包含本次代码、测试和文档，不推送。

## 实际验收与限制

- 最小代码修复 SHA256 为
  `2c49b15fb072b1c7b0c4830706930c8322f3a8925c3ddb358128c1fd138b545a`。
  候选策略由原生 GuestTransferService 使用真实 Windows ACL/身份验证加载成功，
  然后才替换正式 policy。新版 policy SHA256 为
  `1dd230ec84d6fa615507faffa4cf614843be4e109832f5c06b384e164f7e4fa2`；
  备份与原版 SHA 匹配，解析字段仅追加 C:/E: 两个读取根，owner/DACL 均保持。
- 重载后 SCM Running/Auto，实际服务 PID2076，owner=NT AUTHORITY/SYSTEM；
  daily service verify 通过，keepalive 已启用、LastTaskResult=0。官方 SDK
  initialize、137 项工具列表与 capabilities 通过；读取四个根 ID、写入唯一
  data 根 ID、原 UUID/boot identity/limits 逐项匹配。
- `velo-readroots149-f26b-pull` 通过正式 Velo channel 达到 COMPLETE；两个旧范围外
  的封闭测试文件均为 54 字节，宿主独立重读 SHA 与 VM 原件及结果清单一致，
  destination_verified=true、guest/host cleanup=true，源 SHA/ACL 未变。
- 重载后 `velo-readroots149-f26b-write` 在 data 内写入 COMPLETE，48 字节源与
  VM 目标独立 SHA 一致，双端 cleanup=true；`velo-readroots149-f26b-denied`
  在 data 外返回 path_outside_root，published_ever=false，目的目录不存在。
  拒绝任务保留 PREPARING/incomplete 的 journal/package/收据，不冒充清理完成。
- 最终 RootLease active=null、实际 worker=0，env/API 的 SHA/ACL、代码和 policy
  的 ACL 保持。127 个基线进程中 122 个 PID/创建时间保持；5 个变化是原 Velo
  进程及临时控制 shell。dnSpy、FakeNet、Windows-MCP、两个 Velociraptor、
  Explorer、Everything 均保持原 PID/创建时间，Windows-MCP 任务仍 Running。
  初次比较创建时间字符串因小数位格式误判，保留该失败记录后按 UTC ticks 核对。
- 宿主 scoped tests 11 通过、1 Windows-only 跳过；原生新增路径语法两项通过，
  Python 编译和 git diff --check 通过。原生整份 test_transfer_policy 尝试为
  5 通过、1 失败、1 跳过：既有 test_identity_permissions_and_roots 未传 Windows
  ACL verifier，却预期 vm_identity_unavailable，实际正确先拒绝为
  windows_acl_not_verified；该既有测试不兼容本次未修改，失败日志保留。
  不宣称整份 Windows 测试或全库通过；原生实际策略加载和 C:/E: 回收另有上述证据。

宿主独立记录为 `verification.json`、`sdk-verification.json`、
`write-boundary-verification.json`、`native-evidence.json`，正式任务证据在
`.velo-transfer/tasks/<transfer-id>/`。VM 原件包括 baseline、候选加载、
代码发布、私有 policy 替换、daily verify 和 final-state 记录；不发布私有凭据内容。

VM 原件在部署目录 `Logs/velo-readroots149-20261008-f26b/`；宿主原件在
`/tmp/velo-readroots149-20261008-f26b/`。代码/配置旧版及失败证据保留。
原 SYSTEM 迁移与原两根回收验收仍是历史事实，本记录描述其后的读取范围变更。

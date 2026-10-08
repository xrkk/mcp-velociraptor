# .149 所有磁盘写入范围与剩余限制

本记录保留扩大配置后首次 C 卷拒绝的历史事实；后续卷根祖先校验调整及
C/E 实际发布成功见 [内容 ACL 修复验收](windows-content-acl-verification.md)。

用户于 2026-10-08 授权 write_roots 也改为所有磁盘，并要求说明其他限制。
本次只修改 .149 私有策略的 write_roots；没有修改应用 ACL 门禁、任何已有
卷/目录/源文件 ACL、read_roots、work_root、预算、身份或服务配置。
仅受控重载 mcp-velociraptor，不重启 VM、不恢复快照、不停止其他应用。

## 已生效的配置

```text
write_roots:
  E:\VeloTransfer-149\data
  C:\
  E:\
```

保留原 data 精确根；C:/E: 是目前两个有介质、可访问的 NTFS 磁盘。
D: 无光盘介质，无盘符 EFI 分区仅有设备 GUID 路径，未纳入普通文件传输；
没有挂载 EFI 或修改启动分区。新增磁盘需更新静态策略，不自动授权。
读取根仍是 data、artifact-export、C:/E:；内部 work_root 仍为
`E:\VeloTransfer-149\transfer`。这是 guest 本地 pull/push 策略，
不改变宿主 connection profile、宿主目录保护或其他 MCP 的独立约束。

## 实机结果：配置扩大不等于 C 卷可实际写入

- [x] 保存策略、私有配置与代码 SHA/ACL、SCM/task、卷和进程基线，确认 worker=0、
  RootLease active=null；候选策略由真实 Windows GuestTransferService 加载通过。
- [x] disable keepalive、受控停止 Velo 后，通过现有私有 replace helper 替换策略，
  保留原 owner/DACL 和独立私有备份，再启动 Velo、enable keepalive。
  Stop-Service 报错后独立回读 SCM=Stopped 才继续，未强杀。
- [x] 正式策略解析仅追加 C:/E: 两个 write root；新版 SHA256 为
  `ecc5f1d62ec7f7da05110db393f96aeb2884c59f0d7af062317ee58165e6e1ef`。
  原策略备份 SHA 与上一阶段 `1dd230ec...` 一致；env/API/代码 SHA、全部既有
  私有文件 owner/DACL 保持，不把私有配置或凭据复制到共享测试目录。
- [x] 官方鉴权 SDK initialize、137 项 tools/list、capabilities 通过；四个 read
  root ID、三个 write root ID、limits、UUID/boot identity 与预期匹配。
- [x] E 卷 data 外自建私有父目录内，正式 `velo-writeroots149-c71e-e` push COMPLETE；
  48 字节目标大小和 SHA 经 VM 原生独立重读与宿主源及正式 result 匹配，
  destination_verified=true，guest/host cleanup=true。
- [x] C 卷自建私有父目录内，正式 `velo-writeroots149-c71e-c` push 在 VERIFYING
  返回 windows_acl_untrusted_write，published_ever=false，最终目的目录不存在。
  原生 ACL 预检复现同码；E 卷同样的私有父目录预检通过。
  原因是应用检查整个祖先链，C 卷根 ACL 允许 Authenticated Users 写入，
  在 windows_platform.WindowsAclVerifier 中被判定为不受信任写权限。
  即使测试父目录只有 SYSTEM/Administrators，祖先 C:\ 仍使其拒绝。
  这是应用完整性门禁，不能称为 SYSTEM 遭操作系统拒绝访问。
- [x] C 失败的 guest task、worker 错误、host journal/package/result 和未发布
  `.velo-stage-*` 原件保留；没有用广泛删除或 ACL 放行掩盖失败，
  不将该任务标记为 COMPLETE/cleanup 成功。
- [x] 最终 SCM Running/Auto，实际 PID7016、NT AUTHORITY/SYSTEM；daily verify
  通过，keepalive 启用、LastTaskResult=0、Windows-MCP 任务 Running。
  RootLease active=null、实际 worker=0；126 个基线进程中 121 个 PID/创建时间
  保持，5 个变化是原 Velo 与临时控制 shell。dnSpy、FakeNet、Windows-MCP、
  两个 Velociraptor、Explorer 和 Everything 均保持原 PID/创建时间。
- [x] 本地提交前记录及清单逐项核对；提交仅含本次文档，不推送。

候选初次验收调用了不存在的 capabilities 方法，随后修正为实际
transfer_capabilities 后通过，发生在正式策略替换前；失败工具记录保留。
本次没有改代码，无新增模型测试；验收是上述原生加载、SDK 和实际 push，
不宣称 C 卷写入、全库测试或所有磁盘上的任意目录写入成功。

## 仍然生效的限制

1. **ACL 与操作系统权限**：写入父目录、stage/final 及整个祖先链需通过 owner/DACL
   校验；普通用户可写的祖先会拒绝，parent/stage 还拒绝不受信任读权限。
   受保护私有配置/状态继续严格验证。SYSTEM 不自动使用备份权限绕过显式拒绝、
   EFS 或共享锁，文件仍须实际可读/可写。当前 C 卷写入另受上述祖先门禁阻止。
2. **写入语义**：push 发布一个新目录，父目录必须存在，最终目录必须不存在；
   不合并或覆盖已有目录/文件。临时 stage 位于同一父目录，以同卷不覆盖原子
   rename 发布；失败不以拷贝替代原子发布，也不无条件删除残留。
3. **路径/内容**：只接受规范绝对路径和普通文件/目录；祖先及成员的 symlink、
   junction/reparse、设备路径、ADS、dot/短文件名/保留名称等别名会拒绝。
   重名、大小写冲突、内容变化、清单/包/目标 SHA 或身份不符也会拒绝。
   普通 UNC/网络共享没有被本次本地盘根策略授权。
4. **生产和身份**：仍要求 producer_complete/quiescent、有限请求期限、正确 VM UUID
   和 boot identity；bearer/会话/Host/Origin/协议约束保持。该 work root 的实际
   guest worker 一次只运行一个；旧失败任务不会自动冒充成功或自动删除。
5. **预算**：当前 policy 上限如下，请求可以进一步降低上限但不能突破策略，
   请求 min_free_bytes 也不能低于策略；没有另外增加固定单文件大小上限。

| 项目 | 当前策略值 |
| --- | --- |
| 文件数量 | 100,000 |
| 逻辑内容总量 | 16 GiB |
| 传输包总量 | 17 GiB |
| 元数据 / 状态大小 | 各 64 MiB |
| 必须额外保留的可用磁盘空间 | 8 GiB |
| 单个原始 chunk / 每批 chunks | 32 MiB / 32 |
| 任务最长期限 | 24 小时 |

包解压仍有内容集合、类型、大小和膨胀比例校验。空间在内部 work_root 和目的卷
的相关操作阶段检查，允许写某个卷不代表其空间、ACL 或原子发布条件已满足。

## 证据与后续边界

VM 原件在部署目录 `Logs/velo-writeroots149-20261008-c71e/`；宿主原件在
`/tmp/velo-writeroots149-20261008-c71e/`，含 `sdk-verification.json`、
`native-evidence.json`、`verification.json` 与正式任务 evidence。
本次配置修改完成；下一项独立工作是决定如何支持普通用户可写祖先下的安全
发布，再实现和原生验收相应门禁。不能通过修改整个 C 卷 ACL 或把普通用户
加入所有私有状态信任来把当前拒绝当作已解决。

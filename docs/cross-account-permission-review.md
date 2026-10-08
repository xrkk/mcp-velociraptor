# .149 跨工具文件权限核查（2026-10-08）

已复现的八文件回收失败由读取权限缺失直接导致：服务创建的三个文件
可读，管理员创建的五个文件不可读；正式 worker 保留了具体路径、
`operation=open`、`PermissionError` 和 `errno=13`。补齐服务读取权限后，
八文件完整回收、内容 SHA-256 和双方清理均通过。
详见[实机验收记录](transfer-source-handoff-verification.md)。
`OWNER RIGHTS` 适用于对象当前所有者，不等同于授予另一服务账号读取权限。
来源：[Microsoft SID 定义](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)。

## 实机只读观察

本次通过 Windows-MCP 查询 SCM、计划任务、ACL 和策略的路径字段，
通过 FakeNet MCP 查询状态与产物；没有启动捕获、修改 ACL、读取密钥内容
或修改两个生产方仓库。

| 组件 | .149 当前执行身份 | 当前观察 |
| --- | --- | --- |
| Windows-MCP | `DESKTOP-3FI41GR\xxx`，管理员提升 | 自启动任务为 Interactive、Highest |
| FakeNet MCP | `LocalSystem` | SCM 服务 Running；捕获状态 stopped，无选定 run 或注册产物 |
| Velo MCP / pull worker | `NT SERVICE\mcp-velociraptor` | 正式服务 Running，PID 6856 |

活动 Velo 策略只允许 `E:\VeloTransfer-149\data` 作为 read/write root，
`E:\VeloTransfer-149\transfer` 为 work root。data 和 work 根都有可继承的
服务 Modify 授权。因此，正常继承这些授权的新文件不会仅因管理员所有权
而必然失败；受保护 DACL、移动带来的旧 ACL、替换为新对象仍须分别检查。
路径范围由 [policy.py](../velo_transfer/policy.py) 的 `resolve_local` 执行，
范围允许与操作系统可读性是两个条件。

## 已确认的边界及条件风险

1. **Windows-MCP 创建/移动输出，没有自动向 Velo 交接权限。**
   FileSystem 的相对源/目的路径默认解析到当前用户桌面；PowerShell 的工作
   目录是用户 home，不能假定相对输出落在 Velo read root。
   文件操作使用普通 `open`、`copy2/copytree`、`shutil.move`，没有服务 SID
   授权步骤。管理员写入成功只证明管理员可写。
   同卷 rename/move 可能保留原 ACL；把私有文件移动进已授权目录，不能代替
   最终对象权限验证。来源：Windows-MCP
   `src/windows_mcp/tools/filesystem.py:41–46`、
   `src/windows_mcp/powershell/service.py:206–212`、
   `src/windows_mcp/filesystem/service.py:62–136`；
   [Python shutil.move](https://docs.python.org/3/library/shutil.html#shutil.move)、
   [Microsoft 文件安全](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)。

2. **FakeNet 的受保护退出诊断目录有明确的账号边界。**
   实机 `C:\ProgramData\FakeNet-NG-MCP\logs\exit-evidence` 的 DACL
   受保护，只有 SYSTEM 和 Administrators 两个 FullControl ACE。
   FakeNet 源码要求恰好这两个 ACE；递归向这里补 Velo ACE，会违反其校验。
   应通过生产方已有的复制导出生成独立产物，再交接导出副本。
   已有 incident 流程会校验受保护 dump 的身份、大小和 SHA-256，复制到
   新建的 `userdump.dmp.partial` 后发布为普通 incident 产物。
   来源：flare-fakenet-ng `fakenet/mcp/exit_files.py:17–20`、
   `fakenet/mcp/exit_installation.py:84–113`、
   `fakenet/mcp/incident.py:298–302,321–355`，以及本次实机 Get-Acl。

3. **普通 FakeNet 产物还有路径范围和继承条件，未证明现在都不可读。**
   默认输出在 ProgramData 的 `FakeNet-NG-MCP\artifacts` 下，当前不在
   Velo 活动 read root；生产方没有自动配置 Velo 的读取授权。
   实机 artifacts 根为空，继承 Users ReadAndExecute 及目录 Write
   （mask 278、ContainerInherit），SYSTEM/admins FullControl。
   不能仅凭没有显式服务 ACE，断言所有普通产物读取都会失败。
   来源：flare-fakenet-ng `fakenet/mcp/paths.py:58–75`、
   `fakenet/mcp/supervisor.py:160–171`、
   `fakenet/mcp/artifacts.py:153–158`，以及本次实机策略、Get-Acl 和
   FakeNet `get_status/list_artifacts`。

4. **Velo 密钥/配置的新文件替换可能丢失逐文件授权。**
   实机 secrets 目录只给服务目录自身 ReadAndExecute，不向新子文件继承；
   `mcp-service.env`、`transfer-policy.json` 和 `api_client.yaml` 各自有
   显式服务 Read。直接编辑同一文件不必然丢失 ACL，但删后新建或以没有
   该 ACE 的临时文件替换，可能使服务下一次加载配置失败。
   更新方应验证最终对象的读权；产物交接脚本不处理 secrets 或 work root。
   来源：本次实机 Get-Acl；
   [权限交接边界](transfer-windows-platform.md)、
   [configure_transfer_source_access.ps1](../configure_transfer_source_access.ps1)。
   替换行为取决于 API：Windows `ReplaceFile` 可保留原 ACL，不能把所有
   “原子替换”一概判为丢失权限。
   来源：[Microsoft Moving and Replacing Files](https://learn.microsoft.com/en-us/windows/win32/fileio/moving-and-replacing-files)。

## 验证范围与下一步

本次还直接运行了部署中的 `WindowsAclVerifier`，把 Velo 服务 SID 加入
可信集合：data 的 `read_root` 检查接受，FakeNet artifacts 的检查返回
`windows_acl_untrusted_write`。这是该校验器对实际 ACL 的检查结果，
**不是实际 pull 或新增策略后的拒绝复现**；当前 pull 的路径解析并未对
read root 自动调用这一检查。不要把它当成已经发生的回收错误。
来源：[windows_platform.py](../velo_transfer/windows_platform.py) 的
`WindowsAclVerifier/_evaluate`、[policy.py](../velo_transfer/policy.py)。

本次源码基线：flare-fakenet-ng `3ed8592`，Windows-MCP `7c88f7f`；
Windows-MCP 既有未提交工作保持原样。普通 PCAP/HTTP/incident 产物没有
新的跨工具端到端验收，因为当前没有活动或选定捕获产物。

下一步应让两种生产流程把完成且关闭的导出副本写入策略允许的专用目录，
执行 configure/verify，再由真实 Velo worker 读取并核对回收 SHA-256。
分别覆盖新文件、同卷移动的私有文件和发布替换后的文件。
保留 FakeNet 退出诊断目录的原 ACL 合同；配置/密钥更新单独检查最终对象。
当前数据根的既有 Modify 授权未在本次扩大，源产物交接只补读取权限。
文件占用或生产方尚未关闭句柄也可导致打开失败，需要看底层错误区分，
不能把每次 `source_unavailable` 都归因于 ACL。

# .149 内容发布的卷根 ACL 校验修复

用户于 2026-10-08 授权调整 C 卷祖先校验，并询问 SYSTEM 模式下 Velo 产物
是否仅 SYSTEM 可读写。本次调整内容发布门禁，不修改现有卷/源/目标父目录 ACL，
不扩大私有配置/状态信任，不改变已授权的 read/write roots、预算或 VM 身份。
仅维护 Velo 服务，不重启 VM、不恢复快照、不停止其他应用。

## 实现边界

原门禁把 C:\ 的普通账号创建/修改授权也当作替换受保护下级目录的能力。
现在仅在内容 stage/parent 的**祖先**检查中，对规范盘根加一项原生资格检查：
GetDriveTypeW 必须为 DRIVE_FIXED，GetVolumeNameForVolumeMountPointW 必须返回
真实卷 GUID 路径；不合格的 drive/UNC/device alias 仍使用原严格检查。

合格盘根仍要求可信 owner、可解析 ACL、稳定 identity/ACL、无 reparse。
普通创建同级目录的权限不再单独导致拒绝；实际 DELETE_CHILD、WRITE_DAC、
WRITE_OWNER、GENERIC_ALL 的不可信授权仍拒绝。INHERIT_ONLY ACE 不控制盘根
自身，真实下级对象仍逐个执行原校验。卷根不能作为普通子目录被重命名/删除，
不把卷根 DELETE 本身等同于删除受保护子项的 DELETE_CHILD。

**私有父目录、stage/final、普通中间祖先及 policy/work/store 门禁保持严格。**
这允许 C 卷安全专用目录发布，不允许任意普通账号可写/可读目录直接发布。
不向信任 SID 列表加入普通用户，也不自动修复或公开输出 ACL。

ACL 失败现在附带 offending path、requested_path、acl_kind；prepare_staging
保留这些字段及已有 native diagnostics，同时以自己的实际 stage identity 和
registered=false 覆盖错误方不能确认的注册状态。应用 ACL 拒绝没有底层
Win32 拒绝码时，不编造 PermissionError/winerror。

## 清单与实际验证

- [x] 保存原策略/配置/代码 SHA、SDDL、服务、进程、C 卷根/父目录基线；确认
  RootLease active=null、worker=0。
- [x] scoped 回归最终 Ran49，47 通过、2 Windows-only 跳过：标准 C 卷根内容
  通过，其他私有 gate、实际删除子项/安全控制权、不可信 owner、非合格盘根、
  私有父目录与普通中间祖先继续拒绝；stage 诊断路径/native context 保留。
  沙箱 UID 映射导致的初次七项既有失败保留，真实宿主权限视图重跑通过，
  未修改属主保护来绕过失败。
- [x] 四个封闭候选文件通过正式 push 暂存；只替换 windows_platform.py 和
  bundle.py，保存原件、匹配源 SHA、保留 owner/DACL；原生新增卷根回归五项通过。
  只维护 mcp-velociraptor/keepalive，Stop-Service 报错后独立 SCM=Stopped 才部署，
  未强杀；部署 finally 恢复服务及保活。
- [x] 原生 fixed-volume 检测 C:/E: 均为 true；两个原私有父目录 ACL 预检通过，
  自建 AU Modify 的 shared 父目录预检仍返回 windows_acl_untrusted_write。
- [x] `velo-content-acl149-d52a-c` 与 `velo-content-acl149-d52a-e` 两个正式 push
  均达到 COMPLETE，destination_verified=true，guest/host cleanup=true。
  两卷各发布一个 58 字节文件；VM 独立重读大小/SHA 与宿主源及正式清单一致：
  `5175e2e658b30679fd47191c1fa5fbd820550caad91f270b45d08f2653475ff8`。
- [x] `velo-content-acl149-d52a-shared` 在 VERIFYING 拒绝，published_ever=false，
  目的目录不存在；worker 原件保留 shared 祖先的具体路径、requested stage
  路径、acl_kind=ancestor、stage identity 和 registered=false。
  该 incomplete 任务、package、stage 和旧 C 失败原件保留，不冒充清理成功。
- [x] 独立鉴权 SDK initialize、137 项 tools/list 和 capabilities 通过；四个读根、
  三个写根、原 UUID/boot identity/limits 均保持。policy/env/API SHA 与 ACL 不变，
  C 卷根及原测试父目录 SDDL 不变，部署代码 SHA/ACL 再核对通过。
- [x] 最终服务 Running/Auto，实际 PID5904、NT AUTHORITY/SYSTEM；daily verify
  通过，keepalive 启用、LastTaskResult=0，RootLease active=null、worker=0。
  dnSpy、FakeNet、Windows-MCP、两个 Velociraptor、Explorer 和 Everything
  保持原 PID/创建时间。127 个基线进程中 120 个保持，另 7 个差异原件保留：
  原 Velo/临时 shell 五个，以及 taskhostw/svchost 两个；未向其他程序发送停止指令。
- [x] Python 编译、git diff --check、文档及记录逐项核对；创建本地提交，不推送。

部署代码 SHA256：windows_platform.py 为
`ac4a251ddf41f0a6e4505ad8eb88ad5a796592277470f311d307253a3f20fa09`；
bundle.py 为 `5b5b05516fd65747024e220eae751563e1eff4da30dbf15df2a99ab36fe42e83`。
此次是模型权限回归加 .149 原生发布验收，不宣称整库测试、任意目标目录、
断电持久性或对管理员/同账号恶意干预的完整证明。

## 发布件默认权限

.149 实际使用 Python 3.13.7；prepare_staging 用 os.mkdir(..., 0o700) 建私有目录。
[Python 3.13 文档](https://docs.python.org/3.13/library/os.html#os.mkdir)说明 Windows
对该 mode 特别设置当前用户及管理员可访问的 ACL。发布同父目录原子 rename
保留该私有目录；文件在 stage 中新建并继承其 ACL，不复制宿主源文件的 DACL。

C/E 本次实际回读相同：

| 对象 | 实际 owner | DACL |
| --- | --- | --- |
| 发布目录 | BUILTIN\Administrators | protected；SYSTEM、Administrators、OWNER RIGHTS 各 OICI FullControl |
| 目录内文件 | BUILTIN\Administrators | 从目录继承 SYSTEM、Administrators、OWNER RIGHTS FullControl |

所以它们**不是 SYSTEM 独占**，SYSTEM 及提升运行的管理员可以读写；普通用户
没有读写授权。OWNER RIGHTS 仅针对实际 owner，不自动授权每个文件创建者或
其他用户。没有另建普通用户会话做访问试验；上述结论来自原生 owner/DACL
回读，管理员会话读取 SHA 已成功。非提升管理员需按实际 UAC token 判断。
其他 MCP 若以 SYSTEM/提升管理员运行可按这些 ACL 访问；普通身份的消费者
需显式导出/交接授权，本次没有增加此授权或改变输出默认权限。

范围仅指本地 guest push 的发布件，不代表 Velociraptor collection 下载、宿主
pull 接收件或其他工具任意文件创建也采用同一 DACL。

## 证据及主 API 依据

VM 原件在部署目录 `Logs/velo-content-acl149-20261008-d52a/`；宿主在
`/tmp/velo-content-acl149-20261008-d52a/`，含 `sdk-verification.json`、
`native-evidence.json`、`verification.json`、资产 SHA 和正式任务 evidence。
源代码/原配置备份及全部失败原件保留，没有发布凭据内容。

- Microsoft [File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)：文件/目录权利及继承。
- Microsoft [ACE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header)：INHERIT_ONLY 不控制当前对象。
- Microsoft [GetVolumeNameForVolumeMountPointW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumenameforvolumemountpointw)：由真实卷挂载点取得 GUID 路径。

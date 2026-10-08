# .149 双向文件访问及输出权限交接

2026-10-08：按用户最终要求完成实现、部署及 .149 实机验收。Velo 使用 SYSTEM
读取当前可访问的 C/E 全卷；宿主推送到 guest 的新批次自动把输出交给普通用户、
管理员及其他常规 MCP/服务身份读写。没有重启 VM、恢复快照或停止其他应用。

## 当前配置和访问范围

SCM 服务 `mcp-velociraptor` 使用 `LocalSystem`，实际服务进程为 SYSTEM。
受保护的服务环境新增 `VELOCIRAPTOR_TRANSFER_OUTPUT_ACCESS=shared_modify`。
未设置时仍为 `private`；非法值启动失败。模式在 transfer_begin 时写入私有任务
状态，重启修改模式不改变已开始任务；旧任务没有该字段时按 private 处理。

| 配置 | .149 实际值 |
| --- | --- |
| read_roots | `E:\VeloTransfer-149\data`、`E:\VeloTransfer-149\artifact-export`、`C:\`、`E:\` |
| write_roots | `E:\VeloTransfer-149\data`、`C:\`、`E:\` |
| work_root | `E:\VeloTransfer-149\transfer`，继续私有 |

C/E 是当前已挂载、可访问的 NTFS 文件系统；D 是无介质光驱，未挂载 EFI 分区
不属于当前可访问路径。新增或新挂载文件系统需要更新 roots；本次没有实现自动
发现新盘。全卷 roots 消除了传输路径白名单限制，没有绕过 Windows 的实际拒绝、
独占占用、EFS 密钥需求或受限 token，也没有新增 VSS/备份权限读取实现。
遇到这些情况保留具体路径及可用底层错误，不宣称每个系统文件都能无条件读取。

原请求/工具名称不变，仍有 137 个工具；正式传输响应契约新增可选
`output_access_mode` 能力字段及 `output_access` 交接 receipt，以及对应错误码。
宿主和 guest 必须使用匹配的契约资源。本次已核对资源 SHA 一致并通过真实 SDK。

## push 的自动权限交接

shared_modify 接受普通账号拥有或可写的目标父目录与祖先；要求路径、identity、
ACL 解析和稳定性校验仍通过，拒绝 reparse。真正的 stage 仍要求可信 owner 和
私有 DACL。此选项不把普通账号加入 policy/work/state 的私有信任 SID 集合。
在 work_root 或策略文件所在 secrets 目录内创建共享输出会返回
`private_output_target`，防止把内部状态/配置输出变为普通用户可编辑。

流程：私有 stage → 清单/内容验证 → 原子发布 → 删除本任务临时包/账本 →
再次验证输出内容 → 私有任务状态持久化确切交接意图 → 给本批输出对象授予
权限并回读验证 → 等实际 worker 停止、lease 释放 → 双端清理确认 → COMPLETE。
交接发生在 guest release worker 内；ACL 失败不会产生完成 receipt 或 COMPLETE。

| 主体 | SID | 新增权限 |
| --- | --- | --- |
| BUILTIN\Users | `S-1-5-32-545` | Modify |
| Authenticated Users | `S-1-5-11` | Modify |
| SERVICE | `S-1-5-6` | Modify |

普通本地用户由 Users 覆盖，常规其他 MCP 用户由 Users/Authenticated Users
覆盖，LocalService/NetworkService 等服务由 SERVICE 覆盖。保留原 owner 和
SYSTEM/Administrators 等既有 ACE；没有给这些共享主体增加 WRITE_DAC、
WRITE_OWNER 或 FullControl。受限/沙箱 token 或已有显式 Deny 仍以 OS 实际
访问结果为准，不能用静态群组名称承诺所有特殊 token。

本批已有文件、根目录、嵌套目录及空目录逐个授予；目录使用 OI/CI 继承，
因而以后在这些目录内新建的内容也能被上述用户读写。包含有 protected DACL
的子目录时仍显式授予，不依赖单一顶层继承。校验后先固定所有祖先和清单对象
的原生句柄/文件 identity，再修改 ACL；拒绝链接/非单链接文件，不修改祖先
或卷根 ACL。最终根目录最后授权。

私有状态保存绑定 publication、manifest、目录 identity 和主体列表的意图及
交接 receipt。失败/部分交接后可按同一意图重试，必须重新验证内容和 identity。
授予普通用户 Modify 后，他们可以修改、重命名或删除产物；内容 SHA 证明的是
交接前验证的字节，不保证后续编辑后的字节相同，也不保证多对象 ACL 更新原子性。
其他 MCP 新建到别处的文件不由本功能自动修改 ACL；Velo 以 SYSTEM 原样读取。
此前已经完成的 private 输出不会因部署新模式自动重新授权。

## 错误诊断

源文件读取继续使用 `source_io_error`，保留 path、operation、errno、winerror、
os_error 和异常类型。新增 ACL 查询/授权诊断保留确切失败文件或目录路径、
GetNamedSecurityInfoW/CreateFileW/GetSecurityInfo/SetEntriesInAclW/
SetSecurityInfo 等实际操作名及可用 Win32 错误文本/码。原生错误使用真实
ctypes.WinError；应用层门禁没有 Win32 错误时不编造拒绝访问码。

worker 私有 `worker-error-<nonce>.json` 和结构化诊断保存这些信息，公开状态保留
稳定错误码。专项真实 worker 测试注入 `SetSecurityInfo` 的 winerror=5，验证
具体 child 路径/底层错误原样保存、未完成，并验证同一持久化意图重试后可完成；
这是故障注入回归，不能声称实机曾发生此次原生拒绝。

## 验收结果和遗漏核对

- [x] **guest → host**：C/E 两个关闭、DACL 仅 SYSTEM FullControl 的源文件，
  使用正式 pull `velo-shared-output149-a8c1-system-pull` 整批 COMPLETE，2 文件，
  宿主 SHA 与源一致；未改变源 ACL。
- [x] **host → guest**：目标父目录本身允许 Users Modify；C/E 正式 push
  `velo-shared-output149-a8c1-c2`、`velo-shared-output149-a8c1-e` 均 COMPLETE，
  每批 2 文件、6 个交接对象，含嵌套和空目录。最终诊断小修部署后新增 C 正式
  push `velo-shared-output149-a8c1-final-check` 也 COMPLETE。所有正式结果均
  destination_verified=true、guest/host cleanup=true。
- [x] **普通用户实测**：使用 .149 Explorer 的真实非提升 token，elevated=false、
  Administrators 未启用，实际 C/E 文件读取、原文件写入、重命名、新嵌套目录/
  文件读写及删除全部成功；最后一批 C 输出再次通过同样试验。没有新建账号，
  提升管理员操作没有冒充普通用户测试。
- [x] **服务实测**：受控一次性任务分别使用 LocalService（S-1-5-19）、
  NetworkService（S-1-5-20）的实际服务账号，在 C/E 输出上读取/写入现有文件、
  新建嵌套文件并读写/删除成功；任务结果均为 0。保存私有 receipt 后移除本次
  专属任务/临时结果。SYSTEM/admin 原有 FullControl 通过 native owner/DACL 回读
  保持；没有逐个 impersonate 所有其他 MCP 用户。
- [x] **完整性**：试验对原文件写回原字节，移除新建试验件；独立 SHA 与正式
  清单一致。`output.txt` SHA 为
  `56c5ae7d882784ca4746eeaa8e2b7ad4d1e697a6fd2a2c7e0a989dfbe0ad82a3`，
  嵌套 `child.txt` 为
  `7f731919a225aeb4a9ca4001384c6d432802c05536243a1828cc6d11bef63934`。
- [x] **回归**：127 项专项测试执行完成，125 通过、2 个原生 Windows 平台项
  在宿主跳过；另在 .149 实测原生授权、FileIdInfo/identity、继承和上述 token。
  覆盖模式绑定/默认 private、私有范围排除、交接失败/日志/重试、父目录门禁、
  内容/协议/真实 worker 清理及正式 JSON Schema 验证。Python 编译通过。
- [x] **源码闭包**：将新增模块及回归依赖登记到 PC026 显式本地模块目录，
  防止隔离源码遗漏被当作外部依赖；没有修改或生成生产 approval/freeze。
- [x] **部署核对**：最终四个运行文件的 guest/host SHA 相同，服务 Running/Auto，
  实际 PID524、LocalSystem；daily verify 通过，keepalive Ready/result=0，lease=null、
  worker=0。policy/API 内容和三份私有文件 ACL 未变，env 仅增加新选项；C/E 卷根
  ACL 未变。dnSpy、FakeNet、Windows-MCP、Velociraptor、Explorer、Everything
  的原 PID/创建时间均保持；127 个基线进程中 122 个保持，其余 5 个是旧 Velo/
  临时 shell/conhost，差异完整记录。
- [x] **文档**：两份 README 更新，前次门禁文档的未实施设计明确标记历史，
  本记录对照双向访问、普通用户及服务身份、日志、部署和不中断 VM 逐项核对。
- [x] **本地提交**：本功能按专项验收及文档核对结果作为独立本地提交交付，
  提交号见该文件的 git 记录；保留其他并行工作，不推送。

不能将上述专项验收称为整库全绿：初次宽一点的回归有两个旧 golden equality
失败，原版本 `47617b5` 的生产契约已与保留 golden 不一致；该基线差异已另存
核对，本次没有覆盖历史 golden。最终专项明确排除这两个旧 equality 检查，
新能力/receipt 使用当前正式契约校验和真实 SDK/正式 push 验证。

首次 C 试验 `velo-shared-output149-a8c1-c` 因能力新增字段尚未同步正式契约而在
PREPARING 返回 protocol_error，无 guest 任务/发布；保存失败原件后修正契约，
用独立 c2/e/final-check 任务验收，没有把失败改写为成功。

## 原件位置和维护

VM 原件：部署目录 `Logs/velo-shared-output149-20261008-a8c1/`，包括 baseline、
deployment/final-deployment、final-state、ordinary-user 两次探针、服务账号 receipt、
原生探针、output-files 及代码备份。宿主原件：
`/tmp/velo-shared-output149-20261008-a8c1/` 的各正式任务 evidence、SDK 结果、
scoped-tests.log、native-access.json、final-state.json、verification.json。
普通控制 token 无法取得 SYSTEM-only 源的哈希，该次空观察保留；独立 SYSTEM
`Windows.System.PowerShell` flow `F.DB3P485JGFNNM` 最终重读两源 SHA/ACL，与
正式 pull 的宿主结果一致，原件另存 system-source-hashes.json。
证据内没有凭据内容；失败任务和旧私有件仍保留。

| 最终运行文件 | SHA256 |
| --- | --- |
| output_access.py | `29ed3cba5514882723379bd4ff37d6d139f687acd79dee3a1fd1d431bbced4d4` |
| guest_service.py | `90471b8f38b819b24a1f0f4b3e22a386129e37db08fa36a9d0c126d1de80eaed` |
| windows_platform.py | `8bb0fd227c78eed787952068e384d0fcc58fc3a7869966edc212aa12e368c63e` |
| transfer_tools_schema.json | `e98e961801e7fbe453ee2f0e13cf66b568b2760a8370069b9ee86902493b8d9d` |

日常使用现有 host coordinator/CLI push/pull，无需每批手动 icacls；目的目录沿用
传输协议要求的新目录，保持 producer 完成/静止和预算约束。未来有新增盘时只
维护 roots；模式变更通过受保护服务 env 更新流程并只重启 Velo，勿重启 VM。

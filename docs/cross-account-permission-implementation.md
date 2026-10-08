# 跨账号权限交接实施与验收记录

## 授权、范围与完成条件

用户于 2026-10-08 授权：先记录评估和步骤，再逐步推进全部完成；
宣布完成前必须核对记录是否遗漏。涉及 Velo、Windows-MCP、FakeNet-NG
的生产/导出交接与 .149 实机测试，不包括推送代码或扩大服务账号权限。

评估原始记录：[跨工具权限核查](cross-account-permission-review.md)，
提交 `76427da`。原问题修复提交 `d1ffd16`、`2cda973`；
[八文件实机验收](transfer-source-handoff-verification.md) 已完成。
这些已有验收不替代下列生产流程接入与联合验收。

确认事实：Windows-MCP 为提升的交互用户，FakeNet 为 LocalSystem，
Velo 为专用服务账号。OWNER RIGHTS 不保证另一账号能读取。
普通 FakeNet 产物目前在活动 read root 外；受保护 exit-evidence
要求精确 SYSTEM/admins 两 ACE，不能递归加第三个服务 ACE。
Velo secrets 的现有服务读权为逐文件授权，新对象替换须重新验证。
静态 ACL 检查、SOURCE_READY、模拟对象均不能冒充 COMPLETE。

## 分阶段清单

状态仅在保存相应代码/命令和证据后更新；失败也保存，不覆盖为成功。

| ID | 工作及验收条件 | 状态与证据 |
| --- | --- | --- |
| B1 | 记录三个仓库版本、既有脏文件、运行账号、服务/任务及 ACL 基线 | 完成；三个仓库/账号/服务/任务/根ACL基线，见轮次1；嵌套FakeNet配置前置SHA遗漏及替代观察边界明确记录于轮次7 |
| B2 | 留存原负向/八文件成功记录，建立无害且隔离的验收样本 | 完成；原失败/八文件记录保留；隔离 Windows、SYSTEM 格式和 owned managed dump 样本，轮次2–6 |
| C1 | 定义文本、报告、PCAP、HTTP、dump 的生产方/消费方/路径/关闭证据 | 完成；生产/消费/关闭契约及实际 HTTP/log、SYSTEM PCAP/report 格式、controlled incident copy，轮次6；格式测试不代表 live interception |
| C2 | 独立定义配置/密钥更新、Read 与生产方写/覆盖/删除权限 | 完成；独立私有替换契约/native读权与保密拒绝、生产方创建/覆盖/删除权限与服务只读分离；service-file-updates.md，轮次2–3 |
| D1 | 配置专用精确 read root；现有及新建嵌套对象权限验证 | 完成；独立 artifact-export exact read root，SYSTEM/admins FC、服务仅 Read；两批新嵌套对象实机验证 |
| D2 | 策略变更备份及服务/keepalive/传输能力验证 | 完成；政策保留备份/原 ACL，恢复原政策后正式 capabilities enabled；重新加载后 windows-02 COMPLETE，keepalive enabled |
| W1 | Windows-MCP 显式绝对路径产物交接；生产结束后 configure/verify | 完成；Windows-MCP 正式入口 export 后 windows-01 COMPLETE，原件字节/ACL 不变 |
| W2 | 新建、移动、复制、覆盖、替换后的最终对象交接 | 完成；正式 write/copy/move/overwrite、protected 同卷移动及原子替换最终对象；七文件加 receipt 回收 |
| W3 | Windows-MCP 复制/移动失败保留两端路径、操作、原生异常 | 完成；247126d 已加载正式 listener；实测拒绝复制保留中文两端路径、PermissionError/errno13，native winerror 为空如实保留 |
| F1 | FakeNet 根据写入停止与登记信息导出最终普通产物 | 完成；正式 stopped/consistent/nonpartial overview、真实 HTTP closed publication、官方 wrapper；轮次5–6 |
| F2 | 导出副本大小/SHA-256 验证，再权限交接与 Velo 回收 | 完成；19项独立复制/receipt/SHA/原件 ACL保持，20文件正式 COMPLETE 双端清理；轮次6 |
| F3 | incident/dump 经受控导出，原始 exit-evidence 精确 ACL 保持 | 完成；真实 owned child bounded dump→实际 IncidentCollector 控制复制→publication→export→COMPLETE；原 protected source 字节/两ACE保持；轮次5–6 |
| S1 | 配置/密钥最终对象读权与保密边界验证，替换方式明确 | 完成；三个正式 policy/env/API 文件 verify 通过，私有原 owner/DACL 保持，env/API 内容哈希未改 |
| S2 | 更新后真实加载/重启成功；失败诊断和备份恢复流程 | 完成；政策实际 replace/restore、caps enabled、再 replace 后实际下一批 COMPLETE；原生隔离测试覆盖拒绝输入/备份恢复 |
| T1 | 管理员、SYSTEM、服务产物及后续新嵌套文件：正式 worker COMPLETE | 完成；管理员 windows-01/02、SYSTEM FakeNet01、service-owned 均正式 COMPLETE；不以 ACL 模拟替代读取 |
| T2 | 私有同卷移动、protected DACL、发布替换：修复或明确拒绝 | 完成；protected 同卷移动/原子替换最终对象独立导出与正式 pull；scoped repair/native拒绝，轮次2–3 |
| T3 | deny ACE、reparse、策略外路径：受限拒绝且原对象无误修改 | 完成；native group deny/reparse/策略外拒绝且原 ACL保持；正式 private源 Win32 5、策略外 path_outside_root，均未发布；轮次2、5 |
| T4 | 未关闭/持续写入/文件占用：区分完成条件、共享冲突和 ACL 拒绝 | 完成；native 未完成声明/未公布/held writer Win32 32拒绝；正式 healthy overview拒绝、无输出/manifest/根ACL变更；轮次2、6 |
| T5 | 每条正向：独立内容/SHA-256 检查，双方清理完成 | 完成；五条产物正向共44文件独立大小/SHA、receipt、destination_verified及双端cleanup true；轮次3、5–7 |
| J1 | .149 三条链路：Windows-MCP、FakeNet 普通产物、incident 导出 | 完成；Windows 正式8文件、FakeNet 普通/HTTP/格式与incident正式20文件，独立哈希/双端清理；轮次3、6 |
| J2 | 重复交接、下一批新产物、服务重启后行为 | 完成；Windows新嵌套批/策略恢复再加载；FakeNet受控单服务重启后新run/13文件COMPLETE、重复16对象ACL幂等；轮次3、6–7 |
| R1 | 文档、启动/参数说明、失败排查与证据记录同步；分阶段本地提交 | 完成；四README/两producer文档/共享与私有配置/审计记录同步；分阶段本地提交，不push；记录旧golden差异与native资格范围 |
| R2 | 最终服务/任务/捕获状态恢复，原证据保留，无残留活动测试 worker | 完成；服务/任务Running、FakeNet恢复初始stopped/null配置；RootLease空闲、无owned child/helper/fixture/listener/recovery；保留原证据/完整包/精确清单，轮次7 |
| A1 | 逐条比对用户原八阶段、上述每个 ID、实际提交和实机结果；补遗漏 | 完成；八阶段与24个ID逐项核对，补齐HTTP/NoDivert/预检日志/build partition；明确前置配置SHA缺失、113/129进程及历史golden/native资格边界；轮次7 |

## 实施约束与记录格式

- 用户追加约束：不得随意重启 .149 或恢复虚拟机快照，已有其他程序运行。
  本任务不执行虚拟机重启/快照恢复，不终止其他程序；只使用隔离样本。
  单独 MCP 服务维护前先核对活动任务和影响，不能替代为整机重启。
- 路径通过部署配置传入，不硬编码用户路径/密钥，不输出密钥内容。
- 只在独立交接根配置源读权，原生产证据、work root、密钥分别处理。
- Windows-MCP 已有脏文件独立保留；其他仓库先检查再修改。
- FakeNet 负责实验网络生命周期；跨主机产物由 Velo 协调器传输。
- 实机维护前确认无活动任务，保存 ACL/策略/配置；保留失败记录。
- 每轮记录：目标 ID、改动与提交、验证命令/结果、证据、剩余问题。
- 最终审计不得用文档写完、单元测试或部分回收替代实机完成。

## 轮次记录

### 0：先记录范围

已把评估事实、原八阶段的细项和最终遗漏核对要求固定为本清单。
实施尚未完成；后续状态按证据逐项更新。

### 1：基线及 Windows-MCP 错误诊断

- 基线提交：Velo `8617fec`（包含评估与推进清单），FakeNet `3ed8592`，
  Windows-MCP `7c88f7f`；Windows-MCP 原 `.gitignore`、`PLAN/Windows-MCP.md`
  和未跟踪 PLAN 保持原样。
- 实机基线保存在忽略目录 `Logs/velo-handoff149-4021a688f4a0/baseline.json`，
  含服务/任务状态、ACL、其他进程 PID/创建时间及配置哈希，不含密钥内容。
- Windows-MCP 诊断四项测试先失败（缺两端路径和日志），修复后四项通过：
  `python -m unittest discover -s tests/portable -p test_filesystem_diagnostics.py -v`。
  Windows 隔离副本同样四项通过；本地提交 `247126d`。包含 read/write/
  copy/move/delete/list/search/info 的 OS 错误记录，写入内容不进入日志。
  这不是正式 Windows-MCP 服务已加载修复的证明。
- 初次资产推送因本次 payload 子目录默认组可写被拒；只收紧该专用目录后
  新 ID 再推送。第二次遇到既有 `windows_acl_path_changed`，未发布；
  第三次七文件推送 COMPLETE。所有失败和成功结果留在本次主机 journal。
- 第三次推送的 native 测试发现：作用于祖先的继承 ACE 会自动传播到
  无关批次，测试因此失败；候选修复把 scoped handoff 的祖先授权限制为
  目录自身。另修复 Windows PowerShell/GBK 测试输出解码失败。
  原失败见 `native-stage3-failure.json`。修正版仍待实机验收，不计完成。

### 2：共享导出、scoped ACL 与私有配置更新

- 共享导出 native 测试在 stage5 首次通过；stage7 最终候选再次通过。
  包含两批独立复制、源字节/ACL 保持、绑定 receipt、仅服务文件 Read、
  已有目的地/未完成生产方/未公布文件/错误 SHA/相对逃逸拒绝，以及真实
  文件写句柄共享冲突和 Win32 32、中文两端路径的 UTF-8 日志。
- scoped ACL native 测试在 stage4 通过；stage8 补齐 junction 后通过。
  覆盖祖先授权不传播无关批次、protected 修复、新嵌套文件、幂等、
  group deny 保持、策略外/ArtifactPath 外拒绝、真实 junction 拒绝且
  根和目标 ACL 不变。没有对真实 exit-evidence 进行递归授权。
- 私有配置 replace/restore native 测试 stage6、最终 stage7 均通过：
  原 owner/DACL、备份、最终 SHA 保持；无服务 Read 的新文件、公开可读
  替换输入和非授权目标被拒。使用无害临时文本，没有读真实凭据或重启服务。
- 本地 scoped 回归 50 项通过、3 项 Windows-only 跳过，编译通过。
- 最终候选为 stage8 十一文件正式推送 COMPLETE，结果与原生测试记录
  位于本次 journal、staging 和 Logs；这仍不代表生产链路或整项任务完成。

### 3：正式 Windows 交接、策略加载与新批次

- 在活动 worker lease 空闲后，仅维护 Velo MCP 服务，未操作虚拟机电源/快照。
  新 root 在原 write root 外；受保护 SYSTEM/admins FC，服务 Read/traverse。
  真实 policy/env/API 文件分别 verify；只有 policy 内容变更，所有 owner/DACL 保持。
  原政策恢复哈希与基线一致，正式端点 capabilities enabled；再应用新政策。
  SCM 维护发现瞬态 1061，保留原始结果；只在确认 STOPPED 后替换文件，
  不以强杀绕过；最终服务 Running、keepalive enabled。
- 正式 Windows-MCP 只刷新已核对 PID/创建时间/映像/命令的 listener，
  旧 PID 5040、新 PID 8380；没有终止其他 Python/PowerShell 程序。
  新/复制/移动/覆盖均走正式 FileSystem；protected 同卷移动与原子替换
  最终对象共七文件，经 wrapper 产生 receipt 后正式 pull 八文件 COMPLETE。
  `velo-handoff149-windows-01` destination_verified，cleanup guest/host true；
  另逐文件对照 receipt 的大小与 SHA，全部通过，源 ACL/内容保持。
- 再创建下一批中文嵌套文件，重复 configure/verify 通过；
  `velo-handoff149-windows-02` 两文件 COMPLETE，证明策略再加载后可继续生产。
- 正式 FileSystem 复制拒绝案例使用自建文件的当前用户 ReadData deny，
  保留 source/destination 中文绝对路径、PermissionError/errno13；
  实际 Python 异常没有 winerror，日志未编造 Win32 5。之后仅移除该测试 deny。

### 4：FakeNet 发现的生产完成与非权限失败

- 独立源码审计发现 HTTP POST `.txt` 缺少登记，初始证据保留在
  cross-account-handoff-source-audit.md。已修复闭合 registrar，从保留配置
  仅选择 enabled HTTP basename prefix + 时间戳；不扫描绝对/逃逸路径。
  真实登记测试先失败，修复后包括旧窗口、未发布、内容变化及显式闭合入口
  的 24 项通过；提交 5a958fa。
- 为避免影响其他程序，测试 DivertTraffic=No + 无 DNS/route 修改。
  两次实机启动均被正常回收：managed 健康检查强制要求 WinDivert；
  第二次真实 HTTP 请求还暴露 NBI callback(None) AttributeError，未产生 POST dump。
  两者都不是 ACL 拒绝；未把失败产物/启动误记为成功。相关 run 为
  fd83bd49-16cf-4e2d-88a6-34c95d01d502、a2b74d40-4d18-422a-b4d7-b6e1ab49a5ae。
  FakeNet 回到 stopped，exit-evidence 精确原 SDDL 未改。
- 修复显式非接管模式的真实 listener 健康观察与空 NBI callback，
  接管启用时的 native 捕获门槛保持；真实 HTTP listener 用例先失败后通过。
  scoped 共 29 通过、1 Linux 上 Windows-only 跳过；提交 6948bca。
  现从不可变 6948bca 使用既有固定 Docker/Wine 镜像执行完整候选 gate/build，
  未改变正式 FakeNet 包；Wine 结果不替代后续 .149 联合回收。
- 构建基线含其他同期 Linux 提交 1441fd6 等，不是本任务改动；
  本任务仅按明确文件清单提交自己的修改，保留了原 Windows PLAN 脏文件。

### 5：正式构建门禁、预检诊断补漏与 FakeNet 原生修复

- 原 full 构建因镜像缺 MinGit、Windows 错跑 Linux-only 部署用例失败，原
  6948bca gate XML/日志保留。使用既有 MinGit 固定镜像，并把 Linux deploy/update
  归入强制 HOST_ONLY_TESTS 门禁；该 partition 修复 31 项通过，提交 b201e71。
  不以跳过失败替代成功：不可变 b201e71 的 core gate 主项 2583 passed/11 已登记
  skipped、Windows-Python/MinGit sentinel（Wine）4 passed、HTTP 17 passed、Linux host 426 passed。
  candidate mcp-cb201e715-7046452e4b3c，ZIP SHA256
  7046452e4b3c975b26e96c30515d2e92961b536ce9175efbc9a922b4ba4b8088，
  196 个成员大小/SHA 校验通过；既有 native qualification 标签仍为 PARTIAL，
  不将本任务权限验收宣称为全捕获/驱动资格认证。
- 补漏发现：MCP 预检在 worker 之前拒绝路径时只返回 source_unavailable，
  既有 worker-error 日志不能覆盖。回归测试先失败，修复后 private bounded
  operation-errors.jsonl 保存路径/操作/errno/winerror/原生消息及绑定，MCP 仅返回
  代码；链接/满日志不覆盖原证据，stderr fallback。提交 3d2fc21。
  scoped 25 测试通过/1 native-only skipped。旧 golden schema 测试失败已保留；
  HEAD 原代码与补丁的全部 schema 独立比较完全相同，均与既有 golden 不匹配，
  未修改 golden 掩盖该历史差异。
- 仅在 lease_free 和 SCM stopped 后加载日志修复；实机新拒绝尝试
  velo-handoff149-source-denied-diagnostics 保留中文完整路径、lstat、errno13、
  Win32 5、原生“拒绝访问”，未创建 guest task/未发布文件。日志继承私有 work root
  的 service/SYSTEM/admins ACE，不能把其继承 ACL 误记为显式 protected DACL。
- FakeNet 包先完整校验，受控 stop marker succeeded 且 SCM stopped、无该包
  残留进程后，同卷保留完整旧包并替换完整候选，原 SCM/IFEO/helper 路径不变。
  原 stop 首次调用工具显示非零状态，随后读取独立 marker 证实受控停服已成功；
  未强杀/重启 VM/恢复快照。服务新 PID7536，控制 SDDL、恢复配置和 exit-evidence
  精确两 ACE 均保持。注册原包保留为 before-handoff-4021。
- 新正式 run a5246d17-d67c-4fab-8ac0-3744faf23a60：NoDivert healthy，真实 owned
  loopback HTTP POST 返回200并产生 closed dump；正式 stop outcome ok/version4。
  正式 overview 注册该 HTTP txt complete=true、size255、SHA
  59e4f3ecb60c0eea1e4aa95e963fc3679f9d6f9151a5ede48fff95d761efa1ec。
- 对该 owned healthy test child PID2740/creation134359218605546628 受控 bounded
  minidump（未制造崩溃）成功，size156758、SHA
  8efb31142ce9e4e4b57e1a084f04a54e6c58b76d790c03144ed43a9a42d312e7；
  原 dump 留在精确 protected exit-evidence 的本任务私有子目录，原 root ACL 不变。
  controlled incident copy/export/pull 与所有最终状态仍待完成，不能提前关闭 F3/J1。
- windows-02 和 service-owned 正向已独立逐文件大小/SHA、目的地证明及 guest/host
  cleanup true 校验；见 Logs/.../additional-complete-verification.json。

### 6：FakeNet SYSTEM 混合产物与活动生产方拒绝

- SYSTEM 的隔离 fixture 调用真实 DualPcapWriter、payload report model/template，
  使用 RFC 文档地址的合成 UDP 字节生成并关闭两 PCAP/HTML，未发送或截获数据包。
  这些格式权限测试不能冒称 WinDivert live capture qualification。
  实际 IncidentCollector._copy_exit_dump 校验并复制 owned child minidump，
  write_publication 发布 incident 副本；source dump 字节/ACL及 exit-root 精确 ACL 不变。
  一次性 SYSTEM task LastTaskResult=0、结束后仅移除本任务，无残留活动写入。
- 正式 overview 返回 19 complete rows；官方 wrapper 导出新 handoff-fakenet-01。
  export 后逐文件原 SHA/ACL 不变。正式 velo-handoff149-fakenet-01 pull
  共20文件 COMPLETE；独立重读全部结果及19项 receipt 的大小/SHA通过，
  真实 HTTP body、dump 原始 SHA、destination_verified 与 guest/host cleanup true
  均通过；Logs/.../fakenet-01-verification.json。
- FakeNet 受控 stop 后仅重启该 MCP 服务（PID4188），重新 load/start；
  下一 run 34bb1e66-5036-4a65-9214-e27b2c72a8bb healthy，owned HTTP POST200。
  对真实 healthy overview 的 wrapper 负向拒绝，未创建输出/manifest，根 ACL 不变。
  正式 stop outcome ok/version4；新的 closed overview 共12项，下一批 pull 后续完成，
  见轮次7；本轮当时未提前计为完成。

### 7：下一批、运行状态恢复与最终逐项审计

- `velo-handoff149-fakenet-02` 正式13文件 COMPLETE；独立对照12项 producer receipt
  和全部接收文件大小/SHA，真实下一批 HTTP body、destination_verified、双端 cleanup
  true 均通过。重复 configure/verify 两轮16对象，最终 ACL完全相同、源 SHA/ACL不变。
  日志 `fakenet-02-verification.json`；Windows 8+2、service-owned 1、FakeNet20+13
  共五条产物正向、44文件均已独立验证。资产/overview 推送另有正式 COMPLETE 记录，
  不混入产物文件数量。
- FakeNet 再次受控服务 stop/start 恢复初始外部 stopped/version1/config_identity=null、
  run/controller=null，SCM Running/Auto/LocalSystem PID1596；Velo SCM Running/Auto/
  专用账号 PID7160，keepalive Ready/enabled，Windows-MCP task Running。
  实测 root lease free、持久 worker lease active=null、owned managed/helper=0、
  39871监听=0、一次性task不存在、needs_recovery=false；两个成功 run 的原恢复审计
  最后一条 differences={}。原 FakeNet 防火墙规则完全相同。
- 原五个边界根 ACL逐项与最初基线相同；Velo env/API SHA未改，政策为已验收的新
  exact read root 版本，旧政策保留并已真实恢复/再加载。完整旧 FakeNet包212文件的
  大小/SHA/ACL重新比较无差异，新候选196 manifest成员重新校验通过；SCM控制/
  恢复配置、IFEO四值、exit-evidence两ACE保持。未重启VM/恢复快照。
- 最终遗漏检查发现：最初 FakeNet root-level persistent snapshot 没有递归记录
  `configs/service.json` 和 exit-root `registration.json` 的前置 SHA，因此不能宣称
  两文件完成前后 SHA对比。已纠正 package-preservation 中原先空集合导致的
  service_config_preserved=true，改为 null及明确说明。两文件观测写入时间分别
  为10月6日、9月14日，早于本任务；维护未使用 install/uninstall/save，也未写它们。
  保存当前 SHA/ACL和校验过的独立私有备份，仅继承 SYSTEM/admins 权限，不导出凭据。
  这是证据边界，不补造缺失的历史哈希。
- 进程基线129项中113项 PID/创建时间相同；其余16项含已维护 MCP服务/launcher 和
  临时工具进程，完整变化表保留，不能据此宣称所有基线进程持续存活。dnSpy、原
  Velociraptor两个进程、浏览器、Explorer、Everything 等实测 PID/创建时间未变。
  Sysmon历史进程日志不可用，未编造旧 launcher 父子关系。操作仅维护已核对
  Windows listener 及两 MCP服务，没有对其他应用发送终止指令。
- 精确保留清单：本任务 host journal/接收件/大小SHA校验、VM隔离 staging/evidence/
  原生产样本/导出批次、失败阶段/UTF-8错误、三份政策备份、旧 FakeNet完整包、
  protected owned dump及私有配置观察备份。host逐文件清单425项、VM清单86项保存在
  retention-manifest.json/final-retention-manifest.json；均留供复核，不运行通配删除；已结束
  的一次性task已移除，传输 owned package/partial 由已验证的双端 cleanup 完成。
- 审计八阶段映射：基线 B1/B2；契约 C1/C2；专用读根 D1/D2；Windows W1–W3；
  FakeNet F1–F3；私有配置 S1/S2；联合与负向 T1–T5/J1/J2；文档/恢复/遗漏 R1/R2/A1。
  每行均绑定上述实际代码/本地提交及实机证据；新增补漏为 HTTP登记、NoDivert非权限
  故障、MCP预检日志、Linux build partition及缺失前置哈希的诚实证据边界。
  没有以 SOURCE_READY、静态ACL、Wine gate或人工伪造成功替代正式 COMPLETE。
  本任务权限交接范围完成；全 WinDivert native capture资格和既有 golden schema漂移
  仍是明确范围外项，未声称解决。

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
| B1 | 记录三个仓库版本、既有脏文件、运行账号、服务/任务及 ACL 基线 | 完成；见轮次 1 |
| B2 | 留存原负向/八文件成功记录，建立无害且隔离的验收样本 | 已有原记录；新样本待执行 |
| C1 | 定义文本、报告、PCAP、HTTP、dump 的生产方/消费方/路径/关闭证据 | 已定义；见 artifact-export-handoff.md；生产链路验收待执行 |
| C2 | 独立定义配置/密钥更新、Read 与生产方写/覆盖/删除权限 | 已定义；见 service-file-updates.md |
| D1 | 配置专用精确 read root；现有及新建嵌套对象权限验证 | 待执行 |
| D2 | 策略变更备份及服务/keepalive/传输能力验证 | 待执行 |
| W1 | Windows-MCP 显式绝对路径产物交接；生产结束后 configure/verify | 待执行 |
| W2 | 新建、移动、复制、覆盖、替换后的最终对象交接 | 待执行 |
| W3 | Windows-MCP 复制/移动失败保留两端路径、操作、原生异常 | 本地通过并提交；正式服务部署待执行 |
| F1 | FakeNet 根据写入停止与登记信息导出最终普通产物 | 待执行 |
| F2 | 导出副本大小/SHA-256 验证，再权限交接与 Velo 回收 | 待执行 |
| F3 | incident/dump 经受控导出，原始 exit-evidence 精确 ACL 保持 | 待执行 |
| S1 | 配置/密钥最终对象读权与保密边界验证，替换方式明确 | 原生隔离更新/恢复测试通过；正式文件验证待执行 |
| S2 | 更新后真实加载/重启成功；失败诊断和备份恢复流程 | 待执行 |
| T1 | 管理员、SYSTEM、服务产物及后续新嵌套文件：正式 worker COMPLETE | 待执行 |
| T2 | 私有同卷移动、protected DACL、发布替换：修复或明确拒绝 | 待执行 |
| T3 | deny ACE、reparse、策略外路径：受限拒绝且原对象无误修改 | 待执行 |
| T4 | 未关闭/持续写入/文件占用：区分完成条件、共享冲突和 ACL 拒绝 | 待执行 |
| T5 | 每条正向：独立内容/SHA-256 检查，双方清理完成 | 待执行 |
| J1 | .149 三条链路：Windows-MCP、FakeNet 普通产物、incident 导出 | 待执行 |
| J2 | 重复交接、下一批新产物、服务重启后行为 | 待执行 |
| R1 | 文档、启动/参数说明、失败排查与证据记录同步；分阶段本地提交 | 待执行 |
| R2 | 最终服务/任务/捕获状态恢复，原证据保留，无残留活动测试 worker | 待执行 |
| A1 | 逐条比对用户原八阶段、上述每个 ID、实际提交和实机结果；补遗漏 | 待执行 |

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

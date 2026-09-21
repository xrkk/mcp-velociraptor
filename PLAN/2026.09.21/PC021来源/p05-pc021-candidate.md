# PC021 P05 精确契约候选（R03）

状态：隔离候选，**不是现行规范**。  
适用范围：仅供 PC021 作者裁决与后续正式同步使用。  
基线：`main@74c405cb6507eee23c8625bd8e62c28a843cf3ef`。  
继承：R01/R02 已接受的签发回执、签发资格分离、`.next` 先于 intent、v2 形状、五/四键 manifest、确定性下载成员、不可变 SDK 报告、三条业务 flow 和九规范影响结论全部保留；本稿只勘误 PC21-004、PC21-005、PC21-006、PC21-007，不扩展机制。

## 1. 插入锚点、术语与边界

正式作者采纳后才可按以下锚点同步；本候选本身不修改 P05：

1. 以本文 §2 替换 P05 v17 §6 行 378–381 的复合动作，保持 epoch7/epoch8 身份不变；
2. 在 P05 行 383–440 的 activation root/Phase 条款后插入签发、receipt 和能力规则；
3. 以本文 §3 扩充 P05 §2 行 93–125 的 Phase package 规则；
4. 以本文 §2–§4 扩充 P05 §4.3、§8、§10；
5. 以本文 §5 澄清 P05 §6 行 403–433 与 §1.0.1 行 760–766 的三 Flow 范围，不增加 Triage upload 下载。

术语：

- `C7`：进入激活前实际读取并验证通过的 epoch 7 canonical 原件字节；`H7 = SHA-256(C7)`。
- `A`：`activation-189/<activation_uuid>/`；`R = A/activation-evidence.json`；`S = A/issuance-receipt.json`。
- `HR/HS`：`R/S` 实际字节 SHA-256。
- `N8`：从已验证 `C7` 和激活输出确定性构造的 epoch 8 canonical；`H8 = SHA-256(N8)`。
- “内容图有效”：当前字节、路径、哈希与 schema 闭合；不证明过去某次 fsync 成功。
- “操作可继续”：内容图有效，且同一进程、同一 controller 持有未消费的私有一次性完成资格。

本文只规定普通进程正确性、崩溃接续和可审计原件；不声称抵抗恶意同进程伪造、内核/介质欺骗、PKI 攻击或可信计算基攻击。

## 2. activation issuer、固定 receipt 与一次性完成资格

### 2.1 保持既有 activation root，增加同层 receipt

`R` 保持 P05 v17 的 exact keys：

`schema_version/kind/workflow_id/candidate/checkpoint_marker/migration_evidence/preparation_evidence/creation_metadata/initial/candidate_cycles/source_inputs/implementation_sources/issued_at`

本候选不替换其 schema，不给 root 添加 receipt、future canonical 或 future transition 引用。

`S` 必须且只能有下列 **13 个根键**：

`schema_version/kind/workflow_id/issuance_id/operation/source/epoch7/cycle2/activation_root/issued_at/events/status/error`

精确嵌套和值：

- `schema_version=1`；`kind="snapshot189-activation-issuance-receipt-v1"`；`workflow_id` 等于固定 P05 workflow；`issuance_id` 是等于 `<activation_uuid>` 的 canonical lowercase UUID；
- `operation="P05_ACTIVATION_ISSUE"`；`status="ROOT_VALIDATED"`；`error=null`；
- `source` exact keys 为 `source_inputs_sha256/implementation_sources_sha256`，分别是 `R` 中完整对应数组的 P05 canonical JSON SHA-256；摘要不替代逐个 Source 原件验证；
- `epoch7` exact keys 为 `canonical_sha256/schema_version/epoch/phase/active_snapshot`；值分别为 `H7`、整数 6、整数 7、`PREPARATION_BASELINE`、`Snapshot 187-固定IP+WindowsMCP开机自启`；
- `cycle2` exact keys 为 `restore_attempt_id/run_id/report/package_manifest`；两 ID 等于 `R.candidate_cycles[1]`，两个 Ref 与该对象对应 Ref 字节等同；
- `activation_root` 是 P05 三键 Ref，path 固定 `activation-evidence.json`，size/SHA 绑定 `R` 实际字节；
- `issued_at` 与 `R.issued_at` 和 events 第 2 项 `at` 字节等同；
- `events` 恰有六项，每项 exact keys `sequence/event/at`；sequence 依次为 1–6，event 依次为 `PRE_ISSUE_GRAPH_VALIDATED`、`ISSUED_AT_SAMPLED`、`ROOT_WRITTEN`、`ROOT_FILE_FSYNCED`、`ROOT_DIRECTORY_FSYNCED`、`ROOT_READBACK_VALIDATED`；`at` 是同一 issuer 在对应动作成功后取得的 UTC RFC3339 `Z` 观察值。

所有 receipt Ref 从 `A` 解析。绝对/盘符/空/点/dotdot/反斜杠/逃逸/重复/链接或 reparse/特殊文件/size-hash 不符均失败。sequence 与同一 controller 的控制流证明顺序，不比较 guest、host、VMware 或 writer 的墙钟数值。

`ROOT_VALIDATED` 只陈述该调用观察到的内容图和步骤，不是可由磁盘重建的 writer 授权，也不能单凭 receipt 当前字节证明历史 fsync 成功。

### 2.2 非循环 issuer 算法

issuer 是一个生产操作，不提供公开 `skip_receipt/prevalidated/fixture/unsafe` 或等效 gate：

1. 要求 `A` 及其祖先为批准的普通非 reparse 目录；以 no-follow/lexists 证明 `R/S` 均不存在；生产平台若不能提供文件 flush 与父目录持久性（含 Windows 目录持久性）则在创建 root 前 fail closed，测试 seam 不得把 mock 当成生产成功。
2. 一次读取 `C7`，验证 schema6/epoch7 固定状态并保存 `H7`；冻结除 `issued_at` 外的 root 输入；私有 pre-issue predicate 完整验证 preparation/migration/creation、initial/cycle1/cycle2、三 Phase manifest、runtime/business predicate 和所有 Source；不接受 caller “已验证”断言且不写文件。
3. 步骤 2 成功后记录 event 1；实际取 issuer UTC 一次，event 2 与 `R.issued_at` 共用该值；禁止使用预选值、mtime、validator/writer/future 时间或 caller 值。
4. create-if-absent 创建 `R`，完整写、flush、file-fsync、close、parent-directory-fsync；按动作成功记录 events 3–5；no-follow 重开，逐字节等同并对保留的 `C7` 重跑完整 immutable-root verifier，成功后记录 event 6。
5. 用六事件和最终 root Ref 构造 `S`；create-if-absent 完整写、flush、file-fsync、close、parent-directory-fsync、no-follow 重开并逐字节等同；运行 public complete-bundle verifier，重新验证所有原件及绑定。
6. 只有步骤 1–5 全部成功后，同一 controller 才铸造 §2.5 私有一次性能力并直接调用 §4 writer；这才是“操作可继续”。

private pre-issue predicate 解决 receipt 尚不存在的 bootstrap；public complete verifier 从不把该中间态判为 issued success。root 先于向后绑定它的 receipt，但二者之间不存在成功窗口。

### 2.3 publication、并发与失败保全

只有赢得 `R` exclusive-create 的进程可尝试 `S`。并发 loser 不写 receipt、不改变 winner。任一固定目标已经存在（即使字节相同）、临时别名、意外普通成员、链接/reparse 或类型不确定都在新发布前阻断，禁止自动复用、覆盖、改名隔离、修补或重试。

输入在 root 前漂移：不创建 final。root 任一步失败：原位保全已有 root，receipt 缺失，禁止 epoch8。receipt 任一写入/持久化/读回/终验失败：原位保全 root 及可能存在的 receipt，报告失败并禁止 epoch8。完整可解析 receipt 仍可能来自 fsync 返回失败的现场，public content verifier 不得反推历史返回值。

`implementation_sources` 必须在 pre-issue 前纳入实际 issuer、complete verifier、download preserver 及其直接 helper/tests；root、receipt、live report、下载字节、输出 manifest/result、future transition 都是输出，不得作为 implementation source 形成循环。PC021 作者决定在正式执行冻结时进入 `source_inputs`；正式采纳必须生成新的 current-manifest identity，历史 `CURRENT-PC020-R01` 原字节不改。本候选、自检、result 只是草案证据。

### 2.4 public 内容 verifier

一次调用必须从 `A` 验证固定同层 `R/S`、既有 root/Phase/Source/epoch7 predicate、receipt exact keys/事件和全部 cross-binding，并执行 §3 的 package 规则。它可返回 `content_graph_valid=true`，但不得返回 `operationally_issuable=true`、caller bool 授权、可序列化 token 或从磁盘恢复的许可；它明确不能判断历史 receipt fsync 是否曾失败。

### 2.5 私有一次性签发完成能力（PC21-001）

能力是控制器私有、不可序列化、不可复制、不可由调用参数/环境变量/配置/文件/receipt 重建的进程内对象。概念字段固定为：

- `operation = "P05_ACTIVATION_ISSUE"`；
- `workflow_id`；
- `issuance_id`；
- `epoch7_sha256 = H7`；
- `activation_root_sha256 = HR`；
- `issuance_receipt_sha256 = HS`；
- 生命周期状态 `UNSPENT` 或 `SPENT`。

同一 controller 在调用 writer 前必须重新读取 `C7`、`R`、`S` 的实际字节，分别计算 `H7`、`HR`、`HS` 并与能力逐项相等。能力消费与“是否已消费”的判定必须在该 controller 的单一临界区内原子完成，且发生在创建 `.next`、intent、receipt 或其他 writer 副作用之前。

失败、进程崩溃、重启、能力丢失或能力已消费时：

- 不得根据磁盘上的完整 `R`/`S` 自动继续；
- 不得回退到旧 activation bundle 或旧 receipt；
- 不得重新铸造能力；
- 保留当前现场，停止并提交作者裁决；不得由执行方自动重签发、另启或更换固定 workflow/issuance。

能力已被某一 writer 调用消费后，即使该调用在首个文件副作用前失败，也不得复用。两个 writer 并发争用同一能力时，必须恰有一个成功消费；另一个在任何 writer 副作用前失败。

### 2.6 必须具备的静态失败反例

后续实现至少应以可控 I/O seam 验证：

1. `S` 字节完整可解析，但 receipt fsync 注入失败：内容 verifier 可通过，控制器不铸造能力，writer 零副作用；
2. receipt 完整终验后，能力已经铸造但在 writer 开始/签发操作最终返回前崩溃：重启后内容仍可能有效，但进程内能力丢失，禁止自动接续；
3. 一个 writer 已消费能力后再次使用：第二次在副作用前拒绝；
4. 两个 writer 同时使用同一能力：仅一个消费成功，另一个在副作用前拒绝。

这些反例也必须断言：内容 verifier 不谎称能够判断历史 receipt fsync 成败；失败现场不接纳旧 bundle fallback。已 `COMMITTED` 的 epoch8 下游依据 transition 原件，不要求跨进程保留能力。

## 3. 下载原件与 Phase manifest

### 3.1 固定成员身份和编码

每个 Phase 中每次成功 `download_flow_file` 的包成员固定为：

`downloads/<flow_key>/<file_id>/content.bin`

其中 `flow_key = lowercase_hex(SHA-256(flow_id 严格 UTF-8 编码一次))`。`flow_id` 必须是非空 Unicode scalar-value 字符串，不做 normalize、case-fold、strip 或 path-decode；无法编码（含 unpaired surrogate）即失败。`file_id` 必须恰为 64 个小写 ASCII hex，并等于紧邻的完整 `list_flow_files` 返回的 P04 canonical logical-file identity。raw Flow ID、backend path、`original_path`、local filename 和 caller text 均不得形成路径段。

member 相对该 Phase 根而不是 activation 根。不同 Phase 即使得到相同派生文本也属于不同根；§5 要求九个 runtime Flow ID 跨 Phase 全部不同，不能靠目录隔离掩盖复用。

### 3.2 真实产品字段与不可变 SDK/report 绑定（PC21-004）

最终 `report.json` 原字节包含每次调用的 `arguments`、解码后的 `structured` 以及原 MCP `mcp_result.structuredContent`。不得虚构第二份 raw-message、列表行字段或产品字段。

成功 `list_flow_files` 的真实结构必须按 `velociraptor_mcp_core.py` 解释：

- 顶层 exact keys 为 `operation/status/warnings/data/truncated`；列表是 `data`，不是 `files`；`operation="list_flow_files"`、`status="success"`，且完整列表要求 `truncated=false`；
- 每个 `data` row exact keys 为 `file_id/original_path/file_size/uploaded_size/accessor`；row **没有** `flow_id` 或 `sha256`；
- Flow 身份来自该 report call 的 `arguments.flow_id`。list call 的 `structured` 与 `mcp_result.structuredContent` 必须字节语义等同，且唯一选中的 row 由 `file_id` 确定。

成功 `download_flow_file` 的真实 `DownloadResult` exact keys 为 `operation/status/warnings/flow_id/file_id/local_path/size/sha256/original_path`。其 call `arguments` 必须精确含相同的 `flow_id/file_id`，且 `structured` 与 `mcp_result.structuredContent` 必须相等。list/download/package 映射固定为：

| 身份/度量 | list call / row | download call / result | 包内 member |
|---|---|---|---|
| Flow | `list.arguments.flow_id` | `download.arguments.flow_id == DownloadResult.flow_id` | 其严格 UTF-8 SHA-256 构成 `flow_key` |
| file | row `file_id` | `download.arguments.file_id == DownloadResult.file_id` | 形成 `<file_id>` 路径段 |
| 原路径 | row `original_path` | `DownloadResult.original_path`，两者相等 | 只作 source-time assertion，不作包路径 |
| 逻辑长度 | row `file_size` | `DownloadResult.size`，两者相等 | 实际 `content.bin` 字节数相等 |
| 存储长度 | row `uploaded_size` | 无对应 DownloadResult 字段；非负、保留原值，稀疏文件可与逻辑长度不同 | 不作为 member size，不强制等于 `size` |
| accessor | row `accessor` | 无对应 DownloadResult 字段 | 保留在不可变 list 原件，不发明副本字段 |
| 内容哈希 | row 无此字段 | `DownloadResult.sha256` | 实际 `content.bin` SHA-256 相等 |
| 产品落点 | row 无此字段 | `DownloadResult.local_path` | 仅在保全复制阶段按 §3.3 核源；搬运后不解引用 |

所有 size 字段均为非负整数且不接受 bool；哈希为 64 小写 hex；`file_id` 使用 §3.1 规则。`data` 缺失/非数组/为空、`truncated=true`、身份重复、字段非法或上述映射不一致均失败。禁止按目录扫描、mtime、glob、大小或“最新文件”猜测。

### 3.2.1 产品下载、报告冻结与包复制的因果顺序（PC21-005）

最终报告必须包含真实 download 响应，因此顺序只能是：

1. 在产品入口执行 `list_flow_files`，再执行实际 `download_flow_file`；产品先把下载结果发布到其可信 download root，并返回 `DownloadResult`；
2. scenario/report producer 把 list/download 的真实 `arguments`、`structured`、`mcp_result` 和 call 顺序纳入同一最终报告；所有本 Phase 调用及既有 cross-step 检查结束后，以现有 `report.json` 契约一次冻结并持久化最终原字节；
3. package preserver 只读该最终 `report.json`，按本节唯一定位 list row 和 download result，再从 §3.3 的可信产品落点执行包内保全复制；不得修改报告或重新调用产品来改选成员；
4. 两个 fixture 的包内复制均完成并读回验证后，才生成 Phase manifest；manifest 随后进入 activation root/receipt 图。

本顺序不新增 pre-download log、sidecar、临时报告或第二套日志契约。报告持久化失败则不开始包内复制；产品下载失败则不存在成功 download response，不能冻结为成功报告；报告冻结后 source 漂移或复制失败按 §3.3 保全并阻止 manifest/root/receipt。

### 3.3 可信源准入与独占复制

package preserver 只在 §3.2.1 的最终报告冻结后开始。它从该 Phase 已接纳的同一 server-instance evidence/configuration 取得可信 P04 `VELOCIRAPTOR_DOWNLOAD_ROOT`；它不是 caller input，也不从 `local_path` 推断。唯一合法源是 `<trusted_root>/<flow_key>/<file_id>/content.bin`。response `local_path` 必须在 Windows native absolute-path 语义下精确指向它；alternate spelling、dot/dotdot、device/UNC、alias、short-name、大小写歧义或 root 外路径全部拒绝。

trusted root、每个祖先及子目录都必须为普通非 reparse 目录，source 是普通非 reparse 文件。no-follow 打开 source 后记录同一 handle 的 stable volume/file identity、logical size 和 change metadata，从该 handle 有界分块读取并计算 count/SHA，之后再核同一 handle 和 path-to-handle identity。identity、metadata、path binding 或内容偏差均为 source drift。零字节仅在首读 EOF、count=0、SHA 为 empty SHA-256 时合法。

destination Phase root 及 `downloads/flow_key/file_id` 每段均在 Phase 内且为普通非 reparse 目录。package preserver 在同目录 exclusive-create 唯一自有 `.part`，流式复制、flush/file-fsync/close，要求 count/SHA 与不可变 DownloadResult 的 `size/sha256` 相同；重开逐字节验证后以 create-if-absent 发布 `content.bin`，绝不覆盖或接受既有 target（即使字节相同）。发布后重验目标、以生产支持的 primitive 同步包含目录，再安全清理自有 `.part`。

不支持 durability、target collision、source drift、short/extra read、size/hash mismatch、I/O fault、unsafe path 或 cleanup 不确定均 fail closed。失败保留已发布成员和任何不确定自有残留，阻止 Phase sealing；只在重验安全 parent 与自有 identity 后清理精确 owned part，绝不删除 completed member、其他 attempt、外部 sentinel 或目录。

### 3.4 搬运后验证

validator 仅从不可变 report 的 Flow/file identity 重建 member，相对当前 Phase 根读取普通非 reparse 文件，并核验两个 DownloadResult view 的 `size/sha256`、list row 的 `file_size/file_id/original_path` 及调用参数；不得从 list row 读取不存在的 SHA。原 `local_path` 只作为不可变 source-time assertion 保留；搬运后不解析、不打开、不改写，也不要求旧路径存在。报告、Ref 和成员原字节整体搬运仍保持哈希稳定。

不增加 copy sidecar 或产品 response 字段。不可变 response/list identity、确定性 member、实际 member 字节和 exact Phase manifest 共同构成证据，任何一个都不替代实际读取。

### 3.5 Phase manifest 的唯一坐标系（PC21-003）

对每个 Phase：

- Phase 根目录记为 `T`；
- Phase manifest 固定为 `M = T/package-manifest.json`；
- Phase 对象中的 `package_manifest.path` 是**相对 activation 根 `A`** 的规范 POSIX 路径，且必须精确指向 `M`；
- `M.members[*].path` 是**相对 Phase 根 `T`** 的规范 POSIX 路径；解析成员时只能使用 `T / member.path`，不得使用 `A` 或进程 cwd；
- `phase_prefix` 是 `T` 相对 `A` 的规范 POSIX 路径，即 `package_manifest.path` 去掉末尾 `/package-manifest.json` 后的值。

上述两种坐标不得混用。解析后路径必须仍位于批准的根内，并按组件拒绝链接、junction/reparse point 和其他特殊文件。

### 3.6 Phase manifest 精确 schema

`M` 使用确定性 UTF-8 JSON 编码。根对象必须且只能有 P05 §2 的 **5 键**：

1. `schema_version`：整数 `1`；
2. `kind`：固定候选值 `"pc021-p05-phase-manifest-v1"`；
3. `workflow_id`：与 activation root 相同；
4. `created_at`：manifest 实际签发时取得的有效 UTC `Z` 时间；
5. `members`：成员数组。

`created_at` 必须在所有成员写入、关闭并逐字节读回后、activation root 签发前取得；该要求是同一控制器的因果步骤要求，不要求与别的主机墙钟作数值比较。

每个 member 必须且只能有 P05 §2 的 **4 键**：

1. `path`：相对 `T` 的规范 POSIX 路径；
2. `size`：实际普通文件字节数；
3. `sha256`：实际普通文件字节 SHA-256；
4. `origin`：如下确定的批准证据相对来源选择器。

`origin` 的构造规则只有两种：

- 对确定性下载的最终内容成员：`<report_ref_path>#/calls/<i>/structured`。`report_ref_path` 是冻结 SDK 报告相对 `A` 的规范 POSIX 路径；`i` 是该报告 `calls` 数组中唯一产生此逻辑文件记录的十进制零基索引；该 selector 必须反向验证到 §3.2 的唯一 file ID、size 和 sha256；
- 对其余普通成员：`<phase_prefix>/<member.path>`，即该原件相对 `A` 的规范 POSIX 路径。

`origin` 不替代 `path/size/sha256` 的身份验证，也不得包含主机绝对路径、URI、反斜杠、`..` 或未规范化片段。

### 3.7 完整成员算法

manifest 生成器必须：

1. 在停止所有 Phase producer 后递归枚举 `T`；
2. 拒绝任何链接、junction/reparse point、特殊文件、未关闭临时文件或 `.part`；
3. 令 `F` 为 `T` 下全部普通文件的集合；
4. 令 `E = { M }`，且 **只有** `M` 可以排除；activation root 位于 `T` 外，因此不在 `F`，也不得被额外列入排除表；
5. 对 `F - E` 的每个文件从实际字节计算 `path/size/sha256/origin`；
6. 拒绝重复路径、大小写折叠碰撞、Unicode 规范化碰撞和未知额外文件；
7. 按 `path` 的 UTF-8 字节升序输出 members；
8. 写入并持久化 `M`，随后读回，重新枚举并验证 `F - E` 与 members 为 exact set。

集合判定必须同时检查数量、唯一性和 exact set；不得依赖目录枚举顺序，也不得只验证 manifest 所列子集。

### 3.8 历史兼容边界

`kind = "pc021-p05-phase-manifest-v1"` 是 **PC021 候选新类型**，不是当前已存在类型。当前 R03 合成 fixture 的“两键根（`schema_version/members`）+ 三键 member（`path/size/sha256`）”是 legacy 形状。

- 历史包和旧 fixture 字节不改写；
- legacy 形状可以按既有历史迁移规则作为历史原件保全，但不得被新 PC021 success verifier 当作本节 manifest；
- 只有 PC021 正式生效后新创建的包才使用本节 schema；
- 合成 fixture、live producer、P05/P06/P07 consumer 必须配套更新，不能靠 verifier 双义接受两种形状来伪造新成功。

## 4. epoch 8 writer、transition v2 原件与 P06/P07 接续

### 4.1 writer 准入

epoch 8 writer 的唯一自动准入是 §2.5 的未消费能力。writer 必须在单一临界区内完成：

1. 核验能力类型、状态和全部绑定；
2. 从实际 `C7`、`R`、`S` 字节复算 `H7/HR/HS`；
3. 核验当前 canonical 仍精确等于 `C7`；
4. 原子地把能力从 `UNSPENT` 置为 `SPENT`；
5. 然后才允许任何 writer 文件副作用。

调用方布尔、fixture 标志、磁盘 token、完整 `R/S` 或旧 bundle 均不能替代能力。

### 4.2 transition v2 固定位置与键集合（PC21-002）

本次 writer 的原件固定在 `A`：

- intent：`A/epoch8-transition-intent.json`；
- receipt：`A/epoch8-transition-receipt.json`。

两者均是 `R` 签发之后的 transition 输出，不属于 `R` 的 exact schema 或任何预签发 Phase manifest，不得反向改写 `R`。P06 继续使用既有 `activation_evidence` restore record：若其 restore attempt 为 `<restore_attempt_id>`，归档落点必须分别为 `restore/<restore_attempt_id>/activation/epoch8-transition-intent.json` 和 `restore/<restore_attempt_id>/activation/epoch8-transition-receipt.json`，并由既有 outer manifest 逐字节覆盖；无需、也禁止增加第九种 restore record kind。

v2 intent 根对象必须且只能有 **10 键**：

1. `schema_version`：整数 `2`；
2. `kind`：`"pc020-canonical-transition-intent-v2"`；
3. `workflow_id`；
4. `transition_id`：UUID；
5. `from_sha256`：`H7`；
6. `to_sha256`：`H8`；
7. `next_sha256`：`.next` 完整持久化并读回后的实际哈希，必须等于 `H8`；
8. `activation_root_sha256`：`HR`；
9. `issuance_receipt_sha256`：`HS`；
10. `created_at`：intent 实际创建时取得的 UTC `Z` 时间。

v2 receipt 根对象必须且只能有 **15 键**：

1. `schema_version`：整数 `2`；
2. `kind`：`"pc020-canonical-transition-receipt-v2"`；
3. `workflow_id`；
4. `transition_id`；
5. `from_sha256`；
6. `to_sha256`；
7. `next_sha256`；
8. `activation_root_sha256`；
9. `issuance_receipt_sha256`；
10. `started_at`；
11. `replaced_at`；
12. `directory_fsynced_at`；
13. `readback_at`；
14. `status`；
15. `error`。

所有非 null 哈希均为 64 位小写十六进制。receipt 的身份/哈希字段必须与 intent（若 intent 已创建）及实际原件相等。

receipt 状态与 nullability：

| status | `to_sha256` | `next_sha256` | `replaced_at` | `directory_fsynced_at` | `readback_at` | `error` |
|---|---|---|---|---|---|---|
| `COMMITTED` | `H8` | `H8` | UTC Z | UTC Z | UTC Z | `null` |
| `FAILED_BEFORE_REPLACE` | `H8` | 在 `.next` 验证前失败为 `null`，否则 `H8` | `null` | `null` | `null` | 非空字符串 |
| `TRANSITION_INDETERMINATE` | `H8` | `H8` | 仅实际观察到 replace 成功时为 UTC Z，否则 `null` | 仅实际观察到目录 fsync 成功时为 UTC Z，否则 `null` | 仅实际完成 canonical 读回时为 UTC Z，否则 `null` | 非空字符串 |

未知 status、成功状态含 error、失败状态无 error、事件未观察却有时间、已观察却缺时间，均失败。`COMMITTED` 还要求实际 canonical 字节哈希为 `H8`。

### 4.3 不得改变的 writer 顺序

PC021 v2 **不改变**现行 P05 §5 的 `.next → intent → compare → replace` 顺序：

1. 读取并验证 current canonical 为 `C7/H7`；
2. 证明目标 `.next` 不存在；
3. 验证 preparation/migration/activation 内容与能力绑定；
4. 确定性构造 `N8/H8`；
5. exclusive-create `.next`，完整写入、flush/fsync/close，对父目录 fsync；重新打开逐字节读回并验证 `next_sha256 = H8`；
6. **在 `.next` 完整持久化和读回之后**，以 exclusive-create 写入并持久化 v2 intent，读回验证其绑定；
7. intent 成功后立即重新读取 canonical；只有实际字节仍精确等于 `C7/H7` 才可继续；
8. 原子 `replace(.next, canonical)`；
9. 对 canonical 父目录 fsync，重新打开 canonical 逐字节读回并验证 `H8`；
10. 写入、持久化并读回 v2 receipt；只有 `COMMITTED` receipt 完整验证后调用才报告成功。

canonical 在步骤 7 漂移时不得 replace，也不得自动移动/隔离 `.next`；失败现场原位保全。任何失败不自动重试，不复用已消费能力。

现有 epoch 6→7 writer 的 v1 intent/receipt schema 和行为不因本候选被解释为 v2；它仍服务原代次。v2 仅适用于 PC021 epoch 7→8 transition。

### 4.4 P06/P07 接续

一旦 epoch 8 已经 `COMMITTED`，进程内能力不再是 P06/P07 的输入。下游必须读取并验证：

- current canonical 实际字节与 v2 `to_sha256`；
- v2 intent 和 `COMMITTED` v2 receipt 的 exact schema、相互绑定以及 `H7/H8/HR/HS`；
- `R`、`S` 和完整 activation/Phase 内容图；
- restore 包 outer manifest 对这些普通文件的逐字节 size/hash 覆盖。

P06 使用既有 `activation_evidence` 递归携带 `A`，因此 transition v2 两原件在 `restore/<restore_attempt_id>/activation/` 固定路径进入既有 restore 包；不得增加第九种 restore record kind。P07 按同一归档路径及哈希验证。若 v2 receipt 缺失、非 `COMMITTED`、字段不一致或 canonical 不匹配，下游停止并保全，不以进程内 token、旧 bundle 或推测补齐。

## 5. 每 Phase 的精确三 Flow 业务范围

`P05_REPAIR_INITIAL`、candidate cycle 1、candidate cycle 2 各自拥有恰好三个互异 collection Flow，且三个 Phase 的九个 Flow ID 全部互异：

1. 一个真实 `collect_forensic_triage` Flow，使用完整 `_BasicCollection`、2400 秒和已采纳的 4 GiB 单请求预算；
2. 一个固定 ASCII fixture `collect_file` Flow；
3. 一个固定 UTF-8 fixture `collect_file` Flow。

Triage Flow 必须真实到达 `FINISHED`；原 start response 与后续 terminal status 分开保留；枚举实际 declared result sources，并把每条 result chain 读到 terminal pagination；执行一次完整 `list_flow_files` 并保留列表。某个 declared source 可依现行契约为空，但 source set 缺失/未知、result/list 未执行、pagination 截断/未读完、ERROR/cancel/timeout/over-budget/critical error、存在 rows/uploads 却无闭合终页或 aggregate 无解释地全空均非成功。只有已评审场景明确允许正常空，且 source/list 已穷尽，zero-row/zero-file 才可通过。

两个 fixture Flow 各自真实到达 `FINISHED`，完成 file list，按 P04 file identity 唯一选择冻结的逻辑原件（不得猜 filename），实际调用一次 `download_flow_file` 并通过 §3。ASCII/UTF-8 payload 的 size/SHA 必须等于冻结 fixture 规范。list-only、fabricated call、改写 SDK result、缺包内 member 或共享 Flow 均失败。

Triage result 和完整 file list 保留，但本候选不下载任何 Triage upload；两个 fixture download 是每 Phase 的 exact download-original set。不得增加 bulk-Triage copy、选择策略、数量、empty-list fallback 或下载预算。若后续发现正式来源明确要求下载 Triage-produced file，本节失效并返回作者对 target/count/empty/resource 重新裁决，不得擅自取消或扩张。

正常即时完成状态只能来自冻结报告内产品结构化终态并绑定 flow/artifact/client/result；HTTP 成功、快速返回或空列表不能自行解释为完成。等待、取消、终止、超时及失败均保留原请求/响应和最后受支持状态，不伪造即时完成；后续动作必须是显式新步骤。不同主机墙钟不用于推导因果。

## 6. producer / consumer 同步清单

PC021 若正式采纳，至少必须同步以下全部位置；漏一项不得宣称完成：

1. live Phase/activation packager：生成 5/4 键 manifest、fixed kind、created_at、origin 和 exact-set；
2. 合成 fixture producer：`tests/pc020_activation_fixture.py`，停止生成 legacy 2/3 键形状；
3. activation verifier：`tests/p05_pc020_activation.py`，验证坐标、exact keys、kind、created_at、origin 和 all-files-minus-self；
4. P05 transition writer：`tests/p05_pc020_transition.py` 的未来 epoch 7→8 路径；保留现有 epoch 6→7 v1，新增私有能力准入和 v2 记录；
5. P06 evidence verifier：`tests/p06_evidence.py`，识别新 manifest、固定 v2 transition 路径与绑定；
6. P06 packager：`tests/p06_package.py`，继续用既有 `activation_evidence` 递归携带，不新增 restore kind，并断言 v2 原件被 outer manifest 覆盖；
7. P07 handoff/restore verifier：按归档路径验证新 manifest 与 v2 transition 原件；
8. SDK/MCP report producer 与 Phase 下载 packager：先完成真实 product download，再冻结含 `arguments/structured/mcp_result` 的最终 report；按 `data` row 的 `file_id/original_path/file_size/uploaded_size/accessor` 和 DownloadResult 的 `flow_id/file_id/local_path/size/sha256/original_path` 做精确映射，之后复制并生成 manifest；
9. PC021 fixtures、goldens、正反例和 Windows 隔离测试：成套更新，历史 fixture 原字节另存而不覆写。

## 7. 明确不作的推断

- 当前完整 receipt 字节不证明历史 receipt fsync 成功；操作可继续只来自同一控制器的一次性能力。
- `issued_at`、`created_at` 和业务报告时间不跨时钟域建立先后关系；因果顺序由控制器步骤和哈希引用证明。
- 新 Phase kind 不是当前实现已有类型；旧 R03 fixture 不是新 success fixture。
- 本候选不修改任何正式规范、产品代码、共享测试、部署、VM、canonical 或快照。

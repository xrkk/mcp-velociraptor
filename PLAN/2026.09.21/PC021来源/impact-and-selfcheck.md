# PC021 R03 影响映射与自检

状态：隔离研究材料，不是正式规范、自评结论或实施授权。  
基线：`main@74c405cb6507eee23c8625bd8e62c28a843cf3ef`。  
候选正文：`R03-evidence/p05-pc021-candidate.md`。

## 1. R01/R02 保留与 R03 差集

R01/R02 已接受部分保持：13 键签发 receipt、非循环的预签发/终验分工、内容与操作资格分离、`.next` 先于 intent、v2 形状、五/四键 manifest、确定性下载成员、不可变 SDK 报告、三条业务 flow、九规范影响范围。R03 不重释这些结论，只作以下四项勘误：

| ID | R02 精确问题 | R03 勘误 |
|---|---|---|
| PC21-004 | R02 错写 `structured.files`，并把 list row 当成有 flow/hash | 改为真实 `structured.data`；Flow 由 list call argument 绑定，hash 由 DownloadResult 绑定；逐项映射 `file_size/uploaded_size/size` 等真实字段，不新增产品字段 |
| PC21-005 | R02 要求最终 report 在 product download 前持久化，因 report 本身要包含 download response 而不可能 | 固定 `product download → final report freeze/persist → package copy → Phase manifest`，复用现有 report，不建新日志 |
| PC21-006 | 资格丢失后允许执行方另启全新 workflow/issuance | 删除 fallback；只保全并提交作者裁决，不自动重签发或更换固定 workflow |
| PC21-007 | R02 坐标正例 `downloads/result.bin` 不符合确定性路径正文 | 使用真实 Flow 字符串、可复算 UTF-8 SHA-256 与 64-lowerhex file ID 给出完整合法 member；正反解析根与正文一致 |

## 2. 权威来源与当前实现事实

### 2.1 正式规范事实

- `PLAN/2026.09.02/2026.09.05-22-实施子方案-P05测试数据与情景基础设施.md`（当前 P05 v17）§2：Phase manifest 根 exact keys 为 `schema_version/kind/workflow_id/created_at/members`，member exact keys 为 `path/size/sha256/origin`；成员为 Phase 子树全部普通文件减 manifest 自身；root 位于 Phase 子树外。
- 同文件 §5：当前原子 writer 的顺序是 `.next` full write/flush/fsync/directory sync/readback/validation，之后才记录 durable intent，再立即重读 canonical 比较，随后 replace、目录 fsync/readback、receipt。
- 同文件 §5：现行 receipt v1 为 13 键，并有 `COMMITTED`、`FAILED_BEFORE_REPLACE`、`TRANSITION_INDETERMINATE` 三状态及“未观察步骤的时间为 null”规则。

### 2.2 当前实现事实

- `tests/p05_pc020_transition.py` 的 intent v1 为 7 键、receipt v1 为 13 键；实现服务既有 epoch 6→7，不等于本候选 epoch 7→8 v2。
- `tests/p06_package.py` 已将 `activation_evidence` 指向目录递归携带到 `restore/<restore_attempt_id>/activation/...`，因此把 transition v2 原件固定放入 activation 根可复用现有机制，无需第九种 restore record kind。
- `tests/pc020_activation_fixture.py` 当前 Phase manifest 是 legacy 两键根 `schema_version/members` 加三键 member `path/size/sha256`；它不能直接充当 PC021 新 schema 的成功 fixture。
- `velociraptor_mcp_core.py` 的 `FlowFileListResult` 顶层是 `operation/status/warnings/data/truncated`；`FlowFileEntry` 只有 `file_id/original_path/file_size/uploaded_size/accessor`，没有 `flow_id/sha256`。
- 同文件 `DownloadResult` 是 `operation/status/warnings/flow_id/file_id/local_path/size/sha256/original_path`。`velociraptor_fixed_tools.py` 以 list call 参数绑定 Flow、以 row `file_id` 选择下载，并令逻辑下载 size 对应 row `file_size`；`uploaded_size` 是存储长度，稀疏文件可不同。
- `tests/scenario_runner.py` 在 tool call 返回后把 `arguments/structured/mcp_result` 加入 report，并在所有 scenario/cleanup/cross-step/最终状态处理后才写最终 `report.json`；因此最终报告不可能在其 download call 前冻结。

### 2.3 推导与未知

- 推导：私有能力是普通进程正确性门；它解决“当前字节无法证明历史 fsync 返回成功”而不把不可证信息塞进内容 verifier。
- 推导：能力必须在 writer 首个副作用前原子消费，否则复用或并发会重新打开自动接续。
- 推导：transition v2 原件放在 activation 根、但不列入预先签发的 root members，可由现有 P06 递归机制携带且不形成 root 自引用。
- 推导：package preserver 必须消费已经包含真实 DownloadResult 的最终 report；否则要么缺响应，要么需要未获授权的第二日志契约。
- 未知：正式采纳后的具体类名、锁原语和生产模块位置；本候选只冻结语义，不假装当前已有实现。
- 未知：恶意进程、内核或介质是否可信；它们明确不在本候选保证范围。

## 3. exact-key 复核

### 3.1 activation root 与签发 receipt

- activation root 保持 P05 v17 的 13 keys：`schema_version/kind/workflow_id/candidate/checkpoint_marker/migration_evidence/preparation_evidence/creation_metadata/initial/candidate_cycles/source_inputs/implementation_sources/issued_at`；
- receipt 13 root keys：`schema_version/kind/workflow_id/issuance_id/operation/source/epoch7/cycle2/activation_root/issued_at/events/status/error`；
- nested exact keys：source 2、epoch7 5、cycle2 4、activation root Ref 3、六个 event 各 3。

结果：R01 exact schema 原样保留；`status=ROOT_VALIDATED`、`error=null`。它仅表示该次调用观察到的内容验证结果，不单独授权 writer。

### 3.2 一次性能力：非 schema

绑定 `operation/workflow_id/issuance_id/epoch7_sha256/activation_root_sha256/issuance_receipt_sha256` 与 `UNSPENT|SPENT` 生命周期。它不写磁盘、不进 JSON、不进调用参数，不存在“exact keys”兼容入口。

### 3.3 transition v2 intent：10 键

`schema_version/kind/workflow_id/transition_id/from_sha256/to_sha256/next_sha256/activation_root_sha256/issuance_receipt_sha256/created_at`

结果：10 个；schema version 2、kind `pc020-canonical-transition-intent-v2`；`to_sha256 == next_sha256 == H8`；`from_sha256 == H7`；root/receipt 两哈希来自能力与实际字节交叉核验。

### 3.4 transition v2 receipt：15 键

`schema_version/kind/workflow_id/transition_id/from_sha256/to_sha256/next_sha256/activation_root_sha256/issuance_receipt_sha256/started_at/replaced_at/directory_fsynced_at/readback_at/status/error`

结果：15 个；schema version 2、kind `pc020-canonical-transition-receipt-v2`；三状态及 nullability 已在候选 §4.2 完整列出。

### 3.5 Phase manifest：5/4 键

- root：`schema_version/kind/workflow_id/created_at/members`；
- member：`path/size/sha256/origin`。

结果：与当前 P05 §2 精确一致；新固定 kind 是候选而不是当前已有类型。

### 3.6 产品 list/download 字段

- list top-level：`operation/status/warnings/data/truncated`；
- list row：`file_id/original_path/file_size/uploaded_size/accessor`；
- DownloadResult：`operation/status/warnings/flow_id/file_id/local_path/size/sha256/original_path`。

结果：Flow 只由 list call `arguments.flow_id` 与 download argument/result 交叉绑定；list row 不含 `flow_id/sha256`；`file_size == DownloadResult.size == member byte count`，`uploaded_size` 不作为逻辑 member size，`DownloadResult.sha256 == member actual SHA-256`。

## 4. PC21-001 静态故障与并发自检

| 场景 | 磁盘内容图 | 能力 | writer 结果 | 必需断言 |
|---|---|---|---|---|
| receipt 全字节写出但 fsync 注入失败 | 可能可解析且内容验证通过 | 不铸造 | 副作用前拒绝 | verifier 明确无法判定历史 fsync；不得把 content valid 当授权 |
| receipt 完整终验后，writer 开始/签发最终返回前崩溃 | 重启后可能仍完整 | 已铸造但随进程丢失 | 不自动接续 | 不从 `R/S` 重建能力，不回退旧 bundle |
| 能力已被一个 writer 消费后再调用 | 不变 | `SPENT` | 第二次副作用前拒绝 | 即使第一次在首个写操作前失败也不得复用 |
| 两个 writer 并发争用同一能力 | 不变 | 单一临界区原子消费 | 恰一个可进入 writer | 失败方不得创建 `.next`、intent 或 receipt |

边界复核：本机制不声称对恶意同进程对象复制或内核欺骗提供安全性；该非目标写入候选正文。

## 5. PC21-002 paper walkthrough

### 5.1 成功路径

1. 控制器完成签发 receipt 持久化、读回和完整内容验证，铸造能力。
2. 同一控制器从实际 `C7/R/S` 复算并匹配 `H7/HR/HS`，在锁内消费能力。
3. writer 验证 current canonical 精确为 `C7/H7`，且 `.next` 不存在。
4. 构造 `N8/H8`。
5. exclusive-create `.next`，full write、flush/fsync/close、parent fsync、readback；实际 `next_sha256=H8`。
6. 此时才创建、持久化并读回 v2 intent；intent 绑定 `H7/H8/HR/HS`。
7. 立即重读 canonical；仍等于 `C7/H7`。
8. 原子 replace，parent fsync，canonical readback 等于 `N8/H8`。
9. 写入、持久化、读回 `COMMITTED` v2 receipt；全部时间非 null，error null。
10. P06 通过既有 activation 递归路径携带 root、签发 receipt、v2 intent、v2 receipt 和 Phase 文件；outer manifest 覆盖实际字节。P07 从原件验证，不要求进程内能力。

结论：intent 明确位于 `.next` 完整持久化/读回之后，未复现 R01 的逆序。

### 5.2 canonical 漂移

在 durable intent 后立即比较发现 canonical 不再等于 `C7/H7`：

- 不 replace；
- `.next` 和 intent 原位保全，不自动移动/隔离；
- 可写 `FAILED_BEFORE_REPLACE` receipt，其中 `next_sha256=H8`、后三个阶段时间均 null、error 非空；
- 能力已消费，不自动重试。

### 5.3 replace 后不确定

replace 被调用后任一步无法可靠判定完成：

- 状态为 `TRANSITION_INDETERMINATE`；
- 仅为实际观察到的步骤填写时间，未观察的为 null；
- error 非空；
- 不自动重试或回退；
- P06/P07 因无合格 `COMMITTED` 原件而停止。

### 5.4 代次兼容

既有 epoch 6→7 writer 的 v1 intent/receipt 不改写、不冒充 v2。本候选只给未来 epoch 7→8 定义 v2；历史原件按原 schema 保全。

## 6. PC21-003 坐标、来源与完整性自检

### 6.1 坐标正例

假设 activation 根 `A` 下 Phase 目录为 `phases/initial`，真实 Flow 字符串为 `F.PC021-R03-ASCII`，其严格 UTF-8 字节 SHA-256 可复算为 `730c6ceafcf277f7a71cb4dd22a030d9ad42cd8ddead3c24b1ef4f3b2c40ed0c`；选中的真实 `file_id` 为 64-lowerhex `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`：

- Phase Ref：`package_manifest.path = "phases/initial/package-manifest.json"`，从 `A` 解析；
- `T = A/phases/initial`；
- 合法 member：`path = "downloads/730c6ceafcf277f7a71cb4dd22a030d9ad42cd8ddead3c24b1ef4f3b2c40ed0c/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/content.bin"`，只从 `T` 解析；
- 普通成员 origin：`"phases/initial/reports/summary.json"`；
- 下载成员 origin：`"phases/initial/reports/sdk.json#/calls/3/structured"`。

Ref 与 member 使用不同且明确的根，解析后均需批准根 containment 和无链接验证。

### 6.2 坐标反例

- 把上述合法 member 从 `A` 解析：拒绝，根错误；
- member 前缀写成 `phases/initial/downloads/...`：拒绝，因为它不是相对 `T` 的规范 member path；
- 使用 raw Flow `F.PC021-R03-ASCII` 作目录名、使用另一个 Flow hash、非 64-lowerhex file ID，或缺少末尾 `content.bin`：拒绝；
- origin 使用 `C:\...`、`../...`、URI 或未能唯一反查 report call：拒绝；
- Ref 指向另一个 Phase 或 manifest 文件名非固定值：拒绝。

### 6.3 all-files-minus-self 正反例

正例：递归枚举 `T` 得到 11 个普通文件，其中 1 个是 `M`，members 必须是其余 10 个的 exact set，数量 10、路径唯一、按 UTF-8 path bytes 排序。

反例：

- 磁盘多一个未列文件：拒绝；
- manifest 多列、漏列或重复：拒绝；
- 仅目录枚举顺序不同：不得拒绝，比较数量+唯一性+exact set；
- `M` 之外再排除 root、日志或“无关文件”：拒绝；
- `.part`、符号链接、junction/reparse point 或特殊文件存在：封装失败，不得静默排除。

### 6.4 历史边界

当前 R03 fixture 的 2-key/3-key manifest 必须作为 legacy 字节保留。新 success 测试必须生成 5-key/4-key 候选形状；verifier 不得以“兼容”为由同时把 legacy 形状判为 PC021 新 success。

## 7. producer / consumer 同步矩阵

| 位置 | 身份 | 必要同步 | 不得做 |
|---|---|---|---|
| live Phase/activation packager | producer | exact 5/4 keys、fixed kind、created_at、origin、all-files-minus-self | 猜测文件或额外排除 |
| `tests/pc020_activation_fixture.py` | synthetic producer | 新 fixture 生成新形状；legacy fixture 另存 | 覆盖历史原字节 |
| `tests/p05_pc020_activation.py` | consumer | 双坐标、keys/kind/time/origin/exact-set | 双义放行 legacy 为新成功 |
| `tests/p05_pc020_transition.py` | writer | 未来 7→8 路径增加能力门和 v2；保留 6→7 v1 | 修改 v1 历史语义 |
| `tests/p06_evidence.py` | consumer | 校验新 manifest、v2 两原件、canonical/root/receipt 绑定 | 依赖进程内能力 |
| `tests/p06_package.py` | producer | 复用 activation 递归携带并断言 outer manifest 覆盖 v2 | 增加第九 restore kind |
| P07 handoff/restore verifier | consumer | 从归档路径逐字节验证新 manifest 与 v2 | 从内存 token 推断提交 |
| SDK/MCP report producer + downloader | producer | product download 完成后冻结最终 report；按 list `data` row 与 DownloadResult 真字段映射，再执行包复制 | pre-download 冻结最终报告、发明 `files/flow_id/sha256` list 字段或新日志 |
| fixtures/goldens/Windows 隔离 tests | verification | 正反例成套更新 | 把历史 fixture 悄然改成新字节 |

完整性判断：所有已知直接 producer/consumer 均在表中；正式作者仍须在实际实施前用全库引用搜索验证是否出现新的消费点。

## 8. 九规范影响复核

当前冻结对象实际是 requirement、master 与 P01–P07 共九份；“改”仅指未来作者正式同步，本轮未改文件：

| 当前对象 | 改？ | 当前稳定 ID / 条款 | 最小承接 |
|---|---:|---|---|
| requirement v8 | 是 | PC020 priority；`REQ/RACC-013`、`020`、`023`、`026`；累计 35/56/59/62/64/65/67 | 在既有 ID 下承接 receipt/资格/writer、确定性 member 与 exact 三 Flow；不改累计含义 |
| master v21 | 是 | PC020 §0；`OUT-013/020/023/053`、`ACC-013/020/023/026` | 把 issuer/receipt/writer 归于 ACC-020/023/026，把 P05 preservation 和 P06 recursive verification 归于 OUT/ACC-020/023；Pxx 数不变 |
| P01 v4 | 否 | `IMP/ACC-P01-006` Flow/file facts；`IMP/ACC-P01-007` Triage identity | 历史 baseline 不拥有 issuer/packager/下游 consumer，只引用保留事实，不机械加 PC021 条款 |
| P02 v7 | 否 | `IMP/ACC-P02-002` structured originals；`IMP/ACC-P02-005/006` Flow adapter | 不改 schema/cursor/transport/shared backend；report preservation 属 P05，product download 属 P04 |
| P03 v3 | 否 | `IMP-P03-001..008`、`ACC-P03-001..008`；118 dynamic scope 与 PC014 exclusion | 不改 dynamic artifact/tool/allowlist；保留 129+1 accounting |
| P04 v10 | 是，仅 handoff 澄清 | §3.1.2/§3.2；`IMP-P04-003/005/006`；`ACC-P04-001/002/005` | `local_path` 是 immutable source-time text；P05 派生复制固定 member，后续不解引用。六字段 response、file_id/path、错误模型和 no-auto-download 不变 |
| P05 v17 | 是，主对象 | PC020 §2/§4.3/§6/§8/§10；`IMP-P05-002/003/005/008..011`、`ACC-P05-002/004/005/007/008` | 采纳候选 §2–§5、exact receipt/资格/v2 writer、Phase 5/4 manifest；冻结实际 producer/verifier sources；不新增稳定 ID |
| P06 v18 | 是 | PC020 §0；`IMP-P06-002/003/005/006/008`、`ACC-P06-001..006`；129+1/645 | receiver/selection/aggregate 验证 fixed receipt、unchanged report、derived members、v2 originals 和三 Flow；复用 activation recursion；计数不变 |
| P07 v15 | 是 | PC020 §0；`ACC-024/025`；80/67 trace；PC017 file/Triage disclosure | handoff 递归重算 receipt/root/member/manifest/v2；不读旧 absolute source；计数、成本、CHK owner 和 P07 职责不变 |

没有重命名、删除或发明既有 stable ID。正式作者可以为采纳文本分配 PLAN-CHANGE 身份，但本候选不冒称该身份已存在。PC021 作者决定须进入未来 freeze 来源和新 current-manifest；历史冻结 manifest 原字节不改。

## 9. 支持、冲突与未支持

| 方向 | 当前支持 | 当前冲突/缺口 | 候选闭合 |
|---|---|---|---|
| 实际签发 | P05 v17 §6/§10 要求 `cycle2_done → root_issue → epoch8_next` 且 issued_at 被 root hash 绑定 | 当前 verifier 只看合法时间和内容图，不能证明 fsync 返回成功，也没有操作资格 | 固定同层 receipt + controller 私有一次性能力；内容 verifier 不冒充历史 I/O 观察者 |
| epoch8 writer | P05 v17 §5 已冻结 `.next → intent → compare → replace → receipt` | R01 walkthrough 逆序；v2 键/status/P06 位置未穷尽 | 恢复既有顺序，10/15 exact keys、三状态 nullability、activation 递归固定归档路径 |
| portable download | P04 v10 固定 list `data` row 和 DownloadResult；P05/P06/P07 要求递归普通文件 | report 保留绝对 source path；旧 fixture 改写 synthetic path；当前无 source→member producer | product download 后冻结 report；按真实字段映射确定性 member，再安全复制/manifest；后续不打开 source path |
| Triage/fixture | P05 v17 要求每 Phase real Triage 和 list/download file chain；P04 不 auto-download；P06 分开 Triage 与 fixture qualification | 当前无条款选择/计数 Triage uploads 或给予 bulk budget | 每 Phase 恰一 Triage 完整结果/list + 两 fixture 实际下载，不下载 Triage upload |
| Phase manifest | P05 §2 已规定 5-key root、4-key member、完整 Phase tree | 当前 R03 fixture 是 legacy 2/3 shape，kind/origin/坐标未落实 | 新 candidate kind、双坐标、report selector origin、all-files-minus-self；历史字节不改 |
| causal DAG/source freeze | P05 exact root 与 §10 禁止自/未来引用，§4.3 要 actual sources | root 不能引用后生成 receipt；producer 尚未存在于 freeze | source/Phase → root → receipt/能力 → `.next`/intent → canonical/transition receipt → P06；输出不进 implementation sources |

已检查的正式来源未明确要求下载 Triage-produced file。“real Triage plus list/download file chain”孤立看有歧义，但 P04 no-auto-download、P05 分开的 fixture chain 和 P06 qualification actions 支持作者本轮已选的有界解释。未来发现相反正式条款属于重新裁决条件，不能静默扩张或取消。

## 10. 原件不变整包搬运纸面走查

输入：某 Phase 执行 Flow `F.PC021-R03-ASCII`，其 UTF-8 SHA-256 为 `730c6ceafcf277f7a71cb4dd22a030d9ad42cd8ddead3c24b1ef4f3b2c40ed0c`，选中 file ID 为 `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`；product source 位于 P04 configured root 的确定性后缀。

1. `list_flow_files` 返回 `data` row；实际 `download_flow_file` 完成并返回 DownloadResult，report producer 记录真实 `arguments/structured/mcp_result`；
2. 全部调用与 cross-step 检查结束后，最终 `report.json` 原字节冻结持久化；此后不修改；
3. package preserver 从最终 report 核对 list argument Flow、row file ID/original_path/file_size 与 DownloadResult flow/file/original_path/size/sha256，验证 trusted root/source handle；
4. 派生并 exclusive/durable copy 到 `downloads/730c6ceafcf277f7a71cb4dd22a030d9ad42cd8ddead3c24b1ef4f3b2c40ed0c/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/content.bin`；
5. member 实际 bytes 与 DownloadResult `size/sha256`、list `file_size` 相同，随后 Phase exact manifest 收录 member；
6. 完整 activation/P06 package 字节不变搬到新根，旧 service download tree 不存在；consumer 只读新 package，`local_path` 保留为旧 source-time 字符串且不解引用，所有 package-relative Ref/hash 稳定。

反例：member 缺失、linked/reparse、字节变化、猜测 filename、report 重写或 validator 打开旧 `local_path` 都拒绝。此走查是静态推演，无实际文件/VM/产品副作用。

## 11. 下载/签发故障与重新裁决条件

- source escape/alias/device/UNC/reparse：读取或 destination 发布前拒绝，零完成 member；
- source identity/metadata/content drift、short/extra read、size/SHA mismatch：拒绝并禁止 Phase sealing；只安全处理精确 owned part；
- target collision/race：绝不覆盖或把既有文件当本次成功；
- zero byte：必须 first EOF/count 0/empty SHA；Unicode Flow 严格 UTF-8 且 file ID 仍为 lowerhex；
- input/source/cycle2 drift、root/receipt O_EXCL race、short write/flush/fsync/dir-sync/readback/validation failure：按候选原位保全，禁止能力和 epoch8；
- Triage ERROR/cancel/timeout/over-budget/unknown empty/incomplete pagination：不能由两个 fixture 成功掩盖。

以下发现要求作者重新裁决：exact root/Phase keys 不能保持；正式来源明确要求 Triage upload 下载；P04 identity/path 语义变化；生产平台不能提供安全 open/create/fsync primitives；source freeze 无法含实际 producer；或 v2 无法在不让 root 引用未来对象的情况下绑定 root/receipt。不得用弱 fallback 自行继续。

## 12. 停写自检

四项勘误的静态正/负例矩阵（均为纸面契约检查，不是已运行产品测试）：

| ID | 输入 | 操作 | 目标分支 | 实际静态判定 | 允许副作用 |
|---|---|---|---|---|---|
| PC21-004-A | list structured 只有 `files`、没有 `data` | 按候选解析 list | exact list schema | 拒绝：缺 `data` 且有未知键 | 不开始包复制，不生成 manifest/root/receipt |
| PC21-004-B | list row 伪造 `flow_id` 或 `sha256` | 验证 row exact keys | row identity | 拒绝：未知产品字段；不得信任其值 | 同上 |
| PC21-004-C | 稀疏 row `file_size=16, uploaded_size=7`，DownloadResult `size=16` | 绑定长度 | sparse 合法映射 | 接受这组长度关系；若实现强制 7==16 属错误过拒绝 | 后续仍须实际 member count/hash 全过才复制成功 |
| PC21-005-A | 试图在 download call 前冻结“最终” report | 查找真实 download response | report→copy gate | 拒绝：最终报告缺必要调用原件 | 不开始 package copy/manifest |
| PC21-005-B | download 后改写已冻结 report 的 `local_path` | 验证 report Ref/hash | immutable report gate | 拒绝：原字节/Ref/hash 改变 | 不接受改写副本，不生成 manifest/root |
| PC21-006 | 资格已丢失，执行方尝试新 issuance/workflow | writer 准入 | private capability gate | 拒绝并交作者裁决 | writer 零副作用，不自动重签发 |
| PC21-007 | member 为 `downloads/result.bin`、raw Flow 目录、错 hash 或短 file ID | 解析 manifest member | deterministic member/path gate | 拒绝：与 Flow hash/file ID/content.bin 算法不符 | verifier 只读；不签发 root/receipt |

- [x] C01：receipt 13 个根键及所有嵌套键、Ref 根、operation/source/epoch7/cycle2/root/issued_at、六事件和无循环 bootstrap 已精确定义。
- [x] C02：root/receipt exclusive publish、flush/fsync/parent-sync/readback、并发/碰撞/漂移/Windows 不支持及 failure preservation 已覆盖；未来 writer 与 source freeze 无自/未来依赖。
- [x] C03：固定 download member、严格 Flow/file ID、trusted root/source handle、独占复制、碰撞/漂移/残留/零字节/Unicode/relocation 均已覆盖。
- [x] C04：三 Phase 各三独立 Flow、真实 Triage FINISHED/result/list 与两 fixture actual download 已冻结；不新增 Triage bulk download，正式来源冲突则重裁。
- [x] C05：requirement、master、P01–P07 九对象逐项列出当前稳定 ID、改/不改和最小承接；历史 freeze 不改，PC021 仅未来进入新 identity。
- [x] C06：两组完整纸面走查、正反例、故障、重裁条件、exact keys/路径/顺序/无循环/无 future event 及未决实现点已记录；明确未实测。
- [x] PC21-004 使用真实 `data`/list row/DownloadResult 字段并逐项映射，没有发明产品字段。
- [x] PC21-005 因果顺序为 product download → final report freeze/persist → package copy → manifest，没有新增日志契约。
- [x] PC21-006 资格丢失只保全并交作者裁决，无自动重签发或新 workflow fallback。
- [x] PC21-007 正例使用实际 Flow 字符串、可复算 hash、64-lowerhex file ID 与完整确定性 member。
- [x] 仅创建 R03 两份隔离候选；R01/R02 两轮证据均未改写。
- [x] 没有修改正式规范、产品代码、共享测试、历史裁决或旧 result。
- [x] 没有连接 VM、网络、服务、canonical、snapshot 或 datastore。
- [x] PC21-001 四个指定反例全部显式覆盖。
- [x] PC21-002 顺序为 `.next` 后 intent；v2 键集合、状态/nullability、P06 固定位置完整。
- [x] PC21-003 绑定 5/4 schema、candidate kind、created_at、origin、双坐标、all-files-minus-self、历史边界和同步清单。
- [x] 未声称内容 verifier 可证明历史 fsync。
- [x] 未新增第九种 restore record kind。

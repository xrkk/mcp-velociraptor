# PC026：保留现场的新基线续代与七工具契约

状态：主控作者稿 v1，**未采纳、未开启实施或恢复门**。父组 CURRENT-TRANSFER-001-R02。本文由主控决定内容，后续候选九文档、附件、155条保真自评及主控采纳记录齐备后才生效。PC025仍未采纳；不采用无快照/schema3 baseline_binding替代。本文不是产品通过或运行来源冻结证明。

## 1. 不变范围和生效方式

87正式+68累计的155条ID、原业务义务和追溯关系全部保留；本变更增加实现约束而不减少验收。DFIR仍118动态+12固定，129个成功目标与PacketCapture独立排除，五场独立恢复形成645关系。七传输工具独立矩阵不乘入645。首次业务之前安全、身份、依赖、fixture、资源门，真实三Phase/九互异Flow、七/八类恢复证据、失败整场零覆盖、P07五pair成本和清理回归、最后未参与规划实施者独立核验均保留。

候选组名 CURRENT-PC026-R01。九规范拟版本依次为需求v14、总纲v26、P01v5、P02v9、P03v5、P04v14、P05v22、P06v24、P07v20。采用显式优先节覆盖下述受影响旧条款，其余正文逐字保留；不能全局替换历史189、188、130或136。旧原件和旧manifest不修改。每份优先节必须说明本篇的具体责任、当前组和本文各节锚点；历史正文中的旧组/旧版本属于历史语义，不能用它覆盖新节。新manifest逐字绑定九份实际字节和全部新旧有效附件；manifest无自身hash，采纳记录在其外侧绑定最终manifest。

主控完整自评之前不得称signed/current，不得把候选路径接生产。实施后源码变化再冻结实际implementation集合，不能沿用本轮观察指纹。未冻结、缺件、来源漂移均拒绝。

## 2. 恢复profile及精确状态

选择结构保持方案：canonical schema6，唯一精确C7/epoch7到C8/epoch8；以外部批准profile区分新代，不增加canonical顶键。新profile ID `pc026-snapshot191-v1`。当前入口仅认可本profile对应的新191，旧189图即使校验完整也仅历史读取，不允许schema6无profile宽泛接纳189或191。

候选精确名：`Snapshot 191-Velociraptor-MCP可恢复验收基线`。新A坐标 `activation-191/<canonical-lowercase-uuid>`。R仍13键、schema_version=1，kind=`snapshot191-activation-evidence-v1`；S仍13键、schema_version=2，kind=`snapshot191-activation-issuance-receipt-v2`。C8 activation_evidence.source=`snapshot191-activation`，evidence_path=`activation-191/<uuid>/activation-evidence.json`。R/S其余字段及完整业务谓词沿PC021/22保留；source指向本轮批准当前源集合，历史bootstrap在独立policy层验证。

intent10键schema2/kind `pc020-canonical-transition-intent-v2`、receipt15键schema3/kind `pc021-epoch8-activation-transition-receipt-v3`及A下固定文件名不变。共享非候选kind必须同时验证外部profile、新R/S、精确C7、C8及全部hash，不能仅kind/schema放行旧代。

C7原字节SHA256为 `96afd802b2c1630f0a06f441e4ca6fa81cf8c448a6030f4c9d169595ab5ca500`，active187、allowlist仅187、activation=null，永不补写retired或改Ref。C8只从C7确定性派生：同workflow、schema6/epoch8/NETWORK_ACTIVE、active及allowlist仅191；旧retired有序前缀保持，依次追加187、189、190，各status为原MANUAL_ONLY值，重复或交集拒绝。retired是禁止自动恢复的治理清单，不表示这些历史对象都在当前物理树中。

物理保留清单独立且精确：187 UID3无parent/marker Snapshot3；188 UID4 parent3/marker4；189 UID5 parent3/marker5；190 UID6 parent3/marker6。完整名称与VMX basename沿T007匹配原件冻结。新191 UID/marker只能实际创建后读取，不能预填Snapshot7或由191推导。旧四项不得删改。initial恢复后current为187；创建前191零项、旧四身份完全相等，创建后仅新增191一项且parent187，current/marker按真实操作证据核；candidate恢复后current为191。未知旁支、重名或UID/marker/parent漂移拒绝，不自动换候选名。

stage：INITIAL为C7/187恢复、不消费新creation；CANDIDATE为C7仍active187、仅该stage允许191恢复并消费本轮creation；P06_ACTIVE为新C8/191并消费完整激活图。前两类七kind，P06八kind，只增加既有activation_evidence，不创造第九kind。恢复前均要求完整stage资格，不由canonical.active或物理current单字段自动授权。

## 3. bootstrap与当前来源分层

固定旧前驱schema5/epoch6迁移已完成，不得再跑。以下只作历史封闭层：C7原字节、其preparation/migration两个完整递归包、历史外部policy、H5、历史transition intent与COMMITTED receipt。preparation入口SHA `079ebe78576e63dc6a70398392d292c4f0d0116c9d3ab80366c2e78a85d11809`；migration入口SHA `01dddecb5be72626820bdbf32c7d200a06a3d4a6b50159e319707d72a3ee7518`；历史policy SHA `1d23c30546c6d838646c6cf608450c0ade05f2ff074d3a2e0d0456a81f2933f7`；epoch7 receipt SHA `6e51668661bcb01518b1afe9be36c2e2a7c2cf1eb650c5a5509f4e3045ddbca4`；intent SHA `03644378e4e1bf45c5a2fea8c1c4843d2607a79046c7dfb7d521493837126d60`。

历史层仍逐Ref/hash/size/blob/manifest/完整谓词验证，不是豁免校验；其旧source只在该层成立，不要求旧source副本变成当前源码。历史ready、initial、189creation或cycle报告均不得计本轮业务成功。新initial/creation191/两cycle、R/S、writer及P06/P07只用完整新source/root_policy。旧189仅解释历史，不可填补新191因果。

正式相对根保持 `Logs/P05/wf-01a05d1d-p05`。两包按C7原相对路径只增发布；bootstrap固定目录为 `bootstrap-pc020/epoch7`，文件名 `epoch7-canonical.json`、`epoch7-intent.json`、`epoch7-receipt.json`、`historical-policy.json`。完整成员发布清单必须来自经复核的最终闭包；目标同字节可复核复用，异字节、异常类型、未知成员或不安全祖先拒绝且不覆盖。旧archive搜索仅调查用途，loader不得扫描.tmp回退。

## 4. 外部批准、唯一writer与镜像

生产loader从仓库治理目录 `PLAN/2026.10.02/controller-approval.json` 读取外部批准记录；该文件不在待验bundle里，必须为主控在实现冻结、双端发布核验后单独签发的非秘密受控文件。schema_version固定1，kind固定`pc026-controller-approval-v1`。固定格式附件使用exact keys：schema_version、kind、approval_id、workflow_id、profile_id、normative_manifest、implementation_freeze、bootstrap_manifest、root_mapping、publication_receipt、status。前三个manifest及publication_receipt均为相对仓库治理根的path/size/sha256三键Ref；禁止绝对外部输入、逃逸及未知键。status只能READY，缺文件或非READY拒绝，不创建空模板冒充批准。

loader的信任来源是主控受控治理目录及批准动作，明确不抵御可任意改写治理文件的同权限恶意进程；不宣称文件hash是数字签名。审批记录本身不在其引用freeze内，避免自包含hash。主控签发时在独立采纳/运行记录保存批准文件hash，controller启动绑定此精确身份；运行中漂移即拒绝。不得有CLI/env传入任意policy/root或自动更新批准hash的接口。

normative_manifest绑定最终采纳组；implementation_freeze exact成员包括实际生产模块、全部直接/递归helper、writer/validator/selector/receiver/runner/aggregate/P07、相关tests及fixture/scenario/index/schema/依赖声明。第三方wheel/工具/实际安装及服务principal另作真实部署证据，不以本机import或Git HEAD替代。未存在的未来代码不能以null占位获READY。

root_mapping精确区分host治理根、guest批准根及guest canonical位置，使用仓库相对根与guest项目根相对坐标，实际绝对路径由已验证部署配置确定并在publication_receipt绑定volume/file identity/ACL/principal/实例，不从请求参数推导。publication_receipt记双端相同成员清单与真实guest持久化、只读回传核验；先发布核验再批准READY，任一步失败仍未就绪。

guest Windows controller是唯一canonical状态writer。host canonical为治理镜像：准备阶段只接收精确C7；激活后只有guest真实COMMITTED和完整新A/C8闭包经校验才原子发布镜像，不能由host补造C8/receipt或mint资格。guest已提交而host接收失败时，保全guest结果，host停止选择，只能重新只读接收同一事实，禁止回滚C7或重用能力。跨端不宣称原子事务。selector、P06真实runner/receiver/aggregate、P07必须使用同一外部批准束并验证epoch7 receipt及新activation完整资格，孤立helper通过不代表入口接通。

准备与正式恢复有独立阶段门：READY只是来源和部署绑定准备完成，不自动执行恢复。实际恢复之前须清点、保全190之后仍需保留的guest资料，冻结独占窗口和明确操作序列；不得定时回滚。当前作者稿不执行任何恢复。

## 5. 七工具与双通道决策

正式面137=130DFIR+7transfer；原六input schema语义不变，新增transfer_chunks。正式本组要求七工具都存在、schema与新附件逐字一致；六工具旧server为不符合本组，明确`incompatible_server`，不能因此自动切Windows通道。保留同server单chunk操作供本组内batch capability未授予时选择，不称旧六server正式兼容。

transfer_chunks按方向严格互斥：公共transfer_id/request_digest/offset；push仅chunks，pull仅count_per_chunk/chunk_count。unknown/null/bool充整数/非整数、方向混合均在副作用前拒绝。chunk_count/max_batch_chunks为1..64；count为正整数、offset非负整数、hash lowercase64hex、严格base64且decoded count一致。精确input/output、capabilities和稳定error码附件为实施前必需，不以任意result object代完整约束。保留既有`velo.transfer.mcp.response.v1`success/error外层；业务error采用status=error/error.code，MCP协议层错误单列，不把DFIR130的结果合同强套此通道。

选择批次语义：完整批次结构、所有base64/hash/count、方向/offset和metadata/disk/deadline预算预验通过后才开始写。非法批次零writer副作用。合法批次发生IO/崩溃不承诺物理全事务；只允许owned尾巴，ledger/state已确认前缀是唯一进度。恢复必须验证前缀，截断仅该attempt可证明owned尾巴；不截断foreign或已完成对象。每chunk ledger连续且先payload flush/fsync后ledger持久化与state发布；不确定同步不能报告accepted。该语义必须通过中断矩阵，不能把非法第二chunk尾巴合法化。

batch不承诺accepted-range自动幂等重放。push未知结果先status核验固定transfer/request/channel与verified前缀，按已证offset续传；不能盲重发原batch，不能把timeout/protocol-error视为未写。完全完成offset即进入原finish/idempotency规则，不重新发送。明确batch_not_allowed在动作前可选single；二进制与JSON仅编码选择，发生未知结果必须先reconcile，不在失败时直接回放同请求。begin后channel sticky；跨Velo/Windows仅原合同明确的begin前不可用条件，auth/Host/Origin/协议/身份/预算错误不属fallback许可。

pull保持只读源且guest verified_offset不表示host落盘进度；每项按offset连续、count/hash核验，尾chunk可短但不得零长填充，空包按原空内容语义不伪造chunk，超过EOF/短响应/多余payload拒绝。host只在内容验证并实际落盘后推进自己的进度，源身份/metadata漂移失败。

硬上限：单chunk实际decoded不超过min(policy.max_chunk_bytes,1MiB)，批次raw总量≤64MiB且不超过grant；VBT1 header≤1MiB；每次传输数据调用的HTTP请求/响应实际总body≤100MiB（此限不改DFIR结果合同），JSON/SSE还计协议封装字节。额度按实际已读/将写字节计算，不能只用Content-Length或batch sizing估计。逐块读取达到上限立即中止且先于无界buffer；每次调用重算绝对deadline并检查取消/资源预算。更低policy限制优先。超限拒绝而不是切通道。

/chunkbin为同一正式server、进程、28790端口的附属POST数据入口，不是Windows-MCP代理，也不是第八工具。必须先建立同一SDK MCP session；请求Mcp-Session-Id须属于该server当前活session并绑定同Bearer授权上下文，缺失400、未知/过期404，实例漂移拒绝。服务端客户端都核同server-instance，不能在ensure_session之前走binary捷径。capabilities显式公布wire版本`VBT1`及session_required=true，未协商则从一开始选JSON，不经试写猜支持。

安全门顺序保留Bearer→Host/Origin→session/instance→预算/严格frame→业务；401/403/421/413/415等HTTP错误分别稳定分类，禁止归并connection_failed触发fallback。缺Origin沿原正式合同允许，present Origin严格拒绝，Host精确host:port，实际Windows防火墙host-only来源限制仍单独验。错误响应只稳定code，不返回exception detail、token、路径或请求内容。

VBT1固定magic+uint32LE header length+严格UTF8 JSON header+raw payload。重复JSON键/NaN/Infinity/额外键拒绝；push header精确chunks[count,chunk_sha256]序列，payload恰为各count相加；pull请求无payload、header精确形状由附件列明，不能忽略body。方向仅push/pull、header与HTTP参数无歧义对应、数字规范解析禁止bool/负值/分数。成功响应精确status/result及pull chunk offset/count/hash，payload恰好消耗；错误frame仅status/error.code且无payload。返回HTTP200不代表业务或解析成功，只有完整校验后才记wire可用。

## 6. 文档分工、矩阵及完成门

需求/总纲登记新profile/来源分层与137面；P01仅重验受影响底座不重跑历史183；P02负责正式session/双wire安全和实际预算；P03/P04业务参数及130DFIR职责不改；P05负责bootstrap发布、唯一controller、191初验/创建/双cycle/真实发行；P06统一入口/五独立恢复/严格接收聚合；P07成本、清理和最终追溯按同批准组，历史r232无恢复报告不替代正式成功。

新独立矩阵至少逐项覆盖T010的20分支，并增加push成功、pullbatch成功、双wire认证和session/instance负例、真实字节硬限、批次第二项非法零物理写、合法写入断点/ledger/state恢复、未知结果status reconcile、六server明确不兼容、both EOF/empty以及固定channel不逃逸。每格必须有输入/执行点/预期响应/物理副作用/清理与归档/host或Windows性质；未执行一律NOT_VERIFIED，不能由静态报告或unit测试覆盖成正式PASS。

主控自评必须逐155行保留原文/hash、原义、受影响条款与本稿对应、生产/消费同步、正反验收、不降低理由；计数本身不等于通过。新source的变化会使旧运行资格失效，必须新冻结并重验受影响范围。源码/文档提交不等于Windows安装或正式基线通过。实施后仍需全部阶段和未参与者独立全面核验。

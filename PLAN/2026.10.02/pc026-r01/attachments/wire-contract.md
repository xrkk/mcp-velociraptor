> 已采纳规范内容；本文件中的候选历史状态不覆盖 [主控最终修正](controller-review-corrections.md)。运行与恢复尚未批准。

# PC026 七工具/VBT1精确同步合同 R02

状态DRAFT_PENDING_CONTROLLER_SELF_REVIEW。依据[01作者稿](../support/controller-author-v1.md)及补充优先的[02主控OD01–06裁决](../support/controller-decisions-od01-06.md)。六项已由主控决定，不再OPEN；本端仅同步，不是组采纳/READY/代码实现或Windows产品通过。

## W01 七工具与能力

137=130DFIR+7transfer。旧六input逐值不变，第七transfer_chunks公共transfer_id/request_digest/offset，push仅chunks，pull仅count_per_chunk/chunk_count；请求方向是已登记同ID/digest request，不能混用或公开另一个方向真值。exact input/output和复用defs见[七schema](seven-tool-contract.schema.json)。unknown/null/bool充整数/分数/方向混合在副作用前拒绝；strict base64实际decode/count/hash校验不是contentEncoding注释能证明。

enabled=true必需binary_wire，值null或exact{version:VBT1,session_required:true}；stdio=null；null从开始JSON，不试写猜wire。enabled=false仅原schema/enabled/reason三字段。max_batch_chunks可选grant整数1..64，缺则同server single，第七仍必需；旧six server固定incompatible_server，不能自动Windows。binary非空仍要同SDK活session/实例，begin后业务channel固定。

## W02 结果、phase/action与错误

outer保留velo.transfer.mcp.response.v1，success/result或error/error.code exact互斥。合法业务error structuredContent isError=false；tool协议错误与业务error分开，无structuredContent不能成功。SDK标准text content镜像允许，但必须和structuredContent同一事实、无矛盾；不强制content=[]。不能把旧130DFIR结果合同强套transfer。HTTP200 binary业务error为VBT1 status=error/error.code、payload0。

固定错误集合是[码表](error-catalog.json)中R01 catalog并集worker_failed/worker_result_unknown/chunk_outcome_unresolved，去重排序；未列动态内部错误只能internal_error，不因此可重试/fallback；完整细节仅受控本地日志，无响应detail/token/path/input/exception。精确安全HTTP JSON body={error:{code}}，Content-Type application/json：401 unauthorized；421 bad_host；403 origin_denied；400缺session=session_required、frame/header格式=invalid_frame；404 session_not_found；413 body_too_large；415 unsupported_media_type；500 internal_error。客户端instance变化=instance_changed，协议/解析失败=protocol_error或malformed_response，禁止归并connection_failed。

所有phase/state_scope/binding.direction/operation.action/inputs/result/status/Terminal同state交叉一致性强制验证。schema能表达的映射已约束；跨字段same digest/offset/nonce/receipt-K及文件语义必须生产/消费者真实联合复核，不能只看枚举存在。

## W03 VBT1请求及方向组件

附属POST /chunkbin同Windows正式进程28790端口，不是第八tool或Windows控制面代理。SDK先建立同server活session；Mcp-Session-Id绑定同Bearer，缺400/unknown或expired404，同server-instance两端核。Bearer→Host/Origin→session/instance→预算/strictframe→业务；缺Origin原义允许，presentOrigin严格，Host精确host:port；真实host-only防火墙来源门单独证明。

HTTP名称x-velo-transfer-id/x-velo-request-digest/x-velo-offset/x-velo-direction，pull额外x-velo-count-per-chunk/x-velo-chunk-count，push禁止pull参数。各恰一值，大小写变体重复、逗号合并、前后空白、非规范十进制均拒绝；数字格式0|[1-9][0-9]*，正数禁止0。仅push/pull，HTTP元数据与同request身份/方向/digest联合校验；不得frame与headers重复取同一逻辑参数。

Content-Type application/octet-stream。frame=ASCII VBT1(4)+uint32LE headerlength(4)+exact长度strict UTF8 JSON header+payload。重复键/NaN/Infinity/unknown keys/非UTF8/malformed/type错拒绝。push header exact chunks[count,chunk_sha256]，payload恰count总和，逐项真实SHA一致。pull必须完整VBT1帧header={}、payload0，范围只HTTP headers。不能忽略pull body，也不能用任意oneOf猜方向；[VBT1组件库](vbt1-wire.schema.json)按已批准方向/响应种类选具体defs。

push成功header={status:success,result:{verified_offset,accepted}}、payload0；pull={status:success,result:{verified_offset,chunks:[offset,count,chunk_sha256]}}、payload顺序拼接且恰耗尽；业务error={status:error,error:{code}}、payload0。non200安全拒绝先按HTTP分类解析JSON；200也必须完整shape/hash/byte/instance验证后才记wire可用。

## W04 预算、合法写入与只读pull

单decoded chunk≤min(policy.max_chunk_bytes,1048576)，batch grant1..64/raw总量≤67108864，header≤1048576，数据调用实际HTTP请求/响应body≤104857600（JSON/SSE计封装，binary计8+header+payload，更低policy优先，不改DFIR result合同）。实际流式已读/将写字节计数，超过上限立即中止，Content-Length/batch sizing不是硬限。每call重算绝对deadline、取消/metadata/disk/free space预算，超限不切channel。

push完整批次结构、全部decode/hash/count/方向/offset和metadata/disk/deadline预验后才writer，非法第二项也零physical写与任务副作用。合法IO/crash不承诺物理事务：只可证明owned tail；payload flush/fsync先于ledger持久化/state发布，uncertain sync不得accepted。ledger逐chunk offset/count/sha连续，acknowledged prefix唯一进度；恢复完整重验，只截该attempt owned tail，foreign/final不动。batch不承诺已接受range自动幂等重发，原single同字节replay不被删。

pull真实源身份/metadata固定、chunk连续offset/count/hash，尾短但不零填充，空包无chunk；越EOF/短response/extra payload/漂移拒绝。guest verified_offset不等host落盘进度；host实际内容验证落盘才推进。

## W05 OD06未知push重验完成证明

begin/status/abort返回State必需prefix_verification，null或exact七键：schema=velo.transfer.prefix-verification.v1、request_digest=64hex、worker_nonce非空、verified_offset≥0 integer、chunk_count≥0 integer、ledger_sha256=64hex、completed=true。未知结果先status观察固定ID/digest/channel/package并记录旧nonce/proof，再固定原request begin resume执行现verify_partial有界全prefix验证，不续期deadline。活writer只等待同任务在剩余deadline内完成，不并发争抢。

verify_partial真实读取payload/ledger、identity/预算/连续hash全部成功后，证明与state同一受保护修订原子保存，nonce是该worker，不因stopped/进程退出补造。ledger摘要是截至offset完整持久ledger原字节；零prefix摘要空字节SHA也必须验证owned初态。合法写入一开始、offset/ledger/identity改变、重验开始/失败、cancel都清空proof，不能保留旧成功给新offset。

消费者必须见相对事前观察的新verify_partial nonce、完整对应proof、error=null、worker已停止且lease释放，proof digest/offset/chunk_count/ledger与该次重验state匹配，才能续已证offset；begin应答丢也不放宽新nonce门。不能区分新旧→chunk_outcome_unresolved，不盲重试begin/batch、不换channel/编码回放。整包已全也先重验再finish。

State wire只新增prefix_verification，不擅加另一组chunk_count/ledger顶字段；其内部state/ledger联合复核由真实worker/持久化验证器负责，客户端检查已冻结可信服务返回的proof+同request/worker/offset，并以其受控发送/进度记录核可观察约束。不能将证明的自述替代实际producer prefix读取/原子保存/lease证据；这些运行语义由矩阵确认，静态schema和context向量不提供执行证明。

全部新增[矩阵](acceptance-matrix.json)与旧六矩阵均正式Windows NOT_VERIFIED，业务错误不充success/645，非法写拒绝与合法崩溃保全分开。129×5=645、三phase九Flow/七八kind/P07和最后未参与者独立全面核验不减。

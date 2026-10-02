# PC026 六项精确契约主控裁决

主控作者决定，补充2026.10.02-01作者稿。六项设计选择在此确定；完整九文档/附件同步及155条主控自评仍未完成，故尚未采纳规范组、未开启实施/来源READY/恢复门。T011/R01只是候选底稿，其OPEN不得自行成为生产规则。

## OD01 VBT1请求坐标

采用现有HTTP x-velo-transfer-id/request-digest/offset/direction；pull额外count-per-chunk/chunk-count。名称均加x-velo-前缀且各恰一值；重复（包括大小写变体）、逗号合并、前后空白、非规范十进制拒绝。pull请求为完整VBT1帧、header恰{}、payload零字节，范围只取HTTP headers。push header恰chunks数组，各项count/chunk_sha256，禁止pull参数。不得同时从frame与headers取同一逻辑参数。Content-Type固定application/octet-stream。所有HTTP元数据仍需请求身份/方向/摘要联合校验，header长度预算不代替MCP session检查。响应形状采用T011候选，按方向选组件而非用任意oneOf猜方向；严格耗尽payload。

## OD02 capability协商

采用binary_wire必需字段：enabled=true result中为null或exact {version:"VBT1",session_required:true}；null表示该连接无二进制能力，从开始选JSON。enabled=false沿原schema/enabled/reason三字段，不要求binary_wire。stdio连接binary_wire=null。max_batch_chunks为可选grant整数1..64，未授予时只用single，不以服务器不存在第七工具解释。binary_wire非空仍要求SDK session存在且同实例；同begin之后不能换业务channel，JSON/binary未知结果不能回放。

## OD03 输出与错误集合

T011七tool候选嵌套State/Terminal/Operation字段及phase/job枚举作为收紧基础，原六input逐值保持。增加下述OD06 State.prefix_verification字段；不得遗漏动态错误worker_failed。错误集合固定为T011 error-catalog.catalog_candidate并集worker_failed、worker_result_unknown及chunk_outcome_unresolved（去重排序），不允许任意动态字符串穿透。内部未列举异常只映射internal_error，完整详情仅本地受控日志，不进入HTTP/MCP响应；此映射不使未知错误可重试或可降级。

HTTP安全拒绝采用application/json，body恰{error:{code}}：401 unauthorized；421 bad_host；403 origin_denied；400 session_required（缺session）或invalid_frame（frame/headers格式）；404 session_not_found；413 body_too_large；415 unsupported_media_type；500 internal_error。实例变化客户端固定instance_changed，协议/解析失败protocol_error或malformed_response；不得归并connection_failed。六工具旧server固定incompatible_server。

合法业务错误MCP structuredContent保留velo.transfer.mcp.response.v1/error.code，isError=false；工具调用本身的协议错误与业务错误分离，不能把无structuredContent当成功。content允许SDK标准文本镜像但不得产生与structuredContent矛盾的第二事实，不强制content=[]。二进制业务错误HTTP200、VBT1 status=error/error.code、无payload；安全拒绝先按非200状态解析JSON。所有路径只code，不返回异常detail。各phase/action/result的交叉一致性是强制语义验证，不能仅靠schema枚举存在。

## OD04 根与Ref坐标

所有治理Ref统一相对仓库根解析，不相对引用文件parent。Ref规范POSIX相对路径，不允许空段、.、..、反斜线、冒号、绝对路径、NUL、链接或重解析逃逸。治理允许清单由主控采纳记录固定；拒绝.tmp及未采纳candidate，不能允许调用者增目录。

root_mapping采用五键：host_governance_root固定Logs/P05/wf-01a05d1d-p05（此名字表示证据治理镜像根，不是Ref解析基准）、guest_project_coordinate、guest_evidence_root固定同Logs坐标、guest_canonical_coordinate、deployment_configuration三键Ref。guest_project_coordinate是已批准部署base下非空规范相对路径；guest_canonical_coordinate是guest项目根相对路径，与批准规范唯一canonical位置相等。部署配置明确host仓库根/guest部署base及实际项目根，身份核验后才能使用；不是任意env/CLI输入。批准文件仍固定PLAN/2026.10.02/controller-approval.json，且其自身hash由外侧运行记录固定。

## OD05 双端发布身份

保留候选receipt schema1/kind pc026-dual-publication-receipt-v1、19顶键及四UTC时间，不能靠时间字符串证明持久化。新增每member的host_identity/guest_identity均按不同平台精确结构验证，不再把host UID塞入SID字段。

host_identity exact：platform="posix"、device为规范无符号十进制字符串、inode同格式、owner_uid同格式、owner_gid同格式、principal_uid同格式、mode为四位八进制权限串（不含类型位）、acl_sha256为64小写hex。摘要对应完整保存的规范化ACL证据：至少mode/owner/group，若有扩展ACL必须完整排序编码，不支持读取时拒绝，不能只把mode假称完整ACL。

guest_identity exact：platform="windows"、volume_serial为16位小写hex、file_id为32位小写hex（FileIdInfo原16字节按返回内存顺序hex，不作GUID转换）、owner_sid/principal_sid为规范Windows SID字符串、acl_sha256为64小写hex。ACL摘要取同句柄身份绑定的原始self-relative security descriptor字节，其归档Ref必须能定位；不以友好账户名或临时PowerShell身份替代服务/controller实际principal。

上述ACL原件和身份观察记录放在部署/发布证据中；receipt新增顶键identity_evidence，类型为唯一归档manifest的path/size/sha256 Ref，故最终顶键总数20。identity_evidence内逐member/endpoint唯一映射原件Ref和观察身份，完整覆盖，缺失/多余/重复拒绝。root_mapping摘要固定UTF8 JSON ensure_ascii=false/sort_keys=true/separators=(',',':')、无换行、无非有限数。成员按relative_path UTF8字节排序，不能用不稳定对象遍历序。跨端volume/file值无需相同，路径/size/content hash须相同；主机模式值不替代Windows ACL校验。

## OD06 未知push结果的重验完成证明

status先观察同ID/digest/channel/package，但普通verified_offset值不等于新重验。未知push结果（包括binary/JSON超时或坏响应）禁止直接重发；固定原request再次begin，沿现有verify_partial worker执行有界完整prefix验证，不续期原deadline。若仍有活writer则等待同一任务结束并在剩余deadline内重验，不能争抢新writer。

State增加必需prefix_verification，值null或exact对象：schema="velo.transfer.prefix-verification.v1"、request_digest=64hex、worker_nonce非空string、verified_offset非负整数、chunk_count非负整数、ledger_sha256=64hex、completed=true。该对象必须在对应verify_partial worker完整读取实际payload/ledger、核identity/预算/连续hash并持久化成功后，和state同一受保护修订原子保存；使用该worker nonce，不因进程退出或stopped=true自动补造。ledger摘要是截至verified_offset的完整持久ledger原字节；零前缀使用空字节SHA但仍验证owned初态。合法写入一旦开始、offset/ledger/身份变动、重验开始或失败、任务取消时清空该证明。不可将旧成功证明留给新offset使用。

客户端先记录status旧nonce/证明，再begin resume，必须看到对应新verify_partial nonce完成、error=null、worker已停止且lease释放、证明digest/offset/chunk_count/ledger与该重验state一致，才按此offset续传；即使begin响应丢失，也只能接受相对于事前观察的新nonce完整证明。无法区分新旧worker则chunk_outcome_unresolved，不盲重试begin或batch。仅依赖stopped与error为空不足，因为worker可能在证明保存前崩溃。完成全部字节也必须重验后转原finish流程。

追加正反矩阵：重验前/中/保存前崩溃无证明；成功保存且返回丢失可恢复；旧nonce/错digest/旧offset/被篡改ledger拒绝；合法下一chunk使证明失效；零前缀、deadline不续期、foreign尾巴不截断、活writer不并发。此新增output/持久字段属于PC026契约变化，必须同步schemas/消费者/存储验证器和源freeze，不能宣称现代码已实现。

## 采纳边界

六项选择不再留给执行端裁决。执行端仅按此同步候选及检查内部一致性；真正发现相互矛盾必须指出，不自行削弱。主控最终逐155条自评和正式manifest采纳另记，未发生以前不批准生产运行。新正式文档组不依赖.tmp中的可消失文件：规范附件与历史证据引用分别整理，历史调查路径只作溯源，不作为生产loader来源。

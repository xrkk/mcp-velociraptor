> 已采纳规范内容；本文件中的候选历史状态不覆盖 [主控最终修正](controller-review-corrections.md)。运行与恢复尚未批准。

# PC026 外部批准、根与双端身份归档 R02

状态DRAFT_PENDING_CONTROLLER_SELF_REVIEW；[02裁决](../support/controller-decisions-od01-06.md)补充优先，[精确模型](controller-model.schema.json)只定义schema，不生成READY/VERIFIED批准、receipt或观测实例。

## G01 批准、Ref与无循环

loader固定PLAN/2026.10.02/controller-approval.json，11 exact顶keys/schema1/kind pc026-controller-approval-v1/profile pc026-snapshot191-v1，缺失或非READY拒。主控在实施冻结、双端实际发布核验后单独签发；采纳/运行记录在外側锁批准file hash，运行中漂移拒，不自动改hash自授。可信来源是主控受控治理目录/动作，非数字签名，不抵御同权限任意改治理文件的进程。无CLI/env任意policy/root，不能扫描.tmp。

全部治理Ref exact path/size/sha256且统一相对仓库根，不按引用文件parent解析。规范POSIX相对路径无空段、.、..、反斜线、冒号、绝对/NUL或链接/reparse逃逸；主控采纳记录固定治理允许清单，拒仓库.tmp与未采纳candidate，caller不可扩目录。历史固定Logs包内source/.tmp等原relative成员只是已批准历史归档坐标，不是仓库.tmp输入，也不允许据其扫描外部源。

root_mapping五键：host_governance_root=Logs/P05/wf-01a05d1d-p05（证据镜像根，非Ref解析基准）、guest_project_coordinate（批准deployment base下非空规范relative）、guest_evidence_root同Logs项目relative、guest_canonical_coordinate（项目根relative且与唯一canonical批准位置相等）、deployment_configuration三键Ref。部署配置锁host仓库根/guest base/真实项目根并先核identity，非任意env/CLI输入。

normative manifest最终路径PLAN/2026.10.02/pc026-r01/current-normative-inputs-pc026-r01.json；本轮候选状态尚待主控自评，不接loader。manifest不hash自身，approval不入它引用的freeze；publication receipt引用规范/implementation/bootstrap清单及独立identity archive，archive只引用身份观察/ACL原件，不回引receipt或approval。外侧运行批准记录不纳入冻结自授。源码实施后再冻完整实现/helper/tests/fixture/scenarios，不借本轮观测hash或未来null占位READY；第三方wheel/真实安装/service principal另有部署证据。

## G02 平台分型与20键发布receipt

publication receipt schema1/kind pc026-dual-publication-receipt-v1保留R01 19字段，新增identity_evidence三键Ref共20，四真实UTC时间不由字符串证明持久化。members按relative_path UTF8字节排序、target唯一；双端path/size/contentSHA相同，volume/file平台值不要求同值。

host_identity exact8：platform=posix、device/inode/owner_uid/owner_gid/principal_uid为规范无符号十进制string（0或无前导零）、mode四位八进制不含类型位、acl_sha256 lowercase64hex。完整保存规范化ACL至少mode/owner/group，扩展ACL完整排序编码；无法读取拒绝，不能只mode冒完整ACL。

guest_identity exact6：platform=windows、volume_serial=16位lowerhex、file_id=32位lowerhex（同handle FileIdInfo原16字节按内存顺序hex，不作GUID变换）、owner_sid/principal_sid规范Windows SID、acl_sha256=lower64hex。摘要对应同句柄身份绑定的原始self-relative security descriptor bytes，其归档Ref定位真实原件；不用友好账户名/临时PowerShell账户替实际service/controller principal。schema拒混平台/额外键/错编码，数字范围/同句柄/实际principal仍真实语义核验。

identity_evidence Ref唯一归档manifest schema1/kind pc026-identity-evidence-v1，exact顶schema_version/kind/members；每member exact relative_path/endpoint(host|guest)/identity(相应平台)/observation_ref。relative_path+endpoint唯一，完整覆盖receipt每member双端，不缺/extra/duplicate。observation原件至少身份、ACL原件Ref、实际observed_at与method；本模型给exact schema1/kind pc026-identity-observation-v1、relative_path/endpoint/identity/acl_original/observed_at/method。host method=posix_fstat_full_acl，guest=windows_same_handle_fileid_security_descriptor；这些标记不得把静态/替身/申明伪作执行，真实调用/句柄/ACL bytes/action time原件必须另核。

archive/observation/receipt三者identity与path/endpoint、ACL原件hash/size/实际时刻/方法真实对应；host ACL摘要为规范化完整证据字节SHA，guest为原security descriptor字节SHA。root_mapping SHA固定UTF8 JSON ensure_ascii=false/sort_keys=true/separators=(',',':')无换行无非有限数。方法枚举只命名真实观察，不单凭method文字证明过去执行；本轮不制造任何观测。

## G03 历史发布、唯一writer与镜像

[bootstrap声明清单](bootstrap-publication-manifest.json)含448原递归目标+4固定bootstrap文件，只有正式Logs target/hash/size，不引用仓库.tmp源。原路径/hash与T007最终闭包核对的溯源另存本轮证据，不是生产依赖；清单NOT_PUBLISHED，目标未发布不得凭元数据READY。两包只增按原relative路径，bootstrap-pc020/epoch7四文件不变；C7/H5/pre/mig/policy/COMMITTED receipt完整历史谓词验，不重跑消耗5/6，不改历史source成当前source；旧189图/initial/cycle均不充新191成功。

同字节既存可核验复用，不同/异常type/未知member/unsafeancestor拒绝不覆盖。实际host/guest发布核验、guestprincipal/ACL/volume/instance/fsync/readback完整后主控才READY。guest唯一Windows canonical writer执行新initial→creation191→2candidate→完整R13/S13及cap原子复核消费→native C7→C8持久化/完整读回→COMMITTED；host仅先C7治理镜像，后完整COMMITTED+A/C8已核再原子镜像，不补造C8/receipt或mint能力。guestcommit host失败则host停止选择/只读重新接收同事实，不回滚C7/复用cap，无跨端原子事务声称。

selector/实际runner/receiver/aggregate/P07同批准束及旧epoch7 receipt+新activation完整资格；189/188/schema3无快照都不是当前路径。READY只准备，不自动恢复；190后资料保全/独占窗口/明确序列先落实，禁止定时回滚。本轮候选不操作VM。

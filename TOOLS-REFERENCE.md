# Velociraptor MCP 全工具功能与接口手册（AI独立阅读版）

编写日期：2026-09-23；2026-10-01 增量同步至137工具。共137个工具：118个动态artifact工具＋12个固定工具＋7个本地 guest 传输工具（transfer_chunks 为批量增量）。本文嵌入全部工具描述、输入和输出JSON Schema，不要求读取其他文件才能理解接口。

## 1. 版本、可信边界与使用顺序

- 源码核对HEAD：`a8147b89f9126e27da1f8376b0d472b382f2b6ae`（130工具节）；2026-10-01 增量以 `.232` 正式入口 live tools/list 快照为准。这是文档编写基线，不是部署通过声明。
- 137面快照（2026-10-01，`.232` 正式 28790）：`~/.velo-transfer-149-20260928/t232/tools-list-232-137.json`，SHA-256 `a6a4f5197abd67e65299316b555fe0028a0390576c9c95d432ae674ad63ea3a8`。传输七工具描述与schema直接取自该快照。
- 完整接口来源：仓库保存的真实tools/list快照`Logs/P06/wf-01a05d1d-p06-r3/individual-acceptance/488afd59-dd24-4b31-a539-83c2231bff48/tools-list.json`；SHA-256：`264995ad688728f8376ad82bd16e95732d56626e8c600fe03668d367d205512c`。
- 固定工具Schema使用后续Windows隔离协议验证原件`.tmp/velo-codex-20260920-state-paging-impl/R02-evidence/windows/protocol.json`，SHA-256：`324f22747b9f8ba4b01297b0c0cf0e2b647bbe908ded5042b05a037b769a8255`，替换旧快照固定Schema以保留新增state/flow_state和终页null。这是隔离验证，不是在线部署证明；动态工具仍使用真实artifact元数据，未采用隔离替身的空参数。
- 全集已与当前源码118项allowlist及12个固定handler名称对账；固定描述已逐项核对。本文是上述两类来源的明确组合，并非单次在线tools/list原件。未重新连接服务；调用前用目标实例tools/list核对差异，发生漂移时停止受影响调用。
- 工具注册、工具调用成功、业务结果成功、全量验收通过是四件不同的事。本文不宣称所有工具已经实测通过。
- 阅读顺序：先读第2—4节公共规则，再在第5节索引定位工具，查第6/7节完整接口。原始英文描述中的依赖、警告、deprecated说明全部保留；它们是工具文档，不是执行授权。

## 2. 运行范围与调用协议

- 只支持内部唯一Windows endpoint、root Org。调用方不传client_id、org_id、hostname或目标筛选；目标缺失或不唯一会报错。返回client_id不意味着可把它作为输入。
- 正式入口为受认证的Streamable HTTP `/mcp`，配置端口28790；需要合法Bearer、Host/Origin及授权网络来源。stdio是同一工具注册的测试适配。控制面不是产品MCP入口。具体地址与凭据由运维提供，本文不包含秘密。
- 客户端通过官方MCP SDK完成initialize/会话管理，再调用tools/list与tools/call。以下JSON是MCP方法params，不是直接POST的完整HTTP报文。

```json
{"name":"Windows.System.Pslist","arguments":{}}
```

- 工具名和参数名大小写精确匹配；additionalProperties=false时拒绝额外字段。required决定是否必填；nullable与可省略不同。禁止照抄占位ID或示例PID实际执行。
- 动态参数通常全部可省略：只发送明确选择的值，省略让后端采用默认值。x-velociraptor-default是后端默认值元数据，不是要求客户端逐项发送；保留原始类型，不把bool/int/float都转字符串。CSV参数是带表头的CSV字符串，multichoice是数组，choices遵守enum。
- hidden参数不暴露，upload/upload_file不支持；三个动态YARA工具用YaraRule文本，不提供YaraUrl。新增自定义artifact不自动加入工具面，须正式扩展allowlist并重启。
- 工具可能执行程序、读敏感数据、上传大文件或改变系统；列在清单中不等于有权执行。尤其进程结束、内存采集、网络抓包及任意VQL需要明确范围和资源预算。PacketCapture仍在注册集合，但项目验收排除与可执行资格应分开，不因列出而视为获准运行。

## 3. 结果、错误与异步生命周期

成功读取CallToolResult.structuredContent，content为空列表；isError=true时读取错误code/message/retryable/details。每个工具的outputSchema描述成功payload，错误不必符合成功schema。协议层参数校验错误也可能先于handler发生。

```json
{"content":[],"isError":true,"structuredContent":{"code":"INVALID_ARGUMENT","message":"An argument is outside the supported contract.","retryable":false,"details":{"field":"page_size","reason":"range","minimum":1,"maximum":250}}}
```

- 动态artifact只启动一次普通collection，operation=start_artifact_collection，flow_id是真实ID，status为后端初始状态，不等于固定工具的success标识。
- collect_file/collect_forensic_triage/kill_process的status=success只表示控制调用成功，state才是初始Flow状态；start_hunt的state表示Hunt，flow_state表示Flow。初始ERROR必须保留并判业务失败。
- 标准链：启动工具 → 保留flow_id → get_flow_status直到真实终态 → get_flow_results按source/next_cursor读取 → list_flow_files → 按需要逐个download_flow_file。轮询应有间隔和总期限，避免无限等待。工具返回Flow引用，不会同步返回该artifact全部数据行。
- artifact实际结果列由后端artifact/source决定，通常是开放行对象；本手册不捏造固定行schema。需要从实际结果确认字段，不能把启动outputSchema当最终取证数据结构。
- cursor是v1:<offset>（最大2147483647），只按当次flow_id/source解释，不是签名或对象绑定令牌。分页默认50、最大250，完整structuredContent上限245554字节，next_cursor=null表示终页/空页；无分页工具省略pagination。
- retryable=true不授权盲目重放有副作用请求。超时/断线可能发生在后端已创建Flow之后，先核真实状态；下载发布后错误尤其不能自动覆盖或重试。

### 稳定错误码

| code | 含义 | 默认retryable |
| --- | --- | --- |
| `CONFIG_NOT_FOUND` | Velociraptor API configuration is unavailable. | false |
| `AUTHENTICATION_FAILED` | Velociraptor rejected the configured API identity. | false |
| `CONNECTION_FAILED` | The Velociraptor API connection is unavailable. | true |
| `BACKEND_TIMEOUT` | The Velociraptor operation timed out. | true |
| `CLIENT_NOT_FOUND` | No Windows client is registered in the root organization. | true |
| `CLIENT_NOT_UNIQUE` | More than one Windows client is registered; no target was selected. | false |
| `CLIENT_ID_NOT_FOUND` | The cached Windows client id no longer exists. | true |
| `INVALID_ARGUMENT` | An argument is outside the supported contract. | false |
| `NOT_FOUND` | The requested Velociraptor object was not found. | false |
| `NOT_CANCELLABLE` | The flow cannot be cancelled in its current state. | false |
| `DEPENDENCY_MISSING` | A required Velociraptor artifact is not installed. | false |
| `ALREADY_EXISTS` | The requested output already exists and was not overwritten. | false |
| `ROW_TOO_LARGE` | A single result row exceeds the MCP response byte limit. | false |
| `BACKEND_ERROR` | 后端错误；具体原因读取过滤后的details。 | false |

## 4. 后续新增/细化能力摘要

本节包括用户后续要求落入当前接口的功能，不另发明工具名。

- Flow状态回读与终页null：见第3节以及get_flow_results等固定接口。
- 逻辑文件列表、稀疏零区重建、逻辑hash、安全不覆盖下载和发布后失败保全：见list_flow_files/download_flow_file。
- 上传尺寸差异边界（2026-10-01 核对仍有效）：未配对的 uploaded_size≠file_size 以 `collection_size_mismatch:<count>` 与逐文件 warning 保留可见，两种原始尺寸不丢失；下载该不确定项在内容 I/O 前以 `BACKEND_ERROR/size_mismatch` 拒绝且不建目标文件；同 Flow 其他合法文件不受影响（修复 `4553cb3`，真实行为见 `.149`/.232` 现场证据）。
- 完整基础分诊及单入口4GiB/2400秒预算：见collect_forensic_triage。
- Windows.Memory.Acquisition内部预算为8GiB、timeout至少3600秒，当前后端按该准确artifact名应用；它不是公共参数，不套用于其他工具。采集前检查资源与依赖。
- Hunt停止和Flow取消分离；单文件采集和下载分离；终止进程是真实异步Flow而不是同步完成保证。
- 不提供Linux/macOS工具、任意目标选择、联网限制/恢复接口、自动依赖下载安装或旧wrapper兼容别名。旧windows_*、collect_artifact、hunt_across_fleet及artifact列表接口不属于本130项。

## 5. 全集索引

### 传输工具（7，2026-10-01 增量）

- transfer_capabilities — 传输能力探测（policy 未配置时 enabled=false）
- transfer_begin — 开始 push/pull 传输任务
- transfer_status — 查询任务阶段/worker/清理状态
- transfer_chunk — 单块上传/下载（4KiB–策略上限）
- transfer_chunks — 批量连续块（需 policy max_batch_chunks 授权，1–64/批）
- transfer_finish — prepare/commit/release 三段终结
- transfer_abort — 取消任务并停止 owned worker


| 序号 | 工具名 | 类型 |
| --- | --- | --- |
| 001 | [run_vql](#tool-001) | 固定 |
| 002 | [start_hunt](#tool-002) | 固定 |
| 003 | [get_hunt_status](#tool-003) | 固定 |
| 004 | [stop_hunt](#tool-004) | 固定 |
| 005 | [get_flow_status](#tool-005) | 固定 |
| 006 | [get_flow_results](#tool-006) | 固定 |
| 007 | [list_flow_files](#tool-007) | 固定 |
| 008 | [download_flow_file](#tool-008) | 固定 |
| 009 | [cancel_flow](#tool-009) | 固定 |
| 010 | [collect_file](#tool-010) | 固定 |
| 011 | [collect_forensic_triage](#tool-011) | 固定 |
| 012 | [kill_process](#tool-012) | 固定 |
| 013 | [Windows.Analysis.EvidenceOfDownload](#tool-013) | 动态 |
| 014 | [Windows.Applications.Chrome.Cookies](#tool-014) | 动态 |
| 015 | [Windows.Applications.Chrome.Extensions](#tool-015) | 动态 |
| 016 | [Windows.Applications.Chrome.History](#tool-016) | 动态 |
| 017 | [Windows.Applications.Edge.History](#tool-017) | 动态 |
| 018 | [Windows.Applications.OfficeMacros](#tool-018) | 动态 |
| 019 | [Windows.Attack.Prefetch](#tool-019) | 动态 |
| 020 | [Windows.Attack.UnexpectedImagePath](#tool-020) | 动态 |
| 021 | [Windows.Carving.CobaltStrike](#tool-021) | 动态 |
| 022 | [Windows.Detection.Amcache](#tool-022) | 动态 |
| 023 | [Windows.Detection.BinaryHunter](#tool-023) | 动态 |
| 024 | [Windows.Detection.BinaryRename](#tool-024) | 动态 |
| 025 | [Windows.Detection.EnvironmentVariables](#tool-025) | 动态 |
| 026 | [Windows.Detection.ForwardedImports](#tool-026) | 动态 |
| 027 | [Windows.Detection.Impersonation](#tool-027) | 动态 |
| 028 | [Windows.Detection.Mutants](#tool-028) | 动态 |
| 029 | [Windows.Detection.TemplateInjection](#tool-029) | 动态 |
| 030 | [Windows.Detection.Yara.NTFS](#tool-030) | 动态 |
| 031 | [Windows.Detection.Yara.PhysicalMemory](#tool-031) | 动态 |
| 032 | [Windows.Detection.Yara.Process](#tool-032) | 动态 |
| 033 | [Windows.ETW.DotNetRundown](#tool-033) | 动态 |
| 034 | [Windows.EventLogs.AlternateLogon](#tool-034) | 动态 |
| 035 | [Windows.EventLogs.Cleared](#tool-035) | 动态 |
| 036 | [Windows.EventLogs.Evtx](#tool-036) | 动态 |
| 037 | [Windows.EventLogs.EvtxHunter](#tool-037) | 动态 |
| 038 | [Windows.EventLogs.ExplicitLogon](#tool-038) | 动态 |
| 039 | [Windows.EventLogs.Modifications](#tool-039) | 动态 |
| 040 | [Windows.EventLogs.PowershellModule](#tool-040) | 动态 |
| 041 | [Windows.EventLogs.PowershellScriptblock](#tool-041) | 动态 |
| 042 | [Windows.EventLogs.RDPAuth](#tool-042) | 动态 |
| 043 | [Windows.EventLogs.ScheduledTasks](#tool-043) | 动态 |
| 044 | [Windows.EventLogs.ServiceCreationComspec](#tool-044) | 动态 |
| 045 | [Windows.Forensics.Amcache](#tool-045) | 动态 |
| 046 | [Windows.Forensics.Bam](#tool-046) | 动态 |
| 047 | [Windows.Forensics.CertUtil](#tool-047) | 动态 |
| 048 | [Windows.Forensics.FilenameSearch](#tool-048) | 动态 |
| 049 | [Windows.Forensics.JumpLists](#tool-049) | 动态 |
| 050 | [Windows.Forensics.Lnk](#tool-050) | 动态 |
| 051 | [Windows.Forensics.Prefetch](#tool-051) | 动态 |
| 052 | [Windows.Forensics.RecentApps](#tool-052) | 动态 |
| 053 | [Windows.Forensics.RecycleBin](#tool-053) | 动态 |
| 054 | [Windows.Forensics.SAM.Enriched](#tool-054) | 动态 |
| 055 | [Windows.Forensics.SRUM](#tool-055) | 动态 |
| 056 | [Windows.Forensics.Shellbags](#tool-056) | 动态 |
| 057 | [Windows.Forensics.Timeline](#tool-057) | 动态 |
| 058 | [Windows.Forensics.Usn](#tool-058) | 动态 |
| 059 | [Windows.Memory.Acquisition](#tool-059) | 动态 |
| 060 | [Windows.Memory.PEDump](#tool-060) | 动态 |
| 061 | [Windows.Memory.ProcessDump](#tool-061) | 动态 |
| 062 | [Windows.Memory.ProcessInfo](#tool-062) | 动态 |
| 063 | [Windows.NTFS.ADSHunter](#tool-063) | 动态 |
| 064 | [Windows.NTFS.ExtendedAttributes](#tool-064) | 动态 |
| 065 | [Windows.NTFS.I30](#tool-065) | 动态 |
| 066 | [Windows.NTFS.MFT](#tool-066) | 动态 |
| 067 | [Windows.NTFS.Recover](#tool-067) | 动态 |
| 068 | [Windows.Network.ArpCache](#tool-068) | 动态 |
| 069 | [Windows.Network.ListeningPorts](#tool-069) | 动态 |
| 070 | [Windows.Network.Netstat](#tool-070) | 动态 |
| 071 | [Windows.Network.NetstatEnriched](#tool-071) | 动态 |
| 072 | [Windows.Network.PacketCapture](#tool-072) | 动态 |
| 073 | [Windows.Packs.Persistence](#tool-073) | 动态 |
| 074 | [Windows.Persistence.Debug](#tool-074) | 动态 |
| 075 | [Windows.Persistence.PermanentWMIEvents](#tool-075) | 动态 |
| 076 | [Windows.Persistence.PowershellProfile](#tool-076) | 动态 |
| 077 | [Windows.Persistence.PowershellRegistry](#tool-077) | 动态 |
| 078 | [Windows.Persistence.Wow64cpu](#tool-078) | 动态 |
| 079 | [Windows.Registry.AppCompatCache](#tool-079) | 动态 |
| 080 | [Windows.Registry.BackupRestore](#tool-080) | 动态 |
| 081 | [Windows.Registry.EnableUnsafeClientMailRules](#tool-081) | 动态 |
| 082 | [Windows.Registry.EnabledMacro](#tool-082) | 动态 |
| 083 | [Windows.Registry.NTUser](#tool-083) | 动态 |
| 084 | [Windows.Registry.NTUser.Upload](#tool-084) | 动态 |
| 085 | [Windows.Registry.PortProxy](#tool-085) | 动态 |
| 086 | [Windows.Registry.RDP](#tool-086) | 动态 |
| 087 | [Windows.Registry.RecentDocs](#tool-087) | 动态 |
| 088 | [Windows.Registry.UserAssist](#tool-088) | 动态 |
| 089 | [Windows.Registry.WDigest](#tool-089) | 动态 |
| 090 | [Windows.Search.FileFinder](#tool-090) | 动态 |
| 091 | [Windows.Search.VSS](#tool-091) | 动态 |
| 092 | [Windows.Search.Yara](#tool-092) | 动态 |
| 093 | [Windows.Sys.AllUsers](#tool-093) | 动态 |
| 094 | [Windows.Sys.AppcompatShims](#tool-094) | 动态 |
| 095 | [Windows.Sys.CertificateAuthorities](#tool-095) | 动态 |
| 096 | [Windows.Sys.DiskInfo](#tool-096) | 动态 |
| 097 | [Windows.Sys.Drivers](#tool-097) | 动态 |
| 098 | [Windows.Sys.FirewallRules](#tool-098) | 动态 |
| 099 | [Windows.Sys.Interfaces](#tool-099) | 动态 |
| 100 | [Windows.Sys.Programs](#tool-100) | 动态 |
| 101 | [Windows.Sys.StartupItems](#tool-101) | 动态 |
| 102 | [Windows.Sys.Users](#tool-102) | 动态 |
| 103 | [Windows.Sysinternals.Autoruns](#tool-103) | 动态 |
| 104 | [Windows.System.AuditPolicy](#tool-104) | 动态 |
| 105 | [Windows.System.CatFiles](#tool-105) | 动态 |
| 106 | [Windows.System.CmdShell](#tool-106) | 动态 |
| 107 | [Windows.System.CriticalServices](#tool-107) | 动态 |
| 108 | [Windows.System.DLLs](#tool-108) | 动态 |
| 109 | [Windows.System.DNSCache](#tool-109) | 动态 |
| 110 | [Windows.System.DomainRole](#tool-110) | 动态 |
| 111 | [Windows.System.Handles](#tool-111) | 动态 |
| 112 | [Windows.System.HostsFile](#tool-112) | 动态 |
| 113 | [Windows.System.LocalAdmins](#tool-113) | 动态 |
| 114 | [Windows.System.PowerShell](#tool-114) | 动态 |
| 115 | [Windows.System.Powershell.ModuleAnalysisCache](#tool-115) | 动态 |
| 116 | [Windows.System.Powershell.PSReadline](#tool-116) | 动态 |
| 117 | [Windows.System.Pslist](#tool-117) | 动态 |
| 118 | [Windows.System.RootCAStore](#tool-118) | 动态 |
| 119 | [Windows.System.SVCHost](#tool-119) | 动态 |
| 120 | [Windows.System.Services](#tool-120) | 动态 |
| 121 | [Windows.System.Shares](#tool-121) | 动态 |
| 122 | [Windows.System.Signers](#tool-122) | 动态 |
| 123 | [Windows.System.TaskScheduler](#tool-123) | 动态 |
| 124 | [Windows.System.Threads](#tool-124) | 动态 |
| 125 | [Windows.System.UntrustedBinaries](#tool-125) | 动态 |
| 126 | [Windows.System.VAD](#tool-126) | 动态 |
| 127 | [Windows.System.WMIQuery](#tool-127) | 动态 |
| 128 | [Windows.Timeline.MFT](#tool-128) | 动态 |
| 129 | [Windows.Timeline.Prefetch](#tool-129) | 动态 |
| 130 | [Windows.Timeline.Registry.RunMRU](#tool-130) | 动态 |

## 6. 十二个固定工具详细接口

<a id="tool-001"></a>

### 001. `run_vql`

功能描述（真实注册原文）：

Run a bounded VQL query in the root organization.

调用语义与边界：在root Org执行有界VQL。不是只读沙箱，查询可能产生副作用；仅执行已授权查询。最多250行且受245554字节响应上限约束，truncated=true表示不完整。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "run_vql",
  "arguments": {
    "query": "SELECT 1 AS example FROM scope()"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Run a bounded VQL query in the root organization.",
  "inputSchema": {
    "properties": {
      "query": {
        "title": "Query",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "query"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "run_vqlArguments"
  },
  "name": "run_vql",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "data": {
        "items": {
          "additionalProperties": true,
          "type": "object"
        },
        "title": "Data",
        "type": "array"
      },
      "truncated": {
        "title": "Truncated",
        "type": "boolean"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "data",
      "truncated"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "FixedUnpagedDataResult"
  }
}
```

<a id="tool-002"></a>

### 002. `start_hunt`

功能描述（真实注册原文）：

Create a paused hunt and attach one real flow for the unique Windows client.

调用语义与边界：仅接受本手册118项allowlist中的artifact；parameters遵循对应动态工具参数。建立暂停Hunt并为唯一Windows client关联真实Flow，不是全网广播。返回Hunt state与Flow flow_state，两者不能混用。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "start_hunt",
  "arguments": {
    "artifact": "Windows.System.Pslist"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Create a paused hunt and attach one real flow for the unique Windows client.",
  "inputSchema": {
    "properties": {
      "artifact": {
        "title": "Artifact",
        "type": "string",
        "minLength": 1
      },
      "parameters": {
        "anyOf": [
          {
            "additionalProperties": true,
            "type": "object"
          },
          {
            "type": "null"
          }
        ],
        "title": "Parameters"
      },
      "description": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "title": "Description"
      }
    },
    "required": [
      "artifact"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "start_huntArguments"
  },
  "name": "start_hunt",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "hunt_id": {
        "title": "Hunt Id",
        "type": "string"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "client_id": {
        "title": "Client Id",
        "type": "string"
      },
      "state": {
        "title": "State",
        "type": "string"
      },
      "flow_state": {
        "minLength": 1,
        "title": "Flow State",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "hunt_id",
      "flow_id",
      "client_id",
      "state",
      "flow_state"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "HuntStartedResult"
  }
}
```

<a id="tool-003"></a>

### 003. `get_hunt_status`

功能描述（真实注册原文）：

Read one hunt and its only associated flow.

调用语义与边界：读取Hunt及其唯一关联Flow，stats为后端开放对象。nullable字段必须按schema处理；无Flow时不得编造ID。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "get_hunt_status",
  "arguments": {
    "hunt_id": "<真实hunt_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Read one hunt and its only associated flow.",
  "inputSchema": {
    "properties": {
      "hunt_id": {
        "title": "Hunt Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "hunt_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "get_hunt_statusArguments"
  },
  "name": "get_hunt_status",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "hunt_id": {
        "title": "Hunt Id",
        "type": "string"
      },
      "state": {
        "title": "State",
        "type": "string"
      },
      "flow_id": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Flow Id"
      },
      "flow_state": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Flow State"
      },
      "client_id": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Client Id"
      },
      "stats": {
        "additionalProperties": true,
        "title": "Stats",
        "type": "object"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "hunt_id",
      "state",
      "stats"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "HuntStatusResult"
  }
}
```

<a id="tool-004"></a>

### 004. `stop_hunt`

功能描述（真实注册原文）：

Stop a hunt without cancelling its associated flow.

调用语义与边界：停止Hunt后续调度，不取消已运行Flow。如需取消，显式调用cancel_flow。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "stop_hunt",
  "arguments": {
    "hunt_id": "<真实hunt_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Stop a hunt without cancelling its associated flow.",
  "inputSchema": {
    "properties": {
      "hunt_id": {
        "title": "Hunt Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "hunt_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "stop_huntArguments"
  },
  "name": "stop_hunt",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "hunt_id": {
        "title": "Hunt Id",
        "type": "string"
      },
      "state": {
        "title": "State",
        "type": "string"
      },
      "flow_id": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Flow Id"
      },
      "flow_state_before": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Flow State Before"
      },
      "flow_state_after": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "default": null,
        "title": "Flow State After"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "hunt_id",
      "state"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "HuntStoppedResult"
  }
}
```

<a id="tool-005"></a>

### 005. `get_flow_status`

功能描述（真实注册原文）：

Read the backend state and counters for one flow.

调用语义与边界：读取真实状态、artifact/source、计数和后端时间字段。不要根据非空ID判断成功；时间值不在本手册擅自转换单位。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "get_flow_status",
  "arguments": {
    "flow_id": "<真实flow_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Read the backend state and counters for one flow.",
  "inputSchema": {
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "flow_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "get_flow_statusArguments"
  },
  "name": "get_flow_status",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "state": {
        "title": "State",
        "type": "string"
      },
      "status_message": {
        "title": "Status Message",
        "type": "string"
      },
      "artifacts": {
        "items": {
          "type": "string"
        },
        "title": "Artifacts",
        "type": "array"
      },
      "artifacts_with_results": {
        "items": {
          "type": "string"
        },
        "title": "Artifacts With Results",
        "type": "array"
      },
      "create_time": {
        "minimum": 0,
        "title": "Create Time",
        "type": "integer"
      },
      "start_time": {
        "minimum": 0,
        "title": "Start Time",
        "type": "integer"
      },
      "active_time": {
        "minimum": 0,
        "title": "Active Time",
        "type": "integer"
      },
      "total_collected_rows": {
        "minimum": 0,
        "title": "Total Collected Rows",
        "type": "integer"
      },
      "total_logs": {
        "minimum": 0,
        "title": "Total Logs",
        "type": "integer"
      },
      "total_uploaded_files": {
        "minimum": 0,
        "title": "Total Uploaded Files",
        "type": "integer"
      },
      "total_uploaded_bytes": {
        "minimum": 0,
        "title": "Total Uploaded Bytes",
        "type": "integer"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "state",
      "status_message",
      "artifacts",
      "artifacts_with_results",
      "create_time",
      "start_time",
      "active_time",
      "total_collected_rows",
      "total_logs",
      "total_uploaded_files",
      "total_uploaded_bytes"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "FlowStatusResult"
  }
}
```

<a id="tool-006"></a>

### 006. `get_flow_results`

功能描述（真实注册原文）：

Read one bounded cursor page from a flow result source.

调用语义与边界：source可省略；省略时按后端artifacts_with_results顺序拼接各source窗口。默认50行，最大250，仍受字节上限约束。保持同一flow_id/source分页，按next_cursor推进，null结束。无原子结果快照保证。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "get_flow_results",
  "arguments": {
    "flow_id": "<真实flow_id>",
    "page_size": 50
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Read one bounded cursor page from a flow result source.",
  "inputSchema": {
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string",
        "minLength": 1
      },
      "source": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "title": "Source"
      },
      "cursor": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "null"
          }
        ],
        "title": "Cursor"
      },
      "page_size": {
        "anyOf": [
          {
            "type": "integer",
            "minimum": 1,
            "maximum": 250
          },
          {
            "type": "null"
          }
        ],
        "title": "Page Size"
      }
    },
    "required": [
      "flow_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "get_flow_resultsArguments"
  },
  "name": "get_flow_results",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "data": {
        "items": {
          "additionalProperties": true,
          "type": "object"
        },
        "title": "Data",
        "type": "array"
      },
      "pagination": {
        "$ref": "#/$defs/Pagination"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "data",
      "pagination"
    ],
    "type": "object",
    "$defs": {
      "Pagination": {
        "additionalProperties": false,
        "properties": {
          "cursor": {
            "title": "Cursor",
            "type": "string"
          },
          "next_cursor": {
            "anyOf": [
              {
                "type": "string"
              },
              {
                "type": "null"
              }
            ],
            "title": "Next Cursor"
          },
          "page_size": {
            "maximum": 250,
            "minimum": 1,
            "title": "Page Size",
            "type": "integer"
          },
          "returned": {
            "minimum": 0,
            "title": "Returned",
            "type": "integer"
          },
          "truncated": {
            "title": "Truncated",
            "type": "boolean"
          }
        },
        "required": [
          "cursor",
          "next_cursor",
          "page_size",
          "returned",
          "truncated"
        ],
        "title": "Pagination",
        "type": "object"
      }
    },
    "additionalProperties": false,
    "title": "FixedDataResult"
  }
}
```

<a id="tool-007"></a>

### 007. `list_flow_files`

功能描述（真实注册原文）：

List stable file identifiers for uploads in one flow.

调用语义与边界：data包含逻辑原文件，不把Type=idx稀疏范围表当独立下载对象。file_size是逻辑大小，uploaded_size是上传大小，两者可能不同。配对数量通过sparse_indexes_internal:<数量>警告披露；truncated=true表示不完整。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "list_flow_files",
  "arguments": {
    "flow_id": "<真实flow_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "List stable file identifiers for uploads in one flow.",
  "inputSchema": {
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "flow_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "list_flow_filesArguments"
  },
  "name": "list_flow_files",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "data": {
        "items": {
          "$ref": "#/$defs/FlowFileEntry"
        },
        "title": "Data",
        "type": "array"
      },
      "truncated": {
        "title": "Truncated",
        "type": "boolean"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "data",
      "truncated"
    ],
    "type": "object",
    "$defs": {
      "FlowFileEntry": {
        "additionalProperties": false,
        "properties": {
          "file_id": {
            "title": "File Id",
            "type": "string"
          },
          "original_path": {
            "title": "Original Path",
            "type": "string"
          },
          "file_size": {
            "minimum": 0,
            "title": "File Size",
            "type": "integer"
          },
          "uploaded_size": {
            "minimum": 0,
            "title": "Uploaded Size",
            "type": "integer"
          },
          "accessor": {
            "title": "Accessor",
            "type": "string"
          }
        },
        "required": [
          "file_id",
          "original_path",
          "file_size",
          "uploaded_size",
          "accessor"
        ],
        "title": "FlowFileEntry",
        "type": "object"
      }
    },
    "additionalProperties": false,
    "title": "FlowFileListResult"
  }
}
```

<a id="tool-008"></a>

### 008. `download_flow_file`

功能描述（真实注册原文）：

Download one enumerated flow file without overwriting existing output.

调用语义与边界：先list_flow_files，再使用其file_id；不接收调用者目标路径。只下载一个文件到服务端可信下载根；返回local_path不是AI客户端路径，不在MCP响应内返回二进制。稀疏文件恢复逻辑零区，size和sha256对应完整逻辑字节。独占临时文件及原子不覆盖发布；已有完成文件报ALREADY_EXISTS。发布后失败可能残留完成文件，禁止自动重试覆盖或回滚删除。ERROR Flow中的完整单文件可独立下载，不代表整个Flow成功。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "download_flow_file",
  "arguments": {
    "flow_id": "<真实flow_id>",
    "file_id": "<列表返回的file_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Download one enumerated flow file without overwriting existing output.",
  "inputSchema": {
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string",
        "minLength": 1
      },
      "file_id": {
        "title": "File Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "flow_id",
      "file_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "download_flow_fileArguments"
  },
  "name": "download_flow_file",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "file_id": {
        "title": "File Id",
        "type": "string"
      },
      "local_path": {
        "title": "Local Path",
        "type": "string"
      },
      "size": {
        "minimum": 0,
        "title": "Size",
        "type": "integer"
      },
      "sha256": {
        "title": "Sha256",
        "type": "string"
      },
      "original_path": {
        "title": "Original Path",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "file_id",
      "local_path",
      "size",
      "sha256",
      "original_path"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "DownloadResult"
  }
}
```

<a id="tool-009"></a>

### 009. `cancel_flow`

功能描述（真实注册原文）：

Cancel one non-terminal flow and return its before/after state.

调用语义与边界：取消可取消的非终态Flow并返回前后真实状态；不可取消时报NOT_CANCELLABLE。收到取消响应不等同于回滚该Flow之前的副作用。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "cancel_flow",
  "arguments": {
    "flow_id": "<真实flow_id>"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Cancel one non-terminal flow and return its before/after state.",
  "inputSchema": {
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "flow_id"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "cancel_flowArguments"
  },
  "name": "cancel_flow",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "state_before": {
        "title": "State Before",
        "type": "string"
      },
      "state_after": {
        "title": "State After",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "state_before",
      "state_after"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "CancelFlowResult"
  }
}
```

<a id="tool-010"></a>

### 010. `collect_file`

功能描述（真实注册原文）：

Collect one absolute Windows path or glob without downloading it.

调用语义与边界：采集绝对Windows盘符路径或glob（如C:/Temp/example.txt），不直接下载；拒绝UNC、设备路径和相对路径。内部collection超时120秒，返回Flow后用状态/结果/文件工具继续。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "collect_file",
  "arguments": {
    "path": "C:/Temp/example.txt"
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Collect one absolute Windows path or glob without downloading it.",
  "inputSchema": {
    "properties": {
      "path": {
        "title": "Path",
        "type": "string",
        "minLength": 1
      }
    },
    "required": [
      "path"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "collect_fileArguments"
  },
  "name": "collect_file",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "state": {
        "minLength": 1,
        "title": "State",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "state"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "FixedFlowReferenceResult"
  }
}
```

<a id="tool-011"></a>

### 011. `collect_forensic_triage`

功能描述（真实注册原文）：

Start the locked basic Windows forensic triage collection.

调用语义与边界：无参数；调用已准备的Windows.Triage.Targets完整_BasicCollection，timeout=2400秒，仅此入口请求4294967296字节上传预算。预算不是磁盘上界；不自动提限、删减目标、安装依赖或重试。Targets数组在后端环境边界编码，调用者无需提供Targets。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "collect_forensic_triage",
  "arguments": {}
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Start the locked basic Windows forensic triage collection.",
  "inputSchema": {
    "properties": {},
    "type": "object",
    "additionalProperties": false,
    "title": "collect_forensic_triageArguments"
  },
  "name": "collect_forensic_triage",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "state": {
        "minLength": 1,
        "title": "State",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "state"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "FixedFlowReferenceResult"
  }
}
```

<a id="tool-012"></a>

### 012. `kill_process`

功能描述（真实注册原文）：

End one process through the locked Velociraptor process artifact.

调用语义与边界：结束已明确授权的目标PID（1至2147483647，整数且非bool），通过Generic.Utils.KillProcess启动Flow，timeout=120秒。破坏性操作：先确认目标归属；返回初始state不能证明进程已结束，须检查结果及实际效果。

tools/call参数示例（占位值须替换；有副作用工具不得直接试跑）：

```json
{
  "name": "kill_process",
  "arguments": {
    "pid": 1234
  }
}
```

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "End one process through the locked Velociraptor process artifact.",
  "inputSchema": {
    "properties": {
      "pid": {
        "title": "Pid",
        "type": "integer",
        "minimum": 1,
        "maximum": 2147483647
      }
    },
    "required": [
      "pid"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "kill_processArguments"
  },
  "name": "kill_process",
  "outputSchema": {
    "properties": {
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "const": "success",
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      },
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "state": {
        "minLength": 1,
        "title": "State",
        "type": "string"
      }
    },
    "required": [
      "operation",
      "status",
      "warnings",
      "flow_id",
      "state"
    ],
    "type": "object",
    "additionalProperties": false,
    "title": "FixedFlowReferenceResult"
  }
}
```

## 7. 一百一十八个动态工具详细接口

<a id="tool-013"></a>

### 013. `Windows.Analysis.EvidenceOfDownload`

功能描述（真实注册原文）：

Finds downloaded files by searching for `Zone.Identifier` alternate
data streams across user directories.

Use the artifact to find evidence of user download activity.

Based on the Zone.Identifier alternate data stream that is created
alongside with the file downloaded from the internet or intranet.
Zone.Identifier is generated by applications when user saves files
to the local file system from different security zone.

This artifact searches the directory provided for any file with
alternate data stream named Zone.Identifier and then lists all
files with zoneId = 3 or 4 and calculate the hash value of the file
and prints the content of Zone.Identifier alternate stream as it
could contain useful info in some cases.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Finds downloaded files by searching for `Zone.Identifier` alternate\ndata streams across user directories.\n\nUse the artifact to find evidence of user download activity.\n\nBased on the Zone.Identifier alternate data stream that is created\nalongside with the file downloaded from the internet or intranet.\nZone.Identifier is generated by applications when user saves files\nto the local file system from different security zone.\n\nThis artifact searches the directory provided for any file with\nalternate data stream named Zone.Identifier and then lists all\nfiles with zoneId = 3 or 4 and calculate the hash value of the file\nand prints the content of Zone.Identifier alternate stream as it\ncould contain useful info in some cases.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DirectoryPathGlob": {
        "description": "",
        "format": "text/csv",
        "title": "DirectoryPathGlob",
        "type": "string",
        "x-velociraptor-default": "Path\nC:/Users/*/Downloads/**/*\nC:/$Recycle.Bin/*/**/$R*\n",
        "x-velociraptor-type": "csv"
      },
      "ZoneIdRegex": {
        "description": "A Regular expression to match the required zone (default Internet and Restricted Zones).",
        "title": "ZoneIdRegex",
        "type": "string",
        "x-velociraptor-default": "ZoneId=[34]",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_000Arguments",
    "type": "object"
  },
  "name": "Windows.Analysis.EvidenceOfDownload",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-014"></a>

### 014. `Windows.Applications.Chrome.Cookies`

功能描述（真实注册原文）：

Enumerates Chrome browser cookies including host key, name,
timestamps, and encrypted values.

The cookies are typically encrypted by the DPAPI using the user's
credentials. Since Velociraptor is typically not running in the user
context we cannot decrypt these. It may be possible to decrypt the
cookies off line.

The pertinent information from a forensic point of view are the
user's Created and LastAccess timestamps, and the fact that the user
has actually visited the site and obtained a cookie.

**NOTES**

This artifact is deprecated in favor of
`Generic.Forensic.SQLiteHunter` and will be removed in future.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Chrome browser cookies including host key, name,\ntimestamps, and encrypted values.\n\nThe cookies are typically encrypted by the DPAPI using the user's\ncredentials. Since Velociraptor is typically not running in the user\ncontext we cannot decrypt these. It may be possible to decrypt the\ncookies off line.\n\nThe pertinent information from a forensic point of view are the\nuser's Created and LastAccess timestamps, and the fact that the user\nhas actually visited the site and obtained a cookie.\n\n**NOTES**\n\nThis artifact is deprecated in favor of\n`Generic.Forensic.SQLiteHunter` and will be removed in future.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "cookieGlobs": {
        "description": "",
        "title": "cookieGlobs",
        "type": "string",
        "x-velociraptor-default": "\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cookies",
        "x-velociraptor-type": ""
      },
      "cookieSQLQuery": {
        "description": "",
        "title": "cookieSQLQuery",
        "type": "string",
        "x-velociraptor-default": "SELECT creation_utc, host_key, name, value, path, expires_utc,\n       last_access_utc, encrypted_value\nFROM cookies\n",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_001Arguments",
    "type": "object"
  },
  "name": "Windows.Applications.Chrome.Cookies",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-015"></a>

### 015. `Windows.Applications.Chrome.Extensions`

功能描述（真实注册原文）：

Parses Chrome extension manifest files to identify installed
extensions and their permissions.

Chrome extensions are installed into the user's home directory. This
artifact searches for `manifest.json` files in a known path within
each user's home directory, and then parses the manifest file as
JSON.

Many extensions use locale packs to resolve strings like name and
description. In this case we detect the default locale and load
those locale files. We then resolve the extension's name and
description from there.

## NOTES:

This artifact is deprecated in favor of
Generic.Forensic.SQLiteHunter and will be removed in future

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Chrome extension manifest files to identify installed\nextensions and their permissions.\n\nChrome extensions are installed into the user's home directory. This\nartifact searches for `manifest.json` files in a known path within\neach user's home directory, and then parses the manifest file as\nJSON.\n\nMany extensions use locale packs to resolve strings like name and\ndescription. In this case we detect the default locale and load\nthose locale files. We then resolve the extension's name and\ndescription from there.\n\n## NOTES:\n\nThis artifact is deprecated in favor of\nGeneric.Forensic.SQLiteHunter and will be removed in future\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "extensionGlobs": {
        "description": "",
        "title": "extensionGlobs",
        "type": "string",
        "x-velociraptor-default": "\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*\\*\\manifest.json",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_002Arguments",
    "type": "object"
  },
  "name": "Windows.Applications.Chrome.Extensions",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-016"></a>

### 016. `Windows.Applications.Chrome.History`

功能描述（真实注册原文）：

Enumerates visited URLs, titles, and visit timestamps from
Chrome/Edge/Brave/Vivaldi/Opera history databases.

Based on Hindsight and code review of
https://source.chromium.org/chromium/chromium/src/+/master:components/history/core/browser/history_types.h.

**NOTES**

- Some research has shown that older browsers may not have this
  table. In that case you should treat it as you would in a traditional
  investigation. This artifact is aimed at taking advantage of the
  newer tables to reduce false positives.

- This artifact is deprecated in favor of `Generic.Forensic.SQLiteHunter` and
  will be removed in future

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates visited URLs, titles, and visit timestamps from\nChrome/Edge/Brave/Vivaldi/Opera history databases.\n\nBased on Hindsight and code review of\nhttps://source.chromium.org/chromium/chromium/src/+/master:components/history/core/browser/history_types.h.\n\n**NOTES**\n\n- Some research has shown that older browsers may not have this\n  table. In that case you should treat it as you would in a traditional\n  investigation. This artifact is aimed at taking advantage of the\n  newer tables to reduce false positives.\n\n- This artifact is deprecated in favor of `Generic.Forensic.SQLiteHunter` and\n  will be removed in future\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "URLRegex": {
        "description": "",
        "format": "regex",
        "title": "URLRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "historyGlobs": {
        "description": "",
        "title": "historyGlobs",
        "type": "string",
        "x-velociraptor-default": "\\AppData\\{Local,Roaming}\\{Google\\Chrome\\User Data,Microsoft\\Edge\\User Data,BraveSoftware\\Brave-Browser\\User Data,Vivaldi\\User Data,Opera Software\\Opera*Stable}\\*\\History",
        "x-velociraptor-type": ""
      },
      "urlSQLQuery": {
        "description": "",
        "title": "urlSQLQuery",
        "type": "string",
        "x-velociraptor-default": "SELECT U.id AS id,\n       U.url AS url,\n       V.visit_time as visit_time,\n       U.title AS title,\n       U.visit_count,\n       U.typed_count,\n       U.last_visit_time, U.hidden,\n       CASE VS.source\n          WHEN 0 THEN 'Synced'\n          WHEN 1 THEN 'Local'\n          WHEN 2 THEN 'Extension'\n          WHEN 3 THEN 'ImportFromFirefox'\n          WHEN 4 THEN 'ImportFromSafari'\n          WHEN 6 THEN 'ImportFromChrome/Edge'\n          WHEN 7 THEN 'ImportFromEdgeHTML'\n          ELSE 'Local'\n       END Source,\n       V.from_visit,\n       strftime('%H:%M:%f',V.visit_duration/1000000.0, 'unixepoch') as visit_duration,\n       V.transition\nFROM urls AS U\nJOIN visits AS V ON U.id = V.url\nLEFT JOIN visit_source AS VS on V.id = VS.id\n",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_003Arguments",
    "type": "object"
  },
  "name": "Windows.Applications.Chrome.History",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-017"></a>

### 017. `Windows.Applications.Edge.History`

功能描述（真实注册原文）：

Enumerates Edge browsing history (URLs, visit times, titles) from
user profiles.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Edge browsing history (URLs, visit times, titles) from\nuser profiles.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "historyGlobs": {
        "description": "",
        "title": "historyGlobs",
        "type": "string",
        "x-velociraptor-default": "\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History",
        "x-velociraptor-type": ""
      },
      "urlSQLQuery": {
        "description": "",
        "title": "urlSQLQuery",
        "type": "string",
        "x-velociraptor-default": "SELECT U.id AS id, U.url AS url, V.visit_time as visit_time,\nU.title AS title, U.visit_count, U.typed_count,\nU.last_visit_time, U.hidden, V.from_visit, strftime('%H:%M:%f',\nV.visit_duration/1000000.0, 'unixepoch') as visit_duration,\nV.transition FROM urls AS U JOIN visits AS V ON U.id = V.url\n",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_004Arguments",
    "type": "object"
  },
  "name": "Windows.Applications.Edge.History",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-018"></a>

### 018. `Windows.Applications.OfficeMacros`

功能描述（真实注册原文）：

Scans directories for Office documents (xls, xlsm, doc, docx, ppt,
pptm) and extracts embedded VBA macros via OLE parsing.

Office macros are a prominent initial infection vector. Many users
click through the warning dialogs, thus leading to infection.

If you find that any macro calls an external program (e.g.
PowerShell) that is very suspicious!

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans directories for Office documents (xls, xlsm, doc, docx, ppt,\npptm) and extracts embedded VBA macros via OLE parsing.\n\nOffice macros are a prominent initial infection vector. Many users\nclick through the warning dialogs, thus leading to infection.\n\nIf you find that any macro calls an external program (e.g.\nPowerShell) that is very suspicious!\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "officeExtensions": {
        "description": "",
        "title": "officeExtensions",
        "type": "string",
        "x-velociraptor-default": "*.{xls,xlsm,doc,docx,ppt,pptm}",
        "x-velociraptor-type": ""
      },
      "officeFileSearchGlob": {
        "description": "The directory to search for office documents.",
        "title": "officeFileSearchGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\**\\",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_005Arguments",
    "type": "object"
  },
  "name": "Windows.Applications.OfficeMacros",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-019"></a>

### 019. `Windows.Attack.Prefetch`

功能描述（真实注册原文）：

Enumerates Windows Prefetch directory entries and correlates them
with known ATT&CK techniques.

This pack was generated from
https://github.com/teoseller/osquery-attck

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows Prefetch directory entries and correlates them\nwith known ATT&CK techniques.\n\nThis pack was generated from\nhttps://github.com/teoseller/osquery-attck\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_006Arguments",
    "type": "object"
  },
  "name": "Windows.Attack.Prefetch",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-020"></a>

### 020. `Windows.Attack.UnexpectedImagePath`

功能描述（真实注册原文）：

Detects well-known system processes running from unexpected file
paths.

Some malware hides in plain sight by masquerading a legitimate
executable name.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects well-known system processes running from unexpected file\npaths.\n\nSome malware hides in plain sight by masquerading a legitimate\nexecutable name.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "expected_paths": {
        "description": "",
        "format": "text/csv",
        "title": "expected_paths",
        "type": "string",
        "x-velociraptor-default": "ProcName,ExpectedPath\ncsrss.exe,c:\\windows\\system32\\csrss.exe\nsmss.exe,c:\\windows\\system32\\smss.exe\nservices.exe,c:\\windows\\system32\\services.exe\nwininit.exe,c:\\windows\\system32\\wininit.exe\nsvchost.exe,c:\\windows\\system32\\svchost.exe\nsvchost.exe,c:\\windows\\syswow64\\svchost.exe\nruntimebroker.exe,c:\\windows\\system32\\runtimebroker.exe\nlsaiso.exe,c:\\windows\\system32\\lsaiso.exe\ntaskhostw.exe,c:\\windows\\system32\\taskhostw.exe\nlsass.exe,c:\\windows\\system32\\lsass.exe\nwinlogon.exe,c:\\windows\\system32\\winlogon.exe\nexplorer.exe,c:\\windows\\explorer.exe\nexplorer.exe,c:\\windows\\syswow64\\explorer.exe\nconhost.exe,c:\\windows\\system32\\conhost.exe\ndllhost.exe,c:\\windows\\system32\\dllhost.exe\ndllhost.exe,c:\\windows\\syswow64\\dllhost.exe\nwmiprvse.exe,c:\\windows\\system32\\wbem\\wmiprvse.exe\nwmiprvse.exe,c:\\windows\\syswow64\\wbem\\wmiprvse.exe\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_007Arguments",
    "type": "object"
  },
  "name": "Windows.Attack.UnexpectedImagePath",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-021"></a>

### 021. `Windows.Carving.CobaltStrike`

功能描述（真实注册原文）：

Extracts Cobalt Strike beacon configuration from byte streams,
process memory, or files on disk such as a process dump.

Best used as a triage step against a detection of a Cobalt Strike
beacon via a YARA process scan.

The User can define bytes, file glob, process name or pid regex as a
target. The content will search for a configuration pattern, extract
a defined byte size, xor with discovered key, then attempt
configuration extraction.

- Cobalt Strike beacon configuration is typically XORed with 0x69 or
  0x2e (depending on version) but trivial to change.
- Configuration is built in a typical index / type / length / value
  structure with either big endian values or zero terminated strings.
- If no beacon is found, parser will fallback to Cobalt Strike
  Shellcode analysis.

This simply carves the configuration and does not unpack files on
disk. That means pointing this artifact at a packed or obfuscated
file may not return the expected results.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts Cobalt Strike beacon configuration from byte streams,\nprocess memory, or files on disk such as a process dump.\n\nBest used as a triage step against a detection of a Cobalt Strike\nbeacon via a YARA process scan.\n\nThe User can define bytes, file glob, process name or pid regex as a\ntarget. The content will search for a configuration pattern, extract\na defined byte size, xor with discovered key, then attempt\nconfiguration extraction.\n\n- Cobalt Strike beacon configuration is typically XORed with 0x69 or\n  0x2e (depending on version) but trivial to change.\n- Configuration is built in a typical index / type / length / value\n  structure with either big endian values or zero terminated strings.\n- If no beacon is found, parser will fallback to Cobalt Strike\n  Shellcode analysis.\n\nThis simply carves the configuration and does not unpack files on\ndisk. That means pointing this artifact at a packed or obfuscated\nfile may not return the expected results.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "BruteXor": {
        "description": "Select to attempt brute forcing Xor byte in config. Default is 0x2e or 0x69.",
        "title": "BruteXor",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "ExtractBytes": {
        "description": "",
        "title": "ExtractBytes",
        "type": "integer",
        "x-velociraptor-default": "10000",
        "x-velociraptor-type": "int"
      },
      "IncludeDecodedData": {
        "description": "Select to include decoded data in output.",
        "title": "IncludeDecodedData",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "TargetBytes": {
        "description": "",
        "title": "TargetBytes",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "TargetFileGlob": {
        "description": "",
        "title": "TargetFileGlob",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_008Arguments",
    "type": "object"
  },
  "name": "Windows.Carving.CobaltStrike",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-022"></a>

### 022. `Windows.Detection.Amcache`

功能描述（真实注册原文）：

Collects AMCache entries with a SHA1 hash to enable threat
detection.

AmCache is an artifact which stores metadata related to PE execution
and program installation on Windows 7 and Server 2008 R2 and above.
This artifact includes EntryName, EntryPath and SHA1 as great data
points for IOC collection. Secondary datapoints include
publisher/company, BinaryType and OriginalFileName.

Available filters include:

  - SHA1regex - regex entries to filter by SHA1.
  - PathRegex - filter on path if available.
  - NameRegex - filter on EntryName OR OriginalFileName.
  - VersionRegex - filter on Version

NOTE:

  - Secondary fields are not consistent across AMCache types and
    some legacy versions do not return these fields.
  - Some enrichment has occurred but any secondary fields should
    be treated as guidance only.
  - This artifact collects only entries with a SHA1, for complete
    AMCache analysis please download raw artifact sets.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Collects AMCache entries with a SHA1 hash to enable threat\ndetection.\n\nAmCache is an artifact which stores metadata related to PE execution\nand program installation on Windows 7 and Server 2008 R2 and above.\nThis artifact includes EntryName, EntryPath and SHA1 as great data\npoints for IOC collection. Secondary datapoints include\npublisher/company, BinaryType and OriginalFileName.\n\nAvailable filters include:\n\n  - SHA1regex - regex entries to filter by SHA1.\n  - PathRegex - filter on path if available.\n  - NameRegex - filter on EntryName OR OriginalFileName.\n  - VersionRegex - filter on Version\n\nNOTE:\n\n  - Secondary fields are not consistent across AMCache types and\n    some legacy versions do not return these fields.\n  - Some enrichment has occurred but any secondary fields should\n    be treated as guidance only.\n  - This artifact collects only entries with a SHA1, for complete\n    AMCache analysis please download raw artifact sets.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AMCacheGlob": {
        "description": "AMCache hive path",
        "title": "AMCacheGlob",
        "type": "string",
        "x-velociraptor-default": "%SYSTEMROOT%/appcompat/Programs/Amcache.hve",
        "x-velociraptor-type": ""
      },
      "NameRegex": {
        "description": "Regex of entry / binary name",
        "format": "regex",
        "title": "NameRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "Regex of recorded path.",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "SHA1Regex": {
        "description": "Regex of SHA1s to filter",
        "format": "regex",
        "title": "SHA1Regex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "VersionRegex": {
        "description": "Regex of version",
        "format": "regex",
        "title": "VersionRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_009Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Amcache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-023"></a>

### 023. `Windows.Detection.BinaryHunter`

功能描述（真实注册原文）：

This artifact enables hunting for binary attributes.

The artifact takes a glob targeting input, then checks each file in
scope for an MZ header. The artifact also queries Authenticode
details and parses out PE attributes.

Both PE and Authenticode output can be queried for relevant strings
by using a regex filter and whitelist to hunt with. This enables
unique capability to hunt for specific things such as PE imports,
exports or other attributes.

Note:

This artifacts filters are cumulative so a hash based hit will
return no results if the file is filtered out by other filters. For
most performant searches use path, size and date filters. By default
the artifact uses the 'auto' data accessor but can also be changed
as desired.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "This artifact enables hunting for binary attributes.\n\nThe artifact takes a glob targeting input, then checks each file in\nscope for an MZ header. The artifact also queries Authenticode\ndetails and parses out PE attributes.\n\nBoth PE and Authenticode output can be queried for relevant strings\nby using a regex filter and whitelist to hunt with. This enables\nunique capability to hunt for specific things such as PE imports,\nexports or other attributes.\n\nNote:\n\nThis artifacts filters are cumulative so a hash based hit will\nreturn no results if the file is filtered out by other filters. For\nmost performant searches use path, size and date filters. By default\nthe artifact uses the 'auto' data accessor but can also be changed\nas desired.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Accessor": {
        "description": "Velociraptor accessor to use. Changing to ntfs will increase scan time.",
        "title": "Accessor",
        "type": "string",
        "x-velociraptor-default": "auto",
        "x-velociraptor-type": ""
      },
      "AuthenticodeRegex": {
        "description": "Regex to search through all authenticode data.",
        "format": "regex",
        "title": "AuthenticodeRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "AuthenticodeWhitelistRegex": {
        "description": "Regex to whitelist in all Authenticode data.",
        "format": "regex",
        "title": "AuthenticodeWhitelistRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DateAfter": {
        "description": "Search for binaries with timestamps after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "Search for binaries with timestamps before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "ExcludeTrusted": {
        "description": "Exclude binaries with Trusted Authenticode certificates.",
        "title": "ExcludeTrusted",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "MD5List": {
        "description": "MD5 hash list to hunt for. New MD5 hash on each line",
        "title": "MD5List",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "PEInformationRegex": {
        "description": "Regex to filter for PE information. e.g VersionInformation, exports etc",
        "format": "regex",
        "title": "PEInformationRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PEInformationWhitelistRegex": {
        "description": "Regex to whitelist for PE information. e.g VersionInformation, exports etc",
        "format": "regex",
        "title": "PEInformationWhitelistRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "SHA1List": {
        "description": "SHA1 hash list to hunt for. New SHA1 hash on each line",
        "title": "SHA1List",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "SHA256List": {
        "description": "SHA256 hash list to hunt for. New SHA256 hash on each line",
        "title": "SHA256List",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "SizeMax": {
        "description": "Return binaries only under this size in bytes.",
        "title": "SizeMax",
        "type": "integer",
        "x-velociraptor-default": "4294967296",
        "x-velociraptor-type": "int64"
      },
      "SizeMin": {
        "description": "Return binaries only over this size in bytes.",
        "title": "SizeMin",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int64"
      },
      "TargetGlob": {
        "description": "Glob to target.",
        "title": "TargetGlob",
        "type": "string",
        "x-velociraptor-default": "C:/Users/**/*",
        "x-velociraptor-type": ""
      },
      "UnexpectedExtension": {
        "description": "Exclude binaries with expected extension: com|cpl|dll|drv|exe|mui|scr|sfx|sys|winmd",
        "title": "UnexpectedExtension",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UploadFiles": {
        "description": "Select to upload files.\n",
        "title": "UploadFiles",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_010Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.BinaryHunter",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-024"></a>

### 024. `Windows.Detection.BinaryRename`

功能描述（真实注册原文）：

Detects renamed binaries commonly abused by adversaries.

Binary renaming is a defense evasion technique used to bypass
brittle process name and path based detections. Observed in use
across all stages of the attack lifecycle, it is a technique used by
a large selection of actors from commodity malware crews through to
Nation States.

Add additional entries to the VersionInfoTable parameter. For
straight detection on an Internal or Original name, the Filename
entry can be set to an unlikely value - e.g ANY or left blank.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects renamed binaries commonly abused by adversaries.\n\nBinary renaming is a defense evasion technique used to bypass\nbrittle process name and path based detections. Observed in use\nacross all stages of the attack lifecycle, it is a technique used by\na large selection of actors from commodity malware crews through to\nNation States.\n\nAdd additional entries to the VersionInfoTable parameter. For\nstraight detection on an Internal or Original name, the Filename\nentry can be set to an unlikely value - e.g ANY or left blank.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "TargetGlob": {
        "description": "",
        "title": "TargetGlob",
        "type": "string",
        "x-velociraptor-default": "/**/*.exe",
        "x-velociraptor-type": ""
      },
      "VersionInfoTable": {
        "description": "",
        "format": "text/csv",
        "title": "VersionInfoTable",
        "type": "string",
        "x-velociraptor-default": "Filename,Internal,Original,Description,Note\ncmd.exe,cmd,Cmd.Exe,Windows Command Processor,cmd.exe\n7z.exe,7z,7z.exe,7-Zip Console,7z.exe\ncertutil.exe,CertUtil.exe,CertUtil.exe,CertUtil,certutil.exe\ncmstp.exe,CMSTP,CMSTP.EXE,Microsoft Connection Manager Profile Installer,cmstp.exe\ncscript.exe,cscript.exe,cscript.exe,Microsoft ® Console Based Script Host,cscript.exe\nmshta.exe,MSHTA.EXE,MSHTA.EXE,Microsoft ® HTML Application host,mshta.exe\nmsiexec.exe,msiexec,msiexec.exe,Windows® installer,msiexec.exe\npowershell.exe,POWERSHELL,PowerShell.EXE,Windows PowerShell,powershell.exe\npsexec.exe,PsExec,psexec.c,Sysinternals PSExec,psexec.exe\npsexec64.exe,PsExec,psexec.exe,Sysinternals PSExec,psexec64.exe\nregsvr32.exe,REGSVR32,REGSVR32.EXE,Microsoft© Register Server,regsvr32.exe\nrundll32.exe,rundll,RUNDLL32.EXE,Windows host process (Rundll32),rundll32.exe\nwinrar.exe,WinRAR,WinRAR.exe,WinRAR archiver,winrar.exe\nwmic.exe,wmic.exe,wmic.exe,WMI Commandline Utility,wmic.exe\nwscript.exe,wscript.exe,wscript.exe,Microsoft ® Windows Based Script Host,wscript.exe\nwevtutil.exe,wevtutil.exe,wevtutil.exe,,wevtutil.exe\nnet.exe,net.exe,net.exe,,net.exe\nnet1.exe,net1.exe,net1.exe,,net1.exe\nnetsh.exe,netsh.exe,netsh.exe,,netsh.exe\npowershell_ise.exe,powershell_ise.exe,powershell_ise.exe,,powershell_ise.exe\ndsquery.exe,dsquery.exe,dsquery.exe,Microsoft AD DS/LDS query command line utility,dsquery.exe\nnbtstat.exe,nbtinfo.exe,nbtinfo.exe,Microsoft TCP/IP NetBios Information,nbtstat.exe\nnltest.exe,nltestrk.exe,nltestrk.exe,Microsoft® Logon Server Test Utility,nltest.exe\nqprocess.exe,qprocess,qprocess.exe,Query Process Utility,qprocess.exe\nqwinsta.exe,qwinsta,qwinsta.exe,Query Session Utility,qwinsta.exe\nANY,nc,nc.exe,NetCat for Windows - https://github.com/diegocr/netcat,nc.exe\nANY,AdFind.exe,AdFind.exe,Joeware ADFind,AdFind.exe\nANY,rclone,rclone.exe,Rsync for cloud storage,rclone.exe\nANY,MEGAsync.exe,MEGAsync.exe,MEGAsync,MEGAsync.exe\nANY,MEGAcmdShell.exe,MEGAcmdShell,MEGAcmdShell,MEGAcmdShell\nANY,pCloud.exe,pCloud.exe,pCloud cloud storage,pCloud.exe\nANY,,pCloud Drive.exe,pCloud setup,pCloud Drive.exe\nANY,mimikatz,mimikatz.exe,mimikatz for Windows,mimikatz.exe\nANY,ProcDump,procdump,Sysinternals process dump utility,procdump.exe\nANY,ProcDump,procdump,Sysinternals process dump utility,procdump64.exe\nANY,Ammyy Admin,,Ammyy Admin,AA_v3.exe\nANY,,,AnyDesk,AnyDesk.exe\nANY,PDQDeploySetup.exe,PDQDeploySetup.exe,PDQ Deploy Install,Deploy_19.3.298.0.exe\nANY,PDQInventory.exe,PDQInventory.exe,PDQ Inventory Installer,Inventory_19.3.298.0.exe\nANY,,,UltraVNC Setup,UltraVNC_1_3_81_X64_Setup.exe\nANY,,,File Shredder by PowTools,file_shredder_setup.exe\nANY,,pCloud Drive.exe,pCloud Drive,pCloud_Windows_3.11.12_x64.exe\nplink.exe,Plink,Plink,\"Command-line SSH, Telnet, and Rlogin client\",plink.exe\npscp.exe,PSCP,PSCP,Command-line SCP/SFTP client,pscp.exe\npsftp.exe,PSFTP,PSFTP,Command-line interactive SFTP client,psftp.exe\nANY,,,Total Commander Installer,tcmd1000x32.exe\nANY,BulletsPassView,BulletsPassView.exe,BulletsPassView,BulletsPassView.exe\nANY,WinLister,WinLister.exe,WinLister,winlister.exe\nANY,HRSword,HRSword.exe,Huorong Sword GUI Frontend,HRSword v5.0.47.bin\nANY,,,Email Password-Recovery,mailpv.exe\nANY,Process Hacker,ProcessHacker.exe,Process Hacker,ProcessHacker.exe\nANY,peview,peview.exe,PE Viewer,peview.exe\nANY,ChromePass,ChromePass,Chrome Password Recovery,ChromePass.exe\nANY,,,Application for scanning networks,netscan.exe\nANY,WKV,,Extracts wireless keys stored by Windows,WirelessKeyView.exe\nANY,Remote Desktop PassView,rdpv.exe,Password Recovery for Remote Desktop,rdpv.exe\nANY,RouterPassView,RouterPassView.exe,Decrypts Router files.,RouterPassView.exe\nANY,RemCom,RemCom.exe,Remote Command Executor,RemCom.exe\nANY,,,Remote Utilities,host7.1.2.0.exe\nANY,,viewer.7.1.2.0.exe,Remote Utilities - Viewer,viewer7.1.2.0.exe\nANY,Web Browser Pass View,,Web Browser Password Viewer,WebBrowserPassView.exe\nANY,PowerTool.exe,PowerTool.exe,Anti-virus/rootkit/bootkit Tool,PowerTool64.exe\nANY,,winscp.com,Console interface for WinSCP,WinSCP.com\nANY,winscp,winscp.exe,\"WinSCP: SFTP, FTP, WebDAV, S3 and SCP client\",WinSCP.exe\nANY,iepv,iepv.exe,IE Passwords Viewer,iepv.exe\nANY,VNCPassView,VNCPassView.exe,VNCPassView,VNCPassView.exe\nANY,PCHunter,PCHunter.exe,Epoolsoft Windows Information View Tools,PCHunter32.exe\nANY,Massscan_GUI.exe,Massscan_GUI.exe,Masscan_GUI,Massscan_GUI.exe\nANY,ProxyLite.Windows.Console.exe,ProxyLite.Windows.Console.exe,ProxyLite Console Client,ProxyLite\nANY,action1_agent.exe,action1_agent.exe,Endpoint Agent,Action1 agent\nANY,action1_remote.exe,action1_remote.exe,Endpoint Agent,Action1 agent\nANY,Defender Control,Defender Control,Windows Defender Control,Windows Defender Control\nANY,NirCmd,NirCmd.exe,Nir Sofer,nircmd.exe\nANY,NSudo,NSudo.exe,NSudo for Windows,Nsudo\nANY,Python Application,pythonw.exe,Python,Python 3.10.0 packaged with DWAgent - possibly noisy.\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_011Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.BinaryRename",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-025"></a>

### 025. `Windows.Detection.EnvironmentVariables`

功能描述（真实注册原文）：

Find processes which have the specified environment variables.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Find processes which have the specified environment variables.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "EnvironmentVariableRegex": {
        "description": "",
        "format": "regex",
        "title": "EnvironmentVariableRegex",
        "type": "string",
        "x-velociraptor-default": "COMSPEC|COR_PROFILER",
        "x-velociraptor-type": "regex"
      },
      "FilterValueRegex": {
        "description": "",
        "format": "regex",
        "title": "FilterValueRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessNameRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "WhitelistValueRegex": {
        "description": "Ignore these values",
        "format": "regex",
        "title": "WhitelistValueRegex",
        "type": "string",
        "x-velociraptor-default": "^C:\\\\Windows\\\\.+cmd.exe$",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_012Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.EnvironmentVariables",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-026"></a>

### 026. `Windows.Detection.ForwardedImports`

功能描述（真实注册原文）：

Scans DLLs for self-referencing forwarded imports that could
indicate DLL hijacking.

In Windows a common DLL hooking technique is to replace a dll with a
forwarder dll - i.e. one that forwards all imports to the real
dll. If the forwarder DLL is placed earlier in the import order, the
malicious DLL will be seamlessly loaded and injected into another
process.

This artifact searches for DLLs which are named the same as the DLL
they are forwarding to.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans DLLs for self-referencing forwarded imports that could\nindicate DLL hijacking.\n\nIn Windows a common DLL hooking technique is to replace a dll with a\nforwarder dll - i.e. one that forwards all imports to the real\ndll. If the forwarder DLL is placed earlier in the import order, the\nmalicious DLL will be seamlessly loaded and injected into another\nprocess.\n\nThis artifact searches for DLLs which are named the same as the DLL\nthey are forwarding to.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DLLGlob": {
        "description": "",
        "title": "DLLGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\windows\\**\\*.dll",
        "x-velociraptor-type": ""
      },
      "ExcludeRegex": {
        "description": "",
        "format": "regex",
        "title": "ExcludeRegex",
        "type": "string",
        "x-velociraptor-default": "WinSXS|Servicing",
        "x-velociraptor-type": "regex"
      },
      "LogPeriod": {
        "description": "How often to log progress in seconds (Default every 1 sec)",
        "title": "LogPeriod",
        "type": "integer",
        "x-velociraptor-default": "1",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_013Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.ForwardedImports",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-027"></a>

### 027. `Windows.Detection.Impersonation`

功能描述（真实注册原文）：

Enumerates threads with impersonation tokens that differ from their
parent process.

An access token is an object that describes the security context of
a process or thread. The information in a token includes the
identity and privileges of the user account associated with the
process or thread. When a user logs on, the system verifies the
user's password by comparing it with information stored in a
security database.

Every process has a primary token that describes the security
context of the user account associated with the process. By default,
the system uses the primary token when a thread of the process
interacts with a securable object. Moreover, a thread can
impersonate a client account. Impersonation allows the thread to
interact with securable objects using the client's security context.
A thread that is impersonating a client has both a primary token and
an impersonation token.

This artifact enumerates all threads on the system which have an
impersonation token. That is, they are operating with a different
token then the token the entire process has. For example Mimikatz
has a command called `token::elevate` to do just such a thing:

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

688     {0;000003e7} 1 D 42171          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
-> Impersonated !
* Process Token : {0;000195ad} 1 F 757658339   DESKTOP-NHNHT65\mic     S-1-5-21-2310288903-2791442386-3035081252-1001  (15g,24p)       Primary
* Thread Token  : {0;000003e7} 1 D 759094260   NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates threads with impersonation tokens that differ from their\nparent process.\n\nAn access token is an object that describes the security context of\na process or thread. The information in a token includes the\nidentity and privileges of the user account associated with the\nprocess or thread. When a user logs on, the system verifies the\nuser's password by comparing it with information stored in a\nsecurity database.\n\nEvery process has a primary token that describes the security\ncontext of the user account associated with the process. By default,\nthe system uses the primary token when a thread of the process\ninteracts with a securable object. Moreover, a thread can\nimpersonate a client account. Impersonation allows the thread to\ninteract with securable objects using the client's security context.\nA thread that is impersonating a client has both a primary token and\nan impersonation token.\n\nThis artifact enumerates all threads on the system which have an\nimpersonation token. That is, they are operating with a different\ntoken then the token the entire process has. For example Mimikatz\nhas a command called `token::elevate` to do just such a thing:\n\n```\nmimikatz # privilege::debug\nPrivilege '20' OK\n\nmimikatz # token::elevate\nToken Id  : 0\nUser name :\nSID name  : NT AUTHORITY\\SYSTEM\n\n688     {0;000003e7} 1 D 42171          NT AUTHORITY\\SYSTEM     S-1-5-18        (04g,21p)       Primary\n-> Impersonated !\n* Process Token : {0;000195ad} 1 F 757658339   DESKTOP-NHNHT65\\mic     S-1-5-21-2310288903-2791442386-3035081252-1001  (15g,24p)       Primary\n* Thread Token  : {0;000003e7} 1 D 759094260   NT AUTHORITY\\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)\n```\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_014Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Impersonation",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-028"></a>

### 028. `Windows.Detection.Mutants`

功能描述（真实注册原文）：

Searches for named Mutant objects used by selected processes for
malware persistence detection.

Mutants are often used by malware to prevent re-infection.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches for named Mutant objects used by selected processes for\nmalware persistence detection.\n\nMutants are often used by malware to prevent re-infection.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "MutantNameRegex": {
        "description": "",
        "format": "regex",
        "title": "MutantNameRegex",
        "type": "string",
        "x-velociraptor-default": ".+",
        "x-velociraptor-type": "regex"
      },
      "MutantWhitelistRegex": {
        "description": "",
        "format": "regex",
        "title": "MutantWhitelistRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "processRegex": {
        "description": "A regex applied to process names.",
        "format": "regex",
        "title": "processRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_015Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Mutants",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-029"></a>

### 029. `Windows.Detection.TemplateInjection`

功能描述（真实注册原文）：

Detects injected templates in Office and RTF documents.

Template injection is a form of defense evasion. For office
documents a malicious macro is loaded into an OOXML document via a
resource file masquerading as an office template. The OOXML artifact
structure will also detect MSHTML RCE Vulnerability
#CVE-2021-40444 which has a similar payload technique. For RTF
documents, a malicious payload can be delivered by modifying
document formatting control via the `\\\*\template` structure.

This artifact can be customized to search for other suspicious
`rels` files:

- document.xml.rels = macros, ole objects, images.
- settings.xml.rels = templates.
- websettings.xml.rels = frames.
- header#.xml.rels and footer#.xml.rels and others has also been
  observed hosting image files for canary files or abused for
  NetNTLM hash collection.

Change TemplateFileRegex to `\\.xml\\.rels$` for looser file
selection. Change TemplateTargetRegex to
`^(https?|smb|\\\\|//|mhtml|file)` for looser Target selection.

This artifact can also be modified to quickly deploy YARA based
detections on other documents. Simply replace RtfYara with YARA
rules of interest and modify the glob for targeting.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects injected templates in Office and RTF documents.\n\nTemplate injection is a form of defense evasion. For office\ndocuments a malicious macro is loaded into an OOXML document via a\nresource file masquerading as an office template. The OOXML artifact\nstructure will also detect MSHTML RCE Vulnerability\n#CVE-2021-40444 which has a similar payload technique. For RTF\ndocuments, a malicious payload can be delivered by modifying\ndocument formatting control via the `\\\\\\*\\template` structure.\n\nThis artifact can be customized to search for other suspicious\n`rels` files:\n\n- document.xml.rels = macros, ole objects, images.\n- settings.xml.rels = templates.\n- websettings.xml.rels = frames.\n- header#.xml.rels and footer#.xml.rels and others has also been\n  observed hosting image files for canary files or abused for\n  NetNTLM hash collection.\n\nChange TemplateFileRegex to `\\\\.xml\\\\.rels$` for looser file\nselection. Change TemplateTargetRegex to\n`^(https?|smb|\\\\\\\\|//|mhtml|file)` for looser Target selection.\n\nThis artifact can also be modified to quickly deploy YARA based\ndetections on other documents. Simply replace RtfYara with YARA\nrules of interest and modify the glob for targeting.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "RtfYara": {
        "description": "",
        "format": "yara",
        "title": "RtfYara",
        "type": "string",
        "x-velociraptor-default": "rule RTF_TemplateInjection {\n    meta:\n        author = \"Matt Green - @mgreen27\"\n        description = \"Yara for RTF template injection. Using regex match to extract template information\"\n\n    strings:\n        $regex1 = /\\{\\\\\\*\\\\template\\s+http[^\\}]+\\}/ nocase\n        $regex2 = /\\{\\\\\\*\\\\templates\\s+\\\\u-[^\\}]+\\}/ nocase\n        $regex3 = /\\{\\\\\\*\\\\template\\s+file[^\\}]+\\}/ nocase\n\n    condition:\n      // header is {\\rt only to also flag on malformed rtf heders\n      uint32be(0) == 0x7B5C7274 and 1 of them\n}\n",
        "x-velociraptor-type": "yara"
      },
      "SearchGlob": {
        "description": "Glob to search",
        "title": "SearchGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\**\\*.{rtf,doc,dot,docx,docm,dotx,dotm,docb,xls,xlt,xlm,xlsx,xlsm,xltx,xltm,xlsb,ppt,pptx,pptm,potx,potm,ppsx}",
        "x-velociraptor-type": ""
      },
      "TemplateFileRegex": {
        "description": "Regex to search inside resource section.",
        "format": "regex",
        "title": "TemplateFileRegex",
        "type": "string",
        "x-velociraptor-default": "\\.xml\\.rels$",
        "x-velociraptor-type": "regex"
      },
      "TemplateTargetRegex": {
        "description": "Regex to search inside resource section.",
        "format": "regex",
        "title": "TemplateTargetRegex",
        "type": "string",
        "x-velociraptor-default": "^(https?|smb|\\\\\\\\|//|mhtml|script)",
        "x-velociraptor-type": "regex"
      },
      "UploadDocument": {
        "description": "Select to upload document on detection.",
        "title": "UploadDocument",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_016Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.TemplateInjection",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-030"></a>

### 030. `Windows.Detection.Yara.NTFS`

功能描述（真实注册原文）：

Searches the MFT, returns a list of target files, and then runs YARA
over the target list.

There are 3 kinds of YARA rules that can be deployed:

1. URL link to a YARA rule.
2. Shorthand YARA in the format `wide nocase ascii:string1,string2,string3`.
3. or a Standard YARA rule attached as a parameter.

Only one method of YARA will be applied and search order is as
above.

The artifact uses Windows.NTFS.MFT so similar regex filters can be
applied including Path, Size and date. The artifact also has an
option to search across all attached drives and upload any files
with YARA hits.

Some examples of path regex may include:

* Extension at a path: `C:\\Windows\\System32\\.+\.dll$`
* More wildcards: `Windows\\.+\\.+\.dll$`
* Specific file: `Windows\\System32\\kernel32\.dll$`
* Multiple extensions: `\.(php|aspx|resx|asmx)$`

Note: no drive and forward slashes - these expressions are for paths
relative to the root of the filesystem. If upload is selected
NumberOfHits is redundant and not advised as hits are grouped by
path to ensure files only downloaded once.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches the MFT, returns a list of target files, and then runs YARA\nover the target list.\n\nThere are 3 kinds of YARA rules that can be deployed:\n\n1. URL link to a YARA rule.\n2. Shorthand YARA in the format `wide nocase ascii:string1,string2,string3`.\n3. or a Standard YARA rule attached as a parameter.\n\nOnly one method of YARA will be applied and search order is as\nabove.\n\nThe artifact uses Windows.NTFS.MFT so similar regex filters can be\napplied including Path, Size and date. The artifact also has an\noption to search across all attached drives and upload any files\nwith YARA hits.\n\nSome examples of path regex may include:\n\n* Extension at a path: `C:\\\\Windows\\\\System32\\\\.+\\.dll$`\n* More wildcards: `Windows\\\\.+\\\\.+\\.dll$`\n* Specific file: `Windows\\\\System32\\\\kernel32\\.dll$`\n* Multiple extensions: `\\.(php|aspx|resx|asmx)$`\n\nNote: no drive and forward slashes - these expressions are for paths\nrelative to the root of the filesystem. If upload is selected\nNumberOfHits is redundant and not advised as hits are grouped by\npath to ensure files only downloaded once.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AllDrives": {
        "description": "",
        "title": "AllDrives",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "ContextBytes": {
        "description": "Include this amount of bytes around hit as context.",
        "title": "ContextBytes",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      },
      "DriveLetter": {
        "description": "Target drive. Default is a C:",
        "title": "DriveLetter",
        "type": "string",
        "x-velociraptor-default": "C:",
        "x-velociraptor-type": ""
      },
      "EarliestFNCreation": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "EarliestFNCreation",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EarliestSILastChanged": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "EarliestSILastChanged",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "FileNameRegex": {
        "description": "Only file names that match this regular expression will be scanned.",
        "title": "FileNameRegex",
        "type": "string",
        "x-velociraptor-default": "^kernel32\\.dll$",
        "x-velociraptor-type": ""
      },
      "LatestFNCreation": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "LatestFNCreation",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "LatestSILastChanged": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "LatestSILastChanged",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "NumberOfHits": {
        "description": "THis artifact will stop by default at one hit. This setting allows additional hits",
        "title": "NumberOfHits",
        "type": "integer",
        "x-velociraptor-default": "1",
        "x-velociraptor-type": "int64"
      },
      "PathRegex": {
        "description": "Only paths that match this regular expression will be scanned.",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": "C:\\\\Windows\\\\System32\\\\",
        "x-velociraptor-type": ""
      },
      "SizeMax": {
        "description": "",
        "title": "SizeMax",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "SizeMin": {
        "description": "",
        "title": "SizeMin",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "UploadHits": {
        "description": "",
        "title": "UploadHits",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "YaraRule": {
        "description": "Final Yara option and the default if no other options provided.",
        "format": "yara",
        "title": "YaraRule",
        "type": "string",
        "x-velociraptor-default": "rule IsPE:TestRule {\n   meta:\n      author = \"the internet\"\n      date = \"2021-03-04\"\n      description = \"A simple PE rule to test yara features\"\n  condition:\n     uint16(0) == 0x5A4D and\n     uint32(uint32(0x3C)) == 0x00004550\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_017Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Yara.NTFS",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-031"></a>

### 031. `Windows.Detection.Yara.PhysicalMemory`

功能描述（真实注册原文）：

Scans physical memory for YARA matches using the WinPmem driver.

There are 2 kinds of YARA rules that can be deployed:

1. URL link to a YARA rule.
2. A standard YARA rule attached as a parameter.

Only one method of YARA will be applied and search order is as
above. The default is Cobalt Strike opcodes.

The artifact will load the WinPmem driver, then YARA scan the
physical memory and remove the driver.

NOTE: This artifact is experimental and can crash the system!

#### Handling signatures with fixed strings.

When the signature specifies fixed strings, the YARA engine will
load it into memory, causing the signature to match memory used by
Velociraptor. To avoid this false positive encode the fixed string
as an alternative string.

For example instead of:
```
$sequence_5 = { 250000ff00 33d0 8b4db0 c1e908 }
```

Write as:
```
$sequence_5 = { 250000ff00 33d0 8b4db0 c1e9 ( 08 | 08 ) }
```

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans physical memory for YARA matches using the WinPmem driver.\n\nThere are 2 kinds of YARA rules that can be deployed:\n\n1. URL link to a YARA rule.\n2. A standard YARA rule attached as a parameter.\n\nOnly one method of YARA will be applied and search order is as\nabove. The default is Cobalt Strike opcodes.\n\nThe artifact will load the WinPmem driver, then YARA scan the\nphysical memory and remove the driver.\n\nNOTE: This artifact is experimental and can crash the system!\n\n#### Handling signatures with fixed strings.\n\nWhen the signature specifies fixed strings, the YARA engine will\nload it into memory, causing the signature to match memory used by\nVelociraptor. To avoid this false positive encode the fixed string\nas an alternative string.\n\nFor example instead of:\n```\n$sequence_5 = { 250000ff00 33d0 8b4db0 c1e908 }\n```\n\nWrite as:\n```\n$sequence_5 = { 250000ff00 33d0 8b4db0 c1e9 ( 08 | 08 ) }\n```\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ContextBytes": {
        "description": "Include this amount of bytes around hit as context.",
        "title": "ContextBytes",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      },
      "DriverPath": {
        "description": "Where to unpack the driver before loading it.",
        "title": "DriverPath",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\Temp\\winpmem.sys",
        "x-velociraptor-type": ""
      },
      "NumberOfHits": {
        "description": "THis artifact will stop by default at one hit. This setting allows additional hits",
        "title": "NumberOfHits",
        "type": "integer",
        "x-velociraptor-default": "100",
        "x-velociraptor-type": "int64"
      },
      "ServiceName": {
        "description": "Override the name of the driver service to install.",
        "title": "ServiceName",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "YaraRule": {
        "description": "Final Yara option and the default if no other options provided.",
        "format": "yara",
        "title": "YaraRule",
        "type": "string",
        "x-velociraptor-default": "rule win_cobalt_strike_auto {\n   meta:\n     author = \"Felix Bilstein - yara-signator at cocacoding dot com\"\n     date = \"2019-11-26\"\n     version = \"1\"\n     description = \"autogenerated rule brought to you by yara-signator\"\n     tool = \"yara-signator 0.2a\"\n     malpedia_reference = \"https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike\"\n     malpedia_license = \"CC BY-SA 4.0\"\n     malpedia_sharing = \"TLP:WHITE\"\n\n   strings:\n     $sequence_0 = { 3bc7 750d ff15???????? 3d33270000 }\n     $sequence_1 = { e9???????? eb0a b801000000 e9???????? }\n     $sequence_2 = { 8bd0 e8???????? 85c0 7e0e }\n     $sequence_3 = { ffb5f8f9ffff ff15???????? 8b4dfc 33cd e8???????? c9 c3 }\n     $sequence_4 = { e8???????? e9???????? 833d?????????? 7505 e8???????? }\n     $sequence_5 = { 250000ff00 33d0 8b4db0 c1e9 ( 08 | 08 ) }\n     $sequence_6 = { ff75f4 ff7610 ff761c ff75 (fc | fc) }\n     $sequence_7 = { 8903 6a06 eb39 33ff 85c0 762b 03 ( f1 | f1 ) }\n     $sequence_8 = { 894d ( d4 | d4 ) 8b458c d1f8 894580 8b45f8 c1e818 0fb6c8 }\n     $sequence_9 = { 890a 8b45 ( 08 | 08 ) 0fb64804 81e1ff000000 c1e118 8b5508 0fb64205 }\n     $sequence_10 = { 33d2 e8???????? 48b873797374656d3332 4c8bc7 488903 49ffc0 }\n     $sequence_11 = { 488bd1 498d4b ( d8 | d8 ) 498943e0 498943e8 }\n     $sequence_12 = { b904000000 486bc9 ( 0e | 0e ) 488b542430 4c8b442430 418b0c08 8b0402 }\n     $sequence_13 = { ba80000000 e8???????? 488d4c2438 e8???????? 488d4c2420 8bd0 e8???????? }\n     $sequence_14 = { 488b4c2430 8b0401 ( 89 | 89 ) 442428 b804000000 486bc004 }\n     $sequence_15 = { 4883c708 4883c304 49ff ( c3 | c3 ) 48ffcd 0f854fffffff 488d4c2420 }\n\n  condition:\n      7 of them\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_018Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Yara.PhysicalMemory",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-032"></a>

### 032. `Windows.Detection.Yara.Process`

功能描述（真实注册原文）：

Runs YARA over processes in memory and optionally uploads process
dumps.

There are 2 kinds of YARA rules that can be deployed:

1. URL link to a YARA rule.
3. or a Standard YARA rule attached as a parameter.

Only one method of YARA will be applied and search order is as
above. The default is Cobalt Strike opcodes.

Regex parameters can be applied for process name and pid for
targeting. The artifact also has an option to upload any process
with YARA hits.

Note: by default the YARA scan will stop after one hit. Multi-string
rules will also only show one string in returned rows. If upload is
selected NumberOfHits is redundant and not advised as hits are
grouped by path to ensure files only downloaded once.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Runs YARA over processes in memory and optionally uploads process\ndumps.\n\nThere are 2 kinds of YARA rules that can be deployed:\n\n1. URL link to a YARA rule.\n3. or a Standard YARA rule attached as a parameter.\n\nOnly one method of YARA will be applied and search order is as\nabove. The default is Cobalt Strike opcodes.\n\nRegex parameters can be applied for process name and pid for\ntargeting. The artifact also has an option to upload any process\nwith YARA hits.\n\nNote: by default the YARA scan will stop after one hit. Multi-string\nrules will also only show one string in returned rows. If upload is\nselected NumberOfHits is redundant and not advised as hits are\ngrouped by path to ensure files only downloaded once.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ContextBytes": {
        "description": "Include this amount of bytes around hit as context.",
        "title": "ContextBytes",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int64"
      },
      "ExePathWhitelist": {
        "description": "Regex of ProcessPaths to exclude",
        "format": "regex",
        "title": "ExePathWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "NumberOfHits": {
        "description": "THis artifact will stop by default at one hit. This setting allows additional hits",
        "title": "NumberOfHits",
        "type": "integer",
        "x-velociraptor-default": "1",
        "x-velociraptor-type": "int"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "UploadHits": {
        "description": "",
        "title": "UploadHits",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "YaraRule": {
        "description": "Final Yara option and the default if no other options provided.",
        "format": "yara",
        "title": "YaraRule",
        "type": "string",
        "x-velociraptor-default": "rule win_cobalt_strike_auto {\n   meta:\n     author = \"Felix Bilstein - yara-signator at cocacoding dot com\"\n     date = \"2019-11-26\"\n     version = \"1\"\n     description = \"autogenerated rule brought to you by yara-signator\"\n     tool = \"yara-signator 0.2a\"\n     malpedia_reference = \"https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike\"\n     malpedia_license = \"CC BY-SA 4.0\"\n     malpedia_sharing = \"TLP:WHITE\"\n\n   strings:\n     $sequence_0 = { 3bc7 750d ff15???????? 3d33270000 }\n     $sequence_1 = { e9???????? eb0a b801000000 e9???????? }\n     $sequence_2 = { 8bd0 e8???????? 85c0 7e0e }\n     $sequence_3 = { ffb5f8f9ffff ff15???????? 8b4dfc 33cd e8???????? c9 c3 }\n     $sequence_4 = { e8???????? e9???????? 833d?????????? 7505 e8???????? }\n     $sequence_5 = { 250000ff00 33d0 8b4db0 c1e908 }\n     $sequence_6 = { ff75f4 ff7610 ff761c ff75fc }\n     $sequence_7 = { 8903 6a06 eb39 33ff 85c0 762b 03f1 }\n     $sequence_8 = { 894dd4 8b458c d1f8 894580 8b45f8 c1e818 0fb6c8 }\n     $sequence_9 = { 890a 8b4508 0fb64804 81e1ff000000 c1e118 8b5508 0fb64205 }\n     $sequence_10 = { 33d2 e8???????? 48b873797374656d3332 4c8bc7 488903 49ffc0 }\n     $sequence_11 = { 488bd1 498d4bd8 498943e0 498943e8 }\n     $sequence_12 = { b904000000 486bc90e 488b542430 4c8b442430 418b0c08 8b0402 }\n     $sequence_13 = { ba80000000 e8???????? 488d4c2438 e8???????? 488d4c2420 8bd0 e8???????? }\n     $sequence_14 = { 488b4c2430 8b0401 89442428 b804000000 486bc004 }\n     $sequence_15 = { 4883c708 4883c304 49ffc3 48ffcd 0f854fffffff 488d4c2420 }\n\n  condition:\n      7 of them\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_019Arguments",
    "type": "object"
  },
  "name": "Windows.Detection.Yara.Process",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-033"></a>

### 033. `Windows.ETW.DotNetRundown`

功能描述（真实注册原文）：

Queries the Microsoft-Windows-DotNETRuntimeRundown provider to
collect a list of DotNet modules loaded into a process. This can be
useful when responding to reflectively loaded DotNet malware.

NOTE: System.Timestamp represents when the artifact was run, NOT
when the module was loaded.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Queries the Microsoft-Windows-DotNETRuntimeRundown provider to\ncollect a list of DotNet modules loaded into a process. This can be\nuseful when responding to reflectively loaded DotNet malware.\n\nNOTE: System.Timestamp represents when the artifact was run, NOT\nwhen the module was loaded.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AnyKeyword": {
        "description": "Any keyword level for collection",
        "title": "AnyKeyword",
        "type": "integer",
        "x-velociraptor-default": "0x48",
        "x-velociraptor-type": "int"
      },
      "EventIDRegex": {
        "description": "",
        "format": "regex",
        "title": "EventIDRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "Timeout": {
        "description": "",
        "title": "Timeout",
        "type": "integer",
        "x-velociraptor-default": "20",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_020Arguments",
    "type": "object"
  },
  "name": "Windows.ETW.DotNetRundown",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-034"></a>

### 034. `Windows.EventLogs.AlternateLogon`

功能描述（真实注册原文）：

Extracts alternate credential logon events (Event ID 4648) from the
Security event log.

Logon specifying alternate credentials - if NLA enabled on
destination Current logged-on User Name Alternate User Name
Destination Host Name/IP Process Name

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts alternate credential logon events (Event ID 4648) from the\nSecurity event log.\n\nLogon specifying alternate credentials - if NLA enabled on\ndestination Current logged-on User Name Alternate User Name\nDestination Host Name/IP Process Name\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "securityLogFile": {
        "description": "",
        "title": "securityLogFile",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/System32/Winevt/Logs/Security.evtx",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_021Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.AlternateLogon",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-035"></a>

### 035. `Windows.EventLogs.Cleared`

功能描述（真实注册原文）：

Detects event log clearing events from the Security (EID 1102) and
System (EID 104) logs.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects event log clearing events from the Security (EID 1102) and\nSystem (EID 104) logs.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "TargetGlob": {
        "description": "",
        "title": "TargetGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\Winevt\\Logs\\{System,Security}.evtx",
        "x-velociraptor-type": ""
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_022Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.Cleared",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-036"></a>

### 036. `Windows.EventLogs.Evtx`

功能描述（真实注册原文）：

Parses and returns events from Windows evtx logs.

Each event is returned in full, but results can be narrowed by using a glob
pattern for evtx files, a timespan, and regexes to match the evtx path, event
channel, and/or event ID:

- EvtxGlob: glob of event log files (evtx) to target
- StartDate: earliest event created timestamp to target
- EndDate: latest event created timestamp to target
- PathRegex: a regex to match against paths returned from EvtxGlob
- ChannelRegex: a regex to match against the event channel
- IDRegex: a regex to match against the event ID

Gathering these logs enables VQL analysis (_e.g._, via notebooks) and bulk
export (_e.g._, to elasticsearch) for additional processing.  It can also be
used as the basis for custom artifacts with more in-depth filtering.

**Note: This artifact can be resource intensive.**

- Parsing and aggregating may use high amounts of CPU on the client. Consider
reducing the ops/second or narrowing the glob/path regex if necessary.
- Parsing may use significant memory and time when searching VSS volumes and
deduplicating events. This is proportional to the evtx file size and number
of VSS copies. Consider whether the extra events are worth the resources.
- Parsing many event logs may take longer than the default timeout.  When
parsing all log files and searching VSS, consider doubling the default or
more (especially with reduced ops/second, or if targets have high-volume
3rd-party log sources such as Sysmon).
- The artifact routinely produces hundreds of thousands of rows per host.
Consider filtering results using path, channel, and ID regexes if necessary.

Inspired by others in `Windows.EventLogs.*`, many by Matt Green (@mgreen27).

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses and returns events from Windows evtx logs.\n\nEach event is returned in full, but results can be narrowed by using a glob\npattern for evtx files, a timespan, and regexes to match the evtx path, event\nchannel, and/or event ID:\n\n- EvtxGlob: glob of event log files (evtx) to target\n- StartDate: earliest event created timestamp to target\n- EndDate: latest event created timestamp to target\n- PathRegex: a regex to match against paths returned from EvtxGlob\n- ChannelRegex: a regex to match against the event channel\n- IDRegex: a regex to match against the event ID\n\nGathering these logs enables VQL analysis (_e.g._, via notebooks) and bulk\nexport (_e.g._, to elasticsearch) for additional processing.  It can also be\nused as the basis for custom artifacts with more in-depth filtering.\n\n**Note: This artifact can be resource intensive.**\n\n- Parsing and aggregating may use high amounts of CPU on the client. Consider\nreducing the ops/second or narrowing the glob/path regex if necessary.\n- Parsing may use significant memory and time when searching VSS volumes and\ndeduplicating events. This is proportional to the evtx file size and number\nof VSS copies. Consider whether the extra events are worth the resources.\n- Parsing many event logs may take longer than the default timeout.  When\nparsing all log files and searching VSS, consider doubling the default or\nmore (especially with reduced ops/second, or if targets have high-volume\n3rd-party log sources such as Sysmon).\n- The artifact routinely produces hundreds of thousands of rows per host.\nConsider filtering results using path, channel, and ID regexes if necessary.\n\nInspired by others in `Windows.EventLogs.*`, many by Matt Green (@mgreen27).\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ChannelRegex": {
        "description": "",
        "format": "regex",
        "title": "ChannelRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "EndDate": {
        "description": "Parse events on or before this date (YYYY-MM-DDTmm:hh:ssZ)",
        "format": "velociraptor-timestamp",
        "title": "EndDate",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EvtxGlob": {
        "description": "",
        "title": "EvtxGlob",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\winevt\\Logs\\*.evtx",
        "x-velociraptor-type": ""
      },
      "IDRegex": {
        "description": "",
        "format": "regex",
        "title": "IDRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "StartDate": {
        "description": "Parse events on or after this date (YYYY-MM-DDTmm:hh:ssZ)",
        "format": "velociraptor-timestamp",
        "title": "StartDate",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_023Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.Evtx",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-037"></a>

### 037. `Windows.EventLogs.EvtxHunter`

功能描述（真实注册原文）：

Searches all Windows EVTX files for events matching a regex IOC in
message, EventData, or UserData fields.

Searching EventLog files is helpful for triage and scoping an
incident. The idea is a user can search for any IOC or other string
of interest and return all results across the Event Log ecosystem.

There are several parameters available for search leveraging regex:

- EvtxGlob glob of EventLogs to target. Default to all but can be targeted.
- dateAfter enables search for events after this date.
- dateBefore enables search for events before this date.
- IocRegex enables regex search over the message field.
- WhitelistRegex enables a regex whitelist for the Message field.
- PathRegex enables filtering on evtx path for specific log targeting.
- ChannelRegex allows specific EVTX Channel targets.
- IdRegex enables a regex query to select specific event Ids.
- SearchVSS enables searching over VSS

Note: this artifact can potentially be heavy on the endpoint.
Please use with caution.
EventIds with an EventData field regex will be applied and requires double
escape for backslash due to serialization of this field.
E.g `C:\\\\FOLDER\\\\binary\\.exe`
For EventIds with no EventData the Message field is queried and requires
standard Velociraptor escape. E.g `C:\\FOLDER\\binary\\.exe`

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches all Windows EVTX files for events matching a regex IOC in\nmessage, EventData, or UserData fields.\n\nSearching EventLog files is helpful for triage and scoping an\nincident. The idea is a user can search for any IOC or other string\nof interest and return all results across the Event Log ecosystem.\n\nThere are several parameters available for search leveraging regex:\n\n- EvtxGlob glob of EventLogs to target. Default to all but can be targeted.\n- dateAfter enables search for events after this date.\n- dateBefore enables search for events before this date.\n- IocRegex enables regex search over the message field.\n- WhitelistRegex enables a regex whitelist for the Message field.\n- PathRegex enables filtering on evtx path for specific log targeting.\n- ChannelRegex allows specific EVTX Channel targets.\n- IdRegex enables a regex query to select specific event Ids.\n- SearchVSS enables searching over VSS\n\nNote: this artifact can potentially be heavy on the endpoint.\nPlease use with caution.\nEventIds with an EventData field regex will be applied and requires double\nescape for backslash due to serialization of this field.\nE.g `C:\\\\\\\\FOLDER\\\\\\\\binary\\\\.exe`\nFor EventIds with no EventData the Message field is queried and requires\nstandard Velociraptor escape. E.g `C:\\\\FOLDER\\\\binary\\\\.exe`\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ChannelRegex": {
        "description": "Channel regex to enable filtering on path",
        "title": "ChannelRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EvtxGlob": {
        "description": "",
        "title": "EvtxGlob",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\*.evtx",
        "x-velociraptor-type": ""
      },
      "IdRegex": {
        "description": "",
        "format": "regex",
        "title": "IdRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "IocRegex": {
        "description": "IOC regex",
        "format": "regex",
        "title": "IocRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "Event log regex to enable filtering on path",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProviderRegex": {
        "description": "Provider regex to enable filtering on provider",
        "format": "regex",
        "title": "ProviderRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      },
      "WhitelistRegex": {
        "description": "Regex of string to whitelist",
        "format": "regex",
        "title": "WhitelistRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_024Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.EvtxHunter",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-038"></a>

### 038. `Windows.EventLogs.ExplicitLogon`

功能描述（真实注册原文）：

Searches the Windows Security event log for explicit logon events, that is
Event ID 4648: "A logon was attempted using explicit credentials".

If logging is enabled, these events are generated on the source machine
whenever an authentication attempt occurs under a different user context.
Examples include a user authenticating to another machine using wmic or
mapping a drive using different credentials, or using the RunAs option
locally.

This artifact by default filters all events with `localhost` as the server
and `MACHINE$` as target user. A recommended hunt for lateral movement would
be activity to other machines from commonly abused LOLBins or explicit logon
events from unusual processes.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches the Windows Security event log for explicit logon events, that is\nEvent ID 4648: \"A logon was attempted using explicit credentials\".\n\nIf logging is enabled, these events are generated on the source machine\nwhenever an authentication attempt occurs under a different user context.\nExamples include a user authenticating to another machine using wmic or\nmapping a drive using different credentials, or using the RunAs option\nlocally.\n\nThis artifact by default filters all events with `localhost` as the server\nand `MACHINE$` as target user. A recommended hunt for lateral movement would\nbe activity to other machines from commonly abused LOLBins or explicit logon\nevents from unusual processes.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EvtxGlob": {
        "description": "",
        "title": "EvtxGlob",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
        "x-velociraptor-type": ""
      },
      "ProcessNameRegex": {
        "description": "Target process regex",
        "title": "ProcessNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "ProcessNameWhitelist": {
        "description": "Target process whitelist regex",
        "format": "regex",
        "title": "ProcessNameWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "ServerRegex": {
        "description": "Target server regex",
        "format": "regex",
        "title": "ServerRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ServerWhitelist": {
        "description": "Target server whitelist regex",
        "format": "regex",
        "title": "ServerWhitelist",
        "type": "string",
        "x-velociraptor-default": "localhost",
        "x-velociraptor-type": "regex"
      },
      "UsernameRegex": {
        "description": "Target username regex",
        "format": "regex",
        "title": "UsernameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "UsernameWhitelist": {
        "description": "Target username whitelist regex",
        "format": "regex",
        "title": "UsernameWhitelist",
        "type": "string",
        "x-velociraptor-default": "\\\\$$",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_025Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.ExplicitLogon",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-039"></a>

### 039. `Windows.EventLogs.Modifications`

功能描述（真实注册原文）：

Checks registry keys for WINEVT channels and WMI autologger
providers to detect event log tampering.

It is possible to disable windows event logs on a per channel or per
provider basis. Attackers may disable critical log sources to
prevent detections.

This artifact reads the state of the event log system from the
registry and attempts to detect when event logs were disabled.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Checks registry keys for WINEVT channels and WMI autologger\nproviders to detect event log tampering.\n\nIt is possible to disable windows event logs on a per channel or per\nprovider basis. Attackers may disable critical log sources to\nprevent detections.\n\nThis artifact reads the state of the event log system from the\nregistry and attempts to detect when event logs were disabled.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for modifications after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for modifications before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "ProviderRegex": {
        "description": "",
        "format": "regex",
        "title": "ProviderRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_026Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.Modifications",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-040"></a>

### 040. `Windows.EventLogs.PowershellModule`

功能描述（真实注册原文）：

Extracts PowerShell module logging events (EID 4103) from the
PowerShell Operational log with context and payload filtering.

PowerShell is commonly used by attackers across all stages of the
attack lifecycle. Although quite noisy Module logging can provide
valuable insight.

There are several parameters available for search leveraging regex:

- DateAfter enables search for events after this date.
- DateBefore enables search for events before this date.
- ContextRegex enables regex search over ContextInfo text field.
- PayloadRegex enables a regex search over Payload text field.
- SearchVSS enables VSS search

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts PowerShell module logging events (EID 4103) from the\nPowerShell Operational log with context and payload filtering.\n\nPowerShell is commonly used by attackers across all stages of the\nattack lifecycle. Although quite noisy Module logging can provide\nvaluable insight.\n\nThere are several parameters available for search leveraging regex:\n\n- DateAfter enables search for events after this date.\n- DateBefore enables search for events before this date.\n- ContextRegex enables regex search over ContextInfo text field.\n- PayloadRegex enables a regex search over Payload text field.\n- SearchVSS enables VSS search\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ContextRegex": {
        "description": "regex search over Payload text field.",
        "format": "regex",
        "title": "ContextRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EventLog": {
        "description": "",
        "title": "EventLog",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\system32\\winevt\\logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        "x-velociraptor-type": ""
      },
      "PayloadRegex": {
        "description": "regex search over Payload text field.",
        "format": "regex",
        "title": "PayloadRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_027Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.PowershellModule",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-041"></a>

### 041. `Windows.EventLogs.PowershellScriptblock`

功能描述（真实注册原文）：

Parses PowerShell script block logging entries (Event ID 4104) to
detect potentially malicious script content.

PowerShell is commonly used by attackers across all stages of the attack
lifecycle. A valuable hunt is to search Scriptblock logs for signs of
malicious content.

There are several parameters available for search leveraging regex:

- DateAfter enables search for events after this date.
- DateBefore enables search for events before this date.
- SearchStrings enables regex search over scriptblock text field.
- StringWhiteList enables a regex whitelist for scriptblock text field.
- PathWhitelist enables a regex whitelist for path of scriptblock.
- LogLevel enables searching on type of log. Default is Warning level which
  is logged even if ScriptBlock logging is turned off when suspicious keywords
  detected in PowerShell interpreter. See second reference for list of keywords.
- SearchVSS enables VSS search.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses PowerShell script block logging entries (Event ID 4104) to\ndetect potentially malicious script content.\n\nPowerShell is commonly used by attackers across all stages of the attack\nlifecycle. A valuable hunt is to search Scriptblock logs for signs of\nmalicious content.\n\nThere are several parameters available for search leveraging regex:\n\n- DateAfter enables search for events after this date.\n- DateBefore enables search for events before this date.\n- SearchStrings enables regex search over scriptblock text field.\n- StringWhiteList enables a regex whitelist for scriptblock text field.\n- PathWhitelist enables a regex whitelist for path of scriptblock.\n- LogLevel enables searching on type of log. Default is Warning level which\n  is logged even if ScriptBlock logging is turned off when suspicious keywords\n  detected in PowerShell interpreter. See second reference for list of keywords.\n- SearchVSS enables VSS search.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EvtxGlob": {
        "description": "",
        "title": "EvtxGlob",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\winevt\\logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        "x-velociraptor-type": ""
      },
      "LogLevel": {
        "description": "Log level. Warning is PowerShell default bad keyword list.",
        "enum": [
          "All",
          "Warning",
          "Verbose"
        ],
        "title": "LogLevel",
        "type": "string",
        "x-velociraptor-default": "Warning",
        "x-velociraptor-type": "choices"
      },
      "PathWhitelist": {
        "description": "Regex of path to whitelist.",
        "format": "regex",
        "title": "PathWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "SearchStrings": {
        "description": "regex search over scriptblock text field.",
        "format": "regex",
        "title": "SearchStrings",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "StringWhitelist": {
        "description": "Regex of string to whitelist",
        "format": "regex",
        "title": "StringWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_028Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.PowershellScriptblock",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-042"></a>

### 042. `Windows.EventLogs.RDPAuth`

功能描述（真实注册原文）：

Extracts RDP authentication and session events from Security,
System, and Terminal Services event logs.

Security channel - EventID in 4624,4634 AND LogonType 3, 7, or 10.
Security channel - EventID in 4778,4625,4779, or 4647.
System channel -  EventID 9009.
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational - EventID 1149.
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational - EventID 23,22,21,24,25,39, or 40.

Best use of this artifact is to collect RDP and Authentication
events around a timeframe of interest and order by EventTime to
scope RDP activity.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts RDP authentication and session events from Security,\nSystem, and Terminal Services event logs.\n\nSecurity channel - EventID in 4624,4634 AND LogonType 3, 7, or 10.\nSecurity channel - EventID in 4778,4625,4779, or 4647.\nSystem channel -  EventID 9009.\nMicrosoft-Windows-TerminalServices-RemoteConnectionManager/Operational - EventID 1149.\nMicrosoft-Windows-TerminalServices-LocalSessionManager/Operational - EventID 23,22,21,24,25,39, or 40.\n\nBest use of this artifact is to collect RDP and Authentication\nevents around a timeframe of interest and order by EventTime to\nscope RDP activity.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "LocalSessionManager": {
        "description": "path to TerminalServices-LocalSessionManager operational event log.",
        "title": "LocalSessionManager",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        "x-velociraptor-type": ""
      },
      "RemoteConnectionManager": {
        "description": "path to TerminalServices-RemoteConnectionManager operational event log.",
        "title": "RemoteConnectionManager",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
        "x-velociraptor-type": ""
      },
      "Security": {
        "description": "path to Security event log.",
        "title": "Security",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
        "x-velociraptor-type": ""
      },
      "SourceIPRegex": {
        "description": "",
        "format": "regex",
        "title": "SourceIPRegex",
        "type": "string",
        "x-velociraptor-default": ".+",
        "x-velociraptor-type": "regex"
      },
      "System": {
        "description": "path to System event log.",
        "title": "System",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx",
        "x-velociraptor-type": ""
      },
      "UserNameRegex": {
        "description": "",
        "format": "regex",
        "title": "UserNameRegex",
        "type": "string",
        "x-velociraptor-default": ".+",
        "x-velociraptor-type": "regex"
      },
      "UserNameWhitelist": {
        "description": "",
        "format": "regex",
        "title": "UserNameWhitelist",
        "type": "string",
        "x-velociraptor-default": "\\$$",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_029Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.RDPAuth",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-043"></a>

### 043. `Windows.EventLogs.ScheduledTasks`

功能描述（真实注册原文）：

Extracts and formats Windows scheduled task events from the
TaskScheduler operational and Security logs.

Adversaries may abuse tasks for execution, persistence, lateral
movement or privilege escalation. This artifact collates all events
from `Microsoft-Windows-TaskScheduler/Operational` event log channel
and scheduled task events from the Security log if configured.

A common hunting use case may be collection all deleted scheduled
tasks (EID 141), all modified scheduled tasks (EID 140) then run
frequency analysis and chase down any abnormalities for the
environment. Similarly task execution (EID 129) and registration
(EID 106) can be a good collection hunting for unusual paths.

Pivoting can be via either: TaskSchedulerEventRegex, TaskName or IOC
regex (e.g taskname|delete|created|update)

Note: Audit Other Object Access Events is required to be implemented
to record scheduled tasks being registered, modified or disabled in
the Security event log channel.

See: Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Object Access

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts and formats Windows scheduled task events from the\nTaskScheduler operational and Security logs.\n\nAdversaries may abuse tasks for execution, persistence, lateral\nmovement or privilege escalation. This artifact collates all events\nfrom `Microsoft-Windows-TaskScheduler/Operational` event log channel\nand scheduled task events from the Security log if configured.\n\nA common hunting use case may be collection all deleted scheduled\ntasks (EID 141), all modified scheduled tasks (EID 140) then run\nfrequency analysis and chase down any abnormalities for the\nenvironment. Similarly task execution (EID 129) and registration\n(EID 106) can be a good collection hunting for unusual paths.\n\nPivoting can be via either: TaskSchedulerEventRegex, TaskName or IOC\nregex (e.g taskname|delete|created|update)\n\nNote: Audit Other Object Access Events is required to be implemented\nto record scheduled tasks being registered, modified or disabled in\nthe Security event log channel.\n\nSee: Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Object Access\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "IocRegex": {
        "description": "IOC regex to search for.",
        "format": "regex",
        "title": "IocRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "Security": {
        "description": "path to Security event log.",
        "title": "Security",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
        "x-velociraptor-type": ""
      },
      "SecurityEventRegex": {
        "description": "regex of Security log event ids.",
        "format": "regex",
        "title": "SecurityEventRegex",
        "type": "string",
        "x-velociraptor-default": "^(4698|4699|4700|4701|4702)$",
        "x-velociraptor-type": "regex"
      },
      "TaskActionRegex": {
        "description": "regex of target task execution process / path.",
        "format": "regex",
        "title": "TaskActionRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "TaskActionWhitelist": {
        "description": "regex of task processes to exclude from results.",
        "format": "regex",
        "title": "TaskActionWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "TaskNameRegex": {
        "description": "regex of target task name.",
        "format": "regex",
        "title": "TaskNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "TaskNameWhitelist": {
        "description": "regex of task names to exclude from results.",
        "format": "regex",
        "title": "TaskNameWhitelist",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "TaskScheduler": {
        "description": "path to the TaskScheduler/Operational event log",
        "title": "TaskScheduler",
        "type": "string",
        "x-velociraptor-default": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "x-velociraptor-type": ""
      },
      "TaskSchedulerEventRegex": {
        "description": "Regex of TaskScheduler log event ids.",
        "format": "regex",
        "title": "TaskSchedulerEventRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "UserNameRegex": {
        "description": "regex of target user name.",
        "format": "regex",
        "title": "UserNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_030Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.ScheduledTasks",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-044"></a>

### 044. `Windows.EventLogs.ServiceCreationComspec`

功能描述（真实注册原文）：

Detects SCM lateral movement by searching System event log for
service creation events (EID 7045) with "COMSPEC" or "cmd.exe" in
the image path.

This detects many hack tools that use SCM based lateral movement
including `smbexec`.

If `VSSAnalysisAge` is non-zero then this enables querying VSS
instances for the `EventLog` path, which includes event
deduplication.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects SCM lateral movement by searching System event log for\nservice creation events (EID 7045) with \"COMSPEC\" or \"cmd.exe\" in\nthe image path.\n\nThis detects many hack tools that use SCM based lateral movement\nincluding `smbexec`.\n\nIf `VSSAnalysisAge` is non-zero then this enables querying VSS\ninstances for the `EventLog` path, which includes event\ndeduplication.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ComspecRegex": {
        "description": "",
        "format": "regex",
        "title": "ComspecRegex",
        "type": "string",
        "x-velociraptor-default": "(COMSPEC|cmd.exe|ADMIN\\$)",
        "x-velociraptor-type": "regex"
      },
      "EventLog": {
        "description": "",
        "title": "EventLog",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\system32\\winevt\\logs\\System.evtx",
        "x-velociraptor-type": ""
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_031Arguments",
    "type": "object"
  },
  "name": "Windows.EventLogs.ServiceCreationComspec",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-045"></a>

### 045. `Windows.Forensics.Amcache`

功能描述（真实注册原文）：

Parses the Amcache.hve registry hive to enumerate executed binaries,
installed programs, and drivers.

The Amcache.hve is a registry artifact that stores metadata used by
the OS's application compatibility infrastructure to record metadata
about binaries present on the system. This includes file paths,
hashes, timestamps, and install/interaction information for
executables and drivers.

NOTE: potential evidence of execution must be corroborated by
additional artifacts.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the Amcache.hve registry hive to enumerate executed binaries,\ninstalled programs, and drivers.\n\nThe Amcache.hve is a registry artifact that stores metadata used by\nthe OS's application compatibility infrastructure to record metadata\nabout binaries present on the system. This includes file paths,\nhashes, timestamps, and install/interaction information for\nexecutables and drivers.\n\nNOTE: potential evidence of execution must be corroborated by\nadditional artifacts.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "File": {
        "description": "Version `From Windows 8/2012 to Windows 10 1709`. This key is constituted of several subkeys where each representing a volume GUID that contains subkeys looking like `Root\\File\\<GUID>\\<MFTId>`",
        "title": "File",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "Generic": {
        "description": "Version `From Windows 8 to Windows 10 1507`, The Generic key contains one subkey named 0, which in turn contains one subkey per driver installed on the system. Each of these subkeys is actually named as the SHA-1 of the driver it represents, preceded by ’0000’ like `\\Root\\Generic\\0\\0000<SHA1>`",
        "title": "Generic",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "InventoryApplication": {
        "description": "Version `From Windows 10 1607`, This key contains the installation of a program and also programs installed via an AppXPackage.",
        "title": "InventoryApplication",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "InventoryApplicationFile": {
        "description": "Version `From Windows 10 1607`, records EXE files that are part of a program.",
        "title": "InventoryApplicationFile",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "InventoryApplicationShortcut": {
        "description": "Version `From Windows 10 1709`, contains information about LNK files found on the computer in the Start Menu directory",
        "title": "InventoryApplicationShortcut",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "InventoryDeviceContainer": {
        "description": "Version `From Windows 10 1607`, records OS devices such as Bluetooth, printers, etc. Has links to DevicePnps",
        "title": "InventoryDeviceContainer",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "InventoryDevicePnp": {
        "description": "Version `From Windows 10 1607`, records Plug and Play (PnP) devices such as Bluetooth, USB, etc. More verbose details than those contained in DeviceContainers",
        "title": "InventoryDevicePnp",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "InventoryDriverBinary": {
        "description": "Version `From Windows 10 1607`, n this key, each entry is named after the SHA-1 of the driver, preceded by ’0000’, and the subkey representing the drivers.",
        "title": "InventoryDriverBinary",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "InventoryDriverPackage": {
        "description": "Version `From Windows 10 1607`, records Package information that links to both DeviceContainers and DevicePnPs",
        "title": "InventoryDriverPackage",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "NTFS_CACHE_SIZE": {
        "description": "",
        "title": "NTFS_CACHE_SIZE",
        "type": "integer",
        "x-velociraptor-default": "1000",
        "x-velociraptor-type": "int"
      },
      "Programs": {
        "description": "Version `From Windows 8/2012 to Windows 10 1709`, This key contains installed programs only in subkeys like `Root\\Programs\\<AppID>` which contains information about the PE in subkeys.",
        "title": "Programs",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "amCacheGlob": {
        "description": "",
        "title": "amCacheGlob",
        "type": "string",
        "x-velociraptor-default": "%SYSTEMROOT%/appcompat/Programs/Amcache.hve",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_032Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Amcache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-046"></a>

### 046. `Windows.Forensics.Bam`

功能描述（真实注册原文）：

Parses the BAM registry key from Windows 10+ to identify program
execution times.

The Background Activity Moderator (BAM) is a Windows service that
Controls activity of background applications.  This service exists
in Windows 10 only after Fall Creators update – version 1709.

It provides full path of the executable file that was run on the
system and last execution date/time

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the BAM registry key from Windows 10+ to identify program\nexecution times.\n\nThe Background Activity Moderator (BAM) is a Windows service that\nControls activity of background applications.  This service exists\nin Windows 10 only after Fall Creators update – version 1709.\n\nIt provides full path of the executable file that was run on the\nsystem and last execution date/time\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "bamKeys": {
        "description": "",
        "format": "text/csv",
        "title": "bamKeys",
        "type": "string",
        "x-velociraptor-default": "KeyGlob\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\*\\*\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\*\\*\n",
        "x-velociraptor-type": "csv"
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_033Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Bam",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-047"></a>

### 047. `Windows.Forensics.CertUtil`

功能描述（真实注册原文）：

Extracts download metadata from the Windows Certutil
CryptnetUrlCache to reveal LOLBin downloads.

The Windows Certutil binary is capable of downloading arbitrary
files. Attackers typically use it to fetch tools undetected when
using "Living off the Land" (LOL) techniques.

Certutil maintains a cache of the downloaded files and this contains
valuable metadata. The artifact parses this metadata to establish
what was downloaded and when.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts download metadata from the Windows Certutil\nCryptnetUrlCache to reveal LOLBin downloads.\n\nThe Windows Certutil binary is capable of downloading arbitrary\nfiles. Attackers typically use it to fetch tools undetected when\nusing \"Living off the Land\" (LOL) techniques.\n\nCertutil maintains a cache of the downloaded files and this contains\nvaluable metadata. The artifact parses this metadata to establish\nwhat was downloaded and when.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "MetadataGlobSystem": {
        "description": "",
        "title": "MetadataGlobSystem",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/*/config/systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/*",
        "x-velociraptor-type": ""
      },
      "MetadataGlobUser": {
        "description": "",
        "title": "MetadataGlobUser",
        "type": "string",
        "x-velociraptor-default": "C:/Users/*/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/*",
        "x-velociraptor-type": ""
      },
      "MinSize": {
        "description": "Only show contents larger than this size.",
        "title": "MinSize",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "URLWhitelist": {
        "description": "",
        "format": "text/csv",
        "title": "URLWhitelist",
        "type": "string",
        "x-velociraptor-default": "URL\nhttp://sf.symcd.com\nhttp://oneocsp.microsoft.com\nhttp://certificates.godaddy.com\nhttp://ocsp.pki.goog\nhttp://repository.certum.pl\nhttp://www.microsoft.com\nhttp://ocsp.verisign.com\nhttp://ctldl.windowsupdate.com\nhttp://ocsp.sectigo.com\nhttp://ocsp.usertrust.com\nhttp://ocsp.comodoca.com\nhttp://cacerts.digicert.com\nhttp://ocsp.digicert.com\n",
        "x-velociraptor-type": "csv"
      },
      "VSSAnalysisAge": {
        "description": "If larger than zero we analyze VSS within this many days\nago. (e.g 7 will analyze all VSS within the last week).  Note\nthat when using VSS analysis we have to use the ntfs accessor\nfor everything which will be much slower.\n",
        "title": "VSSAnalysisAge",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_034Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.CertUtil",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-048"></a>

### 048. `Windows.Forensics.FilenameSearch`

功能描述（真实注册原文）：

Searches the NTFS `$MFT` using YARA rules to determine if specific
filenames ever existed on the system.

"Did a specific file exist on this machine in the past or does it
still exist on this machine?" This common question comes up
frequently in cases of IP theft, discovery and other matters. One
way to answer this question is to search the $MFT file for any
references to the specific filename. If the filename is fairly
unique then a positive hit on that name generally means the file was
present.

Simply determining that a filename existed on an endpoint in the
past is significant for some investigations.

This artifact applies a YARA search for a set of filenames of
interest on the $MFT file. For any hit, the artifact then identified
the MFT entry where the hit was found and attempts to resolve that
to an actual filename.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches the NTFS `$MFT` using YARA rules to determine if specific\nfilenames ever existed on the system.\n\n\"Did a specific file exist on this machine in the past or does it\nstill exist on this machine?\" This common question comes up\nfrequently in cases of IP theft, discovery and other matters. One\nway to answer this question is to search the $MFT file for any\nreferences to the specific filename. If the filename is fairly\nunique then a positive hit on that name generally means the file was\npresent.\n\nSimply determining that a filename existed on an endpoint in the\npast is significant for some investigations.\n\nThis artifact applies a YARA search for a set of filenames of\ninterest on the $MFT file. For any hit, the artifact then identified\nthe MFT entry where the hit was found and attempts to resolve that\nto an actual filename.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Device": {
        "description": "",
        "title": "Device",
        "type": "string",
        "x-velociraptor-default": "C:",
        "x-velociraptor-type": ""
      },
      "yaraRule": {
        "description": "",
        "format": "yara",
        "title": "yaraRule",
        "type": "string",
        "x-velociraptor-default": "rule Hit {\n   strings:\n     $a = \"my secret file.txt\" nocase wide ascii\n   condition:\n     any of them\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_035Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.FilenameSearch",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-049"></a>

### 049. `Windows.Forensics.JumpLists`

功能描述（真实注册原文）：

Parses Windows AutomaticDestinations JumpList files to extract LNK
entries with application IDs and target paths.

The automaticdestinations jumplist is an OLE2 container containing
LNK files as individual streams.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Windows AutomaticDestinations JumpList files to extract LNK\nentries with application IDs and target paths.\n\nThe automaticdestinations jumplist is an OLE2 container containing\nLNK files as individual streams.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Globs": {
        "description": "",
        "title": "Globs",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_036Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.JumpLists",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-050"></a>

### 050. `Windows.Forensics.Lnk`

功能描述（真实注册原文）：

Parses Windows LNK shortcut files to extract target paths,
arguments, timestamps, and metadata.

A LNK file is a type of Shell Item that serves as a shortcut or
reference to a specific file, folder, or application. It contains
metadata and information about the accessed file or location and is
a valuable forensic artifact. LNK files can be automatically created
by the Windows operating system when a user accesses a file from a
supported application or manually created by the user.

This artifact has several configurable options:

- TargetGlob: glob targeting. Default targets *.lnk files in Startup and Recent paths.
- IOCRegex: Regex search on key fields: StringData, TrackerData and PropertyStore.
- IgnoreRegex: Ignore regex filter on key fields.
- UploadLnk: uploads lnk hits.
- SuspiciousOnly: only returns LNK files reporting a suspicious attribute.
- SusSize: Any lnk over this size in bytes is suspicious.
- SusArgSize: Any lnk with Argument strings over this size is suspicious.
- SusArgRegex: Regex for suspicious strings in Arguments.
- SusHostnameRegex: Regex for suspicious TrackerData Hostname.
- VmPrefixMAC: Regex to match known Virtual Machine MacAddress prefix in TrackerData.
- RiskyExe: Regex target exe to flag as risky.

List of fields targeted by filter regex:

- StringData.TargetPath
- StringData.Name
- StringData.RelativePath
- StringData.WorkingDir
- StringData.Arguments
- StringData.IconLocation
- LinkTarget.LinkTarget
- PropertyStore
- TrackerData.MachineID
- TrackerData.MacAddress

NOTE: regex startof (^) and endof ($) line modifiers will not work.


Windows.Forensics.Lnk also will highlight suspicious lnk attributes in a Suspicious field.

* Large Size - Check for large size, default over 20000 bytes
* Startup Path - Path with \Startup\
* Zeroed Headers - Check for ShellHeader items zeroed.
* Hidden window - Check for ShellLinkHeader.ShowCommand as SHOWMINNOACTIVE
* Target Changed path - Check LNK TargetPath different from PropertyStore path.
* Target Changed size - Check LNK ShellLinkHeader.FileSize different from PropertyStore size.
* Risky target - Checks several LNK target paths to the RiskyExe regex.
* WebDAV - Checks for NetworkProviderType = WNNC_NET_DAV
* Line break in StringData.Name
* Suspicious argument size - large sized arguments over 250 characters as default
* Environment variable script - environment variable with a common script configured (bat|cmd|ps1|js|vbs|vbe|py)
* No Target with environment variable - environment variable only execution
* Suspicious hostname - some common malicious hostnames
* Created in VM - Check TrackerData MacAddress for known VM prefix
* Local Admin- check PropertyStore for indications LNK created by local admin UID 500
* Cyrillic Language - check PropertyStore for Cyrillic strings
* Chinese Language - check PropertyStore for Chinese strings
* Korean Language - check PropertyStore for Korean strings
* Persian Language - check PropertyStore for Persian strings
* Vietnamese Language - check PropertyStore for Vietnamese strings
* CodePage - checks for existence of a ExtraData code page setting. Rare enough to report on - 936:Simplified Chinese, 949:Korean, 950:Traditional Chinese
* Has Overlay - check for overlay and extra data attached to LNK
* Long Base64 - check for a long base64 blog over 20 decoded characters
* Arguments have ticks - ticks are common in malicious LNK files
* Arguments have environment variables - environment variables (%|\$env:) are common in malicious LNKs
* Arguments have rare characters - looks for specific rare characters that may indicate obfuscation (\?|\!|\~|\@)
* Arguments have leading space - malicious LNK files may have a many leading spaces to obfuscate some tools
* Arguments have http strings - LNKs are regularly used as a download cradle - https?://
* Arguments have UNC strings
* Suspicious arguments - some common malicious arguments observed in field (with mind to False positive)

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Windows LNK shortcut files to extract target paths,\narguments, timestamps, and metadata.\n\nA LNK file is a type of Shell Item that serves as a shortcut or\nreference to a specific file, folder, or application. It contains\nmetadata and information about the accessed file or location and is\na valuable forensic artifact. LNK files can be automatically created\nby the Windows operating system when a user accesses a file from a\nsupported application or manually created by the user.\n\nThis artifact has several configurable options:\n\n- TargetGlob: glob targeting. Default targets *.lnk files in Startup and Recent paths.\n- IOCRegex: Regex search on key fields: StringData, TrackerData and PropertyStore.\n- IgnoreRegex: Ignore regex filter on key fields.\n- UploadLnk: uploads lnk hits.\n- SuspiciousOnly: only returns LNK files reporting a suspicious attribute.\n- SusSize: Any lnk over this size in bytes is suspicious.\n- SusArgSize: Any lnk with Argument strings over this size is suspicious.\n- SusArgRegex: Regex for suspicious strings in Arguments.\n- SusHostnameRegex: Regex for suspicious TrackerData Hostname.\n- VmPrefixMAC: Regex to match known Virtual Machine MacAddress prefix in TrackerData.\n- RiskyExe: Regex target exe to flag as risky.\n\nList of fields targeted by filter regex:\n\n- StringData.TargetPath\n- StringData.Name\n- StringData.RelativePath\n- StringData.WorkingDir\n- StringData.Arguments\n- StringData.IconLocation\n- LinkTarget.LinkTarget\n- PropertyStore\n- TrackerData.MachineID\n- TrackerData.MacAddress\n\nNOTE: regex startof (^) and endof ($) line modifiers will not work.\n\n\nWindows.Forensics.Lnk also will highlight suspicious lnk attributes in a Suspicious field.\n\n* Large Size - Check for large size, default over 20000 bytes\n* Startup Path - Path with \\Startup\\\n* Zeroed Headers - Check for ShellHeader items zeroed.\n* Hidden window - Check for ShellLinkHeader.ShowCommand as SHOWMINNOACTIVE\n* Target Changed path - Check LNK TargetPath different from PropertyStore path.\n* Target Changed size - Check LNK ShellLinkHeader.FileSize different from PropertyStore size.\n* Risky target - Checks several LNK target paths to the RiskyExe regex.\n* WebDAV - Checks for NetworkProviderType = WNNC_NET_DAV\n* Line break in StringData.Name\n* Suspicious argument size - large sized arguments over 250 characters as default\n* Environment variable script - environment variable with a common script configured (bat|cmd|ps1|js|vbs|vbe|py)\n* No Target with environment variable - environment variable only execution\n* Suspicious hostname - some common malicious hostnames\n* Created in VM - Check TrackerData MacAddress for known VM prefix\n* Local Admin- check PropertyStore for indications LNK created by local admin UID 500\n* Cyrillic Language - check PropertyStore for Cyrillic strings\n* Chinese Language - check PropertyStore for Chinese strings\n* Korean Language - check PropertyStore for Korean strings\n* Persian Language - check PropertyStore for Persian strings\n* Vietnamese Language - check PropertyStore for Vietnamese strings\n* CodePage - checks for existence of a ExtraData code page setting. Rare enough to report on - 936:Simplified Chinese, 949:Korean, 950:Traditional Chinese\n* Has Overlay - check for overlay and extra data attached to LNK\n* Long Base64 - check for a long base64 blog over 20 decoded characters\n* Arguments have ticks - ticks are common in malicious LNK files\n* Arguments have environment variables - environment variables (%|\\$env:) are common in malicious LNKs\n* Arguments have rare characters - looks for specific rare characters that may indicate obfuscation (\\?|\\!|\\~|\\@)\n* Arguments have leading space - malicious LNK files may have a many leading spaces to obfuscate some tools\n* Arguments have http strings - LNKs are regularly used as a download cradle - https?://\n* Arguments have UNC strings\n* Suspicious arguments - some common malicious arguments observed in field (with mind to False positive)\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "IgnoreRegex": {
        "description": "A regex for fields to ignore",
        "format": "regex",
        "title": "IgnoreRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "IocRegex": {
        "description": "A regex to filter on all fields",
        "format": "regex",
        "title": "IocRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "RiskyExe": {
        "description": "Regex target exe to flag as risky.",
        "format": "regex",
        "title": "RiskyExe",
        "type": "string",
        "x-velociraptor-default": "\\\\(cmd|powershell|cscript|wscript|rundll32|regsvr32|mshta|wmic|conhost)\\.exe$",
        "x-velociraptor-type": "regex"
      },
      "SusArgRegex": {
        "description": "Regex for suspicious strings in arguments.",
        "format": "regex",
        "title": "SusArgRegex",
        "type": "string",
        "x-velociraptor-default": "\\\\AppData\\\\|\\\\Users\\\\Public\\\\|\\\\Temp\\\\|comspec|&cd&echo| -NoP | -W Hidden | [-/]decode | -e.* (JAB|SUVYI|SQBFAFgA|aWV4I|aQBlAHgA)|start\\s*[\\\\/]b|\\.downloadstring\\(|\\.downloadfile\\(|iex",
        "x-velociraptor-type": "regex"
      },
      "SusArgSize": {
        "description": "Any lnk with Argument strings over this size is suspicious.",
        "title": "SusArgSize",
        "type": "integer",
        "x-velociraptor-default": "250",
        "x-velociraptor-type": "int"
      },
      "SusHostnameRegex": {
        "description": "Regex for suspicious TrackerData hostnames.",
        "format": "regex",
        "title": "SusHostnameRegex",
        "type": "string",
        "x-velociraptor-default": "^(Win-|Desktop-|Commando$)",
        "x-velociraptor-type": "regex"
      },
      "SusSize": {
        "description": "Any lnk over this size in bytes is suspicious.",
        "title": "SusSize",
        "type": "integer",
        "x-velociraptor-default": "20000",
        "x-velociraptor-type": "int"
      },
      "SuspiciousOnly": {
        "description": "Only returns LNK files reporting a suspicious attribute",
        "title": "SuspiciousOnly",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "TargetGlob": {
        "description": "",
        "title": "TargetGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\{ProgramData,Users\\*\\AppData\\*}\\Microsoft\\Windows\\{Start Menu\\Programs\\StartUp,Recent\\**}\\*.lnk",
        "x-velociraptor-type": ""
      },
      "UploadLnk": {
        "description": "Also upload the link files themselves.",
        "title": "UploadLnk",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UploadTarget": {
        "description": "Also upload the link file's targets.",
        "title": "UploadTarget",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "VmPrefixMAC": {
        "description": "VM MacAddress prefix regex to compare to LNK TrackerData.",
        "format": "regex",
        "title": "VmPrefixMAC",
        "type": "string",
        "x-velociraptor-default": "^(00:50:56|00:0C:29|00:05:69|00:1C:14|08:00:27|52:54:00|00:21:F6|00:14:4F|00:0F:4B|00:15:5D)",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_037Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Lnk",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-051"></a>

### 051. `Windows.Forensics.Prefetch`

功能描述（真实注册原文）：

Parses Windows prefetch (.pf) files to extract executable execution
history and run counts.

Windows keeps a cache of prefetch files. When an executable is run,
the system records properties about the executable to make it faster
to run next time. By parsing this information we are able to
determine when binaries are run in the past. On Windows10 we can see
the last 8 execution times and creation time (9 potential
executions).

There are several parameters available for this artifact.
- dateAfter enables search for prefetch evidence after this date.
- dateBefore enables search for prefetch evidence before this date.
- binaryRegex enables to filter on binary name, e.g evil.exe.
- hashRegex enables to filter on prefetch hash.

NOTE: The Prefetch file format is described extensively in libscca
and painstakingly reversed by Joachim Metz (Shouts and Thank
you!). Thanks to https://github.com/secDre4mer for additional
information.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Windows prefetch (.pf) files to extract executable execution\nhistory and run counts.\n\nWindows keeps a cache of prefetch files. When an executable is run,\nthe system records properties about the executable to make it faster\nto run next time. By parsing this information we are able to\ndetermine when binaries are run in the past. On Windows10 we can see\nthe last 8 execution times and creation time (9 potential\nexecutions).\n\nThere are several parameters available for this artifact.\n- dateAfter enables search for prefetch evidence after this date.\n- dateBefore enables search for prefetch evidence before this date.\n- binaryRegex enables to filter on binary name, e.g evil.exe.\n- hashRegex enables to filter on prefetch hash.\n\nNOTE: The Prefetch file format is described extensively in libscca\nand painstakingly reversed by Joachim Metz (Shouts and Thank\nyou!). Thanks to https://github.com/secDre4mer for additional\ninformation.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "IncludeFilesAccessed": {
        "description": "Include all accessed files",
        "title": "IncludeFilesAccessed",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "binaryRegex": {
        "description": "Regex of executable name.",
        "format": "regex",
        "title": "binaryRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "dateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "dateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "dateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "dateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "hashRegex": {
        "description": "Regex of prefetch hash.",
        "format": "regex",
        "title": "hashRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "prefetchGlobs": {
        "description": "",
        "title": "prefetchGlobs",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\Prefetch\\*.pf",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_038Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Prefetch",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-052"></a>

### 052. `Windows.Forensics.RecentApps`

功能描述（真实注册原文）：

Enumerates program execution history from the Windows RecentApps
registry key.

GUI Program execution launched on the Win10 system is tracked in the
RecentApps key.

NOTE: This artifact is available up from Windows 10 1607 to 1709.
After that, the RecentApps key is no longer populated in the
referenced location. Previously existing data is not removed.

DEPRECATION: This artifact is deprecated and will be removed
soon. It is replaced by the RegistryHunter.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates program execution history from the Windows RecentApps\nregistry key.\n\nGUI Program execution launched on the Win10 system is tracked in the\nRecentApps key.\n\nNOTE: This artifact is available up from Windows 10 1607 to 1709.\nAfter that, the RecentApps key is no longer populated in the\nreferenced location. Previously existing data is not removed.\n\nDEPRECATION: This artifact is deprecated and will be removed\nsoon. It is replaced by the RegistryHunter.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ExecutionTimeAfter": {
        "description": "If specified only show executions after this time.",
        "format": "velociraptor-timestamp",
        "title": "ExecutionTimeAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "RecentAppsKey": {
        "description": "",
        "title": "RecentAppsKey",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\\*",
        "x-velociraptor-type": ""
      },
      "UserFilter": {
        "description": "If specified we filter by this user ID.",
        "format": "regex",
        "title": "UserFilter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "UserHomes": {
        "description": "",
        "title": "UserHomes",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\*\\NTUSER.DAT",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_039Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.RecentApps",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-053"></a>

### 053. `Windows.Forensics.RecycleBin`

功能描述（真实注册原文）：

Parses Recycle Bin `$I` metadata files to recover deleted file names,
original paths, and deletion timestamps.

Supports Recycle Bin format found in Vista onwards. This will not
parse INFO2 files found in the "Recycler" folder from XP and below.

The layout of the Recycle Bin folder is in the in the form:
```
  C:\$Recycle.Bin\%SID%\
```

Each folder contains the following files:
```
$R###### files; the original data
$I###### files; the "Recycled" file's metadata
```

The first file begins with the value `$R` followed by a random string
– "this file contains the actual contents of the recycled file"

The second file begins with `$I` and ends in the same string as the
`$R` file – this file contains the metadata for that specific file

Limitations: This artifact uses the OS API to read available $I
data. There may be additional unallocated-but-readable $I files
referenced in the MFT that may be recoverable.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Recycle Bin `$I` metadata files to recover deleted file names,\noriginal paths, and deletion timestamps.\n\nSupports Recycle Bin format found in Vista onwards. This will not\nparse INFO2 files found in the \"Recycler\" folder from XP and below.\n\nThe layout of the Recycle Bin folder is in the in the form:\n```\n  C:\\$Recycle.Bin\\%SID%\\\n```\n\nEach folder contains the following files:\n```\n$R###### files; the original data\n$I###### files; the \"Recycled\" file's metadata\n```\n\nThe first file begins with the value `$R` followed by a random string\n– \"this file contains the actual contents of the recycled file\"\n\nThe second file begins with `$I` and ends in the same string as the\n`$R` file – this file contains the metadata for that specific file\n\nLimitations: This artifact uses the OS API to read available $I\ndata. There may be additional unallocated-but-readable $I files\nreferenced in the MFT that may be recoverable.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "Also upload recovered files.",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "RecycleBinGlobs": {
        "description": "",
        "title": "RecycleBinGlobs",
        "type": "string",
        "x-velociraptor-default": "C:\\$Recycle.Bin\\**\\$I*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_040Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.RecycleBin",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-054"></a>

### 054. `Windows.Forensics.SAM.Enriched`

功能描述（真实注册原文）：

Extracts everything usefully derivable from the SAM registry hive

Whereas `Windows.Forensics.SAM` only returns users, this artifact
list groups, group memberships, machine SID and the systems' account
policy.

Sources:

- **Users**: every local user, like `Windows.Forensics.SAM`'s
  `Parsed` source, plus `PrimaryGroupID` and `IsLocalAdmin` (cross-
  referenced against the local `Administrators` group).
- **GroupMembers**: every local group's members, classified as a
  local account, a domain account, or a well-known SID.
- **Aliases**: every local group, without expanding membership.
- **Groups**: global groups (`SAM\Domains\Account\Groups`), only useful
  if on a domain controller.
- **MachineSID**: this machine's own account-domain SID, as a
  single row.
- **AccountPolicy**: password/lockout policy and the domain's own
  creation time, from `SAM\Domains\Account`.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts everything usefully derivable from the SAM registry hive\n\nWhereas `Windows.Forensics.SAM` only returns users, this artifact\nlist groups, group memberships, machine SID and the systems' account\npolicy.\n\nSources:\n\n- **Users**: every local user, like `Windows.Forensics.SAM`'s\n  `Parsed` source, plus `PrimaryGroupID` and `IsLocalAdmin` (cross-\n  referenced against the local `Administrators` group).\n- **GroupMembers**: every local group's members, classified as a\n  local account, a domain account, or a well-known SID.\n- **Aliases**: every local group, without expanding membership.\n- **Groups**: global groups (`SAM\\Domains\\Account\\Groups`), only useful\n  if on a domain controller.\n- **MachineSID**: this machine's own account-domain SID, as a\n  single row.\n- **AccountPolicy**: password/lockout policy and the domain's own\n  creation time, from `SAM\\Domains\\Account`.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "SAMPath": {
        "description": "Path to the SAM hive to parse.",
        "title": "SAMPath",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/System32/Config/SAM",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_041Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.SAM.Enriched",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-055"></a>

### 055. `Windows.Forensics.SRUM`

功能描述（真实注册原文）：

Parses the Windows SRUM database (srudb.dat) to extract execution
stats, resource usage, and network activity.

Update 2026-07-11:
Added optional SruDbIdMapTable to selection table.
We have found this table useful searching for binary name strings.
Added filters for ExecutableRegex, UserRegex and TimeStamp.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the Windows SRUM database (srudb.dat) to extract execution\nstats, resource usage, and network activity.\n\nUpdate 2026-07-11:  \nAdded optional SruDbIdMapTable to selection table. \nWe have found this table useful searching for binary name strings.   \nAdded filters for ExecutableRegex, UserRegex and TimeStamp.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ExecutableRegex": {
        "description": "Filter on application or binary name.\n",
        "title": "ExecutableRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "SRUMLocation": {
        "description": "",
        "title": "SRUMLocation",
        "type": "string",
        "x-velociraptor-default": "c:/windows/system32/sru/srudb.dat",
        "x-velociraptor-type": ""
      },
      "Tables": {
        "description": "SRUM tables to parse. The four original artifact sources are\nselected by default. Availability varies by Windows version.\n",
        "items": {
          "enum": [
            "Execution Stats",
            "Application Resource Usage",
            "Network Connections",
            "Network Usage",
            "SruDbIdMapTable"
          ],
          "type": "string"
        },
        "title": "Tables",
        "type": "array",
        "x-velociraptor-default": "[\"Execution Stats\", \"Application Resource Usage\", \"Network Connections\", \"Network Usage\"]",
        "x-velociraptor-type": "multichoice"
      },
      "TimeAfter": {
        "description": "search for TimeStamp after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "TimeAfter",
        "type": "string",
        "x-velociraptor-default": "1600-01-01",
        "x-velociraptor-type": "timestamp"
      },
      "TimeBefore": {
        "description": "search for TimeStamp before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "TimeBefore",
        "type": "string",
        "x-velociraptor-default": "2200-01-01",
        "x-velociraptor-type": "timestamp"
      },
      "Upload": {
        "description": "Select to Upload the SRUM database file 'srudb.dat'",
        "title": "Upload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UserRegex": {
        "description": "Filter on Username or UserSid\n",
        "format": "regex",
        "title": "UserRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "accessor": {
        "description": "",
        "title": "accessor",
        "type": "string",
        "x-velociraptor-default": "auto",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_042Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.SRUM",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-056"></a>

### 056. `Windows.Forensics.Shellbags`

功能描述（真实注册原文）：

Extracts Shellbag data from NTUSER.DAT and UsrClass.dat to recover
folder navigation history.

Windows uses the Shellbag keys to store user preferences for GUI
folder display within Windows Explorer.

This artifact uses the raw registry parser to inspect various user
registry hives around the filesystem for BagMRU keys. Different OS
versions may have slightly different locations for the MRU keys.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts Shellbag data from NTUSER.DAT and UsrClass.dat to recover\nfolder navigation history.\n\nWindows uses the Shellbag keys to store user preferences for GUI\nfolder display within Windows Explorer.\n\nThis artifact uses the raw registry parser to inspect various user\nregistry hives around the filesystem for BagMRU keys. Different OS\nversions may have slightly different locations for the MRU keys.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "SearchSpecs": {
        "description": "Define locations of MRU bags in various registries.",
        "format": "text/csv",
        "title": "SearchSpecs",
        "type": "string",
        "x-velociraptor-default": "HiveGlob,KeyGlob\nC:/Users/*/NTUSER.dat,\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\**\nC:/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat,\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\**\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_043Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Shellbags",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-057"></a>

### 057. `Windows.Forensics.Timeline`

功能描述（真实注册原文）：

Queries the Windows 10 Timeline ActivitiesCache.db SQLite database
to extract recently used applications.

Win10 records recently used applications and files in a "timeline"
accessible via the "WIN+TAB" key. The data is recorded in a SQLite
database.

**NOTES:**

This artifact is deprecated in favor of
`Generic.Forensic.SQLiteHunter` and will be removed in future.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Queries the Windows 10 Timeline ActivitiesCache.db SQLite database\nto extract recently used applications.\n\nWin10 records recently used applications and files in a \"timeline\"\naccessible via the \"WIN+TAB\" key. The data is recorded in a SQLite\ndatabase.\n\n**NOTES:**\n\nThis artifact is deprecated in favor of\n`Generic.Forensic.SQLiteHunter` and will be removed in future.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ExecutionTimeAfter": {
        "description": "If specified only show executions after this time.",
        "format": "velociraptor-timestamp",
        "title": "ExecutionTimeAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "UserFilter": {
        "description": "If specified we filter by this user ID.",
        "format": "regex",
        "title": "UserFilter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "Win10TimelineGlob": {
        "description": "",
        "title": "Win10TimelineGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_044Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Timeline",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-058"></a>

### 058. `Windows.Forensics.Usn`

功能描述（真实注册原文）：

Parses the NTFS USN journal ($J data stream) to enumerate recent
file creation, modification, and deletion events.

NTFS is a journaled filesystem. This means that it maintains a
journal file where intended filesystem changes are written first,
then the filesystem is changed. This journal is called the USN
journal in NTFS.

Velociraptor can parse the USN journal from the filesystem. This
provides an indication of recent file changes. Typically the system
maintains the journal of around 30mb and depending on system
activity this can go back quite some time.

Use this artifact to determine the times when a file was
modified/added from the journal. This will be present even if the
file was later removed.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the NTFS USN journal ($J data stream) to enumerate recent\nfile creation, modification, and deletion events.\n\nNTFS is a journaled filesystem. This means that it maintains a\njournal file where intended filesystem changes are written first,\nthen the filesystem is changed. This journal is called the USN\njournal in NTFS.\n\nVelociraptor can parse the USN journal from the filesystem. This\nprovides an indication of recent file changes. Typically the system\nmaintains the journal of around 30mb and depending on system\nactivity this can go back quite some time.\n\nUse this artifact to determine the times when a file was\nmodified/added from the journal. This will be present even if the\nfile was later removed.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Accessor": {
        "description": "The accessor to use.",
        "title": "Accessor",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "AllDrives": {
        "description": "Dump USN from all drives and VSC",
        "title": "AllDrives",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "Device": {
        "description": "The NTFS drive to parse",
        "title": "Device",
        "type": "string",
        "x-velociraptor-default": "C:\\",
        "x-velociraptor-type": ""
      },
      "FastPaths": {
        "description": "When set use a faster but less accurate path reassembly algorithm.",
        "title": "FastPaths",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "FileNameRegex": {
        "description": "A regex to match the Filename field.",
        "title": "FileNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "MFTFile": {
        "description": "Alternatively provide an MFTFile to use for resolving paths.",
        "title": "MFTFile",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "MFT_ID_Regex": {
        "description": "A regex to match the MFTId. e.g ^10225$ or ^(10225|232111)$",
        "format": "regex",
        "title": "MFT_ID_Regex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "Parent_MFT_ID_Regex": {
        "description": "A regex to match the MFTId. e.g ^10225$ or ^(10225|232111)$",
        "format": "regex",
        "title": "Parent_MFT_ID_Regex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "A regex to match the entire path (you can watch a directory or a file type).",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "USNFile": {
        "description": "Alternatively provide a previously extracted USN file to parse.",
        "title": "USNFile",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_045Arguments",
    "type": "object"
  },
  "name": "Windows.Forensics.Usn",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-059"></a>

### 059. `Windows.Memory.Acquisition`

功能描述（真实注册原文）：

Acquires a full memory image by using the built-in WinPmem driver.

NOTE: This artifact usually transfers a lot of data. You should
increase the default timeout to allow it to complete.

Memory images are typically susceptible to a lot of smear. To
minimize this we need to acquire memory as quickly as possible. This
artifact offers a few compression methods for the output
file. Reducing the size of the file will decrease time needed for IO
but will increase CPU requirements so this is a
trade-off. Empirically we found that using S2 compression gives a
reasonable compression and very high speed reducing acquisition time
from the no compression options significantly.

To decompress the image you can use the [Go WinPmem binary](https://github.com/Velocidex/WinPmem/releases)

```
go-winpmem.exe extract image.compressed image.raw
```

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Acquires a full memory image by using the built-in WinPmem driver.\n\nNOTE: This artifact usually transfers a lot of data. You should\nincrease the default timeout to allow it to complete.\n\nMemory images are typically susceptible to a lot of smear. To\nminimize this we need to acquire memory as quickly as possible. This\nartifact offers a few compression methods for the output\nfile. Reducing the size of the file will decrease time needed for IO\nbut will increase CPU requirements so this is a\ntrade-off. Empirically we found that using S2 compression gives a\nreasonable compression and very high speed reducing acquisition time\nfrom the no compression options significantly.\n\nTo decompress the image you can use the [Go WinPmem binary](https://github.com/Velocidex/WinPmem/releases)\n\n```\ngo-winpmem.exe extract image.compressed image.raw\n```\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Compression": {
        "description": "Type of compression to use (Recommended None, S2 or Snappy).",
        "enum": [
          "None",
          "S2",
          "Snappy",
          "Gzip"
        ],
        "title": "Compression",
        "type": "string",
        "x-velociraptor-default": "None",
        "x-velociraptor-type": "choices"
      },
      "DriverPath": {
        "description": "Where to unpack the driver before loading it.",
        "title": "DriverPath",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\Temp\\winpmem.sys",
        "x-velociraptor-type": ""
      },
      "ServiceName": {
        "description": "Override the name of the driver service to install.",
        "title": "ServiceName",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_046Arguments",
    "type": "object"
  },
  "name": "Windows.Memory.Acquisition",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-060"></a>

### 060. `Windows.Memory.PEDump`

功能描述（真实注册原文）：

Extracts running executables from process memory using VAD region
enumeration and PE dumping, and uploads the files to the server.

NOTE: The output is not exactly the same as the original binary:

1. Relocations are not fixed.

2. Due to ASLR the base address of the binary will not be the same
as the original.

The result is usually much better than the binaries dumped from a
physical memory image (using e.g. Volatility) because reading
process memory will page in any memory-mapped pages as we copy them
out. Therefore we do not expect to have holes in the produced binary
as is often the case in memory analysis.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts running executables from process memory using VAD region\nenumeration and PE dumping, and uploads the files to the server.\n\nNOTE: The output is not exactly the same as the original binary:\n\n1. Relocations are not fixed.\n\n2. Due to ASLR the base address of the binary will not be the same\nas the original.\n\nThe result is usually much better than the binaries dumped from a\nphysical memory image (using e.g. Volatility) because reading\nprocess memory will page in any memory-mapped pages as we copy them\nout. Therefore we do not expect to have holes in the produced binary\nas is often the case in memory analysis.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "BaseOffset": {
        "description": "The base offset to dump from memory. If not provided, we dump\nall pe files from the PID.\n",
        "title": "BaseOffset",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "FilenameRegex": {
        "description": "Applies to the PE mapping filename to upload",
        "title": "FilenameRegex",
        "type": "string",
        "x-velociraptor-default": ".+exe$",
        "x-velociraptor-type": ""
      },
      "Pid": {
        "description": "The pid to dump",
        "title": "Pid",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_047Arguments",
    "type": "object"
  },
  "name": "Windows.Memory.PEDump",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-061"></a>

### 061. `Windows.Memory.ProcessDump`

功能描述（真实注册原文）：

Captures process memory for selected processes via crash dump or
Velociraptor-compatible sparse upload.

NOTE: This artifact was previously named
`Windows.Triage.ProcessMemory`

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Captures process memory for selected processes via crash dump or\nVelociraptor-compatible sparse upload.\n\nNOTE: This artifact was previously named\n`Windows.Triage.ProcessMemory`\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": "notepad",
        "x-velociraptor-type": "regex"
      },
      "VelociraptorCompatible": {
        "description": "If specified we upload a Velociraptor Compatible sparse file\nupload instead of a crash dump. This makes it easier to run\npost-processing using Velociraptor\n",
        "title": "VelociraptorCompatible",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_048Arguments",
    "type": "object"
  },
  "name": "Windows.Memory.ProcessDump",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-062"></a>

### 062. `Windows.Memory.ProcessInfo`

功能描述（真实注册原文）：

Extracts process information by parsing the Process Environment
Block (PEB) directly for each running process.

This artifact was previously named `Windows.Forensics.ProcessInfo`.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts process information by parsing the Process Environment\nBlock (PEB) directly for each running process.\n\nThis artifact was previously named `Windows.Forensics.ProcessInfo`.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "CommandLineRegex": {
        "description": "",
        "format": "regex",
        "title": "CommandLineRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ImagePathRegex": {
        "description": "",
        "format": "regex",
        "title": "ImagePathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessNameRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_049Arguments",
    "type": "object"
  },
  "name": "Windows.Memory.ProcessInfo",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-063"></a>

### 063. `Windows.NTFS.ADSHunter`

功能描述（真实注册原文）：

Scans NTFS volumes for data hidden in Alternate Data Streams, using
configurable filtering rules.

Adversaries may use NTFS file attributes for covert storage to evade
detection. Alternate Data Streams (ADS) are additional $DATA
attributes for an MFT entry in NTFS file systems. In NTFS, the
primary $DATA attribute is never named but subsequent $DATA
attributes must be named.

Targeting is via mix of path globs and include/exclude regex.

- TargetGlob is a glob to target for ADS. NOTE **\* is recursive. To
  hit C drive we need to search for C:\*
- AdsName is name in glob format: e.g *, Zone.Identifier or Zone.*.
- AdsNameExclusion - A regex value, common ADS added to exclusions
  have been added by default. The artifact also excludes NTFS system
  files by default.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans NTFS volumes for data hidden in Alternate Data Streams, using\nconfigurable filtering rules.\n\nAdversaries may use NTFS file attributes for covert storage to evade\ndetection. Alternate Data Streams (ADS) are additional $DATA\nattributes for an MFT entry in NTFS file systems. In NTFS, the\nprimary $DATA attribute is never named but subsequent $DATA\nattributes must be named.\n\nTargeting is via mix of path globs and include/exclude regex.\n\n- TargetGlob is a glob to target for ADS. NOTE **\\* is recursive. To\n  hit C drive we need to search for C:\\*\n- AdsName is name in glob format: e.g *, Zone.Identifier or Zone.*.\n- AdsNameExclusion - A regex value, common ADS added to exclusions\n  have been added by default. The artifact also excludes NTFS system\n  files by default.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AdsContentExclusion": {
        "description": "ADS content to exclude by regex.",
        "format": "regex",
        "title": "AdsContentExclusion",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "AdsContentRegex": {
        "description": "ADS content to search for by regex.",
        "format": "regex",
        "title": "AdsContentRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "AdsNameExclusion": {
        "description": "Regex of ADS name to exclude.",
        "format": "regex",
        "title": "AdsNameExclusion",
        "type": "string",
        "x-velociraptor-default": "SmartScreen|WofCompressedData|encryptable|favicon|AFP_AfpInfo|OECustomProperty|Win32App_1|com\\.dropbox|icasource|\\{\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}\\}\\.(MetaData|SyncRootIdentity)",
        "x-velociraptor-type": "regex"
      },
      "AdsNameGlob": {
        "description": "AdsName in glob format. e.g *, Zone.Identifier or Zone.*",
        "title": "AdsNameGlob",
        "type": "string",
        "x-velociraptor-default": "*",
        "x-velociraptor-type": ""
      },
      "MaxSize": {
        "description": "Optional - only include alternate data streams below this size in bytes.",
        "title": "MaxSize",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "MinSize": {
        "description": "Optional - only include alternate data streams above this size in bytes.",
        "title": "MinSize",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "TargetGlob": {
        "description": "A Glob to search for target files. **\\* is recursive. To hit C drive we need to search for C:\\*",
        "title": "TargetGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\{*,**\\*}",
        "x-velociraptor-type": ""
      },
      "UploadDataStream": {
        "description": "If selected will upload non-resident data streams.",
        "title": "UploadDataStream",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_050Arguments",
    "type": "object"
  },
  "name": "Windows.NTFS.ADSHunter",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-064"></a>

### 064. `Windows.NTFS.ExtendedAttributes`

功能描述（真实注册原文）：

Parses NTFS Extended Attributes ($EA) from the MFT to detect hidden
data.

Adversaries may use NTFS file attributes for defense evasion to hide
malicious data. This artifact parses NTFS Extended attributes ($EA).
The artifact firstly queries the MFT, then enriches NTFS data to
check for Extended Attributes. Several filters can be applied such
as file search, Extended Attribute size, name or content.

NOTE: By default an EAName exclusion has been applied to filter.
Some common $EA names found on Windows System. Recommended hunt
would be by rare name or $EA size. By default we only parse $EA and
discard $EA_INFORMATION. $EA_INFORMATION typically is very small and
available in NtfsMetadata field of output.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses NTFS Extended Attributes ($EA) from the MFT to detect hidden\ndata.\n\nAdversaries may use NTFS file attributes for defense evasion to hide\nmalicious data. This artifact parses NTFS Extended attributes ($EA).\nThe artifact firstly queries the MFT, then enriches NTFS data to\ncheck for Extended Attributes. Several filters can be applied such\nas file search, Extended Attribute size, name or content.\n\nNOTE: By default an EAName exclusion has been applied to filter.\nSome common $EA names found on Windows System. Recommended hunt\nwould be by rare name or $EA size. By default we only parse $EA and\ndiscard $EA_INFORMATION. $EA_INFORMATION typically is very small and\navailable in NtfsMetadata field of output.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AllDrives": {
        "description": "Select MFT search on all attached ntfs drives.",
        "title": "AllDrives",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DateAfter": {
        "description": "search for host files with timestamps after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for  host files with timestamps before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EAContentRegex": {
        "description": "$EA content to search for by regex.",
        "format": "regex",
        "title": "EAContentRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "EANameExclusion": {
        "description": "Regex of ADS name to exclude.",
        "format": "regex",
        "title": "EANameExclusion",
        "type": "string",
        "x-velociraptor-default": "^(\\$KERNEL\\.PURGE\\.(ESBCACHE|APPXFICACHE)|\\$CI\\.CATALOGHINT|\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}\\.CSC\\.\\w+)$",
        "x-velociraptor-type": "regex"
      },
      "EANameRegex": {
        "description": "$EA Name regex filter to include in results.",
        "format": "regex",
        "title": "EANameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "HostPathRegex": {
        "description": "Regex search over OSPath.",
        "format": "regex",
        "title": "HostPathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "MFTDrive": {
        "description": "",
        "title": "MFTDrive",
        "type": "string",
        "x-velociraptor-default": "C:",
        "x-velociraptor-type": ""
      },
      "SizeMax": {
        "description": "Total $EA attributes in the MFT under this size in bytes.",
        "title": "SizeMax",
        "type": "integer",
        "x-velociraptor-default": "100000",
        "x-velociraptor-type": "int64"
      },
      "SizeMin": {
        "description": "Total $EA attributes in the MFT over this size in bytes.",
        "title": "SizeMin",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int64"
      },
      "UploadHits": {
        "description": "Upload complete attribute data.",
        "title": "UploadHits",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_051Arguments",
    "type": "object"
  },
  "name": "Windows.NTFS.ExtendedAttributes",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-065"></a>

### 065. `Windows.NTFS.I30`

功能描述（真实注册原文）：

Carves the $I30 index stream from NTFS directories to recover
previously deleted file entries, and optionally upload the $I30
stream to the server

This can reveal previously deleted files.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Carves the $I30 index stream from NTFS directories to recover\npreviously deleted file entries, and optionally upload the $I30\nstream to the server\n\nThis can reveal previously deleted files.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "Select to also upload the raw $I30 stream.",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DirectoryGlobs": {
        "description": "",
        "title": "DirectoryGlobs",
        "type": "string",
        "x-velociraptor-default": "C:\\Users\\*",
        "x-velociraptor-type": ""
      },
      "SlackOnly": {
        "description": "Select to return only entries from Slack space.",
        "title": "SlackOnly",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_052Arguments",
    "type": "object"
  },
  "name": "Windows.NTFS.I30",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-066"></a>

### 066. `Windows.NTFS.MFT`

功能描述（真实注册原文）：

Parses $MFT files and returns rows of each in-scope MFT record.

This artifact can be used as the basis for other artifacts where the
MFT needs to be queried or for deleted file recovery.

For deleted file recovery: Take the MFT ID of a file of interest and
provide it to the Windows.NTFS.Recover artifact.

To query all attached NTFS drives: select the AllDrives option.

Due to the multi-drive features, the MFTPath will output the MFT
path of the entry.

Available filters include:

- PathRegex (OSPath): e.g `^C:\\folder\\file\.ext$` or partial `\\folder\\folder2\\` or `string|string2|string3`
- Fileregex: `^filename.ext$` or partial `string1|string2`
- Time bounds to select files with a timestamp within time ranges
- FileSize bounds
- MFTDrive: drive to target collection and show as source in results during offline processing.
- MFTPath: optional filter for offline MFT processing.

**NOTES**

- It is generally more efficient to filter on filename.
- Multiple filters are cumulative.
- OSPath output now uses expected Windows backslash "`\`".

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses $MFT files and returns rows of each in-scope MFT record.\n\nThis artifact can be used as the basis for other artifacts where the\nMFT needs to be queried or for deleted file recovery.\n\nFor deleted file recovery: Take the MFT ID of a file of interest and\nprovide it to the Windows.NTFS.Recover artifact.\n\nTo query all attached NTFS drives: select the AllDrives option.\n\nDue to the multi-drive features, the MFTPath will output the MFT\npath of the entry.\n\nAvailable filters include:\n\n- PathRegex (OSPath): e.g `^C:\\\\folder\\\\file\\.ext$` or partial `\\\\folder\\\\folder2\\\\` or `string|string2|string3`\n- Fileregex: `^filename.ext$` or partial `string1|string2`\n- Time bounds to select files with a timestamp within time ranges\n- FileSize bounds\n- MFTDrive: drive to target collection and show as source in results during offline processing.\n- MFTPath: optional filter for offline MFT processing.\n\n**NOTES**\n\n- It is generally more efficient to filter on filename.\n- Multiple filters are cumulative.\n- OSPath output now uses expected Windows backslash \"`\\`\".\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Accessor": {
        "description": "",
        "title": "Accessor",
        "type": "string",
        "x-velociraptor-default": "ntfs",
        "x-velociraptor-type": ""
      },
      "AllDrives": {
        "description": "Select MFT search on all attached ntfs drives.",
        "title": "AllDrives",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "AllNtfs": {
        "description": "Return all NTFS metadata with results.",
        "title": "AllNtfs",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "FileRegex": {
        "description": "Regex search over File Name",
        "format": "regex",
        "title": "FileRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "MFTDrive": {
        "description": "The path to the drive that holds the MFT file (can be a pathspec). This\ndrive is also used for results for offline processing.\n",
        "title": "MFTDrive",
        "type": "string",
        "x-velociraptor-default": "C:",
        "x-velociraptor-type": ""
      },
      "MFTPath": {
        "description": "Optional path to MFT file for offline processing.",
        "title": "MFTPath",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "NTFS_INCLUDE_SHORT_NAMES": {
        "description": "See all names referencing the file including short names.",
        "title": "NTFS_INCLUDE_SHORT_NAMES",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "PathRegex": {
        "description": "Regex search over OSPath.",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "SizeMax": {
        "description": "Entries in the MFT under this size in bytes.",
        "title": "SizeMax",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int64"
      },
      "SizeMin": {
        "description": "Entries in the MFT over this size in bytes.",
        "title": "SizeMin",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int64"
      }
    },
    "title": "dynamic_artifact_053Arguments",
    "type": "object"
  },
  "name": "Windows.NTFS.MFT",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-067"></a>

### 067. `Windows.NTFS.Recover`

功能描述（真实注册原文）：

Uploads all data streams from a specified MFT ID on an NTFS volume
for deleted file recovery purposes.

If the MFT entry is not allocated there is a chance that the cluster
that contains the actual data of the file will still be intact on
the disk. Therefore it may be possible to recover such deleted
files, which is what this artifact attempts to do.

A common use case is to recover deleted directory entries using the
`Windows.NTFS.I30` artifact first to identify MFT entries of
interest. This artifact can then be used to attempt recovery of the
file data.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Uploads all data streams from a specified MFT ID on an NTFS volume\nfor deleted file recovery purposes.\n\nIf the MFT entry is not allocated there is a chance that the cluster\nthat contains the actual data of the file will still be intact on\nthe disk. Therefore it may be possible to recover such deleted\nfiles, which is what this artifact attempts to do.\n\nA common use case is to recover deleted directory entries using the\n`Windows.NTFS.I30` artifact first to identify MFT entries of\ninterest. This artifact can then be used to attempt recovery of the\nfile data.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Drive": {
        "description": "",
        "title": "Drive",
        "type": "string",
        "x-velociraptor-default": "\\\\.\\C:",
        "x-velociraptor-type": ""
      },
      "MFTId": {
        "description": "",
        "title": "MFTId",
        "type": "string",
        "x-velociraptor-default": "81978",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_054Arguments",
    "type": "object"
  },
  "name": "Windows.NTFS.Recover",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-068"></a>

### 068. `Windows.Network.ArpCache`

功能描述（真实注册原文）：

Enumerates the Windows network neighbor cache (ARP/NDP) showing
resolved IP and MAC address pairs.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates the Windows network neighbor cache (ARP/NDP) showing\nresolved IP and MAC address pairs.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "kMapOfState": {
        "description": "",
        "title": "kMapOfState",
        "type": "string",
        "x-velociraptor-default": "{\n \"0\": \"Unreachable\",\n \"1\": \"Incomplete\",\n \"2\": \"Probe\",\n \"3\": \"Delay\",\n \"4\": \"Stale\",\n \"5\": \"Reachable\",\n \"6\": \"Permanent\",\n \"7\": \"TBD\"\n}\n",
        "x-velociraptor-type": ""
      },
      "wmiNamespace": {
        "description": "",
        "title": "wmiNamespace",
        "type": "string",
        "x-velociraptor-default": "ROOT\\StandardCimv2",
        "x-velociraptor-type": ""
      },
      "wmiQuery": {
        "description": "",
        "title": "wmiQuery",
        "type": "string",
        "x-velociraptor-default": "SELECT AddressFamily, Store, State, InterfaceIndex, IPAddress,\n       InterfaceAlias, LinkLayerAddress\nfrom MSFT_NetNeighbor\n",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_055Arguments",
    "type": "object"
  },
  "name": "Windows.Network.ArpCache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-069"></a>

### 069. `Windows.Network.ListeningPorts`

功能描述（真实注册原文）：

Reports processes that have open listening ports with address,
protocol, and PID details.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Reports processes that have open listening ports with address,\nprotocol, and PID details.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_056Arguments",
    "type": "object"
  },
  "name": "Windows.Network.ListeningPorts",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-070"></a>

### 070. `Windows.Network.Netstat`

功能描述（真实注册原文）：

Reports open network sockets on Windows including binding time,
connection state, and owning process name.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Reports open network sockets on Windows including binding time,\nconnection state, and owning process name.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_057Arguments",
    "type": "object"
  },
  "name": "Windows.Network.Netstat",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-071"></a>

### 071. `Windows.Network.NetstatEnriched`

功能描述（真实注册原文）：

NetstatEnriched adds data enrichment to the Netstat artifact and
provides extensive filtering options.

Examples include: Process name and path, Authenticode information or
network connection details.

WARNING:
KillProcess - attempts to kill the processes returned.
DumpProcess - dumps the process as a sparse file for post-processing.

Please only use these switches after scoping as there are no
guardrails on shooting yourself in the foot.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "NetstatEnriched adds data enrichment to the Netstat artifact and\nprovides extensive filtering options.\n\nExamples include: Process name and path, Authenticode information or\nnetwork connection details.\n\nWARNING:\nKillProcess - attempts to kill the processes returned.\nDumpProcess - dumps the process as a sparse file for post-processing.\n\nPlease only use these switches after scoping as there are no\nguardrails on shooting yourself in the foot.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AuthenticodeIssuerRegex": {
        "description": "regex search over source Authenticode Issuer",
        "format": "regex",
        "title": "AuthenticodeIssuerRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "AuthenticodeSubjectRegex": {
        "description": "regex search over source Authenticode Subject",
        "format": "regex",
        "title": "AuthenticodeSubjectRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "AuthenticodeVerified": {
        "description": "Authenticode signature selection",
        "enum": [
          "ALL",
          "TRUSTED",
          "UNSIGNED",
          "NOT TRUSTED"
        ],
        "title": "AuthenticodeVerified",
        "type": "string",
        "x-velociraptor-default": "ALL",
        "x-velociraptor-type": "choices"
      },
      "CommandLineRegex": {
        "description": "regex search over source process commandline",
        "format": "regex",
        "title": "CommandLineRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DumpProcess": {
        "description": "WARNING: If selected will attempt to dump process from all results.",
        "title": "DumpProcess",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Family": {
        "description": "IP version family selection",
        "enum": [
          "ALL",
          "IPv4",
          "IPv6"
        ],
        "title": "Family",
        "type": "string",
        "x-velociraptor-default": "ALL",
        "x-velociraptor-type": "choices"
      },
      "HashRegex": {
        "description": "regex search over source process hash",
        "format": "regex",
        "title": "HashRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "IPRegex": {
        "description": "regex search over IP address fields.",
        "format": "regex",
        "title": "IPRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "KillProcess": {
        "description": "WARNING: If selected will attempt to kill process from all results.",
        "title": "KillProcess",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "PortRegex": {
        "description": "regex search over port fields.",
        "format": "regex",
        "title": "PortRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessNameRegex": {
        "description": "regex search over source process name",
        "format": "regex",
        "title": "ProcessNameRegex",
        "type": "string",
        "x-velociraptor-default": "^(malware\\.exe|.*)$",
        "x-velociraptor-type": "regex"
      },
      "ProcessPathRegex": {
        "description": "regex search over source process path",
        "format": "regex",
        "title": "ProcessPathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "Status": {
        "description": "TCP status selection",
        "enum": [
          "ALL",
          "ESTABLISHED",
          "LISTENING",
          "OTHER"
        ],
        "title": "Status",
        "type": "string",
        "x-velociraptor-default": "ALL",
        "x-velociraptor-type": "choices"
      },
      "Type": {
        "description": "Transport protocol type selection",
        "enum": [
          "ALL",
          "TCP",
          "UDP"
        ],
        "title": "Type",
        "type": "string",
        "x-velociraptor-default": "ALL",
        "x-velociraptor-type": "choices"
      },
      "UsernameRegex": {
        "description": "regex search over source process user context",
        "format": "regex",
        "title": "UsernameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_058Arguments",
    "type": "object"
  },
  "name": "Windows.Network.NetstatEnriched",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-072"></a>

### 072. `Windows.Network.PacketCapture`

功能描述（真实注册原文）：

Captures network packets on Windows using netsh trace and then
converts these ETL traces to PCAP format.

Run this artifact twice, the first time, set the StartTrace flag to
True to start the PCAP collection, this will have the VQL return a
single row (the TraceFile generated) When you want to stop
collecting, and transform this TraceFile to a PCAP, re-run this
artifact with StartTrace as false, and put path of the .etl file
created in the previous step in the TraceFile. This will then
convert the .etl to a PCAP and upload it.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Captures network packets on Windows using netsh trace and then\nconverts these ETL traces to PCAP format.\n\nRun this artifact twice, the first time, set the StartTrace flag to\nTrue to start the PCAP collection, this will have the VQL return a\nsingle row (the TraceFile generated) When you want to stop\ncollecting, and transform this TraceFile to a PCAP, re-run this\nartifact with StartTrace as false, and put path of the .etl file\ncreated in the previous step in the TraceFile. This will then\nconvert the .etl to a PCAP and upload it.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "StartTrace": {
        "description": "",
        "title": "StartTrace",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "TraceFile": {
        "description": "",
        "title": "TraceFile",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "string"
      }
    },
    "title": "dynamic_artifact_059Arguments",
    "type": "object"
  },
  "name": "Windows.Network.PacketCapture",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-073"></a>

### 073. `Windows.Packs.Persistence`

功能描述（真实注册原文）：

Aggregates results from multiple persistence-related artifacts into
a single artifact "pack".

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Aggregates results from multiple persistence-related artifacts into\na single artifact \"pack\".\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_060Arguments",
    "type": "object"
  },
  "name": "Windows.Packs.Persistence",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-074"></a>

### 074. `Windows.Persistence.Debug`

功能描述（真实注册原文）：

Detects programs with a debugger configured in Image File Execution
Options registry keys.

Windows allows specific configuration of various executables via a
registry key. Some keys allow defining a debugger to attach to a
program as it is run. If this debugger is launched for commonly used
programs (e.g. notepad) then another program can be launched at the
same time (with the same privileges).

There is an additional key for x86 executables `HKEY_LOCAL_MACHINE\
SOFTWARE\wow6432node\Microsoft\Windows NT\CurrentVersion\Image File
Execution Options\*` however this is kept inline with the x64 key and
therefore does not need to be processed.

Limitations: This queries the live registry and therefore does not
parse data in `Windows.old` or `Regback` folders, or VSS.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Detects programs with a debugger configured in Image File Execution\nOptions registry keys.\n\nWindows allows specific configuration of various executables via a\nregistry key. Some keys allow defining a debugger to attach to a\nprogram as it is run. If this debugger is launched for commonly used\nprograms (e.g. notepad) then another program can be launched at the\nsame time (with the same privileges).\n\nThere is an additional key for x86 executables `HKEY_LOCAL_MACHINE\\\nSOFTWARE\\wow6432node\\Microsoft\\Windows NT\\CurrentVersion\\Image File\nExecution Options\\*` however this is kept inline with the x64 key and\ntherefore does not need to be processed.\n\nLimitations: This queries the live registry and therefore does not\nparse data in `Windows.old` or `Regback` folders, or VSS.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "imageFileExecutionOptions": {
        "description": "",
        "title": "imageFileExecutionOptions",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_061Arguments",
    "type": "object"
  },
  "name": "Windows.Persistence.Debug",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-075"></a>

### 075. `Windows.Persistence.PermanentWMIEvents`

功能描述（真实注册原文）：

Enumerates permanent WMI event subscriptions including filters,
consumers, and their bindings across namespaces.

The artifact collects Binding information, then presents associated
Filters and Consumers.

NOTE: the artifact does not report on individual eventing classes. A
separate WMI query will need to be made for unlinked components that
may reside in the WMI datastore.

WMI Eventing components:

- __FilterToConsumerBinding - ties together Filter + Consumer
- __EventFilter - trigger condition
- __EventConsumer - payload

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates permanent WMI event subscriptions including filters,\nconsumers, and their bindings across namespaces.\n\nThe artifact collects Binding information, then presents associated\nFilters and Consumers.\n\nNOTE: the artifact does not report on individual eventing classes. A\nseparate WMI query will need to be made for unlinked components that\nmay reside in the WMI datastore.\n\nWMI Eventing components:\n\n- __FilterToConsumerBinding - ties together Filter + Consumer\n- __EventFilter - trigger condition\n- __EventConsumer - payload\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AllRootNamespaces": {
        "description": "Select to scan all ROOT namespaces. This setting over rides specific namespaces configured below.",
        "title": "AllRootNamespaces",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Namespaces": {
        "description": "Add a list of target namespaces.",
        "format": "text/csv",
        "title": "Namespaces",
        "type": "string",
        "x-velociraptor-default": "namespace\nroot/subscription\nroot/default\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_062Arguments",
    "type": "object"
  },
  "name": "Windows.Persistence.PermanentWMIEvents",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-076"></a>

### 076. `Windows.Persistence.PowershellProfile`

功能描述（真实注册原文）：

Searches for and parses PowerShell profile scripts across user and
system directories for persistence detection.

PowerShell supports several profiles depending on the user or host
program. Adversaries may create or modify these profiles to include
arbitrary commands, functions, modules, and/or PowerShell drives to
gain persistence. When a backdoored PowerShell session is opened the
modified script will be executed unless the -NoProfile flag is used
when it is launched.

The artifact will by default search both User profiles and
System-wide configured profiles. The user can also target and
exclude specific content with relevant regex filters.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches for and parses PowerShell profile scripts across user and\nsystem directories for persistence detection.\n\nPowerShell supports several profiles depending on the user or host\nprogram. Adversaries may create or modify these profiles to include\narbitrary commands, functions, modules, and/or PowerShell drives to\ngain persistence. When a backdoored PowerShell session is opened the\nmodified script will be executed unless the -NoProfile flag is used\nwhen it is launched.\n\nThe artifact will by default search both User profiles and\nSystem-wide configured profiles. The user can also target and\nexclude specific content with relevant regex filters.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "PSHomeProfileGlob": {
        "description": "Glob for PowerShell PSHome profiles.",
        "title": "PSHomeProfileGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\{WindowsPowerShell,Powershell}\\v1.0\\{Profile,Microsoft.*_profile}.ps1",
        "x-velociraptor-type": ""
      },
      "SearchStrings": {
        "description": "regex to filter for in profile content",
        "format": "regex",
        "title": "SearchStrings",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "StringWhiteList": {
        "description": "regex to filter out in profile content",
        "format": "regex",
        "title": "StringWhiteList",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "UserProfileGlob": {
        "description": "Glob for PowerShell user profiles.",
        "title": "UserProfileGlob",
        "type": "string",
        "x-velociraptor-default": "\\Documents\\{WindowsPowerShell,Powershell}\\{Profile,Microsoft.*_profile}.ps1",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_063Arguments",
    "type": "object"
  },
  "name": "Windows.Persistence.PowershellProfile",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-077"></a>

### 077. `Windows.Persistence.PowershellRegistry`

功能描述（真实注册原文）：

Scans NTUSER.DAT registry hives with YARA rules for PowerShell-based
persistence signatures.

A common method of persistence is to install a hook into a user
profile registry hive, using PowerShell. When the user logs in, the
PowerShell script downloads a payload and executes it.

This artifact searches the user's profile registry hive for
signatures related to general PowerShell execution. We use a YARA
signature specifically targeting the user's profile which we extract
by using raw NTFS parsing (in case the user is currently logged on
and the registry hive is locked).

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans NTUSER.DAT registry hives with YARA rules for PowerShell-based\npersistence signatures.\n\nA common method of persistence is to install a hook into a user\nprofile registry hive, using PowerShell. When the user logs in, the\nPowerShell script downloads a payload and executes it.\n\nThis artifact searches the user's profile registry hive for\nsignatures related to general PowerShell execution. We use a YARA\nsignature specifically targeting the user's profile which we extract\nby using raw NTFS parsing (in case the user is currently logged on\nand the registry hive is locked).\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "yaraRule": {
        "description": "",
        "format": "yara",
        "title": "yaraRule",
        "type": "string",
        "x-velociraptor-default": "rule PowerShell {\n  strings:\n    $a = /ActiveXObject.{,500}eval/ wide nocase\n\n  condition:\n    any of them\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_064Arguments",
    "type": "object"
  },
  "name": "Windows.Persistence.PowershellRegistry",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-078"></a>

### 078. `Windows.Persistence.Wow64cpu`

功能描述（真实注册原文）：

Checks for wow64cpu.dll replacement Autorun in Windows 10.
http://www.hexacorn.com/blog/2019/07/11/beyond-good-ol-run-key-part-108-2/

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Checks for wow64cpu.dll replacement Autorun in Windows 10.\nhttp://www.hexacorn.com/blog/2019/07/11/beyond-good-ol-run-key-part-108-2/\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "TargetRegKey": {
        "description": "",
        "title": "TargetRegKey",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Wow64\\**",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_065Arguments",
    "type": "object"
  },
  "name": "Windows.Persistence.Wow64cpu",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-079"></a>

### 079. `Windows.Registry.AppCompatCache`

功能描述（真实注册原文）：

Parses the AppCompatCache (Shimcache) registry value to enumerate
recently executed application paths.

AppCompatCache, also known as Shimcache, is a component of the
Application Compatibility Database, which was created by Microsoft
and used by the Windows operating system to identify application
compatibility issues. This helps developers troubleshoot legacy
functions and contains data related to Windows features.

**NOTES:**

- Windows 10+ systems Execution flag of 1 indicates execution.
- The appcompatcache artifact does not currently support execution
  flag in Windows 7 and 8 / 8.1 Systems.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the AppCompatCache (Shimcache) registry value to enumerate\nrecently executed application paths.\n\nAppCompatCache, also known as Shimcache, is a component of the\nApplication Compatibility Database, which was created by Microsoft\nand used by the Windows operating system to identify application\ncompatibility issues. This helps developers troubleshoot legacy\nfunctions and contains data related to Windows features.\n\n**NOTES:**\n\n- Windows 10+ systems Execution flag of 1 indicates execution.\n- The appcompatcache artifact does not currently support execution\n  flag in Windows 7 and 8 / 8.1 Systems.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AppCompatCacheKey": {
        "description": "",
        "title": "AppCompatCacheKey",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE/System/ControlSet*/Control/Session Manager/AppCompatCache/AppCompatCache",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_066Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.AppCompatCache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-080"></a>

### 080. `Windows.Registry.BackupRestore`

功能描述（真实注册原文）：

Enumerates Windows BackupRestore registry keys showing
applications configured for backup and restore operations.

Applications that request or perform backup and restore operations
can use these keys to communicate with each other or with features
such as the Volume Shadow Copy Service (VSS) and Windows Backup.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows BackupRestore registry keys showing\napplications configured for backup and restore operations.\n\nApplications that request or perform backup and restore operations\ncan use these keys to communicate with each other or with features\nsuch as the Volume Shadow Copy Service (VSS) and Windows Backup.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SYSTEM\\*ControlSet*\\Control\\BackupRestore\\**",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_067Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.BackupRestore",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-081"></a>

### 081. `Windows.Registry.EnableUnsafeClientMailRules`

功能描述（真实注册原文）：

Checks Outlook Security registry for EnableUnsafeClientMailRules set
to 1 (enabled), indicating potential persistence.

This registry key enables execution from Outlook inbox rules which
can be used as a persistence mechanism. Microsoft has released a
patch to disable execution but attackers can reenable it by changing
this value to 1.

HKEY_USERS\*\Software\Microsoft\Office\*\Outlook\Security\EnableUnsafeClientMailRules
= 0 (expected)

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Checks Outlook Security registry for EnableUnsafeClientMailRules set\nto 1 (enabled), indicating potential persistence.\n\nThis registry key enables execution from Outlook inbox rules which\ncan be used as a persistence mechanism. Microsoft has released a\npatch to disable execution but attackers can reenable it by changing\nthis value to 1.\n\nHKEY_USERS\\*\\Software\\Microsoft\\Office\\*\\Outlook\\Security\\EnableUnsafeClientMailRules\n= 0 (expected)\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Office\\*\\Outlook\\Security\\",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_068Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.EnableUnsafeClientMailRules",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-082"></a>

### 082. `Windows.Registry.EnabledMacro`

功能描述（真实注册原文）：

Scans Office Trust Records registry entries for documents with
macro-enabled trust flags.

That is `HKEY_USERS\*\Software\Microsoft\Office\*\Security\Trusted
Documents\TrustRecords` reg keys with values ending in `FFFFFF7F`.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans Office Trust Records registry entries for documents with\nmacro-enabled trust flags.\n\nThat is `HKEY_USERS\\*\\Software\\Microsoft\\Office\\*\\Security\\Trusted\nDocuments\\TrustRecords` reg keys with values ending in `FFFFFF7F`.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Office\\*\\*\\Security\\Trusted Documents\\TrustRecords\\*",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_069Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.EnabledMacro",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-083"></a>

### 083. `Windows.Registry.NTUser`

功能描述（真实注册原文）：

Searches for registry keys and values across all users' NTUSER.DAT
hives using raw NTFS parsing.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked while the user is logged
in. If the user is not logged in, the file is not mapped at all.

This artifact bypasses the locking mechanism by parsing the raw NTFS
filesystem to recover the registry hives. We then parse the registry
hives to search for the glob provided.

This artifact is designed to be reused by other artifacts that need
to access user data.

**NOTE:** Any artifacts that look into the HKEY_USERS registry hive
should be using the `Windows.Registry.NTUser` artifact instead of
accessing the hive via the API. The API only makes the currently
logged in users available in that hive, so if we rely on the windows
API we will miss any settings for the users not currently logged on.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches for registry keys and values across all users' NTUSER.DAT\nhives using raw NTFS parsing.\n\nWhen a user logs into a windows machine the system creates their own\n\"profile\" which consists of a registry hive mapped into the\nHKEY_USERS hive. This hive file is locked while the user is logged\nin. If the user is not logged in, the file is not mapped at all.\n\nThis artifact bypasses the locking mechanism by parsing the raw NTFS\nfilesystem to recover the registry hives. We then parse the registry\nhives to search for the glob provided.\n\nThis artifact is designed to be reused by other artifacts that need\nto access user data.\n\n**NOTE:** Any artifacts that look into the HKEY_USERS registry hive\nshould be using the `Windows.Registry.NTUser` artifact instead of\naccessing the hive via the API. The API only makes the currently\nlogged in users available in that hive, so if we rely on the windows\nAPI we will miss any settings for the users not currently logged on.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\**",
        "x-velociraptor-type": ""
      },
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_070Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.NTUser",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-084"></a>

### 084. `Windows.Registry.NTUser.Upload`

功能描述（真实注册原文）：

Uploads each user's NTUSER.DAT registry hive from disk by bypassing
file locking with raw NTFS parsing.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked while the user is logged
in.

This artifact bypasses the OS file-locking mechanism by extracting
the registry hives using raw NTFS parsing. We then just upload all
hives to the server.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Uploads each user's NTUSER.DAT registry hive from disk by bypassing\nfile locking with raw NTFS parsing.\n\nWhen a user logs into a windows machine the system creates their own\n\"profile\" which consists of a registry hive mapped into the\nHKEY_USERS hive. This hive file is locked while the user is logged\nin.\n\nThis artifact bypasses the OS file-locking mechanism by extracting\nthe registry hives using raw NTFS parsing. We then just upload all\nhives to the server.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "userRegex": {
        "description": "",
        "format": "regex",
        "title": "userRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_071Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.NTUser.Upload",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-085"></a>

### 085. `Windows.Registry.PortProxy`

功能描述（真实注册原文）：

Enumerates Windows port proxy registry entries configured via
netsh or attack tools for network redirection.

This artifact will return any items in the Windows PortProxy service
registry path. The most common configuration of this service is via
the LOLBin `netsh.exe`. Metasploit and other common attack tools
also have related configuration modules.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows port proxy registry entries configured via\nnetsh or attack tools for network redirection.\n\nThis artifact will return any items in the Windows PortProxy service\nregistry path. The most common configuration of this service is via\nthe LOLBin `netsh.exe`. Metasploit and other common attack tools\nalso have related configuration modules.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SYSTEM\\*ControlSet*\\services\\PortProxy\\**",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_072Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.PortProxy",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-086"></a>

### 086. `Windows.Registry.RDP`

功能描述（真实注册原文）：

Extracts historical RDP connection server names and MRU entries from
each user's NTUSER.DAT registry hive.

1. Servers - list of all RDP connections that have ever been established by
this user.
  - UsernameHint shows the username used to connect to the RDP/RDS host.
  - CertHash variable contains the RDP server SSL certificate thumbprint.

2. MRU 10 - Most recently used RDP connections

UserRegex and SidRegex can be used to target a specific user.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts historical RDP connection server names and MRU entries from\neach user's NTUSER.DAT registry hive.\n\n1. Servers - list of all RDP connections that have ever been established by \nthis user.   \n  - UsernameHint shows the username used to connect to the RDP/RDS host.  \n  - CertHash variable contains the RDP server SSL certificate thumbprint.\n\n2. MRU 10 - Most recently used RDP connections \n\nUserRegex and SidRegex can be used to target a specific user.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "KeyGlob": {
        "description": "",
        "title": "KeyGlob",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Terminal Server Client\\{Default,Servers}\\**",
        "x-velociraptor-type": ""
      },
      "SidRegex": {
        "description": "Regex filter to select a target SID",
        "format": "regex",
        "title": "SidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "UserRegex": {
        "description": "Regex filter to select a target username",
        "format": "regex",
        "title": "UserRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_073Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.RDP",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-087"></a>

### 087. `Windows.Registry.RecentDocs`

功能描述（真实注册原文）：

Extracts Recent Documents MRU entries from Windows NTUSER.DAT
registry hives for each user.

By default the artifact will target all users on the machine when
run in live mode but can be targeted directly using the HiveGlob
parameter.

Output includes LastWriteTime of key and a list of MRU items in the
order specified in the MRUListEx key value.
MruEntries has the format: [KeyName] := [Parsed Key value]

Available filters include:

- Time bounds to select LastWrite timestamp within time ranges.
- EntryRegex to target specific entry values
- UserRegex to target specific users. Note: this filter does not work
  when using HiveGlob.
- SidRegex to target a specific SID.

Note: both UserRegex and SidRegex does not work when using HiveGlob
and all MRU will be returned.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts Recent Documents MRU entries from Windows NTUSER.DAT\nregistry hives for each user.\n\nBy default the artifact will target all users on the machine when\nrun in live mode but can be targeted directly using the HiveGlob\nparameter.\n\nOutput includes LastWriteTime of key and a list of MRU items in the\norder specified in the MRUListEx key value.\nMruEntries has the format: [KeyName] := [Parsed Key value]\n\nAvailable filters include:\n\n- Time bounds to select LastWrite timestamp within time ranges.\n- EntryRegex to target specific entry values\n- UserRegex to target specific users. Note: this filter does not work\n  when using HiveGlob.\n- SidRegex to target a specific SID.\n\nNote: both UserRegex and SidRegex does not work when using HiveGlob\nand all MRU will be returned.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EntryRegex": {
        "description": "regex filter for document/entry name.",
        "title": "EntryRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "HiveGlob": {
        "description": "optional hive glob to target for offline processing.",
        "title": "HiveGlob",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "SidRegex": {
        "description": "regex filter for user SID over standard query.",
        "title": "SidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "UserRegex": {
        "description": "regex filter for username over standard query.",
        "title": "UserRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_074Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.RecentDocs",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-088"></a>

### 088. `Windows.Registry.UserAssist`

功能描述（真实注册原文）：

Decodes UserAssist registry keys from NTUSER.DAT to reveal program
execution counts and last run times.

Windows systems maintain a set of keys in the registry database
(UserAssist keys) to keep track of programs that executed. The
number of executions and last execution date and time are available
in these keys.

The information within the binary UserAssist values contains only
statistical data on the applications launched by the user via
Windows Explorer. Programs launched via the command­line (cmd.exe)
do not appear in these registry keys.

From a forensics perspective, being able to decode this information
can be very useful.

**Limitations:** Additional data not parsed by Velociraptor is the
FocusTime and FocusCount however these are not reliable. Also please
note that some methods of viewing an executable will update the
associated UserAssist key, and some methods of accessing an
executable will not update the execution counter or time. Therefore
there may be some executions that have a 0 time and 0 runcount.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Decodes UserAssist registry keys from NTUSER.DAT to reveal program\nexecution counts and last run times.\n\nWindows systems maintain a set of keys in the registry database\n(UserAssist keys) to keep track of programs that executed. The\nnumber of executions and last execution date and time are available\nin these keys.\n\nThe information within the binary UserAssist values contains only\nstatistical data on the applications launched by the user via\nWindows Explorer. Programs launched via the command­line (cmd.exe)\ndo not appear in these registry keys.\n\nFrom a forensics perspective, being able to decode this information\ncan be very useful.\n\n**Limitations:** Additional data not parsed by Velociraptor is the\nFocusTime and FocusCount however these are not reliable. Also please\nnote that some methods of viewing an executable will update the\nassociated UserAssist key, and some methods of accessing an\nexecutable will not update the execution counter or time. Therefore\nthere may be some executions that have a 0 time and 0 runcount.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ExecutionTimeAfter": {
        "description": "If specified only show executions after this time.",
        "format": "velociraptor-timestamp",
        "title": "ExecutionTimeAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "UserAssistKey": {
        "description": "",
        "title": "UserAssistKey",
        "type": "string",
        "x-velociraptor-default": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\*\\Count\\*",
        "x-velociraptor-type": ""
      },
      "UserFilter": {
        "description": "If specified we filter by this username.",
        "format": "regex",
        "title": "UserFilter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_075Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.UserAssist",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-089"></a>

### 089. `Windows.Registry.WDigest`

功能描述（真实注册原文）：

Scans HKLM\SYSTEM ControlSets for WDigest security provider
registry keys that enable credential harvesting.

The artifact will also use GROUP BY to limit all ControlSet output
to a single row.

To prevent a clear-text password from being placed in
LSASS, the following registry key needs to be set to “0” (Digest
Disabled):

- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
  “UseLogonCredential”(DWORD)
  “Negotiate”(DWORD)

These registry keys are worth monitoring in an environment as an
attacker may wish to set it to 1 to enable Digest password support
which forces “clear-text” passwords to be placed in LSASS on any
version of Windows from Windows 7 / 2008R2 up to Windows 10 /
2012R2. Furthermore, Windows 8.1 / 2012 R2 and newer do not have a
“UseLogonCredential” DWORD value, so the key needs to be added.
The existence of the key is suspicious, if not expected.

* ATT&CK tactic: Defense Evasion, Credential Access
* ATT&CK technique: T1112, T1003.001

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans HKLM\\SYSTEM ControlSets for WDigest security provider\nregistry keys that enable credential harvesting.\n\nThe artifact will also use GROUP BY to limit all ControlSet output\nto a single row.\n\nTo prevent a clear-text password from being placed in\nLSASS, the following registry key needs to be set to “0” (Digest\nDisabled):\n\n- HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n  “UseLogonCredential”(DWORD)\n  “Negotiate”(DWORD)\n\nThese registry keys are worth monitoring in an environment as an\nattacker may wish to set it to 1 to enable Digest password support\nwhich forces “clear-text” passwords to be placed in LSASS on any\nversion of Windows from Windows 7 / 2008R2 up to Windows 10 /\n2012R2. Furthermore, Windows 8.1 / 2012 R2 and newer do not have a\n“UseLogonCredential” DWORD value, so the key needs to be added.\nThe existence of the key is suspicious, if not expected.\n\n* ATT&CK tactic: Defense Evasion, Credential Access\n* ATT&CK technique: T1112, T1003.001\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ShowAllValues": {
        "description": "Show all key values. It may be suspicious if these keys exist.",
        "title": "ShowAllValues",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "WDigestGlob": {
        "description": "Use a glob to define the files that will be searched.",
        "title": "WDigestGlob",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\**",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_076Arguments",
    "type": "object"
  },
  "name": "Windows.Registry.WDigest",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-090"></a>

### 090. `Windows.Search.FileFinder`

功能描述（真实注册原文）：

Searches for files by path glob, inspects file content via YARA, and
provides file hash and upload options.

This artifact is useful in the following scenarios:

* We need to locate all the places on our network where customer
  data has been copied.

* We’ve identified malware in a data breach, named using short
  random strings in specific folders and need to search for other
  instances across the network.

* We believe our user account credentials have been dumped and
  need to locate them.

* We need to search for exposed credit card data to satisfy PCI
  requirements.

* We have a sample of data that has been disclosed and need to
  locate other similar files

**Performance Note**

This artifact can be quite resource intensive, especially if we
search file content. It will require opening each file and reading
its entire content. To minimize the impact on the endpoint we
recommend this artifact is collected with a rate limited applied
(about 20-50 ops per second should be reasonable).

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Searches for files by path glob, inspects file content via YARA, and\nprovides file hash and upload options.\n\nThis artifact is useful in the following scenarios:\n\n* We need to locate all the places on our network where customer\n  data has been copied.\n\n* We’ve identified malware in a data breach, named using short\n  random strings in specific folders and need to search for other\n  instances across the network.\n\n* We believe our user account credentials have been dumped and\n  need to locate them.\n\n* We need to search for exposed credit card data to satisfy PCI\n  requirements.\n\n* We have a sample of data that has been disclosed and need to\n  locate other similar files\n\n**Performance Note**\n\nThis artifact can be quite resource intensive, especially if we\nsearch file content. It will require opening each file and reading\nits entire content. To minimize the impact on the endpoint we\nrecommend this artifact is collected with a rate limited applied\n(about 20-50 ops per second should be reasonable).\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Accessor": {
        "description": "The accessor to use",
        "enum": [
          "auto",
          "registry",
          "file",
          "ntfs",
          "ntfs_vss"
        ],
        "title": "Accessor",
        "type": "string",
        "x-velociraptor-default": "auto",
        "x-velociraptor-type": "choices"
      },
      "Calculate_Hash": {
        "description": "",
        "title": "Calculate_Hash",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "Glob": {
        "description": "Search for this file glob",
        "title": "Glob",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": ""
      },
      "ModifiedBefore": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "ModifiedBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "MoreRecentThan": {
        "description": "",
        "format": "velociraptor-timestamp",
        "title": "MoreRecentThan",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "SearchFilesGlobTable": {
        "description": "Specify multiple globs to search for.",
        "format": "text/csv",
        "title": "SearchFilesGlobTable",
        "type": "string",
        "x-velociraptor-default": "Glob\nC:/Users/SomeUser/*\n",
        "x-velociraptor-type": "csv"
      },
      "UPLOAD_IS_RESUMABLE": {
        "description": "If set, file uploads will be asynchronous and resumable.\n",
        "title": "UPLOAD_IS_RESUMABLE",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "Upload_File": {
        "description": "",
        "title": "Upload_File",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "VSS_MAX_AGE_DAYS": {
        "description": "If larger than 0 we restrict VSS age to this many days\nago. Otherwise we find all VSS.\n",
        "title": "VSS_MAX_AGE_DAYS",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      },
      "YaraRule": {
        "description": "A yara rule to search for matching files.",
        "format": "yara",
        "title": "YaraRule",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_077Arguments",
    "type": "object"
  },
  "name": "Windows.Search.FileFinder",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-091"></a>

### 091. `Windows.Search.VSS`

功能描述（真实注册原文）：

Finds files in Volume Shadow Copies (VSS) using the `ntfs_vss`
accessor.

Typically used to output deduplicated paths for processing by other
artifacts.

NOTE: This used to be more complicated but now delegates to the
`ntfs_vss` accessor to do all the hard work.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Finds files in Volume Shadow Copies (VSS) using the `ntfs_vss`\naccessor.\n\nTypically used to output deduplicated paths for processing by other\nartifacts.\n\nNOTE: This used to be more complicated but now delegates to the\n`ntfs_vss` accessor to do all the hard work.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "SearchFilesGlob": {
        "description": "Use a glob to define the files that will be searched.",
        "title": "SearchFilesGlob",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        "x-velociraptor-type": ""
      },
      "VSS_MAX_AGE_DAYS": {
        "description": "If larger than 0 we restrict VSS age to this many days\nago. Otherwise we find all VSS.\n",
        "title": "VSS_MAX_AGE_DAYS",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_078Arguments",
    "type": "object"
  },
  "name": "Windows.Search.VSS",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-092"></a>

### 092. `Windows.Search.Yara`

功能描述（真实注册原文）：

Scans the NTFS filesystem for files matching a YARA rule by first
parsing the MFT to enumerate files.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans the NTFS filesystem for files matching a YARA rule by first\nparsing the MFT to enumerate files.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "Also upload matching files.",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "NTFS_CACHE_TIME": {
        "description": "How often to flush the NTFS cache. (Default is never).",
        "title": "NTFS_CACHE_TIME",
        "type": "integer",
        "x-velociraptor-default": "1000000",
        "x-velociraptor-type": "int"
      },
      "nameRegex": {
        "description": "Only file names that match this regular expression will be scanned.",
        "format": "regex",
        "title": "nameRegex",
        "type": "string",
        "x-velociraptor-default": "(exe|txt|dll|php)$",
        "x-velociraptor-type": "regex"
      },
      "yaraRule": {
        "description": "The YARA Rule to search for.",
        "format": "yara",
        "title": "yaraRule",
        "type": "string",
        "x-velociraptor-default": "rule Hit {\n    strings:\n      $a = \"Keyword\" nocase wide ascii\n    condition:\n      any of them\n}\n",
        "x-velociraptor-type": "yara"
      }
    },
    "title": "dynamic_artifact_079Arguments",
    "type": "object"
  },
  "name": "Windows.Search.Yara",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-093"></a>

### 093. `Windows.Sys.AllUsers`

功能描述（真实注册原文）：

Lists all user accounts on a Windows system including domain users
with cached profiles.

Combines data from three data sources - the output from the
`NetUserEnum` API (termed `local` users), the list of SIDs in the
registry (termed `remote` users) and the SAM.

In this artifact, 'remote' means that user profile was cached in the
registry, but the user does not appear in the output of the
`NetUserEnum` API - this normally happens for users remotely logging
into the system using domain credentials.
'sam' means that the user account was declared in
the SAM hive but was not already listed by the other sources.

On Domain Controllers the `NetUserEnum` API will return the contents
of the entire ActiveDirectory as a list of 'local' users, however
this does not mean that the users have logged into the DC
locally. In this artifact we limit the number of users to 1000. If
you need to obtain the full list from the AD, customize this
artifact.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists all user accounts on a Windows system including domain users\nwith cached profiles.\n\nCombines data from three data sources - the output from the\n`NetUserEnum` API (termed `local` users), the list of SIDs in the\nregistry (termed `remote` users) and the SAM.\n\nIn this artifact, 'remote' means that user profile was cached in the\nregistry, but the user does not appear in the output of the\n`NetUserEnum` API - this normally happens for users remotely logging\ninto the system using domain credentials.\n'sam' means that the user account was declared in\nthe SAM hive but was not already listed by the other sources.\n\nOn Domain Controllers the `NetUserEnum` API will return the contents\nof the entire ActiveDirectory as a list of 'local' users, however\nthis does not mean that the users have logged into the DC\nlocally. In this artifact we limit the number of users to 1000. If\nyou need to obtain the full list from the AD, customize this\nartifact.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "SAMPath": {
        "description": "Path to the SAM file to parse.",
        "title": "SAMPath",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/System32/Config/SAM",
        "x-velociraptor-type": ""
      },
      "remoteRegKey": {
        "description": "",
        "title": "remoteRegKey",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_080Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.AllUsers",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-094"></a>

### 094. `Windows.Sys.AppcompatShims`

功能描述（真实注册原文）：

Queries the Windows registry for Application Compatibility shim
database entries and their associated executables.

Application Compatibility shims are a way to persist malware. This
artifact presents the AppCompat Shim information from the registry
in a nice human-friendly format.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Queries the Windows registry for Application Compatibility shim\ndatabase entries and their associated executables.\n\nApplication Compatibility shims are a way to persist malware. This\nartifact presents the AppCompat Shim information from the registry\nin a nice human-friendly format.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "customKeys": {
        "description": "",
        "title": "customKeys",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*\\*",
        "x-velociraptor-type": ""
      },
      "shimKeys": {
        "description": "",
        "title": "shimKeys",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_081Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.AppcompatShims",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-095"></a>

### 095. `Windows.Sys.CertificateAuthorities`

功能描述（真实注册原文）：

Enumerates certificate authorities from Windows certificate stores.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates certificate authorities from Windows certificate stores.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_082Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.CertificateAuthorities",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-096"></a>

### 096. `Windows.Sys.DiskInfo`

功能描述（真实注册原文）：

Collects physical disk drive information including model, serial
number, size, and interface type via WMI.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Collects physical disk drive information including model, serial\nnumber, size, and interface type via WMI.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_083Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.DiskInfo",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-097"></a>

### 097. `Windows.Sys.Drivers`

功能描述（真实注册原文）：

Enumerates running Windows device drivers with optional authenticode signature checking.

This does not display installed-but-unused drivers.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates running Windows device drivers with optional authenticode signature checking.\n\nThis does not display installed-but-unused drivers.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoCheckAuthenticode": {
        "description": "If selected we also check the authenticode information.",
        "title": "AlsoCheckAuthenticode",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_084Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.Drivers",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-098"></a>

### 098. `Windows.Sys.FirewallRules`

功能描述（真实注册原文）：

Lists Windows firewall rules by parsing the registry FirewallRules
key.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists Windows firewall rules by parsing the registry FirewallRules\nkey.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "regKey": {
        "description": "",
        "title": "regKey",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\**\\FirewallRules\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_085Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.FirewallRules",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-099"></a>

### 099. `Windows.Sys.Interfaces`

功能描述（真实注册原文）：

Report information about the system's network interfaces.

This artifact simply parses the output from `ipconfig /all`.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Report information about the system's network interfaces.\n\nThis artifact simply parses the output from `ipconfig /all`.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_086Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.Interfaces",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-100"></a>

### 100. `Windows.Sys.Programs`

功能描述（真实注册原文）：

Enumerates installed Windows applications by reading registry
uninstall keys.

An application generally correlates to one installation package on
Windows. Some fields may be blank as Windows installation details
are left to the discretion of the product author.

Limitations: This key parses the live registry hives - if a user is
not logged in then their data will not be resident in HKU and
therefore you should instead parse the hives on disk (including
within VSS/`Regback`).

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates installed Windows applications by reading registry\nuninstall keys.\n\nAn application generally correlates to one installation package on\nWindows. Some fields may be blank as Windows installation details\nare left to the discretion of the product author.\n\nLimitations: This key parses the live registry hives - if a user is\nnot logged in then their data will not be resident in HKU and\ntherefore you should instead parse the hives on disk (including\nwithin VSS/`Regback`).\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "programKeys": {
        "description": "",
        "title": "programKeys",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_087Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.Programs",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-101"></a>

### 101. `Windows.Sys.StartupItems`

功能描述（真实注册原文）：

Enumerates startup applications from registry Run keys and Startup
folder locations.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates startup applications from registry Run keys and Startup\nfolder locations.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "If set we also upload the files in the startup folders",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "runKeyGlobs": {
        "description": "",
        "format": "text/csv",
        "title": "runKeyGlobs",
        "type": "string",
        "x-velociraptor-default": "KeyGlobs\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*\nHKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\*\nHKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*\nHKEY_USERS\\*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*\nHKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\*\n",
        "x-velociraptor-type": "csv"
      },
      "startupApprovedGlobs": {
        "description": "",
        "format": "text/csv",
        "title": "startupApprovedGlobs",
        "type": "string",
        "x-velociraptor-default": "KeyGlobs\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**\nHKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**\n",
        "x-velociraptor-type": "csv"
      },
      "startupFolderDirectories": {
        "description": "",
        "format": "text/csv",
        "title": "startupFolderDirectories",
        "type": "string",
        "x-velociraptor-default": "FileGlobs\nC:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**\nC:/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/**\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_088Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.StartupItems",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-102"></a>

### 102. `Windows.Sys.Users`

功能描述（真实注册原文）：

Lists user accounts that have logged on locally by inspecting
registry profile list keys for locally-created profiles.

This method is a reliable way of identifying which users have
physically logged into the system and thereby created local
profiles.

This will not include domain users or the output from `NetUserEnum`
- you should collect the `Windows.Sys.AllUsers` artifact to get all
possible users on the system.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists user accounts that have logged on locally by inspecting\nregistry profile list keys for locally-created profiles.\n\nThis method is a reliable way of identifying which users have\nphysically logged into the system and thereby created local\nprofiles.\n\nThis will not include domain users or the output from `NetUserEnum`\n- you should collect the `Windows.Sys.AllUsers` artifact to get all\npossible users on the system.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "remoteRegKey": {
        "description": "",
        "title": "remoteRegKey",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_089Arguments",
    "type": "object"
  },
  "name": "Windows.Sys.Users",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-103"></a>

### 103. `Windows.Sysinternals.Autoruns`

功能描述（真实注册原文）：

Installs and runs Sysinternals `autorunsc` to enumerate autostart
persistence mechanisms.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Installs and runs Sysinternals `autorunsc` to enumerate autostart\npersistence mechanisms.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "All": {
        "description": "",
        "title": "All",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "Appinit DLLs": {
        "description": "",
        "title": "Appinit DLLs",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Autostart services and non-disabled drivers": {
        "description": "",
        "title": "Autostart services and non-disabled drivers",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Boot execute": {
        "description": "",
        "title": "Boot execute",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Codecs": {
        "description": "",
        "title": "Codecs",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Explorer addons": {
        "description": "",
        "title": "Explorer addons",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Image hijacks": {
        "description": "",
        "title": "Image hijacks",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Internet Explorer addons": {
        "description": "",
        "title": "Internet Explorer addons",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Known DLLs": {
        "description": "",
        "title": "Known DLLs",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "LSA security providers": {
        "description": "",
        "title": "LSA security providers",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Logon startups (this is the default)": {
        "description": "",
        "title": "Logon startups (this is the default)",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Office addins": {
        "description": "",
        "title": "Office addins",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Printer monitor DLLs": {
        "description": "",
        "title": "Printer monitor DLLs",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Scheduled tasks": {
        "description": "",
        "title": "Scheduled tasks",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Sidebar gadgets (Vista and higher)": {
        "description": "",
        "title": "Sidebar gadgets (Vista and higher)",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Verify digital signatures": {
        "description": "",
        "title": "Verify digital signatures",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "WMI entries": {
        "description": "",
        "title": "WMI entries",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Winlogon entries": {
        "description": "",
        "title": "Winlogon entries",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Winsock protocol and network providers": {
        "description": "",
        "title": "Winsock protocol and network providers",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_090Arguments",
    "type": "object"
  },
  "name": "Windows.Sysinternals.Autoruns",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-104"></a>

### 104. `Windows.System.AuditPolicy`

功能描述（真实注册原文）：

Collects Windows Audit Policy configuration data from Windows
systems via auditpol.

Use this artifact to determine which Windows event logs are audited and
identify audit configuration discrepancies across the environment.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Collects Windows Audit Policy configuration data from Windows\nsystems via auditpol.\n\nUse this artifact to determine which Windows event logs are audited and\nidentify audit configuration discrepancies across the environment.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_091Arguments",
    "type": "object"
  },
  "name": "Windows.System.AuditPolicy",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-105"></a>

### 105. `Windows.System.CatFiles`

功能描述（真实注册原文）：

Parses Windows `.cat` catalog files and extracts certificate trust
list hashes with signer information.

Windows stores many hashes in `.cat` files. These catalog files
contain a set of trusted hashes for drivers and other binaries,
even if the PE files do not themselves contain Authenticode
signatures.

This artifact extracts all the trusted hashes from a system by
parsing all the cat files.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses Windows `.cat` catalog files and extracts certificate trust\nlist hashes with signer information.\n\nWindows stores many hashes in `.cat` files. These catalog files\ncontain a set of trusted hashes for drivers and other binaries,\neven if the PE files do not themselves contain Authenticode\nsignatures.\n\nThis artifact extracts all the trusted hashes from a system by\nparsing all the cat files.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "CatGlobs": {
        "description": "",
        "title": "CatGlobs",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\CatRoot\\*\\*.cat",
        "x-velociraptor-type": ""
      },
      "SignerExcludeRegex": {
        "description": "Exclude hashes from this Signer",
        "format": "regex",
        "title": "SignerExcludeRegex",
        "type": "string",
        "x-velociraptor-default": "Microsoft",
        "x-velociraptor-type": "regex"
      },
      "SignerFilterRegex": {
        "description": "Only show hashes from this signer.",
        "format": "regex",
        "title": "SignerFilterRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_092Arguments",
    "type": "object"
  },
  "name": "Windows.System.CatFiles",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-106"></a>

### 106. `Windows.System.CmdShell`

功能描述（真实注册原文）：

Runs shell commands through cmd.exe and captures or uploads stdout
output.

Since Velociraptor clients typically runs as SYSTEM, the commands
will also run as SYSTEM.

This is a very powerful artifact since it allows for arbitrary
command execution on the endpoints. Therefore this artifact requires
elevated permissions (specifically the `EXECVE`
permission). Typically it is only available with the `administrator`
role.

Note there are some limitations with passing commands to the cmd.exe
shell, such as when specifying quoted paths or command-line
arguments with special characters. Using Windows.System.PowerShell
artifact is likely a better option in these cases.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Runs shell commands through cmd.exe and captures or uploads stdout\noutput.\n\nSince Velociraptor clients typically runs as SYSTEM, the commands\nwill also run as SYSTEM.\n\nThis is a very powerful artifact since it allows for arbitrary\ncommand execution on the endpoints. Therefore this artifact requires\nelevated permissions (specifically the `EXECVE`\npermission). Typically it is only available with the `administrator`\nrole.\n\nNote there are some limitations with passing commands to the cmd.exe\nshell, such as when specifying quoted paths or command-line\narguments with special characters. Using Windows.System.PowerShell\nartifact is likely a better option in these cases.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Command": {
        "description": "",
        "title": "Command",
        "type": "string",
        "x-velociraptor-default": "dir C:\\",
        "x-velociraptor-type": ""
      },
      "CommandId": {
        "description": "",
        "title": "CommandId",
        "type": "string",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": ""
      },
      "Stateful": {
        "description": "",
        "title": "Stateful",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "Timeout": {
        "description": "How long to leave the session running for.",
        "title": "Timeout",
        "type": "integer",
        "x-velociraptor-default": "3500",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_093Arguments",
    "type": "object"
  },
  "name": "Windows.System.CmdShell",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-107"></a>

### 107. `Windows.System.CriticalServices`

功能描述（真实注册原文）：

Checks that important Windows services like antivirus and update
services are currently running.

The default list contains virus scanners. If the software is not
installed at all, it will not be shown.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Checks that important Windows services like antivirus and update\nservices are currently running.\n\nThe default list contains virus scanners. If the software is not\ninstalled at all, it will not be shown.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "lookupTable": {
        "description": "",
        "format": "text/csv",
        "title": "lookupTable",
        "type": "string",
        "x-velociraptor-default": "ServiceName\nWinDefend\nMpsSvc\nSepMasterService\nSAVAdminService\nSavService\nwscsvc\nwuauserv\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_094Arguments",
    "type": "object"
  },
  "name": "Windows.System.CriticalServices",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-108"></a>

### 108. `Windows.System.DLLs`

功能描述（真实注册原文）：

Lists DLLs loaded by running processes with optional hash
computation and certificate information.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists DLLs loaded by running processes with optional hash\ncomputation and certificate information.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Calculate_Hash": {
        "description": "",
        "title": "Calculate_Hash",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "CertificateInfo": {
        "description": "",
        "title": "CertificateInfo",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "CommandLineRegex": {
        "description": "",
        "format": "regex",
        "title": "CommandLineRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DllRegex": {
        "description": "A regex applied to the full DLL path (e.g. whitelist all system DLLs)",
        "format": "regex",
        "title": "DllRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ExePathRegex": {
        "description": "",
        "format": "regex",
        "title": "ExePathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "A regex applied to process names.",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_095Arguments",
    "type": "object"
  },
  "name": "Windows.System.DLLs",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-109"></a>

### 109. `Windows.System.DNSCache`

功能描述（真实注册原文）：

Queries the Windows DNS client cache via WMI and reports cached DNS
records with types and status.

Windows maintains DNS lookups for a short time in the DNS cache.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Queries the Windows DNS client cache via WMI and reports cached DNS\nrecords with types and status.\n\nWindows maintains DNS lookups for a short time in the DNS cache.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_096Arguments",
    "type": "object"
  },
  "name": "Windows.System.DNSCache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-110"></a>

### 110. `Windows.System.DomainRole`

功能描述（真实注册原文）：

Extracts and categorizes the domain role of Windows systems based
on `Win32_ComputerSystem` WMI data.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts and categorizes the domain role of Windows systems based\non `Win32_ComputerSystem` WMI data.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DomainRegex": {
        "description": "Regex filter by Domain",
        "title": "DomainRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "HostNameRegex": {
        "description": "Regex filter by DNSHostName",
        "title": "HostNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      },
      "RoleRegex": {
        "description": "Regex filter by Role",
        "title": "RoleRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_097Arguments",
    "type": "object"
  },
  "name": "Windows.System.DomainRole",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-111"></a>

### 111. `Windows.System.Handles`

功能描述（真实注册原文）：

Lists open handles (files, registry keys, etc.) for processes
matching a regex pattern.

Uncheck all the handle types below to fetch all handle types.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists open handles (files, registry keys, etc.) for processes\nmatching a regex pattern.\n\nUncheck all the handle types below to fetch all handle types.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Files": {
        "description": "Search for File Handles",
        "title": "Files",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "IncludeAccessMasks": {
        "description": "",
        "title": "IncludeAccessMasks",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Key": {
        "description": "Search for Key Handles",
        "title": "Key",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "processRegex": {
        "description": "A regex applied to process names.",
        "format": "regex",
        "title": "processRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_098Arguments",
    "type": "object"
  },
  "name": "Windows.System.Handles",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-112"></a>

### 112. `Windows.System.HostsFile`

功能描述（真实注册原文）：

Reads and parses the Windows hosts file, reporting resolution
entries, hostnames, and comments.

Regex searching for Hostname and resolution is enabled over output.
NOTE: For Hostname search is on the hostfile line and regex ^ or $
is not recommended.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Reads and parses the Windows hosts file, reporting resolution\nentries, hostnames, and comments.\n\nRegex searching for Hostname and resolution is enabled over output.\nNOTE: For Hostname search is on the hostfile line and regex ^ or $\nis not recommended.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "HostnameRegex": {
        "description": "Hostname target regex in Hostsfile",
        "format": "regex",
        "title": "HostnameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "HostsFile": {
        "description": "",
        "title": "HostsFile",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "x-velociraptor-type": ""
      },
      "ResolutionRegex": {
        "description": "Resolution target regex in Hostsfile",
        "format": "regex",
        "title": "ResolutionRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_099Arguments",
    "type": "object"
  },
  "name": "Windows.System.HostsFile",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-113"></a>

### 113. `Windows.System.LocalAdmins`

功能描述（真实注册原文）：

Retrieves local administrator accounts from a Windows system via
PowerShell.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Retrieves local administrator accounts from a Windows system via\nPowerShell.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "PowerShellExe": {
        "description": "",
        "title": "PowerShellExe",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_100Arguments",
    "type": "object"
  },
  "name": "Windows.System.LocalAdmins",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-114"></a>

### 114. `Windows.System.PowerShell`

功能描述（真实注册原文）：

Executes arbitrary commands through PowerShell with output capture
and upload support.

Since Velociraptor typically runs as SYSTEM, the commands will also
run as SYSTEM.

This is a very powerful artifact since it allows for arbitrary
command execution on the endpoints. Therefore this artifact requires
elevated permissions (specifically the `EXECVE`
permission). Typically it is only available with the `administrator`
role.

Note that in addition to running PowerShell cmdlets and scripts, the
Windows.System.PowerShell artifact can also be used to launch
Windows command-line executables with their parameters. This can be
difficult to achieve with the Windows.System.CmdShell artifact due
to complications with spaces in paths and other special character
issues. This PowerShell artifact is able to avoid most of these
problems by encoding the command in Base64.

As an example, the following command initiates a Windows Defender AV
quick-scan from the default location, which includes a path with
spaces in it:

```
  & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Scan -ScanType 1
```

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Executes arbitrary commands through PowerShell with output capture\nand upload support.\n\nSince Velociraptor typically runs as SYSTEM, the commands will also\nrun as SYSTEM.\n\nThis is a very powerful artifact since it allows for arbitrary\ncommand execution on the endpoints. Therefore this artifact requires\nelevated permissions (specifically the `EXECVE`\npermission). Typically it is only available with the `administrator`\nrole.\n\nNote that in addition to running PowerShell cmdlets and scripts, the\nWindows.System.PowerShell artifact can also be used to launch\nWindows command-line executables with their parameters. This can be\ndifficult to achieve with the Windows.System.CmdShell artifact due\nto complications with spaces in paths and other special character\nissues. This PowerShell artifact is able to avoid most of these\nproblems by encoding the command in Base64.\n\nAs an example, the following command initiates a Windows Defender AV\nquick-scan from the default location, which includes a path with\nspaces in it:\n\n```\n  & 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -Scan -ScanType 1\n```\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Command": {
        "description": "",
        "title": "Command",
        "type": "string",
        "x-velociraptor-default": "dir C:/",
        "x-velociraptor-type": ""
      },
      "CommandId": {
        "description": "",
        "title": "CommandId",
        "type": "string",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": ""
      },
      "PowerShellExe": {
        "description": "",
        "title": "PowerShellExe",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "x-velociraptor-type": ""
      },
      "Stateful": {
        "description": "",
        "title": "Stateful",
        "type": "boolean",
        "x-velociraptor-default": "Y",
        "x-velociraptor-type": "bool"
      },
      "Timeout": {
        "description": "How long to leave the session running for.",
        "title": "Timeout",
        "type": "integer",
        "x-velociraptor-default": "3500",
        "x-velociraptor-type": "int"
      }
    },
    "title": "dynamic_artifact_101Arguments",
    "type": "object"
  },
  "name": "Windows.System.PowerShell",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-115"></a>

### 115. `Windows.System.Powershell.ModuleAnalysisCache`

功能描述（真实注册原文）：

Parses the PowerShell ModuleAnalysisCache file to enumerate loaded
modules and their functions.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the PowerShell ModuleAnalysisCache file to enumerate loaded\nmodules and their functions.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "FunctionNameRegex": {
        "description": "Regex of FunctionName to include.",
        "format": "regex",
        "title": "FunctionNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "GlobLookup": {
        "description": "",
        "title": "GlobLookup",
        "type": "string",
        "x-velociraptor-default": "C:\\{Users\\*,Windows\\System32\\config\\systemprofile}\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\ModuleAnalysisCache",
        "x-velociraptor-type": ""
      },
      "ModulePathIgnoreRegex": {
        "description": "Regex of installed ModulePath to ignore.",
        "format": "regex",
        "title": "ModulePathIgnoreRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "ModulePathRegex": {
        "description": "Regex of installed ModulePath to target.",
        "format": "regex",
        "title": "ModulePathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_102Arguments",
    "type": "object"
  },
  "name": "Windows.System.Powershell.ModuleAnalysisCache",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-116"></a>

### 116. `Windows.System.Powershell.PSReadline`

功能描述（真实注册原文）：

Extracts PowerShell command history from PSReadline
`ConsoleHost_history.txt` files.

PowerShell is commonly used by attackers across all stages of the
attack lifecycle. The PSReadline module is responsible for command
history and from PowerShell 5 on Windows 10, the default
configuration saves a copy of the console history to disk.

There are several parameters available for search leveraging regex:
- SearchStrings enables regex search over a PSReadline line.
- StringWhiteList enables a regex whitelist for results.
- UserRegex enables a regex search on Username
- UploadFiles enables upload ConsoleHost_history.txt in scope

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts PowerShell command history from PSReadline\n`ConsoleHost_history.txt` files.\n\nPowerShell is commonly used by attackers across all stages of the\nattack lifecycle. The PSReadline module is responsible for command\nhistory and from PowerShell 5 on Windows 10, the default\nconfiguration saves a copy of the console history to disk.\n\nThere are several parameters available for search leveraging regex:\n- SearchStrings enables regex search over a PSReadline line.\n- StringWhiteList enables a regex whitelist for results.\n- UserRegex enables a regex search on Username\n- UploadFiles enables upload ConsoleHost_history.txt in scope\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ConsoleHostHistory": {
        "description": "",
        "title": "ConsoleHostHistory",
        "type": "string",
        "x-velociraptor-default": "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "x-velociraptor-type": ""
      },
      "SearchStrings": {
        "description": "",
        "format": "regex",
        "title": "SearchStrings",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "StringWhiteList": {
        "description": "",
        "format": "regex",
        "title": "StringWhiteList",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "UploadFiles": {
        "description": "Upload ConsoleHost_history.txt files in scope",
        "title": "UploadFiles",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UserRegex": {
        "description": "",
        "format": "regex",
        "title": "UserRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_103Arguments",
    "type": "object"
  },
  "name": "Windows.System.Powershell.PSReadline",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-117"></a>

### 117. `Windows.System.Pslist`

功能描述（真实注册原文）：

Enumerates running processes along with their executable paths and
associated details, with optional authenticode trust verification
and binary hashing.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates running processes along with their executable paths and\nassociated details, with optional authenticode trust verification\nand binary hashing.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "CommandLineRegex": {
        "description": "",
        "format": "regex",
        "title": "CommandLineRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "ExePathRegex": {
        "description": "",
        "format": "regex",
        "title": "ExePathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "UntrustedAuthenticode": {
        "description": "Show only Executables that are not trusted by Authenticode.",
        "title": "UntrustedAuthenticode",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UseTracker": {
        "description": "If set we use the process tracker.",
        "title": "UseTracker",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "UsernameRegex": {
        "description": "",
        "format": "regex",
        "title": "UsernameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_104Arguments",
    "type": "object"
  },
  "name": "Windows.System.Pslist",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-118"></a>

### 118. `Windows.System.RootCAStore`

功能描述（真实注册原文）：

Enumerates root CA certificates from the Windows System Certificate
store.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates root CA certificates from the Windows System Certificate\nstore.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "CertificateRootStoreGlobs": {
        "description": "",
        "format": "text/csv",
        "title": "CertificateRootStoreGlobs",
        "type": "string",
        "x-velociraptor-default": "Accessor,Glob\nreg,HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\**\\Blob\nreg,HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\**\\Blob\nreg,HKEY_USERS\\*\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\**\\Blob\nreg,HKEY_USERS\\*\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\**\\Blob\n",
        "x-velociraptor-type": "csv"
      }
    },
    "title": "dynamic_artifact_105Arguments",
    "type": "object"
  },
  "name": "Windows.System.RootCAStore",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-119"></a>

### 119. `Windows.System.SVCHost`

功能描述（真实注册原文）：

Lists `svchost.exe` processes whose parent is not services.exe,
indicating suspicious activity.

Typically a windows system will have many `svchost.exe`
processes. Sometimes attackers name their processes `svchost.exe` to
try to hide. Typically `svchost.exe` is spawned by `services.exe`.

This artifact lists all the processes named `svchost.exe` and their
parents where the parent is NOT named `services.exe`.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists `svchost.exe` processes whose parent is not services.exe,\nindicating suspicious activity.\n\nTypically a windows system will have many `svchost.exe`\nprocesses. Sometimes attackers name their processes `svchost.exe` to\ntry to hide. Typically `svchost.exe` is spawned by `services.exe`.\n\nThis artifact lists all the processes named `svchost.exe` and their\nparents where the parent is NOT named `services.exe`.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {},
    "title": "dynamic_artifact_106Arguments",
    "type": "object"
  },
  "name": "Windows.System.SVCHost",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-120"></a>

### 120. `Windows.System.Services`

功能描述（真实注册原文）：

Enumerates Windows services via WMI, with optional filtering
criteria, and enriches with hashes and authenticode signatures.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows services via WMI, with optional filtering\ncriteria, and enriches with hashes and authenticode signatures.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Calculate_hashes": {
        "description": "",
        "title": "Calculate_hashes",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "CertificateInfo": {
        "description": "",
        "title": "CertificateInfo",
        "type": "boolean",
        "x-velociraptor-default": "N",
        "x-velociraptor-type": "bool"
      },
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "DisplayNameRegex": {
        "description": "",
        "format": "regex",
        "title": "DisplayNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "FailureCommandRegex": {
        "description": "",
        "format": "regex",
        "title": "FailureCommandRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "NameRegex": {
        "description": "",
        "format": "regex",
        "title": "NameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PathNameRegex": {
        "description": "",
        "format": "regex",
        "title": "PathNameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ServiceDllRegex": {
        "description": "",
        "format": "regex",
        "title": "ServiceDllRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "servicesKeyGlob": {
        "description": "",
        "title": "servicesKeyGlob",
        "type": "string",
        "x-velociraptor-default": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_107Arguments",
    "type": "object"
  },
  "name": "Windows.System.Services",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-121"></a>

### 121. `Windows.System.Shares`

功能描述（真实注册原文）：

Enumerates Windows network shares via the Win32_Share WMI class
with regex filtering.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows network shares via the Win32_Share WMI class\nwith regex filtering.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "NameRegex": {
        "description": "Regex filter for share name. e.g Admin\\$ for Admin$",
        "format": "regex",
        "title": "NameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "Regex filter for local path. e.g C:\\\\Windows$ for Admin$",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_108Arguments",
    "type": "object"
  },
  "name": "Windows.System.Shares",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-122"></a>

### 122. `Windows.System.Signers`

功能描述（真实注册原文）：

Scans executable files and groups them by their authenticode signer
subject.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Scans executable files and groups them by their authenticode signer\nsubject.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "ExecutableGlobs": {
        "description": "",
        "title": "ExecutableGlobs",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/**/*.{dll,exe}",
        "x-velociraptor-type": ""
      },
      "ShowAllSigners": {
        "description": "When checked we show all signed files instead of stacking them.",
        "title": "ShowAllSigners",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_109Arguments",
    "type": "object"
  },
  "name": "Windows.System.Signers",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-123"></a>

### 123. `Windows.System.TaskScheduler`

功能描述（真实注册原文）：

Enumerates Windows scheduled tasks and parses their XML definitions
to extract commands and user contexts.

The Windows task scheduler is a common mechanism that malware uses
for persistence. It can be used to run arbitrary programs at a later
time. Commonly malware installs a scheduled task to run itself
periodically to achieve persistence.

This artifact enumerates all the task jobs (which are XML files).
The artifact uploads the original XML files and then analyses them
to provide an overview of the commands executed and the user under
which they will be run.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates Windows scheduled tasks and parses their XML definitions\nto extract commands and user contexts.\n\nThe Windows task scheduler is a common mechanism that malware uses\nfor persistence. It can be used to run arbitrary programs at a later\ntime. Commonly malware installs a scheduled task to run itself\nperiodically to achieve persistence.\n\nThis artifact enumerates all the task jobs (which are XML files).\nThe artifact uploads the original XML files and then analyses them\nto provide an overview of the commands executed and the user under\nwhich they will be run.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "AlsoUpload": {
        "description": "If set we also upload the task XML files.\n",
        "title": "AlsoUpload",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "TasksPath": {
        "description": "",
        "title": "TasksPath",
        "type": "string",
        "x-velociraptor-default": "C:/Windows/System32/Tasks/**",
        "x-velociraptor-type": ""
      },
      "UploadCommands": {
        "description": "If set we attempt to upload the commands that are\nmentioned in the scheduled tasks\n",
        "title": "UploadCommands",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "Username": {
        "description": "",
        "format": "regex",
        "title": "Username",
        "type": "string",
        "x-velociraptor-default": ".*",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_110Arguments",
    "type": "object"
  },
  "name": "Windows.System.TaskScheduler",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-124"></a>

### 124. `Windows.System.Threads`

功能描述（真实注册原文）：

Lists threads for selected processes, matching by name or PID regex
filters.

This uses Velociraptor's threads plugin.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Lists threads for selected processes, matching by name or PID regex\nfilters.\n\nThis uses Velociraptor's threads plugin.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "A regex applied to process names.",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_111Arguments",
    "type": "object"
  },
  "name": "Windows.System.Threads",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-125"></a>

### 125. `Windows.System.UntrustedBinaries`

功能描述（真实注册原文）：

Checks that common Windows system binaries are signed using
authenticode verification.

Windows runs several services and binaries as part of the operating
system. Sometimes malware pretends to run as those well known names
to hide itself in plain sight. For example, a malware service might
call itself `svchost.exe` so it shows up in the process listing as a
benign service.

This artifact checks that the common system binaries are signed. If
a malware replaces these files or names itself in this way their
signature might not be correct.

Note that unfortunately Microsoft does not sign all their common
binaries so many will not be signed (e.g. `conhost.exe`).

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Checks that common Windows system binaries are signed using\nauthenticode verification.\n\nWindows runs several services and binaries as part of the operating\nsystem. Sometimes malware pretends to run as those well known names\nto hide itself in plain sight. For example, a malware service might\ncall itself `svchost.exe` so it shows up in the process listing as a\nbenign service.\n\nThis artifact checks that the common system binaries are signed. If\na malware replaces these files or names itself in this way their\nsignature might not be correct.\n\nNote that unfortunately Microsoft does not sign all their common\nbinaries so many will not be signed (e.g. `conhost.exe`).\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "DISABLE_DANGEROUS_API_CALLS": {
        "description": "Enable this to disable potentially flakey APIs which may cause\ncrashes.\n",
        "title": "DISABLE_DANGEROUS_API_CALLS",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "processNamesRegex": {
        "description": "A regex to select running processes which we consider should be trusted.",
        "format": "regex",
        "title": "processNamesRegex",
        "type": "string",
        "x-velociraptor-default": "lsass|svchost|conhost|taskmgr|winlogon|wmiprv|dwm|csrss|velociraptor",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_112Arguments",
    "type": "object"
  },
  "name": "Windows.System.UntrustedBinaries",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-126"></a>

### 126. `Windows.System.VAD`

功能描述（真实注册原文）：

Enumerates process memory sections using Virtual Address Descriptor
(VAD) information.

The VAD is used by the Windows memory manager to describe allocated
process memory ranges.

Available filters include process, mapping path, memory permissions
or by content with yara.

Use the `UploadSection` switch to upload any sections.

A notebook suggestion is available for Strings analysis on uploaded
sections.

NOTES:

- ProtectionChoice is a choice to filter on section protection. Default is
all sections and ProtectionRegex can override selection.
- To filter on unmapped sections the MappingNameRegex: ^$ can be used.
- When uploading sections during analysis, its recommended to run once for
  scoping, then a second time once confirmed for upload.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Enumerates process memory sections using Virtual Address Descriptor\n(VAD) information.\n\nThe VAD is used by the Windows memory manager to describe allocated\nprocess memory ranges.\n\nAvailable filters include process, mapping path, memory permissions\nor by content with yara.\n\nUse the `UploadSection` switch to upload any sections.\n\nA notebook suggestion is available for Strings analysis on uploaded\nsections.\n\nNOTES:\n\n- ProtectionChoice is a choice to filter on section protection. Default is\nall sections and ProtectionRegex can override selection.\n- To filter on unmapped sections the MappingNameRegex: ^$ can be used.\n- When uploading sections during analysis, its recommended to run once for\n  scoping, then a second time once confirmed for upload.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "ContextBytes": {
        "description": "Include this amount of bytes around yara hit as context.",
        "title": "ContextBytes",
        "type": "integer",
        "x-velociraptor-default": "0",
        "x-velociraptor-type": "int"
      },
      "MappingNameRegex": {
        "description": "",
        "format": "regex",
        "title": "MappingNameRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "PidRegex": {
        "description": "",
        "format": "regex",
        "title": "PidRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProcessRegex": {
        "description": "A regex applied to process names.",
        "format": "regex",
        "title": "ProcessRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "ProtectionChoice": {
        "description": "Select memory permission you would like to return. Default All.",
        "enum": [
          "Any",
          "Execute, read and write",
          "Any executable"
        ],
        "title": "ProtectionChoice",
        "type": "string",
        "x-velociraptor-default": "Any",
        "x-velociraptor-type": "choices"
      },
      "ProtectionRegex": {
        "description": "Allows a manual regex selection of section Protection permissions. If configured take preference over Protection choice.",
        "format": "regex",
        "title": "ProtectionRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "SuspiciousContent": {
        "description": "A yara rule of suspicious section content",
        "format": "yara",
        "title": "SuspiciousContent",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "yara"
      },
      "UploadSection": {
        "description": "Upload suspicious section.",
        "title": "UploadSection",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      }
    },
    "title": "dynamic_artifact_113Arguments",
    "type": "object"
  },
  "name": "Windows.System.VAD",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-127"></a>

### 127. `Windows.System.WMIQuery`

功能描述（真实注册原文）：

Runs a configurable WMI query on Windows and outputs the result
rows.

Windows Management Instrumentation (WMI) is the Microsoft
implementation of Web-Based Enterprise Management (WBEM), which is
an industry initiative to develop a standard technology for
accessing management information in an enterprise environment. WMI
uses the Common Information Model (CIM) industry standard to
represent systems, applications, networks, devices, and other
managed components. CIM is developed and maintained by the
Distributed Management Task Force (DMTF).

Please see the second reference link for an example of built-in
system classes.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Runs a configurable WMI query on Windows and outputs the result\nrows.\n\nWindows Management Instrumentation (WMI) is the Microsoft\nimplementation of Web-Based Enterprise Management (WBEM), which is\nan industry initiative to develop a standard technology for\naccessing management information in an enterprise environment. WMI\nuses the Common Information Model (CIM) industry standard to\nrepresent systems, applications, networks, devices, and other\nmanaged components. CIM is developed and maintained by the\nDistributed Management Task Force (DMTF).\n\nPlease see the second reference link for an example of built-in\nsystem classes.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Namespace": {
        "description": "Add target Namespace: e.g root/cimv2",
        "title": "Namespace",
        "type": "string",
        "x-velociraptor-default": "root/cimv2",
        "x-velociraptor-type": ""
      },
      "WMIQuery": {
        "description": "Add target WMI query: e.g SELECT * FROM <CLASSNAME>",
        "title": "WMIQuery",
        "type": "string",
        "x-velociraptor-default": "SELECT * FROM Win32_Process",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_114Arguments",
    "type": "object"
  },
  "name": "Windows.System.WMIQuery",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-128"></a>

### 128. `Windows.Timeline.MFT`

功能描述（真实注册原文）：

Parses the MFT and outputs file metadata in timeline format with
anomaly detection flags and advanced filters.

Output is to Timeline field format to enable simple review across
Timeline queries. The TimeOutput parameter enables configuring which
NTFS attribute timestamps are in focus as event_time. for example:
`STANDARD_INFORMATION (4), FILE_NAME (4) or ALL (8)`

This artifact also has the same anomaly logic as AnalyzeMFT added to
each row, to aid analysis.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Parses the MFT and outputs file metadata in timeline format with\nanomaly detection flags and advanced filters.\n\nOutput is to Timeline field format to enable simple review across\nTimeline queries. The TimeOutput parameter enables configuring which\nNTFS attribute timestamps are in focus as event_time. for example:\n`STANDARD_INFORMATION (4), FILE_NAME (4) or ALL (8)`\n\nThis artifact also has the same anomaly logic as AnalyzeMFT added to\neach row, to aid analysis.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "Accessor": {
        "description": "",
        "title": "Accessor",
        "type": "string",
        "x-velociraptor-default": "ntfs",
        "x-velociraptor-type": ""
      },
      "AllocatedType": {
        "description": "Type of entry. Allocated, Unallocated or Both.\n",
        "enum": [
          "Allocated",
          "Unallocated",
          "Both"
        ],
        "title": "AllocatedType",
        "type": "string",
        "x-velociraptor-default": "Both",
        "x-velociraptor-type": "choices"
      },
      "DateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "DateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "DateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "EntryType": {
        "description": "Type of entry. File, Directory or Both.\n",
        "enum": [
          "File",
          "Directory",
          "Both"
        ],
        "title": "EntryType",
        "type": "string",
        "x-velociraptor-default": "Both",
        "x-velociraptor-type": "choices"
      },
      "Inode": {
        "description": "search for inode",
        "title": "Inode",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int64"
      },
      "MFTFilename": {
        "description": "",
        "title": "MFTFilename",
        "type": "string",
        "x-velociraptor-default": "C:/$MFT",
        "x-velociraptor-type": ""
      },
      "NameRegex": {
        "description": "regex search over File Name",
        "format": "regex",
        "title": "NameRegex",
        "type": "string",
        "x-velociraptor-default": ".",
        "x-velociraptor-type": "regex"
      },
      "PathRegex": {
        "description": "regex search over OSPath.",
        "format": "regex",
        "title": "PathRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "SizeMax": {
        "description": "Entries in the MFT over this size in bytes.",
        "title": "SizeMax",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int64"
      },
      "SizeMin": {
        "description": "Entries in the MFT under this size in bytes.",
        "title": "SizeMin",
        "type": "integer",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "int64"
      },
      "TimeOutput": {
        "description": "Timestamps to output as event_time. SI, FN or both.\nNOTE: both will output 8 rows per MFT entry.\n",
        "enum": [
          "STANDARD_INFORMATION",
          "FILE_NAME",
          "ALL"
        ],
        "title": "TimeOutput",
        "type": "string",
        "x-velociraptor-default": "STANDARD_INFORMATION",
        "x-velociraptor-type": "choices"
      }
    },
    "title": "dynamic_artifact_115Arguments",
    "type": "object"
  },
  "name": "Windows.Timeline.MFT",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-129"></a>

### 129. `Windows.Timeline.Prefetch`

功能描述（真实注册原文）：

Extracts execution timestamps from prefetch files and outputs them
in timeline format.

Windows keeps a cache of prefetch files. When an executable is run,
the system records properties about the executable to make it faster
to run next time. By parsing this information we are able to
determine when binaries are run in the past. On Windows10 we can see
the last 8 execution times and creation time (9 potential
executions).

This artifact is a timelined output version of the standard Prefetch
artifact. There are several parameters available.
- dateAfter enables search for prefetch evidence after this date.
- dateBefore enables search for prefetch evidence before this date.
- binaryRegex enables to filter on binary name, e.g evil.exe.
- hashRegex enables to filter on prefetch hash.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts execution timestamps from prefetch files and outputs them\nin timeline format.\n\nWindows keeps a cache of prefetch files. When an executable is run,\nthe system records properties about the executable to make it faster\nto run next time. By parsing this information we are able to\ndetermine when binaries are run in the past. On Windows10 we can see\nthe last 8 execution times and creation time (9 potential\nexecutions).\n\nThis artifact is a timelined output version of the standard Prefetch\nartifact. There are several parameters available.\n- dateAfter enables search for prefetch evidence after this date.\n- dateBefore enables search for prefetch evidence before this date.\n- binaryRegex enables to filter on binary name, e.g evil.exe.\n- hashRegex enables to filter on prefetch hash.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "binaryRegex": {
        "description": "Regex of executable name.",
        "format": "regex",
        "title": "binaryRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "dateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "dateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "dateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ssZ",
        "format": "velociraptor-timestamp",
        "title": "dateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "hashRegex": {
        "description": "Regex of prefetch hash.",
        "format": "regex",
        "title": "hashRegex",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "prefetchGlobs": {
        "description": "",
        "title": "prefetchGlobs",
        "type": "string",
        "x-velociraptor-default": "C:\\Windows\\Prefetch\\*.pf",
        "x-velociraptor-type": ""
      }
    },
    "title": "dynamic_artifact_116Arguments",
    "type": "object"
  },
  "name": "Windows.Timeline.Prefetch",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

<a id="tool-130"></a>

### 130. `Windows.Timeline.Registry.RunMRU`

功能描述（真实注册原文）：

Extracts RunMRU registry entries from user hives and outputs them
in timeline format.

RunMRU is updated when a user enters a command into the START > Run
prompt. Entries will be logged in the user hive under:
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

The artifact numbers all entries with the most recent at reg_mtime
starting at 0. Second recent 1, Third recent 2 etc.

Default output enables a line per MRU entry. The boolean parameter
`groupResults` enables Grouped results with ordering.

Note: This artifact will collect RunMRU from `ntuser.dat` files and
may exclude very recent entries in transaction (HKCU).  Future
versions of this content might address this gap.

调用语义：遵循第2—3节动态collection规则；仅返回Flow引用，最终结果用Flow接口读取。参数解释、默认值、枚举和格式完整保留在下方inputSchema。

完整接口定义（JSON；本节内自包含$defs）：

```json
{
  "description": "Extracts RunMRU registry entries from user hives and outputs them\nin timeline format.\n\nRunMRU is updated when a user enters a command into the START > Run\nprompt. Entries will be logged in the user hive under:\nSoftware\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\n\nThe artifact numbers all entries with the most recent at reg_mtime\nstarting at 0. Second recent 1, Third recent 2 etc.\n\nDefault output enables a line per MRU entry. The boolean parameter\n`groupResults` enables Grouped results with ordering.\n\nNote: This artifact will collect RunMRU from `ntuser.dat` files and\nmay exclude very recent entries in transaction (HKCU).  Future\nversions of this content might address this gap.\n",
  "inputSchema": {
    "additionalProperties": false,
    "properties": {
      "dateAfter": {
        "description": "search for events after this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "dateAfter",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "dateBefore": {
        "description": "search for events before this date. YYYY-MM-DDTmm:hh:ss Z",
        "format": "velociraptor-timestamp",
        "title": "dateBefore",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "timestamp"
      },
      "groupResults": {
        "description": "groups MRU entries to one message line",
        "title": "groupResults",
        "type": "boolean",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "bool"
      },
      "regexValue": {
        "description": "regex search over RunMRU values.",
        "format": "regex",
        "title": "regexValue",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      },
      "targetUser": {
        "description": "target user regex",
        "format": "regex",
        "title": "targetUser",
        "type": "string",
        "x-velociraptor-default": "",
        "x-velociraptor-type": "regex"
      }
    },
    "title": "dynamic_artifact_117Arguments",
    "type": "object"
  },
  "name": "Windows.Timeline.Registry.RunMRU",
  "outputSchema": {
    "additionalProperties": false,
    "properties": {
      "flow_id": {
        "title": "Flow Id",
        "type": "string"
      },
      "operation": {
        "title": "Operation",
        "type": "string"
      },
      "status": {
        "title": "Status",
        "type": "string"
      },
      "warnings": {
        "items": {
          "type": "string"
        },
        "title": "Warnings",
        "type": "array"
      }
    },
    "required": [
      "operation",
      "status",
      "flow_id"
    ],
    "title": "FlowReferenceResult",
    "type": "object"
  }
}
```

## 7b. 七个传输工具详细接口（2026-10-01 增量，取自 .232 live 快照）

### transfer_abort

Local guest transfer abort

输入 schema：

```json
{
 "properties": {
  "transfer_id": {
   "title": "Transfer Id",
   "type": "string",
   "minLength": 1
  },
  "request_digest": {
   "title": "Request Digest",
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  }
 },
 "required": [
  "transfer_id",
  "request_digest"
 ],
 "type": "object",
 "additionalProperties": false,
 "title": "transfer_abortArguments"
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_begin

Local guest transfer begin

输入 schema：

```json
{
 "properties": {
  "request": {
   "$ref": "#/$defs/TransferRequest"
  }
 },
 "required": [
  "request"
 ],
 "type": "object",
 "$defs": {
  "Budget": {
   "additionalProperties": false,
   "properties": {
    "max_files": {
     "exclusiveMinimum": 0,
     "title": "Max Files",
     "type": "integer"
    },
    "max_metadata_bytes": {
     "exclusiveMinimum": 0,
     "title": "Max Metadata Bytes",
     "type": "integer"
    },
    "max_logical_bytes": {
     "minimum": 0,
     "title": "Max Logical Bytes",
     "type": "integer"
    },
    "max_package_bytes": {
     "exclusiveMinimum": 0,
     "title": "Max Package Bytes",
     "type": "integer"
    },
    "min_free_bytes": {
     "minimum": 0,
     "title": "Min Free Bytes",
     "type": "integer"
    },
    "max_chunk_bytes": {
     "exclusiveMinimum": 0,
     "title": "Max Chunk Bytes",
     "type": "integer"
    },
    "max_duration_seconds": {
     "exclusiveMinimum": 0,
     "title": "Max Duration Seconds",
     "type": "integer"
    }
   },
   "required": [
    "max_files",
    "max_metadata_bytes",
    "max_logical_bytes",
    "max_package_bytes",
    "min_free_bytes",
    "max_chunk_bytes",
    "max_duration_seconds"
   ],
   "title": "Budget",
   "type": "object"
  },
  "Destination": {
   "additionalProperties": false,
   "properties": {
    "endpoint": {
     "enum": [
      "host",
      "guest"
     ],
     "title": "Endpoint",
     "type": "string"
    },
    "identity": {
     "additionalProperties": {
      "type": "string"
     },
     "maxProperties": 16,
     "minProperties": 1,
     "title": "Identity",
     "type": "object"
    },
    "canonical_path": {
     "minLength": 1,
     "title": "Canonical Path",
     "type": "string"
    }
   },
   "required": [
    "endpoint",
    "identity",
    "canonical_path"
   ],
   "title": "Destination",
   "type": "object"
  },
  "Evidence": {
   "additionalProperties": false,
   "properties": {
    "producer_complete": {
     "title": "Producer Complete",
     "type": "boolean"
    },
    "producer_quiescent": {
     "title": "Producer Quiescent",
     "type": "boolean"
    },
    "references": {
     "items": {
      "type": "string"
     },
     "minItems": 1,
     "title": "References",
     "type": "array"
    }
   },
   "required": [
    "producer_complete",
    "producer_quiescent",
    "references"
   ],
   "title": "Evidence",
   "type": "object"
  },
  "Package": {
   "additionalProperties": false,
   "properties": {
    "size": {
     "minimum": 0,
     "title": "Size",
     "type": "integer"
    },
    "sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Sha256",
     "type": "string"
    },
    "manifest_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Manifest Sha256",
     "type": "string"
    }
   },
   "required": [
    "size",
    "sha256",
    "manifest_sha256"
   ],
   "title": "Package",
   "type": "object"
  },
  "Source": {
   "additionalProperties": false,
   "properties": {
    "absolute_path": {
     "minLength": 1,
     "title": "Absolute Path",
     "type": "string"
    },
    "relative_path": {
     "minLength": 1,
     "title": "Relative Path",
     "type": "string"
    }
   },
   "required": [
    "absolute_path",
    "relative_path"
   ],
   "title": "Source",
   "type": "object"
  },
  "TransferRequest": {
   "additionalProperties": false,
   "properties": {
    "protocol_version": {
     "const": "velo.transfer.v1",
     "title": "Protocol Version",
     "type": "string"
    },
    "transfer_id": {
     "maxLength": 128,
     "minLength": 1,
     "title": "Transfer Id",
     "type": "string"
    },
    "request_digest": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Request Digest",
     "type": "string"
    },
    "direction": {
     "enum": [
      "pull",
      "push"
     ],
     "title": "Direction",
     "type": "string"
    },
    "sources": {
     "items": {
      "$ref": "#/$defs/Source"
     },
     "minItems": 1,
     "title": "Sources",
     "type": "array"
    },
    "expected_destination": {
     "$ref": "#/$defs/Destination"
    },
    "expected_vm_identity": {
     "$ref": "#/$defs/VmIdentity"
    },
    "evidence_context": {
     "$ref": "#/$defs/Evidence"
    },
    "budget": {
     "$ref": "#/$defs/Budget"
    },
    "package": {
     "$ref": "#/$defs/Package"
    }
   },
   "required": [
    "protocol_version",
    "transfer_id",
    "request_digest",
    "direction",
    "sources",
    "expected_destination",
    "expected_vm_identity",
    "evidence_context",
    "budget"
   ],
   "title": "TransferRequest",
   "type": "object",
   "allOf": [
    {
     "if": {
      "properties": {
       "direction": {
        "const": "push"
       }
      },
      "required": [
       "direction"
      ]
     },
     "then": {
      "required": [
       "package"
      ],
      "properties": {
       "expected_destination": {
        "properties": {
         "endpoint": {
          "const": "guest"
         }
        }
       }
      }
     },
     "else": {
      "not": {
       "required": [
        "package"
       ]
      },
      "properties": {
       "expected_destination": {
        "properties": {
         "endpoint": {
          "const": "host"
         }
        }
       }
      }
     }
    }
   ]
  },
  "VmIdentity": {
   "additionalProperties": false,
   "properties": {
    "vm_uuid": {
     "minLength": 1,
     "title": "Vm Uuid",
     "type": "string"
    },
    "boot_identity": {
     "minLength": 1,
     "title": "Boot Identity",
     "type": "string"
    },
    "vm_epoch": {
     "maxLength": 256,
     "minLength": 1,
     "title": "Vm Epoch",
     "type": "string"
    }
   },
   "required": [
    "vm_uuid",
    "boot_identity",
    "vm_epoch"
   ],
   "title": "VmIdentity",
   "type": "object"
  }
 },
 "additionalProperties": false,
 "title": "transfer_beginArguments"
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_capabilities

Local guest transfer capabilities

输入 schema：

```json
{
 "properties": {},
 "type": "object",
 "additionalProperties": false,
 "title": "transfer_capabilitiesArguments"
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_chunk

Local guest transfer chunk

输入 schema：

```json
{
 "properties": {
  "transfer_id": {
   "title": "Transfer Id",
   "type": "string",
   "minLength": 1
  },
  "request_digest": {
   "title": "Request Digest",
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  },
  "offset": {
   "title": "Offset",
   "type": "integer",
   "minimum": 0
  },
  "count": {
   "title": "Count",
   "type": "integer",
   "minimum": 1
  },
  "data_base64": {
   "type": "string"
  },
  "chunk_sha256": {
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  }
 },
 "required": [
  "transfer_id",
  "request_digest",
  "offset",
  "count"
 ],
 "type": "object",
 "additionalProperties": false,
 "title": "transfer_chunkArguments",
 "oneOf": [
  {
   "required": [
    "data_base64",
    "chunk_sha256"
   ]
  },
  {
   "not": {
    "anyOf": [
     {
      "required": [
       "data_base64"
      ]
     },
     {
      "required": [
       "chunk_sha256"
      ]
     }
    ]
   }
  }
 ]
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_chunks

Local guest transfer chunks

输入 schema：

```json
{
 "properties": {
  "transfer_id": {
   "title": "Transfer Id",
   "type": "string",
   "minLength": 1
  },
  "request_digest": {
   "title": "Request Digest",
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  },
  "offset": {
   "title": "Offset",
   "type": "integer",
   "minimum": 0
  },
  "chunks": {
   "type": "array",
   "minItems": 1,
   "maxItems": 64,
   "items": {
    "type": "object",
    "additionalProperties": false,
    "required": [
     "count",
     "data_base64",
     "chunk_sha256"
    ],
    "properties": {
     "count": {
      "title": "Count",
      "type": "integer",
      "minimum": 1
     },
     "data_base64": {
      "type": "string"
     },
     "chunk_sha256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
     }
    }
   }
  },
  "count_per_chunk": {
   "title": "Count Per Chunk",
   "type": "integer",
   "minimum": 1
  },
  "chunk_count": {
   "title": "Chunk Count",
   "type": "integer",
   "minimum": 1,
   "maximum": 64
  }
 },
 "required": [
  "transfer_id",
  "request_digest",
  "offset"
 ],
 "type": "object",
 "additionalProperties": false,
 "title": "transfer_chunksArguments",
 "oneOf": [
  {
   "required": [
    "chunks"
   ]
  },
  {
   "required": [
    "count_per_chunk",
    "chunk_count"
   ],
   "not": {
    "anyOf": [
     {
      "required": [
       "chunks"
      ]
     }
    ]
   }
  }
 ]
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_finish

Local guest transfer finish

输入 schema：

```json
{
 "properties": {
  "transfer_id": {
   "title": "Transfer Id",
   "type": "string",
   "minLength": 1
  },
  "request_digest": {
   "title": "Request Digest",
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  },
  "action": {
   "enum": [
    "prepare",
    "commit",
    "release"
   ],
   "title": "Action",
   "type": "string"
  },
  "prepare_receipt": {
   "$ref": "#/$defs/PrepareReceipt"
  },
  "source_validation_receipt": {
   "$ref": "#/$defs/SourceValidationReceipt"
  },
  "publication_receipt": {
   "$ref": "#/$defs/PublicationReceipt"
  }
 },
 "required": [
  "transfer_id",
  "request_digest",
  "action"
 ],
 "type": "object",
 "$defs": {
  "Destination": {
   "additionalProperties": false,
   "properties": {
    "endpoint": {
     "enum": [
      "host",
      "guest"
     ],
     "title": "Endpoint",
     "type": "string"
    },
    "identity": {
     "additionalProperties": {
      "type": "string"
     },
     "maxProperties": 16,
     "minProperties": 1,
     "title": "Identity",
     "type": "object"
    },
    "canonical_path": {
     "minLength": 1,
     "title": "Canonical Path",
     "type": "string"
    }
   },
   "required": [
    "endpoint",
    "identity",
    "canonical_path"
   ],
   "title": "Destination",
   "type": "object"
  },
  "DirectoryIdentity": {
   "additionalProperties": false,
   "properties": {
    "device": {
     "minimum": 0,
     "title": "Device",
     "type": "integer"
    },
    "inode": {
     "minimum": 0,
     "title": "Inode",
     "type": "integer"
    }
   },
   "required": [
    "device",
    "inode"
   ],
   "title": "DirectoryIdentity",
   "type": "object"
  },
  "PrepareReceipt": {
   "additionalProperties": false,
   "properties": {
    "type": {
     "const": "prepare",
     "title": "Type",
     "type": "string"
    },
    "binding": {
     "$ref": "#/$defs/ProtocolBinding"
    },
    "prepare_id": {
     "minLength": 1,
     "title": "Prepare Id",
     "type": "string"
    },
    "identity_digest": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Identity Digest",
     "type": "string"
    },
    "prepared": {
     "const": true,
     "title": "Prepared",
     "type": "boolean"
    }
   },
   "required": [
    "type",
    "binding",
    "prepare_id",
    "identity_digest",
    "prepared"
   ],
   "title": "PrepareReceipt",
   "type": "object"
  },
  "ProtocolBinding": {
   "additionalProperties": false,
   "properties": {
    "protocol_version": {
     "const": "velo.transfer.v1",
     "title": "Protocol Version",
     "type": "string"
    },
    "transfer_id": {
     "title": "Transfer Id",
     "type": "string"
    },
    "request_digest": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Request Digest",
     "type": "string"
    },
    "direction": {
     "enum": [
      "pull",
      "push"
     ],
     "title": "Direction",
     "type": "string"
    },
    "vm_uuid": {
     "title": "Vm Uuid",
     "type": "string"
    },
    "boot_identity": {
     "title": "Boot Identity",
     "type": "string"
    },
    "vm_epoch": {
     "title": "Vm Epoch",
     "type": "string"
    },
    "policy_id": {
     "title": "Policy Id",
     "type": "string"
    },
    "package_size": {
     "minimum": 0,
     "title": "Package Size",
     "type": "integer"
    },
    "package_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Package Sha256",
     "type": "string"
    },
    "manifest_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Manifest Sha256",
     "type": "string"
    }
   },
   "required": [
    "protocol_version",
    "transfer_id",
    "request_digest",
    "direction",
    "vm_uuid",
    "boot_identity",
    "vm_epoch",
    "policy_id",
    "package_size",
    "package_sha256",
    "manifest_sha256"
   ],
   "title": "ProtocolBinding",
   "type": "object"
  },
  "PublicationReceipt": {
   "additionalProperties": false,
   "properties": {
    "type": {
     "const": "publication",
     "title": "Type",
     "type": "string"
    },
    "binding": {
     "$ref": "#/$defs/ProtocolBinding"
    },
    "prepare_receipt_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Prepare Receipt Sha256",
     "type": "string"
    },
    "destination": {
     "$ref": "#/$defs/Destination"
    },
    "manifest_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Manifest Sha256",
     "type": "string"
    },
    "directory_identity": {
     "$ref": "#/$defs/DirectoryIdentity"
    },
    "publication_id": {
     "minLength": 1,
     "title": "Publication Id",
     "type": "string"
    }
   },
   "required": [
    "type",
    "binding",
    "prepare_receipt_sha256",
    "destination",
    "manifest_sha256",
    "directory_identity",
    "publication_id"
   ],
   "title": "PublicationReceipt",
   "type": "object"
  },
  "SourceValidationReceipt": {
   "additionalProperties": false,
   "properties": {
    "type": {
     "const": "source_validation",
     "title": "Type",
     "type": "string"
    },
    "binding": {
     "$ref": "#/$defs/ProtocolBinding"
    },
    "prepare_receipt_sha256": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Prepare Receipt Sha256",
     "type": "string"
    },
    "identity_digest": {
     "pattern": "^[0-9a-f]{64}$",
     "title": "Identity Digest",
     "type": "string"
    }
   },
   "required": [
    "type",
    "binding",
    "prepare_receipt_sha256",
    "identity_digest"
   ],
   "title": "SourceValidationReceipt",
   "type": "object"
  }
 },
 "additionalProperties": false,
 "title": "transfer_finishArguments",
 "allOf": [
  {
   "if": {
    "properties": {
     "action": {
      "const": "prepare"
     }
    },
    "required": [
     "action"
    ]
   },
   "then": {
    "not": {
     "anyOf": [
      {
       "required": [
        "prepare_receipt"
       ]
      },
      {
       "required": [
        "source_validation_receipt"
       ]
      },
      {
       "required": [
        "publication_receipt"
       ]
      }
     ]
    }
   }
  },
  {
   "if": {
    "properties": {
     "action": {
      "const": "commit"
     }
    },
    "required": [
     "action"
    ]
   },
   "then": {
    "required": [
     "prepare_receipt",
     "source_validation_receipt"
    ],
    "not": {
     "required": [
      "publication_receipt"
     ]
    }
   }
  },
  {
   "if": {
    "properties": {
     "action": {
      "const": "release"
     }
    },
    "required": [
     "action"
    ]
   },
   "then": {
    "required": [
     "prepare_receipt",
     "publication_receipt"
    ],
    "not": {
     "required": [
      "source_validation_receipt"
     ]
    }
   }
  }
 ]
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

### transfer_status

Local guest transfer status

输入 schema：

```json
{
 "properties": {
  "transfer_id": {
   "title": "Transfer Id",
   "type": "string",
   "minLength": 1
  },
  "request_digest": {
   "title": "Request Digest",
   "type": "string",
   "pattern": "^[0-9a-f]{64}$"
  }
 },
 "required": [
  "transfer_id",
  "request_digest"
 ],
 "type": "object",
 "additionalProperties": false,
 "title": "transfer_statusArguments"
}
```

输出 schema：

```json
{
 "type": "object",
 "oneOf": [
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "success"
    },
    "result": {
     "type": "object"
    }
   },
   "required": [
    "schema",
    "status",
    "result"
   ]
  },
  {
   "type": "object",
   "additionalProperties": false,
   "properties": {
    "schema": {
     "const": "velo.transfer.mcp.response.v1"
    },
    "status": {
     "const": "error"
    },
    "error": {
     "type": "object",
     "additionalProperties": false,
     "properties": {
      "code": {
       "type": "string",
       "pattern": "^[a-z][a-z0-9_]{0,79}$"
      }
     },
     "required": [
      "code"
     ]
    }
   },
   "required": [
    "schema",
    "status",
    "error"
   ]
  }
 ]
}
```

- 调用语义、方向序列与失败语义详见 `docs/transfer-mcp.md` 与 `docs/transfer-guest-engine.md`；批量块（transfer_chunks）仅当 policy 显式 max_batch_chunks 时提供，否则 fail-closed。
- 传输工具的 raw wire 校验（额外键、bool 整数替换、action/receipt 组合）在 handler 前发生（`invalid_transfer_arguments`），MCP `isError` 返回。

## 8. 更新与一致性检查（2026-10-01 增量后）

维护本文时使用同一部署的完整tools/list，检查名字集合与118＋12一致、无重复，并逐工具保留description/inputSchema/outputSchema、required、nullable、enum、pattern、默认值元数据及嵌套$defs。仅更新快照不能证明新实现验收通过；涉及功能变化同时更新公共规则。正文与现场不一致时核对部署版本和当前有效契约，不自动fallback旧名称或猜测缺失字段。

本文只新增文档，未运行产品测试、连接VM或改变部署。目录下其他执行者的未提交改动不属于本文交付。

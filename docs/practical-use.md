# 工具实际使用

当前工作方向是固定版本后使用现有工具，遇到实际问题再局部修复。全量场景、删件矩阵和成本比较不作为受控试用的前置任务；历史未完成验收仍保留原状态。

## 连接入口

### 已部署的 Windows HTTP 服务

在支持 Streamable HTTP 的 MCP 客户端中设置服务 URL：

```text
http://<guest-host-only-ip>:28790/mcp
```

通过客户端的秘密配置提供 `Authorization: Bearer <token>`。使用实际部署时的地址和 token；客户端配置格式以该客户端支持的字段为准。API 凭据留在桥接服务侧，无需交给远端 MCP 客户端。

记录服务实际部署版本，不能把仓库最新提交当作服务当前版本。日常 HTTP 默认 `VELOCIRAPTOR_MCP_OBSERVATION=off`；显式选择 `approved` 严格审计模式时，启动在连接后端或监听前检查固定批准来源、SDK 和私有 Windows 归档根，缺失或过期批准会报 `OBSERVATION_STARTUP_REJECTED`。这个错误需要处理实际部署输入，不能通过删除门禁或使用 MODEL 配置解决。

### Windows 服务启动与保活

正式服务启动文件是仓库根目录的 `velociraptor_windows_service.py`，它沿用已有 `tests/p05_service_host.py` 的 SCM 适配器，再调用同进程的 `mcp_velociraptor_bridge.main`。历史入口放在 `tests` 中是部署验收阶段的文件组织遗留。

已部署服务可在仓库根目录的管理员 PowerShell 中配置和核对：

```powershell
.\configure_windows_service.ps1 -Mode configure
.\configure_windows_service.ps1 -Mode verify
```

配置脚本只修改身份匹配的已有 `mcp-velociraptor` 服务，不安装新服务，也不重启正在运行的服务。正式入口变更后需重启一次使其生效。服务保持专用虚拟账户；启动类型为自动，进程崩溃的 SCM 恢复间隔为 10 秒，所有后续故障继续重启，故障计数 24 小时重置，非零退出恢复标志也开启。正常手动停止由 `mcp-velociraptor-keepalive` 任务在下一次每分钟检查时重新启动；任务也在系统启动时检查，执行者为 SYSTEM。保活仅在服务为自动且已停止时启动它，不处理正在启动、停止中的状态。

计划维护时先关闭保活，再正常停止服务：

```powershell
Disable-ScheduledTask -TaskName mcp-velociraptor-keepalive
Stop-Service -Name mcp-velociraptor
# 完成维护后
Enable-ScheduledTask -TaskName mcp-velociraptor-keepalive
Start-Service -Name mcp-velociraptor
```

把服务启动类型改为手动或禁用也会抑制保活；故障恢复设置独立保留。自动重启会结束当前 MCP 连接，客户端需要建立新会话。SCM 自动启动和任务的开机触发配置不等于已经完成实际整机重启验证。

目前停止命令可能返回 SCM 1061，但服务已正常停止；维护时应检查 `Get-Service mcp-velociraptor` 的实际状态。`.149` 的配置回读、崩溃恢复、正常停止保活及鉴权连接结果见 [服务核验记录](windows-service-verification.md)。

### 本机进程入口

同机 MCP 客户端可以使用现有 stdio 入口启动桥接进程。此入口共享工具业务实现，不加载正式 HTTP 的观察归档批准；它没有正式 HTTP 的归档与部署资格。原 README 将其定位为本地诊断入口，受控试用时需明确这一能力范围。

下面是已有 `mcpServers` 格式的示例，替换为本机的真实绝对路径；Windows 使用虚拟环境内的 `Scripts/python.exe`：

```json
{
  "mcpServers": {
    "velociraptor": {
      "command": "/absolute/path/to/venv/bin/python",
      "args": ["/absolute/path/to/repo/mcp_velociraptor_bridge.py"],
      "env": {
        "VELOCIRAPTOR_MCP_TRANSPORT": "stdio",
        "VELOCIRAPTOR_API_CONFIG": "/absolute/path/to/api_client.yaml",
        "VELOCIRAPTOR_DOWNLOAD_ROOT": "/absolute/path/to/existing/download-directory"
      }
    }
  }
}
```

使用具有所需组织和采集权限的 Velociraptor API identity。环境变量优先于 dotenv；可用 `VELOCIRAPTOR_ENV_FILE` 指定已有 dotenv 文件。凭据不要写入 Git 或问题日志。桥接进程的 stdout 用于 MCP，启动诊断输出到 stderr。

当前支持范围仍以 Windows Velociraptor 工作流为主；该配置示例不声明新增操作系统支持。历史 `agent_poc` 是单独的示例程序，不是连接这些工具的必需组件。

## 工具与日常流程

工具面为 118 个动态 Windows artifact、12 个固定工具和 7 个传输工具，共 137 项。启动会检查实际 root organization 的 artifact 定义；注册检查失败时应核对后端版本及定义，不能只修改计数放行。

没有受保护的 `VELOCIRAPTOR_TRANSFER_POLICY` 时，7 个传输工具仍列出，但 `transfer_capabilities` 报 disabled；原 130 个工具不依赖该 policy。先使用已有 DFIR 能力，有文件传输需求时再配置实际受保护的传输 policy。

| 操作 | 工具及注意事项 |
|---|---|
| 执行查询 | `run_vql` 接受 `query`，结果有上限；使用明确的查询范围。 |
| 采集 artifact | 使用客户端工具列表中的动态 artifact 名称和参数，不猜测工具名。 |
| 启动 Hunt | `start_hunt` 接受 `artifact`、可选 `parameters` 和 `description`；现实现创建 paused Hunt，并关联唯一 Windows client 的 Flow。 |
| 查看采集进度 | 保存返回的 `flow_id`，通过 `get_flow_status` 查看；Hunt 使用 `get_hunt_status`。 |
| 读取结果 | `get_flow_results` 使用同一 `flow_id` 与选定 `source`，按返回的 pagination/cursor 继续读取，直至没有下一页。 |
| 获取采集文件 | 先 `list_flow_files`，再把返回的 `file_id` 交给 `download_flow_file`；下载目录需预先存在，已有文件不覆盖。 |
| 单文件或基础 triage | `collect_file` 或 `collect_forensic_triage` 返回 Flow 引用，再沿上述进度、结果和文件流程读取。 |
| 主动结束工作 | 按实际需要调用 `cancel_flow`、`stop_hunt`；`stop_hunt` 不取消关联 Flow。`kill_process` 会结束目标进程。 |

例如可以向 MCP 客户端说明：“查询这台 Windows client 的网络连接，返回相关进程与连接信息。”先核对实际目标与返回结果，再开展更重的采集。注册数量、调用返回和实际业务结果分别记录，不把一次返回成功当作所有工具已验证。

## 问题处理

出现问题时保存使用版本、工具名、脱敏参数、client/Flow/Hunt 标识、时间、原始错误类型和可复现操作。对会创建 Hunt、采集、结束进程或写文件的调用，结果不确定时先查询状态，避免直接重放产生重复副作用。

只修复影响实际启动、连接和业务结果的问题，使用对应实际操作核对修复。保留鉴权、参数校验、资源上限及安全传输机制；不重新启动全量 645、删件或历史证明任务来替代实际问题处理。

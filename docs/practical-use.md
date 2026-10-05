# 工具实际使用

当前工作方向是固定版本后使用现有工具，遇到实际问题再局部修复。全量场景、删件矩阵和成本比较不作为受控试用的前置任务；历史未完成验收仍保留原状态。

## 连接入口

### 已部署的 Windows HTTP 服务

在支持 Streamable HTTP 的 MCP 客户端中设置服务 URL：

```text
http://<guest-host-only-ip>:28790/mcp
```

通过客户端的秘密配置提供 `Authorization: Bearer <token>`。使用实际部署时的地址和 token；客户端配置格式以该客户端支持的字段为准。API 凭据留在桥接服务侧，无需交给远端 MCP 客户端。

记录服务实际部署版本，不能把仓库最新提交当作服务当前版本。当前源码的 HTTP 启动在连接后端或监听前检查固定批准来源、SDK 和私有 Windows 归档根；缺失或过期批准会报 `OBSERVATION_STARTUP_REJECTED`。这个错误需要处理实际部署输入，不能通过删除门禁或使用 MODEL 配置解决。

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

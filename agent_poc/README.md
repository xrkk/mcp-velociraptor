# Velociraptor Agent POC

> Historical prototype only. `agent_poc` is not supported by the new
> Windows-only MCP bridge contract and is excluded from the current acceptance
> scope. The commands and architecture below document the existing prototype;
> they are not a compatibility promise for the bridge migration.

The P04 bridge itself has 118 dynamic Windows artifact tools plus 12 fixed
lifecycle tools. “Dynamic”
means their MCP schemas are generated from live Velociraptor metadata at process
startup, but only for an exact reviewed allowlist. They use the root organization
and the one Windows endpoint, start a Flow (one collection job), and communicate
over stdio (the MCP client's process pipes). The practical impact is:

| Term | Action and impact |
| --- | --- |
| Dynamic artifact tool | Starts its named artifact on the Windows VM and immediately returns a Flow reference. |
| Allowlist | Blocks unreviewed names or changed definitions before the bridge starts. |
| Root organization | Keeps metadata and collection operations in the bridge's fixed Velociraptor organization. |
| Flow | Identifies the endpoint job that later tools can inspect, page, or cancel. |
| Windows-only | Linux remains an unregistered TODO and macOS is unsupported. |
| stdio | Reserves stdout for MCP protocol data and sends startup diagnostics to stderr; it is the internal test transport. The production transport is a separate stateful Streamable HTTP entry on port 28790 with bearer authentication, which the agent code does not use. |

The historical agent code has not been migrated to those generated names or the
new structured result contract, so do not run it against the P03 bridge as a
compatibility test.

The historical Windows test environment used the post-install Snapshot 186
baseline, but restored fixture/process prerequisites have since failed
revalidation. P05 baseline repair is in progress; P06 must not treat the old
snapshot as a newly qualified starting point. PacketCapture and Autoruns resolve hash-locked binaries
from Velociraptor's local filestore, and the reviewed triage and process-ending
artifacts are installed there. This does not make dependency management part of
the MCP API: preparation remains an operator-owned test-infrastructure step.

P05's deterministic fixture and indexed scenario runner validate the bridge
through the official MCP Python SDK. They test the 130-tool bridge contract; the
historical agent in this directory is still excluded and should not be treated
as a compatibility client.

The test-only `tests/p05_process_parent.py` candidate has fixed `fixture`,
`frontend`, and `client` roles to retain parent identities. It is neither a
product launcher nor an agent feature, and cannot replace a running predecessor
or bypass baseline review and activation. No new baseline is yet activated.

The operator has removed the previous acceptance snapshots and retained a
fixed-IP baseline that is still being requalified. Historical recovery and
qualification instructions below are not current execution authorization.
The candidate P05 service installer requires measured guest `-BindAddress`,
single host `-HostAddress`, and a deployment `-AttemptId` UUID, plus the repo
and protected-env paths. It uses the SCM host and checks exact identities;
rollback requires matching creation ownership and a stopped service. It does
not alter the static IP or Windows-MCP startup. Windows validation is pending,
and install/verify reject noncanonical local paths and reparse-point traversal
before reading the protected configuration. They check protected-file ACLs
before reading secrets, read-only service code, and service-writable download/log
directories without repairing ACLs or settings. Deployment approval still
requires the P05 Windows gates. The service host no longer writes
deployment environment values or partial bearer tokens to a diagnostic file.
SCM callback signatures have Windows-only regression tests pending execution.
The candidate reports running after HTTP startup and forwards service stop
requests to graceful HTTP shutdown in the same process, without stopping the
Velociraptor backend. Actual Windows lifecycle acceptance remains unfinished.
An existing matching manual/automatic startup mode is preserved and reported;
new installations remain manual until separate P05 readiness/autostart checks.

The candidate service host stops startup if its deployment environment file or
reference is missing. Its registry lookup reads only the installer's string
`VELOCIRAPTOR_ENV_FILE` reference, not arbitrary environment values. Direct
stdio and historical agent configuration precedence are unchanged. The service
requires explicit HTTP mode/host/token, API config and download root; missing,
duplicate or conflicting inherited settings stop startup. The service
host discards raw bridge stderr and logs a fixed public failure code,
explanation and exit code for configuration, imports, registry validation,
backend connection or HTTP execution; raw exception text and credentials are
not persisted. These changes still need Windows behavior validation.

The deployment-only P05 observer adds a local process-bound dispatch counter,
not another endpoint or authentication path. It checks the pinned SDK security
boundary and joins counter observations to the actual service process and HTTP
instance header; it records no token or request body. The updated candidate
still needs Windows verification. P05 three-chain stdio runs retain raw SDK
messages and stderr under new UUID directories without inheriting the HTTP
token/protected-env reference. This does not supply complete network-window
proof or replace the snapshot activation gates.

For the reviewed `Windows.Memory.Acquisition` tool only, the bridge internally
requests a 3600-second collection timeout and an 8 GiB upload ceiling so a full
image of the accepted 4 GiB VM is not cancelled by Velociraptor's default 1 GiB
per-collection limit. Callers cannot change this ceiling, and other artifacts
retain their ordinary resource defaults. P06/P07 acceptance is currently reopened;
the new resource qualification and admission implementation is under verification,
not a claim that the five formal scenarios have passed again.

The P06 resource qualifier runs outside the VM with the official SDK against
`http://<guest-host-only-ip>:28790/mcp`, using the deployer's token from
`VELOCIRAPTOR_MCP_BEARER_TOKEN`. It requires complete original Snapshot 188
restore evidence, the unchanged fixture-instance copy, and the guest service
observation in the fixed `Logs/P06/wf-01a05d1d-p06-r3/` root; the qualifier
does not accept an evidence-root override. The Windows test-control channel reads resource counters only;
it never proxies product calls or supplies coverage. Formal scenarios consume
an explicitly selected, byte-verified qualification budget and reject missing
observations, low space, identity changes, or expired deadlines. Neither the
historical agent nor a VM-local stdio test can substitute for this external
qualification. See the main README for the test command and evidence inputs.
The separate individual error-contract acceptance command also uses external
HTTP, its own restored attempt, and zero coverage; neither command uses this
historical agent or overwrites earlier evidence.

Snapshot 187 is now the administratively adopted preparation baseline only
(schema 5 / epoch 5). P06 requires Snapshot 188 activation at schema 5 / epoch 6
after initial acceptance and two complete candidate recovery cycles; adoption
does not certify the product.

### Setup
```bash
.venv/bin/python -m pip install -r requirements.txt
cp example.env .env
ollama pull gemma4:e2b
```

### Usage
```bash
export VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml
export VELOCIRAPTOR_MODEL_PROVIDER=ollama
export OLLAMA_MODEL=gemma4:e2b
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t engagement
```

Use Azure OpenAI with:
```bash
export VELOCIRAPTOR_MODEL_PROVIDER=azure
export AZURE_OPENAI_ENDPOINT=https://example-resource.openai.azure.com
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_MODEL=gpt-5.4-mini
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t engagement
```

For Azure OpenAI, `AZURE_OPENAI_MODEL` is the model/deployment name passed to
the API. Azure OpenAI mode sends the pre-collected evidence bundle to the
configured Azure API account for model summarization. Keep
`VELOCIRAPTOR_MODEL_PROVIDER=ollama` when endpoint evidence must remain local.

Historical prototype option only (not part of the new fixed-root contract):
```bash
export VELOCIRAPTOR_ORG_ID=O123
```

Run a different workflow with:
```bash
export VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml
export VELOCIRAPTOR_MODEL_PROVIDER=ollama
export OLLAMA_MODEL=gemma4:e2b
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t process
```

Choose a readable text view instead of JSON with:
```bash
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t process --output-type text
```

Enable verbose MCP client diagnostics with role labels, collection names, row counts, and summarization progress:
```bash
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t engagement --output-type text -v
```

### Analysis Types
- **triage**: Quick check (processes, network, client info)
- **process**: Single-role process analysis
- **network**: Network connection analysis
- **persistence**: Scheduled task and service review
- **execution**: Evidence of execution artifacts
- **user_activity**: User activity, logon, browser, and shell-history review where supported
- **system_inventory**: Generic OS inventory such as users, groups, mounts, removable storage, and host state where supported
- **filesystem**: Focused filesystem/storage artifact review
- **security**: Security event and detection artifact review
- **engagement**: Bounded manager-led investigation across process, network, persistence, execution, user activity, and system inventory roles
- **deep**: Expanded investigation that also includes filesystem and security roles
- **full**: Alias for `engagement`

### Multi-Agent Design
- One deterministic engagement manager resolves `client_info`, selects analysts, and synthesizes the final case summary.
- Each analyst runs in a separate MCP session with its own conversation history.
- Evidence collection is deterministic in code. The model is used to summarize a pre-collected evidence bundle rather than choose tools free-form.
- Tool access is filtered dynamically per analysis type. For example, `execution` only gets execution tools, `engagement` gets bounded analyst roles, and `deep` opts into heavier filesystem and security roles.
- The historical agent source contains Windows, Linux, and macOS role sets, but
  the current bridge registers only the reviewed Windows surface. Those old role
  sets and their generic collection calls are not compatible with P03.

### Integration Examples

These examples wrap the current host-focused `analyze_endpoint()` workflow.
They are suitable for calling the agent on one endpoint at a time from another
service or scheduler.

#### 1. API Endpoint (FastAPI)
```python
from fastapi import FastAPI
from agent_poc.mcp_agent import VelociraptorAgent

app = FastAPI()
agent = VelociraptorAgent()

@app.on_event("startup")
async def startup():
    await agent.initialize()

@app.post("/analyze/{hostname}")
async def analyze(hostname: str, analysis_type: str = "triage"):
    return await agent.analyze_endpoint(hostname, analysis_type)
```

#### 2. Scheduled Task (APScheduler)
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from agent_poc.mcp_agent import VelociraptorAgent

agent = VelociraptorAgent()
scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('interval', hours=4)
async def sweep_endpoints():
    critical_hosts = ["DC01", "WEB01", "DB01"]
    await agent.batch_analyze(critical_hosts, "triage")

scheduler.start()
```

#### 3. Alert Webhook Handler
```python
@app.post("/webhook/alert")
async def handle_alert(alert: dict):
    hostname = alert.get("hostname")
    if alert.get("severity") == "high":
        # Immediate deep analysis
        results = await agent.analyze_endpoint(hostname, "full")
        # Send to SOAR platform, ticketing system, etc.
        return results
```

### Output
Results are automatically saved to `./agent_poc/output/` as JSON files:
```
agent_poc/output/
  ├── WIN10-WS_engagement_20240115_143022.json
  ├── DC01_full_20240115_150033.json
  └── ...
```

Each result now includes:
- top-level case metadata such as `workflow`, `hostname`, `client_id`, `org_id`, `os_type`, and timestamps
- `manager_summary` for the final case-level synthesis
- `analysts` keyed by role with status, summary, allowed tools, timestamps, and duration
- `errors` and `skipped` for failed or unsupported analysts

## Configuration

Edit `agent_poc/mcp_agent.py` to customize:
- Model selection
- Output directory
- Workflow definitions
- Custom analysis logic

This POC agent is designed for per-host analysis. Cross-endpoint hunting,
global IOC correlation, and autonomous scope expansion are not first-class
features in the current implementation and should not be assumed from these
examples.

The bridge, smoke script, and agent load dotenv config automatically without
overriding variables already supplied by your shell or MCP client. Keep `.env`
and the referenced `api_client.yaml` local and out of version control. Set
`VELOCIRAPTOR_ENV_FILE=/path/to/.env` when an MCP client should load a dotenv
file from somewhere other than the repo root.
Set `VELOCIRAPTOR_DEBUG_VQL=1` only when you want raw VQL request logging on
stderr for debugging.
Set `VELOCIRAPTOR_AGENT_VERBOSE=1` only when you want MCP client connection,
collection progress, and tool-call diagnostics from the agent runtime without
using the CLI `-v` flag.
The agent reads `VELOCIRAPTOR_MODEL_PROVIDER` from the environment or `.env`
and defaults to `ollama`. Ollama mode reads `OLLAMA_MODEL` and defaults to
`gemma4:e2b`. Azure OpenAI mode reads `AZURE_OPENAI_MODEL`, requires
`AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`, requires
`AZURE_OPENAI_API_KEY`, and defaults to `gpt-5.4-mini`.
Each `analyze_endpoint()` run resets prior manager chat state, and each analyst
uses its own isolated MCP session and conversation history.
The current bridge fixes dynamic artifact calls to the root organization and
internally resolves the one Windows endpoint. Old `org_id`/hostname/client
examples in this historical prototype are not supported by that contract.
The dangerous-tools switch has been physically removed from the bridge source
tool. P07 has removed it physically.

The current bridge returns MCP-native `structuredContent` from both dynamic and
fixed tools. This historical agent still expects older tool names and response
handling, so it is not a compatibility client for P04.
`collect_artifact` is no longer registered. Call the exact approved Windows
artifact tool and pass its generated structured arguments instead.
The fixed surface includes bounded VQL, Hunt and Flow lifecycle, one-file
collection/download, basic triage, and process termination. File retrieval is
explicit: list a Flow's uploads, then download one `file_id` beneath the
existing absolute `VELOCIRAPTOR_DOWNLOAD_ROOT`; completed files are not
overwritten. Hunt stop and Flow cancel are separate operations.
The bridge no longer exposes the old Linux, macOS, generic collection, or
artifact-discovery wrappers. The 12 P04 fixed tools are not a compatibility
guarantee for this historical agent.

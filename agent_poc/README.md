# Velociraptor Agent POC

`velociraptor_observation.py` is an independent, opt-in in-memory request
observer. Controlled tests explicitly construct `RequestObserver` with a service
instance and positive request/event/byte budgets and install its middleware.
It observes only HTTP `tools/call`, preserves session and typed request IDs,
hashes canonical arguments, and shares one locked scope with the default SDK
synchronous worker. `emit` requires a current parent and strict JSON facts;
invalid input, duplicate parents and exhausted budgets refuse without replacing
an existing event prefix. Snapshots are independent copies; incomplete scopes
require explicit diagnostic reads and cannot be exported as complete records.
Cancellation may leave a synchronous worker running: sealing follows its actual
awaited exit, and tail facts retain the original parent. Detached/custom worker
chains are unsupported. Returned `isError` is still a returned protocol result.

The bridge and historical agent do not enable this module. It adds no tools,
parameters, headers, CLI/environment switches, RPCs or persistent archive and is
not yet part of the production freeze/catalog. Business fact hooks, controlled
archival and host association require separate contracts and integration.
Loopback SDK/model tests do not qualify Windows, real client/Flow identity,
pagination completeness, Admission or P07 costs.


The read-only recovery selector now consumes the fixed PC026 runtime record
and exact READY approval under `PLAN/2026.10.02/`, from its code-owned repository
root. It checks the adopted interface hash, independent exact Ref allowlist,
complete implementation/bootstrap/publication identity and ACL archive, then
rechecks file identities and bytes before returning a selection. Missing records,
unsafe paths, drift, old 189 evidence and incomplete COMMITTED transitions produce
no recovery argv. There is no CLI/environment policy or root override. The
explicit isolated fixture seam verifies complete 191 content while preserving
historical 448+4 originals and the old 189 verifier defaults. This reader never
publishes evidence, writes canonical state, mints capabilities or executes VMware.
Native Windows observations, service-principal/default ACL qualification and
actual READY issuance remain separate. Current P06 restore, receiver and
aggregate entrypoints retain the same fixed approval and qualify the complete
191/C8 graph plus eight restore kinds. Success receipt admission precedes lock
and ledger writes; duplicates are rejected before a lock. Failed attempts keep
zero coverage and their original failure preservation rule. Aggregation requires
five independent restores and the unchanged 129 × 5 = 645 relation set, while
resource qualification must use that same current graph and 137-tool face.
Every consumed package/selection is retained for a final drift recheck. Historical
restore and aggregate verifiers are explicitly named `verify_historical_restore`
and `aggregate_historical`; historical 188/189/schema3 inputs cannot qualify the
current entrypoints. There is no automatic approval creation or test-root CLI.

The fixed PC026 P07 handoff command is `python -m tests.p07_handoff`;
`python -m tests.p07_handoff --verify` only reads and verifies the existing
`Logs/P06/wf-01a05d1d-p06-r3/p06-handoff.json`. Both use the code-owned
repository, approved 04/05/06 contracts, complete current 191 graph and strict
five-report aggregation. The private controller completion record at
`PLAN/2026.10.02/p06-completion-record.json` stays outside the original runtime
allowlist, approval and freeze. It binds the current approval/selection, actual
Git blobs for every frozen code/resource member, and two distinct new
implementation/independent-check records; a schema-valid synthetic record does
not prove real independent acceptance. The handoff binds the exact recomputed
aggregate bytes and selected evidence closure. Creation is exclusive; identical
existing bytes can be verified, while conflict or drift refuses without replacing
or deleting evidence. A failed final recheck can leave an untrusted output.
Missing production approval/completion prevents publication. Both P07 cost
entrypoints verify this handoff and still refuse the undefined current five-pair
collector. Local synthetic host tests do not qualify Windows service ACLs,
formal P06/645 execution, independent acceptance or cost measurement.

P07 current entrypoints enforce the approval/P06 handoff and refuse historical
cost output. A current upstream five-pair collection binding still needs a controller
contract; current P07 cost production is not complete. The adopted Windows
reader contract keeps the same exact approval model and independent allowlist,
with separately pinned 04/05 interfaces. Platform selection uses the real OS
and the code-owned repository. Windows binds actual TokenUser, full raw
owner/group/DACL/SACL, FileIdInfo, metadata and bytes on retained handles,
rejects reparse/alias paths and checks conservative ancestor/private-file ACLs.
It requires an already assigned SeSecurityPrivilege to read the complete SD;
the scoped enable restores its prior token state. Missing privilege or partial
ACL observation refuses admission. It adds no trusted SID or root override.
Each side compares only its own live publication identity while checking both
archived originals. Consumers recheck before business stages and close retained
handles at the outer consumption boundary; drift preserves failed facts with
zero coverage. Actual service-principal/default ACL qualification and complete
native consumer execution remain unverified; the external HTTP client boundary
still applies. Explicit historical measurement
functions preserve old calculations, without declaring current acceptance.
Isolated host fixtures verify consumer content and rejection boundaries; they
are not real recoveries, 645 business executions or measured cost achievements.
The historical agent does not acquire a recovery feature.

The implementation freeze requires an explicit reviewed local-module catalog,
parent package initializers, and non-Python resources including the transfer
wire/tool schema. Candidate omissions remain semantic failures after every
surviving approval/publication/allowlist hash is rebound. The synthetic fixture
copies this declared closure; an isolated subprocess loads wire, all seven tool
schemas, the bridge and governance/selector modules without reading project code
or resources from the original repository. Installed third-party dependencies
are allowed. This validates loading and read-only closure, not live backend,
Windows publication, service ACLs, or production READY qualification. Resources
and dynamic helper dependencies must be maintained when those entries change.

PC026 VBT1 now uses the same formal HTTP app, bearer, process instance and live session established by the official SDK. Strict frames and headers validate complete payloads before the existing guest engine runs. Actual request/response stream counters enforce the 100 MiB body limit, including JSON/SSE wrappers; chunk, header, batch and guest policy limits remain stricter where applicable. The client negotiates binary once on that session, preserves HTTP error codes and never replays an uncertain write through another encoding. stdio and unsupported session managers advertise `binary_wire:null`. Local and isolated Windows verification use development fixtures; formal port 28790, service-principal/default ACL and source firewall qualification remain pending.

Non-200 binary responses are classified from exact HTTP safety JSON before checking the instance header: a genuine bearer rejection is `unauthorized` even without that header. HTTP 200 still requires the bound instance and full frame validation; malformed safety responses remain `protocol_error`. Unknown writes keep their reconciliation requirement and are never replayed or switched to JSON. Linux ASGI composition and loopback HTTP checks cover these client gates; they do not qualify the formal Windows deployment.

Batch continuation after a real prefix-verification worker now budgets both ownership registration and the final durable state with the consumed proof cleared. Invalid batches and state-budget rejection preserve the original proof and payload bytes; a legal batch invalidates the proof when writing begins. Regression tests link the host coordinator to the actual guest engine and workers for uncertain writes and subsequent batches. The test module now defers the Linux-only host coordinator import so its five guest cases run on Windows. All seven Linux cases and five isolated Windows cases pass; Windows uses the existing process-only `S-1-5-11` fixture grant. Default Windows ACL and service-principal qualification remain unverified; overall T012/P05 acceptance remains partial.

PC026 now persists a worker-bound prefix verification only after full payload/ledger checks in the same protected state revision. Resume reuses the original deadline; writes, cancellation and revalidation clear the proof, and foreign tails are never truncated. Legacy state without a proof requires bounded revalidation.

The host persists exact sent chunk records and reconciles an unknown write through status and one same-request begin with a new verification nonce. It resumes only from the complete durable proof checked against those records; it does not replay an uncertain batch or switch its encoding. Only an explicit pre-action batch rejection permits single chunks. The full prefix is reverified before finish. Transfer requires all seven tools and negotiates VBT1 only when the same official SDK session advertises it; a null capability uses JSON from the start. Historical prepare/commit receipts remain readable after release without starting another worker. Local and isolated Windows tests are development evidence; default Windows ACL qualification and formal deployment remain separate.

PC026 scoped implementation now prevalidates the complete JSON batch (including every decoded hash and total ledger/disk budget) before payload writes. Valid I/O failures retain an owned unacknowledged tail for bounded recovery. This is local development work; formal Windows acceptance and deployment remain separate. The VBT1 implementation has scoped development verification; formal Windows deployment remains separate.

The current bridge now registers seven local guest transfer MCP tools (PC024 six plus the `transfer_chunks` batch increment) alongside its original 130 tools. They require a protected guest policy for transfer work and do not use this historical agent prototype. See [transfer MCP contract](../docs/transfer-mcp.md) and [guest engine documentation](../docs/transfer-guest-engine.md). Windows VM and host coordination remain unaccepted.

Host transfer uses `python -m velo_transfer --spec /absolute/path/to/request.json`, with the original spec and `resume:true` for recovery or `--abort` for cancellation. Locally proven completion returns `complete` (exit 0); a host cleanup fault retains evidence as `cleanup_pending` (exit 5). An invalid connection profile returns one `velo.transfer.command-error.v1` JSON object with `error=invalid_profile` and exit code 3, without a result path. See [host coordinator](../docs/transfer-host-coordinator.md) and [host cleanup](../docs/transfer-host-cleanup.md). This historical agent is not the caller for that command.

PC024 keeps the original DFIR 118 dynamic plus 12 fixed registrations separate from the transfer tools (six-tool matrix plus the registered batch increment): PacketCapture is one recorded exclusion, 129 original tools require real individual success and 645 five-scenario relations, while transfer uses its own real push/pull, failure and global-result matrix. The locally proven host `complete` path preserves its existing CLI/cleanup description above; formal COMPLETE also requires destination proof, both owned cleanups, bound receipts and durable result evidence on the Windows path. The historical agent remains outside both acceptances. Missing transfer policy must not tighten the original 130-tool startup gate; transfer policy/ACL/VM identity and HTTP Bearer/Host/Origin checks remain required for the added path, with internal integrity hashes retained.

Snapshot 186/188 references below describe historical generations. Current P05/P06 use only the canonical activated source and verified restore evidence; no local guest substitute or old snapshot record qualifies this agent or transfer path.

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
Velociraptor backend. The local candidate reports `STOP_PENDING` before that
signal, checks native status-report failures, and reports `STOPPED` once. These
failures use the fixed `SERVICE_STATUS_FAILED` category and a nonzero exit.
These stop changes are not deployed to the running Windows service; actual Windows
lifecycle acceptance remains unfinished.
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

The fixed no-argument `collect_forensic_triage` entry separately requests the
complete `Windows.Triage.Targets` `_BasicCollection` once, with a 2400-second
timeout and a 4 GiB (`4294967296`-byte) upload budget. The budget is private to
that entry: a generic call to the same artifact and all other collection paths
keep their prior defaults. It is measured from pre-compression
`FileBuffer.DataLength` blocks, with cancellation only after the accumulated
value is strictly greater than the cap; parallel or in-flight data can exceed
it. It is not a disk/network limit, MCP file quota, or caller-controlled
setting. The local source and isolated request fixtures implement this rule,
but it is not deployed and does not replace P05 source locking, initial plus
two recovery acceptances, or later P06 qualification.

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
The current fixed startup contract distinguishes control-call completion from
backend work: `collect_file`, `collect_forensic_triage`, and `kill_process`
return required `state`, while `start_hunt` returns Hunt `state` plus required
Flow `flow_state`. The first immediate backend value is preserved, including
`ERROR`; clients must inspect it rather than treating `status="success"` as a
successful collection outcome. Missing or empty initial state is a
`BACKEND_ERROR`.
The bridge's `start_hunt` now validates nested artifact parameters with the
same startup-verified types, options and regex rules as dynamic tools before
creating any Hunt or Flow. Explicit `null`, unknown/hidden/upload parameters,
wrong types and invalid choices fail; omitted parameters retain backend
defaults. Linux-host service/SDK tests use a fake backend, and Windows real
Hunt/Flow acceptance remains pending. This does not qualify the historical agent.
`run_vql` executes in the root organization through
`SELECT * FROM query(query=<encoded query string>) LIMIT 251`. The API quotes
the complete query as a string, preserving quotes, backslashes, newlines and
Unicode without rewriting its VQL. Client reads remain bounded at 251 rows;
responses retain the 250-row / 245554-byte limits and accurate `truncated`.
Linux-host tests inspect real protobuf requests with a gRPC stub; deployed
Windows parser and server-side execution acceptance remain pending.

For `get_flow_results`, `v1:<offset>` is interpreted only in the explicitly
supplied `flow_id`/`source` context. A paged response always carries
`pagination.next_cursor`: a string for another page or JSON `null` at the end;
unpaged responses omit `pagination`. This historical agent has not been updated
or qualified for those additions. The isolated contract work does not deploy
the locally implemented PC017 logical-file download support, and the separate
triage budget is likewise only locally implemented and isolation-tested.
`collect_artifact` is no longer registered. Call the exact approved Windows
artifact tool and pass its generated structured arguments instead.
The fixed surface includes bounded VQL, Hunt and Flow lifecycle, one-file
collection/download, basic triage, and process termination. File retrieval is
explicit: list a Flow's uploads, then download one `file_id` beneath the
existing absolute `VELOCIRAPTOR_DOWNLOAD_ROOT`; completed files are not
overwritten. Hunt stop and Flow cancel are separate operations.

The list is a logical-source-file view: validated sparse `Type="idx"` range
metadata stays internal and is disclosed only as
`sparse_indexes_internal:<count>`, while a naturally named `.idx` source file
is still listed. Sparse download adds one complete compact read before padded
logical reconstruction; returned size/SHA-256 cover the delivered logical
bytes, and there is no raw compact/index export. Publication uses a
non-overwriting hard link. A post-publication validation or owned-part cleanup
failure returns `BACKEND_ERROR/download_post_publish_failed` without a success
payload, but the completed file or owned `.part` may remain; callers must not
automatically retry or overwrite it. Cleanup never deletes completed files or
objects whose safe ownership cannot be proved. No download quota, retention,
or automatic cleanup policy is supplied by this interface.
The bridge no longer exposes the old Linux, macOS, generic collection, or
artifact-discovery wrappers. The 12 P04 fixed tools are not a compatibility
guarantee for this historical agent.

Unpaired uploads whose enumerated `file_size` differs from `uploaded_size`
remain visible with `collection_size_mismatch:<count>` and bounded per-file
`possible_file_modified_during_collection:<file_id>:file_size=<n>:uploaded_size=<n>`
warnings. Both original sizes are preserved. This may reflect a file changing
during collection; the metadata alone cannot rule out an incomplete upload or
missing sparse index. It does not prove a consistent source snapshot. Downloading
that uncertain entry fails with `BACKEND_ERROR/size_mismatch` before content I/O
or output creation; other valid files in the same Flow remain usable. Paired sparse
metadata, identity/selector conflicts, and invalid numeric sizes remain strict.


Current PC026 P06 evidence includes one `call-clock.json` per admitted new
five-scenario run. It binds the final original `report.json` bytes, run ID,
runner identity and a fresh clock ID to the process's real
`time.monotonic_ns` implementation. Every tool-call observation, including
retry and cleanup, carries `monotonic` with `clock_id`, `invoked`,
`started_ns` and `ended_ns`. Pre-call refusal records `invoked=false` with
two null endpoints; a returned error or SDK exception retains its interval.
Clock failure stops new calls and preserves a failed report with no coverage.

The current receiver, aggregator and fixed P07 handoff require matching
clock/report identities and ordered, non-overlapping intervals. The package
includes the clock original. Historical evidence, resource qualification
and individual acceptance keep their existing contracts; old reports must
not be repaired with invented timestamps. `invoked` observes the SDK method,
not a proven wire request. UTC timestamps are display data, and summing
individual `duration_ms` values cannot measure a subchain containing waits.
Call timing alone does not establish raw-message completeness, client/Flow
binding, pagination completion, environment comparability or P07 cost
success. These additions require a new actual source freeze and approved
run; local SDK tests do not constitute Windows acceptance.


`tests/p06_http_body_capture.py` provides transport-body capture
infrastructure for PC026 HTTP body originals. `CaptureTransport` wraps
the installed httpx2 transport used by the official MCP SDK, preserving each
request/response chunk before JSON/SSE parsing and before response
Content-Encoding decoding. It records transport-level body bytes, not TCP/TLS
packets or raw HTTP headers; capture adds real persistence overhead.

The caller supplies its own new admitted run directory and canonical run UUID.
The module exclusively creates `raw-mcp`, incremental body files, and a
fsynced `capture.json` index. EOF, early close, cancellation, error and
unstarted directions remain distinct. Stream failures retain prefixes and
propagate normally; local capture faults propagate and prevent a complete
record. Only response Content-Type/Content-Encoding and status are indexed;
authentication headers and environment values are not collected.

`RECORDED` means the observer closed normally, including incomplete or failed
HTTP exchanges. The read-only verifier checks original files and exact
structure, without granting business success. Failed index staging remains
unpublished. The current admitted five-scenario HTTP runner now uses this
capture inside its header observer. Qualification, individual acceptance and
historical capture rules retain their boundaries. Local loopback SDK and
stream-model tests do not establish Windows acceptance.


`tests/p06_mcp_raw_join.py` now provides an independent read-only
`join(run_dir)` helper for a successful current schema-2 report, its original
capture and validated call clock. It returns an in-memory association with
exact original content Refs and frame locations; it never publishes or repairs
run files. Requests are indexed by globally unique, type-sensitive JSON-RPC IDs
and matched to the report in request order. Complete SDK CallToolResult values
are compared after legitimate defaults and known null omission; ignored
extensions, duplicate/replayed IDs, hidden calls and missing responses refuse.

Decoding supports strict UTF-8 JSON and incrementally read SSE, including BOM,
CR/LF/CRLF, comments and multiple data lines. Identity and one complete gzip
member are supported; truncated trailers, additional members, unknown encodings,
invalid UTF-8, incomplete frames and server-initiated requests refuse. A closed
SSE stream is usable only with complete dispatched frames and a complete gzip
trailer when compressed. Reconnection with ID reuse or identical response replay
is not supported. A 128 MiB per-message/line bound refuses explicitly rather
than truncating or buffering an entire SSE stream.

The current production code path now recomputes this association through the
same Admission security reader. Its POSIX or retained native Windows handle,
owner and complete ACL checks also lock raw-body content; parsing and content
hashing stay incremental. This does not issue admission approval. The governed
catalog includes capture, join and binding code/tests plus the adopted 01/02/03
resources alongside 04/05/06/07. A new real freeze, deployment and approval are
still required before Windows execution.

`tests/p06_http_binding.py` checks one raw initialize and one actual tools/list,
the complete SDK listing, and every captured HTTP response against its original
header observation. The local response extension `pc026_capture_sequence`
identifies the exchange even when GET/POST finish out of order; it is never an
HTTP header. Sequence collisions refuse. Initialization supplies the real
session and service instance, and later request/response identities must match.
No authentication headers are saved.

After the SDK and HTTP client close and capture settles, the runner saves all
headers, final report and clock, then exclusively publishes canonical
`mcp-raw-join.json` and exact-eight-key `mcp-http-binding.json` before sealing
the package. Current successful Admission/receiver/aggregate/handoff consumption
requires and recomputes all these originals, their full raw directory and actual
listing, retaining them for final drift checks. Failures preserve already
observed calls and residual files with empty coverage; they do not repair clock,
join or binding originals or replay an uncertain receipt append.

Real loopback SDK tests use an actual SDK session and a server-generated instance
header. Complete synthetic 191 graphs exercise current consumer/package gates;
their Windows identities and business observations remain modeled. They do not
prove formal service ACLs/191 acceptance, actual client/Flow or pagination
completion, environment comparability or cost success. Both P07 cost entrypoints
retain their refusal of the undefined current collector.

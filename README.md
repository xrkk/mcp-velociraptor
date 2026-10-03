# Velociraptor MCP

TargetContext now emits an exact internal whitelist when a request scope is
present: actual resolution/cache hits, operation begin/end, existing existence
probes and actual cache clears. Per-operation UUIDs and attempts associate
nested calls and the original single reselection; facts use the actual local
client argument and omit return bodies and exception text. With no scope the
adapter is a no-op, while the explicit `emit` API still rejects missing parents.
Observation failures do not trigger client recovery or repeat an operation;
already raised business exceptions and cancellation retain their identity.
The cache gains no global concurrency guarantee. The middleware remains
uninstalled in production. The new core import is listed in the code catalog;
changed source fingerprints require a new real freeze and qualification, not
repairs to historical approvals or evidence. Controlled archival
remains separate work. Fake-backend and loopback checks
observe MODEL clients and do not prove a Windows endpoint selection.

Flow creation also emits an exact internal whitelist within that operation:
`flow.create.begin` hashes the actual normalized env string and records the
actual API resource limits; `flow.create.return` projects the existing rows,
including server resource values and canonical specs hashes; `flow.metadata.return`
records the backend's existing successful state read. Call-local operation and
creation UUIDs restore on nested exit; no last-flow cache or extra query is used.
A creation return remains visible if metadata fails. Observation faults stay
sticky and prevent target probes/retries; an observed creation without matching
operation/client association is refused before its creation RPC. With no scope,
API return objects and existing validation/recovery remain unchanged. Facts omit
parameter bodies, VQL, unrelated response fields and exception text. These are
in-memory diagnostics with MODEL query-boundary and loopback SDK verification;
real Velociraptor/Windows, production enablement and archival remain separate.

Result and file reads emit eight exact internal fact kinds under the actual
operation/client/flow association. Metadata preserves nullable state and the
existing artifact/source rules; result plans, per-source counts and actual
prefetch windows precede the final page hash and complete pagination fields,
including a null next cursor. Uploads record the original ordered JSON hash,
then the existing deduplicated inventory identity hash and bounded file result.
Facts omit row and path bodies. No query, page walk, public output or schema is
added. Lazy adapters do no hashing or extra validation without a request scope;
observation faults preserve the successful prefix and prevent target recovery
or repeated queries. Equal counts do not establish a transaction snapshot, and
one page or enumeration does not establish completeness. MODEL backend and
loopback SDK checks remain separate from real Velociraptor/Windows, controlled
archival, production enablement and a new qualified freeze.

`velociraptor_observation_archive.py` provides the independent PC026 08
record-format codec. Construct `ArchiveCodec` with explicit `max_records`,
`max_record_bytes`, `max_total_bytes` and `max_json_depth`; `encode(record)`
and `parse(bytes)` validate one exact canonical UTF-8 JSON record with one
trailing LF, while `verify(Iterable[bytes])` consumes an accept/event/seal chain
once without collecting all events. Previous Refs hash the preceding original
bytes, including LF. Only the adopted target/create/read fact whitelist is
accepted. Depth counts JSON containers with the outer record at depth one.
Malformed originals and exceeded budgets raise `ArchiveError`; valid unsealed
prefixes return `INCOMPLETE`, and seals distinguish `COMPLETE` from `FAILED`.
A complete archive may retain a raised or cancelled business outcome.
`request_key_sha256` hashes the typed parent key using 04 canonical bytes
without LF; it does not authenticate that parent.

This pure format module performs no I/O, scope activation or emission and is
not installed in production. Format validation grants no trusted source,
persistence, storage EOF, instance-wide acceptance coverage or business success.
New encoding of saved loopback SDK facts is a model demonstration, not proof
that those historical runs had durable archives. Native execution, trusted
configuration/namespace, session cuts, host consumption and a new actual freeze
remain separate work; Windows directory durability is unverified.

`velociraptor_observation_windows.py` implements the independent PC026 09
single-record Windows publication primitive. `WindowsRecordPublisher` takes an
already existing absolute local directory and four explicit codec budgets;
`publish(bytes)` validates one 08 original before creating a random UUID
`.pending`, writes through its exclusive native handle with short-write handling,
flushes and reads back the same bytes, then uses handle-based no-replace
`FileRenameInfo` to publish `<sequence:08d>.json` (maximum 99999999). Existing
final files are rejected even when their bytes match. It returns a relative
content Ref and the actual Windows reader identity, without granting approval
or proving an entire chain. Use its context manager or explicit `close()`.

Directory/ancestor leases retain the original PC026 same-handle identity and
complete SD gates, default actual-principal trust and no-delete sharing. The
principal/impersonation gate is rechecked per publication. The exclusive writer
is closed before private final readback to respect bilateral Windows sharing;
final file handles end with that transaction. A `PublishError` reports a fixed
code, `NOT_CREATED`/`PENDING`/`UNKNOWN` phase and generated candidate basenames.
An uncertain rename or failed post-rename verification/close remains UNKNOWN;
objects are retained, with no deletion, overwrite, automatic retry or ACL repair.
Close diagnostics preserve a primary publication error. Do not replay UNKNOWN
through a new publisher to conceal residuals.

The module depends on `tests.p05_pc026_windows_reader`, its ContentIO/readback
helpers and `velo_transfer.windows_platform`; future approved source closure
must include those dependencies. Host state-machine and ctypes adapter models
are development evidence, not native Windows publication or service-SID/root
qualification. API success/content flush/atomic visibility do not prove directory
power-loss durability. No CLI/env override, alternate SID/API parameter, parent
tree creation, observer/bridge integration, trusted namespace or new freeze is
provided; formal native validation and production authorization remain separate.
The rename buffer includes an owned UTF-16 terminator outside FileNameLength
but inside the passed buffer size, preventing Win32 path normalization from
reading beyond the destination name. Isolated control-principal Windows tests
do not qualify the business service identity or directory power-loss durability.

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
not part of a newly approved production freeze. Further business fact hooks, controlled
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
Velociraptor MCP is a POC Model Context Protocol bridge for exposing LLMs to MCP clients.

The current local bridge registers 137 tools: the original 118 dynamic and 12 fixed tools, plus seven guest transfer tools (`transfer_capabilities`, `transfer_begin`, `transfer_status`, `transfer_chunk`, `transfer_chunks`, `transfer_finish`, `transfer_abort`). `transfer_chunks` batches consecutive chunks for bulk throughput and is only offered when the protected policy grants `max_batch_chunks`; it keeps the single-chunk budget, deadline and hash rules. See [transfer MCP contract](docs/transfer-mcp.md) and [guest engine](docs/transfer-guest-engine.md). A protected `VELOCIRAPTOR_TRANSFER_POLICY` enables local transfer operations; without it the seven tools remain listed, capabilities reports disabled, and the original 130 tools remain available. Windows VM and host coordinator acceptance follow separately.

The host foreground entry is `python -m velo_transfer --spec /absolute/path/to/request.json`; use the original spec path, transfer ID and intent with `resume:true` to resume or add `--abort` to cancel. A locally proven transfer now reports `complete` with exit code 0; a host cleanup fault reports `cleanup_pending` with exit code 5 and retains evidence for recovery. An invalid connection profile returns one `velo.transfer.command-error.v1` JSON object with `error=invalid_profile` and exit code 3; no result path is claimed. See [host coordinator](docs/transfer-host-coordinator.md) and [host cleanup](docs/transfer-host-cleanup.md) for the result path, ownership and phase limits. Local tests use a guest substitute; they are not VM acceptance.

The acceptance plan keeps two denominators: the original DFIR slice is 118 dynamic plus 12 fixed registrations, with PacketCapture recorded as one exclusion, 129 real individual successes, and 645 valid relations across five real scenarios. The transfer slice is the PC024 six-tool matrix plus the registered `transfer_chunks` batch increment (seven transfer tools; increment record in `PLAN/2026.09.30/`); it is not multiplied by five. A 137-name/schema listing or a local `complete` result does not establish Windows VM or full product acceptance. Formal global COMPLETE additionally requires a physically verified destination, both owned cleanups, bound receipts and a durable journal/result. The original 130-tool startup conditions remain available without transfer policy; transfer actions enforce protected policy, VM identity and ACL, while HTTP keeps Bearer/Host/Origin checks. Program code verifies chunk, package, source, destination and receipt hashes internally; AI callers do not need extra before/after SHA commands or full hash lists.

The Snapshot 186/188 passages below describe earlier acceptance generations; current P05/P06 qualification must use the actual activated canonical source and its verified restore evidence. No historical recovery command or local substitute test opens that gate.

> Development status: P05/P06/P07 acceptance reopened; remediation is not yet accepted.
> The previous acceptance snapshots have been removed by the operator. The
> retained fixed-IP baseline is being requalified; do not run historical
> recovery commands or treat old reports as current acceptance.
> The bridge exposes 118 reviewed Windows CLIENT artifacts as
> dynamically generated MCP tools. Their names, descriptions, parameters, and
> definition hashes are checked against the connected root organization before
> stdio starts. Twelve fixed tools provide bounded VQL, single-endpoint Hunt,
> Flow lifecycle, one-file collection/download, basic triage, and process
> termination. The current 137-schema combination is validated before stdio starts.
> The project also supplies locked test-only dependencies, deterministic Windows
> fixture, and an indexed official-SDK scenario runner used for repeatable
> acceptance on the post-install VM snapshot.

Initial version has several Windows orientated triage tools deployed. Best use is querying usecase to target machine name.

e.g 

`can you give me all network connections on MACHINENAME and look for suspicious processes?`

`can you tell me which artifacts target the USN journal`




## Installation

This project currently supports Windows acceptance only. Linux is a future TODO;
macOS is not supported. `requirements.lock` is the exact Windows acceptance
environment, while `requirements.txt` pins the direct project dependencies.

Velociraptor Community Edition is open-source software and does not charge for
using this bridge or its API. Here, “API” means the local automation interface
used to ask the Velociraptor server to start and inspect collections. It is not
a paid cloud API. A separately configured AI/model provider may have its own
charges and data-handling terms, but the bridge does not require one.

Create a virtual environment and install the reproducible set with:

```text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock
```

### 1. Set up a local Velociraptor API identity
https://docs.velociraptor.app/docs/server_automation/server_api/

Generate an api config file:

`velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name api --role administrator,api api_client.yaml`

### 2. Clone mcp-velociraptor repo and test API

- Copy `api_client.yaml` to the repo root, or keep it anywhere local and set `VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml`.
- Copy `example.env` to `.env` for local development, then set `VELOCIRAPTOR_API_CONFIG` to your real `api_client.yaml` path. The bridge, smoke script, and agent load dotenv config automatically without overriding variables already supplied by your shell or MCP client.
- `api_client.yaml` is gitignored and should not be committed.
- Run `.venv\Scripts\python.exe test_api.py` to confirm the API works when `.env` is configured.
- The MCP bridge reads the same `VELOCIRAPTOR_API_CONFIG` environment variable after loading dotenv config.
- Set `VELOCIRAPTOR_DEBUG_VQL=1` only when you want raw VQL request logging on stderr for debugging.
- All legacy wrapper functions and the old dangerous-tools switch have been physically removed.
- Set `VELOCIRAPTOR_DOWNLOAD_ROOT` to an existing absolute directory before
  calling `download_flow_file`. Completed files are never overwritten.
- The agent POC defaults to local Ollama summaries. Set `VELOCIRAPTOR_MODEL_PROVIDER=azure`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, and `AZURE_OPENAI_MODEL` when you explicitly want Azure OpenAI summaries.

### 3. Connect to MCP client of choice

External clients use the deployed stateful Streamable HTTP endpoint
`http://<guest-host-only-ip>:28790/mcp` with the deployer's bearer token.
The following process-launch examples are for VM-local stdio diagnostics only;
they do not connect an external host to the VM and do not count as formal P06
acceptance. For those diagnostics, put values directly in the MCP client config:

```json
{
  "mcpServers": {
    "velociraptor": {
      "command": "/path/to/venv/bin/python",
      "env": {
        "VELOCIRAPTOR_API_CONFIG": "/path/to/api_client.yaml"
      },
      "args": [
        "/path/to/mcp_velociraptor_bridge.py"
      ]
    }
  }
}
```

Or point the MCP client at a dotenv file:

```json
{
  "mcpServers": {
    "velociraptor": {
      "command": "/path/to/venv/bin/python",
      "env": {
        "VELOCIRAPTOR_ENV_FILE": "/path/to/mcp-velociraptor/.env"
      },
      "args": [
        "/path/to/mcp_velociraptor_bridge.py"
      ]
    }
  }
}
```

Config precedence is: direct environment values from the MCP client or shell,
then `VELOCIRAPTOR_ENV_FILE` if set, then repo-local `.env`, then fallback
paths such as `./api_client.yaml` and `~/.config/api_client.yaml`.

The separate agent proof-of-concept lives under `agent_poc/`, but it is not
supported by the new Windows bridge contract and is excluded from current
acceptance. Its historical prototype behavior
includes an engagement manager that fans out to isolated, dynamically
allowlisted analysts in parallel. The `engagement` profile runs bounded
process, network, persistence, execution, user-activity, and system-inventory
roles; `deep` also opts into heavier filesystem and security roles. Evidence
collection is deterministic and synthesis is model-only per role. It supports local
Ollama summaries by default and opt-in Azure OpenAI API summaries via
environment configuration. Azure OpenAI mode sends collected evidence bundles
to the configured Azure API account for summarization. See
`agent_poc/README.md` for agent-specific usage and automation examples,
including verbose collection progress output with artifact names and row counts.

### 4. Tool Response Format

The original 130 tools return MCP-native `structuredContent`, an empty
`content` list, and the protocol `isError` flag. Success models contain only
the documented operation fields, real backend identifiers/states, and public
warnings. Errors use stable
`code/message/retryable/details` fields. Paged results use opaque canonical
`v1:<offset>` cursors, default to 50 rows, accept at most 250 rows, and enforce a
245554-byte limit on the complete serialized `structuredContent` object. A
cursor is only an offset interpreted against the `flow_id` and `source` supplied
on that call; it is not an issued or object-bound token. Whenever `pagination`
is present, `next_cursor` is also present: it is a cursor string for a
non-terminal page and JSON `null` for an empty or terminal page. Unpaged tools
omit `pagination` entirely, and the terminal `null` counts toward the byte
limit.

The fixed `collect_file`, `collect_forensic_triage`, and `kill_process` startup
responses keep `status="success"` for a completed control call and include the
new required `state` field. `start_hunt` keeps `state` for the Hunt and includes
the new required `flow_state` for its created Flow. These values are the first
non-empty backend state read immediately after creation; they are not a wait for
completion. In particular, an initial `ERROR` is reported verbatim and must not
be treated as a successful collection outcome. Missing or empty backend state
is a `BACKEND_ERROR`.

`start_hunt` validates every supplied artifact parameter against the same
startup-verified type, option and regex definitions as its dynamic tool before
creating a Hunt or Flow. Nested explicit `null`, unknown/hidden/upload fields,
wrong scalar types and out-of-set choices are rejected. Omitted parameters stay
omitted so Velociraptor supplies its defaults; valid values are not rewritten.
This fix has Linux-host regression coverage with the actual service and SDK
validation paths plus a fake backend. Windows deployment and real Hunt/Flow
acceptance remain pending.

`run_vql` executes in the root organization through
`SELECT * FROM query(query=<encoded query string>) LIMIT 251`. The API quotes
the complete query as a string, preserving quotes, backslashes, newlines and
Unicode without rewriting its VQL. Client reads remain bounded at 251 rows;
responses retain the 250-row / 245554-byte limits and accurate `truncated`.
Linux-host tests inspect real protobuf requests with a gRPC stub; deployed
Windows parser and server-side execution acceptance remain pending.

This contract implementation and its isolated fixtures do not constitute a
formal service deployment. PC017 logical-file download support is implemented
in the local source tree but is not deployed by this slice. The local fixed
`collect_forensic_triage` implementation now requests one complete
`_BasicCollection` with a 2400-second timeout and a 4 GiB
(`4294967296`-byte) upload budget. This is isolated code/test evidence only;
the deployed service still requires P05 source locking, initial acceptance and
two recovery checks before any later P06 qualification.

The historical Windows environment used the Snapshot 186 network deployment baseline.
Its restored fixture/process prerequisites have failed revalidation; it is not
currently a qualified P06 starting point. P05 baseline repair is in progress.
It contains the hash-locked local dependencies for PacketCapture and Autoruns,
plus the reviewed `Windows.Triage.Targets` and
`Generic.Utils.KillProcess` definitions. Dependency preparation is an operator
test-environment step; the MCP product surface has no download or install tool.

### 5. Tool Inventory

The public surface at P04 contains exactly 130 tools:

- 118 dynamic Windows tools. Each tool name is the exact Velociraptor artifact
  name, such as `Windows.System.Pslist`. The approved names and definition
  hashes are maintained in `APPROVED_WINDOWS_ARTIFACTS` in
  `velociraptor_dynamic_artifacts.py`.
- 12 fixed tools: `run_vql`, `start_hunt`, `get_hunt_status`, `stop_hunt`,
  `get_flow_status`, `get_flow_results`, `list_flow_files`,
  `download_flow_file`, `cancel_flow`, `collect_file`,
  `collect_forensic_triage`, and `kill_process`.

`collect_artifact`, `hunt_across_fleet`, all three `list_*_artifacts` tools,
and the old `windows_*`, `linux_*`, and `macos_*` wrappers are not registered.
Linux implementation remains a TODO. macOS is not supported.

On the historical Snapshot 186 environment, all 118 dynamic tools had their
required local dependencies. PacketCapture and Autoruns resolve their binaries
from Velociraptor's local public filestore; the locked SHA-256 values are
verified before acceptance and no runtime tool fetches them from their original
Internet URLs.

`Windows.Memory.Acquisition` is the one reviewed exception to the ordinary
collection resource defaults. The bridge internally requests a 3600-second
timeout and an 8 GiB upload ceiling because a complete image of the accepted
4 GiB VM cannot fit under Velociraptor's default 1 GiB per-collection limit.
This is not a public tool parameter and does not let callers raise limits for
other artifacts. P06 resource qualification still checks available memory and
disk before admitting the full execution scenarios. The new admission code is
under verification; old successful reports are not proof of the new qualification.

The fixed no-argument `collect_forensic_triage` entry is a second, separate
exception: only that entry requests a 2400-second timeout and a 4 GiB upload
budget for the full `Windows.Triage.Targets` `_BasicCollection`. The budget is
not a public argument, a global default, an MCP download quota, or a physical
disk/network-compression ceiling. Velociraptor charges the pre-compression
`FileBuffer.DataLength` of each block and cancels only when the accumulated
value is strictly greater than the requested cap; parallel or in-flight data
may therefore exceed it. Other calls to the same artifact and all other tools
retain their existing defaults. These semantics have local isolated request
tests, not a real 4 GiB cancellation or completed-triage acceptance run.

The P05 test infrastructure is intentionally separate from the MCP API:

```text
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\p05_prepare_fixtures.ps1 -WorkflowId <workflow-id> -AttemptId <attempt-id>
.venv\Scripts\python.exe tests\p05_dependency_acceptance.py --mode verify --attempt-id <attempt-id>
.venv\Scripts\python.exe tests\scenario_runner.py --scenario-id p05-flow-triage
```

The fixture script and real dependency checks are Windows-VM acceptance tools,
not general host setup commands. Scenario files must be ordinary indexed files
under `tests/scenarios/`; their reviewed hashes prevent command-line or
environment overrides from turning the runner into an arbitrary execution
proxy.

The candidate deployment script `tests/p05_service_install.ps1` now requires
the measured guest `-BindAddress`, single host `-HostAddress`, and deployment
`-AttemptId` UUID, in addition to `-RepoRoot` and `-ProtectedEnvFile`. It uses
the SCM service host, checks the exact existing service/firewall identities,
and refuses rollback of objects not tagged as created by that attempt or of
a running service. It does not change the VM's static IP or Windows-MCP setup.
Install and verify require existing canonical local-drive paths and reject
reparse-point traversal before reading the protected configuration. Verify
also checks protected-file ACLs before reading secrets, read-only service
code, service-writable download/log directories, and formal endpoint settings;
it does not repair ACLs or settings.
An existing matching manual or automatic service keeps its startup mode;
verify reports that mode. Newly created services remain manual until the
separate P05 readiness and automatic-start acceptance steps are complete.
These changes still require Windows validation; do not deploy this candidate
until the P05 gates are reopened. The service host no longer dumps deployment
environment values, including partial bearer tokens, into a diagnostic file.
SCM callback signatures have Windows-only regression tests. The candidate
service reports running only after HTTP startup and forwards stop requests to
the existing HTTP server's graceful shutdown path, without creating a second
server or stopping backend processes. The local candidate reports
`STOP_PENDING` before signaling that shutdown path, checks native status-report
failures through the fixed `SERVICE_STATUS_FAILED` category and a nonzero exit,
and reports `STOPPED` once. These stop changes are not deployed to the
running Windows service; actual Windows lifecycle acceptance remains unfinished.

The service host requires an existing deployment environment file before it
imports the bridge. A missing reference/file stops service startup; it does not
silently continue to repo-local configuration. When the reference is absent
from the process environment, only the installer's `VELOCIRAPTOR_ENV_FILE`
string registry value is read. This does not change direct stdio configuration
precedence. The service configuration must explicitly include the HTTP
mode/host/token, API config and
download root. Missing or duplicate settings and conflicting inherited values
stop startup instead of being completed from repo-local `.env`. Raw bridge
stderr is discarded; the failure log retains a fixed public failure code,
explanation and exit code, not raw
diagnostic text. Categories distinguish deployment configuration, Python
imports, transport settings, artifact/schema validation, backend connection and
HTTP execution failures without persisting exception messages or credentials.

The deployment-only P05 observer records a per-process dispatch counter under
`Logs/p05-dispatch/`. It observes the existing SDK POST handler after Host/Origin
checks, adds no endpoint or authentication exception, and retains no request
content or token. Its SDK version/source guard fails startup if the observed
security boundary changes; the updated candidate still requires Windows tests.
The read-only HTTP evidence collector joins the counter to the actual service
PID, creation time, executable hash and response instance header.

P05 three-chain stdio evidence now retains original SDK JSON-RPC messages and
bridge stderr in a new UUID directory for each execution. The test child is
explicitly stdio and does not inherit the HTTP bearer token or protected-env
reference. These originals alone do not prove the required complete network
observation window, and do not activate a candidate snapshot.

The P05-only candidate `tests/p05_process_parent.py` keeps preparation/backend
parent processes alive for identity checks. Its three fixed roles are `fixture`,
`frontend`, and `client`; it is not a product service or general launcher and
does not replace a running predecessor. Do not invoke it inside a P06 scenario
or use it to bypass the reviewed baseline creation/activation gates. The old
snapshots and evidence remain unchanged; a new baseline is not yet activated.

P06 qualification is an external official-SDK test command, not a VM-local
stdio bridge process:

```text
<external-sdk-python> -m tests.p06_resource_qualification --endpoint http://<guest-host-only-ip>:28790/mcp
<external-sdk-python> -m tests.p06_individual_acceptance --endpoint http://<guest-host-only-ip>:28790/mcp
```

The deployer's token must already be in `VELOCIRAPTOR_MCP_BEARER_TOKEN`; never
put it in arguments or logs. Start only after the reviewed Snapshot 188 recovery
gate has produced complete original restore records, `current-restore.json`,
the unchanged `fixture-instance.json`, and `server-observation.json` in the
fixed `Logs/P06/wf-01a05d1d-p06-r3/` evidence root. Qualification has no
evidence-root override or stdio fallback. Windows test
control collects resource observations only; all product calls remain on one
direct formal HTTP session. Control transcripts are stored separately and do
not contribute tool coverage.

Snapshot 187 has been administratively adopted only as the preparation baseline
(schema 5 / epoch 5). Snapshot 188 must first pass the initial acceptance and
two complete recovery cycles before activation (schema 5 / epoch 6) and P06 use;
administrative adoption is not product acceptance.

Individual error-contract acceptance uses its own restored attempt and formal
HTTP session, checks error codes/details/retryability, and always contributes
zero scenario coverage. Both commands seal their original evidence and append
receipts rather than overwriting previous attempts.

Full scenarios additionally require an explicitly selected successful qualification
and a byte-verified resource budget. Missing/stale observations, mismatched
service identity, insufficient space, and expired deadlines fail closed before
further work. A new immutable evidence generation and complete five-scenario
execution are still required; unit tests and read-only probes do not close P06.

These terms describe what a call does and what it changes:

| Term | Plain meaning | Action and impact |
| --- | --- | --- |
| Dynamic artifact tool | One MCP tool generated from one approved Velociraptor artifact definition | Starts that artifact on the one Windows VM and returns a Flow reference; it does not return all results synchronously. |
| Allowlist | The reviewed set of 118 permitted artifact names and exact definition hashes | Prevents an unexpected or changed artifact from becoming callable; mismatch stops bridge startup. |
| Root organization | The single Velociraptor organization used by this bridge | Metadata reads and collections stay in that organization; callers cannot select another organization on dynamic tools. |
| Flow | One concrete collection job on the Windows client | May read endpoint evidence or run the artifact's documented action; later lifecycle tools inspect or stop it. |
| Windows-only | Only the one Windows endpoint and Windows artifacts are in scope | Linux tools are not registered yet and macOS tools will not be added. |
| stdio | MCP messages travel through the bridge process's standard input/output | Reserved for internal testing; stdout carries only protocol messages, startup diagnostics go to stderr, and failed validation exposes no partial server. |
| Formal HTTP entry | The production transport: one stateful Streamable HTTP server on the exact guest host-only address, port 28790, path `/mcp` | Selected with `VELOCIRAPTOR_MCP_TRANSPORT=http` plus an exact host, a non-empty bearer token, and optional allowed origins; wildcard binds, other ports or paths, or an empty token are rejected before any socket opens. Requests must pass a constant-time bearer check and Host/Origin allowlists (DNS rebinding protection stays on) before any tool runs. Responses admitted past bearer authentication carry a process-scoped `X-MCP-Server-Instance` value that changes on restart; bearer rejections occur before this header is added. The value is checked by the client and does not replace authentication. |

Thanks to [@snoe-findley](https://github.com/snoe-findley) for sharing a fork
that expanded available tools and some of the newer cross-platform additions.

![image](https://github.com/user-attachments/assets/3e810f03-ca74-4757-b5dc-89d4e8f8aef6)


### 6. Caveats

Due to the nature of DFIR, results depend on amount of data returned, model use and context window.

Artifact collection is asynchronous. Use `get_flow_status` and bounded
`get_flow_results` pages. For uploaded evidence, call `list_flow_files` first,
then pass one returned `file_id` to `download_flow_file`. A Hunt is a container
for the unique endpoint's real Flow: stopping the Hunt does not cancel that
Flow, so call `cancel_flow` separately when that is intended.

The file list represents collected logical source files. Velociraptor sparse
range indexes (`Type="idx"`) are validated and consumed internally rather than
listed as separately downloadable files; `warnings` reports
`sparse_indexes_internal:<count>`. A genuinely collected filename ending in
`.idx` remains an ordinary file. Downloads are always explicit, one returned
data `file_id` at a time. For sparse files the bridge first performs an extra
compact, non-padding read and then reconstructs the logical file with padding;
the returned size and SHA-256 cover the reconstructed logical bytes. This adds
one full compact-read pass and does not provide a raw compact/index export.

Completed output is published without overwrite using `os.link`. A failure
before publication creates no new completed file, although a failed cleanup
may leave this request's owned `.part`. A failure after publication validation
or `.part` cleanup returns `BACKEND_ERROR` with reason
`download_post_publish_failed`; the completed file, and sometimes the owned
part, may remain. Do not automatically retry or overwrite it. The bridge never
rolls back by deleting a completed path and stops cleanup when path ownership
cannot be proved. The reported hash proves the bytes actually delivered, not a
backend atomic snapshot or protection against arbitrary privileged local
interference. Download quotas, retention, and automatic cleanup are not part
of this interface.

If a separate hosted AI service is connected, review that service's licensing
and data-processing terms before sending endpoint evidence. This is independent
of Velociraptor Community Edition and its local API.

Please let me know how you go and feel free to add PR!


`can you give me all network connections on MACHINENAME and look for suspicious processes?`
<img alt="image" src="https://github.com/user-attachments/assets/cc19ccde-f8fa-40d5-8b4d-82215777dc6b" />
<img alt="image" src="https://github.com/user-attachments/assets/734ce6d0-6c66-49cf-a0f7-8236f7435be3" />
<img alt="image" src="https://github.com/user-attachments/assets/b6593321-1089-4f00-8011-5ef08cf80d88" />

`can you tell me which artifacts target the USN journal`
<img alt="image" src="https://github.com/user-attachments/assets/b9f93b1c-4a08-437d-b25a-ff82bdd2ab8c" />

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

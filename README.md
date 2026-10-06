# Velociraptor MCP

## Current HTTP runtime modes

Daily HTTP defaults to `VELOCIRAPTOR_MCP_OBSERVATION=off`; leaving the variable
unset has the same effect. The stateful official SDK serves all 137 tools with
bearer authentication, exact Host/Origin checks, session ownership and binary
transfer protection. Daily operation does not load archival approval inputs or
publish observation cuts/archival receipts.

Strict auditing is explicitly selected with
`VELOCIRAPTOR_MCP_OBSERVATION=approved` in the protected service environment,
followed by a restart. This selects the original approval checks; it does not
issue approval or bypass the approved Python/SDK/source/storage requirements.
Invalid values and `approved` with stdio reject configuration. See
[runtime mode details](docs/observation-runtime-mode.md).

## Approved native archive entry

When strict auditing is selected, HTTP constructs `SessionController.open_approved(instance_id)` before
backend RPCs or listening. The fixed governance loader must approve the current
source/resources, SDK pin, archive/lifecycle inputs and actual private Windows
root identity plus full SD. Read-only preflight checks every generated absolute
candidate and caller-available free space; there is no root, group, publisher,
MODEL, CLI or environment approval override. Missing or stale actual approval
still rejects startup as `OBSERVATION_STARTUP_REJECTED`. stdio does not load
archive inputs. The historical agent does not acquire archival integration.

`velociraptor_observation_export.py` borrows the same ledger-owned governed group
and owns a separate native directory allocator for the approved export quota.
It reserves shared files/bytes/directories and one serialized pending lane before
copying the source prefix. Every candidate uses the actual root, UTF-16 length
below 248 and depth at most 64; source SD reserves use the Reader's 1 MiB bound.
The export layout is `e<instance>/s<SHA256(session UTF-8)>/`, beside the ledger.
It copies the complete confirmed global catalog and only that session's NEW
chains, includes all its REJECTED attempts, deduplicates source SD bytes by hash,
and preserves each file's exact six-field source identity.

Publication reuses the 09 same-handle exclusive pending/write/flush/readback/
no-replace transaction and 11 private allocation algorithm. Source copies close
before `source-manifest.json`; `lifecycle.json`, `attempts.json` and `cut.json`
follow. An independent full `CutCodec.verify_cut` readback precedes `export.json`,
then full export verification and all per-export publisher/reader closes precede
the external runtime receipt. DELETE can return the two adopted close headers
only after the actual native thread has exited and joined. Repeated DELETE
returns the same cut; failure preserves originals/pending files and UNKNOWN,
with no successful headers, repair or replay. Timeout/cancellation keeps the
real thread, join task and pending ownership through its actual finally.
Only the ledger closes the borrowed group and retained allocators during drain.

Startup failures after approved construction retain their original exception
and unwind acquired native resources once, including Config/server/run and SDK
lifespan entry failures. Cancellation after lifespan entry uses shielded drain;
cleanup faults remain attached to the original error. Live work or uncertain
I/O stays owned and UNKNOWN, without a forced ledger close or success receipt.
Uvicorn lifespan is required; its startup-failure return or exit preserves the
actual application cause. Transfer shutdown still runs on bridge exit.

The formal app uses one actual pinned SDK manager, controller/ledger instance
and SDK session bindings for MCP and chunkbin, behind bearer and Host/Origin
gates. All 137 schemas and seven transfer protocols remain unchanged. Host
verification exercises the production native algorithm with MODEL Windows
permissions/identities, actual SDK loopback and limited real POSIX file I/O.
The admitted maintenance API below now exercises complete original acquisition
and independent C4 verification on the host. It does not qualify Win32/NTFS/service
identity, directory durability, B1 overall, S2 consumer success gates or the new
production freeze/deployment/approval. Windows qualification remains separate.
Finite body/record/SD and queue gates, observed permanent byte/object peaks and
copy-before resource reserves remain required; full CPython/Rust parser heap
proof is outside the calibrated acceptance scope. No RSS claim is made.

Component progress notes below preserve earlier implementation stages. Their
unavailable-exporter and unconditional-startup-refusal statements describe those
earlier stages; the current opt-in construction and remaining gates are above.


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
repairs to historical approvals or evidence. Controlled native archival
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
real Velociraptor/Windows, production enablement and native archival remain separate.

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
loopback SDK checks remain separate from real Velociraptor/Windows, native
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
tree creation, production observer/bridge integration, trusted namespace or new freeze is
provided; formal native validation and production authorization remain separate.
The rename buffer includes an owned UTF-16 terminator outside FileNameLength
but inside the passed buffer size, preventing Win32 path normalization from
reading beyond the destination name. Isolated control-principal Windows tests
do not qualify the business service identity or directory power-loss durability.

`velociraptor_observation_namespace.py` implements the PC026 11 independent
`WindowsDirectoryAllocator(directory, max_directories=...)`. It binds an existing
private root and all ancestors with the original native reader gates. `root`
and successful `allocate(parent, name)` results are immutable leases owned by
that allocator; matching paths, foreign leases and external Refs grant no rights.
Names use the contract's strict ASCII grammar and exclude Windows device names.
Input/capacity refusals happen before creation and leave the allocator usable.
Actual TokenUser, default trust and full same-handle SD/identity checks are mandatory.

Creation uses exclusive `CreateDirectoryW` with an explicit protected private
DACL at creation, followed by immediate no-follow binding and parent/path rechecks.
Security drift or native creation failures terminate allocation without deleting,
adopting or retrying residuals. Diagnostics distinguish `NOT_ATTEMPTED`,
`CREATE_FAILED`, `CREATED_UNBOUND`, `BOUND` and `UNKNOWN`; they grant no approval.
Keep the allocator alive through publisher construction, publication and closure;
call `allocator.recheck(lease)` before and after handing `lease.path` to the 09
publisher. Publisher and allocator each retain and close their own handles once.
Native directory leases request FILE_LIST_DIRECTORY as well as attributes: this
read access makes Windows enforce the sharing check that denies DELETE opens;
metadata-only access cannot provide that protection.
PC021 issuer readback and bounded preservation use the same LIST requirement.
Readback retains share READ only; preservation parents also share WRITE for
PC022 native refreshes, while both reject DELETE acquisition. Insufficient LIST
access fails closed. This does not qualify formal issuance or the service identity.
The allocator adds no production namespace, observer activation or public SID/API
bypass. Import performs no Windows I/O. The explicit source catalog includes its
native reader and model test dependencies; no production freeze is issued.
Host adapter/reader/publisher/journal models and isolated file loading verify local
control flow only. Windows ABI, inheritance, directory sharing/replacement and
native handoff, service SID/SACL/root and production governance remain separate.

`velociraptor_observation_journal.py` adds the PC026 10 explicit per-request
archive seam. `RequestJournal(publisher, codec, accept_payload,
owns_publisher=False)` publishes and verifies accept before business starts.
Each append validates the 08 whitelist and budgets, reserves one record and
`max_record_bytes` for seal, checks the exact returned path/size/SHA, then advances
the confirmed head. It retains counters and parent metadata, not record bytes.
A known validation refusal can seal FAILED; any publication exception or Ref
mismatch permanently poisons the journal, prohibiting retries and further seals.
Seal records the actual outcome; COMPLETE does not mean business success.

An internal `RequestObserver(..., journal_factory=factory)` passes a copied
key, tool and arguments SHA to trusted factory code. The factory supplies a new
matching journal and acceptance sequence; keys stay reserved after failures,
and cross-scope reuse is refused. Under the scope lock, archive acknowledgment
precedes memory append; sealing and one close attempt precede memory sealing,
after the default awaited SDK worker exits. Every archive fault is sticky and
prevents target recovery/replay. Primary business errors/cancellation survive
finalization and diagnostic faults; normal returns with archive faults fail.
Exact-six snapshots stay unchanged; `journal_diagnostics()` separately exposes
confirmed acceptance/head and failure state without granting source authority.

The factory owns resources it never returns. The observer retires each returned
journal; only `owns_publisher=True` transfers publisher closure to it. External
shared publishers remain caller-owned. Constructor failures close owned resources,
and uncertain close is never retried; close failure leaves the scope unsealed.
The default `journal_factory=None` retains generic in-memory events and no I/O.
The catalog includes the journal and codec dependency. Real loopback official
SDK worker/raw-order checks use MODEL backend/publisher only; Windows journal
integration, service-principal/root qualification, trusted namespace/catalog/cut,
host association and new actual freeze/approval remain unverified.

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

The bridge and historical agent do not enable this module. Its default adds no
tools, parameters, headers, CLI/environment switches, RPCs or persistent archive.
Production archival and host association require separate qualification and a
new approved freeze.
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

The seven transfer schemas are stored compactly in `velo_transfer/transfer_tools_schema.json` (2026-10-06): the shared 333-entry error-code enum stays literal once per tool at `oneOf/1/properties/error/properties/code`, and the other 64 identical occurrences use the local reference `{"$ref": "#/oneOf/1/properties/error/properties/code"}` resolved inside each output schema. The compact file expands to the exact previous schema; SDK registration, jsonschema validation and the runtime error-code set (`_CODES`/`CODES`) load directly from this one file, so this is a representation-only size reduction with no interface or behavior change.

The host foreground entry is `python -m velo_transfer --spec /absolute/path/to/request.json`; use the original spec path, transfer ID and intent with `resume:true` to resume or add `--abort` to cancel. A locally proven transfer now reports `complete` with exit code 0; a host cleanup fault reports `cleanup_pending` with exit code 5 and retains evidence for recovery. An invalid connection profile returns one `velo.transfer.command-error.v1` JSON object with `error=invalid_profile` and exit code 3; no result path is claimed. See [host coordinator](docs/transfer-host-coordinator.md) and [host cleanup](docs/transfer-host-cleanup.md) for the result path, ownership and phase limits. Local tests use a guest substitute; they are not VM acceptance.

A second host foreground entry, `python -m velo_flow --spec /absolute/path/to/request.json`, collects one existing flow in a single run: it waits for FINISHED with bounded backoff, pages one result source to its terminal cursor, writes raw responses and rows plus a bounded summary into a new exclusive output directory, and lists the flow files once (files are enumerated, not downloaded; use the transfer CLI above for retrieval). It only calls `get_flow_status`, `get_flow_results` and `list_flow_files` over the same private connection profile; exit codes are 0 complete, 2 partial/failed, 3 input error. See [flow host coordinator](docs/flow-host-coordinator.md) for the request schema, budgets and verification boundary; it makes no Windows VM or deployment claim.

The shared client runtime (`agent_poc/velociraptor_mcp_runtime.py`) also supports per-task model context selection: an explicit tool list narrows the definitions sent to the model (full schemas, host transfer tools never model-facing) and also gates which tool calls may execute, while `call_tool` returns a bounded `velo.model.view.v1` summary instead of raw payloads; the full host interface (`call_tool_payload`, in-memory `last_tool_result`) stays available for programmatic consumers. See [model context selection](docs/model-context-selection.md).

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


`tests/p05_service_qualification.py` is a separate one-shot SCM foundation
diagnostic for the existing `mcp-velociraptor` virtual-account service. It is
not imported by the bridge or historical agent, adds no MCP tool, and offers no
console/root/SID/config/Win32 override. Import is inert; the no-argument entry
only connects to `StartServiceCtrlDispatcherW`. Deployment, service switching,
account rights, disk/ACL changes and actual Windows execution require separate
controller authorization. It never reads business env/config, opens HTTP,
contacts the backend, installs services or schedules rollback.

Its code-owned sibling input is `tests/p05-service-qualification.json`, generated
only during an approved future deployment. It is canonical UTF-8 JSON with
sorted keys, compact separators, no BOM and exactly one trailing LF, at most
1 MiB and container depth 16. Duplicate/unknown fields, non-finite numbers,
bool-as-int, aliases, escapes and oversized inputs refuse without repair.
The exact eight fields are `schema_version` (integer 1), `kind`
(`pc026-foundation-qualification-input-v1`), `run_id` (canonical UUID4),
`principal_sid`, `namespace_root` (canonical native local Windows absolute path,
disjoint from the code-owned tree), `root_identity` (11 exact-six Windows
platform/volume_serial/file_id/owner_sid/principal_sid/acl_sha256), `source_refs`
and `budgets`. Refs have exactly path/size/SHA256; each path must appear once
in the tool's independent `REQUIRED_SOURCES` catalog (currently 16 files,
including all local imports and package initializers). Input itself is excluded
from that catalog. Each source is safely read with a 1 MiB ceiling and compared
by size/hash; all retained identities/bytes/full SDs are rechecked before writes
and after the probe/report. Missing closure members, case variants and unknown
directories fail. The independent catalog must change with local dependencies.

`budgets` has exactly these five positive integer limits, with inclusive ranges:

| Field | Minimum | Maximum |
|---|---:|---:|
| max_directories | 2 | 8 |
| max_record_bytes | 1024 | 65536 |
| max_records | 3 | 8 |
| max_total_bytes | 3072 | 524288 |
| max_json_depth | 3 | 16 |

`max_total_bytes` must also be at least three times `max_record_bytes` to reserve
seal and fit this fixed probe. No ceiling is silently clipped. Actual TokenUser
must equal both the input SID and `LookupAccountNameW` for
`NT SERVICE\mcp-velociraptor`; thread impersonation and missing assigned
SeSecurityPrivilege refuse. Full owner/group/DACL/SACL and LIST checks use the
current default WindowsSession, with no extra trust or automatic privilege grant.
Config/source leases stay through report readback and final closure. Self-check
hashes do not independently establish trusted interpreter/runtime/package
provenance: that external deployment authority must be verified separately.

After all gates, the default 11 allocator exclusively creates one `run_id`
child and one `request` child; existing names refuse without adoption or retry.
The real 09 publisher and 10 journal write exactly three 08 originals: accept,
`target.resolve`, and seal. Their fixed parent uses
`instance_id="qualification:<run_id>"`, `session_id="MODEL-foundation"`, typed
integer request 1, acceptance sequence 1, tool `qualification.foundation.MODEL`
and client `MODEL-qualification-client`. These are diagnostics, not client/Flow
observations. Original bytes are safely reread, compared to the exact emitted
bytes and verified by 08; allocator leases survive publisher close and recheck.

Only a safely acquired run can receive exclusive `qualification-report.json`.
Its versioned exact top-level schema is: `schema_version`=1, `kind`=
`pc026-foundation-qualification-report-v1`, `outcome`, `code`, `input_ref`,
`source_refs`, `process_before`, `process_after`, `run_identity`,
`request_identity`, `records`, `verify`, `resources`, `boundary`.
Outcomes are only FOUNDATION_PASS/FAILED/CANCELLED. `code` is a fixed category:
FOUNDATION_PASS=0, CONFIG_FAILED=10, IDENTITY_FAILED=11, SOURCE_FAILED=12,
PROBE_FAILED=13, REPORT_FAILED=14, CLOSE_FAILED=15, SCM_FAILED=16, CANCELLED=17,
DEADLINE=18. Process snapshots contain exact principal_sid/account_sid/pid/
started_filetime/privileges (name+attributes)/handle_count_including_query/
thread_impersonation fields. Directory identities use the exact six fields;
request_identity may be null before acquisition. Records contain Ref+identity;
verify is the 08 chain summary or null before verification. Resources contain
closed_before_report (only successful prior closures), background_workers=0,
service_main=ACTIVE_UNTIL_FINAL_CLOSE and
allocator_config_final_close=EXTERNAL_SCM_CONFIRMATION_REQUIRED. Boundary is
DIAGNOSTIC_ONLY_EXTERNAL_RUNTIME_AUTHORITY_REQUIRED. The report carries no
exception messages/stacks, credentials, READY status or approval. It is bounded
at 1 MiB, exclusively written/flushed/closed and privately reread; it has no 09
atomic publication or power-loss guarantee. Failed/uncertain originals remain;
there is no overwrite, deletion or repair. Report write/read/close errors cannot
produce a successful SCM exit. A provisional disk FOUNDATION_PASS cannot
qualify a later failed final lease close or SCM status update; external final
SCM exit and handle/token observations are mandatory. After all owned closes,
the host also rechecks the actual process identity and original privilege
attributes; drift gives a nonzero exit without rewriting the provisional report.

The synchronous service reports START_PENDING, RUNNING (probe executing only),
then STOP_PENDING and one STOPPED after cleanup. The callback only signals STOP;
there is no concurrent evidence writer, thread kill or automatic rerun. STOP and
an explicit 120-second monotonic deadline prevent new probe stages at cooperative
boundaries; an already-started native transaction reaches its safe boundary.
Blocking Win32 I/O cannot be interrupted by this deadline: a stale RUNNING or
pending external observation means completion is unknown, not zero workers or
successful stop. No STOPPED report is emitted until synchronous work returns.
A safe existing run may receive a CANCELLED/FAILED final diagnostic after STOP.
All resource closes are attempted once; primary failures survive close/note
failures. Before a safe run exists, only a fixed nonzero SCM classification is
available, with no fallback output to cwd or old Logs.

Host lifecycle tests exercise real 08/09/10/11 classes and this SCM control flow
with explicitly MODEL native I/O/token APIs. They cover refusal, drift, budgets,
exclusive names, stage STOP, unknown I/O, report and cleanup/status failures;
new isolated source loading checks closure without issuing a freeze. Actual
Windows dispatcher/token/service stopping, root/SACL qualification and deployment
remain unverified. This is not T036 observer config/catalog/cut, production
archival, >4 GiB transfer, N1–N5, a 191 snapshot or P05/P06 acceptance.


`velociraptor_observation_attempts.ArchiveAttemptLedger` is an independent
PC026 attempt ledger, uninstalled in production. Its only approved factory is
`open_approved(instance_id)` (32 lowercase hex characters); it uses the fixed
04/05 governance loader and adopted 2026.10.04 attempt contract, with no
root/SID/fake override. Existing configuration and namespace-root records under
`PLAN/2026.10.02/` and the complete raw root SD are independently bound in
runtime allowed_refs outside the implementation freeze and publication set.
Every immutable input and actual root/lease is rechecked through closure.

`begin(key, tool, arguments_sha256)` permanently reserves the typed parent and
publishes BEGIN before request allocation. Its opaque immutable lease reports
NEW or REJECTED; each duplicate gets its own BEGIN/END without another journal.
`accept(lease)` returns the original owned RequestJournal only after durable
accept acknowledgment and catalog ACK. The caller still claims that journal
exactly once through its actual scope. After the awaited SDK worker has exited
and sealed/closed its journal, `finish(lease, actual_outcome)` privately rereads
the original chain and bounds two same-handle directory enumerations before END.
`close()` refuses active requests, writes INSTANCE_END only for known terminal
attempts and closes the independently owned governance/allocator/catalog leases.
HTTP cancellation alone is not worker exit. A returned `isError` remains
`returned`; COMPLETE/FAILED archival status is independent of business success.

Unknown publication, acknowledgment, readback or close permanently stops the
instance. Original and pending files remain; no deletion, replay, overwrite,
repair or automatic recovery is offered. Context closure preserves primary
exceptions/cancellation. Explicit approved logical budgets reserve all attempts,
catalog records and `max_active * request_max_record_bytes + catalog_max_record_bytes`
for concurrent pending writes. These are logical byte bounds, not physical NTFS
capacity, RSS or power-loss durability guarantees. The separate CatalogCodec
strictly verifies canonical bounded BEGIN/ACK/END originals as one stream;
its chain summary alone grants neither trusted storage nor business acceptance.
The public 09 writer still accepts only original 08 records.

Host tests exercise complete synthetic governance graphs and real ledger,
allocator, publisher, journal and reader control flow with MODEL Win32 I/O.
New directory-enumeration ABI and joint catalog native Windows qualification
remain pending. Production observer/controller wiring, session cuts, host
association, retention maintenance and new actual deployment/freeze/approval
are separate work. The 137 schemas, seven transfer tools and 645 DFIR relations
are unchanged; the historical agent gains no archival integration.


The adopted PC026 lifecycle contract now adds a fixed SDK source pin and a
read-only formal HTTP startup gate. It checks the approved archive/lifecycle
inputs, export and pending reserves, and exact installed dependency versions,
source bytes, AST boundaries and handshake protocols before backend setup.
The pin includes current host Python 3.13.15; another deployment must pass the
same reviewed pin or undergo an explicit new source review. Local hashes alone
do not qualify interpreter provenance or native Windows storage.

Formal HTTP currently refuses startup, including a valid MODEL approval graph,
because the native session exporter is unavailable. There is no runtime enable
switch. Direct formal app construction has the same gate; internal protocol
fixtures use the private composition helper and grant no archive authority.
The stdio entry retains its existing behavior and performs no archival input
loading. Session controller, retained worker barriers and safe cut publication
remain unfinished; this change does not establish DELETE completion or Windows
acceptance. Tool names and all 137 schemas are unchanged.


The transfer SDK wrappers and binary invoke now share a private retained-thread
primitive when an accepted owner has been internally bound. It keeps the real
thread and copied context through repeated cancellation and joins before the
handler can seal; timeout/launch/join uncertainty remains sticky. Without that
internal owner, stdio and protocol fixtures retain their existing thread path.
This primitive is not yet connected to an approved HTTP session controller:
SDK streams/queues, transfer child processes and RootLease completion, cut
publication and formal DELETE headers still require implementation and tests.


Formal lifecycle startup refusal is classified as `OBSERVATION_STARTUP_REJECTED`
through the bridge and the fixed SCM failure-message map. The separate
`SERVICE_OBSERVATION_INVALID` code continues to describe the read-only dispatch
observer. Neither category includes raw exception text or credentials.


The private MCP 2.1.1 resource adapter now covers the eight reviewed SDK
boundaries (592 upstream source lines including the context-manager decorator).
It retains deindexed and cloned streams, attempts each underlying async close
once, records swallowed router/close faults, and drives the actual dispatcher
with strict connection-stack cleanup. A permanent runner reference observes
exit after transport cleanup. Its source pin is checked before manager creation.
Actual host SSE/notification/GET loopback and resource fault tests cover this
component; it does not implement admission, session cuts or DELETE completion.
Formal HTTP remains disabled until the complete approved native lifecycle exists.


The private lifecycle controller now connects the actual HTTP/SDK path to
ledger BEGIN, durable ACK, request-owned journal, and read-back END. It keeps
typed IDs distinct and serializes both wire-string and dispatcher-coerced slots;
queued cancellation cannot cancel an active request with a different typed ID.
The host MODEL fixture uses real SDK handlers and retained threads. DELETE
intercepts the SDK's earlier 200, drains known SDK work, and returns 503 while
the cut exporter is unavailable. This is partial lifecycle implementation:
transfer-child ownership, binary ingress, complete retained-state budgets,
response-only envelopes, safe prefix/export/cut publication and formal completion
headers are pending. The production approved constructor continues to refuse
before writer/backend/listener; there is no CLI/env/HTTP MODEL activation.

The SDK pin also locks the full `mcp.shared.dispatcher` source and the actual
`coerce_request_id` AST used by the new typed-slot queue (15 source modules).
A helper-source drift with otherwise unchanged SDK versions is rejected before
manager creation. This adds no upstream adapter copy and grants no deployment
or archive authority.


The private lifecycle controller now reserves transfer-child ownership before
actual fork/Popen and retains the causal session, worker nonce, request digest,
job and real PID/birth. Child processes clear the inherited SDK observation
scope. Their cleanup receipt follows actual deadline-guard join and RootLease
release; parent closure additionally requires native wait, bounded pipe EOF and
root/lease recheck. Persisted worker.stopped and tool END grant no child-exit
proof. Session DELETE waits only its causal children, keeps live children on
timeout and never uses global transfer shutdown. Host tests use real benign
fork/guard/lease and official SDK seven-tool calls, with MODEL Windows/archive
inputs. Windows Popen/handle qualification remains unverified. Binary lifecycle,
complete object-retention budgets, safe prefix/export/cut and successful close
headers are still pending; production startup continues to refuse.


The private controlled binary route now reserves an independent global work
sequence, actual session/owner and full raw-request SHA before invoking the
existing VBT1 endpoint. Its real retained thread has no 08 parent; HTTP response
completion and real thread join both remain in the session barrier. Bad frames,
instance mismatch and exhausted binary quota refuse before invoke. MODEL host
loopback tests exercise actual binary bytes and a latched native thread through
DELETE timeout; they do not qualify native Windows or successful cut export.
Message reservation now charges the parsed Python containers/strings rather
than only canonical bytes, and failed creation admission does not leak a pending
slot. Full controller/SDK object-retention accounting, response-only correlation,
stable prefix/export/cut and successful closure remain unfinished; no public
production/MODEL activation is added.


Private response-only ingress now requires the actual pinned dispatcher's
issued outgoing waiter with an exact typed id and a single reply reservation.
Unsolicited, coerced aliases and duplicate replies never reach SDK resolution
or ledger writes. The dispatcher hooks retain the actual pending streams and
observe their synchronous closure once; resource faults poison the controller.
An accepted response is independent SDK work and has no 08 journal parent.
Host official-SDK backchannel tests verify real requests and replies rather than
constructing pending entries. The source pin includes the three additional
upstream hook algorithms; the eight copied adapter boundaries remain 592 lines.
Complete lifecycle proof/export/cut, full retained-object budgets and Windows
qualification remain unfinished, and formal production startup still refuses.


After its real causal barrier, the private controller now obtains a bounded
native-reader catalog snapshot under the actual publication transaction lock.
It verifies the anchored global head, complete names before/after reads, full
source SDs and every original in the selected session's NEW chains against ACK
and END. Other open sessions' metadata remains in the complete prefix while
their event originals are excluded; REJECTED tombstones create no request chain.
Temporary snapshot handles close before immutable originals are retained.
Missing/extra/pending/drifting originals and uncertain closure poison the ledger
and controller. Host tests exercise actual ledger/reader algorithms with MODEL
Windows storage. This remains a snapshot, with no published export or cut and
no successful DELETE headers. Full export codecs, runtime I/O closure, object
budget qualification, service drain and native Windows validation remain pending.


The private lifecycle controller now uses one combined pending gate across
sessions, queued SDK messages, binary work, unbound children and issued waiters;
completed records remain permanent. A known pre-handoff HTTP failure uniquely
claims its journal and produces a cancelled read-back END with no business call.
Native prefix reads now run on controller-owned non-daemon threads with permanent
join tasks. HTTP cancellation or deadline refusal keeps the real thread and
its waiter until actual exit; it cannot certify closure early. Host MODEL tests
exercise these boundaries. Complete budget qualification, service drain, cut
publication and successful headers remain separate work; production startup
continues to refuse before archive writes, backend setup or listening.


The private lifecycle now has strict C2/C3 projection, lifecycle, source-manifest,
cut and export content validation, including the fixed lifecycle configuration
Ref and INSTANCE_BEGIN binding. A test-only MODEL exporter uses actual exclusive
POSIX files, flush, full readback and final closure; its Windows identities and
SD observations remain MODEL fixtures. It is never selected by production CLI,
environment or HTTP. Real SDK DELETE reaches CLOSED and the two adopted headers
only after causal workers, source reads and final export I/O exit. Repeated
DELETE retains the same cut. Per-session receipts preserve separate exports;
service drain additionally reads back INSTANCE_END and closes ledger groups.
Published files alone cannot override a failed final close.

Tests cover real benign child/native wait/guard/RootLease, binary thread and
SDK outgoing/reply/GET records in those MODEL cuts. The admitted initialized
notification is awaited when its earlier HTTP 202 races later ingress; readiness
is never inferred from 202. Permanent owned Python objects are measured with
shared-object deduplication and gated before subsequent reservations/publication.
This is domain accounting, not a complete allocator/native/RSS bound. Full
capacity/peak and maintenance qualification, all concurrent failure permutations,
Windows native export/SCM and production approval remain unfinished. Formal
production startup still refuses before writer, backend or listener.


Queued typed-alias HTTP requests now observe actual socket disconnect after full
body EOF, join their receive waiter before SDK handoff, and finish the real
journal as cancelled without calling business code. Cancellation after a possible
handoff preserves the journal and poisons the controller rather than stealing
SDK ownership. Close I/O waits on actual thread exit without scheduling into a
possibly closed event loop; start/join faults retain their records and first
exception. These are host socket/thread tests with MODEL archive storage. They
do not complete retained peak, maintenance or native Windows qualification.


A private maintenance reservation seam now requires the original session's
actual CLOSED receipt and a different initialized SDK session with the same
owner. It reserves remaining catalog attempts, binary work and permanent SDK
sequences against other business, and bounds future calls and body bytes with
actual HTTP/chunkbin ingress and response observations. Completed initialization
calls and bytes also count toward the instance maintenance quota. Reservation
failure occurs before a new tool ticket/BEGIN; received-byte overflow poisons
the session. This seam grants capacity only. B2 must still bind an approved
read-only export source, derive a complete download/retry plan, capture all
exchanges and close the nonrecursive maintenance session; physical maintenance
acquisition and native publication remain unqualified. No public selector was
added, and production startup continues to refuse.


Domain accounting now includes actual SDK driver/connection/task frames, AnyIO
ownership objects, copied thread contexts and closures, exception frame locals
(including Python 3.13 frame proxies), memoryview owners and exporter state.
Shared references stay alive during traversal so temporary object-ID reuse cannot
undercount them. Live thread context is checked before start and results before
wrapper exit; owned SDK sends check payload/context before buffer insertion.
The MODEL publisher checks its constructed and read-back temporary graphs.
Tests fill both sessions, all eight attempts and all 32 permanent work sequences,
then verify complete proof sequences and immutable earlier exports after a legal
catalog append. These observed graph peaks do not establish allocator/native/RSS
limits or every allocation between observation points. Full preallocation and
Windows qualification remain required. Actual initialize handler/HTTP tails are
also awaited before OPEN and before a racing initialized notification proceeds.


Prefix/export cancellation and timeout tests now keep the actual native thread
and join task until exit. A late MODEL publisher checks the retained controller
state at publication boundaries and refuses to start a successful export after
UNKNOWN. Join-task launch failure also retains the live native thread and first
error. Fixed manifest/proof/projection/cut/export close faults preserve their
first exception, residual files and UNKNOWN without success headers. Queue
receive tasks remain permanent records and must be done before handoff or proof.
DELETE-before-cancel tests verify queued alias END, zero late BEGIN and no 200
until the live native handler exits. Native Windows publication and allocation
qualification still require B2 and an approved source.


Host regressions now exercise all sixteen strict budget fields, the real body
and two-session gates, permanent sequence exhaustion, eight actual chunkbin
operations with ninth-operation refusal, and each file/byte/directory/cut/proof/
manifest export guard before first write. Failed maintenance exchanges count
toward calls and body bytes; a plan that exhausts calls before DELETE cannot
claim successful maintenance closure. Actual socket EOF short of Content-Length
creates a body rejection with no ticket or BEGIN. The MODEL capacity vector and
observed object peaks remain test evidence, not a complete preallocation or
Windows native allocator qualification.


Retained measurement also follows exception cause/context chains, SDK async
generator frames and actual slotted path/state objects; measurement failure is
sticky UNKNOWN. Real socket loss after SDK claim keeps the live handler and
journal until its actual finish. Complete allocation-before-construction bounds remain unfinished.


Eight queued control requests hold pending capacity until DELETE settles them;
no late tool BEGIN is created. A timeout at the final MODEL export close keeps
complete residual files but cannot create a late success receipt. The first
timeout and actual native join remain recorded. Production/native allocation
and publication qualification remain separate work.


Controlled HTTP JSON and binary bodies now reserve their fixed backing storage
before construction or parsing. Content-Length can reduce that storage but never
raise the actual body limit or substitute for ASGI EOF. The CPython 3.13 LP64
buffer-layout charge covers the bytearray, final bytes, views and their managed
buffer; equal-sized view assignment avoids geometric growth and intermediate
data slices. The same private lease transfers to the actual work ticket and
releases only after both HTTP and handler tails. Possible handoff uncertainty
retains it. Atomic instance reservations prevent concurrent double spending.

Native close-I/O can also own an explicit private temporary-storage reservation:
HTTP cancellation, deadline and failed join-task creation do not release a live
thread's quota. Its real wrapper finally, or a confirmed never-started thread,
returns that quota. This primitive does not yet derive the complete snapshot or
export temporary graph. Host socket/thread tests verify storage refusal before
buffer/parser/SDK/BEGIN and real lifecycle ownership. JSON/Pydantic/canonical
heap bounds, complete native Reader/export preallocation and Windows allocator
qualification remain unfinished. These storage charges and observed permanent
graphs do not certify allocator arenas, extension state or total process RSS.
Formal production startup continues to refuse before writers/backend/listener.


The read-only lifecycle export preflight now derives source-SD reserves from the
05 Reader's actual 1 MiB sizing gate. The earlier 64 KiB value was only the
historical MODEL vector and underreserved the production logical closure. For
the example S=2/A=8/R=10 configuration, the actual minimum including one pending
file is 224870400 bytes; its previous 15482880-byte MODEL vector is refused by
this preflight. Historical MODEL cut fixtures retain their original vector.
Host tests execute the complete isolated approval loader and actual ctypes
buffer sizing at the maximum and one above it. They do not execute Win32 APIs
or establish full native workspace, allocator, NTFS or RSS qualification.


Snapshot originals now enter a private bounded Reader path. Their confirmed
same-handle file length is checked against the catalog/request codec limit
before ReadFile or complete Python chunk accumulation; ledger END readback uses
the same early check. Full SD/ancestor binding, actual EOF and post-read identity
rechecks remain required. A lying length still fails the original read gate.
Oversized, invalid or overflowing bounds retain source originals and refuse
without content reads or export writes. Host tests exercise actual Reader and
ledger algorithms with MODEL Windows APIs. This content bound does not complete
reservation of SD/ctypes buffers, parser intermediates or the full snapshot graph.


Closed-export maintenance activation now runs through the existing first pull
`transfer_begin` in the formal HTTP app. The source must be the completed native
receipt of another CLOSED session in the same controller, instance and bearer
owner, inside the already approved transfer read root. Native identity, full SD,
member hashes and directory closure are rechecked before any new transfer writer.
The private planner derives permanent call, byte, attempt, binary and SDK work
reserves from that original and the fixed policy. The live initial GET and prior
SDK control traffic count too. Insufficient capacity, unknown sources and changed
bindings are rejected before BEGIN. Ordinary transfers retain their existing
policy; stdio does not create an observation archive. This stage's tests use
actual SDK sockets, POSIX files and processes with MODEL Win32 authority; they
provide no Windows qualification or new production approval.


Binary transfer requests now carry the actual protocol version negotiated by
that existing SDK session. They retain its session ID and bearer connection;
no second initialization or guessed protocol version is used for chunkbin.


The admitted host API is `velociraptor_observation_maintenance.acquire_original`.
An existing caller supplies its fixed `Admission`, locked run directory, parsed
`HostRequest` from that run's `maintenance-request.json`, and the original fully
consumed business DELETE response. The request is a single pull source named
`original`, derived from the actual close descriptor under the approved namespace;
its destination is `maintenance/downloaded` in the same run. The connection
profile must already be in that fixed group's source allowlist. The host API
reads the existing lifecycle/archive configuration and checks source/run drift
before capture or RPC. It issues no approval and does not widen transfer roots.

It opens one different official SDK session, uses the existing seven tools and
chunkbin on that same session, and preserves full raw request/response bodies,
original headers, complete SDK results, monotonic intervals, transfer attempts
and actual prepare/publication/release receipts. Bounded retries reopen the same
durable prefix with the same transfer ID, digest and original deadline; no
business call is replayed. A network capture failure stays FAILED even if the
original bytes later finish downloading. The independent C4 verifier checks the
exact maintenance model, every actual raw/result/receipt binding, full package
hash/prefix, source SD/proof/projection/catalog/cut/member closure, and the real
maintenance DELETE 200 descriptor before publishing COMPLETE. SDK-swallowed
DELETE failures and truncated response bodies cannot qualify. Receipt requirements
are recomputed from raw-joined full SDK results, including completed finish
responses. Every receipt-bearing call must keep its actual receipt Ref even
when later status calls repeat it; the sorted union retains all observed
prepare/publication originals. Missing references/files or altered receipts
with rebound hashes cannot qualify as COMPLETE. The maintenance
session's own cut is recorded only as its actual response descriptor; it is not
downloaded and no recursive third session is opened.

Artifacts live below `run_dir/maintenance`: `maintenance.json`, `raw-mcp`, header
originals, SDK result/error originals, each `transfer-attempt-NN.json`, the final
transfer result, configuration originals and `downloaded/original`. An admitted
caller may independently read them with `validate_maintenance`; a caller-made
hash or consistent context never supplies source authorization. Current host
verification uses MODEL Win32 authority plus actual POSIX no-follow files,
official SDK sockets and joined transfer processes. Windows/NTFS allocation,
free-space/durability, service identity and production approval remain unverified.
This API is not yet required by P06 sidecar/receive/package/aggregate/handoff
success gates; that S2 consumer integration remains separate work.


Maintenance source detection is enabled only by the native exporter source
interface. Ordinary transfer remains usable with the existing private codec
exporter verification seam; it does not acquire a maintenance reservation.


Maintenance native readback runs outside the controller lock on its retained
I/O thread. The atomic reservation rechecks the source/session afterward. A
timeout keeps UNKNOWN and the real join owner; it cannot publish a late
reservation or block the event loop while waiting for native I/O.


Maintenance quota boundary tests include the actual initial SDK/control history:
one call or one byte below its controlled acquisition plan rejects before BEGIN
and leaves the transfer writer, ledger attempt and child set unchanged.


Host readback now shares the fixed maintenance source authorization seam. Its
private reader recovers the original DELETE correlation from complete saved
request/response header occurrences and the physical body-capture index, without
retaining or reconstructing an httpx response. Duplicate headers, incomplete
bodies, non-200 closes, unapproved profiles and source/run drift refuse with no
writer or new SDK session. The profile remains an independently approved source;
its content hash or a close descriptor does not grant authority. This reader
seam has MODEL governance and real POSIX read-only checks. The independent C5
sidecar and mandatory producer/consumer integration remain unfinished.

The current raw join treats the controller's fully consumed HTTP DELETE 200
empty JSON control response separately from JSON-RPC messages. Nonempty control
objects, non-200 responses, and incomplete bodies still refuse success; tool
responses retain their strict JSON-RPC checks. This does not replace the required
independent archive and maintenance consumption gate.

The fixed-admission host reader independently verifies the actual original DELETE headers, complete downloaded export and maintenance receipts before accepting the exact observation sidecar. It never downloads or repairs missing evidence. A fresh business SDK and second maintenance SDK passed on native POSIX with isolated MODEL governance; eleven missing, rebound or extra-original cases were rejected without reader writes. Windows and the remaining successful-entry integration are not qualified by these tests.

Current HTTP transport capture retains full request and response header originals by the physical exchange sequence, alongside the unchanged seven-field summary. Authorization values are excluded. The actual DELETE response object stays owned by the transport until its stream closes; a summary row alone cannot prove that close barrier.

The separate failure reader derives a finite exact diagnostic record from captured HTTP originals. It assigns attempt numbers only from an independently authorized complete source; missing or ambiguous evidence stays unclassified, and a non-invoked call has only its report sequence. Its exclusive publisher never creates a successful observation sidecar. Actual local HTTP rejection/duplicate/raised-handler tests and a fixed-governance MODEL reader test cover this diagnostic module; current producer and successful consumer integration remains under verification.

Run the bounded diagnostic subset with `.venv/bin/python -B -m unittest tests.test_observation_failure tests.test_observation_failure_http`, supplying the existing isolated bootstrap fixture for fixed-loader tests. The suite loads its own two HTTP cases, while the imported fixtures provide setup and shutdown. Historical source coordinates now pass their exact complete-layout checks. Fresh isolated C8 qualification and actual dual-SDK finalization pass the current public package/receive gates; selected package members and the current receipt ledger also pass independent readback. This is host MODEL evidence, with actual SDK/raw/native activity; full scenario aggregation and Windows qualification remain separate.

Historical PC020 and Snapshot187 adoption validation now select between two
code-owned complete coordinate layouts (34 and 12 sources respectively). Each
layout is checked as an exact set; mixed dates, missing/extra sources and aliases
refuse. Readers still open the original `source/<repo_path>` and verify its
actual size, SHA-256, Git blob and Ref. They never translate an old coordinate
to a current file or rewrite historical policy, Source or canonical bytes.
Current implementation approval and full C8 qualification remain mandatory;
these layout checks alone do not qualify successful consumers or Windows.

The host occurrence reader now binds real transfer children to their captured
transfer request/result identities and verified lifecycle source. A finish that
returns `IN_PROGRESS` needs one uniquely attributable closed child; it does not
require an extra status RPC. Missing, extra, ambiguous or unknown children
refuse. Actual host tests cover integer/string ID separation, a foreign session
with an unfinished global prefix, and finite ACK/END/prefix/SDK/binary refusals.
These scoped tests do not qualify Windows or declare the complete S2 workflow.

Current successful P06 packages require independent readback of the fixed archive,
maintenance ledger and exact observation sidecar before any public inventory,
source resolution, manifest verification or receive. The actual producer preserves
original request/response headers, performs the second maintenance SDK acquisition,
and publishes the sidecar only after deriving the closed source. Missing original
sidecar/cut/ledger/capture/body/SDK result/receipt bytes reject even when outer
hashes are rebound. Selected handoff members reuse these gates; this mechanism
does not mint a completion record.

Failed finalization preserves the first failure, raw originals and diagnostic
package without publishing BOUND. A pre-seal failure can seal its failed candidate
once; an already-started package or receipt append is never retried. Secondary
preservation errors attach notes to the primary exception.

The private selected-run member collector requires the real fixed Admission and
resolves every member through the same public package gates. A finite actual
acquired-run matrix also checks the public current receipt ledger: missing any
one of seven required originals rejects without writing selection, receipt or
handoff output. Historical readers cannot treat a current root as old evidence.
This verifies selected-member consumption, not the outer five-run aggregate or
P07 completion/publication.

The internal maintenance SDK closes its owned captured GET body normally before
stopping the SDK reconnect loop and sending the actual session DELETE. It retains
capture errors and the original DELETE response instead of manufacturing close
proof. A failed capture can refuse further network effects; an earlier SDK error
remains primary and receives cleanup notes. COMPLETE still requires the original
bodies, headers, receipt objects and independent C4 readback to agree.

Current HTTP resource qualification and individual acceptance retain their
actual call clock, complete SDK responses and original request/response headers.
They use a separate maintenance SDK to acquire the fixed archive before the
independent binding, package and receiver gates. Individual acceptance retains
and compares both tools/list results. Failed attempts preserve diagnostics with
empty coverage and no BOUND sidecar. Host MODEL runs exercise the actual client
and consumer path; Windows resource readings and production approval remain
separate acceptance requirements.

Formal failure packets retain UNKNOWN close, unacknowledged calls, returned
wire errors and truncated maintenance bodies without upgrading coverage or
publishing BOUND. Attempt numbers require authentic available source originals;
a missing approved cut remains UNCLASSIFIED. An independently verified native
source can establish a wire-error classification without rewriting that packet.

# Velociraptor MCP
Velociraptor MCP is a POC Model Context Protocol bridge for exposing LLMs to MCP clients.

The current local bridge registers 136 tools: the original 118 dynamic and 12 fixed tools, plus six guest transfer tools (`transfer_capabilities`, `transfer_begin`, `transfer_status`, `transfer_chunk`, `transfer_finish`, `transfer_abort`). See [transfer MCP contract](docs/transfer-mcp.md) and [guest engine](docs/transfer-guest-engine.md). A protected `VELOCIRAPTOR_TRANSFER_POLICY` enables local transfer operations; without it the six tools remain listed, capabilities reports disabled, and the original 130 tools remain available. Windows VM and host coordinator acceptance follow separately.

> Development status: P05/P06/P07 acceptance reopened; remediation is not yet accepted.
> The previous acceptance snapshots have been removed by the operator. The
> retained fixed-IP baseline is being requalified; do not run historical
> recovery commands or treat old reports as current acceptance.
> The bridge exposes 118 reviewed Windows CLIENT artifacts as
> dynamically generated MCP tools. Their names, descriptions, parameters, and
> definition hashes are checked against the connected root organization before
> stdio starts. Twelve fixed tools provide bounded VQL, single-endpoint Hunt,
> Flow lifecycle, one-file collection/download, basic triage, and process
> termination. The current 136-schema combination is validated before stdio starts.
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
server or stopping backend processes. Actual Windows lifecycle acceptance
remains unfinished.

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
| Formal HTTP entry | The production transport: one stateful Streamable HTTP server on the exact guest host-only address, port 28790, path `/mcp` | Selected with `VELOCIRAPTOR_MCP_TRANSPORT=http` plus an exact host, a non-empty bearer token, and optional allowed origins; wildcard binds, other ports or paths, or an empty token are rejected before any socket opens. Requests must pass a constant-time bearer check and Host/Origin allowlists (DNS rebinding protection stays on) before any tool runs. Every response carries a process-scoped `X-MCP-Server-Instance` value that changes on restart and cannot be forged by clients. |

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

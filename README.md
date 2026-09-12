# Velociraptor MCP
Velociraptor MCP is a POC Model Context Protocol bridge for exposing LLMs to MCP clients.

> Development status: P06 complete. 118 reviewed Windows CLIENT artifacts as
> dynamically generated MCP tools. Their names, descriptions, parameters, and
> definition hashes are checked against the connected root organization before
> stdio starts. Twelve fixed tools provide bounded VQL, single-endpoint Hunt,
> Flow lifecycle, one-file collection/download, basic triage, and process
> termination. All 130 schemas are validated together before stdio starts.
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
- `ENABLE_DANGEROUS_TOOLS` is legacy source only and does not control or expose
  any P04 tool. P07 has physically removed that dead compatibility source.
- Set `VELOCIRAPTOR_DOWNLOAD_ROOT` to an existing absolute directory before
  calling `download_flow_file`. Completed files are never overwritten.
- The agent POC defaults to local Ollama summaries. Set `VELOCIRAPTOR_MODEL_PROVIDER=azure`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, and `AZURE_OPENAI_MODEL` when you explicitly want Azure OpenAI summaries.

### 3. Connect to MCP client of choice

The easiest configuration is to run your venv python directly calling
`mcp_velociraptor_bridge.py`. You can either put values directly in the MCP
client config:

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

All 130 tools return MCP-native `structuredContent`, an empty
`content` list, and the protocol `isError` flag. Success models contain only
the documented operation fields, real backend identifiers/states, and public
warnings. Errors use stable
`code/message/retryable/details` fields. Paged results use opaque canonical
`v1:<offset>` cursors, default to 50 rows, accept at most 250 rows, and enforce a
245554-byte limit on the complete serialized `structuredContent` object.

The accepted Windows environment uses the post-install Snapshot 186 network deployment baseline.
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

On the accepted Snapshot 186 environment, all 118 dynamic tools have their
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
disk before admitting the full execution scenarios.

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

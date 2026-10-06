# Daily AI workflows over the host CLIs

This page routes the ordinary AI loop to the existing host entry points. An
AI caller with a mechanical next-step decision (keep polling? next page?
list files?) should run one host CLI command instead of making those calls
one MCP round at a time. Direct MCP remains the documented path for
interactive or advanced operations; nothing here changes tool contracts,
permissions or the 137-tool registry.

## Which layer to use

| Need | Entry |
|---|---|
| Read one existing flow (wait, all pages, file list, evidence on disk) | `velo_flow` host CLI (below) |
| Move files across the host/guest boundary | `velo_transfer` CLI — [host request](transfer-request.md), [host coordinator](transfer-host-coordinator.md) |
| Interactive queries, starting a collection, cancelling, hunts | Direct MCP tools as in [practical use](practical-use.md) |
| Programmatic in-process client with model-facing bounded views | Shared client `agent_poc/velociraptor_mcp_runtime.py` — [model context selection](model-context-selection.md) |

An external MCP client (for example a general Codex CLI session) that
connects to the bridge does **not** automatically gain the shared client's
`allowed_tools` narrowing or bounded model views; those belong to the
in-process shared client, which keeps full schemas, the execution gate and
bounded `velo.model.view.v1` output by design. The mechanical-loop reduction
for outside callers is exactly the host CLIs on this page — not automatic
schema trimming on the server.

## Reading one flow: `velo_flow`

Save the real `flow_id` returned by an authorized collection, then run one
foreground command:

```text
.venv/bin/python -m velo_flow --spec /absolute/path/to/flow-request.json
```

The host waits for `FINISHED`, pages the chosen result source to its
terminal cursor, lists the flow files once, and writes everything into one
new output directory; stdout carries a single bounded JSON summary
(≤4096 bytes) with outcome, `rows_saved`, `call_counts`, `complete` and the
`result_path`. The model reads only that summary plus the evidence paths it
needs. Full contract: [flow host coordinator](flow-host-coordinator.md).

Request example (`velo.flow.request.v1`, placeholder paths — replace with
your own absolute paths; the profile stays private and is never echoed):

```json
{
  "schema": "velo.flow.request.v1",
  "flow_id": "F-EXISTING-FLOW-ID",
  "connection_profile": "/absolute/private/path/velo-connection-profile.json",
  "output_dir": "/absolute/new/path/flow-read-F-EXISTING-20261006",
  "source": null,
  "page_size": 250,
  "sample_fields": [],
  "sample_rows": 10,
  "budget": {
    "deadline_seconds": 120,
    "request_timeout_seconds": 30,
    "max_status_calls": 64,
    "max_pages": 100,
    "max_result_bytes": 67108864,
    "max_log_bytes": 67108864
  }
}
```

Hard limits that the AI caller must respect:

- The flow must already exist. The host never starts, replays or cancels a
  collection, never changes `source` mid-run and never retries a call; a
  failed or partial run is re-read in a **new** output directory, not
  resumed in place.
- `output_dir` must not exist yet; every file is written exclusively.
- A file listing is **not** a download proof. `list_flow_files` only
  enumerates; retrieving file content goes through `velo_transfer`.
- `complete=true` requires `FINISHED` plus every page persisted plus a
  complete file list and a clean shutdown. `ERROR` flows end `failed`
  (`flow_error`); hitting a budget ends `partial` (for example
  `page_budget`) with `next_unread_cursor` recorded — never reported as
  complete.
- Exit codes: `0` complete, `2` partial/failed, `3` input error before any
  business call.

## Call accounting

One AI-issued CLI run is **not** one backend request. A single
`velo_flow` execute performs: M `list_tools` metadata-page reads, then N
`get_flow_status` polls (backoff 1/2/4/8/10 s), then P `get_flow_results`
pages, then 1 `list_flow_files` call on the complete path. Metadata may span
multiple pages; the offline fixture uses one. The summary's `call_counts`
counts business calls only. Their raw requests/responses land in
`calls.jsonl` (with size and SHA-256 in `result.json`); discovered tool
schemas are retained in `contract.json`. Offline
adoption evidence with the real execute chain: `tests/test_host_workflow_adoption.py`.

## Moving files: `velo_transfer`

```text
.venv/bin/python -m velo_transfer --spec /absolute/path/to/transfer-request.json
.venv/bin/python -m velo_transfer --spec /absolute/path/to/transfer-request.json --abort
```

The request grammar, budgets, identity binding, resume-by-original-ID and
uncertain-outcome reconciliation are already fixed in
[host request](transfer-request.md) and
[host coordinator](transfer-host-coordinator.md); this page does not repeat
the transfer tool schemas. Resume keeps the original transfer ID and fixed
deadline; `--abort` cancels the original task without deleting evidence.
Never trim validation, print tokens or delete checks to save tokens.

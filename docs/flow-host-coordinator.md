# Flow Host Coordinator (velo_flow)

`velo_flow` is a bounded foreground CLI that lets the host complete, in one
process, what an AI caller would otherwise do step by step: wait for one
existing Velociraptor flow to reach `FINISHED`, read every page of one result
source, persist the raw responses and rows, list the flow files once, and print
one bounded summary. It exists to keep per-call status/page decisions and large
result bodies out of the model context.

Entry:

```text
.venv/bin/python -m velo_flow --spec /absolute/path/to/request.json
```

## What it does and does not do

- It only collects an **existing** flow. It never starts, replays or cancels a
  collection, and it never sends VQL or any expression field.
- It reads through exactly three existing fixed tools — `get_flow_status`,
  `get_flow_results`, `list_flow_files` — over the authenticated Streamable
  HTTP endpoint described by the private connection profile. The 137-tool
  registry, schemas and approval gates are unchanged.
- It does **not** download files. `list_flow_files` only enumerates; when a
  file must be retrieved, keep using the existing `velo_transfer` CLI. A listed
  `file_id` is not a claim that the host holds the file.
- Each run creates one new output directory; re-reading the same flow requires
  a new directory. There is no cursor-resume promise across runs, no forensic
  chain-of-custody proof, and no Windows VM acceptance claim — those remain
  separate qualifications.

## Request spec (velo.flow.request.v1)

One strict JSON object, at most 65536 bytes. Duplicate keys, `NaN`/`Infinity`,
unknown fields, booleans in integer fields and relative paths are rejected
before any connection is made. Example with placeholder values:

```json
{
  "schema": "velo.flow.request.v1",
  "flow_id": "F-EXAMPLE",
  "connection_profile": "/absolute/path/to/velo-connection-profile.json",
  "output_dir": "/absolute/path/to/new-output-directory",
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

- `flow_id` (required): the existing flow, non-empty, no control characters,
  at most 256 characters.
- `connection_profile` (required): absolute path to the private
  `velo.transfer.connection.v1` profile; only its `velo` endpoint is used and
  the bearer token never appears in spec output or logs.
- `output_dir` (required): absolute path of a directory that does not yet
  exist; the parent must exist, no ancestor may be a symlink. The directory is
  created with mode 0700 and every file is written exclusively (never
  overwritten).
- `source` (optional): one result source, or `null` for the merged default.
- `page_size` (optional, default 250, 1..250), `sample_fields` (optional,
  up to 32 field names for the summary projection), `sample_rows` (optional,
  default 10, 0..10).
- `budget` (optional; every key has the default shown): one monotonic deadline
  covers connect, initialize, metadata listing, status polling, pages and the
  file list; each call is additionally bounded by `request_timeout_seconds`.
  Status polling backs off 1/2/4/8/10 s and stops at `max_status_calls`.
  `max_result_bytes` bounds `rows.jsonl` (a page that does not fit whole is
  not partially written), and `max_log_bytes` bounds `calls.jsonl` (a 1 MiB
  slot is reserved before each call; when no slot is free the run stops
  instead of calling).

## Output directory contents

- `contract.json` — the three tools' complete input/output schemas as served
  by the live endpoint, each validated with `Draft202012Validator.check_schema`.
- `calls.jsonl` — one record per business call: tool name, exact arguments and
  the complete `CallToolResult` (`model_dump(mode="json", by_alias=True)`).
  Error responses are kept here for diagnosis.
- `rows.jsonl` — the complete result rows, one compact JSON object per line,
  never trimmed by the summary projection.
- `result.json` — the bounded summary (`velo.flow.result.v1`, at most 16384
  bytes): outcome (`complete`/`partial`/`failed`) and reason, last observed
  state, pages fetched/saved, rows saved, next unread cursor when the run
  stopped early, files count/completeness, call counts, sample rows with an
  honest omission count, warning counts, file sizes and SHA-256 digests, and a
  stable error code (never an exception repr).

stdout carries exactly one compact summary JSON (at most 4096 bytes); progress
diagnostics go to stderr with `--debug`. Exit codes: `0` complete, `2`
partial or failed, `3` input error before any business call.

`complete` requires `FINISHED`, every page read to the terminal cursor with
the whole page persisted, a complete (non-truncated) file list and a clean
SDK/HTTP shutdown; a zero-row, zero-file flow can still be complete. A flow
that ends in `ERROR` is recorded as `failed` with reason `flow_error` and no
result pages are fetched. Server-issued opaque cursors are echoed and checked
for advance; repeated or empty continuations stop the run as `protocol_error`.
Calls are never retried, and no other flow is touched.

## Verification boundary

The implementation is verified by bounded offline evidence (spec validation
through the real CLI entry, full MODEL runs of the production core with real
SDK metadata and result models, one case per required failure branch, and
close-fault injection through the CLI's own session-factory seam). The real
network SDK path is exercised only at a live deployment site; this document
makes no Windows VM, deployment or usage-reduction claim.

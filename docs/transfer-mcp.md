# Local guest transfer MCP tools

The bridge registers six local guest tools on its existing MCPServer. The complete face is 118 reviewed dynamic artifacts, 12 existing fixed tools, and six transfer tools: 136 exact names. The original 130 names and their input and output schemas remain unchanged. Both stdio and the existing stateful HTTP entry use this server. Formal HTTP remains on the configured guest address at port 28790, path `/mcp`, behind the existing bearer, exact Host, and session gates. No transfer tool accepts `client_id` or uses `target_context` to select a Velociraptor endpoint.

These tools operate on the MCP service's own Windows guest roots from `VELOCIRAPTOR_TRANSFER_POLICY`. The service builds one `GuestTransferService` lazily and holds it until bridge shutdown. A missing policy does not initialize Windows identity or ACL providers: `transfer_capabilities` succeeds with `enabled=false`, while the other five actions return `transfer_disabled`. A nonempty invalid policy, VM UUID/boot mismatch, or denied local path returns a stable error and does not turn into an automatic fallback. Production construction always uses real Windows observation and `WindowsAclVerifier`; only Python unit tests can explicitly inject a factory. Bridge shutdown, formal stop request, and exits after the server was created invoke the owned service's `shutdown`. A stop failure is reported and prevents a success return.

## Names, arguments and result

| Tool | Exact arguments |
| --- | --- |
| `transfer_capabilities` | none |
| `transfer_begin` | `request` object below |
| `transfer_status` | `transfer_id`, `request_digest` |
| `transfer_chunk` | `transfer_id`, `request_digest`, nonnegative integer `offset`, positive integer `count`, optionally both `data_base64` and `chunk_sha256` for push |
| `transfer_finish` | `transfer_id`, `request_digest`, `action` (`prepare`, `commit`, `release`); commit requires `prepare_receipt` and `source_validation_receipt`; release requires `prepare_receipt` and `publication_receipt`; prepare has none |
| `transfer_abort` | `transfer_id`, `request_digest` |

The published Draft 2020-12 input schemas are also enforced against raw wire arguments before SDK/Pydantic conversion. They reject unknown top-level and nested keys, wrong types, boolean integers, integer substitutes for booleans, and wrong direction/package or action/receipt combinations. JSON strings are not automatically parsed as nested objects; explicitly present null receipts are rejected where the schema requires their absence. The guest engine also checks the complete request digest, receipt identity, policy limits, source/destination authorization, chunk bytes and hashes at runtime. The `request` for begin has exactly these fields (plus `package` only for push):

```json
{
  "protocol_version": "velo.transfer.v1",
  "transfer_id": "example-1",
  "request_digest": "<sha256-of-canonical-immutable-request-without-this-field>",
  "direction": "pull",
  "sources": [{"absolute_path": "E:\\TransferEvidence\\benign.txt", "relative_path": "benign.txt"}],
  "expected_destination": {"endpoint": "host", "identity": {"host": "fixture-host"}, "canonical_path": "/tmp/host-result"},
  "expected_vm_identity": {"vm_uuid": "00000000-0000-4000-8000-000000000001", "boot_identity": "<observed-boot>", "vm_epoch": "<workflow-epoch>"},
  "evidence_context": {"producer_complete": true, "producer_quiescent": true, "references": ["fixture-evidence-ref"]},
  "budget": {"max_files": 100, "max_metadata_bytes": 100000, "max_logical_bytes": 1000000, "max_package_bytes": 2000000, "min_free_bytes": 0, "max_chunk_bytes": 1048576, "max_duration_seconds": 60}
}
```

For push, set `direction=push`, destination `endpoint=guest`, a policy authorized guest destination, and add `package={"size":...,"sha256":"...","manifest_sha256":"..."}`. The host path for pull is an opaque receipt descriptor on the guest. The example identities and receipts are placeholders, not evidence of a real VM or publication. The `request_digest` is computed by `velo_transfer.guest_service.request_digest` over the complete immutable request except the digest field. A transfer ID cannot be reused with changed intent. Full guest rules and recovery windows are in [transfer-guest-engine.md](transfer-guest-engine.md).

Every completed tool call has exactly one of these structured response shapes:

```json
{"schema":"velo.transfer.mcp.response.v1","status":"success","result":{"schema":"velo.transfer.guest.response.v1","local_phase":"SOURCE_PREPARING"}}
```

```json
{"schema":"velo.transfer.mcp.response.v1","status":"error","error":{"code":"transfer_disabled"}}
```

The `result` preserves the guest operation's actual fields, including local `state_scope`, operation ID, receipts, worker state and verified offset where applicable. A guest error returns only its stable code; unexpected failures use `internal_error`. Malformed transfer arguments rejected before the handler appear as MCP `isError` with `invalid_transfer_arguments`; raw argument values and underlying validation messages are omitted, and no guest factory or operation is invoked. Neither a successful tool call nor guest `SOURCE_RELEASED`/`DEST_RELEASED` is global `COMPLETE`. Never log a successful pull chunk `data_base64` or credentials; it is a program payload for the host coordinator.

## Asynchronous action sequence

For pull, call begin, poll status until `SOURCE_READY`, request bounded chunks to a host-owned package, call finish `prepare`, poll `SOURCE_PREPARED`, and only after the host really publishes and verifies its destination supply the retained prepare and host publication receipts to finish `release`. Poll through `SOURCE_RELEASING` to `SOURCE_RELEASED`. For push, begin with a fixed package identity, send sequential chunks with base64 and SHA-256, finish `prepare` and poll `DEST_PREPARED`, provide retained prepare and source-validation receipts to finish `commit`, poll `DEST_PUBLISHED`, then provide the matching prepare and guest publication receipts to finish `release`. Poll to `DEST_RELEASED`. `IN_PROGRESS` is normal; repeat with the same ID, digest, action and receipts after a lost response. Do not synthesize receipts from these examples. The later host coordinator must own the other endpoint, reverify its final directory, and persist global completion.

`transfer_abort` marks cancellation and stops only a matching owned worker; it preserves original sources, partial packages and published directories. Normal bridge shutdown invokes the same service's bounded worker shutdown. The six tools are already registered when the transfer policy is absent, leaving the legacy 130 functional. Tests cover local Linux fixtures with explicit injected guest observation; real Windows VM, host finalization, deployment and large-file end-to-end acceptance remain separate work.

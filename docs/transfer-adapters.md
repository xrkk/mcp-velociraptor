# Host transfer adapters (internal API)

`velo_transfer.connection.load_connection_profile(path)` loads a protected, deployment-owned JSON file. `velo_transfer.adapters.open_adapter(...)` opens one channel, and `select_adapter(...)` performs a read-only Velo probe before any first `transfer_begin`. These modules transport the six reviewed guest operations; they do not build packages, publish host output, manage global phases or decide `COMPLETE`.

## Connection profile

The exact version 1 object has four keys:

```json
{
  "version": "velo.transfer.connection.v1",
  "velo": {"endpoint": "http://127.0.0.1:28790/mcp", "token_file": "/protected/existing-velo-token"},
  "windows": {"endpoint": "http://127.0.0.1:28791/mcp"},
  "deployment": {
    "python_path": "E:\\Tools\\Python\\python.exe",
    "project_root": "E:\\Tools\\mcp-velociraptor",
    "policy_path": "E:\\TransferPolicy\\policy.json",
    "guest_work_root": "E:\\TransferWork"
  }
}
```

`windows` may be `null`; when present it may also contain `token_file` referencing an existing Windows-MCP bearer. Velo always needs a token reference. This profile and tokens must already exist under a trusted, non-writable ancestor chain and be private regular files owned by the host process identity. Symbolic links, hard links, changed file identity, duplicate JSON keys, oversized files, token newlines and insecure modes fail closed. Tokens are read again just before connecting, then used only in SDK Authorization headers. No token or complete request body is kept in adapter observations or exception text. URLs are HTTP(S) `/mcp` endpoints without user info, query or fragment; redirects are disabled. Guest deployment paths are local Windows absolute paths without UNC, device paths, ADS or `..`. The deployment owns the already-created guest work root, its private `requests` directory, the fixed helper, and the guest policy. A request spec cannot select them.

## Python calls

```python
import time
from velo_transfer.connection import load_connection_profile
from velo_transfer.adapters import select_adapter

profile = load_connection_profile("/protected/transfer-connection.json")
deadline = time.monotonic() + 120
async with select_adapter(profile, expected_vm_identity={
    "vm_uuid": observed_uuid, "boot_identity": observed_boot,
}, deadline_monotonic=deadline, request_timeout_seconds=15) as adapter:
    # The coordinator persists adapter.channel and attempted begin before its first begin.
    capabilities = await adapter.call("transfer_capabilities", {})
    # Then call transfer_begin/status/chunk/finish/abort with the published tool arguments.
```

`select_adapter` returns the same adapter object as `open_adapter`; inspect `adapter.channel`, `adapter.fallback_reason`, `adapter.raw_chunk_bytes`, and `adapter.observations`. Observations include endpoint, `x-mcp-server-instance`, VM UUID, boot identity, build, policy ID and guest limits, never the token. A changed Velo instance raises `instance_changed`; reconcile identity and the existing transfer ID before another action. `vm_epoch` remains the workflow's external evidence and is never inferred from capabilities. The coordinator must persist channel choice and begin attempt before calling begin; pass `begun_channel` on recovery to prohibit switching channels.

Velo uses the installed official MCP SDK Streamable HTTP client with environment proxies disabled. Its six names and exact input/output schemas are checked against `velo_transfer/transfer_tools_schema.json`, a mechanical copy of the reviewed test golden. MCP `isError`, absent or conflicting structured content, malformed envelopes and guest errors never become success. Read-only status/capabilities calls make at most three bounded transport attempts; modifying calls are sent once. All requests share the original monotonic deadline. Only confirmed connection refusal, missing new tools, or explicit `enabled=false` permit pre-begin Windows fallback. Authentication or Host denial, schema/protocol drift, identity mismatch and a single timeout do not. `AdapterError` exposes stable `code`, `may_have_committed`, and `retryable` fields, plus the validated operation, transfer ID and request digest when an attempted call fails. A lost modifying response is `outcome_unknown` and requires same-ID status reconciliation by the coordinator.

Windows uses only the existing Windows-MCP `PowerShell(command, timeout)` tool and fixed command templates. It writes one random private control JSON file under `<guest_work_root>\requests`, with exact `operation` and `arguments` keys, then invokes `python -m velo_transfer.guest_cli --request-file <that-file>`. Upload segments are offset/count/SHA-256 checked and replayed byte-for-byte after a lost acknowledgement. Final size and hash are checked before invoking the helper. The 28,000 character budget includes Windows-MCP's UTF-8 prefix, its UTF-16LE Base64 `-EncodedCommand`, and the shell argv; a 4096-byte segment is reduced when needed. The request is capped at 4 MiB, and a too-long minimum segment fails. The helper's one JSON line and outer `Response`/`Status Code` are both validated. The adapter removes only its own random control file after a confirmed creation. A cleanup failure exposes `observations["cleanup_failed"]`, a `cleanup_path`, and the already received `guest_result` on `AdapterError`; the caller must retain any action or publication receipt in that result. An unknown create acknowledgement leaves `control_cleanup_unknown` and `pending_control_path` for reconciliation without claiming the file. The helper and guest policy still enforce guest identity, ACLs and the fixed request root. The PowerShell templates are simulated on Linux; their actual Windows behavior remains to be checked on the target VM during deployment.

Control scripts use terminating PowerShell errors. Their ACK parser accepts exactly one line with one optional LF or CRLF terminator. The create ACK carries the file's volume and file index; each later script verifies that identity before use, and cleanup marks deletion on the same verified file handle so a replaced path is not deleted. The helper's single JSON line is parsed with the outer `Status Code`: exit 0 requires `status:success`, while exit 3 or 4 requires a matching `status:error` envelope and preserves its stable code. Any other pairing, malformed line, or extra output fails closed. The Windows chunk limit is the minimum of 4096 bytes and the guest's validated maximum and default chunk sizes. A transmitted modifying call with a malformed or contradictory response remains an unknown outcome tied to its original transfer ID and request digest. A TLS or certificate error, or a connection error without a proven unreachable network cause, cannot trigger fallback.

The adapter's response is the raw guest operation result dictionary. A guest `SOURCE_RELEASED` or `DEST_RELEASED` remains a local result. The host coordinator owns package bytes, host publication and re-verification, receipt persistence, final release/tombstone reconciliation, host cleanup and global completion.

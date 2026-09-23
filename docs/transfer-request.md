# Host request grammar (internal API)

`velo_transfer.request.load_request(absolute_path)` reads one strict UTF-8 JSON spec (at most 1 MiB) and returns a `HostRequest`. This module only checks input syntax and constructs the existing guest `transfer_begin` contract. The host coordinator and `python -m velo_transfer --spec ...` command are separate work. Parsing does not open sources, destination, profile, evidence references or any MCP connection, and does not create the derived `work_root`.

## Push example

```json
{
  "schema": "velo.transfer.request.v1",
  "direction": "push",
  "sources": [{"absolute_path": "/evidence/资料 零.bin", "relative_path": "资料/零.bin"}],
  "destination_directory": "E:\\TransferEvidence\\batch-1",
  "connection_profile": "/protected/transfer-connection.json",
  "expected_vm_identity": {
    "vm_uuid": "123e4567-e89b-42d3-a456-426614174000",
    "boot_identity": "observed-boot", "vm_epoch": "workflow-epoch"
  },
  "evidence_context": {
    "producer_complete": true, "producer_quiescent": true,
    "references": ["producer-record"]
  },
  "budget": {
    "max_files": 100, "max_metadata_bytes": 100000,
    "max_logical_bytes": 10000000000, "max_package_bytes": 12000000000,
    "min_free_bytes": 0, "max_chunk_bytes": 1048576,
    "max_duration_seconds": 3600, "request_timeout_seconds": 30
  }
}
```

For a pull, set `direction` to `pull`, use local Windows drive paths for source `absolute_path` (for example `E:\\Exports\\report.bin`), and a POSIX `destination_directory` such as `/evidence/incoming/batch-1`. An optional explicit `transfer_id` uses the guest identifier grammar. Set `resume: true` only with an explicit ID; the future coordinator must prove the previous journal and source, VM, package and channel bindings before resuming. A missing ID is generated once. The parser normalizes a canonical UUID and defaults `resume` to false.

The exact eight budget keys are the guest's seven request limits plus `request_timeout_seconds`. All guest limits are integers other than booleans; logical bytes and free reserve may be zero. The per-request timeout is finite, positive, no more than 300 seconds and no more than the requested total duration. Limits do not assert actual free space or policy approval. The coordinator supplies its already fixed monotonic deadline to `HostRequest.content_budget(deadline)`; this method does not refresh it. `guest_budget` contains only the seven guest fields. Source count and the canonical JSON byte size of the explicit sources and evidence metadata are checked before source entries are processed. Evidence references are limited to 4096 entries, each a nonempty string of at most 512 characters. Actual directory enumeration remains the content layer's bounded work.

Paths must be absolute and lexically canonical. POSIX paths use `/`; Windows paths require a local `X:\\` drive and backslashes. Dot, empty and parent components, devices, ADS, reserved names, ambiguous aliases and trailing spaces or dots are rejected. Source `relative_path` uses `manifest.check_relative`; duplicates, case-fold collisions and file/parent overlap are rejected. Syntactically valid nonexistent source paths can pass this stage because source availability and trust are checked by the coordinator and content layer. The spec itself must be a regular, single-link file with stable identity, size and mtime before, during and after bounded reading; symlink path chains and hard links fail. Filesystem and JSON errors expose stable `TransferContentError.code`, without echoing contents or paths.

## Conversion

```python
from velo_transfer.request import load_request, make_guest_request

request = load_request("/absolute/request.json")
guest_begin = make_guest_request(request, verified_destination, package_identity)
```

`verified_destination` is a caller-verified `{endpoint, identity, canonical_path}` descriptor. Its endpoint and canonical path must match the parsed direction and requested destination. Push requires the already fixed package `{size, sha256, manifest_sha256}` with a nonnegative size within `max_package_bytes` and lowercase SHA-256 digests; pull forbids a package argument. The result has the existing `velo.transfer.v1` guest fields and `guest_service.request_digest` computed over the complete request excluding only that digest field. `intent_digest` hashes the canonical normalized host document excluding `transfer_id` and `resume`. It identifies the initial host intent only and never substitutes for the package-bound guest request digest. Returned dictionaries are independent copies. The parser never establishes guest identity, producer quiescence, path permissions, policy intersection, receipt validity or global `COMPLETE`.

Exponent overflow, non-finite numbers, lone Unicode surrogates, UTF-16 and UTF-32 input are rejected as `invalid_json`; extreme timeout and deadline values produce stable budget/deadline errors.

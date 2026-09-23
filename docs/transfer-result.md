# Host transfer result contract (internal API)

`velo_transfer.result` validates a caller-supplied declaration. It performs no transfer, filesystem read or write, guest check, publication, cleanup, stdout write, or phase transition. The host coordinator must establish the physical facts, persist the complete canonical result under an authorized `HostJournal` evidence path, and only then print one serialized `result_summary` line. A structurally valid `complete` document does not prove delivery by itself.

## Interface

`validate_result(document, *, max_files, max_metadata_bytes)` returns a deep copy. `encode_result` returns canonical UTF-8 JSON bytes using `manifest.canonical_json`; `decode_result` accepts bounded UTF-8 JSON with no duplicate keys and revalidates it. `result_exit_code` and `result_summary` also validate the full document. All functions use the request budget already fixed by the coordinator; this module neither chooses nor extends it. Invalid values raise `TransferContentError.code` without echoing input.

| outcome | exit | required phase and facts |
| --- | ---: | --- |
| complete | 0 | COMPLETE; publication, destination, both cleanups and evidence attested |
| rejected | 2 | FAILED; definitely never published |
| incomplete | 3 | Any phase except COMPLETE; retain true, false or unknown publication |
| conflict | 4 | CONFLICT or FAILED; published truth retained, including damage after publication |
| cleanup_pending | 5 | PUBLISHED or CLEANING; published with receipt, at least one cleanup not true |

The `source_stability` value distinguishes a required pre-release source change from a later change after authorized release. A later change may coexist with complete only when final destination verification and both cleanups are true. A guest local success cannot establish host COMPLETE. Pull complete requires actual verified `source_vm_identity`; push uses null because the source is the host. `channel=windows` requires a bounded machine `fallback_reason`; other channels require null. This validator never chooses fallback. A current or last PUBLISHED/CLEANING/COMPLETE phase, or a publication receipt hash/reference, requires `published_ever=true` even in a later failure. Known publication also requires the original task, request, channel, destination and package binding. Before any affirmative publication fact is available, unknown stays null; a recovered known publication may still lack a durable receipt and remain incomplete.

`package_sha256`, `package_size`, and `manifest_sha256` are either all null or all known. File sizes and package size are exact nonnegative integers, including zero and values above 4 GiB. `files=[]` is valid for an empty directory. File entries are declarations and are not rehashed here. The relative paths use the manifest grammar and reject duplicates, case-fold collisions, and file/parent conflicts. Path text is bounded, UTF-8 encodable, and contains no control characters.

`evidence_index` references only the six-field value actually returned by `HostJournal.write_evidence`: name, size, sha256, device, inode, mtime_ns. The result validator checks shape and numeric types, not persistence or physical identity. Complete requires roles `publication_receipt`, `destination_verification`, `host_cleanup`, and `guest_cleanup`; the publication reference hash must equal `publication_receipt_sha256`. A publication receipt retains the true destination directory identity in journal evidence, not in this summary. Warning codes are unique machine identifiers, never raw tool output or credentials.

`result_summary` contains exactly schema, transfer_id, phase, outcome, exit_code, published_ever, result_path, and file_count. The absolute normalized host `result_path` is syntax-checked only; the caller must first confirm the result bytes were durably stored in its protected path. A failed persistence step must not print a path as though the result had landed.

## Complete, validated examples

All JSON blocks below are full result documents. They are fixture declarations; their paths, hashes, VM identity, and evidence references do not claim a real transfer. Each block is decoded by the module in the test suite.

### Completed push

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "complete",
  "transfer_id": "task-1",
  "request_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "direction": "push",
  "channel": "velo",
  "fallback_reason": null,
  "source_vm_identity": null,
  "destination_identity": {
    "endpoint": "guest",
    "identity": {
      "node": "verified"
    },
    "canonical_path": "E:\\Delivery\\batch"
  },
  "package_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "package_size": 4294967303,
  "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "resumed_bytes": 0,
  "files": [
    {
      "source": "/evidence/资料.bin",
      "relative_path": "资料/零.bin",
      "destination": "E:\\Delivery\\batch\\资料\\零.bin",
      "size": 4294967301,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ],
  "source_stability": "stable_at_required_check",
  "phase": "COMPLETE",
  "last_phase": "CLEANING",
  "published_ever": true,
  "destination_verified": true,
  "cleanup": {
    "host": true,
    "guest": true
  },
  "publication_receipt_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "warnings": [],
  "evidence_index": [
    {
      "role": "publication_receipt",
      "reference": {
        "name": "publication_receipt",
        "size": 32,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "device": 1,
        "inode": 10,
        "mtime_ns": 100
      }
    },
    {
      "role": "destination_verification",
      "reference": {
        "name": "destination_verification",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 11,
        "mtime_ns": 100
      }
    },
    {
      "role": "host_cleanup",
      "reference": {
        "name": "host_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 12,
        "mtime_ns": 100
      }
    },
    {
      "role": "guest_cleanup",
      "reference": {
        "name": "guest_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 13,
        "mtime_ns": 100
      }
    }
  ]
}
```

### Completed pull after authorized release

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "complete",
  "transfer_id": "task-1",
  "request_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "direction": "pull",
  "channel": "velo",
  "fallback_reason": null,
  "source_vm_identity": {
    "vm_uuid": "123e4567-e89b-42d3-a456-426614174000",
    "boot_identity": "boot-1",
    "vm_epoch": "epoch-1"
  },
  "destination_identity": {
    "endpoint": "host",
    "identity": {
      "node": "verified"
    },
    "canonical_path": "/evidence/incoming/batch"
  },
  "package_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "package_size": 4294967303,
  "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "resumed_bytes": 0,
  "files": [
    {
      "source": "E:\\Export\\资料.bin",
      "relative_path": "资料/零.bin",
      "destination": "/evidence/incoming/batch/资料/零.bin",
      "size": 4294967301,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ],
  "source_stability": "changed_after_authorized_release",
  "phase": "COMPLETE",
  "last_phase": "CLEANING",
  "published_ever": true,
  "destination_verified": true,
  "cleanup": {
    "host": true,
    "guest": true
  },
  "publication_receipt_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "warnings": [],
  "evidence_index": [
    {
      "role": "publication_receipt",
      "reference": {
        "name": "publication_receipt",
        "size": 32,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "device": 1,
        "inode": 10,
        "mtime_ns": 100
      }
    },
    {
      "role": "destination_verification",
      "reference": {
        "name": "destination_verification",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 11,
        "mtime_ns": 100
      }
    },
    {
      "role": "host_cleanup",
      "reference": {
        "name": "host_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 12,
        "mtime_ns": 100
      }
    },
    {
      "role": "guest_cleanup",
      "reference": {
        "name": "guest_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 13,
        "mtime_ns": 100
      }
    }
  ]
}
```

### Rejected before publication

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "rejected",
  "transfer_id": null,
  "request_digest": null,
  "direction": null,
  "channel": null,
  "fallback_reason": null,
  "source_vm_identity": null,
  "destination_identity": null,
  "package_sha256": null,
  "package_size": null,
  "manifest_sha256": null,
  "resumed_bytes": 0,
  "files": [],
  "source_stability": "stable_at_required_check",
  "phase": "FAILED",
  "last_phase": "CREATED",
  "published_ever": false,
  "destination_verified": null,
  "cleanup": {
    "host": true,
    "guest": true
  },
  "publication_receipt_sha256": null,
  "warnings": [],
  "evidence_index": []
}
```

### Incomplete with unknown publication

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "incomplete",
  "transfer_id": null,
  "request_digest": null,
  "direction": "push",
  "channel": null,
  "fallback_reason": null,
  "source_vm_identity": null,
  "destination_identity": null,
  "package_sha256": null,
  "package_size": null,
  "manifest_sha256": null,
  "resumed_bytes": 0,
  "files": [],
  "source_stability": "stable_at_required_check",
  "phase": "VERIFYING",
  "last_phase": "TRANSFERRING",
  "published_ever": null,
  "destination_verified": null,
  "cleanup": {
    "host": true,
    "guest": true
  },
  "publication_receipt_sha256": null,
  "warnings": [],
  "evidence_index": []
}
```

### Conflict after publication

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "conflict",
  "transfer_id": "task-1",
  "request_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "direction": "push",
  "channel": "velo",
  "fallback_reason": null,
  "source_vm_identity": null,
  "destination_identity": {
    "endpoint": "guest",
    "identity": {
      "node": "verified"
    },
    "canonical_path": "E:\\Delivery\\batch"
  },
  "package_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "package_size": 4294967303,
  "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "resumed_bytes": 0,
  "files": [
    {
      "source": "/evidence/资料.bin",
      "relative_path": "资料/零.bin",
      "destination": "E:\\Delivery\\batch\\资料\\零.bin",
      "size": 4294967301,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ],
  "source_stability": "stable_at_required_check",
  "phase": "CONFLICT",
  "last_phase": "CLEANING",
  "published_ever": true,
  "destination_verified": false,
  "cleanup": {
    "host": true,
    "guest": true
  },
  "publication_receipt_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "warnings": [],
  "evidence_index": [
    {
      "role": "publication_receipt",
      "reference": {
        "name": "publication_receipt",
        "size": 32,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "device": 1,
        "inode": 10,
        "mtime_ns": 100
      }
    },
    {
      "role": "destination_verification",
      "reference": {
        "name": "destination_verification",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 11,
        "mtime_ns": 100
      }
    },
    {
      "role": "host_cleanup",
      "reference": {
        "name": "host_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 12,
        "mtime_ns": 100
      }
    },
    {
      "role": "guest_cleanup",
      "reference": {
        "name": "guest_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 13,
        "mtime_ns": 100
      }
    }
  ]
}
```

### Published with cleanup pending

```json
{
  "schema": "velo.transfer.result.v1",
  "outcome": "cleanup_pending",
  "transfer_id": "task-1",
  "request_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "direction": "push",
  "channel": "velo",
  "fallback_reason": null,
  "source_vm_identity": null,
  "destination_identity": {
    "endpoint": "guest",
    "identity": {
      "node": "verified"
    },
    "canonical_path": "E:\\Delivery\\batch"
  },
  "package_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "package_size": 4294967303,
  "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "resumed_bytes": 0,
  "files": [
    {
      "source": "/evidence/资料.bin",
      "relative_path": "资料/零.bin",
      "destination": "E:\\Delivery\\batch\\资料\\零.bin",
      "size": 4294967301,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ],
  "source_stability": "stable_at_required_check",
  "phase": "CLEANING",
  "last_phase": "CLEANING",
  "published_ever": true,
  "destination_verified": null,
  "cleanup": {
    "host": true,
    "guest": null
  },
  "publication_receipt_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "warnings": [],
  "evidence_index": [
    {
      "role": "publication_receipt",
      "reference": {
        "name": "publication_receipt",
        "size": 32,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "device": 1,
        "inode": 10,
        "mtime_ns": 100
      }
    },
    {
      "role": "destination_verification",
      "reference": {
        "name": "destination_verification",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 11,
        "mtime_ns": 100
      }
    },
    {
      "role": "host_cleanup",
      "reference": {
        "name": "host_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 12,
        "mtime_ns": 100
      }
    },
    {
      "role": "guest_cleanup",
      "reference": {
        "name": "guest_cleanup",
        "size": 32,
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "device": 1,
        "inode": 13,
        "mtime_ns": 100
      }
    }
  ]
}
```

## Remaining integration

The future coordinator must bind these declarations to the immutable request and journal facts, verify the destination and guest tombstone, persist evidence and result, then publish the small summary and exit code. The module does not supply the coordinator, CLI, VM checks, or real transfer acceptance.

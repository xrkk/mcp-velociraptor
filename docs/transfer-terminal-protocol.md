# Transfer terminal protocol rules (internal API)

`velo_transfer.protocol` implements the reviewed v3 terminal binding, receipt validation and guest action replay rules. It is a pure local rules module. It does not implement an MCP tool, transport, persistent store, worker, source verification or host coordinator. A successful rule transition is not evidence that a file was actually published or that a transfer is globally complete.

## Binding and receipts

`validate_binding` requires the complete immutable K: `protocol_version=velo.transfer.v1`, `transfer_id`, `request_digest`, `direction`, `vm_uuid`, `boot_identity`, `vm_epoch`, `policy_id`, `package_size`, `package_sha256`, and `manifest_sha256`. A pull source must finish preparing the package before constructing this binding. The caller supplies the full request digest fixed at begin; receipts never change it. The expected destination descriptor contains `endpoint` (`host` for pull, `guest` for push), a nonempty string identity mapping, and `canonical_path`. Local filesystem policy validates local paths before registration; a remote path is compared as an opaque registered descriptor, never opened by the other endpoint.

`prepare_receipt`, `source_validation_receipt` (push only), and `publication_receipt` create strictly bound JSON values; corresponding validators reject missing, extra, incorrectly typed or conflicting fields. `receipt_digest` is SHA-256 over canonical JSON, not authentication. Existing transport authentication remains required. Receipt IDs must be saved and reused, never regenerated after a lost response. Receipt makers must only be called by trusted code after the associated actual verification; they cannot turn an assertion into evidence.

`publish_intent` reserves the stable publication receipt fields, real staging identity and parent identity before rename. Persist the intention first. After real exclusive rename and a full destination tree verification, `recover_publication` accepts only the identical directory identity, parent identity and manifest digest. A same-name or same-content directory with a different identity is a conflict. The returned receipt must be persisted before the release call. The helper receives verification results from the content layer; it does not perform the filesystem work itself.

## Guest action ledger

Create `GuestTerminal(binding, destination)` only at `SOURCE_READY` (pull) or `DEST_RECEIVED` (push). Its serialized `snapshot()` contains at most the three terminal operations. `begin_action` validates all supplied receipts before considering an existing operation, including after release. A new action yields `IN_PROGRESS` with a fixed operation ID and input digest. Repeating the same action returns the same operation; changing inputs is rejected. A repeated prepare or commit never implicitly becomes release.

The integration must hold its policy-root writer lock, persist each new snapshot atomically before returning a response, and dispatch only the fixed owned worker. Worker completion methods are internal and must not be exposed as user-controlled MCP actions:

| Action | Required real checks before completion | Rule method and guest result |
|---|---|---|
| prepare (pull) | Source identity/content, producer and epoch, and fixed package reverified | `complete_prepare` -> `SOURCE_PREPARED`, package retained |
| prepare (push) | Received package, manifest, extracted stage and destination preconditions verified | `complete_prepare` -> `DEST_PREPARED`, no publication |
| commit (push only) | Matching source-validation claim, durable publish intention, atomic rename, destination reverify and receipt persistence | `complete_commit` -> `DEST_PUBLISHED` |
| release (pull) | Matching prepare/publication receipts and fresh source/epoch checks before accepting authorization | `authorize_release` -> `SOURCE_RELEASING` |
| release (push) | Receipt exactly equals the guest's stored publication, final directory identity/content reverified | `authorize_release` -> `DEST_RELEASING` |
| accepted release | Persist authorization BEFORE deleting any temporary file; remove only registered owned temp and stop owned workers | `complete_release` -> `SOURCE_RELEASED` or `DEST_RELEASED` |

`authorize_release` is a pure transition, not a durable operation. Its snapshot must reach protected storage before cleanup starts. On reload, an already accepted release continues the same cleanup without treating subsequent source changes as a new transfer version. Failed cleanup leaves the operation in progress. `fail_action` can record a pre-authorization source conflict, but refuses to retract accepted release authorization. Original sources and published evidence are never cleanup targets. Tombstones, receipts and final manifests must survive ordinary cleanup.

`GuestTerminal.restore(snapshot, expected_binding, expected_destination)` replays the saved action history and compares the entire resulting snapshot. This rejects invented completion phases, inconsistent receipts, changed epochs and corrupt operation input digests. The storage layer must additionally validate its own ownership, bounded JSON input, checksum/atomic-write and concurrency guarantees. Replay does not replace revalidation of retained bytes, VM identity or active worker ownership.

`status()` only returns `state_scope=guest_source|guest_destination` and local phases. Pull publication is explicitly `host_reported_publication`; push publication is `guest_verified_destination`. Neither guest status nor an action's `DONE` means global COMPLETE. The future host coordinator must confirm the matching release tombstone, reverify its destination for pull, close its own resources, persist the global result and only then return success.

## Validation and remaining work

`tests/test_transfer_protocol.py` uses deterministic in-memory histories for lost prepare/commit/release responses, source change before versus after release authorization, invalid bindings at terminal state, publish-intention identity mismatch and snapshot corruption. These tests validate the rules only. Actual disk crash recovery, process ownership, transfer adapters, host finalization, Windows behavior and VM end-to-end acceptance remain separate required work.

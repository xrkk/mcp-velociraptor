# Guest transfer engine (local API, v1)

`velo_transfer.guest_service.GuestTransferService` exposes seven local operations for a future authenticated MCP adapter and the fixed Windows helper. It never declares global `COMPLETE`. The host coordinator must verify its own published directory, retain the matching receipts, clean its own resources, and persist the global result. This module has not been run on a Windows VM.

## Production construction and helper

On the Windows guest, set `VELOCIRAPTOR_TRANSFER_POLICY` to an already protected `velo.transfer.policy.v1` file and construct `GuestTransferService()` without test injections. It calls the real CIM observation and `WindowsAclVerifier()` before loading the policy; every operation rechecks policy identity and actual UUID/boot. The current worker subprocess reconstructs this same factory from the inherited environment. The policy path passed explicitly to an in-process service must match that environment before a Windows worker can start. No request field can change policy or ACL trust. Only the existing default trusted SIDs are supported; the helper cannot extend trust or the fixed request root.

The helper is `python -m velo_transfer.guest_cli --request-file <absolute-file>`. Deployment must create the protected `requests` directory immediately under the policy `work_root`; only a regular private request file inside that fixed directory is accepted. The JSON file has exact top-level keys `operation` and `arguments`. Allowed operations are the seven method names below. Unknown operations, duplicate JSON keys, malformed JSON, a file over 4 MiB, symlinks/reparse points, unprotected paths, and paths outside the fixed directory fail closed. Output is one bounded JSON line with `status=success|error`, and an error code only on failure. Pull chunk bytes appear only in a successful `transfer_chunk`/`transfer_chunks` result for a program adapter; callers must not put that response in AI-visible logs. The helper never executes caller code. The Windows adapter must still enforce its encoded command and response budgets.

## Request and response

`transfer_capabilities()` has no arguments. With no policy it returns `enabled=false`; an invalid nonempty policy raises an error. When enabled it returns protocol/build, actual VM UUID/boot, policy ID, root hashes, chunk default/max and policy limits. Root hashes are identifiers, not disclosure of root paths.

`transfer_begin(request)` requires exact keys:

```json
{
  "protocol_version": "velo.transfer.v1",
  "transfer_id": "batch-1",
  "request_digest": "<sha256>",
  "direction": "pull",
  "sources": [{"absolute_path": "<source-path>", "relative_path": "file.txt"}],
  "expected_destination": {"endpoint": "host", "identity": {"host": "<host-id>"}, "canonical_path": "<host-path>"},
  "expected_vm_identity": {"vm_uuid": "<canonical-uuid>", "boot_identity": "<observed-boot>", "vm_epoch": "<workflow-epoch>"},
  "evidence_context": {"producer_complete": true, "producer_quiescent": true, "references": ["<trusted-evidence-ref>"]},
  "budget": {"max_files": 100, "max_metadata_bytes": 100000, "max_logical_bytes": 1000000, "max_package_bytes": 2000000, "min_free_bytes": 0, "max_chunk_bytes": 1048576, "max_duration_seconds": 60}
}
```

For `push`, `expected_destination.endpoint` is `guest`, `canonical_path` is a new directory under a policy write root, and `package` is additionally required with exact `size`, `sha256`, `manifest_sha256`. For `pull`, each source path is locally checked under an explicit read root; sources under multiple separately authorized roots can share one package. For `push`, the source descriptor is remote provenance and is not opened on the guest. `request_digest(request)` is SHA-256 of canonical JSON of the entire immutable request excluding only `request_digest` itself. It includes direction, all source/destination descriptors, VM identity, evidence context, package identity when present, and budget. A repeated ID with changed intent conflicts. Repeating push begin while receiving or received starts a bounded worker that rechecks all acknowledged partial bytes and ledger records, even when their metadata is unchanged. This is the explicit resume boundary. Wait for that worker to stop and check its error before sending more chunks; the returned offset records the earlier acknowledged prefix, not completion of the current resume check. The evidence booleans and references record an upstream producer claim; the host workflow must establish and vet that claim. Hashing alone does not prove producer quiescence or workflow epoch.

The requested maxima may only tighten policy limits and `min_free_bytes` may only increase. The monotonic deadline is fixed at begin and stored. `max_state_bytes` stays the policy limit. Responses are local guest phases and never global completion. `transfer_status(transfer_id, request_digest)` returns package identity, acknowledged offset, terminal snapshot (operation IDs and receipts), cleanup, error and worker identity. Wrong digest is rejected before revealing another task's state.

`transfer_chunk(transfer_id, request_digest, offset, count, data_base64=None, chunk_sha256=None)` reads a fixed pull package or appends an exact push chunk. Count is positive and bounded by the request maximum. Push data must decode strictly to exactly `count` bytes and match SHA-256. Bytes and a JSONL chunk record are both fsynced before offset acknowledgement; a replay confirms identical already held bytes. The protected task state stores the accepted offset, chunk count, and both files' device/inode/size/mtime/ctime identity. A fresh short helper normally checks those identities without rereading the prefix. A changed identity requires full ledger and actual byte verification before any append or replay. A short chunk call verifies at most 1 MiB and 1024 records; a larger changed prefix returns `partial_verification_required`, requiring repeated begin and status to run the verification in the bounded worker. Unacknowledged trailing bytes/records are truncated only after verification. Every verification loop checks the fixed deadline; explicit resume never relies on metadata alone. A filesystem adversary able to alter content while restoring all observed metadata and bypassing task-state protection is outside this local continuity proof. The complete received package hash is checked in prepare. Large offsets use Python integers without a 32-bit limit. There is no arbitrary file path argument.

`transfer_chunks(transfer_id, request_digest, offset, chunks=None, count_per_chunk=0, chunk_count=0)` batches consecutive `transfer_chunk` work into one call: one identity observation, one writer transaction and one journal save per batch. It is only offered when the policy carries an explicit `max_batch_chunks` limit (1–64); otherwise every call fails closed with `batch_not_allowed`. Push takes an explicit `chunks` list (each entry `count`, `data_base64`, `chunk_sha256`); pull takes `count_per_chunk` plus `chunk_count` for a uniform batch and returns the batch's chunk payloads in order. Every member chunk still runs the full budget, deadline, cancellation and SHA-256 checks of a single chunk; a wrong offset or a hash mismatch rejects the batch without advancing the acknowledged offset. The ledger is appended per chunk and fsynced once with the partial file at batch end, and the durable state records the batch-final offset. An interrupted batch therefore leaves the journal at the pre-batch offset, and recovery re-verifies through the existing partial-identity path. Batched transfer is a throughput batching of the same sequential offsets, not a new ordering or a weaker integrity rule.

`transfer_finish(transfer_id, request_digest, action, ...)` accepts only `prepare`, `commit`, or `release`. Prepare takes no receipt. Push commit takes `prepare_receipt` and `source_validation_receipt`; pull cannot commit. Release takes `prepare_receipt` and `publication_receipt`. The pure `GuestTerminal` validates these even on terminal replay. The service persists the new action snapshot before worker activation. Prepare/commit/release may return `IN_PROGRESS`; poll status for the same fixed operation. Pull prepare rechecks sources and fixed package, retaining both. Push prepare verifies the full received package, registers a private stage before extraction, unpacks and verifies each declared file, then persists the prepare receipt. Push commit persists `publish_intent` before exclusive rename, verifies the final tree, and saves the publication receipt. Release persists authorization before deleting its own package/ledger. Source originals and published final directories are never cleanup targets. The terminal tombstone, manifest sidecar and receipts remain. For push, the release worker now rechecks the already published directory **after** deleting its two registered temporary files. It uses the retained manifest, the fixed publication receipt, the original write-root policy/ACL checks, the actual final directory identity, and the publish intent's parent identity. Only a successful real `verify_tree` creates a durable finalization fact. Pull has no guest-side destination verification because the host owns its final directory.

The top-level `transfer_status` and `transfer_begin` response adds `destination_verification`, either `null` or an independent copy of this exact JSON object:

```json
{
  "schema": "velo.transfer.destination-verification.v1",
  "binding": {"protocol_version": "velo.transfer.v1", "transfer_id": "<id>", "request_digest": "<sha256>", "direction": "push", "vm_uuid": "<uuid>", "boot_identity": "<boot>", "vm_epoch": "<workflow-epoch>", "policy_id": "<policy-id>", "package_size": 1, "package_sha256": "<sha256>", "manifest_sha256": "<sha256>"},
  "release_operation_id": "<operation-id>",
  "publication_receipt_sha256": "<sha256>",
  "directory_identity": {"device": 1, "inode": 2},
  "parent_identity": {"device": 1, "inode": 3},
  "manifest_sha256": "<sha256>",
  "release_worker_nonce": "<nonce>",
  "verification_phase": "post_cleanup"
}
```

The placeholder values above show the shape only. The real values are produced by the same authorized release worker after cleanup and are persisted together with its cleanup observation. The finalizer requires an exact canonical match to the stored K, release operation, publication receipt digest and directory identity, publish-intent parent identity, manifest digest, and the stopped release worker nonce. It also requires that the original worker is absent, the task lease is clear, the root OS lock is acquired, both registered temporary paths are gone, and no unresolved worker error exists. Only then does it persist `DEST_RELEASED`. Status reads the durable snapshot; each status call does **not** rehash the directory. The proof is a historical observation at that post-cleanup point, not a promise that files can never change later. A future host U5 checks the same K/receipt and this fact, then closes host-owned resources; this module never declares global `COMPLETE`.

`transfer_abort(transfer_id, request_digest)` marks cancellation and uses the protected task owner and root lease to stop the exact live process with matching transfer, job, nonce, PID and kernel creation identity. A new service instance can cancel an earlier short helper's worker; no request can supply a PID. Termination is bounded and an unconfirmed stop is an error, never a false stopped status. It retains original sources, partial/package, published output and task metadata. `shutdown()` cancels only this service's registered workers. Status stays readable while a worker hashes or extracts.

## Durable layout and recovery

`work_root/tasks/<transfer_id>/state.json` is the `TaskStore` checksum/atomic-CAS envelope. Large manifest bytes live in private `manifest.json`; pull's package in `bundle.zip`, with `package-identity.json` recorded before READY; push's package in `received.part` with bounded `chunks.jsonl`. A reserved `guest-internal-lease` task records the active worker. The child holds `.guest-worker.lock` during business work. Launch writes PID, real process creation time, nonce and job under the short `TaskStore.writer` transaction before sending its activation token; an unactivated child exits after its bounded handshake, including a partial activation line. A worker has an independent monotonic deadline guard, including while content code is blocked. Status reaps a finished local child promptly and reconciles its protected lease only after its real exit and the root OS lock becoming free. Identity observation failure is an error, not evidence of exit; Windows uses one process handle for creation-time and exit checks. Reading an already stopped older task does not reconcile a newer task's lease. Long content work occurs outside the store writer lock.

An existing pull manifest can be revalidated and packaged after an interrupted begin. A package whose complete identity sidecar was durably recorded is rehashed before READY promotion. A bundle without that sidecar remains `package_reconcile_required`. A registered push stage with its exact identity and parent can be cleared of this task's ordinary extraction files and re-extracted after interrupted prepare. An unregistered same-name stage remains a reconciliation conflict and is never claimed automatically. For commit, a persisted intent can recover an already renamed destination only when its real identity, parent and entire tree match. Release first validates receipts and current source or published tree, then persists authorization and exact temporary file identities. Retry after authorization cleans only these task files; an already missing file counts as cleaned, while a changed or linked same-name file is refused. A later source version does not revoke authorization. The worker records deletion progress but cannot mark itself stopped or write the RELEASED tombstone. A subsequent trusted status/finish path checks real process exit, lease, and root lock before persisting RELEASED. A crash between worker death and tombstone save is recoverable by polling status. For push, release retry after partial cleanup uses the exact previously registered file identities and removes only remaining owned files; retry after both files vanished runs a fresh full destination verification. If the proof was durably saved before the worker stopped or the terminal was finalized, status can complete the same release only after the original worker's death and lease are proven. A new worker attempt clears any old proof before replacing the owner nonce; a failed worker cannot borrow an earlier proof. Verification failures keep the release authorization and publication receipt in `DEST_RELEASING`, retain the manifest and final directory, and expose a stable error. They do not restore deleted package bytes or repair/replace the published directory. The original deadline is never extended; once expired, a new release worker cannot be launched merely to turn missing proof into success. Worker errors before authorization keep package/final evidence; a changed pull source becomes `SOURCE_CHANGED`.

Older push `DEST_RELEASED` tombstones written before this field existed return `destination_verification:null`; status cannot manufacture a retroactive post-cleanup observation. A host coordinator must not use such a legacy tombstone as proof of U5 completion. No existing task is migrated or rewritten by this change.

### Internal lease after a guest reboot

Only the reserved `guest-internal-lease` envelope may move to the freshly
observed boot. Recovery holds both the short store writer lock and the real
exclusive `.guest-worker.lock` continuously through the fresh identity/binding
checks, archival, and atomic replacement. The previous envelope must pass the
ordinary checksum, canonical JSON, permissions/ACL and binding checks, retain
the same VM UUID and policy ID, and have the exact internal digest/epoch and
`state={"active":null}`. A different policy/VM, malformed or incomplete state,
an occupied root lock, or any non-null old active owner is refused. In
particular, a recycled PID never authorizes killing a process or clearing an
occupied old-boot lease; such a lease requires separately authorized operational
reconciliation. No process is terminated by migration.

Before replacement, the exact previous envelope is fsynced to the private
`tasks/guest-internal-lease/previous-<revision>-<envelope-sha256>.json` file and
its directory is synced where supported. The new envelope advances the revision
and changes only the internal binding and empty coordination state. A retry
after archival but before replacement verifies and reuses that exact archive;
corrupt or conflicting archives fail closed. Store durability uncertainty stays
an explicit storage error, never permission to replay business work. Archives
are evidence and are not automatically removed by transfer cleanup.

Business task envelopes, package bytes, receipts and original boot/epoch/request
bindings are not migrated. Calls targeting old-boot tasks still fail identity
checks, including reuse of an old transfer ID with a new request. A new transfer
requires fresh capabilities, a new transfer ID, and the current boot/epoch.
Same-boot restart and dead-worker reconciliation keep their existing semantics.

For subsequent native acceptance, deploy this source without clearing tasks,
complete a benign transfer and retain its state/receipt hashes, confirm the
internal lease is idle, and reboot through the authorized controller. Query
capabilities without logging credentials, then start a new benign transfer with
the observed boot and a new ID. Check the exact archived prior lease, advanced
internal revision, unchanged old business evidence, successful new transfer,
and rejection of old-boot resume/ID takeover. Separately verify root-lock
contention and occupied/corrupt/foreign lease refusal in an isolated protected
work root; never inject malformed state into live evidence. Windows ACLs, native
locking/durability and deployment/reboot qualification remain unverified by the
Linux tests.

## Validation scope and remaining limits

Linux tests inject a Windows-shaped observation strictly in process and use only benign temporary files. They exercise actual Linux filesystem publication and real owned child processes. Native Windows handle tests are written but skipped on Linux. These tests do not establish Windows ACL/worker behavior on a VM, VM epoch provenance, host global completion, actual 4 GiB transfers, or VM end-to-end acceptance. A forced deadline exits the worker process, leaving a recoverable task error and any already published final directory intact. Deployers must confirm Windows behavior in the later deployment stage.

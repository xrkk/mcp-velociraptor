# Host pull publication and fresh destination observation

`HostPublication(journal: HostJournal)` is an internal Linux host module. Its caller must hold that same journal's `writer()` throughout each `publish()` or `verify_published()` call. The journal task must already exist. The module has no CLI or network path and does not fetch guest bytes, unpack a ZIP, request guest release, authorize cleanup, or declare global `COMPLETE`.

## Caller data and physical preparation

The caller first fixes a complete pull binding K after guest `SOURCE_READY`, and persists these facts in `HostJournal.data` before publication:

| Key | Required value |
| --- | --- |
| `binding` | Complete `validate_binding` K for `direction: pull`, including guest request digest, package size/hash, manifest hash, policy and VM identities. |
| `guest_request` | Exact pull request made by `make_guest_request`; destination descriptor must be `endpoint: host`, `identity: journal.binding.host_identity`, `canonical_path: request.document.destination_directory`. Host intent digest is a different value. |
| `prepare_receipt` | Valid guest prepare receipt for that same K. |
| `manifest_ref` | Six-field immutable reference returned by `journal.write_evidence("manifest", manifest)`; the decoded manifest digest must equal K's `manifest_sha256`. |
| `staging` | Exact `prepare_staging` four-key result: `staging_directory`, `staging_identity`, `parent_identity`, `destination_directory`. The callback must persist it before any stage content is written. Stage is a private `.velo-stage-*` sibling of the fixed destination. |

The caller's content layer must separately verify the package bytes and run `unpack_bundle` into the registered stage. A valid benign sequence is `capture_sources` → `create_bundle` → fixed pull K and prepare receipt → `write_evidence` for manifest → `prepare_staging` with a journal-saving registration callback → `unpack_bundle` → `HostPublication(journal).publish()`. The isolated test `test_p1_real_bundle_stage_publish_replay_p5_and_copies` executes this whole local file sequence with a Chinese filename and an empty directory. It simulates already supplied guest facts; it does not contact a guest.

## P3: publish and recover

`publish()` returns an independent copy with exactly `publication_receipt` and `reference`. `reference` is the immutable six-field journal evidence reference `{name,size,sha256,device,inode,mtime_ns}`. The receipt is the exact publication object in a durable `publish_intent`, with fixed `publication_id`, complete K, prepare digest, destination descriptor, manifest digest and the registered directory identity.

The method verifies the private stage against the immutable manifest, persists `publish_intent`, then uses exclusive same-volume rename without replacing an existing target. It observes the real destination inode, original parent identity and entire tree before recording the receipt and evidence. Repeating `publish()` or resuming the same task after a lost response recovers that same intent, receipt and immutable reference; it does not allocate a new publication ID or rename again. A same-content directory with another inode cannot be claimed. Published source files and the manifest evidence are never deleted by this module.

After a rename is observed, `published_ever` is retained even if post-rename fsync, tree verification, evidence or receipt persistence fails. Recovery can finish only when the originally registered inode, parent and whole content still match. It also fsyncs the destination parent again before persisting a receipt, because an earlier rename may have succeeded while that directory sync failed. Continuing sync failure remains a published-but-unconfirmed error. If intent exists but both stage and destination are absent, outcome is **unknown**: `TransferContentError.code == "publication_outcome_unknown"` with `context["published"] is None`. This does not assert that publication failed or authorize republishing. A known published destination that later disappears yields `published_destination_missing` (or a physical path error on fresh verification); it cannot be regenerated from a new stage by this method. Existing foreign destinations fail as `destination_exists`; path, identity, receipt and content conflicts fail closed with stable content-layer codes. The original journal deadline remains fixed.

## P5: fresh local observation

`verify_published()` requires a persisted receipt and freshly checks the fixed destination directory, original stage inode, parent identity and complete manifest tree on every call. It returns:

```json
{
  "schema": "velo.transfer.host-destination-verification.v1",
  "binding": "<complete K object>",
  "publication_receipt_sha256": "<sha256 of persisted receipt>",
  "directory_identity": {"device": 1, "inode": 2},
  "parent_identity": {"device": 1, "inode": 3},
  "manifest_sha256": "<verified manifest digest>"
}
```

The JSON shows the field shape; actual `binding` is an object, not the display string. The observation is a fresh local result, not a stored `COMPLETE` attestation or a promise against later changes. The future coordinator must first establish guest `SOURCE_RELEASED` for the same K and receipt before consuming it for P5. Missing, changed bytes, extra/missing files, or same-content replacement with a different inode fail without removing or republishing anything. Returned objects do not mutate journal state.

This module does not implement host package reception, staging recovery before registration, global phase orchestration, guest release, authorized temporary cleanup, VM snapshot handling or actual deployment. Tests use benign Linux temporary files and injected local failures; they do not establish Windows or real-VM behavior.

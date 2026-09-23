# Velo content layer (internal API, v1)

This package is a local byte and directory layer shared by future host and guest coordinators. It has no MCP, connection, worker, transfer state, credentials, release authorization, or cleanup command. The caller must establish allowed roots, VM identity/epoch, source producer complete/quiescent evidence, and a durable transfer budget. The caller must not interpret a package or a local publication as global COMPLETE.

## Call sequence

1. Create `Budget(max_files, max_metadata_bytes, max_logical_bytes, max_package_bytes, min_free_bytes, deadline_monotonic, max_expansion_ratio=1000000, check_cancel=None)`. The deadline is a `time.monotonic()` value. `check_cancel` should raise a caller-defined cancellation error. Budgets are explicit and contain no fixed single-file limit. Required free space is probed before writes and again before each ZIP or extracted data write; bounded I/O and the deadline are checked during loops. The caller budgets concurrent package, partial, staging and retained evidence separately.
2. `capture_sources(source_root, sources, budget, evidence_refs=[]) -> manifest`: `sources` is a nonempty list of `{absolute_path, relative_path}`. `source_root` is one absolute root or a list of separately authorized absolute roots; each source must lie under at least one supplied root and is checked against its most specific matching root. The caller must first authorize each source with policy; supplying a common ancestor does not authorize it. A listed directory is recursively enumerated; no unrelated root is scanned. Ordinary file logical bytes, empty files, nested names and empty directories are represented. Implicit parent directories of a relative file path have empty source identity. Each actual source file has device/inode, size, nanosecond mtime and SHA-256; an actual source directory has the same identity fields. `evidence_refs` is caller-supplied provenance, not proof of quiescence.
3. `validate_sources(source_root, sources, manifest, budget) -> manifest_sha256` fully rescans and rehashes. Call before and after packaging, and again at the higher-level prepare/commit/release gates required by the approved protocol. It catches same-size rewrites, replacements and directory membership changes. It does not prove the external producer stopped or that VM epoch is current.
4. `create_bundle(source_root, sources, manifest, bundle_path, work_root, budget) -> {path,size,sha256,manifest_sha256}` checks the inventory, streams files into a fresh ZIP64/deflate bundle, hashes the completed package, then checks inventory again. Output is exclusive; existing bundles are not replaced. Only its own unpredictable `.part` is removed after failure.
5. Choose and durably record an exact `.velo-stage-*` sibling name and intended destination. Call `prepare_staging(destination_directory, allowed_root, budget, stage_name=..., register_stage=..., verify_windows_acl=...) -> {staging_directory,staging_identity,parent_identity,destination_directory}`. It creates the private directory exclusively, verifies its identity and emptiness, then calls `register_stage(path, identity, parent_identity)` before content writes. The callback must durably bind that exact identity to the caller transaction and return literal `True`; failure retains the empty stage and reports its path/device/inode with `registered=False`. Existing same-name stages are refused. A crash between creation and callback leaves only the caller-chosen path; do not infer ownership or delete it without comparing the persisted intent and actual identity. On Windows, a real protected-ACL verifier for stage and parent is required.
6. `unpack_bundle(bundle_path, bundle_root, expected_size, expected_sha256, destination_directory, allowed_root, budget, staging=..., verify_windows_acl=...) -> {staging_directory,staging_identity,parent_identity,manifest,manifest_sha256,package_size,package_sha256}` accepts only the registered, still-empty identity-bound stage. It verifies package size/hash and bounded ZIP metadata, then manually extracts exact declared members there. The caller retains the stage on failure; errors after ownership acceptance include its exact path/device/inode and `registered=True`. No final directory is published here. On Windows, verify protected ACL again before extraction.
7. Persist the approved §3.6 `publish_intent` with the complete binding key, prepare receipt digest, destination, staging and parent identities, and manifest digest. Then call `publish_directory(staging_directory, destination_directory, allowed_root, manifest, budget, expected_staging_identity=..., expected_parent_identity=..., verify_windows_acl=...)`. It verifies the tree, performs Linux `renameat2(RENAME_NOREPLACE)` or Windows `MoveFileExW` with flags 0, then verifies the final tree and returns `{destination_directory,identity,manifest_sha256,files}`. On Windows, an actual protected-ACL verifier callback for staging and parent is required; a callback that merely returns true is insufficient in production. The caller persists a publication receipt after this return. A crash between rename and receipt requires the caller to compare the existing final directory's real identity and complete tree with the durable intent before accepting it.
8. `verify_tree(root, manifest, budget, expected_identity=None)` checks the complete tree, refusing extra/missing files or directories and byte/hash/type changes. Same content alone never authorizes reuse of an existing final directory; §3.6 K, intent and staging identity remain caller responsibilities.

## Executable local API example

This uses only a benign temporary source. A production caller must persist the stage intention and registration in its own state before relying on the callback result. The `lambda` callbacks here demonstrate the API shape and do not prove durable registration or Windows ACL protection.

```python
import tempfile
import time
from pathlib import Path
from velo_transfer import (Budget, capture_sources, create_bundle, prepare_staging,
                           unpack_bundle, publish_directory)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source, work, destination_root = (root / name for name in ("source", "work", "dest"))
    for directory in (source, work, destination_root):
        directory.mkdir()
    (source / "example.txt").write_bytes(b"benign")
    budget = Budget(100, 100_000, 1_000_000, 2_000_000, 0, time.monotonic() + 30)
    sources = [{"absolute_path": str(source / "example.txt"), "relative_path": "example.txt"}]
    manifest = capture_sources(source, sources, budget)
    package = create_bundle(source, sources, manifest, work / "bundle.zip", work, budget)
    final = destination_root / "batch-1"
    staging = prepare_staging(final, destination_root, budget,
        stage_name=".velo-stage-batch-1",
        register_stage=lambda path, identity, parent: True)
    extracted = unpack_bundle(package["path"], work, package["size"], package["sha256"],
        final, destination_root, budget, staging=staging)
    published = publish_directory(extracted["staging_directory"], final, destination_root,
        extracted["manifest"], budget,
        expected_staging_identity=extracted["staging_identity"],
        expected_parent_identity=extracted["parent_identity"])
    assert published["manifest_sha256"] == package["manifest_sha256"]
```

The example runs on Linux; Windows callers must provide a real `verify_windows_acl` callback at preparation, extraction and publication.

## Layout and bounds

Canonical manifest JSON uses UTF-8, sorted keys, compact separators and no NaN. `manifest_sha256` hashes these exact bytes. Manifest schema is `velo.transfer.manifest.v1` with `schema`, `evidence_refs`, sorted `entries`. Each entry has `path`, `type`, `identity`, and files additionally have `size` and `sha256`. ZIP members are exactly `manifest.json`, `payload/<relative_path>` for files and `payload/<relative_path>/` for directories. The `payload/` namespace prevents a user file named `manifest.json` from colliding with metadata. All source/target relative paths use `/`; absolute, `..`, backslash, ADS colon, Windows device names, trailing dot/space, non-NFC Unicode, duplicates and case-fold collisions are refused.

Files and package hashes are computed in 1 MiB reads. ZIP64 file entries are explicitly requested. Before `zipfile` parses the central directory, ordinary EOCD and any adjacent ZIP64 locator/record are reconciled for counts, sizes, offsets, record length and single-disk structure. The selected central directory is streamed through fixed headers under the file-count and metadata budgets; contradictory records are rejected. Parsed member names, extras and comments are also accounted. Extraction compares declared uncompressed sizes, a configurable expansion ratio, actual bytes, per-file SHA-256 and the exact final tree. A compressed archive's full bytes are never loaded into memory. Python's ZIP directory list still consumes memory proportional to the bounded metadata budget. No `extractall` is used.

## Errors, ownership, and limits

`TransferContentError.code` is stable enough for the upper state machine (`source_changed`, `path_collision`, `logical_budget_exceeded`, `metadata_budget_exceeded`, `package_budget_exceeded`, `disk_budget_exceeded`, `invalid_package`, `destination_exists`, `cross_volume`, `atomic_primitive_unavailable`, `destination_changed`, etc.). `context` includes only short scalar identifiers; exceptions do not include tokens, file bytes or a full manifest. Source files are never deleted. Existing destination directories are never merged or overwritten. A failed publication keeps staging for caller-owned reconciliation. Caller registration is a prerequisite for extraction; this layer does not itself persist transfer state or decide recovery ownership. Linux fsyncs files/directories and the destination parent; Windows `MoveFileExW` gives exclusive same-volume namespace publication, but this module does not claim a Windows directory durability flush. Administrator or same-account hostile interference is outside this API's guarantee. Linux primitive behavior is tested locally; Windows real primitive and ACL behavior require Windows execution before product acceptance.

# Host transfer journal (internal Linux API)

`velo_transfer.host_journal` persists small coordinator facts and immutable JSON evidence under a parsed `HostRequest`. It does no network, source inventory, package work, publication, cleanup, or global phase decision. A saved `COMPLETE` means that a trusted future coordinator supplied and persisted its three completion attestations; this module does not verify the physical files or the guest.

```python
import time
from velo_transfer.host_journal import HostJournal, observe_host_identity
from velo_transfer.request import load_request

request = load_request("/absolute/request.json")
journal = HostJournal(request, observe_host_identity())
with journal.writer():
    envelope = journal.create(time.monotonic() + 60, {
        "phase": "CREATED", "published_ever": False,
        "begin_attempted": False, "channel": None,
    })
    # Keep this lock across the future foreground coordinator's work.
    envelope = journal.save(envelope["revision"], {**envelope["data"], "phase": "PREPARING"})
```

For a resume, the spec must explicitly set the original `transfer_id` and `resume: true`; construct a fresh `HostJournal` with the current observed host identity and call `load()` inside `writer()`. The same spec path, work root, intent digest, transfer ID, VM UUID/boot/epoch, host machine/boot identity and state limit must match. Moving the spec, changing a budget/source/profile, rebooting the host or changing the host machine is a conflict. An expired deadline can be read for diagnosis but is never replaced or extended. Deadline input and stored deadline use bounded finite-number checks: extreme integers produce stable `invalid_deadline` or `invalid_state`, while ordinary large metadata integers remain valid. A new request with an existing ID receives `resume_required`. The caller cannot select another journal root; it is always `<spec parent>/.velo-transfer/tasks/<transfer_id>`.

`observe_host_identity()` reads only Linux `/etc/machine-id` and `/proc/sys/kernel/random/boot_id`; no shell or user configuration is involved. `HostJournal` accepts an explicit previously observed `{machine_id, boot_id}` for isolated tests and the coordinator. Ordinary request JSON does not set this identity.

## Disk layout and limits

The root and `tasks`, task and `evidence` directories are private mode 0700. `.host-writer.lock` is a persistent mode 0600 file at the root; do not unlink it. Initialization creates and syncs the lock and acquires its nonblocking OS flock before creating `tasks`, so a failed first lock attempt can be retried and two first writers use the same lock. If `tasks` already exists but the lock has disappeared, initialization refuses it. A process crash releases the lock without trusting or killing a recorded PID. The state file is `tasks/<transfer_id>/state.json`, mode 0600, canonical UTF-8 JSON with exact schema `velo.transfer.host-journal.v1`, transfer ID, binding, fixed monotonic deadline, revision, data and SHA-256 of all other fields. The state byte limit is the request's `max_metadata_bytes + 2 * MAX_SPEC_BYTES`. SHA-256 detects accidental corruption, not hostile rewriting by the same privileged filesystem owner.

State and evidence values are checked before encoding for finite JSON, canonical UTF-8, at most 32 levels and 10,000 nodes. Evidence values are each limited to `max_metadata_bytes`; the evidence directory has at most `min(max_files + 32, max_metadata_bytes)` entries. These are metadata limits, not a package or per-file byte ceiling. Writes use private same-directory exclusive temporary files and file fsync. The opened temporary file remains available for identity, size and mtime checks immediately before publication. First state creation and evidence use the existing atomic no-replace rename; later state revisions use atomic replacement after checking the old state. The parent directory is then fsynced. A crash around first publication leaves either an incomplete task or a single-link complete file, never a second hard link. A failed post-publication sync produces `storage_durability_unknown` or `evidence_durability_unknown`; read the actual durable path before retrying. An idempotent evidence retry also syncs and rechecks its existing file before success. `storage_write_failed` means the previous complete revision was observed; `storage_reconcile_required` means no complete state could be established. No path is recursively scanned or deleted on recovery.

`write_evidence(name, value)` accepts a lowercase ASCII name with digits, `_` and `-`, writes `evidence/<name>.json` once and returns a relative reference containing name, size, SHA-256 and file identity. The same name with identical canonical bytes is idempotent; changed bytes conflict. `read_evidence(ref)` accepts only that exact reference shape and checks identity, byte length, hash and canonical JSON. The coordinator must persist important refs in state. An orphan file after an interrupted write is not automatically success or a cleanup target; reconcile the fixed name and hash. Neither state nor evidence is removed during ordinary transfer cleanup.

## Data invariants and security boundary

The journal accepts only the global phase names `CREATED`, `PREPARING`, `READY`, `TRANSFERRING`, `VERIFYING`, `PUBLISHED`, `CLEANING`, `COMPLETE`, `FAILED`, `CONFLICT`, `CANCELLED`. It does not choose transitions. `published_ever` and `begin_attempted` are strict booleans that cannot regress. `channel` is null, `velo`, or `windows`; once begin was attempted, it is fixed. Non-null `guest_request`, `binding`, `prepare_receipt`, `source_validation_receipt`, `publication_receipt` and `publish_intent` cannot be deleted or changed, compared by canonical JSON so boolean and integer values remain distinct. `COMPLETE` additionally requires `published_ever`, a publication receipt and strict true `destination_verified`, `guest_cleanup_complete` and `host_cleanup_complete` in `completion`. The future coordinator must first establish those facts through the existing content/protocol and guest APIs.

Every operation rechecks the root, tasks, task, lock and relevant evidence directory identity. Existing files must be private, single-link regular files; directories must be private and owned by the current user. Ancestors must be trusted root or current-user directories. A root-owned sticky `/tmp` can contain a current-user private child; arbitrary writable ancestors cannot. Symlinks, hard links, replacement, broad permissions, duplicate JSON keys, noncanonical bytes, checksum mismatch and oversized records fail closed without reading a caller-supplied external path. The journal assumes trusted same-user coordinator code and a protected private work tree; it cannot resist an administrator or same-user attacker who can rewrite both state and checksum.

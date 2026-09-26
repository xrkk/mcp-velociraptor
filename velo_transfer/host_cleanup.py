"""Delete only registered host temporaries after matching release proofs.

No source/destination recursion. The durable authorization precedes every delete;
missing objects are accepted only under that original authorization on recovery.
"""
from __future__ import annotations

import copy
import os
import stat
from pathlib import Path

from .errors import TransferContentError as Error
from .host_content import _actual_package
from .host_journal import HostJournal, _private
from .host_partial import HostPartial
from .host_publication import HostPublication
from .manifest import canonical_json, directory_identity, file_identity, safe_chain
from .protocol import GuestTerminal, receipt_digest, validate_binding
from .storage import _sync_directory

SCHEMA = "velo.transfer.host-cleanup.v1"


def _same(a, b):
    return canonical_json(a) == canonical_json(b)


def _file_id(info):
    return {**file_identity(info), "ctime_ns": info.st_ctime_ns}


class HostCleanup:
    def __init__(self, journal: HostJournal):
        if not isinstance(journal, HostJournal):
            raise Error("invalid_journal")
        self.journal = journal

    def _save(self, **updates):
        current = self.journal.load()
        current["data"].update(copy.deepcopy(updates))
        return self.journal.save(current["revision"], current["data"])

    def _gate(self, data):
        binding = validate_binding(data.get("binding"))
        request = data.get("guest_request")
        if (not isinstance(request, dict) or request.get("transfer_id") != self.journal.request.transfer_id or
                request.get("request_digest") != binding["request_digest"] or
                data.get("published_ever") is not True or
                data.get("guest_cleanup_complete") is not True or data.get("destination_verified") is not True):
            raise Error("host_cleanup_not_authorized")
        if data.get("adapter_cleanup_pending"):
            # The adapter did not register host-deletable ownership for these
            # remote control paths. Never guess a deletion or claim completion.
            raise Error("adapter_cleanup_pending")
        expected_vm = self.journal.request.document["expected_vm_identity"]
        if (binding["direction"] != self.journal.request.document["direction"] or
                request.get("direction") != binding["direction"] or
                any(binding[k] != expected_vm[k] for k in ("vm_uuid", "boot_identity", "vm_epoch")) or
                data.get("package") != {"size": binding["package_size"], "sha256": binding["package_sha256"],
                                        "manifest_sha256": binding["manifest_sha256"]}):
            raise Error("host_cleanup_proof_conflict")
        refs = data.get("evidence", {})
        if not all(key in refs for key in ("guest_cleanup", "destination_verification", "publication_receipt")):
            raise Error("host_cleanup_not_authorized")
        status = self.journal.read_evidence(refs["guest_cleanup"])
        proof = self.journal.read_evidence(refs["destination_verification"])
        publication = self.journal.read_evidence(refs["publication_receipt"])
        if not _same(publication, data.get("publication_receipt")) or not _same(status, data.get("guest_status")):
            raise Error("host_cleanup_proof_conflict")
        terminal = GuestTerminal.restore(status.get("terminal"), binding, request["expected_destination"])
        prefix = "DEST" if binding["direction"] == "push" else "SOURCE"
        operation = terminal.operations.get("release")
        worker = status.get("worker")
        cleanup = {"temporary_files_removed": True, "workers_stopped": True}
        if (status.get("transfer_id") != binding["transfer_id"] or
                status.get("request_digest") != binding["request_digest"] or
                status.get("local_phase") != prefix + "_RELEASED" or terminal.local_phase != prefix + "_RELEASED" or
                status.get("error") is not None or not _same(status.get("cleanup"), cleanup) or
                not isinstance(operation, dict) or operation["status"] != "DONE" or
                not _same(operation["result"].get("cleanup"), cleanup) or
                not _same(terminal.publication, publication) or not isinstance(worker, dict) or
                worker.get("stopped") is not True or worker.get("job") != "release" or
                not isinstance(worker.get("nonce"), str) or not worker["nonce"]):
            raise Error("host_cleanup_not_authorized")
        expected = {"binding": binding, "publication_receipt_sha256": receipt_digest(publication),
                    "directory_identity": publication["directory_identity"], "manifest_sha256": binding["manifest_sha256"]}
        if binding["direction"] == "push":
            expected.update(schema="velo.transfer.destination-verification.v1",
                            release_operation_id=operation["operation_id"], release_worker_nonce=worker["nonce"],
                            verification_phase="post_cleanup")
            if not _same(proof, status.get("destination_verification")):
                raise Error("host_cleanup_proof_conflict")
        else:
            expected["schema"] = "velo.transfer.host-destination-verification.v1"
            # Recheck actual published bytes before authorizing local removal.
            if not _same(proof, HostPublication(self.journal).verify_published()):
                raise Error("host_cleanup_proof_conflict")
        if (not isinstance(proof, dict) or set(proof) != set(expected) | {"parent_identity"} or
                not _same({k: proof[k] for k in expected}, expected)):
            raise Error("host_cleanup_proof_conflict")
        parent = proof["parent_identity"]
        if not isinstance(parent, dict) or set(parent) != {"device", "inode"} or any(type(v) is not int or v < 0 for v in parent.values()):
            raise Error("host_cleanup_proof_conflict")
        return binding, publication

    def _targets(self, data, budget, *, verify):
        task = self.journal.task_dir
        if self.journal.request.document["direction"] == "push":
            state = data.get("host_push")
            path = task / "push.zip"
            if (not isinstance(state, dict) or state.get("package_path") != str(path) or
                    not isinstance(state.get("package_identity"), dict)):
                raise Error("host_cleanup_ownership_unknown")
            identity = state["package_identity"]
            if verify:
                size, sha, actual = _actual_package(path, budget, identity)
                if size != data["binding"]["package_size"] or sha != data["binding"]["package_sha256"] or actual != identity:
                    raise Error("host_cleanup_package_changed")
            return [{"path": str(path), "kind": "file", "identity": identity}]
        state = data.get("receive_partial")
        stage = data.get("staging")
        if (not isinstance(state, dict) or not isinstance(stage, dict) or
                stage.get("destination_directory") != self.journal.request.document["destination_directory"]):
            raise Error("host_cleanup_ownership_unknown")
        stage_path = Path(stage["staging_directory"])
        destination = Path(stage["destination_directory"])
        if (stage_path.parent != destination.parent or not stage_path.name.startswith(".velo-stage-") or
                stage_path == destination or data["publication_receipt"]["directory_identity"] != stage["staging_identity"]):
            raise Error("host_cleanup_ownership_unknown")
        safe_chain(stage_path, destination.parent, allow_missing_leaf=True)
        if os.path.lexists(stage_path):
            # The authorized stage was renamed into the final destination.
            # A later same-name stage is never a cleanup target.
            raise Error("host_cleanup_stage_residue")
        if verify:
            HostPartial(self.journal, data["binding"]).verify()
            state = self.journal.load()["data"]["receive_partial"]
        directory = task / "receive"
        directory_record = state.get("directory")
        if not isinstance(directory_record, dict) or directory_record.get("path") != str(directory):
            raise Error("host_cleanup_ownership_unknown")
        targets = []
        for key, name in (("partial", "received.part"), ("ledger", "chunks.jsonl")):
            recorded = state.get(key)
            if not isinstance(recorded, dict) or recorded.get("path") != str(directory / name):
                raise Error("host_cleanup_ownership_unknown")
            targets.append({"path": recorded["path"], "kind": "file",
                            "identity": {k: v for k, v in recorded.items() if k != "path"}})
        targets.append({"path": str(directory), "kind": "directory",
                        "identity": {k: v for k, v in directory_record.items() if k != "path"}})
        return targets

    def _check_target(self, target, *, allow_absent):
        path = Path(target["path"])
        safe_chain(path, self.journal.task_dir, allow_missing_leaf=True)
        if not os.path.lexists(path):
            if allow_absent:
                return False
            raise Error("host_cleanup_ownership_unknown")
        directory = target["kind"] == "directory"
        info = _private(path, "task" if directory else "state")
        actual = {"device": info.st_dev, "inode": info.st_ino} if directory else _file_id(info)
        if not _same(actual, target["identity"]) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
            raise Error("host_cleanup_ownership_conflict")
        return True

    def _preflight(self, targets, *, recovering):
        # Validate the parent before children. Missing receive/ is acceptable only
        # after its exact registered identity was authorized for deletion.
        directories = [t for t in targets if t["kind"] == "directory"]
        absent_directories = set()
        for target in directories:
            path = Path(target["path"])
            if not self._check_target(target, allow_absent=recovering):
                absent_directories.add(path)
                continue
            allowed = {Path(t["path"]).name for t in targets if Path(t["path"]).parent == path}
            with os.scandir(path) as children:
                for child in children:
                    if child.name not in allowed:
                        raise Error("host_cleanup_unknown_residue")
        present = []
        for target in targets:
            if Path(target["path"]).parent in absent_directories:
                continue
            if self._check_target(target, allow_absent=recovering):
                present.append(target)
        return present

    def clean(self):
        self.journal._require_writer(task=True)
        envelope = self.journal.load()
        budget = self.journal.request.content_budget(envelope["deadline_monotonic"])
        data = envelope["data"]
        binding, publication = self._gate(data)
        intent = data.get("host_cleanup_intent")
        targets = self._targets(data, budget, verify=intent is None)
        expected = {"schema": SCHEMA, "binding": binding,
                    "publication_receipt_sha256": receipt_digest(publication),
                    "task_identity": directory_identity(self.journal.task_dir), "targets": targets}
        if intent is not None and not _same(intent, expected):
            raise Error("host_cleanup_intent_conflict")
        present = self._preflight(targets, recovering=intent is not None)
        if intent is None:
            self._save(host_cleanup_intent=expected)
        for target in present:
            budget.check()
            self.journal._require_writer(task=True)
            if directory_identity(self.journal.task_dir) != expected["task_identity"]:
                raise Error("host_cleanup_ownership_conflict")
            # Recheck all remaining registered identities and unknown residues
            # before each small deletion, including recovery after a partial run.
            remaining = self._preflight(targets, recovering=True)
            if target not in remaining:
                continue
            path = Path(target["path"])
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parent = os.fstat(parent_fd)
                if directory_identity(path.parent) != {"device": parent.st_dev, "inode": parent.st_ino}:
                    raise Error("host_cleanup_ownership_conflict")
                self._check_target(target, allow_absent=False)
                if target["kind"] == "directory":
                    os.rmdir(path.name, dir_fd=parent_fd)
                else:
                    os.unlink(path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                raise Error("host_cleanup_io_failed") from None
            finally:
                os.close(parent_fd)
        budget.check()
        if self._preflight(targets, recovering=True):
            raise Error("host_cleanup_incomplete")
        # Sync again even if a prior delete succeeded but its fsync failed.
        _sync_directory(self.journal.task_dir)
        proof = {**expected, "temporary_files_removed": True, "workers_stopped": True}
        reference = self.journal.write_evidence("host-cleanup", proof)
        refs = self.journal.load()["data"].get("evidence", {})
        refs["host_cleanup"] = reference
        self._save(host_cleanup_complete=True, evidence=refs)
        return copy.deepcopy(proof)

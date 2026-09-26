"""Bounded local push preparation and pull extraction under a HostJournal writer."""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from pathlib import Path

from .bundle import (_validated_manifest, create_bundle, prepare_staging,
                     unpack_bundle, verify_tree)
from .errors import TransferContentError as Error
from .host_journal import HostJournal, _check_parent_chain
from .host_partial import HostPartial
from .manifest import (_no_link, canonical_json, capture_sources, digest_json,
                       directory_identity, file_identity, safe_chain, validate_sources)
from .protocol import validate_binding
from .request import make_guest_request
from .storage import _sync_directory

PUSH_SCHEMA = "velo.transfer.host-push.v1"
PULL_SCHEMA = "velo.transfer.host-pull.v1"


def _same(left, right):
    return canonical_json(left) == canonical_json(right)


def _package_identity(path):
    info = _no_link(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise Error("host_package_ownership_conflict")
    return {**file_identity(info), "ctime_ns": info.st_ctime_ns}


def _actual_package(path, budget, identity):
    safe_chain(path, path.parent)
    before = _package_identity(path)
    if identity is not None and before != identity:
        raise Error("host_package_ownership_conflict")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(fd)
        if {**file_identity(opened), "ctime_ns": opened.st_ctime_ns} != before:
            raise Error("host_package_ownership_conflict")
        digest = hashlib.sha256()
        size = 0
        while True:
            budget.check()
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > budget.max_package_bytes:
                raise Error("package_budget_exceeded")
            digest.update(chunk)
        if ({**file_identity(os.fstat(fd)), "ctime_ns": os.fstat(fd).st_ctime_ns} != before or
                _package_identity(path) != before or size != before["size"]):
            raise Error("host_package_ownership_conflict")
        return size, digest.hexdigest(), before
    except OSError:
        raise Error("host_package_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


class HostContent:
    def __init__(self, journal: HostJournal):
        if not isinstance(journal, HostJournal):
            raise Error("invalid_journal")
        self.journal = journal

    def _load(self, direction):
        self.journal._require_writer(task=True)
        envelope = self.journal.load()
        if self.journal.request.document["direction"] != direction:
            raise Error("invalid_direction")
        budget = self.journal.request.content_budget(envelope["deadline_monotonic"])
        budget.check()
        return envelope, budget

    def _save(self, **updates):
        current = self.journal.load()
        data = current["data"]
        for key, value in updates.items():
            if data.get(key) is not None and not _same(data[key], value):
                raise Error("host_content_fact_conflict")
            data[key] = copy.deepcopy(value)
        return self.journal.save(current["revision"], data)

    def _push_inputs(self, data):
        sources = self.journal.request.document["sources"]
        roots = []
        for source in sources:
            path = Path(source["absolute_path"])
            root = path.parent
            _check_parent_chain(root)
            safe_chain(path, root)
            if root not in roots:
                roots.append(root)
        records = [{"path": str(root), **directory_identity(root)} for root in roots]
        state = data.get("host_push")
        if state is not None and (not isinstance(state, dict) or state.get("source_roots") != records):
            raise Error("source_root_changed")
        return sources, roots, records

    def _push_state(self, data, records, ref):
        path = self.journal.task_dir / "push.zip"
        state = data.get("host_push")
        if state is None:
            return {"schema": PUSH_SCHEMA, "source_roots": records, "manifest_ref": ref,
                    "package_path": str(path), "package_identity": None}
        if (not isinstance(state, dict) or set(state) !=
                {"schema", "source_roots", "manifest_ref", "package_path", "package_identity"} or
                state["schema"] != PUSH_SCHEMA or state["source_roots"] != records or
                state["manifest_ref"] != ref or state["package_path"] != str(path)):
            raise Error("host_push_state_conflict")
        return state

    def _push_material(self, envelope, budget, *, allow_capture):
        data = envelope["data"]
        sources, roots, records = self._push_inputs(data)
        state = data.get("host_push")
        if state is None:
            if not allow_capture:
                raise Error("host_package_reconcile_required")
            manifest = capture_sources(roots, sources, budget,
                self.journal.request.document["evidence_context"]["references"])
            ref = self.journal.write_evidence("manifest", manifest)
            state = self._push_state(data, records, ref)
            self._save(host_push=state, manifest_ref=ref)
        else:
            ref = state.get("manifest_ref")
            self._push_state(data, records, ref)
            if data.get("manifest_ref") != ref:
                raise Error("host_content_fact_conflict")
            manifest = self.journal.read_evidence(ref)
            manifest = _validated_manifest(canonical_json(manifest), budget)
        if validate_sources(roots, sources, manifest, budget) != digest_json(manifest):
            raise Error("source_changed")
        if self._push_inputs(self.journal.load()["data"])[2] != records:
            raise Error("source_root_changed")
        return state, manifest, ref, sources, roots

    def _push_package(self, state, manifest, ref, sources, roots, budget, *, create):
        path = self.journal.task_dir / "push.zip"
        identity = state["package_identity"]
        if identity is None:
            if not create or os.path.lexists(path):
                raise Error("host_package_reconcile_required")
            result = create_bundle(roots, sources, manifest, path, self.journal.root, budget)
            if result["manifest_sha256"] != digest_json(manifest):
                raise Error("manifest_hash_mismatch")
            try:
                _sync_directory(path.parent)
            except OSError:
                raise Error("host_package_durability_unknown") from None
            size, digest, identity = _actual_package(path, budget, None)
            self._push_inputs(self.journal.load()["data"])
            package = {"size": size, "sha256": digest,
                       "manifest_sha256": result["manifest_sha256"]}
            if size != result["size"] or digest != result["sha256"]:
                raise Error("host_package_reconcile_required")
            updated = copy.deepcopy(state)
            updated["package_identity"] = identity
            current = self.journal.load()
            if current["data"].get("host_push") != state:
                raise Error("host_content_fact_conflict")
            data = current["data"]
            if data.get("package") is not None and not _same(data["package"], package):
                raise Error("host_content_fact_conflict")
            data["host_push"] = updated
            data["package"] = package
            self.journal.save(current["revision"], data)
        else:
            package = self.journal.load()["data"].get("package")
            if (not isinstance(package, dict) or set(package) !=
                    {"size", "sha256", "manifest_sha256"} or
                    package["manifest_sha256"] != digest_json(manifest)):
                raise Error("host_content_fact_conflict")
            size, digest, actual = _actual_package(path, budget, identity)
            if size != package["size"] or digest != package["sha256"]:
                raise Error("package_hash_mismatch")
            identity = actual
        return copy.deepcopy({"package_path": str(path), "package": package,
                              "manifest_ref": ref,
                              "ownership": {"path": str(path), **identity}})

    def prepare_push(self):
        envelope, budget = self._load("push")
        data = envelope["data"]
        if data.get("published_ever") or data.get("publication_receipt") is not None or data.get("host_cleanup_complete"):
            raise Error("host_package_reconcile_required")
        state, manifest, ref, sources, roots = self._push_material(envelope, budget, allow_capture=True)
        return self._push_package(state, manifest, ref, sources, roots, budget, create=True)

    def verify_push_source(self):
        envelope, budget = self._load("push")
        state, manifest, ref, sources, roots = self._push_material(envelope, budget, allow_capture=False)
        result = self._push_package(state, manifest, ref, sources, roots, budget, create=False)
        return copy.deepcopy({"identity_digest": digest_json(manifest),
                              "package": result["package"], "manifest_ref": ref,
                              "ownership": result["ownership"]})

    def _pull_binding(self, data):
        binding = validate_binding(data.get("binding"))
        request = self.journal.request
        descriptor = {"endpoint": "host", "identity": self.journal.binding["host_identity"],
                      "canonical_path": request.document["destination_directory"]}
        expected = make_guest_request(request, descriptor)
        if (binding["direction"] != "pull" or binding["transfer_id"] != request.transfer_id or
                not _same(data.get("guest_request"), expected) or
                binding["request_digest"] != expected["request_digest"] or
                any(binding[key] != expected["expected_vm_identity"][key]
                    for key in ("vm_uuid", "boot_identity", "vm_epoch"))):
            raise Error("host_pull_binding_conflict")
        return binding, Path(descriptor["canonical_path"])

    def _pull_state(self, data, destination, parent):
        name = ".velo-stage-" + hashlib.sha256(self.journal.request.transfer_id.encode()).hexdigest()[:32]
        state = {"schema": PULL_SCHEMA, "stage_name": name, "parent_identity": parent,
                 "extraction_complete": False}
        current = data.get("host_pull")
        if current is not None:
            if (not isinstance(current, dict) or set(current) != set(state) or
                    any(current[key] != state[key] for key in state if key != "extraction_complete") or
                    type(current["extraction_complete"]) is not bool):
                raise Error("host_pull_state_conflict")
            return current
        return state

    def _stage(self, destination, parent, state, data, budget):
        stage_path = destination.parent / state["stage_name"]
        staging = data.get("staging")
        if staging is None:
            if os.path.lexists(stage_path):
                raise Error("stage_reconcile_required")
            self._save(host_pull=state)
            def register(path, identity, parent_identity):
                record = {"staging_directory": path, "staging_identity": identity,
                          "parent_identity": parent_identity,
                          "destination_directory": str(destination)}
                if parent_identity != parent:
                    return False
                self._save(staging=record)
                return True
            return prepare_staging(destination, destination.parent, budget,
                                   stage_name=state["stage_name"], register_stage=register)
        if (not isinstance(staging, dict) or set(staging) !=
                {"staging_directory", "staging_identity", "parent_identity", "destination_directory"} or
                staging["staging_directory"] != str(stage_path) or
                staging["destination_directory"] != str(destination) or
                staging["parent_identity"] != parent):
            raise Error("stage_reconcile_required")
        safe_chain(stage_path, destination.parent)
        if directory_identity(stage_path) != staging["staging_identity"]:
            raise Error("stage_reconcile_required")
        info = _no_link(stage_path)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Error("staging_not_private")
        return staging

    def _clear_stage(self, staging, budget):
        stage = Path(staging["staging_directory"])
        seen = []
        directories = {}
        pending = [(stage, False)]
        metadata = 0
        count = 0

        def directory_marker(info):
            # Child removal changes directory size/mtime, but not its ownership
            # or inode. Keep those stable fields across the two passes.
            return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)

        while pending:
            path, visited = pending.pop()
            budget.check()
            safe_chain(path, stage)
            info = _no_link(path)
            if visited:
                if not stat.S_ISDIR(info.st_mode) or directory_marker(info) != directories[path]:
                    raise Error("stage_reconcile_required")
                if path != stage:
                    seen.append((path, directories[path], "directory"))
                continue
            if path != stage:
                count += 1
                if count > budget.max_files:
                    raise Error("file_count_exceeded")
                metadata += len(str(path).encode()) + 128
                if metadata > budget.max_metadata_bytes:
                    raise Error("metadata_budget_exceeded")
                if info.st_uid != os.geteuid():
                    raise Error("stage_reconcile_required")
                if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                    raise Error("stage_reconcile_required")
                if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                    raise Error("stage_reconcile_required")
            if stat.S_ISDIR(info.st_mode):
                if path != stage and info.st_mode & 0o077:
                    raise Error("stage_reconcile_required")
                directories[path] = directory_marker(info)
                pending.append((path, True))
                try:
                    with os.scandir(path) as children:
                        for child in children:
                            budget.check()
                            pending.append((Path(child.path), False))
                            if len(pending) + count > budget.max_files * 2 + 2:
                                raise Error("file_count_exceeded")
                except OSError:
                    raise Error("stage_reconcile_required") from None
            elif path == stage:
                raise Error("stage_reconcile_required")
            else:
                seen.append((path, file_identity(info), "file"))
        if directory_identity(stage) != staging["staging_identity"]:
            raise Error("stage_reconcile_required")
        for path, identity, kind in seen:
            budget.check()
            safe_chain(path, stage)
            ancestor = path.parent
            while True:
                if directory_marker(_no_link(ancestor)) != directories[ancestor]:
                    raise Error("stage_reconcile_required")
                if ancestor == stage:
                    break
                ancestor = ancestor.parent
            info = _no_link(path)
            if ((kind == "file" and (not stat.S_ISREG(info.st_mode) or
                    info.st_nlink != 1 or file_identity(info) != identity)) or
                    (kind == "directory" and (not stat.S_ISDIR(info.st_mode) or
                    directory_marker(info) != identity))):
                raise Error("stage_reconcile_required")
            try:
                path.rmdir() if kind == "directory" else path.unlink()
            except OSError:
                raise Error("stage_reconcile_required") from None
        _sync_directory(stage)
        if directory_identity(stage) != staging["staging_identity"]:
            raise Error("stage_reconcile_required")

    def prepare_pull(self):
        envelope, budget = self._load("pull")
        data = envelope["data"]
        if (data.get("publish_intent") is not None or data.get("publication_receipt") is not None or
                data["published_ever"]):
            raise Error("publication_already_started")
        binding, destination = self._pull_binding(data)
        package_observed = HostPartial(self.journal, binding).verify()
        package = {"size": package_observed["size"], "sha256": package_observed["sha256"],
                   "manifest_sha256": package_observed["expected_manifest_sha256"]}
        if package != {"size": binding["package_size"], "sha256": binding["package_sha256"],
                        "manifest_sha256": binding["manifest_sha256"]}:
            raise Error("host_pull_binding_conflict")
        if data.get("package") is not None and not _same(data["package"], package):
            raise Error("host_content_fact_conflict")
        _check_parent_chain(destination.parent)
        safe_chain(destination, destination.parent, allow_missing_leaf=True)
        if os.path.lexists(destination):
            raise Error("destination_exists")
        parent = directory_identity(destination.parent)
        state = self._pull_state(data, destination, parent)
        staging = self._stage(destination, parent, state, data, budget)
        if state["extraction_complete"]:
            ref = self.journal.load()["data"].get("manifest_ref")
            manifest = self.journal.read_evidence(ref)
            manifest = _validated_manifest(canonical_json(manifest), budget)
            if digest_json(manifest) != binding["manifest_sha256"]:
                raise Error("manifest_hash_mismatch")
            verify_tree(staging["staging_directory"], manifest, budget,
                        staging["staging_identity"])
            if directory_identity(destination.parent) != parent:
                raise Error("destination_parent_changed")
            if self.journal.load()["data"].get("package") != package:
                raise Error("host_content_fact_conflict")
            return copy.deepcopy({"staging": staging, "package": package, "manifest_ref": ref})
        if self.journal.load()["data"].get("staging") is not None:
            self._clear_stage(staging, budget)
        extracted = unpack_bundle(package_observed["path"], self.journal.root,
            package["size"], package["sha256"], destination, destination.parent,
            budget, staging=staging)
        if extracted["manifest_sha256"] != binding["manifest_sha256"]:
            raise Error("manifest_hash_mismatch")
        ref = self.journal.write_evidence("manifest", extracted["manifest"])
        current = self.journal.load()
        latest = current["data"]
        if (latest.get("host_pull") != state or latest.get("staging") != staging or
                (latest.get("manifest_ref") is not None and latest["manifest_ref"] != ref) or
                (latest.get("package") is not None and latest["package"] != package)):
            raise Error("host_content_fact_conflict")
        latest["manifest_ref"] = ref
        latest["package"] = package
        completed = copy.deepcopy(state)
        completed["extraction_complete"] = True
        latest["host_pull"] = completed
        self.journal.save(current["revision"], latest)
        return copy.deepcopy({"staging": staging, "package": package, "manifest_ref": ref})

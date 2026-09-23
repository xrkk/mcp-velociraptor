"""Local guest transfer engine. Transport authentication belongs to its caller."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from .bundle import _hash_path, create_bundle, prepare_staging, unpack_bundle, verify_tree
from .errors import TransferContentError as Error
from .filesystem import publish_directory
from .guest_worker import (RootLease, process_birth, read_activation, same_process,
                           terminate_verified)
from .manifest import (Budget, _no_link, canonical_json, capture_sources, check_relative,
                       digest_json, directory_identity, file_identity, safe_chain, validate_sources)
from .policy import load_policy
from .protocol import (PROTOCOL_VERSION, GuestTerminal, prepare_receipt, publish_intent,
                       recover_publication, validate_destination)
from .storage import TaskStore, _validate_json
from .windows_platform import WindowsAclVerifier, observe_windows

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_BUDGET_KEYS = frozenset(("max_files", "max_metadata_bytes", "max_logical_bytes",
                          "max_package_bytes", "min_free_bytes", "max_chunk_bytes",
                          "max_duration_seconds"))
_REQUEST_KEYS = frozenset(("protocol_version", "transfer_id", "request_digest", "direction",
                           "sources", "expected_destination", "expected_vm_identity",
                           "evidence_context", "budget"))
_LEASE_ID = "guest-internal-lease"


def request_digest(request: dict) -> str:
    """Canonical digest of immutable intent, excluding only the digest field."""
    if not isinstance(request, dict):
        raise Error("invalid_request")
    return digest_json({key: value for key, value in request.items() if key != "request_digest"})


def _hex(value) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _dict(value, keys, code="invalid_request"):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Error(code)


def _positive(value, *, allow_zero=False):
    return type(value) is int and (value >= 0 if allow_zero else value > 0)


def _strict_json(raw: bytes, maximum: int):
    if len(raw) > maximum:
        raise Error("metadata_budget_exceeded")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Error("duplicate_json_key")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Error("invalid_json")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Error("invalid_json") from exc


class GuestTransferService:
    """Six bounded guest operations. `_observation` is only for isolated in-process tests."""

    def __init__(self, policy_path=None, *, _observation=None, _acl_verifier=None,
                 _guest=True, _worker_delay=0.0):
        self.policy_path = policy_path
        self._test_observation = _observation
        self._test_acl = _acl_verifier
        self._guest = _guest
        self._worker_delay = _worker_delay
        self._owned = {}
        self._chunk_cache = {}
        self.observation = _observation if _observation is not None else observe_windows()
        self.acl = _acl_verifier if _acl_verifier is not None else WindowsAclVerifier()
        status = load_policy(policy_path, observation=self.observation.for_policy(),
                             guest=_guest, verify_windows_acl=self.acl)
        self.enabled = status.enabled
        self.reason = status.reason
        self.policy = status.policy

    def _identity(self):
        current = self._test_observation if self._test_observation is not None else observe_windows()
        if (current.vm_uuid != self.observation.vm_uuid or
                current.boot_identity != self.observation.boot_identity or
                current.os_name != self.observation.os_name):
            raise Error("vm_identity_mismatch")
        if self.policy is None:
            raise Error("transfer_disabled")
        self.policy.revalidate()
        return current

    def _store(self):
        self._identity()
        return TaskStore(self.policy)

    def transfer_capabilities(self):
        if not self.enabled:
            return {"schema": "velo.transfer.guest.response.v1", "enabled": False,
                    "reason": self.reason}
        observed = self._identity()
        limits = dict(self.policy.limits)
        return {"schema": "velo.transfer.guest.response.v1", "enabled": True,
                "protocol_version": PROTOCOL_VERSION, "build": "guest-engine-v1",
                "vm_uuid": observed.vm_uuid, "boot_identity": observed.boot_identity,
                "policy_id": self.policy.policy_id, "can_read": bool(self.policy.read_roots),
                "can_write": bool(self.policy.write_roots),
                "read_root_ids": [digest_json(str(p)) for p in self.policy.read_roots],
                "write_root_ids": [digest_json(str(p)) for p in self.policy.write_roots],
                "default_chunk_bytes": min(1 << 20, limits["max_chunk_bytes"]),
                "limits": limits}

    def _validate_request(self, request):
        self._identity()
        if not isinstance(request, dict) or set(request) not in (_REQUEST_KEYS, _REQUEST_KEYS | {"package"}):
            raise Error("invalid_request")
        _validate_json(request, max_bytes=self.policy.limits["max_state_bytes"] // 2)
        if request["protocol_version"] != PROTOCOL_VERSION or request["direction"] not in ("pull", "push"):
            raise Error("invalid_request")
        transfer_id = request["transfer_id"]
        if (not isinstance(transfer_id, str) or not _ID.fullmatch(transfer_id) or
                transfer_id.startswith("guest-internal-")):
            raise Error("invalid_transfer_id")
        check_relative(transfer_id)
        if not _hex(request["request_digest"]) or request["request_digest"] != request_digest(request):
            raise Error("request_digest_mismatch")
        if (request["direction"] == "push") != ("package" in request):
            raise Error("invalid_request")
        _dict(request["expected_vm_identity"], ("vm_uuid", "boot_identity", "vm_epoch"))
        observed = self._identity()
        expected = request["expected_vm_identity"]
        if expected["vm_uuid"] != observed.vm_uuid or expected["boot_identity"] != observed.boot_identity:
            raise Error("vm_identity_mismatch")
        if not isinstance(expected["vm_epoch"], str) or not 1 <= len(expected["vm_epoch"]) <= 256:
            raise Error("invalid_vm_epoch")
        validate_destination(request["expected_destination"], request["direction"])
        _dict(request["evidence_context"], ("producer_complete", "producer_quiescent", "references"))
        evidence = request["evidence_context"]
        if (evidence["producer_complete"] is not True or evidence["producer_quiescent"] is not True or
                not isinstance(evidence["references"], list) or not evidence["references"] or
                any(not isinstance(x, str) or not 1 <= len(x) <= 512 for x in evidence["references"])):
            raise Error("producer_evidence_missing")
        sources = request["sources"]
        if not isinstance(sources, list) or not sources:
            raise Error("sources_required")
        roots = []
        for source in sources:
            _dict(source, ("absolute_path", "relative_path"))
            if not isinstance(source["absolute_path"], str):
                raise Error("invalid_source_path")
            check_relative(source["relative_path"])
            if request["direction"] == "pull":
                path = self.policy.resolve_local(source["absolute_path"], "read")
                roots.append(max((root for root in self.policy.read_roots if path.is_relative_to(root)),
                                 key=lambda root: len(root.parts)))
        if request["direction"] == "push":
            dest = request["expected_destination"]["canonical_path"]
            path = self.policy.resolve_local(dest, "write", allow_missing_leaf=True)
            self.policy.resolve_local(str(path.parent), "write")
            package = request["package"]
            _dict(package, ("size", "sha256", "manifest_sha256"))
            if not _positive(package["size"], allow_zero=True) or not _hex(package["sha256"]) or not _hex(package["manifest_sha256"]):
                raise Error("invalid_package_identity")
        _dict(request["budget"], _BUDGET_KEYS)
        limits = self.policy.limits
        for key, value in request["budget"].items():
            if not _positive(value, allow_zero=key in ("max_logical_bytes", "min_free_bytes")):
                raise Error("invalid_budget")
            if key == "min_free_bytes":
                if value < limits[key]:
                    raise Error("budget_outside_policy")
            elif value > limits[key]:
                raise Error("budget_outside_policy")
        if request["direction"] == "push" and package["size"] > request["budget"]["max_package_bytes"]:
            raise Error("package_budget_exceeded")
        if len(sources) > request["budget"]["max_files"] or len(canonical_json(request)) > limits["max_state_bytes"] // 2:
            raise Error("state_budget_exceeded")
        return sorted(set(roots), key=str)

    def _binding(self, request):
        identity = request["expected_vm_identity"]
        return {"request_digest": request["request_digest"], "policy_id": self.policy.policy_id,
                "vm_uuid": identity["vm_uuid"], "boot_identity": identity["boot_identity"],
                "vm_epoch": identity["vm_epoch"]}

    def _protocol_binding(self, request, package):
        return {"protocol_version": PROTOCOL_VERSION, "transfer_id": request["transfer_id"],
                "request_digest": request["request_digest"], "direction": request["direction"],
                "vm_uuid": request["expected_vm_identity"]["vm_uuid"],
                "boot_identity": request["expected_vm_identity"]["boot_identity"],
                "vm_epoch": request["expected_vm_identity"]["vm_epoch"],
                "policy_id": self.policy.policy_id, "package_size": package["size"],
                "package_sha256": package["sha256"],
                "manifest_sha256": package["manifest_sha256"]}

    def _budget(self, state, *, cancel=False):
        values = state["request"]["budget"]
        def check_cancel():
            if cancel and self._load(state["request"]["transfer_id"], state["request"]["request_digest"])["state"]["cancelled"]:
                raise Error("transfer_cancelled")
        return Budget(values["max_files"], values["max_metadata_bytes"],
                      values["max_logical_bytes"], values["max_package_bytes"],
                      values["min_free_bytes"], state["deadline_monotonic"],
                      check_cancel=check_cancel if cancel else None)

    def _load(self, transfer_id, digest, store=None):
        if not isinstance(transfer_id, str) or not _ID.fullmatch(transfer_id) or transfer_id.startswith("guest-internal-") or not _hex(digest):
            raise Error("invalid_transfer_id")
        store = store or self._store()
        for attempt in range(3):
            try:
                raw = store._read(store._state_path(transfer_id))
                if raw["binding"]["request_digest"] != digest:
                    raise Error("task_binding_conflict")
                envelope = store.load(transfer_id, raw["binding"])
                break
            except Error as exc:
                if exc.code != "state_changed" or attempt == 2:
                    raise
                time.sleep(0.001)
        state = envelope["state"]
        if state["request"]["request_digest"] != digest or state["request"]["transfer_id"] != transfer_id:
            raise Error("invalid_state")
        expected = state["request"]["expected_vm_identity"]
        if expected["vm_uuid"] != self.observation.vm_uuid or expected["boot_identity"] != self.observation.boot_identity:
            raise Error("vm_identity_mismatch")
        return envelope

    def _save(self, store, envelope, state):
        return store.save(envelope["transfer_id"], envelope["binding"], envelope["revision"], state)

    def _task_path(self, transfer_id):
        store = self._store()
        return store._task_dir(transfer_id)

    def _lease_binding(self):
        return {"request_digest": "0" * 64, "policy_id": self.policy.policy_id,
                "vm_uuid": self.observation.vm_uuid,
                "boot_identity": self.observation.boot_identity, "vm_epoch": "internal"}

    def _lease(self, store):
        return store.create(_LEASE_ID, self._lease_binding(), {"active": None})

    def _check_idle(self, store, *, recovering=None):
        lease = self._lease(store)
        active = lease["state"]["active"]
        if active is not None:
            if same_process(active["pid"], active["birth"]):
                raise Error("worker_busy")
            if recovering != (active["transfer_id"], active["job"]):
                raise Error("worker_result_unknown")
            probe = RootLease(self.policy.work_root)
            probe.acquire()
            probe.release()
            return store.save(_LEASE_ID, lease["binding"], lease["revision"], {"active": None})
        return lease

    def transfer_begin(self, request: dict):
        roots = self._validate_request(request)
        store = self._store()
        transfer_id = request["transfer_id"]
        launch = False
        launch_job = "package"
        with store.writer():
            existing = None
            try:
                existing = self._load(transfer_id, request["request_digest"], store)
            except Error as exc:
                if exc.code not in ("task_not_found", "task_incomplete"):
                    raise
            else:
                if existing["state"]["request"] != request:
                    raise Error("task_binding_conflict")
                state = existing["state"]
                if (request["direction"] == "pull" and state["phase"] == "SOURCE_PREPARING" and
                        state["error"] in (None, "worker_failed", "worker_activation_unknown",
                                           "worker_activation_failed", "worker_activation_timeout") and
                        (state["owner"] is None or state["owner"]["stopped"] or
                         not same_process(state["owner"]["pid"], state["owner"]["birth"]))):
                    launch = True
                elif (request["direction"] == "push" and
                      state["phase"] in ("DEST_RECEIVING", "DEST_RECEIVED") and
                      (state["owner"] is None or state["owner"]["stopped"] or
                       not same_process(state["owner"]["pid"], state["owner"]["birth"]))):
                    # An explicit repeated begin is a resume, unlike ordinary fresh
                    # per-chunk helper instances. Verify the entire acknowledged prefix
                    # once in a bounded worker before accepting further chunks.
                    launch = True
                    launch_job = "verify_partial"
            if existing is None:
                self._check_idle(store)
                deadline = time.monotonic() + request["budget"]["max_duration_seconds"]
                state = {"request": copy.deepcopy(request), "source_roots": [str(x) for x in roots],
                         "deadline_monotonic": deadline, "phase": "SOURCE_PREPARING" if request["direction"] == "pull" else "DEST_RECEIVING",
                         "package": copy.deepcopy(request.get("package")), "offset": 0, "chunk_count": 0,
                         "partial_identity": None, "cleanup_targets": None,
                         "terminal": None, "stage_intent": None, "staging": None,
                         "publish_intent": None, "owner": None, "cancelled": False,
                         "error": None, "cleanup": None}
                envelope = store.create(transfer_id, self._binding(request), state)
                if envelope["state"] != state:
                    raise Error("task_binding_conflict")
                launch = request["direction"] == "pull"
        if launch:
            self._launch(transfer_id, request["request_digest"], launch_job)
        return self.transfer_status(transfer_id, request["request_digest"])

    def _public(self, state):
        terminal = state["terminal"]
        return {"schema": "velo.transfer.guest.response.v1",
                "state_scope": "guest_source" if state["request"]["direction"] == "pull" else "guest_destination",
                "local_phase": state["phase"], "transfer_id": state["request"]["transfer_id"],
                "request_digest": state["request"]["request_digest"],
                "package": state["package"], "verified_offset": state["offset"],
                "terminal": copy.deepcopy(terminal), "cleanup": state["cleanup"],
                "error": state["error"], "worker": copy.deepcopy(state["owner"])}

    def transfer_status(self, transfer_id: str, request_digest: str):
        store = self._store()
        envelope = self._load(transfer_id, request_digest, store)
        state = envelope["state"]
        if state["owner"] is not None and not same_process(state["owner"]["pid"], state["owner"]["birth"]):
            try:
                self._reconcile_exit(transfer_id, request_digest)
            except Error as exc:
                if exc.code != "writer_busy":
                    raise
            envelope = self._load(transfer_id, request_digest, store)
            state = envelope["state"]
        if state["phase"] in ("SOURCE_RELEASING", "DEST_RELEASING"):
            try:
                self._finalize_release(transfer_id, request_digest)
            except Error as exc:
                if exc.code != "writer_busy":
                    raise
            envelope = self._load(transfer_id, request_digest, store)
            state = envelope["state"]
        if state["terminal"] is not None:
            GuestTerminal.restore(state["terminal"], self._protocol_binding(state["request"], state["package"]),
                                  state["request"]["expected_destination"])
        result = self._public(state)
        if result["worker"] is not None and result["worker"]["stopped"]:
            for attempt in range(3):
                try:
                    lease = store._read(store._state_path(_LEASE_ID))
                    break
                except Error as exc:
                    if exc.code != "state_changed" or attempt == 2:
                        raise
                    time.sleep(0.001)
            active = lease["state"]["active"]
            if active is not None and active["nonce"] == result["worker"]["nonce"]:
                result["worker"]["stopped"] = False
        return result

    def _reap_local(self, owner):
        pid = owner["pid"]
        record = self._owned.get(pid)
        if record is None or record[:2] != (owner["transfer_id"], owner["nonce"]):
            return
        if os.name == "posix":
            try:
                finished, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                finished = pid
            if finished == pid:
                self._owned.pop(pid, None)
        elif os.name == "nt" and record[2].poll() is not None:
            record[2].wait(timeout=0)
            self._owned.pop(pid, None)

    def _reconcile_exit(self, transfer_id, digest):
        store = self._store()
        envelope = self._load(transfer_id, digest, store)
        owner = envelope["state"]["owner"]
        if owner is None:
            return
        self._reap_local(owner)
        if owner["stopped"]:
            return
        if same_process(owner["pid"], owner["birth"]):
            return
        probe = RootLease(self.policy.work_root)
        try:
            probe.acquire()
        except Error as exc:
            if exc.code == "worker_busy":
                return
            raise
        try:
            with store.writer():
                fresh = self._load(transfer_id, digest, store)
                current = fresh["state"]
                saved = current["owner"]
                if saved is None or saved["nonce"] != owner["nonce"] or same_process(saved["pid"], saved["birth"]):
                    return
                lease = self._lease(store)
                active = lease["state"]["active"]
                if active is not None:
                    if active["nonce"] != saved["nonce"] or active["transfer_id"] != transfer_id:
                        raise Error("worker_ownership_mismatch")
                    store.save(_LEASE_ID, lease["binding"], lease["revision"], {"active": None})
                if not saved["stopped"]:
                    saved["stopped"] = True
                    if time.monotonic() >= current["deadline_monotonic"] and current["error"] is None:
                        current["error"] = "deadline_exceeded"
                    self._save(store, fresh, current)
        finally:
            probe.release()

    def _launch(self, transfer_id, digest, job):
        """Register child identity under the short writer transaction, then activate."""
        store = self._store()
        nonce = secrets.token_hex(16)
        child = None
        write_fd = None
        birth = None
        with store.writer():
            envelope = self._load(transfer_id, digest, store)
            state = envelope["state"]
            if state["cancelled"] or time.monotonic() >= state["deadline_monotonic"]:
                raise Error("deadline_or_cancelled")
            lease = self._check_idle(store, recovering=(transfer_id, job))
            if os.name == "posix":
                read_fd, write_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(write_fd)
                    if store._lock_fd is not None:
                        os.close(store._lock_fd)
                        store._lock_fd = None
                    try:
                        with os.fdopen(read_fd, "rb", buffering=0) as incoming:
                            self._child(transfer_id, digest, job, nonce, incoming)
                    finally:
                        os._exit(0)
                os.close(read_fd)
                child = pid
                self._owned[pid] = (transfer_id, nonce)
            elif os.name == "nt":
                configured = os.environ.get("VELOCIRAPTOR_TRANSFER_POLICY")
                if not configured or (self.policy_path is not None and str(self.policy_path) != configured):
                    raise Error("worker_policy_configuration_mismatch")
                args = [sys.executable, "-m", "velo_transfer.guest_cli", "--internal-worker",
                        transfer_id, digest, job, nonce]
                child = subprocess.Popen(args, stdin=subprocess.PIPE,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         close_fds=True)
                pid = child.pid
                self._owned[pid] = (transfer_id, nonce, child)
            else:
                raise Error("worker_platform_unsupported")
            try:
                birth = process_birth(pid)
                owner = {"transfer_id": transfer_id, "job": job, "nonce": nonce,
                         "pid": pid, "birth": birth, "deadline_monotonic": state["deadline_monotonic"],
                         "stopped": False}
                state["owner"] = owner
                state["error"] = None
                self._save(store, envelope, state)
                lease_state = {"active": owner}
                store.save(_LEASE_ID, lease["binding"], lease["revision"], lease_state)
            except Exception:
                if write_fd is not None:
                    os.close(write_fd)
                reaped = False
                if isinstance(child, subprocess.Popen):
                    child.stdin.close()
                    try:
                        child.wait(timeout=16)
                        reaped = True
                    except subprocess.TimeoutExpired:
                        if birth is not None:
                            terminate_verified(pid, birth, timeout=3)
                        try:
                            child.wait(timeout=1)
                            reaped = True
                        except subprocess.TimeoutExpired:
                            pass
                elif type(child) is int:
                    until = time.monotonic() + 16
                    while time.monotonic() < until:
                        if os.waitpid(child, os.WNOHANG)[0] == child:
                            reaped = True
                            break
                        time.sleep(0.02)
                    else:
                        if birth is not None:
                            terminate_verified(child, birth, timeout=3)
                        reaped = os.waitpid(child, os.WNOHANG)[0] == child
                if reaped:
                    self._owned.pop(pid, None)
                raise
        try:
            if write_fd is not None:
                os.write(write_fd, (nonce + "\n").encode("ascii"))
                os.close(write_fd)
            else:
                child.stdin.write((nonce + "\n").encode("ascii"))
                child.stdin.flush()
                child.stdin.close()
        except OSError:
            # The durable owner remains for explicit reconciliation.
            raise Error("worker_activation_unknown")

    def _child(self, transfer_id, digest, job, nonce, incoming):
        try:
            read_activation(incoming, nonce)
            lease = RootLease(self.policy.work_root)
            lease.acquire()
            try:
                lock_info = _no_link(lease.path)
                if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                    raise Error("worker_lock_unavailable")
                if os.name == "nt":
                    if self.acl(lease.path, "lock") is not True:
                        raise Error("windows_acl_not_verified")
                elif lock_info.st_mode & 0o077:
                    raise Error("insecure_permissions")
                envelope = self._load(transfer_id, digest)
                owner = envelope["state"]["owner"]
                if (owner is None or owner["nonce"] != nonce or owner["job"] != job or
                        owner["pid"] != os.getpid() or owner["birth"] != process_birth(os.getpid())):
                    raise Error("worker_ownership_mismatch")
                finished = threading.Event()
                def deadline_guard():
                    remaining = max(0, owner["deadline_monotonic"] - time.monotonic())
                    if not finished.wait(remaining):
                        os._exit(124)
                guard = threading.Thread(target=deadline_guard, daemon=False)
                guard.start()
                try:
                    if self._worker_delay:
                        time.sleep(self._worker_delay)
                    self._execute(transfer_id, digest, job)
                finally:
                    finished.set()
                    guard.join(timeout=1)
            finally:
                lease.release()
        except Exception as exc:
            code = exc.code if isinstance(exc, Error) else "worker_failed"
            try:
                store = self._store()
                with store.writer():
                    envelope = self._load(transfer_id, digest, store)
                    state = envelope["state"]
                    if state["owner"] and state["owner"]["nonce"] == nonce:
                        state["error"] = code
                        if state["terminal"] is not None and job in ("prepare", "commit", "release"):
                            terminal = GuestTerminal.restore(state["terminal"],
                                self._protocol_binding(state["request"], state["package"]),
                                state["request"]["expected_destination"])
                            operation = terminal.operations.get(job)
                            recoverable = ((job == "commit" and state["publish_intent"] is not None) or
                                           (job == "prepare" and state["staging"] is not None))
                            if operation and operation["status"] == "IN_PROGRESS" and terminal.release_authorization is None and not recoverable:
                                terminal.fail_action(job, operation["operation_id"], code)
                                state["terminal"] = terminal.snapshot()
                                state["phase"] = terminal.local_phase
                        self._save(store, envelope, state)
            except Exception:
                pass

    def _execute(self, transfer_id, digest, job):
        envelope = self._load(transfer_id, digest)
        state = envelope["state"]
        budget = self._budget(state, cancel=True)
        budget.check()
        if state["cancelled"]:
            raise Error("transfer_cancelled")
        if job == "package":
            self._package(envelope, budget)
        elif job == "verify_partial":
            self._verified_partial(state, force=True, budget=budget)
            store = self._store()
            with store.writer():
                fresh = self._load(transfer_id, digest, store)
                current = fresh["state"]
                if (current["cancelled"] or current["offset"] != state["offset"] or
                        current["chunk_count"] != state["chunk_count"]):
                    raise Error("worker_state_changed")
                current["partial_identity"] = state["partial_identity"]
                self._save(store, fresh, current)
        elif job == "prepare":
            self._prepare(envelope, budget)
        elif job == "commit":
            self._commit(envelope, budget)
        elif job == "release":
            self._release(envelope, budget)
        else:
            raise Error("invalid_worker_job")

    def _atomic_sidecar(self, path: Path, raw: bytes, maximum: int):
        if len(raw) > maximum:
            raise Error("metadata_budget_exceeded")
        safe_chain(path, self.policy.work_root, allow_missing_leaf=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if os.name == "nt" and self.acl(path, "state") is not True:
            raise Error("windows_acl_not_verified")

    def _read_sidecar(self, path: Path, maximum: int):
        safe_chain(path, self.policy.work_root)
        if _no_link(path).st_size > maximum:
            raise Error("metadata_budget_exceeded")
        with path.open("rb") as source:
            return _strict_json(source.read(maximum + 1), maximum)

    def _manifest(self, state):
        path = self._task_path(state["request"]["transfer_id"]) / "manifest.json"
        safe_chain(path, self.policy.work_root)
        maximum = state["request"]["budget"]["max_metadata_bytes"]
        manifest = self._read_sidecar(path, maximum)
        if digest_json(manifest) != state["package"]["manifest_sha256"]:
            raise Error("manifest_hash_mismatch")
        return manifest

    def _package_file(self, state):
        path = self._task_path(state["request"]["transfer_id"]) / ("bundle.zip" if state["request"]["direction"] == "pull" else "received.part")
        safe_chain(path, self.policy.work_root)
        return path

    def _hash_package(self, state, budget):
        path = self._package_file(state)
        before = _no_link(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size != state["package"]["size"]:
            raise Error("package_size_mismatch")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while True:
                budget.check()
                data = source.read(1 << 20)
                if not data:
                    break
                digest.update(data)
        if digest.hexdigest() != state["package"]["sha256"] or file_identity(_no_link(path)) != file_identity(before):
            raise Error("package_hash_mismatch")

    def _package(self, envelope, budget):
        state = envelope["state"]
        request = state["request"]
        task = self._task_path(request["transfer_id"])
        manifest_path = task / "manifest.json"
        bundle_path = task / "bundle.zip"
        identity_path = task / "package-identity.json"
        if manifest_path.exists():
            manifest = self._read_sidecar(manifest_path, request["budget"]["max_metadata_bytes"])
            validate_sources(state["source_roots"], request["sources"], manifest, budget)
        else:
            manifest = capture_sources(state["source_roots"], request["sources"], budget,
                                       request["evidence_context"]["references"])
            self._atomic_sidecar(manifest_path, canonical_json(manifest), request["budget"]["max_metadata_bytes"])
        if bundle_path.exists():
            if not identity_path.exists():
                raise Error("package_reconcile_required")
            metadata = self._read_sidecar(identity_path, 512)
            _dict(metadata, ("size", "sha256", "manifest_sha256"), "package_reconcile_required")
            actual_size, actual_sha = _hash_path(bundle_path, budget)
            if (metadata["size"] != actual_size or metadata["sha256"] != actual_sha or
                    metadata["manifest_sha256"] != digest_json(manifest)):
                raise Error("package_reconcile_required")
        else:
            package = create_bundle(state["source_roots"], request["sources"], manifest,
                                    bundle_path, self.policy.work_root, budget)
            metadata = {key: package[key] for key in ("size", "sha256", "manifest_sha256")}
            self._atomic_sidecar(identity_path, canonical_json(metadata), 512)
        store = self._store()
        with store.writer():
            fresh = self._load(request["transfer_id"], request["request_digest"], store)
            current = fresh["state"]
            if current["phase"] != "SOURCE_PREPARING" or current["cancelled"]:
                raise Error("worker_state_changed")
            current["package"] = metadata
            current["phase"] = "SOURCE_READY"
            current["terminal"] = GuestTerminal(self._protocol_binding(request, metadata),
                                                 request["expected_destination"]).snapshot()
            self._save(store, fresh, current)

    def _ledger_paths(self, state):
        task = self._task_path(state["request"]["transfer_id"])
        return task / "received.part", task / "chunks.jsonl"

    def _verified_partial(self, state, *, force=False, budget=None, short_call=False):
        """Full byte verification on resume; protected identity continuity per chunk."""
        budget = budget or self._budget(state)
        budget.check()
        partial, ledger = self._ledger_paths(state)
        offset = state["offset"]
        if not partial.exists() and not ledger.exists() and offset == 0:
            return
        safe_chain(partial, self.policy.work_root)
        safe_chain(ledger, self.policy.work_root)
        pinfo, linfo = _no_link(partial), _no_link(ledger)
        if not stat.S_ISREG(pinfo.st_mode) or not stat.S_ISREG(linfo.st_mode) or pinfo.st_size < offset:
            raise Error("partial_corrupt")
        if pinfo.st_nlink != 1 or linfo.st_nlink != 1:
            raise Error("partial_corrupt")
        if os.name == "nt" and (self.acl(partial, "state") is not True or
                                self.acl(ledger, "state") is not True):
            raise Error("windows_acl_not_verified")
        key = self._partial_fingerprint(state, pinfo, linfo)
        if not force and state.get("partial_identity") == key:
            return
        if short_call and (offset > (1 << 20) or state["chunk_count"] > 1024):
            raise Error("partial_verification_required")
        max_ledger = state["request"]["budget"]["max_metadata_bytes"]
        if linfo.st_size > max_ledger:
            raise Error("metadata_budget_exceeded")
        with partial.open("rb") as data, ledger.open("rb") as records:
            position = 0
            for _ in range(state["chunk_count"]):
                budget.check()
                line = records.readline(256)
                record = _strict_json(line, 255)
                _dict(record, ("offset", "count", "sha256"), "partial_corrupt")
                if (record["offset"] != position or not _positive(record["count"]) or
                        record["count"] > state["request"]["budget"]["max_chunk_bytes"] or
                        not _hex(record["sha256"])):
                    raise Error("partial_corrupt")
                chunk = data.read(record["count"])
                if len(chunk) != record["count"] or hashlib.sha256(chunk).hexdigest() != record["sha256"]:
                    raise Error("partial_corrupt")
                position += len(chunk)
            if position != offset:
                raise Error("partial_corrupt")
            accepted_ledger_length = records.tell()
        budget.check()
        if (self._partial_fingerprint(state, _no_link(partial), _no_link(ledger)) != key):
            raise Error("partial_changed")
        if pinfo.st_size > offset:
            with partial.open("r+b") as output:
                output.truncate(offset)
                output.flush()
                os.fsync(output.fileno())
        if linfo.st_size > accepted_ledger_length:
            with ledger.open("r+b") as output:
                output.truncate(accepted_ledger_length)
                output.flush()
                os.fsync(output.fileno())
        pinfo, linfo = _no_link(partial), _no_link(ledger)
        state["partial_identity"] = self._partial_fingerprint(state, pinfo, linfo)

    @staticmethod
    def _partial_fingerprint(state, pinfo, linfo):
        def identity(info):
            return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_ctime_ns]
        return {"offset": state["offset"], "chunk_count": state["chunk_count"],
                "partial": identity(pinfo), "ledger": identity(linfo)}

    def transfer_chunk(self, transfer_id: str, request_digest: str, offset: int,
                       count: int, data_base64: str | None = None,
                       chunk_sha256: str | None = None):
        if not _positive(count) or not _positive(offset, allow_zero=True):
            raise Error("invalid_chunk_range")
        envelope = self._load(transfer_id, request_digest)
        state = envelope["state"]
        maximum = state["request"]["budget"]["max_chunk_bytes"]
        if count > maximum or time.monotonic() >= state["deadline_monotonic"]:
            raise Error("chunk_budget_or_deadline")
        if state["cancelled"]:
            raise Error("transfer_cancelled")
        if state["request"]["direction"] == "pull":
            if data_base64 is not None or chunk_sha256 is not None or state["phase"] not in ("SOURCE_READY", "SOURCE_PREPARED"):
                raise Error("chunk_precondition_failed")
            package = state["package"]
            if offset + count > package["size"]:
                raise Error("invalid_chunk_range")
            path = self._package_file(state)
            before = _no_link(path)
            if before.st_size != package["size"]:
                raise Error("package_changed")
            with path.open("rb") as source:
                source.seek(offset)
                data = source.read(count)
            if len(data) != count or file_identity(_no_link(path)) != file_identity(before):
                raise Error("package_changed")
            return {"schema": "velo.transfer.guest.response.v1", "offset": offset,
                    "count": count, "data_base64": base64.b64encode(data).decode("ascii"),
                    "chunk_sha256": hashlib.sha256(data).hexdigest()}
        if (not isinstance(data_base64, str) or len(data_base64) > 4 * ((maximum + 2) // 3) or
                not _hex(chunk_sha256)):
            raise Error("invalid_chunk")
        try:
            data = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Error("invalid_chunk") from exc
        if len(data) != count or hashlib.sha256(data).hexdigest() != chunk_sha256:
            raise Error("chunk_hash_mismatch")
        store = self._store()
        with store.writer():
            fresh = self._load(transfer_id, request_digest, store)
            state = fresh["state"]
            self._check_idle(store)
            if state["phase"] not in ("DEST_RECEIVING", "DEST_RECEIVED"):
                raise Error("chunk_precondition_failed")
            if offset + count > state["package"]["size"]:
                raise Error("invalid_chunk_range")
            self._verified_partial(state, short_call=True)
            partial, ledger = self._ledger_paths(state)
            if offset < state["offset"]:
                if offset + count > state["offset"]:
                    raise Error("chunk_offset_conflict")
                with partial.open("rb") as source:
                    source.seek(offset)
                    previous = source.read(count)
                if previous != data:
                    raise Error("chunk_conflict")
                return {"schema": "velo.transfer.guest.response.v1", "verified_offset": state["offset"],
                        "replayed": True}
            if offset != state["offset"] or state["phase"] != "DEST_RECEIVING":
                raise Error("chunk_offset_conflict")
            if not partial.exists():
                self._atomic_sidecar(partial, b"", state["request"]["budget"]["max_package_bytes"])
                self._atomic_sidecar(ledger, b"", state["request"]["budget"]["max_metadata_bytes"])
            record = canonical_json({"offset": offset, "count": count, "sha256": chunk_sha256}) + b"\n"
            if ledger.stat().st_size + len(record) > state["request"]["budget"]["max_metadata_bytes"]:
                raise Error("metadata_budget_exceeded")
            self._budget(state).space(partial.parent, count)
            with partial.open("r+b") as output:
                output.seek(offset)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            with ledger.open("ab") as output:
                output.write(record)
                output.flush()
                os.fsync(output.fileno())
            state["offset"] += count
            state["chunk_count"] += 1
            if state["offset"] == state["package"]["size"]:
                state["phase"] = "DEST_RECEIVED"
                state["terminal"] = GuestTerminal(self._protocol_binding(state["request"], state["package"]),
                    state["request"]["expected_destination"]).snapshot()
            pinfo, linfo = _no_link(partial), _no_link(ledger)
            state["partial_identity"] = self._partial_fingerprint(state, pinfo, linfo)
            self._save(store, fresh, state)
            return {"schema": "velo.transfer.guest.response.v1", "verified_offset": state["offset"],
                    "replayed": False}

    def transfer_finish(self, transfer_id: str, request_digest: str, action: str,
                        *, prepare_receipt: dict | None = None,
                        source_validation_receipt: dict | None = None,
                        publication_receipt: dict | None = None):
        if action not in ("prepare", "commit", "release"):
            raise Error("action_not_allowed")
        inputs = {}
        if action == "prepare":
            if any(x is not None for x in (prepare_receipt, source_validation_receipt, publication_receipt)):
                raise Error("invalid_action_input")
        elif action == "commit":
            if prepare_receipt is None or source_validation_receipt is None or publication_receipt is not None:
                raise Error("invalid_action_input")
            inputs = {"prepare_receipt": prepare_receipt,
                      "source_validation_receipt": source_validation_receipt}
        else:
            if prepare_receipt is None or publication_receipt is None or source_validation_receipt is not None:
                raise Error("invalid_action_input")
            inputs = {"prepare_receipt": prepare_receipt,
                      "publication_receipt": publication_receipt}
        store = self._store()
        launch = False
        with store.writer():
            envelope = self._load(transfer_id, request_digest, store)
            state = envelope["state"]
            if state["terminal"] is None:
                raise Error("action_precondition_failed")
            terminal = GuestTerminal.restore(state["terminal"],
                self._protocol_binding(state["request"], state["package"]),
                state["request"]["expected_destination"])
            previous = terminal.operations.get(action)
            operation = terminal.begin_action(action, **inputs)
            if previous is None:
                if time.monotonic() >= state["deadline_monotonic"] or state["cancelled"]:
                    raise Error("deadline_or_cancelled")
                self._check_idle(store)
                state["terminal"] = terminal.snapshot()
                state["phase"] = terminal.local_phase
                self._save(store, envelope, state)
                launch = True
            elif (operation["status"] == "IN_PROGRESS" and
                  (state["owner"] is None or state["owner"]["job"] != action or
                   state["owner"]["stopped"] or
                   not same_process(state["owner"]["pid"], state["owner"]["birth"])) and
                  not (action == "prepare" and state["request"]["direction"] == "push" and
                       state["stage_intent"] is not None and state["staging"] is None)):
                launch = True
        if launch:
            self._launch(transfer_id, request_digest, action)
        return {"schema": "velo.transfer.guest.response.v1", "state_scope":
                "guest_source" if state["request"]["direction"] == "pull" else "guest_destination",
                "local_phase": state["phase"], "action": action, "operation": operation}

    def _terminal(self, state):
        return GuestTerminal.restore(state["terminal"],
            self._protocol_binding(state["request"], state["package"]),
            state["request"]["expected_destination"])

    def _content_acl(self, stage, destination):
        if os.name != "nt":
            return None
        return self.acl.content_callback(stage, destination.parent, destination)

    def _clear_registered_stage(self, staging, allowed_root, budget, callback):
        stage = Path(staging["staging_directory"])
        destination = Path(staging["destination_directory"])
        safe_chain(stage, allowed_root)
        if (stage.parent != destination.parent or
                directory_identity(stage) != staging["staging_identity"] or
                directory_identity(stage.parent) != staging["parent_identity"] or
                destination.exists()):
            raise Error("stage_reconcile_required")
        if os.name == "posix" and _no_link(stage).st_mode & 0o077:
            raise Error("staging_not_private")
        if callback is not None and (callback(stage) is not True or callback(stage.parent) is not True):
            raise Error("windows_acl_not_verified")

        def remove_children(directory):
            for child in os.scandir(directory):
                budget.check()
                path = Path(child.path)
                safe_chain(path, stage)
                info = _no_link(path)
                if stat.S_ISDIR(info.st_mode):
                    remove_children(path)
                    path.rmdir()
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    path.unlink()
                else:
                    raise Error("stage_reconcile_required")

        remove_children(stage)
        if os.name == "posix":
            fd = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if directory_identity(stage) != staging["staging_identity"]:
            raise Error("stage_reconcile_required")

    def _prepare(self, envelope, budget):
        state = envelope["state"]
        request = state["request"]
        terminal = self._terminal(state)
        operation = terminal.operations["prepare"]
        if operation["status"] != "IN_PROGRESS":
            raise Error("operation_mismatch")
        if request["direction"] == "pull":
            manifest = self._manifest(state)
            validate_sources(state["source_roots"], request["sources"], manifest, budget)
            self._hash_package(state, budget)
            receipt = prepare_receipt(terminal.binding, digest_json(manifest))
        else:
            self._verified_partial(state)
            self._hash_package(state, budget)
            destination = Path(request["expected_destination"]["canonical_path"])
            self.policy.resolve_local(destination, "write", allow_missing_leaf=True)
            root = max((root for root in self.policy.write_roots if destination.is_relative_to(root)),
                       key=lambda item: len(item.parts))
            if state["staging"] is not None:
                staging = state["staging"]
                if not Path(staging["staging_directory"]).exists():
                    raise Error("stage_reconcile_required")
                callback = self._content_acl(Path(staging["staging_directory"]), destination)
                self._clear_registered_stage(staging, root, budget, callback)
                extracted = unpack_bundle(self._package_file(state), self.policy.work_root,
                    state["package"]["size"], state["package"]["sha256"], destination,
                    root, budget, staging=staging, verify_windows_acl=callback)
                if extracted["manifest_sha256"] != state["package"]["manifest_sha256"]:
                    raise Error("manifest_hash_mismatch")
                manifest_path = self._task_path(request["transfer_id"]) / "manifest.json"
                if manifest_path.exists():
                    self._manifest(state)
                else:
                    self._atomic_sidecar(manifest_path, canonical_json(extracted["manifest"]),
                                         request["budget"]["max_metadata_bytes"])
                receipt = prepare_receipt(terminal.binding,
                    digest_json({"manifest": extracted["manifest_sha256"],
                                 "staging": staging["staging_identity"]}))
                self._persist_prepare(request, operation["operation_id"], receipt)
                return
            stage_name = ".velo-stage-" + hashlib.sha256(request["transfer_id"].encode()).hexdigest()[:32]
            stage = destination.parent / stage_name
            callback = self._content_acl(stage, destination)
            store = self._store()
            with store.writer():
                fresh = self._load(request["transfer_id"], request["request_digest"], store)
                current = fresh["state"]
                if current["stage_intent"] is not None:
                    raise Error("stage_reconcile_required")
                current["stage_intent"] = {"stage_name": stage_name, "destination": str(destination)}
                self._save(store, fresh, current)

            def register(path, identity, parent):
                with store.writer():
                    fresh = self._load(request["transfer_id"], request["request_digest"], store)
                    current = fresh["state"]
                    if current["stage_intent"] != {"stage_name": stage_name, "destination": str(destination)}:
                        return False
                    current["staging"] = {"staging_directory": path,
                        "staging_identity": identity, "parent_identity": parent,
                        "destination_directory": str(destination)}
                    self._save(store, fresh, current)
                    return True

            staging = prepare_staging(destination, root, budget, stage_name=stage_name,
                                      register_stage=register, verify_windows_acl=callback)
            extracted = unpack_bundle(self._package_file(state), self.policy.work_root,
                state["package"]["size"], state["package"]["sha256"], destination, root,
                budget, staging=staging, verify_windows_acl=callback)
            if extracted["manifest_sha256"] != state["package"]["manifest_sha256"]:
                raise Error("manifest_hash_mismatch")
            manifest_path = self._task_path(request["transfer_id"]) / "manifest.json"
            self._atomic_sidecar(manifest_path, canonical_json(extracted["manifest"]),
                                 request["budget"]["max_metadata_bytes"])
            receipt = prepare_receipt(terminal.binding,
                digest_json({"manifest": extracted["manifest_sha256"],
                             "staging": staging["staging_identity"]}))
        self._persist_prepare(request, operation["operation_id"], receipt)

    def _persist_prepare(self, request, operation_id, receipt):
        store = self._store()
        with store.writer():
            fresh = self._load(request["transfer_id"], request["request_digest"], store)
            current = fresh["state"]
            terminal = self._terminal(current)
            terminal.complete_prepare(operation_id, receipt)
            current["terminal"] = terminal.snapshot()
            current["phase"] = terminal.local_phase
            self._save(store, fresh, current)

    def _commit(self, envelope, budget):
        state = envelope["state"]
        request = state["request"]
        if request["direction"] != "push":
            raise Error("action_not_allowed")
        terminal = self._terminal(state)
        operation = terminal.operations["commit"]
        staging = state["staging"]
        if staging is None:
            raise Error("stage_reconcile_required")
        destination = Path(request["expected_destination"]["canonical_path"])
        root = max((root for root in self.policy.write_roots if destination.is_relative_to(root)),
                   key=lambda item: len(item.parts))
        manifest = self._manifest(state)
        callback = self._content_acl(Path(staging["staging_directory"]), destination)
        if state["publish_intent"] is None:
            self._hash_package(state, budget)
            verify_tree(staging["staging_directory"], manifest, budget,
                        staging["staging_identity"])
            intent = publish_intent(terminal.binding, terminal.prepare, terminal.destination,
                                    staging["staging_identity"], staging["parent_identity"])
            store = self._store()
            with store.writer():
                fresh = self._load(request["transfer_id"], request["request_digest"], store)
                current = fresh["state"]
                if current["publish_intent"] is not None:
                    raise Error("publication_reconcile_required")
                current["publish_intent"] = intent
                self._save(store, fresh, current)
        else:
            intent = state["publish_intent"]
        if destination.exists():
            actual = verify_tree(destination, manifest, budget,
                                 intent["publication"]["directory_identity"])
        else:
            published = publish_directory(staging["staging_directory"], destination, root,
                manifest, budget, expected_staging_identity=staging["staging_identity"],
                expected_parent_identity=staging["parent_identity"], verify_windows_acl=callback)
            actual = {"identity": published["identity"],
                      "manifest_sha256": published["manifest_sha256"]}
        receipt = recover_publication(intent, terminal.binding, terminal.prepare,
            terminal.destination, verified_identity=actual["identity"],
            verified_parent_identity=directory_identity(destination.parent),
            verified_manifest_sha256=actual["manifest_sha256"])
        store = self._store()
        with store.writer():
            fresh = self._load(request["transfer_id"], request["request_digest"], store)
            current = fresh["state"]
            terminal = self._terminal(current)
            terminal.complete_commit(operation["operation_id"], receipt)
            current["terminal"] = terminal.snapshot()
            current["phase"] = terminal.local_phase
            self._save(store, fresh, current)

    def _release(self, envelope, budget):
        state = envelope["state"]
        request = state["request"]
        terminal = self._terminal(state)
        operation = terminal.operations["release"]
        if terminal.release_authorization is None:
            if request["direction"] == "pull":
                manifest = self._manifest(state)
                validate_sources(state["source_roots"], request["sources"], manifest, budget)
                self._hash_package(state, budget)
            else:
                manifest = self._manifest(state)
                destination = Path(request["expected_destination"]["canonical_path"])
                verify_tree(destination, manifest, budget,
                            terminal.publication["directory_identity"])
                self._verified_partial(state)
                self._hash_package(state, budget)
            targets = self._capture_cleanup_targets(state)
            terminal.authorize_release(operation["operation_id"])
            store = self._store()
            with store.writer():
                fresh = self._load(request["transfer_id"], request["request_digest"], store)
                current = fresh["state"]
                current["terminal"] = terminal.snapshot()
                current["phase"] = terminal.local_phase
                current["cleanup_targets"] = targets
                self._save(store, fresh, current)
            state["cleanup_targets"] = targets
            state["terminal"] = terminal.snapshot()
            state["phase"] = terminal.local_phase
        if terminal.release_authorization is None or state.get("cleanup_targets") is None:
            raise Error("cleanup_ownership_unknown")
        for name in state["cleanup_targets"]:
            self._remove_owned_temporary(state, name)
        store = self._store()
        with store.writer():
            fresh = self._load(request["transfer_id"], request["request_digest"], store)
            current = fresh["state"]
            current["cleanup"] = {"temporary_files_removed": True, "workers_stopped": False}
            self._save(store, fresh, current)

    def _cleanup_path(self, state, name):
        permitted = ("bundle.zip",) if state["request"]["direction"] == "pull" else (
            "received.part", "chunks.jsonl")
        if name not in permitted:
            raise Error("cleanup_ownership_unknown")
        path = self._task_path(state["request"]["transfer_id"]) / name
        safe_chain(path, self.policy.work_root, allow_missing_leaf=True)
        return path

    def _capture_cleanup_targets(self, state):
        names = ("bundle.zip",) if state["request"]["direction"] == "pull" else (
            "received.part", "chunks.jsonl")
        targets = {}
        for name in names:
            path = self._cleanup_path(state, name)
            info = _no_link(path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Error("cleanup_ownership_unknown")
            if os.name == "nt" and self.acl(path, "state") is not True:
                raise Error("windows_acl_not_verified")
            targets[name] = file_identity(info)
        return targets

    def _owned_temporary_exists(self, state, name):
        terminal = self._terminal(state)
        if terminal.release_authorization is None:
            raise Error("release_not_authorized")
        targets = state.get("cleanup_targets")
        if not isinstance(targets, dict) or name not in targets:
            raise Error("cleanup_ownership_unknown")
        path = self._cleanup_path(state, name)
        if not os.path.lexists(path):
            return False
        info = _no_link(path)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                file_identity(info) != targets[name]):
            raise Error("cleanup_ownership_conflict")
        if os.name == "nt" and self.acl(path, "state") is not True:
            raise Error("windows_acl_not_verified")
        return True

    def _remove_owned_temporary(self, state, name):
        if not self._owned_temporary_exists(state, name):
            return
        path = self._cleanup_path(state, name)
        path.unlink()
        if os.name == "posix":
            fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _finalize_release(self, transfer_id, digest):
        store = self._store()
        with store.writer():
            envelope = self._load(transfer_id, digest, store)
            state = envelope["state"]
            if state["phase"] not in ("SOURCE_RELEASING", "DEST_RELEASING"):
                return
            terminal = self._terminal(state)
            owner = state["owner"]
            if (terminal.release_authorization is None or owner is None or
                    owner["job"] != "release" or not owner["stopped"] or
                    same_process(owner["pid"], owner["birth"])):
                return
            lease = self._lease(store)
            if lease["state"]["active"] is not None:
                return
            probe = RootLease(self.policy.work_root)
            try:
                probe.acquire()
            except Error as exc:
                if exc.code == "worker_busy":
                    return
                raise
            try:
                targets = state.get("cleanup_targets")
                if not isinstance(targets, dict) or not targets:
                    raise Error("cleanup_ownership_unknown")
                for name in targets:
                    if self._owned_temporary_exists(state, name):
                        return
                operation_id = terminal.operations["release"]["operation_id"]
                terminal.complete_release(operation_id,
                    {"temporary_files_removed": True, "workers_stopped": True})
                state["terminal"] = terminal.snapshot()
                state["phase"] = terminal.local_phase
                state["cleanup"] = {"temporary_files_removed": True, "workers_stopped": True}
                self._save(store, envelope, state)
            finally:
                probe.release()

    def transfer_abort(self, transfer_id: str, request_digest: str):
        store = self._store()
        with store.writer():
            envelope = self._load(transfer_id, request_digest, store)
            state = envelope["state"]
            state["cancelled"] = True
            self._save(store, envelope, state)
            owner = state["owner"]
        if owner is not None and not owner["stopped"]:
            self._stop_registered(owner, request_digest)
        return self.transfer_status(transfer_id, request_digest)

    def _stop_registered(self, owner, digest):
        """Cancel a persisted task only while its matching lease still owns the root."""
        store = self._store()
        with store.writer():
            envelope = self._load(owner["transfer_id"], digest, store)
            current = envelope["state"]["owner"]
            lease = self._lease(store)
            active = lease["state"]["active"]
            if current != owner or (active is not None and active != owner):
                raise Error("worker_ownership_mismatch")
            if active is None:
                if same_process(owner["pid"], owner["birth"]):
                    raise Error("worker_ownership_mismatch")
                return
        if not terminate_verified(owner["pid"], owner["birth"], timeout=3):
            if same_process(owner["pid"], owner["birth"]):
                raise Error("worker_stop_unconfirmed")
        self._reconcile_exit(owner["transfer_id"], digest)
        self._reap_local(owner)
        with store.writer():
            fresh = self._load(owner["transfer_id"], digest, store)
            current = fresh["state"]
            if current["owner"] is not None and current["owner"]["nonce"] == owner["nonce"]:
                current["error"] = "transfer_cancelled"
                self._save(store, fresh, current)

    def shutdown(self):
        for pid, record in list(self._owned.items()):
            try:
                store = self._store()
                raw = store._read(store._state_path(record[0]))
                state = self._load(record[0], raw["binding"]["request_digest"], store)["state"]
                owner = state["owner"]
                if (owner and not owner["stopped"] and owner["nonce"] == record[1] and
                        same_process(pid, owner["birth"])):
                    with store.writer():
                        fresh = self._load(record[0], raw["binding"]["request_digest"], store)
                        current = fresh["state"]
                        current["cancelled"] = True
                        self._save(store, fresh, current)
                    self._stop_registered(owner, raw["binding"]["request_digest"])
                else:
                    self._reap_local(owner) if owner else None
            except (ChildProcessError, ProcessLookupError):
                pass
            self._owned.pop(pid, None)

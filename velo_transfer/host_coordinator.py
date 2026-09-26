"""Foreground host orchestration with receipt-gated owned host cleanup.

All remote calls use one journal writer and the original host deadline. Transport
selection owns pre-begin fallback; a persisted begin attempt makes it sticky.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import hashlib
import os
import re
import time
from pathlib import Path, PureWindowsPath

from .adapters import AdapterError, select_adapter
from .connection import load_connection_profile
from .errors import TransferContentError as Error
from .host_content import HostContent, _package_identity
from .host_cleanup import HostCleanup
from .host_journal import HostJournal, observe_host_identity
from .host_partial import HostPartial
from .host_publication import HostPublication
from .manifest import canonical_json, digest_json, file_identity
from .protocol import (GuestTerminal, PROTOCOL_VERSION, receipt_digest,
                       source_validation_receipt, validate_binding,
                       validate_prepare, validate_publication)
from .request import HostRequest, make_guest_request
from .result import result_summary, validate_result

_SCHEMA = "velo.transfer.coordinator.v1"
_CONFLICTS = ("conflict", "changed", "mismatch", "corrupt", "replaced")


def _same(a, b):
    return canonical_json(a) == canonical_json(b)


class TransferCoordinator:
    """One foreground invocation. Injected seams are for trusted local tests only."""

    def __init__(self, request: HostRequest, *, host_identity=None,
                 _adapter_selector=select_adapter, _profile_loader=load_connection_profile):
        self.request = request
        self.journal = HostJournal(request, host_identity or observe_host_identity())
        self.select_adapter = _adapter_selector
        self.profile_loader = _profile_loader
        self.adapter = None
        self.deadline = None
        self.status = None

    def _data(self):
        return self.journal.load()["data"]

    def _save(self, **updates):
        envelope = self.journal.load()
        data = envelope["data"]
        data.update(copy.deepcopy(updates))
        return self.journal.save(envelope["revision"], data)

    def _phase(self, phase):
        data = self._data()
        if data["phase"] != phase:
            self._save(last_phase=data["phase"], phase=phase)

    def _check(self):
        if time.monotonic() >= self.deadline:
            raise Error("deadline_exceeded")

    def _evidence(self, role, value):
        # Identical facts share an immutable name. No per-chunk evidence files.
        name = role[:22] + "-" + digest_json(value)[:32]
        ref = self.journal.write_evidence(name, value)
        refs = self._data().get("evidence", {})
        if role in ("adapter_error", "failure", "host_cleanup_failure") and role in refs and refs[role] != ref:
            # Keep the first error addressable and index every later distinct
            # failure. An overwritten pointer must not hide cleanup ownership.
            role = role + "_" + ref["sha256"][:24]
        refs[role] = ref
        self._save(evidence=refs)
        return ref

    def _identity_args(self):
        guest = self._data()["guest_request"]
        return {"transfer_id": guest["transfer_id"], "request_digest": guest["request_digest"]}

    async def _call(self, operation, arguments):
        self._check()
        # Persist a bounded intent before *every* external action, including reads.
        data = self._data()
        seq = data.get("io_sequence", 0) + 1
        intent = {"sequence": seq, "operation": operation,
                  "arguments_sha256": digest_json(arguments), "channel": self.adapter.channel}
        self._save(io_sequence=seq, io_intent=intent)
        try:
            result = await self.adapter.call(operation, arguments)
        except AdapterError as exc:
            detail = {"code": exc.code, "intent": intent,
                      "may_have_committed": exc.may_have_committed}
            if exc.cleanup_path is not None:
                detail["cleanup_path"] = exc.cleanup_path
            if exc.guest_result is not None:
                # Retain received facts, including receipts, even on control cleanup failure.
                detail["guest_result"] = exc.guest_result
            observations = self.adapter.observations
            for key in ("cleanup_path", "pending_control_path", "control_cleanup_unknown"):
                if key in observations:
                    detail[key] = observations[key]
            self._evidence("adapter_error", detail)
            if exc.cleanup_path or observations.get("cleanup_failed") or observations.get("control_cleanup_unknown"):
                self._save(adapter_cleanup_pending=True)
            if exc.guest_result is not None and operation in ("transfer_begin", "transfer_status"):
                self._ingest(exc.guest_result)
            elif exc.guest_result is not None and operation == "transfer_finish":
                self._accept_finish(exc.guest_result, arguments)
            raise
        self._check()
        self._save(io_result={"sequence": seq, "sha256": digest_json(result)})
        return result

    def _ingest(self, status):
        data = self._data()
        guest = data["guest_request"]
        scope = "guest_source" if guest["direction"] == "pull" else "guest_destination"
        if (not isinstance(status, dict) or status.get("schema") != "velo.transfer.guest.response.v1" or
                status.get("transfer_id") != guest["transfer_id"] or
                status.get("request_digest") != guest["request_digest"] or status.get("state_scope") != scope):
            raise Error("guest_status_binding_conflict")
        offset = status.get("verified_offset")
        if type(offset) is not int or offset < 0:
            raise Error("guest_offset_conflict")
        package = status.get("package")
        updates = {"guest_status": status}
        if package is not None:
            if (not isinstance(package, dict) or set(package) != {"size", "sha256", "manifest_sha256"}):
                raise Error("guest_package_conflict")
            binding = {"protocol_version": PROTOCOL_VERSION, **self._identity_args(),
                       "direction": guest["direction"], **guest["expected_vm_identity"],
                       "policy_id": data["peer"]["policy_id"], "package_size": package["size"],
                       "package_sha256": package["sha256"], "manifest_sha256": package["manifest_sha256"]}
            validate_binding(binding)
            if package["size"] > self.request.guest_budget["max_package_bytes"] or offset > package["size"]:
                raise Error("package_budget_exceeded")
            for key, value in (("binding", binding), ("package", package)):
                if data.get(key) is not None and not _same(data[key], value):
                    raise Error("guest_package_conflict")
                updates[key] = value
        terminal = status.get("terminal")
        if terminal is not None:
            binding = updates.get("binding", data.get("binding"))
            restored = GuestTerminal.restore(terminal, binding, guest["expected_destination"])
            if status.get("local_phase") != restored.local_phase:
                raise Error("guest_phase_conflict")
            actions = data.get("operations", {})
            for action, op in restored.operations.items():
                previous = actions.get(action)
                identity = {"operation_id": op["operation_id"], "input_digest": op["input_digest"]}
                if previous is not None and not _same(previous, identity):
                    raise Error("guest_operation_conflict")
                actions[action] = identity
            updates["operations"] = actions
            for key, value in (("prepare_receipt", restored.prepare),
                               ("publication_receipt", restored.publication)):
                if value is not None:
                    if data.get(key) is not None and not _same(data[key], value):
                        raise Error("receipt_binding_mismatch")
                    updates[key] = value
            if restored.publication is not None:
                updates.update(published_ever=True, publication_unknown=False)
            elif guest["direction"] == "push" and "commit" not in restored.operations:
                updates["publication_unknown"] = False
        self._save(**updates)
        for key in ("prepare_receipt", "publication_receipt"):
            if updates.get(key) is not None:
                self._evidence(key, updates[key])
        self.status = copy.deepcopy(status)
        return status

    async def _status(self):
        return self._ingest(await self._call("transfer_status", self._identity_args()))

    async def _pause(self):
        self._check()
        await asyncio.sleep(min(0.1, max(0, self.deadline - time.monotonic())))

    async def _begin(self):
        data = self._data()
        # Every resumed/uncertain mutation first queries the same ID and digest.
        if data["begin_attempted"]:
            try:
                status = await self._status()
            except AdapterError as exc:
                if exc.code != "task_not_found":
                    raise
            else:
                resumable = status["local_phase"] in ("DEST_RECEIVING", "DEST_RECEIVED", "SOURCE_PREPARING")
                recoverable_errors = (None, "worker_failed", "worker_activation_unknown",
                                      "worker_activation_failed", "worker_activation_timeout")
                if status.get("error") and (not resumable or status["error"] not in recoverable_errors):
                    raise Error(status["error"])
                if not resumable:
                    return status
                worker = status.get("worker")
                if worker is not None and worker.get("stopped") is not True:
                    return status
                # Explicit same-request begin asks the guest to verify the
                # durable acknowledged prefix after a host/process restart.
        attempts = self._data().get("begin_attempts", 0)
        if attempts >= 3:
            raise Error("begin_retry_exhausted")
        self._save(begin_attempted=True, begin_attempts=attempts + 1)
        try:
            status = self._ingest(await self._call("transfer_begin", {"request": self._data()["guest_request"]}))
        except AdapterError as exc:
            if not exc.may_have_committed:
                raise
            status = await self._status()  # unknown stays incomplete if status is unavailable
        return status

    async def _ready(self, status):
        while (status["local_phase"] == "SOURCE_PREPARING" or
               status.get("worker") is not None and status["worker"].get("stopped") is not True):
            if status.get("error"):
                raise Error(status["error"])
            await self._pause()
            status = await self._status()
        if status.get("error"):
            raise Error(status["error"])
        if self._data().get("binding") is None:
            raise Error("guest_package_unavailable")
        return status

    async def _finish(self, action, inputs):
        args = {**self._identity_args(), "action": action, **inputs}
        # Persist exact authorized inputs before request. Operation ID comes from
        # guest history and is pinned by _ingest; it is never regenerated here.
        intents = self._data().get("actions", {})
        fingerprint = digest_json(args)
        if action in intents and intents[action]["arguments_sha256"] != fingerprint:
            raise Error("action_conflict")
        intents.setdefault(action, {"arguments_sha256": fingerprint, "attempts": 0})
        self._save(actions=intents)
        status = await self._status()
        while True:
            terminal = status.get("terminal")
            if terminal is None:
                raise Error("guest_terminal_missing")
            op = terminal["operations"].get(action)
            if op is not None:
                expected = digest_json({"binding": self._data()["binding"], "action": action, "inputs": inputs})
                if op["input_digest"] != expected:
                    raise Error("guest_operation_conflict")
                if op["status"] == "DONE":
                    worker = status.get("worker")
                    if worker is None or worker.get("stopped") is True:
                        return status
                    await self._pause()
                    status = await self._status()
                    continue
                if op["status"] == "FAILED":
                    raise Error(op["result"]["error"])
            worker = status.get("worker")
            stopped = worker is None or worker.get("stopped") is True
            if stopped:
                intents = self._data()["actions"]
                if intents[action]["attempts"] >= 3:
                    raise Error("action_retry_exhausted")
                intents[action]["attempts"] += 1
                updates = {"actions": intents}
                if action == "commit":
                    updates["publication_unknown"] = True
                self._save(**updates)
                try:
                    response = await self._call("transfer_finish", args)
                    self._accept_finish(response, args)
                except AdapterError as exc:
                    if not exc.may_have_committed:
                        raise
                    # No blind retry. Status below must prove the same action.
                status = await self._status()
            else:
                if status.get("error"):
                    raise Error(status["error"])
                await self._pause()
                status = await self._status()

    def _accept_finish(self, response, args):
        data = self._data()
        action = args["action"]
        inputs = {k: v for k, v in args.items() if k not in ("transfer_id", "request_digest", "action")}
        observed = response.get("operation") if isinstance(response, dict) else None
        expected = digest_json({"binding": data["binding"], "action": action, "inputs": inputs})
        if (not isinstance(response, dict) or response.get("schema") != "velo.transfer.guest.response.v1" or
                response.get("action") != action or not isinstance(observed, dict) or
                set(observed) != {"operation_id", "input_digest", "status", "inputs", "result"} or
                observed["input_digest"] != expected or not _same(observed["inputs"], inputs) or
                not isinstance(observed["operation_id"], str) or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", observed["operation_id"]) is None or
                observed["status"] not in ("IN_PROGRESS", "DONE", "FAILED")):
            raise Error("guest_operation_conflict")
        operations = data.get("operations", {})
        identity = {"operation_id": observed["operation_id"], "input_digest": observed["input_digest"]}
        if action in operations and operations[action] != identity:
            raise Error("guest_operation_conflict")
        operations[action] = identity
        self._save(operations=operations)
        if observed["status"] == "DONE":
            result = observed["result"]
            if not isinstance(result, dict):
                raise Error("guest_operation_conflict")
            if action == "prepare":
                receipt = result.get("prepare_receipt")
                validate_prepare(receipt, data["binding"])
                updates = {"prepare_receipt": receipt}
            else:
                receipt = result.get("publication_receipt")
                validate_publication(receipt, data["binding"], data["prepare_receipt"],
                                     data["guest_request"]["expected_destination"])
                updates = {"publication_receipt": receipt, "published_ever": True, "publication_unknown": False}
            self._save(**updates)
            self._evidence("prepare_receipt" if action == "prepare" else "publication_receipt", receipt)

    async def _push(self, status):
        data = self._data()
        # Published resumes never recreate content or revalidate a newer source.
        if data.get("publication_receipt") is None:
            terminal = status.get("terminal")
            commit_started = terminal is not None and "commit" in terminal["operations"]
            if not commit_started:
                prepared = HostContent(self.journal).prepare_push()
                if status["local_phase"] in ("DEST_RECEIVING", "DEST_RECEIVED"):
                    self._phase("TRANSFERRING")
                    await self._send(prepared, status)
                self._phase("VERIFYING")
                await self._finish("prepare", {})
                verified = HostContent(self.journal).verify_push_source()
                data = self._data()
                receipt = source_validation_receipt(data["binding"], data["prepare_receipt"], verified["identity_digest"])
                if data.get("source_validation_receipt") is not None and not _same(receipt, data["source_validation_receipt"]):
                    raise Error("source_validation_conflict")
                self._save(source_validation_receipt=receipt, source_stability="stable_at_required_check")
                self._evidence("source_validation", receipt)
            data = self._data()
            if data.get("source_validation_receipt") is None:
                raise Error("source_validation_missing")
            await self._finish("commit", {"prepare_receipt": data["prepare_receipt"],
                                            "source_validation_receipt": data["source_validation_receipt"]})
        self._phase("PUBLISHED")

    async def _send(self, prepared, status):
        package = prepared["package"]
        path = Path(prepared["package_path"])
        expected = {key: value for key, value in prepared["ownership"].items() if key != "path"}
        if _package_identity(path) != expected:
            raise Error("host_package_ownership_conflict")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            offset = status["verified_offset"]
            if self.request.resume:
                self._save(resumed_bytes=max(self._data().get("resumed_bytes", 0), offset))
            maximum = min(self.request.guest_budget["max_chunk_bytes"], self.adapter.raw_chunk_bytes)
            if type(maximum) is not int or maximum <= 0:
                raise Error("invalid_chunk_range")
            while offset < package["size"]:
                self._check()
                before = {**file_identity(os.fstat(fd)), "ctime_ns": os.fstat(fd).st_ctime_ns}
                if before != expected or _package_identity(path) != expected:
                    raise Error("host_package_ownership_conflict")
                count = min(maximum, package["size"] - offset)
                raw = os.pread(fd, count, offset)
                if len(raw) != count:
                    raise Error("package_changed")
                args = {**self._identity_args(), "offset": offset, "count": count,
                        "data_base64": base64.b64encode(raw).decode("ascii"),
                        "chunk_sha256": hashlib.sha256(raw).hexdigest()}
                self._save(pending_chunk={"offset": offset, "count": count, "sha256": args["chunk_sha256"]})
                try:
                    response = await self._call("transfer_chunk", args)
                    advanced = response.get("verified_offset")
                except AdapterError as exc:
                    if not exc.may_have_committed:
                        raise
                    reconciled = await self._status()
                    advanced = reconciled["verified_offset"]
                    if advanced == offset:
                        # A confirmed non-advance remains recoverable; next run
                        # uses the same bytes. Do not spin on uncertain writes.
                        raise Error("chunk_outcome_unresolved")
                if type(advanced) is not int or advanced != offset + count:
                    raise Error("guest_offset_conflict")
                offset = advanced
                self._save(push_offset=offset, pending_chunk=None)
        finally:
            os.close(fd)

    async def _pull(self, status):
        data = self._data()
        if data.get("publish_intent") is None and not data["published_ever"]:
            if status["local_phase"] not in ("SOURCE_READY", "SOURCE_PREPARED"):
                raise Error("guest_phase_conflict")
            partial = HostPartial(self.journal, data["binding"])
            current = partial.initialize()
            offset = current["verified_offset"]
            if self.request.resume:
                self._save(resumed_bytes=max(data.get("resumed_bytes", 0), offset))
            self._phase("TRANSFERRING")
            maximum = min(self.request.guest_budget["max_chunk_bytes"], self.adapter.raw_chunk_bytes)
            if type(maximum) is not int or maximum <= 0:
                raise Error("invalid_chunk_range")
            while offset < data["package"]["size"]:
                count = min(maximum, data["package"]["size"] - offset)
                response = await self._call("transfer_chunk", {**self._identity_args(), "offset": offset, "count": count})
                encoded = response.get("data_base64")
                if (response.get("offset") != offset or type(response.get("offset")) is not int or
                        response.get("count") != count or type(response.get("count")) is not int or
                        not isinstance(encoded, str) or len(encoded) > 4 * ((count + 2) // 3)):
                    raise Error("invalid_chunk")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error):
                    raise Error("invalid_chunk") from None
                if len(raw) != count:
                    raise Error("invalid_chunk")
                current = partial.append(offset, raw, response.get("chunk_sha256"))
                offset = current["verified_offset"]
            self._phase("VERIFYING")
            HostContent(self.journal).prepare_pull()
            await self._finish("prepare", {})
            self._save(source_stability="stable_at_required_check")
        published = HostPublication(self.journal).publish()
        self._evidence("publication_receipt", published["publication_receipt"])
        self._phase("PUBLISHED")

    def _verify_released(self, status):
        data = self._data()
        terminal = status.get("terminal")
        prefix = "DEST" if self.request.document["direction"] == "push" else "SOURCE"
        cleanup = {"temporary_files_removed": True, "workers_stopped": True}
        worker = status.get("worker")
        if (status.get("local_phase") != prefix + "_RELEASED" or status.get("cleanup") != cleanup or
                status.get("error") is not None or not isinstance(worker, dict) or
                worker.get("stopped") is not True or worker.get("job") != "release" or
                terminal is None or terminal["publication_receipt"] != data["publication_receipt"] or
                terminal["operations"]["release"]["status"] != "DONE" or
                terminal["operations"]["release"]["result"]["cleanup"] != cleanup):
            raise Error("guest_cleanup_unproven")
        if prefix == "DEST":
            proof = status.get("destination_verification")
            expected = {"schema": "velo.transfer.destination-verification.v1", "binding": data["binding"],
                        "release_operation_id": terminal["operations"]["release"]["operation_id"],
                        "publication_receipt_sha256": receipt_digest(data["publication_receipt"]),
                        "directory_identity": data["publication_receipt"]["directory_identity"],
                        "manifest_sha256": data["binding"]["manifest_sha256"],
                        "release_worker_nonce": worker.get("nonce"), "verification_phase": "post_cleanup"}
            if not isinstance(proof, dict) or set(proof) != set(expected) | {"parent_identity"}:
                raise Error("destination_verification_invalid")
            if not _same({k: proof[k] for k in expected}, expected):
                raise Error("destination_verification_invalid")
            parent = proof["parent_identity"]
            if (not isinstance(parent, dict) or set(parent) != {"device", "inode"} or
                    any(type(v) is not int or v < 0 for v in parent.values())):
                raise Error("destination_verification_invalid")
        else:
            proof = HostPublication(self.journal).verify_published()
        self._evidence("guest_cleanup", status)
        self._evidence("destination_verification", proof)
        self._save(destination_verified=True, guest_cleanup_complete=True)

    async def _connected(self, adapter, *, abort):
        self.adapter = adapter
        data = self._data()
        if data["begin_attempted"] and data["channel"] != adapter.channel:
            raise Error("channel_changed")
        peer = {k: adapter.observations.get(k) for k in ("vm_uuid", "boot_identity", "policy_id", "build", "protocol_version")}
        expected = self.request.document["expected_vm_identity"]
        if (peer["vm_uuid"] != expected["vm_uuid"] or peer["boot_identity"] != expected["boot_identity"] or
                peer["protocol_version"] != PROTOCOL_VERSION or
                not all(isinstance(v, str) and v for v in peer.values())):
            raise Error("vm_identity_mismatch")
        if data.get("peer") is not None and not _same(data["peer"], peer):
            raise Error("guest_identity_changed")
        self._save(channel=adapter.channel, peer=peer,
                   fallback_reason=data.get("fallback_reason") or adapter.fallback_reason)
        self._evidence("peer", {**peer, "channel": adapter.channel})
        data = self._data()
        if abort:
            if data["begin_attempted"]:
                await self._status()
                await self._call("transfer_abort", self._identity_args())
                await self._status()
            self._phase("CANCELLED")
            return "incomplete", "transfer_cancelled"
        if data.get("guest_request") is None:
            if self.request.document["direction"] == "push":
                prepared = HostContent(self.journal).prepare_push()
                descriptor = {"endpoint": "guest", "identity": {k: peer[k] for k in ("vm_uuid", "boot_identity", "policy_id")},
                              "canonical_path": self.request.document["destination_directory"]}
                guest = make_guest_request(self.request, descriptor, prepared["package"])
            else:
                descriptor = {"endpoint": "host", "identity": self.journal.binding["host_identity"],
                              "canonical_path": self.request.document["destination_directory"]}
                guest = make_guest_request(self.request, descriptor)
            self._save(guest_request=guest)
        status = await self._ready(await self._begin())
        self._phase("READY")
        if self.request.document["direction"] == "push":
            await self._push(status)
        else:
            await self._pull(status)
        data = self._data()
        self._phase("CLEANING")
        status = await self._finish("release", {"prepare_receipt": data["prepare_receipt"],
                                                "publication_receipt": data["publication_receipt"]})
        self._verify_released(status)
        self._save(host_cleanup_complete=False)
        try:
            HostCleanup(self.journal).clean()
        except (Error, OSError) as exc:
            code = exc.code if isinstance(exc, Error) else "host_cleanup_io_failed"
            if code.startswith(("storage_", "state_", "journal_")) or code == "stale_revision":
                raise
            current = self._data()
            self._evidence("host_cleanup_failure", {"code": code,
                "intent": current.get("host_cleanup_intent"),
                "registered_push": current.get("host_push"),
                "registered_pull": current.get("receive_partial"),
                "registered_stage": current.get("staging")})
            return "cleanup_pending", code
        if self.request.document["direction"] == "pull":
            final_proof = HostPublication(self.journal).verify_published()
            self._evidence("destination_verification", final_proof)
            self._save(destination_verified=True)
        self._check()
        return "complete", None

    def _result(self, outcome, code):
        data = self._data()
        guest = data.get("guest_request")
        package = data.get("package")
        manifest = self.journal.read_evidence(data["manifest_ref"]) if data.get("manifest_ref") else None
        files = []
        if manifest is not None:
            for entry in manifest["entries"]:
                if entry["type"] != "file":
                    continue
                relative = entry["path"]
                source = next((s for s in self.request.document["sources"] if relative == s["relative_path"] or
                               relative.startswith(s["relative_path"] + "/")), None)
                if source is None:
                    raise Error("manifest_source_conflict")
                suffix = relative[len(source["relative_path"]):].lstrip("/")
                source_path = (PureWindowsPath(source["absolute_path"]) if self.request.document["direction"] == "pull"
                               else Path(source["absolute_path"]))
                if suffix:
                    source_path = source_path.joinpath(*suffix.split("/"))
                destination = (PureWindowsPath(self.request.document["destination_directory"])
                               if self.request.document["direction"] == "push" else Path(self.request.document["destination_directory"]))
                files.append({"source": str(source_path), "relative_path": relative,
                              "destination": str(destination.joinpath(*relative.split("/"))),
                              "size": entry["size"], "sha256": entry["sha256"]})
        receipt = data.get("publication_receipt")
        published = True if data["published_ever"] else (None if data.get("publication_unknown") else False)
        document = {"schema": "velo.transfer.result.v1", "outcome": outcome,
                    "transfer_id": self.request.transfer_id, "request_digest": guest["request_digest"] if guest else None,
                    "direction": self.request.document["direction"], "channel": data["channel"],
                    "fallback_reason": data.get("fallback_reason"),
                    "source_vm_identity": self.request.document["expected_vm_identity"] if guest and data.get("peer") and self.request.document["direction"] == "pull" else None,
                    "destination_identity": guest["expected_destination"] if guest else None,
                    "package_sha256": package["sha256"] if package else None, "package_size": package["size"] if package else None,
                    "manifest_sha256": package["manifest_sha256"] if package else None,
                    "resumed_bytes": data.get("resumed_bytes", 0), "files": files,
                    "source_stability": data.get("source_stability", "unknown"),
                    "phase": "COMPLETE" if outcome == "complete" else data["phase"],
                    "last_phase": "CLEANING" if outcome == "complete" else data.get("last_phase"), "published_ever": published,
                    "destination_verified": data.get("destination_verified"),
                    "cleanup": {"host": data.get("host_cleanup_complete", False), "guest": data.get("guest_cleanup_complete")},
                    "publication_receipt_sha256": receipt_digest(receipt) if receipt else None,
                    "warnings": [code] if code else [],
                    "evidence_index": [{"role": role, "reference": ref} for role, ref in data.get("evidence", {}).items()]}
        limits = {k: self.request.guest_budget[k] for k in ("max_files", "max_metadata_bytes")}
        validate_result(document, **limits)
        ref = self.journal.write_evidence("result-" + digest_json(document)[:32], document)
        updates = {"result_ref": ref}
        if outcome == "complete":
            # Durable, validated result and all four evidence roles precede the
            # only global COMPLETE publication in the journal.
            if (data.get("destination_verified") is not True or data.get("guest_cleanup_complete") is not True or
                    data.get("host_cleanup_complete") is not True or data.get("adapter_cleanup_pending")):
                raise Error("completion_unproven")
            updates.update(phase="COMPLETE", last_phase="CLEANING", completion={
                "destination_verified": True, "guest_cleanup_complete": True, "host_cleanup_complete": True})
        self._save(**updates)
        return result_summary(document, str(self.journal.task_dir / "evidence" / (ref["name"] + ".json")), **limits)

    async def run(self, *, abort=False):
        with self.journal.writer():
            if self.request.resume:
                envelope = self.journal.load()
                if envelope["data"].get("coordinator_schema") != _SCHEMA:
                    raise Error("coordinator_state_conflict")
            else:
                envelope = self.journal.create(time.monotonic() + self.request.guest_budget["max_duration_seconds"],
                    {"phase": "CREATED", "published_ever": False, "begin_attempted": False, "channel": None,
                     "coordinator_schema": _SCHEMA, "io_sequence": 0})
            self.deadline = envelope["deadline_monotonic"]
            try:
                self._phase("PREPARING")
                self._save(destination_verified=None)
                self._check()
                profile = self.profile_loader(self.request.document["connection_profile"])
                self._save(connection_attempted=True)  # before adapter's read-only probe
                data = self._data()
                async with self.select_adapter(profile, expected_vm_identity=self.request.document["expected_vm_identity"],
                        deadline_monotonic=self.deadline, request_timeout_seconds=self.request.request_timeout_seconds,
                        begun_channel=data["channel"] if data["begin_attempted"] else None) as adapter:
                    outcome, code = await self._connected(adapter, abort=abort)
            except (Error, AdapterError, OSError) as exc:
                code = exc.code if isinstance(exc, (Error, AdapterError)) else "host_io_failed"
                if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
                    code = "transfer_failed"
                # Do not overwrite a corrupt/replaced journal after a storage/CAS error.
                if code.startswith(("storage_", "state_", "journal_")) or code in ("revision_conflict", "stale_revision", "writer_required"):
                    raise
                data = self._data()
                if isinstance(exc, Error) and "published" in exc.context:
                    if exc.context["published"] is True:
                        self._save(published_ever=True)
                    elif exc.context["published"] is None:
                        self._save(publication_unknown=True)
                self._evidence("failure", {"code": code, "phase": self._data()["phase"], "io_intent": self._data().get("io_intent")})
                data = self._data()
                if data["published_ever"] and code.startswith(("destination_", "tree_", "published_destination_")):
                    self._save(destination_verified=False)
                if code == "source_changed":
                    self._save(source_stability="changed_before_required_check")
                if (any(word in code for word in _CONFLICTS) or code == "destination_exists" or
                        self._data().get("destination_verified") is False):
                    outcome = "conflict"
                    self._phase("CONFLICT")
                elif data.get("publication_receipt") is not None:
                    if data.get("host_cleanup_complete") is True and data.get("guest_cleanup_complete") is True:
                        outcome = "incomplete"
                        self._phase("FAILED")
                    else:
                        outcome = "cleanup_pending"
                        self._phase("CLEANING")
                elif not data["begin_attempted"]:
                    outcome = "rejected"
                    self._phase("FAILED")
                else:
                    outcome = "incomplete"
            return self._result(outcome, code)


async def transfer(request: HostRequest, *, abort=False):
    """Start/resume/abort one parsed request; return only a durable small summary."""
    return await TransferCoordinator(request).run(abort=abort)

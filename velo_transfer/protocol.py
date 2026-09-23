"""Pure terminal-protocol rules. Callers must persist before acknowledging actions.

No filesystem claim is established here: local verification, durable writes, locks,
worker ownership and host global COMPLETE remain coordinator responsibilities.
"""

from __future__ import annotations

import copy
import re
import uuid

from .errors import TransferContentError as Error
from .manifest import canonical_json, digest_json

PROTOCOL_VERSION = "velo.transfer.v1"
BINDING_FIELDS = frozenset(("protocol_version", "transfer_id", "request_digest", "direction",
                            "vm_uuid", "boot_identity", "vm_epoch", "policy_id",
                            "package_size", "package_sha256", "manifest_sha256"))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _object(value, keys, code="invalid_receipt"):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Error(code)


def _text(value, limit=4096):
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise Error("invalid_protocol_value")


def _digest(value):
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise Error("invalid_digest")


def validate_binding(binding):
    """Complete K only; pending pull package metadata cannot enter this layer."""
    _object(binding, BINDING_FIELDS, "invalid_binding")
    if binding["protocol_version"] != PROTOCOL_VERSION or binding["direction"] not in ("push", "pull"):
        raise Error("invalid_binding")
    if not isinstance(binding["transfer_id"], str) or not _ID.fullmatch(binding["transfer_id"]):
        raise Error("invalid_binding")
    for field in ("vm_uuid", "boot_identity", "vm_epoch", "policy_id"):
        _text(binding[field], 256)
    if type(binding["package_size"]) is not int or binding["package_size"] < 0:
        raise Error("invalid_binding")
    for field in ("request_digest", "package_sha256", "manifest_sha256"):
        _digest(binding[field])
    return copy.deepcopy(binding)


def validate_destination(destination, direction):
    """Validate the registered descriptor, without dereferencing remote paths."""
    _object(destination, ("endpoint", "identity", "canonical_path"), "invalid_destination")
    if destination["endpoint"] != ("host" if direction == "pull" else "guest"):
        raise Error("invalid_destination")
    _text(destination["canonical_path"], 32767)
    identity = destination["identity"]
    if not isinstance(identity, dict) or not identity or len(identity) > 16:
        raise Error("invalid_destination")
    for key, value in identity.items():
        _text(key, 128)
        _text(value, 256)
    return copy.deepcopy(destination)


def _directory_identity(value):
    _object(value, ("device", "inode"), "invalid_directory_identity")
    if any(type(number) is not int or number < 0 for number in value.values()):
        raise Error("invalid_directory_identity")


def _identifier(value):
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise Error("invalid_receipt_id")


def receipt_digest(receipt):
    # Public hashing does not assert validity; consumers validate before trusting.
    return digest_json(receipt)


def prepare_receipt(binding, identity_digest, prepare_id=None):
    validate_binding(binding)
    _digest(identity_digest)
    result = {"type": "prepare", "binding": copy.deepcopy(binding),
              "prepare_id": prepare_id if prepare_id is not None else uuid.uuid4().hex,
              "identity_digest": identity_digest, "prepared": True}
    validate_prepare(result, binding)
    return result


def validate_prepare(receipt, binding):
    validate_binding(binding)
    _object(receipt, ("type", "binding", "prepare_id", "identity_digest", "prepared"))
    validate_binding(receipt["binding"])
    if receipt["type"] != "prepare" or receipt["binding"] != binding or receipt["prepared"] is not True:
        raise Error("receipt_binding_mismatch")
    _identifier(receipt["prepare_id"])
    _digest(receipt["identity_digest"])


def source_validation_receipt(binding, prepare, identity_digest):
    validate_prepare(prepare, binding)
    if binding["direction"] != "push":
        raise Error("action_not_allowed")
    _digest(identity_digest)
    return {"type": "source_validation", "binding": copy.deepcopy(binding),
            "prepare_receipt_sha256": receipt_digest(prepare), "identity_digest": identity_digest}


def validate_source_validation(receipt, binding, prepare):
    validate_prepare(prepare, binding)
    _object(receipt, ("type", "binding", "prepare_receipt_sha256", "identity_digest"))
    validate_binding(receipt["binding"])
    if (binding["direction"] != "push" or receipt["type"] != "source_validation" or
            receipt["binding"] != binding or receipt["prepare_receipt_sha256"] != receipt_digest(prepare)):
        raise Error("receipt_binding_mismatch")
    _digest(receipt["identity_digest"])


def publication_receipt(binding, prepare, destination, directory_identity, publication_id=None):
    validate_prepare(prepare, binding)
    validate_destination(destination, binding["direction"])
    _directory_identity(directory_identity)
    result = {"type": "publication", "binding": copy.deepcopy(binding),
              "prepare_receipt_sha256": receipt_digest(prepare),
              "destination": copy.deepcopy(destination), "manifest_sha256": binding["manifest_sha256"],
              "directory_identity": copy.deepcopy(directory_identity),
              "publication_id": publication_id if publication_id is not None else uuid.uuid4().hex}
    validate_publication(result, binding, prepare, destination)
    return result


def validate_publication(receipt, binding, prepare, destination):
    validate_prepare(prepare, binding)
    validate_destination(destination, binding["direction"])
    _object(receipt, ("type", "binding", "prepare_receipt_sha256", "destination",
                      "manifest_sha256", "directory_identity", "publication_id"))
    validate_binding(receipt["binding"])
    validate_destination(receipt["destination"], binding["direction"])
    if (receipt["type"] != "publication" or receipt["binding"] != binding or
            receipt["prepare_receipt_sha256"] != receipt_digest(prepare) or
            receipt["destination"] != destination or receipt["manifest_sha256"] != binding["manifest_sha256"]):
        raise Error("receipt_binding_mismatch")
    _directory_identity(receipt["directory_identity"])
    _identifier(receipt["publication_id"])


def publish_intent(binding, prepare, destination, staging_identity, parent_identity,
                   publication_id=None):
    """Persist this before rename; recover only using actual identity AND content."""
    publication = publication_receipt(binding, prepare, destination, staging_identity, publication_id)
    _directory_identity(parent_identity)
    return {"type": "publish_intent", "publication": publication,
            "parent_identity": copy.deepcopy(parent_identity)}


def recover_publication(intent, binding, prepare, destination, *, verified_identity,
                        verified_parent_identity, verified_manifest_sha256):
    """Called only after real local tree verification, never on directory existence."""
    _object(intent, ("type", "publication", "parent_identity"), "invalid_publish_intent")
    validate_publication(intent["publication"], binding, prepare, destination)
    _directory_identity(intent["parent_identity"])
    _directory_identity(verified_identity)
    _directory_identity(verified_parent_identity)
    if (intent["type"] != "publish_intent" or
            intent["publication"]["directory_identity"] != verified_identity or
            intent["parent_identity"] != verified_parent_identity or
            binding["manifest_sha256"] != verified_manifest_sha256):
        raise Error("publication_recovery_conflict")
    return copy.deepcopy(intent["publication"])


class GuestTerminal:
    """Small replayable guest state machine, starting after fixed package transfer.

    Mutations are only in memory. The owner MUST serialize snapshot() atomically
    before replying or performing the authorized next side effect. begin_action
    has no side effects and no implied completion. A worker calls the completion
    method only after the documented local checks. Do not expose those methods
    as public MCP actions. Load snapshots only from protected, validated storage.
    """

    def __init__(self, binding, destination):
        self.binding = validate_binding(binding)
        self.destination = validate_destination(destination, binding["direction"])
        self.prefix = "SOURCE" if binding["direction"] == "pull" else "DEST"
        self.local_phase = "SOURCE_READY" if self.prefix == "SOURCE" else "DEST_RECEIVED"
        self.prepare = None
        self.publication = None
        self.release_authorization = None
        self.operations = {}

    def snapshot(self):
        return copy.deepcopy({"schema": "velo.transfer.guest_terminal.v1", "binding": self.binding,
                              "destination": self.destination, "local_phase": self.local_phase,
                              "prepare_receipt": self.prepare, "publication_receipt": self.publication,
                              "release_authorization": self.release_authorization,
                              "operations": self.operations})

    def _inputs(self, action, inputs):
        # Validate even terminal retries before consulting operation replay data.
        if action == "prepare":
            _object(inputs, (), "invalid_action_input")
        elif action == "commit":
            if self.binding["direction"] != "push":
                raise Error("action_not_allowed")
            _object(inputs, ("prepare_receipt", "source_validation_receipt"), "invalid_action_input")
            validate_prepare(inputs["prepare_receipt"], self.binding)
            if inputs["prepare_receipt"] != self.prepare:
                raise Error("receipt_binding_mismatch")
            validate_source_validation(inputs["source_validation_receipt"], self.binding, self.prepare)
        elif action == "release":
            _object(inputs, ("prepare_receipt", "publication_receipt"), "invalid_action_input")
            validate_prepare(inputs["prepare_receipt"], self.binding)
            if inputs["prepare_receipt"] != self.prepare:
                raise Error("receipt_binding_mismatch")
            validate_publication(inputs["publication_receipt"], self.binding, self.prepare, self.destination)
            if self.binding["direction"] == "push" and inputs["publication_receipt"] != self.publication:
                raise Error("receipt_binding_mismatch")
        else:
            raise Error("action_not_allowed")

    def begin_action(self, action, **inputs):
        self._inputs(action, inputs)
        key = digest_json({"binding": self.binding, "action": action, "inputs": inputs})
        if action in self.operations:
            previous = self.operations[action]
            if previous["input_digest"] != key:
                raise Error("action_conflict")
            return copy.deepcopy(previous)
        expected = {"prepare": "SOURCE_READY" if self.prefix == "SOURCE" else "DEST_RECEIVED",
                    "commit": "DEST_PREPARED",
                    "release": self.prefix + ("_PREPARED" if self.prefix == "SOURCE" else "_PUBLISHED")}
        if self.local_phase != expected[action] or any(op["status"] == "IN_PROGRESS" for op in self.operations.values()):
            raise Error("action_precondition_failed")
        operation = {"operation_id": uuid.uuid4().hex, "input_digest": key,
                     "status": "IN_PROGRESS", "inputs": copy.deepcopy(inputs), "result": None}
        self.operations[action] = operation
        return copy.deepcopy(operation)

    def _pending(self, action, operation_id):
        operation = self.operations.get(action)
        if operation is None or operation["operation_id"] != operation_id or operation["status"] != "IN_PROGRESS":
            raise Error("operation_mismatch")
        return operation

    def _complete(self, action, operation_id, result):
        operation = self._pending(action, operation_id)
        operation["result"] = copy.deepcopy(result)
        operation["status"] = "DONE"

    def complete_prepare(self, operation_id, receipt):
        """After local source/package or destination-stage checks; persist before reply."""
        self._pending("prepare", operation_id)
        validate_prepare(receipt, self.binding)
        self.prepare = copy.deepcopy(receipt)
        self.local_phase = self.prefix + "_PREPARED"
        self._complete("prepare", operation_id, {"prepare_receipt": receipt})

    def complete_commit(self, operation_id, receipt):
        """Push only, after durable intent, real rename, reverify and receipt write."""
        self._pending("commit", operation_id)
        if self.binding["direction"] != "push":
            raise Error("action_not_allowed")
        validate_publication(receipt, self.binding, self.prepare, self.destination)
        self.publication = copy.deepcopy(receipt)
        self.local_phase = "DEST_PUBLISHED"
        self._complete("commit", operation_id, {"publication_receipt": receipt})

    def authorize_release(self, operation_id):
        """After fresh local checks, persist returned snapshot BEFORE deleting temp.

        Replaying an already persisted authorization continues the same cleanup;
        do not repeat source validation against a newer source version then.
        """
        operation = self._pending("release", operation_id)
        if self.release_authorization is None:
            receipt = operation["inputs"]["publication_receipt"]
            self.publication = copy.deepcopy(receipt)
            self.release_authorization = {"operation_id": operation_id,
                                          "publication_receipt_sha256": receipt_digest(receipt)}
            self.local_phase = self.prefix + "_RELEASING"
        return copy.deepcopy(self.release_authorization)

    def complete_release(self, operation_id, cleanup):
        """After owned temp/worker cleanup; tombstone must remain durable."""
        self._pending("release", operation_id)
        if self.release_authorization is None or self.release_authorization["operation_id"] != operation_id:
            raise Error("release_not_authorized")
        _object(cleanup, ("temporary_files_removed", "workers_stopped"), "invalid_cleanup")
        if any(value is not True for value in cleanup.values()):
            raise Error("cleanup_incomplete")
        self.local_phase = self.prefix + "_RELEASED"
        self._complete("release", operation_id, {"publication_receipt": self.publication,
                                                "cleanup": cleanup})

    def fail_action(self, action, operation_id, code):
        """Persist a failed action; it cannot subsequently be completed or reused."""
        operation = self._pending(action, operation_id)
        _identifier(code)
        if self.release_authorization is not None:
            # Accepted release is irreversible; cleanup faults remain recoverable.
            raise Error("release_already_authorized")
        operation["status"] = "FAILED"
        operation["result"] = {"error": code}
        self.local_phase = "SOURCE_CHANGED" if self.prefix == "SOURCE" and code == "source_changed" else self.prefix + "_FAILED"

    def status(self):
        result = self.snapshot()
        result["state_scope"] = "guest_source" if self.prefix == "SOURCE" else "guest_destination"
        result["publication_evidence"] = ("host_reported_publication" if self.prefix == "SOURCE"
                                          else "guest_verified_destination") if self.publication else None
        return result

    @classmethod
    def restore(cls, snapshot, binding, destination):
        """Replay persisted history and demand exact equality, rejecting partial claims."""
        _object(snapshot, ("schema", "binding", "destination", "local_phase", "prepare_receipt",
                           "publication_receipt", "release_authorization", "operations"), "invalid_terminal_snapshot")
        state = cls(binding, destination)
        if (snapshot["schema"] != "velo.transfer.guest_terminal.v1" or snapshot["binding"] != binding or
                snapshot["destination"] != destination or not isinstance(snapshot["operations"], dict) or
                not set(snapshot["operations"]).issubset({"prepare", "commit", "release"})):
            raise Error("invalid_terminal_snapshot")
        for action in ("prepare", "commit", "release"):
            if action not in snapshot["operations"]:
                continue
            saved = snapshot["operations"][action]
            _object(saved, ("operation_id", "input_digest", "status", "inputs", "result"), "invalid_terminal_snapshot")
            _identifier(saved["operation_id"])
            if not isinstance(saved["inputs"], dict):
                raise Error("invalid_terminal_snapshot")
            started = state.begin_action(action, **saved["inputs"])
            if started["input_digest"] != saved["input_digest"]:
                raise Error("invalid_terminal_snapshot")
            state.operations[action]["operation_id"] = saved["operation_id"]
            op = saved["operation_id"]
            if saved["status"] == "FAILED":
                _object(saved["result"], ("error",), "invalid_terminal_snapshot")
                state.fail_action(action, op, saved["result"]["error"])
            elif saved["status"] == "DONE":
                if action == "prepare":
                    _object(saved["result"], ("prepare_receipt",), "invalid_terminal_snapshot")
                    state.complete_prepare(op, saved["result"]["prepare_receipt"])
                elif action == "commit":
                    _object(saved["result"], ("publication_receipt",), "invalid_terminal_snapshot")
                    state.complete_commit(op, saved["result"]["publication_receipt"])
                else:
                    _object(saved["result"], ("publication_receipt", "cleanup"), "invalid_terminal_snapshot")
                    state.authorize_release(op)
                    state.complete_release(op, saved["result"]["cleanup"])
            elif saved["status"] == "IN_PROGRESS":
                if action == "release" and snapshot["release_authorization"] is not None:
                    state.authorize_release(op)
            else:
                raise Error("invalid_terminal_snapshot")
        if canonical_json(state.snapshot()) != canonical_json(snapshot):
            raise Error("invalid_terminal_snapshot")
        return state

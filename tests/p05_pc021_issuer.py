"""PC021/PC022 activation issuer and private one-shot completion capability.

Implements the P05 v19 0.PC021.2.2 five-step issuer and the 0.PC021.2.5
capability as a production operation on the audited Windows path:

1. verify the approved plain directory layout, prove R/S absent, read and
   verify C7, freeze the root inputs minus ``issued_at``, and run the full
   private pre-issue predicate over preparation/migration/creation, the
   three complete phase graphs, and every frozen source;
2. record PRE_ISSUE_GRAPH_VALIDATED, then take one actual issuer UTC sample
   shared by event 2 and the root ``issued_at``;
3. exclusive-create R with real writes, flush/fsync/close, and the PC022
   native parent refresh, recording events 3-5 at their action boundaries,
   then read R back byte-for-byte and re-run the immutable-root verifier
   (event 6);
4. build the v2 receipt from the six events, persist and natively refresh
   it, read it back, and run the public complete-bundle verifier;
5. only then mint the private one-shot capability in the same controller.

Every failure preserves R/S in place, mints nothing, and never retries,
re-signs, overwrites, or falls back.  A complete parseable receipt never
proves a past operation succeeded.
"""

from __future__ import annotations

import copy
import hashlib
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import pc022_windows_refresh as refresh
from tests import p05_pc021_readback as readback


ISSUANCE_OPERATION = "P05_ACTIVATION_ISSUE"
EVENT_ORDER = graph.EVENT_ORDER


class IssuerError(RuntimeError):
    """Issuance refused or failed; the scene is preserved in place."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(f"{stage}: {message}")
        self.stage = stage


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, eq=False, init=False)
class IssuanceCapability:
    """Controller-private, non-serializable one-shot completion capability.

    The six fields describe bindings, not authority. Authority and lifecycle
    live in this controller's private identity registry, populated only after
    successful issuance. Losing the object/controller loses that authority.
    This is a trusted Python controller boundary, not a sandbox against code
    that mutates module internals or uses arbitrary reflection/monkeypatching.
    """

    operation: str
    workflow_id: str
    issuance_id: str
    epoch7_sha256: str
    activation_root_sha256: str
    issuance_receipt_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError("IssuanceCapability is minted only by successful issuance")

    def __reduce__(self):  # pragma: no cover - guard by design
        raise TypeError("IssuanceCapability cannot be serialized or rebuilt")

    def __deepcopy__(self, memo):  # pragma: no cover - guard by design
        raise TypeError("IssuanceCapability cannot be copied")

    def __copy__(self):
        raise TypeError("IssuanceCapability cannot be copied")

    @property
    def spent(self) -> bool:
        with _registry_lock:
            return _lookup_capability(self).spent

    def spend(self) -> None:
        """Discard authority once; this does not admit or authorize a writer."""
        _consume_for_writer(self, lambda: None)


_BINDING_FIELDS = (
    "operation", "workflow_id", "issuance_id", "epoch7_sha256",
    "activation_root_sha256", "issuance_receipt_sha256",
)


@dataclass
class _CapabilityState:
    bindings: tuple[str, ...]
    lock: threading.Lock
    spent: bool = False


_registry_lock = threading.Lock()
_minted: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _capability_state(capability: IssuanceCapability) -> _CapabilityState:
    with _registry_lock:
        return _lookup_capability(capability)


def _lookup_capability(capability: IssuanceCapability) -> _CapabilityState:
    """Caller holds the controller lock, including for type/origin checks."""
    # Identity, not equal public fields or a caller-controlled token/boolean.
    if type(capability) is not IssuanceCapability:
        raise IssuerError("capability", "writer admits only the private issuance capability")
    state = _minted.get(capability)
    if state is None:
        raise IssuerError("capability", "capability was not minted by this controller")
    return state


def _consume_for_writer(capability: IssuanceCapability, verify: Callable[[], Any]) -> Any:
    """Controller-internal admission: all writer reads/checks run under lock.

    Failed validation leaves authority unspent. Successful validation consumes
    before returning, including when the next file action will fail. This is
    process-local exclusion; the writer still rechecks canonical before replace.
    """
    with _registry_lock:
        state = _lookup_capability(capability)
        if state.spent:
            raise IssuerError("capability", "capability already spent")
        if tuple(getattr(capability, name) for name in _BINDING_FIELDS) != state.bindings:
            raise IssuerError("capability", "capability bindings differ from issuance")
        if capability.operation != ISSUANCE_OPERATION or capability.workflow_id != evidence.WORKFLOW_ID:
            raise IssuerError("capability", "capability operation/workflow differs")
        verified = verify()
        state.spent = True
        return verified


@dataclass(frozen=True)
class IssuanceOutcome:
    root_path: Path
    receipt_path: Path
    issued_at: str
    events: tuple[dict[str, Any], ...]
    capability: IssuanceCapability


def _plain_ancestry(directory: Path, label: str) -> None:
    current = directory
    while True:
        info = current.lstat()
        import stat as stat_module

        if (
            not stat_module.S_ISDIR(info.st_mode)
            or stat_module.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise IssuerError("layout", f"{label} traverses a non-directory or reparse at {current.name}")
        if current.parent == current:
            return
        current = current.parent


def _create_durable_file(path: Path, payload: bytes) -> None:
    import os

    with path.open("xb") as stream:
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            count = stream.write(view[written:])
            if count is None or count <= 0:
                raise IssuerError("write", f"short write for {path.name}")
            written += count
        stream.flush()
        os.fsync(stream.fileno())
    refresh.windows_refresh_directory(path.parent)


def issue_activation(
    activation_dir: Path,
    *,
    root_draft: dict[str, Any],
    policy: evidence.FrozenSourcePolicy,
    root_policy: evidence.FrozenSourcePolicy,
    epoch7_canonical: bytes,
) -> IssuanceOutcome:
    """Run the full five-step issuance in this controller.

    ``root_draft`` carries every root field except ``issued_at``; the draft
    Refs are verified against the on-disk scene before anything is written.
    """
    if set(root_draft) != graph.ROOT_KEYS - {"issued_at"}:
        raise IssuerError("draft", "root draft keys differ (issued_at must be absent)")
    if not activation_dir.is_absolute():
        raise IssuerError("draft", "activation directory must be absolute")
    root_path = activation_dir / "activation-evidence.json"
    receipt_path = activation_dir / "issuance-receipt.json"
    _plain_ancestry(activation_dir, "activation directory")
    if root_path.exists() or root_path.is_symlink():
        raise IssuerError("layout", "activation root already exists")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise IssuerError("layout", "issuance receipt already exists")

    readback._native()  # Fail closed off Windows before creating any issuer output.
    document = json_deep_copy(root_draft)
    events: list[dict[str, Any]] = []

    # Step 1: frozen inputs + full private pre-issue predicate.
    graph._verify_preissue(root_path, document, policy=policy,
                           epoch7_canonical=epoch7_canonical, root_policy=root_policy)
    cycles = document["candidate_cycles"]

    # Step 2: event 1, then exactly one UTC sample shared by event 2 and root.
    events.append({"sequence": 1, "event": EVENT_ORDER[0], "at": _utc_now()})
    issued_at = _utc_now()
    events.append({"sequence": 2, "event": EVENT_ORDER[1], "at": issued_at})
    document["issued_at"] = issued_at

    # Step 3: exclusive-create R with native durability and staged events.
    root_payload = evidence.canonical_json(document)
    _create_durable_file_events(root_path, root_payload, events)
    read_back = readback._read_no_follow(root_path)
    if read_back != root_payload:
        raise IssuerError("readback", "activation root readback differs")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise IssuerError("readback", "receipt appeared before root validation")
    graph._verify_immutable_root(root_path, read_back, policy=policy,
                                 epoch7_canonical=epoch7_canonical, root_policy=root_policy)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise IssuerError("readback", "receipt appeared during root validation")
    events.append({"sequence": 6, "event": EVENT_ORDER[5], "at": _utc_now()})

    # Step 4: v2 receipt persisted, refreshed, read back, public verifier.
    receipt = {
        "schema_version": 2, "kind": graph.RECEIPT_KIND,
        "workflow_id": evidence.WORKFLOW_ID, "issuance_id": activation_dir.name,
        "operation": ISSUANCE_OPERATION,
        "source": {
            "source_inputs_sha256": _sha(evidence.canonical_json(document["source_inputs"])),
            "implementation_sources_sha256": _sha(evidence.canonical_json(document["implementation_sources"])),
        },
        "epoch7": {
            "canonical_sha256": _sha(epoch7_canonical), "schema_version": 6,
            "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": evidence.SNAPSHOT_187,
        },
        "cycle2": {
            "restore_attempt_id": cycles[1]["restore_attempt_id"], "run_id": cycles[1]["run_id"],
            "report": copy.deepcopy(cycles[1]["report"]),
            "package_manifest": copy.deepcopy(cycles[1]["package_manifest"]),
        },
        "activation_root": {
            "path": "activation-evidence.json",
            "size": len(root_payload), "sha256": _sha(root_payload),
        },
        "issued_at": issued_at, "events": list(events),
        "status": "ROOT_VALIDATED", "error": None,
    }
    if set(receipt) != graph.RECEIPT_KEYS:
        raise IssuerError("receipt", "receipt key construction differs")
    receipt_payload = evidence.canonical_json(receipt)
    _create_durable_file(receipt_path, receipt_payload)
    if readback._read_no_follow(receipt_path) != receipt_payload:
        raise IssuerError("readback", "issuance receipt readback differs")
    graph.verify_snapshot189_activation(
        root_path, policy=policy, epoch7_canonical=epoch7_canonical, root_policy=root_policy,
    )

    # Step 5: mint the private capability in this controller only.
    # No callable constructor/mint helper accepts these six public values.
    # Authority is registered only at this successful controller boundary.
    capability = object.__new__(IssuanceCapability)
    values = (
        ISSUANCE_OPERATION, evidence.WORKFLOW_ID, activation_dir.name,
        _sha(epoch7_canonical), _sha(root_payload), _sha(receipt_payload),
    )
    for name, value in zip(_BINDING_FIELDS, values):
        object.__setattr__(capability, name, value)
    with _registry_lock:
        _minted[capability] = _CapabilityState(values, _registry_lock)
    return IssuanceOutcome(
        root_path=root_path,
        receipt_path=receipt_path,
        issued_at=issued_at,
        events=tuple(events),
        capability=capability,
    )


def _create_durable_file_events(path: Path, payload: bytes, events: list[dict[str, Any]]) -> None:
    """Persist one file while recording events 3-5 at their boundaries."""
    import os

    with path.open("xb") as stream:
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            count = stream.write(view[written:])
            if count is None or count <= 0:
                raise IssuerError("write", f"short write for {path.name}")
            written += count
        events.append({"sequence": 3, "event": EVENT_ORDER[2], "at": _utc_now()})
        stream.flush()
        os.fsync(stream.fileno())
    events.append({"sequence": 4, "event": EVENT_ORDER[3], "at": _utc_now()})
    refresh.windows_refresh_directory(path.parent)
    events.append({"sequence": 5, "event": EVENT_ORDER[4], "at": _utc_now()})


def json_deep_copy(value: Any) -> Any:
    return copy.deepcopy(value)

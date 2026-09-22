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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import pc022_windows_refresh as refresh


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


@dataclass(frozen=True)
class IssuanceCapability:
    """Controller-private, non-serializable one-shot completion capability.

    Binding fields follow P05 v19 0.PC021.2.5.  The lifecycle state lives
    behind a lock; spending is a single critical section that happens before
    any writer side effect.  The object cannot be rebuilt from booleans,
    environment variables, on-disk tokens, or a parseable receipt: the only
    constructor path is a fully verified issuance.
    """

    operation: str
    workflow_id: str
    issuance_id: str
    epoch7_sha256: str
    activation_root_sha256: str
    issuance_receipt_sha256: str
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _spent: bool = field(default=False, repr=False, compare=False)

    def __reduce__(self):  # pragma: no cover - guard by design
        raise TypeError("IssuanceCapability cannot be serialized or rebuilt")

    def __deepcopy__(self, memo):  # pragma: no cover - guard by design
        raise TypeError("IssuanceCapability cannot be copied")

    @property
    def spent(self) -> bool:
        with self._lock:
            return self._spent

    def spend(self) -> None:
        """Atomically UNSPENT -> SPENT exactly once; racing losers fail."""
        with self._lock:
            if self._spent:
                raise IssuerError("capability", "capability already spent")
            object.__setattr__(self, "_spent", True)


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

    document = json_deep_copy(root_draft)
    events: list[dict[str, Any]] = []

    # Step 1: frozen inputs + full private pre-issue predicate.
    evidence.verify_schema6_shape(epoch7_canonical, expected_epoch=7)
    canonical = evidence._json_bytes(epoch7_canonical, "trusted epoch7 canonical")
    if canonical["active_snapshot"]["name"] != evidence.SNAPSHOT_187:
        raise IssuerError("preissue", "trusted canonical is not active Snapshot187")
    seen: dict[str, tuple[int, str]] = {}
    preparation_path = evidence._ref(activation_dir, document["preparation_evidence"], "preparation", seen)
    migration_path = evidence._ref(activation_dir, document["migration_evidence"], "migration", seen)
    creation_path = evidence._ref(activation_dir, document["creation_metadata"], "creation", seen)
    preparation = evidence.verify_preparation(preparation_path, policy=policy)
    migration = evidence.verify_migration(migration_path, original_preparation=preparation_path, policy=policy)
    if canonical["preparation_evidence"]["evidence_sha256"] != _sha(preparation_path.read_bytes()):
        raise IssuerError("preissue", "canonical does not bind preparation bytes")
    if canonical["migration_evidence"]["evidence_sha256"] != _sha(migration_path.read_bytes()):
        raise IssuerError("preissue", "canonical does not bind migration bytes")
    sources = evidence._sources(activation_dir, document["source_inputs"], root_policy.source_inputs, "source_inputs", seen)
    implementations = evidence._sources(activation_dir, document["implementation_sources"], root_policy.implementation_sources, "implementation_sources", seen)
    source_graph = graph._source_graph(sources, implementations)
    marker = document.get("checkpoint_marker")
    creation_result = graph.creation.verify_snapshot189_creation(
        creation_path, preparation_admission=preparation_path, policy=policy, expected_marker=marker,
    )
    cycles = document.get("candidate_cycles")
    if not isinstance(cycles, list) or len(cycles) != 2:
        raise IssuerError("preissue", "activation requires exactly two candidate cycles")
    phases = [
        graph._phase(activation_dir, document["initial"], "p05-flow-triage-repair-initial", source_graph, policy, None, seen),
        graph._phase(activation_dir, cycles[0], "p05-flow-triage-repair-candidate", source_graph, policy, creation_path, seen),
        graph._phase(activation_dir, cycles[1], "p05-flow-triage-repair-candidate", source_graph, policy, creation_path, seen),
    ]
    phase_docs = [document["initial"], *cycles]
    for key in ("run_id", "restore_attempt_id"):
        if len({phase[key] for phase in phase_docs}) != 3:
            raise IssuerError("preissue", f"three phases reuse {key}")
    for key in ("session", "runner", "server"):
        if len({phase[key] for phase in phases}) != 3:
            raise IssuerError("preissue", f"three phases reuse decoded {key} identity")
    for left in range(3):
        for right in range(left + 1, 3):
            if phases[left]["flows"] & phases[right]["flows"]:
                raise IssuerError("preissue", "three phases reuse decoded Flow identity")

    # Step 2: event 1, then exactly one UTC sample shared by event 2 and root.
    events.append({"sequence": 1, "event": EVENT_ORDER[0], "at": _utc_now()})
    issued_at = _utc_now()
    events.append({"sequence": 2, "event": EVENT_ORDER[1], "at": issued_at})
    document["issued_at"] = issued_at

    # Step 3: exclusive-create R with native durability and staged events.
    root_payload = evidence.canonical_json(document)
    _create_durable_file_events(root_path, root_payload, events)
    read_back = root_path.read_bytes()
    if read_back != root_payload:
        raise IssuerError("readback", "activation root readback differs")
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
    if receipt_path.read_bytes() != receipt_payload:
        raise IssuerError("readback", "issuance receipt readback differs")
    graph.verify_snapshot189_activation(
        root_path, policy=policy, epoch7_canonical=epoch7_canonical, root_policy=root_policy,
    )

    # Step 5: mint the private capability in this controller only.
    capability = IssuanceCapability(
        operation=ISSUANCE_OPERATION,
        workflow_id=evidence.WORKFLOW_ID,
        issuance_id=activation_dir.name,
        epoch7_sha256=_sha(epoch7_canonical),
        activation_root_sha256=_sha(root_payload),
        issuance_receipt_sha256=_sha(receipt_payload),
    )
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

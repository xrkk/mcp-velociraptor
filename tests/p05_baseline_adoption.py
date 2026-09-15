"""Read-only validation for a self-contained Snapshot187 adoption record.

The same verifier is deliberately usable against the byte-for-byte copy carried
inside a P06 restore package.  It never resolves the canonical record's
original host path and never writes, moves, or deletes evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import uuid
from pathlib import Path, PureWindowsPath
from typing import Any

from tests import p05_snapshot_raw as snapshot_raw


class BaselineAdoptionError(ValueError):
    """The adoption package is not a complete, immutable baseline record."""


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
SNAPSHOT_183 = "Snapshot 183-FakenetNG测试专用"
SNAPSHOT_184 = "Snapshot 184-Velociraptor-MCP测试基线"
SNAPSHOT_1 = "Snapshot 1-开启Windows-MCP"
SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
SNAPSHOT_187 = "Snapshot 187-固定IP+WindowsMCP开机自启"
SNAPSHOT_187_MARKER = "Win10MalBox-Velo-Snapshot3.vmsn"
MANUAL_ONLY = "MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION"

ADOPTION_KEYS = {
    "schema_version",
    "kind",
    "workflow_id",
    "adoption_id",
    "vmx",
    "snapshot_name",
    "checkpoint_marker",
    "old_canonical",
    "snapshot_tree",
    "metadata",
    "guest_identity",
    "source_inputs",
}
REF_KEYS = {"path", "size", "sha256"}
SOURCE_KEYS = {"repo_path", "blob", "content"}
LEGACY_STATE_KEYS = {
    "schema_version",
    "workflow_id",
    "epoch",
    "phase",
    "active_snapshot",
    "automatic_restore_allowlist",
    "retired_snapshots",
    "activation_evidence",
}
SNAPSHOT_KEYS = {"name", "checkpoint_marker", "purpose"}
RETIRED_KEYS = {"name", "status"}
ACTIVATION_KEYS = {"source", "evidence_path", "evidence_sha256", "activated_at"}

# P05 §0.8.2 fixes the complete adoption source set.  The copied bytes carry
# their own Git blob identities so a later dirty worktree cannot rewrite it.
ADOPTION_SOURCE_INPUTS = frozenset(
    {
        "PLAN/2026.09.02/2026.09.02-01-需求提炼-mcp-velociraptor全阶段设计.md",
        "PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发.md",
        "PLAN/2026.09.02/2026.09.05-22-实施子方案-P05测试数据与情景基础设施.md",
        "PLAN/2026.09.02/2026.09.05-29-实施子方案-P06逐工具与连续情景全量执行.md",
        "PLAN/2026.09.02/2026.09.12-18-实施子方案-P07清理与终检.md",
        "PLAN/2026.09.02/2026.09.14-01-PLAN-CHANGE-012-用户重置唯一187基线.md",
        "PLAN/2026.09.02/2026.09.14-08-执行授权-宿主与目标虚拟机文件互传.md",
        "PLAN/2026.09.02/2026.09.14-10-方案自评-PLAN-CHANGE-012新基线契约.md",
        "PLAN/2026.09.02/2026.09.14-11-实施自评补充-P05原件解析与Windows首轮纠偏.md",
        "PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行/快照恢复选择器.py",
        "tests/p05_baseline_adoption.py",
        "tests/p05_snapshot_raw.py",
    }
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _plain_relative_file(root: Path, relative: Any, label: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise BaselineAdoptionError(f"{label} must use contained POSIX components")
    candidate = Path(relative)
    if candidate.is_absolute() or PureWindowsPath(relative).drive or ".." in candidate.parts:
        raise BaselineAdoptionError(f"{label} escapes the adoption directory")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise BaselineAdoptionError(f"cannot stat adoption directory: {exc}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise BaselineAdoptionError("adoption directory must be a plain directory")
    current = root
    try:
        for part in candidate.parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise BaselineAdoptionError(f"{label} contains a link or reparse point")
        if not stat.S_ISREG(current.lstat().st_mode):
            raise BaselineAdoptionError(f"{label} is not a regular file")
    except OSError as exc:
        raise BaselineAdoptionError(f"cannot read {label}: {exc}") from exc
    return current


def _resolve_ref(
    root: Path,
    value: Any,
    label: str,
    seen: dict[str, tuple[int, str]],
) -> Path:
    if not isinstance(value, dict) or set(value) != REF_KEYS:
        raise BaselineAdoptionError(f"{label} must have exact path/size/sha256 keys")
    if type(value["size"]) is not int or value["size"] < 0:
        raise BaselineAdoptionError(f"{label}.size is invalid")
    if not _valid_sha256(value["sha256"]):
        raise BaselineAdoptionError(f"{label}.sha256 is invalid")
    path_text = value["path"]
    path = _plain_relative_file(root, path_text, f"{label}.path")
    identity = (value["size"], value["sha256"])
    previous = seen.setdefault(path_text, identity)
    if previous != identity:
        raise BaselineAdoptionError(f"{label} repeats a path with conflicting identity")
    if path.stat().st_size != value["size"] or _sha256(path) != value["sha256"]:
        raise BaselineAdoptionError(f"{label} byte identity differs")
    return path


def _read_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineAdoptionError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise BaselineAdoptionError(f"{label} must be a JSON object")
    return value


def _read_nonempty_text(path: Path, label: str) -> str:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineAdoptionError(f"{label} must be a readable UTF-8 original") from exc
    if not text.strip():
        raise BaselineAdoptionError(f"{label} must not be empty")
    return text


def _verify_old_canonical(payload: bytes) -> None:
    state = _read_json_bytes(payload, "old_canonical")
    if set(state) != LEGACY_STATE_KEYS:
        raise BaselineAdoptionError("old_canonical root keys differ")
    if (
        state.get("schema_version") != 3
        or state.get("workflow_id") != WORKFLOW_ID
        or state.get("epoch") != 4
        or state.get("phase") != "NETWORK_ACTIVE"
    ):
        raise BaselineAdoptionError("old_canonical is not schema3/epoch4 NETWORK_ACTIVE")
    active = state.get("active_snapshot")
    if not isinstance(active, dict) or set(active) != SNAPSHOT_KEYS:
        raise BaselineAdoptionError("old_canonical active snapshot shape differs")
    marker = active.get("checkpoint_marker")
    fresh_marker = isinstance(marker, str) and re.fullmatch(
        r"Win10MalBox-Velo-Snapshot(\d+)\.vmsn", marker
    )
    if (
        active.get("name") != SNAPSHOT_186
        or not isinstance(active.get("purpose"), str)
        or not active["purpose"]
        or fresh_marker is None
        or int(fresh_marker.group(1)) <= 1
    ):
        raise BaselineAdoptionError("old_canonical Snapshot186 identity differs")
    if state.get("automatic_restore_allowlist") != [SNAPSHOT_186]:
        raise BaselineAdoptionError("old_canonical allowlist differs")
    retired = state.get("retired_snapshots")
    expected_retired = [SNAPSHOT_183, SNAPSHOT_184, SNAPSHOT_1]
    if (
        not isinstance(retired, list)
        or [item.get("name") if isinstance(item, dict) else None for item in retired]
        != expected_retired
        or any(
            not isinstance(item, dict)
            or set(item) != RETIRED_KEYS
            or item.get("status") != MANUAL_ONLY
            for item in retired
        )
    ):
        raise BaselineAdoptionError("old_canonical retired snapshots differ")
    evidence = state.get("activation_evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != ACTIVATION_KEYS
        or not all(isinstance(evidence[key], str) and evidence[key] for key in ACTIVATION_KEYS)
        or not _valid_sha256(evidence["evidence_sha256"])
    ):
        raise BaselineAdoptionError("old_canonical activation evidence shape differs")


def _verify_sources(root: Path, value: Any, seen: dict[str, tuple[int, str]]) -> None:
    if not isinstance(value, list) or len(value) != len(ADOPTION_SOURCE_INPUTS):
        raise BaselineAdoptionError("source_inputs does not contain the complete fixed set")
    paths: set[str] = set()
    for index, source in enumerate(value):
        label = f"source_inputs[{index}]"
        if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
            raise BaselineAdoptionError(f"{label} keys differ")
        repo_path = source.get("repo_path")
        if not isinstance(repo_path, str) or repo_path not in ADOPTION_SOURCE_INPUTS:
            raise BaselineAdoptionError(f"{label}.repo_path is outside the fixed source set")
        if repo_path in paths:
            raise BaselineAdoptionError(f"{label}.repo_path is duplicated")
        paths.add(repo_path)
        blob = source.get("blob")
        if not isinstance(blob, str) or len(blob) != 40 or any(
            character not in "0123456789abcdef" for character in blob
        ):
            raise BaselineAdoptionError(f"{label}.blob is not a Git blob id")
        content = _resolve_ref(root, source.get("content"), f"{label}.content", seen)
        if source["content"]["path"] != f"source/{repo_path}":
            raise BaselineAdoptionError(f"{label}.content path differs from repo_path")
        payload = content.read_bytes()
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BaselineAdoptionError(f"{label}.content is not text") from exc
        header = f"blob {len(payload)}\0".encode("ascii")
        if hashlib.sha1(header + payload).hexdigest() != blob:
            raise BaselineAdoptionError(f"{label}.blob does not identify content bytes")
    if paths != ADOPTION_SOURCE_INPUTS:
        raise BaselineAdoptionError(
            f"source_inputs differs from the fixed set: {sorted(ADOPTION_SOURCE_INPUTS - paths)}"
        )


def _adoption_root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.name != "adoption.json":
        raise BaselineAdoptionError("adoption path must be an absolute adoption.json file")
    root = path.parent
    if root.parent.name != "baseline-adoption":
        raise BaselineAdoptionError("adoption path is outside a baseline-adoption UUID directory")
    try:
        directory_id = uuid.UUID(root.name)
    except (ValueError, AttributeError) as exc:
        raise BaselineAdoptionError("adoption directory is not a UUID") from exc
    if str(directory_id) != root.name:
        raise BaselineAdoptionError("adoption directory UUID is not canonical lowercase")
    try:
        root_info = root.lstat()
        parent_info = root.parent.lstat()
        file_info = path.lstat()
    except OSError as exc:
        raise BaselineAdoptionError(f"cannot stat adoption path: {exc}") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISREG(file_info.st_mode)
        or stat.S_ISLNK(file_info.st_mode)
    ):
        raise BaselineAdoptionError("adoption path must not contain a link or special file")
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BaselineAdoptionError("adoption path traverses a link or reparse point")
    return root


def verify_baseline_adoption(
    path: Path,
    expected_old_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate a self-contained adoption record without modifying any input.

    ``expected_old_bytes`` is supplied by the selector only after it has read
    the canonical predecessor itself.  It is intentionally raw bytes rather
    than a caller-provided digest, preventing a CLI value from substituting an
    arbitrary historical canonical state.
    """
    root = _adoption_root(path)
    document = _read_json_bytes(path.read_bytes(), "adoption")
    if set(document) != ADOPTION_KEYS:
        raise BaselineAdoptionError("adoption root keys differ")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "user187-preparation-adoption-v1"
        or document.get("workflow_id") != WORKFLOW_ID
        or document.get("snapshot_name") != SNAPSHOT_187
        or document.get("checkpoint_marker") != SNAPSHOT_187_MARKER
    ):
        raise BaselineAdoptionError("adoption identity differs")
    adoption_id = document.get("adoption_id")
    if not isinstance(adoption_id, str) or adoption_id != root.name:
        raise BaselineAdoptionError("adoption_id does not match the UUID directory")
    vmx = document.get("vmx")
    try:
        snapshot_raw.host_vmx(vmx)
    except snapshot_raw.SnapshotRawError as exc:
        raise BaselineAdoptionError(str(exc)) from exc
    seen: dict[str, tuple[int, str]] = {}
    old_canonical = _resolve_ref(root, document["old_canonical"], "old_canonical", seen)
    old_bytes = old_canonical.read_bytes()
    if expected_old_bytes is not None:
        if not isinstance(expected_old_bytes, bytes) or old_bytes != expected_old_bytes:
            raise BaselineAdoptionError("old_canonical bytes differ from the canonical predecessor")
    _verify_old_canonical(old_bytes)
    originals = {}
    expected_commands = {
        'snapshot_tree': ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', vmx, 'showTree'],
        'metadata': ['/usr/bin/cat', str(snapshot_raw.host_vmx(vmx).with_suffix('.vmsd'))],
        'guest_identity': None,
    }
    try:
        for name, argv in expected_commands.items():
            original = _resolve_ref(root, document[name], name, seen)
            originals[name] = snapshot_raw.command(
                _read_json_bytes(original.read_bytes(), name), workflow_id=WORKFLOW_ID,
                operation_id=adoption_id, observation=name, vmx=vmx, expected_argv=argv,
            )
        tree, metadata, identity = (originals[name] for name in expected_commands)
        if snapshot_raw.snapshot_names(tree['response']['stdout']) != [SNAPSHOT_187]:
            raise snapshot_raw.SnapshotRawError('snapshot tree is not the unique user187 baseline')
        if snapshot_raw.snapshot_marker(metadata['response']['stdout'], SNAPSHOT_187, only_snapshot=True) != (SNAPSHOT_187_MARKER, '3'):
            raise snapshot_raw.SnapshotRawError('metadata does not bind UID/current=3 and the user187 marker')
        if not (
            snapshot_raw.utc(tree['ended_at']) <= snapshot_raw.utc(metadata['started_at'])
            and snapshot_raw.utc(metadata['ended_at']) <= snapshot_raw.utc(identity['started_at'])
        ):
            raise snapshot_raw.SnapshotRawError('adoption observation order differs')
        identity_argv = identity['request']['argv']
        if (
            not identity_argv[0].lower().endswith('powershell.exe')
            or 'Get-CimInstance' not in identity['request']['command_line']
            or 'Win32_NetworkAdapterConfiguration' not in identity['request']['command_line']
        ):
            raise snapshot_raw.SnapshotRawError('guest identity does not retain its adapter query')
        snapshot_raw.guest_adapter(identity['response']['stdout'])
    except snapshot_raw.SnapshotRawError as exc:
        raise BaselineAdoptionError(str(exc)) from exc
    _verify_sources(root, document["source_inputs"], seen)
    return document

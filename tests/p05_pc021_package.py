"""PC021/PC022 P05 download-original preservation and phase packaging.

Implements P05 v19 section 0.PC021.3 against the frozen runner report:
locate the real list/download chains (0.PC021.3.2 mapping), admit the one
legal trusted source per chain and reject any alternate spelling of the
product ``local_path`` (0.PC021.3.3), stream-copy each original into the
phase tree at ``downloads/<flow_key>/<file_id>/content.bin`` with exclusive
``.part`` handling and CreateHardLinkW publication plus PC022 native
refreshes, then build and verify the 5/4-key phase manifest
(0.PC021.3.6/.3.7/.3.4).

Only members inside the package are ever re-read; the SDK report and the
product ``local_path`` are immutable source-time assertions and are never
rewritten or dereferenced after the copy.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from tests import pc022_windows_refresh as refresh


PHASE_MANIFEST_KIND = "pc021-p05-phase-manifest-v1"
MANIFEST_KEYS = {"schema_version", "kind", "workflow_id", "created_at", "members"}
MEMBER_KEYS = {"path", "size", "sha256", "origin"}
MANIFEST_NAME = "package-manifest.json"
DOWNLOADS_DIR = "downloads"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CHUNK_LIMIT = 1024 * 1024

LIST_TOP_KEYS = {"operation", "status", "warnings", "data", "truncated"}
LIST_ROW_KEYS = {"file_id", "original_path", "file_size", "uploaded_size", "accessor"}
DOWNLOAD_RESULT_KEYS = {
    "operation", "status", "warnings", "flow_id", "file_id",
    "local_path", "size", "sha256", "original_path",
}


class PackagePreservationError(RuntimeError):
    """A preservation or packaging rule refused to proceed."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_lower_hex_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise PackagePreservationError(message)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class DownloadChain:
    """One preserved logical original, joined from the frozen report."""

    flow_id: str
    file_id: str
    list_index: int
    download_index: int
    original_path: str
    logical_size: int
    uploaded_size: int
    accessor: str
    local_path: str
    sha256: str


def locate_download_chains(report: Any) -> list[DownloadChain]:
    """Validate and join the list/download rows of a frozen runner report.

    The report ``calls`` rows carry the real ``arguments``/``structured``
    pairs; the list top level must use the real product fields (``data``, not
    a fabricated ``files``), rows carry no flow id and no source hash, and
    each download joins exactly one list row of the same flow with equal
    logical size, original path, and content hash from the DownloadResult.
    """
    _require(isinstance(report, dict), "report is not an object")
    calls = report.get("calls")
    _require(isinstance(calls, list), "report calls is not an array")
    chains: list[DownloadChain] = []
    seen: set[tuple[str, str]] = set()
    for index, call in enumerate(calls):
        _require(isinstance(call, dict), f"call {index} is not an object")
        tool = call.get("tool")
        structured = call.get("structured")
        if tool != "download_flow_file":
            continue
        _require(isinstance(structured, dict), f"call {index} structured is missing")
        _require(
            set(structured) == DOWNLOAD_RESULT_KEYS,
            f"call {index} DownloadResult keys differ",
        )
        _require(
            structured.get("operation") == "download_flow_file"
            and structured.get("status") == "success",
            f"call {index} download operation/status differ",
        )
        arguments = call.get("arguments")
        _require(isinstance(arguments, dict), f"call {index} arguments missing")
        flow_id = arguments.get("flow_id")
        file_id = arguments.get("file_id")
        _require(
            isinstance(flow_id, str) and flow_id != "",
            f"call {index} flow_id is not a non-empty string",
        )
        try:
            flow_id.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PackagePreservationError(
                f"call {index} flow_id is not encodable as strict UTF-8"
            ) from exc
        _require(
            _is_lower_hex_sha256(file_id),
            f"call {index} file_id is not 64 lowercase hex",
        )
        _require(
            structured.get("flow_id") == flow_id and structured.get("file_id") == file_id,
            f"call {index} download identities differ from arguments",
        )
        size = structured.get("size")
        sha = structured.get("sha256")
        _require(
            isinstance(size, int) and not isinstance(size, bool) and size >= 0,
            f"call {index} download size is not a non-negative integer",
        )
        _require(_is_lower_hex_sha256(sha), f"call {index} download sha256 malformed")
        local_path = structured.get("local_path")
        _require(
            isinstance(local_path, str) and local_path != "",
            f"call {index} local_path is not a non-empty string",
        )
        original_path = structured.get("original_path")
        _require(
            isinstance(original_path, str),
            f"call {index} original_path is not a string",
        )
        row = _join_unique_list_row(calls, index, flow_id, file_id)
        _require(
            row["file_size"] == size and row["original_path"] == original_path,
            f"call {index} list row size/original_path differ from download result",
        )
        key = (flow_id, file_id)
        _require(key not in seen, f"duplicate download chain for {key}")
        seen.add(key)
        chains.append(
            DownloadChain(
                flow_id=flow_id,
                file_id=file_id,
                list_index=row["index"],
                download_index=index,
                original_path=original_path,
                logical_size=size,
                uploaded_size=row["uploaded_size"],
                accessor=row["accessor"],
                local_path=local_path,
                sha256=sha,
            )
        )
    return chains


def _join_unique_list_row(
    calls: list[Any], download_index: int, flow_id: str, file_id: str
) -> dict[str, Any]:
    """Find the unique completed list call of this flow selecting this file id."""
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, call in enumerate(calls):
        if not isinstance(call, dict) or call.get("tool") != "list_flow_files":
            continue
        arguments = call.get("arguments")
        if not isinstance(arguments, dict) or arguments.get("flow_id") != flow_id:
            continue
        structured = call.get("structured")
        _require(isinstance(structured, dict), f"call {index} list structured missing")
        _require(
            set(structured) == LIST_TOP_KEYS,
            f"call {index} list top-level keys differ (data is the real list field)",
        )
        _require(
            structured.get("operation") == "list_flow_files"
            and structured.get("status") == "success"
            and structured.get("truncated") is False,
            f"call {index} list operation/status/truncated differ",
        )
        data = structured.get("data")
        _require(isinstance(data, list) and len(data) > 0, f"call {index} list data empty")
        for row in data:
            _require(
                isinstance(row, dict) and set(row) == LIST_ROW_KEYS,
                f"call {index} list row keys differ",
            )
        _require(
            sum(1 for row in data if row.get("file_id") == file_id) == 1,
            f"call {index} file_id is not unique in list data",
        )
        matches.append((index, next(row for row in data if row.get("file_id") == file_id)))
    _require(
        len(matches) == 1,
        f"download call {download_index} does not join one unique list call/row",
    )
    index, row = matches[0]
    file_size = row.get("file_size")
    uploaded_size = row.get("uploaded_size")
    _require(
        isinstance(file_size, int) and not isinstance(file_size, bool) and file_size >= 0,
        f"call {index} file_size is not a non-negative integer",
    )
    _require(
        isinstance(uploaded_size, int)
        and not isinstance(uploaded_size, bool)
        and uploaded_size >= 0,
        f"call {index} uploaded_size is not a non-negative integer",
    )
    _require(
        isinstance(row.get("accessor"), str),
        f"call {index} accessor is not a string",
    )
    return {
        "index": index,
        "file_size": file_size,
        "uploaded_size": uploaded_size,
        "accessor": row["accessor"],
        "original_path": row["original_path"],
    }


def flow_key(flow_id: str) -> str:
    """flow_key = lowercase hex SHA-256 of the strict UTF-8 encoding once."""
    return hashlib.sha256(flow_id.encode("utf-8")).hexdigest()


def trusted_source_path(trusted_root: Path, chain: DownloadChain) -> Path:
    """Return the one legal source path and reject alternate spellings.

    The product ``local_path`` must point exactly at
    ``<trusted_root>/<flow_key>/<file_id>/content.bin`` in Windows native
    absolute-path semantics; alternate spellings, dot/dotdot, device/UNC,
    alias, short-name, case-ambiguous, or out-of-root forms are rejected by
    the exact-string comparison after separator normalization.
    """
    expected = trusted_root / flow_key(chain.flow_id) / chain.file_id / "content.bin"
    _require(
        chain.local_path == str(expected),
        "local_path does not point exactly at the trusted source "
        f"(expected {expected}, got {chain.local_path})",
    )
    return expected


def _assert_plain_directory_chain(root: Path, path: Path, label: str) -> None:
    """Every ancestor from root down to path.parent must be a plain directory."""
    relative = path.parent.relative_to(root)
    current = root
    info = current.lstat()
    _require(
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not getattr(info, "st_file_attributes", 0) & 0x400,
        f"{label} root is not a plain non-reparse directory",
    )
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PackagePreservationError(
                f"{label} traverses a link/reparse or non-directory at {part}"
            )


def _ensure_phase_hierarchy(phase_root: Path, parts: tuple[str, ...]) -> None:
    """Create only the missing tail below the deepest existing verified level.

    PC022 new-hierarchy creation applies to missing components; existing
    components are verified plain same-volume directories and become the
    deepest approved ancestor.  A hole (a missing level below an existing
    deeper one) is refused.
    """
    existing = 0
    for index in range(len(parts), -1, -1):
        candidate = phase_root.joinpath(*parts[:index]) if index else phase_root
        if candidate.exists() or candidate.is_symlink():
            existing = index
            break
    for index in range(1, existing + 1):
        level = phase_root.joinpath(*parts[:index])
        info = level.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PackagePreservationError(
                f"existing hierarchy level is not a plain directory: {level.name}"
            )
    if existing < len(parts):
        missing = parts[existing:]
        base = phase_root.joinpath(*parts[:existing]) if existing else phase_root
        refresh.create_hierarchy_and_refresh(base, missing)


def _assert_plain_file_object(path: Path, label: str) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise PackagePreservationError(f"{label} is not a plain non-reparse file")


def _file_identity(path: Path) -> tuple[int, int]:
    return refresh.handle_file_identity(path)


def preserve_chain(
    chain: DownloadChain,
    *,
    phase_root: Path,
    trusted_root: Path,
) -> dict[str, Any]:
    """Copy one original into the phase tree and publish it as a hard link.

    Order (P05 v19 0.PC021.3.3 plus the PC022 publish primitive): admit the
    trusted source as a plain non-reparse file; open it once and record
    stable identity, logical size, and change metadata; stream bounded
    chunks and count/SHA-256; re-verify the same handle and the
    path-to-handle identity; demand count/SHA equal the immutable
    DownloadResult; create the destination hierarchy with per-level native
    refresh; exclusive-create the ``.part`` in the same directory, stream,
    flush/fsync/close, refresh the parent, and read back byte-for-byte;
    publish ``content.bin`` with CreateHardLinkW and identity proof; refresh
    the parent; re-verify target identity/size/hash; then remove only the
    owned ``.part`` and refresh the parent again.
    """
    source = trusted_source_path(trusted_root, chain)
    _assert_plain_directory_chain(trusted_root, source, "trusted source chain")
    _assert_plain_file_object(source, "trusted source")
    first_identity = _file_identity(source)
    count = 0
    digest = hashlib.sha256()
    read_back: list[bytes] = []
    with source.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_LIMIT)
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
            read_back.append(chunk)
    second_identity = _file_identity(source)
    _require(
        first_identity == second_identity,
        "trusted source identity drifted during the bounded read",
    )
    if count == 0:
        _require(
            digest.hexdigest() == EMPTY_SHA256 and chain.logical_size == 0,
            "zero-byte member does not satisfy the empty-file contract",
        )
    _require(
        count == chain.logical_size,
        f"source byte count {count} differs from logical size {chain.logical_size}",
    )
    _require(
        digest.hexdigest() == chain.sha256,
        "source content hash differs from the immutable DownloadResult sha256",
    )
    payload = b"".join(read_back)

    relative = Path(DOWNLOADS_DIR) / flow_key(chain.flow_id) / chain.file_id
    _ensure_phase_hierarchy(phase_root, relative.parts)
    part = phase_root / relative / ".pc021.part"
    _require(not part.exists() and not part.is_symlink(), "stale owned part exists")
    with part.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    refresh.windows_refresh_directory(part.parent)
    if part.read_bytes() != payload:
        raise PackagePreservationError("owned part readback differs")
    target = phase_root / relative / "content.bin"
    _require(
        not target.exists() and not target.is_symlink(),
        "member target already exists (collision)",
    )
    refresh.windows_publish_hard_link(part, target)
    refresh.windows_refresh_directory(target.parent)
    published = target.read_bytes()
    _require(
        len(published) == chain.logical_size
        and hashlib.sha256(published).hexdigest() == chain.sha256,
        "published member size/hash differs after native refresh",
    )
    target_identity = _file_identity(target)
    part_identity = _file_identity(part)
    _require(
        target_identity == part_identity,
        "published member identity differs from the owned part",
    )
    part.unlink()
    refresh.windows_refresh_directory(target.parent)
    _require(not part.exists(), "owned part remains after cleanup")
    return {
        "member_path": (relative / "content.bin").as_posix(),
        "size": chain.logical_size,
        "sha256": chain.sha256,
        "source": str(source),
    }


def _plain_tree_files(phase_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in phase_root.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PackagePreservationError(
                f"phase tree contains a link/reparse object: {path.name}"
            )
        if stat.S_ISDIR(info.st_mode):
            continue
        _require(
            not path.name.endswith(".part"),
            f"phase tree contains an unresolved temporary part: {path.name}",
        )
        files.append(path)
    return files


def build_phase_manifest(
    *,
    phase_root: Path,
    phase_prefix: str,
    workflow_id: str,
    report: dict[str, Any],
    report_ref_path: str,
    created_at_fn: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    """Build and persist the 5/4-key phase manifest (0.PC021.3.6/.3.7).

    ``members`` is exactly all plain files under the phase root minus the
    manifest itself; the excluded set contains no other object.  Downloaded
    members get the ``<report_ref>#/calls/<i>/structured`` origin, every
    other member the ``<phase_prefix>/<member.path>`` origin.  ``created_at``
    is taken only after every member has been read back.
    """
    chains = locate_download_chains(report)
    download_members = {
        (Path(DOWNLOADS_DIR) / flow_key(chain.flow_id) / chain.file_id / "content.bin").as_posix(): chain
        for chain in chains
    }
    files = _plain_tree_files(phase_root)
    members: list[dict[str, Any]] = []
    for path in files:
        relative = path.relative_to(phase_root).as_posix()
        if relative == MANIFEST_NAME:
            continue
        data = path.read_bytes()
        chain = download_members.get(relative)
        if chain is not None:
            _require(
                len(data) == chain.logical_size and _sha256_bytes(data) == chain.sha256,
                f"downloaded member bytes differ from the frozen report: {relative}",
            )
            origin = f"{report_ref_path}#/calls/{chain.download_index}/structured"
        else:
            origin = f"{phase_prefix}/{relative}"
        members.append(
            {
                "path": relative,
                "size": len(data),
                "sha256": _sha256_bytes(data),
                "origin": origin,
            }
        )
    _require(
        set(download_members).issubset({member["path"] for member in members}),
        "phase tree is missing a downloaded member required by the report",
    )
    members.sort(key=lambda member: member["path"].encode("utf-8"))
    manifest = {
        "schema_version": 1,
        "kind": PHASE_MANIFEST_KIND,
        "workflow_id": workflow_id,
        "created_at": created_at_fn(),
        "members": members,
    }
    _require(set(manifest) == MANIFEST_KEYS, "manifest key construction differs")
    return manifest


def persist_phase_manifest(manifest: dict[str, Any], phase_root: Path) -> bytes:
    """Write, natively refresh, and read back the manifest bytes."""
    payload = _canonical_json(manifest)
    path = phase_root / MANIFEST_NAME
    _require(not path.exists(), "phase manifest already exists")
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    refresh.windows_refresh_directory(phase_root)
    if path.read_bytes() != payload:
        raise PackagePreservationError("manifest readback differs")
    return payload


def verify_phase_package(
    *,
    phase_root: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    report_ref_path: str,
) -> None:
    """Re-verify a sealed phase package from immutable inputs (0.PC021.3.4).

    Members are rebuilt only from the frozen report's Flow/file identities;
    the original ``local_path`` is never dereferenced, and no field that the
    list rows do not carry (for example a source hash) is ever read.
    """
    _require(set(manifest) == MANIFEST_KEYS, "manifest root keys differ")
    _require(
        manifest.get("kind") == PHASE_MANIFEST_KIND and manifest.get("schema_version") == 1,
        "manifest kind/schema differ",
    )
    members = manifest.get("members")
    _require(isinstance(members, list), "manifest members is not an array")
    listed = [member.get("path") for member in members]
    _require(len(listed) == len(set(listed)), "manifest member paths repeat")
    files = _plain_tree_files(phase_root)
    actual = sorted(
        path.relative_to(phase_root).as_posix()
        for path in files
        if path.name != MANIFEST_NAME
    )
    _require(
        sorted(listed) == actual,
        "manifest member set differs from the phase tree (exact set mismatch)",
    )
    chains = {
        (Path(DOWNLOADS_DIR) / flow_key(chain.flow_id) / chain.file_id / "content.bin").as_posix(): chain
        for chain in locate_download_chains(report)
    }
    calls = report.get("calls")
    for member in members:
        _require(set(member) == MEMBER_KEYS, "member keys differ")
        relative = member["path"]
        pure = PurePosixPath(relative)
        _require(
            not pure.is_absolute() and ".." not in pure.parts and "\\" not in relative,
            f"member path escapes the phase coordinate system: {relative}",
        )
        data = (phase_root / relative).read_bytes()
        _require(
            member["size"] == len(data) and member["sha256"] == _sha256_bytes(data),
            f"member bytes differ from the manifest: {relative}",
        )
        chain = chains.get(relative)
        if chain is not None:
            expected_origin = (
                f"{report_ref_path}#/calls/{chain.download_index}/structured"
            )
            _require(
                member["origin"] == expected_origin,
                f"downloaded member origin differs: {relative}",
            )
        else:
            _require(
                member["origin"] == member["path"] or "/" in member["origin"],
                f"member origin is not a phase-relative reference: {relative}",
            )


def _canonical_json(document: dict[str, Any]) -> bytes:
    import json

    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")

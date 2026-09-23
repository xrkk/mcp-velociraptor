"""Canonical source inventory shared by host and guest content layers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .errors import TransferContentError as Error

BLOCK_SIZE = 1024 * 1024
SCHEMA = "velo.transfer.manifest.v1"
_DRIVE = re.compile(r"^[A-Za-z]:")
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$|clock\$)(?:\.|$)", re.I)
_SHORT_ALIAS = re.compile(r"^[^./]{1,6}~[0-9](?:\.|$)", re.I)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def check_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise Error("invalid_relative_path")
    if value.startswith("/") or _DRIVE.match(value):
        raise Error("invalid_relative_path")
    parts = value.split("/")
    for part in parts:
        if (part in ("", ".", "..") or unicodedata.normalize("NFC", part) != part or ":" in part or
                part.endswith((" ", ".")) or _RESERVED.match(part) or
                _SHORT_ALIAS.match(part) or any(ch in '<>"|?*' for ch in part) or
                any(ord(char) < 32 for char in part)):
            raise Error("invalid_relative_path")
    return value


def _no_link(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Error("source_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise Error("link_or_reparse")
    return info


def safe_chain(path: Path, root: Path, *, allow_missing_leaf: bool = False) -> None:
    if not path.is_absolute() or not root.is_absolute() or not path.is_relative_to(root):
        raise Error("path_outside_root")
    # Verify each ancestor of the caller-supplied root too; no resolved prefix trust.
    ancestors = list(reversed(root.parents)) + [root]
    for ancestor in ancestors:
        _no_link(ancestor)
    current = root
    parts = path.relative_to(root).parts
    for index, part in enumerate(parts):
        check_relative(part)
        current = current / part
        if allow_missing_leaf and index == len(parts) - 1 and not os.path.lexists(current):
            return
        _no_link(current)


def file_identity(info: os.stat_result) -> dict[str, int]:
    return {"device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def directory_identity(path: Path) -> dict[str, int]:
    info = _no_link(path)
    if not stat.S_ISDIR(info.st_mode):
        raise Error("not_directory")
    return {"device": info.st_dev, "inode": info.st_ino}


@dataclass(frozen=True)
class Budget:
    max_files: int
    max_metadata_bytes: int
    max_logical_bytes: int
    max_package_bytes: int
    min_free_bytes: int
    deadline_monotonic: float
    max_expansion_ratio: int = 1_000_000
    check_cancel: Callable[[], None] | None = None

    def check(self) -> None:
        if min(self.max_files, self.max_metadata_bytes, self.max_package_bytes,
               self.max_expansion_ratio) <= 0 or self.max_logical_bytes < 0 or self.min_free_bytes < 0:
            raise Error("invalid_budget")
        if time.monotonic() >= self.deadline_monotonic:
            raise Error("deadline_exceeded")
        if self.check_cancel is not None:
            self.check_cancel()

    def space(self, directory: Path, required: int) -> None:
        self.check()
        try:
            free = __import__("shutil").disk_usage(directory).free
        except OSError as exc:
            raise Error("disk_probe_failed") from exc
        if free < required + self.min_free_bytes:
            raise Error("disk_budget_exceeded")


def _hash_file(path: Path, root: Path, budget: Budget) -> tuple[dict[str, int], str]:
    safe_chain(path, root)
    before = _no_link(path)
    if not stat.S_ISREG(before.st_mode):
        raise Error("unsupported_source_type")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Error("source_unavailable") from exc
    try:
        opened = os.fstat(fd)
        if file_identity(opened) != file_identity(before):
            raise Error("source_changed")
        hasher = hashlib.sha256()
        count = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                budget.check()
                chunk = stream.read(BLOCK_SIZE)
                if not chunk:
                    break
                count += len(chunk)
                if count > budget.max_logical_bytes:
                    raise Error("logical_budget_exceeded")
                hasher.update(chunk)
        after = os.fstat(fd)
        if (file_identity(after) != file_identity(before) or count != before.st_size or
                file_identity(_no_link(path)) != file_identity(before)):
            raise Error("source_changed")
        return file_identity(before), hasher.hexdigest()
    finally:
        os.close(fd)


def _check_collisions(names: list[str], directories: set[str] | None = None) -> None:
    seen: set[str] = set()
    for name in names:
        check_relative(name)
        folded = name.casefold()
        if folded in seen:
            raise Error("path_collision")
        seen.add(folded)
    directory_folded = {name.casefold() for name in (directories or set())}
    file_folded = seen - directory_folded
    for name in names:
        folded = name.casefold()
        parts = folded.split("/")
        if any("/".join(parts[:index]) in file_folded
               for index in range(1, len(parts))):
            raise Error("path_collision")


def source_root_for(path: Path, roots: str | Path | list[str | Path]) -> Path:
    choices = [Path(roots)] if isinstance(roots, (str, Path)) else [Path(x) for x in roots]
    if not choices or any(not root.is_absolute() or not root.is_dir() for root in choices):
        raise Error("invalid_source_root")
    matches = [root for root in choices if path.is_relative_to(root)]
    if not matches:
        raise Error("path_outside_root")
    root = max(matches, key=lambda item: len(item.parts))
    safe_chain(path, root)
    return root


def _scan(root: str | Path | list[str | Path], sources: list[dict[str, str]], budget: Budget,
          evidence_refs: list[str]) -> dict:
    roots = [Path(root)] if isinstance(root, (str, Path)) else [Path(x) for x in root]
    if not roots or any(not item.is_absolute() or not item.is_dir() for item in roots):
        raise Error("invalid_source_root")
    for item in roots:
        _no_link(item)
    if not isinstance(sources, list) or not sources:
        raise Error("sources_required")
    if len(sources) > budget.max_files:
        raise Error("file_count_exceeded")
    if not isinstance(evidence_refs, list) or any(not isinstance(x, str) for x in evidence_refs):
        raise Error("invalid_evidence_refs")
    evidence_size = 32
    for reference in evidence_refs:
        evidence_size += len(reference.encode("utf-8")) + 3
        if evidence_size > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
    entries: list[dict] = []
    names: list[str] = []
    logical = 0
    metadata = len(canonical_json({"schema": SCHEMA, "evidence_refs": evidence_refs}))

    def add(path: Path, relative: str, source_root: Path) -> None:
        nonlocal logical, metadata
        budget.check()
        if len(entries) + 1 > budget.max_files:
            raise Error("file_count_exceeded")
        relative = check_relative(relative)
        safe_chain(path, source_root)
        info = _no_link(path)
        if stat.S_ISDIR(info.st_mode):
            entry = {"path": relative, "type": "directory",
                     "identity": file_identity(info)}
        elif stat.S_ISREG(info.st_mode):
            if logical + info.st_size > budget.max_logical_bytes:
                raise Error("logical_budget_exceeded")
            identity, digest = _hash_file(path, source_root, budget)
            logical += identity["size"]
            entry = {"path": relative, "type": "file", "size": identity["size"],
                     "sha256": digest, "identity": identity}
        else:
            raise Error("unsupported_source_type")
        metadata += len(canonical_json(entry)) + 128 + len(relative.encode("utf-8"))
        if metadata > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
        entries.append(entry)
        names.append(relative)
        if entry["type"] == "directory":
            before = file_identity(info)
            try:
                with os.scandir(path) as children:
                    while True:
                        budget.check()
                        try:
                            child = next(children)
                        except StopIteration:
                            break
                        add(Path(child.path), relative + "/" + child.name, source_root)
            except OSError as exc:
                raise Error("source_unavailable") from exc
            if file_identity(_no_link(path)) != before:
                raise Error("source_changed")

    for spec in sources:
        if not isinstance(spec, dict) or set(spec) != {"absolute_path", "relative_path"}:
            raise Error("invalid_source_spec")
        if not isinstance(spec["absolute_path"], str) or not isinstance(spec["relative_path"], str):
            raise Error("invalid_source_spec")
        path = Path(spec["absolute_path"])
        relative = check_relative(spec["relative_path"])
        if not path.is_absolute():
            raise Error("invalid_source_path")
        add(path, relative, source_root_for(path, roots))
    # Parents of explicit relative paths are represented as virtual directories.
    known = set(names)
    for name in list(names):
        parts = name.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent not in known:
                virtual = {"path": parent, "type": "directory", "identity": {}}
                metadata += len(canonical_json(virtual)) + 128 + len(parent.encode("utf-8"))
                if len(entries) + 1 > budget.max_files:
                    raise Error("file_count_exceeded")
                if metadata > budget.max_metadata_bytes:
                    raise Error("metadata_budget_exceeded")
                entries.append(virtual)
                names.append(parent)
                known.add(parent)
    _check_collisions(names, {e["path"] for e in entries if e["type"] == "directory"})
    entries.sort(key=lambda entry: entry["path"])
    result = {"schema": SCHEMA, "evidence_refs": evidence_refs, "entries": entries}
    if len(canonical_json(result)) > budget.max_metadata_bytes:
        raise Error("metadata_budget_exceeded")
    return result


def capture_sources(source_root: str | Path | list[str | Path], sources: list[dict[str, str]],
                    budget: Budget, evidence_refs: list[str] | None = None) -> dict:
    """Capture fixed ordinary-byte source inventory; caller proves production stopped."""
    return _scan(source_root, sources, budget, evidence_refs or [])


def validate_sources(source_root: str | Path | list[str | Path], sources: list[dict[str, str]],
                     manifest: dict, budget: Budget) -> str:
    """Repeat full enumeration and hashing, including newly added directory members."""
    current = _scan(source_root, sources, budget, manifest["evidence_refs"])
    if current != manifest:
        raise Error("source_changed")
    return digest_json(current)

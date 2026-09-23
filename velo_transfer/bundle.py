"""ZIP64 content packaging and bounded, manual extraction."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import zipfile
from pathlib import Path
from typing import Callable

from .errors import TransferContentError as Error
from .manifest import (BLOCK_SIZE, Budget, SCHEMA, _check_collisions, _hash_file,
                       _no_link, canonical_json, check_relative, directory_identity,
                       file_identity, safe_chain, source_root_for, validate_sources)

MANIFEST_MEMBER = "manifest.json"
PAYLOAD_PREFIX = "payload/"


class _BoundedOutput:
    """Check each ZIP write before it reaches disk, including central metadata."""

    def __init__(self, stream, directory: Path, budget: Budget) -> None:
        self.stream = stream
        self.directory = directory
        self.budget = budget

    def write(self, data: bytes) -> int:
        self.budget.check()
        if self.stream.tell() + len(data) > self.budget.max_package_bytes:
            raise Error("package_budget_exceeded")
        if data:
            self.budget.space(self.directory, len(data))
        return self.stream.write(data)

    def tell(self) -> int:
        return self.stream.tell()

    def seek(self, *args):
        return self.stream.seek(*args)

    def flush(self) -> None:
        self.stream.flush()


def _source_path(entry: dict, sources: list[dict[str, str]]) -> Path:
    matches = [spec for spec in sources if entry["path"] == spec["relative_path"] or
               entry["path"].startswith(spec["relative_path"] + "/")]
    if len(matches) != 1:
        raise Error("source_mapping_ambiguous")
    spec = matches[0]
    suffix = entry["path"][len(spec["relative_path"]):].lstrip("/")
    return Path(spec["absolute_path"]) / suffix if suffix else Path(spec["absolute_path"])


def _hash_path(path: Path, budget: Budget) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            budget.check()
            chunk = stream.read(BLOCK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > budget.max_package_bytes:
                raise Error("package_budget_exceeded")
            hasher.update(chunk)
    return size, hasher.hexdigest()


def create_bundle(source_root: str | Path | list[str | Path], sources: list[dict[str, str]], manifest: dict,
                  bundle_path: str | Path, work_root: str | Path, budget: Budget) -> dict:
    """Build a fresh ZIP64 package with one manifest and exact payload members."""
    bundle_path, work_root = map(Path, (bundle_path, work_root))
    safe_chain(bundle_path.parent, work_root)
    safe_chain(bundle_path, work_root, allow_missing_leaf=True)
    if bundle_path.exists() or bundle_path.is_symlink():
        raise Error("bundle_exists")
    validate_sources(source_root, sources, manifest, budget)
    payload = canonical_json(manifest)
    if len(payload) > budget.max_metadata_bytes:
        raise Error("metadata_budget_exceeded")
    logical_size = sum(entry.get("size", 0) for entry in manifest["entries"])
    estimated = logical_size + len(payload) + 1024 * (len(manifest["entries"]) + 1)
    estimated += 8 * (logical_size // 16384 + 1)
    budget.space(bundle_path.parent, min(budget.max_package_bytes, estimated))
    temp = bundle_path.parent / ("." + bundle_path.name + "." + os.urandom(8).hex() + ".part")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as outer:
            with zipfile.ZipFile(_BoundedOutput(outer, bundle_path.parent, budget), "w", compression=zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as archive:
                archive.writestr(MANIFEST_MEMBER, payload, compress_type=zipfile.ZIP_DEFLATED)
                for entry in manifest["entries"]:
                    budget.check()
                    name = PAYLOAD_PREFIX + entry["path"]
                    if entry["type"] == "directory":
                        archive.writestr(name + "/", b"")
                        continue
                    source = _source_path(entry, sources)
                    safe_chain(source, source_root_for(source, source_root))
                    before = _no_link(source)
                    if file_identity(before) != entry["identity"] or not stat.S_ISREG(before.st_mode):
                        raise Error("source_changed")
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100600 << 16
                    hasher = hashlib.sha256()
                    count = 0
                    flags_in = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    source_fd = os.open(source, flags_in)
                    try:
                        if file_identity(os.fstat(source_fd)) != entry["identity"]:
                            raise Error("source_changed")
                        with os.fdopen(source_fd, "rb", closefd=False) as incoming:
                            with archive.open(info, "w", force_zip64=True) as outgoing:
                                while True:
                                    budget.check()
                                    chunk = incoming.read(BLOCK_SIZE)
                                    if not chunk:
                                        break
                                    count += len(chunk)
                                    if count > entry["size"]:
                                        raise Error("source_changed")
                                    outgoing.write(chunk)
                                    hasher.update(chunk)
                        if (count != entry["size"] or hasher.hexdigest() != entry["sha256"] or
                                file_identity(os.fstat(source_fd)) != entry["identity"] or
                                file_identity(_no_link(source)) != entry["identity"]):
                            raise Error("source_changed")
                    finally:
                        os.close(source_fd)
                    if outer.tell() > budget.max_package_bytes:
                        raise Error("package_budget_exceeded")
            outer.flush()
            os.fsync(outer.fileno())
        size, digest = _hash_path(temp, budget)
        validate_sources(source_root, sources, manifest, budget)
        if size > budget.max_package_bytes:
            raise Error("package_budget_exceeded")
        try:
            os.link(temp, bundle_path, follow_symlinks=False)
        except FileExistsError as exc:
            raise Error("bundle_exists") from exc
        temp.unlink()
        return {"path": str(bundle_path), "size": size, "sha256": digest,
                "manifest_sha256": hashlib.sha256(payload).hexdigest()}
    except Exception:
        # Only this unpredictable owned part is removed. No source or existing final is touched.
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _zip_directory_precheck(path: Path, budget: Budget) -> None:
    """Validate the exact EOCD/ZIP64 records and count central entries before ZipFile."""
    size = path.stat().st_size
    tail_size = min(size, 65557)
    with path.open("rb") as stream:
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
        index = tail.rfind(b"PK\x05\x06")
        if index < 0 or index + 22 > len(tail):
            raise Error("invalid_package")
        end_offset = size - tail_size + index
        disk, central_disk, disk_entries, entries, central_size, central_offset, comment = (
            struct.unpack_from("<HHHHIIH", tail, index + 4))
        if (index + 22 + comment != len(tail) or disk != 0 or central_disk != 0 or
                disk_entries != entries):
            raise Error("invalid_package")
        locator_offset = end_offset - 20
        stream.seek(max(locator_offset, 0))
        locator = stream.read(20) if locator_offset >= 0 else b""
        if locator.startswith(b"PK\x06\x07"):
            if len(locator) != 20:
                raise Error("invalid_package")
            _, locator_disk, record_offset, total_disks = struct.unpack("<4sIQI", locator)
            if locator_disk != 0 or total_disks != 1 or record_offset + 56 != locator_offset:
                raise Error("invalid_package")
            stream.seek(record_offset)
            record = stream.read(56)
            if len(record) != 56 or record[:4] != b"PK\x06\x06":
                raise Error("invalid_package")
            (record_size, made_version, needed_version, record_disk, record_start,
             record_disk_entries, record_entries, record_central_size, record_central_offset) = (
                struct.unpack_from("<QHHIIQQQQ", record, 4))
            if (record_size != 44 or needed_version < 45 or record_disk != 0 or
                    record_start != 0 or record_disk_entries != record_entries):
                raise Error("invalid_package")
            if (entries != 0xFFFF and entries != record_entries) or \
               (central_size != 0xFFFFFFFF and central_size != record_central_size) or \
               (central_offset != 0xFFFFFFFF and central_offset != record_central_offset):
                raise Error("invalid_package")
            entries = record_entries
            central_size = record_central_size
            central_offset = record_central_offset
            central_end = record_offset
        else:
            if entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
                raise Error("invalid_package")
            central_end = end_offset
        if central_offset + central_size != central_end or central_offset < 0:
            raise Error("invalid_package")
        if entries > budget.max_files + 1:
            raise Error("file_count_exceeded")
        if central_size > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
        # EOCD counts can also understate the true directory. Walk fixed-size
        # central headers and skip variable fields without allocating names.
        stream.seek(central_offset)
        position = central_offset
        seen = 0
        while position < central_end:
            budget.check()
            if central_end - position < 46:
                raise Error("invalid_package")
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise Error("invalid_package")
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
            start_disk = struct.unpack_from("<H", header, 34)[0]
            if start_disk not in (0, 0xFFFF):
                raise Error("invalid_package")
            position += 46 + name_length + extra_length + comment_length
            seen += 1
            if seen > budget.max_files + 1:
                raise Error("file_count_exceeded")
            if position > central_end:
                raise Error("invalid_package")
            stream.seek(position)
        if seen != entries:
            raise Error("invalid_package")


def _validated_manifest(raw: bytes, budget: Budget) -> dict:
    if len(raw) > budget.max_metadata_bytes:
        raise Error("metadata_budget_exceeded")
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Error("invalid_manifest") from exc
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "evidence_refs", "entries"}
            or manifest["schema"] != SCHEMA or not isinstance(manifest["entries"], list)
            or not isinstance(manifest["evidence_refs"], list)
            or any(not isinstance(ref, str) for ref in manifest["evidence_refs"])
            or canonical_json(manifest) != raw):
        raise Error("invalid_manifest")
    if len(manifest["entries"]) > budget.max_files:
        raise Error("file_count_exceeded")
    logical = 0
    names = []
    directory_names: set[str] = set()
    identity_keys = {"device", "inode", "size", "mtime_ns"}
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or entry.get("type") not in ("file", "directory"):
            raise Error("invalid_manifest")
        name = check_relative(entry.get("path"))
        names.append(name)
        identity = entry.get("identity")
        if not isinstance(identity, dict):
            raise Error("invalid_manifest")
        if identity and (set(identity) != identity_keys or
                         any(type(value) is not int for value in identity.values()) or
                         any(identity[key] < 0 for key in ("device", "inode", "size"))):
            raise Error("invalid_manifest")
        if entry["type"] == "file":
            if (set(entry) != {"path", "type", "size", "sha256", "identity"} or
                    type(entry["size"]) is not int or entry["size"] < 0 or
                    not isinstance(entry["sha256"], str) or len(entry["sha256"]) != 64 or
                    any(ch not in "0123456789abcdef" for ch in entry["sha256"])):
                raise Error("invalid_manifest")
            if not identity or identity["size"] != entry["size"]:
                raise Error("invalid_manifest")
            logical += entry["size"]
            if logical > budget.max_logical_bytes:
                raise Error("logical_budget_exceeded")
        elif set(entry) != {"path", "type", "identity"}:
            raise Error("invalid_manifest")
        else:
            directory_names.add(name)
    for name in names:
        parts = name.split("/")
        if any("/".join(parts[:index]) not in directory_names
               for index in range(1, len(parts))):
            raise Error("invalid_manifest")
    _check_collisions(names, directory_names)
    if manifest["entries"] != sorted(manifest["entries"], key=lambda e: e["path"]):
        raise Error("invalid_manifest")
    return manifest


def _members(archive: zipfile.ZipFile, manifest: dict, budget: Budget) -> dict[str, zipfile.ZipInfo]:
    expected = {MANIFEST_MEMBER}
    for entry in manifest["entries"]:
        expected.add(PAYLOAD_PREFIX + entry["path"] + ("/" if entry["type"] == "directory" else ""))
    actual: dict[str, zipfile.ZipInfo] = {}
    seen_folded = set()
    metadata = 0
    for info in archive.infolist():
        budget.check()
        name = info.filename
        metadata += len(name.encode("utf-8")) + len(info.extra) + len(info.comment) + 128
        if metadata > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
        if name in actual or name.casefold() in seen_folded:
            raise Error("zip_member_collision")
        if name not in expected:
            raise Error("unexpected_zip_member")
        if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_DEFLATED:
            raise Error("unsupported_zip_member")
        mode = (info.external_attr >> 16) & 0xF000
        if mode not in (0, 0x8000, 0x4000):
            raise Error("unsupported_zip_member")
        actual[name] = info
        seen_folded.add(name.casefold())
    if set(actual) != expected:
        raise Error("missing_zip_member")
    for entry in manifest["entries"]:
        name = PAYLOAD_PREFIX + entry["path"] + ("/" if entry["type"] == "directory" else "")
        info = actual[name]
        size = 0 if entry["type"] == "directory" else entry["size"]
        if info.file_size != size or info.is_dir() != (entry["type"] == "directory"):
            raise Error("zip_size_mismatch")
        mode = (info.external_attr >> 16) & 0xF000
        if mode and mode != (0x4000 if entry["type"] == "directory" else 0x8000):
            raise Error("unsupported_zip_member")
        if info.file_size and (info.compress_size == 0 or
                              info.file_size > info.compress_size * budget.max_expansion_ratio):
            raise Error("expansion_budget_exceeded")
    return actual


def verify_tree(root: str | Path, manifest: dict, budget: Budget,
                expected_identity: dict[str, int] | None = None) -> dict:
    """Reject extras and changed bytes; return verified directory identity/digest."""
    root = Path(root)
    safe_chain(root, root)
    before = directory_identity(root)
    before_stat = file_identity(_no_link(root))
    if expected_identity is not None and before != expected_identity:
        raise Error("destination_changed")
    expected = {entry["path"]: entry for entry in manifest["entries"]}
    actual: set[str] = set()
    pending = [root]
    while pending:
        current = pending.pop()
        budget.check()
        directory_before = file_identity(_no_link(current))
        try:
            with os.scandir(current) as iterator:
                for child in iterator:
                    budget.check()
                    path = Path(child.path)
                    relative = path.relative_to(root).as_posix()
                    check_relative(relative)
                    safe_chain(path, root)
                    if len(actual) + 1 > budget.max_files:
                        raise Error("file_count_exceeded")
                    actual.add(relative)
                    if relative not in expected:
                        raise Error("unexpected_tree_member")
                    entry = expected[relative]
                    if entry["type"] == "directory":
                        if not stat.S_ISDIR(_no_link(path).st_mode):
                            raise Error("tree_type_mismatch")
                        pending.append(path)
                    else:
                        identity, digest = _hash_file(path, root, budget)
                        if identity["size"] != entry["size"] or digest != entry["sha256"]:
                            raise Error("tree_content_mismatch")
        except OSError as exc:
            raise Error("destination_unavailable") from exc
        if file_identity(_no_link(current)) != directory_before:
            raise Error("destination_changed")
    if actual != set(expected):
        raise Error("missing_tree_member")
    after = directory_identity(root)
    if after != before or file_identity(_no_link(root)) != before_stat:
        raise Error("destination_changed")
    return {"identity": after, "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
            "files": sum(e["type"] == "file" for e in manifest["entries"])}


def prepare_staging(destination_directory: str | Path, allowed_root: str | Path,
                    budget: Budget, *, stage_name: str,
                    register_stage: Callable[[str, dict, dict], bool],
                    verify_windows_acl: Callable[[Path], bool] | None = None) -> dict:
    """Create caller-named private stage; register exact identity before any content."""
    destination, allowed_root = map(Path, (destination_directory, allowed_root))
    safe_chain(destination.parent, allowed_root)
    safe_chain(destination, allowed_root, allow_missing_leaf=True)
    if destination.exists() or destination.is_symlink():
        raise Error("destination_exists")
    if (not isinstance(stage_name, str) or not stage_name.startswith(".velo-stage-") or
            len(stage_name) > 80 or "/" in stage_name):
        raise Error("invalid_stage_name")
    check_relative(stage_name)
    stage = destination.parent / stage_name
    safe_chain(stage, allowed_root, allow_missing_leaf=True)
    parent_identity = directory_identity(destination.parent)
    budget.space(destination.parent, 0)
    try:
        os.mkdir(stage, 0o700)
    except FileExistsError as exc:
        raise Error("stage_exists") from exc
    except OSError as exc:
        raise Error("stage_creation_failed") from exc
    identity = directory_identity(stage)
    context = {"stage_path": str(stage), "stage_device": identity["device"],
               "stage_inode": identity["inode"], "registered": False}
    try:
        if os.name == "posix" and _no_link(stage).st_mode & 0o077:
            raise Error("staging_not_private")
        if os.name == "nt" and (verify_windows_acl is None or
                                not verify_windows_acl(stage) or
                                not verify_windows_acl(destination.parent)):
            raise Error("windows_acl_not_verified")
        if directory_identity(destination.parent) != parent_identity:
            raise Error("destination_parent_changed")
        if register_stage(str(stage), dict(identity), dict(parent_identity)) is not True:
            raise Error("stage_registration_failed")
    except Error as exc:
        raise Error(exc.code, **context) from exc
    except Exception as exc:
        raise Error("stage_registration_failed", **context) from exc
    return {"staging_directory": str(stage), "staging_identity": identity,
            "parent_identity": parent_identity, "destination_directory": str(destination)}


def unpack_bundle(bundle_path: str | Path, bundle_root: str | Path,
                  expected_size: int, expected_sha256: str,
                  destination_directory: str | Path, allowed_root: str | Path,
                  budget: Budget, *, staging: dict,
                  verify_windows_acl: Callable[[Path], bool] | None = None) -> dict:
    """Extract only into a previously registered, empty, identity-bound stage."""
    bundle_path, bundle_root, destination, allowed_root = map(Path,
        (bundle_path, bundle_root, destination_directory, allowed_root))
    if (not isinstance(staging, dict) or
            set(staging) != {"staging_directory", "staging_identity",
                            "parent_identity", "destination_directory"} or
            staging["destination_directory"] != str(destination)):
        raise Error("invalid_staging_ownership")
    stage = Path(staging["staging_directory"])
    stage_identity = staging["staging_identity"]
    parent_identity = staging["parent_identity"]
    if (not stage.is_absolute() or stage.parent != destination.parent or stage == destination or
            not isinstance(stage_identity, dict) or not isinstance(parent_identity, dict) or
            set(stage_identity) != {"device", "inode"} or
            set(parent_identity) != {"device", "inode"}):
        raise Error("invalid_staging_ownership")
    safe_chain(stage, allowed_root)
    safe_chain(destination, allowed_root, allow_missing_leaf=True)
    if directory_identity(stage) != stage_identity:
        raise Error("staging_changed")
    if directory_identity(destination.parent) != parent_identity:
        raise Error("destination_parent_changed")
    if os.name == "posix" and _no_link(stage).st_mode & 0o077:
        raise Error("staging_not_private")
    if os.name == "nt" and (verify_windows_acl is None or
                            not verify_windows_acl(stage) or
                            not verify_windows_acl(destination.parent)):
        raise Error("windows_acl_not_verified")
    with os.scandir(stage) as children:
        if next(children, None) is not None:
            raise Error("stage_not_empty")
    context = {"stage_path": str(stage), "stage_device": stage_identity["device"],
               "stage_inode": stage_identity["inode"], "registered": True}
    try:
        safe_chain(bundle_path, bundle_root)
        if destination.exists() or destination.is_symlink():
            raise Error("destination_exists")
        if (type(expected_size) is not int or expected_size < 0 or
                not isinstance(expected_sha256, str) or len(expected_sha256) != 64):
            raise Error("invalid_package_identity")
        if expected_size > budget.max_package_bytes:
            raise Error("package_budget_exceeded")
        initial_package_identity = file_identity(_no_link(bundle_path))
        if not stat.S_ISREG(_no_link(bundle_path).st_mode):
            raise Error("invalid_package")
        if bundle_path.stat().st_size != expected_size:
            raise Error("package_size_mismatch")
        actual_size, actual_sha = _hash_path(bundle_path, budget)
        if (actual_size != expected_size or actual_sha != expected_sha256 or
                file_identity(_no_link(bundle_path)) != initial_package_identity):
            raise Error("package_hash_mismatch")
        _zip_directory_precheck(bundle_path, budget)
        with zipfile.ZipFile(bundle_path, "r") as archive:
            info = archive.getinfo(MANIFEST_MEMBER)
            if info.file_size > budget.max_metadata_bytes:
                raise Error("metadata_budget_exceeded")
            with archive.open(info) as stream:
                raw = stream.read(budget.max_metadata_bytes + 1)
            manifest = _validated_manifest(raw, budget)
            members = _members(archive, manifest, budget)
            logical = sum(e.get("size", 0) for e in manifest["entries"])
            budget.space(destination.parent, logical + len(raw) + 1024 * len(manifest["entries"]))
            for entry in manifest["entries"]:
                budget.check()
                target = stage.joinpath(*entry["path"].split("/"))
                safe_chain(target.parent, stage)
                if entry["type"] == "directory":
                    target.mkdir(mode=0o700)
                    continue
                info = members[PAYLOAD_PREFIX + entry["path"]]
                hasher = hashlib.sha256()
                count = 0
                with archive.open(info, "r") as incoming:
                    with target.open("xb") as outgoing:
                        while True:
                            budget.check()
                            chunk = incoming.read(BLOCK_SIZE)
                            if not chunk:
                                break
                            count += len(chunk)
                            if count > entry["size"] or count > budget.max_logical_bytes:
                                raise Error("logical_budget_exceeded")
                            budget.space(destination.parent, len(chunk))
                            outgoing.write(chunk)
                            hasher.update(chunk)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                if count != entry["size"] or hasher.hexdigest() != entry["sha256"]:
                    raise Error("tree_content_mismatch")
            verified = verify_tree(stage, manifest, budget, stage_identity)
            closing_size, closing_sha = _hash_path(bundle_path, budget)
            if (closing_size != expected_size or closing_sha != expected_sha256 or
                    file_identity(_no_link(bundle_path)) != initial_package_identity):
                raise Error("package_changed")
            if directory_identity(destination.parent) != parent_identity:
                raise Error("destination_parent_changed")
            return {"staging_directory": str(stage), "staging_identity": stage_identity,
                    "parent_identity": parent_identity, "manifest": manifest,
                    "manifest_sha256": verified["manifest_sha256"],
                    "package_size": expected_size, "package_sha256": expected_sha256}
    except Error as exc:
        raise Error(exc.code, **context) from exc
    except (OSError, ValueError, KeyError, EOFError, struct.error,
            zipfile.BadZipFile, RuntimeError) as exc:
        raise Error("invalid_package", **context) from exc

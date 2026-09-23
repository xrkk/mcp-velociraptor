"""Explicit, fail-closed local transfer policy and path authorization."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .errors import TransferContentError as Error
from .manifest import Budget, _no_link, check_relative, directory_identity, file_identity, safe_chain

POLICY_SCHEMA = "velo.transfer.policy.v1"
MAX_POLICY_BYTES = 65536
DEFAULT_CHUNK_BYTES = 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_LIMITS = frozenset(("max_files", "max_metadata_bytes", "max_logical_bytes",
                     "max_package_bytes", "min_free_bytes", "max_chunk_bytes",
                     "max_state_bytes", "max_duration_seconds"))
AclVerifier = Callable[[Path, str], bool]


@dataclass(frozen=True)
class PolicyStatus:
    enabled: bool
    reason: str
    policy: Policy | None = None


@dataclass(frozen=True)
class Policy:
    policy_id: str
    expected_vm_uuid: str
    read_roots: tuple[Path, ...]
    write_roots: tuple[Path, ...]
    work_root: Path
    limits: dict[str, int]
    policy_path: Path
    policy_identity: dict[str, int]
    policy_sha256: str
    root_identities: tuple[tuple[str, dict[str, int]], ...]
    acl_verifier: AclVerifier | None = None

    def revalidate(self) -> None:
        safe_chain(self.policy_path, self.policy_path.parent)
        info = _no_link(self.policy_path)
        if file_identity(info) != self.policy_identity:
            raise Error("policy_changed")
        _protected(self.policy_path, "policy", self.acl_verifier)
        with self.policy_path.open("rb") as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES or hashlib.sha256(raw).hexdigest() != self.policy_sha256:
            raise Error("policy_changed")
        for name, identity in self.root_identities:
            root = Path(name)
            safe_chain(root, root)
            if directory_identity(root) != identity:
                raise Error("root_changed")
        _protected(self.work_root, "work", self.acl_verifier)

    def resolve_local(self, path: str | Path, purpose: str, *, allow_missing_leaf: bool = False) -> Path:
        if purpose not in ("read", "write", "work"):
            raise Error("invalid_path_purpose")
        self.revalidate()
        candidate = _absolute(path)
        roots = {"read": self.read_roots, "write": self.write_roots,
                 "work": (self.work_root,)}[purpose]
        for root in roots:
            if candidate.is_relative_to(root):
                safe_chain(candidate, root, allow_missing_leaf=allow_missing_leaf)
                if candidate.exists() and candidate.is_dir() and purpose == "read":
                    return candidate
                return candidate
        raise Error("path_outside_root")

    def content_budget(self, *, deadline_monotonic: float, check_cancel=None) -> Budget:
        self.revalidate()
        limits = self.limits
        validate_deadline(deadline_monotonic, limits["max_duration_seconds"])
        return Budget(limits["max_files"], limits["max_metadata_bytes"],
                      limits["max_logical_bytes"], limits["max_package_bytes"],
                      limits["min_free_bytes"], deadline_monotonic,
                      check_cancel=check_cancel)


def validate_deadline(value, max_duration: int) -> None:
    if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)):
        raise Error("invalid_deadline")
    now = time.monotonic()
    if value <= now:
        raise Error("deadline_exceeded")
    if value > now + max_duration:
        raise Error("deadline_outside_policy")


def _absolute(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise Error("invalid_local_path")
    raw = str(value)
    if raw.startswith(("\\\\?\\", "\\\\.\\")):
        raise Error("invalid_local_path")
    path = Path(raw)
    if not path.is_absolute() or "\x00" in raw or any(part in (".", "..") for part in path.parts):
        raise Error("invalid_local_path")
    # Do not normalize away spelling that could hide an ancestor or a Windows alias.
    if str(path) != raw.rstrip(os.sep) and raw != os.sep:
        raise Error("invalid_local_path")
    for part in path.parts[1:]:
        check_relative(part)
    return path


def _protected(path: Path, kind: str, verifier: AclVerifier | None) -> None:
    if os.name == "nt":
        if verifier is None or verifier(path, kind) is not True:
            raise Error("windows_acl_not_verified")
    else:
        info = _no_link(path)
        if info.st_mode & 0o022:
            raise Error("insecure_permissions")
        trusted = {0, os.geteuid()}
        if info.st_uid not in trusted:
            raise Error("untrusted_owner")
        # Every ancestor can replace its child. A sticky directory is safe only
        # when both it and the protected child are owned by a trusted principal.
        child = info
        for ancestor in path.parents:
            parent = _no_link(ancestor)
            if parent.st_uid not in trusted:
                raise Error("untrusted_owner")
            if parent.st_mode & 0o022:
                if not parent.st_mode & stat.S_ISVTX or child.st_uid not in trusted:
                    raise Error("insecure_permissions")
            child = parent


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Error("duplicate_policy_key")
        result[key] = value
    return result


def _bad_constant(_):
    raise Error("invalid_policy")


def _roots(values, kind: str, verifier: AclVerifier | None) -> tuple[Path, ...]:
    if not isinstance(values, list) or not values or len(values) > 32:
        raise Error("invalid_policy")
    roots = []
    for raw in values:
        root = _absolute(raw)
        safe_chain(root, root)
        directory_identity(root)
        roots.append(root)
    if len(set(roots)) != len(roots):
        raise Error("invalid_policy")
    return tuple(roots)


def _uuid(value: object) -> str:
    if not isinstance(value, str):
        raise Error("invalid_vm_identity")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise Error("invalid_vm_identity") from exc
    if str(parsed) != value:
        raise Error("invalid_vm_identity")
    return value


def load_policy(path: str | Path | None = None, *, observation: dict | None = None,
                guest: bool = True, verify_windows_acl: AclVerifier | None = None) -> PolicyStatus:
    """Missing explicit configuration disables transfer; invalid configuration raises."""
    if path is None:
        path = os.environ.get("VELOCIRAPTOR_TRANSFER_POLICY")
    if path is None or path == "":
        return PolicyStatus(False, "not_configured")
    policy_path = _absolute(path)
    safe_chain(policy_path, policy_path.parent)
    info = _no_link(policy_path)
    if not stat.S_ISREG(info.st_mode):
        raise Error("invalid_policy_file")
    _protected(policy_path, "policy", verify_windows_acl)
    if info.st_size > MAX_POLICY_BYTES:
        raise Error("policy_too_large")
    with policy_path.open("rb") as stream:
        raw = stream.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise Error("policy_too_large")
    if file_identity(_no_link(policy_path)) != file_identity(info):
        raise Error("policy_changed")
    try:
        data = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_bad_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Error("invalid_policy") from exc
    if (not isinstance(data, dict) or set(data) !=
            {"schema", "policy_id", "expected_vm_uuid", "read_roots", "write_roots",
             "work_root", "limits"} or data["schema"] != POLICY_SCHEMA or
            not isinstance(data["policy_id"], str) or not _ID.fullmatch(data["policy_id"])):
        raise Error("invalid_policy")
    expected_uuid = _uuid(data["expected_vm_uuid"])
    limits = data["limits"]
    if not isinstance(limits, dict) or set(limits) not in (_LIMITS, _LIMITS - {"max_chunk_bytes"}):
        raise Error("invalid_policy")
    limits = dict(limits)
    limits.setdefault("max_chunk_bytes", DEFAULT_CHUNK_BYTES)
    if any(type(value) is not int or value < 0 or value > 2**63 - 1
           for value in limits.values()):
        raise Error("invalid_policy")
    if (min(limits[key] for key in _LIMITS - {"min_free_bytes", "max_logical_bytes"}) <= 0 or
            limits["max_chunk_bytes"] > limits["max_package_bytes"] or
            limits["max_duration_seconds"] > 604800):
        raise Error("invalid_policy")
    read_roots = _roots(data["read_roots"], "read", verify_windows_acl)
    write_roots = _roots(data["write_roots"], "write", verify_windows_acl)
    work_root = _absolute(data["work_root"])
    safe_chain(work_root, work_root)
    directory_identity(work_root)
    _protected(work_root, "work", verify_windows_acl)
    if not isinstance(observation, dict) or set(observation) != {"os_name", "vm_uuid"}:
        raise Error("vm_identity_unavailable")
    if (guest and observation["os_name"] != "Windows") or \
       (not guest and observation["os_name"] not in ("Windows", "Linux", "Darwin")):
        raise Error("wrong_operating_system")
    if _uuid(observation["vm_uuid"]) != expected_uuid:
        raise Error("vm_identity_mismatch")
    root_identities = tuple((str(root), directory_identity(root))
                            for root in (*read_roots, *write_roots, work_root))
    policy = Policy(data["policy_id"], expected_uuid, read_roots, write_roots, work_root,
                    dict(limits), policy_path, file_identity(info),
                    hashlib.sha256(raw).hexdigest(), root_identities, verify_windows_acl)
    policy.revalidate()
    return PolicyStatus(True, "enabled", policy)

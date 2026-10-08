"""Bounded private diagnostics for errors occurring before a worker exists."""

import os
import re
import stat
import time

from .errors import TransferContentError, error_diagnostic
from .manifest import canonical_json, safe_chain
from .storage import TaskStore, _sync_directory

MAX_LOG_BYTES = 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def record_operation_error(service, operation, arguments, exc):
    """Never create a transfer task or log raw arguments, tokens or file bytes."""
    record = {"schema": "velo.transfer.operation-error.v1", "operation": operation,
              "time_ns": time.time_ns(), "error": error_diagnostic(exc)}
    binding = arguments.get("request", arguments)
    if isinstance(binding, dict):
        for key, pattern in (("transfer_id", _ID), ("request_digest", _HEX)):
            value = binding.get(key)
            if isinstance(value, str) and pattern.fullmatch(value):
                record[key] = value
    policy = getattr(service, "policy", None)
    if policy is None:
        return
    # The existing writer lock, root revalidation and private ACL checks also
    # protect failures rejected before task/worker registration.
    store = TaskStore(policy)
    with store.writer():
        path = policy.work_root / "operation-errors.jsonl"
        safe_chain(path, policy.work_root, allow_missing_leaf=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise TransferContentError("invalid_state")
            store._private(path, "state")
            if os.stat(path, follow_symlinks=False).st_ino != info.st_ino:
                raise TransferContentError("state_changed")
            raw = canonical_json(record) + b"\n"
            if len(raw) > 256 * 1024 or info.st_size + len(raw) > MAX_LOG_BYTES:
                raise TransferContentError("metadata_budget_exceeded")
            with os.fdopen(fd, "ab", closefd=False) as output:
                output.write(raw)
                output.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        _sync_directory(path.parent)

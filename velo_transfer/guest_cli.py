"""Fixed Windows helper for a protected request file; no arbitrary execution."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from .errors import TransferContentError as Error
from .guest_service import GuestTransferService, _strict_json
from .manifest import canonical_json, safe_chain

_MAX_REQUEST = 4 * 1024 * 1024
_MAX_RESPONSE = 4 * 1024 * 1024
_OPERATIONS = {
    "transfer_capabilities": frozenset(),
    "transfer_begin": frozenset(("request",)),
    "transfer_status": frozenset(("transfer_id", "request_digest")),
    "transfer_chunk": frozenset(("transfer_id", "request_digest", "offset", "count",
                                  "data_base64", "chunk_sha256")),
    "transfer_finish": frozenset(("transfer_id", "request_digest", "action",
                                   "prepare_receipt", "source_validation_receipt", "publication_receipt")),
    "transfer_abort": frozenset(("transfer_id", "request_digest")),
}


def _request_path(value: str, service: GuestTransferService) -> Path:
    root = service.policy.resolve_local(service.policy.work_root / "requests", "work")
    path = service.policy.resolve_local(value, "work")
    if not path.is_relative_to(root) or path == root:
        raise Error("request_path_outside_root")
    safe_chain(path, root)
    if os.name == "nt":
        service.acl(root, "tasks")
        service.acl(path, "state")
    elif root.stat().st_mode & 0o077 or path.stat().st_mode & 0o077:
        raise Error("insecure_permissions")
    return path


def invoke(request_file: str, service: GuestTransferService):
    path = _request_path(request_file, service)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_REQUEST:
        raise Error("request_too_large")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                 getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Error("request_changed")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(_MAX_REQUEST + 1)
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise Error("request_changed")
    finally:
        os.close(fd)
    payload = _strict_json(raw, _MAX_REQUEST)
    if not isinstance(payload, dict) or set(payload) != {"operation", "arguments"}:
        raise Error("invalid_request")
    name, args = payload["operation"], payload["arguments"]
    if not isinstance(name, str) or name not in _OPERATIONS or not isinstance(args, dict):
        raise Error("invalid_operation")
    required = _OPERATIONS[name]
    if name == "transfer_chunk":
        if set(args) not in (required, required - {"data_base64", "chunk_sha256"}):
            raise Error("invalid_request")
    elif name == "transfer_finish":
        if not {"transfer_id", "request_digest", "action"}.issubset(args) or not set(args).issubset(required):
            raise Error("invalid_request")
    elif set(args) != required:
        raise Error("invalid_request")
    result = getattr(service, name)(**args)
    if len(canonical_json(result)) > _MAX_RESPONSE:
        raise Error("response_too_large")
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 5 and args[0] == "--internal-worker":
        _, transfer_id, digest, job, nonce = args
        try:
            service = GuestTransferService()
            service._child(transfer_id, digest, job, nonce, sys.stdin.buffer)
            return 0
        except Exception:
            return 3
    if len(args) != 2 or args[0] != "--request-file":
        return 2
    try:
        service = GuestTransferService()
        result = invoke(args[1], service)
        sys.stdout.buffer.write(canonical_json({"status": "success", "result": result}) + b"\n")
        return 0
    except Error as exc:
        output = {"status": "error", "error": exc.code}
        sys.stdout.buffer.write(canonical_json(output) + b"\n")
        return 4
    except Exception:
        sys.stdout.buffer.write(b'{"status":"error","error":"internal_error"}\n')
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only Windows VM identity and conservative file ACL gates.

Native calls are loaded only on Windows. Test-only readers are explicitly injected;
production construction always uses GetNamedSecurityInfoW and the process token.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .errors import TransferContentError as Error

_IDENTITY_SCRIPT = ("$ErrorActionPreference='Stop';"
                    "$p=@(Get-CimInstance -ClassName Win32_ComputerSystemProduct);"
                    "$o=@(Get-CimInstance -ClassName Win32_OperatingSystem);"
                    "$u=@($p | ForEach-Object { $_.UUID });"
                    "$b=@($o | ForEach-Object { if ($null -eq $_.LastBootUpTime) { $null } "
                    "else { $_.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') } });"
                    "[pscustomobject]@{uuids=$u;boots=$b} | ConvertTo-Json -Compress -Depth 3")
_BOOT = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z\Z")
_SID = re.compile(r"S-1-(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}\Z")
_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_MAX_OUTPUT = 4096
_MAX_ACL_BYTES = 1 << 20
_MAX_ACES = 4096

# Standard and file/directory-specific rights that can change or remove evidence.
_WRITE = (0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100 |
          0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000)
_READ = 0x0001 | 0x0008 | 0x0080 | 0x00020000 | 0x80000000 | 0x10000000
_KNOWN = 0x001F01FF | 0xF0000000
_PRIVATE_KINDS = frozenset(("work", "tasks", "task", "lock", "state", "stage", "parent"))
_PUBLIC_KINDS = frozenset(("policy", "read_root", "write_root"))


@dataclass(frozen=True)
class WindowsObservation:
    os_name: str
    vm_uuid: str
    boot_identity: str

    def for_policy(self) -> dict[str, str]:
        return {"os_name": self.os_name, "vm_uuid": self.vm_uuid}


@dataclass(frozen=True)
class Ace:
    ace_type: int
    flags: int
    mask: int
    sid: str


@dataclass(frozen=True)
class AclSnapshot:
    owner_sid: str
    aces: tuple[Ace, ...]
    dacl_present: bool = True


def _require_windows() -> None:
    if os.name != "nt":
        raise Error("windows_platform_unsupported")


def _strict_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Error("windows_identity_invalid")
        result[key] = value
    return result


def _reject_constant(_):
    raise Error("windows_identity_invalid")


def parse_identity(raw: bytes) -> WindowsObservation:
    """Validate only the two fixed CIM fields; never accept a guessed VMX UUID."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_OUTPUT:
        raise Error("windows_identity_invalid")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_strict_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Error("windows_identity_invalid") from exc
    if not isinstance(value, dict) or set(value) != {"uuids", "boots"}:
        raise Error("windows_identity_invalid")
    uuids, boots = value["uuids"], value["boots"]
    if (not isinstance(uuids, list) or len(uuids) != 1 or
            not isinstance(boots, list) or len(boots) != 1):
        raise Error("windows_identity_invalid")
    raw_uuid, boot = uuids[0], boots[0]
    if not isinstance(raw_uuid, str) or not isinstance(boot, str) or not _BOOT.fullmatch(boot):
        raise Error("windows_identity_invalid")
    try:
        parsed_uuid = uuid.UUID(raw_uuid)
        parsed_boot = dt.datetime.fromisoformat(boot.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise Error("windows_identity_invalid") from exc
    if (parsed_uuid.int == 0 or parsed_uuid.int == (1 << 128) - 1 or
            parsed_boot.year < 2000 or parsed_boot > dt.datetime.now(dt.timezone.utc) +
            dt.timedelta(minutes=5)):
        raise Error("windows_identity_invalid")
    canonical_uuid = str(parsed_uuid)
    return WindowsObservation("Windows", canonical_uuid,
        "winboot-" + hashlib.sha256(boot.encode("ascii")).hexdigest())


def _capture_bounded(argv: list[str], *, timeout_seconds: float, max_output: int) -> bytes:
    """Drain both pipes in bounded reader threads and always reap our child."""
    if not 0 < timeout_seconds <= 30 or not 0 < max_output <= _MAX_OUTPUT:
        raise Error("windows_identity_invalid")
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False)
    except OSError as exc:
        raise Error("windows_identity_unavailable") from exc
    pieces: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    threads = []

    def drain(stream, name):
        try:
            while True:
                chunk = stream.read1(1024) if hasattr(stream, "read1") else stream.read(1024)
                if not chunk:
                    break
                data = pieces[name]
                remaining = max_output + 1 - len(data)
                if remaining > 0:
                    data.extend(chunk[:remaining])
                if len(chunk) > remaining or len(data) > max_output:
                    overflow.set()
        finally:
            stream.close()

    try:
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            thread = threading.Thread(target=drain, args=(stream, name), daemon=False)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout_seconds
        while proc.poll() is None:
            if overflow.is_set():
                raise Error("windows_identity_output_limit")
            if time.monotonic() >= deadline:
                raise Error("windows_identity_timeout")
            time.sleep(0.01)
        for thread in threads:
            thread.join(timeout=2)
            if thread.is_alive():
                raise Error("windows_identity_unavailable")
        if overflow.is_set():
            raise Error("windows_identity_output_limit")
        if proc.returncode != 0:
            raise Error("windows_identity_command_failed")
        return bytes(pieces["stdout"])
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            raise Error("windows_identity_unavailable")


def _system_powershell() -> str:
    _require_windows()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise Error("windows_identity_unavailable")
    executable = Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file() or executable.is_symlink():
        raise Error("windows_identity_unavailable")
    return str(executable)


def observe_windows(*, timeout_seconds: float = 10.0) -> WindowsObservation:
    _require_windows()
    executable = _system_powershell()
    raw = _capture_bounded([executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                            "-Command", _IDENTITY_SCRIPT], timeout_seconds=timeout_seconds,
                           max_output=_MAX_OUTPUT)
    return parse_identity(raw)


def _canonical_sid(value: str) -> str:
    if not isinstance(value, str) or len(value) > 184 or not _SID.fullmatch(value):
        raise Error("invalid_trusted_sid")
    numbers = [int(part) for part in value.split("-")[2:]]
    if numbers[0] > (1 << 48) - 1 or any(number > (1 << 32) - 1 for number in numbers[1:]):
        raise Error("invalid_trusted_sid")
    return value


def _decode_ace(raw: bytes) -> Ace:
    if not isinstance(raw, bytes) or len(raw) < 16:
        raise Error("windows_acl_malformed")
    ace_type, flags, size = struct.unpack_from("<BBH", raw)
    if size != len(raw) or size < 16 or size % 4 or ace_type not in (0, 1):
        raise Error("windows_acl_unsupported")
    if flags & ~0x1F or (flags & 0x08 and not flags & 0x03):
        raise Error("windows_acl_unsupported")
    mask = struct.unpack_from("<I", raw, 4)[0]
    sid_bytes = raw[8:]
    if len(sid_bytes) < 8 or sid_bytes[0] != 1 or sid_bytes[1] > 15:
        raise Error("windows_acl_malformed")
    sid_size = 8 + 4 * sid_bytes[1]
    if sid_size != len(sid_bytes):
        raise Error("windows_acl_malformed")
    authority = int.from_bytes(sid_bytes[2:8], "big")
    subauth = [struct.unpack_from("<I", sid_bytes, 8 + 4 * index)[0]
               for index in range(sid_bytes[1])]
    sid = "S-1-" + str(authority) + "".join("-" + str(number) for number in subauth)
    return Ace(ace_type, flags, mask, _canonical_sid(sid))


def _evaluate(snapshot: AclSnapshot, kind: str, trusted: frozenset[str]) -> None:
    if kind not in _PRIVATE_KINDS | _PUBLIC_KINDS | {"ancestor"}:
        raise Error("windows_acl_kind_invalid")
    if (not isinstance(snapshot, AclSnapshot) or snapshot.dacl_present is not True or
            not isinstance(snapshot.aces, tuple) or not snapshot.aces):
        raise Error("windows_acl_unprotected")
    if snapshot.owner_sid not in trusted:
        raise Error("windows_acl_untrusted_owner")
    for ace in snapshot.aces:
        if ace.ace_type not in (0, 1) or ace.flags & ~0x1F:
            raise Error("windows_acl_unsupported")
        if type(ace.mask) is not int or ace.mask < 0 or ace.mask & ~_KNOWN:
            raise Error("windows_acl_unsupported")
        if ace.sid in trusted or ace.ace_type == 1:
            continue
        # Deny ACEs never cancel an untrusted allow. Inherit-only grants are
        # considered too: they may become effective on a new child object.
        if ace.mask & _WRITE:
            raise Error("windows_acl_untrusted_write")
        if kind in _PRIVATE_KINDS and ace.mask & _READ:
            raise Error("windows_acl_untrusted_read")


def _native_apis():
    _require_windows()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    return advapi, kernel


def _sid_from_native(pointer: int, advapi, kernel) -> str:
    if not pointer:
        raise Error("windows_acl_malformed")
    is_valid = advapi.IsValidSid
    is_valid.argtypes = [ctypes.c_void_p]
    is_valid.restype = ctypes.c_int
    if not is_valid(pointer):
        raise Error("windows_acl_malformed")
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = ctypes.c_int
    output = ctypes.c_void_p()
    if not convert(pointer, ctypes.byref(output)) or not output.value:
        raise Error("windows_acl_unavailable")
    try:
        return _canonical_sid(ctypes.wstring_at(output.value))
    finally:
        free = kernel.LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(output)


def current_process_sid() -> str:
    """Read TokenUser from this process; no impersonation or account mutation."""
    advapi, kernel = _native_apis()
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    open_token = advapi.OpenProcessToken
    open_token.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
    open_token.restype = ctypes.c_int
    handle = ctypes.c_void_p()
    if not open_token(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(handle)):
        raise Error("windows_token_unavailable")
    try:
        get_info = advapi.GetTokenInformation
        get_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                             ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
        get_info.restype = ctypes.c_int
        length = ctypes.c_uint()
        get_info(handle, 1, None, 0, ctypes.byref(length))
        if not ctypes.sizeof(ctypes.c_void_p) <= length.value <= 4096:
            raise Error("windows_token_unavailable")
        buffer = ctypes.create_string_buffer(length.value)
        if not get_info(handle, 1, buffer, length.value, ctypes.byref(length)):
            raise Error("windows_token_unavailable")
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        base = ctypes.addressof(buffer)
        get_length = advapi.GetLengthSid
        get_length.argtypes = [ctypes.c_void_p]
        get_length.restype = ctypes.c_uint
        if (not sid_pointer or sid_pointer < base or sid_pointer + 8 > base + len(buffer)):
            raise Error("windows_token_unavailable")
        sid_length = get_length(sid_pointer)
        if sid_length < 8 or sid_pointer + sid_length > base + len(buffer):
            raise Error("windows_token_unavailable")
        return _sid_from_native(sid_pointer, advapi, kernel)
    finally:
        kernel.CloseHandle(handle)


class _AclSize(ctypes.Structure):
    _fields_ = [("AceCount", ctypes.c_uint), ("AclBytesInUse", ctypes.c_uint),
                ("AclBytesFree", ctypes.c_uint)]


def _read_security(path: Path) -> AclSnapshot:
    advapi, kernel = _native_apis()
    get_info = advapi.GetNamedSecurityInfoW
    get_info.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint,
                         ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_void_p)]
    get_info.restype = ctypes.c_uint
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    code = get_info(str(path), 1, 0x1 | 0x4, ctypes.byref(owner), None,
                    ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if code:
        raise Error("windows_acl_unavailable", winerror=int(code))
    try:
        if not descriptor.value or not owner.value or not dacl.value:
            raise Error("windows_acl_unprotected")
        get_length = advapi.GetSecurityDescriptorLength
        get_length.argtypes = [ctypes.c_void_p]
        get_length.restype = ctypes.c_uint
        descriptor_size = get_length(descriptor)
        if descriptor_size < 20 or descriptor_size > _MAX_ACL_BYTES + 65536:
            raise Error("windows_acl_malformed")
        descriptor_end = descriptor.value + descriptor_size
        if (not (descriptor.value <= owner.value and owner.value + 8 <= descriptor_end) or
                not (descriptor.value <= dacl.value and dacl.value + 8 <= descriptor_end)):
            raise Error("windows_acl_malformed")
        owner_head = ctypes.string_at(owner.value, 8)
        owner_size = 8 + 4 * owner_head[1]
        if owner_head[0] != 1 or owner_head[1] > 15 or owner.value + owner_size > descriptor_end:
            raise Error("windows_acl_malformed")
        owner_sid = _sid_from_native(owner.value, advapi, kernel)
        acl_info = advapi.GetAclInformation
        acl_info.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
        acl_info.restype = ctypes.c_int
        size = _AclSize()
        if not acl_info(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
            raise Error("windows_acl_malformed")
        if (size.AceCount > _MAX_ACES or size.AclBytesInUse < 8 or
                size.AclBytesInUse > _MAX_ACL_BYTES or
                dacl.value + size.AclBytesInUse > descriptor_end):
            raise Error("windows_acl_malformed")
        get_ace = advapi.GetAce
        get_ace.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
        get_ace.restype = ctypes.c_int
        aces = []
        start = dacl.value
        end = start + size.AclBytesInUse
        for index in range(size.AceCount):
            pointer = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(pointer)) or not pointer.value:
                raise Error("windows_acl_malformed")
            address = pointer.value
            if address < start + 8 or address + 4 > end:
                raise Error("windows_acl_malformed")
            header = ctypes.string_at(address, 4)
            ace_size = struct.unpack_from("<H", header, 2)[0]
            if ace_size < 16 or address + ace_size > end:
                raise Error("windows_acl_malformed")
            aces.append(_decode_ace(ctypes.string_at(address, ace_size)))
        return AclSnapshot(owner_sid, tuple(aces))
    finally:
        if descriptor.value:
            free = kernel.LocalFree
            free.argtypes = [ctypes.c_void_p]
            free.restype = ctypes.c_void_p
            free(descriptor)


def _fingerprint(path: Path) -> tuple[int, int, int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Error("windows_acl_path_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise Error("link_or_reparse")
    return info.st_dev, info.st_ino, info.st_mode, getattr(info, "st_file_attributes", 0)


class WindowsAclVerifier:
    """Conservative read-only DACL verifier for policy/store/content callbacks."""

    def __init__(self, extra_trusted_sids=(), *, _reader: Callable[[Path], AclSnapshot] | None = None,
                 _current_sid: str | None = None):
        extras = tuple(_canonical_sid(item) for item in extra_trusted_sids)
        if len(extras) > 32 or len(set(extras)) != len(extras):
            raise Error("invalid_trusted_sid")
        self._test_mode = _reader is not None or _current_sid is not None
        if self._test_mode and (_reader is None or _current_sid is None):
            raise Error("windows_acl_unavailable")
        if not self._test_mode:
            _require_windows()
        self._reader = _reader or _read_security
        self._trusted = frozenset((_SYSTEM, _ADMINS, _canonical_sid(_current_sid or current_process_sid()), *extras))

    def __call__(self, path: str | Path, kind: str) -> bool:
        if not self._test_mode:
            _require_windows()
        if kind not in _PRIVATE_KINDS | _PUBLIC_KINDS:
            raise Error("windows_acl_kind_invalid")
        candidate = Path(path)
        raw = str(path)
        if (not candidate.is_absolute() or "\x00" in raw or len(raw) > 32767 or
                any(part in (".", "..") for part in candidate.parts) or
                raw.startswith(("\\\\?\\", "\\\\.\\"))):
            raise Error("windows_acl_path_invalid")
        chain = list(reversed(candidate.parents)) + [candidate]
        if len(chain) > 64:
            raise Error("windows_acl_path_invalid")
        before = []
        snapshots = []
        for item in chain:
            fingerprint = _fingerprint(item)
            snapshot = self._reader(item)
            _evaluate(snapshot, kind if item == candidate else "ancestor", self._trusted)
            before.append(fingerprint)
            snapshots.append(snapshot)
        for item, fingerprint, snapshot in zip(chain, before, snapshots):
            if _fingerprint(item) != fingerprint:
                raise Error("windows_acl_path_changed")
            after = self._reader(item)
            if after != snapshot:
                raise Error("windows_acl_changed")
        return True

    def content_callback(self, stage: str | Path, parent: str | Path,
                         destination: str | Path | None = None):
        """One-argument callback for stage, parent and post-publish destination."""
        stage_path, parent_path = Path(stage), Path(parent)
        destination_path = Path(destination) if destination is not None else None
        if (stage_path.parent != parent_path or
                (destination_path is not None and destination_path.parent != parent_path)):
            raise Error("windows_acl_path_invalid")

        def verify(path: Path) -> bool:
            candidate = Path(path)
            if candidate == stage_path:
                return self(candidate, "stage")
            if candidate == parent_path:
                return self(candidate, "parent")
            if destination_path is not None and candidate == destination_path:
                return self(candidate, "stage")
            raise Error("windows_acl_path_invalid")

        return verify

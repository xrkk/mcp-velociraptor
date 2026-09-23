"""Process identity and bounded root lease for guest transfer jobs."""

from __future__ import annotations

import ctypes
import os
import signal
import time
from pathlib import Path

from .errors import TransferContentError as Error


def process_birth(pid: int) -> str:
    """Kernel process creation identity; a PID alone is never an ownership proof."""
    if type(pid) is not int or pid <= 0:
        raise Error("worker_identity_unavailable")
    if os.name == "posix" and Path(f"/proc/{pid}/stat").exists():
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            return "linux-" + raw.rsplit(") ", 1)[1].split()[19]
        except (OSError, IndexError, ValueError) as exc:
            raise Error("worker_identity_unavailable") from exc
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise Error("worker_identity_unavailable")
        try:
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in values)):
                raise Error("worker_identity_unavailable")
            birth = values[0]
            return "windows-" + str((birth.dwHighDateTime << 32) | birth.dwLowDateTime)
        finally:
            kernel.CloseHandle(handle)
    raise Error("worker_identity_unavailable")


def same_process(pid: int, birth: str) -> bool:
    """Return false only for proven absence, exit or identity mismatch, not query failure."""
    if type(pid) is not int or pid <= 0 or not isinstance(birth, str):
        raise Error("worker_identity_unavailable")
    if os.name == "posix":
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            values = raw.rsplit(") ", 1)[1].split()
            return "linux-" + values[19] == birth and values[0] != "Z"
        except FileNotFoundError:
            return False
        except (OSError, IndexError, ValueError) as exc:
            raise Error("worker_identity_unavailable") from exc
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: no such PID.
                return False
            raise Error("worker_identity_unavailable")
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)):
                raise Error("worker_identity_unavailable")
            created = times[0]
            if "windows-" + str((created.dwHighDateTime << 32) | created.dwLowDateTime) != birth:
                return False
            waited = kernel.WaitForSingleObject(handle, 0)
            if waited == 0:
                return False
            if waited == 0x102:
                return True
            raise Error("worker_identity_unavailable")
        finally:
            kernel.CloseHandle(handle)
    raise Error("worker_platform_unsupported")


def terminate_verified(pid: int, birth: str, *, timeout: float = 3.0) -> bool:
    """Stop only a kernel-pinned process with the persisted creation identity."""
    if not 0 < timeout <= 10:
        raise Error("invalid_worker_timeout")
    if not same_process(pid, birth):
        return False
    if os.name == "posix":
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise Error("worker_signal_unavailable")
        fd = os.pidfd_open(pid, 0)
        try:
            if process_birth(pid) != birth:
                raise Error("worker_ownership_mismatch")
            deadline = time.monotonic() + timeout
            for sig in (signal.SIGTERM, signal.SIGKILL):
                if not same_process(pid, birth):
                    return True
                signal.pidfd_send_signal(fd, sig, None, 0)
                grace = min(deadline, time.monotonic() + (0.7 if sig == signal.SIGTERM else timeout))
                while time.monotonic() < grace:
                    if not same_process(pid, birth):
                        return True
                    time.sleep(0.02)
            return not same_process(pid, birth)
        finally:
            os.close(fd)
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        handle = kernel.OpenProcess(0x1000 | 0x100000 | 0x0001, False, pid)
        if not handle:
            return False
        try:
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in values)):
                raise Error("worker_identity_unavailable")
            created = values[0]
            actual = "windows-" + str((created.dwHighDateTime << 32) | created.dwLowDateTime)
            if actual != birth:
                raise Error("worker_ownership_mismatch")
            if kernel.WaitForSingleObject(handle, 0) == 0:
                return True
            if not kernel.TerminateProcess(handle, 124):
                raise Error("worker_stop_failed")
            return kernel.WaitForSingleObject(handle, int(timeout * 1000)) == 0
        finally:
            kernel.CloseHandle(handle)
    raise Error("worker_platform_unsupported")


class RootLease:
    def __init__(self, root: Path):
        self.path = root / ".guest-worker.lock"
        self.fd: int | None = None

    def acquire(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                raise Error("worker_lock_unavailable")
        except (OSError, BlockingIOError) as exc:
            os.close(fd)
            raise Error("worker_busy") from exc
        self.fd = fd

    def release(self) -> None:
        if self.fd is None:
            return
        fd, self.fd = self.fd, None
        if os.name == "posix":
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        os.close(fd)


def read_activation(stream, nonce: str, *, timeout: float = 15.0) -> None:
    """No job writes before the parent has persisted the exact owner."""
    deadline = time.monotonic() + timeout
    expected = (nonce + "\n").encode("ascii")
    held = bytearray()
    fd = stream.fileno()
    while time.monotonic() < deadline:
        if os.name == "posix":
            import select
            ready, _, _ = select.select([fd], [], [], min(0.2, deadline - time.monotonic()))
            if not ready:
                continue
            available = len(expected) - len(held)
        elif os.name == "nt":
            import msvcrt
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            peek = kernel.PeekNamedPipe
            peek.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
            peek.restype = ctypes.c_int
            count = ctypes.c_ulong()
            if not peek(msvcrt.get_osfhandle(fd), None, 0, None, ctypes.byref(count), None):
                raise Error("worker_activation_failed")
            if count.value == 0:
                time.sleep(min(0.02, deadline - time.monotonic()))
                continue
            available = min(count.value, len(expected) - len(held))
        else:
            raise Error("worker_platform_unsupported")
        part = os.read(fd, available)
        if not part:
            raise Error("worker_activation_failed")
        held.extend(part)
        if not expected.startswith(held):
            raise Error("worker_activation_failed")
        if held == expected:
            return
    raise Error("worker_activation_timeout")

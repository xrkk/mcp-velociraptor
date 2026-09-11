"""Thin Windows service host for the formal MCP bridge entry.

python.exe is not a service program, so the SCM times it out.  This host
speaks the minimal service control protocol through ctypes, loads the
deployer-protected environment file referenced by VELOCIRAPTOR_ENV_FILE,
and then runs the very same bridge entrypoint (mcp_velociraptor_bridge.main)
that stdio testing uses -- no second server, no separate business path.

Deployment component only; not imported by the product or the tests.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_NAME = "mcp-velociraptor"
SERVICE_STATUS = {
    "STOPPED": 0x00000001,
    "START_PENDING": 0x00000002,
    "RUNNING": 0x00000004,
    "STOP_PENDING": 0x00000003,
}

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class SERVICE_STATUS_STRUCT(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", ctypes.WINFUNCTYPE(None, wintypes.DWORD, wintypes.LPWSTR)),
    ]


_HANDLER = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID)
SERVICE_STATUS_HANDLE = wintypes.SC_HANDLE

advapi32.RegisterServiceCtrlHandlerW.argtypes = [
    wintypes.LPCWSTR,
    _HANDLER,
]
advapi32.RegisterServiceCtrlHandlerW.restype = SERVICE_STATUS_HANDLE
advapi32.SetServiceStatus.argtypes = [SERVICE_STATUS_HANDLE, ctypes.POINTER(SERVICE_STATUS_STRUCT)]
advapi32.SetServiceStatus.restype = wintypes.BOOL
advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL

_status_handle = None
_stop_requested = False


def _report(state: int, exit_code: int = 0) -> None:
    status = SERVICE_STATUS_STRUCT()
    status.dwServiceType = 0x00000010  # SERVICE_WIN32_OWN_PROCESS
    status.dwCurrentState = state
    status.dwControlsAccepted = 0x00000001 if state == SERVICE_STATUS["RUNNING"] else 0
    status.dwWin32ExitCode = exit_code
    status.dwCheckPoint = 0
    status.dwWaitHint = 0
    advapi32.SetServiceStatus(_status_handle, ctypes.byref(status))


@_HANDLER
def _service_handler(control: int, event_type: int, event_data) -> int:
    global _stop_requested
    if control == 0x00000001:  # SERVICE_CONTROL_STOP
        _stop_requested = True
        _report(SERVICE_STATUS["STOP_PENDING"])
        return 0
    return 0


def _load_protected_env() -> None:
    env_file = os.environ.get("VELOCIRAPTOR_ENV_FILE", "").strip()
    if not env_file:
        # The SCM does not reliably merge the service Environment key for
        # ordinary win32 services; read the deployment reference directly.
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}\Environment",
            )
            try:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, index)
                    entry = str(value) if "=" in str(value) else f"{name}={value}"
                    key_part, _, value_part = entry.partition("=")
                    if key_part and key_part not in os.environ:
                        os.environ[key_part] = value_part
            finally:
                winreg.CloseKey(key)
        except OSError:
            pass
        env_file = os.environ.get("VELOCIRAPTOR_ENV_FILE", "").strip()
    if not env_file:
        return
    path = Path(env_file)
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or "=" not in stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def _service_main(argc: int, argv) -> None:
    global _status_handle
    _status_handle = advapi32.RegisterServiceCtrlHandlerW(
        SERVICE_NAME, _HANDLER(_service_handler)
    )
    _report(SERVICE_STATUS["START_PENDING"])
    try:
        _load_protected_env()
        sys.path.insert(0, str(REPO_ROOT))
        diag = {
            key: (value[:4] + "..." if key.endswith("TOKEN") else value)
            for key, value in os.environ.items()
            if key.startswith("VELOCIRAPTOR")
        }
        try:
            (REPO_ROOT / "Logs").mkdir(parents=True, exist_ok=True)
            (REPO_ROOT / "Logs" / "service-host-env.log").write_text(
                repr(diag), encoding="utf-8", errors="replace"
            )
        except OSError:
            pass
        import mcp_velociraptor_bridge as bridge

        _report(SERVICE_STATUS["RUNNING"])
        import contextlib
        import io

        stderr_capture = io.StringIO()
        with contextlib.redirect_stderr(stderr_capture):
            code = bridge.main()
        if code:
            try:
                log = REPO_ROOT / "Logs" / "service-host-error.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(
                    f"bridge main returned {code}\nstderr:\n{stderr_capture.getvalue()}\n",
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                pass
        _report(SERVICE_STATUS["STOPPED"], code or 0)
    except Exception as exc:  # noqa: BLE001 - the SCM context has no stderr
        try:
            log = REPO_ROOT / "Logs" / "service-host-error.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                f"{type(exc).__name__}: {exc}\n", encoding="utf-8", errors="replace"
            )
        except OSError:
            pass
        _report(SERVICE_STATUS["STOPPED"], 0x0000000A)
        raise


_SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, wintypes.LPWSTR)


def main() -> int:
    callback = _SERVICE_MAIN(_service_main)
    table = (SERVICE_TABLE_ENTRYW * 2)(
        SERVICE_TABLE_ENTRYW(SERVICE_NAME, callback),
        SERVICE_TABLE_ENTRYW(None, _SERVICE_MAIN()),
    )
    if not advapi32.StartServiceCtrlDispatcherW(table):
        return ctypes.get_last_error()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import json
import re
import sys
import threading
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


_SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", _SERVICE_MAIN),
    ]


_HANDLER = ctypes.WINFUNCTYPE(None, wintypes.DWORD)
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
_stop_requested = threading.Event()
_exit_code = 0

_FAILURE_MESSAGES = {
    "SERVICE_CONFIG_UNAVAILABLE": "The deployment configuration reference or file could not be loaded.",
    "BRIDGE_IMPORT_FAILED": "The bridge or a required Python dependency could not be imported.",
    "TRANSPORT_CONFIG_INVALID": "The formal HTTP configuration failed validation; check the protected deployment settings.",
    "SERVICE_TRANSPORT_INVALID": "The Windows service requires the formal HTTP transport.",
    "ARTIFACT_REGISTRY_INVALID": "Approved artifact definitions or tool schemas failed startup validation; verify the locked registry.",
    "BACKEND_INITIALIZATION_FAILED": "The Velociraptor connection or root artifact metadata read failed during startup.",
    "SERVICE_OBSERVATION_INVALID": "The read-only SDK dispatch observation could not be installed or retained.",
    "HTTP_RUNTIME_FAILED": "The HTTP server failed during startup or service execution.",
    "BRIDGE_EXIT_FAILED": "The bridge exited unsuccessfully without a classified startup failure.",
}


def _write_failure(reason: str, exit_code: int) -> None:
    # Only fixed public classifications cross this boundary, never exception
    # messages, environment values, or third-party diagnostic streams.
    if reason not in _FAILURE_MESSAGES:
        reason = "BRIDGE_EXIT_FAILED"
    try:
        log = REPO_ROOT / "Logs" / "service-host-error.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps({
            "code": reason, "message": _FAILURE_MESSAGES[reason],
            "exit_code": exit_code,
        }, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass


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
def _service_handler(control: int) -> None:
    if control == 0x00000001:  # SERVICE_CONTROL_STOP
        _stop_requested.set()
        _report(SERVICE_STATUS["STOP_PENDING"])


def _load_protected_env() -> None:
    env_file = os.environ.get("VELOCIRAPTOR_ENV_FILE", "").strip()
    if not env_file:
        # Read only the reference written by the deployment installer. Other
        # registry values must not become process environment variables.
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}\Environment",
            )
            try:
                value, kind = winreg.QueryValueEx(key, "VELOCIRAPTOR_ENV_FILE")
                if kind != winreg.REG_SZ or not isinstance(value, str):
                    raise ValueError("Invalid service configuration reference type")
                env_file = value.strip()
            finally:
                winreg.CloseKey(key)
        except OSError:
            raise RuntimeError("Service configuration reference is unavailable") from None
    if not env_file:
        raise ValueError("Service configuration reference is empty")
    path = Path(env_file)
    if not path.is_file():
        raise ValueError("Service configuration file is unavailable")
    settings = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise ValueError("Invalid service configuration entry")
        key, _, value = stripped.partition("=")
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in settings or key == "VELOCIRAPTOR_ENV_FILE":
            raise ValueError("Invalid or duplicate service configuration key")
        settings[key] = value.strip()
    required = (
        "VELOCIRAPTOR_MCP_TRANSPORT", "VELOCIRAPTOR_MCP_HOST",
        "VELOCIRAPTOR_MCP_BEARER_TOKEN", "VELOCIRAPTOR_API_CONFIG",
        "VELOCIRAPTOR_DOWNLOAD_ROOT",
    )
    if any(not settings.get(key) for key in required) or settings["VELOCIRAPTOR_MCP_TRANSPORT"] != "http":
        raise ValueError("Protected configuration lacks required formal service settings")
    if any(key in os.environ and os.environ[key] != settings[key] for key in required):
        raise ValueError("Inherited environment conflicts with protected service settings")
    os.environ["VELOCIRAPTOR_ENV_FILE"] = env_file
    for key, value in settings.items():
        if key and key not in os.environ:
            os.environ[key] = value


def _service_main(argc: int, argv) -> None:
    global _status_handle, _exit_code
    _status_handle = advapi32.RegisterServiceCtrlHandlerW(
        SERVICE_NAME, _service_handler
    )
    if not _status_handle:
        # No status can be reported without a valid SCM handle. Keep the
        # callback referenced globally for the entire dispatcher lifetime.
        _exit_code = ctypes.get_last_error() or 10
        return
    _report(SERVICE_STATUS["START_PENDING"])
    failure_reason = "SERVICE_CONFIG_UNAVAILABLE"

    def classify_failure(reason: str) -> None:
        nonlocal failure_reason
        failure_reason = reason if reason in _FAILURE_MESSAGES else "BRIDGE_EXIT_FAILED"

    try:
        _load_protected_env()
        sys.path.insert(0, str(REPO_ROOT))
        # The host can be launched by SCM from System32, where a third-party
        # ``tests`` package must never decide which local observer is loaded.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        # This wraps only the already-registered SDK POST dispatch after the
        # SDK's Host/Origin validation.  It adds no endpoint, server, or auth
        # bypass, and it is installed only after protected-env validation.
        failure_reason = "SERVICE_OBSERVATION_INVALID"
        from p05_service_observation import observe_dispatch
        # Do not persist deployment environment values, including partial
        # credentials. Configuration validation belongs to the shared entry.
        import contextlib
        # The bridge's diagnostic stream may contain third-party exception
        # text. Do not retain it in memory for the service lifetime or persist
        # it on failure: it is not a credential-safe logging interface.
        with observe_dispatch(REPO_ROOT / "Logs"):
            with open(os.devnull, "w", encoding="utf-8") as diagnostic_sink, contextlib.redirect_stderr(diagnostic_sink):
                failure_reason = "BRIDGE_IMPORT_FAILED"
                import mcp_velociraptor_bridge as bridge
                failure_reason = "HTTP_RUNTIME_FAILED"
                code = bridge.main(
                    on_ready=lambda: _report(SERVICE_STATUS["RUNNING"]),
                    stop_requested=_stop_requested.is_set,
                    on_failure=classify_failure,
                )
        if code:
            if failure_reason == "HTTP_RUNTIME_FAILED":
                failure_reason = "BRIDGE_EXIT_FAILED"
            _write_failure(failure_reason, code)
        _exit_code = code or 0
        _report(SERVICE_STATUS["STOPPED"], _exit_code)
    except BaseException:  # ctypes callbacks cannot propagate process exit
        _exit_code = 10
        _write_failure(failure_reason, _exit_code)
        _report(SERVICE_STATUS["STOPPED"], 0x0000000A)


def main() -> int:
    callback = _SERVICE_MAIN(_service_main)
    table = (SERVICE_TABLE_ENTRYW * 2)(
        SERVICE_TABLE_ENTRYW(SERVICE_NAME, callback),
        SERVICE_TABLE_ENTRYW(None, _SERVICE_MAIN()),
    )
    if not advapi32.StartServiceCtrlDispatcherW(table):
        return ctypes.get_last_error()
    return _exit_code


if __name__ == "__main__":
    raise SystemExit(main())

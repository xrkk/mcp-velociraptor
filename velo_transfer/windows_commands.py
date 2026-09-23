"""Fixed PowerShell templates for the existing Windows-MCP executor."""

from __future__ import annotations

import base64
import hashlib
import json
import re

MAX_COMMAND_CHARS = 28000
EXECUTOR_PREFIX = ("$OutputEncoding = [System.Text.Encoding]::UTF8; "
                   "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ")
STOP_ON_ERROR = "$ErrorActionPreference='Stop';"
_IDENTITY_SOURCE = (
    "using System; using System.ComponentModel; using System.Runtime.InteropServices; "
    "using Microsoft.Win32.SafeHandles; "
    "public static class VeloRequestIdentity { "
    "[StructLayout(LayoutKind.Sequential)] public struct FileTime { public uint low; public uint high; } "
    "[StructLayout(LayoutKind.Sequential)] public struct Info { "
    "public uint attributes; public FileTime created; public FileTime accessed; public FileTime written; "
    "public uint volume; public uint sizeHigh; public uint sizeLow; public uint links; "
    "public uint indexHigh; public uint indexLow; } "
    "[DllImport(\"kernel32.dll\", SetLastError=true)] "
    "private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info); "
    "[DllImport(\"kernel32.dll\", CharSet=CharSet.Unicode, SetLastError=true)] "
    "private static extern SafeFileHandle CreateFile(string path, uint access, uint share, "
    "IntPtr security, uint creation, uint flags, IntPtr template); "
    "[StructLayout(LayoutKind.Sequential)] public struct Disposition { "
    "[MarshalAs(UnmanagedType.Bool)] public bool delete; } "
    "[DllImport(\"kernel32.dll\", SetLastError=true)] "
    "private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, "
    "ref Disposition disposition, uint size); "
    "public static string Read(SafeFileHandle handle) { Info info; "
    "if (!GetFileInformationByHandle(handle, out info)) "
    "throw new Win32Exception(Marshal.GetLastWin32Error()); "
    "if (info.links != 1) throw new InvalidOperationException(\"hardlink\"); "
    "return info.volume.ToString(\"x8\") + info.indexHigh.ToString(\"x8\") "
    "+ info.indexLow.ToString(\"x8\"); } "
    "public static void DeleteOwned(string path, string expected) { "
    "using (SafeFileHandle handle = CreateFile(path, 0x10080, 0, IntPtr.Zero, 3, 0x200000, IntPtr.Zero)) { "
    "if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error()); "
    "Info info; if (!GetFileInformationByHandle(handle, out info)) "
    "throw new Win32Exception(Marshal.GetLastWin32Error()); "
    "if ((info.attributes & 0x400) != 0 || Read(handle) != expected) "
    "throw new InvalidOperationException(\"request_replaced\"); "
    "Disposition disposition = new Disposition(); disposition.delete = true; "
    "if (!SetFileInformationByHandle(handle, 4, ref disposition, "
    "(uint)Marshal.SizeOf(typeof(Disposition)))) "
    "throw new Win32Exception(Marshal.GetLastWin32Error()); } } }"
)


def literal(value: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid_literal")
    return "'" + value.replace("'", "''") + "'"


def _identity_setup() -> str:
    return "Add-Type -TypeDefinition " + literal(_IDENTITY_SOURCE) + ";"


def _checked_identity(identity: str) -> str:
    if re.fullmatch(r"[0-9a-f]{24}", identity) is None:
        raise ValueError("invalid_request_identity")
    return literal(identity)


def encoded_argv_length(script: str, *, shell: str = "powershell.exe") -> int:
    full = EXECUTOR_PREFIX + script
    encoded = base64.b64encode(full.encode("utf-16le")).decode("ascii")
    argv = [shell, "-NoProfile"]
    if shell.rsplit("\\", 1)[-1].lower().removesuffix(".exe") == "powershell":
        argv += ["-OutputFormat", "Text"]
    argv += ["-EncodedCommand", encoded]
    return sum(len(part) for part in argv) + len(argv) - 1


def bounded(script: str, *, shell: str = "powershell.exe") -> str:
    if not script.startswith(STOP_ON_ERROR):
        script = STOP_ON_ERROR + script
    if encoded_argv_length(script, shell=shell) > MAX_COMMAND_CHARS:
        raise ValueError("command_too_long")
    return script


def requests_path(work_root: str, nonce: str) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("invalid_nonce")
    return work_root.rstrip("\\") + "\\requests\\" + nonce + ".json"


def create_script(path: str) -> str:
    parent = path.rsplit("\\", 1)[0]
    return bounded(
        "$d=" + literal(parent) + ";$p=" + literal(path) + ";"
        "if(-not [IO.Directory]::Exists($d)){throw 'missing_requests'};"
        "$di=[IO.DirectoryInfo]::new($d);while($null -ne $di){if(($di.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'reparse'};$di=$di.Parent};"
        + _identity_setup() +
        "$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);"
        "try{$id=[VeloRequestIdentity]::Read($f.SafeFileHandle)}finally{$f.Dispose()};'ACK:created:'+$id")


def write_script(path: str, offset: int, raw: bytes, identity: str) -> str:
    if offset < 0 or not raw:
        raise ValueError("invalid_chunk")
    encoded = base64.b64encode(raw).decode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    return bounded(
        "$p=" + literal(path) + ";$id=" + _checked_identity(identity) + ";$o=" + str(offset) + ";$n=" + str(len(raw)) +
        ";$h=" + literal(digest) + ";$b=[Convert]::FromBase64String(" + literal(encoded) + ");"
        "$sha=[Security.Cryptography.SHA256]::Create();try{$got=([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"
        "if($b.Length -ne $n -or $got -ne $h){throw 'chunk_hash'};"
        "$fi=[IO.FileInfo]::new($p);if(-not $fi.Exists -or ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'missing_request'};"
        + _identity_setup() +
        "$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);"
        "try{if([VeloRequestIdentity]::Read($f.SafeFileHandle) -ne $id){throw 'request_replaced'};"
        "if($f.Length -eq $o){$f.Position=$o;$f.Write($b,0,$n);$f.Flush($true)}"
        "elseif($f.Length -ge ($o+$n)){$old=New-Object byte[] $n;$f.Position=$o;"
        "if($f.Read($old,0,$n) -ne $n){throw 'offset_conflict'};for($i=0;$i -lt $n;$i++){if($old[$i] -ne $b[$i]){throw 'offset_conflict'}}}"
        "else{throw 'offset_conflict'}}finally{$f.Dispose()};"
        "'ACK:'+$o+':'+$n+':'+$h")


def verify_script(path: str, size: int, sha256: str, identity: str) -> str:
    return bounded(
        "$p=" + literal(path) + ";$id=" + _checked_identity(identity) + ";$n=" + str(size) + ";$h=" + literal(sha256) + ";"
        "$fi=[IO.FileInfo]::new($p);if(-not $fi.Exists -or ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $fi.Length -ne $n){throw 'request_size'};"
        + _identity_setup() +
        "$f=[IO.File]::OpenRead($p);$sha=[Security.Cryptography.SHA256]::Create();"
        "try{if([VeloRequestIdentity]::Read($f.SafeFileHandle) -ne $id){throw 'request_replaced'};"
        "$actual=([BitConverter]::ToString($sha.ComputeHash($f))).Replace('-','').ToLowerInvariant()}"
        "finally{$sha.Dispose();$f.Dispose()};"
        "if($actual -ne $h){throw 'request_hash'};'ACK:verified'")


def invoke_script(path: str, python_path: str, project_root: str, policy_path: str,
                  identity: str) -> str:
    return bounded(
        "$p=" + literal(path) + ";$id=" + _checked_identity(identity) + ";" + _identity_setup() +
        "$fi=[IO.FileInfo]::new($p);if(-not $fi.Exists -or ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'request_replaced'};"
        "$f=[IO.File]::OpenRead($p);try{if([VeloRequestIdentity]::Read($f.SafeFileHandle) -ne $id){throw 'request_replaced'}}finally{$f.Dispose()};"
        "$env:VELOCIRAPTOR_TRANSFER_POLICY=" + literal(policy_path) + ";"
        "Push-Location -LiteralPath " + literal(project_root) + ";"
        "try{& " + literal(python_path) + " -m velo_transfer.guest_cli --request-file " + literal(path) +
        ";$rc=$LASTEXITCODE}finally{Pop-Location};if($rc -ne 0){exit $rc}")


def cleanup_script(path: str, identity: str) -> str:
    return bounded("$p=" + literal(path) + ";$id=" + _checked_identity(identity) + ";" + _identity_setup() +
                   "[VeloRequestIdentity]::DeleteOwned($p,$id);'ACK:deleted'")


def parse_outer_status(result) -> tuple[str, int]:
    if getattr(result, "is_error", True) or len(getattr(result, "content", ())) != 1:
        raise ValueError("powershell_error")
    block = result.content[0]
    if getattr(block, "type", None) != "text":
        raise ValueError("powershell_error")
    if len(block.text.encode("utf-8")) > 4 * 1024 * 1024 + 128:
        raise ValueError("powershell_response")
    match = re.fullmatch(r"Response: ([\s\S]*)\nStatus Code: (-?[0-9]+)", block.text)
    if match is None:
        raise ValueError("powershell_response")
    return match.group(1), int(match.group(2))


def _single_line(value: str, code: str) -> str:
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if "\r" in value or "\n" in value:
        raise ValueError(code)
    return value


def parse_outer(result) -> str:
    body, status_code = parse_outer_status(result)
    if status_code != 0:
        raise ValueError("powershell_exit")
    return _single_line(body, "powershell_response")


class GuestHelperError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def parse_helper(stdout: str, status_code: int = 0) -> dict:
    line = _single_line(stdout, "helper_response")
    if len(line.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("helper_response")

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("helper_response")
            obj[key] = value
        return obj

    payload = json.loads(line, object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("helper_response")))
    if not isinstance(payload, dict):
        raise ValueError("helper_response")
    if payload.get("status") == "error" and set(payload) == {"status", "error"}:
        code = payload["error"]
        if (not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) is None or
                status_code not in (3, 4) or (status_code == 3 and code != "internal_error")):
            raise ValueError("helper_response")
        raise GuestHelperError(code)
    if (status_code != 0 or payload.get("status") != "success" or
            set(payload) != {"status", "result"} or not isinstance(payload["result"], dict)):
        raise ValueError("helper_response")
    return payload["result"]

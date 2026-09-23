"""Strict, read-only PC020 preparation/migration evidence validation.

The entry points in this module only traverse caller-supplied immutable bundle
roots.  They never create, rename, delete, or update evidence, canonical state,
``.next`` files, VM objects, or services.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from tests import p05_snapshot_raw


class Pc020EvidenceError(ValueError):
    """A PC020 evidence graph is not the exact reviewed graph."""


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
PREDECESSOR_SHA256 = "2d5f378d20c163401b1c4ce7087db102a4719b394fc7a9408baa7d63d7ca4385"
VMX = "/home/adminn/vmware/Win10MalBox-Velo/Win10MalBox-Velo.vmx"
MAC = "00:0c:29:83:b8:65"
SNAPSHOT_187 = "Snapshot 187-固定IP+WindowsMCP开机自启"
SNAPSHOT_188 = "Snapshot 188-Velociraptor-MCP可恢复验收基线"
SNAPSHOT_189 = "Snapshot 189-Velociraptor-MCP可恢复验收基线"
MARKER_187 = "Win10MalBox-Velo-Snapshot3.vmsn"
MANUAL_ONLY = "MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION"
PREP_SCOPE = "current-project-nonsecret-evidence-before-pc020-recovery"
REF_KEYS = {"path", "size", "sha256"}
SOURCE_KEYS = {"repo_path", "blob", "content"}
MEMBER_KEYS = {"path", "size", "sha256", "origin"}
MANIFEST_KEYS = {"schema_version", "kind", "workflow_id", "created_at", "members"}
PREP_KEYS = {
    "schema_version", "kind", "workflow_id", "admission_id", "vmx",
    "snapshot_name", "checkpoint_marker", "snapshot_tree", "snapshot_metadata",
    "vm_identity", "preservation_manifest", "retired_requalification",
    "source_inputs", "implementation_sources", "package_manifest", "qualified_at",
}
MIGRATION_KEYS = {
    "schema_version", "kind", "workflow_id", "migration_id", "predecessor_sha256",
    "predecessor_canonical", "predecessor_baseline", "predecessor_activation",
    "historical_manifest", "preparation_admission", "preparation_manifest",
    "source_inputs", "implementation_sources", "package_manifest", "migrated_at",
}
STATE_KEYS = {
    "schema_version", "workflow_id", "epoch", "phase", "active_snapshot",
    "automatic_restore_allowlist", "retired_snapshots", "migration_evidence",
    "preparation_evidence", "activation_evidence",
}
SNAPSHOT_KEYS = {"name", "checkpoint_marker", "purpose"}
RETIRED_KEYS = {"name", "status"}
MIGRATION_REF_KEYS = {
    "kind", "source", "evidence_path", "evidence_sha256", "predecessor_sha256", "migrated_at",
}
PREPARATION_REF_KEYS = {"kind", "source", "evidence_path", "evidence_sha256", "qualified_at"}
ACTIVATION_REF_KEYS = {"source", "evidence_path", "evidence_sha256", "activated_at"}
FUTURE_WORDS = {"ready", "restore", "revert", "flow", "report", "triage", "epoch7", "transition"}
DECISION_16 = "PLAN/2026.09.20/2026.09.20-16-PC020主方迁移形状与因果顺序裁决.md"
RECEIVER_URL_PREFIX = "http://192.168.204.1:28786/"
RECEIVER_OBSERVER = {
    "scope": "receiver_host",
    "operating_system": "linux",
    "ipv4": "192.168.204.1",
    "endpoint": "http://192.168.204.1:28786/",
}


def receiver_observation_script() -> str:
    """Build the fixed Linux receiver-host identity and listener collector.

    PC023 erratum: the receiver host (192.168.204.1) runs Linux; the
    collector reads /proc/net/fib_trie for local IPv4 addresses and
    /proc/net/tcp{,6} for a listening 28786 socket, and emits the same
    JSON shape the verifier has always required.
    """
    return (
        "import json,re;"
        "ips=sorted(set(re.findall(r'\\|--\\s*([0-9.]+)\\s*\\n\\s*/32 host LOCAL',"
        "open('/proc/net/fib_trie').read())));"
        "ips=[x for x in ips if not x.startswith('127.')];"
        "assert '192.168.204.1' in ips,'collector is not running on the fixed receiver identity';"
        "rows=[];port=format(28786,'04X');"
        "[rows.append(line.split()[1]) for proc in ('/proc/net/tcp','/proc/net/tcp6')"
        " for line in open(proc).read().splitlines()[1:]"
        " if line.split()[1].split(':')[1]==port and line.split()[3]=='0A'];"
        "print(json.dumps({'schema_version':1,'observer_ipv4':'192.168.204.1',"
        "'endpoint':'http://192.168.204.1:28786/','interface_ipv4':ips,"
        "'rows':rows},separators=(',',':')))"
    )


RECEIVER_STOPPED_SCRIPT = receiver_observation_script()
RECEIVER_STOPPED_ARGV = ["/usr/bin/python3", "-c", RECEIVER_STOPPED_SCRIPT]
PC020_REQUIRED_SOURCE_PATHS = frozenset({
    "PLAN/2026.09.02/2026.09.02-01-需求提炼-mcp-velociraptor全阶段设计.md",
    "PLAN/2026.09.02/2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发.md",
    "PLAN/2026.09.02/2026.09.04-01-实施子方案-P01阶段0真实基线.md",
    "PLAN/2026.09.02/2026.09.05-02-实施子方案-P02公共基础与最小测试骨架.md",
    "PLAN/2026.09.02/2026.09.05-07-实施子方案-P03动态artifact工具.md",
    "PLAN/2026.09.02/2026.09.05-15-实施子方案-P04固定工具与生命周期.md",
    "PLAN/2026.09.02/2026.09.05-22-实施子方案-P05测试数据与情景基础设施.md",
    "PLAN/2026.09.02/2026.09.05-29-实施子方案-P06逐工具与连续情景全量执行.md",
    "PLAN/2026.09.02/2026.09.12-18-实施子方案-P07清理与终检.md",
    "PLAN/2026.09.20/current-normative-inputs-pc020-r01.json",
    "PLAN/2026.09.20/current-normative-inputs-pc019-r02.json",
    "PLAN/2026.09.20/current-normative-inputs-pc019.json",
    "PLAN/2026.09.20/pc017-author-revision-2-manifest.json",
    "PLAN/2026.09.20/pc017-author-sync-manifest.json",
    ".tmp/velo-codex-20260920-pc020-activation-time/candidate-manifest.json",
    ".tmp/velo-codex-20260920-pc020-activation-time/codex-R01-verdict.md",
    ".tmp/velo-codex-20260920-pc017-norm-combined/evidence-r02/base-manifest.json",
    ".tmp/velo-codex-20260920-pc017-norm-combined/proposal-r02.patch",
    ".tmp/velo-codex-20260920-pc017-norm-combined/codex-R02-verdict.md",
    "PLAN/2026.09.20/2026.09.20-06-PC017作者稿采纳与规范同步范围.md",
    "PLAN/2026.09.20/2026.09.20-07-PC017主方自评发现-发布后故障边界.md",
    "PLAN/2026.09.20/2026.09.20-08-PC017发布提交点与故障语义裁决.md",
    "PLAN/2026.09.20/2026.09.20-10-PLAN-CHANGE-018登记与裁决-分页游标上下文.md",
    "PLAN/2026.09.20/2026.09.20-11-主方自评发现-固定启动响应状态缺口.md",
    "PLAN/2026.09.20/2026.09.20-12-PLAN-CHANGE-019裁决-固定启动真实状态.md",
    "PLAN/2026.09.20/2026.09.20-13-PC018终页字段勘误与自评续作.md",
    "PLAN/2026.09.20/2026.09.20-15-PLAN-CHANGE-020登记与作者方向-恢复代次重建.md",
    "PLAN/2026.09.20/2026.09.20-16-PC020主方迁移形状与因果顺序裁决.md",
    "PLAN/2026.09.20/2026.09.20-17-PC020集合与证据复用边界勘误.md",
    "PLAN/2026.09.20/2026.09.20-18-PC020作者自评发现与裁决-激活签发时间.md",
    "PLAN/2026.09.20/2026.09.20-19-PC020作者采纳决定与正式同步范围.md",
    "PLAN/2026.09.20/2026.09.20-20-PC020主方完整规范自评与限定实现门.md",
    "PLAN/2026.09.02/2026.09.14-01-PLAN-CHANGE-012-用户重置唯一187基线.md",
    "PLAN/2026.09.02/2026.09.14-08-执行授权-宿主与目标虚拟机文件互传.md",
})


@dataclass(frozen=True)
class FrozenIdentity:
    size: int
    sha256: str
    blob: str


@dataclass(frozen=True)
class FrozenSourcePolicy:
    """Trusted identities frozen outside the untrusted evidence bundle."""

    source_inputs: Mapping[str, FrozenIdentity]
    implementation_sources: Mapping[str, FrozenIdentity]
    synthetic_fixture: bool = False


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _exact_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value) is None:
        raise Pc020EvidenceError(f"{label} must be UTC RFC3339 Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Pc020EvidenceError(f"{label} must be UTC RFC3339 Z") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise Pc020EvidenceError(f"{label} must be UTC RFC3339 Z")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Pc020EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise Pc020EvidenceError(f"non-finite JSON number is forbidden: {value}")


def _json_bytes(data: bytes, label: str, *, canonical: bool = True) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Pc020EvidenceError(f"{label} must be unambiguous UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise Pc020EvidenceError(f"{label} must be a JSON object")
    if canonical and data != canonical_json(value):
        raise Pc020EvidenceError(f"{label} must use sorted compact JSON with one LF")
    return value


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Pc020EvidenceError("JSON value is not canonically serializable") from exc


def _plain_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Pc020EvidenceError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise Pc020EvidenceError(f"{label} is not a plain directory")


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Pc020EvidenceError(f"{label} must be a POSIX relative path")
    # PurePath normalises ``.`` and repeated separators, so reject the raw
    # spelling before constructing it; evidence paths must have one meaning.
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise Pc020EvidenceError(f"{label} escapes its bundle")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive:
        raise Pc020EvidenceError(f"{label} escapes its bundle")
    return value


def _fixed_evidence_path(value: Any, namespace: str, filename: str, label: str) -> str:
    relative = _safe_relative(value, label)
    parts = relative.split("/")
    if len(parts) != 3 or parts[0] != namespace or parts[2] != filename:
        raise Pc020EvidenceError(f"{label} is outside the fixed namespace")
    try:
        identity = str(uuid.UUID(parts[1]))
    except (ValueError, AttributeError) as exc:
        raise Pc020EvidenceError(f"{label} UUID differs") from exc
    if identity != parts[1]:
        raise Pc020EvidenceError(f"{label} UUID differs")
    return relative


def _plain_file(root: Path, relative: Any, label: str) -> Path:
    relative = _safe_relative(relative, label)
    _plain_directory(root, "bundle root")
    current = root
    try:
        for part in PurePosixPath(relative).parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise Pc020EvidenceError(f"{label} traverses a link or reparse point")
        if not stat.S_ISREG(current.lstat().st_mode):
            raise Pc020EvidenceError(f"{label} is not a regular file")
    except OSError as exc:
        raise Pc020EvidenceError(f"{label} is unavailable") from exc
    return current


def _ref(root: Path, value: Any, label: str, seen: dict[str, tuple[int, str]]) -> Path:
    if not isinstance(value, dict) or set(value) != REF_KEYS:
        raise Pc020EvidenceError(f"{label} must have exact path/size/sha256 keys")
    if type(value["size"]) is not int or value["size"] < 0 or not _valid_sha(value["sha256"]):
        raise Pc020EvidenceError(f"{label} identity is invalid")
    path_text = _safe_relative(value["path"], f"{label}.path")
    identity = (value["size"], value["sha256"])
    if path_text in seen and seen[path_text] != identity:
        raise Pc020EvidenceError(f"{label} repeats a path with conflicting identity")
    seen[path_text] = identity
    path = _plain_file(root, path_text, f"{label}.path")
    data = path.read_bytes()
    if len(data) != value["size"] or _sha(data) != value["sha256"]:
        raise Pc020EvidenceError(f"{label} byte identity differs")
    return path


def _walk(root: Path) -> dict[str, Path]:
    _plain_directory(root, "manifest tree")
    result: dict[str, Path] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise Pc020EvidenceError("manifest tree contains a link or reparse point")
            if stat.S_ISDIR(info.st_mode):
                pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                relative = child.relative_to(root).as_posix()
                if relative in result:
                    raise Pc020EvidenceError("manifest tree repeats a path")
                result[relative] = child
            else:
                raise Pc020EvidenceError("manifest tree contains a special file")
    return result


def _manifest(
    root: Path, reference: Any, *, label: str, kind: str,
    exclusions: frozenset[str], seen: dict[str, tuple[int, str]],
) -> dict[str, Any]:
    path = _ref(root, reference, label, seen)
    document = _json_bytes(path.read_bytes(), label)
    if set(document) != MANIFEST_KEYS or not _exact_int(document.get("schema_version"), 1) or document.get("kind") != kind or document.get("workflow_id") != WORKFLOW_ID:
        raise Pc020EvidenceError(f"{label} shape or identity differs")
    _utc(document.get("created_at"), f"{label}.created_at")
    members = document.get("members")
    if not isinstance(members, list):
        raise Pc020EvidenceError(f"{label}.members must be a list")
    actual = _walk(root)
    expected_paths = set(actual) - set(exclusions)
    rows: dict[str, dict[str, Any]] = {}
    order: list[bytes] = []
    for index, row in enumerate(members):
        if not isinstance(row, dict) or set(row) != MEMBER_KEYS:
            raise Pc020EvidenceError(f"{label}.members[{index}] keys differ")
        relative = _safe_relative(row["path"], f"{label}.members[{index}].path")
        if relative in rows or type(row["size"]) is not int or row["size"] < 0 or not _valid_sha(row["sha256"]):
            raise Pc020EvidenceError(f"{label}.members[{index}] identity is invalid or duplicated")
        _safe_relative(row["origin"], f"{label}.members[{index}].origin")
        rows[relative] = row
        order.append(relative.encode("utf-8"))
    if order != sorted(order) or set(rows) != expected_paths:
        raise Pc020EvidenceError(f"{label} does not inventory the exact governed tree")
    for relative, row in rows.items():
        data = actual[relative].read_bytes()
        if len(data) != row["size"] or _sha(data) != row["sha256"]:
            raise Pc020EvidenceError(f"{label} member bytes differ: {relative}")
    return document


def _sources(root: Path, value: Any, policy: Mapping[str, FrozenIdentity], label: str, seen: dict[str, tuple[int, str]]) -> dict[str, Path]:
    if not isinstance(value, list):
        raise Pc020EvidenceError(f"{label} must be a list")
    copies: dict[str, Path] = {}
    for index, source in enumerate(value):
        if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
            raise Pc020EvidenceError(f"{label}[{index}] keys differ")
        repo_path = _safe_relative(source.get("repo_path"), f"{label}[{index}].repo_path")
        if repo_path in copies or repo_path not in policy:
            raise Pc020EvidenceError(f"{label}[{index}] is duplicated or outside the frozen policy")
        path = _ref(root, source.get("content"), f"{label}[{index}].content", seen)
        if source["content"]["path"] != f"source/{repo_path}":
            raise Pc020EvidenceError(f"{label}[{index}] content path differs")
        data = path.read_bytes()
        expected = policy[repo_path]
        if source.get("blob") != _blob(data) or (len(data), _sha(data), source.get("blob")) != (expected.size, expected.sha256, expected.blob):
            raise Pc020EvidenceError(f"{label}[{index}] differs from the trusted frozen identity")
        copies[repo_path] = path
    if set(copies) != set(policy):
        raise Pc020EvidenceError(f"{label} is not the exact frozen source set")
    return copies


def _raw_command(path: Path, *, operation_id: str, observation: str, vmx: str, argv: list[str] | None = None) -> dict[str, Any]:
    document = _json_bytes(path.read_bytes(), observation)
    try:
        return p05_snapshot_raw.command(document, workflow_id=WORKFLOW_ID, operation_id=operation_id, observation=observation, vmx=vmx, expected_argv=argv)
    except p05_snapshot_raw.SnapshotRawError as exc:
        raise Pc020EvidenceError(str(exc)) from exc


def _ready_command(path: Path, *, preservation_id: str) -> dict[str, Any]:
    document = _json_bytes(path.read_bytes(), "receiver_stopped")
    keys = {"schema_version", "kind", "observation", "workflow_id", "run_id", "restore_attempt_id", "host", "request", "started_at", "ended_at", "exit_status", "response"}
    if set(document) != keys or not _exact_int(document.get("schema_version"), 1) or document.get("kind") != "p05-ready-command-v1" or document.get("observation") != "receiver_stopped" or document.get("workflow_id") != WORKFLOW_ID or document.get("run_id") != preservation_id or document.get("restore_attempt_id") != preservation_id:
        raise Pc020EvidenceError("receiver_stopped raw envelope identity differs")
    _utc(document.get("started_at"), "receiver_stopped.started_at")
    _utc(document.get("ended_at"), "receiver_stopped.ended_at")
    if document["ended_at"] < document["started_at"]:
        raise Pc020EvidenceError("receiver_stopped time order differs")
    host = document.get("host")
    request = document.get("request")
    status = document.get("exit_status")
    if not isinstance(request, dict) or set(request) != {"argv", "command_line"} or not isinstance(request.get("argv"), list) or not all(isinstance(x, str) for x in request["argv"]) or request.get("command_line") != " ".join(request["argv"]):
        raise Pc020EvidenceError("receiver_stopped is not the fixed receiver endpoint observation")
    if host != RECEIVER_OBSERVER or request["argv"] != RECEIVER_STOPPED_ARGV:
        raise Pc020EvidenceError("receiver_stopped observer is not the fixed receiver host")
    if not isinstance(status, dict) or set(status) != {"code"} or type(status["code"]) is not int or status["code"] != 0:
        raise Pc020EvidenceError("receiver_stopped command failed")
    response = document.get("response")
    response_keys = {"stdout", "stdout_size", "stdout_sha256", "stderr", "stderr_size", "stderr_sha256"}
    if not isinstance(response, dict) or set(response) != response_keys:
        raise Pc020EvidenceError("receiver_stopped response differs")
    for stream in ("stdout", "stderr"):
        data = response[stream].encode("utf-8") if isinstance(response.get(stream), str) else b""
        if type(response.get(stream + "_size")) is not int or response[stream + "_size"] != len(data) or response.get(stream + "_sha256") != _sha(data):
            raise Pc020EvidenceError("receiver_stopped stream identity differs")
    payload = _json_bytes(response["stdout"].encode("utf-8"), "receiver_stopped.stdout", canonical=False)
    if set(payload) != {"schema_version", "observer_ipv4", "endpoint", "interface_ipv4", "rows"} or not _exact_int(payload.get("schema_version"), 1) or payload.get("observer_ipv4") != RECEIVER_OBSERVER["ipv4"] or payload.get("endpoint") != RECEIVER_OBSERVER["endpoint"] or not isinstance(payload.get("interface_ipv4"), list) or RECEIVER_OBSERVER["ipv4"] not in payload["interface_ipv4"] or not isinstance(payload.get("rows"), list):
        raise Pc020EvidenceError("receiver_stopped stdout is not the fixed receiver observation")
    if payload["rows"]:
        raise Pc020EvidenceError("receiver_stopped does not prove the listener is absent")
    return document


def transfer_command(preservation_id: str, source_path: str, size: int, received_sha256: str) -> str:
    """Return the reviewed byte-sending request for one frozen object."""
    if not isinstance(preservation_id, str):
        raise Pc020EvidenceError("transfer preservation_id is not a canonical UUID")
    try:
        canonical_id = str(uuid.UUID(preservation_id))
    except ValueError as exc:
        raise Pc020EvidenceError("transfer preservation_id is not a canonical UUID") from exc
    if canonical_id != preservation_id:
        raise Pc020EvidenceError("transfer preservation_id is not a canonical UUID")
    source_path = _safe_relative(source_path, "transfer source path")
    if type(size) is not int or size <= 0:
        raise Pc020EvidenceError("transfer size must be a positive integer")
    if not _valid_sha(received_sha256):
        raise Pc020EvidenceError("transfer sha256 must be lowercase hexadecimal")

    def quoted(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    return (
        f"$uri={quoted(RECEIVER_URL_PREFIX + preservation_id)};"
        f"$source={quoted(source_path)};$expectedLength={size};"
        f"$hash={quoted(received_sha256)};"
        "$bytes=[IO.File]::ReadAllBytes($source);"
        "if($bytes.Length -ne $expectedLength){throw 'source length differs'};"
        "$sha256=[Security.Cryptography.SHA256]::Create();try{$digest=$sha256.ComputeHash($bytes)}finally{$sha256.Dispose()};"
        "$actual=($digest|ForEach-Object {$_.ToString('x2')})-join '';"
        "if($actual -ne $hash){throw 'source hash differs'};"
        "$request=[Net.HttpWebRequest]::Create($uri);$request.Method='POST';"
        "$request.ContentType='application/octet-stream';$request.ContentLength=$bytes.Length;"
        "$request.Headers['X-Evidence-SHA256']=$hash;"
        "$stream=$request.GetRequestStream();try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Close()};"
        "$response=$request.GetResponse();try{$status=[int]$response.StatusCode;"
        "$reader=[IO.StreamReader]::new($response.GetResponseStream());try{$body=$reader.ReadToEnd()}finally{$reader.Close()}}finally{$response.Close()};"
        "$receipt=ConvertFrom-Json $body;"
        "if($status -ne 200 -or $receipt.sha256 -ne $hash -or [int64]$receipt.size -ne $expectedLength){throw 'receiver receipt differs'};"
        "[Console]::Out.Write(\"Response: PRESERVATION_HTTP=200`r`nGUEST_SHA256=$($hash.ToUpper())`r`nStatus Code: 0\")"
    )


def _control_result(value: Any, expected_sha256: str) -> None:
    if not isinstance(value, dict) or set(value) != {"jsonrpc", "id", "result"} or value.get("jsonrpc") != "2.0" or type(value.get("id")) is not int:
        raise Pc020EvidenceError("transfer control response envelope differs")
    result = value.get("result")
    if not isinstance(result, dict) or set(result) != {"content", "structuredContent", "isError"} or result.get("isError") is not False:
        raise Pc020EvidenceError("transfer control response reports an error")
    structured = result.get("structuredContent")
    if not isinstance(structured, dict) or set(structured) != {"result"} or not isinstance(structured.get("result"), str):
        raise Pc020EvidenceError("transfer control response result shape differs")
    if result.get("content") != [{"type": "text", "text": structured["result"]}]:
        raise Pc020EvidenceError("transfer control response text and structured result differ")
    match = re.fullmatch(
        r"Response: PRESERVATION_HTTP=(\d{3})\r?\n"
        r"GUEST_SHA256=([0-9A-F]{64})\r?\n"
        r"Status Code: (\d+)",
        structured["result"],
    )
    if match is None or match.group(1) != "200" or match.group(2) != expected_sha256.upper() or match.group(3) != "0":
        raise Pc020EvidenceError("transfer control response does not prove the exact received bytes and successful request")


def _predecessor(data: bytes) -> dict[str, Any]:
    if _sha(data) != PREDECESSOR_SHA256:
        raise Pc020EvidenceError("predecessor canonical bytes differ")
    document = _json_bytes(data, "predecessor canonical", canonical=False)
    keys = {"schema_version", "workflow_id", "epoch", "phase", "active_snapshot", "automatic_restore_allowlist", "retired_snapshots", "baseline_evidence", "activation_evidence"}
    if set(document) != keys or not _exact_int(document.get("schema_version"), 5) or document.get("workflow_id") != WORKFLOW_ID or not _exact_int(document.get("epoch"), 6) or document.get("phase") != "NETWORK_ACTIVE":
        raise Pc020EvidenceError("predecessor is not exact schema5/epoch6 NETWORK_ACTIVE")
    active = document.get("active_snapshot")
    if not isinstance(active, dict) or set(active) != SNAPSHOT_KEYS or active.get("name") != SNAPSHOT_188 or document.get("automatic_restore_allowlist") != [SNAPSHOT_188]:
        raise Pc020EvidenceError("predecessor Snapshot188 identity differs")
    expected = ["Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线", "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", SNAPSHOT_187]
    retired = document.get("retired_snapshots")
    if not isinstance(retired, list) or [x.get("name") if isinstance(x, dict) else None for x in retired] != expected or any(set(x) != RETIRED_KEYS or x.get("status") != MANUAL_ONLY for x in retired):
        raise Pc020EvidenceError("predecessor retired order differs")
    for name in ("baseline_evidence", "activation_evidence"):
        value = document.get(name)
        if not isinstance(value, dict) or set(value) != {"source", "evidence_path", "evidence_sha256", "recorded_at" if name == "baseline_evidence" else "activated_at"} or not _valid_sha(value.get("evidence_sha256")):
            raise Pc020EvidenceError(f"predecessor {name} differs")
    return document


def _bundle_root(path: Path, parent_name: str, filename: str) -> tuple[Path, str]:
    if not isinstance(path, Path) or not path.is_absolute() or path.name != filename or path.parent.parent.name != parent_name:
        raise Pc020EvidenceError(f"{filename} is outside the required bundle layout")
    root = path.parent
    try:
        identity = str(uuid.UUID(root.name))
    except (ValueError, AttributeError) as exc:
        raise Pc020EvidenceError("bundle directory is not a UUID") from exc
    if identity != root.name:
        raise Pc020EvidenceError("bundle UUID is not canonical lowercase")
    _plain_directory(path.parent.parent, "bundle namespace")
    _plain_directory(root, "bundle directory")
    _plain_file(root, filename, filename)
    return root, identity


def _vmx_mac(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise Pc020EvidenceError("raw VMX bytes are not UTF-8") from exc
    values = re.findall(r'^ethernet0\.(?:address|generatedAddress)\s*=\s*"([0-9A-Fa-f:-]+)"\s*$', text, re.MULTILINE)
    normalized = {value.lower().replace("-", ":") for value in values}
    if normalized != {MAC}:
        raise Pc020EvidenceError("raw VMX bytes do not bind the fixed MAC")
    return MAC


def _legacy_graph(root: Path, root_file: Path, label: str) -> None:
    """Validate the old immutable Ref graph without applying new business gates."""
    visited: set[str] = set()
    identities: dict[str, tuple[int, str]] = {}

    def visit_file(path: Path, path_label: str) -> None:
        relative = path.relative_to(root).as_posix()
        if relative in visited or path.suffix.lower() != ".json":
            return
        visited.add(relative)
        data = path.read_bytes()
        # Historical raw JSON can be large. Its bytes are still checked by the
        # parent Ref/manifest, but only reasonably sized graph documents are
        # decoded to discover subordinate Refs.
        if len(data) > 2 * 1024 * 1024:
            return
        document = _json_bytes(data, path_label, canonical=False)
        if set(document) == {"schema_version", "members"}:
            if not _exact_int(document.get("schema_version"), 1) or not isinstance(document.get("members"), list):
                raise Pc020EvidenceError(f"{path_label} legacy manifest shape differs")
            order: list[bytes] = []
            for index, member in enumerate(document["members"]):
                member_path = _ref(root, member, f"{path_label}.members[{index}]", identities)
                order.append(member["path"].encode("utf-8"))
                # The manifest authenticates member bytes; nested package roots
                # are followed, while raw members need no semantic reinterpretation.
                if member_path.name in {"adoption.json", "activation-evidence.json", "ready.json", "report.json"}:
                    visit_file(member_path, f"{path_label}.members[{index}]")
            if order != sorted(order) or len(order) != len(set(order)):
                raise Pc020EvidenceError(f"{path_label} legacy manifest paths differ")
            return
        visit_value(document, path_label)

    def visit_value(value: Any, value_label: str) -> None:
        if isinstance(value, dict) and set(value) == REF_KEYS:
            target = _ref(root, value, value_label, identities)
            # Old reports can authenticate observation paths owned by the
            # original run rather than by this immutable package.  Recurse
            # only through package manifests and explicit bundle entrypoints;
            # every other Ref is still byte-checked above as a leaf.
            if target.name in {"adoption.json", "activation-evidence.json", "ready.json", "report.json"} or target.name.endswith("manifest.json"):
                visit_file(target, value_label)
        elif isinstance(value, dict):
            for key, child in value.items():
                visit_value(child, f"{value_label}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit_value(child, f"{value_label}[{index}]")

    visit_file(root_file, label)


def verify_preparation(path: Path, *, policy: FrozenSourcePolicy) -> dict[str, Any]:
    if set(policy.source_inputs) != PC020_REQUIRED_SOURCE_PATHS or not policy.implementation_sources:
        raise Pc020EvidenceError("trusted policy does not distinguish the fixed PC020 sources from a non-empty post-freeze implementation set")
    root, admission_id = _bundle_root(path, "pc020-preparation", "admission.json")
    document = _json_bytes(path.read_bytes(), "preparation admission")
    if set(document) != PREP_KEYS or not _exact_int(document.get("schema_version"), 1) or document.get("kind") != "pc020-snapshot187-preparation-v1" or document.get("workflow_id") != WORKFLOW_ID or document.get("admission_id") != admission_id:
        raise Pc020EvidenceError("preparation admission identity differs")
    if document.get("vmx") != VMX or document.get("snapshot_name") != SNAPSHOT_187 or document.get("checkpoint_marker") != MARKER_187:
        raise Pc020EvidenceError("preparation target identity differs")
    _utc(document.get("qualified_at"), "qualified_at")
    # ``workflow_id`` contains the lexical fragment ``flow`` but is itself a
    # mandatory identity field.  Only optional/business field names are in
    # scope for the future-stage guard.
    if any(
        word in key.casefold()
        for key in document
        if key != "workflow_id"
        for word in FUTURE_WORDS
    ):
        raise Pc020EvidenceError("preparation contains a future recovery/business field")
    seen: dict[str, tuple[int, str]] = {}
    tree_path = _ref(root, document["snapshot_tree"], "snapshot_tree", seen)
    meta_path = _ref(root, document["snapshot_metadata"], "snapshot_metadata", seen)
    tree = _raw_command(tree_path, operation_id=admission_id, observation="snapshot_tree", vmx=VMX, argv=["/usr/bin/vmrun", "-T", "ws", "listSnapshots", VMX, "showTree"])
    metadata = _raw_command(meta_path, operation_id=admission_id, observation="snapshot_metadata", vmx=VMX, argv=["/usr/bin/cat", str(PurePosixPath(VMX).with_suffix(".vmsd"))])
    names = p05_snapshot_raw.snapshot_names(tree["response"]["stdout"])
    if names != [SNAPSHOT_187, SNAPSHOT_188] or SNAPSHOT_189 in names:
        raise Pc020EvidenceError("snapshot tree is not exactly retained 187/188 with no 189")
    fields = p05_snapshot_raw.vmsd_fields(metadata["response"]["stdout"])
    indices = {value: key[:-12] for key, value in fields.items() if key.endswith(".displayName")}
    index187 = indices.get(SNAPSHOT_187)
    index188 = indices.get(SNAPSHOT_188)
    uid187 = fields.get(index187 + ".uid") if index187 else None
    uid188 = fields.get(index188 + ".uid") if index188 else None
    if (
        set(indices) != {SNAPSHOT_187, SNAPSHOT_188}
        or fields.get("snapshot.numSnapshots") != "2"
        or fields.get("snapshot.current") != uid188
        or fields.get("snapshot.lastUID") != uid188
        or uid187 != "3"
        or uid188 != "4"
        or fields.get(index187 + ".filename") != MARKER_187
        or fields.get(index188 + ".parent") != uid187
    ):
        raise Pc020EvidenceError("snapshot metadata does not bind the unique 187-to-188 parent relation, UID4 current state, and marker")
    vm_path = _ref(root, document["vm_identity"], "vm_identity", seen)
    vm = _json_bytes(vm_path.read_bytes(), "vm_identity")
    vm_keys = {"schema_version", "kind", "workflow_id", "vmx", "vmx_sha256", "mac_address", "current_snapshot_uid", "observed_at", "observation"}
    if set(vm) != vm_keys or not _exact_int(vm.get("schema_version"), 1) or vm.get("kind") != "pc020-vm-identity-v1" or vm.get("workflow_id") != WORKFLOW_ID or vm.get("vmx") != VMX or not _valid_sha(vm.get("vmx_sha256")) or vm.get("mac_address", "").lower().replace("-", ":") != MAC or not _exact_int(vm.get("current_snapshot_uid"), 4):
        raise Pc020EvidenceError("vm_identity differs")
    _utc(vm.get("observed_at"), "vm_identity.observed_at")
    observation = _ref(root, vm["observation"], "vm_identity.observation", seen)
    raw_vm = _raw_command(
        observation,
        operation_id=admission_id,
        observation="vm_identity",
        vmx=VMX,
        argv=["/usr/bin/cat", VMX],
    )
    vmx_bytes = raw_vm["response"]["stdout"].encode("utf-8")
    if vm["vmx_sha256"] != _sha(vmx_bytes) or _vmx_mac(vmx_bytes) != MAC:
        raise Pc020EvidenceError("vm_identity summary differs from its raw observation")
    preservation_path = _ref(root, document["preservation_manifest"], "preservation_manifest", seen)
    preservation = _json_bytes(preservation_path.read_bytes(), "preservation_manifest")
    pkeys = {"schema_version", "kind", "workflow_id", "preservation_id", "scope", "created_at", "transfer_receipt", "receiver_stopped", "included", "excluded"}
    if set(preservation) != pkeys or not _exact_int(preservation.get("schema_version"), 1) or preservation.get("kind") != "pc020-pre-recovery-preservation-v1" or preservation.get("workflow_id") != WORKFLOW_ID or preservation.get("scope") != PREP_SCOPE:
        raise Pc020EvidenceError("preservation_manifest differs")
    preservation_id = preservation.get("preservation_id")
    try:
        if str(uuid.UUID(preservation_id)) != preservation_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as exc:
        raise Pc020EvidenceError("preservation_id is not a canonical UUID") from exc
    _utc(preservation.get("created_at"), "preservation.created_at")
    included = preservation.get("included")
    if not isinstance(included, list) or not included:
        raise Pc020EvidenceError("preservation included set is empty")
    included_rows: dict[str, tuple[int, str]] = {}
    for row in included:
        if not isinstance(row, dict) or set(row) != REF_KEYS or type(row.get("size")) is not int or row["size"] < 0 or not _valid_sha(row.get("sha256")):
            raise Pc020EvidenceError("preservation included row differs")
        name = _safe_relative(row["path"], "preservation included path")
        if name in included_rows:
            raise Pc020EvidenceError("preservation included path is duplicated")
        included_rows[name] = (row["size"], row["sha256"])
        _ref(root, row, "preservation included bytes", seen)
    if [x["path"].encode("utf-8") for x in included] != sorted(x["path"].encode("utf-8") for x in included):
        raise Pc020EvidenceError("preservation included set is not sorted")
    excluded = preservation.get("excluded")
    if not isinstance(excluded, list) or any(not isinstance(x, dict) or set(x) != {"category", "reason"} or not all(isinstance(x[k], str) and x[k] for k in x) for x in excluded):
        raise Pc020EvidenceError("preservation excluded set differs")
    receipt_path = _ref(root, preservation["transfer_receipt"], "transfer_receipt", seen)
    receipt = _json_bytes(receipt_path.read_bytes(), "transfer_receipt")
    receipt_keys = {"identity", "command", "received", "control_exit", "control_response_sha256", "scope", "originals_modified"}
    if set(receipt) != receipt_keys or receipt.get("identity") != preservation_id or type(receipt.get("control_exit")) is not int or receipt["control_exit"] != 0 or receipt.get("originals_modified") is not False or not _valid_sha(receipt.get("control_response_sha256")) or not isinstance(receipt.get("command"), str) or not receipt["command"] or not isinstance(receipt.get("scope"), list) or not receipt["scope"]:
        raise Pc020EvidenceError("transfer receipt differs from the existing preservation format")
    received = receipt.get("received")
    if not isinstance(received, dict) or set(received) != {"size", "sha256", "guest_sha256"} or type(received.get("size")) is not int or received["size"] <= 0 or received.get("guest_sha256") != received.get("sha256") or len(included_rows) != 1 or next(iter(included_rows.values())) != (received.get("size"), received.get("sha256")):
        raise Pc020EvidenceError("transfer receipt does not prove the same included bytes arrived")
    command = receipt["command"]
    included_path = next(iter(included_rows))
    if command != transfer_command(preservation_id, included_path, received["size"], received["sha256"]):
        raise Pc020EvidenceError("transfer receipt is not bound to the fixed receiver endpoint")
    control_response = _plain_file(root, "preservation/control-response.json", "transfer control response")
    control_bytes = control_response.read_bytes()
    if _sha(control_bytes) != receipt["control_response_sha256"]:
        raise Pc020EvidenceError("transfer control response bytes differ")
    control = _json_bytes(control_bytes, "transfer control response", canonical=False)
    _control_result(control, received["sha256"])
    stopped_path = _ref(root, preservation["receiver_stopped"], "receiver_stopped", seen)
    _ready_command(stopped_path, preservation_id=preservation_id)
    source_copies = _sources(root, document["source_inputs"], policy.source_inputs, "source_inputs", seen)
    _sources(root, document["implementation_sources"], policy.implementation_sources, "implementation_sources", seen)
    retired_path = _ref(root, document["retired_requalification"], "retired_requalification", seen)
    retired = _json_bytes(retired_path.read_bytes(), "retired_requalification")
    rkeys = {"schema_version", "kind", "workflow_id", "predecessor_sha256", "snapshot_name", "previous_status", "new_scope", "reason", "decision_source", "issued_at"}
    if set(retired) != rkeys or not _exact_int(retired.get("schema_version"), 1) or retired.get("kind") != "pc020-retired187-requalification-v1" or retired.get("workflow_id") != WORKFLOW_ID or retired.get("predecessor_sha256") != PREDECESSOR_SHA256 or retired.get("snapshot_name") != SNAPSHOT_187 or retired.get("previous_status") != MANUAL_ONLY or retired.get("new_scope") != "P05_PREPARATION_ONLY" or not isinstance(retired.get("reason"), str) or not retired["reason"]:
        raise Pc020EvidenceError("retired requalification differs")
    _utc(retired.get("issued_at"), "retired_requalification.issued_at")
    decision = _ref(root, retired["decision_source"], "retired_requalification.decision_source", seen)
    if retired["decision_source"]["path"] != f"source/{DECISION_16}" or decision != source_copies[DECISION_16] or decision.read_bytes() != source_copies[DECISION_16].read_bytes():
        raise Pc020EvidenceError("retired requalification is not bound to the trusted decision 16 source copy")
    _manifest(root, document["package_manifest"], label="preparation package manifest", kind="pc020-preparation-manifest-v1", exclusions=frozenset({"package-manifest.json", "admission.json"}), seen=seen)
    return {"kind": "preparation_admission", "admission_id": admission_id, "qualified_at": document["qualified_at"], "synthetic_fixture": policy.synthetic_fixture, "operational_ready": False}


def _tree_identity(root: Path, *, omit: frozenset[str] = frozenset()) -> dict[str, tuple[int, str]]:
    return {name: (path.stat().st_size, _sha(path.read_bytes())) for name, path in _walk(root).items() if name not in omit}


def verify_migration(path: Path, *, original_preparation: Path, policy: FrozenSourcePolicy) -> dict[str, Any]:
    if set(policy.source_inputs) != PC020_REQUIRED_SOURCE_PATHS or not policy.implementation_sources:
        raise Pc020EvidenceError("trusted policy does not distinguish the fixed PC020 sources from a non-empty post-freeze implementation set")
    root, migration_id = _bundle_root(path, "pc020-migration", "migration.json")
    document = _json_bytes(path.read_bytes(), "migration")
    if set(document) != MIGRATION_KEYS or not _exact_int(document.get("schema_version"), 1) or document.get("kind") != "pc020-requalification-migration-v1" or document.get("workflow_id") != WORKFLOW_ID or document.get("migration_id") != migration_id or document.get("predecessor_sha256") != PREDECESSOR_SHA256:
        raise Pc020EvidenceError("migration identity differs")
    _utc(document.get("migrated_at"), "migrated_at")
    seen: dict[str, tuple[int, str]] = {}
    canonical_path = _ref(root, document["predecessor_canonical"], "predecessor_canonical", seen)
    if document["predecessor_canonical"]["path"] != "historical/canonical.json":
        raise Pc020EvidenceError("predecessor canonical copy path differs")
    predecessor = _predecessor(canonical_path.read_bytes())
    baseline = _ref(root, document["predecessor_baseline"], "predecessor_baseline", seen)
    activation = _ref(root, document["predecessor_activation"], "predecessor_activation", seen)
    if _sha(baseline.read_bytes()) != predecessor["baseline_evidence"]["evidence_sha256"] or _sha(activation.read_bytes()) != predecessor["activation_evidence"]["evidence_sha256"]:
        raise Pc020EvidenceError("historical root bytes differ from predecessor provenance")
    baseline_id = Path(predecessor["baseline_evidence"]["evidence_path"]).parent.name
    activation_id = Path(predecessor["activation_evidence"]["evidence_path"]).parent.name
    for identity, label in ((baseline_id, "baseline"), (activation_id, "activation")):
        try:
            if str(uuid.UUID(identity)) != identity:
                raise ValueError
        except (ValueError, AttributeError) as exc:
            raise Pc020EvidenceError(f"predecessor {label} directory is not a canonical UUID") from exc
    expected_baseline_path = f"historical/baseline-adoption/{baseline_id}/adoption.json"
    expected_activation_path = f"historical/activation-188/{activation_id}/activation-evidence.json"
    if document["predecessor_baseline"]["path"] != expected_baseline_path or document["predecessor_activation"]["path"] != expected_activation_path:
        raise Pc020EvidenceError("historical root paths differ from predecessor provenance")
    _legacy_graph(baseline.parent, baseline, "historical baseline root")
    _legacy_graph(activation.parent, activation, "historical activation root")
    historical_root = root / "historical"
    _manifest(historical_root, {**document["historical_manifest"], "path": Path(document["historical_manifest"]["path"]).relative_to("historical").as_posix()}, label="historical manifest", kind="pc020-historical-manifest-v1", exclusions=frozenset({"historical-manifest.json"}), seen={})
    copied_prep_root = root / "preparation"
    copied_admission = _ref(root, document["preparation_admission"], "preparation_admission", seen)
    if copied_admission != copied_prep_root / "admission.json":
        raise Pc020EvidenceError("copied preparation admission path differs")
    _manifest(copied_prep_root, {**document["preparation_manifest"], "path": Path(document["preparation_manifest"]["path"]).relative_to("preparation").as_posix()}, label="preparation-copy manifest", kind="pc020-preparation-copy-manifest-v1", exclusions=frozenset({"preparation-copy-manifest.json"}), seen={})
    original_root, _ = _bundle_root(original_preparation, "pc020-preparation", "admission.json")
    verify_preparation(original_preparation, policy=policy)
    copied_files = _tree_identity(copied_prep_root, omit=frozenset({"preparation-copy-manifest.json"}))
    if copied_files != _tree_identity(original_root):
        raise Pc020EvidenceError("original and recursively copied preparation bundles differ")
    if copied_admission.read_bytes() != original_preparation.read_bytes():
        raise Pc020EvidenceError("original and copied preparation admissions differ")
    _sources(root, document["source_inputs"], policy.source_inputs, "source_inputs", seen)
    _sources(root, document["implementation_sources"], policy.implementation_sources, "implementation_sources", seen)
    _manifest(root, document["package_manifest"], label="migration package manifest", kind="pc020-migration-manifest-v1", exclusions=frozenset({"package-manifest.json", "migration.json"}), seen=seen)
    return {"kind": "migration", "migration_id": migration_id, "migrated_at": document["migrated_at"], "predecessor_sha256": PREDECESSOR_SHA256, "synthetic_fixture": policy.synthetic_fixture, "operational_ready": False}


def verify_schema6_shape(data: bytes, *, expected_epoch: int) -> dict[str, Any]:
    """Validate state shape only; never validates activation graph readiness."""
    document = _json_bytes(data, "schema6 canonical")
    if set(document) != STATE_KEYS or not _exact_int(document.get("schema_version"), 6) or document.get("workflow_id") != WORKFLOW_ID or not _exact_int(document.get("epoch"), expected_epoch):
        raise Pc020EvidenceError("schema6 canonical root differs")
    active = document.get("active_snapshot")
    retired = document.get("retired_snapshots")
    allowlist = document.get("automatic_restore_allowlist")
    if not isinstance(active, dict) or set(active) != SNAPSHOT_KEYS or not all(isinstance(active[x], str) and active[x] for x in active) or not isinstance(allowlist, list) or allowlist != [active["name"]] or not isinstance(retired, list) or any(not isinstance(x, dict) or set(x) != RETIRED_KEYS or x.get("status") != MANUAL_ONLY for x in retired):
        raise Pc020EvidenceError("schema6 snapshot collections differ")
    retired_names = [x["name"] for x in retired]
    if len(retired_names) != len(set(retired_names)) or active["name"] in retired_names:
        raise Pc020EvidenceError("schema6 active/allowlist/retired sets differ")
    migration = document.get("migration_evidence")
    preparation = document.get("preparation_evidence")
    if not isinstance(migration, dict) or set(migration) != MIGRATION_REF_KEYS or migration.get("kind") != "pc020-requalification-migration-v1" or migration.get("source") != "pc020-migration" or migration.get("predecessor_sha256") != PREDECESSOR_SHA256 or not _valid_sha(migration.get("evidence_sha256")):
        raise Pc020EvidenceError("schema6 migration Ref differs")
    if not isinstance(preparation, dict) or set(preparation) != PREPARATION_REF_KEYS or preparation.get("kind") != "pc020-snapshot187-preparation-v1" or preparation.get("source") != "pc020-preparation-admission" or not _valid_sha(preparation.get("evidence_sha256")):
        raise Pc020EvidenceError("schema6 preparation Ref differs")
    _fixed_evidence_path(migration["evidence_path"], "pc020-migration", "migration.json", "migration evidence path")
    _fixed_evidence_path(preparation["evidence_path"], "pc020-preparation", "admission.json", "preparation evidence path")
    _utc(migration.get("migrated_at"), "migration migrated_at")
    _utc(preparation.get("qualified_at"), "preparation qualified_at")
    if expected_epoch == 7:
        expected_retired = ["Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线", "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", SNAPSHOT_188]
        if document.get("phase") != "PREPARATION_BASELINE" or active.get("name") != SNAPSHOT_187 or retired_names != expected_retired or document.get("activation_evidence") is not None:
            raise Pc020EvidenceError("epoch7 canonical shape differs")
    elif expected_epoch == 8:
        expected_retired = ["Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线", "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", SNAPSHOT_188, SNAPSHOT_187]
        activation = document.get("activation_evidence")
        if document.get("phase") != "NETWORK_ACTIVE" or active.get("name") != SNAPSHOT_189 or retired_names != expected_retired or not isinstance(activation, dict) or set(activation) != ACTIVATION_REF_KEYS or activation.get("source") != "snapshot189-activation" or not _valid_sha(activation.get("evidence_sha256")):
            raise Pc020EvidenceError("epoch8 canonical shape differs")
        _fixed_evidence_path(activation.get("evidence_path"), "activation-189", "activation-evidence.json", "activation evidence path")
        _utc(activation.get("activated_at"), "activation activated_at")
    else:
        raise Pc020EvidenceError("only schema6 epoch7/8 shapes are reviewed")
    return {"schema_version": 6, "epoch": expected_epoch, "phase": document["phase"], "shape_valid": True, "activation_graph_validated": False, "operational_ready": False}

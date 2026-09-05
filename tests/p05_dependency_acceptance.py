from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from velociraptor_api import init_stub, run_vql_query, vql_literal


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
LOCKED_ROOT = Path(r"C:\VelociraptorMCP\dependencies\p05\locked")
TRIAGE_YAML = LOCKED_ROOT / "Windows.Triage.Targets.yaml"
KILL_YAML = REPO_ROOT / "tests" / "fixtures" / "artifacts" / "Generic.Utils.KillProcess.yaml"
MANIFEST_PATH = REPO_ROOT / "tests" / "data" / "p05_dependency_manifest.json"
EVIDENCE_ROOT = REPO_ROOT / "Logs" / "P05" / "wf-01a05d1d-p05"
TOOL_NAMES = ("etl2pcapng", "Autorun_386", "Autorun_amd64")
ARTIFACT_NAMES = ("Windows.Triage.Targets", "Generic.Utils.KillProcess")


class AcceptanceError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def inventory_rows() -> dict[str, list[dict[str, Any]]]:
    rows = run_vql_query(
        "SELECT * FROM inventory() "
        "WHERE name =~ '^(etl2pcapng|Autorun_386|Autorun_amd64)$' ORDER BY name",
        root_org=True,
    )
    result: dict[str, list[dict[str, Any]]] = {name: [] for name in TOOL_NAMES}
    for row in rows:
        name = row.get("name")
        if name not in result:
            raise AcceptanceError(f"unexpected inventory row: {name}")
        result[str(name)].append(row)
    if any(not result[name] for name in TOOL_NAMES):
        raise AcceptanceError("one or more required inventory names are missing")
    return result


def artifact_rows(name: str) -> list[dict[str, Any]]:
    return run_vql_query(
        "SELECT name, type, raw, parameters, sources, required_permissions "
        "FROM artifact_definitions() "
        f"WHERE name = {vql_literal(name)}",
        root_org=True,
    )


def _empty(value: Any) -> bool:
    return value in (None, "", [], {})


def predecessor_matches(name: str, row: dict[str, Any]) -> bool:
    common = (
        row.get("admin_override") is False
        and row.get("materialize") is False
        and all(_empty(row.get(key)) for key in ("version", "hash", "expected_hash", "invalid_hash"))
    )
    expected = {
        "etl2pcapng": {
            "artifact": "Windows.Network.PacketCapture",
            "filename": "etl2pcapng.zip",
            "serve_locally": False,
        },
        "Autorun_386": {
            "artifact": "Windows.Sysinternals.Autoruns",
            "filename": "autorunsc.exe",
            "serve_locally": True,
        },
        "Autorun_amd64": {
            "artifact": "Notebooks.Demo",
            "filename": "autorunsc64.exe",
            "serve_locally": True,
        },
    }[name]
    return common and all(row.get(key) == value for key, value in expected.items())


def target_matches(
    name: str,
    row: dict[str, Any],
    manifest: dict[str, Any],
) -> bool:
    item = next(value for value in manifest["dependencies"] if value["name"] == name)
    return (
        row.get("version") == item["version"]
        and row.get("filename") == item["filename"]
        and row.get("hash") == item["sha256"]
        and row.get("admin_override") is True
        # Supplying file= to inventory_add places the locked bytes directly in
        # filestore. Velociraptor therefore reports materialize=false: there is
        # no remote source left to materialize.
        and row.get("materialize") is False
        and row.get("serve_locally") is True
        and str(row.get("serve_url", "")).startswith("https://localhost:8000/public/")
        and bool(row.get("filestore_path"))
        and _empty(row.get("invalid_hash"))
    )


def probe_matches(name: str, rows: list[dict[str, Any]], manifest: dict[str, Any]) -> bool:
    if len(rows) != 1 or not isinstance(rows[0].get("Item"), dict):
        return False
    item = next(value for value in manifest["dependencies"] if value["name"] == name)
    probe = rows[0]["Item"]
    definition = probe.get("Definition")
    if not isinstance(definition, dict):
        return False
    prefix = f"Tool_{name}_"
    return (
        probe.get(prefix + "HASH") == item["sha256"]
        and probe.get(prefix + "FILENAME") == item["filename"]
        and str(probe.get(prefix + "URL", "")).startswith("https://localhost:8000/public/")
        and definition.get("name") == name
        and definition.get("version") == item["version"]
        and definition.get("filename") == item["filename"]
        and definition.get("hash") == item["sha256"]
        and definition.get("admin_override") is True
        and definition.get("serve_locally") is True
        and bool(definition.get("filestore_path"))
    )


def verify_local_public_bytes(
    name: str, row: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    item = next(value for value in manifest["dependencies"] if value["name"] == name)
    url = str(row.get("serve_url", ""))
    if not re.fullmatch(r"https://localhost:8000/public/[0-9a-f]{64}", url):
        raise AcceptanceError(f"target inventory URL is not the approved local public form: {name}")
    # The local Velociraptor listener uses its deployment certificate. The
    # response is authenticated by the exact locked SHA-256 rather than public
    # PKI, and the URL cannot leave localhost.
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(url, context=context, timeout=30) as response:
        payload = response.read(item["size"] + 1)
    actual = {
        "url": url,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    if actual["size"] != item["size"] or actual["sha256"] != item["sha256"]:
        raise AcceptanceError(f"local public filestore bytes mismatch: {name}")
    return actual


def target_group_matches(name: str, rows: list[dict[str, Any]], manifest: dict[str, Any]) -> bool:
    predecessors = [row for row in rows if row.get("admin_override") is False]
    overrides = [row for row in rows if row.get("admin_override") is True]
    return (
        len(predecessors) == 1
        and predecessor_matches(name, predecessors[0])
        and len(overrides) == 1
        and target_matches(name, overrides[0], manifest)
    )


def validate_locked_bytes(manifest: dict[str, Any]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for item in manifest["dependencies"]:
        path = LOCKED_ROOT / item["filename"]
        if not path.is_file():
            raise AcceptanceError(f"locked dependency is missing: {item['filename']}")
        actual = {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}
        if actual["sha256"] != item["sha256"] or actual["size"] != item["size"]:
            raise AcceptanceError(f"locked dependency identity mismatch: {item['name']}")
        evidence[item["name"]] = actual
    if not TRIAGE_YAML.is_file():
        raise AcceptanceError("locked triage YAML is missing")
    triage = manifest["triage_artifact"]
    if sha256_file(TRIAGE_YAML) != triage["yaml_sha256"] or TRIAGE_YAML.stat().st_size != triage["yaml_size"]:
        raise AcceptanceError("triage YAML identity mismatch")
    evidence["Windows.Triage.Targets"] = {
        "path": str(TRIAGE_YAML),
        "sha256": sha256_file(TRIAGE_YAML),
        "size": TRIAGE_YAML.stat().st_size,
    }
    evidence["Generic.Utils.KillProcess"] = {
        "path": str(KILL_YAML),
        "sha256": sha256_file(KILL_YAML),
        "size": KILL_YAML.stat().st_size,
    }
    return evidence


def install_inventory(item: dict[str, Any]) -> list[dict[str, Any]]:
    path = LOCKED_ROOT / item["filename"]
    query = (
        "SELECT inventory_add("
        f"tool={vql_literal(item['name'])},"
        f"version={vql_literal(item['version'])},"
        f"filename={vql_literal(item['filename'])},"
        "serve_locally=TRUE,"
        f"hash={vql_literal(item['sha256'])},"
        f"file={vql_literal(path.as_posix())},accessor='file') AS Result FROM scope()"
    )
    return run_vql_query(query, root_org=True)


def set_artifact(path: Path) -> list[dict[str, Any]]:
    definition = path.read_text(encoding="utf-8")
    return run_vql_query(
        "SELECT artifact_set(definition=" + vql_literal(definition) + ") AS Result FROM scope()",
        root_org=True,
    )


def validate_kill_definition(raw: str) -> None:
    required = (
        "name: Generic.Utils.KillProcess",
        "type: CLIENT",
        "required_permissions:",
        "  - EXECVE",
        "precondition: SELECT OS FROM info() WHERE OS = 'windows'",
        "  - name: Pid",
        "    type: int",
        "  - name: KillProcess",
        "SELECT Pid, pskill(pid=Pid) AS Killed FROM scope()",
    )
    if not all(token in raw for token in required):
        raise AcceptanceError("KillProcess definition does not match the reviewed golden")
    forbidden = ("tools:", "imports:", "exports:", "execve(", "http_client(", "process_tracker_pslist(")
    if any(token in raw for token in forbidden):
        raise AcceptanceError("KillProcess definition contains a forbidden capability")
    if len(re.findall(r"(?m)^\s*- name:", raw)) != 2:
        raise AcceptanceError("KillProcess must contain one parameter and one source")


def artifact_readback(name: str, expected_path: Path) -> dict[str, Any]:
    rows = artifact_rows(name)
    if len(rows) != 1:
        raise AcceptanceError(f"artifact must be uniquely defined: {name}")
    row = rows[0]
    raw = row.get("raw")
    if not isinstance(raw, str):
        raise AcceptanceError(f"artifact raw definition is missing: {name}")
    if name == "Generic.Utils.KillProcess":
        validate_kill_definition(raw)
    return {
        "name": name,
        "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "source_sha256": sha256_file(expected_path),
        "type": row.get("type"),
        "parameters": row.get("parameters"),
        "required_permissions": row.get("required_permissions"),
        "sources": row.get("sources"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("inspect", "prepare", "verify"), required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"p05-[a-z0-9-]{4,80}", args.attempt_id):
        raise AcceptanceError("invalid attempt id")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    validate_kill_definition(KILL_YAML.read_text(encoding="utf-8"))
    init_stub()
    before_inventory = inventory_rows()
    before_artifacts = {name: artifact_rows(name) for name in ARTIFACT_NAMES}
    mode = "unknown"
    if all(
        len(before_inventory[name]) == 1
        and predecessor_matches(name, before_inventory[name][0])
        for name in TOOL_NAMES
    ) and all(
        len(before_artifacts[name]) == 0 for name in ARTIFACT_NAMES
    ):
        mode = "predecessor"
    elif all(
        target_group_matches(name, before_inventory[name], manifest)
        for name in TOOL_NAMES
    ) and all(
        len(before_artifacts[name]) == 1 for name in ARTIFACT_NAMES
    ):
        mode = "target"
    if mode == "unknown":
        raise AcceptanceError("runtime dependencies are neither the reviewed predecessor nor target identity")

    evidence: dict[str, Any] = {
        "schema": "p05-dependency-acceptance-v1",
        "workflow_id": WORKFLOW_ID,
        "attempt_id": args.attempt_id,
        "started_at": now(),
        "requested_mode": args.mode,
        "initial_state": mode,
        "before": {"inventory": before_inventory, "artifacts": before_artifacts},
        "writes": [],
    }
    if args.mode == "prepare":
        locked = validate_locked_bytes(manifest)
        evidence["locked_bytes"] = locked
        if mode == "predecessor":
            for item in manifest["dependencies"]:
                evidence["writes"].append({"inventory_add": item["name"], "result": install_inventory(item)})
            evidence["writes"].append({"artifact_set": "Windows.Triage.Targets", "result": set_artifact(TRIAGE_YAML)})
            evidence["writes"].append({"artifact_set": "Generic.Utils.KillProcess", "result": set_artifact(KILL_YAML)})
        else:
            evidence["writes"].append({"result": "NO_CHANGE"})
    elif args.mode == "inspect":
        evidence["ok"] = True
        evidence["ended_at"] = now()
        print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
        return 0

    probes = {}
    for name in TOOL_NAMES:
        probes[name] = run_vql_query(
            f"SELECT inventory_get(tool={vql_literal(name)}, probe=TRUE) AS Item FROM scope()",
            root_org=True,
        )
    after_inventory = inventory_rows()
    selected_targets = {}
    for name in TOOL_NAMES:
        overrides = [row for row in after_inventory[name] if row.get("admin_override") is True]
        if not target_group_matches(name, after_inventory[name], manifest):
            raise AcceptanceError(f"target inventory override readback is incomplete: {name}")
        if not probe_matches(name, probes[name], manifest):
            raise AcceptanceError(f"target inventory probe is incomplete: {name}")
        selected_targets[name] = overrides[0]
    after_artifacts = {
        "Windows.Triage.Targets": artifact_readback("Windows.Triage.Targets", TRIAGE_YAML),
        "Generic.Utils.KillProcess": artifact_readback("Generic.Utils.KillProcess", KILL_YAML),
    }
    local_public_bytes = {
        name: verify_local_public_bytes(name, selected_targets[name], manifest)
        for name in TOOL_NAMES
    }
    evidence["after"] = {
        "inventory": after_inventory,
        "selected_target_overrides": selected_targets,
        "inventory_probe": probes,
        "local_public_bytes": local_public_bytes,
        "artifacts": after_artifacts,
    }
    evidence["ok"] = True
    evidence["ended_at"] = now()
    output_dir = EVIDENCE_ROOT / args.attempt_id
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"dependency-{args.mode}.json"
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "evidence": str(output)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as exc:
        print(f"p05-dependency-acceptance: {exc}", file=sys.stderr)
        raise SystemExit(2)

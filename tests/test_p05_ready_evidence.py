"""Synthetic parser regressions for P05 ready raw-evidence contracts.

These fixtures exercise only the fail-closed parser.  They are deliberately
not represented as Windows execution evidence.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from tests import p05_ready_evidence as ready_evidence


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ready_evidence.WORKFLOW_ID
RUN_ID = "d80e4567-ea57-4f53-b8db-6cfbb0df162a"
RESTORE_ID = "restore-188-a"


def utc(second: int, *, minute: int = 0) -> str:
    return datetime(2026, 9, 13, 12, minute, second, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def win_process(pid: int, parent: int, creation: str, *, name: str, executable: str | None, command: str | None) -> dict:
    return {
        "ProcessId": pid,
        "ParentProcessId": parent,
        "Name": name,
        "ExecutablePath": executable,
        "CreationDate": creation,
        "CommandLine": command,
    }


def host_process(pid: int, parent: int, creation: str, executable: str, executable_sha256: str, argv: str) -> dict:
    return {
        "pid": pid,
        "parent_pid": parent,
        "creation_time_utc": creation,
        "executable": executable,
        "executable_sha256": executable_sha256,
        "argv": argv,
    }


class ReadyRawEvidenceTests(unittest.TestCase):
    def _write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    def _reference(self, root: Path, relative: str) -> dict:
        raw = (root / relative).read_bytes()
        return {"path": relative, "size": len(raw), "sha256": sha(raw)}

    def _envelope(self, observation: str, scope: str, payload: dict, *, computer_name: str) -> dict:
        stdout = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        stderr = ""
        return {
            "schema_version": 1,
            "kind": "p05-ready-command-v1",
            "observation": observation,
            "workflow_id": WORKFLOW,
            "run_id": RUN_ID,
            "restore_attempt_id": RESTORE_ID,
            "host": {"scope": scope, "computer_name": computer_name},
            "request": {"argv": ["powershell.exe", "-Command", "fixed-read-only-observation"], "command_line": "powershell.exe -Command fixed-read-only-observation"},
            "started_at": utc(0),
            "ended_at": utc(30),
            "exit_status": {"code": 0},
            "response": {
                "stdout": stdout,
                "stdout_size": len(stdout.encode("utf-8")),
                "stdout_sha256": sha(stdout.encode("utf-8")),
                "stderr": stderr,
                "stderr_size": 0,
                "stderr_sha256": sha(b""),
            },
        }

    def _sid_bytes(self, value: str) -> bytes:
        parts = value.split("-")
        self.assertGreaterEqual(len(parts), 4)
        self.assertEqual(parts[:2], ["S", "1"])
        authority = int(parts[2])
        subauthorities = [int(item) for item in parts[3:]]
        return bytes((1, len(subauthorities))) + authority.to_bytes(6, "big") + struct.pack(
            "<" + "I" * len(subauthorities), *subauthorities
        )

    def _acl_projection(self, rules: list[dict]) -> dict:
        """Make a real self-relative SD plus matching SDDL/ACE projections.

        This is synthetic parser data, not an assertion about a Windows ACL.
        Keeping all three forms mechanically tied makes the positive fixture
        exercise the same cross-platform binary and SDDL checks as guest data.
        """
        ace_bytes: list[bytes] = []
        aliases = {"S-1-5-18": "SY", "S-1-5-32-544": "BA", "S-1-5-11": "AU", "S-1-5-32-545": "BU"}
        flags_text = ((1, "OI"), (2, "CI"), (4, "NP"), (8, "IO"), (16, "ID"))
        sddl_aces: list[str] = []
        projected: list[dict] = []
        for original in rules:
            rule = deepcopy(original)
            ace_type = rule.get("ace_type", 0)
            ace_flags = rule.get("ace_flags", 0)
            mask = rule["access_mask"]
            raw = struct.pack("<BBHI", ace_type, ace_flags, 8 + len(self._sid_bytes(rule["sid"])), mask) + self._sid_bytes(rule["sid"])
            ace_bytes.append(raw)
            rule.update({
                "ace_type": ace_type,
                "ace_flags": ace_flags,
                "access_control_type": "Allow" if ace_type == 0 else "Deny",
                "is_inherited": bool(ace_flags & 16),
                "inheritance_flags": (ace_flags & 1) | (2 if ace_flags & 2 else 0),
                "propagation_flags": (1 if ace_flags & 4 else 0) | (2 if ace_flags & 8 else 0),
                "raw_ace_base64": base64.b64encode(raw).decode("ascii"),
            })
            projected.append(rule)
            flags = "".join(token for bit, token in flags_text if ace_flags & bit)
            sddl_aces.append(f"({'A' if ace_type == 0 else 'D'};{flags};0x{mask:08x};;;{aliases.get(rule['sid'], rule['sid'])})")
        dacl = struct.pack("<BBHHH", 2, 0, 8 + sum(len(item) for item in ace_bytes), len(ace_bytes), 0) + b"".join(ace_bytes)
        descriptor = struct.pack("<BBHLLLL", 1, 0, 0x8004, 0, 0, 0, 20) + dacl
        return {
            "security_descriptor_base64": base64.b64encode(descriptor).decode("ascii"),
            "sddl": "O:SYG:BAD:" + "".join(sddl_aces),
            "access_rules": projected,
        }

    def _acl_row(self, role: str, path: str, file_type: str, rules: list[dict]) -> dict:
        return {
            "role": role,
            "path": path,
            "is_reparse_point": False,
            "file_type": file_type,
            **self._acl_projection(rules),
        }

    def _valid_inputs(self, root: Path) -> tuple[dict, dict]:
        spec_bytes = (ROOT / "tests/data/p05_fixture_spec.json").read_bytes()
        parent_bytes = (ROOT / "tests/p05_process_parent.py").read_bytes()
        kill_bytes = (ROOT / "tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml").read_bytes()
        manifest = json.loads((ROOT / "tests/data/p05_dependency_manifest.json").read_text(encoding="utf-8"))
        # This fixture is synthetic: freeze a self-consistent triage definition
        # in its copied source rather than claiming that an old Logs original
        # is a current Windows observation.
        triage_raw = "name: Windows.Triage.Targets\ntype: CLIENT\nsources: []\n"
        manifest["triage_artifact"]["yaml_size"] = len(triage_raw.encode("utf-8"))
        manifest["triage_artifact"]["yaml_sha256"] = sha(triage_raw.encode("utf-8"))
        (root / "source/tests/data").mkdir(parents=True)
        (root / "source/tests/p05_process_parent.py").parent.mkdir(parents=True, exist_ok=True)
        (root / "source/tests/fixtures/artifacts").mkdir(parents=True, exist_ok=True)
        (root / "source/tests/data/p05_fixture_spec.json").write_bytes(spec_bytes)
        self._write_json(root / "source/tests/data/p05_dependency_manifest.json", manifest)
        (root / "source/tests/p05_process_parent.py").write_bytes(parent_bytes)
        (root / "source/tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml").write_bytes(kill_bytes)
        spec = json.loads(spec_bytes)
        attempt = "p05-attempt-010"
        fixture_command = rf'C:\mcp-velociraptor\.venv\Scripts\python.exe -c "import time; time.sleep(86400)" "{WORKFLOW}" "{attempt}"'
        fixture = {
            "schema_version": 1,
            "fixture_spec_sha256": sha(spec_bytes),
            "workflow_id": WORKFLOW,
            "attempt_id": attempt,
            "ownership_marker": {"path": r"C:\VelociraptorMCP\fixtures-p05\.p05-owner.json", "workflow_id": WORKFLOW},
            "hostname": ready_evidence.GUEST_COMPUTER_NAME,
            "fixture_root": ready_evidence.FIXTURE_ROOT,
            "files": [
                {"path": str(Path(ready_evidence.FIXTURE_ROOT) / item["path"]), "relative_path": item["path"], "sha256": item["sha256"], "size": item["size"]}
                for item in spec["files"]
            ],
            "registry": {"path": rf"HKLM:\SOFTWARE\VelociraptorMCP\P05\{WORKFLOW}", "values": {"Owner": WORKFLOW, "Attempt": attempt, "FixtureVersion": 1}},
            "event": {"log": "Application", "source": "VelociraptorMCP-P05", "event_id": 42005, "message": f"{WORKFLOW}|{attempt}|fixture-v1", "record_id": 42},
            "task": {"path": "\\VelociraptorMCP\\", "name": "P05-Fixture", "enabled": False, "triggers": [], "execute": r"%SystemRoot%\System32\cmd.exe", "arguments": "/d /c exit 0"},
            "process": {"pid": 600, "creation_time_utc": utc(2), "token": f"{WORKFLOW}|{attempt}", "interpreter": r"C:\mcp-velociraptor\.venv\Scripts\python.exe", "command_line": fixture_command, "sleep_seconds": 86400},
        }
        parent_sha = sha(parent_bytes)
        roots = {"fixture": (500, 501), "frontend": (510, 511), "client": (520, 521)}
        commands = {
            "fixture": ["powershell.exe", "-NoProfile", "-Command", "prepare fixture"],
            "frontend": [r"C:\VelociraptorMCP\bin\velociraptor-v0.77.2-windows-amd64.exe", "-v", "frontend"],
            "client": [r"C:\VelociraptorMCP\bin\velociraptor-v0.77.2-windows-amd64.exe", "-v", "client"],
        }
        guest_rows = [
            win_process(0, 0, utc(0), name="System Idle Process", executable=None, command=None),
            win_process(4, 0, utc(0), name="System", executable=None, command=None),
            win_process(100, 4, utc(0), name="services.exe", executable=r"C:\Windows\System32\services.exe", command=None),
        ]
        records = []
        for role, (parent_pid, child_pid) in roots.items():
            parent = win_process(parent_pid, 100, utc(0), name="python.exe", executable=r"C:\mcp-velociraptor\.venv\Scripts\python.exe", command=f"p05_process_parent.py --role {role}")
            child_command = subprocess.list2cmdline(commands[role])
            child = win_process(child_pid, parent_pid, utc(1), name=("powershell.exe" if role == "fixture" else "velociraptor.exe"), executable=commands[role][0], command=child_command)
            guest_rows.extend((parent, child))
            record = {
                "role": role,
                "parent_pid": parent_pid,
                "parent_parent_pid": 100,
                "argv": commands[role],
                "started_at": utc(0),
                "source_sha256": parent_sha,
                "child_pid": child_pid,
                "parent_identity": deepcopy(parent),
                "child_identity": deepcopy(child),
                "identity_observed": True,
            }
            if role == "fixture":
                target = win_process(600, child_pid, utc(2), name="python.exe", executable=fixture["process"]["interpreter"], command=fixture_command)
                guest_rows.append(target)
                fixture_stdout = json.dumps(fixture, ensure_ascii=False, separators=(",", ":"))
                record["fixture_binding"] = {"instance_sha256": sha(fixture_stdout.encode("utf-8")), "process_identity": deepcopy(target), "preparer_identity": deepcopy(child)}
            records.append(record)
        payloads = {
            "host_clock": {"before_guest_identity_utc": utc(5), "after_guest_identity_utc": utc(15)},
            "guest_identity": {"computer_name": ready_evidence.GUEST_COMPUTER_NAME, "guest_utc": utc(10), "api_client_rows": [{"client_id": ready_evidence.WINDOWS_CLIENT_ID, "os": "windows", "hostname": ready_evidence.GUEST_COMPUTER_NAME}]},
            "fixture_static": {
                "fixture_spec_sha256": sha(spec_bytes),
                "fixture_instance": {"path": r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json", "is_reparse_point": False, "file_type": "file", "sha256": sha(json.dumps(fixture, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))},
                "fixture_root": {"path": ready_evidence.FIXTURE_ROOT, "is_reparse_point": False, "file_type": "directory"},
                "ownership_marker": {"path": r"C:\VelociraptorMCP\fixtures-p05\.p05-owner.json", "is_reparse_point": False, "file_type": "file", "content": {"schema_version": 1, "workflow_id": WORKFLOW}},
                "files": [
                    {"path": row["path"], "relative_path": row["relative_path"], "size": row["size"], "sha256": row["sha256"], "is_reparse_point": False, "file_type": "file"}
                    for row in fixture["files"]
                ],
                "registry": deepcopy(fixture["registry"]),
                "event_rows": [deepcopy(fixture["event"])],
                "task": deepcopy(fixture["task"]),
            },
            "fixture_instance": fixture,
            "guest_processes": {"captured_at_utc": utc(12), "processes": guest_rows},
            "parent_bindings": {"source_sha256": parent_sha, "launch_records": records},
            "host_processes": {"captured_at_utc": utc(12), "processes": [host_process(6990, 1, utc(0), "/usr/bin/python3", "b" * 64, "python supervisor.py"), host_process(7000, 6990, utc(1), "/usr/bin/python3", "a" * 64, "python scenario_runner.py")]},
        }
        inventory_rows = []
        predecessor = {
            "Autorun_386": {"artifact": "Windows.Sysinternals.Autoruns", "filename": "autorunsc.exe", "serve_locally": True},
            "Autorun_amd64": {"artifact": "Notebooks.Demo", "filename": "autorunsc64.exe", "serve_locally": True},
        }
        for item in manifest["dependencies"]:
            name = item["name"]
            inventory_rows.append({
                "name": name, "artifact": predecessor[name]["artifact"], "filename": predecessor[name]["filename"],
                # The restorable pristine predecessor: unmaterialized (empty
                # version/hash) but carrying the artifact definition's declared
                # serve_url and expected filestore_path (PLAN-CHANGE-013).
                "version": "", "hash": "", "admin_override": False, "materialize": False,
                "serve_locally": predecessor[name]["serve_locally"],
                "serve_url": (f"https://localhost:8000/public/{item['sha256']}" if predecessor[name]["serve_locally"] else "https://example.invalid/upstream/tool.zip"),
                "filestore_path": f"fs/{item['sha256']}", "invalid_hash": "",
            })
            inventory_rows.append({
                "name": name, "artifact": predecessor[name]["artifact"], "filename": item["filename"],
                "version": item["version"], "hash": item["sha256"], "admin_override": True,
                "materialize": False, "serve_locally": True,
                "serve_url": "https://localhost:8000/public/" + "d" * 64,
                "filestore_path": "d" * 64, "invalid_hash": None,
            })
        local_public_bytes = []
        locked_files = []
        for item in manifest["dependencies"]:
            name = item["name"]
            local_public_bytes.append({"name": name, "url": "https://localhost:8000/public/" + "d" * 64, "size": item["size"], "sha256": item["sha256"]})
            locked_files.append({"name": name, "path": rf"C:\VelociraptorMCP\dependencies\p05\locked\{item['filename']}", "size": item["size"], "sha256": item["sha256"]})
        payloads["dependencies"] = {
            "dependency_manifest_sha256": sha((root / "source/tests/data/p05_dependency_manifest.json").read_bytes()),
            "inventory_rows": inventory_rows,
            "local_public_bytes": local_public_bytes,
            "locked_files": locked_files,
            "artifact_rows": [
                {"name": "Windows.Triage.Targets", "type": "CLIENT", "raw": triage_raw, "parameters": [], "sources": [], "required_permissions": []},
                {"name": "Generic.Utils.KillProcess", "type": "CLIENT", "raw": kill_bytes.decode("utf-8"), "parameters": [], "sources": [], "required_permissions": []},
            ],
        }
        service_sid = ready_evidence.SERVICE_SID
        payloads["service"] = {
            "service_python_base": "C:\\Python313\\python.exe",
            "service_rows": [{"name": ready_evidence.SERVICE_NAME, "state": "Running", "start_name": ready_evidence.SERVICE_ACCOUNT, "start_mode": "Auto", "process_id": 800, "path_name": r'"C:\mcp-velociraptor\.venv\Scripts\python.exe" "C:\mcp-velociraptor\tests\p05_service_host.py"'}],
            "service_process_rows": [{"ProcessId": 800, "ParentProcessId": 100, "Name": "python.exe", "ExecutablePath": r"C:\Python313\python.exe", "CreationDate": utc(2), "CommandLine": r'"C:\mcp-velociraptor\.venv\Scripts\python.exe" "C:\mcp-velociraptor\tests\p05_service_host.py"', "executable_sha256": "c" * 64}],
            "listeners": [{"LocalAddress": ready_evidence.GUEST_FIXED_ADDRESS, "LocalPort": ready_evidence.SERVICE_PORT, "State": "Listen", "OwningProcess": 800}],
        }
        system = {"identity": "NT AUTHORITY\\SYSTEM", "sid": "S-1-5-18", "access_control_type": "Allow", "access_mask": 0x1F01FF, "is_inherited": False, "inheritance_flags": 0, "propagation_flags": 0}
        admins = {"identity": "BUILTIN\\Administrators", "sid": "S-1-5-32-544", "access_control_type": "Allow", "access_mask": 0x1F01FF, "is_inherited": False, "inheritance_flags": 0, "propagation_flags": 0}
        service_read = {"identity": ready_evidence.SERVICE_ACCOUNT, "sid": service_sid, "access_control_type": "Allow", "access_mask": 0x1200A9, "is_inherited": False, "inheritance_flags": 0, "propagation_flags": 0}
        service_write = {**service_read, "access_mask": 0x1301BF}
        acl_rows = {
            role: self._acl_row(role, path, kind, rules)
            for role, path, kind, rules in (
                ("code_root", r"C:\mcp-velociraptor", "directory", [system, admins, service_read]),
                ("service_python", r"C:\mcp-velociraptor\.venv\Scripts\python.exe", "file", [system, admins, service_read]),
                ("service_host", r"C:\mcp-velociraptor\tests\p05_service_host.py", "file", [system, admins, service_read]),
                ("protected_env", r"C:\VelociraptorMCP\secrets\mcp-service.env", "file", [system, admins, service_read]),
                ("api_client_config", r"C:\VelociraptorMCP\secrets\api_client_service.yaml", "file", [system, admins, service_read]),
                ("download_root", r"C:\VelociraptorMCP\downloads", "directory", [system, admins, service_write]),
                ("runtime_logs", r"C:\mcp-velociraptor\Logs", "directory", [system, admins, service_write]),
            )
        }
        code_acl = self._acl_projection([system, admins, service_read])
        def tree_node(path: str, file_type: str, scope: str, children: list[str], acl: dict) -> dict:
            return {"path": path, "is_reparse_point": False, "file_type": file_type, "scope": scope, "children": children, "acl": deepcopy(acl)}
        code_root = r"C:\mcp-velociraptor"
        venv = code_root + r"\.venv"
        scripts = venv + r"\Scripts"
        tests = code_root + r"\tests"
        logs = code_root + r"\Logs"
        payloads["acl"] = {
            "service_account": {"name": ready_evidence.SERVICE_ACCOUNT, "sid": service_sid},
            "paths": list(acl_rows.values()),
            "code_tree": {
                "root": code_root,
                "runtime_logs_root": logs,
                "nodes": [
                    tree_node(code_root, "directory", "code", [venv, tests, logs], self._acl_projection([system, admins, service_read])),
                    tree_node(venv, "directory", "code", [scripts], code_acl),
                    tree_node(scripts, "directory", "code", [acl_rows["service_python"]["path"]], code_acl),
                    tree_node(acl_rows["service_python"]["path"], "file", "code", [], {key: acl_rows["service_python"][key] for key in ("security_descriptor_base64", "sddl", "access_rules")}),
                    tree_node(tests, "directory", "code", [acl_rows["service_host"]["path"]], code_acl),
                    tree_node(acl_rows["service_host"]["path"], "file", "code", [], {key: acl_rows["service_host"][key] for key in ("security_descriptor_base64", "sddl", "access_rules")}),
                    tree_node(logs, "directory", "runtime_logs", [], {key: acl_rows["runtime_logs"][key] for key in ("security_descriptor_base64", "sddl", "access_rules")}),
                ],
            },
        }
        payloads["firewall"] = {"rules": [{"name": "mcp-velociraptor-28790", "display_name": "mcp-velociraptor-28790", "direction": "Inbound", "action": "Allow", "enabled": True, "protocol": "TCP", "local_port": 28790, "local_address": ready_evidence.GUEST_FIXED_ADDRESS, "remote_address": ready_evidence.HOST_FIXED_ADDRESS}]}
        payloads["resources"] = {"owned_flows": [], "owned_hunts": [], "historical_flows": [], "historical_hunts": [], "trace": {"argv": ["netsh.exe", "trace", "show", "status"], "exit_status": 0, "stdout": "No trace session currently in progress.", "stderr": ""}, "temporary_listeners": []}
        for name, payload in payloads.items():
            scope = "host" if name in {"host_clock", "host_processes"} else "guest"
            computer = "HOST-READY" if scope == "host" else ready_evidence.GUEST_COMPUTER_NAME
            envelope = self._envelope(name, scope, payload, computer_name=computer)
            if name == "guest_identity":
                envelope["started_at"], envelope["ended_at"] = utc(6), utc(14)
            if name == "host_clock":
                envelope["started_at"], envelope["ended_at"] = utc(4), utc(16)
            self._write_json(root / f"raw/{name}.json", envelope)
        observations = {name: self._reference(root, f"raw/{name}.json") for name in ready_evidence.RAW_OBSERVATIONS}
        ready = {"schema_version": 1, "workflow_id": WORKFLOW, "run_id": RUN_ID, "restore_attempt_id": RESTORE_ID, "snapshot_stage": "P05_REPAIR_CANDIDATE", "snapshot_name": "Snapshot 188-Velociraptor-MCP可恢复验收基线", "checkpoint_marker": "Win10MalBox-Velo-Snapshot341.vmsn", "observations": observations}
        report = {"run_id": RUN_ID, "runner": {"pid": 7000, "process_start_time_utc": utc(1), "executable_sha256": "a" * 64}}
        return ready, report

    def _rewrite_payload(self, root: Path, ready: dict, name: str, payload: dict) -> None:
        path = root / f"raw/{name}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        stdout = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        document["response"]["stdout"] = stdout
        document["response"]["stdout_size"] = len(stdout.encode("utf-8"))
        document["response"]["stdout_sha256"] = sha(stdout.encode("utf-8"))
        self._write_json(path, document)
        ready["observations"][name] = self._reference(root, f"raw/{name}.json")

    def test_valid_synthetic_transcripts_validate_without_claiming_windows_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            facts = ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)
        self.assertEqual(facts["fixture_pid"], 600)
        self.assertEqual(facts["guest_computer_name"], "DESKTOP-3FI41GR")
        self.assertEqual(facts["service_process_id"], 800)
        self.assertEqual(facts["formal_listener"]["LocalPort"], 28790)

    def test_rejects_summary_instead_of_raw_api_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            self._rewrite_payload(root, ready, "guest_identity", {"passed": True})
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "prohibited summary"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_guest_clock_outside_fixed_120_second_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/guest_identity.json").read_text(encoding="utf-8"))["response"]["stdout"]
            guest = json.loads(payload)
            guest["guest_utc"] = utc(16, minute=2)
            self._rewrite_payload(root, ready, "guest_identity", guest)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "outside the host UTC interval"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_fixture_pid_reuse_when_creation_time_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/guest_processes.json").read_text(encoding="utf-8"))["response"]["stdout"]
            processes = json.loads(payload)
            next(row for row in processes["processes"] if row["ProcessId"] == 600)["CreationDate"] = utc(3)
            self._rewrite_payload(root, ready, "guest_processes", processes)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "creation time differs"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_unbound_or_incomplete_command_transcript(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            path = root / "raw/host_processes.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            del document["exit_status"]
            self._write_json(path, document)
            ready["observations"]["host_processes"] = self._reference(root, "raw/host_processes.json")
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "keys are invalid"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_fixture_static_reparse_point(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/fixture_static.json").read_text(encoding="utf-8"))["response"]["stdout"]
            static = json.loads(payload)
            static["files"][0]["is_reparse_point"] = True
            self._rewrite_payload(root, ready, "fixture_static", static)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "plain-file contract"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_dependency_summary_instead_of_raw_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            self._rewrite_payload(root, ready, "dependencies", {"passed": True})
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "prohibited summary"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_service_listener_owned_by_another_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/service.json").read_text(encoding="utf-8"))["response"]["stdout"]
            service = json.loads(payload)
            service["listeners"][0]["OwningProcess"] = 801
            self._rewrite_payload(root, ready, "service", service)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "formal service instance"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_predecessor_row_that_is_materialized_or_versioned(self):
        for mutation, pattern in (
            (lambda row: row.update({"materialize": True}), "predecessor inventory row differs"),
            (lambda row: row.update({"version": "14.3"}), "predecessor inventory row differs"),
            (lambda row: row.update({"hash": "a" * 64}), "predecessor inventory row differs"),
            (lambda row: row.update({"serve_url": ""}), "predecessor inventory row differs"),
        ):
            with self.subTest(mutation=pattern), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, report = self._valid_inputs(root)
                payload = json.loads((root / "raw/dependencies.json").read_text(encoding="utf-8"))["response"]["stdout"]
                dependencies = json.loads(payload)
                row = next(r for r in dependencies["inventory_rows"] if r["admin_override"] is False)
                mutation(row)
                self._rewrite_payload(root, ready, "dependencies", dependencies)
                with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, pattern):
                    ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_acl_write_access_for_ordinary_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/acl.json").read_text(encoding="utf-8"))["response"]["stdout"]
            acl = json.loads(payload)
            rules = deepcopy(acl["paths"][0]["access_rules"])
            rules.append({
                "identity": "NT AUTHORITY\\Authenticated Users", "sid": "S-1-5-11",
                "access_mask": 0x1301BF,
            })
            acl["paths"][0].update(self._acl_projection(rules))
            self._rewrite_payload(root, ready, "acl", acl)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "write access to service code"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_firewall_rule_with_non_exact_remote_address(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/firewall.json").read_text(encoding="utf-8"))["response"]["stdout"]
            firewall = json.loads(payload)
            firewall["rules"][0]["remote_address"] = "192.168.204.0/24"
            self._rewrite_payload(root, ready, "firewall", firewall)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "exact 28790 host-only boundary"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_active_trace_or_temporary_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            payload = json.loads((root / "raw/resources.json").read_text(encoding="utf-8"))["response"]["stdout"]
            resources = json.loads(payload)
            resources["trace"]["stdout"] = "Trace session is running."
            self._rewrite_payload(root, ready, "resources", resources)
            with self.assertRaisesRegex(ready_evidence.ReadyEvidenceError, "trace status is not inactive"):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_acl_role_path_substitution_and_inherit_only_service_access(self):
        for change in ('path', 'inherit_only', 'write_attributes', 'delete_child'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, report = self._valid_inputs(root)
                acl = json.loads(json.loads((root / 'raw/acl.json').read_text())['response']['stdout'])
                if change == 'path':
                    acl['paths'][0]['path'] = r'C:\unrelated-directory'
                else:
                    rules = deepcopy(acl['paths'][0]['access_rules'])
                    if change == 'inherit_only':
                        rules[2]['ace_flags'] = 8
                    else:
                        rules[2]['access_mask'] |= 0x100 if change == 'write_attributes' else 0x40
                    acl['paths'][0].update(self._acl_projection(rules))
                self._rewrite_payload(root, ready, 'acl', acl)
                with self.assertRaises(ready_evidence.ReadyEvidenceError):
                    ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_other_service_executable_with_matching_pid_and_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, report = self._valid_inputs(root)
            service = json.loads(json.loads((root / 'raw/service.json').read_text())['response']['stdout'])
            service['service_process_rows'][0]['ExecutablePath'] = r'C:\other\python.exe'
            self._rewrite_payload(root, ready, 'service', service)
            with self.assertRaises(ready_evidence.ReadyEvidenceError):
                ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_acl_code_tree_gaps_reparse_and_child_acl_exception(self):
        for change in ("missing_python", "missing_intermediate", "reparse", "child_write"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, report = self._valid_inputs(root)
                acl = json.loads(json.loads((root / "raw/acl.json").read_text(encoding="utf-8"))["response"]["stdout"])
                nodes = acl["code_tree"]["nodes"]
                if change == "missing_python":
                    nodes[:] = [node for node in nodes if not node["path"].endswith(r"Scripts\python.exe")]
                elif change == "missing_intermediate":
                    nodes[:] = [node for node in nodes if not node["path"].endswith(r"\.venv\Scripts")]
                elif change == "reparse":
                    next(node for node in nodes if node["path"].endswith(r"\tests"))["is_reparse_point"] = True
                else:
                    node = next(node for node in nodes if node["path"].endswith(r"\tests\p05_service_host.py"))
                    rules = deepcopy(node["acl"]["access_rules"])
                    rules.append({"identity": "BUILTIN\\Users", "sid": "S-1-5-32-545", "access_mask": 0x00000100})
                    node["acl"] = self._acl_projection(rules)
                self._rewrite_payload(root, ready, "acl", acl)
                with self.assertRaises(ready_evidence.ReadyEvidenceError):
                    ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_acl_service_sid_secret_extra_account_and_inherit_only_read(self):
        for change in ("other_sid", "secret_extra", "inherit_only_read"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, report = self._valid_inputs(root)
                acl = json.loads(json.loads((root / "raw/acl.json").read_text(encoding="utf-8"))["response"]["stdout"])
                if change == "other_sid":
                    row = next(row for row in acl["paths"] if row["role"] == "service_python")
                    rules = deepcopy(row["access_rules"])
                    rules[2].update({"sid": "S-1-5-80-1-2-3-4-5", "identity": "NT SERVICE\\other-service"})
                    row.update(self._acl_projection(rules))
                elif change == "secret_extra":
                    row = next(row for row in acl["paths"] if row["role"] == "protected_env")
                    rules = deepcopy(row["access_rules"])
                    rules.append({"identity": "BUILTIN\\Users", "sid": "S-1-5-32-545", "access_mask": 0x00120089})
                    row.update(self._acl_projection(rules))
                else:
                    row = next(row for row in acl["paths"] if row["role"] == "api_client_config")
                    rules = deepcopy(row["access_rules"])
                    rules[2]["ace_flags"] = 8
                    row.update(self._acl_projection(rules))
                self._rewrite_payload(root, ready, "acl", acl)
                with self.assertRaises(ready_evidence.ReadyEvidenceError):
                    ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)

    def test_rejects_acl_raw_inheritance_or_sddl_projection_conflict(self):
        for change in ("raw_ace", "sddl"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, report = self._valid_inputs(root)
                acl = json.loads(json.loads((root / "raw/acl.json").read_text(encoding="utf-8"))["response"]["stdout"])
                row = next(row for row in acl["paths"] if row["role"] == "download_root")
                if change == "raw_ace":
                    row["access_rules"][2]["raw_ace_base64"] = ""
                else:
                    row["sddl"] = row["sddl"].replace("0x001301bf", "0x001200a9")
                self._rewrite_payload(root, ready, "acl", acl)
                with self.assertRaises(ready_evidence.ReadyEvidenceError):
                    ready_evidence.verify_ready_raw_evidence(ready, bundle_root=root, report=report)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests import p05_pc020_evidence as evidence


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def ref(root: Path, path: str) -> dict[str, object]:
    data = (root / path).read_bytes()
    return {"path": path, "size": len(data), "sha256": sha(data)}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence.canonical_json(value))


def response(stdout: str, stderr: str = "") -> dict[str, object]:
    return {
        "stdout": stdout, "stdout_size": len(stdout.encode()), "stdout_sha256": sha(stdout.encode()),
        "stderr": stderr, "stderr_size": len(stderr.encode()), "stderr_sha256": sha(stderr.encode()),
    }


def snapshot_command(operation: str, observation: str, stdout: str, argv: list[str]) -> dict[str, object]:
    return {
        "schema_version": 1, "kind": "p05-snapshot-command-v1", "workflow_id": evidence.WORKFLOW_ID,
        "operation_id": operation, "observation": observation, "vmx": evidence.VMX,
        "request": {"argv": argv, "command_line": " ".join(argv)},
        "started_at": "2026-09-20T01:00:00Z", "ended_at": "2026-09-20T01:00:01Z",
        "exit_status": {"code": 0}, "response": response(stdout),
    }


def test_environment() -> dict[str, str]:
    env = dict(os.environ)
    env["PC020_RECEIVER_IPS"] = "203.0.113.77"
    env["PC020_RECEIVER_LISTENER"] = "__PRESENT__"
    env["PC020_RECEIVER_IO_ENDPOINT"] = "http://203.0.113.88:1"
    return env


def receiver_document(mode: str) -> tuple[int, str, str]:
    """Return (exit_code, stdout, stderr) for one collector outcome.

    The absent outcome is produced by really executing the fixed Linux
    collector argv on this host; the remaining modes are document-level
    outcomes (wrong identity, still-listening port, or query failure) that
    cannot be produced on a healthy receiver host and are constructed.
    """
    if mode == "absent":
        # The collector reads /proc, so only the Linux receiver host itself
        # can execute it for real; the Windows isolated suite constructs the
        # byte-identical document and marks it as platform-simulated.
        import subprocess as sp
        if os.name == "posix":
            completed = sp.run(
                list(evidence.RECEIVER_STOPPED_ARGV),
                capture_output=True, text=True, encoding="utf-8", errors="strict", check=False,
            )
            return completed.returncode, completed.stdout, completed.stderr
        payload = {
            "schema_version": 1, "observer_ipv4": "192.168.204.1",
            "endpoint": "http://192.168.204.1:28786/",
            "interface_ipv4": ["192.168.204.1"], "rows": [],
        }
        return 0, json.dumps(payload, separators=(",", ":")) + "\n", ""
    if mode in {"present", "listener_failure", "guest", "other", "empty", "ip_failure"}:
        if mode == "listener_failure":
            return 1, "", "Traceback: synthetic listener query failure"
        if mode == "ip_failure":
            return 1, "", "Traceback: synthetic IP query failure"
        if mode in {"guest", "other", "empty"}:
            # the collector's own identity assertion refuses to run anywhere
            # but the fixed receiver host (or produced no output at all)
            return 1, "", "AssertionError: collector is not running on the fixed receiver identity"
        payload = {
            "schema_version": 1, "observer_ipv4": "192.168.204.1",
            "endpoint": "http://192.168.204.1:28786/",
            "interface_ipv4": ["192.168.204.1"], "rows": [],
        }
        if mode == "present":
            payload["rows"] = ["0.0.0.0:7012"]
        return 0, json.dumps(payload, separators=(",", ":")) + "\n", ""
    raise ValueError(f"unknown receiver mode: {mode}")


def ready_command(identity: str, *, mode: str = "absent", wrong_observer: bool = False, wrong_receiver: bool = False) -> dict[str, object]:
    code, stdout, stderr = receiver_document(mode)
    argv = list(evidence.RECEIVER_STOPPED_ARGV)
    observer = dict(evidence.RECEIVER_OBSERVER)
    if wrong_observer:
        observer["ipv4"] = "192.168.204.99"
    if wrong_receiver:
        observer["endpoint"] = "http://192.168.204.1:9999/"
    return {
        "schema_version": 1, "kind": "p05-ready-command-v1", "observation": "receiver_stopped",
        "workflow_id": evidence.WORKFLOW_ID, "run_id": identity, "restore_attempt_id": identity,
        "host": observer,
        "request": {"argv": argv, "command_line": " ".join(argv)},
        "started_at": "2026-09-20T01:00:03Z", "ended_at": "2026-09-20T01:00:04Z",
        "exit_status": {"code": code}, "response": response(stdout, stderr),
    }


_TRANSFER_SERVER: ThreadingHTTPServer | None = None
_TRANSFER_MODE = "ok"
_TRANSFER_RECORDS: list[dict[str, object]] = []


class TransferHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        _TRANSFER_RECORDS.append({
            "path": self.path, "length": length, "body": body,
            "sha256": sha(body), "header_sha256": self.headers.get("X-Evidence-SHA256"),
        })
        if _TRANSFER_MODE == "drop_response":
            self.connection.close()
            return
        status = 500 if _TRANSFER_MODE == "non200" else 200
        receipt_hash = "f" * 64 if _TRANSFER_MODE == "wrong_receipt" else sha(body)
        payload = json.dumps({"size": len(body), "sha256": receipt_hash}, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


def transfer_wrapper(command: str, endpoint: str) -> str:
    production_create = "$request=[Net.HttpWebRequest]::Create($uri);"
    if command.count(production_create) != 1:
        raise AssertionError("production request constructor changed")
    mapped_create = (
        "$request=[Net.HttpWebRequest]::Create('"
        + endpoint.replace("'", "''").rstrip("/")
        + "/'+$uri.Split('/')[-1]);"
    )
    return command.replace(production_create, mapped_create, 1)


def transfer_seam(root: Path, identity: str, source: str, size: int, digest: str, *, mode: str = "ok") -> subprocess.CompletedProcess[str]:
    global _TRANSFER_MODE
    if _TRANSFER_SERVER is None:
        raise RuntimeError("owned loopback receiver is not running")
    _TRANSFER_MODE = mode
    command = evidence.transfer_command(identity, source, size, digest)
    port = _TRANSFER_SERVER.server_address[1]
    endpoint = "http://127.0.0.1:1" if mode == "send_failure" else f"http://127.0.0.1:{port}"
    wrapper = transfer_wrapper(command, endpoint)
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", wrapper], cwd=root,
        capture_output=True, text=True, encoding="utf-8", errors="strict", check=False, env=test_environment(),
    )


def manifest(root: Path, name: str, kind: str, exclusions: set[str]) -> None:
    members = []
    for path in sorted((x for x in root.rglob("*") if x.is_file() and not x.is_symlink()), key=lambda x: x.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        if relative in exclusions:
            continue
        data = path.read_bytes()
        members.append({"path": relative, "size": len(data), "sha256": sha(data), "origin": f"fixture/{relative}"})
    write_json(root / name, {"schema_version": 1, "kind": kind, "workflow_id": evidence.WORKFLOW_ID, "created_at": "2026-09-20T01:00:05Z", "members": members})


def clone_tree(source: Path, target: Path) -> None:
    def link_or_copy(src: str, dst: str) -> str:
        try:
            os.link(src, dst)
            return dst
        except OSError:
            return shutil.copy2(src, dst)
    shutil.copytree(source, target, copy_function=link_or_copy)


class Fixture:
    def __init__(self, base: Path, source_data: dict[str, bytes] | None = None):
        self.base = base
        self.prep_id = str(uuid.uuid4())
        self.migration_id = str(uuid.uuid4())
        self.preservation_id = str(uuid.uuid4())
        source_data = source_data or {path: f"synthetic source for {path}\n".encode() for path in evidence.PC020_REQUIRED_SOURCE_PATHS}
        implementation_data = {"tests/p05_pc020_evidence.py": b"synthetic reviewed implementation\n"}
        self.policy = evidence.FrozenSourcePolicy(
            source_inputs={path: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for path, data in source_data.items()},
            implementation_sources={path: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for path, data in implementation_data.items()},
            synthetic_fixture=True,
        )
        self.source_data = source_data
        self.implementation_data = implementation_data

    def add_sources(self, root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        def rows(values: dict[str, bytes]) -> list[dict[str, object]]:
            result = []
            for repo_path, data in sorted(values.items()):
                path = root / "source" / repo_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                result.append({"repo_path": repo_path, "blob": blob(data), "content": ref(root, f"source/{repo_path}")})
            return result
        return rows(self.source_data), rows(self.implementation_data)

    def preparation(self, flaw: str | None = None, *, actual_transfer: bool = False) -> Path:
        root = self.base / "pc020-preparation" / self.prep_id
        root.mkdir(parents=True)
        tree_stdout = f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n"
        if flaw == "wrong_tree":
            tree_stdout = f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_189}\n"
        vmsd = "\n".join([
            'snapshot.numSnapshots = "2"', 'snapshot.lastUID = "4"', 'snapshot.current = "4"',
            f'snapshot0.displayName = "{evidence.SNAPSHOT_187}"', 'snapshot0.uid = "3"', f'snapshot0.filename = "{evidence.MARKER_187 if flaw != "wrong_marker" else "wrong.vmsn"}"',
            f'snapshot1.displayName = "{evidence.SNAPSHOT_188}"', 'snapshot1.uid = "4"',
            f'snapshot1.parent = "{2 if flaw == "wrong_parent" else 3}"',
            'snapshot1.filename = "Win10MalBox-Velo-Snapshot4.vmsn"', "",
        ])
        tree_argv = ["/usr/bin/vmrun", "-T", "ws", "listSnapshots", evidence.VMX, "showTree"]
        meta_argv = ["/usr/bin/cat", str(Path(evidence.VMX).with_suffix(".vmsd")).replace("\\", "/")]
        write_json(root / "raw/tree.json", snapshot_command(self.prep_id, "snapshot_tree", tree_stdout, tree_argv))
        write_json(root / "raw/metadata.json", snapshot_command(self.prep_id, "snapshot_metadata", vmsd, meta_argv))
        vmx_bytes = (
            '.encoding = "UTF-8"\n'
            f'ethernet0.generatedAddress = "{"00:0c:29:00:00:00" if flaw == "wrong_vm" else evidence.MAC}"\n'
            'displayName = "Win10MalBox-Velo"\n'
        ).encode()
        vmx_sha = sha(vmx_bytes)
        write_json(root / "raw/vm.json", snapshot_command(self.prep_id, "vm_identity", vmx_bytes.decode(), ["/usr/bin/cat", evidence.VMX]))
        write_json(root / "vm-identity.json", {
            "schema_version": 1, "kind": "pc020-vm-identity-v1", "workflow_id": evidence.WORKFLOW_ID,
            "vmx": evidence.VMX, "vmx_sha256": vmx_sha, "mac_address": evidence.MAC,
            "current_snapshot_uid": 4, "observed_at": "2026-09-20T01:00:02Z", "observation": ref(root, "raw/vm.json"),
        })
        archive = b"synthetic nonsecret preserved bytes"
        (root / "preserved").mkdir()
        (root / "preserved/evidence.zip").write_bytes(archive)
        receipt = {
            "identity": self.preservation_id,
            "command": evidence.transfer_command(self.preservation_id, "preserved/evidence.zip", len(archive), sha(archive)),
            "received": {"size": len(archive), "sha256": sha(archive), "guest_sha256": sha(archive)},
            "control_exit": 0, "control_response_sha256": "0" * 64,
            "scope": ["synthetic/nonsecret"], "originals_modified": False,
        }
        if actual_transfer:
            completed_transfer = transfer_seam(root, self.preservation_id, "preserved/evidence.zip", len(archive), sha(archive))
            if completed_transfer.returncode != 0:
                raise RuntimeError(f"fixture transfer failed: {completed_transfer.stderr}")
            control_text = completed_transfer.stdout
        else:
            control_text = f"Response: PRESERVATION_HTTP=200\r\nGUEST_SHA256={sha(archive).upper()}\r\nStatus Code: 0"
        if flaw == "http_2000":
            control_text = control_text.replace("HTTP=200", "HTTP=2000")
        elif flaw == "status_01":
            control_text = control_text.replace("Status Code: 0", "Status Code: 01")
        elif flaw == "duplicate_control_status":
            control_text += "\r\nStatus Code: 1"
        elif flaw == "wrong_control_result_hash":
            control_text = control_text.replace(sha(archive).upper(), "F" * 64)
        control = {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": control_text}], "structuredContent": {"result": control_text}, "isError": False}}
        write_json(root / "preservation/control-response.json", control)
        receipt["control_response_sha256"] = sha((root / "preservation/control-response.json").read_bytes())
        if flaw == "comment_spoofed_request":
            receipt["command"] = f"# {evidence.RECEIVER_URL_PREFIX}{self.preservation_id} Method='POST' X-Evidence-SHA256\n$request=[System.Net.HttpWebRequest]::Create('http://192.168.204.1:9999/wrong')"
        write_json(root / "preservation/transfer-receipt.json", receipt)
        receiver_mode = {
            "receiver_summary": "present",
            "receiver_empty_stdout": "empty",
            "receiver_query_failure": "ip_failure",
        }.get(flaw, "absent")
        write_json(
            root / "preservation/receiver-stopped.json",
            ready_command(
                self.preservation_id,
                mode=receiver_mode,
                wrong_observer=flaw == "wrong_receiver_observer",
                wrong_receiver=flaw == "wrong_receiver_port",
            ),
        )
        write_json(root / "preservation/manifest.json", {
            "schema_version": 1, "kind": "pc020-pre-recovery-preservation-v1", "workflow_id": evidence.WORKFLOW_ID,
            "preservation_id": self.preservation_id, "scope": evidence.PREP_SCOPE, "created_at": "2026-09-20T01:00:05Z",
            "transfer_receipt": ref(root, "preservation/transfer-receipt.json"), "receiver_stopped": ref(root, "preservation/receiver-stopped.json"),
            "included": [{"path": "preserved/evidence.zip", "size": len(archive), "sha256": sha(archive)}],
            "excluded": [{"category": "secrets", "reason": "not copied or fingerprinted"}],
        })
        sources, implementation = self.add_sources(root)
        decision_name = f"source/{evidence.DECISION_16}"
        write_json(root / "retired.json", {
            "schema_version": 1, "kind": "pc020-retired187-requalification-v1", "workflow_id": evidence.WORKFLOW_ID,
            "predecessor_sha256": evidence.PREDECESSOR_SHA256, "snapshot_name": evidence.SNAPSHOT_187,
            "previous_status": evidence.MANUAL_ONLY, "new_scope": "P05_PREPARATION_ONLY",
            "reason": "explicit one-generation preparation-only exception", "decision_source": ref(root, decision_name),
            "issued_at": "2026-09-20T01:00:06Z",
        })
        if flaw == "wrong_decision_copy":
            other = next(row for row in sources if row["repo_path"] != evidence.DECISION_16)
            retired = json.loads((root / "retired.json").read_bytes())
            retired["decision_source"] = other["content"]
            write_json(root / "retired.json", retired)
        if flaw == "missing_source":
            sources.pop()
        if flaw == "nested_member_removed":
            (root / "nested").mkdir()
            (root / "nested/manifest-only.txt").write_bytes(b"governed nested member\n")
        manifest(root, "package-manifest.json", "pc020-preparation-manifest-v1", {"package-manifest.json", "admission.json"})
        admission = {
            "schema_version": 1, "kind": "pc020-snapshot187-preparation-v1", "workflow_id": evidence.WORKFLOW_ID,
            "admission_id": self.prep_id, "vmx": evidence.VMX, "snapshot_name": evidence.SNAPSHOT_187,
            "checkpoint_marker": evidence.MARKER_187, "snapshot_tree": ref(root, "raw/tree.json"),
            "snapshot_metadata": ref(root, "raw/metadata.json"), "vm_identity": ref(root, "vm-identity.json"),
            "preservation_manifest": ref(root, "preservation/manifest.json"), "retired_requalification": ref(root, "retired.json"),
            "source_inputs": sources, "implementation_sources": implementation,
            "package_manifest": ref(root, "package-manifest.json"), "qualified_at": "2026-09-20T01:00:07Z",
        }
        if flaw == "dotdot":
            admission["snapshot_tree"] = {"path": "../escape.json", "size": 1, "sha256": "0" * 64}
        if flaw == "bool_size":
            admission["snapshot_tree"]["size"] = True
        write_json(root / "admission.json", admission)
        if flaw == "duplicate_json":
            raw = (root / "admission.json").read_text("utf-8")
            (root / "admission.json").write_text(raw.replace('{"admission_id":', '{"schema_version":1,"admission_id":', 1), encoding="utf-8")
        if flaw == "missing_nested_member":
            (root / decision_name).unlink()
        if flaw == "nested_member_removed":
            (root / "nested/manifest-only.txt").unlink()
        if flaw == "special_path":
            (root / "raw/tree.json").unlink()
            (root / "raw/tree.json").mkdir()
        if flaw == "included_bytes_replaced":
            (root / "preserved/evidence.zip").write_bytes(b"replacement with outer hashes synchronized")
            manifest(root, "package-manifest.json", "pc020-preparation-manifest-v1", {"package-manifest.json", "admission.json"})
            admission = json.loads((root / "admission.json").read_bytes())
            admission["package_manifest"] = ref(root, "package-manifest.json")
            write_json(root / "admission.json", admission)
        if flaw == "fake_receipt_digest":
            receipt_path = root / "preservation/transfer-receipt.json"
            changed = json.loads(receipt_path.read_bytes())
            changed["control_response_sha256"] = "f" * 64
            write_json(receipt_path, changed)
            preservation_path = root / "preservation/manifest.json"
            preservation = json.loads(preservation_path.read_bytes())
            preservation["transfer_receipt"] = ref(root, "preservation/transfer-receipt.json")
            write_json(preservation_path, preservation)
            admission = json.loads((root / "admission.json").read_bytes())
            admission["preservation_manifest"] = ref(root, "preservation/manifest.json")
            manifest(root, "package-manifest.json", "pc020-preparation-manifest-v1", {"package-manifest.json", "admission.json"})
            admission["package_manifest"] = ref(root, "package-manifest.json")
            write_json(root / "admission.json", admission)
        return root / "admission.json"

    def migration(self, prep: Path, predecessor: bytes, baseline_dir: Path, activation_dir: Path, flaw: str | None = None) -> Path:
        root = self.base / "pc020-migration" / self.migration_id
        root.mkdir(parents=True)
        baseline_copy = root / "historical/baseline-adoption" / baseline_dir.name
        activation_copy = root / "historical/activation-188" / activation_dir.name
        clone_tree(baseline_dir, baseline_copy)
        clone_tree(activation_dir, activation_copy)
        pred = bytearray(predecessor)
        if flaw == "wrong_predecessor":
            pred[-2] ^= 1
        (root / "historical/canonical.json").write_bytes(bytes(pred))
        if flaw == "history_root_changed":
            target = activation_copy / "activation-evidence.json"
            data = target.read_bytes()
            target.unlink()
            target.write_bytes(data + b" ")
        if flaw == "deep_historical_member_removed":
            (activation_copy / "cycle-1/ready/raw/firewall.json").unlink()
        manifest(root / "historical", "historical-manifest.json", "pc020-historical-manifest-v1", {"historical-manifest.json"})
        shutil.copytree(prep.parent, root / "preparation")
        if flaw == "prep_copy_diff":
            target = root / "preparation/raw/tree.json"
            target.write_bytes(target.read_bytes() + b" ")
            manifest(root / "preparation", "package-manifest.json", "pc020-preparation-manifest-v1", {"package-manifest.json", "admission.json"})
        manifest(root / "preparation", "preparation-copy-manifest.json", "pc020-preparation-copy-manifest-v1", {"preparation-copy-manifest.json"})
        sources, implementation = self.add_sources(root)
        manifest(root, "package-manifest.json", "pc020-migration-manifest-v1", {"package-manifest.json", "migration.json"})
        migration = {
            "schema_version": 1, "kind": "pc020-requalification-migration-v1", "workflow_id": evidence.WORKFLOW_ID,
            "migration_id": self.migration_id, "predecessor_sha256": evidence.PREDECESSOR_SHA256,
            "predecessor_canonical": ref(root, "historical/canonical.json"),
            "predecessor_baseline": ref(root, f"historical/baseline-adoption/{baseline_dir.name}/adoption.json"),
            "predecessor_activation": ref(root, f"historical/activation-188/{activation_dir.name}/activation-evidence.json"),
            "historical_manifest": ref(root, "historical/historical-manifest.json"),
            "preparation_admission": ref(root, "preparation/admission.json"),
            "preparation_manifest": ref(root, "preparation/preparation-copy-manifest.json"),
            "source_inputs": sources, "implementation_sources": implementation,
            "package_manifest": ref(root, "package-manifest.json"), "migrated_at": "2026-09-20T01:00:09Z",
        }
        if flaw == "bad_provenance":
            migration["predecessor_activation"] = migration["predecessor_baseline"]
        if flaw == "substring_history_path":
            fake = root / "historical/prefix-activation-188" / activation_dir.name / "activation-evidence.json"
            fake.parent.mkdir(parents=True)
            fake.write_bytes((activation_copy / "activation-evidence.json").read_bytes())
            migration["predecessor_activation"] = ref(root, fake.relative_to(root).as_posix())
        if flaw == "future_ref":
            future = root / "future/epoch7.json"
            future.parent.mkdir()
            future.write_bytes((root / "preparation/admission.json").read_bytes())
            migration["preparation_admission"] = ref(root, "future/epoch7.json")
        write_json(root / "migration.json", migration)
        if flaw == "self_ref":
            migration["predecessor_canonical"] = ref(root, "migration.json")
            write_json(root / "migration.json", migration)
        return root / "migration.json"


class Pc020EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global _TRANSFER_SERVER
        required = {
            "predecessor": os.environ.get("PC020_PREDECESSOR_FIXTURE"),
            "baseline": os.environ.get("PC020_BASELINE_DIR_FIXTURE"),
            "activation": os.environ.get("PC020_ACTIVATION_DIR_FIXTURE"),
            "real_sources": os.environ.get("PC020_REAL_SOURCE_ROOT"),
        }
        missing = [name for name, value in required.items() if not value or not Path(value).exists()]
        if missing:
            raise RuntimeError(f"required historical byte fixtures missing: {missing}")
        cls.predecessor = Path(required["predecessor"]).read_bytes()
        cls.baseline_dir = Path(required["baseline"])
        cls.activation_dir = Path(required["activation"])
        cls.baseline = (cls.baseline_dir / "adoption.json").read_bytes()
        cls.activation = (cls.activation_dir / "activation-evidence.json").read_bytes()
        source_root = Path(required["real_sources"])
        cls.real_source_data = {path: (source_root / path).read_bytes() for path in evidence.PC020_REQUIRED_SOURCE_PATHS}
        if sha(cls.predecessor) != evidence.PREDECESSOR_SHA256:
            raise RuntimeError("predecessor fixture does not have the reviewed bytes")
        _TRANSFER_SERVER = ThreadingHTTPServer(("127.0.0.1", 0), TransferHandler)
        cls.transfer_thread = threading.Thread(target=_TRANSFER_SERVER.serve_forever, daemon=True)
        cls.transfer_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        global _TRANSFER_SERVER
        if _TRANSFER_SERVER is not None:
            _TRANSFER_SERVER.shutdown()
            _TRANSFER_SERVER.server_close()
            cls.transfer_thread.join(timeout=5)
            _TRANSFER_SERVER = None

    def new(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        return temporary, Fixture(Path(temporary.name))

    def test_complete_preparation_and_migration_graphs_are_accepted_read_only(self):
        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation(actual_transfer=True)
            migration = fixture.migration(prep, self.predecessor, self.baseline_dir, self.activation_dir)
            before = {p.relative_to(Path(temporary.name)).as_posix(): sha(p.read_bytes()) for p in Path(temporary.name).rglob("*") if p.is_file()}
            prep_result = evidence.verify_preparation(prep.resolve(), policy=fixture.policy)
            migration_result = evidence.verify_migration(migration.resolve(), original_preparation=prep.resolve(), policy=fixture.policy)
            after = {p.relative_to(Path(temporary.name)).as_posix(): sha(p.read_bytes()) for p in Path(temporary.name).rglob("*") if p.is_file()}
            self.assertEqual(before, after)
            self.assertEqual(prep_result["kind"], "preparation_admission")
            self.assertEqual(migration_result["kind"], "migration")
            self.assertFalse(prep_result["operational_ready"])
            self.assertFalse(migration_result["operational_ready"])
            old_activation = json.loads(self.activation)
            self.assertNotIn("issued_at", old_activation)  # known old failure preserved, not upgraded

    def test_preparation_targeted_negative_matrix(self):
        cases = {
            "wrong_tree": "snapshot tree", "wrong_marker": "metadata", "wrong_parent": "parent relation", "wrong_vm": "raw VMX bytes",
            "receiver_summary": "receiver_stopped", "missing_source": "exact frozen source set",
            "dotdot": "escapes its bundle", "bool_size": "identity is invalid",
            "duplicate_json": "duplicate JSON key", "missing_nested_member": "unavailable",
            "nested_member_removed": "exact governed tree", "special_path": "not a regular file",
            "wrong_receiver_port": "fixed receiver host", "wrong_receiver_observer": "fixed receiver host",
            "receiver_empty_stdout": "command failed", "receiver_query_failure": "command failed",
            "wrong_decision_copy": "trusted decision 16",
            "included_bytes_replaced": "byte identity differs", "fake_receipt_digest": "control response bytes differ",
            "http_2000": "exact received bytes", "status_01": "exact received bytes",
            "duplicate_control_status": "exact received bytes", "wrong_control_result_hash": "exact received bytes",
            "comment_spoofed_request": "fixed receiver endpoint",
        }
        for flaw, message in cases.items():
            with self.subTest(flaw=flaw):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation(flaw)
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

    def test_receiver_observation_seams_execute_and_feed_the_real_parser(self):
        preservation_id = str(uuid.uuid4())
        cases = {
            "present": "listener is absent",
            "empty": "command failed",
            "ip_failure": "command failed",
            "listener_failure": "command failed",
            "guest": "command failed",
            "other": "command failed",
        }
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        with temporary:
            root = Path(temporary.name)
            absent_code, absent_stdout, absent_stderr = receiver_document("absent")
            print("PC020_OBSERVER_ABSENT_RAW=" + json.dumps({"returncode": absent_code, "stdout": absent_stdout, "stderr": absent_stderr}, sort_keys=True))
            self.assertEqual(absent_code, 0)
            observed = json.loads(absent_stdout)
            self.assertEqual(
                (observed["schema_version"], observed["observer_ipv4"], observed["endpoint"], observed["rows"]),
                (1, "192.168.204.1", evidence.RECEIVER_URL_PREFIX, []),
            )
            self.assertIn("192.168.204.1", observed["interface_ipv4"])
            absent_path = root / "absent.json"
            write_json(absent_path, ready_command(preservation_id, mode="absent"))
            evidence._ready_command(absent_path, preservation_id=preservation_id)
            for mode, message in cases.items():
                with self.subTest(mode=mode):
                    path = root / f"{mode}.json"
                    write_json(path, ready_command(preservation_id, mode=mode))
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence._ready_command(path, preservation_id=preservation_id)
            print("PC020_OBSERVER_SEAMS=" + json.dumps({
                mode: {"document_level": mode != "absent" or os.name != "posix",
                       "production_command": evidence.RECEIVER_STOPPED_SCRIPT,
                       "returncode": receiver_document(mode)[0],
                       "stdout": receiver_document(mode)[1],
                       "stderr": receiver_document(mode)[2]}
                for mode in ("absent", "present", "empty", "ip_failure", "listener_failure", "guest", "other")
            }, sort_keys=True))

    def test_actual_sender_writes_frozen_bytes_and_only_reports_completed_receipt(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        with temporary:
            root = Path(temporary.name)
            source = "preserved/evidence.zip"
            path = root / source
            path.parent.mkdir()
            payload = b"pc020 isolated full-body transfer"
            path.write_bytes(payload)
            identity = str(uuid.uuid4())
            before = len(_TRANSFER_RECORDS)
            completed = transfer_seam(root, identity, source, len(payload), sha(payload))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, f"Response: PRESERVATION_HTTP=200\nGUEST_SHA256={sha(payload).upper()}\nStatus Code: 0")
            record = _TRANSFER_RECORDS[before]
            self.assertEqual(record["body"], payload)
            self.assertEqual(record["length"], len(payload))
            self.assertEqual(record["sha256"], sha(payload))
            self.assertEqual(record["header_sha256"], sha(payload))
            self.assertEqual(record["path"], f"/{identity}")

            cases = {
                "truncated": (len(payload) + 1, sha(payload), "ok"),
                "hash_mismatch": (len(payload), "f" * 64, "ok"),
                "non200": (len(payload), sha(payload), "non200"),
                "wrong_receipt": (len(payload), sha(payload), "wrong_receipt"),
                "send_failure": (len(payload), sha(payload), "send_failure"),
                "response_failure": (len(payload), sha(payload), "drop_response"),
            }
            for label, (expected_size, expected_hash, mode) in cases.items():
                with self.subTest(failure=label):
                    failed = transfer_seam(root, identity, source, expected_size, expected_hash, mode=mode)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertNotIn("PRESERVATION_HTTP=200", failed.stdout)

            empty = root / "preserved/empty.zip"
            empty.write_bytes(b"")
            empty_result = transfer_seam(root, identity, "preserved/empty.zip", 1, sha(b""))
            self.assertNotEqual(empty_result.returncode, 0)
            self.assertNotIn("PRESERVATION_HTTP=200", empty_result.stdout)
            print("PC020_TRANSFER_SEAM=" + json.dumps({
                "synthetic": True,
                "production_command": evidence.transfer_command(identity, source, len(payload), sha(payload)),
                "executed_test_wrapper": transfer_wrapper(
                    evidence.transfer_command(identity, source, len(payload), sha(payload)),
                    f"http://127.0.0.1:{_TRANSFER_SERVER.server_address[1]}",
                ),
                "wrapper_difference": "only HttpWebRequest.Create network address maps fixed receiver to owned loopback",
                "success": {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr},
                "received": {key: value for key, value in record.items() if key != "body"},
                "received_body_hex": payload.hex(),
                "negative_labels": sorted(cases) + ["no_body"],
                "seam": "owned Windows loopback dynamic-port external HTTP I/O mapping",
            }, sort_keys=True))

    def test_transfer_builder_quotes_valid_path_and_rejects_invalid_typed_inputs(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        with temporary:
            root = Path(temporary.name)
            source = "preserved/空 格';Set-Content injected.txt pwned;'.zip"
            path = root / source
            path.parent.mkdir()
            payload = b"quoted logical path bytes"
            path.write_bytes(payload)
            sentinel = root / "sentinel.txt"
            sentinel.write_bytes(b"unchanged")
            identity = str(uuid.uuid4())
            command = evidence.transfer_command(identity, source, len(payload), sha(payload))
            self.assertIn("$source='preserved/空 格'';Set-Content injected.txt pwned;''.zip'", command)
            before = len(_TRANSFER_RECORDS)
            completed = transfer_seam(root, identity, source, len(payload), sha(payload))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(_TRANSFER_RECORDS[before]["body"], payload)
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            self.assertFalse((root / "injected.txt").exists())

            invalid = (
                ("not-a-uuid", source, len(payload), sha(payload), "canonical UUID"),
                (identity, "../escape.zip", len(payload), sha(payload), "escapes"),
                (identity, source, True, sha(payload), "positive integer"),
                (identity, source, 0, sha(payload), "positive integer"),
                (identity, source, len(payload), sha(payload).upper(), "lowercase hexadecimal"),
            )
            for bad_id, bad_source, bad_size, bad_hash, message in invalid:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.transfer_command(bad_id, bad_source, bad_size, bad_hash)
            print("PC020_QUOTED_SOURCE=" + json.dumps({
                "synthetic": True, "source": source, "production_command": command,
                "returncode": completed.returncode, "stdout": completed.stdout,
                "sentinel_unchanged": True, "unexpected_path_absent": True,
            }, ensure_ascii=False, sort_keys=True))

    def test_synthetic_disclosure_never_changes_validator_acceptance(self):
        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation(actual_transfer=True)
            policies = [
                evidence.FrozenSourcePolicy(fixture.policy.source_inputs, fixture.policy.implementation_sources, value)
                for value in (False, True)
            ]
            for policy in policies:
                self.assertEqual(evidence.verify_preparation(prep.resolve(), policy=policy)["kind"], "preparation_admission")
            stopped = prep.parent / "preservation/receiver-stopped.json"
            invalid = json.loads(stopped.read_bytes())
            invalid["host"]["ipv4"] = "192.168.204.99"
            write_json(stopped, invalid)
            preservation = prep.parent / "preservation/manifest.json"
            document = json.loads(preservation.read_bytes())
            document["receiver_stopped"] = ref(prep.parent, "preservation/receiver-stopped.json")
            write_json(preservation, document)
            admission = json.loads(prep.read_bytes())
            admission["preservation_manifest"] = ref(prep.parent, "preservation/manifest.json")
            manifest(prep.parent, "package-manifest.json", "pc020-preparation-manifest-v1", {"package-manifest.json", "admission.json"})
            admission["package_manifest"] = ref(prep.parent, "package-manifest.json")
            write_json(prep, admission)
            for policy in policies:
                with self.assertRaisesRegex(evidence.Pc020EvidenceError, "fixed receiver host"):
                    evidence.verify_preparation(prep.resolve(), policy=policy)

    def test_ref_spelling_identity_and_conflict_boundaries(self):
        cases = {
            "absolute": ("/raw/tree.json", "escapes its bundle"),
            "drive": ("C:/raw/tree.json", "escapes its bundle"),
            "backslash": ("raw\\tree.json", "POSIX relative"),
            "dot": ("raw/./tree.json", "escapes its bundle"),
            "empty_segment": ("raw//tree.json", "escapes its bundle"),
            "empty": ("", "POSIX relative"),
        }
        for label, (path_value, message) in cases.items():
            with self.subTest(case=label):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation()
                    admission = json.loads(prep.read_bytes())
                    admission["snapshot_tree"]["path"] = path_value
                    write_json(prep, admission)
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

        for label in ("hash_drift", "conflicting_repeat"):
            with self.subTest(case=label):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation()
                    admission = json.loads(prep.read_bytes())
                    if label == "hash_drift":
                        admission["snapshot_tree"]["sha256"] = "0" * 64
                        message = "byte identity differs"
                    else:
                        admission["snapshot_metadata"] = dict(admission["snapshot_tree"])
                        admission["snapshot_metadata"]["size"] += 1
                        message = "conflicting identity"
                    write_json(prep, admission)
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

    def test_source_exact_set_duplicate_and_blob_boundaries(self):
        for flaw, message in (("extra", "outside the frozen policy"), ("duplicate", "duplicated"), ("blob", "trusted frozen identity")):
            with self.subTest(flaw=flaw):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation()
                    admission = json.loads(prep.read_bytes())
                    if flaw == "extra":
                        row = dict(admission["source_inputs"][0])
                        row["repo_path"] = "PLAN/not-approved.md"
                        admission["source_inputs"].append(row)
                    elif flaw == "duplicate":
                        admission["source_inputs"].append(dict(admission["source_inputs"][0]))
                    else:
                        admission["source_inputs"][0]["blob"] = "0" * 40
                    write_json(prep, admission)
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

    def test_wrong_policy_cannot_redefine_normative_source_set(self):
        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation()
            policy = evidence.FrozenSourcePolicy({}, fixture.policy.implementation_sources, True)
            with self.assertRaisesRegex(evidence.Pc020EvidenceError, "fixed PC020 sources"):
                evidence.verify_preparation(prep.resolve(), policy=policy)

    def test_real_frozen_source_copy_is_accepted(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        with temporary:
            fixture = Fixture(Path(temporary.name), self.real_source_data)
            prep = fixture.preparation(actual_transfer=True)
            result = evidence.verify_preparation(prep.resolve(), policy=fixture.policy)
            self.assertEqual(result["kind"], "preparation_admission")
            self.assertFalse(result["operational_ready"])

    def test_exact_root_identity_time_uuid_and_nonfinite_json_boundaries(self):
        cases = {
            "extra_key": "identity differs",
            "bool_schema": "identity differs",
            "wrong_kind": "identity differs",
            "wrong_workflow": "identity differs",
            "non_utc": "UTC RFC3339 Z",
            "bad_preservation_uuid": "canonical UUID",
            "nan": "non-finite JSON number",
        }
        for flaw, message in cases.items():
            with self.subTest(flaw=flaw):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation()
                    admission = json.loads(prep.read_bytes())
                    if flaw == "extra_key":
                        admission["unexpected"] = None
                    elif flaw == "bool_schema":
                        admission["schema_version"] = True
                    elif flaw == "wrong_kind":
                        admission["kind"] = "pc020-future-ready-v1"
                    elif flaw == "wrong_workflow":
                        admission["workflow_id"] = "wf-not-reviewed"
                    elif flaw == "non_utc":
                        admission["qualified_at"] = "2026-09-20T09:00:00+08:00"
                    elif flaw == "bad_preservation_uuid":
                        manifest_path = prep.parent / admission["preservation_manifest"]["path"]
                        preservation = json.loads(manifest_path.read_bytes())
                        preservation["preservation_id"] = "not-a-uuid"
                        write_json(manifest_path, preservation)
                        admission["preservation_manifest"] = ref(prep.parent, admission["preservation_manifest"]["path"])
                    write_json(prep, admission)
                    if flaw == "nan":
                        raw = prep.read_text("utf-8")
                        prep.write_text(raw.replace('"schema_version":1', '"schema_version":NaN', 1), encoding="utf-8")
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation()
            invalid_root = prep.parent.with_name("not-a-uuid")
            prep.parent.rename(invalid_root)
            with self.assertRaisesRegex(evidence.Pc020EvidenceError, "not a UUID"):
                evidence.verify_preparation((invalid_root / "admission.json").resolve(), policy=fixture.policy)

    def test_migration_targeted_negative_matrix(self):
        cases = {
            "wrong_predecessor": "predecessor canonical bytes",
            "bad_provenance": "historical root bytes",
            "history_root_changed": "historical root bytes",
            "deep_historical_member_removed": "unavailable",
            "prep_copy_diff": "copied preparation bundles differ",
            "future_ref": "copied preparation admission path differs",
            "self_ref": "byte identity differs",
            "substring_history_path": "historical root paths differ",
        }
        for flaw, message in cases.items():
            with self.subTest(flaw=flaw):
                temporary, fixture = self.new()
                with temporary:
                    prep = fixture.preparation()
                    migration = fixture.migration(prep, self.predecessor, self.baseline_dir, self.activation_dir, flaw)
                    with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                        evidence.verify_migration(migration.resolve(), original_preparation=prep.resolve(), policy=fixture.policy)

    def test_schema6_shapes_do_not_claim_activation_validation(self):
        migration_ref = {"kind": "pc020-requalification-migration-v1", "source": "pc020-migration", "evidence_path": "pc020-migration/00000000-0000-0000-0000-000000000001/migration.json", "evidence_sha256": "1" * 64, "predecessor_sha256": evidence.PREDECESSOR_SHA256, "migrated_at": "2026-09-20T01:00:09Z"}
        prep_ref = {"kind": "pc020-snapshot187-preparation-v1", "source": "pc020-preparation-admission", "evidence_path": "pc020-preparation/00000000-0000-0000-0000-000000000002/admission.json", "evidence_sha256": "2" * 64, "qualified_at": "2026-09-20T01:00:07Z"}
        retired7 = ["Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线", "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", evidence.SNAPSHOT_188]
        base = {"schema_version": 6, "workflow_id": evidence.WORKFLOW_ID, "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": {"name": evidence.SNAPSHOT_187, "checkpoint_marker": evidence.MARKER_187, "purpose": "preparation only"}, "automatic_restore_allowlist": [evidence.SNAPSHOT_187], "retired_snapshots": [{"name": x, "status": evidence.MANUAL_ONLY} for x in retired7], "migration_evidence": migration_ref, "preparation_evidence": prep_ref, "activation_evidence": None}
        result7 = evidence.verify_schema6_shape(evidence.canonical_json(base), expected_epoch=7)
        state8 = json.loads(evidence.canonical_json(base))
        state8.update({"epoch": 8, "phase": "NETWORK_ACTIVE", "active_snapshot": {"name": evidence.SNAPSHOT_189, "checkpoint_marker": "Win10MalBox-Velo-Snapshot5.vmsn", "purpose": "active"}, "automatic_restore_allowlist": [evidence.SNAPSHOT_189], "retired_snapshots": base["retired_snapshots"] + [{"name": evidence.SNAPSHOT_187, "status": evidence.MANUAL_ONLY}], "activation_evidence": {"source": "snapshot189-activation", "evidence_path": "activation-189/00000000-0000-0000-0000-000000000003/activation-evidence.json", "evidence_sha256": "3" * 64, "activated_at": "2026-09-20T02:00:00Z"}})
        result8 = evidence.verify_schema6_shape(evidence.canonical_json(state8), expected_epoch=8)
        self.assertFalse(result7["activation_graph_validated"])
        self.assertFalse(result8["operational_ready"])
        state8["automatic_restore_allowlist"] = [evidence.SNAPSHOT_188]
        with self.assertRaisesRegex(evidence.Pc020EvidenceError, "collections"):
            evidence.verify_schema6_shape(evidence.canonical_json(state8), expected_epoch=8)

    def test_schema6_fixed_namespaces_uuid_and_strict_rfc3339(self):
        migration_ref = {"kind": "pc020-requalification-migration-v1", "source": "pc020-migration", "evidence_path": "pc020-migration/00000000-0000-0000-0000-000000000001/migration.json", "evidence_sha256": "1" * 64, "predecessor_sha256": evidence.PREDECESSOR_SHA256, "migrated_at": "2026-09-20T01:00:09.123Z"}
        prep_ref = {"kind": "pc020-snapshot187-preparation-v1", "source": "pc020-preparation-admission", "evidence_path": "pc020-preparation/00000000-0000-0000-0000-000000000002/admission.json", "evidence_sha256": "2" * 64, "qualified_at": "2026-09-20T01:00:07.1Z"}
        retired = ["Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线", "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线", evidence.SNAPSHOT_188]
        state = {"schema_version": 6, "workflow_id": evidence.WORKFLOW_ID, "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": {"name": evidence.SNAPSHOT_187, "checkpoint_marker": evidence.MARKER_187, "purpose": "preparation only"}, "automatic_restore_allowlist": [evidence.SNAPSHOT_187], "retired_snapshots": [{"name": x, "status": evidence.MANUAL_ONLY} for x in retired], "migration_evidence": migration_ref, "preparation_evidence": prep_ref, "activation_evidence": None}
        self.assertTrue(evidence.verify_schema6_shape(evidence.canonical_json(state), expected_epoch=7)["shape_valid"])
        path_cases = {
            "wrong_prefix": "other/00000000-0000-0000-0000-000000000001/migration.json",
            "wrong_filename": "pc020-migration/00000000-0000-0000-0000-000000000001/not-migration.json",
            "uppercase_uuid": "pc020-migration/AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA/migration.json",
            "extra_directory": "pc020-migration/x/00000000-0000-0000-0000-000000000001/migration.json",
        }
        for label, value in path_cases.items():
            with self.subTest(path=label):
                changed = json.loads(evidence.canonical_json(state))
                changed["migration_evidence"]["evidence_path"] = value
                with self.assertRaisesRegex(evidence.Pc020EvidenceError, "namespace|UUID"):
                    evidence.verify_schema6_shape(evidence.canonical_json(changed), expected_epoch=7)
        for value in ("2026-09-20 01:00:09Z", "20260920T010009Z", "2026-09-20T01:00:09+00:00", "2026-09-20T01:00Z", "2026-09-20T01:00:09,1Z"):
            with self.subTest(time=value):
                changed = json.loads(evidence.canonical_json(state))
                changed["migration_evidence"]["migrated_at"] = value
                with self.assertRaisesRegex(evidence.Pc020EvidenceError, "RFC3339"):
                    evidence.verify_schema6_shape(evidence.canonical_json(changed), expected_epoch=7)

    def test_link_or_reparse_is_rejected_when_windows_can_create_one(self):
        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation()
            target = prep.parent / "raw/tree.json"
            original = prep.parent / "raw/tree-original.json"
            target.rename(original)
            try:
                target.symlink_to(original.name)
            except OSError as exc:
                self.skipTest(f"Windows token cannot create a symlink/reparse fixture: {exc}")
            with self.assertRaisesRegex(evidence.Pc020EvidenceError, "link or reparse"):
                evidence.verify_preparation(prep.resolve(), policy=fixture.policy)

    def test_bundle_namespace_link_is_not_hidden_by_resolution(self):
        temporary, fixture = self.new()
        with temporary:
            prep = fixture.preparation()
            alias = Path(temporary.name) / "alias"
            alias.mkdir()
            namespace = alias / "pc020-preparation"
            try:
                namespace.symlink_to(prep.parent.parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Windows token cannot create a directory reparse fixture: {exc}")
            linked_entry = namespace / prep.parent.name / prep.name
            with self.assertRaisesRegex(evidence.Pc020EvidenceError, "bundle namespace is not a plain directory"):
                evidence.verify_preparation(linked_entry, policy=fixture.policy)


if __name__ == "__main__":
    unittest.main()

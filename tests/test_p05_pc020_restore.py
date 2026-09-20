"""Windows-only synthetic tests for the PC020 epoch7 restore verifier."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

from tests import p05_pc020_creation as creation
from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_restore as restore7
from tests import p06_evidence as legacy
from tests.test_p05_pc020_evidence import Fixture, blob, ref, sha


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence.canonical_json(value))


def response(stdout: str, stderr: str = "") -> dict[str, object]:
    return {
        "stdout": stdout, "stdout_size": len(stdout.encode()), "stdout_sha256": sha(stdout.encode()),
        "stderr": stderr, "stderr_size": len(stderr.encode()), "stderr_sha256": sha(stderr.encode()),
    }


def host_command(attempt: str, operation: str, observation: str, argv: list[str], stdout: str, second: int) -> dict[str, object]:
    return {
        "schema_version": 1, "kind": legacy.RESTORE_HOST_COMMAND_KIND,
        "workflow_id": evidence.WORKFLOW_ID, "operation_id": operation,
        "observation": observation, "vmx": evidence.VMX, "restore_attempt_id": attempt,
        "request": {"argv": argv, "command_line": " ".join(argv)},
        "started_at": f"2026-09-21T03:00:{second:02d}Z",
        "ended_at": f"2026-09-21T03:00:{second + 1:02d}Z",
        "exit_status": {"code": 0}, "response": response(stdout),
    }


def guest_command(attempt: str, second: int = 6) -> dict[str, object]:
    script = legacy.RESTORE_GUEST_IDENTITY_SCRIPT
    stdout = json.dumps({
        "computer_name": "DESKTOP-3FI41GR",
        "adapters": [{
            "MACAddress": "00:0C:29:83:B8:65", "IPAddress": ["192.168.204.232"],
            "DHCPEnabled": False, "IPEnabled": True,
        }],
    }, separators=(",", ":"))
    return {
        "schema_version": 1, "kind": legacy.RESTORE_GUEST_IDENTITY_KIND,
        "workflow_id": evidence.WORKFLOW_ID, "operation_id": "post-restore-identity",
        "observation": "guest-identity-via-control-plane", "vmx": evidence.VMX,
        "restore_attempt_id": attempt, "endpoint": "http://192.168.204.232:28787/mcp",
        "transport": "control-plane-mcp-http",
        "request": {"script": script, "script_sha256": sha(script.encode()), "tool": "PowerShell"},
        "started_at": f"2026-09-21T03:00:{second:02d}Z",
        "ended_at": f"2026-09-21T03:00:{second + 1:02d}Z",
        "exit_status": {"code": 0}, "response": response(stdout),
    }


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class Pc020Epoch7RestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        required = {
            "predecessor": os.environ.get("PC020_PREDECESSOR_FIXTURE"),
            "baseline": os.environ.get("PC020_BASELINE_DIR_FIXTURE"),
            "activation": os.environ.get("PC020_ACTIVATION_DIR_FIXTURE"),
            "real_sources": os.environ.get("PC020_REAL_SOURCE_ROOT"),
        }
        missing = [name for name, value in required.items() if not value or not Path(value).exists()]
        if missing:
            raise RuntimeError(f"required PC020 fixtures missing: {missing}")
        predecessor = Path(required["predecessor"]).read_bytes()
        source_root = Path(required["real_sources"])
        source_data = {name: (source_root / name).read_bytes() for name in evidence.PC020_REQUIRED_SOURCE_PATHS}
        cls.bundle_temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        cls.root = Path(cls.bundle_temp.name).resolve()
        fixture = Fixture(cls.root, source_data)
        repo = Path(__file__).resolve().parents[1]
        implementation_paths = (
            "tests/p05_snapshot_raw.py", "tests/p05_pc020_evidence.py",
            "tests/test_p05_pc020_evidence.py", "tests/p05_pc020_creation.py",
            "tests/test_p05_pc020_creation.py", "tests/p06_evidence.py",
            "tests/test_p06_evidence_schema5.py", "tests/p05_pc020_restore.py",
            "tests/test_p05_pc020_restore.py",
        )
        fixture.implementation_data = {name: (repo / name).read_bytes() for name in implementation_paths}
        fixture.policy = evidence.FrozenSourcePolicy(
            source_inputs={name: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for name, data in source_data.items()},
            implementation_sources={name: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for name, data in fixture.implementation_data.items()},
            synthetic_fixture=True,
        )
        cls.fixture = fixture
        cls.preparation = fixture.preparation().resolve()
        cls.migration = fixture.migration(
            cls.preparation, predecessor, Path(required["baseline"]), Path(required["activation"]),
        ).resolve()
        evidence.verify_preparation(cls.preparation, policy=fixture.policy)
        evidence.verify_migration(cls.migration, original_preparation=cls.preparation, policy=fixture.policy)
        (cls.root / "cases").mkdir()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.bundle_temp.cleanup()

    def fixed_ref(self, path: Path) -> dict[str, object]:
        return {"kind": path.name, "path": path.relative_to(self.root).as_posix(), "sha256": sha(path.read_bytes())}

    def canonical(self, path: Path) -> dict[str, object]:
        prep = json.loads(self.preparation.read_bytes())
        migration = json.loads(self.migration.read_bytes())
        return {
            "schema_version": 6, "workflow_id": evidence.WORKFLOW_ID, "epoch": 7,
            "phase": "PREPARATION_BASELINE",
            "active_snapshot": {
                "name": evidence.SNAPSHOT_187, "checkpoint_marker": evidence.MARKER_187,
                "purpose": "P05 preparation only; not product readiness or P06 authorization",
            },
            "automatic_restore_allowlist": [evidence.SNAPSHOT_187],
            "retired_snapshots": [
                {"name": name, "status": evidence.MANUAL_ONLY}
                for name in (
                    "Snapshot 183-FakenetNG测试专用", "Snapshot 184-Velociraptor-MCP测试基线",
                    "Snapshot 1-开启Windows-MCP", "Snapshot 186-Velociraptor-MCP网络部署基线",
                    evidence.SNAPSHOT_188,
                )
            ],
            "migration_evidence": {
                "kind": "pc020-requalification-migration-v1", "source": "pc020-migration",
                "evidence_path": self.migration.relative_to(self.root).as_posix(),
                "evidence_sha256": sha(self.migration.read_bytes()),
                "predecessor_sha256": evidence.PREDECESSOR_SHA256,
                "migrated_at": migration["migrated_at"],
            },
            "preparation_evidence": {
                "kind": "pc020-snapshot187-preparation-v1", "source": "pc020-preparation-admission",
                "evidence_path": self.preparation.relative_to(self.root).as_posix(),
                "evidence_sha256": sha(self.preparation.read_bytes()),
                "qualified_at": prep["qualified_at"],
            },
            "activation_evidence": None,
        }

    def creation_bundle(self, root: Path, attempt: str, marker: str) -> Path:
        creation_root = root / "creation"
        creation_root.mkdir()
        tree_before = f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n  {evidence.SNAPSHOT_188}\n"
        tree_after = f"Total snapshots: 3\n{evidence.SNAPSHOT_187}\n  {evidence.SNAPSHOT_188}\n  {evidence.SNAPSHOT_189}\n"
        metadata = "\n".join([
            'snapshot.numSnapshots = "3"', 'snapshot.lastUID = "8"', 'snapshot.current = "8"',
            f'snapshot0.displayName = "{evidence.SNAPSHOT_187}"', 'snapshot0.uid = "3"',
            f'snapshot0.filename = "{evidence.MARKER_187}"',
            f'snapshot1.displayName = "{evidence.SNAPSHOT_188}"', 'snapshot1.uid = "4"',
            'snapshot1.parent = "3"', 'snapshot1.filename = "Win10MalBox-Velo-Snapshot4.vmsn"',
            f'snapshot2.displayName = "{evidence.SNAPSHOT_189}"', 'snapshot2.uid = "8"',
            'snapshot2.parent = "3"', f'snapshot2.filename = "{marker}"', "",
        ])
        base = ["/usr/bin/vmrun", "-T", "ws"]
        originals = {
            "tree_before": host_command(attempt, attempt, "tree_before", base + ["listSnapshots", evidence.VMX, "showTree"], tree_before, 20),
            "create_operation": host_command(attempt, attempt, "create_operation", base + ["snapshot", evidence.VMX, evidence.SNAPSHOT_189], "", 22),
            "tree_after": host_command(attempt, attempt, "tree_after", base + ["listSnapshots", evidence.VMX, "showTree"], tree_after, 24),
            "metadata_readback": host_command(attempt, attempt, "metadata_readback", ["/usr/bin/cat", str(Path(evidence.VMX).with_suffix(".vmsd")).replace("\\", "/")], metadata, 26),
        }
        for value in originals.values():
            value.pop("restore_attempt_id")
        document: dict[str, object] = {
            "schema_version": 1, "workflow_id": evidence.WORKFLOW_ID,
            "candidate": evidence.SNAPSHOT_189, "checkpoint_marker": marker, "vmx": evidence.VMX,
        }
        for name, value in originals.items():
            write_json(creation_root / f"{name}.json", value)
            document[name] = ref(creation_root, f"{name}.json")
        write_json(creation_root / "creation.json", document)
        return (creation_root / "creation.json").resolve()

    @contextmanager
    def case(self, stage: str):
        temporary = tempfile.TemporaryDirectory(dir=self.root / "cases")
        try:
            case_root = Path(temporary.name)
            attempt = str(uuid.uuid4())
            run_id = str(uuid.uuid4())
            snapshot = evidence.SNAPSHOT_187 if stage == "P05_REPAIR_INITIAL" else evidence.SNAPSHOT_189
            marker = evidence.MARKER_187 if stage == "P05_REPAIR_INITIAL" else "Win10MalBox-Velo-Snapshot27.vmsn"
            names = [evidence.SNAPSHOT_187, evidence.SNAPSHOT_188]
            if stage == "P05_REPAIR_CANDIDATE":
                names.append(evidence.SNAPSHOT_189)
            tree = "Total snapshots: " + str(len(names)) + "\n" + "\n".join(names) + "\n"
            raw_paths = {
                "snapshot_metadata": case_root / "raw/snapshot-metadata.json",
                "revert_operation": case_root / "raw/revert-operation.json",
                "pre_start_marker": case_root / "raw/pre-start-marker.json",
                "post_restore_hostname": case_root / "raw/post-restore-identity.json",
            }
            base = ["/usr/bin/vmrun", "-T", "ws"]
            write_json(raw_paths["snapshot_metadata"], host_command(attempt, "snapshot-metadata", "snapshot-tree-readonly", base + ["listSnapshots", evidence.VMX], tree, 0))
            write_json(raw_paths["revert_operation"], host_command(attempt, "revert-operation", "single-revert", base + ["revertToSnapshot", evidence.VMX, snapshot], "", 2))
            write_json(raw_paths["pre_start_marker"], host_command(attempt, "pre-start-marker", "vmx-checkpoint-marker-before-start", ["/bin/grep", "^checkpoint.vmState", evidence.VMX], f'checkpoint.vmState = "{marker}"\n', 4))
            write_json(raw_paths["post_restore_hostname"], guest_command(attempt))
            canonical_path = case_root / "canonical-readback.json"
            write_json(canonical_path, self.canonical(canonical_path))
            records = {
                **raw_paths, "canonical_readback": canonical_path,
                "pc020_migration": self.migration, "pc020_preparation": self.preparation,
            }
            restore = {
                "workflow_id": evidence.WORKFLOW_ID, "run_id": run_id,
                "restore_attempt_id": attempt, "snapshot_stage": stage,
                "snapshot_name": snapshot, "checkpoint_marker": marker,
                "canonical_schema_version": 6, "canonical_epoch": 7,
                "canonical_phase": "PREPARATION_BASELINE",
                "canonical_sha256": sha(canonical_path.read_bytes()),
                "restore_records": [
                    {"kind": kind, "path": path.relative_to(self.root).as_posix(), "sha256": sha(path.read_bytes())}
                    for kind, path in records.items()
                ],
            }
            sentinel = case_root / "sentinel.bin"
            sentinel.write_bytes(b"restore7 external sentinel")
            creation_path = None if stage == "P05_REPAIR_INITIAL" else self.creation_bundle(case_root, attempt, marker)
            yield {
                "root": self.root, "case_root": case_root, "restore": restore,
                "records": records, "raw": raw_paths, "canonical": canonical_path,
                "creation": creation_path, "sentinel": sentinel, "stage": stage,
            }
        finally:
            temporary.cleanup()

    def verify(self, case):
        return restore7.verify_epoch7_restore(
            case["restore"], case["root"], policy=self.fixture.policy,
            creation_path=case["creation"],
        )

    def refresh_record(self, case, kind: str) -> None:
        path = case["records"][kind]
        record = next(row for row in case["restore"]["restore_records"] if row["kind"] == kind)
        record["sha256"] = sha(path.read_bytes())
        if kind == "canonical_readback":
            case["restore"]["canonical_sha256"] = record["sha256"]

    def mutate_json_record(self, case, kind: str, mutate) -> None:
        path = case["records"][kind]
        document = json.loads(path.read_bytes())
        mutate(document)
        write_json(path, document)
        self.refresh_record(case, kind)

    def set_snapshot_inventory(self, case, lines: list[str], total: int | None = None) -> None:
        document = json.loads(case["records"]["snapshot_metadata"].read_bytes())
        count = len(lines) if total is None else total
        document["response"] = response(
            "Total snapshots: " + str(count) + "\n" + "\n".join(lines) + "\n"
        )
        write_json(case["records"]["snapshot_metadata"], document)
        self.refresh_record(case, "snapshot_metadata")

    def test_snapshot_inventory_accepts_any_unique_exact_member_order(self):
        cases = (
            ("P05_REPAIR_INITIAL", ["  " + evidence.SNAPSHOT_188, "\t" + evidence.SNAPSHOT_187]),
            ("P05_REPAIR_CANDIDATE", [evidence.SNAPSHOT_189, "  " + evidence.SNAPSHOT_187, evidence.SNAPSHOT_188]),
            ("P05_REPAIR_CANDIDATE", ["\t" + evidence.SNAPSHOT_188, evidence.SNAPSHOT_189, "   " + evidence.SNAPSHOT_187]),
        )
        for stage, lines in cases:
            with self.subTest(stage=stage, lines=lines), self.case(stage) as case:
                self.set_snapshot_inventory(case, lines)
                before = case["sentinel"].read_bytes()
                result = self.verify(case)
                self.assertEqual(result["stage"], stage)
                self.assertEqual(case["sentinel"].read_bytes(), before)

    def test_snapshot_inventory_rejects_nonexact_or_nonunique_members(self):
        cases = (
            ("duplicate", [evidence.SNAPSHOT_187, evidence.SNAPSHOT_189, evidence.SNAPSHOT_189], None),
            ("missing", [evidence.SNAPSHOT_187, evidence.SNAPSHOT_189], None),
            ("unknown", [evidence.SNAPSHOT_187, evidence.SNAPSHOT_189, "Snapshot 190-unknown"], None),
            ("extra", [evidence.SNAPSHOT_187, evidence.SNAPSHOT_188, evidence.SNAPSHOT_189, "Snapshot 190-unknown"], None),
            ("wrong_total", [evidence.SNAPSHOT_187, evidence.SNAPSHOT_188, evidence.SNAPSHOT_189], 4),
        )
        for label, lines, total in cases:
            with self.subTest(case=label), self.case("P05_REPAIR_CANDIDATE") as case:
                self.set_snapshot_inventory(case, lines, total)
                before = case["sentinel"].read_bytes()
                with self.assertRaises(restore7.Epoch7RestoreError):
                    self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), before)

    def test_initial_and_candidate_epoch7_restores_are_verified_read_only(self):
        for stage in ("P05_REPAIR_INITIAL", "P05_REPAIR_CANDIDATE"):
            with self.subTest(stage=stage), self.case(stage) as case:
                before = {p.relative_to(self.root).as_posix(): sha(p.read_bytes()) for p in self.root.rglob("*") if p.is_file()}
                result = self.verify(case)
                after = {p.relative_to(self.root).as_posix(): sha(p.read_bytes()) for p in self.root.rglob("*") if p.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(result["stage"], stage)
                self.assertEqual(result["canonical_epoch"], 7)
                self.assertEqual(result["canonical_active_snapshot"], evidence.SNAPSHOT_187)
                self.assertFalse(result["operational_ready"])
                self.assertFalse(result["authorizes_p06"])
                self.assertEqual(case["sentinel"].read_bytes(), b"restore7 external sentinel")
                if stage == "P05_REPAIR_INITIAL":
                    self.assertIsNone(case["creation"])
                else:
                    self.assertEqual(result["checkpoint_marker"], "Win10MalBox-Velo-Snapshot27.vmsn")
        print("PC020_RESTORE7_SUCCESS=" + json.dumps({
            "synthetic": True, "stages": ["P05_REPAIR_INITIAL", "P05_REPAIR_CANDIDATE"],
            "real_io": ["plain-file traversal", "byte/size/SHA readback"],
            "not_executed": ["VMware", "restore", "start", "canonical write", "activation", "P06"],
        }, sort_keys=True))

    def test_stage_and_epoch7_pairing_matrix_is_rejected(self):
        cases = (
            "snapshot", "schema", "epoch", "phase", "allowlist", "retired", "marker",
            "candidate_active189", "old188", "schema5", "p06_active", "epoch8",
        )
        for label in cases:
            with self.subTest(case=label), self.case("P05_REPAIR_CANDIDATE") as case:
                if label == "snapshot": case["restore"]["snapshot_name"] = evidence.SNAPSHOT_187
                elif label == "schema": case["restore"]["canonical_schema_version"] = 5
                elif label == "epoch": case["restore"]["canonical_epoch"] = 8
                elif label == "phase": case["restore"]["canonical_phase"] = "NETWORK_ACTIVE"
                elif label == "marker": case["restore"]["checkpoint_marker"] = "Win10MalBox-Velo-Snapshot8.vmsn"
                elif label == "old188": case["restore"]["snapshot_name"] = evidence.SNAPSHOT_188
                elif label == "schema5":
                    case["restore"]["canonical_schema_version"] = 5; case["restore"]["canonical_epoch"] = 6
                elif label == "p06_active": case["restore"]["snapshot_stage"] = "P06_ACTIVE"
                elif label == "epoch8": case["restore"]["canonical_epoch"] = 8
                else:
                    canonical = json.loads(case["canonical"].read_bytes())
                    if label == "allowlist": canonical["automatic_restore_allowlist"] = [evidence.SNAPSHOT_189]
                    elif label == "retired": canonical["retired_snapshots"].pop()
                    elif label == "candidate_active189":
                        canonical["active_snapshot"]["name"] = evidence.SNAPSHOT_189
                        canonical["automatic_restore_allowlist"] = [evidence.SNAPSHOT_189]
                    write_json(case["canonical"], canonical); self.refresh_record(case, "canonical_readback")
                with self.assertRaises(restore7.Epoch7RestoreError): self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), b"restore7 external sentinel")

    def test_record_and_package_boundaries_are_rejected(self):
        labels = (
            "missing", "extra", "duplicate", "baseline", "activation", "record_extra",
            "hash", "dotdot", "link", "missing_deep", "migration_ref_hash",
            "preparation_ref_path", "migration_ref_time",
        )
        for label in labels:
            with self.subTest(case=label), self.case("P05_REPAIR_INITIAL") as case:
                records = case["restore"]["restore_records"]
                restore_deep = None
                if label == "missing": records.pop()
                elif label == "extra": records.append({"kind": "activation_evidence", "path": records[0]["path"], "sha256": records[0]["sha256"]})
                elif label == "duplicate": records[-1] = dict(records[0])
                elif label == "baseline": records[-1]["kind"] = "baseline_adoption"
                elif label == "activation": records[-1]["kind"] = "activation_evidence"
                elif label == "record_extra": records[0]["size"] = 1
                elif label == "hash": records[0]["sha256"] = "0" * 64
                elif label == "dotdot": records[0]["path"] = "../escape.json"
                elif label == "link":
                    target = case["case_root"] / "raw/link-target.json"
                    target.write_bytes(case["raw"]["snapshot_metadata"].read_bytes())
                    link = case["case_root"] / "raw/link.json"; link.symlink_to(target.name)
                    records[0]["path"] = link.relative_to(self.root).as_posix()
                elif label == "missing_deep":
                    deep = self.preparation.parent / "raw/tree.json"
                    restore_deep = deep.read_bytes(); deep.unlink()
                else:
                    canonical = json.loads(case["canonical"].read_bytes())
                    if label == "migration_ref_hash": canonical["migration_evidence"]["evidence_sha256"] = "0" * 64
                    elif label == "preparation_ref_path": canonical["preparation_evidence"]["evidence_path"] = "pc020-preparation/00000000-0000-0000-0000-000000000000/admission.json"
                    else: canonical["migration_evidence"]["migrated_at"] = "2026-09-21T00:00:00Z"
                    write_json(case["canonical"], canonical); self.refresh_record(case, "canonical_readback")
                try:
                    with self.assertRaises(restore7.Epoch7RestoreError): self.verify(case)
                finally:
                    if restore_deep is not None: (self.preparation.parent / "raw/tree.json").write_bytes(restore_deep)
                self.assertEqual(case["sentinel"].read_bytes(), b"restore7 external sentinel")

    def test_raw_original_negative_matrix_is_rejected(self):
        labels = (
            "attempt", "workflow", "vmx", "observation", "argv", "exit", "stream",
            "duplicate_revert", "duplicate_start", "order", "no_marker", "wrong_marker",
            "hostname", "mac", "ip", "dhcp", "stderr", "summary", "substring",
        )
        for label in labels:
            with self.subTest(case=label), self.case("P05_REPAIR_CANDIDATE") as case:
                kind = "revert_operation"
                def mutate(document):
                    nonlocal kind
                    if label == "attempt": document["restore_attempt_id"] = str(uuid.uuid4())
                    elif label == "workflow": document["workflow_id"] = "wf-other"
                    elif label == "vmx": document["vmx"] = "/other/Win10MalBox-Velo.vmx"
                    elif label == "observation": document["observation"] = "other"
                    elif label == "argv": document["request"]["argv"][-1] = evidence.SNAPSHOT_187
                    elif label == "exit": document["exit_status"]["code"] = 1
                    elif label == "duplicate_revert": document["request"]["argv"] += ["revertToSnapshot", evidence.VMX, evidence.SNAPSHOT_189]
                    elif label == "duplicate_start":
                        kind = "pre_start_marker"; document = None
                    elif label == "order": document["started_at"] = "2026-09-21T02:59:00Z"; document["ended_at"] = "2026-09-21T02:59:01Z"
                    elif label in {"no_marker", "wrong_marker"}:
                        kind = "pre_start_marker"; document = None
                    elif label in {"hostname", "mac", "ip", "dhcp"}:
                        kind = "post_restore_hostname"; document = None
                    elif label == "stderr": document["response"] = response("", "synthetic error")
                    elif label == "stream": document["response"]["stdout"] = "tampered"
                    elif label == "summary": document.clear(); document.update({"schema_version": 1, "kind": "p05-restore-record-summary-v1", "checkpoint_marker": case["restore"]["checkpoint_marker"]})
                    elif label == "substring":
                        kind = "snapshot_metadata"; document = None
                document = json.loads(case["records"][kind].read_bytes())
                mutate(document)
                if label == "duplicate_start":
                    document = json.loads(case["records"][kind].read_bytes()); document["request"]["argv"] += ["start", evidence.VMX]
                elif label in {"no_marker", "wrong_marker"}:
                    document = json.loads(case["records"][kind].read_bytes())
                    text = "" if label == "no_marker" else 'checkpoint.vmState = "wrong.vmsn"\n'; document["response"] = response(text)
                elif label in {"hostname", "mac", "ip", "dhcp"}:
                    document = json.loads(case["records"][kind].read_bytes()); identity = json.loads(document["response"]["stdout"])
                    if label == "hostname": identity["computer_name"] = "OTHER"
                    elif label == "mac": identity["adapters"][0]["MACAddress"] = "00:00:00:00:00:00"
                    elif label == "ip": identity["adapters"][0]["IPAddress"] = ["192.168.204.99"]
                    else: identity["adapters"][0]["DHCPEnabled"] = True
                    document["response"] = response(json.dumps(identity, separators=(",", ":")))
                elif label == "substring":
                    document = json.loads(case["records"][kind].read_bytes()); document["response"] = response(f"Total snapshots: 1\nprefix-{evidence.SNAPSHOT_189}-suffix\n")
                write_json(case["records"][kind], document); self.refresh_record(case, kind)
                with self.assertRaises(restore7.Epoch7RestoreError): self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), b"restore7 external sentinel")

    def test_scope_and_creation_causality_remain_closed(self):
        with self.case("P05_REPAIR_INITIAL") as initial:
            initial["creation"] = self.creation_bundle(initial["case_root"], str(uuid.uuid4()), "Win10MalBox-Velo-Snapshot27.vmsn")
            with self.assertRaises(restore7.Epoch7RestoreError): self.verify(initial)
        with self.case("P05_REPAIR_CANDIDATE") as candidate:
            candidate["creation"] = None
            with self.assertRaises(restore7.Epoch7RestoreError): self.verify(candidate)
        with self.case("P05_REPAIR_CANDIDATE") as first, self.case("P05_REPAIR_CANDIDATE") as second:
            self.assertNotEqual(first["restore"]["restore_attempt_id"], second["restore"]["restore_attempt_id"])
            self.verify(first); self.verify(second)


if __name__ == "__main__":
    unittest.main()

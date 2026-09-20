"""Windows-only synthetic tests for the read-only PC020 Snapshot189 verifier."""

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
from tests.test_p05_pc020_evidence import Fixture, blob, ref, sha


def response(stdout: str, stderr: str = "") -> dict[str, object]:
    return {
        "stdout": stdout,
        "stdout_size": len(stdout.encode()),
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr": stderr,
        "stderr_size": len(stderr.encode()),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }


def command(
    operation_id: str,
    observation: str,
    argv: list[str],
    stdout: str,
    second: int,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "p05-snapshot-command-v1",
        "workflow_id": evidence.WORKFLOW_ID,
        "operation_id": operation_id,
        "observation": observation,
        "vmx": evidence.VMX,
        "request": {"argv": argv, "command_line": " ".join(argv)},
        "started_at": f"2026-09-21T01:00:{second:02d}Z",
        "ended_at": f"2026-09-21T01:00:{second + 1:02d}Z",
        "exit_status": {"code": 0},
        "response": response(stdout),
    }


def write_json(path: Path, value: object) -> None:
    path.write_bytes(evidence.canonical_json(value))


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class Pc020Creation189Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prep_temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        fixture = Fixture(Path(cls.prep_temp.name))
        repo = Path(__file__).resolve().parents[1]
        implementation_paths = (
            "tests/p05_snapshot_raw.py",
            "tests/p05_pc020_evidence.py",
            "tests/test_p05_pc020_evidence.py",
            "tests/p05_pc020_creation.py",
            "tests/test_p05_pc020_creation.py",
        )
        fixture.implementation_data = {
            name: (repo / name).read_bytes() for name in implementation_paths
        }
        fixture.policy = evidence.FrozenSourcePolicy(
            source_inputs=fixture.policy.source_inputs,
            implementation_sources={
                name: evidence.FrozenIdentity(len(data), sha(data), blob(data))
                for name, data in fixture.implementation_data.items()
            },
            synthetic_fixture=True,
        )
        cls.fixture = fixture
        cls.preparation = fixture.preparation().resolve()
        evidence.verify_preparation(cls.preparation, policy=fixture.policy)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.prep_temp.cleanup()

    @contextmanager
    def case(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        try:
            root = Path(temporary.name)
            evidence_root = root / "activation-189" / str(uuid.uuid4()) / "creation"
            evidence_root.mkdir(parents=True)
            sentinel = root / "external-sentinel.bin"
            sentinel.write_bytes(b"creation189 external sentinel")
            operation_id = str(uuid.uuid4())
            marker = "Win10MalBox-Velo-Snapshot27.vmsn"
            tree_before = (
                f"Total snapshots: 2\n  {evidence.SNAPSHOT_187}\n"
                f"    {evidence.SNAPSHOT_188}\n"
            )
            tree_after = (
                f"Total snapshots: 3\n{evidence.SNAPSHOT_187}\n"
                f"  {evidence.SNAPSHOT_188}\n  {evidence.SNAPSHOT_189}\n"
            )
            metadata = "\n".join([
                'snapshot.numSnapshots = "3"',
                'snapshot.lastUID = "8"',
                'snapshot.current = "8"',
                f'snapshot0.displayName = "{evidence.SNAPSHOT_187}"',
                'snapshot0.uid = "3"',
                f'snapshot0.filename = "{evidence.MARKER_187}"',
                f'snapshot1.displayName = "{evidence.SNAPSHOT_188}"',
                'snapshot1.uid = "4"',
                'snapshot1.parent = "3"',
                'snapshot1.filename = "Win10MalBox-Velo-Snapshot4.vmsn"',
                f'snapshot2.displayName = "{evidence.SNAPSHOT_189}"',
                'snapshot2.uid = "8"',
                'snapshot2.parent = "3"',
                f'snapshot2.filename = "{marker}"',
                "",
            ])
            base = ["/usr/bin/vmrun", "-T", "ws"]
            originals = {
                "tree_before": command(
                    operation_id,
                    "tree_before",
                    base + ["listSnapshots", evidence.VMX, "showTree"],
                    tree_before,
                    0,
                ),
                "create_operation": command(
                    operation_id,
                    "create_operation",
                    base + ["snapshot", evidence.VMX, evidence.SNAPSHOT_189],
                    "",
                    2,
                ),
                "tree_after": command(
                    operation_id,
                    "tree_after",
                    base + ["listSnapshots", evidence.VMX, "showTree"],
                    tree_after,
                    4,
                ),
                "metadata_readback": command(
                    operation_id,
                    "metadata_readback",
                    ["/usr/bin/cat", str(Path(evidence.VMX).with_suffix(".vmsd")).replace("\\", "/")],
                    metadata,
                    6,
                ),
            }
            document: dict[str, object] = {
                "schema_version": 1,
                "workflow_id": evidence.WORKFLOW_ID,
                "candidate": evidence.SNAPSHOT_189,
                "checkpoint_marker": marker,
                "vmx": evidence.VMX,
            }
            for name, original in originals.items():
                write_json(evidence_root / f"{name}.json", original)
                document[name] = ref(evidence_root, f"{name}.json")
            creation_path = evidence_root / "creation.json"
            write_json(creation_path, document)
            yield {
                "temporary": temporary,
                "root": root,
                "evidence_root": evidence_root,
                "creation": creation_path,
                "document": document,
                "originals": originals,
                "marker": marker,
                "operation_id": operation_id,
                "sentinel": sentinel,
            }
        finally:
            temporary.cleanup()

    def replace_original(self, case, name: str, value: dict[str, object]) -> None:
        path = case["evidence_root"] / f"{name}.json"
        write_json(path, value)
        case["document"][name] = ref(case["evidence_root"], f"{name}.json")
        write_json(case["creation"], case["document"])

    def verify(self, case, *, expected_marker: str | None = None):
        return creation.verify_snapshot189_creation(
            case["creation"].resolve(),
            preparation_admission=self.preparation,
            policy=self.fixture.policy,
            expected_marker=expected_marker or case["marker"],
        )

    def test_complete_live_creation_is_verified_read_only_from_actual_marker(self):
        with self.case() as case:
            prep_before = {
                path.relative_to(self.preparation.parent).as_posix(): sha(path.read_bytes())
                for path in self.preparation.parent.rglob("*") if path.is_file()
            }
            creation_before = {
                path.relative_to(case["root"]).as_posix(): sha(path.read_bytes())
                for path in case["root"].rglob("*") if path.is_file()
            }
            result = self.verify(case)
            creation_after = {
                path.relative_to(case["root"]).as_posix(): sha(path.read_bytes())
                for path in case["root"].rglob("*") if path.is_file()
            }
            prep_after = {
                path.relative_to(self.preparation.parent).as_posix(): sha(path.read_bytes())
                for path in self.preparation.parent.rglob("*") if path.is_file()
            }
            self.assertEqual(creation_before, creation_after)
            self.assertEqual(prep_before, prep_after)
            self.assertEqual(result["operation_id"], case["operation_id"])
            self.assertEqual(result["checkpoint_marker"], case["marker"])
            self.assertEqual(result["candidate_uid"], "8")
            self.assertNotIn("Snapshot8.vmsn", result["checkpoint_marker"])
            self.assertFalse(result["operational_ready"])
            self.assertFalse(result["authorizes_activation"])
            self.assertEqual(case["sentinel"].read_bytes(), b"creation189 external sentinel")
            print("PC020_CREATION189_SUCCESS=" + json.dumps({
                "synthetic": True,
                "real_io": ["plain-file traversal", "byte/size/SHA readback"],
                "not_executed": ["VMware", "snapshot creation", "restore", "activation"],
                "result": result,
                "input_files": len(creation_before),
                "inputs_unchanged": creation_before == creation_after and prep_before == prep_after,
            }, ensure_ascii=False, sort_keys=True))

    def test_wrapper_and_ref_boundaries_reject_without_writing_inputs(self):
        wrapper_cases = (
            "extra", "missing", "bool_schema", "old188", "reconstruction", "attestation",
        )
        for label in wrapper_cases:
            with self.subTest(case=label), self.case() as case:
                before = case["sentinel"].read_bytes()
                if label == "extra":
                    case["document"]["unexpected"] = None
                elif label == "missing":
                    del case["document"]["tree_after"]
                elif label == "bool_schema":
                    case["document"]["schema_version"] = True
                elif label == "old188":
                    case["document"]["candidate"] = evidence.SNAPSHOT_188
                elif label == "reconstruction":
                    case["document"]["evidence_mode"] = "historical-reconstruction"
                else:
                    case["document"]["attestation"] = {"passed": True}
                write_json(case["creation"], case["document"])
                with self.assertRaises(creation.Creation189Error):
                    self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), before)

        ref_cases = ("hash", "size", "dotdot", "missing", "conflict", "link")
        for label in ref_cases:
            with self.subTest(case=label), self.case() as case:
                before = case["sentinel"].read_bytes()
                reference = case["document"]["tree_after"]
                if label == "hash":
                    reference["sha256"] = "0" * 64
                elif label == "size":
                    reference["size"] += 1
                elif label == "dotdot":
                    reference["path"] = "../tree_after.json"
                elif label == "missing":
                    (case["evidence_root"] / "tree_after.json").unlink()
                elif label == "conflict":
                    case["document"]["tree_after"] = dict(case["document"]["tree_before"])
                    case["document"]["tree_after"]["size"] += 1
                else:
                    path = case["evidence_root"] / "tree_after.json"
                    target = case["evidence_root"] / "tree_after-target.json"
                    path.rename(target)
                    path.symlink_to(target.name)
                write_json(case["creation"], case["document"])
                with self.assertRaises(creation.Creation189Error):
                    self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), before)

    def test_command_identity_stream_and_causal_boundaries_are_rejected(self):
        cases = (
            "workflow", "operation", "vmx", "observation", "argv", "stop",
            "second_create", "command_line", "failure", "error_stdout", "stderr",
            "overlap", "reverse", "tree_stdout",
        )
        for label in cases:
            with self.subTest(case=label), self.case() as case:
                target = "create_operation"
                value = copy.deepcopy(case["originals"][target])
                if label == "workflow":
                    value["workflow_id"] = "wf-other"
                elif label == "operation":
                    value["operation_id"] = str(uuid.uuid4())
                elif label == "vmx":
                    value["vmx"] = "/other/Win10MalBox-Velo.vmx"
                elif label == "observation":
                    value["observation"] = "tree_after"
                elif label == "argv":
                    value["request"]["argv"][-1] = "Snapshot 190-not-allowed"
                elif label == "stop":
                    value["request"]["argv"][3] = "stop"
                elif label == "second_create":
                    value["request"]["argv"].extend(["snapshot", evidence.VMX, evidence.SNAPSHOT_189])
                elif label == "command_line":
                    value["request"]["command_line"] += "; vmrun snapshot second"
                elif label == "failure":
                    value["exit_status"]["code"] = 1
                elif label == "error_stdout":
                    value["response"] = response("Error: snapshot already exists")
                elif label == "stderr":
                    value["response"] = response("", "vmrun warning")
                elif label == "overlap":
                    value["started_at"] = "2026-09-21T01:00:00Z"
                elif label == "reverse":
                    value["ended_at"] = "2026-09-21T00:59:59Z"
                else:
                    target = "tree_after"
                    value = copy.deepcopy(case["originals"][target])
                    value["response"] = response("snapshot summary only")
                self.replace_original(case, target, value)
                with self.assertRaises(creation.Creation189Error):
                    self.verify(case)
                self.assertEqual(case["sentinel"].read_bytes(), b"creation189 external sentinel")

    def test_tree_and_metadata_identity_matrix_is_rejected(self):
        tree_cases = {
            "before_collision": ("tree_before", f"Total snapshots: 3\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_189}\n"),
            "before_duplicate": ("tree_before", f"Total snapshots: 3\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_188}\n"),
            "after_zero": ("tree_after", f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n"),
            "after_multi": ("tree_after", f"Total snapshots: 4\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_189}\n{evidence.SNAPSHOT_189}\n"),
            "missing187": ("tree_after", f"Total snapshots: 2\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_189}\n"),
            "renamed188": ("tree_after", f"Total snapshots: 3\n{evidence.SNAPSHOT_187}\nrenamed-188\n{evidence.SNAPSHOT_189}\n"),
            "extra190": ("tree_after", f"Total snapshots: 4\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_189}\nSnapshot 190\n"),
            "wrong_total": ("tree_after", f"Total snapshots: 2\n{evidence.SNAPSHOT_187}\n{evidence.SNAPSHOT_188}\n{evidence.SNAPSHOT_189}\n"),
        }
        for label, (target, stdout) in tree_cases.items():
            with self.subTest(case=label), self.case() as case:
                value = copy.deepcopy(case["originals"][target])
                value["response"] = response(stdout)
                self.replace_original(case, target, value)
                with self.assertRaises(creation.Creation189Error):
                    self.verify(case)

        metadata_cases = {
            "guessed_marker": ('Snapshot27.vmsn', 'Snapshot8.vmsn'),
            "reuse_uid": ('snapshot2.uid = "8"', 'snapshot2.uid = "4"'),
            "wrong_current": ('snapshot.current = "8"', 'snapshot.current = "4"'),
            "wrong_last_uid": ('snapshot.lastUID = "8"', 'snapshot.lastUID = "4"'),
            "changed_187_uid": ('snapshot0.uid = "3"', 'snapshot0.uid = "7"'),
            "changed_187_marker": (evidence.MARKER_187, 'Win10MalBox-Velo-Snapshot9.vmsn'),
            "invented_187_parent": ('snapshot0.uid = "3"', 'snapshot0.uid = "3"\nsnapshot0.parent = "1"'),
            "changed_188_uid": ('snapshot1.uid = "4"', 'snapshot1.uid = "6"'),
            "changed_188_marker": ('Win10MalBox-Velo-Snapshot4.vmsn', 'Win10MalBox-Velo-Snapshot6.vmsn'),
            "changed_188_parent": ('snapshot1.parent = "3"', 'snapshot1.parent = "2"'),
            "missing_188_parent": ('snapshot1.parent = "3"\n', ''),
            "parent_188": ('snapshot2.parent = "3"', 'snapshot2.parent = "4"'),
            "missing_189_parent": ('snapshot2.parent = "3"\n', ''),
            "unknown_189_parent": ('snapshot2.parent = "3"', 'snapshot2.parent = "77"'),
            "self_189_parent": ('snapshot2.parent = "3"', 'snapshot2.parent = "8"'),
        }
        for label, (old, new) in metadata_cases.items():
            with self.subTest(case=label), self.case() as case:
                value = copy.deepcopy(case["originals"]["metadata_readback"])
                if label == "guessed_marker":
                    # Guessing filename from UID must not replace the actual
                    # filename recorded by the immutable metadata original.
                    expected = "Win10MalBox-Velo-Snapshot8.vmsn"
                    case["document"]["checkpoint_marker"] = expected
                    write_json(case["creation"], case["document"])
                else:
                    self.assertIn(old, value["response"]["stdout"])
                    value["response"] = response(value["response"]["stdout"].replace(old, new, 1))
                    self.replace_original(case, "metadata_readback", value)
                    expected = case["marker"]
                with self.assertRaises(creation.Creation189Error):
                    self.verify(case, expected_marker=expected)

    def test_scope_rejects_old188_and_never_authorizes_activation(self):
        with self.case() as case:
            result = self.verify(case)
            self.assertEqual(result["scope"], "single_snapshot189_creation_evidence")
            self.assertFalse(result["operational_ready"])
            self.assertFalse(result["authorizes_activation"])
            document = case["document"]
            document["candidate"] = evidence.SNAPSHOT_188
            write_json(case["creation"], document)
            with self.assertRaises(creation.Creation189Error):
                self.verify(case)
            document["candidate"] = evidence.SNAPSHOT_189
            document["evidence_mode"] = "historical-reconstruction"
            write_json(case["creation"], document)
            with self.assertRaises(creation.Creation189Error):
                self.verify(case)


if __name__ == "__main__":
    unittest.main()

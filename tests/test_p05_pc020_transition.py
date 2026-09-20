from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_transition as writer
from tests.test_p05_pc020_evidence import Fixture


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class Pc020TransitionTests(unittest.TestCase):
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
        cls.predecessor = Path(required["predecessor"]).read_bytes()
        if sha(cls.predecessor) != evidence.PREDECESSOR_SHA256:
            raise RuntimeError("predecessor fixture identity differs")
        source_root = Path(required["real_sources"])
        source_data = {path: (source_root / path).read_bytes() for path in evidence.PC020_REQUIRED_SOURCE_PATHS}
        cls.bundle_temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        fixture = Fixture(Path(cls.bundle_temp.name), source_data)
        repo = Path(__file__).resolve().parents[1]
        implementation_paths = (
            "tests/p05_pc020_evidence.py",
            "tests/p05_pc020_transition.py",
            "tests/test_p05_pc020_transition.py",
        )
        fixture.implementation_data = {name: (repo / name).read_bytes() for name in implementation_paths}
        fixture.policy = evidence.FrozenSourcePolicy(
            source_inputs={name: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for name, data in source_data.items()},
            implementation_sources={name: evidence.FrozenIdentity(len(data), sha(data), blob(data)) for name, data in fixture.implementation_data.items()},
            synthetic_fixture=True,
        )
        cls.fixture = fixture
        cls.preparation = fixture.preparation()
        cls.migration = fixture.migration(
            cls.preparation,
            cls.predecessor,
            Path(required["baseline"]),
            Path(required["activation"]),
        )
        evidence.verify_preparation(cls.preparation.resolve(), policy=fixture.policy)
        evidence.verify_migration(
            cls.migration.resolve(),
            original_preparation=cls.preparation.resolve(),
            policy=fixture.policy,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.bundle_temp.cleanup()

    def case(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        root = Path(temporary.name)
        canonical = root / "snapshot-recovery-state.json"
        canonical.write_bytes(self.predecessor)
        sentinel = root / "external-sentinel.bin"
        sentinel.write_bytes(b"external sentinel must remain unchanged")
        return temporary, canonical, sentinel

    def run_writer(self, canonical: Path, transition_id: str, *, fsync=None):
        side_effect = fsync or (lambda path: None)
        with mock.patch.object(writer, "_fsync_directory", side_effect=side_effect):
            return writer.transition_to_epoch7(
                canonical.resolve(),
                self.preparation.resolve(),
                self.migration.resolve(),
                policy=self.fixture.policy,
                transition_id=transition_id,
            )

    def assert_sources_unchanged(self, before: dict[str, tuple[int, str]]) -> None:
        after = {
            path.relative_to(Path(self.bundle_temp.name)).as_posix(): (path.stat().st_size, sha(path.read_bytes()))
            for path in Path(self.bundle_temp.name).rglob("*") if path.is_file()
        }
        self.assertEqual(after, before)

    def test_success_derives_exact_epoch7_and_durable_independent_records(self):
        temporary, canonical, sentinel = self.case()
        with temporary:
            source_before = {
                path.relative_to(Path(self.bundle_temp.name)).as_posix(): (path.stat().st_size, sha(path.read_bytes()))
                for path in Path(self.bundle_temp.name).rglob("*") if path.is_file()
            }
            transition_id = str(uuid.uuid4())
            fsync_events: list[str] = []
            outcome = self.run_writer(canonical, transition_id, fsync=lambda path: fsync_events.append(str(path)))
            self.assertEqual(outcome.status, writer.COMMITTED)
            self.assertTrue(outcome.receipt_written)
            self.assertFalse(outcome.next_path.exists())
            state_bytes = canonical.read_bytes()
            state = read_json(canonical)
            self.assertEqual(evidence.verify_schema6_shape(state_bytes, expected_epoch=7)["phase"], "PREPARATION_BASELINE")
            self.assertEqual(state["active_snapshot"], {
                "name": evidence.SNAPSHOT_187,
                "checkpoint_marker": evidence.MARKER_187,
                "purpose": "P05 preparation only; not product readiness or P06 authorization",
            })
            self.assertEqual(state["automatic_restore_allowlist"], [evidence.SNAPSHOT_187])
            self.assertEqual(
                [row["name"] for row in state["retired_snapshots"]],
                [
                    "Snapshot 183-FakenetNG测试专用",
                    "Snapshot 184-Velociraptor-MCP测试基线",
                    "Snapshot 1-开启Windows-MCP",
                    "Snapshot 186-Velociraptor-MCP网络部署基线",
                    evidence.SNAPSHOT_188,
                ],
            )
            self.assertIsNone(state["activation_evidence"])
            prep = read_json(self.preparation)
            migration = read_json(self.migration)
            self.assertEqual(state["preparation_evidence"]["evidence_sha256"], sha(self.preparation.read_bytes()))
            self.assertEqual(state["preparation_evidence"]["qualified_at"], prep["qualified_at"])
            self.assertEqual(state["migration_evidence"]["evidence_sha256"], sha(self.migration.read_bytes()))
            self.assertEqual(state["migration_evidence"]["migrated_at"], migration["migrated_at"])
            self.assertEqual(state["migration_evidence"]["predecessor_sha256"], evidence.PREDECESSOR_SHA256)

            intent = read_json(outcome.intent_path)
            receipt = read_json(outcome.receipt_path)
            self.assertEqual(set(intent), writer.INTENT_KEYS)
            self.assertEqual(intent["transition_id"], transition_id)
            self.assertEqual(intent["from_sha256"], evidence.PREDECESSOR_SHA256)
            self.assertEqual(intent["next_sha256"], sha(state_bytes))
            self.assertEqual(set(receipt), writer.RECEIPT_KEYS)
            self.assertEqual(receipt["status"], writer.COMMITTED)
            self.assertIsNone(receipt["error"])
            self.assertEqual(receipt["to_sha256"], sha(state_bytes))
            self.assertEqual(receipt["next_sha256"], sha(state_bytes))
            for name in ("started_at", "replaced_at", "directory_fsynced_at", "readback_at"):
                self.assertRegex(receipt[name], r"Z$")
            self.assertEqual(len(fsync_events), 4)  # next, intent, replacement, receipt
            self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
            self.assert_sources_unchanged(source_before)
            print("PC020_TRANSITION_SUCCESS=" + json.dumps({
                "synthetic": True,
                "directory_fsync": "external Windows test seam; not a real Windows durability claim",
                "actual_file_io": ["O_EXCL", "write", "flush", "file_fsync", "close", "replace", "readback"],
                "state_sha256": sha(state_bytes),
                "intent": intent,
                "receipt": receipt,
                "directory_fsync_events": fsync_events,
            }, ensure_ascii=False, sort_keys=True))

    def test_preflight_refusals_preserve_canonical_sources_unknown_next_and_sentinel(self):
        source_before = {
            path.relative_to(Path(self.bundle_temp.name)).as_posix(): (path.stat().st_size, sha(path.read_bytes()))
            for path in Path(self.bundle_temp.name).rglob("*") if path.is_file()
        }
        cases = ("bad_sha", "already_migrated", "unknown_next", "bad_graph", "intent_collision", "receipt_collision")
        for label in cases:
            with self.subTest(case=label):
                temporary, canonical, sentinel = self.case()
                with temporary:
                    transition_id = str(uuid.uuid4())
                    next_path, intent_path, receipt_path, _ = writer._output_paths(canonical, transition_id)
                    preparation = self.preparation
                    original = canonical.read_bytes()
                    unknown = b"unknown pending bytes"
                    if label == "bad_sha":
                        canonical.write_bytes(original + b" ")
                        expected_canonical = original + b" "
                    elif label == "already_migrated":
                        state = {
                            "schema_version": 6, "workflow_id": evidence.WORKFLOW_ID, "epoch": 7,
                            "phase": "PREPARATION_BASELINE", "active_snapshot": {"name": evidence.SNAPSHOT_187, "checkpoint_marker": evidence.MARKER_187, "purpose": "duplicate"},
                            "automatic_restore_allowlist": [evidence.SNAPSHOT_187],
                            "retired_snapshots": [], "migration_evidence": {}, "preparation_evidence": {}, "activation_evidence": None,
                        }
                        canonical.write_bytes(evidence.canonical_json(state))
                        expected_canonical = canonical.read_bytes()
                    else:
                        expected_canonical = original
                    if label == "unknown_next":
                        next_path.mkdir()
                        (next_path / "owner.bin").write_bytes(unknown)
                    elif label == "intent_collision":
                        intent_path.write_bytes(unknown)
                    elif label == "receipt_collision":
                        receipt_path.write_bytes(unknown)
                    elif label == "bad_graph":
                        copied = Path(temporary.name) / "pc020-preparation" / self.preparation.parent.name
                        shutil.copytree(self.preparation.parent, copied)
                        target = copied / "raw/tree.json"
                        target.write_bytes(target.read_bytes() + b" ")
                        preparation = copied / "admission.json"
                    with self.assertRaises(writer.Pc020TransitionError) as caught:
                        with mock.patch.object(writer, "_fsync_directory", return_value=None):
                            writer.transition_to_epoch7(
                                canonical.resolve(), preparation.resolve(), self.migration.resolve(),
                                policy=self.fixture.policy, transition_id=transition_id,
                            )
                    self.assertEqual(caught.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
                    self.assertEqual(canonical.read_bytes(), expected_canonical)
                    self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
                    if label == "unknown_next":
                        self.assertTrue(next_path.is_dir())
                        self.assertEqual((next_path / "owner.bin").read_bytes(), unknown)
                    if label == "intent_collision":
                        self.assertEqual(intent_path.read_bytes(), unknown)
                    if label == "receipt_collision":
                        self.assertEqual(receipt_path.read_bytes(), unknown)
        self.assert_sources_unchanged(source_before)

    def test_predecessor_shape_helper_rejects_wrong_schema_and_root_keys(self):
        base = json.loads(self.predecessor)
        schema = dict(base)
        schema["schema_version"] = 6
        extra = dict(base)
        extra["unexpected"] = None
        missing = dict(base)
        del missing["activation_evidence"]
        for label, value, message in (
            ("schema", schema, "schema"), ("extra", extra, "keys"), ("missing", missing, "keys")
        ):
            with self.subTest(case=label):
                with self.assertRaisesRegex(evidence.Pc020EvidenceError, message):
                    writer._validate_predecessor_shape(value)

    def test_pre_replace_fault_matrix_preserves_failure_scene_in_place(self):
        source_before = {
            path.relative_to(Path(self.bundle_temp.name)).as_posix(): (path.stat().st_size, sha(path.read_bytes()))
            for path in Path(self.bundle_temp.name).rglob("*") if path.is_file()
        }
        labels = (
            "write", "flush", "file_fsync", "close", "next_directory_fsync",
            "candidate_readback", "candidate_semantic", "intent_write",
            "intent_directory_fsync", "intent_readback", "adjacent_drift",
        )
        for label in labels:
            with self.subTest(fault=label):
                temporary, canonical, sentinel = self.case()
                with temporary, ExitStack() as stack:
                    transition_id = str(uuid.uuid4())
                    next_path, intent_path, receipt_path, _ = writer._output_paths(canonical, transition_id)
                    original = canonical.read_bytes()
                    original_write = writer._write_all
                    original_flush = writer._flush_file
                    original_fsync = writer._fsync_file
                    original_close = writer._close_file
                    original_read = writer._read_bytes
                    original_verify = evidence.verify_schema6_shape
                    directory_calls = 0

                    def write_fault(handle, payload, path):
                        if path == next_path and label == "write":
                            handle.write(payload[:7])
                            raise OSError("injected short write")
                        if path == intent_path and label == "intent_write":
                            handle.write(payload[:7])
                            raise OSError("injected intent write")
                        return original_write(handle, payload, path)

                    def flush_fault(handle, path):
                        if path == next_path and label == "flush":
                            raise OSError("injected flush")
                        return original_flush(handle, path)

                    def fsync_fault(handle, path):
                        if path == next_path and label == "file_fsync":
                            raise OSError("injected file fsync")
                        return original_fsync(handle, path)

                    def close_fault(handle, path):
                        original_close(handle, path)
                        if path == next_path and label == "close":
                            raise OSError("injected close")

                    def directory_fault(path):
                        nonlocal directory_calls
                        directory_calls += 1
                        if label == "next_directory_fsync" and directory_calls == 1:
                            raise OSError("injected next directory fsync")
                        if label == "intent_directory_fsync" and directory_calls == 2:
                            raise OSError("injected intent directory fsync")

                    canonical_reads = 0

                    def read_fault(path):
                        nonlocal canonical_reads
                        if path == next_path and label == "candidate_readback":
                            return b"candidate readback differs"
                        if path == intent_path and label == "intent_readback":
                            return b"intent readback differs"
                        if path == canonical:
                            canonical_reads += 1
                            if label == "adjacent_drift" and canonical_reads == 2:
                                canonical.write_bytes(b"external canonical drift")
                        return original_read(path)

                    verify_calls = 0

                    def verify_fault(data, *, expected_epoch):
                        nonlocal verify_calls
                        verify_calls += 1
                        if label == "candidate_semantic" and verify_calls == 2:
                            raise evidence.Pc020EvidenceError("injected candidate semantic rejection")
                        return original_verify(data, expected_epoch=expected_epoch)

                    stack.enter_context(mock.patch.object(writer, "_write_all", side_effect=write_fault))
                    stack.enter_context(mock.patch.object(writer, "_flush_file", side_effect=flush_fault))
                    stack.enter_context(mock.patch.object(writer, "_fsync_file", side_effect=fsync_fault))
                    stack.enter_context(mock.patch.object(writer, "_close_file", side_effect=close_fault))
                    stack.enter_context(mock.patch.object(writer, "_fsync_directory", side_effect=directory_fault))
                    stack.enter_context(mock.patch.object(writer, "_read_bytes", side_effect=read_fault))
                    stack.enter_context(mock.patch.object(evidence, "verify_schema6_shape", side_effect=verify_fault))
                    with self.assertRaises(writer.Pc020TransitionError) as caught:
                        writer.transition_to_epoch7(
                            canonical.resolve(), self.preparation.resolve(), self.migration.resolve(),
                            policy=self.fixture.policy, transition_id=transition_id,
                        )
                    outcome = caught.exception.outcome
                    self.assertEqual(outcome.status, writer.FAILED_BEFORE_REPLACE)
                    self.assertTrue(outcome.receipt_written)
                    receipt = read_json(receipt_path)
                    self.assertEqual(receipt["status"], writer.FAILED_BEFORE_REPLACE)
                    self.assertIsNone(receipt["replaced_at"])
                    self.assertIsNone(receipt["directory_fsynced_at"])
                    self.assertIsNone(receipt["readback_at"])
                    self.assertIsNotNone(receipt["error"])
                    expected_canonical = b"external canonical drift" if label == "adjacent_drift" else original
                    self.assertEqual(canonical.read_bytes(), expected_canonical)
                    self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
                    self.assertIsNone(outcome.isolation_path)
                    self.assertTrue(os.path.lexists(next_path))
                    if label == "adjacent_drift":
                        self.assertEqual(sha(next_path.read_bytes()), outcome.next_sha256)
                    if label in {"intent_write", "intent_directory_fsync", "intent_readback"}:
                        self.assertTrue(os.path.lexists(intent_path))
        self.assert_sources_unchanged(source_before)

    def test_late_failure_scene_changes_remain_in_place_without_cleanup_replace(self):
        source_before = {
            path.relative_to(Path(self.bundle_temp.name)).as_posix(): (path.stat().st_size, sha(path.read_bytes()))
            for path in Path(self.bundle_temp.name).rglob("*") if path.is_file()
        }
        foreign_next = b"foreign next bytes after durable intent"
        foreign_intent = b"foreign intent bytes after durable intent"
        late_isolation = b"late isolation target"
        observations = []
        for label in ("next_identity_changed", "intent_changed", "isolation_target_late"):
            with self.subTest(case=label):
                temporary, canonical, sentinel = self.case()
                with temporary, ExitStack() as stack:
                    transition_id = str(uuid.uuid4())
                    next_path, intent_path, receipt_path, isolation_path = writer._output_paths(
                        canonical, transition_id
                    )
                    original_read = writer._read_bytes
                    canonical_reads = 0
                    original_next_identity = None
                    changed_next_identity = None

                    def read_fault(path):
                        nonlocal canonical_reads, original_next_identity, changed_next_identity
                        if path == canonical:
                            canonical_reads += 1
                            if canonical_reads == 2:
                                canonical.write_bytes(b"external canonical drift")
                                if label == "next_identity_changed":
                                    original_next_identity = (next_path.stat().st_dev, next_path.stat().st_ino)
                                    replacement = next_path.parent / "foreign-next-object"
                                    replacement.write_bytes(foreign_next)
                                    os.replace(replacement, next_path)
                                    changed_next_identity = (next_path.stat().st_dev, next_path.stat().st_ino)
                                elif label == "intent_changed":
                                    intent_path.write_bytes(foreign_intent)
                                else:
                                    isolation_path.write_bytes(late_isolation)
                        return original_read(path)

                    replace_spy = mock.Mock(wraps=writer._replace)
                    stack.enter_context(mock.patch.object(writer, "_read_bytes", side_effect=read_fault))
                    stack.enter_context(mock.patch.object(writer, "_replace", replace_spy))
                    stack.enter_context(mock.patch.object(writer, "_fsync_directory", return_value=None))
                    with self.assertRaises(writer.Pc020TransitionError) as caught:
                        writer.transition_to_epoch7(
                            canonical.resolve(), self.preparation.resolve(), self.migration.resolve(),
                            policy=self.fixture.policy, transition_id=transition_id,
                        )
                    outcome = caught.exception.outcome
                    receipt = read_json(receipt_path)
                    self.assertEqual(outcome.status, writer.FAILED_BEFORE_REPLACE)
                    self.assertIsNone(outcome.isolation_path)
                    self.assertEqual(canonical.read_bytes(), b"external canonical drift")
                    self.assertTrue(next_path.exists())
                    self.assertTrue(intent_path.exists())
                    self.assertNotIn("isolation failed", receipt["error"])
                    replace_spy.assert_not_called()
                    if label == "next_identity_changed":
                        self.assertNotEqual(original_next_identity, changed_next_identity)
                        self.assertEqual(next_path.read_bytes(), foreign_next)
                    elif label == "intent_changed":
                        self.assertEqual(intent_path.read_bytes(), foreign_intent)
                    else:
                        self.assertEqual(isolation_path.read_bytes(), late_isolation)
                    self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
                    observations.append({
                        "case": label,
                        "injection_point": "second canonical read after durable intent and before formal replace",
                        "reason": receipt["error"],
                        "canonical_sha256": sha(canonical.read_bytes()),
                        "next_exists": next_path.exists(),
                        "next_sha256": sha(next_path.read_bytes()),
                        "intent_exists": intent_path.exists(),
                        "intent_sha256": sha(intent_path.read_bytes()),
                        "isolation_exists": isolation_path.exists(),
                        "isolation_sha256": sha(isolation_path.read_bytes()) if isolation_path.exists() else None,
                        "cleanup_replace_calls": replace_spy.call_count,
                    })
        self.assert_sources_unchanged(source_before)
        print("PC020_FAILURE_SCENE=" + json.dumps({
            "synthetic": True,
            "scope": "external test-I/O mutation at the frozen late-failure seam",
            "cases": observations,
        }, sort_keys=True))

    def test_replace_and_post_replace_uncertainty_never_rolls_back_or_claims_commit(self):
        labels = ("replace_before", "replace_after", "post_directory_fsync", "readback_error", "readback_bytes", "receipt_write")
        for label in labels:
            with self.subTest(fault=label):
                temporary, canonical, sentinel = self.case()
                with temporary, ExitStack() as stack:
                    transition_id = str(uuid.uuid4())
                    next_path, _, receipt_path, _ = writer._output_paths(canonical, transition_id)
                    original = canonical.read_bytes()
                    original_replace = writer._replace
                    original_read = writer._read_bytes
                    original_write = writer._write_all
                    directory_calls = 0
                    canonical_reads = 0

                    def replace_fault(source, target):
                        if target == canonical and label == "replace_before":
                            raise OSError("injected replace before syscall")
                        if target == canonical and label == "replace_after":
                            original_replace(source, target)
                            raise OSError("injected replace after syscall")
                        return original_replace(source, target)

                    def directory_fault(path):
                        nonlocal directory_calls
                        directory_calls += 1
                        if label == "post_directory_fsync" and directory_calls == 3:
                            raise OSError("injected post-replace directory fsync")

                    def read_fault(path):
                        nonlocal canonical_reads
                        if path == canonical:
                            canonical_reads += 1
                            if canonical_reads == 3 and label == "readback_error":
                                raise OSError("injected canonical readback")
                            if canonical_reads == 3 and label == "readback_bytes":
                                canonical.write_bytes(b"post-replace anomalous bytes")
                        return original_read(path)

                    def write_fault(handle, payload, path):
                        if path == receipt_path and label == "receipt_write":
                            handle.write(payload[:9])
                            raise OSError("injected receipt write")
                        return original_write(handle, payload, path)

                    stack.enter_context(mock.patch.object(writer, "_replace", side_effect=replace_fault))
                    stack.enter_context(mock.patch.object(writer, "_fsync_directory", side_effect=directory_fault))
                    stack.enter_context(mock.patch.object(writer, "_read_bytes", side_effect=read_fault))
                    stack.enter_context(mock.patch.object(writer, "_write_all", side_effect=write_fault))
                    with self.assertRaises(writer.Pc020TransitionError) as caught:
                        writer.transition_to_epoch7(
                            canonical.resolve(), self.preparation.resolve(), self.migration.resolve(),
                            policy=self.fixture.policy, transition_id=transition_id,
                        )
                    outcome = caught.exception.outcome
                    self.assertEqual(outcome.status, writer.TRANSITION_INDETERMINATE)
                    self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
                    if label == "replace_before":
                        self.assertEqual(canonical.read_bytes(), original)
                        self.assertTrue(next_path.exists())
                    elif label == "readback_bytes":
                        self.assertEqual(canonical.read_bytes(), b"post-replace anomalous bytes")
                        self.assertFalse(next_path.exists())
                    else:
                        self.assertNotEqual(canonical.read_bytes(), original)
                        self.assertFalse(next_path.exists())
                    if label == "receipt_write":
                        self.assertFalse(outcome.receipt_written)
                        self.assertTrue(receipt_path.exists())
                        with self.assertRaises(json.JSONDecodeError):
                            json.loads(receipt_path.read_bytes())
                    else:
                        self.assertTrue(outcome.receipt_written)
                        receipt = read_json(receipt_path)
                        self.assertEqual(receipt["status"], writer.TRANSITION_INDETERMINATE)
                        self.assertIsNotNone(receipt["error"])
                        self.assertIsNone(receipt["readback_at"])
                        if label in {"replace_before", "replace_after"}:
                            self.assertIsNone(receipt["replaced_at"])
                        else:
                            self.assertIsNotNone(receipt["replaced_at"])
                        if label == "post_directory_fsync":
                            self.assertIsNone(receipt["directory_fsynced_at"])

    def test_true_o_excl_race_allows_at_most_one_replace_and_preserves_loser_files(self):
        temporary, canonical, sentinel = self.case()
        with temporary:
            barrier = threading.Barrier(2)
            next_path = Path(str(canonical) + ".next")
            original_open = writer._open_exclusive
            original_replace = writer._replace
            replace_count = 0
            count_lock = threading.Lock()

            def racing_open(path):
                if path == next_path:
                    barrier.wait(timeout=30)
                return original_open(path)

            def counted_replace(source, target):
                nonlocal replace_count
                if target == canonical:
                    with count_lock:
                        replace_count += 1
                return original_replace(source, target)

            ids = [str(uuid.uuid4()), str(uuid.uuid4())]

            def attempt(identity):
                try:
                    result = writer.transition_to_epoch7(
                        canonical.resolve(), self.preparation.resolve(), self.migration.resolve(),
                        policy=self.fixture.policy, transition_id=identity,
                    )
                    return result
                except writer.Pc020TransitionError as exc:
                    return exc.outcome

            with (
                mock.patch.object(writer, "_open_exclusive", side_effect=racing_open),
                mock.patch.object(writer, "_replace", side_effect=counted_replace),
                mock.patch.object(writer, "_fsync_directory", return_value=None),
                concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
            ):
                outcomes = list(pool.map(attempt, ids))
            self.assertEqual([value.status for value in outcomes].count(writer.COMMITTED), 1)
            self.assertEqual([value.status for value in outcomes].count(writer.FAILED_BEFORE_REPLACE), 1)
            self.assertEqual(replace_count, 1)
            self.assertFalse(next_path.exists())
            self.assertEqual(evidence.verify_schema6_shape(canonical.read_bytes(), expected_epoch=7)["epoch"], 7)
            self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
            loser = next(value for value in outcomes if value.status == writer.FAILED_BEFORE_REPLACE)
            winner = next(value for value in outcomes if value.status == writer.COMMITTED)
            self.assertFalse(loser.intent_path.exists())
            self.assertTrue(loser.receipt_path.exists())
            self.assertTrue(winner.intent_path.exists())
            self.assertTrue(winner.receipt_path.exists())
            print("PC020_TRANSITION_RACE=" + json.dumps({
                "synthetic": True, "attempts": ids, "statuses": [x.status for x in outcomes],
                "replace_count": replace_count, "sentinel_sha256": sha(sentinel.read_bytes()),
            }, sort_keys=True))

    def test_path_object_and_collision_guards_fail_closed_without_overwrite(self):
        cases = (
            "canonical_directory", "canonical_link", "parent_link", "next_directory", "next_link",
            "preflight_isolation_collision",
        )
        for label in cases:
            with self.subTest(case=label):
                temporary = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
                with temporary:
                    root = Path(temporary.name)
                    canonical = root / "snapshot-recovery-state.json"
                    target = root / "canonical-target.json"
                    target.write_bytes(self.predecessor)
                    if label == "canonical_directory":
                        canonical.mkdir()
                    elif label == "canonical_link":
                        canonical.symlink_to(target.name)
                    elif label == "parent_link":
                        real_parent = root / "real-parent"
                        real_parent.mkdir()
                        (real_parent / canonical.name).write_bytes(self.predecessor)
                        alias = root / "alias-parent"
                        alias.symlink_to(real_parent.name, target_is_directory=True)
                        canonical = alias / canonical.name
                    else:
                        canonical.write_bytes(self.predecessor)
                    transition_id = str(uuid.uuid4())
                    next_path, _, _, isolation_path = writer._output_paths(canonical, transition_id)
                    marker = b"do not overwrite"
                    if label == "next_directory":
                        next_path.mkdir()
                        (next_path / "marker").write_bytes(marker)
                    elif label == "next_link":
                        link_target = root / "other-next"
                        link_target.write_bytes(marker)
                        next_path.symlink_to(link_target.name)
                    elif label == "preflight_isolation_collision":
                        isolation_path.write_bytes(marker)
                    with self.assertRaises(writer.Pc020TransitionError) as caught:
                        with mock.patch.object(writer, "_fsync_directory", return_value=None):
                            writer.transition_to_epoch7(
                                canonical.absolute(), self.preparation.resolve(), self.migration.resolve(),
                                policy=self.fixture.policy, transition_id=transition_id,
                            )
                    self.assertEqual(caught.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
                    if label == "next_directory":
                        self.assertEqual((next_path / "marker").read_bytes(), marker)
                    elif label == "next_link":
                        self.assertTrue(next_path.is_symlink())
                        self.assertEqual(next_path.read_bytes(), marker)
                    elif label == "preflight_isolation_collision":
                        self.assertEqual(isolation_path.read_bytes(), marker)

    def test_duplicate_run_is_stably_rejected_without_new_next_or_package(self):
        temporary, canonical, sentinel = self.case()
        with temporary:
            first = self.run_writer(canonical, str(uuid.uuid4()))
            committed = canonical.read_bytes()
            second_id = str(uuid.uuid4())
            with self.assertRaises(writer.Pc020TransitionError) as caught:
                self.run_writer(canonical, second_id)
            self.assertEqual(caught.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
            self.assertEqual(canonical.read_bytes(), committed)
            self.assertFalse(Path(str(canonical) + ".next").exists())
            self.assertEqual(sentinel.read_bytes(), b"external sentinel must remain unchanged")
            self.assertTrue(first.receipt_path.exists())


if __name__ == "__main__":
    unittest.main()

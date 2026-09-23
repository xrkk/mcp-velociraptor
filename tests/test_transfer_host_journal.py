"""Isolated benign host journal, fault and lock tests on Linux."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.host_journal import HostJournal, observe_host_identity
from velo_transfer.manifest import canonical_json, digest_json
from velo_transfer.request import load_request


class HostJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "request.json"
        self.document = {"schema": "velo.transfer.request.v1", "direction": "push",
            "sources": [{"absolute_path": "/missing/source", "relative_path": "source"}],
            "destination_directory": "E:\\Transfer\\batch",
            "connection_profile": "/missing/profile.json",
            "expected_vm_identity": {"vm_uuid": str(uuid.uuid4()), "boot_identity": "boot-1",
                                     "vm_epoch": "epoch-1"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["producer"]},
            "budget": {"max_files": 10, "max_metadata_bytes": 4096, "max_logical_bytes": 1 << 34,
                       "max_package_bytes": 1 << 35, "min_free_bytes": 0,
                       "max_chunk_bytes": 1024, "max_duration_seconds": 60,
                       "request_timeout_seconds": 10},
            "transfer_id": "task-1"}
        self.host = {"machine_id": "a" * 32, "boot_id": str(uuid.uuid4())}
        self.write_spec()

    def write_spec(self):
        self.path.write_text(json.dumps(self.document))

    def journal(self, *, resume=False, host=None):
        self.document["resume"] = resume
        self.write_spec()
        return HostJournal(load_request(self.path), host or self.host)

    def created(self):
        journal = self.journal()
        with journal.writer():
            created = journal.create(time.monotonic() + 30, self.initial())
        return journal, created

    @staticmethod
    def initial():
        return {"phase": "CREATED", "published_ever": False, "begin_attempted": False,
                "channel": None, "logical_bytes": (1 << 32) + 3}

    def assert_code(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_create_cas_resume_binding_and_deadline(self):
        journal = self.journal()
        self.assertFalse(journal.root.exists())
        with journal.writer():
            bad = self.initial()
            bad["phase"] = "COMPLETE"
            self.assert_code("invalid_initial_state", lambda: journal.create(time.monotonic() + 30, bad))
            self.assertFalse(journal.task_dir.exists())
            first = journal.create(time.monotonic() + 30, self.initial())
            self.assertEqual(first["revision"], 0)
            self.assertEqual(first["data"]["logical_bytes"], (1 << 32) + 3)
            first["data"]["logical_bytes"] = 0
            self.assertEqual(journal.load()["data"]["logical_bytes"], (1 << 32) + 3)
            next_data = journal.load()["data"]
            next_data.update(phase="PREPARING", channel="velo", begin_attempted=True)
            next_state = journal.save(0, next_data)
            self.assertEqual(next_state["revision"], 1)
            self.assert_code("stale_revision", lambda: journal.save(0, next_data))
            self.assertEqual(next_state["deadline_monotonic"], journal.load()["deadline_monotonic"])
        self.assert_code("resume_required", lambda: self._attempt_duplicate())
        resumed = self.journal(resume=True)
        with resumed.writer():
            self.assertEqual(resumed.load()["revision"], 1)
        alternate_path = self.root / "alternate.json"
        alternate_path.write_text(self.path.read_text())
        moved = HostJournal(load_request(alternate_path), self.host)
        with moved.writer():
            self.assert_code("task_binding_conflict", moved.load)
        self.document["sources"][0]["relative_path"] = "changed"
        changed_intent = self.journal(resume=True)
        with changed_intent.writer():
            self.assert_code("task_binding_conflict", changed_intent.load)
        self.document["sources"][0]["relative_path"] = "source"
        for key, value in (("vm_epoch", "epoch-2"), ("boot_identity", "boot-2")):
            self.document["expected_vm_identity"][key] = value
            changed = self.journal(resume=True)
            with changed.writer():
                self.assert_code("task_binding_conflict", changed.load)
            self.document["expected_vm_identity"][key] = "epoch-1" if key == "vm_epoch" else "boot-1"
        changed = self.journal(resume=True, host={**self.host, "boot_id": str(uuid.uuid4())})
        with changed.writer():
            self.assert_code("host_identity_mismatch", changed.load)

    def test_oversize_create_and_expired_deadline_remains_readable(self):
        journal = self.journal()
        with journal.writer():
            bad = {**self.initial(), "huge": "x" * journal.limit}
            self.assert_code("state_budget_exceeded", lambda: journal.create(time.monotonic() + 30, bad))
            self.assertFalse(journal.task_dir.exists())
            created = journal.create(time.monotonic() + 0.01, self.initial())
        time.sleep(0.02)
        resumed = self.journal(resume=True)
        with resumed.writer():
            self.assertEqual(resumed.load()["deadline_monotonic"], created["deadline_monotonic"])

    def _attempt_duplicate(self):
        other = self.journal()
        with other.writer():
            other.create(time.monotonic() + 30, self.initial())

    def test_state_invariants_and_evidence(self):
        journal, _ = self.created()
        with journal.writer():
            baseline = journal.load()["data"]
            for change, code in (({"published_ever": 1}, "invalid_journal_data"),
                                 ({"begin_attempted": True}, "invalid_channel"),
                                 ({"channel": "other"}, "invalid_channel"),
                                 ({"phase": "COMPLETE"}, "completion_unproven")):
                candidate = {**baseline, **change}
                self.assert_code(code, lambda c=candidate: journal.save(0, c))
            chosen = {**baseline, "phase": "PUBLISHED", "published_ever": True,
                      "begin_attempted": True, "channel": "velo", "guest_request": {"x": True},
                      "publication_receipt": {"receipt": "fixed"}}
            journal.save(0, chosen)
            for change, code in (({"published_ever": False}, "published_fact_lost"),
                                 ({"begin_attempted": False}, "begin_fact_lost"),
                                 ({"channel": "windows"}, "channel_changed"),
                                 ({"guest_request": {"x": 1}}, "immutable_fact_changed")):
                self.assert_code(code, lambda c={**chosen, **change}: journal.save(1, c))
            done = {**chosen, "phase": "COMPLETE", "completion": {
                "destination_verified": True, "guest_cleanup_complete": True,
                "host_cleanup_complete": True}}
            journal.save(1, done)
            self.assertEqual(journal.load()["data"]["phase"], "COMPLETE")
            evidence = {"schema": "fixture", "size": (1 << 32) + 7}
            ref = journal.write_evidence("manifest", evidence)
            self.assertEqual(ref, journal.write_evidence("manifest", copy.deepcopy(evidence)))
            self.assertEqual(journal.read_evidence(ref), evidence)
            self.assert_code("evidence_conflict", lambda: journal.write_evidence("manifest", {"size": 1}))
            self.assert_code("invalid_evidence_name", lambda: journal.write_evidence("../outside", evidence))
            self.assert_code("invalid_evidence_ref", lambda: journal.read_evidence({**ref, "extra": 1}))
            self.assert_code("invalid_evidence_name", lambda: journal.read_evidence({**ref, "name": "../outside"}))
            self.assert_code("evidence_changed", lambda: journal.read_evidence({**ref, "sha256": "0" * 64}))
            self.assert_code("state_budget_exceeded", lambda: journal.write_evidence("huge", {"x": "x" * 5000}))
            path = journal.task_dir / "evidence" / "manifest.json"
            linked = journal.task_dir / "manifest-alias"
            os.link(path, linked)
            self.assert_code("evidence_file_unsafe", lambda: journal.read_evidence(ref))
            linked.unlink()
            path.write_bytes(b"{}")
            self.assert_code("evidence_changed", lambda: journal.read_evidence(ref))

    def test_filesystem_links_permissions_and_state_corruption(self):
        journal, _ = self.created()
        marker = self.root / "marker"
        marker.write_text("safe")
        with journal.writer():
            journal.root.chmod(0o755)
            self.assert_code("root_unsafe", journal.load)
            journal.root.chmod(0o700)
            journal.task_dir.chmod(0o755)
            self.assert_code("task_unsafe", journal.load)
            journal.task_dir.chmod(0o700)
            lock_alias = journal.root / "lock-alias"
            os.link(journal.lock_path, lock_alias)
            self.assert_code("lock_unsafe", journal.load)
            lock_alias.unlink()
            alias = journal.task_dir / "evidence"
            alias.symlink_to(self.root)
            self.assert_code("evidence_unsafe", lambda: journal.write_evidence("x", {"a": 1}))
            alias.unlink()
            state = journal.state_path
            old = state.read_bytes()
            state.unlink()
            state.symlink_to(marker)
            self.assert_code("state_unsafe", journal.load)
            self.assertEqual(marker.read_text(), "safe")
            state.unlink()
            state.write_bytes(old)
            state.chmod(0o600)
            self.assert_code("state_hash_mismatch", lambda: self._corrupt_state(journal))
        self.assertEqual(marker.read_text(), "safe")

    def test_parent_and_task_replacement_and_strict_state_bytes(self):
        journal, _ = self.created()
        with journal.writer():
            root_held = self.root / "root-held"
            journal.root.rename(root_held)
            journal.root.symlink_to(self.root)
            self.assert_code("root_unsafe", journal.load)
            journal.root.unlink()
            root_held.rename(journal.root)
            tasks_held = journal.root / "tasks-held"
            journal.tasks.rename(tasks_held)
            journal.tasks.symlink_to(self.root)
            self.assert_code("tasks_unsafe", journal.load)
            journal.tasks.unlink()
            tasks_held.rename(journal.tasks)
            task_held = journal.tasks / "held"
            journal.task_dir.rename(task_held)
            journal.task_dir.symlink_to(self.root)
            self.assert_code("task_unsafe", journal.load)
            journal.task_dir.unlink()
            task_held.rename(journal.task_dir)
            state = journal.state_path
            original = state.read_bytes()
            for raw, code in ((original + b"\n", "invalid_state"),
                              (b'{"x":1,"x":2}', "duplicate_state_key"),
                              (b'{"x":1e999}', "invalid_state")):
                state.write_bytes(raw)
                self.assert_code(code, journal.load)
            state.write_bytes(original)
            alias = journal.task_dir / "state-alias"
            os.link(state, alias)
            self.assert_code("state_unsafe", journal.load)
            alias.unlink()
            parent = self.root / "untrusted"
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            child_spec = parent / "request.json"
            child_spec.write_text(self.path.read_text())
            unsafe = HostJournal(load_request(child_spec), self.host)
            self.assert_code("untrusted_ancestor", lambda: self._with_writer(unsafe))

    @staticmethod
    def _corrupt_state(journal):
        path = journal.state_path
        value = json.loads(path.read_text())
        value["data"]["phase"] = "FAILED"
        path.write_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode())
        journal.load()

    def test_writer_lock_process_and_crash_release(self):
        journal = self.journal()
        code = ("import sys,time,os; from velo_transfer.request import load_request; "
                "from velo_transfer.host_journal import HostJournal; "
                "j=HostJournal(load_request(sys.argv[1]), {'machine_id':'a'*32,'boot_id':sys.argv[2]}); "
                "w=j.writer(); w.__enter__(); print('LOCKED', flush=True); "
                "sys.stdin.readline(); os._exit(0)")
        child = subprocess.Popen([sys.executable, "-c", code, str(self.path), self.host["boot_id"]],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, cwd=Path(__file__).resolve().parents[1])
        def close_child():
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(close_child)
        self.assertEqual(child.stdout.readline().strip(), "LOCKED")
        self.assert_code("writer_busy", lambda: self._with_writer(journal))
        child.stdin.write("done\n")
        child.stdin.flush()
        child.wait(timeout=5)
        self.assertEqual(child.returncode, 0)
        with journal.writer():
            journal.create(time.monotonic() + 30, self.initial())
        self.assertEqual(journal.state_path.exists(), True)

    @staticmethod
    def _with_writer(journal):
        with journal.writer():
            pass

    def test_write_faults_preserve_old_or_expose_new(self):
        journal, first = self.created()
        with journal.writer():
            data = {**first["data"], "phase": "PREPARING"}
            with mock.patch("velo_transfer.host_journal.os.fsync", side_effect=OSError("file fsync")):
                self.assert_code("storage_write_failed", lambda: journal.save(0, data))
            self.assertEqual(journal.load()["revision"], 0)
            with mock.patch("velo_transfer.host_journal.os.replace", side_effect=OSError("before replace")):
                self.assert_code("storage_write_failed", lambda: journal.save(0, data))
            self.assertEqual(journal.load()["revision"], 0)
            with mock.patch("velo_transfer.host_journal._sync_directory", side_effect=OSError("post replace")):
                self.assert_code("storage_durability_unknown", lambda: journal.save(0, data))
            self.assertEqual(journal.load()["revision"], 1)
            journal.write_evidence("seed", {"proof": True})
            with mock.patch("velo_transfer.host_journal._sync_directory", side_effect=OSError("evidence sync")):
                self.assert_code("evidence_durability_unknown",
                                 lambda: journal.write_evidence("after-sync", {"proof": True}))
            ref = journal.write_evidence("after-sync", {"proof": True})
            self.assertEqual(journal.read_evidence(ref), {"proof": True})

    def test_state_replacement_after_load_refused(self):
        journal, _ = self.created()
        with journal.writer():
            data = journal.load()["data"]
            replacement = journal.task_dir / "replacement"
            replacement.write_bytes(journal.state_path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, journal.state_path)
            self.assert_code("state_changed", lambda: journal.save(0, data))

    def test_missing_persistent_lock_refused(self):
        journal, _ = self.created()
        journal.lock_path.unlink()
        another = self.journal(resume=True)
        self.assert_code("writer_lock_changed", lambda: self._with_writer(another))

    def test_evidence_collection_is_bounded(self):
        journal, _ = self.created()
        with journal.writer():
            for number in range(journal.max_evidence_files):
                journal.write_evidence(f"item{number}", {"number": number})
            self.assert_code("evidence_collection_exceeded",
                             lambda: journal.write_evidence("overflow", {"number": 999}))
            self.assertEqual(journal.read_evidence(journal.write_evidence("item0", {"number": 0})),
                             {"number": 0})

    def test_host_identity_format(self):
        observed = observe_host_identity()
        self.assertEqual(set(observed), {"machine_id", "boot_id"})
        self.assertEqual(len(observed["machine_id"]), 32)
        with self.assertRaises(Error):
            HostJournal(self.journal().request, {"machine_id": "bad", "boot_id": self.host["boot_id"]})

    def test_chk001_failed_lock_creation_retries_and_first_writer_excludes_peer(self):
        journal = self.journal()
        actual_open = os.open
        def fail_lock(path, *args, **kwargs):
            if Path(path) == journal.lock_path:
                raise OSError("injected lock failure")
            return actual_open(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_journal.os.open", side_effect=fail_lock):
            self.assert_code("writer_lock_unavailable", lambda: self._with_writer(journal))
        self.assertFalse(journal.tasks.exists())
        actual_sync = __import__("velo_transfer.host_journal", fromlist=["_sync_directory"])._sync_directory
        def fail_lock_sync(path):
            if Path(path) == journal.root:
                raise OSError("injected lock directory sync failure")
            return actual_sync(path)
        with mock.patch("velo_transfer.host_journal._sync_directory", side_effect=fail_lock_sync):
            self.assert_code("writer_lock_unavailable", lambda: self._with_writer(journal))
        self.assertFalse(journal.tasks.exists())
        child_code = ("import json,sys,time; from velo_transfer.request import load_request; "
                      "from velo_transfer.host_journal import HostJournal; "
                      "j=HostJournal(load_request(sys.argv[1]),json.loads(sys.argv[2])); "
                      "w=j.writer(); w.__enter__(); print('LOCKED',flush=True); "
                      "sys.stdin.readline(); w.__exit__(None,None,None)")
        child = subprocess.Popen([sys.executable, "-c", child_code, str(self.path), json.dumps(self.host)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, cwd=Path(__file__).resolve().parents[1])
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            self.assert_code("writer_busy", lambda: self._with_writer(self.journal()))
            child.stdin.write("release\n")
            child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)
            with self.journal().writer():
                pass
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()

    def test_chk002_crash_before_after_atomic_state_and_evidence_publish(self):
        code = ("import json,os,sys,time; from unittest import mock; "
                "from velo_transfer.request import load_request; "
                "from velo_transfer.host_journal import HostJournal; "
                "from velo_transfer import host_journal as m; "
                "j=HostJournal(load_request(sys.argv[1]),json.loads(sys.argv[2])); "
                "real=m._rename_noreplace; "
                "before=lambda src,dst: os._exit(77); "
                "after=lambda src,dst: (real(src,dst),os._exit(77)); "
                "hook=before if sys.argv[4]=='before' else after; "
                "w=j.writer(); w.__enter__(); "
                "p=mock.patch.object(m,'_rename_noreplace',side_effect=hook); p.__enter__(); "
                "j.create(time.monotonic()+30,{'phase':'CREATED','published_ever':False,'begin_attempted':False,'channel':None}) "
                "if sys.argv[3]=='state' else j.write_evidence('proof',{'proof':True})")
        # The child uses a real no-replace rename and exits immediately on either side.
        for kind in ("state", "evidence"):
            for moment in ("before", "after"):
                with self.subTest(kind=kind, moment=moment):
                    fresh = self.root / f"{kind}-{moment}"
                    fresh.mkdir(mode=0o700)
                    spec = fresh / "request.json"
                    document = copy.deepcopy(self.document)
                    document["transfer_id"] = f"{kind}-{moment}"
                    if kind == "evidence":
                        spec.write_text(json.dumps(document))
                        prepared = HostJournal(load_request(spec), self.host)
                        with prepared.writer():
                            prepared.create(time.monotonic() + 30, self.initial())
                        document["resume"] = True
                    spec.write_text(json.dumps(document))
                    child = subprocess.run([sys.executable, "-c", code, str(spec), json.dumps(self.host),
                                            kind, moment], cwd=Path(__file__).resolve().parents[1],
                                           capture_output=True, text=True, timeout=5)
                    self.assertEqual(child.returncode, 77, child.stderr)
                    resumed = HostJournal(load_request(spec if kind == "evidence" else
                                                       self._resume_spec(spec, document)), self.host)
                    with resumed.writer():
                        if kind == "state" and moment == "before":
                            self.assert_code("task_incomplete", resumed.load)
                        elif kind == "state":
                            self.assertEqual(resumed.load()["revision"], 0)
                            self.assertEqual(resumed.state_path.stat().st_nlink, 1)
                        elif moment == "before":
                            self.assertFalse((resumed.task_dir / "evidence" / "proof.json").exists())
                        else:
                            ref = resumed.write_evidence("proof", {"proof": True})
                            self.assertEqual(resumed.read_evidence(ref), {"proof": True})
                            self.assertEqual((resumed.task_dir / "evidence" / "proof.json").stat().st_nlink, 1)

    @staticmethod
    def _resume_spec(spec, document):
        document["resume"] = True
        spec.write_text(json.dumps(document))
        return spec

    def test_chk003_replaced_temporary_never_published(self):
        for kind in ("create", "save", "evidence"):
            with self.subTest(kind=kind):
                self.document["transfer_id"] = "task-" + kind
                journal = self.journal() if kind == "create" else self.created()[0]
                with journal.writer():
                    original = journal._require_writer
                    replaced = []
                    def swap(**kwargs):
                        original(**kwargs)
                        folder = journal.task_dir if kind != "evidence" else journal.task_dir / "evidence"
                        pattern = ".state-*.tmp" if kind != "evidence" else ".evidence-*.tmp"
                        for path in folder.glob(pattern):
                            if not replaced:
                                held = path.with_suffix(".held")
                                path.rename(held)
                                path.write_bytes(b'{"replacement":true}')
                                path.chmod(0o600)
                                replaced.append((path, held))
                    with mock.patch.object(journal, "_require_writer", side_effect=swap):
                        if kind == "create":
                            self.assert_code("storage_reconcile_required",
                                             lambda: journal.create(time.monotonic() + 30, self.initial()))
                        elif kind == "save":
                            self.assert_code("storage_write_failed",
                                             lambda: journal.save(0, {**self.initial(), "phase": "PREPARING"}))
                        else:
                            self.assert_code("temporary_changed",
                                             lambda: journal.write_evidence("proof", {"proof": True}))
                    self.assertEqual(len(replaced), 1)
                    self.assertEqual(replaced[0][0].read_bytes(), b'{"replacement":true}')
                    if kind == "create":
                        self.assertFalse(journal.state_path.exists())
                    elif kind == "save":
                        self.assertEqual(journal.load()["revision"], 0)
                    else:
                        self.assertFalse((journal.task_dir / "evidence" / "proof.json").exists())

    def test_chk004_extreme_deadline_stable_rejection(self):
        journal = self.journal()
        with journal.writer():
            self.assert_code("invalid_deadline", lambda: journal.create(10 ** 400, self.initial()))
            self.assertFalse(journal.task_dir.exists())
            journal.create(time.monotonic() + 30, self.initial())
            value = journal.load()
            value["deadline_monotonic"] = 10 ** 400
            value["sha256"] = digest_json({k: v for k, v in value.items() if k != "sha256"})
            journal.state_path.write_bytes(canonical_json(value))
            self.assert_code("invalid_state", journal.load)

    def test_chk002_existing_evidence_retry_syncs_before_ack(self):
        journal, _ = self.created()
        with journal.writer():
            ref = journal.write_evidence("proof", {"proof": True})
            with mock.patch("velo_transfer.host_journal._sync_directory", side_effect=OSError("sync")):
                self.assert_code("evidence_durability_unknown",
                                 lambda: journal.write_evidence("proof", {"proof": True}))
            self.assertEqual(ref, journal.write_evidence("proof", {"proof": True}))


if __name__ == "__main__":
    unittest.main()

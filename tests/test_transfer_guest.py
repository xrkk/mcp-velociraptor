"""Isolated benign Linux filesystem tests for the guest boundary."""

import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer import (Budget, capture_sources, create_bundle, prepare_staging,
                           unpack_bundle, publish_directory)
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer import guest_service as guest_module
from velo_transfer.guest_cli import invoke
from velo_transfer.protocol import publication_receipt, source_validation_receipt
from velo_transfer.windows_platform import WindowsObservation


class GuestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.read = self.root / "read"
        self.read2 = self.root / "read2"
        self.write = self.root / "write"
        self.work = self.root / "work"
        self.host = self.root / "host"
        for path in (self.read, self.read2, self.write, self.work, self.host):
            path.mkdir(mode=0o700)
        self.uuid = str(uuid.uuid4())
        self.observation = WindowsObservation("Windows", self.uuid, "boot-fixture")
        self.limits = {"max_files": 100, "max_metadata_bytes": 100000,
                       "max_logical_bytes": 12 * 1024 * 1024,
                       "max_package_bytes": 14 * 1024 * 1024,
                       "min_free_bytes": 0, "max_chunk_bytes": 1 << 20,
                       "max_state_bytes": 65536, "max_duration_seconds": 60}
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": "velo.transfer.policy.v1",
            "policy_id": "fixture", "expected_vm_uuid": self.uuid,
            "read_roots": [str(self.read), str(self.read2)],
            "write_roots": [str(self.write)], "work_root": str(self.work),
            "limits": self.limits}))
        self.policy.chmod(0o600)
        self.service = GuestTransferService(self.policy, _observation=self.observation,
                                            _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)

    def budget(self):
        return Budget(100, 100000, 12 * 1024 * 1024, 14 * 1024 * 1024, 0,
                      time.monotonic() + 60)

    def request(self, direction, sources, destination, package=None, transfer_id="trial"):
        value = {"protocol_version": "velo.transfer.v1", "transfer_id": transfer_id,
            "direction": direction, "sources": sources,
            "expected_destination": {"endpoint": "host" if direction == "pull" else "guest",
                "identity": {"test": "local"}, "canonical_path": str(destination)},
            "expected_vm_identity": {"vm_uuid": self.uuid, "boot_identity": "boot-fixture",
                                     "vm_epoch": "fixture-epoch"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["fixture-producer-record"]},
            "budget": {key: self.limits[key] for key in ("max_files", "max_metadata_bytes",
                "max_logical_bytes", "max_package_bytes", "min_free_bytes",
                "max_chunk_bytes", "max_duration_seconds")}}
        if package is not None:
            value["package"] = package
        value["request_digest"] = request_digest(value)
        return value

    def wait_phase(self, req, phase):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status = self.service.transfer_status(req["transfer_id"], req["request_digest"])
            if status["local_phase"] == phase and status["worker"] and status["worker"]["stopped"]:
                return status
            if status["error"] and status["local_phase"] != phase:
                self.fail(f"worker failed: {status['error']}")
            time.sleep(0.02)
        self.fail(f"worker did not reach {phase}: {status}")

    def test_pull_full_release_multiple_roots(self):
        (self.read / "empty").mkdir()
        (self.read / "零.txt").write_bytes(b"")
        (self.read2 / "nested").mkdir()
        data = os.urandom(8 * 1024 * 1024)
        (self.read2 / "nested" / "random.bin").write_bytes(data)
        sources = [{"absolute_path": str(self.read / "empty"), "relative_path": "one/empty"},
                   {"absolute_path": str(self.read / "零.txt"), "relative_path": "one/零.txt"},
                   {"absolute_path": str(self.read2 / "nested"), "relative_path": "two/nested"}]
        destination = self.host / "delivered"
        req = self.request("pull", sources, destination)
        self.assertEqual(self.service.transfer_begin(req)["local_phase"], "SOURCE_PREPARING")
        ready = self.wait_phase(req, "SOURCE_READY")
        self.assertEqual(self.service.transfer_begin(req)["package"], ready["package"])
        package = self.host / "received.zip"
        with package.open("wb") as output:
            for offset in range(0, ready["package"]["size"], 1 << 20):
                count = min(1 << 20, ready["package"]["size"] - offset)
                part = self.service.transfer_chunk("trial", req["request_digest"], offset, count)
                raw = base64.b64decode(part["data_base64"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), part["chunk_sha256"])
                output.write(raw)
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "SOURCE_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        staging = prepare_staging(destination, self.host, self.budget(), stage_name=".velo-stage-host",
                                  register_stage=lambda path, identity, parent: True)
        extracted = unpack_bundle(package, self.host, ready["package"]["size"],
            ready["package"]["sha256"], destination, self.host, self.budget(), staging=staging)
        publish_directory(staging["staging_directory"], destination, self.host,
            extracted["manifest"], self.budget(),
            expected_staging_identity=staging["staging_identity"],
            expected_parent_identity=staging["parent_identity"])
        publication = publication_receipt(receipt["binding"], receipt, req["expected_destination"],
                                          staging["staging_identity"])
        self.service.transfer_finish("trial", req["request_digest"], "release",
            prepare_receipt=receipt, publication_receipt=publication)
        released = self.wait_phase(req, "SOURCE_RELEASED")
        self.assertEqual(released["terminal"]["publication_receipt"], publication)
        self.assertEqual((destination / "two" / "nested" / "random.bin").read_bytes(), data)
        self.assertEqual((destination / "one" / "零.txt").read_bytes(), b"")
        self.assertTrue((destination / "one" / "empty").is_dir())
        self.assertTrue((self.read2 / "nested" / "random.bin").exists())
        self.assertFalse((self.work / "tasks" / "trial" / "bundle.zip").exists())
        replay = self.service.transfer_finish("trial", req["request_digest"], "release",
            prepare_receipt=receipt, publication_receipt=publication)
        self.assertEqual(replay["operation"]["status"], "DONE")
        for target, path, value in (
                ("prepare", ("prepare_id",), "changed"),
                ("publication", ("publication_id",), "changed"),
                ("publication", ("manifest_sha256",), "0" * 64),
                ("publication", ("destination", "canonical_path"), str(self.host / "other")),
                ("publication", ("binding", "vm_epoch"), "changed"),
                ("publication", ("binding", "package_sha256"), "0" * 64)):
            changed_prepare = json.loads(json.dumps(receipt))
            changed_publication = json.loads(json.dumps(publication))
            changed = changed_prepare if target == "prepare" else changed_publication
            for key in path[:-1]:
                changed = changed[key]
            changed[path[-1]] = value
            with self.assertRaises(Error):
                self.service.transfer_finish("trial", req["request_digest"], "release",
                    prepare_receipt=changed_prepare, publication_receipt=changed_publication)
            self.assertEqual(self.service.transfer_status("trial", req["request_digest"]), released)

    def test_push_full_release_and_replay(self):
        source = self.host / "source"
        source.mkdir()
        (source / "empty").mkdir()
        (source / "文件.txt").write_bytes(b"benign")
        random_bytes = os.urandom(8 * 1024 * 1024)
        (source / "random.bin").write_bytes(random_bytes)
        specs = [{"absolute_path": str(source), "relative_path": "batch"}]
        manifest = capture_sources(source, specs, self.budget(), ["fixture"])
        bundle = self.host / "bundle.zip"
        package = create_bundle(source, specs, manifest, bundle, self.host, self.budget())
        metadata = {key: package[key] for key in ("size", "sha256", "manifest_sha256")}
        destination = self.write / "delivered"
        req = self.request("push", specs, destination, metadata)
        self.assertEqual(self.service.transfer_begin(req)["local_phase"], "DEST_RECEIVING")
        raw = bundle.read_bytes()
        for offset in range(0, len(raw), 1 << 20):
            chunk = raw[offset:offset + (1 << 20)]
            self.service.transfer_chunk("trial", req["request_digest"], offset, len(chunk),
                base64.b64encode(chunk).decode(), hashlib.sha256(chunk).hexdigest())
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "DEST_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        source_receipt = source_validation_receipt(receipt["binding"], receipt,
                                                   hashlib.sha256(b"fixture").hexdigest())
        self.service.transfer_finish("trial", req["request_digest"], "commit",
            prepare_receipt=receipt, source_validation_receipt=source_receipt)
        published = self.wait_phase(req, "DEST_PUBLISHED")
        publication = published["terminal"]["publication_receipt"]
        self.service.transfer_finish("trial", req["request_digest"], "release",
            prepare_receipt=receipt, publication_receipt=publication)
        released = self.wait_phase(req, "DEST_RELEASED")
        self.assertEqual((destination / "batch" / "文件.txt").read_bytes(), b"benign")
        self.assertEqual((destination / "batch" / "random.bin").read_bytes(), random_bytes)
        self.assertTrue((destination / "batch" / "empty").is_dir())
        self.assertEqual(released["terminal"]["publication_receipt"], publication)
        replay = self.service.transfer_finish("trial", req["request_digest"], "commit",
            prepare_receipt=receipt, source_validation_receipt=source_receipt)
        self.assertEqual(replay["operation"]["status"], "DONE")

    def test_corrupt_partial_and_wrong_chunk_do_not_advance(self):
        source = self.host / "source.bin"
        source.write_bytes(os.urandom(4096))
        specs = [{"absolute_path": str(source), "relative_path": "source.bin"}]
        manifest = capture_sources(self.host, specs, self.budget())
        bundle = self.host / "bundle.zip"
        package = create_bundle(self.host, specs, manifest, bundle, self.host, self.budget())
        req = self.request("push", specs, self.write / "final",
            {key: package[key] for key in ("size", "sha256", "manifest_sha256")})
        self.service.transfer_begin(req)
        raw = bundle.read_bytes()
        first = raw[:100]
        encoded = base64.b64encode(first).decode()
        digest = hashlib.sha256(first).hexdigest()
        self.service.transfer_chunk("trial", req["request_digest"], 0, 100, encoded, digest)
        self.assertTrue(self.service.transfer_chunk("trial", req["request_digest"], 0, 100,
            encoded, digest)["replayed"])
        for offset, data, sha in ((101, first, digest),
                                  (100, first, "0" * 64),
                                  (0, b"x" * 100, hashlib.sha256(b"x" * 100).hexdigest())):
            with self.assertRaises(Error):
                self.service.transfer_chunk("trial", req["request_digest"], offset,
                    len(data), base64.b64encode(data).decode(), sha)
        self.assertEqual(self.service.transfer_status("trial", req["request_digest"])["verified_offset"], 100)
        partial = self.work / "tasks" / "trial" / "received.part"
        with partial.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"X")
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunk("trial", req["request_digest"], 100, 1,
                base64.b64encode(raw[100:101]).decode(), hashlib.sha256(raw[100:101]).hexdigest())
        self.assertEqual(caught.exception.code, "partial_corrupt")

    def test_fresh_helpers_use_persisted_chunk_identity_and_reverify_change(self):
        raw = b"benign01" * 1024
        req = self.request("push", [{"absolute_path": "/opaque/host",
            "relative_path": "benign.bin"}], self.write / "final", {
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "manifest_sha256": "0" * 64})
        self.service.transfer_begin(req)
        parsed = []
        original = guest_module._strict_json
        def count_records(raw_json, maximum):
            result = original(raw_json, maximum)
            if isinstance(result, dict) and set(result) == {"offset", "count", "sha256"}:
                parsed.append(result["offset"])
            return result
        with mock.patch.object(guest_module, "_strict_json", side_effect=count_records):
            for offset in range(0, len(raw), 1024):
                instance = GuestTransferService(self.policy, _observation=self.observation,
                                                _acl_verifier=lambda path, kind: True)
                chunk = raw[offset:offset + 1024]
                instance.transfer_chunk("trial", req["request_digest"], offset, len(chunk),
                    base64.b64encode(chunk).decode(), hashlib.sha256(chunk).hexdigest())
        self.assertLessEqual(len(parsed), 1)
        partial = self.work / "tasks" / "trial" / "received.part"
        ledger = self.work / "tasks" / "trial" / "chunks.jsonl"
        with partial.open("ab") as stream:
            stream.write(b"unacknowledged")
        with ledger.open("ab") as stream:
            stream.write(b"unacknowledged\n")
        instance = GuestTransferService(self.policy, _observation=self.observation,
                                        _acl_verifier=lambda path, kind: True)
        instance._verified_partial(instance._load("trial", req["request_digest"])["state"])
        self.assertEqual(partial.stat().st_size, len(raw))
        self.assertEqual(len(ledger.read_text().splitlines()), 8)
        with partial.open("r+b") as stream:
            stream.write(b"X")
        with self.assertRaises(Error) as caught:
            instance._verified_partial(instance._load("trial", req["request_digest"])["state"])
        self.assertEqual(caught.exception.code, "partial_corrupt")

    def test_pull_release_replays_after_owned_bundle_deleted(self):
        source = self.read / "source.txt"
        source.write_bytes(b"before")
        req = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "published")
        self.service.transfer_begin(req)
        self.wait_phase(req, "SOURCE_READY")
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "SOURCE_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        publication = publication_receipt(receipt["binding"], receipt,
            req["expected_destination"], {"device": 1, "inode": 2})
        with mock.patch.object(self.service, "_launch"):
            self.service.transfer_finish("trial", req["request_digest"], "release",
                prepare_receipt=receipt, publication_receipt=publication)
        envelope = self.service._load("trial", req["request_digest"])
        self.service._release(envelope, self.service._budget(envelope["state"]))
        self.assertFalse((self.work / "tasks" / "trial" / "bundle.zip").exists())
        source.write_bytes(b"after")
        fresh = self.service._load("trial", req["request_digest"])
        self.service._release(fresh, self.service._budget(fresh["state"]))
        state = self.service._load("trial", req["request_digest"])["state"]
        self.assertIsNotNone(state["terminal"]["release_authorization"])
        self.assertEqual(state["phase"], "SOURCE_RELEASING")

    def test_push_release_replays_after_first_owned_file_deleted(self):
        source = self.host / "source.txt"
        source.write_bytes(b"benign")
        specs = [{"absolute_path": str(source), "relative_path": "source.txt"}]
        manifest = capture_sources(self.host, specs, self.budget())
        bundle = self.host / "bundle.zip"
        package = create_bundle(self.host, specs, manifest, bundle, self.host, self.budget())
        req = self.request("push", specs, self.write / "published",
            {key: package[key] for key in ("size", "sha256", "manifest_sha256")})
        self.service.transfer_begin(req)
        raw = bundle.read_bytes()
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(raw),
            base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        receipt = self.wait_phase(req, "DEST_PREPARED")["terminal"]["prepare_receipt"]
        validation = source_validation_receipt(receipt["binding"], receipt,
            hashlib.sha256(b"fixture").hexdigest())
        self.service.transfer_finish("trial", req["request_digest"], "commit",
            prepare_receipt=receipt, source_validation_receipt=validation)
        publication = self.wait_phase(req, "DEST_PUBLISHED")["terminal"]["publication_receipt"]
        with mock.patch.object(self.service, "_launch"):
            self.service.transfer_finish("trial", req["request_digest"], "release",
                prepare_receipt=receipt, publication_receipt=publication)
        original = self.service._remove_owned_temporary
        calls = []
        def fail_after_first(state, name):
            original(state, name)
            calls.append(name)
            raise Error("injected_cleanup_crash")
        envelope = self.service._load("trial", req["request_digest"])
        with mock.patch.object(self.service, "_remove_owned_temporary", side_effect=fail_after_first):
            with self.assertRaises(Error):
                self.service._release(envelope, self.service._budget(envelope["state"]))
        self.assertEqual(calls, ["received.part"])
        self.assertFalse((self.work / "tasks" / "trial" / "received.part").exists())
        self.assertTrue((self.work / "tasks" / "trial" / "chunks.jsonl").exists())
        fresh = self.service._load("trial", req["request_digest"])
        original_save = self.service._save
        def fail_after_second_delete(store, envelope, state):
            if state["phase"] == "DEST_RELEASING" and state["cleanup"] is not None:
                raise Error("injected_cleanup_state_loss")
            return original_save(store, envelope, state)
        with mock.patch.object(self.service, "_save", side_effect=fail_after_second_delete):
            with self.assertRaises(Error):
                self.service._release(fresh, self.service._budget(fresh["state"]))
        self.assertFalse((self.work / "tasks" / "trial" / "chunks.jsonl").exists())
        fresh = self.service._load("trial", req["request_digest"])
        self.service._release(fresh, self.service._budget(fresh["state"]))
        self.assertEqual((self.write / "published" / "source.txt").read_bytes(), b"benign")

    def test_release_phase_waits_for_worker_exit(self):
        source = self.read / "source.txt"
        source.write_bytes(b"before")
        req = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "published")
        self.service.transfer_begin(req)
        self.wait_phase(req, "SOURCE_READY")
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        receipt = self.wait_phase(req, "SOURCE_PREPARED")["terminal"]["prepare_receipt"]
        publication = publication_receipt(receipt["binding"], receipt,
            req["expected_destination"], {"device": 1, "inode": 2})
        original = self.service._release
        marker = self.root / "release-paused"
        def pause(envelope, budget):
            original(envelope, budget)
            marker.write_text("alive")
            time.sleep(0.5)
        with mock.patch.object(self.service, "_release", side_effect=pause):
            self.service.transfer_finish("trial", req["request_digest"], "release",
                prepare_receipt=receipt, publication_receipt=publication)
        until = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue(marker.exists())
        status = self.service.transfer_status("trial", req["request_digest"])
        self.assertEqual(status["local_phase"], "SOURCE_RELEASING")
        self.assertFalse(status["cleanup"]["workers_stopped"])
        self.wait_phase(req, "SOURCE_RELEASED")

    def test_release_tombstone_write_loss_recovers_on_status(self):
        source = self.read / "source.txt"
        source.write_bytes(b"before")
        req = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "published")
        self.service.transfer_begin(req)
        self.wait_phase(req, "SOURCE_READY")
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        receipt = self.wait_phase(req, "SOURCE_PREPARED")["terminal"]["prepare_receipt"]
        publication = publication_receipt(receipt["binding"], receipt,
            req["expected_destination"], {"device": 1, "inode": 2})
        self.service.transfer_finish("trial", req["request_digest"], "release",
            prepare_receipt=receipt, publication_receipt=publication)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            state = self.service._load("trial", req["request_digest"])["state"]
            owner = state["owner"]
            if owner and not guest_module.same_process(owner["pid"], owner["birth"]):
                break
            time.sleep(0.01)
        else:
            self.fail("release worker did not exit")
        original = self.service._save
        def fail_terminal(store, envelope, state):
            if state["phase"] == "SOURCE_RELEASED":
                raise Error("injected_tombstone_loss")
            return original(store, envelope, state)
        with mock.patch.object(self.service, "_save", side_effect=fail_terminal):
            with self.assertRaises(Error):
                self.service.transfer_status("trial", req["request_digest"])
        state = self.service._load("trial", req["request_digest"])["state"]
        self.assertEqual(state["phase"], "SOURCE_RELEASING")
        self.assertEqual(self.service.transfer_status("trial", req["request_digest"])["local_phase"],
                         "SOURCE_RELEASED")

    @unittest.skipUnless(os.name == "posix", "POSIX sparse-file fixture")
    def test_sparse_unacknowledged_tail_above_32bit_is_bounded(self):
        import resource
        req = self.request("push", [{"absolute_path": "/opaque/host",
            "relative_path": "benign.bin"}], self.write / "final", {
            "size": 1, "sha256": hashlib.sha256(b"x").hexdigest(),
            "manifest_sha256": "0" * 64})
        self.service.transfer_begin(req)
        state = self.service._load("trial", req["request_digest"])["state"]
        partial, ledger = self.service._ledger_paths(state)
        partial.write_bytes(b"")
        ledger.write_bytes(b"")
        with partial.open("r+b") as stream:
            stream.seek((1 << 32) + 7)
            stream.write(b"x")
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.service._verified_partial(state)
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.assertEqual(partial.stat().st_size, 0)
        self.assertLess(after - before, 32 * 1024)

    def test_changed_pull_source_before_release_keeps_package(self):
        source = self.read / "source.txt"
        source.write_bytes(b"first")
        specs = [{"absolute_path": str(source), "relative_path": "source.txt"}]
        req = self.request("pull", specs, self.host / "published")
        self.service.transfer_begin(req)
        self.wait_phase(req, "SOURCE_READY")
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "SOURCE_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        publication = publication_receipt(receipt["binding"], receipt,
            req["expected_destination"], {"device": 1, "inode": 2})
        wrong = json.loads(json.dumps(publication))
        wrong["binding"]["vm_epoch"] = "other-epoch"
        with self.assertRaises(Error):
            self.service.transfer_finish("trial", req["request_digest"], "release",
                prepare_receipt=receipt, publication_receipt=wrong)
        self.assertEqual(self.service.transfer_status("trial", req["request_digest"])["local_phase"],
                         "SOURCE_PREPARED")
        source.write_bytes(b"changed")
        self.service.transfer_finish("trial", req["request_digest"], "release",
            prepare_receipt=receipt, publication_receipt=publication)
        changed = self.wait_phase(req, "SOURCE_CHANGED")
        self.assertEqual(changed["error"], "source_changed")
        self.assertTrue((self.work / "tasks" / "trial" / "bundle.zip").exists())

    def test_request_schema_and_explicit_root(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"benign")
        req = self.request("pull", [{"absolute_path": str(outside),
            "relative_path": "outside.txt"}], self.host / "out")
        with self.assertRaises(Error) as caught:
            self.service.transfer_begin(req)
        self.assertEqual(caught.exception.code, "path_outside_root")
        self.assertFalse((self.work / "tasks").exists())
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        req = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "out")
        req["extra"] = True
        with self.assertRaises(Error):
            self.service.transfer_begin(req)
        self.assertFalse((self.work / "tasks").exists())

    def test_disabled_invalid_policy_and_identity_drift(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            disabled = GuestTransferService(_observation=self.observation,
                _acl_verifier=lambda path, kind: True)
        self.assertFalse(disabled.transfer_capabilities()["enabled"])
        with self.assertRaises(Error):
            disabled.transfer_begin({})
        with self.assertRaises(Error):
            GuestTransferService(self.root / "missing-policy.json",
                _observation=self.observation, _acl_verifier=lambda path, kind: True)
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        req = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "out")
        self.service._test_observation = WindowsObservation("Windows", self.uuid, "new-boot")
        with self.assertRaises(Error) as caught:
            self.service.transfer_begin(req)
        self.assertEqual(caught.exception.code, "vm_identity_mismatch")
        self.assertFalse((self.work / "tasks").exists())

    def test_fixed_helper_request_root_and_json_guards(self):
        requests = self.work / "requests"
        requests.mkdir(mode=0o700)
        valid = requests / "valid.json"
        valid.write_text(json.dumps({"operation": "transfer_capabilities", "arguments": {}}))
        valid.chmod(0o600)
        self.assertTrue(invoke(str(valid), self.service)["enabled"])
        for raw in (b'{"operation":"unknown","arguments":{}}',
                    b'{"operation":"transfer_capabilities","arguments":{},"arguments":{}}',
                    b'{"operation":"transfer_capabilities","arguments":'):
            valid.write_bytes(raw)
            with self.assertRaises(Error):
                invoke(str(valid), self.service)
        valid.write_bytes(b"{" + b"x" * (4 * 1024 * 1024))
        with self.assertRaises(Error) as caught:
            invoke(str(valid), self.service)
        self.assertEqual(caught.exception.code, "request_too_large")
        outside = self.work / "outside.json"
        outside.write_text(json.dumps({"operation": "transfer_capabilities", "arguments": {}}))
        outside.chmod(0o600)
        with self.assertRaises(Error) as caught:
            invoke(str(outside), self.service)
        self.assertEqual(caught.exception.code, "request_path_outside_root")

    def test_commit_recovers_real_rename_after_lost_receipt(self):
        source = self.host / "source.txt"
        source.write_bytes(b"recovery")
        specs = [{"absolute_path": str(source), "relative_path": "source.txt"}]
        manifest = capture_sources(self.host, specs, self.budget())
        bundle = self.host / "bundle.zip"
        package = create_bundle(self.host, specs, manifest, bundle, self.host, self.budget())
        metadata = {key: package[key] for key in ("size", "sha256", "manifest_sha256")}
        destination = self.write / "published"
        req = self.request("push", specs, destination, metadata)
        self.service.transfer_begin(req)
        raw = bundle.read_bytes()
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(raw),
            base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "DEST_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        validation = source_validation_receipt(receipt["binding"], receipt,
                                               hashlib.sha256(b"source").hexdigest())
        original = guest_module.publish_directory
        def publish_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise Error("injected_after_rename")
        with mock.patch.object(guest_module, "publish_directory", publish_then_fail):
            self.service.transfer_finish("trial", req["request_digest"], "commit",
                prepare_receipt=receipt, source_validation_receipt=validation)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status = self.service.transfer_status("trial", req["request_digest"])
                if status["worker"]["stopped"]:
                    break
                time.sleep(0.02)
            else:
                self.fail("fault-injected worker did not stop")
        self.assertEqual(status["error"], "injected_after_rename")
        self.assertEqual(status["terminal"]["operations"]["commit"]["status"], "IN_PROGRESS")
        self.assertTrue(destination.is_dir())
        self.service.transfer_finish("trial", req["request_digest"], "commit",
            prepare_receipt=receipt, source_validation_receipt=validation)
        recovered = self.wait_phase(req, "DEST_PUBLISHED")
        self.assertEqual(recovered["terminal"]["operations"]["commit"]["status"], "DONE")
        self.assertEqual((destination / "source.txt").read_bytes(), b"recovery")

    def test_registered_partial_stage_is_reextracted(self):
        source = self.host / "source.txt"
        source.write_bytes(b"retry-stage")
        specs = [{"absolute_path": str(source), "relative_path": "source.txt"}]
        manifest = capture_sources(self.host, specs, self.budget())
        bundle = self.host / "bundle.zip"
        package = create_bundle(self.host, specs, manifest, bundle, self.host, self.budget())
        metadata = {key: package[key] for key in ("size", "sha256", "manifest_sha256")}
        req = self.request("push", specs, self.write / "final", metadata)
        self.service.transfer_begin(req)
        raw = bundle.read_bytes()
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(raw),
            base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest())
        def leave_partial(*args, **kwargs):
            stage = Path(kwargs["staging"]["staging_directory"])
            (stage / "partial.txt").write_bytes(b"partial")
            raise Error("injected_partial_extract")
        with mock.patch.object(guest_module, "unpack_bundle", leave_partial):
            self.service.transfer_finish("trial", req["request_digest"], "prepare")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status = self.service.transfer_status("trial", req["request_digest"])
                if status["worker"]["stopped"]:
                    break
                time.sleep(0.02)
            else:
                self.fail("fault-injected stage worker did not stop")
        self.assertEqual(status["terminal"]["operations"]["prepare"]["status"], "IN_PROGRESS")
        self.service.transfer_finish("trial", req["request_digest"], "prepare")
        prepared = self.wait_phase(req, "DEST_PREPARED")
        self.assertIsNotNone(prepared["terminal"]["prepare_receipt"])
        stage = self.write / (".velo-stage-" + hashlib.sha256(b"trial").hexdigest()[:32])
        self.assertFalse((stage / "partial.txt").exists())
        self.assertEqual((stage / "source.txt").read_bytes(), b"retry-stage")


if __name__ == "__main__":
    unittest.main()

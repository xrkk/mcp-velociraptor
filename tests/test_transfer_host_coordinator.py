"""Benign host coordinator integration and fault-boundary tests."""

import asyncio
import base64
import copy
import hashlib
import json
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import asynccontextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

from velo_transfer.adapters import AdapterError, select_adapter
from velo_transfer.bundle import create_bundle
from velo_transfer.host_coordinator import TransferCoordinator
from velo_transfer.host_journal import HostJournal
from velo_transfer.manifest import Budget, capture_sources, digest_json
from velo_transfer.protocol import (GuestTerminal, prepare_receipt,
                                    publication_receipt, receipt_digest)
from velo_transfer.request import load_request
from velo_transfer.__main__ import main as cli_main
from velo_transfer.errors import TransferContentError
from velo_transfer.connection import ConnectionError
from velo_transfer import host_publication


class LocalPeer:
    """Only the remote guest is simulated; host files and journal are real."""

    def __init__(self, fixture, direction):
        self.fixture = fixture
        self.direction = direction
        self.channel = "velo"
        self.fallback_reason = None
        self.raw_chunk_bytes = 128
        self.batch_chunks = 1
        self.observations = {**fixture.vm, "policy_id": "fixture-policy",
                             "build": "guest-engine-v1", "protocol_version": "velo.transfer.v1"}
        self.trace = []
        self.counts = {}
        self.faults = {}
        self.request = None
        self.terminal = None
        self.binding = None
        self.package = None
        self.package_path = None
        self.received = bytearray()
        self.offset = 0
        self.worker = None
        self.proof = None
        self.prefix_proof = None
        self.chunk_records = []
        self.aborted = False
        self.on_finish = None
        self.on_status = None
        self.probe_error = None
        if direction == "pull":
            budget = Budget(100, 200000, 1 << 20, 1 << 20, 0, time.monotonic() + 90)
            sources = [{"absolute_path": str(fixture.source), "relative_path": "payload"}]
            manifest = capture_sources(fixture.root, sources, budget, ["producer-ref"])
            self.package_path = fixture.root / "remote-package.zip"
            built = create_bundle(fixture.root, sources, manifest, self.package_path, fixture.root, budget)
            self.package = {key: built[key] for key in ("size", "sha256", "manifest_sha256")}

    def fail(self, operation, *, action=None, nth=1, when="before", error=None):
        self.faults[(operation, action, nth)] = (when, error or AdapterError("outcome_unknown", may_have_committed=True))

    def _fault(self, key, when):
        specified = self.faults.get((*key, self.counts[key]))
        if specified is not None and specified[0] == when:
            raise specified[1]

    def status(self):
        terminal = self.terminal
        response = {"schema": "velo.transfer.guest.response.v1",
                "state_scope": "guest_source" if self.direction == "pull" else "guest_destination",
                "local_phase": terminal.local_phase if terminal else "DEST_RECEIVING",
                "transfer_id": self.request["transfer_id"],
                "request_digest": self.request["request_digest"],
                "package": copy.deepcopy(self.package), "verified_offset": self.offset,
                "terminal": terminal.snapshot() if terminal else None,
                "cleanup": {"temporary_files_removed": True, "workers_stopped": True}
                           if terminal and terminal.local_phase.endswith("RELEASED") else None,
                "destination_verification": copy.deepcopy(self.proof),
                "error": None, "worker": copy.deepcopy(self.worker),
                "prefix_verification": copy.deepcopy(self.prefix_proof)}
        if self.on_status is not None:
            return self.on_status(response)
        return response

    async def probe(self, _expected_identity):
        if self.probe_error is not None:
            raise AdapterError(self.probe_error)

    async def call(self, operation, arguments):
        action = arguments.get("action") if operation == "transfer_finish" else None
        key = (operation, action)
        self.counts[key] = self.counts.get(key, 0) + 1
        self.trace.append((operation, copy.deepcopy(arguments)))
        self._fault(key, "before")
        if operation == "transfer_begin":
            resume = self.request is not None
            self.request = copy.deepcopy(arguments["request"])
            self.package = self.request.get("package", self.package)
            self.binding = {"protocol_version": "velo.transfer.v1",
                "transfer_id": self.request["transfer_id"],
                "request_digest": self.request["request_digest"],
                "direction": self.direction, **self.request["expected_vm_identity"],
                "policy_id": "fixture-policy", "package_size": self.package["size"],
                "package_sha256": self.package["sha256"],
                "manifest_sha256": self.package["manifest_sha256"]}
            if self.direction == "pull":
                self.terminal = GuestTerminal(self.binding, self.request["expected_destination"])
            if resume and self.direction == "push":
                nonce = 'verify-' + str(self.counts[key])
                self.worker = {'transfer_id':self.request['transfer_id'],'job':'verify_partial',
                    'nonce':nonce,'pid':123,'birth':'fixture-birth','deadline_monotonic':999999999.,'stopped':True}
                ledger = b''.join(json.dumps(r, sort_keys=True, separators=(',', ':')).encode() + b'\n' for r in self.chunk_records)
                self.prefix_proof = {'schema':'velo.transfer.prefix-verification.v1',
                    'request_digest':self.request['request_digest'],'worker_nonce':nonce,
                    'verified_offset':self.offset,'chunk_count':len(self.chunk_records),
                    'ledger_sha256':hashlib.sha256(ledger).hexdigest(),'completed':True}
            response = self.status()
        elif operation == "transfer_status":
            if self.request is None:
                raise AdapterError("task_not_found")
            response = self.status()
        elif operation == "transfer_chunk" and self.direction == "push":
            raw = base64.b64decode(arguments["data_base64"], validate=True)
            assert arguments["offset"] == self.offset
            assert arguments["count"] == len(raw)
            assert hashlib.sha256(raw).hexdigest() == arguments["chunk_sha256"]
            self.prefix_proof = None
            self.chunk_records.append({'offset':self.offset,'count':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            self.received.extend(raw)
            self.offset += len(raw)
            if self.offset == self.package["size"]:
                assert hashlib.sha256(self.received).hexdigest() == self.package["sha256"]
                self.terminal = GuestTerminal(self.binding, self.request["expected_destination"])
            response = {"schema": "velo.transfer.guest.response.v1",
                        "verified_offset": self.offset, "replayed": False}
        elif operation == "transfer_chunk" and self.direction == "pull":
            raw = self.package_path.read_bytes()[arguments["offset"]:arguments["offset"] + arguments["count"]]
            self.offset += len(raw)
            response = {"schema": "velo.transfer.guest.response.v1",
                        "offset": arguments["offset"], "count": len(raw),
                        "data_base64": base64.b64encode(raw).decode("ascii"),
                        "chunk_sha256": hashlib.sha256(raw).hexdigest()}
        elif operation == "transfer_chunks" and self.direction == "pull":
            items = []
            pos = arguments["offset"]
            payload = self.package_path.read_bytes()
            for _ in range(arguments["chunk_count"]):
                raw = payload[pos:pos + arguments["count_per_chunk"]]
                items.append({"offset": pos, "count": len(raw),
                              "data_base64": base64.b64encode(raw).decode("ascii"),
                              "chunk_sha256": hashlib.sha256(raw).hexdigest()})
                pos += len(raw)
                self.offset = pos
            response = {"schema": "velo.transfer.guest.response.v1", "chunks": items}
        elif operation == "transfer_chunks" and self.direction == "push":
            pos = arguments["offset"]
            for item in arguments["chunks"]:
                raw = base64.b64decode(item["data_base64"], validate=True)
                assert pos == self.offset
                assert item["count"] == len(raw)
                assert hashlib.sha256(raw).hexdigest() == item["chunk_sha256"]
                self.prefix_proof = None
                self.chunk_records.append({'offset':self.offset,'count':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
                self.received.extend(raw)
                self.offset += len(raw)
                pos += len(raw)
            if self.offset == self.package["size"]:
                assert hashlib.sha256(self.received).hexdigest() == self.package["sha256"]
                self.terminal = GuestTerminal(self.binding, self.request["expected_destination"])
            response = {"schema": "velo.transfer.guest.response.v1",
                        "verified_offset": self.offset, "accepted":len(arguments["chunks"])}
        elif operation == "transfer_finish":
            inputs = {k: v for k, v in arguments.items()
                      if k not in ("transfer_id", "request_digest", "action")}
            action = arguments["action"]
            pending = self.terminal.begin_action(action, **inputs)
            oid = pending["operation_id"]
            if pending["status"] == "IN_PROGRESS":
                if action == "prepare":
                    self.terminal.complete_prepare(oid, prepare_receipt(
                        self.binding, self.binding["manifest_sha256"]))
                elif action == "commit":
                    self.terminal.complete_commit(oid, publication_receipt(
                        self.binding, self.terminal.prepare,
                        self.request["expected_destination"], {"device": 1, "inode": 2}))
                elif action == "release":
                    self.terminal.authorize_release(oid)
                    cleanup = {"temporary_files_removed": True, "workers_stopped": True}
                    self.terminal.complete_release(oid, cleanup)
                    self.worker = {"stopped": True, "job": "release", "nonce": "fixture-nonce"}
                    if self.direction == "push":
                        self.proof = {"schema": "velo.transfer.destination-verification.v1",
                            "binding": self.binding, "release_operation_id": oid,
                            "publication_receipt_sha256": receipt_digest(self.terminal.publication),
                            "directory_identity": {"device": 1, "inode": 2},
                            "parent_identity": {"device": 1, "inode": 3},
                            "manifest_sha256": self.binding["manifest_sha256"],
                            "release_worker_nonce": "fixture-nonce", "verification_phase": "post_cleanup"}
            response = {"schema": "velo.transfer.guest.response.v1",
                        "action": action, "operation": copy.deepcopy(self.terminal.operations[action]),
                        "state_scope":"guest_source" if self.direction=="pull" else "guest_destination",
                        "local_phase":self.terminal.local_phase}
            if self.on_finish is not None:
                self.on_finish(action)
        elif operation == "transfer_abort":
            self.aborted = True
            response = {"schema": "velo.transfer.guest.response.v1", "aborted": True}
        else:
            raise AssertionError(operation)
        fault = self.faults.get((*key, self.counts[key]))
        if fault is not None and fault[0] == "after" and fault[1].cleanup_path is not None:
            fault[1].guest_result = copy.deepcopy(response)
        self._fault(key, "after")
        return response


class CoordinatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "子").mkdir(mode=0o700)
        (self.source / "子" / "文件.txt").write_bytes(b"benign bytes")
        (self.source / "empty").mkdir(mode=0o700)
        self.second = self.root / "more.txt"
        self.second.write_bytes(b"more benign bytes")
        self.sibling = self.root / "unlisted.txt"
        self.sibling.write_bytes(b"private sibling")
        self.delivery = self.root / "delivery"
        self.delivery.mkdir(mode=0o700)
        self.destination = self.delivery / "final"
        self.host = {"machine_id": "a" * 32, "boot_id": str(uuid.uuid4())}
        self.vm = {"vm_uuid": str(uuid.uuid4()), "boot_identity": "fixture-boot", "vm_epoch": "fixture-epoch"}
        self.document = {"schema": "velo.transfer.request.v1", "direction": "push",
            "sources": [{"absolute_path": str(self.source), "relative_path": "payload"},
                        {"absolute_path": str(self.second), "relative_path": "more.txt"}],
            "destination_directory": "E:\\benign\\final",
            "connection_profile": "/missing/unused-profile.json",
            "expected_vm_identity": self.vm,
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["producer-ref"]},
            "budget": {"max_files": 100, "max_metadata_bytes": 200000,
                       "max_logical_bytes": 1 << 20, "max_package_bytes": 1 << 20,
                       "max_chunk_bytes": 65536, "min_free_bytes": 0,
                       "max_duration_seconds": 90, "request_timeout_seconds": 10},
            "transfer_id": "coordinator-test"}
        self.spec = self.root / "request.json"
        self.peer = None
        self.select_calls = []

    def setup_request(self, direction="push", *, resume=False):
        self.document["direction"] = direction
        self.document["resume"] = resume
        if direction == "pull":
            self.document["sources"] = [{"absolute_path": "E:\\benign\\source",
                                         "relative_path": "payload"}]
            self.document["destination_directory"] = str(self.destination)
        self.spec.write_text(json.dumps(self.document))
        if self.peer is None:
            self.peer = LocalPeer(self, direction)
        return load_request(self.spec)

    @asynccontextmanager
    async def selector(self, profile, **kwargs):
        self.select_calls.append(copy.deepcopy(kwargs))
        yield self.peer

    async def run_transfer(self, direction="push", *, resume=False, abort=False):
        request = self.setup_request(direction, resume=resume)
        coordinator = TransferCoordinator(request, host_identity=self.host,
            _adapter_selector=self.selector, _profile_loader=lambda _path: None)
        return await coordinator.run(abort=abort)

    def journal(self):
        return HostJournal(load_request(self.spec), self.host)

    def journal_data(self):
        return self.journal_envelope()["data"]

    def journal_envelope(self):
        self.document["resume"] = True
        self.spec.write_text(json.dumps(self.document))
        journal = self.journal()
        with journal.writer():
            return journal.load()

    def result(self, summary):
        self.assertEqual(set(summary), {"schema", "transfer_id", "phase", "outcome",
                                        "exit_code", "published_ever", "result_path", "file_count"})
        return json.loads(Path(summary["result_path"]).read_text())

    async def test_c1_push_pull_one_call_real_host_files_and_resume(self):
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                if direction == "pull":
                    self.document["transfer_id"] = "coordinator-pull"
                    self.peer = None
                summary = await self.run_transfer(direction)
                result = self.result(summary)
                self.assertEqual((summary["outcome"], summary["exit_code"]), ("complete", 0))
                self.assertTrue(summary["published_ever"])
                self.assertEqual(result["cleanup"], {"host": True, "guest": True})
                self.assertGreater(self.peer.counts.get(("transfer_chunk", None), 0), 1)
                self.assertEqual(result["package_sha256"], self.peer.package["sha256"])
                if direction == "push":
                    self.assertEqual(hashlib.sha256(self.peer.received).hexdigest(), result["package_sha256"])
                    self.assertEqual(self.sibling.read_bytes(), b"private sibling")
                else:
                    self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                                     b"benign bytes")
                calls = len(self.peer.trace)
                first_path = summary["result_path"]
                first_state = self.journal_envelope()
                request = first_state["data"]["guest_request"]
                binding = first_state["data"]["binding"]
                receipts = {key: first_state["data"].get(key) for key in
                            ("prepare_receipt", "publication_receipt", "source_validation_receipt")}
                operations = copy.deepcopy(first_state["data"]["operations"])
                again = await self.run_transfer(direction, resume=True)
                second_state = self.journal_envelope()
                self.assertEqual(again["result_path"], first_path)
                self.assertEqual(second_state["deadline_monotonic"], first_state["deadline_monotonic"])
                self.assertEqual(second_state["data"]["guest_request"], request)
                self.assertEqual(second_state["data"]["binding"], binding)
                self.assertEqual({key: second_state["data"].get(key) for key in receipts}, receipts)
                self.assertEqual(second_state["data"]["operations"], operations)
                self.assertEqual(second_state["data"]["channel"], first_state["data"]["channel"])
                self.assertEqual([name for name, _ in self.peer.trace[calls:]],
                                 ["transfer_status", "transfer_status"])
                self.assertEqual(self.select_calls[-1]["begun_channel"], "velo")

    async def test_c2_unknown_begin_queries_same_identity_before_continuing(self):
        self.setup_request()
        self.peer.fail("transfer_begin", when="after")
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        names = [name for name, _ in self.peer.trace]
        self.assertEqual(names[:2], ["transfer_begin", "transfer_status"])
        self.assertEqual(names.count("transfer_begin"), 2)  # final full-prefix verification
        begin = self.peer.trace[0][1]["request"]
        status = self.peer.trace[1][1]
        self.assertEqual(status, {"transfer_id": begin["transfer_id"],
                                  "request_digest": begin["request_digest"]})
        self.assertEqual(self.journal_data()["begin_attempts"], 1)

    async def test_pc026_unknown_batch_and_begin_lost_reply_never_duplicate_ranges(self):
        self.setup_request()
        self.peer.batch_chunks = 4
        self.peer.fail("transfer_chunks", when="after")
        self.peer.fail("transfer_begin", nth=2, when="after")
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        writes = [(name,args) for name,args in self.peer.trace if name in ("transfer_chunk","transfer_chunks")]
        offsets = [args["offset"] for _,args in writes]
        self.assertEqual(len(offsets), len(set(offsets)))
        names = [name for name,_ in self.peer.trace]
        first = names.index("transfer_chunks")
        self.assertEqual(names[first+1:first+3], ["transfer_status","transfer_begin"])
        self.assertTrue(all(name == "transfer_chunks" for name,_ in writes))

    async def test_pc026_wrong_ledger_proof_blocks_next_writer(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", when="after")
        def damage(response):
            if response.get("prefix_verification"):
                response["prefix_verification"]["ledger_sha256"] = "f"*64
            return response
        self.peer.on_status = damage
        summary = await self.run_transfer()
        self.assertEqual(self.result(summary)["warnings"], ["chunk_outcome_unresolved"])
        self.assertEqual(sum(op == "transfer_chunk" for op,_ in self.peer.trace), 1)

    async def test_pc026_dead_worker_without_proof_gets_new_bounded_verification(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", when="after")
        def old_failure(response):
            if self.peer.offset and self.peer.prefix_proof is None:
                response["error"] = "worker_result_unknown"
            return response
        self.peer.on_status = old_failure
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        chunks = [args for op,args in self.peer.trace if op == "transfer_chunk"]
        self.assertEqual(len({item["offset"] for item in chunks}), len(chunks))
        self.assertTrue(self.peer.prefix_proof["completed"])

    async def test_pc026_old_nonce_lost_begin_cannot_self_certify(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", when="after")
        self.peer.fail("transfer_begin", nth=2, when="before")
        # A lost begin before any new worker does not provide a new proof.
        summary = await self.run_transfer()
        self.assertEqual(self.result(summary)["warnings"], ["chunk_outcome_unresolved"])
        self.assertEqual(sum(op == "transfer_chunk" for op,_ in self.peer.trace), 1)
        self.assertEqual(sum(op == "transfer_begin" for op,_ in self.peer.trace), 2)

    async def test_pc026_finish_scope_done_error_and_in_progress_result_rejected(self):
        for variant in ('wrong_scope', 'done_error', 'in_progress_result'):
            with self.subTest(variant=variant):
                self.document['transfer_id'] = 'invalid-finish-' + variant
                self.peer = None
                self.setup_request()
                original = self.peer.call
                async def damaged(op, args):
                    response = await original(op, args)
                    if op == 'transfer_finish' and args['action'] == 'prepare':
                        if variant == 'wrong_scope':
                            response['state_scope'] = 'guest_source'
                        elif variant == 'done_error':
                            response['operation']['result']['error'] = 'worker_failed'
                        else:
                            response['operation']['status'] = 'IN_PROGRESS'
                    return response
                self.peer.call = damaged
                summary = await self.run_transfer()
                self.assertEqual(self.result(summary)['warnings'], ['guest_operation_conflict'])
                self.assertFalse(any(op == 'transfer_finish' and args['action'] == 'commit'
                                     for op,args in self.peer.trace))
                self.assertIsNone(self.journal_data().get('prepare_receipt'))

    async def test_c2_unknown_push_chunk_queries_offset_without_duplicate(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", when="after")
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        names = [name for name, _ in self.peer.trace]
        first_chunk = names.index("transfer_chunk")
        self.assertEqual(names[first_chunk + 1], "transfer_status")
        chunks = [args for name, args in self.peer.trace if name == "transfer_chunk"]
        self.assertEqual(chunks[0]["offset"], 0)
        self.assertEqual(chunks[1]["offset"], chunks[0]["count"])
        self.assertEqual(len({item["offset"] for item in chunks}), len(chunks))
        self.assertEqual(hashlib.sha256(self.peer.received).hexdigest(), self.peer.package["sha256"])

    async def test_c2_unknown_prepare_commit_release_query_without_resend(self):
        for action in ("prepare", "commit", "release"):
            with self.subTest(action=action):
                # Each case gets its own physical journal and remote terminal.
                if action != "prepare":
                    self.document["transfer_id"] = "unknown-" + action
                    self.spec = self.root / ("request-" + action + ".json")
                    self.peer = None
                self.setup_request()
                self.peer.fail("transfer_finish", action=action, when="after")
                summary = await self.run_transfer()
                self.assertEqual(summary["outcome"], "complete")
                actions = [args for name, args in self.peer.trace
                           if name == "transfer_finish" and args["action"] == action]
                self.assertEqual(len(actions), 1)
                index = next(i for i, (name, args) in enumerate(self.peer.trace)
                             if name == "transfer_finish" and args["action"] == action)
                self.assertEqual(self.peer.trace[index + 1][0], "transfer_status")
                self.assertEqual(actions[0]["request_digest"], self.peer.request["request_digest"])
                operation = self.peer.terminal.operations[action]
                self.assertEqual(operation["input_digest"], digest_json({
                    "binding": self.peer.binding, "action": action,
                    "inputs": {k: v for k, v in actions[0].items()
                               if k not in ("transfer_id", "request_digest", "action")}}))

    async def test_c2_unknown_begin_and_failed_query_keeps_incomplete_intent(self):
        self.setup_request()
        self.peer.fail("transfer_begin", when="after")
        self.peer.fail("transfer_status", error=AdapterError("transport_timeout"))
        summary = await self.run_transfer()
        result = self.result(summary)
        self.assertEqual(summary["outcome"], "incomplete")
        self.assertEqual([name for name, _ in self.peer.trace[:2]],
                         ["transfer_begin", "transfer_status"])
        self.assertEqual(sum(name == "transfer_begin" for name, _ in self.peer.trace), 1)
        data = self.journal_data()
        self.assertTrue(data["begin_attempted"])
        self.assertEqual(data["begin_attempts"], 1)
        self.assertEqual(data["io_intent"]["operation"], "transfer_status")
        self.assertIn("transport_timeout", result["warnings"])

    async def test_c2_pull_chunk_interruption_resumes_durable_offset(self):
        self.setup_request("pull")
        self.peer.fail("transfer_chunk", nth=2,
                       error=AdapterError("transport_timeout", may_have_committed=True))
        first = await self.run_transfer("pull")
        self.assertEqual(first["outcome"], "incomplete")
        data = self.journal_data()
        boundary = data["receive_partial"]["verified_offset"]
        self.assertEqual(boundary, 128)
        first_calls = len(self.peer.trace)
        self.peer.faults.clear()
        resumed = await self.run_transfer("pull", resume=True)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("complete", 0))
        chunks = [args for op, args in self.peer.trace[first_calls:] if op == "transfer_chunk"]
        self.assertEqual(chunks[0]["offset"], boundary)
        self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")
        self.assertEqual(self.result(resumed)["resumed_bytes"], boundary)

    async def test_c2_batch_degrade_switches_to_single_chunks_for_the_rest_of_the_run(self):
        self.setup_request("pull")
        self.peer.batch_chunks = 4
        self.peer.fail("transfer_chunks", nth=1,
                       error=AdapterError("transport_timeout", may_have_committed=False))
        summary = await self.run_transfer("pull")
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("complete", 0))
        names = [name for name, _ in self.peer.trace]
        first = names.index("transfer_chunks")
        # The degraded run must actually use single-chunk pulls afterwards,
        # not retry the same failing batch for the rest of the transfer.
        self.assertEqual(names[first], "transfer_chunks")
        singles = [name for name in names[first + 1:] if name.startswith("transfer_chunk")]
        self.assertGreater(len(singles), 1)
        self.assertNotIn("transfer_chunks", names[first + 1:])

    async def test_c2_outage_storm_ends_incomplete_with_one_shared_error_file(self):
        # A service outage mid-transfer produced one distinct immutable
        # adapter_error evidence file per retry (intent sequence differs per
        # call) and exhausted the evidence file budget before connectivity
        # returned, turning a recoverable outage into a command error. Same-
        # shape retries must share one file and the run must stop at the first
        # single-chunk failure so a later resume can recover.
        self.setup_request("pull")
        self.peer.batch_chunks = 4
        for nth in range(1, 60):
            self.peer.fail("transfer_chunks", nth=nth,
                           error=AdapterError("outcome_unknown", may_have_committed=True))
        self.peer.fail("transfer_chunk", nth=1,
                       error=AdapterError("transport_timeout", may_have_committed=False))
        first = await self.run_transfer("pull")
        self.assertEqual(first["outcome"], "incomplete")
        evidence_dir = Path(first["result_path"]).parent
        adapter_files = [name for name in os.listdir(evidence_dir) if name.startswith("adapter_error")]
        # One shared file per error shape: the batched outcome_unknown retries
        # collapse into one file, plus one for the single-chunk transport_timeout.
        self.assertEqual(len(adapter_files), 2)
        faulted = sum(1 for name, _ in self.peer.trace if name == "transfer_chunks")
        self.assertLess(faulted, 60)
        self.peer.faults.clear()
        resumed = await self.run_transfer("pull", resume=True)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("complete", 0))
        self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")

    async def test_c2_worker_in_progress_only_queries_until_stopped(self):
        self.setup_request()
        seen = {"after_prepare": 0}

        def finishing(action):
            if action == "prepare":
                self.peer.worker = {"stopped": False, "job": "prepare", "nonce": "busy"}

        def status_hook(response):
            if self.peer.terminal and "prepare" in self.peer.terminal.operations:
                seen["after_prepare"] += 1
                if seen["after_prepare"] >= 3 and self.peer.worker and self.peer.worker["job"] == "prepare":
                    self.peer.worker["stopped"] = True
                    response["worker"]["stopped"] = True
            return response

        self.peer.on_finish = finishing
        self.peer.on_status = status_hook
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        actions = [args["action"] for op, args in self.peer.trace if op == "transfer_finish"]
        self.assertEqual(actions.count("prepare"), 1)
        index = next(i for i, (op, args) in enumerate(self.peer.trace)
                     if op == "transfer_finish" and args["action"] == "prepare")
        self.assertEqual([op for op, _ in self.peer.trace[index + 1:index + 4]],
                         ["transfer_status"] * 3)

    async def test_c2_begin_retry_cap_bounded_per_run(self):
        """The retry cap bounds attempts within one run, not the task lifetime.

        Historical failures (possibly from different, fixed causes) must not
        permanently block re-begin; each new coordinator run gets a fresh
        budget while begin_attempted keeps channel stickiness.
        """
        self.setup_request()
        for nth in (1, 2, 3):
            self.peer.fail("transfer_begin", nth=nth,
                           error=AdapterError("outcome_unknown", may_have_committed=True))
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "incomplete")
        self.assertEqual(self.peer.counts[("transfer_begin", None)], 1)
        # A later run (cause fixed) must be able to begin again; historical
        # attempts never block it.
        self.peer.fail("transfer_begin", nth=4,
                       error=AdapterError("outcome_unknown", may_have_committed=True))
        self.peer.fail("transfer_begin", nth=5,
                       error=AdapterError("outcome_unknown", may_have_committed=True))
        summary2 = await self.run_transfer(resume=True)
        self.assertEqual(summary2["outcome"], "incomplete")
        self.assertEqual(self.peer.counts[("transfer_begin", None)], 2)
        # And with the fault cleared, begin succeeds and re-arms the budget.
        summary3 = await self.run_transfer(resume=True)
        self.assertGreaterEqual(self.peer.counts[("transfer_begin", None)], 3)
        self.assertLessEqual(self.journal_data()["begin_attempts"], 1)

    async def test_c2_prepare_retry_cap_no_unbounded_mutation(self):
        self.setup_request()
        for nth in (1, 2, 3):
            self.peer.fail("transfer_finish", action="prepare", nth=nth,
                           error=AdapterError("outcome_unknown", may_have_committed=True))
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "incomplete")
        self.assertEqual(self.peer.counts[("transfer_finish", "prepare")], 3)
        self.assertEqual(self.journal_data()["actions"]["prepare"]["attempts"], 3)
        self.assertIn("action_retry_exhausted", self.result(summary)["warnings"])

    async def test_c4_peer_identity_change_rejected_before_remote_mutation(self):
        self.setup_request()
        self.peer.observations["boot_identity"] = "wrong-boot"
        summary = await self.run_transfer()
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("conflict", 4))
        self.assertEqual(self.peer.trace, [])
        self.assertIn("vm_identity_mismatch", self.result(summary)["warnings"])

    async def test_c3_coordinator_real_selector_fallback_then_sticky_resume(self):
        self.setup_request()
        self.peer.channel = "windows"
        opened = []

        @asynccontextmanager
        async def fake_open(_profile, channel, **_kwargs):
            opened.append(channel)
            if channel == "velo":
                unavailable = LocalPeer(self, "push")
                unavailable.probe_error = "tools_missing"
                yield unavailable
            else:
                yield self.peer

        async def connected(resume):
            request = self.setup_request(resume=resume)
            coordinator = TransferCoordinator(request, host_identity=self.host,
                _adapter_selector=select_adapter, _profile_loader=lambda _path: None)
            return await coordinator.run()

        with mock.patch("velo_transfer.adapters.open_adapter", fake_open):
            first = await connected(False)
            self.assertEqual((first["outcome"], first["exit_code"]), ("complete", 0))
            self.assertEqual(opened, ["velo", "windows"])
            self.assertEqual(self.result(first)["fallback_reason"], "tools_missing")
            before = len(self.peer.trace)
            second = await connected(True)
        self.assertEqual(second["outcome"], "complete")
        self.assertEqual(opened, ["velo", "windows", "windows"])
        self.assertEqual([op for op, _ in self.peer.trace[before:]],
                         ["transfer_status", "transfer_status"])
        self.assertEqual(self.journal_data()["channel"], "windows")

    async def test_c4_source_changes_before_commit(self):
        self.setup_request()
        self.peer.on_finish = lambda action: (self.source / "子" / "文件.txt").write_bytes(
            b"changed after prepare") if action == "prepare" else None
        summary = await self.run_transfer()
        self.assertNotEqual(summary["outcome"], "complete")
        self.assertNotIn("commit", [args["action"] for op, args in self.peer.trace
                                    if op == "transfer_finish"])
        self.assertFalse(self.result(summary)["published_ever"])

    async def test_c4_expired_resume_keeps_original_deadline_and_no_mutation(self):
        self.document["budget"]["max_duration_seconds"] = 1
        self.document["budget"]["request_timeout_seconds"] = 1
        self.setup_request()
        self.peer.fail("transfer_chunk", error=AdapterError("transport_timeout"))
        first = await self.run_transfer()
        self.assertEqual(first["outcome"], "incomplete")
        deadline = self.journal_envelope()["deadline_monotonic"]
        calls = len(self.peer.trace)
        await asyncio.sleep(1.1)
        resumed = await self.run_transfer(resume=True)
        self.assertEqual(resumed["outcome"], "incomplete")
        self.assertIn("deadline_exceeded", self.result(resumed)["warnings"])
        self.assertEqual(self.journal_envelope()["deadline_monotonic"], deadline)
        self.assertEqual(len(self.peer.trace), calls)

    async def test_c4_changed_request_epoch_or_peer_policy_stops_resume(self):
        for changed in ("request", "epoch", "policy"):
            with self.subTest(changed=changed):
                self.document["transfer_id"] = "changed-" + changed
                self.spec = self.root / (changed + ".json")
                self.peer = None
                self.setup_request()
                self.peer.fail("transfer_chunk", error=AdapterError("transport_timeout"))
                first = await self.run_transfer()
                self.assertEqual(first["outcome"], "incomplete")
                calls = len(self.peer.trace)
                if changed == "request":
                    self.document["evidence_context"]["references"].append("changed-ref")
                elif changed == "epoch":
                    self.document["expected_vm_identity"]["vm_epoch"] = "new-epoch"
                else:
                    self.peer.observations["policy_id"] = "new-policy"
                if changed == "policy":
                    resumed = await self.run_transfer(resume=True)
                    self.assertEqual(resumed["outcome"], "conflict")
                    self.assertIn("guest_identity_changed", self.result(resumed)["warnings"])
                else:
                    with self.assertRaisesRegex(TransferContentError, "task_binding_conflict"):
                        await self.run_transfer(resume=True)
                self.assertEqual(len(self.peer.trace), calls)
                self.document["evidence_context"]["references"] = ["producer-ref"]
                self.document["expected_vm_identity"]["vm_epoch"] = "fixture-epoch"

    async def test_c4_corrupted_pull_prefix_rejected_before_new_chunk(self):
        self.setup_request("pull")
        self.peer.fail("transfer_chunk", nth=2,
                       error=AdapterError("transport_timeout", may_have_committed=True))
        first = await self.run_transfer("pull")
        self.assertEqual(first["outcome"], "incomplete")
        partial = Path(self.journal_data()["receive_partial"]["partial"]["path"])
        with partial.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"X")
        calls = len(self.peer.trace)
        self.peer.faults.clear()
        resumed = await self.run_transfer("pull", resume=True)
        self.assertEqual(resumed["outcome"], "conflict", self.result(resumed)["warnings"])
        self.assertEqual(len([1 for op, _ in self.peer.trace[calls:] if op == "transfer_chunk"]), 0)
        self.assertFalse(self.result(resumed)["published_ever"])

    async def test_c4_cas_failure_propagates_without_external_mutation(self):
        self.setup_request()
        with mock.patch.object(HostJournal, "save", side_effect=TransferContentError("stale_revision")):
            with self.assertRaisesRegex(TransferContentError, "stale_revision"):
                await self.run_transfer()
        self.assertEqual(self.peer.trace, [])
        self.assertFalse(self.journal_data()["begin_attempted"])

    async def test_c4_guest_package_k_change_rejected_on_resume(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", error=AdapterError("transport_timeout"))
        first = await self.run_transfer()
        self.assertEqual(first["outcome"], "incomplete")
        self.peer.package["sha256"] = "0" * 64
        calls = len(self.peer.trace)
        resumed = await self.run_transfer(resume=True)
        self.assertEqual(resumed["outcome"], "conflict", self.result(resumed)["warnings"])
        self.assertIn("guest_package_conflict", self.result(resumed)["warnings"])
        self.assertEqual([op for op, _ in self.peer.trace[calls:]], ["transfer_status"])

    async def test_c4_changed_operation_id_on_resume_rejected(self):
        first = await self.run_transfer()
        self.assertEqual(first["outcome"], "complete")

        def changed(response):
            response["terminal"]["operations"]["release"]["operation_id"] = "different-id"
            response["terminal"]["release_authorization"]["operation_id"] = "different-id"
            return response

        self.peer.on_status = changed
        calls = len(self.peer.trace)
        resumed = await self.run_transfer(resume=True)
        self.assertEqual(resumed["outcome"], "conflict", self.result(resumed)["warnings"])
        self.assertIn("guest_operation_conflict", self.result(resumed)["warnings"])
        self.assertTrue(self.result(resumed)["published_ever"])
        self.assertEqual([op for op, _ in self.peer.trace[calls:]], ["transfer_status"])

    async def test_c4_changed_publication_receipt_on_resume_rejected(self):
        first = await self.run_transfer()
        self.assertEqual(first["outcome"], "complete")
        original_receipt = self.journal_data()["publication_receipt"]

        replacement = publication_receipt(self.peer.binding, self.peer.terminal.prepare,
            self.peer.request["expected_destination"], {"device": 1, "inode": 2},
            publication_id="different-id")

        def changed(response):
            terminal = response["terminal"]
            terminal["publication_receipt"] = replacement
            terminal["operations"]["commit"]["result"]["publication_receipt"] = replacement
            release = terminal["operations"]["release"]
            release["inputs"]["publication_receipt"] = replacement
            release["input_digest"] = digest_json({"binding": self.peer.binding,
                "action": "release", "inputs": release["inputs"]})
            release["result"]["publication_receipt"] = replacement
            terminal["release_authorization"]["publication_receipt_sha256"] = receipt_digest(replacement)
            return response

        self.peer.on_status = changed
        calls = len(self.peer.trace)
        resumed = await self.run_transfer(resume=True)
        self.assertEqual(resumed["outcome"], "conflict", self.result(resumed)["warnings"])
        self.assertIn("guest_operation_conflict", self.result(resumed)["warnings"])
        self.assertEqual(self.journal_data()["publication_receipt"], original_receipt)
        self.assertTrue(self.result(resumed)["published_ever"])
        self.assertEqual([op for op, _ in self.peer.trace[calls:]], ["transfer_status"])

    async def test_c5_pull_occupied_destination_keeps_existing_tree(self):
        self.destination.mkdir()
        sentinel = self.destination / "sentinel.txt"
        sentinel.write_bytes(b"existing owner")
        summary = await self.run_transfer("pull")
        self.assertEqual(summary["outcome"], "conflict")
        self.assertEqual(sentinel.read_bytes(), b"existing owner")
        self.assertFalse(self.result(summary)["published_ever"])
        self.assertNotIn("release", [args["action"] for op, args in self.peer.trace
                                     if op == "transfer_finish"])

    async def test_c5_push_release_proof_mismatch_retains_publication(self):
        self.setup_request()
        self.peer.on_finish = lambda action: self.peer.proof.update(
            manifest_sha256="0" * 64) if action == "release" else None
        summary = await self.run_transfer()
        result = self.result(summary)
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("conflict", 4))
        self.assertTrue(result["published_ever"])
        self.assertFalse(result["destination_verified"])
        self.assertIn("destination_verification_invalid", result["warnings"])
        self.assertEqual((self.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    async def test_c5_pull_rename_before_receipt_recovers_same_publication(self):
        original = host_publication.publish_directory
        injected = {"hit": False}

        def after_rename(*args, **kwargs):
            original(*args, **kwargs)
            injected["hit"] = True
            raise TransferContentError("post_publish_io_failed", published=True)

        with mock.patch.object(host_publication, "publish_directory", after_rename):
            first = await self.run_transfer("pull")
        self.assertTrue(injected["hit"])
        self.assertEqual(first["outcome"], "incomplete")
        self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")
        data = self.journal_data()
        self.assertTrue(data["published_ever"])
        self.assertIsNone(data.get("publication_receipt"))
        destination_id = self.destination.stat().st_ino
        calls = len(self.peer.trace)
        resumed = await self.run_transfer("pull", resume=True)
        self.assertEqual(resumed["outcome"], "complete")
        self.assertEqual(self.destination.stat().st_ino, destination_id)
        self.assertFalse(any(op == "transfer_chunk" for op, _ in self.peer.trace[calls:]))
        self.assertTrue(self.journal_data()["publication_receipt"])

    async def test_c5_pull_published_tree_damage_conflicts_without_republish(self):
        first = await self.run_transfer("pull")
        self.assertEqual(first["outcome"], "complete")
        payload = self.destination / "payload" / "子" / "文件.txt"
        payload.write_bytes(b"damaged after publication")
        calls = len(self.peer.trace)
        resumed = await self.run_transfer("pull", resume=True)
        result = self.result(resumed)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("conflict", 4))
        self.assertTrue(result["published_ever"])
        self.assertFalse(result["destination_verified"])
        self.assertEqual(payload.read_bytes(), b"damaged after publication")
        self.assertFalse(any(op in ("transfer_chunk", "transfer_finish")
                             for op, _ in self.peer.trace[calls:]))

    async def test_c5_pull_release_response_lost_then_source_change(self):
        self.setup_request("pull")
        self.peer.fail("transfer_finish", action="release", when="after")

        def finishing(action):
            if action == "release":
                next_status = self.peer.counts.get(("transfer_status", None), 0) + 1
                self.peer.fail("transfer_status", nth=next_status,
                               error=AdapterError("transport_timeout"))

        self.peer.on_finish = finishing
        first = await self.run_transfer("pull")
        self.assertEqual(first["outcome"], "cleanup_pending")
        self.assertTrue(self.result(first)["published_ever"])
        (self.source / "子" / "文件.txt").write_bytes(b"new source version")
        calls = len(self.peer.trace)
        self.peer.faults.clear()
        self.peer.on_finish = None
        resumed = await self.run_transfer("pull", resume=True)
        self.assertEqual(resumed["outcome"], "complete")
        self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")
        self.assertFalse(any(op in ("transfer_chunk", "transfer_finish")
                             for op, _ in self.peer.trace[calls:]))

    async def test_c5_push_unstopped_worker_cannot_accept_final_proof(self):
        self.document["budget"].update(max_duration_seconds=1, request_timeout_seconds=1)
        self.setup_request()

        def finishing(action):
            if action == "release":
                self.peer.worker["stopped"] = False

        self.peer.on_finish = finishing
        summary = await self.run_transfer()
        result = self.result(summary)
        self.assertEqual(summary["outcome"], "cleanup_pending")
        self.assertTrue(result["published_ever"])
        self.assertIsNot(result["destination_verified"], True)
        self.assertIsNot(result["cleanup"]["guest"], True)
        self.assertIn("deadline_exceeded", result["warnings"])
        self.assertGreater(self.peer.counts[("transfer_status", None)], 3)

    async def test_c2_release_worker_stops_then_same_operation_completes(self):
        self.setup_request()
        seen = {"release_status": 0}

        def finishing(action):
            if action == "release":
                self.peer.worker["stopped"] = False

        def status_hook(response):
            if self.peer.terminal and "release" in self.peer.terminal.operations:
                seen["release_status"] += 1
                if seen["release_status"] >= 3:
                    self.peer.worker["stopped"] = True
                    response["worker"]["stopped"] = True
            return response

        self.peer.on_finish = finishing
        self.peer.on_status = status_hook
        summary = await self.run_transfer()
        self.assertEqual(summary["outcome"], "complete")
        self.assertEqual(self.peer.counts[("transfer_finish", "release")], 1)
        self.assertGreaterEqual(seen["release_status"], 3)
        self.assertTrue(self.result(summary)["destination_verified"])

    async def test_c6_abort_existing_task_preserves_content(self):
        self.setup_request()
        self.peer.fail("transfer_chunk", error=AdapterError("transport_timeout"))
        first = await self.run_transfer()
        self.assertEqual(first["outcome"], "incomplete")
        before = len(self.peer.trace)
        aborted = await self.run_transfer(resume=True, abort=True)
        self.assertEqual(aborted["outcome"], "incomplete")
        self.assertEqual([op for op, _ in self.peer.trace[before:]],
                         ["transfer_status", "transfer_abort", "transfer_status"])
        self.assertTrue(self.peer.aborted)
        self.assertEqual((self.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    async def test_c6_adapter_cleanup_failure_retains_path_and_guest_result(self):
        self.setup_request()
        cleanup_path = str(self.root / "pending-control.json")
        error = AdapterError("control_cleanup_failed", may_have_committed=True,
                             cleanup_path=cleanup_path)
        self.peer.fail("transfer_begin", when="after", error=error)
        self.peer.fail("transfer_status", error=AdapterError("transport_timeout"))
        summary = await self.run_transfer()
        result = self.result(summary)
        self.assertEqual(summary["outcome"], "incomplete")
        self.assertIn("transport_timeout", result["warnings"])
        data = self.journal_data()
        self.assertTrue(data["adapter_cleanup_pending"])
        ref = data["evidence"]["adapter_error"]
        evidence = json.loads((Path(summary["result_path"]).parent /
                               (ref["name"] + ".json")).read_text())
        self.assertEqual(evidence.get("cleanup_path"), cleanup_path)
        self.assertEqual(evidence.get("guest_result", {}).get("transfer_id"),
                         self.document["transfer_id"])
        indexed = {item["role"]: item["reference"] for item in result["evidence_index"]}
        self.assertEqual(indexed["adapter_error"], ref)
        later = [value for role, value in indexed.items() if role.startswith("adapter_error_")]
        self.assertEqual(len(later), 1)
        later_error = json.loads((Path(summary["result_path"]).parent /
                                 (later[0]["name"] + ".json")).read_text())
        self.assertEqual(later_error["code"], "transport_timeout")

    async def test_c6_commit_receipt_survives_control_cleanup_and_status_failure(self):
        self.setup_request()
        cleanup_path = str(self.root / "commit-control.json")
        pending_path = str(self.root / "pending-commit-control.json")
        self.peer.observations["pending_control_path"] = pending_path
        self.peer.observations["control_cleanup_unknown"] = True
        self.peer.fail("transfer_finish", action="commit", when="after",
                       error=AdapterError("control_cleanup_failed", may_have_committed=True,
                                          cleanup_path=cleanup_path))

        def finishing(action):
            if action == "commit":
                next_status = self.peer.counts.get(("transfer_status", None), 0) + 1
                self.peer.fail("transfer_status", nth=next_status,
                               error=AdapterError("transport_timeout"))

        self.peer.on_finish = finishing
        summary = await self.run_transfer()
        result = self.result(summary)
        self.assertEqual(summary["outcome"], "cleanup_pending")
        self.assertTrue(result["published_ever"])
        self.assertIsNotNone(result["publication_receipt_sha256"])
        self.assertTrue(self.journal_data()["adapter_cleanup_pending"])
        index = {item["role"]: item["reference"] for item in result["evidence_index"]}
        first = json.loads((Path(summary["result_path"]).parent /
                            (index["adapter_error"]["name"] + ".json")).read_text())
        self.assertEqual(first["cleanup_path"], cleanup_path)
        self.assertEqual(first["pending_control_path"], pending_path)
        self.assertTrue(first["control_cleanup_unknown"])
        self.assertEqual(first["guest_result"]["action"], "commit")
        self.assertEqual(first["guest_result"]["operation"]["result"]["publication_receipt"],
                         self.journal_data()["publication_receipt"])
        self.assertEqual(len([role for role in index if role.startswith("adapter_error_")]), 1)


class CliTests(unittest.TestCase):
    def test_cli_connection_profile_error_is_bounded(self):
        class Request:
            resume = False

        async def invalid_profile(_request, *, abort):
            raise ConnectionError("invalid_profile")

        output = io.StringIO()
        with mock.patch("velo_transfer.__main__.load_request", return_value=Request()), \
             mock.patch("velo_transfer.__main__.transfer", invalid_profile), \
             redirect_stdout(output):
            code = cli_main(["--spec", "/tmp/fixture-spec.json"])
        self.assertEqual(code, 3)
        self.assertEqual(output.getvalue().splitlines(),
                         ['{"schema":"velo.transfer.command-error.v1","error":"invalid_profile"}'])

    def test_c6_cli_subprocess_summary_matches_durable_result(self):
        script = """
import json
import runpy
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
import velo_transfer.host_coordinator as module
from test_transfer_host_coordinator import LocalPeer

spec = Path(sys.argv[1])
document = json.loads(spec.read_text())
fixture = SimpleNamespace(root=spec.parent,
    source=Path(sys.argv[3]),
    vm=document["expected_vm_identity"])
peer = LocalPeer(fixture, document["direction"])
host_identity = json.loads(sys.argv[2])
original = module.TransferCoordinator
@asynccontextmanager
async def selector(_profile, **_kwargs):
    yield peer
module.TransferCoordinator = lambda request: original(request,
    host_identity=host_identity, _adapter_selector=selector,
    _profile_loader=lambda _path: None)
sys.argv = ["velo_transfer", "--spec", str(spec)]
runpy.run_module("velo_transfer", run_name="__main__")
"""
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(Path(__file__).parent), str(Path(__file__).parent.parent)])}
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                fixture = CoordinatorTests("test_c1_push_pull_one_call_real_host_files_and_resume")
                fixture.setUp()
                for cleanup, args, kwargs in fixture._cleanups:
                    self.addCleanup(cleanup, *args, **kwargs)
                fixture._cleanups.clear()
                fixture.setup_request(direction)
                if direction == "pull":
                    fixture.peer.package_path.unlink()
                completed = subprocess.run([sys.executable, "-c", script, str(fixture.spec),
                    json.dumps(fixture.host), str(fixture.source)], env=env,
                    capture_output=True, text=True, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                summary = json.loads(completed.stdout)
                result_path = Path(summary["result_path"])
                result = json.loads(result_path.read_text())
                state = fixture.journal_envelope()["data"]
                self.assertEqual((summary["outcome"], summary["exit_code"], summary["phase"]),
                                 ("complete", 0, "COMPLETE"))
                self.assertEqual((result["outcome"], result["phase"], state["phase"]),
                                 ("complete", "COMPLETE", "COMPLETE"))
                self.assertEqual(result_path.name, state["result_ref"]["name"] + ".json")
                self.assertEqual(result["transfer_id"], summary["transfer_id"])
                self.assertEqual(result["published_ever"], summary["published_ever"])
                self.assertEqual(result["cleanup"], {"host": True, "guest": True})
                if direction == "pull":
                    self.assertEqual((fixture.destination / "payload" / "子" / "文件.txt").read_bytes(),
                                     b"benign bytes")

        missing = subprocess.run([sys.executable, "-m", "velo_transfer", "--spec",
            str(fixture.root / "missing.json")], env=env, capture_output=True, text=True,
            check=False)
        self.assertEqual(missing.returncode, 3, missing.stderr)
        self.assertEqual(len(missing.stdout.splitlines()), 1)
        self.assertEqual(json.loads(missing.stdout)["schema"], "velo.transfer.command-error.v1")
        self.assertNotIn("result_path", json.loads(missing.stdout))

    def test_c6_cli_one_line_success_and_missing_result_error(self):
        from velo_transfer.errors import TransferContentError

        class Request:
            resume = False

        async def successful(_request, *, abort):
            self.assertFalse(abort)
            return {"schema": "velo.transfer.result.v1", "transfer_id": "fixture",
                    "phase": "COMPLETE", "outcome": "complete", "exit_code": 0,
                    "published_ever": True, "result_path": "/tmp/fixture-result.json",
                    "file_count": 2}

        output = io.StringIO()
        with mock.patch("velo_transfer.__main__.load_request", return_value=Request()), \
             mock.patch("velo_transfer.__main__.transfer", successful), redirect_stdout(output):
            code = cli_main(["--spec", "/tmp/fixture-spec.json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())["result_path"], "/tmp/fixture-result.json")

        output = io.StringIO()
        with mock.patch("velo_transfer.__main__.load_request", side_effect=TransferContentError("invalid_request")), \
             redirect_stdout(output):
            code = cli_main(["--spec", "/tmp/fixture-spec.json"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue()),
                         {"schema": "velo.transfer.command-error.v1", "error": "invalid_request"})
        self.assertEqual(len(output.getvalue().splitlines()), 1)


class AdapterSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_c3_real_selection_fallback_and_sticky(self):
        for initial_code in ("connection_unavailable", "tools_missing", "capabilities_disabled",
                             "authentication_denied", "protocol_error", "identity_mismatch",
                             "transport_timeout"):
            with self.subTest(initial_code=initial_code):
                calls = []

                class FakeAdapter:
                    def __init__(self, channel):
                        self.channel = channel
                        self.fallback_reason = None

                    async def probe(self, _identity):
                        if self.channel == "velo":
                            raise AdapterError(initial_code)

                @asynccontextmanager
                async def opened(_profile, channel, **_kwargs):
                    calls.append(channel)
                    yield FakeAdapter(channel)

                with mock.patch("velo_transfer.adapters.open_adapter", opened):
                    args = {"expected_vm_identity": {"vm_uuid": "v", "boot_identity": "b"},
                            "deadline_monotonic": time.monotonic() + 10,
                            "request_timeout_seconds": 2}
                    if initial_code in ("connection_unavailable", "tools_missing", "capabilities_disabled"):
                        async with select_adapter(None, **args) as selected:
                            self.assertEqual((selected.channel, selected.fallback_reason),
                                             ("windows", initial_code))
                        self.assertEqual(calls, ["velo", "windows"])
                    else:
                        with self.assertRaisesRegex(AdapterError, initial_code):
                            async with select_adapter(None, **args):
                                pass
                        self.assertEqual(calls, ["velo"])
                    calls.clear()
                    async with select_adapter(None, begun_channel="windows", **args) as selected:
                        self.assertEqual(selected.channel, "windows")
                    self.assertEqual(calls, ["windows"])


if __name__ == "__main__":
    unittest.main()

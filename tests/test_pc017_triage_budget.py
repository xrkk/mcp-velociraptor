from __future__ import annotations

import json
import re
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_api
from velociraptor_dynamic_artifacts import ArtifactSpec
from velociraptor_fixed_tools import FixedToolService
from velociraptor_mcp_core import (
    BackendError,
    DependencyMissingError,
    TargetContext,
    VelociraptorBackend,
)


TRIAGE = "Windows.Triage.Targets"
KILL = "Generic.Utils.KillProcess"
HUNT_ARTIFACT = "Windows.Test.Fixed"
SPEC = ArtifactSpec(
    name=HUNT_ARTIFACT,
    description="triage budget isolation fixture",
    definition_sha256="0" * 64,
    parameters=(),
)


class RecordingStub:
    def __init__(self, *, installed=(), state="WAITING") -> None:
        self.installed = set(installed)
        self.state = state
        self.requests: list[dict] = []
        self.submissions: list[str] = []
        self.flow_number = 0

    def Query(self, request):
        query = request.Query[0].VQL
        self.requests.append(
            {"org_id": getattr(request, "org_id", ""), "query": query}
        )
        if "FROM clients()" in query:
            rows = [
                {
                    "client_id": "C.one",
                    "system": "windows",
                    "hostname": "TEST-WINDOWS",
                    "fqdn": "TEST-WINDOWS",
                }
            ]
        elif "FROM artifact_definitions()" in query:
            rows = [
                {"name": artifact}
                for artifact in sorted(self.installed)
                if f"name = '{artifact}'" in query
            ]
        elif "LET collection <= collect_client" in query:
            self.submissions.append(query)
            self.flow_number += 1
            rows = [{"flow_id": f"F.budget{self.flow_number}"}]
        elif "FROM flows(" in query:
            rows = [] if self.state is None else [{"state": self.state}]
        elif query.startswith("SELECT hunt("):
            rows = [{"HuntResult": {"HuntId": "H.budget"}}]
        elif query.startswith("SELECT hunt_add("):
            rows = [{"Result": "C.one"}]
        elif "FROM hunts(hunt_id=" in query:
            rows = [{"hunt_id": "H.budget", "state": "PAUSED", "stats": {}}]
        else:
            raise AssertionError(f"unexpected external query: {query}")
        return [SimpleNamespace(Response=json.dumps(rows), error="", log="")]


class TriageBudgetContractTests(unittest.TestCase):
    def run_with_stub(self, stub, callback):
        with (
            tempfile.TemporaryDirectory() as download_root,
            patch.object(velociraptor_api, "stub", stub),
            patch.object(velociraptor_api, "_stub_created_at", time.monotonic()),
        ):
            backend = VelociraptorBackend()
            service = FixedToolService(
                [SPEC], TargetContext(backend), backend, download_root=download_root
            )
            return callback(service, backend)

    def assert_root_requests(self, stub):
        self.assertTrue(stub.requests)
        self.assertTrue(all(request["org_id"] == "" for request in stub.requests))

    def test_fixed_triage_reaches_query_boundary_with_only_4gib_budget(self):
        stub = RecordingStub(installed={TRIAGE})
        result = self.run_with_stub(
            stub, lambda service, _backend: service.collect_forensic_triage()
        )
        self.assertEqual((result.flow_id, result.state), ("F.budget1", "WAITING"))
        self.assertEqual(len(stub.submissions), 1)
        submit = stub.submissions[0]
        self.assertIn("client_id='C.one'", submit)
        self.assertIn("artifacts='Windows.Triage.Targets'", submit)
        self.assertIn("env=dict(Targets='[\"_BasicCollection\"]')", submit)
        self.assertIn(", timeout=2400", submit)
        self.assertIn(", max_bytes=4294967296", submit)
        self.assertLess(submit.index("timeout=2400"), submit.index("max_bytes=4294967296"))
        self.assert_root_requests(stub)

    def test_other_entry_requests_do_not_inherit_the_triage_budget(self):
        cases = []

        stub = RecordingStub(state="FINISHED")
        self.run_with_stub(
            stub,
            lambda _service, backend: backend.start_collection(
                "C.one", TRIAGE, {"Targets": '["_BasicCollection"]'}, timeout=2400
            ),
        )
        cases.append(("generic_same_artifact", stub.submissions[0], "timeout=2400"))

        stub = RecordingStub(state="FINISHED")
        self.run_with_stub(
            stub,
            lambda _service, backend: backend.start_collection(
                "C.one", "Windows.System.Pslist"
            ),
        )
        cases.append(("dynamic_pslist", stub.submissions[0], None))

        stub = RecordingStub(state="FINISHED")
        self.run_with_stub(
            stub,
            lambda service, _backend: service.collect_file(r"C:\fixture\one.txt"),
        )
        cases.append(("fixed_collect_file", stub.submissions[0], "timeout=120"))

        stub = RecordingStub(installed={KILL}, state="FINISHED")
        self.run_with_stub(stub, lambda service, _backend: service.kill_process(123))
        cases.append(("fixed_kill_process", stub.submissions[0], "timeout=120"))

        stub = RecordingStub(state="FINISHED")
        self.run_with_stub(
            stub,
            lambda service, _backend: service.start_hunt(HUNT_ARTIFACT, None, "budget"),
        )
        cases.append(("start_hunt", stub.submissions[0], None))

        for name, submit, expected_timeout in cases:
            with self.subTest(entry=name):
                self.assertNotIn("max_bytes=4294967296", submit)
                self.assertNotIn("max_bytes=8589934592", submit)
                if expected_timeout is None:
                    self.assertNotIn("timeout=", submit)
                else:
                    self.assertIn(expected_timeout, submit)

        memory = RecordingStub(state="FINISHED")
        self.run_with_stub(
            memory,
            lambda _service, backend: backend.start_collection(
                "C.one", "Windows.Memory.Acquisition"
            ),
        )
        self.assertEqual(len(memory.submissions), 1)
        self.assertIn("timeout=3600", memory.submissions[0])
        self.assertIn("max_bytes=8589934592", memory.submissions[0])
        self.assertNotIn("max_bytes=4294967296", memory.submissions[0])
        print(
            json.dumps(
                {
                    "b03_requests": [
                        {"entry": name, "submit_query": submit}
                        for name, submit, _timeout in cases
                    ]
                    + [
                        {
                            "entry": "memory_acquisition",
                            "submit_query": memory.submissions[0],
                        }
                    ]
                },
                sort_keys=True,
            )
        )

    def test_dependency_and_initial_states_are_single_attempt_and_verbatim(self):
        missing = RecordingStub()
        with self.assertRaises(DependencyMissingError):
            self.run_with_stub(
                missing, lambda service, _backend: service.collect_forensic_triage()
            )
        self.assertEqual(missing.submissions, [])

        state_attempts = {}
        for state in ("WAITING", "FINISHED", "ERROR"):
            with self.subTest(state=state):
                stub = RecordingStub(installed={TRIAGE}, state=state)
                result = self.run_with_stub(
                    stub, lambda service, _backend: service.collect_forensic_triage()
                )
                self.assertEqual(result.state, state)
                self.assertEqual(len(stub.submissions), 1)
                state_attempts[state] = len(stub.submissions)

        absent = RecordingStub(installed={TRIAGE}, state=None)
        with self.assertRaises(BackendError):
            self.run_with_stub(
                absent, lambda service, _backend: service.collect_forensic_triage()
            )
        self.assertEqual(len(absent.submissions), 1)
        print(
            json.dumps(
                {
                    "b04_attempts": {
                        "dependency_missing": len(missing.submissions),
                        **state_attempts,
                        "missing_state": len(absent.submissions),
                    }
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    unittest.main()

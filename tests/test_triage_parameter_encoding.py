from __future__ import annotations

import json
import re
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import velociraptor_api
from velociraptor_api import normalize_env_dict
from velociraptor_fixed_tools import FixedToolService
from velociraptor_mcp_core import TargetContext, VelociraptorBackend


def decode_triage_targets(encoded: str) -> list[str]:
    if not (encoded.startswith("'") and encoded.endswith("'")):
        raise AssertionError(
            f"Targets must be one JSON string at the final env boundary, got {encoded}"
        )
    decoded_vql_string = encoded[1:-1].replace(r"\'", "'").replace(r"\\", "\\")
    decoded = json.loads(decoded_vql_string)
    if decoded != ["_BasicCollection"]:
        raise AssertionError(f"unexpected triage target array: {decoded}")
    return decoded


class RecordingStub:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def Query(self, request):
        query = request.Query[0].VQL
        self.queries.append(query)
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
            rows = [{"name": "Windows.Triage.Targets"}]
        elif "LET collection <= collect_client" in query:
            rows = [{"flow_id": "F.triage"}]
        elif "FROM flows(" in query:
            rows = [{"state": "WAITING"}]
        else:
            raise AssertionError(f"unexpected external query: {query}")
        return [SimpleNamespace(Response=json.dumps(rows), error="", log="")]


class TriageParameterEncodingTests(unittest.TestCase):
    def test_fixed_triage_reaches_submit_boundary_as_json_array_string(self):
        stub = RecordingStub()
        backend = VelociraptorBackend()
        with (
            tempfile.TemporaryDirectory() as download_root,
            patch.object(velociraptor_api, "stub", stub),
            patch.object(velociraptor_api, "_stub_created_at", time.monotonic()),
        ):
            service = FixedToolService(
                [], TargetContext(backend), backend, download_root=download_root
            )
            result = service.collect_forensic_triage()

        self.assertEqual(result.flow_id, "F.triage")
        submit_queries = [
            query for query in stub.queries if "LET collection <= collect_client" in query
        ]
        self.assertEqual(len(submit_queries), 1)
        submit = submit_queries[0]
        self.assertIn("artifacts='Windows.Triage.Targets'", submit)
        self.assertIn(", timeout=2400", submit)

        match = re.search(r"env=dict\(Targets=(.*?)\), timeout=2400", submit)
        self.assertIsNotNone(match, submit)
        encoded = match.group(1)
        self.assertEqual(decode_triage_targets(encoded), ["_BasicCollection"])

    def test_triage_boundary_rejects_bare_or_wrong_target_values(self):
        for encoded in ("_BasicCollection", "['_BasicCollection']", "'[\"_Live\"]'"):
            with self.subTest(encoded=encoded), self.assertRaises(AssertionError):
                decode_triage_targets(encoded)

    def test_shared_parameter_serializer_keeps_existing_scalar_and_list_semantics(self):
        self.assertEqual(
            normalize_env_dict(
                {
                    "Text": "a'b\\c",
                    "Flag": True,
                    "Count": 7,
                    "Choices": ["one", 'two"\\'],
                }
            ),
            "Text='a\\'b\\\\c',Flag=TRUE,Count=7,Choices=['one', 'two\"\\\\']",
        )


if __name__ == "__main__":
    unittest.main()

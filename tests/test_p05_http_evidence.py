"""Future Windows mock-HTTP contracts for P05 raw entry-gate evidence.

The behavior tests are deliberately Windows-gated.  They use an in-process
``http.client`` stand-in, never a VM, host port, or external network.  This
This source includes only an AST static check; behavior execution is reserved
for the future Windows acceptance batch.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _counter(count: int) -> dict:
    stdout = json.dumps({"handler_count": count}, sort_keys=True)
    stderr = ""
    return {
        "schema_version": 1,
        "kind": "p05-http-handler-counter-v1",
        "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
        "run_id": "http-evidence-run",
        "restore_attempt_id": "http-evidence-restore",
        "count": count,
        "instance": "instance-1",
        "time": _utc(),
        "command": {
            "argv": ["Get-P05McpHandlerCount", "-ReadOnly"],
            "command_line": "Get-P05McpHandlerCount -ReadOnly",
            "exit_status": {"code": 0},
        },
        "output": {
            "stdout": stdout,
            "stdout_size": len(stdout.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr": stderr,
            "stderr_size": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        },
    }


class _Response:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.status = status
        self.reason = "synthetic"
        self._headers = headers
        self._body = body

    def getheaders(self):
        return list(self._headers)

    def read(self) -> bytes:
        return self._body


class _FakeConnection:
    """A no-socket HTTP/1.1 endpoint which observes the constructed headers."""

    count = 0
    requests: list[dict] = []

    def __init__(self, host, port, timeout) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.headers: list[tuple[str, str]] = []
        self.body = b""
        self.putrequest_args = None

    def putrequest(self, method, target, *, skip_host, skip_accept_encoding) -> None:
        self.putrequest_args = (method, target, skip_host, skip_accept_encoding)

    def putheader(self, name, value) -> None:
        self.headers.append((name, value))

    def endheaders(self, body) -> None:
        self.body = body

    def getresponse(self):
        headers = {name.casefold(): value for name, value in self.headers}
        payload = json.loads(self.body)
        _FakeConnection.requests.append({"headers": headers, "putrequest": self.putrequest_args})
        authorized = headers.get("authorization") == "Bearer in-memory-test-token-0123456789-abcdef0123456789"
        host = headers.get("host")
        origin = headers.get("origin")
        if not authorized:
            return _Response(401, [], b'{"jsonrpc":"2.0","error":{"code":-1}}')
        if host is None:
            return _Response(400, [], b'{"jsonrpc":"2.0","error":{"code":-1}}')
        if host != "192.168.204.232:28790":
            return _Response(421, [], b'{"jsonrpc":"2.0","error":{"code":-1}}')
        if origin == "https://not-allowed.example":
            return _Response(403, [], b'{"jsonrpc":"2.0","error":{"code":-1}}')
        _FakeConnection.count += 1
        response = {
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "synthetic", "version": "1"},
            },
        }
        return _Response(
            200,
            [("Mcp-Session-Id", "synthetic-session"), ("X-MCP-Server-Instance", "instance-1")],
            json.dumps(response, separators=(",", ":")).encode("utf-8"),
        )

    def close(self) -> None:
        pass


@unittest.skipUnless(sys.platform == "win32", "P05 raw HTTP behavior tests run on future Windows acceptance")
class HttpEvidenceWindowsTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeConnection.count = 0
        _FakeConnection.requests = []

    def test_collects_and_recomputes_all_seven_cases_without_a_token_in_files(self) -> None:
        from tests import p05_http_evidence as evidence

        def reader():
            return _counter(_FakeConnection.count)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evidence.http.client, "HTTPConnection", _FakeConnection
        ):
            result = evidence.probe_entry_gate(
                evidence.EXPECTED_ENDPOINT,
                "in-memory-test-token-0123456789-abcdef0123456789",
                "https://allowed.example",
                reader,
                "http-evidence-run",
                "http-evidence-restore",
                Path(directory),
            )
            recomputed = evidence.verify_entry_gate_raw(
                result["entry_gate_path"],
                bundle_root=Path(directory),
                run_id="http-evidence-run",
                restore_attempt_id="http-evidence-restore",
                endpoint=evidence.EXPECTED_ENDPOINT,
                allowed_origin="https://allowed.example",
            )
            self.assertEqual(recomputed["case_count"], 7)
            self.assertEqual(_FakeConnection.count, 2)
            self.assertNotIn("host", _FakeConnection.requests[4]["headers"])
            self.assertEqual(_FakeConnection.requests[4]["putrequest"][2:], (True, True))
            for file in result["evidence_dir"].rglob("*"):
                if file.is_file():
                    self.assertNotIn(b"in-memory-test-token-0123456789-abcdef0123456789", file.read_bytes())

    def test_verifier_rejects_a_200_header_only_positive_without_initialize_json(self) -> None:
        from tests import p05_http_evidence as evidence

        def reader():
            return _counter(_FakeConnection.count)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            evidence.http.client, "HTTPConnection", _FakeConnection
        ):
            result = evidence.probe_entry_gate(
                evidence.EXPECTED_ENDPOINT, "in-memory-test-token-0123456789-abcdef0123456789", "https://allowed.example", reader,
                "http-evidence-run", "http-evidence-restore", Path(directory),
            )
            path = result["evidence_dir"] / "cases" / "no_origin.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["response"]["body"]["text"] = "{}"
            raw = document["response"]["body"]["text"].encode("utf-8")
            document["response"]["body"]["size"] = len(raw)
            document["response"]["body"]["sha256"] = hashlib.sha256(raw).hexdigest()
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            entry = json.loads(result["entry_gate_path"].read_text(encoding="utf-8"))
            raw_case = path.read_bytes()
            entry["cases"]["no_origin"]["size"] = len(raw_case)
            entry["cases"]["no_origin"]["sha256"] = hashlib.sha256(raw_case).hexdigest()
            with self.assertRaisesRegex(evidence.EntryGateEvidenceError, "initialize response"):
                evidence.verify_entry_gate_raw(
                    entry,
                    bundle_root=Path(directory),
                    run_id="http-evidence-run",
                    restore_attempt_id="http-evidence-restore",
                    endpoint=evidence.EXPECTED_ENDPOINT,
                    allowed_origin="https://allowed.example",
                )

    def test_failed_counter_discovery_original_is_retained_without_synthesizing_a_case(self) -> None:
        from tests import p05_http_evidence as evidence

        original = {
            "schema_version": 1,
            "kind": "p05-service-dispatch-discovery-v1",
            "output": {"stdout": "all raw candidates", "stderr": ""},
        }

        class DiscoveryFailure(RuntimeError):
            raw_original = original

        def reader():
            raise DiscoveryFailure("selection failed")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(evidence.EntryGateEvidenceError) as raised:
                evidence.probe_entry_gate(
                    evidence.EXPECTED_ENDPOINT,
                    "in-memory-test-token-0123456789-abcdef0123456789",
                    "https://allowed.example",
                    reader,
                    "http-evidence-run",
                    "http-evidence-restore",
                    Path(directory),
                )
            # Parse the retained original before the TemporaryDirectory exits.
            failure = json.loads(
                (raised.exception.evidence_dir / "entry-gate-probe-failure.json").read_text(encoding="utf-8")
            )
        self.assertEqual(failure["counter_failure"], original)
        self.assertNotIn("cases", failure)


class HttpEvidenceStaticTests(unittest.TestCase):
    def test_module_is_parseable_without_starting_http_or_a_vm(self) -> None:
        source = Path(__file__).with_name("p05_http_evidence.py")
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

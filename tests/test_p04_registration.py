from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from mcp.server.mcpserver import MCPServer

import velociraptor_fixed_tools as fixed
from velociraptor_dynamic_artifacts import (
    APPROVED_WINDOWS_ARTIFACTS,
    ArtifactRegistryError,
    ArtifactSpec,
    _strict_tool_schema,
)
from velociraptor_mcp_core import FlowReferenceResult, TargetContext


REPO_ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    def list_windows_clients(self):
        return [{"client_id": "C.one"}]

    def client_id_exists(self, client_id):
        return client_id == "C.one"


def _dummy_dynamic_server():
    server = MCPServer("p04-registration")
    specs = []

    def handler() -> FlowReferenceResult:
        return FlowReferenceResult(
            operation="test", status="success", warnings=[], flow_id="F.test"
        )

    for name in APPROVED_WINDOWS_ARTIFACTS:
        server.add_tool(handler, name=name, description="fixture")
        _strict_tool_schema(server._tool_manager.get_tool(name))
        specs.append(
            ArtifactSpec(
                name=name,
                description="fixture",
                definition_sha256="0" * 64,
                parameters=(),
            )
        )
    return server, tuple(specs)


class CombinedRegistrationTests(unittest.TestCase):
    def test_combined_candidate_has_exactly_118_plus_12(self):
        server, specs = _dummy_dynamic_server()
        backend = FakeBackend()
        fixed.register_fixed_tools(
            server,
            specs,
            TargetContext(backend),
            backend,
            download_root=None,
        )
        fixed.validate_combined_registry(server, specs)
        self.assertEqual(len(server._tool_manager._tools), 130)
        self.assertEqual(
            set(server._tool_manager._tools),
            set(APPROVED_WINDOWS_ARTIFACTS).union(fixed.FIXED_TOOL_NAMES),
        )

    def test_fixed_name_conflict_fails_before_any_fixed_registration(self):
        server, specs = _dummy_dynamic_server()

        def occupied() -> FlowReferenceResult:
            return FlowReferenceResult(
                operation="test", status="success", warnings=[], flow_id="F.test"
            )

        server.add_tool(occupied, name="run_vql")
        before = set(server._tool_manager._tools)
        with self.assertRaisesRegex(ArtifactRegistryError, "fixed tool name conflicts"):
            fixed.register_fixed_tools(
                server,
                specs,
                TargetContext(FakeBackend()),
                FakeBackend(),
                download_root=None,
            )
        self.assertEqual(set(server._tool_manager._tools), before)

    def test_all_startup_fault_injections_are_nonzero_and_stdout_clean(self):
        fixture = REPO_ROOT / "tests" / "p04_fixture_server.py"
        for failure in (
            "dynamic_fixed_conflict",
            "fixed_duplicate",
            "invalid_input_schema",
            "missing_output_schema",
            "invalid_output_schema",
            "nth_registration",
        ):
            with self.subTest(failure=failure):
                env = dict(os.environ)
                env["P04_FIXTURE_FAILURE"] = failure
                completed = subprocess.run(
                    [sys.executable, "-m", "tests.p04_fixture_server"],
                    cwd=REPO_ROOT,
                    env=env,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                stderr = completed.stderr.decode("utf-8", errors="replace")
                self.assertIn("P04 fixture startup failed", stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertNotIn("api_client.yaml", stderr)


if __name__ == "__main__":
    unittest.main()

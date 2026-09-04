from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from velociraptor_dynamic_artifacts import (
    APPROVED_WINDOWS_ARTIFACTS,
    EXCLUDED_PARAMETER_TYPES,
    validate_artifact_definitions,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
REMOVED_TOOLS = {
    "collect_artifact",
    "hunt_across_fleet",
    "list_windows_artifacts",
    "list_linux_artifacts",
    "list_macos_artifacts",
}
FIXED_TOOLS = {
    "run_vql",
    "start_hunt",
    "get_hunt_status",
    "stop_hunt",
    "get_flow_status",
    "get_flow_results",
    "list_flow_files",
    "download_flow_file",
    "cancel_flow",
    "collect_file",
    "collect_forensic_triage",
    "kill_process",
}


async def run_session(script: Path, calls, *, env=None, list_twice=False):
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(script)],
            cwd=REPO_ROOT,
            env=env,
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                first = (await session.list_tools()).tools
                second = (await session.list_tools()).tools if list_twice else []
                results = [await session.call_tool(name, args) for name, args in calls]
        stderr_file.flush()
        stderr_file.seek(0)
        return initialized, first, second, results, stderr_file.read()
    finally:
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)


def tool_list_digest(tools) -> str:
    payload = [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
            "outputSchema": tool.output_schema,
        }
        for tool in tools
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class AtomicFixtureTests(unittest.TestCase):
    def test_five_startup_failures_are_nonzero_and_stdout_clean(self):
        fixture = REPO_ROOT / "tests" / "p03_fixture_server.py"
        expected = {
            "connection": "connection unavailable",
            "missing": "missing approved artifacts",
            "type": "not CLIENT",
            "conflict": "name conflicts",
            "schema": "schema is invalid",
        }
        for failure, message in expected.items():
            with self.subTest(failure=failure):
                env = dict(os.environ)
                env["P03_FIXTURE_FAILURE"] = failure
                completed = subprocess.run(
                    [sys.executable, str(fixture)],
                    cwd=REPO_ROOT,
                    env=env,
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                stderr = completed.stderr.decode("utf-8", errors="replace")
                self.assertIn(message, stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertNotIn("api_client.yaml", stderr)

    def test_fixture_schema_alias_validation_and_structured_call(self):
        fixture = REPO_ROOT / "tests" / "p03_fixture_server.py"
        _, tools, _, results, stderr = asyncio.run(
            run_session(
                fixture,
                [
                    ("Windows.Fixture.Dynamic", {"Unexpected": True}),
                    ("Windows.Fixture.Dynamic", {"Boot execute": None}),
                    ("Windows.Fixture.Dynamic", {"Boot execute": "false"}),
                    ("Windows.Fixture.Dynamic", {"Mode": "Unknown"}),
                    ("Windows.Fixture.Dynamic", {"Needle": "["}),
                    ("Windows.Fixture.Dynamic", {"Boot execute": False, "Mode": "Safe"}),
                ],
            )
        )
        self.assertEqual(len(tools), 1)
        schema = tools[0].input_schema
        self.assertEqual(set(schema["properties"]), {"Boot execute", "Mode", "Needle"})
        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn("default", schema["properties"]["Boot execute"])
        for rejected in results[:5]:
            self.assertTrue(rejected.is_error)
        self.assertFalse(results[5].is_error)
        self.assertEqual(results[5].content, [])
        self.assertEqual(results[5].structured_content["flow_id"], "F.fixture.1")
        self.assertNotIn("Traceback", stderr)


class DocumentationBoundaryTests(unittest.TestCase):
    def test_both_readmes_explain_the_six_public_terms_and_platform_boundary(self):
        terms = (
            "Dynamic artifact tool",
            "Allowlist",
            "Root organization",
            "Flow",
            "Windows-only",
            "stdio",
        )
        for relative in ("README.md", "agent_poc/README.md"):
            with self.subTest(path=relative):
                content = (REPO_ROOT / relative).read_text(encoding="utf-8")
                for term in terms:
                    self.assertIn(term, content)
                self.assertIn("Linux", content)
                self.assertIn("TODO", content)
                self.assertIn("macOS", content)
                self.assertIn("not supported", content)


class RealBridgeDynamicTests(unittest.TestCase):
    def test_real_metadata_schema_inventory_stability_and_flow(self):
        config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "").strip()
        self.assertTrue(config, "VELOCIRAPTOR_API_CONFIG is required for Win10 acceptance")
        self.assertTrue(Path(config).is_file(), "configured API file must exist")

        import velociraptor_api

        velociraptor_api.init_stub(config)
        rows = velociraptor_api.read_root_artifact_definitions()
        specs = validate_artifact_definitions(rows)
        self.assertEqual(len(specs), 118)

        env = dict(os.environ)
        env["VELOCIRAPTOR_API_CONFIG"] = config
        initialized, first, second, results, stderr = asyncio.run(
            run_session(
                REPO_ROOT / "mcp_velociraptor_bridge.py",
                [("Windows.System.Pslist", {"ProcessRegex": "^__mcp_p03_no_match__$"})],
                env=env,
                list_twice=True,
            )
        )
        self.assertEqual(initialized.server_info.name, "velociraptor-mcp")
        names = {tool.name for tool in first}
        self.assertEqual(names, set(APPROVED_WINDOWS_ARTIFACTS) | FIXED_TOOLS)
        self.assertEqual(len(names), 130)
        self.assertTrue(names.isdisjoint(REMOVED_TOOLS))
        self.assertFalse(any(name.startswith(("linux_", "macos_", "windows_")) for name in names))
        self.assertEqual(tool_list_digest(first), tool_list_digest(second))

        by_name = {tool.name: tool for tool in first}
        public_parameter_count = sum(
            len(tool.input_schema.get("properties", {}))
            for name, tool in by_name.items()
            if name in APPROVED_WINDOWS_ARTIFACTS
        )
        expected_public_count = sum(
            1
            for spec in specs
            for parameter in spec.parameters
            if parameter.kind not in EXCLUDED_PARAMETER_TYPES
        )
        self.assertEqual((public_parameter_count, expected_public_count), (499, 499))
        json_types = {
            "": "string",
            "string": "string",
            "regex": "string",
            "yara": "string",
            "timestamp": "string",
            "csv": "string",
            "bool": "boolean",
            "int": "integer",
            "int64": "integer",
            "float": "number",
            "choices": "string",
            "multichoice": "array",
        }
        formats = {
            "regex": "regex",
            "yara": "yara",
            "timestamp": "velociraptor-timestamp",
            "csv": "text/csv",
        }
        for spec in specs:
            tool = by_name[spec.name]
            self.assertEqual(tool.description, spec.description)
            self.assertFalse(tool.input_schema["additionalProperties"])
            self.assertEqual(tool.input_schema.get("required", []), [])
            properties = tool.input_schema.get("properties", {})
            self.assertEqual(
                set(properties),
                {parameter.name for parameter in spec.exposed_parameters},
            )
            self.assertNotIn("YaraUrl", properties)
            for parameter in spec.exposed_parameters:
                field = properties[parameter.name]
                self.assertEqual(field["type"], json_types[parameter.kind])
                self.assertEqual(field["description"], parameter.description)
                self.assertEqual(field["title"], parameter.friendly_name or parameter.name)
                self.assertEqual(field["x-velociraptor-type"], parameter.kind)
                self.assertEqual(field["x-velociraptor-default"], parameter.default)
                self.assertNotIn("default", field)
                if parameter.kind in formats:
                    self.assertEqual(field["format"], formats[parameter.kind])
                if parameter.kind == "choices":
                    self.assertEqual(field["enum"], list(parameter.choices))
                if parameter.kind == "multichoice":
                    self.assertEqual(field["items"]["enum"], list(parameter.choices))

        result = results[0]
        self.assertFalse(result.is_error)
        self.assertEqual(result.content, [])
        self.assertTrue(result.structured_content["flow_id"].startswith("F."))
        self.assertTrue(result.structured_content["status"])
        self.assertEqual(result.structured_content["operation"], "start_artifact_collection")
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()

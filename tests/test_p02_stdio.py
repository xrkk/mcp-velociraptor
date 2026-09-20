from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


REPO_ROOT = Path(__file__).resolve().parents[1]


async def run_session(script: Path, calls, *, env=None):
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
                initialize_result = await session.initialize()
                tools_result = await session.list_tools()
                results = []
                for name, arguments in calls:
                    results.append(await session.call_tool(name, arguments))
        stderr_file.flush()
        stderr_file.seek(0)
        return initialize_result, tools_result.tools, results, stderr_file.read()
    finally:
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)


class FixtureStdioTests(unittest.TestCase):
    def test_structured_results_schema_cache_and_clean_restart(self):
        fixture = REPO_ROOT / "tests" / "p02_fixture_server.py"
        calls = [("p02_success", {}), ("p02_error", {}), ("p02_target", {}), ("p02_target", {})]
        initialized, tools, results, stderr = asyncio.run(run_session(fixture, calls))
        self.assertTrue(initialized.server_info.name)
        by_name = {tool.name: tool for tool in tools}
        self.assertEqual(set(by_name), {"p02_success", "p02_error", "p02_target"})
        schema = by_name["p02_success"].output_schema
        self.assertEqual(schema["type"], "object")
        self.assertTrue({"operation", "status", "data", "pagination"}.issubset(schema["required"]))
        target_input = by_name["p02_target"].input_schema
        self.assertEqual(target_input.get("properties", {}), {})

        success, failed, first_target, cached_target = results
        self.assertFalse(success.is_error)
        self.assertEqual(success.content, [])
        self.assertEqual(success.structured_content["data"], [{"value": 1}])
        self.assertIsNone(success.structured_content["pagination"]["next_cursor"])
        self.assertTrue(failed.is_error)
        self.assertEqual(failed.content, [])
        self.assertEqual(failed.structured_content["code"], "INVALID_ARGUMENT")
        self.assertEqual(first_target.structured_content["data"][0]["resolution_queries"], 1)
        self.assertEqual(cached_target.structured_content["data"][0]["resolution_queries"], 1)
        self.assertNotIn("Traceback", stderr)

        _, _, restarted, _ = asyncio.run(run_session(fixture, [("p02_target", {})]))
        self.assertEqual(restarted[0].structured_content["data"][0]["resolution_queries"], 1)


class RealBridgeStdioTests(unittest.TestCase):
    def test_real_bridge_server_and_endpoint_calls(self):
        config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "").strip()
        self.assertTrue(config, "VELOCIRAPTOR_API_CONFIG is required for Win10 acceptance")
        self.assertTrue(Path(config).is_file(), "configured API file must exist")

        import velociraptor_api

        velociraptor_api.init_stub(config)
        clients = velociraptor_api.list_windows_clients_strict()
        self.assertEqual(len(clients), 1)
        from velociraptor_mcp_core import TargetContext, VelociraptorBackend

        backend = VelociraptorBackend()
        target = TargetContext(backend)
        flow = target.run_with_client(
            lambda client_id: backend.start_collection(
                client_id,
                "Windows.System.Pslist",
                {"ProcessRegex": "^__mcp_p02_no_match__$"},
                timeout=60,
            )
        )
        self.assertTrue(flow.flow_id.startswith("F."))
        self.assertTrue(flow.status)
        self.assertNotEqual(flow.status, "SUBMITTED")

        env = dict(os.environ)
        env["VELOCIRAPTOR_API_CONFIG"] = config
        calls = [
            ("Windows.System.Pslist", {"ProcessRegex": "^__mcp_p02_no_match__$"}),
            ("get_flow_status", {"flow_id": flow.flow_id}),
        ]
        initialized, tools, results, stderr = asyncio.run(
            run_session(REPO_ROOT / "mcp_velociraptor_bridge.py", calls, env=env)
        )
        self.assertEqual(initialized.server_info.name, "velociraptor-mcp")
        names = {tool.name for tool in tools}
        self.assertIn("Windows.System.Pslist", names)
        self.assertNotIn("list_windows_artifacts", names)
        self.assertNotIn("client_info", names)
        self.assertIn("get_flow_status", names)
        self.assertEqual(len(names), 130)
        dynamic, lifecycle = results
        self.assertFalse(dynamic.is_error)
        self.assertEqual(dynamic.content, [])
        self.assertTrue(dynamic.structured_content["flow_id"].startswith("F."))
        self.assertEqual(dynamic.structured_content["operation"], "start_artifact_collection")
        self.assertFalse(lifecycle.is_error)
        self.assertEqual(lifecycle.content, [])
        self.assertEqual(lifecycle.structured_content["flow_id"], flow.flow_id)
        self.assertTrue(lifecycle.structured_content["state"])
        self.assertNotIn("ImportError", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()

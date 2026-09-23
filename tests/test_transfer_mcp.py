"""Local MCP SDK boundary and owned service lifecycle for six guest tools."""

import asyncio
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from mcp.server.mcpserver import MCPServer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError

from tests.test_p04_registration import _dummy_dynamic_server, FakeBackend
from tests import test_transfer_guest as guest_fixture
from velo_transfer import Budget, capture_sources, create_bundle
from velo_transfer.errors import TransferContentError
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.guest_worker import same_process
from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES, TransferToolService, register_transfer_tools
from velo_transfer.protocol import publication_receipt, source_validation_receipt
from velociraptor_dynamic_artifacts import APPROVED_WINDOWS_ARTIFACTS, ArtifactRegistryError
from velociraptor_fixed_tools import FIXED_TOOL_NAMES, register_fixed_tools, validate_combined_registry
from velociraptor_mcp_core import TargetContext


def call(server, name, **arguments):
    return asyncio.run(server.call_tool(name, arguments))


class TransferMcpRegistrationTests(unittest.TestCase):
    def test_exact_136_and_legacy_schemas(self):
        server, specs = _dummy_dynamic_server()
        before = {name: (copy.deepcopy(tool.parameters), copy.deepcopy(tool.fn_metadata.output_schema))
                  for name, tool in server._tool_manager._tools.items()}
        backend = FakeBackend()
        register_fixed_tools(server, specs, TargetContext(backend), backend, download_root=None)
        for name in FIXED_TOOL_NAMES:
            tool = server._tool_manager.get_tool(name)
            before[name] = (copy.deepcopy(tool.parameters), copy.deepcopy(tool.fn_metadata.output_schema))
        manager = register_transfer_tools(server, factory=lambda: object())
        self.addCleanup(manager.shutdown)
        validate_combined_registry(server, specs, transfer_names=TRANSFER_TOOL_NAMES)
        self.assertEqual(len(server._tool_manager._tools), 136)
        self.assertEqual(set(server._tool_manager._tools), set(before) | set(TRANSFER_TOOL_NAMES))
        for name, (input_schema, output_schema) in before.items():
            tool = server._tool_manager.get_tool(name)
            self.assertEqual(tool.parameters, input_schema, name)
            self.assertEqual(tool.fn_metadata.output_schema, output_schema, name)
        golden = json.loads((Path(__file__).parent / "data" / "transfer_tools_golden.json").read_text())
        actual = {name: {"inputSchema": server._tool_manager.get_tool(name).parameters,
                         "outputSchema": server._tool_manager.get_tool(name).fn_metadata.output_schema}
                  for name in TRANSFER_TOOL_NAMES}
        self.assertEqual(actual, golden)
        for contract in actual.values():
            Draft202012Validator.check_schema(contract["inputSchema"])
            Draft202012Validator.check_schema(contract["outputSchema"])
            self.assertNotIn("client_id", contract["inputSchema"].get("properties", {}))

    def test_collision_missing_and_extra_rejected(self):
        server, specs = _dummy_dynamic_server()
        backend = FakeBackend()
        register_fixed_tools(server, specs, TargetContext(backend), backend, download_root=None)
        register_transfer_tools(server, factory=lambda: object())
        with self.assertRaises(ArtifactRegistryError):
            register_transfer_tools(server, factory=lambda: object())
        validate_combined_registry(server, specs, transfer_names=TRANSFER_TOOL_NAMES)
        server.remove_tool("transfer_abort")
        with self.assertRaises(ArtifactRegistryError):
            validate_combined_registry(server, specs, transfer_names=TRANSFER_TOOL_NAMES)
        server.add_tool(lambda: {"x": 1}, name="unexpected")
        with self.assertRaises(ArtifactRegistryError):
            validate_combined_registry(server, specs, transfer_names=TRANSFER_TOOL_NAMES)

    def test_schema_rejects_nested_and_action_errors_before_side_effect(self):
        class Service:
            calls = 0
            def transfer_begin(self, request):
                self.calls += 1
                return {"ok": True}
            def transfer_finish(self, **kwargs):
                self.calls += 1
                return {"ok": True}
            def transfer_chunk(self, **kwargs):
                self.calls += 1
                return {"ok": True}
            def shutdown(self):
                pass
        service = Service()
        server = MCPServer("transfer-schema")
        register_transfer_tools(server, factory=lambda: service)
        Fixture = guest_fixture.GuestTests
        Fixture.setUp(self)
        source = self.read / "x"
        source.write_bytes(b"x")
        request = Fixture.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "x"}], self.host / "out")
        begin_schema = server._tool_manager.get_tool("transfer_begin").parameters
        self.assertTrue(Draft202012Validator(begin_schema).is_valid({"request": request}))
        for malformed in (
            dict(request, extra=True),
            dict(request, budget=dict(request["budget"], max_files=True)),
            dict(request, sources=[dict(request["sources"][0], extra=True)]),
            dict(request, package={"size": 1, "sha256": "0" * 64, "manifest_sha256": "0" * 64}),
        ):
            with self.subTest(malformed=malformed):
                self.assertFalse(Draft202012Validator(begin_schema).is_valid({"request": malformed}))
                with self.assertRaises(ToolError):
                    call(server, "transfer_begin", request=malformed)
        for args in (
            {"transfer_id": "x", "request_digest": "0" * 64, "offset": True, "count": 1},
            {"transfer_id": "x", "request_digest": "0" * 64, "offset": 0, "count": "1"},
            {"transfer_id": "x", "request_digest": "0" * 64, "offset": 0, "count": 1, "extra": 1},
        ):
            with self.assertRaises(ToolError):
                call(server, "transfer_chunk", **args)
        with self.assertRaises(ToolError):
            call(server, "transfer_finish", transfer_id="x",
                 request_digest="0" * 64, action="bad")
        self.assertEqual(service.calls, 0)

    def test_disabled_and_single_factory_instance(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            server = MCPServer("disabled")
            manager = register_transfer_tools(server)
            caps = call(server, "transfer_capabilities").structured_content
            output_schema = server._tool_manager.get_tool("transfer_capabilities").fn_metadata.output_schema
            Draft202012Validator(output_schema).validate(caps)
            self.assertEqual(caps["result"]["enabled"], False)
            disabled = call(server, "transfer_abort", transfer_id="x",
                request_digest="0" * 64).structured_content
            Draft202012Validator(server._tool_manager.get_tool("transfer_abort").fn_metadata.output_schema).validate(disabled)
            self.assertEqual(disabled["error"]["code"], "transfer_disabled")
            self.assertIsNone(manager._service)
            manager.shutdown()
        made = []
        class Service:
            def transfer_capabilities(self):
                return {"enabled": True}
            def transfer_status(self, transfer_id, request_digest):
                return {"local_phase": "SOURCE_READY"}
            def shutdown(self):
                made.append("shutdown")
        def factory():
            made.append("factory")
            return Service()
        server = MCPServer("reuse")
        manager = register_transfer_tools(server, factory=factory)
        self.assertEqual(call(server, "transfer_capabilities").structured_content["status"], "success")
        self.assertEqual(call(server, "transfer_status", transfer_id="x",
            request_digest="0" * 64).structured_content["status"], "success")
        self.assertEqual(made, ["factory"])
        manager.shutdown()
        self.assertEqual(made, ["factory", "shutdown"])

    def test_error_envelope_is_bounded_and_secrets_are_not_reflected(self):
        marker = "SYNTHETIC_PRIVATE_PAYLOAD_923"
        class Service:
            def transfer_chunk(self, **kwargs):
                raise TransferContentError("chunk_conflict")
            def shutdown(self):
                pass
        server = MCPServer("error-envelope")
        manager = register_transfer_tools(server, factory=Service)
        self.addCleanup(manager.shutdown)
        response = call(server, "transfer_chunk", transfer_id="x",
            request_digest="0" * 64, offset=0, count=1,
            data_base64=marker, chunk_sha256="0" * 64).structured_content
        self.assertEqual(response, {"schema": "velo.transfer.mcp.response.v1",
            "status": "error", "error": {"code": "chunk_conflict"}})
        self.assertNotIn(marker, json.dumps(response))
        class BadFactory:
            def __call__(self):
                raise RuntimeError(marker)
        server = MCPServer("factory-error")
        register_transfer_tools(server, factory=BadFactory())
        response = call(server, "transfer_capabilities").structured_content
        self.assertEqual(response["error"]["code"], "internal_error")
        self.assertNotIn(marker, json.dumps(response))

    def test_invalid_config_is_error_and_unknown_tool_is_sdk_error(self):
        from velo_transfer.windows_platform import WindowsObservation
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temporary:
            bad = Path(temporary) / "invalid-policy.json"
            bad.write_text("not-json")
            observation = WindowsObservation("Windows", "00000000-0000-4000-8000-000000000001", "boot")
            server = MCPServer("invalid-policy")
            manager = register_transfer_tools(server, factory=lambda: GuestTransferService(
                bad, _observation=observation, _acl_verifier=lambda path, kind: True))
            self.addCleanup(manager.shutdown)
            response = call(server, "transfer_capabilities").structured_content
            self.assertEqual(response["status"], "error")
            self.assertNotIn("not-json", json.dumps(response))
            with self.assertRaises(ToolError):
                call(server, "transfer_unknown")

    def test_production_create_server_registers_six_without_policy_factory(self):
        import mcp_velociraptor_bridge as bridge
        fixture, specs = _dummy_dynamic_server()
        def dynamic(server, *args, **kwargs):
            server._tool_manager._tools.update(fixture._tool_manager._tools)
            return specs
        with mock.patch.object(bridge, "init_stub"), \
                mock.patch.object(bridge, "read_root_artifact_definitions", return_value=[]), \
                mock.patch.object(bridge, "register_dynamic_artifact_tools", side_effect=dynamic), \
                mock.patch.object(bridge, "velociraptor_backend", FakeBackend()), \
                mock.patch.object(bridge, "target_context", TargetContext(FakeBackend())), \
                mock.patch.dict(os.environ, {"VELOCIRAPTOR_TRANSFER_POLICY": ""}):
            server = bridge.create_server()
        self.assertEqual(len(server._tool_manager._tools), 136)
        self.assertIsNone(server._guest_transfer_tools._service)
        server._guest_transfer_tools.shutdown()

    def test_bridge_shutdown_on_normal_stop_error_and_uncreated_service(self):
        import mcp_velociraptor_bridge as bridge
        from types import SimpleNamespace
        callbacks = []
        class Manager:
            def shutdown(self):
                callbacks.append("shutdown")
        server = SimpleNamespace(_guest_transfer_tools=Manager())
        config = SimpleNamespace(mode="http")
        with mock.patch.object(bridge, "resolve_transport_config", return_value=config), \
                mock.patch.object(bridge, "create_server", return_value=server), \
                mock.patch.object(bridge, "run_formal_http") as run:
            self.assertEqual(bridge.main(stop_requested=lambda: True), 0)
            run.assert_called_once()
        self.assertEqual(callbacks, ["shutdown"])
        with mock.patch.object(bridge, "resolve_transport_config", return_value=config), \
                mock.patch.object(bridge, "create_server", return_value=server), \
                mock.patch.object(bridge, "run_formal_http", side_effect=RuntimeError("synthetic")):
            with self.assertRaisesRegex(RuntimeError, "synthetic"):
                bridge.main()
        self.assertEqual(callbacks, ["shutdown", "shutdown"])
        failure = mock.Mock()
        class FailingManager:
            def shutdown(self):
                raise TransferContentError("worker_stop_unconfirmed")
        server._guest_transfer_tools = FailingManager()
        with mock.patch.object(bridge, "resolve_transport_config", return_value=config), \
                mock.patch.object(bridge, "create_server", return_value=server), \
                mock.patch.object(bridge, "run_formal_http"), \
                mock.patch("sys.stderr"):
            self.assertEqual(bridge.main(on_failure=failure), 2)
        failure.assert_called_once_with("TRANSFER_SHUTDOWN_FAILED")

    def test_formal_app_rejects_unauthenticated_and_wrong_host_before_tool(self):
        from starlette.testclient import TestClient
        from velociraptor_transport import TransportConfig, build_formal_http_app
        made = []
        def factory():
            made.append("constructed")
            raise RuntimeError("must not reach tool")
        server = MCPServer("transfer-gate")
        manager = register_transfer_tools(server, factory=factory)
        self.addCleanup(manager.shutdown)
        app = build_formal_http_app(server, TransportConfig("http", host="127.0.0.1",
            bearer_token="local-fixture-token"))
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "transfer_capabilities", "arguments": {}}}
        with TestClient(app) as client:
            missing = client.post("/mcp", json=payload,
                headers={"host": "127.0.0.1:28790"})
            self.assertEqual(missing.status_code, 401)
            bad_host = client.post("/mcp", json=payload,
                headers={"host": "wrong.example", "authorization": "Bearer local-fixture-token"})
            self.assertEqual(bad_host.status_code, 421)
            self.assertNotIn("local-fixture-token", missing.text + bad_host.text)
        self.assertEqual(made, [])

    def test_official_stdio_client_sees_136_and_disabled_envelope(self):
        async def session():
            with tempfile.TemporaryFile(mode="w+t") as stderr_file:
                env = dict(os.environ)
                env.pop("VELOCIRAPTOR_TRANSFER_POLICY", None)
                parameters = StdioServerParameters(command=sys.executable,
                    args=["-m", "tests.transfer_mcp_stdio_fixture"],
                    cwd=Path(__file__).parents[1], env=env)
                async with stdio_client(parameters, errlog=stderr_file) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        tools = (await client.list_tools()).tools
                        caps = await client.call_tool("transfer_capabilities", {})
                        disabled = await client.call_tool("transfer_abort", {
                            "transfer_id": "x", "request_digest": "0" * 64})
                        malformed = await client.call_tool("transfer_chunk", {
                            "transfer_id": "x", "request_digest": "0" * 64,
                            "offset": True, "count": 1, "extra": "SYNTHETIC_STDIO_PRIVATE_ARGUMENT"})
                stderr_file.seek(0)
                return tools, caps, disabled, malformed, stderr_file.read()
        tools, caps, disabled, malformed, stderr = asyncio.run(session())
        self.assertEqual(len(tools), 136)
        self.assertEqual({tool.name for tool in tools},
            set(TRANSFER_TOOL_NAMES) | set(FIXED_TOOL_NAMES) |
            set(APPROVED_WINDOWS_ARTIFACTS))
        self.assertEqual(caps.structured_content["result"]["enabled"], False)
        self.assertEqual(disabled.structured_content["error"]["code"], "transfer_disabled")
        self.assertTrue(malformed.is_error)
        self.assertNotIn("SYNTHETIC_STDIO_PRIVATE_ARGUMENT", malformed.model_dump_json() + stderr)
        self.assertIn("invalid_transfer_arguments", malformed.model_dump_json())
        self.assertNotIn("Traceback", stderr)


class TransferMcpGuestTests(unittest.TestCase):
    def setUp(self):
        guest_fixture.GuestTests.setUp(self)
        self.server = MCPServer("guest-fixture")
        self.manager = register_transfer_tools(self.server, factory=lambda: self.service)
        self.addCleanup(self.manager.shutdown)

    def request(self, *args, **kwargs):
        return guest_fixture.GuestTests.request(self, *args, **kwargs)

    def wait_phase(self, request, phase):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            response = call(self.server, "transfer_status", transfer_id=request["transfer_id"],
                            request_digest=request["request_digest"]).structured_content
            self.assertEqual(response["status"], "success")
            state = response["result"]
            if state["local_phase"] == phase and (state["worker"] is None or state["worker"]["stopped"]):
                return state
            time.sleep(0.02)
        self.fail(f"phase {phase} not reached")

    def test_real_local_pull_and_push_through_mcp_calls(self):
        source = self.read / "良性.txt"
        source.write_bytes(b"benign")
        pull = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "良性.txt"}], self.host / "published", transfer_id="pull")
        response = call(self.server, "transfer_begin", request=pull).structured_content
        self.assertEqual(response["status"], "success")
        ready = self.wait_phase(pull, "SOURCE_READY")
        part = call(self.server, "transfer_chunk", transfer_id="pull",
            request_digest=pull["request_digest"], offset=0, count=ready["package"]["size"]).structured_content
        self.assertEqual(part["status"], "success")
        self.assertEqual(hashlib.sha256(base64.b64decode(part["result"]["data_base64"])).hexdigest(),
                         part["result"]["chunk_sha256"])
        call(self.server, "transfer_finish", transfer_id="pull",
             request_digest=pull["request_digest"], action="prepare")
        prepared = self.wait_phase(pull, "SOURCE_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        published = publication_receipt(receipt["binding"], receipt,
            pull["expected_destination"], {"device": 1, "inode": 2})
        wrong = copy.deepcopy(published)
        wrong["manifest_sha256"] = "0" * 64
        rejected = call(self.server, "transfer_finish", transfer_id="pull",
            request_digest=pull["request_digest"], action="release",
            prepare_receipt=receipt, publication_receipt=wrong).structured_content
        self.assertEqual(rejected["status"], "error")
        self.assertEqual(self.wait_phase(pull, "SOURCE_PREPARED")["local_phase"], "SOURCE_PREPARED")
        call(self.server, "transfer_finish", transfer_id="pull",
             request_digest=pull["request_digest"], action="release",
             prepare_receipt=receipt, publication_receipt=published)
        self.assertEqual(self.wait_phase(pull, "SOURCE_RELEASED")["state_scope"], "guest_source")
        self.assertEqual(source.read_bytes(), b"benign")

        host_source = self.host / "host.txt"
        host_source.write_bytes(b"payload")
        specs = [{"absolute_path": str(host_source), "relative_path": "host.txt"}]
        budget = Budget(100, 100000, 12 * 1024 * 1024, 14 * 1024 * 1024, 0,
                        time.monotonic() + 60)
        manifest = capture_sources(self.host, specs, budget)
        bundle = self.host / "push.zip"
        package = create_bundle(self.host, specs, manifest, bundle, self.host, budget)
        push = self.request("push", specs, self.write / "published",
            {key: package[key] for key in ("size", "sha256", "manifest_sha256")}, transfer_id="push")
        self.assertEqual(call(self.server, "transfer_begin", request=push).structured_content["status"], "success")
        raw = bundle.read_bytes()
        answer = call(self.server, "transfer_chunk", transfer_id="push",
            request_digest=push["request_digest"], offset=0, count=len(raw),
            data_base64=base64.b64encode(raw).decode(),
            chunk_sha256=hashlib.sha256(raw).hexdigest()).structured_content
        self.assertEqual(answer["result"]["verified_offset"], len(raw))
        call(self.server, "transfer_finish", transfer_id="push",
             request_digest=push["request_digest"], action="prepare")
        prepared = self.wait_phase(push, "DEST_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        validation = source_validation_receipt(receipt["binding"], receipt,
            hashlib.sha256(b"host-fixture").hexdigest())
        wrong_validation = copy.deepcopy(validation)
        wrong_validation["binding"]["vm_epoch"] = "wrong"
        rejected = call(self.server, "transfer_finish", transfer_id="push",
            request_digest=push["request_digest"], action="commit",
            prepare_receipt=receipt, source_validation_receipt=wrong_validation).structured_content
        self.assertEqual(rejected["status"], "error")
        self.assertEqual(self.wait_phase(push, "DEST_PREPARED")["local_phase"], "DEST_PREPARED")
        call(self.server, "transfer_finish", transfer_id="push",
             request_digest=push["request_digest"], action="commit",
             prepare_receipt=receipt, source_validation_receipt=validation)
        published = self.wait_phase(push, "DEST_PUBLISHED")["terminal"]["publication_receipt"]
        call(self.server, "transfer_finish", transfer_id="push",
             request_digest=push["request_digest"], action="release",
             prepare_receipt=receipt, publication_receipt=published)
        self.assertEqual(self.wait_phase(push, "DEST_RELEASED")["state_scope"], "guest_destination")
        self.assertEqual((self.write / "published" / "host.txt").read_bytes(), b"payload")

    def test_manager_shutdown_stops_only_its_registered_worker(self):
        self.service._worker_delay = 2
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "out")
        response = call(self.server, "transfer_begin", request=request).structured_content
        owner = response["result"]["worker"]
        self.assertTrue(same_process(owner["pid"], owner["birth"]))
        self.manager.shutdown()
        self.assertFalse(same_process(owner["pid"], owner["birth"]))
        self.assertFalse(self.service._owned)
        self.assertEqual(source.read_bytes(), b"benign")

    def test_wrong_boot_and_unauthorized_source_fail_before_worker(self):
        from velo_transfer.windows_platform import WindowsObservation
        source = self.root / "outside.txt"
        source.write_bytes(b"benign")
        request = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "outside.txt"}], self.host / "out")
        rejected = call(self.server, "transfer_begin", request=request).structured_content
        self.assertEqual(rejected["status"], "error")
        self.assertEqual(rejected["error"]["code"], "path_outside_root")
        self.assertFalse((self.work / "tasks").exists())
        source = self.read / "inside.txt"
        source.write_bytes(b"benign")
        request = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "inside.txt"}], self.host / "out")
        self.service._test_observation = WindowsObservation("Windows", self.uuid, "wrong-boot")
        rejected = call(self.server, "transfer_begin", request=request).structured_content
        self.assertEqual(rejected["error"]["code"], "vm_identity_mismatch")
        self.assertFalse((self.work / "tasks").exists())


if __name__ == "__main__":
    unittest.main()

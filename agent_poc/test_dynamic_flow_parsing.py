"""Offline regression for dynamic artifact flow parsing in the shared client.

The chain under test is real: the dynamic artifact handler, the real result
models, ``call_tool_payload``/``_host_payload`` and the bounded model view.
Only the RPC edge (target, backend, SDK session) is faked; no Velociraptor
connection, VM, model API or production smoke is involved.

The dynamic Windows artifact contract is: ``operation`` is always
``start_artifact_collection`` (never the artifact/tool name) and ``status``
carries the real initial Flow state (WAITING/RUNNING/FINISHED/ERROR), while
fixed tools keep their own ``status="success"`` envelope with the initial
Flow state in ``state``/``flow_state``.
"""

import json
import unittest

from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from agent_poc.velociraptor_mcp_runtime import (
    TRANSFER_RESPONSE_SCHEMA,
    VIEW_SCHEMA,
    VelociraptorMCPClient,
)
from velociraptor_dynamic_artifacts import ArtifactSpec, make_artifact_handler
from velociraptor_mcp_core import (
    BackendError,
    FixedFlowReferenceResult,
    FlowReferenceResult,
    HuntStartedResult,
    success_result,
)

DYNAMIC_OPERATION = "start_artifact_collection"
FLOW_ID = "F.audit.offline"
CLIENT_ID = "C.audit.offline"
TOOL_NAME = "Windows.System.Pslist"

# Captured verbatim from the live 2.x SDK over a real stdio list_tools
# session (probe-output-schema.py, 2026-10-06): what a connected client
# actually receives for one dynamic and one fixed flow-reference tool.
DYNAMIC_OUTPUT_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "flow_id": {"title": "Flow Id", "type": "string"},
        "operation": {"title": "Operation", "type": "string"},
        "status": {"title": "Status", "type": "string"},
        "warnings": {
            "items": {"type": "string"},
            "title": "Warnings",
            "type": "array",
        },
    },
    "required": ["operation", "status", "flow_id"],
    "title": "FlowReferenceResult",
    "type": "object",
}

FIXED_OUTPUT_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "flow_id": {"title": "Flow Id", "type": "string"},
        "operation": {"title": "Operation", "type": "string"},
        "state": {"minLength": 1, "title": "State", "type": "string"},
        "status": {"const": "success", "title": "Status", "type": "string"},
        "warnings": {
            "items": {"type": "string"},
            "title": "Warnings",
            "type": "array",
        },
    },
    "required": ["operation", "status", "warnings", "flow_id", "state"],
    "title": "FixedFlowReferenceResult",
    "type": "object",
}

SPEC = ArtifactSpec(TOOL_NAME, "audit probe", "0" * 64, ())


class FakeTarget:
    def run_with_client(self, operation):
        return operation(CLIENT_ID)


class FakeBackend:
    """Replaces only the gRPC backend call the handler performs."""

    def __init__(self, state="WAITING"):
        self.calls = 0
        self.state = state

    def start_collection(self, *args):
        self.calls += 1
        if isinstance(self.state, Exception):
            raise self.state
        return FlowReferenceResult(
            operation="backend",
            status=self.state,
            flow_id=FLOW_ID,
        )


def real_dynamic_result(state):
    """A real handler output for one initial Flow state."""
    backend = FakeBackend(state)
    handler = make_artifact_handler(SPEC, FakeTarget(), backend, index=0)
    return handler()


def build_client(state="WAITING"):
    client = VelociraptorMCPClient(model="fake-model")
    backend = FakeBackend(state)

    class FakeSession:
        async def call_tool(self, name, arguments):
            handler = make_artifact_handler(SPEC, FakeTarget(), backend, index=0)
            return handler(**arguments)

    client.session = FakeSession()
    client.backend = backend
    return client


def view_object(payload):
    return VelociraptorMCPClient(model="fake-model")._model_view_object(payload)


class DynamicFlowParsingTests(unittest.IsolatedAsyncioTestCase):
    async def test_waiting_and_running_accepted_without_completion(self):
        for state in ("WAITING", "RUNNING"):
            with self.subTest(state=state):
                client = build_client(state)
                payload = await client.call_tool_payload(TOOL_NAME, {})
                self.assertTrue(payload["ok"], payload)
                self.assertNotEqual(payload.get("error"), {"code": "protocol_error"})
                structured = payload["structured_content"]
                self.assertEqual(structured["status"], state)
                self.assertEqual(structured["flow_id"], FLOW_ID)
                self.assertEqual(client.backend.calls, 1)
                view = view_object(payload)
                self.assertTrue(view["tool_ok"])
                self.assertEqual(view["status"], state)
                self.assertNotEqual(view["status"], "FINISHED")
                self.assertEqual(view["payload"]["flow_id"], FLOW_ID)

    async def test_finished_preserves_terminal_state(self):
        client = build_client("FINISHED")
        payload = await client.call_tool_payload(TOOL_NAME, {})
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["structured_content"]["status"], "FINISHED")
        self.assertEqual(payload["structured_content"]["flow_id"], FLOW_ID)
        view = view_object(payload)
        self.assertTrue(view["tool_ok"])
        self.assertEqual(view["status"], "FINISHED")

    async def test_error_state_is_business_failure_with_identity(self):
        client = build_client("ERROR")
        payload = await client.call_tool_payload(TOOL_NAME, {})
        self.assertFalse(payload["ok"])
        error = payload["error"]
        self.assertNotEqual(error, {"code": "protocol_error"})
        self.assertEqual(error["status"], "ERROR")
        self.assertEqual(error["flow_id"], FLOW_ID)
        self.assertEqual(payload["structured_content"]["status"], "ERROR")
        view = view_object(payload)
        self.assertFalse(view["tool_ok"])
        self.assertEqual(view["error"]["flow_id"], FLOW_ID)
        self.assertEqual(view["status"], "ERROR")

    async def test_unknown_state_stays_explicitly_unknown(self):
        client = build_client("UNFINISHED")
        payload = await client.call_tool_payload(TOOL_NAME, {})
        self.assertFalse(payload["ok"])
        error = payload["error"]
        self.assertNotEqual(error, {"code": "protocol_error"})
        self.assertEqual(error["code"], "unknown_flow_state")
        self.assertEqual(error["flow_id"], FLOW_ID)
        self.assertEqual(error["state"], "UNFINISHED")
        self.assertEqual(payload["structured_content"]["status"], "UNFINISHED")
        self.assertEqual(client.backend.calls, 1)
        view = view_object(payload)
        self.assertEqual(view["error"]["code"], "unknown_flow_state")
        self.assertEqual(view["status"], "UNFINISHED")

    async def test_wrong_or_missing_operation_is_protocol_error(self):
        result = real_dynamic_result("WAITING")
        result.structured_content["operation"] = TOOL_NAME
        client = build_client()
        payload = client._host_payload(TOOL_NAME, result)
        self.assertEqual(
            payload, {"ok": False, "error": {"code": "protocol_error"},
                      "structured_content": result.structured_content})

        result = real_dynamic_result("WAITING")
        del result.structured_content["operation"]
        payload = client._host_payload(TOOL_NAME, result)
        self.assertEqual(payload["error"], {"code": "protocol_error"})

    async def test_invalid_flow_id_is_protocol_error(self):
        client = build_client()
        for bad in ("", None, 123, []):
            with self.subTest(flow_id=bad):
                result = real_dynamic_result("WAITING")
                result.structured_content["flow_id"] = bad
                payload = client._host_payload(TOOL_NAME, result)
                self.assertEqual(payload["ok"], False)
                self.assertEqual(payload["error"], {"code": "protocol_error"})

    async def test_missing_or_invalid_status_is_protocol_error(self):
        client = build_client()
        result = real_dynamic_result("WAITING")
        del result.structured_content["status"]
        self.assertEqual(
            client._host_payload(TOOL_NAME, result)["error"],
            {"code": "protocol_error"})
        for bad in (None, "", 7, {"state": "WAITING"}):
            with self.subTest(status=bad):
                result = real_dynamic_result("WAITING")
                result.structured_content["status"] = bad
                payload = client._host_payload(TOOL_NAME, result)
                self.assertEqual(payload["error"], {"code": "protocol_error"})

    async def test_sdk_error_wins_over_body_success(self):
        client = build_client(BackendError(details={"operation": "x"}))
        payload = await client.call_tool_payload(TOOL_NAME, {})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "BACKEND_ERROR")

        forged = CallToolResult(
            content=[],
            structuredContent={
                "operation": TOOL_NAME, "status": "success",
                "warnings": [], "flow_id": FLOW_ID,
            },
            isError=True,
        )
        payload = build_client()._host_payload(TOOL_NAME, forged)
        self.assertFalse(payload["ok"])

    async def test_dynamic_body_not_promoted_for_undiscovered_tool(self):
        client = build_client()
        client.dynamic_flow_tools = frozenset()
        result = real_dynamic_result("WAITING")
        payload = client._host_payload(TOOL_NAME, result)
        self.assertEqual(payload["error"], {"code": "protocol_error"})

    async def test_load_tools_identifies_dynamic_flow_tools(self):
        client = build_client()

        class FakeListSession:
            async def list_tools(self, params=None):
                return ListToolsResult(
                    tools=[
                        Tool(
                            name=TOOL_NAME,
                            description="audit probe",
                            inputSchema={"type": "object", "properties": {},
                                         "required": []},
                            outputSchema=DYNAMIC_OUTPUT_SCHEMA,
                        ),
                        Tool(
                            name="collect_file",
                            description="fixed",
                            inputSchema={"type": "object", "properties": {},
                                         "required": []},
                            outputSchema=FIXED_OUTPUT_SCHEMA,
                        ),
                    ],
                    nextCursor=None,
                )

        client.session = FakeListSession()
        await client._load_tools()
        self.assertEqual(client.dynamic_flow_tools, frozenset({TOOL_NAME}))
        # With discovery done, the fixed tool keeps the strict envelope even
        # if its body were shaped like a dynamic flow contract.
        dynamic_shaped = CallToolResult(
            content=[],
            structuredContent={
                "operation": DYNAMIC_OPERATION, "status": "WAITING",
                "warnings": [], "flow_id": FLOW_ID,
            },
            isError=False,
        )
        payload = client._host_payload("collect_file", dynamic_shaped)
        self.assertEqual(payload["error"], {"code": "protocol_error"})


class FixedToolRegressionTests(unittest.TestCase):
    def _fixed_result(self, operation):
        return success_result(FixedFlowReferenceResult(
            operation=operation, status="success", warnings=[],
            flow_id=FLOW_ID, state="WAITING",
        ))

    def test_fixed_flow_tools_still_accepted_with_waiting_initial_state(self):
        client = build_client()
        for operation in ("collect_file", "kill_process",
                          "collect_forensic_triage"):
            with self.subTest(operation=operation):
                payload = client._host_payload(operation, self._fixed_result(operation))
                self.assertTrue(payload["ok"])
                # state=WAITING is the initial Flow state, not completion:
                # it must survive as-is and never imply FINISHED.
                self.assertEqual(payload["data"]["state"], "WAITING")
                self.assertEqual(payload["data"]["status"], "success")

    def test_start_hunt_envelope_unchanged(self):
        hunt = success_result(HuntStartedResult(
            operation="start_hunt", status="success", warnings=[],
            hunt_id="H.audit.offline", flow_id=FLOW_ID, client_id=CLIENT_ID,
            state="PAUSED", flow_state="WAITING",
        ))
        payload = build_client()._host_payload("start_hunt", hunt)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["flow_state"], "WAITING")
        self.assertEqual(payload["data"]["state"], "PAUSED")

    def test_fixed_tool_operation_mismatch_still_rejected(self):
        result = self._fixed_result("collect_file")
        payload = build_client()._host_payload("kill_process", result)
        self.assertEqual(payload["error"], {"code": "protocol_error"})

    def test_transfer_envelope_unchanged(self):
        client = build_client()
        ok = CallToolResult(
            content=[],
            structuredContent={
                "schema": TRANSFER_RESPONSE_SCHEMA,
                "status": "success",
                "result": {"transfer_id": "T.1"},
            },
            isError=False,
        )
        payload = client._host_payload("transfer_status", ok)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"], {"transfer_id": "T.1"})
        failed = CallToolResult(
            content=[],
            structuredContent={
                "schema": TRANSFER_RESPONSE_SCHEMA,
                "status": "failed",
                "error": {"code": "TRANSFER_STATE"},
            },
            isError=False,
        )
        payload = client._host_payload("transfer_status", failed)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], {"code": "TRANSFER_STATE"})

    def test_legacy_envelope_unchanged(self):
        legacy = CallToolResult(
            content=[TextContent(type="text", text='{"ok": true, "data": {"x": 1}}')],
            structuredContent=None,
            isError=False,
        )
        payload = build_client()._host_payload("legacy_tool", legacy)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["legacy_envelope"])
        self.assertEqual(payload["data"], {"x": 1})


class ModelViewBudgetTests(unittest.TestCase):
    def test_full_raw_result_preserved_for_recovery(self):
        client = build_client("WAITING")

        async def run():
            return await client.call_tool_payload(TOOL_NAME, {})

        import asyncio
        payload = asyncio.run(run())
        raw = client.last_tool_result
        self.assertEqual(raw["structuredContent"]["flow_id"], FLOW_ID)
        self.assertEqual(raw["structuredContent"]["status"], "WAITING")

        view = json.loads(client._model_view(payload))
        self.assertEqual(view["schema"], VIEW_SCHEMA)
        self.assertTrue(view["tool_ok"])
        self.assertEqual(view["status"], "WAITING")
        self.assertEqual(view["payload"]["flow_id"], FLOW_ID)
        # Budget semantics unchanged: the tiny flow reference is not cut.
        self.assertTrue(view["view_complete"])
        self.assertNotIn("payload_omitted", view)


if __name__ == "__main__":
    unittest.main()

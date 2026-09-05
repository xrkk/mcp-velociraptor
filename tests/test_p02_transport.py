"""ACC-P02-009/010: shared-registration dual transport and the formal entry gate.

Unit cases run anywhere; the protocol cases require the Win10 acceptance VM
with a reachable Velociraptor API (they boot the real registration path with
an injected fake backend through both transports).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from velociraptor_transport import (
    ALLOWED_ORIGINS_ENV,
    FORMAL_PATH,
    FORMAL_PORT,
    HOST_ENV,
    PATH_ENV,
    PORT_ENV,
    TEST_TRANSPORT,
    TOKEN_ENV,
    TRANSPORT_ENV,
    BearerAuthGate,
    ServerInstanceHeader,
    TransportConfigError,
    new_server_instance_id,
    resolve_transport_config,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "p02_transport_fixture.py"

TEST_TOKEN = "p02-transport-test-token"
FORMAL_URL = f"http://127.0.0.1:{FORMAL_PORT}{FORMAL_PATH}"


def _http_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env[TRANSPORT_ENV] = "http"
    env[HOST_ENV] = "127.0.0.1"
    env[TOKEN_ENV] = TEST_TOKEN
    env.pop(ALLOWED_ORIGINS_ENV, None)
    env.update(extra or {})
    return env


def _wait_port(host: str, port: int, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.25)
    raise TimeoutError(f"formal entry did not open {host}:{port}")


def _port_closed(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return False
    except OSError:
        return True


class ConfigResolutionTests(unittest.TestCase):
    def test_stdio_is_the_default_mode(self):
        config = resolve_transport_config({})
        self.assertEqual(config.mode, TEST_TRANSPORT)
        self.assertIsNone(config.host)

    def test_valid_formal_config_resolves(self):
        config = resolve_transport_config(
            {
                TRANSPORT_ENV: "http",
                HOST_ENV: "192.168.204.149",
                TOKEN_ENV: "secret-value",
                ALLOWED_ORIGINS_ENV: "https://a.example; https://b.example",
            }
        )
        self.assertEqual(config.mode, "http")
        self.assertEqual(config.host, "192.168.204.149")
        self.assertEqual(config.port, FORMAL_PORT)
        self.assertEqual(config.path, FORMAL_PATH)
        self.assertEqual(config.allowed_origins, ("https://a.example", "https://b.example"))

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config({TRANSPORT_ENV: "sse"})

    def test_missing_host_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config({TRANSPORT_ENV: "http", TOKEN_ENV: "t"})

    def test_wildcard_binds_are_rejected(self):
        for wildcard in ("0.0.0.0", "::"):
            with self.assertRaises(TransportConfigError):
                resolve_transport_config(
                    {TRANSPORT_ENV: "http", HOST_ENV: wildcard, TOKEN_ENV: "t"}
                )

    def test_wrong_port_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config(
                {
                    TRANSPORT_ENV: "http",
                    HOST_ENV: "192.168.204.149",
                    PORT_ENV: "28791",
                    TOKEN_ENV: "t",
                }
            )

    def test_non_integer_port_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config(
                {
                    TRANSPORT_ENV: "http",
                    HOST_ENV: "192.168.204.149",
                    PORT_ENV: "http",
                    TOKEN_ENV: "t",
                }
            )

    def test_wrong_path_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config(
                {
                    TRANSPORT_ENV: "http",
                    HOST_ENV: "192.168.204.149",
                    PATH_ENV: "/api",
                    TOKEN_ENV: "t",
                }
            )

    def test_empty_token_is_rejected(self):
        with self.assertRaises(TransportConfigError):
            resolve_transport_config(
                {TRANSPORT_ENV: "http", HOST_ENV: "192.168.204.149", TOKEN_ENV: " "}
            )

    def test_injected_bind_address_validator_runs(self):
        seen = []

        def validator(host: str) -> None:
            seen.append(host)
            if not host.startswith("192.168.204."):
                raise RuntimeError("not the measured NIC")

        good = resolve_transport_config(
            {TRANSPORT_ENV: "http", HOST_ENV: "192.168.204.149", TOKEN_ENV: "t"},
            bind_address_validator=validator,
        )
        self.assertEqual(seen, ["192.168.204.149"])
        self.assertEqual(good.host, "192.168.204.149")
        with self.assertRaises(TransportConfigError):
            resolve_transport_config(
                {TRANSPORT_ENV: "http", HOST_ENV: "10.0.0.5", TOKEN_ENV: "t"},
                bind_address_validator=validator,
            )


class ServerInstanceIdTests(unittest.TestCase):
    def test_ids_are_unique_hex_and_secret_free(self):
        first = new_server_instance_id()
        second = new_server_instance_id()
        self.assertNotEqual(first, second)
        int(first, 16)
        self.assertEqual(len(first), 32)
        for forbidden in ("DESKTOP", "mcp-velociraptor", "/", "C:", TEST_TOKEN):
            self.assertNotIn(forbidden, first)


class _RecordedSend:
    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.started: dict | None = None

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)
        if message["type"] == "http.response.start":
            self.started = message


def _http_scope(headers: list[tuple[bytes, bytes]]) -> dict:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": FORMAL_PATH,
        "headers": headers,
    }


async def _noop_receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


class CapturedApp:
    def __init__(self) -> None:
        self.calls = 0
        self.headers: list[tuple[bytes, bytes]] = []

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        self.headers = list(scope.get("headers", []))
        await _send_plain(send)


async def _send_plain(send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"ok"})


class BearerGateTests(unittest.TestCase):
    def _run(self, headers):
        app = CapturedApp()
        gate = BearerAuthGate(app, TEST_TOKEN)
        recorder = _RecordedSend()
        asyncio.run(gate(_http_scope(headers), _noop_receive, recorder))
        return app, recorder

    def test_missing_authorization_is_401(self):
        app, recorder = self._run([])
        self.assertEqual(app.calls, 0)
        self.assertEqual(recorder.started["status"], 401)

    def test_wrong_scheme_is_401(self):
        app, recorder = self._run([(b"authorization", f"Basic {TEST_TOKEN}".encode())])
        self.assertEqual(app.calls, 0)
        self.assertEqual(recorder.started["status"], 401)

    def test_wrong_token_is_401_without_leaking(self):
        app, recorder = self._run([(b"authorization", b"Bearer wrong-token")])
        self.assertEqual(app.calls, 0)
        self.assertEqual(recorder.started["status"], 401)
        body = b"".join(
            m.get("body", b"") for m in recorder.messages if m["type"] == "http.response.body"
        )
        self.assertNotIn(TEST_TOKEN.encode(), body)

    def test_correct_token_reaches_downstream(self):
        app, recorder = self._run([(b"authorization", f"Bearer {TEST_TOKEN}".encode())])
        self.assertEqual(app.calls, 1)
        self.assertEqual(recorder.started["status"], 200)


class InstanceHeaderTests(unittest.TestCase):
    def test_response_carries_stamped_header(self):
        app = CapturedApp()
        layer = ServerInstanceHeader(app, "instance-a")
        recorder = _RecordedSend()
        asyncio.run(layer(_http_scope([]), _noop_receive, recorder))
        headers = dict(recorder.started["headers"])
        self.assertEqual(headers[b"x-mcp-server-instance"], b"instance-a")

    def test_downstream_duplicate_header_is_replaced(self):
        async def downstream(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"x-mcp-server-instance", b"injected-by-app")],
                }
            )
            await send({"type": "http.response.body", "body": b""})

        layer = ServerInstanceHeader(downstream, "authoritative")
        recorder = _RecordedSend()
        asyncio.run(layer(_http_scope([]), _noop_receive, recorder))
        values = [
            value
            for name, value in recorder.started["headers"]
            if name == b"x-mcp-server-instance"
        ]
        self.assertEqual(values, [b"authoritative"])

    def test_forged_request_header_does_not_change_response(self):
        app = CapturedApp()
        layer = ServerInstanceHeader(app, "server-owned")
        recorder = _RecordedSend()
        scope = _http_scope([(b"x-mcp-server-instance", b"client-forged")])
        asyncio.run(layer(scope, _noop_receive, recorder))
        headers = dict(recorder.started["headers"])
        self.assertEqual(headers[b"x-mcp-server-instance"], b"server-owned")


def _stdio_session(script: Path, calls, *, env=None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run():
        stderr_file = tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8", delete=False
        )
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
                    tools = (await session.list_tools()).tools
                    results = [
                        await session.call_tool(name, arguments)
                        for name, arguments in calls
                    ]
            stderr_file.flush()
            stderr_file.seek(0)
            return initialized, tools, results, stderr_file.read()
        finally:
            stderr_file.close()

    return asyncio.run(run())


def _tool_schema_map(tools) -> dict:
    return {
        tool.name: {
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
        }
        for tool in tools
    }


class _FormalEntryProcess:
    def __init__(self, extra_env: dict[str, str] | None = None) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(FIXTURE)],
            cwd=REPO_ROOT,
            env=_http_env(extra_env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def __enter__(self) -> "_FormalEntryProcess":
        _wait_port("127.0.0.1", FORMAL_PORT)
        return self

    def __exit__(self, *exc_info) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)

    def stderr_text(self) -> str:
        return self.proc.stderr.read().decode("utf-8", "replace") if self.proc.stderr else ""


def _formal_http_session(calls, *, client_headers: dict[str, str] | None = None):
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def run():
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        headers.update(client_headers or {})
        async with httpx2.AsyncClient(headers=headers, timeout=30.0) as http:
            async with streamable_http_client(FORMAL_URL, http_client=http) as (
                read,
                write,
            ):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    tools = (await session.list_tools()).tools
                    results = [
                        await session.call_tool(name, arguments)
                        for name, arguments in calls
                    ]
        return initialized, tools, results

    return asyncio.run(run())


def _raw_rpc(payload: dict, *, headers: dict[str, str]):
    import httpx2

    async def run():
        base = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {TEST_TOKEN}",
        }
        base.update(headers)
        async with httpx2.AsyncClient(timeout=30.0) as http:
            return await http.post(FORMAL_URL, json=payload, headers=base)

    return asyncio.run(run())


def _initialize_payload() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "p02-raw-probe", "version": "0"},
        },
    }


REPRESENTATIVE_CALLS = [
    ("Windows.System.Pslist", {"ProcessRegex": "^__mcp_p02_no_match__$"}),
    ("get_flow_status", {"flow_id": "F.FAKE0001"}),
]


@unittest.skipUnless(
    os.environ.get("VELOCIRAPTOR_API_CONFIG", "").strip(),
    "formal transport acceptance requires the Win10 VM API config",
)
class SharedRegistrationTransportTests(unittest.TestCase):
    """ACC-P02-009: one registration, two transports, identical schemas."""

    def test_single_server_construction_and_full_registration(self):
        import mcp.server.mcpserver as mcpserver
        import mcp_velociraptor_bridge as bridge
        import velociraptor_dynamic_artifacts as dynamic

        original = mcpserver.MCPServer
        constructed: list[str] = []

        class CountingServer(original):
            def __init__(self, *args, **kwargs):
                name = args[0] if args else kwargs.get("name", "")
                constructed.append(name)
                super().__init__(*args, **kwargs)

        bridge.MCPServer = CountingServer
        dynamic.MCPServer = CountingServer
        try:
            server = bridge.create_server()
        finally:
            bridge.MCPServer = original
            dynamic.MCPServer = original
        self.assertEqual(constructed.count("velociraptor-mcp"), 1)
        self.assertEqual(len(server._tool_manager._tools), 130)

    def test_stdio_and_http_share_identical_toolset(self):
        _, stdio_tools, stdio_results, stderr = _stdio_session(
            FIXTURE, REPRESENTATIVE_CALLS
        )
        self.assertNotIn("Traceback", stderr)
        with _FormalEntryProcess():
            _, http_tools, http_results = _formal_http_session(REPRESENTATIVE_CALLS)
            stdio_map = _tool_schema_map(stdio_tools)
            http_map = _tool_schema_map(http_tools)
            self.assertEqual(set(stdio_map) - set(http_map), set())
            self.assertEqual(set(http_map) - set(stdio_map), set())
            self.assertEqual(len(stdio_map), 130)
            self.assertEqual(stdio_map, http_map)
            for stdio_result, http_result in zip(stdio_results, http_results):
                self.assertFalse(stdio_result.is_error)
                self.assertFalse(http_result.is_error)
                self.assertEqual(stdio_result.content, [])
                self.assertEqual(http_result.content, [])
                self.assertEqual(
                    stdio_result.structured_content, http_result.structured_content
                )
            self.assertEqual(stdio_results[0].structured_content["flow_id"], "F.FAKE0001")

    def test_instance_header_is_stable_and_survives_forged_request_header(self):
        with _FormalEntryProcess():
            first = _raw_rpc(_initialize_payload(), headers={})
            self.assertEqual(first.status_code, 200)
            instance_first = first.headers.get("x-mcp-server-instance")
            self.assertTrue(instance_first)
            session_id = first.headers.get("mcp-session-id")
            self.assertTrue(session_id)

            forged = _raw_rpc(
                _initialize_payload(),
                headers={"X-MCP-Server-Instance": "client-forged"},
            )
            self.assertEqual(forged.status_code, 200)
            self.assertEqual(forged.headers.get("x-mcp-server-instance"), instance_first)

            listing = _raw_rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
                headers={
                    "mcp-session-id": session_id,
                    "mcp-protocol-version": "2025-06-18",
                },
            )
            self.assertEqual(listing.status_code, 200)
            self.assertEqual(
                listing.headers.get("x-mcp-server-instance"), instance_first
            )

        with _FormalEntryProcess():
            restarted = _raw_rpc(_initialize_payload(), headers={})
            self.assertEqual(restarted.status_code, 200)
            self.assertNotEqual(
                restarted.headers.get("x-mcp-server-instance"), instance_first
            )


@unittest.skipUnless(
    os.environ.get("VELOCIRAPTOR_API_CONFIG", "").strip(),
    "formal transport acceptance requires the Win10 VM API config",
)
class FormalEntryGateTests(unittest.TestCase):
    """ACC-P02-010: fail-closed config plus bearer, Host, and Origin gates."""

    def test_rejected_configs_fail_before_any_socket(self):
        bad_configs = [
            {TOKEN_ENV: " "},
            {HOST_ENV: "0.0.0.0"},
            {HOST_ENV: "::"},
            {PORT_ENV: "28791"},
            {PATH_ENV: "/api"},
        ]
        for extra in bad_configs:
            with self.subTest(extra=extra):
                env = _http_env(extra)
                completed = subprocess.run(
                    [sys.executable, str(FIXTURE)],
                    cwd=REPO_ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn(
                    "transport configuration rejected", completed.stderr
                )
                self.assertEqual(completed.stdout, "")
                self.assertTrue(_port_closed("127.0.0.1", FORMAL_PORT))

    def test_authentication_rejections_do_not_reach_handler(self):
        with _FormalEntryProcess():
            missing = _raw_rpc(
                _initialize_payload(), headers={"Authorization": ""}
            )
            self.assertEqual(missing.status_code, 401)
            wrong_scheme = _raw_rpc(
                _initialize_payload(),
                headers={"Authorization": f"Basic {TEST_TOKEN}"},
            )
            self.assertEqual(wrong_scheme.status_code, 401)
            wrong_token = _raw_rpc(
                _initialize_payload(), headers={"Authorization": "Bearer nope"}
            )
            self.assertEqual(wrong_token.status_code, 401)
            for response in (missing, wrong_scheme, wrong_token):
                self.assertIsNone(response.headers.get("x-mcp-server-instance"))
                self.assertNotIn(TEST_TOKEN.encode(), response.content)
                self.assertNotIn(b"mcp-velociraptor", response.content.lower())

    def test_host_and_origin_gates(self):
        with _FormalEntryProcess():
            bad_host = _raw_rpc(
                _initialize_payload(), headers={"Host": "rebind.example"}
            )
            self.assertEqual(bad_host.status_code, 421)
            bad_origin = _raw_rpc(
                _initialize_payload(),
                headers={"Origin": "https://not-allowed.example"},
            )
            self.assertEqual(bad_origin.status_code, 403)

    def test_allowed_origin_succeeds_and_default_has_none(self):
        with _FormalEntryProcess():
            no_origin = _raw_rpc(_initialize_payload(), headers={})
            self.assertEqual(no_origin.status_code, 200)

        with _FormalEntryProcess(
            {ALLOWED_ORIGINS_ENV: "https://allowed.example"}
        ):
            allowed = _raw_rpc(
                _initialize_payload(),
                headers={"Origin": "https://allowed.example"},
            )
            self.assertEqual(allowed.status_code, 200)


if __name__ == "__main__":
    unittest.main()

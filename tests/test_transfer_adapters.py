"""Local-only host adapter contract regression tests."""

import asyncio
import base64
import errno
import hashlib
import io
import json
import os
import socket
import re
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

import uvicorn
import httpx2
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from velo_transfer import windows_commands as wc
from velo_transfer.adapters import AdapterError, SCHEMAS, TransportAdapter, WindowsAdapter, _classify, select_adapter
from velo_transfer.connection import ConnectionError, Deployment, load_connection_profile
from velo_transfer.errors import TransferContentError
from velo_transfer import guest_cli
from velo_transfer.mcp_tools import register_transfer_tools
from velociraptor_transport import BearerAuthGate, ServerInstanceHeader


class PrivateProfile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.token = self.root / "token"
        self.token.write_text("benign-fixture-token")
        self.token.chmod(0o600)
        self.path = self.root / "profile.json"
        self.payload = {
            "version": "velo.transfer.connection.v1",
            "velo": {"endpoint": "http://127.0.0.1:9/mcp", "token_file": str(self.token)},
            "windows": None,
            "deployment": {"python_path": "E:\\Tools\\python.exe", "project_root": "E:\\Tools\\mcp",
                           "policy_path": "E:\\Policy\\policy.json", "guest_work_root": "E:\\Work"},
        }
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.payload))
        self.path.chmod(0o600)

    def test_profile_and_secret_redaction(self):
        profile = load_connection_profile(self.path)
        self.assertNotIn("benign-fixture-token", repr(profile))
        self.assertEqual(profile.velo.token.read(), "benign-fixture-token")
        self.token.write_text("changed-secret")
        self.assertEqual(profile.velo.token.read(), "changed-secret")
        self.payload["windows"] = {"endpoint": "http://127.0.0.1:28791/mcp"}
        self.save()
        self.assertIsNone(load_connection_profile(self.path).windows.token)

    def test_profile_negative_cases(self):
        for field, value in (("endpoint", "http://user:secret@127.0.0.1/mcp"),
                             ("endpoint", "http://127.0.0.1/mcp?token=x")):
            self.payload["velo"][field] = value
            self.save()
            with self.assertRaises(ConnectionError):
                load_connection_profile(self.path)
        self.payload["velo"]["endpoint"] = "http://127.0.0.1/mcp"
        for path in ("\\\\server\\share", "E:\\bad\\..\\x", "E:\\bad:stream", "E:\\bad\\"):
            self.payload["deployment"]["guest_work_root"] = path
            self.save()
            with self.assertRaises(ConnectionError):
                load_connection_profile(self.path)

    def test_file_security_and_duplicates(self):
        self.path.write_text('{"version":1,"version":2}')
        with self.assertRaises(ConnectionError) as err:
            load_connection_profile(self.path)
        self.assertEqual(err.exception.code, "duplicate_key")
        self.save()
        self.path.chmod(0o644)
        with self.assertRaises(ConnectionError):
            load_connection_profile(self.path)
        self.payload["velo"]["token_file"] = str(self.token)
        self.save()
        hardlink = self.root / "hardlink"
        os.link(self.token, hardlink)
        with self.assertRaises(ConnectionError):
            load_connection_profile(self.path)
        hardlink.unlink()
        self.path.chmod(0o600)
        self.token.write_text("token\nsecond")
        with self.assertRaises(ConnectionError):
            load_connection_profile(self.path)
        self.token.write_text("token")
        link = self.root / "link"
        link.symlink_to(self.token)
        self.payload["velo"]["token_file"] = str(link)
        self.save()
        with self.assertRaises(ConnectionError):
            load_connection_profile(self.path)


class PowerShellBoundary(unittest.TestCase):
    def test_full_encoded_budget_and_literals(self):
        path = "E:\\工作\\quote' `$\\request.json"
        script = wc.write_script(path, 1 << 33, b"x" * 4096, "a" * 24)
        self.assertLessEqual(wc.encoded_argv_length(script), 28000)
        self.assertIn("quote'' `$", script)
        self.assertIn(str(1 << 33), script)
        self.assertNotIn("Invoke-Expression", script)
        with self.assertRaises(ValueError):
            wc.bounded("x" * 28000)

    def test_auto_shrink_boundary(self):
        path = "E:\\" + ("😀" * 100 + "\\") * 20 + "request.json"
        count = 4096
        while count:
            try:
                script = wc.write_script(path, 0, b"x" * count, "a" * 24)
                break
            except ValueError:
                count //= 2
        self.assertGreater(count, 0)
        self.assertLess(count, 4096)
        self.assertLessEqual(wc.encoded_argv_length(script), 28000)
        with self.assertRaises(ValueError):
            wc.write_script("E:\\" + "长" * 10000 + "\\x", 0, b"x", "a" * 24)

    def test_strict_response(self):
        from mcp.types import CallToolResult, TextContent
        good = CallToolResult(content=[TextContent(type="text", text="Response: ACK:created\nStatus Code: 0")])
        self.assertEqual(wc.parse_outer(good), "ACK:created")
        for value in ("Response: ok\nStatus Code: 4", "Response: ok\nStatus Code: 0\nextra", "ok"):
            with self.assertRaises(ValueError):
                wc.parse_outer(CallToolResult(content=[TextContent(type="text", text=value)]))
        self.assertEqual(wc.parse_helper('{"status":"success","result":{"schema":"velo.transfer.guest.response.v1"}}\n'),
                         {"schema": "velo.transfer.guest.response.v1"})
        for value in ('{"status":"success","result":{},"result":{}}',
                      '{"status":"success","result":{}}\nextra', '{"status":"success"}'):
            with self.assertRaises(ValueError):
                wc.parse_helper(value)


class _SimulatedPowerShell:
    """Interprets only markers from our fixed templates; never runs shell text."""

    def __init__(self, *, lose_write_ack=False, fail_cleanup=False, corrupt_replay=False,
                 truncate_on_verify=False, corrupt_on_verify=False, invoke_timeout=False,
                 replace_before_cleanup=False, helper_error=None):
        self.files = {}
        self.identities = {}
        self.commands = []
        self.lose_write_ack = lose_write_ack
        self.fail_cleanup = fail_cleanup
        self.corrupt_replay = corrupt_replay
        self.truncate_on_verify = truncate_on_verify
        self.corrupt_on_verify = corrupt_on_verify
        self.invoke_timeout = invoke_timeout
        self.replace_before_cleanup = replace_before_cleanup
        self.helper_error = helper_error
        self.request = None

    async def call_tool(self, name, arguments, **_):
        from mcp.types import CallToolResult, TextContent
        assert name == "PowerShell"
        script = arguments["command"]
        self.commands.append(script)
        if wc.encoded_argv_length(script) > 28000:
            raise AssertionError("command budget exceeded")
        match = re.search(r"\$p='([^']+)'", script)
        if match is None:
            match = re.search(r"--request-file '([^']+)'", script)
        if match is None:
            raise AssertionError("unexpected script")
        path = match.group(1)
        status_code = 0
        if "ACK:created" in script:
            self.files.setdefault(path, bytearray())
            self.identities[path] = "a" * 24
            answer = "ACK:created:" + self.identities[path]
        else:
            identity = re.search(r"\$id='([0-9a-f]{24})'", script)
            assert identity is not None and (
                "[VeloRequestIdentity]::Read" in script or
                "[VeloRequestIdentity]::DeleteOwned" in script)
            if self.identities[path] != identity.group(1):
                return CallToolResult(content=[TextContent(type="text", text="Response: request_replaced\r\n\nStatus Code: 4")])
        if "ACK:created" in script:
            pass
        elif "[Convert]::FromBase64String" in script:
            offset = int(re.search(r"\$o=([0-9]+)", script).group(1))
            raw = base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", script).group(1))
            body = self.files[path]
            if len(body) == offset:
                body.extend(raw)
            elif body[offset:offset + len(raw)] != raw:
                raise ValueError("offset_conflict")
            answer = f"ACK:{offset}:{len(raw)}:{hashlib.sha256(raw).hexdigest()}"
            if self.lose_write_ack:
                self.lose_write_ack = False
                if self.corrupt_replay:
                    body[offset] ^= 1
                raise asyncio.TimeoutError()
        elif "ACK:verified" in script:
            if self.truncate_on_verify:
                self.files[path].pop()
            if self.corrupt_on_verify:
                self.files[path][0] ^= 1
            expected_size = int(re.search(r"\$n=([0-9]+)", script).group(1))
            expected_hash = re.search(r"\$h='([0-9a-f]{64})'", script).group(1)
            if (len(self.files[path]) != expected_size or
                    hashlib.sha256(self.files[path]).hexdigest() != expected_hash):
                return CallToolResult(content=[TextContent(type="text", text="Response: verify_failed\nStatus Code: 4")])
            answer = "ACK:verified"
        elif "--request-file" in script:
            self.request = json.loads(bytes(self.files[path]))
            if self.invoke_timeout:
                raise asyncio.TimeoutError()
            if self.helper_error is not None:
                answer = json.dumps({"status": "error", "error": self.helper_error})
                status_code = 4
            else:
                service = _FixtureService()
                service.enabled = True
                answer = json.dumps({"status": "success", "result": getattr(service,
                    self.request["operation"])(**self.request["arguments"])})
            if self.replace_before_cleanup:
                self.identities[path] = "b" * 24
        elif "ACK:deleted" in script:
            assert "[VeloRequestIdentity]::DeleteOwned($p,$id)" in script
            assert "[IO.File]::Delete" not in script
            if self.fail_cleanup:
                raise ValueError("simulated_cleanup_denied")
            del self.files[path]
            del self.identities[path]
            answer = "ACK:deleted"
        else:
            raise AssertionError("unexpected script")
        return CallToolResult(content=[TextContent(type="text", text=f"Response: {answer}\r\n\nStatus Code: {status_code}")])


class SimulatedWindowsAdapter(unittest.TestCase):
    def test_multipart_idempotent_ack_replay_and_large_offset(self):
        session = _SimulatedPowerShell(lose_write_ack=True)
        adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp",
            Deployment("E:\\Tools\\python.exe", "E:\\Tools\\mcp", "E:\\Policy\\policy.json", "E:\\Work"),
            time.monotonic() + 10, 3, [])
        raw = b"x" * 4096
        args = {"transfer_id": "fixture", "request_digest": "0" * 64, "offset": 1 << 33,
                "count": 4096, "data_base64": base64.b64encode(raw).decode(),
                "chunk_sha256": hashlib.sha256(raw).hexdigest()}
        result = asyncio.run(adapter.call("transfer_chunk", args))
        self.assertEqual(result["offset"], 1 << 33)
        self.assertEqual(session.request, {"operation": "transfer_chunk", "arguments": args})
        self.assertGreaterEqual(sum("[Convert]::FromBase64String" in s for s in session.commands), 3)
        self.assertEqual(session.files, {})
        with self.assertRaises(AdapterError) as err:
            asyncio.run(adapter.call("transfer_chunk", dict(args, count=4097)))
        self.assertEqual(err.exception.code, "chunk_too_large")

    def test_cleanup_failure_preserves_guest_result(self):
        session = _SimulatedPowerShell(fail_cleanup=True)
        adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp",
            Deployment("E:\\Tools\\python.exe", "E:\\Tools\\mcp", "E:\\Policy\\policy.json", "E:\\Work"),
            time.monotonic() + 10, 3, [])
        async def run():
            with self.assertRaises(AdapterError) as err:
                await adapter.call("transfer_status", {"transfer_id": "x", "request_digest": "0" * 64})
            self.assertEqual(err.exception.code, "cleanup_failed")
            self.assertEqual(err.exception.guest_result["schema"], "velo.transfer.guest.response.v1")
            self.assertEqual(err.exception.cleanup_path, adapter.observations["pending_control_path"])
            self.assertTrue(adapter.observations["cleanup_failed"])
        asyncio.run(run())

    def test_control_conflicts_and_helper_timeout_stay_unknown(self):
        cases = [
            (_SimulatedPowerShell(lose_write_ack=True, corrupt_replay=True), "powershell_response", True),
            (_SimulatedPowerShell(truncate_on_verify=True), "powershell_response", True),
            (_SimulatedPowerShell(corrupt_on_verify=True), "powershell_response", True),
            (_SimulatedPowerShell(invoke_timeout=True), "outcome_unknown", True),
        ]
        for session, code, may_have_committed in cases:
            adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp",
                Deployment("E:\\Tools\\python.exe", "E:\\Tools\\mcp", "E:\\Policy\\policy.json", "E:\\Work"),
                time.monotonic() + 10, 3, [])
            args = {"transfer_id": "same-id", "request_digest": "0" * 64, "offset": 0,
                    "count": 1, "data_base64": "eA==", "chunk_sha256": hashlib.sha256(b"x").hexdigest()}
            async def run():
                with self.assertRaises(AdapterError) as err:
                    await adapter.call("transfer_chunk", args)
                self.assertEqual(err.exception.code, code)
                self.assertEqual(err.exception.may_have_committed, may_have_committed)
                self.assertEqual(err.exception.transfer_id, "same-id")
                self.assertEqual(err.exception.request_digest, "0" * 64)
            asyncio.run(run())
            self.assertEqual(session.files, {})


class CorrectionRegressions(unittest.TestCase):
    @staticmethod
    def deployment():
        return Deployment("E:\\Tools\\python.exe", "E:\\Tools\\mcp",
                          "E:\\Policy\\policy.json", "E:\\Work")

    def test_chk001_crlf_ack_all_stages_and_replacement_cleanup(self):
        session = _SimulatedPowerShell()
        adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp", self.deployment(),
                                 time.monotonic() + 10, 3, [])
        result = asyncio.run(adapter.call("transfer_capabilities", {}))
        self.assertTrue(result["enabled"])
        self.assertEqual(session.files, {})
        self.assertTrue(all(command.startswith(wc.STOP_ON_ERROR) for command in session.commands))
        self.assertTrue(all(wc.encoded_argv_length(command) <= 28000 for command in session.commands))
        from mcp.types import CallToolResult, TextContent
        for body in ("ACK:created\r\n\r\n", "ACK:created\r\nnoise", "ACK:created\n\n"):
            with self.assertRaises(ValueError):
                wc.parse_outer(CallToolResult(content=[TextContent(
                    type="text", text=f"Response: {body}\nStatus Code: 0")]))
        replaced = _SimulatedPowerShell(replace_before_cleanup=True)
        adapter = WindowsAdapter(replaced, "http://127.0.0.1:9/mcp", self.deployment(),
                                 time.monotonic() + 10, 3, [])
        async def run():
            with self.assertRaises(AdapterError) as error:
                await adapter.call("transfer_capabilities", {})
            self.assertEqual(error.exception.code, "cleanup_failed")
            self.assertTrue(error.exception.guest_result["enabled"])
            self.assertEqual(error.exception.cleanup_path, adapter.observations["pending_control_path"])
        asyncio.run(run())
        self.assertEqual(len(replaced.files), 1)  # Foreign replacement was not deleted.

    def test_chk002_real_guest_cli_exit_and_envelope_alignment(self):
        from mcp.types import CallToolResult, TextContent
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()
        for code in ("partial_verification_required", "source_changed", "transfer_not_found"):
            output = Output()
            with mock.patch.object(guest_cli, "GuestTransferService", return_value=object()), \
                 mock.patch.object(guest_cli, "invoke", side_effect=TransferContentError(code)), \
                 mock.patch.object(guest_cli.sys, "stdout", output):
                exit_code = guest_cli.main(["--request-file", "E:\\Work\\requests\\benign.json"])
            self.assertEqual(exit_code, 4)
            body = output.buffer.getvalue().decode("utf-8").replace("\n", "\r\n")
            outer = CallToolResult(content=[TextContent(type="text", text=f"Response: {body}\nStatus Code: {exit_code}")])
            parsed_body, parsed_code = wc.parse_outer_status(outer)
            with self.assertRaises(wc.GuestHelperError) as error:
                wc.parse_helper(parsed_body, parsed_code)
            self.assertEqual(error.exception.code, code)
        good = '{"status":"success","result":{"schema":"velo.transfer.guest.response.v1"}}\r\n'
        self.assertEqual(wc.parse_helper(good, 0)["schema"], "velo.transfer.guest.response.v1")
        for body, status in ((good, 4), ('{"status":"error","error":"source_changed"}\r\n', 0),
                             ('{"status":"error","error":"source_changed"}\r\n', 3),
                             (good + "extra", 0)):
            with self.assertRaises(ValueError):
                wc.parse_helper(body, status)
        session = _SimulatedPowerShell(helper_error="partial_verification_required")
        adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp", self.deployment(),
                                 time.monotonic() + 10, 3, [])
        async def run():
            with self.assertRaises(AdapterError) as error:
                await adapter.call("transfer_abort", {"transfer_id": "same-id", "request_digest": "0" * 64})
            self.assertEqual(error.exception.code, "partial_verification_required")
            self.assertTrue(error.exception.may_have_committed)
            self.assertEqual(error.exception.transfer_id, "same-id")
        asyncio.run(run())

    def test_chk003_post_send_malformed_is_unknown_and_local_reject_is_not(self):
        from mcp.types import CallToolResult, TextContent
        class Session:
            def __init__(self, result):
                self.result = result
                self.calls = 0
            async def call_tool(self, *args, **kwargs):
                self.calls += 1
                return self.result
        envelope = {"schema": "velo.transfer.mcp.response.v1", "status": "success",
                    "result": {"schema": "velo.transfer.guest.response.v1"}}
        for response in (
            CallToolResult(content=[TextContent(type="text", text="truncated")]),
            CallToolResult(content=[TextContent(type="text", text=json.dumps(envelope))],
                           structured_content=envelope, is_error=True),
            CallToolResult(content=[TextContent(type="text", text="{}")], structured_content=envelope),
        ):
            session = Session(response)
            adapter = TransportAdapter(session, "velo", "http://127.0.0.1:9/mcp",
                                       time.monotonic() + 10, 3, [])
            async def run():
                with self.assertRaises(AdapterError) as error:
                    await adapter.call("transfer_abort", {"transfer_id": "same-id", "request_digest": "0" * 64})
                self.assertTrue(error.exception.may_have_committed)
                self.assertEqual(error.exception.transfer_id, "same-id")
                self.assertEqual(error.exception.request_digest, "0" * 64)
            asyncio.run(run())
            self.assertEqual(session.calls, 1)
        session = Session(None)
        adapter = TransportAdapter(session, "velo", "http://127.0.0.1:9/mcp",
                                   time.monotonic() + 10, 3, [])
        async def reject():
            with self.assertRaises(AdapterError) as error:
                await adapter.call("transfer_abort", {"transfer_id": "x", "request_digest": "bad"})
            self.assertFalse(error.exception.may_have_committed)
        asyncio.run(reject())
        self.assertEqual(session.calls, 0)

    def test_six_actual_guest_operations_and_fixed_helper_error(self):
        from tests.test_transfer_guest import GuestTests
        fixture = GuestTests(methodName="test_pull_full_release_multiple_roots")
        fixture.setUp()
        try:
            source = fixture.read / "benign.txt"
            source.write_bytes(b"benign transfer fragment")
            request = fixture.request("pull", [{"absolute_path": str(source),
                "relative_path": "benign.txt"}], fixture.host / "result", transfer_id="adapter-real")
            service = fixture.service
            caps = service.transfer_capabilities()
            self.assertTrue(caps["enabled"])
            self.assertEqual(service.transfer_begin(request)["transfer_id"], "adapter-real")
            ready = fixture.wait_phase(request, "SOURCE_READY")
            self.assertEqual(service.transfer_status("adapter-real", request["request_digest"])["package"],
                             ready["package"])
            count = min(64, ready["package"]["size"])
            part = service.transfer_chunk("adapter-real", request["request_digest"], 0, count)
            raw = base64.b64decode(part["data_base64"])
            self.assertEqual(len(raw), count)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), part["chunk_sha256"])
            finish = service.transfer_finish("adapter-real", request["request_digest"], "prepare")
            self.assertEqual(finish["action"], "prepare")
            fixture.wait_phase(request, "SOURCE_PREPARED")
            aborted = service.transfer_abort("adapter-real", request["request_digest"])
            self.assertEqual(aborted["transfer_id"], "adapter-real")
            request_dir = fixture.work / "requests"
            request_dir.mkdir(mode=0o700)
            control = request_dir / "real-error.json"
            control.write_text(json.dumps({"operation": "transfer_status", "arguments": {
                "transfer_id": "missing-id", "request_digest": "0" * 64}}))
            control.chmod(0o600)
            with self.assertRaises(TransferContentError) as error:
                guest_cli.invoke(str(control), service)
            self.assertEqual(error.exception.code, "task_not_found")
        finally:
            fixture.doCleanups()

    def test_chk004_structured_connect_causes(self):
        for number in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH):
            error = httpx2.ConnectError("opaque")
            error.__cause__ = OSError(number, "opaque")
            self.assertEqual(_classify(error).code, "connection_unavailable")
        tls = httpx2.ConnectError("opaque")
        tls.__cause__ = ssl.SSLCertVerificationError(1, "opaque")
        self.assertEqual(_classify(tls).code, "tls_auth_failed")
        self.assertEqual(_classify(httpx2.ConnectError("opaque")).code, "connection_failed")
        network = httpx2.ConnectError("opaque")
        network.__cause__ = OSError(errno.ECONNREFUSED, "opaque")
        self.assertEqual(_classify(ExceptionGroup("mixed", [network, tls])).code, "tls_auth_failed")

    def test_chk005_windows_caps_bound_both_guest_limit_and_default(self):
        for maximum, default, expected in ((1024, 1024, 1024), (4096, 512, 512),
                                           (1 << 20, 1 << 20, 4096)):
            caps = _FixtureService().transfer_capabilities()
            caps["limits"]["max_chunk_bytes"] = maximum
            caps["default_chunk_bytes"] = default
            session = _SimulatedPowerShell()
            adapter = WindowsAdapter(session, "http://127.0.0.1:9/mcp", self.deployment(),
                                     time.monotonic() + 10, 3, [])
            async def run():
                with mock.patch.object(_FixtureService, "transfer_capabilities", return_value=caps):
                    await adapter.call("transfer_capabilities", {})
                self.assertEqual(adapter.raw_chunk_bytes, expected)
                before = len(session.commands)
                with self.assertRaises(AdapterError) as error:
                    await adapter.call("transfer_chunk", {"transfer_id": "x", "request_digest": "0" * 64,
                        "offset": 0, "count": expected + 1})
                self.assertEqual(error.exception.code, "chunk_too_large")
                self.assertEqual(len(session.commands), before)
                answer = await adapter.call("transfer_chunk", {"transfer_id": "x", "request_digest": "0" * 64,
                    "offset": 0, "count": expected})
                self.assertEqual(answer["offset"], 0)
            asyncio.run(run())


class _FixtureService:
    enabled = True

    def transfer_capabilities(self):
        if not self.enabled:
            return {"schema": "velo.transfer.guest.response.v1", "enabled": False,
                    "reason": "fixture_disabled"}
        return {"schema": "velo.transfer.guest.response.v1", "enabled": True,
                "protocol_version": "velo.transfer.v1", "vm_uuid": "fixture-vm", "boot_identity": "fixture-boot",
                "build": "fixture", "policy_id": "fixture-policy", "default_chunk_bytes": 1048576,
                "limits": {"max_chunk_bytes": 1048576}}

    def transfer_status(self, **kwargs):
        return {"schema": "velo.transfer.guest.response.v1", "transfer_id": kwargs["transfer_id"],
                "offset": 1 << 33}

    def transfer_begin(self, **kwargs):
        return {"schema": "velo.transfer.guest.response.v1", "transfer_id": kwargs["request"]["transfer_id"]}

    def transfer_chunk(self, **kwargs):
        return {"schema": "velo.transfer.guest.response.v1", "offset": kwargs["offset"]}

    def transfer_finish(self, **kwargs):
        return {"schema": "velo.transfer.guest.response.v1", "action": kwargs["action"]}

    def transfer_abort(self, **kwargs):
        return {"schema": "velo.transfer.guest.response.v1", "transfer_id": kwargs["transfer_id"]}

    def shutdown(self):
        pass


class SdkLoopback(PrivateProfile):
    @classmethod
    def _start_extra(cls, server, *, bearer=None):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=False,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                allowed_hosts=[f"127.0.0.1:{port}"], allowed_origins=[]), host="127.0.0.1")
        if bearer is not None:
            app.add_middleware(BearerAuthGate, token=bearer)
        running = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                                log_level="critical", lifespan="on"))
        thread = threading.Thread(target=running.run, daemon=False)
        thread.start()
        deadline = time.monotonic() + 10
        while not running.started and time.monotonic() < deadline:
            time.sleep(.02)
        if not running.started:
            raise RuntimeError("secondary fixture listener failed")
        cls.extra.append((running, thread))
        return port

    @classmethod
    def setUpClass(cls):
        cls.extra = []
        server = MCPServer("fixture-transfer")
        cls.manager = register_transfer_tools(server, factory=_FixtureService)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        cls.port = sock.getsockname()[1]
        sock.close()
        app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=False,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                allowed_hosts=[f"127.0.0.1:{cls.port}"], allowed_origins=[]), host="127.0.0.1")
        app.add_middleware(ServerInstanceHeader, instance_id="fixture-instance")
        app.add_middleware(BearerAuthGate, token="benign-fixture-token")
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port,
                                                  log_level="critical", lifespan="on"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=False)
        cls.thread.start()
        deadline = time.monotonic() + 10
        while not cls.server.started and time.monotonic() < deadline:
            time.sleep(.02)
        if not cls.server.started:
            raise RuntimeError("fixture listener failed")
        windows = MCPServer("fixture-windows")
        cls.ps_session = _SimulatedPowerShell()
        async def powershell(command: str, timeout: int = 30) -> str:
            response = await cls.ps_session.call_tool("PowerShell", {"command": command, "timeout": timeout})
            return response.content[0].text
        windows.add_tool(powershell, name="PowerShell")
        cls.windows_port = cls._start_extra(windows)
        missing = MCPServer("fixture-missing")
        cls.missing_manager = register_transfer_tools(missing, factory=_FixtureService)
        missing.remove_tool("transfer_abort")
        cls.missing_port = cls._start_extra(missing, bearer="benign-fixture-token")
        drift = MCPServer("fixture-drift")
        cls.drift_manager = register_transfer_tools(drift, factory=_FixtureService)
        drift._tool_manager.get_tool("transfer_status").parameters["properties"]["transfer_id"]["minLength"] = 2
        cls.drift_port = cls._start_extra(drift, bearer="benign-fixture-token")

    @classmethod
    def tearDownClass(cls):
        for running, thread in cls.extra:
            running.should_exit = True
            thread.join(10)
            if thread.is_alive():
                raise RuntimeError("secondary fixture listener leak")
        cls.server.should_exit = True
        cls.thread.join(10)
        cls.manager.shutdown()
        cls.missing_manager.shutdown()
        cls.drift_manager.shutdown()
        if cls.thread.is_alive():
            raise RuntimeError("fixture listener leak")

    def test_sdk_initialize_list_call_and_preference(self):
        self.payload["velo"]["endpoint"] = f"http://127.0.0.1:{self.port}/mcp"
        self.save()
        profile = load_connection_profile(self.path)

        async def run():
            async with select_adapter(profile, expected_vm_identity={"vm_uuid": "fixture-vm",
                "boot_identity": "fixture-boot"}, deadline_monotonic=time.monotonic() + 10,
                request_timeout_seconds=3) as adapter:
                self.assertEqual(adapter.channel, "velo")
                self.assertIsNone(adapter.fallback_reason)
                status = await adapter.call("transfer_status", {"transfer_id": "x", "request_digest": "0" * 64})
                self.assertEqual(status["offset"], 1 << 33)
                self.assertEqual(adapter.observations["vm_uuid"], "fixture-vm")
                self.assertIn("instance", adapter.observations)
                self.assertEqual(adapter.observations["instance"], "fixture-instance")
                request = {"protocol_version": "velo.transfer.v1", "transfer_id": "x",
                    "request_digest": "0" * 64, "direction": "pull",
                    "sources": [{"absolute_path": "E:\\Read\\x", "relative_path": "x"}],
                    "expected_destination": {"endpoint": "host", "identity": {"host": "fixture"},
                                             "canonical_path": "/fixture/out"},
                    "expected_vm_identity": {"vm_uuid": "fixture-vm", "boot_identity": "fixture-boot",
                                             "vm_epoch": "fixture-epoch"},
                    "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                         "references": ["fixture-ref"]},
                    "budget": {"max_files": 1, "max_metadata_bytes": 1000, "max_logical_bytes": 1000,
                               "max_package_bytes": 2000, "min_free_bytes": 0, "max_chunk_bytes": 1024,
                               "max_duration_seconds": 60}}
                self.assertEqual((await adapter.call("transfer_begin", {"request": request}))["transfer_id"], "x")
                chunk = {"transfer_id": "x", "request_digest": "0" * 64, "offset": 1 << 33, "count": 1}
                self.assertEqual((await adapter.call("transfer_chunk", chunk))["offset"], 1 << 33)
                self.assertEqual((await adapter.call("transfer_finish", {"transfer_id": "x",
                    "request_digest": "0" * 64, "action": "prepare"}))["action"], "prepare")
                self.assertEqual((await adapter.call("transfer_abort", {"transfer_id": "x",
                    "request_digest": "0" * 64}))["transfer_id"], "x")
                windows = WindowsAdapter(_SimulatedPowerShell(), "http://127.0.0.1:9/mcp",
                    profile.deployment, time.monotonic() + 10, 3, [])
                calls = [
                    ("transfer_capabilities", {}),
                    ("transfer_begin", {"request": request}),
                    ("transfer_status", {"transfer_id": "x", "request_digest": "0" * 64}),
                    ("transfer_chunk", chunk),
                    ("transfer_finish", {"transfer_id": "x", "request_digest": "0" * 64, "action": "prepare"}),
                    ("transfer_abort", {"transfer_id": "x", "request_digest": "0" * 64}),
                ]
                for operation, arguments in calls:
                    self.assertEqual(await adapter.call(operation, arguments),
                                     await windows.call(operation, arguments), operation)

        asyncio.run(run())

    def test_auth_denied_never_falls_back(self):
        self.payload["velo"]["endpoint"] = f"http://127.0.0.1:{self.port}/mcp"
        self.payload["windows"] = {"endpoint": f"http://127.0.0.1:{self.windows_port}/mcp"}
        self.save()
        self.token.write_text("wrong-benign-token")
        profile = load_connection_profile(self.path)

        async def run():
            with self.assertRaises(AdapterError) as err:
                async with select_adapter(profile, expected_vm_identity={"vm_uuid": "fixture-vm", "boot_identity": "fixture-boot"},
                    deadline_monotonic=time.monotonic() + 10, request_timeout_seconds=3):
                    pass
            self.assertEqual(err.exception.code, "authentication_denied")

        asyncio.run(run())

    def test_sdk_fallback_only_for_missing_disabled_and_connection_refused(self):
        self.payload["windows"] = {"endpoint": f"http://127.0.0.1:{self.windows_port}/mcp"}
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        refused = sock.getsockname()[1]
        sock.close()

        async def run(reason):
            profile = load_connection_profile(self.path)
            async with select_adapter(profile, expected_vm_identity={"vm_uuid": "fixture-vm",
                "boot_identity": "fixture-boot"}, deadline_monotonic=time.monotonic() + 10,
                request_timeout_seconds=3) as adapter:
                self.assertEqual(adapter.channel, "windows")
                self.assertEqual(adapter.fallback_reason, reason)
                self.assertEqual((await adapter.call("transfer_status", {"transfer_id": "x",
                    "request_digest": "0" * 64}))["offset"], 1 << 33)

        for port, reason in ((self.missing_port, "tools_missing"), (refused, "connection_unavailable")):
            self.payload["velo"]["endpoint"] = f"http://127.0.0.1:{port}/mcp"
            self.save()
            asyncio.run(run(reason))
        try:
            _FixtureService.enabled = False
            self.payload["velo"]["endpoint"] = f"http://127.0.0.1:{self.port}/mcp"
            self.save()
            asyncio.run(run("capabilities_disabled"))
        finally:
            _FixtureService.enabled = True

    def test_schema_drift_and_host_rejection_never_fallback(self):
        self.payload["windows"] = {"endpoint": f"http://127.0.0.1:{self.windows_port}/mcp"}
        for endpoint, expected in ((f"http://127.0.0.1:{self.drift_port}/mcp", "schema_mismatch"),
                                   (f"http://localhost:{self.port}/mcp", "host_rejected")):
            self.payload["velo"]["endpoint"] = endpoint
            self.save()
            profile = load_connection_profile(self.path)
            async def run():
                with self.assertRaises(AdapterError) as err:
                    async with select_adapter(profile, expected_vm_identity={"vm_uuid": "fixture-vm",
                        "boot_identity": "fixture-boot"}, deadline_monotonic=time.monotonic() + 10,
                        request_timeout_seconds=3):
                        pass
                self.assertEqual(err.exception.code, expected)
            asyncio.run(run())

    def test_identity_and_begun_channel_fail_closed(self):
        self.payload["velo"]["endpoint"] = f"http://127.0.0.1:{self.port}/mcp"
        self.save()
        profile = load_connection_profile(self.path)

        async def run():
            with self.assertRaises(AdapterError) as err:
                async with select_adapter(profile, expected_vm_identity={"vm_uuid": "wrong", "boot_identity": "fixture-boot"},
                    deadline_monotonic=time.monotonic() + 10, request_timeout_seconds=3):
                    pass
            self.assertEqual(err.exception.code, "identity_mismatch")

        asyncio.run(run())


class SchemaResource(unittest.TestCase):
    def test_production_schema_matches_reviewed_golden(self):
        golden = json.loads((Path(__file__).parent / "data" / "transfer_tools_golden.json").read_text())
        self.assertEqual(SCHEMAS, golden)


class SelectionRules(unittest.TestCase):
    def test_fallback_only_before_begin_and_for_allowlisted_causes(self):
        import velo_transfer.adapters as module

        class Fake:
            def __init__(self, channel, cause):
                self.channel = channel
                self.fallback_reason = None
                self.cause = cause
            async def probe(self, identity):
                if self.channel == "velo" and self.cause:
                    raise AdapterError(self.cause)

        async def trial(cause, begun=None):
            calls = []

            @asynccontextmanager
            async def fake_open(profile, channel, **kwargs):
                calls.append(channel)
                yield Fake(channel, cause)

            with mock.patch.object(module, "open_adapter", fake_open):
                try:
                    async with select_adapter(object(), expected_vm_identity={},
                        deadline_monotonic=time.monotonic() + 10, request_timeout_seconds=1,
                        begun_channel=begun) as adapter:
                        return calls, adapter.channel, adapter.fallback_reason
                except AdapterError as exc:
                    return calls, exc.code, None

        for cause in ("connection_unavailable", "tools_missing", "capabilities_disabled"):
            self.assertEqual(asyncio.run(trial(cause)), (["velo", "windows"], "windows", cause))
        for cause in ("authentication_denied", "host_rejected", "schema_mismatch", "identity_mismatch",
                      "protocol_error", "transport_timeout"):
            self.assertEqual(asyncio.run(trial(cause)), (["velo"], cause, None))
        self.assertEqual(asyncio.run(trial("connection_unavailable", "velo")),
                         (["velo"], "connection_unavailable", None))

    def test_mutation_timeout_is_unknown_without_retry(self):
        class Session:
            def __init__(self):
                self.calls = 0
            async def call_tool(self, name, args, **kwargs):
                self.calls += 1
                raise asyncio.TimeoutError()

        session = Session()
        adapter = TransportAdapter(session, "velo", "http://127.0.0.1:9/mcp",
                                   time.monotonic() + 10, 1, [])
        args = {"transfer_id": "x", "request_digest": "0" * 64}
        async def run():
            with self.assertRaises(AdapterError) as err:
                await adapter.call("transfer_abort", args)
            self.assertTrue(err.exception.may_have_committed)
            self.assertEqual(err.exception.code, "outcome_unknown")
        asyncio.run(run())
        self.assertEqual(session.calls, 1)

    def test_read_only_has_three_bounded_attempts(self):
        class Session:
            def __init__(self):
                self.calls = 0
            async def call_tool(self, name, args, **kwargs):
                self.calls += 1
                raise asyncio.TimeoutError()

        session = Session()
        adapter = TransportAdapter(session, "velo", "http://127.0.0.1:9/mcp",
                                   time.monotonic() + 10, 1, [])
        async def run():
            with self.assertRaises(AdapterError):
                await adapter.call("transfer_status", {"transfer_id": "x", "request_digest": "0" * 64})
        asyncio.run(run())
        self.assertEqual(session.calls, 3)

    def test_expired_total_deadline_never_sends(self):
        class Session:
            calls = 0
            async def call_tool(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("sent after deadline")
        session = Session()
        adapter = TransportAdapter(session, "velo", "http://127.0.0.1:9/mcp",
                                   time.monotonic() - 1, 1, [])
        async def run():
            with self.assertRaises(AdapterError) as err:
                await adapter.call("transfer_capabilities", {})
            self.assertEqual(err.exception.code, "deadline_exceeded")
        asyncio.run(run())
        self.assertEqual(session.calls, 0)

    def test_malformed_or_conflicting_mcp_content_fails_closed(self):
        from mcp.types import CallToolResult, TextContent

        class Session:
            def __init__(self, result):
                self.result = result
            async def call_tool(self, *args, **kwargs):
                return self.result

        envelope = {"schema": "velo.transfer.mcp.response.v1", "status": "success",
                    "result": {"schema": "velo.transfer.guest.response.v1"}}
        cases = [
            CallToolResult(content=[TextContent(type="text", text=json.dumps(envelope))],
                           structured_content=envelope, is_error=True),
            CallToolResult(content=[TextContent(type="text", text="{}")], structured_content=envelope),
            CallToolResult(content=[TextContent(type="text", text=json.dumps(envelope))],
                           structured_content={"status": "success"}),
        ]
        for response in cases:
            adapter = TransportAdapter(Session(response), "velo", "http://127.0.0.1:9/mcp",
                                       time.monotonic() + 10, 1, [])
            async def run():
                with self.assertRaises(AdapterError):
                    await adapter.call("transfer_capabilities", {})
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()

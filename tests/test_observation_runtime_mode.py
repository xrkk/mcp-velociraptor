"""Bounded daily/approved entry checks; no archive qualification or VM suite."""
from contextlib import redirect_stderr
from io import StringIO
import unittest
from unittest.mock import Mock, patch

from mcp.server.mcpserver import MCPServer
import asyncio
import socket
import threading
import time
import httpx2
import uvicorn
import mcp_velociraptor_bridge as bridge
from velociraptor_transport import (
    OBSERVATION_ENV, TransportConfigError, build_formal_http_app,
    resolve_transport_config,
)


class RuntimeModeTests(unittest.TestCase):
    def config(self, **extra):
        return resolve_transport_config({
            'VELOCIRAPTOR_MCP_TRANSPORT': 'http',
            'VELOCIRAPTOR_MCP_HOST': '127.0.0.1',
            'VELOCIRAPTOR_MCP_BEARER_TOKEN': 'mode-test', **extra,
        })

    def test_daily_is_default_and_approved_is_explicit(self):
        self.assertFalse(self.config().observation_enabled)
        self.assertTrue(self.config(**{OBSERVATION_ENV: 'approved'}).observation_enabled)
        self.assertFalse(resolve_transport_config({}).observation_enabled)

    def test_invalid_selector_and_stdio_approved_reject(self):
        for value in ('', 'true', 'on', 'model', 'aproved'):
            with self.subTest(value=value), self.assertRaises(TransportConfigError):
                self.config(**{OBSERVATION_ENV: value})
        with self.assertRaises(TransportConfigError):
            resolve_transport_config({OBSERVATION_ENV: 'approved'})

    def test_daily_main_never_requests_archive_authority(self):
        server = Mock()
        with patch.object(bridge, 'resolve_transport_config', return_value=self.config()), \
                patch.object(bridge, 'create_server', return_value=server), \
                patch.object(bridge, 'run_formal_http') as run, \
                patch('velociraptor_observation_controller.SessionController.open_approved',
                      side_effect=AssertionError('archive must stay off')):
            self.assertEqual(bridge.main(), 0)
        run.assert_called_once_with(server, self.config())
        server._guest_transfer_tools.shutdown.assert_called_once_with()

    def test_approved_missing_authority_rejects_before_backend(self):
        failure = Mock()
        with patch.object(bridge, 'resolve_transport_config',
                          return_value=self.config(**{OBSERVATION_ENV: 'approved'})), \
                patch.object(bridge, 'create_server') as backend, \
                patch('velociraptor_observation_controller.SessionController.open_approved',
                      side_effect=RuntimeError('unapproved')), redirect_stderr(StringIO()):
            self.assertEqual(bridge.main(on_failure=failure), 2)
        backend.assert_not_called()
        failure.assert_called_once_with('OBSERVATION_STARTUP_REJECTED')


class DailyHTTPTests(unittest.IsolatedAsyncioTestCase):
    config = RuntimeModeTests.config

    async def test_daily_actual_sdk_session_and_security_gates(self):
        server = MCPServer('daily-mode')
        @server.tool()
        def echo(value: str) -> str:
            return value
        base = {'authorization': 'Bearer mode-test',
                'accept': 'application/json, text/event-stream'}
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                   'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                              'clientInfo': {'name': 'mode-test', 'version': '1'}}}
        from dataclasses import replace
        sock = socket.socket(); sock.bind(('127.0.0.1', 0)); sock.listen(); sock.setblocking(False)
        port = sock.getsockname()[1]
        app = build_formal_http_app(server, replace(self.config(), port=port))
        self.assertFalse(hasattr(app.state, 'observation_controller'))
        service = uvicorn.Server(uvicorn.Config(app, log_level='critical'))
        thread = threading.Thread(target=lambda: service.run(sockets=[sock]), daemon=False)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not service.started and time.monotonic() < deadline:
                await asyncio.sleep(.01)
            self.assertTrue(service.started)
            async with httpx2.AsyncClient(base_url=f'http://127.0.0.1:{port}',
                                          trust_env=False, timeout=5) as client:
                self.assertEqual((await client.post('/mcp', json=payload)).status_code, 401)
                self.assertEqual((await client.post('/mcp', json=payload,
                    headers={**base, 'host': 'foreign.example'})).status_code, 421)
                self.assertEqual((await client.post('/mcp', json=payload,
                    headers={**base, 'origin': 'https://foreign.example'})).status_code, 403)
                response = await client.post('/mcp', json=payload, headers=base)
                self.assertEqual(response.status_code, 200, response.text)
                sid = response.headers['mcp-session-id']
                instance = response.headers['x-mcp-server-instance']
                headers = {**base, 'mcp-session-id': sid,
                           'mcp-protocol-version': '2025-11-25'}
                initialized = await client.post('/mcp', headers=headers,
                    json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                self.assertEqual(initialized.status_code, 202)
                call = await client.post('/mcp', headers=headers,
                    json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                          'params': {'name': 'echo', 'arguments': {'value': 'daily'}}})
                self.assertEqual(call.status_code, 200, call.text)
                self.assertIn('daily', call.text)
                self.assertIn(sid, app.state.transfer_bindings.initialized)
                self.assertEqual(app.state.transfer_bindings.instance, instance)
                closed = await client.delete('/mcp', headers=headers)
                self.assertEqual(closed.status_code, 200, closed.text)
                self.assertNotIn('x-velo-observation-cut', closed.headers)
                self.assertFalse(app.state.transfer_bindings.live(sid))
        finally:
            service.should_exit = True
            await asyncio.to_thread(thread.join, 10)
            sock.close()
            self.assertFalse(thread.is_alive())

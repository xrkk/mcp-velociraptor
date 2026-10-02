"""Real formal middleware + client; ASGI is an explicit transport/mutation seam.

Guest business is a dispatch spy here. Native guest semantics remain unchanged.
"""
import base64
import hashlib
import time
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx2
from mcp.server.mcpserver import MCPServer
from velo_transfer.adapters import AdapterError, TransportAdapter, _DirectChunkChannel
from velociraptor_transport import TransportConfig, build_formal_http_app


ARGS = {'transfer_id': 'trial', 'request_digest': 'a' * 64, 'offset': 0,
        'chunks': [{'count': 1, 'data_base64': base64.b64encode(b'x').decode(),
                    'chunk_sha256': hashlib.sha256(b'x').hexdigest()}]}


class ResponseMutation:
    """Corrupt an actual middleware/endpoint response, never manufacture httpx Response."""
    def __init__(self, app):
        self.app = app
        self.mode = None
        self.content_type = None
        self.seen = []

    async def __call__(self, scope, receive, send):
        async def observe(message):
            if scope.get('path') == '/chunkbin':
                self.seen.append(dict(message))
                if self.mode and message['type'] == 'http.response.start':
                    message = dict(message)
                    headers = [(k, v) for k, v in message['headers']
                               if k.lower() not in (b'content-length', b'x-mcp-server-instance')]
                    if self.mode == 'changed_instance':
                        headers.append((b'x-mcp-server-instance', b'changed'))
                    if self.content_type:
                        headers = [(k,v) for k,v in headers if k.lower() != b'content-type']
                        headers.append((b'content-type', self.content_type))
                    message['headers'] = headers
                if isinstance(self.mode, bytes) and message['type'] == 'http.response.body':
                    message = dict(message, body=self.mode)
            await send(message)
        await self.app(scope, receive, observe)


class SafetyClientTests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def connected(self):
        self.dispatched = []
        def invoke(name, **arguments):
            self.dispatched.append((name, arguments))
            return SimpleNamespace(status='success', result={'verified_offset': 1, 'accepted': 1})
        server = MCPServer('pc026-security-composition')
        server._guest_transfer_tools = SimpleNamespace(invoke=invoke)
        app = build_formal_http_app(server, TransportConfig('http', host='fixture', port=28790,
            bearer_token='fixture-token', allowed_origins=('https://allowed.example',)))
        self.app = app
        self.transport_app = ResponseMutation(app)
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(self.transport_app),
                    base_url='http://fixture:28790', trust_env=False,
                    headers={'Authorization': 'Bearer fixture-token'}) as http:
                # Real SDK manager creates the ID, middleware observes both official handshakes.
                init = await http.post('/mcp', headers={'Accept': 'application/json, text/event-stream'},
                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                        'protocolVersion': '2025-03-26', 'capabilities': {},
                        'clientInfo': {'name': 'test', 'version': '1'}}})
                self.assertEqual(init.status_code, 200)
                sid = init.headers['mcp-session-id']
                initialized = await http.post('/mcp', headers={'Mcp-Session-Id': sid,
                        'Accept': 'application/json, text/event-stream'},
                    json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                self.assertEqual(initialized.status_code, 202)
                self.adapter = TransportAdapter(None, 'velo', 'http://fixture:28790/mcp',
                                                time.monotonic() + 30, 5, [init.headers['x-mcp-server-instance']])
                self.adapter._direct = _DirectChunkChannel(http, self.adapter.endpoint, sid,
                    init.headers['x-mcp-server-instance'], self.adapter.deadline_monotonic, 5)
                self.http = http
                try:
                    yield
                finally:
                    # Official session termination before closing the lifespan,
                    # including cases that deliberately corrupt response headers.
                    self.transport_app.app = app
                    self.transport_app.mode = None
                    http.headers['Authorization'] = 'Bearer fixture-token'
                    for key in ('Host', 'Origin'):
                        http.headers.pop(key, None)
                    await http.delete('/mcp', headers={'Mcp-Session-Id': sid})

    async def assert_error(self, code):
        start = len(self.transport_app.seen)
        with self.assertRaises(AdapterError) as raised:
            await self.adapter.call('transfer_chunks', ARGS)
        error = raised.exception
        self.assertEqual(error.code, code)
        self.assertTrue(error.may_have_committed)
        self.assertFalse(error.retryable)
        self.assertEqual(error.operation, 'transfer_chunks')
        starts = [m for m in self.transport_app.seen[start:] if m['type'] == 'http.response.start']
        self.assertEqual(len(starts), 1, 'one binary request, no JSON replay/retry')
        self.assertIsNotNone(self.adapter._direct)
        return starts[0]

    async def test_real_gates_auth_host_origin_and_session_exact_codes_no_dispatch(self):
        async with self.connected():
            for token in ('Bearer wrong', None):
                with self.subTest(token_present=token is not None):
                    if token is None:
                        del self.http.headers['Authorization']
                    else:
                        self.http.headers['Authorization'] = token
                    self.http.headers['Host'] = 'bad'
                    self.http.headers['Origin'] = 'https://denied.example'
                    start = await self.assert_error('unauthorized')
                    self.assertEqual(start['status'], 401)
                    self.assertNotIn(b'x-mcp-server-instance', dict(start['headers']))
            self.http.headers['Authorization'] = 'Bearer fixture-token'
            await self.assert_error('bad_host')
            del self.http.headers['Host']
            await self.assert_error('origin_denied')
            del self.http.headers['Origin']
            channel = self.adapter._direct
            sid = channel.session_id
            channel.session_id = ''
            await self.assert_error('invalid_frame')
            channel.session_id = 'unknown'
            await self.assert_error('session_not_found')
            channel.session_id = sid
            self.app.state.transfer_bindings.owners[sid] = b'wrong-owner'
            await self.assert_error('session_not_found')
            self.app.state.transfer_bindings.owners[sid] = hashlib.sha256(b'fixture-token').digest()
            ended = await self.http.delete('/mcp', headers={'Mcp-Session-Id': sid})
            self.assertEqual(ended.status_code, 200)
            await self.assert_error('session_not_found')
            self.assertEqual(self.dispatched, [])

    async def test_missing_session_real_gate(self):
        async with self.connected():
            # Remove only the session header at the request transport seam.
            original = self.transport_app.app
            async def remove_session(scope, receive, send):
                scope = dict(scope, headers=[(k,v) for k,v in scope['headers'] if k.lower()!=b'mcp-session-id'])
                await original(scope, receive, send)
            self.transport_app.app = remove_session
            start = await self.assert_error('session_required')
            self.assertEqual(start['status'], 400)
            self.assertEqual(self.dispatched, [])

    async def test_malformed_non200_not_valid_unauthorized(self):
        async with self.connected():
            self.http.headers['Authorization'] = 'Bearer wrong'
            for body in (b'[]', b'null', b'{"error":{"code":null}}',
                         b'{"error":{"code":"origin_denied"}}',
                         b'{"error":{"code":"unauthorized","detail":"hidden"}}',
                         b'{"error":{"code":"unauthorized"},"extra":1}',
                         b'{"error":{"code":"unauthorized","code":"unauthorized"}}', b'broken'):
                with self.subTest(body=body):
                    self.transport_app.mode = body
                    await self.assert_error('protocol_error')
            self.assertEqual(self.dispatched, [])

    async def test_non200_wrong_media_type_not_valid_unauthorized(self):
        async with self.connected():
            self.http.headers['Authorization'] = 'Bearer wrong'
            self.transport_app.mode = b'{"error":{"code":"unauthorized"}}'
            for content_type in (b'text/plain', b'application/json; charset=utf-8', b'application/octet-stream'):
                with self.subTest(content_type=content_type):
                    self.transport_app.content_type = content_type
                    await self.assert_error('protocol_error')
            self.assertEqual(self.dispatched, [])

    async def test_success_missing_or_changed_instance_unknown_and_no_replay(self):
        async with self.connected():
            for mode in ('missing_instance', 'changed_instance'):
                with self.subTest(mode=mode):
                    self.transport_app.mode = mode
                    await self.assert_error('instance_changed')
            self.assertEqual(len(self.dispatched), 2, 'each successful server write dispatched once')

    async def test_safe_non200_classifies_before_changed_instance(self):
        async with self.connected():
            self.transport_app.mode = 'changed_instance'
            self.http.headers['Origin'] = 'https://denied.example'
            await self.assert_error('origin_denied')
            self.assertEqual(self.dispatched, [])

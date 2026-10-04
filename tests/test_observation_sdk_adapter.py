"""Real official SDK loopback and resource fault tests; no controller/cut authority."""
import asyncio
import contextvars
from contextlib import asynccontextmanager
import socket
import threading
import time
import unittest
from unittest.mock import patch

import anyio
import httpx2
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.server.lowlevel.server import StreamableHTTPASGIApp
from starlette.applications import Starlette
from starlette.routing import Mount
import velociraptor_observation_sdk_adapter as adapter


class ResourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_source_pin_drift_rejects_actual_manager_before_base_constructor(self):
        import velociraptor_observation_sdk as sdk
        actual = sdk.importlib.metadata.version
        with patch.object(sdk.importlib.metadata, 'version',
                side_effect=lambda key: 'drift' if key=='mcp' else actual(key)), \
                patch.object(adapter._BaseManager, '__init__') as create, \
                self.assertRaisesRegex(sdk.SDKQualificationError,'sdk_version_drift'):
            adapter._TrackedManager(MCPServer('MODEL-gate')._lowlevel_server)
        create.assert_not_called()

    async def test_real_context_and_memory_streams_clones_and_deindexed_pair_close_once(self):
        resources = adapter._Resources()
        send, receive = resources.memory(1)
        clone = send.clone()
        await clone.send('MODEL')
        self.assertEqual(await receive.receive(), 'MODEL')
        await resources.close_all()
        await resources.close_all()
        self.assertEqual(len(resources.streams), 3)
        self.assertTrue(all(s.closed and s._attempted for s in resources.streams))
        other = adapter._Resources()
        transport = adapter._TrackedTransport(mcp_session_id='MODEL', resources=other)
        pair = other.memory(1)
        transport._request_streams['slot'] = pair
        await transport._clean_up_memory_streams('slot')
        self.assertNotIn('slot', transport._request_streams)
        self.assertEqual(len(other.streams), 2)
        self.assertTrue(all(s.closed for s in pair))
        context = other.context(1)
        variable = contextvars.ContextVar('MODEL-sdk-context')
        token = variable.set('copied-at-send')
        try:
            await context[0].send('context-payload')
        finally:
            variable.reset(token)
        self.assertEqual(await context[1].receive(), 'context-payload')
        self.assertEqual(context[1].last_context.get(variable), 'copied-at-send')
        await other.close_all()

    async def test_actual_dispatcher_strict_connection_close_fault_is_not_swallowed(self):
        resources = adapter._Resources()
        send, receive = resources.context(0)
        outgoing, output = resources.context(0)
        primary = OSError('MODEL-connection-close')
        calls=[]
        class FaultConnection(adapter.Connection):
            @classmethod
            def for_loop(cls, *args, **kwargs):
                connection = super().for_loop(*args, **kwargs)
                async def fail():
                    calls.append(True)
                    raise primary
                connection.exit_stack.push_async_callback(fail)
                return connection
        with patch.object(adapter, 'Connection', FaultConnection):
            task = asyncio.create_task(adapter._serve_loop(MCPServer('MODEL-close')._lowlevel_server,
                receive, outgoing, lifespan_state=None, session_id='MODEL', resources=resources))
            await asyncio.sleep(.01)
            await send.aclose()
            with self.assertRaises(OSError) as caught:
                await task
        self.assertIs(caught.exception, primary)
        self.assertEqual(calls,[True])
        self.assertTrue(resources.dispatcher_joined)
        self.assertFalse(resources.connection_closed)
        self.assertIs(resources.error,primary)
        with self.assertRaises(OSError): await resources.close_all()
        self.assertTrue(all(s.closed for s in resources.streams))

    async def test_close_failure_retained_after_deindex_and_other_close_attempted_once(self):
        resources = adapter._Resources()
        primary = OSError('MODEL-close')
        class Stream:
            def __init__(self, fail=False): self.calls = 0; self.fail = fail
            async def aclose(self):
                self.calls += 1
                if self.fail: raise primary
        first, second = Stream(True), Stream()
        transport = adapter._TrackedTransport(mcp_session_id='MODEL', resources=resources)
        transport._request_streams['slot'] = (resources.watch(first), resources.watch(second))
        with self.assertRaises(OSError) as caught:
            await transport._clean_up_memory_streams('slot')
        self.assertIs(caught.exception, primary)
        self.assertEqual((first.calls, second.calls), (1, 1))
        self.assertNotIn('slot', transport._request_streams)
        self.assertEqual(len(resources.streams), 2)
        for _ in range(2):
            with self.assertRaises(OSError): await resources.close_all()
        self.assertEqual((first.calls, second.calls), (1, 1))
        self.assertFalse(resources.known_closed())

    async def test_terminate_closes_unindexed_resources_and_preserves_close_failure(self):
        resources = adapter._Resources()
        transport = adapter._TrackedTransport(mcp_session_id='MODEL', resources=resources)
        pair = resources.memory(1)  # Already deindexed SDK pair still owned.
        await transport.terminate()
        self.assertTrue(resources.closing)
        self.assertTrue(all(s.closed for s in pair))
        self.assertFalse(resources.known_closed(), 'no actual runner/dispatcher/connection exit yet')

    async def test_real_memory_sync_close_fault_retained_once_not_retried_async(self):
        resources=adapter._Resources()
        send,receive=resources.memory(1)
        original=type(send._stream).close
        primary=OSError('MODEL-after-real-sync-close')
        calls=[]
        def fail(stream):
            calls.append(stream)
            original(stream)
            raise primary
        with patch.object(type(send._stream),'close',new=fail):
            with self.assertRaises(OSError) as caught:send.close()
        self.assertIs(caught.exception,primary)
        self.assertIs(resources.error,primary)
        with self.assertRaises(OSError) as caught:await send.aclose()
        self.assertIs(caught.exception,primary)
        self.assertEqual(calls,[send._stream])
        await receive.aclose()
        self.assertFalse(send.closed)


class LoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        server = MCPServer('MODEL-adapter')
        @server.tool()
        def echo(value: str) -> str:
            return value
        self.manager = adapter._TrackedManager(server._lowlevel_server)
        @asynccontextmanager
        async def lifespan(app):
            async with self.manager.run():
                yield
        self.app = Starlette(routes=[Mount('/mcp', app=StreamableHTTPASGIApp(self.manager))], lifespan=lifespan)
        sock = socket.socket()
        sock.bind(('127.0.0.1',0)); sock.listen(); sock.setblocking(False)
        self.sock = sock
        self.url = f'http://127.0.0.1:{sock.getsockname()[1]}/mcp/'
        self.running = uvicorn.Server(uvicorn.Config(self.app, log_level='critical'))
        self.thread = threading.Thread(target=lambda: self.running.run(sockets=[sock]), daemon=False)
        self.thread.start()
        deadline = time.monotonic()+5
        while not self.running.started and time.monotonic()<deadline:
            await asyncio.sleep(.01)
        self.assertTrue(self.running.started)

    async def asyncTearDown(self):
        self.running.should_exit = True
        await asyncio.to_thread(self.thread.join, 5)
        self.sock.close()
        self.assertFalse(self.thread.is_alive())

    async def test_actual_sdk_sse_normal_notification_get_and_strict_runner_exit(self):
        ids=[]
        async def observe(response):
            if response.headers.get('mcp-session-id'): ids.append(response.headers['mcp-session-id'])
        async with httpx2.AsyncClient(trust_env=False, timeout=5,event_hooks={'response':[observe]}) as http:
            async with streamable_http_client(self.url,http_client=http) as (read,write):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    self.assertEqual(len((await session.list_tools()).tools),1)
                    result = await session.call_tool('echo',{'value':'MODEL-real-wire'})
                    self.assertFalse(result.is_error)
        self.assertTrue(ids)
        transport = self.manager._owned_transports[ids[0]]
        deadline = time.monotonic()+3
        while not transport._owned.runner_exited and time.monotonic()<deadline:
            await asyncio.sleep(.001)
        self.assertTrue(transport._owned.known_closed(), repr(transport._owned.error))
        self.assertTrue(transport._owned.streams)
        self.assertTrue(all(s.closed for s in transport._owned.streams))

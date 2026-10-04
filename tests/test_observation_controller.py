"""Actual SDK/HTTP -> real ledger with MODEL Win32 I/O; no native qualification."""
import asyncio
from contextlib import asynccontextmanager
import socket
import threading
import time
import unittest
from unittest.mock import patch

import httpx2
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.routing import Mount

from velociraptor_observation_controller import SessionController, _HTTPIngress, _Ticket
from velociraptor_observation_sdk_adapter import _TrackedManager
from velociraptor_transport import BearerAuthGate, HostOriginGate
from tests import test_observation_attempts as ledger_fixture
from tests.test_observation_startup import model_budgets


class ChainTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture=ledger_fixture.LedgerModels();self.addCleanup(self.fixture.doCleanups)
        self.ledger,self.fs,self.config=self.fixture.ledger()
        self.controller=object.__new__(SessionController)
        self.controller._initialize(self.ledger,model_budgets())
        self.calls=[];self.started=threading.Event();self.release=threading.Event()
        server=MCPServer('MODEL-controller')
        @server.tool()
        def echo(value:str)->str:
            # The actual catalog ACK must predate even the first side effect.
            rows=self.records()
            from velociraptor_observation import current_scope
            sequence=current_scope()._journal.parent()['acceptance_sequence']
            self.assertEqual(len([r for r in rows if r['record_type']=='ACCEPT_ACK'
                and r['payload']['attempt_sequence']==sequence]),1)
            self.calls.append(value)
            if value=='latch':
                self.started.set();self.assertTrue(self.release.wait(5))
            return value
        self.manager=_TrackedManager(server._lowlevel_server)
        self.controller._attach_manager(self.manager)
        @asynccontextmanager
        async def lifespan(app):
            self.server_loop=asyncio.get_running_loop()
            async with self.manager.run():yield
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();sock.setblocking(False)
        self.sock=sock;port=sock.getsockname()[1];self.url=f'http://127.0.0.1:{port}/mcp/'
        app=Starlette(routes=[Mount('/mcp',app=_HTTPIngress(self.controller))],lifespan=lifespan)
        app=BearerAuthGate(HostOriginGate(app,(f'127.0.0.1:{port}',),()),'MODEL')
        self.server=uvicorn.Server(uvicorn.Config(app,log_level='critical'))
        self.thread=threading.Thread(target=lambda:self.server.run(sockets=[sock]),daemon=False)
        self.thread.start();deadline=time.monotonic()+5
        while not self.server.started and time.monotonic()<deadline:await asyncio.sleep(.01)
        self.assertTrue(self.server.started)
        self.http=httpx2.AsyncClient(trust_env=False,timeout=8,headers={'authorization':'Bearer MODEL',
            'accept':'application/json, text/event-stream','content-type':'application/json'})

    async def asyncTearDown(self):
        self.release.set()
        for transport in self.manager._owned_transports.values():
            # Test fixture cleanup only; no successful cut claimed.
            if not transport.is_terminated:
                asyncio.run_coroutine_threadsafe(transport.terminate(),self.server_loop).result(5)
        async def settle():
            await asyncio.gather(*self.controller._close_tasks.values(),return_exceptions=True)
        asyncio.run_coroutine_threadsafe(settle(),self.server_loop).result(5)
        self.assertTrue(all(t.done() for t in self.controller._close_tasks.values()))
        await self.http.aclose()
        self.server.should_exit=True
        await asyncio.to_thread(self.thread.join,5);self.sock.close()
        self.assertFalse(self.thread.is_alive())

    def records(self):
        return [self.config.catalog_codec.parse(x) for x in self.fixture.catalog(self.ledger,self.fs)]

    async def initialize(self):
        # Use actual raw SDK envelopes to retain exact typed IDs for concurrency.
        r=await self.http.post(self.url,json={'jsonrpc':'2.0','id':0,'method':'initialize','params':
            {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'MODEL','version':'1'}}})
        self.assertEqual(r.status_code,200,r.text)
        session=r.headers['mcp-session-id']
        headers={'mcp-session-id':session,'mcp-protocol-version':'2025-11-25'}
        self.http.headers.update(headers)
        r=await self.http.post(self.url,json={'jsonrpc':'2.0','method':'notifications/initialized'})
        self.assertEqual(r.status_code,202,r.text)
        deadline=time.monotonic()+3
        while not self.controller._sessions[session]['initialized'] and time.monotonic()<deadline:await asyncio.sleep(.001)
        self.assertTrue(self.controller._sessions[session]['initialized'])
        return session

    async def call(self,rid,value='ok',name='echo'):
        return await self.http.post(self.url,json={'jsonrpc':'2.0','id':rid,'method':'tools/call',
            'params':{'name':name,'arguments':{'value':value}}})

    async def test_actual_official_sdk_chain_ack_business_end_and_delete_refuses_cut(self):
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                self.assertEqual(len((await sdk.list_tools()).tools),1)
                result=await sdk.call_tool('echo',{'value':'official'})
                self.assertFalse(result.is_error)
        self.assertEqual(self.calls,['official'])
        rows=self.records()
        self.assertEqual([r['record_type'] for r in rows],['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END'])
        self.assertEqual(rows[-1]['payload']['outcome'],'returned')
        self.assertFalse(self.ledger._active)
        self.assertTrue(all(r.handler_exited and r.http_exited for r in self.controller._work.values()))
        self.assertTrue(all(s['state']=='CLOSING' for s in self.controller._sessions.values()))

    async def test_typed_alias_queue_cancel_does_not_cancel_active_other_type(self):
        session=await self.initialize()
        first=asyncio.create_task(self.call(7,'latch'))
        try:
            deadline=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            second=asyncio.create_task(self.call('007','never'))
            deadline=time.monotonic()+3
            while self.ledger._attempt_count<2 and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertEqual(self.ledger._attempt_count,2)
            self.assertEqual(self.calls,['latch'])
            cancel=await self.http.post(self.url,json={'jsonrpc':'2.0','method':'notifications/cancelled',
                'params':{'requestId':'007','reason':'MODEL-queued'}})
            self.assertEqual(cancel.status_code,202)
            rejected=await second
            self.assertIn('Request cancelled',rejected.text)
            self.assertFalse(first.done())
            self.release.set();self.assertEqual((await first).status_code,200)
        finally:
            self.release.set()
            if not first.done():await first
        ends=[r['payload'] for r in self.records() if r['record_type']=='ATTEMPT_END']
        self.assertEqual(sorted(x['outcome'] for x in ends),['cancelled','returned'])
        self.assertEqual(len(self.ledger._seen),2)
        self.assertEqual(self.calls,['latch'])
        self.assertEqual(self.controller._state,'ACTIVE')

    async def test_duplicate_has_new_begin_end_without_second_sdk_business(self):
        await self.initialize()
        self.assertEqual((await self.call(9)).status_code,200)
        r=await self.call(9)
        self.assertIn('DUPLICATE',r.text)
        self.assertEqual(self.calls,['ok'])
        self.assertEqual([r['record_type'] for r in self.records()],
            ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END','ATTEMPT_BEGIN','ATTEMPT_END'])
        self.assertEqual(self.records()[-1]['payload']['disposition'],'REJECTED')

    async def test_schema_failure_after_ack_zero_business_and_actual_raised_end(self):
        await self.initialize()
        r=await self.http.post(self.url,json={'jsonrpc':'2.0','id':5,'method':'tools/call',
            'params':{'name':'echo','arguments':{},'_meta':1}})
        self.assertEqual(r.status_code,200)
        self.assertIn('error',r.text)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.records()[-1]['payload']['outcome'],'raised')
        self.assertEqual(self.ledger._attempt_count,1)

    async def test_gates_auth_host_modern_duplicate_header_invalid_parent_zero_writer(self):
        await self.initialize();before=self.records()
        cases=[({'authorization':'Bearer bad'}, {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'echo'}},401),
            ({'host':'foreign:1'},{'jsonrpc':'2.0','id':1,'method':'tools/list'},421),
            ({'mcp-protocol-version':'2026-07-28'},{'jsonrpc':'2.0','id':1,'method':'tools/list'},400),
            ({'last-event-id':'replay'},{'jsonrpc':'2.0','id':1,'method':'tools/list'},400),
            ({},{'jsonrpc':'2.0','id':True,'method':'tools/call','params':{'name':'echo'}},400)]
        for headers,message,status in cases:
            r=await self.http.post(self.url,headers=headers,json=message)
            self.assertEqual(r.status_code,status,r.text)
        r=await self.http.post(self.url,content=b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}')
        self.assertEqual(r.status_code,400)
        self.assertEqual(self.records(),before);self.assertEqual(self.calls,[])

    async def test_constructor_and_ticket_cannot_mint_public_model_authority(self):
        with self.assertRaises(TypeError):SessionController()
        with self.assertRaises(TypeError):_Ticket()

    async def test_wire_and_dispatcher_alias_slots_wait_real_handler_and_stream_close(self):
        await self.initialize()
        first=asyncio.create_task(self.call(7,'latch'))
        second=None
        try:
            deadline=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            second=asyncio.create_task(self.call('007','after'))
            deadline=time.monotonic()+3
            while self.ledger._attempt_count<2 and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertEqual(self.ledger._attempt_count,2)
            self.assertFalse(second.done());self.assertEqual(self.calls,['latch'])
            self.release.set();await first;await second
        finally:
            self.release.set()
            for task in (first,second):
                if task is not None and not task.done():await task
        self.assertEqual(self.calls,['latch','after'])
        keys=[r['payload']['key'] for r in self.records() if r['record_type']=='ATTEMPT_BEGIN']
        self.assertEqual([(k['request_id_type'],k['request_id']) for k in keys],[('integer',7),('string','007')])
        self.assertEqual(len([r for r in self.records() if r['record_type']=='ATTEMPT_END']),2)

    async def test_timeout_keeps_true_live_thread_and_rejects_late_ingress_without_begin(self):
        session=await self.initialize()
        self.controller._limits['close_timeout_ns']=50000000
        first=asyncio.create_task(self.call(7,'latch'))
        try:
            deadline=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            response=await self.http.delete(self.url)
            self.assertEqual(response.status_code,503,response.text)
            self.assertIn('close_unknown',response.text)
            self.assertNotIn('x-velo-observation-close',response.headers)
            self.assertNotIn('x-velo-observation-cut',response.headers)
            self.assertFalse(self.release.is_set())
            self.assertTrue(any(r.started and not r.handler_exited for r in self.controller._work.values()))
            before=self.ledger._attempt_count
            late=await self.call(8,'late')
            self.assertEqual(late.status_code,503)
            self.assertEqual(self.ledger._attempt_count,before)
            self.release.set();await first
        finally:
            self.release.set()
            if not first.done():await first
        self.assertEqual(self.controller._sessions[session]['state'],'UNKNOWN')
        self.assertEqual(self.controller._state,'DRAINING')
        self.assertEqual(self.calls,['latch'])

    async def fail_catalog(self,kind):
        await self.initialize();actual=self.ledger._catalog.publish
        primary=OSError('MODEL-'+kind);writes=[]
        def publish(raw):
            writes.append(self.config.catalog_codec.parse(raw)['record_type'])
            result=actual(raw)
            if writes[-1]==kind:raise primary
            return result
        with patch.object(self.ledger._catalog,'publish',side_effect=publish):
            r=await self.call(7,'fault')
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertTrue(self.ledger._unknown)
        self.assertTrue(any(row.error is primary for row in self.controller._work.values()))
        self.assertEqual(self.calls,['fault'] if kind=='ATTEMPT_END' else [])
        count=self.ledger._attempt_count
        self.assertEqual((await self.call(8,'late')).status_code,503)
        self.assertEqual(self.ledger._attempt_count,count)
        self.assertEqual(writes.count(kind),1)
        self.assertNotIn('x-velo-observation-cut',r.headers)

    async def test_actual_begin_publication_unknown_zero_business_and_sticky(self):
        await self.fail_catalog('ATTEMPT_BEGIN')

    async def test_actual_ack_publication_unknown_zero_business_and_sticky(self):
        await self.fail_catalog('ACCEPT_ACK')

    async def test_actual_end_publication_unknown_preserves_error_and_refuses_late(self):
        await self.fail_catalog('ATTEMPT_END')

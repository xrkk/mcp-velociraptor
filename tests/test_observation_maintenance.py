"""Actual POSIX export files/loopback/SDK/transfer processes, Win32 authority MODEL."""
import asyncio
from contextlib import asynccontextmanager
import copy
import hashlib
import json
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
import uvicorn

from tests import test_observation_attempts as attempts
from tests import test_observation_native_export as native
from tests import test_transfer_guest as guest_fixture
from velociraptor_observation_controller import SessionController, _APPROVED_CONTROLLERS
from velociraptor_observation_maintenance_plan import acquisition_plan
from velociraptor_transport import TransportConfig, build_formal_http_app
from velo_transfer.mcp_tools import register_transfer_tools


def archive_limits():
    values=attempts.budgets();A=4096
    values.update(max_attempts=A,max_directories=A+2,max_catalog_records=3*A+2,
        max_total_archive_bytes=(3*A+2)*4096+A*40960+12288,max_seen_key_bytes=A*1024)
    return values


def lifecycle_limits(limits):
    limits.update(max_sdk_work=20000,max_binary_work=4000,max_sessions=3,
        max_retained_state_bytes=128<<20,max_export_files=400000,max_export_directories=15000,
        max_export_bytes=1<<42,max_maintenance_calls=12000,max_maintenance_bytes=2<<30,
        max_proof_bytes=4<<20,max_source_manifest_bytes=4<<20,max_cut_bytes=4<<20)


class MaintenanceHTTP(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.native=native.PosixExportIO();self.native.configure_limits=lifecycle_limits
        self.addCleanup(self.native.doCleanups)
        # Capture original first: fixture patch must not recurse.
        original=attempts.budgets;values=original();A=4096
        values.update(max_attempts=A,max_directories=A+2,max_catalog_records=3*A+2,
            max_total_archive_bytes=(3*A+2)*4096+A*40960+12288,max_seen_key_bytes=A*1024)
        p=patch.object(attempts,'budgets',return_value=values);p.start();self.addCleanup(p.stop)
        configuration=attempts.configuration
        def configured(fs):
            value=configuration(fs)
            value.group.allowed[native.attempts.cfg.CONFIG]=native.ref(native.attempts.cfg.CONFIG,native.canonical(value.document))
            return value
        p=patch.object(attempts,'configuration',side_effect=configured);p.start();self.addCleanup(p.stop)
        self.ledger,self.fs,self.config,self.exporter=self.native.setup_export()
        p=patch.object(native.export,'_free_bytes',return_value=1<<60);p.start();self.addCleanup(p.stop)
        self.guest=guest_fixture.GuestTests();self.guest.setUp();self.addCleanup(self.guest.doCleanups)
        # Exact existing export root only, not its namespace. Policy is issued
        # before initialization and never widened after the original cut.
        self.export_parent=self.native.disk_root/'controlled'/('e'+self.ledger._instance)
        # Real path mapping is solely this private OS-I/O test seam.
        self.exporter._namespace_source=getattr(self,'_native_namespace_source',
            lambda raw:Path(raw).is_relative_to(self.native.disk_root/'controlled'))
        source_path=self.exporter._source_path
        self.exporter._source_path=lambda sid:self.fs.local(source_path(sid))
        limits=dict(self.exporter.codec.limits)
        self.controller=object.__new__(SessionController);self.controller._initialize(self.ledger,limits)
        self.controller._exporter=self.exporter;_APPROVED_CONTROLLERS.add(self.controller)
        server=MCPServer('MODEL-maintenance')
        @server.tool()
        def echo(value:str)->str:return value
        service=register_transfer_tools(server,factory=lambda:self.guest.service)
        server._guest_transfer_tools=service;server._observation_controller=self.controller
        self.service=service
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen();self.socket.setblocking(False)
        port=self.socket.getsockname()[1];self.url=f'http://127.0.0.1:{port}/mcp'
        app=build_formal_http_app(server,TransportConfig('http',host='127.0.0.1',port=port,bearer_token='MODEL',observation_enabled=True))
        self.server=uvicorn.Server(uvicorn.Config(app,log_level='critical'))
        self.thread=threading.Thread(target=lambda:self.server.run(sockets=[self.socket]),daemon=False)
        self.thread.start()
        until=time.monotonic()+5
        while not self.server.started and time.monotonic()<until:await asyncio.sleep(.01)
        self.assertTrue(self.server.started)
        self.responses=[]
        async def hook(response):
            self.responses.append(response)
        self.http=httpx2.AsyncClient(headers={'authorization':'Bearer MODEL'},trust_env=False,timeout=15,
            event_hooks={'response':[hook]})
        await self._original_sdk()
        if getattr(self,'ENTRYPOINT_OWNS_RUN',False):return
        closed=[r for r in self.responses if r.request.method=='DELETE']
        self.assertEqual(closed[-1].status_code,200,closed[-1].text)
        self.original=next(sid for sid,r in self.controller._sessions.items() if r['state']=='CLOSED')
        self.source=self.exporter._source_path(self.original)
        self.assertTrue((self.source/'cut.json').is_file())
        # Fixed policy for this isolated transfer fixture authorizes the exact
        # source directory. Replace before GuestService is exposed to any RPC.
        self.guest.service.shutdown()
        policy=json.loads(self.guest.policy.read_bytes());policy['read_roots']=[str(self.source)]
        policy['limits']['max_batch_chunks']=4
        configure=getattr(self,'configure_policy',None)
        if configure is not None:configure(policy['limits'])
        self.guest.limits.update(policy['limits'])
        self.guest.policy.write_text(json.dumps(policy));self.guest.policy.chmod(0o600)
        from velo_transfer.guest_service import GuestTransferService
        self.guest.service=GuestTransferService(self.guest.policy,_observation=self.guest.observation,
            _acl_verifier=lambda path,kind:True)
        self.addCleanup(self.guest.service.shutdown)
        self.request=self.guest.request('pull',[{'absolute_path':str(self.source),'relative_path':'original'}],
            self.guest.host/'downloaded',transfer_id='maintenance')

    async def _original_sdk(self):
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize();await sdk.call_tool('echo',{'value':'original'})

    async def asyncTearDown(self):
        await self.http.aclose();self.service.shutdown()
        self.server.should_exit=True
        await asyncio.to_thread(self.thread.join,10);self.socket.close()
        self.assertFalse(self.thread.is_alive())
        for io in self.controller._close_io.values():
            if io.thread is not None:self.assertFalse(io.thread.is_alive())
        self.assertFalse(self.fs.fds)

    async def test_sdk_begin_actual_activation_live_get_and_native_source(self):
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize();await sdk.list_tools()
                result=await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertEqual(result.structured_content['status'],'success',result)
                sid=next(s for s in self.controller._sessions if s!=self.original)
                record=self.controller._maintenance[sid]
                self.assertEqual(record['original'],self.original)
                self.assertEqual(record['transfer_binding'],('maintenance',self.request['request_digest']))
                self.assertGreater(record['initial_calls'],1)
                status=result.structured_content['result']
                until=time.monotonic()+10
                while status['worker']['stopped'] is not True and time.monotonic()<until:
                    await asyncio.sleep(.02)
                    status=(await sdk.call_tool('transfer_status',{'transfer_id':'maintenance',
                        'request_digest':self.request['request_digest']})).structured_content['result']
                self.assertEqual(status['local_phase'],'SOURCE_READY',status)
                self.assertTrue(status['worker']['stopped'])
                self.assertTrue(any(c.session==sid and c.wait_status is not None and c.resources_closed
                    for c in self.controller._children.values()))
                self.assertTrue(self.controller._close_io[(sid,'maintenance_activation')].joined)
        closed=[r for r in self.responses if r.request.method=='DELETE']
        self.assertEqual(closed[-1].status_code,200,closed[-1].text)
        self.assertEqual(self.controller._sessions[sid]['state'],'CLOSED')
        self.assertTrue(self.exporter.receipt(sid,self.controller._closed_cuts[sid]))

    async def test_capacity_minus_one_zero_transfer_writer(self):
        facts=self.exporter._maintenance_source(self.original)
        plan=acquisition_plan(facts,self.guest.service.policy.limits,self.request['budget'],
            self.controller._limits['max_request_body_bytes'])
        self.controller._limits['max_binary_work']=plan['binary']-1
        before=list(self.guest.work.iterdir())
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertFalse(self.controller._maintenance)
                self.assertEqual(before,list(self.guest.work.iterdir()))
                self.assertEqual(self.ledger._attempt_count,1)  # Only the original echo.
        self.assertEqual([r for r in self.responses if r.request.method=='DELETE'][-1].status_code,200)

    async def test_source_identity_drift_zero_transfer_writer(self):
        name=next(n for n in self.fs.nodes if n.endswith('export.json'))
        self.fs.nodes[name]['id']=(1,b'X'*16)
        before=list(self.guest.work.iterdir())
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertFalse(self.controller._maintenance)
                self.assertEqual(before,list(self.guest.work.iterdir()))
                self.assertEqual(self.ledger._attempt_count,1)

    async def _deny(self,code):
        before=list(self.guest.work.iterdir())
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':self.request})
                denied=[r for r in self.responses if r.status_code>=400]
                self.assertIn(code,denied[-1].text)
                self.assertFalse(self.controller._maintenance)
                self.assertEqual(before,list(self.guest.work.iterdir()))
                self.assertEqual(self.ledger._attempt_count,1)
                self.assertFalse(self.controller._children)

    async def test_calls_minus_one_before_begin(self):
        await self._history_capacity_minus_one('calls','max_maintenance_calls')

    async def test_bytes_minus_one_before_begin(self):
        await self._history_capacity_minus_one('bytes','max_maintenance_bytes')

    async def _history_capacity_minus_one(self,kind,limit):
        facts=self.exporter._maintenance_source(self.original)
        plan=acquisition_plan(facts,self.guest.service.policy.limits,self.request['budget'],self.controller._limits['max_request_body_bytes'])
        before=self.ledger._attempt_count
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize();await sdk.list_tools()
                sid=next(s for s in self.controller._sessions if s!=self.original)
                history=[r for r in self.controller._work.values() if r.session==sid]
                actual=len(history) if kind=='calls' else sum(r.request_bytes+r.response_bytes for r in history)
                self.controller._limits[limit]=plan[kind]+actual-1
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertIn('maintenance_capacity',[r for r in self.responses if r.status_code>=400][-1].text)
                self.assertFalse(self.controller._maintenance);self.assertFalse(list(self.guest.work.iterdir()))
                self.assertEqual(self.ledger._attempt_count,before);self.assertFalse(self.controller._children)

    async def test_attempts_minus_one_before_begin(self):
        facts=self.exporter._maintenance_source(self.original)
        plan=acquisition_plan(facts,self.guest.service.policy.limits,self.request['budget'],self.controller._limits['max_request_body_bytes'])
        self.ledger._limits['max_attempts']=self.ledger._attempt_count+plan['attempts']-1
        await self._deny('maintenance_capacity')

    async def test_sdk_work_minus_one_before_begin(self):
        facts=self.exporter._maintenance_source(self.original)
        plan=acquisition_plan(facts,self.guest.service.policy.limits,self.request['budget'],self.controller._limits['max_request_body_bytes'])
        before=self.ledger._attempt_count
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                self.controller._limits['max_sdk_work']=self.controller._sequence+plan['sdk_work']-1
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertIn('maintenance_capacity',[r for r in self.responses if r.status_code>=400][-1].text)
                self.assertEqual(self.ledger._attempt_count,before)
                self.assertFalse(self.controller._maintenance);self.assertFalse(list(self.guest.work.iterdir()))
                self.controller._limits['max_sdk_work']=20000

    async def test_unknown_namespace_source_before_begin(self):
        self.request['sources'][0]['absolute_path']=str(self.source.parent/('s'+'b'*64))
        from velo_transfer.guest_service import request_digest
        self.request['request_digest']=request_digest(self.request)
        await self._deny('maintenance_source_invalid')

    async def test_wrong_owner_before_begin(self):
        self.controller._sessions[self.original]['owner']=b'x'*32
        await self._deny('maintenance_source_invalid')

    async def test_unclosed_source_before_begin(self):
        self.controller._sessions[self.original]['state']='UNKNOWN'
        try:await self._deny('maintenance_source_invalid')
        finally:self.controller._sessions[self.original]['state']='CLOSED'

    async def test_foreign_sd_before_begin(self):
        from tests.test_observation_windows import sd
        name=next(n for n in self.fs.nodes if n.endswith('export.json'))
        self.fs.nodes[name]['sd']=sd(foreign='S-1-5-11')
        await self._deny('invalid_or_unknown')

    async def test_fake_cut_source_before_begin(self):
        from velo_transfer.guest_service import request_digest
        self.request['sources'][0]['absolute_path']=str(self.source/'cut.json')
        self.request['request_digest']=request_digest(self.request)
        await self._deny('maintenance_source_invalid')

    async def test_other_instance_source_before_begin(self):
        from velo_transfer.guest_service import request_digest
        self.request['sources'][0]['absolute_path']=str(self.source.parent.parent/('e'+'b'*32)/self.source.name)
        self.request['request_digest']=request_digest(self.request)
        await self._deny('maintenance_source_invalid')

    async def test_read_root_insufficient_before_begin(self):
        from velo_transfer.guest_service import GuestTransferService
        self.guest.service.shutdown()
        document=json.loads(self.guest.policy.read_bytes());document['read_roots']=[str(self.guest.read)]
        self.guest.policy.write_text(json.dumps(document))
        self.guest.service=GuestTransferService(self.guest.policy,_observation=self.guest.observation,_acl_verifier=lambda p,k:True)
        self.addCleanup(self.guest.service.shutdown)
        await self._deny('invalid_or_unknown')

    async def test_activated_session_extra_tool_and_changed_transfer_rejected_before_begin(self):
        from velo_transfer.guest_service import request_digest
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                result=await sdk.call_tool('transfer_begin',{'request':self.request})
                self.assertEqual(result.structured_content['status'],'success')
                before=self.ledger._attempt_count
                work_before=set(self.guest.work.iterdir())
                with self.assertRaises(Exception):await sdk.call_tool('echo',{'value':'extra'})
                changed=copy.deepcopy(self.request);changed['transfer_id']='other';changed['request_digest']=request_digest(changed)
                with self.assertRaises(Exception):await sdk.call_tool('transfer_begin',{'request':changed})
                self.assertEqual(self.ledger._attempt_count,before)
                self.assertEqual(set(self.guest.work.iterdir()),work_before)

    async def test_closed_original_session_cannot_be_maintenance(self):
        before=self.ledger._attempt_count
        response=await self.http.post(self.url,headers={'Mcp-Session-Id':self.original,
            'Mcp-Protocol-Version':'2025-11-25','Accept':'application/json, text/event-stream'},
            json={'jsonrpc':'2.0','id':99,'method':'tools/call','params':{'name':'transfer_begin','arguments':{'request':self.request}}})
        self.assertGreaterEqual(response.status_code,400)
        self.assertFalse(self.controller._maintenance);self.assertFalse(list(self.guest.work.iterdir()))
        self.assertEqual(self.ledger._attempt_count,before)

    async def test_native_source_timeout_keeps_owned_thread_and_no_late_reservation(self):
        entered=threading.Event();release=threading.Event()
        real=self.exporter._maintenance_source
        def blocked(sid):
            entered.set();release.wait(5)
            return real(sid)
        self.exporter._maintenance_source=blocked
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize();self.controller._limits['close_timeout_ns']=20_000_000
                try:
                    with self.assertRaises(Exception):
                        await asyncio.wait_for(sdk.call_tool('transfer_begin',{'request':self.request}),2)
                    self.assertTrue(entered.is_set())
                    sid=next(s for s in self.controller._sessions if s!=self.original)
                    io=self.controller._close_io[(sid,'maintenance_activation')]
                    self.assertTrue(io.thread.is_alive());self.assertFalse(io.joined)
                    self.assertEqual(self.controller._sessions[sid]['state'],'UNKNOWN')
                    self.assertFalse(self.controller._maintenance);self.assertFalse(list(self.guest.work.iterdir()))
                finally:
                    release.set();self.controller._limits['close_timeout_ns']=300_000_000_000
                until=time.monotonic()+2
                while not io.joined and time.monotonic()<until:await asyncio.sleep(.001)
                self.assertFalse(io.thread.is_alive());self.assertTrue(io.joined)
                self.assertFalse(self.controller._maintenance);self.assertFalse(list(self.guest.work.iterdir()))
                # Actual server-loop ownership is preserved, never awaited on
                # the host test loop. After join, fixture teardown may release
                # its own held native descriptors without issuing CLOSED_KNOWN.
                self.exporter.close();self.ledger._poison()
                with self.assertRaisesRegex(Exception,'ledger_unknown'):self.ledger.close()
                self.assertEqual(self.controller._sessions[sid]['state'],'UNKNOWN')

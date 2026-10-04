"""Actual MODEL source reader + real exclusive filesystem exporter + SDK close."""
import base64
import copy
import json
import tempfile
import unittest
from unittest.mock import patch

from velociraptor_observation_cut import CutError, canonical, close_headers
from tests.observation_model_export import ModelExporter
from tests import test_observation_controller as chain

CUT_TRACES=[]


class CutHTTPTests(unittest.IsolatedAsyncioTestCase):
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call

    async def asyncSetUp(self):
        await chain.ChainTests.asyncSetUp(self)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.exporter=ModelExporter(self.directory.name,self.config,self.controller._limits)
        self.controller._exporter=self.exporter

    async def asyncTearDown(self):
        for row in self.controller._close_io.values():
            if row.task is not None:await row.task
            self.assertFalse(row.thread.is_alive())
        await chain.ChainTests.asyncTearDown(self)
        CUT_TRACES.append(dict(test=self.id(),boundary='MODEL_WINDOWS_SOURCE_AND_EXPORT_IDENTITIES_REAL_POSIX_EXCLUSIVE_IO',
            source_configuration_hex=self.exporter.lifecycle_config_raw.hex(),
            descriptors=self.exporter.completed,files={n:raw.hex() for n,raw in self.exporter.files.items()},
            model_writer_handles_open=len(self.exporter.handles),server_joined=not self.thread.is_alive(),
            io=[dict(session=r.session,wrapper_exited=r.wrapper_exited,joined=r.joined,
                alive=r.thread.is_alive(),error=None if r.error is None else type(r.error).__name__)
                for r in self.controller._close_io.values()],
            measured_domain_bytes=self.controller._measure_retained(),
            measured_domain_peak=self.controller._retained_measured_peak))

    async def test_actual_cut_readback_and_final_close_precede_200_and_repeat_keeps_bytes(self):
        session=await self.initialize();await self.call(7)
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,200,response.text)
        self.assertTrue(self.exporter.closed);self.assertFalse(self.exporter.handles)
        self.assertEqual(response.headers['x-velo-observation-close'],'pc026-session-close-v1')
        header=response.headers['x-velo-observation-cut'];self.assertNotIn('=',header)
        descriptor=json.loads(base64.urlsafe_b64decode(header+'='*(-len(header)%4)))
        self.assertEqual(descriptor,self.exporter.descriptor)
        self.assertEqual(self.controller._sessions[session]['state'],'CLOSED')
        proof=json.loads(self.exporter.files['lifecycle.json'])
        self.assertEqual(proof['attempt_sequences'],[1])
        self.assertEqual(len(proof['sdk_work']['messages']),3)
        self.assertTrue(all(r.joined for r in self.controller._close_io.values()))
        before=dict(self.exporter.files);events=list(self.exporter.events)
        repeated=await self.http.delete(self.url)
        self.assertEqual(repeated.status_code,200)
        self.assertEqual(repeated.headers['x-velo-observation-cut'],header)
        self.assertEqual(before,self.exporter.files);self.assertEqual(events,self.exporter.events)
        rejected=await self.call(8,'late');self.assertEqual(rejected.status_code,409)
        self.assertEqual(self.ledger._attempt_count,1)
        with self.assertRaises(FileExistsError):
            self.exporter._write('cut.json',before['cut.json'])
        self.assertEqual((self.exporter.base/'cut.json').read_bytes(),before['cut.json'])

    async def test_two_sessions_preserve_separate_exports_and_do_not_wait_other_live_handler(self):
        import asyncio,time
        first=await self.initialize()
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        second=await self.initialize()
        task=asyncio.create_task(self.call(7,'latch'))
        try:
            until=time.monotonic()+2
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            response=await self.http.delete(self.url,headers={'mcp-session-id':first})
            self.assertEqual(response.status_code,200,response.text)
            first_base=self.exporter.base;first_bytes=(first_base/'export.json').read_bytes()
            self.assertFalse(task.done())
            self.assertEqual(self.controller._sessions[second]['state'],'OPEN')
            self.release.set();await task
            response=await self.http.delete(self.url)
            self.assertEqual(response.status_code,200,response.text)
            self.assertNotEqual(first_base,self.exporter.base)
            self.assertEqual((first_base/'export.json').read_bytes(),first_bytes)
            self.assertEqual(set(self.exporter.completed),{first,second})
        finally:
            self.release.set()
            if not task.done():await task

    async def test_copy_close_failure_keeps_residual_and_refuses_proof_and_cut(self):
        session=await self.initialize();await self.call(7)
        primary=OSError('MODEL-copy-close')
        def fail(stage):
            if stage=='read_close:originals/c/00000000.json':raise primary
        self.exporter.fault=fail
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503)
        self.assertIs(self.controller._close_errors[session],primary)
        self.assertFalse(self.exporter.handles)
        self.assertTrue((self.exporter.base/'originals/c/00000000.json').exists())
        self.assertFalse((self.exporter.base/'lifecycle.json').exists())
        self.assertFalse((self.exporter.base/'cut.json').exists())

    async def test_actual_extra_empty_export_directory_refuses_200(self):
        session=await self.initialize();await self.call(7)
        def add_directory(stage):
            if stage=='before:cut.json':(self.exporter.base/'unknown-extra').mkdir()
        self.exporter.fault=add_directory
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503)
        self.assertEqual(str(self.controller._close_errors[session]),'model_export_directory_closure')
        self.assertNotIn(session,self.exporter.completed)
        self.assertFalse(self.exporter.handles)
        self.assertNotIn('x-velo-observation-cut',response.headers)

    async def test_export_space_or_candidate_budget_refusal_is_before_first_write(self):
        session=await self.initialize();await self.call(7)
        self.exporter.codec.limits['min_free_bytes']=2**100
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503)
        self.assertFalse(self.exporter.events);self.assertFalse(self.exporter.base.exists())
        self.assertNotIn('x-velo-observation-cut',response.headers)

    async def test_final_close_error_preserves_published_files_but_never_200(self):
        session=await self.initialize();await self.call(7)
        primary=OSError('MODEL-external-final-close')
        def fail(stage):
            if stage=='final_close':raise primary
        self.exporter.fault=fail
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503)
        self.assertNotIn('x-velo-observation-cut',response.headers)
        self.assertFalse(self.exporter.closed);self.assertFalse(self.exporter.handles)
        self.assertTrue((self.exporter.base/'export.json').is_file())
        self.assertIs(self.controller._close_errors[session],primary)
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertEqual((await self.http.delete(self.url)).status_code,503)

    async def test_full_graph_rejects_missing_extra_pending_tampered_ref_and_other_session_projection(self):
        await self.initialize();await self.call(7);response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,200,response.text)
        codec=self.exporter.codec;files=self.exporter.files
        for label in ('missing','extra','pending','tampered','projection'):
            mutated=copy.deepcopy(files)
            if label=='missing':del mutated['originals/c/00000001.json']
            elif label=='extra':mutated['extra.json']=b'{}\n'
            elif label=='pending':mutated['unknown.pending']=b'{}\n'
            elif label=='tampered':mutated['originals/c/00000001.json']+=b' '
            else:
                p=json.loads(mutated['attempts.json']);p['attempt_sequences']=[]
                mutated['attempts.json']=canonical(p)
            with self.subTest(label=label),self.assertRaises(Exception):
                codec.verify(mutated,self.config.catalog_codec,self.config.codec,self.exporter.lifecycle_config_raw)
        good=json.loads(files['cut.json'])
        for mutate in (lambda r:r.update(worker_count=True),lambda r:r.update(extra=1),
            lambda r:r['members'][0].update(path='../escape'),lambda r:r.update(session_id='\ud800')):
            value=copy.deepcopy(good);mutate(value)
            with self.assertRaises((CutError,UnicodeError)):codec.encode(value,'cut')
        with self.assertRaises(CutError):codec.parse(files['cut.json'][:-1],'cut')
        with self.assertRaises(CutError):close_headers(dict(path='cut.json',size=1,sha256='0'*64))

    async def test_service_drain_closes_actual_instance_end_and_all_model_native_handles(self):
        session=await self.initialize();await self.call(7)
        import asyncio
        future=asyncio.run_coroutine_threadsafe(self.controller._drain(),self.server_loop)
        await asyncio.wrap_future(future)
        self.assertEqual(self.controller._state,'CLOSED')
        self.assertEqual(self.controller._sessions[session]['state'],'CLOSED')
        self.assertTrue(self.ledger._closed);self.assertFalse(self.fs.handles)
        self.assertEqual(self.records()[-1]['record_type'],'INSTANCE_END')
        self.assertEqual(self.config.group.closed,1)
        self.assertTrue(all(row.joined for row in self.controller._close_io.values()))


class ResponseCut(unittest.IsolatedAsyncioTestCase):
    records=chain.ChainTests.records

    async def asyncSetUp(self):
        from tests import test_observation_responses as response_fixture
        await response_fixture.ResponseChain.asyncSetUp(self)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.exporter=ModelExporter(self.directory.name,self.config,self.controller._limits)
        self.controller._exporter=self.exporter

    async def asyncTearDown(self):
        for row in self.controller._close_io.values():
            if row.task is not None:await row.task
            self.assertFalse(row.thread.is_alive())
        await chain.ChainTests.asyncTearDown(self)
        CUT_TRACES.append(dict(test=self.id(),boundary='MODEL_WINDOWS_SOURCE_AND_EXPORT_IDENTITIES_REAL_POSIX_EXCLUSIVE_IO',
            source_configuration_hex=self.exporter.lifecycle_config_raw.hex(),
            descriptors=self.exporter.completed,files={n:raw.hex() for n,raw in self.exporter.files.items()},
            model_writer_handles_open=len(self.exporter.handles),server_joined=not self.thread.is_alive(),
            io=[dict(session=r.session,wrapper_exited=r.wrapper_exited,joined=r.joined,
                alive=r.thread.is_alive(),error=None if r.error is None else type(r.error).__name__)
                for r in self.controller._close_io.values()],
            measured_domain_bytes=self.controller._measure_retained(),
            measured_domain_peak=self.controller._retained_measured_peak))

    async def test_real_official_sdk_outgoing_response_get_and_retired_work_in_cut(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                result=await sdk.call_tool('ask_peer',{})
                self.assertFalse(result.is_error,result)
        self.assertTrue(self.exporter.completed)
        proof=json.loads(self.exporter.files['lifecycle.json'])
        rows=proof['sdk_work']['messages'];methods=[r['method'] for r in rows]
        self.assertIn('JSONRPC_RESPONSE',methods);self.assertIn('ping',methods);self.assertIn('HTTP_GET_SSE',methods)
        self.assertEqual(len(rows),len(self.controller._work)+len(self.controller._outgoing_records))
        self.assertEqual(len({r['operation_sequence'] for r in rows}),len(rows))
        self.assertTrue(all(r['worker_exited'] for r in rows))
        self.assertTrue(all(d['state']=='CLOSED' for d in self.controller._sessions.values()))

    async def test_shared_pending_full_refuses_new_begin_but_real_reply_drains_and_closes(self):
        import asyncio
        import time
        self.controller._limits['max_pending_work']=1
        session=await chain.ChainTests.initialize(self)
        got=asyncio.Event();finish=asyncio.Event()
        async def reader():
            async with self.http.stream('GET',self.url) as response:
                self.assertEqual(response.status_code,200)
                async for line in response.aiter_lines():
                    if line.startswith('data: ') and json.loads(line[6:]).get('method')=='ping':
                        got.set();await finish.wait();return
        get=asyncio.create_task(reader())
        task=asyncio.create_task(self.http.post(self.url,json=dict(jsonrpc='2.0',id=11,
            method='tools/call',params=dict(name='ask_peer',arguments={}))))
        try:
            await asyncio.wait_for(got.wait(),3)
            self.assertEqual(self.controller._pending_count(),1)
            before=self.ledger._attempt_count
            denied=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=12,
                method='tools/call',params=dict(name='ask_peer',arguments={})))
            self.assertEqual(denied.status_code,503,denied.text)
            self.assertEqual(self.ledger._attempt_count,before)
            self.assertEqual(self.controller._state,'DRAINING')
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=7,result={}))
            self.assertEqual(response.status_code,202,response.text)
            self.assertEqual((await task).status_code,200)
            finish.set();await get
            until=time.monotonic()+2
            while self.controller._pending_count() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertEqual(self.controller._pending_count(),0)
            response=await self.http.delete(self.url)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(self.controller._sessions[session]['state'],'CLOSED')
        finally:
            finish.set()
            if not get.done():get.cancel()
            if not task.done():task.cancel()
            await asyncio.gather(get,task,return_exceptions=True)

class MaintenanceReservationTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    asyncTearDown=CutHTTPTests.asyncTearDown
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def pair(self):
        original=await self.initialize();await self.call(1)
        self.assertEqual((await self.http.delete(self.url)).status_code,200)
        original_files={str(p):p.read_bytes() for p in self.exporter.base.rglob('*') if p.is_file()}
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        session=await self.initialize()
        return original,session,original_files

    async def test_real_control_and_tool_exchanges_consume_reserved_capacity_and_bytes(self):
        original,session,files=await self.pair();c=self.controller
        c._reserve_maintenance(original,session,c._sessions[session]['owner'],calls=3,bytes=10000,attempts=1,binary=1,sdk_work=8)
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=3,method='tools/list'))
        self.assertEqual(response.status_code,200)
        self.assertEqual((await self.call(4,'maintenance')).status_code,200)
        self.assertEqual((await self.http.delete(self.url)).status_code,200)
        reservation=c._maintenance[session]
        self.assertEqual(reservation['remaining']['calls'],0)
        self.assertEqual(reservation['remaining']['attempts'],0)
        self.assertEqual(reservation['remaining']['binary'],1)
        self.assertEqual([r['method'] for r in reservation['exchanges']],['HTTP_POST','HTTP_POST','HTTP_DELETE'])
        self.assertTrue(all(r['finished'] for r in reservation['exchanges']))
        total=sum(r['request_bytes']+r['response_bytes'] for r in reservation['exchanges'])
        self.assertGreater(total,100);self.assertEqual(reservation['remaining']['bytes'],10000-total)
        self.assertEqual(self.calls,['ok','maintenance'])
        for name,raw in files.items():self.assertEqual(__import__('pathlib').Path(name).read_bytes(),raw)

    async def test_attempt_and_binary_reserves_deny_other_business_before_ticket_or_begin(self):
        from velociraptor_observation_controller import ControllerError
        original,session,_=await self.pair();c=self.controller
        c._limits['max_sessions']=3
        c._reserve_maintenance(original,session,c._sessions[session]['owner'],calls=3,bytes=10000,
            attempts=c._ledger._limits['max_attempts']-c._ledger._attempt_count,
            binary=c._limits['max_binary_work'],sdk_work=8)
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        other=await self.initialize()
        before=(c._sequence,c._ledger._attempt_count,len(c._work))
        response=await self.call(6,'never')
        self.assertEqual(response.status_code,503)
        self.assertEqual((c._sequence,c._ledger._attempt_count,len(c._work)),before)
        self.assertEqual(c._state,'ACTIVE');self.assertEqual(self.calls,['ok'])
        with self.assertRaises(ControllerError) as caught:
            c._admit_binary(other,c._sessions[other]['owner'],'0'*64)
        self.assertEqual(caught.exception.code,'reserved_binary')
        self.assertEqual((c._sequence,c._ledger._attempt_count,len(c._work)),before)
        self.assertFalse(c._binary_sequences)

    async def test_future_byte_overrun_is_unknown_and_retains_actual_received_bytes(self):
        original,session,_=await self.pair();c=self.controller
        c._reserve_maintenance(original,session,c._sessions[session]['owner'],calls=2,bytes=1,
            attempts=1,binary=0,sdk_work=8)
        before=self.ledger._attempt_count
        response=await self.call(2,'never')
        self.assertEqual(response.status_code,503)
        self.assertEqual(c._state,'UNKNOWN');self.assertEqual(self.ledger._attempt_count,before)
        row=c._maintenance[session]['exchanges'][0]
        self.assertTrue(row['finished']);self.assertGreater(row['request_bytes'],1)
        self.assertEqual(row['response_bytes'],len(response.content))
        self.assertEqual(self.calls,['ok'])

    async def test_no_receipt_or_wrong_owner_or_exhausted_plan_cannot_reserve(self):
        from velociraptor_observation_controller import ControllerError
        original,session,_=await self.pair();c=self.controller;owner=c._sessions[session]['owner']
        plan=dict(calls=1,bytes=1000,attempts=1,binary=1,sdk_work=4)
        with self.assertRaises(ControllerError):c._reserve_maintenance(original,session,b'x'*32,**plan)
        with self.assertRaises(ControllerError):c._reserve_maintenance(session,session,owner,**plan)
        with self.assertRaises(ControllerError):c._reserve_maintenance(original,session,owner,**dict(plan,attempts=100))
        with self.assertRaises(ControllerError):c._reserve_maintenance(original,session,owner,**dict(plan,calls=True))
        self.assertFalse(c._maintenance)
        c._reserve_maintenance(original,session,owner,**plan)
        with self.assertRaises(ControllerError):c._reserve_maintenance(original,session,owner,**plan)
    async def test_maintenance_failed_exchange_counts_and_call_exhaustion_cannot_close(self):
        original,session,_=await self.pair();c=self.controller
        c._reserve_maintenance(original,session,c._sessions[session]['owner'],calls=2,bytes=10000,
            attempts=1,binary=1,sdk_work=8)
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=3,method='tools/list'))
        self.assertEqual(response.status_code,200)
        response=await self.http.post(self.url,content=b'{broken')
        self.assertEqual(response.status_code,400)
        reservation=c._maintenance[session]
        self.assertEqual(len(reservation['exchanges']),2)
        self.assertEqual(reservation['exchanges'][1]['request_bytes'],7)
        self.assertEqual(reservation['exchanges'][1]['response_bytes'],len(response.content))
        self.assertEqual(reservation['initial_calls'],2);self.assertGreater(reservation['initial_bytes'],0)
        self.assertEqual(reservation['plan']['calls'],4)
        before=(c._sequence,self.ledger._attempt_count)
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503);self.assertIn('maintenance_calls',response.text)
        self.assertNotIn('x-velo-observation-cut',response.headers)
        self.assertEqual((c._sequence,self.ledger._attempt_count),before)
        self.assertEqual(c._state,'DRAINING');self.assertEqual(c._sessions[session]['state'],'OPEN')
        self.assertEqual(set(self.exporter.completed),{original})


class FullCapacityTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    asyncTearDown=CutHTTPTests.asyncTearDown
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def test_all_attempts_two_sessions_later_catalog_append_preserves_first_export(self):
        first=await self.initialize()
        for rid in range(1,5):self.assertEqual((await self.call(rid,f'first-{rid}')).status_code,200)
        for rid in (501,502):
            self.assertEqual((await self.http.post(self.url,json=dict(jsonrpc='2.0',id=rid,method='tools/list'))).status_code,200)
        response=await self.http.delete(self.url);self.assertEqual(response.status_code,200,response.text)
        first_base=self.exporter.base
        old={str(p.relative_to(first_base)):p.read_bytes() for p in first_base.rglob('*') if p.is_file()}
        first_proof=json.loads(old['lifecycle.json']);first_projection=json.loads(old['attempts.json'])
        first_head=json.loads(old['cut.json'])['catalog_head']
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        second=await self.initialize()
        for rid in range(1,5):self.assertEqual((await self.call(rid,f'second-{rid}')).status_code,200)
        self.assertEqual(self.ledger._attempt_count,self.ledger._limits['max_attempts'])
        for rid in (501,502):
            self.assertEqual((await self.http.post(self.url,json=dict(jsonrpc='2.0',id=rid,method='tools/list'))).status_code,200)
        before=self.ledger._attempt_count
        exhausted=await self.call(9,'never')
        self.assertEqual(exhausted.status_code,503);self.assertIn('work_budget',exhausted.text)
        self.assertEqual(self.ledger._attempt_count,before)
        response=await self.http.delete(self.url);self.assertEqual(response.status_code,200,response.text)
        second_proof=json.loads(self.exporter.files['lifecycle.json'])
        self.assertEqual(self.controller._sequence,self.controller._limits['max_sdk_work'])
        self.assertEqual(first_projection['attempt_sequences'],[1,2,3,4])
        self.assertEqual(json.loads(self.exporter.files['attempts.json'])['attempt_sequences'],[5,6,7,8])
        self.assertGreater(json.loads(self.exporter.files['cut.json'])['catalog_head']['path'],first_head['path'])
        for name,raw in old.items():self.assertEqual((first_base/name).read_bytes(),raw)
        for session,proof in ((first,first_proof),(second,second_proof)):
            expected=sorted(r.sequence for r in self.controller._work.values() if r.session==session)
            self.assertEqual([r['operation_sequence'] for r in proof['sdk_work']['messages']],expected)
            self.assertEqual(len(expected),8)
            self.assertTrue(all(r['worker_exited'] for r in proof['sdk_work']['messages']))
        self.assertEqual(len(self.controller._sequence_records),32)
        self.assertEqual(len(self.exporter.completed),2)
        self.assertTrue(all(r.joined for r in self.controller._close_io.values()))

class NativePhaseFaultTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    asyncTearDown=CutHTTPTests.asyncTearDown
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def phase_fault(self, phase, mode):
        import asyncio,threading,time
        from velociraptor_observation_controller import ControllerError
        session=await self.initialize();await self.call(7)
        entered=threading.Event();release=threading.Event();c=self.controller
        target,method=(self.ledger,'_session_prefix') if phase=='prefix' else (self.exporter,'publish')
        actual=getattr(target,method)
        def latched(*args,**kwargs):
            entered.set()
            if not release.wait(3):raise AssertionError('native-phase latch expired')
            return actual(*args,**kwargs)
        key=session if phase=='prefix' else (session,'export')
        if mode=='timeout':c._limits['close_timeout_ns']=100000000
        future=None;http=None
        try:
            with patch.object(target,method,latched):
                if mode=='timeout':http=asyncio.create_task(self.http.delete(self.url))
                else:future=asyncio.run_coroutine_threadsafe(c._close_session(session,c._sessions[session]['owner']),self.server_loop)
                until=time.monotonic()+2
                while not entered.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
                self.assertTrue(entered.is_set());row=c._close_io[key]
                if mode=='timeout':
                    response=await http
                    self.assertEqual(response.status_code,503,response.text)
                    self.assertNotIn('x-velo-observation-cut',response.headers)
                    self.assertIsInstance(c._close_errors[session],ControllerError)
                else:
                    future.cancel()
                    until=time.monotonic()+2
                    while session not in c._close_errors and time.monotonic()<until:await asyncio.sleep(.001)
                    self.assertIsInstance(c._close_errors[session],asyncio.CancelledError)
                self.assertEqual(c._state,'UNKNOWN')
                self.assertTrue(row.thread.is_alive());self.assertFalse(row.joined or row.task.done())
                self.assertFalse(self.exporter.completed)
                release.set()
                async def settle():await row.task
                await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(settle(),self.server_loop))
                self.assertTrue(row.joined and row.wrapper_exited);self.assertFalse(row.thread.is_alive())
                self.assertEqual(c._state,'UNKNOWN');self.assertFalse(self.exporter.completed)
                if phase=='export':self.assertEqual(row.error.code,'export_owner_unknown')
        finally:
            release.set()
            if http is not None and not http.done():await http

    async def test_prefix_timeout_keeps_native_owner_until_true_join(self):await self.phase_fault('prefix','timeout')
    async def test_prefix_cancel_keeps_native_owner_until_true_join(self):await self.phase_fault('prefix','cancel')
    async def test_export_timeout_cannot_publish_after_unknown(self):await self.phase_fault('export','timeout')
    async def test_export_cancel_cannot_publish_after_unknown(self):await self.phase_fault('export','cancel')

    async def close_fault(self, stage):
        session=await self.initialize();await self.call(7)
        primary=OSError('actual-MODEL-close:'+stage)
        def fail(actual):
            if actual==stage:raise primary
        self.exporter.fault=fail
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503,response.text)
        self.assertNotIn('x-velo-observation-cut',response.headers)
        self.assertIs(self.controller._close_errors[session],primary)
        self.assertEqual(self.controller._state,'UNKNOWN');self.assertFalse(self.exporter.completed)
        self.assertFalse(self.exporter.handles)
        self.assertTrue(all(r.joined for r in self.controller._close_io.values()))
        before=dict(self.exporter.files)
        self.assertEqual((await self.http.delete(self.url)).status_code,503)
        self.assertEqual(before,self.exporter.files)
        self.assertIs(self.controller._close_errors[session],primary)

    async def test_source_manifest_write_close_fault(self):await self.close_fault('write_close:source-manifest.json')
    async def test_lifecycle_write_close_fault(self):await self.close_fault('write_close:lifecycle.json')
    async def test_projection_write_close_fault(self):await self.close_fault('write_close:attempts.json')
    async def test_cut_write_close_fault(self):await self.close_fault('write_close:cut.json')
    async def test_export_write_close_fault(self):await self.close_fault('write_close:export.json')
    async def test_final_graph_export_read_close_fault(self):await self.close_fault('read_close:export.json')

class DeleteOrderTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    asyncTearDown=CutHTTPTests.asyncTearDown
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def test_delete_cancels_queued_alias_then_late_cancel_and_tool_have_zero_begin(self):
        import asyncio,time
        session=await self.initialize();first=asyncio.create_task(self.call(7,'latch'))
        second=delete=None
        try:
            until=time.monotonic()+2
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            second=asyncio.create_task(self.call('007','never'))
            until=time.monotonic()+2
            while self.ledger._attempt_count<2 and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertEqual(self.ledger._attempt_count,2)
            delete=asyncio.create_task(self.http.delete(self.url))
            until=time.monotonic()+2
            while self.controller._sessions[session]['state']=='OPEN' and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertEqual(self.controller._sessions[session]['state'],'CLOSING')
            self.assertIn('Request cancelled',(await second).text)
            queued=next(r for r in self.controller._work.values() if r.message.get('id')=='007')
            self.assertFalse(queued.enqueued);self.assertTrue(queued.receive_waiter.done())
            self.assertFalse(delete.done());self.assertFalse(self.release.is_set())
            before=self.ledger._attempt_count
            self.assertEqual((await self.call(8,'late')).status_code,409)
            cancel=await self.http.post(self.url,json=dict(jsonrpc='2.0',method='notifications/cancelled',params=dict(requestId=7)))
            self.assertEqual(cancel.status_code,409);self.assertEqual(self.ledger._attempt_count,before)
            self.release.set();await first
            self.assertEqual((await delete).status_code,200)
            self.assertEqual(self.calls,['latch'])
            self.assertEqual(sorted(r['payload']['outcome'] for r in self.records() if r['record_type']=='ATTEMPT_END'),['cancelled','returned'])
            proof=json.loads(self.exporter.files['lifecycle.json'])
            self.assertEqual(proof['attempt_sequences'],[1,2])
            self.assertEqual(len(proof['sdk_work']['messages']),4)
        finally:
            self.release.set()
            for task in (first,second,delete):
                if task is not None and not task.done():await task

class ExportBudgetTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=CutHTTPTests.asyncSetUp
    asyncTearDown=CutHTTPTests.asyncTearDown
    records=CutHTTPTests.records
    initialize=CutHTTPTests.initialize
    call=CutHTTPTests.call

    async def limited(self, name):
        await self.initialize();await self.call(7)
        originals={n:r['data'] for n,r in self.fs.nodes.items() if not r['directory']}
        self.exporter.codec.limits[name]=1  # Target runtime fault, not an approved vector.
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503,response.text)
        self.assertNotIn('x-velo-observation-cut',response.headers)
        self.assertFalse(self.exporter.events or self.exporter.completed or self.exporter.handles)
        self.assertEqual(originals,{n:r['data'] for n,r in self.fs.nodes.items() if not r['directory']})
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertTrue(all(r.joined for r in self.controller._close_io.values()))

    async def test_actual_export_file_reserve_before_first_write(self):await self.limited('max_export_files')
    async def test_actual_export_byte_reserve_before_first_write(self):await self.limited('max_export_bytes')
    async def test_actual_export_directory_reserve_before_first_write(self):await self.limited('max_export_directories')
    async def test_actual_cut_encode_budget_before_first_write(self):await self.limited('max_cut_bytes')
    async def test_actual_lifecycle_encode_budget_before_first_write(self):await self.limited('max_proof_bytes')
    async def test_actual_source_manifest_encode_budget_before_first_write(self):await self.limited('max_source_manifest_bytes')

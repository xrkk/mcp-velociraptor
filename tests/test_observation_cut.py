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

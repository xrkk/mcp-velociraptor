"""Local SDK observations and explicit clock models, never Windows acceptance."""
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
from unittest.mock import patch

from mcp import ClientSession
from mcp.types import CallToolResult, TextContent
from tests import p06_call_clock as clocks, scenario_runner as runner
from tests import p06_package as package


def step(tool='ok', expected=False):
    return {'id': tool, 'tool': tool, 'kind': 'tool', 'arguments': {},
            'assertions': [{'op': 'is_error', 'actual': '/isError', 'expected': expected}]}


def report(calls, status='success'):
    return {'run_id': str(uuid.uuid4()), 'runner': {'pid': 123, 'process_start_time_utc':
            '2026-10-03T00:00:00Z', 'executable_sha256': 'a'*64},
            'calls': calls, 'status': status, 'coverage': [], 'failure': None}


class Session:
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.calls = []

    async def call_tool(self, tool, arguments):
        self.calls.append((tool, arguments))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome or CallToolResult(content=[], is_error=False, structured_content={'ok': True})


class ModelClockTests(unittest.IsolatedAsyncioTestCase):
    async def execute(self, session, clock, calls=None, spec=None):
        calls = [] if calls is None else calls
        await runner.execute_tool_step(session, spec or step(), {}, {}, calls, _call_clock=clock)
        return calls

    async def test_boundaries_before_assertion_serialization_and_utc_rollback(self):
        clock = clocks.RunClock(); trace = []
        raw = Session().outcome or CallToolResult(content=[], is_error=False)
        original_dump = type(raw).model_dump
        def dump(self, **kwargs):
            trace.append('dump'); return original_dump(self, **kwargs)
        samples = iter([100, 2_000_100])
        def sample():
            trace.append('sample'); return next(samples)
        class Traced(Session):
            async def call_tool(self, *args):
                trace.append('SDK'); return raw
        calls = []
        with patch.object(clock, '_sample', side_effect=sample), patch('tests.p05_pc026_governance.before_effect', side_effect=lambda: trace.append('gate')), patch.object(type(raw), 'model_dump', dump), patch.object(runner, 'utc_now', side_effect=['2026-10-03T00:00:01Z', '2026-10-03T00:00:00Z']):
            await self.execute(Traced(), clock, calls)
        self.assertEqual(trace, ['gate','sample','SDK','sample','dump'])
        self.assertEqual(calls[0]['duration_ms'], 2)
        clocks.validate_calls(report(calls), clock.clock)

    async def test_repeat_and_sleep_gap_in_same_clock_domain(self):
        clock = clocks.RunClock(); calls=[]; samples=iter([0,2_000_000,502_000_000,505_000_000])
        spec=step();spec['repeat_until']={'max_attempts':2,'interval_seconds':0.5,'assertions':[{'op':'eq','actual':'/structuredContent/ok','expected':True}]}
        class Poll(Session):
            async def call_tool(self,*args):
                self.calls.append(args)
                return CallToolResult(content=[], structured_content={'ok':len(self.calls)==2})
        with patch.object(clock,'_sample',side_effect=lambda:next(samples)), patch.object(runner.asyncio,'sleep',return_value=None) as sleep:
            await self.execute(Poll(),clock,calls,spec)
        sleep.assert_awaited_once_with(0.5)
        clocks.validate_calls(report(calls),clock.clock)
        self.assertEqual([c['attempt'] for c in calls],[1,2])
        self.assertEqual(sum(c['duration_ms'] for c in calls),5)
        self.assertEqual((calls[-1]['monotonic']['ended_ns']-calls[0]['monotonic']['started_ns'])/1e6,505)

    async def test_gate_and_preparation_refusal_no_sdk_or_fake_clock(self):
        for preparation in (False,True):
            clock=clocks.RunClock();session=Session();calls=[];spec=step()
            if preparation:spec['arguments']={'bad':{'$ref':'/steps/missing/value'}}
            with patch('tests.p05_pc026_governance.before_effect',side_effect=ValueError('pre-call denied')):
                with self.assertRaises(ValueError):await self.execute(session,clock,calls,spec)
            self.assertEqual(session.calls,[])
            self.assertEqual(calls[0]['monotonic'],clock.not_invoked())
            clocks.validate_calls(report(calls,'failed'),clock.clock)

    async def test_sdk_exception_cancel_and_iserror_preserved(self):
        for outcome in (ValueError('SDK error'),asyncio.CancelledError('SDK cancelled'),CallToolResult(content=[TextContent(type='text',text='error')],is_error=True)):
            clock=clocks.RunClock();calls=[];session=Session(outcome)
            if isinstance(outcome,BaseException):
                with self.assertRaises(type(outcome)):await self.execute(session,clock,calls)
                self.assertEqual(calls[0]['error']['type'],type(outcome).__name__)
            else:
                await self.execute(session,clock,calls,step(expected=True))
                self.assertTrue(calls[0]['mcp_result']['isError'])
            self.assertTrue(calls[0]['monotonic']['invoked'])
            clocks.validate_calls(report(calls,'failed'),clock.clock)

    async def test_sampling_failures_preserve_result_and_stop_new_invocations(self):
        for values in ([True], [10,False], [10,9], [10,RuntimeError('end unavailable')]):
            clock=clocks.RunClock();session=Session();calls=[]
            with patch.object(clocks.time,'monotonic_ns',side_effect=values):
                with self.assertRaises((clocks.ClockError,RuntimeError)):await self.execute(session,clock,calls)
            self.assertTrue(clock.failed)
            if len(values)>1:
                self.assertEqual(len(session.calls),1);self.assertIn('mcp_result',calls[0])
            else:
                self.assertEqual(session.calls,[]);self.assertEqual(calls[0]['monotonic'],clock.not_invoked())
            with self.assertRaises(clocks.ClockError):await self.execute(session,clock,calls)
            self.assertEqual(len(session.calls),1 if len(values)>1 else 0)
            if len(values)>1:
                with self.assertRaises(clocks.ClockError):clocks.validate_calls(report(calls,'failed'),clock.clock)

    async def test_end_clock_error_retains_sdk_exception_and_serialization_error_retains_fields(self):
        clock=clocks.RunClock();calls=[]
        with patch.object(clocks.time,'monotonic_ns',side_effect=[10,RuntimeError('end clock')]):
            with self.assertRaisesRegex(ValueError,'primary SDK'):await self.execute(Session(ValueError('primary SDK')),clock,calls)
        self.assertEqual(calls[0]['error']['type'],'ValueError');self.assertIn('timing_error',calls[0])
        clock=clocks.RunClock();calls=[]
        with patch.object(CallToolResult,'model_dump',side_effect=ValueError('serialization failed')):
            with self.assertRaisesRegex(ValueError,'serialization failed'):await self.execute(Session(),clock,calls)
        self.assertEqual(calls[0]['structured'],{'ok':True});self.assertFalse(calls[0]['is_error'])
        self.assertTrue(calls[0]['monotonic']['invoked'])


class ClockRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'))
        self.run=Path(self.temp.name); self.clock=clocks.RunClock()
        self.report=report([{'sequence':1,'duration_ms':1,'monotonic':{'clock_id':self.clock.clock['clock_id'],'invoked':True,'started_ns':0,'ended_ns':1_000_000}}])
        self.raw=package.canonical_bytes(self.report);(self.run/'report.json').write_bytes(self.raw)
        self.clock.save(self.run,self.report,self.raw)
        self.value=json.loads((self.run/'call-clock.json').read_bytes())
    def tearDown(self):self.temp.cleanup()
    def test_exact_ref_binding_and_inventory_no_overwrite(self):
        clocks.validate((self.run/'call-clock.json').read_bytes(),self.raw,self.report)
        self.assertIn('run/call-clock.json',{r['path'] for r in package.member_inventory(self.run,self.run)['members']})
        with self.assertRaises(FileExistsError):self.clock.save(self.run,self.report,self.raw)
    def test_clock_record_model_and_interval_negatives(self):
        changes=[lambda v:v.update(extra=1),lambda v:v.update(schema_version=True),lambda v:v.update(run_id=str(uuid.uuid4())),lambda v:v['runner'].update(pid=True),lambda v:v['report_ref'].update(size=True),lambda v:v['report_ref'].update(path='../report.json'),lambda v:v['report_ref'].update(sha256='0'*64),lambda v:v['clock'].update(resolution_seconds=True),lambda v:v['clock'].update(resolution_seconds=0),lambda v:v['clock'].update(api='time.time_ns'),lambda v:v['clock'].update(adjustable=True)]
        for change in changes:
            v=copy.deepcopy(self.value);change(v)
            with self.assertRaises(ValueError):clocks.validate(package.canonical_bytes(v),self.raw,self.report)
        for change in [lambda c:c.update(started_ns=True),lambda c:c.update(ended_ns=-1),lambda c:c.update(ended_ns=0,started_ns=1),lambda c:c.update(clock_id=str(uuid.uuid4())),lambda c:c.update(invoked=1),lambda c:c.update(invoked=False),lambda c:c.update(extra=1),lambda c:c.pop('ended_ns')]:
            d=copy.deepcopy(self.report);change(d['calls'][0]['monotonic'])
            with self.assertRaises(clocks.ClockError):clocks.validate_calls(d,self.clock.clock)
        d=copy.deepcopy(self.report);d['calls'].append(copy.deepcopy(d['calls'][0]));d['calls'][1]['sequence']=2
        with self.assertRaisesRegex(clocks.ClockError,'overlap'):clocks.validate_calls(d,self.clock.clock)
        duplicate=b'{"schema_version":1,"schema_version":1}'
        with self.assertRaises(ValueError):clocks.validate(duplicate,self.raw,self.report)
        bad=json.dumps(self.value).replace('1e-09','NaN').encode()
        # Regardless of resolution platform, explicitly insert nonfinite JSON.
        v=copy.deepcopy(self.value);v['clock']['resolution_seconds']=float('inf')
        with self.assertRaises(ValueError):clocks.validate(json.dumps(v).encode(),self.raw,self.report)
    def test_clock_write_and_seal_failure_preserve_failed_report(self):
        for failure in ('clock','seal'):
            with tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT')) as tmp:
                run=Path(tmp);d=copy.deepcopy(self.report);d['coverage']=[{'synthetic':True}]
                clock=clocks.RunClock();clock.clock=self.clock.clock
                if failure=='clock':
                    with patch.object(clock,'save',side_effect=OSError('clock fsync failed')):
                        runner._finalize_report(d,run,run,clock,seal=False)
                else:
                    with patch.object(package,'verify_manifest',side_effect=ValueError('tail package drift')):
                        with self.assertRaisesRegex(ValueError,'tail package drift'):runner._finalize_report(d,run,run,clock,seal=True)
                    with self.assertRaisesRegex(clocks.ClockError,'report Ref'):
                        clocks.validate((run/'call-clock.json').read_bytes(),(run/'report.json').read_bytes(),d)
                final=json.loads((run/'report.json').read_bytes());self.assertEqual(final['status'],'failed');self.assertEqual(final['coverage'],[])
                self.assertEqual(final['calls'],d['calls'])
    def test_unique_production_domains(self):self.assertNotEqual(clocks.RunClock().clock['clock_id'],clocks.RunClock().clock['clock_id'])


class LocalSDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_loopback_sdk_success_and_error_through_runner(self):
        from mcp.server.mcpserver import MCPServer
        from mcp.client.streamable_http import streamable_http_client
        import httpx2
        import uvicorn
        app=MCPServer('local-clock-observation')
        @app.tool()
        async def clock_success() -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='local success')],structured_content={'ok':True},is_error=False)
        @app.tool()
        async def clock_error() -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='local error')],is_error=True)
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
        self.assertNotEqual(port,28790)
        server=uvicorn.Server(uvicorn.Config(app.streamable_http_app(),log_level='error',access_log=False))
        task=asyncio.create_task(server.serve(sockets=[sock]));calls=[];clock=clocks.RunClock()
        try:
            for _ in range(200):
                if server.started:break
                if task.done():await task
                await asyncio.sleep(.01)
            self.assertTrue(server.started)
            async with httpx2.AsyncClient() as client:
                async with streamable_http_client(f'http://127.0.0.1:{port}/mcp',http_client=client) as (read,write):
                    async with ClientSession(read,write) as session:
                        await session.initialize()
                        await runner.execute_tool_step(session,step('clock_success'),{},{},calls,_call_clock=clock)
                        await asyncio.sleep(.02)
                        await runner.execute_tool_step(session,step('clock_error',True),{},{},calls,_call_clock=clock)
            clocks.validate_calls(report(calls,'failed'),clock.clock)
            self.assertEqual([c['mcp_result']['isError'] for c in calls],[False,True])
            self.assertGreaterEqual(calls[-1]['monotonic']['started_ns']-calls[0]['monotonic']['ended_ns'],10_000_000)
            evidence=os.environ.get('P06_CLOCK_SDK_EVIDENCE')
            if evidence:
                target=Path(evidence)
                with target.open('x') as stream:json.dump({'nature':'real host loopback SDK, not Windows','port':port,'clock':clock.clock,'calls':calls},stream,ensure_ascii=False,indent=2)
        finally:
            server.should_exit=True
            await asyncio.wait_for(task,10)
            sock.close()
        self.assertTrue(task.done())

class RunnerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_runner_finally_retains_failure_cancel_and_clock_fault(self):
        """Actual lifecycle; transport/admission/resource fixtures are models."""
        from contextlib import asynccontextmanager, ExitStack
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from tests import p06_pc026_binding, p06_resource_gate
        import mcp.client.streamable_http as transport
        import httpx2
        for mode in ('exception','cancel','clock','headers'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT')) as tmp:
                root=Path(tmp); run_id=str(uuid.uuid4()); sid='p06-compromise-scope'
                source=root/'scenario.json';source.write_text('{}')
                fixture_path=root/'fixture-instance.json';fixture_path.write_text('{}')
                observation=root/'server-observation.json';observation.write_text('{}')
                h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
                scenario={'scenario_id':sid,'fixture_spec_sha256':'a'*64,
                          'steps':[step()], 'cleanup':[dict(step('cleanup'),when='always')]}
                index={'path':'full/'+sid+'.json','required_snapshot':runner.SNAPSHOT_191}
                refs={'tests/data/p06_scenario_index.json':{'sha256':h(source)},
                      'tests/scenarios/full/'+sid+'.json':{'sha256':h(source)}}
                admission=SimpleNamespace(group=SimpleNamespace(freeze_refs=refs),
                    read=lambda p:p.read_bytes(),recheck=lambda:None,finish_report=lambda r:None)
                observed={'computer_name':'synthetic-guest','service_name':'test','pid':1,
                    'process_start_time_utc':'2026-10-03T00:00:00Z','instance_id':'local-model',
                    'executable_sha256':'a'*64}
                class Header:
                    def __init__(self,*args):
                        self.responses=[{'method':'POST','mcp_session_id':'model-session',
                                         'server_instance_id':'local-model'}]
                class SDK(Session):
                    async def __aenter__(self):return self
                    async def __aexit__(self,*args):pass
                    async def initialize(self):pass
                    async def list_tools(self):
                        tools=[SimpleNamespace(name=n,input_schema={},output_schema=None)
                               for n in ['ok','cleanup',*[f'local{i}' for i in range(135)]]]
                        return SimpleNamespace(tools=tools,model_dump=lambda **k:{'tools':[]})
                sdk=SDK(ValueError('synthetic SDK failure') if mode=='exception' else
                        asyncio.CancelledError('synthetic cancellation') if mode=='cancel' else None)
                @asynccontextmanager
                async def streams(*args,**kwargs):yield None,None
                async def guarded(gate,id,fn):return await fn(),None
                original_finalize=runner._finalize_report
                def finalize(r,run,e,c,**kwargs):original_finalize(r,run,e,c,seal=False)
                original_write=Path.write_bytes
                def write(path,data):
                    if mode=='headers' and path.name=='http-headers.json':raise OSError('header write failure')
                    return original_write(path,data)
                with ExitStack() as stack:
                    for obj,name,value in [(runner,'P06_REPORT_ROOT',root),(runner,'load_indexed_scenario',lambda _: (scenario,index,h(source),source)),
                        (runner,'load_fixture',lambda *a:( {},h(fixture_path))),
                        (runner,'load_current_restore',lambda *a,**k:{'run_id':run_id}),
                        (runner,'verify_server_observation',lambda *a:observed),
                        (runner,'HttpHeaderCapture',Header),(runner,'ClientSession',lambda *a:sdk),
                        (runner,'_p06_coverage',lambda *a:[{}]*129),
                        (runner,'_verify_terminal_flow_classification',lambda *a:None),
                        (runner,'_finalize_report',finalize),
                        (p06_pc026_binding,'load',lambda:admission),
                        (transport,'streamable_http_client',streams),
                        (httpx2,'AsyncClient',lambda **kw:SimpleNamespace(aclose=AsyncMock())),
                        (p06_resource_gate,'ScenarioResourceGate',lambda *a,**kw:SimpleNamespace(before=AsyncMock(return_value={}))),
                        (p06_resource_gate,'GuestResourceSampler',lambda *a:None),
                        (p06_resource_gate,'guarded_step',guarded)]:stack.enter_context(patch.object(obj,name,value))
                    stack.enter_context(patch.dict(os.environ,{'LOCAL_CLOCK_MODEL_TOKEN':'nonsecret-model'}))
                    stack.enter_context(patch.object(Path,'write_bytes',write))
                    if mode=='clock':stack.enter_context(patch.object(clocks.time,'monotonic_ns',side_effect=[10,RuntimeError('end clock failed')]))
                    if mode=='cancel':
                        with self.assertRaises(asyncio.CancelledError):
                            await runner.run_scenario(sid,transport='streamable-http',endpoint='http://127.0.0.1:28790/mcp',token_env='LOCAL_CLOCK_MODEL_TOKEN',evidence_root=root,server_observation=observation,run_id=run_id)
                    else:
                        result,_=await runner.run_scenario(sid,transport='streamable-http',endpoint='http://127.0.0.1:28790/mcp',token_env='LOCAL_CLOCK_MODEL_TOKEN',evidence_root=root,server_observation=observation,run_id=run_id)
                run=root/sid/run_id;final=json.loads((run/'report.json').read_bytes());clock_value=json.loads((run/'call-clock.json').read_bytes())
                self.assertEqual(final['status'],'failed');self.assertEqual(final['coverage'],[])
                self.assertTrue(final['calls'][0]['monotonic']['invoked'])
                self.assertEqual(clock_value['report_ref']['sha256'],h(run/'report.json'))
                if mode=='clock':
                    self.assertEqual(len(sdk.calls),1);self.assertIn('mcp_result',final['calls'][0])
                    with self.assertRaises(clocks.ClockError):clocks.validate((run/'call-clock.json').read_bytes(),(run/'report.json').read_bytes(),final)
                else:
                    clocks.validate((run/'call-clock.json').read_bytes(),(run/'report.json').read_bytes(),final)

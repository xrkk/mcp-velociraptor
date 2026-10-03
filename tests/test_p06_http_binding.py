"""Current raw binding tests; synthetic graphs never qualify real Windows."""
import asyncio
import socket
import sys
import uuid
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from tests import p05_pc026_governance as gov, p06_pc026_binding as admission
from tests import p06_mcp_raw_join as rawjoin, p06_call_clock as clocks
from tests.test_p06_mcp_raw_join import host_report
from tests import p06_http_binding as binding, p06_http_body_capture as capture
from tests.test_p06_mcp_raw_join import Fixture, rpc_response
from mcp.types import ListToolsResult, CallToolResult


def isolated_reader():
    # Explicit host security reader model for library gates; full graph tests
    # use binding._from_group rather than this deliberately unapproved object.
    group=gov.GovernedGroup(Path.cwd(),{}, {},{}, {},{}, {},True)
    return admission.Admission(group,b'',None)


class Models(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'))
        self.f=Fixture(self.temp.name).basic().save()
        report=self.f.report
        report['mcp_session']['id']='model-session';report['server_identity']['instance_id']='model-instance'
        self.f.save()
        (self.f.run/'tools-list.json').write_bytes(capture.canonical(ListToolsResult(tools=[]).model_dump(mode='json',by_alias=True,exclude_none=True)))
        headers=[]
        for row in self.f.rows:
            headers.append(dict(method=row['method'],path='/mcp',status_code=row['response_status'],
                mcp_session_id='model-session' if row['sequence']==1 else None,
                server_instance_id='model-instance',request_session_id=None if row['sequence']==1 else 'model-session',
                exchange_sequence=row['sequence']))
        self.headers=headers;self.save_headers()
    def tearDown(self):self.temp.cleanup()
    def save_headers(self):(self.f.run/'http-headers.json').write_bytes(capture.canonical(self.headers))
    def test_exact_binding_and_readonly_recompute(self):
        binding.publish(isolated_reader(),self.f.run)
        before=self.f.hashes();value=binding.validate(isolated_reader(),self.f.run)
        self.assertEqual(set(value),{'schema_version','kind','run_id','report_ref','capture_ref','headers_ref','join_ref','status'})
        self.assertEqual(before,self.f.hashes())
        with self.assertRaises(FileExistsError):binding.publish(isolated_reader(),self.f.run)
        self.assertEqual(before,self.f.hashes())
    def test_header_sequence_coverage_and_identity_negative_matrix(self):
        for case in ('duplicate','missing','extra','bool','path','method','status','init-request','init-response','request','response','instance'):
            with self.subTest(case=case):
                headers=json.loads(capture.canonical(self.headers))
                if case=='duplicate':headers[-1]['exchange_sequence']=1
                elif case=='missing':headers.pop()
                elif case=='extra':headers.append({**headers[-1],'exchange_sequence':99})
                elif case=='bool':headers[-1]['exchange_sequence']=True
                elif case in {'path','method','status'}:headers[-1][{'path':'path','method':'method','status':'status_code'}[case]]={'path':'/wrong','method':'GET','status':401}[case]
                elif case=='init-request':headers[0]['request_session_id']='model-session'
                elif case=='init-response':headers[0]['mcp_session_id']='another'
                elif case=='request':headers[-1]['request_session_id']='another'
                elif case=='response':headers[-1]['mcp_session_id']='another'
                else:headers[-1]['server_instance_id']='another'
                (self.f.run/'http-headers.json').write_bytes(capture.canonical(headers));before=self.f.hashes()
                with self.assertRaisesRegex(ValueError,'header|session|instance'):binding._derive(self.f.run,binding._AdmissionReader(isolated_reader(),self.f.run))
                self.assertEqual(before,self.f.hashes())
    def test_saved_join_binding_listing_missing_and_drift(self):
        binding.publish(isolated_reader(),self.f.run)
        for name in (binding.JOIN,binding.BINDING,'tools-list.json'):
            p=self.f.run/name;original=p.read_bytes();p.write_bytes(original+b' ');before=self.f.hashes()
            # listing semantic whitespace is valid; mismatch must be substantive.
            if name=='tools-list.json':p.write_bytes(capture.canonical({'tools':[],'nextCursor':'wrong'}));before=self.f.hashes()
            with self.assertRaisesRegex(ValueError,'saved|tools/list'):binding.validate(isolated_reader(),self.f.run)
            self.assertEqual(before,self.f.hashes());p.write_bytes(original)
        reader=isolated_reader();binding.validate(reader,self.f.run)
        p=self.f.run/'raw-mcp/exchange-00000003-response.bin';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'drift'):reader.recheck()
    def test_binding_failure_retains_calls_and_never_repairs_clock(self):
        from tests import scenario_runner as runner
        from tests.p06_call_clock import validate,ClockError
        report=self.f.report;report['coverage']=[{'synthetic':True}]
        (self.f.run/'call-clock.json').unlink()
        self.headers[-1]['request_session_id']='wrong';self.save_headers()
        with self.assertRaisesRegex(ValueError,'session'):
            runner._finalize_report(report,self.f.run,self.f.run,self.f.clock,seal=False,_admission=isolated_reader())
        final=json.loads((self.f.run/'report.json').read_bytes())
        self.assertEqual(final['status'],'failed');self.assertEqual(final['coverage'],[])
        self.assertEqual(final['calls'],self.f.calls)
        with self.assertRaisesRegex(ClockError,'report Ref'):
            validate((self.f.run/'call-clock.json').read_bytes(),(self.f.run/'report.json').read_bytes(),final)
        self.assertFalse((self.f.run/binding.JOIN).exists());self.assertFalse((self.f.run/binding.BINDING).exists())

    def test_second_list_and_missing_raw_refuse(self):
        self.f.exchange({'jsonrpc':'2.0','id':90,'method':'tools/list'},rpc_response(90,{'tools':[]}));self.f.save()
        with self.assertRaisesRegex(ValueError,'one tools/list'):binding._derive(self.f.run,binding._AdmissionReader(isolated_reader(),self.f.run))


class LocalSDK(unittest.IsolatedAsyncioTestCase):
    async def test_real_sdk_capture_clock_join_and_independent_body_oracle(self):
        import httpx2
        import uvicorn
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from mcp.server import MCPServer
        from mcp.types import TextContent
        from tests import scenario_runner as runner

        app=MCPServer('raw-join-local')
        @app.tool()
        async def join_success(n:int) -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='真实成功中')],structured_content={'n':n},is_error=False)
        @app.tool()
        async def join_error(n:int) -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='真实错误中')],structured_content={'n':n},is_error=True)
        official=app.streamable_http_app();oracle=[];instance=str(uuid.uuid4())
        async def observed(scope,receive,send):
            if scope['type']!='http':await official(scope,receive,send);return
            row=dict(method=scope['method'],status=None,request=bytearray(),response=bytearray());oracle.append(row)
            async def recv():
                message=await receive()
                if message['type']=='http.request':row['request'].extend(message.get('body',b''))
                return message
            async def transmit(message):
                if message['type']=='http.response.start':
                    row['status']=message['status']
                    message={**message,'headers':[*message.get('headers',[]),(b'x-mcp-server-instance',instance.encode())]}
                if message['type']=='http.response.body':row['response'].extend(message.get('body',b''))
                await send(message)
            await official(scope,recv,transmit)
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
        self.assertNotEqual(port,28790)
        server=uvicorn.Server(uvicorn.Config(observed,log_level='error',access_log=False))
        worker=asyncio.create_task(server.serve(sockets=[sock]))
        target=os.environ.get('P06_BINDING_SDK_EVIDENCE');temporary=None
        if target:root=Path(target);root.mkdir()
        else:temporary=tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'));root=Path(temporary.name)
        run_id=str(uuid.uuid4());run=root/run_id;run.mkdir();clock=clocks.RunClock();calls=[]
        transport=capture.CaptureTransport(httpx2.AsyncHTTPTransport(),run,run_id)
        header=runner.HttpHeaderCapture(transport,_current_raw=True)
        try:
            for _ in range(200):
                if server.started:break
                if worker.done():await worker
                await asyncio.sleep(.01)
            self.assertTrue(server.started)
            started=runner.utc_now()
            async with httpx2.AsyncClient(transport=header,trust_env=False,
                            headers={'authorization':'FIXED_JOIN_TEST_AUTH'}) as client:
                async with streamable_http_client(f'http://127.0.0.1:{port}/mcp',http_client=client) as (read,write):
                    async with ClientSession(read,write) as session:
                        initialized=await session.initialize()
                        live=binding.initialized_header(transport,header.responses)
                        header.expected_identity=(live['mcp_session_id'],instance)
                        listed=await session.list_tools()
                        for seq,(name,error) in enumerate((('join_success',False),('join_error',True)),1):
                            spec={'id':name,'kind':'tool','tool':name,'arguments':{'n':seq},
                                  'assertions':[{'op':'is_error','actual':'/isError','expected':error}]}
                            await runner.execute_tool_step(session,spec,{},{},calls,_call_clock=clock)
            with (run/'http-headers.json').open('xb') as out:out.write(capture.canonical(header.responses))
            with (run/'tools-list.json').open('xb') as out:out.write(capture.canonical(listed.model_dump(mode='json',by_alias=True,exclude_none=True)))
            report=host_report(run_id,calls)
            report['mcp_session']['id']=live['mcp_session_id']
            report['server_identity']['instance_id']=instance
            report.update(endpoint=f'http://127.0.0.1:{port}/mcp',started_at=started,ended_at=runner.utc_now(),
                runner={'pid':os.getpid(),'process_start_time_utc':runner._runner_start_time_utc(),
                        'executable_sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()})
            report['mcp_session'].update(initialized_at=started,closed_at=report['ended_at'])
            report_raw=capture.canonical(report)
            with (run/'report.json').open('xb') as out:out.write(report_raw)
            clock.save(run,report,report_raw)
            bound=binding.publish(isolated_reader(),run)
            self.assertEqual(bound['status'],'BOUND')
            before={str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob('*') if p.is_file()}
            binding.validate(isolated_reader(),run)
            joined=rawjoin.join(run)
            self.assertEqual(before,{str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob('*') if p.is_file()})
            self.assertEqual(len(joined['calls']),2)
            self.assertEqual([r['result_sha256'] for r in joined['calls']],[rawjoin.digest(c['mcp_result']) for c in calls])
            index=capture.verify(run);expected=list(oracle)
            self.assertEqual(len(index['exchanges']),len(expected))
            for row in index['exchanges']:
                request=(run/'raw-mcp'/row['request_ref']['path']).read_bytes() if row['request_ref'] else b''
                response=(run/'raw-mcp'/row['response_ref']['path']).read_bytes() if row['response_ref'] else b''
                options=[r for r in expected if r['method']==row['method'] and bytes(r['request'])==request
                         and r['status']==row['response_status'] and bytes(r['response']).startswith(response)]
                self.assertTrue(options)
                if row['response_end']=='eof':self.assertTrue(any(bytes(r['response'])==response for r in options))
                expected.remove(options[0])
            (root/'join.json').write_bytes(capture.canonical(joined))
            sdk_proof={'nature':'real loopback SDK session and server-generated instance headers; remaining host identity synthetic, not 191/Windows',
                'session':live['mcp_session_id'],'instance':instance,'binding':bound,'headers':header.responses,
                'run_id':run_id,'port':port,'runner':report['runner'],'initialized':initialized.model_dump(mode='json',by_alias=True,exclude_none=True),
                'listed':listed.model_dump(mode='json',by_alias=True,exclude_none=True),'calls':calls,'join':joined,
                'source_sha256':{str(p.relative_to(Path.cwd())):hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in [Path(rawjoin.__file__),Path(__file__),Path(capture.__file__),
                                          Path(binding.__file__),Path(gov.__file__),Path(runner.__file__),Path(clocks.__file__)]},'raw_hashes':before}
            (root/'sdk-proof.json').write_bytes(capture.canonical(sdk_proof))
            oracle_refs=[]
            for seq,row in enumerate(oracle,1):
                item={'method':row['method'],'status':row['status']}
                for direction in ('request','response'):
                    name=f'oracle-{seq:08d}-{direction}.bin';body=bytes(row[direction])
                    with (root/name).open('xb') as out:out.write(body)
                    item[direction]={'path':name,'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}
                oracle_refs.append(item)
            (root/'server-oracle.json').write_bytes(capture.canonical(oracle_refs))
        finally:
            server.should_exit=True;await asyncio.wait_for(worker,10);sock.close();await transport.aclose()
            if temporary:temporary.cleanup()
        self.assertTrue(worker.done())


from tests.test_p06_pc026_binding import CurrentConsumerTests
from tests import p06_receive, p06_package
from unittest.mock import patch


class RawConsumerTests(CurrentConsumerTests):
    def test_raw_current_receiver_negative_matrix_and_tail_drift(self):
        run,_=self.attempt()
        originals={p.relative_to(run):p.read_bytes() for p in run.rglob('*') if p.is_file()}
        def restore():
            for name,data in originals.items():
                p=run/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        cases=[('missing-'+name,name,'missing') for name in ('raw-mcp/capture.json',binding.JOIN,binding.BINDING,
            'http-headers.json','tools-list.json','raw-mcp/exchange-00000003-response.bin')]
        cases += [(label,name,'change') for label,name in (
            ('sequence','http-headers.json'),('session','http-headers.json'),('instance','http-headers.json'),
            ('join',binding.JOIN),('binding-ref',binding.BINDING),('listing','tools-list.json'),
            ('capture-ref','raw-mcp/capture.json'),('body','raw-mcp/exchange-00000003-response.bin'))]
        for label,name,action in cases:
            with self.subTest(label=label):
                restore();path=run/name
                if action=='missing':path.unlink()
                elif label=='body':path.write_bytes(path.read_bytes()+b' ')
                else:
                    value=json.loads(path.read_bytes())
                    if label=='sequence':value[-1]['exchange_sequence']=value[0]['exchange_sequence']
                    elif label=='session':value[-1]['request_session_id']='wrong'
                    elif label=='instance':value[-1]['server_instance_id']='wrong'
                    elif label=='join':value['calls'][0]['result_sha256']='0'*64
                    elif label=='binding-ref':value['report_ref']['path']='../report.json'
                    elif label=='listing':value['nextCursor']='unknown'
                    elif label=='capture-ref':value['exchanges'][2]['response_ref']['sha256']='0'*64
                    path.write_bytes(capture.canonical(value))
                before={str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob('*') if p.is_file()}
                with patch.object(gov,'load',side_effect=self.load),self.no_writers():
                    target=('No such file|safe governance|capture.*(directory|file)|report must be a plain file' if action=='missing' else {
                        'sequence':'header sequence','session':'session','instance':'instance','join':'saved raw join',
                        'binding-ref':'saved HTTP binding','listing':'raw tools/list','capture-ref':'Ref.*(hash|drift)','body':'Ref.*(hash|drift)'}[label])
                    with self.assertRaisesRegex((ValueError,OSError),target):p06_receive.receive(run,self.received)
                self.assertEqual(before,{str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob('*') if p.is_file()})
                self.assertFalse((self.received/'.receive.lock').exists());self.assertFalse((self.received/'接收清单.jsonl').exists())
        restore()
        # No repaired successful artifacts: package omission is a separate gate.
        manifest=run/'package-manifest.json';original=manifest.read_bytes();value=json.loads(original)
        value['members']=[r for r in value['members'] if r['path']!='run/'+binding.JOIN]
        manifest.write_bytes(capture.canonical(value))
        with patch.object(gov,'load',side_effect=self.load),self.no_writers():
            with self.assertRaisesRegex(ValueError,'package identity'):p06_receive.receive(run,self.received)
        manifest.write_bytes(original)
        from tests import p06_aggregate_reports as aggregate
        identity=aggregate.ledger_identity;body=run/'raw-mcp/exchange-00000003-response.bin'
        def drift(report):
            value=identity(report);body.write_bytes(body.read_bytes()+b' ');return value
        with patch.object(gov,'load',side_effect=self.load),patch.object(aggregate,'ledger_identity',side_effect=drift):
            with self.assertRaisesRegex(ValueError,'streamed input drift'):p06_receive.receive(run,self.received)
        self.assertFalse((self.received/'接收清单.jsonl').exists());self.assertFalse((self.received/'.receive.lock').exists())
        restore()
        with patch.object(gov,'load',side_effect=self.load):receipt=p06_receive.receive(run,self.received)
        self.assertEqual(receipt['status'],'success')
        for name in (binding.JOIN,binding.BINDING,'raw-mcp/capture.json','tools-list.json'):
            self.assertIn('run/'+name,{r['path'] for r in json.loads(manifest.read_bytes())['members']})


class TransportModels(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_headers_use_capture_start_sequence_not_completion_order(self):
        import httpx2
        from tests.scenario_runner import HttpHeaderCapture
        from tests.test_p06_http_body_capture import Stream,Transport
        ready=__import__('asyncio').Event();release=__import__('asyncio').Event()
        class Reordered(Transport):
            async def handle_async_request(self,request):
                async for _ in request.stream:pass
                self.asserted_no_extension='pc026_capture_sequence' not in request.extensions
                if request.method=='GET':ready.set();await release.wait()
                else:release.set()
                return httpx2.Response(200,stream=Stream(),headers={'x-mcp-server-instance':'model-instance'})
        with tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT')) as root:
            inner=Reordered();body=capture.CaptureTransport(inner,Path(root),str(uuid.uuid4()));headers=HttpHeaderCapture(body,_current_raw=True)
            async def call(method):
                response=await headers.handle_async_request(httpx2.Request(method,'http://model.invalid/mcp',stream=Stream()))
                async for _ in response.stream:pass
                await response.aclose()
            get=asyncio.create_task(call('GET'));await ready.wait();await call('POST');await get;await headers.aclose()
            self.assertEqual([r['exchange_sequence'] for r in headers.responses],[2,1])
            self.assertTrue(inner.asserted_no_extension)
            self.assertEqual([r['method'] for r in capture.verify(Path(root))['exchanges']],['GET','POST'])
    async def test_inner_sequence_collision_is_failed_and_original_closes_once(self):
        import httpx2
        from tests.test_p06_http_body_capture import Stream,Transport
        source=Stream()
        class Collision(Transport):
            async def handle_async_request(self,request):
                async for _ in request.stream:pass
                return httpx2.Response(200,stream=source,extensions={'pc026_capture_sequence':99})
        with tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT')) as root:
            body=capture.CaptureTransport(Collision(),Path(root),str(uuid.uuid4()))
            with self.assertRaisesRegex(capture.CaptureError,'collision'):
                await body.handle_async_request(httpx2.Request('POST','http://model.invalid/mcp',stream=Stream()))
            await body.aclose();self.assertEqual(source.closes,1)
            self.assertEqual(capture.verify(Path(root))['status'],'FAILED')

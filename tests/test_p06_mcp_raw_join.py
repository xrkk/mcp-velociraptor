"""Synthetic raw gates and a distinct real official-SDK capture/clock run."""
import asyncio
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from mcp.types import CallToolResult
from tests import p06_mcp_raw_join as rawjoin, p06_http_body_capture as capture, p06_call_clock as clocks
from tests.p06_aggregate_reports import REPORT_KEYS


def result(error=False):
    return {'content':[{'type':'text','text':'真实中'}], 'isError':error, 'structuredContent':{'value':error}}


def rpc_request(id,method,params=None):
    v={'jsonrpc':'2.0','id':id,'method':method}
    if params is not None:v['params']=params
    return v


def rpc_response(id,value):
    return {'jsonrpc':'2.0','id':id,'result':value}


def host_report(run_id,calls):
    """Current schema2 shape, explicitly synthetic host identities/no approval."""
    report={key:None for key in REPORT_KEYS}
    report.update(schema_version=2,scenario='p06-compromise-scope',run_id=run_id,
        status='success',failure=None,transport='streamable-http',endpoint='http://127.0.0.1:1/mcp',
        authorization_configured=True,runner={'pid':123,'process_start_time_utc':'2026-10-03T00:00:00Z',
            'executable_sha256':'a'*64},calls=calls,steps=[],cleanup=[],coverage=[],unexecuted_step_ids=[],
        mcp_session={'id':'synthetic-host','initialized_at':'2026-10-03T00:00:00Z','closed_at':'2026-10-03T00:00:01Z'},
        server_identity={'computer_name':'SYNTHETIC-HOST','service_name':'synthetic', 'pid':123,
            'process_start_time_utc':'2026-10-03T00:00:00Z','instance_id':str(uuid.uuid4()),'executable_sha256':'a'*64},
        started_at='2026-10-03T00:00:00Z',ended_at='2026-10-03T00:00:01Z',duration_ms=1000)
    return report


class Fixture:
    def __init__(self,root):
        self.run_id=str(uuid.uuid4());self.run=Path(root)/self.run_id;self.run.mkdir();(self.run/'raw-mcp').mkdir()
        self.clock=clocks.RunClock();self.rows=[]
        self.calls=[]
        for seq in (1,2):
            value=CallToolResult.model_validate(result(seq==2)).model_dump(mode='json',by_alias=True,exclude_none=True)
            self.calls.append(dict(sequence=seq,attempt=seq,tool='same_tool',arguments={'n':seq},
                is_error=seq==2,structured=value['structuredContent'],mcp_result=value,duration_ms=1,
                monotonic={'clock_id':self.clock.clock['clock_id'],'invoked':True,
                           'started_ns':seq*2_000_000,'ended_ns':seq*2_000_000+1_000_000}))
        self.report=host_report(self.run_id,self.calls)
        self.init=rpc_request(0,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'host','version':'1'}})
        self.init_result=rpc_response(0,{'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'host','version':'1'}})
        self.list=rpc_request(1,'tools/list',{})
        self.list_result=rpc_response(1,{'tools':[]})
        self.requests=[rpc_request(id,'tools/call',{'name':'same_tool','arguments':{'n':seq}})
                       for seq,id in enumerate((7,'7'),1)]
        self.responses=[rpc_response(id,result(seq==2)) for seq,id in enumerate((7,'7'),1)]

    def exchange(self,request,response=None, *, method='POST',kind='application/json',encoding='',end='eof',status=200):
        seq=len(self.rows)+1
        def body(direction,value):
            if value is None:return None
            raw=rawjoin.canonical(value) if isinstance(value,dict) else value
            name=f'exchange-{seq:08d}-{direction}.bin';(self.run/'raw-mcp'/name).write_bytes(raw)
            return {'path':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        self.rows.append(dict(sequence=seq,method=method,request_ref=body('request',request),request_end='eof',
            response_ref=body('response',response),response_end=end if response is not None else 'not_started',
            response_status=status,response_content_type=kind,response_content_encoding=encoding,error=None))

    def basic(self):
        self.exchange(self.init,self.init_result);self.exchange(self.list,self.list_result)
        for request,response in zip(self.requests,self.responses):self.exchange(request,response)
        self.exchange({'jsonrpc':'2.0','method':'notifications/initialized'},None,status=202)
        return self

    def save(self):
        (self.run/'report.json').write_bytes(capture.canonical(self.report))
        value=dict(schema_version=1,kind=clocks.KIND,run_id=self.run_id,runner=self.report['runner'],
             report_ref={'path':'report.json','size':len((self.run/'report.json').read_bytes()),
                         'sha256':hashlib.sha256((self.run/'report.json').read_bytes()).hexdigest()},
             clock=self.clock.clock,status='RECORDED')
        (self.run/'call-clock.json').write_bytes(capture.canonical(value))
        self.capture=dict(schema_version=1,kind=capture.KIND,run_id=self.run_id,exchanges=self.rows,status='RECORDED',failure=None)
        (self.run/'raw-mcp/capture.json').write_bytes(capture.canonical(self.capture))
        return self

    def change_body(self,seq,direction,message):
        row=self.rows[seq-1];ref=row[direction+'_ref'];raw=rawjoin.canonical(message) if isinstance(message,dict) else message
        (self.run/'raw-mcp'/ref['path']).write_bytes(raw)
        ref.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())

    def hashes(self):
        return {str(p.relative_to(self.run)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.run.rglob('*') if p.is_file()}


class Models(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('P06_JOIN_TEST_ROOT'));self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def fixture(self):return Fixture(self.root).basic().save()
    def reject(self,f,pattern):
        before=f.hashes()
        with self.assertRaisesRegex((ValueError,OSError),pattern):rawjoin.join(f.run)
        self.assertEqual(before,f.hashes())

    def test_exact_output_type_sensitive_ids_retry_defaults_and_readonly(self):
        f=self.fixture();before=f.hashes();value=rawjoin.join(f.run)
        self.assertEqual(set(value),{'schema_version','kind','run_id','report_ref','capture_ref','clock_ref','calls'})
        self.assertEqual([r['request_id'] for r in value['calls']],[7,'7'])
        for seq,row in enumerate(value['calls'],1):
            self.assertEqual(set(row),{'sequence','request_id','request_location','response_location','tool','arguments_sha256','result_sha256'})
            self.assertEqual(row['result_sha256'],rawjoin.digest(f.calls[seq-1]['mcp_result']))
            for direction in ('request','response'):
                location=row[direction+'_location'];self.assertEqual(set(location),{'exchange_sequence','direction','frame_index','body_ref'})
                self.assertEqual(location['body_ref'],f.rows[seq+1][direction+'_ref'])
        self.assertEqual(before,f.hashes())

    def test_controller_delete_control_json_is_not_a_jsonrpc_response(self):
        f=self.fixture();f.exchange(b'',{},method='DELETE');f.save()
        before=f.hashes()
        self.assertEqual(len(rawjoin.join(f.run)['calls']),2)
        self.assertEqual(before,f.hashes())
        for body,end,status,pattern in (({'extra':1},'eof',200,'DELETE control'),
                ({},'closed',200,'JSON response is incomplete'),({},'eof',503,'non-success HTTP')):
            f=self.fixture();f.exchange(b'',body,method='DELETE',end=end,status=status);f.save()
            self.reject(f,pattern)
        f=self.fixture();f.change_body(3,'response',{});f.save()
        self.reject(f,'version differs')

    def test_sse_bom_crlf_cr_multidata_notifications_and_out_of_order(self):
        f=Fixture(self.root);f.exchange(f.init,f.init_result);f.exchange(f.list,f.list_result)
        notice={'jsonrpc':'2.0','method':'notifications/progress','params':{'progressToken':1,'progress':1}}
        data=b'\xef\xbb\xbf: heartbeat\r\n\r\n'
        for message in (notice,f.responses[1],f.responses[0]):
            raw=rawjoin.canonical(message).decode();left,right=raw.split(',',1)
            data+=('id: retained\revent: message\rdata: '+left+',\rdata: '+right+'\r\r').encode()
        f.exchange(b'',data,method='GET',kind='text/event-stream; charset=utf-8',end='closed')
        for request in f.requests:f.exchange(request,None,status=202)
        f.save();value=rawjoin.join(f.run)
        self.assertEqual([r['response_location']['frame_index'] for r in value['calls']],[3,2])
        self.assertEqual([r['response_location']['exchange_sequence'] for r in value['calls']],[3,3])
        # Chunk boundaries deliberately split BOM, multibyte code points and CRLF.
        decoded=list(rawjoin.sse(bytes([b]) for b in data));self.assertEqual(decoded,[notice,f.responses[1],f.responses[0]])

    def test_gzip_json_and_complete_closed_gzip_sse(self):
        f=self.fixture();raw=gzip.compress(rawjoin.canonical(f.responses[0]),mtime=0)
        f.change_body(3,'response',raw);f.rows[2]['response_content_encoding']='gzip';f.save()
        self.assertEqual(len(rawjoin.join(f.run)['calls']),2)
        f=Fixture(self.root);f.exchange(f.init,f.init_result);f.exchange(f.list,f.list_result)
        body=b''.join(b'data: '+rawjoin.canonical(r)+b'\n\n' for r in f.responses)
        f.exchange(b'',gzip.compress(body,mtime=0),method='GET',kind='text/event-stream',encoding='gzip',end='closed')
        for request in f.requests:f.exchange(request,None,status=202)
        f.save();self.assertEqual(len(rawjoin.join(f.run)['calls']),2)

    def test_duplicate_request_response_same_bytes_orphan_and_lifecycle(self):
        for case in ('request','response','orphan','initialize','before-init'):
            f=self.fixture()
            if case=='request':f.change_body(4,'request',f.requests[0])
            if case=='response':f.change_body(4,'response',f.responses[0])
            if case=='orphan':f.change_body(4,'response',rpc_response('orphan',result(True)))
            if case=='initialize':f.exchange(rpc_request(100,'initialize',f.init['params']),rpc_response(100,f.init_result['result']))
            if case=='before-init':
                f.change_body(1,'request',f.list);f.change_body(2,'request',f.init)
            f.save();self.reject(f,{'request':'duplicate request','response':'duplicate response','orphan':'orphan',
                                   'initialize':'initialize lifecycle','before-init':'precedes initialize'}[case])

    def test_bad_id_types_and_missing_responses_lists(self):
        for id in (True,None,1.5):
            f=self.fixture();message=copy.deepcopy(f.requests[0]);message['id']=id
            f.change_body(3,'request',message);f.save();self.reject(f,'id is not strict')
        for target in (1,2,3):
            f=self.fixture();f.rows[target-1].update(response_ref=None,response_end='not_started',response_status=202)
            # Remove only the synthetic original intentionally missing from capture.
            (f.run/'raw-mcp'/f'exchange-{target:08d}-response.bin').unlink();f.save();self.reject(f,'response missing')

    def test_rpc_error_server_request_and_ambiguous_or_unknown_messages(self):
        changes=[({'jsonrpc':'2.0','id':7,'error':{'code':-1,'message':'failure'}},'JSON-RPC error'),
                 (rpc_request(99,'sampling/createMessage',{}),'server-initiated'),
                 ({**rpc_response(7,result()),'error':{}},'result/error'),
                 ({**rpc_response(7,result()),'jsonrpc':'1.0'},'version'),
                 ({'jsonrpc':'2.0','method':'custom/unknown'},'uninterpretable notification')]
        for message,pattern in changes:
            f=self.fixture();f.change_body(3,'response',message);f.save();self.reject(f,pattern)

    def test_params_hidden_calls_result_and_extension_loss(self):
        for case in ('args','missing-args','name','params-extra','hidden','content','isError','structured','top-extra','nested-extra','scalar','aliases'):
            f=self.fixture();request=copy.deepcopy(f.requests[0]);response=copy.deepcopy(f.responses[0]);pattern=''
            if case=='args':request['params']['arguments']={'n':True};pattern='arguments differ'
            if case=='missing-args':del request['params']['arguments'];pattern='arguments missing'
            if case=='name':request['params']['name']='other';pattern='tool/arguments differ'
            if case=='params-extra':request['params']['extra']='lost';pattern='dropped extension'
            if case=='hidden':f.exchange(rpc_request(9,'tools/call',request['params']),rpc_response(9,result()));pattern='count differs'
            if case=='content':response['result']['content'][0]['text']='changed';pattern='full SDK'
            if case=='isError':response['result']['isError']=True;pattern='full SDK'
            if case=='structured':response['result']['structuredContent']['value']='different';pattern='full SDK'
            if case=='top-extra':response['result']['extension']='lost';pattern='dropped extension'
            if case=='nested-extra':response['result']['content'][0]['extension']='lost';pattern='dropped extension'
            if case=='scalar':response['result']['isError']=1;pattern='model invalid'
            if case=='aliases':response['result']['is_error']=False;pattern='aliases collide'
            f.change_body(3,'request',request);f.change_body(3,'response',response);f.save();self.reject(f,pattern)

    def test_sse_utf8_half_frames_and_unknown_event(self):
        for body,pattern in [(b'data: '+rawjoin.canonical(rpc_response(7,result()))+b'\n','undispatched'),
            (b'data: {}','unterminated'),(b': ok\n\n\xe4','UTF8'),
            (b'event: custom\ndata: '+rawjoin.canonical(rpc_response(7,result()))+b'\n\n','unsupported SSE'),
            (b'data: bad\n\n','invalid UTF8/JSON')]:
            f=self.fixture();f.change_body(3,'response',body);f.rows[2].update(response_content_type='text/event-stream',response_end='closed')
            f.save();self.reject(f,pattern)

    def test_json_encoding_gzip_trailer_members_and_strict_json(self):
        valid=rawjoin.canonical(rpc_response(7,result()))
        changes=[(gzip.compress(valid)[:-4],'gzip','gzip incomplete'),(b'not-gzip','gzip','gzip integrity'),
                 (gzip.compress(valid)+gzip.compress(valid),'gzip','extra member'),
                 (gzip.compress(valid)+b'tail','gzip','extra member'),(valid,'br','unsupported Content-Encoding'),
                 (valid+b'\xe4','','invalid UTF8/JSON'),(b'[]','','batch/non-object'),
                 (valid.replace(b'"id":7',b'"id":7,"id":7'),'','duplicate JSON'),
                 (valid.replace(b'"value":false',b'"value":NaN'),'','nonfinite')]
        for body,encoding,pattern in changes:
            f=self.fixture();f.change_body(3,'response',body);f.rows[2]['response_content_encoding']=encoding
            f.save();self.reject(f,pattern)
        f=self.fixture();f.rows[2]['response_content_type']='application/octet-stream';f.save();self.reject(f,'unsupported nonempty Content-Type')
        f=self.fixture();f.rows[2]['response_end']='closed';f.save();self.reject(f,'JSON response is incomplete')
        f=self.fixture();f.rows[2]['response_status']=401;f.save();self.reject(f,'non-success HTTP')

    def test_capture_report_clock_bindings_and_failed_inputs(self):
        for case in ('capture-run','clock-run','clock-id','report-ref','failed','invoked','schema3','body-ref','capture-failed','error-end'):
            f=self.fixture()
            if case=='capture-run':
                p=f.run/'raw-mcp/capture.json';v=json.loads(p.read_bytes());v['run_id']=str(uuid.uuid4());p.write_bytes(capture.canonical(v))
            if case=='clock-id':f.calls[0]['monotonic']['clock_id']=str(uuid.uuid4());f.save()
            if case=='failed':f.report['status']='failed';f.save()
            if case=='invoked':f.calls[0]['monotonic'].update(invoked=False,started_ns=None,ended_ns=None);f.save()
            if case=='schema3':f.report['schema_version']=3;f.save()
            if case in ('clock-run','report-ref'):
                p=f.run/'call-clock.json';v=json.loads(p.read_bytes())
                if case=='clock-run':v['run_id']=str(uuid.uuid4())
                else:v['report_ref']['sha256']='0'*64
                p.write_bytes(capture.canonical(v))
            if case in ('body-ref','capture-failed','error-end'):
                p=f.run/'raw-mcp/capture.json';v=json.loads(p.read_bytes())
                if case=='body-ref':v['exchanges'][2]['response_ref']['sha256']='0'*64
                if case=='capture-failed':v.update(status='FAILED',failure={'type':'OSError','message':'local fixed'})
                if case=='error-end':v['exchanges'][2]['response_end']='error'
                p.write_bytes(capture.canonical(v))
            self.reject(f,{'capture-run':'cross-run','clock-run':'cross-run','clock-id':'domain','report-ref':'Ref',
                'failed':'successful','invoked':'non-invoked','schema3':'schema','body-ref':'hash','capture-failed':'FAILED','error-end':'error termination'}[case])

    def test_explicit_size_refusal_never_truncates_and_nested_any_preserved(self):
        f=self.fixture()
        with patch.object(rawjoin,'MAX_MESSAGE_BYTES',16):self.reject(f,'message limit')
        f=self.fixture();response=copy.deepcopy(f.responses[0]);response['result']['structuredContent']['extension']={'unknown':123}
        f.calls[0]['mcp_result']=CallToolResult.model_validate(response['result']).model_dump(mode='json',by_alias=True,exclude_none=True)
        f.change_body(3,'response',response);f.save();self.assertEqual(len(rawjoin.join(f.run)['calls']),2)

    def test_utf16_and_closed_gzip_prefix_explicitly_unsupported(self):
        for direction in ('request','response'):
            f=self.fixture();message=f.requests[0] if direction=='request' else f.responses[0]
            f.change_body(3,direction,rawjoin.canonical(message).decode().encode('utf-16'));f.save()
            self.reject(f,'invalid UTF8/JSON')
        f=self.fixture();body=gzip.compress(b'data: '+rawjoin.canonical(f.responses[0])+b'\n\n')[:-4]
        f.change_body(3,'response',body);f.rows[2].update(response_content_type='text/event-stream',
                    response_content_encoding='gzip',response_end='closed');f.save()
        self.reject(f,'gzip incomplete')

    def test_compression_expansion_above_read_chunk_preserves_full_sdk_result(self):
        f=self.fixture();message=copy.deepcopy(f.responses[0]);message['result']['content'][0]['text']='中'*40000
        f.calls[0]['mcp_result']=CallToolResult.model_validate(message['result']).model_dump(mode='json',by_alias=True,exclude_none=True)
        f.change_body(3,'response',gzip.compress(rawjoin.canonical(message),mtime=0));f.rows[2]['response_content_encoding']='gzip'
        f.save();value=rawjoin.join(f.run)
        self.assertEqual(value['calls'][0]['result_sha256'],rawjoin.digest(f.calls[0]['mcp_result']))

    def test_initialize_params_must_be_complete(self):
        for params in (None,{}, {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'host'}}):
            f=self.fixture();f.change_body(1,'request',rpc_request(0,'initialize',params));f.save()
            self.reject(f,'model invalid')

    def test_paginated_list_requests_all_need_unique_complete_responses(self):
        f=self.fixture();f.change_body(2,'response',rpc_response(1,{'tools':[],'nextCursor':'page2'}))
        f.exchange(rpc_request('list2','tools/list',{'cursor':'page2'}),rpc_response('list2',{'tools':[]}))
        f.save();before=f.hashes();self.assertEqual(len(rawjoin.join(f.run)['calls']),2);self.assertEqual(before,f.hashes())
        f.rows[-1].update(response_ref=None,response_end='not_started',response_status=202)
        (f.run/'raw-mcp/exchange-00000006-response.bin').unlink();f.save();self.reject(f,'response missing')

    def test_final_recheck_rejects_actor_drift_without_module_writes(self):
        f=self.fixture();original=rawjoin._Reader.recheck;actor_state={}
        def changed(reader):
            p=f.run/'report.json';p.write_bytes(p.read_bytes()+b' ')
            actor_state.update(f.hashes());return original(reader)
        with patch.object(rawjoin._Reader,'recheck',changed):
            with self.assertRaisesRegex(rawjoin.JoinError,'identity drift'):rawjoin.join(f.run)
        self.assertEqual(actor_state,f.hashes())


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
        official=app.streamable_http_app();oracle=[]
        async def observed(scope,receive,send):
            if scope['type']!='http':await official(scope,receive,send);return
            row=dict(method=scope['method'],status=None,request=bytearray(),response=bytearray());oracle.append(row)
            async def recv():
                message=await receive()
                if message['type']=='http.request':row['request'].extend(message.get('body',b''))
                return message
            async def transmit(message):
                if message['type']=='http.response.start':row['status']=message['status']
                if message['type']=='http.response.body':row['response'].extend(message.get('body',b''))
                await send(message)
            await official(scope,recv,transmit)
        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
        self.assertNotEqual(port,28790)
        server=uvicorn.Server(uvicorn.Config(observed,log_level='error',access_log=False))
        worker=asyncio.create_task(server.serve(sockets=[sock]))
        target=os.environ.get('P06_JOIN_SDK_EVIDENCE');temporary=None
        if target:root=Path(target);root.mkdir()
        else:temporary=tempfile.TemporaryDirectory(dir=os.environ.get('P06_JOIN_TEST_ROOT'));root=Path(temporary.name)
        run_id=str(uuid.uuid4());run=root/run_id;run.mkdir();clock=clocks.RunClock();calls=[]
        transport=capture.CaptureTransport(httpx2.AsyncHTTPTransport(),run,run_id)
        try:
            for _ in range(200):
                if server.started:break
                if worker.done():await worker
                await asyncio.sleep(.01)
            self.assertTrue(server.started)
            started=runner.utc_now()
            async with httpx2.AsyncClient(transport=transport,trust_env=False,
                            headers={'authorization':'FIXED_JOIN_TEST_AUTH'}) as client:
                async with streamable_http_client(f'http://127.0.0.1:{port}/mcp',http_client=client) as (read,write):
                    async with ClientSession(read,write) as session:
                        initialized=await session.initialize();listed=await session.list_tools()
                        for seq,(name,error) in enumerate((('join_success',False),('join_error',True)),1):
                            spec={'id':name,'kind':'tool','tool':name,'arguments':{'n':seq},
                                  'assertions':[{'op':'is_error','actual':'/isError','expected':error}]}
                            await runner.execute_tool_step(session,spec,{},{},calls,_call_clock=clock)
            report=host_report(run_id,calls)
            report.update(endpoint=f'http://127.0.0.1:{port}/mcp',started_at=started,ended_at=runner.utc_now(),
                runner={'pid':os.getpid(),'process_start_time_utc':runner._runner_start_time_utc(),
                        'executable_sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()})
            report['mcp_session'].update(initialized_at=started,closed_at=report['ended_at'])
            report_raw=capture.canonical(report)
            with (run/'report.json').open('xb') as out:out.write(report_raw)
            clock.save(run,report,report_raw)
            before={str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob('*') if p.is_file()}
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
            sdk_proof={'nature':'real loopback official SDK; schema2 shaped synthetic host identity, not 191/Windows approval',
                'run_id':run_id,'port':port,'runner':report['runner'],'initialized':initialized.model_dump(mode='json',by_alias=True,exclude_none=True),
                'listed':listed.model_dump(mode='json',by_alias=True,exclude_none=True),'calls':calls,'join':joined,
                'source_sha256':{str(p.relative_to(Path.cwd())):hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in [Path(rawjoin.__file__),Path(__file__)]},'raw_hashes':before}
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

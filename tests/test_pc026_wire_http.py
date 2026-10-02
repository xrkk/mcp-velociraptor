"""Real loopback HTTP/official SDK, actual guest engine with explicit host fixture.

This is host development evidence, not native Windows/firewall qualification.
"""
import asyncio
import base64
import hashlib
import json
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
from tests import test_transfer_pc026_prefix as prefix_fixture
from contextlib import asynccontextmanager
from functools import wraps
from velo_transfer import wire
from velo_transfer.http_wire import TransferHTTPGate, SDKSessionBindings, BodyLimitExceeded
from velo_transfer.mcp_tools import register_transfer_tools
from velociraptor_transport import build_formal_http_app, TransportConfig


def connected_test(fn):
    @wraps(fn)
    async def run(self):
        async with self.connected():
            await fn(self)
    return run


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.f = prefix_fixture.PrefixTests('test_actual_worker_proof_matches_ledger_new_nonce_and_deadline')
        self.f.setUp()
        self.server = MCPServer('pc026-real-http')
        manager = register_transfer_tools(self.server, factory=lambda:self.f.service)
        self.server._guest_transfer_tools = manager
        sock = socket.socket(); sock.bind(('127.0.0.1',0)); self.port=sock.getsockname()[1]; sock.close()
        self.app=build_formal_http_app(self.server, TransportConfig('http',host='127.0.0.1',port=self.port,
            bearer_token='local-only-fixture-token',allowed_origins=('https://allowed.example',)))
        self.running=uvicorn.Server(uvicorn.Config(self.app,host='127.0.0.1',port=self.port,log_level='critical'))
        self.thread=threading.Thread(target=self.running.run,daemon=False);self.thread.start()
        deadline=time.monotonic()+10
        while not self.running.started and time.monotonic()<deadline:await asyncio.sleep(.02)
        self.assertTrue(self.running.started)
        self.url=f'http://127.0.0.1:{self.port}/mcp'

    async def asyncTearDown(self):
        self.running.should_exit=True
        await asyncio.to_thread(self.thread.join,10)
        self.assertFalse(self.thread.is_alive(), 'owned HTTP thread must stop')
        self.f.doCleanups()

    @asynccontextmanager
    async def connected(self):
        self.ids=[]; self.instances=[]
        async def hook(response):
            sid=response.headers.get('mcp-session-id')
            if sid:self.ids.append(sid)
            instance=response.headers.get('x-mcp-server-instance')
            if instance:self.instances.append(instance)
        async with httpx2.AsyncClient(headers={'Authorization':'Bearer local-only-fixture-token'},
                trust_env=False,timeout=30,event_hooks={'response':[hook]}) as self.http:
            async with streamable_http_client(self.url,http_client=self.http) as (read,write):
                async with ClientSession(read,write) as self.session:
                    await self.session.initialize()
                    await self.session.list_tools()
                    self.sid=self.ids[0];self.instance=self.instances[0]
                    yield

    def headers(self, req, direction='push'):
        return {'Mcp-Session-Id':self.sid,'X-MCP-Server-Instance':self.instance,
                'Content-Type':'application/octet-stream','x-velo-direction':direction,
                'x-velo-transfer-id':req['transfer_id'],'x-velo-request-digest':req['request_digest'],
                'x-velo-offset':'0'}

    def pushframe(self, payload=b'abcdefghi'):
        parts=[payload[:4],payload[4:]]
        return wire.encode({'chunks':[{'count':len(p),'chunk_sha256':hashlib.sha256(p).hexdigest()} for p in parts]},payload,'push_request')

    async def post(self, headers, body):
        return await self.http.post(self.url.replace('/mcp','/chunkbin'),headers=headers,content=body)

    def snapshot(self):
        return {str(p):(p.read_bytes(),p.stat().st_ino,p.stat().st_mtime_ns) for p in self.f.work.rglob('*') if p.is_file()}

    @connected_test
    async def test_adapter_real_loopback_401_without_instance_and_security_order(self):
        from velo_transfer.adapters import TransportAdapter, _DirectChunkChannel, AdapterError
        req = self.f.push()
        before = self.snapshot()
        adapter = TransportAdapter(None, 'velo', self.url, time.monotonic()+60, 10, [self.instance])
        channel = _DirectChunkChannel(self.http, self.url, self.sid, self.instance,
                                      adapter.deadline_monotonic, 10)
        adapter._direct = channel
        args = {'transfer_id': req['transfer_id'], 'request_digest': req['request_digest'],
                'offset': 0, 'chunks': [{'count': 1, 'data_base64': 'eA==',
                    'chunk_sha256': hashlib.sha256(b'x').hexdigest()}]}
        responses = []
        async def observe(response):
            responses.append((response.status_code, response.headers.get('x-mcp-server-instance')))
        self.http.event_hooks['response'].append(observe)
        for token in ('Bearer wrong', None):
            with self.subTest(token_present=token is not None):
                if token is None:
                    del self.http.headers['Authorization']
                else:
                    self.http.headers['Authorization'] = token
                self.http.headers['Host'] = 'bad'
                self.http.headers['Origin'] = 'https://denied.example'
                previous = len(responses)
                with self.assertRaises(AdapterError) as raised:
                    await adapter.call('transfer_chunks', args)
                error = raised.exception
                self.assertEqual(error.code, 'unauthorized')
                self.assertTrue(error.may_have_committed)
                self.assertFalse(error.retryable)
                self.assertEqual(responses[previous:], [(401, None)])
                self.assertIs(adapter._direct, channel)
                self.assertEqual(self.snapshot(), before)
        self.http.headers['Authorization'] = 'Bearer local-only-fixture-token'
        for code, change in (('bad_host', {}), ('origin_denied', {'Host': None}),
                             ('session_not_found', {'Origin': None})):
            for key, value in change.items():
                if value is None:
                    del self.http.headers[key]
            if code == 'session_not_found':
                channel.session_id = 'unknown'
            previous = len(responses)
            with self.assertRaises(AdapterError) as raised:
                await adapter.call('transfer_chunks', args)
            self.assertEqual(raised.exception.code, code)
            self.assertTrue(raised.exception.may_have_committed)
            self.assertFalse(raised.exception.retryable)
            self.assertEqual(len(responses)-previous, 1)
            self.assertEqual(self.snapshot(), before)
        channel.session_id = self.sid

    @connected_test
    async def test_real_sdk_push_and_pull_business(self):
        req=self.f.push()
        r=await self.post(self.headers(req),self.pushframe())
        self.assertEqual(r.status_code,200,r.text)
        h,p=wire.decode(r.content,'push_response');self.assertEqual(h['result'],{'verified_offset':9,'accepted':2})
        self.assertEqual((self.f.work/'tasks/trial/received.part').read_bytes(),b'abcdefghi')
        self.assertEqual(self.app.state.transfer_bindings.owners[self.sid],hashlib.sha256(b'local-only-fixture-token').digest())

    @connected_test
    async def test_real_sdk_pull_package_bytes(self):
        source=self.f.read/'source.bin';source.write_bytes(b'pull-source-data')
        req=self.f.request('pull',[{'absolute_path':str(source),'relative_path':'source.bin'}],self.f.host/'out')
        from velo_transfer.guest_service import request_digest
        req['request_digest']=request_digest(req)
        self.f.service.transfer_begin(req)
        self.f.wait_phase(req,'SOURCE_READY')
        headers=self.headers(req,'pull');headers.update({'x-velo-count-per-chunk':'16','x-velo-chunk-count':'2'})
        r=await self.post(headers,wire.encode({},b'','pull_request'))
        self.assertEqual(r.status_code,200,r.text)
        h,p=wire.decode(r.content,'pull_response');self.assertTrue(p.startswith(b'PK'));self.assertEqual(len(p),32)
        self.assertEqual([c['offset'] for c in h['result']['chunks']],[0,16])

    @connected_test
    async def test_security_order_missing_unknown_expired_instance_token(self):
        req=self.f.push();before=self.snapshot();base=self.headers(req)
        cases=[({'Authorization':'Bearer wrong','Host':'bad'},401,'unauthorized'),
               ({'Host':'bad'},421,'bad_host'),({'Origin':'https://bad.example'},403,'origin_denied'),
               ({'Mcp-Session-Id':None},400,'session_required'),
               ({'Mcp-Session-Id':'unknown'},404,'session_not_found'),
               ({'Mcp-Session-Id':'unknown','X-MCP-Server-Instance':None},404,'session_not_found'),
               ({'X-MCP-Server-Instance':'changed'},400,'invalid_frame')]
        for change,status,code in cases:
            headers=dict(base);headers.update(change);headers={k:v for k,v in headers.items() if v is not None}
            r=await self.post(headers,b'bad')
            self.assertEqual(r.status_code,status,(change,r.text));self.assertEqual(r.json(),{'error':{'code':code}})
            self.assertEqual(self.snapshot(),before)
        # Authentic session but wrong owner is indistinguishable from unknown.
        self.app.state.transfer_bindings.owners[self.sid]=b'other-owner'
        r=await self.post(base,self.pushframe());self.assertEqual(r.status_code,404)
        self.app.state.transfer_bindings.owners[self.sid]=hashlib.sha256(b'local-only-fixture-token').digest()
        r=await self.http.delete(self.url,headers={'Mcp-Session-Id':self.sid})
        self.assertEqual(r.status_code,200)
        r=await self.post(base,self.pushframe());self.assertEqual(r.status_code,404)
        self.assertEqual(self.snapshot(),before)

    @connected_test
    async def test_invalid_second_item_bad_frame_headers_zero_effects(self):
        req=self.f.push();before=self.snapshot();base=self.headers(req)
        raw=b'{"chunks":[{"count":3,"chunk_sha256":"'+hashlib.sha256(b'abc').hexdigest().encode()+b'"},{"count":3,"chunk_sha256":"'+b'0'*64+b'"}]}'
        bad=wire.MAGIC+len(raw).to_bytes(4,'little')+raw+b'abcdef'
        duplicate=[(k,v) for k,v in base.items()]+[('X-Velo-Offset','0')]
        for headers,body in ((base,bad),(base,self.pushframe()+b'extra'),(duplicate,self.pushframe()),
                             (dict(base,**{'x-velo-offset':'00'}),self.pushframe())):
            r=await self.post(headers,body);self.assertEqual(r.status_code,400,r.text)
            self.assertEqual(r.json(),{'error':{'code':'invalid_frame'}});self.assertEqual(self.snapshot(),before)
        r=await self.post(dict(base,**{'Content-Type':'application/json'}),b'{}')
        self.assertEqual(r.status_code,415);self.assertEqual(self.snapshot(),before)

    @connected_test
    async def test_real_chunked_100mib_limit_no_writer(self):
        req=self.f.push();before=self.snapshot()
        async def fragments():
            for _ in range(100):yield b'x'*(1<<20)
            yield b'!'
        r=await self.http.post(self.url.replace('/mcp','/chunkbin'),headers=self.headers(req),content=fragments())
        self.assertEqual(r.status_code,413)
        self.assertEqual(r.json(),{'error':{'code':'body_too_large'}})
        self.assertEqual(self.snapshot(),before)

    @connected_test
    async def test_real_json_chunked_100mib_limit_no_writer(self):
        req=self.f.push();before=self.snapshot()
        async def fragments():
            yield b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"transfer_chunks","arguments":{"padding":"'
            for _ in range(100):yield b'x'*(1<<20)
            yield b'"}}}'
        headers={'Mcp-Session-Id':self.sid,'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
        r=await self.http.post(self.url,headers=headers,content=fragments())
        self.assertEqual(r.status_code,413)
        self.assertEqual(r.json(),{'error':{'code':'body_too_large'}});self.assertEqual(self.snapshot(),before)

    @connected_test
    async def test_negotiated_adapter_same_sdk_session_binary(self):
        from types import SimpleNamespace
        from velo_transfer.adapters import open_adapter
        req=self.f.push()
        token=SimpleNamespace(read=lambda:'local-only-fixture-token')
        profile=SimpleNamespace(velo=SimpleNamespace(url=self.url,token=token))
        async with open_adapter(profile,'velo',deadline_monotonic=time.monotonic()+90,request_timeout_seconds=30) as adapter:
            await adapter.probe({'vm_uuid':self.f.uuid,'boot_identity':self.f.observation.boot_identity})
            self.assertIsNotNone(adapter._direct)
            self.assertTrue(self.app.state.transfer_bindings.live(adapter._direct.session_id))
            chunk={'count':9,'data_base64':base64.b64encode(b'abcdefghi').decode(),
                   'chunk_sha256':hashlib.sha256(b'abcdefghi').hexdigest()}
            result=await adapter.call('transfer_chunks',{'transfer_id':'trial','request_digest':req['request_digest'],
                'offset':0,'chunks':[chunk]})
            self.assertEqual(result['verified_offset'],9)
            self.assertEqual((self.f.work/'tasks/trial/received.part').read_bytes(),b'abcdefghi')

    @connected_test
    async def test_sdk_json_error_keeps_http_session_code(self):
        from types import SimpleNamespace
        from velo_transfer.adapters import open_adapter, AdapterError
        token=SimpleNamespace(read=lambda:'local-only-fixture-token')
        profile=SimpleNamespace(velo=SimpleNamespace(url=self.url,token=token))
        async with open_adapter(profile,'velo',deadline_monotonic=time.monotonic()+90,request_timeout_seconds=30) as adapter:
            await adapter.probe({'vm_uuid':self.f.uuid,'boot_identity':self.f.observation.boot_identity})
            direct=adapter._direct
            await direct.http.delete(self.url,headers={'Mcp-Session-Id':direct.session_id})
            with self.assertRaises(AdapterError) as raised:
                await adapter.call('transfer_status',{'transfer_id':'trial','request_digest':'a'*64})
            self.assertEqual(raised.exception.code,'session_not_found')



class ActualCountingTests(unittest.IsolatedAsyncioTestCase):
    async def run_gate(self, parts, *, binary=False, response_parts=None, limit=10):
        sent=[]; dispatched=[];messages=[{'type':'http.request','body':p,'more_body':i<len(parts)-1} for i,p in enumerate(parts)]
        async def receive():return messages.pop(0) if messages else {'type':'http.disconnect'}
        async def send(m):sent.append(m)
        async def app(scope,receive,send):
            dispatched.append(True);await receive()
            await send({'type':'http.response.start','status':200,'headers':[]})
            for i,p in enumerate(response_parts or [b'ok']):
                await send({'type':'http.response.body','body':p,'more_body':i<len(response_parts or [b'ok'])-1})
        # Counting seam only; real sessions exercised by HTTPTests above.
        bindings=SDKSessionBindings(None,'instance');bindings.check=lambda *a,**k:None
        gate=TransferHTTPGate(app,bindings,body_limit=limit)
        scope={'type':'http','method':'POST','path':'/chunkbin' if binary else '/mcp',
               'headers':[(b'content-length',b'1')]}
        try:await gate(scope,receive,send)
        except BodyLimitExceeded:pass
        return sent,dispatched

    async def test_fake_small_length_fragmented_or_absent_actual_request_limit(self):
        for parts in ([b'123456',b'78901'],[b'x'*11]):
            sent,dispatched=await self.run_gate(parts,binary=True)
            self.assertFalse(dispatched);self.assertEqual(sent[0]['status'],413)
            self.assertEqual(json.loads(sent[1]['body']),{'error':{'code':'body_too_large'}})

    async def test_nonobject_json_rejects_before_dispatch(self):
        for body in (b'[]',b'null',b'true',b'3'):
            sent,dispatched=await self.run_gate([body],limit=128)
            self.assertFalse(dispatched);self.assertEqual(sent[0]['status'],400)
            self.assertEqual(json.loads(sent[1]['body']),{'error':{'code':'invalid_frame'}})

    async def test_binary_response_interrupt_never_writes_overlimit(self):
        sent,_=await self.run_gate([b''],binary=True,response_parts=[b'123456',b'78901'])
        self.assertEqual(sum(len(m.get('body',b'')) for m in sent if m['type']=='http.response.body'),6)
        self.assertTrue(sent[-1]['more_body'])

    async def test_json_and_sse_serialized_wrapper_limit(self):
        request=json.dumps({'method':'tools/call','params':{'name':'transfer_chunks'}}).encode()
        for response in (b'{"result":"'+b'x'*130+b'"}', b'data: '+b'x'*130+b'\n\n'):
            sent,_=await self.run_gate([request],limit=128,response_parts=[response])
            self.assertEqual(sent[0]['status'],413)


class FullBudgetCountingTests(unittest.IsolatedAsyncioTestCase):
    run_gate = ActualCountingTests.run_gate
    async def test_actual_100mib_json_and_sse_response_wrapper_interruption(self):
        request=json.dumps({'method':'tools/call','params':{'name':'transfer_chunks'}}).encode()
        unit=1<<20
        for prefix,tail in ((b'{"result":"',b'"}'),(b'data: {"result":"',b'"}\n\n')):
            parts=[prefix+b'x'*(unit-len(prefix))]+[b'x'*unit]*99+[tail]
            sent,dispatched=await self.run_gate([request],limit=wire.BODY_LIMIT,response_parts=parts)
            self.assertTrue(dispatched)
            self.assertEqual(sum(len(m.get('body',b'')) for m in sent if m['type']=='http.response.body'),wire.BODY_LIMIT)
            self.assertTrue(sent[-1]['more_body'])

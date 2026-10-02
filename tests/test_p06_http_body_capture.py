"""Transport stream models and independent real loopback SDK evidence."""
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

import httpx2
from tests import p06_http_body_capture as capture


def temp_root():
    return os.environ.get('P06_BODY_TEST_ROOT')


class Stream(httpx2.AsyncByteStream):
    def __init__(self, chunks=(), error=None, wait=False):
        self.chunks, self.error, self.wait = chunks, error, wait
        self.closes = 0; self.seen = []; self.waiting = asyncio.Event()

    async def __aiter__(self):
        for chunk in self.chunks:
            self.seen.append(chunk); yield chunk
        if self.wait:
            self.waiting.set(); await asyncio.Event().wait()
        if self.error:
            raise self.error

    async def aclose(self):
        self.closes += 1


class Transport(httpx2.AsyncBaseTransport):
    def __init__(self, chunks=(), error=None, wait=False, encoding='', read_request=True):
        self.chunks, self.error, self.wait, self.encoding = chunks, error, wait, encoding
        self.read_request = read_request
        self.closes = 0; self.requests = []; self.responses = []

    async def handle_async_request(self, request):
        body = [chunk async for chunk in request.stream] if self.read_request else None
        self.requests.append((request.method, body))
        stream = Stream(self.chunks, self.error, self.wait); self.responses.append(stream)
        return httpx2.Response(200, headers={'content-type':'text/event-stream',
                              'content-encoding':self.encoding,'set-cookie':'AUTH_SECRET'},stream=stream)

    async def aclose(self):
        self.closes += 1


class Models(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=temp_root());self.root=Path(self.tmp.name)
        self.run_id=str(uuid.uuid4());self.run=self.root/self.run_id;self.run.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def wrapper(self, inner):
        return capture.CaptureTransport(inner,self.run,self.run_id)

    async def request(self, wrapper, chunks=(b'request',)):
        source=Stream(chunks)
        request=httpx2.Request('POST','http://model.invalid/mcp',stream=source,
                              headers={'authorization':'AUTH_SECRET','cookie':'COOKIE_SECRET'})
        return await wrapper.handle_async_request(request),source

    def original(self, ref):
        return (self.run/'raw-mcp'/ref['path']).read_bytes()

    async def test_chunks_utf8_empty_and_no_auth_headers(self):
        chunks=[b'data: "\xe4',b'\xb8',b'\xad"\n\n',b'data: second\n\n']
        inner=Transport(chunks);wrapper=self.wrapper(inner)
        response,source=await self.request(wrapper,[b'\xe4',b'\xb8\xad'])
        self.assertEqual([p async for p in response.stream],chunks)
        self.assertEqual(inner.requests,[('POST',[b'\xe4',b'\xb8\xad'])])
        await response.aclose();await wrapper.aclose();await wrapper.aclose()
        value=capture.verify(self.run,self.run_id);row=value['exchanges'][0]
        self.assertEqual(self.original(row['request_ref']),b'\xe4\xb8\xad')
        self.assertEqual(self.original(row['response_ref']),b''.join(chunks))
        self.assertEqual((row['request_end'],row['response_end']),('eof','eof'))
        self.assertEqual((source.closes,inner.responses[0].closes,inner.closes),(1,1,1))
        raw=(self.run/'raw-mcp/capture.json').read_bytes()
        for secret in (b'AUTH_SECRET',b'COOKIE_SECRET',b'authorization',b'set-cookie'):
            self.assertNotIn(secret,raw)

    async def test_empty_and_unstarted_directions(self):
        inner=Transport();wrapper=self.wrapper(inner)
        response,_=await self.request(wrapper,[])
        self.assertEqual([p async for p in response.stream],[])
        await wrapper.aclose();row=capture.verify(self.run)['exchanges'][0]
        self.assertEqual([row[k]['size'] for k in ('request_ref','response_ref')],[0,0])
        other=self.root/str(uuid.uuid4());other.mkdir();inner=Transport(read_request=False)
        wrapper=capture.CaptureTransport(inner,other,str(uuid.uuid4()))
        await self.request(wrapper);await wrapper.aclose();row=capture.verify(other)['exchanges'][0]
        self.assertEqual((row['request_end'],row['response_end']),('not_started','not_started'))
        self.assertIsNone(row['request_ref']);self.assertIsNone(row['response_ref'])

    async def test_early_close_sse_prefix_no_prefetch_or_drain(self):
        inner=Transport([b'data: one\n\n',b'data: two\n\n'],wait=True);wrapper=self.wrapper(inner)
        response,_=await self.request(wrapper);iterator=response.stream.__aiter__()
        self.assertEqual(await anext(iterator),b'data: one\n\n')
        await response.aclose();await wrapper.aclose()
        before=(self.run/'raw-mcp/capture.json').read_bytes()
        self.assertEqual(inner.responses[0].seen,[b'data: one\n\n'])
        with self.assertRaises(StopAsyncIteration):await anext(iterator)
        self.assertEqual((self.run/'raw-mcp/capture.json').read_bytes(),before)
        row=capture.verify(self.run)['exchanges'][0]
        self.assertEqual(row['response_end'],'closed')
        self.assertEqual(self.original(row['response_ref']),b'data: one\n\n')

    async def test_content_encoding_observed_before_actual_httpx_decoding(self):
        plaintext='跨块 gzip transport body'.encode();encoded=gzip.compress(plaintext,mtime=0)
        inner=Transport([encoded[:7],encoded[7:15],encoded[15:]],encoding='gzip')
        wrapper=self.wrapper(inner)
        async with httpx2.AsyncClient(transport=wrapper,trust_env=False) as client:
            response=await client.post('http://model.invalid/mcp',content=b'x')
            self.assertEqual(response.content,plaintext)
        row=capture.verify(self.run)['exchanges'][0]
        self.assertEqual(self.original(row['response_ref']),encoded)
        self.assertEqual(row['response_content_encoding'],'gzip')

    async def test_stream_error_and_cancel_keep_prefix_and_safe_diagnostic(self):
        for cancel in (False,True):
            run=self.root/str(uuid.uuid4());run.mkdir()
            inner=Transport([b'prefix'],error=RuntimeError('REMOTE_AUTH_SECRET') if not cancel else None,wait=cancel)
            wrapper=capture.CaptureTransport(inner,run,str(uuid.uuid4()));response,_=await self.request(wrapper)
            iterator=response.stream.__aiter__();self.assertEqual(await anext(iterator),b'prefix')
            if cancel:
                task=asyncio.create_task(anext(iterator));await inner.responses[0].waiting.wait();task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
            else:
                with self.assertRaisesRegex(RuntimeError,'REMOTE_AUTH_SECRET'):await anext(iterator)
            await wrapper.aclose();value=capture.verify(run);row=value['exchanges'][0]
            self.assertEqual(row['response_end'],'closed' if cancel else 'error')
            self.assertEqual((run/'raw-mcp'/row['response_ref']['path']).read_bytes(),b'prefix')
            self.assertEqual(value['status'],'RECORDED')
            self.assertNotIn(b'REMOTE_AUTH_SECRET',(run/'raw-mcp/capture.json').read_bytes())

    async def test_transport_close_cancels_blocked_read_and_is_idempotent(self):
        inner=Transport([b'prefix'],wait=True);wrapper=self.wrapper(inner)
        response,_=await self.request(wrapper);iterator=response.stream.__aiter__();await anext(iterator)
        task=asyncio.create_task(anext(iterator));await inner.responses[0].waiting.wait()
        await asyncio.wait_for(wrapper.aclose(),2)
        with self.assertRaises(StopAsyncIteration):await task
        await wrapper.aclose()
        row=capture.verify(self.run)['exchanges'][0];self.assertEqual(row['response_end'],'closed')
        self.assertEqual(inner.responses[0].closes,1)

    async def test_concurrent_exchanges_do_not_interleave_files(self):
        class Echo(Transport):
            async def handle_async_request(self, request):
                chunks=[]
                async for c in request.stream:
                    chunks.append(c);await asyncio.sleep(0)
                self.requests.append((request.method,chunks))
                stream=Stream(chunks);self.responses.append(stream)
                return httpx2.Response(200,stream=stream)
        inner=Echo();wrapper=self.wrapper(inner)
        async def call(n):
            response,source=await self.request(wrapper,[str(n).encode(),b'!',str(n).encode()])
            return b''.join([c async for c in response.stream])
        values=await asyncio.gather(*(call(n) for n in range(8)))
        self.assertEqual(values,[f'{n}!{n}'.encode() for n in range(8)])
        await asyncio.gather(wrapper.aclose(),wrapper.aclose())
        rows=capture.verify(self.run)['exchanges'];self.assertEqual(len(rows),8)
        for row in rows:self.assertEqual(self.original(row['request_ref']),self.original(row['response_ref']))
        self.assertEqual(inner.closes,1)

    async def test_disk_write_and_fsync_faults_surface_and_keep_prefix(self):
        for stage in ('write','fsync'):
            run=self.root/str(uuid.uuid4());run.mkdir();inner=Transport([b'prefix',b'tail'])
            wrapper=capture.CaptureTransport(inner,run,str(uuid.uuid4()));response,_=await self.request(wrapper)
            iterator=response.stream.__aiter__();await anext(iterator)
            target=capture.os.write if stage=='write' else capture.os.fsync
            with patch.object(capture.os,stage,side_effect=OSError('DISK_SECRET')):
                with self.assertRaises(OSError):
                    if stage=='write':await anext(iterator)
                    else:
                        await anext(iterator);await anext(iterator)
            await wrapper.aclose();row=capture.verify(run)['exchanges'][0]
            self.assertEqual(row['response_end'],'error')
            raw=(run/'raw-mcp'/row['response_ref']['path']).read_bytes()
            self.assertEqual(raw,b'prefix' if stage=='write' else b'prefixtail')
            self.assertNotIn(b'DISK_SECRET',(run/'raw-mcp/capture.json').read_bytes())

    async def test_index_fault_no_complete_record_and_close_once(self):
        inner=Transport();wrapper=self.wrapper(inner)
        with patch.object(capture.os,'fsync',side_effect=OSError('index fsync failed')):
            with self.assertRaises(OSError):await wrapper.aclose()
        await wrapper.aclose();self.assertEqual(inner.closes,1)
        # A full byte write with fsync failure is not a complete publication.
        self.assertTrue(wrapper.closed)
        self.assertFalse((self.run/'raw-mcp/capture.json').exists())
        self.assertTrue((self.run/'raw-mcp/capture.pending.json').exists())
        with self.assertRaises(FileNotFoundError):capture.verify(self.run)

    async def test_inner_failure_zero_response_and_pending_request_close(self):
        class Broken(Transport):
            async def handle_async_request(self, request):
                async for _ in request.stream:pass
                raise RuntimeError('REMOTE_SECRET')
        inner=Broken();wrapper=self.wrapper(inner)
        with self.assertRaisesRegex(RuntimeError,'REMOTE_SECRET'):await self.request(wrapper)
        await wrapper.aclose();row=capture.verify(self.run)['exchanges'][0]
        self.assertIsNone(row['response_status']);self.assertEqual(row['response_end'],'not_started')
        self.assertNotIn(b'REMOTE_SECRET',(self.run/'raw-mcp/capture.json').read_bytes())
        class Pending(Transport):
            async def handle_async_request(self,request):
                self.entered.set();await asyncio.Event().wait()
        run=self.root/str(uuid.uuid4());run.mkdir();inner=Pending();inner.entered=asyncio.Event()
        wrapper=capture.CaptureTransport(inner,run,str(uuid.uuid4()))
        task=asyncio.create_task(self.request(wrapper));await inner.entered.wait()
        await asyncio.wait_for(wrapper.aclose(),2)
        with self.assertRaises(capture.CaptureError):await task
        self.assertEqual(capture.verify(run)['exchanges'][0]['request_end'],'not_started')

    async def test_validator_negative_matrix(self):
        wrapper=self.wrapper(Transport([b'body']));response,_=await self.request(wrapper)
        _=[p async for p in response.stream];await wrapper.aclose()
        path=self.run/'raw-mcp/capture.json';raw=path.read_bytes();value=json.loads(raw)
        edits=[('extra',lambda v:v.update(extra=1)),
               ('sequence',lambda v:v['exchanges'][0].update(sequence=True)),
               ('exchange extra',lambda v:v['exchanges'][0].update(extra=1)),
               ('status',lambda v:v['exchanges'][0].update(response_status=True)),
               ('headers',lambda v:v['exchanges'][0].update(response_content_type=None)),
               ('end',lambda v:v['exchanges'][0].update(response_end='complete')),
               ('missing ref',lambda v:v['exchanges'][0].update(response_ref=None)),
               ('path escape',lambda v:v['exchanges'][0]['response_ref'].update(path='../secret')),
               ('duplicate ref',lambda v:v['exchanges'][0].update(response_ref=v['exchanges'][0]['request_ref'])),
               ('size bool',lambda v:v['exchanges'][0]['response_ref'].update(size=True)),
               ('hash',lambda v:v['exchanges'][0]['response_ref'].update(sha256='0'*64)),
               ('run',lambda v:v.update(run_id='not-uuid')),
               ('unstarted',lambda v:v['exchanges'][0].update(response_end='not_started'))]
        for label,edit in edits:
            with self.subTest(label=label):
                v=copy.deepcopy(value);edit(v);path.write_bytes(capture.canonical(v))
                with self.assertRaises(capture.CaptureError):capture.verify(self.run,self.run_id)
        path.write_bytes(raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1'))
        with self.assertRaises(capture.CaptureError):capture.verify(self.run)
        path.write_bytes(raw);body=self.run/'raw-mcp'/value['exchanges'][0]['response_ref']['path'];original=body.read_bytes()
        body.unlink()
        with self.assertRaises(FileNotFoundError):capture.verify(self.run)
        body.write_bytes(original+b'changed')
        with self.assertRaises(capture.CaptureError):capture.verify(self.run)
        body.write_bytes(original);extra=self.run/'raw-mcp/extra.bin';extra.write_bytes(b'x')
        with self.assertRaises(capture.CaptureError):capture.verify(self.run)
        extra.unlink();body.unlink();body.symlink_to(self.root/'missing')
        with self.assertRaises((OSError,capture.CaptureError)):capture.verify(self.run)

    async def test_directory_and_exclusive_safety(self):
        wrapper=self.wrapper(Transport());await wrapper.aclose()
        with self.assertRaises(FileExistsError):self.wrapper(Transport())
        link=self.root/'linked';link.symlink_to(self.run,target_is_directory=True)
        with self.assertRaises(capture.CaptureError):capture.CaptureTransport(Transport(),link,str(uuid.uuid4()))
        with self.assertRaises(capture.CaptureError):capture.verify(link)
        with self.assertRaises(capture.CaptureError):capture.CaptureTransport(Transport(),self.root,True)

    async def test_read_fault_with_fsync_fault_preserves_primary_error(self):
        inner=Transport([b'prefix'],error=RuntimeError('PRIMARY_REMOTE_SECRET'))
        wrapper=self.wrapper(inner);response,_=await self.request(wrapper)
        iterator=response.stream.__aiter__();await anext(iterator)
        with patch.object(capture.os,'fsync',side_effect=OSError('DISK_SECRET')):
            with self.assertRaisesRegex(RuntimeError,'PRIMARY_REMOTE_SECRET') as caught:
                await anext(iterator)
        self.assertIsInstance(caught.exception.__cause__,OSError)
        await wrapper.aclose();value=capture.verify(self.run)
        self.assertEqual(value['status'],'FAILED')
        self.assertEqual(value['exchanges'][0]['response_end'],'error')
        raw=(self.run/'raw-mcp/capture.json').read_bytes()
        self.assertNotIn(b'PRIMARY_REMOTE_SECRET',raw);self.assertNotIn(b'DISK_SECRET',raw)

    async def test_body_open_fault_and_inner_close_fault_are_exposed(self):
        inner=Transport([b'x']);wrapper=self.wrapper(inner);response,_=await self.request(wrapper)
        original=wrapper.directory.open
        def opened(name,flags):
            if name.endswith('-response.bin'):raise OSError('OPEN_SECRET')
            return original(name,flags)
        with patch.object(wrapper.directory,'open',side_effect=opened):
            with self.assertRaises(OSError):_=[p async for p in response.stream]
        await wrapper.aclose();value=capture.verify(self.run)
        self.assertEqual(value['status'],'FAILED');row=value['exchanges'][0]
        self.assertEqual(row['response_end'],'error');self.assertIsNone(row['response_ref'])
        class BrokenClose(Transport):
            async def aclose(self):
                self.closes+=1;raise RuntimeError('CLOSE_SECRET')
        run=self.root/str(uuid.uuid4());run.mkdir();inner=BrokenClose()
        wrapper=capture.CaptureTransport(inner,run,str(uuid.uuid4()))
        with self.assertRaises(RuntimeError):await wrapper.aclose()
        await wrapper.aclose();self.assertEqual(inner.closes,1)
        self.assertEqual(capture.verify(run)['status'],'FAILED')

    async def test_remote_read_error_does_not_block_original_sdk_retry(self):
        inner=Transport([b'prefix'],error=RuntimeError('remote failed'));wrapper=self.wrapper(inner)
        response,_=await self.request(wrapper)
        with self.assertRaises(RuntimeError):_=[p async for p in response.stream]
        inner.error=None;response,_=await self.request(wrapper)
        self.assertEqual([p async for p in response.stream],[b'prefix'])
        await wrapper.aclose();value=capture.verify(self.run)
        self.assertEqual(len(value['exchanges']),2)
        self.assertEqual([r['response_end'] for r in value['exchanges']],['error','eof'])
        self.assertEqual(value['status'],'RECORDED')

    async def test_partial_disk_write_is_preserved_and_new_requests_are_blocked(self):
        inner=Transport([b'prefix',b'TAIL']);wrapper=self.wrapper(inner)
        response,_=await self.request(wrapper);iterator=response.stream.__aiter__();await anext(iterator)
        real_write=os.write;calls=0
        def partial(fd,data):
            nonlocal calls
            calls+=1
            if calls==1:return real_write(fd,data[:2])
            raise OSError('partial disk fault')
        with patch.object(capture.os,'write',side_effect=partial):
            with self.assertRaises(OSError):await anext(iterator)
        self.assertEqual(len(inner.requests),1)
        with self.assertRaises(capture.CaptureError):await self.request(wrapper)
        self.assertEqual(len(inner.requests),1)
        await wrapper.aclose();value=capture.verify(self.run)
        self.assertEqual(value['status'],'FAILED')
        self.assertEqual(self.original(value['exchanges'][0]['response_ref']),b'prefixTA')

    async def test_index_publication_never_overwrites_existing_original(self):
        inner=Transport();wrapper=self.wrapper(inner)
        path=self.run/'raw-mcp/capture.json';path.write_bytes(b'protected-existing')
        with self.assertRaises(FileExistsError):await wrapper.aclose()
        await wrapper.aclose()
        self.assertEqual(path.read_bytes(),b'protected-existing')
        self.assertTrue((path.parent/'capture.pending.json').exists())
        self.assertEqual(inner.closes,1)

    async def test_httpx_owned_redirect_replays_original_request_without_capture_replay(self):
        class Redirect(Transport):
            async def handle_async_request(self,request):
                self.requests.append((request.method,[p async for p in request.stream]))
                if len(self.requests)==1:
                    return httpx2.Response(307,headers={'location':'/final'},stream=Stream([]))
                return httpx2.Response(200,stream=Stream([b'ok']))
        inner=Redirect();wrapper=self.wrapper(inner);source=Stream([b'body',b'-tail'])
        async with httpx2.AsyncClient(transport=wrapper,follow_redirects=True,trust_env=False) as client:
            response=await client.send(httpx2.Request('POST','http://model.invalid/first',stream=source))
            self.assertEqual(response.content,b'ok')
        self.assertEqual(inner.requests,[('POST',[b'body',b'-tail'])]*2)
        self.assertEqual(source.closes,1)
        rows=capture.verify(self.run)['exchanges'];self.assertEqual(len(rows),2)
        self.assertEqual([self.original(r['request_ref']) for r in rows],[b'body-tail']*2)

    async def test_same_request_object_restored_for_owner_reuse(self):
        inner=Transport([b'answer']);wrapper=self.wrapper(inner);source=Stream([b'original'])
        request=httpx2.Request('POST','http://model.invalid/mcp',stream=source)
        for _ in range(2):
            response=await wrapper.handle_async_request(request)
            self.assertIs(request.stream,source)
            self.assertEqual([p async for p in response.stream],[b'answer'])
        self.assertEqual(source.closes,0)
        await wrapper.aclose();self.assertEqual(source.closes,1)
        self.assertEqual(len(capture.verify(self.run)['exchanges']),2)


class LocalSDK(unittest.IsolatedAsyncioTestCase):
    async def test_official_sdk_wrapped_matches_unwrapped_and_real_gzip_bytes(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from mcp.server import MCPServer
        from mcp.types import CallToolResult, TextContent
        import uvicorn

        server_app=MCPServer('body-originals-local')
        @server_app.tool()
        async def body_success() -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='真实 UTF8 中')],
                                  structured_content={'answer':'真实 UTF8 中'},is_error=False)
        @server_app.tool()
        async def body_error() -> CallToolResult:
            return CallToolResult(content=[TextContent(type='text',text='local failure')],is_error=True)
        underlying=server_app.streamable_http_app(json_response=True);oracle=[]
        async def app(scope, receive, send):
            if scope['type']!='http':
                await underlying(scope,receive,send);return
            # Independent server-side oracle: receive bytes and transmitted bytes.
            # It does not collect authorization or arbitrary request headers.
            marker=dict(scope['headers']).get(b'x-test-marker',b'unknown').decode()
            row={'marker':marker,'method':scope['method'],'request':bytearray(),
                 'response':bytearray(),'status':None}
            oracle.append(row);compress=False;compressor=None
            import zlib
            async def recv():
                message=await receive()
                if message['type']=='http.request':row['request'].extend(message.get('body',b''))
                return message
            async def transmit(message):
                nonlocal compress,compressor
                message=dict(message)
                if message['type']=='http.response.start':
                    row['status']=message['status']
                    # Actual HTTP gzip on the SDK's POST response, not a tee mock.
                    compress=scope['method']=='POST' and message['status']==200
                    if compress:
                        compressor=zlib.compressobj(wbits=31)
                        message['headers']=[(k,v) for k,v in message.get('headers',[]) if k.lower()!=b'content-length']
                        message['headers'].append((b'content-encoding',b'gzip'))
                elif message['type']=='http.response.body':
                    body=message.get('body',b'')
                    if compress:
                        body=compressor.compress(body)+compressor.flush(
                            zlib.Z_SYNC_FLUSH if message.get('more_body',False) else zlib.Z_FINISH)
                        message['body']=body
                    row['response'].extend(body)
                await send(message)
            await underlying(scope,recv,transmit)

        sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
        self.assertNotEqual(port,28790)
        server=uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False))
        task=asyncio.create_task(server.serve(sockets=[sock]))
        evidence=os.environ.get('P06_BODY_SDK_EVIDENCE')
        temporary=None
        if evidence:
            root=Path(evidence);root.mkdir()
        else:
            temporary=tempfile.TemporaryDirectory(dir=temp_root());root=Path(temporary.name)
        run_id=str(uuid.uuid4());run=root/run_id;run.mkdir()
        wrapper=None
        try:
            for _ in range(200):
                if server.started:break
                if task.done():await task
                await asyncio.sleep(.01)
            self.assertTrue(server.started)
            results={}
            for marker in ('baseline','wrapped'):
                transport=httpx2.AsyncHTTPTransport()
                if marker=='wrapped':
                    wrapper=capture.CaptureTransport(transport,run,run_id);transport=wrapper
                async with httpx2.AsyncClient(transport=transport,trust_env=False,
                        headers={'x-test-marker':marker,'authorization':'FIXED_TEST_AUTH_SECRET'}) as client:
                    async with streamable_http_client(f'http://127.0.0.1:{port}/mcp',http_client=client) as (read,write):
                        async with ClientSession(read,write) as session:
                            values=[await session.initialize(),await session.list_tools(),
                                    await session.call_tool('body_success',{}),await session.call_tool('body_error',{})]
                            results[marker]=[v.model_dump(mode='json',by_alias=True,exclude_none=True) for v in values]
            self.assertEqual(results['wrapped'],results['baseline'])
            self.assertEqual([v['isError'] for v in results['wrapped'][-2:]],[False,True])
            value=capture.verify(run,run_id)
            self.assertEqual(value['status'],'RECORDED')
            expected=[r for r in oracle if r['marker']=='wrapped']
            self.assertEqual(len(value['exchanges']),len(expected))
            decoded=[];compressed=0
            for row in value['exchanges']:
                request=(run/'raw-mcp'/row['request_ref']['path']).read_bytes() if row['request_ref'] else b''
                response=(run/'raw-mcp'/row['response_ref']['path']).read_bytes() if row['response_ref'] else b''
                candidates=[r for r in expected if r['method']==row['method'] and bytes(r['request'])==request
                            and r['status']==row['response_status'] and bytes(r['response']).startswith(response)]
                self.assertTrue(candidates,(row['sequence'],row['method']))
                if row['response_end']=='eof':self.assertTrue(any(bytes(r['response'])==response for r in candidates))
                expected.remove(candidates[0])
                if row['response_content_encoding']=='gzip':
                    compressed+=1;decoded.append(json.loads(gzip.decompress(response)))
            self.assertGreaterEqual(compressed,4)
            self.assertEqual([type(v).model_validate(r['result']).model_dump(
                mode='json',by_alias=True,exclude_none=True) for v,r in zip(values,decoded)],results['wrapped'])
            index=(run/'raw-mcp/capture.json').read_bytes()
            self.assertNotIn(b'FIXED_TEST_AUTH_SECRET',index)
            baseline_posts=[bytes(r['request']) for r in oracle if r['marker']=='baseline' and r['method']=='POST']
            wrapped_posts=[bytes(r['request']) for r in oracle if r['marker']=='wrapped' and r['method']=='POST']
            self.assertEqual(baseline_posts,wrapped_posts)
            from tests.scenario_runner import _runner_start_time_utc
            start_time = _runner_start_time_utc()
            self.assertIsNotNone(start_time)
            identity={'nature':'real official SDK with independent loopback server byte oracle, not Windows',
                      'port':port,'pid':os.getpid(),'run_id':run_id,
                      'process_start_time_utc':start_time,
                      'executable_sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                      'source_sha256':{str(p.relative_to(Path.cwd())):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (Path(capture.__file__),Path(__file__))},
                      'results':results,'capture_ref':{'path':str((run/'raw-mcp/capture.json').relative_to(root)),
                        'size':len(index),'sha256':hashlib.sha256(index).hexdigest()},
                      'server_observed_exchanges':len(oracle),'gzip_responses':compressed}
            (root/'sdk-proof.json').write_bytes(capture.canonical(identity))
            # Oracle body originals are separate test evidence, not the capture API.
            oracle_rows=[]
            for i,row in enumerate(oracle,1):
                item={k:row[k] for k in ('marker','method','status')}
                for direction in ('request','response'):
                    name=f'oracle-{i:08d}-{direction}.bin';raw=bytes(row[direction])
                    with (root/name).open('xb') as out:out.write(raw)
                    item[direction]={'path':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                oracle_rows.append(item)
            (root/'server-oracle.json').write_bytes(capture.canonical(oracle_rows))
        finally:
            server.should_exit=True
            await asyncio.wait_for(task,10)
            sock.close()
            if wrapper is not None:await wrapper.aclose()
            if temporary:temporary.cleanup()
        self.assertTrue(task.done())

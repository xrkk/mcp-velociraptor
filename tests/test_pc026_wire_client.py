"""Client uncertain-outcome and actual HTTP stream-budget seams."""
import asyncio
import base64
import hashlib
import time
import unittest
from unittest.mock import patch
import httpx2
from velo_transfer import wire
from velo_transfer.adapters import AdapterError, TransportAdapter, _DirectChunkChannel
from velo_transfer.http_budget import CountedTransport, HTTPBodyLimitError


class Pieces(httpx2.AsyncByteStream):
    def __init__(self, *parts):self.parts=parts;self.closed=False;self.seen=0
    async def __aiter__(self):
        try:
            for part in self.parts:self.seen+=1;yield part
        finally:
            self.closed=True
    async def aclose(self):self.closed=True


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self,response):
        calls=[]
        async def handler(request):
            calls.append((str(request.url),request.headers.get('mcp-session-id'),await request.aread()))
            return response
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler),trust_env=False) as http:
            adapter=TransportAdapter(None,'velo','http://fixture/mcp',time.monotonic()+10,3,['instance'])
            adapter._direct=_DirectChunkChannel(http,adapter.endpoint,'sdk-established-session','instance',adapter.deadline_monotonic,3)
            args={'transfer_id':'trial','request_digest':'a'*64,'offset':0,'chunks':[{'count':3,
                'data_base64':base64.b64encode(b'abc').decode(),'chunk_sha256':hashlib.sha256(b'abc').hexdigest()}]}
            try:return await adapter.call('transfer_chunks',args),calls
            except AdapterError as exc:return exc,calls

    def response(self,body,status=200,instance='instance',kind='application/octet-stream'):
        return httpx2.Response(status,headers={'x-mcp-server-instance':instance,'content-type':kind},content=body)

    async def test_non200_exact_codes_and_no_replay(self):
        for status,code in [(400,'session_required'),(400,'invalid_frame'),*wire.HTTP_ERRORS.items()]:
            response=self.response(('{"error":{"code":"'+code+'"}}').encode(),status,kind='application/json')
            error,calls=await self.invoke(response)
            self.assertEqual(error.code,code);self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][1],'sdk-established-session')
            self.assertTrue(error.may_have_committed);self.assertFalse(error.retryable)

    async def test_malformed200_changed_instance_and_interrupted_response_unknown_no_fallback(self):
        for response,code in [(self.response(b'VBT1\x00'), 'malformed_response'),
            (self.response(b'ignored',instance='new-instance'),'instance_changed'),
            (self.response(b'{"error":{"code":"unlisted"}}',400,kind='application/json'),'protocol_error')]:
            error,calls=await self.invoke(response)
            self.assertEqual(error.code,code);self.assertTrue(error.may_have_committed)
            self.assertFalse(error.retryable);self.assertEqual(len(calls),1)

    async def test_interrupted_stream_is_unknown_without_json_replay(self):
        class Interrupted(Pieces):
            async def __aiter__(self):
                try:
                    yield b'VBT1'
                    raise httpx2.ReadError('labelled interrupted response')
                finally:self.closed=True
        stream=Interrupted()
        response=httpx2.Response(200,headers={'x-mcp-server-instance':'instance',
            'content-type':'application/octet-stream'},stream=stream)
        error,calls=await self.invoke(response)
        self.assertEqual(error.code,'outcome_unknown');self.assertTrue(error.may_have_committed)
        self.assertFalse(error.retryable);self.assertEqual(len(calls),1);self.assertTrue(stream.closed)

    async def test_hash_byte_and_accepted_binding(self):
        body=wire.encode({'status':'success','result':{'verified_offset':4,'accepted':1}},b'','push_response')
        error,calls=await self.invoke(self.response(body));self.assertEqual(error.code,'malformed_response');self.assertEqual(len(calls),1)
        body=wire.encode({'status':'success','result':{'verified_offset':3,'accepted':1}},b'','push_response')
        result,calls=await self.invoke(self.response(body));self.assertEqual(result['verified_offset'],3)

    async def test_actual_response_stream_limit_and_close(self):
        stream=Pieces(b'123456',b'78901')
        async def handler(request):return httpx2.Response(200,stream=stream)
        async with httpx2.AsyncClient(transport=CountedTransport(httpx2.MockTransport(handler),limit=10)) as http:
            with self.assertRaises(HTTPBodyLimitError) as raised:
                await http.get('http://fixture/')
            self.assertEqual(str(raised.exception),'response_too_large')
            self.assertTrue(stream.closed)

    async def test_actual_request_stream_limit_before_transport_and_fake_length(self):
        stream=Pieces(b'123456',b'78901',b'never-forward')
        captured=[]
        class Reader(httpx2.AsyncBaseTransport):
            async def handle_async_request(self,request):
                async for part in request.stream:captured.append(part)
                return httpx2.Response(200,content=b'ok')
        async with httpx2.AsyncClient(transport=CountedTransport(Reader(),limit=10)) as http:
            with self.assertRaises(HTTPBodyLimitError) as raised:
                await http.post('http://fixture/',content=stream,headers={'Content-Length':'1'})
            self.assertEqual(str(raised.exception),'request_too_large')
            self.assertEqual(captured,[b'123456']);self.assertEqual(stream.seen,2);self.assertTrue(stream.closed)

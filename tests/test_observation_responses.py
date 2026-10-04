"""Actual official SDK backchannel response correlation; archive I/O MODEL."""
import asyncio
import json
import time
import unittest

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context
from tests import test_observation_controller as chain


class ResponseChain(unittest.IsolatedAsyncioTestCase):
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    asyncTearDown=chain.ChainTests.asyncTearDown

    async def asyncSetUp(self):
        def configure(server):
            @server.tool()
            async def ask_peer(ctx:Context)->str:
                await ctx.session._connection.send_raw_request('ping',{}, {'request_id':7})
                return 'peer-returned'
        self.configure_server=configure
        await chain.ChainTests.asyncSetUp(self)

    async def test_actual_sdk_response_only_waiter_owns_real_typed_id_and_close_streams(self):
        async with streamable_http_client(self.url,http_client=self.http) as (read,write):
            async with ClientSession(read,write) as sdk:
                await sdk.initialize()
                result=await sdk.call_tool('ask_peer',{})
                self.assertFalse(result.is_error,result)
        responses=[r for r in self.controller._work.values() if r.response_pending is not None]
        self.assertEqual(len(responses),1)
        row=responses[0]
        self.assertEqual(row.message['id'],7);self.assertIs(type(row.message['id']),int)
        self.assertTrue(row.started and row.handler_exited and row.http_exited)
        self.assertIsNone(row.scope);self.assertIsNone(row.journal)
        issued=row.response_pending
        self.assertIs(issued['reply'],row)
        self.assertTrue(issued['pending'].send.closed and issued['pending'].receive.closed)
        self.assertEqual([r['record_type'] for r in self.records()],
            ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END'])
        self.assertFalse(self.ledger._active)

    async def test_unsolicited_response_rejects_before_ticket_writer_or_sdk_resolution(self):
        await self.initialize()
        before=self.records();count=len(self.controller._work)
        for rid in (7,'7','007'):
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=rid,result={}))
            self.assertEqual(response.status_code,400,response.text)
            self.assertIn('response_not_pending',response.text)
        self.assertEqual(self.records(),before)
        self.assertEqual(len(self.controller._work),count)
        self.assertEqual(self.controller._state,'ACTIVE')

    async def test_real_pending_wrong_typed_alias_and_duplicate_reject_zero_resolution(self):
        session=await self.initialize()
        # Actual open GET channel delivers the server's request while raw HTTP
        # keeps exact ids. Never install a synthetic pending entry.
        got=asyncio.Event();finish=asyncio.Event()
        async def reader():
            async with self.http.stream('GET',self.url) as response:
                self.assertEqual(response.status_code,200)
                async for line in response.aiter_lines():
                    if line.startswith('data: '):
                        message=json.loads(line[6:])
                        if message.get('method')=='ping':
                            self.assertEqual(message['id'],7);got.set()
                            await finish.wait();return
        get=asyncio.create_task(reader())
        task=asyncio.create_task(self.http.post(self.url,json=dict(jsonrpc='2.0',id=11,
            method='tools/call',params=dict(name='ask_peer',arguments={}))))
        try:
            await asyncio.wait_for(got.wait(),3)
            for rid in ('7','007'):
                response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=rid,result={}))
                self.assertEqual(response.status_code,400,response.text)
                self.assertFalse(task.done())
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=7,result={}))
            self.assertEqual(response.status_code,202,response.text)
            self.assertEqual((await task).status_code,200)
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=7,result={}))
            self.assertEqual(response.status_code,400,response.text)
            self.assertIn('response_not_pending',response.text)
            self.assertEqual(len([r for r in self.controller._work.values() if r.response_pending]),1)
        finally:
            finish.set()
            if not get.done():get.cancel()
            await asyncio.gather(get,return_exceptions=True)
            if not task.done():task.cancel()
            await asyncio.gather(task,return_exceptions=True)

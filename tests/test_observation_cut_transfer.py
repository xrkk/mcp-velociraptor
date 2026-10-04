"""Real benign transfer child/binary and actual MODEL cut, never DFIR/native qualification."""
import asyncio
import json
import os
import tempfile
import time
import unittest

from tests import test_observation_transfer_children as child
from tests.observation_model_export import ModelExporter
from velo_transfer.guest_worker import same_process


@unittest.skipUnless(os.name=='posix','real fork host coverage')
class TransferCut(unittest.IsolatedAsyncioTestCase):
    records=child.TransferChildren.records
    initialize=child.TransferChildren.initialize
    tool=child.TransferChildren.tool
    latch=child.TransferChildren.latch
    settled=child.TransferChildren.settled
    binary_headers=child.TransferChildren.binary_headers

    async def asyncSetUp(self):
        await child.TransferChildren.asyncSetUp(self)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.exporter=ModelExporter(self.directory.name,self.config,self.controller._limits)
        self.controller._exporter=self.exporter

    async def asyncTearDown(self):
        for row in self.controller._close_io.values():
            if row.task is not None:await row.task
            self.assertFalse(row.thread.is_alive())
        await child.TransferChildren.asyncTearDown(self)

    async def test_real_child_native_wait_and_binary_tail_are_in_final_cut_proof(self):
        from velo_transfer import wire
        session=await self.initialize();writer=self.latch()
        await self.tool(1,'transfer_begin',dict(request=self.request))
        row=next(iter(self.controller._children.values()))
        closing=asyncio.create_task(self.http.delete(self.url))
        try:
            until=time.monotonic()+2
            while self.controller._sessions[session]['state']=='OPEN' and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertFalse(closing.done());self.assertTrue(same_process(row.pid,row.birth))
            self.assertFalse(list(self.exporter.root.rglob('cut.json')))
            os.write(writer,b'X')
            response=await closing;self.assertEqual(response.status_code,200,response.text)
            proof=json.loads(self.exporter.files['lifecycle.json'])
            worker=proof['sdk_work']['transfer_workers'][0]
            self.assertEqual(worker['pid'],row.pid);self.assertEqual(worker['birth'],row.birth)
            self.assertTrue(row.resources_closed and row.native_resources_closed and row.wait_status is not None)
            self.assertTrue(worker['process_exited'] and worker['resources_closed'])
        finally:
            if not closing.done():os.write(writer,b'X');await closing

    async def test_actual_binary_sha_and_true_retained_thread_are_exported_without_08_parent(self):
        from velo_transfer import wire
        import hashlib
        session=await self.initialize()
        await self.tool(1,'transfer_begin',dict(request=self.request));await self.settled()
        body=wire.encode({},b'','pull_request')
        response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),headers=self.binary_headers(),content=body)
        self.assertEqual(response.status_code,200,response.text)
        response=await self.http.delete(self.url);self.assertEqual(response.status_code,200,response.text)
        proof=json.loads(self.exporter.files['lifecycle.json'])
        self.assertEqual(proof['attempt_sequences'],[1])
        self.assertEqual(len(proof['binary_work']),1)
        binary=proof['binary_work'][0]
        self.assertEqual(binary['request_sha256'],hashlib.sha256(body).hexdigest())
        self.assertTrue(binary['thread_exited'] and binary['resources_closed'])
        self.assertTrue(self.controller._sessions[session]['threads']._quiescent())

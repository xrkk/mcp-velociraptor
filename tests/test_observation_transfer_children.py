"""Actual host SDK/fork/guard/lease; Windows/archive authority stays MODEL."""
import asyncio
import json
import os
import time
import unittest
from unittest.mock import patch

from tests import test_observation_controller as chain
from tests import test_transfer_guest as guest_fixture
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.guest_worker import RootLease, same_process
from velo_transfer.mcp_tools import register_transfer_tools
from velociraptor_observation_controller import ControllerError


TRACES=[]


@unittest.skipUnless(os.name=='posix','real fork coverage; Windows Popen is separate')
class TransferChildren(unittest.IsolatedAsyncioTestCase):
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize

    async def asyncSetUp(self):
        self.guest=guest_fixture.GuestTests();self.guest.setUp();self.addCleanup(self.guest.doCleanups)
        document=json.loads(self.guest.policy.read_text())
        document['limits']['max_batch_chunks']=4
        self.guest.policy.write_text(json.dumps(document))
        self.guest.service=GuestTransferService(self.guest.policy,
            _observation=self.guest.observation,_acl_verifier=lambda p,k:True)
        self.addCleanup(self.guest.service.shutdown)
        def configure(server):
            self.binary_service=register_transfer_tools(server,factory=lambda:self.guest.service)
        self.configure_server=configure
        self.guest.read.joinpath('benign').write_bytes(b'benign local transfer')
        self.request=self.guest.request('pull',[dict(absolute_path=str(self.guest.read/'benign'),relative_path='benign')],self.guest.host/'out')
        self.args=dict(transfer_id=self.request['transfer_id'],request_digest=self.request['request_digest'])
        self.latches=[]
        await chain.ChainTests.asyncSetUp(self)
        self.controller._limits['max_sdk_work']=128

    async def asyncTearDown(self):
        for reader,writer in self.latches:
            try:os.write(writer,b'X')
            except OSError:pass
        # Actual native joins precede fixture shutdown/root deletion.
        until=time.monotonic()+5
        while time.monotonic()<until:
            children=list(self.controller._children.values())
            for row in children:row._poll()
            if all(r.wait_status is not None or r.no_spawn for r in children):break
            await asyncio.sleep(.005)
        self.assertTrue(all(r.wait_status is not None or r.no_spawn for r in self.controller._children.values()))
        for reader,writer in self.latches:
            os.close(reader);os.close(writer)
        await chain.ChainTests.asyncTearDown(self)
        TRACES.append(dict(test=self.id(),children=[dict(sequence=r.sequence,session=r.session,
            transfer_id=r.transfer_id,digest=r.digest,nonce=r.nonce,job=r.job,pid=r.pid,
            birth=r.birth,wait_status=r.wait_status,no_spawn=r.no_spawn,
            native_resources_closed=r.native_resources_closed,resources_closed=r.resources_closed,
            error=None if r.error is None else type(r.error).__name__) for r in self.controller._children.values()],
            binary=[dict(sequence=r.sequence,session=r.session,request_sha256=r.request_sha256,
                handler_exited=r.handler_exited,http_exited=r.http_exited,outcome=r.outcome)
                for r in self.controller._work.values() if r.request_sha256 is not None],
            sessions={key:value['state'] for key,value in self.controller._sessions.items()},
            test_server_joined=not self.thread.is_alive()))

    async def tool(self,number,name,args):
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=number,
            method='tools/call',params=dict(name=name,arguments=args)))
        self.assertEqual(response.status_code,200,response.text)
        # SDK default JSON result is one SSE message, preserve real parsing.
        raw=next(line[6:] for line in response.text.splitlines() if line.startswith('data: '))
        result=json.loads(raw)['result']
        self.assertFalse(result.get('isError',False),result)
        envelope=result['structuredContent']
        self.assertEqual(envelope['status'],'success',envelope)
        return envelope['result']

    def latch(self):
        reader,writer=os.pipe();self.latches.append((reader,writer))
        execute=self.guest.service._execute
        def held(*args):
            from velociraptor_observation import _current
            from velociraptor_observation_workers import _CURRENT_OWNER
            if _current.get() is not None or _CURRENT_OWNER.get() is not None:os._exit(125)
            os.read(reader,1)
            return execute(*args)
        self.guest.service._execute=held
        return writer

    async def settled(self):
        until=time.monotonic()+5
        while time.monotonic()<until:
            if all(row._poll() for row in self.controller._children.values()):return
            await asyncio.sleep(.005)
        self.fail('real child cleanup did not close')

    async def test_seven_actual_sdk_transfer_tools_real_children_and_readback_end(self):
        session=await self.initialize()
        caps=await self.tool(1,'transfer_capabilities',{})
        self.assertTrue(caps)
        fork=os.fork
        def checked_fork():
            rows=list(self.controller._children.values())
            self.assertTrue(rows)
            self.assertIsNone(rows[-1].pid)
            self.assertEqual(rows[-1].session,session)
            return fork()
        with patch('velo_transfer.guest_service.os.fork',side_effect=checked_fork):
            await self.tool(2,'transfer_begin',dict(request=self.request))
        await self.settled()
        status=await self.tool(3,'transfer_status',self.args)
        self.assertEqual(status['local_phase'],'SOURCE_READY')
        await self.tool(4,'transfer_chunk',dict(self.args,offset=0,count=status['package']['size']))
        await self.tool(5,'transfer_chunks',dict(self.args,offset=0,count_per_chunk=128,chunk_count=1))
        await self.tool(6,'transfer_finish',dict(self.args,action='prepare'))
        await self.settled()
        await self.tool(7,'transfer_abort',self.args)
        rows=self.records()
        self.assertEqual([r['record_type'] for r in rows].count('ATTEMPT_BEGIN'),7)
        self.assertEqual([r['record_type'] for r in rows].count('ACCEPT_ACK'),7)
        self.assertEqual([r['record_type'] for r in rows].count('ATTEMPT_END'),7)
        self.assertEqual({r['payload']['tool'] for r in rows if r['record_type']=='ATTEMPT_BEGIN'},
            {'transfer_capabilities','transfer_begin','transfer_status','transfer_chunk','transfer_chunks','transfer_finish','transfer_abort'})
        children=list(self.controller._children.values())
        self.assertEqual([r.job for r in children],['package','prepare'])
        self.assertTrue(all(r.resources_closed and r.wait_status is not None and r.error is None for r in children))
        self.assertEqual(self.controller._state,'ACTIVE')
        self.assertEqual(self.controller._sequence_records[min(self.controller._sequence_records)][0],session)

    async def test_other_session_delete_never_kills_live_child_or_waits_foreign_owner(self):
        first=await self.initialize()
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        second=await self.initialize()
        self.http.headers['mcp-session-id']=first
        writer=self.latch()
        await self.tool(1,'transfer_begin',dict(request=self.request))
        child=next(iter(self.controller._children.values()))
        self.assertEqual(child.session,first)
        self.assertTrue(same_process(child.pid,child.birth))
        self.assertEqual(self.records()[-1]['record_type'],'ATTEMPT_END')
        response=await self.http.delete(self.url,headers={'mcp-session-id':second})
        self.assertEqual(response.status_code,503,response.text)
        self.assertIn('cut_unavailable',response.text)
        self.assertTrue(same_process(child.pid,child.birth))
        self.assertIsNone(child.wait_status)
        os.write(writer,b'X');await self.settled()
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503,response.text)
        self.assertIn('cut_unavailable',response.text)
        self.assertNotIn('x-velo-observation-close',response.headers)

    async def test_timeout_retains_actual_child_guard_and_rootlease_until_exit(self):
        session=await self.initialize();writer=self.latch()
        await self.tool(1,'transfer_begin',dict(request=self.request))
        child=next(iter(self.controller._children.values()))
        # Lease acquisition occurs before execution/latch; wait for true lease.
        busy=False;until=time.monotonic()+2
        while time.monotonic()<until:
            probe=RootLease(self.guest.work)
            try:probe.acquire()
            except Exception:busy=True;break
            else:probe.release();await asyncio.sleep(.005)
        self.assertTrue(busy)
        self.controller._limits['close_timeout_ns']=30000000
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503,response.text)
        self.assertIn('close_unknown',response.text)
        self.assertTrue(same_process(child.pid,child.birth))
        self.assertFalse(child.resources_closed);self.assertIsNone(child.wait_status)
        self.assertEqual(self.controller._sessions[session]['state'],'UNKNOWN')
        os.write(writer,b'X');await self.settled()
        self.assertEqual(self.controller._sessions[session]['state'],'UNKNOWN')

    async def test_registration_budget_denies_before_real_fork_zero_child(self):
        await self.initialize()
        # Exhaust permanent sequence only after actual HTTP and handler owner.
        self.controller._limits['max_sdk_work']=self.controller._sequence+3
        with patch('velo_transfer.guest_service.os.fork',side_effect=AssertionError('must not spawn')) as fork:
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=1,method='tools/call',
                params=dict(name='transfer_begin',arguments=dict(request=self.request))))
        self.assertEqual(response.status_code,200,response.text)
        self.assertIn('internal_error',response.text)
        fork.assert_not_called()
        self.assertFalse(self.controller._children)
        self.assertFalse(self.guest.service._owned)
        self.assertEqual(self.controller._state,'DRAINING')

    async def test_native_wait_without_cleanup_receipt_is_sticky_unknown(self):
        session=await self.initialize()
        original=self.guest.service._child
        def no_receipt(*args,_report_fd=None):
            try:original(*args,_report_fd=None)
            finally:
                if _report_fd is not None:os.close(_report_fd)
        self.guest.service._child=no_receipt
        await self.tool(1,'transfer_begin',dict(request=self.request))
        child=next(iter(self.controller._children.values()))
        until=time.monotonic()+3
        while child.wait_status is None and time.monotonic()<until:
            child._poll();await asyncio.sleep(.005)
        self.assertIsNotNone(child.wait_status)
        self.assertTrue(child.native_resources_closed)
        self.assertFalse(child.resources_closed)
        self.assertEqual(child.error.code,'child_cleanup_unconfirmed')
        self.assertEqual(self.controller._sessions[session]['state'],'UNKNOWN')
        before=self.ledger._attempt_count
        response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503,response.text)
        self.assertNotIn('x-velo-observation-close',response.headers)
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=2,method='tools/list'))
        self.assertEqual(response.status_code,503,response.text)
        self.assertEqual(self.ledger._attempt_count,before)

    async def test_real_fork_failure_keeps_known_unspawned_permanent_record(self):
        await self.initialize()
        with patch('velo_transfer.guest_service.os.fork',side_effect=OSError('MODEL-before-fork')):
            response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=1,method='tools/call',
                params=dict(name='transfer_begin',arguments=dict(request=self.request))))
        self.assertEqual(response.status_code,200,response.text)
        self.assertIn('internal_error',response.text)
        child=next(iter(self.controller._children.values()))
        self.assertTrue(child.no_spawn and child.resources_closed and child.native_resources_closed)
        self.assertIsNone(child.pid);self.assertFalse(self.guest.service._owned)
        self.assertEqual(self.controller._sequence_records[child.sequence][1],'transfer_child')

    def binary_headers(self):
        return {'content-type':'application/octet-stream','x-mcp-server-instance':self.ledger._instance,
            'x-velo-direction':'pull','x-velo-transfer-id':self.request['transfer_id'],
            'x-velo-request-digest':self.request['request_digest'],'x-velo-offset':'0',
            'x-velo-count-per-chunk':'128','x-velo-chunk-count':'1'}

    async def test_actual_binary_ticket_sha_thread_exit_no_fabricated_attempt(self):
        from velo_transfer import wire
        session=await self.initialize()
        await self.tool(1,'transfer_begin',dict(request=self.request));await self.settled()
        body=wire.encode({},b'','pull_request')
        before=self.ledger._attempt_count
        response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),
            headers=self.binary_headers(),content=body)
        self.assertEqual(response.status_code,200,response.text)
        meta,payload=wire.decode(response.content,'pull_response')
        self.assertEqual(meta['status'],'success');self.assertTrue(payload)
        self.assertEqual(self.ledger._attempt_count,before)
        self.assertEqual(len(self.controller._binary_sequences),1)
        sequence=next(iter(self.controller._binary_sequences))
        row=next(r for r in self.controller._work.values() if r.sequence==sequence)
        import hashlib
        self.assertEqual(row.request_sha256,hashlib.sha256(body).hexdigest())
        self.assertIsNone(row.scope);self.assertIsNone(row.journal)
        self.assertTrue(row.handler_exited and row.http_exited)
        threads=self.controller._sessions[session]['threads']
        owned=[r for r in threads._threads.values() if r.owner is row.worker_owner]
        self.assertEqual(len(owned),1)
        self.assertTrue(owned[0].wrapper_exited and owned[0].joined)
        self.assertFalse(owned[0].thread.is_alive())

    async def test_actual_binary_latched_native_thread_prevents_delete_completion(self):
        from velo_transfer import wire
        session=await self.initialize()
        await self.tool(1,'transfer_begin',dict(request=self.request));await self.settled()
        invoke=self.binary_service.invoke
        def held(name,**args):
            if name=='transfer_chunks':
                self.started.set();self.release.wait(5)
            return invoke(name,**args)
        self.binary_service.invoke=held
        task=asyncio.create_task(self.http.post(self.url.replace('/mcp/','/chunkbin/'),
            headers=self.binary_headers(),content=wire.encode({},b'','pull_request')))
        try:
            until=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.005)
            self.assertTrue(self.started.is_set())
            self.controller._limits['close_timeout_ns']=30000000
            response=await self.http.delete(self.url)
            self.assertEqual(response.status_code,503,response.text)
            row=next(r for r in self.controller._work.values() if r.request_sha256 is not None)
            self.assertFalse(row.http_exited or row.handler_exited)
            threads=self.controller._sessions[session]['threads']
            self.assertTrue(any(r.owner is row.worker_owner and r.thread.is_alive() and not r.joined for r in threads._threads.values()))
            self.release.set();self.assertEqual((await task).status_code,200)
            self.assertTrue(row.http_exited and row.handler_exited)
            self.assertEqual(self.controller._sessions[session]['state'],'UNKNOWN')
        finally:
            self.release.set()
            if not task.done():await task

    async def test_binary_wrong_instance_incomplete_frame_and_exhaustion_zero_invoke(self):
        from velo_transfer import wire
        await self.initialize()
        headers=self.binary_headers();headers['x-mcp-server-instance']='b'*32
        with patch.object(self.binary_service,'invoke',side_effect=AssertionError('must not invoke')) as invoke:
            response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),headers=headers,
                content=wire.encode({},b'','pull_request'))
            self.assertEqual(response.status_code,400,response.text)
            response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),headers=self.binary_headers(),content=b'VBT1')
            self.assertEqual(response.status_code,400,response.text)
            self.assertFalse(self.controller._binary_sequences)
            self.controller._limits['max_binary_work']=1
            # One real accepted binary worker with a known engine error still
            # consumes its permanent sequence. No request state is fabricated.
        response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),headers=self.binary_headers(),
            content=wire.encode({},b'','pull_request'))
        self.assertEqual(response.status_code,200,response.text)
        with patch.object(self.binary_service,'invoke',side_effect=AssertionError('must not invoke')) as invoke:
            response=await self.http.post(self.url.replace('/mcp/','/chunkbin/'),headers=self.binary_headers(),
                content=wire.encode({},b'','pull_request'))
            self.assertEqual(response.status_code,503,response.text)
            self.assertIn('binary_budget',response.text);invoke.assert_not_called()
        self.assertEqual(len(self.controller._binary_sequences),1)
        self.assertEqual(self.ledger._attempt_count,0)

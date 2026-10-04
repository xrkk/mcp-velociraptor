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
        self.configure_server=lambda server:register_transfer_tools(server,factory=lambda:self.guest.service)
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

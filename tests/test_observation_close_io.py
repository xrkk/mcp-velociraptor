"""Controller-owned real native I/O and shared pending capacity (MODEL ledger)."""
import asyncio
import threading
import time
import unittest
from unittest.mock import patch

from velociraptor_observation_controller import SessionController, ControllerError
from tests import test_observation_attempts as ledger_fixture
from tests import test_observation_controller as chain
from tests.test_observation_startup import model_budgets


class PendingTests(unittest.TestCase):
    def setUp(self):
        self.fixture=ledger_fixture.LedgerModels();self.addCleanup(self.fixture.doCleanups)
        self.ledger,_,_=self.fixture.ledger()
        self.controller=object.__new__(SessionController)
        self.controller._initialize(self.ledger,model_budgets())

    def test_shared_pending_gate_counts_across_sessions_before_sequence_or_begin(self):
        c=self.controller;c._limits['max_sessions']=8;c._limits['max_pending_work']=2
        _,first=c._admit(None,b'a'*32,dict(method='initialize'))
        _,second=c._admit(None,b'b'*32,dict(method='initialize'))
        self.assertEqual(c._pending_count(),2)
        before=c._sequence
        with self.assertRaises(ControllerError) as caught:
            c._admit(None,b'c'*32,dict(method='initialize'))
        self.assertEqual(caught.exception.code,'session_budget')
        self.assertEqual(c._sequence,before)
        self.assertEqual(self.ledger._attempt_count,0)
        first.handler_exited=True;first.pending_creation=False;c._pending-=1
        self.assertEqual(c._pending_count(),1)
        self.assertEqual(len(c._work),2)  # No retired-history eviction.


class CloseIOTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture=ledger_fixture.LedgerModels();self.addCleanup(self.fixture.doCleanups)
        ledger,_,_=self.fixture.ledger()
        self.c=object.__new__(SessionController);self.c._initialize(ledger,model_budgets())
        self.started=threading.Event();self.release=threading.Event()

    async def asyncTearDown(self):
        self.release.set()
        for row in self.c._close_io.values():
            if row.task is not None:await row.task
            if row.thread.ident is not None:row.thread.join(3)
            self.assertFalse(row.thread.is_alive())

    def native(self):
        self.started.set()
        if not self.release.wait(3):raise RuntimeError('test latch not released')
        return b'actual-native-result'

    async def test_timeout_retains_actual_thread_and_join_task_until_exit(self):
        with self.assertRaises(ControllerError) as caught:
            await self.c._owned_close_io('session',self.native,time.monotonic_ns()+20000000)
        self.assertEqual(caught.exception.code,'close_io_timeout')
        row=self.c._close_io['session']
        self.assertTrue(self.started.is_set());self.assertTrue(row.thread.is_alive())
        self.assertFalse(row.joined);self.assertFalse(row.task.done())
        self.release.set();await row.task
        self.assertTrue(row.joined);self.assertTrue(row.wrapper_exited)
        self.assertFalse(row.thread.is_alive());self.assertEqual(row.result,b'actual-native-result')

    async def test_http_waiter_cancellation_does_not_cancel_native_join(self):
        waiter=asyncio.create_task(self.c._owned_close_io('session',self.native,time.monotonic_ns()+3000000000))
        while not self.started.is_set():await asyncio.sleep(.001)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):await waiter
        row=self.c._close_io['session'];self.assertFalse(row.task.done())
        self.assertTrue(row.thread.is_alive())
        self.release.set();await row.task
        self.assertTrue(row.joined);self.assertFalse(row.thread.is_alive())

    async def test_actual_native_primary_preserved_after_true_join(self):
        primary=OSError('native-primary')
        def fail():raise primary
        with self.assertRaises(OSError) as caught:
            await self.c._owned_close_io('session',fail,time.monotonic_ns()+3000000000)
        self.assertIs(caught.exception,primary)
        row=self.c._close_io['session'];self.assertIs(row.error,primary)
        self.assertTrue(row.joined);self.assertFalse(row.thread.is_alive())


class UnclaimedHTTPTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call

    async def test_queued_http_failure_claims_once_and_finishes_real_end_without_business(self):
        await self.initialize()
        primary=OSError('actual-pre-handoff-failure')
        with patch.object(self.controller,'_slot',side_effect=primary):
            response=await self.call(7,'never')
        self.assertEqual(response.status_code,503,response.text)
        self.assertEqual(self.calls,[])
        self.assertFalse(self.ledger._active)
        rows=self.records()
        self.assertEqual([r['record_type'] for r in rows],
            ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END'])
        self.assertEqual(rows[-1]['payload']['outcome'],'cancelled')
        row=next(r for r in self.controller._work.values() if r.message.get('id')==7)
        self.assertIs(row.error,primary);self.assertTrue(row.handler_exited and row.http_exited)
        self.assertEqual(self.controller._state,'UNKNOWN')


class RetainedAccountingTests(PendingTests):
    def test_permanent_owned_message_growth_is_measured_and_denies_before_next_admission(self):
        c=self.controller
        _,row=c._admit(None,b'a'*32,dict(method='initialize',params={}))
        before=c._measure_retained()
        row.message['params']['retained-tail']='z'*65536
        row.handler_exited=True
        after=c._measure_retained()
        self.assertGreater(after-before,65536)
        c._limits['max_retained_state_bytes']=after-1
        with self.assertRaises(ControllerError):c._retained_gate()
        self.assertEqual(c._state,'DRAINING')
        self.assertEqual(len(c._work),1)
        self.assertGreaterEqual(c._retained_measured_peak,after)

class SocketTailTests(UnclaimedHTTPTests):
    # Reuse the real server fixture without repeating inherited test methods.
    test_queued_http_failure_claims_once_and_finishes_real_end_without_business=None

    async def test_actual_socket_disconnect_queued_alias_has_cancelled_end_zero_business(self):
        import json
        from urllib.parse import urlsplit
        session=await self.initialize()
        first=asyncio.create_task(self.call(7,'latch'))
        writer=None
        try:
            deadline=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            url=urlsplit(self.url)
            reader,writer=await asyncio.open_connection(url.hostname,url.port)
            body=json.dumps(dict(jsonrpc='2.0',id='007',method='tools/call',
                params=dict(name='echo',arguments=dict(value='never')))).encode()
            headers=(f'POST /mcp/ HTTP/1.1\r\nHost: {url.netloc}\r\nAuthorization: Bearer MODEL\r\n'
                f'Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n'
                f'Mcp-Session-Id: {session}\r\nMcp-Protocol-Version: 2025-11-25\r\n'
                f'Content-Length: {len(body)}\r\n\r\n').encode()
            writer.write(headers+body);await writer.drain()
            deadline=time.monotonic()+3
            while self.ledger._attempt_count<2 and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertEqual(self.ledger._attempt_count,2)
            row=next(r for r in self.controller._work.values() if r.message.get('id')=='007')
            self.assertFalse(row.enqueued)
            writer.close();await writer.wait_closed()
            deadline=time.monotonic()+3
            while not row.http_exited and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(row.http_exited and row.handler_exited)
            self.assertEqual(row.outcome,'cancelled');self.assertFalse(row.enqueued)
            self.assertFalse(first.done());self.assertEqual(self.calls,['latch'])
            self.assertEqual(self.records()[-1]['payload']['outcome'],'cancelled')
            self.assertEqual(self.controller._state,'ACTIVE')
            self.release.set();self.assertEqual((await first).status_code,200)
            self.assertFalse(self.ledger._active)
        finally:
            if writer is not None:writer.close();await writer.wait_closed()
            self.release.set()
            if not first.done():await first

    async def test_possible_handoff_http_cancellation_keeps_journal_and_unknown(self):
        await self.initialize()
        entered=threading.Event()
        async def lost_handoff(*args):
            entered.set()
            raise asyncio.CancelledError('handoff-not-confirmed')
        with patch.object(self.manager,'handle_request',side_effect=lost_handoff):
            response=await self.call(7,'never')
        self.assertTrue(entered.is_set());self.assertEqual(response.status_code,500)
        row=next(r for r in self.controller._work.values() if r.message.get('id')==7)
        self.assertTrue(row.enqueued and row.http_exited)
        self.assertFalse(row.started or row.handler_exited)
        self.assertIsInstance(row.error,asyncio.CancelledError)
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertTrue(self.ledger._active);self.assertEqual(self.calls,[])
        self.assertEqual([r['record_type'] for r in self.records()],
            ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK'])
        count=self.ledger._attempt_count
        self.assertEqual((await self.call(8)).status_code,503)
        self.assertEqual(self.ledger._attempt_count,count)


class CloseIOFaultTests(CloseIOTests):
    # Parent tests remain useful here but are not duplicated in suite collection.
    test_timeout_retains_actual_thread_and_join_task_until_exit=None
    test_http_waiter_cancellation_does_not_cancel_native_join=None
    test_actual_native_primary_preserved_after_true_join=None

    async def test_start_failure_retains_record_and_exact_primary(self):
        primary=OSError('thread-start-primary')
        with patch.object(threading.Thread,'start',side_effect=primary):
            with self.assertRaises(OSError) as caught:
                await self.c._owned_close_io('session',lambda:b'x',time.monotonic_ns()+1000000000)
        self.assertIs(caught.exception,primary)
        row=self.c._close_io['session']
        self.assertIs(row.error,primary);self.assertFalse(row.joined or row.wrapper_exited)
        self.assertIsNone(row.thread.ident);self.assertEqual(self.c._state,'UNKNOWN')

    async def test_join_failure_preserves_native_primary_and_real_exit(self):
        primary=OSError('native-primary');secondary=OSError('join-secondary')
        def fail():raise primary
        actual=threading.Thread.join
        def join(thread,*args,**kwargs):
            actual(thread,*args,**kwargs)
            if thread.name=='pc026-close-io':raise secondary
        with patch.object(threading.Thread,'join',join):
            with self.assertRaises(OSError) as caught:
                await self.c._owned_close_io('session',fail,time.monotonic_ns()+1000000000)
        self.assertIs(caught.exception,primary)
        row=self.c._close_io['session']
        self.assertTrue(row.wrapper_exited);self.assertFalse(row.thread.is_alive() or row.joined)
        self.assertIn('close_io_join_unknown',primary.__notes__)
        self.assertEqual(self.c._state,'UNKNOWN')

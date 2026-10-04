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


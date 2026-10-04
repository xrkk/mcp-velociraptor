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

class LoopLossTests(unittest.TestCase):
    def test_actual_loop_shutdown_keeps_unjoined_native_io_and_no_loop_callback(self):
        fixture=ledger_fixture.LedgerModels();self.addCleanup(fixture.doCleanups)
        ledger,_,_=fixture.ledger();c=object.__new__(SessionController);c._initialize(ledger,model_budgets())
        started=threading.Event();release=threading.Event()
        def native():
            started.set()
            if not release.wait(3):raise RuntimeError('loop-loss fixture latch')
            return b'actual-post-loop-result'
        loop=asyncio.new_event_loop()
        waiter=loop.create_task(c._owned_close_io('lost-loop',native,time.monotonic_ns()+3000000000))
        async def reached():
            while not started.is_set():await asyncio.sleep(.001)
        try:
            loop.run_until_complete(reached())
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):loop.run_until_complete(waiter)
            row=c._close_io['lost-loop'];self.assertTrue(row.thread.is_alive())
            row.task.cancel();loop.run_until_complete(row.task)
            self.assertEqual(c._state,'UNKNOWN');self.assertFalse(row.joined)
            loop.close()
            release.set();row.thread.join(3)
            self.assertFalse(row.thread.is_alive());self.assertTrue(row.wrapper_exited)
            self.assertFalse(row.joined);self.assertEqual(row.result,b'actual-post-loop-result')
        finally:
            release.set()
            for row in c._close_io.values():
                if row.thread.ident is not None:row.thread.join(3)
            if not loop.is_closed():loop.close()

class RetainedGraphTests(PendingTests):
    test_shared_pending_gate_counts_across_sessions_before_sequence_or_begin=None

    def test_exception_frame_local_payload_is_permanently_charged(self):
        c=self.controller;before=c._measure_retained()
        def fail():
            retained_payload=bytearray(65536)
            raise OSError('frame-retained-primary')
        try:fail()
        except OSError as error:c._close_errors['actual-error']=error
        after=c._measure_retained()
        self.assertGreater(after-before,65536)
        c._limits['max_retained_state_bytes']=after-1
        with self.assertRaises(ControllerError):c._retained_gate()
        self.assertEqual(c._state,'DRAINING')
        self.assertIn('retained_payload',c._close_errors['actual-error'].__traceback__.tb_next.tb_frame.f_locals)

    def test_context_closure_and_exporter_graph_payloads_are_shared_counted_once(self):
        import contextvars
        from types import SimpleNamespace
        c=self.controller;payload=bytearray(65536);variable=contextvars.ContextVar('actual-domain-payload')
        context=contextvars.Context();context.run(variable.set,payload)
        def closure():return payload
        c._exporter=SimpleNamespace(actual_context=context,actual_closure=closure,shared=payload)
        before=c._measure_retained();c._exporter.aliases=[payload]*64
        after=c._measure_retained()
        self.assertGreater(before,65536);self.assertLess(after-before,4096)
        payload.extend(b'x'*65536)
        self.assertGreaterEqual(c._measure_retained()-after,65536)

class LiveContextBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_copied_thread_context_denied_before_start_and_side_effect(self):
        import contextvars
        from velociraptor_observation_controller import _Threads
        from velociraptor_observation_workers import _CURRENT_OWNER, _owned_to_thread
        fixture=ledger_fixture.LedgerModels();self.addCleanup(fixture.doCleanups)
        ledger,_,_=fixture.ledger();c=object.__new__(SessionController);c._initialize(ledger,model_budgets())
        group=_Threads(c,'MODEL-context');c._sessions['MODEL-context']=dict(threads=group)
        owner=group._admit();owner_token=_CURRENT_OWNER.set(owner)
        variable=contextvars.ContextVar('retained-live-payload');token=variable.set(bytearray(65536))
        c._limits['max_retained_state_bytes']=32768;calls=[]
        try:
            with self.assertRaises(ControllerError):await _owned_to_thread(lambda:calls.append(True))
        finally:
            variable.reset(token);_CURRENT_OWNER.reset(owner_token)
        self.assertEqual(calls,[]);self.assertEqual(c._state,'DRAINING')
        work=next(iter(group._threads.values()))
        self.assertIsNone(work.thread.ident);self.assertFalse(work.joined)
        self.assertIsInstance(work.error,ControllerError)
        self.assertGreater(c._retained_measured_peak,65536)

class InitializationTailTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    call=chain.ChainTests.call

    async def test_actual_initialize_200_before_handler_exit_keeps_notify_waiting_until_open(self):
        entered=threading.Event();release=threading.Event();actual=self.controller._dispatch
        async def delayed(dctx,method,params,next):
            async def callback(*args):
                result=await next(*args)
                if method=='initialize':
                    entered.set()
                    while not release.is_set():await asyncio.sleep(.001)
                return result
            return await actual(dctx,method,params,callback)
        try:
            with patch.object(self.controller,'_dispatch',delayed):
                async with self.http.stream('POST',self.url,json=dict(jsonrpc='2.0',id=0,method='initialize',params=
                    dict(protocolVersion='2025-11-25',capabilities={},clientInfo=dict(name='MODEL',version='1')))) as response:
                    self.assertEqual(response.status_code,200)
                    session=response.headers['mcp-session-id']
                    deadline=time.monotonic()+3
                    while not entered.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
                    self.assertTrue(entered.is_set())
                    self.http.headers.update({'mcp-session-id':session,'mcp-protocol-version':'2025-11-25'})
                    notify=asyncio.create_task(self.http.post(self.url,json=dict(jsonrpc='2.0',method='notifications/initialized')))
                    await asyncio.sleep(.02);self.assertFalse(notify.done())
                    self.assertEqual(self.controller._sessions[session]['state'],'PENDING')
                    self.assertTrue(any(not r.handler_exited for r in self.controller._work.values()))
                    release.set();await response.aread();self.assertEqual((await notify).status_code,202)
                deadline=time.monotonic()+3
                while not self.controller._sessions[session]['initialized'] and time.monotonic()<deadline:await asyncio.sleep(.001)
                self.assertEqual((await self.call(7,'after-init')).status_code,200)
                self.assertEqual(self.controller._state,'ACTIVE');self.assertEqual(self.calls,['after-init'])
        finally:release.set()

class SDKPayloadBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_owned_sdk_stream_gate_counts_payload_before_buffer_side_effect(self):
        from velociraptor_observation_sdk_adapter import _Resources
        fixture=ledger_fixture.LedgerModels();self.addCleanup(fixture.doCleanups)
        ledger,_,_=fixture.ledger();c=object.__new__(SessionController);c._initialize(ledger,model_budgets())
        resources=_Resources();resources.controller=c
        send,receive=resources.memory(1)
        c._limits['max_retained_state_bytes']=32768
        payload=dict(actual_sdk_payload=bytearray(65536))
        try:
            with self.assertRaises(ControllerError):await send.send(payload)
            self.assertEqual(send._stream.statistics().current_buffer_used,0)
            self.assertEqual(c._state,'UNKNOWN');self.assertIsInstance(resources.error,ControllerError)
            self.assertGreater(c._retained_measured_peak,65536)
        finally:
            await send.aclose();await receive.aclose()
        self.assertTrue(send.closed and receive.closed)

class JoinTaskLaunchTests(CloseIOTests):
    test_timeout_retains_actual_thread_and_join_task_until_exit=None
    test_http_waiter_cancellation_does_not_cancel_native_join=None
    test_actual_native_primary_preserved_after_true_join=None

    async def test_join_task_launch_failure_retains_live_native_thread_and_primary(self):
        primary=RuntimeError('join-task-launch')
        with patch.object(asyncio,'create_task',side_effect=primary):
            with self.assertRaises(RuntimeError) as caught:
                await self.c._owned_close_io('session',self.native,time.monotonic_ns()+3000000000)
        self.assertIs(caught.exception,primary)
        row=self.c._close_io['session']
        self.assertIs(row.error,primary);self.assertIsNone(row.task)
        self.assertTrue(row.thread.is_alive());self.assertFalse(row.joined)
        self.assertEqual(self.c._state,'UNKNOWN')
        self.release.set();row.thread.join(3)
        self.assertTrue(row.wrapper_exited);self.assertFalse(row.thread.is_alive() or row.joined)

class IngressBudgetAndEOFTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call

    async def test_actual_body_budget_rejects_before_sdk_ticket_and_begin(self):
        await self.initialize();before=(self.controller._sequence,len(self.controller._work),self.records())
        self.controller._limits['max_request_body_bytes']=1
        response=await self.call(7,'never');self.assertEqual(response.status_code,413)
        self.assertEqual((self.controller._sequence,len(self.controller._work),self.records()),before)
        self.assertEqual(self.calls,[])

    async def test_actual_two_session_limit_refuses_third_before_writer_or_sdk_creation(self):
        first=await self.initialize()
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        second=await self.initialize();self.assertNotEqual(first,second)
        before=(self.controller._sequence,len(self.controller._work),self.records())
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=0,method='initialize',params=
            dict(protocolVersion='2025-11-25',capabilities={},clientInfo=dict(name='MODEL',version='1'))))
        self.assertEqual(response.status_code,503);self.assertIn('session_budget',response.text)
        self.assertEqual((self.controller._sequence,len(self.controller._work),self.records()),before)
        self.assertEqual(len(self.manager._owned_transports),2);self.assertEqual(self.controller._state,'DRAINING')

    async def test_socket_eof_before_declared_body_end_is_not_complete_json_request(self):
        import json
        from urllib.parse import urlsplit
        import velociraptor_observation_controller as module
        session=await self.initialize();before=(self.controller._sequence,len(self.controller._work),self.records())
        url=urlsplit(self.url);reader,writer=await asyncio.open_connection(url.hostname,url.port)
        body=json.dumps(dict(jsonrpc='2.0',id=7,method='tools/call',params=dict(name='echo',arguments=dict(value='never')))).encode()
        headers=(f'POST /mcp/ HTTP/1.1\r\nHost: {url.netloc}\r\nAuthorization: Bearer MODEL\r\n'
            f'Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n'
            f'Mcp-Session-Id: {session}\r\nMcp-Protocol-Version: 2025-11-25\r\n'
            f'Content-Length: {len(body)+1}\r\n\r\n').encode()
        observed=threading.Event();actual=module.JSONResponse
        def response(content,*args,**kwargs):
            if content=={'error':{'code':'body_incomplete'}}:
                self.assertEqual(kwargs['status_code'],400);observed.set()
            return actual(content,*args,**kwargs)
        try:
            with patch.object(module,'JSONResponse',response):
                writer.write(headers+body);await writer.drain();writer.close();await writer.wait_closed()
                until=time.monotonic()+2
                while not observed.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
                self.assertTrue(observed.is_set())  # Response constructed after real disconnect, not received.
            self.assertEqual((self.controller._sequence,len(self.controller._work),self.records()),before)
            self.assertEqual(self.calls,[]);self.assertEqual(self.controller._state,'ACTIVE')
            self.assertEqual((await self.call(8,'after-eof')).status_code,200)
        finally:writer.close();await writer.wait_closed()


class BudgetShapeTests(PendingTests):
    test_shared_pending_gate_counts_across_sessions_before_sequence_or_begin=None

    def test_each_of_all_sixteen_limits_is_strict_positive_integer(self):
        limits=model_budgets();self.assertEqual(len(limits),16)
        for name in limits:
            for invalid in (True,0,-1,1.0,None):
                with self.subTest(name=name,invalid=invalid),self.assertRaises(ControllerError):
                    controller=object.__new__(SessionController)
                    controller._initialize(self.ledger,dict(limits,**{name:invalid}))
        self.assertEqual(self.ledger._attempt_count,0)

class ProtocolHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    call=chain.ChainTests.call

    async def handshake(self, version):
        import json
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=0,method='initialize',params=
            dict(protocolVersion=version,capabilities={},clientInfo=dict(name='MODEL',version='1'))))
        self.assertEqual(response.status_code,200,response.text)
        message=json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))
        self.assertEqual(message['result']['protocolVersion'],version)
        session=response.headers['mcp-session-id']
        self.http.headers.update({'mcp-session-id':session,'mcp-protocol-version':version})
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',method='notifications/initialized'))
        self.assertEqual(response.status_code,202,response.text)
        until=time.monotonic()+2
        while not self.controller._sessions[session]['initialized'] and time.monotonic()<until:await asyncio.sleep(.001)
        self.assertEqual((await self.call(7,version)).status_code,200)
        self.assertEqual(self.calls,[version]);self.assertEqual(self.controller._state,'ACTIVE')
        self.assertEqual([r['record_type'] for r in self.records()],
            ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK','ATTEMPT_END'])

    async def test_actual_2024_11_05_handshake_and_tool(self):await self.handshake('2024-11-05')
    async def test_actual_2025_03_26_handshake_and_tool(self):await self.handshake('2025-03-26')
    async def test_actual_2025_06_18_handshake_and_tool(self):await self.handshake('2025-06-18')
    async def test_actual_2025_11_25_handshake_and_tool(self):await self.handshake('2025-11-25')

class ChainedExceptionGraphTests(PendingTests):
    test_shared_pending_gate_counts_across_sessions_before_sequence_or_begin=None

    def test_retained_cause_frame_and_path_slots_are_not_opaque(self):
        from pathlib import Path
        from types import SimpleNamespace
        c=self.controller;before=c._measure_retained()
        def fail():
            payload=bytearray(65536)
            raise OSError('actual-cause')
        try:fail()
        except OSError as error:primary=RuntimeError('first-error');primary.__cause__=error
        c._close_errors['first']=primary
        c._exporter=SimpleNamespace(actual_path=Path('/MODEL/'+65536*'x'))
        self.assertGreater(c._measure_retained()-before,131072)
        self.assertIs(c._close_errors['first'],primary)

    def test_unmeasurable_graph_is_sticky_unknown(self):
        with patch.object(self.controller,'_measure_retained',side_effect=OSError('actual-measurement-fault')):
            with self.assertRaises(OSError):self.controller._retained_gate()
        self.assertEqual(self.controller._state,'UNKNOWN')

class ActiveSocketTailTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call

    async def test_actual_socket_disconnect_after_sdk_claim_retains_live_handler_journal(self):
        import json
        from urllib.parse import urlsplit
        session=await self.initialize();url=urlsplit(self.url)
        reader,writer=await asyncio.open_connection(url.hostname,url.port)
        body=json.dumps(dict(jsonrpc='2.0',id=7,method='tools/call',params=dict(name='echo',arguments=dict(value='latch')))).encode()
        headers=(f'POST /mcp/ HTTP/1.1\r\nHost: {url.netloc}\r\nAuthorization: Bearer MODEL\r\n'
            f'Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n'
            f'Mcp-Session-Id: {session}\r\nMcp-Protocol-Version: 2025-11-25\r\n'
            f'Content-Length: {len(body)}\r\n\r\n').encode()
        try:
            writer.write(headers+body);await writer.drain()
            until=time.monotonic()+2
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            row=next(r for r in self.controller._work.values() if r.message.get('id')==7)
            self.assertTrue(row.started and row.enqueued);self.assertIsNotNone(row.worker_owner)
            writer.close();await writer.wait_closed()
            until=time.monotonic()+2
            while not row.http_exited and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(row.http_exited)
            self.assertFalse(row.handler_exited);self.assertTrue(self.ledger._active)
            self.assertEqual([r['record_type'] for r in self.records()],
                ['INSTANCE_BEGIN','ATTEMPT_BEGIN','ACCEPT_ACK'])
            self.release.set()
            until=time.monotonic()+2
            while not row.handler_exited and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(row.handler_exited);self.assertFalse(self.ledger._active)
            self.assertEqual(self.records()[-1]['record_type'],'ATTEMPT_END')
            self.assertIn(self.records()[-1]['payload']['outcome'],('returned','cancelled'))
            self.assertEqual(self.calls,['latch'])
        finally:self.release.set();writer.close();await writer.wait_closed()

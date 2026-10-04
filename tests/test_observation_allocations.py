"""Actual storage pre-reservations, not complete JSON/native heap qualification."""
import asyncio
import sys
import threading
import time
import unittest
from unittest.mock import patch

import velociraptor_observation_controller as module
from tests import test_observation_close_io as close_io
from tests import test_observation_controller as chain


class StorageTests(unittest.TestCase):
    def test_fixed_maximum_backing_and_no_growth_or_intermediate_data_slice(self):
        for size in (0,1,65536):
            with self.subTest(size=size):
                b=module._BodyBuffer(size)
                try:
                    backing=b.storage;before=sys.getsizeof(backing)
                    for position in range(0,size,127):b.append(b'x'*min(127,size-position))
                    self.assertIs(b.storage,backing)
                    self.assertEqual(sys.getsizeof(backing),before)
                    raw=b.finish();self.assertEqual(raw,b'x'*size)
                    # Postmeasurement verifies the explicitly scoped backing
                    # storage bound only, never parser/allocator/RSS.
                    self.assertLessEqual(sys.getsizeof(backing)+sys.getsizeof(raw)
                        +2*sys.getsizeof(b.view),module._body_storage_bound(size))
                    with self.assertRaises(module.ControllerError):b.append(b'x')
                finally:b.close()
    def test_size_shape_overflow_and_content_length_bound(self):
        for bad in (True,-1,1.0,None,sys.maxsize+1,sys.maxsize):
            with self.subTest(bad=bad),self.assertRaises(module.ControllerError):module._body_storage_bound(bad)
        self.assertEqual(module._body_capacity([],65536),65536)
        self.assertEqual(module._body_capacity([(b'content-length',b'12')],65536),12)
        for value in (b'',b'-1',b'1.0',b'9'*21,b'65537'):
            with self.subTest(value=value),self.assertRaises(module.ControllerError):module._body_capacity([(b'content-length',value)],65536)


class ReservationTests(close_io.PendingTests):
    test_shared_pending_gate_counts_across_sessions_before_sequence_or_begin=None
    def test_exact_and_minus_one_arithmetic_and_single_release(self):
        c=self.controller;size=module._body_storage_bound(65536)
        with patch.object(c,'_measure_retained',return_value=0):
            c._limits['max_retained_state_bytes']=size;c._retained=0
            lease=c._reserve_temporary(size,'input')
            self.assertEqual(c._temporary_reserved,size)
            with self.assertRaises(module.ControllerError):c._reserve_temporary(1,'other')
            lease.release();lease.release();self.assertEqual(c._temporary_reserved,0)
            c._limits['max_retained_state_bytes']=size-1
            with self.assertRaises(module.ControllerError):c._reserve_temporary(size,'input')
            self.assertEqual(c._temporary_reserved,0)
    def test_actual_simultaneous_threads_cannot_double_spend(self):
        c=self.controller;barrier=threading.Barrier(9);release=threading.Event();held=[];refused=[]
        def run():
            barrier.wait()
            try:lease=c._reserve_temporary(1000,threading.current_thread())
            except module.ControllerError:refused.append(True);return
            held.append(lease);release.wait(3);lease.release()
        with patch.object(c,'_measure_retained',return_value=0):
            c._limits['max_retained_state_bytes']=3000;c._retained=0
            threads=[threading.Thread(target=run,daemon=False) for _ in range(8)]
            for t in threads:t.start()
            try:
                barrier.wait();deadline=time.monotonic()+2
                while len(held)+len(refused)<8 and time.monotonic()<deadline:time.sleep(.001)
                self.assertEqual(len(held),3);self.assertEqual(len(refused),5)
                self.assertEqual(c._temporary_reserved,3000)
            finally:
                release.set()
                for t in threads:t.join(3);self.assertFalse(t.is_alive())
            self.assertEqual(c._temporary_reserved,0)
    def test_work_owner_requires_both_actual_tails(self):
        c=self.controller;_,row=c._admit(None,b'a'*32,{'method':'initialize'})
        row.input_storage=c._reserve_temporary(100,'input');row.input_storage.owner=row
        row.http_exited=True;c._release_input_storage(row);self.assertEqual(c._temporary_reserved,100)
        row.handler_exited=True;c._release_input_storage(row);self.assertEqual(c._temporary_reserved,0)


class NativeReservationTests(close_io.CloseIOTests):
    test_timeout_retains_actual_thread_and_join_task_until_exit=None
    test_http_waiter_cancellation_does_not_cancel_native_join=None
    test_actual_native_primary_preserved_after_true_join=None
    async def test_timeout_and_cross_session_shortage_hold_until_native_finally(self):
        c=self.c;c._limits['max_retained_state_bytes']=1000
        with patch.object(c,'_measure_retained',return_value=0):
            with self.assertRaises(module.ControllerError):
                await c._owned_close_io('first',self.native,time.monotonic_ns()+20000000,temporary_bytes=1000)
            self.assertTrue(self.started.is_set());self.assertEqual(c._temporary_reserved,1000)
            side_effect=[]
            with self.assertRaises(module.ControllerError):
                await c._owned_close_io('second',lambda:side_effect.append(True),time.monotonic_ns()+3000000000,temporary_bytes=1)
            self.assertEqual(side_effect,[]);self.assertNotIn('second',c._close_io)
            c._unknown('first');self.assertEqual(c._temporary_reserved,1000)
            self.release.set();await c._close_io['first'].task
            self.assertEqual(c._temporary_reserved,0);self.assertTrue(c._close_io['first'].joined)
    async def test_cancel_does_not_release_live_native_quota(self):
        waiter=asyncio.create_task(self.c._owned_close_io('first',self.native,time.monotonic_ns()+3000000000,temporary_bytes=1000))
        while not self.started.is_set():await asyncio.sleep(.001)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):await waiter
        self.assertEqual(self.c._temporary_reserved,1000)
        self.release.set();await self.c._close_io['first'].task
        self.assertEqual(self.c._temporary_reserved,0)
    async def test_known_no_start_returns_quota_but_start_then_raise_keeps_live_owner(self):
        with patch.object(module.threading.Thread,'start',side_effect=OSError('no-start')):
            with self.assertRaises(OSError):await self.c._owned_close_io('none',self.native,time.monotonic_ns()+3000000000,temporary_bytes=1000)
        self.assertEqual(self.c._temporary_reserved,0);self.assertFalse(self.started.is_set())
        actual=threading.Thread.start
        def start_and_raise(thread):actual(thread);raise OSError('after-start')
        with patch.object(module.threading.Thread,'start',start_and_raise):
            with self.assertRaises(OSError):await self.c._owned_close_io('live',self.native,time.monotonic_ns()+3000000000,temporary_bytes=1000)
        row=self.c._close_io['live'];self.assertTrue(row.thread.is_alive());self.assertEqual(self.c._temporary_reserved,1000)
        self.release.set();row.thread.join(3);self.assertFalse(row.thread.is_alive())
        self.assertEqual(self.c._temporary_reserved,0);self.assertFalse(row.joined)
    async def test_join_task_launch_failure_keeps_native_quota_and_first_error(self):
        primary=RuntimeError('join-task-start')
        with patch.object(module.asyncio,'create_task',side_effect=primary):
            with self.assertRaises(RuntimeError) as caught:
                await self.c._owned_close_io('live',self.native,time.monotonic_ns()+3000000000,temporary_bytes=1000)
        row=self.c._close_io['live']
        self.assertIs(caught.exception,primary);self.assertIs(row.error,primary)
        self.assertTrue(row.thread.is_alive());self.assertEqual(self.c._temporary_reserved,1000)
        self.release.set();row.thread.join(3)
        self.assertFalse(row.thread.is_alive());self.assertEqual(self.c._temporary_reserved,0)
        self.assertFalse(row.joined);self.assertEqual(self.c._state,'UNKNOWN')


class HTTPStorageTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=chain.ChainTests.asyncSetUp
    asyncTearDown=chain.ChainTests.asyncTearDown
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call
    async def test_shortage_on_real_socket_before_buffer_parser_sdk_begin(self):
        await self.initialize();c=self.controller
        before=(c._sequence,c._ledger._attempt_count)
        c._limits['max_retained_state_bytes']=1
        with patch.object(module,'_BodyBuffer',wraps=module._BodyBuffer) as buffer,patch.object(module,'strict_json',wraps=module.strict_json) as parser,patch.object(module.jsonrpc_message_adapter,'validate_python',wraps=module.jsonrpc_message_adapter.validate_python) as model,patch.object(self.manager,'handle_request',wraps=self.manager.handle_request) as sdk:
            r=await self.call(7,'never')
            self.assertEqual(r.status_code,503,r.text)
            self.assertEqual(r.json()['error']['code'],'retained_budget')
            buffer.assert_not_called();parser.assert_not_called();model.assert_not_called();sdk.assert_not_called()
        self.assertEqual((c._sequence,c._ledger._attempt_count),before)
        self.assertEqual(self.calls,[]);self.assertEqual(c._temporary_reserved,0)
    async def test_accepted_storage_transfers_to_actual_ticket_and_releases_after_exit(self):
        await self.initialize();first=asyncio.create_task(self.call(7,'latch'))
        try:
            deadline=time.monotonic()+3
            while not self.started.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set())
            row=next(r for r in self.controller._work.values() if r.message.get('id')==7)
            self.assertIs(row.input_storage.owner,row);self.assertFalse(row.input_storage.released)
            self.assertGreater(self.controller._temporary_reserved,0)
            self.release.set();self.assertEqual((await first).status_code,200)
            deadline=time.monotonic()+3
            while not row.http_exited and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(row.handler_exited and row.http_exited)
            self.assertTrue(row.input_storage.released);self.assertEqual(self.controller._temporary_reserved,0)
        finally:
            self.release.set()
            if not first.done():await first


class DescriptorBufferTests(unittest.TestCase):
    def test_actual_ctypes_maximum_and_one_over_refuses_before_buffer_construction(self):
        import ctypes
        from tests import p05_pc026_windows_reader as reader
        from tests.test_p05_pc026_windows_reader import sd
        for size in (reader.MAX_SD_BYTES,reader.MAX_SD_BYTES+1):
            api=object.__new__(reader.NativeIO)
            def security(handle,flags,buffer,capacity,needed):
                ctypes.cast(needed,ctypes.POINTER(ctypes.c_uint32))[0]=size
                if buffer is None:return 0
                ctypes.memmove(buffer,sd(),len(sd()));return 1
            api.security=security;api.valid=lambda buffer:1;api.length=lambda buffer:size
            with patch.object(ctypes,'get_last_error',return_value=122,create=True),patch.object(ctypes,'create_string_buffer',wraps=ctypes.create_string_buffer) as allocate:
                if size<=reader.MAX_SD_BYTES:
                    raw=api.descriptor(9);self.assertEqual(len(raw),size)
                    allocate.assert_called_once_with(size)
                else:
                    with self.assertRaises(reader.NativeReadError):api.descriptor(9)
                    allocate.assert_not_called()


class SnapshotReadBounds(unittest.TestCase):
    def fixture(self):
        from tests import test_p05_pc026_windows_reader as models
        f=models.NativeReaderModels();self.addCleanup(f.doCleanups)
        return f.reader()
    def test_confirmed_size_above_limit_refuses_before_native_content_read(self):
        from pathlib import PureWindowsPath
        from tests import p05_pc026_windows_reader as reader_module
        reader=self.fixture();path=PureWindowsPath(r'C:\controlled\original.json')
        with patch.object(reader.api,'read',wraps=reader.api.read) as native_read:
            with self.assertRaisesRegex(reader_module.NativeReadError,'record byte budget'):
                reader._read_original(path,len(reader.api.data)-1)
            native_read.assert_not_called()
        self.assertTrue(reader.objects)  # Original retained security ownership.
        reader.close();self.assertFalse(reader.api.pending)
    def test_exact_original_and_lying_metadata_still_require_real_eof(self):
        from pathlib import PureWindowsPath
        from tests import p05_pc026_windows_reader as reader_module
        reader=self.fixture();path=PureWindowsPath(r'C:\controlled\original.json')
        raw,_,identity=reader._read_original(path,len(reader.api.data))
        self.assertEqual(raw,reader.api.data);self.assertEqual(identity['principal_sid'],reader.sid)
        reader.close();reader=self.fixture()
        with patch.object(reader.api,'metadata',return_value=(len(reader.api.data)-1,1,2,3,0)):
            with self.assertRaisesRegex(reader_module.NativeReadError,'extra read'):
                reader._read_original(path,len(reader.api.data)-1)
    def test_invalid_limit_never_opens_native_handle(self):
        from pathlib import PureWindowsPath
        reader=self.fixture()
        with patch.object(reader.api,'open',wraps=reader.api.open) as open_file:
            for bad in (True,0,-1,1.0,None,sys.maxsize+1):
                with self.assertRaises(Exception):reader._read_original(PureWindowsPath(r'C:\controlled\x'),bad)
            open_file.assert_not_called()
    def test_actual_snapshot_oversize_record_does_not_read_its_content(self):
        from tests import test_observation_attempts as models
        from tests import p05_pc026_windows_reader as reader_module
        f=models.LedgerModels();self.addCleanup(f.doCleanups)
        ledger,fs,config=f.ledger();path=ledger._catalog_dir.path/'00000000.json'
        fs.nodes[str(path)]['data']+=b' '*config.catalog_codec.max_record_bytes
        node=fs.nodes[str(path)];node['meta']=(len(node['data']),*node['meta'][1:])
        before={p:n['data'] for p,n in fs.nodes.items() if not n['directory']}
        reads=[];actual=fs.read
        def read(handle):reads.append(fs.handles[handle]['node'] is node);return actual(handle)
        with patch.object(fs,'read',read),self.assertRaisesRegex(reader_module.NativeReadError,'record byte budget'):
            ledger._session_prefix('one',max_files=100,max_bytes=1000000)
        self.assertFalse(any(reads));self.assertTrue(ledger._unknown)
        self.assertEqual(before,{p:n['data'] for p,n in fs.nodes.items() if not n['directory']})

"""Real dedicated host threads and cancellation; not a formal SDK barrier."""
import asyncio
import contextvars
import threading
import unittest
from unittest.mock import patch

import anyio
import velociraptor_observation_workers as workers


class RetainedThreadTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, function, group=None):
        group = group or workers._WorkerGroup(8)
        owner = group._admit()
        token = workers._CURRENT_OWNER.set(owner)
        primary = None
        try:
            try:
                return await workers._owned_to_thread(function)
            except BaseException as exc:
                primary = exc
                raise
            finally:
                group._finish_owner(owner, primary=primary)
        finally:
            workers._CURRENT_OWNER.reset(token)

    async def test_real_thread_and_context_exit_before_return(self):
        variable = contextvars.ContextVar('MODEL-retained-test')
        token = variable.set('MODEL-value')
        group = workers._WorkerGroup(8)
        loop_thread = threading.get_ident()
        try:
            value = await self.exercise(lambda: (threading.get_ident(), variable.get()), group)
        finally:
            variable.reset(token)
        self.assertNotEqual(value[0], loop_thread)
        self.assertEqual(value[1], 'MODEL-value')
        work = next(iter(group._threads.values()))
        self.assertFalse(work.thread.is_alive())
        self.assertTrue(work.wrapper_exited and work.joined)
        self.assertEqual(await group._wait_barrier(100000000), 2)

    async def test_repeated_asyncio_cancellation_cannot_release_live_worker(self):
        started, release = threading.Event(), threading.Event()
        group = workers._WorkerGroup(8)
        def blocking():
            started.set()
            if not release.wait(5):
                raise AssertionError('test latch expired')
        task = asyncio.create_task(self.exercise(blocking, group))
        try:
            while not started.is_set():
                await asyncio.sleep(.001)
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(.005)
                self.assertFalse(task.done())
                self.assertTrue(next(iter(group._threads.values())).thread.is_alive())
                self.assertFalse(group._quiescent())
            barrier = asyncio.create_task(group._wait_barrier(1000000000))
            await asyncio.sleep(.02)
            self.assertFalse(barrier.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(await barrier, 2)
        finally:
            release.set()
            if not task.done():
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self.assertTrue(next(iter(group._threads.values())).cancelled)

    async def test_anyio_level_cancellation_is_shielded_until_real_exit(self):
        started, release = threading.Event(), threading.Event()
        group = workers._WorkerGroup(8)
        task_done = asyncio.Event()
        def blocking():
            started.set()
            self.assertTrue(release.wait(5))
        async def runner():
            with anyio.CancelScope() as scope:
                self.scope = scope
                await self.exercise(blocking, group)
            task_done.set()
        async with anyio.create_task_group() as tg:
            tg.start_soon(runner)
            while not started.is_set():
                await anyio.sleep(.001)
            self.scope.cancel()
            await anyio.sleep(.02)
            self.assertFalse(task_done.is_set())
            self.assertFalse(group._quiescent())
            release.set()
        self.assertTrue(task_done.is_set())
        self.assertTrue(group._quiescent())

    async def test_timeout_is_sticky_and_does_not_drop_live_ownership(self):
        started, release = threading.Event(), threading.Event()
        group = workers._WorkerGroup(8)
        def blocking():
            started.set()
            self.assertTrue(release.wait(5))
        task = asyncio.create_task(self.exercise(blocking, group))
        try:
            while not started.is_set():
                await asyncio.sleep(.001)
            with self.assertRaisesRegex(workers.WorkerOwnershipError, 'barrier_unknown'):
                await group._wait_barrier(5000000)
            self.assertEqual(len(group._threads), 1)
            self.assertTrue(next(iter(group._threads.values())).thread.is_alive())
            release.set()
            await task
            self.assertFalse(next(iter(group._threads.values())).thread.is_alive())
            with self.assertRaisesRegex(workers.WorkerOwnershipError, 'barrier_unknown'):
                await group._wait_barrier(100000000)
        finally:
            release.set()
            if not task.done():
                await task

    async def test_frozen_ingress_allows_only_actual_admitted_owner_descendants(self):
        group = workers._WorkerGroup(8)
        owner = group._admit()
        group._freeze()
        with self.assertRaisesRegex(workers.WorkerOwnershipError, 'ingress_closed'):
            group._admit()
        token = workers._CURRENT_OWNER.set(owner)
        try:
            self.assertEqual(await workers._owned_to_thread(lambda: 'causal'), 'causal')
        finally:
            workers._CURRENT_OWNER.reset(token)
        group._finish_owner(owner)
        with self.assertRaisesRegex(workers.WorkerOwnershipError, 'owner_invalid'):
            group._register(owner)
        self.assertEqual(await group._wait_barrier(100000000), 2)

    async def test_other_group_is_independent_and_original_exception_survives(self):
        group, other = workers._WorkerGroup(8), workers._WorkerGroup(8)
        group._mark_unknown()
        original = RuntimeError('MODEL-worker-error')
        def fail():
            raise original
        with self.assertRaises(RuntimeError) as caught:
            await self.exercise(fail, other)
        self.assertIs(caught.exception, original)
        self.assertEqual(await other._wait_barrier(100000000), 2)

    async def test_start_failure_remains_owned_and_unknown(self):
        group = workers._WorkerGroup(8)
        owner = group._admit()
        token = workers._CURRENT_OWNER.set(owner)
        called = []
        try:
            with patch.object(threading.Thread, 'start', side_effect=RuntimeError('MODEL-launch')), \
                    self.assertRaisesRegex(RuntimeError, 'MODEL-launch'):
                await workers._owned_to_thread(lambda: called.append(True))
        finally:
            workers._CURRENT_OWNER.reset(token)
        self.assertEqual(called, [])
        self.assertEqual(len(group._threads), 1)
        self.assertFalse(next(iter(group._threads.values())).joined)
        with self.assertRaisesRegex(workers.WorkerOwnershipError, 'barrier_unknown'):
            await group._wait_barrier(100000000)

    async def test_lookalike_owner_cannot_register_and_real_token_is_immutable(self):
        from dataclasses import FrozenInstanceError
        group = workers._WorkerGroup(8)
        owner = group._admit()
        fake = workers._Owner(group, owner.sequence)
        with self.assertRaisesRegex(workers.WorkerOwnershipError, 'owner_invalid'):
            group._register(fake)
        with self.assertRaises(FrozenInstanceError):
            owner.sequence = 99
        self.assertEqual(group._threads, {})
        group._finish_owner(owner)
        self.assertEqual(await group._wait_barrier(100000000), 1)

    async def test_budget_reserves_before_thread_or_business(self):
        group = workers._WorkerGroup(1)
        owner = group._admit()
        token = workers._CURRENT_OWNER.set(owner)
        called = []
        try:
            with self.assertRaisesRegex(workers.WorkerOwnershipError, 'budget_exhausted'):
                await workers._owned_to_thread(lambda: called.append(True))
        finally:
            workers._CURRENT_OWNER.reset(token)
        self.assertEqual(called, [])
        self.assertEqual(group._threads, {})
        group._finish_owner(owner)
        self.assertEqual(await group._wait_barrier(100000000), 1)

    async def test_join_fault_preserves_worker_primary_and_refuses_barrier(self):
        group = workers._WorkerGroup(8)
        owner = group._admit()
        original = RuntimeError('MODEL-primary')
        def fail():
            raise original
        def bad_join(thread, *args, **kwargs):
            actual_join(thread, *args, **kwargs)
            raise OSError('MODEL-join')
        actual_join = threading.Thread.join
        token = workers._CURRENT_OWNER.set(owner)
        try:
            with patch.object(threading.Thread, 'join', bad_join), self.assertRaises(RuntimeError) as caught:
                await workers._owned_to_thread(fail)
            self.assertIs(caught.exception, original)
            self.assertIn('retained_worker_join_failed', original.__notes__)
        finally:
            workers._CURRENT_OWNER.reset(token)
        self.assertFalse(next(iter(group._threads.values())).thread.is_alive())
        with self.assertRaisesRegex(workers.WorkerOwnershipError, 'barrier_unknown'):
            await group._wait_barrier(100000000)

    async def test_all_seven_real_sdk_wrappers_share_retained_owner_without_schema_change(self):
        from mcp.server.mcpserver import MCPServer
        from velo_transfer.mcp_tools import register_transfer_tools, TRANSFER_TOOL_NAMES
        calls = []
        class Service:
            def __getattr__(self, name):
                if name == 'shutdown':
                    return lambda: None
                def call(**args):
                    calls.append((name, workers._CURRENT_OWNER.get(), threading.get_ident()))
                    return {}
                return call
        server = MCPServer('MODEL-retained-transfer')
        manager = register_transfer_tools(server, factory=Service)
        self.addCleanup(manager.shutdown)
        request = dict(protocol_version='velo.transfer.v1', transfer_id='MODEL', request_digest='a'*64,
            direction='pull', sources=[dict(absolute_path='/MODEL/source',relative_path='source')],
            expected_destination=dict(endpoint='host',identity={'device':'MODEL'},canonical_path='/MODEL/dest'),
            expected_vm_identity=dict(vm_uuid='MODEL',boot_identity='MODEL',vm_epoch='MODEL'),
            evidence_context=dict(producer_complete=True,producer_quiescent=True,references=['MODEL']),
            budget=dict(max_files=1,max_metadata_bytes=1024,max_logical_bytes=1,max_package_bytes=1024,
                        min_free_bytes=0,max_chunk_bytes=1,max_duration_seconds=1))
        common = dict(transfer_id='MODEL',request_digest='a'*64)
        arguments = [{}, dict(request=request), common, dict(common,offset=0,count=1),
            dict(common,offset=0,count_per_chunk=1,chunk_count=1), dict(common,action='prepare'), common]
        group = workers._WorkerGroup(16)
        owner = group._admit()
        token = workers._CURRENT_OWNER.set(owner)
        try:
            for name, args in zip(TRANSFER_TOOL_NAMES, arguments, strict=True):
                result = await server.call_tool(name, args)
                self.assertFalse(result.is_error, name)
                self.assertEqual(result.structured_content['status'], 'success')
            group._finish_owner(owner)
        finally:
            workers._CURRENT_OWNER.reset(token)
        self.assertEqual([c[0] for c in calls], list(TRANSFER_TOOL_NAMES))
        self.assertTrue(all(c[1] is owner and c[2] != threading.get_ident() for c in calls))
        self.assertEqual(len(group._threads), 7)
        self.assertTrue(all(w.joined and not w.thread.is_alive() for w in group._threads.values()))
        self.assertEqual(await group._wait_barrier(100000000), 8)

    async def test_actual_binary_endpoint_cancellation_retains_invoke_and_preserves_owner(self):
        from types import SimpleNamespace
        from starlette.requests import Request
        from velo_transfer.http_wire import chunk_endpoint
        from velo_transfer import wire
        import hashlib
        started, release = threading.Event(), threading.Event()
        group = workers._WorkerGroup(8)
        observed = []
        def invoke(name, **args):
            observed.append((name, workers._CURRENT_OWNER.get()))
            started.set()
            self.assertTrue(release.wait(5))
            return SimpleNamespace(status='success',result={'verified_offset':1,'accepted':1})
        raw = wire.encode({'chunks':[{'count':1,'chunk_sha256':hashlib.sha256(b'x').hexdigest()}]},b'x','push_request')
        headers = [(b'content-type',b'application/octet-stream'),(b'x-velo-direction',b'push'),
            (b'x-velo-transfer-id',b'MODEL'),(b'x-velo-request-digest',b'a'*64),(b'x-velo-offset',b'0')]
        async def receive():
            return {'type':'http.request','body':raw,'more_body':False}
        endpoint = chunk_endpoint(SimpleNamespace(invoke=invoke))
        owner = group._admit()
        async def runner():
            token = workers._CURRENT_OWNER.set(owner)
            try:
                try:
                    return await endpoint(Request({'type':'http','headers':headers},receive))
                finally:
                    group._finish_owner(owner)
            finally:
                workers._CURRENT_OWNER.reset(token)
        task = asyncio.create_task(runner())
        try:
            while not started.is_set():
                if task.done():
                    self.fail('binary failed before invoke: ' + repr(task.result()))
                await asyncio.sleep(.001)
            task.cancel()
            await asyncio.sleep(.02)
            self.assertFalse(task.done())
            self.assertFalse(group._quiescent())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            release.set()
            if not task.done():
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self.assertEqual(observed, [('transfer_chunks',owner)])
        self.assertEqual(await group._wait_barrier(100000000), 2)

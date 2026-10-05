"""Actual approved construction/entry cleanup; Windows authority explicitly MODEL.

Fixed isolated approval reader, real controller/ledger/exporter/native algorithm,
SDK manager and (where stated) actual uvicorn lifespan. No VM or deployment.
"""
import asyncio
from contextlib import asynccontextmanager, redirect_stderr
from io import StringIO
import time
import threading
import unittest
from unittest.mock import Mock, patch

from mcp.server.mcpserver import MCPServer
import mcp_velociraptor_bridge as bridge
import velociraptor_transport as transport
from velociraptor_observation_controller import SessionController
from velociraptor_observation_sdk_adapter import _TrackedManager
from tests.test_observation_native_startup import ApprovedNativeStartup
from tests.test_observation_attempts import INSTANCE

TRACES=[]

class StartupCleanup(unittest.TestCase):
    def setUp(self):
        self.fixture=ApprovedNativeStartup('test_full_fixed_loader_preflight_construct_and_transport_share_one_group_instance')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fs=self.fixture.fs;self.controller=None;self.group_closes=[]
        self.config=transport.TransportConfig('http',host='127.0.0.1',port=0,bearer_token='MODEL')
        self.server=MCPServer('MODEL-startup-cleanup')
        from velociraptor_observation_config import load_approved
        def load():
            archive=load_approved();close=archive.group.close
            def counted():
                self.group_closes.append('close');return close()
            archive.group.close=counted
            return archive
        self.fixture.stack.enter_context(patch('velociraptor_observation_config.load_approved',side_effect=load))
        self.addCleanup(self.release)

    def release(self):
        # Baseline failures can leave acquired native resources. Explicitly
        # release only after this test has no worker, to protect the test host.
        if self.controller is not None and not self.controller._ledger._closed:
            self.controller._ledger._closed=True
            self.controller._ledger._cleanup()

    def open(self,instance=INSTANCE):
        self.controller=SessionController.open_approved(instance)
        self.server._observation_controller=self.controller
        self.assertTrue(self.fs.handles)
        return self.controller

    def trace(self,layer,error):
        c=self.controller
        row=dict(test=self.id(),layer=layer,error_type=type(error).__name__,error=str(error),
            notes=getattr(error,'__notes__',[]),ledger_closed=c._ledger._closed,
            ledger_unknown=c._ledger._unknown,group_close_calls=len(self.group_closes),
            native_handles_remaining=len(self.fs.handles),controller_state=c._state,
            startup_phase=getattr(c,'_startup_phase','R09_NO_MARKER'))
        TRACES.append(row)
        return row

    def closed_once(self,error,layer):
        row=self.trace(layer,error)
        self.assertTrue(row['ledger_closed'],row)
        self.assertEqual(row['group_close_calls'],1,row)
        self.assertEqual(row['native_handles_remaining'],0,row)
        self.controller._abort_startup(error)
        self.assertEqual(len(self.group_closes),1)

    def main(self,**callbacks):
        actual=SessionController.open_approved
        def opened(instance):
            self.controller=actual(instance);return self.controller
        with patch.object(bridge,'resolve_transport_config',return_value=self.config),patch.object(bridge,'create_server',return_value=self.server),patch.object(SessionController,'open_approved',side_effect=opened):
            return bridge.main(**callbacks)

    def test_actual_bridge_ready_stop_drains_native_resources_once(self):
        ready=[]
        self.server._guest_transfer_tools=Mock()
        def on_ready():
            ready.append(self.controller._startup_phase)
            self.assertTrue(self.fs.handles)
        self.assertEqual(self.main(on_ready=on_ready,stop_requested=lambda:True),0)
        self.assertEqual(ready,['ACTIVE'])
        self.assertEqual(self.controller._state,'CLOSED')
        self.server._guest_transfer_tools.shutdown.assert_called_once_with()
        self.closed_once(RuntimeError('MODEL-success-diagnostic'),'actual bridge ready / local port zero / stop / real drain')

    def test_actual_bridge_config_failure_closes_acquired_native_resources(self):
        primary=RuntimeError('MODEL-uvicorn-config-failure')
        self.server._guest_transfer_tools=Mock()
        with patch('uvicorn.Config',side_effect=primary),self.assertRaises(RuntimeError) as caught:
            self.main()
        self.assertIs(caught.exception,primary)
        self.server._guest_transfer_tools.shutdown.assert_called_once_with()
        self.closed_once(primary,'actual bridge / actual app built / Config')

    def test_server_constructor_failure_after_config(self):
        import uvicorn
        self.open();primary=RuntimeError('MODEL-server-constructor-failure')
        with patch.object(uvicorn.Server,'__init__',side_effect=primary),self.assertRaises(RuntimeError) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary);self.closed_once(primary,'server __init__')

    def test_run_before_lifespan_baseexception_preserves_primary(self):
        import uvicorn
        self.open();primary=KeyboardInterrupt('MODEL-before-lifespan')
        with patch.object(uvicorn.Server,'run',side_effect=primary),self.assertRaises(KeyboardInterrupt) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary);self.closed_once(primary,'run before lifespan BaseException')

    def test_no_started_return_cleans_and_reports_readiness(self):
        import uvicorn
        self.open()
        with patch.object(uvicorn.Server,'run',return_value=None),self.assertRaisesRegex(RuntimeError,'did not reach readiness') as caught:
            transport.run_formal_http(self.server,self.config)
        self.closed_once(caught.exception,'uvicorn returned not started without lifespan')

    def test_manager_run_call_failure_before_enter(self):
        self.open();app=transport.build_formal_http_app(self.server,self.config)
        primary=RuntimeError('MODEL-manager-run-call')
        async def execute():
            with patch.object(_TrackedManager,'run',side_effect=primary):
                async with app.router.lifespan_context(app):pass
        with self.assertRaises(RuntimeError) as caught:asyncio.run(execute())
        self.assertIs(caught.exception,primary);self.closed_once(primary,'manager.run before context enter')

    def test_actual_sdk_app_lifespan_enter_failure(self):
        primary=RuntimeError('MODEL-SDK-app-enter')
        @asynccontextmanager
        async def broken(server):
            raise primary
            yield
        self.server=MCPServer('MODEL-failed-sdk-enter',lifespan=broken)
        self.open();app=transport.build_formal_http_app(self.server,self.config)
        async def execute():
            async with app.router.lifespan_context(app):pass
        with self.assertRaises(RuntimeError) as caught:asyncio.run(execute())
        self.assertIs(caught.exception,primary)
        self.assertIsNone(self.controller._manager._task_group)
        self.closed_once(primary,'actual SDK manager entering real app lifespan')

    def test_uvicorn_actual_swallowed_lifespan_error_retains_original(self):
        primary=RuntimeError('MODEL-actual-uvicorn-lifespan-failure')
        @asynccontextmanager
        async def broken(server):
            raise primary
            yield
        self.server=MCPServer('MODEL-uvicorn-enter-failure',lifespan=broken)
        self.open()
        # Actual uvicorn never binds: the real lifespan reports startup.failed.
        with redirect_stderr(StringIO()),self.assertRaises(RuntimeError) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary)
        self.closed_once(primary,'actual uvicorn startup.failed / swallowed ASGI error')

    def test_uvicorn_lifespan_failed_unstarted_return_retains_original(self):
        import uvicorn
        from uvicorn.lifespan.on import LifespanOn
        primary=RuntimeError('MODEL-unstarted-lifespan-cause')
        @asynccontextmanager
        async def broken(server):
            raise primary
            yield
        self.server=MCPServer('MODEL-unstarted',lifespan=broken)
        self.open()
        def returned(http_server):
            http_server.lifespan=LifespanOn(http_server.config)
            asyncio.run(http_server.lifespan.startup())
            self.assertTrue(http_server.lifespan.startup_failed)
            self.assertFalse(http_server.started)
        with patch.object(uvicorn.Server,'run',returned),redirect_stderr(StringIO()),self.assertRaises(RuntimeError) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary)
        self.closed_once(primary,'actual uvicorn LifespanOn failed / unstarted return seam')

    def test_app_build_failure_closes_already_acquired_controller(self):
        self.open();primary=RuntimeError('MODEL-app-build')
        with patch.object(transport,'build_formal_http_app',side_effect=primary),self.assertRaises(RuntimeError) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary);self.closed_once(primary,'app build after approved acquisition')

    def test_active_manager_exit_fault_keeps_body_primary_and_real_drain(self):
        primary=RuntimeError('MODEL-body-before-exit');secondary=OSError('MODEL-SDK-lifespan-exit')
        @asynccontextmanager
        async def broken_exit(server):
            try:yield {}
            finally:raise secondary
        self.server=MCPServer('MODEL-manager-exit',lifespan=broken_exit)
        self.open();app=transport.build_formal_http_app(self.server,self.config)
        async def execute():
            async with app.router.lifespan_context(app):raise primary
        with self.assertRaises(RuntimeError) as caught:asyncio.run(execute())
        self.assertIs(caught.exception,primary)
        self.assertIs(caught.exception.__cause__,secondary)
        self.assertIn('observation_manager_exit_failed',primary.__notes__)
        self.closed_once(primary,'actual SDK app exit secondary after real drain')

    def test_cleanup_fault_preserves_original_and_continues_other_closes(self):
        import uvicorn
        self.open();primary=RuntimeError('MODEL-original-config-failure')
        actual=self.controller._exporter.close;secondary=OSError('MODEL-exporter-close-after-release')
        def failed():actual();raise secondary
        with patch.object(self.controller._exporter,'close',side_effect=failed),patch.object(uvicorn,'Config',side_effect=primary),self.assertRaises(RuntimeError) as caught:
            transport.run_formal_http(self.server,self.config)
        self.assertIs(caught.exception,primary)
        self.assertIn('archive_resource_close_failed',primary.__notes__)
        self.closed_once(primary,'cleanup fault after real exporter release')

    def test_active_lifespan_body_primary_preserved_when_drain_fails(self):
        self.open();app=transport.build_formal_http_app(self.server,self.config)
        primary=RuntimeError('MODEL-active-body');secondary=OSError('MODEL-drain-failure')
        async def execute():
            with patch.object(self.controller,'_drain',side_effect=secondary):
                async with app.router.lifespan_context(app):raise primary
        with self.assertRaises(RuntimeError) as caught:asyncio.run(execute())
        self.assertIs(caught.exception,primary)
        row=self.trace('active lifespan cleanup fault / retain',primary)
        self.assertEqual(row['controller_state'],'UNKNOWN');self.assertFalse(row['ledger_closed'])
        self.assertEqual(row['group_close_calls'],0);self.assertTrue(self.fs.handles)
        self.assertIn('observation_drain_failed',primary.__notes__)
        self.controller._abort_startup(primary)
        self.assertFalse(self.controller._ledger._closed)

    def test_cancelled_active_lifespan_drains_and_closes_once(self):
        self.open();app=transport.build_formal_http_app(self.server,self.config)
        primary=asyncio.CancelledError('MODEL-lifespan-cancel')
        async def execute():
            async with app.router.lifespan_context(app):raise primary
        with self.assertRaises(asyncio.CancelledError) as caught:asyncio.run(execute())
        self.assertIs(caught.exception,primary);self.closed_once(primary,'active lifespan cancellation / actual drain')

    def test_live_native_thread_cannot_be_stolen_by_startup_abort(self):
        self.open();started=threading.Event();release=threading.Event();primary=RuntimeError('MODEL-loop-failure')
        def io():
            started.set();release.wait(3)
        async def execute():
            c=self.controller
            task=asyncio.create_task(c._owned_close_io(None,io,time.monotonic_ns()+3_000_000_000,'startup-test'))
            while not started.is_set():await asyncio.sleep(.001)
            c._abort_startup(primary)
            row=self.trace('actual non-daemon I/O alive / retain',primary)
            self.assertFalse(row['ledger_closed']);self.assertEqual(row['group_close_calls'],0)
            self.assertEqual(row['controller_state'],'UNKNOWN');self.assertTrue(self.fs.handles)
            native=c._close_io[(None,'startup-test')]
            self.assertTrue(native.thread.is_alive());self.assertFalse(native.joined)
            release.set();await task
            self.assertTrue(native.joined);self.assertFalse(native.thread.is_alive())
            c._abort_startup(primary)
            self.assertFalse(c._ledger._closed) # UNKNOWN cannot gain a false closed receipt.
        try:asyncio.run(execute())
        finally:release.set()

    def test_backend_baseexception_closes_before_transport(self):
        primary=SystemExit('MODEL-backend-baseexception')
        actual=SessionController.open_approved
        def opened(instance):self.controller=actual(instance);return self.controller
        with patch.object(bridge,'resolve_transport_config',return_value=self.config),patch.object(SessionController,'open_approved',side_effect=opened),patch.object(bridge,'create_server',side_effect=primary),self.assertRaises(SystemExit) as caught:
            bridge.main()
        self.assertIs(caught.exception,primary);self.closed_once(primary,'backend BaseException before transport')

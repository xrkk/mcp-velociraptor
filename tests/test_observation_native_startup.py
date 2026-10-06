"""Fixed complete POSIX approval/freeze loading with MODEL Windows native APIs.

No approval issuance and no backend/VM/listener. The production constructors
are exercised; only native OS factories are replaced inside these tests.
"""
import copy
from contextlib import ExitStack
import inspect
from io import StringIO
from contextlib import redirect_stderr
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import velociraptor_observation_namespace as namespace
import velociraptor_observation_windows as windows
import velociraptor_observation_attempts as ledger
import velociraptor_observation_export as export
import velociraptor_observation_startup as startup
from velociraptor_observation_controller import SessionController
from velociraptor_transport import build_formal_http_app, TransportConfig
from tests import p05_pc026_governance as gov
from tests import test_observation_startup as lifecycle_fixture
from tests.test_observation_attempts import ArchiveFS, INSTANCE
from tests.test_observation_windows import ROOT, session
from tests.test_p05_pc026_governance import inventory


class ApprovedNativeStartup(unittest.TestCase):
    def setUp(self):
        self.fixture=lifecycle_fixture.LifecyclePreflightTests('test_real_complete_loader_reads_actual_sdk_and_rechecks_without_writer')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.f=self.fixture.f
        self.fs=ArchiveFS()
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for p in (patch.object(gov,'REPOSITORY',self.root),
                patch.object(namespace,'_session',side_effect=lambda:session(self.fs)),
                patch.object(namespace,'_directory_api',return_value=self.fs),
                patch.object(windows,'_session',side_effect=lambda:session(self.fs)),
                patch.object(windows,'_writer_api',return_value=self.fs),
                patch.object(ledger,'WindowsSession',side_effect=lambda:session(self.fs)),
                patch.object(export,'WindowsSession',side_effect=lambda:session(self.fs)),
                patch.object(export,'_free_bytes',return_value=2**40)):
            self.stack.enter_context(p)

    def test_full_fixed_loader_preflight_construct_and_transport_share_one_group_instance(self):
        from mcp.server.mcpserver import MCPServer
        before=inventory(self.root)
        with patch.object(gov,'load',wraps=gov.load) as load:
            controller=SessionController.open_approved(INSTANCE)
        self.assertEqual(load.call_count,1)
        self.addCleanup(lambda:controller._ledger.close() if not controller._ledger._closed else None)
        self.assertIs(controller._exporter._ledger,controller._ledger)
        self.assertIs(controller._exporter._config.group,controller._ledger._config.group)
        self.assertIsNot(controller._exporter._allocator,controller._ledger._allocator)
        self.assertFalse(controller._exporter._instance_dir)
        server=MCPServer('MODEL-native-entry');server._observation_controller=controller
        with patch.object(gov,'load',side_effect=AssertionError('second group')):
            app=build_formal_http_app(server,TransportConfig('http',host='127.0.0.1',bearer_token='MODEL',observation_enabled=True))
        self.assertIs(app.state.observation_controller,controller)
        self.assertIs(app.state.transfer_bindings.manager,controller._manager)
        self.assertEqual(app.state.transfer_bindings.instance,INSTANCE)
        self.assertEqual(inventory(self.root),before)
        controller._ledger.close();self.assertFalse(self.fs.handles)

    def test_missing_approval_source_drift_and_omitted_native_closure_before_mkdir_backend(self):
        import mcp_velociraptor_bridge as bridge
        paths=('velociraptor_observation_export.py','tests/test_observation_native_export.py','tests/test_observation_native_startup.py')
        for mode in ('missing','drift',*paths):
            saved=None
            if mode=='missing':
                path=self.root/gov.APPROVAL;saved=path.read_bytes();path.unlink()
            elif mode=='drift':
                path=self.root/'velociraptor_observation_export.py';saved=path.read_bytes();path.write_bytes(saved+b'\n# MODEL drift\n')
            else:
                saved=self.f.freeze.pop(mode);self.f.refresh()
                self.fixture.fixture.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE]
                self.fixture.fixture.bind()
                from velociraptor_observation_config import CONFIG
                self.fixture.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE]
                self.fixture.doc['archive_config_ref']=self.f.refs[CONFIG];self.fixture.bind()
            before=inventory(self.root)
            with self.subTest(mode=mode),patch.object(bridge,'resolve_transport_config',return_value=SimpleNamespace(mode='http',observation_enabled=True)),patch.object(bridge,'create_server') as backend,redirect_stderr(StringIO()):
                self.assertEqual(bridge.main(),2);backend.assert_not_called()
            self.assertEqual(inventory(self.root),before);self.assertFalse(self.fs.created);self.assertFalse(self.fs.handles)
            if mode in ('missing','drift'):path.write_bytes(saved)
            else:
                self.f.freeze[mode]=saved
                self.f.refresh();self.fixture.fixture.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE];self.fixture.fixture.bind()
                self.fixture.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE];self.fixture.doc['archive_config_ref']=self.f.refs[CONFIG];self.fixture.bind()

    def test_exporter_construction_error_reverse_cleanup_group_once_primary_preserved(self):
        primary=RuntimeError('MODEL-export-construction')
        from velociraptor_observation_config import load_approved
        group_close=[]
        actual=load_approved
        def loaded():
            config=actual();original=config.group.close
            def close():group_close.append('close');original()
            config.group.close=close
            return config
        with patch('velociraptor_observation_config.load_approved',side_effect=loaded),patch.object(export.NativeExporter,'_borrow',side_effect=primary),self.assertRaises(RuntimeError) as caught:
            SessionController.open_approved(INSTANCE)
        self.assertIs(caught.exception,primary);self.assertEqual(group_close,['close']);self.assertFalse(self.fs.handles)

    def test_root_full_sd_drift_and_export_candidate_refuse_before_writer(self):
        from tests.test_observation_windows import sd
        self.fs.nodes[str(ROOT)]['sd']=sd(foreign='S-1-5-11')
        with self.assertRaises(Exception):SessionController.open_approved(INSTANCE)
        self.assertFalse(self.fs.created);self.assertFalse(self.fs.handles)
        self.assertEqual(set(inspect.signature(SessionController.open_approved).parameters),{'instance_id'})
        with self.assertRaises(TypeError):export.NativeExporter()

    def test_isolated_freeze_imports_current_native_export_and_controller_without_escape(self):
        import subprocess,sys
        code='''import sys
from pathlib import Path
root=Path(sys.argv[1]);original=Path(sys.argv[2]);sys.path.insert(0,str(root))
def audit(event,args):
 if event=='open' and isinstance(args[0],(str,bytes)):
  p=Path(args[0])
  if p.is_absolute() and p.is_relative_to(original) and not (p.is_relative_to(root) or p.is_relative_to(original/'.venv')):raise AssertionError('source escape')
sys.addaudithook(audit)
import velociraptor_observation_export,velociraptor_observation_controller,velociraptor_transport
from velociraptor_observation_config import load_approved
from velociraptor_observation_startup import _precheck_loaded
c=load_approved();_precheck_loaded(c);c.group.close();print('ISOLATED_NATIVE_SOURCE_OK')
'''
        run=subprocess.run([sys.executable,'-I','-B','-c',code,str(self.root),str(gov.REPOSITORY)],capture_output=True,text=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertIn('ISOLATED_NATIVE_SOURCE_OK',run.stdout)

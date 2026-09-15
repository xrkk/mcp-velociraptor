"""Regressions for the actual P05 acceptance process-protection seam."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests import p05_real_acceptance as acceptance


class ProtectedProcessTests(unittest.TestCase):
    def test_child_binding_rejects_wrong_parent_command_executable_and_reused_pid(self):
        from tests import p05_process_parent as parent
        argv=parent.command('frontend')
        owner={'ProcessId':100,'CreationDate':'2026-09-13T00:00:00Z'}
        child={'ProcessId':101,'ParentProcessId':100,'CreationDate':'2026-09-13T00:00:01Z',
               'CommandLine':parent.subprocess.list2cmdline(argv),'ExecutablePath':argv[0]}
        with patch.object(parent.os,'getpid',return_value=100):
            parent.verify_child_binding(owner,child,101,argv)
            for change in ({'ParentProcessId':99},{'ProcessId':102},{'CommandLine':'foreign'},
                           {'ExecutablePath':r'C:\foreign.exe'},{'CreationDate':'2026-09-12T00:00:00Z'}):
                with self.subTest(change=change),self.assertRaises(ValueError):
                    parent.verify_child_binding(owner,{**child,**change},101,argv)

    def test_fixture_readiness_requires_this_preparer_and_exact_process_identity(self):
        from tests import p05_process_parent as parent
        preparer={'ProcessId':42,'CreationDate':'2026-09-13T00:00:00Z'}
        target={'pid':1304,'creation_time_utc':'2026-09-13T00:00:01Z',
                'token':parent.WORKFLOW+'|'+parent.FIXTURE_ATTEMPT,
                'command_line':'python sleep '+parent.WORKFLOW+' '+parent.FIXTURE_ATTEMPT}
        instance={'workflow_id':parent.WORKFLOW,'attempt_id':parent.FIXTURE_ATTEMPT,'process':target}
        observed={'ProcessId':1304,'ParentProcessId':42,'CreationDate':target['creation_time_utc'],
                  'CommandLine':target['command_line']}
        with patch.object(parent,'require_plain_path'), \
             patch.object(Path,'read_bytes',return_value=json.dumps(instance).encode()):
            with patch.object(acceptance,'process_identity',side_effect=[observed,preparer]):
                self.assertEqual(parent.await_fixture_binding(preparer)['process_identity'],observed)
            for change in ({'ParentProcessId':43},{'CreationDate':'2026-09-13T00:00:02Z'},
                           {'CommandLine':target['command_line']+' extra'}):
                with self.subTest(change=change), \
                     patch.object(acceptance,'process_identity',return_value={**observed,**change}), \
                     self.assertRaises(ValueError):
                    parent.await_fixture_binding(preparer)
            with patch.object(acceptance,'process_identity',side_effect=[observed,None]),self.assertRaises(ValueError):
                parent.await_fixture_binding(preparer)
            with patch.object(acceptance,'process_identity',return_value=None), \
                 patch.object(parent.time,'monotonic',side_effect=[0,31]),self.assertRaises(RuntimeError):
                parent.await_fixture_binding(preparer)

    def test_interrupted_child_wait_retains_role_lock(self):
        from tests import p05_process_parent as parent
        for failure in (KeyboardInterrupt(),OSError('wait failed')):
            process=Mock(pid=1234)
            process.wait.side_effect=failure
            with tempfile.TemporaryDirectory() as directory, \
                 patch.object(parent.subprocess,'Popen',return_value=process), \
                 patch.object(acceptance,'process_identity',side_effect=RuntimeError('observation failed')):
                root=Path(directory)
                with self.assertRaises(type(failure)):
                    with parent.role_lock(root,'frontend'):
                        parent.launch('frontend',parent.command('frontend'),root)
                self.assertTrue((root/'frontend.active.lock').exists())
                with self.assertRaises(FileExistsError):
                    with parent.role_lock(root,'frontend'):
                        self.fail('uncertain child permitted a duplicate launcher')

    def test_parent_waits_for_child_when_identity_observation_fails(self):
        from tests import p05_process_parent as parent
        process=Mock(pid=1234)
        process.wait.return_value=0
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(parent.subprocess,'Popen',return_value=process), \
             patch.object(acceptance,'process_identity',side_effect=RuntimeError('private observation detail')):
            with self.assertRaises(RuntimeError):
                parent.launch('frontend',parent.command('frontend'),Path(directory))
            process.wait.assert_called_once_with()
            process.terminate.assert_not_called()
            process.kill.assert_not_called()

    def test_parent_role_lock_rejects_concurrent_same_role(self):
        from tests.p05_process_parent import role_lock
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with role_lock(root,'frontend'):
                with self.assertRaises(FileExistsError):
                    with role_lock(root,'frontend'):
                        self.fail('concurrent launcher entered')
            self.assertFalse((root/'frontend.active.lock').exists())

    def test_backend_parent_rejects_live_predecessor_and_observation_failure(self):
        from tests.p05_process_parent import require_absent_predecessor
        for count in ('1','2','invalid'):
            with patch.object(acceptance,'powershell',return_value=count),self.assertRaises(ValueError):
                require_absent_predecessor('frontend')
        with patch.object(acceptance,'powershell',return_value='0'):
            require_absent_predecessor('frontend')
        with patch.object(acceptance,'powershell',side_effect=RuntimeError('observation failed')),self.assertRaises(RuntimeError):
            require_absent_predecessor('client')

    def test_fixture_parent_rejects_live_pid_or_foreign_identity(self):
        from tests import p05_process_parent as parent
        fixture={'workflow_id':parent.WORKFLOW,'attempt_id':parent.FIXTURE_ATTEMPT,'process':{'pid':1304}}
        with patch.object(parent,'require_plain_path'),patch.object(Path,'read_text',return_value=json.dumps(fixture)):
            with patch.object(acceptance,'process_snapshot',return_value=[{'ProcessId':1304}]),self.assertRaises(ValueError):
                parent.require_absent_predecessor('fixture')
            with patch.object(acceptance,'process_snapshot',return_value=[]):
                parent.require_absent_predecessor('fixture')
        for key in ('workflow_id','attempt_id'):
            with patch.object(parent,'require_plain_path'), \
                 patch.object(Path,'read_text',return_value=json.dumps({**fixture,key:'foreign'})),self.assertRaises(ValueError):
                parent.require_absent_predecessor('fixture')

    def test_parent_roles_have_no_command_pid_or_config_override(self):
        from tests.p05_process_parent import command
        for role in ('frontend','client'):
            argv=command(role)
            self.assertEqual(argv[1:4],['-v',role,'--config'])
            self.assertTrue(argv[0].endswith('velociraptor-v0.77.2-windows-amd64.exe'))
        self.assertIn('Start-Sleep -Seconds 86400',command('fixture')[-1])
        with self.assertRaises(ValueError):
            command('arbitrary-command')

    def test_complete_parent_identities_are_retained(self):
        pairs = [(0,0,'System Idle Process'),(4,0,'System'),(100,99,'python.exe'),
                 (99,98,'powershell.exe'),(98,4,'controller.exe'),
                 (7604,5660,'velociraptor.exe'),(5760,1580,'velociraptor.exe'),
                 (5660,98,'launcher.exe'),(1580,98,'launcher.exe')]
        rows = [dict(ProcessId=pid,ParentProcessId=parent,Name=name,CreationDate='2026-09-11T00:00:00Z')
                for pid,parent,name in pairs]
        with patch.object(acceptance.os,'getpid',return_value=100), \
             patch.object(acceptance.os,'getppid',return_value=99), \
             patch.object(acceptance,'powershell',return_value=json.dumps(rows)):
            self.assertEqual({row['ProcessId'] for row in acceptance.protected_processes()},
                             {row['ProcessId'] for row in rows})

    def test_missing_velociraptor_parent_cannot_be_silently_omitted(self):
        # Reproduce Snapshot186: the two Velociraptor children are alive,
        # but their recorded launcher PIDs are absent from the process table.
        rows = [dict(ProcessId=pid, ParentProcessId=parent, Name=name,
                     CreationDate='2026-09-11T00:00:00Z', CommandLine='')
                for pid, parent, name in [(0,0,'System Idle Process'),(4,0,'System'),
                    (100,99,'python.exe'),(99,98,'powershell.exe'),
                    (7604,5660,'velociraptor.exe'),(5760,1580,'velociraptor.exe')]]
        with patch.object(acceptance.os,'getpid',return_value=100), \
             patch.object(acceptance.os,'getppid',return_value=99), \
             patch.object(acceptance,'powershell',return_value=json.dumps(rows)):
            with self.assertRaisesRegex(ValueError,'protected.*parent'):
                acceptance.protected_processes()

    def test_fixture_absence_pid_reuse_command_change_and_protected_target_rejected(self):
        target = dict(pid=1304,creation_time_utc='2026-09-04T23:42:32.923Z',
                      token='wf-test|p05-test',command_line='python sleep wf-test p05-test')
        observed = dict(ProcessId=1304,CreationDate=target['creation_time_utc'],CommandLine=target['command_line'])
        acceptance.verify_fixture_process(target,observed,workflow_id='wf-test',attempt_id='p05-test',protected=[])
        acceptance.verify_fixture_process(target,{**observed,'CreationDate':'2026-09-04T23:42:32.9234567Z'},
                                          workflow_id='wf-test',attempt_id='p05-test',protected=[])
        for value,protected in [(None,[]),({**observed,'CreationDate':'2026-09-11T00:00:00Z'},[]),
                                ({**observed,'CommandLine':target['command_line']+' extra'},[]),
                                (observed,[{'ProcessId':1304}])]:
            with self.subTest(observed=value),self.assertRaises(ValueError):
                acceptance.verify_fixture_process(target,value,workflow_id='wf-test',attempt_id='p05-test',protected=protected)


class GuardedKillTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_snapshot_includes_preparer_and_no_observation_intervenes_before_call(self):
        rows = [dict(ProcessId=pid,ParentProcessId=parent,Name=name,CreationDate='2026-09-11T00:00:00Z')
                for pid,parent,name in [(0,0,'System'),(4,0,'System'),(100,99,'python.exe'),
                    (99,98,'powershell.exe'),(98,4,'controller.exe'),(42,43,'preparer.exe'),
                    (43,98,'parent.exe'),(7604,5660,'velociraptor.exe'),(5660,98,'parent.exe'),
                    (5760,1580,'velociraptor.exe'),(1580,98,'parent.exe')]]
        target=dict(pid=1304,creation_time_utc='2026-09-11T00:00:01.123Z',
                    token=acceptance.WORKFLOW_ID+'|p05-test',
                    command_line='python sleep '+acceptance.WORKFLOW_ID+' p05-test')
        rows.append(dict(ProcessId=1304,ParentProcessId=42,Name='python.exe',
                         CreationDate=target['creation_time_utc'],CommandLine=target['command_line']))
        for missing in (None,42,43):
            sequence=[]
            def snapshot(pid):
                self.assertEqual(pid,1304)
                sequence.append('snapshot')
                return [row for row in rows if row['ProcessId']!=missing]
            async def call(*args):
                sequence.append('call')
                return {'is_error':False}
            with patch.object(acceptance.os,'getpid',return_value=100), \
                 patch.object(acceptance.os,'getppid',return_value=99), \
                 patch.object(acceptance,'process_snapshot',side_effect=snapshot), \
                 patch.object(acceptance,'call',side_effect=call) as product_call:
                if missing is None:
                    _,_,protected=await acceptance.guarded_kill(None,{},target,'p05-test')
                    self.assertTrue({42,43}<={row['ProcessId'] for row in protected})
                    self.assertEqual(sequence,['snapshot','call'])
                else:
                    with self.assertRaises(ValueError):
                        await acceptance.guarded_kill(None,{},target,'p05-test')
                    product_call.assert_not_called()


if __name__=='__main__':
    unittest.main()

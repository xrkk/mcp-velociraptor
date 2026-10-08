"""Local contract negatives; native kernel coverage is separately required."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import uuid

from velociraptor_linux_domain import register_linux_domain_tools, LinuxDomainError
from velociraptor_linux_scope import ScopeBackend, validate_request, process, canonical
from velociraptor_linux_worker import Worker
from velociraptor_linux_probe import program, decode


def request(action='apply'):
    p = process(os.getpid())
    p.pop('alive')
    return dict(session_id=str(uuid.uuid4()), owner_id=str(uuid.uuid4()),
                operation_id=str(uuid.uuid4()), client_id='C.123', vm_uuid=str(uuid.uuid4()),
                boot_id=str(uuid.uuid4()), targets=[p], lifetime_seconds=30)


class ScopeTests(unittest.TestCase):
    def test_missing_and_reused_targets_fail_before_side_effect(self):
        for change in ({'targets': []}, {'targets': [{'pid': os.getpid(), 'birth': '1', 'uid': os.getuid()}]},
                       {'lifetime_seconds': 0}, {'targets': ['pid:1']}):
            r = dict(request(), **change)
            backend = ScopeBackend(Mock(root=Path('/missing'), binding={}))
            with patch.object(backend, '_identity') as identity, patch.object(backend, '_apply') as apply:
                with self.assertRaises((LinuxDomainError, ValueError)):
                    backend.call('apply', r)
                identity.assert_not_called()
                apply.assert_not_called()

    def test_extension_requires_targets_reason_expiry_and_termination(self):
        r = request()
        r.pop('lifetime_seconds')
        r.update(reason='related fork', termination='end of bounded observation', expires_in_seconds=10)
        validate_request('extend', r)
        for name in ('reason', 'targets', 'expires_in_seconds', 'termination'):
            bad = dict(r)
            bad.pop(name)
            with self.assertRaises(LinuxDomainError):
                validate_request('extend', bad)

    def test_wrong_client_and_boot_no_directory(self):
        for field in ('client_id', 'boot_id', 'vm_uuid'):
            r = request()
            professional = Mock(root=Path('/missing'), binding={k: r[k] for k in ('client_id', 'boot_id', 'vm_uuid')})
            r[field] = 'C.wrong' if field == 'client_id' else str(uuid.uuid4())
            b = ScopeBackend(professional)
            with patch.object(b, '_apply') as apply:
                with self.assertRaises(LinuxDomainError):
                    b.call('apply', r)
                apply.assert_not_called()

    def test_foreign_owner_stop_no_request_written(self):
        with tempfile.TemporaryDirectory() as d:
            r = request()
            r.pop('targets'); r.pop('lifetime_seconds')
            root = Path(d); directory = root / 'scopes' / r['session_id']
            directory.mkdir(parents=True)
            (directory / 'premise.json').write_bytes(canonical(dict(r, owner_id=str(uuid.uuid4()))))
            b = ScopeBackend(Mock(root=root, binding={k:r[k] for k in ('client_id','vm_uuid','boot_id')}))
            with patch('velociraptor_linux_scope.private_path', side_effect=lambda p, **_: Path(p)):
                with self.assertRaises(LinuxDomainError):
                    b.call('stop', r)
            self.assertEqual(list(directory.iterdir()), [directory/'premise.json'])

    def test_registry_has_no_memory_success_fallback(self):
        server = Mock(); entries = {}
        server.add_tool.side_effect = lambda f, **kw: entries.update({kw['name']: f})
        register_linux_domain_tools(server)
        for name in ('linux_scope_apply', 'linux_scope_get', 'linux_scope_stop'):
            with self.assertRaisesRegex(LinuxDomainError, 'NO_TRIAGE_BACKEND'):
                entries[name](request={})

    def test_kernel_source_has_birth_inheritance_and_independent_expiry(self):
        r=request()['targets'][0]
        source=program([dict(r, until_ns=1234567, root_pid=r['pid'], root_birth=r['birth'])], 1234568, 10**7)
        self.assertIn('start_boottime / 10000000', source)
        self.assertIn('@until[$cpid, $cbirth] = @until[pid,', source)
        self.assertIn('> nsecs && nsecs < 1234568', source)
        self.assertIn('interval:s:1', source)
        self.assertIn('kretfunc:do_filp_open', source)
        self.assertIn('$f->f_mode & 0x100000', source)
        self.assertIn('(uint64)$f < (uint64)-4095', source)
        for name in ('fork', 'exec', 'exit', 'create', 'modify', 'delete', 'rename', 'connect'):
            self.assertIn('"'+name+'"', source)
        with self.assertRaises(ValueError):
            decode('{"type":"lost_events","data":4}', 1)

    def test_withdraw_uses_latest_default_and_no_stale_children(self):
        w=Worker.__new__(Worker)
        w.premise={'deadline_ns':10**20}
        a=dict(pid=101, birth='2',uid=1000); b=dict(pid=102,birth='3',uid=1000)
        w.state={'default_targets':[b], 'extension':None}
        w.known={(103,'4'):dict(pid=103,birth='4',uid=1000,root_pid=101,root_birth='2')}
        with patch('velociraptor_linux_worker.alive',return_value=True):
            self.assertEqual([x['pid'] for x in w.active_targets()], [102])

    def test_query_missing_worker_not_applied_and_never_drives_expiry(self):
        b=ScopeBackend(Mock(root=Path('/unused')))
        state={'status':'APPLIED','worker':None,'probe':None,'backend_applied':True, 'deadline_ns':0}
        with patch('velociraptor_linux_scope.read',return_value=state), patch('velociraptor_linux_scope.publish',return_value={}):
            answer=b._snapshot(Path('/unused'))
        self.assertEqual(answer['status'],'UNKNOWN')
        self.assertFalse(answer['backend_applied'])

    def test_repeated_terminal_stop_preserves_exported_originals(self):
        backend=ScopeBackend(Mock(root=Path('/unused')))
        state={'status':'STOPPED','probe':None,'worker':None}
        with patch.object(backend,'_snapshot',return_value={'status':'STOPPED'}) as snapshot, \
             patch('velociraptor_linux_scope.atomic') as write:
            answer=backend._recover_stop(Path('/unused'),state)
            self.assertEqual(answer['status'],'STOPPED')
            write.assert_not_called()
            snapshot.assert_called_once()

    def test_worker_expiry_runs_without_any_query(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)
            for n in ('requests','responses'): (directory/n).mkdir()
            r=request(); r.update(deadline_ns=100, tick_ns=10**7)
            (directory/'premise.json').write_bytes(canonical(r))
            clock=[0]; actions=[]
            class LocalWorker(Worker):
                def start_probe(self):
                    self.child=Mock(); self.child.poll.return_value=None
                    self.state.update(status='APPLIED',backend_applied=True)
                    actions.append('start')
                def stop_probe(self):
                    if self.child is not None:
                        actions.append('stop'); self.child=None
                def drain(self, wait=0): clock[0]+=10
            with patch('velociraptor_linux_scope.private_path',side_effect=lambda p,**_:Path(p)), \
                 patch('velociraptor_linux_worker.now',side_effect=lambda:clock[0]), \
                 patch('velociraptor_linux_worker.signal.signal'):
                w=LocalWorker(directory)
                w.state['extension']={'targets':r['targets'],'expires_ns':20}
                w.run()
            self.assertEqual(w.state['status'],'EXPIRED')
            self.assertIsNone(w.state['extension'])
            self.assertEqual(actions,['start','stop','start','stop'])
            self.assertTrue(any(x['action']=='extension_expired' for x in w.state['transitions']))

    def test_stop_failure_propagates(self):
        w=Worker.__new__(Worker); w.premise=request(); w.state={}; w.fault=None
        r={k:v for k,v in w.premise.items() if k not in ('targets','lifetime_seconds')}
        w.transition=Mock()
        def failed(): w.fault='PROBE_FORCED_KILL'
        w.stop_probe=failed
        with self.assertRaisesRegex(LinuxDomainError,'PROBE_FORCED_KILL'):
            w.change(dict(r,action='stop',requested_ns=1))
        self.assertNotEqual(w.state.get('status'), 'STOPPED')


if __name__ == '__main__':
    unittest.main()

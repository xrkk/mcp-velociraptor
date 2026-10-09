"""Explicit synthetic source fixtures; these never certify native execution."""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import velociraptor_linux_scheduler as source


def fixture():
    root = dict(boot_id='boot', pid=123, start_time='42')
    actor = dict(pid=123, birth='42', parent_pid=10, uids=[1201]*4, gids=[2201]*4,
                 groups=[], image='/fixture/sample', inode=1, device=2049, cgroup='0::/root', cmdline=['/fixture/sample'])
    manager = dict(actor, pid=901, birth='90', image='/usr/lib/systemd/systemd', image_sha256='b'*64)
    config = dict(directory='/opt/t42/objects', service='one.service', timer='one.timer', payload='payload',
                  manager=manager, socket='/run/user/1201/systemd/private', window_seconds=12)
    binding = dict(session_id='session', owner_id='owner', boot_id='boot', vm_uuid='vm', client_id='client')
    rows = []
    def row(kind, stamp, **kw):
        rows.append(dict(kind=kind, monotonic_ns=stamp, **kw))
    row('intent', 200, source=source.SOURCE, config=config, binding=binding, root=root, directory_inode=500, directory_device=2049)
    row('fresh', 210, peer=[901,1201,2201], absent=['one.service','one.timer'], units={n:dict(LoadState='not-found',ActiveState='inactive',FragmentPath='',ActivationDetails=[],InvocationID=[]) for n in ('one.service','one.timer')})
    row('ready', 220, deadline_ns=90000000000)
    payload = b'\x7fELFexplicit-local-fixture-only'
    service = b'[Unit]\nDescription=fixture\nDefaultDependencies=no\nRefuseManualStart=yes\n[Service]\nType=exec\nExecStart=/opt/t42/objects/payload\nRestart=no\nRuntimeMaxSec=4s\nStandardOutput=journal\nStandardError=journal\n'
    timer = b'[Unit]\nDescription=fixture\nDefaultDependencies=no\n[Timer]\nUnit=one.service\nOnActiveSec=3s\nAccuracySec=1ms\nRemainAfterElapse=yes\nPersistent=no\n'
    files = {}
    for i, (name, raw) in enumerate([('payload',payload),('one.service',service),('one.timer',timer)]):
        files[name] = dict(path='/opt/t42/objects/'+name, inode=600+i, device=2049, size=len(raw), sha256=source.sha(raw),content=base64.b64encode(raw).decode())
        row('closed-write', 1000*(i+1), actor=copy.deepcopy(actor), file=files[name], lease='F_RDLCK')
    for i, name in enumerate(('one.service','one.timer')):
        row('manager-open',3500+500*i,actor=manager,file=copy.deepcopy(files[name]))
    fired = dict(actor,pid=902,birth='91',parent_pid=901,image='/opt/t42/objects/payload',inode=600,cgroup='0::/user/one.service',cmdline=['/opt/t42/objects/payload'])
    row('exec-open',10001000,actor=dict(fired,image='/usr/lib/systemd/systemd-executor'),file=copy.deepcopy(files['payload']))
    sp = dict(ActivationDetails=[['trigger_unit','one.timer'],['trigger_timer_monotonic_usec','10000'],['trigger_timer_realtime_usec','2000000']],
              InvocationID=list(range(16)),MainPID=902,ControlGroup='/user/one.service',FragmentPath=files['one.service']['path'],DropInPaths=[],
              ExecStart=[[files['payload']['path'],[files['payload']['path']],False,0,0,0,0,902,0,0]],NRestarts=0,RefuseManualStart=1)
    tp = dict(Unit='one.service',LastTriggerUSecMonotonic=10000,TimersMonotonic=[['OnActiveUSec',3000000,10000]],FragmentPath=files['one.timer']['path'],DropInPaths=[],Persistent=0,ActivationDetails=[])
    row('invocation',11000000,actor=fired,service=sp,timer=tp,peer=[901,1201,2201])
    row('closed',12000000,error=None,lease_broken=False)
    events = []
    for kind, stamp, detail in [('exec',300,['/fixture/sample']),('modify',500,['payload',500,8388609,30]),('modify',1500,['one.service',500,8388609,100]),('modify',2500,['one.timer',500,8388609,100]),('exit',5000000,[0])]:
        events.append(dict(kind=kind,monotonic_ns=stamp,pid=123,birth='42',uid=1201,root_pid=123,root_birth='42',detail=detail,generation=1,source='fixture-kernel',strings_may_be_truncated=False))
    return rows, dict(config=config,binding=binding,root=root,credentials=actor,kernel=events)


class SchedulerSourceTests(unittest.TestCase):
    def test_complete_chain_comes_only_from_closed_source_facts(self):
        rows, args = fixture()
        result = source.normalize(rows, **args)
        self.assertEqual([e['kind'] for e in result],['artifact','definition','scheduler-fire'])
        self.assertEqual(result[2]['fired_instance']['pid'],902)
        self.assertEqual(result[1]['definition_version'],result[2]['fire_definition_version'])
        self.assertTrue(all(e['source_rows'] for e in result))

    def test_missing_facts_never_degrade_to_same_name_or_time(self):
        for kind in ('closed-write','manager-open','exec-open','invocation','fresh','ready','closed'):
            with self.subTest(kind=kind):
                rows,args=fixture();rows.remove(next(r for r in rows if r['kind']==kind))
                with self.assertRaises((ValueError,KeyError)):source.normalize(rows,**args)

    def test_mutations_wrong_writer_manual_start_reuse_and_old_trigger_refuse(self):
        changes = {
            'writer':lambda r,a:r[3]['actor'].update(pid=999),
            'reused-writer':lambda r,a:r[3]['actor'].update(birth='999'),
            'hash':lambda r,a:r[3]['file'].update(sha256='c'*64),
            'loaded-content':lambda r,a:r[6]['file'].update(content=base64.b64encode(b'new').decode()),
            'replacement':lambda r,a:r[8]['file'].update(inode=999),
            'lease-break':lambda r,a:r[-1].update(lease_broken=True),
            'manual-same-image':lambda r,a:r[9]['actor'].update(parent_pid=10),
            'controller-start':lambda r,a:r[9]['service'].update(ActivationDetails=[]),
            'old-trigger':lambda r,a:r[9]['service']['ActivationDetails'][1].__setitem__(1,'1'),
            'definition-changed':lambda r,a:r[9]['service'].update(ExecStart=[['/other',['/other'],False]]),
            'root-uid':lambda r,a:r[9]['actor'].update(uids=[0]*4),
            'pid-reuse':lambda r,a:r[9]['actor'].update(birth='999'),
            'wrong-boot':lambda r,a:a['root'].update(boot_id='foreign'),
            'old-unit':lambda r,a:r[1]['units']['one.service'].update(InvocationID=[1]*16),
            'existing-definition':lambda r,a:r[1]['units']['one.service'].update(LoadState='loaded'),
            'expired':lambda r,a:r[2].update(deadline_ns=1000),
            'unready':lambda r,a:r[2].update(monotonic_ns=100000),
            'restart':lambda r,a:r[9]['service'].update(NRestarts=1),
            'unknown-scope':lambda r,a:a['kernel'][0].update(root_birth='999'),
            'dead-author':lambda r,a:a['kernel'].insert(2,dict(a['kernel'][-1],monotonic_ns=800)),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                rows,args=fixture();change(rows,args)
                with self.assertRaises((ValueError,KeyError)):source.normalize(rows,**args)


class LivePropertyBoundaryTests(unittest.TestCase):
    def test_cgroup_uses_service_interface_and_partial_facts_survive_error(self):
        from unittest.mock import patch
        rows, args = fixture()
        for fail in (False, True):
            with self.subTest(fail=fail):
                captured = []
                class Manager:
                    peer = rows[9]['peer']
                    def get(self, unit, interface, name, signature):
                        if name == 'ControlGroup':
                            if interface != 'Service':raise OSError(53, 'wrong interface')
                            if fail:raise OSError(53, 'explicit later source failure')
                        return rows[9]['service' if unit.endswith('.service') else 'timer'][name]
                observer = source.Collector.__new__(source.Collector)
                observer.config=args['config'];observer.directory=Path(args['config']['directory']);observer.error=None;observer.last_tick=0
                observer.execs=[(rows[8]['actor'],rows[8]['file'])]
                observer.invocation=None;observer.manager=Manager()
                observer.record=lambda kind,**kw:captured.append(dict(kind=kind,**kw))
                with patch.object(source,'process',return_value=rows[9]['actor']):
                    if fail:
                        with self.assertRaises(OSError):observer.tick()
                    else:observer.tick()
                self.assertEqual(captured[0]['kind'],'invocation-probe')
                self.assertEqual(captured[0]['actor'],rows[9]['actor'])
                self.assertEqual(observer.invocation,rows[9]['service']['InvocationID'])
                self.assertEqual(any(r['kind']=='invocation' for r in captured),not fail)


if __name__ == '__main__':
    unittest.main()


class OnlineFollowTests(unittest.TestCase):
    def observer(self, mutate=None, call_error=None, process_error=None, live_change=None, source_error=False):
        from unittest.mock import patch
        import threading
        rows, args = fixture()
        rows = rows[:-1]
        actor=dict(rows[9]['actor'],image_sha256=rows[3]['file']['sha256'])
        if mutate:
            mutate(rows, args)
        observer = source.FollowingCollector.__new__(source.FollowingCollector)
        observer.config=args['config']; observer.binding=args['binding']; observer.root=args['root']
        observer.credentials=args['credentials']; observer.records=rows
        observer.follow_attempted=False; observer.error=None; observer.lease_broken=source_error
        observer.finish_event=threading.Event(); observer.lock=threading.Lock()
        observer.kernel_prefix=lambda:(args['kernel'], dict(path='fixture', size=10, sha256='f'*64))
        captured=[]
        def record(kind, **kw):
            row=dict(kind=kind, monotonic_ns=13000000, **kw); captured.append(row); rows.append(row); return row
        observer.record=record
        class Client:
            def call(self, tool, arguments):
                captured.append(dict(tool=tool,arguments=arguments))
                if call_error:raise call_error
                request=arguments['request']
                return dict(args['binding'],status='APPLIED',backend_applied=True,generation=2,
                    extension=dict(request,expires_ns=12000000000),
                    transitions=[dict(action='applied',generation=2,ready_ns=14000000)])
        observer.client=Client()
        if live_change:actor.update(live_change)
        with patch.object(source.Collector,'tick'), patch.object(source,'process',return_value=actor,side_effect=process_error), \
             patch.object(source.Path,'read_text',return_value='boot'), \
             patch.object(source.time,'monotonic_ns',return_value=13000000):
            observer.tick();observer.tick()
        return captured

    def test_complete_online_chain_causes_exactly_one_actual_extend_call(self):
        records=self.observer()
        calls=[r for r in records if 'tool' in r]
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]['tool'],'linux_scope_extend')
        self.assertEqual(calls[0]['arguments']['request']['targets'],[dict(pid=902,birth='91',uid=1201)])
        self.assertEqual(records[-1]['kind'],'admission-ready')
        self.assertGreater(records[-1]['fire_to_ready_ns'],0)

    def test_incomplete_wrong_boot_reused_dead_or_same_image_never_calls_scope(self):
        changes=[lambda r,a:r.pop(3),
            lambda r,a:a['binding'].update(boot_id='wrong'),
            lambda r,a:r[8]['actor'].update(birth='reuse'),
            lambda r,a:r[9]['service'].update(ActivationDetails=[]),
            lambda r,a:r[9]['actor'].update(parent_pid=10),
            lambda r,a:a['kernel'].append(dict(a['kernel'][-1],monotonic_ns=5000001))]
        for change in changes:
            with self.subTest(change=change):
                records=self.observer(change)
                self.assertFalse(any('tool' in r for r in records))
                self.assertEqual(records[-1]['kind'],'admission-insufficient')

    def test_unknown_extension_is_preserved_and_never_retried(self):
        records=self.observer(call_error=TimeoutError('unknown extension outcome'))
        self.assertEqual(sum('tool' in r for r in records),1)
        self.assertEqual(records[-1]['kind'],'admission-insufficient')

    def test_live_identity_loss_and_source_error_refuse(self):
        for options in [dict(process_error=FileNotFoundError('dead')),
                        dict(live_change=dict(birth='reused')),
                        dict(live_change=dict(uids=[0]*4)), dict(source_error=True)]:
            with self.subTest(options=options):
                records=self.observer(**options)
                self.assertFalse(any('tool' in r for r in records))
                self.assertEqual(records[-1]['kind'],'admission-insufficient')

    def test_expired_window_cannot_extend_scope(self):
        records=self.observer(lambda r,a:a['config'].update(window_seconds=1))
        self.assertFalse(any('tool' in r for r in records))
        self.assertIn('insufficient admission window',records[-1]['error'])


class ExecTransitionTests(unittest.TestCase):
    def test_empty_argv_during_exec_does_not_consume_first_invocation(self):
        from unittest.mock import patch
        rows,args=fixture();observer=source.Collector.__new__(source.Collector)
        observer.config=args['config'];observer.directory=Path(args['config']['directory'])
        observer.error=None;observer.last_tick=0;observer.execs=[(rows[8]['actor'],rows[8]['file'])]
        observer.invocation=None;captured=[]
        observer.record=lambda kind,**kw:captured.append(dict(kind=kind,**kw))
        class Manager:
            peer=rows[9]['peer']
            def get(self,unit,interface,name,signature):
                return rows[9]['service' if unit.endswith('.service') else 'timer'][name]
        observer.manager=Manager()
        with patch.object(source,'process',return_value=dict(rows[9]['actor'],cmdline=[])):
            observer.tick()
        self.assertIsNone(observer.invocation)
        self.assertEqual([r['kind'] for r in captured],['exec-transition'])
        observer.last_tick=0
        with patch.object(source,'process',return_value=rows[9]['actor']):observer.tick()
        self.assertEqual(sum(r['kind']=='invocation' for r in captured),1)

"""Local synthetic service source checks; not native acceptance."""
import base64
import copy
import unittest
from unittest.mock import patch
import velociraptor_linux_scheduler as source
import test_linux_scheduler as timer_tests
fixture = timer_tests.fixture


def service_fixture():
    rows, args = fixture()
    config = args['config']
    config.pop('timer')
    config['mechanism'] = 'service'
    rows[0]['source'] = 'MalTrace.UserService.v1'
    rows[1]['absent'] = ['one.service']
    rows[1]['units'].pop('one.timer')
    rows = [r for r in rows if not (r['kind'] in ('closed-write', 'manager-open') and r['file']['path'].endswith('.timer'))]
    for row in rows:
        if row['kind'] in ('closed-write', 'manager-open') and row['file']['path'].endswith('.service'):
            raw = base64.b64decode(row['file']['content']).replace(b'RefuseManualStart=yes', b'RefuseManualStart=no')
            row['file'].update(content=base64.b64encode(raw).decode(), sha256=source.sha(raw), size=len(raw))
        if row['kind'] == 'invocation':
            row['timer'] = {}
            row['service'].update(ActivationDetails=[], RefuseManualStart=0)
    args['kernel'] = [e for e in args['kernel'] if not (e['kind'] == 'modify' and e['detail'][0] == 'one.timer')]
    return rows, args


class ServiceSourceTests(unittest.TestCase):
    def test_first_observed_service_uses_version_and_invocation(self):
        rows, args = service_fixture()
        result = source.normalize(rows, **args)
        self.assertEqual(result[1]['definition_mechanism'], 'service')
        self.assertEqual(result[1]['definition_id'], 'user:1201:one.service')
        self.assertEqual(result[-1]['monotonic_ns'], next(r['monotonic_ns'] for r in rows if r['kind']=='exec-open'))
        self.assertEqual(result[-1]['execution_identity']['uids'], [1201]*4)

    def test_service_can_qualify_before_root_exit(self):
        rows, args = service_fixture()
        args['kernel'] = [e for e in args['kernel'] if e['kind'] != 'exit']
        self.assertEqual(source.qualify(rows[:-1], boundary_ns=12000000, **args)[1]['definition_mechanism'], 'service')

    def test_no_timer_profile_guessing(self):
        rows, args = service_fixture()
        for change in (lambda c:c.pop('mechanism'), lambda c:c.update(timer='one.timer'),
                       lambda c:c.update(mechanism='cron'),lambda c:c['manager'].update(uids=[0]*4)):
            config = copy.deepcopy(args['config']); change(config)
            with self.subTest(config=config), self.assertRaises(ValueError):
                source.validate_profile(config)

    def test_names_or_time_without_actual_chain_never_qualify(self):
        changes = [
            lambda r,a:r.remove(next(x for x in r if x['kind']=='manager-open')),
            lambda r,a:r.remove(next(x for x in r if x['kind']=='exec-open')),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['actor'].update(parent_pid=10),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['service'].update(InvocationID=[0]*16),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['service'].update(ActivationDetails=[['trigger_unit','other.timer']]),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['service'].update(ControlGroup='/other'),
            lambda r,a:next(x for x in r if x['kind']=='manager-open').update(monotonic_ns=11000000),
            lambda r,a:next(x for x in r if x['kind']=='closed-write')['actor'].update(pid=999),
            lambda r,a:next(x for x in r if x['kind']=='exec-open')['file'].update(inode=999),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['service'].update(NRestarts=1),
            lambda r,a:r[-1].update(lease_broken=True),
            lambda r,a:next(x for x in r if x['kind']=='invocation')['actor'].update(uids=[0]*4),
            lambda r,a:a['kernel'].insert(1,dict(a['kernel'][-1],monotonic_ns=400)),
        ]
        for change in changes:
            with self.subTest(change=change):
                rows,args=service_fixture();change(rows,args)
                with self.assertRaises((ValueError,KeyError)):source.normalize(rows,**args)

    def test_native_property_collection_does_not_query_timer(self):
        rows,args=service_fixture();captured=[]
        observer=source.Collector.__new__(source.Collector)
        observer.config=args['config'];observer.directory=source.Path(args['config']['directory'])
        observer.error=None;observer.last_tick=0;observer.invocation=None
        opened=next(x for x in rows if x['kind']=='exec-open')
        fired=next(x for x in rows if x['kind']=='invocation')
        observer.execs=[(opened['actor'],opened['file'])]
        observer.record=lambda kind,**kw:captured.append(dict(kind=kind,**kw))
        class Manager:
            peer=fired['peer']
            def get(self,unit,interface,name,signature):
                assert unit=='one.service'
                return fired['service'][name]
        observer.manager=Manager()
        with patch.object(source,'process',return_value=fired['actor']):observer.tick()
        self.assertEqual(captured[-1]['timer'],{})
        self.assertEqual(captured[-1]['kind'],'invocation')

    def test_online_service_before_exit_extends_exact_live_actor_once(self):
        def obtain():
            rows,args=service_fixture();args['kernel']=[e for e in args['kernel'] if e['kind']!='exit']
            # Preserve the legacy helper's row offsets without adding facts.
            rows.insert(5, dict(kind='diagnostic',monotonic_ns=3000))
            rows.insert(7, dict(kind='diagnostic',monotonic_ns=4000))
            return rows,args
        with patch('test_linux_scheduler.fixture',side_effect=obtain):
            records=timer_tests.OnlineFollowTests().observer()
        self.assertEqual(sum('tool' in r for r in records),1)
        self.assertEqual(records[-1]['kind'],'admission-ready')
        intent=next(r for r in records if r['kind']=='admission-intent')
        self.assertIn('user service',intent['request']['reason'])

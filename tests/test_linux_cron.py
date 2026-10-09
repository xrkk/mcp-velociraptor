"""Local synthetic crond source checks; native delivery is separate."""
import base64
import copy
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from unittest.mock import patch
import velociraptor_linux_scheduler as shared
import velociraptor_linux_cron as cron
import test_linux_scheduler as old


def fixture(schedule='calendar'):
    rows,a=old.fixture();root=a['credentials'];m=a['config']['manager'];m.update(uids=[0]*4,gids=[0]*4,image='/opt/carrier/busybox',image_sha256='b'*64)
    c=dict(directory='/opt/t42/objects',payload='payload',crontab='sampleuser',mechanism='cron',schedule=schedule,manager=m,
           launcher=dict(m,image='/usr/bin/python3.12',image_sha256='c'*64),daemon_argv=[],manager_unit='cron-one.service',
           manager_unit_file='/run/systemd/system/cron-one.service',manager_unit_sha256='d'*64,log='/opt/t42/daemon.log',
           window_seconds=85 if schedule=='calendar' else 18,reboot_marker_absent=True)
    c['daemon_argv']=[m['image'],'crond','-f','-l','0','-L',c['log'],'-c',c['directory']];m['cmdline']=c['daemon_argv'];c['launcher']['cmdline']=['/usr/bin/python3.12','/fixture/launcher.py']
    a['config']=c;rows[0].update(source=cron.SOURCE,config=c)
    rows[1]=dict(kind='fresh',monotonic_ns=210,launcher=c['launcher'],empty_spool=True,log_inode=77,log_device=2049,reboot_marker_absent=True,pidfile_absent=True)
    rows=[r for r in rows if not(r['kind'] in ('closed-write','manager-open') and r['file']['path'].endswith('.timer'))]
    text='MAILTO=\n'+('@reboot' if schedule=='@reboot' else '5 10 9 10 5')+' exec /opt/t42/objects/payload\n'
    for r in rows:
        if r['kind'] in ('closed-write','manager-open') and r['file']['path'].endswith('.service'):
            r['file'].update(path='/opt/t42/objects/sampleuser',content=base64.b64encode(text.encode()).decode(),sha256=shared.sha(text.encode()),size=len(text))
    fire=next(r for r in rows if r['kind']=='invocation');actor=fire['actor'];actor['image_sha256']=rows[3]['file']['sha256']
    log='crond: crond (busybox 1.36.1) started, log level 0\ncrond: USER sampleuser pid 902 cmd exec /opt/t42/objects/payload\n'
    fire.clear();fire.update(kind='cron-invocation',monotonic_ns=11000000,actor=actor,daemon=m,log_base64=base64.b64encode(log.encode()).decode(),log_inode=77,log_device=2049,dispatch_line=log.splitlines()[-1],marker=dict(inode=78,device=2049,uid=0,size=0,mode=0o100000),table_owner=0,table_mode=0o600,wall_ns=10000000000)
    a['kernel']=[e for e in a['kernel'] if not(e['kind']=='modify' and e['detail'][0]=='one.timer')]
    for e in a['kernel']:
        if e['kind']=='modify' and e['detail'][0]=='one.service':e['detail'][0]='sampleuser'
    return rows,a


class CronSourceTests(unittest.TestCase):
    def test_calendar_and_startup_preserve_actual_cron_subtype(self):
        for schedule in ('calendar','@reboot'):
            rows,a=fixture(schedule);v=shared.normalize(rows,**a)
            self.assertEqual(v[1]['definition_mechanism'],'cron')
            self.assertEqual(v[1]['definition_schedule'],schedule)
            self.assertEqual(v[-1]['execution_identity']['uids'],[1201]*4)
            self.assertIn(schedule,v[1]['definition_id'])
            self.assertEqual(v[-1]['fired_instance']['boot_id'],a['root']['boot_id'])

    def test_source_refuses_unproven_load_dispatch_identity_and_version(self):
        changes=[lambda r,a:r.remove(next(x for x in r if x['kind']=='manager-open')),
                 lambda r,a:r.remove(next(x for x in r if x['kind']=='exec-open')),
                 lambda r,a:r.remove(next(x for x in r if x['kind']=='closed-write')),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation')['actor'].update(uids=[0]*4),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation')['actor'].update(parent_pid=2),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation').update(dispatch_line='foreign'),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation')['marker'].update(uid=1201),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation').update(table_owner=1201),
                 lambda r,a:next(x for x in r if x['kind']=='fresh').update(reboot_marker_absent=False),
                 lambda r,a:next(x for x in r if x['kind']=='closed-write')['file'].update(inode=999),
                 lambda r,a:next(x for x in r if x['kind']=='cron-invocation').update(log_inode=99),
                 lambda r,a:r[-1].update(error='explicit source failure')]
        for change in changes:
            rows,a=fixture();change(rows,a)
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):shared.normalize(rows,**a)

    def test_late_identical_table_read_preserves_first_dispatch_proof(self):
        for schedule in ('calendar', '@reboot'):
            rows, args = fixture(schedule)
            online = shared.qualify(rows[:-1], boundary_ns=11500000, **args)
            late = copy.deepcopy(next(r for r in rows if r['kind'] == 'manager-open'))
            late['monotonic_ns'] = 11500000
            rows.insert(-1, late)
            self.assertEqual(shared.normalize(rows, **args), online)
            self.assertNotIn(len(rows) - 1, online[1]['source_rows'])

    def test_late_wrong_table_version_or_reader_still_refuses(self):
        for change in (lambda r: r['file'].update(inode=999),
                       lambda r: r['file'].update(sha256='f'*64),
                       lambda r: r['actor'].update(birth='reused'),
                       lambda r: r['actor'].update(uids=[1201]*4)):
            rows, args = fixture()
            late = copy.deepcopy(next(r for r in rows if r['kind'] == 'manager-open'))
            late['monotonic_ns'] = 11500000
            change(late)
            rows.insert(-1, late)
            with self.subTest(change=change), self.assertRaises(ValueError):
                shared.normalize(rows, **args)

    def test_post_dispatch_load_cannot_replace_missing_initial_load(self):
        rows, args = fixture()
        load = next(r for r in rows if r['kind'] == 'manager-open')
        rows.remove(load)
        load['monotonic_ns'] = 11500000
        rows.insert(-1, load)
        with self.assertRaisesRegex(ValueError, 'cron write/load/exec order'):
            shared.normalize(rows, **args)

    def test_uncontrolled_daemon_profiles_never_pass(self):
        for change in (lambda c:c.update(window_seconds=86),lambda c:c.update(reboot_marker_absent=False),
                       lambda c:c['daemon_argv'].append('--other'),lambda c:c.update(manager_unit_file='/etc/foreign'),
                       lambda c:c['launcher'].update(birth='other')):
            rows,a=fixture();change(a['config'])
            with self.subTest(change=change),self.assertRaises(ValueError):shared.validate_profile(a['config'])

    def test_factory_preserves_user_collector_and_selects_cron_explicitly(self):
        rows,a=fixture()
        with patch('velociraptor_linux_cron.CronCollector',return_value='cron') as ctor:
            self.assertEqual(shared.create_collector(a['config'],1,2,3,4,5),'cron');ctor.assert_called_once()
        _,a=old.fixture()
        with patch.object(shared,'FollowingCollector',return_value='timer'):
            self.assertEqual(shared.create_collector(a['config'],1,2,3,4,5),'timer')

    def test_complete_online_calendar_extends_exact_live_actor(self):
        import threading
        rows,a=fixture();actor=next(r for r in rows if r['kind']=='cron-invocation')['actor']
        observer=cron.CronCollector.__new__(cron.CronCollector);observer.config=a['config'];observer.binding=a['binding'];observer.root=a['root'];observer.credentials=a['credentials'];observer.records=rows[:-1];observer.follow_attempted=False;observer.error=None;observer.lease_broken=False;observer.finish_event=threading.Event();observer.lock=threading.Lock()
        observer.kernel_prefix=lambda:(a['kernel'],dict(path='fixture',size=10,sha256='f'*64));captured=[]
        observer.record=lambda kind,**kw:captured.append(dict(kind=kind,**kw))
        class Client:
            def call(self,tool,args):
                captured.append(dict(tool=tool,args=args));return dict(a['binding'],status='APPLIED',backend_applied=True,generation=2,extension=dict(args['request'],expires_ns=75000000000),transitions=[dict(action='applied',generation=2,ready_ns=14000000)])
        observer.client=Client()
        with patch.object(shared,'process',return_value=actor),patch.object(shared.Path,'read_text',return_value='boot'),patch.object(shared.time,'monotonic_ns',return_value=13000000):observer.admit();observer.admit()
        self.assertEqual(sum('tool' in r for r in captured),1)
        self.assertEqual(captured[-1]['kind'],'admission-ready')

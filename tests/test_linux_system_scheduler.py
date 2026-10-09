"""Synthetic PID1 source checks, separate from native acceptance."""
import base64
import copy
import unittest
import velociraptor_linux_scheduler as source
import test_linux_scheduler as timers
import test_linux_user_service as services


def system_fixture(mode):
    rows,args=services.service_fixture() if mode=='service' else timers.fixture()
    c=args['config'];c.update(manager_scope='system',socket='/run/systemd/private')
    c['manager'].update(pid=1,birth='1',uids=[0]*4,gids=[0]*4)
    for r in rows:
        if r['kind']=='intent':r['source']=source.source_name(c)
        if r['kind'] in ('fresh','invocation'):r['peer']=[1,0,0]
        if r['kind'] in ('exec-open','invocation'):r['actor']['parent_pid']=1
        if r['kind'] in ('closed-write','manager-open') and r['file']['path'].endswith('.service'):
            raw=base64.b64decode(r['file']['content']).replace(b'Type=exec\n',b'Type=exec\nUser=1201\nGroup=2201\n')
            r['file'].update(content=base64.b64encode(raw).decode(),size=len(raw),sha256=source.sha(raw))
    return rows,args


class SystemSourceTests(unittest.TestCase):
    def test_manager_is_root_payload_remains_ordinary(self):
        for mode in ('service','timer'):
            with self.subTest(mode=mode):
                rows,args=system_fixture(mode);events=source.normalize(rows,**args)
                self.assertEqual(events[1]['definition_id'],'system:one.'+mode)
                self.assertEqual(events[-1]['execution_identity']['uids'],[1201]*4)
                self.assertEqual(events[-1]['execution_identity']['parent_pid'],1)

    def test_manager_profile_rejects_foreign_or_guessed_scope(self):
        for change in (lambda c:c.update(socket='/run/foreign'),lambda c:c['manager'].update(pid=901),
                       lambda c:c['manager'].update(uids=[0,0,0,1201]),lambda c:c.update(manager_scope='guess'),
                       lambda c:c.pop('manager_scope')):
            rows,args=system_fixture('service');change(args['config'])
            with self.subTest(change=change),self.assertRaises(ValueError):source.validate_profile(args['config'])

    def test_loaded_definition_must_bind_actual_ordinary_identity(self):
        for key,value in ((b'User=1201',b'User=0'),(b'Group=2201',b'Group=other'),(b'User=1201\n',b'')):
            rows,args=system_fixture('service')
            for row in rows:
                if row['kind'] in ('closed-write','manager-open') and row['file']['path'].endswith('.service'):
                    raw=base64.b64decode(row['file']['content']).replace(key,value)
                    row['file'].update(content=base64.b64encode(raw).decode(),size=len(raw),sha256=source.sha(raw))
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):source.normalize(rows,**args)

    def test_same_name_manual_other_process_or_incomplete_chain_refuses(self):
        for mode in ('service','timer'):
            for change in (lambda r:r.remove(next(x for x in r if x['kind']=='manager-open')),
                           lambda r:next(x for x in r if x['kind']=='invocation')['actor'].update(parent_pid=901),
                           lambda r:next(x for x in r if x['kind']=='invocation')['service'].update(DropInPaths=['foreign']),
                           lambda r:next(x for x in r if x['kind']=='invocation')['actor'].update(uids=[0]*4)):
                rows,args=system_fixture(mode);change(rows)
                with self.subTest(mode=mode,change=change),self.assertRaises(ValueError):source.normalize(rows,**args)

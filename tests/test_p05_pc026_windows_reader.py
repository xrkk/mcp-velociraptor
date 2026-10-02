"""Explicit native-reader unit models; Windows API evidence lives separately."""
import asyncio
import hashlib
import os
from pathlib import PureWindowsPath
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import p05_pc026_windows_reader as native
from tests import p05_pc026_governance as gov
from velo_transfer import windows_platform as acl

SID = 'S-1-5-21-1-2-3-1001'


def sd(*, foreign=None, mask=0x1F01FF):
    def sid(value):
        nums = [int(x) for x in value.split('-')[2:]]
        return bytes((1,len(nums)-1))+nums[0].to_bytes(6,'big')+b''.join(struct.pack('<I',x) for x in nums[1:])
    owner = sid(SID)
    aces = []
    for value, rights in ((SID,0x1F01FF), *(([(foreign,mask)]) if foreign else [])):
        encoded = sid(value);aces.append(struct.pack('<BBHI',0,0,8+len(encoded),rights)+encoded)
    dacl = struct.pack('<BBHHH',2,0,8+sum(map(len,aces)),len(aces),0)+b''.join(aces)
    return struct.pack('<BBHIIII',1,0,0x8004,20,0,0,20+len(owner))+owner+dacl


class FakeIO:
    def __init__(self):
        self.pending={};self.next=0;self.closed=[];self.raw=sd();self.data=b'original';self.alias=None;self.drift=False
    def open(self,path,directory):
        self.next+=1;self.pending[self.next]=(str(path),directory);return self.next
    def identity(self,handle,directory):
        path,_=self.pending[handle];return 1,hashlib.md5(path.encode()).digest()
    def descriptor(self,handle):return self.raw
    def metadata(self,handle):return len(self.data),1,2,3,0
    def name(self,handle):return self.alias or self.pending[handle][0]
    def rewind(self,handle):self.remaining=self.data
    def read(self,handle):
        chunk=self.remaining;self.remaining=b'';return chunk
    def close(self,handle):self.closed.append(handle);del self.pending[handle]


class NativeReaderModels(unittest.TestCase):
    def reader(self):
        # This construction is an explicit unit model, never production init.
        reader=native.WindowsSession.__new__(native.WindowsSession)
        reader.sid=SID;reader.trusted=frozenset(('S-1-5-18','S-1-5-32-544',SID))
        reader.api=FakeIO();reader.objects={};reader.closed=False;reader.lock=threading.RLock()
        self.addCleanup(reader.close)
        return reader
    def test_path_escape_aliases(self):
        native.check_path(r'C:\controlled\project\ordinary.json')
        for name in (r'\\server\share\x',r'\\?\C:\x',r'C:\x:stream',r'C:\x\..\file',r'C:\x.\file',r'C:\x \file',r'C:\CON',r'C:\SHORT~1\x',r'c:\x'):
            with self.subTest(name=name),self.assertRaises(native.NativeReadError):native.check_path(name)
    def test_descriptor_uses_original_bytes_and_conservative_policy(self):
        value=native.descriptor_snapshot(sd())
        acl._evaluate(value,'state',frozenset((SID,)))
        foreign=sd(foreign='S-1-5-11',mask=0x1)
        acl._evaluate(native.descriptor_snapshot(foreign),'policy',frozenset((SID,)))
        with self.assertRaisesRegex(acl.Error,'untrusted_read'):
            acl._evaluate(native.descriptor_snapshot(foreign),'state',frozenset((SID,)))
        with self.assertRaisesRegex(acl.Error,'untrusted_write'):
            acl._evaluate(native.descriptor_snapshot(sd(foreign='S-1-5-11')),'ancestor',frozenset((SID,)))
        for raw in (b'',sd()[:-1],sd().replace(b'\x04\x80',b'\x00\x80',1)):
            with self.assertRaises((native.NativeReadError,acl.Error)):native.descriptor_snapshot(raw)
    def test_retained_chain_rechecks_and_closes(self):
        reader=self.reader();path=PureWindowsPath(r'C:\controlled\file.json')
        data,identity,publication=reader.read(path,private=True)
        self.assertEqual(data,b'original');self.assertEqual(publication['file_id'],identity[-1][0][1].hex())
        self.assertEqual(publication['acl_sha256'],hashlib.sha256(sd()).hexdigest())
        self.assertEqual(len(reader.objects),3)
        self.assertEqual(reader.read(path,private=True),(data,identity,publication))
        reader.api.raw=sd(foreign='S-1-5-11')
        with self.assertRaisesRegex(native.NativeReadError,'drift'):reader.read(path,private=True)
        reader.close();self.assertFalse(reader.api.pending);self.assertEqual(len(reader.api.closed),len(set(reader.api.closed)))
    def test_close_waits_for_retained_read_transaction(self):
        reader=self.reader();entered=threading.Event();release=threading.Event();closed=threading.Event()
        original=reader.api.read
        def blocked(handle):
            entered.set()
            if not release.wait(2):raise RuntimeError('test release timeout')
            return original(handle)
        reader.api.read=blocked
        values=[]
        def read():values.append(reader.read(PureWindowsPath(r'C:\controlled\file.json')))
        thread=threading.Thread(target=read);thread.start()
        self.assertTrue(entered.wait(2))
        closer=threading.Thread(target=lambda:(reader.close(),closed.set()));closer.start()
        try:self.assertFalse(closed.wait(0.02))
        finally:release.set();thread.join(2);closer.join(2)
        self.assertFalse(thread.is_alive());self.assertFalse(closer.is_alive())
        self.assertTrue(closed.is_set());self.assertEqual(values[0][0],b'original')
    def test_final_path_alias_rejected_with_close(self):
        reader=self.reader();reader.api.alias=r'C:\OTHER'
        with self.assertRaisesRegex(native.NativeReadError,'alias'):reader.read(PureWindowsPath(r'C:\controlled\file.json'))
        self.assertFalse(reader.api.pending)
    def test_production_native_constructor_never_selects_mock(self):
        if os.name!='nt':
            with self.assertRaisesRegex(native.NativeReadError,'unavailable'):native.WindowsSession()
    def test_effect_rechecks_and_outer_scope_closes_on_error(self):
        events=[]
        group=SimpleNamespace(recheck=lambda:events.append('recheck'),close=lambda:events.append('close'))
        @gov.consumption
        async def run():
            gov._CONSUMPTION.get().append(group)
            gov.before_effect()
            raise RuntimeError('stopped')
        with self.assertRaisesRegex(RuntimeError,'stopped'):asyncio.run(run())
        self.assertEqual(events,['recheck','close'])
        self.assertIsNone(gov._CONSUMPTION.get())
    def test_scope_closes_all_groups_without_masking_primary(self):
        events=[]
        def bad_close():
            events.append('bad close');raise RuntimeError('secondary close')
        @gov.consumption
        def run():
            gov._CONSUMPTION.get().extend([
                SimpleNamespace(close=lambda:events.append('good close')),
                SimpleNamespace(close=bad_close)])
            raise RuntimeError('primary failure')
        with self.assertRaisesRegex(RuntimeError,'primary failure') as error:run()
        self.assertEqual(events,['bad close','good close'])
        self.assertIn('secondary close',str(error.exception.__notes__))
        self.assertIsNone(gov._CONSUMPTION.get())
    def test_drift_preserves_failure_facts_and_zero_coverage(self):
        from tests.p06_pc026_binding import Admission
        admission=Admission.__new__(Admission)
        admission.recheck=lambda:(_ for _ in ()).throw(gov.GovernanceError('revoked'))
        report={'status':'success','coverage':[{'tool':'synthetic'}],'calls':[{'fact':'already happened'}],'failure':None}
        admission.finish_report(report)
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(report['calls'],[{'fact':'already happened'}]);self.assertIn('revoked',report['failure']['message'])
    def test_business_effect_rechecks_consumed_run_stage_before_call(self):
        from tests.p06_pc026_binding import Admission
        group=gov.GovernedGroup(PureWindowsPath(r'C:\controlled'),{}, {}, {}, {}, {}, {},True)
        admission=Admission(group,b'',None)
        path=PureWindowsPath(r'C:\controlled\current-restore.json')
        current=[(b'approved run/stage',('identity',),{})]
        effects=[]
        @gov.consumption
        def run():
            gov._CONSUMPTION.get().append(group)
            admission.read(path)
            current[0]=(b'replaced run/stage',('other identity',),{})
            gov.before_effect()
            effects.append('business call')
        with patch.object(gov,'_read',side_effect=lambda *args,**kwargs:current[0]):
            with self.assertRaisesRegex(gov.GovernanceError,'consumer input drift'):run()
        self.assertEqual(effects,[])
    def test_host_archive_requires_complete_acl_original(self):
        from tests.p05_pc020_evidence import canonical_json
        identity={'mode':'0600','owner_uid':'1','owner_gid':'1'}
        value={**identity,'extended_acl':[{'name':name,'value_hex':None} for name in ('system.posix_acl_access','system.posix_acl_default')]}
        gov._host_descriptor(canonical_json(value),identity)
        value['extended_acl'].pop()
        with self.assertRaisesRegex(gov.GovernanceError,'missing'):gov._host_descriptor(canonical_json(value),identity)
    def test_guest_deployment_principal_and_root_are_local(self):
        group=SimpleNamespace(endpoint='guest',repository=PureWindowsPath(r'C:\controlled\project'),reader=SimpleNamespace(sid=SID))
        deployment={'host_project_root':'/controlled/host','guest_deployment_base':r'C:\controlled','guest_project_coordinate':'project','guest_principal_sid':SID,'vm_uuid':gov.VM_UUID}
        with patch.object(acl,'observe_windows',return_value=SimpleNamespace(vm_uuid=gov.VM_UUID)):
            gov._deployment_binding(group,deployment)
            for key,bad in (('guest_principal_sid','S-1-5-18'),('guest_project_coordinate','other'),('vm_uuid','0'*36)):
                altered=dict(deployment);altered[key]=bad
                with self.assertRaises(gov.GovernanceError):gov._deployment_binding(group,altered)


if __name__=='__main__':unittest.main()

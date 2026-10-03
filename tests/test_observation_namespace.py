"""11 real allocator/reader/publisher/journal control flow with MODEL native I/O."""
import ctypes
from dataclasses import FrozenInstanceError
import inspect
import os
from pathlib import PureWindowsPath
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

import velociraptor_observation_namespace as n
import velociraptor_observation_windows as w
from velociraptor_observation_journal import RequestJournal
from tests.test_observation_windows import ModelFS, ROOT, SID, sd, session
from tests.test_observation_archive import accept, codec


MODEL_TRACES = []  # Optional runner export; no test writes or production injection.

def foreign_owner(raw):
    data=bytearray(raw);struct.pack_into('<I',data,44,1111);return bytes(data)


def protected(raw=None):
    data=bytearray(sd() if raw is None else raw)
    struct.pack_into('<H',data,2,struct.unpack_from('<H',data,2)[0] | 0x1000)
    return bytes(data)


class DirectoryFS(ModelFS):
    def __init__(self):
        super().__init__();self.created=[]
    def create_private(self,path,sid):
        self.created.append((str(path),sid,n._private_sddl(sid)))
        self.invoke('mkdir')
        if str(path) in self.nodes:
            raise n.AllocationError('exists',phase='CREATE_FAILED',winerror=183)
        self.node(path,True)['sd']=protected()
        self.invoke('after_mkdir')


class AllocatorModels(unittest.TestCase):
    def allocator(self,fs=None,limit=3):
        fs=fs or DirectoryFS()
        factories=[patch.object(n,'_session',side_effect=lambda:session(fs)),
                   patch.object(n,'_directory_api',return_value=fs)]
        for p in factories:p.start();self.addCleanup(p.stop)
        a=n.WindowsDirectoryAllocator(ROOT,max_directories=limit)
        def trace():
            MODEL_TRACES.append({'case':self.id(),'inputs':{'root':str(ROOT),'max_directories':limit},
                'create_calls':fs.created,'native_actions':fs.events,'close_calls':fs.closed,
                'diagnostics':a.diagnostics(),'remaining_handles':list(fs.handles),
                'residuals':{key:{'directory':v['directory'],'identity':[v['id'][0],v['id'][1].hex()],
                    'sd_hex':v['sd'].hex(),'bytes_hex':v['data'].hex()} for key,v in fs.nodes.items()}})
        self.addCleanup(trace)
        self.addCleanup(a.close)
        return a,fs
    def refused(self,fn,phase):
        with self.assertRaises(n.AllocationError) as e:fn()
        self.assertEqual(e.exception.phase,phase)
        MODEL_TRACES.append({'case':self.id(),'refusal':{'code':e.exception.code,'phase':e.exception.phase,'name':e.exception.name,'winerror':e.exception.winerror}})
        return e.exception
    def test_nested_immutable_leases_default_trust_and_single_close(self):
        a,fs=self.allocator();child=a.allocate(a.root,'One');other=a.allocate(child,'Two')
        self.assertEqual(other.path,ROOT/'One'/'Two');self.assertEqual(child.identity['principal_sid'],SID)
        with self.assertRaises(FrozenInstanceError):child.path=ROOT
        detached=child.identity;detached['file_id']='bad';self.assertNotEqual(child.identity,detached)
        self.assertEqual(a._session.trusted,frozenset(('S-1-5-18','S-1-5-32-544',SID)))
        self.assertEqual(a.diagnostics()['attempts'],2);self.assertEqual(a.diagnostics()['phase'],'BOUND')
        a.recheck(child);a.close();count=len(fs.closed);a.close()
        self.assertEqual(len(fs.closed),count);self.assertFalse(fs.handles)
        self.assertEqual(len(fs.closed),len(set(fs.closed)));self.assertIn(str(other.path),fs.nodes)
    def test_pure_names_parent_and_capacity_zero_creation_remain_usable(self):
        a,fs=self.allocator(limit=1)
        names=['','CON','cOn','PRN','AUX','NUL','COM1','com9','LPT9','a.b','a/b','a\\b','a:stream','a ','-a','é','a'*129,True,None]
        for name in names:
            with self.subTest(name=name):self.refused(lambda:a.allocate(a.root,name),'NOT_ATTEMPTED')
        for parent in [ROOT,n.DirectoryLease(a.root.path,a.root._identity),object()]:
            self.refused(lambda:a.allocate(parent,'valid'),'NOT_ATTEMPTED')
        self.assertEqual(fs.created,[]);child=a.allocate(a.root,'valid')
        self.refused(lambda:a.allocate(child,'next'),'NOT_ATTEMPTED');self.assertEqual(len(fs.created),1)
        a.recheck(child);self.assertFalse(a.failed)
    def test_foreign_allocator_parent_and_closed_lease_refuse(self):
        a,fs=self.allocator();b,_=self.allocator(fs)
        self.refused(lambda:b.allocate(a.root,'foreign'),'NOT_ATTEMPTED')
        c=a.allocate(a.root,'own');a.close()
        self.refused(lambda:a.allocate(c,'closed'),'NOT_ATTEMPTED');self.assertEqual(len(fs.created),1)
    def test_long_path_and_depth_before_native_creation(self):
        a,fs=self.allocator();long=PureWindowsPath('C:\\'+'x'*240)
        fs.node(long,True)
        with patch.object(n,'_session',side_effect=lambda:session(fs)):
            b=n.WindowsDirectoryAllocator(long,max_directories=1)
            try:self.refused(lambda:b.allocate(b.root,'TooLong'),'NOT_ATTEMPTED')
            finally:b.close()
        self.assertEqual(fs.created,[])
        path=PureWindowsPath('C:\\'+'\\'.join(['a']*64))
        self.refused(lambda:n.WindowsDirectoryAllocator(path,max_directories=1),'NOT_ATTEMPTED')
    def test_constructor_security_and_budget_default_reject_matrix(self):
        for mutate in [lambda fs:fs.nodes[str(ROOT)].update(sd=foreign_owner(sd())),lambda fs:fs.nodes.pop(str(ROOT)),lambda fs:fs.nodes[str(ROOT)].update(sd=sd(foreign='S-1-5-11',mask=1)),lambda fs:fs.nodes[str(ROOT.parent)].update(sd=sd(foreign='S-1-5-11')),lambda fs:fs.nodes[str(ROOT)].update(alias='C:\\OTHER'),lambda fs:fs.nodes[str(ROOT)].update(reparse=True),lambda fs:fs.nodes[str(ROOT)].update(id=(2,b'x'*16)),lambda fs:fs.nodes[str(ROOT)].update(sd=b'partial')]:
            fs=DirectoryFS();mutate(fs)
            with patch.object(n,'_session',side_effect=lambda:session(fs)),patch.object(n,'_directory_api',return_value=fs):
                self.refused(lambda:n.WindowsDirectoryAllocator(ROOT,max_directories=2),'NOT_ATTEMPTED')
            self.assertEqual(fs.created,[]);self.assertFalse(fs.handles)
        for limit in [True,0,-1,1.0,None]:self.refused(lambda:n.WindowsDirectoryAllocator(ROOT,max_directories=limit),'NOT_ATTEMPTED')
    def test_precreate_security_drift_and_thread_token_terminal_zero_effect(self):
        for mode in ['sd','parent','alias','identity','impersonation','sid']:
            a,fs=self.allocator()
            if mode=='sd':fs.nodes[str(ROOT)]['sd']=sd(foreign='S-1-5-11',mask=1)
            elif mode=='parent':fs.nodes[str(ROOT.parent)]['sd']=sd(foreign='S-1-5-11')
            elif mode=='alias':fs.nodes[str(ROOT)]['alias']='C:\\OTHER'
            elif mode=='identity':fs.nodes[str(ROOT)]['id']=(1,b'z'*16)
            if mode in ('impersonation','sid'):
                probe=session(fs);probe.sid='S-1-5-18'
                gate=patch.object(n,'_session',side_effect=RuntimeError('impersonation')) if mode=='impersonation' else patch.object(n,'_session',return_value=probe)
            else:gate=patch.object(n,'_session',side_effect=lambda:session(fs))
            with gate:self.refused(lambda:a.allocate(a.root,'child'),'NOT_ATTEMPTED')
            self.assertTrue(a.failed);self.assertEqual(fs.created,[])
            self.refused(lambda:a.allocate(a.root,'other'),'NOT_ATTEMPTED');a.close();self.assertFalse(fs.handles)
    def test_sd_preparation_failure_terminal_without_creation_or_slot(self):
        a,fs=self.allocator()
        with patch.object(fs,'create_private',side_effect=n.AllocationError('descriptor_conversion')):
            self.refused(lambda:a.allocate(a.root,'child'),'NOT_ATTEMPTED')
        self.assertTrue(a.failed);self.assertEqual(fs.created,[])
        self.assertEqual(a.diagnostics()['attempts'],0)
        self.refused(lambda:a.allocate(a.root,'later'),'NOT_ATTEMPTED')
    def test_principal_probe_close_preserves_changed_principal_primary(self):
        a,fs=self.allocator();probe=session(fs);probe.sid='S-1-5-18'
        with patch.object(n,'_session',return_value=probe),patch.object(probe,'close',side_effect=OSError('close')):
            error=self.refused(lambda:a.allocate(a.root,'child'),'NOT_ATTEMPTED')
        self.assertEqual(error.__cause__.code,'directory_principal_changed')
        self.assertEqual(error.__cause__.__notes__,['principal_probe_close_failed'])
        self.assertTrue(a.failed);self.assertEqual(fs.created,[])
    def test_create_failure_exists_unknown_and_never_retry_or_delete(self):
        for mode,phase in [('exists','CREATE_FAILED'),('before','UNKNOWN'),('after','UNKNOWN')]:
            a,fs=self.allocator()
            if mode=='exists':fs.node(ROOT/'child',True)['data']=b'winner'
            def hook(method,h):
                if (mode=='before' and method=='mkdir') or (mode=='after' and method=='after_mkdir'):raise OSError('unknown native completion')
            fs.hook=hook;self.refused(lambda:a.allocate(a.root,'child'),phase)
            self.assertTrue(a.failed);self.assertEqual(a.diagnostics()['attempts'],1)
            self.refused(lambda:a.allocate(a.root,'next'),'NOT_ATTEMPTED');self.assertEqual(len(fs.created),1)
            if mode!='before':self.assertIn(str(ROOT/'child'),fs.nodes)
            if mode=='exists':self.assertEqual(fs.nodes[str(ROOT/'child')]['data'],b'winner')
            a.close();self.assertFalse(fs.handles)
    def test_every_postcreate_binding_gate_preserves_unbound_residual(self):
        mutations={'owner':lambda node:node.update(sd=foreign_owner(protected())), 'open':None,'private_read':lambda node:node.update(sd=protected(sd(foreign='S-1-5-11',mask=1))),
                   'private_write':lambda node:node.update(sd=protected(sd(foreign='S-1-5-11'))),
                   'partial_sd':lambda node:node.update(sd=b'partial'),'unprotected':lambda node:node.update(sd=sd()),
                   'alias':lambda node:node.update(alias='C:\\OTHER'),'reparse':lambda node:node.update(reparse=True),
                   'volume':lambda node:node.update(id=(2,b'x'*16)),'type':lambda node:node.update(directory=False),
                   'parent':lambda node:None,'path_swap':lambda node:None,'retained_sd':lambda node:None}
        for mode,mutate in mutations.items():
            a,fs=self.allocator();done=False
            def hook(method,h):
                nonlocal done
                if method=='after_mkdir':
                    if mutate:mutate(fs.nodes[str(ROOT/'child')])
                    if mode=='parent':fs.nodes[str(ROOT)]['sd']=sd(foreign='S-1-5-11')
                if mode=='open' and method=='open' and str(ROOT/'child') in fs.nodes:raise OSError('open failed')
                if method=='identity' and h and fs.handles[h]['node']['name']==str(ROOT/'child'):
                    if mode=='path_swap' and not done:
                        done=True;old=fs.nodes[str(ROOT/'child')];fs.nodes[str(ROOT/'child')]={**old,'id':(1,b'z'*16)}
                    if mode=='retained_sd' and done:fs.handles[h]['node']['sd']=protected(sd(foreign='S-1-5-11'))
                    elif mode=='retained_sd':done=True
            fs.hook=hook
            with self.subTest(mode=mode):self.refused(lambda:a.allocate(a.root,'child'),'CREATED_UNBOUND')
            self.assertTrue(a.failed);self.assertEqual(a.diagnostics()['directories'],0)
            self.assertIn(str(ROOT/'child'),fs.nodes);fs.hook=lambda *a:None;a.close();self.assertFalse(fs.handles)
    def test_native_binding_steps_and_cleanup_preserve_primary(self):
        for method in ('identity','descriptor','name','close'):
            a,fs=self.allocator();primary=OSError('MODEL-'+method)
            def hook(action,h):
                if h and fs.handles[h]['node']['name']==str(ROOT/'child') and action==method:
                    if method=='close':del fs.handles[h]
                    raise primary
            fs.hook=hook
            error=self.refused(lambda:a.allocate(a.root,'child'),'CREATED_UNBOUND')
            self.assertIs(error.__cause__,primary);self.assertTrue(a.failed)
            self.assertIn(str(ROOT/'child'),fs.nodes)
            fs.hook=lambda *args:None;a.close();self.assertFalse(fs.handles)
        for probe_failure in (False,True):
            a,fs=self.allocator();primary=OSError('MODEL-binding-primary');identities=0
            def hook(action,h):
                nonlocal identities
                if not h or fs.handles[h]['node']['name']!=str(ROOT/'child'):return
                if action=='identity':
                    identities+=1
                    if identities==(3 if probe_failure else 1):raise primary
                if action=='close':del fs.handles[h];raise OSError('MODEL-close-secondary')
            fs.hook=hook
            error=self.refused(lambda:a.allocate(a.root,'child'),'CREATED_UNBOUND')
            self.assertIs(error.__cause__,primary)
            self.assertEqual(primary.__notes__,['native_probe_close_failed' if probe_failure else 'native_binding_close_failed'])
            fs.hook=lambda *args:None;a.close();self.assertFalse(fs.handles)
    def test_recheck_failure_terminal_and_context_close_preserves_primary(self):
        a,fs=self.allocator();child=a.allocate(a.root,'child');fs.nodes[str(child.path)]['id']=(1,b'z'*16)
        self.refused(lambda:a.recheck(child),'BOUND');self.assertTrue(a.failed);a.close()
        a,fs=self.allocator();primary=RuntimeError('primary')
        def failclose(method,h):
            if method=='close':del fs.handles[h];raise OSError('unknown close')
        fs.hook=failclose
        with self.assertRaises(RuntimeError) as caught:
            with a:raise primary
        self.assertIs(caught.exception,primary);self.assertEqual(primary.__notes__,['allocator_close_failed'])
        count=len(fs.closed);a.close();self.assertEqual(count,len(fs.closed));self.assertFalse(fs.handles);self.assertTrue(a.failed)
    def test_concurrent_atomic_slot_and_exclusive_same_name(self):
        a,fs=self.allocator(limit=1)
        def allocate(name):
            try:return a.allocate(a.root,name)
            except n.AllocationError:return None
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(allocate,[str(i) for i in range(8)]))
        self.assertEqual(sum(x is not None for x in results),1);self.assertEqual(len(fs.created),1);self.assertEqual(a.diagnostics()['attempts'],1)
        a,fs=self.allocator();a.allocate(a.root,'same')
        self.refused(lambda:a.allocate(a.root,'same'),'CREATE_FAILED');self.assertTrue(a.failed);self.assertEqual(len(fs.created),2)
    def test_real_publisher_journal_handoff_independent_owners(self):
        a,fs=self.allocator();lease=a.allocate(a.root,'request');a.recheck(lease)
        with patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs):
            publisher=w.WindowsRecordPublisher(lease.path,max_record_bytes=1000000,max_records=10,max_total_bytes=2000000,max_json_depth=12)
            a.recheck(lease)
            journal=RequestJournal(publisher,codec(),accept()['payload'],owns_publisher=True)
            journal.seal('returned');journal.close();a.recheck(lease)
            raws=[fs.nodes[str(lease.path/f'{i:08d}.json')]['data'] for i in range(2)]
            self.assertEqual(codec().verify(iter(raws))['status'],'COMPLETE')
        self.assertTrue(publisher.closed);self.assertFalse(a.closed)
        self.assertEqual(len(fs.handles),3);self.assertTrue(all(v['node']['directory'] for v in fs.handles.values()))
        a.close();self.assertFalse(fs.handles)
    def test_allocator_close_does_not_close_external_publisher(self):
        a,fs=self.allocator();lease=a.allocate(a.root,'request')
        with patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs):
            publisher=w.WindowsRecordPublisher(lease.path,max_record_bytes=1000,max_records=2,max_total_bytes=2000,max_json_depth=12)
        a.close();self.assertFalse(publisher.closed);self.assertEqual(len(fs.handles),3)
        publisher.close();self.assertFalse(fs.handles)
    def test_import_constructor_no_public_bypass_on_nonwindows(self):
        self.assertEqual(set(inspect.signature(n.WindowsDirectoryAllocator).parameters),{'directory','max_directories'})
        if os.name!='nt':
            with patch.object(n,'_session',n.reader.WindowsSession):self.refused(lambda:n.WindowsDirectoryAllocator(ROOT,max_directories=1),'NOT_ATTEMPTED')


class AdapterModels(unittest.TestCase):
    def api(self):return n._DirectoryAPI.__new__(n._DirectoryAPI)
    def test_actual_ctypes_security_buffer_lifetime_and_abi(self):
        api=self.api();raw=protected();buffer=ctypes.create_string_buffer(raw);events=[]
        def convert(sddl,revision,ptr,size):
            events.append(('convert',sddl,revision));ctypes.cast(ptr,ctypes.POINTER(ctypes.c_void_p))[0]=ctypes.addressof(buffer);ctypes.cast(size,ctypes.POINTER(ctypes.c_uint32))[0]=len(raw);return 1
        def create(path,ptr):
            sa=ctypes.cast(ptr,ctypes.POINTER(n._SecurityAttributes)).contents
            self.assertEqual(sa.length,ctypes.sizeof(n._SecurityAttributes));self.assertEqual(sa.inherit_handle,0)
            self.assertEqual(ctypes.string_at(sa.descriptor,len(raw)),raw);events.append(('create',path));return 1
        api.convert=convert;api.create=create;api.free=lambda p:events.append(('free',p.value))
        api.create_private(ROOT/'child',SID)
        MODEL_TRACES.append({'case':self.id(),'adapter_events':events,'sd_hex':raw.hex(),'pointer_size':ctypes.sizeof(ctypes.c_void_p)})
        self.assertEqual([e[0] for e in events],['convert','create','free'])
        self.assertIn('O:'+SID+'D:P',events[0][1]);self.assertNotIn('S-1-5-11',events[0][1])
        self.assertEqual(n._SecurityAttributes.descriptor.offset,8 if ctypes.sizeof(ctypes.c_void_p)==8 else 4)
        self.assertEqual(ctypes.sizeof(n._SecurityAttributes),24 if ctypes.sizeof(ctypes.c_void_p)==8 else 12)
    def test_conversion_create_exception_and_free_failure_phases(self):
        for mode,phase in [('convert','NOT_ATTEMPTED'),('false','CREATE_FAILED'),('unknown','UNKNOWN'),('free','CREATED_UNBOUND'),('false_and_free','CREATE_FAILED')]:
            api=self.api();frees=[];buffer=ctypes.create_string_buffer(protected())
            def convert(sddl,revision,ptr,size):
                ctypes.cast(ptr,ctypes.POINTER(ctypes.c_void_p))[0]=ctypes.addressof(buffer);ctypes.cast(size,ctypes.POINTER(ctypes.c_uint32))[0]=len(protected());return mode!='convert'
            def create(*args):
                if mode=='unknown':raise OSError('native exception')
                return mode not in ('false','false_and_free')
            api.convert=convert;api.create=create;api.free=lambda p:(frees.append(p.value) or (1 if mode in ('free','false_and_free') else 0))
            with patch.object(ctypes,'get_last_error',return_value=183,create=True),self.assertRaises(n.AllocationError) as e:api.create_private(ROOT/'child',SID)
            MODEL_TRACES.append({'case':self.id(),'mode':mode,'phase':e.exception.phase,'code':e.exception.code,'free_calls':frees,'notes':getattr(e.exception,'__notes__',[])})
            self.assertEqual(e.exception.phase,phase);self.assertEqual(len(frees),1)
            if mode=='false_and_free':self.assertEqual(e.exception.__notes__,['security_descriptor_release_failed'])
    def test_native_signature_binding_has_no_public_override(self):
        class Function:
            def __call__(self,*a):return 1
        class Library:pass
        advapi=Library();kernel=Library();advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW=Function();kernel.CreateDirectoryW=Function();kernel.LocalFree=Function()
        with patch.object(n.reader.acl,'_native_apis',return_value=(advapi,kernel)):api=n._DirectoryAPI()
        self.assertEqual(len(api.convert.argtypes),4);self.assertEqual(api.create.argtypes,[ctypes.c_wchar_p,ctypes.POINTER(n._SecurityAttributes)])
        self.assertEqual(api.free.argtypes,[ctypes.c_void_p]);self.assertEqual(api.free.restype,ctypes.c_void_p)


if __name__=='__main__':unittest.main()

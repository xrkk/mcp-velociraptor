"""09 real state machine + Win32 adapter models, never native Windows evidence."""
import ctypes
import hashlib
import inspect
import os
from pathlib import PureWindowsPath
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import velociraptor_observation_windows as w
from tests import p05_pc026_windows_reader as r
from tests.test_p05_pc026_windows_reader import sd, SID
from tests.test_observation_archive import accept, codec, event, reference

ROOT = PureWindowsPath(r'C:\controlled')


class ModelFS:
    def __init__(self):
        self.nodes = {}
        self.handles = {}
        self.next_handle = 0
        self.events = []
        self.closed = []
        self.hook = lambda method, handle=None: None
        self.short_write = 7
        for p in (ROOT.parent, ROOT):self.node(p,True)
    def node(self,path,directory=False):
        name=str(path)
        self.nodes[name]=dict(name=name,directory=directory,id=(1,hashlib.md5(name.encode()).digest()),sd=sd(),data=b'',meta=(0,1,2,3,0x10 if directory else 0x20))
        return self.nodes[name]
    def invoke(self,method,handle=None):
        self.events.append((method,handle));self.hook(method,handle)
    def open(self,path,directory):return self.acquire(path,directory,0x01020080 if directory else 0x81020000,3 if directory else 1,False)
    def acquire(self,path,directory,access,share,create):
        self.invoke('create' if create else 'open')
        name=str(path)
        if create:
            if name in self.nodes:raise w._CreateFailure(created=False)
            self.node(path)
        if name not in self.nodes:raise r.NativeReadError('missing directory/file')
        node=self.nodes[name]
        # Bilateral sharing check: each open's requested read/write/delete must
        # be allowed by every other handle's share flags, including DELETE.
        def rights(a):return (1 if a&0x80000000 or a&0x80 else 0)|(2 if a&0x40000000 else 0)|(4 if a&0x10000 else 0)
        for old in self.handles.values():
            if old['node'] is node and (rights(access)&~old['share'] or rights(old['access'])&~share):
                raise r.NativeReadError('sharing violation')
        self.next_handle+=1;h=self.next_handle
        self.handles[h]=dict(node=node,access=access,share=share,pos=0)
        return h
    def create_pending(self,path):return self.acquire(path,False,0xC1030000,0,True)
    def identity(self,h,directory):
        self.invoke('identity',h);n=self.handles[h]['node']
        if n.get('reparse'):raise r.NativeReadError('reparse object')
        if n['directory']!=directory:raise r.NativeReadError('type differs')
        return n['id']
    def descriptor(self,h):self.invoke('descriptor',h);return self.handles[h]['node']['sd']
    def metadata(self,h):self.invoke('metadata',h);return self.handles[h]['node']['meta']
    def name(self,h):self.invoke('name',h);return self.handles[h]['node'].get('alias',self.handles[h]['node']['name'])
    def write(self,h,data):
        self.invoke('write',h);count=min(len(data),self.short_write);n=self.handles[h]['node'];n['data']+=data[:count];n['meta']=(len(n['data']),1,20,30,0x20);return count
    def flush(self,h):self.invoke('flush',h)
    def rewind(self,h):self.invoke('rewind',h);self.handles[h]['pos']=0
    def read(self,h):
        self.invoke('read',h);row=self.handles[h];pos=row['pos'];data=row['node']['data'][pos:pos+65536];row['pos']+=len(data);return data
    def rename(self,h,path):
        self.invoke('rename',h);name=str(path)
        if name in self.nodes:raise w._NativeFailure('destination_exists')
        n=self.handles[h]['node'];del self.nodes[n['name']];n['name']=name;self.nodes[name]=n
        size,created,write,change,attr=n['meta'];n['meta']=(size,created,write,change+1,attr)
        self.invoke('after_rename',h)
    def close(self,h):
        # Model a successful release even when a close diagnostic is injected;
        # separate tests assert no second close call is attempted.
        self.closed.append(h)
        self.invoke('close',h)
        del self.handles[h]


def session(fs):
    s=r.WindowsSession.__new__(r.WindowsSession)
    s.sid=SID;s.trusted=frozenset(('S-1-5-18','S-1-5-32-544',SID));s.api=fs;s.objects={};s.closed=False;s.lock=threading.RLock()
    return s


class PublisherModels(unittest.TestCase):
    def publisher(self,fs):
        factories=[patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs)]
        for factory in factories:
            factory.start();self.addCleanup(factory.stop)
        p=w.WindowsRecordPublisher(ROOT,max_record_bytes=1000000,max_records=10,max_total_bytes=1000000,max_json_depth=12)
        self.addCleanup(lambda: p.close() if not p.closed else None)
        return p
    def files(self,fs):return {k:v['data'] for k,v in fs.nodes.items() if not v['directory']}
    def refusal(self,p,raw,code,phase):
        with self.assertRaises(w.PublishError) as caught:p.publish(raw)
        e=caught.exception;self.assertEqual((e.code,e.phase),(code,phase));return e
    def test_real_machine_short_writes_flush_rename_private_reader_and_no_retry(self):
        fs=ModelFS();p=self.publisher(fs);raw=codec().encode(accept());result=p.publish(raw)
        self.assertEqual(result['ref'],dict(path='00000000.json',**reference(raw)))
        self.assertEqual(result['identity']['principal_sid'],SID);self.assertEqual(result['identity']['acl_sha256'],hashlib.sha256(sd()).hexdigest())
        self.assertEqual(self.files(fs),{str(ROOT/'00000000.json'):raw})
        operations=[x[0] for x in fs.events];self.assertGreater(operations.count('write'),1);self.assertEqual(operations.count('rename'),1);self.assertEqual(operations.count('flush'),1)
        rename=operations.index('rename');writer_close=operations.index('close',rename)
        self.assertGreater(operations.index('open',writer_close),writer_close)
        p.close();self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_format_budget_and_sequence_gate_before_create(self):
        fs=ModelFS();p=self.publisher(fs)
        self.refusal(p,b'bad','record_invalid','NOT_CREATED');self.assertFalse(self.files(fs))
        first=codec().encode(accept());large=event(first,99999999+1);raw=codec().encode(large)
        self.refusal(p,raw,'sequence_filename_limit','NOT_CREATED');self.assertFalse(self.files(fs));self.assertFalse(any(n=='create' for n,_ in fs.events))
    def test_missing_or_unsafe_ancestor_no_new_files(self):
        for mutate in (lambda fs:fs.nodes.pop(str(ROOT)),lambda fs:fs.nodes[str(ROOT.parent)].update(sd=sd(foreign='S-1-5-11')),lambda fs:fs.nodes[str(ROOT)].update(alias='C:\\OTHER'),lambda fs:fs.nodes[str(ROOT)].update(id=(2,b'x'*16)),lambda fs:fs.nodes[str(ROOT)].update(reparse=True)):
            fs=ModelFS();mutate(fs)
            with self.subTest(mutate=mutate),patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs):
                with self.assertRaises(w.PublishError) as e:w.WindowsRecordPublisher(ROOT,max_record_bytes=1000,max_records=10,max_total_bytes=1000,max_json_depth=12)
                self.assertEqual(e.exception.phase,'NOT_CREATED');self.assertFalse(self.files(fs));self.assertFalse(fs.handles)
    def test_directory_drift_before_create_no_effect(self):
        fs=ModelFS();p=self.publisher(fs);fs.nodes[str(ROOT)]['sd']=sd(foreign='S-1-5-11')
        self.refusal(p,codec().encode(accept()),'directory_recheck_failed','NOT_CREATED');self.assertFalse(self.files(fs))
    def test_pending_initial_security_negative_matrix(self):
        for mutation,reason in [(lambda n:n.update(sd=sd(foreign='S-1-5-11',mask=1)),'untrusted_read'),(lambda n:n.update(sd=sd(foreign='S-1-5-11')),'untrusted_write'),(lambda n:n.update(sd=b'partial'),'descriptor'),(lambda n:n.update(alias='C:\\OTHER'),'alias'),(lambda n:n.update(reparse=True),'reparse'),(lambda n:n.update(id=(2,b'x'*16)),'volume'),(lambda n:n.update(directory=True),'type'),(lambda n:n.update(meta=(1,1,2,3,0x20)),'empty')]:
            fs=ModelFS();p=self.publisher(fs);done=False
            def hook(method,h):
                nonlocal done
                if method=='identity' and h is not None and fs.handles[h]['node']['name'].endswith('.pending') and not done:
                    done=True;mutation(fs.handles[h]['node'])
            fs.hook=hook
            with self.subTest(reason=reason):
                e=self.refusal(p,codec().encode(accept()),'pending_security_failed','PENDING');self.assertIn(reason,str(e.__cause__))
                self.assertEqual(len(self.files(fs)),0 if reason=='type' else 1)
                self.assertFalse(any(n in ('write','rename') for n,_ in fs.events));self.assertTrue(any(n.endswith('.pending') for n in fs.nodes))
    def test_write_zero_flush_and_prefix_preservation(self):
        for method,code in [('write','write_failed'),('flush','flush_failed')]:
            fs=ModelFS();p=self.publisher(fs)
            def hook(m,h):
                if m==method:raise w._NativeFailure('injected')
            fs.hook=hook;self.refusal(p,codec().encode(accept()),code,'PENDING')
            self.assertEqual(len(self.files(fs)),1);self.assertFalse(any(n=='rename' for n,_ in fs.events))
        fs=ModelFS();p=self.publisher(fs);fs.short_write=0;self.refusal(p,codec().encode(accept()),'write_failed','PENDING')
        self.assertEqual(list(self.files(fs).values()),[b''])
    def test_created_acquisition_failure_preserves_pending_and_close_once(self):
        fs=ModelFS();p=self.publisher(fs)
        original=fs.create_pending
        def fail_create(path):
            h=original(path);fs.close(h);raise w._CreateFailure(created=True)
        with patch.object(fs,'create_pending',side_effect=fail_create):self.refusal(p,codec().encode(accept()),'pending_create_failed','PENDING')
        self.assertEqual(list(self.files(fs).values()),[b'']);p.close();self.assertFalse(fs.handles)
        fs=ModelFS();p=self.publisher(fs)
        with patch.object(fs,'create_pending',side_effect=w._CreateFailure(created=False)):self.refusal(p,codec().encode(accept()),'pending_create_failed','NOT_CREATED')
        self.assertFalse(self.files(fs))
    def test_pending_written_identity_sd_metadata_and_bytes_drift(self):
        mutations=[lambda n:n.update(id=(1,b'x'*16)),lambda n:n.update(sd=sd(foreign='S-1-5-11')),lambda n:n.update(meta=(n['meta'][0],99,20,30,0x20)),lambda n:n.update(data=b'bad'),lambda n:n.update(meta=(n['meta'][0]-1,1,20,30,0x20))]
        for mutate in mutations:
            fs=ModelFS();p=self.publisher(fs)
            def hook(m,h):
                if m=='flush':mutate(fs.handles[h]['node'])
            fs.hook=hook;self.refusal(p,codec().encode(accept()),'pending_readback_failed','PENDING');self.assertFalse(any(n=='rename' for n,_ in fs.events))
    def test_ancestor_drift_after_write_before_rename_preserves_prefix(self):
        fs=ModelFS();p=self.publisher(fs)
        def hook(m,h):
            if m=='flush':fs.nodes[str(ROOT)]['sd']=sd(foreign='S-1-5-11')
        fs.hook=hook;raw=codec().encode(accept());self.refusal(p,raw,'pending_readback_failed','PENDING');self.assertEqual(list(self.files(fs).values()),[raw]);self.assertFalse(any(n=='rename' for n,_ in fs.events))
    def test_existing_target_rename_before_after_unknown_no_overwrite_replay(self):
        for mode in ('existing','same_bytes','before','after'):
            fs=ModelFS();p=self.publisher(fs)
            if mode in ('existing','same_bytes'):fs.node(ROOT/'00000000.json')['data']=b'winner' if mode=='existing' else codec().encode(accept())
            def hook(m,h):
                if (mode=='before' and m=='rename') or (mode=='after' and m=='after_rename'):raise w._NativeFailure('rename uncertainty')
            fs.hook=hook;raw=codec().encode(accept());e=self.refusal(p,raw,'rename_unknown','UNKNOWN')
            self.assertEqual(e.final,'00000000.json');self.assertTrue(e.pending.endswith('.pending'))
            self.assertEqual(sum(n=='rename' for n,_ in fs.events),1)
            self.refusal(p,raw,'publisher_unavailable','NOT_CREATED');self.assertEqual(sum(n=='rename' for n,_ in fs.events),1)
            if mode=='existing':self.assertEqual(self.files(fs)[str(ROOT/'00000000.json')],b'winner')
            elif mode=='same_bytes':self.assertEqual(self.files(fs)[str(ROOT/'00000000.json')],raw)
            elif mode=='after':self.assertEqual(self.files(fs),{str(ROOT/'00000000.json'):raw})
            else:self.assertEqual(list(self.files(fs).values()),[raw])
    def test_rename_handle_and_final_path_readback_failures_unknown(self):
        for mode in ('alias','bytes','path_identity','path_security','path_grown'):
            fs=ModelFS();p=self.publisher(fs);altered=False
            def hook(m,h):
                nonlocal altered
                if mode=='alias' and m=='after_rename':fs.handles[h]['node']['alias']='C:\\OTHER'
                if mode=='bytes' and m=='after_rename':fs.handles[h]['node']['data']=b'changed'
                if mode.startswith('path_') and m=='open' and str(ROOT/'00000000.json') in fs.nodes and not altered:
                    # Only mutate after writer was closed, leaving pinned directory
                    # probes intact until the final file read.
                    if any(x['node']['name'].endswith('.json') for x in fs.handles.values()):return
                    altered=True;n=fs.nodes[str(ROOT/'00000000.json')]
                    n['id']=(1,b'x'*16) if mode=='path_identity' else n['id']
                    if mode=='path_security':n['sd']=sd(foreign='S-1-5-11')
                    if mode=='path_grown':n['data']=b'x'*2000000;n['meta']=(len(n['data']),1,20,40,0x20)
            fs.hook=hook
            e=self.refusal(p,codec().encode(accept()),'published_handle_check_failed' if mode in ('alias','bytes') else 'final_readback_failed','UNKNOWN')
            self.assertTrue(str(ROOT/'00000000.json') in self.files(fs))
    def test_close_errors_do_not_mask_primary_or_repeat_close(self):
        fs=ModelFS();p=self.publisher(fs)
        def hook(m,h):
            if m=='flush':raise w._NativeFailure('original flush fault')
            if m=='close' and fs.handles[h]['node']['name'].endswith('.pending'):
                del fs.handles[h];raise w._NativeFailure('secret close message')
        fs.hook=hook;e=self.refusal(p,codec().encode(accept()),'flush_failed','PENDING');self.assertIn('original flush fault',str(e.__cause__));self.assertEqual(e.__notes__,['writer_close_failed']);p.close();self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_post_rename_close_error_unknown_retains_final(self):
        fs=ModelFS();p=self.publisher(fs)
        def hook(m,h):
            if m=='close' and fs.handles[h]['node']['name'].endswith('.json'):
                del fs.handles[h];raise w._NativeFailure('close ambiguous')
        fs.hook=hook;self.refusal(p,codec().encode(accept()),'writer_close_failed','UNKNOWN');self.assertEqual(len(self.files(fs)),1)
        p.close();self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_pending_collision_is_exclusive_and_partial_write_is_preserved(self):
        fs=ModelFS();p=self.publisher(fs);name='184a9076-bb09-4449-9df6-68286a55cadd.pending'
        fs.node(ROOT/name)['data']=b'foreign pending'
        with patch.object(w.uuid,'uuid4',return_value=name[:-8]):
            self.refusal(p,codec().encode(accept()),'pending_create_failed','NOT_CREATED')
        self.assertEqual(self.files(fs),{str(ROOT/name):b'foreign pending'})
        self.assertEqual(sum(n=='create' for n,_ in fs.events),1)
        fs=ModelFS();p=self.publisher(fs);writes=0
        def hook(m,h):
            nonlocal writes
            if m=='write':
                writes+=1
                if writes==3:raise w._NativeFailure('write interruption')
        fs.hook=hook;raw=codec().encode(accept())
        self.refusal(p,raw,'write_failed','PENDING');self.assertEqual(list(self.files(fs).values()),[raw[:14]])
        self.assertFalse(any(n in ('flush','rename') for n,_ in fs.events))

    def test_final_reader_close_failure_is_unknown_without_success_payload(self):
        fs=ModelFS();p=self.publisher(fs)
        def hook(m,h):
            if m=='close' and fs.handles[h]['node']['name'].endswith('.json') and fs.handles[h]['share']==1 and len(fs.handles)==3:
                del fs.handles[h];raise w._NativeFailure('reader close uncertainty')
        fs.hook=hook;self.refusal(p,codec().encode(accept()),'final_close_failed','UNKNOWN');p.close();self.assertFalse(fs.handles)
        self.assertEqual(len(fs.closed),len(set(fs.closed)))

    def test_principal_recheck_and_impersonation_refuse_before_create(self):
        fs=ModelFS();p=self.publisher(fs)
        changed=session(fs);changed.sid='S-1-5-18'
        with patch.object(w,'_session',return_value=changed):
            self.refusal(p,codec().encode(accept()),'principal_recheck_failed','NOT_CREATED')
        self.assertFalse(self.files(fs))
        fs=ModelFS();p=self.publisher(fs)
        with patch.object(w,'_session',side_effect=r.NativeReadError('impersonated reader principal is unsupported')):
            self.refusal(p,codec().encode(accept()),'principal_recheck_failed','NOT_CREATED')
        self.assertFalse(self.files(fs))

    def test_file_handles_do_not_accumulate_across_publications(self):
        fs=ModelFS();p=self.publisher(fs);raw=codec().encode(accept())
        p.publish(raw)
        for i in range(1,8):
            raw=codec().encode(event(raw,i));p.publish(raw)
            self.assertEqual(len(fs.handles),2)
            self.assertTrue(all(row['node']['directory'] for row in fs.handles.values()))
        p.close();self.assertFalse(fs.handles)

    def test_context_close_preserves_primary_and_nonwindows_no_bypass(self):
        fs=ModelFS();p=self.publisher(fs);primary=RuntimeError('primary')
        def hook(m,h):
            if m=='close':del fs.handles[h];raise RuntimeError('secret secondary')
        fs.hook=hook
        with self.assertRaises(RuntimeError) as e:
            with p:raise primary
        self.assertIs(e.exception,primary);self.assertEqual(primary.__notes__,['directory_close_failed']);self.assertFalse(fs.handles)
        expected={'directory','max_record_bytes','max_records','max_total_bytes','max_json_depth'}
        self.assertEqual(set(inspect.signature(w.WindowsRecordPublisher).parameters),expected)
        if os.name!='nt':
            with patch.object(w,'_session',r.WindowsSession),self.assertRaises(w.PublishError):w.WindowsRecordPublisher(ROOT,max_record_bytes=1000,max_records=2,max_total_bytes=1000,max_json_depth=12)


class NativeAdapterModels(unittest.TestCase):
    def adapter(self):
        api=w._PublisherIO.__new__(w._PublisherIO)
        api.advapi=object();api.kernel=object()
        return api
    def test_create_flags_privilege_scope_and_acquisition_cleanup(self):
        api=self.adapter();calls=[]
        class Privilege:
            def __init__(self,*args):pass
            def __enter__(self):calls.append('enable assigned privilege')
            def __exit__(self,*args):calls.append('restore privilege')
        api._open=lambda *args:(calls.append(args) or 9)
        with patch.object(r,'_security_privilege',Privilege):self.assertEqual(api.create_pending(ROOT/'x.pending'),9)
        self.assertEqual(calls[1],(ROOT/'x.pending',0xC1030000,0,1));self.assertEqual(calls[-1],'restore privilege')
        class BadRestore(Privilege):
            def __exit__(self,*args):raise RuntimeError('restore failed')
        api.close=lambda h:calls.append(('close',h))
        with patch.object(r,'_security_privilege',BadRestore),self.assertRaises(w._CreateFailure) as e:api.create_pending(ROOT/'x.pending')
        self.assertTrue(e.exception.created);self.assertEqual(calls[-1],('close',9))
    def test_write_flush_and_rename_use_real_ctypes_buffers_and_flags(self):
        api=self.adapter();observed=[]
        def write(h,b,n,count,overlap):
            observed.append(('write',h,ctypes.string_at(b,n),overlap));ctypes.cast(count,ctypes.POINTER(ctypes.c_uint32))[0]=2;return 1
        api.write_file=write;self.assertEqual(api.write(9,b'abc'),2)
        api.flush_file=lambda h:(observed.append(('flush',h)) or 1);api.flush(9)
        def rename(h,kind,b,n):
            header=w._RenameInfo.from_buffer(b);name=ctypes.string_at(ctypes.addressof(b)+w._RenameInfo.name.offset,header.length).decode('utf-16-le')
            self.assertEqual(n,w._RenameInfo.name.offset+header.length+2)
            self.assertEqual(bytes(b)[n-2:n],b'\0\0')
            observed.append(('rename',h,kind,header.replace,header.root,name,n));return 1
        api.set_info=rename;api.rename(9,ROOT/'00000000.json')
        self.assertEqual(observed[-1][1:6],(9,3,0,None,str(ROOT/'00000000.json')))
        self.assertEqual(observed[-1][-1],w._RenameInfo.name.offset+len(str(ROOT/'00000000.json').encode('utf-16-le'))+2)
        self.assertEqual(w._RenameInfo.root.offset,8 if ctypes.sizeof(ctypes.c_void_p)==8 else 4)
        api.write_file=lambda *args:0
        with self.assertRaisesRegex(w._NativeFailure,'write_failed'):api.write(9,b'abc')
        api.flush_file=lambda *args:0
        with self.assertRaisesRegex(w._NativeFailure,'flush_failed'):api.flush(9)
        api.set_info=lambda *args:0
        with self.assertRaisesRegex(w._NativeFailure,'rename_failed'):api.rename(9,ROOT/'00000000.json')
    def test_native_init_binds_signatures_without_public_fake_parameter(self):
        class Function:
            def __call__(self,*args):return 1
        kernel=SimpleNamespace(WriteFile=Function(),FlushFileBuffers=Function())
        def init(api):api.kernel=kernel
        with patch.object(r.NativeIO,'__init__',init):api=w._PublisherIO()
        self.assertEqual(len(api.write_file.argtypes),5);self.assertEqual(api.flush_file.argtypes,[ctypes.c_void_p])


if __name__=='__main__':unittest.main()

"""Production exporter/Win32 transaction under MODEL permission/identity I/O.

Actual SDK loopback uses the production algorithm. No native Windows authority.
"""
import asyncio
import copy
import hashlib
import json
from pathlib import PureWindowsPath
import threading
import time
import unittest
from unittest.mock import patch

import velociraptor_observation_export as export
from velociraptor_observation_cut import canonical, ref
from velociraptor_observation_sdk import PIN_REF
from velociraptor_observation_startup import CONFIG, CONTRACT_REF
from tests import test_observation_controller as chain
from tests import test_observation_attempts as attempts
from tests.test_observation_windows import session
from tests.test_observation_startup import model_budgets
_ARCHIVE_FS = attempts.ArchiveFS


def lifecycle(config,budgets):
    return dict(schema_version=1,kind='pc026-observation-lifecycle-configuration-v1',profile_id='MODEL',workflow_id='MODEL',
        contract_ref=CONTRACT_REF,archive_config_ref=config.group.allowed['PLAN/2026.10.02/observation-archive-configuration.json'],
        deployment_ref=ref('MODEL/deployment.json',b'{}'),implementation_freeze_ref=config.document['implementation_freeze_ref'],
        budgets=budgets,metadata_policy='GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS',status='AUTHORIZED')


def proof(ledger,session_id):
    return dict(schema_version=1,kind='pc026-observation-session-lifecycle-v1',instance_id=ledger._instance,
        session_id=session_id,sdk_pin_ref=PIN_REF,close_reason='DELETE',admission_watermark=0,
        sdk_work=dict(messages=[],transfer_workers=[]),binary_work=[],attempt_sequences=[],
        cleanup={k:True for k in 'runner_exited dispatcher_joined connection_closed transport_closed journals_closed export_io_closed'.split()},status='CLOSED_KNOWN')


def install(test,ledger,fs,config,limits):
    raw=canonical(lifecycle(config,limits));config.group.allowed[CONFIG]=ref(CONFIG,raw)
    config.group.read=lambda value:raw
    old_names=fs._names
    def names(h,limit,*,directories=False):
        if not directories:return (yield from old_names(h,limit))
        fs.invoke('enumerate',h)
        parent=PureWindowsPath(fs.handles[h]['node']['name']);count=0
        for row in list(fs.nodes.values()):
            child=PureWindowsPath(row['name'])
            if child.parent==parent and child!=parent:
                count+=1
                if count>limit or row.get('reparse'):raise RuntimeError('MODEL enumeration bound/alias')
                yield child.name
    fs._names=names
    for p in (patch.object(export,'WindowsSession',side_effect=lambda:session(fs)),
              patch.object(export,'_free_bytes',return_value=2**40)):
        p.start();test.addCleanup(p.stop)
    return export.NativeExporter._borrow(ledger,lifecycle(config,limits))


class NativeExportModels(unittest.TestCase):
    def setup_export(self):
        self.fixture=attempts.LedgerModels();self.addCleanup(self.fixture.doCleanups)
        l,fs,c=self.fixture.ledger();limits=model_budgets();limits['max_export_bytes']=224870400
        e=install(self,l,fs,c,limits)
        return l,fs,c,e

    def prefix(self,l):
        return l._session_prefix('MODEL-session',max_files=434,max_bytes=224870400)

    def contents(self,fs):return {n:r['data'] for n,r in fs.nodes.items() if '\\e'+attempts.INSTANCE+'\\' in n and not r['directory']}

    def test_native_algorithm_global_prefix_own_new_rejected_and_source_sd_identity(self):
        l,fs,c,e=self.setup_export()
        self.fixture.terminal(l,l.begin(attempts.key(),'tool',attempts.SHA),events=1)
        l.begin(attempts.key(),'tool',attempts.SHA)
        self.fixture.terminal(l,l.begin(attempts.key(2,'other'),'tool',attempts.SHA),events=1)
        e.reserve('MODEL-session');p=self.prefix(l);d=e.publish(p,proof(l,p.session),retain=lambda g:None)
        self.assertTrue(e.receipt(p.session,d));files=self.contents(fs);base=d['path'].rsplit('/',1)[0].replace('/','\\')
        names={n.split('\\'+base+'\\',1)[1].replace('\\','/'):r for n,r in files.items()}
        e.codec.verify(names,c.catalog_codec,c.codec,e.lifecycle_config_raw)
        s=json.loads(names['source-manifest.json']);projection=json.loads(names['attempts.json'])
        self.assertEqual(projection['attempt_sequences'],[1,2]);self.assertEqual(len(projection['request_records']),1)
        self.assertEqual(len(projection['catalog_prefix']),l._catalog_count)
        self.assertEqual(len([n for n in names if n.startswith('sd/')]),len({row['identity']['acl_sha256'] for row in s['files']}))
        self.assertFalse(any('r000000000003-' in n for n in names))
        self.assertFalse(any(not r['node']['directory'] for r in fs.handles.values()))
        l.close();self.assertFalse(fs.handles);self.assertEqual(c.group.closed,1)

    def test_copy_before_quota_minus_one_duplicate_path_and_free_zero_writer(self):
        for quota in ('max_export_files','max_export_directories','max_export_bytes','min_free_bytes','path','duplicate'):
            l,fs,c,e=self.setup_export();before=list(fs.created)
            if quota=='max_export_files':e.codec.limits[quota]=e._plan['files']-1
            elif quota=='max_export_directories':e.codec.limits[quota]=e._plan['directories']
            elif quota=='max_export_bytes':e.codec.limits[quota]=e._plan['bytes']+e._plan['pending']-1
            elif quota=='min_free_bytes':e.codec.limits[quota]=2**50
            elif quota=='path':
                from dataclasses import replace
                e._allocator.root=replace(e._allocator.root,path=PureWindowsPath('C:\\'+'x'*200))
            else:e.reserve('MODEL-session')
            with self.subTest(quota=quota),self.assertRaises(Exception):e.reserve('MODEL-session')
            self.assertEqual(before,fs.created);self.assertFalse(self.contents(fs))

    def test_unissued_prefix_or_source_sd_drift_never_writes(self):
        for mode in ('unissued','sd','principal'):
            l,fs,c,e=self.setup_export();e.reserve('MODEL-session');p=self.prefix(l)
            if mode=='unissued':p=copy.copy(p)
            else:
                r=p.originals[0]
                if mode=='sd':object.__setattr__(r,'sd',r.sd+b'x')
                else:
                    identity=json.loads(r.identity);identity['principal_sid']='S-1-5-18';object.__setattr__(r,'identity',canonical(identity))
            before=list(fs.created)
            with self.subTest(mode=mode),self.assertRaises(Exception):e.publish(p,proof(l,p.session),retain=lambda g:None)
            self.assertEqual(before,fs.created);self.assertFalse(self.contents(fs));self.assertFalse(e.completed)

    def test_publish_readback_and_final_reader_close_fail_preserve_original_and_residual(self):
        for mode in ('flush','read','identity','sd','final_close','extra','pending'):
            l,fs,c,e=self.setup_export();e.reserve('MODEL-session');p=self.prefix(l)
            primary=RuntimeError('MODEL-'+mode);fired=False
            def hook(action,h):
                nonlocal fired
                if fired:return
                node=fs.handles[h]['node'] if h is not None and h in fs.handles else None
                is_export=node and '\\e'+l._instance+'\\' in node['name']
                if mode=='flush' and action=='flush':fired=True;raise primary
                if is_export and mode=='read' and action=='read' and node['name'].endswith('export.json'):
                    fired=True;raise primary
                if is_export and mode in ('identity','sd') and action=='open' :pass
                if is_export and mode=='identity' and action=='identity' and node['name'].endswith('cut.json'):
                    fired=True;node['id']=(1,b'X'*16)
                if is_export and mode=='sd' and action=='descriptor' and node['name'].endswith('.pending'):
                    from tests.test_observation_windows import sd
                    fired=True;node['sd']=sd(foreign='S-1-5-11')
                if is_export and mode=='final_close' and action=='close' and node['name'].endswith('export.json') and fs.handles[h]['share']==1:
                    fired=True;del fs.handles[h];raise primary
                if is_export and mode in ('extra','pending') and action=='after_rename' and node['name'].endswith('cut.json'):
                    fired=True;fs.node(PureWindowsPath(node['name']).parent/('bad.pending' if mode=='pending' else 'unknown'))
            fs.hook=hook
            with self.subTest(mode=mode),self.assertRaises(Exception):e.publish(p,proof(l,p.session),retain=lambda g:None)
            fs.hook=lambda *a:None
            self.assertTrue(fired);self.assertTrue(self.contents(fs));self.assertFalse(e.completed);self.assertTrue(l._unknown)

    def test_missing_catalog_or_leaf_and_other_session_event_full_closure_refuse(self):
        for mode in ('BEGIN','ACK','END','leaf','other','extra'):
            l,fs,c,e=self.setup_export();self.fixture.terminal(l,l.begin(attempts.key(),'tool',attempts.SHA))
            e.reserve('MODEL-session');p=self.prefix(l);files,_,_=e._documents(p,proof(l,p.session))
            if mode in ('BEGIN','ACK','END'):del files['originals/c/'+{'BEGIN':'00000001','ACK':'00000002','END':'00000003'}[mode]+'.json']
            elif mode=='leaf':del files[next(n for n in files if n.startswith('originals/r') and n.endswith('00000001.json'))]
            elif mode=='other':files['originals/r000000000008-'+64*'f'+'/00000000.json']=b'{}\n'
            else:files['x.pending']=b'x'
            with self.subTest(mode=mode),self.assertRaises(Exception):e.codec.verify_cut(files,c.catalog_codec,c.codec,e.lifecycle_config_raw)
            self.assertFalse(self.contents(fs))


    def test_actual_short_read_and_fake_eof_refuse_residual_without_receipt(self):
        for mode in ('short','eof'):
            l,fs,c,e=self.setup_export();e.reserve('MODEL-session');prefix=self.prefix(l)
            read=fs.read;fired=False
            def changed(h):
                nonlocal fired
                raw=read(h)
                if not fired and fs.handles[h]['node']['name'].endswith('.pending'):
                    fired=True;return raw[:1] if mode=='short' else b''
                return raw
            with patch.object(fs,'read',side_effect=changed),self.subTest(mode=mode),self.assertRaises(Exception):
                e.publish(prefix,proof(l,prefix.session),retain=lambda g:None)
            self.assertTrue(fired);self.assertFalse(e.completed);self.assertTrue(self.contents(fs))


class NativeExportHTTP(unittest.IsolatedAsyncioTestCase):
    records=chain.ChainTests.records
    initialize=chain.ChainTests.initialize
    call=chain.ChainTests.call
    def configure_server(self,server):
        self.controller._limits['max_export_bytes']=224870400
        self.controller._limits['max_retained_state_bytes']=8<<20
        self.exporter=install(self,self.ledger,self.fs,self.config,self.controller._limits)
        self.controller._exporter=self.exporter
    async def asyncSetUp(self):await chain.ChainTests.asyncSetUp(self)
    async def asyncTearDown(self):
        for r in self.controller._close_io.values():
            if r.task is not None:await r.task
            self.assertFalse(r.thread.is_alive())
        await chain.ChainTests.asyncTearDown(self)

    async def test_actual_sdk_latch_two_sessions_native_export_before_200(self):
        first=await self.initialize();task=asyncio.create_task(self.call(7,'latch'))
        closed=asyncio.create_task(self.http.delete(self.url));
        try:
            until=time.monotonic()+2
            while not self.started.is_set() and time.monotonic()<until:await asyncio.sleep(.001)
            self.assertTrue(self.started.is_set());await asyncio.sleep(.03);self.assertFalse(closed.done())
            self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
            second=await self.initialize();self.assertNotEqual(first,second)
            self.assertEqual((await self.call(8)).status_code,200)
            self.assertFalse(closed.done());self.release.set();await task
            response=await closed;self.assertEqual(response.status_code,200,response.text)
            self.assertIn('x-velo-observation-cut',response.headers);self.assertTrue(self.exporter.completed)
            self.assertEqual(self.controller._sessions[first]['state'],'CLOSED')
            self.assertEqual(self.controller._sessions[second]['state'],'OPEN')
            self.assertFalse(any(not r['node']['directory'] for r in self.fs.handles.values()))
        finally:
            self.release.set();await task;await closed

    async def test_actual_native_final_close_error_no_success_header(self):
        s=await self.initialize();await self.call(7)
        def hook(action,h):
            if action=='close' and h in self.fs.handles:
                row=self.fs.handles[h]
                if row['node']['name'].endswith('export.json') and row['share']==1:
                    del self.fs.handles[h];raise RuntimeError('MODEL-real-final-close')
        self.fs.hook=hook
        try:
            response=await self.http.delete(self.url);self.assertEqual(response.status_code,503,response.text)
            self.assertNotIn('x-velo-observation-cut',response.headers);self.assertFalse(self.exporter.completed)
            self.assertEqual(self.controller._sessions[s]['state'],'UNKNOWN')
        finally:self.fs.hook=lambda *a:None

    async def test_native_deadline_keeps_actual_thread_pending_lane_and_no_late_receipt(self):
        session_id=await self.initialize();await self.call(7)
        gate=threading.Event();entered=threading.Event();fired=False
        self.controller._limits['close_timeout_ns']=100_000_000
        def hook(action,h):
            nonlocal fired
            if action=='flush' and not fired:
                fired=True;entered.set();gate.wait(5)
        self.fs.hook=hook
        try:
            response=await self.http.delete(self.url)
            self.assertTrue(entered.is_set());self.assertEqual(response.status_code,503)
            self.assertNotIn('x-velo-observation-cut',response.headers)
            io=self.controller._close_io[(session_id,'export')]
            self.assertTrue(io.thread.is_alive());self.assertFalse(io.joined)
            self.assertEqual(self.exporter._pending_reserved,self.exporter._plan['pending'])
            gate.set()
            deadline=time.monotonic()+3
            while io.thread.is_alive() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertFalse(io.thread.is_alive());self.assertEqual(self.exporter._pending_reserved,0)
            self.assertFalse(self.exporter.completed);self.assertEqual(self.controller._sessions[session_id]['state'],'UNKNOWN')
        finally:gate.set();self.fs.hook=lambda *a:None

    async def test_native_cancel_keeps_join_owner_until_actual_export_finally(self):
        session_id=await self.initialize();await self.call(7)
        gate=threading.Event();entered=threading.Event();fired=False
        def hook(action,h):
            nonlocal fired
            if action=='flush' and not fired:fired=True;entered.set();gate.wait(5)
        self.fs.hook=hook
        future=asyncio.run_coroutine_threadsafe(self.controller._close_session(session_id,self.controller._sessions[session_id]['owner']),self.server_loop)
        try:
            deadline=time.monotonic()+3
            while not entered.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertTrue(entered.is_set());future.cancel()
            deadline=time.monotonic()+3
            while self.controller._state!='UNKNOWN' and time.monotonic()<deadline:await asyncio.sleep(.001)
            io=self.controller._close_io[(session_id,'export')]
            self.assertTrue(io.thread.is_alive());self.assertFalse(io.joined)
            self.assertEqual(self.exporter._pending_reserved,self.exporter._plan['pending'])
            gate.set()
            deadline=time.monotonic()+3
            while io.thread.is_alive() and time.monotonic()<deadline:await asyncio.sleep(.001)
            self.assertFalse(io.thread.is_alive());self.assertFalse(self.exporter.completed)
        finally:gate.set();self.fs.hook=lambda *a:None


    async def test_last_full_readback_close_latch_blocks_actual_http_success(self):
        session_id=await self.initialize();await self.call(7)
        entered=threading.Event();gate=threading.Event()
        def reader():
            value=session(self.fs);original=value.close
            def close():
                if any(path.endswith('export.json') for path in value.objects):
                    entered.set();gate.wait(5)
                original()
            value.close=close
            return value
        with patch.object(export,'WindowsSession',side_effect=reader):
            request=asyncio.create_task(self.http.delete(self.url))
            try:
                deadline=time.monotonic()+3
                while not entered.is_set() and time.monotonic()<deadline:await asyncio.sleep(.001)
                self.assertTrue(entered.is_set());self.assertFalse(request.done());self.assertFalse(self.exporter.completed)
                self.assertTrue(any(r['node']['name'].endswith('export.json') for r in self.fs.handles.values()))
                gate.set();response=await request
                self.assertEqual(response.status_code,200,response.text);self.assertTrue(self.exporter.completed)
                self.assertFalse(any(not r['node']['directory'] for r in self.fs.handles.values()))
                self.assertEqual(self.controller._sessions[session_id]['state'],'CLOSED')
            finally:gate.set();await request

    async def test_last_full_readback_close_error_preserves_primary_and_full_residual_no_200(self):
        session_id=await self.initialize();await self.call(7);primary=RuntimeError('MODEL-actual-last-reader-close')
        def reader():
            value=session(self.fs);original=value.close
            def close():
                final=any(path.endswith('export.json') for path in value.objects)
                original()
                if final:raise primary
            value.close=close
            return value
        with patch.object(export,'WindowsSession',side_effect=reader):response=await self.http.delete(self.url)
        self.assertEqual(response.status_code,503);self.assertNotIn('x-velo-observation-cut',response.headers)
        self.assertFalse(self.exporter.completed);self.assertIs(self.controller._close_errors[session_id],primary)
        self.assertTrue(any(path.endswith('export.json') for path in self.fs.nodes))
        self.assertFalse(any(not r['node']['directory'] for r in self.fs.handles.values()))


class PosixExportIO(NativeExportModels):
    """Real POSIX exclusive/open/no-follow/write/fsync/link/read/close seam.

    All Win32 permission, identity, sharing and rename semantics remain MODEL.
    """
    def setup_export(self):
        import os
        import tempfile
        from pathlib import Path
        from tests.test_observation_namespace import DirectoryFS
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        class Filesystem(_ARCHIVE_FS):
            def __init__(self):self.fds={};super().__init__()
            def local(self,path):return root.joinpath(*PureWindowsPath(path).parts[1:])
            def node(self,path,directory=False):
                local=self.local(path)
                if directory:
                    if local!=root:local.mkdir()
                else:
                    fd=os.open(local,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
                return super().node(path,directory)
            def acquire(self,path,directory,access,share,create):
                h=super().acquire(path,directory,access,share,create)
                try:self.fds[h]=os.open(self.local(path),(os.O_RDWR if create else os.O_RDONLY)|os.O_NOFOLLOW|(os.O_DIRECTORY if directory else 0))
                except BaseException:super().close(h);raise
                return h
            def write(self,h,data):
                count=os.write(self.fds[h],data[:self.short_write]);self.invoke('write',h)
                n=self.handles[h]['node'];n['data']+=data[:count];n['meta']=(len(n['data']),1,20,30,0x20);return count
            def read(self,h):self.invoke('read',h);return os.read(self.fds[h],65536)
            def rewind(self,h):self.invoke('rewind',h);os.lseek(self.fds[h],0,os.SEEK_SET)
            def flush(self,h):self.invoke('flush',h);os.fsync(self.fds[h])
            def rename(self,h,path):
                original=self.local(self.handles[h]['node']['name']);destination=self.local(path)
                os.link(original,destination,follow_symlinks=False);os.unlink(original)
                super().rename(h,path)
            def close(self,h):
                fd=self.fds.pop(h,None)
                if fd is not None:os.close(fd)
                super().close(h)
        factory=patch.object(attempts,'ArchiveFS',Filesystem);factory.start();self.addCleanup(factory.stop)
        result=super().setup_export();self.disk_root=root
        return result

    # Use two meaningful inherited cases with actual disk I/O; MODEL-only
    # mutation tests deliberately change synthetic node content/SD in memory.
    test_copy_before_quota_minus_one_duplicate_path_and_free_zero_writer=None
    test_unissued_prefix_or_source_sd_drift_never_writes=None
    test_publish_readback_and_final_reader_close_fail_preserve_original_and_residual=None
    test_missing_catalog_or_leaf_and_other_session_event_full_closure_refuse=None

    def test_real_posix_exclusive_collision_no_overwrite(self):
        l,fs,c,e=self.setup_export();e.reserve('MODEL-session');p=self.prefix(l)
        d=e.publish(p,proof(l,p.session),retain=lambda g:None)
        target=self.disk_root/'controlled'/d['path'];original=target.read_bytes()
        with self.assertRaises(FileExistsError):
            import os
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            os.close(fd)
        self.assertEqual(target.read_bytes(),original)
        l.close();self.assertFalse(fs.fds);self.assertFalse(fs.handles)

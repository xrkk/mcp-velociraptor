"""Full one-shot SCM host lifecycle with real 08/09/10/11 + private MODEL Win32 IO.

No native service, token, privilege, ACL, VM or backend mutation qualification.
"""
import copy
import ctypes
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import sys
import threading
import unittest
from unittest.mock import patch

from tests import p05_service_qualification as q
from tests.test_observation_namespace import DirectoryFS, protected
from tests.test_observation_windows import session, SID, sd, ROOT
import velociraptor_observation_namespace as n
import velociraptor_observation_windows as w
import velociraptor_observation_journal as j
import velociraptor_observation_archive as a

RUN='184a9076-bb09-4449-9df6-68286a55cadd'
CODE=PureWindowsPath(r'C:\code')
TRACES=[]


class NativeModel(q._Native):
    def __init__(self, fs):
        self.fs=fs;self.root=CODE;self.reader=n.reader;self.namespace=n
        self.publisher=w;self.journal=j;self.archive=a
        self.identity={'principal_sid':SID,'account_sid':SID,'pid':123,
            'started_filetime':456,'privileges':[{'name':'SeSecurityPrivilege','attributes':0}],
            'handle_count_including_query':5,'thread_impersonation':False}
        self.report_attempts=0;self.snapshots=0
    def session(self):return session(self.fs)
    def snapshot(self):self.snapshots+=1;return copy.deepcopy(self.identity)
    def write_report(self,path,raw):
        self.report_attempts+=1;h=None
        try:
            h=self.fs.acquire(path,False,0x40000000,0,True)
            count=0
            while count<len(raw):count+=self.fs.write(h,raw[count:])
            self.fs.flush(h)
        finally:
            if h is not None:self.fs.close(h)


class SCMModel:
    def __init__(self):self.states=[];self.control=None;self.hook=lambda state:None
    def register(self,control):self.control=control
    def status(self,state,exit_code=0):
        self.states.append((state,exit_code));self.hook(state)


def fixture(fs):
    root=Path(__file__).absolute().parents[1]
    for path in [CODE,CODE/'tests',CODE/'velo_transfer']:fs.node(path,True)
    refs=[]
    for name in sorted(q.REQUIRED_SOURCES):
        data=(root/name).read_bytes();node=fs.node(CODE/PureWindowsPath(name))
        node.update(data=data,meta=(len(data),1,2,3,0x20))
        refs.append(q._ref(name,data))
    root_identity=n.DirectoryLease(ROOT,()).identity
    node=fs.nodes[str(ROOT)]
    root_identity={'platform':'windows','volume_serial':'0000000000000001',
        'file_id':node['id'][1].hex(),'owner_sid':SID,'principal_sid':SID,
        'acl_sha256':q.hashlib.sha256(node['sd']).hexdigest()}
    return {'schema_version':1,'kind':'pc026-foundation-qualification-input-v1','run_id':RUN,
        'principal_sid':SID,'namespace_root':str(ROOT),'root_identity':root_identity,
        'source_refs':refs,'budgets':{'max_directories':2,'max_record_bytes':1024,
        'max_records':3,'max_total_bytes':3072,'max_json_depth':3}}


class LifecycleModels(unittest.TestCase):
    def setup_model(self,mutate=None,raw=None):
        fs=DirectoryFS();value=fixture(fs)
        if mutate:mutate(value,fs)
        content=q._canonical(value) if raw is None else raw
        node=fs.node(CODE/'tests'/q.INPUT_NAME);node.update(data=content,meta=(len(content),1,2,3,0x20))
        native=NativeModel(fs);scm=SCMModel();service=q._Service(scm)
        for p in [patch.object(q,'_native',return_value=native),
                  patch.object(n,'_session',side_effect=lambda:session(fs)),
                  patch.object(n,'_directory_api',return_value=fs),
                  patch.object(w,'_session',side_effect=lambda:session(fs)),
                  patch.object(w,'_writer_api',return_value=fs)]:
            p.start();self.addCleanup(p.stop)
        self.addCleanup(lambda: TRACES.append({'case':self.id(),'exit_code':service.exit_code,
            'states':scm.states,'code':None if service.run is None else service.run.code,
            'created':fs.created,'actions':fs.events,'closed':fs.closed,
            'remaining_handles':list(fs.handles),'report_attempts':native.report_attempts,
            'files':{k:{'sha256':q.hashlib.sha256(v['data']).hexdigest(),'bytes':len(v['data'])} for k,v in fs.nodes.items() if not v['directory']}}))
        return service,native,fs,value
    def report(self,fs):return json.loads(fs.nodes[str(ROOT/RUN/'qualification-report.json')]['data'])
    def run_model(self,service,fs):
        service.service_main()
        self.assertFalse(fs.handles)
        self.assertEqual(len(fs.closed),len(set(fs.closed)))
        self.assertEqual(service.scm.states[-1],('STOPPED',service.exit_code))
    def test_full_success_fixed_originals_and_report_boundaries(self):
        service,native,fs,value=self.setup_model();self.run_model(service,fs)
        self.assertEqual(service.exit_code,0);self.assertEqual([s for s,_ in service.scm.states],['START_PENDING','RUNNING','STOP_PENDING','STOPPED'])
        self.assertEqual(len(fs.created),2);report=self.report(fs)
        self.assertEqual(report['outcome'],'FOUNDATION_PASS');self.assertEqual(report['verify']['event_count'],1)
        self.assertEqual(report['verify']['key']['request_id'],1);self.assertEqual(report['verify']['tool'],'qualification.foundation.MODEL')
        self.assertEqual(report['resources']['closed_before_report'],['journal','publisher'])
        self.assertNotIn('reader',report['resources']['closed_before_report'])
        self.assertEqual(report['resources']['service_main'],'ACTIVE_UNTIL_FINAL_CLOSE')
        self.assertEqual(service.run.closed,['journal','publisher','report_reader','reader','allocator'])
        self.assertEqual(native.report_attempts,1)
        self.assertEqual(report['process_before']['privileges'],report['process_after']['privileges'])
        directory_reads=[v for v in fs.events if v[0]=='open'];self.assertTrue(directory_reads)
    def test_input_gate_matrix_zero_writer(self):
        changes=[lambda v,f:v.update(schema_version=True),lambda v,f:v.update(unknown='secret'),
          lambda v,f:v.update(run_id=RUN.upper()),lambda v,f:v.update(run_id=str(q.uuid.uuid1())),
          lambda v,f:v['source_refs'].pop(),lambda v,f:v['source_refs'].append(v['source_refs'][0]),
          lambda v,f:v['source_refs'][0].update(path='../outside.py'),lambda v,f:v['source_refs'][0].update(path='Tests/__init__.py'),
          lambda v,f:v['source_refs'][0].update(path='unknown/x.py'),lambda v,f:v['source_refs'][0].update(size=True),
          lambda v,f:v['root_identity'].update(unknown=1),lambda v,f:v['budgets'].update(max_records=2),
          lambda v,f:v['budgets'].update(max_total_bytes=3071),lambda v,f:v['budgets'].update(max_directories=True),
          lambda v,f:v['budgets'].update(max_record_bytes=65537),lambda v,f:v['budgets'].update(max_json_depth=17),
          lambda v,f:v['budgets'].update(max_records=9),lambda v,f:v['budgets'].update(max_directories=9)]
        for change in changes:
            with self.subTest(change=change):
                service,_,fs,_=self.setup_model(change);self.run_model(service,fs)
                self.assertNotEqual(service.exit_code,0);self.assertFalse(fs.created)
    def test_noncanonical_duplicate_nonfinite_depth_and_oversize_full_lifecycle(self):
        fs=DirectoryFS();raw=q._canonical(fixture(fs))
        for content in [raw[:-1],raw+b'\n',b'\xef\xbb\xbf'+raw,raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1'),
            raw.replace(b'"schema_version":1',b'"schema_version":NaN'),raw.replace(b'"schema_version":1',b'"schema_version":1e999'),
            b'['*17+b'0'+b']'*17+b'\n',b'x'*(q.INPUT_LIMIT+1)]:
            with self.subTest(length=len(content)):
                service,_,fs,_=self.setup_model(raw=content);self.run_model(service,fs);self.assertFalse(fs.created);self.assertNotEqual(service.exit_code,0)
    def test_wrong_sid_missing_privilege_thread_impersonation_zero_writer(self):
        for change in [lambda x:x.update(principal_sid='S-1-5-18'),lambda x:x.update(account_sid='S-1-5-18'),
                       lambda x:x.update(privileges=[]),lambda x:x.update(thread_impersonation=True)]:
            service,native,fs,_=self.setup_model();change(native.identity);self.run_model(service,fs)
            self.assertEqual(service.exit_code,q.CODES['IDENTITY_FAILED']);self.assertFalse(fs.created)
        service,_,fs,_=self.setup_model(lambda v,f:v.update(principal_sid='S-1-5-18',root_identity=dict(v['root_identity'],principal_sid='S-1-5-18')))
        self.run_model(service,fs);self.assertFalse(fs.created)
    def test_unsafe_config_root_and_namespace_and_input_acl_zero_writer(self):
        for path in [CODE,CODE/'tests'/q.INPUT_NAME,ROOT]:
            service,_,fs,_=self.setup_model();fs.nodes[str(path)]['sd']=sd(foreign='S-1-5-11')
            self.run_model(service,fs);self.assertNotEqual(service.exit_code,0);self.assertFalse(fs.created)
        service,_,fs,_=self.setup_model(lambda v,f:v.update(namespace_root=str(CODE)))
        self.run_model(service,fs);self.assertFalse(fs.created)
    def test_source_missing_bytes_identity_and_drift_zero_writer(self):
        for mode in ['missing','hash','alias','reparse','post_read_drift']:
            service,_,fs,value=self.setup_model();path=CODE/PureWindowsPath(value['source_refs'][0]['path'])
            if mode=='missing':fs.nodes.pop(str(path))
            if mode=='hash':fs.nodes[str(path)]['data']=b'x'
            if mode=='alias':fs.nodes[str(path)]['alias']='C:\\other'
            if mode=='reparse':fs.nodes[str(path)]['reparse']=True
            if mode=='post_read_drift':
                original=q._bounded_read;seen=False
                def read(s,p,limit):
                    nonlocal seen
                    result=original(s,p,limit)
                    if p==path and not seen:seen=True;fs.nodes[str(p)]['id']=(1,b'X'*16)
                    return result
                patcher=patch.object(q,'_bounded_read',side_effect=read);patcher.start();self.addCleanup(patcher.stop)
            self.run_model(service,fs);self.assertFalse(fs.created);self.assertNotEqual(service.exit_code,0)
    def test_root_identity_mismatch_and_existing_run_no_adoption(self):
        service,_,fs,_=self.setup_model(lambda v,f:v['root_identity'].update(file_id='f'*32))
        self.run_model(service,fs);self.assertFalse(fs.created)
        service,_,fs,_=self.setup_model();fs.node(ROOT/RUN,True)['data']=b'winner'
        self.run_model(service,fs);self.assertEqual(len(fs.created),1);self.assertEqual(fs.nodes[str(ROOT/RUN)]['data'],b'winner')
        self.assertNotIn(str(ROOT/RUN/'qualification-report.json'),fs.nodes)
    def test_stop_every_boundary_never_restarts_writes(self):
        original=q._Run.boundary
        for point in range(1,30):
            service,native,fs,_=self.setup_model();calls=0
            def boundary(run):
                nonlocal calls
                calls+=1
                if calls==point:run.stop.set()
                return original(run)
            with self.subTest(point=point),patch.object(q._Run,'boundary',boundary):self.run_model(service,fs)
            self.assertEqual(service.exit_code,q.CODES['CANCELLED'])
            if str(ROOT/RUN/'qualification-report.json') in fs.nodes:self.assertEqual(self.report(fs)['outcome'],'CANCELLED')
            self.assertLessEqual(len(fs.created),2)
    def test_stop_during_write_finishes_transaction_then_cancels(self):
        service,_,fs,_=self.setup_model();done=False
        def hook(method,h):
            nonlocal done
            if method=='write' and not done:done=True;service.control(1)
        fs.hook=hook;self.run_model(service,fs)
        self.assertEqual(service.exit_code,q.CODES['CANCELLED']);report=self.report(fs)
        self.assertEqual(report['outcome'],'CANCELLED')
        self.assertIn(str(ROOT/RUN/'request'/'00000000.json'),fs.nodes)
        self.assertNotIn(str(ROOT/RUN/'request'/'00000001.json'),fs.nodes)
    def test_callback_only_signals_no_status_or_io(self):
        scm=SCMModel();service=q._Service(scm);service.control(1)
        self.assertTrue(service.stop.is_set());self.assertEqual(scm.states,[])
    def test_deadline_limits_new_stages_not_blocking_io(self):
        service,_,fs,_=self.setup_model()
        with patch.object(q._Run,'boundary',side_effect=q.QualificationError('DEADLINE')):self.run_model(service,fs)
        self.assertEqual(service.exit_code,q.CODES['DEADLINE']);self.assertFalse(fs.created)
    def test_io_unknown_prefix_preserved_failed_report_and_exit(self):
        for fault in ['write','flush','rename','after_rename']:
            service,_,fs,_=self.setup_model();done=False
            def hook(method,h):
                nonlocal done
                if method==fault and not done:done=True;raise OSError('secret IO failure')
            fs.hook=hook;self.run_model(service,fs)
            self.assertNotEqual(service.exit_code,0);report=self.report(fs);self.assertEqual(report['outcome'],'FAILED')
            self.assertNotIn('secret',json.dumps(report));self.assertTrue(any(p.endswith('.pending') or p.endswith('00000000.json') for p in fs.nodes))
    def test_report_write_read_and_exclusive_existing_fail_no_pass(self):
        for mode in ['write','read','existing']:
            service,native,fs,_=self.setup_model();original=native.write_report
            if mode=='write':native.write_report=lambda *args:(_ for _ in ()).throw(OSError('secret write'))
            if mode=='read':
                def write(path,raw):original(path,raw);fs.nodes[str(path)]['data']=b'changed'
                native.write_report=write
            if mode=='existing':
                def write(path,raw):fs.node(path)['data']=b'winner';original(path,raw)
                native.write_report=write
            self.run_model(service,fs);self.assertEqual(service.exit_code,q.CODES['REPORT_FAILED'])
            if mode=='existing':self.assertEqual(fs.nodes[str(ROOT/RUN/'qualification-report.json')]['data'],b'winner')
    def test_close_failure_and_bad_note_preserve_primary_single_attempt(self):
        service,_,fs,_=self.setup_model();primary=RuntimeError('secret primary');notes=[]
        primary.add_note=lambda note:(_ for _ in ()).throw(RuntimeError('secret note'))
        def hook(method,h):
            if method=='flush' and fs.handles[h]['node']['name'].endswith('.pending'):raise primary
            if method=='close':
                notes.append(h);del fs.handles[h];raise OSError('secret close')
        fs.hook=hook;service.service_main()
        # Reader/allocator acquisition may fail earlier on the injected close; no false success.
        self.assertNotEqual(service.exit_code,0);self.assertFalse(fs.handles)
        self.assertEqual(len(fs.closed),len(set(fs.closed)))
        run=q._Run(threading.Event());run.failure(primary,'PROBE_FAILED')
        class BadClose:
            def close(self):raise OSError('secondary')
        run.close('x',BadClose());self.assertIs(run.primary,primary);self.assertEqual(run.code,'PROBE_FAILED')
    def test_publisher_close_failure_then_failed_report(self):
        service,native,fs,_=self.setup_model();orig=native.publish
        def create(*args):
            p=orig(*args);close=p.close
            def fail():close();raise OSError('close')
            p.close=fail;return p
        native.publish=create;self.run_model(service,fs)
        self.assertEqual(service.exit_code,q.CODES['CLOSE_FAILED']);self.assertEqual(self.report(fs)['outcome'],'FAILED')
    def test_final_allocator_close_failure_cannot_upgrade_disk_pass(self):
        service,native,fs,_=self.setup_model();orig=native.allocator
        def create(*args):
            alloc=orig(*args);close=alloc.close
            def fail():close();raise OSError('close')
            alloc.close=fail;return alloc
        native.allocator=create;self.run_model(service,fs)
        self.assertEqual(service.exit_code,q.CODES['CLOSE_FAILED']);self.assertEqual(self.report(fs)['outcome'],'FOUNDATION_PASS')
        self.assertEqual(self.report(fs)['resources']['allocator_config_final_close'],'EXTERNAL_SCM_CONFIRMATION_REQUIRED')
    def test_scm_errors_each_state_fixed_nonzero_preserve_primary(self):
        for state in q.STATES:
            service,_,fs,_=self.setup_model()
            def hook(s):
                if s==state:raise OSError('secret SCM error')
            service.scm.hook=hook;service.service_main()
            self.assertEqual(service.exit_code,q.CODES['SCM_FAILED']);self.assertFalse(fs.handles)
        service,_,fs,_=self.setup_model();error=RuntimeError('original')
        with patch.object(q,'_native',side_effect=error):
            service.scm.hook=lambda s:(_ for _ in ()).throw(OSError('secondary')) if s=='STOPPED' else None
            service.service_main()
        self.assertIs(service.run.primary,error);self.assertNotEqual(service.exit_code,0)
    def test_no_business_env_network_or_backend_through_full_lifecycle(self):
        service,_,fs,_=self.setup_model()
        with patch('socket.socket',side_effect=AssertionError('network forbidden')),patch.dict(os.environ,{'VELOCIRAPTOR_ENV_FILE':'forbidden'}),patch('builtins.open',side_effect=AssertionError('file forbidden')):
            self.run_model(service,fs)
        self.assertEqual(service.exit_code,0)
        self.assertNotIn('mcp_velociraptor_bridge',sys.modules)
        self.assertNotIn('velociraptor_api',sys.modules)


class EntryModels(unittest.TestCase):
    def test_inert_import_and_dispatcher_only_no_console(self):
        spec=importlib.util.spec_from_file_location('qualification_inert',q.__file__);module=importlib.util.module_from_spec(spec)
        with patch('builtins.open',side_effect=AssertionError('I/O')),patch.object(ctypes,'WinDLL',side_effect=AssertionError('native'),create=True):
            spec.loader.exec_module(module)
        with patch.object(q,'_SCM',side_effect=q.QualificationError('SCM_FAILED')),patch.object(sys,'argv',['host']):self.assertEqual(q.main(),16)
        with patch.object(q,'_SCM',side_effect=AssertionError('must not construct')),patch.object(sys,'argv',['host','--console']):self.assertEqual(q.main(),16)
    def test_real_dispatch_wrapper_model_protocol_and_abi(self):
        service=q._Service(SCMModel());calls=[]
        with patch.object(sys,'argv',['host']),patch.object(q,'_SCM') as factory:
            factory.return_value.dispatch.side_effect=lambda s:(calls.append(s) or 17)
            self.assertEqual(q.main(),17);self.assertIsInstance(calls[0],q._Service)
        self.assertEqual(ctypes.sizeof(q._Status),28)


# os used solely for the guard test, not qualification configuration.
import os

class NativeBoundaryModels(unittest.TestCase):
    def test_scm_real_ctypes_table_callbacks_and_status_codes_with_model_win32(self):
        calls=[]
        class Function:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        control=None
        def register(name,callback):
            nonlocal control
            self.assertEqual(name,q.SERVICE_NAME);control=callback;return 999
        def status(handle,pointer):
            self.assertEqual(handle,999);value=ctypes.cast(pointer,ctypes.POINTER(q._Status)).contents
            calls.append((value.state,value.accepted,value.win32_exit,value.checkpoint,value.wait_hint));return 1
        def dispatch(table):
            self.assertEqual(table[0].name,q.SERVICE_NAME);self.assertIsNone(table[1].name)
            table[0].callback(0,None);return 1
        api=type('API',(),{})();api.RegisterServiceCtrlHandlerW=Function(register)
        api.SetServiceStatus=Function(status);api.StartServiceCtrlDispatcherW=Function(dispatch)
        service,native,fs,_=LifecycleModels.setup_model(self)
        # Only _SCM OS gate is modeled, without changing pathlib's global OS.
        with patch.object(q,'os',type('OS',(),{'name':'nt'})()),patch.object(ctypes,'WinDLL',return_value=api,create=True),patch.object(ctypes,'WINFUNCTYPE',ctypes.CFUNCTYPE,create=True):scm=q._SCM()
        service.scm=scm;self.assertEqual(scm.dispatch(service),0)
        self.assertEqual([r[0] for r in calls],[2,4,3,1]);self.assertEqual(calls[-1][2],0)
        self.assertEqual(calls[1][1],1);self.assertFalse(fs.handles)
        control(1);self.assertTrue(service.stop.is_set())
        before=len(calls);control(1);self.assertEqual(before,len(calls))
        api.SetServiceStatus=Function(lambda *args:0)
        with self.assertRaises(q.QualificationError):scm.status('RUNNING')
    def test_clock_and_stop_callback_failures_do_not_escape(self):
        scm=SCMModel();service=q._Service(scm)
        with patch.object(q,'_Run',side_effect=RuntimeError('clock secret')):service.service_main()
        self.assertEqual(service.exit_code,16);self.assertEqual(scm.states[-1],('STOPPED',16))
        service,native,fs,_=LifecycleModels.setup_model(self)
        def hook(state):
            if state=='RUNNING':
                with patch.object(service.stop,'set',side_effect=RuntimeError('callback secret')):service.control(1)
        service.scm.hook=hook;service.service_main();self.assertEqual(service.exit_code,16);self.assertFalse(fs.handles)

    def test_actual_exclusive_report_writer_partial_progress_close_and_bad_note(self):
        native=q._Native.__new__(q._Native)
        class Output:
            def __init__(self):self.data=b'';self.closes=0
            def write(self,data):self.data+=data[:2];return min(2,len(data))
            def flush(self):pass
            def fileno(self):return 42
            def close(self):self.closes+=1
        out=Output()
        with patch('builtins.open',return_value=out) as opened,patch.object(q.os,'fsync') as flushed:
            native.write_report(ROOT/'report.json',b'abcde')
        self.assertEqual(opened.call_args.args,(str(ROOT/'report.json'),'xb'))
        self.assertEqual(opened.call_args.kwargs,{'buffering':0});self.assertEqual(out.data,b'abcde')
        flushed.assert_called_once_with(42);self.assertEqual(out.closes,1)
        primary=RuntimeError('MODEL original');primary.add_note=lambda n:(_ for _ in ()).throw(RuntimeError('note'))
        out.write=lambda data:(_ for _ in ()).throw(primary)
        def failclose():out.closes+=1;raise RuntimeError('close')
        out.close=failclose
        with patch('builtins.open',return_value=out),self.assertRaises(RuntimeError) as caught:native.write_report(ROOT/'report.json',b'x')
        self.assertIs(caught.exception,primary);self.assertEqual(out.closes,2)
    def test_actual_snapshot_ctypes_queries_model_privileges_account_sid_and_closure(self):
        calls=[]
        class Function:
            def __init__(self,name,fn):self.name=name;self.fn=fn
            def __call__(self,*args):calls.append(self.name);return self.fn(*args)
        api=type('API',(),{})();kernel=type('API',(),{})()
        def function(obj,name,fn):setattr(obj,name,Function(name,fn))
        function(kernel,'GetCurrentThread',lambda:1);function(kernel,'GetCurrentProcess',lambda:2)
        function(kernel,'CloseHandle',lambda token:1)
        function(api,'OpenThreadToken',lambda *args:0)
        def token(proc,access,pointer):ctypes.cast(pointer,ctypes.POINTER(ctypes.c_void_p))[0]=99;return 1
        function(api,'OpenProcessToken',token)
        def info(token,kind,buffer,length,size):
            ctypes.cast(size,ctypes.POINTER(ctypes.c_uint32))[0]=16
            if buffer is None:return 0
            ctypes.c_uint32.from_buffer(buffer).value=1
            ctypes.c_uint32.from_buffer(buffer,12).value=0;return 1
        function(api,'GetTokenInformation',info)
        def pname(system,luid,text,size):text.value='SeSecurityPrivilege';return 1
        function(api,'LookupPrivilegeNameW',pname)
        def lookup(system,name,sid,ns,domain,nd,use):
            self.assertEqual(name,'NT SERVICE\\mcp-velociraptor')
            ctypes.cast(ns,ctypes.POINTER(ctypes.c_uint32))[0]=16
            ctypes.cast(nd,ctypes.POINTER(ctypes.c_uint32))[0]=16
            return int(sid is not None)
        function(api,'LookupAccountNameW',lookup)
        text=ctypes.create_unicode_buffer(SID)
        def convert(sid,output):ctypes.cast(output,ctypes.POINTER(ctypes.c_void_p))[0]=ctypes.addressof(text);return 1
        function(api,'ConvertSidToStringSidW',convert);function(kernel,'LocalFree',lambda p:0)
        def times(proc,*pointers):
            ctypes.cast(pointers[0],ctypes.POINTER(ctypes.c_uint64))[0]=456;return 1
        function(kernel,'GetProcessTimes',times)
        def handles(proc,output):ctypes.cast(output,ctypes.POINTER(ctypes.c_uint32))[0]=5;return 1
        function(kernel,'GetProcessHandleCount',handles)
        native=q._Native.__new__(q._Native);native.reader=n.reader
        # Ordered Win32 last-error sizing conventions, no real token operation.
        with patch.object(n.reader.acl,'_native_apis',return_value=(api,kernel)),patch.object(n.reader.acl,'current_process_sid',return_value=SID),patch.object(ctypes,'get_last_error',side_effect=[1008,122,122],create=True):snapshot=native.snapshot()
        q._principal(snapshot,SID);self.assertEqual(snapshot['started_filetime'],456)
        self.assertEqual(calls.count('CloseHandle'),1);self.assertEqual(calls.count('LocalFree'),1)
        self.assertEqual(api.OpenProcessToken.argtypes[1],ctypes.c_uint32)
        TRACES.append({'case':self.id(),'boundary':'MODEL exact ctypes token/account/process query','calls':calls,'snapshot':snapshot})

    def test_blocked_native_transaction_stop_does_not_claim_worker_exit(self):
        service,_,fs,_=LifecycleModels.setup_model(self);entered=threading.Event();release=threading.Event();once=False
        def hook(method,handle):
            nonlocal once
            if method=='flush' and not once:
                once=True;entered.set()
                if not release.wait(5):raise RuntimeError('MODEL blocking deadline')
        fs.hook=hook;thread=threading.Thread(target=service.service_main)
        thread.start()
        try:
            self.assertTrue(entered.wait(5));service.control(1)
            self.assertTrue(thread.is_alive());self.assertFalse(any(s=='STOPPED' for s,_ in service.scm.states))
            self.assertNotIn(str(ROOT/RUN/'qualification-report.json'),fs.nodes)
        finally:release.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertEqual(service.exit_code,q.CODES['CANCELLED']);self.assertFalse(fs.handles)

    def test_report_reader_close_and_post_report_source_drift_exit_failure(self):
        for mode in ('close','drift'):
            service,native,fs,_=LifecycleModels.setup_model(self)
            if mode=='close':
                original=native.session;calls=0
                def session_factory():
                    nonlocal calls
                    calls+=1;s=original()
                    if calls==2:
                        close=s.close
                        def fail():
                            if s.closed:return
                            close();raise RuntimeError('close')
                        s.close=fail
                    return s
                native.session=session_factory
            else:
                write=native.write_report
                def changed(path,raw):
                    write(path,raw);fs.nodes[str(CODE/'tests'/q.INPUT_NAME)]['sd']=sd(foreign='S-1-5-11')
                native.write_report=changed
            service.service_main();self.assertNotEqual(service.exit_code,0);self.assertFalse(fs.handles)
            self.assertEqual(LifecycleModels.report(self,fs)['outcome'],'FOUNDATION_PASS')

    def test_bounded_private_stream_primary_survives_close_and_note_failure(self):
        primary=RuntimeError('MODEL stream original');primary.add_note=lambda text:(_ for _ in ()).throw(RuntimeError('note'))
        class Stream:
            closes=0
            def __next__(self):raise primary
            def close(self):self.closes+=1;raise RuntimeError('close')
        stream=Stream()
        model=type('Reader',(),{'lock':threading.RLock(),'_stream_bound':lambda self,*args,**kwargs:stream})()
        with self.assertRaises(RuntimeError) as caught:q._bounded_read(model,ROOT/'file',1024)
        self.assertIs(caught.exception,primary);self.assertEqual(stream.closes,1)
    def test_removed_privilege_is_not_assigned_and_real_boundary_deadline(self):
        value={'principal_sid':SID,'account_sid':SID,'thread_impersonation':False,
               'privileges':[{'name':'SeSecurityPrivilege','attributes':4}]}
        with self.assertRaises(q.QualificationError):q._principal(value,SID)
        ticks=iter([0,119,120]);run=q._Run(threading.Event(),clock=lambda:next(ticks))
        run.boundary()
        with self.assertRaises(q.QualificationError) as caught:run.boundary()
        self.assertEqual(caught.exception.code,'DEADLINE')

    def test_final_token_privilege_drift_after_report_and_close_rejects_exit(self):
        service,native,fs,_=LifecycleModels.setup_model(self);original=native.snapshot
        def snapshot():
            result=original()
            if native.snapshots==7:result['privileges'][0]['attributes']=2
            return result
        native.snapshot=snapshot;service.service_main()
        self.assertEqual(native.snapshots,7);self.assertEqual(service.exit_code,q.CODES['IDENTITY_FAILED'])
        self.assertFalse(fs.handles);self.assertEqual(LifecycleModels.report(self,fs)['outcome'],'FOUNDATION_PASS')


if __name__=='__main__':unittest.main()

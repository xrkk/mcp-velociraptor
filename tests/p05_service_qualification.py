"""One-shot SCM foundation diagnostic; never a production approval or MCP tool.

Import is inert. Only main() connects to SCM; private boundaries are MODEL seams
for host tests. The fixed input is not observer configuration. Self hashes do not
establish interpreter/package provenance; external deployment authority is required.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sys
import threading
import time
import uuid

SERVICE_NAME = 'mcp-velociraptor'
INPUT_NAME = 'p05-service-qualification.json'
INPUT_LIMIT = 1 << 20
SOURCE_LIMIT = 1 << 20
REPORT_LIMIT = 1 << 20
DEADLINE_SECONDS = 120
REQUIRED_SOURCES = frozenset({
    'tests/__init__.py', 'tests/p05_service_qualification.py',
    'tests/p05_pc026_windows_reader.py', 'tests/p05_pc021_streaming.py',
    'tests/p05_pc021_readback.py', 'tests/p05_pc021_readonly.py',
    'velociraptor_observation_namespace.py', 'velociraptor_observation_windows.py',
    'velociraptor_observation_journal.py', 'velociraptor_observation_archive.py',
    'velo_transfer/__init__.py', 'velo_transfer/errors.py', 'velo_transfer/manifest.py',
    'velo_transfer/bundle.py', 'velo_transfer/filesystem.py', 'velo_transfer/windows_platform.py',
})
# The fixed records fit the minimum ceilings; no clipping or inferred defaults.
BUDGET_RANGES = {'max_directories': (2, 8), 'max_record_bytes': (1024, 65536),
                 'max_records': (3, 8), 'max_total_bytes': (3072, 524288),
                 'max_json_depth': (3, 16)}
CODES = {'FOUNDATION_PASS': 0, 'CONFIG_FAILED': 10, 'IDENTITY_FAILED': 11,
         'SOURCE_FAILED': 12, 'PROBE_FAILED': 13, 'REPORT_FAILED': 14,
         'CLOSE_FAILED': 15, 'SCM_FAILED': 16, 'CANCELLED': 17, 'DEADLINE': 18}
STATES = {'STOPPED': 1, 'START_PENDING': 2, 'STOP_PENDING': 3, 'RUNNING': 4}
_ID_FIELDS = {'platform', 'volume_serial', 'file_id', 'owner_sid', 'principal_sid', 'acl_sha256'}


class QualificationError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _note(primary, text):
    try:
        primary.add_note(text)
    except BaseException:
        pass


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise QualificationError('CONFIG_FAILED')
        value[key] = item
    return value


def _reject_constant(value):
    raise QualificationError('CONFIG_FAILED')


def _require(value, code='CONFIG_FAILED'):
    if not value:
        raise QualificationError(code)


def _sid(value):
    return type(value) is str and re.fullmatch(r'S-1-(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}', value) is not None


def _identity(value):
    _require(type(value) is dict and set(value) == _ID_FIELDS)
    _require(value['platform'] == 'windows' and _sid(value['owner_sid']) and _sid(value['principal_sid']))
    for key, length in (('volume_serial', 16), ('file_id', 32), ('acl_sha256', 64)):
        _require(type(value[key]) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value[key]) is not None)


def _parse(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= INPUT_LIMIT)
    # Bound recursive decoder BEFORE parsing. Strings/escaped braces don't nest.
    depth = 0
    quoted = escaped = False
    for b in raw:
        if quoted:
            if escaped: escaped = False
            elif b == 92: escaped = True
            elif b == 34: quoted = False
        elif b == 34: quoted = True
        elif b in (123, 91):
            depth += 1
            _require(depth <= 16)
        elif b in (125, 93): depth -= 1
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_reject_constant)
        _require(_canonical(value) == raw)
        _require(type(value) is dict and set(value) == {'schema_version', 'kind', 'run_id',
            'principal_sid', 'namespace_root', 'root_identity', 'source_refs', 'budgets'})
        _require(type(value['schema_version']) is int and value['schema_version'] == 1)
        _require(value['kind'] == 'pc026-foundation-qualification-input-v1')
        run = uuid.UUID(value['run_id'])
        _require(run.version == 4 and str(run) == value['run_id'])
        _require(_sid(value['principal_sid']) and type(value['namespace_root']) is str)
        _identity(value['root_identity'])
        _require(value['root_identity']['principal_sid'] == value['principal_sid'])
        refs = value['source_refs']
        _require(type(refs) is list and len(refs) == len(REQUIRED_SOURCES))
        seen = set()
        for ref in refs:
            _require(type(ref) is dict and set(ref) == {'path', 'size', 'sha256'})
            # Exact code-owned catalog excludes absolute/escape/case aliases and unknown dirs.
            _require(type(ref['path']) is str and ref['path'] in REQUIRED_SOURCES and ref['path'] not in seen)
            _require(type(ref['size']) is int and 0 <= ref['size'] <= SOURCE_LIMIT)
            _require(type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}', ref['sha256']) is not None)
            seen.add(ref['path'])
        _require(seen == REQUIRED_SOURCES)
        budgets = value['budgets']
        _require(type(budgets) is dict and set(budgets) == set(BUDGET_RANGES))
        for key, (low, high) in BUDGET_RANGES.items():
            _require(type(budgets[key]) is int and low <= budgets[key] <= high)
        _require(budgets['max_total_bytes'] >= 3 * budgets['max_record_bytes'])
        return value
    except QualificationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError, OverflowError) as cause:
        raise QualificationError('CONFIG_FAILED') from cause


def _ref(path, raw):
    return {'path': str(path), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _bounded_read(session, path, maximum):
    # private state + fullSD/LIST, retained same handles, bounded before collection.
    with session.lock:
        stream = session._stream_bound(path, private=True)
        chunks, count, primary = [], 0, None
        try:
            while True:
                try: chunk = next(stream)
                except StopIteration as end:
                    return b''.join(chunks), *end.value
                _require(type(chunk) is bytes and len(chunk) <= 65536, 'SOURCE_FAILED')
                count += len(chunk)
                _require(count <= maximum, 'SOURCE_FAILED')
                chunks.append(chunk)
        except BaseException as error:
            primary=error
            raise
        finally:
            try: stream.close()
            except BaseException:
                if primary is None: raise
                _note(primary,'qualification_stream_close_failed')


class _Native:
    """Private deferred native boundary. No environment, backend, HTTP or grants."""
    def __init__(self):
        _require(os.name == 'nt', 'IDENTITY_FAILED')
        self.root = PureWindowsPath(str(Path(__file__).absolute().parents[1]))
        modules = ('tests.p05_pc026_windows_reader', 'velociraptor_observation_namespace',
                   'velociraptor_observation_windows', 'velociraptor_observation_journal',
                   'velociraptor_observation_archive')
        sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
        loaded = [importlib.import_module(name) for name in modules]
        for path in REQUIRED_SOURCES:
            name = path[:-3].replace('/', '.')
            if name.endswith('.__init__'): name = name[:-9]
            module = sys.modules.get(name)
            if module is not None:
                _require(Path(module.__file__).absolute() == Path(str(self.root / path)), 'SOURCE_FAILED')
        self.reader, self.namespace, self.publisher, self.journal, self.archive = loaded

    def session(self): return self.reader.WindowsSession()
    def allocator(self, root, budget):
        return self.namespace.WindowsDirectoryAllocator(root, max_directories=budget)
    def publish(self, path, budgets): return self.publisher.WindowsRecordPublisher(path, **budgets)
    def codec(self, budgets): return self.archive.ArchiveCodec(**budgets)
    def journal_for(self, publisher, codec, payload):
        return self.journal.RequestJournal(publisher, codec, payload, owns_publisher=False)

    def snapshot(self):
        # Explicit ctypes signatures independent of production service_host globals.
        a, k = self.reader.acl._native_apis()
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.GetCurrentThread.restype = ctypes.c_void_p
        k.CloseHandle.argtypes = [ctypes.c_void_p]; k.CloseHandle.restype = ctypes.c_int
        a.OpenThreadToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        a.OpenThreadToken.restype = ctypes.c_int
        a.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        a.OpenProcessToken.restype = ctypes.c_int
        a.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        a.GetTokenInformation.restype = ctypes.c_int
        a.LookupPrivilegeNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        a.LookupPrivilegeNameW.restype = ctypes.c_int
        token = ctypes.c_void_p()
        if a.OpenThreadToken(k.GetCurrentThread(), 8, True, ctypes.byref(token)):
            _require(k.CloseHandle(token), 'CLOSE_FAILED')
            raise QualificationError('IDENTITY_FAILED')
        _require(ctypes.get_last_error() == 1008, 'IDENTITY_FAILED')
        _require(a.OpenProcessToken(k.GetCurrentProcess(), 8, ctypes.byref(token)), 'IDENTITY_FAILED')
        primary = None
        try:
            size = ctypes.c_uint32()
            _require(not a.GetTokenInformation(token, 3, None, 0, ctypes.byref(size)) and ctypes.get_last_error() == 122, 'IDENTITY_FAILED')
            _require(4 <= size.value <= 65536, 'IDENTITY_FAILED')
            buf = ctypes.create_string_buffer(size.value)
            _require(a.GetTokenInformation(token, 3, buf, len(buf), ctypes.byref(size)), 'IDENTITY_FAILED')
            count = ctypes.c_uint32.from_buffer(buf).value
            _require(count <= 256 and 4+count*12 <= len(buf), 'IDENTITY_FAILED')
            privileges = []
            for i in range(count):
                n = ctypes.c_uint32(256); name = ctypes.create_unicode_buffer(256)
                _require(a.LookupPrivilegeNameW(None, ctypes.byref(buf, 4+i*12), name, ctypes.byref(n)), 'IDENTITY_FAILED')
                privileges.append({'name': name.value, 'attributes': ctypes.c_uint32.from_buffer(buf, 12+i*12).value})
            sid = self.reader.acl.current_process_sid()
            # LookupAccountName SID is independent of caller's supplied principal.
            a.LookupAccountNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
            a.LookupAccountNameW.restype = ctypes.c_int
            ns, nd, use = ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32()
            _require(not a.LookupAccountNameW(None, 'NT SERVICE\\'+SERVICE_NAME, None, ctypes.byref(ns), None, ctypes.byref(nd), ctypes.byref(use)) and ctypes.get_last_error()==122, 'IDENTITY_FAILED')
            _require(8 <= ns.value <= 256 and nd.value <= 256, 'IDENTITY_FAILED')
            sidbuf, domain = ctypes.create_string_buffer(ns.value), ctypes.create_unicode_buffer(max(1,nd.value))
            _require(a.LookupAccountNameW(None,'NT SERVICE\\'+SERVICE_NAME,sidbuf,ctypes.byref(ns),domain,ctypes.byref(nd),ctypes.byref(use)), 'IDENTITY_FAILED')
            a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
            a.ConvertSidToStringSidW.restype = ctypes.c_int
            k.LocalFree.argtypes = [ctypes.c_void_p]; k.LocalFree.restype = ctypes.c_void_p
            text = ctypes.c_wchar_p()
            _require(a.ConvertSidToStringSidW(sidbuf,ctypes.byref(text)), 'IDENTITY_FAILED')
            try: account_sid = text.value
            finally: _require(not k.LocalFree(ctypes.cast(text,ctypes.c_void_p)), 'CLOSE_FAILED')
            times = (ctypes.c_uint64 * 4)()
            k.GetProcessTimes.argtypes = [ctypes.c_void_p]+[ctypes.c_void_p]*4; k.GetProcessTimes.restype=ctypes.c_int
            _require(k.GetProcessTimes(k.GetCurrentProcess(),*[ctypes.byref(times,i*8) for i in range(4)]), 'IDENTITY_FAILED')
            handles=ctypes.c_uint32()
            k.GetProcessHandleCount.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]; k.GetProcessHandleCount.restype=ctypes.c_int
            _require(k.GetProcessHandleCount(k.GetCurrentProcess(),ctypes.byref(handles)), 'IDENTITY_FAILED')
            return {'principal_sid':sid,'account_sid':account_sid,'pid':os.getpid(),
                'started_filetime':int(times[0]),'privileges':sorted(privileges,key=lambda p:p['name']),
                'handle_count_including_query':handles.value,'thread_impersonation':False}
        except BaseException as exc:
            primary=exc;raise
        finally:
            try: _require(k.CloseHandle(token), 'CLOSE_FAILED')
            except BaseException:
                if primary is None: raise
                _note(primary,'token_close_failed')

    def write_report(self, path, raw):
        # Not a 09 atomic publication. CREATE_NEW, short writes, flush, single close.
        output = open(str(path), 'xb', buffering=0)
        primary = None
        try:
            count=0
            while count < len(raw):
                n=output.write(raw[count:])
                _require(type(n) is int and 0 < n <= len(raw)-count,'REPORT_FAILED')
                count+=n
            output.flush()
            os.fsync(output.fileno())
        except BaseException as error:
            primary=error
            raise
        finally:
            try: output.close()  # One attempt, including ambiguous close.
            except BaseException:
                if primary is None: raise
                _note(primary,'report_writer_close_failed')


def _native(): return _Native()


def _principal(snapshot, expected=None):
    _require(snapshot['thread_impersonation'] is False and snapshot['principal_sid']==snapshot['account_sid'], 'IDENTITY_FAILED')
    if expected is not None: _require(snapshot['principal_sid']==expected,'IDENTITY_FAILED')
    _require(any(p['name']=='SeSecurityPrivilege' and not p['attributes'] & 4 for p in snapshot['privileges']), 'IDENTITY_FAILED')


class _Run:
    """Synchronous worker; deadline/STOP prohibit new stages, never interrupt I/O."""
    def __init__(self, stop, clock=time.monotonic):
        self.stop,self.clock=stop,clock
        self.deadline=clock()+DEADLINE_SECONDS
        self.primary=None
        self.code='FOUNDATION_PASS'
        self.closed=[]

    def boundary(self):
        if self.stop.is_set(): raise QualificationError('CANCELLED')
        if self.clock()>=self.deadline: raise QualificationError('DEADLINE')

    def failure(self, error, fallback):
        if self.primary is None:
            self.primary=error
            self.code=error.code if isinstance(error,QualificationError) and error.code in CODES else fallback
        else: _note(self.primary,'qualification_secondary_failure')

    def close(self, name, resource):
        if resource is None: return
        try:
            resource.close()
            self.closed.append(name)
        except BaseException as error:
            self.failure(error,'CLOSE_FAILED')

    def execute(self, native):
        reader=allocator=publisher=journal=None
        run=request=None
        inputs=input_ref=before=after=None
        records=[];verified=None;sources=[];retained={}
        stage='IDENTITY_FAILED'
        try:
            self.boundary();before=native.snapshot();_principal(before)
            self.boundary();stage='CONFIG_FAILED';reader=native.session()
            input_path=native.root/'tests'/INPUT_NAME
            raw,obs,identity=_bounded_read(reader,input_path,INPUT_LIMIT)
            inputs=_parse(raw);input_ref=_ref('tests/'+INPUT_NAME,raw)
            _principal(before,inputs['principal_sid'])
            _require(reader.sid==inputs['principal_sid'],'IDENTITY_FAILED')
            retained[input_path]=(raw,obs,identity)
            stage='SOURCE_FAILED'
            for ref in inputs['source_refs']:
                self.boundary()
                path=native.root/PureWindowsPath(ref['path'])
                data,obs,ident=_bounded_read(reader,path,SOURCE_LIMIT)
                _require(_ref(ref['path'],data)==ref,'SOURCE_FAILED')
                retained[path]=(data,obs,ident);sources.append(dict(ref))
            self.boundary();stage='PROBE_FAILED'
            namespace = native.reader.check_path(inputs['namespace_root'])
            left, right = str(namespace).casefold(), str(native.root).casefold()
            _require(left != right and not left.startswith(right+'\\') and not right.startswith(left+'\\'), 'CONFIG_FAILED')
            allocator=native.allocator(namespace,inputs['budgets']['max_directories'])
            _require(allocator.root.identity==inputs['root_identity'],'IDENTITY_FAILED')
            # Recheck input/source before any directory writer action.
            def recheck():
                _principal(native.snapshot(),inputs['principal_sid'])
                for path,observed in retained.items():
                    _require(_bounded_read(reader,path,SOURCE_LIMIT)==observed,'SOURCE_FAILED')
                allocator.recheck(allocator.root)
            recheck();self.boundary()
            run=allocator.allocate(allocator.root,inputs['run_id'])
            self.boundary();request=allocator.allocate(run,'request')
            self.boundary();allocator.recheck(request)
            budgets={k:v for k,v in inputs['budgets'].items() if k!='max_directories'}
            codec=native.codec(budgets)
            publisher=native.publish(request.path,budgets)
            allocator.recheck(request);self.boundary()
            key={'instance_id':'qualification:'+inputs['run_id'], 'session_id':'MODEL-foundation',
                 'request_id_type':'integer','request_id':1}
            payload={'key':key,'tool':'qualification.foundation.MODEL',
                     'arguments_sha256':hashlib.sha256(b'{}').hexdigest(),'acceptance_sequence':1}
            event={'sequence':1,'kind':'target.resolve','facts':{
                'operation_id':None,'mode':'selected','client_id':'MODEL-qualification-client'}}
            expected=[codec.encode({'schema_version':1,'kind':native.archive.ACCEPT,'sequence':0,'previous':None,'payload':payload})]
            expected.append(codec.encode({'schema_version':1,'kind':native.archive.EVENT,'sequence':1,
                'previous':{k:v for k,v in _ref('',expected[-1]).items() if k!='path'},'payload':event}))
            expected.append(codec.encode({'schema_version':1,'kind':native.archive.SEAL,'sequence':2,
                'previous':{k:v for k,v in _ref('',expected[-1]).items() if k!='path'},
                'payload':{'outcome':'returned','archive_status':'COMPLETE','event_count':1}}))
            journal=native.journal_for(publisher,codec,payload)
            self.boundary()
            journal.append(event)
            self.boundary();journal.seal('returned')
            self.close('journal',journal);journal=None
            self.close('publisher',publisher);publisher=None
            _require(self.primary is None,'CLOSE_FAILED')
            self.boundary();allocator.recheck(request)
            originals=[]
            for i in range(3):
                path=request.path/f'{i:08d}.json'
                data,obs,ident=_bounded_read(reader,path,budgets['max_record_bytes'])
                _require(data==expected[i],'PROBE_FAILED')
                records.append({'ref':_ref(f'request/{i:08d}.json',data),'identity':ident})
                retained[path]=(data,obs,ident);originals.append(data)
            verified=codec.verify(iter(originals))
            _require(verified['status']=='COMPLETE' and verified['outcome']=='returned' and verified['event_count']==1,'PROBE_FAILED')
            recheck();allocator.recheck(run)
            self.boundary();after=native.snapshot();_principal(after,inputs['principal_sid'])
            _require(before['privileges']==after['privileges'],'IDENTITY_FAILED')
        except BaseException as error:
            self.failure(error,stage)
        finally:
            self.close('journal',journal)
            self.close('publisher',publisher)
        # Report only in a successfully acquired safe run, never cwd/old Logs.
        if run is not None:
            report_reader=None
            try:
                # STOP allows a final CANCELLED diagnostic, not another probe action.
                if self.primary is None:
                    try: self.boundary()
                    except BaseException as error: self.failure(error,'REPORT_FAILED')
                allocator.recheck(run)
                diagnostic=native.snapshot();_principal(diagnostic,inputs['principal_sid'])
                if before is not None:
                    _require(before['privileges']==diagnostic['privileges'],'IDENTITY_FAILED')
                report={'schema_version':1,'kind':'pc026-foundation-qualification-report-v1',
                    'outcome':('FOUNDATION_PASS' if self.primary is None else 'CANCELLED' if self.code=='CANCELLED' else 'FAILED'),
                    'code':self.code,'input_ref':input_ref,'source_refs':sources,
                    'process_before':before,'process_after':after or diagnostic,
                    'run_identity':run.identity,'request_identity':None if request is None else request.identity,
                    'records':records,'verify':verified,'resources':{'closed_before_report':list(self.closed),
                    'background_workers':0,'service_main':'ACTIVE_UNTIL_FINAL_CLOSE','allocator_config_final_close':'EXTERNAL_SCM_CONFIRMATION_REQUIRED'},
                    'boundary':'DIAGNOSTIC_ONLY_EXTERNAL_RUNTIME_AUTHORITY_REQUIRED'}
                raw=_canonical(report);_require(len(raw)<=REPORT_LIMIT,'REPORT_FAILED')
                path=run.path/'qualification-report.json'
                native.write_report(path,raw)
                report_reader=native.session()
                observed,_,_= _bounded_read(report_reader,path,REPORT_LIMIT)
                _require(observed==raw,'REPORT_FAILED')
                allocator.recheck(run)
                _principal(native.snapshot(),inputs['principal_sid'])
                for retained_path, prior in retained.items():
                    _require(_bounded_read(reader,retained_path,SOURCE_LIMIT)==prior,'SOURCE_FAILED')
            except BaseException as error: self.failure(error,'REPORT_FAILED')
            finally: self.close('report_reader',report_reader)
        self.close('reader',reader)
        self.close('allocator',allocator)
        if before is not None:
            try:
                final=native.snapshot()
                _principal(final,before['principal_sid'])
                _require(final['pid']==before['pid'] and final['started_filetime']==before['started_filetime']
                         and final['privileges']==before['privileges'],'IDENTITY_FAILED')
            except BaseException as error: self.failure(error,'IDENTITY_FAILED')
        return CODES[self.code]


class _Service:
    def __init__(self, scm):
        self.scm=scm;self.stop=threading.Event();self.run=None;self.exit_code=CODES['SCM_FAILED']
        self.control_failed=False

    def control(self, control):
        if control==1:
            try: self.stop.set()  # callback never writes files/status or kills worker
            except BaseException: self.control_failed=True

    def service_main(self, argc=0, argv=None):
        try: self.run=_Run(self.stop)
        except BaseException:
            # Even a clock-construction failure cannot escape a ctypes callback.
            self.exit_code=CODES['SCM_FAILED']
            for state in ('STOP_PENDING','STOPPED'):
                try: self.scm.status(state,self.exit_code if state=='STOPPED' else 0)
                except BaseException: pass
            return
        stage='SCM_FAILED'
        try:
            self.scm.register(self.control)
            self.scm.status('START_PENDING')
            self.run.boundary()
            native=_native()
            self.scm.status('RUNNING')  # probe executing only, no production meaning
            self.run.execute(native)
            _require(not self.control_failed,'SCM_FAILED')
        except BaseException as error: self.run.failure(error,stage)
        finally:
            try: self.scm.status('STOP_PENDING')
            except BaseException as error: self.run.failure(error,'SCM_FAILED')
            self.exit_code=CODES[self.run.code]
            try: self.scm.status('STOPPED',self.exit_code)
            except BaseException as error:
                self.run.failure(error,'SCM_FAILED');self.exit_code=CODES[self.run.code]


class _Status(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint32) for name in ('service_type','state','accepted',
              'win32_exit','specific_exit','checkpoint','wait_hint')]


class _SCM:
    def __init__(self):
        _require(os.name=='nt','SCM_FAILED')
        self.api=ctypes.WinDLL('advapi32',use_last_error=True)
        self.main_type=ctypes.WINFUNCTYPE(None,ctypes.c_uint32,ctypes.POINTER(ctypes.c_wchar_p))
        self.control_type=ctypes.WINFUNCTYPE(None,ctypes.c_uint32)
        class Table(ctypes.Structure):
            _fields_=[('name',ctypes.c_wchar_p),('callback',self.main_type)]
        self.Table=Table;self.handle=None;self.checkpoint=0
        self.api.RegisterServiceCtrlHandlerW.argtypes=[ctypes.c_wchar_p,self.control_type]
        self.api.RegisterServiceCtrlHandlerW.restype=ctypes.c_void_p
        self.api.SetServiceStatus.argtypes=[ctypes.c_void_p,ctypes.POINTER(_Status)]
        self.api.SetServiceStatus.restype=ctypes.c_int
        self.api.StartServiceCtrlDispatcherW.argtypes=[ctypes.POINTER(Table)]
        self.api.StartServiceCtrlDispatcherW.restype=ctypes.c_int

    def register(self, control):
        self.control_callback=self.control_type(control)
        self.handle=self.api.RegisterServiceCtrlHandlerW(SERVICE_NAME,self.control_callback)
        _require(bool(self.handle),'SCM_FAILED')

    def status(self,state,exit_code=0):
        pending=state in ('START_PENDING','STOP_PENDING')
        self.checkpoint=self.checkpoint+1 if pending else 0
        status=_Status(16,STATES[state],1 if state=='RUNNING' else 0,
                       exit_code,0,self.checkpoint,5000 if pending else 0)
        _require(self.handle and self.api.SetServiceStatus(self.handle,ctypes.byref(status)),'SCM_FAILED')

    def dispatch(self, service):
        self.main_callback=self.main_type(service.service_main)
        self.table=(self.Table*2)(self.Table(SERVICE_NAME,self.main_callback),self.Table(None,self.main_type()))
        _require(self.api.StartServiceCtrlDispatcherW(self.table),'SCM_FAILED')
        return service.exit_code


def main():
    # No console mode, CLI root/SID/input/Win32 adapter override or installation.
    if len(sys.argv)!=1: return CODES['SCM_FAILED']
    try:
        scm=_SCM()
        return scm.dispatch(_Service(scm))
    except BaseException:
        return CODES['SCM_FAILED']


if __name__=='__main__': raise SystemExit(main())

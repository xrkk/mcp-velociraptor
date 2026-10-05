"""C3 native export, privately borrowed from the fixed approved ledger.

No public root/publisher/group or platform overrides. Source authority is the
ledger-issued, safely closed prefix; content codecs grant no close authority.
Only the ledger closes the borrowed governed group and retained allocators.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import threading

from tests.p05_pc026_windows_reader import WindowsSession, MAX_SD_BYTES, _note
from velociraptor_observation_namespace import WindowsDirectoryAllocator, _path
from velociraptor_observation_windows import _RecordTransaction
from velociraptor_observation_cut import CutCodec, canonical, ref, _require
from velociraptor_observation_catalog import _directory


def _free_bytes(root):
    # Actual caller-available Win32 free bytes. No portable production fallback.
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    api = kernel.GetDiskFreeSpaceExW
    api.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64),
                   ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
    api.restype = ctypes.c_int
    available, total, free = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
    if not api(str(root), ctypes.byref(available), ctypes.byref(total), ctypes.byref(free)):
        raise RuntimeError('export_free_space_unavailable')
    return available.value


def _plan(archive, budgets):
    old = archive.document['budgets']
    A, C = old['max_attempts'], old['max_catalog_record_bytes']
    R, B, T = (old['request_codec'][k] for k in ('max_records','max_record_bytes','max_total_bytes'))
    K, P, J = (budgets[k] for k in ('max_cut_bytes','max_proof_bytes','max_source_manifest_bytes'))
    N = 3*A+2+A*R
    pending = max(K,P,J,B,C,MAX_SD_BYTES)
    return dict(files=2*N+5, directories=A+4,
        bytes=(3*A+2)*C+A*T+N*MAX_SD_BYTES+P+J+3*K, pending=pending)


def _preflight(archive, budgets):
    """Read-only candidate/root/physical-free gate before any writer or RPC."""
    root = _path(archive.document['guest_namespace_root'])
    base = root / ('e'+'0'*32) / ('s'+'0'*64)
    for directory in (base, base/'originals', base/'originals'/'c',
                      base/'originals'/('r'+'9'*12+'-'+'0'*64), base/'sd'):
        _path(directory)
        _path(directory/('0'*36+'.pending'))
        names = (['0'*64+'.bin'] if directory.name=='sd' else
                 ['source-manifest.json','lifecycle.json','attempts.json','cut.json','export.json']
                 if directory==base else ['99999999.json'])
        for name in names:_path(directory/name)
    plan = _plan(archive,budgets)
    reader=None;primary=None
    try:
        reader=WindowsSession()
        chain=list(reversed(root.parents))+[root]
        observations=[reader._bind(p,True,'state' if p==root else 'ancestor')[1] for p in chain]
        _require(len({r[0][0] for r in observations})==1,'export_preflight_volume')
        from tests.p05_pc026_windows_reader import descriptor_snapshot
        identity,sd,_=observations[-1]
        actual=dict(platform='windows',volume_serial=f'{identity[0]:016x}',file_id=identity[1].hex(),
            owner_sid=descriptor_snapshot(sd).owner_sid,principal_sid=reader.sid,acl_sha256=hashlib.sha256(sd).hexdigest())
        _require(actual==archive.document['root_identity'] and sd==archive.root_sd,'export_preflight_root')
        _require(_free_bytes(root)>=budgets['min_free_bytes']+plan['bytes']+plan['pending'],'export_free_space')
        archive.group.recheck()
    except BaseException as error:primary=error;raise
    finally:
        if reader is not None:
            try:reader.close()
            except BaseException:
                if primary is None:raise
                _note(primary,'export_preflight_close_failed')
    return plan


class NativeExporter:
    def __init__(self):
        raise TypeError('exporters are ledger-owned')

    @classmethod
    def _borrow(cls, ledger, lifecycle):
        from velociraptor_observation_startup import CONFIG
        _require(ledger._exporter is None and not ledger._closed and not ledger._unknown,'export_ledger_owner')
        self = object.__new__(cls)
        self._ledger, self._config = ledger, ledger._config
        self.codec = CutCodec(lifecycle['budgets'])
        self.lifecycle_config_raw = self._config.group.read(self._config.group.allowed[CONFIG])
        _require(canonical(lifecycle)==self.lifecycle_config_raw,'export_lifecycle_original')
        self._plan = _preflight(self._config,self.codec.limits)
        self._lock = threading.RLock()
        self._receipt_lock = threading.Lock()
        self._reservations, self.completed = {}, {}
        self._sources = {}
        self._pending_reserved = 0
        self._allocator = None
        self._instance_dir = None
        self.closed = False
        try:
            self._allocator = WindowsDirectoryAllocator(self._config.document['guest_namespace_root'],
                max_directories=self.codec.limits['max_export_directories'])
            self._check(self._allocator.root)
        except BaseException as primary:
            if self._allocator is not None:
                try:self._allocator.close()
                except BaseException:_note(primary,'export_allocator_close_failed')
            raise
        ledger._exporter = self  # Sole cleanup owner; never close borrowed group.
        return self

    def _check(self, lease):
        _require(not self.closed and not self._ledger._unknown and not self._ledger._closed,'export_owner_unknown')
        self._ledger._recheck(self._ledger._allocator.root)
        self._allocator.recheck(lease)
        root = self._allocator.root
        _require(root.identity==self._config.document['root_identity'],'export_root_identity')
        _require(self._allocator._session._bind(root.path,True,'state')[1][1]==self._config.root_sd,'export_root_sd')

    def reserve(self, session):
        """Atomic shared worst-case reserve BEFORE the source prefix is copied.

        Permanent per-session reservations survive failure/timeout. A native
        task retains the pending lane until its finally; no caller can recycle
        unknown resources. Publisher concurrency is serialized by this lock.
        """
        _require(type(session) is str and bool(session),'export_session')
        with self._lock:
            self._check(self._allocator.root)
            _require(session not in self._reservations,'export_reservation_duplicate')
            count=len(self._reservations)+1; b=self.codec.limits; p=self._plan
            _require(count<=b['max_sessions'],'export_sessions')
            _require(count*p['files']<=b['max_export_files'],'export_files')
            _require(1+count*p['directories']<=b['max_export_directories'],'export_directories')
            _require(count*p['bytes']+p['pending']<=b['max_export_bytes'],'export_bytes')
            _require(_free_bytes(self._allocator.root.path)>=b['min_free_bytes']+count*p['bytes']+p['pending'],'export_free_space')
            # Use the actual approved root, not a fabricated short candidate.
            base=self._allocator.root.path/('e'+self._ledger._instance)/('s'+hashlib.sha256(session.encode('utf-8')).hexdigest())
            _path(base/('originals')/('r'+'9'*12+'-'+'0'*64)/('0'*36+'.pending'))
            self._reservations[session] = object()

    def receipt(self, session, descriptor):
        with self._receipt_lock:return self.completed.get(session)==descriptor

    def _namespace_source(self, path):
        from pathlib import PureWindowsPath
        return PureWindowsPath(path).is_relative_to(self._allocator.root.path)

    def _source_path(self, session):
        # Derived only from our actual published receipt; no caller root.
        with self._receipt_lock:
            source=self._sources.get(session)
            _require(source is not None and session in self.completed,'maintenance_receipt_missing')
            return source[0].path

    def _maintenance_source(self, session):
        """No-follow full identity/SD/hash/closure readback before transfer writer.

        The immutable snapshot comes from the actual final native readback.
        Return sizes only; transfer still reads the real files through its own
        authorized policy, worker and source stability protocol.
        """
        with self._lock:
            with self._receipt_lock:source=self._sources.get(session)
            _require(source is not None,'maintenance_receipt_missing')
            base,leases,snapshot=source
            expected=json.loads(snapshot)
            reader=WindowsSession();primary=None
            try:
                _require(reader.sid==self._allocator.root.identity['principal_sid'],'maintenance_principal')
                names={name:set() for name in leases}
                for name in leases:
                    if name:
                        parent,child=name.rsplit('/',1) if '/' in name else ('',name)
                        names[parent].add(child)
                for member in expected['members']:
                    name=member['path'];parent,child=name.rsplit('/',1) if '/' in name else ('',name)
                    names[parent].add(child)
                def check():
                    for name,lease in leases.items():
                        self._check(lease)
                        _require(reader._directory_names(lease.path,len(names[name])+1,directories=True)==frozenset(names[name]),'maintenance_source_closure')
                check()
                for member in expected['members']:
                    name=member['path']
                    raw,_,identity=reader._read_original(base.path/name.replace('/','\\'),member['size'])
                    _require(identity==expected['identities'][name] and ref(name,raw)==member,'maintenance_source_drift')
                check()
                return dict(files=len(expected['members']),bytes=sum(r['size'] for r in expected['members']))
            except BaseException as error:primary=error;raise
            finally:
                try:reader.close()
                except BaseException:
                    if primary is None:raise
                    _note(primary,'maintenance_source_close_failed')

    def _documents(self, prefix, lifecycle):
        from velociraptor_observation_startup import CONFIG
        _require(self._ledger._issued_prefixes.get(prefix.session) is prefix,'export_prefix_not_issued')
        _require(prefix.instance==self._ledger._instance,'export_prefix_instance')
        originals={r.path:r for r in prefix.originals}
        _require(len(originals)==len(prefix.originals),'export_source_duplicate')
        common=dict(schema_version=1,instance_id=prefix.instance,session_id=prefix.session)
        files={}; manifest=[]
        root=self._allocator.root.identity
        for path,row in originals.items():
            identity=json.loads(row.identity)
            _require(identity['principal_sid']==root['principal_sid'] and identity['volume_serial']==root['volume_serial'],
                'export_source_principal_volume')
            from tests.p05_pc026_windows_reader import descriptor_snapshot, acl
            snapshot=descriptor_snapshot(row.sd)
            _require(snapshot.owner_sid==identity['owner_sid'],'export_source_owner')
            acl._evaluate(snapshot,'state',self._allocator._session.trusted)
            _require(hashlib.sha256(row.sd).hexdigest()==identity['acl_sha256'],'export_source_sd')
            sd_name='sd/'+identity['acl_sha256']+'.bin'
            files['originals/'+path]=row.raw;files[sd_name]=row.sd
            manifest.append(dict(source_ref=ref(path,row.raw),export_ref=ref('originals/'+path,row.raw),
                identity=identity,sd_ref=ref(sd_name,row.sd)))
        catalog=[originals[f'c/{i:08d}.json'].raw for i in range(prefix.catalog_count)]
        begins={r['payload']['attempt_sequence']:r['payload'] for raw in catalog
            if (r:=self._config.catalog_codec.parse(raw))['record_type']=='ATTEMPT_BEGIN'}
        head=dict(json.loads(prefix.catalog_head),path=f'c/{prefix.catalog_count-1:08d}.json')
        cfg=ref(CONFIG,self.lifecycle_config_raw)
        source=dict(common,kind='pc026-observation-export-source-v1',config_ref=cfg,catalog_head=head,files=manifest,status='OBSERVED')
        lifecycle=dict(lifecycle,attempt_sequences=list(prefix.attempts))
        projection=dict(common,kind='pc026-observation-session-projection-v1',catalog_prefix=[ref(f'originals/c/{i:08d}.json',raw)
            for i,raw in enumerate(catalog)],attempt_sequences=list(prefix.attempts),request_records=[],lifecycle_ref={})
        for n in prefix.attempts:
            begin=begins[n]
            if begin['decision']=='NEW':
                directory=_directory(n,begin['key'])
                records=[ref('originals/'+p,originals[p].raw) for p in sorted(originals) if p.startswith(directory+'/')]
                projection['request_records'].append(dict(attempt_sequence=n,records=records))
        files['source-manifest.json']=self.codec.encode(source,'source')
        files['lifecycle.json']=self.codec.encode(lifecycle,'lifecycle')
        projection['lifecycle_ref']=ref('lifecycle.json',files['lifecycle.json'])
        files['attempts.json']=self.codec.encode(projection,'projection')
        cut=dict(common,kind='pc026-observation-session-cut-v1',instance_ref=ref('c/00000000.json',catalog[0]),config_ref=cfg,
            catalog_head=head,attempts_ref=ref('attempts.json',files['attempts.json']),members=sorted([ref(n,r) for n,r in files.items()],key=lambda r:r['path']),
            close_reason=lifecycle['close_reason'],worker_count=0,status='CLOSED_KNOWN')
        files['cut.json']=self.codec.encode(cut,'cut')
        self.codec.verify_cut(files,self._config.catalog_codec,self._config.codec,self.lifecycle_config_raw)
        _require(len(files)+1<=self._plan['files'] and sum(map(len,files.values()))+self.codec.limits['max_cut_bytes']<=self._plan['bytes'],'export_actual_budget')
        return files,common,cut

    def _write(self, base, name, raw, leases):
        parent,leaf=name.rsplit('/',1) if '/' in name else ('',name)
        self._check(leases[parent])
        transaction = _RecordTransaction(base.path/parent.replace('/','\\') if parent else base.path,None)
        primary=None
        try:
            result=transaction._publish_named(raw,leaf)
            self._check(leases[parent])
            return result['identity']
        except BaseException as error:primary=error;raise
        finally:
            try:transaction.close()
            except BaseException:
                if primary is None:raise
                _note(primary,'export_transaction_close_failed')

    def _readback(self, base, files, identities, leases, retain):
        reader=WindowsSession();primary=None
        try:
            _require(reader.sid==self._allocator.root.identity['principal_sid'],'export_readback_principal')
            expected={name:set() for name in leases}
            for name in leases:
                if name:
                    parent,child=name.rsplit('/',1) if '/' in name else ('',name)
                    expected[parent].add(child)
            for name in files:
                parent,child=name.rsplit('/',1) if '/' in name else ('',name)
                expected[parent].add(child)
            def enumerate_all():
                for name,lease in leases.items():
                    self._check(lease)
                    _require(reader._directory_names(lease.path,len(expected[name])+1,directories=True)==frozenset(expected[name]),'export_directory_closure')
            enumerate_all()
            observed={}
            for name,raw in files.items():
                path=base.path/name.replace('/','\\')
                actual,_,identity=reader._read_original(path,len(raw))
                _require(actual==raw and identity==identities[name],'export_readback_identity_bytes')
                observed[name]=actual
                retain((files,observed,identities))
            enumerate_all()
            return observed
        except BaseException as error:primary=error;raise
        finally:
            try:reader.close()
            except BaseException:
                if primary is None:raise
                _note(primary,'export_readback_close_failed')

    def publish(self, prefix, lifecycle, *, retain):
        with self._lock:
            session=prefix.session
            _require(session in self._reservations and session not in self.completed,'export_reservation_missing')
            self._check(self._allocator.root)
            files,common,cut=self._documents(prefix,lifecycle)
            retain((files,common,cut))
            relative='e'+prefix.instance+'/s'+hashlib.sha256(session.encode('utf-8')).hexdigest()
            for name in list(files)+['export.json']:
                candidate=self._allocator.root.path/relative.replace('/','\\')/name.replace('/','\\')
                _path(candidate);_path(candidate.parent/('0'*36+'.pending'))
            _require(not self._pending_reserved,'export_pending_lane')
            self._pending_reserved=self._plan['pending']
            try:
                retain((files,))
                if self._instance_dir is None:self._instance_dir=self._allocator.allocate(self._allocator.root,'e'+prefix.instance)
                base=self._allocator.allocate(self._instance_dir,relative.split('/')[1])
                parents={''}
                for name in files:
                    parts=name.split('/')[:-1]
                    parents.update('/'.join(parts[:i]) for i in range(1,len(parts)+1))
                leases={'':base}
                for name in sorted(parents-{''},key=lambda p:(p.count('/'),p)):
                    parent,child=name.rsplit('/',1) if '/' in name else ('',name)
                    leases[name]=self._allocator.allocate(leases[parent],child)
                _require(len(leases)<=self._plan['directories'],'export_actual_directories')
                identities={}
                for name in sorted(n for n in files if n.startswith(('originals/','sd/'))):
                    retain((files,identities));identities[name]=self._write(base,name,files[name],leases)
                for name in ('source-manifest.json','lifecycle.json','attempts.json','cut.json'):
                    retain((files,identities));identities[name]=self._write(base,name,files[name],leases)
                observed=self._readback(base,files,identities,leases,retain)
                self.codec.verify_cut(observed,self._config.catalog_codec,self._config.codec,self.lifecycle_config_raw)
                wrapper=dict(common,kind='pc026-observation-session-export-v1',cut_ref=ref('cut.json',files['cut.json']),
                    cut_identity=identities['cut.json'],members=sorted(cut['members']+[ref('cut.json',files['cut.json'])],key=lambda r:r['path']),status='PUBLISHED')
                files['export.json']=self.codec.encode(wrapper,'export')
                retain((files,observed,wrapper,identities))
                identities['export.json']=self._write(base,'export.json',files['export.json'],leases)
                observed=self._readback(base,files,identities,leases,retain)
                self.codec.verify(observed,self._config.catalog_codec,self._config.codec,self.lifecycle_config_raw)
                self._check(base)
                retain((files,observed,wrapper,identities))  # UNKNOWN/deadline owner cannot issue receipt.
                descriptor=ref(relative+'/cut.json',files['cut.json'])
                # All per-export publishers/readers have actually closed. The
                # ledger-owned allocator remains a retained directory lease.
                snapshot=canonical(dict(members=[ref(n,r) for n,r in sorted(observed.items())],identities=identities))
                retain((files,observed,wrapper,identities,snapshot))
                with self._receipt_lock:
                    self._sources[session]=(base,dict(leases),snapshot)
                    self.completed[session]=dict(descriptor)
                return descriptor
            except BaseException:
                self._ledger._poison();raise
            finally:
                self._pending_reserved=0  # Runs only on this actual native thread.

    def close(self):
        with self._lock:
            if self.closed:return
            self.closed=True
            if self._allocator is not None:self._allocator.close()

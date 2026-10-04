"""Test-only MODEL exporter: real exclusive POSIX files; no Windows authority.

Windows identities/SDs on export files are explicitly MODELed from fstat and
source-fixture SD. This module is never imported by a production entrypoint.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import uuid

from velociraptor_observation_cut import CutCodec, canonical, ref, _require
from velociraptor_observation_catalog import _directory


class ModelExporter:
    def __init__(self, root, config, budgets):
        self.root=Path(root);self.config=config;self.codec=CutCodec(budgets)
        self.closed=False;self.handles=set();self.events=[];self.fault=lambda stage:None
        self._lock=threading.Lock();self.completed={};self._reserved_files=0;self._reserved_bytes=0;self._reserved_dirs=set()
        self.files={};self.identities={};self.descriptor=None
        from velociraptor_observation_startup import CONTRACT_REF
        self.lifecycle_config_raw=canonical(dict(schema_version=1,kind='pc026-observation-lifecycle-configuration-v1',
            profile_id='MODEL',workflow_id='MODEL',contract_ref=CONTRACT_REF,
            archive_config_ref=config.group.allowed['PLAN/2026.10.02/observation-archive-configuration.json'],
            deployment_ref=ref('MODEL/deployment.json',b'{}'),
            implementation_freeze_ref=config.document['implementation_freeze_ref'],budgets=budgets,
            metadata_policy='GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS',status='AUTHORIZED'))

    def _read(self, name):
        fd=os.open(self.base/name,os.O_RDONLY|os.O_NOFOLLOW);self.handles.add(fd)
        try:
            raw=bytearray()
            while part:=os.read(fd,65536):raw.extend(part)
            st=os.fstat(fd)
            identity=dict(self.config.document['root_identity'])
            identity.update(volume_serial=f'{st.st_dev:016x}',file_id=f'{st.st_ino:032x}')
            self.identities[name]=identity
            return bytes(raw)
        finally:
            os.close(fd);self.handles.remove(fd)
            self.fault('read_close:'+name)

    def _write(self, name, raw):
        self.fault('before:'+name)
        final=self.base/name;pending=final.parent/(uuid.uuid4().hex+'.pending')
        final.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);self.handles.add(fd)
        try:
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);_require(count>0,'short_write');view=view[count:]
            os.fsync(fd)
        finally:
            os.close(fd);self.handles.remove(fd)
            self.fault('write_close:'+name)
        os.link(pending,final,follow_symlinks=False)  # Exclusive even if final exists.
        pending.unlink()  # Only successful publication removes its own pending.
        _require(self._read(name)==raw,'model_readback')
        self.files[name]=raw;self.events.append(name)

    def receipt(self, session, descriptor):
        return self.completed.get(session)==descriptor

    def publish(self, prefix, lifecycle, *, retain=lambda graph:None):
        with self._lock:return self._publish(prefix,lifecycle,retain)

    def _publish(self, prefix, lifecycle, retain):
        self.closed=False
        instance,session=prefix.instance,prefix.session
        relative=f'e{instance}/s'+hashlib.sha256(session.encode('utf-8')).hexdigest()
        self.base=self.root/relative
        common=dict(schema_version=1,instance_id=instance,session_id=session)
        originals={r.path:r for r in prefix.originals}
        files={'originals/'+p:r.raw for p,r in originals.items()}
        manifest=[]
        for path,r in originals.items():
            identity=json.loads(r.identity);sd_name='sd/'+hashlib.sha256(r.sd).hexdigest()+'.bin'
            files[sd_name]=r.sd
            manifest.append(dict(source_ref=ref(path,r.raw),export_ref=ref('originals/'+path,r.raw),
                identity=identity,sd_ref=ref(sd_name,r.sd)))
        head=dict(json.loads(prefix.catalog_head),path=f'c/{prefix.catalog_count-1:08d}.json')
        cfg=ref('PLAN/2026.10.02/observation-lifecycle-configuration.json',self.lifecycle_config_raw)
        source=dict(common,kind='pc026-observation-export-source-v1',config_ref=cfg,catalog_head=head,
            files=manifest,status='OBSERVED')
        catalog=[originals[f'c/{i:08d}.json'].raw for i in range(prefix.catalog_count)]
        begins={r['payload']['attempt_sequence']:r['payload'] for raw in catalog
            if (r:=self.config.catalog_codec.parse(raw))['record_type']=='ATTEMPT_BEGIN'}
        projection=dict(common,kind='pc026-observation-session-projection-v1',
            catalog_prefix=[ref(f'originals/c/{i:08d}.json',raw) for i,raw in enumerate(catalog)],
            attempt_sequences=list(prefix.attempts),request_records=[],lifecycle_ref={})
        for n in prefix.attempts:
            b=begins[n]
            if b['decision']=='NEW':
                directory=_directory(n,b['key'])
                records=[ref('originals/'+p,originals[p].raw) for p in sorted(originals) if p.startswith(directory+'/')]
                projection['request_records'].append(dict(attempt_sequence=n,records=records))
        lifecycle=dict(lifecycle,attempt_sequences=list(prefix.attempts))
        files['source-manifest.json']=self.codec.encode(source,'source')
        files['lifecycle.json']=self.codec.encode(lifecycle,'lifecycle')
        projection['lifecycle_ref']=ref('lifecycle.json',files['lifecycle.json'])
        files['attempts.json']=self.codec.encode(projection,'projection')
        cut=dict(common,kind='pc026-observation-session-cut-v1',instance_ref=ref('c/00000000.json',catalog[0]),
            config_ref=cfg,catalog_head=head,attempts_ref=ref('attempts.json',files['attempts.json']),
            members=sorted([ref(n,raw) for n,raw in files.items()],key=lambda r:r['path']),
            close_reason=lifecycle['close_reason'],worker_count=0,status='CLOSED_KNOWN')
        files['cut.json']=self.codec.encode(cut,'cut')
        retain((files,manifest,projection,cut,lifecycle,source,catalog,begins))
        # Reserve wrapper maximum as well as a complete pending before any write.
        limits=self.codec.limits
        _require(self._reserved_files+len(files)+1<=limits['max_export_files'],'export_files')
        reserve=sum(map(len,files.values()))+limits['max_cut_bytes']
        _require(self._reserved_bytes+reserve<=limits['max_export_bytes'],'export_bytes')
        dirs={str(Path(name).parent) for name in files}
        dirs|={str(Path(name).parent.parent) for name in files if '/' in name}
        directories={relative+'/'+d for d in dirs}|{relative,relative.split('/')[0]}
        _require(len(self._reserved_dirs|directories)<=limits['max_export_directories'],'export_directories')
        for name in list(files)+['export.json']:
            for candidate in (name,str(Path(name).parent/(32*'f'+'.pending'))):
                windows='C:\\private\\'+relative.replace('/','\\')+'\\'+candidate.replace('/','\\')
                _require(len(windows.encode('utf-16-le'))//2<248 and len(windows.split('\\'))<=64,'windows_candidate')
        _require(shutil.disk_usage(self.root).free>=limits['min_free_bytes']+sum(map(len,files.values()))
            +2*limits['max_cut_bytes'],'actual_free_space')
        self._reserved_files+=len(files)+1;self._reserved_bytes+=reserve;self._reserved_dirs|=directories
        self.files={}
        self.base.mkdir(parents=True,exist_ok=False)
        try:
            for name in sorted(n for n in files if n.startswith(('originals/','sd/'))):self._write(name,files[name])
            # Source-copy close witness is reached before lifecycle is published.
            _require(not self.handles,'copy_io_closed')
            for name in ('source-manifest.json','lifecycle.json','attempts.json','cut.json'):self._write(name,files[name])
            exported=dict(common,kind='pc026-observation-session-export-v1',cut_ref=ref('cut.json',files['cut.json']),
                cut_identity=self.identities['cut.json'],members=sorted(cut['members']+[ref('cut.json',files['cut.json'])],
                    key=lambda r:r['path']),status='PUBLISHED')
            files['export.json']=self.codec.encode(exported,'export')
            self._write('export.json',files['export.json'])
            observed={str(p.relative_to(self.base)).replace(os.sep,'/'):self._read(str(p.relative_to(self.base)))
                for p in self.base.rglob('*') if p.is_file()}
            expected_directories={'.'}
            for name in files:
                parent=Path(name).parent
                while str(parent)!='.':
                    expected_directories.add(str(parent).replace(os.sep,'/'));parent=parent.parent
            entries=list(self.base.rglob('*'))
            _require(not any(p.is_symlink() for p in entries),'model_export_alias')
            actual_directories={'.'}|{str(p.relative_to(self.base)).replace(os.sep,'/') for p in entries if p.is_dir()}
            _require(actual_directories==expected_directories,'model_export_directory_closure')
            retain((files,manifest,projection,cut,lifecycle,source,catalog,begins,exported,observed))
            self.codec.verify(observed,self.config.catalog_codec,self.config.codec,self.lifecycle_config_raw)
            self.fault('final_close')
            _require(not self.handles,'final_io_closed')
            self.closed=True
            self.descriptor=ref(relative+'/cut.json',files['cut.json'])
            self.completed[session]=dict(self.descriptor)
            return self.descriptor
        except BaseException:
            self.closed=False
            raise

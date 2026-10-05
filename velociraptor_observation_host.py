"""Fixed-admission read-only C5 consumption of an acquired original session.

Content and descriptors never authorize sources. Readers do not fetch, repair,
cache, or publish evidence; the producer explicitly publishes derived bytes.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
import shutil
import stat

from velociraptor_observation_cut import canonical, ref, _require
from velociraptor_observation_maintenance import (
    _json, _read_authority, _verify_export, validate_maintenance,
)

SIDECAR='mcp-observation-binding.json'
REFS={
    'report_ref':'report.json', 'clock_ref':'call-clock.json',
    'raw_join_ref':'mcp-raw-join.json', 'http_binding_ref':'mcp-http-binding.json',
    'session_cut_ref':'archive/cut.json', 'maintenance_ledger_ref':'maintenance/ledger.json',
}


def _tree(admission, root, *, max_files, max_bytes, max_directories):
    """Enumerate actual safe storage, independently of its declared manifest."""
    from velo_transfer.manifest import safe_chain
    root=Path(root);files={};directories=0;total=0
    def walk(path):
        nonlocal directories,total
        safe_chain(path,root)
        before=path.lstat();_require(stat.S_ISDIR(before.st_mode),'host_directory')
        directories+=1;_require(directories<=max_directories,'host_directory_budget')
        names=sorted(os.listdir(path))
        for name in names:
            leaf=path/name;info=leaf.lstat()
            _require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
                'host_tree_link')
            if stat.S_ISDIR(info.st_mode):walk(leaf);continue
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'host_tree_file')
            _require(len(files)<max_files and total+info.st_size<=max_bytes,'host_tree_budget')
            data=admission.read(leaf);total+=len(data)
            _require(total<=max_bytes,'host_tree_budget')
            files[leaf.relative_to(root).as_posix()]=data
        after=path.lstat()
        _require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)
            and names==sorted(os.listdir(path)),'host_tree_drift')
    walk(root)
    admission.recheck()
    return files


def _occurrences(files, context, index, joined, reader):
    """Full current session BEGIN/ACK/END and SDK work versus physical raw."""
    from velociraptor_observation_config import _budgets
    from tests import p06_mcp_raw_join as raw
    _,catalog=_budgets(context['archive']['budgets'])
    projection=_json(files['attempts.json']);proof=_json(files['lifecycle.json'])
    begins={};ends={}
    for reference in projection['catalog_prefix']:
        record=catalog.parse(files[reference['path']]);payload=record['payload']
        if record['record_type']=='ATTEMPT_BEGIN' and payload['key']['session_id']==context['original_session']:
            begins[payload['attempt_sequence']]=payload
        elif record['record_type']=='ATTEMPT_END':ends[payload['attempt_sequence']]=payload
    _require(len(begins)==len(joined['calls']),'host_attempt_bijection')
    consumed=set()
    for call in joined['calls']:
        rid=call['request_id'];kind='integer' if type(rid) is int else 'string'
        candidates=[(n,b) for n,b in begins.items() if b['key']==dict(instance_id=context['instance'],
            session_id=context['original_session'],request_id_type=kind,request_id=rid)]
        _require(len(candidates)==1,'host_typed_attempt_unique')
        n,begin=candidates[0];_require(n not in consumed,'host_attempt_reused');consumed.add(n)
        request=index['exchanges'][call['request_location']['exchange_sequence']-1]
        messages=list(raw.messages(reader,request,'request'))
        actual=[m for m,location in messages if location==call['request_location']]
        _require(len(actual)==1,'host_raw_location')
        arguments=actual[0]['params'].get('arguments',{})
        _require(begin['decision']=='NEW' and begin['tool']==call['tool']
            and begin['arguments_sha256']==raw.digest(arguments),
            'host_attempt_call_binding')
        _require(ends[n]['disposition']=='COMPLETE' and ends[n]['outcome']=='returned','host_attempt_success')
    _require(consumed==set(begins),'host_attempt_extra')
    expected=[]
    for exchange in index['exchanges']:
        if exchange['method']=='DELETE':continue
        if exchange['method']=='GET':expected.append((None,None,'HTTP_GET_SSE'));continue
        for message,_ in raw.messages(reader,exchange,'request'):
            rid=message.get('id')
            typ=None if rid is None else 'integer' if type(rid) is int else 'string'
            expected.append((typ,rid,message.get('method','JSONRPC_RESPONSE')))
    actual=[]
    for work in proof['sdk_work']['messages']:
        _require(work['handler_outcome']=='returned','host_sdk_work_outcome')
        actual.append((work['request_id_type'],work['request_id'],work['method']))
    _require(Counter(actual)==Counter(expected),'host_sdk_work_bijection')
    # Current HTTPbinding supports only /mcp, hence no business chunkbin.
    _require(proof['binary_work']==[],'host_unobserved_binary')
    _require(proof['sdk_work']['transfer_workers']==[],'host_unobserved_transfer_worker')


def _derive(admission, run_dir):
    from tests import p06_http_binding as http, p06_http_body_capture as capture
    run=Path(run_dir)
    context,request=_read_authority(admission,run)  # Fixed sources first.
    report_raw=admission.read(run/'report.json');report=_json(report_raw)
    _require(report['status']=='success' and report['failure'] is None,'host_report_success')
    http.validate(admission,run)
    reader=http._AdmissionReader(admission,run)
    index=capture.verify(run,report['run_id'],_reader=reader)
    joined=_json(admission.read(run/'mcp-raw-join.json'))
    limits=context['lifecycle']['budgets']
    # Pin every maintenance original before the legacy independent algorithm
    # rereads it. The final Admission recheck catches identity or byte changes.
    _tree(admission,run/'maintenance',max_files=limits['max_export_files']+limits['max_maintenance_calls']*6+32,
        max_bytes=limits['max_export_bytes']+limits['max_maintenance_bytes']*3,
        max_directories=limits['max_export_directories']+16)
    ledger_raw=admission.read(run/'maintenance/ledger.json')
    _require(ledger_raw==admission.read(run/'maintenance/maintenance.json'),'host_ledger_original_bytes')
    ledger=validate_maintenance(ledger_raw,run,context,request)
    _require(ledger['status']=='COMPLETE','host_maintenance_complete')
    acquired=_verify_export(context,request,context['descriptor'])
    published=_tree(admission,run/'archive',max_files=limits['max_export_files'],
        max_bytes=limits['max_export_bytes'],max_directories=limits['max_export_directories'])
    _require(published==acquired,'host_archive_original_bytes')
    _occurrences(published,context,index,joined,reader)
    value=dict(schema_version=1,kind='pc026-p06-observation-binding-v1',run_id=report['run_id'],status='BOUND')
    for key,name in REFS.items():value[key]=ref(name,admission.read(run/name))
    admission.recheck()
    return value


def validate(admission, run_dir):
    value=_derive(admission,run_dir)
    _require(admission.read(Path(run_dir)/SIDECAR)==canonical(value),'host_sidecar_original_bytes')
    admission.recheck()
    return value


def _publish_acquired(admission, run_dir):
    """Exclusive fixed copies, after validation and complete pre-copy reserves."""
    from tests.p06_http_binding import _exclusive
    from tests.p06_http_body_capture import _Directory
    run=Path(run_dir);context,request=_read_authority(admission,run)
    limits=context['lifecycle']['budgets'];ledger=admission.read(run/'maintenance/maintenance.json')
    _require(validate_maintenance(ledger,run,context,request)['status']=='COMPLETE','host_maintenance_complete')
    files=_verify_export(context,request,context['descriptor'])
    names=set()
    for name in files:
        names.update(Path(name).parents)
    names.discard(Path('.'))
    _require(len(files)<=limits['max_export_files'] and len(names)+1<=limits['max_export_directories']
        and sum(map(len,files.values()))<=limits['max_export_bytes'],'host_copy_budget')
    _require(shutil.disk_usage(run).free>=sum(map(len,files.values()))+len(ledger)
        +max(map(len,files.values()))+limits['min_free_bytes'],'host_copy_free')
    admission.recheck()
    anchor=_Directory(run)
    try:
        os.mkdir('archive',mode=0o700,dir_fd=anchor.fd);anchor.check()
    finally:anchor.close()
    for parent in sorted(names,key=lambda p:(len(p.parts),p.as_posix())):
        anchor=_Directory(run/'archive'/parent.parent)
        try:os.mkdir(parent.name,mode=0o700,dir_fd=anchor.fd);anchor.check()
        finally:anchor.close()
    def original(directory,name,data):
        anchor=_Directory(directory)
        try:
            fd=anchor.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
            try:
                view=memoryview(data)
                while view:
                    count=os.write(fd,view);_require(count>0,'host_copy_short_write');view=view[count:]
                os.fsync(fd)
            finally:os.close(fd)
            anchor.check()
        finally:anchor.close()
    for name,data in sorted(files.items()):
        admission.recheck();original(run/'archive'/Path(name).parent,Path(name).name,data)
    admission.recheck();original(run/'maintenance','ledger.json',ledger)
    value=_derive(admission,run)
    admission.recheck();_exclusive(run,SIDECAR,value)
    return validate(admission,run)

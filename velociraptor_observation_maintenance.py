"""One admitted host acquisition, with a separate nonrecursive C4 ledger.

The public bridge and seven transfer schemas are unchanged. Admission/source
approval is required before capture, download, or RPC. Content verification
alone never grants source authority. Maintenance only records its own cut.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import sys
import time

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tests import p06_http_body_capture as capture
from tests.p06_call_clock import RunClock, validate_clock
from tests.p06_mcp_raw_join import strict_json
from velociraptor_observation_cut import CutCodec, canonical, ref, _ref, _require
from velociraptor_observation_maintenance_plan import acquisition_plan
from velo_transfer.adapters import TransportAdapter, _DirectChunkChannel
from velo_transfer.host_coordinator import TransferCoordinator
from velo_transfer.manifest import safe_chain

KIND='pc026-observation-maintenance-v1'
HEADER_KEYS={'method','path','status_code','mcp_session_id','server_instance_id','request_session_id','exchange_sequence'}
CALL_KEYS={'sequence','work_kind','method','exchange_sequence','request_key','tool','arguments_sha256','result_ref','error_ref','monotonic','transfer'}
LEDGER_KEYS={'schema_version','kind','original_cut_ref','maintenance_session','instance_id','capture_ref','headers_ref','calls','clock','transfer_receipts','close','status'}


@asynccontextmanager
async def _settled_sdk(endpoint, http, identity, *, _capture=None):
    """Stop the SDK reconnect loop, then retain one actual DELETE response."""
    try:
        async with streamable_http_client(endpoint,http_client=http,terminate_on_close=False) as streams:
            try:
                yield streams
            finally:
                # Close the actual owned GET body through its capture stream
                # before the SDK cancels its task group. Cancellation remains
                # an error when it is not this explicit normal stream close.
                if _capture is not None:
                    primary=sys.exc_info()[1];first_close_error=None
                    for stream in _capture.streams:
                        if stream.direction=='response' and stream.row['method']=='GET' and not stream.closed:
                            try:await stream.aclose()
                            except BaseException as stream_error:
                                if primary is not None:
                                    primary.add_note('formal GET capture close failed: '+type(stream_error).__name__)
                                elif first_close_error is None:first_close_error=stream_error
                    if primary is None and first_close_error is not None:raise first_close_error
    finally:
        session,protocol=identity()
        if session is not None:
            primary=sys.exc_info()[1]
            try:
                from tests.p05_pc026_governance import before_effect
                before_effect()
                response=await http.delete(endpoint,headers={
                    'Mcp-Session-Id':session,'Mcp-Protocol-Version':protocol or '2025-11-25',
                    'Accept':'application/json, text/event-stream'})
                response.raise_for_status()
            except BaseException as close_error:
                if primary is None:raise
                primary.add_note('formal DELETE failed: '+type(close_error).__name__)


def _read(root, name, maximum):
    _require(type(name) is str and name and not name.startswith('/') and '\\' not in name
        and all(p not in ('','.','..') for p in name.split('/')),'maintenance_path')
    path=Path(root).joinpath(*name.split('/'));safe_chain(path,Path(root))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,'maintenance_file_bound')
        chunks=[];size=0
        while chunk:=os.read(fd,min(65536,maximum+1-size)):
            size+=len(chunk);_require(size<=maximum,'maintenance_file_bound');chunks.append(chunk)
        after=os.fstat(fd);current=path.lstat()
        _require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==
            (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns),'maintenance_file_drift')
        return b''.join(chunks)
    finally:os.close(fd)


def _write(root,name,data):
    _require(Path(name).name==name and name not in ('.','..'),'maintenance_write_name')
    directory=capture._Directory(root)
    try:
        fd=directory.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        try:
            view=memoryview(data)
            while view:
                count=os.write(fd,view);_require(count>0,'maintenance_short_write');view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        directory.check()
    finally:directory.close()
    return ref('maintenance/'+name,data)


def _json(raw, maximum=16<<20):
    _require(type(raw) is bytes and len(raw)<=maximum,'maintenance_json_bound')
    def pairs(items):
        result={}
        for key,value in items:
            _require(key not in result,'maintenance_duplicate_key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('maintenance_nonfinite')))
    _require(canonical(value)==raw,'maintenance_canonical')
    todo=[(value,0)];count=0
    while todo:
        item,depth=todo.pop();count+=1
        _require(depth<=64 and count<=1000000,'maintenance_json_complexity')
        if type(item) is dict:todo.extend((v,depth+1) for v in item.values())
        elif type(item) is list:todo.extend((v,depth+1) for v in item)
        elif type(item) is float:_require(math.isfinite(item),'maintenance_nonfinite')
    return value


def _descriptor(headers, instance, session):
    def one(name):
        values=[v for k,v in headers if k.lower()==name]
        _require(len(values)==1,'maintenance_close_header_unique');return values[0]
    _require(one('x-velo-observation-close')=='pc026-session-close-v1','maintenance_close_version')
    _require(one('x-mcp-server-instance')==instance,'maintenance_close_instance')
    raw=one('x-velo-observation-cut')
    _require(type(raw) is str and len(raw)<=2048 and re.fullmatch('[A-Za-z0-9_-]+',raw),'maintenance_descriptor_encoding')
    data=base64.urlsafe_b64decode(raw+'='*((-len(raw))%4));descriptor=_json(data,2048);_ref(descriptor)
    _require(base64.urlsafe_b64encode(data).rstrip(b'=').decode()==raw,'maintenance_descriptor_canonical')
    expected='e'+instance+'/s'+hashlib.sha256(session.encode()).hexdigest()+'/cut.json'
    _require(descriptor['path']==expected,'maintenance_descriptor_session')
    return descriptor


class _QuotaStream(httpx2.AsyncByteStream):
    def __init__(self,stream,owner):self.stream,self.owner=stream,owner;self.count=0
    async def __aiter__(self):
        async for part in self.stream:
            self.count+=len(part)
            from velo_transfer.wire import BODY_LIMIT
            _require(self.count<=BODY_LIMIT,'maintenance_http_body_limit')
            self.owner.bytes+=len(part)
            _require(self.owner.bytes<=self.owner.plan['bytes'],'maintenance_capture_quota')
            yield part
    async def aclose(self):await self.stream.aclose()


class _QuotaHTTP(httpx2.AsyncHTTPTransport):
    def __init__(self,owner):super().__init__();self.owner=owner
    async def handle_async_request(self,request):
        response=await super().handle_async_request(request)
        response.stream=_QuotaStream(response.stream,self.owner)
        return response


class _EndedStream(httpx2.AsyncByteStream):
    def __init__(self,original,row,clock):self.original,self.row,self.clock=original,row,clock
    async def __aiter__(self):
        async for part in self.original:yield part
        self.row['ended_ns']=self.clock._sample()
    async def aclose(self):
        try:await self.original.aclose()
        finally:self.row['ended_ns']=self.clock._sample()


class _Capture(capture.CaptureTransport):
    def __init__(self,root,run_id,plan,instance):
        self.plan,self.instance=plan,instance;self.bytes=0;self.headers=[];self.original_headers=[];self.request_headers=[]
        self.clock=RunClock();self.intervals={};self.sid=None;self.sdk=[]
        super().__init__(_QuotaHTTP(self),root,run_id)
    def observe_error(self,row,exc,message):
        super().observe_error(row,exc,message)
        # The general capture records network failures per exchange. This
        # acquisition additionally keeps their first cause as a permanent
        # failure, even when the same durable transfer later resumes.
        if isinstance(exc,(httpx2.NetworkError,httpx2.TimeoutException,httpx2.RemoteProtocolError)):
            self.fail(row,exc,message)
    def _allow_failed_requests(self):
        # Keep the immutable first failure and FAILED capture status. Only a
        # network-read failure permits bounded same-session recovery; capture
        # writer/identity/close failures never become recoverable.
        return self.failure is not None and self.failure['type'] in {
            'ReadError','RemoteProtocolError','ConnectError','ReadTimeout'}
    async def handle_async_request(self,request):
        _require(len(self.rows)<self.plan['calls'],'maintenance_call_quota')
        sequence=len(self.rows)+1
        interval=dict(clock_id=self.clock.clock['clock_id'],invoked=True,started_ns=self.clock._sample(),ended_ns=None)
        self.intervals[sequence]=interval
        self.request_headers.append(dict(exchange_sequence=sequence,headers=[[k.decode('latin1'),v.decode('latin1')]
            for k,v in request.headers.raw if k.lower()!=b'authorization']))
        request.stream=_QuotaStream(request.stream,self)
        try:response=await super().handle_async_request(request)
        except BaseException:
            interval['ended_ns']=self.clock._sample();raise
        h=dict(method=request.method,path=request.url.path,status_code=response.status_code,
            mcp_session_id=response.headers.get('mcp-session-id'),server_instance_id=response.headers.get('x-mcp-server-instance'),
            request_session_id=request.headers.get('mcp-session-id'),exchange_sequence=sequence)
        self.headers.append(h)
        original=[[k.decode('latin1'),v.decode('latin1')] for k,v in response.headers.raw]
        self.original_headers.append(dict(exchange_sequence=sequence,headers=original))
        if self.sid is None and h['mcp_session_id'] is not None:self.sid=h['mcp_session_id']
        response.stream=_EndedStream(response.stream,interval,self.clock)
        # The SDK stops an SSE POST after its matching message and closes
        # notifications without iterating their empty body. Drain the bounded
        # finite POST/error response through the original capture before the
        # SDK can close it early; a truncated HTTP body still raises here.
        if request.method!='GET' or response.status_code>=400:
            await response.aread()
        # Preserve these headers/failed bodies even when binding fails.
        if (h['path'] not in {'/mcp','/chunkbin'} or h['server_instance_id']!=self.instance
                or h['request_session_id'] not in (None,self.sid) or h['mcp_session_id'] not in (None,self.sid)):
            self.fail(self.rows[-1],ValueError('maintenance_header_binding'),'maintenance header binding')
            await response.aclose();raise ValueError('maintenance_header_binding')
        return response


class _SDK:
    def __init__(self,session,transport,root):self.session,self.transport,self.root=session,transport,root
    async def _call(self,method,tool,args,function,*pos,**kw):
        row=dict(method=method,tool=tool,arguments_sha256=hashlib.sha256(canonical(args)).hexdigest(),
            result_ref=None,error_ref=None,monotonic=dict(clock_id=self.transport.clock.clock['clock_id'],invoked=True,started_ns=None,ended_ns=None))
        self.transport.sdk.append(row);n=len(self.transport.sdk)
        row['monotonic']['started_ns']=self.transport.clock._sample()
        try:value=await function(*pos,**kw)
        except BaseException as error:
            row['monotonic']['ended_ns']=self.transport.clock._sample()
            row['error_ref']=_write(self.root,f'error-{n:08d}.json',canonical(dict(type=type(error).__name__,message=str(error)[:2048])))
            raise
        else:row['monotonic']['ended_ns']=self.transport.clock._sample()
        row['result_ref']=_write(self.root,f'result-{n:08d}.json',canonical(value.model_dump(mode='json',by_alias=True,exclude_none=True)))
        return value
    async def initialize(self):return await self._call('initialize',None,{},self.session.initialize)
    async def list_tools(self):return await self._call('tools/list',None,{},self.session.list_tools)
    async def call_tool(self,name,arguments,**kw):
        return await self._call('tools/call',name,arguments,self.session.call_tool,name,arguments,**kw)


def _exception(error, depth=0):
    value=dict(type=type(error).__name__,message=str(error)[:2048])
    if isinstance(error,BaseExceptionGroup) and depth<8:
        value['exceptions']=[_exception(child,depth+1) for child in error.exceptions[:16]]
    return value


def _runner():
    from tests.scenario_runner import _runner_start_time_utc
    value=dict(pid=os.getpid(),process_start_time_utc=_runner_start_time_utc(),
        executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
    _require(value['process_start_time_utc'] is not None,'maintenance_runner_start')
    return value


def _body_ref(r):
    return None if r is None else dict(r,path='maintenance/raw-mcp/'+r['path'])


def _actual_receipts(result):
    """Derive receipt originals from a raw-joined full SDK result, never Refs.

    One call records its completed operation receipt, otherwise the latest
    terminal receipt (publication, then prepare) or source-validation receipt.
    Earlier prepare observations retain their own Ref even when a later
    terminal response contains both receipts.
    """
    terminal=(result or {}).get('terminal') or {}
    operation=((result or {}).get('operation') or {}).get('result') or {}
    receipts=[]
    for r in (operation.get('publication_receipt'),operation.get('prepare_receipt'),operation.get('source_validation_receipt'),
            terminal.get('publication_receipt'),terminal.get('prepare_receipt'),(result or {}).get('source_validation_receipt')):
        if r is not None and r not in receipts:receipts.append(r)
    return receipts


def _receipt_ref(receipt):
    data=canonical(receipt);digest=hashlib.sha256(data).hexdigest()
    return ref('maintenance/receipt-'+digest+'.json',data)


def _build_ledger(root,transport,original,run_id,success):
    rows=[];used=set();deadline=None;receipts={}
    for exchange in transport.rows:
        seq=exchange['sequence'];header=next((h for h in transport.headers if h['exchange_sequence']==seq),None)
        clock=transport.intervals[seq]
        if clock['ended_ns'] is None:clock['ended_ns']=transport.clock._sample();success=False
        method=exchange['method'];tool=key=None;arguments={};transfer=None;result_ref=error_ref=None
        body=b'' if exchange['request_ref'] is None else _read(root,'raw-mcp/'+exchange['request_ref']['path'],transport.plan['bytes'])
        if method=='POST' and header is not None and header['path']=='/mcp':
            request=strict_json(body);method=request['method'];params=request.get('params',{})
            arguments=params.get('arguments',{}) if method=='tools/call' else params
            if method=='tools/call':
                tool=params['name'];rid=request['id'];key=dict(instance_id=transport.instance,session_id=transport.sid,
                    request_id_type='integer' if type(rid) is int else 'string',request_id=rid)
            sha=hashlib.sha256(canonical(arguments)).hexdigest()
            candidates=[(i,r) for i,r in enumerate(transport.sdk) if i not in used and r['method']==method and r['tool']==tool
                and (method!='tools/call' or r['arguments_sha256']==sha)
                and r['monotonic']['started_ns']<=clock['started_ns']<=r['monotonic']['ended_ns']]
            if candidates:
                i,sdk=candidates[0];used.add(i);clock=sdk['monotonic'];result_ref=sdk['result_ref'];error_ref=sdk['error_ref']
            if method=='tools/call' and tool.startswith('transfer_') and tool!='transfer_capabilities':
                details=arguments.get('request',arguments)
                transfer=dict(transfer_id=details['transfer_id'],request_digest=details['request_digest'],deadline=None,receipt_ref=None)
                if result_ref is not None:
                    result=_json(_read(root,result_ref['path'].removeprefix('maintenance/'),transport.plan['bytes']))
                    guest=result.get('structuredContent',{}).get('result',{})
                    worker=guest.get('worker')
                    if worker is not None:
                        value=worker.get('deadline_monotonic')
                        if type(value) in (int,float) and math.isfinite(value) and value>0:
                            deadline=dict(clock_domain='guest_process_monotonic',value=value,source_ref=result_ref)
                    actual_receipts=_actual_receipts(guest)
                    if actual_receipts:
                        receipt=actual_receipts[0]
                        data=canonical(receipt);digest=hashlib.sha256(data).hexdigest()
                        if digest not in receipts:receipts[digest]=_write(root,'receipt-'+digest+'.json',data)
                        transfer['receipt_ref']=receipts[digest]
                transfer['deadline']=copy_ref(deadline)
        else:
            method='HTTP_CHUNKBIN' if header is not None and header['path']=='/chunkbin' else 'HTTP_GET_SSE' if method=='GET' else 'HTTP_DELETE'
            sha=hashlib.sha256(body).hexdigest()
            if method=='HTTP_CHUNKBIN':
                # Request identity is in the actual request headers; preserved
                # by the direct adapter alongside immutable raw response bytes.
                identity=transport.binary.get(seq)
                if identity is not None:transfer=dict(identity,deadline=copy_ref(deadline),receipt_ref=None)
                result_ref=_body_ref(exchange['response_ref'])
        row=dict(sequence=0,work_kind='binary_http' if method=='HTTP_CHUNKBIN' else 'sdk_tool' if method=='tools/call' else 'sdk_control',
            method=method,exchange_sequence=seq,request_key=key,tool=tool,arguments_sha256=sha,result_ref=result_ref,error_ref=error_ref,
            monotonic=dict(clock),transfer=transfer)
        rows.append(row)
    _require(len(used)==len(transport.sdk),'maintenance_sdk_exchange_join')
    rows.sort(key=lambda r:(r['monotonic']['started_ns'],r['exchange_sequence']))
    for i,row in enumerate(rows,1):row['sequence']=i
    close=None
    for h in transport.headers:
        if h['method']!='DELETE':continue
        exchange=transport.rows[h['exchange_sequence']-1]
        if (h['status_code']==200 and exchange['response_end']=='eof' and exchange['error'] is None
                and h['request_session_id']==transport.sid):
            raw=next(r['headers'] for r in transport.original_headers if r['exchange_sequence']==h['exchange_sequence'])
            try:descriptor=_descriptor(raw,transport.instance,transport.sid)
            except Exception:success=False;continue
            close=dict(exchange_sequence=h['exchange_sequence'],status_code=200,cut_ref=descriptor,barrier_version='pc026-session-close-v1')
    success=success and close is not None and transport.failure is None
    headers_ref=_write(root,'http-headers.json',canonical(transport.headers))
    _write(root,'response-headers.json',canonical(transport.original_headers))
    _write(root,'request-headers.json',canonical(transport.request_headers))
    return dict(schema_version=1,kind=KIND,original_cut_ref=original,maintenance_session=transport.sid,instance_id=transport.instance,
        capture_ref=ref('maintenance/raw-mcp/capture.json',_read(root,'raw-mcp/capture.json',16<<20)),headers_ref=headers_ref,
        calls=rows,clock=dict(runner=_runner(),domain=transport.clock.clock),transfer_receipts=sorted(
            {r['transfer']['receipt_ref']['path']:r['transfer']['receipt_ref'] for r in rows
             if r['transfer'] is not None and r['transfer']['receipt_ref'] is not None}.values(),key=lambda r:r['path']),
        close=close,status='COMPLETE' if success else 'FAILED')


def copy_ref(value):return None if value is None else json.loads(canonical(value))


def _verify_export(context, request, descriptor):
    root=Path(request.document['destination_directory'])/'original'
    codec=CutCodec(context['lifecycle']['budgets']);files={}
    for path in root.rglob('*'):
        safe_chain(path,root)
        if path.is_file():
            name=path.relative_to(root).as_posix()
            _require(len(files)<codec.limits['max_export_files'],'maintenance_export_files')
            files[name]=_read(root,name,min(request.guest_budget['max_package_bytes'],codec.limits['max_export_bytes']))
    _require(sum(map(len,files.values()))<=request.guest_budget['max_logical_bytes'],'maintenance_export_bytes')
    from velociraptor_observation_config import _budgets
    request_codec,catalog_codec=_budgets(context['archive']['budgets'])
    cut=codec.verify(files,catalog_codec,request_codec,context['lifecycle_raw'])
    _require(cut['instance_id']==context['instance'] and cut['session_id']==context['original_session'],'maintenance_export_binding')
    _require(dict(ref(descriptor['path'],files['cut.json']))==descriptor,'maintenance_original_descriptor')
    from tests.p05_pc026_windows_reader import descriptor_snapshot, acl
    identity=context['archive']['root_identity']
    trusted={identity['principal_sid'],'S-1-5-18','S-1-5-32-544'}
    source=_json(files['source-manifest.json'])
    for row in source['files']:
        observed=row['identity'];sd=files[row['sd_ref']['path']]
        _require(observed['volume_serial']==identity['volume_serial']
            and observed['principal_sid']==identity['principal_sid'],'maintenance_source_authority')
        snapshot=descriptor_snapshot(sd)
        _require(snapshot.owner_sid==observed['owner_sid'],'maintenance_source_owner')
        acl._evaluate(snapshot,'state',trusted)
    return files


def _source_authority(admission,run_dir,request):
    """Existing fixed Admission and approved allowlist, before any host writer.

    A connection profile must already be an allowed original in that same
    governed group. This function cannot issue or extend an approval.
    """
    from tests.p06_pc026_binding import Admission
    from tests.p05_pc026_governance import GovernedGroup
    from tests.scenario_runner import P06_REPORT_ROOT
    from velociraptor_observation_startup import CONFIG
    _require(type(admission) is Admission and type(admission.group) is GovernedGroup,'maintenance_admission')
    admission.recheck()
    from velociraptor_observation_config import _configuration
    from velociraptor_observation_startup import _precheck_loaded
    archive_configuration=_configuration(admission.group)
    _precheck_loaded(archive_configuration)  # Full fixed sources/SD/SDK/C6, read-only.
    root=Path(run_dir)
    _require(root.is_relative_to(P06_REPORT_ROOT),'maintenance_run_root')
    report_raw=admission.read(root/'report.json');report=_json(report_raw)
    _require(root.name==report['run_id'] and root.parent.name==report['scenario'],'maintenance_run_binding')
    sid=report['mcp_session']['id'];instance=report['server_identity']['instance_id']
    lifecycle_raw=admission.group.read(admission.group.allowed[CONFIG]);lifecycle=_json(lifecycle_raw)
    archive_ref=lifecycle['archive_config_ref']
    _require(admission.group.allowed.get(archive_ref['path'])==archive_ref,'maintenance_archive_approval')
    archive_raw=admission.group.read(archive_ref);archive=_json(archive_raw)
    _require(lifecycle['status']=='AUTHORIZED' and lifecycle['metadata_policy']=='GLOBAL_PREFIX_NO_OTHER_SESSION_EVENTS','maintenance_source_approval')
    relative='e'+instance+'/s'+hashlib.sha256(sid.encode()).hexdigest()
    source=str(PureWindowsPath(archive['guest_namespace_root']).joinpath(*relative.split('/')))
    _require(request.document['direction']=='pull' and request.document['sources']==[
        dict(absolute_path=source,relative_path='original')],'maintenance_fixed_source')
    _require(request.document['destination_directory']==str(root/'maintenance'/'downloaded')
        and request.spec_path==root/'maintenance-request.json','maintenance_host_paths')
    from velo_transfer.request import _parse
    _require(_parse(admission.read(request.spec_path))==request.document,'maintenance_request_original')
    profile_path=Path(request.document['connection_profile'])
    _require(profile_path.is_relative_to(admission.group.repository),'maintenance_profile_source')
    profile_ref=admission.group.allowed.get(profile_path.relative_to(admission.group.repository).as_posix())
    _require(profile_ref is not None,'maintenance_profile_approval')
    profile_raw=admission.group.read(profile_ref)
    _require(admission.read(profile_path)==profile_raw,'maintenance_profile_drift')
    from tests.scenario_runner import verify_server_observation
    observed=verify_server_observation(root/'server-observation.json',instance,_admission=admission)
    from tests.p05_pc026_governance import DEPLOYMENT
    deployment=admission.group.document(admission.group.allowed[DEPLOYMENT])
    _require(report['server_identity']=={k:v for k,v in observed.items() if k!='observed_at'}
        and request.document['expected_vm_identity']['vm_uuid']==deployment['vm_uuid'],'maintenance_server_source')
    admission.recheck()
    return dict(lifecycle_raw=lifecycle_raw,lifecycle=lifecycle,archive=archive,archive_raw=archive_raw,instance=instance,original_session=sid,
        run_id=report['run_id'])


def _authorize(admission,run_dir,request,original_close):
    context=_source_authority(admission,run_dir,request)
    _require(original_close.request.method=='DELETE' and original_close.status_code==200
        and original_close.is_closed and original_close.request.headers.get('mcp-session-id')==context['original_session'],
        'maintenance_original_close')
    context['descriptor']=_descriptor([(k.decode('latin1'),v.decode('latin1')) for k,v in original_close.headers.raw],
        context['instance'],context['original_session'])
    admission.recheck()
    return context


def _read_authority(admission, run_dir):
    """Recover authority from fixed sources and actual saved DELETE originals.

    No last-response object, caller context, download or writer participates.
    The descriptor is correlation after source authorization, never approval.
    """
    from velo_transfer.request import load_request
    from tests.p06_http_binding import _AdmissionReader
    root=Path(run_dir)
    request=load_request(root/'maintenance-request.json')
    context=_source_authority(admission,root,request)
    reader=_AdmissionReader(admission,root)
    index=capture.verify(root,context['run_id'],_reader=reader)
    _require(index['status']=='RECORDED' and index['failure'] is None,'original_capture_complete')
    rows=[r for r in index['exchanges'] if r['method']=='DELETE']
    _require(len(rows)==1,'original_close_unique')
    close=rows[0];seq=close['sequence']
    _require(close['request_end']=='eof' and close['response_end']=='eof'
        and close['response_status']==200 and close['error'] is None,'original_close_actual')
    def headers(name):
        value=_json(admission.read(root/name))
        _require(type(value) is list,'original_header_array')
        seen=set();found=None
        for row in value:
            _require(type(row) is dict and set(row)=={'exchange_sequence','headers'}
                and type(row['exchange_sequence']) is int and row['exchange_sequence']>0
                and row['exchange_sequence'] not in seen,'original_header_sequence')
            seen.add(row['exchange_sequence']);items=row['headers']
            _require(type(items) is list and len(items)<=256 and all(type(v) is list and len(v)==2
                and all(type(c) is str and len(c)<=8192 for c in v) for v in items),'original_header_bytes')
            if row['exchange_sequence']==seq:found=items
        expected={r['sequence'] for r in index['exchanges']
            if name=='request-headers.json' or r['response_status'] is not None}
        _require(seen==expected and found is not None,'original_header_coverage')
        return found
    incoming=headers('request-headers.json');outgoing=headers('response-headers.json')
    sessions=[v for k,v in incoming if k.lower()=='mcp-session-id']
    _require(sessions==[context['original_session']],'original_request_session_unique')
    context['descriptor']=_descriptor(outgoing,context['instance'],context['original_session'])
    header_rows=_json(admission.read(root/'http-headers.json'))
    summary=[r for r in header_rows if r['exchange_sequence']==seq]
    _require(len(summary)==1 and set(summary[0])==HEADER_KEYS and summary[0]['method']=='DELETE'
        and summary[0]['path']=='/mcp' and summary[0]['status_code']==200
        and summary[0]['request_session_id']==context['original_session']
        and summary[0]['server_instance_id']==context['instance'],'original_close_header_binding')
    admission.recheck()
    return context,request


async def acquire_original(admission, run_dir, request, original_close):
    """Acquire an approved original through one new actual SDK session.

    No P06 sidecar/package/aggregate success policy is added here (S2).
    The existing caller supplies its fixed Admission, locked run inputs and
    original fully consumed DELETE response; hashes cannot substitute for it.
    """
    context=_authorize(admission,run_dir,request,original_close)
    return await _acquire(Path(run_dir),request,context,recheck=admission.recheck)


async def _acquire(run_dir,request,context,*,recheck):
    # Private algorithm seam: isolated tests may model approval/Win32 path
    # translation, but still use actual SDK, native files and transfer workers.
    from velo_transfer.connection import load_connection_profile
    limits=context['lifecycle']['budgets'];root=run_dir/'maintenance'
    plan=dict(calls=limits['max_maintenance_calls'],bytes=limits['max_maintenance_bytes'])
    free=shutil.disk_usage(run_dir).free
    maximum=plan['bytes']+3*request.guest_budget['max_package_bytes']+plan['calls']*16384+limits['min_free_bytes']
    _require(free>=maximum,'maintenance_host_free')
    _require(len(str(root/'downloaded'/'original'/'originals'/('r'+'9'*12+'-'+'f'*64)/'99999999.json').encode())<=4096,
        'maintenance_host_path_bound')
    recheck();profile=load_connection_profile(request.document['connection_profile'])
    endpoint=profile.velo;token=endpoint.token.read()
    recheck()
    anchor=capture._Directory(run_dir)
    try:
        os.mkdir('maintenance',mode=0o700,dir_fd=anchor.fd);anchor.check()
    finally:anchor.close()
    _write(root,'lifecycle-configuration.json',context['lifecycle_raw'])
    _write(root,'archive-configuration.json',context['archive_raw'])
    transport=_Capture(root,context['run_id'],plan,context['instance']);transport.binary={}
    http_handle=transport.handle_async_request
    async def record_binary(request_http):
        seq=len(transport.rows)+1
        if request_http.url.path=='/chunkbin':
            transport.binary[seq]=dict(transfer_id=request_http.headers.get('x-velo-transfer-id'),
                request_digest=request_http.headers.get('x-velo-request-digest'))
        return await http_handle(request_http)
    transport.handle_async_request=record_binary
    success=False;error=None;summary=None
    try:
        async with httpx2.AsyncClient(headers={'Authorization':'Bearer '+token,'Accept-Encoding':'identity'},
            transport=transport,timeout=request.request_timeout_seconds,trust_env=False,follow_redirects=False) as http:
            async with _settled_sdk(endpoint.url,http,lambda:(transport.sid,'2025-11-25'),_capture=transport) as (read,write):
                async with ClientSession(read,write) as raw_sdk:
                    sdk=_SDK(raw_sdk,transport,root);await sdk.initialize()
                    _require(transport.sid is not None and transport.sid!=context['original_session'],'maintenance_distinct_session')
                    adapter=TransportAdapter(sdk,'velo',endpoint.url,time.monotonic()+request.guest_budget['max_duration_seconds'],
                        request.request_timeout_seconds,[context['instance']])
                    adapter._binary_factory=lambda:_DirectChunkChannel(http,endpoint.url,transport.sid,context['instance'],
                        adapter.deadline_monotonic,request.request_timeout_seconds,raw_sdk.protocol_version)
                    @asynccontextmanager
                    async def selector(_profile,**kw):
                        recheck();adapter.deadline_monotonic=kw['deadline_monotonic']
                        await adapter.probe(kw['expected_vm_identity']);yield adapter
                    from dataclasses import replace
                    current=request
                    for attempt in range(1,4):
                        coordinator=TransferCoordinator(current,_adapter_selector=selector)
                        summary=await coordinator.run()
                        with coordinator.journal.writer():
                            state=coordinator._data()
                            transfer_result=coordinator.journal.read_evidence(state['result_ref'])
                        _write(root,f'transfer-attempt-{attempt:02d}.json',canonical(transfer_result))
                        if state['phase']=='COMPLETE':break
                        if (transport.failure is None or not transport._allow_failed_requests()
                                or state['phase']=='CONFLICT' or time.monotonic()>=coordinator.deadline):break
                        # Reopen only the same durable request, transfer ID,
                        # digest, deadline and acknowledged host prefix.
                        from velo_transfer.manifest import canonical_json
                        resumed_document=dict(request.document,resume=True)
                        current=replace(request,resume=True,_document_bytes=canonical_json(resumed_document))
                    _write(root,'transfer-summary.json',canonical(summary))
                    _write(root,'transfer-result.json',canonical(transfer_result))
                    _require(state['phase']=='COMPLETE','maintenance_transfer_incomplete')
                    recheck()
                    files=_verify_export(context,request,context['descriptor'])
                    # The ledger's original_cut_ref is host-run relative, while
                    # descriptor remains the actual guest namespace correlation.
                    original=ref('maintenance/downloaded/original/cut.json',files['cut.json'])
                    _write(root,'original-close.json',canonical(context['descriptor']))
                    success=True
    except BaseException as exc:
        error=exc
        _write(root,'failure.json',canonical(_exception(exc)))
    finally:
        if not transport.closed:await transport.aclose()
    if not success:
        # Preserve the actual original close as failure correlation; no copied
        # original is invented and no partial acquisition gets COMPLETE.
        original=ref('maintenance/original-close.json',canonical(context['descriptor']))
        if not (root/'original-close.json').exists():_write(root,'original-close.json',canonical(context['descriptor']))
    ledger=_build_ledger(root,transport,original,context['run_id'],success)
    data=canonical(ledger)
    # Independent validation decides COMPLETE; SDK context exit alone does not.
    if ledger['status']=='COMPLETE':
        try:validate_maintenance(data,run_dir,context,request);recheck()
        except Exception as exc:
            ledger['status']='FAILED';data=canonical(ledger)
            _write(root,'validation-error.json',canonical(dict(type=type(exc).__name__,message=str(exc)[:2048])))
    _write(root,'maintenance.json',data)
    if isinstance(error,asyncio.CancelledError):raise error
    return ledger


def validate_maintenance(raw, run_dir, context, request):
    """Independent bounded artifact/SDK/raw/close/transfer/full-export verifier.

    Context is obtained only from the fixed Admission caller in production;
    passing a content-consistent context is not itself source authorization.
    No response is downloaded here and no session is opened.
    """
    limits=context['lifecycle']['budgets'];maximum=limits['max_maintenance_bytes']
    value=_json(raw);_require(type(value) is dict and set(value)==LEDGER_KEYS,'maintenance_exact12')
    _require(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']==KIND
        and value['status'] in ('COMPLETE','FAILED'),'maintenance_model')
    complete=value['status']=='COMPLETE';root=Path(run_dir)/'maintenance'
    def original(reference):
        _ref(reference)
        data=_read(run_dir,reference['path'],maximum)
        _require(ref(reference['path'],data)==reference,'maintenance_ref_content');return data
    _require(value['capture_ref']['path']=='maintenance/raw-mcp/capture.json'
        and value['headers_ref']['path']=='maintenance/http-headers.json','maintenance_fixed_refs')
    original(value['capture_ref']);headers=_json(original(value['headers_ref']))
    original(value['original_cut_ref'])
    index=capture.verify(root,context['run_id'])
    original_headers=_json(_read(root,'response-headers.json',16<<20))
    request_headers=_json(_read(root,'request-headers.json',16<<20))
    def headers_for(rows,seq):
        matches=[r for r in rows if r['exchange_sequence']==seq]
        _require(len(matches)==1 and set(matches[0])=={'exchange_sequence','headers'},'maintenance_original_headers')
        entries=matches[0]['headers'];_require(type(entries) is list and all(type(r) is list and len(r)==2
            and all(type(v) is str for v in r) for r in entries),'maintenance_header_bytes')
        return entries
    def header(entries,name):
        found=[v for k,v in entries if k.lower()==name]
        _require(len(found)==1,'maintenance_request_header_unique');return found[0]
    sid=value['maintenance_session'];instance=value['instance_id']
    _require(type(sid) is str and sid and sid!=context['original_session'] and instance==context['instance'],
        'maintenance_session_binding')
    _require(type(headers) is list and len({h['exchange_sequence'] for h in headers})==len(headers),'maintenance_header_unique')
    by_header={}
    for h in headers:
        _require(type(h) is dict and set(h)==HEADER_KEYS and type(h['exchange_sequence']) is int,'maintenance_header_exact7')
        seq=h['exchange_sequence']
        _require(1<=seq<=len(index['exchanges']) and type(h['status_code']) is int
            and h['status_code']==index['exchanges'][seq-1]['response_status']
            and h['method']==index['exchanges'][seq-1]['method'],'maintenance_header_exchange')
        raw_headers=headers_for(original_headers,seq);incoming=headers_for(request_headers,seq)
        def optional(entries,name):
            found=[v for k,v in entries if k.lower()==name]
            _require(len(found)<=1,'maintenance_original_header_unique')
            return found[0] if found else None
        _require(optional(raw_headers,'x-mcp-server-instance')==h['server_instance_id']
            and optional(raw_headers,'mcp-session-id')==h['mcp_session_id']
            and optional(incoming,'mcp-session-id')==h['request_session_id'],'maintenance_original_header_binding')
        _require(h['path'] in {'/mcp','/chunkbin'} and h['server_instance_id']==instance
            and h['mcp_session_id'] in (None,sid) and h['request_session_id'] in (None,sid),'maintenance_header_binding')
        by_header[h['exchange_sequence']]=h
    _require(type(value['clock']) is dict and set(value['clock'])=={'runner','domain'},'maintenance_clock_exact2')
    validate_clock(value['clock']['domain']);runner=value['clock']['runner']
    _require(type(runner) is dict and set(runner)=={'pid','process_start_time_utc','executable_sha256'}
        and type(runner['pid']) is int and runner['pid']>0 and type(runner['process_start_time_utc']) is str
        and re.fullmatch('[0-9a-f]{64}',runner['executable_sha256']),'maintenance_runner')
    from datetime import datetime
    _require(datetime.fromisoformat(runner['process_start_time_utc']).utcoffset() is not None,'maintenance_runner_timezone')
    _require(type(value['calls']) is list and len(value['calls'])==len(index['exchanges'])<=limits['max_maintenance_calls'],'maintenance_call_coverage')
    by_exchange={};previous=None;receipt_refs={};observed_receipts={};prepares={};chunks={};packages={};bindings={};tools=0;seen_results={};deadlines={}
    from tests import p06_mcp_raw_join as join
    from mcp.types import CallToolResult, InitializeResult, ListToolsResult
    from velo_transfer import wire
    from velo_transfer.guest_service import request_digest
    from velo_transfer.mcp_tools import TRANSFER_TOOL_NAMES
    reader=join._Reader(root)
    try:
        for n,row in enumerate(value['calls'],1):
            _require(type(row) is dict and set(row)==CALL_KEYS and type(row['sequence']) is int and row['sequence']==n,'maintenance_call_exact11')
            seq=row['exchange_sequence'];_require(type(seq) is int and 1<=seq<=len(index['exchanges']) and seq not in by_exchange,'maintenance_exchange_unique')
            by_exchange[seq]=row;exchange=index['exchanges'][seq-1];h=by_header.get(seq)
            timing=row['monotonic'];_require(type(timing) is dict and set(timing)=={'clock_id','invoked','started_ns','ended_ns'},'maintenance_interval_exact4')
            _require(timing['clock_id']==value['clock']['domain']['clock_id'] and timing['invoked'] is True
                and type(timing['started_ns']) is int and type(timing['ended_ns']) is int
                and 0<=timing['started_ns']<=timing['ended_ns'],'maintenance_interval')
            _require(previous is None or previous<=timing['started_ns'],'maintenance_start_order');previous=timing['started_ns']
            _require(not(row['result_ref'] is not None and row['error_ref'] is not None),'maintenance_result_error')
            for field in ('result_ref','error_ref'):
                if row[field] is not None:original(row[field])
            if complete:
                _require(exchange['request_end']=='eof' and exchange['response_status'] is not None
                    and exchange['error'] is None and (exchange['response_end']=='eof'
                        or row['method']=='HTTP_GET_SSE' and exchange['response_end']=='closed'),'maintenance_complete_body')
                _require(h is not None and h['status_code']==exchange['response_status'],'maintenance_header_status')
            data=b'' if exchange['request_ref'] is None else reader.read(exchange['request_ref']['path'],raw=True)
            result=None;arguments={};method=row['method'];key=None;tool=None
            if exchange['method']=='POST' and h is not None and h['path']=='/mcp':
                message=strict_json(data);_require(message['method']==method,'maintenance_raw_method')
                args=message.get('params',{})
                if method=='tools/call':
                    tool=args['name'];arguments=args.get('arguments',{});rid=message['id'];tools+=1
                    key=dict(instance_id=instance,session_id=sid,request_id_type='integer' if type(rid) is int else 'string',request_id=rid)
                    _require(type(rid) in (str,int) and tool in TRANSFER_TOOL_NAMES,'maintenance_tool_identity')
                else:arguments=args
                sha=hashlib.sha256(canonical(arguments)).hexdigest()
                _require(row['work_kind']==('sdk_tool' if tool is not None else 'sdk_control'),'maintenance_work_kind')
                if row['result_ref'] is not None:
                    actual=_json(original(row['result_ref']))
                    responses=[r for r,_ in join.messages(reader,exchange,'response') if type(r.get('id')) is type(message.get('id'))
                        and r.get('id')==message.get('id') and 'result' in r]
                    _require(len(responses)==1,'maintenance_sdk_raw_result')
                    model=CallToolResult if tool else InitializeResult if method=='initialize' else ListToolsResult
                    _require(join.sdk(model,responses[0]['result'])==actual,'maintenance_full_sdk_result')
                    seen_results[row['result_ref']['path']]=row['result_ref']
                    if tool is not None:
                        envelope=actual.get('structuredContent',{})
                        from jsonschema import Draft202012Validator
                        from velo_transfer.adapters import SCHEMAS
                        _require(Draft202012Validator(SCHEMAS[tool]['outputSchema']).is_valid(envelope),
                            'maintenance_transfer_schema')
                        if envelope.get('status')=='success':result=envelope['result']
                if complete and tool is not None:_require(row['result_ref'] is not None and result is not None,'maintenance_tool_success')
            else:
                sha=hashlib.sha256(data).hexdigest()
                expected='HTTP_CHUNKBIN' if h is not None and h['path']=='/chunkbin' else 'HTTP_GET_SSE' if exchange['method']=='GET' else 'HTTP_DELETE'
                _require(method==expected and row['work_kind']==('binary_http' if method=='HTTP_CHUNKBIN' else 'sdk_control'),'maintenance_http_method')
                if method=='HTTP_CHUNKBIN' and exchange['response_end']=='eof' and exchange['response_status']==200:
                    raw_response=reader.read(exchange['response_ref']['path'],raw=True)
                    metadata,payload=wire.parse(raw_response);wire.validate(metadata,payload,'pull_response')
                    result=metadata['result'];offset=0
                    entries=headers_for(request_headers,seq)
                    _require(result['chunks'][0]['offset']==int(header(entries,'x-velo-offset')),'maintenance_binary_offset')
                    for chunk in result['chunks']:
                        piece=payload[offset:offset+chunk['count']];offset+=chunk['count']
                        _require(chunk['offset'] not in chunks or chunks[chunk['offset']]==piece,'maintenance_prefix_conflict')
                        chunks[chunk['offset']]=piece
                    _require(row['result_ref']==_body_ref(exchange['response_ref']),'maintenance_binary_original')
            _require(row['request_key']==key and row['tool']==tool and row['arguments_sha256']==sha,'maintenance_raw_call_binding')
            transfer=row['transfer']
            needs_transfer=method=='HTTP_CHUNKBIN' or tool is not None and tool!='transfer_capabilities'
            _require((transfer is not None)==needs_transfer,'maintenance_transfer_presence')
            if transfer is None:continue
            _require(type(transfer) is dict and set(transfer)=={'transfer_id','request_digest','deadline','receipt_ref'},'maintenance_transfer_exact4')
            if method=='HTTP_CHUNKBIN':
                entries=headers_for(request_headers,seq)
                ident=(header(entries,'x-velo-transfer-id'),header(entries,'x-velo-request-digest'))
            else:
                details=arguments.get('request',arguments);ident=(details['transfer_id'],details['request_digest'])
                if tool=='transfer_begin':
                    _require(request_digest(details)==details['request_digest'],'maintenance_request_digest');bindings[ident]=details
            _require(ident==(transfer['transfer_id'],transfer['request_digest']) and ident[0]==request.transfer_id,'maintenance_transfer_identity')
            if result is not None:
                if result.get('package') is not None:
                    old=packages.setdefault(ident,result['package']);_require(old==result['package'],'maintenance_package_drift')
                if tool=='transfer_chunk':
                    piece=base64.b64decode(result['data_base64'],validate=True)
                    _require(result['offset']==arguments['offset'] and result['count']==arguments['count']==len(piece)
                        and hashlib.sha256(piece).hexdigest()==result['chunk_sha256'],'maintenance_chunk_original')
                    _require(result['offset'] not in chunks or chunks[result['offset']]==piece,'maintenance_prefix_conflict')
                    chunks[result['offset']]=piece
            deadline=transfer['deadline']
            if deadline is not None:
                _require(type(deadline) is dict and set(deadline)=={'clock_domain','value','source_ref'}
                    and deadline['clock_domain']=='guest_process_monotonic' and type(deadline['value']) in (int,float)
                    and math.isfinite(deadline['value']) and deadline['value']>0,'maintenance_deadline_exact3')
                _require(seen_results.get(deadline['source_ref']['path'])==deadline['source_ref'],'maintenance_deadline_original_source')
                source=_json(original(deadline['source_ref']))
                guest=source['structuredContent']['result']
                _require((guest['transfer_id'],guest['request_digest'])==ident
                    and type(guest['worker']['deadline_monotonic']) is type(deadline['value'])
                    and guest['worker']['deadline_monotonic']==deadline['value'],'maintenance_deadline_actual_worker')
                previous_deadline=deadlines.setdefault(ident,deadline['value'])
                _require(previous_deadline==deadline['value'],'maintenance_deadline_drift')
            # These expectations come from independently raw-joined SDK bytes,
            # not the ledger's declared call Refs or top-level union. Every
            # occurrence must retain its own Ref, including repeated status.
            actual_receipts=_actual_receipts(result)
            expected_ref=_receipt_ref(actual_receipts[0]) if actual_receipts else None
            receipt=transfer['receipt_ref']
            if receipt is not None:_ref(receipt)
            _require(receipt==expected_ref,'maintenance_receipt_call_required')
            if actual_receipts:
                from velo_transfer import protocol
                terminal=(result or {}).get('terminal') or {}
                binding=terminal.get('binding') or actual_receipts[0]['binding']
                protocol.validate_binding(binding)
                details=bindings.get(ident)
                _require(details is not None and (binding['transfer_id'],binding['request_digest'])==ident
                    and binding['direction']==details['direction']
                    and all(binding[k]==details['expected_vm_identity'][k] for k in ('vm_uuid','boot_identity','vm_epoch')),
                    'maintenance_receipt_transfer_binding')
                package=packages.get(ident)
                _require(package is not None and all(binding['package_'+k]==package[k] for k in ('size','sha256'))
                    and binding['manifest_sha256']==package['manifest_sha256'],'maintenance_receipt_package_binding')
                for actual in actual_receipts:
                    if actual.get('type')=='prepare':
                        protocol.validate_prepare(actual,binding)
                        old=prepares.setdefault(ident,actual)
                        _require(old==actual,'maintenance_receipt_prepare_drift')
                for actual in actual_receipts:
                    if actual.get('type')=='publication':
                        protocol.validate_publication(actual,binding,prepares.get(ident),details['expected_destination'])
                        _require(actual['destination']['canonical_path']==request.document['destination_directory'],
                            'maintenance_receipt_destination_binding')
                    elif actual.get('type')=='source_validation':
                        protocol.validate_source_validation(actual,binding,prepares.get(ident))
                    else:_require(actual.get('type')=='prepare','maintenance_receipt_kind')
                for actual in actual_receipts:
                    expected=_receipt_ref(actual);observed_receipts[expected['path']]=expected
                    _require(original(expected)==canonical(actual),'maintenance_receipt_actual_result')
                receipt_refs[expected_ref['path']]=expected_ref
        if complete:
            _require(observed_receipts==receipt_refs,'maintenance_receipt_stage_coverage')
        _require(value['transfer_receipts']==sorted(receipt_refs.values(),key=lambda r:r['path']),'maintenance_receipt_union')
    finally:reader.close()
    close=value['close']
    if close is not None:
        _require(type(close) is dict and set(close)=={'exchange_sequence','status_code','cut_ref','barrier_version'}
            and type(close['exchange_sequence']) is int and type(close['status_code']) is int
            and close['status_code']==200 and close['barrier_version']=='pc026-session-close-v1','maintenance_close_exact4')
        _ref(close['cut_ref']);seq=close['exchange_sequence'];h=by_header.get(seq)
        _require(h is not None and h['method']=='DELETE' and h['status_code']==200 and h['request_session_id']==sid
            and by_exchange[seq]['method']=='HTTP_DELETE' and index['exchanges'][seq-1]['response_end']=='eof'
            and index['exchanges'][seq-1]['error'] is None,'maintenance_close_actual')
        _require(_descriptor(headers_for(original_headers,seq),instance,sid)==close['cut_ref'],'maintenance_close_descriptor')
    if complete:
        _require(index['status']=='RECORDED' and index['failure'] is None,'maintenance_capture_complete')
        _require(sum((r['request_ref']['size'] if r['request_ref'] else 0)
            +(r['response_ref']['size'] if r['response_ref'] else 0) for r in index['exchanges'])<=maximum,'maintenance_capture_byte_quota')
        for method in ('initialize','tools/list'):
            entries=[r for r in value['calls'] if r['method']==method]
            _require(len(entries)==1 and entries[0]['result_ref'] is not None and entries[0]['error_ref'] is None,'maintenance_control_result')
        _require(close is not None,'maintenance_close_required')
        _require(len([h for h in headers if h['method']=='DELETE'])==1,'maintenance_one_close')
        descriptor=_json(_read(root,'original-close.json',2048))
        _require(descriptor==context['descriptor'],'maintenance_original_close_binding')
        _require(_read(root,'lifecycle-configuration.json',16<<20)==context['lifecycle_raw']
            and _read(root,'archive-configuration.json',16<<20)==context['archive_raw'],'maintenance_configuration_originals')
        files=_verify_export(context,request,descriptor)
        _require(value['original_cut_ref']==ref('maintenance/downloaded/original/cut.json',files['cut.json']),'maintenance_original_cut_ref')
        from velo_transfer.result import validate_result
        result=_json(_read(root,'transfer-result.json',request.guest_budget['max_metadata_bytes']))
        validate_result(result,max_files=request.guest_budget['max_files'],max_metadata_bytes=request.guest_budget['max_metadata_bytes'])
        _require(result['outcome']=='complete' and result['destination_verified'] is True and result['cleanup']=={'host':True,'guest':True}
            and result['source_stability']=='stable_at_required_check','maintenance_transfer_proof')
        digest=hashlib.sha256();offset=0
        for start,piece in sorted(chunks.items()):
            _require(start==offset,'maintenance_full_package_prefix');digest.update(piece);offset+=len(piece)
        _require(offset==result['package_size'] and digest.hexdigest()==result['package_sha256'],'maintenance_package_hash_eof')
        _require(packages and all(p['size']==offset and p['sha256']==digest.hexdigest() for p in packages.values()),'maintenance_guest_package')
    return value

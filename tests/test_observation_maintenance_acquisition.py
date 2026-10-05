"""Actual host acquisition and raw/C4 checks, explicitly MODEL source authority."""
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import httpx2
from tests import test_observation_maintenance as guest
from tests import test_observation_native_export as native

class AcquisitionHTTP(guest.MaintenanceHTTP):
    test_sdk_begin_actual_activation_live_get_and_native_source=None
    test_capacity_minus_one_zero_transfer_writer=None
    test_source_identity_drift_zero_transfer_writer=None
    def host_request(self):
        import uuid
        from velo_transfer.request import HostRequest
        from velo_transfer.manifest import canonical_json,digest_json
        import velociraptor_observation_maintenance as maintenance
        run=self.guest.host/str(uuid.uuid4());run.mkdir(mode=0o700)
        token=self.guest.host/'token';token.write_text('MODEL');token.chmod(0o600)
        profile=self.guest.host/'connection.json';profile.write_text(json.dumps(dict(version='velo.transfer.connection.v1',
            velo=dict(endpoint=self.url,token_file=str(token)),windows=None,
            deployment=dict(python_path='C:\\fixture\\python.exe',project_root='C:\\fixture',
                policy_path='C:\\fixture\\policy.json',guest_work_root='C:\\fixture\\work'))));profile.chmod(0o600)
        budget=dict(self.request['budget'],request_timeout_seconds=15)
        document=dict(schema='velo.transfer.request.v1',direction='pull',sources=self.request['sources'],
            connection_profile=str(profile),expected_vm_identity=self.request['expected_vm_identity'],
            evidence_context=self.request['evidence_context'],budget=budget,
            destination_directory=str(run/'maintenance'/'downloaded'),transfer_id='maintenance',resume=False)
        request=HostRequest(run/'maintenance-request.json',run/'.velo-transfer','maintenance',False,
            digest_json({k:v for k,v in document.items() if k not in ('transfer_id','resume')}),15,canonical_json(document))
        context=dict(lifecycle_raw=self.exporter.lifecycle_config_raw,lifecycle=json.loads(self.exporter.lifecycle_config_raw),
            archive=self.config.document,archive_raw=native.canonical(self.config.document),instance=self.ledger._instance,original_session=self.original,
            run_id=run.name,descriptor=self.controller._closed_cuts[self.original])
        return run,request,context

    async def acquire(self):
        import velociraptor_observation_maintenance as maintenance
        run,request,context=self.host_request()
        value=await maintenance._acquire(run,request,context,recheck=self.config.group.recheck)
        self.preserve(run)
        return value,run,request,context

    def preserve(self,run):
        evidence=os.environ.get('PC026_MAINTENANCE_EVIDENCE_ROOT')
        if evidence:
            self.evidence=Path(evidence)/('acquisition-'+run.name)
            shutil.copytree(run,self.evidence)

    async def test_actual_same_session_full_binary_acquisition_and_c4(self):
        import velociraptor_observation_maintenance as maintenance
        value,run,request,context=await self.acquire()
        failure=(run/'maintenance'/'failure.json')
        validation=(run/'maintenance'/'validation-error.json')
        details=(failure.read_text() if failure.exists() else '')+(validation.read_text() if validation.exists() else '')
        if value['status']!='COMPLETE':
            capture=json.loads((run/'maintenance'/'raw-mcp'/'capture.json').read_bytes())
            details+=str([(r['sequence'],r['method'],r['request_end'],r['response_end'],r['error']) for r in capture['exchanges']])
        self.assertEqual(value['status'],'COMPLETE',details)
        self.assertEqual(maintenance.validate_maintenance(maintenance.canonical(value),run,context,request),value)
        self.assertTrue(any(r['work_kind']=='binary_http' for r in value['calls']))
        self.assertTrue(value['transfer_receipts'])
        self.assertNotEqual(value['maintenance_session'],self.original)
        self.assertEqual(value['close']['cut_ref'],self.controller._closed_cuts[value['maintenance_session']])
        self.assertEqual(len(self.controller._sessions),2)  # No recursive third SDK session.
        self.assertFalse(any(not c.resources_closed for c in self.controller._children.values()))
        original_files={p.relative_to(self.source).as_posix():p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        delivered=run/'maintenance'/'downloaded'/'original'
        self.assertEqual(original_files,{p.relative_to(delivered).as_posix():p.read_bytes() for p in delivered.rglob('*') if p.is_file()})

        for kind in ('extra','extra_call','bool_sequence','clock_bool','close_cut','cross_instance','cross_session','deadline_source',
                'deadline_value','missing_binary','missing_control','clock_reverse','close_bool'):
            changed=copy.deepcopy(value)
            if kind=='extra':changed['approved']=True
            elif kind=='extra_call':changed['calls'][0]['unused']=False
            elif kind=='bool_sequence':changed['calls'][0]['sequence']=True
            elif kind=='clock_bool':changed['clock']['domain']['resolution_seconds']=True
            elif kind=='close_cut':changed['close']['cut_ref']['sha256']='f'*64
            elif kind=='cross_instance':changed['instance_id']='b'*32
            elif kind=='cross_session':changed['maintenance_session']=self.original
            elif kind in ('deadline_source','deadline_value'):
                row=next(r for r in changed['calls'] if r['transfer'] is not None and r['transfer']['deadline'] is not None)
                if kind=='deadline_source':row['transfer']['deadline']['source_ref']=changed['original_cut_ref']
                else:row['transfer']['deadline']['value']+=1
            elif kind=='missing_binary':changed['calls'].remove(next(r for r in changed['calls'] if r['work_kind']=='binary_http'))
            elif kind=='missing_control':changed['calls'].remove(next(r for r in changed['calls'] if r['method']=='initialize'))
            elif kind=='clock_reverse':changed['calls'][0]['monotonic']['ended_ns']=changed['calls'][0]['monotonic']['started_ns']-1
            else:changed['close']['exchange_sequence']=True
            with self.subTest(kind=kind),self.assertRaises(Exception):
                maintenance.validate_maintenance(maintenance.canonical(changed),run,context,request)
        victim=next(p for p in delivered.rglob('*.json') if '/originals/' in p.as_posix())
        original=victim.read_bytes();wrapper=delivered/'export.json';raw=wrapper.read_bytes()
        doc=json.loads(raw);doc['members']=[r for r in doc['members'] if r['path']!=victim.relative_to(delivered).as_posix()]
        try:
            victim.unlink();wrapper.write_bytes(maintenance.canonical(doc))
            with self.assertRaises(Exception):maintenance.validate_maintenance(maintenance.canonical(value),run,context,request)
        finally:victim.write_bytes(original);wrapper.write_bytes(raw)
        binary=next(r for r in value['calls'] if r['work_kind']=='binary_http')
        name=binary['result_ref']['path'];path=run/name;raw=path.read_bytes()
        index_path=run/value['capture_ref']['path'];index_raw=index_path.read_bytes();index=json.loads(index_raw)
        short=raw[:-1];index['exchanges'][binary['exchange_sequence']-1]['response_ref']=native.ref(Path(name).name,short)
        changed=copy.deepcopy(value);changed['calls'][binary['sequence']-1]['result_ref']=native.ref(name,short)
        modified_index=maintenance.canonical(index);changed['capture_ref']=native.ref(value['capture_ref']['path'],modified_index)
        try:
            path.write_bytes(short);index_path.write_bytes(modified_index)
            with self.assertRaises(Exception):maintenance.validate_maintenance(maintenance.canonical(changed),run,context,request)
        finally:path.write_bytes(raw);index_path.write_bytes(index_raw)
        for kind in ('package_hash','unreleased','offset'):
            result_path=run/'maintenance'/'transfer-result.json';original=result_path.read_bytes();modified=json.loads(original)
            if kind=='package_hash':modified['package_sha256']='d'*64
            elif kind=='offset':modified['package_size']+=1
            else:modified['cleanup']['guest']=False
            try:
                result_path.write_bytes(maintenance.canonical(modified))
                with self.subTest(kind=kind),self.assertRaises(Exception):
                    maintenance.validate_maintenance(maintenance.canonical(value),run,context,request)
            finally:result_path.write_bytes(original)
        receipt=value['transfer_receipts'][0];path=run/receipt['path'];original=path.read_bytes();modified=json.loads(original)
        modified['invalid_receipt']=True;data=maintenance.canonical(modified);changed=copy.deepcopy(value)
        newref=native.ref(receipt['path'],data)
        changed['transfer_receipts']=[newref if r==receipt else r for r in changed['transfer_receipts']]
        for row in changed['calls']:
            if row['transfer'] and row['transfer']['receipt_ref']==receipt:row['transfer']['receipt_ref']=newref
        try:
            path.write_bytes(data)
            with self.assertRaises(Exception):maintenance.validate_maintenance(maintenance.canonical(changed),run,context,request)
        finally:path.write_bytes(original)
        for raw in (b'{"kind":1,"kind":2}\n',b'{"x":1e999}\n',b'{"x":'+b'['*65+b'0'+b']'*65+b'}\n'):
            with self.assertRaises(Exception):maintenance.validate_maintenance(raw,run,context,request)

    async def test_host_space_minus_one_before_capture_sdk(self):
        import velociraptor_observation_maintenance as maintenance
        from types import SimpleNamespace
        run,request,context=self.host_request();limits=context['lifecycle']['budgets']
        required=limits['max_maintenance_bytes']+3*request.guest_budget['max_package_bytes']+limits['max_maintenance_calls']*16384+limits['min_free_bytes']
        before=self.ledger._attempt_count
        with patch.object(maintenance.shutil,'disk_usage',return_value=SimpleNamespace(free=required-1)),self.assertRaisesRegex(Exception,'maintenance_host_free'):
            await maintenance._acquire(run,request,context,recheck=self.config.group.recheck)
        self.assertFalse((run/'maintenance').exists());self.assertEqual(len(self.controller._sessions),1)
        self.assertEqual(self.ledger._attempt_count,before);self.assertFalse(list(self.guest.work.iterdir()))

    async def asyncTearDown(self):
        await super().asyncTearDown()
        if hasattr(self,'evidence'):
            details=dict(authority='Win32 permission/identity MODEL; actual POSIX fd and sockets/SDK/processes',
                server_thread_exited=not self.thread.is_alive(),native_fd_count=len(self.fs.fds),
                child_count=len(self.controller._children),children=[dict(pid=c.pid,job=c.job,wait_status=c.wait_status,
                    resources_closed=c.resources_closed,native_resources_closed=c.native_resources_closed,
                    guard_closed=c.activation_closed) for c in self.controller._children.values()],
                native_io=[dict(joined=r.joined,thread_alive=r.thread.is_alive(),error=None if r.error is None else str(r.error))
                    for r in self.controller._close_io.values()],state=self.controller._state,
                sessions={sid:r['state'] for sid,r in self.controller._sessions.items()})
            (self.evidence/'teardown.json').write_bytes(native.canonical(details))

for _name in vars(guest.MaintenanceHTTP):
    if _name.startswith('test_'):setattr(AcquisitionHTTP,_name,None)

class ReceiptHTTP(AcquisitionHTTP):
    test_actual_same_session_full_binary_acquisition_and_c4=None
    test_host_space_minus_one_before_capture_sdk=None

    async def test_actual_receipt_coverage_and_original_removal(self):
        import velociraptor_observation_maintenance as maintenance
        call=maintenance._SDK.call_tool;replayed=[]
        async def observe_replays(sdk,name,arguments,**kw):
            response=await call(sdk,name,arguments,**kw)
            result=(response.structured_content or {}).get('result',{})
            if name=='transfer_status' and result.get('local_phase')=='SOURCE_RELEASED' and not replayed:
                replayed.append(True);terminal=result['terminal']
                for action in ('prepare','release'):
                    args=dict(transfer_id=arguments['transfer_id'],request_digest=arguments['request_digest'],action=action)
                    if action=='release':args.update(prepare_receipt=terminal['prepare_receipt'],publication_receipt=terminal['publication_receipt'])
                    replay=await call(sdk,'transfer_finish',args)
                    self.assertEqual(replay.structured_content['result']['operation']['status'],'DONE')
            return response
        with patch.object(maintenance._SDK,'call_tool',observe_replays):value,run,request,context=await self.acquire()
        self.assertEqual(value['status'],'COMPLETE')
        self.assertEqual(replayed,[True])
        immutable={p.relative_to(run).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (run/'maintenance').rglob('*') if p.is_file()
            and (p.name.startswith('result-') or 'raw-mcp' in p.parts)}
        expected={};observations=[];receipt_rows=[];multi=[]
        # Independently inspect the saved full SDK results, without using the
        # production receipt selector or any declared ledger receipt Ref.
        for row in value['calls']:
            if row['tool'] is None or row['result_ref'] is None:continue
            result=json.loads((run/row['result_ref']['path']).read_bytes())['structuredContent']['result']
            terminal=result.get('terminal') or {}
            operation=(result.get('operation') or {}).get('result') or {}
            actual=[]
            for r in (operation.get('publication_receipt'),operation.get('prepare_receipt'),operation.get('source_validation_receipt'),
                    terminal.get('publication_receipt'),terminal.get('prepare_receipt'),result.get('source_validation_receipt')):
                if r is not None and r not in actual:actual.append(r)
            refs=[native.ref('maintenance/receipt-'+hashlib.sha256(native.canonical(r)).hexdigest()+'.json',
                native.canonical(r)) for r in actual]
            expected.update({r['path']:r for r in refs})
            if row['transfer'] is not None:
                self.assertEqual(row['transfer']['receipt_ref'],refs[0] if refs else None)
            if refs:receipt_rows.append(row)
            if len(refs)>1:multi.append(row['sequence'])
            observations.append(dict(sequence=row['sequence'],tool=row['tool'],result_ref=row['result_ref'],
                session=value['maintenance_session'],instance=value['instance_id'],
                kinds=[r['type'] for r in actual],expected_refs=refs))
        self.assertTrue(multi)  # Actual released terminal returns prepare AND publication.
        self.assertEqual(value['transfer_receipts'],sorted(expected.values(),key=lambda r:r['path']))
        self.assertEqual(len(expected),2)
        duplicates=[r for r in receipt_rows if r['transfer']['receipt_ref']==receipt_rows[0]['transfer']['receipt_ref']]
        self.assertGreaterEqual(len(duplicates),2)  # Same real prepare seen in later status.
        outcomes=[]
        def reject(kind,changed,code,exception=Exception):
            data=maintenance.canonical(changed)
            if hasattr(self,'evidence'):
                (self.evidence/('negative-'+kind+'.json')).write_bytes(data)
            try:
                with patch.object(maintenance,'_write',side_effect=AssertionError('unexpected receipt writer')) as writer:
                    try:maintenance.validate_maintenance(data,run,context,request)
                    finally:writer.assert_not_called()
            except Exception as error:
                self.assertIsInstance(error,exception,kind);self.assertRegex(str(error),code,kind)
                outcomes.append(dict(kind=kind,error=type(error).__name__,diagnostic=str(error),
                    input_sha256=hashlib.sha256(data).hexdigest(),writer_calls=writer.call_count))
            else:self.fail('receipt negative accepted: '+kind)
        def clear():
            changed=copy.deepcopy(value);changed['transfer_receipts']=[]
            for row in changed['calls']:
                if row['transfer'] is not None:row['transfer']['receipt_ref']=None
            return changed
        reject('all_refs_and_union_removed',clear(),'maintenance_receipt_call_required')
        originals=[(run/r['path'],(run/r['path']).read_bytes()) for r in value['transfer_receipts']]
        try:
            for path,_ in originals:path.unlink()
            reject('all_refs_union_and_originals_removed',clear(),'maintenance_receipt_call_required')
            reject('receipt_files_missing_refs_retained',value,'source_unavailable')
        finally:
            for path,data in originals:path.write_bytes(data)
        changed=copy.deepcopy(value);changed['calls'][duplicates[0]['sequence']-1]['transfer']['receipt_ref']=None
        reject('one_early_ref_removed_later_duplicate_retained',changed,'maintenance_receipt_call_required')
        changed=copy.deepcopy(value);changed['transfer_receipts']=changed['transfer_receipts'][1:]
        reject('union_member_removed_only',changed,'maintenance_receipt_union')
        for kind in ('extra_union','duplicate_union','wrong_result_source','unobserved_call_receipt','bool_ref_size','receipt_alias','foreign_session_ref'):
            changed=copy.deepcopy(value);row=changed['calls'][receipt_rows[0]['sequence']-1]
            if kind=='extra_union':changed['transfer_receipts'].append(value['original_cut_ref'])
            elif kind=='duplicate_union':changed['transfer_receipts'].append(changed['transfer_receipts'][0])
            elif kind=='wrong_result_source':row['transfer']['receipt_ref']=row['result_ref']
            elif kind=='unobserved_call_receipt':
                row=next(r for r in changed['calls'] if r['transfer'] and r['transfer']['receipt_ref'] is None)
                row['transfer']['receipt_ref']=value['transfer_receipts'][0]
            elif kind=='bool_ref_size':row['transfer']['receipt_ref']['size']=True
            else:row['transfer']['receipt_ref']['path']=('maintenance/foreign-session/' if kind=='foreign_session_ref' else
                'maintenance/')+'aliased-receipt.json'
            reject(kind,changed,'maintenance_receipt_union' if kind in ('extra_union','duplicate_union') else
                'integer' if kind=='bool_ref_size' else 'maintenance_receipt_call_required')
        for receipt in value['transfer_receipts']:
            path=run/receipt['path'];original=path.read_bytes()
            try:
                path.write_bytes(original[:-1])
                reject('truncated_'+json.loads(original)['type'],value,'maintenance_ref_content')
            finally:path.write_bytes(original)
        for kind in ('wrong_transfer','wrong_digest','wrong_kind','wrong_prepare_digest','altered_content'):
            selected=next(r for r in value['transfer_receipts'] if json.loads((run/r['path']).read_bytes())['type']=='publication')
            path=run/selected['path'];original=path.read_bytes();doc=json.loads(original)
            if kind=='wrong_transfer':doc['binding']['transfer_id']='foreign-transfer'
            elif kind=='wrong_digest':doc['binding']['request_digest']='f'*64
            elif kind=='wrong_kind':doc['type']='prepare'
            elif kind=='wrong_prepare_digest':doc['prepare_receipt_sha256']='f'*64
            else:doc['publication_id']='altered'
            data=maintenance.canonical(doc);rebound=native.ref(selected['path'],data);changed=copy.deepcopy(value)
            if hasattr(self,'evidence'):
                (self.evidence/('altered-'+kind+'.json')).write_bytes(data)
            changed['transfer_receipts']=[rebound if r==selected else r for r in changed['transfer_receipts']]
            for row in changed['calls']:
                if row['transfer'] and row['transfer']['receipt_ref']==selected:row['transfer']['receipt_ref']=rebound
            try:
                path.write_bytes(data)
                reject(kind+'_outer_hash_rebound',changed,'maintenance_receipt_call_required')
            finally:path.write_bytes(original)
        self.assertEqual(maintenance.validate_maintenance(maintenance.canonical(value),run,context,request),value)
        self.assertEqual(immutable,{p:hashlib.sha256((run/p).read_bytes()).hexdigest() for p in immutable})
        if hasattr(self,'evidence'):
            (self.evidence/'receipt-coverage.json').write_bytes(native.canonical(dict(
                boundary='fresh official SDK/socket/transfer workers; Win32/source authority MODEL',
                status='COMPLETE',observations=observations,expected_union=sorted(expected.values(),key=lambda r:r['path']),
                multi_receipt_sequences=multi,duplicate_prepare_sequences=[r['sequence'] for r in duplicates],
                raw_sdk_unchanged=immutable,negatives=outcomes)))

class CloseFailureHTTP(AcquisitionHTTP):
    test_actual_same_session_full_binary_acquisition_and_c4=None
    test_host_space_minus_one_before_capture_sdk=None
    async def test_sdk_swallowed_actual_delete_503_never_complete(self):
        from velociraptor_observation_controller import ControllerError
        original=self.controller._close_session
        async def refuse(sid,owner,reason='DELETE'):
            if sid!=self.original and reason=='DELETE':raise ControllerError('MODEL_close_refused',503)
            return await original(sid,owner,reason)
        self.controller._close_session=refuse
        value,run,request,context=await self.acquire()
        self.assertEqual(value['status'],'FAILED');self.assertIsNone(value['close'])
        index=json.loads((run/'maintenance'/'raw-mcp'/'capture.json').read_bytes())
        deleted=[r for r in index['exchanges'] if r['method']=='DELETE']
        self.assertEqual(len(deleted),1);self.assertEqual(deleted[0]['response_status'],503)
        self.assertEqual(deleted[0]['response_end'],'eof')
        self.assertFalse((run/'maintenance'/'failure.json').exists())  # SDK swallowed it.
        self.assertEqual(len(self.controller._sessions),2)

    async def test_actual_client_socket_close_truncated_delete_never_complete(self):
        import velociraptor_observation_maintenance as maintenance
        real=maintenance._QuotaHTTP.handle_async_request
        class Dropped(httpx2.AsyncByteStream):
            def __init__(self,stream):self.stream=stream
            async def __aiter__(self):
                async for part in self.stream:
                    yield part[:1]
                    await self.stream.aclose()
                    raise httpx2.ReadError('MODEL intentionally closed actual DELETE socket after one byte')
            async def aclose(self):await self.stream.aclose()
        async def broken(transport,request_http):
            response=await real(transport,request_http)
            if request_http.method=='DELETE':response.stream=Dropped(response.stream)
            return response
        with patch.object(maintenance._QuotaHTTP,'handle_async_request',broken):value,run,request,context=await self.acquire()
        self.assertEqual(value['status'],'FAILED');self.assertIsNone(value['close'])
        index=json.loads((run/'maintenance'/'raw-mcp'/'capture.json').read_bytes())
        deleted=next(r for r in index['exchanges'] if r['method']=='DELETE')
        self.assertEqual(deleted['response_status'],200);self.assertEqual(deleted['response_ref']['size'],1)
        self.assertEqual(deleted['response_end'],'error');self.assertIsNotNone(deleted['error'])
        self.assertEqual(len(self.controller._sessions),2)
        self.assertEqual(self.controller._sessions[value['maintenance_session']]['state'],'CLOSED')


class ResumeHTTP(AcquisitionHTTP):
    test_actual_same_session_full_binary_acquisition_and_c4=None
    test_host_space_minus_one_before_capture_sdk=None

    def configure_policy(self,limits):
        limits.update(max_chunk_bytes=1024,max_batch_chunks=2,max_metadata_bytes=10000,max_package_bytes=1<<20)

    async def test_real_socket_drop_same_sdk_durable_prefix_resume_preserves_failure(self):
        import velociraptor_observation_maintenance as maintenance
        real=maintenance._QuotaHTTP.handle_async_request
        dropped=[];binary=0
        class Dropped(httpx2.AsyncByteStream):
            def __init__(self,stream):self.stream=stream
            async def __aiter__(self):
                async for part in self.stream:
                    yield part[:16]
                    await self.stream.aclose()
                    raise httpx2.ReadError('MODEL deliberately closed actual transfer socket after sixteen bytes')
            async def aclose(self):await self.stream.aclose()
        async def broken(transport,request_http):
            nonlocal binary
            response=await real(transport,request_http)
            if request_http.url.path=='/chunkbin':binary+=1
            if request_http.url.path=='/chunkbin' and binary==2:
                dropped.append(request_http.url.path);response.stream=Dropped(response.stream)
            return response
        chunk=self.guest.service.transfer_chunk
        def refuse_once(**arguments):
            if len(dropped)==1:
                from velo_transfer.host_content import Error
                dropped.append('tool_error');raise Error('internal_error')
            return chunk(**arguments)
        with patch.object(maintenance._QuotaHTTP,'handle_async_request',broken),patch.object(self.guest.service,'transfer_chunk',refuse_once):
            value,run,request,context=await self.acquire()
        self.assertEqual(dropped,['/chunkbin','tool_error'])
        self.assertEqual(value['status'],'FAILED')  # Real first capture failure remains immutable.
        first=json.loads((run/'maintenance'/'transfer-attempt-01.json').read_bytes())
        second=json.loads((run/'maintenance'/'transfer-attempt-02.json').read_bytes())
        self.assertNotEqual(first['outcome'],'complete')
        self.assertEqual(second['outcome'],'complete');self.assertGreater(second['resumed_bytes'],0)
        self.assertEqual(first['transfer_id'],second['transfer_id'])
        self.assertEqual(first['request_digest'],second['request_digest'])
        deadlines={r['transfer']['deadline']['value'] for r in value['calls'] if r['transfer'] and r['transfer']['deadline']}
        self.assertEqual(len(deadlines),1)
        self.assertEqual(len(self.controller._sessions),2)
        self.assertEqual(self.ledger._attempt_count-1,len([r for r in value['calls'] if r['work_kind']=='sdk_tool']))
        self.assertEqual(len([r for r in self.responses if r.request.method=='DELETE']),1)  # Original only on this separate client.
        index=json.loads((run/'maintenance'/'raw-mcp'/'capture.json').read_bytes())
        self.assertEqual(index['status'],'FAILED');self.assertEqual(index['failure']['type'],'ReadError')
        self.assertEqual(len([r for r in index['exchanges'] if r['response_end']=='error']),1)
        delivered=run/'maintenance'/'downloaded'/'original'
        self.assertEqual({p.relative_to(self.source).as_posix():p.read_bytes() for p in self.source.rglob('*') if p.is_file()},
            {p.relative_to(delivered).as_posix():p.read_bytes() for p in delivered.rglob('*') if p.is_file()})
        self.assertEqual(maintenance.validate_maintenance(maintenance.canonical(value),run,context,request),value)

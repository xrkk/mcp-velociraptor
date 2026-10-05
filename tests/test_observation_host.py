"""Fresh SDK/POSIX original and fixed governance MODEL, without Windows qualification."""
import asyncio
import json
import os
from pathlib import Path, PureWindowsPath
import socket
import tempfile
from unittest.mock import patch

import httpx2
from mcp import ClientSession
from tests import test_observation_maintenance_acquisition as acquisition
from tests import test_observation_native_export as native
from tests import test_observation_startup as startup
from tests import test_observation_attempts as attempts
from tests import scenario_runner as runner, p05_pc026_governance as gov
from tests.test_p05_pc026_governance import reference
from tests.p06_pc026_binding import Admission
from tests.p06_call_clock import RunClock
from velociraptor_observation_cut import canonical
import velociraptor_observation_maintenance as maintenance
import velociraptor_observation_host as host


class HostHTTP(acquisition.AcquisitionHTTP):
    test_actual_same_session_full_binary_acquisition_and_c4=None
    test_host_space_minus_one_before_capture_sdk=None

    async def asyncSetUp(self):
        self.preflight=startup.LifecyclePreflightTests();self.preflight.setUp()
        self.addCleanup(self.preflight.doCleanups)
        self._prepare_authority()
        self.root=self.preflight.root
        (self.root/'Logs').chmod(0o700)
        probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();port=getattr(self,'FIXED_PORT',port)
        token=self.root/'host-token';token.write_text('MODEL');token.chmod(0o600)
        self.profile=self.root/'host-connection.json'
        self.profile.write_bytes(canonical(dict(version='velo.transfer.connection.v1',
            velo=dict(endpoint=f'http://127.0.0.1:{port}/mcp',token_file=str(token)),windows=None,
            deployment=dict(python_path=r'C:\fixture\python.exe',project_root=r'C:\fixture',
                policy_path=r'C:\fixture\policy.json',guest_work_root=r'C:\fixture\work'))))
        self.profile.chmod(0o600)
        self.preflight.f.refs[self.profile.name]=reference(self.root,self.profile.name)
        self.preflight.fixture.doc['budgets']=acquisition.guest.archive_limits()
        self.preflight.fixture.bind()
        self.preflight.doc['archive_config_ref']=self.preflight.f.refs[attempts.cfg.CONFIG]
        acquisition.guest.lifecycle_limits(self.preflight.doc['budgets']);self.preflight.bind()
        self.report_root=self.root/'Logs/P06/model'
        import uuid
        self.run=self.report_root/getattr(self,'SCENARIO','p06-compromise-scope')/str(uuid.uuid4())
        for part in reversed((self.run,*self.run.parents)):
            if part.is_relative_to(self.root) and not part.exists():part.mkdir(mode=0o700)
        self.clock=RunClock();self.calls=[];self.original_listing=None;self.original_capture=None
        self.guest_group=None
        configuration=attempts.configuration
        def configured(fs):
            self.guest_configuration=self.preflight.fixture.load()
            self.guest_group=self.guest_configuration.group
            model=configuration(fs)
            from dataclasses import replace
            model=replace(model,document=self.guest_configuration.document,
                root_sd=self.guest_configuration.root_sd,codec=self.guest_configuration.codec,
                catalog_codec=self.guest_configuration.catalog_codec)
            model.group.allowed=dict(self.guest_group.allowed)
            model.group.read=self.guest_group.read
            return model
        self.addCleanup(lambda:self.guest_group and self.guest_group.close())
        self.patch(attempts,'configuration',configured)
        # The exporter still reads the real fixed original configuration. Only
        # Win32 file APIs/path spelling below are modeled on actual POSIX I/O.
        install=native.install
        def installed(test,ledger,fs,config,limits):
            read=config.group.read
            try:
                return install(test,ledger,fs,config,limits)
            finally:config.group.read=read
        self.patch(native,'install',installed)
        self.patch(native,'lifecycle',lambda config,limits:json.loads(canonical(self.preflight.doc)))
        mapping={}
        base=type(Path())
        class ModelPath(base):
            def __init__(self,*args):
                if args and isinstance(args[0],str) and args[0].lower().startswith('c:'+chr(92)) and 'disk' in mapping:
                    args=(str(mapping['disk'].joinpath(*PureWindowsPath(args[0]).parts[1:])),*args[1:])
                super().__init__(*args)
            def __fspath__(self):return super().__str__()
            def __str__(self):
                actual=super().__str__();disk=mapping.get('disk')
                if disk is not None and actual.startswith(str(disk)+'/'):
                    return str(PureWindowsPath('C:/').joinpath(*Path(actual).relative_to(disk).parts))
                return actual
        self._native_namespace_source=lambda raw:ModelPath(raw).is_relative_to(ModelPath(mapping['disk']/'controlled'))
        setup=native.PosixExportIO.setup_export
        def setup_export(fixture):
            result=setup(fixture);mapping['disk']=fixture.disk_root
            fs=result[1];local=fs.local;fs.local=lambda path:ModelPath(local(path))
            return result
        self.patch(native.PosixExportIO,'setup_export',setup_export)
        from velo_transfer import policy
        self.patch(policy,'Path',ModelPath)
        from velo_transfer import manifest,bundle
        self.patch(manifest,'Path',ModelPath);self.patch(bundle,'Path',ModelPath)
        absolute=policy._absolute
        self.patch(policy,'_absolute',lambda value:absolute(ModelPath(value) if isinstance(value,Path) else value))
        from tests import test_transfer_guest as guest
        setup_guest=guest.GuestTests.setUp
        def guest_setup(fixture):
            setup_guest(fixture);fixture.service.shutdown()
            fixture.uuid=gov.VM_UUID
            from velo_transfer.windows_platform import WindowsObservation
            fixture.observation=WindowsObservation('Windows',fixture.uuid,'boot-fixture')
            document=json.loads(fixture.policy.read_bytes());document['expected_vm_uuid']=fixture.uuid
            fixture.policy.write_text(json.dumps(document))
        self.patch(guest.GuestTests,'setUp',guest_setup)
        bind=socket.socket.bind
        def bound(sock,address):return bind(sock,('127.0.0.1',port) if address==('127.0.0.1',0) else address)
        self.patch(socket.socket,'bind',bound)
        client=httpx2.AsyncClient
        def original_client(*args,**kwargs):
            if 'event_hooks' in kwargs and self.original_capture is None:
                self.original_capture=maintenance._Capture(self.run,self.run.name,
                    dict(calls=12000,bytes=2<<30),'a'*32)
                kwargs['transport']=self.original_capture
            kwargs['timeout']=120
            return client(*args,**kwargs)
        self.patch(httpx2,'AsyncClient',original_client)
        call=ClientSession.call_tool;listing=ClientSession.list_tools
        async def observed(session,name,arguments,**kwargs):
            if name!='echo':return await call(session,name,arguments,**kwargs)
            if self.original_listing is None:await session.list_tools()
            name,arguments=self._business_call(name,arguments)
            row=dict(sequence=len(self.calls)+1,step_id='actual-echo',tool=name,arguments=arguments,
                attempt=1,started_at=runner.utc_now(),is_error=True,structured=None,mcp_result=None)
            self.calls.append(row)
            # A real SDK await, with the production call-clock boundary.
            result,error,timing=await self.clock.observe(_SDKCall(session,call),name,arguments,row)
            if error:raise error
            if timing:raise timing
            row.update(ended_at=runner.utc_now(),is_error=result.is_error,structured=result.structured_content,
                mcp_result=result.model_dump(mode='json',by_alias=True,exclude_none=True))
            return result
        async def listed(session,*args,**kwargs):
            result=await listing(session,*args,**kwargs)
            if self.original_listing is None:self.original_listing=result
            return result
        self.patch(ClientSession,'call_tool',observed);self.patch(ClientSession,'list_tools',listed)
        # Setup failure owns the same finite shutdown as a successful fixture.
        self.addAsyncCleanup(self._shutdown_partial)
        try:
            await asyncio.wait_for(super().asyncSetUp(),getattr(self,'SETUP_TIMEOUT',180))
        except BaseException:
            import traceback
            evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);evidence.mkdir(parents=True,exist_ok=True)
            (evidence/'setup-failure.txt').write_text(traceback.format_exc())
            if self.original_capture is not None:
                (evidence/'setup-capture.json').write_bytes(canonical(dict(failure=self.original_capture.failure,rows=self.original_capture.rows)))
            if hasattr(self,'controller'):
                (evidence/'setup-controller.txt').write_text(repr(vars(self.controller)))
            raise
        # Settle the actual transport before any independent reader uses files.
        await self.http.aclose()
        if getattr(self,'ENTRYPOINT_OWNS_RUN',False):return
        self.exporter._namespace_source=lambda raw:ModelPath(raw).is_relative_to(ModelPath(mapping['disk']/'controlled'))
        self.source=ModelPath(self.source)
        headers=self.original_capture
        for name,rows in (('request-headers.json',headers.request_headers),('response-headers.json',headers.original_headers),
                          ('http-headers.json',headers.headers)):
            if getattr(self,'DEFER_FINALIZATION',False) and name!='http-headers.json':continue
            (self.run/name).write_bytes(canonical(rows))
        (self.run/'tools-list.json').write_bytes(canonical(self.original_listing.model_dump(mode='json',by_alias=True,exclude_none=True)))
        identity=dict(computer_name='DESKTOP-3FI41GR',service_name='mcp-velociraptor',pid=os.getpid(),
            process_start_time_utc=runner._runner_start_time_utc(),instance_id=self.ledger._instance,
            executable_sha256=runner._runner_executable_sha256())
        from tests.p06_aggregate_reports import REPORT_KEYS
        self.report={key:None for key in REPORT_KEYS}
        self.report.update(schema_version=2,scenario=self.run.parent.name,run_id=self.run.name,status='success',
            failure=None,transport='streamable-http',endpoint=self.url,mcp_session=dict(id=self.original,
            initialized_at=runner.utc_now(),closed_at=runner.utc_now()),server_identity=identity,
            runner=maintenance._runner(),calls=self.calls,steps=[],cleanup=[],coverage=[],unexecuted_step_ids=[])
        (self.run/'server-observation.json').write_bytes(canonical(dict(identity,observed_at=runner.utc_now())))
        (self.run/'report.json').write_bytes(canonical(self.report))
        self._candidate_inputs()
        if not getattr(self,'DEFER_FINALIZATION',False):self.clock.save(self.run,self.report,canonical(self.report))
        self.patch(runner,'P06_REPORT_ROOT',self.report_root)
        self.admission_configuration=self.preflight.fixture.load();self.addCleanup(self.admission_configuration.group.close)
        group=self.admission_configuration.group
        c=(self.root/gov.CANONICAL).read_bytes()
        self.admission=Admission(group,c,gov.bindings_for(group,c))
        from tests.p06_http_binding import publish
        if not getattr(self,'DEFER_FINALIZATION',False):publish(self.admission,self.run)

    def _prepare_authority(self):pass
    def _business_call(self,name,arguments):return name,arguments
    def _candidate_inputs(self):pass

    async def _shutdown_partial(self):
        if hasattr(self,'http'):await self.http.aclose()
        if hasattr(self,'service'):self.service.shutdown()
        if hasattr(self,'server'):self.server.should_exit=True
        if hasattr(self,'thread'):
            await asyncio.to_thread(self.thread.join,10)
            self.assertFalse(self.thread.is_alive())
        if hasattr(self,'socket'):self.socket.close()

    def patch(self,owner,name,value):
        change=patch.object(owner,name,value);change.start();self.addCleanup(change.stop)

    def host_request(self):
        from velo_transfer.request import load_request
        document=dict(schema='velo.transfer.request.v1',direction='pull',sources=[dict(absolute_path=str(self.source),relative_path='original')],
            connection_profile=str(self.profile),expected_vm_identity=self.request['expected_vm_identity'],
            evidence_context=self.request['evidence_context'],budget=dict(self.request['budget'],request_timeout_seconds=15),
            destination_directory=str(self.run/'maintenance/downloaded'),transfer_id='maintenance',resume=False)
        (self.run/'maintenance-request.json').write_bytes(canonical(document))
        return load_request(self.run/'maintenance-request.json')

    async def test_fresh_sdk_independent_derived_sidecar_and_missing_original(self):
        request=self.host_request()
        ledger=await maintenance.acquire_original(self.admission,self.run,request,
            next(r for r in self.responses if r.request.method=='DELETE'))
        self.preserve(self.run)
        if ledger['status'] != 'COMPLETE':
            from velo_transfer.host_journal import _check_parent_chain
            records=[]
            for p in (request.work_root.parent,*request.work_root.parent.parents):
                i=p.lstat();records.append(dict(path=str(p),mode=oct(i.st_mode),uid=i.st_uid,euid=os.geteuid()))
            (self.evidence/'host-ancestors.json').write_bytes(canonical(records))
        self.assertEqual(ledger['status'],'COMPLETE')
        value=host._publish_acquired(self.admission,self.run)
        self.assertEqual(host.validate(self.admission,self.run),value)
        self.assertEqual(set(value),{'schema_version','kind','run_id','status',*host.REFS})
        import shutil
        shutil.copytree(self.run,self.evidence/'final',dirs_exist_ok=False)
        self.assertEqual(len(self.controller._sessions),2)
        self.assertEqual(self.original_capture.failure,None)
        await self.independent_negatives(value)

    def fresh_admission(self):
        configuration=self.preflight.fixture.load()
        group=configuration.group
        self.addCleanup(group.close)
        raw=(self.root/gov.CANONICAL).read_bytes()
        return Admission(group,raw,gov.bindings_for(group,raw))

    async def independent_negatives(self,value):
        import copy,hashlib
        from tests import p06_http_binding as http,p06_mcp_raw_join as raw
        originals={p.relative_to(self.run).as_posix():p.read_bytes() for p in self.run.rglob('*') if p.is_file()}
        outcomes=[]
        async def negative(name,mutate,code):
            mutate()
            sidecar=copy.deepcopy(value)
            for key,path in host.REFS.items():
                if (self.run/path).exists():sidecar[key]=host.ref(path,(self.run/path).read_bytes())
            (self.run/host.SIDECAR).write_bytes(canonical(sidecar))
            before={p.relative_to(self.run).as_posix():p.read_bytes() for p in self.run.rglob('*') if p.is_file()}
            try:
                with self.assertRaisesRegex(Exception,code) as error:
                    host.validate(self.fresh_admission(),self.run)
                self.assertEqual(before,{p.relative_to(self.run).as_posix():p.read_bytes()
                    for p in self.run.rglob('*') if p.is_file()})
                outcomes.append(dict(case=name,error=str(error.exception),reader_writes=0))
            finally:
                for p in self.run.rglob('*'):
                    if p.is_file() and p.relative_to(self.run).as_posix() not in originals:p.unlink()
                for path,data in originals.items():(self.run/path).write_bytes(data)
        def remove(path):return lambda:(self.run/path).unlink()
        for name,path in (('missing_sidecar',host.SIDECAR),('missing_cut','archive/cut.json'),
                ('missing_ledger','maintenance/ledger.json')):
            # Sidecar missing is not an actor rehash operation.
            if name=='missing_sidecar':
                original=(self.run/path).read_bytes();(self.run/path).unlink()
                try:
                    with self.assertRaises(Exception):host.validate(self.fresh_admission(),self.run)
                    outcomes.append(dict(case=name,reader_writes=0))
                finally:(self.run/path).write_bytes(original)
            else:await negative(name,remove(path),'source|safe governance|unavailable|host_archive_original_bytes')
        ledger=json.loads(originals['maintenance/ledger.json'])
        receipt=ledger['transfer_receipts'][0]['path']
        await negative('missing_actual_receipt_outer_rebound',remove(receipt),'source|unavailable|safe governance')
        result=next(r['result_ref']['path'] for r in ledger['calls'] if r['work_kind']=='sdk_tool')
        await negative('missing_sdk_result_outer_rebound',remove(result),'source|unavailable|safe governance')
        join=json.loads(originals['mcp-raw-join.json']);body=join['calls'][0]['request_location']['body_ref']['path']
        await negative('missing_business_body_outer_rebound',remove('raw-mcp/'+body),'source|unavailable|safe governance')
        def extra():
            for tree in ('archive','maintenance/downloaded/original'):(self.run/tree/'extra.pending').write_bytes(b'x')
        await negative('extra_export_pending_both_copies',extra,'member|closure|files|export')
        def headers():
            rows=json.loads(originals['response-headers.json'])
            deleted=next(r['sequence'] for r in json.loads(originals['raw-mcp/capture.json'])['exchanges'] if r['method']=='DELETE')
            row=next(r for r in rows if r['exchange_sequence']==deleted)
            row['headers'].append(next(v for v in row['headers'] if v[0].lower()=='x-velo-observation-cut'))
            (self.run/'response-headers.json').write_bytes(canonical(rows))
        await negative('duplicate_actual_descriptor',headers,'close_header_unique')
        def rebound(which):
            report=json.loads(originals['report.json']);index=json.loads(originals['raw-mcp/capture.json'])
            seq=join['calls'][0]['request_location']['exchange_sequence'];exchange=index['exchanges'][seq-1]
            path=self.run/'raw-mcp'/exchange['request_ref']['path'];message=json.loads(path.read_bytes())
            if which=='arguments':message['params']['arguments']['value']='actor';report['calls'][0]['arguments']=message['params']['arguments']
            if which=='tool':message['params']['name']='other';report['calls'][0]['tool']='other'
            if which=='typed_id':
                old=message['id'];message['id']=str(old)
                response=index['exchanges'][join['calls'][0]['response_location']['exchange_sequence']-1]
                path2=self.run/'raw-mcp'/response['response_ref']['path'];data=path2.read_bytes()
                data=data.replace(('"id":'+str(old)+',').encode(),('"id":"'+str(old)+'",').encode())
                path2.write_bytes(data);response['response_ref']=host.ref(path2.name,data)
            data=raw.canonical(message);path.write_bytes(data);exchange['request_ref']=host.ref(path.name,data)
            (self.run/'raw-mcp/capture.json').write_bytes(canonical(index))
            data=canonical(report);(self.run/'report.json').write_bytes(data)
            clock=json.loads(originals['call-clock.json']);clock['report_ref']=host.ref('report.json',data)
            (self.run/'call-clock.json').write_bytes(canonical(clock))
            adm=self.fresh_admission();joined,binding=http._derive(self.run,http._AdmissionReader(adm,self.run))
            (self.run/http.JOIN).write_bytes(canonical(joined));(self.run/http.BINDING).write_bytes(canonical(binding))
        for which in ('arguments','tool','typed_id'):
            await negative(which+'_all_host_refs_rebound',lambda w=which:rebound(w),'host_attempt_call_binding|host_typed_attempt_unique')
        (self.evidence/'independent-negatives.json').write_bytes(canonical(outcomes))
        self.assertEqual(len(outcomes),11)



class _SDKCall:
    def __init__(self,session,call):self.session,self.call=session,call
    async def call_tool(self,name,args):return await self.call(self.session,name,args)

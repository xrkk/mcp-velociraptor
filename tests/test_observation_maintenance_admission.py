"""Real isolated fixed source loader and Admission locks; MODEL close/Win32 identity.

The modeled business report/close do not claim a Windows run or S2 consumer
success. No profile is authorized merely by its own content hash.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import unittest
import subprocess
import sys
from unittest.mock import patch
import httpx2
from tests import test_observation_startup as fixture
from tests import p05_pc026_governance as gov, scenario_runner
from tests.p06_pc026_binding import Admission
from velociraptor_observation_cut import canonical
import velociraptor_observation_maintenance as maintenance

class FixedAdmission(unittest.TestCase):
    def setUp(self):
        self.preflight=fixture.LifecyclePreflightTests()
        self.preflight.setUp();self.addCleanup(self.preflight.doCleanups)
        self.root=self.preflight.root;f=self.preflight.f
        self.report_root=self.root/'Logs'/'P06'/'model'
        import uuid
        self.run=self.report_root/'p06-model'/str(uuid.uuid4());self.run.mkdir(parents=True)
        self.sid='MODEL-original-session';self.instance='a'*32
        source=str(PureWindowsPath(self.preflight.fixture.doc['guest_namespace_root']) /
            ('e'+self.instance) / ('s'+hashlib.sha256(self.sid.encode()).hexdigest()))
        descriptor=dict(path='e'+self.instance+'/s'+hashlib.sha256(self.sid.encode()).hexdigest()+'/cut.json',size=10,sha256='b'*64)
        self.close=httpx2.Response(200,content=b'{}',headers={
            'x-mcp-server-instance':self.instance,'x-velo-observation-close':'pc026-session-close-v1',
            'x-velo-observation-cut':base64.urlsafe_b64encode(canonical(descriptor)).rstrip(b'=').decode()},
            request=httpx2.Request('DELETE','http://localhost/mcp',headers={'Mcp-Session-Id':self.sid}))
        identity=dict(computer_name='DESKTOP-3FI41GR',pid=42,process_start_time_utc='2026-10-05T00:00:00Z',
            identity='MODEL',instance_id=self.instance,executable_sha256='c'*64)
        # The existing source reader uses its exact actual seven keys.
        keys=scenario_runner.SERVER_OBSERVATION_KEYS-{'observed_at'}
        identity={key:identity.get(key,'MODEL') for key in keys}
        report=dict(run_id=self.run.name,scenario=self.run.parent.name,mcp_session={'id':self.sid},server_identity=identity)
        (self.run/'report.json').write_bytes(canonical(report))
        (self.run/'server-observation.json').write_bytes(canonical(dict(identity,observed_at='2026-10-05T00:00:00Z')))
        self.profile=self.root/'maintenance-profile.json';self.profile.write_bytes(b'{}\n')
        from tests.test_p05_pc026_governance import reference
        f.refs[self.profile.name]=reference(self.root,self.profile.name);f.runtime()
        from velo_transfer.request import HostRequest
        from velo_transfer.manifest import canonical_json,digest_json
        budgets=dict(max_files=100,max_metadata_bytes=100000,max_logical_bytes=1<<20,max_package_bytes=2<<20,
            min_free_bytes=0,max_chunk_bytes=1<<20,max_duration_seconds=60,request_timeout_seconds=15)
        doc=dict(schema='velo.transfer.request.v1',direction='pull',sources=[{'absolute_path':source,'relative_path':'original'}],
            destination_directory=str(self.run/'maintenance'/'downloaded'),connection_profile=str(self.profile),
            expected_vm_identity={'vm_uuid':gov.VM_UUID,'boot_identity':'MODEL','vm_epoch':'MODEL'},
            evidence_context={'producer_complete':True,'producer_quiescent':True,'references':['MODEL original cut']},
            budget=budgets,transfer_id='maintenance',resume=False)
        spec=self.run/'maintenance-request.json';spec.write_bytes(canonical_json(doc))
        self.request=HostRequest(spec,self.run/'.velo-transfer','maintenance',False,
            digest_json({k:v for k,v in doc.items() if k not in ('transfer_id','resume')}),15,canonical_json(doc))
        self.group=self.preflight.fixture.load().group;self.addCleanup(self.group.close)
        canonical_bytes=(self.root/gov.CANONICAL).read_bytes()
        self.admission=Admission(self.group,canonical_bytes,gov.bindings_for(self.group,canonical_bytes))
        p=patch.object(scenario_runner,'P06_REPORT_ROOT',self.report_root);p.start();self.addCleanup(p.stop)

    def authorize(self):return maintenance._authorize(self.admission,self.run,self.request,self.close)

    def test_actual_fixed_loader_source_and_dynamic_run_lock(self):
        from tests.test_p05_pc026_governance import inventory
        before=inventory(self.root);context=self.authorize()
        self.assertEqual(context['descriptor']['path'],
            'e'+self.instance+'/s'+hashlib.sha256(self.sid.encode()).hexdigest()+'/cut.json')
        self.assertEqual(context['original_session'],self.sid)
        self.assertEqual(inventory(self.root),before);self.assertIn(self.run/'report.json',self.admission.consumed)
        self.assertIn(self.profile,self.admission.consumed)

    def test_self_hashed_profile_outside_allowlist_denied_before_capture(self):
        self.group.allowed.pop(self.profile.name)
        with patch.object(maintenance,'_Capture') as writer,self.assertRaisesRegex(Exception,'maintenance_profile_approval'):
            self.authorize()
        writer.assert_not_called();self.assertFalse((self.run/'maintenance').exists())

    def test_original_header_descriptor_and_locked_run_drift_refuse(self):
        saved=self.close.headers['x-velo-observation-cut']
        self.close.headers['x-velo-observation-cut']=saved+'='
        with self.assertRaisesRegex(Exception,'descriptor_encoding'):self.authorize()
        self.close.headers['x-velo-observation-cut']=saved
        self.authorize()
        (self.run/'report.json').write_bytes(b'{}\n')
        with patch.object(maintenance,'_Capture') as writer,self.assertRaisesRegex(Exception,'consumer input drift'):
            self.authorize()
        writer.assert_not_called();self.assertFalse((self.run/'maintenance').exists())

    def test_approval_source_drift_before_capture(self):
        path=self.root/gov.APPROVAL;path.write_bytes(path.read_bytes()+b'\n')
        with patch.object(maintenance,'_Capture') as writer,self.assertRaises(Exception):self.authorize()
        writer.assert_not_called();self.assertFalse((self.run/'maintenance').exists())

    def test_arbitrary_caller_is_not_admission(self):
        with patch.object(maintenance,'_Capture') as writer,self.assertRaisesRegex(Exception,'maintenance_admission'):
            maintenance._authorize(object(),self.run,self.request,self.close)
        writer.assert_not_called()

    def saved_close(self):
        # Explicit MODEL input for source/authority gates only. This does not
        # claim a physical SDK/DELETE observation or a C5 successful report.
        from tests import p06_http_body_capture as capture
        from velociraptor_observation_cut import ref
        raw=self.run/'raw-mcp';raw.mkdir()
        request=b'';response=b'{}'
        request_ref=dict(ref('exchange-00000001-request.bin',b'x'),size=0,
            sha256=hashlib.sha256(request).hexdigest())
        response_ref=ref('exchange-00000001-response.bin',response)
        (raw/request_ref['path']).write_bytes(request);(raw/response_ref['path']).write_bytes(response)
        index=dict(schema_version=1,kind=capture.KIND,run_id=self.run.name,status='RECORDED',failure=None,
            exchanges=[dict(sequence=1,method='DELETE',request_ref=request_ref,request_end='eof',
                response_status=200,response_content_type='application/json',response_content_encoding='',
                response_ref=response_ref,response_end='eof',error=None)])
        (raw/'capture.json').write_bytes(canonical(index))
        incoming=[['mcp-session-id',self.sid]]
        outgoing=[[k.decode('latin1'),v.decode('latin1')] for k,v in self.close.headers.raw]
        for name,headers in (('request-headers.json',incoming),('response-headers.json',outgoing)):
            (self.run/name).write_bytes(canonical([dict(exchange_sequence=1,headers=headers)]))
        summary=dict(exchange_sequence=1,method='DELETE',path='/mcp',status_code=200,
            mcp_session_id=None,server_instance_id=self.instance,request_session_id=self.sid)
        (self.run/'http-headers.json').write_bytes(canonical([summary]))
        return index

    def test_readback_authority_uses_fixed_sources_without_response_or_writer(self):
        from tests.test_p05_pc026_governance import inventory
        self.saved_close();before=inventory(self.root)
        with patch.object(maintenance,'_Capture') as writer,patch.object(maintenance,'_write') as publish:
            context,request=maintenance._read_authority(self.admission,self.run)
        self.assertEqual(context,self.authorize())
        self.assertEqual(request.document,self.request.document)
        writer.assert_not_called();publish.assert_not_called()
        self.assertEqual(inventory(self.root),before)
        for name in ('request-headers.json','response-headers.json','raw-mcp/capture.json'):
            self.assertIn(self.run/name,self.admission.consumed)

    def test_readback_authority_refuses_duplicate_descriptor_before_writer(self):
        self.saved_close();path=self.run/'response-headers.json';rows=json.loads(path.read_bytes())
        headers=rows[0]['headers'];headers.append(next(row for row in headers if row[0]=='x-velo-observation-cut'))
        path.write_bytes(canonical(rows))
        with patch.object(maintenance,'_write') as writer,self.assertRaisesRegex(Exception,'maintenance_close_header_unique'):
            maintenance._read_authority(self.admission,self.run)
        writer.assert_not_called()

    def test_readback_authority_requires_actual_complete_200_exchange(self):
        index=self.saved_close();index['exchanges'][0]['response_status']=503
        (self.run/'raw-mcp/capture.json').write_bytes(canonical(index))
        with patch.object(maintenance,'_write') as writer,self.assertRaisesRegex(Exception,'original_close_actual'):
            maintenance._read_authority(self.admission,self.run)
        writer.assert_not_called()

    def test_readback_authority_missing_profile_approval_precedes_raw_reads(self):
        self.saved_close();self.group.allowed.pop(self.profile.name)
        (self.run/'raw-mcp/capture.json').unlink()
        with self.assertRaisesRegex(Exception,'maintenance_profile_approval'):
            maintenance._read_authority(self.admission,self.run)

    def test_isolated_host_lazy_imports_and_fixed_source_loader(self):
        code='''import sys
from pathlib import Path
root=Path(sys.argv[1]);original=Path(sys.argv[2]);sys.path.insert(0,str(root))
def audit(event,args):
 if event=='open' and isinstance(args[0],(str,bytes)):
  p=Path(args[0])
  if p.is_absolute() and p.is_relative_to(original) and not (p.is_relative_to(root) or p.is_relative_to(original/'.venv')):
   raise AssertionError('escaped isolated source closure')
sys.addaudithook(audit)
import velociraptor_observation_maintenance
from tests import test_observation_maintenance_acquisition,test_observation_maintenance_admission,test_transfer_protocol_channel
import velociraptor_observation_config as cfg
v=cfg.load_approved();v.group.recheck();v.group.close();print('ISOLATED_MAINTENANCE_LOADER_OK')
'''
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(self.root),str(gov.REPOSITORY)],
            capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('ISOLATED_MAINTENANCE_LOADER_OK',result.stdout)

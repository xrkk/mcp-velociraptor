"""Real formal wire error after a successful handler; no success gate patched."""
import json
import os
from pathlib import Path
from tests.test_observation_host_qualification_entry import ActualQualification
from velociraptor_observation_cut import canonical

class ActualReturnedWireError(ActualQualification):
    ENTRY_SUCCESS=False
    test_actual_resource_qualification_entry_and_original_management_gate=None
    def start_model_management(self,identity):
        super().start_model_management(identity)
        actual=self.server.config.loaded_app;self.wire_faults=[]
        async def altered(scope,receive,send):
            request=[];target=False
            async def incoming():
                nonlocal target
                message=await receive()
                if message['type']=='http.request':
                    request.append(message.get('body',b''))
                    if not message.get('more_body',False) and request:
                        try:document=json.loads(b''.join(request))
                        except (ValueError,UnicodeError):document={}
                        target=document.get('method')=='tools/call' and not self.wire_faults
                return message
            async def outgoing(message):
                if target and message['type']=='http.response.body' and message.get('body') and not self.wire_faults:
                    data=message['body'];start=data.find(b'data: ')
                    if start>=0:
                        original=json.loads(data[start+6:].strip())
                        if 'result' in original:
                            self.wire_faults.append(dict(request=json.loads(b''.join(request)),original=original))
                            wire=dict(jsonrpc='2.0',id=original['id'],error=dict(code=-32000,message='MODEL actual returned handler wire error'))
                            message={**message,'body':b'event: message\r\ndata: '+canonical(wire).strip()+b'\r\n\r\n'}
                await send(message)
            await actual(scope,incoming,outgoing)
        self.server.config.loaded_app=altered
    async def test_actual_returned_wire_error_preserves_formal_failed_packet(self):
        report=self.entry_report;run=self.entry_run
        self.assertEqual(len(self.wire_faults),1)
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(len(report['calls']),1);self.assertTrue(report['calls'][0]['is_error'])
        self.assertEqual(self.model_backend.counter,1)
        self.assertEqual(len(self.controller._sessions),1)
        sid=report['mcp_session']['id']
        self.assertEqual(self.controller._sessions[sid]['state'],'CLOSED')
        source=Path(os.fspath(self.exporter._source_path(sid)))
        files={p.relative_to(source).as_posix():p.read_bytes() for p in source.rglob('*') if p.is_file()}
        native_evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])/'closed-native-source'
        native_evidence.mkdir()
        for name,data in files.items():
            target=native_evidence/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(data)
        records=[self.config.catalog_codec.parse(p.read_bytes()) for p in sorted((source/'originals/c').glob('*.json'))]
        ends=[r['payload'] for r in records if r['record_type']=='ATTEMPT_END']
        self.assertEqual(len(ends),1)
        self.assertEqual((ends[0]['disposition'],ends[0]['outcome']),('COMPLETE','returned'))
        # The separate native source proof uses actual exported originals and
        # the real codec. It does not replace the fixed C5 reader's missing
        # downloaded source or rewrite its original UNCLASSIFIED packet.
        self.exporter.codec.verify(files,self.ledger._config.catalog_codec,
            self.ledger._config.codec,self.exporter.lifecycle_config_raw)
        from tests.p06_http_binding import _AdmissionReader
        from tests.p06_http_body_capture import verify
        from velociraptor_observation_failure import _classify
        from tests import p05_pc026_governance as gov
        from unittest.mock import patch
        with patch.object(gov,'REPOSITORY',self.root):
            admission=self.fresh_admission();reader=_AdmissionReader(admission,run)
            index=verify(run,run.name,_reader=reader)
            headers=json.loads(admission.read(run/'request-headers.json'))
            known=_classify(index,reader,headers,records,report)
        classified=[row for row in known['rows'] if row['classification']=='ACCEPTED_COMPLETE_WITH_WIRE_ERROR']
        self.assertEqual(len(classified),1);self.assertEqual(classified[0]['reason'],'WIRE_ERROR')
        self.assertEqual(classified[0]['attempt_sequences'],[ends[0]['attempt_sequence']])
        diagnostic=json.loads((run/'mcp-observation-failure.json').read_bytes())
        self.assertEqual(diagnostic['status'],'FAILED')
        self.assertTrue(all(row['attempt_sequences']==[] for row in diagnostic['rows']))
        self.assertFalse((run/'mcp-observation-binding.json').exists())
        receipt=[json.loads(line) for line in (self.report_root/'接收清单.jsonl').read_bytes().splitlines()]
        self.assertEqual(len(receipt),1);self.assertEqual(receipt[0]['status'],'failed')
        self.assertTrue((run/'package-manifest.json').is_file())
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        (evidence/'actual-returned-wire-error.json').write_bytes(canonical(dict(
            faults=self.wire_faults,catalog_originals=records,classification=diagnostic,
            independently_verified_native_source_algorithm=known,
            model_backend_residual_flows=self.model_backend.flows,
            nature='actual CLI/SDK/raw wire error after real returned handler; unacquired original cut yields UNCLASSIFIED with no invented sequence')))
        self.preserve(run)

def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(ActualReturnedWireError)

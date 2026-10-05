"""Actual failed second SDK close through the formal candidate finalizer."""
import json
from unittest.mock import patch
from types import SimpleNamespace

from tests.test_observation_host_producer import ActualProducer
from tests import p05_pc026_governance as gov,scenario_runner as runner
from velociraptor_observation_cut import canonical
from velociraptor_observation_controller import ControllerError
import velociraptor_observation_host as host


class FailedProducer(ActualProducer):
    test_formal_candidate_clock_raw_header_acquisition_seal_and_receive=None

    async def test_swallowed_second_delete_503_preserves_failure_package_and_receipt(self):
        request=self.host_request();(self.run/'maintenance-request.json').unlink()
        (self.report_root/'maintenance-request.json').write_bytes(canonical(request.document))
        actual=self.controller._close_session
        async def refuse(sid,owner,reason='DELETE'):
            if sid!=self.original and reason=='DELETE':raise ControllerError('MODEL_close_refused',503)
            return await actual(sid,owner,reason)
        self.controller._close_session=refuse
        capture=SimpleNamespace(request_headers=self.original_capture.request_headers,
            response_headers=self.original_capture.original_headers,
            original_close=next(r for r in self.responses if r.request.method=='DELETE'))
        with patch.object(gov,'REPOSITORY',self.root):
            with self.assertRaisesRegex(Exception,'host_acquisition_failed'):
                await runner._finalize_current(self.report,self.run,self.report_root,self.clock,capture,self.admission,seal=True)
        report=json.loads((self.run/'report.json').read_bytes())
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(report['failure']['message'],'host_acquisition_failed')
        self.assertFalse((self.run/host.SIDECAR).exists())
        ledger=json.loads((self.run/'maintenance/maintenance.json').read_bytes())
        self.assertEqual(ledger['status'],'FAILED');self.assertIsNone(ledger['close'])
        index=json.loads((self.run/'maintenance/raw-mcp/capture.json').read_bytes())
        deleted=next(r for r in index['exchanges'] if r['method']=='DELETE')
        self.assertEqual(deleted['response_status'],503);self.assertEqual(deleted['response_end'],'eof')
        classification=json.loads((self.run/'mcp-observation-failure.json').read_bytes())
        self.assertEqual(classification['status'],'FAILED')
        self.assertTrue(all(row['attempt_sequences']==[] for row in classification['rows']))
        self.assertTrue((self.run/'package-manifest.json').is_file())
        received=json.loads((self.report_root/'接收清单.jsonl').read_bytes())
        self.assertEqual(received['status'],'failed')
        self.assertEqual(len(self.controller._sessions),2)
        self.preserve(self.run)


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(FailedProducer)

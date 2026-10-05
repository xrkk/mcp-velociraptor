"""Actual candidate finalizer, original SDK capture/clock and second SDK.

Only backend, governance and restore authority are isolated MODEL inputs.
"""
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_observation_host_consumers import CurrentHostHTTP
from tests import p05_pc026_governance as gov,scenario_runner as runner
from velociraptor_observation_cut import canonical
import velociraptor_observation_host as host


class ActualProducer(CurrentHostHTTP):
    DEFER_FINALIZATION=True
    test_actual_candidate_package_receive_and_member_gate=None

    async def test_formal_candidate_clock_raw_header_acquisition_seal_and_receive(self):
        request=self.host_request();(self.run/'maintenance-request.json').unlink()
        (self.report_root/'maintenance-request.json').write_bytes(canonical(request.document))
        capture=SimpleNamespace(request_headers=self.original_capture.request_headers,
            response_headers=self.original_capture.original_headers,
            original_close=next(r for r in self.responses if r.request.method=='DELETE'))
        self.assertFalse((self.run/'call-clock.json').exists())
        self.assertFalse((self.run/'mcp-http-binding.json').exists())
        self.assertFalse((self.run/host.SIDECAR).exists())
        with patch.object(gov,'REPOSITORY',self.root):
            await runner._finalize_current(self.report,self.run,self.report_root,self.clock,capture,self.admission,seal=True)
            self.assertEqual(self.report['status'],'success')
            self.assertEqual(host.validate(self.fresh_admission(),self.run)['status'],'BOUND')
        self.assertTrue((self.run/'package-manifest.json').is_file())
        self.assertTrue((self.report_root/'接收清单.jsonl').is_file())
        self.assertEqual(len(self.controller._sessions),2)
        self.preserve(self.run)


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(ActualProducer)

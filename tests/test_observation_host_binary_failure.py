"""Actual truncated maintenance socket through the current formal finalizer."""
import json
from types import SimpleNamespace
from unittest.mock import patch
import httpx2
from tests.test_observation_host_producer import ActualProducer
from tests import p05_pc026_governance as gov,scenario_runner as runner
from velociraptor_observation_cut import canonical
import velociraptor_observation_maintenance as maintenance
import velociraptor_observation_host as host

class TruncatedProducer(ActualProducer):
    test_formal_candidate_clock_raw_header_acquisition_seal_and_receive=None
    async def test_actual_binary_truncation_retains_failed_packet_without_bound(self):
        request=self.host_request();(self.run/'maintenance-request.json').unlink()
        (self.report_root/'maintenance-request.json').write_bytes(canonical(request.document))
        capture=SimpleNamespace(request_headers=self.original_capture.request_headers,
            response_headers=self.original_capture.original_headers,
            original_close=next(r for r in self.responses if r.request.method=='DELETE'))
        actual=maintenance._QuotaHTTP.handle_async_request;dropped=[]
        class Truncated(httpx2.AsyncByteStream):
            def __init__(self,stream):self.stream=stream
            async def __aiter__(self):
                async for data in self.stream:
                    yield data[:16]
                    await self.stream.aclose()
                    raise httpx2.ReadError('MODEL deliberate actual maintenance socket truncation')
            async def aclose(self):await self.stream.aclose()
        async def truncate(transport,http_request):
            response=await actual(transport,http_request)
            if http_request.url.path=='/chunkbin':
                dropped.append(str(http_request.url));response.stream=Truncated(response.stream)
            return response
        with patch.object(gov,'REPOSITORY',self.root),patch.object(maintenance._QuotaHTTP,'handle_async_request',truncate):
            with self.assertRaisesRegex(Exception,'host_acquisition_failed'):
                await runner._finalize_current(self.report,self.run,self.report_root,self.clock,capture,self.admission,seal=True)
        self.assertTrue(dropped,'actual binary ingress was never reached')
        report=json.loads((self.run/'report.json').read_bytes())
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(report['failure']['message'],'host_acquisition_failed')
        self.assertFalse((self.run/host.SIDECAR).exists())
        index=json.loads((self.run/'maintenance/raw-mcp/capture.json').read_bytes())
        self.assertEqual(index['status'],'FAILED');self.assertEqual(index['failure']['type'],'ReadError')
        broken=[row for row in index['exchanges'] if row['response_end']=='error']
        self.assertTrue(broken)
        self.assertTrue(all(row['response_ref']['size']==16 for row in broken))
        diagnostic=json.loads((self.run/'mcp-observation-failure.json').read_bytes())
        self.assertEqual(diagnostic['status'],'FAILED')
        self.assertTrue(all(row['attempt_sequences']==[] for row in diagnostic['rows']))
        self.assertTrue((self.run/'package-manifest.json').is_file())
        receipt=json.loads((self.report_root/'接收清单.jsonl').read_bytes())
        self.assertEqual(receipt['status'],'failed')
        self.assertEqual(len(self.controller._sessions),2)
        self.preserve(self.run)

def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(TruncatedProducer)

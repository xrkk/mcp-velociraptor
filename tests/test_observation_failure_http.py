"""Actual HTTP gates/ledger dispatch, Win32 source MODEL; no approved cut claim."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

import httpx2
from tests.test_observation_controller import ChainTests
from tests.scenario_runner import HttpHeaderCapture
from tests.p06_http_body_capture import CaptureTransport,verify
from tests.p06_mcp_raw_join import _Reader
from velociraptor_observation_cut import canonical
from velociraptor_observation_failure import _classify


class FailureHTTP(ChainTests):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.run=Path(self.temp.name)/str(uuid.uuid4());self.run.mkdir(mode=0o700)
        await super().asyncSetUp()
        await self.http.aclose()
        self.capture=CaptureTransport(httpx2.AsyncHTTPTransport(),self.run,self.run.name)
        self.headers=HttpHeaderCapture(self.capture,_current_raw=True)
        self.http=httpx2.AsyncClient(trust_env=False,timeout=8,transport=self.headers,
            headers={'authorization':'Bearer MODEL','accept':'application/json, text/event-stream','content-type':'application/json'})

    async def test_actual_gates_duplicate_failed_end_typed_sessions_and_delete(self):
        sid=await self.initialize()
        begin=self.ledger._attempt_count
        for headers,status,reason in (({'authorization':'Bearer bad'},401,'AUTH'),
                ({'host':'foreign:1'},421,'HOST'),({'origin':'http://foreign'},403,'ORIGIN')):
            response=await self.http.post(self.url,headers=headers,json=dict(jsonrpc='2.0',id=9,
                method='tools/call',params=dict(name='echo',arguments=dict(value='denied'))))
            self.assertEqual(response.status_code,status)
        self.assertEqual(self.ledger._attempt_count,begin)
        self.assertEqual((await self.call(7)).status_code,200)
        duplicate=await self.call(7);self.assertIn('DUPLICATE',duplicate.text)
        self.assertEqual((await self.call('7')).status_code,200)
        response=await self.http.post(self.url,json=dict(jsonrpc='2.0',id=8,method='tools/call',
            params=dict(name='echo',arguments={},_meta=1)))
        self.assertIn('error',response.text)
        # A new independently initialized session can legally reuse int 7.
        self.http.headers.pop('mcp-session-id');self.http.headers.pop('mcp-protocol-version')
        sid2=await self.initialize();self.assertNotEqual(sid,sid2)
        self.assertEqual((await self.call(7,value='other-session')).status_code,200)
        deleted=await self.http.delete(self.url)
        self.assertEqual(deleted.status_code,503)  # Fixture has no native exporter.
        await self.http.aclose()
        index=verify(self.run,self.run.name)
        reader=_Reader(self.run)
        try:
            # Actual catalog codec originals from this MODEL source. This pure
            # diagnostic assertion does not patch fixed-source derive/Admission.
            report=dict(run_id=self.run.name,server_identity=dict(instance_id=self.ledger._instance),
                calls=[dict(sequence=1,monotonic=dict(invoked=False))])
            value=_classify(index,reader,self.headers.request_headers,self.records(),report)
        finally:reader.close()
        target=os.environ.get('PC026_FAILURE_EVIDENCE_ROOT')
        if target:
            evidence=Path(target);shutil.copytree(self.run,evidence)
            (evidence/'request-headers.json').write_bytes(canonical(self.headers.request_headers))
            (evidence/'response-headers.json').write_bytes(canonical(self.headers.response_headers))
            (evidence/'model-catalog-originals.json').write_bytes(canonical(self.records()))
            (evidence/'report-model.json').write_bytes(canonical(report))
            (evidence/'failure-derived.json').write_bytes(canonical(value))

        rows=value['rows'];gates=[r for r in rows if r['classification']=='PRE_OBSERVER_REJECT']
        self.assertEqual({r['reason'] for r in gates},{'AUTH','HOST','ORIGIN'})
        self.assertTrue(all(r['attempt_sequences']==[] for r in gates))
        self.assertEqual(len([r for r in rows if r['classification']=='DUPLICATE_REJECT']),1)
        self.assertEqual(len([r for r in rows if r['classification']=='ACCEPTED_FAILED']),1)
        self.assertEqual(len([r for r in rows if r['reason']=='CLOSE_UNKNOWN']),1)
        self.assertEqual(rows[-1]['classification'],'NOT_INVOKED')

    async def asyncTearDown(self):
        await super().asyncTearDown()
        target=os.environ.get('PC026_FAILURE_EVIDENCE_ROOT')
        if target and Path(target).exists():
            (Path(target)/'teardown.json').write_bytes(canonical(dict(server_thread_exited=not self.thread.is_alive(),
                http_closed=self.http.is_closed,close_tasks_done=all(t.done() for t in self.controller._close_tasks.values()))))


from tests.test_observation_host import HostHTTP


class FixedFailureHTTP(HostHTTP):
    test_fresh_sdk_independent_derived_sidecar_and_missing_original=None

    async def test_actual_authorized_failure_reader_and_exclusive_publication(self):
        import copy
        from velociraptor_observation_failure import derive,publish,FILE
        run=self.run.parent/str(uuid.uuid4());run.mkdir(mode=0o700)
        body=CaptureTransport(httpx2.AsyncHTTPTransport(),run,run.name)
        headers=HttpHeaderCapture(body,_current_raw=True)
        before=self.ledger._attempt_count
        async with httpx2.AsyncClient(transport=headers,timeout=8,trust_env=False) as client:
            response=await client.post(self.url,headers={'authorization':'Bearer invalid'},json=dict(jsonrpc='2.0',id=7,
                method='tools/call',params=dict(name='echo',arguments=dict(value='denied'))))
            self.assertEqual(response.status_code,401)
        self.assertEqual(before,self.ledger._attempt_count)
        report=copy.deepcopy(self.report);report.update(run_id=run.name,status='failed',coverage=[],
            failure=dict(type='AUTH',message='actual 401 before observer'),calls=[dict(sequence=1,
                monotonic=dict(invoked=False))])
        (run/'report.json').write_bytes(canonical(report))
        (run/'request-headers.json').write_bytes(canonical(headers.request_headers))
        (run/'response-headers.json').write_bytes(canonical(headers.response_headers))
        originals={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
        value=derive(self.fresh_admission(),run)
        self.assertEqual(originals,{p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()})
        self.assertEqual(value['rows'][0]['classification'],'PRE_OBSERVER_REJECT')
        self.assertEqual(value['rows'][0]['attempt_sequences'],[])
        self.assertEqual(value['rows'][1]['classification'],'NOT_INVOKED')
        saved=publish(self.fresh_admission(),run);self.assertEqual(saved,value)
        self.assertEqual((run/FILE).read_bytes(),canonical(value))
        self.assertFalse((run/'mcp-observation-binding.json').exists())
        self.preserve(run)
        with self.assertRaises(FileExistsError):publish(self.fresh_admission(),run)


def load_tests(loader,tests,pattern):
    # Imported parent fixtures confer setup/cleanup, not duplicate test cases.
    return loader.loadTestsFromNames([
        'FailureHTTP.test_actual_gates_duplicate_failed_end_typed_sessions_and_delete',
        'FixedFailureHTTP.test_actual_authorized_failure_reader_and_exclusive_publication'],
        module=__import__(__name__,fromlist=['']))

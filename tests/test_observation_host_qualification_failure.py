"""Actual formal qualification close UNKNOWN with valid MODEL authority/budgets."""
import json
import os
from pathlib import Path
from tests.test_observation_host_qualification_entry import ActualQualification
from velociraptor_observation_cut import canonical

class UnknownPhysicalCleanup:
    async def asyncTearDown(self):
        # UNKNOWN deliberately retains source guards in the running instance.
        # Only this isolated MODEL fixture owns these POSIX descriptors. Stop
        # the real server/HTTP and join actual I/O before releasing them; the
        # logical UNKNOWN evidence and production controller remain unchanged.
        if self.controller._state=='UNKNOWN':
            import asyncio
            await self.http.aclose();self.service.shutdown()
            self.server.should_exit=True
            await asyncio.to_thread(self.thread.join,10);self.socket.close()
            self.assertFalse(self.thread.is_alive())
            self.assertTrue(all(task.done() for task in self.controller._close_tasks.values()))
            self.assertTrue(all(io.thread is None or not io.thread.is_alive() for io in self.controller._close_io.values()))
            retained=list(self.fs.fds)
            for handle in retained:self.fs.close(handle)
            evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
            (evidence/(type(self).__name__+'-physical-release.json')).write_bytes(canonical(dict(
                logical_state=self.controller._state,retained_model_handles=retained,
                physical_remaining=len(self.fs.fds),server_exited=True,
                nature='explicit owned MODEL descriptor release only after server/HTTP/I/O stopped; UNKNOWN is not CLOSED_KNOWN')))
        await super().asyncTearDown()

class ActualUnknownClose(UnknownPhysicalCleanup,ActualQualification):
    ENTRY_SUCCESS=False
    test_actual_resource_qualification_entry_and_original_management_gate=None
    def start_model_management(self,identity):
        super().start_model_management(identity)
        close=self.controller._close_session
        async def unknown(sid,owner,reason='DELETE'):
            self.controller._unknown(sid)
            return await close(sid,owner,reason)
        self.controller._close_session=unknown
    async def test_actual_unknown_close_failed_packet_and_independent_classification(self):
        report=self.entry_report;run=self.entry_run
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(len(report['calls']),41)
        self.assertTrue(all(row['is_error'] is False for row in report['calls']))
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertEqual(len(self.controller._sessions),1)
        index=json.loads((run/'raw-mcp/capture.json').read_bytes())
        deletes=[row for row in index['exchanges'] if row['method']=='DELETE']
        self.assertEqual(len(deletes),1);self.assertEqual(deletes[0]['response_status'],503)
        diagnostic=json.loads((run/'mcp-observation-failure.json').read_bytes())
        self.assertEqual(diagnostic['status'],'FAILED')
        self.assertTrue(all(row['attempt_sequences']==[] for row in diagnostic['rows']))
        self.assertEqual(len([row for row in diagnostic['rows'] if row['reason']=='CLOSE_UNKNOWN']),1)
        self.assertFalse((run/'mcp-observation-binding.json').exists())
        self.assertTrue((run/'package-manifest.json').exists())
        received=[json.loads(line) for line in (self.report_root/'接收清单.jsonl').read_bytes().splitlines()]
        self.assertEqual(len(received),1);self.assertEqual(received[0]['status'],'failed')
        self.preserve(run)
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        (evidence/'unknown-close-assertions.json').write_bytes(canonical(dict(
            nature='actual qualification CLI/SDK; explicit controller UNKNOWN injection; valid MODEL authority and 12-record budget',
            raw_delete=deletes[0],classification=diagnostic,received=received[0],
            source_unavailable='UNKNOWN has no authorized complete cut; no attempt numbers guessed')))

class ActualUnacknowledged(UnknownPhysicalCleanup,ActualQualification):
    ENTRY_SUCCESS=False
    test_actual_resource_qualification_entry_and_original_management_gate=None
    def start_model_management(self,identity):
        super().start_model_management(identity)
        actual=self.ledger._catalog.publish;self.ack_faults=[]
        def publish(data):
            record=self.config.catalog_codec.parse(data)
            if record['record_type']=='ACCEPT_ACK':
                self.ack_faults.append(record)
                raise OSError('MODEL actual ACCEPT_ACK publication failure before write')
            return actual(data)
        self.patch(self.ledger._catalog,'publish',publish)
    async def test_actual_unacknowledged_formal_call_is_failed_and_unclassified_without_cut(self):
        report=self.entry_report;run=self.entry_run
        self.assertEqual(report['status'],'failed');self.assertEqual(report['coverage'],[])
        self.assertEqual(len(self.ack_faults),1)
        self.assertEqual(len(report['calls']),1)
        self.assertEqual(self.controller._state,'UNKNOWN')
        self.assertTrue(self.ledger._unknown)
        self.assertEqual(self.model_backend.counter,0,'business dispatched before durable ACK')
        self.assertEqual(len(self.controller._sessions),1)
        diagnostic=json.loads((run/'mcp-observation-failure.json').read_bytes())
        self.assertEqual(diagnostic['status'],'FAILED')
        self.assertTrue(all(row['attempt_sequences']==[] for row in diagnostic['rows']))
        tool_rows=[row for row in diagnostic['rows'] if row['classification']=='UNCLASSIFIED']
        self.assertTrue(tool_rows,'no authentic closed cut can authorize an ACK_UNKNOWN attempt number')
        self.assertFalse((run/'mcp-observation-binding.json').exists())
        received=[json.loads(line) for line in (self.report_root/'接收清单.jsonl').read_bytes().splitlines()]
        self.assertEqual(len(received),1);self.assertEqual(received[0]['status'],'failed')
        self.assertTrue((run/'package-manifest.json').is_file())
        self.preserve(run)
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        (evidence/'ack-publication-fault.json').write_bytes(canonical(dict(
            actual_failed_publication=self.ack_faults,classification=diagnostic,
            nature='actual formal CLI/SDK; fault before ACK original publication; no business dispatch; source unavailable UNKNOWN, no attempt number invented')))

def load_tests(loader,tests,pattern):
    import unittest
    return unittest.TestSuite([loader.loadTestsFromTestCase(ActualUnknownClose),
        loader.loadTestsFromTestCase(ActualUnacknowledged)])

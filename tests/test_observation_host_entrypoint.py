"""Actual formal individual entry; backend/governance/restore are MODEL only."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import patch

from tests.test_observation_host_consumers import CurrentHostHTTP
from tests.test_p04_fixed_tools import FakeBackend,flow_row
from tests import p05_pc026_governance as gov,scenario_runner as runner
from velociraptor_observation_cut import canonical


class IndividualBackend(FakeBackend):
    def __init__(self):
        super().__init__();self.flows['F.fixture']=flow_row('F.fixture','FINISHED')

    def get_hunt_details(self,hunt_id):
        if hunt_id=='H.__p06_missing__':return None
        return super().get_hunt_details(hunt_id)

    def list_flow_uploads(self,client_id,flow_id):
        if flow_id=='F.fixture':return []
        return super().list_flow_uploads(client_id,flow_id)


class ActualIndividual(CurrentHostHTTP):
    SCENARIO='individual-acceptance'
    ENTRY_SCRIPT='p06_individual_acceptance.py'
    ENTRYPOINT_OWNS_RUN=True
    SETUP_TIMEOUT=3600
    backend_factory=IndividualBackend
    MODEL_DOWNLOAD_ROOT=True
    test_actual_candidate_package_receive_and_member_gate=None

    async def asyncSetUp(self):
        self.entry_children=[]
        self.addCleanup(self._record_owned_cleanup)
        await super().asyncSetUp()

    def _record_owned_cleanup(self):
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);evidence.mkdir(parents=True,exist_ok=True)
        controller=getattr(self,'controller',None)
        value=dict(parent_pid=os.getpid(),
            server_thread_exited=not getattr(self,'thread',None) or not self.thread.is_alive(),
            http_closed=not getattr(self,'http',None) or self.http.is_closed,
            children=[dict(pid=child.pid,exit=child.returncode) for child in self.entry_children],
            native_open_fd_count=len(getattr(getattr(self,'fs',None),'fds',{})),
            close_tasks_done=controller is None or all(task.done() for task in controller._close_tasks.values()),
            close_io_threads_exited=controller is None or all(io.thread is None or not io.thread.is_alive() for io in controller._close_io.values()),
            logical_controller_state=None if controller is None else controller._state,
            nature='observed after all fixture cleanup callbacks; logical UNKNOWN is not CLOSED_KNOWN')
        (evidence/'owned-cleanup.json').write_bytes(canonical(value))
        self.assertTrue(value['server_thread_exited']);self.assertTrue(value['http_closed'])
        self.assertTrue(all(row['exit'] is not None for row in value['children']))
        self.assertTrue(value['close_io_threads_exited'])

    def configure_model_server(self,server,backend):
        from velociraptor_mcp_core import FlowReferenceResult
        from velociraptor_dynamic_artifacts import _strict_tool_schema
        def terminal(Command:str,Timeout:int,Stateful:bool)->FlowReferenceResult:
            return FlowReferenceResult(operation='fixture',status='success',warnings=[],flow_id='F.fixture')
        server.remove_tool('Windows.System.PowerShell')
        server.add_tool(terminal,name='Windows.System.PowerShell',description='MODEL terminal probe')
        _strict_tool_schema(server._tool_manager.get_tool('Windows.System.PowerShell'))

    async def _original_sdk(self):
        self.report_root=self.root/'Logs/P06/wf-01a05d1d-p06-r3'
        self.report_root.mkdir(parents=True,mode=0o700)
        self.run=self.report_root/self.SCENARIO/self.run.name
        from tests.test_p06_pc026_binding import CurrentConsumerTests
        from velo_transfer.guest_service import GuestTransferService
        builder=CurrentConsumerTests('test_call_clock_actual_admission_matrix_and_tail_drift')
        builder.root=self.root;builder.A=self.activation;builder.received=self.report_root
        builder.canonical=(self.root/gov.CANONICAL).read_bytes();builder.state=json.loads(builder.canonical)
        builder.seal=lambda run:None
        for key in ('preparation_evidence','migration_evidence','activation_evidence'):
            relative=builder.state[key]['evidence_path']
            shutil.copytree((self.root/gov.EVIDENCE/relative).parent,(self.report_root/relative).parent)
        fixture,restore=builder.attempt(self.SCENARIO);restore['run_id']=self.run.name
        shutil.copyfile(fixture/'fixture-instance.json',self.report_root/'fixture-instance.json')
        shutil.rmtree(fixture)
        # The fixture builder used the process umask for its owned scenario
        # directory. Transfer ancestry requires it to be private before SDK I/O.
        self.run.parent.chmod(0o700)
        (self.report_root/'current-restore.json').write_bytes(canonical(restore))
        identity=dict(computer_name='DESKTOP-3FI41GR',service_name='mcp-velociraptor',pid=os.getpid(),
            process_start_time_utc=runner._runner_start_time_utc(),instance_id=self.ledger._instance,
            executable_sha256=runner._runner_executable_sha256(),observed_at=runner.utc_now())
        (self.report_root/'server-observation.json').write_bytes(canonical(identity))
        # MODEL policy is fixed before the business SDK. Native source activation
        # still admits only the actual closed export, never an open namespace.
        source=self.preflight.fixture.doc['guest_namespace_root']
        self.guest.service.shutdown();policy=json.loads(self.guest.policy.read_bytes())
        policy['read_roots']=[source];policy['limits']['max_batch_chunks']=4
        policy['limits'].update(getattr(self,'MODEL_GUEST_LIMITS',{}))
        self.guest.limits.update(policy['limits']);self.guest.policy.write_text(json.dumps(policy));self.guest.policy.chmod(0o600)
        self.guest.service=GuestTransferService(self.guest.policy,_observation=self.guest.observation,_acl_verifier=lambda p,k:True)
        self.addCleanup(self.guest.service.shutdown)
        guest_request=self.guest.request('pull',[dict(absolute_path=str(source),relative_path='original')],
            self.guest.host/'downloaded',transfer_id='maintenance')
        document=dict(schema='velo.transfer.request.v1',direction='pull',sources=guest_request['sources'],
            connection_profile=str(self.profile),expected_vm_identity=guest_request['expected_vm_identity'],
            evidence_context=guest_request['evidence_context'],budget=dict(guest_request['budget'],request_timeout_seconds=getattr(self,'MODEL_REQUEST_TIMEOUT',15)),
            destination_directory=str(self.run/'maintenance/downloaded'),transfer_id='maintenance',resume=False)
        (self.report_root/'maintenance-request.json').write_bytes(canonical(document))
        # Execute the complete frozen source tree, so __file__, indexes and the
        # production code-owned root all name the same approved MODEL deployment.
        # No validator or admission loader is replaced in this real client.
        setup=getattr(self,'start_model_management',None)
        if setup is not None:setup(identity)
        command=[sys.executable,'-B',str(self.root/'tests'/self.ENTRY_SCRIPT),
            '--endpoint',self.url,'--token-env','PC026_R14_TOKEN']
        child=await asyncio.create_subprocess_exec(*command,cwd=self.root,
            env={**os.environ,'PYTHONPATH':str(self.root),'PC026_R14_TOKEN':'MODEL'},
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        self.entry_children.append(child)
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);evidence.mkdir(parents=True,exist_ok=True)
        (evidence/'entry-child.json').write_bytes(canonical(dict(pid=child.pid,command=command)))
        output,error=b'',b''
        try:
            output,error=await asyncio.wait_for(child.communicate(),3400)
        finally:
            if child.returncode is None:
                child.terminate();await child.wait()
        (evidence/'entry-stdout.bin').write_bytes(output);(evidence/'entry-stderr.bin').write_bytes(error)
        (evidence/'entry-exit.json').write_bytes(canonical(dict(pid=child.pid,exit=child.returncode)))
        self.entry_run=self.run
        self.entry_report=json.loads((self.run/'report.json').read_bytes())
        (evidence/'controller-close-outcomes.json').write_bytes(canonical(dict(
            state=self.controller._state,
            retained_high_water=self.controller._retained,
            retained_measured_peak=self.controller._retained_measured_peak,
            retained_limit=self.controller._limits['max_retained_state_bytes'],
            sessions={sid:row['state'] for sid,row in self.controller._sessions.items()},
            errors={sid:runner._exception_chain(error) for sid,error in self.controller._close_errors.items()})))
        expected=0 if getattr(self,'ENTRY_SUCCESS',True) else 1
        self.assertEqual(child.returncode,expected,error.decode(errors='replace')[-1000:])

    async def test_actual_individual_entry_clock_binding_archive_and_failed_tool_contracts(self):
        self.assertEqual(self.entry_report['status'],'success',self.entry_report['failure'])
        self.assertEqual(self.entry_report['coverage'],[])
        self.assertEqual(len(self.controller._sessions),2)
        self.assertEqual(len(json.loads((self.entry_run/'tools-list.json').read_bytes())['tools']),137)
        for name in ('mcp-observation-binding.json','archive/cut.json','maintenance/ledger.json',
                'call-clock.json','mcp-http-binding.json','package-manifest.json'):
            self.assertTrue((self.entry_run/name).is_file(),name)
        self.assertTrue((self.report_root/'接收清单.jsonl').is_file())
        self.assertEqual(len([r for r in self.entry_report['calls'] if r['is_error']]),8)
        self.preserve(self.entry_run)


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(ActualIndividual)

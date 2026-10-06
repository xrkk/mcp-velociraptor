"""Six real CLI/SDK attempts under one isolated approval; all business backends MODEL.

No assertions, qualification readers or coverage reports are replaced. Five
original complete scenarios must produce their own 645 relations before the
actual aggregate may succeed. The MODEL management channel is explicit.
"""
import asyncio
from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

from tests.test_observation_host_qualification_entry import ActualQualification,QualificationBackend
from tests.test_observation_host_consumers import guest
from tests import p05_pc026_governance as gov,scenario_runner as runner
from velociraptor_dynamic_artifacts import ArtifactParameterSpec,_strict_tool_schema
from velociraptor_fixed_tools import KILL_PROCESS_ARTIFACT
from velociraptor_mcp_core import FlowReferenceResult
from velociraptor_observation_cut import canonical

class ScenarioBackend(QualificationBackend):
    def __init__(self):
        super().__init__();self.dependencies.add(KILL_PROCESS_ARTIFACT);self.special={}
    def run_vql(self,query,*,max_rows):
        match=re.fullmatch(r'SELECT (\d+) AS ScenarioOrdinal, "([^"]+)" AS FocusFile FROM scope\(\)',query)
        if match:return [{'ScenarioOrdinal':int(match[1]),'FocusFile':match[2]}]
        return super().run_vql(query,max_rows=max_rows)
    def start_collection(self,client_id,artifact,parameters=None,**options):
        result=super().start_collection(client_id,artifact,parameters,**options)
        if (parameters or {}).get('Command','').startswith('Start-Sleep'):
            self.flows[result.flow_id]['state']='WAITING'
            result=FlowReferenceResult(operation='fixture',status='WAITING',warnings=[],flow_id=result.flow_id)
        if artifact==KILL_PROCESS_ARTIFACT:self.special[result.flow_id]=[{'Killed':parameters['Pid']}]
        return result
    def get_flow_results_window(self,client_id,flow_id,artifact,*,source,start_row,count):
        if flow_id in self.special:return self.special[flow_id][start_row:start_row+count]
        return super().get_flow_results_window(client_id,flow_id,artifact,source=source,start_row=start_row,count=count)
    def get_flow_result_count(self,client_id,flow_id,artifact,*,source):
        if flow_id in self.special:return len(self.special[flow_id])
        return super().get_flow_result_count(client_id,flow_id,artifact,source=source)

class ActualFullScenarios(ActualQualification):
    SETUP_TIMEOUT=43200
    backend_factory=ScenarioBackend
    test_actual_resource_qualification_entry_and_original_management_gate=None
    async def asyncSetUp(self):
        limits=guest.lifecycle_limits
        archive=guest.archive_limits
        def six_attempt_archives():
            value=archive();a=32768
            value.update(max_attempts=a,max_directories=a+2,max_catalog_records=3*a+2,
                max_seen_key_bytes=a*value['max_key_bytes'])
            codec=value['request_codec'];codec.update(max_records=12,max_total_bytes=12*codec['max_record_bytes'])
            value['max_total_archive_bytes']=(3*a+2)*value['max_catalog_record_bytes']+a*codec['max_total_bytes']+value['max_active']*codec['max_record_bytes']+value['max_catalog_record_bytes']
            return value
        self.patch(guest,'archive_limits',six_attempt_archives)
        def many_owned_sessions(value):
            limits(value);value.update(max_retained_state_bytes=512<<20,
                max_sessions=16,max_export_files=16000000,
                max_export_directories=600000,max_export_bytes=1<<46,
                max_sdk_work=100000,max_binary_work=16000,max_maintenance_calls=18000,
                max_maintenance_bytes=10<<30,max_cut_bytes=64<<20,
                max_proof_bytes=64<<20,max_source_manifest_bytes=64<<20)
        self.patch(guest,'lifecycle_limits',many_owned_sessions)
        await super().asyncSetUp()
    def configure_model_server(self,server,backend):
        invocations=json.loads(Path('tests/data/p03_invocations.json').read_bytes())
        values={row['artifact']:row['parameters'] for row in invocations}
        def make(artifact,parameters):
            def dynamic(**arguments)->FlowReferenceResult:
                return backend.start_collection('C.one',artifact,arguments)
            dynamic.__signature__=inspect.Signature([
                inspect.Parameter(name,inspect.Parameter.KEYWORD_ONLY,annotation=type(value))
                for name,value in parameters.items()],return_annotation=FlowReferenceResult)
            return dynamic
        from tests.p04_fixture_server import dynamic_candidate
        _,specs=dynamic_candidate();result=[]
        for spec in specs:
            parameters=values[spec.name]
            server.remove_tool(spec.name)
            server.add_tool(make(spec.name,parameters),name=spec.name,description='MODEL inert collection')
            _strict_tool_schema(server._tool_manager.get_tool(spec.name))
            result.append(replace(spec,parameters=tuple(ArtifactParameterSpec(
                name=name,kind={str:'string',int:'int',bool:'bool'}[type(value)],default=value,
                description='MODEL',friendly_name='',choices=(),validating_regex='')
                for name,value in parameters.items())))
        return tuple(result)
    async def _original_sdk(self):
        await super()._original_sdk()
        assert self.entry_report['status']=='success'
        qualification=self.entry_run
        (self.report_root/'resource-qualification-selection.json').write_bytes(canonical(dict(
            report_relative_path=(qualification/'report.json').relative_to(self.report_root).as_posix(),
            report_sha256=hashlib.sha256((qualification/'report.json').read_bytes()).hexdigest())))
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        from tests.test_p06_pc026_binding import CurrentConsumerTests
        builder=CurrentConsumerTests('test_call_clock_actual_admission_matrix_and_tail_drift')
        builder.root=self.root;builder.A=self.activation;builder.received=self.report_root
        builder.canonical=(self.root/gov.CANONICAL).read_bytes();builder.state=json.loads(builder.canonical)
        builder.seal=lambda run:None
        self.scene_runs=[]
        scenarios=json.loads((self.root/'tests/data/p06_scenario_index.json').read_bytes())['scenarios']
        for row in scenarios:
            scene=row['scenario_id'];temporary,restore=builder.attempt(scene)
            run_id=temporary.name;shutil.rmtree(temporary);temporary.parent.chmod(0o700)
            (self.report_root/'current-restore.json').write_bytes(canonical(restore))
            command=[sys.executable,'-B',str(self.root/'tests/scenario_runner.py'),
                '--scenario-id',scene,'--transport','streamable-http','--endpoint',self.url,
                '--token-env','PC026_R14_TOKEN','--run-id',run_id,
                '--server-observation',str(self.report_root/'server-observation.json')]
            child=await asyncio.create_subprocess_exec(*command,cwd=self.root,
                env={**os.environ,'PYTHONPATH':str(self.root),'PC026_R14_TOKEN':'MODEL'},
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            self.entry_children.append(child)
            (evidence/(scene+'-child.json')).write_bytes(canonical(dict(pid=child.pid,command=command)))
            output,error=b'',b''
            try:output,error=await asyncio.wait_for(child.communicate(),7200)
            finally:
                if child.returncode is None:child.terminate();await child.wait()
                (evidence/(scene+'-stdout.bin')).write_bytes(output)
                (evidence/(scene+'-stderr.bin')).write_bytes(error)
                (evidence/(scene+'-exit.json')).write_bytes(canonical(dict(pid=child.pid,exit=child.returncode)))
            self.assertEqual(child.returncode,0,error.decode(errors='replace')[-2000:])
            report=json.loads((temporary/'report.json').read_bytes())
            self.assertEqual(report['status'],'success',report['failure'])
            self.assertEqual(len(report['coverage']),129)
            self.scene_runs.append(temporary)
            (evidence/'scene-progress.json').write_bytes(canonical([str(path) for path in self.scene_runs]))
    async def test_actual_five_scenario_aggregate_with_645_original_relations(self):
        from tests import p06_aggregate_reports as aggregate
        from unittest.mock import patch
        rows=[json.loads(line) for line in (self.report_root/'接收清单.jsonl').read_bytes().splitlines()]
        selected={row['scenario']:{key:row[key] for key in ('monotonic_attempt','report_sha256',
            'manifest_relative_path','manifest_sha256','package_sha256')}
            for row in rows if row['scenario'].startswith('p06-')}
        selection=dict(schema_version=2,all_attempts=[row['monotonic_attempt'] for row in rows],
            selected=selected,rejected={str(row['monotonic_attempt']):'resource qualification has zero scenario coverage'
                for row in rows if not row['scenario'].startswith('p06-')})
        (self.report_root/'final-selection.json').write_bytes(canonical(selection))
        with patch.object(gov,'REPOSITORY',self.root),patch.object(runner,'P06_REPORT_ROOT',self.report_root):
            value=aggregate.aggregate(evidence_root=self.report_root,
                ledger_path=self.report_root/'接收清单.jsonl',selection_path=self.report_root/'final-selection.json',
                manifest_path=self.root/'tests/data/p06_coverage_manifest.json')
        self.assertEqual(value['scenario_count'],5);self.assertEqual(value['relation_count'],645)
        self.assertEqual(len(self.controller._sessions),12)
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT'])
        (evidence/'aggregate-derived.json').write_bytes(canonical(value))
        await self._full_consumer_matrix(rows,selection,evidence)
        for run in [self.entry_run,*self.scene_runs]:self.preserve(run)

    async def _full_consumer_matrix(self,rows,selection,evidence):
        from unittest.mock import patch
        import traceback
        from tests import p06_package as package,p06_pc026_binding as binding
        from tests import p06_aggregate_reports as aggregate,p07_handoff as handoff
        import velociraptor_observation_host as host
        run=self.scene_runs[0];reports=self.report_root
        originals={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
        sidecar=json.loads(originals[host.SIDECAR])
        ledger=json.loads(originals['maintenance/ledger.json'])
        join=json.loads(originals['mcp-raw-join.json'])
        targets={'sidecar':host.SIDECAR,'cut':'archive/cut.json','ledger':'maintenance/ledger.json',
            'capture':'raw-mcp/capture.json','body':'raw-mcp/'+join['calls'][0]['request_location']['body_ref']['path'],
            'SDK':next(row['result_ref']['path'] for row in ledger['calls'] if row['work_kind']=='sdk_tool'),
            'receipt':ledger['transfer_receipts'][0]['path']}
        ledger_path=reports/'接收清单.jsonl';selection_path=reports/'final-selection.json'
        old_ledger=ledger_path.read_bytes();old_selection=selection_path.read_bytes()
        def snapshot():
            return {p.relative_to(self.root).as_posix():(hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mtime_ns)
                for p in self.root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        @gov.consumption
        def selected():
            admission=binding.load();members=[]
            def add(path):
                value=handoff._ref(admission,path);members.append(value);return value
            for path in self.scene_runs:handoff._selected_run_members(admission,path,reports,add)
            admission.recheck();return members
        def aggregated():
            return aggregate.aggregate(evidence_root=reports,ledger_path=ledger_path,
                selection_path=selection_path,manifest_path=self.root/'tests/data/p06_coverage_manifest.json')
        outcomes=[]
        with patch.object(gov,'REPOSITORY',self.root),patch.object(runner,'P06_REPORT_ROOT',reports):
            before=snapshot();members=selected();self.assertEqual(snapshot(),before)
            self.assertTrue(members)
            (evidence/'five-run-selected-members.json').write_bytes(canonical(members))
            for entry,consume in [('aggregate',aggregated),('five_run_selected_members',selected)]:
                for name,relative in targets.items():
                    with self.subTest(entry=entry,missing=name):
                        try:
                            (run/relative).unlink()
                            if name!='sidecar':
                                changed=dict(sidecar)
                                for key,path in host.REFS.items():
                                    if (run/path).exists():changed[key]=host.ref(path,(run/path).read_bytes())
                                (run/host.SIDECAR).write_bytes(canonical(changed))
                            inventory=canonical(package._member_inventory(run,reports))
                            (run/package.FINAL_MANIFEST).write_bytes(inventory)
                            sha=hashlib.sha256(inventory).hexdigest()
                            rebound=[dict(row) for row in rows]
                            target=next(row for row in rebound if row['report_relative_path']==(run/'report.json').relative_to(reports).as_posix())
                            target.update(manifest_sha256=sha,package_sha256=sha)
                            ledger_path.write_bytes(b''.join(canonical(row) for row in rebound))
                            chosen=json.loads(old_selection)
                            chosen['selected'][target['scenario']].update(manifest_sha256=sha,package_sha256=sha)
                            selection_path.write_bytes(canonical(chosen))
                            before=snapshot()
                            try:consume()
                            except Exception as error:
                                trace=''.join(traceback.format_exception(error));message=str(error)
                            else:self.fail('full consumer accepted missing original')
                            self.assertIn('velociraptor_observation_host.py',trace)
                            self.assertNotIn('package manifest differs',message)
                            self.assertEqual(snapshot(),before)
                            outcomes.append(dict(entry=entry,missing=name,path=str(run/relative),error=message,traceback=trace,writes=0))
                            (evidence/'five-run-consumer-matrix.json').write_bytes(canonical(outcomes))
                        finally:
                            for path,data in originals.items():(run/path).write_bytes(data)
                            ledger_path.write_bytes(old_ledger);selection_path.write_bytes(old_selection)
        self.assertEqual(len(outcomes),14)

def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(ActualFullScenarios)

"""Host file-tree consumer checks; no VM or real business success is asserted."""
from __future__ import annotations
import asyncio
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid
import zipfile
import subprocess
import sys
from unittest.mock import patch

from tests import p05_pc026_governance as gov
from tests import p05_pc020_evidence as ev
from tests import p05_pc026_profile as profiles
from tests import p06_pc026_binding as binding
from tests import p06_evidence, p06_package, p06_receive, scenario_runner
from tests import p06_aggregate_reports, p07_cost_measurement, p07_cost_measurement_r232
from tests.pc026_governance_fixture import build
from tests.test_p05_pc026_governance import inventory
from tests.test_p06_evidence_schema5 import restore_action_envelopes


class CurrentConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bootstrap = os.environ.get('PC026_BOOTSTRAP_FIXTURE_ROOT')
        if not bootstrap:
            raise unittest.SkipTest('explicit historical bootstrap fixture required')
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'))
        cls.root = Path(cls.temp.name)
        values = {key: os.environ[key] for key in (
            'PC020_ACTIVATION188_FIXTURE', 'PC020_PREDECESSOR_FIXTURE',
            'PC020_BASELINE_DIR_FIXTURE', 'PC020_ACTIVATION_DIR_FIXTURE', 'PC020_REAL_SOURCE_ROOT')}
        cls.A = build(cls.root, Path(bootstrap), values, gov.REPOSITORY)
        cls.received = cls.root / 'received'
        cls.received.mkdir()
        cls.canonical = (cls.root / gov.CANONICAL).read_bytes()
        cls.state = json.loads(cls.canonical)
        for key in ('preparation_evidence', 'migration_evidence', 'activation_evidence'):
            relative = cls.state[key]['evidence_path']
            shutil.copytree((cls.root / gov.EVIDENCE / relative).parent,
                            (cls.received / relative).parent)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def load(self):
        return gov._load_at(self.root, synthetic_fixture=True)

    def attempt(self, scenario="p06-compromise-scope"):
        run_id, attempt = str(uuid.uuid4()), str(uuid.uuid4())
        run = self.received / scenario / run_id
        run.mkdir(parents=True)
        raw_root = self.received / 'restore-originals' / attempt
        paths = restore_action_envelopes(raw_root, attempt, profiles.CURRENT.snapshot,
            self.state['active_snapshot']['checkpoint_marker'])
        path = paths['snapshot_metadata']
        value = json.loads(path.read_bytes())
        names = [*profiles.CURRENT.retained, profiles.CURRENT.snapshot]
        stdout = f'Total snapshots: {len(names)}\n' + '\n'.join(names) + '\n'
        value['response'].update(stdout=stdout, stdout_size=len(stdout.encode()),
                                 stdout_sha256=ev._sha(stdout.encode()))
        path.write_bytes(ev.canonical_json(value))
        paths['canonical_readback'] = raw_root / 'canonical.json'
        paths['canonical_readback'].write_bytes(self.canonical)
        for kind, key in (('pc020_preparation', 'preparation_evidence'),
                          ('pc020_migration', 'migration_evidence'),
                          ('activation_evidence', 'activation_evidence')):
            paths[kind] = self.received / self.state[key]['evidence_path']
        restore = {'workflow_id': ev.WORKFLOW_ID, 'run_id': run_id,
            'restore_attempt_id': attempt, 'snapshot_stage': 'P06_ACTIVE',
            'snapshot_name': profiles.CURRENT.snapshot,
            'checkpoint_marker': self.state['active_snapshot']['checkpoint_marker'],
            'canonical_schema_version': 6, 'canonical_epoch': 8,
            'canonical_phase': 'NETWORK_ACTIVE', 'canonical_sha256': ev._sha(self.canonical),
            'restore_records': [{'kind': k, 'path': p.relative_to(self.received).as_posix(),
                'sha256': ev._sha(p.read_bytes())} for k, p in paths.items()]}
        rootdoc = json.loads((self.A / 'activation-evidence.json').read_bytes())
        report = json.loads((self.A / rootdoc['candidate_cycles'][1]['report']['path']).read_bytes())
        report.update(scenario=scenario, run_id=run_id)
        report['mcp_session']['id'] = 'synthetic-session-' + run_id
        report['runner']['pid'] = int(uuid.UUID(run_id)) % 100000 + 1000
        index_bytes = (self.root / 'tests/data/p06_scenario_index.json').read_bytes()
        if scenario in {'resource-qualification','individual-acceptance'}:
            report.update(index_sha256=ev._sha((self.root/'tests/data'/('p03_invocations.json' if scenario=='resource-qualification' else 'p06_scenario_index.json')).read_bytes()),
                          source_sha256=ev._sha((self.root/'tests'/('p06_resource_qualification.py' if scenario=='resource-qualification' else 'p06_individual_acceptance.py')).read_bytes()), coverage=[])
        else:
            row = next(r for r in json.loads(index_bytes)['scenarios'] if r['scenario_id'] == scenario)
            report.update(index_sha256=ev._sha(index_bytes), source_sha256=row['sha256'])
        fixture = (self.A / rootdoc['candidate_cycles'][1]['report']['path']).parent.joinpath('fixture-instance.json').read_bytes()
        (run / 'fixture-instance.json').write_bytes(fixture)
        report['fixture_instance_sha256'] = ev._sha(fixture)
        observation = {**report['server_identity'], 'observed_at': report['started_at']}
        (run / 'server-observation.json').write_bytes(ev.canonical_json(observation))
        report['server_observation_sha256'] = ev._sha((run / 'server-observation.json').read_bytes())
        source_run = (self.A / rootdoc['candidate_cycles'][1]['report']['path']).parent
        tools = json.loads((source_run / 'tools-schema.json').read_bytes())
        transfer = json.loads((self.root / 'velo_transfer/transfer_tools_schema.json').read_bytes())
        tools += [{'name': name, 'inputSchema': schema['inputSchema'],
                   'outputSchema': schema['outputSchema']} for name, schema in transfer.items()]
        tools.sort(key=lambda t: t['name'])
        (run / 'tools-schema.json').write_bytes(ev.canonical_json(tools))
        (run / 'tools-list.json').write_bytes(ev.canonical_json({'tools': tools}))
        report['tools_schema_sha256'] = ev._sha((run / 'tools-schema.json').read_bytes())
        snapshot = {'restore': restore, 'scenario_id': scenario, 'source_sha256': report['source_sha256'],
            'index_sha256': report['index_sha256'], 'mcp_session_id': report['mcp_session']['id'],
            'server_instance_id': report['server_identity']['instance_id'],
            'server_observation_sha256': report['server_observation_sha256']}
        (run / 'snapshot-evidence.json').write_bytes(ev.canonical_json(snapshot))
        report['snapshot_evidence_sha256'] = ev._sha((run / 'snapshot-evidence.json').read_bytes())
        (run / 'report.json').write_bytes(ev.canonical_json(report))
        self.seal(run)
        return run, restore

    def observation(self, run, report, value, step_id):
        value.update(run_id=report['run_id'], hostname=report['server_identity']['computer_name'],
                     server_pid=report['server_identity']['pid'], observed_at=report['started_at'],
                     step_id=step_id, trace_status='synthetic inactive',
                     transcript='resources/' + str(value['sequence']) + '.json')
        original = {key: value[key] for key in ('hostname','server_pid','observed_at','reading','trace_status')}
        envelope = {'result': {'isError': False, 'structuredContent': {
            'result': 'Response: ' + json.dumps(original) + '\nStatus Code: 0'}}}
        path = run/value['transcript']; path.parent.mkdir(exist_ok=True)
        path.write_bytes(ev.canonical_json({'run_id': report['run_id'], 'step_id': step_id,
            'control_plane_only': True, 'transcript': [{'request': {'method':'tools/call',
                'params': {'name':'PowerShell'}}, 'response': json.dumps(envelope)}]}))
        return value

    def qualification(self):
        from tests.test_p06_resource_gate import synthetic_qualification
        from tests.p06_resource_gate import freeze_measurements
        run, _ = self.attempt('resource-qualification')
        report = json.loads((run/'report.json').read_bytes())
        rows = synthetic_qualification()['steps']
        for row in rows:
            if row['id'] == 'static-resource-gate':
                self.observation(run, report, row['observation'], 'qualification-start')
            else:
                self.observation(run, report, row['before'], row['id']+'-before')
                self.observation(run, report, row['after'], row['id']+'-after')
        report['steps'] = [{'id':'implementation-identity','kind':'source-identity', 'files': {
            name: ev._sha((self.root/'tests'/name).read_bytes()) for name in (
                'scenario_runner.py','p06_resource_gate.py','p06_formal_session.py',
                'p06_resource_qualification.py','p06_package.py','p06_evidence.py','p06_resource_policy.py',
                'p06_receive.py','p06_aggregate_reports.py','p06_pc026_binding.py','p06_call_clock.py',
                'p06_http_body_capture.py','p06_mcp_raw_join.py','p06_http_binding.py',
                'data/p06_scenario_index.json','data/p06_resource_policy.json','data/p03_invocations.json')}}] + rows
        report['calls'] = []; report['coverage'] = []
        def add(label, tool, arguments, structured):
            report['calls'].append({'sequence':len(report['calls'])+1, 'step_id':label, 'tool':tool,
                'arguments':arguments,'structured':structured,'is_error':False,'ended_at':report['ended_at'],
                'mcp_result':{'isError':False,'content':[],'structuredContent':structured}})
        fixture_flow = None
        for row in rows[1:]:
            label = row['id']
            if label == 'download':
                continue
            flow = 'F.synthetic-' + label; row['flow_id'] = flow
            add(label,row['tool'],{}, {'flow_id':flow})
            add(label+'-wait','get_flow_status',{'flow_id':flow}, {'flow_id':flow,'state':'FINISHED'})
            add(label+'-results','get_flow_results',{'flow_id':flow}, {'operation':'get_flow_results','data':[]})
            files = [{'file_id':'a'*64}] if label == 'fixture-file' else []
            add(label+'-files','list_flow_files',{'flow_id':flow}, {'operation':'list_flow_files','data':files})
            if label == 'fixture-file': fixture_flow = flow
        add('download','download_flow_file',{'flow_id':fixture_flow,'file_id':'a'*64},
            {'flow_id':fixture_flow,'file_id':'a'*64})
        report['failure'] = None; report['unexecuted_step_ids'] = []
        (run/'report.json').write_bytes(ev.canonical_json(report))
        manifest = p06_package.member_inventory(run, self.received, payload=True)
        (run/'qualification-payload-manifest.json').write_bytes(ev.canonical_json(manifest))
        sources = p06_package.member_sources(run, self.received)
        with zipfile.ZipFile(run/'qualification-payload.zip','x',zipfile.ZIP_STORED) as archive:
            archive.write(run/'qualification-payload-manifest.json','qualification-payload-manifest.json')
            for member in manifest['members']:
                archive.write(sources[member['path']], member['path'])
        budget = {'schema_version':1,'report_sha256':ev._sha((run/'report.json').read_bytes()),
            **p06_package.verify_payload_zip(run,self.received), **freeze_measurements(report)}
        (run/'resource-budget.json').write_bytes(ev.canonical_json(budget)); self.seal(run)
        (self.received/'resource-qualification-selection.json').write_bytes(ev.canonical_json({
            'report_relative_path':(run/'report.json').relative_to(self.received).as_posix(),
            'report_sha256':ev._sha((run/'report.json').read_bytes())}))
        return run

    def full_report(self, scenario, admission):
        from tests.p06_resource_gate import ScenarioResourceGate, admit, remaining_peak
        from tests.test_p06_resource_gate import reading
        run, _ = self.attempt(scenario)
        report = json.loads((run/'report.json').read_bytes())
        source = json.loads((self.root/'tests/scenarios/full'/f'{scenario}.json').read_bytes())
        gate = ScenarioResourceGate(self.received, source, None, _admission=admission)
        sequence = 100
        def observe(step_id):
            nonlocal sequence
            sequence += 1
            return self.observation(run, report, {'sequence':sequence,'reading':reading(80*1024**3)}, step_id)
        first = observe('p06-resource-start-before')
        report['steps'] = [{'id':'p06-resource-start','resource':{'observation':first,
            'qualification':gate.identity, 'scenario_deadline_seconds':gate.scenario_seconds,
            'admission':admit(first['reading'],remaining_increment=remaining_peak(
                list(gate.labels.values()),gate.budget['steps']),
                evidence_reserve=gate.budget['evidence_reserve_bytes'],initial_peak=gate.budget['observed_peak_bytes'])}}]
        pending = list(gate.labels)
        for step in source['steps']:
            item = {'id':step['id'],'kind':step['kind'],'passed':True}
            if step['id'] in gate.related:
                resource = {'qualification':gate.identity}
                if step['id'] in gate.labels:
                    before = observe(step['id']+'-before')
                    resource.update(observation=before, step_deadline_seconds=gate.deadlines[step['id']],
                        admission=admit(before['reading'], remaining_increment=remaining_peak(
                            [gate.labels[k] for k in pending],gate.budget['steps']),
                            evidence_reserve=gate.budget['evidence_reserve_bytes']))
                    pending.remove(step['id'])
                resource['after'] = observe(step['id']+'-after'); item['resource'] = resource
            report['steps'].append(item)
        manifest = json.loads((self.root/'tests/data/p06_coverage_manifest.json').read_bytes())
        report['coverage'] = [{'scenario_id':scenario,'tool':row['tool']} for row in manifest['relations']
                              if row['scenario_id'] == scenario]
        report['failure'] = None; report['unexecuted_step_ids'] = []; report['duration_ms'] = 1
        (run/'report.json').write_bytes(ev.canonical_json(report)); self.seal(run)
        return run

    def seal(self, run):
        # Synthetic fixture only: declared intervals are model observations,
        # never appended to production/historical success originals.
        from tests.p06_call_clock import RunClock
        report = json.loads((run/'report.json').read_bytes())
        if report['scenario'] not in {'resource-qualification', 'individual-acceptance'} and report['status']=='success':
            from tests.pc026_raw_fixture import prepare,construct
            prepare(run,report)
            clock_path = run/'call-clock.json'
            metadata = (json.loads(clock_path.read_bytes())['clock'] if clock_path.exists()
                        else RunClock().clock)
            for i, call in enumerate(report['calls']):
                call['monotonic'] = {'clock_id': metadata['clock_id'], 'invoked': True,
                                     'started_ns': i*2_000_000, 'ended_ns': i*2_000_000+1_000_000}
                call['duration_ms'] = 1
            raw = ev.canonical_json(report); (run/'report.json').write_bytes(raw)
            value = {'schema_version': 1, 'kind': 'pc026-p06-call-clock-v1',
                     'run_id': report['run_id'], 'runner': report['runner'],
                     'report_ref': {'path': 'report.json', 'size': len(raw), 'sha256': ev._sha(raw)},
                     'clock': metadata, 'status': 'RECORDED'}
            clock_path.write_bytes(ev.canonical_json(value))
            construct(run)
        (run / 'package-manifest.json').write_bytes(p06_package.canonical_bytes(
            p06_package.member_inventory(run, self.received)))

    def test_call_clock_actual_admission_matrix_and_tail_drift(self):
        from tests import p06_call_clock
        run, _ = self.attempt()
        report_path = run/'report.json'; clock_path = run/'call-clock.json'
        original_report = report_path.read_bytes(); original_clock = clock_path.read_bytes()
        report = json.loads(original_report)
        admission = binding._from_group(self.load())
        admission.report(report, run, self.received)
        self.assertIn(clock_path, admission.consumed)
        self.assertIn('run/call-clock.json', {r['path'] for r in p06_package.member_inventory(run,self.received)['members']})
        mutations = ['missing','bool','inverse','overlap','domain','run','ref','extra','duplicate']
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report_path.write_bytes(original_report); clock_path.write_bytes(original_clock)
                d=json.loads(original_report); c=json.loads(original_clock)
                if mutation == 'bool':d['calls'][0]['monotonic']['started_ns']=True
                if mutation == 'inverse':d['calls'][0]['monotonic']['ended_ns']=-1
                if mutation == 'overlap':d['calls'][1]['monotonic']['started_ns']=0
                if mutation == 'domain':d['calls'][0]['monotonic']['clock_id']=str(uuid.uuid4())
                raw=ev.canonical_json(d);report_path.write_bytes(raw)
                c['report_ref'].update(size=len(raw),sha256=ev._sha(raw))
                if mutation == 'run':c['run_id']=str(uuid.uuid4())
                if mutation == 'ref':c['report_ref']['sha256']='0'*64
                if mutation == 'extra':c['clock']['extra']=1
                clock_path.write_bytes(ev.canonical_json(c))
                if mutation == 'missing':clock_path.unlink()
                if mutation == 'duplicate':clock_path.write_bytes(b'{"schema_version":1,"schema_version":1}')
                # Rebind only the synthetic package: the target is the actual
                # clock consumer predicate, not an unrelated stale manifest.
                (run/'package-manifest.json').write_bytes(p06_package.canonical_bytes(
                    p06_package.member_inventory(run,self.received)))
                with self.assertRaises((ValueError, p06_evidence.EvidenceError, OSError)):
                    binding._from_group(self.load()).report(d,run,self.received)
        report_path.write_bytes(original_report);clock_path.write_bytes(original_clock)
        (run/'package-manifest.json').write_bytes(p06_package.canonical_bytes(
            p06_package.member_inventory(run,self.received)))
        admission=binding._from_group(self.load());admission.report(report,run,self.received)
        changed=json.loads(original_clock);changed['clock']['implementation']+=' drift'
        clock_path.write_bytes(ev.canonical_json(changed))
        with self.assertRaisesRegex(ev.Pc020EvidenceError,'drift'):admission.recheck()

    def test_call_clock_run_domain_cannot_be_reused(self):
        run1,_=self.attempt();run2,_=self.attempt('p06-ransomware-root-cause')
        old=json.loads((run1/'call-clock.json').read_bytes())['clock']['clock_id']
        report=json.loads((run2/'report.json').read_bytes())
        value=json.loads((run2/'call-clock.json').read_bytes())
        value['clock']['clock_id']=old
        for row in report['calls']:row['monotonic']['clock_id']=old
        raw=ev.canonical_json(report);(run2/'report.json').write_bytes(raw)
        value['report_ref'].update(size=len(raw),sha256=ev._sha(raw))
        (run2/'call-clock.json').write_bytes(ev.canonical_json(value))
        (run2/'package-manifest.json').write_bytes(p06_package.canonical_bytes(p06_package.member_inventory(run2,self.received)))
        self.seal(run2)
        admission=binding._from_group(self.load())
        admission.report(json.loads((run1/'report.json').read_bytes()),run1,self.received)
        with self.assertRaisesRegex(ev.Pc020EvidenceError,'domain reused'):
            admission.report(report,run2,self.received)

    def test_full_aggregate_and_selection_rejection_actual_entry(self):
        qualification = self.qualification()
        with patch.object(gov, 'load', side_effect=self.load):
            admission = binding.load()
            runs = [self.full_report(s, admission) for s in p07_cost_measurement.SCENARIOS]
            selected = {}
            for run in runs:
                receipt = p06_receive.receive(run, self.received)
                selected[receipt['scenario']] = {k:receipt[k] for k in (
                    'monotonic_attempt','report_sha256','manifest_relative_path','manifest_sha256','package_sha256')}
            rows = p06_aggregate_reports.load_ledger(self.received/'接收清单.jsonl', self.received)
            selection = {'schema_version':2,'all_attempts':[r['monotonic_attempt'] for r in rows],
                         'selected':selected,'rejected':{str(r['monotonic_attempt']):'isolated other case'
                           for r in rows if r['monotonic_attempt'] not in {s['monotonic_attempt'] for s in selected.values()}}}
            path = self.received/'final-selection.json'; path.write_bytes(ev.canonical_json(selection))
            options = dict(evidence_root=self.received,ledger_path=self.received/'接收清单.jsonl',
                selection_path=path,manifest_path=self.root/'tests/data/p06_coverage_manifest.json')
            result = p06_aggregate_reports.aggregate(**options)
            self.assertEqual((result['relation_count'],result['distinct_restore_attempt_count']), (645,5))
            before = inventory(self.received)
            # Current P07 now consumes the fixed handoff; this older receiver
            # fixture has no controlled completion/Git records. Its aggregate
            # success above is not handoff qualification. Exercise the actual
            # cost-entry refusal after a focused verifier seam; full handoff
            # create/read-only verification lives in test_p07_handoff.
            from tests import p07_handoff
            for entry in (p07_cost_measurement.main, p07_cost_measurement_r232.main):
                with patch.object(p07_handoff, 'verify', return_value={}) as verify:
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        with self.assertRaisesRegex(ValueError, 'upstream|historical'):
                            entry()
                        self.assertEqual(output.getvalue(), '')
                    verify.assert_called_once_with()
                self.assertEqual(inventory(self.received), before)
            bad = copy.deepcopy(selection)
            keys = list(selected)
            bad['selected'][keys[0]],bad['selected'][keys[1]] = bad['selected'][keys[1]],bad['selected'][keys[0]]
            path.write_bytes(ev.canonical_json(bad))
            with self.assertRaisesRegex(ValueError, 'another scenario'):
                p06_aggregate_reports.aggregate(**options)
            path.write_bytes(ev.canonical_json(selection))
            # Actual aggregate tail recheck after successful content validation.
            original = p06_aggregate_reports.aggregate_historical
            def drift(**kwargs):
                value = original(**kwargs)
                path.write_bytes(ev.canonical_json(bad))
                return value
            with patch.object(p06_aggregate_reports,'aggregate_historical',side_effect=drift), \
                    self.assertRaisesRegex(ev.Pc020EvidenceError,'consumer input drift'):
                p06_aggregate_reports.aggregate(**options)
            path.write_bytes(ev.canonical_json(selection))

    def test_individual_success_receives_only_zero_coverage(self):
        run, _ = self.attempt('individual-acceptance')
        with patch.object(gov,'load',side_effect=self.load):
            receipt = p06_receive.receive(run,self.received)
        self.assertEqual(receipt['status'],'success')
        self.assertEqual(json.loads((run/'report.json').read_bytes())['coverage'],[])

    def test_isolated_current_consumer_closure(self):
        code = r"""
import sys, json
from pathlib import Path
root = Path(sys.argv[1]); original = Path(sys.argv[2])
sys.path.insert(0, str(root))
def audit(event,args):
    if event == 'open' and isinstance(args[0], (str, bytes)):
        path = Path(args[0]).absolute()
        if path.is_relative_to(original) and not (path.is_relative_to(root) or path.is_relative_to(original/'.venv')):
            raise AssertionError('consumer read escaped freeze: ' + str(path))
sys.addaudithook(audit)
from tests import p06_pc026_binding as binding
from tests import scenario_runner, p06_receive, p06_aggregate_reports, p06_call_clock
from tests import p06_http_binding, p06_http_body_capture, p06_mcp_raw_join
from tests import p07_cost_measurement, p07_cost_measurement_r232, p06_resource_qualification
admission = binding.load()
modules = {}
for name, module in tuple(sys.modules.items()):
    if name == 'tests' or name.startswith(('tests.', 'velo_transfer', 'velociraptor_')):
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(root), (name,path)
        assert path.relative_to(root).as_posix() in admission.group.freeze_refs, (name,path)
        modules[name] = path.relative_to(root).as_posix()
admission.recheck()
print(json.dumps({'qualified':True,'modules':modules}))
"""
        before = inventory(self.root)
        result = subprocess.run([sys.executable,'-I','-B','-c',code,str(self.root),str(gov.REPOSITORY)],
            cwd=self.root,capture_output=True,text=True,timeout=120)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['qualified'])
        self.assertEqual(inventory(self.root),before)
        print('isolated consumer load: '+result.stdout.strip(),flush=True)

    def test_rebound_current_closure_omissions(self):
        from tests.test_p05_pc026_governance import ApprovalFixture
        with tempfile.TemporaryDirectory(dir=os.environ['PC020_TEST_TEMP_ROOT']) as directory:
            root = Path(directory)
            fixture = ApprovalFixture(root,Path(os.environ['PC026_BOOTSTRAP_FIXTURE_ROOT']))
            for name in ('tests/p06_http_body_capture.py','tests/p06_mcp_raw_join.py','tests/p06_http_binding.py',
                         gov.BODY_CONTRACT,gov.JOIN_CONTRACT,gov.HTTP_BINDING_CONTRACT,
                         'tests/p06_call_clock.py',gov.CALL_CLOCK_CONTRACT,'tests/p06_pc026_binding.py','tests/p06_resource_qualification.py',
                         'tests/data/p03_invocations.json','tests/scenarios/full/p06-data-exfiltration.json'):
                original = (root/name).read_bytes()
                ref = fixture.freeze.pop(name); fixture.refs.pop(name); (root/name).unlink()
                try:
                    fixture.refresh(); before = inventory(root)
                    with self.assertRaisesRegex(ev.Pc020EvidenceError,'required resource|entry/import|anchor missing'):
                        gov._load_at(root,synthetic_fixture=True)
                    self.assertEqual(inventory(root),before)
                finally:
                    (root/name).write_bytes(original)
                    fixture.freeze[name] = ref; fixture.refs[name] = ref; fixture.refresh()

    def test_failed_attempt_preserved_without_current_approval(self):
        run, _ = self.attempt()
        report = json.loads((run/'report.json').read_bytes())
        report.update(status='failed',coverage=[],failure={'type':'synthetic-test','message':'failed call'})
        (run/'call-clock.json').unlink()
        (run/'report.json').write_bytes(ev.canonical_json(report)); self.seal(run)
        with patch.object(gov,'load',side_effect=AssertionError('failed attempt must not obtain qualification')):
            receipt = p06_receive.receive(run,self.received)
        self.assertEqual(receipt['status'],'failed')
        self.assertEqual(json.loads((run/'report.json').read_bytes())['coverage'],[])

    def test_runner_current_admission_precedes_run_directory(self):
        run, restore = self.attempt()
        (self.received/'current-restore.json').write_bytes(ev.canonical_json(restore))
        (self.received/'fixture-instance.json').write_bytes((run/'fixture-instance.json').read_bytes())
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(gov,'load',side_effect=self.load))
            for key,value in {'P06_REPORT_ROOT':self.received,'P06_INDEX_PATH':self.root/'tests/data/p06_scenario_index.json',
                              'P05_INDEX_PATH':self.root/'tests/data/p05_scenario_index.json',
                              'SCENARIO_ROOT':self.root/'tests/scenarios',
                              'SCHEMA_PATH':self.root/'tests/scenarios/schema-v1.json',
                              'FIXTURE_SPEC_PATH':self.root/'tests/data/p05_fixture_spec.json'}.items():
                stack.enter_context(patch.object(scenario_runner,key,value))
            from tests import p06_resource_policy
            stack.enter_context(patch.object(p06_resource_policy,'ROOT',self.root))
            # Existing UUID directory makes the real runner stop at its first
            # write attempt. Passing the gate reaches FileExistsError, not HTTP.
            with self.assertRaises(FileExistsError):
                asyncio.run(scenario_runner.run_scenario('p06-compromise-scope',
                    transport='streamable-http', evidence_root=self.received, run_id=restore['run_id']))
        before = inventory(self.received)
        with patch.object(gov,'load',side_effect=ev.Pc020EvidenceError('missing approval')):
            with self.assertRaisesRegex(ev.Pc020EvidenceError,'missing approval'):
                asyncio.run(scenario_runner.run_scenario('p06-compromise-scope',transport='streamable-http'))
        self.assertEqual(inventory(self.received),before)

    @contextlib.contextmanager
    def no_writers(self):
        original = Path.open
        def guarded(path, mode='r', *args, **kwargs):
            if any(flag in mode for flag in ('w','a','x','+')):
                raise AssertionError('rejected receiver attempted a writer: '+str(path))
            return original(path,mode,*args,**kwargs)
        with patch.object(Path,'open',new=guarded):
            yield

    def test_receive_tail_drift_does_not_append_ledger(self):
        run, restore = self.attempt()
        approval = self.root/gov.APPROVAL; original = approval.read_bytes()
        old = p06_aggregate_reports.ledger_identity
        def drift(report):
            value = old(report)
            if report['run_id'] == restore['run_id']:
                self.assertTrue((self.received/'.receive.lock').is_file())
                approval.write_bytes(original+b'\n')
            return value
        before = inventory(self.received)
        try:
            with patch.object(gov,'load',side_effect=self.load), \
                    patch.object(p06_aggregate_reports,'ledger_identity',side_effect=drift), \
                    self.assertRaisesRegex(ev.Pc020EvidenceError,'governance consumption drift'):
                p06_receive.receive(run,self.received)
            self.assertEqual(inventory(self.received),before)
        finally:
            approval.write_bytes(original)

    def test_current_restore_and_receiver_actual_entries(self):
        run, restore = self.attempt()
        with patch.object(gov, 'load', side_effect=self.load):
            self.assertEqual(len(p06_evidence.verify_restore(restore, self.received)), 8)
            (self.received / 'current-restore.json').write_bytes(ev.canonical_json(restore))
            self.assertEqual(scenario_runner.load_current_restore(self.received, restore['run_id']), restore)
            receipt = p06_receive.receive(run, self.received)
            self.assertEqual(receipt['status'], 'success')
            before = inventory(self.received)
            with self.no_writers(), self.assertRaisesRegex(ValueError, 'already received'):
                p06_receive.receive(run, self.received)
            self.assertEqual(inventory(self.received), before)

    def test_restore_identity_negatives_without_writer(self):
        run, restore = self.attempt()
        for changes in ({'canonical_epoch': 7}, {'canonical_schema_version': 5}, {'snapshot_stage':'P05_REPAIR_INITIAL'},
                        {'snapshot_name': profiles.HISTORICAL.snapshot},
                        {'checkpoint_marker': 'Win10MalBox-Velo-Snapshot999.vmsn'},
                        {'restore_records': restore['restore_records'][:-1]}):
            with self.subTest(changes=changes), patch.object(gov, 'load', side_effect=self.load):
                before = inventory(self.received)
                with self.assertRaises((ValueError, ev.Pc020EvidenceError)):
                    p06_evidence.verify_restore({**restore, **changes}, self.received)
                self.assertEqual(inventory(self.received), before)

    def test_missing_approval_and_source_drift_reject_actual_outputs(self):
        run, _ = self.attempt()
        missing = self.root / gov.APPROVAL
        saved = missing.with_suffix('.held')
        missing.rename(saved)
        try:
            before = inventory(self.received)
            with self.no_writers(), patch.object(gov, 'load', side_effect=self.load), self.assertRaises(ev.Pc020EvidenceError):
                p06_receive.receive(run, self.received)
            self.assertEqual(inventory(self.received), before)
        finally:
            saved.rename(missing)
        for path in (self.root / gov.APPROVAL, self.root / 'tests/p06_receive.py'):
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            try:
                before = inventory(self.received)
                for entry in (lambda: p06_receive.receive(run, self.received),
                              p06_aggregate_reports.aggregate, p07_cost_measurement.main,
                              p07_cost_measurement_r232.main):
                    with patch.object(gov, 'load', side_effect=self.load), contextlib.redirect_stdout(io.StringIO()) as output:
                        with self.no_writers(), self.assertRaises(ev.Pc020EvidenceError):
                            entry()
                        self.assertEqual(output.getvalue(), '')
                    self.assertEqual(inventory(self.received), before)
            finally:
                path.write_bytes(original)
                # Source bytes are repaired only in this isolated fixture;
                # original inode/ACL identities remain unchanged.

    def test_carried_committed_and_cross_run_rejected_before_lock(self):
        run, _ = self.attempt()
        receipt = self.received / self.state['activation_evidence']['evidence_path']
        receipt = receipt.parent / 'epoch8-transition-receipt.json'
        original = receipt.read_bytes()
        receipt.write_bytes(original.replace(b'COMMITTED', b'ABORTED'))
        self.seal(run)
        try:
            before = inventory(self.received)
            with self.no_writers(), patch.object(gov, 'load', side_effect=self.load), self.assertRaises(ev.Pc020EvidenceError):
                p06_receive.receive(run, self.received)
            self.assertEqual(inventory(self.received), before)
        finally:
            receipt.write_bytes(original)
        report_path = run / 'report.json'
        report = json.loads(report_path.read_bytes()); report['run_id'] = str(uuid.uuid4())
        report_path.write_bytes(ev.canonical_json(report)); self.seal(run)
        before = inventory(self.received)
        with self.no_writers(), patch.object(gov, 'load', side_effect=self.load), self.assertRaises(ev.Pc020EvidenceError):
            p06_receive.receive(run, self.received)
        self.assertEqual(inventory(self.received), before)

    def test_runner_schema3_refusal_precedes_any_work(self):
        before = inventory(self.received)
        with self.assertRaisesRegex(scenario_runner.ScenarioInputError, 'historical'):
            asyncio.run(scenario_runner.run_scenario('p06-compromise-scope',
                transport='streamable-http', baseline_binding=self.received / 'absent'))
        self.assertEqual(inventory(self.received), before)

    def test_consumption_recheck_detects_selection_drift(self):
        with patch.object(gov, 'load', side_effect=self.load):
            admission = binding.load()
        path = self.received / 'selection-test.json'
        path.write_bytes(b'{}\n'); admission.read(path)
        path.write_bytes(b'[]\n')
        with self.assertRaisesRegex(ev.Pc020EvidenceError, 'consumer input drift'):
            admission.recheck()


if __name__ == '__main__':
    unittest.main()

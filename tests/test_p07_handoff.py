"""Synthetic host 191/five-report graph and actual isolated Git objects.

Fixture construction omits receiver executions and uses a lightweight resource
label builder. Acceptance calls the unchanged real current aggregator; focused
late-predicate tests explicitly reuse its validated result, never a mock positive.
No production READY, completion record, VM operation or cost success is issued.
"""
import contextlib
import copy
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import p07_handoff as handoff
from tests import p05_pc020_evidence as ev
from tests import p05_pc026_governance as gov
from tests import p06_pc026_binding as binding
from tests import p06_aggregate_reports as agg
from tests import p06_package as package
from tests import p06_resource_gate as resources
from tests import p07_cost_measurement as cost, p07_cost_measurement_r232 as cost232
from tests import test_p06_pc026_binding as consumer_fixture
from tests.test_p05_pc026_governance import reference


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('fixture: begin synthetic host 191', flush=True)
        consumer_fixture.CurrentConsumerTests.setUpClass.__func__(cls)
        fixed = cls.root / handoff.ROOT_REL
        fixed.parent.mkdir(parents=True, exist_ok=True)
        cls.received.rename(fixed); cls.received = fixed
        cls.builder = consumer_fixture.CurrentConsumerTests()
        for key in ('root', 'received', 'canonical', 'state', 'A'):
            setattr(cls.builder, key, getattr(cls, key))
        original_zip = zipfile.ZipFile
        def fixture_zip(file, mode='r', compression=zipfile.ZIP_STORED, **kwargs):
            # ZIP encoding is a fixture construction choice; every decompressed
            # original and actual archive byte/size is checked by production.
            if mode == 'x': compression = zipfile.ZIP_DEFLATED
            return original_zip(file, mode, compression, **kwargs)
        with patch.object(zipfile, 'ZipFile', side_effect=fixture_zip):
            cls.qualification = cls.builder.qualification()
        print('fixture: qualification sealed', flush=True)
        budget = json.loads((cls.qualification / 'resource-budget.json').read_bytes())
        def labels(root, scenario, sampler, **kwargs):
            # Test construction only: the positive aggregate rechecks all of
            # these actual policy, qualification, payload and budget originals.
            from tests.p06_resource_policy import load_policy
            with patch('tests.p06_resource_policy.ROOT', cls.root):
                policy = load_policy(scenario)
            identity = {'report_sha256': ev._sha((cls.qualification/'report.json').read_bytes()),
                        'budget_sha256': ev._sha((cls.qualification/'resource-budget.json').read_bytes()),
                        'payload_sha256': ev._sha((cls.qualification/'qualification-payload.zip').read_bytes())}
            gate = SimpleNamespace(budget=budget, identity=identity)
            gate.labels = {key: row['qualification_label'] for key, row in policy.items() if row['class']=='admission'}
            gate.related = dict(gate.labels); gate.deadlines = {}
            for step in scenario['steps']:
                repeat = step.get('repeat_until', {})
                upper = max(60, repeat.get('max_attempts',1)*repeat.get('interval_seconds',0)+60)
                label = policy.get(step['id'],{}).get('qualification_label')
                if label: gate.related[step['id']] = label
                gate.deadlines[step['id']] = max(upper,budget['steps'][label]['deadline_seconds'] if label else upper)
            gate.scenario_seconds = math.ceil(sum(gate.deadlines.values())*1.1)
            return gate
        with patch.object(resources, 'ScenarioResourceGate', side_effect=labels):
            cls.runs = [cls.builder.full_report(s, None) for s in cost.SCENARIOS]
        rows = []
        selected = {}
        for i, run in enumerate(cls.runs, 1):
            report = json.loads((run/'report.json').read_bytes())
            manifest = reference(cls.root, str((run/'package-manifest.json').relative_to(cls.root)))
            row = {'monotonic_attempt': i, 'received_at': report['ended_at'], 'status': report['status'],
                   'scenario': report['scenario'], 'report_relative_path': str((run/'report.json').relative_to(fixed)),
                   'report_sha256': ev._sha((run/'report.json').read_bytes()),
                   'manifest_relative_path': str((run/'package-manifest.json').relative_to(fixed)),
                   'manifest_sha256': manifest['sha256'], 'package_sha256': manifest['sha256'],
                   **agg.ledger_identity(report)}
            rows.append(row)
            selected[report['scenario']] = {k: row[k] for k in ('monotonic_attempt','report_sha256',
                                        'manifest_relative_path','manifest_sha256','package_sha256')}
        (fixed/'接收清单.jsonl').write_bytes(b''.join(ev.canonical_json(row) for row in rows))
        (fixed/'final-selection.json').write_bytes(ev.canonical_json({'schema_version':2,
                         'all_attempts':list(range(1,6)), 'selected':selected, 'rejected':{}}))
        from tests.p06_receive import initialize_history
        initialize_history(fixed)
        print('fixture: five reports/ledger sealed; actual isolated Git', flush=True)
        git_env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        git_env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull)
        def git(*args, input=None):
            return subprocess.run(['git','-C',str(cls.root),*args],env=git_env,input=input,
                                  capture_output=True,check=True).stdout
        git('init','-q')
        # Stage only explicitly frozen code/resources and the two synthetic new
        # record originals. The isolated fixture has no shared repository writes.
        frozen = json.loads((cls.root/gov.FREEZE).read_bytes())['members']
        git('add','--',*[r['path'] for r in frozen])
        cls.record_paths = ['records/new-p06-implementation.md','records/new-p06-independent-check.md']
        for name in cls.record_paths:
            path = cls.root/name;path.parent.mkdir(exist_ok=True)
            path.write_bytes(('synthetic host record: '+name+'\n').encode())
        git('add','--',*cls.record_paths)
        tree = git('write-tree').strip().decode()
        oid = git('-c','user.name=SyntheticFixture','-c','user.email=fixture@example.invalid',
                  'commit-tree',tree,input=b'synthetic fixed handoff fixture\n').strip().decode()
        git('update-ref','HEAD',oid)
        cls.completion = {'schema_version':1,'kind':'pc026-p06-completion-v1','profile_id':gov.PROFILE,
            'workflow_id':ev.WORKFLOW_ID,'approval_ref':reference(cls.root,gov.APPROVAL),
            'implementation_head':oid,'implementation_record':{'ref':reference(cls.root,cls.record_paths[0]),'commit_oid':oid},
            'independent_check_record':{'ref':reference(cls.root,cls.record_paths[1]),'commit_oid':oid},
            'final_selection_ref':reference(cls.root,str((fixed/'final-selection.json').relative_to(cls.root))),
            'status':'ACCEPTED'}
        (cls.root/gov.COMPLETION).write_bytes(ev.canonical_json(cls.completion))
        (cls.root/gov.COMPLETION).chmod(0o600)
        # Build expected aggregate from the synthetic originals, not an
        # aggregation mock. create/verify must independently recompute it.
        reports = [json.loads((run/'report.json').read_bytes()) for run in cls.runs]
        inputs = []
        for row, report, run in zip(rows,reports,cls.runs):
            restore = json.loads((run/'snapshot-evidence.json').read_bytes())['restore']
            inputs.append({k:row[k] for k in ('monotonic_attempt','package_sha256','report_relative_path','report_sha256')} |
                {'restore_attempt_id':restore['restore_attempt_id'],'baseline_binding_sha256':None,
                 'run_id':report['run_id'],'scenario':report['scenario']})
        cls.expected_aggregate = {'schema_version':2,'status':'success','scenario_count':5,'tool_count':129,
            'relation_count':645,'manifest_sha256':ev._sha((cls.root/'tests/data/p06_coverage_manifest.json').read_bytes()),
            'ledger_sha256':ev._sha((fixed/'接收清单.jsonl').read_bytes()),
            'selection_sha256':ev._sha((fixed/'final-selection.json').read_bytes()),
            'tools_schema_sha256':reports[0]['tools_schema_sha256'],'fixture_spec_sha256':reports[0]['fixture_spec_sha256'],
            'distinct_session_count':5,'distinct_restore_attempt_count':5,'distinct_baseline_binding_count':0,
            'runner_lifecycle_count':5,'server_instance_count':len({r['server_identity']['instance_id'] for r in reports}),
            'unexpected_error_count':0,'unexecuted_step_count':0,'inputs':inputs,
            'total_duration_ms':sum(r['duration_ms'] for r in reports)}
        (fixed/'aggregate.json').write_bytes(agg.canonical_bytes(cls.expected_aggregate))
        print('fixture: ready '+str(cls.root), flush=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def admission(self, *, real=False):
        if real:
            return binding._from_group(gov._load_at(self.root, synthetic_fixture=True))
        # Focused downstream predicates reuse an independently qualified stable
        # large graph. Each receives fresh consumer locks; public positive calls
        # and actual isolated loading above/below have no such seam.
        if not hasattr(type(self), 'qualified_base'):
            type(self).qualified_base = self.admission(real=True)
        base = type(self).qualified_base
        group = copy.copy(base.group)
        group.locked = dict(base.group.locked)
        group.consumer_inputs = {}
        return binding.Admission(group, base.canonical, base.bindings)

    def test_00_real_create_and_readonly_verify(self):
        started = time.monotonic()
        with patch.object(gov,'load',side_effect=lambda:gov._load_at(self.root,synthetic_fixture=True)):
            value = handoff.create()
            raw = (self.received/handoff.OUTPUT).read_bytes()
            self.assertEqual(raw, ev.canonical_json(value))
            print('real create complete: seconds='+str(time.monotonic()-started)+
                  ' members='+str(len(value['members'])),flush=True)
            before = (self.received/handoff.OUTPUT).stat()
            self.assertEqual(handoff.verify(),value)
            self.assertEqual((self.received/handoff.OUTPUT).read_bytes(),raw)
            self.assertEqual((self.received/handoff.OUTPUT).stat(),before)
        self.assertEqual(len(value),15)
        self.assertEqual(len(value['consumed_selection']),5)
        self.assertNotIn(gov.COMPLETION,{r['path'] for r in value['members']})
        self.assertEqual(len(value['members']),len({r['path'] for r in value['members']}))
        for r in value['members']:
            self.assertEqual(reference(self.root,r['path']),r)
        type(self).validated = value
        (self.received/handoff.OUTPUT).unlink()  # test-only reset between cases
        print('real readonly verify complete: seconds='+str(time.monotonic()-started),flush=True)

    @contextlib.contextmanager
    def change(self,path,raw):
        original=path.read_bytes();path.write_bytes(raw)
        try: yield
        finally: path.write_bytes(original)

    def reject(self,pattern, *, cached=False, real=False):
        self.assertFalse((self.received/handoff.OUTPUT).exists())
        with contextlib.ExitStack() as stack:
            if cached:
                stack.enter_context(patch.object(agg,'_aggregate_current',return_value=copy.deepcopy(self.expected_aggregate)))
            with self.assertRaisesRegex((ValueError,KeyError,OSError),pattern):
                handoff._use(self.admission(real=real),create=True)
        self.assertFalse((self.received/handoff.OUTPUT).exists())

    def test_10_governance_completion_git_and_private_gates(self):
        path=self.root/gov.APPROVAL;held=path.with_suffix('.held');path.rename(held)
        try:self.reject('safe governance read',real=True)
        finally:held.rename(path)
        path=self.root/gov.COMPLETION;held=path.with_suffix('.held');path.rename(held)
        try:self.reject('safe governance read')
        finally:held.rename(path)
        for changes,pattern in [({'schema_version':True},'exact model'),({'extra':1},'exact model'),
             ({'profile_id':'pc020-snapshot189-v1'},'profile/workflow'),
             ({'final_selection_ref':reference(self.root,gov.APPROVAL)},'approval/selection'),
             ({'implementation_head':'0'*40},'Command'),
             ({'independent_check_record':self.completion['implementation_record']},'distinct new')]:
            with self.subTest(changes=changes),self.change(path,ev.canonical_json(self.completion|changes)):
                # nonexistent OID raises CalledProcessError, separately below
                if changes.get('implementation_head')=='0'*40:
                    with self.assertRaises(subprocess.CalledProcessError):handoff._use(self.admission(),create=True)
                else:self.reject(pattern)
        duplicate=ev.canonical_json(self.completion).replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1')
        with self.change(path,duplicate):self.reject('duplicate')
        # Old canonical 189 is rejected by real fixed current qualification.
        canonical=self.root/gov.CANONICAL
        state=json.loads(canonical.read_bytes());state['active_snapshot']['name']='Snapshot 189-Velociraptor-MCP可恢复验收基线'
        with self.change(canonical,ev.canonical_json(state)):
            self.reject('canonical|snapshot|191|active|allowlist',real=True)
        # Restoring mutable canonical bytes changes its metadata; qualify a new
        # base rather than pretending the previous identity lock survived.
        if hasattr(type(self), 'qualified_base'): del type(self).qualified_base
        original_mode=path.stat().st_mode;path.chmod(0o666)
        try:self.reject('owner/ACL')
        finally:path.chmod(original_mode & 0o777)
        record=self.root/self.record_paths[0]
        with self.change(record,b'wrong Git bytes\n'):
            changed=copy.deepcopy(self.completion);changed['implementation_record']['ref']=reference(self.root,self.record_paths[0])
            with self.change(path,ev.canonical_json(changed)):self.reject('Git blob.*differ')
        freeze_ref=next(iter(self.admission().group.freeze_refs.values()))
        bad=dict(freeze_ref);bad['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'Git blob bytes differ'):
            handoff._git_ref(self.root,self.completion['implementation_head'],bad)
        self.assertFalse((self.received/handoff.OUTPUT).exists())
        # HEAD may advance for an unrelated record; the approved implementation
        # commit's complete freeze tree remains the only implementation source.
        git_env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        git_env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull)
        def git(*args,input=None):
            return subprocess.run(['git','-C',str(self.root),*args],env=git_env,input=input,
                                  capture_output=True,check=True).stdout
        followup=self.root/'records/unrelated-followup.md';followup.write_bytes(b'synthetic unrelated followup\n')
        git('add','--','records/unrelated-followup.md');tree=git('write-tree').strip().decode()
        newer=git('-c','user.name=SyntheticFixture','-c','user.email=fixture@example.invalid',
                  'commit-tree',tree,'-p',self.completion['implementation_head'],
                  input=b'synthetic unrelated followup\n').strip().decode()
        git('update-ref','HEAD',newer)
        self.assertNotEqual(newer,self.completion['implementation_head'])
        admission=self.admission()
        handoff._completion(admission,reference(self.root,str((self.received/'final-selection.json').relative_to(self.root))))
        self.assertNotIn(gov.COMPLETION,admission.group.allowed)
        self.assertNotIn(gov.COMPLETION,admission.group.freeze_refs)

    def test_20_focused_closure_selection_and_drift(self):
        # The successful real graph/result above is reused only at this late
        # aggregate boundary. No negative claims full aggregation was repeated.
        path=self.received/'aggregate.json'
        with self.change(path,agg.canonical_bytes(self.expected_aggregate|{'total_duration_ms':999})):
            self.reject('aggregate original bytes',cached=True)
        qualification=self.received/'resource-qualification-selection.json'
        q=json.loads(qualification.read_bytes());q['report_relative_path']='../escape/report.json'
        with self.change(qualification,ev.canonical_json(q)):self.reject('unsafe|relative|escape',cached=True)
        path=self.qualification/'resource-budget.json';held=path.with_suffix('.held');path.rename(held)
        try:self.reject('member set|inventory|missing|unsafe',cached=True)
        finally:held.rename(path)
        path=self.runs[0]/'tools-schema.json';held=path.with_suffix('.held');path.rename(held)
        try:self.reject('member set|inventory|missing|unsafe',cached=True)
        finally:held.rename(path)
        path=self.runs[0]/'tools-schema.json';held=path.with_suffix('.held');path.rename(held);path.symlink_to(held)
        try:self.reject('link|plain|regular',cached=True)
        finally:path.unlink();held.rename(path)
        for key in ('run_id','restore_attempt_id'):
            data=copy.deepcopy(self.expected_aggregate);data['inputs'][0][key]=data['inputs'][1][key]
            with self.change(self.received/'aggregate.json',agg.canonical_bytes(data)), \
                    patch.object(agg,'_aggregate_current',return_value=data):
                self.reject('path/run|run/restore')
        original=agg._aggregate_current
        path=self.root/gov.COMPLETION
        def drift(admission):
            value=copy.deepcopy(self.expected_aggregate)
            path.write_bytes(path.read_bytes()+b'\n')
            return value
        saved=path.read_bytes()
        try:
            with patch.object(agg,'_aggregate_current',side_effect=drift):self.reject('consumer input drift')
        finally:path.write_bytes(saved)

    def test_30_output_conflict_idempotence_and_tail_residual(self):
        with patch.object(agg,'_aggregate_current',return_value=copy.deepcopy(self.expected_aggregate)):
            value=handoff._use(self.admission(),create=True)
            path=self.received/handoff.OUTPUT;raw=path.read_bytes();info=path.stat()
            self.assertEqual(handoff._use(self.admission(),create=True),value)
            self.assertEqual(path.stat(),info)
            with self.change(path,raw+b'\n'):
                before=path.read_bytes()
                with self.assertRaisesRegex(ValueError,'conflicts'):handoff._use(self.admission(),create=True)
                self.assertEqual(path.read_bytes(),before)
            path.unlink()
            admission=self.admission();old_read=admission.read
            completion=self.root/gov.COMPLETION;saved=completion.read_bytes()
            def tail(target):
                data=old_read(target)
                if target==path:completion.write_bytes(saved+b'\n')
                return data
            try:
                with patch.object(admission,'read',side_effect=tail),self.assertRaisesRegex(ValueError,'consumer input drift'):
                    handoff._use(admission,create=True)
                self.assertTrue(path.exists())
                residual=path.read_bytes()
                # The residual never qualifies while the consumed completion drifts.
                with self.assertRaises(ValueError):handoff._use(self.admission(),create=False)
                self.assertEqual(path.read_bytes(),residual)
            finally:completion.write_bytes(saved);path.unlink()

    def test_40_two_cost_entries_read_only_and_refuse_collector(self):
        with patch.object(handoff,'verify',return_value=getattr(self,'validated',{})) as verify:
            for entry in (cost.main,cost232.main):
                with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaisesRegex(ValueError,'upstream|historical'):
                    entry()
                self.assertEqual(output.getvalue(),'')
            self.assertEqual(verify.call_count,2)
        with patch.object(handoff,'verify',side_effect=ValueError('missing fixed handoff')):
            for entry in (cost.main,cost232.main):
                with self.assertRaisesRegex(ValueError,'missing fixed handoff'):entry()

    def test_50_actual_frozen_isolated_load(self):
        code='''
import sys,json
from pathlib import Path
root=Path(sys.argv[1]);original=Path(sys.argv[2]);sys.path.insert(0,str(root))
def audit(event,args):
 if event=='open' and isinstance(args[0],(str,bytes)):
  path=Path(args[0]).absolute()
  if path.is_relative_to(original) and not (path.is_relative_to(root) or path.is_relative_to(original/'.venv')):
   raise AssertionError('escaped frozen tree: '+str(path))
sys.addaudithook(audit)
from tests import p07_handoff, p07_cost_measurement, p07_cost_measurement_r232, test_p07_handoff, p06_call_clock
from tests import p05_pc026_governance as gov
from tests import p06_pc026_binding as binding
admission=binding.load()
assert gov.HANDOFF_CONTRACT in admission.group.freeze_refs
assert gov.CALL_CLOCK_CONTRACT in admission.group.freeze_refs
assert 'tests/p06_call_clock.py' in admission.group.freeze_refs
assert 'tests/test_p06_call_clock.py' in admission.group.freeze_refs
assert 'tests/test_p07_handoff.py' in admission.group.freeze_refs
p07_handoff._completion(admission,p07_handoff._ref(admission,root/p07_handoff.ROOT_REL/'final-selection.json'))
modules={}
for name,module in tuple(sys.modules.items()):
 if name=='tests' or name.startswith(('tests.','velo_transfer','velociraptor_')):
  path=Path(module.__file__).resolve();assert path.is_relative_to(root),(name,path)
  coordinate=path.relative_to(root).as_posix();assert coordinate in admission.group.freeze_refs,(name,coordinate)
  modules[name]=coordinate
admission.recheck()
print(json.dumps({'frozen_load':True,'modules':modules,'contract':gov.HANDOFF_CONTRACT}))
'''
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(self.root),str(gov.REPOSITORY)],
                              cwd=self.root,capture_output=True,text=True,timeout=180)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['frozen_load'])
        print('isolated load: '+result.stdout.strip(),flush=True)


if __name__=='__main__':unittest.main()

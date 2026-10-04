"""Actual complete isolated governance loader graph, synthetic MODEL identities."""
import copy
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import velociraptor_observation_config as cfg
import velociraptor_observation_attempts as a
from tests import p05_pc026_governance as gov
from tests.test_p05_pc026_governance import ApprovalFixture, write, reference, inventory
from tests.test_observation_attempts import configuration, ArchiveFS, budgets, INSTANCE
from tests.test_observation_windows import ROOT

@unittest.skipUnless(os.name=='posix','POSIX actual governance fixture')
class ConfigurationGraphTests(unittest.TestCase):
    def setUp(self):
        bootstrap=os.environ.get('PC026_BOOTSTRAP_FIXTURE_ROOT')
        if not bootstrap:raise RuntimeError('verified 448+4 bootstrap input required')
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT'));self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.f=ApprovalFixture(self.root,Path(bootstrap))
        model=configuration(ArchiveFS());sdpath=gov.BASE+'namespace-root.sd'
        (self.root/sdpath).write_bytes(model.root_sd);self.f.refs[sdpath]=reference(self.root,sdpath)
        rootdoc=dict(schema_version=1,kind='pc026-observation-namespace-root-v1',profile_id=gov.PROFILE,workflow_id=gov.evidence.WORKFLOW_ID,root=str(ROOT),identity=model.document['root_identity'],sd_ref=self.f.refs[sdpath])
        self.f.refs[cfg.ROOT_RECORD]=write(self.root,cfg.ROOT_RECORD,rootdoc)
        self.doc=dict(schema_version=1,kind='pc026-observation-archive-configuration-v1',profile_id=gov.PROFILE,workflow_id=gov.evidence.WORKFLOW_ID,contract_ref=cfg.CONTRACT_REF,deployment_ref=self.f.refs[gov.DEPLOYMENT],implementation_freeze_ref=self.f.refs[gov.FREEZE],guest_namespace_root=str(ROOT),root_identity=model.document['root_identity'],budgets=budgets(),retention='KEEP_ALL_NO_AUTO_RECOVERY',status='AUTHORIZED')
        self.bind()
    def bind(self):self.f.refs[cfg.CONFIG]=write(self.root,cfg.CONFIG,self.doc);self.f.runtime()
    def load(self):
        with patch.object(gov,'REPOSITORY',self.root):return cfg.load_approved()
    def refuse_no_writer(self):
        before=inventory(self.root)
        with patch.object(a,'WindowsDirectoryAllocator') as writer,patch.object(gov,'REPOSITORY',self.root),self.assertRaises(Exception):a.ArchiveAttemptLedger.open_approved(INSTANCE)
        writer.assert_not_called();self.assertEqual(inventory(self.root),before)
    def test_actual_fixed_loader_keeps_owned_group_and_input_outside_freeze(self):
        before=inventory(self.root);config=self.load()
        self.assertEqual(config.document,self.doc);self.assertFalse(config.group.synthetic_fixture)
        self.assertTrue({cfg.CONFIG,cfg.ROOT_RECORD}.isdisjoint(config.group.freeze_refs));config.group.recheck();config.group.close()
        self.assertEqual(inventory(self.root),before)
        self.assertEqual(set(inspect.signature(a.ArchiveAttemptLedger.open_approved).parameters),{'instance_id'})
        self.assertFalse(inspect.signature(cfg.load_approved).parameters)
    def test_exact_config_negative_matrix_and_strong_pending_boundary(self):
        mutations=[lambda d:d.update(extra=1),lambda d:d.update(schema_version=True),lambda d:d['root_identity'].update(principal_sid='S-1-5-18'),lambda d:d.update(guest_namespace_root=r'C:\other'),lambda d:d['budgets'].update(max_total_archive_bytes=446463),lambda d:d['budgets'].update(max_active=True),lambda d:d['contract_ref'].update(sha256='0'*64),lambda d:d['implementation_freeze_ref'].update(sha256='0'*64)]
        original=copy.deepcopy(self.doc)
        for mutation in mutations:
            self.doc=copy.deepcopy(original);mutation(self.doc);self.bind()
            with self.subTest(mutation=mutation):self.refuse_no_writer()
    def test_missing_approval_drift_ref_and_future_ref_refuse_before_writer(self):
        original=(self.root/gov.APPROVAL).read_bytes();(self.root/gov.APPROVAL).unlink();self.refuse_no_writer();(self.root/gov.APPROVAL).write_bytes(original)
        (self.root/cfg.CONFIG).write_bytes(b'{}\n');self.refuse_no_writer();self.bind()
        self.f.refs['MODEL/future.json']=dict(path='MODEL/future.json',size=1,sha256='0'*64);self.f.runtime();self.refuse_no_writer()
    def test_every_new_closure_member_omission_rebound_refuses(self):
        paths=[cfg.CONTRACT,'velociraptor_observation_attempts.py','velociraptor_observation_catalog.py','velociraptor_observation_config.py','tests/test_observation_attempts.py','tests/test_observation_catalog.py','tests/test_observation_config.py','tests/test_velociraptor_observation.py','README.md','agent_poc/README.md',*[p for p in gov.RESOURCES if p.startswith('PLAN/2026.10.03-') and any('-'+v+'-' in p for v in ('08','09','10','11'))]]
        for path in paths:
            saved=self.f.freeze.pop(path);self.f.refresh();self.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE];self.bind()
            with self.subTest(path=path):self.refuse_no_writer()
            self.f.freeze[path]=saved
        self.f.freeze[cfg.CONFIG]=self.f.refs[cfg.CONFIG];self.f.refresh();self.doc['implementation_freeze_ref']=self.f.refs[gov.FREEZE];self.bind();self.refuse_no_writer()
    def test_isolated_actual_imports_and_governance_loading(self):
        code="""import sys
from pathlib import Path
root=Path(sys.argv[1]);original=Path(sys.argv[2]);sys.path.insert(0,str(root))
def audit(event,args):
 if event=='open' and isinstance(args[0],(str,bytes)):
  p=Path(args[0])
  if not p.is_absolute():return
  if p.is_relative_to(original) and not (p.is_relative_to(root) or p.is_relative_to(original/'.venv')):raise AssertionError('escaped isolated source')
sys.addaudithook(audit)
import velociraptor_observation_attempts,velociraptor_observation_catalog,velociraptor_observation_config as c
from tests import test_observation_attempts,test_observation_catalog,test_observation_config
v=c.load_approved();v.group.recheck();v.group.close();print('ISOLATED_MODEL_LOADER_OK')
"""
        p=subprocess.run([sys.executable,'-I','-B','-c',code,str(self.root),str(gov.REPOSITORY)],capture_output=True,text=True,timeout=60)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr);self.assertIn('ISOLATED_MODEL_LOADER_OK',p.stdout)
    def test_fixed_ledger_open_through_whole_real_loader_graph_model_native_only(self):
        from tests.test_observation_windows import session
        from tests.test_observation_attempts import ArchiveFS, key
        import velociraptor_observation_namespace as n
        import velociraptor_observation_windows as w
        fs=ArchiveFS()
        with patch.object(gov,'REPOSITORY',self.root),patch.object(n,'_session',side_effect=lambda:session(fs)),patch.object(n,'_directory_api',return_value=fs),patch.object(w,'_session',side_effect=lambda:session(fs)),patch.object(w,'_writer_api',return_value=fs),patch.object(a,'WindowsSession',side_effect=lambda:session(fs)):
            l=a.ArchiveAttemptLedger.open_approved(INSTANCE)
            lease=l.begin(key(),'tool','a'*64);j=l.accept(lease);p=j.parent();j.claim(object(),p['key'],p['tool'],p['arguments_sha256']);j.seal('returned');j.close();l.finish(lease,'returned');l.close()
            self.assertFalse(fs.handles)
            rows=[row['data'] for path,row in sorted(fs.nodes.items()) if path.startswith(str(l._catalog_dir.path)+'\\') and path.endswith('.json')]
            self.assertEqual(l._config.catalog_codec.verify(rows)['status'],'CLOSED_KNOWN')

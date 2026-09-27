"""Real OS subprocess/flock/fsync/signal tests against isolated fake vmrun only."""
import datetime,hashlib,json,os,signal,subprocess,sys,tempfile,time,unittest,uuid
from pathlib import Path
HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
from tests import host_safety_guard as guard
from tests import host_safety_units as units

class HostGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=HERE,prefix='fake-guard-')
        self.dir=Path(self.tmp.name);self.state=self.dir/'state';self.state.mkdir(mode=0o700)
        self.vmx=self.dir/'fake.vmx';self.vmx.write_bytes(b'fake-vmx')
        self.canonical=self.dir/'canonical.json'
        self.canonical.write_bytes(guard.encoded({'epoch':7,'phase':'PREPARATION_BASELINE',
            'active_snapshot':{'name':'Approved-Current-Snapshot'}}))
        self.fake_state=self.dir/'vmrun-state.json';self.log=self.dir/'vmrun-log.jsonl'
        self.id=str(uuid.uuid4());self.name='Snapshot G14-SAFETY-'+self.id
        self.fake_state.write_text(json.dumps({'vmx':str(self.vmx),'running':True,'snapshots':[],
            'base_snapshots':['Baseline-A','Baseline-B','Baseline-C'],'reverts':0}))
        self.manifest=self.dir/'manifest.json'
        self.decision=self.dir/'approval.json'
        self.external=self.dir/'external-qualification.json'
        self.m={'schema_version':1,'kind':'velo-g14-safety-guard-v1','attempt_id':self.id,'test_mode':True,
            'vmx':str(self.vmx),'vmx_sha256':guard.digest(self.vmx.read_bytes()),
            'vmx_device':self.vmx.stat().st_dev,'vmx_inode':self.vmx.stat().st_ino,
            'vmrun_path':str(HERE/'fake_vmrun_guard.py'),'vmrun_target':None,'canonical_path':str(self.canonical),
            'canonical_sha256':guard.digest(self.canonical.read_bytes()),
            'epoch7_active_snapshot_name':'Approved-Current-Snapshot','epoch7_phase':'PREPARATION_BASELINE','state_dir':str(self.state),
            'checkpoint_name':self.name,'deadline_utc':'2000-01-01T00:00:00Z','min_free_bytes':0,
            'vmrun_timeout_seconds':1,'approved_guest_collector_sha256':'a'*64,
            'interpreter_path':sys.executable,'interpreter_sha256':guard.digest(Path(sys.executable).read_bytes()),
            'vmrun_sha256':guard.digest((HERE/'fake_vmrun_guard.py').read_bytes()),
            'code_sha256':guard.digest((HERE/'host_safety_guard.py').read_bytes()),
            'installer_sha256':guard.digest((HERE/'host_safety_units.py').read_bytes()),
            'controller_install_path':str(HERE/'host_safety_guard.py'),
            'unit_service_path':str(self.dir/'review.service'),
            'unit_timer_path':str(self.dir/'review.timer'),
            'retention':'KEEP_UNTIL_SEPARATE_DELETE_APPROVAL','max_actions':8,
            'approval_decision_sha256':'b'*64,'approval_decision_path':str(self.decision),
            'authorized_actions':['bootstrap','qualify','confirm-guest','arm','deadline','commit']}
        self.seal()
        self.env=dict(os.environ,FAKE_VMRUN_STATE=str(self.fake_state),FAKE_VMRUN_LOG=str(self.log))
    def tearDown(self):self.tmp.cleanup()
    def seal(self):
        decision={'kind':'velo-g14-safety-approval-v1','status':'APPROVED','attempt_id':self.id,
                  'vmx':str(self.vmx),'vmx_sha256':self.m['vmx_sha256'],
                  'checkpoint_name':self.name,'actions':self.m['authorized_actions'],
                  'manifest_binding':guard.approval_binding(self.m)}
        self.decision.write_bytes(guard.encoded(decision))
        self.m['approval_decision_sha256']=guard.digest(self.decision.read_bytes())
        self.manifest.write_bytes(guard.encoded(self.m));self.approval=guard.digest(self.manifest.read_bytes())
    def run_guard(self,command,*,env=None,expect=0):
        cmd=[sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),'--approval-sha',self.approval,command]
        if command in ('confirm-guest','commit','finish-rehearsal') and self.external.exists():
            cmd+=['--external-decision',str(self.external),'--external-sha',guard.digest(self.external.read_bytes())]
        proc=subprocess.run(cmd,env=env or self.env,capture_output=True,text=True,timeout=12)
        self.assertEqual(proc.returncode,expect,(command,proc.stdout,proc.stderr));return proc
    def external_approval(self,kind,scope,receipt):
        decision={'kind':kind,'status':'APPROVED','attempt_id':self.id,'vmx':str(self.vmx),
                  'checkpoint_name':self.name,'collector_sha256':'a'*64,
                  'receipt_sha256':guard.digest(receipt.read_bytes()),'scope':scope}
        self.external.write_bytes(guard.encoded(decision))
    def calls(self):return [json.loads(x)['action'] for x in self.log.read_text().splitlines()] if self.log.exists() else []
    def prepared(self):
        self.run_guard('bootstrap');self.run_guard('qualify')
        receipt={'kind':'velo-g14-guest-reentry-v1','attempt_id':self.id,'checkpoint_name':self.name,
                 'vmx':str(self.vmx),'collector_sha256':'a'*64,
                 'service_and_frontend_healthy':True,'secrets_file_readback':True,
                 'management_reentry_original_sha256':'c'*64,'health_original_sha256':'d'*64,
                 'secrets_readback_original_sha256':'e'*64}
        path=self.state/'guest-reentry.json';path.write_bytes(guard.encoded(receipt));path.chmod(0o600)
        self.external_approval('velo-g14-guest-qualification-approval-v1','GUEST_REENTRY_ONLY',path)
        self.run_guard('confirm-guest');self.run_guard('arm')
    def finish_health(self):
        receipt={'kind':'velo-g14-safety-finish-health-v1','attempt_id':self.id,
                 'checkpoint_name':self.name,'vmx':str(self.vmx),'collector_sha256':'a'*64,
                 'service_and_frontend_healthy':True,'secrets_file_readback':True,
                 'management_reentry_original_sha256':'c'*64,'health_original_sha256':'d'*64,
                 'secrets_readback_original_sha256':'e'*64}
        path=self.state/'safety-finish-health.json';path.write_bytes(guard.encoded(receipt));path.chmod(0o600)
        self.external_approval('velo-g14-safety-finish-approval-v1','SAFETY_REHEARSAL_FINISH_ONLY',path)
        return path
    def test_safety_rehearsal_finish_is_independent_terminal_state(self):
        self.prepared();self.finish_health()
        canonical_before=self.canonical.read_bytes();before=self.calls().count('revertToSnapshot')
        self.run_guard('finish-rehearsal')
        state=guard.read(self.state/'state.json')
        self.assertEqual(state['status'],'SAFETY_REHEARSAL_COMPLETE')
        self.assertTrue(state['timer_disarm_eligible'])
        self.assertEqual(guard.read(self.state/'safety-finish-receipt.json')['epoch7_canonical_sha256'],
                         self.m['canonical_sha256'])
        self.assertEqual(self.canonical.read_bytes(),canonical_before)
        self.run_guard('deadline');self.run_guard('deadline');self.run_guard('finish-rehearsal')
        self.run_guard('commit',expect=3)
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_safety_finish_needs_independent_health_approval_and_epoch7(self):
        self.prepared();self.finish_health();self.external.unlink()
        self.run_guard('finish-rehearsal',expect=3)
        self.assertFalse((self.state/'safety-finish-receipt.json').exists())
        self.finish_health();self.canonical.write_bytes(b'{"epoch":8}')
        self.run_guard('finish-rehearsal',expect=3)
        self.assertFalse((self.state/'safety-finish-receipt.json').exists())
    def test_finish_receipt_crash_gap_blocks_deadline_revert(self):
        self.prepared();self.finish_health();before=self.calls().count('revertToSnapshot')
        self.run_guard('finish-rehearsal',env=dict(self.env,FAKE_GUARD_CRASH_AFTER_FINISH_RECEIPT='1'),expect=97)
        self.assertEqual(guard.read(self.state/'state.json')['status'],'ARMED')
        self.run_guard('deadline')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
        self.run_guard('finish-rehearsal')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'SAFETY_REHEARSAL_COMPLETE')
    def test_bootstrap_separate_from_qualification(self):
        self.run_guard('bootstrap')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'CREATED_UNQUALIFIED')
        self.run_guard('arm',expect=3)
        self.assertNotIn('revertToSnapshot',self.calls())
        self.run_guard('qualify')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        self.run_guard('arm',expect=3)
    def test_native_style_indented_tree_and_running_restore(self):
        row=json.loads(self.fake_state.read_text())
        row['indented_tree']=True;row['running_after_revert']=True
        self.fake_state.write_text(json.dumps(row))
        self.run_guard('bootstrap');self.run_guard('qualify')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        self.assertNotIn('start',self.calls())
        self.assertEqual(self.calls().count('revertToSnapshot'),1)
    def test_snapshot_tree_and_running_list_reject_malformed_or_duplicate(self):
        with self.assertRaises(guard.GuardError):
            guard.snapshot_names('Total snapshots: 1\n\tX\n\tX\n')
        self.assertEqual(guard.snapshot_names('Total snapshots: 2\nX\n\tY\n'),['X','Y'])
        with self.assertRaises(guard.GuardError):
            guard.running_count('Total running VMs: 1\nX\nX\n','X')
    def test_deadline_and_repeat(self):
        self.prepared();before=self.calls().count('revertToSnapshot')
        self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        self.run_guard('deadline');self.assertEqual(self.calls().count('revertToSnapshot'),before+1)
        self.assertEqual(guard.read(self.state/'state.json')['pending_operation'],None)
        self.assertGreater(len(list((self.state/'events').glob('*.json'))),5)
    def test_missing_image_fails_before_revert(self):
        self.prepared();value=json.loads(self.fake_state.read_text());value['snapshots']=[];self.fake_state.write_text(json.dumps(value))
        before=self.calls().count('revertToSnapshot');self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_vmx_drift_fails_before_revert(self):
        self.prepared();before=self.calls().count('revertToSnapshot')
        self.vmx.write_bytes(b'changed-vmx')
        self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_missing_persistent_lock_refuses_without_vmrun(self):
        self.prepared();before=len(self.calls())
        (self.state/'controller.lock').unlink()
        self.run_guard('deadline',expect=3)
        self.assertEqual(len(self.calls()),before)
    def test_action_budget_exhaustion_refuses_recovery(self):
        self.prepared();before=self.calls().count('revertToSnapshot')
        state=guard.read(self.state/'state.json');state['action_count']=8
        (self.state/'state.json').write_bytes(guard.encoded(state))
        self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_unknown_vmrun_does_not_repeat(self):
        self.prepared();before=self.calls().count('revertToSnapshot')
        self.run_guard('deadline',env=dict(self.env,FAKE_VMRUN_TIMEOUT='1'))
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.run_guard('deadline');self.assertEqual(self.calls().count('revertToSnapshot'),before+1)
    def test_controller_crash_and_reboot_style_resume(self):
        self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            os.kill(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
            self.run_guard('deadline')
            self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_live_held_lock_exact_owner_takeover(self):
        self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            self.run_guard('deadline')
            proc.wait(timeout=3)
            self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_predeadline_does_not_take_over_controller(self):
        self.m['deadline_utc']='2999-01-01T00:00:00Z';self.seal();self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            self.run_guard('deadline');self.assertIsNone(proc.poll())
            self.assertEqual(guard.read(self.state/'state.json')['status'],'ARMED')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_pending_operation_held_lock_refuses_takeover(self):
        self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            state=guard.read(self.state/'state.json');state['pending_operation']='revertToSnapshot'
            (self.state/'state.json').write_bytes(guard.encoded(state))
            self.run_guard('deadline',expect=3);self.assertIsNone(proc.poll())
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_wrong_owner_identity_refuses_takeover(self):
        self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            owner=guard.read(self.state/'owner.json');owner['identity']['start_tick']+=1
            (self.state/'owner.json').write_bytes(guard.encoded(owner))
            self.run_guard('deadline',expect=3);self.assertIsNone(proc.poll())
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_commit_preempts_deadline(self):
        self.prepared()
        receipt={'kind':'velo-g14-commit-qualification-v1','attempt_id':self.id,'collector_sha256':'a'*64,
                 'epoch8_committed':True,'guest_and_host_healthy':True,
                 'epoch8_canonical_sha256':'0'*64,'transition_receipt_sha256':'1'*64,
                 'vmx':str(self.vmx),'active_snapshot_name':'Approved-Business-Snapshot',
                 'guest_health_original_sha256':'2'*64,'host_health_original_sha256':'3'*64}
        canonical={'epoch':8,'phase':'NETWORK_ACTIVE','active_snapshot':{'name':'Approved-Business-Snapshot'}}
        self.canonical.write_bytes(guard.encoded(canonical));receipt['epoch8_canonical_sha256']=guard.digest(self.canonical.read_bytes())
        path=self.state/'commit-qualification.json';path.write_bytes(guard.encoded(receipt));path.chmod(0o600)
        self.external_approval('velo-g14-commit-approval-v1','EPOCH8_COMMIT_ONLY',path)
        before=self.calls().count('revertToSnapshot');self.run_guard('commit');self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'COMMITTED')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_missing_approval_fail_closed(self):
        self.decision.unlink();self.run_guard('bootstrap',expect=3)
        self.assertFalse(self.log.exists())
    def test_tampered_approval_and_manifest_refuse_without_vmrun(self):
        self.decision.write_bytes(b'{}')
        self.run_guard('bootstrap',expect=3)
        self.assertFalse(self.log.exists())
        self.seal()
        self.m['vmx_sha256']='0'*64
        self.manifest.write_bytes(guard.encoded(self.m))
        self.run_guard('bootstrap',expect=3)
        self.assertFalse(self.log.exists())
    def test_duplicate_manifest_json_refused_before_vmrun(self):
        raw=self.manifest.read_bytes().replace(b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',1)
        self.manifest.write_bytes(raw);self.approval=guard.digest(raw)
        self.run_guard('bootstrap',expect=3)
        self.assertFalse(self.log.exists())
    def test_check_does_not_create_state_root(self):
        self.state.rmdir()
        self.run_guard('check')
        self.assertFalse(self.state.exists())
        self.assertFalse(self.log.exists())
    def test_guest_receipt_cannot_self_qualify(self):
        self.run_guard('bootstrap');self.run_guard('qualify')
        path=self.state/'guest-reentry.json'
        path.write_bytes(guard.encoded({'kind':'velo-g14-guest-reentry-v1','attempt_id':self.id,
            'checkpoint_name':self.name,'vmx':str(self.vmx),'collector_sha256':'a'*64,
            'service_and_frontend_healthy':True,'secrets_file_readback':True,
            'management_reentry_original_sha256':'c'*64,'health_original_sha256':'d'*64,
            'secrets_readback_original_sha256':'e'*64}))
        path.chmod(0o600)
        self.run_guard('confirm-guest',expect=3)
        self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
        self.external_approval('velo-g14-guest-qualification-approval-v1','GUEST_REENTRY_ONLY',path)
        receipt=guard.read(path);receipt['health_original_sha256']='0'*64
        path.write_bytes(guard.encoded(receipt))
        self.external_approval('velo-g14-guest-qualification-approval-v1','GUEST_REENTRY_ONLY',path)
        self.run_guard('confirm-guest',expect=3)
        self.assertEqual(guard.read(self.state/'state.json')['status'],'HOST_RESTORED_PENDING_GUEST')
    def test_pending_commit_prevents_deadline_revert(self):
        self.prepared()
        before=self.calls().count('revertToSnapshot')
        state=guard.read(self.state/'state.json');state['pending_operation']='commit'
        (self.state/'state.json').write_bytes(guard.encoded(state))
        self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def assert_restore_crash_is_not_replayed(self,point):
        self.prepared();before=self.calls().count('revertToSnapshot')
        self.run_guard('deadline',env=dict(self.env,FAKE_GUARD_CRASH_RESTORE_AT=point),expect=98)
        crashed=guard.read(self.state/'state.json')
        self.assertEqual(crashed['status'],'ARMED')
        self.assertNotEqual(crashed['restore_transaction']['stage'],'COMPLETE')
        after=self.calls().count('revertToSnapshot')
        self.assertIn(after-before,(0,1))
        self.run_guard('deadline')
        self.assertEqual(guard.read(self.state/'state.json')['status'],'INDETERMINATE')
        self.run_guard('deadline')
        self.assertEqual(self.calls().count('revertToSnapshot'),after)
    def test_qualification_crash_does_not_replay_revert(self):
        self.run_guard('bootstrap')
        self.run_guard('qualify',env=dict(self.env,FAKE_GUARD_CRASH_RESTORE_AT='after_revert_response'),expect=98)
        before=self.calls().count('revertToSnapshot')
        self.run_guard('qualify',expect=3)
        self.assertEqual(self.calls().count('revertToSnapshot'),before)
    def test_held_lock_open_restore_transaction_is_not_signalled(self):
        self.prepared()
        proc=subprocess.Popen([sys.executable,str(HERE/'host_safety_guard.py'),'--manifest',str(self.manifest),
             '--approval-sha',self.approval,'hold','--hold-seconds','10'],env=self.env,
             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if (self.state/'owner.json').exists() and guard.read(self.state/'owner.json')['identity']['pid']==proc.pid:break
                time.sleep(.05)
            state=guard.read(self.state/'state.json')
            state['restore_transaction']={'id':'test-open','stage':'BEFORE_REVERT'}
            (self.state/'state.json').write_bytes(guard.encoded(state))
            self.run_guard('deadline',expect=3)
            self.assertIsNone(proc.poll())
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    def test_test_mode_cannot_choose_real_vmrun(self):
        self.m['vmrun_path']='/usr/bin/vmrun';self.seal()
        self.run_guard('bootstrap',expect=3)
        self.assertFalse(self.log.exists())
    def test_vmrun_link_must_have_exact_approved_target_and_bytes(self):
        target=self.dir/'target';target.write_bytes(b'approved-executable');target.chmod(0o755)
        link=self.dir/'link';link.symlink_to(target)
        self.assertEqual(guard.vmrun_bytes(link,str(target)),b'approved-executable')
        with self.assertRaises(guard.GuardError):guard.vmrun_bytes(link,str(self.dir/'other'))
        with self.assertRaises(guard.GuardError):guard.vmrun_bytes(link,None)
        target.write_bytes(b'drifted-executable')
        self.assertNotEqual(guard.digest(guard.vmrun_bytes(link,str(target))),guard.digest(b'approved-executable'))
    def test_review_units_have_inert_condition_and_boot_timer(self):
        m=dict(self.m);m['test_mode']=False;m['vmrun_path']='/usr/bin/vmrun';m['vmx']='/opt/example/safety.vmx'
        m['state_dir']=f'/var/lib/velo-g14-guard/{self.id}'
        m['controller_install_path']=f'/usr/local/libexec/velo-g14-guard-{self.id}.py'
        m['unit_service_path']=f'/etc/systemd/system/velo-g14-guard@{self.id}.service'
        m['unit_timer_path']=f'/etc/systemd/system/velo-g14-guard@{self.id}.timer'
        service,timer=units.render(m,'a'*64,review=True)
        self.assertIn(b'ConditionPathExists=/nonexistent/VELO-G14-REVIEW-ONLY',service)
        self.assertIn(b'OnBootSec=1min',timer)
        self.assertNotIn(str(HERE).encode(),service)
        output=self.dir/'units';output.mkdir()
        service_path=output/'review.service';timer_path=output/'review.timer'
        service_path.write_bytes(service);timer_path.write_bytes(timer)
        verified=subprocess.run(['/usr/bin/systemd-analyze','verify',str(service_path),str(timer_path)],
                                capture_output=True,text=True,check=False,timeout=10)
        self.assertEqual(verified.returncode,0,verified.stderr)
        review_manifest=self.dir/'review-manifest.json';review_manifest.write_bytes(guard.encoded(m))
        cli_output=self.dir/'review-cli';cli_output.mkdir()
        cli=subprocess.run([sys.executable,'-m','tests.host_safety_units','--manifest',str(review_manifest),
                            '--approval-sha',guard.digest(review_manifest.read_bytes()),
                            '--review-output',str(cli_output)],capture_output=True,text=True,timeout=10)
        self.assertEqual(cli.returncode,0,cli.stderr)
        self.assertTrue(json.loads(cli.stdout)['review_only'])
        self.assertEqual(len(list(cli_output.iterdir())),2)

for _point in ('after_transaction_intent','after_stop_response','after_stop_stage',
               'before_revert','after_revert_response','after_revert_stage',
               'before_start','after_start_response','after_start_stage','before_final_state'):
    def _case(self, point=_point):
        self.assert_restore_crash_is_not_replayed(point)
    setattr(HostGuardTests,f'test_restore_crash_{_point}',_case)

if __name__=='__main__':unittest.main()
